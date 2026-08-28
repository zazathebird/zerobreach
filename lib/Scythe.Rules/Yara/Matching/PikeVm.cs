namespace Scythe.Rules.Yara.Matching;

/// <summary>
/// Priority-ordered Thompson simulation ("Pike VM") over a byte buffer. Linear in
/// (window × states) with no backtracking, so a hostile pattern can be slow but never
/// exponential — and the per-pattern deadline bounds "slow".
///
/// Thread priority reproduces the reference engine's match selection: greedy quantifiers
/// prefer consuming, lazy ones prefer leaving, and the first Match reached in priority
/// order cuts every lower-priority thread. Threads spawned before that match survive and
/// may override it with a longer match later (which is exactly greedy behaviour).
///
/// Not reentrant: one instance per scanning thread. All state is instance-local, so
/// distinct instances over one shared <see cref="NfaProgram"/> are safe in parallel.
/// </summary>
internal sealed class PikeVm
{
    private readonly NfaProgram _program;
    private readonly int[] _currentList;
    private readonly int[] _nextList;
    private readonly int[] _seenStamp;
    private readonly int[] _walkStack;
    private int _stamp;

    public PikeVm(NfaProgram program)
    {
        _program = program;
        int n = program.Instructions.Length;
        _currentList = new int[n];
        _nextList = new int[n];
        _seenStamp = new int[n];
        // A pc can sit on the stack twice before its first pop marks it seen (two splits
        // sharing a target), but each instruction contributes at most two pushes, so 2n+2
        // bounds the stack.
        _walkStack = new int[2 * n + 2];
    }

    /// <summary>
    /// Attempts a match anchored at <paramref name="start"/>. Returns the match length
    /// (possibly 0), or -1 for no match. <paramref name="windowEnd"/> caps how far the
    /// attempt may read; the caller derives it from MaxLength and the budget.
    /// </summary>
    public int MatchAt(ReadOnlySpan<byte> buffer, int start, int windowEnd)
    {
        var code = _program.Instructions;
        int matched = -1;

        _stamp++;
        int currentCount = Closure(_currentList, 0, 0, buffer, start, ref matched);

        for (int pos = start; pos < windowEnd && currentCount > 0; pos++)
        {
            byte b = buffer[pos];
            _stamp++;
            int nextCount = 0;
            for (int i = 0; i < currentCount; i++)
            {
                var inst = code[_currentList[i]];
                bool consumes = inst.Op == NfaOp.Byte
                    ? ((b & inst.Mask) == inst.Value) != inst.Negated
                    : _program.ClassContains(inst.ClassIndex, b);
                if (!consumes)
                {
                    continue;
                }
                int before = matched;
                nextCount = Closure(_nextList, nextCount, _currentList[i] + 1, buffer, pos + 1, ref matched);
                if (matched > before)
                {
                    // This thread's closure reached Match. Every remaining thread in the
                    // current list is lower priority and is cut; threads already moved to
                    // the next list are higher priority and keep running.
                    break;
                }
            }
            Array.Copy(_nextList, _currentList, nextCount);
            currentCount = nextCount;
        }
        return matched < 0 ? -1 : matched - start;
    }

    /// <summary>
    /// Adds the epsilon closure of <paramref name="pc"/> to <paramref name="list"/> in
    /// priority order (explicit stack — a chain of thousands of splits from an expanded
    /// counted repeat must not recurse the CLR stack). Reaching Match records the match
    /// position and discards the rest of the closure, which is all lower priority.
    /// </summary>
    private int Closure(int[] list, int count, int pc, ReadOnlySpan<byte> buffer, int pos, ref int matched)
    {
        var code = _program.Instructions;
        var stack = _walkStack;
        int sp = 0;
        stack[sp++] = pc;
        while (sp > 0)
        {
            int p = stack[--sp];
            if (_seenStamp[p] == _stamp)
            {
                continue;
            }
            _seenStamp[p] = _stamp;
            var inst = code[p];
            switch (inst.Op)
            {
                case NfaOp.Jmp:
                    stack[sp++] = inst.A;
                    break;
                case NfaOp.Split:
                    // Push B first so A pops first: A is the preferred branch.
                    stack[sp++] = inst.B;
                    stack[sp++] = inst.A;
                    break;
                case NfaOp.Match:
                    if (matched < pos)
                    {
                        matched = pos;
                    }
                    // Anything still on the stack is lower priority than this match.
                    return count;
                case NfaOp.AssertBufferStart:
                    if (pos == 0)
                    {
                        stack[sp++] = p + 1;
                    }
                    break;
                case NfaOp.AssertBufferEnd:
                    if (pos == buffer.Length)
                    {
                        stack[sp++] = p + 1;
                    }
                    break;
                case NfaOp.AssertWordBoundary:
                    if (IsWordBoundary(buffer, pos))
                    {
                        stack[sp++] = p + 1;
                    }
                    break;
                case NfaOp.AssertNotWordBoundary:
                    if (!IsWordBoundary(buffer, pos))
                    {
                        stack[sp++] = p + 1;
                    }
                    break;
                default:
                    list[count++] = p;
                    break;
            }
        }
        return count;
    }

    private static bool IsWordByte(byte b) =>
        b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'_';

    private static bool IsWordBoundary(ReadOnlySpan<byte> buffer, int pos)
    {
        bool before = pos > 0 && IsWordByte(buffer[pos - 1]);
        bool after = pos < buffer.Length && IsWordByte(buffer[pos]);
        return before != after;
    }
}
