using Scythe.Rules.Yara.Parsing;

namespace Scythe.Rules.Yara.Matching;

internal enum NfaOp : byte
{
    /// <summary>Consume one byte if (b &amp; Mask) == Value, inverted when Negated.</summary>
    Byte,
    /// <summary>Consume one byte if it is in the class bitmap.</summary>
    Class,
    /// <summary>Fork: try <see cref="NfaInst.A"/> first (higher priority), then B.</summary>
    Split,
    Jmp,
    Match,
    AssertBufferStart,
    AssertBufferEnd,
    AssertWordBoundary,
    AssertNotWordBoundary,
}

internal struct NfaInst
{
    public NfaOp Op;
    public int A;          // jump/split target
    public int B;          // second split target
    public byte Value;
    public byte Mask;
    public bool Negated;
    public int ClassIndex;
}

/// <summary>
/// A compiled byte-NFA shared by hex strings and regexes. Immutable after construction and
/// safe to share across threads; all per-run state lives in the Pike VM.
/// </summary>
internal sealed class NfaProgram
{
    public required NfaInst[] Instructions { get; init; }
    public required ulong[][] Classes { get; init; }

    /// <summary>Shortest number of bytes any match consumes; used to skip scan positions
    /// too close to the end of the buffer.</summary>
    public required int MinLength { get; init; }

    /// <summary>Longest possible match, or null when a loop makes it unbounded; bounds the
    /// window a single anchored attempt may examine.</summary>
    public required int? MaxLength { get; init; }

    /// <summary>Bytes that can begin a match — a conservative prefilter (a byte outside the
    /// set can never start a match; a byte inside it might not).</summary>
    public required ulong[] FirstBytes { get; init; }

    /// <summary>True when every path starts with `^`, so only offset 0 can match.</summary>
    public required bool AnchoredAtStart { get; init; }

    public bool FirstBytesContain(byte b) => (FirstBytes[b >> 6] & (1UL << (b & 63))) != 0;

    public bool ClassContains(int classIndex, byte b) =>
        (Classes[classIndex][b >> 6] & (1UL << (b & 63))) != 0;
}

/// <summary>
/// Builds <see cref="NfaProgram"/>s from regex ASTs and hex-string ASTs. Counted repeats
/// are expanded, so total size is capped: exceeding <see cref="MaxInstructions"/> is a
/// compile-time <see cref="DiagnosticCode.PatternTooComplex"/> error, never a slow scan.
/// </summary>
internal sealed class NfaBuilder
{
    public const int MaxInstructions = 30_000;

    private readonly List<NfaInst> _code = [];
    private readonly List<ulong[]> _classes = [];
    private readonly bool _wide;
    private bool _tooBig;

    private NfaBuilder(bool wide) => _wide = wide;

    public static NfaProgram? FromRegex(
        RegexNode node, bool wide, string owner, string fileName, SourceLocation location,
        List<Diagnostic> diagnostics)
    {
        var b = new NfaBuilder(wide);
        b.Emit(node);
        return b.Finish(owner, fileName, location, diagnostics);
    }

    public static NfaProgram? FromHex(
        HexSequence sequence, string owner, string fileName, SourceLocation location,
        List<Diagnostic> diagnostics)
    {
        var b = new NfaBuilder(wide: false);
        b.EmitHexSequence(sequence);
        return b.Finish(owner, fileName, location, diagnostics);
    }

    private NfaProgram? Finish(string owner, string fileName, SourceLocation location, List<Diagnostic> diagnostics)
    {
        Add(new NfaInst { Op = NfaOp.Match });
        if (_tooBig)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.PatternTooComplex,
                $"pattern of {owner} at {location} compiles to more than {MaxInstructions} states and is rejected; " +
                "simplify the pattern or reduce its repetition counts",
                fileName, location));
            return null;
        }
        var insts = _code.ToArray();
        var (minLen, maxLen) = ComputeLengths(insts);
        var (firstBytes, anchored) = ComputeFirstBytes(insts);
        return new NfaProgram
        {
            Instructions = insts,
            Classes = _classes.ToArray(),
            MinLength = minLen,
            MaxLength = maxLen,
            FirstBytes = firstBytes,
            AnchoredAtStart = anchored,
        };
    }

    // ------------------------------------------------------------------ emission

    private int Add(NfaInst inst)
    {
        if (_code.Count >= MaxInstructions)
        {
            _tooBig = true;
            return _code.Count == 0 ? 0 : _code.Count - 1;
        }
        _code.Add(inst);
        return _code.Count - 1;
    }

    private void EmitConsuming(NfaInst inst)
    {
        Add(inst);
        if (_wide)
        {
            // UTF-16LE: every unit is the byte followed by 0x00.
            Add(new NfaInst { Op = NfaOp.Byte, Value = 0, Mask = 0xFF });
        }
    }

    private int AddClass(ByteSet set)
    {
        // Freeze the set into a bitmap; small dedupe keeps repeated classes cheap.
        var bits = new ulong[4];
        for (int b = 0; b <= 255; b++)
        {
            if (set.Contains((byte)b))
            {
                bits[b >> 6] |= 1UL << (b & 63);
            }
        }
        for (int i = 0; i < _classes.Count; i++)
        {
            if (_classes[i].AsSpan().SequenceEqual(bits))
            {
                return i;
            }
        }
        _classes.Add(bits);
        return _classes.Count - 1;
    }

    private void Emit(RegexNode node)
    {
        if (_tooBig)
        {
            return;
        }
        switch (node)
        {
            case RegexLiteral lit:
                EmitConsuming(new NfaInst { Op = NfaOp.Byte, Value = lit.Value, Mask = 0xFF });
                break;
            case RegexClass cls:
                EmitConsuming(new NfaInst { Op = NfaOp.Class, ClassIndex = AddClass(cls.Set) });
                break;
            case RegexAssertion a:
                Add(new NfaInst
                {
                    Op = a.Kind switch
                    {
                        RegexAssertionKind.BufferStart => NfaOp.AssertBufferStart,
                        RegexAssertionKind.BufferEnd => NfaOp.AssertBufferEnd,
                        RegexAssertionKind.WordBoundary => NfaOp.AssertWordBoundary,
                        _ => NfaOp.AssertNotWordBoundary,
                    },
                });
                break;
            case RegexConcat concat:
                foreach (var child in concat.Nodes)
                {
                    Emit(child);
                }
                break;
            case RegexAlternation alt:
                EmitAlternation(alt.Branches, Emit);
                break;
            case RegexRepeat rep:
                EmitRepeat(() => Emit(rep.Body), rep.Min, rep.Max, rep.Lazy);
                break;
        }
    }

    private void EmitAlternation<T>(IReadOnlyList<T> branches, Action<T> emitBranch)
    {
        // split(b1, split(b2, ... bn)) with jumps to a common exit; branch order is
        // priority order, which is what makes alternation deterministic.
        var jumpsToPatch = new List<int>();
        var splitsToPatch = new List<int>();
        for (int i = 0; i < branches.Count; i++)
        {
            int split = -1;
            if (i < branches.Count - 1)
            {
                split = Add(new NfaInst { Op = NfaOp.Split });
            }
            if (split >= 0)
            {
                PatchA(split, _code.Count);
            }
            emitBranch(branches[i]);
            if (i < branches.Count - 1)
            {
                jumpsToPatch.Add(Add(new NfaInst { Op = NfaOp.Jmp }));
                splitsToPatch.Add(split);
            }
        }
        int exit = _code.Count;
        foreach (var j in jumpsToPatch)
        {
            PatchA(j, exit);
        }
        // Each split's B falls through to the next branch, which begins right after the
        // jump that was emitted for the previous branch.
        for (int i = 0; i < splitsToPatch.Count; i++)
        {
            PatchB(splitsToPatch[i], jumpsToPatch[i] + 1);
        }
    }

    private void EmitRepeat(Action emitBody, int min, int? max, bool lazy)
    {
        for (int i = 0; i < min; i++)
        {
            if (_tooBig)
            {
                return;
            }
            emitBody();
        }
        if (max is int m)
        {
            int optional = m - min;
            var splits = new List<int>();
            for (int i = 0; i < optional; i++)
            {
                if (_tooBig)
                {
                    return;
                }
                splits.Add(Add(new NfaInst { Op = NfaOp.Split }));
                emitBody();
            }
            int exit = _code.Count;
            foreach (var s in splits)
            {
                // Greedy prefers taking the body (A = next instruction); lazy prefers
                // skipping to the exit.
                if (lazy)
                {
                    PatchA(s, exit);
                    PatchB(s, s + 1);
                }
                else
                {
                    PatchA(s, s + 1);
                    PatchB(s, exit);
                }
            }
        }
        else
        {
            // Unbounded tail: L: split(body, exit); body; jmp L
            int loop = Add(new NfaInst { Op = NfaOp.Split });
            emitBody();
            Add(new NfaInst { Op = NfaOp.Jmp, A = loop });
            int exit = _code.Count;
            if (lazy)
            {
                PatchA(loop, exit);
                PatchB(loop, loop + 1);
            }
            else
            {
                PatchA(loop, loop + 1);
                PatchB(loop, exit);
            }
        }
    }

    private void PatchA(int index, int target)
    {
        var inst = _code[index];
        inst.A = target;
        _code[index] = inst;
    }

    private void PatchB(int index, int target)
    {
        var inst = _code[index];
        inst.B = target;
        _code[index] = inst;
    }

    // ------------------------------------------------------------------ hex strings

    private void EmitHexSequence(HexSequence seq)
    {
        foreach (var node in seq.Nodes)
        {
            if (_tooBig)
            {
                return;
            }
            switch (node)
            {
                case HexByteNode b:
                    Add(new NfaInst { Op = NfaOp.Byte, Value = b.Value, Mask = b.Mask, Negated = b.Negated });
                    break;
                case HexJumpNode j:
                    // The reference compiles jumps as non-greedy: the shortest span wins
                    // (verified against yara 4.5.5: { 41 [0-2] 42 } on "ABB" matches 2 bytes).
                    EmitRepeat(
                        () => Add(new NfaInst { Op = NfaOp.Byte, Value = 0, Mask = 0x00 }),
                        j.Min, j.Max, lazy: true);
                    break;
                case HexAltNode alt:
                    EmitAlternation(alt.Branches, EmitHexSequence);
                    break;
            }
        }
    }

    // ------------------------------------------------------------------ analysis

    private static (int Min, int? Max) ComputeLengths(NfaInst[] code)
    {
        // Longest path: any cycle (which only unbounded loops create) means unbounded.
        // Both walks are DAG-style DP with cycle detection over the small instruction graph.
        int?[] minMemo = new int?[code.Length];
        var minVisiting = new bool[code.Length];
        int? min = MinFrom(0);

        bool unbounded = false;
        int?[] maxMemo = new int?[code.Length];
        var maxVisiting = new bool[code.Length];
        int? max = unboundedSafeMaxFrom(0);

        return (min ?? 0, unbounded ? null : max);

        int? MinFrom(int pc)
        {
            if (minMemo[pc] is int done)
            {
                return done;
            }
            if (minVisiting[pc])
            {
                return null; // a cycle cannot shorten a path; ignore this branch
            }
            minVisiting[pc] = true;
            var inst = code[pc];
            int? result = inst.Op switch
            {
                NfaOp.Match => 0,
                NfaOp.Byte or NfaOp.Class => MinFrom(pc + 1) + 1,
                NfaOp.Jmp => MinFrom(inst.A),
                NfaOp.Split => Min2(MinFrom(inst.A), MinFrom(inst.B)),
                _ => MinFrom(pc + 1), // assertions consume nothing
            };
            minVisiting[pc] = false;
            minMemo[pc] = result;
            return result;

            static int? Min2(int? a, int? b) =>
                a is null ? b : b is null ? a : Math.Min(a.Value, b.Value);
        }

        int? unboundedSafeMaxFrom(int pc)
        {
            if (maxMemo[pc] is int done)
            {
                return done;
            }
            if (maxVisiting[pc])
            {
                unbounded = true;
                return 0;
            }
            maxVisiting[pc] = true;
            var inst = code[pc];
            int? result = inst.Op switch
            {
                NfaOp.Match => 0,
                NfaOp.Byte or NfaOp.Class => unboundedSafeMaxFrom(pc + 1) + 1,
                NfaOp.Jmp => unboundedSafeMaxFrom(inst.A),
                NfaOp.Split => Max2(unboundedSafeMaxFrom(inst.A), unboundedSafeMaxFrom(inst.B)),
                _ => unboundedSafeMaxFrom(pc + 1),
            };
            maxVisiting[pc] = false;
            maxMemo[pc] = result;
            return result;

            static int? Max2(int? a, int? b) =>
                a is null ? b : b is null ? a : Math.Max(a.Value, b.Value);
        }
    }

    private (ulong[] FirstBytes, bool Anchored) ComputeFirstBytes(NfaInst[] code)
    {
        var bits = new ulong[4];
        var visited = new bool[code.Length];
        Walk(0);
        var anchoredMemo = new bool?[code.Length];
        bool anchored = Anchored(0);
        return (bits, anchored);

        void Walk(int pc)
        {
            if (visited[pc])
            {
                return;
            }
            visited[pc] = true;
            var inst = code[pc];
            switch (inst.Op)
            {
                case NfaOp.Byte:
                    if (inst.Mask == 0xFF && !inst.Negated)
                    {
                        bits[inst.Value >> 6] |= 1UL << (inst.Value & 63);
                    }
                    else
                    {
                        for (int b = 0; b <= 255; b++)
                        {
                            bool eq = (b & inst.Mask) == inst.Value;
                            if (eq != inst.Negated)
                            {
                                bits[b >> 6] |= 1UL << (b & 63);
                            }
                        }
                    }
                    break;
                case NfaOp.Class:
                    var cls = _classes[inst.ClassIndex];
                    for (int i = 0; i < 4; i++)
                    {
                        bits[i] |= cls[i];
                    }
                    break;
                case NfaOp.Match:
                    // A pattern that can match empty can "start" anywhere.
                    for (int i = 0; i < 4; i++)
                    {
                        bits[i] = ulong.MaxValue;
                    }
                    break;
                case NfaOp.Split:
                    Walk(inst.A);
                    Walk(inst.B);
                    break;
                case NfaOp.Jmp:
                    Walk(inst.A);
                    break;
                default:
                    // Assertions consume nothing; the first byte lies beyond them.
                    Walk(pc + 1);
                    break;
            }
        }

        // True only when every path crosses `^` before consuming anything, in which case
        // scanning can stop after offset 0.
        bool Anchored(int pc)
        {
            if (anchoredMemo[pc] is bool memo)
            {
                return memo;
            }
            anchoredMemo[pc] = true; // cycles cannot un-anchor a path
            var inst = code[pc];
            bool result = inst.Op switch
            {
                NfaOp.AssertBufferStart => true,
                NfaOp.Byte or NfaOp.Class or NfaOp.Match => false,
                NfaOp.Split => Anchored(inst.A) && Anchored(inst.B),
                NfaOp.Jmp => Anchored(inst.A),
                _ => Anchored(pc + 1),
            };
            anchoredMemo[pc] = result;
            return result;
        }
    }
}
