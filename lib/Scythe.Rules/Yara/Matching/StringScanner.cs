using System.Diagnostics;

namespace Scythe.Rules.Yara.Matching;

/// <summary>One occurrence of a string: offset and length in the scanned buffer.</summary>
public readonly record struct StringMatch(int Offset, int Length) : IComparable<StringMatch>
{
    public int End => Offset + Length;

    public int CompareTo(StringMatch other)
    {
        int c = Offset.CompareTo(other.Offset);
        return c != 0 ? c : Length.CompareTo(other.Length);
    }
}

/// <summary>All matches for one string, plus whether matching finished for it.</summary>
public sealed class StringMatchSet
{
    public required IReadOnlyList<StringMatch> Matches { get; init; }

    /// <summary>False when this string's matching was cut short — by its per-pattern
    /// deadline, the whole-scan deadline or the match cap. A rule referencing an
    /// unfinished string must evaluate to Incomplete, never to false.</summary>
    public required bool Complete { get; init; }

    public string? IncompleteReason { get; init; }

    /// <summary>Greedy left-to-right non-overlapping occurrence count, which is what `#s`
    /// reports (BLUEPRINT §4.3 — a deliberate divergence from the reference, which counts
    /// one match per starting offset even when they overlap; confirmed by the owner).</summary>
    public required int NonOverlappingCount { get; init; }
}

/// <summary>Result of matching every compiled string against one buffer.</summary>
public sealed class StringScanResult
{
    public required OperationState State { get; init; }
    public string? Reason { get; init; }
    public required IReadOnlyList<StringMatchSet> PerString { get; init; }
}

/// <summary>
/// Runs the two-tier match: one Aho-Corasick pass over the buffer for every literal
/// variant, then per-string NFA scans for hex and regex patterns (prefiltered by first-byte
/// sets). All limits come from the <see cref="ScanBudget"/>; exceeding any of them yields
/// Incomplete with the reason — "no match" is what a clean file looks like, so a timeout
/// must never be reported as one.
/// </summary>
public static class StringScanner
{
    private const int DeadlineCheckMask = 0xFFFF; // check the clock every 64 Ki steps

    public static StringScanResult Scan(
        CompiledStringSet set, ReadOnlySpan<byte> data, ScanBudget budget,
        IReadOnlySet<int>? skipStrings = null)
    {
        int stringCount = set.StringCount;
        if (data.Length > budget.MaxInputBytes)
        {
            return AllIncomplete(set,
                $"input is {data.Length} bytes, over the {budget.MaxInputBytes} byte budget; nothing was scanned");
        }

        long deadlineTimestamp = Stopwatch.GetTimestamp() + (long)(budget.Deadline.TotalSeconds * Stopwatch.Frequency);

        var collectors = new List<StringMatch>[stringCount];
        for (int i = 0; i < stringCount; i++)
        {
            collectors[i] = [];
        }
        var incompleteReasons = new string?[stringCount];
        if (skipStrings is { Count: > 0 })
        {
            // Skipped strings (a disabled rule) are unfinished by definition, never
            // silently empty.
            foreach (int i in skipStrings)
            {
                incompleteReasons[i] = "skipped: rule disabled after exceeding its budget on an earlier scan";
            }
        }
        int totalMatches = 0;
        bool capHit = false;
        string? globalReason = null;

        // ---- literal pass -------------------------------------------------------------
        bool literalsAborted = false;
        if (set.SensitiveAutomaton is not null || set.FoldedAutomaton is not null)
        {
            int sState = 0, fState = 0;
            for (int pos = 0; pos < data.Length; pos++)
            {
                if ((pos & DeadlineCheckMask) == 0 && Stopwatch.GetTimestamp() > deadlineTimestamp)
                {
                    literalsAborted = true;
                    globalReason = $"scan deadline exhausted during literal pass at offset {pos} of {data.Length}";
                    break;
                }
                byte b = data[pos];
                if (set.SensitiveAutomaton is not null)
                {
                    sState = set.SensitiveAutomaton.Step(sState, b);
                    foreach (int patternId in set.SensitiveAutomaton.OutputsAt(sState))
                    {
                        if (!Record(set.SensitivePatterns[patternId], pos, data, collectors, ref totalMatches, budget, skipStrings))
                        {
                            capHit = true;
                            break;
                        }
                    }
                }
                if (!capHit && set.FoldedAutomaton is not null)
                {
                    fState = set.FoldedAutomaton.Step(fState, YaraStringCompiler.FoldByte(b));
                    foreach (int patternId in set.FoldedAutomaton.OutputsAt(fState))
                    {
                        if (!Record(set.FoldedPatterns[patternId], pos, data, collectors, ref totalMatches, budget, skipStrings))
                        {
                            capHit = true;
                            break;
                        }
                    }
                }
                if (capHit)
                {
                    globalReason = $"match cap of {budget.MaxMatches} reached at offset {pos}; matching stopped";
                    break;
                }
            }
        }

        if (literalsAborted || capHit)
        {
            // Which literal-bearing strings would have matched later is unknowable, so
            // every one of them is explicitly unfinished.
            foreach (var v in set.SensitivePatterns)
            {
                incompleteReasons[v.StringIndex] ??= globalReason;
            }
            foreach (var v in set.FoldedPatterns)
            {
                incompleteReasons[v.StringIndex] ??= globalReason;
            }
        }

        // ---- NFA pass (hex strings and regexes) --------------------------------------
        long perPatternTicks = (long)(BudgetDefaults.PerPatternDeadline.TotalSeconds * Stopwatch.Frequency);
        foreach (var entry in set.NfaStrings)
        {
            if (skipStrings is not null && skipStrings.Contains(entry.StringIndex))
            {
                continue;
            }
            if (capHit)
            {
                incompleteReasons[entry.StringIndex] ??= globalReason;
                continue;
            }
            long now = Stopwatch.GetTimestamp();
            if (now > deadlineTimestamp)
            {
                globalReason ??= "scan deadline exhausted before all patterns ran";
                incompleteReasons[entry.StringIndex] ??= "not scanned: file budget exhausted";
                continue;
            }
            long entryDeadline = Math.Min(deadlineTimestamp, now + perPatternTicks);

            var program = entry.Program;
            var vm = new PikeVm(program);
            int lastStart = program.AnchoredAtStart ? 0 : data.Length - program.MinLength;
            for (int off = 0; off <= lastStart; off++)
            {
                if ((off & 0x3FF) == 0 && Stopwatch.GetTimestamp() > entryDeadline)
                {
                    incompleteReasons[entry.StringIndex] =
                        $"pattern budget exhausted at offset {off} of {data.Length}";
                    if (Stopwatch.GetTimestamp() > deadlineTimestamp)
                    {
                        globalReason ??= "scan deadline exhausted during pattern scan";
                    }
                    break;
                }
                if (!program.FirstBytesContain(data[off]))
                {
                    continue;
                }
                int windowEnd = program.MaxLength is int maxLen
                    ? Math.Min(data.Length, off + maxLen)
                    : data.Length;
                int length = vm.MatchAt(data, off, windowEnd);
                if (length < 0)
                {
                    continue;
                }
                if (entry.Fullword && !FullwordOk(data, off, length, entry.Encoding))
                {
                    continue;
                }
                collectors[entry.StringIndex].Add(new StringMatch(off, length));
                if (++totalMatches >= budget.MaxMatches)
                {
                    capHit = true;
                    globalReason = $"match cap of {budget.MaxMatches} reached; matching stopped";
                    incompleteReasons[entry.StringIndex] ??= globalReason;
                    break;
                }
            }
        }

        // ---- finalize -----------------------------------------------------------------
        var perString = new StringMatchSet[stringCount];
        for (int i = 0; i < stringCount; i++)
        {
            var list = collectors[i];
            list.Sort();
            Dedupe(list);
            perString[i] = new StringMatchSet
            {
                Matches = list,
                Complete = incompleteReasons[i] is null,
                IncompleteReason = incompleteReasons[i],
                NonOverlappingCount = CountNonOverlapping(list),
            };
        }
        bool anyIncomplete = globalReason is not null || incompleteReasons.Any(r => r is not null);
        return new StringScanResult
        {
            State = anyIncomplete ? OperationState.Incomplete : OperationState.Ok,
            Reason = globalReason ?? (anyIncomplete ? "one or more patterns did not finish" : null),
            PerString = perString,
        };
    }

    private static StringScanResult AllIncomplete(CompiledStringSet set, string reason)
    {
        var perString = new StringMatchSet[set.StringCount];
        for (int i = 0; i < set.StringCount; i++)
        {
            perString[i] = new StringMatchSet
            {
                Matches = [],
                Complete = false,
                IncompleteReason = reason,
                NonOverlappingCount = 0,
            };
        }
        return new StringScanResult { State = OperationState.Incomplete, Reason = reason, PerString = perString };
    }

    private static bool Record(
        LiteralVariant variant, int endPos, ReadOnlySpan<byte> data,
        List<StringMatch>[] collectors, ref int totalMatches, ScanBudget budget,
        IReadOnlySet<int>? skipStrings)
    {
        if (skipStrings is not null && skipStrings.Contains(variant.StringIndex))
        {
            return true;
        }
        int length = variant.Bytes.Length;
        int start = endPos - length + 1;
        if (variant.Fullword && !FullwordOk(data, start, length, variant.Encoding))
        {
            return true;
        }
        collectors[variant.StringIndex].Add(new StringMatch(start, length));
        return ++totalMatches < budget.MaxMatches;
    }

    /// <summary>
    /// Boundary test for `fullword`, on raw buffer bytes (the reference does not decode
    /// xor'd neighbours — verified). Ascii: the bytes on both sides must not be
    /// alphanumeric. Wide: the two bytes before must not form an (alnum, 0x00) pair, and
    /// likewise after. Note the asymmetry with regex `\b`, pinned by differential test:
    /// fullword uses isalnum (underscore is a boundary), `\b` counts underscore as a word
    /// character.
    /// </summary>
    private static bool FullwordOk(ReadOnlySpan<byte> data, int start, int length, VariantEncoding encoding)
    {
        int end = start + length;
        if (encoding == VariantEncoding.Ascii)
        {
            if (start > 0 && IsWordByte(data[start - 1]))
            {
                return false;
            }
            if (end < data.Length && IsWordByte(data[end]))
            {
                return false;
            }
            return true;
        }
        if (start >= 2 && data[start - 1] == 0 && IsWordByte(data[start - 2]))
        {
            return false;
        }
        if (end + 1 < data.Length && data[end + 1] == 0 && IsWordByte(data[end]))
        {
            return false;
        }
        return true;
    }

    private static bool IsWordByte(byte b) =>
        b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9';

    private static void Dedupe(List<StringMatch> sorted)
    {
        int w = 0;
        for (int r = 0; r < sorted.Count; r++)
        {
            if (w == 0 || sorted[r] != sorted[w - 1])
            {
                sorted[w++] = sorted[r];
            }
        }
        if (w < sorted.Count)
        {
            sorted.RemoveRange(w, sorted.Count - w);
        }
    }

    /// <summary>Greedy left-to-right disjoint count; at equal offsets the shortest match is
    /// taken (it can only increase the count, making the count canonical and deterministic).</summary>
    private static int CountNonOverlapping(List<StringMatch> sorted)
    {
        int count = 0;
        long nextFree = 0;
        foreach (var m in sorted)
        {
            if (m.Offset >= nextFree)
            {
                count++;
                nextFree = m.End;
            }
        }
        return count;
    }
}
