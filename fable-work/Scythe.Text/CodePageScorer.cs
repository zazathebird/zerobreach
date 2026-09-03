namespace Scythe.Text;

/// <summary>
/// Scores every candidate page over the sampled extents and returns the ranked list. Rules and
/// weights are the tables in reference/11.2_text.md §11.2, implemented in integer arithmetic so
/// the ranking cannot drift with floating-point evaluation order.
/// </summary>
internal static class CodePageScorer
{
    // Per-byte weights.
    private const int UndefinedEntryScore = -100;
    private const int C1ControlScore = -50;
    private const int PrimaryScriptLetterScore = 3;
    private const int ProseSymbolScore = 1;
    private const int ForeignScriptLetterScore = -5;

    // Adjacency weights, over consecutive byte pairs within one sampled range.
    private const int LetterBesideAsciiLetterScore = 2;
    private const int SameScriptLetterPairScore = 1;
    private const int DifferentScriptLetterPairScore = -5;
    private const int SymbolPairScore = -2;
    private const int SymbolRunScore = -10;
    private const int SymbolRunMinimumLength = 3;

    /// <summary>Bias per non-ASCII byte granted to a caller-hinted page. Biases, never decides.</summary>
    private const int HintBiasPerNonAsciiByte = 2;

    internal static (IReadOnlyList<RankedCandidate> Ranked, int NonAsciiCount) Score(
        ReadOnlySpan<byte> bytes,
        IReadOnlyList<SampledRange> ranges,
        TextEncodingKind? hintedPage)
        => Score(bytes, ranges, hintedPage, CodePage.CanonicalOrder);

    /// <summary>
    /// Evaluation-order-independent by construction: the ranking sorts on (score, canonical
    /// index), never on the order candidates were walked. The determinism suite calls this
    /// overload with the list reversed and asserts an identical ranking.
    /// </summary>
    internal static (IReadOnlyList<RankedCandidate> Ranked, int NonAsciiCount) Score(
        ReadOnlySpan<byte> bytes,
        IReadOnlyList<SampledRange> ranges,
        TextEncodingKind? hintedPage,
        IReadOnlyList<CodePage> evaluationOrder)
    {
        var nonAscii = 0;
        foreach (var range in ranges)
        {
            var span = bytes.Slice(range.Offset, range.Length);
            foreach (var b in span)
            {
                if (b >= 0x80)
                {
                    nonAscii++;
                }
            }
        }

        var scored = new List<RankedCandidate>(evaluationOrder.Count);
        foreach (var page in evaluationOrder)
        {
            var score = ScoreOne(bytes, ranges, page);
            if (hintedPage == page.Kind)
            {
                score += (long)HintBiasPerNonAsciiByte * nonAscii;
            }

            scored.Add(new RankedCandidate(
                page.Kind,
                score,
                nonAscii == 0 ? 0.0 : score / (double)nonAscii));
        }

        scored.Sort((a, b) =>
        {
            var byScore = b.Score.CompareTo(a.Score);
            return byScore != 0 ? byScore : CanonicalIndex(a.Encoding).CompareTo(CanonicalIndex(b.Encoding));
        });

        return (scored, nonAscii);
    }

    private static int CanonicalIndex(TextEncodingKind kind)
    {
        for (var i = 0; i < CodePage.CanonicalOrder.Length; i++)
        {
            if (CodePage.CanonicalOrder[i].Kind == kind)
            {
                return i;
            }
        }

        return int.MaxValue;
    }

    private static long ScoreOne(ReadOnlySpan<byte> bytes, IReadOnlyList<SampledRange> ranges, CodePage page)
    {
        long score = 0;

        foreach (var range in ranges)
        {
            var span = bytes.Slice(range.Offset, range.Length);
            var symbolRun = 0;

            for (var i = 0; i < span.Length; i++)
            {
                var b = span[i];
                var category = page.CategoryOf(b);

                score += category switch
                {
                    EntryCategory.Undefined => UndefinedEntryScore,
                    EntryCategory.C1Control => C1ControlScore,
                    EntryCategory.Letter => page.ScriptOf(b) == page.PrimaryScript
                        ? PrimaryScriptLetterScore
                        : ForeignScriptLetterScore,
                    EntryCategory.ProseSymbol => ProseSymbolScore,
                    _ => 0, // AsciiRange and OtherSymbol carry no per-byte signal
                };

                // A run of three or more consecutive non-ASCII bytes all mapping to symbols.
                if (b >= 0x80 && category is EntryCategory.ProseSymbol or EntryCategory.OtherSymbol)
                {
                    symbolRun++;
                }
                else
                {
                    if (symbolRun >= SymbolRunMinimumLength)
                    {
                        score += SymbolRunScore;
                    }

                    symbolRun = 0;
                }

                if (i + 1 < span.Length)
                {
                    score += ScorePair(page, b, span[i + 1]);
                }
            }

            if (symbolRun >= SymbolRunMinimumLength)
            {
                score += SymbolRunScore;
            }
        }

        return score;
    }

    private static long ScorePair(CodePage page, byte left, byte right)
    {
        var leftNonAscii = left >= 0x80;
        var rightNonAscii = right >= 0x80;
        if (!leftNonAscii && !rightNonAscii)
        {
            return 0;
        }

        var leftCategory = page.CategoryOf(left);
        var rightCategory = page.CategoryOf(right);

        if (leftNonAscii && rightNonAscii)
        {
            if (leftCategory == EntryCategory.Letter && rightCategory == EntryCategory.Letter)
            {
                return page.ScriptOf(left) == page.ScriptOf(right)
                    ? SameScriptLetterPairScore
                    : DifferentScriptLetterPairScore;
            }

            if (leftCategory is EntryCategory.ProseSymbol or EntryCategory.OtherSymbol
                && rightCategory is EntryCategory.ProseSymbol or EntryCategory.OtherSymbol)
            {
                return SymbolPairScore;
            }

            // Pairs involving an undefined or C1 entry carry no adjacency signal — their
            // per-byte penalty is already decisive.
            return 0;
        }

        // Exactly one side is non-ASCII: the prose pattern worth rewarding is a non-ASCII
        // letter of the page's primary script sitting against an ASCII letter, as accented
        // letters do inside words.
        var (nonAsciiByte, nonAsciiCategory, asciiByte) = leftNonAscii
            ? (left, leftCategory, right)
            : (right, rightCategory, left);

        if (nonAsciiCategory == EntryCategory.Letter
            && page.ScriptOf(nonAsciiByte) == page.PrimaryScript
            && IsAsciiLetter(asciiByte))
        {
            return LetterBesideAsciiLetterScore;
        }

        return 0;
    }

    private static bool IsAsciiLetter(byte b) => (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A);
}
