namespace Scythe.Text;

/// <summary>
/// Detects the encoding of a byte buffer: byte-order mark first (longest first), then UTF-8
/// structural validation, then the markless UTF-16 null-distribution heuristic, then ranked
/// single-byte code-page scoring. reference/11.2_text.md §11.2 has the rules and weights.
/// </summary>
public static class TextDetector
{
    // Markless UTF-16 thresholds, from the reference. Ratios are of nulls per code unit.
    private const int MinimumUtf16Length = 16;
    private const int DominantNullPercentHigh = 45;
    private const int DominantNullPercentMinimum = 30;
    private const int OppositeNullPercentMaximum = 2;

    // Single-byte scoring samples a bounded extent of large buffers: the whole answer cannot
    // require reading gigabytes, and the sampled extent is reported so a caller knows what the
    // confidence covers (Q2 brief, open question 3).
    internal const int PrefixSampleBytes = 64 * 1024;
    internal const int MiddleSampleBytes = 16 * 1024;
    internal const int EndSampleBytes = 16 * 1024;

    // Confidence gap thresholds over the ranked scores, in percent of the top score.
    private const int TiePercent = 5;
    private const int ClearLeadPercent = 15;

    // C0 control bytes (other than tab/LF/CR) at or above this share of the buffer cap a
    // single-byte or ASCII answer at Low: controls are not prose, and a buffer full of them is
    // usually not single-byte text at all — Greek or CJK UTF-16 read byte-wise looks exactly
    // like this.
    private const int ControlDensityPercentCap = 10;

    /// <summary>
    /// Detects the encoding of <paramref name="bytes"/>. The buffer is held by reference in the
    /// result's <see cref="DetectionResult.OriginalBytes"/>, not copied.
    /// </summary>
    public static TextResult<DetectionResult> Detect(
        byte[] bytes,
        DetectionHint? hint = null,
        ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        budget ??= ScanBudget.Default;

        if (bytes.LongLength > budget.MaxInputBytes)
        {
            return TextResult<DetectionResult>.Incomplete(
                Result(TextEncodingKind.Unknown, DetectionConfidence.Low, 0, bytes, hint,
                    hint is null ? HintOutcome.NotProvided : HintOutcome.NotEvaluated),
                $"input is {bytes.LongLength} bytes, over the {budget.MaxInputBytes}-byte MaxInputBytes budget; detection did not run");
        }

        if (bytes.Length == 0)
        {
            // Empty text is valid in every encoding; ASCII is the answer under which a
            // re-encode is a no-op. A hint neither confirms nor contradicts zero bytes.
            return TextResult<DetectionResult>.Ok(Result(
                TextEncodingKind.Ascii, DetectionConfidence.High, 0, bytes, hint,
                hint is null ? HintOutcome.NotProvided : HintOutcome.AgreedWithEvidence));
        }

        var scan = BufferScan.Run(bytes);

        // 1. Byte-order mark, longest first. A recognised mark decides outright, and beats a
        //    contradicting hint.
        if (ByteOrderMark.TryMatch(bytes, out var marked, out var markLength))
        {
            var outcome = hint is null
                ? HintOutcome.NotProvided
                : hint.Encoding == marked ? HintOutcome.AgreedWithEvidence : HintOutcome.ContradictedByMark;
            return TextResult<DetectionResult>.Ok(Result(
                marked, DetectionConfidence.FromMark, markLength, bytes, hint, outcome, scan));
        }
        var hintKind = hint?.Encoding;
        var hintIsUtf16 = hintKind is TextEncodingKind.Utf16LittleEndian or TextEncodingKind.Utf16BigEndian;
        var evenLength = (bytes.Length & 1) == 0;

        // 2. UTF-8 well-formedness. A nul-free buffer that validates is decided here; a buffer
        //    holding NUL bytes is not, because Latin-script UTF-16 without a mark is a valid
        //    "ASCII" byte sequence — the nulls have to be offered to the UTF-16 heuristic first.
        if (scan.IsValidUtf8 && scan.NulByteCount == 0)
        {
            var structural = scan.MultiByteSequenceCount > 0 ? TextEncodingKind.Utf8 : TextEncodingKind.Ascii;

            if (hintIsUtf16 && structural == TextEncodingKind.Ascii && evenLength)
            {
                // Every byte under 0x80 and no nulls reads as ASCII, but an even-length buffer
                // of such bytes is also what CJK UTF-16 looks like. The bytes cannot settle it;
                // the caller's flag can.
                return TextResult<DetectionResult>.Ok(Result(
                    hintKind!.Value, DetectionConfidence.Medium, 0, bytes, hint,
                    HintOutcome.FollowedForUtf16, scan));
            }

            var confidence = scan.ControlByteCount * 100 >= bytes.Length * ControlDensityPercentCap
                ? DetectionConfidence.Low
                : DetectionConfidence.High;
            return TextResult<DetectionResult>.Ok(Result(
                structural, confidence, 0, bytes, hint,
                HintFateAgainst(structural, hintKind), scan));
        }

        // 3. Markless UTF-16 from the null-byte distribution. Latin-script UTF-16 puts nulls in
        //    the high half of nearly every code unit; an odd length disqualifies outright.
        if (evenLength && bytes.Length >= MinimumUtf16Length)
        {
            var halves = bytes.Length / 2;
            var (leDominant, leOpposite) = (scan.NulAtOddOffset, scan.NulAtEvenOffset);
            var (beDominant, beOpposite) = (scan.NulAtEvenOffset, scan.NulAtOddOffset);

            if (Utf16Matches(leDominant, leOpposite, halves, out var leConfidence))
            {
                return TextResult<DetectionResult>.Ok(Result(
                    TextEncodingKind.Utf16LittleEndian, leConfidence, 0, bytes, hint,
                    HintFateAgainst(TextEncodingKind.Utf16LittleEndian, hintKind), scan));
            }

            if (Utf16Matches(beDominant, beOpposite, halves, out var beConfidence))
            {
                return TextResult<DetectionResult>.Ok(Result(
                    TextEncodingKind.Utf16BigEndian, beConfidence, 0, bytes, hint,
                    HintFateAgainst(TextEncodingKind.Utf16BigEndian, hintKind), scan));
            }
        }

        // A caller's UTF-16 hint stands in for the null pattern that non-Latin script does not
        // produce — but only when the length does not disqualify UTF-16 outright.
        if (hintIsUtf16 && evenLength)
        {
            return TextResult<DetectionResult>.Ok(Result(
                hintKind!.Value, DetectionConfidence.Medium, 0, bytes, hint,
                HintOutcome.FollowedForUtf16, scan));
        }

        // The buffer validated as UTF-8 but holds NUL bytes no heuristic explained: report the
        // structural answer, at Low, because NULs inside single-byte text are anomalous.
        if (scan.IsValidUtf8)
        {
            var structural = scan.MultiByteSequenceCount > 0 ? TextEncodingKind.Utf8 : TextEncodingKind.Ascii;
            return TextResult<DetectionResult>.Ok(Result(
                structural, DetectionConfidence.Low, 0, bytes, hint,
                HintFateAgainst(structural, hintKind), scan));
        }

        // 4. Single-byte code pages, ranked. Reached only with at least one byte >= 0x80 in the
        //    buffer (ill-formed UTF-8 requires one).
        var ranges = SampleRanges(bytes.Length);
        var hintedPage = hintKind is not null && CodePage.ForKind(hintKind.Value) is not null ? hintKind : null;
        var (ranked, _) = CodePageScorer.Score(bytes, ranges, hintedPage);

        var top = ranked[0];
        var second = ranked.Count > 1 ? ranked[1] : null;
        var rankedConfidence = ConfidenceFromScores(top.Score, second?.Score);

        // NULs or a high control density cap the answer at Low regardless of the score gap.
        if ((scan.NulByteCount > 0 || scan.ControlByteCount * 100 >= bytes.Length * ControlDensityPercentCap)
            && rankedConfidence > DetectionConfidence.Low)
        {
            rankedConfidence = DetectionConfidence.Low;
        }

        var pageOutcome = hint is null
            ? HintOutcome.NotProvided
            : hintedPage is not null ? HintOutcome.BiasApplied : HintOutcome.ContradictedByStructure;

        return TextResult<DetectionResult>.Ok(Result(
            top.Encoding, rankedConfidence, 0, bytes, hint, pageOutcome, scan, ranked, ranges));
    }

    private static bool Utf16Matches(int dominant, int opposite, int halves, out DetectionConfidence confidence)
    {
        confidence = DetectionConfidence.Low;
        if (dominant * 100 < DominantNullPercentMinimum * halves
            || opposite * 100 > OppositeNullPercentMaximum * halves)
        {
            return false;
        }

        confidence = dominant * 100 >= DominantNullPercentHigh * halves
            ? DetectionConfidence.High
            : DetectionConfidence.Medium;
        return true;
    }

    private static DetectionConfidence ConfidenceFromScores(long top, long? second)
    {
        if (second is null)
        {
            return top > 0 ? DetectionConfidence.High : DetectionConfidence.Low;
        }

        if (top <= 0)
        {
            return DetectionConfidence.Low;
        }

        var gap = top - second.Value;
        if (gap * 100 <= top * TiePercent)
        {
            return DetectionConfidence.Ambiguous;
        }

        return gap * 100 >= top * ClearLeadPercent
            ? DetectionConfidence.High
            : DetectionConfidence.Medium;
    }

    private static HintOutcome HintFateAgainst(TextEncodingKind answer, TextEncodingKind? hintKind)
    {
        if (hintKind is null)
        {
            return HintOutcome.NotProvided;
        }

        if (hintKind == answer)
        {
            return HintOutcome.AgreedWithEvidence;
        }

        // ASCII bytes decode identically under every supported page and under UTF-8, so a
        // single-byte or UTF-8 hint on an all-ASCII buffer is compatible with the answer rather
        // than contradicted by it. The answer stays ASCII: the caller asked what the bytes are.
        if (answer == TextEncodingKind.Ascii
            && (hintKind == TextEncodingKind.Utf8 || CodePage.ForKind(hintKind.Value) is not null))
        {
            return HintOutcome.AgreedWithEvidence;
        }

        return HintOutcome.ContradictedByStructure;
    }

    /// <summary>
    /// A bounded prefix plus bounded samples from the middle and the end. Small buffers are read
    /// whole; the extents never overlap and are reported on the result.
    /// </summary>
    internal static IReadOnlyList<SampledRange> SampleRanges(int length)
    {
        if (length <= PrefixSampleBytes + MiddleSampleBytes + EndSampleBytes)
        {
            return [new SampledRange(0, length)];
        }

        var endStart = length - EndSampleBytes;
        var middleStart = Math.Max(PrefixSampleBytes, length / 2 - MiddleSampleBytes / 2);
        var middleLength = Math.Min(MiddleSampleBytes, endStart - middleStart);

        var ranges = new List<SampledRange> { new(0, PrefixSampleBytes) };
        if (middleLength > 0)
        {
            ranges.Add(new SampledRange(middleStart, middleLength));
        }

        ranges.Add(new SampledRange(endStart, EndSampleBytes));
        return ranges;
    }

    private static DetectionResult Result(
        TextEncodingKind encoding,
        DetectionConfidence confidence,
        int markLength,
        byte[] bytes,
        DetectionHint? hint,
        HintOutcome outcome,
        BufferScan scan = default,
        IReadOnlyList<RankedCandidate>? ranked = null,
        IReadOnlyList<SampledRange>? ranges = null)
        => new(
            encoding,
            confidence,
            markLength,
            ranked ?? [],
            ranges ?? [],
            hint?.Encoding,
            outcome,
            scan.NulByteCount,
            scan.ControlByteCount,
            bytes);
}
