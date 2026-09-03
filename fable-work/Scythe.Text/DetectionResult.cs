namespace Scythe.Text;

/// <summary>One single-byte candidate's position in the ranked scoring.</summary>
/// <param name="Encoding">The page.</param>
/// <param name="Score">
/// Raw integer score, summed per the rules in reference/11.2_text.md. Comparable only against
/// the other candidates for the same buffer.
/// </param>
/// <param name="ScorePerNonAsciiByte">
/// The raw score normalised by the count of non-ASCII bytes scored, for reporting. The ranking
/// is computed on the raw integer score.
/// </param>
public sealed record RankedCandidate(
    TextEncodingKind Encoding,
    long Score,
    double ScorePerNonAsciiByte);

/// <summary>A contiguous extent of the buffer that scoring actually read.</summary>
public sealed record SampledRange(int Offset, int Length);

/// <summary>
/// The outcome of one detection. Members state what was observed, not what a caller should
/// conclude (reference/00_shared.md, naming).
/// </summary>
/// <param name="Encoding">The detected encoding — the mark's, the structure's, or the top-ranked page.</param>
/// <param name="Confidence">How the answer was reached; see <see cref="DetectionConfidence"/>.</param>
/// <param name="MarkLength">Byte length of the recognised mark, so callers can skip it. Zero when markless.</param>
/// <param name="SingleByteCandidates">
/// Every single-byte candidate with its score, best first, ties broken by the canonical order.
/// Empty when detection never reached single-byte scoring.
/// </param>
/// <param name="SampledRanges">
/// The extents single-byte scoring read. Detection samples large buffers rather than scoring
/// every byte, and the confidence only covers what was read. Empty when scoring never ran.
/// </param>
/// <param name="Hint">The caller's hint as given, or null.</param>
/// <param name="HintOutcome">What detection did with the hint.</param>
/// <param name="NulByteCount">Count of 0x00 bytes in the buffer. Nulls in single-byte text are anomalous.</param>
/// <param name="ControlByteCount">
/// Count of C0 control bytes other than tab, LF and CR (0x7F included). Controls in prose are
/// anomalous and cap the confidence of a single-byte or ASCII answer.
/// </param>
/// <param name="OriginalBytes">The buffer exactly as received, mark included. Callers hashing content hash this.</param>
public sealed record DetectionResult(
    TextEncodingKind Encoding,
    DetectionConfidence Confidence,
    int MarkLength,
    IReadOnlyList<RankedCandidate> SingleByteCandidates,
    IReadOnlyList<SampledRange> SampledRanges,
    TextEncodingKind? Hint,
    HintOutcome HintOutcome,
    int NulByteCount,
    int ControlByteCount,
    byte[] OriginalBytes);
