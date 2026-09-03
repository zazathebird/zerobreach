namespace Scythe.Text;

/// <summary>
/// How the detection answer was reached, as a small ordered enum. Not a float: a float invites
/// arithmetic on it and implies a calibration nobody has performed (reference/11.2_text.md).
/// Order is meaningful — a larger value is a stronger answer.
/// </summary>
public enum DetectionConfidence
{
    /// <summary>
    /// Nothing fit. For single-byte scoring, the best candidate's score was not positive; for a
    /// buffer whose bytes carry anomalies (NUL or C0 control bytes in what otherwise reads as
    /// single-byte text), the answer is reported but should not be leaned on.
    /// </summary>
    Low = 0,

    /// <summary>
    /// The top two candidates are within 5% of each other. The answer is the tie-break of a
    /// documented fixed order, and the ranked list shows how close the call was.
    /// </summary>
    Ambiguous = 1,

    /// <summary>
    /// The evidence points one way but not overwhelmingly: a positive score with a small lead, a
    /// UTF-16 null-byte ratio in the lower band, or a caller hint standing in for byte evidence.
    /// </summary>
    Medium = 2,

    /// <summary>
    /// Structural evidence: clean UTF-8 with multi-byte sequences, a dominant UTF-16 null-byte
    /// pattern, or a single-byte score with a clear lead.
    /// </summary>
    High = 3,

    /// <summary>A recognised byte-order mark decided the encoding outright.</summary>
    FromMark = 4,
}
