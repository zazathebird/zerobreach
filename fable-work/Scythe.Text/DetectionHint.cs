namespace Scythe.Text;

/// <summary>
/// A caller-supplied expectation — a hive value's type field, a shell link's Unicode flag —
/// that biases detection but never bypasses validation. A hint contradicting a byte-order mark
/// loses to the mark, and the contradiction is reported (Q2 brief, open question 2).
/// </summary>
public sealed record DetectionHint(TextEncodingKind Encoding);

/// <summary>What detection did with the caller's hint. Recorded on every result.</summary>
public enum HintOutcome
{
    NotProvided = 0,

    /// <summary>The hint named what the byte evidence decided on its own.</summary>
    AgreedWithEvidence,

    /// <summary>
    /// The hint supplied the answer where the bytes alone were inconclusive — a markless UTF-16
    /// buffer whose null-byte pattern is weak (non-Latin script does not produce one). Capped at
    /// Medium confidence because the evidence is external to the buffer.
    /// </summary>
    FollowedForUtf16,

    /// <summary>
    /// The hinted single-byte page received a scoring bias. The ranked list shows whether the
    /// bias decided anything; the winner may still be another page.
    /// </summary>
    BiasApplied,

    /// <summary>A recognised byte-order mark named a different encoding. The mark wins.</summary>
    ContradictedByMark,

    /// <summary>
    /// Structural evidence ruled the hint out: an odd-length buffer hinted as UTF-16, clean
    /// multi-byte UTF-8 hinted as something else, a buffer that fails the hinted family's own
    /// requirements.
    /// </summary>
    ContradictedByStructure,

    /// <summary>
    /// A hint was given but detection did not run — the buffer was over the input budget — so
    /// nothing was learned about it either way. Distinct from <see cref="NotProvided"/> so the
    /// caller's hint is not reported as absent, and from the contradiction outcomes so an
    /// unevaluated hint is never reported as refuted.
    /// </summary>
    NotEvaluated,
}
