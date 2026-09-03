namespace Scythe.Scoring;

/// <summary>Which part of the composition a contribution came from.</summary>
public enum ContributionKind
{
    /// <summary>The top of the range, before anything is taken off. Always first, always +100.</summary>
    Baseline = 0,

    /// <summary>Findings at one severity level: count × weight, taken off.</summary>
    Findings = 1,

    /// <summary>
    /// The weighted findings exceeded the range, and the deduction stopped at the floor. Present
    /// only when it happened, so the report can say that findings alone accounted for everything.
    /// </summary>
    FindingsSaturation = 2,

    /// <summary>
    /// Inconclusive coverage: the amount by which the score after findings was scaled down to the
    /// share of attempted checks that completed. Always present, last, so a low score from
    /// coverage and a low score from findings are never confused.
    /// </summary>
    Coverage = 3,
}

/// <summary>
/// One stated step in the composition of a <see cref="CleanlinessScore"/>. The contributions of
/// a score sum exactly to its value; a technician asked "why is this an 80?" reads them off.
/// </summary>
/// <param name="Kind">Where it came from.</param>
/// <param name="Severity">The level, for <see cref="ContributionKind.Findings"/>; null for the others.</param>
/// <param name="Count">Findings at that level, or attempted checks left inconclusive for <see cref="ContributionKind.Coverage"/>; zero for the baseline.</param>
/// <param name="Effect">Signed points. Positive for the baseline and for a saturation give-back; otherwise zero or negative. A <see cref="long"/> because a per-severity deduction is count × weight before the floor is applied, and an absurd count must not overflow it.</param>
/// <param name="Detail">The arithmetic in words, e.g. <c>2 High findings × 15 points</c>.</param>
public sealed record ScoreContribution(
    ContributionKind Kind,
    Severity? Severity,
    int Count,
    long Effect,
    string Detail);
