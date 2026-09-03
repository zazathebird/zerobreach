namespace Scythe.Scoring;

/// <summary>
/// How many findings the record holds at one severity. One entry per level of
/// <see cref="Scoring.Severity"/> is always present, zero-count entries included: a report that
/// silently omits "0 critical" reads as though the question was not asked.
/// </summary>
/// <param name="Severity">The level.</param>
/// <param name="Count">Findings at that level. Zero is a real answer and is reported as one.</param>
/// <param name="Weight">Points each finding at this level deducts, from <see cref="ScoreWeights"/>, so the report can explain the arithmetic beside the count.</param>
public sealed record SeverityCount(
    Severity Severity,
    int Count,
    int Weight);
