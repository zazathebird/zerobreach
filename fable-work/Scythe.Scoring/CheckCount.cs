namespace Scythe.Scoring;

/// <summary>
/// One check of the inventory with its status and how many findings it produced. Every check in
/// the inventory appears, zero-count entries included, ordered by <see cref="CheckId"/> ordinally.
/// </summary>
/// <param name="CheckId">The inventory identifier.</param>
/// <param name="Title">Carried from the inventory for rendering.</param>
/// <param name="Status">What became of the check. A zero finding count means nothing only when this is <see cref="CheckStatus.Completed"/>.</param>
/// <param name="StatusReason">The reason the inventory gave, whitespace-trimmed; null when none was given or the status needs none.</param>
/// <param name="FindingCount">Findings whose <c>CheckId</c> is this check.</param>
/// <param name="HighestSeverity">The highest severity among those findings; null when there are none. Null, not a level, so absence cannot be mistaken for <see cref="Severity.Informational"/>.</param>
public sealed record CheckCount(
    string CheckId,
    string Title,
    CheckStatus Status,
    string? StatusReason,
    int FindingCount,
    Severity? HighestSeverity);
