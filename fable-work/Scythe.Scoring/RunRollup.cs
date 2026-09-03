namespace Scythe.Scoring;

/// <summary>
/// The numbers at the top of the report: counts by severity, counts by check, the coverage
/// statement and the score with its contributions. Everything in it is ordered by a stated key.
/// </summary>
/// <param name="SeverityCounts">One per <see cref="Severity"/> level, highest first, zero counts included.</param>
/// <param name="CheckCounts">One per inventory check, by check id ordinally, zero counts included.</param>
/// <param name="TotalFindings">All findings, whatever their severity or producing check.</param>
/// <param name="Coverage">What was looked at. Beside the score, not inside it.</param>
/// <param name="Score">What was found, with why.</param>
public sealed record RunRollup(
    IReadOnlyList<SeverityCount> SeverityCounts,
    IReadOnlyList<CheckCount> CheckCounts,
    int TotalFindings,
    CoverageStatement Coverage,
    CleanlinessScore Score);
