namespace Scythe.Scoring;

/// <summary>
/// The projection of a run record that the rollup consumes: the check inventory and the
/// findings, reduced to the fields scoring reads.
/// </summary>
/// <remarks>
/// The run record itself is owned by <c>Scythe.Reporting</c> (reference/07.3_record_model.md),
/// which this project does not reference — the README's dependency graph lists no edge, and the
/// integration protocol says to take the data as a parameter rather than stub a project that
/// may not exist yet. This is therefore <b>not</b> a copy of <c>RunRecord</c>: it carries none of
/// the run's identity, times, mode, descriptions, targets or properties, only the identifiers,
/// statuses, reasons and severities the arithmetic needs. A caller holding a <c>RunRecord</c>
/// maps each <c>CheckEntry</c> to a <see cref="CheckInput"/> and each <c>Finding</c> to a
/// <see cref="FindingInput"/>, field for field.
/// </remarks>
public sealed record RollupInput(
    IReadOnlyList<CheckInput> Checks,
    IReadOnlyList<FindingInput> Findings);

/// <summary>One entry of the run's check inventory. Mirrors <c>CheckEntry</c> in the record model.</summary>
/// <param name="Id">Stable across runs and versions. The key every per-check count is ordered by.</param>
/// <param name="Title">Carried into the per-check counts so a report can render them without a second lookup.</param>
/// <param name="Status">What became of the check.</param>
/// <param name="StatusReason">
/// Required by the record model when <paramref name="Status"/> is <see cref="CheckStatus.Inconclusive"/>
/// or <see cref="CheckStatus.Skipped"/>. The rollup treats its absence there as an unfinished
/// coverage statement, not as a malformed record — see <see cref="Rollup.Compute"/>.
/// </param>
public sealed record CheckInput(
    string Id,
    string Title,
    CheckStatus Status,
    string? StatusReason);

/// <summary>One finding. Mirrors the scoring-relevant fields of <c>Finding</c> in the record model.</summary>
/// <param name="Id">Stable. Duplicates are a malformed record.</param>
/// <param name="Severity">Which of the five levels the producing check assigned.</param>
/// <param name="CheckId">The check that produced it. Must name an entry of <see cref="RollupInput.Checks"/>.</param>
public sealed record FindingInput(
    string Id,
    Severity Severity,
    string CheckId);
