namespace ZeroBreach.Diff;

/// <summary>
/// Result state per BLUEPRINT §2. For the diff engine only <see cref="Ok"/> and
/// <see cref="Failed"/> are produced: diffing is a pure structural join with no budget and no
/// partially-parseable input, so there is no truncation path and <see cref="Incomplete"/> is
/// unused. It is kept in the enum so the shape matches the rest of the package.
/// </summary>
public enum OperationState
{
    /// <summary>The diff completed and the answer is trustworthy. Warnings may still be present.</summary>
    Ok,

    /// <summary>Unused by the diff engine; see the type remarks.</summary>
    Incomplete,

    /// <summary>The inputs are not comparable (different machine) or violate the host's id
    /// contract (duplicate ids). No partial output is produced.</summary>
    Failed,
}

/// <summary>One field-level difference on a finding that exists in both runs.</summary>
/// <param name="Field">
/// Which field changed: <c>"category"</c>, <c>"target"</c>, <c>"severity"</c>,
/// <c>"description"</c>, or <c>"property:&lt;key&gt;"</c> for a property-bag entry.
/// </param>
/// <param name="BaselineValue">Value in the baseline; null when the field (a property) was absent there.</param>
/// <param name="CurrentValue">Value in the current run; null when the field (a property) is absent now.</param>
public sealed record FieldChange(
    string Field,
    string? BaselineValue,
    string? CurrentValue);

/// <summary>
/// A finding present in both runs with at least one material difference. Both snapshots are
/// carried so a renderer can show either side without re-joining.
/// </summary>
public sealed record ChangedFinding(
    Finding Baseline,
    Finding Current,
    IReadOnlyList<FieldChange> Changes);

/// <summary>How a check's coverage moved between the two runs.</summary>
public enum CoverageChangeKind
{
    /// <summary>Completed in the baseline, Inconclusive or NotRun now: a regression in visibility.</summary>
    Regression,

    /// <summary>Inconclusive or NotRun in the baseline, Completed now.</summary>
    Improvement,

    /// <summary>Check present in the current inventory but not the baseline's.</summary>
    Added,

    /// <summary>Check present in the baseline inventory but not the current one.</summary>
    Removed,
}

/// <summary>
/// One coverage delta. Coverage is a first-class output: a check that stopped producing
/// trustworthy results is reported even when no finding changed at all, because "nothing new"
/// while checks quietly stopped running is the false all-clear this product exists to avoid.
/// </summary>
/// <param name="CheckId">The check whose coverage changed.</param>
/// <param name="Kind">The classification of the transition.</param>
/// <param name="BaselineStatus">Status in the baseline; null for <see cref="CoverageChangeKind.Added"/>.</param>
/// <param name="BaselineReason">Reason recorded in the baseline, when the host supplied one.</param>
/// <param name="CurrentStatus">Status in the current run; null for <see cref="CoverageChangeKind.Removed"/>.</param>
/// <param name="CurrentReason">Reason recorded in the current run, when the host supplied one.</param>
public sealed record CoverageDelta(
    string CheckId,
    CoverageChangeKind Kind,
    CheckStatus? BaselineStatus,
    string? BaselineReason,
    CheckStatus? CurrentStatus,
    string? CurrentReason);

/// <summary>
/// The full result of diffing a baseline run against a current run. A data structure, not text;
/// rendering is the host's job. Every list is deterministically ordered (ordinal by finding id /
/// check id; warnings in a fixed generation order).
/// </summary>
public sealed record DiffResult
{
    /// <summary>Overall state. On <see cref="OperationState.Failed"/> every list is empty —
    /// a refused diff never carries partial output.</summary>
    public required OperationState State { get; init; }

    /// <summary>Why the diff was refused. Null when <see cref="State"/> is <see cref="OperationState.Ok"/>.</summary>
    public string? Error { get; init; }

    /// <summary>Comparability warnings (stale baseline, clock skew, mode mismatch, narrower
    /// baseline inventory, id-contract anomalies). Always non-null; empty when clean.</summary>
    public required IReadOnlyList<string> Warnings { get; init; }

    /// <summary>Findings whose id appears in the current run but not the baseline.</summary>
    public required IReadOnlyList<Finding> NewFindings { get; init; }

    /// <summary>Findings whose id appears in the baseline but not the current run.</summary>
    public required IReadOnlyList<Finding> ResolvedFindings { get; init; }

    /// <summary>Findings present in both runs with no material change. The current run's
    /// snapshot is reported.</summary>
    public required IReadOnlyList<Finding> PersistingFindings { get; init; }

    /// <summary>Findings present in both runs with at least one material change, with the
    /// field-by-field detail.</summary>
    public required IReadOnlyList<ChangedFinding> ChangedFindings { get; init; }

    /// <summary>Coverage deltas — first-class output, populated even when every finding list
    /// above is empty.</summary>
    public required IReadOnlyList<CoverageDelta> CoverageDeltas { get; init; }

    internal static DiffResult CreateFailed(string error) => new()
    {
        State = OperationState.Failed,
        Error = error,
        Warnings = Array.Empty<string>(),
        NewFindings = Array.Empty<Finding>(),
        ResolvedFindings = Array.Empty<Finding>(),
        PersistingFindings = Array.Empty<Finding>(),
        ChangedFindings = Array.Empty<ChangedFinding>(),
        CoverageDeltas = Array.Empty<CoverageDelta>(),
    };
}
