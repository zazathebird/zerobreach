namespace ZeroBreach.Diff;

/// <summary>Outcome of a single check within one run.</summary>
public enum CheckStatus
{
    /// <summary>The check ran to completion; its findings (or absence of findings) are trustworthy.</summary>
    Completed,

    /// <summary>The check ran but could not produce a trustworthy answer.</summary>
    Inconclusive,

    /// <summary>The check did not run at all in this scan.</summary>
    NotRun,
}

/// <summary>
/// One entry in a run's check inventory: which check, how it ended, and — for anything other
/// than a clean completion — why, when the host recorded a reason.
/// </summary>
public sealed record CheckResult(
    string CheckId,
    CheckStatus Status,
    string? Reason = null);

/// <summary>Severity assigned to a finding by the host.</summary>
public enum FindingSeverity
{
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// <summary>
/// One finding from a run. <see cref="Id"/> is the host-computed stable identity — a hash over
/// category, target and a discriminator — and is the join key for diffing; the same artifact on
/// the same machine yields the same id across runs (BLUEPRINT §11).
/// </summary>
/// <param name="Id">Host-computed stable identity. Opaque to this layer; compared ordinally.</param>
/// <param name="Category">What kind of finding this is (e.g. "autorun", "yara-match").</param>
/// <param name="Target">What the finding is about (a path, a registry value, ...).</param>
/// <param name="Severity">Host-assigned severity.</param>
/// <param name="Description">Human-readable description.</param>
/// <param name="Properties">
/// Extensible bag of additional fields the host attaches (hashes, signer names, ...). Null is
/// treated as empty. Keys and values are compared ordinally for change detection.
/// </param>
public sealed record Finding(
    string Id,
    string Category,
    string Target,
    FindingSeverity Severity,
    string Description,
    IReadOnlyDictionary<string, string>? Properties = null);

/// <summary>
/// The record of one audit run against one machine: identity, when it ran, which scan mode was
/// requested, which checks were attempted and how they ended, and what was found.
/// </summary>
/// <param name="MachineId">Host-assigned machine identity. Opaque to this layer; compared ordinally.</param>
/// <param name="Timestamp">When the run was taken. Used only for staleness / skew warnings, never in deltas.</param>
/// <param name="ScanMode">Name of the scan mode (e.g. "quick", "deep"). Informational; comparability
/// is judged from the check inventory, not from this string.</param>
/// <param name="Checks">The check inventory. Check ids must be unique within one record.</param>
/// <param name="Findings">The findings. Finding ids must be unique within one record.</param>
public sealed record RunRecord(
    string MachineId,
    DateTimeOffset Timestamp,
    string ScanMode,
    IReadOnlyList<CheckResult> Checks,
    IReadOnlyList<Finding> Findings);
