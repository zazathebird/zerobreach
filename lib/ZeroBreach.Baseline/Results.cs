namespace ZeroBreach.Baseline;

/// <summary>Per-check outcome. Undetermined is a distinct result: a setting that could not be
/// read is a gap in what was verified, never a clean bill of health.</summary>
public enum ComplianceStatus
{
    Compliant,
    NonCompliant,
    NotApplicable,
    Undetermined,
}

/// <summary>
/// One problem instance of a multi-instance check: which instance, what was observed there, and
/// why it did not comply (or could not be evaluated). An operator told "one of your nine
/// interfaces is misconfigured" without which one has been given a puzzle, not a finding.
/// </summary>
public sealed record InstanceOutcome(
    string InstanceId,
    ComplianceStatus Status,
    SettingObservation Observation,
    string Reason);

/// <summary>The result of one evaluated check. Every evaluated check appears in the output,
/// passes included; filtering to failures is the caller's choice.</summary>
public sealed record CheckResult
{
    public required string CheckId { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public required ComplianceStatus Status { get; init; }

    /// <summary>Human-readable reason for the status, including observed vs expected.</summary>
    public required string Reason { get; init; }

    /// <summary>Operator remediation text, carried through from the check.</summary>
    public required string Remediation { get; init; }

    /// <summary>The observed value for a single-instance check whose setting was present;
    /// null when absent, read-failed, not applicable, or multi-instance.</summary>
    public SettingValue? ObservedValue { get; init; }

    /// <summary>For multi-instance checks: every instance that was non-compliant or could not
    /// be evaluated, sorted by instance id (ordinal). Empty for compliant checks and for
    /// single-instance checks.</summary>
    public IReadOnlyList<InstanceOutcome> InstanceOutcomes { get; init; } = Array.Empty<InstanceOutcome>();
}

/// <summary>
/// Rollup totals: a separate count per result kind, and nothing else. Deliberately no pass-rate
/// property: any single percentage either absorbs Undetermined into the denominator (hiding a
/// verification gap) or silently drops it. Callers that want a rate must compute it themselves
/// from the counts, with the undetermined count in front of them.
/// </summary>
public sealed record RollupCounts(
    int Compliant,
    int NonCompliant,
    int NotApplicable,
    int Undetermined)
{
    public int Total => Compliant + NonCompliant + NotApplicable + Undetermined;
}

/// <summary>Result state per BLUEPRINT §2. Evaluation is a pure join over already-collected
/// data with no budget-consuming step, so Incomplete is defined for uniformity with the rest of
/// the package but is never produced by this evaluator.</summary>
public enum EvaluationState
{
    Ok,
    Incomplete,
    Failed,
}

/// <summary>One check-table validation error. <see cref="CheckId"/> is null for errors that are
/// not attributable to a single check (e.g. structural loader errors).</summary>
public sealed record CheckTableError(string? CheckId, string Message);

/// <summary>
/// The evaluator's result. When the check table fails validation the state is Failed, the error
/// list says why (with check ids), <see cref="Results"/> is empty and <see cref="Rollup"/> is
/// null: a table that fails validation evaluates nothing, because a check that cannot be
/// evaluated must never count as compliant — and a zeroed rollup could be misread as a clean run.
/// </summary>
public sealed record EvaluationResult
{
    public required EvaluationState State { get; init; }

    /// <summary>Per-check results in table order. Empty when <see cref="State"/> is Failed.</summary>
    public required IReadOnlyList<CheckResult> Results { get; init; }

    /// <summary>Null if and only if <see cref="State"/> is Failed.</summary>
    public RollupCounts? Rollup { get; init; }

    /// <summary>Empty when <see cref="State"/> is Ok.</summary>
    public required IReadOnlyList<CheckTableError> TableErrors { get; init; }
}
