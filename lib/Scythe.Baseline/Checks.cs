namespace Scythe.Baseline;

/// <summary>Severity of a non-compliant finding. The permitted set; anything outside it is a
/// table-validation error.</summary>
public enum Severity
{
    Low,
    Medium,
    High,
    Critical,
}

/// <summary>Whether a check concerns one setting per machine or one per instance of something
/// (per network interface, per share, per profile).</summary>
public enum CheckInstancing
{
    SingleInstance,
    MultiInstance,
}

/// <summary>
/// What an empty instance collection means for a multi-instance check. No instances found is not
/// obviously compliant and not obviously undetermined — a machine with zero shares trivially
/// satisfies a per-share check, while zero network interfaces on a workstation means the probe
/// went wrong. The answer differs per check, so the field is required per check (validated),
/// with deliberately no default.
/// </summary>
public enum EmptyInstancesRule
{
    EmptyIsCompliant,
    EmptyIsNonCompliant,
    EmptyIsUndetermined,
}

/// <summary>Case sensitivity of string comparison, declared per check rather than assumed:
/// some values are identifiers where case is irrelevant and some are paths where it is not.
/// Comparison is ordinal (or ordinal-ignore-case), never culture-sensitive.</summary>
public enum StringCase
{
    Sensitive,
    Insensitive,
}

/// <summary>
/// Optional applicability predicate: the check applies only when the machine context carries
/// <see cref="ContextKey"/> with a value in <see cref="AnyOf"/>. Key and value matching is
/// ordinal-ignore-case (context properties are role/feature identifiers, not paths).
/// When the predicate is false — including when the key is missing from the context — the
/// check's result is NotApplicable, which counts as neither pass nor failure.
/// </summary>
public sealed record ApplicabilityCondition(string ContextKey, IReadOnlyList<string> AnyOf);

/// <summary>The machine-context record applicability predicates are evaluated against.
/// Supplied by the host; this library never inspects a machine.</summary>
public sealed record MachineContext(IReadOnlyDictionary<string, string> Properties)
{
    public static MachineContext Empty { get; } =
        new(new Dictionary<string, string>());
}

/// <summary>
/// One declarative baseline check: what a setting should be and how to judge it.
/// The table these live in is data edited by people who are not the author of this library,
/// so everything here is validated by <see cref="CheckTableValidator"/> before any evaluation.
/// </summary>
public sealed record BaselineCheck
{
    /// <summary>Stable identifier, unique within the table.</summary>
    public required string Id { get; init; }

    /// <summary>Human-readable title.</summary>
    public required string Title { get; init; }

    /// <summary>The setting this check concerns; the join key into the observations.</summary>
    public required string SettingKey { get; init; }

    /// <summary>Declared type of the setting's value. Observations of a different type make the
    /// check Undetermined — a type mismatch is a collection defect, not evidence either way.</summary>
    public required SettingValueKind ExpectedKind { get; init; }

    public required CheckComparison Comparison { get; init; }

    public required Severity Severity { get; init; }

    /// <summary>Operator-run remediation text. Required non-empty: a finding without a fix is
    /// a puzzle, not a finding.</summary>
    public required string Remediation { get; init; }

    /// <summary>What absence means for this check. Required; no global fallback exists.</summary>
    public required AbsenceRule Absence { get; init; }

    public CheckInstancing Instancing { get; init; } = CheckInstancing.SingleInstance;

    /// <summary>Required when <see cref="Instancing"/> is MultiInstance (validated); ignored
    /// for single-instance checks.</summary>
    public EmptyInstancesRule? EmptyInstances { get; init; }

    /// <summary>Required when <see cref="ExpectedKind"/> is String (validated); ignored for
    /// integer and boolean checks.</summary>
    public StringCase? CaseSensitivity { get; init; }

    /// <summary>Optional; when null the check applies to every machine.</summary>
    public ApplicabilityCondition? AppliesWhen { get; init; }
}

/// <summary>An ordered check table. Output ordering follows table ordering.</summary>
public sealed record CheckTable(IReadOnlyList<BaselineCheck> Checks);
