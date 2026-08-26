namespace ZeroBreach.Rules.Sigma;

/// <summary>A compile-time problem in a Sigma rule, with its source name and 1-based
/// position. These messages are read by a technician at a client's desk — they name the
/// offending construct, not just "parse error".</summary>
public sealed record SigmaDiagnostic(string Source, string Message, int Line, int Column)
{
    public override string ToString() => $"{Source}: {Message} (line {Line}, column {Column})";
}

/// <summary>
/// A rule's logsource, or the logsource of the record being scanned. A component the rule
/// leaves null is a wildcard: the rule applies regardless of that component.
/// </summary>
public sealed record SigmaLogsource(string? Product = null, string? Category = null, string? Service = null)
{
    public static readonly SigmaLogsource Any = new();

    /// <summary>True when this rule's logsource applies to a record from
    /// <paramref name="recordSource"/>. Every component the rule specifies must equal the
    /// record's component, case-insensitively; a record component that is null cannot
    /// satisfy a rule that names one.</summary>
    public bool Matches(SigmaLogsource recordSource)
    {
        return ComponentMatches(Product, recordSource.Product)
            && ComponentMatches(Category, recordSource.Category)
            && ComponentMatches(Service, recordSource.Service);

        static bool ComponentMatches(string? required, string? actual) =>
            required is null || string.Equals(required, actual, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Evaluation-time options. <see cref="FieldNameMap"/> is the single mapping table from
/// Sigma rule field names to the host's record field names (task brief A5's open question:
/// by default the host is assumed to supply Sigma's standard Windows field names, so no
/// map is applied and lookup is a direct case-insensitive name match).
/// </summary>
public sealed class SigmaEvaluationOptions
{
    /// <summary>Rule field name → record field name. Keys compare case-insensitively.
    /// Null means identity: rule names are looked up in the record directly.</summary>
    public IReadOnlyDictionary<string, string>? FieldNameMap { get; init; }
}

/// <summary>Outcome of evaluating one rule against one record. <see cref="IsMatch"/> is
/// meaningful only when <see cref="State"/> is <see cref="OperationState.Ok"/> — an
/// Incomplete rule has no trustworthy match state and must never be read as "no match".</summary>
public sealed class SigmaRuleResult
{
    public required OperationState State { get; init; }
    public required bool IsMatch { get; init; }
    public string? Reason { get; init; }
    public required string RuleTitle { get; init; }
    public string? RuleId { get; init; }

    /// <summary>False when the rule was skipped because its logsource does not apply to
    /// the record (State is Ok, IsMatch is false — the rule genuinely does not fire).</summary>
    public bool LogsourceMatched { get; init; } = true;
}

/// <summary>Result of compiling one Sigma rule. Failed means <see cref="Rule"/> is null:
/// a malformed rule never becomes "a rule that matches nothing".</summary>
public sealed class SigmaCompileResult
{
    public required OperationState State { get; init; }
    public string? Reason { get; init; }
    public CompiledSigmaRule? Rule { get; init; }
    public required IReadOnlyList<SigmaDiagnostic> Diagnostics { get; init; }
}
