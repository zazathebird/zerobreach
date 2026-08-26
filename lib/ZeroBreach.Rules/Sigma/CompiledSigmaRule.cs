namespace ZeroBreach.Rules.Sigma;

/// <summary>
/// One compiled Sigma rule, ready to evaluate against event records. Immutable and
/// thread-safe: all per-evaluation state lives in the evaluation context.
/// </summary>
public sealed class CompiledSigmaRule
{
    private readonly DetectionItem[] _items;
    private readonly ConditionNode _condition;

    internal CompiledSigmaRule(
        string title,
        string? id,
        string? level,
        string? status,
        SigmaLogsource logsource,
        IReadOnlyList<string> tags,
        IReadOnlyList<string> fields,
        DetectionItem[] items,
        ConditionNode condition,
        string? aggregationText,
        string? timeframe)
    {
        Title = title;
        Id = id;
        Level = level;
        Status = status;
        Logsource = logsource;
        Tags = tags;
        Fields = fields;
        _items = items;
        _condition = condition;
        AggregationText = aggregationText;
        Timeframe = timeframe;
    }

    public string Title { get; }
    public string? Id { get; }
    public string? Level { get; }
    public string? Status { get; }
    public SigmaLogsource Logsource { get; }
    public IReadOnlyList<string> Tags { get; }
    public IReadOnlyList<string> Fields { get; }

    /// <summary>The aggregation part of the condition (after '|'), when present. Parsed
    /// and kept, but not evaluated: see <see cref="RequiresCorrelation"/>.</summary>
    public string? AggregationText { get; }

    /// <summary>The detection's <c>timeframe</c>, when present. Kept, not evaluated.</summary>
    public string? Timeframe { get; }

    /// <summary>True when the rule needs cross-record correlation (aggregation and/or
    /// timeframe) that this per-record engine does not perform. Such a rule evaluates to
    /// Incomplete — a per-record answer would be confidently wrong (task brief A5).</summary>
    public bool RequiresCorrelation => AggregationText is not null || Timeframe is not null;

    /// <summary>Names of the detection items, in declaration order (diagnostic aid).</summary>
    public IReadOnlyList<string> SelectionNames => _items.Select(i => i.Name).ToArray();

    /// <summary>
    /// Evaluates this rule against one event record. Field-name lookup is
    /// case-insensitive (via <paramref name="options"/>' field-name map when set). When
    /// <paramref name="recordLogsource"/> is supplied and the rule's logsource does not
    /// apply, the result is Ok/no-match with <see cref="SigmaRuleResult.LogsourceMatched"/>
    /// false. Budget exhaustion — wall clock or input size — yields Incomplete with the
    /// reason, never a silent no-match.
    /// </summary>
    public SigmaRuleResult Evaluate(
        IReadOnlyDictionary<string, object?> record,
        SigmaLogsource? recordLogsource = null,
        ScanBudget? budget = null,
        SigmaEvaluationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(record);
        budget ??= ScanBudget.Default;

        if (recordLogsource is not null && !Logsource.Matches(recordLogsource))
        {
            return new SigmaRuleResult
            {
                State = OperationState.Ok,
                IsMatch = false,
                RuleTitle = Title,
                RuleId = Id,
                LogsourceMatched = false,
            };
        }

        if (RequiresCorrelation)
        {
            string what = AggregationText is not null
                ? $"aggregation '{AggregationText}'"
                : $"timeframe '{Timeframe}'";
            return new SigmaRuleResult
            {
                State = OperationState.Incomplete,
                IsMatch = false,
                Reason = $"rule requires {what}, which this engine does not evaluate; a per-record answer would not be trustworthy",
                RuleTitle = Title,
                RuleId = Id,
            };
        }

        var ctx = new SigmaEvalContext(record, options, budget, _items.Length);
        if (ctx.InputOverBudgetReason is string overBudget)
        {
            return new SigmaRuleResult
            {
                State = OperationState.Incomplete,
                IsMatch = false,
                Reason = overBudget,
                RuleTitle = Title,
                RuleId = Id,
            };
        }

        var outcome = _condition.Evaluate(ctx);
        if (outcome.IsIncomplete)
        {
            return new SigmaRuleResult
            {
                State = OperationState.Incomplete,
                IsMatch = false,
                Reason = outcome.Reason,
                RuleTitle = Title,
                RuleId = Id,
            };
        }
        return new SigmaRuleResult
        {
            State = OperationState.Ok,
            IsMatch = outcome.IsTrue,
            RuleTitle = Title,
            RuleId = Id,
        };
    }
}
