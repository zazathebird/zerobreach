using System.Diagnostics;

namespace Scythe.Rules.Sigma;

/// <summary>
/// Per-evaluation state: a case-insensitive snapshot of the record's fields (stringified
/// once), the flattened value list for keyword selections, the optional rule→record field
/// name map, the wall-clock budget, and memoised detection-item results.
/// </summary>
internal sealed class SigmaEvalContext
{
    private readonly record struct Slot(string OriginalKey, string?[] Values);

    private readonly Dictionary<string, Slot> _fields;
    private readonly Dictionary<string, string>? _nameMap;
    private readonly Stopwatch _clock;
    private readonly TimeSpan _deadline;

    /// <summary>Every value of every field, for keyword (unbound) selections. Ordered by
    /// ordinal field name so the snapshot itself is deterministic regardless of the
    /// record dictionary's enumeration order.</summary>
    public string?[] AllValues { get; }

    /// <summary>Memoised per-item results, indexed by <see cref="DetectionItem.Index"/>.
    /// An item referenced twice in the condition is evaluated once.</summary>
    public TriState?[] ItemResults { get; }

    /// <summary>Non-null when the record itself blows <see cref="ScanBudget.MaxInputBytes"/>;
    /// evaluation must not proceed on a truncated view, so the rule reports Incomplete.</summary>
    public string? InputOverBudgetReason { get; }

    public SigmaEvalContext(
        IReadOnlyDictionary<string, object?> record,
        SigmaEvaluationOptions? options,
        ScanBudget budget,
        int itemCount)
    {
        _clock = Stopwatch.StartNew();
        _deadline = budget.Deadline;
        ItemResults = new TriState?[itemCount];

        // Snapshot the record once. Field lookup is case-insensitive; when two record
        // keys collide case-insensitively the ordinal-smaller key wins, so the outcome
        // does not depend on the caller's dictionary enumeration order (determinism).
        _fields = new Dictionary<string, Slot>(record.Count, StringComparer.OrdinalIgnoreCase);
        long inputChars = 0;
        foreach (var kvp in record)
        {
            string?[] values = Flatten(kvp.Value);
            foreach (var v in values)
            {
                inputChars += v?.Length ?? 0;
            }
            if (_fields.TryGetValue(kvp.Key, out var existing))
            {
                if (string.CompareOrdinal(kvp.Key, existing.OriginalKey) < 0)
                {
                    _fields[kvp.Key] = new Slot(kvp.Key, values);
                }
            }
            else
            {
                _fields[kvp.Key] = new Slot(kvp.Key, values);
            }
        }

        // UTF-16 chars are two bytes each; that is the memory the snapshot actually holds.
        long inputBytes = inputChars * 2;
        if (inputBytes > budget.MaxInputBytes)
        {
            InputOverBudgetReason =
                $"record exceeds the input budget ({inputBytes} bytes of field values > {budget.MaxInputBytes})";
        }

        var all = new List<string?>();
        foreach (var key in _fields.Keys.Order(StringComparer.Ordinal))
        {
            all.AddRange(_fields[key].Values);
        }
        AllValues = all.ToArray();

        if (options?.FieldNameMap is { } map)
        {
            _nameMap = new Dictionary<string, string>(map.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in map)
            {
                // Same ordinal-smallest-key-wins rule as the record snapshot, for the
                // same determinism reason.
                if (!_nameMap.TryGetValue(kvp.Key, out _)
                    || string.CompareOrdinal(kvp.Key, FindExistingMapKey(kvp.Key)) < 0)
                {
                    _nameMap[kvp.Key] = kvp.Value;
                }
            }
        }
    }

    private string FindExistingMapKey(string key)
    {
        // Recover the original-cased key already stored under this case-insensitive slot.
        foreach (var k in _nameMap!.Keys)
        {
            if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase))
            {
                return k;
            }
        }
        return key;
    }

    /// <summary>A record value that is a collection (and not a string/char[]) is a
    /// multi-valued field — common for fields like Hashes — and a match against any one
    /// element is a match on the field.</summary>
    private static string?[] Flatten(object? value)
    {
        if (value is System.Collections.IEnumerable e and not string and not char[])
        {
            var list = new List<string?>();
            foreach (var element in e)
            {
                list.Add(SigmaText.Stringify(element));
            }
            return list.ToArray();
        }
        return [SigmaText.Stringify(value)];
    }

    /// <summary>Non-null reason when the wall-clock deadline is exhausted. Checked at
    /// every field test and keyword sweep so a stalled evaluation surfaces as Incomplete
    /// rather than running unboundedly.</summary>
    public string? BudgetExceededReason() =>
        _clock.Elapsed > _deadline
            ? $"time budget of {_deadline.TotalMilliseconds:0}ms exceeded during evaluation"
            : null;

    /// <summary>Case-insensitive field lookup, via the field-name map when one is set.
    /// Returns false when the field is missing — which is not a match for any value test,
    /// including the null test (missing is distinct from present-with-null).</summary>
    public bool TryGetField(string ruleFieldName, out string?[] values)
    {
        string lookupName = ruleFieldName;
        if (_nameMap is not null && _nameMap.TryGetValue(ruleFieldName, out string? mapped))
        {
            lookupName = mapped;
        }
        if (_fields.TryGetValue(lookupName, out var slot))
        {
            values = slot.Values;
            return true;
        }
        values = [];
        return false;
    }
}

/// <summary>
/// One <c>Field|modifiers: value(s)</c> entry. Values are OR-linked by default; the
/// <c>all</c> modifier switches the linkage to AND. A missing field is false for every
/// linkage — it can never satisfy a test.
/// </summary>
internal sealed class FieldTest
{
    public required string FieldName { get; init; }
    public required bool MatchAll { get; init; }
    public required ValueMatcher[] Matchers { get; init; }

    public TriState Evaluate(SigmaEvalContext ctx)
    {
        if (ctx.BudgetExceededReason() is string over)
        {
            return TriState.Incomplete(over);
        }
        if (!ctx.TryGetField(FieldName, out string?[] values))
        {
            return TriState.False;
        }
        if (MatchAll)
        {
            // Kleene AND across matchers: a definite false wins outright; otherwise any
            // Incomplete taints the conjunction.
            string? incomplete = null;
            foreach (var m in Matchers)
            {
                var r = AnyValue(m, values);
                if (r.IsFalse)
                {
                    return TriState.False;
                }
                if (r.IsIncomplete)
                {
                    incomplete ??= r.Reason;
                }
            }
            return incomplete is null ? TriState.True : TriState.Incomplete(incomplete);
        }
        else
        {
            string? incomplete = null;
            foreach (var m in Matchers)
            {
                var r = AnyValue(m, values);
                if (r.IsTrue)
                {
                    return TriState.True;
                }
                if (r.IsIncomplete)
                {
                    incomplete ??= r.Reason;
                }
            }
            return incomplete is null ? TriState.False : TriState.Incomplete(incomplete);
        }
    }

    /// <summary>A multi-valued field matches when any element matches (Kleene OR over the
    /// elements: a definite hit wins, an Incomplete element taints a miss).</summary>
    internal static TriState AnyValue(ValueMatcher matcher, string?[] values)
    {
        string? incomplete = null;
        foreach (var v in values)
        {
            var r = matcher.Matches(v);
            if (r.IsTrue)
            {
                return TriState.True;
            }
            if (r.IsIncomplete)
            {
                incomplete ??= r.Reason;
            }
        }
        return incomplete is null ? TriState.False : TriState.Incomplete(incomplete);
    }
}

/// <summary>A named entry of the <c>detection</c> mapping (everything except
/// <c>condition</c>/<c>timeframe</c>). Results are memoised per evaluation.</summary>
internal abstract class DetectionItem
{
    public required string Name { get; init; }

    /// <summary>Declaration index within the detection mapping; also the memo slot.</summary>
    public required int Index { get; init; }

    public TriState Evaluate(SigmaEvalContext ctx)
    {
        if (ctx.ItemResults[Index] is TriState memo)
        {
            return memo;
        }
        var result = EvaluateCore(ctx);
        ctx.ItemResults[Index] = result;
        return result;
    }

    protected abstract TriState EvaluateCore(SigmaEvalContext ctx);
}

/// <summary>A selection written as a mapping (AND across its field tests), or as a list
/// of mappings (OR across the mappings).</summary>
internal sealed class MapDetectionItem : DetectionItem
{
    public required FieldTest[][] Groups { get; init; }

    protected override TriState EvaluateCore(SigmaEvalContext ctx)
    {
        string? incomplete = null;
        foreach (var group in Groups)
        {
            var groupResult = EvaluateGroup(group, ctx);
            if (groupResult.IsTrue)
            {
                return TriState.True;
            }
            if (groupResult.IsIncomplete)
            {
                incomplete ??= groupResult.Reason;
            }
        }
        return incomplete is null ? TriState.False : TriState.Incomplete(incomplete);
    }

    private static TriState EvaluateGroup(FieldTest[] group, SigmaEvalContext ctx)
    {
        string? incomplete = null;
        foreach (var test in group)
        {
            var r = test.Evaluate(ctx);
            if (r.IsFalse)
            {
                return TriState.False;
            }
            if (r.IsIncomplete)
            {
                incomplete ??= r.Reason;
            }
        }
        return incomplete is null ? TriState.True : TriState.Incomplete(incomplete);
    }
}

/// <summary>A selection written as a list of scalars ("keywords"): it matches when any
/// keyword matches any field value of the record, with contains semantics.</summary>
internal sealed class KeywordDetectionItem : DetectionItem
{
    public required ValueMatcher[] Keywords { get; init; }

    protected override TriState EvaluateCore(SigmaEvalContext ctx)
    {
        if (ctx.BudgetExceededReason() is string over)
        {
            return TriState.Incomplete(over);
        }
        string? incomplete = null;
        foreach (var keyword in Keywords)
        {
            var r = FieldTest.AnyValue(keyword, ctx.AllValues);
            if (r.IsTrue)
            {
                return TriState.True;
            }
            if (r.IsIncomplete)
            {
                incomplete ??= r.Reason;
            }
        }
        return incomplete is null ? TriState.False : TriState.Incomplete(incomplete);
    }
}
