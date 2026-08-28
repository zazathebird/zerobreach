using Scythe.Rules;
using Scythe.Rules.Sigma;
using Xunit;
using static Scythe.Rules.Tests.Sigma.SigmaTestHelpers;

namespace Scythe.Rules.Tests.Sigma;

/// <summary>
/// Budget behaviour and tri-state discipline. Incomplete must never collapse into Ok or
/// into false: an attacker who can stall the evaluation must not be able to convert the
/// stall into a clean verdict.
/// </summary>
public sealed class SigmaBudgetTests
{
    /// <summary>A regex that is *known* pathological under a backtracking engine: nested
    /// quantifier, then a forced failure at the end of the input. This is the section's
    /// canary — if budget enforcement silently becomes a no-op, this test hangs or fails.</summary>
    private const string PathologicalRegex = "(a+)+$";

    private static string PathologicalInput() => new string('a', 64) + "!";

    [Fact]
    public void PathologicalRegex_BlowsItsBudget_AndReportsIncomplete_NotFalse()
    {
        var rule = MustCompile(
            "title: Canary\nlogsource:\n  product: windows\ndetection:\n" +
            $"  sel:\n    CommandLine|re: '{PathologicalRegex}'\n  condition: sel");
        string reason = AssertIncomplete(rule, ("CommandLine", PathologicalInput()));
        Assert.Contains("budget", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PathologicalRegex_OnBenignInput_StillAnswersOk()
    {
        // The budget cuts off the blow-up, not the feature: the same rule on input the
        // regex resolves quickly must stay Ok.
        var rule = MustCompile(
            "title: Canary\nlogsource:\n  product: windows\ndetection:\n" +
            $"  sel:\n    CommandLine|re: '{PathologicalRegex}'\n  condition: sel");
        AssertHit(rule, ("CommandLine", "aaa"));
    }

    [Fact]
    public void ZeroDeadline_YieldsIncomplete_WithReason()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n  sel:\n    A: 1\n  condition: sel");
        var budget = ScanBudget.Default with { Deadline = TimeSpan.Zero };
        var result = rule.Evaluate(Record(("A", 1)), budget: budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.False(result.IsMatch);
        Assert.Contains("time budget", result.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public void OversizedRecord_YieldsIncomplete_NotATruncatedScan()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n  sel:\n    A: 1\n  condition: sel");
        var budget = ScanBudget.Default with { MaxInputBytes = 64 };
        var result = rule.Evaluate(
            Record(("A", 1), ("Blob", new string('x', 4096))), budget: budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.False(result.IsMatch);
        Assert.Contains("input budget", result.Reason!, StringComparison.Ordinal);
    }

    // ---- Kleene logic: definite answers may not depend on Incomplete sub-results ------

    private static CompiledSigmaRule SlowAndOther(string condition) => MustCompile(
        "title: T\nlogsource:\n  product: windows\ndetection:\n" +
        $"  slow:\n    Payload|re: '{PathologicalRegex}'\n" +
        "  hit:\n    A: 1\n" +
        $"  condition: {condition}");

    [Fact]
    public void IncompleteAndFalse_IsOkFalse()
    {
        // false AND x is false whatever x turns out to be — the definite answer is sound
        // and must be reported as Ok, not degraded to Incomplete.
        var rule = SlowAndOther("slow and hit");
        var result = rule.Evaluate(Record(("Payload", PathologicalInput()), ("A", 999)));
        Assert.Equal(OperationState.Ok, result.State);
        Assert.False(result.IsMatch);
    }

    [Fact]
    public void IncompleteOrTrue_IsOkTrue()
    {
        var rule = SlowAndOther("slow or hit");
        var result = rule.Evaluate(Record(("Payload", PathologicalInput()), ("A", 1)));
        Assert.Equal(OperationState.Ok, result.State);
        Assert.True(result.IsMatch);
    }

    [Fact]
    public void IncompleteAndTrue_StaysIncomplete()
    {
        // The conjunction's answer genuinely depends on the regex that could not run.
        var rule = SlowAndOther("slow and hit");
        var result = rule.Evaluate(Record(("Payload", PathologicalInput()), ("A", 1)));
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.False(result.IsMatch);
        Assert.NotNull(result.Reason);
    }

    [Fact]
    public void IncompleteOrFalse_StaysIncomplete()
    {
        var rule = SlowAndOther("slow or hit");
        var result = rule.Evaluate(Record(("Payload", PathologicalInput()), ("A", 999)));
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.False(result.IsMatch);
    }

    [Fact]
    public void NotIncomplete_StaysIncomplete()
    {
        // Negating an unknown must not manufacture a confident verdict in either direction.
        var rule = SlowAndOther("hit and not slow");
        var result = rule.Evaluate(Record(("Payload", PathologicalInput()), ("A", 1)));
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.False(result.IsMatch);
    }

    [Fact]
    public void QuantifierOverIncomplete_IsIncompleteOnlyWhenTheAnswerDependsOnIt()
    {
        // 1 of them: 'hit' already satisfies the threshold — Ok true despite 'slow'.
        var satisfied = SlowAndOther("1 of them").Evaluate(
            Record(("Payload", PathologicalInput()), ("A", 1)));
        Assert.Equal(OperationState.Ok, satisfied.State);
        Assert.True(satisfied.IsMatch);

        // 2 of them: the answer depends on the selection that could not run.
        var depends = SlowAndOther("2 of them").Evaluate(
            Record(("Payload", PathologicalInput()), ("A", 1)));
        Assert.Equal(OperationState.Incomplete, depends.State);
        Assert.False(depends.IsMatch);
    }

    // ---- aggregation / timeframe ------------------------------------------------------

    [Fact]
    public void AggregationCondition_CompilesButEvaluatesIncomplete()
    {
        var result = SigmaCompiler.Compile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  selection:\n    EventID: 4625\n" +
            "  condition: selection | count() by TargetUserName > 5");
        Assert.Equal(OperationState.Ok, result.State);
        var rule = result.Rule!;
        Assert.True(rule.RequiresCorrelation);
        Assert.Equal("count() by TargetUserName > 5", rule.AggregationText);

        // Even a record that satisfies the base selection must come back Incomplete: a
        // per-record answer to an aggregation rule is confidently wrong in both
        // directions.
        var eval = rule.Evaluate(Record(("EventID", 4625)));
        Assert.Equal(OperationState.Incomplete, eval.State);
        Assert.False(eval.IsMatch);
        Assert.Contains("aggregation", eval.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public void TimeframeRule_CompilesButEvaluatesIncomplete()
    {
        var result = SigmaCompiler.Compile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  selection:\n    EventID: 4625\n" +
            "  timeframe: 5m\n" +
            "  condition: selection");
        Assert.Equal(OperationState.Ok, result.State);
        var rule = result.Rule!;
        Assert.True(rule.RequiresCorrelation);
        Assert.Equal("5m", rule.Timeframe);
        var eval = rule.Evaluate(Record(("EventID", 4625)));
        Assert.Equal(OperationState.Incomplete, eval.State);
        Assert.Contains("timeframe", eval.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public void NearAggregation_IsParsedAndReportedIncomplete()
    {
        var result = SigmaCompiler.Compile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  selection:\n    EventID: 1\n" +
            "  other:\n    EventID: 2\n" +
            "  condition: selection | near other");
        Assert.Equal(OperationState.Ok, result.State);
        var eval = result.Rule!.Evaluate(Record(("EventID", 1)));
        Assert.Equal(OperationState.Incomplete, eval.State);
    }

    [Fact]
    public void LogsourceMismatch_ShortCircuitsBeforeCorrelationIncomplete()
    {
        // A rule that does not apply to the record's source genuinely does not fire —
        // that is a trustworthy Ok/false, even for a correlation rule.
        var result = SigmaCompiler.Compile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  selection:\n    EventID: 4625\n" +
            "  condition: selection | count() > 5");
        var eval = result.Rule!.Evaluate(
            Record(("EventID", 4625)), new SigmaLogsource(Product: "linux"));
        Assert.Equal(OperationState.Ok, eval.State);
        Assert.False(eval.IsMatch);
        Assert.False(eval.LogsourceMatched);
    }
}
