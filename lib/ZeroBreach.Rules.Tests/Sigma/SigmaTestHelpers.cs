using ZeroBreach.Rules;
using ZeroBreach.Rules.Sigma;
using Xunit;

namespace ZeroBreach.Rules.Tests.Sigma;

internal static class SigmaTestHelpers
{
    /// <summary>Compiles and asserts success, surfacing the compiler's reason on failure
    /// so a broken fixture is diagnosable from the test output.</summary>
    public static CompiledSigmaRule MustCompile(string yaml)
    {
        var result = SigmaCompiler.Compile(yaml, "test.yml");
        Assert.True(result.State == OperationState.Ok, $"expected Ok compile, got {result.State}: {result.Reason}");
        Assert.NotNull(result.Rule);
        Assert.Empty(result.Diagnostics);
        return result.Rule!;
    }

    /// <summary>Compiles and asserts a loud failure: Failed state, no rule object at all
    /// (a malformed rule must never become "a rule that matches nothing"), and a
    /// diagnostic with a position.</summary>
    public static SigmaDiagnostic MustFail(string yaml)
    {
        var result = SigmaCompiler.Compile(yaml, "test.yml");
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Null(result.Rule);
        Assert.NotNull(result.Reason);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.True(diagnostic.Line >= 1);
        Assert.True(diagnostic.Column >= 1);
        return diagnostic;
    }

    public static Dictionary<string, object?> Record(params (string Key, object? Value)[] fields)
    {
        var record = new Dictionary<string, object?>();
        foreach (var (key, value) in fields)
        {
            record[key] = value;
        }
        return record;
    }

    public static SigmaRuleResult Eval(CompiledSigmaRule rule, params (string Key, object? Value)[] fields) =>
        rule.Evaluate(Record(fields));

    public static void AssertHit(CompiledSigmaRule rule, params (string Key, object? Value)[] fields)
    {
        var result = Eval(rule, fields);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.True(result.IsMatch, $"expected a match for rule '{rule.Title}'");
    }

    public static void AssertMiss(CompiledSigmaRule rule, params (string Key, object? Value)[] fields)
    {
        var result = Eval(rule, fields);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.False(result.IsMatch, $"expected no match for rule '{rule.Title}'");
    }

    public static string AssertIncomplete(CompiledSigmaRule rule, params (string Key, object? Value)[] fields)
    {
        var result = Eval(rule, fields);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.False(result.IsMatch);
        Assert.NotNull(result.Reason);
        return result.Reason!;
    }
}
