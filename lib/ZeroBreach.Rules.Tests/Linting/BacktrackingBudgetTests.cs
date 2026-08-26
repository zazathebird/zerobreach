using ZeroBreach.Rules.Linting;
using Xunit;
using static ZeroBreach.Rules.Tests.Linting.LintTestHelpers;

namespace ZeroBreach.Rules.Tests.Linting;

public class BacktrackingBudgetTests
{
    private static LintResult LintAllow(string jsonPattern) =>
        Lint($$"""{ "fp_allowlists": { "a": ["{{jsonPattern}}"] } }""");

    /// <summary>
    /// The mandatory canary (BLUEPRINT §3): a pattern *known* to be pathological, with an
    /// assertion that it is caught. Without this the whole backtracking section could
    /// silently become a no-op. ^(a+)+$ is the textbook exponential nested quantifier and
    /// was verified to blow a 150 ms budget on this runtime against the bait battery.
    /// </summary>
    [Fact]
    public void CanaryPathologicalPatternIsCaught()
    {
        var finding = LintAllow("^(a+)+$").Single(LintCode.CatastrophicBacktracking);
        Assert.Equal(LintSeverity.Error, finding.Severity);
        Assert.Contains("denial of service", finding.Message);
        Assert.Contains("ms match budget", finding.Message);
    }

    [Theory]
    [InlineData("^(a|aa)+$")]        // overlapping alternation under a quantifier
    [InlineData("^(.*a){20}$")]      // polynomial blow-up, not just exponential
    [InlineData("^([a-z]+)*!$")]     // nested quantifier over a class
    [InlineData("^(\\\\d+)*x$")]     // digit-hungry variant (JSON-decodes to ^(\d+)*x$)
    public void KnownPathologicalShapesAreCaught(string jsonPattern)
    {
        Assert.Single(LintAllow(jsonPattern).WithCode(LintCode.CatastrophicBacktracking));
    }

    [Theory]
    [InlineData("^C:\\\\Program Files\\\\Vendor\\\\.*$")]
    [InlineData("^[0-9a-f]{64}$")]
    [InlineData("^(alpha|beta|gamma)_tool$")]
    public void HealthyPatternsStayInsideTheBudget(string jsonPattern)
    {
        LintAllow(jsonPattern).AssertNone(LintCode.CatastrophicBacktracking);
    }

    [Fact]
    public void ACaughtPatternIsNotProbedFurther()
    {
        // A pattern that blew the budget must not burn it again on every canary and
        // corpus probe: the universal-allowlist check is skipped for it.
        var result = LintAllow("^(a+)+$");
        result.AssertNone(LintCode.UniversalAllowlist);
    }

    [Fact]
    public void TheBaitBatteryStaysVaried()
    {
        // Same pattern as the canary/corpus variety tests: the battery is the check.
        Assert.True(BacktrackingProbe.Baits.Count >= 7);
        Assert.Contains(BacktrackingProbe.Baits, b => b.Contains("aaaa"));
        Assert.Contains(BacktrackingProbe.Baits, b => b.Contains("1111"));
        Assert.Contains(BacktrackingProbe.Baits, b => b.Contains("abab"));
        Assert.Contains(BacktrackingProbe.Baits, b => b.Contains("    "));
        Assert.Contains(BacktrackingProbe.Baits, b => b.Contains(@"\aaaaaaaa"));
        Assert.All(BacktrackingProbe.Baits, b => Assert.True(b.Length >= BacktrackingProbe.BaitLength));
    }

    [Fact]
    public void ExhaustingTheTotalDeadlineIsIncompleteNeverSilentlyShorter()
    {
        var options = new LintOptions { TotalDeadline = TimeSpan.Zero };
        var result = Lint("""{ "s": ["some_pattern_aaaa"] }""", options);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("budget", result.Reason!);
        Assert.Contains("0 of 1", result.Reason!);
    }

    [Fact]
    public void AZeroDeadlineStillReportsStructuralFindings()
    {
        // Findings gathered before the cut are returned with the Incomplete state —
        // partial coverage is reported honestly, not discarded and not passed off as Ok.
        var options = new LintOptions { TotalDeadline = TimeSpan.Zero };
        var result = Lint("""{ "empty_one": [] }""", options);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Single(result.WithCode(LintCode.EmptyIndicatorSet));
    }

    [Fact]
    public void OversizedInputIsRefusedAsIncomplete()
    {
        string big = "\"" + new string('x', (int)(LintDefaults.MaxInputBytes / 2)) + "\"";
        var result = RuleFileLinter.Lint(big, FileName);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("larger than", result.Reason!);
        Assert.Empty(result.Findings);
    }
}
