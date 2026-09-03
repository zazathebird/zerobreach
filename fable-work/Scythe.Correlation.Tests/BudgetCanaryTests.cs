using Scythe.Correlation.Tests.Fixtures;
using Xunit;
using static Scythe.Correlation.Tests.Fixtures.CorrelationFixtures;

namespace Scythe.Correlation.Tests;

/// <summary>
/// One canary per budget member that binds, each with its negative control, so that if a guard is
/// refactored into a no-op the suite says so instead of continuing to assert a safety that is
/// not there.
/// </summary>
public sealed class BudgetCanaryTests
{
    [Fact]
    public void DefaultBudgetHasTheValuesTheSharedContractStates()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), ScanBudget.Default.Deadline);
        Assert.Equal(64L * 1024 * 1024, ScanBudget.Default.MaxInputBytes);
        Assert.Equal(10_000, ScanBudget.Default.MaxMatches);
        Assert.Equal(16, ScanBudget.Default.MaxNestingDepth);
    }

    [Fact]
    public void InputPastTheByteBudgetIsIncompleteWithTheBudgetNamed()
    {
        // Reverted form: delete the inputBytes check in ChainBuilder.Build.
        var findings = AllDistinct(3); // ~30 chars each -> well over 16 bytes
        var result = ChainBuilder.Build(findings, ScanBudget.Default with { MaxInputBytes = 16 });

        Assert.Equal(CorrelationResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains("budget allows 16", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void InputExactlyAtTheByteBudgetIsOk()
    {
        var finding = Finding("A", "abcd", EntityReference.Path(@"C:\x")); // (4 + 4) * 2 = 16
        Assert.True(ChainBuilder.Build([finding], ScanBudget.Default with { MaxInputBytes = 16 }).IsOk);
        Assert.Equal(CorrelationResultState.Incomplete, ChainBuilder.Build([finding], ScanBudget.Default with { MaxInputBytes = 15 }).State);
    }

    [Fact]
    public void MoreMentionsThanTheMatchBudgetIsIncompleteNotFewerChains()
    {
        // Reverted form: stop decrementing remainingMatches, or return Ok when it hits zero.
        // The second is the dangerous one — a chain set built from the first N mentions looks
        // exactly like a complete one.
        var findings = new List<FindingReference>
        {
            Finding("A", @"C:\1.exe C:\2.exe C:\3.exe"),
            Finding("B", @"C:\4.exe C:\5.exe C:\6.exe"),
        };

        var result = ChainBuilder.Build(findings, ScanBudget.Default with { MaxMatches = 5 });

        Assert.Equal(CorrelationResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains("budget allows 5", result.Reason, StringComparison.Ordinal);
        Assert.Contains("'B'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void MentionsExactlyAtTheMatchBudgetAreOk()
    {
        var findings = new List<FindingReference>
        {
            Finding("A", @"C:\1.exe C:\2.exe C:\3.exe"),
            Finding("B", @"C:\4.exe C:\5.exe C:\6.exe"),
        };

        Assert.True(ChainBuilder.Build(findings, ScanBudget.Default with { MaxMatches = 6 }).IsOk);
    }

    [Fact]
    public void TargetsCountAgainstTheMatchBudgetToo()
    {
        var findings = new List<FindingReference>
        {
            Finding("A", "", EntityReference.Path(@"C:\1.exe")),
            Finding("B", "", EntityReference.Path(@"C:\2.exe")),
        };

        Assert.Equal(CorrelationResultState.Incomplete, ChainBuilder.Build(findings, ScanBudget.Default with { MaxMatches = 1 }).State);
        Assert.True(ChainBuilder.Build(findings, ScanBudget.Default with { MaxMatches = 2 }).IsOk);
    }

    [Fact]
    public void AnExpiredDeadlineIsIncompleteWithTheDeadlineNamed()
    {
        // A negative deadline has already passed when the first finding is reached. Reverted
        // form: delete the stopwatch check at the top of the per-finding loop.
        var result = ChainBuilder.Build(AllDistinct(2), ScanBudget.Default with { Deadline = TimeSpan.FromTicks(-1) });

        Assert.Equal(CorrelationResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains("deadline", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheExtractorHonoursAnExpiredDeadlineOnLongText()
    {
        var text = string.Join(' ', Enumerable.Range(0, 500).Select(i => $@"C:\a\b{i}.exe"));
        var result = EntityExtractor.Extract(text, ScanBudget.Default with { Deadline = TimeSpan.FromTicks(-1) });

        Assert.Equal(CorrelationResultState.Incomplete, result.State);
        Assert.Contains("deadline", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyRunUnderAnExpiredDeadlineIsStillOk()
    {
        // Nothing to do cannot run out of time; the guard sits inside the loop on purpose.
        Assert.True(ChainBuilder.Build([], ScanBudget.Default with { Deadline = TimeSpan.FromTicks(-1) }).IsOk);
    }

    [Fact]
    public void TheExtractorRefusesTextPastTheByteBudget()
    {
        var result = EntityExtractor.Extract(@"C:\a.exe", ScanBudget.Default with { MaxInputBytes = 4 });
        Assert.Equal(CorrelationResultState.Incomplete, result.State);
        Assert.Contains("budget allows 4", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheExtractorStopsAtTheMatchBudget()
    {
        var result = EntityExtractor.Extract(@"C:\1.exe C:\2.exe C:\3.exe", ScanBudget.Default with { MaxMatches = 2 });
        Assert.Equal(CorrelationResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.True(EntityExtractor.Extract(@"C:\1.exe C:\2.exe C:\3.exe", ScanBudget.Default with { MaxMatches = 3 }).IsOk);
    }

    [Fact]
    public void OmittingTheBudgetUsesTheDefaultRatherThanNoLimit()
    {
        var text = string.Join(' ', Enumerable.Range(0, ScanBudget.DefaultMaxMatches + 1).Select(i => $@"C:\n{i}"));
        var result = EntityExtractor.Extract(text);
        Assert.Equal(CorrelationResultState.Incomplete, result.State);
    }

    [Fact]
    public void ARunPastTheDefaultMatchBudgetIsIncomplete()
    {
        var text = string.Join(' ', Enumerable.Range(0, 5001).Select(i => $@"C:\n{i}"));
        var result = ChainBuilder.Build([Finding("A", text), Finding("B", text)]);
        Assert.Equal(CorrelationResultState.Incomplete, result.State);
        Assert.Contains("10000", result.Reason, StringComparison.Ordinal);
    }
}
