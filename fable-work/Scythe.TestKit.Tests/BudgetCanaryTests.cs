using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

/// <summary>Input known to trip each budget dimension, asserted Exhausted or refused — never Holds.</summary>
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
    public void MoreCasesThanMaxMatchesIsExhaustedNotHolds()
    {
        var budget = ScanBudget.Default with { MaxMatches = 10 };

        var r = Property.ForAll("capped", 1, 50, 8, _ => null, budget);

        Assert.Equal(PropertyOutcome.Exhausted, r.Outcome);
        Assert.False(r.Holds);
        Assert.Equal(10, r.CasesRun);
        Assert.Equal(50, r.CasesPlanned);
        Assert.Contains("MaxMatches is 10", r.Detail, StringComparison.Ordinal);
        Assert.Contains("EXHAUSTED", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ExactlyMaxMatchesCasesStillHolds()
    {
        var r = Property.ForAll("at the ceiling", 1, 10, 8, _ => null, ScanBudget.Default with { MaxMatches = 10 });

        Assert.Equal(PropertyOutcome.Holds, r.Outcome);
    }

    [Fact]
    public void ACheckThatOutlivesTheDeadlineIsExhausted()
    {
        var budget = ScanBudget.Default with { Deadline = TimeSpan.FromMilliseconds(1) };

        var r = Property.ForAll("slow", 1, 5, 8, _ => { Thread.Sleep(30); return null; }, budget);

        Assert.Equal(PropertyOutcome.Exhausted, r.Outcome);
        Assert.False(r.Holds);
        Assert.InRange(r.CasesRun, 1, 4);
        Assert.Contains("deadline of 1 ms passed", r.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void TheSameSlowCheckUnderTheDefaultDeadlineHolds()
    {
        var r = Property.ForAll("slow", 1, 5, 8, _ => { Thread.Sleep(30); return null; });

        Assert.Equal(PropertyOutcome.Holds, r.Outcome);
    }

    [Fact]
    public void AMaxLengthAboveMaxInputBytesIsRefused()
    {
        var budget = ScanBudget.Default with { MaxInputBytes = 10 };

        var e = Assert.Throws<FixtureException>(() => Property.ForAll("big", 1, 5, 100, _ => null, budget));

        Assert.Contains("exceeds the budget's MaxInputBytes 10", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ShrinkingStopsAtMaxMatchesEvaluationsAndReportsTheCap()
    {
        var budget = ScanBudget.Default with { MaxMatches = 3 };

        var r = Property.ForAll("fails when non-empty", 1, 2, 64, input => input.Length > 0 ? "non-empty" : null, budget);

        Assert.Equal(PropertyOutcome.Falsified, r.Outcome);
        Assert.True(r.ShrinkCapped);
        Assert.Equal(3, r.ShrinkEvaluations);
        Assert.Contains("shrink capped", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RegionsNestedDeeperThanMaxNestingDepthAreRefused()
    {
        var budget = ScanBudget.Default with { MaxNestingDepth = 2 };
        var b = new FixtureBuilder(Endian.Little, budget);

        var e = Assert.Throws<FixtureException>(() =>
            b.Region("a", () => b.Region("b", () => b.Region("c", () => b.U8(1)))));

        Assert.Contains("would nest 3 deep; the budget allows 2", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RegionsNestedToExactlyMaxNestingDepthAreAllowed()
    {
        var b = new FixtureBuilder(Endian.Little, ScanBudget.Default with { MaxNestingDepth = 2 });

        b.Region("a", () => b.Region("b", () => b.U8(1)));

        Assert.Equal(2, b.Build().Regions.Count);
    }

    [Fact]
    public void StructuredGenerationPassesTheBudgetToTheBuilder()
    {
        var budget = ScanBudget.Default with { MaxNestingDepth = 1 };

        Assert.Throws<FixtureException>(() => Gen.Structured(1, Endian.Little, (b, _) => b.Region("a", () => b.Region("b", () => b.U8(1))), budget));
    }
}
