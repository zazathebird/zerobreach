using Scythe.Techniques.Tests.Fixtures;
using Xunit;
using static Scythe.Techniques.Tests.Fixtures.MapFixtures;

namespace Scythe.Techniques.Tests;

/// <summary>
/// One canary per budget dimension, each with a negative control showing the guard is quiet
/// on ordinary input.
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
    public void AMapPastTheByteBudgetIsIncompleteNamingTheBudget()
    {
        var bytes = Standard().Bytes();

        var result = TechniqueMapLoader.Load(bytes, ScanBudget.Default with { MaxInputBytes = bytes.Length - 1 });

        Assert.Equal(TechniqueResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains($"budget allows {bytes.Length - 1}", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AMapExactlyAtTheByteBudgetLoads()
    {
        var bytes = Standard().Bytes();

        Assert.True(TechniqueMapLoader.Load(bytes, ScanBudget.Default with { MaxInputBytes = bytes.Length }).IsOk);
    }

    [Fact]
    public void ADeeplyNestedMapIsIncompleteNamingTheDepth()
    {
        var json = "{\"entries\":" + new string('[', 40) + new string(']', 40) + "}";

        var result = TechniqueMapLoader.Load(json);

        Assert.True(result.State == TechniqueResultState.Incomplete, result.Reason);
        Assert.Contains("deeper than the budget's 16 levels", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheStandardMapNeedsExactlyThreeLevels()
    {
        // Root object, entries array, entry object. Depth 3 loads; depth 2 is a budget stop,
        // not a schema failure, because the reader never saw the whole file.
        Assert.True(Standard().Load(ScanBudget.Default with { MaxNestingDepth = 3 }).IsOk);

        var tooShallow = Standard().Load(ScanBudget.Default with { MaxNestingDepth = 2 });
        Assert.Equal(TechniqueResultState.Incomplete, tooShallow.State);
    }

    [Fact]
    public void MoreEntriesThanMaxMatchesIsIncompleteWithNoPartialMap()
    {
        var result = Standard().Load(ScanBudget.Default with { MaxMatches = 5 });

        Assert.Equal(TechniqueResultState.Incomplete, result.State);
        // A partial map would resolve some identifiers and not others while looking whole.
        Assert.Null(result.Value);
        Assert.Contains("6 entries; budget allows 5", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void MoreRulesThanMaxMatchesIsIncomplete()
    {
        var builder = new MapBuilder().Entry("T0001").Entry("T0002");
        builder.Rule("alpha keyword", "T0001").Rule("beta keyword", "T0002").Rule("gamma keyword", "T0001");

        var result = builder.Load(ScanBudget.Default with { MaxMatches = 2 });

        Assert.Equal(TechniqueResultState.Incomplete, result.State);
        Assert.Contains("3 keyword rules; budget allows 2", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void EntriesExactlyAtMaxMatchesLoad()
    {
        Assert.True(Standard().Load(ScanBudget.Default with { MaxMatches = 6 }).IsOk);
    }

    [Fact]
    public void AZeroDeadlineStopsTheLoaderWithIncomplete()
    {
        var result = Standard().Load(ScanBudget.Default with { Deadline = TimeSpan.Zero });

        Assert.Equal(TechniqueResultState.Incomplete, result.State);
        Assert.Contains("deadline", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AZeroDeadlineStopsTheLoaderEvenWhenTheMapHasNoRules()
    {
        // The entries loop and the rules loop each check the deadline. A map with no rules
        // isolates the first check, so removing it cannot hide behind the second.
        var result = new MapBuilder().Entry("T1234").Load(ScanBudget.Default with { Deadline = TimeSpan.Zero });

        Assert.Equal(TechniqueResultState.Incomplete, result.State);
        Assert.Contains("entries[0]", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AZeroDeadlineStopsTheResolverWithIncompleteAndAnEmptyPartial()
    {
        var result = StandardResolver().ResolveAll(new[] { F("a", explicitId: "T1053") }, ScanBudget.Default with { Deadline = TimeSpan.Zero });

        Assert.Equal(TechniqueResultState.Incomplete, result.State);
        Assert.NotNull(result.Value);
        Assert.Empty(result.Value!.Resolutions);
        Assert.Contains("deadline", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void MoreFindingsThanMaxMatchesIsIncompleteCarryingOnlyTheFindingsProcessed()
    {
        var findings = Enumerable.Range(0, 5).Select(i => F($"f{i}", explicitId: "T1053")).ToArray();

        var result = StandardResolver().ResolveAll(findings, ScanBudget.Default with { MaxMatches = 3 });

        Assert.Equal(TechniqueResultState.Incomplete, result.State);
        Assert.Equal(3, result.Value!.Resolutions.Count);
        Assert.Equal(3, result.Value.Rollup.FindingCount);
        Assert.Contains("5 findings; budget allows 3", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void FindingsExactlyAtMaxMatchesAreOk()
    {
        var findings = Enumerable.Range(0, 3).Select(i => F($"f{i}", explicitId: "T1053")).ToArray();

        Assert.True(StandardResolver().ResolveAll(findings, ScanBudget.Default with { MaxMatches = 3 }).IsOk);
    }

    [Fact]
    public void TheDefaultBudgetIsUsedWhenNoneIsSupplied()
    {
        Assert.True(Standard().Load().IsOk);
        Assert.True(StandardResolver().ResolveAll(new[] { F("a") }).IsOk);
    }
}
