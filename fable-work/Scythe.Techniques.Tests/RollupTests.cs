using Scythe.Techniques.Tests.Fixtures;
using Xunit;
using static Scythe.Techniques.Tests.Fixtures.MapFixtures;

namespace Scythe.Techniques.Tests;

/// <summary>The two rollups, and the explicit double count between the direct and rolled-up members.</summary>
public sealed class RollupTests
{
    private static TechniqueRollup RollupOf(params Finding[] findings) =>
        StandardResolver().ResolveAll(findings).Value!.Rollup;

    private static int Count(IReadOnlyList<CountedName> counts, string name) =>
        counts.SingleOrDefault(c => c.Name == name)?.Count ?? 0;

    [Fact]
    public void ARunOfOnlySubTechniqueFindingsReportsTheSubTechniqueAndTheParentFromTheDocumentedMembers()
    {
        var rollup = RollupOf(F("a", explicitId: "T1053.005"), F("b", explicitId: "T1053.005"));

        // Direct: the sub-technique only, twice.
        Assert.Equal(new[] { new CountedName("T1053.005", 2) }, rollup.DirectCountsByIdentifier);

        // Rolled up: the parent was observed twice as well. Sums to 4, not 2, by design.
        Assert.Equal(new[] { new CountedName("T1053", 2), new CountedName("T1053.005", 2) }, rollup.RolledUpCountsByIdentifier);
        Assert.Equal(4, rollup.RolledUpCountsByIdentifier.Sum(c => c.Count));

        Assert.Equal(new[] { "T1053.005" }, rollup.IdentifiersSeen);
        Assert.Equal(new[] { "T1053", "T1053.005" }, rollup.IdentifiersSeenIncludingParents);
    }

    [Fact]
    public void TheDirectCountsSumToTheResolvedFindingCount()
    {
        var rollup = RollupOf(
            F("a", explicitId: "T1053.005"),
            F("b", explicitId: "T1053"),
            F("c", check: "check.psh"),
            F("d", description: "a run key"),
            F("e", explicitId: "T1547.001"),
            F("f", description: "unmatched"),
            F("g", explicitId: "T1999"));

        Assert.Equal(7, rollup.FindingCount);
        Assert.Equal(5, rollup.ResolvedCount);
        Assert.Equal(2, rollup.UnresolvedCount);
        Assert.Equal(5, rollup.DirectCountsByIdentifier.Sum(c => c.Count));
        Assert.Equal(5, rollup.DirectCountsByCategory.Sum(c => c.Count));
        Assert.Equal(5, rollup.CountsByStrategy.Sum(c => c.Count));

        // Four of the five are sub-techniques, so the rolled-up members exceed by exactly four.
        Assert.Equal(9, rollup.RolledUpCountsByIdentifier.Sum(c => c.Count));
        Assert.Equal(9, rollup.RolledUpCountsByCategory.Sum(c => c.Count));
    }

    [Fact]
    public void AParentObservedDirectlyAndThroughASubTechniqueAddsUp()
    {
        var rollup = RollupOf(F("a", explicitId: "T1053"), F("b", explicitId: "T1053.005"), F("c", explicitId: "T1053.005"));

        Assert.Equal(1, Count(rollup.DirectCountsByIdentifier, "T1053"));
        Assert.Equal(2, Count(rollup.DirectCountsByIdentifier, "T1053.005"));
        Assert.Equal(3, Count(rollup.RolledUpCountsByIdentifier, "T1053"));
        Assert.Equal(2, Count(rollup.RolledUpCountsByIdentifier, "T1053.005"));
    }

    [Fact]
    public void CategoryRollUpCountsTheParentsCategoryWhenItDiffers()
    {
        // T1547.001 is "Defense Evasion" in the fixture; its parent T1547 is "Persistence".
        var rollup = RollupOf(F("a", explicitId: "T1547.001"));

        Assert.Equal(new[] { new CountedName(DefenseEvasion, 1) }, rollup.DirectCountsByCategory);
        Assert.Equal(new[] { new CountedName(DefenseEvasion, 1), new CountedName(Persistence, 1) }, rollup.RolledUpCountsByCategory);
    }

    [Fact]
    public void CategoryRollUpCountsASharedCategoryTwiceForOneSubTechniqueFinding()
    {
        // Documented behaviour, pinned so it cannot silently change: T1053.005 and T1053 are
        // both "Persistence", and the rolled-up member counts the one finding at both levels.
        var rollup = RollupOf(F("a", explicitId: "T1053.005"));

        Assert.Equal(1, Count(rollup.DirectCountsByCategory, Persistence));
        Assert.Equal(2, Count(rollup.RolledUpCountsByCategory, Persistence));
    }

    [Fact]
    public void CountsByStrategyAreInChainOrderAndCorrect()
    {
        var rollup = RollupOf(
            F("a", explicitId: "T1053"),
            F("b", explicitId: "T1059"),
            F("c", check: "check.psh"),
            F("d", description: "a run key"));

        Assert.Equal(new[]
        {
            new StrategyCount(ResolutionStrategy.ExplicitIdentifier, 2),
            new StrategyCount(ResolutionStrategy.CheckMapping, 1),
            new StrategyCount(ResolutionStrategy.KeywordRule, 1),
        }, rollup.CountsByStrategy);
    }

    [Fact]
    public void UnresolvedCountsByReasonCoverEveryReasonAndSumToTheUnresolvedCount()
    {
        var rollup = RollupOf(
            F("a", explicitId: "T1999"),
            F("b", explicitId: "bad"),
            F("c", check: "check.newer"),
            F("d"),
            F("e"),
            F("ok", explicitId: "T1053"));

        Assert.Equal(5, rollup.UnresolvedCount);
        Assert.Equal(Enum.GetValues<UnresolvedReason>().Length, rollup.UnresolvedCountsByReason.Count);
        Assert.Equal(5, rollup.UnresolvedCountsByReason.Sum(c => c.Count));
        Assert.Equal(1, rollup.UnresolvedCountsByReason.Single(c => c.Reason == UnresolvedReason.ExplicitIdentifierAbsentFromMap).Count);
        Assert.Equal(1, rollup.UnresolvedCountsByReason.Single(c => c.Reason == UnresolvedReason.ExplicitIdentifierMalformed).Count);
        Assert.Equal(1, rollup.UnresolvedCountsByReason.Single(c => c.Reason == UnresolvedReason.CheckIdentifierAbsentFromMap).Count);
        Assert.Equal(2, rollup.UnresolvedCountsByReason.Single(c => c.Reason == UnresolvedReason.NoStrategyProduced).Count);
        Assert.Equal(new[] { "a", "b", "c", "d", "e" }, rollup.Unresolved.Select(u => u.FindingId));
    }

    [Fact]
    public void IdentifiersAreSortedOrdinallyWhichIsNumericOrder()
    {
        var map = new MapBuilder().Entry("T1003").Entry("T1003.001").Entry("T1021").Entry("T0999").Entry("T1003.010").LoadOk();
        var resolver = TechniqueResolver.Create(map, Array.Empty<CheckMapping>()).Value!;

        var rollup = resolver.ResolveAll(new[]
        {
            F("a", explicitId: "T1021"),
            F("b", explicitId: "T1003.010"),
            F("c", explicitId: "T0999"),
            F("d", explicitId: "T1003.001"),
            F("e", explicitId: "T1003"),
        }).Value!.Rollup;

        Assert.Equal(new[] { "T0999", "T1003", "T1003.001", "T1003.010", "T1021" }, rollup.IdentifiersSeen);
        Assert.Equal(rollup.IdentifiersSeen, rollup.DirectCountsByIdentifier.Select(c => c.Name));
    }

    [Fact]
    public void CategoriesAreSortedOrdinally()
    {
        var map = new MapBuilder()
            .Entry("T0001", category: "b")
            .Entry("T0002", category: "B")
            .Entry("T0003", category: "a")
            .LoadOk();
        var resolver = TechniqueResolver.Create(map, Array.Empty<CheckMapping>()).Value!;

        var rollup = resolver.ResolveAll(new[] { F("1", explicitId: "T0001"), F("2", explicitId: "T0002"), F("3", explicitId: "T0003") }).Value!.Rollup;

        // Ordinal: upper-case before lower-case. A culture sort would interleave them.
        Assert.Equal(new[] { "B", "a", "b" }, rollup.DirectCountsByCategory.Select(c => c.Name));
    }

    [Fact]
    public void AnEmptyRunRollsUpToZeroesNotToAnError()
    {
        var run = StandardResolver().ResolveAll(Array.Empty<Finding>());

        Assert.True(run.IsOk);
        var rollup = run.Value!.Rollup;
        Assert.Equal(0, rollup.FindingCount);
        Assert.Empty(rollup.DirectCountsByIdentifier);
        Assert.Empty(rollup.Unresolved);
        Assert.Equal(3, rollup.CountsByStrategy.Count);
        Assert.All(rollup.CountsByStrategy, s => Assert.Equal(0, s.Count));
    }

    [Fact]
    public void BuildIsPublicAndAgreesWithTheRunsRollup()
    {
        var resolver = StandardResolver();
        var run = resolver.ResolveAll(new[] { F("a", explicitId: "T1053.005"), F("b") }).Value!;

        var rebuilt = TechniqueRollup.Build(run.Resolutions, resolver.Map);

        Assert.Equal(MapFixtures.RenderCounts(run.Rollup), MapFixtures.RenderCounts(rebuilt));
    }
}
