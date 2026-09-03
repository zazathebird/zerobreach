using Scythe.Techniques.Tests.Fixtures;
using Xunit;
using static Scythe.Techniques.Tests.Fixtures.MapFixtures;

namespace Scythe.Techniques.Tests;

/// <summary>
/// The rule that shapes the design: nothing resolves to nothing silently. These are the named
/// strictness tests from the brief; each one goes red if the chain is allowed to fall through or
/// an unresolved finding is dropped.
/// </summary>
public sealed class StrictnessTests
{
    [Fact]
    public void AnExplicitIdentifierAbsentFromTheMapIsUnresolvedAndDoesNotFallThrough()
    {
        // The finding also names a mapped check and carries a description a rule matches. If
        // the chain fell through, either would resolve it; neither may.
        var resolution = StandardResolver().Resolve(F("f1", "check.psh", "a scheduled task ran", "T1999"));

        var un = Assert.IsType<UnresolvedFinding>(resolution);
        Assert.Equal(UnresolvedReason.ExplicitIdentifierAbsentFromMap, un.Reason);
        Assert.Contains("explicitly tagged T1999 but absent from the map", un.Detail, StringComparison.Ordinal);
        Assert.Single(un.Attempts);
        Assert.Equal(ResolutionStrategy.ExplicitIdentifier, un.Attempts[0].Strategy);
    }

    [Fact]
    public void AMalformedExplicitIdentifierIsUnresolvedAndDoesNotFallThrough()
    {
        var resolution = StandardResolver().Resolve(F("f1", "check.psh", "a scheduled task ran", "t1053"));

        var un = Assert.IsType<UnresolvedFinding>(resolution);
        Assert.Equal(UnresolvedReason.ExplicitIdentifierMalformed, un.Reason);
        Assert.Contains("'t1053'", un.Detail, StringComparison.Ordinal);
        Assert.Single(un.Attempts);
    }

    [Theory]
    [InlineData(" T1053")]
    [InlineData("T1053 ")]
    [InlineData("")]
    [InlineData("T1053.5")]
    public void AnExplicitIdentifierIsNotTrimmedOrRepaired(string explicitId)
    {
        var un = Assert.IsType<UnresolvedFinding>(StandardResolver().Resolve(F("f1", explicitId: explicitId)));

        Assert.Equal(UnresolvedReason.ExplicitIdentifierMalformed, un.Reason);
    }

    [Fact]
    public void ACheckIdentifierAbsentFromTheMapIsUnresolvedAndDoesNotFallThroughToKeywords()
    {
        var resolution = StandardResolver().Resolve(F("f1", "check.newer", "a scheduled task ran"));

        var un = Assert.IsType<UnresolvedFinding>(resolution);
        Assert.Equal(UnresolvedReason.CheckIdentifierAbsentFromMap, un.Reason);
        Assert.Contains("check 'check.newer' declares T1999", un.Detail, StringComparison.Ordinal);
        Assert.Equal(2, un.Attempts.Count);
        Assert.DoesNotContain(un.Attempts, a => a.Strategy == ResolutionStrategy.KeywordRule);
    }

    [Fact]
    public void AMapOlderThanTheChecksSurfacesAsAbsentFromTheMapInTheRollup()
    {
        // Open question 5: the checks and the map are curated separately. The signal that the
        // map needs updating has to be visible in the rollup, not buried.
        var run = StandardResolver().ResolveAll(new[] { F("f1", "check.newer"), F("f2", "check.newer") }).Value!;

        Assert.Equal(2, run.Rollup.UnresolvedCount);
        Assert.Equal(2, run.Rollup.UnresolvedCountsByReason.Single(r => r.Reason == UnresolvedReason.CheckIdentifierAbsentFromMap).Count);
        Assert.All(run.Rollup.Unresolved, u => Assert.Contains("T1999", u.Detail, StringComparison.Ordinal));
    }

    [Fact]
    public void AnUnresolvableFindingAppearsInTheOutputAndInTheRollupAsItsOwnGroup()
    {
        var run = StandardResolver().ResolveAll(new[]
        {
            F("resolved", explicitId: "T1053"),
            F("orphan", description: "nothing a rule knows"),
        }).Value!;

        Assert.Equal(2, run.Resolutions.Count);
        Assert.Equal(2, run.Rollup.FindingCount);
        Assert.Equal(1, run.Rollup.ResolvedCount);
        Assert.Equal(1, run.Rollup.UnresolvedCount);

        var un = Assert.Single(run.Rollup.Unresolved);
        Assert.Equal("orphan", un.FindingId);
        Assert.Equal(UnresolvedReason.NoStrategyProduced, un.Reason);

        // Never folded into a category: the category counts account for the one resolved
        // finding and nothing else.
        Assert.Equal(1, run.Rollup.DirectCountsByCategory.Sum(c => c.Count));
        Assert.DoesNotContain(run.Rollup.DirectCountsByCategory, c => c.Name.Contains("other", StringComparison.OrdinalIgnoreCase) || c.Name.Contains("unresolved", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void TheUnresolvedReasonSaysWhichStrategiesWereTriedAndWhyEachDeclined()
    {
        var un = Assert.IsType<UnresolvedFinding>(StandardResolver().Resolve(F("f1", "check.unknown", "plain text")));

        Assert.Equal(new[] { ResolutionStrategy.ExplicitIdentifier, ResolutionStrategy.CheckMapping, ResolutionStrategy.KeywordRule }, un.Attempts.Select(a => a.Strategy));
        Assert.Contains("carries no explicit identifier", un.Attempts[0].Declined, StringComparison.Ordinal);
        Assert.Contains("check 'check.unknown' declares no mapping", un.Attempts[1].Declined, StringComparison.Ordinal);
        Assert.Contains("none of the 3 keyword rules matched", un.Attempts[2].Declined, StringComparison.Ordinal);
        Assert.Contains("declares no mapping", un.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void NoDescriptionAndNoMatchingRuleAreDifferentReasons()
    {
        var resolver = StandardResolver();

        var noDescription = Assert.IsType<UnresolvedFinding>(resolver.Resolve(F("f1")));
        var noMatch = Assert.IsType<UnresolvedFinding>(resolver.Resolve(F("f2", description: "unrelated")));

        Assert.Contains("has no description", noDescription.Attempts[^1].Declined, StringComparison.Ordinal);
        Assert.Contains("none of the 3 keyword rules matched", noMatch.Attempts[^1].Declined, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyMapMakesEveryFindingUnresolvedWithACoherentReason()
    {
        var map = new MapBuilder().LoadOk();
        var resolver = TechniqueResolver.Create(map, new[] { new CheckMapping("c", "T1053") }).Value!;

        var byExplicit = Assert.IsType<UnresolvedFinding>(resolver.Resolve(F("f1", explicitId: "T1053")));
        var byCheck = Assert.IsType<UnresolvedFinding>(resolver.Resolve(F("f2", check: "c")));
        var byText = Assert.IsType<UnresolvedFinding>(resolver.Resolve(F("f3", description: "a scheduled task")));

        Assert.Equal(UnresolvedReason.ExplicitIdentifierAbsentFromMap, byExplicit.Reason);
        Assert.Equal(UnresolvedReason.CheckIdentifierAbsentFromMap, byCheck.Reason);
        Assert.Equal(UnresolvedReason.NoStrategyProduced, byText.Reason);
        Assert.Contains("map declares no keyword rules", byText.Attempts[^1].Declined, StringComparison.Ordinal);
    }

    [Fact]
    public void IdentifierShapedTextInADescriptionIsNotTreatedAsAnIdentifier()
    {
        var map = new MapBuilder().Entry("T1053").LoadOk();
        var resolver = TechniqueResolver.Create(map, Array.Empty<CheckMapping>()).Value!;

        var un = Assert.IsType<UnresolvedFinding>(resolver.Resolve(F("f1", description: "Observed T1053 behaviour in the log")));

        Assert.Equal(UnresolvedReason.NoStrategyProduced, un.Reason);
    }

    [Fact]
    public void AnIdentifierInsideAPathInADescriptionIsNotTreatedAsAnIdentifier()
    {
        var resolver = StandardResolver();

        var un = Assert.IsType<UnresolvedFinding>(resolver.Resolve(F("f1", description: "Executed C:\\tools\\T1059.001\\stage.exe from a share")));

        Assert.Equal(UnresolvedReason.NoStrategyProduced, un.Reason);
    }

    [Fact]
    public void ANullDescriptionAgainstTheKeywordStrategyDeclinesRatherThanThrowing()
    {
        var un = Assert.IsType<UnresolvedFinding>(StandardResolver().Resolve(F("f1", description: null)));

        Assert.Equal(ResolutionStrategy.KeywordRule, un.Attempts[^1].Strategy);
        Assert.Contains("has no description", un.Attempts[^1].Declined, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyDescriptionMatchesNoRule()
    {
        var un = Assert.IsType<UnresolvedFinding>(StandardResolver().Resolve(F("f1", description: "")));

        Assert.Equal(UnresolvedReason.NoStrategyProduced, un.Reason);
    }

    [Fact]
    public void TheResolutionTypeExposesNoNullableIdentifier()
    {
        // The two silent-loss shapes the brief names: a nullable identifier the caller can
        // coalesce away, and a rule that matches everything. This pins the first at the type
        // level: the base type has no identifier member at all.
        var members = typeof(FindingResolution).GetProperties().Select(p => p.Name).ToArray();

        Assert.DoesNotContain("Identifier", members);
        Assert.DoesNotContain("Entry", members);
        Assert.Contains("IsResolved", members);
    }
}
