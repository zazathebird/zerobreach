using Scythe.Techniques.Tests.Fixtures;
using Xunit;
using static Scythe.Techniques.Tests.Fixtures.MapFixtures;

namespace Scythe.Techniques.Tests;

/// <summary>Each strategy in isolation, and the chain order between them.</summary>
public sealed class ResolutionChainTests
{
    private static ResolvedFinding Resolved(FindingResolution resolution) =>
        Assert.IsType<ResolvedFinding>(resolution);

    [Fact]
    public void AnExplicitIdentifierResolvesAloneAndReportsItsStrategy()
    {
        var resolution = StandardResolver().Resolve(F("f1", explicitId: "T1059"));

        var r = Resolved(resolution);
        Assert.Equal("T1059", r.Identifier.Value);
        Assert.Equal(ResolutionStrategy.ExplicitIdentifier, r.Strategy);
        Assert.Null(r.RuleOrdinal);
        Assert.Equal("f1", r.FindingId);
        Assert.True(r.IsResolved);
    }

    [Fact]
    public void ACheckMappingResolvesAloneAndReportsItsStrategy()
    {
        var resolution = StandardResolver().Resolve(F("f1", check: "check.psh"));

        var r = Resolved(resolution);
        Assert.Equal("T1059.001", r.Identifier.Value);
        Assert.Equal(ResolutionStrategy.CheckMapping, r.Strategy);
        Assert.Null(r.RuleOrdinal);
    }

    [Fact]
    public void AKeywordRuleResolvesAloneAndReportsItsStrategyAndOrdinal()
    {
        var resolution = StandardResolver().Resolve(F("f1", description: "A Run Key was added under HKCU."));

        var r = Resolved(resolution);
        Assert.Equal("T1547.001", r.Identifier.Value);
        Assert.Equal(ResolutionStrategy.KeywordRule, r.Strategy);
        Assert.Equal(2, r.RuleOrdinal);
    }

    [Fact]
    public void AnExplicitIdentifierBeatsACheckMapping()
    {
        var resolution = StandardResolver().Resolve(F("f1", check: "check.psh", explicitId: "T1053"));

        var r = Resolved(resolution);
        Assert.Equal("T1053", r.Identifier.Value);
        Assert.Equal(ResolutionStrategy.ExplicitIdentifier, r.Strategy);
    }

    [Fact]
    public void ACheckMappingBeatsAMatchingKeywordRule()
    {
        var resolution = StandardResolver().Resolve(F("f1", check: "check.psh", description: "a scheduled task ran"));

        var r = Resolved(resolution);
        Assert.Equal("T1059.001", r.Identifier.Value);
        Assert.Equal(ResolutionStrategy.CheckMapping, r.Strategy);
    }

    [Fact]
    public void AnExplicitIdentifierBeatsAMatchingKeywordRule()
    {
        var resolution = StandardResolver().Resolve(F("f1", description: "a scheduled task ran", explicitId: "T1547"));

        var r = Resolved(resolution);
        Assert.Equal("T1547", r.Identifier.Value);
        Assert.Equal(ResolutionStrategy.ExplicitIdentifier, r.Strategy);
    }

    [Fact]
    public void WithAllThreeAvailableTheExplicitIdentifierWins()
    {
        var resolution = StandardResolver().Resolve(F("f1", "check.psh", "a scheduled task ran", "T1547"));

        Assert.Equal("T1547", Resolved(resolution).Identifier.Value);
    }

    [Fact]
    public void TheCheckIdIsMatchedOrdinallyAndCaseSensitively()
    {
        var resolver = StandardResolver();

        var exact = resolver.Resolve(F("f1", check: "check.psh"));
        var cased = resolver.Resolve(F("f2", check: "Check.PSH"));

        Assert.True(exact.IsResolved);
        var un = Assert.IsType<UnresolvedFinding>(cased);
        Assert.Contains(un.Attempts, a => a.Strategy == ResolutionStrategy.CheckMapping && a.Declined.Contains("declares no mapping", StringComparison.Ordinal));
    }

    [Fact]
    public void AnEmptyCheckIdIsTreatedAsNoCheck()
    {
        var un = Assert.IsType<UnresolvedFinding>(StandardResolver().Resolve(F("f1", check: "")));

        Assert.Contains(un.Attempts, a => a.Strategy == ResolutionStrategy.CheckMapping && a.Declined.Contains("names no producing check", StringComparison.Ordinal));
    }

    [Fact]
    public void AgreeingDuplicateCheckMappingsAreAcceptedAsOne()
    {
        var map = Standard().LoadOk();
        var result = TechniqueResolver.Create(map, new[]
        {
            new CheckMapping("c", "T1053"),
            new CheckMapping("c", "T1053"),
        });

        Assert.True(result.IsOk);
        Assert.Equal(1, result.Value!.CheckMappingCount);
    }

    [Fact]
    public void DisagreeingCheckMappingsAreAConstructionFailureNamingTheCheck()
    {
        var map = Standard().LoadOk();
        var result = TechniqueResolver.Create(map, new[]
        {
            new CheckMapping("c", "T1053"),
            new CheckMapping("c", "T1059"),
        });

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Contains("checkMappings[1] (check 'c')", result.Reason, StringComparison.Ordinal);
        Assert.Contains("one identifier per check", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AMalformedCheckMappingIdentifierIsAConstructionFailure()
    {
        var result = TechniqueResolver.Create(Standard().LoadOk(), new[] { new CheckMapping("c", "t1053") });

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Contains("'t1053'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyCheckIdInAMappingIsAConstructionFailure()
    {
        var result = TechniqueResolver.Create(Standard().LoadOk(), new[] { new CheckMapping("", "T1053") });

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Contains("checkMappings[0]", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ACheckMappingAbsentFromTheMapIsNotAConstructionFailure()
    {
        // It is a per-finding unresolved instead: the map is older than the checks, and the
        // resolver should still work for every other check.
        Assert.True(TechniqueResolver.Create(Standard().LoadOk(), StandardCheckMappings).IsOk);
    }

    [Fact]
    public void ResolutionsComeBackInInputOrderWithTheFindingIdEchoed()
    {
        var run = StandardResolver().ResolveAll(new[]
        {
            F("c", explicitId: "T1053"),
            F("a", check: "check.psh"),
            F("b", description: "nothing here"),
        });

        Assert.True(run.IsOk);
        Assert.Equal(new[] { "c", "a", "b" }, run.Value!.Resolutions.Select(r => r.FindingId));
    }

    [Fact]
    public void MatchForcesBothBranchesToBeHandled()
    {
        var resolver = StandardResolver();

        var ok = resolver.Resolve(F("f1", explicitId: "T1053")).Match(r => "R:" + r.Identifier.Value, u => "U:" + u.Reason);
        var un = resolver.Resolve(F("f2")).Match(r => "R:" + r.Identifier.Value, u => "U:" + u.Reason);

        Assert.Equal("R:T1053", ok);
        Assert.Equal("U:NoStrategyProduced", un);
    }

    [Fact]
    public void ANullFindingInTheListIsFailedNamingTheIndex()
    {
        var result = StandardResolver().ResolveAll(new Finding[] { F("f1", explicitId: "T1053"), null! });

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Contains("findings[1] is null", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AFindingWithoutAnIdIsFailedNamingTheIndex()
    {
        var result = StandardResolver().ResolveAll(new[] { F("", explicitId: "T1053") });

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Contains("findings[0]", result.Reason, StringComparison.Ordinal);
    }
}
