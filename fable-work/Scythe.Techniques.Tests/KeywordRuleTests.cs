using Scythe.Techniques.Tests.Fixtures;
using Xunit;
using static Scythe.Techniques.Tests.Fixtures.MapFixtures;

namespace Scythe.Techniques.Tests;

/// <summary>The weakest strategy, and the constraints that keep it honest.</summary>
public sealed class KeywordRuleTests
{
    private static TechniqueResolver ResolverFor(MapBuilder builder) =>
        TechniqueResolver.Create(builder.LoadOk(), Array.Empty<CheckMapping>()).Value!;

    private static MapBuilder ThreeMatchingRules(params string[] order)
    {
        var builder = new MapBuilder().Entry("T1001").Entry("T1002").Entry("T1003");
        foreach (var keyword in order)
        {
            builder.Rule(keyword, keyword switch
            {
                "task scheduler" => "T1001",
                "scheduled task" => "T1002",
                "schtasks" => "T1003",
                _ => throw new ArgumentException(keyword),
            });
        }

        return builder;
    }

    private const string MatchesAllThree = "schtasks registered a scheduled task with the task scheduler";

    [Fact]
    public void TheFirstMatchingRuleWinsOverALaterOne()
    {
        var resolver = ResolverFor(ThreeMatchingRules("task scheduler", "scheduled task", "schtasks"));

        var r = Assert.IsType<ResolvedFinding>(resolver.Resolve(F("f1", description: MatchesAllThree)));

        Assert.Equal("T1001", r.Identifier.Value);
        Assert.Equal(0, r.RuleOrdinal);
    }

    public static IEnumerable<object[]> Permutations()
    {
        var keywords = new[] { "task scheduler", "scheduled task", "schtasks" };
        foreach (var a in keywords)
        foreach (var b in keywords.Where(k => k != a))
        foreach (var c in keywords.Where(k => k != a && k != b))
        {
            yield return new object[] { a, b, c };
        }
    }

    [Theory]
    [MemberData(nameof(Permutations))]
    public void EveryPermutationOfConstructionOrderYieldsTheFirstRuleInThatOrder(string first, string second, string third)
    {
        var resolver = ResolverFor(ThreeMatchingRules(first, second, third));

        var r = Assert.IsType<ResolvedFinding>(resolver.Resolve(F("f1", description: MatchesAllThree)));

        Assert.Equal(first, resolver.Map.Rules[r.RuleOrdinal!.Value].Keyword);
        Assert.Equal(0, r.RuleOrdinal);
    }

    [Fact]
    public void RuleOrderIsStableAcrossRepeatedLoads()
    {
        var builder = ThreeMatchingRules("scheduled task", "schtasks", "task scheduler");

        var first = MapFixtures.RenderMap(builder.LoadOk());
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(first, MapFixtures.RenderMap(builder.LoadOk()));
        }
    }

    [Fact]
    public void MatchingIsCaseInsensitive()
    {
        var resolver = StandardResolver();

        var lower = resolver.Resolve(F("f1", description: "powershell -enc ..."));
        var upper = resolver.Resolve(F("f2", description: "POWERSHELL -ENC ..."));
        var mixed = resolver.Resolve(F("f3", description: "PoWeRsHeLl"));

        Assert.All(new[] { lower, upper, mixed }, r => Assert.Equal("T1059.001", Assert.IsType<ResolvedFinding>(r).Identifier.Value));
    }

    [Fact]
    public void MatchingIsBySubstringNotByWholeWord()
    {
        var r = Assert.IsType<ResolvedFinding>(StandardResolver().Resolve(F("f1", description: "xpowershellx")));

        Assert.Equal("T1059.001", r.Identifier.Value);
    }

    [Fact]
    public void MatchingIsOrdinalNotCultural()
    {
        // A culture-aware comparison could equate "ss" with "ß" or ignore soft hyphens;
        // ordinal must not. The rule "powershell" must not match a description with a
        // soft hyphen inserted.
        var un = StandardResolver().Resolve(F("f1", description: "power\u00ADshell"));

        Assert.IsType<UnresolvedFinding>(un);
    }

    [Fact]
    public void ANonMatchingRuleSetDeclinesWithTheRuleCount()
    {
        var un = Assert.IsType<UnresolvedFinding>(StandardResolver().Resolve(F("f1", description: "nothing relevant")));

        Assert.Contains("none of the 3 keyword rules matched", un.Attempts[^1].Declined, StringComparison.Ordinal);
    }

    [Fact]
    public void AVeryLongDescriptionIsSearchedWithoutIncident()
    {
        var description = new string('x', 2_000_000) + " scheduled task";

        var r = Assert.IsType<ResolvedFinding>(StandardResolver().Resolve(F("f1", description: description)));

        Assert.Equal("T1053.005", r.Identifier.Value);
    }

    [Fact]
    public void KeywordRuleMatchesIsExposedForReview()
    {
        var rule = StandardResolver().Map.Rules[0];

        Assert.True(rule.Matches("A SCHEDULED TASK"));
        Assert.False(rule.Matches("a scheduled job"));
    }
}
