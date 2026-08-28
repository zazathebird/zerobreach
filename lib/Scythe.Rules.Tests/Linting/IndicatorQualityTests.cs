using Scythe.Rules.Linting;
using Xunit;
using static Scythe.Rules.Tests.Linting.LintTestHelpers;

namespace Scythe.Rules.Tests.Linting;

public class IndicatorLengthTests
{
    private static LintResult LintSet(string jsonPattern) =>
        Lint($$"""{ "families": ["{{jsonPattern}}"] }""");

    [Fact]
    public void AThreeCharacterLiteralIsSuspect()
    {
        var finding = LintSet("abc").Single(LintCode.IndicatorTooShort);
        Assert.Equal(LintSeverity.Warning, finding.Severity);
        Assert.Contains("4+", finding.Message);
    }

    [Fact]
    public void AFourCharacterLiteralPasses()
    {
        LintSet("abcd").AssertNone(LintCode.IndicatorTooShort);
    }

    [Fact]
    public void APatternWithNoRequiredLiteralIsSuspect()
    {
        // Judgement call, pinned: [0-9a-f]{64} is all class, no literal — it would match
        // any hex hash whatsoever, which is generic in exactly the harmful way.
        LintSet("[0-9a-f]{64}").Single(LintCode.IndicatorTooShort);
    }

    [Fact]
    public void AnOptionalTailDoesNotShrinkTheRequiredPrefix()
    {
        LintSet("mimi(katz)?").AssertNone(LintCode.IndicatorTooShort);
    }

    [Fact]
    public void TheWeakestAlternationBranchDecides()
    {
        LintSet("(mimikatz|abc)").Single(LintCode.IndicatorTooShort);
    }

    [Fact]
    public void LiteralRunsMergeAcrossEscapes()
    {
        // ^go\.exe$ — the run is "go.exe" (6), not "go" (2).
        LintSet("^go\\\\.exe$").AssertNone(LintCode.IndicatorTooShort);
    }

    [Fact]
    public void AllowlistEntriesAreNeverMeasuredForLength()
    {
        // Short allowlists are pointless but harmless; the length check is about
        // indicators colliding with the world.
        Lint("""{ "fp_allowlists": { "a": ["^ab$"] } }""")
            .AssertNone(LintCode.IndicatorTooShort);
    }
}

public class CollisionCorpusTests
{
    [Fact]
    public void AnIndicatorMatchingARealProcessNameIsAnError()
    {
        var result = Lint("""{ "families": ["svchost"] }""");
        var finding = result.Single(LintCode.IndicatorCollidesWithLegitimateName);
        Assert.Equal(LintSeverity.Error, finding.Severity);
        Assert.Contains("svchost.exe", finding.Message); // names the legitimate software
        Assert.Contains("healthy machine", finding.Message);
    }

    [Fact]
    public void TheCollisionIsCaseInsensitive()
    {
        Lint("""{ "families": ["SVCHOST"] }""")
            .Single(LintCode.IndicatorCollidesWithLegitimateName);
    }

    [Fact]
    public void ARealisticFamilyNameDoesNotCollide()
    {
        Lint("""{ "families": ["xx_scythe_test_family_99"] }""")
            .AssertNone(LintCode.IndicatorCollidesWithLegitimateName);
    }

    [Fact]
    public void AnchorsKeepAPathIndicatorOffTheNameCorpus()
    {
        Lint("""{ "paths": ["^C:\\\\evil\\\\payload\\.bin$"] }""")
            .AssertNone(LintCode.IndicatorCollidesWithLegitimateName);
    }

    [Fact]
    public void TheOwnerCanExtendTheCorpus()
    {
        var options = new LintOptions
        {
            AdditionalCollisionNames = new[] { "ContosoLineOfBusiness.exe" },
        };
        var result = Lint("""{ "families": ["contosolineofbusiness"] }""", options);
        Assert.Single(result.WithCode(LintCode.IndicatorCollidesWithLegitimateName));
    }

    [Fact]
    public void MultipleCollisionsAreSummarisedInOneFinding()
    {
        // "exe" (with word boundaries off) matches dozens of corpus names; one finding,
        // with a count, beats forty findings for one entry.
        var result = Lint("""{ "families": ["\\.exe"] }""");
        var finding = result.Single(LintCode.IndicatorCollidesWithLegitimateName);
        Assert.Contains("more corpus name", finding.Message);
    }

    [Fact]
    public void TheStarterCorpusStaysBroad()
    {
        // Same rationale as the canary-variety test: silently shrinking the corpus
        // weakens the check with nothing else failing.
        Assert.True(CollisionCorpus.StarterNames.Count >= 40);
        Assert.Contains("svchost.exe", CollisionCorpus.StarterNames);
        Assert.Contains(CollisionCorpus.StarterNames, n => !n.EndsWith(".exe")); // vendors too
    }
}
