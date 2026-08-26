using ZeroBreach.Rules.Linting;
using Xunit;
using static ZeroBreach.Rules.Tests.Linting.LintTestHelpers;

namespace ZeroBreach.Rules.Tests.Linting;

public class UniversalAllowlistTests
{
    private static string AllowlistFile(string jsonPattern) =>
        $$"""{ "fp_allowlists": { "phase_allow": ["{{jsonPattern}}"] } }""";

    [Theory]
    [InlineData(".*")]
    [InlineData("^.*$")]
    [InlineData("^[\\\\s\\\\S]*$")] // JSON-decodes to ^[\s\S]*$
    public void EntriesMatchingEveryCanaryAreCritical(string jsonPattern)
    {
        var result = Lint(AllowlistFile(jsonPattern));
        var finding = result.Single(LintCode.UniversalAllowlist);
        Assert.Equal(LintSeverity.Critical, finding.Severity);
        Assert.Contains("suppresses every detection", finding.Message);
        Assert.Equal("phase_allow", finding.SetName);
    }

    [Fact]
    public void AGenuinelyNarrowAllowlistMustPass()
    {
        // The brief demands this direction explicitly: a linter that always cries
        // universal gets ignored, and the narrow entry is the product's honest case.
        var result = Lint(AllowlistFile("^C:\\\\Program Files\\\\Vendor\\\\.*$"));
        result.AssertNone(LintCode.UniversalAllowlist);
        result.AssertNone(LintCode.UnanchoredAllowlist);
    }

    [Fact]
    public void MatchingManyButNotAllCanariesIsNotUniversal()
    {
        // Matches the path canary (ends in .exe) but not the domain or hash canaries.
        var result = Lint(AllowlistFile("^.*\\\\.exe$"));
        result.AssertNone(LintCode.UniversalAllowlist);
    }

    [Fact]
    public void TheCanarySetStaysVaried()
    {
        // The check's power is the variety of the canaries; shrinking the set weakens
        // every rule file's lint without any test failing — except this one.
        Assert.True(AllowlistCanaries.All.Count >= 8);
        Assert.Contains(AllowlistCanaries.All, c => c.Contains(@":\"));         // Windows path
        Assert.Contains(AllowlistCanaries.All, c => c.Contains("HKEY_"));       // registry key
        Assert.Contains(AllowlistCanaries.All, c => c.StartsWith("https://"));  // URL
        Assert.Contains(AllowlistCanaries.All, c => c.Length == 64
            && c.All(Uri.IsHexDigit));                                          // hex hash
        Assert.Contains(AllowlistCanaries.All, c => c.Contains(' ')
            && c.EndsWith('.'));                                                // prose
    }
}

public class AllowlistAnchoringTests
{
    private static LintResult LintAllow(string jsonPattern) =>
        Lint($$"""{ "fp_allowlists": { "a": ["{{jsonPattern}}"] } }""");

    [Theory]
    [InlineData("vendor_service", "at either end")]
    [InlineData("^C:\\\\temp\\\\.*", "at the end")]
    [InlineData(".*\\\\.tmp$", "at the start")]
    [InlineData("^ok$|fragment$", "at the start")] // one branch unanchored poisons the entry
    public void UnanchoredEntriesAreErrors(string jsonPattern, string expectedWhere)
    {
        var finding = LintAllow(jsonPattern).Single(LintCode.UnanchoredAllowlist);
        Assert.Equal(LintSeverity.Error, finding.Severity);
        Assert.Contains(expectedWhere, finding.Message);
        Assert.Contains("allowlist itself", finding.Message);
    }

    [Theory]
    [InlineData("^C:\\\\Vendor\\\\app\\\\.*$")]
    [InlineData("^a{40}$|^b{40}$")]      // every branch anchored
    [InlineData("^(alpha|beta)$")]       // anchors outside an alternation group
    [InlineData("\\\\Aroot\\\\.exe\\\\z")] // \A...\z anchors count too
    public void FullyAnchoredEntriesPass(string jsonPattern)
    {
        LintAllow(jsonPattern).AssertNone(LintCode.UnanchoredAllowlist);
    }

    [Fact]
    public void AnEscapedDollarIsNotAnAnchor()
    {
        // ^price\$ ends in a literal dollar sign, not an end anchor.
        var result = LintAllow("^price\\\\$");
        Assert.Single(result.WithCode(LintCode.UnanchoredAllowlist));
    }
}

public class SwallowedDetectionTests
{
    [Fact]
    public void AnAllowlistCoveringItsDetectionsWitnessWarns()
    {
        var result = Lint(
            """
            {
              "dropper_names": ["evil_dropper\\.exe"],
              "fp_allowlists": { "noise_allow": ["^.*evil_dropper\\.exe$"] }
            }
            """);
        var finding = result.Single(LintCode.AllowlistSwallowsDetection);
        Assert.Equal(LintSeverity.Warning, finding.Severity);
        Assert.Equal("noise_allow", finding.SetName);
        Assert.Contains("evil_dropper.exe", finding.Message);  // the witness itself
        Assert.Contains("dropper_names", finding.Message);
        Assert.Contains("unreachable", finding.Message);
    }

    [Fact]
    public void ANarrowAllowlistDoesNotWarn()
    {
        var result = Lint(
            """
            {
              "dropper_names": ["evil_dropper\\.exe"],
              "fp_allowlists": { "vendor": ["^C:\\\\Program Files\\\\Vendor\\\\.*$"] }
            }
            """);
        result.AssertNone(LintCode.AllowlistSwallowsDetection);
    }

    [Fact]
    public void WitnessesHonourMinimumRepetitions()
    {
        // Witness of ab{3}c is abbbc; the allowlist matches exactly that string.
        var result = Lint(
            """
            {
              "sigs": ["ab{3}c"],
              "fp_allowlists": { "odd": ["^abbbc$"] }
            }
            """);
        Assert.Single(result.WithCode(LintCode.AllowlistSwallowsDetection));
    }

    [Fact]
    public void AUniversalEntryReportsCriticalNotOneSwallowPerIndicator()
    {
        var result = Lint(
            """
            {
              "sig_a": ["evil_alpha"],
              "sig_b": ["evil_beta"],
              "fp_allowlists": { "wild": [".*"] }
            }
            """);
        Assert.Single(result.WithCode(LintCode.UniversalAllowlist));
        result.AssertNone(LintCode.AllowlistSwallowsDetection);
    }
}
