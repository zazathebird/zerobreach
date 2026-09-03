using Scythe.Rules.Linting;
using Xunit;
using static Scythe.Rules.Tests.Linting.LintTestHelpers;

namespace Scythe.Rules.Tests.Linting;

/// <summary>
/// The accepted-findings mechanism: a maintainer can keep, with a reason, a finding of one
/// of three judgement-call codes, and it is then reported at Info with the reason appended
/// rather than failing the lint. Every case is proven in both directions — the same entry
/// without the acceptance keeps its original severity — and the manifest refuses anything
/// that would turn the mechanism into a silent suppression.
/// </summary>
public class AcceptedFindingsTests
{
    private static readonly LintOptions Flat = LintOptions.Default with { Shape = RuleFileShape.Flat };

    private static StringWriter Errors() => new();

    // ── Manifest parsing ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData("IndicatorCollidesWithLegitimateName", LintCode.IndicatorCollidesWithLegitimateName)]
    [InlineData("IndicatorTooShort", LintCode.IndicatorTooShort)]
    [InlineData("AllowlistSwallowsDetection", LintCode.AllowlistSwallowsDetection)]
    public void ManifestParsesAcceptedFindingsForEachAcceptableCode(string name, LintCode expected)
    {
        string text = $$"""{ "accepted_findings": [ { "code": "{{name}}", "set": "s", "entry": "e", "why": "w" } ] }""";
        var errors = Errors();
        var manifest = LintManifest.Parse(text, "m.json", errors);
        Assert.True(manifest is not null, errors.ToString());
        var finding = Assert.Single(manifest!.AcceptedFindings);
        Assert.Equal(new AcceptedFinding(expected, "s", "e", "w"), finding);
        Assert.Equal(finding, Assert.Single(manifest.Apply(LintOptions.Default).AcceptedFindings));
    }

    [Theory]
    [InlineData("RegexDoesNotCompile")]          // a real LintCode, but a defect, not an opinion
    [InlineData("UniversalAllowlist")]           // the one code that must never be acceptable
    [InlineData("indicatortooshort")]            // case matters: Enum.TryParse is case-sensitive here
    [InlineData("NoSuchCode")]
    [InlineData("11")]                           // a numeric enum value is not a name
    public void ManifestRefusesACodeThatCannotBeAccepted(string code)
    {
        string text = $$"""{ "accepted_findings": [ { "code": "{{code}}", "set": "s", "entry": "e", "why": "w" } ] }""";
        var errors = Errors();
        Assert.Null(LintManifest.Parse(text, "m.json", errors));
        string message = errors.ToString();
        Assert.Contains(code, message);
        // The error names the codes that ARE allowed, so the maintainer need not guess.
        Assert.Contains("IndicatorCollidesWithLegitimateName", message);
        Assert.Contains("IndicatorTooShort", message);
        Assert.Contains("AllowlistSwallowsDetection", message);
    }

    [Theory]
    [InlineData("""{ "accepted_findings": [ { "set": "s", "entry": "e", "why": "w" } ] }""")]                      // no code
    [InlineData("""{ "accepted_findings": [ { "code": "IndicatorTooShort", "set": "s", "entry": "e" } ] }""")]      // no why
    [InlineData("""{ "accepted_findings": [ { "code": "IndicatorTooShort", "set": "s", "entry": "e", "why": "" } ] }""")]
    [InlineData("""{ "accepted_findings": [ { "code": "IndicatorTooShort", "set": "s", "entry": "e", "why": "  " } ] }""")]
    [InlineData("""{ "accepted_findings": [ { "code": "IndicatorTooShort", "entry": "e", "why": "w" } ] }""")]       // no set
    [InlineData("""{ "accepted_findings": [ { "code": "IndicatorTooShort", "set": "s", "why": "w" } ] }""")]         // no entry
    [InlineData("""{ "accepted_findings": [ { "code": "IndicatorTooShort", "set": "s", "entry": "e", "why": "w", "extra": "x" } ] }""")]
    [InlineData("""{ "accepted_findings": [ "IndicatorTooShort" ] }""")]                                             // not an object
    [InlineData("""{ "accepted_findings": { "code": "IndicatorTooShort" } }""")]                                     // not an array
    public void ManifestRefusesAnIncompleteAcceptedFinding(string text)
    {
        var errors = Errors();
        Assert.Null(LintManifest.Parse(text, "m.json", errors));
        Assert.StartsWith("error: manifest 'm.json'", errors.ToString());
    }

    [Fact]
    public void LegacyCollisionsKeyMapsToTheCollisionCodeAndRefusesACodeField()
    {
        var manifest = LintManifest.Parse(
            """{ "accepted_collisions": [ { "set": "s", "entry": "e", "why": "w" } ] }""", "m.json", Errors());
        Assert.NotNull(manifest);
        Assert.Equal(
            new AcceptedFinding(LintCode.IndicatorCollidesWithLegitimateName, "s", "e", "w"),
            Assert.Single(manifest!.AcceptedFindings));

        // Even the code the legacy key implies is refused there: the field has one home.
        var errors = Errors();
        Assert.Null(LintManifest.Parse(
            """{ "accepted_collisions": [ { "code": "IndicatorCollidesWithLegitimateName", "set": "s", "entry": "e", "why": "w" } ] }""",
            "m.json", errors));
        Assert.Contains("accepted_findings", errors.ToString());
    }

    [Fact]
    public void BothKeysMayAppearAndAreConcatenated()
    {
        string text = """
            { "accepted_collisions": [ { "set": "a", "entry": "1", "why": "legacy" } ],
              "accepted_findings": [ { "code": "IndicatorTooShort", "set": "b", "entry": "2", "why": "new" } ] }
            """;
        var errors = Errors();
        var manifest = LintManifest.Parse(text, "m.json", errors);
        Assert.True(manifest is not null, errors.ToString());
        Assert.Equal(new[]
        {
            new AcceptedFinding(LintCode.IndicatorCollidesWithLegitimateName, "a", "1", "legacy"),
            new AcceptedFinding(LintCode.IndicatorTooShort, "b", "2", "new"),
        }, manifest!.AcceptedFindings);

        // Apply appends to whatever the caller already had, in order.
        var prior = new AcceptedFinding(LintCode.AllowlistSwallowsDetection, "c", "3", "prior");
        var options = manifest.Apply(LintOptions.Default with { AcceptedFindings = new[] { prior } });
        Assert.Equal(3, options.AcceptedFindings.Count);
        Assert.Equal(prior, options.AcceptedFindings[0]);
    }

    [Fact]
    public void UnknownKeyErrorNamesAcceptedFindings()
    {
        var errors = Errors();
        Assert.Null(LintManifest.Parse("""{ "accepted-findings": [] }""", "m.json", errors));
        Assert.Contains("accepted_findings", errors.ToString());
    }

    // ── IndicatorTooShort ────────────────────────────────────────────────────────

    [Fact]
    public void AnAcceptedTooShortRegexIndicatorIsInfoWithTheReasonAndUnacceptedIsWarning()
    {
        // "\\d{3}" guarantees no literal at all; it is the regex-branch IndicatorTooShort.
        string json = """{ "ids": [ "\\d{3}" ] }""";
        Assert.Equal(LintSeverity.Warning, Lint(json, Flat).Single(LintCode.IndicatorTooShort).Severity);

        var accepted = new AcceptedFinding(LintCode.IndicatorTooShort, "ids", "\\d{3}", "matched only inside a longer path");
        var finding = Lint(json, Flat with { AcceptedFindings = new[] { accepted } }).Single(LintCode.IndicatorTooShort);
        Assert.Equal(LintSeverity.Info, finding.Severity);
        Assert.EndsWith(" [accepted: matched only inside a longer path]", finding.Message);
        Assert.Equal("ids", finding.SetName);
        Assert.Equal("\\d{3}", finding.Entry);
    }

    [Fact]
    public void AnAcceptedTooShortLiteralIndicatorIsInfoAndUnacceptedIsWarning()
    {
        // Under literal_sets the entry is an escaped substring; "ab" is under the 4-char floor.
        string json = """{ "procs": [ "ab" ] }""";
        var literal = Flat with { LiteralSets = new[] { "procs" } };
        Assert.Equal(LintSeverity.Warning, Lint(json, literal).Single(LintCode.IndicatorTooShort).Severity);

        var accepted = new AcceptedFinding(LintCode.IndicatorTooShort, "procs", "ab", "host compares against a two-letter field");
        var finding = Lint(json, literal with { AcceptedFindings = new[] { accepted } }).Single(LintCode.IndicatorTooShort);
        Assert.Equal(LintSeverity.Info, finding.Severity);
        Assert.EndsWith(" [accepted: host compares against a two-letter field]", finding.Message);
    }

    [Fact]
    public void AnAcceptanceIsKeyedOnCodeSetAndEntryExactly()
    {
        string json = """{ "ids": [ "\\d{3}" ] }""";

        // Right set and entry, wrong code: the collision acceptance does not cover a length finding.
        var wrongCode = new AcceptedFinding(LintCode.IndicatorCollidesWithLegitimateName, "ids", "\\d{3}", "w");
        Assert.Equal(LintSeverity.Warning,
            Lint(json, Flat with { AcceptedFindings = new[] { wrongCode } }).Single(LintCode.IndicatorTooShort).Severity);

        // Wrong set.
        var wrongSet = new AcceptedFinding(LintCode.IndicatorTooShort, "other", "\\d{3}", "w");
        Assert.Equal(LintSeverity.Warning,
            Lint(json, Flat with { AcceptedFindings = new[] { wrongSet } }).Single(LintCode.IndicatorTooShort).Severity);

        // Entry differs only by case: ordinal comparison, so it does not match.
        var wrongCase = new AcceptedFinding(LintCode.IndicatorTooShort, "ids", "\\D{3}", "w");
        Assert.Equal(LintSeverity.Warning,
            Lint(json, Flat with { AcceptedFindings = new[] { wrongCase } }).Single(LintCode.IndicatorTooShort).Severity);
    }

    // ── AllowlistSwallowsDetection ───────────────────────────────────────────────

    private const string SwallowJson = """{ "benign": [ "^SYSTEM$" ], "procs": [ "^SYSTEM$" ] }""";

    private static readonly LintOptions Swallow = Flat with { AllowlistNames = new[] { "benign" } };

    [Fact]
    public void AnAcceptedSwallowedDetectionIsInfoOnTheAllowlistEntryAndUnacceptedIsWarning()
    {
        var unaccepted = Lint(SwallowJson, Swallow).Single(LintCode.AllowlistSwallowsDetection);
        Assert.Equal(LintSeverity.Warning, unaccepted.Severity);
        Assert.Equal("benign", unaccepted.SetName);
        Assert.Equal("^SYSTEM$", unaccepted.Entry);

        // Keyed on what the finding reports: the ALLOWLIST set and entry.
        var accepted = new AcceptedFinding(LintCode.AllowlistSwallowsDetection, "benign", "^SYSTEM$", "phase 47 pairs benign with a different set");
        var finding = Lint(SwallowJson, Swallow with { AcceptedFindings = new[] { accepted } }).Single(LintCode.AllowlistSwallowsDetection);
        Assert.Equal(LintSeverity.Info, finding.Severity);
        Assert.EndsWith(" [accepted: phase 47 pairs benign with a different set]", finding.Message);
        Assert.Equal("benign", finding.SetName);
        Assert.Equal("^SYSTEM$", finding.Entry);
    }

    [Fact]
    public void ASwallowAcceptanceNamingTheIndicatorSideDoesNotMatch()
    {
        // The indicator set has the same entry text; naming it instead of the allowlist is a
        // different (set, entry) pair and must not accept the finding.
        var indicatorSide = new AcceptedFinding(LintCode.AllowlistSwallowsDetection, "procs", "^SYSTEM$", "w");
        Assert.Equal(LintSeverity.Warning,
            Lint(SwallowJson, Swallow with { AcceptedFindings = new[] { indicatorSide } }).Single(LintCode.AllowlistSwallowsDetection).Severity);
    }

    [Fact]
    public void AnAcceptedSwallowStillLeavesEveryOtherCodeAlone()
    {
        // Accepting the swallow does not touch the same allowlist entry's other findings, and
        // an acceptance never removes a finding — it is still there, just at Info.
        var accepted = new AcceptedFinding(LintCode.AllowlistSwallowsDetection, "benign", "^SYSTEM$", "w");
        var result = Lint(SwallowJson, Swallow with { AcceptedFindings = new[] { accepted } });
        Assert.Single(result.WithCode(LintCode.AllowlistSwallowsDetection));
        Assert.Equal(
            Lint(SwallowJson, Swallow).Findings.Count,
            result.Findings.Count);
    }

    // ── End to end through the tool ──────────────────────────────────────────────

    [Fact]
    public void LintToolHonoursAcceptedFindingsFromTheManifest()
    {
        string dir = Path.Combine(Path.GetTempPath(), "scythe-lint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string rules = Path.Combine(dir, "rules.json");
            File.WriteAllText(rules, """{ "benign": [ "^SYSTEM$" ], "procs": [ "^SYSTEM$" ] }""");
            string manifest = Path.Combine(dir, "manifest.json");
            File.WriteAllText(manifest, """
                { "shape": "flat", "allowlists": ["benign"], "consumed": ["procs"],
                  "accepted_findings": [ { "code": "AllowlistSwallowsDetection", "set": "benign", "entry": "^SYSTEM$", "why": "reviewed" } ] }
                """);

            // Without the acceptance the swallow is a warning, so --fail-on-warning fails.
            string bare = Path.Combine(dir, "bare.json");
            File.WriteAllText(bare, """{ "shape": "flat", "allowlists": ["benign"], "consumed": ["procs"] }""");
            Assert.Equal(LintTool.ExitFindings,
                LintTool.Run(new[] { rules, "--manifest", bare, "--fail-on-warning" }, new StringWriter(), new StringWriter()));

            var stdout = new StringWriter();
            var stderr = new StringWriter();
            int exit = LintTool.Run(new[] { rules, "--manifest", manifest, "--fail-on-warning" }, stdout, stderr);
            Assert.Equal("", stderr.ToString());
            Assert.Equal(LintTool.ExitClean, exit);
            Assert.Contains("[accepted: reviewed]", stdout.ToString());
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
