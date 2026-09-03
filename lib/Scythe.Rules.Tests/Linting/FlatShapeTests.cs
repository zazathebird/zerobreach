using Scythe.Rules.Linting;
using Xunit;
using static Scythe.Rules.Tests.Linting.LintTestHelpers;

namespace Scythe.Rules.Tests.Linting;

/// <summary>
/// The flat rule-file shape and the host-declared match kinds — what lets the linter read
/// <c>data/detection_signatures.json</c> as the engine reads it instead of as the nested
/// BLUEPRINT §9 schema. Every category is proven in both directions: the check it disables
/// stays live for a set not in the category.
/// </summary>
public class FlatShapeTests
{
    private static readonly LintOptions Flat = LintOptions.Default with { Shape = RuleFileShape.Flat };

    [Fact]
    public void CommentKeysAreDocumentationNotSets()
    {
        var result = Lint("""{ "_comment_x": "explains x", "x": ["abcd"] }""", Flat);
        result.AssertNone(LintCode.SchemaViolation);
        // Nested shape still refuses a string value: the comment convention is a flat-file property.
        Assert.Single(Lint("""{ "_comment_x": "explains x", "x": ["abcd"] }""").WithCode(LintCode.SchemaViolation));
    }

    [Fact]
    public void ASingleRegexStringIsAOneEntrySet()
    {
        var result = Lint("""{ "c2_named_pipe_regex": "meterpreter|(unclosed" }""", Flat);
        var finding = result.Single(LintCode.RegexDoesNotCompile);
        Assert.Equal("c2_named_pipe_regex", finding.SetName);
    }

    [Fact]
    public void RuleObjectsLintTheirPatternFieldsAndNothingElse()
    {
        // "Name" and "Why" are prose; only Pattern / *Rx / *_rule / *Regex are regexes.
        string json = """
            { "rules": [
                { "Name": "bad (prose", "Pattern": "(unclosed", "Why": "also (prose" },
                { "Name": "ok", "Rx": "(?i)^psexesvc\\.exe$", "Severity": "HIGH" },
                { "Name": "ok2", "unattended_rule": "(also unclosed", "NameRx": "^a$" }
            ] }
            """;
        var result = Lint(json, Flat);
        var broken = result.WithCode(LintCode.RegexDoesNotCompile);
        Assert.Equal(2, broken.Count);
        Assert.All(broken, f => Assert.Equal("rules", f.SetName));
        Assert.Contains(broken, f => f.Entry == "(unclosed");
        Assert.Contains(broken, f => f.Entry == "(also unclosed");
        result.AssertNone(LintCode.SchemaViolation);
    }

    [Fact]
    public void NumberListsAndThresholdObjectsAreDeclaredButNotEmpty()
    {
        var options = Flat with { ExternalReferences = new[] { "stratum_ports", "thresholds" } };
        var result = Lint("""{ "stratum_ports": [3333, 4444], "thresholds": { "MaxFiles": 400 } }""", options);
        result.AssertNone(LintCode.EmptyIndicatorSet);
        result.AssertNone(LintCode.SchemaViolation);
        result.AssertNone(LintCode.DanglingReference);
        result.AssertNone(LintCode.OrphanSet);
        // A genuinely empty array is still empty in either shape.
        Assert.Single(Lint("""{ "empty": [] }""", Flat).WithCode(LintCode.EmptyIndicatorSet));
    }

    [Fact]
    public void ABareScalarIsStillASchemaViolationInFlatShape()
    {
        Assert.Single(Lint("""{ "n": 42 }""", Flat).WithCode(LintCode.SchemaViolation));
        Assert.Single(Lint("""{ "b": true }""", Flat).WithCode(LintCode.SchemaViolation));
    }

    [Fact]
    public void AllowlistNamesSelectAllowlistChecksInAFlatFile()
    {
        string json = """{ "x_benign_paths": ["foo"] }""";
        // Without the name: linted as an indicator (too short / collision family), never as an allowlist.
        Lint(json, Flat).AssertNone(LintCode.UnanchoredAllowlist);
        // With it: the allowlist rule applies.
        var result = Lint(json, Flat with { AllowlistNames = new[] { "x_benign_paths" } });
        var finding = result.Single(LintCode.UnanchoredAllowlist);
        Assert.Equal(LintSeverity.Error, finding.Severity);
        result.AssertNone(LintCode.IndicatorTooShort);
    }

    [Fact]
    public void LiteralSetsAreEscapedAndMatchedAsSubstrings()
    {
        string json = """{ "paths": ["$env:APPDATA\\Roaming\\Thing"], "procs": ["svchost"], "empty": [""] }""";
        // As regexes: \R is an unrecognised escape, "svchost" collides, and "" matches everything.
        var asRegex = Lint(json, Flat);
        Assert.Single(asRegex.WithCode(LintCode.RegexDoesNotCompile));
        var regexCollision = Assert.Single(asRegex.WithCode(LintCode.IndicatorCollidesWithLegitimateName).Where(f => f.SetName == "procs"));
        Assert.Equal(LintSeverity.Error, regexCollision.Severity);

        var options = Flat with { LiteralSets = new[] { "paths", "procs", "empty" } };
        var asLiteral = Lint(json, options);
        asLiteral.AssertNone(LintCode.RegexDoesNotCompile);
        var collision = asLiteral.Single(LintCode.IndicatorCollidesWithLegitimateName);
        Assert.Contains("is a substring of", collision.Message);
        // An empty literal on a substring list matches every input: an error, not a style nit.
        var empty = Assert.Single(asLiteral.WithCode(LintCode.IndicatorTooShort).Where(f => f.SetName == "empty"));
        Assert.Equal(LintSeverity.Error, empty.Severity);
    }

    [Fact]
    public void EqualitySetsCompareWholeValues()
    {
        string json = """{ "exts": [".exe", ".bat", ""], "names": ["svchost.exe"] }""";
        var options = Flat with { EqualitySets = new[] { "exts", "names" } };
        var result = Lint(json, options);
        // ".exe" equals nothing in the corpus; "svchost.exe" equals a corpus name exactly.
        var collision = result.Single(LintCode.IndicatorCollidesWithLegitimateName);
        Assert.Equal("names", collision.SetName);
        Assert.Contains("equals", collision.Message);
        // "" by equality matches only an extension-less file, so it is not the everything-matcher.
        Assert.DoesNotContain(result.Findings, f => f.Code == LintCode.IndicatorTooShort && f.Severity == LintSeverity.Error);

        // The same file as substrings: ".exe" is inside "explorer.exe" and "" is an error.
        var asLiteral = Lint(json, Flat with { LiteralSets = new[] { "exts", "names" } });
        Assert.True(asLiteral.WithCode(LintCode.IndicatorCollidesWithLegitimateName).Count >= 2);
        Assert.Contains(asLiteral.Findings, f => f.Code == LintCode.IndicatorTooShort && f.Severity == LintSeverity.Error);
    }

    [Fact]
    public void WildcardSetsAreCheckedAsTheAnchoredGlobTheHostBuilds()
    {
        string json = """{ "tools": ["lsassy*", "*.exe"] }""";
        // As a regex "lsassy*" is "lsass" + optional y and collides with lsass.exe.
        Assert.Contains(Lint(json, Flat).WithCode(LintCode.IndicatorCollidesWithLegitimateName), f => f.Entry == "lsassy*");

        var result = Lint(json, Flat with { WildcardSets = new[] { "tools" } });
        var collisions = result.WithCode(LintCode.IndicatorCollidesWithLegitimateName);
        // "lsassy*" as a glob needs the y; "*.exe" as a glob matches every corpus executable.
        Assert.DoesNotContain(collisions, f => f.Entry == "lsassy*");
        Assert.Contains(collisions, f => f.Entry == "*.exe");
        result.AssertNone(LintCode.RegexDoesNotCompile);
    }

    [Fact]
    public void ReferenceSetsSkipCollisionAndLengthButNotCompile()
    {
        string json = """{ "system_image_names": ["svchost.exe", "ab", "(broken"] }""";
        var plain = Lint(json, Flat);
        Assert.NotEmpty(plain.WithCode(LintCode.IndicatorCollidesWithLegitimateName));
        Assert.NotEmpty(plain.WithCode(LintCode.IndicatorTooShort));

        var result = Lint(json, Flat with { ReferenceSets = new[] { "system_image_names" } });
        result.AssertNone(LintCode.IndicatorCollidesWithLegitimateName);
        result.AssertNone(LintCode.IndicatorTooShort);
        Assert.Single(result.WithCode(LintCode.RegexDoesNotCompile));
    }

    [Fact]
    public void ReferenceSetsAreNotDetectionsAnAllowlistCanSwallow()
    {
        string json = """{ "fp_allowlists": { "svc_benign": ["^(BITS|TrustedInstaller)$"] }, "safeboot": ["trustedinstaller"] }""";
        Assert.Single(Lint(json).WithCode(LintCode.AllowlistSwallowsDetection));
        Lint(json, LintOptions.Default with { ReferenceSets = new[] { "safeboot" } })
            .AssertNone(LintCode.AllowlistSwallowsDetection);
    }

    [Fact]
    public void WholeValueSetsAreNotDetectionsAnAllowlistCanSwallow()
    {
        // A path handed to Test-Path is not a detection; an allowlist that skips it is a design choice.
        string json = """{ "fp_allowlists": { "never_read": ["(?i)\\\\Microsoft\\\\Credentials(\\\\|$)"] }, "paths_raw": ["$env:APPDATA\\Microsoft\\Credentials"] }""";
        Assert.Single(Lint(json, LintOptions.Default with { LiteralSets = new[] { "paths_raw" } })
            .WithCode(LintCode.AllowlistSwallowsDetection));
        Lint(json, LintOptions.Default with { EqualitySets = new[] { "paths_raw" } })
            .AssertNone(LintCode.AllowlistSwallowsDetection);
    }

    [Theory]
    [InlineData("\\\\Program Files\\\\Foo\\\\", false)]
    [InlineData("(?i)\\\\Foo\\\\Bar(\\\\|$)", false)]
    [InlineData("(?i)\\\\Windows\\\\CCM\\\\", false)]
    [InlineData("\\\\pcl5ures\\.dll$", false)]
    [InlineData("^\\\\Tasks\\\\Microsoft\\\\", false)]
    [InlineData("foo", true)]
    [InlineData("\\\\AppData\\\\Local\\\\Temp\\\\(pip|npm)", true)]
    public void SubstringAllowlistsAreHeldToComponentAnchoringAtWarningLevel(string entry, bool warns)
    {
        string json = "{ \"fp_allowlists\": { \"x_benign_paths\": [" + System.Text.Json.JsonSerializer.Serialize(entry) + "] } }";
        var strict = Lint(json);
        var relaxed = Lint(json, LintOptions.Default with { SubstringAllowlists = new[] { "x_benign_paths" } });

        var finding = relaxed.WithCode(LintCode.UnanchoredAllowlist);
        if (warns)
        {
            Assert.Equal(LintSeverity.Warning, Assert.Single(finding).Severity);
            Assert.Contains("path component", finding[0].Message);
        }
        else
        {
            Assert.Empty(finding);
        }
        // Component anchoring is only ever a relaxation: a fully ^…$-anchored entry passes both.
        if (strict.WithCode(LintCode.UnanchoredAllowlist).Count == 0)
        {
            Assert.Empty(finding);
        }
    }

    [Fact]
    public void AnAllowlistNotDeclaredSubstringKeepsTheStrictRule()
    {
        string json = """{ "fp_allowlists": { "values": ["\\\\Program Files\\\\Foo\\\\"] } }""";
        Assert.Equal(LintSeverity.Error, Lint(json).Single(LintCode.UnanchoredAllowlist).Severity);
    }

    [Fact]
    public void CollisionAcceptancesAreReportedAtInfoWithTheReasonAndOnlyForTheExactEntry()
    {
        string json = """{ "artifacts": [ { "Name": "n", "Rx": "(?i)^[a-z]{8}\\.exe$" } ] }""";
        var accepted = new AcceptedFinding(LintCode.IndicatorCollidesWithLegitimateName, "artifacts", "(?i)^[a-z]{8}\\.exe$", "shape is the only signal; Info severity");
        var result = Lint(json, Flat with { AcceptedFindings = new[] { accepted } });
        var finding = result.Single(LintCode.IndicatorCollidesWithLegitimateName);
        Assert.Equal(LintSeverity.Info, finding.Severity);
        Assert.Contains("[accepted: shape is the only signal", finding.Message);

        // A different entry text — the rule was edited — re-opens the question.
        var stale = new AcceptedFinding(LintCode.IndicatorCollidesWithLegitimateName, "artifacts", "(?i)^[a-z]{7}\\.exe$", "old reason");
        Assert.Equal(LintSeverity.Error,
            Lint(json, Flat with { AcceptedFindings = new[] { stale } }).Single(LintCode.IndicatorCollidesWithLegitimateName).Severity);
    }

    [Fact]
    public void ManifestObjectFormParsesEverySectionAndRefusesUnknownKeys()
    {
        string text = """
            { "_comment": "doc", "shape": "flat",
              "consumed": ["a"], "allowlists": ["b"], "literal_sets": ["c"], "equality_sets": ["d"],
              "wildcard_sets": ["e"], "reference_sets": ["f"], "substring_allowlists": ["g"],
              "accepted_collisions": [ { "set": "s", "entry": "e", "why": "w" } ] }
            """;
        var errors = new StringWriter();
        var manifest = LintManifest.Parse(text, "m.json", errors);
        Assert.True(manifest is not null, errors.ToString());
        Assert.Equal(RuleFileShape.Flat, manifest!.Shape);
        var options = manifest.Apply(LintOptions.Default);
        Assert.Equal(RuleFileShape.Flat, options.Shape);
        Assert.Equal(new[] { "a", "b" }, options.ExternalReferences);
        Assert.Contains("b", options.AllowlistNames);
        Assert.Contains("c", options.LiteralSets);
        Assert.Contains("d", options.EqualitySets);
        Assert.Contains("e", options.WildcardSets);
        Assert.Contains("f", options.ReferenceSets);
        Assert.Contains("g", options.SubstringAllowlists);
        var legacy = Assert.Single(options.AcceptedFindings);
        Assert.Equal("w", legacy.Why);
        Assert.Equal(LintCode.IndicatorCollidesWithLegitimateName, legacy.Code);

        Assert.Null(LintManifest.Parse("""{ "literal-sets": ["c"] }""", "m.json", new StringWriter()));
        Assert.Null(LintManifest.Parse("""{ "shape": "round" }""", "m.json", new StringWriter()));
        Assert.Null(LintManifest.Parse("""{ "accepted_collisions": [ { "set": "s", "entry": "e" } ] }""", "m.json", new StringWriter()));
        Assert.Null(LintManifest.Parse("""{ "accepted_collisions": [ { "set": "s", "entry": "e", "why": "" } ] }""", "m.json", new StringWriter()));
    }

    [Fact]
    public void ManifestLegacyArrayFormIsTheConsumedList()
    {
        var manifest = LintManifest.Parse("""["host_set"]""", "m.json", new StringWriter());
        Assert.NotNull(manifest);
        Assert.Null(manifest!.Shape);
        Assert.Equal(new[] { "host_set" }, manifest.Apply(LintOptions.Default).ExternalReferences);
    }

    [Fact]
    public void LintToolAcceptsTheObjectManifest()
    {
        string dir = Path.Combine(Path.GetTempPath(), "scythe-lint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string rules = Path.Combine(dir, "rules.json");
            File.WriteAllText(rules, """{ "_comment_x": "doc", "x_benign": ["\\\\Program Files\\\\X\\\\"], "procs": ["$env:APPDATA\\X"] }""");
            string manifest = Path.Combine(dir, "manifest.json");
            File.WriteAllText(manifest, """{ "shape": "flat", "allowlists": ["x_benign"], "consumed": ["procs"], "equality_sets": ["procs"], "substring_allowlists": ["x_benign"] }""");

            var stdout = new StringWriter();
            var stderr = new StringWriter();
            int exit = LintTool.Run(new[] { rules, "--manifest", manifest }, stdout, stderr);
            Assert.Equal(LintTool.ExitClean, exit);
            Assert.Equal("", stderr.ToString());

            // Without the manifest the same file is unreadable in the nested schema.
            Assert.Equal(LintTool.ExitFindings, LintTool.Run(new[] { rules }, new StringWriter(), new StringWriter()));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
