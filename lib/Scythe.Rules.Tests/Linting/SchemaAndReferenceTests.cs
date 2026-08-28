using Scythe.Rules.Linting;
using Xunit;
using static Scythe.Rules.Tests.Linting.LintTestHelpers;

namespace Scythe.Rules.Tests.Linting;

public class SchemaTests
{
    [Fact]
    public void TopLevelMustBeAnObject()
    {
        var result = Lint("[1, 2]");
        Assert.Equal(OperationState.Ok, result.State); // linted completely; the finding fails CI
        var finding = result.Single(LintCode.SchemaViolation);
        Assert.Equal(LintSeverity.Error, finding.Severity);
        Assert.Contains("top level", finding.Message);
    }

    [Fact]
    public void IndicatorSetValueMustBeAnArray()
    {
        var result = Lint("""{ "bad_set": "not an array" }""");
        var finding = result.Single(LintCode.SchemaViolation);
        Assert.Contains("bad_set", finding.Message);
        Assert.Equal("bad_set", finding.SetName);
    }

    [Fact]
    public void SetEntriesMustBeStrings()
    {
        var result = Lint("""{ "s": ["ok_pattern", 42] }""");
        var finding = result.Single(LintCode.SchemaViolation);
        Assert.Contains("must be a string", finding.Message);
    }

    [Fact]
    public void AllowlistsKeyMustBeAnObjectOfArrays()
    {
        Assert.Single(Lint("""{ "fp_allowlists": [] }""").WithCode(LintCode.SchemaViolation));
        Assert.Single(
            Lint("""{ "fp_allowlists": { "a": "nope" } }""").WithCode(LintCode.SchemaViolation));
    }

    [Fact]
    public void DuplicateTopLevelKeysAreErrorsAtTheSecondOccurrence()
    {
        var result = Lint("{\n\"dup_set\": [\"aaaa\"],\n\"dup_set\": [\"bbbb\"]\n}");
        var finding = result.Single(LintCode.DuplicateKey);
        Assert.Equal(LintSeverity.Error, finding.Severity);
        Assert.Equal(3, finding.Location.Line);
        Assert.Contains("silently replace", finding.Message);
    }

    [Fact]
    public void DuplicateAllowlistNamesAreErrors()
    {
        var result = Lint(
            """{ "fp_allowlists": { "w": ["^a$"], "w": ["^b$"] } }""");
        Assert.Single(result.WithCode(LintCode.DuplicateKey));
    }

    [Fact]
    public void DuplicateEntriesInOneSetWarn()
    {
        var result = Lint("""{ "s": ["evil_tool_name", "evil_tool_name"] }""");
        var finding = result.Single(LintCode.DuplicateEntry);
        Assert.Equal(LintSeverity.Warning, finding.Severity);
        Assert.Equal("evil_tool_name", finding.Entry);
    }

    [Fact]
    public void EmptyIndicatorSetWarnsButEmptyAllowlistDoesNot()
    {
        var result = Lint("""{ "empty_set": [], "fp_allowlists": { "empty_allow": [] } }""");
        var finding = result.Single(LintCode.EmptyIndicatorSet);
        Assert.Equal("empty_set", finding.SetName);
    }

    [Fact]
    public void CleanFileLintsCleanApartFromTheInactiveReferenceNotice()
    {
        // Both failure directions matter: a linter that always warns gets ignored.
        var result = Lint(
            """
            {
              "malware_families": ["mimikatz", "cobaltstrike"],
              "fp_allowlists": {
                "install_phase": ["^C:\\\\Program Files\\\\Vendor\\\\.*$"]
              }
            }
            """);
        Assert.Equal(OperationState.Ok, result.State);
        var only = Assert.Single(result.Findings);
        Assert.Equal(LintCode.ReferenceAnalysisInactive, only.Code);
        Assert.Equal(LintSeverity.Info, only.Severity);
    }
}

public class ReferenceTests
{
    [Fact]
    public void NoReferenceDataYieldsExactlyOneInactiveNotice()
    {
        var result = Lint("""{ "some_set": ["some_pattern"] }""");
        var finding = result.Single(LintCode.ReferenceAnalysisInactive);
        Assert.Equal(LintSeverity.Info, finding.Severity);
        result.AssertNone(LintCode.OrphanSet);
        result.AssertNone(LintCode.DanglingReference);
    }

    [Fact]
    public void DanglingReferenceIsAnErrorAtTheTargetPosition()
    {
        var result = Lint(
            "{\n\"real_set\": [\"aaaa\"],\n\"references\": { \"scan_phase\": [\"real_set\", \"ghost_set\"] }\n}");
        var finding = result.Single(LintCode.DanglingReference);
        Assert.Equal(LintSeverity.Error, finding.Severity);
        Assert.Contains("ghost_set", finding.Message);
        Assert.Contains("scan_phase", finding.Message);
        Assert.Equal(3, finding.Location.Line);
        result.AssertNone(LintCode.ReferenceAnalysisInactive);
    }

    [Fact]
    public void UnreferencedSetsAndAllowlistsAreOrphans()
    {
        var result = Lint(
            """
            {
              "used_set": ["aaaa"],
              "orphan_set": ["bbbb"],
              "fp_allowlists": { "orphan_allow": ["^x{40}$"] },
              "references": { "phase": ["used_set"] }
            }
            """);
        var orphans = result.WithCode(LintCode.OrphanSet);
        Assert.Equal(2, orphans.Count);
        Assert.Contains(orphans, f => f.SetName == "orphan_set");
        Assert.Contains(orphans, f => f.SetName == "orphan_allow");
        Assert.DoesNotContain(orphans, f => f.SetName == "used_set");
    }

    [Fact]
    public void ExternalManifestCountsAsReferenceData()
    {
        var options = new LintOptions
        {
            ExternalReferences = new[] { "host_set", "missing_host_set" },
        };
        var result = Lint("""{ "host_set": ["aaaa"] }""", options);
        result.AssertNone(LintCode.ReferenceAnalysisInactive);
        result.AssertNone(LintCode.OrphanSet);
        var dangling = result.Single(LintCode.DanglingReference);
        Assert.Contains("missing_host_set", dangling.Message);
        Assert.Contains("external manifest", dangling.Message);
    }

    [Fact]
    public void ReferenceNamesAreComparedCaseSensitively()
    {
        // Conservative judgement call, pinned: a case-mismatched reference is reported
        // (dangling + orphan), never silently matched.
        var result = Lint(
            """
            {
              "My_Set": ["aaaa"],
              "references": { "phase": ["my_set"] }
            }
            """);
        Assert.Single(result.WithCode(LintCode.DanglingReference));
        Assert.Single(result.WithCode(LintCode.OrphanSet));
    }

    [Fact]
    public void ReferencesShapeIsValidated()
    {
        Assert.Single(Lint("""{ "references": [] }""").WithCode(LintCode.SchemaViolation));
        Assert.Single(
            Lint("""{ "references": { "phase": "not_an_array" } }""")
                .WithCode(LintCode.SchemaViolation));
    }
}
