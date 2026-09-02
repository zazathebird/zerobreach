using Scythe.Rules.Linting;
using Scythe.Rules.Linting.Json;
using Xunit;

namespace Scythe.Rules.Tests.Linting;

public class LintToolTests : IDisposable
{
    private readonly string _dir;

    public LintToolTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "scythe-lint-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteFile(string name, string content)
    {
        string path = Path.Combine(_dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static (int Exit, string Out, string Err) Run(params string[] args)
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        int exit = LintTool.Run(args, stdout, stderr);
        return (exit, stdout.ToString(), stderr.ToString());
    }

    private const string CleanFile =
        """
        {
          "malware_families": ["mimikatz", "cobaltstrike"],
          "fp_allowlists": {
            "install_phase": ["^C:\\\\Program Files\\\\Vendor\\\\.*$"]
          },
          "references": {
            "file_scan": ["malware_families", "install_phase"]
          }
        }
        """;

    [Fact]
    public void CleanFileExitsZero()
    {
        var (exit, output, _) = Run(WriteFile("clean.json", CleanFile));
        Assert.Equal(LintTool.ExitClean, exit);
        Assert.Contains("0 critical, 0 error(s), 0 warning(s), 0 info", output);
    }

    [Fact]
    public void ErrorFindingsExitOne()
    {
        var (exit, output, _) = Run(WriteFile("bad.json", """{ "s": ["broken(regex"] }"""));
        Assert.Equal(LintTool.ExitFindings, exit);
        Assert.Contains("RegexDoesNotCompile", output);
    }

    [Fact]
    public void CriticalFindingsExitOne()
    {
        var (exit, output, _) = Run(
            WriteFile("universal.json", """{ "fp_allowlists": { "a": ["^.*$"] } }"""));
        Assert.Equal(LintTool.ExitFindings, exit);
        Assert.Contains("critical UniversalAllowlist", output);
    }

    [Fact]
    public void WarningsPassByDefaultAndFailWithTheFlag()
    {
        // The brief's open question, answered as it suggests: warnings do not fail CI
        // unless opted in.
        string path = WriteFile("warn.json",
            """{ "s": ["abc"], "references": { "phase": ["s"] } }""");
        Assert.Equal(LintTool.ExitClean, Run(path).Exit);
        Assert.Equal(LintTool.ExitFindings, Run(path, "--fail-on-warning").Exit);
    }

    [Fact]
    public void HumanOutputNamesFileKeyEntryAndPosition()
    {
        var (_, output, _) = Run(WriteFile("named.json", "{\n\"s\": [\"broken(regex\"]\n}"));
        Assert.Contains("named.json(2,7): error RegexDoesNotCompile", output);
        Assert.Contains("\"s\"", output);
        Assert.Contains("broken(regex", output);
    }

    [Fact]
    public void JsonOutputIsMachineReadableAndComplete()
    {
        var (exit, output, _) = Run(
            WriteFile("bad.json", """{ "s": ["broken(regex"] }"""), "--format", "json");
        Assert.Equal(LintTool.ExitFindings, exit);

        // The report must itself be parseable JSON; reuse the linter's own parser.
        var parsed = JsonSourceParser.Parse(output);
        Assert.Equal(OperationState.Ok, parsed.State);
        var root = Assert.IsType<JsonSourceObject>(parsed.Root);
        var byName = root.Properties.ToDictionary(p => p.Name, p => p.Value);
        Assert.Equal("bad.json", Assert.IsType<JsonSourceString>(byName["file"]).Value);
        Assert.Equal("ok", Assert.IsType<JsonSourceString>(byName["state"]).Value);
        Assert.IsType<JsonSourceObject>(byName["counts"]);

        var findings = Assert.IsType<JsonSourceArray>(byName["findings"]);
        var finding = Assert.IsType<JsonSourceObject>(
            findings.Items.Single(f =>
                ((JsonSourceObject)f).Properties.Any(p =>
                    p.Name == "code" && ((JsonSourceString)p.Value).Value == "RegexDoesNotCompile")));
        var fields = finding.Properties.ToDictionary(p => p.Name, p => p.Value);
        Assert.Equal("error", ((JsonSourceString)fields["severity"]).Value);
        Assert.Equal("s", ((JsonSourceString)fields["set"]).Value);
        Assert.Equal("broken(regex", ((JsonSourceString)fields["entry"]).Value);
        Assert.True(((JsonSourceNumber)fields["line"]).Value >= 1);
        Assert.True(((JsonSourceNumber)fields["column"]).Value >= 1);
    }

    [Fact]
    public void UnparseableJsonExitsTwoWithPosition()
    {
        var (exit, output, _) = Run(WriteFile("broken.json", "{ not json"));
        Assert.Equal(LintTool.ExitDidNotComplete, exit);
        Assert.Contains("error:", output);
        Assert.Contains("(1,3)", output); // the position of the offending token
    }

    [Fact]
    public void MissingFileExitsTwo()
    {
        var (exit, _, err) = Run(Path.Combine(_dir, "does-not-exist.json"));
        Assert.Equal(LintTool.ExitDidNotComplete, exit);
        Assert.Contains("cannot read", err);
    }

    [Fact]
    public void BadUsageExitsTwoWithUsageText()
    {
        Assert.Equal(LintTool.ExitDidNotComplete, Run().Exit);
        var (exit, _, err) = Run("--format", "yaml", "x.json");
        Assert.Equal(LintTool.ExitDidNotComplete, exit);
        Assert.Contains("--format", err);
    }

    [Fact]
    public void ManifestSuppliesExternalReferences()
    {
        string rules = WriteFile("rules.json", """{ "host_set": ["some_pattern"] }""");
        string manifest = WriteFile("manifest.json", """["host_set"]""");

        // Without the manifest: reference analysis is inactive (info only).
        var (_, without, _) = Run(rules);
        Assert.Contains("ReferenceAnalysisInactive", without);

        // With it: analysis runs and the referenced set is not an orphan.
        var (exit, with, _) = Run(rules, "--manifest", manifest);
        Assert.Equal(LintTool.ExitClean, exit);
        Assert.DoesNotContain("ReferenceAnalysisInactive", with);
        Assert.DoesNotContain("OrphanSet", with);
    }

    [Fact]
    public void ABadManifestExitsTwo()
    {
        string rules = WriteFile("rules.json", """{ "s": ["some_pattern"] }""");
        string manifest = WriteFile("manifest.json", "42");
        var (exit, _, err) = Run(rules, "--manifest", manifest);
        Assert.Equal(LintTool.ExitDidNotComplete, exit);
        Assert.Contains("array of set names", err);

        // The object form refuses a key it does not know, so a typo cannot silently
        // disable the section it was meant to fill.
        string typo = WriteFile("typo.json", """{ "not": ["a section"] }""");
        var (exit2, _, err2) = Run(rules, "--manifest", typo);
        Assert.Equal(LintTool.ExitDidNotComplete, exit2);
        Assert.Contains("unknown key 'not'", err2);
    }
}
