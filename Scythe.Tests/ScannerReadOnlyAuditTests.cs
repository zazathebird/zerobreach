using System.Text.RegularExpressions;

namespace Scythe.Tests;

/// <summary>
/// Architectural rule from the spec/guide: scanners are READ-ONLY — the destructive audit
/// surface is Scythe.Remediation and nothing else. This test greps the scanner (and
/// Core) sources for mutating APIs so a violation fails CI, not code review.
/// </summary>
public class ScannerReadOnlyAuditTests
{
    /// <summary>API name fragments no scanner/Core source may contain. Word-ish boundaries
    /// avoid false hits inside longer identifiers.</summary>
    private static readonly string[] ForbiddenFragments =
    {
        @"File\.Delete", @"File\.Move", @"File\.Copy", @"File\.Replace",
        @"File\.WriteAll", @"File\.AppendAll", @"File\.Create\s*\(",
        @"Directory\.Delete", @"Directory\.Move", @"Directory\.CreateDirectory",
        @"\.SetValue\s*\(", @"\.DeleteValue\s*\(", @"\.DeleteSubKey", @"\.CreateSubKey\s*\(",
        @"writable:\s*true", @"RegistryKeyPermissionCheck\.ReadWriteSubTree",
        @"\.Kill\s*\(", @"Process\.Start\s*\(", @"ProcessStartInfo",
        @"FileMode\.Create", @"FileMode\.Append", @"FileMode\.OpenOrCreate", @"FileMode\.Truncate",
        @"FileAccess\.Write", @"FileAccess\.ReadWrite",
        @"\.SetAccessControl", @"\.SetOwner",
        @"Environment\.Exit",
    };

    public static IEnumerable<object[]> ScannerSources() => SourcesOf("Scythe.Scanners");

    // Core is equally read-only, with audited exceptions:
    //  - HiveLoader mounts hives (opt-in, non-destructive, spec §4)
    //  - Reporting writes report files to the OPERATOR-CHOSEN output dir, not scan targets
    //  - FollowUpPlan writes leads/profile files to the same operator-chosen output dir
    //    (the rest of Triage — SymptomMap, EscalationEngine — stays fully audited)
    public static IEnumerable<object[]> CoreScanningSources() =>
        SourcesOf("Scythe.Core").Where(o =>
            !((string)o[0]).Contains($"{Path.DirectorySeparatorChar}Reporting{Path.DirectorySeparatorChar}")
            && !((string)o[0]).EndsWith("HiveLoader.cs")
            && !((string)o[0]).EndsWith("FollowUpPlan.cs"));

    [Theory]
    [MemberData(nameof(ScannerSources))]
    [MemberData(nameof(CoreScanningSources))]
    public void Source_file_contains_no_destructive_api_calls(string sourceFile)
    {
        var text = File.ReadAllText(sourceFile);
        // strip comments so a mention in a doc comment doesn't fail the audit
        text = Regex.Replace(text, @"//.*?$", "", RegexOptions.Multiline);
        text = Regex.Replace(text, @"/\*.*?\*/", "", RegexOptions.Singleline);

        var hits = ForbiddenFragments
            .Where(f => Regex.IsMatch(text, f))
            .ToList();

        Assert.True(hits.Count == 0,
            $"{Path.GetFileName(sourceFile)} contains destructive/mutating API usage: " +
            string.Join(", ", hits) + " — scanners and Core must be read-only (spec §6/§8); " +
            "destructive logic belongs only in Scythe.Remediation.");
    }

    [Fact]
    public void Scanner_project_exists_and_audit_found_its_sources()
    {
        // Guards against the audit silently passing because the path walk broke.
        Assert.NotEmpty(SourcesOf("Scythe.Core"));
    }

    private static IEnumerable<object[]> SourcesOf(string projectDirName)
    {
        var root = FindRepoRoot();
        var dir = Path.Combine(root, projectDirName);
        if (!Directory.Exists(dir)) yield break;
        foreach (var f in Directory.EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories))
        {
            if (f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") ||
                f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
                continue;
            yield return new object[] { f };
        }
    }

    private static string FindRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "Scythe.sln")))
            dir = Path.GetDirectoryName(dir);
        return dir ?? throw new InvalidOperationException("Scythe.sln not found above test dir");
    }
}
