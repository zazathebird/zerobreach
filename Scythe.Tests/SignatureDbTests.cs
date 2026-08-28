using Scythe.Core.Model;
using Scythe.Core.Signatures;
using static Scythe.Tests.TestHelpers;

namespace Scythe.Tests;

public class SignatureDbTests
{
    [Fact]
    public void Unknown_set_is_empty_not_an_error()
    {
        Assert.Empty(new SignatureDb().Set("no.such.set"));
    }

    [Fact]
    public void Text_ioc_file_classifies_lines_by_shape()
    {
        var path = Path.Combine(NewScratchDir(), "iocs.txt");
        File.WriteAllLines(path, new[]
        {
            "# comment line",
            new string('a', 64),          // sha256
            "10.20.30.40",                // ip
            "evil-c2.example.com",        // domain
            "dropper.exe",                // filename (extension excluded from domain shape)
            "",
        });

        var db = new SignatureDb();
        db.LoadIocFile(path);

        Assert.Single(db.Set("custom.hashes"));
        Assert.Single(db.Set("custom.ips"));
        Assert.Single(db.Set("custom.domains"));
        Assert.Single(db.Set("custom.filenames"));
        Assert.Empty(db.LoadErrors);

        // §6.6 discipline: text-extracted IOCs are low-precision → Possible, and the entry
        // carries no fix action at all (scanners must not arm them destructively).
        Assert.All(db.Set("custom.ips"), e => Assert.Equal(Severity.Possible, e.Severity));
    }

    [Fact]
    public void Trailing_dot_fqdn_is_stripped_and_classified_as_domain()
    {
        var path = Path.Combine(NewScratchDir(), "iocs.txt");
        File.WriteAllLines(path, new[] { "evil.com." }); // valid DNS notation, common in intel dumps

        var db = new SignatureDb();
        db.LoadIocFile(path);

        var entry = Assert.Single(db.Set("custom.domains"));
        Assert.Equal("evil.com", entry.Pattern); // stored stripped, so it matches real lookups
        Assert.Empty(db.Set("custom.filenames"));
        Assert.Empty(db.LoadErrors);
    }

    [Fact]
    public void Leading_zero_ip_is_normalized_to_canonical_form()
    {
        var path = Path.Combine(NewScratchDir(), "iocs.txt");
        File.WriteAllLines(path, new[] { "192.168.001.001" });

        var db = new SignatureDb();
        db.LoadIocFile(path);

        var entry = Assert.Single(db.Set("custom.ips"));
        Assert.Equal("192.168.1.1", entry.Pattern); // canonical form netstat output uses
        Assert.Empty(db.LoadErrors);
    }

    [Fact]
    public void Ip_shaped_line_with_invalid_octet_is_a_load_error_not_a_dead_indicator()
    {
        var path = Path.Combine(NewScratchDir(), "iocs.txt");
        File.WriteAllLines(path, new[] { "999.1.2.3" });

        var db = new SignatureDb();
        db.LoadIocFile(path);

        var err = Assert.Single(db.LoadErrors);
        Assert.Contains("999.1.2.3", err);
        Assert.Empty(db.Set("custom.ips"));
        Assert.Empty(db.Set("custom.filenames"));
    }

    [Fact]
    public void Md5_and_sha1_length_hex_are_load_errors_not_dead_filenames()
    {
        var path = Path.Combine(NewScratchDir(), "iocs.txt");
        File.WriteAllLines(path, new[]
        {
            new string('a', 32), // MD5-length
            new string('b', 40), // SHA-1-length
        });

        var db = new SignatureDb();
        db.LoadIocFile(path);

        Assert.Equal(2, db.LoadErrors.Count);
        Assert.All(db.LoadErrors, e => Assert.Contains("SHA-256", e));
        Assert.Empty(db.Set("custom.hashes"));
        Assert.Empty(db.Set("custom.filenames"));
    }

    [Fact]
    public void Fresh_db_reports_zero_match_timeouts()
    {
        Assert.Equal(0L, new SignatureDb().TotalMatchTimeouts());
    }

    [Fact]
    public void Bad_regex_in_rules_is_a_load_error_not_a_crash()
    {
        var path = Path.Combine(NewScratchDir(), "rules.json");
        File.WriteAllText(path, """
            { "sets": { "test.set": [ { "pattern": "(unclosed", "kind": "regex" } ] } }
            """);

        var db = new SignatureDb();
        db.LoadRulesFile(path);

        Assert.NotEmpty(db.LoadErrors);
        Assert.Empty(db.Set("test.set"));
    }

    [Fact]
    public void Vendor_trusted_matches_substring_case_insensitive()
    {
        var path = Path.Combine(NewScratchDir(), "rules.json");
        File.WriteAllText(path, """{ "vendorTrusted": ["TeamViewer"] }""");
        var db = new SignatureDb();
        db.LoadRulesFile(path);

        Assert.True(db.IsVendorTrusted(@"C:\Program Files\teamviewer\TeamViewer.exe"));
        Assert.False(db.IsVendorTrusted(@"C:\evil\payload.exe"));
        Assert.False(db.IsVendorTrusted(null));
    }
}

public class IndicatorEntryTests
{
    [Theory]
    [InlineData("evil.exe", "evil.exe", true)]
    [InlineData("evil.exe", "EVIL.EXE", true)]
    [InlineData("evil.exe", @"c:\path\evil.exe", false)] // literal = whole-string unless Substring
    public void Literal_matching(string pattern, string input, bool expected) =>
        Assert.Equal(expected, new IndicatorEntry { Pattern = pattern }.Matches(input));

    [Fact]
    public void Literal_substring_matching()
    {
        var e = new IndicatorEntry { Pattern = "cobalt", Substring = true };
        Assert.True(e.Matches(@"C:\tools\CobaltLoader.exe"));
    }

    [Theory]
    [InlineData(@"*.vbs", @"startup.vbs", true)]
    [InlineData(@"*.vbs", @"startup.vbs.txt", false)]
    [InlineData(@"msupd?te.exe", @"msupdAte.exe", true)]
    [InlineData(@"C:\tools\*.exe", @"C:\tools\x.exe", true)]   // literal '\' before a wildcard
    [InlineData(@"C:\tools\*.exe", @"C:\TOOLS\X.EXE", true)]   // still case-insensitive
    [InlineData(@"C:\tools\*.exe", @"C:\other\x.exe", false)]
    [InlineData("a?c", "abc", true)]
    [InlineData("a?c", "ac", false)]    // '?' is exactly one char, never zero
    [InlineData("a?c", "abbc", false)]  // ...and never two
    public void Glob_matching(string pattern, string input, bool expected) =>
        Assert.Equal(expected, new IndicatorEntry { Pattern = pattern, Kind = MatchKind.Glob }.Matches(input));

    [Fact]
    public void Glob_timeout_returns_no_match_but_is_counted()
    {
        // Catastrophic backtracking: many ".*a" segments against an 'a'-run that fails only
        // at the final "$" — the splits of the run among the segments are combinatorial.
        // (A wildcard-char-free input fails fast and never backtracks, so 'a's are required.)
        var e = new IndicatorEntry
        {
            Pattern = string.Concat(Enumerable.Repeat("*a", 20)),
            Kind = MatchKind.Glob,
        };
        var hostile = new string('a', 100) + "!";

        Assert.False(e.Matches(hostile));   // returns within the 2s match timeout
        Assert.Equal(1, e.MatchTimeouts);   // §6.7: "couldn't evaluate" is disclosed, not folded into no-match
    }

    [Fact]
    public void Regex_timeout_returns_no_match_but_is_counted()
    {
        var e = new IndicatorEntry { Pattern = "^(a+)+$", Kind = MatchKind.Regex };
        var hostile = new string('a', 40) + "!";

        Assert.False(e.Matches(hostile));
        Assert.Equal(1, e.MatchTimeouts);
    }

    [Fact]
    public void Regex_matching_and_null_input()
    {
        var e = new IndicatorEntry { Pattern = @"^readme.*\.txt$", Kind = MatchKind.Regex };
        Assert.True(e.Matches("README-RESTORE.txt"));
        Assert.False(e.Matches(null));
    }

    [Fact]
    public void Mitre_ref_built_from_technique_fields()
    {
        var e = new IndicatorEntry { Pattern = "x", Technique = "T1547.001", TechniqueName = "Run Keys", Tactic = "Persistence" };
        Assert.Equal("T1547.001", e.Mitre!.TechniqueId);
        Assert.Null(new IndicatorEntry { Pattern = "x" }.Mitre);
    }
}
