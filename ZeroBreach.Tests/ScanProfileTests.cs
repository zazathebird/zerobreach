using ZeroBreach.Core.Scanning;
using static ZeroBreach.Tests.TestHelpers;

namespace ZeroBreach.Tests;

/// <summary>Custom-scan profiles (spec §2): strict parsing — a profile that doesn't say
/// exactly what the operator meant must fail the run, never silently scan differently.</summary>
public class ScanProfileTests
{
    private static string WriteProfile(string dir, string json)
    {
        var path = Path.Combine(dir, "profile.json");
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public void Round_trip_preserves_all_fields()
    {
        var dir = NewScratchDir();
        var path = WriteProfile(dir, """
            {
              "name": "dc-triage",
              "description": "domain controller triage",
              "mode": "FULL",
              "sinceHours": 48,
              "only": ["Persistence", "C2"],
              "iocFile": "iocs.txt",
              "html": true
            }
            """);

        var p = ScanProfile.Load(path);
        Assert.Equal("dc-triage", p.Name);
        Assert.Equal("FULL", p.Mode);
        Assert.Equal(48, p.SinceHours);
        Assert.Equal(new[] { "Persistence", "C2" }, p.Only);
        Assert.True(p.Html);

        // ToJson → reload gives the same effective profile.
        var path2 = Path.Combine(dir, "resaved.json");
        File.WriteAllText(path2, p.ToJson());
        var p2 = ScanProfile.Load(path2);
        Assert.Equal(p.Name, p2.Name);
        Assert.Equal(p.Mode, p2.Mode);
        Assert.Equal(p.SinceHours, p2.SinceHours);
        Assert.Equal(p.Only, p2.Only);
        Assert.Equal(p.IocFile, p2.IocFile);
    }

    [Fact]
    public void Relative_ioc_and_rules_paths_resolve_against_the_profiles_own_directory()
    {
        // A profile travels with its IOC list — relative paths must not depend on the
        // directory the technician happens to run the scan from.
        var dir = NewScratchDir();
        var path = WriteProfile(dir, """{ "iocFile": "iocs.txt", "rulesFile": "sub/rules.json" }""");

        var p = ScanProfile.Load(path);
        Assert.Equal(Path.Combine(dir, "iocs.txt"), p.IocFile);
        Assert.Equal(Path.GetFullPath(Path.Combine(dir, "sub", "rules.json")), p.RulesFile);
    }

    [Fact]
    public void Unknown_property_is_rejected_not_ignored()
    {
        // "skpi" silently ignored would run a BROADER scan than the operator believes.
        var path = WriteProfile(NewScratchDir(), """{ "mode": "FULL", "skpi": ["EventLog"] }""");
        var ex = Assert.Throws<InvalidDataException>(() => ScanProfile.Load(path));
        Assert.Contains("skpi", ex.Message);
    }

    [Fact]
    public void Invalid_mode_is_rejected()
    {
        var path = WriteProfile(NewScratchDir(), """{ "mode": "PARANOID" }""");
        var ex = Assert.Throws<InvalidDataException>(() => ScanProfile.Load(path));
        Assert.Contains("PARANOID", ex.Message);
    }

    [Theory]
    [InlineData("""{ "mode": "FULL", "only": [] }""")]
    [InlineData("""{ "mode": "FULL", "skip": [] }""")]
    public void Empty_category_list_is_rejected_not_silently_ignored(string json)
    {
        // An ignored empty list runs a BROADER scan than the profile text suggests —
        // same hard-error rule as the CLI's `--only ","`.
        var path = WriteProfile(NewScratchDir(), json);
        var ex = Assert.Throws<InvalidDataException>(() => ScanProfile.Load(path));
        Assert.Contains("at least one category", ex.Message);
    }

    [Fact]
    public void Mode_is_normalized_to_upper_case()
    {
        var path = WriteProfile(NewScratchDir(), """{ "mode": "deep" }""");
        Assert.Equal("DEEP", ScanProfile.Load(path).Mode);
    }

    [Fact]
    public void Only_and_skip_together_are_rejected()
    {
        var path = WriteProfile(NewScratchDir(),
            """{ "only": ["Persistence"], "skip": ["EventLog"] }""");
        Assert.Throws<InvalidDataException>(() => ScanProfile.Load(path));
    }

    [Fact]
    public void Negative_since_hours_is_rejected()
    {
        var path = WriteProfile(NewScratchDir(), """{ "sinceHours": -5 }""");
        Assert.Throws<InvalidDataException>(() => ScanProfile.Load(path));
    }

    [Fact]
    public void Malformed_json_and_missing_file_are_clear_errors()
    {
        var dir = NewScratchDir();
        Assert.Throws<InvalidDataException>(() => ScanProfile.Load(Path.Combine(dir, "nope.json")));
        Assert.Throws<InvalidDataException>(() => ScanProfile.Load(WriteProfile(dir, "{ not json")));
    }

    [Fact]
    public void Profile_has_no_way_to_express_per_run_opt_ins()
    {
        // Spec §4: hive loading is an explicit per-run opt-in; interactive remediation and
        // baselines are per-run too. The profile type must not even have the properties —
        // this locks the door at the schema, and Load() rejects unknown members anyway.
        var names = typeof(ScanProfile).GetProperties().Select(p => p.Name).ToList();
        Assert.DoesNotContain("LoadHives", names);
        Assert.DoesNotContain("Interactive", names);
        Assert.DoesNotContain("BaselinePath", names);
        Assert.DoesNotContain("SaveBaselinePath", names);
        var path = WriteProfile(NewScratchDir(), """{ "loadHives": true }""");
        Assert.Throws<InvalidDataException>(() => ScanProfile.Load(path));
    }
}
