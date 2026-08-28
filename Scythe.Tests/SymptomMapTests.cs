using System.Text.Json;
using Scythe.Core.Scanning;
using Scythe.Core.Triage;
using static Scythe.Tests.TestHelpers;

namespace Scythe.Tests;

/// <summary>
/// Symptom-to-scan-plan mapping (spec §2 custom scans; §3 data-file philosophy):
/// deterministic offline phrase matching from technician descriptions to detection
/// categories. The safety-relevant property: the zero-match fallback is a BROAD scan
/// (empty Categories = run everything, FULL depth) — an unrecognized description must
/// never quietly shrink coverage (spec §6.7 spirit).
/// </summary>
public class SymptomMapTests
{
    /// <summary>The scanner's real detection-category names (CliOptions usage text).</summary>
    private static readonly string[] ScannerCategories =
    {
        "Persistence", "DefenseEvasion", "C2", "CredentialAccess", "Ransomware",
        "EmailResidue", "RootkitBoot", "AclIntegrity", "ContentScan", "EventLog",
    };

    [Fact]
    public void Embedded_database_loads_cleanly_and_is_big_enough()
    {
        var map = SymptomMap.LoadEmbedded();
        Assert.Empty(map.LoadErrors);

        // 40+ curated entries — the DB is the product here, not a stub.
        using var doc = JsonDocument.Parse(ReadEmbeddedSymptomsJson());
        Assert.True(doc.RootElement.GetProperty("symptoms").GetArrayLength() >= 40,
            "embedded symptoms.json must have at least 40 entries");
    }

    [Fact]
    public void Every_category_in_the_embedded_database_is_a_real_scanner_group()
    {
        // Self-consistency: a typo'd category in the DB would be dropped at Analyze time
        // (with a warning), silently weakening every plan that entry contributes to.
        using var doc = JsonDocument.Parse(ReadEmbeddedSymptomsJson());
        foreach (var symptom in doc.RootElement.GetProperty("symptoms").EnumerateArray())
        {
            var name = symptom.GetProperty("name").GetString();
            foreach (var cat in symptom.GetProperty("categories").EnumerateArray())
                Assert.True(ScannerCategories.Contains(cat.GetString()),
                    $"symptom '{name}' names '{cat}', which is not a scanner category");
        }
    }

    [Fact]
    public void Ransomware_description_maps_to_ransomware_at_deep()
    {
        var plan = SymptomMap.LoadEmbedded().Analyze(
            "there is a ransom note on the desktop and all my files are encrypted",
            ScannerCategories);

        Assert.NotEmpty(plan.Matches);
        Assert.Contains("Ransomware", plan.Categories);
        Assert.Equal("DEEP", plan.Mode);
        Assert.Empty(plan.UnmatchedInput);
        Assert.Empty(plan.Warnings);
    }

    [Fact]
    public void Miner_symptoms_map_to_c2()
    {
        var plan = SymptomMap.LoadEmbedded().Analyze(
            "fans are maxed out and the computer is slow",
            ScannerCategories);

        Assert.NotEmpty(plan.Matches);
        Assert.Contains("C2", plan.Categories);
        Assert.Contains("Persistence", plan.Categories);
    }

    [Fact]
    public void Multi_symptom_text_unions_categories_and_takes_the_deepest_mode()
    {
        var plan = SymptomMap.LoadEmbedded().Analyze(
            "homepage changed and popups everywhere, also a ransom note appeared",
            ScannerCategories);

        Assert.True(plan.Matches.Count >= 2, "expected both a browser and a ransomware match");
        Assert.Contains("Ransomware", plan.Categories);   // from the DEEP entry
        Assert.Contains("Persistence", plan.Categories);  // from the FULL browser entries
        Assert.Equal("DEEP", plan.Mode);                  // deepest wins
        Assert.Equal(plan.Categories.Count, plan.Categories.Distinct().Count());
    }

    [Fact]
    public void Unrecognized_text_falls_back_to_a_broad_full_scan_never_a_narrow_one()
    {
        var plan = SymptomMap.LoadEmbedded().Analyze(
            "the quarterly report is late\nplease fix by friday",
            ScannerCategories);

        Assert.Empty(plan.Matches);
        Assert.Empty(plan.Categories);                    // empty = run EVERYTHING
        Assert.Equal("FULL", plan.Mode);                  // never QUICK
        Assert.Equal(new[] { "the quarterly report is late", "please fix by friday" },
            plan.UnmatchedInput);
    }

    [Fact]
    public void Lines_no_fired_phrase_occurs_in_are_reported_as_unmatched()
    {
        var plan = SymptomMap.LoadEmbedded().Analyze(
            "my files are encrypted\nthe printer smells funny",
            ScannerCategories);

        Assert.NotEmpty(plan.Matches);
        Assert.Equal(new[] { "the printer smells funny" }, plan.UnmatchedInput);
    }

    [Fact]
    public void Phrase_matching_is_case_insensitive_and_whitespace_tolerant()
    {
        var plan = SymptomMap.LoadEmbedded().Analyze(
            "MY   FILES\tARE   ENCRYPTED!!!",
            ScannerCategories);

        Assert.NotEmpty(plan.Matches);
        Assert.Contains("Ransomware", plan.Categories);
    }

    [Fact]
    public void Unknown_category_in_an_extension_file_is_dropped_and_disclosed()
    {
        var dir = NewScratchDir();
        var path = Path.Combine(dir, "extra-symptoms.json");
        File.WriteAllText(path, """
            {
              "symptoms": [
                {
                  "name": "printer-gremlins",
                  "phrases": ["printer prints garbage"],
                  "categories": ["Networking", "Persistence"],
                  "depth": "FULL",
                  "rationale": "site-specific"
                }
              ]
            }
            """);

        var map = SymptomMap.LoadEmbedded();
        map.LoadFile(path);
        Assert.Empty(map.LoadErrors);                     // shape is fine; validation is per-Analyze

        var plan = map.Analyze("the printer prints garbage", ScannerCategories);
        Assert.Single(plan.Matches);
        Assert.Contains(plan.Warnings, w => w.Contains("printer-gremlins") && w.Contains("Networking"));
        Assert.DoesNotContain("Networking", plan.Categories);
        Assert.Equal(new[] { "Persistence" }, plan.Categories);
    }

    [Fact]
    public void Broken_extension_file_lands_in_load_errors_not_an_exception()
    {
        var dir = NewScratchDir();
        var path = Path.Combine(dir, "broken.json");
        File.WriteAllText(path, "{ not json");

        var map = SymptomMap.LoadEmbedded();
        map.LoadFile(path);
        Assert.Contains(map.LoadErrors, e => e.Contains("broken.json"));
    }

    [Fact]
    public void ToProfile_round_trips_through_scan_profile_load()
    {
        var plan = SymptomMap.LoadEmbedded().Analyze(
            "ransom note on desktop and defender is disabled",
            ScannerCategories);
        var profile = plan.ToProfile("triage-2026-08-19");

        var dir = NewScratchDir();
        var path = Path.Combine(dir, "triage.json");
        File.WriteAllText(path, profile.ToJson());

        var loaded = ScanProfile.Load(path);
        Assert.Equal("triage-2026-08-19", loaded.Name);
        Assert.Equal("DEEP", loaded.Mode);
        Assert.Equal(plan.Categories, loaded.Only);
        Assert.Null(loaded.Skip);
    }

    [Fact]
    public void ToProfile_with_zero_matches_selects_no_categories_meaning_run_everything()
    {
        var plan = SymptomMap.LoadEmbedded().Analyze("nothing recognizable here", ScannerCategories);
        var profile = plan.ToProfile("broad-fallback");

        // Only = null means no category selection — the whole scan runs. An EMPTY Only
        // list would be rejected by ScanProfile.Load, so prove the round trip too.
        Assert.Null(profile.Only);
        var dir = NewScratchDir();
        var path = Path.Combine(dir, "fallback.json");
        File.WriteAllText(path, profile.ToJson());
        var loaded = ScanProfile.Load(path);
        Assert.Equal("FULL", loaded.Mode);
        Assert.Null(loaded.Only);
    }

    [Fact]
    public void Matched_phrases_and_rationale_are_reported_for_operator_review()
    {
        // The mapping must be explainable: the operator sees WHICH phrase fired and WHY
        // those categories were chosen, never a bare category list.
        var plan = SymptomMap.LoadEmbedded().Analyze("my files are encrypted", ScannerCategories);
        var match = Assert.Single(plan.Matches, m => m.MatchedPhrases.Contains("files are encrypted"));
        Assert.False(string.IsNullOrWhiteSpace(match.Rationale));
        Assert.NotEmpty(match.Categories);
    }

    [Fact]
    public void Embedded_database_never_suggests_quick()
    {
        // Triage that suspects an infection never goes shallower than FULL.
        using var doc = JsonDocument.Parse(ReadEmbeddedSymptomsJson());
        foreach (var symptom in doc.RootElement.GetProperty("symptoms").EnumerateArray())
        {
            var depth = symptom.TryGetProperty("depth", out var d) ? d.GetString() : null;
            Assert.True(depth is null or "FULL" or "DEEP",
                $"symptom '{symptom.GetProperty("name")}' suggests depth '{depth}'");
        }
    }

    private static string ReadEmbeddedSymptomsJson()
    {
        var asm = typeof(SymptomMap).Assembly;
        var res = asm.GetManifestResourceNames()
            .Single(r => r.EndsWith(".Triage.symptoms.json", StringComparison.OrdinalIgnoreCase));
        using var stream = asm.GetManifestResourceStream(res)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
