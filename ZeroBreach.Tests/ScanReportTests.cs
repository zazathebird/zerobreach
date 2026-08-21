using ZeroBreach.Core.Model;
using ZeroBreach.Core.Reporting;
using static ZeroBreach.Tests.TestHelpers;

namespace ZeroBreach.Tests;

/// <summary>Report persistence (spec §2/§7): a saved report — plain .json or the STEALTH
/// .json.gz blob — must be readable back without rescanning, with gzip detected by content
/// so a renamed blob still loads. Also covers the optional case_id/operator engagement
/// metadata for MSP/IR workflows.</summary>
public class ScanReportTests
{
    private static readonly DateTime Started = new(2026, 8, 19, 9, 30, 0, DateTimeKind.Utc);

    private static ScanReport MakeReport(string? caseId = null, string? operatorName = null)
    {
        var findings = new[] { MakeFinding(), MakeFinding(discriminator: "second") };
        var checks = new[]
        {
            new CheckStatus(1, "Persistence: Run keys", CheckOutcome.Completed),
            new CheckStatus(2, "Event Log: Security", CheckOutcome.Inconclusive, "log source disabled"),
        };
        var summary = ScanSummary.Build(findings, checks, TimeSpan.FromSeconds(12.5));
        return ScanReport.Build("1.2.3-test", "FULL", Started, findings, checks, summary,
            phaseTimings: null, caseId: caseId, operatorName: operatorName);
    }

    [Fact]
    public void Plain_json_save_load_roundtrip_preserves_report_identity()
    {
        var dir = NewScratchDir();
        var path = Path.Combine(dir, "report.json");
        var original = MakeReport();
        try
        {
            File.WriteAllText(path, original.ToJson());
            var loaded = ScanReport.Load(path);
            Assert.Equal(original.Version, loaded.Version);
            Assert.Equal(original.Host, loaded.Host);
            Assert.Equal(original.Mode, loaded.Mode);
            Assert.Equal(original.Findings.Count, loaded.Findings.Count);
            Assert.Equal(original.Summary.Verdict, loaded.Summary.Verdict);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Stealth_compressed_blob_roundtrips_through_load()
    {
        var dir = NewScratchDir();
        var path = Path.Combine(dir, "report.json.gz");
        var original = MakeReport();
        try
        {
            original.WriteCompressed(path);
            var loaded = ScanReport.Load(path);
            Assert.Equal(original.Version, loaded.Version);
            Assert.Equal(original.Host, loaded.Host);
            Assert.Equal(original.Mode, loaded.Mode);
            Assert.Equal(original.Findings.Count, loaded.Findings.Count);
            Assert.Equal(original.Summary.Verdict, loaded.Summary.Verdict);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Gzip_blob_renamed_to_json_still_loads_because_detection_is_by_content()
    {
        // Spec §2/§7 spirit: the stealth blob is the run's only artifact — losing it to a
        // rename would mean rescanning, so gzip is sniffed from the magic bytes, not the name.
        var dir = NewScratchDir();
        var path = Path.Combine(dir, "renamed-report.json");
        var original = MakeReport();
        try
        {
            original.WriteCompressed(path);
            var loaded = ScanReport.Load(path);
            Assert.Equal(original.Summary.Verdict, loaded.Summary.Verdict);
            Assert.Equal(original.Findings.Count, loaded.Findings.Count);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("{ this is not json")]
    [InlineData("null")]
    public void Malformed_or_null_file_throws_InvalidDataException_naming_the_path(string content)
    {
        var dir = NewScratchDir();
        var path = Path.Combine(dir, "broken.json");
        try
        {
            File.WriteAllText(path, content);
            var ex = Assert.Throws<InvalidDataException>(() => ScanReport.Load(path));
            Assert.Contains(path, ex.Message);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Build_with_case_and_operator_serializes_them_as_case_id_and_operator()
    {
        var json = MakeReport(caseId: "IR-2026-0042", operatorName: "P. McClevarty").ToJson();
        Assert.Contains("\"case_id\": \"IR-2026-0042\"", json);
        Assert.Contains("\"operator\": \"P. McClevarty\"", json);
    }

    [Fact]
    public void Build_without_engagement_metadata_omits_both_keys()
    {
        var json = MakeReport().ToJson();
        Assert.DoesNotContain("case_id", json);
        Assert.DoesNotContain("\"operator\"", json);
    }

    [Fact]
    public void Existing_arity_Build_call_still_compiles_and_omits_case_id()
    {
        // The new parameters are trailing optionals — every pre-existing caller keeps working.
        var findings = new[] { MakeFinding() };
        var checks = new[] { new CheckStatus(1, "Persistence: Run keys", CheckOutcome.Completed) };
        var summary = ScanSummary.Build(findings, checks, TimeSpan.FromSeconds(1));

        var report = ScanReport.Build("1.2.3-test", "QUICK", Started, findings, checks, summary);

        Assert.Null(report.CaseId);
        Assert.Null(report.Operator);
        Assert.DoesNotContain("case_id", report.ToJson());
    }

    [Fact]
    public void Baseline_diff_is_recorded_in_the_report_and_survives_a_roundtrip()
    {
        // A diffed report indistinguishable from a clean one is the §6.7 sin — the report
        // must carry what the baseline suppressed and its sanity warnings.
        var findings = new[] { MakeFinding() };
        var checks = new[] { new CheckStatus(1, "Persistence: Run keys", CheckOutcome.Completed) };
        var summary = ScanSummary.Build(findings, checks, TimeSpan.FromSeconds(1));
        var baseline = new ScanReport.BaselineJson
        {
            Path = "/cases/old-baseline.json",
            Host = "OTHER-HOST",
            CreatedUtc = Started.AddDays(-40),
            Suppressed = 3,
            Warnings = new List<string> { "baseline was created on host 'OTHER-HOST'..." },
        };

        var report = ScanReport.Build("1.2.3-test", "FULL", Started, findings, checks, summary,
            baseline: baseline);
        var json = report.ToJson();
        Assert.Contains("\"baseline\"", json);
        Assert.Contains("\"suppressed\": 3", json);

        var dir = NewScratchDir();
        var path = Path.Combine(dir, "diffed.json");
        try
        {
            File.WriteAllText(path, json);
            var loaded = ScanReport.Load(path);
            Assert.NotNull(loaded.Baseline);
            Assert.Equal(3, loaded.Baseline!.Suppressed);
            Assert.Equal("OTHER-HOST", loaded.Baseline.Host);
            Assert.Single(loaded.Baseline.Warnings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }

        // No baseline supplied → key absent, so a plain run's report shape is unchanged.
        Assert.DoesNotContain("\"baseline\"", MakeReport().ToJson());
    }
}
