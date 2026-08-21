using ZeroBreach.Core.Model;
using ZeroBreach.Core.Reporting;
using static ZeroBreach.Tests.TestHelpers;

namespace ZeroBreach.Tests;

/// <summary>Baseline-diff mode (spec §2). A baseline suppresses previously-seen findings,
/// so a wrong baseline silently hides real ones — spec §6.7 spirit: never silently hide.
/// SafetyWarnings must flag foreign, stale, and future-dated baselines before use.</summary>
public class BaselineTests
{
    private static readonly DateTime Now = new(2026, 8, 19, 12, 0, 0, DateTimeKind.Utc);

    private static Baseline Make(
        string host = "WORKSTATION-01",
        DateTime? createdUtc = null,
        IEnumerable<string>? ids = null) => new()
    {
        Host = host,
        CreatedUtc = createdUtc ?? Now,
        FindingIds = new HashSet<string>(
            ids ?? new[] { MakeFinding().Id }, StringComparer.OrdinalIgnoreCase),
    };

    [Fact]
    public void Save_load_roundtrip_preserves_host_timestamp_and_finding_ids()
    {
        var dir = NewScratchDir();
        var path = Path.Combine(dir, "baseline.json");
        var ids = new[]
        {
            Finding.ComputeId("Persistence", @"HKLM\Run\evil", "value"),
            Finding.ComputeId("C2", @"C:\Users\victim\beacon.exe", "conn"),
        };
        var original = Make(createdUtc: new DateTime(2026, 8, 1, 3, 4, 5, DateTimeKind.Utc), ids: ids);
        try
        {
            original.Save(path);
            var loaded = Baseline.Load(path);
            Assert.Equal(original.Host, loaded.Host);
            Assert.Equal(original.CreatedUtc, loaded.CreatedUtc);
            Assert.Equal(original.FindingIds.OrderBy(i => i), loaded.FindingIds.OrderBy(i => i));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Diff_splits_new_from_suppressed_and_discloses_suppressed_count()
    {
        // Spec §6.7 spirit: suppressed findings disappear from the report body but their
        // count is returned so it can always be disclosed.
        var known = MakeFinding(discriminator: "known");
        var fresh = MakeFinding(discriminator: "fresh");
        var baseline = Make(ids: new[] { known.Id });

        var (newFindings, suppressed) = baseline.Diff(new[] { known, fresh });

        Assert.Single(newFindings);
        Assert.Equal(fresh.Id, newFindings[0].Id);
        Assert.Equal(1, suppressed);
    }

    [Fact]
    public void Diff_id_comparison_is_case_insensitive()
    {
        // Ids are deterministic hashes (spec §5); casing differences in serialized files
        // must not resurrect a suppressed finding or hide a new one.
        var finding = MakeFinding(discriminator: "case");
        var baseline = Make(ids: new[] { finding.Id.ToUpperInvariant() });

        var (newFindings, suppressed) = baseline.Diff(new[] { finding });

        Assert.Empty(newFindings);
        Assert.Equal(1, suppressed);
    }

    [Fact]
    public void Host_mismatch_warns_that_a_foreign_baseline_can_suppress_real_findings()
    {
        var warnings = Make(host: "OTHER-PC").SafetyWarnings("WORKSTATION-01", Now);

        var w = Assert.Single(warnings);
        Assert.Contains("OTHER-PC", w);
        Assert.Contains("WORKSTATION-01", w);
        Assert.Contains("suppress real findings", w);
    }

    [Fact]
    public void Host_comparison_is_case_insensitive_so_same_host_different_case_does_not_warn()
    {
        Assert.Empty(Make(host: "workstation-01").SafetyWarnings("WORKSTATION-01", Now));
    }

    [Theory]
    [InlineData(31, true)]
    [InlineData(29, false)]
    public void Baseline_older_than_30_days_warns_stale_with_age_and_refresh_hint(
        int ageDays, bool expectWarning)
    {
        var warnings = Make(createdUtc: Now.AddDays(-ageDays)).SafetyWarnings("WORKSTATION-01", Now);

        if (expectWarning)
        {
            var w = Assert.Single(warnings);
            Assert.Contains($"{ageDays} days", w);
            Assert.Contains("--save-baseline", w);
        }
        else
        {
            Assert.Empty(warnings);
        }
    }

    [Theory]
    [InlineData(10, true)]  // beyond the 5-minute clock-skew tolerance
    [InlineData(2, false)]  // within tolerance
    public void Future_dated_baseline_beyond_clock_skew_tolerance_warns(
        int minutesAhead, bool expectWarning)
    {
        var warnings = Make(createdUtc: Now.AddMinutes(minutesAhead))
            .SafetyWarnings("WORKSTATION-01", Now);

        if (expectWarning)
        {
            var w = Assert.Single(warnings);
            Assert.Contains("future", w);
        }
        else
        {
            Assert.Empty(warnings);
        }
    }

    [Fact]
    public void Fresh_same_host_baseline_produces_no_warnings()
    {
        Assert.Empty(Make(createdUtc: Now.AddDays(-1)).SafetyWarnings("WORKSTATION-01", Now));
    }

    [Fact]
    public void Loaded_baseline_keeps_case_insensitive_id_matching()
    {
        // JSON deserialization builds a default-comparer HashSet; Load must rewrap it so
        // a hand-edited (uppercased) baseline id still suppresses the same finding.
        var dir = NewScratchDir();
        var path = Path.Combine(dir, "baseline.json");
        var finding = MakeFinding();
        try
        {
            Make(ids: new[] { finding.Id.ToUpperInvariant() }).Save(path);
            var (fresh, suppressed) = Baseline.Load(path).Diff(new[] { finding });
            Assert.Empty(fresh);
            Assert.Equal(1, suppressed);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
