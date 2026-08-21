using System.Text.Json;
using ZeroBreach.Core.Model;
using ZeroBreach.Core.Profiles;
using ZeroBreach.Core.Reporting;
using ZeroBreach.Core.Scanning;
using ZeroBreach.Core.Signatures;

namespace ZeroBreach.Tests;

/// <summary>Per-phase timings (spec §7): every phase that actually ran — including one that
/// crashed or was cancelled mid-way — records a wall-clock PhaseTiming; skipped/excluded
/// phases (which did not run) record nothing, and the JSON report carries the timings only
/// when the caller supplies them.</summary>
public class PhaseTimingTests
{
    private sealed class FakeScanner : IScanner
    {
        public required int PhaseNum { get; init; }
        public required string GroupName { get; init; }
        public ScanDepth MinDepthValue { get; init; } = ScanDepth.Quick;
        public int FindingsToEmit { get; init; }
        public Exception? Throws { get; init; }
        /// <summary>When set, Run cancels this source then throws — a genuine mid-phase
        /// scan cancellation (a stray OCE without the token reads as a crash instead).</summary>
        public CancellationTokenSource? CancelsMidRun { get; init; }

        public int Phase => PhaseNum;
        public string Name => $"Fake {GroupName}";
        public string Group => GroupName;
        public ScanDepth MinDepth => MinDepthValue;

        public void Run(ScanContext ctx, IFindingSink sink)
        {
            for (var i = 0; i < FindingsToEmit; i++)
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(GroupName, $"target-{i}", $"phase-{PhaseNum}"),
                    Severity = Severity.Info,
                    Description = "fake finding",
                    Target = $"target-{i}",
                    Group = GroupName,
                });
            if (CancelsMidRun is not null)
            {
                CancelsMidRun.Cancel();
                throw new OperationCanceledException();
            }
            if (Throws is not null) throw Throws;
            // Real scanners must report at least one CheckStatus (PhaseRunner enforces it).
            sink.ReportCheck(new CheckStatus(PhaseNum, Name, CheckOutcome.Completed));
        }
    }

    private static ScanContext Ctx(ScanDepth depth = ScanDepth.Deep, CancellationToken cancel = default) => new()
    {
        Depth = depth,
        Signatures = new SignatureDb(),
        Profiles = new List<UserProfile>(),
        Cancel = cancel,
    };

    [Fact]
    public void Executed_phases_record_timings_with_phase_numbers_and_finding_counts()
    {
        var a = new FakeScanner { PhaseNum = 1, GroupName = "Persistence", FindingsToEmit = 2 };
        var b = new FakeScanner { PhaseNum = 2, GroupName = "EventLog", FindingsToEmit = 0 };
        var collector = new FindingCollector();

        new PhaseRunner(new IScanner[] { a, b }).Run(Ctx(), collector);

        Assert.Equal(2, collector.PhaseTimings.Count);
        Assert.Equal(new[] { 1, 2 }, collector.PhaseTimings.Select(t => t.Phase).ToArray());
        Assert.Equal(2, collector.PhaseTimings[0].FindingCount);
        Assert.Equal("Fake Persistence", collector.PhaseTimings[0].Name);
        Assert.Equal(0, collector.PhaseTimings[1].FindingCount);
        Assert.All(collector.PhaseTimings, t => Assert.True(t.Elapsed >= TimeSpan.Zero));
    }

    [Fact]
    public void Crashing_scanner_still_records_a_timing_and_its_inconclusive_status()
    {
        // Spec §6.7: the crash reads Inconclusive, never clean — and time WAS spent, so the
        // phase still shows up in the timings (partial findings included in its count).
        var crasher = new FakeScanner
        {
            PhaseNum = 3, GroupName = "Rootkit", FindingsToEmit = 1,
            Throws = new InvalidOperationException("boom"),
        };
        var collector = new FindingCollector();

        new PhaseRunner(new IScanner[] { crasher }).Run(Ctx(), collector);

        var timing = Assert.Single(collector.PhaseTimings);
        Assert.Equal(3, timing.Phase);
        Assert.Equal(1, timing.FindingCount);
        var check = Assert.Single(collector.Checks);
        Assert.Equal(CheckOutcome.Inconclusive, check.Outcome);
        Assert.Contains("crashed", check.Detail);
    }

    [Fact]
    public void Cancelled_scanner_records_its_timing_before_the_run_stops()
    {
        using var cts = new CancellationTokenSource();
        var cancelled = new FakeScanner
        {
            PhaseNum = 1, GroupName = "Persistence", FindingsToEmit = 1,
            CancelsMidRun = cts,
        };
        var never = new FakeScanner { PhaseNum = 2, GroupName = "EventLog" };
        var collector = new FindingCollector();

        new PhaseRunner(new IScanner[] { cancelled, never }).Run(Ctx(cancel: cts.Token), collector);

        var timing = Assert.Single(collector.PhaseTimings);
        Assert.Equal(1, timing.Phase);
        Assert.Equal(1, timing.FindingCount);
        var interrupted = Assert.Single(collector.Checks, c => c.Phase == 1);
        Assert.Equal(CheckOutcome.Inconclusive, interrupted.Outcome);
        Assert.Contains("cancelled", interrupted.Detail);
        // The never-started phase is disclosed too (spec §6.7) — CancellationCoverageTests
        // pins that behavior in full; here we just confirm it doesn't get a timing.
        var neverRan = Assert.Single(collector.Checks, c => c.Phase == 2);
        Assert.Equal(CheckOutcome.Skipped, neverRan.Outcome);
    }

    [Fact]
    public void Excluded_and_depth_skipped_phases_record_no_timing()
    {
        // Skipped phases did not run — a timing for them would fake coverage (spec §6.7).
        var excluded = new FakeScanner { PhaseNum = 1, GroupName = "EventLog" };
        var tooDeep = new FakeScanner { PhaseNum = 2, GroupName = "ContentScan", MinDepthValue = ScanDepth.Deep };
        var ran = new FakeScanner { PhaseNum = 3, GroupName = "Persistence" };
        var collector = new FindingCollector();

        new PhaseRunner(new IScanner[] { excluded, tooDeep, ran }, new[] { "EventLog" })
            .Run(Ctx(ScanDepth.Quick), collector);

        var timing = Assert.Single(collector.PhaseTimings);
        Assert.Equal(3, timing.Phase);
        Assert.Equal(2, collector.Checks.Count(c => c.Outcome == CheckOutcome.Skipped));
    }

    [Fact]
    public void Report_with_timings_serializes_phases_array()
    {
        var timings = new[]
        {
            new PhaseTiming(1, "Persistence", TimeSpan.FromMilliseconds(1234.4), 2),
            new PhaseTiming(2, "Event Log", TimeSpan.Zero, 0),
        };
        var report = ScanReport.Build("1.0", "FULL", DateTime.UtcNow,
            Array.Empty<Finding>(), Array.Empty<CheckStatus>(),
            ScanSummary.Build(Array.Empty<Finding>(), Array.Empty<CheckStatus>(), TimeSpan.FromSeconds(2)),
            timings);

        using var doc = JsonDocument.Parse(report.ToJson());
        var phases = doc.RootElement.GetProperty("phases");
        Assert.Equal(2, phases.GetArrayLength());
        Assert.Equal(1, phases[0].GetProperty("phase").GetInt32());
        Assert.Equal("Persistence", phases[0].GetProperty("name").GetString());
        Assert.Equal(1.234, phases[0].GetProperty("elapsed_seconds").GetDouble(), 3);
        Assert.Equal(2, phases[0].GetProperty("findings").GetInt32());
        Assert.All(phases.EnumerateArray(),
            p => Assert.True(p.GetProperty("elapsed_seconds").GetDouble() >= 0));
    }

    [Fact]
    public void Report_without_timings_omits_phases_from_the_json()
    {
        var report = ScanReport.Build("1.0", "FULL", DateTime.UtcNow,
            Array.Empty<Finding>(), Array.Empty<CheckStatus>(),
            ScanSummary.Build(Array.Empty<Finding>(), Array.Empty<CheckStatus>(), TimeSpan.FromSeconds(1)));

        using var doc = JsonDocument.Parse(report.ToJson());
        Assert.False(doc.RootElement.TryGetProperty("phases", out _));
    }
}
