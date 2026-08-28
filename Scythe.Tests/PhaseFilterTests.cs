using Scythe.Core.Model;
using Scythe.Core.Profiles;
using Scythe.Core.Scanning;
using Scythe.Core.Signatures;

namespace Scythe.Tests;

/// <summary>Custom-scan category selection: excluded phases must not run — and must be
/// REPORTED as skipped (spec §6.7: an operator-narrowed scan never looks like a full one).</summary>
public class PhaseFilterTests
{
    private sealed class FakeScanner : IScanner
    {
        public required int PhaseNum { get; init; }
        public required string GroupName { get; init; }
        public ScanDepth MinDepthValue { get; init; } = ScanDepth.Quick;
        public bool Ran { get; private set; }

        public int Phase => PhaseNum;
        public string Name => $"Fake {GroupName}";
        public string Group => GroupName;
        public ScanDepth MinDepth => MinDepthValue;
        public void Run(ScanContext ctx, IFindingSink sink)
        {
            Ran = true;
            // Real scanners must report at least one CheckStatus (PhaseRunner enforces it).
            sink.ReportCheck(new CheckStatus(PhaseNum, Name, CheckOutcome.Completed));
        }
    }

    private static ScanContext Ctx(ScanDepth depth = ScanDepth.Deep) => new()
    {
        Depth = depth,
        Signatures = new SignatureDb(),
        Profiles = new List<UserProfile>(),
    };

    [Fact]
    public void Excluded_group_does_not_run_and_is_reported_skipped()
    {
        var persistence = new FakeScanner { PhaseNum = 1, GroupName = "Persistence" };
        var eventLog = new FakeScanner { PhaseNum = 2, GroupName = "EventLog" };
        var collector = new FindingCollector();

        new PhaseRunner(new IScanner[] { persistence, eventLog }, new[] { "EventLog" })
            .Run(Ctx(), collector);

        Assert.True(persistence.Ran);
        Assert.False(eventLog.Ran);
        var skip = Assert.Single(collector.Checks, c => c.Phase == 2);
        Assert.Equal(CheckOutcome.Skipped, skip.Outcome);
        Assert.Contains("excluded by operator", skip.Detail);
    }

    [Fact]
    public void Exclusion_is_case_insensitive()
    {
        var s = new FakeScanner { PhaseNum = 1, GroupName = "Persistence" };
        var collector = new FindingCollector();
        new PhaseRunner(new IScanner[] { s }, new[] { "persistence" }).Run(Ctx(), collector);
        Assert.False(s.Ran);
        Assert.Contains(collector.Checks, c => c.Outcome == CheckOutcome.Skipped);
    }

    [Fact]
    public void No_exclusions_runs_everything_with_no_skip_noise()
    {
        var a = new FakeScanner { PhaseNum = 1, GroupName = "A" };
        var b = new FakeScanner { PhaseNum = 2, GroupName = "B" };
        var collector = new FindingCollector();
        new PhaseRunner(new IScanner[] { a, b }).Run(Ctx(), collector);
        Assert.True(a.Ran);
        Assert.True(b.Ran);
        Assert.DoesNotContain(collector.Checks, c => c.Outcome != CheckOutcome.Completed);
    }

    [Fact]
    public void Operator_exclusion_is_reported_even_when_depth_would_skip_the_phase_anyway()
    {
        // The report should show the phase was excluded on purpose, not "wrong depth" —
        // otherwise re-running deeper would surprise the operator by NOT covering it.
        var s = new FakeScanner { PhaseNum = 1, GroupName = "ContentScan", MinDepthValue = ScanDepth.Deep };
        var collector = new FindingCollector();
        new PhaseRunner(new IScanner[] { s }, new[] { "ContentScan" }).Run(Ctx(ScanDepth.Quick), collector);
        var skip = Assert.Single(collector.Checks);
        Assert.Contains("excluded by operator", skip.Detail);
    }
}
