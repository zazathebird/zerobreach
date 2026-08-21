using ZeroBreach.Core.Model;
using ZeroBreach.Core.Profiles;
using ZeroBreach.Core.Scanning;
using ZeroBreach.Core.Signatures;

namespace ZeroBreach.Tests;

/// <summary>Cancellation coverage (spec §6.7): when a scan is cancelled (operator interrupt
/// or --max-minutes deadline), every phase that never started must surface as a Skipped
/// check — an unchecked area must never silently vanish from the report. The interrupted
/// phase itself stays Inconclusive with its PhaseTiming, and no phase gets two statuses.</summary>
public class CancellationCoverageTests
{
    private sealed class FakeScanner : IScanner
    {
        public required int PhaseNum { get; init; }
        public required string GroupName { get; init; }
        public ScanDepth MinDepthValue { get; init; } = ScanDepth.Quick;
        /// <summary>When set, Run cancels this source then throws OperationCanceledException —
        /// simulating a Ctrl+C / deadline landing mid-phase.</summary>
        public CancellationTokenSource? CancelsMidRun { get; init; }
        public bool Ran { get; private set; }

        public int Phase => PhaseNum;
        public string Name => $"Fake {GroupName}";
        public string Group => GroupName;
        public ScanDepth MinDepth => MinDepthValue;

        /// <summary>When set, Run throws OperationCanceledException WITHOUT cancelling the
        /// scan token — simulating a scanner-internal timeout escaping (must read as a crash
        /// of that phase, never as whole-run cancellation).</summary>
        public bool ThrowsStrayCancellation { get; init; }

        /// <summary>When set, Run completes without reporting any CheckStatus — simulating
        /// an undisciplined scanner (PhaseRunner's §6.7 backstop must flag it).</summary>
        public bool SkipsCheckStatus { get; init; }

        public void Run(ScanContext ctx, IFindingSink sink)
        {
            Ran = true;
            if (CancelsMidRun is not null)
            {
                CancelsMidRun.Cancel();
                throw new OperationCanceledException();
            }
            if (ThrowsStrayCancellation) throw new OperationCanceledException();
            if (!SkipsCheckStatus)
                sink.ReportCheck(new CheckStatus(PhaseNum, Name, CheckOutcome.Completed));
        }
    }

    private static ScanContext Ctx(CancellationToken cancel = default, ScanDepth depth = ScanDepth.Deep) => new()
    {
        Depth = depth,
        Signatures = new SignatureDb(),
        Profiles = new List<UserProfile>(),
        Cancel = cancel,
    };

    [Fact]
    public void Mid_run_cancellation_reports_every_not_yet_started_phase_as_skipped()
    {
        using var cts = new CancellationTokenSource();
        var first = new FakeScanner { PhaseNum = 1, GroupName = "Persistence" };
        var interrupted = new FakeScanner { PhaseNum = 2, GroupName = "EventLog", CancelsMidRun = cts };
        var neverA = new FakeScanner { PhaseNum = 3, GroupName = "Rootkit" };
        var neverB = new FakeScanner { PhaseNum = 4, GroupName = "Network" };
        var collector = new FindingCollector();

        new PhaseRunner(new IScanner[] { first, interrupted, neverA, neverB })
            .Run(Ctx(cts.Token), collector);

        Assert.True(first.Ran);
        Assert.True(interrupted.Ran);
        Assert.False(neverA.Ran);
        Assert.False(neverB.Ran);

        // The interrupted phase: exactly one Inconclusive status, plus its timing (spec §7).
        var inconclusive = Assert.Single(collector.Checks, c => c.Phase == 2);
        Assert.Equal(CheckOutcome.Inconclusive, inconclusive.Outcome);
        Assert.Contains("cancelled mid-phase", inconclusive.Detail);
        Assert.Contains(collector.PhaseTimings, t => t.Phase == 2);

        // The phases that never started: exactly one Skipped status each, naming cancellation.
        foreach (var phase in new[] { 3, 4 })
        {
            var skip = Assert.Single(collector.Checks, c => c.Phase == phase);
            Assert.Equal(CheckOutcome.Skipped, skip.Outcome);
            Assert.Contains("cancelled before this phase started", skip.Detail);
            Assert.Contains("NOT checked", skip.Detail);
        }

        // No phase ends up with two statuses, and phases without timings recorded none.
        Assert.All(collector.Checks.GroupBy(c => c.Phase), g => Assert.Single(g));
        Assert.DoesNotContain(collector.PhaseTimings, t => t.Phase is 3 or 4);
    }

    [Fact]
    public void Token_cancelled_before_run_reports_all_phases_skipped_with_no_timings()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var scanners = new[]
        {
            new FakeScanner { PhaseNum = 1, GroupName = "Persistence" },
            new FakeScanner { PhaseNum = 2, GroupName = "EventLog" },
            new FakeScanner { PhaseNum = 3, GroupName = "Rootkit" },
            new FakeScanner { PhaseNum = 4, GroupName = "Network" },
        };
        var collector = new FindingCollector();

        new PhaseRunner(scanners).Run(Ctx(cts.Token), collector);

        Assert.All(scanners, s => Assert.False(s.Ran));
        Assert.Equal(4, collector.Checks.Count);
        Assert.All(collector.Checks, c =>
        {
            Assert.Equal(CheckOutcome.Skipped, c.Outcome);
            Assert.Contains("cancelled before this phase started", c.Detail);
        });
        Assert.Empty(collector.PhaseTimings);
    }

    [Fact]
    public void Uncancelled_run_of_the_same_scanners_produces_no_cancellation_statuses()
    {
        var scanners = new[]
        {
            new FakeScanner { PhaseNum = 1, GroupName = "Persistence" },
            new FakeScanner { PhaseNum = 2, GroupName = "EventLog" },
            new FakeScanner { PhaseNum = 3, GroupName = "Rootkit" },
            new FakeScanner { PhaseNum = 4, GroupName = "Network" },
        };
        var collector = new FindingCollector();

        new PhaseRunner(scanners).Run(Ctx(), collector);

        Assert.All(scanners, s => Assert.True(s.Ran));
        Assert.All(collector.Checks, c => Assert.Equal(CheckOutcome.Completed, c.Outcome));
        Assert.Equal(4, collector.PhaseTimings.Count);
    }

    [Fact]
    public void Stray_cancellation_exception_is_that_phases_crash_not_a_run_abort()
    {
        // An OperationCanceledException from a scanner-internal timeout (the scan token was
        // NOT cancelled) must not kill the remaining phases or claim operator cancellation.
        var stray = new FakeScanner { PhaseNum = 1, GroupName = "Persistence", ThrowsStrayCancellation = true };
        var next = new FakeScanner { PhaseNum = 2, GroupName = "EventLog" };
        var collector = new FindingCollector();

        new PhaseRunner(new IScanner[] { stray, next }).Run(Ctx(), collector);

        Assert.True(next.Ran);
        var crashed = Assert.Single(collector.Checks, c => c.Phase == 1);
        Assert.Equal(CheckOutcome.Inconclusive, crashed.Outcome);
        Assert.Contains("crashed", crashed.Detail);
        var completed = Assert.Single(collector.Checks, c => c.Phase == 2);
        Assert.Equal(CheckOutcome.Completed, completed.Outcome);
    }

    [Fact]
    public void Scanner_reporting_no_check_status_is_flagged_inconclusive_not_invisible()
    {
        // Spec §6.7 backstop: a phase that ran but reported nothing must not leave its whole
        // area neither cleared nor flagged.
        var silent = new FakeScanner { PhaseNum = 1, GroupName = "Persistence", SkipsCheckStatus = true };
        var collector = new FindingCollector();

        new PhaseRunner(new IScanner[] { silent }).Run(Ctx(), collector);

        var check = Assert.Single(collector.Checks);
        Assert.Equal(CheckOutcome.Inconclusive, check.Outcome);
        Assert.Contains("coverage cannot be confirmed", check.Detail);
    }
}
