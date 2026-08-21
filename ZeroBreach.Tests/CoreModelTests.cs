using ZeroBreach.Core.Model;
using ZeroBreach.Core.Reporting;
using ZeroBreach.Core.Scanning;
using static ZeroBreach.Tests.TestHelpers;

namespace ZeroBreach.Tests;

public class FindingIdTests
{
    [Fact]
    public void Id_is_deterministic_across_runs()
    {
        var a = Finding.ComputeId("Persistence", @"C:\Users\bob\run.exe", "Run::Updater");
        var b = Finding.ComputeId("Persistence", @"C:\Users\bob\run.exe", "Run::Updater");
        Assert.Equal(a, b);
    }

    [Fact]
    public void Id_is_case_insensitive_like_windows_paths()
    {
        Assert.Equal(
            Finding.ComputeId("Persistence", @"C:\USERS\Bob\Run.EXE", "X"),
            Finding.ComputeId("persistence", @"c:\users\bob\run.exe", "x"));
    }

    [Fact]
    public void Same_filename_different_identity_does_not_collide()
    {
        // The original project's bug: two users' identical artifacts collapsing to one id.
        var alice = Finding.ComputeId("Persistence", @"C:\Users\alice\evil.exe", "S-1-5-21-1::Run");
        var bob = Finding.ComputeId("Persistence", @"C:\Users\bob\evil.exe", "S-1-5-21-2::Run");
        Assert.NotEqual(alice, bob);

        // ...and two different discriminators on one target are two findings.
        Assert.NotEqual(
            Finding.ComputeId("Persistence", @"C:\x\a.exe", "Run::V1"),
            Finding.ComputeId("Persistence", @"C:\x\a.exe", "Run::V2"));
    }
}

public class EnumerationBudgetTests
{
    [Fact]
    public void Item_budget_latches_exhausted()
    {
        var b = new EnumerationBudget(3, TimeSpan.FromMinutes(5));
        Assert.True(b.TryConsume());
        Assert.True(b.TryConsume());
        Assert.True(b.TryConsume());
        Assert.False(b.TryConsume());
        Assert.True(b.Exhausted);
        Assert.Contains("item budget", b.ExhaustedReason);
        Assert.False(b.TryConsume()); // stays exhausted
    }

    [Fact]
    public void Time_budget_exhausts()
    {
        var b = new EnumerationBudget(int.MaxValue, TimeSpan.Zero);
        Thread.Sleep(15);
        Assert.False(b.TryConsume());
        Assert.Contains("time budget", b.ExhaustedReason);
    }

    [Fact]
    public void Exhausted_walk_reports_inconclusive_never_clean()
    {
        var collector = new FindingCollector();
        var b = new EnumerationBudget(1, TimeSpan.FromMinutes(5));
        b.TryConsume();
        b.TryConsume(); // exhausts

        collector.CompleteOrInconclusive(1, "walk-test", b, "profile alice");

        var check = Assert.Single(collector.Checks);
        Assert.Equal(CheckOutcome.Inconclusive, check.Outcome);
        Assert.Contains("cut short", check.Detail);
        Assert.Contains("profile alice", check.Detail);
    }

    [Fact]
    public void Budget_scales_with_depth()
    {
        var ctx = new ScanContext
        {
            Depth = ScanDepth.Deep,
            Signatures = new Core.Signatures.SignatureDb(),
            Profiles = Array.Empty<Core.Profiles.UserProfile>(),
            BudgetScale = 5.0,
        };
        Assert.Equal(500, ctx.CreateBudget(100, TimeSpan.FromSeconds(10)).MaxItems);
    }
}

public class ScanSummaryTests
{
    [Fact]
    public void Verdict_never_reads_clean_while_checks_are_inconclusive()
    {
        // Spec §6.7 — "no findings" plus coverage gaps is NOT a clean bill.
        var checks = new[]
        {
            new CheckStatus(1, "a", CheckOutcome.Completed),
            new CheckStatus(2, "b", CheckOutcome.Inconclusive, "budget"),
            new CheckStatus(3, "c", CheckOutcome.Skipped, "hive not mounted"),
        };
        var s = ScanSummary.Build(Array.Empty<Finding>(), checks, TimeSpan.FromSeconds(1));

        Assert.DoesNotContain("all checks completed", s.Verdict);
        Assert.Contains("NOT", s.Verdict);
        Assert.Equal(1, s.ChecksInconclusive);
        Assert.Equal(1, s.ChecksSkipped);
    }

    [Fact]
    public void Fully_completed_run_with_no_findings_is_clean()
    {
        var s = ScanSummary.Build(Array.Empty<Finding>(),
            new[] { new CheckStatus(1, "a", CheckOutcome.Completed) }, TimeSpan.FromSeconds(1));
        Assert.Contains("all checks completed", s.Verdict);
    }

    [Fact]
    public void Severity_counts_drive_the_verdict_order()
    {
        var findings = new[] { MakeFinding(Severity.Critical), MakeFinding(Severity.Info, discriminator: "z") };
        var s = ScanSummary.Build(findings, Array.Empty<CheckStatus>(), TimeSpan.Zero);
        Assert.StartsWith("COMPROMISE", s.Verdict);
    }

    [Fact]
    public void Info_only_findings_never_read_as_no_findings()
    {
        // "NO FINDINGS" above a findings table with rows in it would be a lie.
        var findings = new[] { MakeFinding(Severity.Info), MakeFinding(Severity.Info, discriminator: "z") };
        var s = ScanSummary.Build(findings, Array.Empty<CheckStatus>(), TimeSpan.Zero);
        Assert.DoesNotContain("NO FINDINGS", s.Verdict);
        Assert.Contains("INFORMATIONAL", s.Verdict);
    }
}

// Baseline coverage lives in BaselineTests.cs (roundtrip, diff, safety warnings).

public class FindingCollectorTests
{
    [Fact]
    public void Same_id_reported_twice_is_one_finding()
    {
        var c = new FindingCollector();
        c.Report(MakeFinding(discriminator: "same"));
        c.Report(MakeFinding(discriminator: "same"));
        Assert.Single(c.Findings);
    }
}
