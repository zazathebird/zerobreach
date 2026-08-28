using Scythe.Core.Model;
using Scythe.Core.Profiles;
using Scythe.Core.Scanning;
using Scythe.Core.Signatures;
using Scythe.Core.Triage;

namespace Scythe.Tests;

/// <summary>Adaptive-scan escalation: findings raised in early phases arm detection-only
/// indicators (custom.* sets, POSSIBLE severity, no fix action — spec §6.6 discipline) that
/// later phases of the SAME run can match, every armed indicator is recorded as a Lead, and
/// FollowUpPlan turns the run's leads into a generated (never auto-run) DEEP follow-up.</summary>
public class EscalationTests
{
    /// <summary>Minimal well-behaved scanner (same pattern as CancellationCoverageTests):
    /// runs an optional body, then reports a Completed CheckStatus — PhaseRunner flags
    /// scanners that report none, and these tests are not about that backstop.</summary>
    private sealed class FakeScanner : IScanner
    {
        public required int PhaseNum { get; init; }
        public required string GroupName { get; init; }
        public Action<ScanContext, IFindingSink>? Body { get; init; }

        public int Phase => PhaseNum;
        public string Name => $"Fake {GroupName}";
        public string Group => GroupName;
        public ScanDepth MinDepth => ScanDepth.Quick;

        public void Run(ScanContext ctx, IFindingSink sink)
        {
            Body?.Invoke(ctx, sink);
            sink.ReportCheck(new CheckStatus(PhaseNum, Name, CheckOutcome.Completed));
        }
    }

    private static ScanContext Ctx(SignatureDb signatures) => new()
    {
        Depth = ScanDepth.Deep,
        Signatures = signatures,
        Profiles = new List<UserProfile>(),
    };

    [Fact]
    public void Phase_1_ip_finding_is_armed_so_a_phase_2_scanner_sees_custom_ips_populated()
    {
        var db = new SignatureDb();
        var escalation = new EscalationEngine(db);
        var finding = TestHelpers.MakeFinding(severity: Severity.High,
            target: "outbound beacon to 203.0.113.55", group: "Network");

        var observedIps = -1;
        var phase1 = new FakeScanner
        {
            PhaseNum = 1, GroupName = "Network",
            Body = (_, sink) => sink.Report(finding),
        };
        var phase2 = new FakeScanner
        {
            PhaseNum = 2, GroupName = "EventLog",
            // Captures what a LATER phase of the same run actually sees in the signature db.
            Body = (ctx, _) => observedIps = ctx.Signatures.Set("custom.ips").Count,
        };

        new PhaseRunner(new IScanner[] { phase1, phase2 }, escalation: escalation)
            .Run(Ctx(db), new FindingCollector());

        Assert.Equal(1, observedIps);
        var lead = Assert.Single(escalation.Leads);
        Assert.Equal("203.0.113.55", lead.Indicator);
        Assert.Equal(IocKind.Ipv4, lead.Kind);
        Assert.Equal(finding.Id, lead.SourceFindingId);
        Assert.Equal(1, lead.SourcePhase);
        Assert.Equal(Severity.High, lead.SourceSeverity);
    }

    [Fact]
    public void Info_findings_never_widen_the_scan()
    {
        var db = new SignatureDb();
        var escalation = new EscalationEngine(db);
        var info = TestHelpers.MakeFinding(severity: Severity.Info,
            target: "listener bound to 203.0.113.99");

        var armed = escalation.ProcessNewFindings(1, new[] { info });

        Assert.Equal(0, armed);
        Assert.Empty(escalation.Leads);
        Assert.Empty(db.Set("custom.ips"));
    }

    [Fact]
    public void Same_finding_seen_across_two_calls_arms_only_once()
    {
        var db = new SignatureDb();
        var escalation = new EscalationEngine(db);
        var finding = TestHelpers.MakeFinding(severity: Severity.Possible,
            target: "C2 host 203.0.113.55");

        // FindingCollector.Findings is the FULL re-sorted list after every phase, so the
        // same finding is presented to the engine again — id tracking must dedupe it.
        Assert.Equal(1, escalation.ProcessNewFindings(1, new[] { finding }));
        Assert.Equal(0, escalation.ProcessNewFindings(2, new[] { finding }));

        Assert.Single(escalation.Leads);
        Assert.Single(db.Set("custom.ips"));
    }

    [Fact]
    public void Indicator_already_in_the_set_is_not_rearmed_and_creates_no_lead()
    {
        var db = new SignatureDb();
        // Case differs on purpose: the presence check is case-insensitive.
        db.Add("custom.filenames", new IndicatorEntry { Pattern = "EVIL.EXE" });
        var escalation = new EscalationEngine(db);
        var finding = TestHelpers.MakeFinding(severity: Severity.High,
            target: @"C:\Users\victim\AppData\evil.exe");

        var armed = escalation.ProcessNewFindings(1, new[] { finding });

        Assert.Equal(0, armed);
        Assert.Empty(escalation.Leads);
        Assert.Single(db.Set("custom.filenames")); // the pre-existing entry, nothing added
    }

    [Fact]
    public void Cap_stops_arming_sets_CapReached_and_discloses_once()
    {
        var db = new SignatureDb();
        var escalation = new EscalationEngine(db, maxArmed: 2);
        var notes = new List<string>();
        escalation.OnEscalation = notes.Add;

        var finding = TestHelpers.MakeFinding(severity: Severity.Critical,
            target: "c2 pool: 198.51.100.10 198.51.100.11 198.51.100.12");

        var armed = escalation.ProcessNewFindings(1, new[] { finding });

        Assert.Equal(2, armed);
        Assert.Equal(2, escalation.Leads.Count);
        Assert.True(escalation.CapReached);
        Assert.Equal(2, db.Set("custom.ips").Count);
        var note = Assert.Single(notes);
        Assert.Contains("cap", note);
        Assert.Contains("NOT be armed", note);

        // A later phase with a fresh lead arms nothing and does not re-disclose the cap.
        var later = TestHelpers.MakeFinding(severity: Severity.High,
            target: "another host 198.51.100.13", discriminator: "e");
        Assert.Equal(0, escalation.ProcessNewFindings(2, new[] { later }));
        Assert.Single(notes);
    }

    [Fact]
    public void Armed_entries_are_possible_severity_detection_only_with_escalation_note()
    {
        var db = new SignatureDb();
        var escalation = new EscalationEngine(db);
        var hash = new string('b', 64);
        // Target and FixParam are BOTH mined (joined text).
        var finding = TestHelpers.MakeFinding(severity: Severity.High,
            target: $"dropped payload sha256 {hash}", fixParam: "203.0.113.9");

        Assert.Equal(2, escalation.ProcessNewFindings(3, new[] { finding }));

        var hashEntry = Assert.Single(db.Set("custom.hashes"));
        Assert.Equal(hash, hashEntry.Pattern);
        Assert.Equal(MatchKind.Sha256, hashEntry.Kind);
        Assert.Equal(Severity.Possible, hashEntry.Severity);
        Assert.Equal($"escalated mid-scan from finding {finding.Id} (phase 3)", hashEntry.Note);

        var ipEntry = Assert.Single(db.Set("custom.ips"));
        Assert.Equal("203.0.113.9", ipEntry.Pattern);
        Assert.Equal(MatchKind.Literal, ipEntry.Kind);
        Assert.Equal(Severity.Possible, ipEntry.Severity);

        // Detection-only means no severity above POSSIBLE ever comes from escalation —
        // the source finding was High, the armed indicators are not.
        Assert.All(escalation.Leads, l => Assert.Equal(Severity.High, l.SourceSeverity));
    }

    [Fact]
    public void FollowUpPlan_of_zero_leads_is_null()
    {
        Assert.Null(FollowUpPlan.Build(Array.Empty<Lead>()));
    }

    [Fact]
    public void FollowUpPlan_write_produces_loadable_ioc_file_profile_and_provenance_json()
    {
        var fid = Finding.ComputeId("Network", "beacon", "d");
        var leads = new List<Lead>
        {
            new(new string('a', 64), IocKind.Sha256, fid, 1, Severity.High),
            new("203.0.113.7", IocKind.Ipv4, fid, 2, Severity.Possible),
            new("evil.example.com", IocKind.Domain, fid, 2, Severity.Possible),
            new("payload.exe", IocKind.Filename, fid, 4, Severity.Critical),
        };
        var plan = FollowUpPlan.Build(leads);
        Assert.NotNull(plan);
        Assert.Equal("DEEP", plan!.Mode);

        var dir = TestHelpers.NewScratchDir();
        try
        {
            var (leadsPath, iocPath, profilePath) = plan.Write(dir, "scan-20260819");

            // The IOC file round-trips through SignatureDb.LoadIocFile into the right sets.
            var db = new SignatureDb();
            db.LoadIocFile(iocPath);
            Assert.Empty(db.LoadErrors);
            Assert.Equal(new string('a', 64), Assert.Single(db.Set("custom.hashes")).Pattern);
            Assert.Equal("203.0.113.7", Assert.Single(db.Set("custom.ips")).Pattern);
            Assert.Equal("evil.example.com", Assert.Single(db.Set("custom.domains")).Pattern);
            Assert.Equal("payload.exe", Assert.Single(db.Set("custom.filenames")).Pattern);

            // The header must say where the indicators came from.
            var iocText = File.ReadAllText(iocPath);
            Assert.StartsWith("#", iocText);
            Assert.Contains("scan-20260819", iocText);

            // The profile loads through the real validator: DEEP, no category narrowing,
            // IocFile resolving (by filename, relative to the profile) to the written list.
            var profile = ScanProfile.Load(profilePath);
            Assert.Equal("DEEP", profile.Mode);
            Assert.Null(profile.Only);
            Assert.Null(profile.Skip);
            Assert.Equal(Path.GetFullPath(iocPath), profile.IocFile);
            Assert.Contains("scan-20260819", profile.Description);

            // Full provenance survives in the leads file.
            var leadsJson = File.ReadAllText(leadsPath);
            Assert.Contains(fid, leadsJson);
            Assert.Contains("source_finding_id", leadsJson);
            Assert.Contains("source_phase", leadsJson);
            Assert.Contains("source_severity", leadsJson);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
