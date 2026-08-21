using ZeroBreach.Core.Model;
using ZeroBreach.Core.Scanning;
using ZeroBreach.Core.Signatures;
using ZeroBreach.Core.Triage;
using ZeroBreach.Scanners;
using static ZeroBreach.Tests.TestHelpers;

namespace ZeroBreach.Tests;

/// <summary>
/// Regressions for defects found on the first live Windows run. Each test names the wrong
/// behavior it locks out — these were false positives and false-coverage claims on healthy
/// machines, which is the failure mode this engine's whole design is aimed against.
/// </summary>
public class LiveRunRegressionTests
{
    // ---------------------------------------------------------------- EVTX-004 member identity

    [Theory]
    [InlineData("-", "")]
    [InlineData("--", "")]
    [InlineData("  ", "")]
    [InlineData("Administrator", "Administrator")]
    public void Unresolved_event_field_is_absent_not_a_name(string raw, string expected) =>
        Assert.Equal(expected, EventLogScanner.Clean(raw));

    [Fact]
    public void Member_identity_falls_back_to_the_sid_instead_of_printing_a_dash()
    {
        // Windows logs MemberName="-" with the real identity only in MemberSid. Reporting the
        // dash made the finding unactionable: the operator had no way to tell who was added.
        var name = EventLogScanner.Clean("-");
        var sid = EventLogScanner.Clean("S-1-5-21-1-2-3-1001");

        var identity = EventLogScanner.Identify(name, sid);

        Assert.DoesNotContain("'-'", identity);
        Assert.Contains("S-1-5-21-1-2-3-1001", identity);
    }

    [Fact]
    public void Member_identity_keeps_both_name_and_sid_when_both_are_logged()
    {
        var identity = EventLogScanner.Identify("svc_backup", "S-1-5-21-9-9-9-1105");
        Assert.Contains("svc_backup", identity);
        Assert.Contains("S-1-5-21-9-9-9-1105", identity);
    }

    [Theory]
    [InlineData("S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003")] // NT SERVICE\...
    [InlineData("S-1-5-82-271721585-897601226-2024613209-625570482-296978595")]     // IIS APPPOOL\...
    [InlineData("S-1-5-83-1-1234567890-1234567890-1234567890-1234567890")]          // Hyper-V VM
    [InlineData("S-1-5-90-0-1")]                                                    // DWM
    public void Virtual_service_sids_are_machine_principals(string sid) =>
        Assert.True(EventLogScanner.IsMachinePrincipal(sid, ""));

    [Fact]
    public void A_real_user_sid_is_not_a_machine_principal() =>
        Assert.False(EventLogScanner.IsMachinePrincipal("S-1-5-21-1111111111-2222222222-3333333333-1001", "attacker"));

    [Fact]
    public void A_machine_account_name_is_a_machine_principal_when_no_sid_was_logged() =>
        Assert.True(EventLogScanner.IsMachinePrincipal("", @"WORKSTATION$"));

    [Fact]
    public void A_named_user_without_a_sid_is_not_a_machine_principal() =>
        Assert.False(EventLogScanner.IsMachinePrincipal("", "backdoor"));

    // ---------------------------------------------------------------- PERS-004 service images

    [SkippableFact]
    public void Native_driver_paths_resolve_to_real_files()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "Windows path semantics (drive roots, separators)");
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        // The three native forms the service database stores. Before this resolution existed,
        // every driver failed File.Exists and silently skipped signature and hash inspection.
        var fromSystemRoot = PersistenceScanner.ResolveServiceImage(@"\SystemRoot\System32\drivers\http.sys", windir);
        var fromDevice = PersistenceScanner.ResolveServiceImage(@"\??\C:\Windows\System32\drivers\http.sys", windir);
        var fromRelative = PersistenceScanner.ResolveServiceImage(@"System32\drivers\http.sys", windir);

        Assert.Equal(Path.Combine(windir, @"System32\drivers\http.sys"), fromSystemRoot);
        Assert.Equal(@"C:\Windows\System32\drivers\http.sys", fromDevice);
        Assert.Equal(Path.Combine(windir, @"System32\drivers\http.sys"), fromRelative);
    }

    [SkippableFact]
    public void Unresolvable_service_images_return_null_rather_than_a_guess()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "Windows path semantics");
        // An unexpanded variable must not be guessed at: a wrong guess becomes a false
        // "service binary is missing from disk" finding.
        Assert.Null(PersistenceScanner.ResolveServiceImage(@"%NOT_A_REAL_VAR%\svc.exe",
            Environment.GetFolderPath(Environment.SpecialFolder.Windows)));
    }

    [SkippableTheory]
    [InlineData(@"C:\Windows\System32\drivers\x.sys", true)]
    [InlineData(@"C:\Program Files\App\svc.exe", true)]
    [InlineData(@"C:\Windows\System32\x.dll", true)]
    [InlineData(@"\\fileserver\share\svc.exe", false)]   // unreachable share != deleted file
    [InlineData(@"C:\Windows\System32\svchost", false)]  // no image extension: parse is unsure
    public void Only_local_image_paths_are_asserted_to_exist(string path, bool expected)
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "Windows path semantics");
        Assert.Equal(expected, PersistenceScanner.LooksLikeLocalImage(path));
    }

    // ---------------------------------------------------------------- circular corroboration

    [Fact]
    public void A_finding_a_later_phase_owes_to_escalation_is_marked_as_derived()
    {
        // Phase 1 raises a finding on evil.exe; escalation arms "evil.exe" as a detection-only
        // indicator; phase 2 then "finds" the same artifact. The phase-2 finding is the phase-1
        // finding's echo, and correlation must be able to tell.
        var signatures = new SignatureDb();
        var escalation = new EscalationEngine(signatures);
        var collector = new FindingCollector();

        var seed = MakeFinding(target: @"C:\Users\victim\AppData\Local\Temp\evil.exe",
            group: "Persistence", discriminator: "seed");
        var echo = MakeFinding(target: @"C:\Users\victim\AppData\Local\Temp\evil.exe",
            group: "C2", discriminator: "echo");

        var runner = new PhaseRunner(
            new IScanner[] { new StubScanner(1, "Persistence", seed), new StubScanner(2, "C2", echo) },
            escalation: escalation);
        runner.Run(Context(), collector);

        var seeded = collector.Findings.Single(f => f.Group == "Persistence");
        var echoed = collector.Findings.Single(f => f.Group == "C2");

        Assert.Null(seeded.DerivedFromFindingId);              // the original stands on its own
        Assert.Equal(seeded.Id, echoed.DerivedFromFindingId);  // the echo is attributed to it
    }

    [Fact]
    public void Findings_from_the_phase_that_armed_an_indicator_are_not_marked_as_derived()
    {
        // Guard against over-marking: escalation runs AFTER a phase, so nothing that phase
        // reported can owe its discovery to what it armed.
        var escalation = new EscalationEngine(new SignatureDb());
        var collector = new FindingCollector();

        var a = MakeFinding(target: @"C:\Users\victim\AppData\Local\Temp\evil.exe",
            group: "Persistence", discriminator: "a");
        var b = MakeFinding(target: @"C:\Users\victim\AppData\Local\Temp\evil.exe",
            group: "Persistence", discriminator: "b");

        new PhaseRunner(new IScanner[] { new StubScanner(1, "Persistence", a, b) }, escalation: escalation)
            .Run(Context(), collector);

        Assert.All(collector.Findings, f => Assert.Null(f.DerivedFromFindingId));
    }

    [Fact]
    public void Without_escalation_nothing_is_marked_as_derived()
    {
        var collector = new FindingCollector();
        var f = MakeFinding(target: @"C:\Users\victim\AppData\Local\Temp\evil.exe", group: "C2");

        new PhaseRunner(new IScanner[] { new StubScanner(1, "C2", f) }).Run(Context(), collector);

        Assert.Null(collector.Findings.Single().DerivedFromFindingId);
    }

    // ---------------------------------------------------------------- EVTX-002 benign transients

    [Fact]
    public void Defender_definition_drivers_match_the_benign_transient_set()
    {
        // Defender installs a randomly-named MpKsl* kernel driver with each definition update
        // and removes it afterwards. That is the exact install-run-remove shape EVTX-002 calls
        // a "classic attacker pattern", so a HIGH finding fired on every clean Windows box.
        var db = new SignatureDb();
        db.LoadEmbedded(typeof(EventLogScanner).Assembly);

        var set = db.Set("eventlog.service_install_benign_transient");
        Assert.NotEmpty(set);

        Assert.Contains(set, i => i.Matches("MpKslDrv"));
        Assert.Contains(set, i => i.Matches("MpKsl6d8f9a1c"));
        Assert.Contains(set, i => i.Matches(
            @"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\MpKslDrv.sys"));
    }

    [Fact]
    public void An_ordinary_service_does_not_match_the_benign_transient_set()
    {
        // The allowance must be narrow: a self-removing service is the pattern the check
        // exists for, so anything outside Defender's definition path must still escalate.
        var db = new SignatureDb();
        db.LoadEmbedded(typeof(EventLogScanner).Assembly);
        var set = db.Set("eventlog.service_install_benign_transient");

        Assert.DoesNotContain(set, i => i.Matches("PSEXESVC"));
        Assert.DoesNotContain(set, i => i.Matches(@"C:\Users\victim\AppData\Local\Temp\svc.exe"));
        Assert.DoesNotContain(set, i => i.Matches(@"C:\Windows\System32\drivers\evil.sys"));
    }

    private static ScanContext Context() => new()
    {
        Depth = ScanDepth.Full,
        Signatures = new SignatureDb(),
        Profiles = Array.Empty<Core.Profiles.UserProfile>(),
    };

    private sealed class StubScanner : IScanner
    {
        private readonly Finding[] _findings;
        public StubScanner(int phase, string group, params Finding[] findings)
        {
            Phase = phase;
            Group = group;
            _findings = findings;
        }

        public int Phase { get; }
        public string Name => $"Stub {Phase}";
        public string Group { get; }
        public ScanDepth MinDepth => ScanDepth.Quick;

        public void Run(ScanContext ctx, IFindingSink sink)
        {
            foreach (var f in _findings) sink.Report(f);
            sink.Completed(Phase, $"STUB-{Phase}");
        }
    }
}
