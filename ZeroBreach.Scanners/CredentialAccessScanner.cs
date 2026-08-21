// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). ZeroBreach is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Management;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;
using Microsoft.Win32;
using ZeroBreach.Core.Model;
using ZeroBreach.Core.Scanning;
using ZeroBreach.Core.Signatures;
using ZeroBreach.Core.Util;

namespace ZeroBreach.Scanners;

/// <summary>
/// Phase 4 — Credential Access (spec §3). Read-only: inspects LSA/NTLM/WDigest policy,
/// dumping-tool presence (hash / content+signature, never bare filename alone), LSASS
/// access telemetry and dump files, out-of-place registry-hive copies, DPAPI / browser
/// credential-store artifact anomalies, and credential-adjacent task/service command
/// lines. Never opens or parses credential material itself — presence, location and
/// metadata only (hard scope boundary).
/// </summary>
public sealed class CredentialAccessScanner : IScanner
{
    public int Phase => 4;
    public string Name => "Credential Access";
    public string Group => "CredentialAccess";
    public ScanDepth MinDepth => ScanDepth.Full;

    private const string LsaKeyPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string WDigestKeyPath = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
    private const string ServicesKeyPath = @"SYSTEM\CurrentControlSet\Services";
    private const string SysmonChannel = "Microsoft-Windows-Sysmon/Operational";
    private const string DefenderChannel = "Microsoft-Windows-Windows Defender/Operational";

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        Cred001DumpingToolPresence(ctx, sink);
        Cred002LsaProtectionPosture(ctx, sink);
        Cred003WDigestNtlmPolicy(ctx, sink);
        Cred004LsassAccessTelemetry(ctx, sink);
        Cred004LsassDumpFiles(ctx, sink);
        Cred005HiveCopies(ctx, sink);
        Cred006DpapiArtifacts(ctx, sink);
        Cred007CredentialAdjacentCommands(ctx, sink);
    }

    // ---------------------------------------------------------------- CRED-001

    private sealed class DumperSets
    {
        public required IReadOnlyList<IndicatorEntry> KnownBadHashes { get; init; }
        public required IReadOnlyList<IndicatorEntry> CustomHashes { get; init; }
        public required IReadOnlyList<IndicatorEntry> Names { get; init; }
        public required IReadOnlyList<IndicatorEntry> CustomNames { get; init; }
        public required IReadOnlyList<IndicatorEntry> ContentStrings { get; init; }
    }

    /// <summary>CRED-001 — dumping-tool presence: candidate executables from running
    /// processes, service image paths, and user-writable directories. Detection is by
    /// hash / content-with-signature-corroboration; a name match alone is POSSIBLE and
    /// says so (spec §3).</summary>
    private void Cred001DumpingToolPresence(ScanContext ctx, IFindingSink sink)
    {
        const string check = "CRED-001";
        try
        {
            var sets = new DumperSets
            {
                KnownBadHashes = ctx.Signatures.Set("credentialaccess.known_bad_hashes"),
                CustomHashes = ctx.Signatures.Set("custom.hashes"),
                Names = ctx.Signatures.Set("credentialaccess.dumper_names"),
                CustomNames = ctx.Signatures.Set("custom.filenames"),
                ContentStrings = ctx.Signatures.Set("credentialaccess.dumper_content_strings"),
            };
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // --- Running processes (active state — time-window filter does not apply).
            var procBudget = ctx.CreateBudget(600, TimeSpan.FromSeconds(30));
            int unreadableProcs = 0;
            foreach (var proc in Process.GetProcesses())
            {
                using (proc)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (!procBudget.TryConsume()) break;
                    string? path = null;
                    try { path = proc.MainModule?.FileName; }
                    catch { unreadableProcs++; } // protected/PPL/other-bitness process
                    if (path is not null && seen.Add(path))
                        ExamineCandidate(ctx, sink, sets, check, path, userWritableOrigin: false,
                            origin: $"running process (pid {proc.Id})");
                }
            }
            if (procBudget.Exhausted)
                sink.Inconclusive(Phase, check, $"running-process walk cut short: {procBudget.ExhaustedReason}");
            else if (unreadableProcs > 0)
                sink.Inconclusive(Phase, check,
                    $"running processes: {unreadableProcs} process path(s) unreadable (typically protected/system processes) — those binaries were not examined");
            else
                sink.Completed(Phase, check, "running processes");

            // --- Service image paths (config state — no time-window filter).
            var svcBudget = ctx.CreateBudget(2000, TimeSpan.FromSeconds(20));
            foreach (var (_, imagePath, serviceDll) in EnumerateServices(ctx, svcBudget))
            {
                foreach (var raw in new[] { imagePath, serviceDll })
                {
                    var exe = ExtractExecutablePath(raw);
                    if (exe is not null && File.Exists(exe) && seen.Add(exe))
                        ExamineCandidate(ctx, sink, sets, check, exe, userWritableOrigin: false, origin: "service image path");
                }
            }
            sink.CompleteOrInconclusive(Phase, check, svcBudget, "service image paths");

            // --- Per-profile user-writable directories (fresh budget per profile, spec §4).
            var exts = new[] { ".exe", ".dll", ".sys", ".scr", ".com", ".bin" };
            foreach (var p in ctx.Profiles)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var budget = ctx.CreateBudget(1500, TimeSpan.FromSeconds(25));
                var stats = new WalkStats();
                foreach (var root in ProfileWritableRoots(p.ProfilePath))
                foreach (var f in WalkFiles(root, budget, stats, ctx.Cancel))
                {
                    if (!exts.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase)) continue;
                    if (!ctx.WithinTimeWindow(FileStampUtc(f))) continue;
                    if (seen.Add(f))
                        ExamineCandidate(ctx, sink, sets, check, f, userWritableOrigin: true,
                            origin: $"user-writable dir (profile {p.UserName})");
                }
                FinishWalk(sink, check, budget, stats, $"profile {p.UserName}: user-writable dirs");
            }

            // --- System temp.
            {
                var budget = ctx.CreateBudget(1000, TimeSpan.FromSeconds(20));
                var stats = new WalkStats();
                foreach (var f in WalkFiles(SystemTemp, budget, stats, ctx.Cancel))
                {
                    if (!exts.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase)) continue;
                    if (!ctx.WithinTimeWindow(FileStampUtc(f))) continue;
                    if (seen.Add(f))
                        ExamineCandidate(ctx, sink, sets, check, f, userWritableOrigin: true, origin: "system temp");
                }
                FinishWalk(sink, check, budget, stats, "system temp");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void ExamineCandidate(ScanContext ctx, IFindingSink sink, DumperSets sets, string check,
        string path, bool userWritableOrigin, string origin)
    {
        var fileName = Path.GetFileName(path);
        var vendorTrusted = ctx.Signatures.IsVendorTrusted(path);
        var nameHit = sets.Names.FirstOrDefault(e => e.Matches(fileName));
        var customNameHit = sets.CustomNames.FirstOrDefault(e => e.Matches(fileName) || e.Matches(path));

        // Hash check — only worth the I/O when a hash set is actually populated.
        if (sets.KnownBadHashes.Count > 0 || sets.CustomHashes.Count > 0)
        {
            var hash = FileHasher.Sha256(path, maxBytes: 64 * 1024 * 1024);
            if (hash is not null)
            {
                var bad = sets.KnownBadHashes.FirstOrDefault(e => e.Matches(hash));
                if (bad is not null)
                {
                    sink.Report(F(check, Severity.Critical, path, $"cred-001:known-bad-hash:{hash}",
                        $"SHA-256 {hash} matches known-bad credential-dumping tool set ({bad.Note ?? bad.Pattern}). " +
                        $"Surfaced via {origin}. Hash-confirmed known-bad; quarantine preserves the file as evidence " +
                        "(preferred over delete per spec §4.5/§6.4).",
                        FixAction.Quarantine, path, bad.Mitre ?? MitreLsass, hashConfirmed: true, vendorTrusted: vendorTrusted));
                    return;
                }
                var custom = sets.CustomHashes.FirstOrDefault(e => e.Matches(hash));
                if (custom is not null)
                {
                    // hashConfirmed stays false: an operator-supplied IOC file is untrusted
                    // input, not curated confirmation (spec §6.6).
                    sink.Report(F(check, Severity.Possible, path, $"cred-001:custom-ioc-hash:{hash}",
                        $"SHA-256 {hash} matches an operator-supplied custom IOC hash ({custom.Note ?? "custom IOC"}). " +
                        $"Surfaced via {origin}. Custom IOCs are low-precision by policy (spec §6.6) — verify before acting.",
                        FixAction.Quarantine, path, custom.Mitre ?? MitreLsass, hashConfirmed: false, vendorTrusted: vendorTrusted));
                    return;
                }
            }
        }

        // Content matcher — bounded read, only for name-matched files or files found in
        // user-writable locations (a signed vendor binary in Program Files is out of scope).
        var contentScanned = false;
        List<IndicatorEntry> contentHits = new();
        if (userWritableOrigin || nameHit is not null)
        {
            var maxBytes = ctx.Depth >= ScanDepth.Deep ? 16 * 1024 * 1024 : 8 * 1024 * 1024;
            contentScanned = TryContentScan(path, sets.ContentStrings, maxBytes, out contentHits);
        }

        if (contentHits.Count > 0)
        {
            var first = contentHits[0];
            var matched = string.Join("', '", contentHits.Take(4).Select(h => h.Pattern));
            var (sig, sigDetail) = GetAuthenticodeState(path);
            switch (sig)
            {
                case SigState.Absent:
                    // Content match + unsigned binary = two independent signals → HIGH.
                    sink.Report(F(check, Severity.High, path, $"cred-001:content+unsigned:{first.Pattern}",
                        $"Binary contains credential-dumper string(s) '{matched}' and has {sigDetail}. " +
                        $"Surfaced via {origin}. Not hash-confirmed — quarantine (reversible), do not delete.",
                        FixAction.Quarantine, path, first.Mitre ?? MitreLsass, vendorTrusted: vendorTrusted));
                    break;
                case SigState.Present:
                    sink.Report(F(check, Severity.Possible, path, $"cred-001:content-signed:{first.Pattern}",
                        $"Binary contains credential-dumper string(s) '{matched}' but carries an embedded " +
                        $"Authenticode signature ({sigDetail}; chain not verified here). Could be security/research " +
                        $"tooling — operator judgment required. Surfaced via {origin}.",
                        FixAction.None, path, first.Mitre ?? MitreLsass, vendorTrusted: vendorTrusted));
                    break;
                default:
                    sink.Report(F(check, Severity.Possible, path, $"cred-001:content-sig-unknown:{first.Pattern}",
                        $"Binary contains credential-dumper string(s) '{matched}'; its Authenticode signature could " +
                        $"NOT be checked ({sigDetail}) — this is distinct from being unsigned, so the content match " +
                        $"stands uncorroborated. Surfaced via {origin}.",
                        FixAction.None, path, first.Mitre ?? MitreLsass, vendorTrusted: vendorTrusted));
                    break;
            }
            return;
        }

        if (nameHit is not null)
        {
            var contentNote = contentScanned
                ? "a bounded content scan found no dumper strings"
                : "the file content could not be scanned";
            sink.Report(F(check, Severity.Possible, path, $"cred-001:name-only:{nameHit.Pattern}",
                $"File name matches credential-dumping tool pattern '{nameHit.Pattern}' ({nameHit.Note ?? "known tool name"}) — " +
                $"name match only, not corroborated: no hash match and {contentNote}. A file with this name may be " +
                $"benign (renamed/training material){(nameHit.Note?.Contains("DUAL-USE", StringComparison.OrdinalIgnoreCase) == true ? "; this is a dual-use admin tool" : "")}. " +
                $"Surfaced via {origin}.",
                FixAction.None, path, nameHit.Mitre ?? MitreLsass, vendorTrusted: vendorTrusted));
        }

        if (customNameHit is not null)
        {
            sink.Report(F(check, Severity.Possible, path, "cred-001:custom-ioc-filename",
                $"File matches operator-supplied custom IOC filename '{customNameHit.Pattern}'. Custom IOCs are " +
                $"low-precision by policy (spec §6.6) — verify before acting. Surfaced via {origin}.",
                FixAction.None, path, customNameHit.Mitre, vendorTrusted: vendorTrusted));
        }
    }

    // ---------------------------------------------------------------- CRED-002

    /// <summary>CRED-002 — LSA protection posture: RunAsPPL, RestrictedAdmin, Credential
    /// Guard state. Hardening findings, not evidence of compromise; the Lsa key is on the
    /// protected-registry list, so everything here is report-only (fix_action = none).</summary>
    private void Cred002LsaProtectionPosture(ScanContext ctx, IFindingSink sink)
    {
        const string check = "CRED-002";
        const string lsaTarget = @"HKLM\" + LsaKeyPath;
        try
        {
            using (var lsa = Registry.LocalMachine.OpenSubKey(LsaKeyPath))
            {
                if (lsa is null)
                {
                    sink.Inconclusive(Phase, check, $"could not open {lsaTarget}");
                    return;
                }

                var runAsPpl = lsa.GetValue("RunAsPPL") as int?;
                if (runAsPpl is null or 0)
                {
                    sink.Report(F(check, Severity.Possible, lsaTarget, "cred-002:runasppl",
                        $"LSA protection (RunAsPPL) is {(runAsPpl is null ? "not configured in the registry" : "disabled (0)")} — " +
                        "LSASS may not be running as a protected process, making credential dumping from its memory easier. " +
                        "This is a HARDENING GAP, not evidence of compromise" +
                        (runAsPpl is null
                            ? "; note that Windows 11 22H2+ can enable LSA protection by default without setting this " +
                              "value, so verify actual state (Event ID 12 in the LSA log / msinfo32) before acting"
                            : "") +
                        ". Report-only: this key is on the protected-registry list; change it via normal configuration management.",
                        FixAction.None, null, MitreLsass));
                }

                var disableRestrictedAdmin = lsa.GetValue("DisableRestrictedAdmin") as int?;
                if (disableRestrictedAdmin is 0)
                {
                    sink.Report(F(check, Severity.Possible, lsaTarget, "cred-002:disablerestrictedadmin",
                        "DisableRestrictedAdmin = 0: Restricted Admin mode for inbound RDP is enabled, which permits " +
                        "pass-the-hash logons to this host. Legitimate in some environments; attackers also set it. " +
                        "Report-only (protected registry key); review who set it and when.",
                        FixAction.None, null, new MitreRef("T1112", "Modify Registry", "Defense Evasion")));
                }
            }

            // Credential Guard state via WMI Win32_DeviceGuard.
            string? wmiError = null;
            try
            {
                var credGuardRunning = false;
                var queried = false;
                using var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\DeviceGuard",
                    "SELECT SecurityServicesRunning FROM Win32_DeviceGuard");
                foreach (var obj in searcher.Get())
                {
                    queried = true;
                    using (obj)
                    {
                        if (obj["SecurityServicesRunning"] is int[] runningInts)
                            credGuardRunning = runningInts.Contains(1);
                        else if (obj["SecurityServicesRunning"] is uint[] runningUints)
                            credGuardRunning = runningUints.Contains(1u);
                    }
                }
                if (!queried)
                    wmiError = "Win32_DeviceGuard returned no instances";
                else if (!credGuardRunning)
                    sink.Report(F(check, Severity.Info, "Win32_DeviceGuard", "cred-002:credential-guard",
                        "Credential Guard is not running (Win32_DeviceGuard SecurityServicesRunning does not include 1). " +
                        "Hardening gap only — derived domain credentials are not VBS-isolated on this host. Report-only.",
                        FixAction.None, null, MitreLsass));
            }
            catch (Exception ex)
            {
                wmiError = $"{ex.GetType().Name}: {ex.Message}";
            }

            if (wmiError is not null)
                sink.Inconclusive(Phase, check,
                    $"LSA registry posture checked, but Credential Guard state is unknown (Win32_DeviceGuard: {wmiError})");
            else
                sink.Completed(Phase, check, "RunAsPPL, RestrictedAdmin, Credential Guard");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- CRED-003

    /// <summary>CRED-003 — WDigest and NTLM policy. UseLogonCredential=1 forces cleartext
    /// credentials into LSASS memory (HIGH); weak LM/NTLM policy values are POSSIBLE
    /// hardening findings. All report-only.</summary>
    private void Cred003WDigestNtlmPolicy(ScanContext ctx, IFindingSink sink)
    {
        const string check = "CRED-003";
        try
        {
            using (var wdigest = Registry.LocalMachine.OpenSubKey(WDigestKeyPath))
            {
                // Key/value absent = secure default on Win8.1+/2012R2+ — no finding.
                var useLogonCredential = wdigest?.GetValue("UseLogonCredential") as int?;
                if (useLogonCredential is 1)
                {
                    sink.Report(F(check, Severity.High, @"HKLM\" + WDigestKeyPath, "cred-003:uselogoncredential",
                        "WDigest UseLogonCredential = 1: Windows is forced to keep CLEARTEXT credentials in LSASS " +
                        "memory. This has no legitimate modern use and is a classic attacker preparation step for " +
                        "credential dumping (T1112 → enables T1003.001). Report-only: revert via configuration " +
                        "management and investigate who set it.",
                        FixAction.None, null, new MitreRef("T1112", "Modify Registry", "Defense Evasion")));
                }
            }

            using (var lsa = Registry.LocalMachine.OpenSubKey(LsaKeyPath))
            {
                if (lsa is null)
                {
                    sink.Inconclusive(Phase, check, $@"WDigest checked; could not open HKLM\{LsaKeyPath} for NTLM policy");
                    return;
                }

                var lmCompat = lsa.GetValue("LmCompatibilityLevel") as int?;
                if (lmCompat is < 3)
                {
                    sink.Report(F(check, Severity.Possible, @"HKLM\" + LsaKeyPath, "cred-003:lmcompatibilitylevel",
                        $"LmCompatibilityLevel = {lmCompat}: LM/NTLMv1 responses are permitted on the wire, exposing " +
                        "easily-cracked/relayable authentication. Hardening gap (modern default is 3+). Report-only; " +
                        "fix through normal policy management.",
                        FixAction.None, null, new MitreRef("T1003", "OS Credential Dumping", "Credential Access")));
                }

                var noLmHash = lsa.GetValue("NoLMHash") as int?;
                if (noLmHash is 0)
                {
                    sink.Report(F(check, Severity.Possible, @"HKLM\" + LsaKeyPath, "cred-003:nolmhash",
                        "NoLMHash = 0: LM hashes of passwords may be stored at next password change — trivially " +
                        "crackable. Hardening gap (default is 1 on all supported Windows). Report-only.",
                        FixAction.None, null, new MitreRef("T1003.002", "OS Credential Dumping: Security Account Manager", "Credential Access")));
                }
            }

            sink.Completed(Phase, check, "WDigest UseLogonCredential, LmCompatibilityLevel, NoLMHash");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- CRED-004 (telemetry)

    /// <summary>CRED-004 (telemetry half) — LSASS access events: Sysmon EID 10
    /// (ProcessAccess targeting lsass with VM_READ) and Defender ASR LSASS-rule events
    /// (EID 1121/1122). No telemetry source available → Inconclusive, never clean.</summary>
    private void Cred004LsassAccessTelemetry(ScanContext ctx, IFindingSink sink)
    {
        const string check = "CRED-004";
        try
        {
            var sysmonUsable = ChannelUsable(SysmonChannel, out var sysmonWhy);
            var defenderUsable = ChannelUsable(DefenderChannel, out var defenderWhy);
            if (!sysmonUsable && !defenderUsable)
            {
                sink.Inconclusive(Phase, check,
                    $"no LSASS-access telemetry available (Sysmon: {sysmonWhy}; Defender operational: {defenderWhy})");
                return;
            }

            var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(25));
            string? readError = null;

            if (sysmonUsable)
                readError = ScanSysmonLsassAccess(ctx, sink, check, budget);
            if (defenderUsable && readError is null)
                readError = ScanDefenderAsrLsass(ctx, sink, check, budget);

            if (readError is not null)
                sink.Inconclusive(Phase, check, $"telemetry read failed: {readError}");
            else if (budget.Exhausted)
                sink.Inconclusive(Phase, check, $"event walk cut short: {budget.ExhaustedReason}");
            else
                sink.Completed(Phase, check,
                    $"telemetry: Sysmon EID 10 {(sysmonUsable ? "checked" : $"unavailable ({sysmonWhy})")}; " +
                    $"Defender ASR {(defenderUsable ? "checked" : $"unavailable ({defenderWhy})")}");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private string? ScanSysmonLsassAccess(ScanContext ctx, IFindingSink sink, string check, EnumerationBudget budget)
    {
        var benign = ctx.Signatures.Set("credentialaccess.lsass_access_benign_sources");
        var bybSource = new Dictionary<string, (int Count, DateTime? LastUtc, uint Access)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var query = new EventLogQuery(SysmonChannel, PathType.LogName, "*[System[(EventID=10)]]")
            {
                ReverseDirection = true, // newest first, so the --since cutoff can stop the walk
            };
            using var reader = new EventLogReader(query);
            for (EventRecord? rec = reader.ReadEvent(); rec is not null; rec = reader.ReadEvent())
            {
                using (rec)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (!budget.TryConsume()) break;
                    var utc = rec.TimeCreated?.ToUniversalTime();
                    if (ctx.SinceUtc is not null && utc is not null && utc < ctx.SinceUtc) break;

                    string? target = null, source = null, granted = null;
                    try
                    {
                        var xml = XElement.Parse(rec.ToXml());
                        XNamespace ns = xml.Name.Namespace;
                        var data = xml.Element(ns + "EventData")?.Elements(ns + "Data").ToList();
                        if (data is null) continue;
                        string? Get(string name) =>
                            data.FirstOrDefault(d => (string?)d.Attribute("Name") == name)?.Value;
                        target = Get("TargetImage");
                        source = Get("SourceImage");
                        granted = Get("GrantedAccess");
                    }
                    catch { continue; } // malformed record — skip it, budget already charged

                    if (target is null || source is null) continue;
                    if (!target.EndsWith(@"\lsass.exe", StringComparison.OrdinalIgnoreCase)) continue;

                    var access = ParseAccessMask(granted);
                    // PROCESS_VM_READ (0x10) is the signal; QUERY_INFORMATION alone is
                    // routine and would drown the report in noise.
                    if ((access & 0x10) == 0) continue;
                    if (benign.Any(e => e.Matches(source))) continue;

                    bybSource.TryGetValue(source, out var agg);
                    bybSource[source] = (agg.Count + 1, utc ?? agg.LastUtc, access);
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return $"Sysmon channel: {ex.GetType().Name}: {ex.Message}";
        }

        foreach (var (source, agg) in bybSource)
        {
            sink.Report(F(check, Severity.High, source, "cred-004:lsass-access",
                $"Sysmon recorded {agg.Count} ProcessAccess event(s) (EID 10) where this non-allowlisted process " +
                $"requested read access to lsass.exe memory (granted access 0x{agg.Access:X}" +
                $"{(agg.LastUtc is not null ? $", most recent {agg.LastUtc:u}" : "")}). Reading LSASS memory is the " +
                "primary credential-dumping technique. Identify the product; if unexpected, treat as active compromise.",
                FixAction.None, null, MitreLsass, vendorTrusted: ctx.Signatures.IsVendorTrusted(source)));
        }
        return null;
    }

    private string? ScanDefenderAsrLsass(ScanContext ctx, IFindingSink sink, string check, EnumerationBudget budget)
    {
        var asrRules = ctx.Signatures.Set("credentialaccess.defender_asr_lsass_rules");
        if (asrRules.Count == 0) return null;
        var byProcess = new Dictionary<string, (int Count, DateTime? LastUtc)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var query = new EventLogQuery(DefenderChannel, PathType.LogName,
                "*[System[(EventID=1121 or EventID=1122)]]")
            {
                ReverseDirection = true,
            };
            using var reader = new EventLogReader(query);
            for (EventRecord? rec = reader.ReadEvent(); rec is not null; rec = reader.ReadEvent())
            {
                using (rec)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (!budget.TryConsume()) break;
                    var utc = rec.TimeCreated?.ToUniversalTime();
                    if (ctx.SinceUtc is not null && utc is not null && utc < ctx.SinceUtc) break;

                    string xmlText;
                    try { xmlText = rec.ToXml(); }
                    catch { continue; }
                    if (!asrRules.Any(e => e.Matches(xmlText))) continue;

                    var process = "unknown process";
                    try
                    {
                        var xml = XElement.Parse(xmlText);
                        XNamespace ns = xml.Name.Namespace;
                        process = xml.Element(ns + "EventData")?.Elements(ns + "Data")
                            .FirstOrDefault(d => ((string?)d.Attribute("Name"))?.Contains("Process Name", StringComparison.OrdinalIgnoreCase) == true)
                            ?.Value ?? process;
                    }
                    catch { /* keep aggregate under "unknown process" */ }

                    byProcess.TryGetValue(process, out var agg);
                    byProcess[process] = (agg.Count + 1, utc ?? agg.LastUtc);
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return $"Defender channel: {ex.GetType().Name}: {ex.Message}";
        }

        foreach (var (process, agg) in byProcess)
        {
            sink.Report(F(check, Severity.High, process, "cred-004:defender-asr-lsass",
                $"Microsoft Defender ASR rule 'Block credential stealing from LSASS' fired {agg.Count} time(s) for " +
                $"this process (EID 1121 blocked / 1122 audited{(agg.LastUtc is not null ? $", most recent {agg.LastUtc:u}" : "")}). " +
                "Something attempted to read LSASS credentials; even when blocked, the attempt itself needs investigation.",
                FixAction.None, null, MitreLsass, vendorTrusted: ctx.Signatures.IsVendorTrusted(process)));
        }
        return null;
    }

    // ---------------------------------------------------------------- CRED-004 (dump files)

    /// <summary>CRED-004 (disk half) — LSASS dump files in temp locations: minidump header
    /// (MDMP) plus either an lsass* name or an embedded lsass.exe module string. The dump
    /// is EVIDENCE — quarantine preserves it; it is never suggested for deletion.</summary>
    private void Cred004LsassDumpFiles(ScanContext ctx, IFindingSink sink)
    {
        const string check = "CRED-004";
        try
        {
            var namePatterns = ctx.Signatures.Set("credentialaccess.dump_name_patterns");
            var scanBytes = ctx.Depth >= ScanDepth.Deep ? 32 * 1024 * 1024 : 16 * 1024 * 1024;

            void ScanRoot(string root, string scope)
            {
                var budget = ctx.CreateBudget(1500, TimeSpan.FromSeconds(20));
                var stats = new WalkStats();
                foreach (var f in WalkFiles(root, budget, stats, ctx.Cancel))
                {
                    var fileName = Path.GetFileName(f);
                    var ext = Path.GetExtension(f);
                    var nameHit = namePatterns.FirstOrDefault(e => e.Matches(fileName));
                    var isDumpExt = ext.Equals(".dmp", StringComparison.OrdinalIgnoreCase) ||
                                    ext.Equals(".mdmp", StringComparison.OrdinalIgnoreCase);
                    if (nameHit is null && !isDumpExt) continue;
                    if (!ctx.WithinTimeWindow(FileStampUtc(f))) continue;

                    if (!TryReadBytes(f, 4, out var header))
                    {
                        stats.UnreadableFiles++;
                        continue;
                    }
                    var isMinidump = header.Length == 4 &&
                                     header[0] == (byte)'M' && header[1] == (byte)'D' &&
                                     header[2] == (byte)'M' && header[3] == (byte)'P';

                    if (isMinidump && nameHit is not null)
                    {
                        sink.Report(F(check, Severity.Critical, f, "cred-004:lsass-dump:named",
                            $"Minidump file named like an LSASS dump ('{fileName}', MDMP header confirmed) in {scope}. " +
                            "Almost certainly a credential dump of LSASS memory. This file is EVIDENCE — quarantine " +
                            "preserves it in the vault with a restore manifest; do NOT delete it.",
                            FixAction.Quarantine, f, nameHit.Mitre ?? MitreLsass));
                    }
                    else if (isMinidump)
                    {
                        // Generic *.dmp: confirm by embedded module list before flagging —
                        // WER produces legitimate dumps of ordinary apps all the time.
                        if (BoundedWideContains(f, "lsass.exe", scanBytes))
                            sink.Report(F(check, Severity.Critical, f, "cred-004:lsass-dump:content",
                                $"Minidump in {scope} whose embedded module list references lsass.exe " +
                                $"('{fileName}', MDMP header confirmed). Consistent with a renamed LSASS memory dump. " +
                                "This file is EVIDENCE — quarantine preserves it; do NOT delete it.",
                                FixAction.Quarantine, f, MitreLsass));
                    }
                    else if (nameHit is not null)
                    {
                        sink.Report(F(check, Severity.Possible, f, "cred-004:lsass-dump:name-only",
                            $"File named like an LSASS dump ('{fileName}') in {scope}, but it is not a minidump " +
                            "(no MDMP header) — name match only, not corroborated. Review manually.",
                            FixAction.None, null, nameHit.Mitre ?? MitreLsass));
                    }
                }
                FinishWalk(sink, check, budget, stats, $"dump-file scan: {scope}");
            }

            ScanRoot(SystemTemp, "system temp");
            foreach (var p in ctx.Profiles)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                ScanRoot(Path.Combine(p.ProfilePath, @"AppData\Local\Temp"), $"profile {p.UserName} temp");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"dump-file scan crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- CRED-005

    /// <summary>CRED-005 — SAM/SYSTEM/SECURITY hive copies outside %SystemRoot%\System32\config,
    /// detected by 'regf' header magic plus size band (name only prioritizes); ntds.dit
    /// copies by ESE magic; reg-save residue names; shadow-copy-mounted links in temp.</summary>
    private void Cred005HiveCopies(ScanContext ctx, IFindingSink sink)
    {
        const string check = "CRED-005";
        try
        {
            var hiveNames = ctx.Signatures.Set("credentialaccess.hive_copy_names");

            void ScanRoot(string root, string scope, bool topLevelOnly, EnumerationBudget budget, WalkStats stats,
                bool profileRoot = false)
            {
                foreach (var f in WalkFiles(root, budget, stats, ctx.Cancel, recursive: !topLevelOnly))
                {
                    var fileName = Path.GetFileName(f);
                    // A profile root legitimately holds the user's own NTUSER.DAT (+ logs).
                    if (profileRoot && fileName.StartsWith("ntuser", StringComparison.OrdinalIgnoreCase)) continue;
                    // Structural exclusion: the hives' real home.
                    if (f.Contains(@"\System32\config", StringComparison.OrdinalIgnoreCase)) continue;

                    var nameHit = hiveNames.FirstOrDefault(e => e.Matches(fileName));
                    long len;
                    try { len = new FileInfo(f).Length; } catch { stats.UnreadableFiles++; continue; }

                    // Size band for the magic check: real hive copies are ≥ tens of KB;
                    // reading 8 header bytes per candidate is budget-bounded and cheap.
                    var inBand = len is >= 8192 and <= 512L * 1024 * 1024;
                    if (nameHit is null && !inBand) continue;
                    if (!ctx.WithinTimeWindow(FileStampUtc(f))) continue;

                    byte[] header = Array.Empty<byte>();
                    if ((inBand || nameHit is not null) && !TryReadBytes(f, 8, out header))
                    {
                        if (nameHit is not null) stats.UnreadableFiles++;
                        continue;
                    }
                    var isRegf = header.Length >= 4 &&
                                 header[0] == (byte)'r' && header[1] == (byte)'e' &&
                                 header[2] == (byte)'g' && header[3] == (byte)'f';
                    var isEse = header.Length >= 8 &&
                                header[4] == 0xEF && header[5] == 0xCD && header[6] == 0xAB && header[7] == 0x89;

                    if (isRegf && inBand)
                    {
                        sink.Report(F(check, Severity.Critical, f, "cred-005:regf-copy",
                            $"Registry hive file ('regf' header confirmed, {len / 1024} KB) outside " +
                            $@"%SystemRoot%\System32\config, in {scope}" +
                            $"{(nameHit is not null ? $" — name also matches hive-copy pattern '{nameHit.Pattern}'" : " — content-identified regardless of name")}. " +
                            "Saved SAM/SYSTEM/SECURITY copies are the standard offline credential-extraction staging " +
                            "artifact. Quarantine preserves it as evidence.",
                            FixAction.Quarantine, f, nameHit?.Mitre ?? MitreSam));
                    }
                    else if (isEse && nameHit is not null &&
                             fileName.Equals("ntds.dit", StringComparison.OrdinalIgnoreCase) &&
                             !f.Contains(@"\Windows\NTDS", StringComparison.OrdinalIgnoreCase))
                    {
                        sink.Report(F(check, Severity.Critical, f, "cred-005:ntds-copy",
                            $"ntds.dit (ESE database header confirmed, {len / 1024} KB) outside %SystemRoot%\\NTDS, " +
                            $"in {scope}. A copied AD database is a domain-wide credential-theft artifact. " +
                            "Quarantine preserves it as evidence.",
                            FixAction.Quarantine, f, new MitreRef("T1003.003", "OS Credential Dumping: NTDS", "Credential Access")));
                    }
                    else if (nameHit is not null && !isRegf)
                    {
                        sink.Report(F(check, Severity.Possible, f, $"cred-005:name-residue:{nameHit.Pattern}",
                            $"File name matches hive-copy/reg-save residue pattern '{nameHit.Pattern}' in {scope}, " +
                            "but its content is not a registry hive (no 'regf' header) — name match only. " +
                            "Could be unrelated; review manually.",
                            FixAction.None, null, nameHit.Mitre ?? MitreSam));
                    }
                }
            }

            void ScanShadowLinks(string root, EnumerationBudget budget, WalkStats stats)
            {
                if (!Directory.Exists(root)) return;
                IEnumerable<FileSystemInfo> entries;
                // An unenumerable temp dir means the shadow-link check did NOT run there —
                // count it so FinishWalk reports Inconclusive, not clean (spec §6.7).
                try { entries = new DirectoryInfo(root).EnumerateFileSystemInfos(); }
                catch { stats.UnreadableDirs++; return; }
                foreach (var e in entries)
                {
                    if (!budget.TryConsume()) break;
                    string? linkTarget = null;
                    try { linkTarget = e.LinkTarget; } catch { /* unreadable reparse data */ }
                    if (linkTarget is not null &&
                        linkTarget.Contains("HarddiskVolumeShadowCopy", StringComparison.OrdinalIgnoreCase))
                    {
                        sink.Report(F(check, Severity.High, e.FullName, "cred-005:shadow-mount",
                            $"Link in a temp directory resolves into a volume shadow copy ({linkTarget}). Mounting " +
                            "shadow copies from temp is a standard way to copy locked hives/NTDS.dit. Report-only — " +
                            "investigate what created the link before removing anything.",
                            FixAction.None, null, MitreSam));
                    }
                }
            }

            // System temp (recursive) + shadow-link check.
            {
                var budget = ctx.CreateBudget(1000, TimeSpan.FromSeconds(20));
                var stats = new WalkStats();
                ScanShadowLinks(SystemTemp, budget, stats);
                ScanRoot(SystemTemp, "system temp", topLevelOnly: false, budget, stats);
                FinishWalk(sink, check, budget, stats, "system temp");
            }

            // Per-profile roots — fresh budget per profile (spec §4).
            foreach (var p in ctx.Profiles)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var budget = ctx.CreateBudget(1500, TimeSpan.FromSeconds(25));
                var stats = new WalkStats();
                ScanShadowLinks(Path.Combine(p.ProfilePath, @"AppData\Local\Temp"), budget, stats);
                foreach (var root in ProfileWritableRoots(p.ProfilePath))
                    ScanRoot(root, $"profile {p.UserName}", topLevelOnly: false, budget, stats);
                ScanRoot(p.ProfilePath, $"profile {p.UserName} root", topLevelOnly: true, budget, stats, profileRoot: true);
                FinishWalk(sink, check, budget, stats, $"profile {p.UserName}");
            }

            // DEEP only: fixed-drive roots (top level) and ProgramData.
            if (ctx.Depth >= ScanDepth.Deep)
            {
                var budget = ctx.CreateBudget(300, TimeSpan.FromSeconds(15));
                var stats = new WalkStats();
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
                    ScanRoot(drive.RootDirectory.FullName, $"drive root {drive.Name}", topLevelOnly: true, budget, stats);
                FinishWalk(sink, check, budget, stats, "fixed-drive roots");

                var pdBudget = ctx.CreateBudget(1500, TimeSpan.FromSeconds(20));
                var pdStats = new WalkStats();
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                ScanRoot(programData, "ProgramData", topLevelOnly: false, pdBudget, pdStats);
                FinishWalk(sink, check, pdBudget, pdStats, "ProgramData");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- CRED-006

    /// <summary>CRED-006 — DPAPI artifact anomalies, per-profile: masterkey directory
    /// ownership/recent-modification, and browser credential stores copied outside their
    /// normal location. HARD SCOPE BOUNDARY: this check never opens, parses, or decrypts
    /// credential material — presence, location, and metadata only.</summary>
    private void Cred006DpapiArtifacts(ScanContext ctx, IFindingSink sink)
    {
        const string check = "CRED-006";
        var browserFiles = ctx.Signatures.Set("credentialaccess.browser_cred_files");
        // Locations where these file names are legitimately IN PLACE (structural exclusions).
        var inPlaceMarkers = new[] { @"\user data\", @"\mozilla\", @"\opera software\", @"\vivaldi\", @"\packages\" };

        foreach (var p in ctx.Profiles)
        {
            try
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var budget = ctx.CreateBudget(1500, TimeSpan.FromSeconds(20));
                var stats = new WalkStats();
                var aclErrors = 0;

                // Masterkey directories: %APPDATA%\Microsoft\Protect\<SID>.
                var protect = Path.Combine(p.ProfilePath, @"AppData\Roaming\Microsoft\Protect");
                if (Directory.Exists(protect))
                {
                    string[] sidDirs;
                    try { sidDirs = Directory.GetDirectories(protect); }
                    catch { sidDirs = Array.Empty<string>(); stats.UnreadableDirs++; }
                    foreach (var sidDir in sidDirs)
                    {
                        if (!budget.TryConsume()) break;
                        var dirName = Path.GetFileName(sidDir);
                        if (!dirName.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) continue;

                        // Ownership: expected owner is the profile's own SID (or SYSTEM/Administrators).
                        try
                        {
                            var owner = new DirectoryInfo(sidDir).GetAccessControl()
                                .GetOwner(typeof(SecurityIdentifier))?.Value;
                            var expected = owner is null ||
                                           owner.Equals(p.Sid, StringComparison.OrdinalIgnoreCase) ||
                                           owner is "S-1-5-18" or "S-1-5-32-544";
                            if (!expected)
                            {
                                sink.Report(F(check, Severity.Possible, sidDir, $"cred-006:masterkey-owner:{p.Sid}",
                                    $"DPAPI masterkey directory for {p.UserName} is owned by unexpected SID {owner} " +
                                    $"(expected {p.Sid}, SYSTEM, or Administrators). Ownership changes here can " +
                                    "indicate masterkey tampering/theft staging. Metadata-only check — contents were " +
                                    "not read. Report-only.",
                                    FixAction.None, null, MitreDpapi));
                            }
                        }
                        catch { aclErrors++; }

                        // Recent modification — only meaningful when the operator set a time window
                        // (masterkeys legitimately rotate ~every 90 days, so without a window this
                        // signal would flag every machine).
                        if (ctx.SinceUtc is not null)
                        {
                            DateTime mtime;
                            try { mtime = Directory.GetLastWriteTimeUtc(sidDir); } catch { stats.UnreadableDirs++; continue; }
                            if (mtime >= ctx.SinceUtc)
                            {
                                sink.Report(F(check, Severity.Possible, sidDir, $"cred-006:masterkey-mtime:{p.Sid}",
                                    $"DPAPI masterkey directory for {p.UserName} was modified {mtime:u}, inside the " +
                                    "scan's time window. Legitimate rotation also does this — correlate with the " +
                                    "incident timeline. Metadata-only check; contents were not read. Report-only.",
                                    FixAction.None, null, MitreDpapi));
                            }
                        }
                    }
                }

                // Browser credential stores copied outside their normal location.
                var tempRoot = Path.Combine(p.ProfilePath, @"AppData\Local\Temp");
                foreach (var root in ProfileWritableRoots(p.ProfilePath))
                foreach (var f in WalkFiles(root, budget, stats, ctx.Cancel))
                {
                    var fileName = Path.GetFileName(f);
                    var hit = browserFiles.FirstOrDefault(e => e.Matches(fileName));
                    if (hit is null) continue;
                    if (inPlaceMarkers.Any(m => f.Contains(m, StringComparison.OrdinalIgnoreCase))) continue;
                    if (!ctx.WithinTimeWindow(FileStampUtc(f))) continue;

                    var inTemp = f.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase);
                    // A copied Login Data in %TEMP% is HIGH (legitimate software reads it in
                    // place); elsewhere, or for needs-corroboration names, POSSIBLE.
                    var sev = inTemp && !hit.NeedsCorroboration && hit.Severity >= Severity.High
                        ? Severity.High : Severity.Possible;
                    sink.Report(F(check, sev, f, $"cred-006:browser-store:{p.Sid}",
                        $"Browser credential-store file '{fileName}' ({hit.Note ?? "credential store"}) found outside " +
                        $"its normal profile location, in {(inTemp ? "the user's TEMP directory" : $"profile {p.UserName}'s user folders")}. " +
                        "Legitimate software reads these in place — a copy is an exfil-staging pattern. The file was " +
                        "NOT opened or parsed (metadata only). Quarantine preserves the copy as evidence.",
                        inTemp ? FixAction.Quarantine : FixAction.None, inTemp ? f : null, hit.Mitre ?? MitreDpapi));
                }

                if (budget.Exhausted)
                    sink.Inconclusive(Phase, check, $"profile {p.UserName}: walk cut short: {budget.ExhaustedReason}");
                else if (aclErrors > 0 || stats.UnreadableDirs > 0 || stats.UnreadableFiles > 0)
                    sink.Inconclusive(Phase, check,
                        $"profile {p.UserName}: coverage incomplete ({aclErrors} masterkey ACL(s) unreadable, " +
                        $"{stats.UnreadableDirs} dir(s)/{stats.UnreadableFiles} file(s) unreadable)");
                else
                    sink.Completed(Phase, check, $"profile {p.UserName}: masterkey metadata + browser-store locations");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"profile {p.UserName}: check crashed: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    // ---------------------------------------------------------------- CRED-007

    /// <summary>CRED-007 — scheduled tasks and services whose command lines reference
    /// credential-access tooling (reg save hklm\sam, ntdsutil, esentutl-on-hives, vaultcmd,
    /// cmdkey /list, comsvcs minidump, ...). Task/service removal commands are DISPLAY-ONLY
    /// Info findings; only a non-OS payload binary gets a quarantine suggestion.</summary>
    private void Cred007CredentialAdjacentCommands(ScanContext ctx, IFindingSink sink)
    {
        const string check = "CRED-007";
        var patterns = ctx.Signatures.Set("credentialaccess.cred_command_patterns");
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        // --- Scheduled tasks (XML files under System32\Tasks).
        try
        {
            var tasksRoot = Path.Combine(windir, @"System32\Tasks");
            if (!Directory.Exists(tasksRoot))
            {
                sink.Inconclusive(Phase, check, $"scheduled tasks: {tasksRoot} not found/accessible");
            }
            else
            {
                var budget = ctx.CreateBudget(1500, TimeSpan.FromSeconds(30));
                var stats = new WalkStats();
                foreach (var f in WalkFiles(tasksRoot, budget, stats, ctx.Cancel))
                {
                    string commandLine, firstCommand = "";
                    try
                    {
                        var info = new FileInfo(f);
                        if (info.Length > 1024 * 1024) continue; // not a plausible task definition
                        var text = File.ReadAllText(f);
                        var execs = new List<string>();
                        try
                        {
                            var xml = XDocument.Parse(text);
                            foreach (var exec in xml.Descendants().Where(e => e.Name.LocalName == "Exec"))
                            {
                                var cmd = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value ?? "";
                                var args = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments")?.Value ?? "";
                                execs.Add($"{cmd} {args}".Trim());
                            }
                        }
                        catch { execs.Add(text); } // unparsable XML — fall back to raw text
                        if (execs.Count == 0) continue;
                        firstCommand = execs[0];
                        commandLine = string.Join("\n", execs);
                    }
                    catch { stats.UnreadableFiles++; continue; }

                    var hit = patterns.FirstOrDefault(e => e.Matches(commandLine));
                    if (hit is null) continue;

                    var taskName = f.Substring(tasksRoot.Length).Replace('/', '\\');
                    var payload = ExtractExecutablePath(firstCommand.Split(' ')[0] == firstCommand
                        ? firstCommand : firstCommand);
                    var payloadQuarantinable = payload is not null && File.Exists(payload) &&
                                               !payload.StartsWith(windir, StringComparison.OrdinalIgnoreCase);

                    sink.Report(F(check, Severity.High, taskName, $"cred-007:task:{hit.Pattern}",
                        $"Scheduled task action matches credential-access pattern '{hit.Note ?? hit.Pattern}': " +
                        $"\"{Truncate(commandLine, 300)}\". Persisted credential-theft commands indicate deliberate, " +
                        "repeated harvesting." +
                        (payloadQuarantinable
                            ? $" Suggested action quarantines the non-OS payload binary ({payload})."
                            : " The command uses an OS-protected binary, so no file action is offered — remove the task itself (see companion Info finding)."),
                        payloadQuarantinable ? FixAction.Quarantine : FixAction.None,
                        payloadQuarantinable ? payload : null,
                        hit.Mitre,
                        vendorTrusted: ctx.Signatures.IsVendorTrusted(payload)));

                    sink.Report(F(check, Severity.Info, taskName, "cred-007:task-delete-cmd",
                        "Operator command to remove the credential-access scheduled task above. DISPLAY-ONLY: the " +
                        "engine never executes run_command fixes — review the task in Task Scheduler first, then run " +
                        "this by hand if appropriate.",
                        FixAction.RunCommand, $"schtasks.exe /Delete /TN \"{taskName.TrimStart('\\')}\" /F",
                        hit.Mitre));
                }
                FinishWalk(sink, check, budget, stats, "scheduled tasks");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"scheduled tasks: check crashed: {ex.GetType().Name}: {ex.Message}");
        }

        // --- Services (ImagePath / ServiceDll).
        try
        {
            var budget = ctx.CreateBudget(2000, TimeSpan.FromSeconds(20));
            foreach (var (name, imagePath, serviceDll) in EnumerateServices(ctx, budget))
            {
                var candidate = $"{imagePath} {serviceDll}".Trim();
                if (candidate.Length == 0) continue;
                var hit = patterns.FirstOrDefault(e => e.Matches(candidate));
                if (hit is null) continue;

                var target = $@"HKLM\{ServicesKeyPath}\{name}";
                sink.Report(F(check, Severity.High, target, $"cred-007:service:{hit.Pattern}",
                    $"Service '{name}' command line matches credential-access pattern '{hit.Note ?? hit.Pattern}': " +
                    $"\"{Truncate(candidate, 300)}\". A service persisting a credential-theft command indicates " +
                    "deliberate harvesting. Report-only on the registry side — removing a service's ImagePath value " +
                    "outright would strand the service; remove the service deliberately (see companion Info finding).",
                    FixAction.None, null, hit.Mitre));

                sink.Report(F(check, Severity.Info, target, "cred-007:service-delete-cmd",
                    $"Operator commands to stop and remove service '{name}'. DISPLAY-ONLY: the engine never executes " +
                    "run_command fixes — verify the service owner first, then run by hand if appropriate.",
                    FixAction.RunCommand, $"sc.exe stop \"{name}\" && sc.exe delete \"{name}\"", hit.Mitre));
            }
            sink.CompleteOrInconclusive(Phase, check, budget, "services");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"services: check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- shared helpers

    private static MitreRef MitreLsass => new("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access");
    private static MitreRef MitreSam => new("T1003.002", "OS Credential Dumping: Security Account Manager", "Credential Access");
    private static MitreRef MitreDpapi => new("T1555", "Credentials from Password Stores", "Credential Access");

    private static string SystemTemp =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");

    private static IEnumerable<string> ProfileWritableRoots(string profilePath)
    {
        yield return Path.Combine(profilePath, @"AppData\Local\Temp");
        yield return Path.Combine(profilePath, "Downloads");
        yield return Path.Combine(profilePath, "Desktop");
        yield return Path.Combine(profilePath, "Documents");
    }

    private Finding F(string check, Severity severity, string target, string discriminator, string description,
        FixAction fix = FixAction.None, string? fixParam = null, MitreRef? mitre = null,
        bool hashConfirmed = false, bool vendorTrusted = false) => new()
    {
        Id = Finding.ComputeId(Group, target, discriminator),
        Severity = severity,
        Description = description,
        Target = target,
        FixAction = fix,
        FixParam = fixParam,
        Mitre = mitre,
        Group = Group,
        HashConfirmed = hashConfirmed,
        VendorTrusted = vendorTrusted,
        Check = check,
    };

    private sealed class WalkStats
    {
        public int UnreadableDirs;
        public int UnreadableFiles;
    }

    /// <summary>Budget-bounded, cycle-safe file walk. Unreadable directories are counted in
    /// <paramref name="stats"/> so the caller can refuse to report "clean" over partial
    /// coverage (spec §6.7).</summary>
    private static IEnumerable<string> WalkFiles(string root, EnumerationBudget budget, WalkStats stats,
        CancellationToken cancel, bool recursive = true, int maxDepth = 24)
    {
        if (!Directory.Exists(root)) yield break;
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            cancel.ThrowIfCancellationRequested();
            var (dir, depth) = stack.Pop();

            string[] files;
            try { files = Directory.GetFiles(dir); }
            catch { stats.UnreadableDirs++; files = Array.Empty<string>(); }
            foreach (var f in files)
            {
                if (!budget.TryConsume()) yield break;
                yield return f;
            }

            if (!recursive || depth >= maxDepth) continue;
            string[] subs;
            try { subs = Directory.GetDirectories(dir); }
            catch { if (files.Length == 0) stats.UnreadableDirs++; continue; }
            foreach (var s in subs)
            {
                try
                {
                    if ((new DirectoryInfo(s).Attributes & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch { stats.UnreadableDirs++; continue; }
                stack.Push((s, depth + 1));
            }
        }
    }

    private void FinishWalk(IFindingSink sink, string check, EnumerationBudget budget, WalkStats stats, string scope)
    {
        if (budget.Exhausted)
            sink.Inconclusive(Phase, check, $"walk of {scope} cut short: {budget.ExhaustedReason}");
        else if (stats.UnreadableDirs > 0 || stats.UnreadableFiles > 0)
            sink.Inconclusive(Phase, check,
                $"{scope}: coverage incomplete — {stats.UnreadableDirs} director(ies) and {stats.UnreadableFiles} file(s) unreadable");
        else
            sink.Completed(Phase, check, scope);
    }

    /// <summary>Newer of creation/last-write time (UTC) — the time-window filter should
    /// catch both freshly dropped and freshly modified artifacts.</summary>
    private static DateTime? FileStampUtc(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return null;
            return info.LastWriteTimeUtc > info.CreationTimeUtc ? info.LastWriteTimeUtc : info.CreationTimeUtc;
        }
        catch { return null; }
    }

    private static bool TryReadBytes(string path, int count, out byte[] bytes)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buf = new byte[count];
            var read = 0;
            while (read < count)
            {
                var n = fs.Read(buf, read, count - read);
                if (n <= 0) break;
                read += n;
            }
            bytes = read == count ? buf : buf.AsSpan(0, read).ToArray();
            return true;
        }
        catch
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    /// <summary>Bounded content scan: matches indicators against both the raw-byte (Latin-1)
    /// and UTF-16LE views of the first <paramref name="maxBytes"/>. Returns false when the
    /// file could not be read at all (so the caller can say "not scanned", never "clean").</summary>
    private static bool TryContentScan(string path, IReadOnlyList<IndicatorEntry> indicators, int maxBytes,
        out List<IndicatorEntry> hits)
    {
        hits = new List<IndicatorEntry>();
        if (indicators.Count == 0) return true;
        byte[] buf;
        int read;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var len = (int)Math.Min(fs.Length, maxBytes);
            if (len == 0) return true;
            buf = new byte[len];
            read = 0;
            while (read < len)
            {
                var n = fs.Read(buf, read, len - read);
                if (n <= 0) break;
                read += n;
            }
        }
        catch
        {
            return false;
        }

        var narrow = Encoding.Latin1.GetString(buf, 0, read);
        var wide = Encoding.Unicode.GetString(buf, 0, read);
        foreach (var ind in indicators)
            if (ind.Matches(narrow) || ind.Matches(wide) ||
                narrow.Contains(ind.Pattern, StringComparison.OrdinalIgnoreCase) ||
                wide.Contains(ind.Pattern, StringComparison.OrdinalIgnoreCase))
                hits.Add(ind);
        return true;
    }

    /// <summary>True when the UTF-16LE view of the first <paramref name="maxBytes"/> contains
    /// <paramref name="needle"/> (minidump module names are stored UTF-16).</summary>
    private static bool BoundedWideContains(string path, string needle, int maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var len = (int)Math.Min(fs.Length, maxBytes);
            if (len == 0) return false;
            var buf = new byte[len];
            var read = 0;
            while (read < len)
            {
                var n = fs.Read(buf, read, len - read);
                if (n <= 0) break;
                read += n;
            }
            return Encoding.Unicode.GetString(buf, 0, read).Contains(needle, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private enum SigState { Present, Absent, Unknown }

    /// <summary>Authenticode presence check. Distinguishes "no embedded signature" from
    /// "signature could not be checked" (guide rule 15) — only the former corroborates.</summary>
    private static (SigState State, string Detail) GetAuthenticodeState(string path)
    {
        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(path);
            using var cert2 = new X509Certificate2(cert);
            return (SigState.Present, $"signer '{cert2.GetNameInfo(X509NameType.SimpleName, false)}'");
        }
        catch (CryptographicException)
        {
            return (SigState.Absent, "no embedded Authenticode signature (unsigned or invalid)");
        }
        catch (Exception ex)
        {
            return (SigState.Unknown, $"{ex.GetType().Name} while reading the signature");
        }
    }

    /// <summary>True when the event channel exists AND is enabled (guide rule 14: a
    /// disabled/absent channel is "unreadable", never "empty").</summary>
    private static bool ChannelUsable(string channel, out string why)
    {
        try
        {
            var config = new EventLogConfiguration(channel);
            if (!config.IsEnabled)
            {
                why = "channel disabled";
                return false;
            }
            why = "ok";
            return true;
        }
        catch (EventLogNotFoundException)
        {
            why = "channel not present";
            return false;
        }
        catch (Exception ex)
        {
            why = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private static uint ParseAccessMask(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return 0;
        var s = value.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return uint.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : 0;
    }

    /// <summary>Best-effort executable path from a raw service/task command string.</summary>
    private static string? ExtractExecutablePath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim();
        if (s.StartsWith(@"\??\", StringComparison.Ordinal)) s = s[4..];
        s = Environment.ExpandEnvironmentVariables(s);
        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            return end > 1 ? s[1..end] : null;
        }
        var exeIdx = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx >= 0) return s[..(exeIdx + 4)];
        var space = s.IndexOf(' ');
        return space > 0 ? s[..space] : s;
    }

    /// <summary>Enumerates services from the registry: (name, expanded ImagePath,
    /// Parameters\ServiceDll). Read-only; budget-bounded.</summary>
    private static IEnumerable<(string Name, string ImagePath, string ServiceDll)> EnumerateServices(
        ScanContext ctx, EnumerationBudget budget)
    {
        using var services = Registry.LocalMachine.OpenSubKey(ServicesKeyPath);
        if (services is null) yield break;
        foreach (var name in services.GetSubKeyNames())
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            if (!budget.TryConsume()) yield break;
            string imagePath = "", serviceDll = "";
            try
            {
                using var key = services.OpenSubKey(name);
                if (key is null) continue;
                imagePath = key.GetValue("ImagePath") as string ?? "";
                using var parameters = key.OpenSubKey("Parameters");
                serviceDll = parameters?.GetValue("ServiceDll") as string ?? "";
            }
            catch { continue; }
            if (imagePath.Length > 0 || serviceDll.Length > 0)
                yield return (name, imagePath, serviceDll);
        }
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
