// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). ZeroBreach is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.Management;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ZeroBreach.Core.Model;
using ZeroBreach.Core.Scanning;
using ZeroBreach.Core.Signatures;
using ZeroBreach.Core.Util;

namespace ZeroBreach.Scanners;

/// <summary>
/// Phase 2 — Defense Evasion (spec §3): disabled/blinded security tooling, AMSI/ETW tamper
/// indicators, event-log health and clearance, PowerShell logging posture, LOLBin abuse
/// history, and (DEEP) a timestomping heuristic. Strictly read-only; every check ends in
/// exactly one Completed / Inconclusive / Skipped status per scope (spec §6.7).
/// </summary>
public sealed class DefenseEvasionScanner : IScanner
{
    public int Phase => 2;
    public string Name => "Defense Evasion";
    public string Group => "DefenseEvasion";
    public ScanDepth MinDepth => ScanDepth.Quick;

    // MITRE refs used by structural checks (signature-driven hits carry their own).
    private static readonly MitreRef DisableTools =
        new("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion");
    private static readonly MitreRef DisableEventLogging =
        new("T1562.002", "Impair Defenses: Disable Windows Event Logging", "Defense Evasion");
    private static readonly MitreRef IndicatorBlocking =
        new("T1562.006", "Impair Defenses: Indicator Blocking", "Defense Evasion");
    private static readonly MitreRef ClearLogs =
        new("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion");
    private static readonly MitreRef DllHijack =
        new("T1574.001", "Hijack Execution Flow: DLL Search Order Hijacking", "Defense Evasion");
    private static readonly MitreRef TimestompRef =
        new("T1070.006", "Indicator Removal: Timestomp", "Defense Evasion");

    private static readonly HashSet<string> PeExtensions =
        new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".scr", ".com" };

    // Shared state within one run: DEFE-003 establishes whether the Security log is usable
    // and whether 4688 auditing produces events; DEFE-005 consumes both (a disabled log
    // makes the dependent check Inconclusive, never silently clean).
    private bool _securityLogUsable;
    private bool? _has4688;

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        CheckDefenderState(ctx, sink);      // DEFE-001
        CheckAmsiEtwTamper(ctx, sink);      // DEFE-002
        CheckEventLogHealth(ctx, sink);     // DEFE-003
        CheckPowerShellLogging(ctx, sink);  // DEFE-004
        CheckLolbinActivity(ctx, sink);     // DEFE-005 (FULL+)
        CheckTimestomp(ctx, sink);          // DEFE-006 (DEEP)
    }

    // ----------------------------------------------------------------------------------
    // DEFE-001 — Microsoft Defender state: service, real-time protection, tamper
    // protection, and the full exclusion list (each exclusion is itself a finding).
    // ----------------------------------------------------------------------------------
    private void CheckDefenderState(ScanContext ctx, IFindingSink sink)
    {
        const string check = "DEFE-001";
        try
        {
            var gaps = new List<string>();
            bool servicePresent = CheckDefenderService(sink, check, gaps);

            using var opRoot = OpenLmKey(@"SOFTWARE\Microsoft\Windows Defender", gaps);
            using var polRoot = OpenLmKey(@"SOFTWARE\Policies\Microsoft\Windows Defender", gaps);

            if (!servicePresent && opRoot is null)
            {
                sink.Inconclusive(Phase, check,
                    "Microsoft Defender is not present or its state is unreadable (third-party AV?) — " +
                    "Defender posture NOT verified; confirm the replacement AV is healthy by hand");
                return;
            }

            // Real-time protection off — operational state (written by Defender itself).
            if (SafeDword(opRoot, "Real-Time Protection", "DisableRealtimeMonitoring", gaps,
                    "operational Real-Time Protection key") == 1)
            {
                Report(sink, check, Severity.High,
                    "Microsoft Defender real-time monitoring is OFF (operational state). Nothing is " +
                    "scanning file/process activity in real time.",
                    @"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                    "DisableRealtimeMonitoring=1", DisableTools);
            }

            // Real-time protection off — forced by policy value (classic attacker/rogue-admin move).
            if (SafeDword(polRoot, "Real-Time Protection", "DisableRealtimeMonitoring", gaps,
                    "policy Real-Time Protection key") == 1)
            {
                Report(sink, check, Severity.High,
                    "Policy value forces Microsoft Defender real-time monitoring OFF. If this is not a " +
                    "sanctioned GPO, an attacker disabled AV via registry policy. Deleting the value " +
                    "restores the default (GPO-managed machines will re-apply their policy).",
                    @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                    "policy:DisableRealtimeMonitoring=1", DisableTools, FixAction.DeleteRegistryValue,
                    @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection::DisableRealtimeMonitoring");
            }

            // Other protection toggles forced off by policy — POSSIBLE (need operator judgment;
            // may be sanctioned in managed environments).
            foreach (var value in new[]
                     {
                         "DisableBehaviorMonitoring", "DisableOnAccessProtection",
                         "DisableIOAVProtection", "DisableScriptScanning",
                     })
            {
                if (SafeDword(polRoot, "Real-Time Protection", value, gaps, "policy Real-Time Protection key") == 1)
                {
                    Report(sink, check, Severity.Possible,
                        $"Policy value {value}=1 disables a Defender real-time protection component. " +
                        "Verify this is a sanctioned configuration.",
                        @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                        $"policy:{value}=1", DisableTools, FixAction.DeleteRegistryValue,
                        $@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection::{value}");
                }
            }

            foreach (var value in new[] { "DisableAntiSpyware", "DisableAntiVirus" })
            {
                if (SafeDword(polRoot, null, value, gaps, "Defender policy root") == 1)
                {
                    Report(sink, check, Severity.Possible,
                        $"Policy value {value}=1 is set (ignored on current Windows builds but a known " +
                        "tamper/legacy-disable artifact; also legitimately set by some third-party AV installers).",
                        @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", $"policy:{value}=1",
                        DisableTools, FixAction.DeleteRegistryValue,
                        $@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender::{value}");
                }
            }

            CheckTamperProtection(sink, check, opRoot, gaps);

            // Exclusions — the list itself is the finding (INFO), suspicious ones elevated
            // by the signature sets.
            EnumerateExclusions(ctx, sink, check, opRoot, @"HKLM\SOFTWARE\Microsoft\Windows Defender", gaps);
            EnumerateExclusions(ctx, sink, check, polRoot, @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", gaps);

            FinishFlat(sink, check, gaps);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>Tamper-protection state, read from the authoritative source.
    ///
    /// The registry value HKLM\...\Windows Defender\Features\TamperProtection is NOT it: its
    /// encoding varies by build and management state (a tamper-protected machine can report
    /// values other than 5), so treating "!= 5" as disabled reported tamper protection OFF on
    /// healthy machines — a false "your AV is compromised" is exactly the kind of finding that
    /// destroys operator trust in the whole report. Defender's own WMI provider
    /// (MSFT_MpComputerStatus.IsTamperProtected, what Get-MpComputerStatus surfaces) is
    /// authoritative, so that is what decides. When the provider cannot be reached the state is
    /// recorded as a coverage gap — never asserted from the registry value (spec §6.7).</summary>
    private void CheckTamperProtection(IFindingSink sink, string check, RegistryKey? opRoot, List<string> gaps)
    {
        var raw = SafeDword(opRoot, "Features", "TamperProtection", gaps, "Defender Features key");
        var context = raw is int r ? $" (registry TamperProtection={r}, informational only)" : "";

        bool? protectedState;
        try
        {
            protectedState = QueryDefenderTamperState();
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            gaps.Add($"tamper protection state NOT verified: Defender WMI provider unavailable " +
                     $"({ex.GetType().Name}: {ex.Message}); the registry value alone does not determine it");
            return;
        }

        if (protectedState is null)
        {
            gaps.Add("tamper protection state NOT verified: Defender WMI provider returned no status " +
                     "(the registry value alone does not determine it)");
            return;
        }

        if (protectedState == false)
        {
            Report(sink, check, Severity.Possible,
                "Microsoft Defender tamper protection is DISABLED (MSFT_MpComputerStatus." +
                $"IsTamperProtected = false){context}. With it off, malware can turn Defender " +
                "settings off programmatically. Re-enable via Windows Security > Virus & threat " +
                "protection settings.",
                @"HKLM\SOFTWARE\Microsoft\Windows Defender\Features", "IsTamperProtected=false",
                DisableTools);
        }
    }

    /// <summary>Reads MSFT_MpComputerStatus.IsTamperProtected. Returns null when Defender
    /// exposes no status instance; throws when the provider itself is unreachable.</summary>
    private static bool? QueryDefenderTamperState()
    {
        using var searcher = new ManagementObjectSearcher(
            @"root\Microsoft\Windows\Defender",
            "SELECT IsTamperProtected FROM MSFT_MpComputerStatus");
        using var results = searcher.Get();
        foreach (ManagementBaseObject mo in results)
        {
            using (mo)
            {
                if (mo["IsTamperProtected"] is bool b) return b;
            }
        }
        return null;
    }

    private bool CheckDefenderService(IFindingSink sink, string check, List<string> gaps)
    {
        try
        {
            using var sc = new ServiceController("WinDefend");
            var status = sc.Status; // throws when the service does not exist
            if (status != ServiceControllerStatus.Running)
            {
                Report(sink, check, Severity.High,
                    $"Microsoft Defender service (WinDefend) is not running (state: {status}). " +
                    "Unless a third-party AV owns this box, real-time protection is dead.",
                    "service:WinDefend", $"status:{status}", DisableTools);
            }
            if (SafeDword(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\WinDefend", "Start",
                    gaps, "WinDefend service key") == 4)
            {
                Report(sink, check, Severity.High,
                    "Microsoft Defender service (WinDefend) start type is DISABLED — it will not start at boot.",
                    @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend", "Start=4", DisableTools);
            }
            return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            gaps.Add("WinDefend service not present/queryable (third-party AV or Defender removed)");
            return false;
        }
    }

    private void EnumerateExclusions(ScanContext ctx, IFindingSink sink, string check,
        RegistryKey? root, string rootDisplay, List<string> gaps)
    {
        if (root is null) return;

        RegistryKey? excl;
        try { excl = root.OpenSubKey("Exclusions"); }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            gaps.Add($"{rootDisplay}\\Exclusions: access denied (SYSTEM-only on current builds — " +
                     "exclusion list NOT enumerated; re-run as SYSTEM or use Get-MpPreference by hand)");
            return;
        }
        if (excl is null) return;

        using (excl)
        {
            foreach (var kind in new[] { "Paths", "Processes", "Extensions", "IpAddresses", "TemporaryPaths" })
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                RegistryKey? sub;
                try { sub = excl.OpenSubKey(kind); }
                catch (Exception ex) when (IsAccessDenied(ex))
                {
                    gaps.Add($"{rootDisplay}\\Exclusions\\{kind}: access denied");
                    continue;
                }
                if (sub is null) continue;

                using (sub)
                {
                    var suspectSet = kind switch
                    {
                        "Paths" or "TemporaryPaths" => "defenseevasion.exclusion_suspect_paths",
                        "Processes" => "defenseevasion.exclusion_suspect_processes",
                        "Extensions" => "defenseevasion.exclusion_suspect_extensions",
                        _ => null,
                    };

                    foreach (var valueName in sub.GetValueNames())
                    {
                        if (string.IsNullOrEmpty(valueName)) continue;
                        var hit = suspectSet is null
                            ? null
                            : ctx.Signatures.Set(suspectSet).FirstOrDefault(e => e.Matches(valueName));
                        var target = $"{rootDisplay}\\Exclusions\\{kind}";
                        var desc = hit is null
                            ? $"Defender exclusion ({kind}): '{valueName}'. Exclusions are the most common " +
                              "quiet AV-blinding move — verify every one is sanctioned."
                            : $"Defender exclusion ({kind}): '{valueName}' matches suspicious-exclusion " +
                              $"pattern '{hit.Pattern}'{(hit.Note is null ? "" : $" — {hit.Note}")}.";
                        Report(sink, check, hit is null ? Severity.Info : CapSeverity(hit), desc, target,
                            $"exclusion:{kind}:{valueName}", hit?.Mitre ?? DisableTools,
                            FixAction.DeleteRegistryValue, $"{target}::{valueName}");
                    }
                }
            }
        }
    }

    // ----------------------------------------------------------------------------------
    // DEFE-002 — AMSI/ETW tamper indicators: AMSI provider registrations, rogue amsi.dll
    // copies in search-order-hijack locations, EventLog autologger sessions.
    // ----------------------------------------------------------------------------------
    private void CheckAmsiEtwTamper(ScanContext ctx, IFindingSink sink)
    {
        const string check = "DEFE-002";
        try
        {
            var gaps = new List<string>();

            // (a) AMSI provider registrations
            var knownClsids = ctx.Signatures.Set("defenseevasion.amsi_known_provider_clsids");
            using (var prov = OpenLmKey(@"SOFTWARE\Microsoft\AMSI\Providers", gaps, out var provDenied))
            {
                if (prov is null && !provDenied)
                {
                    Report(sink, check, Severity.Possible,
                        "No AMSI providers are registered — script content is not scanned by any " +
                        "antimalware provider. A stock system has at least the Microsoft Defender provider.",
                        @"HKLM\SOFTWARE\Microsoft\AMSI\Providers", "providers:none", DisableTools);
                }
                else if (prov is not null)
                {
                    foreach (var clsid in prov.GetSubKeyNames())
                    {
                        ctx.Cancel.ThrowIfCancellationRequested();
                        var dll = ResolveClsidInprocServer(clsid);
                        bool known = knownClsids.Any(e => e.Matches(clsid));
                        if (dll is null)
                        {
                            Report(sink, check, Severity.Possible,
                                $"AMSI provider {clsid} is registered but does not resolve to an " +
                                "InprocServer32 DLL — dangling or deliberately broken provider registration.",
                                $@"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{clsid}", $"amsi:unresolvable:{clsid}",
                                DisableTools);
                        }
                        else if (!IsInTrustedProgramDir(dll))
                        {
                            Report(sink, check, Severity.High,
                                $"AMSI provider {clsid} loads '{dll}' from outside " +
                                "System32/Program Files/ProgramData\\Microsoft — consistent with an AMSI " +
                                "provider hijack that silently blinds script scanning.",
                                dll, $"amsi:provider:{clsid}", DisableTools, FixAction.Quarantine, dll,
                                ctx.Signatures.IsVendorTrusted(dll));
                        }
                        else if (!known)
                        {
                            Report(sink, check, Severity.Info,
                                $"Non-Microsoft AMSI provider {clsid} -> '{dll}'. Normal for third-party " +
                                "AV; verify the vendor is expected on this machine.",
                                dll, $"amsi:provider:{clsid}", null,
                                vendorTrusted: ctx.Signatures.IsVendorTrusted(dll));
                        }
                    }
                }
            }

            // (b) Security-DLL search-order hijack: fixed candidate locations only (QUICK-safe).
            var hijackNames = ctx.Signatures.Set("defenseevasion.hijack_dll_names");
            foreach (var dir in HijackCandidateDirs(ctx))
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                foreach (var entry in hijackNames.Where(e => e.Kind == MatchKind.Literal))
                {
                    string candidate;
                    bool exists;
                    try
                    {
                        candidate = Path.Combine(dir, entry.Pattern);
                        exists = File.Exists(candidate);
                    }
                    catch { continue; }
                    if (!exists) continue;

                    Report(sink, check, CapSeverity(entry),
                        $"'{entry.Pattern}' present at {candidate}, outside its System32 home. A copy here " +
                        $"is loaded in preference to the real DLL by binaries started from this directory" +
                        $"{(entry.Note is null ? "" : $" — {entry.Note}")}.",
                        candidate, $"hijackdll:{entry.Pattern}", entry.Mitre ?? DllHijack,
                        FixAction.Quarantine, candidate, ctx.Signatures.IsVendorTrusted(candidate));
                }
            }

            // (c) EventLog ETW autologger sessions
            foreach (var session in new[] { "EventLog-Application", "EventLog-System", "EventLog-Security" })
            {
                var target = $@"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\{session}";
                using var k = OpenLmKey($@"SYSTEM\CurrentControlSet\Control\WMI\Autologger\{session}",
                    gaps, out var denied);
                if (k is null)
                {
                    if (!denied)
                        Report(sink, check, Severity.Possible,
                            $"ETW autologger session '{session}' is missing — event-log tracing for this " +
                            "channel will not start at boot. Expected on no supported Windows build.",
                            target, "autologger:missing", IndicatorBlocking);
                }
                else if ((k.GetValue("Start") as int?) == 0)
                {
                    Report(sink, check, Severity.High,
                        $"ETW autologger session '{session}' is disabled (Start=0) — events for this " +
                        "channel are suppressed from boot, a documented ETW-tampering technique. " +
                        "Restore by setting Start=1 and rebooting.",
                        target, "autologger:start0", IndicatorBlocking);
                }
            }

            FinishFlat(sink, check, gaps);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static IEnumerable<string> HijackCandidateDirs(ScanContext ctx)
    {
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        yield return windir;
        yield return Path.Combine(windir, "Temp");
        yield return Path.Combine(windir, @"System32\WindowsPowerShell\v1.0");
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrEmpty(pf)) yield return Path.Combine(pf, @"PowerShell\7");
        foreach (var p in ctx.Profiles)
        {
            // Profile filesystem is walkable regardless of hive state (guide rule 4).
            yield return p.ProfilePath;
            yield return Path.Combine(p.ProfilePath, "Desktop");
            yield return Path.Combine(p.ProfilePath, "Downloads");
            yield return Path.Combine(p.ProfilePath, @"AppData\Local\Temp");
        }
    }

    // ----------------------------------------------------------------------------------
    // DEFE-003 — Event log health: service state, channel enabled/size/retention, recent
    // clear events (Security 1102 / System 104), process-audit posture probe.
    // ----------------------------------------------------------------------------------
    private void CheckEventLogHealth(ScanContext ctx, IFindingSink sink)
    {
        const string check = "DEFE-003";
        bool securityUsable = true;
        try
        {
            var gaps = new List<string>();

            try
            {
                using var sc = new ServiceController("EventLog");
                var status = sc.Status;
                if (status != ServiceControllerStatus.Running)
                {
                    Report(sink, check, Severity.High,
                        $"Windows Event Log service is not running (state: {status}) — no events are " +
                        "being recorded machine-wide.",
                        "service:EventLog", $"status:{status}", DisableEventLogging);
                    securityUsable = false;
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                Report(sink, check, Severity.High,
                    "Windows Event Log service could not be queried — extremely abnormal; " +
                    "machine-wide logging state unknown.",
                    "service:EventLog", "status:unqueryable", DisableEventLogging);
                gaps.Add("EventLog service unqueryable");
            }
            if (SafeDword(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\EventLog", "Start",
                    gaps, "EventLog service key") == 4)
            {
                Report(sink, check, Severity.High,
                    "Windows Event Log service start type is DISABLED — logging will not survive a reboot.",
                    @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog", "Start=4", DisableEventLogging);
            }

            var channels = new (string Log, Severity SevIfDisabled)[]
            {
                ("Security", Severity.High),
                ("System", Severity.High),
                ("Application", Severity.Possible),
                ("Windows PowerShell", Severity.Possible),
                ("Microsoft-Windows-PowerShell/Operational", Severity.Possible),
            };
            foreach (var (log, sevIfDisabled) in channels)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                try
                {
                    using var cfg = new EventLogConfiguration(log);
                    if (!cfg.IsEnabled)
                    {
                        Report(sink, check, sevIfDisabled,
                            $"Event log channel '{log}' is DISABLED — events sent to it are discarded.",
                            $"eventlog:{log}", "channel:disabled", DisableEventLogging);
                        if (log == "Security") securityUsable = false;
                    }
                    else if (log == "Security")
                    {
                        if (cfg.MaximumSizeInBytes < 20 * 1024 * 1024)
                        {
                            Report(sink, check, Severity.Info,
                                $"Security log maximum size is only {cfg.MaximumSizeInBytes / (1024 * 1024)} MB — " +
                                "short retention hampers post-incident reconstruction. Consider >= 100 MB.",
                                "eventlog:Security", "config:maxsize");
                        }
                        if (cfg.LogMode == EventLogMode.Retain)
                        {
                            Report(sink, check, Severity.Info,
                                "Security log is in 'retain' (do-not-overwrite) mode: when full, NEW events " +
                                "are dropped — an attacker can flood the log to blind it going forward.",
                                "eventlog:Security", "config:retain");
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    gaps.Add($"channel '{log}' unreadable ({ex.GetType().Name})");
                    if (log == "Security") securityUsable = false;
                }
            }

            // Recent clear events. Timestamped artifacts — honor the --since window
            // (default lookback 30 days).
            var since = ctx.SinceUtc ?? DateTime.UtcNow.AddDays(-30);
            if (securityUsable &&
                !ScanClearEvents(ctx, sink, check, "Security", 1102, "Microsoft-Windows-Eventlog", since, gaps))
            {
                securityUsable = false;
            }
            ScanClearEvents(ctx, sink, check, "System", 104, "Microsoft-Windows-Eventlog", since, gaps);

            // Audit-posture probe: does process-creation auditing (4688) produce events?
            // Result is reused as the DEFE-005 precondition.
            if (securityUsable)
            {
                bool any = false;
                bool ok = TryQueryEvents("Security", TimeBoundXPath(4688, DateTime.UtcNow.AddDays(-7), null),
                    ctx, (_, _) => { any = true; return false; }, out var err);
                if (ok)
                {
                    _has4688 = any;
                    if (!any)
                    {
                        Report(sink, check, Severity.Info,
                            "No process-creation audit events (Security 4688) in the last 7 days — " +
                            "'Audit Process Creation' appears off, so there is no command-line history " +
                            "for LOLBin detection. Verify with the command below and enable via policy.",
                            "auditpolicy:ProcessCreation", "no4688", DisableEventLogging,
                            FixAction.RunCommand, "auditpol /get /subcategory:\"Process Creation\"");
                    }
                }
                else
                {
                    gaps.Add($"Security 4688 probe failed ({err})");
                }
            }

            _securityLogUsable = securityUsable;
            FinishFlat(sink, check, gaps);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _securityLogUsable = false;
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>Returns false when the log could not be queried (caller records the gap).</summary>
    private bool ScanClearEvents(ScanContext ctx, IFindingSink sink, string check, string log,
        int eventId, string provider, DateTime since, List<string> gaps)
    {
        int hits = 0;
        bool ok = TryQueryEvents(log, TimeBoundXPath(eventId, since, provider), ctx, (rec, xml) =>
        {
            var t = rec.TimeCreated?.ToUniversalTime();
            if (!ctx.WithinTimeWindow(t)) return true;
            var channel = ExtractBetween(xml, "<Channel>", "</Channel>") ?? log;
            Report(sink, check, Severity.High,
                $"Event log CLEARED: '{channel}' (event {eventId} in the {log} log at {t:u}). Log " +
                "clearance is a classic anti-forensics move — confirm whether it was sanctioned maintenance.",
                $"eventlog:{channel}",
                $"logclear:{log}:{rec.RecordId?.ToString() ?? t?.Ticks.ToString() ?? "unknown"}",
                ClearLogs);
            return ++hits < 50;
        }, out var err);
        if (!ok) gaps.Add($"{log} log unreadable for clear-event ({eventId}) query ({err})");
        return ok;
    }

    // ----------------------------------------------------------------------------------
    // DEFE-004 — PowerShell logging posture: ScriptBlockLogging / ModuleLogging /
    // Transcription policy keys; a *recently disabled* policy outranks never-configured.
    // ----------------------------------------------------------------------------------
    private void CheckPowerShellLogging(ScanContext ctx, IFindingSink sink)
    {
        const string check = "DEFE-004";
        try
        {
            var gaps = new List<string>();
            var recentCutoff = ctx.SinceUtc ?? DateTime.UtcNow.AddDays(-30);
            var policies = new (string SubKey, string Value, string Label)[]
            {
                ("ScriptBlockLogging", "EnableScriptBlockLogging", "PowerShell script-block logging"),
                ("ModuleLogging", "EnableModuleLogging", "PowerShell module logging"),
                ("Transcription", "EnableTranscripting", "PowerShell transcription"),
            };

            foreach (var (subKey, value, label) in policies)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var keyPath = $@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\{subKey}";
                RegistryKey? k;
                try { k = Registry.LocalMachine.OpenSubKey(keyPath); }
                catch (Exception ex) when (IsAccessDenied(ex))
                {
                    gaps.Add($"HKLM\\{keyPath}: access denied");
                    continue;
                }

                using (k)
                {
                    var setting = k?.GetValue(value) as int?;
                    if (setting is null)
                    {
                        Report(sink, check, Severity.Info,
                            $"{label} is not configured (no policy value). Hardening gap: without it, " +
                            "attacker PowerShell activity leaves far less evidence.",
                            $@"HKLM\{keyPath}", $"notconfigured:{value}");
                    }
                    else if (setting == 0)
                    {
                        var writeTime = k is null ? null : RegKeyLastWriteUtc(k);
                        bool recent = writeTime is not null && writeTime >= recentCutoff;
                        Report(sink, check, recent ? Severity.High : Severity.Possible,
                            recent
                                ? $"{label} is explicitly DISABLED and the policy key was modified recently " +
                                  $"({writeTime:u}) — a fresh logging teardown is far more interesting than a " +
                                  "never-configured one. Deleting the value restores the default."
                                : $"{label} is explicitly disabled by policy value ({value}=0). Verify this " +
                                  "is sanctioned; deleting the value restores the default.",
                            $@"HKLM\{keyPath}", $"disabled:{value}", DisableEventLogging,
                            FixAction.DeleteRegistryValue, $@"HKLM\{keyPath}::{value}");
                    }
                    // setting == 1: enabled — nothing to report.
                }
            }

            FinishFlat(sink, check, gaps);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ----------------------------------------------------------------------------------
    // DEFE-005 — LOLBin activity from whatever process-history source exists: Security
    // 4688 command lines (preferred) or Prefetch (weaker fallback). Neither -> Inconclusive.
    // ----------------------------------------------------------------------------------
    private void CheckLolbinActivity(ScanContext ctx, IFindingSink sink)
    {
        const string check = "DEFE-005";
        try
        {
            if (ctx.Depth < ScanDepth.Full)
            {
                sink.Skipped(Phase, check,
                    "process-history scan (Security 4688 / Prefetch) runs at FULL depth and above");
                return;
            }

            var reasons = new List<string>();
            bool cmdlineCaptured = SafeDword(Registry.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
                "ProcessCreationIncludeCmdLine_Enabled", null, null) == 1;

            if (!_securityLogUsable) reasons.Add("Security log disabled/unreadable");
            else if (_has4688 != true) reasons.Add("no 4688 process-creation events (auditing off or probe failed)");
            else if (!cmdlineCaptured) reasons.Add("4688 events lack command lines (ProcessCreationIncludeCmdLine_Enabled not set)");

            if (reasons.Count == 0)
            {
                ScanProcessAuditEvents(ctx, sink, check);
                return;
            }
            if (!ScanPrefetch(ctx, sink, check, reasons))
            {
                sink.Inconclusive(Phase, check,
                    "no process-audit source available: " + string.Join("; ", reasons));
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void ScanProcessAuditEvents(ScanContext ctx, IFindingSink sink, string check)
    {
        var patterns = ctx.Signatures.Set("defenseevasion.lolbin_cmdline");
        if (patterns.Count == 0)
        {
            sink.Inconclusive(Phase, check, "signature set defenseevasion.lolbin_cmdline is empty — nothing matched against");
            return;
        }

        var since = ctx.SinceUtc ?? DateTime.UtcNow.AddDays(-14);
        var budget = ctx.CreateBudget(20000, TimeSpan.FromSeconds(45));
        bool ok = TryQueryEvents("Security", TimeBoundXPath(4688, since, null), ctx, (rec, xml) =>
        {
            if (!budget.TryConsume()) return false;
            var cmd = ExtractEventData(xml, "CommandLine");
            if (string.IsNullOrWhiteSpace(cmd)) return true;
            var t = rec.TimeCreated?.ToUniversalTime();
            if (!ctx.WithinTimeWindow(t)) return true;

            foreach (var p in patterns.Where(p => p.Matches(cmd)))
            {
                var exe = ExtractEventData(xml, "NewProcessName") ?? "unknown-process";
                Report(sink, check, CapSeverity(p),
                    $"LOLBin abuse pattern in audited process creation at {t:u}: " +
                    $"\"{Truncate(cmd, 220)}\"{(p.Note is null ? "" : $" — {p.Note}")}. Source: Security 4688.",
                    exe,
                    $"4688:{rec.RecordId?.ToString() ?? t?.Ticks.ToString() ?? "unknown"}:{p.Pattern}",
                    p.Mitre, vendorTrusted: ctx.Signatures.IsVendorTrusted(exe));
            }
            return true;
        }, out var err);

        if (!ok)
        {
            sink.Inconclusive(Phase, check, $"Security 4688 scan failed: {err}");
            return;
        }
        sink.CompleteOrInconclusive(Phase, check, budget, $"Security 4688 command lines since {since:u}");
    }

    /// <summary>Prefetch fallback. Returns false when Prefetch is unavailable too
    /// (caller then reports the combined Inconclusive).</summary>
    private bool ScanPrefetch(ScanContext ctx, IFindingSink sink, string check, List<string> reasons)
    {
        var pfDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        string[] files;
        try
        {
            if (!Directory.Exists(pfDir))
            {
                reasons.Add("Prefetch directory not present (prefetching disabled?)");
                return false;
            }
            files = Directory.GetFiles(pfDir, "*.pf");
        }
        catch (Exception ex)
        {
            reasons.Add($"Prefetch unreadable ({ex.GetType().Name})");
            return false;
        }

        var pfSet = ctx.Signatures.Set("defenseevasion.lolbin_prefetch");
        var budget = ctx.CreateBudget(4096, TimeSpan.FromSeconds(15));
        foreach (var f in files)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            if (!budget.TryConsume()) break;
            var name = Path.GetFileName(f);
            DateTime lastRun;
            try { lastRun = File.GetLastWriteTimeUtc(f); }
            catch { continue; }
            if (!ctx.WithinTimeWindow(lastRun)) continue;

            foreach (var p in pfSet.Where(p => p.Matches(name)))
            {
                Report(sink, check, CapSeverity(p),
                    $"Prefetch shows recent execution: {name} (last run ~{lastRun:u})" +
                    $"{(p.Note is null ? "" : $" — {p.Note}")}. Prefetch proves execution only, with no " +
                    "command line; corroborate before acting.",
                    f, $"prefetch:{name}", p.Mitre);
            }
        }

        sink.CompleteOrInconclusive(Phase, check, budget,
            $"Prefetch fallback ({string.Join("; ", reasons)}) — weaker source than 4688 command-line audit");
        return true;
    }

    // ----------------------------------------------------------------------------------
    // DEFE-006 — Timestomp heuristic (DEEP only): executables in temp/user-writable dirs
    // whose creation time exactly clones a known OS binary's, or whose timestamps have the
    // zero-sub-second signature of timestomping tools. Always POSSIBLE — it is a heuristic.
    // Custom IOC name/hash sets are also applied to the files walked here.
    // ----------------------------------------------------------------------------------
    private void CheckTimestomp(ScanContext ctx, IFindingSink sink)
    {
        const string check = "DEFE-006";
        try
        {
            if (ctx.Depth < ScanDepth.Deep)
            {
                sink.Skipped(Phase, check, "timestomp heuristic runs at DEEP depth only");
                return;
            }

            var refs = LoadReferenceTimes();
            var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            // Machine-wide temp: its own walk, its own budget.
            {
                var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(20));
                var gaps = new List<string>();
                WalkForTimestomp(ctx, sink, check, Path.Combine(windir, "Temp"), refs, budget, gaps, 0);
                FinishWalk(sink, check, budget, @"machine-wide %WINDIR%\Temp", gaps);
            }

            // Per-profile user-writable dirs: fresh budget PER profile (spec §4 — never shared).
            foreach (var profile in ctx.Profiles)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var budget = ctx.CreateBudget(6000, TimeSpan.FromSeconds(30));
                var gaps = new List<string>();
                foreach (var rel in new[] { @"AppData\Local\Temp", "Downloads", "Desktop", @"AppData\Roaming" })
                    WalkForTimestomp(ctx, sink, check, Path.Combine(profile.ProfilePath, rel), refs, budget, gaps, 0);
                FinishWalk(sink, check, budget, $"profile {profile.UserName} user-writable dirs", gaps);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void WalkForTimestomp(ScanContext ctx, IFindingSink sink, string check, string dir,
        IReadOnlyList<(string Name, DateTime CreationUtc)> refs, EnumerationBudget budget,
        List<string> gaps, int depth)
    {
        if (depth > 3 || budget.Exhausted) return;
        string[] files, subdirs;
        try
        {
            if (!Directory.Exists(dir)) return;
            files = Directory.GetFiles(dir);
            subdirs = Directory.GetDirectories(dir);
        }
        catch (Exception ex)
        {
            gaps.Add($"{dir}: {ex.GetType().Name}");
            return;
        }

        var iocNames = ctx.Signatures.Set("custom.filenames");
        var iocHashes = ctx.Signatures.Set("custom.hashes");

        foreach (var f in files)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            if (!budget.TryConsume()) return;
            var fileName = Path.GetFileName(f);

            // Operator-supplied IOC name match (POSSIBLE, no destructive fix — spec §6.6).
            var iocName = iocNames.FirstOrDefault(e => e.Matches(fileName));
            if (iocName is not null)
            {
                Report(sink, check, Severity.Possible,
                    $"File name matches operator-supplied IOC '{iocName.Pattern}'. Name-based IOC matches " +
                    "are low-precision; confirm individually before acting.",
                    f, $"customioc:name:{iocName.Pattern}", iocName.Mitre,
                    vendorTrusted: ctx.Signatures.IsVendorTrusted(f));
            }

            if (!PeExtensions.Contains(Path.GetExtension(f))) continue;

            // Operator-supplied IOC hash match.
            if (iocHashes.Count > 0)
            {
                var sha = FileHasher.Sha256(f, 32 * 1024 * 1024);
                var iocHash = sha is null ? null : iocHashes.FirstOrDefault(e => e.Matches(sha));
                if (iocHash is not null)
                {
                    // hashConfirmed stays false: an operator-supplied IOC file is untrusted
                    // input, not curated confirmation (spec §6.6).
                    Report(sink, check, Severity.Possible,
                        $"SHA-256 matches operator-supplied IOC hash ({sha}). Operator IOCs never auto-arm " +
                        "destructive actions — quarantine suggested for manual review.",
                        f, $"customioc:sha256:{iocHash.Pattern}", iocHash.Mitre, FixAction.Quarantine, f,
                        ctx.Signatures.IsVendorTrusted(f), hashConfirmed: false);
                }
            }

            DateTime created, modified;
            try
            {
                created = File.GetCreationTimeUtc(f);
                modified = File.GetLastWriteTimeUtc(f);
            }
            catch (Exception ex)
            {
                gaps.Add($"{f}: timestamps unreadable ({ex.GetType().Name})");
                continue;
            }
            // Deliberately NOT applying ctx.WithinTimeWindow here: the premise of this
            // check is that the timestamps themselves may be forged.

            var refHit = refs.FirstOrDefault(r => r.CreationUtc.Ticks == created.Ticks);
            if (refHit.Name is not null)
            {
                Report(sink, check, Severity.Possible,
                    $"Creation time is identical to the tick with OS binary {refHit.Name} ({created:O}) — " +
                    "the classic timestomp pattern of cloning $STANDARD_INFORMATION from a system file. " +
                    "HEURISTIC ONLY: verify against the USN journal / $MFT $FILE_NAME times before acting.",
                    f, $"timestomp:refclone:{refHit.Name}", TimestompRef, FixAction.Quarantine, f,
                    ctx.Signatures.IsVendorTrusted(f));
            }
            else if (created.Ticks % TimeSpan.TicksPerSecond == 0 &&
                     modified.Ticks % TimeSpan.TicksPerSecond == 0)
            {
                Report(sink, check, Severity.Possible,
                    $"Both creation and last-write times carry exactly zero sub-second precision " +
                    $"(created {created:u}, modified {modified:u}) — a common artifact of timestomping " +
                    "tools that set whole-second values. HEURISTIC ONLY (archive extraction and some " +
                    "installers also produce this); corroborate before acting.",
                    f, "timestomp:zerosub", TimestompRef,
                    vendorTrusted: ctx.Signatures.IsVendorTrusted(f));
            }
        }

        foreach (var sub in subdirs)
        {
            if (budget.Exhausted) return;
            WalkForTimestomp(ctx, sink, check, sub, refs, budget, gaps, depth + 1);
        }
    }

    private static IReadOnlyList<(string Name, DateTime CreationUtc)> LoadReferenceTimes()
    {
        var sys32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
        var refs = new List<(string, DateTime)>();
        foreach (var name in new[] { "kernel32.dll", "ntdll.dll", "user32.dll", "cmd.exe" })
        {
            try
            {
                var p = Path.Combine(sys32, name);
                if (File.Exists(p)) refs.Add((name, File.GetCreationTimeUtc(p)));
            }
            catch
            {
                // reference binary unreadable — heuristic simply has one fewer anchor
            }
        }
        return refs;
    }

    // ----------------------------------------------------------------------------------
    // Shared helpers
    // ----------------------------------------------------------------------------------

    private void Report(IFindingSink sink, string check, Severity severity, string description,
        string target, string discriminator, MitreRef? mitre = null,
        FixAction fix = FixAction.None, string? fixParam = null,
        bool vendorTrusted = false, bool hashConfirmed = false)
    {
        sink.Report(new Finding
        {
            Id = Finding.ComputeId(Group, target, discriminator),
            Severity = severity,
            Description = description,
            Target = target,
            Group = Group,
            Check = check,
            Mitre = mitre,
            FixAction = fix,
            FixParam = fixParam,
            VendorTrusted = vendorTrusted,
            HashConfirmed = hashConfirmed,
        });
    }

    /// <summary>Flat (non-budgeted) check epilogue: partial coverage is never clean.</summary>
    private void FinishFlat(IFindingSink sink, string check, List<string> gaps)
    {
        if (gaps.Count > 0)
            sink.Inconclusive(Phase, check, "partial coverage: " + string.Join("; ", gaps));
        else
            sink.Completed(Phase, check);
    }

    /// <summary>Budgeted-walk epilogue: budget exhaustion or unreadable sub-scopes both
    /// demote the walk to Inconclusive.</summary>
    private void FinishWalk(IFindingSink sink, string check, EnumerationBudget budget,
        string scope, List<string> gaps)
    {
        if (budget.Exhausted)
            sink.Inconclusive(Phase, check, $"walk of {scope} cut short: {budget.ExhaustedReason}");
        else if (gaps.Count > 0)
            sink.Inconclusive(Phase, check,
                $"walk of {scope} partially unreadable: {string.Join("; ", gaps.Take(5))}" +
                (gaps.Count > 5 ? $" (+{gaps.Count - 5} more)" : ""));
        else
            sink.Completed(Phase, check, scope);
    }

    /// <summary>An indicator flagged NeedsCorroboration can never alone justify above
    /// POSSIBLE (guide rule 5).</summary>
    private static Severity CapSeverity(IndicatorEntry entry) =>
        entry.NeedsCorroboration && entry.Severity > Severity.Possible
            ? Severity.Possible
            : entry.Severity;

    private static bool IsAccessDenied(Exception ex) =>
        ex is System.Security.SecurityException or UnauthorizedAccessException or IOException;

    private static RegistryKey? OpenLmKey(string path, List<string> gaps) =>
        OpenLmKey(path, gaps, out _);

    /// <summary>Opens an HKLM subkey read-only. Returns null both when the key is absent
    /// (denied=false — often a legitimate state) and when access is denied (denied=true,
    /// recorded as a coverage gap so the check ends Inconclusive, never clean).</summary>
    private static RegistryKey? OpenLmKey(string path, List<string> gaps, out bool denied)
    {
        denied = false;
        try
        {
            return Registry.LocalMachine.OpenSubKey(path);
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            denied = true;
            gaps.Add($"HKLM\\{path}: access denied");
            return null;
        }
    }

    /// <summary>Reads a DWORD value; access-denied surfaces as a coverage gap, never as
    /// "value not set".</summary>
    private static int? SafeDword(RegistryKey? root, string? subPath, string valueName,
        List<string>? gaps, string? gapLabel)
    {
        if (root is null) return null;
        try
        {
            if (subPath is null) return root.GetValue(valueName) as int?;
            using var k = root.OpenSubKey(subPath);
            return k?.GetValue(valueName) as int?;
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            gaps?.Add($"{gapLabel ?? subPath ?? valueName}: access denied");
            return null;
        }
    }

    private static string? ResolveClsidInprocServer(string clsid)
    {
        foreach (var view in new[] { @"SOFTWARE\Classes\CLSID\", @"SOFTWARE\Classes\WOW6432Node\CLSID\" })
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(view + clsid + @"\InprocServer32");
                if (k?.GetValue(null) is string raw && !string.IsNullOrWhiteSpace(raw))
                    return Environment.ExpandEnvironmentVariables(raw.Trim().Trim('"'));
            }
            catch
            {
                // fall through to the other registry view
            }
        }
        return null;
    }

    /// <summary>Known-good roots for security-provider DLLs (structural constants, not
    /// indicators — guide rule 10).</summary>
    private static bool IsInTrustedProgramDir(string path)
    {
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var roots = new[]
        {
            Path.Combine(windir, "System32"),
            Path.Combine(windir, "SysWOW64"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft"),
        };
        return roots.Where(r => !string.IsNullOrEmpty(r))
            .Any(r => path.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Runs an event-log query newest-first, calling <paramref name="visit"/> until
    /// it returns false. Returns false (with an error) when the log could not be queried —
    /// the caller must report that scope Inconclusive.</summary>
    private static bool TryQueryEvents(string log, string xpath, ScanContext ctx,
        Func<EventRecord, string, bool> visit, out string? error)
    {
        error = null;
        try
        {
            var query = new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            for (var rec = reader.ReadEvent(); rec is not null; rec = reader.ReadEvent())
            {
                using (rec)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    string xml;
                    try { xml = rec.ToXml(); }
                    catch { continue; }
                    if (!visit(rec, xml)) break;
                }
            }
            return true;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private static string TimeBoundXPath(int eventId, DateTime sinceUtc, string? provider)
    {
        long ms = Math.Max(0, (long)(DateTime.UtcNow - sinceUtc).TotalMilliseconds);
        var providerClause = provider is null ? "" : $"Provider[@Name='{provider}'] and ";
        return $"*[System[{providerClause}(EventID={eventId}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]";
    }

    private static string? ExtractEventData(string xml, string dataName)
    {
        var open = $"<Data Name=\"{dataName}\">";
        var start = xml.IndexOf(open, StringComparison.OrdinalIgnoreCase);
        if (start < 0) return null;
        start += open.Length;
        var end = xml.IndexOf("</Data>", start, StringComparison.OrdinalIgnoreCase);
        if (end < 0) return null;
        return System.Net.WebUtility.HtmlDecode(xml[start..end]);
    }

    private static string? ExtractBetween(string xml, string open, string close)
    {
        var start = xml.IndexOf(open, StringComparison.OrdinalIgnoreCase);
        if (start < 0) return null;
        start += open.Length;
        var end = xml.IndexOf(close, start, StringComparison.OrdinalIgnoreCase);
        if (end < 0) return null;
        return System.Net.WebUtility.HtmlDecode(xml[start..end]);
    }

    private static string Truncate(string s, int max)
    {
        s = s.Replace('\r', ' ').Replace('\n', ' ');
        return s.Length <= max ? s : s[..max] + "…";
    }

    /// <summary>Registry key last-write time via RegQueryInfoKeyW (read-only API; .NET does
    /// not expose it). Null when unavailable.</summary>
    private static DateTime? RegKeyLastWriteUtc(RegistryKey key)
    {
        try
        {
            return NativeMethods.RegQueryInfoKeyW(key.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                       IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                       IntPtr.Zero, out long ft) == 0
                ? DateTime.FromFileTimeUtc(ft)
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static class NativeMethods
    {
        [DllImport("advapi32.dll", ExactSpelling = true)]
        internal static extern int RegQueryInfoKeyW(SafeRegistryHandle hKey, IntPtr lpClass,
            IntPtr lpcchClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen,
            IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen,
            IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
    }
}
