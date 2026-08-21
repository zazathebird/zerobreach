// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). ZeroBreach is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ZeroBreach.Core.Model;
using ZeroBreach.Core.Scanning;
using ZeroBreach.Core.Signatures;
using ZeroBreach.Core.Util;

namespace ZeroBreach.Scanners;

/// <summary>
/// Phase 7 — Rootkit / boot integrity (spec §3 "Rootkit / boot integrity" bullet).
/// Hidden-process discrepancies via dual enumeration, driver signature / BYOVD checks,
/// BCD boot-configuration tampering, Secure Boot posture, MBR bootstrap inspection and
/// kernel code-integrity (HVCI) posture. Strictly read-only; checks needing elevation
/// report Inconclusive ("requires elevation") instead of vanishing (spec §6.7).
/// </summary>
public sealed class RootkitBootScanner : IScanner
{
    public int Phase => 7;
    public string Name => "Rootkit / Boot Integrity";
    public string Group => "RootkitBoot";
    public ScanDepth MinDepth => ScanDepth.Full;

    private const string ChkProc = "ROOT-001 Process enumeration discrepancy";
    private const string ChkDrv = "ROOT-002 Driver inventory & BYOVD";
    private const string ChkBcd = "ROOT-003 Boot configuration (BCD)";
    private const string ChkSb = "ROOT-004 Secure Boot / firmware posture";
    private const string ChkMbr = "ROOT-005 MBR bootstrap inspection";
    private const string ChkHvci = "ROOT-006 Kernel-mode integrity posture";

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        var elevated = IsElevated();

        CheckProcessDiscrepancy(ctx, sink);
        CheckDrivers(ctx, sink);
        CheckBootConfiguration(ctx, sink, elevated);
        CheckSecureBoot(ctx, sink);
        CheckMbrBootstrap(ctx, sink, elevated);
        CheckKernelIntegrityPosture(ctx, sink);
    }

    // ---------------------------------------------------------------- ROOT-001

    /// <summary>Diff two independent process enumerations (Win32 API vs WMI). A PID that one
    /// source sees and the other does not — surviving a second, order-reversed pass to weed
    /// out processes that merely started/exited between calls — indicates process hiding.</summary>
    private void CheckProcessDiscrepancy(ScanContext ctx, IFindingSink sink)
    {
        try
        {
            var api1 = SnapshotProcessesApi();

            Dictionary<int, (string Name, string? Path)> wmi1;
            try { wmi1 = SnapshotProcessesWmi(ctx.Cancel); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, ChkProc,
                    $"WMI Win32_Process query failed ({ex.GetType().Name}: {ex.Message}) — dual enumeration not possible");
                return;
            }

            var apiOnly = api1.Keys.Where(pid => !wmi1.ContainsKey(pid)).ToList();
            var wmiOnly = wmi1.Keys.Where(pid => !api1.ContainsKey(pid)).ToList();

            if (apiOnly.Count == 0 && wmiOnly.Count == 0)
            {
                sink.Completed(Phase, ChkProc,
                    $"API and WMI enumerations agree ({api1.Count} processes)");
                return;
            }

            // Re-check once before flagging anything: short-lived processes are the dominant
            // false positive. Second pass runs in the REVERSED order so a timing skew that
            // produced the first mismatch cannot reproduce the same artifact. If the re-check
            // itself fails, the first-pass discrepancies are UNCONFIRMED — report that,
            // never the raw single-pass diff (it is noise on every busy machine).
            if (ctx.Cancel.WaitHandle.WaitOne(750)) ctx.Cancel.ThrowIfCancellationRequested();
            Dictionary<int, (string Name, string? Path)> wmi2;
            Dictionary<int, string> api2;
            try
            {
                wmi2 = SnapshotProcessesWmi(ctx.Cancel);
                api2 = SnapshotProcessesApi();
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, ChkProc,
                    $"first pass saw {apiOnly.Count + wmiOnly.Count} enumeration discrepancies but the confirmation " +
                    $"re-check failed ({ex.GetType().Name}: {ex.Message}) — discrepancies UNCONFIRMED, not clean");
                return;
            }

            var confirmedApiOnly = apiOnly.Where(pid => api2.ContainsKey(pid) && !wmi2.ContainsKey(pid)).ToList();
            var confirmedWmiOnly = wmiOnly.Where(pid => wmi2.ContainsKey(pid) && !api2.ContainsKey(pid)).ToList();

            foreach (var pid in confirmedWmiOnly)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var (name, imagePath) = wmi2.TryGetValue(pid, out var n) ? n : ("?", null);
                sink.Report(new Finding
                {
                    // Image path (when WMI can see it) is the stable part of the identity;
                    // the PID alone is per-boot and would break baseline diffing.
                    Id = Finding.ComputeId(Group, imagePath ?? $"pid:{pid}", $"hidden-from-api:{name}"),
                    Severity = Severity.High,
                    Description = $"Process PID {pid} ('{name}'{(imagePath is null ? "" : $", image: {imagePath}")}) is " +
                                  "visible to WMI (Win32_Process) but absent " +
                                  "from the Win32 process-enumeration API in two consecutive passes. A process hidden " +
                                  "from the standard API is a classic rootkit symptom (DKOM / API hooking). Investigate " +
                                  "with an independent forensic toolset; do not kill blind — a hidden process is a " +
                                  "forensics finding, not a one-click fix.",
                    Target = $"PID {pid} ({imagePath ?? name})",
                    Group = Group,
                    Check = ChkProc,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1014", "Rootkit", "Defense Evasion"),
                });
            }

            foreach (var pid in confirmedApiOnly)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var name = api2.TryGetValue(pid, out var n) ? n : "?";
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, $"pid:{pid}", $"hidden-from-wmi:{name}"),
                    Severity = Severity.High,
                    Description = $"Process PID {pid} ('{name}') is visible to the Win32 process-enumeration API but " +
                                  "absent from WMI (Win32_Process) in two consecutive passes — the process is being " +
                                  "hidden from the WMI provider, or the provider itself is tampered. Investigate with " +
                                  "an independent forensic toolset; do not kill blind.",
                    Target = $"PID {pid} ({name})",
                    Group = Group,
                    Check = ChkProc,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1014", "Rootkit", "Defense Evasion"),
                });
            }

            sink.Completed(Phase, ChkProc,
                $"double-pass diff of {api2.Count} API vs {wmi2.Count} WMI processes; " +
                $"{confirmedApiOnly.Count + confirmedWmiOnly.Count} confirmed discrepancies " +
                $"({apiOnly.Count + wmiOnly.Count - confirmedApiOnly.Count - confirmedWmiOnly.Count} first-pass mismatches cleared as races)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, ChkProc, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static Dictionary<int, string> SnapshotProcessesApi()
    {
        var map = new Dictionary<int, string>();
        foreach (var p in Process.GetProcesses())
        {
            try { map[p.Id] = p.ProcessName; }
            catch { map[p.Id] = "?"; }
            finally { p.Dispose(); }
        }
        return map;
    }

    /// <summary>WMI process snapshot including the image path, which is the stable half of a
    /// hidden process's identity (the PID is per-boot). ExecutablePath is null for protected
    /// and System processes — that is expected, and callers fall back to the PID.</summary>
    private static Dictionary<int, (string Name, string? Path)> SnapshotProcessesWmi(CancellationToken cancel)
    {
        var map = new Dictionary<int, (string Name, string? Path)>();
        using var searcher = new ManagementObjectSearcher("SELECT ProcessId, Name, ExecutablePath FROM Win32_Process");
        foreach (ManagementBaseObject mo in searcher.Get())
        {
            cancel.ThrowIfCancellationRequested();
            using (mo)
            {
                var pid = mo["ProcessId"];
                if (pid is null) continue;
                map[(int)Convert.ToInt64(pid)] = (mo["Name"] as string ?? "?", mo["ExecutablePath"] as string);
            }
        }
        return map;
    }

    // ---------------------------------------------------------------- ROOT-002

    /// <summary>Driver inventory: Win32_SystemDriver services (plus, at DEEP, loose *.sys
    /// files in System32\drivers), each with SHA-256 and Authenticode state. BYOVD hash
    /// matches, unsigned/invalid-signature running drivers, out-of-tree paths.</summary>
    private void CheckDrivers(ScanContext ctx, IFindingSink sink)
    {
        try
        {
            var drivers = new List<(string Name, string? RawPath, bool Running)>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, PathName, State, Started FROM Win32_SystemDriver");
                foreach (ManagementBaseObject mo in searcher.Get())
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    using (mo)
                    {
                        var name = mo["Name"] as string ?? "?";
                        var running = mo["Started"] as bool? == true ||
                                      string.Equals(mo["State"] as string, "Running", StringComparison.OrdinalIgnoreCase);
                        drivers.Add((name, mo["PathName"] as string, running));
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, ChkDrv,
                    $"Win32_SystemDriver query failed ({ex.GetType().Name}: {ex.Message}) — driver inventory not possible");
                return;
            }

            var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var driversDir = Path.Combine(windir, "System32", "drivers");
            var knownPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int sigUnchecked = 0, hashUnavailable = 0;

            // Registered driver services (one walk, one budget).
            var budget = ctx.CreateBudget(800, TimeSpan.FromSeconds(120));
            foreach (var d in drivers)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) break;

                var path = NormalizeDriverPath(d.RawPath, windir);
                if (path is null) continue; // no binary path registered — nothing to inspect here
                knownPaths.Add(path);

                if (!File.Exists(path))
                {
                    if (d.Running)
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, path, $"backing-file-missing:{d.Name}"),
                            Severity = Severity.Possible,
                            Description = $"Driver service '{d.Name}' is RUNNING but its backing file was not found on " +
                                          "disk. The file may be hidden by a rootkit filesystem filter, or deleted after " +
                                          "load — but path-normalization quirks can also cause this; verify the path by hand.",
                            Target = path,
                            Group = Group,
                            Check = ChkDrv,
                            FixAction = FixAction.None,
                            Mitre = new MitreRef("T1014", "Rootkit", "Defense Evasion"),
                        });
                    continue;
                }

                EvaluateDriverFile(ctx, sink, path, d.Name, d.Running, registered: true,
                    windir, ref sigUnchecked, ref hashUnavailable);
            }

            // DEEP only: sweep loose *.sys files in System32\drivers that no driver service
            // references (a dropped-but-not-yet-registered or orphaned rootkit component).
            var sweepExhausted = false;
            var sweepCount = 0;
            if (ctx.Depth < ScanDepth.Deep)
            {
                // The registered-driver walk above only sees drivers that have a service
                // registration. A dropped .sys that nothing references yet is exactly what the
                // sweep is for, so at FULL the scope is genuinely narrower — say so as its own
                // ledger entry instead of letting "N drivers checked" read as full coverage
                // of the drivers directory (spec §6.7).
                sink.Skipped(Phase, "ROOT-002 unregistered driver-file sweep",
                    $"DEEP-only: loose *.sys files in {driversDir} that no driver service references " +
                    "were NOT examined (run with --mode DEEP to include them)");
            }
            else
            {
                var sweepBudget = ctx.CreateBudget(1500, TimeSpan.FromSeconds(120));
                try
                {
                    foreach (var file in Directory.EnumerateFiles(driversDir, "*.sys"))
                    {
                        ctx.Cancel.ThrowIfCancellationRequested();
                        if (!sweepBudget.TryConsume()) break;
                        if (knownPaths.Contains(file)) continue;
                        if (!ctx.WithinTimeWindow(File.GetLastWriteTimeUtc(file))) continue;
                        sweepCount++;
                        EvaluateDriverFile(ctx, sink, file, Path.GetFileNameWithoutExtension(file),
                            running: false, registered: false, windir, ref sigUnchecked, ref hashUnavailable);
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    sink.Inconclusive(Phase, ChkDrv,
                        $"loose-file sweep of {driversDir} failed: {ex.GetType().Name}: {ex.Message}");
                    return;
                }
                sweepExhausted = sweepBudget.Exhausted;
            }

            // Coverage verdict: any driver whose signature or hash could not be checked means
            // the scope was not fully covered — never fold that into "clean" (spec §6.7).
            var gaps = new List<string>();
            if (budget.Exhausted) gaps.Add($"driver walk cut short: {budget.ExhaustedReason}");
            if (sweepExhausted) gaps.Add("loose-file sweep cut short");
            if (sigUnchecked > 0) gaps.Add($"{sigUnchecked} driver file(s): signature could NOT be checked (verification error, not 'unsigned')");
            if (hashUnavailable > 0) gaps.Add($"{hashUnavailable} driver file(s) unreadable for hashing");

            if (gaps.Count > 0)
                sink.Inconclusive(Phase, ChkDrv, string.Join("; ", gaps));
            else
                sink.Completed(Phase, ChkDrv,
                    $"{budget.Consumed} registered drivers" +
                    (ctx.Depth >= ScanDepth.Deep
                        ? $" + {sweepCount} unregistered .sys files"
                        : " (registered only — the unregistered-file sweep is DEEP-only and is " +
                          "reported separately as not performed)") +
                    " hashed and signature-checked");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, ChkDrv, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void EvaluateDriverFile(ScanContext ctx, IFindingSink sink, string path, string driverName,
        bool running, bool registered, string windir, ref int sigUnchecked, ref int hashUnavailable)
    {
        var fileName = Path.GetFileName(path);
        var runState = running ? "currently LOADED/RUNNING"
            : registered ? "registered as a driver service, not currently running"
            : "present in the drivers directory but not registered as any driver service";

        var hash = FileHasher.Sha256(path);
        if (hash is null) hashUnavailable++;

        var sig = Authenticode.Check(path);
        if (sig.State == Authenticode.SigState.CheckFailed) sigUnchecked++;

        var vendorTrusted = ctx.Signatures.IsVendorTrusted(sig.Signer) || ctx.Signatures.IsVendorTrusted(path);
        var unloadWarning = running
            ? " Do NOT unload a running kernel driver from a scan tool — that risks bugchecking the machine; " +
              "plan removal in a maintenance window after forensic acquisition."
            : "";

        // 1. Known-vulnerable driver hash (BYOVD) — hash-confirmed.
        if (hash is not null)
        {
            var byovd = ctx.Signatures.Set("rootkitboot.vulnerable_drivers").FirstOrDefault(e => e.Matches(hash));
            if (byovd is not null)
            {
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, path, "byovd-hash"),
                    Severity = CapIfNeedsCorroboration(byovd),
                    Description = $"Driver '{driverName}' matches a known-vulnerable driver hash (BYOVD — legitimately " +
                                  $"signed driver with a known exploitable primitive). {byovd.Note ?? ""} " +
                                  $"State: {runState}. SHA-256 {hash}.{unloadWarning}" +
                                  (running ? "" : " The file is not loaded and can be quarantined."),
                    Target = path,
                    Group = Group,
                    Check = ChkDrv,
                    HashConfirmed = true,
                    FixAction = running ? FixAction.None : FixAction.Quarantine,
                    FixParam = running ? null : path,
                    Mitre = byovd.Mitre ?? new MitreRef("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
                    VendorTrusted = vendorTrusted,
                });
            }

            var customHash = ctx.Signatures.Set("custom.hashes").FirstOrDefault(e => e.Matches(hash));
            if (customHash is not null)
            {
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, path, "custom-ioc-hash"),
                    Severity = Severity.Possible,
                    Description = $"Driver file SHA-256 {hash} matches an operator-supplied IOC hash " +
                                  $"({customHash.Note ?? "custom IOC"}). State: {runState}. Operator-supplied IOCs are " +
                                  "low-precision by policy — confirm individually before acting.",
                    Target = path,
                    Group = Group,
                    Check = ChkDrv,
                    FixAction = FixAction.None,
                    Mitre = customHash.Mitre,
                    VendorTrusted = vendorTrusted,
                });
            }
        }

        // 2. Name-only indicators (weak evidence: legit installs of the same product exist).
        var nameHit = ctx.Signatures.Set("rootkitboot.vulnerable_driver_names").FirstOrDefault(e => e.Matches(fileName));
        if (nameHit is not null)
        {
            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, path, "byovd-name"),
                Severity = CapIfNeedsCorroboration(nameHit),
                Description = $"Driver filename '{fileName}' matches a driver family widely abused for BYOVD " +
                              $"(bring-your-own-vulnerable-driver) attacks. {nameHit.Note ?? ""} State: {runState}. " +
                              "Name-only match — verify the file hash against a vulnerable-driver feed (e.g. loldrivers) " +
                              "and whether the associated product is legitimately installed.",
                Target = path,
                Group = Group,
                Check = ChkDrv,
                FixAction = FixAction.None,
                Mitre = nameHit.Mitre ?? new MitreRef("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
                VendorTrusted = vendorTrusted,
            });
        }

        var customName = ctx.Signatures.Set("custom.filenames").FirstOrDefault(e => e.Matches(fileName));
        if (customName is not null)
        {
            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, path, "custom-ioc-filename"),
                Severity = Severity.Possible,
                Description = $"Driver filename '{fileName}' matches an operator-supplied IOC filename " +
                              $"({customName.Note ?? "custom IOC"}). State: {runState}. Confirm individually before acting.",
                Target = path,
                Group = Group,
                Check = ChkDrv,
                FixAction = FixAction.None,
                Mitre = customName.Mitre,
                VendorTrusted = vendorTrusted,
            });
        }

        // 3. Signature state. "Unsigned" is only claimed when BOTH the embedded check and the
        //    security-catalog lookup positively found nothing; a verification failure is
        //    reported as exactly that (guide rule 15) and rolls into the coverage verdict.
        switch (sig.State)
        {
            case Authenticode.SigState.NoSignature:
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, path, "unsigned"),
                    Severity = running ? Severity.High : Severity.Possible,
                    Description = $"Driver '{driverName}' is UNSIGNED — no embedded Authenticode signature and no entry " +
                                  $"in any installed security catalog (confirmed unsigned, not 'could not check'). " +
                                  $"State: {runState}. " +
                                  (running
                                      ? "Loading unsigned kernel code normally requires test-signing mode or an exploit " +
                                        "— strong rootkit indicator; correlate with ROOT-003 boot-configuration findings."
                                      : "An unsigned driver file that is not loaded is suspicious but may be a leftover " +
                                        "from old tooling.") + unloadWarning,
                    Target = path,
                    Group = Group,
                    Check = ChkDrv,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1014", "Rootkit", "Defense Evasion"),
                    VendorTrusted = vendorTrusted,
                });
                break;

            case Authenticode.SigState.Invalid:
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, path, "invalid-signature"),
                    Severity = running ? Severity.High : Severity.Possible,
                    Description = $"Driver '{driverName}' carries an Authenticode signature that does NOT verify " +
                                  $"({sig.Detail}){(sig.Signer is null ? "" : $", signer '{sig.Signer}'")}. " +
                                  $"State: {runState}. A tampered or re-signed driver binary is a rootkit/BYOVD " +
                                  $"indicator.{unloadWarning}",
                    Target = path,
                    Group = Group,
                    Check = ChkDrv,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1553.002", "Subvert Trust Controls: Code Signing", "Defense Evasion"),
                    VendorTrusted = vendorTrusted,
                });
                break;
        }

        // 4. Registered driver whose binary lives outside the Windows directory. (DriverStore
        //    and System32\drivers are both under %WINDIR%, so the whole Windows tree is the
        //    precision cutoff — flagging DriverStore would drown the report in noise.)
        if (registered && !path.StartsWith(windir + "\\", StringComparison.OrdinalIgnoreCase))
        {
            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, path, "out-of-tree"),
                Severity = Severity.Possible,
                Description = $"Driver service '{driverName}' loads its binary from outside the Windows directory. " +
                              $"State: {runState}. Legitimate for some third-party products (AV, virtualization, " +
                              "hardware tools) but also a common rootkit/BYOVD staging location — verify the vendor " +
                              "and signature.",
                Target = path,
                Group = Group,
                Check = ChkDrv,
                FixAction = FixAction.None,
                Mitre = new MitreRef("T1543.003", "Create or Modify System Process: Windows Service", "Persistence"),
                VendorTrusted = vendorTrusted,
            });
        }
    }

    private static Severity CapIfNeedsCorroboration(IndicatorEntry e) =>
        e.NeedsCorroboration && e.Severity > Severity.Possible ? Severity.Possible : e.Severity;

    private static string? NormalizeDriverPath(string? raw, string windir)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var p = raw.Trim().Trim('"');
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(windir, p[@"\SystemRoot\".Length..]);
        else if (p.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(windir, p[@"SystemRoot\".Length..]);
        else if (!p.Contains(':'))
            p = Path.Combine(windir, p.TrimStart('\\')); // bare "system32\drivers\x.sys" form
        try { return Path.GetFullPath(p); }
        catch { return p; }
    }

    // ---------------------------------------------------------------- ROOT-003

    // BCD element codes (structural constants of the BCD registry hive layout).
    private const string ElTestSigning = "16000049";        // allowprereleasesignatures / testsigning
    private const string ElNoIntegrityChecks = "16000048";  // disableintegritychecks / nointegritychecks
    private const string ElBootDebug = "16000010";          // bootdebug
    private const string ElKernelDebug = "260000a0";        // debug (kernel debugger)
    private const string ElRecoveryEnabled = "16000009";    // recoveryenabled
    private const string ElApplicationPath = "12000002";    // application path (winload/bootmgr/...)
    private const string ElDescription = "12000004";        // entry description string

    /// <summary>Reads boot configuration from the BCD registry hive mount (HKLM\BCD00000000)
    /// — no bcdedit parsing. Flags testsigning, nointegritychecks, boot/kernel debug,
    /// recovery disabled, and unexpected boot-application paths.</summary>
    private void CheckBootConfiguration(ScanContext ctx, IFindingSink sink, bool elevated)
    {
        try
        {
            RegistryKey? objects;
            try { objects = Registry.LocalMachine.OpenSubKey(@"BCD00000000\Objects"); }
            catch (System.Security.SecurityException) { objects = null; }
            catch (UnauthorizedAccessException) { objects = null; }

            if (objects is null)
            {
                sink.Inconclusive(Phase, ChkBcd, elevated
                    ? @"BCD hive not readable at HKLM\BCD00000000 (nonstandard store or hive not mounted) — boot configuration NOT verified"
                    : "requires elevation — BCD hive not readable, boot configuration NOT verified");
                return;
            }

            using (objects)
            {
                var expectedApps = ctx.Signatures.Set("rootkitboot.expected_boot_apps");
                int inspected = 0;

                foreach (var guid in objects.GetSubKeyNames())
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    using var elements = objects.OpenSubKey(guid + @"\Elements");
                    if (elements is null) continue;
                    inspected++;

                    var entryName = ReadStringElement(elements, ElDescription) ?? guid;
                    var target = $@"HKLM\BCD00000000\Objects\{guid}";

                    if (ReadBoolElement(elements, ElTestSigning) == true)
                        sink.Report(BcdFinding(target, ElTestSigning, Severity.High,
                            $"Boot entry '{entryName}': TEST SIGNING is enabled (allowprereleasesignatures). This lets " +
                            "the kernel load unsigned/test-signed drivers and is a standard precondition for installing " +
                            "an unsigned rootkit driver. If not an intentional developer machine, remove it BY HAND " +
                            $"(a wrong BCD edit can make the machine unbootable): bcdedit /deletevalue {guid} testsigning",
                            new MitreRef("T1553.006", "Subvert Trust Controls: Code Signing Policy Modification", "Defense Evasion")));

                    if (ReadBoolElement(elements, ElNoIntegrityChecks) == true)
                        sink.Report(BcdFinding(target, ElNoIntegrityChecks, Severity.High,
                            $"Boot entry '{entryName}': driver INTEGRITY CHECKS are DISABLED (nointegritychecks). " +
                            "Kernel code-signing enforcement is off — a precondition for loading an unsigned rootkit " +
                            "driver. Remove BY HAND after confirming it is not an intentional lab setting: " +
                            $"bcdedit /deletevalue {guid} nointegritychecks",
                            new MitreRef("T1553.006", "Subvert Trust Controls: Code Signing Policy Modification", "Defense Evasion")));

                    if (ReadBoolElement(elements, ElBootDebug) == true)
                        sink.Report(BcdFinding(target, ElBootDebug, Severity.Possible,
                            $"Boot entry '{entryName}': boot debugging is enabled (bootdebug). Rare outside driver " +
                            "development; kernel/boot debugging weakens code-integrity protections (PatchGuard). " +
                            $"Review and, if unexpected, remove by hand: bcdedit /deletevalue {guid} bootdebug",
                            new MitreRef("T1553.006", "Subvert Trust Controls: Code Signing Policy Modification", "Defense Evasion")));

                    if (ReadBoolElement(elements, ElKernelDebug) == true)
                        sink.Report(BcdFinding(target, ElKernelDebug, Severity.Possible,
                            $"Boot entry '{entryName}': kernel debugging is enabled (debug). Rare outside driver " +
                            "development; an attached kernel debugger disables PatchGuard. Review and, if unexpected, " +
                            $"remove by hand: bcdedit /deletevalue {guid} debug",
                            new MitreRef("T1553.006", "Subvert Trust Controls: Code Signing Policy Modification", "Defense Evasion")));

                    if (ReadBoolElement(elements, ElRecoveryEnabled) == false)
                        sink.Report(BcdFinding(target, ElRecoveryEnabled, Severity.Possible,
                            $"Boot entry '{entryName}': automatic recovery is DISABLED (recoveryenabled No). Ransomware " +
                            "commonly disables recovery before encryption (also a Phase 5 signal). Review and, if " +
                            $"unexpected, restore by hand: bcdedit /set {guid} recoveryenabled Yes",
                            new MitreRef("T1490", "Inhibit System Recovery", "Impact")));

                    var appPath = ReadStringElement(elements, ElApplicationPath);
                    if (appPath is not null && expectedApps.Count > 0)
                    {
                        var appFile = appPath[(appPath.LastIndexOf('\\') + 1)..];
                        if (appFile.Length > 0 && !expectedApps.Any(e => e.Matches(appFile)))
                            sink.Report(BcdFinding(target, ElApplicationPath, Severity.Possible,
                                $"Boot entry '{entryName}' launches an unexpected boot application: '{appPath}'. " +
                                "Standard Windows entries use winload/winresume/bootmgr/memtest images. OEM recovery " +
                                "tools and multi-boot loaders are legitimate causes — verify the file's origin and " +
                                "signature before acting.",
                                new MitreRef("T1542.003", "Pre-OS Boot: Bootkit", "Persistence")));
                    }
                }

                sink.Completed(Phase, ChkBcd, $"{inspected} BCD objects inspected via registry hive");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, ChkBcd, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private Finding BcdFinding(string target, string elementCode, Severity severity, string description, MitreRef mitre) =>
        new()
        {
            Id = Finding.ComputeId(Group, target, $"bcd-element:{elementCode}"),
            Severity = severity,
            Description = description,
            Target = target,
            Group = Group,
            Check = ChkBcd,
            // Deliberately no scriptable fix: a wrong BCD edit is a non-booting machine. The
            // exact bcdedit command is in the description for the operator to run by hand.
            FixAction = FixAction.None,
            Mitre = mitre,
        };

    private static bool? ReadBoolElement(RegistryKey elements, string code)
    {
        using var k = elements.OpenSubKey(code);
        return k?.GetValue("Element") switch
        {
            byte[] { Length: > 0 } b => b[0] != 0,
            int i => i != 0,
            null => null,
            _ => null,
        };
    }

    private static string? ReadStringElement(RegistryKey elements, string code)
    {
        using var k = elements.OpenSubKey(code);
        return k?.GetValue("Element") switch
        {
            string s => s,
            byte[] b => Encoding.Unicode.GetString(b).TrimEnd('\0'),
            _ => null,
        };
    }

    // ---------------------------------------------------------------- ROOT-004

    /// <summary>Secure Boot / firmware posture from the registry (no cmdlets, no process
    /// execution): PEFirmwareType + SecureBoot\State.</summary>
    private void CheckSecureBoot(ScanContext ctx, IFindingSink sink)
    {
        try
        {
            int? firmwareType;
            using (var ctl = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control"))
                firmwareType = ctl?.GetValue("PEFirmwareType") as int?;

            if (firmwareType == 1)
            {
                // Legacy BIOS — Secure Boot not applicable. Not a failure (INFO), and exactly
                // the machine ROOT-005 exists for.
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, "boot-firmware", "legacy-bios"),
                    Severity = Severity.Info,
                    Description = "Machine boots via legacy BIOS/MBR. Secure Boot is not applicable on this firmware, " +
                                  "so no firmware-level bootkit protection exists; the MBR bootstrap check (ROOT-005, " +
                                  "DEEP depth, elevated) covers the boot path instead.",
                    Target = "boot-firmware",
                    Group = Group,
                    Check = ChkSb,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1542", "Pre-OS Boot", "Defense Evasion"),
                });
                sink.Completed(Phase, ChkSb, "legacy BIOS — Secure Boot not applicable");
                return;
            }

            int? sbState;
            using (var sb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State"))
                sbState = sb?.GetValue("UEFISecureBootEnabled") as int?;

            if (sbState is null)
            {
                sink.Inconclusive(Phase, ChkSb,
                    "Secure Boot state not readable (SecureBoot\\State\\UEFISecureBootEnabled absent) — " +
                    "firmware posture NOT verified");
                return;
            }

            if (sbState == 0)
            {
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "secureboot-disabled"),
                    Severity = Severity.Possible,
                    Description = "UEFI firmware with Secure Boot DISABLED. Unsigned boot components (bootkits) can be " +
                                  "loaded before the OS. Sometimes intentional (dual-boot, legacy drivers) — confirm with " +
                                  "the machine owner; enabling Secure Boot is a firmware-setup change, not something a " +
                                  "scan tool should touch.",
                    Target = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                    Group = Group,
                    Check = ChkSb,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1542", "Pre-OS Boot", "Defense Evasion"),
                });
            }

            sink.Completed(Phase, ChkSb,
                $"firmware={(firmwareType == 2 ? "UEFI" : $"unknown({firmwareType?.ToString() ?? "n/a"})")}, " +
                $"SecureBoot={(sbState == 1 ? "enabled" : "DISABLED")}");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, ChkSb, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- ROOT-005

    /// <summary>DEEP + elevation: read sector 0 of \\.\PHYSICALDRIVE0 strictly read-only,
    /// hash the 440-byte bootstrap area and compare against known-good hashes from the data
    /// file. Never writes; no remediation path exists for this check.</summary>
    private void CheckMbrBootstrap(ScanContext ctx, IFindingSink sink, bool elevated)
    {
        try
        {
            if (ctx.Depth < ScanDepth.Deep)
            {
                sink.Skipped(Phase, ChkMbr, "requires DEEP depth");
                return;
            }

            int? firmwareType;
            using (var ctl = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control"))
                firmwareType = ctl?.GetValue("PEFirmwareType") as int?;

            if (firmwareType == 2)
            {
                sink.Skipped(Phase, ChkMbr, "UEFI boot — legacy MBR bootstrap is not in the boot path");
                return;
            }
            if (firmwareType is null)
            {
                sink.Inconclusive(Phase, ChkMbr, "firmware type undetermined (PEFirmwareType absent) — MBR NOT inspected");
                return;
            }
            if (!elevated)
            {
                sink.Inconclusive(Phase, ChkMbr, @"requires elevation to read \\.\PHYSICALDRIVE0 — MBR NOT inspected");
                return;
            }

            var sector = new byte[512];
            try
            {
                // Read-only open, shared, never written under any circumstance.
                using var disk = new FileStream(@"\\.\PHYSICALDRIVE0", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (disk.ReadAtLeast(sector, 512, throwOnEndOfStream: false) < 512)
                {
                    sink.Inconclusive(Phase, ChkMbr, "short read of sector 0 — MBR NOT inspected");
                    return;
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, ChkMbr,
                    $@"could not open \\.\PHYSICALDRIVE0 read-only ({ex.GetType().Name}: {ex.Message}) — MBR NOT inspected");
                return;
            }

            const string target = @"\\.\PHYSICALDRIVE0";

            if (sector[510] != 0x55 || sector[511] != 0xAA)
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, target, "mbr-missing-boot-signature"),
                    Severity = Severity.Possible,
                    Description = "Sector 0 of the boot disk lacks the 0x55AA boot signature — the MBR is corrupt or " +
                                  "nonstandard. On a machine that boots from this disk that should not happen; image the " +
                                  "disk and analyze offline. No automated remediation exists for boot-sector findings.",
                    Target = target,
                    Group = Group,
                    Check = ChkMbr,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1542.003", "Pre-OS Boot: Bootkit", "Persistence"),
                });

            // Bootstrap code = first 440 bytes (before the optional disk signature at 0x1B8).
            var bootstrapHash = Convert.ToHexString(SHA256.HashData(sector.AsSpan(0, 440))).ToLowerInvariant();
            var knownGood = ctx.Signatures.Set("rootkitboot.mbr_known_good");

            if (knownGood.Count == 0)
            {
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, target, "mbr-bootstrap-hash"),
                    Severity = Severity.Info,
                    Description = $"MBR bootstrap code (first 440 bytes of sector 0) SHA-256: {bootstrapHash}. No " +
                                  "known-good baseline is loaded (rootkitboot.mbr_known_good is empty), so the hash is " +
                                  "reported for manual comparison against a known-clean reference machine of the same " +
                                  "OS build.",
                    Target = target,
                    Group = Group,
                    Check = ChkMbr,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1542.003", "Pre-OS Boot: Bootkit", "Persistence"),
                });
                sink.Inconclusive(Phase, ChkMbr,
                    "bootstrap hashed, but rootkitboot.mbr_known_good set is empty — comparison not possible " +
                    "(hash emitted as an Info finding for manual verification)");
                return;
            }

            if (!knownGood.Any(e => e.Matches(bootstrapHash)))
            {
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, target, "mbr-bootstrap-mismatch"),
                    Severity = Severity.Possible,
                    Description = $"MBR bootstrap code does not match any known-good hash (SHA-256 {bootstrapHash}). " +
                                  "MBR bootkits overwrite this code — but OEM utilities, disk encryption and multi-boot " +
                                  "loaders (GRUB etc.) also produce legitimate mismatches. Image the disk and compare " +
                                  "offline before drawing conclusions. No automated remediation exists for this finding.",
                    Target = target,
                    Group = Group,
                    Check = ChkMbr,
                    FixAction = FixAction.None,
                    Mitre = new MitreRef("T1542.003", "Pre-OS Boot: Bootkit", "Persistence"),
                });
                sink.Completed(Phase, ChkMbr, "bootstrap hashed and compared: mismatch reported");
            }
            else
            {
                sink.Completed(Phase, ChkMbr, "bootstrap matches a known-good hash");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, ChkMbr, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------- ROOT-006

    /// <summary>HVCI / memory-integrity posture via Win32_DeviceGuard
    /// (root\Microsoft\Windows\DeviceGuard). Disabled-but-capable is POSSIBLE — it leaves the
    /// kernel exposed to exactly the BYOVD attacks ROOT-002 hunts for.</summary>
    private void CheckKernelIntegrityPosture(ScanContext ctx, IFindingSink sink)
    {
        try
        {
            ManagementBaseObject? dg = null;
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    new ManagementScope(@"root\Microsoft\Windows\DeviceGuard"),
                    new ObjectQuery("SELECT * FROM Win32_DeviceGuard"));
                dg = searcher.Get().Cast<ManagementBaseObject>().FirstOrDefault();
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, ChkHvci,
                    $"Win32_DeviceGuard not queryable ({ex.GetType().Name}: {ex.Message}) — kernel integrity posture NOT verified");
                return;
            }

            if (dg is null)
            {
                sink.Inconclusive(Phase, ChkHvci,
                    "Win32_DeviceGuard returned no instances — kernel integrity posture NOT verified");
                return;
            }

            using (dg)
            {
                var vbsStatus = dg["VirtualizationBasedSecurityStatus"] is null ? -1 : Convert.ToInt32(dg["VirtualizationBasedSecurityStatus"]);
                var running = ToIntArray(dg["SecurityServicesRunning"]);
                var hvciRunning = running.Contains(2); // 2 = hypervisor-enforced code integrity

                const string target = @"root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard";

                if (vbsStatus == 2 && !hvciRunning)
                {
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, target, "hvci-not-running"),
                        Severity = Severity.Possible,
                        Description = "Virtualization-based security is running, but HVCI (memory integrity / " +
                                      "hypervisor-enforced code integrity) is NOT among the running security services. " +
                                      "Without HVCI the kernel is substantially more exposed to vulnerable-driver (BYOVD) " +
                                      "and rootkit techniques. Enable Memory Integrity in Windows Security > Core " +
                                      "isolation if driver compatibility allows.",
                        Target = target,
                        Group = Group,
                        Check = ChkHvci,
                        FixAction = FixAction.None,
                        Mitre = new MitreRef("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
                    });
                }
                else if (vbsStatus != 2)
                {
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, target, "vbs-not-running"),
                        Severity = Severity.Possible,
                        Description = $"Virtualization-based security is not running (status={vbsStatus}); HVCI/memory " +
                                      "integrity is therefore unavailable. This is a hardening gap, not evidence of " +
                                      "compromise — but it is the posture BYOVD attacks rely on. If the hardware is " +
                                      "capable, enable Memory Integrity (Core isolation).",
                        Target = target,
                        Group = Group,
                        Check = ChkHvci,
                        FixAction = FixAction.None,
                        Mitre = new MitreRef("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
                    });
                }

                sink.Completed(Phase, ChkHvci,
                    $"VBS status={vbsStatus}, running security services=[{string.Join(",", running)}], HVCI={(hvciRunning ? "running" : "not running")}");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, ChkHvci, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static int[] ToIntArray(object? value) => value switch
    {
        int[] i => i,
        uint[] u => u.Select(x => (int)x).ToArray(),
        Array a => a.Cast<object>().Select(Convert.ToInt32).ToArray(),
        _ => Array.Empty<int>(),
    };

    // ---------------------------------------------------------------- helpers

    private static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>Authenticode verification that distinguishes four states the report must not
    /// conflate (guide rule 15): valid (embedded or catalog), confirmed-unsigned, present-but-
    /// invalid, and "could not check". Most inbox drivers carry no embedded signature and are
    /// catalog-signed, so "no embedded signature" alone is NOT "unsigned".</summary>
    private static class Authenticode
    {
        public enum SigState { ValidEmbedded, ValidCatalog, NoSignature, Invalid, CheckFailed }

        public readonly record struct Result(SigState State, string? Signer, string? Detail);

        private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
        private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
        private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);

        public static Result Check(string path)
        {
            int hr;
            try { hr = VerifyEmbedded(path); }
            catch (Exception ex) { return new Result(SigState.CheckFailed, null, $"WinVerifyTrust unavailable: {ex.GetType().Name}"); }

            if (hr == 0)
                return new Result(SigState.ValidEmbedded, TryGetSigner(path), null);

            if (hr is TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN)
                return CatalogLookup(path); // no embedded signature — check security catalogs

            var u = (uint)hr;
            var signaturePresentButBad = (u >= 0x800B0101 && u <= 0x800B0200)   // CERT_E_* family
                                      || (u >= 0x80096001 && u <= 0x800960FF);  // TRUST_E_BAD_DIGEST etc.
            return signaturePresentButBad
                ? new Result(SigState.Invalid, TryGetSigner(path), $"hr=0x{hr:X8}")
                : new Result(SigState.CheckFailed, null, $"WinVerifyTrust hr=0x{hr:X8}");
        }

        private static Result CatalogLookup(string path)
        {
            var admin = IntPtr.Zero;
            try
            {
                if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
                    return new Result(SigState.CheckFailed, null, "catalog admin context unavailable");

                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var cb = 64;
                var hash = new byte[cb];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle, ref cb, hash, 0))
                    return new Result(SigState.CheckFailed, null, "catalog file-hash computation failed");

                var prev = IntPtr.Zero;
                var cat = CryptCATAdminEnumCatalogFromHash(admin, hash, cb, 0, ref prev);
                if (cat != IntPtr.Zero)
                {
                    CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                    return new Result(SigState.ValidCatalog, null, null);
                }
                // Positively looked in the catalogs and found nothing: confirmed unsigned.
                return new Result(SigState.NoSignature, null, null);
            }
            catch (Exception ex)
            {
                return new Result(SigState.CheckFailed, null, $"catalog lookup failed: {ex.GetType().Name}");
            }
            finally
            {
                if (admin != IntPtr.Zero) CryptCATAdminReleaseContext(admin, 0);
            }
        }

        private static int VerifyEmbedded(string path)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = path,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };
            var pFile = Marshal.AllocHGlobal(fileInfo.cbStruct);
            try
            {
                Marshal.StructureToPtr(fileInfo, pFile, false);
                var data = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = 2,                  // WTD_UI_NONE
                    fdwRevocationChecks = 0,         // WTD_REVOKE_NONE
                    dwUnionChoice = 1,               // WTD_CHOICE_FILE
                    pFile = pFile,
                    dwStateAction = 0,               // WTD_STATEACTION_IGNORE
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = 0x10 | 0x1000,     // WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL (no network during a scan)
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero,
                };
                var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                var result = WinVerifyTrust(IntPtr.Zero, in action, ref data);
                Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pFile);
            }
        }

        private static string? TryGetSigner(string path)
        {
            try
            {
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
                var name = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                return string.IsNullOrWhiteSpace(name) ? cert.Subject : name;
            }
            catch { return null; }
        }

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public int cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public int cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public int dwUIChoice;
            public int fdwRevocationChecks;
            public int dwUnionChoice;
            public IntPtr pFile;
            public int dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true)]
        private static extern int WinVerifyTrust(IntPtr hwnd, in Guid pgActionID, ref WINTRUST_DATA pWVTData);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem,
            string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile,
            ref int pcbHash, byte[] pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash,
            int cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
    }
}
