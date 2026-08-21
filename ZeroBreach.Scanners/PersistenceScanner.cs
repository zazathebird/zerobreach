// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). ZeroBreach is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32;
using ZeroBreach.Core.Model;
using ZeroBreach.Core.Scanning;
using ZeroBreach.Core.Signatures;
using ZeroBreach.Core.Util;

namespace ZeroBreach.Scanners;

/// <summary>
/// Phase 1 — Persistence (spec §3 first bullet; catalog PERS-001..PERS-010).
/// Read-only: enumerates autorun registry keys, startup folders, scheduled tasks, services,
/// WMI event subscriptions, Winlogon/AppInit/IFEO, per-user COM hijack points, browser
/// extensions, Office trust settings and shell extension handlers. All indicator content
/// lives in Signatures/persistence.json.
/// </summary>
public sealed class PersistenceScanner : IScanner
{
    public int Phase => 1;
    public string Name => "Persistence";
    public string Group => "Persistence";
    public ScanDepth MinDepth => ScanDepth.Quick;

    // ---- MITRE refs used as check-level defaults (indicator-level refs come from the JSON) ----
    private static readonly MitreRef T1547_001 = new("T1547.001", "Registry Run Keys / Startup Folder", "Persistence");
    private static readonly MitreRef T1547_004 = new("T1547.004", "Winlogon Helper DLL", "Persistence");
    private static readonly MitreRef T1053_005 = new("T1053.005", "Scheduled Task", "Persistence");
    private static readonly MitreRef T1543_003 = new("T1543.003", "Create or Modify System Process: Windows Service", "Persistence");
    private static readonly MitreRef T1574_009 = new("T1574.009", "Hijack Execution Flow: Path Interception by Unquoted Path", "Persistence");
    private static readonly MitreRef T1546_003 = new("T1546.003", "Event Triggered Execution: WMI Event Subscription", "Persistence");
    private static readonly MitreRef T1546_010 = new("T1546.010", "Event Triggered Execution: AppInit DLLs", "Persistence");
    private static readonly MitreRef T1546_012 = new("T1546.012", "Event Triggered Execution: Image File Execution Options Injection", "Persistence");
    private static readonly MitreRef T1546_015 = new("T1546.015", "Event Triggered Execution: Component Object Model Hijacking", "Persistence");
    private static readonly MitreRef T1176 = new("T1176", "Browser Extensions", "Persistence");
    private static readonly MitreRef T1137 = new("T1137", "Office Application Startup", "Persistence");
    private static readonly MitreRef T1137_004 = new("T1137.004", "Office Application Startup: Outlook Home Page", "Persistence");

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        Guarded(sink, "PERS-001 Run/RunOnce keys", () => CheckRunKeys(ctx, sink));
        Guarded(sink, "PERS-002 Startup folders", () => CheckStartupFolders(ctx, sink));
        Guarded(sink, "PERS-003 Scheduled tasks", () => CheckScheduledTasks(ctx, sink));
        Guarded(sink, "PERS-004 Services", () => CheckServices(ctx, sink));
        Guarded(sink, "PERS-005 WMI event subscriptions", () => CheckWmiSubscriptions(ctx, sink));
        Guarded(sink, "PERS-006 Winlogon/AppInit/IFEO", () => CheckWinlogonAndIfeo(ctx, sink));
        Guarded(sink, "PERS-007 COM hijack", () => CheckComHijack(ctx, sink));
        Guarded(sink, "PERS-008 Browser extensions", () => CheckBrowserExtensions(ctx, sink));
        Guarded(sink, "PERS-009 Office trust & Outlook", () => CheckOfficeTrust(ctx, sink));
        Guarded(sink, "PERS-010 Shell extensions", () => CheckShellExtensions(ctx, sink));
    }

    /// <summary>Outer safety net per check: an unexpected crash becomes Inconclusive,
    /// never a silent absence of results (spec §6.7). Cancellation propagates.</summary>
    private void Guarded(IFindingSink sink, string check, Action body)
    {
        try { body(); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, check, $"check crashed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    // =====================================================================================
    // PERS-001 — Run/RunOnce/RunOnceEx keys (machine + per-profile). T1547.001.
    // =====================================================================================

    // Walked under BOTH registry views via LmViews() — never via literal Wow6432Node
    // paths, which silently resolve to nothing (= false "clean") in a WOW-redirected process.
    private static readonly string[] MachineRunKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    };

    private static readonly string[] UserRunKeys =
    {
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    };

    private void CheckRunKeys(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-001 Run/RunOnce keys";

        // Machine hives (own walk, own budget), both 64- and 32-bit views.
        try
        {
            var budget = ctx.CreateBudget(500, TimeSpan.FromSeconds(20));
            foreach (var (view, _, wow) in LmViews())
            {
                if (budget.Exhausted) break;
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                foreach (var subPath in MachineRunKeys)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (budget.Exhausted) break;
                    using var key = hklm.OpenSubKey(subPath);
                    if (key is null) continue; // key absent = nothing registered there
                    // Name the PHYSICAL key (WOW6432Node for the 32-bit view) so the finding
                    // target/fix_param address the real location regardless of process bitness.
                    var physical = PhysicalLmPath(subPath, wow);
                    WalkRunKey(ctx, sink, check, budget, key, $@"HKLM\{physical}", $@"HKLM\{physical}", "machine", "machine");
                }
            }
            sink.CompleteOrInconclusive(Phase, check, budget, "machine Run keys (64+32-bit views)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, $"machine Run keys: {ex.Message}"); }

        // Every profile, fresh budget each (spec §4).
        foreach (var p in ctx.Profiles)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            try
            {
                using var root = p.OpenHiveRoot();
                if (root is null)
                {
                    sink.Skipped(Phase, check, $"profile {p.UserName}: hive not mounted (run with --load-hives)");
                    continue;
                }
                var budget = ctx.CreateBudget(200, TimeSpan.FromSeconds(10));
                foreach (var subPath in UserRunKeys)
                {
                    if (budget.Exhausted) break;
                    using var key = root.OpenSubKey(subPath);
                    if (key is null) continue;
                    WalkRunKey(ctx, sink, check, budget, key,
                        $@"HKU\{p.Sid}\{subPath}", $@"HKU\{p.HiveKeyName}\{subPath}", p.UserName, p.Sid);
                }
                sink.CompleteOrInconclusive(Phase, check, budget, $"profile {p.UserName}");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.Message}"); }
        }
    }

    private void WalkRunKey(ScanContext ctx, IFindingSink sink, string check, EnumerationBudget budget,
        RegistryKey key, string displayKey, string fixKeyPath, string owner, string ownerSid)
    {
        foreach (var valueName in key.GetValueNames())
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            if (!budget.TryConsume()) return;
            if (valueName.Length == 0) continue; // default value not used by Run key semantics
            var data = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString();
            if (string.IsNullOrWhiteSpace(data)) continue;
            AnalyzeAutorunValue(ctx, sink, check, displayKey, fixKeyPath, valueName, data, owner, ownerSid);
        }

        // RunOnceEx nests its commands one level down (0001\, 0002\, ...).
        if (!displayKey.Contains("RunOnceEx", StringComparison.OrdinalIgnoreCase)) return;
        foreach (var subName in key.GetSubKeyNames())
        {
            if (budget.Exhausted) return;
            using var sub = key.OpenSubKey(subName);
            if (sub is null) continue;
            WalkRunKey(ctx, sink, check, budget, sub, $@"{displayKey}\{subName}", $@"{fixKeyPath}\{subName}", owner, ownerSid);
        }
    }

    private void AnalyzeAutorunValue(ScanContext ctx, IFindingSink sink, string check,
        string displayKey, string fixKeyPath, string valueName, string data, string owner, string ownerSid)
    {
        var sig = new SignalSet();
        ApplySet(ctx, sig, "persistence.autorun_suspect_patterns", data, "command pattern");

        var expanded = Environment.ExpandEnvironmentVariables(data);
        var exe = ExtractExecutable(data);
        var exeRooted = exe is not null && Path.IsPathRooted(exe);
        var exeExists = exeRooted && File.Exists(exe!);

        var uw = UserWritableMatch(ctx, expanded);
        if (uw is not null && (!uw.NeedsCorroboration || sig.Any))
            sig.Add(CapSeverity(uw), $"points into user-writable location ({uw.Note ?? uw.Pattern})", uw.Mitre);

        if (exeRooted && !exeExists)
            sig.Add(Severity.Possible, $"target file not found (orphaned autorun): {exe}");

        var hashConfirmed = false;
        if (exeExists)
        {
            if (uw is not null)
                AddAuthenticodeSignal(sig, exe!, Severity.High, "executable in user-writable path", T1547_001);
            ApplyFileIocSignals(ctx, sig, exe!, ref hashConfirmed);
        }

        if (!sig.Any || sig.Severity < Severity.Possible) return;

        var fix = FixAction.None;
        string? fixParam = null;
        if (hashConfirmed && exeExists) { fix = FixAction.DeleteFile; fixParam = exe; }
        else if (sig.Severity >= Severity.High) { fix = FixAction.DeleteRegistryValue; fixParam = $"{fixKeyPath}::{valueName}"; }

        Emit(sink, ctx, check, displayKey, $"{valueName}|{ownerSid}", sig.Severity,
            $"Autorun value '{valueName}' ({owner}) = {Trunc(data, 200)} — {sig.ReasonText}",
            fix, fixParam, sig.Mitre ?? T1547_001, data, hashConfirmed);
    }

    // =====================================================================================
    // PERS-002 — Startup folders (per-profile + all-users). T1547.001.
    // =====================================================================================

    private void CheckStartupFolders(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-002 Startup folders";

        try
        {
            var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            var budget = ctx.CreateBudget(200, TimeSpan.FromSeconds(10));
            WalkStartupFolder(ctx, sink, check, budget, common, "all users", "machine");
            sink.CompleteOrInconclusive(Phase, check, budget, "common Startup folder");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, $"common Startup folder: {ex.Message}"); }

        foreach (var p in ctx.Profiles)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            try
            {
                // Filesystem location — walkable whether or not the hive is mounted.
                var dir = Path.Combine(p.ProfilePath, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");
                var budget = ctx.CreateBudget(200, TimeSpan.FromSeconds(10));
                WalkStartupFolder(ctx, sink, check, budget, dir, p.UserName, p.Sid);
                sink.CompleteOrInconclusive(Phase, check, budget, $"profile {p.UserName}");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.Message}"); }
        }
    }

    private void WalkStartupFolder(ScanContext ctx, IFindingSink sink, string check,
        EnumerationBudget budget, string dir, string owner, string ownerSid)
    {
        if (!Directory.Exists(dir)) return; // absent folder = nothing to start
        foreach (var file in Directory.EnumerateFiles(dir))
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            if (!budget.TryConsume()) return;
            var name = Path.GetFileName(file);
            if (string.Equals(name, "desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            // Current-state persistence: a startup item fires at every logon no matter how
            // old its mtime is, so --since never suppresses it — the time window only
            // annotates recency (see AnalyzeStartupItem).
            AnalyzeStartupItem(ctx, sink, check, file, owner, ownerSid);
        }
    }

    private void AnalyzeStartupItem(ScanContext ctx, IFindingSink sink, string check,
        string file, string owner, string ownerSid)
    {
        var sig = new SignalSet();
        if (ctx.SinceUtc is not null && File.GetLastWriteTimeUtc(file) >= ctx.SinceUtc.Value)
            sig.AddNote("modified inside the scan time window");
        ApplySet(ctx, sig, "persistence.startup_suspect_ext", Path.GetFileName(file), "startup item");

        string? payload = file;
        var ext = Path.GetExtension(file).ToLowerInvariant();
        if (ext == ".lnk")
        {
            var (target, args, resolved) = ResolveShortcut(file);
            if (!resolved || string.IsNullOrWhiteSpace(target))
            {
                sig.AddNote("shortcut target could not be resolved");
                payload = null;
            }
            else
            {
                payload = target;
                ApplySet(ctx, sig, "persistence.startup_suspect_ext", Path.GetFileName(target), "shortcut target");
                ApplySet(ctx, sig, "persistence.autorun_suspect_patterns", $"{target} {args}", "shortcut command");
                var uw = UserWritableMatch(ctx, Environment.ExpandEnvironmentVariables(target));
                if (uw is not null && (!uw.NeedsCorroboration || sig.Any))
                    sig.Add(CapSeverity(uw), $"shortcut target in user-writable location ({uw.Note ?? uw.Pattern})", uw.Mitre);
                if (Path.IsPathRooted(target) && !File.Exists(target))
                    sig.Add(Severity.Possible, $"shortcut target missing: {target}");
                else if (uw is not null && File.Exists(target))
                    AddAuthenticodeSignal(sig, target, Severity.High, "shortcut target in user-writable path", T1547_001);
            }
        }
        else if (ext == ".exe")
        {
            sig.Add(Severity.Possible, "executable placed directly in Startup folder (installers normally use shortcuts)");
        }

        var hashConfirmed = false;
        if (payload is not null && File.Exists(payload))
            ApplyFileIocSignals(ctx, sig, payload, ref hashConfirmed);

        if (!sig.Any || sig.Severity < Severity.Possible) return;

        var fix = FixAction.None;
        string? fixParam = null;
        if (hashConfirmed && payload is not null) { fix = FixAction.DeleteFile; fixParam = payload; }
        else if (sig.Severity >= Severity.High) { fix = FixAction.Quarantine; fixParam = file; }

        Emit(sink, ctx, check, file, $"startup|{ownerSid}", sig.Severity,
            $"Startup folder item ({owner}): {sig.ReasonText}",
            fix, fixParam, sig.Mitre ?? T1547_001, payload ?? file, hashConfirmed);
    }

    // =====================================================================================
    // PERS-003 — Scheduled tasks via raw XML under System32\Tasks. T1053.005.
    // =====================================================================================

    private void CheckScheduledTasks(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-003 Scheduled tasks";
        var tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(tasksRoot))
        {
            sink.Inconclusive(Phase, check, $"{tasksRoot} not present/accessible (are we elevated?)");
            return;
        }

        var budget = ctx.CreateBudget(3000, TimeSpan.FromSeconds(60));
        int deniedDirs = 0, parseFailures = 0;
        var stack = new Stack<string>();
        stack.Push(tasksRoot);
        while (stack.Count > 0 && !budget.Exhausted)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            var dir = stack.Pop();
            string[] files, subdirs;
            try
            {
                files = Directory.GetFiles(dir);
                subdirs = Directory.GetDirectories(dir);
            }
            catch (UnauthorizedAccessException) { deniedDirs++; continue; }
            catch (IOException) { deniedDirs++; continue; }

            foreach (var d in subdirs) stack.Push(d);
            foreach (var f in files)
            {
                if (!budget.TryConsume()) break;
                if (!AnalyzeTaskFile(ctx, sink, check, tasksRoot, f)) parseFailures++;
            }
        }

        var detail = $"{tasksRoot}" +
                     (parseFailures > 0 ? $", {parseFailures} unparseable task file(s)" : "");
        if (deniedDirs > 0)
            sink.Inconclusive(Phase, check, $"{detail}: {deniedDirs} task subfolder(s) access-denied — coverage incomplete");
        else
            sink.CompleteOrInconclusive(Phase, check, budget, detail);
    }

    /// <summary>Returns false when the task XML could not be parsed.</summary>
    private bool AnalyzeTaskFile(ScanContext ctx, IFindingSink sink, string check, string tasksRoot, string file)
    {
        // Current-state persistence: a registered task fires on its triggers no matter how
        // old the task XML's mtime is, so --since never suppresses it — the time window
        // only annotates recency (note added to the signal set below).
        XDocument doc;
        try { doc = XDocument.Load(file); }
        catch { return false; }

        var taskName = @"\" + Path.GetRelativePath(tasksRoot, file);
        var isRoot = !taskName.TrimStart('\\').Contains('\\');
        var underMicrosoft = taskName.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);

        var commands = new List<string>();
        foreach (var exec in doc.Descendants().Where(e => e.Name.LocalName == "Exec"))
        {
            var cmd = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value ?? "";
            var args = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments")?.Value ?? "";
            var full = $"{cmd} {args}".Trim();
            if (full.Length > 0) commands.Add(full);
        }
        var joined = string.Join(" | ", commands);

        var hidden = doc.Descendants().Any(e => e.Name.LocalName == "Hidden" &&
            string.Equals(e.Value.Trim(), "true", StringComparison.OrdinalIgnoreCase));
        var author = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Author")?.Value;
        var logonOrBoot = doc.Descendants().Any(e => e.Name.LocalName is "LogonTrigger" or "BootTrigger");

        var sig = new SignalSet();
        if (ctx.SinceUtc is not null && File.GetLastWriteTimeUtc(file) >= ctx.SinceUtc.Value)
            sig.AddNote("task file modified inside the scan time window");
        string? exe = null;
        var uwMatched = false;
        if (joined.Length > 0)
        {
            ApplySet(ctx, sig, "persistence.autorun_suspect_patterns", joined, "task action");
            var expanded = Environment.ExpandEnvironmentVariables(joined);
            var uw = UserWritableMatch(ctx, expanded);
            if (uw is not null && (!uw.NeedsCorroboration || sig.Any))
            {
                uwMatched = true;
                sig.Add(CapSeverity(uw), $"task action in user-writable location ({uw.Note ?? uw.Pattern})", uw.Mitre);
            }
            exe = ExtractExecutable(commands[0]);
            if (exe is not null && Path.IsPathRooted(exe))
            {
                if (!File.Exists(exe))
                    sig.Add(Severity.Possible, $"task action target missing: {exe}");
                else if (uwMatched)
                    AddAuthenticodeSignal(sig, exe, Severity.High, "task action in user-writable path", T1053_005);
            }
        }

        // Boosters — gated so common legitimate shapes (hidden Microsoft tasks, vendor
        // updaters at root level) don't arm findings on their own.
        if (hidden && (!underMicrosoft || sig.Any))
            sig.Add(Severity.Possible, "task is marked Hidden");
        if (logonOrBoot && string.IsNullOrWhiteSpace(author) && !underMicrosoft)
            sig.Add(Severity.Possible, "logon/boot trigger with blank author");
        if (isRoot && sig.Any)
            ApplySet(ctx, sig, "persistence.task_lookalike_names", taskName.TrimStart('\\'), "task name");

        var hashConfirmed = false;
        if (exe is not null && Path.IsPathRooted(exe) && File.Exists(exe))
            ApplyFileIocSignals(ctx, sig, exe, ref hashConfirmed);

        if (!sig.Any || sig.Severity < Severity.Possible) return true;

        var fix = FixAction.None;
        string? fixParam = null;
        if (hashConfirmed && exe is not null) { fix = FixAction.DeleteFile; fixParam = exe; }
        else if (sig.Severity >= Severity.High && uwMatched && exe is not null && File.Exists(exe))
        {
            fix = FixAction.Quarantine; // prefer quarantining the payload over task surgery
            fixParam = exe;
        }

        Emit(sink, ctx, check, $"Task:{taskName}", joined, sig.Severity,
            $"Scheduled task '{taskName}' action(s): {Trunc(joined, 260)} — {sig.ReasonText}. " +
            $"Review/remove by hand after triage: schtasks /Delete /TN \"{taskName.TrimStart('\\')}\"",
            fix, fixParam, sig.Mitre ?? T1053_005, joined, hashConfirmed);
        return true;
    }

    // =====================================================================================
    // PERS-004 — Services (Win32_Service). T1543.003 / T1574.009.
    // =====================================================================================

    private void CheckServices(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-004 Services";
        try
        {
            // Win32_Service covers user-mode services ONLY — kernel-mode driver services
            // (a loaded rootkit's registration is one) are invisible to it. Win32_BaseService
            // is the parent class of both, so one query and one budget cover the whole
            // service namespace.
            var budget = ctx.CreateBudget(3000, TimeSpan.FromSeconds(60));
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, PathName, State, StartMode, ServiceType FROM Win32_BaseService");
            using var results = searcher.Get();
            foreach (ManagementBaseObject mo in results)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) break;
                AnalyzeService(ctx, sink, check, mo);
            }
            sink.CompleteOrInconclusive(Phase, check, budget, "Win32_BaseService enumeration (services and driver services)");
        }
        catch (OperationCanceledException) { throw; }
        catch (ManagementException ex) { sink.Inconclusive(Phase, check, $"Win32_BaseService query failed: {ex.Message}"); }
    }

    private void AnalyzeService(ScanContext ctx, IFindingSink sink, string check, ManagementBaseObject mo)
    {
        var name = Prop(mo, "Name");
        var raw = Prop(mo, "PathName");
        if (name is null || string.IsNullOrWhiteSpace(raw)) return;

        var sig = new SignalSet();
        var expanded = Environment.ExpandEnvironmentVariables(raw);
        var exe = ExtractExecutable(raw);
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var uw = UserWritableMatch(ctx, expanded);
        if (uw is not null)
        {
            // A service binary in a truly user-writable dir is high-confidence (catalog: HIGH).
            if (!uw.NeedsCorroboration)
                sig.Add(Severity.High, $"service binary in user-writable directory ({uw.Note ?? uw.Pattern})", T1543_003);
            else
                sig.Add(Severity.Possible, $"service binary in {uw.Note ?? uw.Pattern}", T1543_003);
        }

        // Unquoted ImagePath containing spaces (T1574.009).
        if (!raw.StartsWith('"'))
        {
            var idx = raw.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (idx > 0 && raw[..(idx + 4)].Contains(' '))
                sig.Add(Severity.Possible, "unquoted service path containing spaces", T1574_009);
        }

        // svchost-hosted: the real payload is the ServiceDll.
        // Driver services register native paths (\??\C:\..., \SystemRoot\..., or relative to
        // System32) that File.Exists cannot open; resolve them before any file-based check,
        // or every driver silently skips signature/hash inspection.
        var resolved = ResolveServiceImage(exe ?? raw, windir);
        string? binary = exe is not null && Path.IsPathRooted(exe) && File.Exists(exe) ? exe : null;
        if (binary is null && resolved is not null && File.Exists(resolved)) binary = resolved;

        // A service whose binary is not on disk is the mirror of the missing scheduled-task
        // target PERS-003 already flags: either a failed uninstall, or a component that ran and
        // deleted itself. UNC paths are excluded — an unreachable share is not a missing file.
        if (binary is null && resolved is not null && LooksLikeLocalImage(resolved) && !File.Exists(resolved))
            sig.Add(Severity.Possible,
                $"registered service binary is missing from disk ({resolved}) — failed uninstall, or " +
                "a component that ran and removed its own file", T1543_003);

        if (exe is not null &&
            string.Equals(Path.GetFileName(exe), "svchost.exe", StringComparison.OrdinalIgnoreCase) &&
            raw.Contains("-k", StringComparison.OrdinalIgnoreCase))
        {
            using var parms = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}\Parameters");
            if (parms?.GetValue("ServiceDll")?.ToString() is { Length: > 0 } dllRaw)
            {
                var dll = Environment.ExpandEnvironmentVariables(dllRaw);
                var sys32 = Path.Combine(windir, "System32");
                var wow64 = Path.Combine(windir, "SysWOW64");
                if (!dll.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) &&
                    !dll.StartsWith(wow64, StringComparison.OrdinalIgnoreCase))
                    sig.Add(Severity.High, $"svchost-hosted ServiceDll outside System32: {dll}", T1543_003);
                if (File.Exists(dll)) binary = dll;
            }
        }

        var hashConfirmed = false;
        if (binary is not null)
        {
            if (!binary.StartsWith(windir, StringComparison.OrdinalIgnoreCase))
                AddAuthenticodeSignal(sig, binary, uw is not null ? Severity.High : Severity.Possible,
                    "service binary outside the Windows directory", T1543_003);
            ApplyFileIocSignals(ctx, sig, binary, ref hashConfirmed);
        }

        if (!sig.Any || sig.Severity < Severity.Possible) return;

        var fix = FixAction.None;
        string? fixParam = null;
        if (hashConfirmed && binary is not null) { fix = FixAction.DeleteFile; fixParam = binary; }
        else if (sig.Severity >= Severity.High && uw is not null && binary is not null)
        {
            fix = FixAction.Quarantine;
            fixParam = binary;
        }

        var display = Prop(mo, "DisplayName");
        var state = Prop(mo, "State");
        var mode = Prop(mo, "StartMode");
        var type = Prop(mo, "ServiceType");
        var kind = string.IsNullOrEmpty(type) ? "service" : type;
        Emit(sink, ctx, check, $"Service:{name}", raw, sig.Severity,
            $"{kind} '{name}' ({display}, {state}/{mode}) ImagePath = {Trunc(raw, 200)} — {sig.ReasonText}",
            fix, fixParam, sig.Mitre ?? T1543_003, raw, hashConfirmed);
    }

    // =====================================================================================
    // PERS-005 — WMI event subscriptions (root\subscription). T1546.003.
    // =====================================================================================

    private void CheckWmiSubscriptions(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-005 WMI event subscriptions";
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();

            // WMI enumerations can stall on a wedged provider — honor cancellation per item
            // (PhaseRunner treats OperationCanceledException as scan cancellation).
            var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var mo in Query(scope, "SELECT Name, Query FROM __EventFilter"))
                using (mo)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (Prop(mo, "Name") is { } fn)
                        filters[fn] = Prop(mo, "Query") ?? "";
                }

            var bindings = new List<string>();
            foreach (var mo in Query(scope, "SELECT Filter, Consumer FROM __FilterToConsumerBinding"))
                using (mo)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    bindings.Add($"{Prop(mo, "Consumer")}=>{Prop(mo, "Filter")}");
                }

            var consumers = 0;
            foreach (var mo in Query(scope, "SELECT * FROM CommandLineEventConsumer"))
                using (mo)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    consumers++;
                    var content = $"{Prop(mo, "ExecutablePath")} {Prop(mo, "CommandLineTemplate")}".Trim();
                    EmitWmiConsumer(ctx, sink, check, "CommandLineEventConsumer", Prop(mo, "Name"), content, filters, bindings);
                }
            foreach (var mo in Query(scope, "SELECT * FROM ActiveScriptEventConsumer"))
                using (mo)
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    consumers++;
                    var content = ($"{Prop(mo, "ScriptFileName")} {Prop(mo, "ScriptText")}").Trim();
                    EmitWmiConsumer(ctx, sink, check, "ActiveScriptEventConsumer", Prop(mo, "Name"), content, filters, bindings);
                }

            sink.Completed(Phase, check,
                $"{filters.Count} filter(s), {consumers} command/script consumer(s), {bindings.Count} binding(s)");
        }
        catch (OperationCanceledException) { throw; }
        catch (ManagementException ex)
        {
            sink.Inconclusive(Phase, check, @$"root\subscription namespace unreadable ({ex.Message}) — WMI persistence NOT checked");
        }
        catch (UnauthorizedAccessException ex)
        {
            sink.Inconclusive(Phase, check, @$"root\subscription access denied ({ex.Message}) — WMI persistence NOT checked");
        }
    }

    private static IEnumerable<ManagementBaseObject> Query(ManagementScope scope, string wql)
    {
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
        using var results = searcher.Get();
        foreach (ManagementBaseObject mo in results) yield return mo;
    }

    private void EmitWmiConsumer(ScanContext ctx, IFindingSink sink, string check,
        string className, string? name, string content,
        Dictionary<string, string> filters, List<string> bindings)
    {
        name ??= "(unnamed)";

        var bound = bindings.FirstOrDefault(b => b.Contains($"{className}.Name=\"{name}\"", StringComparison.OrdinalIgnoreCase));

        // Any command/script consumer is at least POSSIBLE; content matching a
        // non-corroboration-required High indicator is a corroborated artifact — but only a
        // BOUND consumer actually fires, so CRITICAL ("unambiguous active compromise")
        // requires the binding; a dormant match caps at HIGH.
        var sev = Severity.Possible;
        var reasons = new List<string> { $"{className} present (rare outside managed enterprise tooling)" };
        foreach (var setName in new[] { "persistence.autorun_suspect_patterns", "persistence.wmi_suspect_content" })
            foreach (var e in ctx.Signatures.Set(setName))
            {
                if (!e.Matches(content)) continue;
                reasons.Add($"content matches: {e.Note ?? e.Pattern}");
                if (!e.NeedsCorroboration && e.Severity >= Severity.High && bound is not null) sev = Severity.Critical;
                else if (sev < Severity.High) sev = Severity.High;
            }
        if (bound is not null)
        {
            var filterName = filters.Keys.FirstOrDefault(f => bound.Contains($"__EventFilter.Name=\"{f}\"", StringComparison.OrdinalIgnoreCase));
            reasons.Add(filterName is not null
                ? $"bound to EventFilter '{filterName}' (query: {Trunc(filters[filterName], 160)})"
                : "bound to an event filter");
        }
        else
        {
            reasons.Add("no FilterToConsumerBinding found (dormant consumer)");
        }

        Emit(sink, ctx, check, $@"WMI:root\subscription:{className}.Name={name}", Trunc(content, 500), sev,
            $"WMI event consumer '{name}' ({className}): {Trunc(content, 260)} — {string.Join("; ", reasons)}. " +
            "Removal requires deleting the consumer, filter and binding instances by hand after triage.",
            FixAction.None, null, T1546_003, content, hashConfirmed: false);
    }

    // =====================================================================================
    // PERS-006 — Winlogon Shell/Userinit, AppInit_DLLs, IFEO Debugger/SilentProcessExit.
    // =====================================================================================

    private void CheckWinlogonAndIfeo(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-006 Winlogon/AppInit/IFEO";
        const string winlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        var gaps = new List<string>();

        // Fixed-location reads.
        using (var winlogon = Registry.LocalMachine.OpenSubKey(winlogonPath))
        {
            if (winlogon is null)
            {
                gaps.Add($@"HKLM\{winlogonPath} unreadable — Winlogon NOT checked");
            }
            else
            {
                if (winlogon.GetValue("Shell")?.ToString() is { Length: > 0 } shell &&
                    !string.Equals(shell.Trim().Trim('"'), "explorer.exe", StringComparison.OrdinalIgnoreCase))
                {
                    Emit(sink, ctx, check, $@"HKLM\{winlogonPath}", "Shell", Severity.High,
                        $"Winlogon Shell is '{shell}' instead of the default 'explorer.exe' — replacement shells are a classic persistence/lockout technique. " +
                        "Restore the value by hand after confirming the binary; deleting the value outright breaks logon.",
                        FixAction.None, null, T1547_004, shell, false);
                }

                if (winlogon.GetValue("Userinit")?.ToString() is { Length: > 0 } userinit)
                {
                    var entries = userinit.Split(',').Select(e => e.Trim()).Where(e => e.Length > 0).ToList();
                    var extra = entries.Count > 1 ||
                                (entries.Count == 1 && !entries[0].EndsWith("userinit.exe", StringComparison.OrdinalIgnoreCase));
                    if (extra)
                        Emit(sink, ctx, check, $@"HKLM\{winlogonPath}", "Userinit", Severity.High,
                            $"Winlogon Userinit = '{userinit}' — anything beyond 'userinit.exe,' executes at every logon. " +
                            "Edit the value by hand after triage; deleting it outright breaks logon.",
                            FixAction.None, null, T1547_004, userinit, false);
                }
            }
        }

        // AppInit_DLLs — both registry views (single native view on a 32-bit OS, where
        // walking "both" would double-report the same physical key).
        foreach (var (view, label, _) in LmViews())
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var win = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
            if (win is null)
            {
                gaps.Add($@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows ({label} view) unreadable — AppInit_DLLs NOT checked");
                continue;
            }
            var appInit = win.GetValue("AppInit_DLLs")?.ToString();
            if (string.IsNullOrWhiteSpace(appInit)) continue;
            var loadOn = win.GetValue("LoadAppInit_DLLs") is int load && load == 1;
            Emit(sink, ctx, check,
                $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows ({label})", $"AppInit_DLLs|{label}",
                loadOn ? Severity.High : Severity.Possible,
                $"AppInit_DLLs ({label} view) = '{appInit}', LoadAppInit_DLLs={(loadOn ? 1 : 0)} — DLLs here inject into every GUI process" +
                (loadOn ? "." : " (currently not loaded, but staged)."),
                FixAction.None, null, T1546_010, appInit, false);
        }

        // One status for the fixed-location part — never "Completed" over a scope that
        // was actually unreadable (spec §6.7).
        if (gaps.Count > 0)
            sink.Inconclusive(Phase, check, "partial coverage: " + string.Join("; ", gaps));
        else
            sink.Completed(Phase, check, "Winlogon Shell/Userinit + AppInit_DLLs (both views)");

        // IFEO walk (own budget; reported under the same check with its own scope). IFEO is
        // WOW-redirected, so both views are walked.
        const string ifeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        var budget = ctx.CreateBudget(3000, TimeSpan.FromSeconds(30));
        var ifeoGaps = new List<string>();
        foreach (var (view, label, wow) in LmViews())
        {
            if (budget.Exhausted) break;
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var ifeo = baseKey.OpenSubKey(ifeoPath);
            if (ifeo is null)
            {
                ifeoGaps.Add($@"HKLM\{ifeoPath} ({label} view) unreadable — IFEO NOT checked");
                continue;
            }
            var physicalIfeo = PhysicalLmPath(ifeoPath, wow);
            foreach (var exeName in ifeo.GetSubKeyNames())
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) break;
                using var sub = ifeo.OpenSubKey(exeName);
                if (sub is null) continue;

                if (sub.GetValue("Debugger")?.ToString() is { Length: > 0 } dbg)
                {
                    var expected = ctx.Signatures.Set("persistence.ifeo_expected_debuggers").FirstOrDefault(e => e.Matches(dbg));
                    var sev = expected is null ? Severity.High : Severity.Possible;
                    Emit(sink, ctx, check, $@"HKLM\{physicalIfeo}\{exeName}", "Debugger", sev,
                        $"IFEO Debugger for '{exeName}' = '{dbg}' — every launch of {exeName} runs this instead" +
                        (expected is not null ? $" ({expected.Note})." : "."),
                        FixAction.DeleteRegistryValue, $@"HKLM\{physicalIfeo}\{exeName}::Debugger",
                        T1546_012, dbg, false);
                }

                if (sub.GetValue("GlobalFlag") is int gf && (gf & 0x200) != 0)
                {
                    using var spe = baseKey.OpenSubKey(
                        $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{exeName}");
                    if (spe?.GetValue("MonitorProcess")?.ToString() is { Length: > 0 } monitor)
                        Emit(sink, ctx, check, $@"HKLM\{physicalIfeo}\{exeName}", "GlobalFlag+SilentProcessExit", Severity.High,
                            $"GlobalFlag 0x200 on '{exeName}' paired with SilentProcessExit MonitorProcess = '{monitor}' — " +
                            "runs the monitor whenever the target exits (stealth persistence/dump technique). " +
                            "Remove both the GlobalFlag bit and the SilentProcessExit key by hand.",
                            FixAction.None, null, T1546_012, monitor, false);
                }
            }
        }
        if (ifeoGaps.Count > 0)
            sink.Inconclusive(Phase, check, "IFEO subkeys: " + string.Join("; ", ifeoGaps));
        else
            sink.CompleteOrInconclusive(Phase, check, budget, "IFEO subkeys (64+32-bit views)");
    }

    // =====================================================================================
    // PERS-007 — Per-user COM hijack (HKU CLSID InprocServer32 in user-writable paths). FULL.
    // =====================================================================================

    private void CheckComHijack(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-007 COM hijack";
        if (ctx.Depth < ScanDepth.Full)
        {
            sink.Skipped(Phase, check, "requires FULL depth");
            return;
        }

        foreach (var p in ctx.Profiles)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            try
            {
                using var root = p.OpenHiveRoot();
                if (root is null)
                {
                    sink.Skipped(Phase, check, $"profile {p.UserName}: hive not mounted (run with --load-hives)");
                    continue;
                }
                using var clsids = root.OpenSubKey(@"Software\Classes\CLSID");
                if (clsids is null)
                {
                    sink.Completed(Phase, check, $"profile {p.UserName}: no per-user CLSID registrations");
                    continue;
                }
                var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(30));
                foreach (var guid in clsids.GetSubKeyNames())
                {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (!budget.TryConsume()) break;
                    foreach (var serverKind in new[] { "InprocServer32", "LocalServer32" })
                    {
                        using var srv = clsids.OpenSubKey($@"{guid}\{serverKind}");
                        var path = srv?.GetValue(null)?.ToString(); // REG_EXPAND_SZ auto-expanded
                        if (string.IsNullOrWhiteSpace(path)) continue;

                        var uw = UserWritableMatch(ctx, path);
                        if (uw is null) continue;

                        bool overridesMachine;
                        using (var hklm = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{guid}"))
                            overridesMachine = hklm is not null;
                        if (uw.NeedsCorroboration && !overridesMachine) continue; // location alone can't arm this

                        var sev = overridesMachine ? Severity.High : Severity.Possible;
                        var file = ExtractExecutable(path);
                        var fileExists = file is not null && Path.IsPathRooted(file) && File.Exists(file);
                        Emit(sink, ctx, check,
                            $@"HKU\{p.Sid}\Software\Classes\CLSID\{guid}\{serverKind}", $"{path}|{p.Sid}", sev,
                            $"Per-user COM {serverKind} for {guid} ({p.UserName}) points to user-writable path '{path}' " +
                            (overridesMachine
                                ? "and OVERRIDES an existing machine-wide registration (classic COM hijack)."
                                : "(no machine-wide counterpart — review origin).") +
                            (fileExists ? "" : " Server binary not found on disk."),
                            sev >= Severity.High && fileExists ? FixAction.Quarantine : FixAction.None,
                            sev >= Severity.High && fileExists ? file : null,
                            T1546_015, path, false);
                    }
                }
                sink.CompleteOrInconclusive(Phase, check, budget, $"profile {p.UserName}");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.Message}"); }
        }
    }

    // =====================================================================================
    // PERS-008 — Browser extensions (Chrome/Edge manifests, Firefox extensions.json). FULL.
    // =====================================================================================

    private void CheckBrowserExtensions(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-008 Browser extensions";
        if (ctx.Depth < ScanDepth.Full)
        {
            sink.Skipped(Phase, check, "requires FULL depth");
            return;
        }

        foreach (var p in ctx.Profiles)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            try
            {
                var budget = ctx.CreateBudget(600, TimeSpan.FromSeconds(20));
                var parseFailures = 0;

                foreach (var (browser, userData) in new[]
                {
                    ("Chrome", Path.Combine(p.ProfilePath, @"AppData\Local\Google\Chrome\User Data")),
                    ("Edge", Path.Combine(p.ProfilePath, @"AppData\Local\Microsoft\Edge\User Data")),
                })
                {
                    if (!Directory.Exists(userData)) continue;
                    foreach (var bp in Directory.EnumerateDirectories(userData)
                                 .Where(d => Path.GetFileName(d) is "Default" || Path.GetFileName(d).StartsWith("Profile ", StringComparison.OrdinalIgnoreCase)))
                    {
                        var extRoot = Path.Combine(bp, "Extensions");
                        if (!Directory.Exists(extRoot)) continue;
                        foreach (var idDir in Directory.EnumerateDirectories(extRoot))
                        {
                            ctx.Cancel.ThrowIfCancellationRequested();
                            if (!budget.TryConsume()) break;
                            if (!AnalyzeChromiumExtension(ctx, sink, check, browser, p, idDir)) parseFailures++;
                        }
                        if (budget.Exhausted) break;
                    }
                    if (budget.Exhausted) break;
                }

                if (!budget.Exhausted)
                    AnalyzeFirefoxExtensions(ctx, sink, check, p, budget, ref parseFailures);

                sink.CompleteOrInconclusive(Phase, check, budget,
                    $"profile {p.UserName}" + (parseFailures > 0 ? $" ({parseFailures} unreadable manifest(s))" : ""));
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.Message}"); }
        }
    }

    /// <summary>Returns false when no manifest under the extension dir could be parsed.</summary>
    private bool AnalyzeChromiumExtension(ScanContext ctx, IFindingSink sink, string check,
        string browser, ZeroBreach.Core.Profiles.UserProfile p, string idDir)
    {
        var extId = Path.GetFileName(idDir);
        var parsedAny = false;
        foreach (var verDir in Directory.EnumerateDirectories(idDir))
        {
            var manifest = Path.Combine(verDir, "manifest.json");
            if (!File.Exists(manifest) || new FileInfo(manifest).Length > 256 * 1024) continue;

            string name;
            var perms = new List<string>();
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
                var rootEl = doc.RootElement;
                name = rootEl.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString()! : extId;
                if (name.StartsWith("__MSG_", StringComparison.OrdinalIgnoreCase)) name = extId;
                foreach (var prop in new[] { "permissions", "host_permissions", "optional_permissions" })
                    if (rootEl.TryGetProperty(prop, out var arr) && arr.ValueKind == JsonValueKind.Array)
                        foreach (var el in arr.EnumerateArray())
                            if (el.ValueKind == JsonValueKind.String)
                                perms.Add(el.GetString()!);
            }
            catch { continue; }
            parsedAny = true;

            var badId = ctx.Signatures.Set("persistence.browser_extension_bad_ids").FirstOrDefault(e => e.Matches(extId));
            var flagEntries = ctx.Signatures.Set("persistence.browser_permission_flags");
            var matched = perms.SelectMany(perm => flagEntries.Where(e => e.Matches(perm))
                    .Select(e => (perm, e))).ToList();
            var allUrls = matched.Any(m => m.perm is "<all_urls>" or "*://*/*");
            var otherRisk = matched.Count(m => m.e.Severity >= Severity.Possible && m.perm is not ("<all_urls>" or "*://*/*"));

            if (badId is not null)
            {
                Emit(sink, ctx, check, manifest, $"{extId}|{p.Sid}",
                    badId.NeedsCorroboration ? Severity.Possible : Severity.High,
                    $"{browser} extension '{name}' ({extId}, {p.UserName}) matches known-bad extension ID list ({badId.Note ?? badId.Pattern}).",
                    FixAction.None, null, badId.Mitre ?? T1176, name, false);
            }
            else if (allUrls && otherRisk >= 1)
            {
                var permText = string.Join(", ", matched.Select(m => $"{m.perm} ({m.e.Note})").Distinct());
                Emit(sink, ctx, check, manifest, $"{extId}|{p.Sid}", Severity.Possible,
                    $"{browser} extension '{name}' ({extId}, {p.UserName}) holds broad permissions: {Trunc(permText, 220)} — review whether this extension is expected.",
                    FixAction.None, null, T1176, name, false);
            }
            break; // one version dir is enough for identity/permissions
        }
        return parsedAny || !Directory.EnumerateDirectories(idDir).Any();
    }

    private void AnalyzeFirefoxExtensions(ScanContext ctx, IFindingSink sink, string check,
        ZeroBreach.Core.Profiles.UserProfile p, EnumerationBudget budget, ref int parseFailures)
    {
        var profilesDir = Path.Combine(p.ProfilePath, @"AppData\Roaming\Mozilla\Firefox\Profiles");
        if (!Directory.Exists(profilesDir)) return;
        foreach (var ffProfile in Directory.EnumerateDirectories(profilesDir))
        {
            var extFile = Path.Combine(ffProfile, "extensions.json");
            if (!File.Exists(extFile) || new FileInfo(extFile).Length > 20 * 1024 * 1024) continue;
            if (!budget.TryConsume()) return;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(extFile));
                if (!doc.RootElement.TryGetProperty("addons", out var addons) || addons.ValueKind != JsonValueKind.Array)
                    continue;
                foreach (var addon in addons.EnumerateArray())
                {
                    if (!budget.TryConsume()) return;
                    var id = addon.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "(no id)" : "(no id)";
                    var active = addon.TryGetProperty("active", out var actEl) && actEl.ValueKind == JsonValueKind.True;
                    var location = addon.TryGetProperty("location", out var locEl) ? locEl.GetString() : null;
                    int? signedState = addon.TryGetProperty("signedState", out var ssEl) && ssEl.ValueKind == JsonValueKind.Number
                        ? ssEl.GetInt32() : null;
                    var name = addon.TryGetProperty("defaultLocale", out var dl) &&
                               dl.ValueKind == JsonValueKind.Object &&
                               dl.TryGetProperty("name", out var nEl) ? nEl.GetString() ?? id : id;

                    var badId = ctx.Signatures.Set("persistence.browser_extension_bad_ids").FirstOrDefault(e => e.Matches(id));
                    if (badId is not null)
                    {
                        Emit(sink, ctx, check, extFile, $"{id}|{p.Sid}",
                            badId.NeedsCorroboration ? Severity.Possible : Severity.High,
                            $"Firefox extension '{name}' ({id}, {p.UserName}) matches known-bad extension ID list ({badId.Note ?? badId.Pattern}).",
                            FixAction.None, null, badId.Mitre ?? T1176, name, false);
                    }
                    else if (active && location == "app-profile" && signedState is < 2)
                    {
                        Emit(sink, ctx, check, extFile, $"{id}|{p.Sid}", Severity.Possible,
                            $"Firefox extension '{name}' ({id}, {p.UserName}) is active in the profile but not Mozilla-signed (signedState={signedState}).",
                            FixAction.None, null, T1176, name, false);
                    }
                }
            }
            catch { parseFailures++; }
        }
    }

    // =====================================================================================
    // PERS-009 — Office macro trust, Trusted Locations, Outlook WebView/OTM. FULL.
    // =====================================================================================

    private static readonly string[] OfficeVersions = { "16.0", "15.0", "14.0" };
    private static readonly string[] OfficeApps = { "Word", "Excel", "PowerPoint", "Access", "Publisher", "Outlook" };

    private void CheckOfficeTrust(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-009 Office trust & Outlook";
        if (ctx.Depth < ScanDepth.Full)
        {
            sink.Skipped(Phase, check, "requires FULL depth");
            return;
        }

        foreach (var p in ctx.Profiles)
        {
            ctx.Cancel.ThrowIfCancellationRequested();

            // Filesystem part — walkable regardless of hive state.
            try
            {
                var otm = Path.Combine(p.ProfilePath, @"AppData\Roaming\Microsoft\Outlook\VbaProject.OTM");
                if (File.Exists(otm))
                {
                    // Current-state persistence: the OTM runs at every Outlook start no
                    // matter how old its mtime is, so --since never suppresses it — the
                    // time window only annotates recency (same rule as MAIL-004).
                    var mtime = File.GetLastWriteTimeUtc(otm);
                    var inWindow = ctx.SinceUtc is not null && mtime >= ctx.SinceUtc.Value;
                    // FixAction.None: bare presence is a single weak indicator, and pulling a
                    // user's macro project breaks legitimate macros — operator triage only.
                    Emit(sink, ctx, check, otm, $"otm|{p.Sid}", Severity.Possible,
                        $"Outlook VBA project (VbaProject.OTM) present for {p.UserName}, last modified " +
                        $"{mtime:yyyy-MM-dd}" +
                        (inWindow ? " (inside the scan time window)" : "") +
                        " — Outlook macros execute at startup; confirm the user authored them.",
                        FixAction.None, null, T1137, otm, false);
                }
            }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, check, $"profile {p.UserName}: Outlook OTM check failed: {ex.Message}");
            }

            // Registry part — requires the hive.
            try
            {
                using var root = p.OpenHiveRoot();
                if (root is null)
                {
                    sink.Skipped(Phase, check, $"profile {p.UserName}: hive not mounted (run with --load-hives)");
                    continue;
                }

                foreach (var ver in OfficeVersions)
                {
                    foreach (var app in OfficeApps)
                    {
                        var secPath = $@"Software\Microsoft\Office\{ver}\{app}\Security";
                        using var sec = root.OpenSubKey(secPath);
                        if (sec is null) continue;

                        if (sec.GetValue("VBAWarnings") is int vw && vw == 1)
                            Emit(sink, ctx, check, $@"HKU\{p.Sid}\{secPath}", "VBAWarnings", Severity.High,
                                $"{app} {ver} macro security for {p.UserName} is set to 'Enable all macros' (VBAWarnings=1) — all VBA runs without prompt.",
                                FixAction.None, null, T1137, null, false);

                        if (sec.GetValue("AccessVBOM") is int av && av == 1)
                            Emit(sink, ctx, check, $@"HKU\{p.Sid}\{secPath}", "AccessVBOM", Severity.Possible,
                                $"{app} {ver} for {p.UserName} allows programmatic access to the VBA project object model (AccessVBOM=1) — used by macro droppers to self-modify.",
                                FixAction.None, null, T1137, null, false);

                        using var trusted = root.OpenSubKey($@"{secPath}\Trusted Locations");
                        if (trusted is not null)
                            foreach (var locName in trusted.GetSubKeyNames())
                            {
                                using var loc = trusted.OpenSubKey(locName);
                                var locPath = loc?.GetValue("Path")?.ToString();
                                if (string.IsNullOrWhiteSpace(locPath)) continue;
                                var uw = UserWritableMatch(ctx, Environment.ExpandEnvironmentVariables(locPath));
                                if (uw is null) continue;
                                Emit(sink, ctx, check, $@"HKU\{p.Sid}\{secPath}\Trusted Locations\{locName}", locPath, Severity.Possible,
                                    $"{app} {ver} Trusted Location for {p.UserName} points to user-writable path '{locPath}' ({uw.Note ?? uw.Pattern}) — macros there run without any security prompt.",
                                    FixAction.None, null, T1137, locPath, false);
                            }
                    }

                    // Outlook folder home pages (T1137.004).
                    foreach (var folder in new[] { "Inbox", "Calendar" })
                    {
                        using var wv = root.OpenSubKey($@"Software\Microsoft\Office\{ver}\Outlook\WebView\{folder}");
                        var url = wv?.GetValue("URL")?.ToString();
                        if (string.IsNullOrWhiteSpace(url)) continue;
                        Emit(sink, ctx, check, $@"HKU\{p.Sid}\Software\Microsoft\Office\{ver}\Outlook\WebView\{folder}", "URL", Severity.High,
                            $"Outlook {ver} {folder} home page for {p.UserName} is set to '{Trunc(url, 200)}' — Outlook folder home pages execute script and are a known persistence vector.",
                            FixAction.DeleteRegistryValue,
                            $@"HKU\{p.HiveKeyName}\Software\Microsoft\Office\{ver}\Outlook\WebView\{folder}::URL",
                            T1137_004, url, false);
                    }
                }

                sink.Completed(Phase, check, $"profile {p.UserName} (registry)");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.Message}"); }
        }
    }

    // =====================================================================================
    // PERS-010 — Shell extension / context menu handlers resolving to user-writable DLLs. DEEP.
    // =====================================================================================

    private static readonly string[] ShellHandlerContainers =
    {
        @"*\shellex\ContextMenuHandlers",
        @"*\shellex\PropertySheetHandlers",
        @"Directory\shellex\ContextMenuHandlers",
        @"Directory\Background\shellex\ContextMenuHandlers",
        @"Directory\shellex\DragDropHandlers",
        @"Folder\shellex\ContextMenuHandlers",
        @"Drive\shellex\ContextMenuHandlers",
        @"AllFilesystemObjects\shellex\ContextMenuHandlers",
    };

    private void CheckShellExtensions(ScanContext ctx, IFindingSink sink)
    {
        const string check = "PERS-010 Shell extensions";
        if (ctx.Depth < ScanDepth.Deep)
        {
            sink.Skipped(Phase, check, "requires DEEP depth");
            return;
        }

        var budget = ctx.CreateBudget(3000, TimeSpan.FromSeconds(60));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var container in ShellHandlerContainers)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            if (budget.Exhausted) break;
            using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\{container}");
            if (key is null) continue;
            foreach (var handlerName in key.GetSubKeyNames())
            {
                if (!budget.TryConsume()) break;
                using var handler = key.OpenSubKey(handlerName);
                var clsid = handler?.GetValue(null)?.ToString();
                if (string.IsNullOrWhiteSpace(clsid))
                    clsid = handlerName.StartsWith('{') ? handlerName : null;
                if (clsid is null || !seen.Add(clsid)) continue;
                AnalyzeShellHandlerClsid(ctx, sink, check, container, handlerName, clsid);
            }
        }

        // Icon overlay identifiers + shell service objects (values are CLSIDs too).
        using (var overlays = Registry.LocalMachine.OpenSubKey(
                   @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"))
        {
            if (overlays is not null)
                foreach (var name in overlays.GetSubKeyNames())
                {
                    if (!budget.TryConsume()) break;
                    using var sub = overlays.OpenSubKey(name);
                    var clsid = sub?.GetValue(null)?.ToString();
                    if (string.IsNullOrWhiteSpace(clsid) || !seen.Add(clsid)) continue;
                    AnalyzeShellHandlerClsid(ctx, sink, check, "ShellIconOverlayIdentifiers", name, clsid);
                }
        }
        using (var ssodl = Registry.LocalMachine.OpenSubKey(
                   @"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"))
        {
            if (ssodl is not null)
                foreach (var valueName in ssodl.GetValueNames())
                {
                    if (!budget.TryConsume()) break;
                    var clsid = ssodl.GetValue(valueName)?.ToString();
                    if (string.IsNullOrWhiteSpace(clsid) || !seen.Add(clsid)) continue;
                    AnalyzeShellHandlerClsid(ctx, sink, check, "ShellServiceObjectDelayLoad", valueName, clsid);
                }
        }

        sink.CompleteOrInconclusive(Phase, check, budget, $"{seen.Count} distinct handler CLSID(s)");
    }

    private void AnalyzeShellHandlerClsid(ScanContext ctx, IFindingSink sink, string check,
        string container, string handlerName, string clsid)
    {
        // Resolve in the 64-bit view first, then the WOW6432Node view (32-bit-only handlers
        // register there and would otherwise be invisible to this check).
        string? dll = null;
        var clsidKeyPath = $@"SOFTWARE\Classes\CLSID\{clsid}";
        foreach (var prefix in new[] { @"SOFTWARE\Classes\CLSID\", @"SOFTWARE\Classes\WOW6432Node\CLSID\" })
        {
            using var srv = Registry.LocalMachine.OpenSubKey($@"{prefix}{clsid}\InprocServer32");
            if (srv?.GetValue(null)?.ToString() is { Length: > 0 } resolved) // REG_EXPAND_SZ auto-expanded
            {
                dll = resolved;
                clsidKeyPath = prefix + clsid;
                break;
            }
        }
        if (string.IsNullOrWhiteSpace(dll)) return;

        var uw = UserWritableMatch(ctx, dll);
        var file = ExtractExecutable(dll);
        var fileMissing = file is not null && Path.IsPathRooted(file) && !File.Exists(file);

        if (uw is not null && !uw.NeedsCorroboration)
        {
            Emit(sink, ctx, check, $@"HKLM\{clsidKeyPath}\InprocServer32", container, Severity.High,
                $"Shell extension handler '{handlerName}' ({container}) resolves CLSID {clsid} to user-writable DLL '{dll}' ({uw.Note ?? uw.Pattern}) — loads into Explorer.",
                !fileMissing && file is not null ? FixAction.Quarantine : FixAction.None,
                !fileMissing && file is not null ? file : null,
                T1546_015, dll, false);
        }
        else if (fileMissing)
        {
            Emit(sink, ctx, check, $@"HKLM\{clsidKeyPath}\InprocServer32", container, Severity.Possible,
                $"Shell extension handler '{handlerName}' ({container}) resolves CLSID {clsid} to missing DLL '{dll}' — dangling handler (possible removed payload or hijack staging).",
                FixAction.None, null, T1546_015, dll, false);
        }
    }

    // =====================================================================================
    // Shared helpers
    // =====================================================================================

    /// <summary>Accumulates weighted evidence for one artifact. Info-level notes never arm
    /// a finding by themselves (emit gate requires >= Possible).</summary>
    private sealed class SignalSet
    {
        private Severity _mitreSev = Severity.Info;
        public Severity Severity { get; private set; } = Severity.Info;
        public bool Any { get; private set; }
        public List<string> Reasons { get; } = new();
        public MitreRef? Mitre { get; private set; }
        public string ReasonText => string.Join("; ", Reasons);

        public void Add(Severity sev, string reason, MitreRef? mitre = null)
        {
            Any = true;
            Reasons.Add(reason);
            if (sev > Severity) Severity = sev;
            if (mitre is not null && (Mitre is null || sev >= _mitreSev))
            {
                Mitre = mitre;
                _mitreSev = sev;
            }
        }

        /// <summary>Adds context without arming the finding.</summary>
        public void AddNote(string reason) => Reasons.Add(reason);
    }

    /// <summary>NeedsCorroboration caps an indicator's standalone contribution at POSSIBLE
    /// (guide rule 5).</summary>
    private static Severity CapSeverity(IndicatorEntry e) =>
        e.NeedsCorroboration && e.Severity > Severity.Possible ? Severity.Possible : e.Severity;

    private static void ApplySet(ScanContext ctx, SignalSet sig, string setName, string? input, string prefix)
    {
        if (string.IsNullOrEmpty(input)) return;
        foreach (var e in ctx.Signatures.Set(setName))
        {
            if (!e.Matches(input)) continue;
            sig.Add(CapSeverity(e), $"{prefix}: {e.Note ?? e.Pattern}", e.Mitre);
        }
    }

    private static IndicatorEntry? UserWritableMatch(ScanContext ctx, string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        IndicatorEntry? best = null;
        foreach (var e in ctx.Signatures.Set("persistence.user_writable_paths"))
        {
            if (!e.Matches(path)) continue;
            // Prefer a non-corroboration-required match (e.g. \Temp\ beats \AppData\Local\).
            if (best is null || (best.NeedsCorroboration && !e.NeedsCorroboration)) best = e;
        }
        return best;
    }

    /// <summary>Matches file name/hash against custom IOC sets and the (deliberately empty
    /// until populated) persistence known-bad hash set. Only a known-bad hash match sets
    /// <paramref name="hashConfirmed"/>; custom IOC hits stay POSSIBLE (guide rule 12).</summary>
    private static void ApplyFileIocSignals(ScanContext ctx, SignalSet sig, string filePath, ref bool hashConfirmed)
    {
        var fileName = Path.GetFileName(filePath);
        foreach (var e in ctx.Signatures.Set("custom.filenames"))
            if (e.Matches(fileName))
                sig.Add(Severity.Possible, $"file name matches custom IOC '{e.Pattern}'", e.Mitre);

        var knownBad = ctx.Signatures.Set("persistence.known_bad_hashes");
        var customHashes = ctx.Signatures.Set("custom.hashes");
        if (knownBad.Count == 0 && customHashes.Count == 0) return;

        var sha = FileHasher.Sha256(filePath, 32 * 1024 * 1024);
        if (sha is null) return;
        foreach (var e in knownBad)
            if (e.Matches(sha))
            {
                hashConfirmed = true;
                sig.Add(Severity.Critical, $"SHA-256 matches known-bad set ({e.Note ?? "persistence.known_bad_hashes"})", e.Mitre);
            }
        foreach (var e in customHashes)
            if (e.Matches(sha))
                sig.Add(Severity.Possible, "SHA-256 matches custom IOC hash", e.Mitre);
    }

    private enum AuthenticodeState { Present, Absent, Unknown }

    private static AuthenticodeState CheckAuthenticode(string filePath)
    {
        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(filePath);
            return AuthenticodeState.Present;
        }
        catch (CryptographicException) { return AuthenticodeState.Absent; }
        catch { return AuthenticodeState.Unknown; }
    }

    /// <summary>Adds the Authenticode result as a signal, distinguishing "unsigned" from
    /// "signature could not be checked" (guide rule 15).</summary>
    private static void AddAuthenticodeSignal(SignalSet sig, string filePath, Severity unsignedSev, string context, MitreRef mitre)
    {
        switch (CheckAuthenticode(filePath))
        {
            case AuthenticodeState.Absent:
                sig.Add(unsignedSev, $"no Authenticode signature ({context})", mitre);
                break;
            case AuthenticodeState.Unknown:
                sig.AddNote("Authenticode signature could not be checked (distinct from unsigned)");
                break;
            case AuthenticodeState.Present:
                sig.AddNote("file carries an Authenticode certificate (validity not verified)");
                break;
        }
    }

    /// <summary>Best-effort executable path from a command line (quoted, or longest
    /// existing unquoted prefix, else first token).</summary>
    /// <summary>Best-effort Win32 path for a service/driver ImagePath. Handles the native
    /// forms the service database stores: the \??\ device prefix, \SystemRoot\-relative paths,
    /// and paths relative to System32 (how most drivers are registered). Returns null when the
    /// form cannot be resolved confidently — a guess would produce false "missing binary"
    /// findings, which is worse than no finding.</summary>
    internal static string? ResolveServiceImage(string raw, string windir)
    {
        var s = Environment.ExpandEnvironmentVariables(raw.Trim()).Trim().Trim('"');
        if (s.Length == 0) return null;
        if (s.Contains('%')) return null;               // an env var that did not expand

        if (s.StartsWith(@"\??\", StringComparison.Ordinal)) s = s[4..];
        if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            s = Path.Combine(windir, s[12..]);   // len(@"\SystemRoot\") == 12
        else if (s.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase))
            s = Path.Combine(Path.GetPathRoot(windir) ?? @"C:\", s[1..]);
        else if (!Path.IsPathRooted(s))
            s = Path.Combine(windir, "System32", s);    // driver paths are System32-relative

        try { return Path.GetFullPath(s); }
        catch { return null; }
    }

    /// <summary>True for a local, fixed-disk image path worth asserting existence about.
    /// Network paths are excluded: an unreachable share must not read as a deleted binary.</summary>
    internal static bool LooksLikeLocalImage(string path)
    {
        if (!Path.IsPathRooted(path)) return false;
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return false;   // UNC
        var ext = Path.GetExtension(path);
        return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);
    }

    private static string? ExtractExecutable(string commandLine)
    {
        var s = Environment.ExpandEnvironmentVariables(commandLine.Trim()).Trim();
        if (s.Length == 0) return null;
        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            return end > 1 ? s[1..end] : s.Trim('"');
        }
        var parts = s.Split(' ');
        string? best = null;
        var acc = "";
        for (var i = 0; i < parts.Length && i < 8; i++)
        {
            acc = i == 0 ? parts[0] : $"{acc} {parts[i]}";
            if (File.Exists(acc)) best = acc;
            else if (File.Exists(acc + ".exe")) best = acc + ".exe";
        }
        if (best is not null) return best;
        return parts[0].Length == 0 ? null : parts[0];
    }

    /// <summary>Resolves a .lnk via the WScript.Shell COM object (read-only). Returns
    /// resolved=false when COM is unavailable or the shortcut is unreadable.</summary>
    private static (string? Target, string? Args, bool Resolved) ResolveShortcut(string lnkPath)
    {
        object? shell = null, shortcut = null;
        try
        {
            var t = Type.GetTypeFromProgID("WScript.Shell");
            if (t is null) return (null, null, false);
            shell = Activator.CreateInstance(t);
            if (shell is null) return (null, null, false);
            shortcut = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
            if (shortcut is null) return (null, null, false);
            var st = shortcut.GetType();
            var target = st.InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, null) as string;
            var args = st.InvokeMember("Arguments", BindingFlags.GetProperty, null, shortcut, null) as string;
            return (target, args, true);
        }
        catch
        {
            return (null, null, false);
        }
        finally
        {
            if (shortcut is not null) Marshal.ReleaseComObject(shortcut);
            if (shell is not null) Marshal.ReleaseComObject(shell);
        }
    }

    private static string? Prop(ManagementBaseObject mo, string name)
    {
        try { return mo[name]?.ToString(); }
        catch (ManagementException) { return null; }
    }

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    /// <summary>The HKLM registry views to walk. On a 64-bit OS the 32-bit view is a
    /// physically distinct key (WOW6432Node) and must be walked separately; on a 32-bit OS
    /// both views resolve to the SAME key, so walking "both" would double-report every hit.
    /// The bool is "this view is WOW-redirected" — feed it to <see cref="PhysicalLmPath"/>.</summary>
    private static IEnumerable<(RegistryView View, string Label, bool Wow)> LmViews()
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            yield return (RegistryView.Registry32, "native", false);
            yield break;
        }
        yield return (RegistryView.Registry64, "64-bit", false);
        yield return (RegistryView.Registry32, "32-bit", true);
    }

    /// <summary>Rewrites an HKLM subkey path to the PHYSICAL key the given view reads, so a
    /// finding's Target/FixParam addresses the real location regardless of this process's
    /// bitness. Only SOFTWARE\ is WOW-redirected; other roots are shared between views.</summary>
    private static string PhysicalLmPath(string subPath, bool wow)
    {
        const string software = @"Software\";
        if (!wow || !subPath.StartsWith(software, StringComparison.OrdinalIgnoreCase))
            return subPath;
        // Keep the caller's casing of the SOFTWARE prefix; only splice the node in.
        return string.Concat(subPath[..software.Length], @"WOW6432Node\", subPath[software.Length..]);
    }

    private void Emit(IFindingSink sink, ScanContext ctx, string check, string target, string discriminator,
        Severity sev, string description, FixAction fix, string? fixParam, MitreRef? mitre,
        string? vendorTrustCandidate, bool hashConfirmed)
    {
        sink.Report(new Finding
        {
            Id = Finding.ComputeId(Group, target, discriminator),
            Severity = sev,
            Description = description,
            Target = target,
            FixAction = fix,
            FixParam = fixParam,
            Mitre = mitre,
            Group = Group,
            VendorTrusted = ctx.Signatures.IsVendorTrusted(vendorTrustCandidate),
            HashConfirmed = hashConfirmed,
            Check = check,
        });
    }
}
