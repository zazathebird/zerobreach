// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). Scythe is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.Diagnostics.Eventing.Reader;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;
using Scythe.Core.Model;
using Scythe.Core.Scanning;
using Scythe.Core.Signatures;

namespace Scythe.Scanners;

/// <summary>
/// Phase 5 — Ransomware Indicators (spec §3 "Ransomware indicators").
/// Checks: RANS-001 ransom notes, RANS-002 known extension renames, RANS-003 entropy
/// anomaly (FULL+), RANS-004 shadow-copy/recovery tampering, RANS-005 WinRE state,
/// RANS-006 mass-modification signal (DEEP).
/// Strictly read-only. Nothing in this phase ever carries an executable fix for
/// shadow-copy or recovery state — see the RANS-004 region comment and spec §6.8.
/// </summary>
public sealed class RansomwareScanner : IScanner
{
    public int Phase => 5;
    public string Name => "Ransomware Indicators";
    public string Group => "Ransomware";
    public ScanDepth MinDepth => ScanDepth.Quick;

    private const string Rans1 = "RANS-001 ransom notes";
    private const string Rans2 = "RANS-002 known extension renames";
    private const string Rans3 = "RANS-003 entropy anomaly";
    private const string Rans4Events = "RANS-004 recovery tampering (Security 4688)";
    private const string Rans4Ps = "RANS-004 recovery tampering (PowerShell 4104)";
    private const string Rans4Tasks = "RANS-004 recovery tampering (scheduled tasks)";
    private const string Rans4Services = "RANS-004 recovery tampering (service ImagePath)";
    private const string Rans4Shadow = "RANS-004 shadow copy state";
    private const string Rans4Bcd = "RANS-004 BCD recovery state";
    private const string Rans5 = "RANS-005 recovery environment (WinRE)";
    private const string Rans6 = "RANS-006 mass modification";

    private static readonly MitreRef MitreEncrypt = new("T1486", "Data Encrypted for Impact", "Impact");
    private static readonly MitreRef MitreInhibit = new("T1490", "Inhibit System Recovery", "Impact");

    private const int NoteContentReadBytes = 8 * 1024;      // bounded note-content read
    private const int EntropyPrefixBytes = 32 * 1024;       // bounded entropy sample read
    private const double EntropyHighThreshold = 7.5;        // bits/byte ≈ near-random
    private const int EntropySampleFloor = 20;              // below this the check has no verdict
    private const int EntropyMaxSamples = 240;              // per profile, across its roots
    private const int ExtMeaningfulCount = 3;               // RANS-002 "meaningful count"

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        var sigs = LoadSigs(ctx);
        var ev = new Evidence();

        // Per-profile walks: RANS-001/002 always, RANS-003 at FULL+, RANS-006 at DEEP.
        ScanUserRoots(ctx, sink, sigs, ev);
        ScanDriveRoots(ctx, sink, sigs, ev);
        if (ctx.Depth < ScanDepth.Full)
            sink.Skipped(Phase, Rans3, "entropy sampling requires FULL or DEEP scan depth");
        if (ctx.Depth < ScanDepth.Deep)
            sink.Skipped(Phase, Rans6, "mass-modification counting requires DEEP scan depth");

        // RANS-004 — evidence of recovery tampering (runs after the walks so state checks
        // can reference command evidence, and RANS-005 last so it can corroborate).
        ScanProcessCreationEvents(ctx, sink, sigs, ev);
        ScanPowerShellScriptBlocks(ctx, sink, sigs, ev);
        ScanScheduledTaskActions(ctx, sink, sigs, ev);
        ScanServiceImagePaths(ctx, sink, sigs, ev);
        CheckShadowCopyState(ctx, sink, ev);
        CheckBcdRecoveryState(ctx, sink, ev);

        // RANS-005 — last, so any Phase 5 evidence gathered above can escalate it.
        CheckWinReState(ctx, sink, ev);
    }

    // ==================================================================================
    // RANS-001 / RANS-002 / RANS-003 / RANS-006 — per-profile document-root walks
    // ==================================================================================

    private void ScanUserRoots(ScanContext ctx, IFindingSink sink, Sigs sigs, Evidence ev)
    {
        var entropyDepth = ctx.Depth >= ScanDepth.Full;
        var massModDepth = ctx.Depth >= ScanDepth.Deep;

        if (!sigs.NotesLoaded)
            sink.Inconclusive(Phase, Rans1, "signature set ransomware.ransom_note_patterns is empty — signature data failed to load, note filename checks could not run");
        if (!sigs.ExtsLoaded)
            sink.Inconclusive(Phase, Rans2, "signature set ransomware.known_ransom_extensions is empty — signature data failed to load");

        foreach (var p in ctx.Profiles)
        {
            try
            {
                var roots = new[] { "Documents", "Desktop", "Downloads" }
                    .Select(r => Path.Combine(p.ProfilePath, r))
                    .Where(Directory.Exists)
                    .ToArray();
                var scope = $"profile {p.UserName}";

                if (roots.Length == 0)
                {
                    if (sigs.NotesLoaded) sink.Skipped(Phase, Rans1, $"{scope}: no Documents/Desktop/Downloads roots under {p.ProfilePath}");
                    if (sigs.ExtsLoaded) sink.Skipped(Phase, Rans2, $"{scope}: no document roots to walk");
                    if (entropyDepth) sink.Skipped(Phase, Rans3, $"{scope}: no document roots to sample");
                    if (massModDepth) sink.Skipped(Phase, Rans6, $"{scope}: no document roots to walk");
                    continue;
                }

                // Fresh budget PER PROFILE (spec §4 — never shared across profiles).
                var budget = ctx.CreateBudget(5000, TimeSpan.FromSeconds(20));
                var state = new WalkState();

                foreach (var root in roots)
                {
                    if (budget.Exhausted) break;
                    WalkRoot(ctx, sink, sigs, state, budget, root, ownerTag: p.Sid, maxDepth: 4,
                        sampleEntropy: entropyDepth, recordModTimes: massModDepth);
                }

                EmitExtensionFindings(sink, state, ev);
                if (state.NoteFoundConfirmed) ev.NoteConfirmed = true;

                var scopeDetail = $"{scope}: {state.FilesSeen} files across {roots.Length} root(s)";
                if (sigs.NotesLoaded) ReportWalkStatus(sink, Rans1, budget, state, scopeDetail);
                if (sigs.ExtsLoaded) ReportWalkStatus(sink, Rans2, budget, state, scopeDetail);
                if (entropyDepth) EmitEntropyResult(sink, p.ProfilePath, p.Sid, p.UserName, state, budget);
                if (massModDepth) EmitMassModResult(sink, p.ProfilePath, p.Sid, p.UserName, state, budget, ev);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                // Every sub-check that depended on this profile's walk must surface the
                // failure (spec §6.7) — not just the filename checks.
                sink.Inconclusive(Phase, Rans1, $"profile {p.UserName}: walk failed: {ex.Message}");
                sink.Inconclusive(Phase, Rans2, $"profile {p.UserName}: walk failed: {ex.Message}");
                if (entropyDepth) sink.Inconclusive(Phase, Rans3, $"profile {p.UserName}: walk failed: {ex.Message}");
                if (massModDepth) sink.Inconclusive(Phase, Rans6, $"profile {p.UserName}: walk failed: {ex.Message}");
            }
        }
    }

    /// <summary>Ransom notes are frequently dropped at drive roots too — walk the top
    /// level of each fixed drive (name/extension checks only, own budget per drive).</summary>
    private void ScanDriveRoots(ScanContext ctx, IFindingSink sink, Sigs sigs, Evidence ev)
    {
        if (!sigs.NotesLoaded && !sigs.ExtsLoaded) return; // already reported Inconclusive once

        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                var root = d.RootDirectory.FullName;

                var budget = ctx.CreateBudget(500, TimeSpan.FromSeconds(5));
                var state = new WalkState();
                WalkRoot(ctx, sink, sigs, state, budget, root, ownerTag: "drive-root", maxDepth: 0,
                    sampleEntropy: false, recordModTimes: false);

                EmitExtensionFindings(sink, state, ev);
                if (state.NoteFoundConfirmed) ev.NoteConfirmed = true;

                if (sigs.NotesLoaded) ReportWalkStatus(sink, Rans1, budget, state, $"drive root {root} (top level, {state.FilesSeen} files)");
                if (sigs.ExtsLoaded) ReportWalkStatus(sink, Rans2, budget, state, $"drive root {root} (top level)");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                sink.Inconclusive(Phase, Rans1, $"drive root {d.Name}: walk failed: {ex.Message}");
                sink.Inconclusive(Phase, Rans2, $"drive root {d.Name}: walk failed: {ex.Message}");
            }
        }
    }

    private void WalkRoot(ScanContext ctx, IFindingSink sink, Sigs sigs, WalkState state,
        EnumerationBudget budget, string root, string ownerTag, int maxDepth,
        bool sampleEntropy, bool recordModTimes)
    {
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((root, 0));

        while (stack.Count > 0 && !budget.Exhausted)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            var (dir, depth) = stack.Pop();

            foreach (var file in SafeList(() => Directory.EnumerateFiles(dir), state))
            {
                if (!budget.TryConsume()) return;
                ctx.Cancel.ThrowIfCancellationRequested();
                ProcessFile(ctx, sink, sigs, state, root, ownerTag, file, sampleEntropy, recordModTimes);
            }

            if (depth >= maxDepth) continue;
            foreach (var sub in SafeList(() => Directory.EnumerateDirectories(dir), state))
            {
                // Skip reparse points: avoids junction cycles and the legacy per-profile
                // compat junctions ("My Music" etc.) that deny listing by design.
                try
                {
                    if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch { state.DeniedDirs++; continue; }
                stack.Push((sub, depth + 1));
            }
        }
    }

    private void ProcessFile(ScanContext ctx, IFindingSink sink, Sigs sigs, WalkState state,
        string root, string ownerTag, string file, bool sampleEntropy, bool recordModTimes)
    {
        state.FilesSeen++;
        var name = Path.GetFileName(file);
        var ext = Path.GetExtension(file).ToLowerInvariant();

        DateTime? lastWrite = null;
        var haveTime = false;
        DateTime? LastWrite()
        {
            if (!haveTime)
            {
                haveTime = true;
                try { lastWrite = File.GetLastWriteTimeUtc(file); } catch { lastWrite = null; }
            }
            return lastWrite;
        }
        // Unreadable timestamps count as in-window: flagging is non-destructive, so err
        // toward looking rather than silently skipping (spec §6.7 spirit).
        bool InWindow() => LastWrite() is not DateTime t || ctx.WithinTimeWindow(t);

        // RANS-001 — ransom note filename patterns (+ bounded content corroboration).
        var noteEntry = FirstMatch(sigs.NotePatterns, name);
        if (noteEntry is not null && InWindow())
        {
            var text = ReadTextPrefix(file, NoteContentReadBytes);
            var markers = text is null
                ? new List<IndicatorEntry>()
                : sigs.NoteMarkers.Where(m => m.Matches(text)).ToList();
            var critical = markers.Count > 0;

            state.NoteFoundAny = true;
            if (critical) state.NoteFoundConfirmed = true;

            var markerDesc = critical
                ? string.Join(", ", markers.Select(m => m.Note ?? m.Pattern).Distinct().Take(3))
                : "";
            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, file, $"RANS-001:{ownerTag}"),
                Severity = critical ? Severity.Critical : Severity.Possible,
                Description = critical
                    ? $"Ransom note: filename matches pattern '{noteEntry.Pattern}' ({noteEntry.Note}) AND the first {NoteContentReadBytes / 1024} KB contain note-like content ({markerDesc}). " +
                      "This file is EVIDENCE — preserve it unmodified for the insurer / IR firm; it typically also contains the attacker's victim ID needed for any recovery discussion. Do not delete."
                    : $"Filename matches ransom-note pattern '{noteEntry.Pattern}' ({noteEntry.Note}), but no note-like content markers matched in the first {NoteContentReadBytes / 1024} KB" +
                      (text is null ? " (file content could not be read)" : "") +
                      ". Review by hand; if it is a ransom note, preserve it as evidence for the insurer / IR firm.",
                Target = file,
                FixAction = FixAction.None, // notes are evidence, never remediation targets
                Mitre = noteEntry.Mitre ?? MitreEncrypt,
                Group = Group,
                Check = Rans1,
            });
        }

        // RANS-002 — known ransomware extension: count per (extension, root), aggregate later.
        if (ext.Length > 1 && sigs.Extensions.TryGetValue(ext, out var extEntry) && InWindow())
        {
            var key = root + "|" + ext;
            if (state.ExtHits.TryGetValue(key, out var hit)) hit.Count++;
            else state.ExtHits[key] = new ExtHit { Entry = extEntry, Root = root, Ext = ext, Count = 1, ExampleFile = file };
        }

        // Custom filename IOCs (spec §6.6 / guide rule 12): POSSIBLE, never auto-actioned.
        var ioc = FirstMatch(sigs.CustomFilenames, name);
        if (ioc is not null && InWindow())
        {
            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, file, $"RANS-001:ioc:{ownerTag}:{ioc.Pattern}"),
                Severity = Severity.Possible,
                Description = $"File name matches operator-supplied IOC '{ioc.Pattern}' ({ioc.Note}). " +
                              "Custom-IOC hits are advisory only and are never auto-actioned — confirm relevance by hand.",
                Target = file,
                FixAction = FixAction.None,
                Group = Group,
                Check = Rans1,
            });
        }

        // RANS-003 — entropy sampling of normally-low-entropy file types (FULL+).
        if (sampleEntropy && state.EntropySampled < EntropyMaxSamples &&
            ext.Length > 1 && sigs.EntropyExtensions.Contains(ext) && InWindow())
        {
            var h = SampleEntropy(file);
            if (h is not null)
            {
                state.EntropySampled++;
                if (h.Value >= EntropyHighThreshold) state.EntropyHigh++;
            }
        }

        // RANS-006 — modification-time collection (DEEP).
        if (recordModTimes && LastWrite() is DateTime mt && ctx.WithinTimeWindow(mt))
            state.ModTimesUtc.Add(mt);
    }

    private void EmitExtensionFindings(IFindingSink sink, WalkState state, Evidence ev)
    {
        foreach (var hit in state.ExtHits.Values)
        {
            var corroborated = state.NoteFoundAny;
            var meaningful = hit.Count >= ExtMeaningfulCount;

            Severity sev;
            if (hit.Entry.NeedsCorroboration && !corroborated) sev = Severity.Possible; // guide rule 5
            else if (meaningful) sev = hit.Entry.Severity;
            else sev = Severity.Possible;

            if (sev == Severity.Critical) state.ExtCritical = true;
            if (sev >= Severity.High) ev.ExtensionEvidence = true;

            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, hit.Root, $"RANS-002:{hit.Ext}"),
                Severity = sev,
                Description = $"{hit.Count} file(s) under '{hit.Root}' carry the ransomware-associated extension '{hit.Ext}' ({hit.Entry.Note}); e.g. '{hit.ExampleFile}'. " +
                              "Aggregate finding (one per extension per root, not one per file). Encrypted files are evidence and potentially recoverable — no automatic action is offered." +
                              (hit.Entry.NeedsCorroboration && !corroborated
                                  ? " This extension is also produced by legitimate software and no ransom note was found alongside it — treat as needs-review."
                                  : ""),
                Target = hit.Root,
                FixAction = FixAction.None,
                Mitre = hit.Entry.Mitre ?? MitreEncrypt,
                Group = Group,
                Check = Rans2,
            });
        }
    }

    private void EmitEntropyResult(IFindingSink sink, string profilePath, string sid, string userName,
        WalkState state, EnumerationBudget budget)
    {
        var sampled = state.EntropySampled;
        var high = state.EntropyHigh;

        if (sampled < EntropySampleFloor && budget.Exhausted)
        {
            // Catalog rule: sample below floor because the budget ran out first → Inconclusive, never clean.
            sink.Inconclusive(Phase, Rans3,
                $"profile {userName}: only {sampled} file(s) sampled before the walk budget ran out ({budget.ExhaustedReason}) — below the {EntropySampleFloor}-sample floor, no verdict");
            return;
        }

        if (sampled >= EntropySampleFloor)
        {
            var frac = (double)high / sampled;
            if (frac >= 0.4 && high >= 8)
            {
                // High entropy alone is a STATISTICAL indicator → POSSIBLE; only a ransom
                // note or a known-extension hit in the same profile makes it CRITICAL.
                var corroborated = state.NoteFoundConfirmed || state.ExtCritical;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, profilePath, $"RANS-003:{sid}"),
                    Severity = corroborated ? Severity.Critical : Severity.Possible,
                    Description = $"Entropy anomaly (statistical indicator, not proof): of {sampled} sampled files with normally-low-entropy extensions (.txt/.csv/.rtf/.sql/.log) under this profile's document roots, " +
                                  $"{high} ({frac:P0}) are near-random (Shannon entropy ≥ {EntropyHighThreshold} bits/byte over the first {EntropyPrefixBytes / 1024} KB) — consistent with bulk file encryption." +
                                  (corroborated
                                      ? " Corroborated by a ransom note / known ransomware extension found in the same profile."
                                      : " No corroborating note or extension rename was found — could also be compressed or already-encrypted data stored with a text extension; review by hand."),
                    Target = profilePath,
                    FixAction = FixAction.None,
                    Mitre = MitreEncrypt,
                    Group = Group,
                    Check = Rans3,
                });
            }
        }

        if (budget.Exhausted)
            sink.Inconclusive(Phase, Rans3, $"profile {userName}: walk cut short ({budget.ExhaustedReason}); sampled {sampled}, {high} near-random");
        else if (sampled < EntropySampleFloor)
            sink.Completed(Phase, Rans3, $"profile {userName}: only {sampled} eligible file(s) exist — below the {EntropySampleFloor}-sample floor, no signal either way");
        else
            sink.Completed(Phase, Rans3, $"profile {userName}: sampled {sampled}, {high} near-random");
    }

    private void EmitMassModResult(IFindingSink sink, string profilePath, string sid, string userName,
        WalkState state, EnumerationBudget budget, Evidence ev)
    {
        var times = state.ModTimesUtc;
        if (times.Count >= 50)
        {
            times.Sort();
            int best = 0, j = 0;
            var bestStart = times[0];
            var window = TimeSpan.FromMinutes(10);
            for (var i = 0; i < times.Count; i++)
            {
                while (times[i] - times[j] > window) j++;
                var cnt = i - j + 1;
                if (cnt > best) { best = cnt; bestStart = times[j]; }
            }

            if (best >= 150 && best >= times.Count * 0.3)
            {
                var otherEvidence = state.NoteFoundAny || state.ExtHits.Count > 0 || ev.Strong;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, profilePath, $"RANS-006:{sid}"),
                    Severity = otherEvidence ? Severity.High : Severity.Possible,
                    Description = $"Mass-modification signal (aggregate, statistical): {best} of {times.Count} walked files under this profile's document roots were modified within a single 10-minute span starting {bestStart:u} — " +
                                  "a burst pattern consistent with bulk encryption." +
                                  (otherEvidence
                                      ? " Other Phase 5 ransomware evidence was found in this scan, which strengthens this signal."
                                      : " No other ransomware evidence was found — large legitimate operations (sync clients, restores, archive extraction) also produce this pattern; review by hand."),
                    Target = profilePath,
                    FixAction = FixAction.None,
                    Mitre = MitreEncrypt,
                    Group = Group,
                    Check = Rans6,
                });
            }
        }

        if (budget.Exhausted)
            sink.Inconclusive(Phase, Rans6, $"profile {userName}: walk cut short ({budget.ExhaustedReason}); modification-rate count incomplete");
        else
            sink.Completed(Phase, Rans6, $"profile {userName}: {times.Count} file timestamps considered");
    }

    // ==================================================================================
    // RANS-004 — shadow copy / recovery tampering.
    //
    // DO NOT ADD AN EXECUTABLE FIX TO ANY FINDING IN THIS REGION. Spec §3 (Ransomware
    // bullet) and §6.8 call this out BY NAME: shadow-copy manipulation and recovery
    // re-enable/delete commands are Info-only, operator-run-BY-HAND, never scriptable in
    // one click. Every finding below must use FixAction.None or FixAction.RunCommand
    // (RunCommand is display-only — the engine refuses to execute it in every code path,
    // including remediation batches, and it must always be Severity.Info). If you came
    // here to "helpfully" wire a one-click fix for these findings: that is exactly the
    // change the spec forbids. Don't.
    // ==================================================================================

    private void ScanProcessCreationEvents(ScanContext ctx, IFindingSink sink, Sigs sigs, Evidence ev)
    {
        try
        {
            if (sigs.TamperCommands.Count == 0)
            {
                sink.Inconclusive(Phase, Rans4Events, "signature set ransomware.recovery_tamper_commands is empty — signature data failed to load");
                return;
            }

            // Coverage precondition: without this policy, 4688 events carry no command line.
            var cmdLineAudit = false;
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"))
                cmdLineAudit = k?.GetValue("ProcessCreationIncludeCmdLine_Enabled") is int v && v == 1;

            var since = EventWindowStart(ctx);
            var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(15));
            var hits = ScanEventChannel(ctx, sigs, budget, "Security", 4688, "CommandLine", since);
            EmitTamperEventFindings(sink, ev, hits, "EventLog:Security", "4688 process-creation", since, Rans4Events);

            if (!cmdLineAudit)
                sink.Inconclusive(Phase, Rans4Events,
                    "process-creation command-line auditing (ProcessCreationIncludeCmdLine_Enabled) is not on — 4688 events carry no command lines, so absence of matches is not evidence of absence");
            else
                sink.CompleteOrInconclusive(Phase, Rans4Events, budget, $"Security 4688 since {since:u} ({budget.Consumed} events)");
        }
        catch (OperationCanceledException) { throw; }
        catch (UnauthorizedAccessException)
        {
            sink.Inconclusive(Phase, Rans4Events, "access denied reading the Security event log (run elevated)");
        }
        catch (EventLogException ex)
        {
            sink.Inconclusive(Phase, Rans4Events, $"Security event log unreadable: {ex.Message}");
        }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, Rans4Events, $"check crashed: {ex.Message}");
        }
    }

    private void ScanPowerShellScriptBlocks(ScanContext ctx, IFindingSink sink, Sigs sigs, Evidence ev)
    {
        const string channel = "Microsoft-Windows-PowerShell/Operational";
        try
        {
            if (sigs.TamperCommands.Count == 0)
            {
                sink.Inconclusive(Phase, Rans4Ps, "signature set ransomware.recovery_tamper_commands is empty — signature data failed to load");
                return;
            }

            var sblEnabled = false;
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"))
                sblEnabled = k?.GetValue("EnableScriptBlockLogging") is int v && v == 1;

            var since = EventWindowStart(ctx);
            var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(15));
            var hits = ScanEventChannel(ctx, sigs, budget, channel, 4104, "ScriptBlockText", since);
            EmitTamperEventFindings(sink, ev, hits, $"EventLog:{channel}", "4104 script-block", since, Rans4Ps);

            if (!sblEnabled)
                sink.Inconclusive(Phase, Rans4Ps,
                    $"PowerShell script-block logging is not enabled by policy — only auto-logged 'suspicious' blocks reach {channel}, so coverage is partial");
            else
                sink.CompleteOrInconclusive(Phase, Rans4Ps, budget, $"{channel} 4104 since {since:u} ({budget.Consumed} events)");
        }
        catch (OperationCanceledException) { throw; }
        catch (UnauthorizedAccessException)
        {
            sink.Inconclusive(Phase, Rans4Ps, $"access denied reading {channel} (run elevated)");
        }
        catch (EventLogNotFoundException)
        {
            sink.Inconclusive(Phase, Rans4Ps, $"event channel {channel} not found on this machine");
        }
        catch (EventLogException ex)
        {
            sink.Inconclusive(Phase, Rans4Ps, $"event channel {channel} unreadable: {ex.Message}");
        }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, Rans4Ps, $"check crashed: {ex.Message}");
        }
    }

    private static DateTime EventWindowStart(ScanContext ctx) =>
        ctx.SinceUtc ?? DateTime.UtcNow - (ctx.Depth >= ScanDepth.Full ? TimeSpan.FromDays(30) : TimeSpan.FromDays(7));

    private sealed class TamperHit
    {
        public required IndicatorEntry Entry { get; init; }
        public int Count;
        public required string Example { get; set; }
    }

    private static Dictionary<string, TamperHit> ScanEventChannel(ScanContext ctx, Sigs sigs,
        EnumerationBudget budget, string channel, int eventId, string dataField, DateTime since)
    {
        var hits = new Dictionary<string, TamperHit>(StringComparer.OrdinalIgnoreCase);
        var ms = (long)Math.Max(0, (DateTime.UtcNow - since).TotalMilliseconds);
        var query = new EventLogQuery(channel, PathType.LogName,
            $"*[System[(EventID={eventId}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]")
        { ReverseDirection = true };

        using var reader = new EventLogReader(query);
        while (true)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            using var rec = reader.ReadEvent();
            if (rec is null) break;
            if (!budget.TryConsume()) break;

            string? payload;
            try { payload = ExtractEventData(rec.ToXml(), dataField); }
            catch { continue; }
            if (string.IsNullOrEmpty(payload)) continue;

            foreach (var entry in sigs.TamperCommands)
            {
                if (!entry.Matches(payload)) continue;
                if (hits.TryGetValue(entry.Pattern, out var hit)) hit.Count++;
                else hits[entry.Pattern] = new TamperHit { Entry = entry, Count = 1, Example = payload };
            }
        }
        return hits;
    }

    private void EmitTamperEventFindings(IFindingSink sink, Evidence ev,
        Dictionary<string, TamperHit> hits, string target, string sourceDesc, DateTime since, string check)
    {
        foreach (var hit in hits.Values)
        {
            // needsCorroboration entries (e.g. shadow-storage resize, a legitimate admin
            // operation) are capped at POSSIBLE on their own (guide rule 5).
            var sev = hit.Entry.NeedsCorroboration ? Severity.Possible : hit.Entry.Severity;
            if (sev >= Severity.High) ev.TamperCommandSeen = true;

            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, target, $"RANS-004:{sourceDesc}:{hit.Entry.Pattern}"),
                Severity = sev,
                Description = $"{hit.Count} {sourceDesc} event(s) since {since:u} match recovery-tampering pattern: {hit.Entry.Note}. " +
                              $"Example: \"{Trunc(hit.Example, 300)}\". This is evidence of Inhibit System Recovery (T1490) activity. " +
                              "Verify current shadow-copy/backup state BY HAND (e.g. 'vssadmin list shadows' — read-only). " +
                              "Deliberately no one-click fix: shadow-copy and recovery-state changes are operator-run-by-hand only (spec §6.8).",
                Target = target,
                FixAction = FixAction.None, // NEVER executable here — see region comment
                Mitre = hit.Entry.Mitre ?? MitreInhibit,
                Group = Group,
                Check = check,
            });
        }
    }

    private void ScanScheduledTaskActions(ScanContext ctx, IFindingSink sink, Sigs sigs, Evidence ev)
    {
        try
        {
            if (sigs.TamperCommands.Count == 0)
            {
                sink.Inconclusive(Phase, Rans4Tasks, "signature set ransomware.recovery_tamper_commands is empty — signature data failed to load");
                return;
            }

            var tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (!Directory.Exists(tasksRoot))
            {
                sink.Inconclusive(Phase, Rans4Tasks, $"scheduled task store not found at {tasksRoot}");
                return;
            }

            var budget = ctx.CreateBudget(3000, TimeSpan.FromSeconds(15));
            var state = new WalkState(); // reused only for DeniedDirs counting
            var stack = new Stack<string>();
            stack.Push(tasksRoot);

            while (stack.Count > 0 && !budget.Exhausted)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                var dir = stack.Pop();

                foreach (var file in SafeList(() => Directory.EnumerateFiles(dir), state))
                {
                    if (!budget.TryConsume()) break;
                    var xml = ReadTextPrefix(file, 64 * 1024);
                    if (xml is null) { state.DeniedDirs++; continue; }

                    // Task actions split the command across <Command> and <Arguments>
                    // elements, so a raw-text regex like "vssadmin\s+delete" never sees
                    // "vssadmin.exe delete shadows" contiguously for a direct-exec task.
                    // Match each action's Command+Arguments joined, plus the raw XML as a
                    // fallback for odd schemas / cmd-wrapped one-liners.
                    var haystacks = new List<string> { xml };
                    try
                    {
                        var doc = XDocument.Parse(xml);
                        foreach (var exec in doc.Descendants().Where(e => e.Name.LocalName == "Exec"))
                        {
                            var cmd = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value.Trim() ?? "";
                            var args = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments")?.Value.Trim() ?? "";
                            var joined = (cmd + " " + args).Trim();
                            if (joined.Length > 0) haystacks.Add(joined);
                        }
                    }
                    catch { /* truncated/unparseable XML — the raw-text match above still applies */ }

                    foreach (var entry in sigs.TamperCommands)
                    {
                        if (!haystacks.Any(h => entry.Matches(h))) continue;
                        var sev = entry.NeedsCorroboration ? Severity.Possible : entry.Severity;
                        if (sev >= Severity.High) ev.TamperCommandSeen = true;
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, file, $"RANS-004:task:{entry.Pattern}"),
                            Severity = sev,
                            Description = $"Scheduled task definition contains a recovery-tampering command ({entry.Note}) — a persistent task that inhibits system recovery (T1490). " +
                                          "Review the task by hand ('schtasks /query /xml' or Task Scheduler UI). " +
                                          "Deliberately no one-click fix here: recovery/shadow-copy manipulation is operator-run-by-hand only (spec §6.8).",
                            Target = file,
                            FixAction = FixAction.None, // NEVER executable here — see region comment
                            Mitre = entry.Mitre ?? MitreInhibit,
                            Group = Group,
                            VendorTrusted = ctx.Signatures.IsVendorTrusted(file),
                            Check = Rans4Tasks,
                        });
                    }
                }

                foreach (var sub in SafeList(() => Directory.EnumerateDirectories(dir), state))
                    stack.Push(sub);
            }

            ReportWalkStatus(sink, Rans4Tasks, budget, state, $"{tasksRoot} ({budget.Consumed} task files)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, Rans4Tasks, $"check crashed: {ex.Message}");
        }
    }

    private void ScanServiceImagePaths(ScanContext ctx, IFindingSink sink, Sigs sigs, Evidence ev)
    {
        try
        {
            if (sigs.TamperCommands.Count == 0)
            {
                sink.Inconclusive(Phase, Rans4Services, "signature set ransomware.recovery_tamper_commands is empty — signature data failed to load");
                return;
            }

            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null)
            {
                sink.Inconclusive(Phase, Rans4Services, @"cannot open HKLM\SYSTEM\CurrentControlSet\Services");
                return;
            }

            var budget = ctx.CreateBudget(6000, TimeSpan.FromSeconds(10));
            foreach (var svcName in services.GetSubKeyNames())
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) break;

                string? imagePath;
                try
                {
                    using var sub = services.OpenSubKey(svcName);
                    imagePath = sub?.GetValue("ImagePath") as string;
                }
                catch { continue; }
                if (string.IsNullOrEmpty(imagePath)) continue;

                foreach (var entry in sigs.TamperCommands)
                {
                    if (!entry.Matches(imagePath)) continue;
                    var sev = entry.NeedsCorroboration ? Severity.Possible : entry.Severity;
                    if (sev >= Severity.High) ev.TamperCommandSeen = true;
                    var keyPath = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}";
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, keyPath, $"RANS-004:service:{entry.Pattern}"),
                        Severity = sev,
                        Description = $"Service '{svcName}' ImagePath contains a recovery-tampering command ({entry.Note}): \"{Trunc(imagePath, 300)}\". " +
                                      "A service that inhibits system recovery (T1490) is a strong ransomware-preparation indicator. Review the service by hand. " +
                                      "Deliberately no one-click fix here: recovery/shadow-copy manipulation is operator-run-by-hand only (spec §6.8).",
                        Target = keyPath,
                        FixAction = FixAction.None, // NEVER executable here — see region comment
                        Mitre = entry.Mitre ?? MitreInhibit,
                        Group = Group,
                        VendorTrusted = ctx.Signatures.IsVendorTrusted(imagePath),
                        Check = Rans4Services,
                    });
                }
            }

            sink.CompleteOrInconclusive(Phase, Rans4Services, budget, $"{budget.Consumed} services inspected");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, Rans4Services, $"check crashed: {ex.Message}");
        }
    }

    private void CheckShadowCopyState(ScanContext ctx, IFindingSink sink, Evidence ev)
    {
        try
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            using var searcher = new ManagementObjectSearcher("SELECT ID FROM Win32_ShadowCopy");
            using var results = searcher.Get();
            var count = results.Count; // read-only WMI query

            if (count == 0)
            {
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, "Win32_ShadowCopy", "RANS-004:state:none"),
                    Severity = Severity.Info, // RunCommand findings are always Info (guide rule 6)
                    Description = "No Volume Shadow Copies currently exist on this machine. " +
                                  (ev.TamperCommandSeen
                                      ? "Combined with the shadow-copy/recovery deletion command evidence found in this scan, this is consistent with T1490 recovery inhibition. "
                                      : "This can be normal (System Protection off, or no restore points yet). ") +
                                  "Verify by hand with the read-only command below. Display-only: this engine never executes shadow-copy commands (spec §6.8).",
                    Target = "Win32_ShadowCopy",
                    FixAction = FixAction.RunCommand, // display-only, engine refuses to execute
                    FixParam = "vssadmin list shadows",
                    Mitre = MitreInhibit,
                    Group = Group,
                    Check = Rans4Shadow,
                });
            }

            sink.Completed(Phase, Rans4Shadow, $"{count} shadow cop{(count == 1 ? "y" : "ies")} present");
        }
        catch (ManagementException ex)
        {
            sink.Inconclusive(Phase, Rans4Shadow, $"WMI Win32_ShadowCopy query failed: {ex.Message} — verify by hand with 'vssadmin list shadows' (read-only)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, Rans4Shadow, $"shadow copy state unreadable: {ex.Message} — verify by hand with 'vssadmin list shadows' (read-only)");
        }
    }

    private void CheckBcdRecoveryState(ScanContext ctx, IFindingSink sink, Evidence ev)
    {
        try
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            // Read the system BCD store via its mounted registry hive — read-only; we never
            // shell out to bcdedit and never suggest an executable bcdedit fix (§6.8).
            using var objects = Registry.LocalMachine.OpenSubKey(@"BCD00000000\Objects");
            if (objects is null)
            {
                sink.Inconclusive(Phase, Rans4Bcd, @"BCD registry hive (HKLM\BCD00000000) not accessible — run elevated, or verify by hand with 'bcdedit /enum' (read-only)");
                return;
            }

            var inspected = 0;
            foreach (var guid in objects.GetSubKeyNames())
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                inspected++;

                // Element 16000009 = recoveryenabled (boolean).
                using (var el = objects.OpenSubKey(guid + @"\Elements\16000009"))
                {
                    if (el?.GetValue("Element") is byte[] v && v.Length > 0 && v[0] == 0)
                    {
                        sink.Report(new Finding
                        {
                            Id = Finding.ComputeId(Group, $@"HKLM\BCD00000000\Objects\{guid}", "RANS-004:bcd:recoveryenabled"),
                            Severity = ev.TamperCommandSeen ? Severity.High : Severity.Possible,
                            Description = $"Boot entry {guid} has recovery disabled (BCD element 16000009 'recoveryenabled' = No) — the state 'bcdedit /set recoveryenabled no' produces, a documented ransomware preparation step (T1490)." +
                                          (ev.TamperCommandSeen ? " Corroborated by recovery-tampering command evidence found in this scan." : " Can also be an intentional admin/kiosk configuration.") +
                                          " Verify by hand with 'bcdedit /enum' (read-only). Deliberately no one-click fix: recovery-state changes are operator-run-by-hand only (spec §6.8).",
                            Target = $@"HKLM\BCD00000000\Objects\{guid}",
                            FixAction = FixAction.None, // NEVER executable here — see region comment
                            Mitre = MitreInhibit,
                            Group = Group,
                            Check = Rans4Bcd,
                        });
                    }
                }

                // Element 250000E0 = bootstatuspolicy (integer; 1 = IgnoreAllFailures).
                using (var el = objects.OpenSubKey(guid + @"\Elements\250000e0"))
                {
                    if (el?.GetValue("Element") is byte[] v && v.Length > 0)
                    {
                        long val = 0;
                        for (var i = v.Length - 1; i >= 0; i--) val = (val << 8) | v[i];
                        if (val == 1)
                        {
                            sink.Report(new Finding
                            {
                                Id = Finding.ComputeId(Group, $@"HKLM\BCD00000000\Objects\{guid}", "RANS-004:bcd:bootstatuspolicy"),
                                Severity = ev.TamperCommandSeen ? Severity.High : Severity.Possible,
                                Description = $"Boot entry {guid} has bootstatuspolicy = IgnoreAllFailures (BCD element 250000E0) — the state 'bcdedit /set bootstatuspolicy ignoreallfailures' produces, used by ransomware to suppress boot-failure recovery (T1490)." +
                                              (ev.TamperCommandSeen ? " Corroborated by recovery-tampering command evidence found in this scan." : " Can also be an intentional admin configuration.") +
                                              " Verify by hand with 'bcdedit /enum' (read-only). Deliberately no one-click fix (spec §6.8).",
                                Target = $@"HKLM\BCD00000000\Objects\{guid}",
                                FixAction = FixAction.None, // NEVER executable here — see region comment
                                Mitre = MitreInhibit,
                                Group = Group,
                                Check = Rans4Bcd,
                            });
                        }
                    }
                }
            }

            sink.Completed(Phase, Rans4Bcd, $"{inspected} BCD objects inspected");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, Rans4Bcd, $"BCD state unreadable: {ex.Message} — verify by hand with 'bcdedit /enum' (read-only)");
        }
    }

    // ==================================================================================
    // RANS-005 — Windows Recovery Environment state ('reagentc /info' equivalent, read
    // from ReAgent.xml — we never execute reagentc).
    // ==================================================================================

    private void CheckWinReState(ScanContext ctx, IFindingSink sink, Evidence ev)
    {
        try
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "Recovery", "ReAgent.xml");
            if (!File.Exists(path))
            {
                sink.Inconclusive(Phase, Rans5, $"ReAgent.xml not found at {path} — verify WinRE state by hand with 'reagentc /info' (read-only)");
                return;
            }

            var xmlText = ReadTextPrefix(path, 64 * 1024);
            if (xmlText is null)
            {
                sink.Inconclusive(Phase, Rans5, $"cannot read {path} (access denied?) — run elevated or verify by hand with 'reagentc /info' (read-only)");
                return;
            }

            bool? disabled = null;
            var doc = XDocument.Parse(xmlText);

            // Modern schema: WinreBCD id all-zero GUID <=> WinRE disabled.
            var winreBcdId = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "WinreBCD")?.Attribute("id")?.Value;
            if (!string.IsNullOrEmpty(winreBcdId))
                disabled = winreBcdId.Contains("00000000-0000-0000-0000-000000000000", StringComparison.OrdinalIgnoreCase);

            // Older schema fallback: <InstallState state="0"> <=> disabled.
            if (disabled is null)
            {
                var installState = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "InstallState")?.Attribute("state")?.Value;
                if (!string.IsNullOrEmpty(installState)) disabled = installState.Trim() == "0";
            }

            if (disabled is null)
            {
                sink.Inconclusive(Phase, Rans5, "could not determine WinRE state from ReAgent.xml (unknown schema) — verify by hand with 'reagentc /info' (read-only)");
                return;
            }

            if (disabled.Value)
            {
                DateTime? modified = null;
                try { modified = File.GetLastWriteTimeUtc(path); } catch { /* keep null */ }
                var inWindow = modified is null || ctx.WithinTimeWindow(modified);
                // POSSIBLE alone; HIGH when disabled inside the time window alongside other
                // Phase 5 evidence (catalog: "POSSIBLE→HIGH alongside other Phase 5 hits").
                var sev = ev.Strong && inWindow ? Severity.High : Severity.Possible;
                sink.Report(new Finding
                {
                    Id = Finding.ComputeId(Group, path, "RANS-005:winre-disabled"),
                    Severity = sev,
                    Description = "Windows Recovery Environment (WinRE) is DISABLED (ReAgent.xml" +
                                  (modified is null ? "" : $", last modified {modified:u}") + "). " +
                                  "Disabling WinRE is a documented ransomware preparation step (T1490 Inhibit System Recovery)." +
                                  (ev.Strong
                                      ? " Other Phase 5 ransomware evidence was found in this scan, which escalates this finding."
                                      : " It can also be a deliberate admin choice on space-constrained images.") +
                                  " Verify by hand with 'reagentc /info' (read-only); re-enable, if appropriate, is an operator decision made by hand — deliberately no one-click fix (spec §6.8).",
                    Target = path,
                    FixAction = FixAction.None,
                    Mitre = MitreInhibit,
                    Group = Group,
                    Check = Rans5,
                });
                sink.Completed(Phase, Rans5, "WinRE disabled — finding raised");
            }
            else
            {
                sink.Completed(Phase, Rans5, "WinRE enabled");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            sink.Inconclusive(Phase, Rans5, $"WinRE state unreadable: {ex.Message} — verify by hand with 'reagentc /info' (read-only)");
        }
    }

    // ==================================================================================
    // Helpers
    // ==================================================================================

    private sealed class Evidence
    {
        public bool NoteConfirmed;       // RANS-001 name + content (CRITICAL)
        public bool ExtensionEvidence;   // RANS-002 finding at HIGH+
        public bool TamperCommandSeen;   // RANS-004 command evidence at HIGH+
        public bool Strong => NoteConfirmed || ExtensionEvidence || TamperCommandSeen;
    }

    private sealed class WalkState
    {
        public bool NoteFoundAny;
        public bool NoteFoundConfirmed;
        public bool ExtCritical;
        public int FilesSeen;
        public int DeniedDirs;
        /// <summary>A directory listing hit the hard cap — coverage is partial (spec §6.7).</summary>
        public bool ListTruncated;
        public int EntropySampled;
        public int EntropyHigh;
        public readonly List<DateTime> ModTimesUtc = new();
        public readonly Dictionary<string, ExtHit> ExtHits = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class ExtHit
    {
        public required IndicatorEntry Entry { get; init; }
        public required string Root { get; init; }
        public required string Ext { get; init; }
        public int Count;
        public required string ExampleFile { get; init; }
    }

    private sealed class Sigs
    {
        public required IReadOnlyList<IndicatorEntry> NotePatterns { get; init; }
        public required IReadOnlyList<IndicatorEntry> NoteMarkers { get; init; }
        public required IReadOnlyList<IndicatorEntry> TamperCommands { get; init; }
        public required Dictionary<string, IndicatorEntry> Extensions { get; init; }
        public required HashSet<string> EntropyExtensions { get; init; }
        public required IReadOnlyList<IndicatorEntry> CustomFilenames { get; init; }
        // Tracked independently: RANS-001 and RANS-002 are separate checks, and a set that
        // failed to load must make ONLY its own check inconclusive (spec §6.5) — never
        // silently suppress the other, and never let the other's data imply this one ran.
        public bool NotesLoaded => NotePatterns.Count > 0;
        public bool ExtsLoaded => Extensions.Count > 0;
    }

    private static Sigs LoadSigs(ScanContext ctx)
    {
        var exts = new Dictionary<string, IndicatorEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in ctx.Signatures.Set("ransomware.known_ransom_extensions"))
            if (e.Kind == MatchKind.Literal && e.Pattern.StartsWith('.'))
                exts.TryAdd(e.Pattern, e);

        var entropyExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in ctx.Signatures.Set("ransomware.entropy_target_extensions"))
            if (e.Kind == MatchKind.Literal && e.Pattern.StartsWith('.'))
                entropyExts.Add(e.Pattern);

        return new Sigs
        {
            NotePatterns = ctx.Signatures.Set("ransomware.ransom_note_patterns"),
            NoteMarkers = ctx.Signatures.Set("ransomware.note_content_markers"),
            TamperCommands = ctx.Signatures.Set("ransomware.recovery_tamper_commands"),
            Extensions = exts,
            EntropyExtensions = entropyExts,
            CustomFilenames = ctx.Signatures.Set("custom.filenames"),
        };
    }

    private static IndicatorEntry? FirstMatch(IReadOnlyList<IndicatorEntry> entries, string input)
    {
        foreach (var e in entries)
            if (e.Matches(input)) return e;
        return null;
    }

    private const int ListingCap = 10_000; // per-directory hard cap; the budget bounds actual work

    /// <summary>Enumerates safely: an access-denied / IO failure counts one denied dir and
    /// returns what was gathered, so one bad directory never kills the walk. A listing cut
    /// short by the hard cap latches <see cref="WalkState.ListTruncated"/> so the walk is
    /// never reported complete (spec §6.7).</summary>
    private static List<string> SafeList(Func<IEnumerable<string>> enumerate, WalkState state)
    {
        var list = new List<string>();
        try
        {
            foreach (var item in enumerate())
            {
                list.Add(item);
                if (list.Count >= ListingCap) { state.ListTruncated = true; break; }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { state.DeniedDirs++; }
        return list;
    }

    /// <summary>Like CompleteOrInconclusive, but also refuses to call a walk with unreadable
    /// subdirectories or a truncated listing "complete" (spec §6.7 — didn't look is never clean).</summary>
    private void ReportWalkStatus(IFindingSink sink, string check, EnumerationBudget budget, WalkState state, string scope)
    {
        if (budget.Exhausted)
            sink.Inconclusive(Phase, check, $"walk of {scope} cut short: {budget.ExhaustedReason}");
        else if (state.ListTruncated)
            sink.Inconclusive(Phase, check, $"{scope}; a directory listing exceeded the {ListingCap}-entry cap and was truncated");
        else if (state.DeniedDirs > 0)
            sink.Inconclusive(Phase, check, $"{scope}; {state.DeniedDirs} subdirector{(state.DeniedDirs == 1 ? "y" : "ies")} unreadable (access denied)");
        else
            sink.Completed(Phase, check, scope);
    }

    /// <summary>Bounded, BOM-aware text read (never reads more than maxBytes). Null when unreadable.</summary>
    private static string? ReadTextPrefix(string path, int maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var toRead = fs.Length > 0 ? (int)Math.Min(fs.Length, maxBytes) : maxBytes;
            var buf = new byte[toRead];
            var total = 0;
            while (total < buf.Length)
            {
                var n = fs.Read(buf, total, buf.Length - total);
                if (n <= 0) break;
                total += n;
            }
            if (total <= 0) return "";
            if (total >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) return Encoding.Unicode.GetString(buf, 2, total - 2);
            if (total >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(buf, 2, total - 2);
            if (total >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) return Encoding.UTF8.GetString(buf, 3, total - 3);
            return Encoding.UTF8.GetString(buf, 0, total);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Shannon entropy (bits/byte) over a bounded prefix; null when the file is
    /// too small (&lt; 256 bytes) or unreadable, so tiny files don't skew the sample.</summary>
    private static double? SampleEntropy(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length < 256) return null;
            var buf = new byte[(int)Math.Min(fs.Length, EntropyPrefixBytes)];
            var total = 0;
            while (total < buf.Length)
            {
                var n = fs.Read(buf, total, buf.Length - total);
                if (n <= 0) break;
                total += n;
            }
            if (total < 256) return null;

            Span<int> counts = stackalloc int[256];
            for (var i = 0; i < total; i++) counts[buf[i]]++;
            double h = 0;
            for (var i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                var p = (double)counts[i] / total;
                h -= p * Math.Log2(p);
            }
            return h;
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractEventData(string xml, string dataName)
    {
        var m = Regex.Match(xml, $"<Data Name=[\"']{dataName}[\"']>(.*?)</Data>",
            RegexOptions.Singleline | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2));
        return m.Success ? System.Net.WebUtility.HtmlDecode(m.Groups[1].Value) : null;
    }

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max] + "...";
}
