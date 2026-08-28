// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). Scythe is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Scythe.Core.Model;
using Scythe.Core.Profiles;
using Scythe.Core.Scanning;
using Scythe.Core.Signatures;
using Scythe.Core.Util;

namespace Scythe.Scanners;

// ====================================================================================
// HARD SCOPE BOUNDARY (spec §3, phase catalog Phase 6):
// This phase inspects the mail ATTACHMENT CACHE only — Outlook SecureTemp /
// Content.Outlook folders, plus Downloads for provenance — and NOTHING ELSE.
// It must NEVER enumerate, open, hash, or parse an OST/PST mail store. The store is
// multi-gigabyte, usually locked by the client, and contains the user's entire
// correspondence: reading it is both a performance disaster and a privacy violation
// this tool has no business committing. Every file walk below explicitly excludes
// *.ost / *.pst, and no code path follows a path into a mail store.
// ====================================================================================

/// <summary>Phase 6 — Email / Phishing Residue. Read-only detection of phishing
/// delivery artifacts left in per-user attachment caches (MAIL-001..MAIL-004).</summary>
public sealed class EmailResidueScanner : IScanner
{
    public int Phase => 6;
    public string Name => "Email / Phishing Residue";
    public string Group => "EmailResidue";
    public ScanDepth MinDepth => ScanDepth.Full;

    private static readonly MitreRef SpearphishMitre = new("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access");
    private static readonly MitreRef MotwBypassMitre = new("T1553.005", "Subvert Trust Controls: Mark-of-the-Web Bypass", "Defense Evasion");
    private static readonly MitreRef OutlookRulesMitre = new("T1137.005", "Office Application Startup: Outlook Rules", "Persistence");
    private static readonly MitreRef OfficeStartupMitre = new("T1137", "Office Application Startup", "Persistence");
    private static readonly MitreRef ScriptExecMitre = new("T1059", "Command and Scripting Interpreter", "Execution");

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        var state = new RunState();
        Mail001_AttachmentCache(ctx, sink, state);   // each check: own try/catch → Inconclusive on crash
        Mail002_MarkOfTheWeb(ctx, sink, state);
        Mail003_ScriptDroppers(ctx, sink, state);
        Mail004_OutlookPersistence(ctx, sink, state);
    }

    // ------------------------------------------------------------------ shared state

    private sealed class RunState
    {
        /// <summary>SIDs of profiles that produced at least one Possible+ finding in this
        /// phase — used by MAIL-004 for the catalog's "other Phase 6 findings" escalation.</summary>
        public readonly HashSet<string> SidsWithFindings = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Memoized per-SID attachment-cache resolution so all checks agree.</summary>
        public readonly Dictionary<string, CacheResolution> CacheDirs = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class CacheResolution
    {
        public List<string> Dirs { get; } = new();
        /// <summary>True when the profile hive was mounted and we could read it.</summary>
        public bool HiveConsulted;
        /// <summary>True when Software\Microsoft\Office existed in the hive.</summary>
        public bool OfficePresent;
        /// <summary>True when at least one OutlookSecureTempFolder value resolved.</summary>
        public bool RegistryValueFound;
    }

    /// <summary>Resolves the per-profile attachment cache directories: the registry-configured
    /// OutlookSecureTempFolder per Office version (hive required), plus the well-known default
    /// Content.Outlook locations (filesystem-only, valid whether or not the hive is mounted).</summary>
    private static CacheResolution ResolveCacheDirs(UserProfile p, RunState state)
    {
        if (state.CacheDirs.TryGetValue(p.Sid, out var cached)) return cached;

        var res = new CacheResolution();
        try
        {
            using var hive = p.OpenHiveRoot();
            if (hive is not null)
            {
                res.HiveConsulted = true;
                using var office = hive.OpenSubKey(@"Software\Microsoft\Office");
                if (office is not null)
                {
                    res.OfficePresent = true;
                    foreach (var ver in office.GetSubKeyNames())
                    {
                        if (!Regex.IsMatch(ver, @"^\d{1,2}\.\d$")) continue;
                        using var sec = office.OpenSubKey(ver + @"\Outlook\Security");
                        if (sec?.GetValue("OutlookSecureTempFolder") is string folder && folder.Length > 0)
                        {
                            res.RegistryValueFound = true;
                            try { if (Directory.Exists(folder)) AddDirUnique(res.Dirs, folder); }
                            catch { /* bad/unreachable configured path — nothing to walk */ }
                        }
                    }
                }
            }
        }
        catch { /* hive read failure — treated as unresolved; callers report the gap */ }

        foreach (var root in new[]
        {
            Path.Combine(p.ProfilePath, @"AppData\Local\Microsoft\Windows\INetCache\Content.Outlook"),
            Path.Combine(p.ProfilePath, @"AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook"),
        })
        {
            try { if (Directory.Exists(root)) AddDirUnique(res.Dirs, root); }
            catch { /* inaccessible default root — walk skips it */ }
        }

        state.CacheDirs[p.Sid] = res;
        return res;
    }

    private static void AddDirUnique(List<string> dirs, string dir)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dir));
        if (!dirs.Any(d => string.Equals(d, full, StringComparison.OrdinalIgnoreCase)))
            dirs.Add(full);
    }

    // ------------------------------------------------------------------ MAIL-001

    /// <summary>MAIL-001: per-profile Outlook secure-temp attachment cache walk — flags
    /// macro-capable documents (VBA-confirmed via zip central directory), direct
    /// executables/scripts, disk-image containers, shortcuts, double extensions,
    /// executable-bearing archives, and custom-IOC name/hash matches.</summary>
    private void Mail001_AttachmentCache(ScanContext ctx, IFindingSink sink, RunState state)
    {
        const string check = "MAIL-001";
        try
        {
            foreach (var p in ctx.Profiles)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                try
                {
                    var res = ResolveCacheDirs(p, state);

                    if (!res.HiveConsulted)
                        sink.Skipped(Phase, check, res.Dirs.Count == 0
                            ? $"profile {p.UserName}: hive not mounted (run with --load-hives) — OutlookSecureTempFolder not resolved and no default Content.Outlook cache present; attachment cache not scanned"
                            : $"profile {p.UserName}: hive not mounted (run with --load-hives) — OutlookSecureTempFolder not resolved; scanning default Content.Outlook cache paths only");

                    if (res.Dirs.Count == 0)
                    {
                        if (res.HiveConsulted && res.OfficePresent)
                            // Spec catalog: value absent => Inconclusive for the profile, not clean.
                            sink.Inconclusive(Phase, check, $"profile {p.UserName}: OutlookSecureTempFolder not set and no default Content.Outlook cache found — attachment cache location unknown, not scanned");
                        else if (res.HiveConsulted)
                            sink.Completed(Phase, check, $"profile {p.UserName}: no Office/Outlook registry presence and no cache folder — nothing to scan");
                        continue; // hive-not-mounted case already reported Skipped above
                    }

                    var budget = ctx.CreateBudget(2500, TimeSpan.FromSeconds(25)); // fresh per profile (spec §4)
                    var files = 0;
                    foreach (var dir in res.Dirs)
                    {
                        foreach (var file in EnumerateFilesSafe(dir, recurse: true))
                        {
                            ctx.Cancel.ThrowIfCancellationRequested();
                            if (!budget.TryConsume()) break;
                            files++;
                            InspectCacheFile(ctx, sink, state, p, check, file);
                        }
                        if (budget.Exhausted) break;
                    }

                    var scope = $"profile {p.UserName}: {res.Dirs.Count} cache dir(s), {files} file(s) examined";
                    if (!budget.Exhausted && res.HiveConsulted && res.OfficePresent && !res.RegistryValueFound)
                        // We walked defaults, but the registry-configured location (if any Office
                        // version uses a non-default one) could not be determined — not clean.
                        sink.Inconclusive(Phase, check, scope + "; OutlookSecureTempFolder value absent — default cache paths only, registry-configured location unknown");
                    else
                        sink.CompleteOrInconclusive(Phase, check, budget, scope);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.Message}"); }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, $"check crashed: {ex.Message}"); }
    }

    private void InspectCacheFile(ScanContext ctx, IFindingSink sink, RunState state, UserProfile p, string check, string path)
    {
        var sig = ctx.Signatures;
        var name = Path.GetFileName(path);
        var ext = Path.GetExtension(path);

        // HARD SCOPE BOUNDARY: never touch a mail store, even one oddly placed in a cache dir.
        if (ext.Equals(".ost", StringComparison.OrdinalIgnoreCase) || ext.Equals(".pst", StringComparison.OrdinalIgnoreCase))
            return;

        DateTime newest;
        try
        {
            var fi = new FileInfo(path);
            newest = fi.LastWriteTimeUtc > fi.CreationTimeUtc ? fi.LastWriteTimeUtc : fi.CreationTimeUtc;
        }
        catch { return; }
        if (!ctx.WithinTimeWindow(newest)) return;

        // 1) Macro-capable Office documents: bare presence is POSSIBLE at most (people do
        //    legitimately receive macro documents); confirmed embedded VBA project => HIGH.
        var macroHit = FirstMatch(sig.Set("emailresidue.macro_ext"), name);
        if (macroHit is not null)
        {
            var inspected = TryZipMembers(path, out var members);
            var vbaConfirmed = inspected &&
                members.Any(m => FirstMatch(sig.Set("emailresidue.macro_zip_member"), m) is not null);
            if (vbaConfirmed)
                ReportFile(ctx, sink, state, p, check, path, "macro-vba", Severity.High,
                    $"Macro-capable Office document '{name}' in the mail attachment cache of user {p.UserName} contains an embedded VBA project (vbaProject.bin listed in the OOXML zip central directory; nothing was extracted). A macro document actually opened from email is a primary phishing delivery vehicle.",
                    FixAction.Quarantine, path, macroHit.Mitre ?? SpearphishMitre);
            else
                ReportFile(ctx, sink, state, p, check, path, "macro-capable", Severity.Possible,
                    $"Macro-capable Office document '{name}' ({macroHit.Note}) was opened from an email by user {p.UserName}. " +
                    (inspected
                        ? "No embedded VBA project was found in its container."
                        : "Its container could not be inspected (corrupt, encrypted, or not OOXML) — macro presence is unconfirmed, not absent.") +
                    " Bare presence is common and legitimate; review before acting.",
                    FixAction.None, null, macroHit.Mitre ?? SpearphishMitre);
        }
        else
        {
            // 2) Direct executables / scripts / containers / shortcuts in the cache.
            var extHit = FirstMatch(sig.Set("emailresidue.cache_suspect_ext"), name);
            if (extHit is not null)
                ReportFile(ctx, sink, state, p, check, path, $"suspect-ext{ext.ToLowerInvariant()}", CappedSeverity(extHit),
                    $"'{name}' in the mail attachment cache of user {p.UserName}: {extHit.Note}. Files in this cache were opened from email by the user. The cache copy is transient, so quarantining it is low-risk and reversible.",
                    FixAction.Quarantine, path, extHit.Mitre ?? SpearphishMitre);
        }

        // 3) Archive wrapping an executable (zip central directory names only — bounded,
        //    nothing is ever extracted).
        if (FirstMatch(sig.Set("emailresidue.archive_ext"), name) is not null && TryZipMembers(path, out var archiveMembers))
        {
            var badMembers = archiveMembers
                .Where(m => FirstMatch(sig.Set("emailresidue.archive_member_suspect"), Path.GetFileName(m)) is not null)
                .Take(5).ToList();
            if (badMembers.Count > 0)
                ReportFile(ctx, sink, state, p, check, path, "archive-exec-member", Severity.High,
                    $"Archive '{name}' in the mail attachment cache of user {p.UserName} contains executable content: {string.Join(", ", badMembers)} (member names read from the zip central directory only). An executable inside a mailed archive is a standard phishing delivery wrapper.",
                    FixAction.Quarantine, path, SpearphishMitre);
        }

        // 4) Double extension.
        var dblHit = FirstMatch(sig.Set("emailresidue.double_ext"), name);
        if (dblHit is not null)
            ReportFile(ctx, sink, state, p, check, path, "double-ext", CappedSeverity(dblHit),
                $"'{name}' in the mail attachment cache of user {p.UserName} uses a double extension ({dblHit.Note}).",
                FixAction.Quarantine, path, dblHit.Mitre ?? SpearphishMitre);

        // 5) Operator custom IOCs (spec §6.6: low-precision — POSSIBLE, never delete/kill).
        var nameIoc = FirstMatch(sig.Set("custom.filenames"), name);
        if (nameIoc is not null)
            ReportFile(ctx, sink, state, p, check, path, $"custom-filename:{nameIoc.Pattern}", Severity.Possible,
                $"'{name}' in the mail attachment cache of user {p.UserName} matches operator-supplied IOC '{nameIoc.Pattern}'. Operator IOCs are low-precision — confirm individually before acting.",
                FixAction.Quarantine, path, nameIoc.Mitre ?? SpearphishMitre);

        var customHashes = sig.Set("custom.hashes");
        var knownBad = sig.Set("emailresidue.known_bad_sha256"); // empty unless an operator rules file supplies it
        if (customHashes.Count > 0 || knownBad.Count > 0)
        {
            var sha = FileHasher.Sha256(path, 32 * 1024 * 1024);
            if (sha is not null)
            {
                var kb = FirstMatch(knownBad, sha);
                if (kb is not null)
                    ReportFile(ctx, sink, state, p, check, path, $"known-bad-sha256:{sha}", kb.Severity,
                        $"SHA-256 of '{name}' in the mail attachment cache of user {p.UserName} matches known-bad hash {sha}" + (kb.Note is null ? "." : $" ({kb.Note})."),
                        FixAction.DeleteFile, path, kb.Mitre ?? SpearphishMitre, hashConfirmed: true);
                else if (FirstMatch(customHashes, sha) is { } customHash)
                    // hashConfirmed stays false: an operator-supplied IOC file is untrusted
                    // input, not curated confirmation (spec §6.6).
                    ReportFile(ctx, sink, state, p, check, path, $"custom-sha256:{sha}", Severity.Possible,
                        $"SHA-256 of '{name}' in the mail attachment cache of user {p.UserName} is {sha}, matching an operator-supplied IOC hash" + (customHash.Note is null ? "." : $" ({customHash.Note}).") + " Operator IOCs are low-precision — confirm individually before acting.",
                        FixAction.Quarantine, path, customHash.Mitre ?? SpearphishMitre, hashConfirmed: false);
            }
        }
    }

    // ------------------------------------------------------------------ MAIL-002

    /// <summary>MAIL-002: Mark-of-the-Web provenance for candidate files in the attachment
    /// cache and Downloads — Zone.Identifier ADS reads, provenance-URL IOC matching, and the
    /// stripped-MOTW sibling anomaly (Downloads only).</summary>
    private void Mail002_MarkOfTheWeb(ScanContext ctx, IFindingSink sink, RunState state)
    {
        const string check = "MAIL-002";
        try
        {
            foreach (var p in ctx.Profiles)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                try
                {
                    var res = ResolveCacheDirs(p, state);
                    var downloads = Path.Combine(p.ProfilePath, "Downloads");
                    var haveDownloads = Directory.Exists(downloads);
                    if (res.Dirs.Count == 0 && !haveDownloads)
                    {
                        sink.Completed(Phase, check, $"profile {p.UserName}: no attachment cache and no Downloads folder — nothing to check");
                        continue;
                    }

                    var budget = ctx.CreateBudget(1500, TimeSpan.FromSeconds(15)); // fresh per profile (spec §4)
                    int candidates = 0, adsErrors = 0;
                    var nonNtfs = new List<string>();

                    // Cache dirs: provenance-IOC checks only — cache copies legitimately often
                    // lack MOTW, so the missing-MOTW anomaly is evaluated in Downloads only.
                    foreach (var dir in res.Dirs)
                        WalkMotw(ctx, sink, state, p, check, dir, recurse: true, siblingBaseline: false, budget, ref candidates, ref adsErrors, nonNtfs);
                    if (haveDownloads && !budget.Exhausted)
                        WalkMotw(ctx, sink, state, p, check, downloads, recurse: false, siblingBaseline: true, budget, ref candidates, ref adsErrors, nonNtfs);

                    var scope = $"profile {p.UserName}: {candidates} candidate file(s) checked";
                    if (nonNtfs.Count > 0)
                        sink.Inconclusive(Phase, check, $"{scope}; Zone.Identifier ADS unavailable on non-NTFS volume(s): {string.Join(", ", nonNtfs.Distinct())} — MOTW state unknown there");
                    else if (adsErrors > 0)
                        sink.Inconclusive(Phase, check, $"{scope}; {adsErrors} Zone.Identifier read failure(s) — MOTW state unknown for those files");
                    else
                        sink.CompleteOrInconclusive(Phase, check, budget, scope);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.Message}"); }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, $"check crashed: {ex.Message}"); }
    }

    private void WalkMotw(ScanContext ctx, IFindingSink sink, RunState state, UserProfile p, string check,
        string root, bool recurse, bool siblingBaseline, EnumerationBudget budget,
        ref int candidates, ref int adsErrors, List<string> nonNtfs)
    {
        var fmt = VolumeFormat(root);
        if (fmt is not null && fmt is not ("NTFS" or "ReFS"))
        {
            nonNtfs.Add($"{root} ({fmt})");
            return;
        }

        var sig = ctx.Signatures;
        var baseline = siblingBaseline ? new List<(string Path, bool HasMotw, bool ExecClass, bool AdsError)>() : null;

        foreach (var file in EnumerateFilesSafe(root, recurse))
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            if (!budget.TryConsume()) break;

            var name = Path.GetFileName(file);
            var fext = Path.GetExtension(file);
            if (fext.Equals(".ost", StringComparison.OrdinalIgnoreCase) || fext.Equals(".pst", StringComparison.OrdinalIgnoreCase))
                continue; // mail store — hard scope boundary
            if (!IsMotwCandidate(sig, name)) continue;

            DateTime newest;
            try
            {
                var fi = new FileInfo(file);
                newest = fi.LastWriteTimeUtc > fi.CreationTimeUtc ? fi.LastWriteTimeUtc : fi.CreationTimeUtc;
            }
            catch { continue; }
            if (!ctx.WithinTimeWindow(newest)) continue;

            candidates++;
            var hasMotw = TryReadMotw(file, out var zone, out var hostUrl, out var referrerUrl, out var adsError);
            if (adsError) adsErrors++;

            if (hasMotw && zone >= 3)
            {
                var seenHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var url in new[] { hostUrl, referrerUrl })
                {
                    if (string.IsNullOrWhiteSpace(url)) continue;

                    var urlHit = FirstMatch(sig.Set("emailresidue.motw_url"), url);
                    if (urlHit is not null)
                        ReportFile(ctx, sink, state, p, check, file, $"motw-url:{url}", CappedSeverity(urlHit),
                            $"'{name}' carries Mark-of-the-Web ZoneId={zone} with provenance URL '{url}': {urlHit.Note}. MOTW provenance is genuine evidence of where the file came from.",
                            FixAction.None, null, urlHit.Mitre ?? SpearphishMitre);

                    var host = UrlHost(url);
                    if (host is null || !seenHosts.Add(host)) continue;
                    var iocHit = MatchDomain(sig.Set("custom.domains"), host) ?? FirstMatch(sig.Set("custom.ips"), host);
                    if (iocHit is not null)
                        // Spec §6.6 / hard rule 12: operator IOC hits stay POSSIBLE, no destructive fix.
                        ReportFile(ctx, sink, state, p, check, file, $"motw-ioc:{host}", Severity.Possible,
                            $"'{name}' was downloaded from '{url}' (Mark-of-the-Web ZoneId={zone}); host '{host}' matches operator-supplied IOC '{iocHit.Pattern}'. Operator IOCs are low-precision — confirm individually before acting.",
                            FixAction.None, null, iocHit.Mitre ?? SpearphishMitre);
                }
            }

            baseline?.Add((file, hasMotw, IsExecClass(sig, name), adsError));
        }

        // Stripped-MOTW anomaly: only meaningful where siblings establish a baseline.
        if (baseline is not null)
        {
            var withMotw = baseline.Count(b => b.HasMotw);
            if (withMotw >= 3)
                foreach (var b in baseline.Where(b => b.ExecClass && !b.HasMotw && !b.AdsError))
                    ReportFile(ctx, sink, state, p, check, b.Path, "motw-missing", Severity.Possible,
                        $"Executable/script '{Path.GetFileName(b.Path)}' in the Downloads folder of user {p.UserName} has no Zone.Identifier (Mark-of-the-Web) while {withMotw} sibling file(s) there carry one. A stripped MOTW is a known evasion technique, but it is also a normal artifact of copying a file from a USB stick or other non-NTFS media — verify how the file arrived before acting.",
                        FixAction.None, null, MotwBypassMitre);
        }
    }

    // ------------------------------------------------------------------ MAIL-003

    /// <summary>MAIL-003: bounded content matching over script-typed candidates from the
    /// attachment cache and Downloads. All content indicators require corroboration: two or
    /// more independent indicator hits => HIGH; a single hit never exceeds POSSIBLE.</summary>
    private void Mail003_ScriptDroppers(ScanContext ctx, IFindingSink sink, RunState state)
    {
        const string check = "MAIL-003";
        try
        {
            var droppers = ctx.Signatures.Set("emailresidue.dropper_content");
            var scriptSel = ctx.Signatures.Set("emailresidue.script_ext");
            if (droppers.Count == 0 || scriptSel.Count == 0)
            {
                sink.Inconclusive(Phase, check, "emailresidue signature sets not loaded (emailresidue.dropper_content / emailresidue.script_ext empty) — content matching could not run");
                return;
            }

            foreach (var p in ctx.Profiles)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                try
                {
                    var res = ResolveCacheDirs(p, state);
                    var downloads = Path.Combine(p.ProfilePath, "Downloads");
                    var roots = new List<(string Dir, bool Recurse)>();
                    foreach (var d in res.Dirs) roots.Add((d, true));
                    if (Directory.Exists(downloads)) roots.Add((downloads, false));
                    if (roots.Count == 0)
                    {
                        sink.Completed(Phase, check, $"profile {p.UserName}: no attachment cache and no Downloads folder — nothing to scan");
                        continue;
                    }

                    var budget = ctx.CreateBudget(800, TimeSpan.FromSeconds(20)); // fresh per profile (spec §4)
                    int scanned = 0, readErrors = 0;

                    foreach (var (dir, recurse) in roots)
                    {
                        foreach (var file in EnumerateFilesSafe(dir, recurse))
                        {
                            ctx.Cancel.ThrowIfCancellationRequested();
                            if (!budget.TryConsume()) break;

                            var name = Path.GetFileName(file);
                            var fext = Path.GetExtension(file);
                            if (fext.Equals(".ost", StringComparison.OrdinalIgnoreCase) || fext.Equals(".pst", StringComparison.OrdinalIgnoreCase))
                                continue; // mail store — hard scope boundary
                            if (FirstMatch(scriptSel, name) is null) continue;

                            DateTime newest;
                            try
                            {
                                var fi = new FileInfo(file);
                                if (fi.Length == 0) continue;
                                newest = fi.LastWriteTimeUtc > fi.CreationTimeUtc ? fi.LastWriteTimeUtc : fi.CreationTimeUtc;
                            }
                            catch { continue; }
                            if (!ctx.WithinTimeWindow(newest)) continue;

                            var text = ReadTextPrefix(file, 64 * 1024); // bounded read — never the whole file
                            if (text is null) { readErrors++; continue; }
                            scanned++;

                            var hits = droppers.Where(d => d.Matches(text) || text.Contains(d.Pattern, StringComparison.OrdinalIgnoreCase)).Distinct().ToList();
                            if (hits.Count == 0) continue;

                            var summary = string.Join("; ", hits.Take(4).Select(h => $"'{h.Pattern}'" + (h.Note is null ? "" : $" ({h.Note})")));
                            if (hits.Count >= 2)
                                // Corroborated: multiple independent dropper indicators in one
                                // mail-delivered script (catalog: corroborated match => HIGH).
                                ReportFile(ctx, sink, state, p, check, file, "dropper-corroborated", Severity.High,
                                    $"Script '{name}' from the mail attachment cache/Downloads of user {p.UserName} contains {hits.Count} independent dropper indicators: {summary}. Multiple corroborating download/execute/obfuscation constructs in a mail-delivered script are characteristic of an attachment-borne dropper.",
                                    FixAction.Quarantine, file, hits[0].Mitre ?? ScriptExecMitre);
                            else
                                // Single indicator: NeedsCorroboration caps this at POSSIBLE (hard rule 5).
                                ReportFile(ctx, sink, state, p, check, file, $"dropper-single:{hits[0].Pattern}", Severity.Possible,
                                    $"Script '{name}' from the mail attachment cache/Downloads of user {p.UserName} contains one dropper-associated construct: {summary}. A single indicator also occurs in legitimate admin scripts — operator review required.",
                                    FixAction.None, null, hits[0].Mitre ?? ScriptExecMitre);
                        }
                        if (budget.Exhausted) break;
                    }

                    var scope = $"profile {p.UserName}: {scanned} script file(s) content-checked";
                    if (readErrors > 0)
                        sink.Inconclusive(Phase, check, $"{scope}; {readErrors} file(s) unreadable (locked/access denied) — their content was not checked");
                    else
                        sink.CompleteOrInconclusive(Phase, check, budget, scope);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.Message}"); }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, $"check crashed: {ex.Message}"); }
    }

    // ------------------------------------------------------------------ MAIL-004

    /// <summary>MAIL-004: Outlook client-side persistence — VbaProject.OTM presence/mtime
    /// (filesystem, deliberate overlap with PERS-009), EnableUnsafeClientMailRules
    /// re-enablement, and rules/settings blob presence+size (never parsed).</summary>
    private void Mail004_OutlookPersistence(ScanContext ctx, IFindingSink sink, RunState state)
    {
        const string check = "MAIL-004";
        try
        {
            foreach (var p in ctx.Profiles)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                try
                {
                    // (a) VbaProject.OTM — filesystem, checkable whether or not the hive is mounted.
                    var otm = Path.Combine(p.ProfilePath, @"AppData\Roaming\Microsoft\Outlook\VbaProject.OTM");
                    if (File.Exists(otm))
                    {
                        var mtime = File.GetLastWriteTimeUtc(otm);
                        var inWindow = ctx.SinceUtc is not null && mtime >= ctx.SinceUtc.Value;
                        // Catalog: HIGH only when changed in-window AND corroborated by other
                        // Phase 6 findings for this profile; POSSIBLE otherwise.
                        var corroborated = inWindow && state.SidsWithFindings.Contains(p.Sid);
                        ReportFile(ctx, sink, state, p, check, otm, "otm-present",
                            corroborated ? Severity.High : Severity.Possible,
                            $"Outlook VBA project (VbaProject.OTM) present for user {p.UserName}, last modified {mtime:u}." +
                            (inWindow ? " It was modified inside the scan time window." : "") +
                            (corroborated ? " Combined with other Phase 6 findings for this profile, treat as likely mail-client persistence." : "") +
                            " Outlook VBA runs when the client starts and is a documented persistence mechanism — but it is also where legitimate mail-automation macros live. Review with olevba or the Outlook VBA editor; do not remove blind.",
                            FixAction.None, null, OfficeStartupMitre);
                    }

                    // (b) Registry: needs the mounted hive.
                    using var hive = p.OpenHiveRoot();
                    if (hive is null)
                    {
                        sink.Skipped(Phase, check, $"profile {p.UserName}: hive not mounted (run with --load-hives) — Outlook Security/rules registry not checked (VbaProject.OTM was checked on disk)");
                        continue;
                    }

                    var versionsChecked = 0;
                    using (var office = hive.OpenSubKey(@"Software\Microsoft\Office"))
                    {
                        if (office is not null)
                        {
                            foreach (var ver in office.GetSubKeyNames())
                            {
                                if (!Regex.IsMatch(ver, @"^\d{1,2}\.\d$")) continue;
                                versionsChecked++;

                                // "Run script"/"start application" rule actions were disabled by the
                                // 2017 Outlook security updates; EnableUnsafeClientMailRules=1
                                // deliberately re-enables them and is a standard precondition for
                                // rules-based persistence. Kept POSSIBLE (not HIGH) because legacy
                                // environments do set it via GPO — single indicator, err low.
                                using (var sec = office.OpenSubKey($@"{ver}\Outlook\Security"))
                                {
                                    if (sec?.GetValue("EnableUnsafeClientMailRules") is int unsafeRules && unsafeRules == 1)
                                    {
                                        var keyPath = $@"Software\Microsoft\Office\{ver}\Outlook\Security";
                                        var target = $@"HKU\{p.Sid}\{keyPath}";
                                        sink.Report(new Finding
                                        {
                                            Id = Finding.ComputeId(Group, target, "EnableUnsafeClientMailRules"),
                                            Severity = Severity.Possible,
                                            Description = $"EnableUnsafeClientMailRules=1 for user {p.UserName} (Outlook {ver}): re-enables the deprecated 'start application'/'run script' mail-rule actions that Microsoft disabled for security. Attackers set this to make malicious mailbox rules executable; some legacy environments set it via GPO — verify provenance before removing.",
                                            Target = target,
                                            FixAction = FixAction.DeleteRegistryValue,
                                            FixParam = $@"HKU\{p.HiveKeyName}\{keyPath}::EnableUnsafeClientMailRules",
                                            Mitre = OutlookRulesMitre,
                                            Group = Group,
                                            Check = check,
                                        });
                                        state.SidsWithFindings.Add(p.Sid);
                                    }
                                }

                                // Rules/settings blobs: presence and size ONLY. This scanner
                                // deliberately does NOT parse the rules blob format (catalog:
                                // presence and mtime/size are enough to tell the operator where
                                // to look) — a blob parser is an attack surface this tool must not grow.
                                using var profiles = office.OpenSubKey($@"{ver}\Outlook\Profiles");
                                if (profiles is null) continue;
                                foreach (var outlookProfile in profiles.GetSubKeyNames().Take(10))
                                {
                                    using var pk = profiles.OpenSubKey(outlookProfile);
                                    if (pk is null) continue;
                                    int visited = 0, blobCount = 0;
                                    long blobBytes = 0;
                                    var examples = new List<string>();
                                    ScanForBlobs(pk, outlookProfile, ref visited, 400, ref blobCount, ref blobBytes, examples);
                                    if (blobCount == 0) continue;

                                    var target = $@"HKU\{p.Sid}\Software\Microsoft\Office\{ver}\Outlook\Profiles\{outlookProfile}";
                                    sink.Report(new Finding
                                    {
                                        Id = Finding.ComputeId(Group, target, "rules-blob-presence"),
                                        Severity = Severity.Info,
                                        Description = $"Outlook profile '{outlookProfile}' (user {p.UserName}, Outlook {ver}) holds {blobCount} large binary settings/rules blob(s) totalling {blobBytes} bytes (e.g. {string.Join(", ", examples.Take(3))}). Presence and size only — the blob format is deliberately not parsed. Review client-side rules in Outlook (Manage Rules & Alerts) or MFCMAPI for 'start application'/'run script' actions.",
                                        Target = target,
                                        FixAction = FixAction.None,
                                        Mitre = OutlookRulesMitre,
                                        Group = Group,
                                        Check = check,
                                    });
                                }
                            }
                        }
                    }

                    sink.Completed(Phase, check, $"profile {p.UserName}: VbaProject.OTM and Outlook registry checked ({versionsChecked} Office version key(s))");
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { sink.Inconclusive(Phase, check, $"profile {p.UserName}: {ex.Message}"); }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { sink.Inconclusive(Phase, check, $"check crashed: {ex.Message}"); }
    }

    /// <summary>Bounded recursive scan of a registry key for large binary values —
    /// presence and size only, values are never decoded or parsed.</summary>
    private static void ScanForBlobs(RegistryKey key, string relPath, ref int keysVisited, int maxKeys,
        ref int blobCount, ref long blobBytes, List<string> examples)
    {
        if (++keysVisited > maxKeys) return;

        string[] valueNames;
        try { valueNames = key.GetValueNames(); }
        catch { return; }
        foreach (var vn in valueNames)
        {
            try
            {
                if (key.GetValueKind(vn) != RegistryValueKind.Binary) continue;
                if (key.GetValue(vn) is byte[] data && data.Length >= 4096)
                {
                    blobCount++;
                    blobBytes += data.Length;
                    if (examples.Count < 5)
                        examples.Add($@"{relPath}\{(vn.Length == 0 ? "(default)" : vn)} ({data.Length} bytes)");
                }
            }
            catch { /* unreadable value — skip */ }
        }

        string[] subKeys;
        try { subKeys = key.GetSubKeyNames(); }
        catch { return; }
        foreach (var sub in subKeys)
        {
            if (keysVisited > maxKeys) return;
            try
            {
                using var sk = key.OpenSubKey(sub);
                if (sk is not null)
                    ScanForBlobs(sk, relPath + @"\" + sub, ref keysVisited, maxKeys, ref blobCount, ref blobBytes, examples);
            }
            catch { /* unreadable subkey — skip */ }
        }
    }

    // ------------------------------------------------------------------ helpers

    private void ReportFile(ScanContext ctx, IFindingSink sink, RunState state, UserProfile p, string check,
        string path, string discriminator, Severity severity, string description, FixAction fix, string? fixParam,
        MitreRef? mitre, bool hashConfirmed = false)
    {
        sink.Report(new Finding
        {
            // Discriminator includes the profile SID: two users' identical artifacts must
            // produce two findings (hard rule 7).
            Id = Finding.ComputeId(Group, path, $"{p.Sid}:{check}:{discriminator}"),
            Severity = severity,
            Description = description,
            Target = path,
            FixAction = fix,
            FixParam = fixParam,
            Mitre = mitre,
            Group = Group,
            VendorTrusted = ctx.Signatures.IsVendorTrusted(path),
            HashConfirmed = hashConfirmed,
            Check = check,
        });
        if (severity > Severity.Info)
            state.SidsWithFindings.Add(p.Sid);
    }

    private static IndicatorEntry? FirstMatch(IReadOnlyList<IndicatorEntry> set, string input)
    {
        foreach (var e in set)
            if (e.Matches(input))
                return e;
        return null;
    }

    /// <summary>Hard rule 5: an indicator with NeedsCorroboration can never alone justify
    /// a severity above POSSIBLE.</summary>
    private static Severity CappedSeverity(IndicatorEntry e) =>
        e.NeedsCorroboration && e.Severity > Severity.Possible ? Severity.Possible : e.Severity;

    private static IndicatorEntry? MatchDomain(IReadOnlyList<IndicatorEntry> set, string host)
    {
        foreach (var e in set)
            if (e.Matches(host) || host.EndsWith("." + e.Pattern, StringComparison.OrdinalIgnoreCase))
                return e;
        return null;
    }

    private static string? UrlHost(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        return Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Host.Length > 0 ? u.Host : null;
    }

    private static bool IsMotwCandidate(SignatureDb sig, string name) =>
        FirstMatch(sig.Set("emailresidue.motw_required_ext"), name) is not null ||
        FirstMatch(sig.Set("emailresidue.cache_suspect_ext"), name) is not null ||
        FirstMatch(sig.Set("emailresidue.macro_ext"), name) is not null ||
        FirstMatch(sig.Set("emailresidue.archive_ext"), name) is not null;

    private static bool IsExecClass(SignatureDb sig, string name) =>
        FirstMatch(sig.Set("emailresidue.motw_required_ext"), name) is not null;

    private static string? VolumeFormat(string path)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(path));
            if (string.IsNullOrEmpty(root)) return null;
            return new DriveInfo(root).DriveFormat;
        }
        catch { return null; }
    }

    /// <summary>Reads the Zone.Identifier alternate data stream. Returns true when MOTW is
    /// present; <paramref name="adsError"/> is set when the stream could not be read for a
    /// reason other than "not there" (locked file, ACL, non-NTFS quirk) — that is "unknown",
    /// never "absent".</summary>
    private static bool TryReadMotw(string path, out int zoneId, out string? hostUrl, out string? referrerUrl, out bool adsError)
    {
        zoneId = -1;
        hostUrl = null;
        referrerUrl = null;
        adsError = false;
        try
        {
            using var fs = new FileStream(path + ":Zone.Identifier", FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var lines = 0;
            while (reader.ReadLine() is { } line && lines++ < 32)
            {
                if (line.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase) &&
                    int.TryParse(line["ZoneId=".Length..].Trim(), out var z))
                    zoneId = z;
                else if (line.StartsWith("HostUrl=", StringComparison.OrdinalIgnoreCase))
                    hostUrl = line["HostUrl=".Length..].Trim();
                else if (line.StartsWith("ReferrerUrl=", StringComparison.OrdinalIgnoreCase))
                    referrerUrl = line["ReferrerUrl=".Length..].Trim();
            }
            return zoneId >= 0;
        }
        catch (FileNotFoundException) { return false; } // no ADS => no MOTW: a real answer
        catch (Exception) { adsError = true; return false; }
    }

    /// <summary>Lists zip member names from the central directory only — bounded, nothing is
    /// ever extracted or decompressed. Also used for OOXML macro containers.</summary>
    private static bool TryZipMembers(string path, out List<string> members)
    {
        members = new List<string>();
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length == 0 || fi.Length > 64L * 1024 * 1024) return false;
            using var zip = ZipFile.OpenRead(path);
            foreach (var entry in zip.Entries)
            {
                members.Add(entry.FullName);
                if (members.Count >= 500) break;
            }
            return true;
        }
        catch { return false; } // corrupt / encrypted / not a zip — caller treats as uninspected
    }

    /// <summary>Bounded text read: first <paramref name="maxBytes"/> only, matched as
    /// Latin-1 plus a UTF-16LE view when NUL bytes suggest a wide-string file.</summary>
    private static string? ReadTextPrefix(string path, int maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var toRead = (int)Math.Min(fs.Length, maxBytes);
            if (toRead <= 0) return null;
            var buf = new byte[toRead];
            var n = fs.Read(buf, 0, toRead);
            if (n <= 0) return null;
            var text = Encoding.Latin1.GetString(buf, 0, n);
            if (Array.IndexOf(buf, (byte)0, 0, n) >= 0)
                text += "\n" + Encoding.Unicode.GetString(buf, 0, n);
            return text;
        }
        catch { return null; }
    }

    /// <summary>Exception-hardened file enumeration: inaccessible entries are skipped,
    /// reparse points are not followed, recursion depth is bounded.</summary>
    private static IEnumerable<string> EnumerateFilesSafe(string root, bool recurse)
    {
        IEnumerator<string>? it = null;
        try
        {
            it = Directory.EnumerateFiles(root, "*", new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = recurse,
                AttributesToSkip = FileAttributes.ReparsePoint,
                MaxRecursionDepth = 8,
            }).GetEnumerator();
        }
        catch { it = null; }
        if (it is null) yield break;

        using (it)
        {
            while (true)
            {
                bool moved;
                try { moved = it.MoveNext(); }
                catch { moved = false; }
                if (!moved) yield break;
                yield return it.Current;
            }
        }
    }
}
