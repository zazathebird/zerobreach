// NOTE - Detection vocabulary in this file is deliberate.
// Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
// named malware families, are detection category labels, operator-facing report text, or
// MITRE ATT&CK tactic names (a published standard). Scythe is a defensive incident-
// response tool; these strings are what it reports, not what it does. See CLAUDE.md,
// "The detection vocabulary is deliberate". Do not sanitise them.

using System.Text;
using Scythe.Core.Model;
using Scythe.Core.Profiles;
using Scythe.Core.Scanning;
using Scythe.Core.Signatures;
using Scythe.Core.Util;

namespace Scythe.Scanners;

/// <summary>
/// Phase 9 — General file / content scanning (the YARA-lite matcher), spec §3.
///
/// Walks per-profile user-writable hot paths (Downloads, Desktop, Temp, AppData) with a
/// FRESH budget per profile, plus machine temp/public/ProgramData roots each with their own
/// budget. Cheap gates run before expensive work: extension filter → size band → magic-byte
/// sniff → bounded read (head + tail, never the whole file) → pattern match against both a
/// latin-1 and a UTF-16LE view of the bytes (wide strings in PE files).
///
/// Corroboration rule (spec §3 — not optional): every content-string indicator is marked
/// NeedsCorroboration in the signature file, so a single hit can never justify above
/// Possible — a saved advisory or IR report that merely mentions a malware family must not
/// escalate. Escalation to the indicators' own severity requires 2+ independent signals
/// (distinct indicators, a magic/extension mismatch, or a filename trick), and content
/// matches alone are hard-capped at High: Critical requires hash confirmation, and the
/// shipped known-bad hash set is intentionally empty (operator-extendable; no fabricated
/// hashes).
///
/// Self-exclusion: the tool's own directory, quarantine vault and report output are removed
/// from the candidate set — otherwise the signature data matches itself every run.
/// </summary>
public sealed class ContentScanScanner : IScanner
{
    public int Phase => 9;
    public string Name => "Content Scan";
    public string Group => "ContentScan";
    public ScanDepth MinDepth => ScanDepth.Deep;

    private const string CheckRuleMatch = "CONT-001 content-rule-match";
    private const string CheckMagicMismatch = "CONT-002 magic-extension-mismatch";
    private const string CheckFilenameTricks = "CONT-003 filename-tricks";
    private const string CheckIocMatch = "CONT-004 custom-ioc-match";

    // Structural scan-scope constants: which file classes the walk examines. These are not
    // indicators of badness (those live in Signatures/contentscan.json) — they bound the
    // candidate set the same way a list of registry keys bounds a registry check.
    private static readonly HashSet<string> ExecExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".scr", ".com", ".pif", ".sys", ".cpl", ".ocx" };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta" };

    private const int HeadReadBytes = 1024 * 1024;       // bounded read: first 1 MB
    private const int TailReadBytes = 64 * 1024;         // bounded read: last 64 KB
    private const long MaxContentFileBytes = 64L * 1024 * 1024;  // skip content match on huge files
    private const long MaxHashFileBytes = 64L * 1024 * 1024;     // skip hashing huge files

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        var sets = new SetBundle(
            Strings: ctx.Signatures.Set("contentscan.malware_strings"),
            DocMasquerade: ctx.Signatures.Set("contentscan.doc_masquerade_ext"),
            FilenameTricks: ctx.Signatures.Set("contentscan.filename_tricks"),
            KnownBadHashes: ctx.Signatures.Set("contentscan.known_bad_hashes"),
            CustomHashes: ctx.Signatures.Set("custom.hashes"),
            CustomFilenames: ctx.Signatures.Set("custom.filenames"));

        // A missing signature set means the check cannot run — that is never "clean" (§6).
        if (sets.Strings.Count == 0)
            sink.Inconclusive(Phase, CheckRuleMatch,
                "signature set contentscan.malware_strings missing or empty — content rule matching did not run");
        if (sets.DocMasquerade.Count == 0)
            sink.Inconclusive(Phase, CheckMagicMismatch,
                "signature set contentscan.doc_masquerade_ext missing or empty — magic/extension mismatch check did not run");
        if (sets.FilenameTricks.Count == 0)
            sink.Inconclusive(Phase, CheckFilenameTricks,
                "signature set contentscan.filename_tricks missing or empty — filename trick check did not run");
        if (!sets.HasIocs)
            sink.Skipped(Phase, CheckIocMatch,
                "no operator-supplied IOC hashes/filenames and no known-bad hash set loaded — nothing to match");

        foreach (var profile in ctx.Profiles)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            ScanProfile(ctx, sink, sets, profile);
        }

        foreach (var (root, depth, exclude) in MachineRoots())
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            ScanMachineRoot(ctx, sink, sets, root, depth, exclude);
        }
    }

    // ---------------------------------------------------------------- walk targets

    private void ScanProfile(ScanContext ctx, IFindingSink sink, SetBundle sets, UserProfile p)
    {
        var scope = $"profile {p.UserName}";
        try
        {
            if (!Directory.Exists(p.ProfilePath))
            {
                foreach (var check in ActiveChecks(sets))
                    sink.Skipped(Phase, check, $"{scope}: profile path {p.ProfilePath} not found on disk");
                return;
            }

            // Fresh budget PER PROFILE (spec §4) — never shared across profiles.
            var budget = ctx.CreateBudget(4000, TimeSpan.FromSeconds(45));
            var stats = new WalkStats();
            var localTemp = Path.Combine(p.ProfilePath, "AppData", "Local", "Temp");

            var roots = new (string Root, int Depth, string[] Exclude)[]
            {
                (Path.Combine(p.ProfilePath, "Downloads"), 6, Array.Empty<string>()),
                (Path.Combine(p.ProfilePath, "Desktop"), 6, Array.Empty<string>()),
                (localTemp, 8, Array.Empty<string>()),
                (Path.Combine(p.ProfilePath, "AppData", "Roaming"), 4, Array.Empty<string>()),
                // AppData\Local walked shallow, minus Temp (already walked at full depth).
                (Path.Combine(p.ProfilePath, "AppData", "Local"), 4, new[] { localTemp }),
            };

            foreach (var (root, depth, exclude) in roots)
            {
                if (budget.Exhausted) break;
                if (!Directory.Exists(root)) continue;
                Walk(ctx, sink, sets, root, depth, budget, p.Sid, stats, exclude);
            }

            ReportWalkStatuses(sink, sets, budget, stats, scope);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            foreach (var check in ActiveChecks(sets))
                sink.Inconclusive(Phase, check, $"{scope}: walk failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void ScanMachineRoot(ScanContext ctx, IFindingSink sink, SetBundle sets,
        string root, int maxDepth, string[] exclude)
    {
        var scope = exclude.Length > 0
            ? $"machine root {root} (excluding OS-owned subdirectories)"
            : $"machine root {root}";
        try
        {
            if (!Directory.Exists(root))
            {
                foreach (var check in ActiveChecks(sets))
                    sink.Skipped(Phase, check, $"{scope}: directory not found");
                return;
            }

            // Each machine root gets its own fresh budget.
            var budget = ctx.CreateBudget(3000, TimeSpan.FromSeconds(30));
            var stats = new WalkStats();
            Walk(ctx, sink, sets, root, maxDepth, budget, "machine", stats, exclude);
            ReportWalkStatuses(sink, sets, budget, stats, scope);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            foreach (var check in ActiveChecks(sets))
                sink.Inconclusive(Phase, check, $"{scope}: walk failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static IEnumerable<(string Root, int Depth, string[] Exclude)> MachineRoots()
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(winDir))
            yield return (Path.Combine(winDir, "Temp"), 8, Array.Empty<string>());

        var publicDir = Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public";
        yield return (publicDir, 6, Array.Empty<string>());

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrEmpty(programData))
        {
            // ProgramData minus the OS-owned bulk; the exclusion is stated in the check
            // status detail so partial scope is never silent.
            yield return (programData, 3, new[]
            {
                Path.Combine(programData, "Microsoft"),
                Path.Combine(programData, "Packages"),
                Path.Combine(programData, "Package Cache"),
            });
        }
    }

    // ---------------------------------------------------------------- walking

    private void Walk(ScanContext ctx, IFindingSink sink, SetBundle sets, string root, int maxDepth,
        EnumerationBudget budget, string scopeTag, WalkStats stats, string[] excludeDirs)
    {
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((root, 0));

        while (stack.Count > 0)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            var (dir, depth) = stack.Pop();
            if (IsSelfPath(dir) || excludeDirs.Any(e => PathUnder(dir, e))) continue;

            FileInfo[] files;
            DirectoryInfo[] subDirs;
            try
            {
                var di = new DirectoryInfo(dir);
                files = di.GetFiles();
                subDirs = depth < maxDepth ? di.GetDirectories() : Array.Empty<DirectoryInfo>();
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                stats.DeniedDirs++;
                continue;
            }

            foreach (var fi in files)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                if (!budget.TryConsume()) return;                       // exhausted → caller reports Inconclusive
                if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (IsSelfPath(fi.FullName)) continue;

                try { ProcessFile(ctx, sink, sets, fi, scopeTag, stats); }
                catch (OperationCanceledException) { throw; }
                catch { stats.UnreadableFiles++; }
            }
            if (budget.Exhausted) return;

            foreach (var sub in subDirs)
            {
                if ((sub.Attributes & FileAttributes.ReparsePoint) != 0) continue;   // no junction loops
                stack.Push((sub.FullName, depth + 1));
            }
        }
    }

    private void ProcessFile(ScanContext ctx, IFindingSink sink, SetBundle sets, FileInfo fi,
        string scopeTag, WalkStats stats)
    {
        var newest = fi.LastWriteTimeUtc > fi.CreationTimeUtc ? fi.LastWriteTimeUtc : fi.CreationTimeUtc;
        if (!ctx.WithinTimeWindow(newest)) return;      // --since filter (spec §2)
        if (fi.Length == 0) return;                     // size band: skip zero-byte

        stats.FilesExamined++;
        var vendorTrusted = ctx.Signatures.IsVendorTrusted(fi.FullName);

        // CONT-003 — filename tricks (checked on every file, any extension).
        var trickHits = sets.FilenameTricks.Where(t => t.Matches(fi.Name)).ToList();
        foreach (var t in trickHits)
        {
            // A NeedsCorroboration entry is capped at Possible: a bare name match is a
            // single signal and can never alone justify a severity that pre-arms
            // remediation (spec §3 — same rule as the content indicators).
            var severity = t.NeedsCorroboration && t.Severity > Severity.Possible
                ? Severity.Possible : t.Severity;
            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, fi.FullName, $"cont-003:{t.Pattern}:{scopeTag}"),
                Severity = severity,
                Description = $"Filename manipulation: {t.Note ?? t.Pattern}. File \"{fi.Name}\" — " +
                              "these naming tricks have essentially no legitimate use.",
                Target = fi.FullName,
                FixAction = FixAction.Quarantine,
                FixParam = fi.FullName,
                Mitre = t.Mitre,
                Group = Group,
                Check = CheckFilenameTricks,
                VendorTrusted = vendorTrusted,
            });
        }

        // CONT-004 (filename part) — operator-supplied filename IOCs.
        foreach (var e in sets.CustomFilenames.Where(e => e.Matches(fi.Name)))
        {
            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, fi.FullName, $"cont-004:name:{e.Pattern}:{scopeTag}"),
                Severity = Severity.Possible,
                Description = $"Filename matches operator-supplied IOC \"{e.Pattern}\"" +
                              (e.Note is null ? "" : $" ({e.Note})") +
                              ". Name-only match, not corroborated by content or hash — custom IOC hits are " +
                              "low-precision by policy (spec §6.6) and require operator review.",
                Target = fi.FullName,
                FixAction = FixAction.None,
                Mitre = e.Mitre,
                Group = Group,
                Check = CheckIocMatch,
                VendorTrusted = vendorTrusted,
            });
        }

        var ext = fi.Extension;
        var isExec = ExecExtensions.Contains(ext);
        var isScript = ScriptExtensions.Contains(ext);
        var isDocTyped = !isExec && !isScript && sets.DocMasquerade.Count > 0
                         && sets.DocMasquerade.Any(e => e.Matches(fi.Name));

        if (!isExec && !isScript && !isDocTyped) return;    // extension gate: not a candidate

        // Magic-byte sniff — first 8 bytes only, cheap for any file size.
        var sniff = ReadChunk(fi.FullName, 0, (int)Math.Min(fi.Length, 8));
        var isPe = sniff.Length >= 2 && sniff[0] == (byte)'M' && sniff[1] == (byte)'Z';

        // Bounded content read + pattern match. Documents are only content-matched when the
        // sniff shows they are really executables; huge files are skipped, never streamed whole.
        var contentHits = new List<IndicatorEntry>();
        if (sets.Strings.Count > 0 && fi.Length <= MaxContentFileBytes
            && (isExec || isScript || (isDocTyped && isPe)))
        {
            var text = BuildTextViews(fi);
            foreach (var e in sets.Strings)
                if (e.Matches(text)) contentHits.Add(e);
        }

        // CONT-002 — executable masquerading as a document/media file.
        if (isDocTyped && isPe)
        {
            var corroborated = contentHits.Count > 0 || trickHits.Count > 0;
            sink.Report(new Finding
            {
                Id = Finding.ComputeId(Group, fi.FullName, $"cont-002:mz-masquerade:{scopeTag}"),
                Severity = corroborated ? Severity.High : Severity.Possible,
                Description = $"Executable content (PE \"MZ\" header) in a file named as {ext} — an executable " +
                              "masquerading as a document/media file." +
                              (corroborated
                                  ? " Corroborated by an additional independent signal " +
                                    "(content-string match or filename trick) on the same file."
                                  : " No second signal on this file — reported as Possible for operator review."),
                Target = fi.FullName,
                FixAction = FixAction.Quarantine,
                FixParam = fi.FullName,
                Mitre = new MitreRef("T1036.008", "Masquerading: Masquerade File Type", "Defense Evasion"),
                Group = Group,
                Check = CheckMagicMismatch,
                VendorTrusted = vendorTrusted,
            });
        }

        // CONT-001 — content rule match with the corroboration requirement (spec §3).
        if (contentHits.Count > 0)
            ReportContentFinding(sink, fi, scopeTag, contentHits,
                mismatchSignal: isDocTyped && isPe, trickSignal: trickHits.Count > 0, vendorTrusted);

        // CONT-004 (hash part) — known-bad and operator-supplied hash sets.
        if ((sets.KnownBadHashes.Count > 0 || sets.CustomHashes.Count > 0)
            && (isExec || isScript || isPe) && fi.Length <= MaxHashFileBytes)
        {
            var sha = FileHasher.Sha256(fi.FullName, MaxHashFileBytes);
            if (sha is null)
            {
                stats.UnreadableFiles++;    // hashing was in scope but could not run — not clean
            }
            else
            {
                var known = sets.KnownBadHashes.FirstOrDefault(e => e.Matches(sha));
                if (known is not null)
                {
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, fi.FullName, $"cont-004:knownbad:{sha}:{scopeTag}"),
                        Severity = Severity.Critical,
                        Description = $"SHA-256 {sha} matches the known-bad hash set" +
                                      (known.Note is null ? "" : $" ({known.Note})") +
                                      ". Hash-confirmed malicious file. Quarantine preferred over delete — " +
                                      "reversible and preserves evidence (spec §6.4).",
                        Target = fi.FullName,
                        FixAction = FixAction.Quarantine,
                        FixParam = fi.FullName,
                        Mitre = known.Mitre,
                        Group = Group,
                        Check = CheckIocMatch,
                        VendorTrusted = vendorTrusted,
                        HashConfirmed = true,
                    });
                }
                else if (sets.CustomHashes.FirstOrDefault(e => e.Matches(sha)) is { } custom)
                {
                    sink.Report(new Finding
                    {
                        Id = Finding.ComputeId(Group, fi.FullName, $"cont-004:custom:{sha}:{scopeTag}"),
                        Severity = Severity.Possible,
                        Description = $"SHA-256 {sha} matches an operator-supplied IOC hash" +
                                      (custom.Note is null ? "" : $" ({custom.Note})") +
                                      ". Custom IOC hits are low-precision by policy (spec §6.6) — reported as " +
                                      "Possible; no destructive action is pre-armed.",
                        Target = fi.FullName,
                        FixAction = FixAction.Quarantine,
                        FixParam = fi.FullName,
                        Mitre = custom.Mitre,
                        Group = Group,
                        Check = CheckIocMatch,
                        VendorTrusted = vendorTrusted,
                    });
                }
            }
        }
    }

    // ---------------------------------------------------------------- CONT-001 corroboration

    private void ReportContentFinding(IFindingSink sink, FileInfo fi, string scopeTag,
        List<IndicatorEntry> hits, bool mismatchSignal, bool trickSignal, bool vendorTrusted)
    {
        // Independent signals: each distinct indicator, plus structural signals on the file.
        var corroboration = hits.Count + (mismatchSignal ? 1 : 0) + (trickSignal ? 1 : 0);
        var maxSev = hits.Max(h => h.Severity);
        var standalone = hits.Any(h => !h.NeedsCorroboration);

        Severity severity;
        if (corroboration >= 2 || standalone)
            severity = maxSev;
        else
            severity = maxSev > Severity.Possible ? Severity.Possible : maxSev;    // single needs-corroboration hit

        if (severity > Severity.High) severity = Severity.High;    // Critical requires hash confirmation

        var names = string.Join("; ", hits.Select(h => h.Note ?? h.Pattern).Distinct().Take(5));
        var description = corroboration >= 2
            ? $"Content match: {corroboration} independent indicators on one file ({names}). " +
              "Multiple corroborating signals — this is unlikely to be documentation that merely mentions a tool."
            : $"Content match: single indicator ({names}) — NOT corroborated. A file that merely mentions a " +
              "tool or malware family (research, advisories, saved IR notes) can hit this string, so it is " +
              "capped at Possible (spec §3) and needs operator review.";

        var discriminator = "cont-001:" +
            string.Join("|", hits.Select(h => h.Pattern).OrderBy(x => x, StringComparer.OrdinalIgnoreCase)) +
            $":{scopeTag}";

        sink.Report(new Finding
        {
            Id = Finding.ComputeId(Group, fi.FullName, discriminator),
            Severity = severity,
            Description = description,
            Target = fi.FullName,
            FixAction = severity >= Severity.High ? FixAction.Quarantine : FixAction.None,
            FixParam = severity >= Severity.High ? fi.FullName : null,
            Mitre = hits.OrderByDescending(h => h.Severity).Select(h => h.Mitre).FirstOrDefault(m => m is not null),
            Group = Group,
            Check = CheckRuleMatch,
            VendorTrusted = vendorTrusted,
        });
    }

    // ---------------------------------------------------------------- status reporting

    private void ReportWalkStatuses(IFindingSink sink, SetBundle sets, EnumerationBudget budget,
        WalkStats stats, string scope)
    {
        string? problem = null;
        if (budget.Exhausted)
            problem = $"walk cut short: {budget.ExhaustedReason}";
        else if (stats.DeniedDirs > 0 || stats.UnreadableFiles > 0)
            problem = $"partial coverage: {stats.DeniedDirs} directories inaccessible, {stats.UnreadableFiles} files unreadable";

        foreach (var check in ActiveChecks(sets))
        {
            if (problem is not null)
                sink.Inconclusive(Phase, check, $"{scope}: {problem} ({stats.FilesExamined} files examined)");
            else
                sink.Completed(Phase, check, $"{scope}: {stats.FilesExamined} files examined");
        }
    }

    private static IEnumerable<string> ActiveChecks(SetBundle sets)
    {
        if (sets.Strings.Count > 0) yield return CheckRuleMatch;
        if (sets.DocMasquerade.Count > 0) yield return CheckMagicMismatch;
        if (sets.FilenameTricks.Count > 0) yield return CheckFilenameTricks;
        if (sets.HasIocs) yield return CheckIocMatch;
    }

    // ---------------------------------------------------------------- bounded IO helpers

    /// <summary>Latin-1 and UTF-16LE views of the file's head (and tail, for larger files) —
    /// wide-string constants in PE files are caught, and no file is ever read whole.</summary>
    private static string BuildTextViews(FileInfo fi)
    {
        var head = ReadChunk(fi.FullName, 0, (int)Math.Min(fi.Length, HeadReadBytes));
        var sb = new StringBuilder(head.Length * 3);
        sb.Append(Encoding.Latin1.GetString(head)).Append('\n');
        sb.Append(Encoding.Unicode.GetString(head)).Append('\n');

        if (fi.Length > head.Length + TailReadBytes)
        {
            var tail = ReadChunk(fi.FullName, fi.Length - TailReadBytes, TailReadBytes);
            sb.Append(Encoding.Latin1.GetString(tail)).Append('\n');
            sb.Append(Encoding.Unicode.GetString(tail));
        }
        return sb.ToString();
    }

    private static byte[] ReadChunk(string path, long offset, int count)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        if (offset > 0) fs.Seek(offset, SeekOrigin.Begin);
        var buf = new byte[count];
        var read = fs.ReadAtLeast(buf, count, throwOnEndOfStream: false);
        if (read < count) Array.Resize(ref buf, read);
        return buf;
    }

    // ---------------------------------------------------------------- self-exclusion

    private static readonly string[] SelfRoots = BuildSelfRoots();

    private static string[] BuildSelfRoots()
    {
        var roots = new List<string>();
        try
        {
            var baseDir = AppContext.BaseDirectory;
            if (!string.IsNullOrEmpty(baseDir))
                roots.Add(Path.TrimEndingDirectorySeparator(Path.GetFullPath(baseDir)));
        }
        catch { /* best effort — exclusion list only */ }
        try
        {
            var exeDir = Path.GetDirectoryName(Environment.ProcessPath);
            if (!string.IsNullOrEmpty(exeDir))
                roots.Add(Path.TrimEndingDirectorySeparator(Path.GetFullPath(exeDir)));
        }
        catch { /* best effort — exclusion list only */ }
        return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>The tool must never scan itself, its quarantine vault, or its report output —
    /// otherwise the signature data matches itself and every run flags the scanner (Phase 9
    /// catalog, matcher contract #6).</summary>
    private static bool IsSelfPath(string path)
    {
        foreach (var root in SelfRoots)
            if (PathUnder(path, root)) return true;

        return path.Contains(@"\ScytheQuarantine", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\ScytheVault", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\ScytheReports", StringComparison.OrdinalIgnoreCase)
            // Pre-rename vault names. A machine that ran the old build still has these
            // directories; without them the scanner reports its own quarantined evidence
            // back as findings.
            || path.Contains(@"\ZeroBreachQuarantine", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\ZeroBreachVault", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\ZeroBreachReports", StringComparison.OrdinalIgnoreCase);
    }

    private static bool PathUnder(string path, string root)
    {
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;
        return path.Length == root.Length || path[root.Length] is '\\' or '/';
    }

    // ---------------------------------------------------------------- small types

    private sealed record SetBundle(
        IReadOnlyList<IndicatorEntry> Strings,
        IReadOnlyList<IndicatorEntry> DocMasquerade,
        IReadOnlyList<IndicatorEntry> FilenameTricks,
        IReadOnlyList<IndicatorEntry> KnownBadHashes,
        IReadOnlyList<IndicatorEntry> CustomHashes,
        IReadOnlyList<IndicatorEntry> CustomFilenames)
    {
        public bool HasIocs => KnownBadHashes.Count > 0 || CustomHashes.Count > 0 || CustomFilenames.Count > 0;
    }

    private sealed class WalkStats
    {
        public int FilesExamined;
        public int DeniedDirs;
        public int UnreadableFiles;
    }
}
