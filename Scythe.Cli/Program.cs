using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using Scythe.Cli;
using Scythe.Core.Model;
using Scythe.Core.Profiles;
using Scythe.Core.Reporting;
using Scythe.Core.Scanning;
using Scythe.Core.Signatures;
using Scythe.Core.Triage;
using Scythe.Remediation;

const string Version = "1.0.0";

var options = CliOptions.Parse(args, out var parseError);
if (parseError is not null)
{
    Console.Error.WriteLine($"error: {parseError}");
    Console.Error.WriteLine();
    Console.Error.WriteLine(CliOptions.Usage);
    return 1;
}

// --log installs the transcript ONCE, here, around every command. Doing it inside RunScan
// would miss the triage conversation that precedes a derived scan, and would open the file
// twice when triage re-parses its derived command line and calls RunScan in-process.
RunTranscript? transcript = null;
if (options.LogFile is not null)
{
    try
    {
        transcript = RunTranscript.Start(options.LogFile, Version, args);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException
                                  or NotSupportedException)
    {
        // Fail before the scan, not after it. An unwritable transcript path discovered at
        // the END of a DEEP run has already cost the operator the run.
        Console.Error.WriteLine($"error: --log path unusable: {ex.Message}");
        return 1;
    }
}

try
{
    switch (options.Command)
    {
        case "help":
            Console.WriteLine(CliOptions.Usage);
            return 0;
        case "categories":
            return RunCategoriesCommand();
        case "triage":
            return RunTriage(options, args);
        case "report":
            return RunReportCommand(options);
        case "rules":
            return RunRulesCommand(options);
        case "vault":
            return RunVaultCommand(options);
        case "log":
            return RunLogCommand(options);
        default:
            return RunScan(options);
    }
}
finally
{
    // finally, not Dispose-on-success: the transcript of a run that threw is the one an
    // operator most needs to read.
    transcript?.Dispose();
}

static int RunTriage(CliOptions options, string[] originalArgs)
{
    // ---- symptom text -------------------------------------------------------------------
    string? symptomText = options.SymptomsText;
    if (options.SymptomsFile is not null)
    {
        try { symptomText = File.ReadAllText(options.SymptomsFile); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: --symptoms-file unreadable: {ex.Message}");
            return 1;
        }
    }

    var scanners = DiscoverScanners(LoadScannersAssembly());
    var validCategories = scanners.Select(s => s.Group).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    var map = SymptomMap.LoadEmbedded();
    foreach (var err in map.LoadErrors)
        Console.Error.WriteLine($"! symptom map: {err}");

    var session = new TriageSession(map, validCategories);
    symptomText ??= session.CollectSymptomsInteractively();
    var approved = session.BuildAndConfirm(symptomText, options.LlmAssist);
    if (approved is null) return 1;

    // ---- translate the approved plan into a scan command line ----------------------------
    // The plan supplies DEFAULTS: anything the operator typed alongside `triage` wins,
    // exactly like a profile (a typed --mode or --only/--skip is respected untouched).
    var scanArgs = new List<string>();
    for (var i = 0; i < originalArgs.Length; i++)
    {
        var a = originalArgs[i].ToLowerInvariant();
        if (i == 0 && a == "triage") continue;
        if (a is "--symptoms" or "--symptoms-file") { i++; continue; }
        if (a == "--llm-assist") continue;
        scanArgs.Add(originalArgs[i]);
    }
    var lower = scanArgs.Select(a => a.ToLowerInvariant()).ToHashSet();
    if (!lower.Contains("--mode") && !lower.Contains("-m"))
        scanArgs.AddRange(new[] { "--mode", approved.Mode });
    if (!lower.Contains("--only") && !lower.Contains("--skip") && approved.Categories.Count > 0)
        scanArgs.AddRange(new[] { "--only", string.Join(",", approved.Categories) });
    if (!lower.Contains("--adaptive"))
        scanArgs.Add("--adaptive"); // triage scans always adapt to what they find

    var scanOptions = CliOptions.Parse(scanArgs.ToArray(), out var scanError);
    if (scanError is not null)
    {
        Console.Error.WriteLine($"error: derived scan command line invalid ({scanError})");
        return 1;
    }
    Console.WriteLine($"\n[{approved.Summary}]");
    return RunScan(scanOptions);
}

static int RunScan(CliOptions options, bool allowChain = true)
{
    // ---- custom scan profile (spec §2) ------------------------------------------------
    // Loaded before anything else so its settings (mode, categories, IOC files) shape the
    // run; a broken profile is a hard error — never "scan anyway with other settings".
    ScanProfile? profile = null;
    if (options.ProfilePath is not null)
    {
        try
        {
            profile = ScanProfile.Load(options.ProfilePath);
        }
        catch (InvalidDataException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
        if (!options.ApplyProfile(profile, out var mergeError))
        {
            Console.Error.WriteLine($"error: {mergeError}");
            return 1;
        }
    }

    var stealth = options.Stealth;
    void Say(string s) { if (!stealth) Console.WriteLine(s); }

    var startedUtc = DateTime.UtcNow;
    var sinceUtc = options.SinceUtc; // capture once — the property is relative to "now"
    var clock = Stopwatch.StartNew();

    Say($"Scythe Scan Engine v{Version} — mode {options.Mode}" +
        (profile is null ? "" : $", profile '{profile.Name ?? Path.GetFileNameWithoutExtension(options.ProfilePath!)}'") +
        (sinceUtc is null ? "" : $", time window: last {options.SinceHours}h") +
        (options.MaxMinutes > 0 ? $", time budget {options.MaxMinutes}m" : "") +
        (options.CaseId is null ? "" : $", case {options.CaseId}"));

    // Elevation check (spec-guide §3): warn, don't refuse — degraded checks report
    // Inconclusive "requires elevation" instead of vanishing.
    bool elevated;
    using (var identity = WindowsIdentity.GetCurrent())
        elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    if (!elevated)
        Say("! not running elevated — many checks will be inconclusive (run from an admin shell for full coverage)");

    // ---- signatures -------------------------------------------------------------------
    // An operator-named file that can't be read is a hard error like a broken profile —
    // "scan anyway without the operator's indicators" is a silently different scan, and in
    // STEALTH nobody would even see the warning (spec §6.7).
    foreach (var (flag, file) in new[] { ("--rules", options.RulesFile), ("--ioc-file", options.IocFile) })
        if (file is not null && !File.Exists(file))
        {
            Console.Error.WriteLine($"error: {flag} file not found: {file} — refusing to scan without the indicators you asked for");
            return 1;
        }

    var signatures = new SignatureDb();
    var scannersAsm = LoadScannersAssembly();
    signatures.LoadEmbedded(typeof(SignatureDb).Assembly, scannersAsm);
    if (options.RulesFile is not null) signatures.LoadRulesFile(options.RulesFile);
    if (options.IocFile is not null) signatures.LoadIocFile(options.IocFile);
    foreach (var err in signatures.LoadErrors)
        Say($"! signature load: {err}");
    if (!signatures.SetNames.Any())
    {
        Console.Error.WriteLine("error: no signature sets loaded at all — engine data is missing or corrupt, refusing to scan");
        return 1;
    }

    // ---- IOC extraction from free-form text (spec §6.6) --------------------------------
    // Extraction only stages candidates; each one is armed detection-only after an
    // individual typed confirmation. STEALTH+extract is already rejected at parse time.
    if (options.ExtractIocsFile is not null)
    {
        string alertText;
        try
        {
            alertText = File.ReadAllText(options.ExtractIocsFile);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: --extract-iocs file unreadable: {ex.Message}");
            return 1;
        }
        var candidates = IocExtractor.Extract(alertText);
        new IocReviewSession(candidates, signatures, Path.GetFileName(options.ExtractIocsFile)).Run();
    }

    // ---- profiles (spec §4) -----------------------------------------------------------
    var profiles = ProfileEnumerator.Enumerate(out var profileError);
    var collector = new FindingCollector();
    if (!stealth) collector.OnFinding = ConsoleScanLogger.PrintFinding;
    if (profileError is not null)
        collector.ReportCheck(new CheckStatus(0, "profile enumeration", CheckOutcome.Inconclusive, profileError));

    // Signature entries that failed to load (bad regex, malformed set) shrink detection
    // coverage — they must reach the report and the exit code, not just the console, which
    // STEALTH doesn't even have (spec §6.7).
    foreach (var err in signatures.LoadErrors)
        collector.ReportCheck(new CheckStatus(0, "signature loading", CheckOutcome.Inconclusive,
            $"indicator(s) not loaded: {err}"));

    using var hiveLoader = new HiveLoader();
    if (options.LoadHives)
    {
        foreach (var (sid, why) in hiveLoader.LoadMissingHives(profiles))
        {
            var name = profiles.FirstOrDefault(p => p.Sid == sid)?.UserName ?? sid;
            collector.ReportCheck(new CheckStatus(0, "hive loading",
                CheckOutcome.Inconclusive, $"profile {name}: {why}"));
        }
    }
    var unmounted = profiles.Where(p => !p.HiveMounted).Select(p => p.UserName).ToList();
    Say($"profiles: {profiles.Count} found" + (unmounted.Count == 0 ? ", all hives mounted"
        : $"; hive NOT mounted for: {string.Join(", ", unmounted)}" +
          (options.LoadHives ? "" : " (per-user registry checks for these are reported as unchecked; opt in with --load-hives)")));

    // ---- scanners ---------------------------------------------------------------------
    var scanners = DiscoverScanners(scannersAsm);
    if (scanners.Count == 0)
    {
        Console.Error.WriteLine("error: no scanners found in Scythe.Scanners — nothing to run");
        return 1;
    }

    // ---- category selection (custom scans) --------------------------------------------
    var excludedGroups = CategorySelection.ComputeExcluded(
        scanners, options.Only, options.Skip, out var selectionError);
    if (selectionError is not null)
    {
        Console.Error.WriteLine($"error: {selectionError}");
        return 1;
    }
    if (excludedGroups is { Count: > 0 })
        Say($"category selection: excluding {string.Join(", ", excludedGroups)} — these areas will be reported as UNCHECKED");

    if (options.SaveProfilePath is not null)
    {
        // Written before the scan so a long run isn't a prerequisite for keeping the
        // definition. Core stays read-only; the CLI owns this operator-requested write.
        try
        {
            var parent = Path.GetDirectoryName(Path.GetFullPath(options.SaveProfilePath));
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
            var name = Path.GetFileNameWithoutExtension(options.SaveProfilePath);
            File.WriteAllText(options.SaveProfilePath, options.ToProfile(name).ToJson());
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: cannot save profile to {options.SaveProfilePath}: {ex.Message}");
            return 1;
        }
        Say($"custom-scan profile saved: {options.SaveProfilePath} (re-run with --profile \"{options.SaveProfilePath}\")");
    }

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
    // Hard time budget (--max-minutes): a deadline is a cooperative cancel, and PhaseRunner
    // reports every phase that never ran as unchecked — a timed-out scan can't read as clean.
    if (options.MaxMinutes > 0)
        cts.CancelAfter(TimeSpan.FromMinutes(options.MaxMinutes));

    // ---- adaptive escalation (--adaptive / triage) --------------------------------------
    // Detection-only: findings arm their extracted IPs/domains/hashes/filenames into the
    // custom.* sets between phases, so later phases hunt what earlier phases surfaced.
    // Nothing escalation-derived can reach a destructive path — armed entries are POSSIBLE
    // severity with no fix action, same discipline as operator IOCs (spec §6.6).
    EscalationEngine? escalation = null;
    if (options.Adaptive)
    {
        escalation = new EscalationEngine(signatures);
        if (!stealth) escalation.OnEscalation = msg => Console.WriteLine($"  ~ adaptive: {msg}");
        Say("adaptive scanning: ON — leads found mid-scan sharpen the later phases");
    }

    var ctx = new ScanContext
    {
        Depth = options.Depth,
        SinceUtc = sinceUtc,
        Signatures = signatures,
        Profiles = profiles,
        HiveLoadingEnabled = options.LoadHives,
        Log = stealth ? NullScanLogger.Instance : new ConsoleScanLogger(scanners.Max(s => s.Phase)),
        Cancel = cts.Token,
        BudgetScale = options.BudgetScale,
    };

    new PhaseRunner(scanners, excludedGroups, escalation).Run(ctx, collector);
    clock.Stop();

    // ---- baseline diff (spec §2) ------------------------------------------------------
    var findings = collector.Findings;
    var suppressed = 0;
    ScanReport.BaselineJson? baselineRecord = null;
    if (options.BaselinePath is not null)
    {
        try
        {
            var baseline = Baseline.Load(options.BaselinePath);
            // A wrong baseline silently hides real findings — surface sanity problems
            // (foreign host, stale, future-dated) before its suppression is applied.
            var warnings = baseline.SafetyWarnings(Environment.MachineName, DateTime.UtcNow);
            foreach (var warning in warnings)
                Console.Error.WriteLine($"! baseline: {warning}");
            (findings, suppressed) = baseline.Diff(findings);
            // The report must record that a diff happened, what it hid, and the warnings —
            // a diffed report indistinguishable from a clean one is the §6.7 sin, and in
            // STEALTH the report is the ONLY output there is.
            baselineRecord = new ScanReport.BaselineJson
            {
                Path = Path.GetFullPath(options.BaselinePath),
                Host = baseline.Host,
                CreatedUtc = baseline.CreatedUtc,
                Suppressed = suppressed,
                Warnings = warnings.ToList(),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: baseline unusable ({ex.Message}) — reporting ALL findings instead of a diff");
            collector.ReportCheck(new CheckStatus(0, "baseline diff", CheckOutcome.Inconclusive,
                $"baseline {options.BaselinePath} unusable ({ex.Message}) — ALL findings reported, no diff applied"));
        }
    }

    // A signature match that timed out never fired for its artifact — that is "couldn't
    // evaluate", not "didn't match", and must be disclosed (spec §6.7).
    var matchTimeouts = signatures.TotalMatchTimeouts();
    if (matchTimeouts > 0)
        collector.ReportCheck(new CheckStatus(0, "signature matching", CheckOutcome.Inconclusive,
            $"{matchTimeouts} indicator evaluation(s) timed out — those indicators did not fire for the affected artifacts"));

    var summary = ScanSummary.Build(findings, collector.Checks, clock.Elapsed);
    // The report's mode string records how the scan was shaped — a profile-narrowed run
    // must be distinguishable from a stock preset when the report is read later.
    var modeDescription = options.Mode
        + (profile is null ? "" : $" (profile: {profile.Name ?? Path.GetFileNameWithoutExtension(options.ProfilePath!)})")
        + (excludedGroups is { Count: > 0 } ? $" [excluded: {string.Join(",", excludedGroups)}]" : "");
    var report = ScanReport.Build(Version, modeDescription, startedUtc, findings, collector.Checks.ToList(), summary,
        collector.PhaseTimings, options.CaseId, options.OperatorName, baselineRecord);

    // ---- reports (spec §7) ------------------------------------------------------------
    Directory.CreateDirectory(options.OutputDir);
    var stem = Path.Combine(options.OutputDir, $"scythescan-{Environment.MachineName}-{startedUtc:yyyyMMdd-HHmmss}");
    if (stealth)
    {
        report.WriteCompressed(stem + ".json.gz");
    }
    else
    {
        File.WriteAllLines(stem + ".jsonl", findings.Select(FindingJson.ToJsonLine));
        File.WriteAllText(stem + ".json", report.ToJson());
        if (options.Html) HtmlReport.Write(stem + ".html", report);
    }

    if (options.SaveBaselinePath is not null)
    {
        // Baseline covers everything seen this run, pre-diff — a baseline built from a
        // diffed list would "forget" the previously-known findings it suppressed.
        Baseline.FromFindings(collector.Findings).Save(options.SaveBaselinePath);
        Say($"baseline saved: {options.SaveBaselinePath} ({collector.Findings.Count} finding id(s))");
    }

    // ---- end-of-run summary (spec §7, §6.7) -------------------------------------------
    if (!stealth)
    {
        var problems = collector.Checks
            .Where(c => c.Outcome != CheckOutcome.Completed)
            .OrderBy(c => c.Phase).ToList();
        if (problems.Count > 0)
        {
            Console.WriteLine("\nChecks that did NOT complete (these areas are NOT cleared — spec §6.7):");
            foreach (var c in problems)
                Console.WriteLine($"  [{c.Outcome.ToString().ToLowerInvariant(),-12}] phase {c.Phase}: {c.Check} — {c.Detail}");
        }

        Console.WriteLine();
        Console.WriteLine($"=== Scan complete in {clock.Elapsed:hh\\:mm\\:ss} ===");
        Console.WriteLine($"  CRITICAL {summary.Critical}   HIGH {summary.High}   POSSIBLE {summary.Possible}   INFO {summary.Info}" +
                          (suppressed > 0 ? $"   (+{suppressed} known finding(s) suppressed by baseline)" : ""));
        Console.WriteLine($"  checks: {summary.ChecksCompleted} completed, {summary.ChecksInconclusive} inconclusive, {summary.ChecksSkipped} skipped/unchecked");
        Console.WriteLine($"  verdict: {summary.Verdict}");
        Console.WriteLine($"  reports: {stem}.json / .jsonl" + (options.Html ? " / .html" : ""));
    }

    if (options.Interactive && !cts.IsCancellationRequested)
        new RemediationSession(findings).Run();

    // Exit codes: 0 clean+complete, 2 findings present, 3 nothing found but coverage gaps.
    var exitCode = summary.Critical + summary.High + summary.Possible > 0 ? 2
        : summary.ChecksInconclusive > 0 || summary.ChecksSkipped > 0 ? 3 : 0;

    // ---- leads + follow-up (adaptive) ----------------------------------------------------
    if (escalation is { Leads.Count: > 0 } && FollowUpPlan.Build(escalation.Leads) is { } followUp)
    {
        var (leadsPath, iocPath, profilePath) = followUp.Write(options.OutputDir, Path.GetFileName(stem));
        Say($"\nadaptive: {escalation.Leads.Count} lead(s) recorded -> {leadsPath}");
        Say($"adaptive: DEEP follow-up scan generated -> {profilePath}");
        Say($"          (its IOC list: {iocPath})");

        if (allowChain && !stealth && !cts.IsCancellationRequested)
        {
            // Ask-then-chain: the deeper pass is generated either way; running it now is the
            // operator's call. One level only — the follow-up never chains a third pass.
            Console.Write($"Run the deeper follow-up scan now ({followUp.Mode}, all categories, leads armed)? [y/N] > ");
            if (Console.ReadLine()?.Trim().ToLowerInvariant() == "y")
            {
                var followArgs = new List<string> { "--profile", profilePath, "--output-dir", options.OutputDir, "--adaptive" };
                if (options.Html) followArgs.Add("--html");
                if (options.LoadHives) followArgs.Add("--load-hives");
                if (options.Interactive) followArgs.Add("-i");
                if (options.CaseId is not null) followArgs.AddRange(new[] { "--case", options.CaseId });
                if (options.OperatorName is not null) followArgs.AddRange(new[] { "--operator", options.OperatorName });
                var followOptions = CliOptions.Parse(followArgs.ToArray(), out var followError);
                if (followError is not null)
                {
                    Console.Error.WriteLine($"error: follow-up command line invalid ({followError}) — run it manually:");
                    Console.Error.WriteLine($"  scythescan --profile \"{profilePath}\"");
                }
                else
                {
                    Console.WriteLine("\n=== Follow-up scan (pass 2) ===");
                    var followExit = RunScan(followOptions, allowChain: false);
                    // Findings anywhere beat coverage gaps anywhere beat clean.
                    exitCode = exitCode == 2 || followExit == 2 ? 2
                        : exitCode == 3 || followExit == 3 ? 3 : 0;
                }
            }
            else
            {
                Console.WriteLine($"  run it later with: scythescan --profile \"{profilePath}\"");
            }
        }
    }

    return exitCode;
}

static Assembly LoadScannersAssembly()
{
    // Loaded by name rather than a typeof() anchor so the CLI compiles and runs even while
    // the scanners assembly is empty; DiscoverScanners handles "no types yet".
    return Assembly.Load(new AssemblyName("Scythe.Scanners"));
}

static IReadOnlyList<IScanner> DiscoverScanners(Assembly asm)
{
    var list = new List<IScanner>();
    foreach (var type in asm.GetTypes())
    {
        if (type.IsAbstract || !typeof(IScanner).IsAssignableFrom(type)) continue;
        if (Activator.CreateInstance(type) is IScanner s) list.Add(s);
    }
    return list;
}

static int RunCategoriesCommand()
{
    // Reads the categories off the real scanner list, so this can never drift from the build.
    var scanners = DiscoverScanners(LoadScannersAssembly());
    if (scanners.Count == 0)
    {
        Console.Error.WriteLine("error: no scanners found in Scythe.Scanners");
        return 1;
    }
    Console.WriteLine("Detection categories in this build (use with --only/--skip or a profile):\n");
    Console.WriteLine($"  {"phase",-6} {"category",-18} {"min mode",-9} name");
    foreach (var s in scanners.OrderBy(s => s.Phase))
        Console.WriteLine($"  {s.Phase,-6} {s.Group,-18} {s.MinDepth.ToString().ToUpperInvariant(),-9} {s.Name}");
    return 0;
}

static int RunReportCommand(CliOptions options)
{
    // Re-renders a saved report — the way a STEALTH run's single .json.gz blob gets read
    // without rescanning. Exit codes mirror a live scan so scripts can consume either.
    if (options.SubCommand != "show" || options.SubArgument is null)
    {
        Console.Error.WriteLine("usage: scythescan report show <file.json | file.json.gz>");
        return 1;
    }
    ScanReport report;
    try
    {
        report = ScanReport.Load(options.SubArgument);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"error: {ex.Message}");
        return 1;
    }

    var s = report.Summary;
    Console.WriteLine($"{report.Tool} v{report.Version} — {report.Host} — mode {report.Mode}");
    Console.WriteLine($"  started: {report.StartedUtc:u}   elapsed: {TimeSpan.FromSeconds(s.ElapsedSeconds):hh\\:mm\\:ss}" +
                      (report.CaseId is null ? "" : $"   case: {report.CaseId}") +
                      (report.Operator is null ? "" : $"   operator: {report.Operator}"));
    Console.WriteLine($"  CRITICAL {s.Critical}   HIGH {s.High}   POSSIBLE {s.Possible}   INFO {s.Info}");
    Console.WriteLine($"  checks: {s.ChecksCompleted} completed, {s.ChecksInconclusive} inconclusive, {s.ChecksSkipped} skipped/unchecked");
    Console.WriteLine($"  verdict: {s.Verdict}");
    if (report.Baseline is { } bl)
    {
        Console.WriteLine($"  BASELINE DIFF APPLIED: {bl.Suppressed} known finding(s) suppressed (baseline from {bl.Host}, created {bl.CreatedUtc:u})");
        foreach (var w in bl.Warnings) Console.WriteLine($"    ! {w}");
    }

    if (report.Findings.Count > 0)
    {
        Console.WriteLine("\nFindings:");
        foreach (var f in report.Findings)
            Console.WriteLine($"  [{f.Severity.ToUpperInvariant(),-8}] {f.Group,-16} {f.Target}\n             {f.Description}");
    }

    var problems = report.Checks.Where(c => c.Outcome != "completed").ToList();
    if (problems.Count > 0)
    {
        Console.WriteLine("\nChecks that did NOT complete (these areas are NOT cleared — spec §6.7):");
        foreach (var c in problems)
            Console.WriteLine($"  [{c.Outcome,-12}] phase {c.Phase}: {c.Check} — {c.Detail}");
    }

    if (report.Phases is { Count: > 0 })
    {
        Console.WriteLine("\nPhase timings:");
        foreach (var p in report.Phases)
            Console.WriteLine($"  phase {p.Phase,2}  {p.ElapsedSeconds,8:F3}s  {p.Findings,3} finding(s)  {p.Name}");
    }

    if (s.Critical + s.High + s.Possible > 0) return 2;
    if (s.ChecksInconclusive > 0 || s.ChecksSkipped > 0) return 3;
    return 0;
}

static int RunRulesCommand(CliOptions options)
{
    // Validates a rules/IOC file the same way a scan would load it, without scanning —
    // so a typo'd regex or malformed JSON is caught at authoring time, not mid-engagement.
    if (options.SubCommand != "lint" || options.SubArgument is null)
    {
        Console.Error.WriteLine("usage: scythescan rules lint <rules.json | iocs.txt>");
        return 1;
    }
    if (!File.Exists(options.SubArgument))
    {
        Console.Error.WriteLine($"error: file not found: {options.SubArgument}");
        return 1;
    }

    var db = new SignatureDb();
    db.LoadIocFile(options.SubArgument); // handles both JSON rules shape and plain-text IOC lines

    var totalEntries = 0;
    foreach (var set in db.SetNames.OrderBy(n => n))
    {
        var count = db.Set(set).Count;
        totalEntries += count;
        Console.WriteLine($"  {set,-28} {count,5} entr{(count == 1 ? "y" : "ies")}");
    }
    if (db.VendorTrusted.Count > 0)
        Console.WriteLine($"  {"(vendor-trusted names)",-28} {db.VendorTrusted.Count,5}");

    foreach (var err in db.LoadErrors)
        Console.Error.WriteLine($"  ERROR: {err}");

    if (db.LoadErrors.Count > 0)
    {
        Console.Error.WriteLine($"\nlint FAILED: {db.LoadErrors.Count} error(s) — entries listed above still load, but fix the errors before an engagement.");
        return 1;
    }
    if (totalEntries == 0 && db.VendorTrusted.Count == 0)
    {
        Console.Error.WriteLine("lint: file loaded but contains no indicators at all — check the file shape.");
        return 1;
    }
    Console.WriteLine($"\nlint OK: {totalEntries} indicator(s) across {db.SetNames.Count()} set(s).");
    return 0;
}

static int RunVaultCommand(CliOptions options)
{
    var vault = new QuarantineVault();
    switch (options.SubCommand)
    {
        case "list":
        {
            var items = vault.List();
            if (items.Count == 0) { Console.WriteLine("vault is empty."); return 0; }
            foreach (var m in items.OrderBy(m => m.QuarantinedUtc))
                Console.WriteLine($"  {m.QuarantineId}  {m.QuarantinedUtc:u}  {m.SizeBytes,10:N0} B  {m.OriginalPath}");
            return 0;
        }
        case "restore" when options.SubArgument is not null:
        {
            try
            {
                var m = vault.Restore(options.SubArgument);
                new ActionLog().Append("restore_from_vault", m.OriginalPath, "ok",
                    $"vault id {m.QuarantineId}", m.FindingId);
                Console.WriteLine($"restored: {m.OriginalPath}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"restore failed: {ex.Message}");
                return 1;
            }
        }
        case "verify":
        {
            // Read-only integrity check: proves vaulted evidence still matches the SHA-256
            // recorded at quarantine time (companion to the action log, spec §6.10).
            var results = vault.VerifyAll();
            if (results.Count == 0) { Console.WriteLine("vault is empty — nothing to verify."); return 0; }
            var bad = 0;
            foreach (var r in results.OrderBy(r => r.Manifest.QuarantinedUtc))
            {
                var tag = r.State switch
                {
                    QuarantineVault.VaultItemState.Ok => "ok      ",
                    QuarantineVault.VaultItemState.HashUnknown => "no-hash ",
                    QuarantineVault.VaultItemState.FileMissing => "MISSING ",
                    _ => "TAMPERED",
                };
                if (r.State is QuarantineVault.VaultItemState.HashMismatch or QuarantineVault.VaultItemState.FileMissing) bad++;
                Console.WriteLine($"  [{tag}] {r.Manifest.QuarantineId}  {r.Manifest.OriginalPath} — {r.Detail}");
            }
            if (bad > 0)
            {
                Console.Error.WriteLine($"\nvault verify FAILED: {bad} of {results.Count} item(s) missing or altered.");
                return 2;
            }
            Console.WriteLine($"\nvault verify OK: {results.Count} item(s) intact.");
            return 0;
        }
        case "purge" when options.SubArgument is not null:
        {
            // Purge is the one irreversible vault operation, so it gets the full §6
            // treatment: show what will be destroyed, typed CONFIRM, action-log entry.
            try
            {
                var m = vault.List().FirstOrDefault(m => m.QuarantineId == options.SubArgument);
                if (m is null)
                {
                    Console.Error.WriteLine($"purge failed: no quarantined item with id {options.SubArgument}");
                    return 1;
                }
                Console.WriteLine($"About to PERMANENTLY delete this quarantined file (cannot be restored afterwards):");
                Console.WriteLine($"  id:            {m.QuarantineId}");
                Console.WriteLine($"  original path: {m.OriginalPath}");
                Console.WriteLine($"  sha256:        {m.Sha256 ?? "(unknown)"}");
                Console.WriteLine($"  size:          {m.SizeBytes:N0} B   quarantined: {m.QuarantinedUtc:u}");
                Console.Write($"Type {ConfirmationGate.RequiredWord} to proceed, anything else to cancel > ");
                if (!ConfirmationGate.IsConfirmed(Console.ReadLine()))
                {
                    Console.WriteLine("  not confirmed — no action taken.");
                    return 1;
                }
                var purged = vault.Purge(options.SubArgument);
                new ActionLog().Append("purge_from_vault", purged.OriginalPath, "ok",
                    $"vault id {purged.QuarantineId}; sha256 {purged.Sha256 ?? "unknown"}", purged.FindingId);
                Console.WriteLine($"purged: {purged.QuarantineId} (was {purged.OriginalPath})");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"purge failed: {ex.Message}");
                return 1;
            }
        }
        default:
            Console.Error.WriteLine("usage: scythescan vault list | verify | restore <id> | purge <id>");
            return 1;
    }
}

static int RunLogCommand(CliOptions options)
{
    var log = new ActionLog();
    switch (options.SubCommand)
    {
        case "verify":
        {
            var result = log.VerifyChain();
            switch (result.State)
            {
                case ActionLog.ChainState.Intact:
                    Console.WriteLine($"action log OK — hash chain verifies and the anchor confirms the " +
                                      $"end of the log ({result.Entries} entries)");
                    return 0;
                case ActionLog.ChainState.Truncated:
                    Console.Error.WriteLine($"TAMPER EVIDENT: {result.Why}");
                    return 2;
                case ActionLog.ChainState.Broken:
                    Console.Error.WriteLine($"TAMPER EVIDENT: chain broken at seq {result.BrokenSeq}: {result.Why}");
                    return 2;
                default:
                    // Links verify but completeness is unprovable. Not "OK" (spec §6.7) and not
                    // tamper evidence either — it exits 3 like any other coverage gap.
                    Console.Error.WriteLine($"UNVERIFIABLE: {result.Why} ({result.Entries} entries read)");
                    return 3;
            }
        }
        case "show":
            foreach (var e in log.ReadAll())
                Console.WriteLine($"  #{e.Seq}  {e.Utc:u}  {e.Operator}  {e.Action}  {e.Target}  => {e.Result}" +
                                  (e.Detail is null ? "" : $"  ({e.Detail})"));
            return 0;
        default:
            Console.Error.WriteLine("usage: scythescan log verify | scythescan log show");
            return 1;
    }
}
