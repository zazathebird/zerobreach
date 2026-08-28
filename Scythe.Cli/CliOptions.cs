using Scythe.Core.Scanning;

namespace Scythe.Cli;

/// <summary>Parsed command line. Spec §2 modes plus the cross-cutting flags.</summary>
public sealed class CliOptions
{
    public string Command { get; private set; } = "scan";   // scan | triage | categories | report | rules | vault | log | help
    public string? SubCommand { get; private set; }          // vault: list/restore/purge, log: verify/show, report: show, rules: lint
    public string? SubArgument { get; private set; }         // vault restore <id>, report show <file>, rules lint <file>

    public string Mode { get; private set; } = "QUICK";      // QUICK | FULL | DEEP | STEALTH
    public int SinceHours { get; private set; }
    public int MaxMinutes { get; private set; }
    public string? CaseId { get; private set; }
    public string? OperatorName { get; private set; }
    public string? IocFile { get; private set; }
    public string? RulesFile { get; private set; }
    public string? ExtractIocsFile { get; private set; }
    public string? LogFile { get; private set; }

    // Triage (symptom-driven scan creation) and adaptive scanning.
    public string? SymptomsText { get; private set; }
    public string? SymptomsFile { get; private set; }
    public bool LlmAssist { get; private set; }
    public bool Adaptive { get; private set; }
    public string? BaselinePath { get; private set; }
    public string? SaveBaselinePath { get; private set; }
    public bool LoadHives { get; private set; }
    public bool Interactive { get; private set; }
    public bool Html { get; private set; }
    public string OutputDir { get; private set; } =
        Path.Combine(Environment.CurrentDirectory, "reports");

    // Custom scans (spec §2): a saved profile plus inline category selection.
    public string? ProfilePath { get; private set; }
    public string? SaveProfilePath { get; private set; }
    public IReadOnlyList<string> Only => _only;
    public IReadOnlyList<string> Skip => _skip;
    private List<string> _only = new();
    private List<string> _skip = new();

    // Which fields the command line set EXPLICITLY — a profile fills in only the rest,
    // so a flag typed by the operator always beats the same setting in a profile file.
    private bool _modeSet, _sinceSet, _iocSet, _rulesSet, _htmlSet, _categoriesSet;

    public bool Stealth => Mode == "STEALTH";

    /// <summary>STEALTH is an output mode at FULL depth, not a depth of its own (spec §2).</summary>
    public ScanDepth Depth => Mode switch
    {
        "QUICK" => ScanDepth.Quick,
        "DEEP" => ScanDepth.Deep,
        _ => ScanDepth.Full,
    };

    /// <summary>Budget scale by depth: deeper modes walk more before cutting off (spec §4).</summary>
    public double BudgetScale => Depth switch
    {
        ScanDepth.Quick => 1.0,
        ScanDepth.Full => 2.0,
        _ => 5.0,
    };

    public DateTime? SinceUtc => SinceHours > 0 ? DateTime.UtcNow.AddHours(-SinceHours) : null;

    public static CliOptions Parse(string[] args, out string? error)
    {
        error = null;
        var o = new CliOptions();
        var i = 0;

        if (args.Length > 0 && !args[0].StartsWith('-'))
        {
            o.Command = args[0].ToLowerInvariant();
            i = 1;
            if (o.Command is "vault" or "log" or "report" or "rules")
            {
                if (i < args.Length && !args[i].StartsWith('-')) o.SubCommand = args[i++].ToLowerInvariant();
                if (i < args.Length && !args[i].StartsWith('-')) o.SubArgument = args[i++];
                if (i < args.Length)
                { error = $"unexpected argument '{args[i]}' after '{o.Command} {o.SubCommand}'"; return o; }
                // Subcommands that take no argument must reject one — a discarded token can
                // mean the operator thought they scoped the command when they didn't.
                if (o.SubArgument is not null && (o.Command, o.SubCommand)
                        is ("vault", "list") or ("vault", "verify") or ("log", "verify") or ("log", "show"))
                    error = $"'{o.Command} {o.SubCommand}' does not take an argument (got '{o.SubArgument}')";
                return o;
            }
            if (o.Command is not ("scan" or "triage" or "help" or "categories"))
            {
                error = $"unknown command '{o.Command}' (expected scan, triage, categories, report, rules, vault, log, help)";
                return o;
            }
        }

        for (; i < args.Length; i++)
        {
            var a = args[i].ToLowerInvariant();
            string Next(string flag)
            {
                if (i + 1 >= args.Length) throw new ArgumentException($"{flag} requires a value");
                // Refuse to swallow the next option as a value: `--case --html` must be an
                // error, not a case id of "--html" plus a silently missing HTML report.
                if (args[i + 1].StartsWith('-'))
                    throw new ArgumentException(
                        $"{flag} requires a value (got '{args[i + 1]}', which looks like another option)");
                return args[++i];
            }

            try
            {
                switch (a)
                {
                    case "--mode" or "-m":
                        o.Mode = Next(a).ToUpperInvariant();
                        o._modeSet = true;
                        if (o.Mode is not ("QUICK" or "FULL" or "DEEP" or "STEALTH"))
                        { error = $"invalid mode '{o.Mode}' (QUICK, FULL, DEEP, STEALTH)"; return o; }
                        break;
                    case "--since-hours":
                        if (!int.TryParse(Next(a), out var h) || h < 0)
                        { error = "--since-hours requires a non-negative integer"; return o; }
                        o.SinceHours = h;
                        o._sinceSet = true;
                        break;
                    case "--ioc-file": o.IocFile = Next(a); o._iocSet = true; break;
                    case "--rules": o.RulesFile = Next(a); o._rulesSet = true; break;
                    case "--extract-iocs": o.ExtractIocsFile = Next(a); break;
                    case "--log": o.LogFile = Next(a); break;
                    case "--max-minutes":
                        if (!int.TryParse(Next(a), out var mm) || mm <= 0)
                        { error = "--max-minutes requires a positive integer"; return o; }
                        o.MaxMinutes = mm;
                        break;
                    case "--case": o.CaseId = Next(a); break;
                    case "--operator": o.OperatorName = Next(a); break;
                    case "--symptoms": o.SymptomsText = Next(a); break;
                    case "--symptoms-file": o.SymptomsFile = Next(a); break;
                    case "--llm-assist": o.LlmAssist = true; break;
                    case "--adaptive": o.Adaptive = true; break;
                    case "--only":
                        o._only = SplitList(Next(a));
                        o._categoriesSet = true;
                        if (o._only.Count == 0) { error = "--only requires at least one category name"; return o; }
                        break;
                    case "--skip":
                        o._skip = SplitList(Next(a));
                        o._categoriesSet = true;
                        if (o._skip.Count == 0) { error = "--skip requires at least one category name"; return o; }
                        break;
                    case "--profile": o.ProfilePath = Next(a); break;
                    case "--save-profile": o.SaveProfilePath = Next(a); break;
                    case "--baseline": o.BaselinePath = Next(a); break;
                    case "--save-baseline": o.SaveBaselinePath = Next(a); break;
                    case "--load-hives": o.LoadHives = true; break;
                    case "--interactive" or "-i": o.Interactive = true; break;
                    case "--html": o.Html = true; o._htmlSet = true; break;
                    case "--output-dir" or "-o": o.OutputDir = Next(a); break;
                    case "--help" or "-h" or "-?": o.Command = "help"; break;
                    default:
                        error = $"unknown option '{args[i]}'";
                        return o;
                }
            }
            catch (ArgumentException ex)
            {
                error = ex.Message;
                return o;
            }
        }

        if (o._only.Count > 0 && o._skip.Count > 0)
        { error = "--only and --skip cannot be combined — pick one way to select categories"; return o; }
        if (o.Stealth && o.Interactive)
        { error = "--interactive cannot be combined with STEALTH mode (stealth is silent by definition)"; return o; }
        if (o.Stealth && o.ExtractIocsFile is not null)
        { error = "--extract-iocs cannot be combined with STEALTH mode — every extracted " +
                  "indicator needs an individual operator confirmation at the console (spec §6.6)"; return o; }
        if (o.Stealth && o.LogFile is not null)
        { error = "--log cannot be combined with STEALTH mode — a stealth run writes no console " +
                  "output, so the transcript would be empty; read the .json.gz report instead"; return o; }
        if (o.SymptomsText is not null && o.SymptomsFile is not null)
        { error = "--symptoms and --symptoms-file cannot be combined — pick one source"; return o; }
        if (o.Command != "triage" && (o.SymptomsText is not null || o.SymptomsFile is not null || o.LlmAssist))
        { error = "--symptoms/--symptoms-file/--llm-assist only apply to the triage command (scythescan triage ...)"; return o; }
        if (o.Command == "triage" && o.Stealth)
            error = "triage cannot run in STEALTH mode — deriving and confirming the scan plan is a console conversation";
        return o;
    }

    /// <summary>
    /// Applies a loaded scan profile as DEFAULTS: any setting the operator typed explicitly
    /// on the command line wins over the profile. Category selection (only/skip) is one
    /// unit — if the command line sets either, the profile's selection is ignored entirely
    /// rather than half-merged into something nobody asked for.
    /// Returns false with an error when the merged result is invalid.
    /// </summary>
    public bool ApplyProfile(ScanProfile profile, out string? error)
    {
        error = null;
        if (!_modeSet && profile.Mode is not null) Mode = profile.Mode;
        if (!_sinceSet && profile.SinceHours is int sh) SinceHours = sh;
        if (!_iocSet && profile.IocFile is not null) IocFile = profile.IocFile;
        if (!_rulesSet && profile.RulesFile is not null) RulesFile = profile.RulesFile;
        if (!_htmlSet && profile.Html is bool html) Html = html;
        if (!_categoriesSet)
        {
            if (profile.Only is { Count: > 0 }) _only = profile.Only.ToList();
            else if (profile.Skip is { Count: > 0 }) _skip = profile.Skip.ToList();
        }

        if (Stealth && Interactive)
        {
            error = "profile sets STEALTH mode, which cannot be combined with --interactive";
            return false;
        }
        if (Stealth && LogFile is not null)
        {
            error = "profile sets STEALTH mode, which cannot be combined with --log " +
                    "(a stealth run writes no console output to transcribe)";
            return false;
        }
        if (Stealth && ExtractIocsFile is not null)
        {
            error = "profile sets STEALTH mode, which cannot be combined with --extract-iocs " +
                    "(extracted indicators need per-item console confirmation, spec §6.6)";
            return false;
        }
        return true;
    }

    /// <summary>The effective options as a saveable custom-scan profile (--save-profile).
    /// Deliberately excludes --load-hives, --interactive, and baseline paths — those are
    /// per-run decisions a profile file must not preconfigure (spec §4/§6).</summary>
    public ScanProfile ToProfile(string profileName) => new()
    {
        Name = profileName,
        Description = $"saved with --save-profile from a {Mode} scan command line",
        Mode = Mode,
        SinceHours = SinceHours > 0 ? SinceHours : null,
        Only = _only.Count > 0 ? _only.ToList() : null,
        Skip = _skip.Count > 0 ? _skip.ToList() : null,
        IocFile = IocFile is null ? null : Path.GetFullPath(IocFile),
        RulesFile = RulesFile is null ? null : Path.GetFullPath(RulesFile),
        Html = Html ? true : null,
    };

    private static List<string> SplitList(string value) =>
        value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
             .Distinct(StringComparer.OrdinalIgnoreCase)
             .ToList();

    public const string Usage = """
        Scythe Scan Engine — technician-run, local-only IR sweep

        usage:
          scythescan [scan] [options]        run a scan (default command)
          scythescan triage [options]        describe the machine's symptoms in plain text and
                                         let the engine derive a matching custom scan
          scythescan categories              list the detection categories/phases this build has
          scythescan report show <file>      re-render a saved report (.json or STEALTH .json.gz)
          scythescan rules lint <file>       validate a rules/IOC file without scanning
          scythescan vault list              list quarantined files
          scythescan vault verify            integrity-check vaulted files against their manifests
          scythescan vault restore <id>      restore a quarantined file to its original path
          scythescan vault purge <id>        PERMANENTLY delete a quarantined file (typed CONFIRM)
          scythescan log verify              verify the tamper-evident action log hash chain
          scythescan log show                print the action log
          scythescan help                    this text

        scan options:
          -m, --mode <M>          QUICK (default) | FULL | DEEP | STEALTH
                                  STEALTH = FULL depth, no console output, one .json.gz blob
          --since-hours <N>       only flag artifacts created/modified in the last N hours
          --max-minutes <N>       hard time budget: cancel the scan after N minutes; phases
                                  that never ran are reported as UNCHECKED, never silent
          --case <id>             engagement/case id recorded in the report metadata
          --operator <name>       operator name recorded in the report metadata
          --ioc-file <path>       custom IOC file (JSON rules or one indicator per line)
          --rules <path>          extra signature rules file (same shape as embedded JSON)
          --extract-iocs <path>   extract IOC candidates from free-form text (a pasted alert,
                                  a threat-intel note); each candidate is shown with its source
                                  line and armed for THIS scan only after you confirm it
                                  individually — never in bulk, never automatically (spec §6.6)

        custom scans:
          --only <cats>           run ONLY these detection categories (comma-separated)
          --skip <cats>           run everything EXCEPT these categories
                                  categories: Persistence, DefenseEvasion, C2,
                                  CredentialAccess, Ransomware, EmailResidue, RootkitBoot,
                                  AclIntegrity, ContentScan, EventLog
                                  excluded phases are reported as UNCHECKED, never silent
          --profile <path>        load a saved custom-scan profile (JSON); flags typed on
                                  the command line override the profile's settings
          --save-profile <path>   save this command line as a reusable custom-scan profile
                                  (never includes --load-hives / --interactive / baselines —
                                  those stay per-run decisions)
          --baseline <path>       diff against a prior baseline; only NEW findings reported
          --save-baseline <path>  write this run's finding ids as a baseline file
          --load-hives            OPT-IN: mount logged-off users' registry hives (else those
                                  profiles' registry checks are reported as unchecked)
          -i, --interactive       post-scan remediation review (typed CONFIRM required)
          -o, --output-dir <dir>  report directory (default .\reports)
          --log <path>            tee this run's console output to a plain-text transcript
                                  (unrelated to `scythescan log`, which is the tamper-evident
                                  record of remediation ACTIONS); written as it happens, so
                                  a cancelled or crashed run still leaves a usable file
          --html                  also write an HTML report
          --adaptive              in-run escalation: findings arm their IPs/domains/hashes/
                                  filenames as DETECTION-ONLY indicators for later phases,
                                  leads are written beside the reports, and a DEEP follow-up
                                  profile is generated (triage scans are always adaptive)

        triage options (in addition to scan options):
          --symptoms "<text>"     plain-text symptom description ("ransom note on desktop,
                                  browser redirecting, fans maxed")
          --symptoms-file <path>  read the symptom description from a text file
                                  (neither given: an interactive symptom wizard runs)
          --llm-assist            ALSO ask Google Gemini to suggest categories (opt-in;
                                  needs SCYTHE_GEMINI_API_KEY env var; only the symptom text
                                  leaves the machine; the suggestion is validated against
                                  the real category list and you confirm it before use)
        """;
}
