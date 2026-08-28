using Scythe.Core.Triage;

namespace Scythe.Cli;

/// <summary>
/// Symptom-driven scan creation (the `triage` command): turns a plain-text description of
/// the affected machine into a scan plan via the curated symptom map, optionally augmented
/// by an operator-confirmed Gemini suggestion (spec §6.6 discipline: LLM output is untrusted,
/// strictly validated, and only ever SELECTS among the engine's own categories/modes).
/// The derived plan is shown in full and confirmed before anything runs, and the fallback
/// direction is always BROADER (nothing mapped → full scan), never silently narrower.
/// </summary>
public sealed class TriageSession
{
    private readonly SymptomMap _map;
    private readonly IReadOnlyCollection<string> _validCategories;

    public TriageSession(SymptomMap map, IReadOnlyCollection<string> validCategories)
    {
        _map = map;
        _validCategories = validCategories;
    }

    /// <summary>The final plan the operator approved, or null when they aborted.</summary>
    public sealed record ApprovedPlan(string Mode, IReadOnlyList<string> Categories, string Summary);

    /// <summary>Fixed wizard: each yes maps to canonical phrasing the symptom map understands,
    /// so the wizard and free-text paths share one mapping (and one set of tests).</summary>
    private static readonly (string Question, string Phrases)[] WizardQuestions =
    {
        ("Ransom note, files that won't open, or files renamed with a strange extension?",
         "ransom note, files are encrypted, files renamed strange extension"),
        ("Browser redirecting, homepage changed, popups, or unwanted toolbars/extensions?",
         "browser redirect, homepage changed, popups, unwanted toolbar"),
        ("Machine suddenly slow, fans loud/maxed, or CPU pegged while idle?",
         "computer slow, fans loud, high cpu while idle, overheating"),
        ("Fake virus warnings / 'call this number' popups?",
         "fake virus warning, call this number, tech support scam popup"),
        ("Mouse moving by itself, signs of remote control, webcam light coming on?",
         "mouse moving by itself, someone controlling remotely, webcam light"),
        ("Accounts hacked, passwords stolen or changed, logged out everywhere?",
         "passwords stolen, account hacked, password changed itself, account lockouts"),
        ("User clicked a suspicious link / opened an attachment / enabled macros?",
         "clicked a link, opened attachment, phishing email, macro enabled"),
        ("Contacts receiving spam from this user, or sent items they didn't write?",
         "contacts got spam from me, sent emails I didn't write, inbox rules appeared"),
        ("Antivirus/Defender turned off, or Task Manager/regedit blocked?",
         "antivirus turned off, defender disabled, can't open task manager"),
        ("Unknown startup entries, strange scheduled tasks, or programs that come back after removal?",
         "unknown startup program, strange scheduled task, program keeps coming back"),
        ("Unusual network traffic, unknown connections, or firewall alerts?",
         "weird network traffic, unknown connections, firewall alert"),
        ("Crashes/BSOD, boot problems, or files/processes that seem hidden?",
         "bsod, crashes at boot, hidden files"),
    };

    /// <summary>Interactive symptom wizard: builds the free-text blob the map analyzes.</summary>
    public string CollectSymptomsInteractively()
    {
        Console.WriteLine();
        Console.WriteLine("=== Symptom wizard — answer y/N, or describe freely at the end ===");
        var parts = new List<string>();
        foreach (var (question, phrases) in WizardQuestions)
        {
            Console.Write($"  {question} [y/N] > ");
            if (Console.ReadLine()?.Trim().ToLowerInvariant() == "y") parts.Add(phrases);
        }
        Console.Write("  Anything else you noticed? (free text, blank to finish) > ");
        var extra = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(extra)) parts.Add(extra);
        return string.Join('\n', parts);
    }

    /// <summary>Analyzes the symptoms, optionally merges an operator-confirmed LLM suggestion,
    /// shows the full derived plan, and asks for confirmation. Returns null when aborted.</summary>
    public ApprovedPlan? BuildAndConfirm(string symptomText, bool llmAssist)
    {
        if (string.IsNullOrWhiteSpace(symptomText))
        {
            Console.WriteLine("no symptoms described — nothing to derive. Run a plain `scythescan --mode FULL` instead.");
            return null;
        }

        var plan = _map.Analyze(symptomText, _validCategories);
        foreach (var w in plan.Warnings)
            Console.WriteLine($"! symptom map: {w}");

        var categories = plan.Categories.ToList();
        var mode = plan.Mode;

        Console.WriteLine();
        Console.WriteLine("=== Derived scan plan ===");
        if (plan.Matches.Count == 0)
        {
            Console.WriteLine("  Nothing in the description matched the symptom database — falling back to a");
            Console.WriteLine("  BROAD scan (all categories) rather than guessing narrow (spec §6.7 direction).");
        }
        foreach (var m in plan.Matches)
        {
            Console.WriteLine($"  matched: {m.SymptomName}  (\"{string.Join("\", \"", m.MatchedPhrases.Take(3))}\")");
            Console.WriteLine($"           -> {string.Join(", ", m.Categories)} — {m.Rationale}");
        }
        if (plan.UnmatchedInput.Count > 0 && plan.Matches.Count > 0)
        {
            Console.WriteLine("  Didn't map (scan scope is unaffected by these):");
            foreach (var u in plan.UnmatchedInput) Console.WriteLine($"    ? {u}");
        }

        if (llmAssist)
        {
            var (assisted, assistedCategories, assistedMode) = TryLlmAssist(symptomText, categories, mode);
            if (assisted) (categories, mode) = (assistedCategories, assistedMode);
            else Console.WriteLine("  continuing with the offline symptom map only.");
        }

        Console.WriteLine();
        Console.WriteLine($"  mode: {mode}");
        Console.WriteLine(categories.Count == 0
            ? "  categories: ALL (no narrowing)"
            : $"  categories: {string.Join(", ", categories)} — everything else will be reported as UNCHECKED");
        Console.WriteLine("  adaptive: ON — findings arm detection-only indicators for later phases; a DEEP");
        Console.WriteLine("  follow-up profile is generated from any leads (you confirm before it runs).");
        Console.Write("\nRun this scan now? [Y/n] > ");
        var answer = Console.ReadLine()?.Trim().ToLowerInvariant();
        if (answer is "n" or "no" or "q" or "quit")
        {
            Console.WriteLine("  aborted — nothing was scanned.");
            return null;
        }

        var summary = plan.Matches.Count == 0
            ? "triage: no symptom match, broad scan"
            : "triage: " + string.Join(", ", plan.Matches.Select(m => m.SymptomName));
        return new ApprovedPlan(mode, categories, summary);
    }

    /// <summary>Gemini assist (opt-in): a validated suggestion the operator accepts item-set by
    /// item-set — never silently merged (spec §6.6). Ok=false when assist was unavailable.</summary>
    private (bool Ok, List<string> Categories, string Mode) TryLlmAssist(
        string symptomText, List<string> categories, string mode)
    {
        var key = Environment.GetEnvironmentVariable("SCYTHE_GEMINI_API_KEY");
        if (string.IsNullOrWhiteSpace(key))
        {
            Console.WriteLine("! --llm-assist: SCYTHE_GEMINI_API_KEY is not set — cannot ask Gemini.");
            return (false, categories, mode);
        }

        Console.WriteLine("\n  asking Gemini for a second opinion (only the symptom text leaves this machine)...");
        GeminiSuggestion suggestion;
        try
        {
            suggestion = new GeminiSymptomAssist(key)
                .SuggestAsync(symptomText, _validCategories).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"! --llm-assist failed ({ex.Message})");
            return (false, categories, mode);
        }

        foreach (var r in suggestion.RejectedOutput)
            Console.WriteLine($"  [rejected LLM output, not used]: {r}");
        if (suggestion.Rationale is not null)
            Console.WriteLine($"  Gemini says (untrusted): {suggestion.Rationale}");

        var newCats = suggestion.Categories
            .Where(c => !categories.Contains(c, StringComparer.OrdinalIgnoreCase)).ToList();
        if (newCats.Count > 0)
        {
            Console.Write($"  Gemini suggests ADDING categories: {string.Join(", ", newCats)} — accept? [y/N] > ");
            if (Console.ReadLine()?.Trim().ToLowerInvariant() == "y" && categories.Count > 0)
                categories.AddRange(newCats);
            else if (categories.Count == 0)
                Console.WriteLine("  (scan is already unnarrowed — suggestion changes nothing)");
        }
        if (suggestion.SuggestedMode is not null && Deeper(suggestion.SuggestedMode, mode))
        {
            Console.Write($"  Gemini suggests going DEEPER: {suggestion.SuggestedMode} (currently {mode}) — accept? [y/N] > ");
            if (Console.ReadLine()?.Trim().ToLowerInvariant() == "y") mode = suggestion.SuggestedMode;
        }
        // A shallower LLM suggestion is never even offered: assist can widen a triage scan,
        // not quietly shrink it.
        return (true, categories, mode);
    }

    private static bool Deeper(string candidate, string current) =>
        Rank(candidate) > Rank(current);

    private static int Rank(string mode) => mode switch
    {
        "DEEP" => 2, "FULL" => 1, _ => 0,
    };
}
