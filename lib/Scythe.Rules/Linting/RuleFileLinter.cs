using System.Diagnostics;
using System.Text.RegularExpressions;
using Scythe.Rules.Linting.Json;
using Scythe.Rules.Linting.Patterns;

namespace Scythe.Rules.Linting;

/// <summary>
/// Lints one BLUEPRINT §9 rule file. Same input, same options, same findings in the same
/// order — the only nondeterminism anywhere is wall-clock (budget checks), and crossing a
/// budget is always a visible outcome (a finding or <see cref="OperationState.Incomplete"/>),
/// never a silently shortened result.
/// </summary>
public static class RuleFileLinter
{
    /// <summary>Regex options used for every compiled entry: the host compares these
    /// patterns against Windows paths and names, which are case-insensitive.</summary>
    private const RegexOptions EntryOptions = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    /// <summary>Letters that follow a literal backslash only when someone double-escaped
    /// a regex class in JSON (<c>\\d</c> written for <c>\d</c>).</summary>
    private const string ClassLetters = "dwsDWSbB";

    public static LintResult Lint(string jsonText, string fileName, LintOptions? options = null)
    {
        options ??= LintOptions.Default;

        // Size gate first (BLUEPRINT §3): refusal is Incomplete with the reason, never a
        // silent truncation. UTF-16 length understates UTF-8 bytes at most 3×, plenty
        // precise for a 16 MiB ceiling on a hand-maintained file.
        if ((long)jsonText.Length * sizeof(char) > LintDefaults.MaxInputBytes)
        {
            return new LintResult(OperationState.Incomplete,
                $"input is larger than {LintDefaults.MaxInputBytes} bytes; not linted",
                Array.Empty<LintFinding>());
        }

        var parse = JsonSourceParser.Parse(jsonText);
        if (parse.State != OperationState.Ok)
        {
            // No partial results on error: a file that is not JSON gets no findings list
            // that could be mistaken for "linted clean".
            return new LintResult(OperationState.Failed,
                $"{fileName}({parse.ErrorLocation.Line},{parse.ErrorLocation.Column}): {parse.Message}",
                Array.Empty<LintFinding>());
        }

        var findings = new List<LintFinding>();
        var file = RuleFileReader.Read(parse.Root!, fileName, findings, options);

        LintStructure(file, fileName, findings);
        LintReferences(file, fileName, options, findings);
        string? incompleteReason = LintPatterns(file, fileName, options, findings);

        findings.Sort(CompareFindings);
        return new LintResult(
            incompleteReason is null ? OperationState.Ok : OperationState.Incomplete,
            incompleteReason,
            findings);
    }

    private static int CompareFindings(LintFinding a, LintFinding b)
    {
        int byLine = a.Location.Line.CompareTo(b.Location.Line);
        if (byLine != 0)
        {
            return byLine;
        }
        int byColumn = a.Location.Column.CompareTo(b.Location.Column);
        if (byColumn != 0)
        {
            return byColumn;
        }
        int byCode = ((int)a.Code).CompareTo((int)b.Code);
        return byCode != 0 ? byCode : string.CompareOrdinal(a.Message, b.Message);
    }

    // ── Structure ────────────────────────────────────────────────────────────────

    private static void LintStructure(RuleFile file, string fileName, List<LintFinding> findings)
    {
        foreach (var set in file.IndicatorSets)
        {
            if (set.ItemCount == 0)
            {
                findings.Add(new LintFinding(
                    LintSeverity.Warning, LintCode.EmptyIndicatorSet,
                    $"indicator set \"{set.Name}\" has no entries; it can never match, which looks exactly like a passing check",
                    fileName, set.NameLocation, SetName: set.Name));
            }
        }

        foreach (var set in file.IndicatorSets.Concat(file.Allowlists))
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in set.Entries)
            {
                if (!seen.Add(entry.Value))
                {
                    findings.Add(new LintFinding(
                        LintSeverity.Warning, LintCode.DuplicateEntry,
                        $"entry \"{entry.Value}\" appears more than once in \"{set.Name}\"",
                        fileName, entry.Location, SetName: set.Name, Entry: entry.Value));
                }
            }
        }
    }

    // ── References ───────────────────────────────────────────────────────────────

    private static void LintReferences(
        RuleFile file, string fileName, LintOptions options, List<LintFinding> findings)
    {
        bool hasAnyReferenceData =
            file.HasReferenceKey || options.ExternalReferences.Count > 0;

        if (!hasAnyReferenceData)
        {
            // The check cannot run without data. Saying so beats skipping silently:
            // a skipped check looks identical to a passing one.
            findings.Add(new LintFinding(
                LintSeverity.Info, LintCode.ReferenceAnalysisInactive,
                $"no \"{RuleFileReader.ReferencesKey}\" key and no external manifest: orphan and dangling-reference analysis did not run",
                fileName, LintLocation.FileLevel));
            return;
        }

        var declared = new HashSet<string>(StringComparer.Ordinal);
        foreach (var set in file.IndicatorSets.Concat(file.Allowlists))
        {
            declared.Add(set.Name);
        }

        // Names are compared exactly (ordinal). A case-mismatched reference is dangling
        // and says so — guessing that the author meant the other casing would hide the
        // exact class of quiet mismatch this analysis exists to catch.
        var referenced = new HashSet<string>(StringComparer.Ordinal);
        foreach (var reference in file.References)
        {
            referenced.Add(reference.Target.Value);
            if (!declared.Contains(reference.Target.Value))
            {
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.DanglingReference,
                    $"\"{reference.Consumer}\" references \"{reference.Target.Value}\", which does not exist in this file; that consumer finds nothing and fails silently",
                    fileName, reference.Target.Location, SetName: reference.Consumer,
                    Entry: reference.Target.Value));
            }
        }
        foreach (var external in options.ExternalReferences)
        {
            referenced.Add(external);
            if (!declared.Contains(external))
            {
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.DanglingReference,
                    $"the host consumes \"{external}\" (external manifest), which does not exist in this file",
                    fileName, LintLocation.FileLevel, Entry: external));
            }
        }

        foreach (var set in file.IndicatorSets.Concat(file.Allowlists))
        {
            if (!referenced.Contains(set.Name))
            {
                findings.Add(new LintFinding(
                    LintSeverity.Warning, LintCode.OrphanSet,
                    $"nothing references \"{set.Name}\"; it is either dead weight or a lost reference",
                    fileName, set.NameLocation, SetName: set.Name));
            }
        }
    }

    // ── Patterns ─────────────────────────────────────────────────────────────────

    /// <summary>One entry's compiled/analysed state, kept for the cross-checks.</summary>
    private sealed record AnalyzedEntry(
        RuleSet Set, RuleEntry Entry, Regex? Regex, PatternNode? Ast, bool BlewBudget,
        bool IsReference, bool IsWholeValue);

    private enum EntryKind { Regex, Literal, Equality, Wildcard }

    private static string? LintPatterns(
        RuleFile file, string fileName, LintOptions options, List<LintFinding> findings)
    {
        var stopwatch = Stopwatch.StartNew();
        int totalEntries = file.IndicatorSets.Concat(file.Allowlists).Sum(s => s.Entries.Count);
        int checkedEntries = 0;

        string? OverBudget() =>
            $"lint budget of {options.TotalDeadline.TotalSeconds:0.#} s exceeded after " +
            $"checking {checkedEntries} of {totalEntries} pattern entries; remaining checks did not run";

        var indicators = new List<AnalyzedEntry>();
        var allowlists = new List<AnalyzedEntry>();

        foreach (var (set, isAllowlist) in
                 file.IndicatorSets.Select(s => (s, false))
                     .Concat(file.Allowlists.Select(s => (s, true))))
        {
            foreach (var entry in set.Entries)
            {
                if (stopwatch.Elapsed > options.TotalDeadline)
                {
                    return OverBudget();
                }
                var analyzed = AnalyzeEntry(set, entry, isAllowlist, fileName, options, findings);
                (isAllowlist ? allowlists : indicators).Add(analyzed);
                checkedEntries++;
            }
        }

        if (stopwatch.Elapsed > options.TotalDeadline)
        {
            return OverBudget();
        }

        LintSwallowedDetections(indicators, allowlists, fileName, options, findings,
            () => stopwatch.Elapsed > options.TotalDeadline, out bool cutShort);
        return cutShort ? OverBudget() : null;
    }

    private static AnalyzedEntry AnalyzeEntry(
        RuleSet set, RuleEntry entry, bool isAllowlist, string fileName,
        LintOptions options, List<LintFinding> findings)
    {
        bool isReference = options.ReferenceSets.Contains(set.Name);
        var kind = options.LiteralSets.Contains(set.Name) ? EntryKind.Literal
                 : options.EqualitySets.Contains(set.Name) ? EntryKind.Equality
                 : options.WildcardSets.Contains(set.Name) ? EntryKind.Wildcard
                 : EntryKind.Regex;

        if (kind is EntryKind.Literal or EntryKind.Equality)
        {
            return AnalyzeLiteralEntry(set, entry, isAllowlist, isReference,
                wholeValue: kind == EntryKind.Equality, fileName, options, findings);
        }

        // A glob is checked as the anchored regex the host builds from it:
        // '^' + [regex]::Escape($_).Replace('\*','.*') + '$'.
        string pattern = kind == EntryKind.Wildcard
            ? "^" + Regex.Escape(entry.Value).Replace(@"\*", ".*").Replace(@"\?", ".") + "$"
            : entry.Value;

        if (kind == EntryKind.Regex && FindDoubleEscapedClass(pattern) is { } doubled)
        {
            findings.Add(new LintFinding(
                LintSeverity.Warning, LintCode.DoubleEscapedClass,
                $"entry \"{pattern}\" in \"{set.Name}\" contains a literal backslash followed by '{doubled}': " +
                $"if the regex class \\{doubled} was meant, remove one escaping level (JSON \"\\\\{doubled}\", not \"\\\\\\\\{doubled}\") — as written the entry silently never matches it",
                fileName, entry.Location, SetName: set.Name, Entry: pattern));
        }

        Regex? regex;
        try
        {
            regex = new Regex(pattern, EntryOptions, options.PerPatternTimeout);
        }
        catch (ArgumentException ex)
        {
            findings.Add(new LintFinding(
                LintSeverity.Error, LintCode.RegexDoesNotCompile,
                $"entry \"{entry.Value}\" in \"{set.Name}\" is not a valid regex ({TrimEngineMessage(ex.Message)}); it matches nothing, which looks exactly like a passing check",
                fileName, entry.Location, SetName: set.Name, Entry: entry.Value));
            return new AnalyzedEntry(set, entry, null, null, BlewBudget: false, isReference, IsWholeValue: false);
        }

        bool blewBudget = false;
        if (BacktrackingProbe.FindBudgetBlowingBait(regex) is { } bait)
        {
            blewBudget = true;
            findings.Add(new LintFinding(
                LintSeverity.Error, LintCode.CatastrophicBacktracking,
                $"entry \"{entry.Value}\" in \"{set.Name}\" exceeded the {options.PerPatternTimeout.TotalMilliseconds:0} ms match budget against {bait}; " +
                "on attacker-authored content this pattern is a denial of service on the scan",
                fileName, entry.Location, SetName: set.Name, Entry: entry.Value));
        }

        var ast = PatternParser.TryParse(pattern);

        if (isAllowlist)
        {
            // A glob is whole-string by construction; only a hand-written regex can be unanchored.
            LintAllowlistEntry(set, entry, regex, ast, blewBudget,
                checkAnchors: kind == EntryKind.Regex, fileName, options, findings);
        }
        else if (!isReference)
        {
            LintIndicatorEntry(set, entry, regex, ast, blewBudget, fileName, options, findings);
        }

        return new AnalyzedEntry(set, entry, regex, ast, blewBudget, isReference, IsWholeValue: kind == EntryKind.Wildcard);
    }

    /// <summary>
    /// An entry the host matches as a literal substring or by equality. Escaped before it is
    /// compiled, so the regex checks (compile, backtracking, double-escaped classes,
    /// anchoring) do not apply — but the collision corpus does, on the escaped form, because
    /// a substring match on a process name is exactly what the host's auto-kill lists do. An
    /// empty literal is an error, not a warning: <c>-match [regex]::Escape('')</c> is true for
    /// every input, and on an auto-kill list that is every process on the machine.
    /// </summary>
    private static AnalyzedEntry AnalyzeLiteralEntry(
        RuleSet set, RuleEntry entry, bool isAllowlist, bool isReference, bool wholeValue,
        string fileName, LintOptions options, List<LintFinding> findings)
    {
        string literal = entry.Value;
        if (string.IsNullOrWhiteSpace(literal))
        {
            // Equality against an empty string matches only an empty value (a file with no
            // extension); it is the substring form that matches everything.
            if (!isReference && !isAllowlist && !wholeValue)
            {
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.IndicatorTooShort,
                    $"literal entry in \"{set.Name}\" is empty or whitespace; as a substring it matches every input, which on an auto-kill list is every process on the machine",
                    fileName, entry.Location, SetName: set.Name, Entry: literal));
            }
            return new AnalyzedEntry(set, entry, null, null, BlewBudget: false, isReference, wholeValue);
        }

        string escaped = wholeValue ? "^" + Regex.Escape(literal) + "$" : Regex.Escape(literal);
        var regex = new Regex(escaped, EntryOptions, options.PerPatternTimeout);
        var ast = PatternParser.TryParse(escaped);

        if (isAllowlist || isReference)
        {
            // A literal cannot be universal unless empty (handled above) and anchoring is a
            // regex concept; a reference entry is legitimate by design. Nothing further.
            return new AnalyzedEntry(set, entry, regex, ast, BlewBudget: false, isReference, wholeValue);
        }

        if (literal.Length < options.MinIndicatorLiteralLength)
        {
            findings.Add(Accepted(
                LintSeverity.Warning, LintCode.IndicatorTooShort,
                $"literal indicator \"{literal}\" in \"{set.Name}\" is shorter than {options.MinIndicatorLiteralLength} characters; " +
                "as a substring it will occur inside legitimate names",
                fileName, entry.Location, set.Name, literal, options));
        }

        ReportCollisions(set, entry, regex, wholeValue ? "equals" : "is a substring of", fileName, options, findings);
        return new AnalyzedEntry(set, entry, regex, ast, BlewBudget: false, isReference, wholeValue);
    }

    private static void LintIndicatorEntry(
        RuleSet set, RuleEntry entry, Regex regex, PatternNode? ast, bool blewBudget,
        string fileName, LintOptions options, List<LintFinding> findings)
    {
        if (ast is not null &&
            PatternInsight.LongestRequiredLiteralRun(ast) < options.MinIndicatorLiteralLength)
        {
            findings.Add(Accepted(
                LintSeverity.Warning, LintCode.IndicatorTooShort,
                $"indicator \"{entry.Value}\" in \"{set.Name}\" guarantees no literal of {options.MinIndicatorLiteralLength}+ characters in what it matches; " +
                "indicators this generic collide with legitimate software",
                fileName, entry.Location, set.Name, entry.Value, options));
        }

        if (blewBudget)
        {
            return; // every corpus probe would just burn the budget again
        }

        ReportCollisions(set, entry, regex, "matches", fileName, options, findings);
    }

    private static void ReportCollisions(
        RuleSet set, RuleEntry entry, Regex regex, string verb,
        string fileName, LintOptions options, List<LintFinding> findings)
    {
        string? firstHit = null;
        int hits = 0;
        foreach (var name in CollisionCorpus.StarterNames.Concat(options.AdditionalCollisionNames))
        {
            if (SafeIsMatch(regex, name))
            {
                firstHit ??= name;
                hits++;
            }
        }
        if (firstHit is null)
        {
            return;
        }

        string more = hits > 1 ? $" (and {hits - 1} more corpus name{(hits > 2 ? "s" : "")})" : "";
        string message =
            $"indicator \"{entry.Value}\" in \"{set.Name}\" {verb} \"{firstHit}\"{more} — the name of real, common software; this detection would fire on a healthy machine";

        findings.Add(Accepted(
            LintSeverity.Error, LintCode.IndicatorCollidesWithLegitimateName,
            message, fileName, entry.Location, set.Name, entry.Value, options));
    }

    /// <summary>
    /// Builds a finding for one of the acceptable codes, downgrading it to Info with the
    /// maintainer's reason appended when <see cref="LintOptions.AcceptedFindings"/> carries a
    /// matching (code, set, entry). The match is exact and ordinal: editing the entry
    /// re-opens the question. Codes outside <see cref="AcceptedFinding.AcceptableCodes"/>
    /// never reach here — they cannot be accepted.
    /// </summary>
    private static LintFinding Accepted(
        LintSeverity severity, LintCode code, string message, string fileName,
        LintLocation location, string setName, string entry, LintOptions options)
    {
        Debug.Assert(AcceptedFinding.IsAcceptable(code), $"{code} is not an acceptable code");
        var accepted = options.AcceptedFindings.FirstOrDefault(a =>
            a.Code == code &&
            string.Equals(a.Set, setName, StringComparison.Ordinal) &&
            string.Equals(a.Entry, entry, StringComparison.Ordinal));
        return accepted is null
            ? new LintFinding(severity, code, message, fileName, location, SetName: setName, Entry: entry)
            : new LintFinding(LintSeverity.Info, code, message + $" [accepted: {accepted.Why}]",
                fileName, location, SetName: setName, Entry: entry);
    }

    private static void LintAllowlistEntry(
        RuleSet set, RuleEntry entry, Regex regex, PatternNode? ast, bool blewBudget,
        bool checkAnchors, string fileName, LintOptions options, List<LintFinding> findings)
    {
        if (checkAnchors)
        {
            bool substring = options.SubstringAllowlists.Contains(set.Name);
            bool startsAnchored, endsAnchored;
            if (ast is not null)
            {
                startsAnchored = PatternInsight.StartsAnchored(ast);
                endsAnchored = PatternInsight.EndsAnchored(ast);
            }
            else
            {
                (startsAnchored, endsAnchored) = TextualAnchors(entry.Value);
            }
            if (substring)
            {
                var (componentStart, componentEnd) = ComponentAnchors(entry.Value);
                startsAnchored |= componentStart;
                endsAnchored |= componentEnd;
            }
            if (!startsAnchored || !endsAnchored)
            {
                string where = (startsAnchored, endsAnchored) switch
                {
                    (false, false) => "at either end",
                    (false, true) => "at the start",
                    _ => "at the end",
                };
                findings.Add(substring
                    ? new LintFinding(
                        LintSeverity.Warning, LintCode.UnanchoredAllowlist,
                        $"allowlist entry \"{entry.Value}\" in \"{set.Name}\" is not anchored to a path component {where}; " +
                        "a bare substring can be reproduced inside a path the attacker chooses",
                        fileName, entry.Location, SetName: set.Name, Entry: entry.Value)
                    : new LintFinding(
                        LintSeverity.Error, LintCode.UnanchoredAllowlist,
                        $"allowlist entry \"{entry.Value}\" in \"{set.Name}\" is not anchored {where}; " +
                        "allowlists are compared against attacker-controlled values, and an unanchored entry lets malware allowlist itself by choosing its own name",
                        fileName, entry.Location, SetName: set.Name, Entry: entry.Value));
            }
        }

        if (blewBudget)
        {
            return; // canary probes would just burn the budget again
        }

        bool matchesEverything = true;
        foreach (var canary in AllowlistCanaries.All)
        {
            if (!SafeIsMatch(regex, canary))
            {
                matchesEverything = false;
                break;
            }
        }
        if (matchesEverything)
        {
            findings.Add(new LintFinding(
                LintSeverity.Critical, LintCode.UniversalAllowlist,
                $"allowlist entry \"{entry.Value}\" in \"{set.Name}\" matches every one of {AllowlistCanaries.All.Count} deliberately unrelated canary strings (a path, a domain, a hash, prose, a registry key, a URL, an IP, a GUID); " +
                "it suppresses every detection downstream of it while the tool keeps reporting success",
                fileName, entry.Location, SetName: set.Name, Entry: entry.Value));
        }
    }

    /// <summary>
    /// Path-component anchoring, the host's own rule for path allowlists: the entry begins
    /// at a path separator (an escaped backslash) and ends at one, or at a real anchor. A
    /// trailing <c>(\\|$)</c> — "separator or end of string" — counts as an end anchor.
    /// Leading inline option groups such as <c>(?i)</c> are skipped.
    /// </summary>
    private static (bool Start, bool End) ComponentAnchors(string pattern)
    {
        string body = pattern;
        while (body.StartsWith("(?", StringComparison.Ordinal))
        {
            int close = body.IndexOf(')');
            if (close < 0 || body.AsSpan(2, close - 2).IndexOfAny('(', '|') >= 0)
            {
                break; // not an inline-option group
            }
            body = body[(close + 1)..];
        }
        bool start = body.StartsWith(@"\\", StringComparison.Ordinal);
        bool end = body.EndsWith(@"\\", StringComparison.Ordinal)
                   || body.EndsWith(@"(\\|$)", StringComparison.Ordinal);
        return (start, end);
    }

    private static void LintSwallowedDetections(
        List<AnalyzedEntry> indicators, List<AnalyzedEntry> allowlists, string fileName,
        LintOptions options, List<LintFinding> findings, Func<bool> overDeadline, out bool cutShort)
    {
        cutShort = false;
        var universal = new HashSet<AnalyzedEntry>(
            allowlists.Where(a =>
                a.Regex is not null && !a.BlewBudget &&
                AllowlistCanaries.All.All(c => SafeIsMatch(a.Regex, c))));

        foreach (var indicator in indicators)
        {
            if (indicator.Regex is null || indicator.Ast is null || indicator.BlewBudget ||
                indicator.IsReference || indicator.IsWholeValue)
            {
                continue;
            }
            if (PatternInsight.TryBuildWitness(indicator.Ast) is not { } witness ||
                !SafeIsMatch(indicator.Regex, witness))
            {
                continue; // no honest witness — skip rather than guess
            }

            foreach (var allow in allowlists)
            {
                if (overDeadline())
                {
                    cutShort = true;
                    return;
                }
                if (allow.Regex is null || allow.BlewBudget || universal.Contains(allow))
                {
                    continue;
                }
                if (SafeIsMatch(allow.Regex, witness))
                {
                    // Accepted on the ALLOWLIST's (set, entry) — the pair the finding reports.
                    findings.Add(Accepted(
                        LintSeverity.Warning, LintCode.AllowlistSwallowsDetection,
                        $"allowlist entry \"{allow.Entry.Value}\" in \"{allow.Set.Name}\" matches \"{witness}\", a string indicator \"{indicator.Entry.Value}\" in \"{indicator.Set.Name}\" exists to catch; that detection branch is unreachable",
                        fileName, allow.Entry.Location, allow.Set.Name, allow.Entry.Value, options));
                }
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    /// <summary>IsMatch that treats a budget blow-up as "no match" — the blow-up itself
    /// is already a <see cref="LintCode.CatastrophicBacktracking"/> finding, and a probe
    /// must never crash the lint.</summary>
    private static bool SafeIsMatch(Regex regex, string input)
    {
        try
        {
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>
    /// Finds the first double-escaped-class mistake: a literal backslash (<c>\\</c>)
    /// followed by a class letter that stands alone or is quantified. A letter starting a
    /// longer word (<c>\\data</c>) is a directory name, not a mistake — that refinement
    /// keeps the warning quiet on ordinary Windows-path patterns.
    /// </summary>
    private static char? FindDoubleEscapedClass(string pattern)
    {
        int i = 0;
        while (i < pattern.Length)
        {
            if (pattern[i] != '\\')
            {
                i++;
                continue;
            }
            if (i + 1 >= pattern.Length)
            {
                break;
            }
            if (pattern[i + 1] != '\\')
            {
                i += 2; // a proper single escape (\d, \., …) — skip its payload
                continue;
            }
            // A literal backslash. Look at what follows it.
            if (i + 2 < pattern.Length && ClassLetters.Contains(pattern[i + 2]))
            {
                char next = i + 3 < pattern.Length ? pattern[i + 3] : '\0';
                bool quantified = next is '+' or '*' or '?' or '{';
                bool standsAlone = next == '\0' || !(char.IsAsciiLetterOrDigit(next) || next == '_');
                if (quantified || standsAlone)
                {
                    return pattern[i + 2];
                }
            }
            i += 2; // past the literal backslash pair
        }
        return null;
    }

    /// <summary>Outermost-character anchor check for patterns beyond the AST model.</summary>
    private static (bool Start, bool End) TextualAnchors(string pattern)
    {
        bool start = pattern.StartsWith('^') || pattern.StartsWith(@"\A", StringComparison.Ordinal);
        bool end = false;
        if (pattern.EndsWith(@"\z", StringComparison.Ordinal) ||
            pattern.EndsWith(@"\Z", StringComparison.Ordinal))
        {
            end = CountTrailingBackslashes(pattern, pattern.Length - 2) % 2 == 0;
        }
        else if (pattern.EndsWith('$'))
        {
            end = CountTrailingBackslashes(pattern, pattern.Length - 1) % 2 == 0;
        }
        return (start, end);

        static int CountTrailingBackslashes(string s, int before)
        {
            int count = 0;
            for (int i = before - 1; i >= 0 && s[i] == '\\'; i--)
            {
                count++;
            }
            return count;
        }
    }

    /// <summary>The engine's message repeats the pattern; keep only the explanation.</summary>
    private static string TrimEngineMessage(string message)
    {
        int dash = message.IndexOf(" - ", StringComparison.Ordinal);
        return dash >= 0 ? message[(dash + 3)..] : message;
    }
}
