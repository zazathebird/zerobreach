using System.Diagnostics;
using System.Runtime.CompilerServices;
using ZeroBreach.Rules.Yara.Evaluation;
using ZeroBreach.Rules.Yara.Matching;
using ZeroBreach.Rules.Yara.Parsing;

namespace ZeroBreach.Rules.Yara;

/// <summary>One matched string within a fired rule.</summary>
public sealed record MatchedString(string Identifier, IReadOnlyList<StringMatch> Matches);

/// <summary>One rule that fired, with everything the host reports: name, tags, meta and
/// the matched strings with offsets. Private strings are omitted; private rules never
/// appear at all.</summary>
public sealed record RuleMatch(
    string RuleName,
    IReadOnlyList<string> Tags,
    IReadOnlyList<MetaEntry> Meta,
    IReadOnlyList<MatchedString> Strings);

/// <summary>A rule that could not be decided, and why. Distinct from "did not match".</summary>
public sealed record IncompleteRule(string RuleName, string Reason);

/// <summary>Result of scanning one buffer against a compiled set. The tri-state is the
/// contract: Incomplete lists exactly which rules did not finish — a budget-exhausted scan
/// is never Ok-with-fewer-matches.</summary>
public sealed class ScanResult
{
    public required OperationState State { get; init; }
    public string? Reason { get; init; }
    public required IReadOnlyList<RuleMatch> Matches { get; init; }
    public required IReadOnlyList<IncompleteRule> IncompleteRules { get; init; }
}

/// <summary>
/// Options for <see cref="YaraScanner"/>. <paramref name="DisableRulesExceedingBudget"/>
/// trades determinism-across-a-run for throughput: a rule whose patterns blow their budget
/// is skipped (reported Incomplete, reason "disabled") on subsequent scans by the same
/// scanner instance, protecting a thousands-of-files run from one pathological rule. Off
/// by default because it makes later results depend on earlier files.
/// </summary>
public sealed record YaraScannerOptions(bool DisableRulesExceedingBudget = false);

/// <summary>
/// The scan entry point the host calls. Stateless with default options (safe to share);
/// with rule-disabling enabled it keeps a per-rule-set memory of budget offenders, which
/// is the only state and is concurrency-safe.
/// </summary>
public sealed class YaraScanner
{
    private readonly YaraScannerOptions _options;
    private readonly ConditionalWeakTable<CompiledRuleSet, HashSet<int>> _disabledRules = new();

    public YaraScanner(YaraScannerOptions? options = null) => _options = options ?? new YaraScannerOptions();

    public ScanResult ScanBytes(CompiledRuleSet rules, ReadOnlyMemory<byte> data, ScanBudget? budget = null, long? entrypoint = null)
    {
        budget ??= ScanBudget.Default;
        long deadline = Stopwatch.GetTimestamp() + (long)(budget.Deadline.TotalSeconds * Stopwatch.Frequency);

        HashSet<int>? disabled = null;
        if (_options.DisableRulesExceedingBudget)
        {
            lock (_disabledRules)
            {
                if (_disabledRules.TryGetValue(rules, out var set))
                {
                    disabled = new HashSet<int>(set);
                }
            }
        }

        HashSet<int>? skipStrings = null;
        if (disabled is { Count: > 0 })
        {
            skipStrings = [];
            for (int i = 0; i < rules.StringSet.StringCount; i++)
            {
                if (disabled.Contains(rules.StringSet.StringInfo(i).RuleIndex))
                {
                    skipStrings.Add(i);
                }
            }
        }

        var stringResult = StringScanner.Scan(rules.StringSet, data.Span, budget, skipStrings);

        // ---- evaluate every rule in definition order, memoising for rule references ----
        var evaluations = new RuleEvaluation[rules.Rules.Count];
        var memo = new Dictionary<string, RuleEvaluation>(StringComparer.Ordinal);
        var skippedRuleNames = new HashSet<string>(rules.SkippedRules, StringComparer.Ordinal);

        for (int r = 0; r < rules.Rules.Count; r++)
        {
            var rule = rules.Rules[r];
            RuleEvaluation evaluation;
            if (disabled is not null && disabled.Contains(r))
            {
                evaluation = new RuleEvaluation(RuleTriState.Incomplete,
                    "disabled after exceeding its budget on an earlier scan");
            }
            else if (Stopwatch.GetTimestamp() > deadline)
            {
                evaluation = new RuleEvaluation(RuleTriState.Incomplete,
                    "scan deadline exhausted before this rule was evaluated");
            }
            else
            {
                int first = rule.FirstStringOrdinal;
                var ctx = new EvaluationContext
                {
                    Data = data,
                    Strings = rule.Ast.Strings,
                    MatchesForString = i => stringResult.PerString[first + i],
                    RuleLookup = name =>
                        memo.TryGetValue(name, out var m) ? m.State
                        : skippedRuleNames.Contains(name) ? RuleTriState.Incomplete
                        : null,
                    Entrypoint = entrypoint,
                    DeadlineTimestamp = deadline,
                };
                evaluation = ConditionEvaluator.Evaluate(rule.Ast.Condition, ctx);
            }
            evaluations[r] = evaluation;
            memo[rule.Name] = evaluation;
        }

        // ---- global-rule suppression, scoped to the source file (pinned decision) -------
        var fileGlobalFailed = new HashSet<string>(StringComparer.Ordinal);
        var fileGlobalIncomplete = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int r = 0; r < rules.Rules.Count; r++)
        {
            var rule = rules.Rules[r];
            if (!rule.Ast.IsGlobal)
            {
                continue;
            }
            switch (evaluations[r].State)
            {
                case RuleTriState.False:
                    fileGlobalFailed.Add(rule.SourceFile);
                    break;
                case RuleTriState.Incomplete:
                    fileGlobalIncomplete.TryAdd(rule.SourceFile, rule.Name);
                    break;
            }
        }

        var matches = new List<RuleMatch>();
        var incomplete = new List<IncompleteRule>();
        foreach (var name in rules.SkippedRules)
        {
            incomplete.Add(new IncompleteRule(name,
                $"uses a module this engine does not implement ({string.Join(", ", rules.UnsupportedModules)})"));
        }

        for (int r = 0; r < rules.Rules.Count; r++)
        {
            var rule = rules.Rules[r];
            var evaluation = evaluations[r];

            // A failed global rule suppresses every rule from its file — including ones
            // that matched. This is defined semantics, not a silent gap.
            if (fileGlobalFailed.Contains(rule.SourceFile))
            {
                continue;
            }
            if (fileGlobalIncomplete.TryGetValue(rule.SourceFile, out var globalName) &&
                evaluation.State != RuleTriState.False)
            {
                // The gate itself is unresolved, so nothing from this file can be
                // confidently reported.
                incomplete.Add(new IncompleteRule(rule.Name,
                    rule.Name == globalName
                        ? evaluation.IncompleteReason ?? "global rule incomplete"
                        : $"global rule '{globalName}' in the same file is incomplete"));
                continue;
            }

            switch (evaluation.State)
            {
                case RuleTriState.True when !rule.Ast.IsPrivate:
                    matches.Add(BuildMatch(rules, rule, r, stringResult));
                    break;
                case RuleTriState.Incomplete:
                    incomplete.Add(new IncompleteRule(rule.Name,
                        evaluation.IncompleteReason ?? "condition incomplete"));
                    break;
            }
        }

        // ---- remember budget offenders when the option is on ---------------------------
        if (_options.DisableRulesExceedingBudget)
        {
            RememberBudgetOffenders(rules, stringResult);
        }

        bool isIncomplete = stringResult.State == OperationState.Incomplete || incomplete.Count > 0;
        return new ScanResult
        {
            State = isIncomplete ? OperationState.Incomplete : OperationState.Ok,
            Reason = isIncomplete
                ? stringResult.Reason ?? $"{incomplete.Count} rule(s) could not be decided"
                : null,
            Matches = matches,
            IncompleteRules = incomplete,
        };
    }

    private static RuleMatch BuildMatch(CompiledRuleSet rules, CompiledRule rule, int ruleIndex, StringScanResult stringResult)
    {
        var matched = new List<MatchedString>();
        for (int i = 0; i < rule.StringCount; i++)
        {
            int ordinal = rule.FirstStringOrdinal + i;
            if (rules.StringSet.StringInfo(ordinal).IsPrivate)
            {
                continue;
            }
            var ms = stringResult.PerString[ordinal];
            if (ms.Matches.Count > 0)
            {
                matched.Add(new MatchedString(rule.Ast.Strings[i].Identifier, ms.Matches));
            }
        }
        return new RuleMatch(rule.Name, rule.Ast.Tags, rule.Ast.Meta, matched);
    }

    private void RememberBudgetOffenders(CompiledRuleSet rules, StringScanResult stringResult)
    {
        List<int>? offenders = null;
        for (int i = 0; i < rules.StringSet.StringCount; i++)
        {
            var ms = stringResult.PerString[i];
            if (!ms.Complete && ms.IncompleteReason is not null &&
                ms.IncompleteReason.Contains("pattern budget", StringComparison.Ordinal))
            {
                (offenders ??= []).Add(rules.StringSet.StringInfo(i).RuleIndex);
            }
        }
        if (offenders is null)
        {
            return;
        }
        lock (_disabledRules)
        {
            var set = _disabledRules.GetOrCreateValue(rules);
            foreach (var r in offenders)
            {
                set.Add(r);
            }
        }
    }
}
