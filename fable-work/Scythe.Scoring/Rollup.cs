using System.Globalization;
using System.Text;

namespace Scythe.Scoring;

/// <summary>
/// The entry point. Turns the scoring projection of a run record into a <see cref="RunRollup"/>.
/// </summary>
/// <remarks>
/// <para>
/// A pure function of its arguments: no clock, no randomness, no ambient state, no I/O. The
/// same input produces the same output, member for member and in the same order, on every
/// platform, because every number is computed in the integer domain (<see cref="ScoreWeights"/>).
/// </para>
/// <para>
/// The signature is shaped so that a later revision can add an optional chain argument (K1
/// output) after <paramref name="budget"/> without breaking callers. The first implementation
/// takes none.
/// </para>
/// </remarks>
public static class Rollup
{
    /// <summary>
    /// Computes the rollup.
    /// </summary>
    /// <returns>
    /// <list type="bullet">
    /// <item><b>Ok</b> — every check and finding was tallied, every inconclusive or skipped
    /// check gave a reason, and at least one check was attempted.</item>
    /// <item><b>Incomplete</b> (with the partial rollup) — an inconclusive or skipped check gave
    /// no reason, so the coverage statement cannot say why part of the host went unexamined; or
    /// no check was attempted, so the score is a statement about coverage alone.
    /// <b>Incomplete</b> (without a value) — the record holds more checks plus findings than
    /// <see cref="ScanBudget.MaxMatches"/>; a rollup over a subset would read as a rollup over
    /// the whole, so none is produced.</item>
    /// <item><b>Failed</b> — a malformed record: a null list or entry, a blank identifier, an
    /// undefined status or severity, a check appearing twice in the inventory, a finding id
    /// appearing twice, or a finding whose producing check is not in the inventory. The
    /// message names the offender and <see cref="ScoringResult{T}.Position"/> is its index in
    /// the list the message names. A record-construction bug is surfaced, never counted around.</item>
    /// </list>
    /// </returns>
    public static ScoringResult<RunRollup> Compute(RollupInput input, ScanBudget? budget = null)
    {
        budget ??= ScanBudget.Default;

        if (input is null)
        {
            return ScoringResult<RunRollup>.Failed("record: input is null");
        }

        if (input.Checks is null)
        {
            return ScoringResult<RunRollup>.Failed("record: the check inventory is null");
        }

        if (input.Findings is null)
        {
            return ScoringResult<RunRollup>.Failed("record: the finding list is null");
        }

        // The budget is checked before anything is tallied. A rollup that counted the first
        // MaxMatches findings and stopped would be the exact lie this library exists to prevent:
        // forty findings out of four hundred looks like forty findings.
        long entries = (long)input.Checks.Count + input.Findings.Count;
        if (entries > budget.MaxMatches)
        {
            return ScoringResult<RunRollup>.Incomplete(
                null,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"record holds {input.Checks.Count} checks and {input.Findings.Count} findings ({entries} entries); budget MaxMatches allows {budget.MaxMatches}. No rollup is produced over a subset because a partial count reads as a whole one."));
        }

        // ------------------------------------------------------------ the check inventory

        var checksById = new Dictionary<string, (int Index, CheckInput Check)>(StringComparer.Ordinal);
        for (int i = 0; i < input.Checks.Count; i++)
        {
            var check = input.Checks[i];
            if (check is null)
            {
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"check {i}: entry is null"), i);
            }

            if (string.IsNullOrWhiteSpace(check.Id))
            {
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"check {i}: id is null or blank"), i);
            }

            if (!Enum.IsDefined(check.Status))
            {
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"check {i} '{check.Id}': status {(int)check.Status} is not Completed, Inconclusive or Skipped"), i);
            }

            if (checksById.TryGetValue(check.Id, out var earlier))
            {
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"check {i} '{check.Id}': appears twice in the inventory (first at check {earlier.Index})"), i);
            }

            checksById.Add(check.Id, (i, check));
        }

        // ------------------------------------------------------------ the findings

        var findingIds = new Dictionary<string, int>(StringComparer.Ordinal);
        var perCheckCount = new Dictionary<string, int>(StringComparer.Ordinal);
        var perCheckHighest = new Dictionary<string, Severity>(StringComparer.Ordinal);
        var perSeverity = new int[SeverityLevels.Length];

        for (int i = 0; i < input.Findings.Count; i++)
        {
            var finding = input.Findings[i];
            if (finding is null)
            {
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"finding {i}: entry is null"), i);
            }

            if (string.IsNullOrWhiteSpace(finding.Id))
            {
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"finding {i}: id is null or blank"), i);
            }

            if (!Enum.IsDefined(finding.Severity))
            {
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"finding {i} '{finding.Id}': severity {(int)finding.Severity} is not one of the five levels"), i);
            }

            if (string.IsNullOrWhiteSpace(finding.CheckId))
            {
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"finding {i} '{finding.Id}': producing check id is null or blank"), i);
            }

            if (!checksById.ContainsKey(finding.CheckId))
            {
                // Silently counting an orphan would hide a record-construction bug behind a
                // plausible number, so the whole rollup declines.
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"finding {i} '{finding.Id}': producing check '{finding.CheckId}' is not in the inventory"), i);
            }

            if (findingIds.TryGetValue(finding.Id, out int earlier))
            {
                return ScoringResult<RunRollup>.Failed(
                    Invariant($"finding {i} '{finding.Id}': id appears twice (first at finding {earlier})"), i);
            }

            findingIds.Add(finding.Id, i);

            perSeverity[(int)finding.Severity]++;
            perCheckCount[finding.CheckId] = perCheckCount.GetValueOrDefault(finding.CheckId) + 1;
            if (!perCheckHighest.TryGetValue(finding.CheckId, out var highest) || finding.Severity > highest)
            {
                perCheckHighest[finding.CheckId] = finding.Severity;
            }
        }

        // ------------------------------------------------------------ counts

        var severityCounts = new SeverityCount[SeverityLevels.Length];
        for (int i = 0; i < SeverityLevels.Length; i++)
        {
            // Highest first: the order a report reads them in. Stated key: Severity descending.
            var level = SeverityLevels[SeverityLevels.Length - 1 - i];
            severityCounts[i] = new SeverityCount(level, perSeverity[(int)level], ScoreWeights.WeightFor(level)!.Value);
        }

        var orderedChecks = checksById.Values
            .OrderBy(entry => entry.Check.Id, StringComparer.Ordinal)
            .Select(entry => entry.Check)
            .ToArray();

        var checkCounts = new CheckCount[orderedChecks.Length];
        for (int i = 0; i < orderedChecks.Length; i++)
        {
            var check = orderedChecks[i];
            checkCounts[i] = new CheckCount(
                check.Id,
                check.Title ?? string.Empty,
                check.Status,
                NormaliseReason(check.StatusReason),
                perCheckCount.GetValueOrDefault(check.Id),
                perCheckHighest.TryGetValue(check.Id, out var highest) ? highest : null);
        }

        // ------------------------------------------------------------ coverage

        var coverage = BuildCoverage(orderedChecks);

        // ------------------------------------------------------------ score

        var score = ComposeScore(severityCounts, input.Findings.Count, coverage);

        var rollup = new RunRollup(
            severityCounts,
            checkCounts,
            input.Findings.Count,
            coverage,
            score);

        // ------------------------------------------------------------ state

        var unfinished = new List<string>();
        if (coverage.CompletedCount + coverage.InconclusiveCount == 0)
        {
            unfinished.Add(Invariant(
                $"no check was attempted ({coverage.InventorySize} in the inventory, {coverage.SkippedCount} skipped); the score reflects zero coverage, not findings"));
        }

        if (coverage.InconclusiveWithoutReason.Count > 0)
        {
            unfinished.Add(Invariant(
                $"{coverage.InconclusiveWithoutReason.Count} inconclusive check(s) gave no reason ({string.Join(", ", coverage.InconclusiveWithoutReason)}); the coverage statement cannot say why they did not finish"));
        }

        if (coverage.SkippedWithoutReason.Count > 0)
        {
            unfinished.Add(Invariant(
                $"{coverage.SkippedWithoutReason.Count} skipped check(s) gave no reason ({string.Join(", ", coverage.SkippedWithoutReason)}); the coverage statement cannot say why they were not run"));
        }

        return unfinished.Count == 0
            ? ScoringResult<RunRollup>.Ok(rollup)
            : ScoringResult<RunRollup>.Incomplete(rollup, string.Join("; ", unfinished));
    }

    /// <summary>The five levels, ascending. Built from the enum so a sixth level cannot be added without this list seeing it.</summary>
    private static readonly Severity[] SeverityLevels =
        Enum.GetValues<Severity>().OrderBy(level => (int)level).ToArray();

    private static string Invariant(FormattableString text) =>
        text.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// A reason that is null, empty or whitespace is no reason. Trimmed so that "locked" and
    /// "locked " are one distinct reason rather than two.
    /// </summary>
    private static string? NormaliseReason(string? reason) =>
        string.IsNullOrWhiteSpace(reason) ? null : reason.Trim();

    private static CoverageStatement BuildCoverage(CheckInput[] orderedChecks)
    {
        int completed = 0, inconclusive = 0, skipped = 0;
        var inconclusiveReasons = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var skippedReasons = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var inconclusiveWithout = new List<string>();
        var skippedWithout = new List<string>();

        foreach (var check in orderedChecks)
        {
            switch (check.Status)
            {
                case CheckStatus.Completed:
                    completed++;
                    break;
                case CheckStatus.Inconclusive:
                    inconclusive++;
                    Record(check, inconclusiveReasons, inconclusiveWithout);
                    break;
                case CheckStatus.Skipped:
                    skipped++;
                    Record(check, skippedReasons, skippedWithout);
                    break;
            }
        }

        var inconclusiveList = Ordered(inconclusiveReasons);
        var skippedList = Ordered(skippedReasons);

        return new CoverageStatement(
            orderedChecks.Length,
            completed,
            inconclusive,
            skipped,
            inconclusiveList,
            inconclusiveWithout,
            skippedList,
            skippedWithout,
            Statement(orderedChecks.Length, completed, inconclusive, skipped, inconclusiveList, inconclusiveWithout));

        static void Record(CheckInput check, Dictionary<string, List<string>> reasons, List<string> without)
        {
            var reason = NormaliseReason(check.StatusReason);
            if (reason is null)
            {
                without.Add(check.Id);
                return;
            }

            if (!reasons.TryGetValue(reason, out var ids))
            {
                ids = new List<string>();
                reasons.Add(reason, ids);
            }

            ids.Add(check.Id);
        }

        // Stated key: reason text ordinal ascending; check ids within a reason are already in
        // ordinal order because the inventory was walked in that order.
        static CoverageReason[] Ordered(Dictionary<string, List<string>> reasons) =>
            reasons
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new CoverageReason(pair.Key, pair.Value.ToArray()))
                .ToArray();
    }

    /// <summary>
    /// One sentence for the top of the report. Counts only — never a percentage, because a
    /// percentage is the thing a reader mistakes for "fine".
    /// </summary>
    private static string Statement(
        int inventory,
        int completed,
        int inconclusive,
        int skipped,
        CoverageReason[] inconclusiveReasons,
        List<string> inconclusiveWithout)
    {
        var text = new StringBuilder();
        text.Append(Invariant($"{completed} of {inventory} checks completed, {inconclusive} inconclusive, {skipped} skipped."));

        if (inventory == 0)
        {
            text.Append(" The inventory is empty: nothing was looked at.");
        }
        else if (completed + inconclusive == 0)
        {
            text.Append(" No check was attempted: nothing was looked at.");
        }
        else if (inconclusive == 0)
        {
            text.Append(skipped == 0
                ? " Every check completed."
                : " Every attempted check completed.");
        }
        else
        {
            text.Append(Invariant($" {inconclusive} check(s) were not examined to the end:"));
            foreach (var reason in inconclusiveReasons)
            {
                text.Append(Invariant($" {reason.Reason} ({string.Join(", ", reason.CheckIds)});"));
            }

            if (inconclusiveWithout.Count > 0)
            {
                text.Append(Invariant($" no reason given ({string.Join(", ", inconclusiveWithout)});"));
            }

            // Replace the trailing semicolon with a full stop.
            text.Length--;
            text.Append('.');
        }

        return text.ToString();
    }

    private static CleanlinessScore ComposeScore(SeverityCount[] severityCounts, int totalFindings, CoverageStatement coverage)
    {
        var contributions = new List<ScoreContribution>
        {
            new(ContributionKind.Baseline, null, 0, CleanlinessScore.Maximum,
                Invariant($"start at {CleanlinessScore.Maximum}, the clean end of the range")),
        };

        // Findings: count × weight per level, highest first. long, so an absurd count cannot
        // overflow before the floor is applied.
        long weighted = 0;
        foreach (var entry in severityCounts)
        {
            if (entry.Count == 0)
            {
                continue;
            }

            long effect = (long)entry.Count * entry.Weight;
            weighted += effect;
            contributions.Add(new ScoreContribution(
                ContributionKind.Findings,
                entry.Severity,
                entry.Count,
                -effect,
                Invariant($"{entry.Count} {entry.Severity} finding(s) × {entry.Weight} point(s)")));
        }

        long range = CleanlinessScore.Maximum - CleanlinessScore.Minimum;
        if (weighted > range)
        {
            contributions.Add(new ScoreContribution(
                ContributionKind.FindingsSaturation,
                null,
                totalFindings,
                weighted - range,
                Invariant($"weighted findings total {weighted} points, {weighted - range} beyond the range; the deduction stops at {CleanlinessScore.Minimum}")));
        }

        int afterFindings = (int)(CleanlinessScore.Maximum - Math.Min(weighted, range));

        // Coverage: scale by the share of attempted checks that completed, rounding down. Any
        // inconclusive check therefore keeps the score below the maximum, and no attempted check
        // at all scores the minimum. Skipped checks are outside "attempted" by design — see
        // CoverageStatement. The weight constant lets a single edit soften the scaling.
        int attempted = coverage.CompletedCount + coverage.InconclusiveCount;
        int scaled;
        string coverageDetail;
        if (attempted == 0)
        {
            scaled = CleanlinessScore.Minimum;
            coverageDetail = Invariant($"no check was attempted ({coverage.SkippedCount} skipped); the score is held at {CleanlinessScore.Minimum}");
        }
        else
        {
            // afterFindings × (attempted − inconclusive × w/100) / attempted, all in long.
            long numerator = (long)afterFindings * (attempted * 100L - (long)coverage.InconclusiveCount * ScoreWeights.CoverageWeightHundredths);
            scaled = (int)(numerator / (attempted * 100L));
            coverageDetail = coverage.InconclusiveCount == 0
                ? Invariant($"all {attempted} attempted check(s) completed; no coverage deduction")
                : Invariant($"{coverage.InconclusiveCount} of {attempted} attempted check(s) inconclusive; {afterFindings} scaled to {scaled}");
        }

        contributions.Add(new ScoreContribution(
            ContributionKind.Coverage,
            null,
            coverage.InconclusiveCount,
            scaled - afterFindings,
            coverageDetail));

        return new CleanlinessScore(scaled, contributions, ScoreWeights.Version);
    }
}
