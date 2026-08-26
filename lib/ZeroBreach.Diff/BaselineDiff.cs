namespace ZeroBreach.Diff;

/// <summary>
/// Diffs two run records from the same machine: finding deltas (new / resolved / persisting /
/// changed) plus first-class coverage deltas, with comparability validated up front.
/// </summary>
public static class BaselineDiff
{
    /// <summary>
    /// Diff <paramref name="baseline"/> against <paramref name="current"/>.
    /// Neither input is mutated. O(n + m) in findings and checks via dictionary joins;
    /// output ordering is ordinal by id and independent of input order.
    /// </summary>
    public static DiffResult Diff(RunRecord baseline, RunRecord current, DiffOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(current);
        options ??= new DiffOptions();

        // --- Comparability validation, before any diffing -------------------------------

        // A baseline from a different machine is a hard error, not a warning: every finding id
        // is machine-scoped, so a cross-machine diff would produce a confidently wrong answer.
        // Machine ids are host-assigned opaque identity, compared ordinally.
        if (!string.Equals(baseline.MachineId, current.MachineId, StringComparison.Ordinal))
        {
            return DiffResult.CreateFailed(
                $"baseline is from machine '{baseline.MachineId}' but the current run is from " +
                $"machine '{current.MachineId}'; refusing to diff runs from different machines");
        }

        // The host's contract is that finding ids and check ids are unique within one record.
        // A duplicate means the identity scheme is broken, and a diff built on a broken join
        // key is untrustworthy in both directions — so this is Failed, not a warning.
        if (!TryIndexFindings(baseline, "baseline", out var baselineFindings, out var failure) ||
            !TryIndexFindings(current, "current", out var currentFindings, out failure) ||
            !TryIndexChecks(baseline, "baseline", out var baselineChecks, out failure) ||
            !TryIndexChecks(current, "current", out var currentChecks, out failure))
        {
            return failure;
        }

        var warnings = new List<string>();

        // Baseline newer than current: the "age" is negative, which means at least one of the
        // two clocks lied. The diff itself is still structurally valid (ids do not depend on
        // time), so this is a warning rather than an error — but the caller must know, because
        // "baseline" may in fact be the newer run handed in backwards.
        if (baseline.Timestamp > current.Timestamp)
        {
            warnings.Add(
                $"baseline timestamp ({baseline.Timestamp:O}) is later than the current run's " +
                $"({current.Timestamp:O}); clock skew, or the runs may be swapped");
        }
        else if (options.MaxBaselineAge is TimeSpan maxAge &&
                 current.Timestamp - baseline.Timestamp > maxAge)
        {
            // Staleness is measured against the current run's timestamp, not wall-clock now:
            // no DateTime.Now in a result (BLUEPRINT §2), and the answer to "was the baseline
            // too old when this run was taken" does not change with when the diff is computed.
            var age = current.Timestamp - baseline.Timestamp;
            warnings.Add(
                $"baseline is {FormatAge(age)} older than the current run, exceeding the " +
                $"configured maximum baseline age of {FormatAge(maxAge)}");
        }

        // Mode-string mismatch is worth a warning of its own, but it is advisory: the string is
        // a label, and the authoritative comparability signal is the check inventory below.
        if (!string.Equals(baseline.ScanMode, current.ScanMode, StringComparison.Ordinal))
        {
            warnings.Add(
                $"scan mode differs: baseline '{baseline.ScanMode}', current '{current.ScanMode}'");
        }

        // Narrower baseline, detected from the inventories: any check the current run has that
        // the baseline never attempted means everything that check finds will show as "new",
        // which misleads. Detected from the inventory rather than the mode string so a renamed
        // or lying mode label cannot hide it.
        var checksMissingFromBaseline = currentChecks.Keys
            .Where(id => !baselineChecks.ContainsKey(id))
            .Order(StringComparer.Ordinal)
            .ToList();
        if (checksMissingFromBaseline.Count > 0)
        {
            warnings.Add(
                "baseline was taken with a narrower scan than the current run; checks absent " +
                $"from the baseline inventory: {string.Join(", ", checksMissingFromBaseline)}. " +
                "Findings from these checks will all appear as new");
        }

        // --- Finding deltas -------------------------------------------------------------

        var newFindings = new List<Finding>();
        var resolvedFindings = new List<Finding>();
        var persistingFindings = new List<Finding>();
        var changedFindings = new List<ChangedFinding>();
        var idContractWarnings = new List<string>();

        foreach (var (id, currentFinding) in currentFindings)
        {
            if (!baselineFindings.TryGetValue(id, out var baselineFinding))
            {
                newFindings.Add(currentFinding);
                continue;
            }

            var changes = ComputeFieldChanges(baselineFinding, currentFinding, id, idContractWarnings);
            if (changes.Count == 0)
            {
                persistingFindings.Add(currentFinding);
            }
            else
            {
                changedFindings.Add(new ChangedFinding(baselineFinding, currentFinding, changes));
            }
        }

        foreach (var (id, baselineFinding) in baselineFindings)
        {
            if (!currentFindings.ContainsKey(id))
            {
                resolvedFindings.Add(baselineFinding);
            }
        }

        // Id-contract warnings are appended after the comparability warnings, sorted so that
        // the warning list is deterministic regardless of input order.
        idContractWarnings.Sort(StringComparer.Ordinal);
        warnings.AddRange(idContractWarnings);

        // --- Coverage deltas (first-class, computed even when no finding changed) --------

        var coverageDeltas = new List<CoverageDelta>();
        foreach (var (checkId, currentCheck) in currentChecks)
        {
            if (!baselineChecks.TryGetValue(checkId, out var baselineCheck))
            {
                coverageDeltas.Add(new CoverageDelta(
                    checkId, CoverageChangeKind.Added,
                    BaselineStatus: null, BaselineReason: null,
                    CurrentStatus: currentCheck.Status, CurrentReason: currentCheck.Reason));
                continue;
            }

            // Completed is the only status that means "the answer is trustworthy", so the
            // regression/improvement boundary is crossing into or out of Completed.
            // Inconclusive <-> NotRun is deliberately not reported: neither side had
            // visibility, so nothing about what the technician can trust has changed.
            var kind =
                baselineCheck.Status == CheckStatus.Completed && currentCheck.Status != CheckStatus.Completed
                    ? CoverageChangeKind.Regression
                : baselineCheck.Status != CheckStatus.Completed && currentCheck.Status == CheckStatus.Completed
                    ? CoverageChangeKind.Improvement
                    : (CoverageChangeKind?)null;

            if (kind is CoverageChangeKind k)
            {
                coverageDeltas.Add(new CoverageDelta(
                    checkId, k,
                    baselineCheck.Status, baselineCheck.Reason,
                    currentCheck.Status, currentCheck.Reason));
            }
        }

        foreach (var (checkId, baselineCheck) in baselineChecks)
        {
            if (!currentChecks.ContainsKey(checkId))
            {
                coverageDeltas.Add(new CoverageDelta(
                    checkId, CoverageChangeKind.Removed,
                    baselineCheck.Status, baselineCheck.Reason,
                    CurrentStatus: null, CurrentReason: null));
            }
        }

        // --- Deterministic ordering -------------------------------------------------------

        newFindings.Sort(CompareFindings);
        resolvedFindings.Sort(CompareFindings);
        persistingFindings.Sort(CompareFindings);
        changedFindings.Sort(static (a, b) => string.CompareOrdinal(a.Current.Id, b.Current.Id));
        coverageDeltas.Sort(static (a, b) => string.CompareOrdinal(a.CheckId, b.CheckId));

        return new DiffResult
        {
            State = OperationState.Ok,
            Error = null,
            Warnings = warnings,
            NewFindings = newFindings,
            ResolvedFindings = resolvedFindings,
            PersistingFindings = persistingFindings,
            ChangedFindings = changedFindings,
            CoverageDeltas = coverageDeltas,
        };
    }

    private static int CompareFindings(Finding a, Finding b) => string.CompareOrdinal(a.Id, b.Id);

    /// <summary>
    /// Fields that participate in "changed": category, target, severity, description, and every
    /// property-bag entry. Timestamps do not participate — the run's timestamp lives on the
    /// record, not the finding, precisely so that re-observing an unchanged artifact does not
    /// look like a change. Category/target should be impossible to change under a stable id
    /// (the id hashes over them); if they differ anyway the host's id contract is suspect, so
    /// the change is reported *and* flagged with a warning rather than silently trusted.
    /// </summary>
    private static List<FieldChange> ComputeFieldChanges(
        Finding baseline, Finding current, string id, List<string> idContractWarnings)
    {
        var changes = new List<FieldChange>();

        if (!string.Equals(baseline.Category, current.Category, StringComparison.Ordinal))
        {
            changes.Add(new FieldChange("category", baseline.Category, current.Category));
            idContractWarnings.Add(
                $"finding '{id}' changed category ('{baseline.Category}' -> '{current.Category}') " +
                "under a stable id; the host's finding-identity contract may be broken");
        }

        if (!string.Equals(baseline.Target, current.Target, StringComparison.Ordinal))
        {
            changes.Add(new FieldChange("target", baseline.Target, current.Target));
            idContractWarnings.Add(
                $"finding '{id}' changed target ('{baseline.Target}' -> '{current.Target}') " +
                "under a stable id; the host's finding-identity contract may be broken");
        }

        if (baseline.Severity != current.Severity)
        {
            changes.Add(new FieldChange("severity", baseline.Severity.ToString(), current.Severity.ToString()));
        }

        if (!string.Equals(baseline.Description, current.Description, StringComparison.Ordinal))
        {
            changes.Add(new FieldChange("description", baseline.Description, current.Description));
        }

        // Property bag: union of keys, ordinally sorted so the change list is deterministic.
        // A key present on only one side is reported with null on the absent side.
        var baselineProps = baseline.Properties ?? EmptyProperties;
        var currentProps = current.Properties ?? EmptyProperties;
        var keys = baselineProps.Keys.Concat(currentProps.Keys)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            var inBaseline = baselineProps.TryGetValue(key, out var baselineValue);
            var inCurrent = currentProps.TryGetValue(key, out var currentValue);
            if (inBaseline != inCurrent || !string.Equals(baselineValue, currentValue, StringComparison.Ordinal))
            {
                changes.Add(new FieldChange(
                    "property:" + key,
                    inBaseline ? baselineValue : null,
                    inCurrent ? currentValue : null));
            }
        }

        return changes;
    }

    private static readonly IReadOnlyDictionary<string, string> EmptyProperties =
        new Dictionary<string, string>();

    private static bool TryIndexFindings(
        RunRecord record, string role,
        out Dictionary<string, Finding> index, out DiffResult failure)
    {
        index = new Dictionary<string, Finding>(record.Findings.Count, StringComparer.Ordinal);
        foreach (var finding in record.Findings)
        {
            if (!index.TryAdd(finding.Id, finding))
            {
                failure = DiffResult.CreateFailed(
                    $"{role} run record contains duplicate finding id '{finding.Id}'; finding " +
                    "ids must be unique within a run — the host's identity contract is broken " +
                    "and a diff over a broken join key would be untrustworthy");
                return false;
            }
        }

        failure = null!; // only read when the method returns false
        return true;
    }

    private static bool TryIndexChecks(
        RunRecord record, string role,
        out Dictionary<string, CheckResult> index, out DiffResult failure)
    {
        index = new Dictionary<string, CheckResult>(record.Checks.Count, StringComparer.Ordinal);
        foreach (var check in record.Checks)
        {
            if (!index.TryAdd(check.CheckId, check))
            {
                failure = DiffResult.CreateFailed(
                    $"{role} run record contains duplicate check id '{check.CheckId}'; check " +
                    "ids must be unique within a run's inventory");
                return false;
            }
        }

        failure = null!; // only read when the method returns false
        return true;
    }

    /// <summary>Renders a span for warning text: whole days when large, otherwise hours/minutes.</summary>
    private static string FormatAge(TimeSpan age)
    {
        if (age.TotalDays >= 1)
        {
            return $"{age.TotalDays:0.#} days";
        }

        return age.TotalHours >= 1 ? $"{age.TotalHours:0.#} hours" : $"{age.TotalMinutes:0.#} minutes";
    }
}
