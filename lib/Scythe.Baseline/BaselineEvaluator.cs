namespace Scythe.Baseline;

/// <summary>
/// Joins a validated check table with the host's observations and produces one result per check.
/// Pure: never mutates either input, and the same inputs always produce the same results in the
/// same (table) order. Linear in checks plus instances.
/// </summary>
public static class BaselineEvaluator
{
    public static EvaluationResult Evaluate(
        CheckTable table,
        BaselineObservations observations,
        MachineContext context)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(observations);
        ArgumentNullException.ThrowIfNull(context);

        // The table is validated before anything is evaluated. A table that fails validation
        // evaluates NOTHING: a partially-evaluated table would let a defective check disappear
        // from the output, and a check that cannot be evaluated must never count as compliant.
        var tableErrors = CheckTableValidator.Validate(table);
        if (tableErrors.Count > 0)
        {
            return new EvaluationResult
            {
                State = EvaluationState.Failed,
                Results = Array.Empty<CheckResult>(),
                Rollup = null,
                TableErrors = tableErrors,
            };
        }

        var results = new List<CheckResult>(table.Checks.Count);
        int compliant = 0, nonCompliant = 0, notApplicable = 0, undetermined = 0;

        foreach (var check in table.Checks)
        {
            var result = EvaluateCheck(check, observations, context);
            results.Add(result);
            switch (result.Status)
            {
                case ComplianceStatus.Compliant: compliant++; break;
                case ComplianceStatus.NonCompliant: nonCompliant++; break;
                case ComplianceStatus.NotApplicable: notApplicable++; break;
                case ComplianceStatus.Undetermined: undetermined++; break;
            }
        }

        return new EvaluationResult
        {
            State = EvaluationState.Ok,
            Results = results,
            Rollup = new RollupCounts(compliant, nonCompliant, notApplicable, undetermined),
            TableErrors = Array.Empty<CheckTableError>(),
        };
    }

    private static CheckResult EvaluateCheck(
        BaselineCheck check, BaselineObservations observations, MachineContext context)
    {
        if (check.AppliesWhen is { } condition && !Applies(condition, context))
        {
            return Result(check, ComplianceStatus.NotApplicable,
                $"not applicable: context '{condition.ContextKey}' is not one of [{string.Join(", ", condition.AnyOf)}]");
        }

        return check.Instancing == CheckInstancing.SingleInstance
            ? EvaluateSingleInstance(check, observations)
            : EvaluateMultiInstance(check, observations);
    }

    /// <summary>Applies when any context property with the condition's key (ordinal-ignore-case)
    /// has a value in the condition's list (ordinal-ignore-case). A missing key means the
    /// predicate is false: the check does not apply. Order-independent by construction.</summary>
    private static bool Applies(ApplicabilityCondition condition, MachineContext context)
    {
        foreach (var property in context.Properties)
        {
            if (!string.Equals(property.Key, condition.ContextKey, StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var candidate in condition.AnyOf)
            {
                if (string.Equals(property.Value, candidate, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    private static CheckResult EvaluateSingleInstance(BaselineCheck check, BaselineObservations observations)
    {
        if (observations.Settings.TryGetValue(check.SettingKey, out var observation))
        {
            var (status, reason) = EvaluateObservation(check, observation);
            return Result(check, status, reason,
                observedValue: observation is ObservedPresent p ? p.Value : null);
        }

        // A key entirely missing from the map is not the same as an explicit Absent: the host
        // never reported on this setting at all, so nothing was verified.
        if (observations.InstanceSettings.ContainsKey(check.SettingKey))
        {
            return Result(check, ComplianceStatus.Undetermined,
                $"setting '{check.SettingKey}' was observed per-instance but the check is single-instance");
        }
        return Result(check, ComplianceStatus.Undetermined,
            $"no observation supplied for setting '{check.SettingKey}'");
    }

    private static CheckResult EvaluateMultiInstance(BaselineCheck check, BaselineObservations observations)
    {
        if (!observations.InstanceSettings.TryGetValue(check.SettingKey, out var instances))
        {
            if (observations.Settings.ContainsKey(check.SettingKey))
            {
                return Result(check, ComplianceStatus.Undetermined,
                    $"setting '{check.SettingKey}' was observed single-instance but the check is multi-instance");
            }
            return Result(check, ComplianceStatus.Undetermined,
                $"no observation supplied for setting '{check.SettingKey}'");
        }

        if (instances.Count == 0)
        {
            // Validated non-null for multi-instance checks; the rule is per-check by design.
            return check.EmptyInstances!.Value switch
            {
                EmptyInstancesRule.EmptyIsCompliant => Result(check, ComplianceStatus.Compliant,
                    "no instances found; this check declares an empty instance collection compliant"),
                EmptyInstancesRule.EmptyIsNonCompliant => Result(check, ComplianceStatus.NonCompliant,
                    "no instances found; this check declares an empty instance collection non-compliant"),
                _ => Result(check, ComplianceStatus.Undetermined,
                    "no instances found; this check declares an empty instance collection undetermined"),
            };
        }

        // Evaluate every instance with the same semantics as a single observation, including
        // the absence rule — an absent setting on one interface means the default applies there.
        var problems = new List<InstanceOutcome>();
        foreach (var (instanceId, observation) in instances)
        {
            var (status, reason) = EvaluateObservation(check, observation);
            if (status != ComplianceStatus.Compliant)
                problems.Add(new InstanceOutcome(instanceId, status, observation, reason));
        }

        // Instance dictionaries carry no ordering guarantee; sort so output is deterministic.
        problems.Sort(static (a, b) => string.CompareOrdinal(a.InstanceId, b.InstanceId));

        var failingIds = problems.Where(p => p.Status == ComplianceStatus.NonCompliant)
                                 .Select(p => p.InstanceId).ToList();
        var undeterminedIds = problems.Where(p => p.Status == ComplianceStatus.Undetermined)
                                      .Select(p => p.InstanceId).ToList();

        // The machine complies only if EVERY instance complies. A definite failure on any
        // instance makes the check non-compliant even if other instances could not be read;
        // the unread ones are still surfaced so the coverage gap is not hidden by the finding.
        if (failingIds.Count > 0)
        {
            var reason = $"{failingIds.Count} of {instances.Count} instances non-compliant: {string.Join(", ", failingIds)}";
            if (undeterminedIds.Count > 0)
                reason += $"; {undeterminedIds.Count} could not be evaluated: {string.Join(", ", undeterminedIds)}";
            return Result(check, ComplianceStatus.NonCompliant, reason, problems);
        }

        // No definite failure, but not every instance was verified: that is a coverage gap,
        // never a pass.
        if (undeterminedIds.Count > 0)
        {
            return Result(check, ComplianceStatus.Undetermined,
                $"{undeterminedIds.Count} of {instances.Count} instances could not be evaluated: {string.Join(", ", undeterminedIds)}",
                problems);
        }

        return Result(check, ComplianceStatus.Compliant, $"all {instances.Count} instances compliant");
    }

    /// <summary>Evaluates one observation under the check's comparison and absence rule.</summary>
    private static (ComplianceStatus Status, string Reason) EvaluateObservation(
        BaselineCheck check, SettingObservation observation)
    {
        switch (observation)
        {
            case ObservedPresent present:
                if (present.Value.Kind != check.ExpectedKind)
                {
                    // A type mismatch is a collection defect, not evidence about the machine:
                    // the check was not verified, so the result is Undetermined, never a pass.
                    return (ComplianceStatus.Undetermined,
                        $"observed value is {present.Value.Kind} but the check declares {check.ExpectedKind}");
                }
                return Compare(check, present.Value, observedDescription: $"observed {present.Value.ToDisplay()}");

            case ObservedAbsent:
                return check.Absence switch
                {
                    AbsenceIsCompliant => (ComplianceStatus.Compliant,
                        "setting is absent; absence is declared compliant"),
                    AbsenceIsNonCompliant => (ComplianceStatus.NonCompliant,
                        "setting is absent; absence is declared non-compliant"),
                    AbsenceMeansDefault d => Compare(check, d.DefaultValue,
                        observedDescription: $"setting is absent; platform default {d.DefaultValue.ToDisplay()}"),
                    _ => (ComplianceStatus.Undetermined, "setting is absent and the absence rule is unrecognised"),
                };

            case ObservedReadFailed failed:
                // The host could not read the setting. Nothing was verified: a gap, not a pass.
                return (ComplianceStatus.Undetermined, $"read failed: {failed.Reason}");

            default:
                return (ComplianceStatus.Undetermined,
                    $"unrecognised observation type {observation.GetType().Name}");
        }
    }

    private static (ComplianceStatus, string) Compare(
        BaselineCheck check, SettingValue value, string observedDescription)
    {
        var satisfied = check.Comparison switch
        {
            EqualsComparison e => AreEqual(value, e.Expected, check.CaseSensitivity),
            NotEqualsComparison n => !AreEqual(value, n.Expected, check.CaseSensitivity),
            // Numeric floor: greater or equal passes, because higher is stricter. Validation
            // guarantees both the declared kind and (via kind checks above) the value are integer.
            AtLeastComparison a => ((IntegerValue)value).Value >= a.Floor,
            OneOfComparison o => o.Values.Any(v => AreEqual(value, v, check.CaseSensitivity)),
            NoneOfComparison o => !o.Values.Any(v => AreEqual(value, v, check.CaseSensitivity)),
            _ => (bool?)null,
        };

        if (satisfied is null)
            return (ComplianceStatus.Undetermined, $"unrecognised comparison type {check.Comparison.GetType().Name}");

        return satisfied.Value
            ? (ComplianceStatus.Compliant, $"{observedDescription} satisfies {check.Comparison.Describe()}")
            : (ComplianceStatus.NonCompliant, $"{observedDescription} does not satisfy {check.Comparison.Describe()}");
    }

    /// <summary>Value equality. Strings compare per the check's declared case sensitivity,
    /// ordinal (never culture-sensitive) in both modes. Cross-kind values are never equal.</summary>
    private static bool AreEqual(SettingValue a, SettingValue b, StringCase? stringCase) => (a, b) switch
    {
        (IntegerValue x, IntegerValue y) => x.Value == y.Value,
        (BooleanValue x, BooleanValue y) => x.Value == y.Value,
        (StringValue x, StringValue y) => string.Equals(x.Value, y.Value,
            stringCase == StringCase.Insensitive ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal),
        _ => false,
    };

    private static CheckResult Result(
        BaselineCheck check,
        ComplianceStatus status,
        string reason,
        IReadOnlyList<InstanceOutcome>? instanceOutcomes = null,
        SettingValue? observedValue = null) => new()
    {
        CheckId = check.Id,
        Title = check.Title,
        Severity = check.Severity,
        Status = status,
        Reason = reason,
        Remediation = check.Remediation,
        ObservedValue = observedValue,
        InstanceOutcomes = instanceOutcomes ?? Array.Empty<InstanceOutcome>(),
    };
}
