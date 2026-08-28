using System.Reflection;

namespace Scythe.Baseline.Tests;

/// <summary>The evaluator's overall contract: all four results are producible, every evaluated
/// check appears in the output, and the rollup never hides Undetermined behind a pass rate.</summary>
public sealed class EvaluatorCoreTests
{
    [Fact]
    public void AllFourResultsAreProduced_AndEveryCheckAppearsInOutput()
    {
        var table = TestData.Table(
            TestData.IntegerCheck(id: "C-PASS", settingKey: "K1",
                comparison: CheckComparison.EqualTo(SettingValue.OfInteger(1))),
            TestData.IntegerCheck(id: "C-FAIL", settingKey: "K2",
                comparison: CheckComparison.EqualTo(SettingValue.OfInteger(1))),
            TestData.IntegerCheck(id: "C-NA", settingKey: "K1",
                appliesWhen: new ApplicabilityCondition("Role", new[] { "Server" })),
            TestData.IntegerCheck(id: "C-UNDET", settingKey: "K3"));

        var observations = TestData.Observed(
            ("K1", SettingObservation.Present(SettingValue.OfInteger(1))),
            ("K2", SettingObservation.Present(SettingValue.OfInteger(0))),
            ("K3", SettingObservation.ReadFailed("access denied")));

        var evaluation = BaselineEvaluator.Evaluate(
            table, observations, TestData.Context(("Role", "Workstation")));

        Assert.Equal(EvaluationState.Ok, evaluation.State);

        // Report what passed, not only what failed: every check is in the output, in table order.
        Assert.Equal(new[] { "C-PASS", "C-FAIL", "C-NA", "C-UNDET" },
            evaluation.Results.Select(r => r.CheckId));
        Assert.Equal(
            new[]
            {
                ComplianceStatus.Compliant,
                ComplianceStatus.NonCompliant,
                ComplianceStatus.NotApplicable,
                ComplianceStatus.Undetermined,
            },
            evaluation.Results.Select(r => r.Status));

        Assert.NotNull(evaluation.Rollup);
        Assert.Equal(new RollupCounts(1, 1, 1, 1), evaluation.Rollup);
        Assert.Equal(4, evaluation.Rollup!.Total);
    }

    [Fact]
    public void CompliantResult_CarriesObservedValueAndReason()
    {
        var check = TestData.IntegerCheck(comparison: CheckComparison.AtLeast(3));
        var result = TestData.EvaluateOne(check, TestData.Observed(
            (check.SettingKey, SettingObservation.Present(SettingValue.OfInteger(5)))));

        Assert.Equal(ComplianceStatus.Compliant, result.Status);
        Assert.Equal(SettingValue.OfInteger(5), result.ObservedValue);
        Assert.Contains("at-least 3", result.Reason, StringComparison.Ordinal);
        Assert.Equal(check.Remediation, result.Remediation);
        Assert.Equal(check.Severity, result.Severity);
        Assert.Equal(check.Title, result.Title);
    }

    [Fact]
    public void ReadFailure_IsUndetermined_NeverCompliant()
    {
        var check = TestData.IntegerCheck();
        var result = TestData.EvaluateOne(check, TestData.Observed(
            (check.SettingKey, SettingObservation.ReadFailed("registry hive unavailable"))));

        Assert.Equal(ComplianceStatus.Undetermined, result.Status);
        Assert.Contains("registry hive unavailable", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void SettingNeverReportedByHost_IsUndetermined()
    {
        // A key entirely missing from the observation map is distinct from an explicit Absent:
        // the host never looked, so nothing was verified.
        var check = TestData.IntegerCheck(settingKey: "Never\\Reported",
            absence: AbsenceRule.Compliant);
        var result = TestData.EvaluateOne(check, TestData.Observed());

        // Even though absence is declared compliant, no-observation is not absence.
        Assert.Equal(ComplianceStatus.Undetermined, result.Status);
        Assert.Contains("no observation supplied", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ObservedTypeMismatch_IsUndetermined_NeverCompliant()
    {
        // A type mismatch is a collection defect, not evidence about the machine.
        var check = TestData.IntegerCheck();
        var result = TestData.EvaluateOne(check, TestData.Observed(
            (check.SettingKey, SettingObservation.Present(SettingValue.OfString("5")))));

        Assert.Equal(ComplianceStatus.Undetermined, result.Status);
        Assert.Contains("String", result.Reason, StringComparison.Ordinal);
        Assert.Contains("Integer", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void SingleInstanceCheck_AgainstPerInstanceObservation_IsUndetermined()
    {
        var check = TestData.IntegerCheck(settingKey: "Shape\\Mismatch");
        var observations = TestData.ObservedInstances("Shape\\Mismatch",
            ("eth0", SettingObservation.Present(SettingValue.OfInteger(1))));

        var result = TestData.EvaluateOne(check, observations);
        Assert.Equal(ComplianceStatus.Undetermined, result.Status);
        Assert.Contains("per-instance", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void MultiInstanceCheck_AgainstSingleObservation_IsUndetermined()
    {
        var check = TestData.MultiIntegerCheck(settingKey: "Shape\\Mismatch2");
        var observations = TestData.Observed(
            ("Shape\\Mismatch2", SettingObservation.Present(SettingValue.OfInteger(9))));

        var result = TestData.EvaluateOne(check, observations);
        Assert.Equal(ComplianceStatus.Undetermined, result.Status);
        Assert.Contains("single-instance", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void UndeterminedIsCountedSeparately_NeverInsideCompliant()
    {
        var table = TestData.Table(
            TestData.IntegerCheck(id: "A", settingKey: "K1"),
            TestData.IntegerCheck(id: "B", settingKey: "K2"));
        var observations = TestData.Observed(
            ("K1", SettingObservation.Present(SettingValue.OfInteger(1))),
            ("K2", SettingObservation.ReadFailed("timeout")));

        var evaluation = BaselineEvaluator.Evaluate(table, observations, MachineContext.Empty);

        Assert.Equal(1, evaluation.Rollup!.Compliant);
        Assert.Equal(1, evaluation.Rollup.Undetermined);
        Assert.Equal(0, evaluation.Rollup.NonCompliant);
    }

    [Fact]
    public void NoExposedPassRate_ThatCouldAbsorbUndetermined()
    {
        // The rollup deliberately exposes only the four counts (plus their total). Any
        // percentage-shaped member would either absorb Undetermined into its denominator or
        // silently drop it; this pins that no such member exists on the result surface.
        var suspicious = new[] { "rate", "percent", "ratio", "score", "passed", "compliance" };
        foreach (var type in new[] { typeof(RollupCounts), typeof(EvaluationResult) })
        {
            foreach (var member in type.GetMembers(BindingFlags.Public | BindingFlags.Instance))
            {
                foreach (var word in suspicious)
                {
                    Assert.False(
                        member.Name.Contains(word, StringComparison.OrdinalIgnoreCase),
                        $"{type.Name}.{member.Name} looks like a pass-rate; the rollup must expose only counts");
                }
            }
        }
    }

    [Fact]
    public void RollupTotal_IsTheSumOfAllFourCounts()
    {
        var rollup = new RollupCounts(3, 2, 1, 4);
        Assert.Equal(10, rollup.Total);
    }
}
