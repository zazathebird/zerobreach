namespace Scythe.Baseline.Tests;

/// <summary>The three absence rules. Absent is not zero and not automatically non-compliant:
/// an unset setting means the platform default applies, and each check declares what that means.</summary>
public sealed class AbsenceRuleTests
{
    private static CheckResult EvaluateAbsent(BaselineCheck check) =>
        TestData.EvaluateOne(check, TestData.Observed((check.SettingKey, SettingObservation.Absent)));

    [Fact]
    public void AbsenceIsCompliant_AbsentSettingPasses()
    {
        var result = EvaluateAbsent(TestData.IntegerCheck(absence: AbsenceRule.Compliant));
        Assert.Equal(ComplianceStatus.Compliant, result.Status);
        Assert.Contains("absence is declared compliant", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AbsenceIsNonCompliant_AbsentSettingFails()
    {
        var result = EvaluateAbsent(TestData.IntegerCheck(absence: AbsenceRule.NonCompliant));
        Assert.Equal(ComplianceStatus.NonCompliant, result.Status);
        Assert.Contains("absence is declared non-compliant", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AbsenceMeansDefault_EvaluatesAgainstTheDefault_NotAgainstAbsence()
    {
        // The brief's specific requirement: a missing value under "default is X" evaluates
        // against X. Floor 2, platform default 3: absent must PASS, because the default is
        // strict enough — an evaluator that treats missing as zero would fail it.
        var passing = EvaluateAbsent(TestData.IntegerCheck(
            comparison: CheckComparison.AtLeast(2),
            absence: AbsenceRule.MeansDefault(SettingValue.OfInteger(3))));
        Assert.Equal(ComplianceStatus.Compliant, passing.Status);
        Assert.Contains("platform default 3", passing.Reason, StringComparison.Ordinal);

        // Floor 5, platform default 3: absent must FAIL, because the default is too lax —
        // an evaluator that treats missing as fine would pass it.
        var failing = EvaluateAbsent(TestData.IntegerCheck(
            comparison: CheckComparison.AtLeast(5),
            absence: AbsenceRule.MeansDefault(SettingValue.OfInteger(3))));
        Assert.Equal(ComplianceStatus.NonCompliant, failing.Status);
    }

    [Fact]
    public void AbsenceMeansDefault_UsesTheCheckComparison_NotJustEquality()
    {
        // Default "Disabled" against none-of {"Disabled"}: the default itself is the
        // forbidden value, so an unset setting is a finding.
        var result = EvaluateAbsent(TestData.StringCheck(StringCase.Insensitive,
            comparison: CheckComparison.NoneOf(SettingValue.OfString("Disabled")),
            absence: AbsenceRule.MeansDefault(SettingValue.OfString("disabled"))));
        Assert.Equal(ComplianceStatus.NonCompliant, result.Status);
    }

    [Fact]
    public void AbsentWithDefault_LeavesObservedValueNull()
    {
        // The default is what the comparison ran against, not what was observed; reporting it
        // as an observed value would fabricate a reading the host never made.
        var result = EvaluateAbsent(TestData.IntegerCheck(
            comparison: CheckComparison.AtLeast(2),
            absence: AbsenceRule.MeansDefault(SettingValue.OfInteger(3))));
        Assert.Null(result.ObservedValue);
    }

    [Fact]
    public void ExplicitAbsent_IsDistinctFromNoObservation()
    {
        // Same check, two situations: the host read the setting and found it unset (absence
        // rule applies) versus the host never reported on it (nothing verified, Undetermined).
        var check = TestData.IntegerCheck(absence: AbsenceRule.Compliant);

        var absent = TestData.EvaluateOne(check,
            TestData.Observed((check.SettingKey, SettingObservation.Absent)));
        var unreported = TestData.EvaluateOne(check, TestData.Observed());

        Assert.Equal(ComplianceStatus.Compliant, absent.Status);
        Assert.Equal(ComplianceStatus.Undetermined, unreported.Status);
    }

    [Fact]
    public void AbsenceRule_AppliesPerInstance_InMultiInstanceChecks()
    {
        // An absent setting on one interface means the default applies there. Default 3
        // against floor 2: the absent instance passes; the explicit 1 fails.
        var check = TestData.MultiIntegerCheck(
            comparison: CheckComparison.AtLeast(2),
            absence: AbsenceRule.MeansDefault(SettingValue.OfInteger(3)));
        var observations = TestData.ObservedInstances(check.SettingKey,
            ("eth0", SettingObservation.Absent),
            ("eth1", SettingObservation.Present(SettingValue.OfInteger(1))));

        var result = TestData.EvaluateOne(check, observations);
        Assert.Equal(ComplianceStatus.NonCompliant, result.Status);
        var outcome = Assert.Single(result.InstanceOutcomes);
        Assert.Equal("eth1", outcome.InstanceId);
    }
}
