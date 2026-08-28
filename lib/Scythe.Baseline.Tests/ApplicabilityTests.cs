namespace Scythe.Baseline.Tests;

/// <summary>Applicability predicates: a check that does not apply is NotApplicable, which is
/// neither a pass nor a failure and is counted as neither.</summary>
public sealed class ApplicabilityTests
{
    private static BaselineCheck ServerOnlyCheck() => TestData.IntegerCheck(
        id: "SRV-001",
        appliesWhen: new ApplicabilityCondition("Role", new[] { "Server", "DomainController" }));

    [Fact]
    public void NonMatchingContext_YieldsNotApplicable_CountedAsNeitherPassNorFail()
    {
        var check = ServerOnlyCheck();
        // The observation would PASS if evaluated — proving NotApplicable is decided before
        // the comparison ever runs, not derived from it.
        var observations = TestData.Observed(
            (check.SettingKey, SettingObservation.Present(SettingValue.OfInteger(1))));

        var evaluation = BaselineEvaluator.Evaluate(TestData.Table(check), observations,
            TestData.Context(("Role", "Workstation")));

        var result = Assert.Single(evaluation.Results);
        Assert.Equal(ComplianceStatus.NotApplicable, result.Status);
        Assert.Equal(new RollupCounts(0, 0, 1, 0), evaluation.Rollup);
    }

    [Fact]
    public void MatchingContext_EvaluatesNormally()
    {
        var check = ServerOnlyCheck();
        var observations = TestData.Observed(
            (check.SettingKey, SettingObservation.Present(SettingValue.OfInteger(0))));

        var result = TestData.EvaluateOne(check, observations,
            TestData.Context(("Role", "Server")));

        // Applied — and the value is wrong, so this is a real failure, not NotApplicable.
        Assert.Equal(ComplianceStatus.NonCompliant, result.Status);
    }

    [Fact]
    public void ContextKeyAndValue_MatchCaseInsensitively()
    {
        var check = ServerOnlyCheck();
        var observations = TestData.Observed(
            (check.SettingKey, SettingObservation.Present(SettingValue.OfInteger(1))));

        var result = TestData.EvaluateOne(check, observations,
            TestData.Context(("role", "domaincontroller")));

        Assert.Equal(ComplianceStatus.Compliant, result.Status);
    }

    [Fact]
    public void MissingContextKey_MeansTheCheckDoesNotApply()
    {
        var check = ServerOnlyCheck();
        var observations = TestData.Observed(
            (check.SettingKey, SettingObservation.Present(SettingValue.OfInteger(1))));

        var result = TestData.EvaluateOne(check, observations, MachineContext.Empty);

        Assert.Equal(ComplianceStatus.NotApplicable, result.Status);
        Assert.Contains("Role", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void CheckWithoutPredicate_AppliesToEveryMachine()
    {
        var check = TestData.IntegerCheck();
        var observations = TestData.Observed(
            (check.SettingKey, SettingObservation.Present(SettingValue.OfInteger(1))));

        var result = TestData.EvaluateOne(check, observations,
            TestData.Context(("Role", "AnythingAtAll")));

        Assert.Equal(ComplianceStatus.Compliant, result.Status);
    }

    [Fact]
    public void NotApplicable_TakesPrecedenceOverMissingObservation()
    {
        // A check that does not apply is NotApplicable even when the host also never
        // observed its setting — inapplicability is decided first and is not a coverage gap.
        var check = ServerOnlyCheck();

        var result = TestData.EvaluateOne(check, TestData.Observed(),
            TestData.Context(("Role", "Workstation")));

        Assert.Equal(ComplianceStatus.NotApplicable, result.Status);
    }
}
