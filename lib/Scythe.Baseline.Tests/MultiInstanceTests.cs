namespace Scythe.Baseline.Tests;

/// <summary>Multi-instance checks: the machine complies only if every instance complies, and a
/// failing check names exactly which instances failed.</summary>
public sealed class MultiInstanceTests
{
    [Fact]
    public void TwoOfFiveInstancesBad_FailsNamingExactlyThoseTwo()
    {
        var check = TestData.MultiIntegerCheck(comparison: CheckComparison.AtLeast(2));
        var observations = TestData.ObservedInstances(check.SettingKey,
            ("eth0", SettingObservation.Present(SettingValue.OfInteger(3))),
            ("eth1", SettingObservation.Present(SettingValue.OfInteger(0))),
            ("eth2", SettingObservation.Present(SettingValue.OfInteger(2))),
            ("eth3", SettingObservation.Present(SettingValue.OfInteger(1))),
            ("eth4", SettingObservation.Present(SettingValue.OfInteger(5))));

        var result = TestData.EvaluateOne(check, observations);

        Assert.Equal(ComplianceStatus.NonCompliant, result.Status);

        // Exactly the failing instances, by id, nothing else — an operator told "one of your
        // nine interfaces is misconfigured" without which one has a puzzle, not a finding.
        Assert.Equal(new[] { "eth1", "eth3" },
            result.InstanceOutcomes.Select(o => o.InstanceId));
        Assert.All(result.InstanceOutcomes,
            o => Assert.Equal(ComplianceStatus.NonCompliant, o.Status));

        // The summary names them too, with the counts.
        Assert.Contains("2 of 5", result.Reason, StringComparison.Ordinal);
        Assert.Contains("eth1", result.Reason, StringComparison.Ordinal);
        Assert.Contains("eth3", result.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("eth0", result.Reason, StringComparison.Ordinal);

        // Per-instance detail carries what was observed there and why it failed.
        var eth1 = result.InstanceOutcomes[0];
        Assert.Equal(SettingObservation.Present(SettingValue.OfInteger(0)), eth1.Observation);
        Assert.Contains("at-least 2", eth1.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AllInstancesComply_Passes()
    {
        var check = TestData.MultiIntegerCheck(comparison: CheckComparison.AtLeast(2));
        var observations = TestData.ObservedInstances(check.SettingKey,
            ("eth0", SettingObservation.Present(SettingValue.OfInteger(2))),
            ("eth1", SettingObservation.Present(SettingValue.OfInteger(4))),
            ("eth2", SettingObservation.Present(SettingValue.OfInteger(3))));

        var result = TestData.EvaluateOne(check, observations);

        Assert.Equal(ComplianceStatus.Compliant, result.Status);
        Assert.Empty(result.InstanceOutcomes);
        Assert.Contains("all 3 instances compliant", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(EmptyInstancesRule.EmptyIsCompliant, ComplianceStatus.Compliant)]
    [InlineData(EmptyInstancesRule.EmptyIsNonCompliant, ComplianceStatus.NonCompliant)]
    [InlineData(EmptyInstancesRule.EmptyIsUndetermined, ComplianceStatus.Undetermined)]
    public void EmptyInstanceCollection_FollowsTheCheckDeclaredRule(
        EmptyInstancesRule rule, ComplianceStatus expected)
    {
        // No instances found is not obviously compliant and not obviously undetermined — a
        // machine with zero shares trivially satisfies a per-share check, while zero network
        // interfaces means the probe went wrong. So the answer is declared per check.
        var check = TestData.MultiIntegerCheck(emptyInstances: rule);
        var observations = TestData.ObservedInstances(check.SettingKey /* zero instances */);

        var result = TestData.EvaluateOne(check, observations);
        Assert.Equal(expected, result.Status);
        Assert.Contains("no instances found", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void UnreadableInstance_WithNoDefiniteFailure_IsUndetermined_NeverAPass()
    {
        // Two instances comply, one could not be read. Not every instance was verified:
        // that is a coverage gap, never a pass.
        var check = TestData.MultiIntegerCheck(comparison: CheckComparison.AtLeast(2));
        var observations = TestData.ObservedInstances(check.SettingKey,
            ("eth0", SettingObservation.Present(SettingValue.OfInteger(3))),
            ("eth1", SettingObservation.ReadFailed("adapter query failed")),
            ("eth2", SettingObservation.Present(SettingValue.OfInteger(2))));

        var result = TestData.EvaluateOne(check, observations);

        Assert.Equal(ComplianceStatus.Undetermined, result.Status);
        var outcome = Assert.Single(result.InstanceOutcomes);
        Assert.Equal("eth1", outcome.InstanceId);
        Assert.Equal(ComplianceStatus.Undetermined, outcome.Status);
        Assert.Contains("1 of 3", result.Reason, StringComparison.Ordinal);
        Assert.Contains("eth1", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void DefiniteFailurePlusUnreadableInstance_IsNonCompliant_AndSurfacesBoth()
    {
        // A definite failure on any instance makes the check non-compliant even when another
        // instance could not be read — but the unread one is still surfaced, so the finding
        // does not hide the coverage gap.
        var check = TestData.MultiIntegerCheck(comparison: CheckComparison.AtLeast(2));
        var observations = TestData.ObservedInstances(check.SettingKey,
            ("eth0", SettingObservation.Present(SettingValue.OfInteger(0))),
            ("eth1", SettingObservation.ReadFailed("adapter query failed")),
            ("eth2", SettingObservation.Present(SettingValue.OfInteger(4))));

        var result = TestData.EvaluateOne(check, observations);

        Assert.Equal(ComplianceStatus.NonCompliant, result.Status);
        Assert.Equal(new[] { "eth0", "eth1" }, result.InstanceOutcomes.Select(o => o.InstanceId));
        Assert.Equal(ComplianceStatus.NonCompliant, result.InstanceOutcomes[0].Status);
        Assert.Equal(ComplianceStatus.Undetermined, result.InstanceOutcomes[1].Status);
        Assert.Contains("could not be evaluated", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void InstanceOutcomes_AreSortedByInstanceIdOrdinal_RegardlessOfInsertionOrder()
    {
        var check = TestData.MultiIntegerCheck(comparison: CheckComparison.AtLeast(10));
        // Deliberately inserted out of order; every instance fails, so all appear.
        var observations = TestData.ObservedInstances(check.SettingKey,
            ("zeta", SettingObservation.Present(SettingValue.OfInteger(1))),
            ("alpha", SettingObservation.Present(SettingValue.OfInteger(1))),
            ("Mid", SettingObservation.Present(SettingValue.OfInteger(1))));

        var result = TestData.EvaluateOne(check, observations);

        // Ordinal: uppercase 'M' sorts before lowercase letters.
        Assert.Equal(new[] { "Mid", "alpha", "zeta" },
            result.InstanceOutcomes.Select(o => o.InstanceId));
    }

    [Fact]
    public void TypeMismatchOnOneInstance_MakesThatInstanceUndetermined()
    {
        var check = TestData.MultiIntegerCheck(comparison: CheckComparison.AtLeast(2));
        var observations = TestData.ObservedInstances(check.SettingKey,
            ("eth0", SettingObservation.Present(SettingValue.OfInteger(3))),
            ("eth1", SettingObservation.Present(SettingValue.OfString("3"))));

        var result = TestData.EvaluateOne(check, observations);

        Assert.Equal(ComplianceStatus.Undetermined, result.Status);
        var outcome = Assert.Single(result.InstanceOutcomes);
        Assert.Equal("eth1", outcome.InstanceId);
    }
}
