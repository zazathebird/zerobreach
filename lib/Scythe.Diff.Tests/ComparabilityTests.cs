namespace Scythe.Diff.Tests;

using Xunit;
using static TestData;

public sealed class ComparabilityTests
{
    [Fact]
    public void DifferentMachine_Failed_WithNoPartialResults()
    {
        var baseline = BaselineRun(
            findings: new[] { Finding("f1") }, machine: "machine-A");
        var current = Run(
            findings: new[] { Finding("f2") }, machine: "machine-B");

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(OperationState.Failed, result.State);
        Assert.NotNull(result.Error);
        Assert.Contains("machine-A", result.Error);
        Assert.Contains("machine-B", result.Error);
        // Refused means refused: no partial output of any kind.
        Assert.Empty(result.NewFindings);
        Assert.Empty(result.ResolvedFindings);
        Assert.Empty(result.PersistingFindings);
        Assert.Empty(result.ChangedFindings);
        Assert.Empty(result.CoverageDeltas);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void MachineIdComparison_IsOrdinalCaseSensitive()
    {
        // Machine ids are opaque host-assigned identity; folding case would treat two distinct
        // ids as one machine. If the host's ids are case-insensitive it normalises them.
        var baseline = BaselineRun(machine: "MACHINE-A");
        var current = Run(machine: "machine-a");

        Assert.Equal(OperationState.Failed, BaselineDiff.Diff(baseline, current).State);
    }

    [Fact]
    public void NarrowerBaseline_WarnsNamingMissingChecks_DetectedFromInventoryNotModeString()
    {
        // Mode strings are deliberately identical: the detection must come from the inventory.
        var baseline = BaselineRun(mode: "deep", checks: new[] { Check("chk.a") });
        var current = Run(mode: "deep", checks: new[]
        {
            Check("chk.a"), Check("chk.registry"), Check("chk.services"),
        });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(OperationState.Ok, result.State);
        var warning = Assert.Single(result.Warnings);
        Assert.Contains("narrower", warning);
        Assert.Contains("chk.registry", warning);
        Assert.Contains("chk.services", warning);
        Assert.DoesNotContain("chk.a,", warning);
    }

    [Fact]
    public void ModeStringMismatch_Warns_EvenWhenInventoriesMatch()
    {
        var checks = new[] { Check("chk.a") };
        var baseline = BaselineRun(mode: "quick", checks: checks);
        var current = Run(mode: "deep", checks: checks);

        var result = BaselineDiff.Diff(baseline, current);

        var warning = Assert.Single(result.Warnings);
        Assert.Contains("quick", warning);
        Assert.Contains("deep", warning);
    }

    [Fact]
    public void StaleBaseline_Warns_FreshBaselineDoesNot()
    {
        var baseline = BaselineRun(timestamp: CurrentTime - TimeSpan.FromDays(45));
        var current = Run(timestamp: CurrentTime);

        var stale = BaselineDiff.Diff(baseline, current, new DiffOptions(TimeSpan.FromDays(30)));
        var fresh = BaselineDiff.Diff(baseline, current, new DiffOptions(TimeSpan.FromDays(60)));
        var unchecked_ = BaselineDiff.Diff(baseline, current); // no MaxBaselineAge supplied

        Assert.Equal(OperationState.Ok, stale.State);
        var warning = Assert.Single(stale.Warnings);
        Assert.Contains("45 days", warning);
        Assert.Contains("30 days", warning);
        Assert.Empty(fresh.Warnings);
        Assert.Empty(unchecked_.Warnings);
    }

    [Fact]
    public void BaselineNewerThanCurrent_ClockSkew_Warns()
    {
        var baseline = BaselineRun(timestamp: CurrentTime + TimeSpan.FromHours(2));
        var current = Run(timestamp: CurrentTime);

        var result = BaselineDiff.Diff(baseline, current, new DiffOptions(TimeSpan.FromDays(30)));

        Assert.Equal(OperationState.Ok, result.State);
        var warning = Assert.Single(result.Warnings);
        Assert.Contains("later than", warning);
    }

    [Fact]
    public void DuplicateFindingId_Failed_HostContractBroken()
    {
        var baseline = BaselineRun(findings: new[] { Finding("f1"), Finding("f1") });
        var current = Run(findings: new[] { Finding("f1") });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(OperationState.Failed, result.State);
        Assert.NotNull(result.Error);
        Assert.Contains("duplicate finding id 'f1'", result.Error);
        Assert.Contains("baseline", result.Error);
        Assert.Empty(result.PersistingFindings);
    }

    [Fact]
    public void DuplicateFindingIdInCurrent_AlsoFailed()
    {
        var baseline = BaselineRun(findings: new[] { Finding("f1") });
        var current = Run(findings: new[] { Finding("f2"), Finding("f2") });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("current", result.Error!);
    }

    [Fact]
    public void DuplicateCheckId_Failed()
    {
        var baseline = BaselineRun(checks: new[] { Check("chk.a"), Check("chk.a", CheckStatus.NotRun) });
        var current = Run();

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("duplicate check id 'chk.a'", result.Error!);
    }
}
