namespace ZeroBreach.Diff.Tests;

using Xunit;
using static TestData;

public sealed class FindingDeltaTests
{
    [Fact]
    public void MixedScenario_PopulatesAllFourSetsCorrectly()
    {
        var baseline = BaselineRun(findings: new[]
        {
            Finding("f-resolved", description: "goes away"),
            Finding("f-persisting", description: "stays the same"),
            Finding("f-changed", severity: FindingSeverity.Low, description: "will escalate"),
        });
        var current = Run(findings: new[]
        {
            Finding("f-new", description: "just appeared"),
            Finding("f-persisting", description: "stays the same"),
            Finding("f-changed", severity: FindingSeverity.High, description: "will escalate"),
        });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal(new[] { "f-new" }, result.NewFindings.Select(f => f.Id));
        Assert.Equal(new[] { "f-resolved" }, result.ResolvedFindings.Select(f => f.Id));
        Assert.Equal(new[] { "f-persisting" }, result.PersistingFindings.Select(f => f.Id));
        Assert.Equal(new[] { "f-changed" }, result.ChangedFindings.Select(c => c.Current.Id));
    }

    [Fact]
    public void SeverityChange_LandsInChangedOnly_NotNewPlusResolved()
    {
        var baseline = BaselineRun(findings: new[] { Finding("f1", FindingSeverity.Low) });
        var current = Run(findings: new[] { Finding("f1", FindingSeverity.Critical) });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Empty(result.NewFindings);
        Assert.Empty(result.ResolvedFindings);
        Assert.Empty(result.PersistingFindings);
        var changed = Assert.Single(result.ChangedFindings);
        var change = Assert.Single(changed.Changes);
        Assert.Equal("severity", change.Field);
        Assert.Equal("Low", change.BaselineValue);
        Assert.Equal("Critical", change.CurrentValue);
    }

    [Fact]
    public void DescriptionChange_ReportedFieldByField()
    {
        var baseline = BaselineRun(findings: new[] { Finding("f1", description: "old text") });
        var current = Run(findings: new[] { Finding("f1", description: "new text") });

        var result = BaselineDiff.Diff(baseline, current);

        var changed = Assert.Single(result.ChangedFindings);
        var change = Assert.Single(changed.Changes);
        Assert.Equal("description", change.Field);
        Assert.Equal("old text", change.BaselineValue);
        Assert.Equal("new text", change.CurrentValue);
    }

    [Fact]
    public void PropertyBagValueChange_ReportedAsChangedWithFieldDetail()
    {
        var baseline = BaselineRun(findings: new[]
        {
            Finding("f1", properties: new Dictionary<string, string> { ["sha256"] = "aaaa", ["signer"] = "Vendor" }),
        });
        var current = Run(findings: new[]
        {
            Finding("f1", properties: new Dictionary<string, string> { ["sha256"] = "bbbb", ["signer"] = "Vendor" }),
        });

        var result = BaselineDiff.Diff(baseline, current);

        var changed = Assert.Single(result.ChangedFindings);
        var change = Assert.Single(changed.Changes);
        Assert.Equal("property:sha256", change.Field);
        Assert.Equal("aaaa", change.BaselineValue);
        Assert.Equal("bbbb", change.CurrentValue);
    }

    [Fact]
    public void PropertyAddedAndRemoved_ReportedWithNullOnAbsentSide()
    {
        var baseline = BaselineRun(findings: new[]
        {
            Finding("f1", properties: new Dictionary<string, string> { ["removed"] = "was-here" }),
        });
        var current = Run(findings: new[]
        {
            Finding("f1", properties: new Dictionary<string, string> { ["added"] = "now-here" }),
        });

        var result = BaselineDiff.Diff(baseline, current);

        var changed = Assert.Single(result.ChangedFindings);
        Assert.Equal(2, changed.Changes.Count);
        Assert.Equal(new FieldChange("property:added", null, "now-here"), changed.Changes[0]);
        Assert.Equal(new FieldChange("property:removed", "was-here", null), changed.Changes[1]);
    }

    [Fact]
    public void NullAndEmptyPropertyBags_AreEquivalent_NoChangeReported()
    {
        // Null bag and empty bag both mean "no extra fields"; treating them as different would
        // report a phantom change every time the host normalises one to the other.
        var baseline = BaselineRun(findings: new[] { Finding("f1", properties: null) });
        var current = Run(findings: new[] { Finding("f1", properties: new Dictionary<string, string>()) });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Single(result.PersistingFindings);
        Assert.Empty(result.ChangedFindings);
    }

    [Fact]
    public void IdenticalRecords_AllPersisting_EverythingElseEmpty_NoWarnings()
    {
        var findings = new[]
        {
            Finding("f1", properties: new Dictionary<string, string> { ["k"] = "v" }),
            Finding("f2"),
        };
        var checks = new[] { Check("chk.a"), Check("chk.b", CheckStatus.Inconclusive, "access denied") };
        var baseline = BaselineRun(findings, checks);
        var current = Run(findings, checks);

        var result = BaselineDiff.Diff(
            baseline, current, new DiffOptions(MaxBaselineAge: TimeSpan.FromDays(90)));

        Assert.Equal(OperationState.Ok, result.State);
        Assert.Null(result.Error);
        Assert.Empty(result.Warnings);
        Assert.Equal(new[] { "f1", "f2" }, result.PersistingFindings.Select(f => f.Id));
        Assert.Empty(result.NewFindings);
        Assert.Empty(result.ResolvedFindings);
        Assert.Empty(result.ChangedFindings);
        Assert.Empty(result.CoverageDeltas);
    }

    [Fact]
    public void EmptyBaseline_EverythingNew_AndAllChecksCoverageAdded()
    {
        var baseline = BaselineRun(
            findings: Array.Empty<Finding>(), checks: Array.Empty<CheckResult>());
        var current = Run(
            findings: new[] { Finding("f1"), Finding("f2") },
            checks: new[] { Check("chk.a"), Check("chk.b") });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(new[] { "f1", "f2" }, result.NewFindings.Select(f => f.Id));
        Assert.Empty(result.ResolvedFindings);
        Assert.Empty(result.PersistingFindings);
        Assert.Empty(result.ChangedFindings);
        Assert.Equal(2, result.CoverageDeltas.Count);
        Assert.All(result.CoverageDeltas, d => Assert.Equal(CoverageChangeKind.Added, d.Kind));
        // An empty baseline inventory is the extreme narrower-baseline case, so the warning
        // must fire here too — every finding shown as "new" is against a run that saw nothing.
        Assert.Contains(result.Warnings, w => w.Contains("narrower"));
    }

    [Fact]
    public void EmptyCurrent_EverythingResolved_AndAllChecksCoverageRemoved()
    {
        var baseline = BaselineRun(
            findings: new[] { Finding("f1"), Finding("f2") },
            checks: new[] { Check("chk.a"), Check("chk.b") });
        var current = Run(
            findings: Array.Empty<Finding>(), checks: Array.Empty<CheckResult>());

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(new[] { "f1", "f2" }, result.ResolvedFindings.Select(f => f.Id));
        Assert.Empty(result.NewFindings);
        Assert.Empty(result.PersistingFindings);
        Assert.Equal(2, result.CoverageDeltas.Count);
        Assert.All(result.CoverageDeltas, d => Assert.Equal(CoverageChangeKind.Removed, d.Kind));
    }

    [Fact]
    public void TargetChangeUnderStableId_ReportedAsChanged_AndContractWarned()
    {
        // By construction the id hashes over the target, so this "cannot happen" — which is
        // exactly why it must be surfaced loudly if it does: the identity contract is broken.
        var baseline = BaselineRun(findings: new[] { Finding("f1", target: @"C:\old\path.exe") });
        var current = Run(findings: new[] { Finding("f1", target: @"C:\new\path.exe") });

        var result = BaselineDiff.Diff(baseline, current);

        var changed = Assert.Single(result.ChangedFindings);
        var change = Assert.Single(changed.Changes);
        Assert.Equal("target", change.Field);
        Assert.Contains(result.Warnings, w => w.Contains("identity contract") && w.Contains("f1"));
    }
}
