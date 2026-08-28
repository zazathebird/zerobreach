namespace Scythe.Diff.Tests;

using Xunit;
using static TestData;

public sealed class CoverageDeltaTests
{
    [Fact]
    public void CompletedToInconclusive_IsRegression_EvenWithZeroFindingChanges()
    {
        // THE key property: a diff that says "nothing new" while a check stopped producing
        // trustworthy results must be impossible. Findings are identical on both sides here.
        var findings = new[] { Finding("f1") };
        var baseline = BaselineRun(findings, checks: new[] { Check("chk.autoruns") });
        var current = Run(findings, checks: new[]
        {
            Check("chk.autoruns", CheckStatus.Inconclusive, "access denied to hive"),
        });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Empty(result.NewFindings);
        Assert.Empty(result.ResolvedFindings);
        Assert.Empty(result.ChangedFindings);
        var delta = Assert.Single(result.CoverageDeltas);
        Assert.Equal("chk.autoruns", delta.CheckId);
        Assert.Equal(CoverageChangeKind.Regression, delta.Kind);
        Assert.Equal(CheckStatus.Completed, delta.BaselineStatus);
        Assert.Equal(CheckStatus.Inconclusive, delta.CurrentStatus);
        Assert.Equal("access denied to hive", delta.CurrentReason);
    }

    [Fact]
    public void CompletedToNotRun_IsRegression()
    {
        var baseline = BaselineRun(checks: new[] { Check("chk.a") });
        var current = Run(checks: new[] { Check("chk.a", CheckStatus.NotRun, "disabled by policy") });

        var result = BaselineDiff.Diff(baseline, current);

        var delta = Assert.Single(result.CoverageDeltas);
        Assert.Equal(CoverageChangeKind.Regression, delta.Kind);
        Assert.Equal(CheckStatus.NotRun, delta.CurrentStatus);
        Assert.Equal("disabled by policy", delta.CurrentReason);
    }

    [Fact]
    public void InconclusiveToCompleted_IsImprovement()
    {
        var baseline = BaselineRun(checks: new[]
        {
            Check("chk.a", CheckStatus.Inconclusive, "timed out"),
        });
        var current = Run(checks: new[] { Check("chk.a") });

        var result = BaselineDiff.Diff(baseline, current);

        var delta = Assert.Single(result.CoverageDeltas);
        Assert.Equal(CoverageChangeKind.Improvement, delta.Kind);
        Assert.Equal(CheckStatus.Inconclusive, delta.BaselineStatus);
        Assert.Equal("timed out", delta.BaselineReason);
        Assert.Equal(CheckStatus.Completed, delta.CurrentStatus);
    }

    [Fact]
    public void NotRunToCompleted_IsImprovement()
    {
        var baseline = BaselineRun(checks: new[] { Check("chk.a", CheckStatus.NotRun) });
        var current = Run(checks: new[] { Check("chk.a") });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(CoverageChangeKind.Improvement, Assert.Single(result.CoverageDeltas).Kind);
    }

    [Fact]
    public void InconclusiveToNotRunAndBack_NotReported()
    {
        // Neither side of these transitions had visibility, so nothing about what the
        // technician can trust has changed. Judgement call documented in the handoff.
        var baseline = BaselineRun(checks: new[]
        {
            Check("chk.a", CheckStatus.Inconclusive),
            Check("chk.b", CheckStatus.NotRun),
        });
        var current = Run(checks: new[]
        {
            Check("chk.a", CheckStatus.NotRun),
            Check("chk.b", CheckStatus.Inconclusive),
        });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Empty(result.CoverageDeltas);
    }

    [Fact]
    public void CheckOnlyInCurrent_IsAdded_CheckOnlyInBaseline_IsRemoved()
    {
        var baseline = BaselineRun(checks: new[] { Check("chk.old"), Check("chk.both") });
        var current = Run(checks: new[] { Check("chk.both"), Check("chk.new") });

        var result = BaselineDiff.Diff(baseline, current);

        Assert.Equal(2, result.CoverageDeltas.Count);
        Assert.Equal(new CoverageDelta("chk.new", CoverageChangeKind.Added,
            null, null, CheckStatus.Completed, null), result.CoverageDeltas[0]);
        Assert.Equal(new CoverageDelta("chk.old", CoverageChangeKind.Removed,
            CheckStatus.Completed, null, null, null), result.CoverageDeltas[1]);
    }
}
