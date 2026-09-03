using Scythe.Scoring.Tests.Fixtures;
using Xunit;

namespace Scythe.Scoring.Tests;

/// <summary>The happy path: an ordinary record, every number checked by hand.</summary>
public sealed class OrdinaryRollupTests
{
    private static RunRollup Ordinary()
    {
        var result = Rollup.Compute(RecordBuilder.Ordinary().Build());
        Assert.True(result.IsOk, result.Reason);
        return result.Value!;
    }

    [Fact]
    public void AnOrdinaryRecordIsOk()
    {
        var result = Rollup.Compute(RecordBuilder.Ordinary().Build());

        Assert.Equal(ScoringResultState.Ok, result.State);
        Assert.NotNull(result.Value);
        Assert.Null(result.Reason);
        Assert.Null(result.Position);
    }

    [Fact]
    public void SeverityCountsAreRightAndCoverEveryLevel()
    {
        var rollup = Ordinary();

        var expected = new[]
        {
            (Severity.Critical, 0),
            (Severity.High, 1),
            (Severity.Medium, 2),
            (Severity.Low, 1),
            (Severity.Informational, 1),
        };
        Assert.Equal(expected, rollup.SeverityCounts.Select(c => (c.Severity, c.Count)));
    }

    [Fact]
    public void SeverityCountsCarryTheWeightThatExplainsThem()
    {
        var rollup = Ordinary();

        Assert.Equal(40, rollup.SeverityCounts.Single(c => c.Severity == Severity.Critical).Weight);
        Assert.Equal(15, rollup.SeverityCounts.Single(c => c.Severity == Severity.High).Weight);
        Assert.Equal(1, rollup.SeverityCounts.Single(c => c.Severity == Severity.Informational).Weight);
    }

    [Fact]
    public void CheckCountsAreRightAndOrderedByIdOrdinally()
    {
        var rollup = Ordinary();

        var expected = new[]
        {
            ("autoruns", CheckStatus.Completed, 2),
            ("hives", CheckStatus.Inconclusive, 1),
            ("mft", CheckStatus.Skipped, 0),
            ("services", CheckStatus.Completed, 1),
            ("tasks", CheckStatus.Completed, 1),
        };
        Assert.Equal(expected, rollup.CheckCounts.Select(c => (c.CheckId, c.Status, c.FindingCount)));
    }

    [Fact]
    public void CheckCountsCarryTitleReasonAndHighestSeverity()
    {
        var rollup = Ordinary();

        var autoruns = rollup.CheckCounts.Single(c => c.CheckId == "autoruns");
        Assert.Equal("Title of autoruns", autoruns.Title);
        Assert.Null(autoruns.StatusReason);
        Assert.Equal(Severity.High, autoruns.HighestSeverity);

        var hives = rollup.CheckCounts.Single(c => c.CheckId == "hives");
        Assert.Equal("needed elevation", hives.StatusReason);
        Assert.Equal(Severity.Informational, hives.HighestSeverity);

        var mft = rollup.CheckCounts.Single(c => c.CheckId == "mft");
        Assert.Equal("not in quick mode", mft.StatusReason);
        Assert.Null(mft.HighestSeverity);
    }

    [Fact]
    public void TotalFindingsIsTheWholeList()
    {
        Assert.Equal(5, Ordinary().TotalFindings);
    }

    [Fact]
    public void CoverageTotalsAreSeparateAndSumToTheInventory()
    {
        var coverage = Ordinary().Coverage;

        Assert.Equal(5, coverage.InventorySize);
        Assert.Equal(3, coverage.CompletedCount);
        Assert.Equal(1, coverage.InconclusiveCount);
        Assert.Equal(1, coverage.SkippedCount);
        Assert.Equal(coverage.InventorySize, coverage.CompletedCount + coverage.InconclusiveCount + coverage.SkippedCount);
    }

    [Fact]
    public void TheScoreIsTheHandWorkedValue()
    {
        // 100 − (15 + 5 + 5 + 2 + 1) = 72; three of four attempted completed → floor(72 × 3 / 4) = 54.
        Assert.Equal(54, Ordinary().Score.Value);
    }

    [Fact]
    public void TheContributionsExplainTheScoreInOrder()
    {
        var contributions = Ordinary().Score.Contributions;

        var expected = new[]
        {
            (ContributionKind.Baseline, (Severity?)null, 0, 100L),
            (ContributionKind.Findings, Severity.High, 1, -15L),
            (ContributionKind.Findings, Severity.Medium, 2, -10L),
            (ContributionKind.Findings, Severity.Low, 1, -2L),
            (ContributionKind.Findings, Severity.Informational, 1, -1L),
            (ContributionKind.Coverage, null, 1, -18L),
        };
        Assert.Equal(expected, contributions.Select(c => (c.Kind, c.Severity, c.Count, c.Effect)));
    }

    [Fact]
    public void TheContributionsSumToTheScore()
    {
        var score = Ordinary().Score;

        Assert.Equal(score.Value, score.Contributions.Sum(c => c.Effect));
    }

    [Fact]
    public void EveryContributionHasAHumanReadableDetail()
    {
        foreach (var contribution in Ordinary().Score.Contributions)
        {
            Assert.False(string.IsNullOrWhiteSpace(contribution.Detail));
        }

        var high = Ordinary().Score.Contributions.Single(c => c.Severity == Severity.High);
        Assert.Contains("1 High finding(s) × 15 point(s)", high.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void TheScoreRecordsTheWeightsVersion()
    {
        Assert.Equal(ScoreWeights.Version, Ordinary().Score.WeightsVersion);
        Assert.False(string.IsNullOrWhiteSpace(ScoreWeights.Version));
    }

    [Fact]
    public void ARecordWithChecksButNoFindingsHasZeroEverywhereAndAFullScore()
    {
        var result = Rollup.Compute(RecordBuilder.Clean(4).Build());

        Assert.True(result.IsOk);
        var rollup = result.Value!;
        Assert.Equal(0, rollup.TotalFindings);
        Assert.All(rollup.SeverityCounts, c => Assert.Equal(0, c.Count));
        Assert.All(rollup.CheckCounts, c => Assert.Equal(0, c.FindingCount));
        Assert.All(rollup.CheckCounts, c => Assert.Null(c.HighestSeverity));
        Assert.Equal(100, rollup.Score.Value);
    }

    [Fact]
    public void ANullBudgetMeansTheDefault()
    {
        var withNull = Rollup.Compute(RecordBuilder.Ordinary().Build(), null);
        var withDefault = Rollup.Compute(RecordBuilder.Ordinary().Build(), ScanBudget.Default);

        Assert.Equal(RecordBuilder.Serialise(withDefault), RecordBuilder.Serialise(withNull));
    }

    [Fact]
    public void FindingsFromAnInconclusiveCheckAreStillCountedAndScored()
    {
        // A check can produce findings and then fail to finish; those findings are real.
        var result = Rollup.Compute(new RecordBuilder()
            .Inconclusive("hives", "locked")
            .Completed("tasks")
            .Finding("f", Severity.Critical, "hives")
            .Build());

        Assert.True(result.IsOk);
        Assert.Equal(1, result.Value!.CheckCounts.Single(c => c.CheckId == "hives").FindingCount);
        Assert.Equal(1, result.Value.SeverityCounts.Single(c => c.Severity == Severity.Critical).Count);
        // 100 − 40 = 60; one of two attempted completed → 30.
        Assert.Equal(30, result.Value.Score.Value);
    }
}
