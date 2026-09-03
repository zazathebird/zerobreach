using Scythe.Scoring.Tests.Fixtures;
using Xunit;

namespace Scythe.Scoring.Tests;

/// <summary>
/// The score: its range, its ends, its weights and the separability of its two causes.
/// </summary>
public sealed class ScoreCompositionTests
{
    private static RunRollup Value(RollupInput input)
    {
        var result = Rollup.Compute(input);
        Assert.NotNull(result.Value);
        return result.Value!;
    }

    // ------------------------------------------------------------------ the range

    [Fact]
    public void TheRangeIsZeroToOneHundredAndItsDirectionIsInTheName()
    {
        Assert.Equal(0, CleanlinessScore.Minimum);
        Assert.Equal(100, CleanlinessScore.Maximum);
        // The type is named for its direction: more cleanliness is cleaner.
        Assert.Contains("Clean", nameof(CleanlinessScore), StringComparison.Ordinal);
    }

    /// <summary>Reverted form: change the baseline contribution to 99, or floor instead of round-down-only in the scaling.</summary>
    [Fact]
    public void TheMaximumIsReachable()
    {
        Assert.Equal(CleanlinessScore.Maximum, Value(RecordBuilder.Clean(1).Build()).Score.Value);
        Assert.Equal(CleanlinessScore.Maximum, Value(RecordBuilder.Clean(1000).Build()).Score.Value);
    }

    /// <summary>Reverted form: drop the <c>Math.Min(weighted, range)</c> floor and let the value go negative.</summary>
    [Fact]
    public void TheMinimumIsReachableByFindingsAlone()
    {
        var rollup = Value(RecordBuilder.Clean(1).Findings(3, Severity.Critical, "check-00").Build());

        Assert.Equal(CleanlinessScore.Minimum, rollup.Score.Value);
        Assert.Equal(-120, rollup.Score.Contributions.Single(c => c.Kind == ContributionKind.Findings).Effect);
        Assert.Equal(20, rollup.Score.Contributions.Single(c => c.Kind == ContributionKind.FindingsSaturation).Effect);
        Assert.Equal(rollup.Score.Value, rollup.Score.Contributions.Sum(c => c.Effect));
    }

    [Fact]
    public void TheMinimumIsReachableByCoverageAlone()
    {
        var rollup = Value(new RecordBuilder().Inconclusive("a", "locked").Build());

        Assert.Equal(CleanlinessScore.Minimum, rollup.Score.Value);
        Assert.Empty(rollup.Score.Contributions.Where(c => c.Kind == ContributionKind.Findings));
    }

    [Theory]
    [InlineData(0, Severity.Informational)]
    [InlineData(1, Severity.Informational)]
    [InlineData(99, Severity.Informational)]
    [InlineData(100, Severity.Informational)]
    [InlineData(101, Severity.Informational)]
    [InlineData(7, Severity.Low)]
    [InlineData(19, Severity.Medium)]
    [InlineData(6, Severity.High)]
    [InlineData(2, Severity.Critical)]
    [InlineData(3, Severity.Critical)]
    public void TheScoreNeverLeavesTheRange(int count, Severity severity)
    {
        var rollup = Value(RecordBuilder.Clean(2).Findings(count, severity, "check-01").Build());

        Assert.InRange(rollup.Score.Value, CleanlinessScore.Minimum, CleanlinessScore.Maximum);
        Assert.Equal(rollup.Score.Value, rollup.Score.Contributions.Sum(c => c.Effect));
    }

    [Fact]
    public void ExactlyOneHundredPointsOfFindingsReachesTheFloorWithoutSaturating()
    {
        var rollup = Value(RecordBuilder.Clean(1).Findings(100, Severity.Informational, "check-00").Build());

        Assert.Equal(0, rollup.Score.Value);
        Assert.DoesNotContain(rollup.Score.Contributions, c => c.Kind == ContributionKind.FindingsSaturation);
    }

    [Fact]
    public void OnePointPastTheRangeProducesASaturationContribution()
    {
        var rollup = Value(RecordBuilder.Clean(1).Findings(101, Severity.Informational, "check-00").Build());

        var saturation = Assert.Single(rollup.Score.Contributions, c => c.Kind == ContributionKind.FindingsSaturation);
        Assert.Equal(1, saturation.Effect);
        Assert.Equal(101, saturation.Count);
        Assert.Contains("101 points, 1 beyond the range", saturation.Detail, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ weights

    /// <summary>Open question 5: strictly increasing, none zero. Reverted form: set any weight to 0 or swap two.</summary>
    [Fact]
    public void SeverityWeightsAreStrictlyIncreasingAndNoneIsZero()
    {
        var weights = Enum.GetValues<Severity>()
            .OrderBy(s => (int)s)
            .Select(s => ScoreWeights.WeightFor(s))
            .ToArray();

        Assert.Equal(5, weights.Length);
        Assert.All(weights, w => Assert.True(w is > 0));
        for (int i = 1; i < weights.Length; i++)
        {
            Assert.True(weights[i]!.Value > weights[i - 1]!.Value, $"weight {i} is not above weight {i - 1}");
        }
    }

    [Fact]
    public void TheNamedWeightConstantsAreTheOnesTheTableUses()
    {
        Assert.Equal(ScoreWeights.InformationalWeight, ScoreWeights.WeightFor(Severity.Informational));
        Assert.Equal(ScoreWeights.LowWeight, ScoreWeights.WeightFor(Severity.Low));
        Assert.Equal(ScoreWeights.MediumWeight, ScoreWeights.WeightFor(Severity.Medium));
        Assert.Equal(ScoreWeights.HighWeight, ScoreWeights.WeightFor(Severity.High));
        Assert.Equal(ScoreWeights.CriticalWeight, ScoreWeights.WeightFor(Severity.Critical));
    }

    [Fact]
    public void AnUndefinedSeverityHasNoWeight()
    {
        Assert.Null(ScoreWeights.WeightFor((Severity)5));
        Assert.Null(ScoreWeights.WeightFor((Severity)(-1)));
    }

    /// <summary>
    /// The coverage weight is in hundredths and the scaling formula assumes 1..100: above 100 the
    /// numerator can go negative, at 0 coverage stops participating, which the brief forbids.
    /// </summary>
    [Fact]
    public void TheCoverageWeightIsWithinTheRangeTheFormulaAssumes()
    {
        Assert.InRange(ScoreWeights.CoverageWeightHundredths, 1, 100);
    }

    [Fact]
    public void EveryFindingCostsSomething()
    {
        foreach (var severity in Enum.GetValues<Severity>())
        {
            var rollup = Value(RecordBuilder.Clean(1).Finding("f", severity, "check-00").Build());
            Assert.True(rollup.Score.Value < CleanlinessScore.Maximum, $"a {severity} finding cost nothing");
        }
    }

    // ------------------------------------------------------------------ separability

    /// <summary>
    /// The brief's separability test: two runs with the same low score, one from findings and one
    /// from coverage, are told apart from the contributions alone.
    /// </summary>
    [Fact]
    public void ALowScoreFromCoverageAndALowScoreFromFindingsAreDistinguishableFromTheContributions()
    {
        // Findings only: 100 − 2×15 − 4×5 = 50, everything completed.
        var byFindings = Value(RecordBuilder.Clean(2)
            .Findings(2, Severity.High, "check-00")
            .Findings(4, Severity.Medium, "check-01")
            .Build()).Score;

        // Coverage only: no findings, one of two attempted inconclusive → floor(100 × 1 / 2) = 50.
        var byCoverage = Value(new RecordBuilder()
            .Completed("a")
            .Inconclusive("b", "needed elevation")
            .Build()).Score;

        Assert.Equal(byFindings.Value, byCoverage.Value);

        Assert.Equal(-50, byFindings.Contributions.Where(c => c.Kind == ContributionKind.Findings).Sum(c => c.Effect));
        Assert.Equal(0, byFindings.Contributions.Single(c => c.Kind == ContributionKind.Coverage).Effect);

        Assert.Empty(byCoverage.Contributions.Where(c => c.Kind == ContributionKind.Findings));
        Assert.Equal(-50, byCoverage.Contributions.Single(c => c.Kind == ContributionKind.Coverage).Effect);
    }

    [Fact]
    public void TheCoverageContributionIsAlwaysPresentEvenWhenItTakesNothing()
    {
        var clean = Value(RecordBuilder.Clean(3).Build()).Score;

        var coverage = Assert.Single(clean.Contributions, c => c.Kind == ContributionKind.Coverage);
        Assert.Equal(0, coverage.Effect);
        Assert.Equal(0, coverage.Count);
        Assert.Contains("all 3 attempted check(s) completed", coverage.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void CoverageScalesWhatFindingsLeftAndReportsBothNumbers()
    {
        // 100 − 40 = 60 after findings; two of three attempted → floor(60 × 2 / 3) = 40.
        var score = Value(new RecordBuilder()
            .Completed("a", "b")
            .Inconclusive("c", "locked")
            .Finding("f", Severity.Critical, "a")
            .Build()).Score;

        Assert.Equal(40, score.Value);
        var coverage = score.Contributions.Single(c => c.Kind == ContributionKind.Coverage);
        Assert.Equal(-20, coverage.Effect);
        Assert.Equal(1, coverage.Count);
        Assert.Equal("1 of 3 attempted check(s) inconclusive; 60 scaled to 40", coverage.Detail);
    }

    [Fact]
    public void ContributionsComeInCompositionOrder()
    {
        var kinds = Value(RecordBuilder.Clean(2)
            .Inconclusive("z", "locked")
            .Findings(5, Severity.Critical, "check-00")
            .Finding("low", Severity.Low, "check-01")
            .Build()).Score.Contributions.Select(c => c.Kind).ToArray();

        Assert.Equal(
            new[] { ContributionKind.Baseline, ContributionKind.Findings, ContributionKind.Findings, ContributionKind.FindingsSaturation, ContributionKind.Coverage },
            kinds);
    }

    [Fact]
    public void FindingsContributionsAreOrderedBySeverityDescendingAndOmitEmptyLevels()
    {
        var severities = Value(RecordBuilder.Clean(1)
            .Finding("a", Severity.Low, "check-00")
            .Finding("b", Severity.Critical, "check-00")
            .Finding("c", Severity.Medium, "check-00")
            .Build()).Score.Contributions
            .Where(c => c.Kind == ContributionKind.Findings)
            .Select(c => c.Severity)
            .ToArray();

        Assert.Equal(new Severity?[] { Severity.Critical, Severity.Medium, Severity.Low }, severities);
    }

    [Fact]
    public void TheBaselineIsAlwaysFirstAndAlwaysTheMaximum()
    {
        var first = Value(RecordBuilder.Ordinary().Build()).Score.Contributions[0];

        Assert.Equal(ContributionKind.Baseline, first.Kind);
        Assert.Equal(CleanlinessScore.Maximum, first.Effect);
        Assert.Null(first.Severity);
    }

    [Fact]
    public void RoundingIsAlwaysDownwards()
    {
        // 100 × 2 / 3 = 66.67 → 66, never 67: rounding up would flatter coverage.
        Assert.Equal(66, Value(new RecordBuilder().Completed("a", "b").Inconclusive("c", "x").Build()).Score.Value);
        // 99 × 1 / 2 = 49.5 → 49.
        Assert.Equal(49, Value(new RecordBuilder().Completed("a").Inconclusive("c", "x").Finding("f", Severity.Informational, "a").Build()).Score.Value);
    }
}
