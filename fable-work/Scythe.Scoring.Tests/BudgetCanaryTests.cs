using Scythe.Scoring.Tests.Fixtures;
using Xunit;

namespace Scythe.Scoring.Tests;

/// <summary>
/// Canaries for the one budget member that binds, and the extreme-count arithmetic.
/// </summary>
/// <remarks>
/// Only <see cref="ScanBudget.MaxMatches"/> constrains anything here: the rollup takes structured
/// entries rather than bytes, does not recurse, and is a pure function with nothing to time. The
/// canary exists so that if the guard is refactored into a no-op the suite says so.
/// </remarks>
public sealed class BudgetCanaryTests
{
    [Fact]
    public void DefaultBudgetHasTheValuesTheSharedContractStates()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), ScanBudget.Default.Deadline);
        Assert.Equal(64L * 1024 * 1024, ScanBudget.Default.MaxInputBytes);
        Assert.Equal(10_000, ScanBudget.Default.MaxMatches);
        Assert.Equal(16, ScanBudget.Default.MaxNestingDepth);
    }

    /// <summary>Reverted form: delete the <c>entries &gt; budget.MaxMatches</c> check in <c>Compute</c>.</summary>
    [Fact]
    public void ARecordPastTheMatchBudgetIsIncompleteWithNoValueAndTheBudgetNamed()
    {
        var input = RecordBuilder.Clean(2).Findings(9, Severity.Low, "check-00").Build(); // 11 entries

        var result = Rollup.Compute(input, ScanBudget.Default with { MaxMatches = 10 });

        Assert.Equal(ScoringResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Equal(
            "record holds 2 checks and 9 findings (11 entries); budget MaxMatches allows 10. No rollup is produced over a subset because a partial count reads as a whole one.",
            result.Reason);
    }

    [Fact]
    public void ARecordExactlyAtTheMatchBudgetIsStillOk()
    {
        var input = RecordBuilder.Clean(2).Findings(8, Severity.Low, "check-00").Build(); // 10 entries

        var result = Rollup.Compute(input, ScanBudget.Default with { MaxMatches = 10 });

        Assert.True(result.IsOk, result.Reason);
        Assert.Equal(8, result.Value!.TotalFindings);
    }

    [Fact]
    public void ChecksCountAgainstTheBudgetAsWellAsFindings()
    {
        var result = Rollup.Compute(RecordBuilder.Clean(11).Build(), ScanBudget.Default with { MaxMatches = 10 });

        Assert.Equal(ScoringResultState.Incomplete, result.State);
        Assert.Null(result.Value);
    }

    [Fact]
    public void TheDefaultBudgetRefusesTenThousandAndOneEntries()
    {
        var input = RecordBuilder.Clean(1).Findings(10_000, Severity.Informational, "check-00").Build();

        var result = Rollup.Compute(input);

        Assert.Equal(ScoringResultState.Incomplete, result.State);
        Assert.Contains("budget MaxMatches allows 10000", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ABudgetOfZeroRefusesEverythingButAnEmptyRecord()
    {
        var zero = ScanBudget.Default with { MaxMatches = 0 };

        Assert.Equal(ScoringResultState.Incomplete, Rollup.Compute(RecordBuilder.Clean(1).Build(), zero).State);
        Assert.Null(Rollup.Compute(RecordBuilder.Clean(1).Build(), zero).Value);
        // An empty record is within a zero budget; it is Incomplete for the other reason, with a value.
        var empty = Rollup.Compute(new RecordBuilder().Build(), zero);
        Assert.Equal(ScoringResultState.Incomplete, empty.State);
        Assert.NotNull(empty.Value);
    }

    // ------------------------------------------------------------------ extreme counts

    /// <summary>
    /// The brief's tens-of-thousands case. Counts are exact and the weighted sum is carried in a
    /// <see cref="long"/>, so the saturation contribution states the full overshoot.
    /// </summary>
    [Fact]
    public void FiftyThousandFindingsAreCountedExactlyAndDoNotOverflow()
    {
        var big = ScanBudget.Default with { MaxMatches = 200_000 };
        var input = RecordBuilder.Clean(3)
            .Findings(20_000, Severity.Critical, "check-00", "c")
            .Findings(20_000, Severity.Informational, "check-01", "i")
            .Findings(10_000, Severity.High, "check-02", "h")
            .Build();

        var result = Rollup.Compute(input, big);

        Assert.True(result.IsOk, result.Reason);
        var rollup = result.Value!;
        Assert.Equal(50_000, rollup.TotalFindings);
        Assert.Equal(20_000, rollup.SeverityCounts.Single(c => c.Severity == Severity.Critical).Count);
        Assert.Equal(10_000, rollup.SeverityCounts.Single(c => c.Severity == Severity.High).Count);
        Assert.Equal(20_000, rollup.SeverityCounts.Single(c => c.Severity == Severity.Informational).Count);
        Assert.Equal(20_000, rollup.CheckCounts.Single(c => c.CheckId == "check-00").FindingCount);

        Assert.Equal(CleanlinessScore.Minimum, rollup.Score.Value);
        // 20 000 × 40 + 10 000 × 15 + 20 000 × 1 = 970 000 weighted points; 969 900 beyond the range.
        Assert.Equal(-800_000, rollup.Score.Contributions.Single(c => c.Severity == Severity.Critical).Effect);
        Assert.Equal(969_900, rollup.Score.Contributions.Single(c => c.Kind == ContributionKind.FindingsSaturation).Effect);
        Assert.Equal(rollup.Score.Value, rollup.Score.Contributions.Sum(c => c.Effect));
    }

    [Fact]
    public void AHugeInventoryWithOneInconclusiveCheckIsScaledExactly()
    {
        var big = ScanBudget.Default with { MaxMatches = 200_000 };
        var input = RecordBuilder.Clean(99_999).Inconclusive("zzz", "timed out").Build();

        var result = Rollup.Compute(input, big);

        Assert.True(result.IsOk, result.Reason);
        // floor(100 × 99 999 / 100 000) = 99: still not the maximum.
        Assert.Equal(99, result.Value!.Score.Value);
        Assert.Equal(100_000, result.Value.CheckCounts.Count);
        Assert.Equal(100_000, result.Value.Coverage.InventorySize);
    }
}
