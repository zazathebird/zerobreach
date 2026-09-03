using Scythe.Scoring.Tests.Fixtures;
using Xunit;

namespace Scythe.Scoring.Tests;

/// <summary>
/// Coverage honesty. The single most important property of this library: a run that did not
/// examine part of the host must not read as though it did.
/// </summary>
public sealed class CoverageTests
{
    /// <summary>
    /// The brief's named coverage test. Reverted form: in <c>Rollup.ComposeScore</c>, replace the
    /// scaling with <c>scaled = afterFindings</c>; the score becomes 100 and this fails.
    /// </summary>
    [Fact]
    public void AThirdInconclusiveWithNoFindingsIsNotTheCleanEndOfTheRange()
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Completed("a", "b", "c", "d")
            .Inconclusive("e", "needed elevation")
            .Inconclusive("f", "artifact locked")
            .Build());

        Assert.True(result.IsOk, result.Reason);
        var rollup = result.Value!;

        Assert.NotEqual(CleanlinessScore.Maximum, rollup.Score.Value);
        // floor(100 × 4 / 6) = 66.
        Assert.Equal(66, rollup.Score.Value);

        Assert.Equal(2, rollup.Coverage.InconclusiveCount);
        Assert.Equal(
            new[] { "artifact locked", "needed elevation" },
            rollup.Coverage.InconclusiveReasons.Select(r => r.Reason));
        Assert.Equal(new[] { "f" }, rollup.Coverage.InconclusiveReasons[0].CheckIds);
        Assert.Equal(new[] { "e" }, rollup.Coverage.InconclusiveReasons[1].CheckIds);
    }

    [Fact]
    public void ACleanRunReachesTheMaximumAndTheStatementSaysSoExplicitly()
    {
        var result = Rollup.Compute(RecordBuilder.Clean(6).Build());

        Assert.True(result.IsOk);
        Assert.Equal(CleanlinessScore.Maximum, result.Value!.Score.Value);
        Assert.Equal("6 of 6 checks completed, 0 inconclusive, 0 skipped. Every check completed.", result.Value.Coverage.Statement);
        Assert.Empty(result.Value.Coverage.InconclusiveReasons);
        Assert.Empty(result.Value.Coverage.InconclusiveWithoutReason);
    }

    /// <summary>
    /// Reverted form: count Inconclusive into <c>completed</c> in <c>BuildCoverage</c>; the three
    /// totals then no longer come out independently.
    /// </summary>
    [Fact]
    public void TheThreeTotalsAreIndependentAndSumToTheInventory()
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Completed("c1", "c2", "c3", "c4", "c5")
            .Inconclusive("i1").Inconclusive("i2").Inconclusive("i3")
            .Skipped("s1").Skipped("s2")
            .Build());

        var coverage = result.Value!.Coverage;
        Assert.Equal(10, coverage.InventorySize);
        Assert.Equal(5, coverage.CompletedCount);
        Assert.Equal(3, coverage.InconclusiveCount);
        Assert.Equal(2, coverage.SkippedCount);
        Assert.Equal(coverage.InventorySize, coverage.CompletedCount + coverage.InconclusiveCount + coverage.SkippedCount);
    }

    /// <summary>Open question 3: Skipped is reported but does not depress the score.</summary>
    [Fact]
    public void SkippedChecksAreReportedButDoNotDepressTheScore()
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Completed("a", "b")
            .Skipped("s1", "not in quick mode")
            .Skipped("s2", "not in quick mode")
            .Skipped("s3", "excluded by operator")
            .Build());

        Assert.True(result.IsOk, result.Reason);
        var rollup = result.Value!;
        Assert.Equal(CleanlinessScore.Maximum, rollup.Score.Value);
        Assert.Equal(3, rollup.Coverage.SkippedCount);
        Assert.Equal(
            new[] { ("excluded by operator", new[] { "s3" }), ("not in quick mode", new[] { "s1", "s2" }) },
            rollup.Coverage.SkippedReasons.Select(r => (r.Reason, r.CheckIds.ToArray())));
        Assert.Equal("2 of 5 checks completed, 0 inconclusive, 3 skipped. Every attempted check completed.", rollup.Coverage.Statement);
    }

    [Fact]
    public void ASingleInconclusiveCheckAmongAThousandKeepsTheScoreBelowTheMaximum()
    {
        var builder = RecordBuilder.Clean(999).Inconclusive("zz", "timed out");

        var result = Rollup.Compute(builder.Build());

        Assert.True(result.IsOk, result.Reason);
        Assert.Equal(99, result.Value!.Score.Value);
        Assert.True(result.Value.Score.Value < CleanlinessScore.Maximum);
    }

    [Fact]
    public void InconclusiveReasonsAreDistinctOrderedOrdinallyAndCarryTheirChecks()
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Inconclusive("c", "needed elevation")
            .Inconclusive("a", "needed elevation")
            .Inconclusive("b", "Artifact locked")   // capital A sorts before lowercase ordinally
            .Completed("d")
            .Build());

        var reasons = result.Value!.Coverage.InconclusiveReasons;
        Assert.Equal(new[] { "Artifact locked", "needed elevation" }, reasons.Select(r => r.Reason));
        Assert.Equal(new[] { "b" }, reasons[0].CheckIds);
        Assert.Equal(new[] { "a", "c" }, reasons[1].CheckIds);
    }

    [Fact]
    public void ReasonsDifferingOnlyInSurroundingWhitespaceAreOneReason()
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Inconclusive("a", "locked")
            .Inconclusive("b", "  locked ")
            .Inconclusive("c", "locked\t")
            .Completed("d")
            .Build());

        var reasons = result.Value!.Coverage.InconclusiveReasons;
        Assert.Single(reasons);
        Assert.Equal("locked", reasons[0].Reason);
        Assert.Equal(new[] { "a", "b", "c" }, reasons[0].CheckIds);
        Assert.Equal("locked", result.Value.CheckCounts.Single(c => c.CheckId == "b").StatusReason);
    }

    [Fact]
    public void TheStatementNamesEveryDistinctInconclusiveReason()
    {
        var statement = Rollup.Compute(RecordBuilder.Ordinary().Inconclusive("wmi", "artifact locked").Build())
            .Value!.Coverage.Statement;

        Assert.Equal(
            "3 of 6 checks completed, 2 inconclusive, 1 skipped. 2 check(s) were not examined to the end: artifact locked (wmi); needed elevation (hives).",
            statement);
    }

    /// <summary>
    /// A percentage is the one thing the statement may never contain, whatever else changes
    /// about its wording. The reflection test guards the typed surface; this guards the prose.
    /// </summary>
    [Theory]
    [InlineData(0, 0)]
    [InlineData(3, 0)]
    [InlineData(3, 2)]
    [InlineData(0, 4)]
    public void TheStatementNeverContainsAPercentSign(int completed, int inconclusive)
    {
        var builder = new RecordBuilder();
        for (int i = 0; i < completed; i++) builder.Check($"c{i}");
        for (int i = 0; i < inconclusive; i++) builder.Inconclusive($"i{i}", "reason");

        var result = Rollup.Compute(builder.Build());

        Assert.NotNull(result.Value);
        Assert.DoesNotContain("%", result.Value!.Coverage.Statement, StringComparison.Ordinal);
        Assert.DoesNotContain("percent", result.Value.Coverage.Statement, StringComparison.OrdinalIgnoreCase);
    }

    // ------------------------------------------------------------------ missing reasons

    /// <summary>
    /// Reverted form: return <c>Ok(rollup)</c> unconditionally at the end of <c>Compute</c>.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public void AnInconclusiveCheckWithNoReasonMakesTheRollupIncompleteWithAPartialValue(string? reason)
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Completed("a", "b")
            .Inconclusive("c", reason)
            .Finding("f", Severity.Low, "a")
            .Build());

        Assert.Equal(ScoringResultState.Incomplete, result.State);
        Assert.False(result.IsOk);
        Assert.NotNull(result.Value);
        Assert.Contains("1 inconclusive check(s) gave no reason (c)", result.Reason, StringComparison.Ordinal);

        // The partial value still carries every number that could be computed.
        Assert.Equal(1, result.Value!.TotalFindings);
        Assert.Equal(1, result.Value.Coverage.InconclusiveCount);
        Assert.Equal(new[] { "c" }, result.Value.Coverage.InconclusiveWithoutReason);
        Assert.Empty(result.Value.Coverage.InconclusiveReasons);
        Assert.Null(result.Value.CheckCounts.Single(c => c.CheckId == "c").StatusReason);
        // 100 − 2 = 98; two of three attempted → floor(98 × 2 / 3) = 65.
        Assert.Equal(65, result.Value.Score.Value);
        Assert.Contains("no reason given (c)", result.Value.Coverage.Statement, StringComparison.Ordinal);
    }

    [Fact]
    public void ASkippedCheckWithNoReasonMakesTheRollupIncompleteToo()
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Completed("a")
            .Skipped("s", null)
            .Build());

        Assert.Equal(ScoringResultState.Incomplete, result.State);
        Assert.NotNull(result.Value);
        Assert.Contains("1 skipped check(s) gave no reason (s)", result.Reason, StringComparison.Ordinal);
        Assert.Equal(new[] { "s" }, result.Value!.Coverage.SkippedWithoutReason);
        // Skipped still does not depress the score, reason or no reason.
        Assert.Equal(CleanlinessScore.Maximum, result.Value.Score.Value);
    }

    [Fact]
    public void MissingReasonsAreListedTogetherInTheIncompleteReason()
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Completed("a")
            .Inconclusive("i2", null).Inconclusive("i1", "")
            .Skipped("s1", " ")
            .Build());

        Assert.Equal(ScoringResultState.Incomplete, result.State);
        Assert.Contains("2 inconclusive check(s) gave no reason (i1, i2)", result.Reason, StringComparison.Ordinal);
        Assert.Contains("1 skipped check(s) gave no reason (s1)", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ACompletedCheckMayCarryAReasonWithoutConsequence()
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Check("a", CheckStatus.Completed, "finished early")
            .Build());

        Assert.True(result.IsOk, result.Reason);
        Assert.Equal("finished early", result.Value!.CheckCounts[0].StatusReason);
        Assert.Empty(result.Value.Coverage.InconclusiveReasons);
        Assert.Empty(result.Value.Coverage.SkippedReasons);
    }

    // ------------------------------------------------------------------ nothing attempted

    /// <summary>
    /// An empty record has looked at nothing. It must not score as clean, and it is not a
    /// finished answer either. Reverted form: drop the <c>attempted == 0</c> branch in
    /// <c>ComposeScore</c> and the state check in <c>Compute</c>.
    /// </summary>
    [Fact]
    public void AnEmptyRecordIsIncompleteAndScoresTheMinimum()
    {
        var result = Rollup.Compute(new RecordBuilder().Build());

        Assert.Equal(ScoringResultState.Incomplete, result.State);
        Assert.Contains("no check was attempted (0 in the inventory, 0 skipped)", result.Reason, StringComparison.Ordinal);
        Assert.NotNull(result.Value);

        var rollup = result.Value!;
        Assert.Equal(CleanlinessScore.Minimum, rollup.Score.Value);
        Assert.Equal(0, rollup.Coverage.InventorySize);
        Assert.Empty(rollup.CheckCounts);
        Assert.Equal(5, rollup.SeverityCounts.Count);
        Assert.Equal("0 of 0 checks completed, 0 inconclusive, 0 skipped. The inventory is empty: nothing was looked at.", rollup.Coverage.Statement);

        var coverage = rollup.Score.Contributions.Single(c => c.Kind == ContributionKind.Coverage);
        Assert.Equal(-100, coverage.Effect);
        Assert.Contains("no check was attempted", coverage.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ARecordWhereEveryCheckWasSkippedIsIncompleteAndScoresTheMinimum()
    {
        var result = Rollup.Compute(new RecordBuilder()
            .Skipped("a").Skipped("b").Skipped("c")
            .Build());

        Assert.Equal(ScoringResultState.Incomplete, result.State);
        Assert.Contains("no check was attempted (3 in the inventory, 3 skipped)", result.Reason, StringComparison.Ordinal);
        Assert.Equal(CleanlinessScore.Minimum, result.Value!.Score.Value);
        Assert.Equal(3, result.Value.Coverage.SkippedCount);
        Assert.Equal("0 of 3 checks completed, 0 inconclusive, 3 skipped. No check was attempted: nothing was looked at.", result.Value.Coverage.Statement);
    }

    [Fact]
    public void ARecordWhereEveryCheckWasInconclusiveIsOkButScoresTheMinimum()
    {
        // Attempted but nothing finished: a finished answer about a run that examined nothing.
        var result = Rollup.Compute(new RecordBuilder()
            .Inconclusive("a", "locked").Inconclusive("b", "locked")
            .Build());

        Assert.True(result.IsOk, result.Reason);
        Assert.Equal(CleanlinessScore.Minimum, result.Value!.Score.Value);
        Assert.Equal(-100, result.Value.Score.Contributions.Single(c => c.Kind == ContributionKind.Coverage).Effect);
    }
}
