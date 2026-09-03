using Scythe.Scoring.Tests.Fixtures;
using Xunit;

namespace Scythe.Scoring.Tests;

/// <summary>Stated ordering keys, and zero-count entries that say "the question was asked".</summary>
public sealed class OrderingAndZeroCountTests
{
    /// <summary>Reverted form: emit only severities with a non-zero count.</summary>
    [Fact]
    public void EverySeverityLevelAppearsEvenWithNoFindings()
    {
        var rollup = Rollup.Compute(RecordBuilder.Clean(2).Finding("f", Severity.Low, "check-00").Build()).Value!;

        Assert.Equal(Enum.GetValues<Severity>().Length, rollup.SeverityCounts.Count);
        Assert.Equal(0, rollup.SeverityCounts.Single(c => c.Severity == Severity.Critical).Count);
        Assert.Equal(0, rollup.SeverityCounts.Single(c => c.Severity == Severity.High).Count);
        Assert.Equal(0, rollup.SeverityCounts.Single(c => c.Severity == Severity.Medium).Count);
        Assert.Equal(1, rollup.SeverityCounts.Single(c => c.Severity == Severity.Low).Count);
        Assert.Equal(0, rollup.SeverityCounts.Single(c => c.Severity == Severity.Informational).Count);
    }

    /// <summary>Stated key: severity descending, so "0 Critical" is the first line a reader sees.</summary>
    [Fact]
    public void SeverityCountsAreOrderedHighestFirst()
    {
        var order = Rollup.Compute(RecordBuilder.Ordinary().Build()).Value!.SeverityCounts.Select(c => c.Severity).ToArray();

        Assert.Equal(new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Informational }, order);
    }

    /// <summary>Reverted form: build <c>CheckCounts</c> from the findings' check ids rather than the inventory.</summary>
    [Fact]
    public void EveryInventoryCheckAppearsEvenWithNoFindings()
    {
        var rollup = Rollup.Compute(new RecordBuilder()
            .Completed("with", "without-1", "without-2")
            .Skipped("skipped")
            .Finding("f", Severity.Medium, "with")
            .Build()).Value!;

        Assert.Equal(4, rollup.CheckCounts.Count);
        Assert.Equal(0, rollup.CheckCounts.Single(c => c.CheckId == "without-1").FindingCount);
        Assert.Equal(0, rollup.CheckCounts.Single(c => c.CheckId == "without-2").FindingCount);
        Assert.Equal(0, rollup.CheckCounts.Single(c => c.CheckId == "skipped").FindingCount);
    }

    /// <summary>
    /// Stated key: check id, ordinal. Ordinal puts every uppercase letter before every lowercase
    /// one and "check10" before "check2"; a culture-aware or numeric-aware sort would not, and a
    /// sort that varies with the host is not a sort. Reverted form: <c>StringComparer.OrdinalIgnoreCase</c>.
    /// </summary>
    [Fact]
    public void CheckCountsAreOrderedByIdOrdinally()
    {
        var order = Rollup.Compute(new RecordBuilder()
            .Completed("check2", "check10", "b", "B", "a", "Z", "_under", "1numeric")
            .Build()).Value!.CheckCounts.Select(c => c.CheckId).ToArray();

        Assert.Equal(new[] { "1numeric", "B", "Z", "_under", "a", "b", "check10", "check2" }, order);
    }

    [Fact]
    public void CheckCountOrderDoesNotDependOnInventoryOrder()
    {
        var forward = Rollup.Compute(new RecordBuilder().Completed("a", "b", "c").Build()).Value!;
        var backward = Rollup.Compute(new RecordBuilder().Completed("c", "b", "a").Build()).Value!;

        Assert.Equal(forward.CheckCounts.Select(c => c.CheckId), backward.CheckCounts.Select(c => c.CheckId));
    }

    [Fact]
    public void ReasonsAreOrderedByTextOrdinally()
    {
        var reasons = Rollup.Compute(new RecordBuilder()
            .Inconclusive("a", "zeta")
            .Inconclusive("b", "Alpha")
            .Inconclusive("c", "beta")
            .Inconclusive("d", "alpha")
            .Completed("e")
            .Build()).Value!.Coverage.InconclusiveReasons.Select(r => r.Reason).ToArray();

        Assert.Equal(new[] { "Alpha", "alpha", "beta", "zeta" }, reasons);
    }

    [Fact]
    public void CheckIdsWithinAReasonAreOrderedOrdinally()
    {
        var ids = Rollup.Compute(new RecordBuilder()
            .Inconclusive("c", "locked")
            .Inconclusive("A", "locked")
            .Inconclusive("b", "locked")
            .Completed("z")
            .Build()).Value!.Coverage.InconclusiveReasons.Single().CheckIds;

        Assert.Equal(new[] { "A", "b", "c" }, ids);
    }

    [Fact]
    public void HighestSeverityIsTheHighestNotTheFirstOrTheLast()
    {
        var rollup = Rollup.Compute(RecordBuilder.Clean(1)
            .Finding("a", Severity.Low, "check-00")
            .Finding("b", Severity.Critical, "check-00")
            .Finding("c", Severity.Medium, "check-00")
            .Build()).Value!;

        Assert.Equal(Severity.Critical, rollup.CheckCounts[0].HighestSeverity);
    }

    [Fact]
    public void ANullTitleIsCarriedAsEmptyNotNull()
    {
        var result = Rollup.Compute(new RecordBuilder().RawCheck(new CheckInput("a", null!, CheckStatus.Completed, null)).Build());

        Assert.True(result.IsOk, result.Reason);
        Assert.Equal(string.Empty, result.Value!.CheckCounts[0].Title);
    }
}
