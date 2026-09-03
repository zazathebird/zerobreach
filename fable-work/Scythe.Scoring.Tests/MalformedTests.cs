using Scythe.Scoring.Tests.Fixtures;
using Xunit;

namespace Scythe.Scoring.Tests;

/// <summary>
/// Records a host would never construct on purpose. Every one is <c>Failed</c> with a message that
/// names the offender and a position in the list the message names; none throws.
/// </summary>
public sealed class MalformedTests
{
    private static ScoringResult<RunRollup> Failing(RollupInput input)
    {
        var result = Rollup.Compute(input);
        Assert.Equal(ScoringResultState.Failed, result.State);
        Assert.Null(result.Value);
        Assert.False(result.IsOk);
        Assert.NotNull(result.Reason);
        return result;
    }

    [Fact]
    public void ANullInputIsFailedNotAThrow()
    {
        var result = Failing(null!);

        Assert.Equal("record: input is null", result.Reason);
        Assert.Null(result.Position);
    }

    [Fact]
    public void ANullCheckListIsFailed()
    {
        var result = Failing(new RollupInput(null!, Array.Empty<FindingInput>()));

        Assert.Contains("check inventory is null", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ANullFindingListIsFailed()
    {
        var result = Failing(new RollupInput(Array.Empty<CheckInput>(), null!));

        Assert.Contains("finding list is null", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ANullCheckEntryIsFailedAtItsIndex()
    {
        var result = Failing(new RecordBuilder().Completed("a").RawCheck(null).Build());

        Assert.Equal("check 1: entry is null", result.Reason);
        Assert.Equal(1, result.Position);
    }

    [Fact]
    public void ANullFindingEntryIsFailedAtItsIndex()
    {
        var result = Failing(new RecordBuilder().Completed("a").Finding("f", Severity.Low, "a").RawFinding(null).Build());

        Assert.Equal("finding 1: entry is null", result.Reason);
        Assert.Equal(1, result.Position);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void ABlankCheckIdIsFailed(string? id)
    {
        var result = Failing(new RecordBuilder().Completed("ok").RawCheck(new CheckInput(id!, "t", CheckStatus.Completed, null)).Build());

        Assert.Equal("check 1: id is null or blank", result.Reason);
        Assert.Equal(1, result.Position);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("\t")]
    public void ABlankFindingIdIsFailed(string? id)
    {
        var result = Failing(new RecordBuilder().Completed("a").RawFinding(new FindingInput(id!, Severity.Low, "a")).Build());

        Assert.Equal("finding 0: id is null or blank", result.Reason);
        Assert.Equal(0, result.Position);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ABlankProducingCheckIdIsFailed(string? checkId)
    {
        var result = Failing(new RecordBuilder().Completed("a").RawFinding(new FindingInput("f", Severity.Low, checkId!)).Build());

        Assert.Equal("finding 0 'f': producing check id is null or blank", result.Reason);
    }

    /// <summary>
    /// The brief's orphan case. Silently counting it would hide a record-construction bug behind a
    /// plausible number. Reverted form: drop the <c>ContainsKey</c> check and count under the
    /// unknown id.
    /// </summary>
    [Fact]
    public void AFindingWhoseCheckIsNotInTheInventoryIsFailedNamingTheOrphan()
    {
        var result = Failing(RecordBuilder.Ordinary().Finding("stray", Severity.Critical, "ghost").Build());

        Assert.Equal("finding 5 'stray': producing check 'ghost' is not in the inventory", result.Reason);
        Assert.Equal(5, result.Position);
    }

    [Fact]
    public void AnOrphanIsFailedEvenWhenTheInventoryIsEmpty()
    {
        var result = Failing(new RecordBuilder().Finding("f", Severity.Low, "a").Build());

        Assert.Contains("'a' is not in the inventory", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void CheckIdsAreMatchedExactlyNotCaseInsensitively()
    {
        var result = Failing(new RecordBuilder().Completed("Autoruns").Finding("f", Severity.Low, "autoruns").Build());

        Assert.Contains("'autoruns' is not in the inventory", result.Reason, StringComparison.Ordinal);
    }

    /// <summary>Reverted form: skip the duplicate check and let the second occurrence overwrite the first.</summary>
    [Fact]
    public void ADuplicateFindingIdIsFailedNamingBothPositions()
    {
        var result = Failing(new RecordBuilder()
            .Completed("a")
            .Finding("dup", Severity.Low, "a")
            .Finding("other", Severity.Low, "a")
            .Finding("dup", Severity.High, "a")
            .Build());

        Assert.Equal("finding 2 'dup': id appears twice (first at finding 0)", result.Reason);
        Assert.Equal(2, result.Position);
    }

    /// <summary>Reverted form: use <c>checksById[check.Id] = ...</c> instead of <c>Add</c> after the check.</summary>
    [Fact]
    public void ACheckAppearingTwiceInTheInventoryIsFailedNamingBothPositions()
    {
        var result = Failing(new RecordBuilder()
            .Completed("a", "b")
            .Inconclusive("a", "locked")
            .Build());

        Assert.Equal("check 2 'a': appears twice in the inventory (first at check 0)", result.Reason);
        Assert.Equal(2, result.Position);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void AnUndefinedSeverityIsFailed(int raw)
    {
        var result = Failing(new RecordBuilder().Completed("a").RawFinding(new FindingInput("f", (Severity)raw, "a")).Build());

        Assert.Equal($"finding 0 'f': severity {raw} is not one of the five levels", result.Reason);
        Assert.Equal(0, result.Position);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void AnUndefinedCheckStatusIsFailed(int raw)
    {
        var result = Failing(new RecordBuilder().RawCheck(new CheckInput("a", "t", (CheckStatus)raw, null)).Build());

        Assert.Equal($"check 0 'a': status {raw} is not Completed, Inconclusive or Skipped", result.Reason);
    }

    [Fact]
    public void TheFirstDefectWinsSoTheMessageIsAboutOneThing()
    {
        // A duplicate check at 1 and an orphan finding at 0: the inventory is walked first.
        var result = Failing(new RecordBuilder()
            .Completed("a", "a")
            .Finding("f", Severity.Low, "ghost")
            .Build());

        Assert.StartsWith("check 1 'a'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void FindingIdsAndCheckIdsAreSeparateNamespaces()
    {
        // A finding may share an id string with a check; only duplicates within a list are defects.
        var result = Rollup.Compute(new RecordBuilder().Completed("same").Finding("same", Severity.Low, "same").Build());

        Assert.True(result.IsOk, result.Reason);
    }

    [Fact]
    public void NothingThrowsAcrossASweepOfBrokenRecords()
    {
        var broken = new RollupInput?[]
        {
            null,
            new(null!, null!),
            new(new CheckInput[] { null! }, Array.Empty<FindingInput>()),
            new(Array.Empty<CheckInput>(), new FindingInput[] { null! }),
            new(new[] { new CheckInput(null!, null!, (CheckStatus)99, null) }, Array.Empty<FindingInput>()),
            new(new[] { new CheckInput("a", null!, CheckStatus.Inconclusive, null) }, new[] { new FindingInput(null!, (Severity)99, null!) }),
            new(new[] { new CheckInput("a", "t", CheckStatus.Completed, null), new CheckInput("a", "t", CheckStatus.Completed, null) }, Array.Empty<FindingInput>()),
            new(new[] { new CheckInput("a", "t", CheckStatus.Completed, null) }, new[] { new FindingInput("f", Severity.Low, "b"), new FindingInput("f", Severity.Low, "a") }),
            new(new[] { new CheckInput(" ", "t", CheckStatus.Completed, null) }, Array.Empty<FindingInput>()),
        };

        foreach (var input in broken)
        {
            var result = Rollup.Compute(input!);
            Assert.NotEqual(ScoringResultState.Ok, result.State);
            Assert.NotNull(result.Reason);
        }
    }
}
