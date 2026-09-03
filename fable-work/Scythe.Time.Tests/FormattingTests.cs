using Scythe.Time.Tests.Fixtures;
using Xunit;

namespace Scythe.Time.Tests;

/// <summary>
/// The rendered text, pinned exactly, because a report's text is compared across runs.
/// </summary>
public sealed class FormattingTests
{
    [Fact]
    public void HundredNanosecondValuesCarrySevenFractionalDigitsAndAZoneMarker()
    {
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(
            TimeFixtures.Counter1601(new DateTime(2021, 6, 5, 12, 34, 56, DateTimeKind.Utc).AddTicks(1234567))));

        Assert.Equal("2021-06-05T12:34:56.1234567Z", TimeFormatter.Format(decoded));
    }

    [Fact]
    public void SecondPrecisionValuesCarryNoFractionalDigitsAtAll()
    {
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter64(
            TimeFixtures.UnixSeconds(new DateTime(2021, 6, 5, 12, 34, 56, DateTimeKind.Utc))));

        // A format string is a claim about resolution. Seven zeros here would assert 100 ns
        // precision the encoding cannot deliver.
        Assert.Equal("2021-06-05T12:34:56Z", TimeFormatter.Format(decoded));
    }

    [Fact]
    public void MillisecondPrecisionValuesCarryThreeFractionalDigits()
    {
        var reading = TimeFixtures.Unwrap(
            TimeDecoder.DecodeSplitCalendarFields(2021, 6, 5, 12, 34, 56, 789));

        Assert.Equal("2021-06-05T12:34:56.789 (zone unknown)", TimeFormatter.Format(reading.Timestamp));
    }

    [Fact]
    public void TwoSecondValuesCarryTheWidthMarkerAndTheLocalMarker()
    {
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 34, 56);
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        Assert.Equal("2021-06-05T12:34:56 ±1s (local, offset unknown)", TimeFormatter.Format(decoded));
    }

    [Fact]
    public void ARecordedOffsetIsRenderedRatherThanAppliedToTheValue()
    {
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 34, 56);
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time))
            .WithKnownOffset(TimeSpan.FromHours(-5));

        // The reading stays 12:34:56. Shifting the digits and dropping the marker would produce a
        // value that looks like UTC and is not.
        Assert.Equal("2021-06-05T12:34:56 ±1s (local, offset -05:00)", TimeFormatter.Format(decoded));
    }

    [Theory]
    [InlineData(0, "+00:00")]
    [InlineData(90, "+01:30")]
    [InlineData(-330, "-05:30")]
    [InlineData(840, "+14:00")]
    [InlineData(-720, "-12:00")]
    public void OffsetsRenderAsSignedHoursAndMinutes(int minutes, string expected)
    {
        Assert.Equal(expected, TimeFormatter.FormatOffset(TimeSpan.FromMinutes(minutes)));
    }

    [Fact]
    public void AbsentRendersWithoutASingleDigit()
    {
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(0));
        var text = TimeFormatter.Format(decoded);

        Assert.Equal("(not set)", text);
        Assert.DoesNotContain(text, char.IsDigit);
    }

    [Fact]
    public void ToStringOnTheValueMatchesTheFormatter()
    {
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(
            TimeFixtures.Counter1601(TimeFixtures.Ordinary)));

        Assert.Equal(TimeFormatter.Format(decoded), decoded.ToString());
    }

    [Fact]
    public void TheAmbiguousReadingsReasonNamesBothCandidateDates()
    {
        var result = TimeDecoder.DecodeSecondCounter32Ambiguous(0x9000_0000);

        Assert.Equal(TimeResultState.Incomplete, result.State);
        Assert.Contains("1910-", result.Reason, StringComparison.Ordinal);
        Assert.Contains("2046-", result.Reason, StringComparison.Ordinal);
    }
}
