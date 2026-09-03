using Scythe.Time.Tests.Fixtures;
using Xunit;

namespace Scythe.Time.Tests;

/// <summary>
/// Fixture class 3 — malformed input. Nothing here may throw, and nothing may come back as a
/// plausible date.
/// </summary>
public sealed class MalformedTests
{
    // ------------------------------------------------------------------ truncated spans

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    public void PackedCounter1601_ShortSpanIsIncompleteNotFailed(int length)
    {
        var result = TimeDecoder.DecodePackedCounter1601(new byte[length]);

        // Truncation is Incomplete: nothing about the field is malformed, the caller simply did
        // not supply all of it. A caller chases a coverage gap differently from a finding about
        // the artifact, so the two states must not be collapsed.
        Assert.Equal(TimeResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains("needs 8 bytes", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryFixedWidthSpanOverloadReportsTruncationRatherThanGuessing()
    {
        Assert.Equal(TimeResultState.Incomplete, TimeDecoder.DecodeSplitCounter1601(new byte[7]).State);
        Assert.Equal(TimeResultState.Incomplete, TimeDecoder.DecodeSecondCounter64(new byte[7]).State);
        Assert.Equal(TimeResultState.Incomplete, TimeDecoder.DecodeVariantDayCount(new byte[7]).State);
        Assert.Equal(TimeResultState.Incomplete, TimeDecoder.DecodePackedDateAndTime(new byte[3]).State);
        Assert.Equal(
            TimeResultState.Incomplete,
            TimeDecoder.DecodeSecondCounter32(new byte[3], CounterSignedness.Unsigned).State);
    }

    [Fact]
    public void AnEmptySpanIsNeverMistakenForTheZeroSentinel()
    {
        // A zeroed eight-byte field says "never written". No field at all says nothing, and the
        // two must not produce the same answer.
        var absent = TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(new byte[8]));
        Assert.Equal(TimePresence.Absent, absent.Presence);

        Assert.Equal(TimeResultState.Incomplete, TimeDecoder.DecodePackedCounter1601(ReadOnlySpan<byte>.Empty).State);
    }

    // ------------------------------------------------------------------ packed date and time fields

    [Fact]
    public void PackedDate_MonthZeroIsFailedWithTheFieldNamed()
    {
        var result = TimeDecoder.DecodePackedDateAndTime(
            TimeFixtures.PackDateFields(41, 0, 5), TimeFixtures.PackTime(12, 0, 0));

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("month field is 0", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PackedDate_MonthThirteenIsFailedWithTheFieldNamed()
    {
        var result = TimeDecoder.DecodePackedDateAndTime(
            TimeFixtures.PackDateFields(41, 13, 5), TimeFixtures.PackTime(12, 0, 0));

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("month field is 13", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PackedDate_DayZeroIsFailedWithTheFieldNamed()
    {
        var result = TimeDecoder.DecodePackedDateAndTime(
            TimeFixtures.PackDateFields(41, 6, 0), TimeFixtures.PackTime(12, 0, 0));

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("day field is 0", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PackedDate_DayPastTheEndOfTheMonthIsFailedWithTheMonthLengthNamed()
    {
        // The 5-bit day field tops out at 31, so "day 32" is unreachable; the overrun that does
        // occur is a day past the end of a short month, and it is just as malformed.
        var result = TimeDecoder.DecodePackedDateAndTime(
            TimeFixtures.PackDateFields(41, 4, 31), TimeFixtures.PackTime(12, 0, 0));

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("day field is 31", result.Reason, StringComparison.Ordinal);
        Assert.Contains("30 days", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PackedDate_ThirtiethOfFebruaryIsFailed()
    {
        var result = TimeDecoder.DecodePackedDateAndTime(
            TimeFixtures.PackDateFields(41, 2, 30), TimeFixtures.PackTime(12, 0, 0));

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("28 days", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PackedDate_TwentyNinthOfFebruaryIsAcceptedInALeapYear()
    {
        // The negative control for the day-of-month check: it must reject a day past the end of
        // the month without rejecting a legitimate leap day.
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(
            TimeFixtures.PackDate(2020, 2, 29), TimeFixtures.PackTime(12, 0, 0)));

        Assert.Equal(new DateTime(2020, 2, 29, 12, 0, 0), decoded.Value);
    }

    [Fact]
    public void PackedTime_HourTwentyFourIsFailedWithTheFieldNamed()
    {
        var result = TimeDecoder.DecodePackedDateAndTime(
            TimeFixtures.PackDate(2021, 6, 5), TimeFixtures.PackTimeFields(24, 0, 0));

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("hour field is 24", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PackedTime_MinuteSixtyIsFailedWithTheFieldNamed()
    {
        var result = TimeDecoder.DecodePackedDateAndTime(
            TimeFixtures.PackDate(2021, 6, 5), TimeFixtures.PackTimeFields(12, 60, 0));

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("minute field is 60", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PackedTime_TwoSecondFieldPastTwentyNineIsFailed()
    {
        // 30 and 31 are representable in the 5-bit field and would decode to 60 and 62 seconds.
        var result = TimeDecoder.DecodePackedDateAndTime(
            TimeFixtures.PackDate(2021, 6, 5), TimeFixtures.PackTimeFields(12, 0, 30));

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("two-second field is 30", result.Reason, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ variant day count

    [Fact]
    public void VariantDayCount_NaNIsFailed()
    {
        var result = TimeDecoder.DecodeVariantDayCount(double.NaN);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("NaN", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    public void VariantDayCount_InfinitiesAreFailed(double value)
    {
        var result = TimeDecoder.DecodeVariantDayCount(value);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("infinity", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1e18)]
    [InlineData(-1e18)]
    [InlineData(3_000_000.0)]
    [InlineData(-700_000.0)]
    public void VariantDayCount_MagnitudeBeyondTheRepresentableRangeIsFailed(double value)
    {
        var result = TimeDecoder.DecodeVariantDayCount(value);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("outside the representable range", result.Reason, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ range

    [Fact]
    public void PackedCounter1601_OneTickPastTheMaximumIsFailedNotAbsent()
    {
        // Q1 open question 5: out of range is a malformed field, not an unwritten one. Reporting
        // it as Absent would let a corrupted value disappear silently from a report.
        const ulong justPast = 2_650_467_744_000_000_000UL;

        var result = TimeDecoder.DecodePackedCounter1601(justPast);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("exceeds the largest representable count", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void PackedCounter1601_TheMaximumItselfIsAccepted()
    {
        // The negative control for the range check: one tick lower must still decode.
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(2_650_467_743_999_999_999UL));

        Assert.Equal(9999, decoded.Value!.Value.Year);
    }

    // ------------------------------------------------------------------ decimal string

    [Fact]
    public void DecimalStringCounter1601_FourHundredDigitsIsFailedPromptly()
    {
        var absurd = new string('9', 400);

        var result = TimeDecoder.DecodeDecimalStringCounter1601(absurd);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("400 digits", result.Reason, StringComparison.Ordinal);

        // The guard fires on the length, before any digit is examined, so the reported position
        // is the cap rather than somewhere 400 characters in.
        Assert.NotNull(result.Position);
        Assert.Equal(20L, result.Position!.Value);
    }

    [Fact]
    public void DecimalStringCounter1601_AVeryLongStringIsRefusedWithoutScanningIt()
    {
        // Ten million characters. If the length guard were removed and the digits scanned
        // instead, this test would take a visibly different amount of time to fail; the point of
        // the fixture is that the refusal cost does not track the input size.
        var enormous = new string('7', 10_000_000);

        var result = TimeDecoder.DecodeDecimalStringCounter1601(enormous);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("10000000 digits", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("+1")]
    [InlineData("1.5")]
    [InlineData("1 2")]
    [InlineData("0x10")]
    [InlineData("１２３")]
    public void DecimalStringCounter1601_NonDigitCharactersAreFailedWithThePositionNamed(string text)
    {
        var result = TimeDecoder.DecodeDecimalStringCounter1601(text);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("is not an ASCII digit", result.Reason, StringComparison.Ordinal);
        Assert.NotNull(result.Position);
    }

    [Fact]
    public void DecimalStringCounter1601_OverflowOfTheSixtyFourBitCountIsFailed()
    {
        // Twenty digits, so the length guard passes, but the value does not fit. Wrapping it
        // would produce a small count and a date early in the seventeenth century.
        var result = TimeDecoder.DecodeDecimalStringCounter1601("99999999999999999999");

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("overflows", result.Reason, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ split calendar fields

    [Theory]
    [InlineData(0, 6, 5, 12, 0, 0, 0, "year field is 0")]
    [InlineData(2021, 0, 5, 12, 0, 0, 0, "month field is 0")]
    [InlineData(2021, 13, 5, 12, 0, 0, 0, "month field is 13")]
    [InlineData(2021, 6, 0, 12, 0, 0, 0, "day field is 0")]
    [InlineData(2021, 6, 31, 12, 0, 0, 0, "30 days")]
    [InlineData(2021, 6, 5, 24, 0, 0, 0, "hour field is 24")]
    [InlineData(2021, 6, 5, 12, 60, 0, 0, "minute field is 60")]
    [InlineData(2021, 6, 5, 12, 0, 60, 0, "second field is 60")]
    [InlineData(2021, 6, 5, 12, 0, 0, 1000, "millisecond field is 1000")]
    public void SplitCalendarFields_OutOfRangeFieldsAreFailedWithTheOffenderNamed(
        int year, int month, int day, int hour, int minute, int second, int millisecond, string expected)
    {
        var result = TimeDecoder.DecodeSplitCalendarFields(
            (ushort)year, (ushort)month, (ushort)day,
            (ushort)hour, (ushort)minute, (ushort)second, (ushort)millisecond);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains(expected, result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void SplitCalendarFields_DayOfWeekPastSixIsFailed()
    {
        var result = TimeDecoder.DecodeSplitCalendarFields(2021, 6, 5, 12, 0, 0, 0, dayOfWeek: 7);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("day-of-week field is 7", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void SplitCalendarFields_ADayOfWeekDisagreeingWithTheDateIsAccepted()
    {
        // Zero is both "Sunday" and the value producers leave when they do not fill the field in,
        // so a disagreement cannot be told from an omission and must not be treated as malformed.
        // 2021-06-05 was a Saturday.
        var reading = TimeFixtures.Unwrap(
            TimeDecoder.DecodeSplitCalendarFields(2021, 6, 5, 12, 0, 0, 0, dayOfWeek: 0));

        Assert.Equal(new DateTime(2021, 6, 5, 12, 0, 0), reading.Timestamp.Value);
    }

    // ------------------------------------------------------------------ nothing throws

    [Fact]
    public void NoDecoderThrowsOnAnyOfTheMalformedFixtures()
    {
        var exception = Record.Exception(() =>
        {
            TimeDecoder.DecodePackedCounter1601(ulong.MaxValue - 1);
            TimeDecoder.DecodeSplitCounter1601(uint.MaxValue, uint.MaxValue - 1);
            TimeDecoder.DecodeDecimalStringCounter1601(new string('9', 400));
            TimeDecoder.DecodeSecondCounter64(long.MinValue);
            TimeDecoder.DecodeSecondCounter64(long.MaxValue);
            TimeDecoder.DecodeSecondCounter32(uint.MaxValue - 1, CounterSignedness.Signed);
            TimeDecoder.DecodeSecondCounter32Ambiguous(uint.MaxValue - 1);
            TimeDecoder.DecodeVariantDayCount(double.MaxValue);
            TimeDecoder.DecodeVariantDayCount(double.MinValue);
            TimeDecoder.DecodeVariantDayCount(double.Epsilon);
            TimeDecoder.DecodeSplitCalendarFields(
                ushort.MaxValue, ushort.MaxValue, ushort.MaxValue, ushort.MaxValue,
                ushort.MaxValue, ushort.MaxValue, ushort.MaxValue, ushort.MaxValue);

            for (var date = 0; date <= ushort.MaxValue; date += 97)
            {
                for (var time = 0; time <= ushort.MaxValue; time += 1013)
                {
                    TimeDecoder.DecodePackedDateAndTime((ushort)date, (ushort)time);
                }
            }
        });

        Assert.Null(exception);
    }
}
