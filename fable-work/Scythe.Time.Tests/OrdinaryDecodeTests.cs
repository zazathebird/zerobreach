using Scythe.Time.Tests.Fixtures;
using Xunit;

namespace Scythe.Time.Tests;

/// <summary>
/// Fixture class 1 — valid, ordinary input. Each encoding carries a known instant and comes back
/// as that instant, with the precision and zone certainty the encoding actually supports.
/// </summary>
public sealed class OrdinaryDecodeTests
{
    [Fact]
    public void PackedCounter1601_RoundTripsCurrentDecadeInstant()
    {
        var decoded = TimeFixtures.Unwrap(
            TimeDecoder.DecodePackedCounter1601(TimeFixtures.Counter1601(TimeFixtures.Ordinary)));

        Assert.Equal(TimePresence.Present, decoded.Presence);
        Assert.Equal(TimeFixtures.Ordinary, decoded.Value);
        Assert.Equal(DateTimeKind.Utc, decoded.Value!.Value.Kind);
        Assert.Equal(TimePrecision.HundredNanoseconds, decoded.Precision);
        Assert.Equal(ZoneCertainty.Utc, decoded.Zone);
        Assert.Equal(TimeEncoding.PackedCounter1601, decoded.Encoding);
    }

    [Fact]
    public void PackedCounter1601_OneTickPastEpochIsTheEpochPlusOneTick()
    {
        // The epoch boundary itself is the sentinel, so the first expressible moment is one tick
        // later. Getting this wrong by a whole epoch is the failure mode the encoding invites.
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(1));

        Assert.Equal(TimeFixtures.Epoch1601.AddTicks(1), decoded.Value);
    }

    [Fact]
    public void PackedCounter1601_CarriesTheRawCountAndItsBytes()
    {
        var count = TimeFixtures.Counter1601(TimeFixtures.Ordinary);
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(count));

        Assert.Equal(count.ToString(System.Globalization.CultureInfo.InvariantCulture), decoded.Raw.Scalar);
        Assert.Equal(Convert.ToHexString(TimeFixtures.Counter1601Bytes(TimeFixtures.Ordinary)), decoded.Raw.BytesHex);
    }

    [Fact]
    public void SplitCounter1601_LowMemberFirstMatchesThePackedForm()
    {
        var (low, high) = TimeFixtures.SplitCounter1601(TimeFixtures.Ordinary);

        var split = TimeFixtures.Unwrap(TimeDecoder.DecodeSplitCounter1601(low, high));
        var packed = TimeFixtures.Unwrap(
            TimeDecoder.DecodePackedCounter1601(TimeFixtures.Counter1601(TimeFixtures.Ordinary)));

        Assert.Equal(packed.Value, split.Value);
        Assert.Equal(TimePrecision.HundredNanoseconds, split.Precision);
        Assert.Equal(ZoneCertainty.Utc, split.Zone);
        Assert.Equal(TimeEncoding.SplitCounter1601, split.Encoding);
    }

    [Fact]
    public void DecimalStringCounter1601_MatchesThePackedForm()
    {
        var count = TimeFixtures.Counter1601(TimeFixtures.Ordinary);

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodeDecimalStringCounter1601(
            count.ToString(System.Globalization.CultureInfo.InvariantCulture)));

        Assert.Equal(TimeFixtures.Ordinary, decoded.Value);
        Assert.Equal(TimePrecision.HundredNanoseconds, decoded.Precision);
        Assert.Equal(TimeEncoding.DecimalStringCounter1601, decoded.Encoding);
    }

    [Fact]
    public void SecondCounter32_RoundTripsCurrentDecadeInstantAtOneSecondPrecision()
    {
        var instant = new DateTime(2021, 6, 5, 12, 34, 56, DateTimeKind.Utc);

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter32(
            TimeFixtures.UnixSeconds32(instant), CounterSignedness.Unsigned));

        Assert.Equal(instant, decoded.Value);
        Assert.Equal(DateTimeKind.Utc, decoded.Value!.Value.Kind);
        Assert.Equal(TimePrecision.OneSecond, decoded.Precision);
        Assert.Equal(ZoneCertainty.Utc, decoded.Zone);
    }

    [Fact]
    public void SecondCounter32_OneSecondPastTheEpochIsNineteenSeventy()
    {
        var decoded = TimeFixtures.Unwrap(
            TimeDecoder.DecodeSecondCounter32(1, CounterSignedness.Unsigned));

        Assert.Equal(TimeFixtures.Epoch1970.AddSeconds(1), decoded.Value);
    }

    [Fact]
    public void SecondCounter64_RoundTripsCurrentDecadeInstant()
    {
        var instant = new DateTime(2021, 6, 5, 12, 34, 56, DateTimeKind.Utc);

        var decoded = TimeFixtures.Unwrap(
            TimeDecoder.DecodeSecondCounter64(TimeFixtures.UnixSeconds(instant)));

        Assert.Equal(instant, decoded.Value);
        Assert.Equal(TimePrecision.OneSecond, decoded.Precision);
        Assert.Equal(TimeEncoding.SecondCounter64, decoded.Encoding);
    }

    [Fact]
    public void SecondCounter64_ExpressesPreEpochMomentsThatTheUnsignedFormCannot()
    {
        var instant = new DateTime(1969, 7, 20, 20, 17, 40, DateTimeKind.Utc);

        var decoded = TimeFixtures.Unwrap(
            TimeDecoder.DecodeSecondCounter64(TimeFixtures.UnixSeconds(instant)));

        Assert.Equal(instant, decoded.Value);
    }

    [Fact]
    public void PackedDateAndTime_RoundTripsAtTwoSecondPrecisionAndStaysLocal()
    {
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 34, 56);

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        Assert.Equal(new DateTime(2021, 6, 5, 12, 34, 56), decoded.Value);

        // The reading is a local wall clock whose machine's offset is nowhere in the file, so it
        // must not acquire a Kind that claims otherwise.
        Assert.Equal(DateTimeKind.Unspecified, decoded.Value!.Value.Kind);
        Assert.Equal(ZoneCertainty.LocalOffsetUnknown, decoded.Zone);
        Assert.Equal(TimePrecision.TwoSeconds, decoded.Precision);
    }

    [Fact]
    public void VariantDayCount_RoundTripsAPostEpochMoment()
    {
        var local = new DateTime(2021, 6, 5, 12, 34, 56, 500);

        var decoded = TimeFixtures.Unwrap(
            TimeDecoder.DecodeVariantDayCount(TimeFixtures.VariantDayCount(local)));

        Assert.Equal(local, decoded.Value);
        Assert.Equal(TimePrecision.Millisecond, decoded.Precision);

        // Producers disagree about whether this form is local or UTC and nothing in the value
        // records it, so the decoder must not pick one. Q1 open question 1.
        Assert.Equal(ZoneCertainty.Unknown, decoded.Zone);
    }

    [Fact]
    public void SplitCalendarFields_RoundTripsAtMillisecondPrecision()
    {
        var reading = TimeFixtures.Unwrap(
            TimeDecoder.DecodeSplitCalendarFields(2021, 6, 5, 12, 34, 56, 789, dayOfWeek: 6));

        Assert.Equal(new DateTime(2021, 6, 5, 12, 34, 56, 789), reading.Timestamp.Value);
        Assert.Equal(TimePrecision.Millisecond, reading.Timestamp.Precision);
        Assert.Equal(ZoneCertainty.Unknown, reading.Timestamp.Zone);
        Assert.False(reading.MillisecondsFieldWasZero);
    }

    [Fact]
    public void SplitCalendarFields_ReportsAZeroMillisecondsFieldWithoutCoarseningPrecision()
    {
        var reading = TimeFixtures.Unwrap(
            TimeDecoder.DecodeSplitCalendarFields(2021, 6, 5, 12, 34, 56, 0));

        Assert.True(reading.MillisecondsFieldWasZero);

        // Q1 open question 3: many producers always write zero here, so a zero is not evidence of
        // coarser resolution. Inferring one would discard the difference between ".000" written
        // and ".000" left.
        Assert.Equal(TimePrecision.Millisecond, reading.Timestamp.Precision);
    }

    [Fact]
    public void SpanOverloadsAgreeWithTheScalarOverloads()
    {
        var expected = TimeFixtures.Unwrap(
            TimeDecoder.DecodePackedCounter1601(TimeFixtures.Counter1601(TimeFixtures.Ordinary)));

        var fromSpan = TimeFixtures.Unwrap(
            TimeDecoder.DecodePackedCounter1601(TimeFixtures.Counter1601Bytes(TimeFixtures.Ordinary)));

        Assert.Equal(expected.Value, fromSpan.Value);
        Assert.Equal(expected.Raw.BytesHex, fromSpan.Raw.BytesHex);
    }
}
