using System.Globalization;
using Scythe.Time.Tests.Fixtures;
using Xunit;

namespace Scythe.Time.Tests;

/// <summary>
/// Fixture class 2 — valid, but at the corners reference/11.1_time.md calls out. These are the
/// inputs where an implementation silently disagrees with the format rather than failing on it.
/// </summary>
public sealed class AwkwardButValidTests
{
    [Fact]
    public void PackedDateAndTime_AtItsMinimumIsNineteenEighty()
    {
        // The year field is an offset from 1980, so 0 is a real year and not an absence. Only the
        // whole pair being zero means "never written".
        var (date, time) = TimeFixtures.PackedDateAndTime(1980, 1, 1, 0, 0, 0);

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        Assert.Equal(TimePresence.Present, decoded.Presence);
        Assert.Equal(new DateTime(1980, 1, 1, 0, 0, 0), decoded.Value);
    }

    [Fact]
    public void PackedDateAndTime_AtItsMaximumIsTwentyOneOhSeven()
    {
        // Year field 127, month 12, day 31, hour 23, minute 59, two-second field 29.
        var (date, time) = TimeFixtures.PackedDateAndTime(2107, 12, 31, 23, 59, 58);

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        Assert.Equal(new DateTime(2107, 12, 31, 23, 59, 58), decoded.Value);
    }

    [Fact]
    public void PackedDateAndTime_CannotExpressAnOddSecondSoPrecisionStaysTwoSeconds()
    {
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 0);

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        // The value happens to land on an even second, but two-second resolution is a property of
        // the encoding rather than of this particular value, so it is attributed regardless.
        Assert.Equal(TimePrecision.TwoSeconds, decoded.Precision);
        Assert.Equal(TimeSpan.FromSeconds(2), decoded.PrecisionWidth);
    }

    [Fact]
    public void SecondCounter32_BelowTheSignBitReadsIdenticallyEitherWay()
    {
        var field = TimeFixtures.UnixSeconds32(new DateTime(2021, 6, 5, 12, 34, 56, DateTimeKind.Utc));
        Assert.True(field < 0x8000_0000, "fixture must sit below the sign bit for this test to mean anything");

        var result = TimeDecoder.DecodeSecondCounter32Ambiguous(field);

        Assert.Equal(TimeResultState.Ok, result.State);
        Assert.True(result.Value!.ReadingsAgree);
        Assert.Equal(result.Value.Signed.Value, result.Value.Unsigned.Value);
    }

    [Fact]
    public void SecondCounter32_AboveTheSignBitIsReportedAsAmbiguousRatherThanPicked()
    {
        const uint field = 0x9000_0000;

        var result = TimeDecoder.DecodeSecondCounter32Ambiguous(field);

        // Incomplete, not Ok: the reader ran, but the answer depends on a fact about the field
        // that the caller did not supply. Collapsing this to one reading would commit a report to
        // a date that is either in the 1910s or in the 2040s, with nothing downstream able to tell.
        Assert.Equal(TimeResultState.Incomplete, result.State);
        Assert.False(result.Value!.ReadingsAgree);

        Assert.Equal(1910, result.Value.Signed.Value!.Value.Year);
        Assert.Equal(2046, result.Value.Unsigned.Value!.Value.Year);

        Assert.Contains("signedness", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void SecondCounter32_StatingTheSignednessResolvesTheSameFieldToOneAnswer()
    {
        const uint field = 0x9000_0000;

        var signed = TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter32(field, CounterSignedness.Signed));
        var unsigned = TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter32(field, CounterSignedness.Unsigned));

        Assert.Equal(1910, signed.Value!.Value.Year);
        Assert.Equal(2046, unsigned.Value!.Value.Year);
    }

    [Fact]
    public void VariantDayCount_NegativeValueTreatsTheFractionAsAMagnitude()
    {
        // The correct conversion is epoch + truncate(v) days + abs(fraction(v)) x 24 h.
        const double days = -1.25;

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodeVariantDayCount(days));

        Assert.Equal(new DateTime(1899, 12, 29, 6, 0, 0), decoded.Value);
    }

    [Fact]
    public void VariantDayCount_NegativeValueDisagreesWithANaiveAddDays()
    {
        // This is the assertion that pins the corner. A plain AddDays treats the fraction as a
        // signed remainder and lands half a day out — close enough to look like a real time.
        const double days = -1.25;

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodeVariantDayCount(days));
        var naive = TimeFixtures.Epoch1899.AddDays(days);

        Assert.NotEqual(naive, decoded.Value);
        Assert.Equal(TimeSpan.FromHours(12), decoded.Value!.Value - naive);
    }

    [Fact]
    public void VariantDayCount_RoundTripsAPreEpochMomentThroughTheFixtureBuilder()
    {
        var local = new DateTime(1899, 12, 28, 18, 0, 0);

        var encoded = TimeFixtures.VariantDayCount(local);
        Assert.Equal(-2.75, encoded);

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodeVariantDayCount(encoded));
        Assert.Equal(local, decoded.Value);
    }

    [Fact]
    public void SplitCounter1601_InTheDocumentedMemberOrderDecodesToARecentMoment()
    {
        const uint low = 0xD1C4_0000;
        const uint high = 0x01D7_5A00;

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodeSplitCounter1601(low, high));

        Assert.Equal("2021-06-05T11:49:19.6502016Z", TimeFormatter.Format(decoded));
    }

    [Fact]
    public void SplitCounter1601_WithTheMembersTransposedFailsRatherThanYieldingAPlausibleDate()
    {
        const uint low = 0xD1C4_0000;
        const uint high = 0x01D7_5A00;

        // The members supplied the wrong way round. This is the single most likely integration
        // mistake for this encoding, and the only thing that makes it visible is that the
        // assembled count lands far past the representable range instead of somewhere in the
        // seventeenth century, where it would still look like a date.
        var result = TimeDecoder.DecodeSplitCounter1601(high, low);

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("exceeds the largest representable count", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void DecimalStringCounter1601_AcceptsLeadingZerosAndSurroundingWhitespace()
    {
        var count = TimeFixtures.Counter1601(TimeFixtures.Ordinary);

        // Zero-padded to the full twenty digits a 64-bit count can occupy, so the padding also
        // exercises the length guard's boundary rather than sitting comfortably inside it.
        var digits = count.ToString(CultureInfo.InvariantCulture).PadLeft(20, '0');

        var decoded = TimeFixtures.Unwrap(
            TimeDecoder.DecodeDecimalStringCounter1601("  \t" + digits + " \r\n"));

        Assert.Equal(TimeFixtures.Ordinary, decoded.Value);

        // Raw keeps the trimmed digits, so a report shows what was parsed, not the padding.
        Assert.Equal(digits, System.Text.Encoding.UTF8.GetString(decoded.Raw.Bytes));
    }

    [Fact]
    public void DecimalStringCounter1601_AtExactlyTwentyDigitsIsAcceptedThenRangeChecked()
    {
        // ulong.MaxValue is twenty digits, so the length guard must not reject it as too long; it
        // is the range check that has to catch it, and with a different message.
        var result = TimeDecoder.DecodeDecimalStringCounter1601("18446744073709551615");

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("exceeds the largest representable count", result.Reason, StringComparison.Ordinal);
    }
}
