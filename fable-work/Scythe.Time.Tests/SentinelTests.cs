using Scythe.Time.Tests.Fixtures;
using Xunit;

namespace Scythe.Time.Tests;

/// <summary>
/// One test per encoding's "never set" pattern.
/// </summary>
/// <remarks>
/// Each asserts two things: that the result is Absent, and that the formatted output contains no
/// year. The second is the one that matters in a client-facing report — an unwritten 1601-epoch
/// field rendered naively reads "1601-01-01", which is indistinguishable from a fact about the
/// machine and never throws, never fails a test that was not written for it, and reads as a
/// strange-but-real finding to whoever receives it.
/// </remarks>
public sealed class SentinelTests
{
    private static void AssertAbsentAndYearless(NormalisedTimestamp decoded, SentinelKind expected)
    {
        Assert.Equal(TimePresence.Absent, decoded.Presence);
        Assert.Equal(expected, decoded.Sentinel);
        Assert.Null(decoded.Value);

        var text = TimeFormatter.Format(decoded);

        Assert.Equal(TimeFormatter.AbsentRendering, text);
        Assert.DoesNotContain("1601", text, StringComparison.Ordinal);
        Assert.DoesNotContain("1970", text, StringComparison.Ordinal);
        Assert.DoesNotContain("1899", text, StringComparison.Ordinal);
        Assert.DoesNotContain("1980", text, StringComparison.Ordinal);

        // Stronger than checking for the four epoch years: no digit at all can appear, so the
        // rendering cannot be mistaken for a date whatever the encoding.
        Assert.DoesNotContain(text, c => char.IsDigit(c));
    }

    [Fact]
    public void PackedCounter1601_ZeroIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(0)),
            SentinelKind.Zero);

    [Fact]
    public void PackedCounter1601_AllBitsSetIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(ulong.MaxValue)),
            SentinelKind.AllBitsSet);

    [Fact]
    public void SplitCounter1601_BothMembersZeroIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeSplitCounter1601(0, 0)),
            SentinelKind.Zero);

    [Fact]
    public void SplitCounter1601_BothMembersAllBitsSetIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeSplitCounter1601(uint.MaxValue, uint.MaxValue)),
            SentinelKind.AllBitsSet);

    [Fact]
    public void SplitCounter1601_OnlyTheWholeGroupIsASentinel()
    {
        // A low member of 0xFFFFFFFF beside a high member of 0 is an ordinary count of about
        // seven minutes past the epoch, not an absence. Testing the assembled value instead of
        // the members would swallow it.
        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodeSplitCounter1601(uint.MaxValue, 0));

        Assert.Equal(TimePresence.Present, decoded.Presence);
        Assert.Equal(TimeFixtures.Epoch1601.AddTicks(uint.MaxValue), decoded.Value);
    }

    [Fact]
    public void DecimalStringCounter1601_ZeroTextIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeDecimalStringCounter1601("0")),
            SentinelKind.Zero);

    [Fact]
    public void DecimalStringCounter1601_PaddedZeroTextIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeDecimalStringCounter1601(" 0000 ")),
            SentinelKind.Zero);

    [Fact]
    public void DecimalStringCounter1601_EmptyIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeDecimalStringCounter1601("")),
            SentinelKind.Empty);

    [Fact]
    public void DecimalStringCounter1601_WhitespaceOnlyIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeDecimalStringCounter1601("  \t \r\n ")),
            SentinelKind.Whitespace);

    [Fact]
    public void SecondCounter32_ZeroIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter32(0, CounterSignedness.Unsigned)),
            SentinelKind.Zero);

    [Fact]
    public void SecondCounter32_AllBitsSetIsAbsentUnderBothSignednesses()
    {
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter32(uint.MaxValue, CounterSignedness.Unsigned)),
            SentinelKind.AllBitsSet);

        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter32(uint.MaxValue, CounterSignedness.Signed)),
            SentinelKind.AllBitsSet);
    }

    [Fact]
    public void SecondCounter64_ZeroIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter64(0)),
            SentinelKind.Zero);

    [Fact]
    public void SecondCounter64_MinusOneIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter64(-1)),
            SentinelKind.AllBitsSet);

    [Fact]
    public void PackedDateAndTime_BothWordsZeroIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(0, 0)),
            SentinelKind.Zero);

    [Fact]
    public void PackedDateAndTime_AZeroDateBesideANonZeroTimeIsMalformedNotAbsent()
    {
        // Only the whole pair means "never written". A zero date word on its own carries month 0
        // and day 0, which is a malformed field, and calling it an absence would let corruption
        // vanish from a report.
        var result = TimeDecoder.DecodePackedDateAndTime(0, TimeFixtures.PackTime(12, 0, 0));

        Assert.Equal(TimeResultState.Failed, result.State);
        Assert.Contains("month field is 0", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void VariantDayCount_ExactlyZeroIsAbsent() =>
        AssertAbsentAndYearless(
            TimeFixtures.Unwrap(TimeDecoder.DecodeVariantDayCount(0.0)),
            SentinelKind.Zero);

    [Fact]
    public void SplitCalendarFields_AllEightFieldsZeroIsAbsent()
    {
        var reading = TimeFixtures.Unwrap(
            TimeDecoder.DecodeSplitCalendarFields(0, 0, 0, 0, 0, 0, 0, 0));

        AssertAbsentAndYearless(reading.Timestamp, SentinelKind.Zero);
    }

    // ------------------------------------------------------------------ negative control

    [Fact]
    public void WithoutSentinelHandlingTheEpochWouldAppearAsAData()
    {
        // The guard cannot be reverted from inside a test, so this pins what reverting it would
        // produce: the naive conversion of each "never set" pattern renders as its epoch year,
        // and every one of those is a date a reader would act on.
        Assert.Equal("1601-01-01", TimeFixtures.Epoch1601.AddTicks(0).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal("1970-01-01", TimeFixtures.Epoch1970.AddSeconds(0).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal("1899-12-30", TimeFixtures.Epoch1899.AddDays(0.0).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));

        // And this is what the library returns for the same three inputs instead.
        foreach (var decoded in new[]
                 {
                     TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(0)),
                     TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter64(0)),
                     TimeFixtures.Unwrap(TimeDecoder.DecodeVariantDayCount(0.0)),
                 })
        {
            Assert.Equal("(not set)", TimeFormatter.Format(decoded));
        }
    }
}
