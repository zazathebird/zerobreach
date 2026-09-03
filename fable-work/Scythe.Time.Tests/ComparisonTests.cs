using Scythe.Time.Tests.Fixtures;
using Xunit;

namespace Scythe.Time.Tests;

/// <summary>
/// The four-outcome comparison, including the outcome an implementer is most tempted to drop.
/// </summary>
public sealed class ComparisonTests
{
    private static readonly DateTime Base = new(2021, 6, 5, 12, 0, 0, DateTimeKind.Utc);

    private static NormalisedTimestamp Utc100Ns(TimeSpan offsetFromBase) =>
        TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(
            TimeFixtures.Counter1601(Base + offsetFromBase)));

    private static NormalisedTimestamp UtcOneSecond(TimeSpan offsetFromBase) =>
        TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter64(
            TimeFixtures.UnixSeconds(Base + offsetFromBase)));

    /// <summary>
    /// A two-second-precision value anchored by an explicitly supplied offset, so it can be
    /// compared against a UTC one at all. The packed pair is the only two-second encoding and it
    /// is local by nature.
    /// </summary>
    private static NormalisedTimestamp TwoSecondAnchored(int hour, int minute, int second)
    {
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, hour, minute, second);
        return TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time))
            .WithKnownOffset(TimeSpan.Zero);
    }

    [Fact]
    public void TwoHundredNanosecondValuesFiveHundredNanosecondsApartAreOrdered()
    {
        var early = Utc100Ns(TimeSpan.Zero);
        var late = Utc100Ns(TimeSpan.FromTicks(5)); // 5 ticks = 500 ns

        Assert.Equal(TimeComparison.Before, TimeComparer.Compare(early, late));
        Assert.Equal(TimeComparison.After, TimeComparer.Compare(late, early));
    }

    [Fact]
    public void CoarseningOneSideToTwoSecondsMakesThePairNotDistinguishable()
    {
        var precise = Utc100Ns(TimeSpan.FromTicks(5));
        var coarse = TwoSecondAnchored(12, 0, 0);

        // Not "equal": the moments may well differ. The statement is about what the encodings can
        // resolve, and a two-second window swallows a 500 ns separation.
        Assert.Equal(TimeComparison.NotDistinguishable, TimeComparer.Compare(precise, coarse));
        Assert.Equal(TimeComparison.NotDistinguishable, TimeComparer.Compare(coarse, precise));
    }

    [Fact]
    public void TwoSecondCounterValuesOneSecondApartRemainOrdered()
    {
        // The negative control for the widening: a window that merely touches its neighbour must
        // not swallow it, or every second-resolution comparison in the package collapses.
        var early = UtcOneSecond(TimeSpan.Zero);
        var late = UtcOneSecond(TimeSpan.FromSeconds(1));

        Assert.Equal(TimeComparison.Before, TimeComparer.Compare(early, late));
    }

    [Fact]
    public void IdenticalValuesAreNotDistinguishableRatherThanEqual()
    {
        Assert.Equal(TimeComparison.NotDistinguishable, TimeComparer.Compare(Utc100Ns(TimeSpan.Zero), Utc100Ns(TimeSpan.Zero)));
    }

    [Fact]
    public void AUtcValueAndAZoneUnknownValueAreNotComparableHoweverFarApartTheyLook()
    {
        var utc = Utc100Ns(TimeSpan.Zero);

        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 0);
        var local = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        Assert.Equal(TimeComparison.NotComparable, TimeComparer.Compare(utc, local));
        Assert.Equal(TimeComparison.NotComparable, TimeComparer.Compare(local, utc));
    }

    [Fact]
    public void AYearApartAcrossAnUnknownZoneIsStillNotComparable()
    {
        // The temptation is to order these anyway, because a year plainly exceeds any offset. The
        // outcome is a property of what is known about the values, not of how far apart they
        // happen to be, and a rule that switched on the gap would be a rule nobody could state.
        var utc = Utc100Ns(TimeSpan.Zero);

        var (date, time) = TimeFixtures.PackedDateAndTime(2015, 1, 1, 0, 0, 0);
        var local = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        Assert.Equal(TimeComparison.NotComparable, TimeComparer.Compare(utc, local));
    }

    [Fact]
    public void AZoneUnknownVariantValueIsNotComparableWithAUtcValue()
    {
        var utc = Utc100Ns(TimeSpan.Zero);
        var variant = TimeFixtures.Unwrap(
            TimeDecoder.DecodeVariantDayCount(TimeFixtures.VariantDayCount(new DateTime(2021, 6, 5, 12, 0, 0))));

        Assert.Equal(ZoneCertainty.Unknown, variant.Zone);
        Assert.Equal(TimeComparison.NotComparable, TimeComparer.Compare(utc, variant));
    }

    [Fact]
    public void AnAbsentValueIsNotComparableWithAnything()
    {
        var absent = TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(0));

        Assert.Equal(TimeComparison.NotComparable, TimeComparer.Compare(absent, Utc100Ns(TimeSpan.Zero)));
        Assert.Equal(TimeComparison.NotComparable, TimeComparer.Compare(Utc100Ns(TimeSpan.Zero), absent));
        Assert.Equal(TimeComparison.NotComparable, TimeComparer.Compare(absent, absent));
    }

    [Fact]
    public void AnAssumedOffsetMakesAMixedPairComparableAndRecordsTheAssumption()
    {
        var utc = Utc100Ns(TimeSpan.FromHours(5));

        // A local reading of 12:00 that is really 12:00-05:00, i.e. 17:00 UTC — five hours after
        // the UTC value it is being compared with.
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 0);
        var local = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        var assumed = TimeComparer.CompareWithAssumedOffset(utc, local, TimeSpan.FromHours(-5));

        Assert.Equal(TimeComparison.NotDistinguishable, assumed.Outcome);
        Assert.Equal(TimeSpan.FromHours(-5), assumed.AssumedOffset);
        Assert.True(assumed.AssumptionWasUsed);
    }

    [Fact]
    public void AnAssumedOffsetChangesTheOutcomeItIsGivenAndSaysSo()
    {
        var utc = Utc100Ns(TimeSpan.Zero);

        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 0);
        var local = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        // Same pair, a different assumption, a different answer. That the answer moves with the
        // assumption is exactly why the assumption travels with the result.
        var atZero = TimeComparer.CompareWithAssumedOffset(utc, local, TimeSpan.Zero);
        var atPlusNine = TimeComparer.CompareWithAssumedOffset(utc, local, TimeSpan.FromHours(9));

        Assert.Equal(TimeComparison.NotDistinguishable, atZero.Outcome);
        Assert.Equal(TimeComparison.After, atPlusNine.Outcome);
    }

    [Fact]
    public void AnAssumedOffsetIsReportedUnusedWhenBothValuesWereAlreadyAnchored()
    {
        var result = TimeComparer.CompareWithAssumedOffset(
            Utc100Ns(TimeSpan.Zero), Utc100Ns(TimeSpan.FromTicks(5)), TimeSpan.FromHours(3));

        Assert.Equal(TimeComparison.Before, result.Outcome);
        Assert.False(result.AssumptionWasUsed);
    }

    [Fact]
    public void NotDistinguishableIsNotTransitive()
    {
        // a ~ b and b ~ c, but a < c. A caller that assumed transitivity would build a sort whose
        // output depends on the order the values arrived in, which is why this is pinned in a
        // fixture named for it rather than left as a remark in a comment.
        var a = Utc100Ns(TimeSpan.Zero);
        var b = TwoSecondAnchored(12, 0, 0);
        var c = Utc100Ns(TimeSpan.FromMilliseconds(900));

        Assert.Equal(TimeComparison.NotDistinguishable, TimeComparer.Compare(a, b));
        Assert.Equal(TimeComparison.NotDistinguishable, TimeComparer.Compare(b, c));
        Assert.Equal(TimeComparison.Before, TimeComparer.Compare(a, c));
    }

    [Fact]
    public void TwoLocalReadingsAreComparedAsWrittenBecauseNeitherIsAnchored()
    {
        // Both sides unanchored: the caller comparing two local readings is asserting they came
        // from the same machine, and the comparison honours that rather than refusing outright.
        var (earlyDate, earlyTime) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 0);
        var (lateDate, lateTime) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 10);

        var early = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(earlyDate, earlyTime));
        var late = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(lateDate, lateTime));

        Assert.Equal(TimeComparison.Before, TimeComparer.Compare(early, late));
    }

    [Fact]
    public void WithKnownOffsetLeavesTheOriginalValueUntouched()
    {
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 0);
        var original = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        var narrowed = original.WithKnownOffset(TimeSpan.FromHours(-5));

        Assert.Equal(ZoneCertainty.LocalOffsetUnknown, original.Zone);
        Assert.Null(original.RecordedOffset);

        Assert.Equal(ZoneCertainty.LocalOffsetRecorded, narrowed.Zone);
        Assert.Equal(TimeSpan.FromHours(-5), narrowed.RecordedOffset);

        // The reading itself does not move, and the raw value still shows what was on disk.
        Assert.Equal(original.Value, narrowed.Value);
        Assert.Equal(original.Raw.BytesHex, narrowed.Raw.BytesHex);
    }

    [Fact]
    public void ARecordedOffsetAnchorsTheReadingInTheDirectionThatSubtractsIt()
    {
        // A wall clock reading 12:00 at an offset of -05:00 is 17:00 UTC, not 07:00. Every other
        // test that attaches an offset uses zero, where the sign cannot show; without this one a
        // flipped sign would sit in the library with the whole suite green.
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 0);
        var local = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time))
            .WithKnownOffset(TimeSpan.FromHours(-5));

        var seventeenHundredUtc = Utc100Ns(TimeSpan.FromHours(5));
        var sevenHundredUtc = Utc100Ns(TimeSpan.FromHours(-5));

        Assert.Equal(TimeComparison.NotDistinguishable, TimeComparer.Compare(local, seventeenHundredUtc));
        Assert.Equal(TimeComparison.After, TimeComparer.Compare(local, sevenHundredUtc));
    }

    [Fact]
    public void APositiveRecordedOffsetAnchorsTheOtherWay()
    {
        // The mirror of the test above, so that the sign is pinned in both directions rather than
        // by one example a symmetric mistake could still satisfy. 12:00 at +09:00 is 03:00 UTC.
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 0);
        var local = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time))
            .WithKnownOffset(TimeSpan.FromHours(9));

        Assert.Equal(
            TimeComparison.NotDistinguishable,
            TimeComparer.Compare(local, Utc100Ns(TimeSpan.FromHours(-9))));
    }

    [Fact]
    public void WithKnownOffsetRejectsAnOffsetNoZoneCouldHave()
    {
        var (date, time) = TimeFixtures.PackedDateAndTime(2021, 6, 5, 12, 0, 0);
        var local = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(date, time));

        Assert.Throws<ArgumentOutOfRangeException>(() => local.WithKnownOffset(TimeSpan.FromHours(15)));
        Assert.Throws<ArgumentOutOfRangeException>(() => local.WithKnownOffset(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public void AnAbsentValueDoesNotAcquireAZoneByBeingToldOne()
    {
        var absent = TimeFixtures.Unwrap(TimeDecoder.DecodePackedDateAndTime(0, 0));

        var told = absent.WithKnownOffset(TimeSpan.FromHours(2));

        Assert.Equal(TimePresence.Absent, told.Presence);
        Assert.Equal(ZoneCertainty.LocalOffsetUnknown, told.Zone);
        Assert.Null(told.RecordedOffset);
    }

    [Fact]
    public void NarrowUnknownZoneRefusesToOverwriteAZoneTheEncodingAlreadySettles()
    {
        var utc = Utc100Ns(TimeSpan.Zero);

        Assert.Throws<InvalidOperationException>(() => utc.NarrowUnknownZone(ZoneCertainty.LocalOffsetUnknown));
    }

    [Fact]
    public void NarrowUnknownZoneLetsACallerSettleTheVariantFormsConvention()
    {
        var variant = TimeFixtures.Unwrap(
            TimeDecoder.DecodeVariantDayCount(TimeFixtures.VariantDayCount(new DateTime(2021, 6, 5, 12, 0, 0))));

        var asUtc = variant.NarrowUnknownZone(ZoneCertainty.Utc);

        Assert.Equal(ZoneCertainty.Utc, asUtc.Zone);
        Assert.Equal(DateTimeKind.Utc, asUtc.Value!.Value.Kind);
        Assert.Equal(TimeComparison.NotDistinguishable, TimeComparer.Compare(asUtc, Utc100Ns(TimeSpan.Zero)));
    }

    [Fact]
    public void DisplayOrderIsTotalAndStableAcrossInputOrderings()
    {
        var values = new[]
        {
            Utc100Ns(TimeSpan.FromMinutes(3)),
            TimeFixtures.Unwrap(TimeDecoder.DecodePackedCounter1601(0)),
            Utc100Ns(TimeSpan.Zero),
            UtcOneSecond(TimeSpan.FromMinutes(1)),
            TimeFixtures.Unwrap(TimeDecoder.DecodeSecondCounter64(-1)),
        };

        var forward = values.OrderBy(v => v, DisplayOrderOnlyComparer.Instance).ToArray();
        var reversed = values.Reverse().OrderBy(v => v, DisplayOrderOnlyComparer.Instance).ToArray();

        Assert.Equal(
            forward.Select(TimeFormatter.Format),
            reversed.Select(TimeFormatter.Format));

        // Absent values sort last, so a rendered table does not open with a column of "(not set)".
        Assert.Equal(TimePresence.Absent, forward[^1].Presence);
        Assert.Equal(TimePresence.Absent, forward[^2].Presence);
    }
}
