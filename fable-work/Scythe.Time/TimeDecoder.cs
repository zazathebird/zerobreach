using System.Globalization;

namespace Scythe.Time;

/// <summary>
/// The decoders for the encodings tabulated in reference/11.1_time.md §11.1.
/// </summary>
/// <remarks>
/// Every entry point is pure: no file access, no clock, no host zone, no host culture. Each takes
/// values or small spans a Track E or Track H reader has already located — this project has no
/// notion of what artifact a timestamp came from beyond the encoding the caller names.
/// </remarks>
public static partial class TimeDecoder
{
    /// <summary>1601-01-01 00:00:00 UTC, in <see cref="DateTime"/> ticks.</summary>
    internal const long Epoch1601Ticks = 504_911_232_000_000_000L;

    /// <summary>1970-01-01 00:00:00 UTC, in <see cref="DateTime"/> ticks.</summary>
    internal const long Epoch1970Ticks = 621_355_968_000_000_000L;

    /// <summary>1899-12-30 00:00:00, in <see cref="DateTime"/> ticks. Not 1899-12-31.</summary>
    internal const long Epoch1899Ticks = 599_264_352_000_000_000L;

    /// <summary>The largest 1601-epoch count that lands inside <see cref="DateTime.MaxValue"/>.</summary>
    internal const ulong MaxCount1601 = 2_650_467_743_999_999_999UL;

    internal const long MinUnixSeconds = -62_135_596_800L;
    internal const long MaxUnixSeconds = 253_402_300_799L;

    /// <summary>Days from the 1899 epoch to <see cref="DateTime.MinValue"/> and MaxValue.</summary>
    internal const double MinVariantDays = -693_593.0;
    internal const double MaxVariantDays = 2_958_466.0;

    /// <summary>
    /// Twenty digits is the widest a <c>uint64</c> can be. Checked before any parse, so a
    /// pathological string is refused in time proportional to nothing.
    /// </summary>
    internal const int MaxCounterDigits = 20;

    // ---------------------------------------------------------------- 1601-epoch counters

    /// <summary>
    /// Decodes a 64-bit count of 100 ns intervals since 1601-01-01 UTC. UTC by definition of the
    /// encoding, so the result's zone certainty is not in doubt.
    /// </summary>
    public static TimeResult<NormalisedTimestamp> DecodePackedCounter1601(ulong count)
    {
        var raw = RawTimeValue.FromUInt64(TimeEncoding.PackedCounter1601, count);
        return Counter1601(count, TimeEncoding.PackedCounter1601, raw);
    }

    /// <summary>
    /// Decodes the same count carried as two 32-bit members. The low member comes first — that is
    /// the documented member order, and supplying them the other way round is the mistake this
    /// signature's parameter names exist to prevent. A transposed pair yields a count far past
    /// the representable range, which is Failed rather than a plausible date.
    /// </summary>
    public static TimeResult<NormalisedTimestamp> DecodeSplitCounter1601(uint low, uint high)
    {
        var count = ((ulong)high << 32) | low;

        Span<ushort> words =
        [
            (ushort)(low & 0xFFFF), (ushort)(low >> 16),
            (ushort)(high & 0xFFFF), (ushort)(high >> 16),
        ];

        var raw = RawTimeValue.FromWords(
            TimeEncoding.SplitCounter1601,
            words,
            string.Create(
                CultureInfo.InvariantCulture,
                $"low={low}, high={high}, count={count}"));

        // Both members zero, and both members all-bits-set, are the group's sentinels. Checking
        // the assembled count would treat a low of 0xFFFFFFFF with a high of 0 as an ordinary
        // value, which it is; only the whole group means "never written".
        if (low == 0 && high == 0)
        {
            return TimeResult<NormalisedTimestamp>.Ok(Absent1601(SentinelKind.Zero, TimeEncoding.SplitCounter1601, raw));
        }

        if (low == uint.MaxValue && high == uint.MaxValue)
        {
            return TimeResult<NormalisedTimestamp>.Ok(Absent1601(SentinelKind.AllBitsSet, TimeEncoding.SplitCounter1601, raw));
        }

        return Counter1601(
            count,
            TimeEncoding.SplitCounter1601,
            raw,
            zeroIsSentinel: false,
            allBitsSetIsSentinel: false);
    }

    /// <summary>
    /// Decodes a 1601-epoch count carried as decimal text. Leading zeros and surrounding
    /// whitespace are accepted; a sign, embedded separators and any non-ASCII digit are not.
    /// </summary>
    /// <remarks>
    /// The length is checked against <see cref="MaxCounterDigits"/> before anything is parsed or
    /// copied, so an absurdly long string fails immediately and allocates nothing proportional to
    /// its size.
    /// </remarks>
    public static TimeResult<NormalisedTimestamp> DecodeDecimalStringCounter1601(
        ReadOnlySpan<char> text,
        ScanBudget? budget = null)
    {
        budget ??= ScanBudget.Default;

        if ((long)text.Length > budget.MaxInputBytes)
        {
            return TimeResult<NormalisedTimestamp>.Incomplete(
                null,
                $"decimal-string counter: input is {text.Length} characters, budget allows {budget.MaxInputBytes}");
        }

        if (text.Length == 0)
        {
            var empty = RawTimeValue.FromText(TimeEncoding.DecimalStringCounter1601, text, "(empty)");
            return TimeResult<NormalisedTimestamp>.Ok(
                Absent1601(SentinelKind.Empty, TimeEncoding.DecimalStringCounter1601, empty));
        }

        var trimmed = text.Trim();

        if (trimmed.Length == 0)
        {
            // Keep the original span in Raw: "how many spaces" is occasionally the diagnostic.
            var blank = RawTimeValue.FromText(TimeEncoding.DecimalStringCounter1601, text, "(whitespace)");
            return TimeResult<NormalisedTimestamp>.Ok(
                Absent1601(SentinelKind.Whitespace, TimeEncoding.DecimalStringCounter1601, blank));
        }

        if (trimmed.Length > MaxCounterDigits)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                $"decimal-string counter: {trimmed.Length} digits, maximum for a 64-bit count is {MaxCounterDigits}",
                position: MaxCounterDigits);
        }

        ulong count = 0;
        for (var i = 0; i < trimmed.Length; i++)
        {
            var c = trimmed[i];
            if (c is < '0' or > '9')
            {
                return TimeResult<NormalisedTimestamp>.Failed(
                    $"decimal-string counter: character '{c}' at index {i} is not an ASCII digit",
                    position: i);
            }

            var digit = (ulong)(c - '0');

            // Twenty digits can still overflow uint64; catch it on the digit that does it rather
            // than wrapping into a plausible-looking count.
            if (count > (ulong.MaxValue - digit) / 10)
            {
                return TimeResult<NormalisedTimestamp>.Failed(
                    $"decimal-string counter: value overflows a 64-bit count at index {i}",
                    position: i);
            }

            count = (count * 10) + digit;
        }

        var raw = RawTimeValue.FromText(
            TimeEncoding.DecimalStringCounter1601,
            trimmed,
            count.ToString(CultureInfo.InvariantCulture));

        return Counter1601(
            count,
            TimeEncoding.DecimalStringCounter1601,
            raw,
            allBitsSetIsSentinel: false);
    }

    /// <param name="zeroIsSentinel">
    /// False only for the split form, whose group sentinels are checked on the members before the
    /// count is assembled.
    /// </param>
    /// <param name="allBitsSetIsSentinel">
    /// False for the decimal-string form. reference/11.1_time.md lists that row's "not set"
    /// patterns as "0", empty and whitespace-only, and does not list the all-bits-set value — so
    /// the text "18446744073709551615" is an out-of-range count, which is Failed, rather than an
    /// absence. Reading the table exactly matters here: treating it as a sentinel would make a
    /// corrupt field disappear from a report instead of being flagged.
    /// </param>
    private static TimeResult<NormalisedTimestamp> Counter1601(
        ulong count,
        TimeEncoding encoding,
        RawTimeValue raw,
        bool zeroIsSentinel = true,
        bool allBitsSetIsSentinel = true)
    {
        if (zeroIsSentinel && count == 0)
        {
            return TimeResult<NormalisedTimestamp>.Ok(Absent1601(SentinelKind.Zero, encoding, raw));
        }

        if (allBitsSetIsSentinel && count == ulong.MaxValue)
        {
            return TimeResult<NormalisedTimestamp>.Ok(Absent1601(SentinelKind.AllBitsSet, encoding, raw));
        }

        if (count > MaxCount1601)
        {
            // A malformed field, not an unwritten one — Q1 open question 5. Conflating the two
            // would let a corrupted value vanish from a report instead of being flagged.
            return TimeResult<NormalisedTimestamp>.Failed(
                $"1601-epoch counter: {count} exceeds the largest representable count {MaxCount1601}");
        }

        var value = new DateTime(Epoch1601Ticks + (long)count, DateTimeKind.Utc);

        return TimeResult<NormalisedTimestamp>.Ok(NormalisedTimestamp.Present(
            value, TimePrecision.HundredNanoseconds, ZoneCertainty.Utc, encoding, raw));
    }

    private static NormalisedTimestamp Absent1601(SentinelKind kind, TimeEncoding encoding, RawTimeValue raw) =>
        NormalisedTimestamp.Absent(kind, TimePrecision.HundredNanoseconds, ZoneCertainty.Utc, encoding, raw);

    // ---------------------------------------------------------------- 1970-epoch counters

    /// <summary>
    /// Decodes a 32-bit count of seconds since 1970-01-01 UTC. The caller states the signedness,
    /// because it is a property of the field rather than of the encoding (Q1 open question 2).
    /// </summary>
    public static TimeResult<NormalisedTimestamp> DecodeSecondCounter32(
        uint field,
        CounterSignedness signedness)
    {
        var seconds = signedness == CounterSignedness.Signed ? unchecked((int)field) : (long)field;

        var raw = RawTimeValue.FromUInt32(
            TimeEncoding.SecondCounter32,
            field,
            string.Create(CultureInfo.InvariantCulture, $"{seconds} ({signedness})"));

        // Both readings share their sentinels: 0 is zero either way, and 0xFFFFFFFF is
        // all-bits-set whether it is read as -1 or as 4294967295.
        if (field == 0)
        {
            return TimeResult<NormalisedTimestamp>.Ok(AbsentUnix(SentinelKind.Zero, TimeEncoding.SecondCounter32, raw));
        }

        if (field == uint.MaxValue)
        {
            return TimeResult<NormalisedTimestamp>.Ok(AbsentUnix(SentinelKind.AllBitsSet, TimeEncoding.SecondCounter32, raw));
        }

        return UnixSeconds(seconds, TimeEncoding.SecondCounter32, raw);
    }

    /// <summary>
    /// Decodes a 32-bit second counter whose signedness the caller cannot state, returning both
    /// readings. <see cref="TimeResultState.Ok"/> when they agree; Incomplete when they do not,
    /// with the ambiguity reported rather than resolved.
    /// </summary>
    public static TimeResult<AmbiguousSecondCounterReading> DecodeSecondCounter32Ambiguous(uint field)
    {
        var signed = DecodeSecondCounter32(field, CounterSignedness.Signed);
        var unsigned = DecodeSecondCounter32(field, CounterSignedness.Unsigned);

        if (signed.State == TimeResultState.Failed)
        {
            return TimeResult<AmbiguousSecondCounterReading>.Failed(signed.Reason!, signed.Position);
        }

        if (unsigned.State == TimeResultState.Failed)
        {
            return TimeResult<AmbiguousSecondCounterReading>.Failed(unsigned.Reason!, unsigned.Position);
        }

        // Only values with the top bit set can disagree; below that the two readings are the same
        // number, and 0xFFFFFFFF is the sentinel under both.
        var agree = signed.Value!.Value == unsigned.Value!.Value
                    && signed.Value.Presence == unsigned.Value.Presence;

        var reading = new AmbiguousSecondCounterReading(signed.Value, unsigned.Value, agree);

        if (agree)
        {
            return TimeResult<AmbiguousSecondCounterReading>.Ok(reading);
        }

        return TimeResult<AmbiguousSecondCounterReading>.Incomplete(
            reading,
            string.Create(
                CultureInfo.InvariantCulture,
                $"32-bit second counter 0x{field:X8}: signedness not stated and the readings differ — "
                + $"signed reads {TimeFormatter.Format(signed.Value)}, "
                + $"unsigned reads {TimeFormatter.Format(unsigned.Value)}"));
    }

    /// <summary>Decodes a 64-bit signed count of seconds since 1970-01-01 UTC.</summary>
    public static TimeResult<NormalisedTimestamp> DecodeSecondCounter64(long seconds)
    {
        var raw = RawTimeValue.FromInt64(TimeEncoding.SecondCounter64, seconds);

        if (seconds == 0)
        {
            return TimeResult<NormalisedTimestamp>.Ok(AbsentUnix(SentinelKind.Zero, TimeEncoding.SecondCounter64, raw));
        }

        if (seconds == -1)
        {
            return TimeResult<NormalisedTimestamp>.Ok(AbsentUnix(SentinelKind.AllBitsSet, TimeEncoding.SecondCounter64, raw));
        }

        return UnixSeconds(seconds, TimeEncoding.SecondCounter64, raw);
    }

    private static TimeResult<NormalisedTimestamp> UnixSeconds(long seconds, TimeEncoding encoding, RawTimeValue raw)
    {
        if (seconds < MinUnixSeconds || seconds > MaxUnixSeconds)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                $"1970-epoch second counter: {seconds} falls outside the representable range "
                + $"{MinUnixSeconds}..{MaxUnixSeconds}");
        }

        var value = new DateTime(Epoch1970Ticks + (seconds * TimeSpan.TicksPerSecond), DateTimeKind.Utc);

        return TimeResult<NormalisedTimestamp>.Ok(NormalisedTimestamp.Present(
            value, TimePrecision.OneSecond, ZoneCertainty.Utc, encoding, raw));
    }

    private static NormalisedTimestamp AbsentUnix(SentinelKind kind, TimeEncoding encoding, RawTimeValue raw) =>
        NormalisedTimestamp.Absent(kind, TimePrecision.OneSecond, ZoneCertainty.Utc, encoding, raw);

    // ---------------------------------------------------------------- packed date and time

    /// <summary>
    /// Decodes the packed 16-bit date and 16-bit time pair.
    /// </summary>
    /// <remarks>
    /// Date word: bits 0–4 day, 5–8 month, 9–15 year minus 1980. Time word: bits 0–4 seconds
    /// divided by two, 5–10 minute, 11–15 hour. The halved seconds field is where the two-second
    /// precision comes from; it is a property of the encoding and not of the writer, so it is
    /// attributed even when the value happens to land on an even second.
    /// <para>
    /// The reading is local wall-clock with the machine's offset recorded nowhere in the file, so
    /// it stays local. See <see cref="NormalisedTimestamp.WithKnownOffset"/> for the explicit way
    /// to attach an offset known out of band.
    /// </para>
    /// </remarks>
    public static TimeResult<NormalisedTimestamp> DecodePackedDateAndTime(ushort date, ushort time)
    {
        Span<ushort> words = [date, time];

        var day = date & 0x1F;
        var month = (date >> 5) & 0x0F;
        var year = ((date >> 9) & 0x7F) + 1980;

        var doubleSeconds = time & 0x1F;
        var minute = (time >> 5) & 0x3F;
        var hour = (time >> 11) & 0x1F;

        var raw = RawTimeValue.FromWords(
            TimeEncoding.PackedDateAndTime,
            words,
            string.Create(
                CultureInfo.InvariantCulture,
                $"date=0x{date:X4}, time=0x{time:X4}, y={year}, mo={month}, d={day}, h={hour}, mi={minute}, s2={doubleSeconds}"));

        // Only the whole pair means "never written". A zero date word beside a non-zero time word
        // is a malformed date, not an absence, and is reported as such below.
        if (date == 0 && time == 0)
        {
            return TimeResult<NormalisedTimestamp>.Ok(NormalisedTimestamp.Absent(
                SentinelKind.Zero,
                TimePrecision.TwoSeconds,
                ZoneCertainty.LocalOffsetUnknown,
                TimeEncoding.PackedDateAndTime,
                raw));
        }

        if (month is < 1 or > 12)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                $"packed date 0x{date:X4}: month field is {month}, valid range is 1..12");
        }

        if (day < 1)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                $"packed date 0x{date:X4}: day field is {day}, valid range is 1..31");
        }

        // The 5-bit day field cannot express 32, so the reachable overrun is a day past the end of
        // a short month — 31 April, 30 February — which is exactly as malformed and far likelier.
        var daysInMonth = DateTime.DaysInMonth(year, month);
        if (day > daysInMonth)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                $"packed date 0x{date:X4}: day field is {day}, but {year}-{month:D2} has {daysInMonth} days");
        }

        if (hour > 23)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                $"packed time 0x{time:X4}: hour field is {hour}, valid range is 0..23");
        }

        if (minute > 59)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                $"packed time 0x{time:X4}: minute field is {minute}, valid range is 0..59");
        }

        if (doubleSeconds > 29)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                $"packed time 0x{time:X4}: two-second field is {doubleSeconds} ({doubleSeconds * 2} s), valid range is 0..29");
        }

        var value = new DateTime(year, month, day, hour, minute, doubleSeconds * 2, DateTimeKind.Unspecified);

        return TimeResult<NormalisedTimestamp>.Ok(NormalisedTimestamp.Present(
            value,
            TimePrecision.TwoSeconds,
            ZoneCertainty.LocalOffsetUnknown,
            TimeEncoding.PackedDateAndTime,
            raw));
    }

    // ---------------------------------------------------------------- variant day count

    /// <summary>
    /// Decodes a floating-point day offset from 1899-12-30.
    /// </summary>
    /// <remarks>
    /// The fractional part is a <em>magnitude</em>, not a signed remainder, so the conversion is
    /// <c>epoch + truncate(v) days + abs(fraction(v)) × 24 h</c>. A plain <c>AddDays(v)</c> is
    /// wrong for every pre-epoch value by twice the fraction — six hours on a value like -1.25,
    /// small enough to look like a real time.
    /// <para>
    /// Zone certainty is <see cref="ZoneCertainty.Unknown"/>: producers disagree about whether
    /// this form carries local or UTC readings and nothing in the value records it (Q1 open
    /// question 1). A caller that knows the convention for its artifact narrows it with
    /// <see cref="NormalisedTimestamp.NarrowUnknownZone"/>.
    /// </para>
    /// </remarks>
    public static TimeResult<NormalisedTimestamp> DecodeVariantDayCount(double days)
    {
        var raw = RawTimeValue.FromDouble(TimeEncoding.VariantDayCount, days);

        if (double.IsNaN(days))
        {
            return TimeResult<NormalisedTimestamp>.Failed("variant day count: value is NaN");
        }

        if (double.IsInfinity(days))
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                $"variant day count: value is {(double.IsPositiveInfinity(days) ? "positive" : "negative")} infinity");
        }

        // Exactly 0.0 is the sentinel. Negative zero shares the comparison but not the bit
        // pattern, and Raw keeps the bits, so a caller can still tell them apart.
        if (days == 0.0)
        {
            return TimeResult<NormalisedTimestamp>.Ok(NormalisedTimestamp.Absent(
                SentinelKind.Zero,
                TimePrecision.Millisecond,
                ZoneCertainty.Unknown,
                TimeEncoding.VariantDayCount,
                raw));
        }

        if (days < MinVariantDays || days > MaxVariantDays)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"variant day count: {days:R} falls outside the representable range {MinVariantDays:R}..{MaxVariantDays:R}"));
        }

        var whole = Math.Truncate(days);
        var fraction = Math.Abs(days - whole);

        var dayTicks = (long)whole * TimeSpan.TicksPerDay;
        var timeTicks = (long)Math.Round(fraction * TimeSpan.TicksPerDay, MidpointRounding.AwayFromZero);

        // Millisecond precision is what is attributed, so the value is rounded to it rather than
        // carrying mantissa noise into the seven-digit slot of a formatter that would print it.
        timeTicks = RoundTicksToMillisecond(timeTicks);

        var total = Epoch1899Ticks + dayTicks + timeTicks;

        if (total < DateTime.MinValue.Ticks || total > DateTime.MaxValue.Ticks)
        {
            return TimeResult<NormalisedTimestamp>.Failed(
                string.Create(CultureInfo.InvariantCulture, $"variant day count: {days:R} converts outside the representable date range"));
        }

        return TimeResult<NormalisedTimestamp>.Ok(NormalisedTimestamp.Present(
            new DateTime(total, DateTimeKind.Unspecified),
            TimePrecision.Millisecond,
            ZoneCertainty.Unknown,
            TimeEncoding.VariantDayCount,
            raw));
    }

    private static long RoundTicksToMillisecond(long ticks)
    {
        const long perMs = TimeSpan.TicksPerMillisecond;
        var remainder = ticks % perMs;
        if (remainder == 0)
        {
            return ticks;
        }

        return remainder * 2 >= perMs ? ticks - remainder + perMs : ticks - remainder;
    }

    // ---------------------------------------------------------------- split calendar fields

    /// <summary>
    /// Decodes the eight absolute 16-bit calendar fields.
    /// </summary>
    /// <remarks>
    /// The fields are taken by name rather than as a span, deliberately. reference/11.1_time.md
    /// gives the field set but not the order they sit in on disk, and a decoder that assumed one
    /// would be silently wrong for any producer using another. The reader that located the
    /// structure knows its layout; it maps to these parameters.
    /// <para>
    /// Zone certainty is <see cref="ZoneCertainty.Unknown"/>: the reference records the
    /// convention as unrecorded, though UTC when the structure is carried in an event record. The
    /// reader that knows which case it has narrows with
    /// <see cref="NormalisedTimestamp.NarrowUnknownZone"/>.
    /// </para>
    /// </remarks>
    /// <param name="dayOfWeek">
    /// Range-checked only. It is redundant with the date, and zero is both "Sunday" and the value
    /// producers leave when they do not fill it in, so a disagreement with the computed weekday is
    /// not treated as malformed.
    /// </param>
    public static TimeResult<SplitCalendarReading> DecodeSplitCalendarFields(
        ushort year,
        ushort month,
        ushort day,
        ushort hour,
        ushort minute,
        ushort second,
        ushort millisecond,
        ushort dayOfWeek = 0)
    {
        Span<ushort> words = [year, month, day, hour, minute, second, millisecond, dayOfWeek];

        var raw = RawTimeValue.FromWords(
            TimeEncoding.SplitCalendarFields,
            words,
            string.Create(
                CultureInfo.InvariantCulture,
                $"y={year}, mo={month}, d={day}, h={hour}, mi={minute}, s={second}, ms={millisecond}, dow={dayOfWeek}"));

        if (year == 0 && month == 0 && day == 0 && hour == 0
            && minute == 0 && second == 0 && millisecond == 0 && dayOfWeek == 0)
        {
            return TimeResult<SplitCalendarReading>.Ok(new SplitCalendarReading(
                NormalisedTimestamp.Absent(
                    SentinelKind.Zero,
                    TimePrecision.Millisecond,
                    ZoneCertainty.Unknown,
                    TimeEncoding.SplitCalendarFields,
                    raw),
                millisecondsFieldWasZero: true));
        }

        if (year is < 1 or > 9999)
        {
            return TimeResult<SplitCalendarReading>.Failed(
                $"split calendar fields: year field is {year}, valid range is 1..9999");
        }

        if (month is < 1 or > 12)
        {
            return TimeResult<SplitCalendarReading>.Failed(
                $"split calendar fields: month field is {month}, valid range is 1..12");
        }

        var daysInMonth = DateTime.DaysInMonth(year, month);
        if (day < 1 || day > daysInMonth)
        {
            return TimeResult<SplitCalendarReading>.Failed(
                $"split calendar fields: day field is {day}, but {year}-{month:D2} has {daysInMonth} days");
        }

        if (hour > 23)
        {
            return TimeResult<SplitCalendarReading>.Failed(
                $"split calendar fields: hour field is {hour}, valid range is 0..23");
        }

        if (minute > 59)
        {
            return TimeResult<SplitCalendarReading>.Failed(
                $"split calendar fields: minute field is {minute}, valid range is 0..59");
        }

        // 60 is rejected along with everything above it: DateTime cannot represent a leap second,
        // so accepting it would mean silently renumbering the value to :59 or to the next minute.
        if (second > 59)
        {
            return TimeResult<SplitCalendarReading>.Failed(
                $"split calendar fields: second field is {second}, valid range is 0..59");
        }

        if (millisecond > 999)
        {
            return TimeResult<SplitCalendarReading>.Failed(
                $"split calendar fields: millisecond field is {millisecond}, valid range is 0..999");
        }

        if (dayOfWeek > 6)
        {
            return TimeResult<SplitCalendarReading>.Failed(
                $"split calendar fields: day-of-week field is {dayOfWeek}, valid range is 0..6");
        }

        var value = new DateTime(year, month, day, hour, minute, second, millisecond, DateTimeKind.Unspecified);

        return TimeResult<SplitCalendarReading>.Ok(new SplitCalendarReading(
            NormalisedTimestamp.Present(
                value,
                TimePrecision.Millisecond,
                ZoneCertainty.Unknown,
                TimeEncoding.SplitCalendarFields,
                raw),
            millisecondsFieldWasZero: millisecond == 0));
    }
}
