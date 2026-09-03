namespace Scythe.Time;

/// <summary>
/// One decoded moment, carrying everything known about how it was read.
/// </summary>
/// <remarks>
/// There is deliberately no conversion to <c>DateTimeOffset</c> and no implicit conversion to
/// <c>DateTime</c>. Both would let a caller obtain a moment without seeing <see cref="Zone"/> and
/// <see cref="Precision"/>, and those two are the product: the conversion arithmetic is trivial,
/// and carrying enough context that a wrong reading is visible is not.
/// </remarks>
public sealed class NormalisedTimestamp
{
    private NormalisedTimestamp(
        TimePresence presence,
        SentinelKind sentinel,
        DateTime? value,
        TimePrecision precision,
        ZoneCertainty zone,
        TimeSpan? recordedOffset,
        TimeEncoding encoding,
        RawTimeValue raw)
    {
        Presence = presence;
        Sentinel = sentinel;
        Value = value;
        Precision = precision;
        Zone = zone;
        RecordedOffset = recordedOffset;
        Encoding = encoding;
        Raw = raw;
    }

    public TimePresence Presence { get; }

    /// <summary>
    /// Which "never set" pattern matched, when <see cref="Presence"/> is Absent;
    /// <see cref="SentinelKind.None"/> otherwise.
    /// </summary>
    public SentinelKind Sentinel { get; }

    /// <summary>
    /// The moment, with the <c>Kind</c> that <see cref="Zone"/> implies — Utc, or Unspecified for
    /// a local reading. Null when <see cref="Presence"/> is Absent.
    /// </summary>
    public DateTime? Value { get; }

    /// <summary>The window this encoding resolves.</summary>
    public TimePrecision Precision { get; }

    /// <summary>The width of that window, as a <see cref="TimeSpan"/>.</summary>
    public TimeSpan PrecisionWidth => Precision.Width();

    public ZoneCertainty Zone { get; }

    /// <summary>
    /// The offset, non-null only when <see cref="Zone"/> is
    /// <see cref="ZoneCertainty.LocalOffsetRecorded"/>.
    /// </summary>
    public TimeSpan? RecordedOffset { get; }

    public TimeEncoding Encoding { get; }

    public RawTimeValue Raw { get; }

    /// <summary>True when the value is anchored to a known point on the UTC line.</summary>
    internal bool IsAnchored =>
        Zone is ZoneCertainty.Utc or ZoneCertainty.LocalOffsetRecorded;

    /// <summary>
    /// The moment expressed as a UTC instant. Only meaningful when <see cref="IsAnchored"/>.
    /// </summary>
    internal DateTime AnchoredUtc =>
        Zone == ZoneCertainty.Utc
            ? Value!.Value
            : Value!.Value - RecordedOffset!.Value;

    internal static NormalisedTimestamp Present(
        DateTime value,
        TimePrecision precision,
        ZoneCertainty zone,
        TimeEncoding encoding,
        RawTimeValue raw,
        TimeSpan? recordedOffset = null) =>
        new(TimePresence.Present, SentinelKind.None, value, precision, zone, recordedOffset, encoding, raw);

    internal static NormalisedTimestamp Absent(
        SentinelKind sentinel,
        TimePrecision precision,
        ZoneCertainty zone,
        TimeEncoding encoding,
        RawTimeValue raw) =>
        new(TimePresence.Absent, sentinel, null, precision, zone, null, encoding, raw);

    /// <summary>
    /// Pairs a local reading with an offset the caller knows out of band, producing a new value
    /// whose zone certainty is <see cref="ZoneCertainty.LocalOffsetRecorded"/>.
    /// </summary>
    /// <remarks>
    /// Explicitly named, never a default, and never a mutation of the decoded value: the original
    /// stays intact and the returned value keeps the same <see cref="Raw"/>, so a report can show
    /// what was on disk next to what was assumed about it. Q1 open question 4.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The offset is outside ±14:00, or is not a whole number of minutes. Both are programming
    /// errors on the caller's part rather than properties of the input, which is why this throws
    /// where the decoders return a result.
    /// </exception>
    public NormalisedTimestamp WithKnownOffset(TimeSpan offset)
    {
        if (offset < TimeSpan.FromHours(-14) || offset > TimeSpan.FromHours(14))
        {
            throw new ArgumentOutOfRangeException(
                nameof(offset), offset, "Assumed offset must lie within ±14:00.");
        }

        if (offset.Ticks % TimeSpan.TicksPerMinute != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(offset), offset, "Assumed offset must be a whole number of minutes.");
        }

        if (Presence == TimePresence.Absent)
        {
            // An unwritten field does not acquire a zone by being told one.
            return this;
        }

        // The reading itself does not move. Only what is known about it changes.
        return new NormalisedTimestamp(
            Presence,
            Sentinel,
            DateTime.SpecifyKind(Value!.Value, DateTimeKind.Unspecified),
            Precision,
            ZoneCertainty.LocalOffsetRecorded,
            offset,
            Encoding,
            Raw);
    }

    /// <summary>
    /// Narrows a value decoded with <see cref="ZoneCertainty.Unknown"/> to the convention the
    /// caller knows for that artifact — see Q1 open question 1, which is why the variant day
    /// count decodes as Unknown rather than guessing.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The value's zone certainty is not <see cref="ZoneCertainty.Unknown"/>. Narrowing a value
    /// whose zone the encoding already settles would be overwriting a fact with an assumption.
    /// </exception>
    public NormalisedTimestamp NarrowUnknownZone(ZoneCertainty certainty)
    {
        if (Zone != ZoneCertainty.Unknown)
        {
            throw new InvalidOperationException(
                $"Zone certainty is already {Zone}; only Unknown may be narrowed.");
        }

        if (certainty is not (ZoneCertainty.Utc or ZoneCertainty.LocalOffsetUnknown))
        {
            throw new ArgumentOutOfRangeException(
                nameof(certainty),
                certainty,
                "Narrow to Utc or LocalOffsetUnknown; use WithKnownOffset to supply an offset.");
        }

        if (Presence == TimePresence.Absent)
        {
            return this;
        }

        var kind = certainty == ZoneCertainty.Utc ? DateTimeKind.Utc : DateTimeKind.Unspecified;

        return new NormalisedTimestamp(
            Presence,
            Sentinel,
            DateTime.SpecifyKind(Value!.Value, kind),
            Precision,
            certainty,
            null,
            Encoding,
            Raw);
    }

    /// <summary>
    /// The deterministic rendering from reference/11.1_time.md. Delegates to
    /// <see cref="TimeFormatter"/>; see there for the patterns and the reason there is no
    /// culture-sensitive overload.
    /// </summary>
    public override string ToString() => TimeFormatter.Format(this);
}
