namespace Scythe.Time;

/// <summary>
/// Both readings of a 32-bit second counter whose signedness the caller could not state.
/// </summary>
/// <remarks>
/// The two readings differ only for raw values in <c>0x80000000..0xFFFFFFFE</c>. Below that they
/// agree; at <c>0xFFFFFFFF</c> both are the all-bits-set sentinel. When they differ the decode is
/// <see cref="TimeResultState.Incomplete"/> — the ambiguity is reported, never picked, because
/// picking one silently commits the report to a date that is either in 2038 or in 2106.
/// </remarks>
public sealed class AmbiguousSecondCounterReading
{
    internal AmbiguousSecondCounterReading(
        NormalisedTimestamp signed,
        NormalisedTimestamp unsigned,
        bool readingsAgree)
    {
        Signed = signed;
        Unsigned = unsigned;
        ReadingsAgree = readingsAgree;
    }

    /// <summary>The field read as <c>int32</c>: reaches back before 1970, forward only to 2038.</summary>
    public NormalisedTimestamp Signed { get; }

    /// <summary>The field read as <c>uint32</c>: reaches to 2106, cannot express earlier dates.</summary>
    public NormalisedTimestamp Unsigned { get; }

    /// <summary>
    /// True when both readings denote the same moment, so the unstated signedness does not matter
    /// for this particular value.
    /// </summary>
    public bool ReadingsAgree { get; }
}

/// <summary>
/// A split calendar decode, with the one fact open question 3 asks to be reported rather than
/// inferred from.
/// </summary>
public sealed class SplitCalendarReading
{
    internal SplitCalendarReading(NormalisedTimestamp timestamp, bool millisecondsFieldWasZero)
    {
        Timestamp = timestamp;
        MillisecondsFieldWasZero = millisecondsFieldWasZero;
    }

    public NormalisedTimestamp Timestamp { get; }

    /// <summary>
    /// Whether the milliseconds field held zero. Many producers always write zero there, so a
    /// zero is not evidence of coarser resolution — the value keeps
    /// <see cref="TimePrecision.Millisecond"/> either way and this member lets a caller decide
    /// what to make of it. Inferring coarser precision from the zero would throw away the
    /// distinction between "written as .000" and "not written".
    /// </summary>
    public bool MillisecondsFieldWasZero { get; }
}
