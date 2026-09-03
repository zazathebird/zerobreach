namespace Scythe.Time;

/// <summary>
/// Which decoder produced a value. Travels with every result so a report can say how a moment was
/// read — the encodings in reference/11.1_time.md all produce a plausible date when read with the
/// wrong rule, and this is what makes a wrong reading visible rather than merely wrong.
/// </summary>
public enum TimeEncoding
{
    /// <summary>64-bit count of 100 ns intervals since 1601-01-01 UTC, one field.</summary>
    PackedCounter1601,

    /// <summary>The same count carried as two 32-bit members, low member first.</summary>
    SplitCounter1601,

    /// <summary>The same count carried as decimal text.</summary>
    DecimalStringCounter1601,

    /// <summary>32-bit count of seconds since 1970-01-01 UTC. Signedness is the caller's to state.</summary>
    SecondCounter32,

    /// <summary>64-bit signed count of seconds since 1970-01-01 UTC.</summary>
    SecondCounter64,

    /// <summary>Two 16-bit words: a packed date and a packed time, two-second resolution, local.</summary>
    PackedDateAndTime,

    /// <summary>Floating-point day offset from 1899-12-30, fractional part a magnitude.</summary>
    VariantDayCount,

    /// <summary>Eight absolute 16-bit calendar fields.</summary>
    SplitCalendarFields,
}

/// <summary>
/// Whether a 32-bit second counter's field is signed. A property of the field, not of the
/// encoding, so the caller states it (Q1 open question 2).
/// </summary>
public enum CounterSignedness
{
    Signed,
    Unsigned,
}
