namespace Scythe.Time;

/// <summary>
/// Whether the field held a moment. Absence is a normal, complete answer — the field exists and
/// says "never written" — so it arrives as <see cref="TimeResultState.Ok"/>, not Incomplete
/// (nothing was truncated) and not Failed (nothing was malformed).
/// </summary>
public enum TimePresence
{
    Present,
    Absent,
}

/// <summary>
/// Which "never set" bit pattern matched. Callers distinguish a field left at zero from one
/// written with the all-bits-set placeholder; the two mean different things about the producer
/// even though both mean "no moment here".
/// </summary>
public enum SentinelKind
{
    /// <summary>No sentinel matched — the value is present.</summary>
    None,

    /// <summary>All bits of the field, or all members of the group, were zero.</summary>
    Zero,

    /// <summary>
    /// All bits of the field, or all members of the group, were set. For the signed 64-bit second
    /// counter this is the value -1; the name describes the bit pattern, which is what the
    /// producer wrote.
    /// </summary>
    AllBitsSet,

    /// <summary>The decimal-string form was empty.</summary>
    Empty,

    /// <summary>The decimal-string form held only whitespace.</summary>
    Whitespace,
}
