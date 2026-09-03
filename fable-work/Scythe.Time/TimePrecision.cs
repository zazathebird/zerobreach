namespace Scythe.Time;

/// <summary>
/// The window an encoding resolves. Ordered coarsest-first, and the ordering is load-bearing:
/// <see cref="TimeComparison"/> widens each value by its precision before comparing, and the
/// display comparer breaks ties on it. Do not reorder.
/// </summary>
public enum TimePrecision
{
    /// <summary>Packed date/time pair. The seconds field counts two-second units.</summary>
    TwoSeconds = 0,

    /// <summary>Second counters, 32- and 64-bit.</summary>
    OneSecond = 1,

    /// <summary>
    /// Split calendar fields, and the variant day count. The variant form's mantissa resolves
    /// finer than this over the usable range, but no producer writes finer, and claiming
    /// resolution the data does not support is the defect this member exists to avoid.
    /// </summary>
    Millisecond = 2,

    /// <summary>1601-epoch counters, in all three of their carriers.</summary>
    HundredNanoseconds = 3,
}

public static class TimePrecisionExtensions
{
    /// <summary>The width of the window the precision denotes.</summary>
    public static TimeSpan Width(this TimePrecision precision) => precision switch
    {
        TimePrecision.TwoSeconds => TimeSpan.FromSeconds(2),
        TimePrecision.OneSecond => TimeSpan.FromSeconds(1),
        TimePrecision.Millisecond => TimeSpan.FromMilliseconds(1),
        TimePrecision.HundredNanoseconds => TimeSpan.FromTicks(1),
        _ => throw new ArgumentOutOfRangeException(nameof(precision), precision, null),
    };
}
