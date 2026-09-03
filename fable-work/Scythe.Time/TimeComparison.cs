namespace Scythe.Time;

/// <summary>
/// The outcome of a precision-aware comparison. Four values, not three.
/// </summary>
public enum TimeComparison
{
    /// <summary>The windows are disjoint and the left value's is the earlier.</summary>
    Before,

    /// <summary>The windows are disjoint and the left value's is the later.</summary>
    After,

    /// <summary>
    /// The windows overlap, or the values coincide. Deliberately not called "equal": it is a
    /// statement about what the encodings can resolve, not about the moments.
    /// </summary>
    NotDistinguishable,

    /// <summary>
    /// One value's zone is unknown and the other's is not. The unknown one could sit anywhere
    /// across an offset range wider than a day, so no ordering claim would be honest. Also the
    /// outcome when either value is absent — an unwritten field has no place in an ordering.
    /// </summary>
    NotComparable,
}

/// <summary>
/// A comparison a caller obtained by supplying an offset the encodings did not carry, together
/// with the assumption that produced it.
/// </summary>
public sealed class AssumedOffsetComparison
{
    internal AssumedOffsetComparison(TimeComparison outcome, TimeSpan assumedOffset, bool assumptionWasUsed)
    {
        Outcome = outcome;
        AssumedOffset = assumedOffset;
        AssumptionWasUsed = assumptionWasUsed;
    }

    public TimeComparison Outcome { get; }

    /// <summary>The offset the caller supplied for the zone-unknown side.</summary>
    public TimeSpan AssumedOffset { get; }

    /// <summary>
    /// False when both values were already anchored, so the outcome does not rest on the
    /// assumption at all. A caller reporting the assumption alongside the result should say so.
    /// </summary>
    public bool AssumptionWasUsed { get; }
}
