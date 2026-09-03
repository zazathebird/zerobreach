namespace Scythe.Time;

/// <summary>
/// Precision-aware comparison over decoded timestamps.
/// </summary>
/// <remarks>
/// Each value denotes a window: the value widened by its precision, half the width either side.
/// The reference's own marker for the two-second form — <c>±1s</c> — is what settles the window
/// as centred on the value rather than running forward from it.
/// </remarks>
public static class TimeComparer
{
    /// <summary>
    /// Compares two values, returning one of four outcomes. Never orders two values whose zones
    /// are not both known, and never reports "equal" for two values it merely cannot separate.
    /// </summary>
    public static TimeComparison Compare(NormalisedTimestamp left, NormalisedTimestamp right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        if (left.Presence == TimePresence.Absent || right.Presence == TimePresence.Absent)
        {
            return TimeComparison.NotComparable;
        }

        if (left.IsAnchored != right.IsAnchored)
        {
            // One sits on the UTC line and the other is a wall-clock reading from a machine whose
            // offset is not in the file. The gap between them is unbounded by more than a day.
            return TimeComparison.NotComparable;
        }

        // Both anchored: compare instants. Neither anchored: compare the readings as written,
        // which is honest only if they came from the same machine — the caller supplying two
        // local readings is asserting exactly that by comparing them.
        var leftTicks = left.IsAnchored ? left.AnchoredUtc.Ticks : left.Value!.Value.Ticks;
        var rightTicks = right.IsAnchored ? right.AnchoredUtc.Ticks : right.Value!.Value.Ticks;

        return CompareWindows(leftTicks, left.PrecisionWidth, rightTicks, right.PrecisionWidth);
    }

    /// <summary>
    /// Compares two values, applying an offset the caller supplies for whichever side's zone the
    /// encoding did not settle. The result carries the assumption that produced it.
    /// </summary>
    /// <remarks>
    /// This is the escape hatch for a caller that needs an ordering across a mixed pair. It is a
    /// separate call rather than an optional argument on <see cref="Compare"/> so that the
    /// assumption cannot be made by accident, and it returns the assumption alongside the outcome
    /// so a report can state it.
    /// </remarks>
    public static AssumedOffsetComparison CompareWithAssumedOffset(
        NormalisedTimestamp left,
        NormalisedTimestamp right,
        TimeSpan assumedOffset)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        if (left.Presence == TimePresence.Absent || right.Presence == TimePresence.Absent)
        {
            return new AssumedOffsetComparison(TimeComparison.NotComparable, assumedOffset, assumptionWasUsed: false);
        }

        var used = !left.IsAnchored || !right.IsAnchored;

        var leftTicks = AnchorWith(left, assumedOffset);
        var rightTicks = AnchorWith(right, assumedOffset);

        var outcome = CompareWindows(leftTicks, left.PrecisionWidth, rightTicks, right.PrecisionWidth);

        return new AssumedOffsetComparison(outcome, assumedOffset, used);
    }

    private static long AnchorWith(NormalisedTimestamp timestamp, TimeSpan assumedOffset) =>
        timestamp.IsAnchored
            ? timestamp.AnchoredUtc.Ticks
            : timestamp.Value!.Value.Ticks - assumedOffset.Ticks;

    private static TimeComparison CompareWindows(
        long leftTicks,
        TimeSpan leftWidth,
        long rightTicks,
        TimeSpan rightWidth)
    {
        var leftHalf = leftWidth.Ticks / 2;
        var rightHalf = rightWidth.Ticks / 2;

        var leftStart = leftTicks - leftHalf;
        var leftEnd = leftTicks + leftHalf;
        var rightStart = rightTicks - rightHalf;
        var rightEnd = rightTicks + rightHalf;

        // Strict, so that two windows merely touching at an endpoint stay ordered: two
        // second-counter values exactly one second apart are genuinely distinguishable, and an
        // inclusive test would report otherwise.
        var overlaps = leftStart < rightEnd && rightStart < leftEnd;

        if (overlaps)
        {
            return TimeComparison.NotDistinguishable;
        }

        if (leftTicks < rightTicks)
        {
            return TimeComparison.Before;
        }

        if (leftTicks > rightTicks)
        {
            return TimeComparison.After;
        }

        // Equal values at 100 ns precision produce degenerate, non-overlapping windows.
        return TimeComparison.NotDistinguishable;
    }
}

/// <summary>
/// A total order over decoded timestamps, for rendering a table in a stable sequence.
/// </summary>
/// <remarks>
/// <b>This is not a chronology and must never be read as one.</b> It sorts by the underlying
/// value exactly as written, without normalising zones, so a local reading and a UTC reading sort
/// against each other on two different lines. It exists because a four-outcome comparison cannot
/// drive <c>List.Sort</c>, and it is kept off <see cref="TimeComparer"/> so it cannot be mistaken
/// for a correctness claim. Use <see cref="TimeComparer.Compare"/> for any question about
/// ordering in fact.
/// <para>
/// Tie-break, in order, so that the sequence is identical across runs: absent values last, then
/// the value's ticks, then precision, then zone certainty, then encoding, then the raw bytes as
/// hex, then the raw scalar — the last two compared ordinally.
/// </para>
/// </remarks>
public sealed class DisplayOrderOnlyComparer : IComparer<NormalisedTimestamp>
{
    public static DisplayOrderOnlyComparer Instance { get; } = new();

    public int Compare(NormalisedTimestamp? x, NormalisedTimestamp? y)
    {
        if (ReferenceEquals(x, y))
        {
            return 0;
        }

        if (x is null)
        {
            return -1;
        }

        if (y is null)
        {
            return 1;
        }

        var xAbsent = x.Presence == TimePresence.Absent;
        var yAbsent = y.Presence == TimePresence.Absent;

        if (xAbsent != yAbsent)
        {
            return xAbsent ? 1 : -1;
        }

        if (!xAbsent)
        {
            var byValue = x.Value!.Value.Ticks.CompareTo(y.Value!.Value.Ticks);
            if (byValue != 0)
            {
                return byValue;
            }
        }
        else
        {
            var bySentinel = ((int)x.Sentinel).CompareTo((int)y.Sentinel);
            if (bySentinel != 0)
            {
                return bySentinel;
            }
        }

        var byPrecision = ((int)x.Precision).CompareTo((int)y.Precision);
        if (byPrecision != 0)
        {
            return byPrecision;
        }

        var byZone = ((int)x.Zone).CompareTo((int)y.Zone);
        if (byZone != 0)
        {
            return byZone;
        }

        var byEncoding = ((int)x.Encoding).CompareTo((int)y.Encoding);
        if (byEncoding != 0)
        {
            return byEncoding;
        }

        var byBytes = string.CompareOrdinal(x.Raw.BytesHex, y.Raw.BytesHex);
        return byBytes != 0 ? byBytes : string.CompareOrdinal(x.Raw.Scalar, y.Raw.Scalar);
    }
}
