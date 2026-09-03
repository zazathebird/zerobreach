namespace Scythe.ShellItems;

/// <summary>Whether a FILETIME field holds a moment, was never written, or holds a count outside what a calendar can express.</summary>
public enum FileTimePresence
{
    /// <summary>All-zero: the writer never set the field. Rendering it as 1601 would look like data.</summary>
    Unset,

    /// <summary>A count that converts to a calendar moment.</summary>
    Set,

    /// <summary>A non-zero count beyond the range a <see cref="DateTime"/> can hold; kept as raw ticks only.</summary>
    BeyondRange,
}

/// <summary>
/// A FILETIME kept as its exact 100-nanosecond tick count since 1601-01-01 UTC. Timestamps are
/// carried raw so they round-trip exactly; normalisation is Track Q's job.
/// </summary>
public readonly record struct FileTimeValue(ulong Ticks)
{
    // DateTime.MaxValue.Ticks - new DateTime(1601, 1, 1).Ticks.
    private const ulong MaxConvertibleTicks = 2_650_467_743_999_999_999UL;

    public FileTimePresence Presence =>
        Ticks == 0 ? FileTimePresence.Unset
        : Ticks > MaxConvertibleTicks ? FileTimePresence.BeyondRange
        : FileTimePresence.Set;

    /// <summary>The moment in UTC, or null when <see cref="Presence"/> is not <see cref="FileTimePresence.Set"/>.</summary>
    public DateTime? ToUtcDateTime() =>
        Presence == FileTimePresence.Set ? DateTime.FromFileTimeUtc((long)Ticks) : null;
}
