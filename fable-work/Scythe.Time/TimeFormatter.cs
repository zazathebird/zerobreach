using System.Globalization;

namespace Scythe.Time;

/// <summary>
/// The deterministic rendering from reference/11.1_time.md §11.1.
/// </summary>
/// <remarks>
/// There is no culture-sensitive overload and no way to pass a culture in. A report's text is
/// compared across runs and across machines, and a formatter that consulted the host's culture,
/// zone or clock would make that comparison depend on which workstation produced it.
/// </remarks>
public static class TimeFormatter
{
    /// <summary>What an absent value renders as. Contains no digit, by test.</summary>
    public const string AbsentRendering = "(not set)";

    /// <summary>
    /// The two-second form's width marker. The encoding resolves to two seconds, so the value it
    /// carries is one second either side of the moment that was written.
    /// </summary>
    public const string TwoSecondWidthMarker = " ±1s";

    public const string LocalOffsetUnknownMarker = " (local, offset unknown)";

    /// <summary>
    /// Rendering for <see cref="ZoneCertainty.Unknown"/>. Not tabulated in the reference, which
    /// gives markers only for Utc and for the local-unrecorded case; this spells out the third
    /// state rather than letting it borrow either one's marker.
    /// </summary>
    public const string ZoneUnknownMarker = " (zone unknown)";

    public static string Format(NormalisedTimestamp timestamp)
    {
        ArgumentNullException.ThrowIfNull(timestamp);

        if (timestamp.Presence == TimePresence.Absent)
        {
            // Deliberately incapable of being mistaken for a date. An unwritten 1601-epoch field
            // rendered naively reads "1601-01-01", which in a client-facing report is
            // indistinguishable from a fact about the machine.
            return AbsentRendering;
        }

        var value = timestamp.Value!.Value;

        var pattern = timestamp.Precision switch
        {
            TimePrecision.HundredNanoseconds => "yyyy-MM-ddTHH:mm:ss.fffffff",
            TimePrecision.Millisecond => "yyyy-MM-ddTHH:mm:ss.fff",
            TimePrecision.OneSecond => "yyyy-MM-ddTHH:mm:ss",
            TimePrecision.TwoSeconds => "yyyy-MM-ddTHH:mm:ss",
            _ => throw new ArgumentOutOfRangeException(nameof(timestamp), timestamp.Precision, null),
        };

        // A fixed pattern per precision, because a format string is a claim about resolution: a
        // two-second value printed with seven fractional digits is a lie told by the formatter.
        var text = value.ToString(pattern, CultureInfo.InvariantCulture);

        if (timestamp.Precision == TimePrecision.TwoSeconds)
        {
            text += TwoSecondWidthMarker;
        }

        return text + ZoneMarker(timestamp);
    }

    private static string ZoneMarker(NormalisedTimestamp timestamp) => timestamp.Zone switch
    {
        ZoneCertainty.Utc => "Z",
        ZoneCertainty.LocalOffsetUnknown => LocalOffsetUnknownMarker,
        ZoneCertainty.LocalOffsetRecorded => $" (local, offset {FormatOffset(timestamp.RecordedOffset!.Value)})",
        ZoneCertainty.Unknown => ZoneUnknownMarker,
        _ => throw new ArgumentOutOfRangeException(nameof(timestamp), timestamp.Zone, null),
    };

    /// <summary>Renders an offset as ±HH:MM, invariantly.</summary>
    public static string FormatOffset(TimeSpan offset)
    {
        var sign = offset < TimeSpan.Zero ? '-' : '+';
        var magnitude = offset.Duration();

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{sign}{magnitude.Hours + (magnitude.Days * 24):D2}:{magnitude.Minutes:D2}");
    }
}
