namespace Scythe.Time;

/// <summary>
/// What is known about the zone a reading was taken in. A required member of every decoded value,
/// not an annotation: flattening this into a <c>DateTimeOffset</c> with a zero offset is a false
/// claim that the value is UTC, and downstream nothing can tell it from a true one.
/// </summary>
public enum ZoneCertainty
{
    /// <summary>UTC by definition of the encoding. The value's Kind is Utc.</summary>
    Utc,

    /// <summary>
    /// A local wall-clock reading whose machine's offset is recorded nowhere in the file. Never
    /// converted to UTC — see reference/11.1_time.md. The value's Kind is Unspecified.
    /// </summary>
    LocalOffsetUnknown,

    /// <summary>
    /// A local reading the caller has supplied an offset for, out of band, through
    /// <see cref="NormalisedTimestamp.WithKnownOffset"/>. The offset is then present.
    /// </summary>
    LocalOffsetRecorded,

    /// <summary>
    /// The convention varies by producer and this reader cannot narrow it. Degrades comparison to
    /// <see cref="TimeComparison.NotComparable"/>, which is the safe direction.
    /// </summary>
    Unknown,
}
