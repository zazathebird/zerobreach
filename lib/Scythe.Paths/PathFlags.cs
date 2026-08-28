namespace Scythe.Paths;

/// <summary>
/// Signals raised during normalisation. Flags are evidence, not errors: a flagged path still
/// normalises, and the guard decides policy. Nothing flagged here is ever silently resolved
/// or folded away — resolving 8.3 names needs the file system, and folding homoglyphs would
/// destroy a detection signal.
/// </summary>
[Flags]
public enum PathFlags
{
    None = 0,

    /// <summary>A component looks like a DOS 8.3 short name (<c>PROGRA~1</c>). Left as-is; resolving it needs the file system.</summary>
    ShortNameComponent = 1 << 0,

    /// <summary>A component names a reserved DOS device (<c>CON</c>, <c>NUL</c>, <c>COM1</c>…, with or without an extension).</summary>
    ReservedDeviceName = 1 << 1,

    /// <summary>The path contains Unicode look-alike or invisible characters. Flagged, never folded.</summary>
    HomoglyphCharacters = 1 << 2,

    /// <summary>Trailing dots and/or spaces were stripped, as Windows does silently.</summary>
    TrailingDotsOrSpacesStripped = 1 << 3,

    /// <summary>An alternate data stream suffix (<c>:stream</c> / <c>:stream:$DATA</c>) was split out.</summary>
    AlternateDataStream = 1 << 4,

    /// <summary>The stream suffix named the default data stream (<c>::$DATA</c>), which is the file itself.</summary>
    DefaultDataStream = 1 << 5,

    /// <summary>
    /// The input carried a literal <c>\\?\</c> prefix. Real Windows passes such paths to the
    /// kernel verbatim (no separator, dot-segment, or trailing-dot processing). This library
    /// still normalises them so the comparison form is useful; this flag preserves the fact
    /// that Windows itself would not have.
    /// </summary>
    VerbatimPrefix = 1 << 6,

    /// <summary>A <c>..</c> segment tried to climb above the root (or above <c>\\server\share</c>) and was clamped.</summary>
    ParentTraversalClamped = 1 << 7,

    /// <summary>UNC server is a loopback name (<c>localhost</c>, <c>127.0.0.1</c>): the path may alias a local drive.</summary>
    LoopbackUncServer = 1 << 8,

    /// <summary>UNC share looks administrative (<c>C$</c>, <c>ADMIN$</c>): the path may alias a local drive.</summary>
    AdministrativeShare = 1 << 9,
}
