namespace Scythe.Text;

/// <summary>
/// Every encoding this library can name. Naming is wider than decoding: the stateful and
/// seven-bit transformation formats (and GB18030) are recognised by their byte-order marks and
/// named, but a decode request for one returns Incomplete with "recognised but not decoded"
/// rather than either a wrong string or silence (reference/11.2_text.md).
/// </summary>
public enum TextEncodingKind
{
    Unknown = 0,

    /// <summary>Every byte 0x00–0x7F. A distinct answer from Utf8: a re-encode is a no-op.</summary>
    Ascii,
    Utf8,
    Utf16LittleEndian,
    Utf16BigEndian,
    Utf32LittleEndian,
    Utf32BigEndian,

    // Recognised by mark, named, not decoded.
    Utf7,
    Utf1,
    UtfEbcdic,
    Scsu,
    Bocu1,
    Gb18030,

    // Single-byte pages with embedded tables, in the canonical scoring order.
    Windows1252,
    Windows1250,
    Windows1251,
    Iso8859Part1,
    Iso8859Part2,
    Iso8859Part5,
    Cp437,
    Cp850,
}
