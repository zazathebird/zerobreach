namespace Scythe.Text;

/// <summary>
/// The byte-order-mark table from reference/11.2_text.md, in the order it must be tested:
/// longest first. The UTF-32 LE mark begins with the UTF-16 LE mark, so a reader that tests
/// two-byte marks first decodes every UTF-32 file as UTF-16 and returns alternating real
/// characters and nulls. That ordering is pinned by a test.
/// </summary>
internal static class ByteOrderMark
{
    internal sealed record Entry(TextEncodingKind Encoding, byte[] Bytes);

    // UTF-7's fourth byte varies; it is handled explicitly in TryMatch.
    private static readonly Entry[] Marks =
    [
        new(TextEncodingKind.Utf32LittleEndian, [0xFF, 0xFE, 0x00, 0x00]),
        new(TextEncodingKind.Utf32BigEndian, [0x00, 0x00, 0xFE, 0xFF]),
        new(TextEncodingKind.UtfEbcdic, [0xDD, 0x73, 0x66, 0x73]),
        new(TextEncodingKind.Gb18030, [0x84, 0x31, 0x95, 0x33]),
        new(TextEncodingKind.Utf8, [0xEF, 0xBB, 0xBF]),
        new(TextEncodingKind.Utf1, [0xF7, 0x64, 0x4C]),
        new(TextEncodingKind.Scsu, [0x0E, 0xFE, 0xFF]),
        new(TextEncodingKind.Bocu1, [0xFB, 0xEE, 0x28]),
        new(TextEncodingKind.Utf16LittleEndian, [0xFF, 0xFE]),
        new(TextEncodingKind.Utf16BigEndian, [0xFE, 0xFF]),
    ];

    private static readonly byte[] Utf7Prefix = [0x2B, 0x2F, 0x76];
    private static readonly byte[] Utf7FourthBytes = [0x38, 0x39, 0x2B, 0x2F];

    /// <summary>
    /// Matches a mark at the start of the buffer, longest first. Returns false when no mark is
    /// recognised; a truncated long mark falls through to the shorter marks it begins with,
    /// which is the only honest reading of the bytes that are actually present.
    /// </summary>
    internal static bool TryMatch(ReadOnlySpan<byte> bytes, out TextEncodingKind encoding, out int markLength)
    {
        // UTF-7 sits among the four-byte marks: 2B 2F 76 then one of 38 39 2B 2F.
        if (bytes.Length >= 4 && bytes[..3].SequenceEqual(Utf7Prefix)
            && Array.IndexOf(Utf7FourthBytes, bytes[3]) >= 0)
        {
            encoding = TextEncodingKind.Utf7;
            markLength = 4;
            return true;
        }

        foreach (var mark in Marks)
        {
            if (bytes.Length >= mark.Bytes.Length && bytes[..mark.Bytes.Length].SequenceEqual(mark.Bytes))
            {
                encoding = mark.Encoding;
                markLength = mark.Bytes.Length;
                return true;
            }
        }

        encoding = TextEncodingKind.Unknown;
        markLength = 0;
        return false;
    }

    /// <summary>The mark a given encoding writes, for decode-side skipping. Empty when none.</summary>
    internal static ReadOnlySpan<byte> MarkFor(TextEncodingKind encoding)
    {
        foreach (var mark in Marks)
        {
            if (mark.Encoding == encoding)
            {
                return mark.Bytes;
            }
        }

        return [];
    }
}
