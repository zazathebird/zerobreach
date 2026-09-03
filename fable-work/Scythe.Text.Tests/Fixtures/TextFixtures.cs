using System.Text;

namespace Scythe.Text.Tests.Fixtures;

/// <summary>
/// Fixture builders. Everything is constructed programmatically — no checked-in blobs — so the
/// malformed variants are one mutated field away from the valid ones
/// (tasks/00_INTEGRATION.md, "Write a fixture builder, not fixture files").
/// </summary>
internal static class TextFixtures
{
    internal static byte[] Utf8Mark => [0xEF, 0xBB, 0xBF];
    internal static byte[] Utf16LeMark => [0xFF, 0xFE];
    internal static byte[] Utf16BeMark => [0xFE, 0xFF];
    internal static byte[] Utf32LeMark => [0xFF, 0xFE, 0x00, 0x00];
    internal static byte[] Utf32BeMark => [0x00, 0x00, 0xFE, 0xFF];

    internal static byte[] Concat(params byte[][] parts)
    {
        var total = parts.Sum(p => p.Length);
        var bytes = new byte[total];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(bytes, offset);
            offset += part.Length;
        }

        return bytes;
    }

    internal static byte[] Ascii(string text) => Encoding.ASCII.GetBytes(text);

    internal static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);

    internal static byte[] Utf16(string text, bool bigEndian, bool withMark)
    {
        var payload = new byte[text.Length * 2];
        for (var i = 0; i < text.Length; i++)
        {
            var unit = (ushort)text[i];
            if (bigEndian)
            {
                payload[i * 2] = (byte)(unit >> 8);
                payload[i * 2 + 1] = (byte)unit;
            }
            else
            {
                payload[i * 2] = (byte)unit;
                payload[i * 2 + 1] = (byte)(unit >> 8);
            }
        }

        return withMark
            ? Concat(bigEndian ? Utf16BeMark : Utf16LeMark, payload)
            : payload;
    }

    internal static byte[] Utf32(int[] codePoints, bool bigEndian, bool withMark)
    {
        var payload = new byte[codePoints.Length * 4];
        for (var i = 0; i < codePoints.Length; i++)
        {
            var v = (uint)codePoints[i];
            if (bigEndian)
            {
                payload[i * 4] = (byte)(v >> 24);
                payload[i * 4 + 1] = (byte)(v >> 16);
                payload[i * 4 + 2] = (byte)(v >> 8);
                payload[i * 4 + 3] = (byte)v;
            }
            else
            {
                payload[i * 4] = (byte)v;
                payload[i * 4 + 1] = (byte)(v >> 8);
                payload[i * 4 + 2] = (byte)(v >> 16);
                payload[i * 4 + 3] = (byte)(v >> 24);
            }
        }

        return withMark
            ? Concat(bigEndian ? Utf32BeMark : Utf32LeMark, payload)
            : payload;
    }

    /// <summary>
    /// Encodes text into a single-byte page by reversing the library's own embedded table.
    /// Round-trip fidelity against that table is exactly what the decode tests want; agreement
    /// of the table itself with the published mappings is pinned separately by
    /// CodePageTableTests against hand-written expected values.
    /// </summary>
    internal static byte[] PageEncode(string text, TextEncodingKind page)
    {
        var codePage = CodePage.ForKind(page)
            ?? throw new ArgumentException($"not a single-byte page: {page}", nameof(page));

        var bytes = new byte[text.Length];
        for (var i = 0; i < text.Length; i++)
        {
            var c = (ushort)text[i];
            var found = -1;
            for (var b = 0; b < 256; b++)
            {
                if (codePage.Map[b] == c)
                {
                    found = b;
                    break;
                }
            }

            if (found < 0)
            {
                throw new ArgumentException($"'{text[i]}' (U+{c:X4}) has no {page} encoding");
            }

            bytes[i] = (byte)found;
        }

        return bytes;
    }

    /// <summary>
    /// A byte cycle constructed so every one of the eight candidate pages accumulates a firmly
    /// negative score: 0x98 is undefined in windows-1251 and windows-1250, a C1 control in the
    /// ISO pages and a mere symbol in windows-1252; 0x9D is undefined in windows-1252; and
    /// 0xB0–0xB4 form a box-drawing symbol run in the OEM pages. Repeated, nothing fits.
    /// </summary>
    internal static byte[] EveryPageScoresBadly(int totalBytes)
    {
        byte[] cycle = [0x98, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0x98, 0x9D];
        var bytes = new byte[totalBytes];
        for (var i = 0; i < totalBytes; i++)
        {
            bytes[i] = cycle[i % cycle.Length];
        }

        return bytes;
    }
}
