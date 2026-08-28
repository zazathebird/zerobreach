using Scythe.Rules.Yara.Parsing;

namespace Scythe.Rules.Yara.Matching;

/// <summary>Which encoding carried the plaintext, for fullword boundary checks. Boundary
/// bytes are always tested raw (verified against the reference: an xor'd match checks its
/// un-decoded neighbours), but wide matches use the two-byte (alnum, 0x00) pair test.</summary>
internal enum VariantEncoding : byte { Ascii, Wide }

/// <summary>One concrete byte pattern searched by the literal engine. A YARA string with
/// modifiers expands into several of these (encodings × xor keys × base64 permutations).</summary>
internal sealed record LiteralVariant(
    int StringIndex,
    byte[] Bytes,
    bool Nocase,
    bool Fullword,
    VariantEncoding Encoding);

internal static class LiteralVariantGenerator
{
    /// <summary>
    /// Expands a text string's modifier set into concrete patterns, following the
    /// reference semantics verified by differential test:
    ///  - `wide ascii` produces both encodings, as separate patterns;
    ///  - bare `xor` is all 256 keys including 0 (the plaintext itself);
    ///  - `base64`/`base64wide` produce the three encoding permutations, and combine with
    ///    `wide`/`ascii` by encoding the *plaintext* first, then base64-ing that;
    ///  - base64 output is never nocase/fullword/xor (the parser rejects those combos).
    /// </summary>
    public static List<LiteralVariant> Expand(int stringIndex, TextStringDecl decl)
    {
        var m = decl.Modifiers;
        var result = new List<LiteralVariant>();
        bool wantAscii = m.Has(StringModifierKind.Ascii) || !m.Has(StringModifierKind.Wide);
        bool wantWide = m.Has(StringModifierKind.Wide);

        var plaintexts = new List<(byte[] Bytes, VariantEncoding Enc)>();
        if (wantAscii)
        {
            plaintexts.Add((decl.ValueBytes, VariantEncoding.Ascii));
        }
        if (wantWide)
        {
            plaintexts.Add((Widen(decl.ValueBytes), VariantEncoding.Wide));
        }

        if (m.Has(StringModifierKind.Base64) || m.Has(StringModifierKind.Base64Wide))
        {
            var alphabet = AlphabetBytes(m.Base64Alphabet);
            foreach (var (bytes, _) in plaintexts)
            {
                foreach (var perm in Base64Permutations(bytes, alphabet))
                {
                    if (m.Has(StringModifierKind.Base64))
                    {
                        result.Add(new LiteralVariant(stringIndex, perm, Nocase: false, Fullword: false, VariantEncoding.Ascii));
                    }
                    if (m.Has(StringModifierKind.Base64Wide))
                    {
                        result.Add(new LiteralVariant(stringIndex, Widen(perm), Nocase: false, Fullword: false, VariantEncoding.Wide));
                    }
                }
            }
            return result;
        }

        bool nocase = m.Has(StringModifierKind.Nocase);
        bool fullword = m.Has(StringModifierKind.Fullword);
        foreach (var (bytes, enc) in plaintexts)
        {
            if (m.Has(StringModifierKind.Xor))
            {
                for (int key = m.XorMin; key <= m.XorMax; key++)
                {
                    var x = new byte[bytes.Length];
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        x[i] = (byte)(bytes[i] ^ key);
                    }
                    result.Add(new LiteralVariant(stringIndex, x, Nocase: false, fullword, enc));
                }
            }
            else
            {
                result.Add(new LiteralVariant(stringIndex, bytes, nocase, fullword, enc));
            }
        }
        return result;
    }

    internal static byte[] Widen(byte[] bytes)
    {
        var wide = new byte[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            wide[i * 2] = bytes[i];
        }
        return wide;
    }

    private static byte[] AlphabetBytes(string? alphabet)
    {
        const string standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var text = alphabet ?? standard;
        var bytes = new byte[64];
        for (int i = 0; i < 64; i++)
        {
            bytes[i] = (byte)text[i];
        }
        return bytes;
    }

    /// <summary>
    /// The three alignment permutations of the base64-encoded form (verified byte-for-byte
    /// against yara 4.5.5): permutation i encodes i dummy bytes before the data, then trims
    /// the characters whose bits are not fully determined by the data — leading 0/2/3
    /// characters for i = 0/1/2, and one trailing character when the tail 3-byte group is
    /// partial.
    /// </summary>
    internal static List<byte[]> Base64Permutations(byte[] data, byte[] alphabet)
    {
        var result = new List<byte[]>(3);
        for (int shift = 0; shift < 3; shift++)
        {
            var padded = new byte[shift + data.Length];
            data.CopyTo(padded, shift);
            var encoded = EncodeNoPadding(padded, alphabet);
            int lead = shift switch { 0 => 0, 1 => 2, _ => 3 };
            int trail = (shift + data.Length) % 3 == 0 ? 0 : 1;
            result.Add(encoded[lead..(encoded.Length - trail)]);
        }
        return result;
    }

    private static byte[] EncodeNoPadding(byte[] data, byte[] alphabet)
    {
        int outLen = data.Length / 3 * 4 + (data.Length % 3) switch { 0 => 0, 1 => 2, _ => 3 };
        var output = new byte[outLen];
        int o = 0;
        int i = 0;
        for (; i + 2 < data.Length; i += 3)
        {
            int v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
            output[o++] = alphabet[(v >> 18) & 63];
            output[o++] = alphabet[(v >> 12) & 63];
            output[o++] = alphabet[(v >> 6) & 63];
            output[o++] = alphabet[v & 63];
        }
        int rem = data.Length - i;
        if (rem == 1)
        {
            int v = data[i] << 16;
            output[o++] = alphabet[(v >> 18) & 63];
            output[o] = alphabet[(v >> 12) & 63];
        }
        else if (rem == 2)
        {
            int v = (data[i] << 16) | (data[i + 1] << 8);
            output[o++] = alphabet[(v >> 18) & 63];
            output[o++] = alphabet[(v >> 12) & 63];
            output[o] = alphabet[(v >> 6) & 63];
        }
        return output;
    }
}
