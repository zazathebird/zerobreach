namespace Scythe.TestKit;

/// <summary>Which derived value a checksum field carries.</summary>
public enum ChecksumKind
{
    /// <summary>CRC-32 as used by zlib, PNG and Ethernet: reflected polynomial 0xEDB88320, initial and final XOR 0xFFFFFFFF.</summary>
    Crc32,

    /// <summary>Byte-wise sum, modulo the field width.</summary>
    Sum,

    /// <summary>XOR of consecutive words the width of the field, read in the field's endianness; a trailing partial word is zero-padded.</summary>
    XorFold,

    /// <summary>A caller-supplied function.</summary>
    Custom,
}

/// <summary>
/// The derived-value algorithms the builder can write over a recorded region. Implemented here
/// rather than taken from a package: the kit depends on nothing under test, and the one in-box
/// CRC type (System.IO.Hashing) is not part of the shared framework.
/// </summary>
public static class Checksums
{
    private static readonly uint[] Crc32Table = BuildCrc32Table();

    public static uint Crc32(ReadOnlySpan<byte> bytes)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte b in bytes)
        {
            crc = Crc32Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFF;
    }

    /// <summary>Sum of every byte, reduced to <paramref name="width"/> bytes.</summary>
    public static ulong Sum(ReadOnlySpan<byte> bytes, int width)
    {
        ulong sum = 0;
        foreach (byte b in bytes)
        {
            sum = unchecked(sum + b);
        }

        return sum & FieldCodec.MaxUnsigned(width);
    }

    /// <summary>
    /// XOR of consecutive <paramref name="width"/>-byte words. This is the hive base-block
    /// convention (XOR of 32-bit words) generalised to any width; a trailing partial word is
    /// padded with zeroes on the end, which under either endianness leaves the present bytes in
    /// the positions they would have occupied.
    /// </summary>
    public static ulong XorFold(ReadOnlySpan<byte> bytes, int width, Endian endian)
    {
        if (!FieldCodec.IsSupportedWidth(width))
        {
            throw new FixtureException($"unsupported checksum width {width}; use 1, 2, 4 or 8");
        }

        ulong acc = 0;
        Span<byte> word = stackalloc byte[8];
        for (int at = 0; at < bytes.Length; at += width)
        {
            word.Clear();
            int take = Math.Min(width, bytes.Length - at);
            bytes.Slice(at, take).CopyTo(word);
            acc ^= FieldCodec.Read(word, width, endian);
        }

        return acc;
    }

    private static uint[] BuildCrc32Table()
    {
        var table = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++)
            {
                c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            }

            table[n] = c;
        }

        return table;
    }
}
