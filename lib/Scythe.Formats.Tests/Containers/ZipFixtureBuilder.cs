using System.IO.Compression;
using System.Text;

namespace Scythe.Formats.Tests.Containers;

/// <summary>
/// Hand-writes ZIP byte buffers — local headers, central directory, end-of-central-directory
/// record — so tests control every field, including the lying ones. Deliberately independent
/// of the reader under test: offsets and sizes are computed here from first principles, and
/// the CRC-32 is a second implementation, so agreement between builder and reader actually
/// means something.
/// </summary>
internal sealed class ZipEntryFixture
{
    public required string Name { get; init; }

    /// <summary>Raw name bytes override (for CP437 / invalid-UTF-8 cases). When null, Name is UTF-8 encoded.</summary>
    public byte[]? NameBytesOverride { get; init; }

    public byte[] Data { get; init; } = Array.Empty<byte>();

    /// <summary>0 = stored, 8 = deflate.</summary>
    public ushort Method { get; init; } = 0;

    public bool Encrypted { get; init; }

    public bool Utf8NameFlag { get; init; }

    public ushort DosTime { get; init; }

    public ushort DosDate { get; init; } = 0x58CF; // 2024-06-15

    /// <summary>Pre-compressed payload override; when set, Data is only used for CRC/size fields.</summary>
    public byte[]? CompressedOverride { get; init; }

    // Central-directory lies: when set, the CD records these instead of the truth.
    public uint? CdCrcOverride { get; init; }
    public uint? CdCompressedSizeOverride { get; init; }
    public uint? CdUncompressedSizeOverride { get; init; }
    public string? CdNameOverride { get; init; }
    public ushort? CdMethodOverride { get; init; }
    public uint? CdLocalOffsetOverride { get; init; }
}

internal static class ZipFixtureBuilder
{
    internal static byte[] Build(params ZipEntryFixture[] entries) => Build(entries, eocdCountOverride: null);

    internal static byte[] Build(ZipEntryFixture[] entries, ushort? eocdCountOverride)
    {
        var buffer = new MemoryStream();
        var localOffsets = new long[entries.Length];
        var payloads = new byte[entries.Length][];
        var crcs = new uint[entries.Length];

        for (int i = 0; i < entries.Length; i++)
        {
            var e = entries[i];
            localOffsets[i] = buffer.Length;
            payloads[i] = e.CompressedOverride ?? (e.Method == 8 ? Deflate(e.Data) : e.Data);
            crcs[i] = Crc32(e.Data);
            byte[] nameBytes = e.NameBytesOverride ?? Encoding.UTF8.GetBytes(e.Name);

            WriteU32(buffer, 0x04034B50);
            WriteU16(buffer, 20);                       // version needed
            WriteU16(buffer, LocalFlags(e));
            WriteU16(buffer, e.Method);
            WriteU16(buffer, e.DosTime);
            WriteU16(buffer, e.DosDate);
            WriteU32(buffer, crcs[i]);
            WriteU32(buffer, (uint)payloads[i].Length);
            WriteU32(buffer, (uint)e.Data.Length);
            WriteU16(buffer, (ushort)nameBytes.Length);
            WriteU16(buffer, 0);                        // extra length
            buffer.Write(nameBytes);
            buffer.Write(payloads[i]);
        }

        long cdOffset = buffer.Length;
        for (int i = 0; i < entries.Length; i++)
        {
            var e = entries[i];
            byte[] nameBytes = e.CdNameOverride is not null
                ? Encoding.UTF8.GetBytes(e.CdNameOverride)
                : e.NameBytesOverride ?? Encoding.UTF8.GetBytes(e.Name);

            WriteU32(buffer, 0x02014B50);
            WriteU16(buffer, 20);                       // version made by
            WriteU16(buffer, 20);                       // version needed
            WriteU16(buffer, LocalFlags(e));
            WriteU16(buffer, e.CdMethodOverride ?? e.Method);
            WriteU16(buffer, e.DosTime);
            WriteU16(buffer, e.DosDate);
            WriteU32(buffer, e.CdCrcOverride ?? crcs[i]);
            WriteU32(buffer, e.CdCompressedSizeOverride ?? (uint)payloads[i].Length);
            WriteU32(buffer, e.CdUncompressedSizeOverride ?? (uint)e.Data.Length);
            WriteU16(buffer, (ushort)nameBytes.Length);
            WriteU16(buffer, 0);                        // extra length
            WriteU16(buffer, 0);                        // comment length
            WriteU16(buffer, 0);                        // disk number start
            WriteU16(buffer, 0);                        // internal attributes
            WriteU32(buffer, 0);                        // external attributes
            WriteU32(buffer, e.CdLocalOffsetOverride ?? (uint)localOffsets[i]);
            buffer.Write(nameBytes);
        }

        long cdSize = buffer.Length - cdOffset;
        ushort count = eocdCountOverride ?? (ushort)entries.Length;
        WriteU32(buffer, 0x06054B50);
        WriteU16(buffer, 0);                            // disk number
        WriteU16(buffer, 0);                            // central directory disk
        WriteU16(buffer, count);
        WriteU16(buffer, count);
        WriteU32(buffer, (uint)cdSize);
        WriteU32(buffer, (uint)cdOffset);
        WriteU16(buffer, 0);                            // comment length
        return buffer.ToArray();
    }

    private static ushort LocalFlags(ZipEntryFixture e)
    {
        ushort flags = 0;
        if (e.Encrypted)
        {
            flags |= 0x0001;
        }
        if (e.Utf8NameFlag)
        {
            flags |= 0x0800;
        }
        return flags;
    }

    /// <summary>Raw deflate via the BCL — test-side compression only; the reader's parsing is what's under test.</summary>
    internal static byte[] Deflate(byte[] raw)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            deflate.Write(raw);
        }
        return output.ToArray();
    }

    /// <summary>Bitwise CRC-32, independent of the library's table-driven one.</summary>
    internal static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int k = 0; k < 8; k++)
            {
                crc = (crc & 1) != 0 ? 0xEDB88320u ^ (crc >> 1) : crc >> 1;
            }
        }
        return crc ^ 0xFFFFFFFFu;
    }

    internal static void WriteU16(Stream s, ushort v)
    {
        s.WriteByte((byte)(v & 0xFF));
        s.WriteByte((byte)(v >> 8));
    }

    internal static void WriteU32At(byte[] buffer, int offset, uint v)
    {
        buffer[offset] = (byte)(v & 0xFF);
        buffer[offset + 1] = (byte)((v >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((v >> 16) & 0xFF);
        buffer[offset + 3] = (byte)(v >> 24);
    }

    internal static void WriteU32(Stream s, uint v)
    {
        s.WriteByte((byte)(v & 0xFF));
        s.WriteByte((byte)((v >> 8) & 0xFF));
        s.WriteByte((byte)((v >> 16) & 0xFF));
        s.WriteByte((byte)(v >> 24));
    }
}
