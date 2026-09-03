using System.Buffers.Binary;
using System.Text;

namespace Scythe.ShellItems.Tests.Fixtures;

/// <summary>Byte-level building blocks. Every fixture in this suite is constructed, never collected.</summary>
internal static class Bytes
{
    internal static byte[] Concat(params byte[][] parts)
    {
        var bytes = new byte[parts.Sum(p => p.Length)];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(bytes, offset);
            offset += part.Length;
        }

        return bytes;
    }

    internal static byte[] U16(ushort value)
    {
        var b = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(b, value);
        return b;
    }

    internal static byte[] U32(uint value)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        return b;
    }

    internal static byte[] I32(int value)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(b, value);
        return b;
    }

    internal static byte[] U64(ulong value)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, value);
        return b;
    }

    internal static byte[] Guid(Guid value) => value.ToByteArray();

    /// <summary>UTF-16LE code unit by code unit, so a lone surrogate is written as-is rather than replaced.</summary>
    internal static byte[] Utf16(string text)
    {
        var b = new byte[text.Length * 2];
        for (var i = 0; i < text.Length; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(i * 2), text[i]);
        }

        return b;
    }

    internal static byte[] Utf16Z(string text) => Concat(Utf16(text), [0, 0]);

    internal static byte[] Latin1(string text) => Encoding.Latin1.GetBytes(text);

    internal static byte[] Latin1Z(string text) => Concat(Latin1(text), [0]);

    /// <summary>Copies <paramref name="value"/> into a zero-filled field of exactly <paramref name="length"/> bytes.</summary>
    internal static byte[] Fixed(byte[] value, int length)
    {
        var b = new byte[length];
        Array.Copy(value, b, Math.Min(value.Length, length));
        return b;
    }

    internal static byte[] Patch(this byte[] source, int offset, ushort value)
    {
        var copy = (byte[])source.Clone();
        BinaryPrimitives.WriteUInt16LittleEndian(copy.AsSpan(offset), value);
        return copy;
    }

    internal static byte[] Patch(this byte[] source, int offset, uint value)
    {
        var copy = (byte[])source.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(offset), value);
        return copy;
    }

    internal static byte[] Patch(this byte[] source, int offset, byte value)
    {
        var copy = (byte[])source.Clone();
        copy[offset] = value;
        return copy;
    }

    internal static byte[] Take(this byte[] source, int count) => source[..count];
}
