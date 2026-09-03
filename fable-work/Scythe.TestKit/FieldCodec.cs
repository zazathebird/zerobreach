using System.Buffers.Binary;

namespace Scythe.TestKit;

/// <summary>
/// The one place integers of any width are written into or read out of a byte array. Every
/// builder write, every placeholder resolution and every mutation goes through here, so the
/// endianness rule is spelled once.
/// </summary>
internal static class FieldCodec
{
    public static bool IsSupportedWidth(int width) => width is 1 or 2 or 4 or 8;

    /// <summary>Largest unsigned value a slot of this width can hold.</summary>
    public static ulong MaxUnsigned(int width) => width == 8 ? ulong.MaxValue : (1UL << (8 * width)) - 1;

    /// <summary>Most negative two's-complement value a slot of this width can hold.</summary>
    public static long MinSigned(int width) => width == 8 ? long.MinValue : -(1L << (8 * width - 1));

    /// <summary>
    /// True when <paramref name="value"/> is representable at this width under either the
    /// unsigned or the two's-complement reading. Which reading the format uses is the fixture
    /// author's business; the slot only has to be able to hold the bits.
    /// </summary>
    public static bool Fits(long value, int width)
    {
        if (width == 8)
        {
            return true;
        }

        return value >= MinSigned(width) && value <= (long)MaxUnsigned(width);
    }

    /// <summary>The bit pattern for <paramref name="value"/> at this width, two's complement if negative.</summary>
    public static ulong ToBits(long value, int width) => unchecked((ulong)value) & MaxUnsigned(width);

    public static void Write(Span<byte> slot, int width, Endian endian, ulong bits)
    {
        switch (width)
        {
            case 1:
                slot[0] = (byte)bits;
                break;
            case 2:
                if (endian == Endian.Little)
                {
                    BinaryPrimitives.WriteUInt16LittleEndian(slot, (ushort)bits);
                }
                else
                {
                    BinaryPrimitives.WriteUInt16BigEndian(slot, (ushort)bits);
                }

                break;
            case 4:
                if (endian == Endian.Little)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(slot, (uint)bits);
                }
                else
                {
                    BinaryPrimitives.WriteUInt32BigEndian(slot, (uint)bits);
                }

                break;
            case 8:
                if (endian == Endian.Little)
                {
                    BinaryPrimitives.WriteUInt64LittleEndian(slot, bits);
                }
                else
                {
                    BinaryPrimitives.WriteUInt64BigEndian(slot, bits);
                }

                break;
            default:
                throw new FixtureException($"unsupported field width {width}; use 1, 2, 4 or 8");
        }
    }

    public static ulong Read(ReadOnlySpan<byte> slot, int width, Endian endian)
    {
        return width switch
        {
            1 => slot[0],
            2 => endian == Endian.Little
                ? BinaryPrimitives.ReadUInt16LittleEndian(slot)
                : BinaryPrimitives.ReadUInt16BigEndian(slot),
            4 => endian == Endian.Little
                ? BinaryPrimitives.ReadUInt32LittleEndian(slot)
                : BinaryPrimitives.ReadUInt32BigEndian(slot),
            8 => endian == Endian.Little
                ? BinaryPrimitives.ReadUInt64LittleEndian(slot)
                : BinaryPrimitives.ReadUInt64BigEndian(slot),
            _ => throw new FixtureException($"unsupported field width {width}; use 1, 2, 4 or 8"),
        };
    }

    /// <summary>Renders a value as a fixed-width hex literal, the way a failing test should print it.</summary>
    public static string Hex(ulong bits, int width) => "0x" + bits.ToString("X" + (2 * width), System.Globalization.CultureInfo.InvariantCulture);

    public static string Hex(long value) => "0x" + value.ToString("X", System.Globalization.CultureInfo.InvariantCulture);
}
