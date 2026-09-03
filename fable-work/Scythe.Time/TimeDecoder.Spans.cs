using System.Buffers.Binary;
using System.Globalization;

namespace Scythe.Time;

/// <summary>
/// Span entry points for the fixed-width encodings, for a caller holding the field's bytes rather
/// than a scalar it has already read out.
/// </summary>
/// <remarks>
/// All of these formats are little-endian on disk, and these overloads read them that way
/// explicitly rather than through <c>BitConverter</c>, so a big-endian host decodes identically.
/// <para>
/// A span shorter than the encoding needs is <see cref="TimeResultState.Incomplete"/>, not
/// Failed: nothing about the field is malformed, the caller simply did not supply all of it. The
/// distinction matters downstream — a truncated read is a coverage gap to be chased, a malformed
/// field is a finding about the artifact.
/// </para>
/// <para>
/// There is deliberately no span overload for the split calendar fields. reference/11.1_time.md
/// gives that structure's field set but not the order the fields sit in on disk, so a span
/// overload would have to guess at a layout; the named-parameter entry point makes the reader
/// that knows the layout state it.
/// </para>
/// </remarks>
public static partial class TimeDecoder
{
    /// <inheritdoc cref="DecodePackedCounter1601(ulong)"/>
    public static TimeResult<NormalisedTimestamp> DecodePackedCounter1601(ReadOnlySpan<byte> field)
    {
        if (field.Length < 8)
        {
            return Truncated<NormalisedTimestamp>("packed 1601-epoch counter", 8, field.Length);
        }

        return DecodePackedCounter1601(BinaryPrimitives.ReadUInt64LittleEndian(field));
    }

    /// <inheritdoc cref="DecodeSplitCounter1601(uint, uint)"/>
    public static TimeResult<NormalisedTimestamp> DecodeSplitCounter1601(ReadOnlySpan<byte> field)
    {
        if (field.Length < 8)
        {
            return Truncated<NormalisedTimestamp>("split 1601-epoch counter", 8, field.Length);
        }

        // Low member first, as the format documents.
        var low = BinaryPrimitives.ReadUInt32LittleEndian(field);
        var high = BinaryPrimitives.ReadUInt32LittleEndian(field[4..]);

        return DecodeSplitCounter1601(low, high);
    }

    /// <inheritdoc cref="DecodeSecondCounter32(uint, CounterSignedness)"/>
    public static TimeResult<NormalisedTimestamp> DecodeSecondCounter32(
        ReadOnlySpan<byte> field,
        CounterSignedness signedness)
    {
        if (field.Length < 4)
        {
            return Truncated<NormalisedTimestamp>("32-bit second counter", 4, field.Length);
        }

        return DecodeSecondCounter32(BinaryPrimitives.ReadUInt32LittleEndian(field), signedness);
    }

    /// <inheritdoc cref="DecodeSecondCounter64(long)"/>
    public static TimeResult<NormalisedTimestamp> DecodeSecondCounter64(ReadOnlySpan<byte> field)
    {
        if (field.Length < 8)
        {
            return Truncated<NormalisedTimestamp>("64-bit second counter", 8, field.Length);
        }

        return DecodeSecondCounter64(BinaryPrimitives.ReadInt64LittleEndian(field));
    }

    /// <inheritdoc cref="DecodePackedDateAndTime(ushort, ushort)"/>
    public static TimeResult<NormalisedTimestamp> DecodePackedDateAndTime(ReadOnlySpan<byte> field)
    {
        if (field.Length < 4)
        {
            return Truncated<NormalisedTimestamp>("packed date and time pair", 4, field.Length);
        }

        var date = BinaryPrimitives.ReadUInt16LittleEndian(field);
        var time = BinaryPrimitives.ReadUInt16LittleEndian(field[2..]);

        return DecodePackedDateAndTime(date, time);
    }

    /// <inheritdoc cref="DecodeVariantDayCount(double)"/>
    public static TimeResult<NormalisedTimestamp> DecodeVariantDayCount(ReadOnlySpan<byte> field)
    {
        if (field.Length < 8)
        {
            return Truncated<NormalisedTimestamp>("variant day count", 8, field.Length);
        }

        return DecodeVariantDayCount(BinaryPrimitives.ReadDoubleLittleEndian(field));
    }

    private static TimeResult<T> Truncated<T>(string what, int needed, int available) where T : class =>
        TimeResult<T>.Incomplete(
            null,
            string.Create(
                CultureInfo.InvariantCulture,
                $"{what}: field needs {needed} bytes, {available} available"));
}
