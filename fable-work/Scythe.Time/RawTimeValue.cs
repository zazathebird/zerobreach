using System.Buffers.Binary;
using System.Globalization;

namespace Scythe.Time;

/// <summary>
/// The encoded value exactly as it appeared, alongside the scalar the decoder read out of it.
/// This is what makes a wrong decode diagnosable with the file in front of you rather than a
/// month later, and it costs nothing to carry.
/// </summary>
/// <remarks>
/// Every scalar is laid out little-endian here regardless of the host's endianness. All of these
/// formats are little-endian on disk, and a raw rendering that changed with the processor running
/// the reader would break the determinism rule the package is built on.
/// </remarks>
public sealed class RawTimeValue
{
    private readonly byte[] _bytes;

    private RawTimeValue(TimeEncoding encoding, byte[] bytes, string scalar)
    {
        _bytes = bytes;
        Encoding = encoding;
        Scalar = scalar;
        BytesHex = Convert.ToHexString(bytes);
    }

    public TimeEncoding Encoding { get; }

    /// <summary>The field's bytes, little-endian, in the order the file held them.</summary>
    public ReadOnlySpan<byte> Bytes => _bytes;

    /// <summary>
    /// Upper-case, unseparated hex of <see cref="Bytes"/>. Present because a report and a test
    /// both need a stable text rendering, and formatting one at each call site invites a
    /// culture-dependent spelling.
    /// </summary>
    public string BytesHex { get; }

    /// <summary>
    /// The decoder's scalar reading, rendered invariantly. For counter forms this is the count
    /// itself; for the field-based forms it is the fields in a fixed order.
    /// </summary>
    public string Scalar { get; }

    internal static RawTimeValue FromUInt64(TimeEncoding encoding, ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
        return new RawTimeValue(encoding, bytes, value.ToString(CultureInfo.InvariantCulture));
    }

    internal static RawTimeValue FromInt64(TimeEncoding encoding, long value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        return new RawTimeValue(encoding, bytes, value.ToString(CultureInfo.InvariantCulture));
    }

    internal static RawTimeValue FromUInt32(TimeEncoding encoding, uint value, string scalar)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        return new RawTimeValue(encoding, bytes, scalar);
    }

    internal static RawTimeValue FromDouble(TimeEncoding encoding, double value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteDoubleLittleEndian(bytes, value);
        return new RawTimeValue(encoding, bytes, value.ToString("R", CultureInfo.InvariantCulture));
    }

    internal static RawTimeValue FromWords(TimeEncoding encoding, ReadOnlySpan<ushort> words, string scalar)
    {
        var bytes = new byte[words.Length * 2];
        for (var i = 0; i < words.Length; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(i * 2, 2), words[i]);
        }

        return new RawTimeValue(encoding, bytes, scalar);
    }

    internal static RawTimeValue FromText(TimeEncoding encoding, ReadOnlySpan<char> text, string scalar) =>
        new(encoding, System.Text.Encoding.UTF8.GetBytes(text.ToString()), scalar);
}
