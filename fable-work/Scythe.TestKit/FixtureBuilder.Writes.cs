using System.Text;

namespace Scythe.TestKit;

/// <summary>The write surface: integers, text, layout and derived values.</summary>
public sealed partial class FixtureBuilder
{
    private static readonly Encoding Utf16LeStrict = new UnicodeEncoding(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true);
    private static readonly Encoding Utf16BeStrict = new UnicodeEncoding(bigEndian: true, byteOrderMark: false, throwOnInvalidBytes: true);
    private static readonly Encoding Utf8Strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static int codePagesRegistered;

    // ---- integers in the builder's endianness ------------------------------------------------

    public FixtureBuilder U8(byte value) => Int(1, value, Endian);

    public FixtureBuilder I8(sbyte value) => Int(1, unchecked((byte)value), Endian);

    public FixtureBuilder U16(ushort value) => Int(2, value, Endian);

    public FixtureBuilder I16(short value) => Int(2, unchecked((ushort)value), Endian);

    public FixtureBuilder U32(uint value) => Int(4, value, Endian);

    public FixtureBuilder I32(int value) => Int(4, unchecked((uint)value), Endian);

    public FixtureBuilder U64(ulong value) => Int(8, value, Endian);

    public FixtureBuilder I64(long value) => Int(8, unchecked((ulong)value), Endian);

    // ---- per-call overrides, because several formats mix both orders in one structure --------

    public FixtureBuilder U16Le(ushort value) => Int(2, value, Endian.Little);

    public FixtureBuilder U16Be(ushort value) => Int(2, value, Endian.Big);

    public FixtureBuilder I16Le(short value) => Int(2, unchecked((ushort)value), Endian.Little);

    public FixtureBuilder I16Be(short value) => Int(2, unchecked((ushort)value), Endian.Big);

    public FixtureBuilder U32Le(uint value) => Int(4, value, Endian.Little);

    public FixtureBuilder U32Be(uint value) => Int(4, value, Endian.Big);

    public FixtureBuilder I32Le(int value) => Int(4, unchecked((uint)value), Endian.Little);

    public FixtureBuilder I32Be(int value) => Int(4, unchecked((uint)value), Endian.Big);

    public FixtureBuilder U64Le(ulong value) => Int(8, value, Endian.Little);

    public FixtureBuilder U64Be(ulong value) => Int(8, value, Endian.Big);

    public FixtureBuilder I64Le(long value) => Int(8, unchecked((ulong)value), Endian.Little);

    public FixtureBuilder I64Be(long value) => Int(8, unchecked((ulong)value), Endian.Big);

    /// <summary>An unnamed integer of any supported width in any order.</summary>
    public FixtureBuilder Int(int width, ulong bits, Endian endian)
    {
        if (!FieldCodec.IsSupportedWidth(width))
        {
            throw new FixtureException($"unsupported integer width {width}; use 1, 2, 4 or 8");
        }

        if (bits > FieldCodec.MaxUnsigned(width))
        {
            throw new FixtureException($"{FieldCodec.Hex((long)bits)} does not fit in {width} byte(s)");
        }

        Span<byte> span = stackalloc byte[width];
        FieldCodec.Write(span, width, endian, bits);
        Append(span);
        return this;
    }

    // ---- text -------------------------------------------------------------------------------

    /// <summary>
    /// 7-bit ASCII. A character above 0x7F is an error, not a substitution. With
    /// <paramref name="fixedWidth"/> the text is NUL-padded to that width and must fit in it.
    /// </summary>
    public FixtureBuilder Ascii(string text, int? fixedWidth = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] > 0x7F)
            {
                throw new FixtureException($"Ascii: character U+{(int)text[i]:X4} at index {i} is not ASCII; use Utf8, CodePage or Raw for it");
            }
        }

        return Text(Encoding.ASCII, text, fixedWidth);
    }

    /// <summary>UTF-16 little-endian code units, written verbatim — a lone surrogate is passed through, because awkward text is exactly what a text reader's fixtures need.</summary>
    public FixtureBuilder Utf16Le(string text, int? fixedWidth = null) => Utf16(text, Endian.Little, fixedWidth);

    public FixtureBuilder Utf16Be(string text, int? fixedWidth = null) => Utf16(text, Endian.Big, fixedWidth);

    /// <summary>UTF-8 without a byte-order mark. A lone surrogate is an error, since UTF-8 cannot encode one; use <see cref="Raw(ReadOnlySpan{byte})"/> for deliberately ill-formed bytes.</summary>
    public FixtureBuilder Utf8(string text, int? fixedWidth = null) => Text(Utf8Strict, text, fixedWidth);

    /// <summary>
    /// A legacy single- or multi-byte code page (1252, 932, 437 ...). A character the code page
    /// cannot represent is an error rather than a '?', because a fixture with a silent
    /// substitution tests the reader against text nobody wrote.
    /// </summary>
    public FixtureBuilder CodePage(string text, int codePage, int? fixedWidth = null)
    {
        if (Interlocked.Exchange(ref codePagesRegistered, 1) == 0)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }

        Encoding encoding;
        try
        {
            encoding = Encoding.GetEncoding(codePage, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException)
        {
            throw new FixtureException($"code page {codePage} is not available on this runtime: {e.Message}");
        }

        return Text(encoding, text, fixedWidth);
    }

    /// <summary>Text in any <see cref="Encoding"/>, optionally NUL-padded to a fixed byte width.</summary>
    public FixtureBuilder Text(Encoding encoding, string text, int? fixedWidth = null)
    {
        ArgumentNullException.ThrowIfNull(encoding);
        ArgumentNullException.ThrowIfNull(text);
        return Fixed(EncodeStrict(encoding, text), fixedWidth, text);
    }

    /// <summary>Text followed by the encoding's NUL — one byte for single-byte encodings, two for UTF-16.</summary>
    public FixtureBuilder NulTerminated(Encoding encoding, string text)
    {
        ArgumentNullException.ThrowIfNull(encoding);
        ArgumentNullException.ThrowIfNull(text);
        Append(EncodeStrict(encoding, text));
        Append(EncodeStrict(encoding, "\0"));
        return this;
    }

    /// <summary>
    /// A length prefix then the text. <paramref name="unit"/> says whether the prefix counts
    /// bytes or characters (UTF-16 code units, for UTF-16); the prefix is written in the
    /// builder's endianness unless <paramref name="prefixEndian"/> overrides it.
    /// </summary>
    public FixtureBuilder LengthPrefixed(Encoding encoding, string text, int prefixWidth, LengthUnit unit, Endian? prefixEndian = null)
    {
        ArgumentNullException.ThrowIfNull(encoding);
        ArgumentNullException.ThrowIfNull(text);
        byte[] bytes = EncodeStrict(encoding, text);
        int count = unit == LengthUnit.Bytes ? bytes.Length : encoding.GetCharCount(bytes);
        if (!FieldCodec.IsSupportedWidth(prefixWidth))
        {
            throw new FixtureException($"LengthPrefixed: unsupported prefix width {prefixWidth}; use 1, 2, 4 or 8");
        }

        if ((ulong)count > FieldCodec.MaxUnsigned(prefixWidth))
        {
            throw new FixtureException($"LengthPrefixed: a count of {count} {unit.ToString().ToLowerInvariant()} does not fit a {prefixWidth}-byte prefix");
        }

        Int(prefixWidth, (ulong)count, prefixEndian ?? Endian);
        Append(bytes);
        return this;
    }

    // ---- layout -----------------------------------------------------------------------------

    public FixtureBuilder Pad(int count) => Zeroes(count);

    /// <summary>Zero-fills up to <paramref name="offset"/>. Going backwards is an error: the builder is append-only.</summary>
    public FixtureBuilder PadTo(int offset)
    {
        if (offset < buffer.Count)
        {
            throw new FixtureException($"PadTo({FieldCodec.Hex(offset)}) but the buffer is already {FieldCodec.Hex(buffer.Count)} bytes long; the builder only appends");
        }

        return Zeroes(offset - buffer.Count);
    }

    /// <summary>Zero-fills to the next multiple of <paramref name="alignment"/>.</summary>
    public FixtureBuilder Align(int alignment)
    {
        if (alignment <= 0)
        {
            throw new FixtureException($"Align({alignment}): alignment must be positive");
        }

        int remainder = buffer.Count % alignment;
        return remainder == 0 ? this : Zeroes(alignment - remainder);
    }

    public FixtureBuilder Zeroes(int count) => Fill(0, count);

    public FixtureBuilder Fill(byte value, int count)
    {
        RequireNonNegative(count, "a fill count");
        for (int i = 0; i < count; i++)
        {
            buffer.Add(value);
        }

        return this;
    }

    public FixtureBuilder Raw(params byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        Append(bytes);
        return this;
    }

    public FixtureBuilder Raw(ReadOnlySpan<byte> bytes)
    {
        Append(bytes);
        return this;
    }

    // ---- derived values ---------------------------------------------------------------------

    /// <summary>
    /// Reserves a 4-byte slot and, at <see cref="Build"/>, writes the CRC-32 of the named region
    /// into it. The region may be written after this call and may contain the slot, which is
    /// taken as zero while computing. The slot is recorded as field <paramref name="fieldName"/>
    /// (default <c>region.crc32</c>) and as a checksum, which is what <c>CorruptChecksum</c> needs.
    /// </summary>
    public FixtureBuilder Crc32(string region, string? fieldName = null, Endian? endian = null) =>
        Checksum(region, 4, ChecksumKind.Crc32, bytes => Checksums.Crc32(bytes), fieldName ?? region + ".crc32", endian);

    /// <summary>Byte-wise sum of the region, modulo the slot width.</summary>
    public FixtureBuilder Sum(string region, int width = 4, string? fieldName = null, Endian? endian = null) =>
        Checksum(region, width, ChecksumKind.Sum, bytes => Checksums.Sum(bytes, width), fieldName ?? region + ".sum", endian);

    /// <summary>XOR of the region's <paramref name="width"/>-byte words, read in the slot's endianness.</summary>
    public FixtureBuilder XorFold(string region, int width = 4, string? fieldName = null, Endian? endian = null)
    {
        Endian e = endian ?? Endian;
        return Checksum(region, width, ChecksumKind.XorFold, bytes => Checksums.XorFold(bytes, width, e), fieldName ?? region + ".xor", e);
    }

    /// <summary>A checksum slot filled by a caller-supplied function over the region's bytes.</summary>
    public FixtureBuilder Checksum(string region, int width, ChecksumKind kind, Func<byte[], ulong> compute, string fieldName, Endian? endian = null)
    {
        ArgumentNullException.ThrowIfNull(compute);
        RequireName(region, "checksum region");
        var slot = Reserve(fieldName, width, endian ?? Endian);
        slot.Checksum = new FixtureChecksum(fieldName, region, kind);
        slot.ComputeChecksum = bytes =>
        {
            ulong value = compute(bytes);
            if (value > FieldCodec.MaxUnsigned(width))
            {
                throw new FixtureException($"checksum '{fieldName}': {kind} over region '{region}' produced {FieldCodec.Hex((long)value)}, which does not fit {width} byte(s)");
            }

            return value;
        };
        return this;
    }

    // ---- internals --------------------------------------------------------------------------

    private FixtureBuilder Utf16(string text, Endian endian, int? fixedWidth)
    {
        ArgumentNullException.ThrowIfNull(text);
        var bytes = new byte[text.Length * 2];
        for (int i = 0; i < text.Length; i++)
        {
            FieldCodec.Write(bytes.AsSpan(2 * i, 2), 2, endian, text[i]);
        }

        return Fixed(bytes, fixedWidth, text);
    }

    private FixtureBuilder Fixed(byte[] bytes, int? fixedWidth, string text)
    {
        if (fixedWidth is int width)
        {
            RequireNonNegative(width, "a fixed width");
            if (bytes.Length > width)
            {
                throw new FixtureException($"text \"{text}\" encodes to {bytes.Length} bytes and does not fit a fixed width of {width}");
            }

            Append(bytes);
            Zeroes(width - bytes.Length);
            return this;
        }

        Append(bytes);
        return this;
    }

    private static byte[] EncodeStrict(Encoding encoding, string text)
    {
        try
        {
            return encoding.GetBytes(text);
        }
        catch (EncoderFallbackException e)
        {
            throw new FixtureException($"\"{text}\" cannot be encoded as {encoding.WebName}: {e.Message}");
        }
    }

    private void Append(ReadOnlySpan<byte> bytes)
    {
        foreach (byte b in bytes)
        {
            buffer.Add(b);
        }
    }

    // Exposed so tests and consumers can reach the strict encodings without re-declaring them.
    public static Encoding Utf16LittleEndian => Utf16LeStrict;

    public static Encoding Utf16BigEndian => Utf16BeStrict;

    public static Encoding Utf8NoBom => Utf8Strict;
}
