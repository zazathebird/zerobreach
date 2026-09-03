using System.Buffers.Binary;
using System.Text;

namespace Scythe.ShellItems;

/// <summary>How the bytes of a <see cref="LinkString"/> were interpreted.</summary>
public enum LinkStringEncoding
{
    /// <summary>UTF-16LE, decoded code unit by code unit. Unpaired surrogates are kept as they are.</summary>
    Utf16LittleEndian,

    /// <summary>
    /// The code page of the machine that wrote the link, which the file does not record. Decoded
    /// as Latin-1 — a total, lossless byte-to-char mapping — so the raw bytes always round-trip.
    /// </summary>
    SystemCodePage,
}

/// <summary>
/// A string read out of a link, kept both decoded and as the exact bytes it came from. The
/// decoded form may legitimately contain <c>U+0000</c> (StringData fields are counted, not
/// terminated) and unpaired surrogates; nothing here normalises or substitutes.
/// </summary>
public sealed record LinkString
{
    private LinkString(string value, byte[] rawBytes, LinkStringEncoding encoding, bool ambiguousEncoding)
    {
        Value = value;
        RawBytes = rawBytes;
        Encoding = encoding;
        AmbiguousEncoding = ambiguousEncoding;
    }

    public string Value { get; }

    /// <summary>The bytes exactly as they appeared, excluding any terminator that was not part of the counted extent.</summary>
    public byte[] RawBytes { get; }

    public LinkStringEncoding Encoding { get; }

    /// <summary>
    /// True when the string came from the code-page branch and at least one byte exceeds 0x7F,
    /// so the Latin-1 reading of <see cref="Value"/> may differ from what the writing machine
    /// meant. The bytes in <see cref="RawBytes"/> are still exact.
    /// </summary>
    public bool AmbiguousEncoding { get; }

    public int Length => Value.Length;

    internal static LinkString FromUtf16(ReadOnlySpan<byte> bytes)
    {
        // Explicitly little-endian, code unit by code unit: Encoding.Unicode would replace an
        // unpaired surrogate with U+FFFD, and MemoryMarshal.Cast would follow the host's byte order.
        var chars = new char[bytes.Length / 2];
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = (char)BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(i * 2, 2));
        }

        return new LinkString(new string(chars), bytes.ToArray(), LinkStringEncoding.Utf16LittleEndian, ambiguousEncoding: false);
    }

    internal static LinkString FromCodePage(ReadOnlySpan<byte> bytes)
    {
        var ambiguous = false;
        foreach (var b in bytes)
        {
            if (b > 0x7F)
            {
                ambiguous = true;
                break;
            }
        }

        return new LinkString(System.Text.Encoding.Latin1.GetString(bytes), bytes.ToArray(), LinkStringEncoding.SystemCodePage, ambiguous);
    }

    internal static LinkString Empty(LinkStringEncoding encoding) =>
        new(string.Empty, [], encoding, ambiguousEncoding: false);
}
