namespace Scythe.Identity;

/// <summary>
/// The one bounds-checked reader every parse goes through (reference/00_shared.md §3, hazard 1).
/// Every accessor returns false rather than slicing when the field would run past the buffer,
/// so no offset arithmetic elsewhere can throw.
/// </summary>
internal static class ByteReader
{
    public static bool TryU8(ReadOnlySpan<byte> bytes, long offset, out byte value)
    {
        value = 0;
        if (offset < 0 || offset >= bytes.Length)
        {
            return false;
        }

        value = bytes[(int)offset];
        return true;
    }

    public static bool TryU16(ReadOnlySpan<byte> bytes, long offset, out ushort value)
    {
        value = 0;
        if (!Fits(bytes, offset, 2))
        {
            return false;
        }

        var at = (int)offset;
        value = (ushort)(bytes[at] | (bytes[at + 1] << 8));
        return true;
    }

    public static bool TryU32(ReadOnlySpan<byte> bytes, long offset, out uint value)
    {
        value = 0;
        if (!Fits(bytes, offset, 4))
        {
            return false;
        }

        var at = (int)offset;
        value = bytes[at]
            | ((uint)bytes[at + 1] << 8)
            | ((uint)bytes[at + 2] << 16)
            | ((uint)bytes[at + 3] << 24);
        return true;
    }

    /// <summary>
    /// The one big-endian field in the package: the identifier authority, 48 bits wide.
    /// </summary>
    public static bool TryAuthorityBigEndian48(ReadOnlySpan<byte> bytes, long offset, out ulong value)
    {
        value = 0;
        if (!Fits(bytes, offset, 6))
        {
            return false;
        }

        var at = (int)offset;
        for (var i = 0; i < 6; i++)
        {
            value = (value << 8) | bytes[at + i];
        }

        return true;
    }

    /// <summary>Sixteen bytes in the mixed-endian layout <see cref="Guid"/> expects on Windows.</summary>
    public static bool TryGuid(ReadOnlySpan<byte> bytes, long offset, out Guid value)
    {
        value = Guid.Empty;
        if (!Fits(bytes, offset, 16))
        {
            return false;
        }

        value = new Guid(bytes.Slice((int)offset, 16));
        return true;
    }

    public static bool Fits(ReadOnlySpan<byte> bytes, long offset, long length) =>
        offset >= 0 && length >= 0 && offset <= bytes.Length && length <= bytes.Length - offset;
}
