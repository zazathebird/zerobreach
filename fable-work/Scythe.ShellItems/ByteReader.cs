using System.Buffers.Binary;

namespace Scythe.ShellItems;

/// <summary>
/// The one bounds-checked reader every parse in this project goes through
/// (reference/00_shared.md §3, hazard 1). Every offset and length is validated against the
/// buffer before it is used to slice, and all arithmetic is in <see cref="long"/> so a lying
/// <c>uint32</c> size cannot wrap.
/// </summary>
internal readonly ref struct ByteReader
{
    private readonly ReadOnlySpan<byte> _bytes;

    public ByteReader(ReadOnlySpan<byte> bytes)
    {
        _bytes = bytes;
    }

    public int Length => _bytes.Length;

    public ReadOnlySpan<byte> Span => _bytes;

    public bool Has(long offset, long length) =>
        offset >= 0 && length >= 0 && offset <= _bytes.Length && length <= _bytes.Length - offset;

    public long Remaining(long offset) => offset < 0 || offset > _bytes.Length ? 0 : _bytes.Length - offset;

    public bool TryU8(long offset, out byte value)
    {
        if (!Has(offset, 1))
        {
            value = 0;
            return false;
        }

        value = _bytes[(int)offset];
        return true;
    }

    public bool TryU16(long offset, out ushort value)
    {
        if (!Has(offset, 2))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt16LittleEndian(_bytes.Slice((int)offset, 2));
        return true;
    }

    public bool TryU32(long offset, out uint value)
    {
        if (!Has(offset, 4))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice((int)offset, 4));
        return true;
    }

    public bool TryI32(long offset, out int value)
    {
        if (!Has(offset, 4))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadInt32LittleEndian(_bytes.Slice((int)offset, 4));
        return true;
    }

    public bool TryU64(long offset, out ulong value)
    {
        if (!Has(offset, 8))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt64LittleEndian(_bytes.Slice((int)offset, 8));
        return true;
    }

    /// <summary>Reads a GUID in its on-disk (mixed-endian) layout, which is what <see cref="Guid(ReadOnlySpan{byte})"/> expects.</summary>
    public bool TryGuid(long offset, out Guid value)
    {
        if (!Has(offset, 16))
        {
            value = Guid.Empty;
            return false;
        }

        value = new Guid(_bytes.Slice((int)offset, 16));
        return true;
    }

    public bool TrySlice(long offset, long length, out ReadOnlySpan<byte> slice)
    {
        if (!Has(offset, length))
        {
            slice = default;
            return false;
        }

        slice = _bytes.Slice((int)offset, (int)length);
        return true;
    }

    /// <summary>A reader over a sub-range the caller has already checked with <see cref="Has"/>.</summary>
    public ByteReader Sub(long offset, long length) => new(_bytes.Slice((int)offset, (int)length));

    /// <summary>Index of the first zero byte at or after <paramref name="offset"/>, or -1.</summary>
    public int FindNullByte(long offset)
    {
        if (offset < 0 || offset >= _bytes.Length)
        {
            return -1;
        }

        var index = _bytes[(int)offset..].IndexOf((byte)0);
        return index < 0 ? -1 : (int)offset + index;
    }

    /// <summary>Index of the first <c>00 00</c> pair on the two-byte grid starting at <paramref name="offset"/>, or -1.</summary>
    public int FindNullChar(long offset)
    {
        if (offset < 0)
        {
            return -1;
        }

        for (var i = offset; i + 2 <= _bytes.Length; i += 2)
        {
            if (_bytes[(int)i] == 0 && _bytes[(int)i + 1] == 0)
            {
                return (int)i;
            }
        }

        return -1;
    }
}
