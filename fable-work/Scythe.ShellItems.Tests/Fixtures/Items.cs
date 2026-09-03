using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests.Fixtures;

/// <summary>Shell item builders (reference/04.3 "LinkTargetIDList").</summary>
internal static class Items
{
    internal static readonly Guid MyComputer = ShellLinkReader.MyComputerClassId;
    internal static readonly Guid NetworkPlaces = ShellLinkReader.NetworkPlacesClassId;
    internal static readonly Guid Desktop = new("B4BFCC3A-DB2C-424C-B029-7FE99A87C641");

    /// <summary>One item: a <c>uint16</c> size including itself, then the data.</summary>
    internal static byte[] Item(params byte[][] data)
    {
        var payload = Concat(data);
        return Concat(U16((ushort)(payload.Length + 2)), payload);
    }

    /// <summary>An item whose size field lies.</summary>
    internal static byte[] ItemWithSize(ushort size, params byte[][] data) => Concat(U16(size), Concat(data));

    internal static byte[] Root(Guid classId, byte sortIndex = 0x50) => Item([0x1F, sortIndex], Guid(classId));

    internal static byte[] Volume(string drive, byte classType = 0x2F) =>
        Item([classType], Fixed(Latin1Z(drive), 20));

    internal static byte[] Raw(byte classType, params byte[] data) => Item([classType], data);

    internal static byte[] FileEntry(
        string primaryName,
        bool directory,
        string? longName = null,
        ushort extensionVersion = 9,
        uint fileSize = 0,
        uint dosDateTime = 0,
        ushort attributes = 0,
        bool unicodeName = false,
        ulong fileReference = 0,
        byte[]? extraExtension = null)
    {
        var classType = (byte)(0x30 | (directory ? 0x01 : 0x02) | (unicodeName ? 0x04 : 0x00));
        var name = unicodeName ? Utf16Z(primaryName) : Latin1Z(primaryName);
        var head = Concat([classType, 0x00], U32(fileSize), U32(dosDateTime), U16(attributes), name);

        // Pad to a two-byte boundary measured from the item start (the size field is 2 bytes).
        if (((head.Length + 2) & 1) == 1)
        {
            head = Concat(head, [0]);
        }

        var extension = longName is null ? [] : Beef4(extensionVersion, longName, fileReference: fileReference);
        return Item(head, extension, extraExtension ?? []);
    }

    /// <summary>The <c>0xBEEF0004</c> block at a given version; the long name's offset follows the version.</summary>
    internal static byte[] Beef4(ushort version, string longName, uint creation = 0, uint access = 0, ulong fileReference = 0)
    {
        var fixedPart = Concat(U16(version), U32(0xBEEF0004), U32(creation), U32(access), U16(0x002E));
        if (version >= 7)
        {
            fixedPart = Concat(fixedPart, U16(0), U64(fileReference), U64(0));
        }

        if (version >= 3)
        {
            fixedPart = Concat(fixedPart, U16(0)); // long string size
        }

        if (version >= 9)
        {
            fixedPart = Concat(fixedPart, U32(0));
        }

        if (version >= 8)
        {
            fixedPart = Concat(fixedPart, U32(0));
        }

        var body = Concat(fixedPart, Utf16Z(longName), U16(0x0014)); // first extension block offset
        return Concat(U16((ushort)(body.Length + 2)), body);
    }

    /// <summary>An extension block with an arbitrary signature, kept raw by the reader.</summary>
    internal static byte[] Extension(uint signature, ushort version, byte[] payload)
    {
        var body = Concat(U16(version), U32(signature), payload);
        return Concat(U16((ushort)(body.Length + 2)), body);
    }

    internal static byte[] Network(string location, byte classType = 0x41, string? description = null, string? comments = null)
    {
        byte flags = 0;
        if (description is not null)
        {
            flags |= 0x80;
        }

        if (comments is not null)
        {
            flags |= 0x40;
        }

        return Item(
            [classType, 0x00, flags],
            Latin1Z(location),
            description is null ? [] : Latin1Z(description),
            comments is null ? [] : Latin1Z(comments));
    }

    /// <summary>A complete LinkTargetIDList: the size field, the items, the terminal ID.</summary>
    internal static byte[] IdList(params byte[][] items)
    {
        var body = Concat(Concat(items), U16(0));
        return Concat(U16((ushort)body.Length), body);
    }

    /// <summary>A list whose declared size is whatever the test says.</summary>
    internal static byte[] IdListWithSize(ushort size, bool terminal, params byte[][] items)
    {
        var body = terminal ? Concat(Concat(items), U16(0)) : Concat(items);
        return Concat(U16(size), body);
    }

    internal static byte[] OrdinaryLocalList() => IdList(
        Root(MyComputer),
        Volume("C:\\"),
        FileEntry("Users", directory: true, longName: "Users", attributes: 0x10),
        FileEntry("README~1.TXT", directory: false, longName: "readme.txt", fileSize: 1234));
}
