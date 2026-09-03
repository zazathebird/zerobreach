namespace Scythe.ShellItems;

/// <summary>The fixed 76-byte header. Values are kept as the file holds them.</summary>
public sealed record ShellLinkHeader(
    uint HeaderSize,
    Guid ClassId,
    LinkFlags Flags,
    uint FileAttributes,
    FileTimeValue CreationTime,
    FileTimeValue AccessTime,
    FileTimeValue WriteTime,
    uint FileSize,
    int IconIndex,
    uint ShowCommand,
    ushort HotKey,
    byte[] RawBytes)
{
    /// <summary>True when the header's Unicode flag is set, which decides the width of every StringData field.</summary>
    public bool IsUnicode => (Flags & LinkFlags.IsUnicode) != 0;
}
