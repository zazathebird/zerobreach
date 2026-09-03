namespace Scythe.ShellItems;

/// <summary>Which item layout the reader recognised from the class-type byte.</summary>
public enum ShellItemKind
{
    /// <summary>A class type this reader does not decode (URI, control panel, delegate, property view...). Kept raw.</summary>
    Unknown,
    RootFolder,
    Volume,
    FileEntry,
    NetworkLocation,
}

public enum FileEntryKind
{
    File,
    Directory,
}

/// <summary>How much of the target path the item-ID list yielded.</summary>
public enum PathCompleteness
{
    /// <summary>No items, or no item contributed a segment.</summary>
    None,

    /// <summary>Every item was decoded; the path is the whole list.</summary>
    Complete,

    /// <summary>
    /// At least one item was not decoded. <see cref="LinkTargetIdList.Path"/> is the contiguous
    /// prefix before the first such item, never a path with a hole in it.
    /// </summary>
    Partial,
}

/// <summary>The <c>0xBEEF0004</c> file-entry extension block, decoded per its version.</summary>
public sealed record FileEntryExtension(
    ushort Size,
    ushort Version,
    uint CreationDosDateTime,
    uint AccessDosDateTime,
    ulong? FileReference,
    string? LongName,
    ushort? FirstExtensionOffset,
    byte[] RawBytes);

/// <summary>An extension block on a file entry other than <c>0xBEEF0004</c>, kept raw.</summary>
public sealed record RawExtensionBlock(ushort Size, ushort Version, uint Signature, byte[] RawBytes);

/// <summary>
/// One item of an item-ID list. <see cref="RawData"/> is always present (the data bytes after the
/// size field); the typed members are set for the kinds the reader decodes.
/// </summary>
public sealed record ShellItem
{
    public required byte ClassType { get; init; }

    public required ShellItemKind Kind { get; init; }

    public required byte[] RawData { get; init; }

    /// <summary>
    /// True when the item's contribution to the reconstructed path is known — including a known
    /// contribution of nothing, as for the "My Computer" root. False for undecoded items and for
    /// root folders whose meaning as a path prefix this reader does not know.
    /// </summary>
    public required bool PathSegmentKnown { get; init; }

    /// <summary>The text this item adds to the path, or null when it adds nothing or is unknown.</summary>
    public string? PathSegment { get; init; }

    public byte? SortIndex { get; init; }

    public Guid? RootFolderClassId { get; init; }

    public string? DriveString { get; init; }

    public FileEntryKind? FileEntryKind { get; init; }

    public uint? FileSize { get; init; }

    /// <summary>Packed DOS date/time as stored; decoding it is Track Q's job.</summary>
    public uint? ModifiedDosDateTime { get; init; }

    public ushort? FileAttributes { get; init; }

    /// <summary>The null-terminated primary (short) name of a file entry.</summary>
    public string? PrimaryName { get; init; }

    public FileEntryExtension? Extension { get; init; }

    public IReadOnlyList<RawExtensionBlock> OtherExtensionBlocks { get; init; } = [];

    public byte? NetworkFlags { get; init; }

    public string? NetworkLocation { get; init; }

    public string? NetworkDescription { get; init; }

    public string? NetworkComments { get; init; }
}

/// <summary>The LinkTargetIDList section, or the list carried by a "Vista and above" block.</summary>
public sealed record LinkTargetIdList(
    int DeclaredSize,
    IReadOnlyList<ShellItem> Items,
    string? Path,
    PathCompleteness PathCompleteness,
    IReadOnlyList<string> Notes);
