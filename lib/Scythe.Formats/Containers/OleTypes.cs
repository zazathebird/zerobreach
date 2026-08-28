namespace Scythe.Formats.Containers;

/// <summary>Object type of an OLE directory entry, from the raw type byte.</summary>
public enum OleEntryType
{
    /// <summary>Type byte 0 (unused slot) or a value this reader does not model (3, 4).</summary>
    Unknown = 0,

    /// <summary>Type byte 1 — a storage (directory-like node).</summary>
    Storage = 1,

    /// <summary>Type byte 2 — a stream (leaf carrying bytes).</summary>
    Stream = 2,

    /// <summary>Type byte 5 — the root storage; its "stream" is the mini-stream container.</summary>
    RootStorage = 5,
}

/// <summary>
/// One node of the OLE directory tree. Children are materialised in-order from the
/// red-black sibling tree, which makes enumeration order deterministic for a given file.
/// </summary>
public sealed record OleDirectoryEntryInfo
{
    /// <summary>Index of the 128-byte entry in the directory stream.</summary>
    public required int Index { get; init; }

    /// <summary>Entry name, UTF-16 as stored.</summary>
    public required string Name { get; init; }

    /// <summary>Slash-joined path from the root, e.g. <c>Macros/VBA/ThisDocument</c>. Empty for the root itself.</summary>
    public required string Path { get; init; }

    /// <summary>The raw type byte, preserved because unknown values are themselves a signal.</summary>
    public required byte RawType { get; init; }

    public required OleEntryType Type { get; init; }

    /// <summary>First sector of the stream (FAT or mini-FAT space depending on size), as declared.</summary>
    public required uint StartSector { get; init; }

    /// <summary>Declared stream size in bytes. For version 3 files only the low 32 bits are meaningful and the rest are masked off.</summary>
    public required ulong Size { get; init; }

    public required Guid Clsid { get; init; }

    /// <summary>Child nodes (storages only), in deterministic in-order tree order.</summary>
    public required IReadOnlyList<OleDirectoryEntryInfo> Children { get; init; }
}

/// <summary>
/// Parsed structure of one compound file: the directory tree plus the allocation tables
/// needed to read streams later. The raw bytes are not retained — pass them back to
/// <see cref="OleReader.ReadStream"/>.
/// </summary>
public sealed class OleFileInfo
{
    public required ushort MajorVersion { get; init; }

    public required int SectorSize { get; init; }

    public required int MiniSectorSize { get; init; }

    /// <summary>Streams smaller than this live in the mini stream (spec value 4096).</summary>
    public required uint MiniStreamCutoff { get; init; }

    public required OleDirectoryEntryInfo Root { get; init; }

    /// <summary>FAT: next-sector chain, indexed by sector id. (Not <c>required</c>: internal members of a public type cannot be.)</summary>
    internal uint[] Fat { get; init; } = Array.Empty<uint>();

    /// <summary>Mini-FAT: next-mini-sector chain, indexed by mini sector id.</summary>
    internal uint[] MiniFat { get; init; } = Array.Empty<uint>();

    /// <summary>The root storage's FAT chain — the sectors that hold the mini stream, in order.</summary>
    internal uint[] MiniStreamSectors { get; init; } = Array.Empty<uint>();
}

/// <summary>
/// Result of <see cref="OleReader.Read"/>. <c>Failed</c> — not a compound file, or its core
/// structures are corrupt (bad signature, cyclic FAT, root missing); offset says where.
/// <c>Incomplete</c> — structure readable but not fully: truncated sectors, caps hit,
/// dangling or cyclic directory references; reasons list each. Never collapsed into
/// <c>Ok</c>.
/// </summary>
public sealed record OleReadResult(
    OperationState State,
    string? Message,
    long? ErrorOffset,
    IReadOnlyList<string> IncompleteReasons,
    OleFileInfo? File)
{
    internal static OleReadResult Fail(string message, long? offset) =>
        new(OperationState.Failed, message, offset, Array.Empty<string>(), null);

    internal static OleReadResult IncompleteWithoutFile(string reason) =>
        new(OperationState.Incomplete, reason, null, new[] { reason }, null);

    internal static OleReadResult From(IReadOnlyList<string> reasons, OleFileInfo file) =>
        reasons.Count == 0
            ? new(OperationState.Ok, null, null, Array.Empty<string>(), file)
            : new(OperationState.Incomplete, string.Join("; ", reasons), null, reasons, file);
}

/// <summary>Result of <see cref="OleReader.ReadStream"/>: the stream's bytes, or why not.</summary>
public sealed record OleStreamDataResult(
    OperationState State,
    string? Reason,
    byte[]? Bytes)
{
    internal static OleStreamDataResult NotRead(OperationState state, string reason) =>
        new(state, reason, null);
}
