namespace ZeroBreach.Formats.Containers;

/// <summary>
/// Anomalies in an entry's declared path. Each of these is a known attack with a name
/// (zip-slip and friends), so each is a detection signal in its own right — the reader
/// surfaces them and never resolves such a path against anything.
/// </summary>
[Flags]
public enum PathAnomalies
{
    None = 0,

    /// <summary>The path contains a <c>..</c> segment (under either separator).</summary>
    ParentTraversal = 1,

    /// <summary>The path begins with <c>/</c> or <c>\</c>.</summary>
    AbsolutePath = 2,

    /// <summary>The path begins with a drive letter and colon (<c>C:...</c>).</summary>
    DriveQualified = 4,

    /// <summary>The name contains a NUL or other control byte — never legitimate in a file name.</summary>
    ContainsNulOrControl = 8,
}

/// <summary>
/// What an entry's local file header says about it. Kept separate from the central-directory
/// values on <see cref="ZipEntryInfo"/> because malformed archives make the two disagree
/// <em>deliberately</em>; the reader reports both and never merges them (task brief).
/// </summary>
public sealed record ZipLocalHeaderInfo
{
    /// <summary>Entry name as spelled in the local header (may differ from the central directory's).</summary>
    public required string Name { get; init; }

    public required ushort Flags { get; init; }

    public required ushort CompressionMethod { get; init; }

    public required uint Crc32 { get; init; }

    public required uint CompressedSize { get; init; }

    public required uint UncompressedSize { get; init; }

    /// <summary>Absolute offset of the entry's data (after the local header, name and extra field).</summary>
    public required long DataOffset { get; init; }

    /// <summary>
    /// General-purpose flag bit 3: sizes and CRC were written after the data in a data
    /// descriptor, so zeros in the local header are expected there, not a lie.
    /// </summary>
    public required bool HasDataDescriptor { get; init; }
}

/// <summary>
/// One central-directory entry, plus what its local header says, plus every disagreement and
/// anomaly found. Values are reported exactly as declared — nothing here is trusted, resolved
/// or normalised.
/// </summary>
public sealed record ZipEntryInfo
{
    /// <summary>Position in the central directory (also the deterministic output order).</summary>
    public required int Index { get; init; }

    /// <summary>Decoded entry name from the central directory: UTF-8 when flag bit 11 is set, CP437 otherwise.</summary>
    public required string Name { get; init; }

    /// <summary>True when general-purpose flag bit 11 declared the name UTF-8.</summary>
    public required bool NameIsUtf8 { get; init; }

    public required PathAnomalies PathAnomalies { get; init; }

    public required ushort Flags { get; init; }

    /// <summary>Flag bit 0, or AES method 99. Content is present but unreadable without a key.</summary>
    public required bool IsEncrypted { get; init; }

    public required ushort CompressionMethod { get; init; }

    /// <summary>CRC-32 as declared by the central directory.</summary>
    public required uint Crc32 { get; init; }

    /// <summary>Compressed size as declared by the central directory.</summary>
    public required uint CompressedSize { get; init; }

    /// <summary>Uncompressed size as declared by the central directory.</summary>
    public required uint UncompressedSize { get; init; }

    /// <summary>DOS timestamp decoded; null when the field does not encode a valid date-time (noted in <see cref="Anomalies"/>).</summary>
    public required DateTime? LastModified { get; init; }

    /// <summary>Local-header offset as declared by the central directory.</summary>
    public required long LocalHeaderOffset { get; init; }

    /// <summary>The local header at that offset, or null when unreadable (why is in <see cref="Anomalies"/>).</summary>
    public required ZipLocalHeaderInfo? LocalHeader { get; init; }

    /// <summary>
    /// Every field where the central directory and the local header disagree, one message per
    /// field, both values quoted. Empty means they agree.
    /// </summary>
    public required IReadOnlyList<string> Mismatches { get; init; }

    /// <summary>Non-path oddities: unreadable local header, invalid timestamp, suspicious declared ratio, truncated data.</summary>
    public required IReadOnlyList<string> Anomalies { get; init; }

    /// <summary>Convention only: an entry whose name ends in a separator carries no file content.</summary>
    public bool IsDirectory => Name.EndsWith('/') || Name.EndsWith('\\');
}

/// <summary>Successfully-enumerated archive structure. Presence here never implies the entries are benign.</summary>
public sealed record ZipArchiveInfo
{
    /// <summary>Entries in central-directory order — the deterministic output order.</summary>
    public required IReadOnlyList<ZipEntryInfo> Entries { get; init; }

    /// <summary>Archive-level anomalies: overlapping entry data, data overlapping the central directory, duplicate offsets.</summary>
    public required IReadOnlyList<string> ArchiveAnomalies { get; init; }

    public required long EndOfCentralDirectoryOffset { get; init; }

    public required long CentralDirectoryOffset { get; init; }

    public required long CentralDirectorySize { get; init; }

    /// <summary>Entry count declared by the end-of-central-directory record (may exceed <c>Entries.Count</c> when capped).</summary>
    public required int DeclaredEntryCount { get; init; }
}

/// <summary>
/// Result of <see cref="ZipReader.Read"/>. State rules (BLUEPRINT §2):
/// <c>Failed</c> — not a usable ZIP (no end-of-central-directory record, corrupt central
/// directory); <see cref="ErrorOffset"/> says where. <c>Incomplete</c> — structure readable
/// but not fully (truncated, over a cap, ZIP64/multi-disk variant); never collapsed into
/// <c>Ok</c>. <c>Ok</c> — every declared entry enumerated and validated.
/// </summary>
public sealed record ZipReadResult(
    OperationState State,
    string? Message,
    long? ErrorOffset,
    IReadOnlyList<string> IncompleteReasons,
    ZipArchiveInfo? Archive)
{
    internal static ZipReadResult Fail(string message, long? offset) =>
        new(OperationState.Failed, message, offset, Array.Empty<string>(), null);

    internal static ZipReadResult IncompleteWithoutArchive(string reason) =>
        new(OperationState.Incomplete, reason, null, new[] { reason }, null);

    internal static ZipReadResult From(IReadOnlyList<string> reasons, ZipArchiveInfo archive) =>
        reasons.Count == 0
            ? new(OperationState.Ok, null, null, Array.Empty<string>(), archive)
            : new(OperationState.Incomplete, string.Join("; ", reasons), null, reasons, archive);
}

/// <summary>
/// Result of <see cref="ZipReader.ReadEntry"/>. <c>Ok</c> means the bytes are the complete
/// decompressed content; CRC agreement is reported separately because a CRC mismatch is a
/// lying header — a signal about the metadata, not doubt about the recovered bytes.
/// <c>Incomplete</c> covers encrypted, unsupported method, truncation, and every guard trip,
/// each with its reason; <c>Failed</c> means the compressed data itself is corrupt.
/// </summary>
public sealed record ZipEntryDataResult(
    OperationState State,
    string? Reason,
    byte[]? Bytes,
    bool? CrcMatchesCentralDirectory,
    bool? CrcMatchesLocalHeader,
    IReadOnlyList<string> Notes)
{
    internal static ZipEntryDataResult NotRead(OperationState state, string reason) =>
        new(state, reason, null, null, null, Array.Empty<string>());
}
