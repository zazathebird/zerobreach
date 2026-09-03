namespace Scythe.ShellItems;

/// <summary>The 32-byte header of a <c>DestList</c> stream.</summary>
public sealed record DestListHeader(
    uint Version,
    uint EntryCount,
    uint PinnedEntryCount,
    float UnknownFloat,
    uint LastEntryNumber,
    uint Unknown1,
    ulong LastRevisionNumber);

/// <summary>One <c>DestList</c> entry paired with the link stream it names.</summary>
public sealed record DestListEntry(
    long Offset,
    ulong Checksum,
    Guid NewVolumeId,
    Guid NewObjectId,
    Guid BirthVolumeId,
    Guid BirthObjectId,
    LinkString MachineName,
    uint EntryNumber,
    FileTimeValue LastAccessTime,
    int PinStatus,
    uint? AccessCount,
    LinkString Path,
    string? LinkStreamName,
    LinkResult<ShellLink>? Link)
{
    /// <summary>The pin slot, or null when <see cref="PinStatus"/> is -1 (not pinned).</summary>
    public int? PinnedIndex => PinStatus >= 0 ? PinStatus : null;
}

public sealed record AutomaticDestinations(
    DestListHeader Header,
    IReadOnlyList<DestListEntry> Entries,
    IReadOnlyList<string> UnreferencedLinkStreams,
    IReadOnlyList<string> Notes);

public sealed record CustomDestinationEntry(long Offset, LinkResult<ShellLink> Link);

public sealed record CustomDestinations(
    uint Version,
    uint Unknown1,
    uint Unknown2,
    uint DeclaredEntryCount,
    IReadOnlyList<CustomDestinationEntry> Entries,
    long? FooterOffset,
    long SkippedBytes,
    IReadOnlyList<string> Notes);
