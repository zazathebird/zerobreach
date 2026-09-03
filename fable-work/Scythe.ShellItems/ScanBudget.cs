namespace Scythe.ShellItems;

/// <summary>
/// The resource ceiling a caller imposes on one read. Shape is fixed across the package
/// (reference/00_shared.md §3) so a caller composing several Scythe libraries does not have to
/// translate between spellings of the same idea.
/// </summary>
/// <remarks>
/// All four members bind here. <see cref="MaxInputBytes"/> caps the link or stream handed in;
/// <see cref="MaxMatches"/> caps item-ID entries, extra-data blocks and jump-list entries;
/// <see cref="MaxNestingDepth"/> caps a link inside a jump list inside a container, and the
/// item-ID list a "Vista and above" block nests inside a link; <see cref="Deadline"/> is checked
/// between every entry so an expired budget never emits a half-decoded one.
/// </remarks>
public sealed record ScanBudget(
    TimeSpan Deadline,
    long MaxInputBytes,
    int MaxMatches,
    int MaxNestingDepth)
{
    /// <summary>Wall-clock ceiling for one artifact. reference/00_shared.md §3.</summary>
    public static readonly TimeSpan DefaultDeadline = TimeSpan.FromSeconds(5);

    /// <summary>64 MiB.</summary>
    public const long DefaultMaxInputBytes = 64L * 1024 * 1024;

    public const int DefaultMaxMatches = 10_000;

    public const int DefaultMaxNestingDepth = 16;

    public static ScanBudget Default { get; } = new(
        DefaultDeadline,
        DefaultMaxInputBytes,
        DefaultMaxMatches,
        DefaultMaxNestingDepth);
}
