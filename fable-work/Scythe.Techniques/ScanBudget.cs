namespace Scythe.Techniques;

/// <summary>
/// The resource ceiling a caller imposes on one operation. Shape is fixed across the package
/// (reference/00_shared.md §3) so a caller composing several Scythe libraries does not have to
/// translate between spellings of the same idea.
/// </summary>
/// <remarks>
/// All four members bind in this project. <see cref="MaxInputBytes"/> caps the map file;
/// <see cref="MaxNestingDepth"/> caps the JSON depth the loader will follow;
/// <see cref="MaxMatches"/> caps the number of map entries and rules the loader accepts and the
/// number of findings one resolution run processes; <see cref="Deadline"/> is checked once per
/// entry, rule and finding.
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
