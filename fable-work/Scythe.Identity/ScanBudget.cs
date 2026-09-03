namespace Scythe.Identity;

/// <summary>
/// The resource ceiling a caller imposes on one decode. Shape is fixed across the package
/// (reference/00_shared.md §3) so a caller composing several Scythe libraries does not have to
/// translate between spellings of the same idea.
/// </summary>
/// <remarks>
/// Three members bind here. <see cref="MaxInputBytes"/> caps every buffer and string handed in;
/// <see cref="MaxMatches"/> caps the total number of access-control entries collected across a
/// descriptor's two lists; <see cref="Deadline"/> is checked once per entry. Nothing in this
/// project nests, so <see cref="MaxNestingDepth"/> is carried rather than consulted — a caller
/// sets one budget per artifact and hands the same object to every reader.
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
