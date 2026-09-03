namespace Scythe.Time;

/// <summary>
/// The resource ceiling a caller imposes on one decode. Shape is fixed across the package
/// (reference/00_shared.md §3) so a caller composing several Scythe libraries does not have to
/// translate between spellings of the same idea.
/// </summary>
/// <remarks>
/// Most of this project's entry points are single-value conversions that cannot run long or
/// allocate without bound, so only <see cref="MaxInputBytes"/> binds in practice — it caps the
/// decimal-string form, which is the one input here whose size a caller does not control.
/// The other three members are carried unused rather than dropped, because a caller sets one
/// budget for a whole artifact and hands the same object to every reader.
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
