namespace Scythe.Text;

/// <summary>
/// The resource ceiling a caller imposes on one operation. Shape is fixed across the package
/// (reference/00_shared.md §3) so a caller composing several Scythe libraries does not have to
/// translate between spellings of the same idea.
/// </summary>
/// <remarks>
/// Every pass in this project is a single linear scan over the input, so
/// <see cref="MaxInputBytes"/> bounds the work and <see cref="MaxMatches"/> caps the
/// undecodable-run list a hostile buffer could otherwise grow without limit. There is no
/// recursion and no expansion, so <see cref="Deadline"/> and <see cref="MaxNestingDepth"/> are
/// carried unused rather than dropped — a caller sets one budget for a whole artifact and hands
/// the same object to every reader.
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
