namespace Scythe.TestKit;

/// <summary>
/// The resource ceiling a caller imposes on one operation. Shape is fixed across the package
/// (reference/00_shared.md §3) so a caller composing several Scythe libraries does not have to
/// translate between spellings of the same idea.
/// </summary>
/// <remarks>
/// In this project the budget bounds the property harness: <see cref="Deadline"/> is the
/// wall-clock ceiling for one property run, <see cref="MaxInputBytes"/> caps the size of any
/// generated case, and <see cref="MaxMatches"/> caps both the number of cases and the number of
/// shrink candidates evaluated. <see cref="MaxNestingDepth"/> caps the depth of nested regions a
/// <see cref="FixtureBuilder"/> will record. All four are honoured; none is carried unused.
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
