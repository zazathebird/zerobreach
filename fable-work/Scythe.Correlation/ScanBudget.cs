namespace Scythe.Correlation;

/// <summary>
/// The resource ceiling a caller imposes on one chain assembly. Shape is fixed across the package
/// (reference/00_shared.md §3) so a caller composing several Scythe libraries does not have to
/// translate between spellings of the same idea.
/// </summary>
/// <remarks>
/// Three of the four members bind here. <see cref="MaxInputBytes"/> caps the total text handed to
/// the extractor (descriptions plus target strings, counted as UTF-16 code units × 2);
/// <see cref="MaxMatches"/> caps the number of entity mentions extracted across the whole run;
/// <see cref="Deadline"/> is checked between findings and between tokens. There is no nesting in
/// this format — findings do not contain findings — so <see cref="MaxNestingDepth"/> is carried
/// unused rather than dropped, because a caller sets one budget per artifact and hands the same
/// object to every reader.
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
