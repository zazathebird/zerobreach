namespace ZeroBreach.Intel;

/// <summary>
/// Resource budget for one ingest batch (BLUEPRINT §3). Feeds are third-party content and
/// must be treated as attacker-authored: a feed that hangs or floods the ingest is a denial
/// of service on the scan that consumes it.
/// </summary>
/// <param name="Deadline">Wall-clock ceiling for the whole batch. Exceeding it yields
/// <see cref="OperationState.Incomplete"/> with the reason — never a silent Ok.</param>
/// <param name="MaxInputBytes">Per-feed input ceiling (UTF-8 byte count of the content). A
/// feed over this is not parsed at all and is reported <see cref="OperationState.Incomplete"/>;
/// parsing a truncated document would risk quietly halving a feed.</param>
/// <param name="MaxIndicators">Cap on total accepted indicators across the batch. Valid
/// candidates past the cap are counted as truncated and force
/// <see cref="OperationState.Incomplete"/>.</param>
/// <param name="MaxNestingDepth">Structural nesting ceiling (OpenIOC Indicator nesting).</param>
public sealed record IngestBudget(
    TimeSpan Deadline,
    long MaxInputBytes,
    int MaxIndicators,
    int MaxNestingDepth)
{
    /// <summary>5 s, the whole-file default from BLUEPRINT §3.</summary>
    public static readonly TimeSpan DefaultDeadline = TimeSpan.FromSeconds(5);

    /// <summary>64 MiB (BLUEPRINT §3).</summary>
    public const long DefaultMaxInputBytes = 64L * 1024 * 1024;

    /// <summary>10 000 (BLUEPRINT §3 MaxMatches, applied here to accepted indicators).</summary>
    public const int DefaultMaxIndicators = 10_000;

    /// <summary>Depth 8 (BLUEPRINT §3).</summary>
    public const int DefaultMaxNestingDepth = 8;

    public static IngestBudget Default { get; } = new(
        DefaultDeadline, DefaultMaxInputBytes, DefaultMaxIndicators, DefaultMaxNestingDepth);
}
