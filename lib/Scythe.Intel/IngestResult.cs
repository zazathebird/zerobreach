namespace Scythe.Intel;

/// <summary>One rejected raw value with the reason it was rejected. Nothing is ever silently
/// dropped: every candidate that does not become an <see cref="Indicator"/> appears here.</summary>
public sealed record RejectedIndicator(string RawValue, string Reason, string SourceFeedId);

/// <summary>
/// Per-feed outcome. A feed that failed to parse contributes zero indicators and zero
/// rejections (no partial results from a malformed document), but the batch still processes
/// the other feeds.
/// </summary>
/// <param name="FeedId">Feed id as supplied.</param>
/// <param name="FeedName">Feed name as supplied.</param>
/// <param name="State"><see cref="OperationState.Failed"/> for a malformed document,
/// <see cref="OperationState.Incomplete"/> when the batch cap truncated this feed or its
/// input exceeded the size budget, else <see cref="OperationState.Ok"/>.</param>
/// <param name="Message">Reason for a non-<see cref="OperationState.Ok"/> state, with
/// line/column where the format has one.</param>
/// <param name="AcceptedCount">Indicators accepted from this feed (after dedup).</param>
/// <param name="RejectedCount">Candidates rejected from this feed, each listed in
/// <see cref="IngestResult.Rejections"/>.</param>
/// <param name="DuplicateCount">Valid candidates skipped because an equal indicator (same
/// type, case-insensitively same value) was already accepted earlier in the batch.</param>
/// <param name="TruncatedCount">Valid candidates dropped because the batch indicator cap was
/// already reached. Nonzero here forces the feed and batch to <see cref="OperationState.Incomplete"/>.</param>
/// <param name="RejectionCountsByReason">Rejection counts grouped by reason, ordinal-sorted
/// by reason for deterministic enumeration.</param>
public sealed record FeedResult(
    string FeedId,
    string FeedName,
    OperationState State,
    string? Message,
    int AcceptedCount,
    int RejectedCount,
    int DuplicateCount,
    int TruncatedCount,
    IReadOnlyDictionary<string, int> RejectionCountsByReason);

/// <summary>
/// The batch result: the flat deduplicated indicator list, the full rejection report, and
/// per-feed outcomes.
/// Batch <paramref name="State"/> shape: <see cref="OperationState.Failed"/> only when every
/// feed in a non-empty batch failed to parse; <see cref="OperationState.Incomplete"/> when the
/// cap truncated output or at least one (but not every) feed failed or was incomplete;
/// <see cref="OperationState.Ok"/> otherwise. Per-feed states carry the detail either way.
/// </summary>
public sealed record IngestResult(
    OperationState State,
    string? Reason,
    IReadOnlyList<Indicator> Indicators,
    IReadOnlyList<RejectedIndicator> Rejections,
    IReadOnlyList<FeedResult> Feeds,
    int TruncatedCount);
