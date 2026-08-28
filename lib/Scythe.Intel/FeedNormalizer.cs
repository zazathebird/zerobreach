namespace Scythe.Intel;

using System.Diagnostics;
using System.Text;

/// <summary>
/// The public entry point: normalises a batch of feeds into one flat, validated, deduplicated,
/// typed indicator list plus a full rejection report (task brief; BLUEPRINT §10).
///
/// Per candidate, in order: trim → defang restoration (before validation, recorded on the
/// indicator) → type resolution (inference for plain text, IP family, filename-vs-path) →
/// validation → case-insensitive dedup preserving first-seen source → batch cap.
///
/// Nothing is silently dropped: every candidate that does not become an indicator is either a
/// listed rejection with a reason, a counted duplicate, or a counted truncation — and the
/// latter forces <see cref="OperationState.Incomplete"/>, never a quiet Ok.
/// </summary>
public static class FeedNormalizer
{
    public static IngestResult Ingest(IReadOnlyList<FeedSource> feeds, IngestBudget? budget = null)
    {
        budget ??= IngestBudget.Default;
        var stopwatch = Stopwatch.StartNew();

        var indicators = new List<Indicator>();
        var rejections = new List<RejectedIndicator>();
        var feedResults = new List<FeedResult>();
        // Dedup key: (type, lowercased normalised value). Lowercasing on top of normalisation
        // covers the types whose canonical form preserves case (file paths, mutexes, registry
        // keys) — the brief requires dedup to be case-insensitive across the whole set.
        var seen = new HashSet<(IndicatorType, string)>();

        var deadlineHit = false;
        var totalTruncated = 0;

        foreach (var feed in feeds)
        {
            if (deadlineHit || stopwatch.Elapsed > budget.Deadline)
            {
                deadlineHit = true;
                feedResults.Add(new FeedResult(feed.Id, feed.Name, OperationState.Incomplete,
                    "not processed: batch deadline exceeded", 0, 0, 0, 0, EmptyCounts));
                continue;
            }

            var inputBytes = (long)Encoding.UTF8.GetByteCount(feed.Content);
            if (inputBytes > budget.MaxInputBytes)
            {
                // Refused outright rather than parsed truncated: half a document parses as a
                // smaller, valid-looking feed, which is the silent failure this module bans.
                feedResults.Add(new FeedResult(feed.Id, feed.Name, OperationState.Incomplete,
                    $"input is {inputBytes} bytes, over the {budget.MaxInputBytes} byte budget; feed not parsed",
                    0, 0, 0, 0, EmptyCounts));
                continue;
            }

            var read = feed.Format switch
            {
                FeedFormat.Stix2Json => StixReader.Read(feed.Content),
                FeedFormat.MispJson => MispReader.Read(feed.Content),
                FeedFormat.OpenIocXml => OpenIocReader.Read(feed.Content, budget),
                FeedFormat.PlainText => PlainTextReader.Read(feed.Content),
                _ => FeedReadResult.Fail($"unknown feed format {feed.Format}"),
            };

            if (read.State == OperationState.Failed)
            {
                // A malformed document contributes nothing — no partial results — but the
                // batch still processes the other feeds.
                feedResults.Add(new FeedResult(feed.Id, feed.Name, OperationState.Failed,
                    read.Message, 0, 0, 0, 0, EmptyCounts));
                continue;
            }

            var accepted = 0;
            var duplicates = 0;
            var truncated = 0;
            var processed = 0;
            var countsByReason = new SortedDictionary<string, int>(StringComparer.Ordinal);

            foreach (var readerRejection in read.Rejections)
            {
                rejections.Add(new RejectedIndicator(readerRejection.RawValue, readerRejection.Reason, feed.Id));
                Bump(countsByReason, readerRejection.Reason);
            }

            foreach (var candidate in read.Candidates)
            {
                if (stopwatch.Elapsed > budget.Deadline)
                {
                    deadlineHit = true;
                    break;
                }
                processed++;

                var value = candidate.RawValue.Trim();
                var restored = Defanger.Restore(value, out var wasDefanged).Trim();
                if (restored.Length == 0)
                {
                    // "Never emit an indicator with an empty value" — and never skip one
                    // silently either.
                    rejections.Add(new RejectedIndicator(candidate.RawValue, "empty value", feed.Id));
                    Bump(countsByReason, "empty value");
                    continue;
                }

                if (!TryResolveType(candidate.Type, restored, out var type, out var typeReason))
                {
                    rejections.Add(new RejectedIndicator(candidate.RawValue, typeReason!, feed.Id));
                    Bump(countsByReason, typeReason!);
                    continue;
                }

                if (!IndicatorValidator.TryValidate(type, restored, out var normalized, out var reason))
                {
                    rejections.Add(new RejectedIndicator(candidate.RawValue, reason!, feed.Id));
                    Bump(countsByReason, reason!);
                    continue;
                }

                if (!seen.Add((type, normalized.ToLowerInvariant())))
                {
                    // First-seen attribution wins; later sightings are counted, not listed.
                    duplicates++;
                    continue;
                }

                if (indicators.Count >= budget.MaxIndicators)
                {
                    truncated++;
                    continue;
                }

                accepted++;
                indicators.Add(new Indicator(
                    type, normalized, candidate.RawValue, feed.Id, feed.Name, wasDefanged,
                    candidate.Confidence, candidate.Severity, candidate.Expiry, candidate.Label));
            }

            totalTruncated += truncated;

            OperationState feedState;
            string? feedMessage;
            if (read.State == OperationState.Incomplete)
            {
                // Structural reader budget (e.g. OpenIOC nesting) — keep the reader's message.
                feedState = OperationState.Incomplete;
                feedMessage = read.Message;
            }
            else if (deadlineHit)
            {
                feedState = OperationState.Incomplete;
                feedMessage = $"batch deadline exceeded after processing {processed} of {read.Candidates.Count} candidates";
            }
            else if (truncated > 0)
            {
                feedState = OperationState.Incomplete;
                feedMessage = $"batch indicator cap ({budget.MaxIndicators}) reached; {truncated} valid candidates truncated";
            }
            else
            {
                feedState = OperationState.Ok;
                feedMessage = null;
            }

            feedResults.Add(new FeedResult(feed.Id, feed.Name, feedState, feedMessage,
                accepted, countsByReason.Values.Sum(), duplicates, truncated, countsByReason));
        }

        var (state, stateReason) = AggregateState(feeds.Count, feedResults, totalTruncated, deadlineHit, budget);
        return new IngestResult(state, stateReason, indicators, rejections, feedResults, totalTruncated);
    }

    /// <summary>Maps the reader's candidate type to a final indicator type, resolving the
    /// hint types (see <see cref="CandidateType"/> docs).</summary>
    private static bool TryResolveType(
        CandidateType candidateType, string value, out IndicatorType type, out string? reason)
    {
        reason = null;
        switch (candidateType)
        {
            case CandidateType.Infer:
                return IndicatorValidator.TryInfer(value, out type, out reason);
            case CandidateType.IpAny:
                return IndicatorValidator.TryResolveIpFamily(value, out type, out reason);
            case CandidateType.FilenameOrPath:
                type = value.IndexOfAny(PathSeparators) >= 0 ? IndicatorType.FilePath : IndicatorType.Filename;
                return true;
            default:
                // The first twelve CandidateType entries map 1:1 onto IndicatorType by design
                // (see Candidate.cs); this cast is that mapping.
                type = (IndicatorType)candidateType;
                return true;
        }
    }

    private static (OperationState State, string? Reason) AggregateState(
        int feedCount, List<FeedResult> feedResults, int totalTruncated, bool deadlineHit, IngestBudget budget)
    {
        if (feedCount == 0)
            return (OperationState.Ok, null);

        var failed = feedResults.Count(f => f.State == OperationState.Failed);
        var incomplete = feedResults.Count(f => f.State == OperationState.Incomplete);

        if (failed == feedCount)
        {
            // Every feed malformed: the batch as a whole failed. A single-feed batch keeps the
            // feed's own positioned message so the caller need not dig for it.
            return (OperationState.Failed, feedCount == 1
                ? feedResults[0].Message
                : $"all {feedCount} feeds failed to parse; first: {feedResults.First(f => f.State == OperationState.Failed).Message}");
        }

        if (deadlineHit)
            return (OperationState.Incomplete, $"batch deadline ({budget.Deadline.TotalMilliseconds:0} ms) exceeded");
        if (totalTruncated > 0)
            return (OperationState.Incomplete,
                $"batch indicator cap ({budget.MaxIndicators}) reached; {totalTruncated} valid candidates truncated");
        if (failed > 0)
            return (OperationState.Incomplete, $"{failed} of {feedCount} feeds failed to parse");
        if (incomplete > 0)
            return (OperationState.Incomplete, $"{incomplete} of {feedCount} feeds incomplete");

        return (OperationState.Ok, null);
    }

    private static void Bump(SortedDictionary<string, int> counts, string reason)
    {
        counts[reason] = counts.TryGetValue(reason, out var n) ? n + 1 : 1;
    }

    private static readonly char[] PathSeparators = { '/', '\\' };

    private static readonly IReadOnlyDictionary<string, int> EmptyCounts =
        new SortedDictionary<string, int>(StringComparer.Ordinal);
}
