namespace ZeroBreach.Intel.Tests;

using Xunit;
using ZeroBreach.Intel;

/// <summary>Cross-feed behaviour: dedup, caps, batch state aggregation, determinism, and the
/// budget canaries. This is where the tri-state discipline is pinned.</summary>
public class PipelineTests
{
    // --- dedup ---------------------------------------------------------------------------

    [Fact]
    public void Dedup_IsCaseInsensitive_AcrossFormats_AndPreservesFirstSeenSource()
    {
        var f1 = TestData.Feed(FeedFormat.PlainText, TestData.Sha256A.ToUpperInvariant(), id: "first", name: "First Feed");
        var f2 = TestData.Feed(FeedFormat.Stix2Json,
            """{"type":"bundle","objects":[{"type":"indicator","pattern":"[file:hashes.'SHA-256' = '"""
            + TestData.Sha256A + """']"}]}""",
            id: "second", name: "Second Feed");

        var result = TestData.Ingest(f1, f2);

        var ind = Assert.Single(result.Indicators);
        Assert.Equal("first", ind.SourceFeedId);
        Assert.Equal("First Feed", ind.SourceFeedName);
        Assert.Equal(TestData.Sha256A, ind.Value); // canonical lowercase

        Assert.Equal(1, result.Feeds[0].AcceptedCount);
        Assert.Equal(0, result.Feeds[1].AcceptedCount);
        Assert.Equal(1, result.Feeds[1].DuplicateCount);
        Assert.Equal(OperationState.Ok, result.State); // a duplicate is not an error
    }

    [Fact]
    public void Dedup_DefangedAndCleanFormsOfSameValue_Collapse()
    {
        var result = TestData.IngestLines("hxxp://evil.example/x", "http://evil.example/x");
        Assert.Single(result.Indicators);
        Assert.Equal(1, result.Feeds[0].DuplicateCount);
    }

    [Fact]
    public void Dedup_IsCaseInsensitive_ForCasePreservingTypes()
    {
        // A file path keeps its case in the canonical value, so collapsing these two can only
        // come from the case-folded dedup key — not from value normalisation. (The mutation
        // check for the dedup key relies on this test; the hash/domain dedup tests pass even
        // with a case-sensitive key because their normalisation already lowercases.)
        var misp = """{"Event":{"Attribute":[{"type":"filename","value":"C:\\Bad\\Evil.exe"},{"type":"filename","value":"C:\\BAD\\EVIL.EXE"}]}}""";
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, misp));

        var ind = Assert.Single(result.Indicators);
        Assert.Equal(IndicatorType.FilePath, ind.Type);
        Assert.Equal(@"C:\Bad\Evil.exe", ind.Value); // first-seen casing wins
        Assert.Equal(1, Assert.Single(result.Feeds).DuplicateCount);
    }

    [Fact]
    public void SameValueDifferentType_IsNotADuplicate()
    {
        // The same string can legitimately be two indicators of different types.
        var misp = """{"Event":{"Attribute":[{"type":"filename","value":"evil.example"},{"type":"domain","value":"evil.example"}]}}""";
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, misp));
        Assert.Equal(2, result.Indicators.Count);
    }

    // --- cap / budget --------------------------------------------------------------------

    [Fact]
    public void CapHit_YieldsIncomplete_WithTruncationCounted_NeverOk()
    {
        var budget = IngestBudget.Default with { MaxIndicators = 2 };
        var result = TestData.Ingest(budget,
            TestData.Feed(FeedFormat.PlainText, "a.example\nb.example\nc.example\nd.example"));

        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.NotEqual(OperationState.Ok, result.State);
        Assert.Contains("cap", result.Reason);
        Assert.Equal(2, result.Indicators.Count);
        Assert.Equal(2, result.TruncatedCount);

        var feed = Assert.Single(result.Feeds);
        Assert.Equal(OperationState.Incomplete, feed.State);
        Assert.Equal(2, feed.TruncatedCount);
    }

    [Fact]
    public void CapHit_DuplicatesAndRejectionsStillCounted_NothingVanishes()
    {
        var budget = IngestBudget.Default with { MaxIndicators = 1 };
        var result = TestData.Ingest(budget,
            TestData.Feed(FeedFormat.PlainText, "a.example\nA.EXAMPLE\n%%%%\nb.example"));

        var feed = Assert.Single(result.Feeds);
        Assert.Equal(1, feed.AcceptedCount);
        Assert.Equal(1, feed.DuplicateCount);   // A.EXAMPLE
        Assert.Equal(1, feed.RejectedCount);    // %%%%
        Assert.Equal(1, feed.TruncatedCount);   // b.example
        Assert.Equal(OperationState.Incomplete, result.State);
    }

    [Fact]
    public void OversizedFeed_NotParsed_ReportedIncomplete()
    {
        var budget = IngestBudget.Default with { MaxInputBytes = 10 };
        var result = TestData.Ingest(budget,
            TestData.Feed(FeedFormat.PlainText, "evil.example.com\nmore.example.com"));

        Assert.Equal(OperationState.Incomplete, result.State);
        var feed = Assert.Single(result.Feeds);
        Assert.Equal(OperationState.Incomplete, feed.State);
        Assert.Contains("byte", feed.Message);
        Assert.Empty(result.Indicators);
    }

    [Fact]
    public void DeadlineCanary_ZeroDeadline_YieldsIncomplete_NeverSilentlyOk()
    {
        // The budget canary (BLUEPRINT §3): with no time at all, the batch must say
        // Incomplete with the reason — if deadline enforcement quietly disappears, this
        // test is the tripwire.
        // FromTicks(-1): a deadline already in the past, so the outcome cannot depend on how
        // fast the first stopwatch read happens.
        var budget = IngestBudget.Default with { Deadline = TimeSpan.FromTicks(-1) };
        var result = TestData.Ingest(budget, TestData.Feed(FeedFormat.PlainText, "evil.example"));

        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("deadline", result.Reason);
        var feed = Assert.Single(result.Feeds);
        Assert.Equal(OperationState.Incomplete, feed.State);
    }

    // --- rejection reporting -------------------------------------------------------------

    [Fact]
    public void EntirelyInvalidFeed_EmptySet_FullRejectionReport_NoException()
    {
        var result = TestData.IngestLines("%%%%", "1.2.3.999", "....", "!!");

        Assert.Empty(result.Indicators);
        Assert.Equal(4, result.Rejections.Count);
        var feed = Assert.Single(result.Feeds);
        Assert.Equal(0, feed.AcceptedCount);
        Assert.Equal(4, feed.RejectedCount);
        // "This feed gave us 4 and threw away 1,200" must be visible in counts by reason.
        Assert.Equal(4, feed.RejectionCountsByReason.Values.Sum());
    }

    [Fact]
    public void RejectionReasons_SurviveToCaller_WithFeedAttribution()
    {
        var result = TestData.Ingest(
            TestData.Feed(FeedFormat.PlainText, "%%%%", id: "feedA"),
            TestData.Feed(FeedFormat.PlainText, "ok.example", id: "feedB"));

        var rej = Assert.Single(result.Rejections);
        Assert.Equal("feedA", rej.SourceFeedId);
        Assert.Equal("%%%%", rej.RawValue);
        Assert.False(string.IsNullOrWhiteSpace(rej.Reason));

        var feedA = result.Feeds.Single(f => f.FeedId == "feedA");
        Assert.Equal(1, feedA.RejectionCountsByReason[rej.Reason]);
    }

    [Fact]
    public void EmptyValueAfterTrim_Rejected_NeverEmitted()
    {
        var misp = """{"Event":{"Attribute":[{"type":"domain","value":"   "}]}}""";
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, misp));
        Assert.Empty(result.Indicators);
        Assert.Contains("empty value", Assert.Single(result.Rejections).Reason);
    }

    // --- batch aggregation ---------------------------------------------------------------

    [Fact]
    public void EmptyBatch_IsOkAndEmpty()
    {
        var result = TestData.Ingest();
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Empty(result.Indicators);
        Assert.Empty(result.Feeds);
    }

    [Fact]
    public void OneFailedFeedAmongGood_BatchIncomplete_GoodFeedsStillProcessed()
    {
        var result = TestData.Ingest(
            TestData.Feed(FeedFormat.Stix2Json, "{ not json", id: "bad"),
            TestData.Feed(FeedFormat.PlainText, "ok.example", id: "good"));

        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("1 of 2 feeds failed", result.Reason);
        Assert.Single(result.Indicators);
        Assert.Equal(OperationState.Failed, result.Feeds.Single(f => f.FeedId == "bad").State);
        Assert.Equal(OperationState.Ok, result.Feeds.Single(f => f.FeedId == "good").State);
    }

    [Fact]
    public void AllFeedsFailed_BatchFailed_NotIncompleteAndNotOk()
    {
        var result = TestData.Ingest(
            TestData.Feed(FeedFormat.Stix2Json, "{ not json", id: "a"),
            TestData.Feed(FeedFormat.MispJson, "also not json", id: "b"));

        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("all 2 feeds failed", result.Reason);
        Assert.Empty(result.Indicators);
    }

    // --- metadata ------------------------------------------------------------------------

    [Fact]
    public void ExpiredIndicator_Kept_WithExpirySurfaced()
    {
        // Brief open question, resolved as documented: keep, the host decides.
        var json = """{"type":"bundle","objects":[{"type":"indicator","pattern":"[domain-name:value = 'evil.example']","valid_until":"2019-06-01T00:00:00Z"}]}""";
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));
        var ind = Assert.Single(result.Indicators);
        Assert.NotNull(ind.Expiry);
        Assert.True(ind.Expiry < DateTimeOffset.UtcNow);
    }

    // --- determinism ---------------------------------------------------------------------

    [Fact]
    public void SameInput_SameOutput_SameOrder()
    {
        var feeds = new[]
        {
            TestData.Feed(FeedFormat.PlainText, "z.example\na.example\n10.0.0.1\n%%%%", id: "p"),
            TestData.Feed(FeedFormat.MispJson,
                """{"Event":{"threat_level_id":"2","Attribute":[{"type":"sha256","value":""" + '"' + TestData.Sha256B + '"' + "}]}}", id: "m"),
            TestData.Feed(FeedFormat.OpenIocXml,
                """<ioc><definition><Indicator operator="OR"><IndicatorItem condition="is"><Context search="DnsEntryItem/Host"/><Content type="string">host.example</Content></IndicatorItem></Indicator></definition></ioc>""",
                id: "o"),
        };

        var r1 = FeedNormalizer.Ingest(feeds);
        var r2 = FeedNormalizer.Ingest(feeds);

        Assert.Equal(r1.State, r2.State);
        Assert.Equal(r1.Indicators, r2.Indicators);   // records: value equality, order included
        Assert.Equal(r1.Rejections, r2.Rejections);
        Assert.Equal(r1.Feeds.Select(f => (f.FeedId, f.State, f.AcceptedCount, f.RejectedCount)),
                     r2.Feeds.Select(f => (f.FeedId, f.State, f.AcceptedCount, f.RejectedCount)));

        // Output order is input order: feed order, then candidate order within the feed.
        Assert.Equal(new[] { "z.example", "a.example", "10.0.0.1", TestData.Sha256B, "host.example" },
            r1.Indicators.Select(i => i.Value).ToArray());
    }

    [Fact]
    public void RejectionCountsByReason_AreOrdinallySorted()
    {
        // Three distinct reasons: two scheme rejections (each names its scheme) plus
        // unclassifiable — enough keys for the ordering to be observable.
        var result = TestData.IngestLines("%%%%", "wss://y.example/b", "foo://x.example/a");
        var feed = Assert.Single(result.Feeds);
        Assert.Equal(3, feed.RejectionCountsByReason.Count);
        var keys = feed.RejectionCountsByReason.Keys.ToArray();
        Assert.Equal(keys.OrderBy(k => k, StringComparer.Ordinal).ToArray(), keys);
    }
}
