namespace ZeroBreach.Intel.Tests;

using Xunit;
using ZeroBreach.Intel;

public class StixFeedTests
{
    private static string Bundle(params string[] objects)
        => """{"type":"bundle","id":"bundle--1","objects":[""" + string.Join(",", objects) + "]}";

    private static string Indicator(string pattern, string extra = "")
        => "{\"type\":\"indicator\",\"id\":\"indicator--1\",\"pattern\":\"" + pattern + "\"" + extra + "}";

    [Fact]
    public void SupportedObjectPaths_ParseToTypedIndicators()
    {
        var json = Bundle(
            Indicator(@"[file:hashes.'SHA-256' = '" + TestData.Sha256A + "']"),
            Indicator(@"[file:hashes.MD5 = '" + TestData.Md5A + "']"),
            Indicator(@"[ipv4-addr:value = '10.1.2.3']"),
            Indicator(@"[ipv6-addr:value = '2001:db8::5']"),
            Indicator(@"[domain-name:value = 'evil.example.com']"),
            Indicator(@"[url:value = 'http://evil.example/p']"),
            Indicator(@"[email-addr:value = 'bad@evil.example']"),
            Indicator(@"[windows-registry-key:key = 'HKLM\\\\Software\\\\Bad']"),
            Indicator(@"[mutex:name = 'Global_BadMutex']"),
            Indicator(@"[file:name = 'evil.exe']"),
            Indicator(@"[directory:path = 'C:\\\\bad\\\\dir']"));

        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Empty(result.Rejections);

        var types = result.Indicators.Select(i => i.Type).ToArray();
        Assert.Equal(new[]
        {
            IndicatorType.Sha256, IndicatorType.Md5, IndicatorType.Ipv4, IndicatorType.Ipv6,
            IndicatorType.Domain, IndicatorType.Url, IndicatorType.EmailAddress,
            IndicatorType.RegistryKey, IndicatorType.Mutex, IndicatorType.Filename,
            IndicatorType.FilePath,
        }, types);
    }

    [Fact]
    public void OrJoinedComparisons_YieldOneIndicatorEach()
    {
        var json = Bundle(Indicator(
            @"[file:hashes.MD5 = '" + TestData.Md5A + @"' OR file:hashes.'SHA-256' = '" + TestData.Sha256A + "'] OR [domain-name:value = 'evil.example']"));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal(3, result.Indicators.Count);
    }

    [Theory]
    [InlineData(@"[file:name = 'a.exe' AND file:hashes.MD5 = 'dddddddddddddddddddddddddddddddd']", "AND")]
    [InlineData(@"[domain-name:value MATCHES 'evil.*']", "MATCHES")]
    [InlineData(@"[file:name = 'a.exe'] FOLLOWEDBY [file:name = 'b.exe']", "FOLLOWEDBY")]
    [InlineData(@"[network-traffic:dst_port = '443']", "network-traffic")]
    [InlineData(@"[domain-name:value != 'good.example']", "!=")]
    public void UnsupportedPatternConstructs_RejectedWithConstructNamed(string pattern, string expectedInReason)
    {
        var json = Bundle(Indicator(pattern.Replace(@"\", @"\\")));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));

        Assert.Empty(result.Indicators);
        var rej = Assert.Single(result.Rejections);
        Assert.Contains(expectedInReason, rej.Reason);
        // The reason must survive to the caller's per-feed counts too.
        var feed = Assert.Single(result.Feeds);
        Assert.Equal(1, feed.RejectionCountsByReason[rej.Reason]);
    }

    [Fact]
    public void MixedSupportedAndUnsupported_WholePatternRejected()
    {
        // One indicator object is one assertion; extracting half of it would fabricate
        // indicators the feed never asserted. Conservative call, documented in the handoff.
        var json = Bundle(Indicator(
            @"[domain-name:value = 'evil.example' OR x-custom:thing = 'v']"));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));
        Assert.Empty(result.Indicators);
        Assert.Single(result.Rejections);
    }

    [Fact]
    public void NonStixPatternType_RejectedWithTypeNamed()
    {
        var json = Bundle(Indicator(@"alert tcp any any", @",""pattern_type"":""snort"""));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));
        Assert.Empty(result.Indicators);
        Assert.Contains("snort", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void RevokedIndicator_RejectedNotUsed()
    {
        var json = Bundle(Indicator(@"[domain-name:value = 'evil.example']", @",""revoked"":true"));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));
        Assert.Empty(result.Indicators);
        Assert.Contains("revoked", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void NonIndicatorObjects_SkippedWithoutRejection()
    {
        var json = Bundle(
            """{"type":"malware","id":"malware--1","name":"bad"}""",
            Indicator(@"[domain-name:value = 'evil.example']"));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));
        Assert.Single(result.Indicators);
        Assert.Empty(result.Rejections);
    }

    [Fact]
    public void ConfidenceLabelsAndExpiry_Preserved()
    {
        var json = Bundle(Indicator(
            @"[domain-name:value = 'evil.example']",
            @",""name"":""Campaign X"",""labels"":[""malicious-activity""],""confidence"":85,""valid_until"":""2020-01-01T00:00:00Z"""));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));

        var ind = Assert.Single(result.Indicators);
        Assert.Equal(85, ind.Confidence);
        Assert.Equal("Campaign X [malicious-activity]", ind.Label);
        // Already expired — kept, with expiry surfaced. The host decides (brief open question).
        Assert.Equal(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), ind.Expiry);
    }

    [Fact]
    public void UnparseableValidUntil_RejectsLoudly_RatherThanSheddingExpiry()
    {
        var json = Bundle(Indicator(
            @"[domain-name:value = 'evil.example']", @",""valid_until"":""not-a-date"""));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));
        Assert.Empty(result.Indicators);
        Assert.Contains("valid_until", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void MalformedJson_FailsWithPosition_AndNoPartialResults()
    {
        var json = "{\"type\":\"bundle\",\n\"objects\": [ %%% ]}";
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, json));

        Assert.Equal(OperationState.Failed, result.State);
        var feed = Assert.Single(result.Feeds);
        Assert.Equal(OperationState.Failed, feed.State);
        Assert.Contains("line 2", feed.Message);
        Assert.Contains("column", feed.Message);
        Assert.Empty(result.Indicators);
    }

    [Fact]
    public void MissingObjectsArray_Fails_NotAnEmptyCleanFeed()
    {
        var result = TestData.Ingest(TestData.Feed(FeedFormat.Stix2Json, """{"type":"bundle"}"""));
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("objects", result.Reason);
    }
}
