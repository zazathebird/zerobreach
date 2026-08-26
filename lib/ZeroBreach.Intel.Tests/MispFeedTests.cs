namespace ZeroBreach.Intel.Tests;

using Xunit;
using ZeroBreach.Intel;

public class MispFeedTests
{
    private static string Event(string attributes, string extraEventProps = "", string objects = "")
        => "{\"Event\":{\"info\":\"test\"" + extraEventProps + ",\"Attribute\":[" + attributes + "]" + objects + "}}";

    private static string Attr(string type, string value, string extra = "")
        => "{\"type\":\"" + type + "\",\"value\":\"" + value + "\"" + extra + "}";

    [Fact]
    public void SimpleAttributeTypes_MapToTypedIndicators()
    {
        var json = Event(string.Join(",",
            Attr("sha256", TestData.Sha256A),
            Attr("sha1", TestData.Sha1A),
            Attr("md5", TestData.Md5A),
            Attr("ip-dst", "10.9.8.7"),
            Attr("ip-src", "2001:db8::9"),
            Attr("domain", "evil.example.com"),
            Attr("hostname", "host.evil.example"),
            Attr("url", "http://evil.example/q"),
            Attr("filename", "evil.exe"),
            Attr("filename", "C:\\\\bad\\\\evil.exe"),
            Attr("regkey", "HKCU\\\\Software\\\\Bad"),
            Attr("mutex", "Global_BadMutex"),
            Attr("email-src", "bad@evil.example")));

        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Empty(result.Rejections);

        var types = result.Indicators.Select(i => i.Type).ToArray();
        Assert.Equal(new[]
        {
            IndicatorType.Sha256, IndicatorType.Sha1, IndicatorType.Md5,
            IndicatorType.Ipv4, IndicatorType.Ipv6,      // ip-* family resolved per value
            IndicatorType.Domain, IndicatorType.Domain, IndicatorType.Url,
            IndicatorType.Filename, IndicatorType.FilePath, // filename split on separators
            IndicatorType.RegistryKey, IndicatorType.Mutex, IndicatorType.EmailAddress,
        }, types);
    }

    [Fact]
    public void CompositeAttribute_SplitsIntoOneCandidatePerPart()
    {
        var json = Event(Attr("filename|sha256", "evil.exe|" + TestData.Sha256A));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));

        Assert.Equal(2, result.Indicators.Count);
        Assert.Equal(IndicatorType.Filename, result.Indicators[0].Type);
        Assert.Equal("evil.exe", result.Indicators[0].Value);
        Assert.Equal(IndicatorType.Sha256, result.Indicators[1].Type);
    }

    [Fact]
    public void CompositeIpPort_KeepsTheIp_PortIsNotAnIndicatorKind()
    {
        var json = Event(Attr("ip-dst|port", "10.1.1.1|4444"));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));
        var ind = Assert.Single(result.Indicators);
        Assert.Equal(IndicatorType.Ipv4, ind.Type);
        Assert.Equal("10.1.1.1", ind.Value);
    }

    [Fact]
    public void CompositePartCountMismatch_Rejected()
    {
        var json = Event(Attr("filename|sha256", "evil.exe"));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));
        Assert.Empty(result.Indicators);
        Assert.Contains("parts", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void ToIdsFalse_RejectedWithReason_NotSilentlyUsedOrDropped()
    {
        var json = Event(string.Join(",",
            Attr("domain", "keep.example", @",""to_ids"":true"),
            Attr("domain", "context-only.example", @",""to_ids"":false")));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));

        Assert.Single(result.Indicators);
        var rej = Assert.Single(result.Rejections);
        Assert.Equal("context-only.example", rej.RawValue);
        Assert.Contains("to_ids", rej.Reason);
    }

    [Fact]
    public void DeletedAttribute_Rejected()
    {
        var json = Event(Attr("domain", "gone.example", @",""deleted"":true"));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));
        Assert.Empty(result.Indicators);
        Assert.Contains("deleted", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void UnmappedAttributeType_RejectedWithTypeNamed()
    {
        var json = Event(Attr("yara", "rule x { condition: true }"));
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));
        Assert.Empty(result.Indicators);
        Assert.Contains("'yara'", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void ThreatLevel_BecomesSeverity_AndCategoryCommentBecomeLabel()
    {
        var json = Event(
            Attr("domain", "evil.example", @",""category"":""Network activity"",""comment"":""C2 host"""),
            extraEventProps: @",""threat_level_id"":""1""");
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));

        var ind = Assert.Single(result.Indicators);
        Assert.Equal("high", ind.Severity);
        Assert.Equal("Network activity | C2 host", ind.Label);
    }

    [Fact]
    public void ObjectAttributes_AreReadToo()
    {
        var json = Event(
            Attr("domain", "evil.example"),
            objects: @",""Object"":[{""name"":""file"",""Attribute"":[" + Attr("sha256", TestData.Sha256B) + "]}]");
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));

        Assert.Equal(2, result.Indicators.Count);
        Assert.Equal(IndicatorType.Sha256, result.Indicators[1].Type);
    }

    [Fact]
    public void AttributeMissingTypeOrValue_Rejected()
    {
        var json = Event("""{"category":"Network activity"}""");
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, json));
        Assert.Empty(result.Indicators);
        Assert.Contains("missing", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void MalformedJson_FailsWithPosition()
    {
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, """{"Event": {"Attribute": [}}"""));
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("line 1", result.Reason);
        Assert.Contains("column", result.Reason);
        Assert.Empty(result.Indicators);
    }

    [Fact]
    public void MissingEventObject_Fails_NotAnEmptyCleanFeed()
    {
        var result = TestData.Ingest(TestData.Feed(FeedFormat.MispJson, """{"response": []}"""));
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("Event", result.Reason);
    }
}
