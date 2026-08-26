namespace ZeroBreach.Intel.Tests;

using Xunit;
using ZeroBreach.Intel;

public class OpenIocFeedTests
{
    private static string Ioc(string body)
        => $"""<?xml version="1.0" encoding="utf-8"?><ioc xmlns="http://schemas.mandiant.com/2010/ioc"><definition>{body}</definition></ioc>""";

    private static string Item(string search, string value, string condition = "is")
        => $"""<IndicatorItem condition="{condition}"><Context document="X" search="{search}" type="mir"/><Content type="string">{value}</Content></IndicatorItem>""";

    [Fact]
    public void SupportedSearchPaths_ParseToTypedIndicators()
    {
        var xml = Ioc($"""
            <Indicator operator="OR">
            {Item("FileItem/Md5sum", TestData.Md5A)}
            {Item("FileItem/Sha256sum", TestData.Sha256A)}
            {Item("FileItem/FileName", "evil.exe")}
            {Item("FileItem/FullPath", @"C:\bad\evil.exe")}
            {Item("DnsEntryItem/Host", "evil.example.com")}
            {Item("UrlHistoryItem/URL", "http://evil.example/r")}
            {Item("PortItem/remoteIP", "10.4.4.4")}
            {Item("RegistryItem/KeyPath", @"HKLM\Software\Bad")}
            {Item("ProcessItem/Mutex", "Global_BadMutex")}
            {Item("Email/From", "bad@evil.example")}
            </Indicator>
            """);

        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Empty(result.Rejections);

        var types = result.Indicators.Select(i => i.Type).ToArray();
        Assert.Equal(new[]
        {
            IndicatorType.Md5, IndicatorType.Sha256, IndicatorType.Filename,
            IndicatorType.FilePath, IndicatorType.Domain, IndicatorType.Url,
            IndicatorType.Ipv4, IndicatorType.RegistryKey, IndicatorType.Mutex,
            IndicatorType.EmailAddress,
        }, types);

        // The Context search path travels as the label (Indicator.Label doc).
        Assert.Equal("FileItem/Md5sum", result.Indicators[0].Label);
    }

    [Fact]
    public void NonEqualityCondition_RejectedWithConditionNamed()
    {
        var xml = Ioc($"""<Indicator operator="OR">{Item("FileItem/FileName", "evil", condition: "contains")}</Indicator>""");
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));
        Assert.Empty(result.Indicators);
        Assert.Contains("'contains'", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void UnmappedSearchPath_RejectedWithSearchNamed()
    {
        var xml = Ioc($"""<Indicator operator="OR">{Item("ServiceItem/descriptiveName", "BadService")}</Indicator>""");
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));
        Assert.Empty(result.Indicators);
        Assert.Contains("ServiceItem/descriptiveName", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void MissingContent_Rejected()
    {
        var xml = Ioc("""<Indicator operator="OR"><IndicatorItem condition="is"><Context search="FileItem/Md5sum"/></IndicatorItem></Indicator>""");
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));
        Assert.Empty(result.Indicators);
        Assert.Contains("Content", Assert.Single(result.Rejections).Reason);
    }

    [Fact]
    public void NestedIndicators_WithinBudget_AllItemsRead()
    {
        var xml = Ioc($"""
            <Indicator operator="OR">{Item("FileItem/Md5sum", TestData.Md5A)}
            <Indicator operator="AND">{Item("DnsEntryItem/Host", "evil.example")}</Indicator>
            </Indicator>
            """);
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal(2, result.Indicators.Count);
    }

    [Fact]
    public void NestingBeyondBudgetDepth_YieldsIncomplete_NeverOk()
    {
        var depth = IngestBudget.DefaultMaxNestingDepth + 2;
        var open = string.Concat(Enumerable.Repeat("""<Indicator operator="OR">""", depth));
        var close = string.Concat(Enumerable.Repeat("</Indicator>", depth));
        var xml = Ioc(open + Item("FileItem/Md5sum", TestData.Md5A) + close);

        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));
        Assert.Equal(OperationState.Incomplete, result.State);
        var feed = Assert.Single(result.Feeds);
        Assert.Equal(OperationState.Incomplete, feed.State);
        Assert.Contains("nesting", feed.Message);
    }

    [Fact]
    public void MalformedXml_FailsWithPosition_AndNoPartialResults()
    {
        var xml = "<ioc>\n<definition><Indicator></definition></ioc>";
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));

        Assert.Equal(OperationState.Failed, result.State);
        var feed = Assert.Single(result.Feeds);
        Assert.Contains("line 2", feed.Message);
        Assert.Contains("column", feed.Message);
        Assert.Empty(result.Indicators);
    }

    [Fact]
    public void NonIocXml_Fails_NotAnEmptyCleanFeed()
    {
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, "<html><body/></html>"));
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("'html'", result.Reason);
    }

    // --- the XXE / DOCTYPE gate -----------------------------------------------------------

    [Fact]
    public void ExternalEntityPayload_IsRejectedAtTheDoctype_NotExpanded()
    {
        // Classic XXE: a DOCTYPE declaring an external entity, referenced from Content. With
        // DtdProcessing.Prohibit and no resolver this must die at the DOCTYPE — the file read
        // must never happen and nothing may parse out of the document. (The prohibition
        // exception carries no line info, so the message names the DTD instead.)
        var xml = """
            <?xml version="1.0"?>
            <!DOCTYPE ioc [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <ioc><definition><Indicator operator="OR">
            <IndicatorItem condition="is"><Context search="DnsEntryItem/Host"/><Content type="string">&xxe;</Content></IndicatorItem>
            </Indicator></definition></ioc>
            """;
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));

        Assert.Equal(OperationState.Failed, result.State);
        var feed = Assert.Single(result.Feeds);
        Assert.Equal(OperationState.Failed, feed.State);
        Assert.Contains("DTD", feed.Message); // rejected at the DOCTYPE itself
        Assert.Empty(result.Indicators);
        Assert.Empty(result.Rejections);
        // Belt and braces: nothing that could only come from /etc/passwd escaped anywhere.
        Assert.DoesNotContain("root:", feed.Message);
    }

    [Fact]
    public void InternalEntityPayload_IsRejected_ProvingNoExpansionPathExists()
    {
        // An internal (non-external) entity would not touch the file system, but accepting it
        // would prove DTD processing is on — the same switch XXE needs. It must be rejected,
        // and in particular "evil.example" must NOT come out the other side as an indicator.
        var xml = """
            <?xml version="1.0"?>
            <!DOCTYPE ioc [<!ENTITY e "evil.example">]>
            <ioc><definition><Indicator operator="OR">
            <IndicatorItem condition="is"><Context search="DnsEntryItem/Host"/><Content type="string">&e;</Content></IndicatorItem>
            </Indicator></definition></ioc>
            """;
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));

        Assert.Equal(OperationState.Failed, result.State);
        Assert.Empty(result.Indicators);
        Assert.DoesNotContain(result.Indicators, i => i.Value.Contains("evil.example"));
    }

    [Fact]
    public void BillionLaughsStyleDoctype_IsRejectedUpFront()
    {
        // Entity-expansion bomb: with DTDs prohibited it must fail at the DOCTYPE line,
        // not expand and not hang. This is this file's pathological-input canary.
        var xml = """
            <?xml version="1.0"?>
            <!DOCTYPE ioc [
              <!ENTITY a "aaaaaaaaaa">
              <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
              <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
            ]>
            <ioc><definition><Indicator operator="OR">
            <IndicatorItem condition="is"><Context search="DnsEntryItem/Host"/><Content type="string">&c;</Content></IndicatorItem>
            </Indicator></definition></ioc>
            """;
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Empty(result.Indicators);
    }

    [Fact]
    public void BuiltInEntities_StillWork_TheGateIsDtdsNotEntities()
    {
        // &amp; is predefined XML, not DTD-declared; prohibiting DTDs must not break it.
        var xml = Ioc($"""<Indicator operator="OR">{Item("UrlHistoryItem/URL", "http://evil.example/?a=1&amp;b=2")}</Indicator>""");
        var result = TestData.Ingest(TestData.Feed(FeedFormat.OpenIocXml, xml));
        var ind = Assert.Single(result.Indicators);
        Assert.Contains("a=1&b=2", ind.Value);
    }
}
