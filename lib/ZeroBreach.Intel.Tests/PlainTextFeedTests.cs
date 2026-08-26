namespace ZeroBreach.Intel.Tests;

using Xunit;
using ZeroBreach.Intel;

public class PlainTextFeedTests
{
    [Fact]
    public void CommentsAndBlankLines_Skipped_WithoutRejection()
    {
        var result = TestData.Ingest(TestData.Feed(FeedFormat.PlainText, """
            # header comment
            ; also a comment

            evil.example.com
              # indented comment
            10.0.0.5
            """));
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal(2, result.Indicators.Count);
        Assert.Empty(result.Rejections);
    }

    [Fact]
    public void MixedLines_EachInferredToItsType()
    {
        var result = TestData.IngestLines(
            TestData.Sha256A,
            "http://evil.example/x",
            @"HKLM\Software\Bad",
            "10.0.0.9",
            "2001:db8::7",
            "bad@evil.example",
            @"C:\bad\evil.exe",
            "evil.example.com");

        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal(new[]
        {
            IndicatorType.Sha256, IndicatorType.Url, IndicatorType.RegistryKey,
            IndicatorType.Ipv4, IndicatorType.Ipv6, IndicatorType.EmailAddress,
            IndicatorType.FilePath, IndicatorType.Domain,
        }, result.Indicators.Select(i => i.Type).ToArray());
    }

    [Fact]
    public void UnclassifiableLine_RejectedWithReason_OthersStillAccepted()
    {
        var result = TestData.IngestLines("evil.example", "%%%%");
        Assert.Single(result.Indicators);
        var rej = Assert.Single(result.Rejections);
        Assert.Equal("%%%%", rej.RawValue);
        Assert.Contains("unclassifiable", rej.Reason);
        // Ok, not Incomplete: everything was processed and everything is accounted for.
        Assert.Equal(OperationState.Ok, result.State);
    }

    [Fact]
    public void WindowsLineEndings_Handled()
    {
        var result = TestData.Ingest(TestData.Feed(FeedFormat.PlainText, "evil.example\r\n10.0.0.1\r\n"));
        Assert.Equal(2, result.Indicators.Count);
        Assert.Equal("evil.example", result.Indicators[0].Value);
    }
}
