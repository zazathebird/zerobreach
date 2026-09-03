using Scythe.Text.Tests.Fixtures;
using Xunit;

namespace Scythe.Text.Tests;

public class OrdinaryDecodeTests
{
    private static DecodedText Ok(TextResult<DecodedText> result)
    {
        Assert.Equal(TextResultState.Ok, result.State);
        Assert.NotNull(result.Value);
        return result.Value!;
    }

    [Fact]
    public void Utf8WithAMarkDecodesWithTheMarkSkippedButKeptInOriginalBytes()
    {
        var bytes = TextFixtures.Concat(TextFixtures.Utf8Mark, TextFixtures.Utf8("héllo"));

        var decoded = Ok(TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf8));

        Assert.Equal("héllo", decoded.Text);
        Assert.Equal(3, decoded.MarkLength);
        Assert.Empty(decoded.UndecodableRuns);
        Assert.Same(bytes, decoded.OriginalBytes);
    }

    [Fact]
    public void MarklessUtf8DecodesIncludingAstralCharacters()
    {
        var decoded = Ok(TextDecoder.DecodeReporting(TextFixtures.Utf8("a\U0001F600b"), TextEncodingKind.Utf8));

        Assert.Equal("a\U0001F600b", decoded.Text);
        Assert.Equal(0, decoded.MarkLength);
        Assert.Empty(decoded.UndecodableRuns);
    }

    [Theory]
    [InlineData(false, TextEncodingKind.Utf16LittleEndian)]
    [InlineData(true, TextEncodingKind.Utf16BigEndian)]
    public void Utf16DecodesInBothByteOrders(bool bigEndian, TextEncodingKind kind)
    {
        var bytes = TextFixtures.Utf16("Ω text\U0001F600", bigEndian, withMark: true);

        var decoded = Ok(TextDecoder.DecodeReporting(bytes, kind));

        Assert.Equal("Ω text\U0001F600", decoded.Text);
        Assert.Equal(2, decoded.MarkLength);
        Assert.Empty(decoded.UndecodableRuns);
        Assert.Empty(decoded.UnpairedSurrogates);
    }

    [Theory]
    [InlineData(false, TextEncodingKind.Utf32LittleEndian)]
    [InlineData(true, TextEncodingKind.Utf32BigEndian)]
    public void Utf32DecodesInBothByteOrders(bool bigEndian, TextEncodingKind kind)
    {
        var bytes = TextFixtures.Utf32([0x41, 0x1F600, 0x2013], bigEndian, withMark: true);

        var decoded = Ok(TextDecoder.DecodeReporting(bytes, kind));

        Assert.Equal("A\U0001F600–", decoded.Text);
        Assert.Equal(4, decoded.MarkLength);
        Assert.Empty(decoded.UndecodableRuns);
    }

    [Theory]
    [InlineData(TextEncodingKind.Windows1252, "les « détails » d’hier")]
    [InlineData(TextEncodingKind.Windows1250, "žluťoučký kůň")]
    [InlineData(TextEncodingKind.Windows1251, "всё ещё")]
    [InlineData(TextEncodingKind.Iso8859Part1, "déjà réglé")]
    [InlineData(TextEncodingKind.Iso8859Part2, "Źdźbło")]
    [InlineData(TextEncodingKind.Iso8859Part5, "привет")]
    [InlineData(TextEncodingKind.Cp437, "müde Grüße ±α")]
    [InlineData(TextEncodingKind.Cp850, "møde på øen ¾")]
    public void EachSingleBytePageRoundTripsItsCharacteristicText(TextEncodingKind page, string text)
    {
        var bytes = TextFixtures.PageEncode(text, page);

        var decoded = Ok(TextDecoder.DecodeReporting(bytes, page));

        Assert.Equal(text, decoded.Text);
        Assert.Empty(decoded.UndecodableRuns);
        Assert.Equal(0, decoded.SourceReplacementCharacterCount);
    }

    [Fact]
    public void AnEmptyBufferIsAValidOkWithEmptyText()
    {
        var decoded = Ok(TextDecoder.DecodeReporting([], TextEncodingKind.Utf8));

        Assert.Equal(string.Empty, decoded.Text);
        Assert.Empty(decoded.UndecodableRuns);

        var strict = Ok(TextDecoder.DecodeStrict([], TextEncodingKind.Utf8));
        Assert.Equal(string.Empty, strict.Text);
    }

    [Fact]
    public void ABufferHoldingOnlyAMarkDecodesToEmptyText()
    {
        var decoded = Ok(TextDecoder.DecodeReporting(TextFixtures.Utf16LeMark, TextEncodingKind.Utf16LittleEndian));

        Assert.Equal(string.Empty, decoded.Text);
        Assert.Equal(2, decoded.MarkLength);
        Assert.Empty(decoded.UndecodableRuns);
    }

    [Fact]
    public void StrictAndReportingAgreeOnCleanInput()
    {
        var bytes = TextFixtures.Utf8("perfectly ordinary — text");

        var strict = Ok(TextDecoder.DecodeStrict(bytes, TextEncodingKind.Utf8));
        var reporting = Ok(TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf8));

        Assert.Equal(reporting.Text, strict.Text);
        Assert.Empty(strict.UndecodableRuns);
        Assert.Empty(reporting.UndecodableRuns);
    }

    [Fact]
    public void ARecognisedButNotDecodedEncodingSaysSoRatherThanGuessing()
    {
        var bytes = TextFixtures.Concat([0x0E, 0xFE, 0xFF], TextFixtures.Ascii("scsu payload"));

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Scsu);

        Assert.Equal(TextResultState.Incomplete, result.State);
        Assert.Contains("recognised but not decoded", result.Reason);
        Assert.Same(bytes, result.Value!.OriginalBytes);
    }

    [Fact]
    public void AsciiDecodesAsItself()
    {
        var decoded = Ok(TextDecoder.DecodeStrict(TextFixtures.Ascii("plain"), TextEncodingKind.Ascii));

        Assert.Equal("plain", decoded.Text);
    }
}
