using Scythe.Text.Tests.Fixtures;
using Xunit;

namespace Scythe.Text.Tests;

public class OrdinaryDetectionTests
{
    private static DetectionResult Detect(byte[] bytes, DetectionHint? hint = null)
    {
        var result = TextDetector.Detect(bytes, hint);
        Assert.Equal(TextResultState.Ok, result.State);
        Assert.NotNull(result.Value);
        return result.Value!;
    }

    [Fact]
    public void Utf8WithMarkIsDecidedByTheMark()
    {
        var detected = Detect(TextFixtures.Concat(TextFixtures.Utf8Mark, TextFixtures.Utf8("héllo")));

        Assert.Equal(TextEncodingKind.Utf8, detected.Encoding);
        Assert.Equal(DetectionConfidence.FromMark, detected.Confidence);
        Assert.Equal(3, detected.MarkLength);
    }

    [Fact]
    public void MarklessUtf8WithAMultiByteSequenceIsUtf8WithHighConfidence()
    {
        var detected = Detect(TextFixtures.Utf8("naïve — but honest"));

        Assert.Equal(TextEncodingKind.Utf8, detected.Encoding);
        Assert.Equal(DetectionConfidence.High, detected.Confidence);
        Assert.Equal(0, detected.MarkLength);
    }

    [Fact]
    public void AllAsciiIsReportedAsAsciiWithHighConfidence()
    {
        var detected = Detect(TextFixtures.Ascii("plain seven-bit text, nothing else.\r\n"));

        Assert.Equal(TextEncodingKind.Ascii, detected.Encoding);
        Assert.Equal(DetectionConfidence.High, detected.Confidence);
    }

    [Theory]
    [InlineData(false, TextEncodingKind.Utf16LittleEndian)]
    [InlineData(true, TextEncodingKind.Utf16BigEndian)]
    public void Utf16WithAMarkIsDecidedByTheMark(bool bigEndian, TextEncodingKind expected)
    {
        var detected = Detect(TextFixtures.Utf16("marked text", bigEndian, withMark: true));

        Assert.Equal(expected, detected.Encoding);
        Assert.Equal(DetectionConfidence.FromMark, detected.Confidence);
        Assert.Equal(2, detected.MarkLength);
    }

    [Theory]
    [InlineData(false, TextEncodingKind.Utf16LittleEndian)]
    [InlineData(true, TextEncodingKind.Utf16BigEndian)]
    public void MarklessLatinScriptUtf16IsFoundByTheNullDistribution(bool bigEndian, TextEncodingKind expected)
    {
        var detected = Detect(TextFixtures.Utf16("The null bytes sit on one side.", bigEndian, withMark: false));

        Assert.Equal(expected, detected.Encoding);
        Assert.Equal(DetectionConfidence.High, detected.Confidence);
        Assert.Equal(0, detected.MarkLength);
    }

    // One buffer per supported page, holding that page's characteristic letters. Where two
    // pages genuinely map every fixture byte identically (windows-1252 and iso-8859-1 agree on
    // all of 0xA0–0xFF; cp437 and cp850 agree on the common accented range), byte content
    // cannot separate them: the assertion is that the page is at the top of the ranking, tied
    // at worst, with the tie visible in the reported confidence.
    [Theory]
    [InlineData(TextEncodingKind.Windows1252, "les détails déjà réglés très tôt", true)]
    [InlineData(TextEncodingKind.Windows1250, "žluťoučký kůň pěl ďábelské ódy", true)]
    [InlineData(TextEncodingKind.Windows1251, "она сказала „всё ещё“ и вышла", true)]
    [InlineData(TextEncodingKind.Iso8859Part1, "les détails déjà réglés", false)]
    [InlineData(TextEncodingKind.Iso8859Part2, "Źdźbło, Śliwka, Ťava, ślad", true)]
    [InlineData(TextEncodingKind.Iso8859Part5, "ПРИВЕТ АНДРЕЙ ГДЕ ВАГОН", true)]
    [InlineData(TextEncodingKind.Cp437, "schöne Wörter können blühen", true)]
    [InlineData(TextEncodingKind.Cp850, "møde på øen: Døgnet rundt", true)]
    public void CharacteristicSingleByteTextRanksItsPageAtTheTop(
        TextEncodingKind page, string text, bool expectedOutrightWinner)
    {
        var detected = Detect(TextFixtures.PageEncode(text, page));

        if (expectedOutrightWinner)
        {
            Assert.Equal(page, detected.Encoding);
        }
        else
        {
            // Tied at the top: the winner is the canonical-order tie-break, but the page's
            // score must equal the winner's and the closeness must be reported.
            var top = detected.SingleByteCandidates[0];
            var self = detected.SingleByteCandidates.Single(c => c.Encoding == page);
            Assert.Equal(top.Score, self.Score);
            Assert.Equal(DetectionConfidence.Ambiguous, detected.Confidence);
        }

        Assert.True(detected.SingleByteCandidates.Count == 8,
            "every candidate page is scored and reported, not a winner alone");
    }

    [Fact]
    public void AnEmptyBufferIsAsciiNotAFailure()
    {
        var detected = Detect([]);

        Assert.Equal(TextEncodingKind.Ascii, detected.Encoding);
        Assert.Equal(DetectionConfidence.High, detected.Confidence);
    }

    [Fact]
    public void ABufferHoldingOnlyAMarkIsRecognised()
    {
        var detected = Detect(TextFixtures.Utf8Mark);

        Assert.Equal(TextEncodingKind.Utf8, detected.Encoding);
        Assert.Equal(DetectionConfidence.FromMark, detected.Confidence);
        Assert.Equal(3, detected.MarkLength);
    }

    [Theory]
    [InlineData(new byte[] { 0x2B, 0x2F, 0x76, 0x38 }, TextEncodingKind.Utf7)]
    [InlineData(new byte[] { 0xDD, 0x73, 0x66, 0x73 }, TextEncodingKind.UtfEbcdic)]
    [InlineData(new byte[] { 0x84, 0x31, 0x95, 0x33 }, TextEncodingKind.Gb18030)]
    [InlineData(new byte[] { 0xF7, 0x64, 0x4C }, TextEncodingKind.Utf1)]
    [InlineData(new byte[] { 0x0E, 0xFE, 0xFF }, TextEncodingKind.Scsu)]
    [InlineData(new byte[] { 0xFB, 0xEE, 0x28 }, TextEncodingKind.Bocu1)]
    public void TheStatefulAndSevenBitMarksAreRecognisedAndNamed(byte[] mark, TextEncodingKind expected)
    {
        var detected = Detect(mark);

        Assert.Equal(expected, detected.Encoding);
        Assert.Equal(DetectionConfidence.FromMark, detected.Confidence);
        Assert.Equal(mark.Length, detected.MarkLength);
    }

    [Fact]
    public void OriginalBytesAreTheBufferAsReceivedMarkIncluded()
    {
        var bytes = TextFixtures.Concat(TextFixtures.Utf8Mark, TextFixtures.Utf8("payload"));

        var detected = Detect(bytes);

        Assert.Same(bytes, detected.OriginalBytes);
    }
}
