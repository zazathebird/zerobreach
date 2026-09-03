using System.Text;
using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

public sealed class BuilderTextTests
{
    [Fact]
    public void AsciiWritesOneByteACharacter()
    {
        var bytes = new FixtureBuilder(Endian.Little).Ascii("REGF").Build().ToArray();

        Assert.Equal(new byte[] { 0x52, 0x45, 0x47, 0x46 }, bytes);
    }

    [Fact]
    public void AsciiFixedWidthPadsWithNul()
    {
        var bytes = new FixtureBuilder(Endian.Little).Ascii("ab", 4).Build().ToArray();

        Assert.Equal(new byte[] { 0x61, 0x62, 0, 0 }, bytes);
    }

    [Fact]
    public void AsciiFixedWidthRefusesTextThatDoesNotFit()
    {
        var e = TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Ascii("abcde", 4));

        Assert.Contains("does not fit a fixed width of 4", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AsciiRefusesANonAsciiCharacterRatherThanSubstituting()
    {
        var e = TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Ascii("café"));

        Assert.Contains("U+00E9 at index 3", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Utf16LeAndBeWriteCodeUnitsInTheStatedOrder()
    {
        var le = new FixtureBuilder(Endian.Big).Utf16Le("A€").Build().ToArray();
        var be = new FixtureBuilder(Endian.Little).Utf16Be("A€").Build().ToArray();

        Assert.Equal(new byte[] { 0x41, 0x00, 0xAC, 0x20 }, le);
        Assert.Equal(new byte[] { 0x00, 0x41, 0x20, 0xAC }, be);
    }

    [Fact]
    public void Utf16PassesALoneSurrogateThroughVerbatim()
    {
        // Awkward text is what a text reader's fixtures exist to supply; Encoding.Unicode would
        // have replaced this with U+FFFD and the fixture would test a string nobody wrote.
        var bytes = new FixtureBuilder(Endian.Little).Utf16Le("\uD800x").Build().ToArray();

        Assert.Equal(new byte[] { 0x00, 0xD8, 0x78, 0x00 }, bytes);
    }

    [Fact]
    public void Utf16FixedWidthCountsBytesNotCharacters()
    {
        var bytes = new FixtureBuilder(Endian.Little).Utf16Le("ab", 6).Build().ToArray();

        Assert.Equal(new byte[] { 0x61, 0, 0x62, 0, 0, 0 }, bytes);
    }

    [Fact]
    public void Utf8WritesMultiByteSequencesWithoutABom()
    {
        var bytes = new FixtureBuilder(Endian.Little).Utf8("€").Build().ToArray();

        Assert.Equal(new byte[] { 0xE2, 0x82, 0xAC }, bytes);
    }

    [Fact]
    public void Utf8RefusesALoneSurrogate()
    {
        var e = TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Utf8("\uD800"));

        Assert.Contains("cannot be encoded as utf-8", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CodePage1252EncodesLatin1Characters()
    {
        var bytes = new FixtureBuilder(Endian.Little).CodePage("é€", 1252).Build().ToArray();

        Assert.Equal(new byte[] { 0xE9, 0x80 }, bytes);
    }

    [Fact]
    public void CodePage932EncodesADoubleByteCharacter()
    {
        var bytes = new FixtureBuilder(Endian.Little).CodePage("あ", 932).Build().ToArray();

        Assert.Equal(new byte[] { 0x82, 0xA0 }, bytes);
    }

    [Fact]
    public void CodePageRefusesAnUnmappableCharacterRatherThanWritingAQuestionMark()
    {
        var e = TestSupport.Throws(() => new FixtureBuilder(Endian.Little).CodePage("€", 437));

        Assert.Contains("cannot be encoded", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CodePageRefusesAnUnknownCodePage()
    {
        var e = TestSupport.Throws(() => new FixtureBuilder(Endian.Little).CodePage("a", 99999));

        Assert.Contains("99999", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LengthPrefixInBytesAndInCharactersDifferForUtf16()
    {
        var inBytes = new FixtureBuilder(Endian.Little).LengthPrefixed(FixtureBuilder.Utf16LittleEndian, "Software", 2, LengthUnit.Bytes).Build().ToArray();
        var inChars = new FixtureBuilder(Endian.Little).LengthPrefixed(FixtureBuilder.Utf16LittleEndian, "Software", 2, LengthUnit.Characters).Build().ToArray();

        Assert.Equal(new byte[] { 16, 0 }, inBytes[..2]);
        Assert.Equal(new byte[] { 8, 0 }, inChars[..2]);
        Assert.Equal(inBytes[2..], inChars[2..]);
        Assert.Equal(18, inBytes.Length);
    }

    [Fact]
    public void LengthPrefixInCharactersCountsUtf8CharactersNotBytes()
    {
        var bytes = new FixtureBuilder(Endian.Little).LengthPrefixed(FixtureBuilder.Utf8NoBom, "€", 1, LengthUnit.Characters).Build().ToArray();

        Assert.Equal(new byte[] { 1, 0xE2, 0x82, 0xAC }, bytes);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(8)]
    public void LengthPrefixHonoursEveryWidthInTheBuildersOrder(int width)
    {
        var bytes = new FixtureBuilder(Endian.Big).LengthPrefixed(Encoding.ASCII, "abc", width, LengthUnit.Bytes).Build().ToArray();

        Assert.Equal(width + 3, bytes.Length);
        Assert.Equal(3, bytes[width - 1]);
        Assert.All(bytes[..(width - 1)], b => Assert.Equal(0, b));
    }

    [Fact]
    public void LengthPrefixEndianCanBeOverriddenPerCall()
    {
        var bytes = new FixtureBuilder(Endian.Little).LengthPrefixed(Encoding.ASCII, "abc", 2, LengthUnit.Bytes, Endian.Big).Build().ToArray();

        Assert.Equal(new byte[] { 0, 3 }, bytes[..2]);
    }

    [Fact]
    public void LengthPrefixRefusesACountThatDoesNotFitThePrefix()
    {
        var e = TestSupport.Throws(() => new FixtureBuilder(Endian.Little).LengthPrefixed(Encoding.ASCII, new string('x', 256), 1, LengthUnit.Bytes));

        Assert.Contains("256 bytes does not fit a 1-byte prefix", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NulTerminatorIsTheEncodingsWidth()
    {
        var narrow = new FixtureBuilder(Endian.Little).NulTerminated(Encoding.ASCII, "a").Build().ToArray();
        var wide = new FixtureBuilder(Endian.Little).NulTerminated(FixtureBuilder.Utf16LittleEndian, "a").Build().ToArray();

        Assert.Equal(new byte[] { 0x61, 0 }, narrow);
        Assert.Equal(new byte[] { 0x61, 0, 0, 0 }, wide);
    }
}
