using Scythe.ShellItems.Tests.Fixtures;
using Xunit;
using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests;

/// <summary>The counted-string rule, exercised on the strings that break a null-scanning reader.</summary>
public class StringDataTests
{
    private static ShellLink ReadOk(LinkFixture fixture)
    {
        var result = ShellLinkReader.Read(fixture.Build());
        Assert.Equal(LinkResultState.Ok, result.State);
        return result.Value!;
    }

    [Fact]
    public void ArgumentsWithAnEmbeddedNullAreKeptWhole()
    {
        var arguments = "before\0after";
        var link = ReadOk(new LinkFixture { Arguments = arguments, IconLocation = "icon.dll" });

        Assert.Equal(arguments, link.Arguments!.Value);
        Assert.Equal(12, link.Arguments.Length);
        Assert.Equal(Utf16(arguments), link.Arguments.RawBytes);
        // The field after the null-bearing one is still found at the right offset.
        Assert.Equal("icon.dll", link.IconLocation!.Value);
    }

    [Fact]
    public void ArgumentsWithTabAndNewlineRoundTrip()
    {
        var arguments = "a\tb\r\nc";
        var link = ReadOk(new LinkFixture { Arguments = arguments });

        Assert.Equal(arguments, link.Arguments!.Value);
        Assert.Equal(Utf16(arguments), link.Arguments.RawBytes);
    }

    [Fact]
    public void ArgumentsWithALoneSurrogateAreKeptUnrepaired()
    {
        var arguments = "x\uD800y";
        var link = ReadOk(new LinkFixture { Arguments = arguments });

        Assert.Equal(3, link.Arguments!.Length);
        Assert.Equal(0xD800, link.Arguments.Value[1]);
        Assert.Equal(Utf16(arguments), link.Arguments.RawBytes);
        Assert.DoesNotContain('\uFFFD', link.Arguments.Value);
    }

    [Fact]
    public void ArgumentsWithAnAstralCharacterRoundTrip()
    {
        var arguments = "\U0001F600 grin";
        var link = ReadOk(new LinkFixture { Arguments = arguments });

        Assert.Equal(arguments, link.Arguments!.Value);
        Assert.Equal(arguments.Length, link.Arguments.Length);
        Assert.Equal(Utf16(arguments), link.Arguments.RawBytes);
    }

    [Fact]
    public void NonUnicodeHighBitArgumentsAreByteExactAndFlaggedAmbiguous()
    {
        var link = ReadOk(new LinkFixture { Unicode = false, Arguments = "caf\u00E9 \u00FF" });

        Assert.Equal(new byte[] { 0x63, 0x61, 0x66, 0xE9, 0x20, 0xFF }, link.Arguments!.RawBytes);
        Assert.Equal("caf\u00E9 \u00FF", link.Arguments.Value);
        Assert.True(link.Arguments.AmbiguousEncoding);
        Assert.Equal(LinkStringEncoding.SystemCodePage, link.Arguments.Encoding);
        Assert.DoesNotContain('\uFFFD', link.Arguments.Value);
    }

    [Fact]
    public void NonUnicodeAsciiArgumentsAreNotAmbiguous()
    {
        var link = ReadOk(new LinkFixture { Unicode = false, Arguments = "plain ascii" });
        Assert.False(link.Arguments!.AmbiguousEncoding);
    }

    [Fact]
    public void NonUnicodeEmbeddedNullIsAlsoData()
    {
        var link = ReadOk(new LinkFixture { Unicode = false, Arguments = "a\0b", IconLocation = "i" });

        Assert.Equal(new byte[] { 0x61, 0x00, 0x62 }, link.Arguments!.RawBytes);
        Assert.Equal("i", link.IconLocation!.Value);
    }

    [Fact]
    public void IconLocationRoundTripsByteExact()
    {
        var icon = "%SystemRoot%\\sys\0tem32\\shell32.dll,\uDBFF";
        var link = ReadOk(new LinkFixture { IconLocation = icon });

        Assert.Equal(icon, link.IconLocation!.Value);
        Assert.Equal(Utf16(icon), link.IconLocation.RawBytes);
    }

    [Fact]
    public void StringsAreReadInFlagOrderAndAbsentOnesAreNull()
    {
        var link = ReadOk(new LinkFixture { RelativePath = "..\\r", IconLocation = "ic" });

        Assert.Null(link.Name);
        Assert.Equal("..\\r", link.RelativePath!.Value);
        Assert.Null(link.WorkingDirectory);
        Assert.Null(link.Arguments);
        Assert.Equal("ic", link.IconLocation!.Value);
    }

    [Fact]
    public void AnEmptyCountedStringIsEmptyNotAbsent()
    {
        var link = ReadOk(new LinkFixture { Arguments = string.Empty, IconLocation = "after" });

        Assert.NotNull(link.Arguments);
        Assert.Equal(0, link.Arguments.Length);
        Assert.Empty(link.Arguments.RawBytes);
        Assert.Equal("after", link.IconLocation!.Value);
    }

    [Fact]
    public void ACountedStringMadeOnlyOfNullsIsKept()
    {
        var link = ReadOk(new LinkFixture { Arguments = "\0\0\0" });
        Assert.Equal(3, link.Arguments!.Length);
        Assert.Equal(new byte[6], link.Arguments.RawBytes);
    }

    [Fact]
    public void IconEnvironmentBlockWhereCopiesDisagree_UnicodeWinsAndDisagreementIsReported()
    {
        var fixture = new LinkFixture { ExtraBlocks = [Blocks.IconEnvironment("%WINDIR%\\old.ico", "%WINDIR%\\new.ico")] };
        var block = Assert.Single(ReadOk(fixture).ExtraData.OfType<EnvironmentStringsBlock>());

        Assert.Equal(ExtraDataSignature.IconEnvironment, block.Signature);
        Assert.Equal("%WINDIR%\\new.ico", block.Target);
        Assert.Equal("%WINDIR%\\old.ico", block.AnsiTarget.Value);
        Assert.True(block.AnsiAndUnicodeDisagree);
        Assert.Equal("%WINDIR%\\old.ico".Length, block.AnsiTarget.RawBytes.Length);
    }
}
