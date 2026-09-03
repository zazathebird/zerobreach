using Scythe.ShellItems.Tests.Fixtures;
using Xunit;
using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests;

public class ExtraDataTests
{
    private static LinkResult<ShellLink> Read(params byte[][] blocks) =>
        ShellLinkReader.Read(new LinkFixture { Arguments = "a", ExtraBlocks = blocks.ToList() }.Build());

    [Fact]
    public void UnrecognisedSignatureIsKeptAsSignatureAndBytes()
    {
        var block = Blocks.Raw(ExtraDataSignature.PropertyStore, [1, 2, 3, 4, 5, 6, 7, 8]);
        var result = Read(block);

        Assert.Equal(LinkResultState.Ok, result.State);
        var raw = Assert.IsType<RawExtraDataBlock>(Assert.Single(result.Value!.ExtraData));
        Assert.Equal(ExtraDataSignature.PropertyStore, raw.Signature);
        Assert.Equal(block, raw.RawBytes);
        Assert.Equal(16u, raw.Size);
        Assert.Null(raw.Note);
    }

    [Fact]
    public void KnownSignatureWithTheWrongSizeIsKeptRawWithANote()
    {
        var block = Blocks.WithSize(0x50, ExtraDataSignature.Tracker, new byte[0x48]);
        var raw = Assert.IsType<RawExtraDataBlock>(Assert.Single(Read(block).Value!.ExtraData));

        Assert.Equal(ExtraDataSignature.Tracker, raw.Signature);
        Assert.Contains("needs 0x60", raw.Note);
    }

    [Fact]
    public void BlocksAreReturnedInFileOrder()
    {
        var link = Read(Blocks.SpecialFolder(1, 2), Blocks.Tracker(), Blocks.KnownFolder(Blocks.DocumentsFolder, 0)).Value!;

        Assert.Equal(
            new[] { ExtraDataSignature.SpecialFolder, ExtraDataSignature.Tracker, ExtraDataSignature.KnownFolder },
            link.ExtraData.Select(b => b.Signature).ToArray());
    }

    [Fact]
    public void TerminalBlockOfSizeThreeEndsTheWalk()
    {
        var bytes = new LinkFixture { Arguments = "a", ExtraBlocks = [Blocks.Tracker()], Terminal = U32(3) }.Build();
        var result = ShellLinkReader.Read(Concat(bytes, new byte[20]));

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Single(result.Value!.ExtraData);
        Assert.Equal(bytes.Length, result.Value.Length);
    }

    [Fact]
    public void MinimumTerminalOnlyIsOk()
    {
        var result = ShellLinkReader.Read(new LinkFixture { Terminal = U32(0) }.Build());
        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Equal(80, result.Value!.Length);
    }

    [Fact]
    public void BlockSizeBelowEight_Incomplete()
    {
        var result = Read(Blocks.WithSize(5, ExtraDataSignature.Tracker, []));

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("size 5", result.Reason);
        Assert.Contains("cannot advance", result.Reason);
    }

    [Fact]
    public void BlockSizeExceedingTheFile_Incomplete()
    {
        var result = Read(Blocks.WithSize(0x1000, ExtraDataSignature.Tracker, new byte[8]));

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("declares 4096 bytes", result.Reason);
        Assert.NotNull(result.Value);
        Assert.Empty(result.Value.ExtraData);
    }

    [Fact]
    public void BlockSizeThatWouldStepBackwardsAsASignedInt_Incomplete()
    {
        var result = Read(Blocks.WithSize(0xFFFFFFFC, ExtraDataSignature.Tracker, new byte[8]));

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("4294967292", result.Reason);
    }

    [Fact]
    public void MissingTerminalBlock_Incomplete()
    {
        var result = ShellLinkReader.Read(new LinkFixture { Arguments = "a", Terminal = null }.Build());

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("terminal block is missing", result.Reason);
        Assert.Equal("a", result.Value!.Arguments!.Value);
    }

    [Fact]
    public void BlocksBeforeATruncationAreCarriedInThePartial()
    {
        var bytes = new LinkFixture { ExtraBlocks = [Blocks.Tracker(), Blocks.Tracker()] }.Build();
        var result = ShellLinkReader.Read(bytes.Take(bytes.Length - 10));

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Single(result.Value!.ExtraData);
    }

    [Fact]
    public void MalformedVistaListIsKeptRawWithANoteNotAFailure()
    {
        var broken = Blocks.Block(ExtraDataSignature.VistaAndAboveIdList, Concat(Items.ItemWithSize(1, [0x1F]), U16(0)));
        var result = Read(broken);

        Assert.Equal(LinkResultState.Ok, result.State);
        var raw = Assert.IsType<RawExtraDataBlock>(Assert.Single(result.Value!.ExtraData));
        Assert.Contains("nested item-ID list is malformed", raw.Note);
    }

    [Fact]
    public void VistaBlockTooSmallForAListIsKeptRaw()
    {
        var raw = Assert.IsType<RawExtraDataBlock>(Assert.Single(Read(Blocks.WithSize(8, ExtraDataSignature.VistaAndAboveIdList, [])).Value!.ExtraData));
        Assert.Contains("needs 0xA", raw.Note);
    }

    [Fact]
    public void EnvironmentBlockFieldsAreBoundedByTheirFixedExtents()
    {
        var ansi = new string('a', 260);
        var unicode = new string('u', 260);
        var block = Assert.IsType<EnvironmentStringsBlock>(Assert.Single(Read(Blocks.Environment(ansi, unicode)).Value!.ExtraData));

        Assert.Equal(260, block.AnsiTarget.Length);
        Assert.Equal(260, block.UnicodeTarget.Length);
        Assert.True(block.AnsiAndUnicodeDisagree);
    }
}
