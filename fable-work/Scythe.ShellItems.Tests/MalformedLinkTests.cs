using Scythe.ShellItems.Tests.Fixtures;
using Xunit;
using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests;

public class MalformedLinkTests
{
    [Fact]
    public void EmptyInput_Failed()
    {
        var result = ShellLinkReader.Read([]);
        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("empty", result.Reason);
    }

    [Fact]
    public void HeaderSizeNot0x4C_FailedAtOffsetZero()
    {
        var result = ShellLinkReader.Read(new LinkFixture { HeaderSizeField = 0x4D }.Build());

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("0x0000004D", result.Reason);
        Assert.Equal(0L, result.Position);
        Assert.Null(result.Value);
    }

    [Fact]
    public void WrongClassIdentifier_FailedAtOffsetFour()
    {
        var result = ShellLinkReader.Read(new LinkFixture { ClassId = new System.Guid("00021401-0000-0000-C000-000000000047") }.Build());

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("class identifier", result.Reason);
        Assert.Equal(4L, result.Position);
    }

    [Fact]
    public void TruncatedInsideTheHeader_Incomplete()
    {
        var bytes = LinkFixture.OrdinaryBytes();
        Assert.Equal(LinkResultState.Incomplete, ShellLinkReader.Read(bytes.Take(3)).State);
        Assert.Equal(LinkResultState.Incomplete, ShellLinkReader.Read(bytes.Take(19)).State);
        var result = ShellLinkReader.Read(bytes.Take(40));
        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("40 of 76", result.Reason);
        Assert.Null(result.Value);
    }

    [Fact]
    public void TruncatedRightAfterTheHeader_IncompleteWithHeaderAsPartial()
    {
        var result = ShellLinkReader.Read(LinkFixture.OrdinaryBytes().Take(76));

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.NotNull(result.Value);
        Assert.Equal(LinkFixture.CreationTicks, result.Value.Header.CreationTime.Ticks);
        Assert.Null(result.Value.TargetIdList);
    }

    [Fact]
    public void HeaderOnlyWithNoFlagsAndNoTerminal_Incomplete()
    {
        var result = ShellLinkReader.Read(new LinkFixture { Terminal = null }.Build());
        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Equal(76, result.Value!.Length);
    }

    [Fact]
    public void TruncatedMidString_IncompleteNamesTheField()
    {
        var fixture = new LinkFixture { Name = "n", Arguments = "some arguments" };
        var bytes = fixture.Build();
        var result = ShellLinkReader.Read(bytes.Take(fixture.StringDataOffset + 2 + 2 + 2 + 5));

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("COMMAND_LINE_ARGUMENTS", result.Reason);
        Assert.Contains("truncated mid-string", result.Reason);
        Assert.Equal("n", result.Value!.Name!.Value);
        Assert.Null(result.Value.Arguments);
    }

    [Fact]
    public void CountCharactersOf0xFFFFOnA200ByteFile_Incomplete()
    {
        var fixture = new LinkFixture { Arguments = "short" };
        var bytes = fixture.Build();
        var padded = Concat(bytes, new byte[200 - bytes.Length]);
        var result = ShellLinkReader.Read(padded.Patch(fixture.StringDataOffset, (ushort)0xFFFF));

        Assert.Equal(200, padded.Length);
        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("65535 characters (131070 bytes)", result.Reason);
    }

    [Fact]
    public void EveryTruncationOfTheOrdinaryLinkIsNotOkAndDoesNotThrow()
    {
        var bytes = LinkFixture.OrdinaryBytes();
        for (var length = 0; length < bytes.Length; length++)
        {
            var result = ShellLinkReader.Read(bytes.Take(length));
            Assert.NotEqual(LinkResultState.Ok, result.State);
            Assert.NotNull(result.Reason);
        }

        Assert.Equal(LinkResultState.Ok, ShellLinkReader.Read(bytes).State);
    }

    [Fact]
    public void EveryTruncationOfAUncLinkWithVistaBlockIsNotOkAndDoesNotThrow()
    {
        var bytes = new LinkFixture
        {
            IdList = Items.IdList(Items.Root(Items.NetworkPlaces), Items.Network("\\\\s\\t"), Items.FileEntry("a", directory: false, longName: "a")),
            LinkInfo = new LinkInfoFixture { HeaderSize = 0x24, Network = true, NetNameUnicode = "\\\\s\\t", UnicodeLabelSentinel = true }.Build(),
            Arguments = "x",
            ExtraBlocks = [Blocks.Vista(Items.Volume("C:\\")), Blocks.Environment("a", "b")],
        }.Build();

        for (var length = 0; length < bytes.Length; length++)
        {
            Assert.NotEqual(LinkResultState.Ok, ShellLinkReader.Read(bytes.Take(length)).State);
        }

        Assert.Equal(LinkResultState.Ok, ShellLinkReader.Read(bytes).State);
    }

    [Fact]
    public void FlippingEveryByteOfTheOrdinaryLinkNeverThrows()
    {
        var bytes = LinkFixture.OrdinaryBytes();
        var budget = ScanBudget.Default with { MaxMatches = 64 };
        for (var i = 0; i < bytes.Length; i++)
        {
            foreach (var value in new byte[] { 0x00, 0x01, 0x7F, 0xFF })
            {
                var mutated = bytes.Patch(i, value);
                var result = ShellLinkReader.Read(mutated, budget);
                Assert.True(result.State == LinkResultState.Ok || result.Reason is not null);
            }
        }
    }

    [Fact]
    public void ARandomisedByteSoupNeverThrows()
    {
        var random = new Random(20260902);
        var header = LinkFixture.OrdinaryBytes().Take(76);
        for (var round = 0; round < 500; round++)
        {
            var soup = new byte[random.Next(0, 400)];
            random.NextBytes(soup);
            var bytes = Concat(header.Patch(0x14, (uint)random.Next()), soup);
            var result = ShellLinkReader.Read(bytes);
            Assert.True(result.State == LinkResultState.Ok || result.Reason is not null);
        }
    }
}
