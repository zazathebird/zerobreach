using Scythe.ShellItems.Tests.Fixtures;
using Xunit;
using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests;

public class IdListTests
{
    private static LinkResult<ShellLink> Read(byte[] idList, string? arguments = "tail") =>
        ShellLinkReader.Read(new LinkFixture { IdList = idList, Arguments = arguments }.Build());

    [Fact]
    public void UnknownItemTypeYieldsAPartialPathAndTheRestOfTheFileStillParses()
    {
        var list = Items.IdList(
            Items.Root(Items.MyComputer),
            Items.Volume("C:\\"),
            Items.Raw(0x60, 0x01, 0x02, 0x03),
            Items.FileEntry("x.txt", directory: false, longName: "x.txt"));
        var result = Read(list);

        Assert.Equal(LinkResultState.Ok, result.State);
        var ids = result.Value!.TargetIdList!;
        Assert.Equal(PathCompleteness.Partial, ids.PathCompleteness);
        Assert.Equal("C:\\", ids.Path);
        Assert.Equal(4, ids.Items.Count);
        Assert.Equal(ShellItemKind.Unknown, ids.Items[2].Kind);
        Assert.Equal((byte)0x60, ids.Items[2].ClassType);
        Assert.Equal(new byte[] { 0x60, 0x01, 0x02, 0x03 }, ids.Items[2].RawData);
        Assert.False(ids.Items[2].PathSegmentKnown);
        Assert.Contains(ids.Notes, n => n.Contains("0x60", StringComparison.Ordinal));
        Assert.Equal("tail", result.Value.Arguments!.Value);
    }

    [Theory]
    [InlineData((ushort)3)]
    [InlineData((ushort)7)]
    [InlineData((ushort)8)]
    [InlineData((ushort)9)]
    public void Beef4LongNameIsReadAtEachDocumentedVersion(ushort version)
    {
        var list = Items.IdList(Items.Root(Items.MyComputer), Items.Volume("C:\\"), Items.FileEntry("LONGNA~1.TXT", directory: false, longName: "long name.txt", extensionVersion: version));
        var ids = Read(list).Value!.TargetIdList!;

        Assert.Equal("C:\\long name.txt", ids.Path);
        Assert.Equal(PathCompleteness.Complete, ids.PathCompleteness);
        Assert.Equal(version, ids.Items[2].Extension!.Version);
        Assert.Equal("long name.txt", ids.Items[2].Extension!.LongName);
        Assert.Equal((ushort)0x0014, ids.Items[2].Extension!.FirstExtensionOffset);
        Assert.Empty(ids.Notes);
    }

    [Fact]
    public void Beef4UnknownVersionFallsBackToThePrimaryNameWithANote()
    {
        var list = Items.IdList(Items.Root(Items.MyComputer), Items.Volume("C:\\"), Items.FileEntry("SHORT~1.TXT", directory: false, longName: "long.txt", extensionVersion: 5));
        var ids = Read(list).Value!.TargetIdList!;

        Assert.Null(ids.Items[2].Extension!.LongName);
        Assert.Equal((ushort)5, ids.Items[2].Extension!.Version);
        Assert.Equal("C:\\SHORT~1.TXT", ids.Path);
        Assert.Contains(ids.Notes, n => n.Contains("version 5", StringComparison.Ordinal));
    }

    [Fact]
    public void Beef4FileReferenceIsOnlyReadOnVersionsThatCarryIt()
    {
        var v3 = Read(Items.IdList(Items.FileEntry("a", directory: false, longName: "a", extensionVersion: 3, fileReference: 0x0005000000001234UL))).Value!.TargetIdList!;
        var v9 = Read(Items.IdList(Items.FileEntry("a", directory: false, longName: "a", extensionVersion: 9, fileReference: 0x0005000000001234UL))).Value!.TargetIdList!;

        Assert.Null(v3.Items[0].Extension!.FileReference);
        Assert.Equal(0x0005000000001234UL, v9.Items[0].Extension!.FileReference);
    }

    [Fact]
    public void UnicodePrimaryNameItemDecodes()
    {
        var list = Items.IdList(Items.Root(Items.MyComputer), Items.Volume("C:\\"), Items.FileEntry("caf\u00E9 \u2603", directory: false, unicodeName: true));
        var ids = Read(list).Value!.TargetIdList!;

        Assert.Equal((byte)0x36, ids.Items[2].ClassType);
        Assert.Equal("caf\u00E9 \u2603", ids.Items[2].PrimaryName);
        Assert.Null(ids.Items[2].Extension);
        Assert.Equal("C:\\caf\u00E9 \u2603", ids.Path);
    }

    [Fact]
    public void EmptyIdListHasNoItemsAndNoPath()
    {
        var ids = Read(Items.IdList()).Value!.TargetIdList!;

        Assert.Empty(ids.Items);
        Assert.Null(ids.Path);
        Assert.Equal(PathCompleteness.None, ids.PathCompleteness);
        Assert.Equal(2, ids.DeclaredSize);
    }

    [Fact]
    public void RootFolderThatIsNotAKnownPathRootMakesThePathPartial()
    {
        var ids = Read(Items.IdList(Items.Root(Items.Desktop), Items.FileEntry("x.txt", directory: false, longName: "x.txt"))).Value!.TargetIdList!;

        Assert.Equal(ShellItemKind.RootFolder, ids.Items[0].Kind);
        Assert.Equal(Items.Desktop, ids.Items[0].RootFolderClassId);
        Assert.False(ids.Items[0].PathSegmentKnown);
        Assert.Equal(PathCompleteness.Partial, ids.PathCompleteness);
        Assert.Null(ids.Path);
    }

    [Fact]
    public void NetworkLocationWithDescriptionAndComments()
    {
        var ids = Read(Items.IdList(Items.Root(Items.NetworkPlaces), Items.Network("\\\\nas\\media", classType: 0x42, description: "Media", comments: "read only"))).Value!.TargetIdList!;

        var item = ids.Items[1];
        Assert.Equal(ShellItemKind.NetworkLocation, item.Kind);
        Assert.Equal("\\\\nas\\media", item.NetworkLocation);
        Assert.Equal("Media", item.NetworkDescription);
        Assert.Equal("read only", item.NetworkComments);
        Assert.Equal((byte)0xC0, item.NetworkFlags);
        Assert.Equal("\\\\nas\\media", ids.Path);
    }

    [Fact]
    public void OddLengthPrimaryNameIsPaddedBeforeTheExtensionBlock()
    {
        var ids = Read(Items.IdList(Items.FileEntry("ab", directory: true, longName: "abc"))).Value!.TargetIdList!;

        Assert.Equal("ab", ids.Items[0].PrimaryName);
        Assert.Equal("abc", ids.Items[0].Extension!.LongName);
        Assert.Empty(ids.Notes);
    }

    [Fact]
    public void ExtensionBlocksOtherThanBeef4AreKeptRaw()
    {
        var other = Items.Extension(0xBEEF0025, 1, [1, 2, 3, 4, 5, 6, 7, 8]);
        var ids = Read(Items.IdList(Items.FileEntry("a", directory: false, longName: "a", extraExtension: other))).Value!.TargetIdList!;

        var raw = Assert.Single(ids.Items[0].OtherExtensionBlocks);
        Assert.Equal(0xBEEF0025u, raw.Signature);
        Assert.Equal(other, raw.RawBytes);
        Assert.Equal("a", ids.Items[0].Extension!.LongName);
    }

    [Fact]
    public void VolumeWithAnEmptyDriveStringMakesThePathPartial()
    {
        var ids = Read(Items.IdList(Items.Root(Items.MyComputer), Items.Volume(string.Empty, classType: 0x2E), Items.FileEntry("a", directory: false, longName: "a"))).Value!.TargetIdList!;

        Assert.Equal(PathCompleteness.Partial, ids.PathCompleteness);
        Assert.Null(ids.Path);
        Assert.Equal(string.Empty, ids.Items[1].DriveString);
    }

    [Fact]
    public void ShortFileEntryIsKeptRawWithANote()
    {
        var ids = Read(Items.IdList(Items.Raw(0x32, 0x00, 0x01))).Value!.TargetIdList!;

        Assert.Equal(ShellItemKind.FileEntry, ids.Items[0].Kind);
        Assert.False(ids.Items[0].PathSegmentKnown);
        Assert.Null(ids.Items[0].PrimaryName);
        Assert.Contains(ids.Notes, n => n.Contains("needs 12", StringComparison.Ordinal));
    }

    // ---- malformed ----

    [Fact]
    public void DeclaredSizeLargerThanTheItems_TerminalArrivesEarly_Failed()
    {
        var items = new[] { Items.Root(Items.MyComputer), Items.Volume("C:\\") };
        var list = Items.IdListWithSize((ushort)(items.Sum(i => i.Length) + 2 + 6), terminal: true, items);
        var result = ShellLinkReader.Read(new LinkFixture { IdList = Concat(list, new byte[6]) }.Build());

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("size 0", result.Reason);
        Assert.Contains("not the terminal position", result.Reason);
        Assert.NotNull(result.Position);
    }

    [Fact]
    public void DeclaredSizeSmallerThanTheItems_ItemOverruns_Failed()
    {
        var items = new[] { Items.Root(Items.MyComputer), Items.Volume("C:\\") };
        var list = Items.IdListWithSize((ushort)(items.Sum(i => i.Length) - 4), terminal: true, items);
        var result = ShellLinkReader.Read(new LinkFixture { IdList = list }.Build());

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("disagrees with the sum of its items", result.Reason);
    }

    [Fact]
    public void ItemSizeZeroBeforeTheEnd_FailedNotAnInfiniteLoop()
    {
        var zero = Items.ItemWithSize(0, [0x1F, 0x50]);
        var list = Items.IdList(Items.Root(Items.MyComputer), zero, Items.Volume("C:\\"));
        var result = Read(list);

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("size 0", result.Reason);
        Assert.Equal(76L + 2 + Items.Root(Items.MyComputer).Length, result.Position);
    }

    [Fact]
    public void ItemSizeOne_Failed()
    {
        var one = Items.ItemWithSize(1, [0x1F]);
        var result = Read(Items.IdList(Items.Root(Items.MyComputer), one));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("size 1", result.Reason);
    }

    [Fact]
    public void ListWithoutATerminalId_Failed()
    {
        var items = new[] { Items.Root(Items.MyComputer), Items.Volume("C:\\") };
        var list = Items.IdListWithSize((ushort)items.Sum(i => i.Length), terminal: false, items);
        var result = Read(list);

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("without a terminal ID", result.Reason);
    }

    [Fact]
    public void TruncatedMidIdList_IncompleteWithTheHeaderAsPartial()
    {
        var full = new LinkFixture { IdList = Items.OrdinaryLocalList(), Arguments = "x" }.Build();
        var result = ShellLinkReader.Read(full.Take(76 + 10));

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("truncated in the item-ID list", result.Reason);
        Assert.NotNull(result.Value);
        Assert.Null(result.Value.TargetIdList);
        Assert.Equal(76, result.Value.Length);
    }

    [Fact]
    public void TruncatedBeforeTheIdListSizeField_Incomplete()
    {
        var full = new LinkFixture { IdList = Items.OrdinaryLocalList() }.Build();
        var result = ShellLinkReader.Read(full.Take(77));

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("size field is missing", result.Reason);
    }

    [Fact]
    public void EmptyItemWithNoClassTypeByteIsKeptRaw()
    {
        var ids = Read(Items.IdList(Items.Item())).Value!.TargetIdList!;

        Assert.Single(ids.Items);
        Assert.Equal(ShellItemKind.Unknown, ids.Items[0].Kind);
        Assert.Empty(ids.Items[0].RawData);
        Assert.Equal(PathCompleteness.Partial, ids.PathCompleteness);
    }
}
