using Scythe.ShellItems.Tests.Fixtures;
using Xunit;
using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests;

public class OrdinaryLinkTests
{
    private static ShellLink ReadOk(byte[] bytes)
    {
        var result = ShellLinkReader.Read(bytes);
        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.NotNull(result.Value);
        return result.Value;
    }

    [Fact]
    public void LocalFileLinkWithAllFiveStrings_ReadsEveryStringExactly()
    {
        var fixture = LinkFixture.Ordinary();
        var link = ReadOk(fixture.Build());

        Assert.Equal(fixture.Name, link.Name!.Value);
        Assert.Equal(fixture.RelativePath, link.RelativePath!.Value);
        Assert.Equal(fixture.WorkingDirectory, link.WorkingDirectory!.Value);
        Assert.Equal(fixture.Arguments, link.Arguments!.Value);
        Assert.Equal(fixture.IconLocation, link.IconLocation!.Value);
        Assert.Equal(Utf16(fixture.Arguments!), link.Arguments.RawBytes);
        Assert.Equal(Utf16(fixture.IconLocation!), link.IconLocation.RawBytes);
        Assert.Equal(LinkStringEncoding.Utf16LittleEndian, link.Arguments.Encoding);
        Assert.False(link.Arguments.AmbiguousEncoding);
    }

    [Fact]
    public void HeaderFieldsAreReadAsStored()
    {
        var fixture = LinkFixture.Ordinary();
        var header = ReadOk(fixture.Build()).Header;

        Assert.Equal(0x4Cu, header.HeaderSize);
        Assert.Equal(ShellLinkReader.ShellLinkClassId, header.ClassId);
        Assert.Equal(fixture.Flags, header.Flags);
        Assert.True(header.IsUnicode);
        Assert.Equal(0x20u, header.FileAttributes);
        Assert.Equal(1234u, header.FileSize);
        Assert.Equal(-3, header.IconIndex);
        Assert.Equal(1u, header.ShowCommand);
        Assert.Equal((ushort)0x0341, header.HotKey);
        Assert.Equal(76, header.RawBytes.Length);
    }

    [Fact]
    public void TimestampsRoundTripToExactFileTimeTicks()
    {
        var header = ReadOk(LinkFixture.OrdinaryBytes()).Header;

        Assert.Equal(LinkFixture.CreationTicks, header.CreationTime.Ticks);
        Assert.Equal(LinkFixture.AccessTicks, header.AccessTime.Ticks);
        Assert.Equal(LinkFixture.WriteTicks, header.WriteTime.Ticks);
        Assert.Equal(FileTimePresence.Set, header.CreationTime.Presence);
        Assert.Equal(new DateTime(2023, 11, 14, 15, 26, 45, DateTimeKind.Utc).AddTicks(1_234_567), header.CreationTime.ToUtcDateTime());
    }

    [Fact]
    public void ZeroTimestampIsUnsetNotTheEpoch()
    {
        var fixture = new LinkFixture { Arguments = "x", CreationTime = 0, AccessTime = 5, WriteTime = ulong.MaxValue };
        var header = ReadOk(fixture.Build()).Header;

        Assert.Equal(FileTimePresence.Unset, header.CreationTime.Presence);
        Assert.Null(header.CreationTime.ToUtcDateTime());
        Assert.Equal(FileTimePresence.Set, header.AccessTime.Presence);
        Assert.Equal(FileTimePresence.BeyondRange, header.WriteTime.Presence);
        Assert.Null(header.WriteTime.ToUtcDateTime());
        Assert.Equal(ulong.MaxValue, header.WriteTime.Ticks);
    }

    [Fact]
    public void IdListPathIsReconstructedFromVolumeAndFileEntries()
    {
        var list = ReadOk(LinkFixture.OrdinaryBytes()).TargetIdList;

        Assert.NotNull(list);
        Assert.Equal("C:\\Users\\readme.txt", list.Path);
        Assert.Equal(PathCompleteness.Complete, list.PathCompleteness);
        Assert.Equal(
            new[] { ShellItemKind.RootFolder, ShellItemKind.Volume, ShellItemKind.FileEntry, ShellItemKind.FileEntry },
            list.Items.Select(i => i.Kind).ToArray());
        Assert.Equal(Items.MyComputer, list.Items[0].RootFolderClassId);
        Assert.Equal("C:\\", list.Items[1].DriveString);
        Assert.Equal(FileEntryKind.Directory, list.Items[2].FileEntryKind);
        Assert.Equal("README~1.TXT", list.Items[3].PrimaryName);
        Assert.Equal("readme.txt", list.Items[3].Extension!.LongName);
        Assert.Equal(1234u, list.Items[3].FileSize);
        Assert.Empty(list.Notes);
    }

    [Fact]
    public void LinkInfoLocalPathIsBasePathPlusSuffix()
    {
        var fixture = new LinkFixture
        {
            LinkInfo = new LinkInfoFixture { LocalBasePath = "C:\\Data", Suffix = "\\deep\\file.bin", Label = "DATA", SerialNumber = 0x1234ABCD, DriveType = 2 }.Build(),
        };
        var info = ReadOk(fixture.Build()).LinkInfo;

        Assert.NotNull(info);
        Assert.Equal("C:\\Data\\deep\\file.bin", info.LocalPath);
        Assert.Null(info.NetworkPath);
        Assert.Equal("C:\\Data", info.LocalBasePath!.Value);
        Assert.Equal("\\deep\\file.bin", info.CommonPathSuffix!.Value);
        Assert.Equal(DriveType.Removable, info.VolumeId!.DriveType);
        Assert.Equal(0x1234ABCDu, info.VolumeId.SerialNumber);
        Assert.Equal("DATA", info.VolumeId.Label!.Value);
        Assert.Null(info.VolumeId.UnicodeLabel);
    }

    [Fact]
    public void TargetPathsAgreeWhenIdListAndLinkInfoMatch()
    {
        var link = ReadOk(LinkFixture.OrdinaryBytes());
        Assert.False(link.TargetPathsDisagree);
    }

    [Fact]
    public void TargetPathsDisagreeIsReportedNotResolved()
    {
        var fixture = new LinkFixture
        {
            IdList = Items.OrdinaryLocalList(),
            LinkInfo = new LinkInfoFixture { LocalBasePath = "D:\\elsewhere.txt" }.Build(),
        };
        var link = ReadOk(fixture.Build());

        Assert.True(link.TargetPathsDisagree);
        Assert.Equal("C:\\Users\\readme.txt", link.TargetIdList!.Path);
        Assert.Equal("D:\\elsewhere.txt", link.LinkInfo!.LocalPath);
    }

    [Fact]
    public void TargetPathsDisagreeIsNullWithOnlyOneSource()
    {
        Assert.Null(ReadOk(new LinkFixture { IdList = Items.OrdinaryLocalList() }.Build()).TargetPathsDisagree);
        Assert.Null(ReadOk(new LinkFixture { LinkInfo = new LinkInfoFixture().Build() }.Build()).TargetPathsDisagree);
    }

    [Fact]
    public void LinkWithoutTargetIdListStillReadsTheRest()
    {
        var fixture = new LinkFixture
        {
            LinkInfo = new LinkInfoFixture().Build(),
            Arguments = "/k dir",
            IconLocation = "cmd.exe",
        };
        var link = ReadOk(fixture.Build());

        Assert.Null(link.TargetIdList);
        Assert.NotNull(link.LinkInfo);
        Assert.Equal("/k dir", link.Arguments!.Value);
        Assert.Equal("cmd.exe", link.IconLocation!.Value);
        Assert.Null(link.Name);
        Assert.Null(link.RelativePath);
        Assert.Null(link.WorkingDirectory);
    }

    [Fact]
    public void UncLinkReadsTheNetworkBranchAndTheNetworkIdList()
    {
        var fixture = new LinkFixture
        {
            IdList = Items.IdList(
                Items.Root(Items.NetworkPlaces),
                Items.Network("\\\\server\\share", classType: 0x41),
                Items.FileEntry("docs", directory: true, longName: "docs"),
                Items.FileEntry("A~1.TXT", directory: false, longName: "a.txt")),
            LinkInfo = new LinkInfoFixture
            {
                Local = false,
                Network = true,
                NetName = "\\\\server\\share",
                DeviceName = "Z:",
                ProviderType = 0x00020000,
                Suffix = "docs\\a.txt",
            }.Build(),
        };
        var link = ReadOk(fixture.Build());

        Assert.Equal("\\\\server\\share\\docs\\a.txt", link.TargetIdList!.Path);
        Assert.Equal(PathCompleteness.Complete, link.TargetIdList.PathCompleteness);
        var net = link.LinkInfo!.NetworkRelativeLink;
        Assert.NotNull(net);
        Assert.Equal("\\\\server\\share", net.NetName!.Value);
        Assert.Equal("Z:", net.DeviceName!.Value);
        Assert.Equal(0x00020000u, net.NetworkProviderType);
        Assert.Null(net.NetNameUnicode);
        Assert.Equal("\\\\server\\share\\docs\\a.txt", link.LinkInfo.NetworkPath);
        Assert.Null(link.LinkInfo.LocalPath);
        Assert.Null(link.LinkInfo.VolumeId);
        Assert.False(link.TargetPathsDisagree);
    }

    [Fact]
    public void DirectoryTargetIsADirectoryFileEntry()
    {
        var fixture = new LinkFixture
        {
            IdList = Items.IdList(Items.Root(Items.MyComputer), Items.Volume("C:\\"), Items.FileEntry("Windows", directory: true, longName: "Windows", attributes: 0x10)),
            FileAttributes = 0x10,
        };
        var link = ReadOk(fixture.Build());

        Assert.Equal("C:\\Windows", link.TargetIdList!.Path);
        Assert.Equal(FileEntryKind.Directory, link.TargetIdList.Items[2].FileEntryKind);
        Assert.Equal((ushort)0x10, link.TargetIdList.Items[2].FileAttributes);
        Assert.Equal(0x10u, link.Header.FileAttributes);
    }

    [Fact]
    public void LengthIsTheBytesConsumedThroughTheTerminalBlock()
    {
        var bytes = LinkFixture.OrdinaryBytes();
        Assert.Equal(bytes.Length, ReadOk(bytes).Length);

        var withTrailer = Concat(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
        Assert.Equal(bytes.Length, ReadOk(withTrailer).Length);
    }

    [Fact]
    public void TrackerBlockDecodesMachineIdAndDroids()
    {
        var link = ReadOk(LinkFixture.OrdinaryBytes());
        var tracker = Assert.Single(link.ExtraData.OfType<TrackerBlock>());

        Assert.Equal(0x58u, tracker.Length);
        Assert.Equal(0u, tracker.Version);
        Assert.Equal("workstation7", tracker.MachineId.Value);
        Assert.Equal(Blocks.DroidVolume, tracker.DroidVolume);
        Assert.Equal(Blocks.DroidFile, tracker.DroidFile);
        Assert.Equal(Blocks.BirthVolume, tracker.DroidBirthVolume);
        Assert.Equal(Blocks.BirthFile, tracker.DroidBirthFile);
        Assert.Equal(0x60, tracker.RawBytes.Length);
    }

    [Fact]
    public void KnownFolderAndSpecialFolderBlocksDecode()
    {
        var fixture = new LinkFixture { ExtraBlocks = [Blocks.KnownFolder(Blocks.DocumentsFolder, 0x1C), Blocks.SpecialFolder(5, 0x3A)] };
        var link = ReadOk(fixture.Build());

        var known = Assert.Single(link.ExtraData.OfType<KnownFolderBlock>());
        Assert.Equal(Blocks.DocumentsFolder, known.KnownFolderId);
        Assert.Equal(0x1Cu, known.Offset);
        var special = Assert.Single(link.ExtraData.OfType<SpecialFolderBlock>());
        Assert.Equal(5u, special.SpecialFolderId);
        Assert.Equal(0x3Au, special.Offset);
    }

    [Fact]
    public void EnvironmentBlockWithAgreeingCopiesDecodes()
    {
        var fixture = new LinkFixture { ExtraBlocks = [Blocks.Environment("%USERPROFILE%\\x.txt", "%USERPROFILE%\\x.txt")] };
        var env = Assert.Single(ReadOk(fixture.Build()).ExtraData.OfType<EnvironmentStringsBlock>());

        Assert.Equal(ExtraDataSignature.EnvironmentVariable, env.Signature);
        Assert.Equal("%USERPROFILE%\\x.txt", env.Target);
        Assert.Equal("%USERPROFILE%\\x.txt", env.AnsiTarget.Value);
        Assert.False(env.AnsiAndUnicodeDisagree);
    }

    [Fact]
    public void VistaIdListBlockDecodesItsNestedList()
    {
        var fixture = new LinkFixture
        {
            ExtraBlocks = [Blocks.Vista(Items.Root(Items.MyComputer), Items.Volume("D:\\"), Items.FileEntry("x.txt", directory: false, longName: "x.txt"))],
        };
        var vista = Assert.Single(ReadOk(fixture.Build()).ExtraData.OfType<VistaIdListBlock>());

        Assert.Equal("D:\\x.txt", vista.IdList.Path);
        Assert.Equal(3, vista.IdList.Items.Count);
        Assert.Equal(PathCompleteness.Complete, vista.IdList.PathCompleteness);
    }

    [Fact]
    public void ZeroExtraDataBlocksIsAnEmptyList()
    {
        var link = ReadOk(new LinkFixture { Arguments = "a" }.Build());
        Assert.Empty(link.ExtraData);
        Assert.Empty(link.Notes);
    }

    [Fact]
    public void NonUnicodeLinkReadsCodePageStrings()
    {
        var fixture = new LinkFixture { Unicode = false, Name = "plain", Arguments = "-a -b" };
        var link = ReadOk(fixture.Build());

        Assert.False(link.Header.IsUnicode);
        Assert.Equal("plain", link.Name!.Value);
        Assert.Equal("-a -b", link.Arguments!.Value);
        Assert.Equal(LinkStringEncoding.SystemCodePage, link.Arguments.Encoding);
        Assert.Equal(Latin1("-a -b"), link.Arguments.RawBytes);
    }
}
