using Scythe.ShellItems.Tests.Fixtures;
using Xunit;
using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests;

public class LinkInfoTests
{
    private static LinkResult<ShellLink> Read(byte[] linkInfo) =>
        ShellLinkReader.Read(new LinkFixture { LinkInfo = linkInfo, Arguments = "tail" }.Build());

    [Fact]
    public void HeaderSize0x1C_ReadsNoUnicodeOffsets()
    {
        var info = Read(new LinkInfoFixture { HeaderSize = 0x1C, LocalBasePath = "C:\\ansi.txt" }.Build()).Value!.LinkInfo!;

        Assert.Equal(0x1Cu, info.HeaderSize);
        Assert.False(info.HasUnicodeOffsets);
        Assert.Null(info.LocalBasePathUnicode);
        Assert.Null(info.CommonPathSuffixUnicode);
        Assert.Equal("C:\\ansi.txt", info.LocalPath);
    }

    [Fact]
    public void HeaderSize0x24_ReadsUnicodeOffsetsAndTheUnicodeCopyWins()
    {
        var fixture = new LinkInfoFixture { HeaderSize = 0x24, LocalBasePath = "C:\\ansi.txt", LocalBasePathUnicode = "C:\\unic\u00F6de.txt", Suffix = string.Empty };
        var info = Read(fixture.Build()).Value!.LinkInfo!;

        Assert.True(info.HasUnicodeOffsets);
        Assert.Equal("C:\\ansi.txt", info.LocalBasePath!.Value);
        Assert.Equal("C:\\unic\u00F6de.txt", info.LocalBasePathUnicode!.Value);
        Assert.Equal(string.Empty, info.CommonPathSuffixUnicode!.Value);
        Assert.Equal("C:\\unic\u00F6de.txt", info.LocalPath);
    }

    [Fact]
    public void HeaderSizeAbove0x24IsAccepted()
    {
        var result = Read(new LinkInfoFixture { HeaderSize = 0x28 }.Build());
        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.NotNull(result.Value!.LinkInfo!.LocalBasePathUnicode);
    }

    [Fact]
    public void HeaderSizeBetween0x1CAnd0x24_Failed()
    {
        var bytes = new LinkInfoFixture { HeaderSize = 0x1C }.Build().Patch(4, 0x20u);
        var result = Read(bytes);

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("must be 0x1C or at least 0x24", result.Reason);
        Assert.Equal(76 + 4, result.Position);
    }

    [Fact]
    public void VolumeLabelSentinelReadsTheUnicodeLabel()
    {
        var info = Read(new LinkInfoFixture { UnicodeLabelSentinel = true, UnicodeLabel = "Dat\u00E9n" }.Build()).Value!.LinkInfo!;

        Assert.Equal(0x14u, info.VolumeId!.LabelOffset);
        Assert.Equal(0x14u, info.VolumeId.UnicodeLabelOffset);
        Assert.Equal(string.Empty, info.VolumeId.Label!.Value);
        Assert.Equal("Dat\u00E9n", info.VolumeId.UnicodeLabel!.Value);
    }

    [Fact]
    public void NonSentinelLabelOffsetDoesNotReadAUnicodeLabel()
    {
        var info = Read(new LinkInfoFixture { Label = "OS" }.Build()).Value!.LinkInfo!;

        Assert.Equal(0x10u, info.VolumeId!.LabelOffset);
        Assert.Null(info.VolumeId.UnicodeLabelOffset);
        Assert.Null(info.VolumeId.UnicodeLabel);
        Assert.Equal("OS", info.VolumeId.Label!.Value);
    }

    [Fact]
    public void LinkInfoSizeSmallerThanItsHeader_Failed()
    {
        var result = Read(new LinkInfoFixture().Build().Patch(0, 0x10u));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("smaller than the minimum header", result.Reason);
        Assert.Equal(76L, result.Position);
    }

    [Fact]
    public void HeaderSizeLargerThanLinkInfoSize_Failed()
    {
        var fixture = new LinkInfoFixture();
        var bytes = fixture.Build();
        var result = Read(bytes.Patch(4, fixture.Size + 4));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("exceeds the LinkInfo size", result.Reason);
    }

    [Fact]
    public void OffsetPointingOutsideLinkInfo_Failed()
    {
        var fixture = new LinkInfoFixture();
        var result = Read(fixture.Build().Patch(0x10, fixture.Size + 10));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("local base path offset", result.Reason);
        Assert.Contains("outside LinkInfo", result.Reason);
        Assert.Equal(76 + 0x10, result.Position);
    }

    [Fact]
    public void OffsetPointingIntoTheHeader_Failed()
    {
        var result = Read(new LinkInfoFixture().Build().Patch(0x18, 4u));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("common path suffix offset", result.Reason);
        Assert.Contains("into the LinkInfo header", result.Reason);
    }

    [Fact]
    public void StringOffsetPointingAtTheVolumeIdStructure_Failed()
    {
        var fixture = new LinkInfoFixture();
        var bytes = fixture.Build();
        var result = Read(bytes.Patch(0x10, fixture.VolumeIdOffset));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("inside the VolumeID structure", result.Reason);
    }

    [Fact]
    public void VolumeIdOffsetPointingAtTheBasePathString_Failed()
    {
        var fixture = new LinkInfoFixture();
        var bytes = fixture.Build();
        // The base path text read as a VolumeID size is absurd; the reader must say so, not decode it.
        var result = Read(bytes.Patch(0x0C, fixture.LocalBasePathOffset));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("VolumeID", result.Reason);
    }

    [Fact]
    public void VolumeIdSizeOverrunningLinkInfo_Failed()
    {
        var fixture = new LinkInfoFixture();
        var bytes = fixture.Build();
        var result = Read(bytes.Patch((int)fixture.VolumeIdOffset, fixture.Size));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("overruns LinkInfo", result.Reason);
    }

    [Fact]
    public void VolumeLabelOffsetOutsideTheVolumeId_Failed()
    {
        var fixture = new LinkInfoFixture();
        var bytes = fixture.Build();
        var result = Read(bytes.Patch((int)fixture.VolumeIdOffset + 12, 0x200u));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("label offset", result.Reason);
    }

    [Fact]
    public void UnterminatedStringInsideLinkInfo_Failed()
    {
        var fixture = new LinkInfoFixture { Suffix = "tail" };
        var bytes = fixture.Build();
        // The suffix is the last thing in LinkInfo; overwrite its terminator.
        var result = Read(bytes.Patch(bytes.Length - 1, (byte)'x'));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("not null-terminated", result.Reason);
    }

    [Fact]
    public void TruncatedMidLinkInfo_Incomplete()
    {
        var full = new LinkFixture { LinkInfo = new LinkInfoFixture().Build(), Arguments = "x" }.Build();
        var result = ShellLinkReader.Read(full.Take(76 + 0x20));

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("truncated in LinkInfo", result.Reason);
        Assert.NotNull(result.Value);
        Assert.Null(result.Value.LinkInfo);
    }

    [Fact]
    public void NetworkLinkWithUnicodeOffsetsReadsBothCopies()
    {
        var fixture = new LinkInfoFixture
        {
            Local = false,
            Network = true,
            NetName = "\\\\srv\\ansi",
            DeviceName = "Y:",
            NetNameUnicode = "\\\\srv\\\u00FCnicode",
            DeviceNameUnicode = "Y:",
            Suffix = "f.txt",
        };
        var net = Read(fixture.Build()).Value!.LinkInfo!.NetworkRelativeLink!;

        Assert.Equal(0x1Cu, net.NetNameOffset);
        Assert.Equal("\\\\srv\\ansi", net.NetName!.Value);
        Assert.Equal("\\\\srv\\\u00FCnicode", net.NetNameUnicode!.Value);
        Assert.Equal("Y:", net.DeviceNameUnicode!.Value);
        Assert.Equal("\\\\srv\\\u00FCnicode\\f.txt", Read(fixture.Build()).Value!.LinkInfo!.NetworkPath);
    }

    [Fact]
    public void NetworkDeviceNameAndProviderAreOnlyReadWhenTheirFlagsSay()
    {
        var net = Read(new LinkInfoFixture { Local = false, Network = true }.Build()).Value!.LinkInfo!.NetworkRelativeLink!;

        Assert.Equal(0u, net.Flags);
        Assert.Null(net.DeviceName);
        Assert.Null(net.NetworkProviderType);
        Assert.Equal(0x14u, net.NetNameOffset);
        Assert.Null(net.NetNameUnicode);
    }

    [Fact]
    public void NetworkLinkSizeSmallerThanItsHeader_Failed()
    {
        var fixture = new LinkInfoFixture { Local = false, Network = true };
        var bytes = fixture.Build();
        var result = Read(bytes.Patch((int)fixture.NetworkLinkOffset, 0x08u));

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.Contains("CommonNetworkRelativeLink", result.Reason);
    }

    [Fact]
    public void UnicodeOffsetOfZeroIsAbsentWithANote()
    {
        var result = Read(new LinkInfoFixture { HeaderSize = 0x24 }.Build().Patch(0x1C, 0u));

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Null(result.Value!.LinkInfo!.LocalBasePathUnicode);
        Assert.Contains(result.Value.Notes, n => n.Contains("offset is 0", StringComparison.Ordinal));
    }

    [Fact]
    public void ClearedFlagWithNonZeroOffsetIsNotedNotFollowed()
    {
        var fixture = new LinkInfoFixture();
        var result = Read(fixture.Build().Patch(8, 0u));

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Null(result.Value!.LinkInfo!.VolumeId);
        Assert.Null(result.Value.LinkInfo.LocalPath);
        Assert.Contains(result.Value.Notes, n => n.Contains("flag 0x1 is clear", StringComparison.Ordinal));
    }
}
