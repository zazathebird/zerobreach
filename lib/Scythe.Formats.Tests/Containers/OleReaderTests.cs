using System.Text;
using Scythe.Formats;
using Scythe.Formats.Containers;
using Xunit;

namespace Scythe.Formats.Tests.Containers;

public class OleReaderTests
{
    private static ScanBudget Budget => BudgetDefaults.Default;

    private static (byte[] Bytes, OleFixtureBuilder.Result Layout, byte[] Big, byte[] Small) MacroDocument()
    {
        // Root
        //  ├─ Macros (storage)
        //  │   └─ VBA (mini stream, 100 bytes — below the 4096 cutoff)
        //  └─ WordDocument (FAT stream, 5000 bytes — above the cutoff)
        var builder = new OleFixtureBuilder();
        byte[] big = new byte[5000];
        for (int i = 0; i < big.Length; i++)
        {
            big[i] = (byte)(i * 7);
        }
        byte[] small = Encoding.ASCII.GetBytes(new string('v', 100));
        uint bigStart = builder.AddFatStream(big);
        uint smallStart = builder.AddMiniStream(small);
        builder.AddDirEntry("Macros", 1, OleFixtureBuilder.NoStream, 3, 2, 0, 0);   // entry 1
        builder.AddDirEntry("VBA", 2, OleFixtureBuilder.NoStream, OleFixtureBuilder.NoStream, OleFixtureBuilder.NoStream, smallStart, (ulong)small.Length); // entry 2
        builder.AddDirEntry("WordDocument", 2, OleFixtureBuilder.NoStream, OleFixtureBuilder.NoStream, OleFixtureBuilder.NoStream, bigStart, (ulong)big.Length); // entry 3
        builder.SetRootChild(1);
        var layout = builder.Build();
        return (layout.Bytes, layout, big, small);
    }

    [Fact]
    public void DirectoryTree_WalkedWithNamesTypesSizesPaths()
    {
        var (bytes, _, big, small) = MacroDocument();
        var result = OleReader.Read(bytes, Budget);
        Assert.Equal(OperationState.Ok, result.State);

        var root = result.File!.Root;
        Assert.Equal(OleEntryType.RootStorage, root.Type);
        Assert.Equal("Root Entry", root.Name);
        // In-order traversal of the sibling tree: Macros (node), then its right sibling.
        Assert.Equal(new[] { "Macros", "WordDocument" }, root.Children.Select(c => c.Name));

        var macros = root.Children[0];
        Assert.Equal(OleEntryType.Storage, macros.Type);
        Assert.Equal("Macros", macros.Path);
        var vba = Assert.Single(macros.Children);
        Assert.Equal("Macros/VBA", vba.Path);
        Assert.Equal(OleEntryType.Stream, vba.Type);
        Assert.Equal((ulong)small.Length, vba.Size);

        var word = root.Children[1];
        Assert.Equal("WordDocument", word.Path);
        Assert.Equal((ulong)big.Length, word.Size);
    }

    [Fact]
    public void FatStream_ReadBackExactly()
    {
        var (bytes, _, big, _) = MacroDocument();
        var file = OleReader.Read(bytes, Budget).File!;
        var word = file.Root.Children[1];
        var read = OleReader.ReadStream(bytes, file, word, Budget);
        Assert.Equal(OperationState.Ok, read.State);
        Assert.Equal(big, read.Bytes);
    }

    [Fact]
    public void MiniStream_ReadThroughMiniFat_Exactly()
    {
        var (bytes, _, _, small) = MacroDocument();
        var file = OleReader.Read(bytes, Budget).File!;
        var vba = file.Root.Children[0].Children[0];
        var read = OleReader.ReadStream(bytes, file, vba, Budget);
        Assert.Equal(OperationState.Ok, read.State);
        Assert.Equal(small, read.Bytes);
    }

    [Fact]
    public void ReadStream_OnAStorage_RefusedNotGuessed()
    {
        var (bytes, _, _, _) = MacroDocument();
        var file = OleReader.Read(bytes, Budget).File!;
        var macros = file.Root.Children[0];
        var read = OleReader.ReadStream(bytes, file, macros, Budget);
        Assert.Equal(OperationState.Failed, read.State);
        Assert.Contains("not a stream", read.Reason);
    }

    [Fact]
    public void BadSignature_Failed()
    {
        var (bytes, _, _, _) = MacroDocument();
        bytes[0] = 0x00;
        var result = OleReader.Read(bytes, Budget);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("signature", result.Message);
        Assert.Equal(0, result.ErrorOffset);
    }

    [Fact]
    public void TooSmallForHeader_Failed()
    {
        var result = OleReader.Read(new byte[100], Budget);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("512", result.Message);
    }

    [Fact]
    public void FatChainCycle_ReadStreamFailsLoudly()
    {
        var (bytes, layout, _, _) = MacroDocument();
        var file = OleReader.Read(bytes, Budget).File!;
        var word = file.Root.Children[1];
        // Point the big stream's first FAT link back at itself: a classic scanner-hang.
        OleFixtureBuilder.WriteU32(bytes, layout.FatTableOffset + 4 * (int)word.StartSector, word.StartSector);
        var reparsed = OleReader.Read(bytes, Budget).File!;
        var read = OleReader.ReadStream(bytes, reparsed, reparsed.Root.Children[1], Budget);
        Assert.Equal(OperationState.Failed, read.State);
        Assert.Contains("cycle", read.Reason);
    }

    [Fact]
    public void TruncatedFile_Incomplete_NeverOk()
    {
        var (bytes, _, _, _) = MacroDocument();
        // Cut the last sector off; the FAT lives at the end, so the structure is torn.
        byte[] cut = bytes.AsSpan(0, bytes.Length - OleFixtureBuilder.SectorSize).ToArray();
        var result = OleReader.Read(cut, Budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("truncated", result.Message);
    }

    [Fact]
    public void DirectoryTreeCycle_ReportedAndBounded()
    {
        var (bytes, layout, _, _) = MacroDocument();
        // Entry 3's right-sibling pointer -> entry 1 creates a sibling loop 1 -> 3 -> 1.
        int entry3Offset = layout.DirTableOffset + 3 * 128;
        OleFixtureBuilder.WriteU32(bytes, entry3Offset + 72, 1);
        var result = OleReader.Read(bytes, Budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains(result.IncompleteReasons, r => r.Contains("cycle"));
        // The tree that was walked before the cycle is still surfaced.
        Assert.NotNull(result.File);
    }

    [Fact]
    public void RootEntryNotAStorage_Failed()
    {
        var (bytes, layout, _, _) = MacroDocument();
        bytes[layout.DirTableOffset + 66] = 2; // root's type byte -> stream
        var result = OleReader.Read(bytes, Budget);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("root storage", result.Message);
    }

    [Fact]
    public void StreamSizeLies_ChainEndsEarly_Incomplete()
    {
        var (bytes, layout, big, _) = MacroDocument();
        // Entry 3 declares 20000 bytes; its chain only holds ceil(5000/512) sectors.
        int entry3Offset = layout.DirTableOffset + 3 * 128;
        OleFixtureBuilder.WriteU64(bytes, entry3Offset + 120, 20000);
        var file = OleReader.Read(bytes, Budget).File!;
        var word = file.Root.Children[1];
        Assert.Equal(20000ul, word.Size);
        var read = OleReader.ReadStream(bytes, file, word, Budget);
        Assert.Equal(OperationState.Incomplete, read.State);
        Assert.Contains("ends after", read.Reason);
        Assert.Null(read.Bytes);
        _ = big;
    }

    [Fact]
    public void Version3SizeField_HighHalfIsGarbage_Masked()
    {
        var (bytes, layout, _, small) = MacroDocument();
        // Real v3 writers leave junk in the high 32 bits of the size; entry 2 gets some.
        int entry2Offset = layout.DirTableOffset + 2 * 128;
        OleFixtureBuilder.WriteU64(bytes, entry2Offset + 120, (1UL << 32) | (uint)small.Length);
        var file = OleReader.Read(bytes, Budget).File!;
        var vba = file.Root.Children[0].Children[0];
        Assert.Equal((ulong)small.Length, vba.Size);
        var read = OleReader.ReadStream(bytes, file, vba, Budget);
        Assert.Equal(OperationState.Ok, read.State);
        Assert.Equal(small, read.Bytes);
    }

    [Fact]
    public void DeadlineZero_Canary_Incomplete()
    {
        var (bytes, _, _, _) = MacroDocument();
        var result = OleReader.Read(bytes, Budget with { Deadline = TimeSpan.Zero });
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("deadline", result.Message);
    }

    [Fact]
    public void SameBytes_SameTree_Deterministic()
    {
        var (bytes, _, _, _) = MacroDocument();
        var first = OleReader.Read(bytes, Budget);
        var second = OleReader.Read(bytes, Budget);
        Assert.Equal(Flatten(first.File!.Root), Flatten(second.File!.Root));
    }

    private static IEnumerable<(string, OleEntryType, ulong)> Flatten(OleDirectoryEntryInfo node)
    {
        yield return (node.Path, node.Type, node.Size);
        foreach (var child in node.Children)
        {
            foreach (var item in Flatten(child))
            {
                yield return item;
            }
        }
    }
}
