using System.Text;
using ZeroBreach.Formats;
using ZeroBreach.Formats.Containers;
using Xunit;

namespace ZeroBreach.Formats.Tests.Containers;

public class ContainerWalkerTests
{
    private static ScanBudget Budget => BudgetDefaults.Default;

    /// <summary>zip( zip( zip( leaf.txt ) ) ) ... to the requested depth.</summary>
    private static byte[] NestedZips(int levels)
    {
        byte[] current = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "leaf.txt",
            Data = Encoding.ASCII.GetBytes("innermost payload"),
        });
        for (int i = levels - 1; i >= 1; i--)
        {
            current = ZipFixtureBuilder.Build(new ZipEntryFixture
            {
                Name = $"level{i}.zip",
                Data = current,
                Method = 0, // stored so nesting, not compression, is what's under test
            });
        }
        return current;
    }

    [Fact]
    public void NestedZips_AtTheDepthLimit_WalkedCleanly_AndSaysSo()
    {
        var budget = Budget with { MaxNestingDepth = 3 };
        var result = ContainerWalker.Walk(NestedZips(3), budget);
        Assert.Equal(OperationState.Ok, result.State);

        var level1 = result.Root!;
        Assert.Equal(1, level1.Depth);
        var level2 = Assert.Single(level1.Children);
        Assert.Equal("level1.zip", level2.Path);
        var level3 = Assert.Single(level2.Children);
        Assert.Equal("level1.zip!level2.zip", level3.Path);
        Assert.Equal(3, level3.Depth);
        Assert.Empty(level3.Children); // leaf.txt is not a container
    }

    [Fact]
    public void NestedZips_OnePastTheLimit_TerminatesCleanly_ReportsIncomplete()
    {
        var budget = Budget with { MaxNestingDepth = 3 };
        var result = ContainerWalker.Walk(NestedZips(4), budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains(result.IncompleteReasons, r => r.Contains("depth") && r.Contains("level3.zip"));

        // The walk went exactly to the cap and no further.
        var level3 = result.Root!.Children.Single().Children.Single();
        Assert.Equal(3, level3.Depth);
        Assert.Empty(level3.Children);
    }

    [Fact]
    public void OoxmlInsideZip_ClassifiedWithMacroFlag()
    {
        byte[] docm = ZipFixtureBuilder.Build(
            new ZipEntryFixture
            {
                Name = "[Content_Types].xml",
                Data = Encoding.UTF8.GetBytes(
                    "<Types xmlns=\"x\"><Override PartName=\"/word/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/></Types>"),
                Method = 8,
            },
            new ZipEntryFixture { Name = "word/vbaProject.bin", Data = new byte[] { 1, 2, 3 }, Method = 0 });
        byte[] outer = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "invoice.docm", Data = docm, Method = 0 });

        var result = ContainerWalker.Walk(outer, Budget);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal(ContainerKind.Zip, result.Root!.Kind);
        var doc = Assert.Single(result.Root.Children);
        Assert.Equal(ContainerKind.Ooxml, doc.Kind);
        Assert.True(doc.HasMacroPart);
    }

    [Fact]
    public void OleInsideZip_FoundAndWalked()
    {
        var builder = new OleFixtureBuilder();
        uint start = builder.AddMiniStream(Encoding.ASCII.GetBytes("legacy stream content"));
        builder.AddDirEntry("WordDocument", 2, OleFixtureBuilder.NoStream, OleFixtureBuilder.NoStream, OleFixtureBuilder.NoStream, start, 21);
        builder.SetRootChild(1);
        byte[] ole = builder.Build().Bytes;
        byte[] outer = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "old-doc.doc", Data = ole, Method = 0 });

        var result = ContainerWalker.Walk(outer, Budget);
        Assert.Equal(OperationState.Ok, result.State);
        var doc = Assert.Single(result.Root!.Children);
        Assert.Equal(ContainerKind.Ole, doc.Kind);
        Assert.Equal(1, doc.EntryCount);
    }

    [Fact]
    public void EncryptedEntryInside_WholeWalkIncomplete_PathNamed()
    {
        byte[] outer = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "fine.txt", Data = new byte[] { 1 } },
            new ZipEntryFixture { Name = "locked.bin", Data = new byte[] { 2, 3 }, Encrypted = true });
        var result = ContainerWalker.Walk(outer, Budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains(result.IncompleteReasons, r => r.Contains("locked.bin") && r.Contains("encrypted"));
    }

    [Fact]
    public void CorruptInnerArchive_WalkIncomplete_ChildMarkedFailed()
    {
        // A ZIP signature followed by garbage: sniffs as ZIP, fails to parse.
        byte[] corrupt = new byte[256];
        corrupt[0] = 0x50;
        corrupt[1] = 0x4B;
        corrupt[2] = 0x03;
        corrupt[3] = 0x04;
        new Random(5).NextBytes(corrupt.AsSpan(4));
        byte[] outer = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "broken.zip", Data = corrupt, Method = 0 });

        var result = ContainerWalker.Walk(outer, Budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        var child = Assert.Single(result.Root!.Children);
        Assert.Equal(OperationState.Failed, child.State);
        Assert.Contains(result.IncompleteReasons, r => r.Contains("broken.zip"));
    }

    [Fact]
    public void UnknownRootBuffer_Failed()
    {
        var result = ContainerWalker.Walk(Encoding.ASCII.GetBytes("plain text, no container here...."), Budget);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Null(result.Root);
    }

    /// <summary>Nested-walk canary: a bomb one level down must still be stopped by the shared guard.</summary>
    [Fact]
    public void Canary_BombInsideNestedZip_StoppedByGuard()
    {
        byte[] zeros = new byte[8 * 1024 * 1024];
        byte[] inner = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "bomb.bin", Data = zeros, Method = 8 });
        byte[] outer = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "wrapper.zip", Data = inner, Method = 0 });

        var result = ContainerWalker.Walk(outer, Budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains(result.IncompleteReasons, r => r.Contains("bomb.bin") && r.Contains("ratio"));
    }

    [Fact]
    public void DeadlineZero_Canary_Incomplete()
    {
        var result = ContainerWalker.Walk(NestedZips(2), Budget with { Deadline = TimeSpan.Zero });
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains(result.IncompleteReasons, r => r.Contains("deadline"));
    }

    [Fact]
    public void SameBytes_SameTree_Deterministic()
    {
        byte[] outer = NestedZips(3);
        var first = ContainerWalker.Walk(outer, Budget);
        var second = ContainerWalker.Walk(outer, Budget);
        Assert.Equal(Flatten(first.Root!), Flatten(second.Root!));
        Assert.Equal(first.IncompleteReasons, second.IncompleteReasons);
    }

    private static IEnumerable<(string, ContainerKind, int, OperationState)> Flatten(ContainerNode node)
    {
        yield return (node.Path, node.Kind, node.Depth, node.State);
        foreach (var child in node.Children)
        {
            foreach (var item in Flatten(child))
            {
                yield return item;
            }
        }
    }
}
