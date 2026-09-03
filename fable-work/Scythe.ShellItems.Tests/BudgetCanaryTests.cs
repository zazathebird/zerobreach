using System.Diagnostics;
using Scythe.ShellItems.Tests.Fixtures;
using Xunit;
using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests;

/// <summary>Each budget dimension tripped by input known to be pathological, plus the quiet side of each guard.</summary>
public class BudgetCanaryTests
{
    private static (byte[] DestList, Dictionary<string, byte[]> Streams) FiveThousandEntries()
    {
        var link = JumpListFixtures.LinkTo("x.txt", "-x");
        var entries = new List<DestEntry>();
        var streams = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        for (uint i = 1; i <= 5000; i++)
        {
            entries.Add(new DestEntry { Number = i, Path = $"C:\\f{i}.txt" });
            streams[i.ToString("x")] = link;
        }

        return (JumpListFixtures.DestList(3, entries), streams);
    }

    [Fact]
    public void MaxMatchesOnAFiveThousandEntryJumpList_IncompleteWithTheEntriesGatheredSoFar()
    {
        var (destList, streams) = FiveThousandEntries();
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams, ScanBudget.Default with { MaxMatches = 100 });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("MaxMatches", result.Reason);
        Assert.Equal(100, result.Value!.Entries.Count);
        Assert.Equal(100u, result.Value.Entries[99].EntryNumber);
    }

    [Fact]
    public void TheSameFiveThousandEntriesInsideTheBudgetAreOk()
    {
        var (destList, streams) = FiveThousandEntries();
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Equal(5000, result.Value!.Entries.Count);
    }

    [Fact]
    public void ADeadlineExpiringBetweenEntriesEmitsNoHalfDecodedEntry()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams, ScanBudget.Default with { Deadline = TimeSpan.Zero });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("Deadline", result.Reason);
        Assert.Empty(result.Value!.Entries);
    }

    [Fact]
    public void ADeadlineOfZeroOnALink_Incomplete()
    {
        var result = ShellLinkReader.Read(LinkFixture.OrdinaryBytes(), ScanBudget.Default with { Deadline = TimeSpan.Zero });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("Deadline", result.Reason);
    }

    [Fact]
    public void ADeadlineOfZeroOnCustomDestinations_IncompleteWithNoEntries()
    {
        var bytes = JumpListFixtures.Custom(1, [JumpListFixtures.LinkTo("a", "1")]);
        var result = JumpListReader.ReadCustomDestinations(bytes, ScanBudget.Default with { Deadline = TimeSpan.Zero });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("Deadline", result.Reason);
        Assert.Empty(result.Value!.Entries);
    }

    [Fact]
    public void MaxInputBytesOnALink_IncompleteNamesTheBudget()
    {
        var bytes = LinkFixture.OrdinaryBytes();
        var result = ShellLinkReader.Read(bytes, ScanBudget.Default with { MaxInputBytes = bytes.Length - 1 });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("MaxInputBytes", result.Reason);
        Assert.Equal(LinkResultState.Ok, ShellLinkReader.Read(bytes, ScanBudget.Default with { MaxInputBytes = bytes.Length }).State);
    }

    [Fact]
    public void MaxInputBytesCountsTheDestListAndEveryLinkStream()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        var total = destList.Length + streams.Values.Sum(s => s.Length);
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams, ScanBudget.Default with { MaxInputBytes = total - 1 });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("MaxInputBytes", result.Reason);
        Assert.Equal(LinkResultState.Ok, JumpListReader.ReadAutomaticDestinations(destList, streams, ScanBudget.Default with { MaxInputBytes = total }).State);
    }

    [Fact]
    public void MaxInputBytesOnCustomDestinations_Incomplete()
    {
        var bytes = JumpListFixtures.Custom(1, [JumpListFixtures.LinkTo("a", "1")]);
        var result = JumpListReader.ReadCustomDestinations(bytes, ScanBudget.Default with { MaxInputBytes = 10 });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("MaxInputBytes", result.Reason);
    }

    [Fact]
    public void MaxNestingDepthOfOneRefusesTheVistaIdListBlock()
    {
        var bytes = new LinkFixture { ExtraBlocks = [Blocks.Vista(Items.Volume("C:\\"))] }.Build();
        var result = ShellLinkReader.Read(bytes, ScanBudget.Default with { MaxNestingDepth = 1 });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("MaxNestingDepth", result.Reason);
        Assert.Equal(LinkResultState.Ok, ShellLinkReader.Read(bytes, ScanBudget.Default with { MaxNestingDepth = 2 }).State);
    }

    [Fact]
    public void MaxNestingDepthOfOneRefusesLinksInsideAJumpList()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams, ScanBudget.Default with { MaxNestingDepth = 1 });

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.All(result.Value!.Entries, e =>
        {
            Assert.Equal(LinkResultState.Incomplete, e.Link!.State);
            Assert.StartsWith("MaxNestingDepth", e.Link.Reason);
        });
    }

    [Fact]
    public void MaxNestingDepthOfZeroRefusesEvenTheLink()
    {
        var result = ShellLinkReader.Read(LinkFixture.OrdinaryBytes(), ScanBudget.Default with { MaxNestingDepth = 0 });
        Assert.Equal(LinkResultState.Incomplete, result.State);
    }

    [Fact]
    public void MaxMatchesOnItemIdEntries_Incomplete()
    {
        var items = Enumerable.Range(0, 50).Select(_ => Items.FileEntry("d", directory: true, longName: "d")).ToArray();
        var bytes = new LinkFixture { IdList = Items.IdList(items) }.Build();
        var result = ShellLinkReader.Read(bytes, ScanBudget.Default with { MaxMatches = 10 });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("MaxMatches", result.Reason);
        Assert.Equal(LinkResultState.Ok, ShellLinkReader.Read(bytes, ScanBudget.Default with { MaxMatches = 50 }).State);
    }

    [Fact]
    public void MaxMatchesOnExtraDataBlocks_Incomplete()
    {
        var blocks = Enumerable.Range(0, 30).Select(_ => Blocks.SpecialFolder(1, 1)).ToList();
        var bytes = new LinkFixture { ExtraBlocks = blocks }.Build();
        var result = ShellLinkReader.Read(bytes, ScanBudget.Default with { MaxMatches = 5 });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("MaxMatches", result.Reason);
        Assert.Equal(5, result.Value!.ExtraData.Count);
    }

    [Fact]
    public void MaxMatchesOnCustomDestinationsRecords_Incomplete()
    {
        var links = Enumerable.Range(0, 20).Select(i => JumpListFixtures.LinkTo("a", i.ToString())).ToArray();
        var result = JumpListReader.ReadCustomDestinations(JumpListFixtures.Custom(20, links), ScanBudget.Default with { MaxMatches = 7 });

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.StartsWith("MaxMatches", result.Reason);
        Assert.Equal(7, result.Value!.Entries.Count);
    }

    [Fact]
    public void AZeroSizeItemReturnsPromptlyInsteadOfSpinning()
    {
        var list = Items.IdList(Items.Root(Items.MyComputer), Items.ItemWithSize(0, [0x1F, 0x50]), Items.Volume("C:\\"));
        var bytes = new LinkFixture { IdList = list }.Build();

        var clock = Stopwatch.StartNew();
        var result = ShellLinkReader.Read(bytes, ScanBudget.Default with { Deadline = TimeSpan.FromSeconds(2) });
        clock.Stop();

        Assert.Equal(LinkResultState.Failed, result.State);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(2), $"took {clock.Elapsed}");
    }

    [Fact]
    public void AnAbsurdEntryCountIsBoundedByTheStreamNotTheCount()
    {
        var destList = JumpListFixtures.DestList(3, [new DestEntry { Number = 1, Path = "p" }], declaredCount: uint.MaxValue);
        var result = JumpListReader.ReadAutomaticDestinations(destList, new Dictionary<string, byte[]>());

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Single(result.Value!.Entries);
    }
}
