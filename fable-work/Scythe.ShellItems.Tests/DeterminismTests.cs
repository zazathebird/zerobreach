using Scythe.ShellItems.Tests.Fixtures;
using Xunit;
using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests;

public class DeterminismTests
{
    [Fact]
    public void TheSameLinkBytesTwiceRenderByteIdentically()
    {
        var bytes = new LinkFixture
        {
            IdList = Items.IdList(Items.Root(Items.MyComputer), Items.Volume("C:\\"), Items.Raw(0x60, 1, 2), Items.FileEntry("a", directory: false, longName: "a\uD800")),
            LinkInfo = new LinkInfoFixture { HeaderSize = 0x24, UnicodeLabelSentinel = true, LocalBasePathUnicode = "C:\\\u00FC" }.Build(),
            Name = "n\0n",
            Arguments = "\uDBFF\t",
            IconLocation = "i",
            ExtraBlocks = [Blocks.Tracker(), Blocks.Environment("a", "b"), Blocks.Vista(Items.Volume("D:\\")), Blocks.Raw(0xA0000009, [9, 9])],
        }.Build();

        var first = Dump.Link(ShellLinkReader.Read(bytes));
        var second = Dump.Link(ShellLinkReader.Read(bytes));

        Assert.Equal(first, second);
        Assert.Contains("state=Ok", first);
        Assert.Contains("completeness=Partial", first);
    }

    [Fact]
    public void AnIncompleteLinkRendersByteIdentically()
    {
        var bytes = LinkFixture.OrdinaryBytes().Take(120);
        Assert.Equal(Dump.Link(ShellLinkReader.Read(bytes)), Dump.Link(ShellLinkReader.Read(bytes)));
    }

    [Fact]
    public void TheSameJumpListTwiceRendersByteIdentically()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        streams["9"] = JumpListFixtures.LinkTo("orphan", "");
        var first = Dump.Automatic(JumpListReader.ReadAutomaticDestinations(destList, streams));
        var second = Dump.Automatic(JumpListReader.ReadAutomaticDestinations(destList, streams));

        Assert.Equal(first, second);
        Assert.Contains("unreferenced=9", first);
    }

    [Fact]
    public void StreamDictionaryInsertionOrderDoesNotChangeTheOutput()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        streams["b"] = JumpListFixtures.LinkTo("o1", "");
        streams["a"] = JumpListFixtures.LinkTo("o2", "");

        var reversed = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var pair in streams.Reverse())
        {
            reversed[pair.Key] = pair.Value;
        }

        Assert.NotEqual(streams.Keys.ToArray(), reversed.Keys.ToArray());
        Assert.Equal(
            Dump.Automatic(JumpListReader.ReadAutomaticDestinations(destList, streams)),
            Dump.Automatic(JumpListReader.ReadAutomaticDestinations(destList, reversed)));
        Assert.Contains("unreferenced=a|b", Dump.Automatic(JumpListReader.ReadAutomaticDestinations(destList, reversed)));
    }

    [Fact]
    public void TheSameCustomDestinationsTwiceRendersByteIdentically()
    {
        var bytes = JumpListFixtures.Custom(2, [JumpListFixtures.LinkTo("a", "1"), JumpListFixtures.LinkTo("b", "2")]);
        Assert.Equal(Dump.Custom(JumpListReader.ReadCustomDestinations(bytes)), Dump.Custom(JumpListReader.ReadCustomDestinations(bytes)));
    }

    [Fact]
    public void ResultsNeverCarryTheReadTime()
    {
        // Nothing in a result is derived from the clock: two reads a moment apart are identical
        // even though the stopwatch inside the reader has moved on.
        var bytes = LinkFixture.OrdinaryBytes();
        var first = Dump.Link(ShellLinkReader.Read(bytes));
        Thread.Sleep(5);
        Assert.Equal(first, Dump.Link(ShellLinkReader.Read(bytes)));
    }
}
