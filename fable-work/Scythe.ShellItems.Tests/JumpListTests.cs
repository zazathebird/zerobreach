using Scythe.ShellItems.Tests.Fixtures;
using Xunit;
using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests;

public class JumpListTests
{
    [Fact]
    public void DestListVersion3PairsEntriesWithTheirLinkStreams()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic(version: 3);
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal(LinkResultState.Ok, result.State);
        var auto = result.Value!;
        Assert.Equal(3u, auto.Header.Version);
        Assert.Equal(3u, auto.Header.EntryCount);
        Assert.Equal(3u, auto.Header.LastEntryNumber);
        Assert.Equal(-1.0f, auto.Header.UnknownFloat);
        Assert.Equal(3, auto.Entries.Count);

        var first = auto.Entries[0];
        Assert.Equal(1u, first.EntryNumber);
        Assert.Equal("C:\\Users\\a.txt", first.Path.Value);
        Assert.Equal(4u, first.AccessCount);
        Assert.Equal(LinkFixture.WriteTicks, first.LastAccessTime.Ticks);
        Assert.Equal(-1, first.PinStatus);
        Assert.Null(first.PinnedIndex);
        Assert.Equal("workstation7", first.MachineName.Value);
        Assert.Equal(0x0123456789ABCDEFUL, first.Checksum);
        Assert.Equal(Blocks.DroidVolume, first.NewVolumeId);
        Assert.Equal(Blocks.BirthFile, first.BirthObjectId);
        Assert.Equal("1", first.LinkStreamName);
        Assert.Equal(LinkResultState.Ok, first.Link!.State);
        Assert.Equal("--one", first.Link.Value!.Arguments!.Value);
        Assert.Equal("C:\\a.txt", first.Link.Value.TargetIdList!.Path);

        Assert.Equal("--three", auto.Entries[2].Link!.Value!.Arguments!.Value);
        Assert.Empty(auto.UnreferencedLinkStreams);
        Assert.Empty(auto.Notes);
    }

    [Fact]
    public void DestListVersion1UsesTheShorterStrideAndHasNoAccessCount()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic(version: 1);
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Equal(3, result.Value!.Entries.Count);
        Assert.All(result.Value.Entries, e => Assert.Null(e.AccessCount));
        Assert.Equal("C:\\Users\\b.txt", result.Value.Entries[1].Path.Value);
        Assert.Equal(0, result.Value.Entries[1].PinStatus);
        Assert.Equal(0, result.Value.Entries[1].PinnedIndex);
        Assert.Equal(LinkFixture.WriteTicks, result.Value.Entries[2].LastAccessTime.Ticks);
    }

    [Fact]
    public void DestListVersion4UsesTheVersion3Layout()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic(version: 4);
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Equal(9u, result.Value!.Entries[2].AccessCount);
    }

    [Fact]
    public void UnknownDestListVersion_IncompleteWithTheHeaderOnly()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic(version: 2);
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("version 2", result.Reason);
        Assert.NotNull(result.Value);
        Assert.Equal(2u, result.Value.Header.Version);
        Assert.Empty(result.Value.Entries);
    }

    [Fact]
    public void MissingLinkStreamLeavesLinkNullWithANote()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        streams.Remove("2");
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Null(result.Value!.Entries[1].Link);
        Assert.Null(result.Value.Entries[1].LinkStreamName);
        Assert.Contains(result.Value.Notes, n => n.Contains("no link stream named 2", StringComparison.Ordinal));
    }

    [Fact]
    public void UnreferencedLinkStreamsAreListedAndNonHexNamesIgnored()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        streams["7"] = JumpListFixtures.LinkTo("orphan.txt", "");
        streams["a"] = JumpListFixtures.LinkTo("orphan2.txt", "");
        streams["DestListPropertyStore"] = [1, 2, 3];
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Equal(new[] { "7", "a" }, result.Value!.UnreferencedLinkStreams);
    }

    [Fact]
    public void StreamNamesAreMatchedAsHexRegardlessOfCase()
    {
        var destList = JumpListFixtures.DestList(3, [new DestEntry { Number = 0x1A, Path = "p" }]);
        var streams = new Dictionary<string, byte[]> { ["1A"] = JumpListFixtures.LinkTo("p", "u") };
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal("1A", result.Value!.Entries[0].LinkStreamName);
        Assert.Equal("u", result.Value.Entries[0].Link!.Value!.Arguments!.Value);
    }

    [Fact]
    public void DuplicateStreamNumbersUseTheOrdinallyFirstNameAndNote()
    {
        var destList = JumpListFixtures.DestList(3, [new DestEntry { Number = 1, Path = "p" }]);
        var streams = new Dictionary<string, byte[]> { ["01"] = JumpListFixtures.LinkTo("p", "zero-one"), ["1"] = JumpListFixtures.LinkTo("p", "one") };
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal("01", result.Value!.Entries[0].LinkStreamName);
        Assert.Contains(result.Value.Notes, n => n.Contains("both name entry 1", StringComparison.Ordinal));
    }

    [Fact]
    public void EntryCountLargerThanTheStream_IncompleteWithGatheredEntries()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        var result = JumpListReader.ReadAutomaticDestinations(destList.Patch(4, 4u), streams);

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("entry 3", result.Reason);
        Assert.Contains("declared 4 entries", result.Reason);
        Assert.Equal(3, result.Value!.Entries.Count);
    }

    [Fact]
    public void EntryCountSmallerThanTheStream_Incomplete()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        var result = JumpListReader.ReadAutomaticDestinations(destList.Patch(4, 2u), streams);

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("disagrees with the stream length", result.Reason);
        Assert.Equal(2, result.Value!.Entries.Count);
    }

    [Fact]
    public void EntryPathRunningPastTheStream_Incomplete()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        var firstEntryPathLength = JumpListReader.DestListHeaderSize + 128;
        var result = JumpListReader.ReadAutomaticDestinations(destList.Patch(firstEntryPathLength, (ushort)0x7FFF), streams);

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("32767 characters", result.Reason);
        Assert.Empty(result.Value!.Entries);
    }

    [Fact]
    public void Version1LayoutAppliedToVersion3Bytes_IsIncompleteNotWrong()
    {
        // The same entries under a version byte of 1 make the stride disagree with the stream:
        // the reader must say so instead of emitting entries decoded at the wrong offsets.
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic(version: 3);
        var result = JumpListReader.ReadAutomaticDestinations(destList.Patch(0, 1u), streams);

        Assert.Equal(LinkResultState.Incomplete, result.State);
    }

    [Fact]
    public void TruncatedDestListHeader_Incomplete()
    {
        var result = JumpListReader.ReadAutomaticDestinations(new byte[20], new Dictionary<string, byte[]>());
        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("needs 32", result.Reason);
    }

    [Fact]
    public void EmptyDestListWithZeroEntriesIsOk()
    {
        var result = JumpListReader.ReadAutomaticDestinations(JumpListFixtures.DestList(3, []), new Dictionary<string, byte[]>());
        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Empty(result.Value!.Entries);
    }

    [Fact]
    public void ABrokenLinkStreamIsReportedOnItsEntryNotTheContainer()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        streams["2"] = streams["2"].Take(60);
        var result = JumpListReader.ReadAutomaticDestinations(destList, streams);

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Equal(LinkResultState.Incomplete, result.Value!.Entries[1].Link!.State);
        Assert.Equal(LinkResultState.Ok, result.Value.Entries[0].Link!.State);
    }

    // ---- customDestinations-ms ----

    [Fact]
    public void CustomDestinationsWalksEveryLinkRecordToTheFooter()
    {
        var links = new[] { JumpListFixtures.LinkTo("a.txt", "--a"), JumpListFixtures.LinkTo("b.txt", "--b"), JumpListFixtures.LinkTo("c.txt", "--c") };
        var bytes = JumpListFixtures.Custom(3, links);
        var result = JumpListReader.ReadCustomDestinations(bytes);

        Assert.Equal(LinkResultState.Ok, result.State);
        var custom = result.Value!;
        Assert.Equal(2u, custom.Version);
        Assert.Equal(3u, custom.DeclaredEntryCount);
        Assert.Equal(3, custom.Entries.Count);
        Assert.Equal(new[] { "--a", "--b", "--c" }, custom.Entries.Select(e => e.Link.Value!.Arguments!.Value).ToArray());
        Assert.Equal(16 + 16, custom.Entries[0].Offset);
        Assert.Equal(16 + 16 + links[0].Length + 16, custom.Entries[1].Offset);
        Assert.Equal(48, custom.SkippedBytes);
        Assert.Equal(bytes.Length - 4, custom.FooterOffset);
        Assert.Empty(custom.Notes);
    }

    [Fact]
    public void CustomDestinationsWithoutCategoryGapsIsAlsoOk()
    {
        var bytes = JumpListFixtures.Custom(2, [JumpListFixtures.LinkTo("a", "1"), JumpListFixtures.LinkTo("b", "2")], categoryGuidBeforeEach: false);
        var result = JumpListReader.ReadCustomDestinations(bytes);

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Equal(0, result.Value!.SkippedBytes);
        Assert.Equal(2, result.Value.Entries.Count);
    }

    [Fact]
    public void CustomDestinationsMissingFooter_Incomplete()
    {
        var bytes = JumpListFixtures.Custom(2, [JumpListFixtures.LinkTo("a", "1"), JumpListFixtures.LinkTo("b", "2")], footer: false);
        var result = JumpListReader.ReadCustomDestinations(bytes);

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("footer", result.Reason);
        Assert.Null(result.Value!.FooterOffset);
        Assert.Equal(2, result.Value.Entries.Count);
    }

    [Fact]
    public void CustomDestinationsEntryCountDisagreement_Incomplete()
    {
        var bytes = JumpListFixtures.Custom(5, [JumpListFixtures.LinkTo("a", "1"), JumpListFixtures.LinkTo("b", "2")]);
        var result = JumpListReader.ReadCustomDestinations(bytes);

        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("declares 5 entries but 2", result.Reason);
        Assert.NotNull(result.Value!.FooterOffset);
    }

    [Fact]
    public void CustomDestinationsTruncatedHeader_Incomplete()
    {
        var result = JumpListReader.ReadCustomDestinations(new byte[10]);
        Assert.Equal(LinkResultState.Incomplete, result.State);
        Assert.Contains("needs 16", result.Reason);
    }

    [Fact]
    public void CustomDestinationsResynchronisesAfterAFailedRecord()
    {
        var broken = new LinkFixture { LinkInfo = new LinkInfoFixture().Build().Patch(0, 0x10u), Arguments = "bad" }.Build();
        var bytes = JumpListFixtures.Custom(2, [broken, JumpListFixtures.LinkTo("b", "good")]);
        var result = JumpListReader.ReadCustomDestinations(bytes);

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Equal(2, result.Value!.Entries.Count);
        Assert.Equal(LinkResultState.Failed, result.Value.Entries[0].Link.State);
        Assert.Equal("good", result.Value.Entries[1].Link.Value!.Arguments!.Value);
    }

    [Fact]
    public void CustomDestinationsBytesAfterTheFooterAreNoted()
    {
        var bytes = Concat(JumpListFixtures.Custom(1, [JumpListFixtures.LinkTo("a", "1")]), new byte[7]);
        var result = JumpListReader.ReadCustomDestinations(bytes);

        Assert.Equal(LinkResultState.Ok, result.State);
        Assert.Contains(result.Value!.Notes, n => n.StartsWith("7 bytes follow the footer", StringComparison.Ordinal));
    }

    [Fact]
    public void EveryTruncationOfACustomDestinationsFileIsNotOk()
    {
        var bytes = JumpListFixtures.Custom(2, [JumpListFixtures.LinkTo("a", "1"), JumpListFixtures.LinkTo("b", "2")]);
        for (var length = 0; length < bytes.Length; length++)
        {
            Assert.NotEqual(LinkResultState.Ok, JumpListReader.ReadCustomDestinations(bytes.Take(length)).State);
        }
    }

    [Fact]
    public void EveryTruncationOfADestListIsNotOk()
    {
        var (destList, streams) = JumpListFixtures.OrdinaryAutomatic();
        for (var length = 0; length < destList.Length; length++)
        {
            Assert.NotEqual(LinkResultState.Ok, JumpListReader.ReadAutomaticDestinations(destList.Take(length), streams).State);
        }
    }
}
