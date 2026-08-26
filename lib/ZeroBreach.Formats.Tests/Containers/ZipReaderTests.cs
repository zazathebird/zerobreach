using System.Text;
using ZeroBreach.Formats;
using ZeroBreach.Formats.Containers;
using Xunit;

namespace ZeroBreach.Formats.Tests.Containers;

public class ZipReaderTests
{
    private static ScanBudget Budget => BudgetDefaults.Default;

    [Fact]
    public void StoredEntry_NameSizesCrcTimestampCorrect_AndBytesRoundTrip()
    {
        byte[] content = Encoding.ASCII.GetBytes("hello container layer");
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "docs/readme.txt",
            Data = content,
            Method = 0,
            DosDate = 0x58CF,           // 2024-06-15
            DosTime = 0x6472,           // 12:35:36
        });

        var result = ZipReader.Read(zip, Budget);
        Assert.Equal(OperationState.Ok, result.State);
        var entry = Assert.Single(result.Archive!.Entries);
        Assert.Equal("docs/readme.txt", entry.Name);
        Assert.Equal(0, entry.CompressionMethod);
        Assert.Equal((uint)content.Length, entry.CompressedSize);
        Assert.Equal((uint)content.Length, entry.UncompressedSize);
        Assert.Equal(ZipFixtureBuilder.Crc32(content), entry.Crc32);
        Assert.Equal(new DateTime(2024, 6, 15, 12, 35, 36), entry.LastModified);
        Assert.False(entry.IsEncrypted);
        Assert.Empty(entry.Mismatches);
        Assert.Equal(PathAnomalies.None, entry.PathAnomalies);

        var data = ZipReader.ReadEntry(zip, entry, Budget);
        Assert.Equal(OperationState.Ok, data.State);
        Assert.Equal(content, data.Bytes);
        Assert.True(data.CrcMatchesCentralDirectory);
        Assert.True(data.CrcMatchesLocalHeader);
    }

    [Fact]
    public void DeflatedEntry_RoundTrips()
    {
        byte[] content = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("deflate me, again and again. ", 50)));
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "a.txt", Data = content, Method = 8 });

        var result = ZipReader.Read(zip, Budget);
        Assert.Equal(OperationState.Ok, result.State);
        var entry = Assert.Single(result.Archive!.Entries);
        Assert.Equal(8, entry.CompressionMethod);
        Assert.Equal((uint)content.Length, entry.UncompressedSize);
        Assert.True(entry.CompressedSize < content.Length);

        var data = ZipReader.ReadEntry(zip, entry, Budget);
        Assert.Equal(OperationState.Ok, data.State);
        Assert.Equal(content, data.Bytes);
        Assert.True(data.CrcMatchesCentralDirectory);
        Assert.Empty(data.Notes);
    }

    [Fact]
    public void Cp437Name_DecodedViaCp437_NotLatin1OrUtf8()
    {
        // 0x82 is é in CP437; 0xFF is a non-breaking space. Both differ from Latin-1.
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "placeholder",
            NameBytesOverride = new byte[] { (byte)'r', 0x82, (byte)'s', 0x75, 0x6D, 0x82, 0xFF, (byte)'x' },
            Data = new byte[] { 1 },
        });

        var result = ZipReader.Read(zip, Budget);
        var entry = Assert.Single(result.Archive!.Entries);
        Assert.False(entry.NameIsUtf8);
        Assert.Equal("r\u00E9sum\u00E9\u00A0x", entry.Name); // é from 0x82, NBSP from 0xFF
    }

    [Fact]
    public void Utf8FlaggedName_DecodedAsUtf8()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "börse/データ.txt",
            Utf8NameFlag = true,
            Data = new byte[] { 1 },
        });

        var result = ZipReader.Read(zip, Budget);
        var entry = Assert.Single(result.Archive!.Entries);
        Assert.True(entry.NameIsUtf8);
        Assert.Equal("börse/データ.txt", entry.Name);
    }

    [Fact]
    public void EmptyArchive_BareEocd_OkWithZeroEntries()
    {
        byte[] zip = ZipFixtureBuilder.Build();
        var result = ZipReader.Read(zip, Budget);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Empty(result.Archive!.Entries);
        Assert.Equal(0, result.Archive.DeclaredEntryCount);
    }

    [Fact]
    public void NotAZip_FailsLoudly()
    {
        byte[] junk = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("this is not a zip file at all...", 8)));
        var result = ZipReader.Read(junk, Budget);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("end-of-central-directory", result.Message);
        Assert.Null(result.Archive);
    }

    [Fact]
    public void MultipleEntries_EnumeratedInCentralDirectoryOrder()
    {
        byte[] zip = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "zeta.bin", Data = new byte[] { 1 } },
            new ZipEntryFixture { Name = "alpha.bin", Data = new byte[] { 2 } },
            new ZipEntryFixture { Name = "mid/way.bin", Data = new byte[] { 3 } });

        var result = ZipReader.Read(zip, Budget);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal(new[] { "zeta.bin", "alpha.bin", "mid/way.bin" }, result.Archive!.Entries.Select(e => e.Name));
        Assert.Equal(new[] { 0, 1, 2 }, result.Archive.Entries.Select(e => e.Index));
    }

    [Fact]
    public void SameBytes_ProduceIdenticalResults_Deterministic()
    {
        byte[] zip = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "x/один.txt", Utf8NameFlag = true, Data = Encoding.UTF8.GetBytes("payload one"), Method = 8 },
            new ZipEntryFixture { Name = "y.bin", Data = new byte[] { 9, 9, 9 } });

        var first = ZipReader.Read(zip, Budget);
        var second = ZipReader.Read(zip, Budget);
        Assert.Equal(OperationState.Ok, first.State);
        Assert.Equal(first.State, second.State);
        Assert.Equal(
            first.Archive!.Entries.Select(e => (e.Name, e.Crc32, e.CompressedSize, e.UncompressedSize, e.LocalHeaderOffset)),
            second.Archive!.Entries.Select(e => (e.Name, e.Crc32, e.CompressedSize, e.UncompressedSize, e.LocalHeaderOffset)));
    }

    [Fact]
    public void DirectoryEntry_IsDirectoryConvention()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "folder/", Data = Array.Empty<byte>() });
        var result = ZipReader.Read(zip, Budget);
        Assert.True(Assert.Single(result.Archive!.Entries).IsDirectory);
    }

    [Fact]
    public void InvalidDosTimestamp_NullAndFlagged_NotInvented()
    {
        // Month 0 does not encode a date; a made-up default would be a lie in a report.
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "t.bin",
            Data = new byte[] { 1 },
            DosDate = 0x0000,
        });
        var result = ZipReader.Read(zip, Budget);
        var entry = Assert.Single(result.Archive!.Entries);
        Assert.Null(entry.LastModified);
        Assert.Contains(entry.Anomalies, a => a.Contains("timestamp"));
    }

    [Fact]
    public void InputOverMaxInputBytes_RefusedAsIncomplete()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "a", Data = new byte[100] });
        var tight = Budget with { MaxInputBytes = 10 };
        var result = ZipReader.Read(zip, tight);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("budget", result.Message);
        Assert.Null(result.Archive);
    }

    [Fact]
    public void EntryCountOverBudgetCap_IncompleteWithPartialEnumeration()
    {
        byte[] zip = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "1", Data = new byte[] { 1 } },
            new ZipEntryFixture { Name = "2", Data = new byte[] { 2 } },
            new ZipEntryFixture { Name = "3", Data = new byte[] { 3 } });
        var result = ZipReader.Read(zip, Budget with { MaxMatches = 2 });
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Equal(2, result.Archive!.Entries.Count);
        Assert.Equal(3, result.Archive.DeclaredEntryCount);
        Assert.Contains(result.IncompleteReasons, r => r.Contains("cap"));
    }

    [Fact]
    public void Zip64Sentinels_ReportedUnsupported_NotMisparsed()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "a", Data = new byte[] { 1 } });
        // Overwrite the EOCD total-entries field (eocd+10) with the ZIP64 sentinel.
        int eocd = zip.Length - 22;
        zip[eocd + 10] = 0xFF;
        zip[eocd + 11] = 0xFF;
        zip[eocd + 8] = 0xFF;
        zip[eocd + 9] = 0xFF;
        var result = ZipReader.Read(zip, Budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("ZIP64", result.Message);
        Assert.Null(result.Archive);
    }
}
