using System.Text;
using ZeroBreach.Formats;
using ZeroBreach.Formats.Containers;
using Xunit;

namespace ZeroBreach.Formats.Tests.Containers;

/// <summary>
/// The hostile set from the task brief: traversal names, encrypted entries, decompression
/// bombs (the required budget canary lives here), lying and overlapping headers, truncation.
/// </summary>
public class ZipHostileTests
{
    private static ScanBudget Budget => BudgetDefaults.Default;

    // --- Path traversal -----------------------------------------------------------------

    [Theory]
    [InlineData("../evil.dll", PathAnomalies.ParentTraversal)]
    [InlineData("a/../../evil.dll", PathAnomalies.ParentTraversal)]
    [InlineData("..\\windows\\evil.dll", PathAnomalies.ParentTraversal)]
    [InlineData("/etc/passwd", PathAnomalies.AbsolutePath)]
    [InlineData("\\boot.ini", PathAnomalies.AbsolutePath)]
    [InlineData("C:\\windows\\system32\\evil.dll", PathAnomalies.DriveQualified)]
    [InlineData("c:relative.dll", PathAnomalies.DriveQualified)]
    public void TraversalNames_ReportedAsDistinctAnomaly(string name, PathAnomalies expected)
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = name, Data = new byte[] { 1 } });
        var result = ZipReader.Read(zip, Budget);
        var entry = Assert.Single(result.Archive!.Entries);
        Assert.True(entry.PathAnomalies.HasFlag(expected), $"{name} should carry {expected}, has {entry.PathAnomalies}");
        // Never resolved: the raw declared name is surfaced untouched.
        Assert.Equal(name, entry.Name);
    }

    [Fact]
    public void NulByteInName_Flagged()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "placeholder",
            NameBytesOverride = new byte[] { (byte)'a', 0x00, (byte)'b' },
            Data = new byte[] { 1 },
        });
        var entry = Assert.Single(ZipReader.Read(zip, Budget).Archive!.Entries);
        Assert.True(entry.PathAnomalies.HasFlag(PathAnomalies.ContainsNulOrControl));
    }

    [Fact]
    public void DotDotInFileName_NotASegment_NotFlagged()
    {
        // "a..b.txt" contains dots but no ".." *segment*; flagging it would flood reports.
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "a..b.txt", Data = new byte[] { 1 } });
        var entry = Assert.Single(ZipReader.Read(zip, Budget).Archive!.Entries);
        Assert.Equal(PathAnomalies.None, entry.PathAnomalies);
    }

    // --- Encryption ---------------------------------------------------------------------

    [Fact]
    public void EncryptedEntry_ReportedPresentButUnreadable_NeverSkipped()
    {
        byte[] zip = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "clear.txt", Data = Encoding.ASCII.GetBytes("in the clear") },
            new ZipEntryFixture { Name = "secret.txt", Data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, Encrypted = true });

        var result = ZipReader.Read(zip, Budget);
        Assert.Equal(2, result.Archive!.Entries.Count); // present, not skipped
        var secret = result.Archive.Entries[1];
        Assert.True(secret.IsEncrypted);

        var read = ZipReader.ReadEntry(zip, secret, Budget);
        Assert.Equal(OperationState.Incomplete, read.State);
        Assert.Contains("encrypted", read.Reason);
        Assert.Null(read.Bytes);
    }

    // --- Decompression bombs ------------------------------------------------------------

    /// <summary>
    /// BUDGET CANARY (required by the brief): a known bomb — megabytes of zeros deflating
    /// to a few KiB — asserted to be *stopped* by the ratio guard under default settings.
    /// If this test ever passes with an Ok state, the guard section has become a no-op.
    /// </summary>
    [Fact]
    public void Canary_KnownBomb_StoppedByRatioGuard()
    {
        byte[] zeros = new byte[8 * 1024 * 1024];
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "bomb.bin", Data = zeros, Method = 8 });
        var entry = Assert.Single(ZipReader.Read(zip, Budget).Archive!.Entries);
        Assert.True(entry.CompressedSize < 64 * 1024, "fixture must actually be a high-ratio bomb");
        // Enumeration already warns from declared sizes alone.
        Assert.Contains(entry.Anomalies, a => a.Contains("ratio"));

        var read = ZipReader.ReadEntry(zip, entry, Budget);
        Assert.Equal(OperationState.Incomplete, read.State);
        Assert.Contains("ratio", read.Reason);
        Assert.Null(read.Bytes);
    }

    [Fact]
    public void Bomb_TotalExpansionGuard_TripsAcrossEntries()
    {
        byte[] eighty = new byte[80 * 1024];
        new Random(7).NextBytes(eighty); // incompressible so the ratio guard stays silent
        byte[] zip = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "one.bin", Data = eighty, Method = 0 },
            new ZipEntryFixture { Name = "two.bin", Data = eighty, Method = 0 });
        var archive = ZipReader.Read(zip, Budget).Archive!;

        var guard = new ExpansionGuard(maxTotalExpandedBytes: 100 * 1024);
        var first = ZipReader.ReadEntry(zip, archive.Entries[0], Budget, guard);
        Assert.Equal(OperationState.Ok, first.State);

        var second = ZipReader.ReadEntry(zip, archive.Entries[1], Budget, guard);
        Assert.Equal(OperationState.Incomplete, second.State);
        Assert.Contains("cap", second.Reason);
        Assert.Null(second.Bytes);
    }

    [Fact]
    public void DeadlineZero_Canary_IncompleteNeverSilentNoMatch()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "a.bin", Data = new byte[] { 1, 2, 3 } });
        var expired = Budget with { Deadline = TimeSpan.Zero };

        var read = ZipReader.Read(zip, expired);
        Assert.Equal(OperationState.Incomplete, read.State);
        Assert.Contains("deadline", read.Message);

        var archive = ZipReader.Read(zip, Budget).Archive!;
        var entry = ZipReader.ReadEntry(zip, archive.Entries[0], expired);
        Assert.Equal(OperationState.Incomplete, entry.State);
        Assert.Contains("deadline", entry.Reason);
    }

    // --- Central directory vs local headers ---------------------------------------------

    [Fact]
    public void LyingCentralDirectory_BothSidesReported_HostDecides()
    {
        byte[] content = Encoding.ASCII.GetBytes("the actual payload bytes here");
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "true-name.txt",
            Data = content,
            Method = 0,
            CdNameOverride = "innocent.txt",
            CdCrcOverride = 0x12345678,
            CdUncompressedSizeOverride = 5,
        });

        var result = ZipReader.Read(zip, Budget);
        // Disagreement is data for the host, not an error: enumeration itself completed.
        Assert.Equal(OperationState.Ok, result.State);
        var entry = Assert.Single(result.Archive!.Entries);

        Assert.Equal("innocent.txt", entry.Name);              // what the CD claims
        Assert.Equal("true-name.txt", entry.LocalHeader!.Name); // what the local header claims
        Assert.Contains(entry.Mismatches, m => m.Contains("name"));
        Assert.Contains(entry.Mismatches, m => m.Contains("crc32"));
        Assert.Contains(entry.Mismatches, m => m.Contains("uncompressed size"));

        // Reading still recovers the physical bytes, and reports CRC agreement per side.
        var read = ZipReader.ReadEntry(zip, entry, Budget);
        Assert.Equal(OperationState.Ok, read.State);
        Assert.Equal(content, read.Bytes);
        Assert.False(read.CrcMatchesCentralDirectory);
        Assert.True(read.CrcMatchesLocalHeader);
        Assert.Contains(read.Notes, n => n.Contains("central directory"));
    }

    [Fact]
    public void OverlappingEntries_SharedLocalHeader_ReportedAsArchiveAnomaly()
    {
        byte[] zip = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "a.bin", Data = new byte[] { 1, 2, 3, 4 } },
            new ZipEntryFixture { Name = "b.bin", Data = new byte[] { 5, 6, 7, 8 }, CdLocalOffsetOverride = 0 });

        var result = ZipReader.Read(zip, Budget);
        Assert.Contains(result.Archive!.ArchiveAnomalies, a => a.Contains("overlap"));
        // The second entry's local header (entry 0's) disagrees with its CD record.
        Assert.Contains(result.Archive.Entries[1].Mismatches, m => m.Contains("name"));
    }

    [Fact]
    public void CdPointsPastEndOfFile_LocalHeaderUnreadable_ReadIncomplete()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "ghost.bin",
            Data = new byte[] { 1 },
            CdLocalOffsetOverride = 0x00FFFFFF,
        });
        var entry = Assert.Single(ZipReader.Read(zip, Budget).Archive!.Entries);
        Assert.Null(entry.LocalHeader);
        Assert.Contains(entry.Anomalies, a => a.Contains("past the end"));

        var read = ZipReader.ReadEntry(zip, entry, Budget);
        Assert.Equal(OperationState.Incomplete, read.State);
        Assert.Null(read.Bytes);
    }

    // --- Truncation ---------------------------------------------------------------------

    [Fact]
    public void TruncatedTail_NoEocd_Failed()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "a.bin", Data = new byte[64] });
        byte[] cut = zip.AsSpan(0, zip.Length - 30).ToArray(); // EOCD gone
        var result = ZipReader.Read(cut, Budget);
        Assert.Equal(OperationState.Failed, result.State);
    }

    [Fact]
    public void CentralDirectoryRangeBeyondEocd_Incomplete_NotOk()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "a.bin", Data = new byte[64] });
        // Rewrite the EOCD's CD-offset field to point past its own record.
        int eocd = zip.Length - 22;
        ZipFixtureBuilder.WriteU32At(zip, eocd + 16, (uint)zip.Length);
        var result = ZipReader.Read(zip, Budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("truncated", result.Message);
        Assert.Null(result.Archive);
    }

    [Fact]
    public void TruncatedEntryData_ReadIsIncomplete_NeverACleanRead()
    {
        byte[] payload = new byte[4096];
        new Random(3).NextBytes(payload);
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "big.bin",
            Data = payload,
            Method = 0,
            // CD and local both claim 4096 bytes, but the physical bytes are cut short below.
        });
        // Cut inside the entry data, then re-append a fresh EOCD-less tail is complex; instead
        // lie upward: declare more data than exists by bumping both size fields.
        var entry = Assert.Single(ZipReader.Read(zip, Budget).Archive!.Entries);
        long dataOffset = entry.LocalHeader!.DataOffset;
        // Truncate the archive to half the entry's data; the CD is gone, so rebuild a minimal
        // EOCD claiming the same central directory at its original offset — the result is a
        // file whose entry data physically stops early.
        int keep = (int)dataOffset + payload.Length / 2;
        var truncated = new MemoryStream();
        truncated.Write(zip, 0, keep);
        long cdOffset = keep; // write a fresh CD describing the full-size entry
        ZipFixtureBuilder.WriteU32(truncated, 0x02014B50);
        ZipFixtureBuilder.WriteU16(truncated, 20);
        ZipFixtureBuilder.WriteU16(truncated, 20);
        ZipFixtureBuilder.WriteU16(truncated, 0);
        ZipFixtureBuilder.WriteU16(truncated, 0);           // stored
        ZipFixtureBuilder.WriteU16(truncated, 0);
        ZipFixtureBuilder.WriteU16(truncated, 0x58CF);
        ZipFixtureBuilder.WriteU32(truncated, entry.Crc32);
        ZipFixtureBuilder.WriteU32(truncated, (uint)payload.Length);
        ZipFixtureBuilder.WriteU32(truncated, (uint)payload.Length);
        ZipFixtureBuilder.WriteU16(truncated, (ushort)"big.bin".Length);
        ZipFixtureBuilder.WriteU16(truncated, 0);
        ZipFixtureBuilder.WriteU16(truncated, 0);
        ZipFixtureBuilder.WriteU16(truncated, 0);
        ZipFixtureBuilder.WriteU16(truncated, 0);
        ZipFixtureBuilder.WriteU32(truncated, 0);
        ZipFixtureBuilder.WriteU32(truncated, 0);           // local offset 0
        truncated.Write(Encoding.ASCII.GetBytes("big.bin"));
        long cdSize = truncated.Length - cdOffset;
        ZipFixtureBuilder.WriteU32(truncated, 0x06054B50);
        ZipFixtureBuilder.WriteU16(truncated, 0);
        ZipFixtureBuilder.WriteU16(truncated, 0);
        ZipFixtureBuilder.WriteU16(truncated, 1);
        ZipFixtureBuilder.WriteU16(truncated, 1);
        ZipFixtureBuilder.WriteU32(truncated, (uint)cdSize);
        ZipFixtureBuilder.WriteU32(truncated, (uint)cdOffset);
        ZipFixtureBuilder.WriteU16(truncated, 0);
        byte[] bytes = truncated.ToArray();

        var reparsed = ZipReader.Read(bytes, Budget);
        var cutEntry = Assert.Single(reparsed.Archive!.Entries);
        Assert.Contains(cutEntry.Anomalies, a => a.Contains("truncated"));

        var read = ZipReader.ReadEntry(bytes, cutEntry, Budget);
        Assert.Equal(OperationState.Incomplete, read.State);
        Assert.Contains("truncated", read.Reason);
        Assert.Null(read.Bytes); // a truncated read is never handed over as a clean one
    }

    [Fact]
    public void CorruptDeflateStream_Failed_WithEntryNamed()
    {
        byte[] good = ZipFixtureBuilder.Deflate(Encoding.ASCII.GetBytes("some sensible payload data"));
        byte[] garbage = new byte[good.Length];
        new Random(11).NextBytes(garbage);
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "corrupt.bin",
            Data = Encoding.ASCII.GetBytes("some sensible payload data"),
            Method = 8,
            CompressedOverride = garbage,
        });
        var entry = Assert.Single(ZipReader.Read(zip, Budget).Archive!.Entries);
        var read = ZipReader.ReadEntry(zip, entry, Budget);
        Assert.Equal(OperationState.Failed, read.State);
        Assert.Contains("corrupt.bin", read.Reason);
    }

    [Fact]
    public void UnsupportedCompressionMethod_Incomplete_NotSilentlySkipped()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture
        {
            Name = "lzma.bin",
            Data = new byte[] { 1, 2, 3 },
            Method = 14, // LZMA
        });
        var entry = Assert.Single(ZipReader.Read(zip, Budget).Archive!.Entries);
        var read = ZipReader.ReadEntry(zip, entry, Budget);
        Assert.Equal(OperationState.Incomplete, read.State);
        Assert.Contains("method 14", read.Reason);
    }
}
