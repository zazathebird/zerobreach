using System.Buffers.Binary;
using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

public sealed class ChecksumTests
{
    [Fact]
    public void Crc32MatchesThePublishedCheckValue()
    {
        // The CRC-32 check value from the ITU/zlib specification: "123456789" -> 0xCBF43926.
        Assert.Equal(0xCBF43926u, Checksums.Crc32("123456789"u8));
        Assert.Equal(0u, Checksums.Crc32(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Crc32SlotIsFilledOverARegionWrittenAfterIt()
    {
        var f = new FixtureBuilder(Endian.Little)
            .Crc32("data")
            .Region("data", b => b.Ascii("123456789"))
            .Build();

        Assert.Equal(0xCBF43926UL, f.ReadField("data.crc32"));
        Assert.Equal(new byte[] { 0x26, 0x39, 0xF4, 0xCB }, f.ToArray()[..4]);
        Assert.Single(f.Checksums);
        Assert.Equal(new FixtureChecksum("data.crc32", "data", ChecksumKind.Crc32), f.Checksums[0]);
    }

    [Fact]
    public void Crc32SlotCanBeBigEndianAndNamed()
    {
        var f = new FixtureBuilder(Endian.Little)
            .Region("data", b => b.Ascii("123456789"))
            .Crc32("data", fieldName: "trailer_crc", endian: Endian.Big)
            .Build();

        Assert.Equal(new byte[] { 0xCB, 0xF4, 0x39, 0x26 }, f.ToArray()[9..]);
        Assert.Equal(0xCBF43926UL, f.ReadField("trailer_crc"));
    }

    [Fact]
    public void AChecksumSlotInsideItsOwnRegionIsTakenAsZeroWhileComputing()
    {
        var f = new FixtureBuilder(Endian.Little)
            .Region("header", b => b.Ascii("HDR!").Crc32("header").U32(0x11223344))
            .Build();

        var bytes = f.ToArray();
        var zeroed = (byte[])bytes.Clone();
        Array.Clear(zeroed, 4, 4);
        Assert.Equal(Checksums.Crc32(zeroed), (uint)f.ReadField("header.crc32"));
        Assert.NotEqual(Checksums.Crc32(bytes), (uint)f.ReadField("header.crc32"));
    }

    [Fact]
    public void ChecksumCoversResolvedPlaceholderValuesNotTheZeroedSlots()
    {
        var f = new FixtureBuilder(Endian.Little)
            .Crc32("body")
            .Region("body", b => b.Placeholder("p", 4).ResolveToLength("p"))
            .Build();

        var body = f.RegionBytes("body");
        Assert.Equal(8u, BinaryPrimitives.ReadUInt32LittleEndian(body));
        Assert.Equal(Checksums.Crc32(body), (uint)f.ReadField("body.crc32"));
    }

    [Theory]
    [InlineData(1, 0x01UL)]   // 0x101 mod 0x100
    [InlineData(2, 0x0101UL)]
    public void SumIsReducedToTheSlotWidth(int width, ulong expected)
    {
        var f = new FixtureBuilder(Endian.Little)
            .Region("d", b => b.Raw(0xFF, 0x02))
            .Sum("d", width)
            .Build();

        Assert.Equal(expected, f.ReadField("d.sum"));
    }

    [Fact]
    public void XorFoldFoldsWordsInTheSlotsEndianness()
    {
        // Words 0x04030201 and 0x08070605 little-endian; XOR = 0x0C040404. Then a fixture with
        // an odd trailing word to show the endianness and the zero padding.
        var even = new FixtureBuilder(Endian.Little).Region("d", b => b.Raw(1, 2, 3, 4, 5, 6, 7, 8)).XorFold("d").Build();
        Assert.Equal(0x0C040404UL, even.ReadField("d.xor"));

        var le = new FixtureBuilder(Endian.Little).Region("d", b => b.Raw(1, 2, 3, 4, 0xAA)).XorFold("d").Build();
        var be = new FixtureBuilder(Endian.Big).Region("d", b => b.Raw(1, 2, 3, 4, 0xAA)).XorFold("d").Build();
        Assert.Equal(0x04030201UL ^ 0x000000AAUL, le.ReadField("d.xor"));
        Assert.Equal(0x01020304UL ^ 0xAA000000UL, be.ReadField("d.xor"));
    }

    [Fact]
    public void XorFoldWidthTwoUsesTwoByteWords()
    {
        var f = new FixtureBuilder(Endian.Little).Region("d", b => b.Raw(1, 2, 3, 4)).XorFold("d", 2).Build();

        Assert.Equal(0x0201UL ^ 0x0403UL, f.ReadField("d.xor"));
    }

    [Fact]
    public void ACustomChecksumUsesTheSuppliedFunction()
    {
        var f = new FixtureBuilder(Endian.Little)
            .Region("d", b => b.Raw(1, 2, 3))
            .Checksum("d", 1, ChecksumKind.Custom, bytes => (ulong)bytes.Length, "count")
            .Build();

        Assert.Equal(3UL, f.ReadField("count"));
        Assert.Equal(ChecksumKind.Custom, f.Checksums[0].Kind);
    }

    [Fact]
    public void AChecksumOverAnUnknownRegionThrowsAtBuild()
    {
        var b = new FixtureBuilder(Endian.Little).Crc32("missing");

        var e = TestSupport.Throws(() => b.Build());

        Assert.Contains("no region named 'missing'", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ACustomChecksumWiderThanItsSlotThrowsAtBuild()
    {
        var b = new FixtureBuilder(Endian.Little).Region("d", x => x.U8(1)).Checksum("d", 1, ChecksumKind.Custom, _ => 0x100, "c");

        var e = TestSupport.Throws(() => b.Build());

        Assert.Contains("does not fit 1 byte(s)", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AChecksumSlotCannotAlsoBeResolvedByHand()
    {
        var b = new FixtureBuilder(Endian.Little).Region("d", x => x.U8(1)).Crc32("d");

        var e = TestSupport.Throws(() => b.ResolveToLength("d.crc32"));

        Assert.Contains("filled at Build()", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void XorFoldRejectsAnUnsupportedWidth()
    {
        TestSupport.Throws(() => Checksums.XorFold(new byte[] { 1 }, 3, Endian.Little));
    }
}
