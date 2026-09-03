using System.Buffers.Binary;
using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

/// <summary>Ordinary input: every width and endianness round-trips through BinaryPrimitives, the independent reader.</summary>
public sealed class BuilderIntegerTests
{
    [Theory]
    [InlineData(Endian.Little)]
    [InlineData(Endian.Big)]
    public void UnsignedWidthsRoundTrip(Endian endian)
    {
        var bytes = new FixtureBuilder(endian).U8(0xAB).U16(0xBEEF).U32(0xDEADBEEF).U64(0x0123456789ABCDEF).Build().ToArray();

        Assert.Equal(15, bytes.Length);
        Assert.Equal(0xAB, bytes[0]);
        if (endian == Endian.Little)
        {
            Assert.Equal(0xBEEF, BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(1)));
            Assert.Equal(0xDEADBEEF, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(3)));
            Assert.Equal(0x0123456789ABCDEFUL, BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(7)));
        }
        else
        {
            Assert.Equal(0xBEEF, BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(1)));
            Assert.Equal(0xDEADBEEF, BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(3)));
            Assert.Equal(0x0123456789ABCDEFUL, BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(7)));
        }
    }

    [Theory]
    [InlineData(Endian.Little)]
    [InlineData(Endian.Big)]
    public void SignedWidthsRoundTripAsTwosComplement(Endian endian)
    {
        var bytes = new FixtureBuilder(endian).I8(-2).I16(-3).I32(-4).I64(-5).Build().ToArray();

        Assert.Equal(unchecked((byte)-2), bytes[0]);
        if (endian == Endian.Little)
        {
            Assert.Equal(-3, BinaryPrimitives.ReadInt16LittleEndian(bytes.AsSpan(1)));
            Assert.Equal(-4, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(3)));
            Assert.Equal(-5L, BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(7)));
        }
        else
        {
            Assert.Equal(-3, BinaryPrimitives.ReadInt16BigEndian(bytes.AsSpan(1)));
            Assert.Equal(-4, BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(3)));
            Assert.Equal(-5L, BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(7)));
        }
    }

    [Fact]
    public void LittleAndBigEndianBuildersDisagreeOnEveryMultiByteWidth()
    {
        var little = new FixtureBuilder(Endian.Little).U16(0x0102).U32(0x01020304).U64(0x0102030405060708).Build().ToArray();
        var big = new FixtureBuilder(Endian.Big).U16(0x0102).U32(0x01020304).U64(0x0102030405060708).Build().ToArray();

        Assert.Equal(new byte[] { 2, 1, 4, 3, 2, 1, 8, 7, 6, 5, 4, 3, 2, 1 }, little);
        Assert.Equal(new byte[] { 1, 2, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8 }, big);
    }

    [Fact]
    public void PerCallOverridesIgnoreTheBuildersOrder()
    {
        // A little-endian builder writing big-endian fields, as a format that mixes both would need.
        var bytes = new FixtureBuilder(Endian.Little)
            .U16Be(0x0102).U32Be(0x01020304).U64Be(0x0102030405060708)
            .U16Le(0x0102).U32Le(0x01020304).U64Le(0x0102030405060708)
            .Build().ToArray();

        Assert.Equal(new byte[] { 1, 2, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8 }, bytes[..14]);
        Assert.Equal(new byte[] { 2, 1, 4, 3, 2, 1, 8, 7, 6, 5, 4, 3, 2, 1 }, bytes[14..]);
    }

    [Fact]
    public void SignedPerCallOverridesMatchBinaryPrimitives()
    {
        var bytes = new FixtureBuilder(Endian.Big).I16Le(-300).I32Le(-70000).I64Le(-5_000_000_000).I16Be(-300).I32Be(-70000).I64Be(-5_000_000_000).Build().ToArray();

        Assert.Equal(-300, BinaryPrimitives.ReadInt16LittleEndian(bytes.AsSpan(0)));
        Assert.Equal(-70000, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(2)));
        Assert.Equal(-5_000_000_000, BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(6)));
        Assert.Equal(-300, BinaryPrimitives.ReadInt16BigEndian(bytes.AsSpan(14)));
        Assert.Equal(-70000, BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(16)));
        Assert.Equal(-5_000_000_000, BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(20)));
    }

    [Fact]
    public void GenericIntRejectsAValueWiderThanTheSlot()
    {
        var b = new FixtureBuilder(Endian.Little);

        var e = TestSupport.Throws(() => b.Int(2, 0x10000, Endian.Little));

        Assert.Contains("does not fit in 2 byte(s)", e.Message, StringComparison.Ordinal);
        Assert.Equal(0, b.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(16)]
    public void GenericIntRejectsAnUnsupportedWidth(int width)
    {
        var e = TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Int(width, 1, Endian.Little));

        Assert.Contains("unsupported integer width", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PositionAndLengthAdvanceTogether()
    {
        var b = new FixtureBuilder(Endian.Little);
        Assert.Equal(0, b.Position);

        b.U32(1).U8(2);

        Assert.Equal(5, b.Position);
        Assert.Equal(5, b.Length);
    }
}
