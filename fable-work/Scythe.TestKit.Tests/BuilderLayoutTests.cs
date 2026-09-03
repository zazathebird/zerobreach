using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

public sealed class BuilderLayoutTests
{
    [Fact]
    public void PadAndZeroesWriteZeroBytes()
    {
        var bytes = new FixtureBuilder(Endian.Little).U8(1).Pad(2).Zeroes(1).U8(2).Build().ToArray();

        Assert.Equal(new byte[] { 1, 0, 0, 0, 2 }, bytes);
    }

    [Fact]
    public void PadToFillsUpToTheOffset()
    {
        var b = new FixtureBuilder(Endian.Little).U8(1).PadTo(4);

        Assert.Equal(4, b.Length);
        Assert.Equal(new byte[] { 1, 0, 0, 0 }, b.Build().ToArray());
    }

    [Fact]
    public void PadToTheCurrentOffsetWritesNothing()
    {
        var b = new FixtureBuilder(Endian.Little).U8(1).PadTo(1);

        Assert.Equal(1, b.Length);
    }

    [Fact]
    public void PadToBackwardsIsAnError()
    {
        var e = TestSupport.Throws(() => new FixtureBuilder(Endian.Little).U32(1).PadTo(2));

        Assert.Contains("only appends", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AlignPadsToTheNextMultiple()
    {
        var b = new FixtureBuilder(Endian.Little).U8(1).Align(8);

        Assert.Equal(8, b.Length);
    }

    [Fact]
    public void AlignOnAnAlignedOffsetWritesNothing()
    {
        var b = new FixtureBuilder(Endian.Little).U32(1).Align(4);

        Assert.Equal(4, b.Length);
    }

    [Fact]
    public void AlignToAPageFromTheReferenceScript()
    {
        var b = new FixtureBuilder(Endian.Little).Ascii("REGF").Align(4096);

        Assert.Equal(4096, b.Position);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-4)]
    public void AlignRejectsANonPositiveAlignment(int alignment)
    {
        TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Align(alignment));
    }

    [Fact]
    public void FillRepeatsTheByte()
    {
        var bytes = new FixtureBuilder(Endian.Little).Fill(0xCC, 3).Build().ToArray();

        Assert.Equal(new byte[] { 0xCC, 0xCC, 0xCC }, bytes);
    }

    [Fact]
    public void FillOfZeroCountWritesNothing()
    {
        Assert.Equal(0, new FixtureBuilder(Endian.Little).Fill(0xCC, 0).Length);
    }

    [Fact]
    public void NegativeCountsAreErrorsNotSilence()
    {
        Assert.Contains("cannot be negative", TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Fill(0, -1)).Message, StringComparison.Ordinal);
        Assert.Contains("cannot be negative", TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Zeroes(-1)).Message, StringComparison.Ordinal);
        Assert.Contains("cannot be negative", TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Ascii("a", -1)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RawWritesBytesVerbatimFromArrayAndSpan()
    {
        var bytes = new FixtureBuilder(Endian.Little).Raw(1, 2).Raw(new byte[] { 3, 4 }.AsSpan()).Build().ToArray();

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, bytes);
    }

    [Fact]
    public void RegionsRecordTheBytesTheirBodyWrote()
    {
        var f = new FixtureBuilder(Endian.Little)
            .U32(0)
            .Region("body", b => b.U16(1).U16(2))
            .U8(9)
            .Build();

        var region = f.Region("body");
        Assert.Equal(4, region.Offset);
        Assert.Equal(4, region.Length);
        Assert.Equal(8, region.End);
        Assert.Null(region.Parent);
        Assert.Equal(new byte[] { 1, 0, 2, 0 }, f.RegionBytes("body"));
    }

    [Fact]
    public void NestedRegionsAreBufferRelativeAndKnowTheirParent()
    {
        var f = new FixtureBuilder(Endian.Little)
            .Pad(10)
            .Region("outer", b => b.Pad(3).Region("inner", () => b.Pad(2)).Pad(1))
            .Build();

        var inner = f.Region("inner");
        Assert.Equal(13, inner.Offset);
        Assert.Equal(2, inner.Length);
        Assert.Equal("outer", inner.Parent);
        Assert.Equal(new[] { "outer", "inner" }, f.Regions.Select(r => r.Name));
        Assert.Equal(new[] { "outer" }, f.Ancestors("inner").Select(r => r.Name));
        Assert.Empty(f.Ancestors("outer"));
    }

    [Fact]
    public void AnEmptyRegionIsRecordedWithZeroLength()
    {
        var f = new FixtureBuilder(Endian.Little).U8(1).Region("empty", () => { }).Build();

        Assert.Equal(1, f.Region("empty").Offset);
        Assert.Equal(0, f.Region("empty").Length);
    }
}
