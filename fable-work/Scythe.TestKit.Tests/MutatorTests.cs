using Scythe.TestKit;
using Xunit;
using static Scythe.TestKit.Tests.TestSupport;

namespace Scythe.TestKit.Tests;

/// <summary>Each standard mutation applied to the sample buffer produces exactly the intended difference and nothing else.</summary>
public sealed class MutatorTests
{
    private readonly Fixture fixture = SampleFixture.Build();
    private readonly byte[] original;

    public MutatorTests()
    {
        original = fixture.ToArray();
    }

    [Fact]
    public void TheSampleFixtureHasTheDocumentedLayout()
    {
        Assert.Equal(SampleFixture.Length, fixture.Length);
        Assert.Equal(30UL, fixture.ReadField("total_len"));
        Assert.Equal(18UL, fixture.ReadField("root_off"));
        Assert.Equal(22UL, fixture.ReadField("child_off"));
        Assert.Equal(new FixtureRegion("child", 22, 5, "root"), fixture.Region("child"));
    }

    [Fact]
    public void LengthTooLongYieldsOnePastTheBufferAndAllOnes()
    {
        var m = Mutations.Apply(fixture, Mutators.LengthTooLong("total_len"));

        Assert.Equal(2, m.Count);
        AssertDiffersOnlyAt(original, m[0].Bytes, 4);
        Assert.Equal(31, m[0].Bytes[4]);
        AssertDiffersOnlyAt(original, m[1].Bytes, 4, 5, 6, 7);
        Assert.Equal(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, m[1].Bytes[4..8]);
        Assert.Contains("'total_len'", m[0].Description, StringComparison.Ordinal);
        Assert.Contains("0x0000001E -> 0x0000001F", m[0].Description, StringComparison.Ordinal);
        Assert.Contains("buffer is 0x1E bytes", m[0].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void LengthTooLongOnANarrowFieldDropsCandidatesThatDoNotFit()
    {
        var wide = new FixtureBuilder(Endian.Little).Field("n", 1, 7).Pad(300).Build();

        var m = Mutations.Apply(wide, Mutators.LengthTooLong("n"));

        Assert.Single(m);
        Assert.Equal(0xFF, m[0].Bytes[0]);
    }

    [Fact]
    public void LengthTooShortSubtractsOne()
    {
        var m = Mutations.Apply(fixture, Mutators.LengthTooShort("count"));

        Assert.Single(m);
        AssertDiffersOnlyAt(original, m[0].Bytes, 12);
        Assert.Equal(2, m[0].Bytes[12]);
        Assert.Contains("0x0003 -> 0x0002", m[0].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void LengthZeroClearsTheField()
    {
        var m = Mutations.Apply(fixture, Mutators.LengthZero("count"));

        Assert.Single(m);
        AssertDiffersOnlyAt(original, m[0].Bytes, 12);
        Assert.Equal(0, m[0].Bytes[12]);
    }

    [Fact]
    public void OffsetPastEndYieldsTheBufferLengthAndAllOnes()
    {
        var m = Mutations.Apply(fixture, Mutators.OffsetPastEnd("root_off"));

        Assert.Equal(2, m.Count);
        AssertDiffersOnlyAt(original, m[0].Bytes, 8);
        Assert.Equal(30, m[0].Bytes[8]);
        AssertDiffersOnlyAt(original, m[1].Bytes, 8, 9, 10, 11);
    }

    [Fact]
    public void OffsetToSelfPointsAtTheContainingRegion()
    {
        var m = Mutations.Apply(fixture, Mutators.OffsetToSelf("child_off", "root"));

        Assert.Single(m);
        AssertDiffersOnlyAt(original, m[0].Bytes, 18);
        Assert.Equal(18, m[0].Bytes[18]);
        Assert.Contains("its own structure 'root' at 0x12", m[0].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void OffsetToParentPointsAtTheAncestor()
    {
        var m = Mutations.Apply(fixture, Mutators.OffsetToParent("child_off", "child"));

        Assert.Single(m);
        AssertDiffersOnlyAt(original, m[0].Bytes, 18);
        Assert.Equal(18, m[0].Bytes[18]);
        Assert.Contains("ancestor 'root'", m[0].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void OffsetToParentYieldsOneVariantPerAncestorNearestFirst()
    {
        var deep = new FixtureBuilder(Endian.Little)
            .Pad(1)
            .Region("a", b => b.Pad(1).Region("b", () => b.Pad(1).Region("c", () => b.Field("off", 1, 0x7F))))
            .Build();

        var m = Mutations.Apply(deep, Mutators.OffsetToParent("off", "c"));

        Assert.Equal(2, m.Count);
        Assert.Equal(2, m[0].Bytes[3]);
        Assert.Contains("'b'", m[0].Description, StringComparison.Ordinal);
        Assert.Equal(1, m[1].Bytes[3]);
        Assert.Contains("'a'", m[1].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void CountInflatedMultiplies()
    {
        var m = Mutations.Apply(fixture, Mutators.CountInflated("count", 1000));

        Assert.Single(m);
        AssertDiffersOnlyAt(original, m[0].Bytes, 12, 13);
        Assert.Equal(new byte[] { 0xB8, 0x0B }, m[0].Bytes[12..14]);
        Assert.Contains("x1000", m[0].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void CountInflatedSaturatesAtTheWidth()
    {
        var m = Mutations.Apply(fixture, Mutators.CountInflated("cell_size", 1000));

        Assert.Single(m);
        AssertDiffersOnlyAt(original, m[0].Bytes, 22);
        Assert.Equal(0xFF, m[0].Bytes[22]);
        Assert.Contains("saturated at 0xFF", m[0].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void TruncateAtCutsAtStartOneShortAndEnd()
    {
        var m = Mutations.Apply(fixture, Mutators.TruncateAt("child"));

        Assert.Equal(new[] { 22, 26, 27 }, m.Select(x => x.Bytes.Length));
        Assert.All(m, x => Assert.Equal(original[..x.Bytes.Length], x.Bytes));
        Assert.Contains("at the start of 'child': 30 -> 22 bytes", m[0].Description, StringComparison.Ordinal);
        Assert.Contains("one byte before the end of 'child'", m[1].Description, StringComparison.Ordinal);
        Assert.Contains("at the end of 'child'", m[2].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void TruncateAtTheFirstRegionIncludesTheEmptyBuffer()
    {
        var m = Mutations.Apply(fixture, Mutators.TruncateAt("header"));

        Assert.Equal(new[] { 0, 17, 18 }, m.Select(x => x.Bytes.Length));
    }

    [Fact]
    public void TruncateAtARegionEndingAtTheBufferEndOmitsTheWholeBufferCut()
    {
        var m = Mutations.Apply(fixture, Mutators.TruncateAt("tail"));

        Assert.Equal(new[] { 27, 29 }, m.Select(x => x.Bytes.Length));
    }

    [Fact]
    public void TruncateAtEveryBoundaryIsSortedDistinctAndNeverWhole()
    {
        var m = Mutations.Apply(fixture, Mutators.TruncateAtEveryBoundary());

        var lengths = m.Select(x => x.Bytes.Length).ToList();
        Assert.Equal(new[] { 0, 17, 18, 22, 26, 27, 29 }, lengths);
        Assert.All(m, x => Assert.Equal(original[..x.Bytes.Length], x.Bytes));
    }

    [Fact]
    public void CorruptChecksumFlipsCoveredDataAndSeparatelyTheStoredValue()
    {
        var m = Mutations.Apply(fixture, Mutators.CorruptChecksum("header"));

        Assert.Equal(2, m.Count);
        AssertDiffersOnlyAt(original, m[0].Bytes, 0);
        Assert.Equal(original[0] ^ 1, m[0].Bytes[0]);
        Assert.Contains("covered by Crc32 field 'header.crc32'", m[0].Description, StringComparison.Ordinal);
        AssertDiffersOnlyAt(original, m[1].Bytes, 14);
        Assert.Contains("stored Crc32 'header.crc32' at 0xE", m[1].Description, StringComparison.Ordinal);

        // Both variants make the stored value disagree with the bytes, which is the point.
        foreach (var variant in m)
        {
            var header = variant.Bytes[..18];
            Array.Clear(header, 14, 4);
            Assert.NotEqual(Checksums.Crc32(header), BitConverter.ToUInt32(variant.Bytes, 14));
        }
    }

    [Fact]
    public void FlipByteInYieldsOneVariantPerByte()
    {
        var m = Mutations.Apply(fixture, Mutators.FlipByteIn("child"));

        Assert.Equal(5, m.Count);
        for (int i = 0; i < 5; i++)
        {
            AssertDiffersOnlyAt(original, m[i].Bytes, 22 + i);
            Assert.Equal(original[22 + i] ^ 0xFF, m[i].Bytes[22 + i]);
        }

        Assert.Contains("byte at 0x16 in region 'child' inverted, 0x05 -> 0xFA", m[0].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void FlipByteAtInvertsOneAbsoluteOffset()
    {
        var m = Mutations.Apply(fixture, Mutators.FlipByteAt(29));

        Assert.Single(m);
        AssertDiffersOnlyAt(original, m[0].Bytes, 29);
        Assert.Equal(0xFF, m[0].Bytes[29]);
    }

    [Fact]
    public void InterleaveCopiesTheSecondRegionOverTheFirstsSecondHalf()
    {
        var m = Mutations.Apply(fixture, Mutators.Interleave("header", "child"));

        Assert.Single(m);
        // child (05 01 02 03 04) lands at 9..14; byte 12 was already 03, so it does not change.
        Assert.Equal(new byte[] { 5, 1, 2, 3, 4 }, m[0].Bytes[9..14]);
        AssertDiffersOnlyAt(original, m[0].Bytes, 9, 10, 11, 13);
        Assert.Equal(original[22..27], m[0].Bytes[22..27]);
        Assert.Contains("copied over 0x9..0xE", m[0].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void InterleaveClipsAtTheBufferEnd()
    {
        var f = new FixtureBuilder(Endian.Little).Region("a", b => b.Raw(1, 2, 3, 4)).Region("b", b => b.Raw(9, 9, 9, 9, 9, 9)).Build();

        var m = Mutations.Apply(f, Mutators.Interleave("b", "a"));

        Assert.Equal(10, m[0].Bytes.Length);
        Assert.Equal(new byte[] { 9, 9, 9, 1, 2, 3 }, m[0].Bytes[4..10]);
    }

    [Fact]
    public void OffsetIntoPointsAtTheMiddleOfTheRegion()
    {
        var m = Mutations.Apply(fixture, Mutators.OffsetInto("root_off", "child"));

        Assert.Single(m);
        AssertDiffersOnlyAt(original, m[0].Bytes, 8);
        Assert.Equal(24, m[0].Bytes[8]);
    }

    [Fact]
    public void SetFieldWritesTheValueInTheFieldsEndianness()
    {
        var m = Mutations.Apply(fixture, Mutators.SetField("count", 0x1234, "a count the buffer cannot hold"));

        Assert.Single(m);
        AssertDiffersOnlyAt(original, m[0].Bytes, 12, 13);
        Assert.Equal(new byte[] { 0x34, 0x12 }, m[0].Bytes[12..14]);
        Assert.EndsWith("— a count the buffer cannot hold", m[0].Description, StringComparison.Ordinal);
    }

    [Fact]
    public void SetFieldOnABigEndianSlotWritesBigEndian()
    {
        var f = new FixtureBuilder(Endian.Little).Field("be", 2, 0, Endian.Big).Build();

        var m = Mutations.Apply(f, Mutators.SetField("be", 0x1234));

        Assert.Equal(new byte[] { 0x12, 0x34 }, m[0].Bytes);
    }

    [Fact]
    public void CustomMutationsGetTheSameReporting()
    {
        var m = Mutations.Apply(fixture, Mutators.Custom("magic lower-cased", bytes =>
        {
            bytes[0] = (byte)'h';
            return bytes;
        }));

        Assert.Single(m);
        Assert.Equal("magic lower-cased", m[0].Description);
        Assert.Equal("magic lower-cased", m[0].ToString());
        AssertDiffersOnlyAt(original, m[0].Bytes, 0);
    }

    [Fact]
    public void ApplyConcatenatesMutatorsInOrderAndTheoryDataWrapsThem()
    {
        var m = Mutations.Apply(fixture, Mutators.LengthZero("count"), Mutators.FlipByteAt(0), Mutators.TruncateAt("tail"));

        Assert.Equal(4, m.Count);
        var rows = Mutations.TheoryData(m).ToList();
        Assert.Equal(4, rows.Count);
        Assert.All(rows, row => Assert.IsType<Mutation>(Assert.Single(row)));
        Assert.Same(m[2], rows[2][0]);
    }

    [Fact]
    public void MutationsNeverAliasTheFixturesBytes()
    {
        var m = Mutations.Apply(fixture, Mutators.LengthZero("count"));
        m[0].Bytes[0] = 0xEE;

        Assert.Equal(original, fixture.ToArray());
    }

    [Fact]
    public void MutationsComposeThroughWithBytes()
    {
        var first = Mutations.Apply(fixture, Mutators.LengthZero("count"))[0];
        var second = Mutations.Apply(fixture.WithBytes(first.Bytes), Mutators.LengthTooShort("cell_size"))[0];

        AssertDiffersOnlyAt(original, second.Bytes, 12, 22);
        Assert.Equal(0, second.Bytes[12]);
        Assert.Equal(4, second.Bytes[22]);
    }
}
