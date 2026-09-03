using System.Buffers.Binary;
using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

/// <summary>
/// Placeholder back-fill is the part of the kit the brief calls most likely to be got wrong:
/// resolution order must not be able to make a fixture inconsistent, and every failure mode
/// (unresolved, resolved twice, too wide) must be an error rather than a quiet zero.
/// </summary>
public sealed class PlaceholderTests
{
    private static Fixture ReferenceScript()
    {
        // The script from reference/17.1_builder.md, verbatim in shape.
        var b = new FixtureBuilder(Endian.Little);
        b.Region("header", () =>
        {
            b.Ascii("REGF", 4);
            b.Placeholder("total_size", 4);
            b.U32(1);
            b.Placeholder("root_offset", 4);
        });
        b.Align(4096);
        b.Resolve("root_offset", b.Position);
        b.Region("root", () =>
        {
            b.U16(0x6B6E);
            b.LengthPrefixed(FixtureBuilder.Utf16LittleEndian, "Software", prefixWidth: 2, unit: LengthUnit.Bytes);
        });
        b.Resolve("total_size", b.Length);
        return b.Build();
    }

    [Fact]
    public void TheReferenceScriptProducesAConsistentHeader()
    {
        var f = ReferenceScript();
        var bytes = f.ToArray();

        Assert.Equal(4096 + 2 + 2 + 16, bytes.Length);
        Assert.Equal((uint)bytes.Length, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(8)));
        Assert.Equal(4096u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(12)));
        Assert.Equal(4096, f.Region("root").Offset);
        Assert.Equal(20, f.Region("root").Length);
        Assert.Equal(0x6B6E, BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(4096)));
        Assert.Equal(16, BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(4098)));
    }

    [Fact]
    public void ResolvedPlaceholdersAreRecordedAsFieldsWithTheirValues()
    {
        var f = ReferenceScript();

        var total = f.Field("total_size");
        Assert.Equal(4, total.Offset);
        Assert.Equal(4, total.Width);
        Assert.Equal(Endian.Little, total.Endian);
        Assert.Equal((ulong)f.Length, total.Value);
        Assert.Equal((ulong)f.Length, f.ReadField("total_size"));
        Assert.Equal(4096UL, f.ReadField("root_offset"));
        Assert.Equal(new[] { "total_size", "root_offset" }, f.Fields.Select(x => x.Name));
    }

    [Fact]
    public void AForwardReferenceIsFilledWhereItWasReserved()
    {
        var b = new FixtureBuilder(Endian.Big);
        b.Placeholder("p", 2).U8(0xAA);
        b.Resolve("p", 0x1234);

        Assert.Equal(new byte[] { 0x12, 0x34, 0xAA }, b.Build().ToArray());
    }

    [Fact]
    public void SeveralPlaceholdersResolveIndependentlyInAnyOrder()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("a", 1).Placeholder("b", 2).Placeholder("c", 4);
        b.Resolve("c", 3).Resolve("a", 1).Resolve("b", 2);

        Assert.Equal(new byte[] { 1, 2, 0, 3, 0, 0, 0 }, b.Build().ToArray());
    }

    [Fact]
    public void PlaceholderEndianCanBeOverriddenPerSlot()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("be", 2, Endian.Big).Placeholder("le", 2);
        b.Resolve("be", 0x0102).Resolve("le", 0x0102);

        Assert.Equal(new byte[] { 1, 2, 2, 1 }, b.Build().ToArray());
    }

    [Fact]
    public void ANestedOuterSizeCanDependOnAnInnerRegionResolvedLater()
    {
        // The header's size field covers a body whose own size is only known after an inner
        // structure of variable length has been written. Both are declared before either body
        // exists; both are computed at Build().
        var b = new FixtureBuilder(Endian.Little);
        b.Region("header", () =>
        {
            b.Placeholder("body_size", 4);
            b.Placeholder("inner_size", 2);
        });
        b.ResolveToRegionLength("body_size", "body");
        b.ResolveToRegionLength("inner_size", "inner");
        b.Region("body", () =>
        {
            b.U32(0xFFFFFFFF);
            b.Region("inner", () => b.LengthPrefixed(FixtureBuilder.Utf8NoBom, "hello, world", 1, LengthUnit.Bytes));
            b.U8(0);
        });
        var f = b.Build();

        Assert.Equal(4 + 13 + 1, (int)f.ReadField("body_size"));
        Assert.Equal(13, (int)f.ReadField("inner_size"));
        Assert.Equal(f.Region("body").Length, (int)f.ReadField("body_size"));
        Assert.Equal(f.Region("inner").Length, (int)f.ReadField("inner_size"));
    }

    [Fact]
    public void DeferredResolutionDeclaredBeforeOrAfterTheRegionGivesIdenticalBytes()
    {
        static Fixture Script(bool declareFirst)
        {
            var b = new FixtureBuilder(Endian.Little);
            b.Placeholder("start", 4).Placeholder("len", 4).Placeholder("end", 4).Placeholder("total", 4);
            if (declareFirst)
            {
                b.ResolveToRegionStart("start", "r").ResolveToRegionLength("len", "r").ResolveToRegionEnd("end", "r").ResolveToLength("total");
            }

            b.Pad(3).Region("r", () => b.Ascii("payload")).Pad(5);
            if (!declareFirst)
            {
                b.ResolveToRegionStart("start", "r").ResolveToRegionLength("len", "r").ResolveToRegionEnd("end", "r").ResolveToLength("total");
            }

            return b.Build();
        }

        var first = Script(true);
        var second = Script(false);

        Assert.Equal(first.ToArray(), second.ToArray());
        Assert.Equal(19UL, first.ReadField("start"));
        Assert.Equal(7UL, first.ReadField("len"));
        Assert.Equal(26UL, first.ReadField("end"));
        Assert.Equal((ulong)first.Length, first.ReadField("total"));
    }

    [Fact]
    public void ResolveLaterSeesTheFinishedBufferNotTheBufferAtDeclaration()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 4);
        b.ResolveLater("p", "the final length", x => x.Length);
        b.Pad(100);

        Assert.Equal(104UL, b.Build().ReadField("p"));
    }

    [Fact]
    public void ResolveToPositionUsesTheCurrentWriteCursor()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("next", 1).Pad(9);
        b.ResolveToPosition("next");

        Assert.Equal(10UL, b.Build().ReadField("next"));
    }

    [Fact]
    public void FieldWritesANamedImmediateValue()
    {
        var f = new FixtureBuilder(Endian.Little).Field("count", 2, 7).Build();

        Assert.Equal(new byte[] { 7, 0 }, f.ToArray());
        Assert.Equal(7UL, f.ReadField("count"));
        Assert.Equal(0, f.Field("count").Offset);
    }

    [Fact]
    public void ANegativeValueIsWrittenAsTwosComplementAtTheSlotWidth()
    {
        var f = new FixtureBuilder(Endian.Little).Field("neg", 2, -1).Build();

        Assert.Equal(new byte[] { 0xFF, 0xFF }, f.ToArray());
        Assert.Equal(0xFFFFUL, f.Field("neg").Value);
    }

    [Fact]
    public void AFullWidthUnsignedValueFitsItsSlot()
    {
        var f = new FixtureBuilder(Endian.Little).Field("max", 4, 0xFFFFFFFF).Build();

        Assert.Equal(0xFFFFFFFFUL, f.ReadField("max"));
    }

    // ---- malformed scripts: every one an error, none a quiet zero ----------------------------

    [Fact]
    public void BuildWithAnUnresolvedPlaceholderThrowsAndNamesIt()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("root_offset", 4).Placeholder("total_size", 4).Resolve("total_size", 8);

        var e = TestSupport.Throws(() => b.Build());

        Assert.Contains("1 unresolved placeholder(s): 'root_offset'", e.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("'total_size'", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ResolvingTwiceThrowsAndTheFirstValueStands()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 2).Resolve("p", 1);

        var e = TestSupport.Throws(() => b.Resolve("p", 2));

        Assert.Contains("already resolved to 0x0001", e.Message, StringComparison.Ordinal);
        Assert.Equal(1UL, b.Build().ReadField("p"));
    }

    [Fact]
    public void ADeferredResolutionAfterAnImmediateOneThrows()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 2).Resolve("p", 1);

        TestSupport.Throws(() => b.ResolveToLength("p"));
    }

    [Fact]
    public void AnImmediateResolutionAfterADeferredOneThrows()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 2).ResolveToLength("p");

        var e = TestSupport.Throws(() => b.Resolve("p", 1));

        Assert.Contains("already has a deferred resolution", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TwoDeferredResolutionsThrow()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 2).ResolveToLength("p");

        TestSupport.Throws(() => b.ResolveToLength("p"));
    }

    [Fact]
    public void AValueTooWideForItsSlotThrowsAndNothingIsTruncated()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 1);

        var e = TestSupport.Throws(() => b.Resolve("p", 256));

        Assert.Contains("1 byte(s) wide and cannot hold 256", e.Message, StringComparison.Ordinal);
        // The slot is still unresolved, so Build refuses rather than emitting the truncated 0x00.
        TestSupport.Throws(() => b.Build());
    }

    [Fact]
    public void ANegativeValueBelowTheSignedRangeThrows()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 1);

        TestSupport.Throws(() => b.Resolve("p", -129));
    }

    [Fact]
    public void ADeferredValueTooWideForItsSlotThrowsAtBuild()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 1).ResolveToLength("p").Pad(300);

        var e = TestSupport.Throws(() => b.Build());

        Assert.Contains("cannot hold 301", e.Message, StringComparison.Ordinal);
        Assert.Contains("the final buffer length", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ResolvingAnUnknownNameThrowsAndListsTheKnownOnes()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("known", 1);

        var e = TestSupport.Throws(() => b.Resolve("unknown", 1));

        Assert.Contains("'unknown'", e.Message, StringComparison.Ordinal);
        Assert.Contains("'known'", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ADeferredResolutionToAnUnknownRegionThrowsAtBuild()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 4).ResolveToRegionStart("p", "nowhere");

        var e = TestSupport.Throws(() => b.Build());

        Assert.Contains("no region named 'nowhere'", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DuplicateFieldAndRegionNamesThrow()
    {
        var b = new FixtureBuilder(Endian.Little);
        b.Placeholder("p", 1).Region("r", () => { });

        Assert.Contains("already reserved", TestSupport.Throws(() => b.Placeholder("p", 1)).Message, StringComparison.Ordinal);
        Assert.Contains("already recorded", TestSupport.Throws(() => b.Region("r", () => { })).Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    public void AnUnsupportedPlaceholderWidthThrows(int width)
    {
        TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Placeholder("p", width));
    }

    [Fact]
    public void EmptyNamesThrow()
    {
        TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Placeholder(string.Empty, 1));
        TestSupport.Throws(() => new FixtureBuilder(Endian.Little).Region(string.Empty, () => { }));
    }

    [Fact]
    public void BuildInsideARegionBodyThrows()
    {
        var b = new FixtureBuilder(Endian.Little);

        var e = TestSupport.Throws(() => b.Region("r", () => b.Build()));

        Assert.Contains("inside region 'r'", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RegionOfAnOpenRegionThrows()
    {
        var b = new FixtureBuilder(Endian.Little);

        var e = TestSupport.Throws(() => b.Region("r", () => b.RegionOf("r")));

        Assert.Contains("still open", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailingRegionBodyLeavesTheBuilderClosedAgain()
    {
        var b = new FixtureBuilder(Endian.Little);
        Assert.Throws<InvalidOperationException>(() => b.Region("r", () => throw new InvalidOperationException()));

        Assert.Equal(0, b.Depth);
    }

    [Fact]
    public void FixtureLookupsThrowForUnknownNames()
    {
        var f = new FixtureBuilder(Endian.Little).Field("f", 1, 1).Region("r", () => { }).Build();

        Assert.Contains("recorded regions: 'r'", TestSupport.Throws(() => f.Region("x")).Message, StringComparison.Ordinal);
        Assert.Contains("recorded fields: 'f'", TestSupport.Throws(() => f.Field("x")).Message, StringComparison.Ordinal);
        Assert.True(f.HasRegion("r"));
        Assert.False(f.HasField("r"));
    }
}
