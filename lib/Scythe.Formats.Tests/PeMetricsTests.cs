using Scythe.Formats;
using Scythe.Formats.Pe;
using Xunit;

namespace Scythe.Formats.Tests;

/// <summary>Derived anomaly metrics: entropy, entry-point location, W+X, overlay, name commonality.</summary>
public sealed class PeMetricsTests
{
    private static readonly byte[] Code = { 0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3, 0x90 };

    [Fact]
    public void Entropy_AllZeroSection_IsExactlyZero()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddSection(".data", new byte[1024], PeFixtureBuilder.WritableData);
        var r = TestParse.Run(b.Build());

        // One byte value with probability 1: entropy exactly 0.0 — a fact ("a run of one
        // value"), distinct from null ("no bytes to measure").
        Assert.Equal(0.0, r.Metrics!.Sections[1].Entropy);
    }

    [Fact]
    public void Entropy_UniformByteDistribution_IsExactlyEight()
    {
        byte[] uniform = new byte[1024];
        for (int i = 0; i < uniform.Length; i++)
            uniform[i] = (byte)i; // every value exactly 4 times: maximal entropy
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddSection(".data", uniform, PeFixtureBuilder.Data);
        var r = TestParse.Run(b.Build());

        Assert.NotNull(r.Metrics!.Sections[1].Entropy);
        Assert.Equal(8.0, r.Metrics!.Sections[1].Entropy!.Value, precision: 9);
    }

    [Fact]
    public void Entropy_RealishCode_LandsStrictlyBetweenZeroAndEight()
    {
        // Deterministic "code-like" bytes: skewed distribution, some repetition.
        byte[] codeish = new byte[2048];
        for (int i = 0; i < codeish.Length; i++)
            codeish[i] = (byte)((i * 31 + i / 7) % 97);
        var b = new PeFixtureBuilder();
        b.AddSection(".text", codeish, PeFixtureBuilder.Code);
        var r = TestParse.Run(b.Build());

        double e = r.Metrics!.Sections[0].Entropy!.Value;
        Assert.InRange(e, 1.0, 7.9);
        Assert.NotNull(r.Metrics!.WholeFileEntropy);
    }

    [Fact]
    public void Entropy_ZeroRawSizeSection_IsNullNotZero()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddSection(".bss", Array.Empty<byte>(), PeFixtureBuilder.WritableData, virtualSize: 0x2000);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        // Null, not 0.0: there are no bytes to measure, which is a different fact from
        // "bytes that are all one value".
        Assert.Null(r.Metrics!.Sections[1].Entropy);
    }

    [Fact]
    public void ZeroRawSizeWithLargeVirtualSize_FlaggedOnlyAtThreshold()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddSection(".big", Array.Empty<byte>(), PeFixtureBuilder.WritableData, virtualSize: PeParserLimits.LargeVirtualSizeThreshold);
        b.AddSection(".small", Array.Empty<byte>(), PeFixtureBuilder.WritableData, virtualSize: PeParserLimits.LargeVirtualSizeThreshold - 1);
        var r = TestParse.Run(b.Build());

        Assert.True(r.Metrics!.Sections[1].ZeroRawSizeWithLargeVirtualSize);
        Assert.False(r.Metrics!.Sections[2].ZeroRawSizeWithLargeVirtualSize); // ordinary uninitialised data
    }

    [Fact]
    public void WritableAndExecutable_FlaggedOnlyWhenBothBitsSet()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);                 // X, not W
        b.AddSection(".data", new byte[16], PeFixtureBuilder.WritableData); // W, not X
        b.AddSection(".wx", new byte[16], PeFixtureBuilder.WriteExecCode);  // both
        var r = TestParse.Run(b.Build());

        Assert.False(r.Metrics!.Sections[0].WritableAndExecutable);
        Assert.False(r.Metrics!.Sections[1].WritableAndExecutable);
        Assert.True(r.Metrics!.Sections[2].WritableAndExecutable);
    }

    [Fact]
    public void EntryPoint_InsideExecutableSection_SetsNeitherFlag()
    {
        var b = new PeFixtureBuilder();
        uint va = b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.SetEntryPoint(va + 2);
        var r = TestParse.Run(b.Build());

        Assert.False(r.Metrics!.EntryPointOutsideAnySection);
        Assert.False(r.Metrics!.EntryPointInWritableSection);
    }

    [Fact]
    public void EntryPoint_AtExactSectionStart_IsInside()
    {
        // Boundary pin: containment is [VirtualAddress, VirtualAddress + size).
        var b = new PeFixtureBuilder();
        uint va = b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.SetEntryPoint(va);
        var r = TestParse.Run(b.Build());

        Assert.False(r.Metrics!.EntryPointOutsideAnySection);
    }

    [Fact]
    public void EntryPoint_OnePastSectionEnd_IsOutside()
    {
        var b = new PeFixtureBuilder();
        uint va = b.AddSection(".text", Code, PeFixtureBuilder.Code, virtualSize: (uint)Code.Length);
        b.SetEntryPoint(va + (uint)Code.Length); // first RVA past the mapped extent
        var r = TestParse.Run(b.Build());

        Assert.True(r.Metrics!.EntryPointOutsideAnySection);
        Assert.False(r.Metrics!.EntryPointInWritableSection);
    }

    [Fact]
    public void EntryPoint_InNoSection_IsFlaggedOutside()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.SetEntryPoint(0x0009_0000);
        var r = TestParse.Run(b.Build());

        Assert.True(r.Metrics!.EntryPointOutsideAnySection);
    }

    [Fact]
    public void EntryPoint_InWritableSection_IsFlagged()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        uint wx = b.AddSection(".wx", new byte[32], PeFixtureBuilder.WriteExecCode);
        b.SetEntryPoint(wx + 4);
        var r = TestParse.Run(b.Build());

        Assert.False(r.Metrics!.EntryPointOutsideAnySection);
        Assert.True(r.Metrics!.EntryPointInWritableSection);
    }

    [Fact]
    public void EntryPoint_Zero_SetsNeitherFlag()
    {
        // Zero is common for DLLs and resource-only images: "no entry point", not "entry
        // point outside all sections".
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.SetEntryPoint(0);
        var r = TestParse.Run(b.Build());

        Assert.False(r.Metrics!.EntryPointOutsideAnySection);
        Assert.False(r.Metrics!.EntryPointInWritableSection);
    }

    [Fact]
    public void Overlay_AbsentWhenFileEndsWithMappedContent()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        byte[] file = b.Build();
        var r = TestParse.Run(file);

        Assert.False(r.Metrics!.OverlayPresent);
        Assert.Equal(0, r.Metrics!.OverlaySize);
        Assert.Equal(file.Length, r.Metrics!.OverlayOffset);
    }

    [Fact]
    public void Overlay_DetectedAndSized()
    {
        byte[] overlay = Enumerable.Repeat((byte)0xAB, 321).ToArray();
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        byte[] withoutOverlay = b.Build();
        b.AddOverlay(overlay);
        byte[] file = b.Build();
        var r = TestParse.Run(file);

        Assert.True(r.Metrics!.OverlayPresent);
        Assert.Equal(321, r.Metrics!.OverlaySize);
        Assert.Equal(withoutOverlay.Length, r.Metrics!.OverlayOffset); // overlay starts where mapped content ended
    }

    [Fact]
    public void SectionNames_CommonVersusUncommon_IncludingCaseVariant()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddSection(".TEXT", new byte[8], PeFixtureBuilder.Code); // case variant of a stock name is itself a signal
        b.AddSection("UPX0", new byte[8], PeFixtureBuilder.Data);
        var r = TestParse.Run(b.Build());

        Assert.False(r.Metrics!.Sections[0].UncommonName);
        Assert.True(r.Metrics!.Sections[1].UncommonName);
        Assert.True(r.Metrics!.Sections[2].UncommonName);
    }
}
