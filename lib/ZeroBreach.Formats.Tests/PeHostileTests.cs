using System.Buffers.Binary;
using ZeroBreach.Formats;
using ZeroBreach.Formats.Pe;
using Xunit;

namespace ZeroBreach.Formats.Tests;

/// <summary>
/// Hostile input is the normal case: truncation at every header boundary, lying counts and
/// offsets, overflowing sizes, self-referencing trees. Every test here asserts a returned
/// state — nothing in this class may throw.
/// </summary>
public sealed class PeHostileTests
{
    private static readonly byte[] Code = { 0xC3, 0x90, 0x90, 0x90 };

    private static byte[] MinimalPe32()
    {
        var b = new PeFixtureBuilder();
        uint va = b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.SetEntryPoint(va);
        return b.Build();
    }

    [Fact]
    public void EmptyFile_FailsAtOffsetZero()
    {
        var r = TestParse.Run(Array.Empty<byte>());
        Assert.Equal(OperationState.Failed, r.State);
        Assert.Equal(0, r.ErrorOffset);
        Assert.Null(r.Image);
        Assert.Null(r.Metrics);
    }

    [Fact]
    public void FileThatIsOnlyMz_FailsAsTruncatedDosHeader()
    {
        var r = TestParse.Run(new byte[] { (byte)'M', (byte)'Z' });
        Assert.Equal(OperationState.Failed, r.State);
        Assert.Contains("DOS header", r.Message);
        Assert.Null(r.Image);
    }

    [Fact]
    public void NotMz_FailsAtOffsetZero()
    {
        var r = TestParse.Run(new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 0, 0, 0, 0 });
        Assert.Equal(OperationState.Failed, r.State);
        Assert.Equal(0, r.ErrorOffset);
        Assert.Contains("MZ", r.Message);
    }

    public static TheoryData<int> HeaderBoundaries()
    {
        int coff = PeFixtureBuilder.Lfanew + 4;
        int opt = coff + 20;
        return new TheoryData<int>
        {
            1,          // inside the magic
            2,          // magic only
            0x20,       // inside the DOS header
            0x3F,       // one byte short of e_lfanew being usable
            0x41,       // DOS header complete, PE signature entirely absent
            PeFixtureBuilder.Lfanew + 2, // partial PE signature
            coff + 10,  // partial COFF header
            opt + 1,    // optional-header magic cut in half
            opt + 50,   // inside the optional header fixed fields
            opt + 95,   // one byte short of the PE32 fixed fields
        };
    }

    [Theory]
    [MemberData(nameof(HeaderBoundaries))]
    public void TruncatedAtHeaderBoundary_FailsWithPosition_NeverThrows(int length)
    {
        byte[] full = MinimalPe32();
        var r = TestParse.Run(full.AsSpan(0, length).ToArray());

        Assert.Equal(OperationState.Failed, r.State);
        Assert.NotNull(r.Message);
        Assert.NotNull(r.ErrorOffset); // every header failure names a byte position
        Assert.Null(r.Image);
    }

    [Fact]
    public void TruncatedInsideDataDirectoryTable_IsIncompleteWithRecoveredHeaders()
    {
        // Headers are intact, so this is Incomplete-with-image, not Failed: the DOS/COFF/
        // optional fixed fields were all readable and are reported.
        byte[] full = MinimalPe32();
        int opt = PeFixtureBuilder.Lfanew + 24;
        var r = TestParse.Run(full.AsSpan(0, opt + 96 + 5 * 8 + 4).ToArray());

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.NotNull(r.Image);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("data directory table truncated"));
    }

    [Fact]
    public void TruncatedInsideSectionTable_IsIncompleteWithRecoveredSections()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddSection(".data", new byte[8], PeFixtureBuilder.WritableData);
        byte[] full = b.Build();
        // Cut mid-way through the second section table entry.
        var r = TestParse.Run(full.AsSpan(0, b.SectionTableOffset + 40 + 20).ToArray());

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("section table truncated"));
        Assert.Equal(".text", Assert.Single(r.Image!.Sections).Name); // the readable entry survives
    }

    [Fact]
    public void SectionCount65535_IsCappedWithReason_TableNotRead()
    {
        var b = new PeFixtureBuilder { SectionCountOverride = 65535 };
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons,
            x => x.Contains("section count 65535") && x.Contains($"cap {PeParserLimits.MaxSections}"));
        Assert.Empty(r.Image!.Sections); // a corrupt count is not walked at all
        Assert.NotNull(r.Metrics);       // whole-file metrics still computed
    }

    [Fact]
    public void SectionRawOffsetBeyondFile_IsIncomplete_EntropyNull()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        byte[] file = b.Build();
        // Point the section's raw data far past the end of the file.
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(b.SectionTableOffset + 20), 0x1000_0000);
        var r = TestParse.Run(file);

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains(".text") && x.Contains("past end of file"));
        Assert.Null(r.Metrics!.Sections[0].Entropy); // no readable bytes: null, not 0.0
    }

    [Fact]
    public void SectionRawSizeOverhangingFileEnd_IsIncomplete_EntropyOverReadablePart()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        byte[] file = b.Build();
        // Raw size lies: claims far more bytes than the file holds past the raw offset.
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(b.SectionTableOffset + 16), 0x0800_0000);
        var r = TestParse.Run(file);

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains(".text") && x.Contains("past end of file"));
        Assert.NotNull(r.Metrics!.Sections[0].Entropy); // the bytes that do exist are still measured
    }

    [Fact]
    public void OverflowingVirtualAddressPlusSize_IsHandledWithoutThrow()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        byte[] file = b.Build();
        // VirtualAddress + VirtualSize overflows 32 bits; all arithmetic must be 64-bit.
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(b.SectionTableOffset + 8), 0x0000_2000);  // VirtualSize
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(b.SectionTableOffset + 12), 0xFFFF_F000); // VirtualAddress
        // Entry point numerically above the section start; containment must not wrap.
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(PeFixtureBuilder.Lfanew + 24 + 16), 0xFFFF_F010);
        var r = TestParse.Run(file);

        Assert.True(r.State is OperationState.Ok or OperationState.Incomplete);
        Assert.NotNull(r.Image);
        Assert.False(r.Metrics!.EntryPointOutsideAnySection); // 0xFFFFF010 sits inside the (lying) section
    }

    [Fact]
    public void ResourceTreeReferencingItself_IsReportedAsCycle()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        uint va = b.NextVa();
        // Hand-built resource directory: one id entry whose subdirectory offset is 0 — itself.
        var rsrc = new byte[24];
        BinaryPrimitives.WriteUInt16LittleEndian(rsrc.AsSpan(14), 1);            // one id entry
        BinaryPrimitives.WriteUInt32LittleEndian(rsrc.AsSpan(16), 42);           // id
        BinaryPrimitives.WriteUInt32LittleEndian(rsrc.AsSpan(20), 0x8000_0000);  // subdir at offset 0 = the root
        b.AddSection(".rsrc", rsrc, PeFixtureBuilder.Data);
        b.SetDirectory(2, va, (uint)rsrc.Length);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("cycle"));
        var root = r.Image!.ResourceRoot!;
        var child = Assert.Single(root.Children);
        Assert.Equal(42u, child.Id);
        Assert.Empty(child.Children); // the cycle was not descended
    }

    [Fact]
    public void ResourceTreeDeeperThanBudgetNestingDepth_IsCapped()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddResources(ResSpec.Dir(1u, ResSpec.Dir(2u, ResSpec.Dir(3u, ResSpec.Leaf(4u, new byte[] { 9 })))));
        var budget = BudgetDefaults.Default with { MaxNestingDepth = 2 };
        var r = PeParser.Parse(b.Build(), budget);

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("resource tree depth exceeds cap 2"));
    }

    [Fact]
    public void ImportNameRvaPointingNowhere_YieldsNullNameWithReason()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        uint va = b.NextVa();
        var idata = new byte[48];
        void W(int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(idata.AsSpan(at), v);
        W(0, va + 40);         // OriginalFirstThunk
        W(12, 0x00DD_0000);    // Name RVA maps to nothing
        W(16, va + 40);
        W(40, 0x8000_0005);    // one ordinal import
        // rel 44 is the zero terminator
        b.AddSection(".idata", idata, PeFixtureBuilder.Data);
        b.SetDirectory(1, va, 40);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("DLL name") && x.Contains("no file data"));
        var dll = Assert.Single(r.Image!.Imports);
        Assert.Null(dll.Name); // null with a reason — never a made-up name
        Assert.Equal((ushort)5, Assert.Single(dll.Functions).Ordinal);
    }

    [Fact]
    public void GarbageBytes_NeverThrow_AcrossManyLengths()
    {
        // Deterministic pseudo-garbage, some starting with MZ, at many lengths, including
        // ones that look just plausible enough to reach deeper parse stages.
        var rng = new Random(1234);
        for (int len = 0; len < 700; len += 13)
        {
            byte[] junk = new byte[len];
            rng.NextBytes(junk);
            if (len >= 2 && len % 2 == 0)
            {
                junk[0] = (byte)'M';
                junk[1] = (byte)'Z';
            }
            if (len > 0x40 && len % 4 == 0)
                BinaryPrimitives.WriteUInt32LittleEndian(junk.AsSpan(0x3C), (uint)(len / 2));
            var r = TestParse.Run(junk); // must return a state, never throw
            Assert.True(r.State is OperationState.Ok or OperationState.Incomplete or OperationState.Failed);
            if (r.State == OperationState.Failed)
                Assert.NotNull(r.Message);
        }
    }
}
