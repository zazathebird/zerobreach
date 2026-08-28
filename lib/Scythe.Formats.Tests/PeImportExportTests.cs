using Scythe.Formats;
using Scythe.Formats.Pe;
using Xunit;

namespace Scythe.Formats.Tests;

/// <summary>Import and export directory parsing, PE32 and PE32+ thunk widths, ordinals, forwarders.</summary>
public sealed class PeImportExportTests
{
    private static readonly byte[] Code = { 0xC3, 0x90, 0x90, 0x90 };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Imports_ByNameAndByOrdinal_AreDecoded(bool pe32Plus)
    {
        var b = new PeFixtureBuilder(pe32Plus);
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddImports(
            new ImportDll("KERNEL32.dll", ImportFunc.ByName("ExitProcess", hint: 7), ImportFunc.ByName("CreateFileW", hint: 0x120)),
            new ImportDll("WS2_32.dll", ImportFunc.ByOrdinal(515))); // > 255: pins the full 16-bit ordinal mask
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        var imports = r.Image!.Imports;
        Assert.Equal(2, imports.Count);

        Assert.Equal("KERNEL32.dll", imports[0].Name);
        Assert.Collection(imports[0].Functions,
            f =>
            {
                Assert.Equal("ExitProcess", f.Name);
                Assert.Equal((ushort)7, f.Hint);
                Assert.Null(f.Ordinal);
            },
            f =>
            {
                Assert.Equal("CreateFileW", f.Name);
                Assert.Equal((ushort)0x120, f.Hint);
                Assert.Null(f.Ordinal);
            });

        Assert.Equal("WS2_32.dll", imports[1].Name);
        var ordinal = Assert.Single(imports[1].Functions);
        Assert.Null(ordinal.Name);
        Assert.Equal((ushort)515, ordinal.Ordinal); // low 16 bits only, high flag stripped
        Assert.Null(ordinal.Hint);

        Assert.Equal(2, r.Metrics!.ImportedDllCount);
        Assert.Equal(3, r.Metrics!.ImportedFunctionCount);
    }

    [Fact]
    public void Imports_UnmappableDirectoryRva_YieldsIncompleteNotThrow()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.SetDirectory(1, 0x00F0_0000, 0x100); // maps to no section
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("import directory") && x.Contains("no file data"));
        Assert.Empty(r.Image!.Imports);
    }

    [Fact]
    public void Imports_ThunkArrayRunningOffEndOfFile_IsReportedNotThrown()
    {
        // A descriptor whose INT runs to the end of the file with no terminator: the walk must
        // stop with a reason, not read past the buffer.
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        uint va = b.NextVa();
        var idata = new byte[48]; // one descriptor + terminator (40), then 2 unterminated thunks
        void W(int at, uint v) => System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(idata.AsSpan(at), v);
        W(0, va + 40);              // OriginalFirstThunk -> array at rel 40
        W(12, va + 2);              // Name RVA -> "ll" inside .text? No: point at NUL-terminated bytes below
        W(16, va + 40);
        W(40, 0x8000_0001);         // ordinal 1
        W(44, 0x8000_0002);         // ordinal 2 — and then the section (and file) just ends
        // Give the name RVA something readable: point it at offset 12+... simpler: reuse rel 8
        // (a zero dword inside the descriptor) as an empty name.
        W(12, va + 8);
        b.AddSection(".idata", idata, PeFixtureBuilder.Data);
        b.SetDirectory(1, va, 40);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("thunk array") && x.Contains("end of file"));
        var dll = Assert.Single(r.Image!.Imports);
        Assert.Equal(2, dll.Functions.Count); // both readable thunks were still recovered
        Assert.Equal((ushort)1, dll.Functions[0].Ordinal);
        Assert.Equal((ushort)2, dll.Functions[1].Ordinal);
    }

    [Fact]
    public void Exports_NamesOrdinalsForwardersAndUnnamedSlots_AreDecoded()
    {
        var b = new PeFixtureBuilder();
        uint textVa = b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.AddExports("SAMPLE.dll", ordinalBase: 5,
            new ExportSpec("Alpha", textVa),
            new ExportSpec("Beta", textVa + 1),
            new ExportSpec(null, textVa + 2),
            new ExportSpec("Fwd", 0, Forwarder: "NTDLL.RtlAllocateHeap"));
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        var ex = r.Image!.Exports!;
        Assert.Equal("SAMPLE.dll", ex.DllName);
        Assert.Equal(5u, ex.OrdinalBase);

        Assert.Collection(ex.Entries,
            e =>
            {
                Assert.Equal("Alpha", e.Name);
                Assert.Equal(5u, e.Ordinal); // biased: base + index
                Assert.Equal(textVa, e.Rva);
                Assert.Null(e.Forwarder);
            },
            e =>
            {
                Assert.Equal("Beta", e.Name);
                Assert.Equal(6u, e.Ordinal);
                Assert.Equal(textVa + 1, e.Rva);
            },
            e =>
            {
                Assert.Null(e.Name); // export by ordinal only
                Assert.Equal(7u, e.Ordinal);
                Assert.Equal(textVa + 2, e.Rva);
            },
            e =>
            {
                Assert.Equal("Fwd", e.Name);
                Assert.Equal(8u, e.Ordinal);
                Assert.Equal("NTDLL.RtlAllocateHeap", e.Forwarder); // RVA points inside the export dir
            });
    }

    [Fact]
    public void Exports_UnmappableDirectory_YieldsIncompleteWithNullExports()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", Code, PeFixtureBuilder.Code);
        b.SetDirectory(0, 0x00E0_0000, 0x40);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("export directory"));
        Assert.Null(r.Image!.Exports);
    }
}
