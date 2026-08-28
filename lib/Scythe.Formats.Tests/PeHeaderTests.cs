using Scythe.Formats;
using Scythe.Formats.Pe;
using Xunit;

namespace Scythe.Formats.Tests;

/// <summary>Valid-file structure parsing: DOS/COFF/optional headers, sections, directories, both magics.</summary>
public sealed class PeHeaderTests
{
    private static byte[] SomeCode() => new byte[] { 0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3, 0x90, 0xCC, 0xCC, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };

    [Fact]
    public void MinimalPe32_ParsesOk()
    {
        var b = new PeFixtureBuilder();
        uint textVa = b.AddSection(".text", SomeCode(), PeFixtureBuilder.Code);
        b.SetEntryPoint(textVa + 2);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        Assert.Null(r.Message);
        Assert.Empty(r.IncompleteReasons);
        var img = Assert.IsType<PeImage>(r.Image);
        Assert.NotNull(r.Metrics);

        Assert.Equal(0x5A4Du, img.DosHeader.Magic);
        Assert.Equal((uint)PeFixtureBuilder.Lfanew, img.DosHeader.Lfanew);
        Assert.Equal(0x14C, img.FileHeader.Machine);
        Assert.Equal(1, img.FileHeader.NumberOfSections);
        Assert.False(img.OptionalHeader.IsPe32Plus);
        Assert.Equal(0x10B, img.OptionalHeader.Magic);
        Assert.NotNull(img.OptionalHeader.BaseOfData);
        Assert.Equal(0x0040_0000UL, img.OptionalHeader.ImageBase);
        Assert.Equal(PeFixtureBuilder.HeadersSize, img.OptionalHeader.SizeOfHeaders);
        Assert.Equal(3, img.OptionalHeader.Subsystem);
        Assert.Equal(16u, img.OptionalHeader.NumberOfRvaAndSizes);
        Assert.Equal(textVa + 2, img.OptionalHeader.AddressOfEntryPoint);

        var section = Assert.Single(img.Sections);
        Assert.Equal(".text", section.Name);
        Assert.Equal(0x1000u, section.VirtualAddress);
        Assert.Equal((uint)SomeCode().Length, section.SizeOfRawData);
        Assert.Equal(PeFixtureBuilder.HeadersSize, section.PointerToRawData);
        Assert.Equal(PeFixtureBuilder.Code, section.Characteristics);

        // No optional structures were declared: absence is null/empty, never a fake default.
        Assert.Empty(img.Imports);
        Assert.Null(img.Exports);
        Assert.Null(img.ResourceRoot);
        Assert.Null(img.Certificate);
        Assert.Empty(img.DebugEntries);
        Assert.Null(img.RichHeader);
        Assert.Null(img.Tls);
        // All directory slots are zero, so the reported (non-empty) directory list is empty.
        Assert.Empty(img.DataDirectories);
    }

    [Fact]
    public void MinimalPe32Plus_ParsesOk_With64BitFields()
    {
        var b = new PeFixtureBuilder(pe32Plus: true);
        uint textVa = b.AddSection(".text", SomeCode(), PeFixtureBuilder.Code);
        b.SetEntryPoint(textVa);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        var img = r.Image!;
        Assert.Equal(0x8664, img.FileHeader.Machine);
        Assert.True(img.OptionalHeader.IsPe32Plus);
        Assert.Equal(0x20B, img.OptionalHeader.Magic);
        Assert.Null(img.OptionalHeader.BaseOfData); // PE32+ has no BaseOfData
        Assert.Equal(0x1_4000_0000UL, img.OptionalHeader.ImageBase);
        Assert.Equal(".text", Assert.Single(img.Sections).Name);
    }

    [Fact]
    public void TimeDateStamp_NonZero_IsDecodedAsUtc()
    {
        var b = new PeFixtureBuilder { TimeDateStamp = 1_600_000_000 };
        b.AddSection(".text", SomeCode(), PeFixtureBuilder.Code);
        var r = TestParse.Run(b.Build());

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_600_000_000), r.Image!.FileHeader.TimeDateStampUtc);
    }

    [Fact]
    public void TimeDateStamp_Zero_IsNullNotEpoch()
    {
        // Reproducible builds zero the field or store a hash; zero must read as "not set",
        // not as 1970-01-01.
        var b = new PeFixtureBuilder { TimeDateStamp = 0 };
        b.AddSection(".text", SomeCode(), PeFixtureBuilder.Code);
        var r = TestParse.Run(b.Build());

        Assert.Null(r.Image!.FileHeader.TimeDateStampUtc);
    }

    [Fact]
    public void MultipleSections_KeepTableOrderAndGetDistinctAddresses()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", SomeCode(), PeFixtureBuilder.Code);
        b.AddSection(".data", new byte[] { 1, 2, 3, 4 }, PeFixtureBuilder.WritableData);
        b.AddSection(".rsrc", new byte[64], PeFixtureBuilder.Data);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Ok, r.State);
        var sections = r.Image!.Sections;
        Assert.Equal(new[] { ".text", ".data", ".rsrc" }, sections.Select(s => s.Name));
        Assert.Equal(new uint[] { 0x1000, 0x2000, 0x3000 }, sections.Select(s => s.VirtualAddress));
        Assert.True(sections[0].PointerToRawData < sections[1].PointerToRawData);
        Assert.True(sections[1].PointerToRawData < sections[2].PointerToRawData);
    }

    [Fact]
    public void SectionName_WithNonAsciiBytes_SurvivesAsLatin1()
    {
        // The 8-byte name field is arbitrary bytes; 0x80-0xFF must survive rather than
        // collapsing to '?', or two differently-named sections become indistinguishable.
        var b = new PeFixtureBuilder();
        b.AddSection("évil", new byte[16], PeFixtureBuilder.Data); // 0xE9 'é' in Latin-1
        var r = TestParse.Run(b.Build());

        Assert.Equal("évil", Assert.Single(r.Image!.Sections).Name);
    }

    [Fact]
    public void DataDirectories_OnlyNonEmptySlotsAreReported_WithStandardNames()
    {
        var b = new PeFixtureBuilder();
        b.AddSection(".text", SomeCode(), PeFixtureBuilder.Code);
        b.SetDirectory(5, 0x7000, 0x40); // BaseRelocation: present but pointing nowhere we read
        var r = TestParse.Run(b.Build());

        var dir = Assert.Single(r.Image!.DataDirectories);
        Assert.Equal(5, dir.Index);
        Assert.Equal("BaseRelocation", dir.Name);
        Assert.Equal(0x7000u, dir.VirtualAddress);
        Assert.Equal(0x40u, dir.Size);
    }

    [Fact]
    public void DeclaredDirectoryCountAboveSixteen_IsCappedWithReason()
    {
        // NumberOfRvaAndSizes is attacker data; the format defines exactly 16 slots. Reading
        // "extra" ones would walk into the section table. The excess is reported, not silent.
        var b = new PeFixtureBuilder { NumberOfRvaAndSizesOverride = 0x1000 };
        b.AddSection(".text", SomeCode(), PeFixtureBuilder.Code);
        var r = TestParse.Run(b.Build());

        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Contains(r.IncompleteReasons, x => x.Contains("NumberOfRvaAndSizes") && x.Contains("16"));
        Assert.NotNull(r.Image); // everything else was still recovered
    }
}
