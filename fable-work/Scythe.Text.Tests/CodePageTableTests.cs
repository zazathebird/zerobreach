using Xunit;

namespace Scythe.Text.Tests;

/// <summary>
/// Pins the embedded tables against hand-written values from the published Unicode Consortium
/// mappings. The fixtures elsewhere encode text through the library's own tables, so agreement
/// with the outside world has to be asserted somewhere independent — here, on the entries that
/// carry the discrimination weight: the undefined holes, the 0x80–0x9F family split, and each
/// page's characteristic letters.
/// </summary>
public class CodePageTableTests
{
    private static CodePage Page(TextEncodingKind kind) => CodePage.ForKind(kind)!;

    [Theory]
    [InlineData(TextEncodingKind.Windows1252, new byte[] { 0x81, 0x8D, 0x8F, 0x90, 0x9D })]
    [InlineData(TextEncodingKind.Windows1250, new byte[] { 0x81, 0x83, 0x88, 0x90, 0x98 })]
    [InlineData(TextEncodingKind.Windows1251, new byte[] { 0x98 })]
    public void TheWindowsPagesLeaveExactlyTheirDocumentedHolesUndefined(TextEncodingKind kind, byte[] holes)
    {
        var page = Page(kind);

        for (var b = 0; b < 256; b++)
        {
            var expectUndefined = holes.Contains((byte)b);
            Assert.Equal(expectUndefined, page.Map[b] == CodePage.UndefinedEntry);
            Assert.Equal(expectUndefined, page.CategoryOf((byte)b) == EntryCategory.Undefined);
        }
    }

    [Theory]
    [InlineData(TextEncodingKind.Iso8859Part1)]
    [InlineData(TextEncodingKind.Iso8859Part2)]
    [InlineData(TextEncodingKind.Iso8859Part5)]
    [InlineData(TextEncodingKind.Cp437)]
    [InlineData(TextEncodingKind.Cp850)]
    public void TheIsoAndOemPagesDefineAllEntries(TextEncodingKind kind)
    {
        var page = Page(kind);

        for (var b = 0; b < 256; b++)
        {
            Assert.NotEqual(CodePage.UndefinedEntry, page.Map[b]);
        }
    }

    [Theory]
    [InlineData(TextEncodingKind.Iso8859Part1)]
    [InlineData(TextEncodingKind.Iso8859Part2)]
    [InlineData(TextEncodingKind.Iso8859Part5)]
    public void TheIsoPagesMapEightyToNinetyNineFToC1Controls(TextEncodingKind kind)
    {
        var page = Page(kind);

        for (var b = 0x80; b <= 0x9F; b++)
        {
            Assert.Equal((ushort)b, page.Map[b]);
            Assert.Equal(EntryCategory.C1Control, page.CategoryOf((byte)b));
        }
    }

    [Theory]
    // windows-1252: the curly punctuation and the euro that discriminate it from iso-8859-1.
    [InlineData(TextEncodingKind.Windows1252, 0x80, 0x20AC)] // €
    [InlineData(TextEncodingKind.Windows1252, 0x92, 0x2019)] // ’
    [InlineData(TextEncodingKind.Windows1252, 0x9F, 0x0178)] // Ÿ
    // windows-1250: Central-European letters, including the 0x80–0x9F block ISO pages lack.
    [InlineData(TextEncodingKind.Windows1250, 0x9D, 0x0165)] // ť
    [InlineData(TextEncodingKind.Windows1250, 0xF9, 0x016F)] // ů
    [InlineData(TextEncodingKind.Windows1250, 0xA5, 0x0104)] // Ą
    // windows-1251: Cyrillic.
    [InlineData(TextEncodingKind.Windows1251, 0xC0, 0x0410)] // А
    [InlineData(TextEncodingKind.Windows1251, 0xB8, 0x0451)] // ё
    [InlineData(TextEncodingKind.Windows1251, 0x90, 0x0452)] // ђ
    // iso-8859-1 / iso-8859-2 high halves.
    [InlineData(TextEncodingKind.Iso8859Part1, 0xE9, 0x00E9)] // é
    [InlineData(TextEncodingKind.Iso8859Part2, 0xA1, 0x0104)] // Ą
    [InlineData(TextEncodingKind.Iso8859Part2, 0xB9, 0x0161)] // š
    // iso-8859-5.
    [InlineData(TextEncodingKind.Iso8859Part5, 0xB0, 0x0410)] // А
    [InlineData(TextEncodingKind.Iso8859Part5, 0xF1, 0x0451)] // ё
    [InlineData(TextEncodingKind.Iso8859Part5, 0xF0, 0x2116)] // №
    // cp437: OEM letters, currency, and the Greek block.
    [InlineData(TextEncodingKind.Cp437, 0x81, 0x00FC)] // ü
    [InlineData(TextEncodingKind.Cp437, 0x9B, 0x00A2)] // ¢
    [InlineData(TextEncodingKind.Cp437, 0xE0, 0x03B1)] // α
    [InlineData(TextEncodingKind.Cp437, 0xB0, 0x2591)] // ░
    // cp850: where it diverges from cp437.
    [InlineData(TextEncodingKind.Cp850, 0x9B, 0x00F8)] // ø
    [InlineData(TextEncodingKind.Cp850, 0x9D, 0x00D8)] // Ø
    [InlineData(TextEncodingKind.Cp850, 0xD5, 0x0131)] // ı
    public void SpotEntriesMatchThePublishedMappings(TextEncodingKind kind, int b, int codePoint)
    {
        Assert.Equal((ushort)codePoint, Page(kind).Map[b]);
    }

    [Fact]
    public void TheGreekBlockInCp437IsClassifiedAsAForeignScriptLetter()
    {
        var page = Page(TextEncodingKind.Cp437);

        Assert.Equal(EntryCategory.Letter, page.CategoryOf(0xE0)); // α
        Assert.Equal(LetterScript.Greek, page.ScriptOf(0xE0));
        Assert.Equal(LetterScript.Latin, page.PrimaryScript);
    }

    [Fact]
    public void CyrillicPagesDeclareACyrillicPrimaryScript()
    {
        Assert.Equal(LetterScript.Cyrillic, Page(TextEncodingKind.Windows1251).PrimaryScript);
        Assert.Equal(LetterScript.Cyrillic, Page(TextEncodingKind.Iso8859Part5).PrimaryScript);
        Assert.Equal(LetterScript.Cyrillic, Page(TextEncodingKind.Windows1251).ScriptOf(0xC0));
    }

    [Fact]
    public void TheAsciiHalfIsTransparentInEveryPage()
    {
        foreach (var page in CodePage.CanonicalOrder)
        {
            for (var b = 0; b < 0x80; b++)
            {
                Assert.Equal((ushort)b, page.Map[b]);
                Assert.Equal(EntryCategory.AsciiRange, page.CategoryOf((byte)b));
            }
        }
    }

    [Fact]
    public void TheCanonicalOrderIsTheDocumentedOne()
    {
        // The tie-break order is API behaviour; reordering it silently changes which page an
        // ambiguous buffer reports.
        var documented = new[]
        {
            TextEncodingKind.Windows1252,
            TextEncodingKind.Windows1250,
            TextEncodingKind.Windows1251,
            TextEncodingKind.Iso8859Part1,
            TextEncodingKind.Iso8859Part2,
            TextEncodingKind.Iso8859Part5,
            TextEncodingKind.Cp437,
            TextEncodingKind.Cp850,
        };
        Assert.Equal(documented, CodePage.CanonicalOrder.Select(p => p.Kind).ToArray());
    }
}
