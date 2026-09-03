namespace Scythe.Text;

/// <summary>Per-entry scoring category, packed with the script into CodePageData's class bytes.</summary>
internal enum EntryCategory : byte
{
    /// <summary>The page leaves this byte undefined. The strongest scoring signal there is.</summary>
    Undefined = 0,

    /// <summary>0x00–0x7F. Carries no discriminating information; scores zero.</summary>
    AsciiRange = 1,

    /// <summary>Maps to U+0080–U+009F. Printable in the Windows pages, controls in the ISO pages.</summary>
    C1Control = 2,

    Letter = 3,

    /// <summary>Punctuation or a symbol common in prose: quotes, dashes, currency.</summary>
    ProseSymbol = 4,

    /// <summary>Defined, printable, but not prose punctuation — box drawing, maths, dingbats.</summary>
    OtherSymbol = 5,
}

internal enum LetterScript : byte
{
    None = 0,
    Latin = 1,
    Greek = 2,
    Cyrillic = 3,
}

/// <summary>
/// One embedded single-byte page: a 256-entry map (0xFFFF marks an undefined entry) and a
/// parallel classification table precomputed for the scorer. The tables live in
/// CodePages.g.cs with each one's source recorded beside it.
/// </summary>
internal sealed class CodePage
{
    internal const ushort UndefinedEntry = 0xFFFF;

    private CodePage(TextEncodingKind kind, string name, LetterScript primaryScript, ushort[] map, byte[] classes)
    {
        Kind = kind;
        Name = name;
        PrimaryScript = primaryScript;
        Map = map;
        Classes = classes;
    }

    internal TextEncodingKind Kind { get; }
    internal string Name { get; }
    internal LetterScript PrimaryScript { get; }
    internal ushort[] Map { get; }
    internal byte[] Classes { get; }

    internal EntryCategory CategoryOf(byte b) => (EntryCategory)(Classes[b] & 0x07);

    internal LetterScript ScriptOf(byte b) => (LetterScript)(Classes[b] >> 3);

    /// <summary>
    /// The candidate set from reference/11.2_text.md §11.2, in the canonical scoring order that
    /// breaks ties. This order is documented API behaviour: reordering it changes which page a
    /// genuinely ambiguous buffer reports.
    /// </summary>
    internal static readonly CodePage[] CanonicalOrder =
    [
        new(TextEncodingKind.Windows1252, "windows-1252", LetterScript.Latin,
            CodePageData.Windows1252Map, CodePageData.Windows1252Class),
        new(TextEncodingKind.Windows1250, "windows-1250", LetterScript.Latin,
            CodePageData.Windows1250Map, CodePageData.Windows1250Class),
        new(TextEncodingKind.Windows1251, "windows-1251", LetterScript.Cyrillic,
            CodePageData.Windows1251Map, CodePageData.Windows1251Class),
        new(TextEncodingKind.Iso8859Part1, "iso-8859-1", LetterScript.Latin,
            CodePageData.Iso8859Part1Map, CodePageData.Iso8859Part1Class),
        new(TextEncodingKind.Iso8859Part2, "iso-8859-2", LetterScript.Latin,
            CodePageData.Iso8859Part2Map, CodePageData.Iso8859Part2Class),
        new(TextEncodingKind.Iso8859Part5, "iso-8859-5", LetterScript.Cyrillic,
            CodePageData.Iso8859Part5Map, CodePageData.Iso8859Part5Class),
        new(TextEncodingKind.Cp437, "cp437", LetterScript.Latin,
            CodePageData.Cp437Map, CodePageData.Cp437Class),
        new(TextEncodingKind.Cp850, "cp850", LetterScript.Latin,
            CodePageData.Cp850Map, CodePageData.Cp850Class),
    ];

    internal static CodePage? ForKind(TextEncodingKind kind)
    {
        foreach (var page in CanonicalOrder)
        {
            if (page.Kind == kind)
            {
                return page;
            }
        }

        return null;
    }
}
