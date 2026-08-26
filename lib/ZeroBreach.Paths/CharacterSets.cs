using System.Globalization;
using System.Text;

namespace ZeroBreach.Paths;

/// <summary>
/// Character and name classification tables. Everything here is a pure lookup — no locale,
/// no file system, no process state — so the answers are identical on every machine.
/// </summary>
internal static class CharacterSets
{
    // ---------------------------------------------------------------- reserved device names

    /// <summary>
    /// DOS reserved device names. A component whose base name (the part before the first '.',
    /// with trailing spaces trimmed — that is how Windows applies the check, which is why
    /// "NUL.txt" is reserved) matches one of these is flagged, never rejected.
    ///
    /// Set: CON, PRN, AUX, NUL, COM1–COM9, LPT1–LPT9, plus the superscript-digit variants
    /// COM¹/COM²/COM³ and LPT¹/LPT²/LPT³ which modern Windows also reserves, plus CONIN$ and
    /// CONOUT$ (reserved since Windows 8 console rework). COM0/LPT0 are deliberately NOT in
    /// the set — classic Windows does not reserve them. Documented in HANDOFF_C1.md.
    /// </summary>
    private static readonly HashSet<string> ReservedNames = BuildReservedNames();

    private static HashSet<string> BuildReservedNames()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        };
        for (int i = 1; i <= 9; i++)
        {
            set.Add($"COM{i}");
            set.Add($"LPT{i}");
        }
        // U+00B9 ¹, U+00B2 ², U+00B3 ³ — reserved alongside the ASCII digits in modern Windows.
        foreach (char sup in "¹²³")
        {
            set.Add($"COM{sup}");
            set.Add($"LPT{sup}");
        }
        return set;
    }

    internal static bool IsReservedDeviceName(string segment)
    {
        int dot = segment.IndexOf('.');
        string baseName = (dot < 0 ? segment : segment[..dot]).TrimEnd(' ');
        return baseName.Length > 0 && ReservedNames.Contains(baseName);
    }

    // ---------------------------------------------------------------- 8.3 short-name shape

    /// <summary>
    /// Heuristic for DOS 8.3 short names of the NAME~N[.EXT] shape NTFS generates
    /// (PROGRA~1, LONGFI~1.TXT). Requirements: base name 2–8 chars, a '~' at position ≥ 1
    /// followed only by digits to the end of the base name, extension (if any) ≤ 3 chars with
    /// no '~' or space. This is a shape check only — proving that a component actually IS a
    /// short name for something needs the file system, which is exactly why it is flagged
    /// rather than resolved.
    /// </summary>
    internal static bool LooksLikeShortName(string segment)
    {
        int dot = segment.LastIndexOf('.');
        string name = dot < 0 ? segment : segment[..dot];
        string ext = dot < 0 ? string.Empty : segment[(dot + 1)..];

        if (ext.Length > 3 || ext.Contains('~') || ext.Contains(' '))
            return false;
        if (name.Length is < 2 or > 8)
            return false;

        int tilde = name.LastIndexOf('~');
        if (tilde < 1 || tilde == name.Length - 1)
            return false;
        for (int i = tilde + 1; i < name.Length; i++)
        {
            if (!char.IsAsciiDigit(name[i]))
                return false;
        }
        return true;
    }

    // ---------------------------------------------------------------- illegal characters

    /// <summary>
    /// Characters never legal in a Windows path component. '?' and '*' are wildcards and a
    /// concrete path handed to a guard must not contain them — rejecting is fail-closed.
    /// ':' '\' '/' are structural and validated separately.
    /// </summary>
    internal static bool IsIllegalNameChar(char c) =>
        c < 0x20 || c is '"' or '<' or '>' or '|' or '*' or '?';

    /// <summary>Returns the first illegal character in <paramref name="component"/>, or null.</summary>
    internal static char? FirstIllegalNameChar(string component)
    {
        foreach (char c in component)
        {
            if (IsIllegalNameChar(c))
                return c;
        }
        return null;
    }

    // ---------------------------------------------------------------- environment variable names

    /// <summary>
    /// Whether the text between two '%' signs is plausibly an environment variable name.
    /// Anything containing separators, structural, wildcard, or control characters is treated
    /// as literal text instead (mirroring ExpandEnvironmentStrings' leniency for stray '%').
    /// </summary>
    internal static bool IsPlausibleEnvName(string name)
    {
        if (name.Length == 0)
            return false;
        foreach (char c in name)
        {
            if (c < 0x20 || c is '\\' or '/' or ':' or '"' or '<' or '>' or '|' or '*' or '?')
                return false;
        }
        return true;
    }

    // ---------------------------------------------------------------- homoglyphs / look-alikes

    /// <summary>
    /// Curated set of characters that visually imitate ASCII letters, digits, or path
    /// punctuation. Deliberately curated rather than "anything non-ASCII": client machines
    /// legitimately have non-Latin paths, and flagging every accented or CJK character would
    /// bury the signal. The full rationale and list is in HANDOFF_C1.md.
    /// </summary>
    private static readonly HashSet<int> ConfusableCodePoints = new()
    {
        // Superscript / subscript digits (COM¹ is reserved precisely because ¹ passes for 1).
        0x00B9, 0x00B2, 0x00B3, // ¹ ² ³
        0x2070, 0x2074, 0x2075, 0x2076, 0x2077, 0x2078, 0x2079, // ⁰ ⁴–⁹ (¹²³ above; U+2071/2/3 are not digits)
        0x2080, 0x2081, 0x2082, 0x2083, 0x2084, 0x2085, 0x2086, 0x2087, 0x2088, 0x2089, // ₀–₉

        // Cyrillic letters visually identical to Latin in most fonts.
        0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0443, 0x0445, // а е о р с у х
        0x0456, 0x0458, 0x04BB, 0x0501, 0x051B, 0x051D,          // і ј һ ԁ ԛ ԝ
        0x0410, 0x0412, 0x0415, 0x041A, 0x041C, 0x041D, 0x041E,  // А В Е К М Н О
        0x0420, 0x0421, 0x0422, 0x0425, 0x0405, 0x0406, 0x0408,  // Р С Т Х Ѕ І Ј

        // Greek letters visually identical to Latin.
        0x0391, 0x0392, 0x0395, 0x0396, 0x0397, 0x0399, 0x039A, 0x039C, // Α Β Ε Ζ Η Ι Κ Μ
        0x039D, 0x039F, 0x03A1, 0x03A4, 0x03A5, 0x03A7,                 // Ν Ο Ρ Τ Υ Χ
        0x03B1, 0x03B9, 0x03BD, 0x03BF, 0x03C1,                         // α ι ν ο ρ

        // Turkish dotless/dotted i — passes for i/I.
        0x0131, 0x0130, // ı İ

        // Punctuation that imitates path structure: separators, dots, colons.
        0x2024, // ․ one-dot leader
        0x2044, // ⁄ fraction slash
        0x2215, // ∕ division slash
        0x2216, // ∖ set minus (backslash look-alike)
        0x2236, // ∶ ratio (colon look-alike)
        0x29F8, // ⧸ big solidus
        0x29F9, // ⧹ big reverse solidus
        0xFE68, // ﹨ small reverse solidus
        0xA789, // ꞉ modifier letter colon

        // The Unicode replacement character: its presence means the string held an invalid
        // UTF-16 sequence (for example a lone surrogate), which is itself a signal.
        0xFFFD,
    };

    /// <summary>
    /// Whether the string contains look-alike or invisible characters. Flags:
    /// - any Format (Cf) character — zero-width, bidi controls, soft hyphen, BOM;
    /// - line/paragraph separators (Zl/Zp);
    /// - any space separator other than plain U+0020 (NBSP, en/em/ideographic spaces);
    /// - Control category at or above U+007F (DEL and the C1 block; C0 is rejected outright);
    /// - the fullwidth ASCII block U+FF01–U+FF5E (／ ＼ ： Ｗ …);
    /// - the curated confusable table above.
    /// Printable ASCII never flags.
    /// </summary>
    internal static bool ContainsHomoglyphs(string text)
    {
        foreach (Rune rune in text.EnumerateRunes())
        {
            int cp = rune.Value;
            if (cp <= 0x7E)
                continue; // fast path: printable ASCII (and C0, which illegal-char checks reject)

            UnicodeCategory category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
                return true;
            if (category == UnicodeCategory.SpaceSeparator)
                return true; // any non-ASCII space
            if (category == UnicodeCategory.Control)
                return true; // DEL + C1 controls
            if (cp is >= 0xFF01 and <= 0xFF5E)
                return true; // fullwidth ASCII forms
            if (ConfusableCodePoints.Contains(cp))
                return true;
        }
        return false;
    }
}
