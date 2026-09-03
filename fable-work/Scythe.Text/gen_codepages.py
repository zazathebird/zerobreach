#!/usr/bin/env python3
"""Generates Scythe.Text/CodePages.g.cs.

Each single-byte page is a 256-entry table. The mappings come from CPython's bundled codec
tables, which implement the Unicode Consortium reference mappings for these pages; undefined
entries surface as UnicodeDecodeError and are emitted as the 0xFFFF sentinel. The scoring
classification (letter/script/prose-symbol/...) is computed here from unicodedata and baked
into the C# file as data, so the library never consults the host's Unicode tables at runtime.
"""
import os
import unicodedata

PAGES = [
    # (C# identifier, python codec, TextEncodingKind, primary script, human name, source note)
    ("Windows1252", "cp1252",    "Windows1252",  "Latin",    "windows-1252",
     "Unicode mapping CP1252.TXT (via CPython codec cp1252)"),
    ("Windows1250", "cp1250",    "Windows1250",  "Latin",    "windows-1250",
     "Unicode mapping CP1250.TXT (via CPython codec cp1250)"),
    ("Windows1251", "cp1251",    "Windows1251",  "Cyrillic", "windows-1251",
     "Unicode mapping CP1251.TXT (via CPython codec cp1251)"),
    ("Iso8859Part1", "latin_1",  "Iso8859Part1", "Latin",    "iso-8859-1",
     "Unicode mapping 8859-1.TXT (via CPython codec latin_1)"),
    ("Iso8859Part2", "iso8859_2","Iso8859Part2", "Latin",    "iso-8859-2",
     "Unicode mapping 8859-2.TXT (via CPython codec iso8859_2)"),
    ("Iso8859Part5", "iso8859_5","Iso8859Part5", "Cyrillic", "iso-8859-5",
     "Unicode mapping 8859-5.TXT (via CPython codec iso8859_5)"),
    ("Cp437", "cp437",           "Cp437",        "Latin",    "cp437",
     "Unicode mapping CP437.TXT (via CPython codec cp437)"),
    ("Cp850", "cp850",           "Cp850",        "Latin",    "cp850",
     "Unicode mapping CP850.TXT (via CPython codec cp850)"),
]

# Punctuation and symbols common in running prose: quotes, dashes, ellipsis, currency,
# section/paragraph marks, legal marks, degree, bullets, fractions. Everything defined,
# non-letter and non-C1 that is NOT in this set scores 0 per byte (OtherSymbol) and relies
# on the adjacency rules to be penalised.
PROSE = {
    0x00A0, 0x00AD,                                  # nbsp, soft hyphen
    0x00A1, 0x00BF,                                  # inverted ! ?
    0x00A7, 0x00B6, 0x00A9, 0x00AE, 0x2122, 0x2116,  # section, pilcrow, (c), (r), tm, No
    0x00AB, 0x00BB, 0x2018, 0x2019, 0x201A, 0x201C, 0x201D, 0x201E, 0x2039, 0x203A,
    0x2013, 0x2014, 0x2026, 0x2022, 0x2030, 0x00B7,
    0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x20AC, 0x20A7,  # currency
    0x00B0, 0x00BC, 0x00BD, 0x00BE,
}

# Category values must match CodePage.cs
CAT_UNDEFINED, CAT_ASCII, CAT_C1, CAT_LETTER, CAT_PROSE, CAT_OTHER = 0, 1, 2, 3, 4, 5
SCR_NONE, SCR_LATIN, SCR_GREEK, SCR_CYRILLIC = 0, 1, 2, 3


def script_of(cp: int) -> int:
    if 0x0041 <= cp <= 0x024F or 0x1E00 <= cp <= 0x1EFF:
        return SCR_LATIN
    if 0x0370 <= cp <= 0x03FF:
        return SCR_GREEK
    if 0x0400 <= cp <= 0x052F:
        return SCR_CYRILLIC
    return SCR_NONE


def classify(byte: int, cp: int | None) -> tuple[int, int]:
    if cp is None:
        return CAT_UNDEFINED, SCR_NONE
    if byte < 0x80:
        return CAT_ASCII, SCR_NONE
    if 0x80 <= cp <= 0x9F:
        return CAT_C1, SCR_NONE
    if cp == 0x00B5:  # micro sign: category Ll but a unit symbol in prose, not a letter
        return CAT_OTHER, SCR_NONE
    if unicodedata.category(chr(cp)).startswith("L"):
        return CAT_LETTER, script_of(cp)
    if cp in PROSE:
        return CAT_PROSE, SCR_NONE
    return CAT_OTHER, SCR_NONE


def decode_table(codec: str) -> list[int | None]:
    out: list[int | None] = []
    for b in range(256):
        try:
            ch = bytes([b]).decode(codec)
            assert len(ch) == 1
            out.append(ord(ch))
        except UnicodeDecodeError:
            out.append(None)
    return out


def hex_rows(values: list[int], per_row: int, fmt: str) -> str:
    rows = []
    for i in range(0, 256, per_row):
        row = ", ".join(fmt.format(v) for v in values[i:i + per_row])
        rows.append(f"        {row}, // 0x{i:02X}")
    return "\n".join(rows)


def main() -> None:
    # Sanity pins: a codec surprise should fail generation, not ship a wrong table.
    t1252 = decode_table("cp1252")
    assert t1252[0x80] == 0x20AC and t1252[0x9F] == 0x0178
    assert [b for b in range(0x80, 0x100) if t1252[b] is None] == [0x81, 0x8D, 0x8F, 0x90, 0x9D]
    t1251 = decode_table("cp1251")
    assert t1251[0xC0] == 0x0410 and t1251[0xB8] == 0x0451
    assert [b for b in range(256) if t1251[b] is None] == [0x98]
    t437 = decode_table("cp437")
    assert t437[0xE0] == 0x03B1 and t437[0x9B] == 0x00A2
    t850 = decode_table("cp850")
    assert t850[0xD5] == 0x0131 and t850[0x9B] == 0x00F8
    tiso2 = decode_table("iso8859_2")
    assert tiso2[0xA1] == 0x0104 and tiso2[0x85] == 0x0085  # C1 controls are defined in ISO pages
    tiso5 = decode_table("iso8859_5")
    assert tiso5[0xB0] == 0x0410 and tiso5[0xF1] == 0x0451
    t1250 = decode_table("cp1250")
    assert [b for b in range(256) if t1250[b] is None] == [0x81, 0x83, 0x88, 0x90, 0x98]

    parts = []
    parts.append("""// <auto-generated>
// Generated by gen_codepages.py, kept beside this file. Re-run it to regenerate.
// The byte-to-code-point mappings are CPython's bundled codec tables, which implement the
// Unicode Consortium reference mappings for these pages. The 0xFFFF sentinel marks an entry
// the page leaves undefined; representing the holes as holes is deliberate — they are one of
// the strongest scoring signals available (reference/11.2_text.md).
// The classification bytes pack (script << 3) | category, precomputed from unicodedata so the
// scorer never consults the host's Unicode tables at runtime.
// </auto-generated>

namespace Scythe.Text;

internal static class CodePageData
{
""")
    for ident, codec, _kind, _script, name, source in PAGES:
        table = decode_table(codec)
        undefined = [b for b in range(256) if table[b] is None]
        map_vals = [0xFFFF if v is None else v for v in table]
        cls_vals = []
        for b in range(256):
            cat, scr = classify(b, table[b])
            cls_vals.append((scr << 3) | cat)
        undef_note = (
            "none" if not undefined
            else ", ".join(f"0x{b:02X}" for b in undefined)
        )
        parts.append(f"    // {name} — source: {source}. Undefined entries: {undef_note}.\n")
        parts.append(f"    internal static readonly ushort[] {ident}Map =\n    [\n")
        parts.append(hex_rows(map_vals, 8, "0x{:04X}"))
        parts.append("\n    ];\n\n")
        parts.append(f"    internal static readonly byte[] {ident}Class =\n    [\n")
        parts.append(hex_rows(cls_vals, 16, "0x{:02X}"))
        parts.append("\n    ];\n\n")
    parts.append("}\n")

    out = "".join(parts)
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "CodePages.g.cs")
    with open(target, "w") as f:
        f.write(out)

    # Print the undefined sets and a few spot values for the test file to pin independently.
    for ident, codec, *_ in PAGES:
        t = decode_table(codec)
        undefined = [f"0x{b:02X}" for b in range(256) if t[b] is None]
        print(ident, "undefined:", undefined or "none")
    print("generated OK")


if __name__ == "__main__":
    main()
