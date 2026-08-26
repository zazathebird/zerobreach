using ZeroBreach.Rules.Yara.Parsing;

namespace ZeroBreach.Rules.Yara.Matching;

/// <summary>Public description of one compiled string.</summary>
public sealed record CompiledStringInfo(
    int RuleIndex,
    string Identifier,
    bool IsPrivate);

/// <summary>An NFA-matched string (hex or regex): one program per encoding.</summary>
internal sealed record NfaStringEntry(
    int StringIndex,
    NfaProgram Program,
    bool Fullword,
    VariantEncoding Encoding);

/// <summary>
/// The immutable, thread-safe compiled form of every string across a rule set: literal
/// variants baked into two Aho-Corasick automatons (case-sensitive over raw bytes,
/// case-insensitive over ASCII-folded bytes) plus one NFA per hex/regex encoding.
/// </summary>
public sealed class CompiledStringSet
{
    internal IReadOnlyList<CompiledStringInfo> Strings { get; }
    internal AhoCorasick? SensitiveAutomaton { get; }
    internal LiteralVariant[] SensitivePatterns { get; }
    internal AhoCorasick? FoldedAutomaton { get; }
    internal LiteralVariant[] FoldedPatterns { get; }
    internal IReadOnlyList<NfaStringEntry> NfaStrings { get; }

    internal CompiledStringSet(
        IReadOnlyList<CompiledStringInfo> strings,
        AhoCorasick? sensitiveAutomaton,
        LiteralVariant[] sensitivePatterns,
        AhoCorasick? foldedAutomaton,
        LiteralVariant[] foldedPatterns,
        IReadOnlyList<NfaStringEntry> nfaStrings)
    {
        Strings = strings;
        SensitiveAutomaton = sensitiveAutomaton;
        SensitivePatterns = sensitivePatterns;
        FoldedAutomaton = foldedAutomaton;
        FoldedPatterns = foldedPatterns;
        NfaStrings = nfaStrings;
    }

    public int StringCount => Strings.Count;

    public CompiledStringInfo StringInfo(int index) => Strings[index];

    /// <summary>Total number of concrete literal patterns; reported so the host can see
    /// compiled-set size (xor expands 256-fold, and that should be visible, not silent).</summary>
    public int LiteralPatternCount => SensitivePatterns.Length + FoldedPatterns.Length;
}

/// <summary>Compiles the strings of parsed rules into a <see cref="CompiledStringSet"/>.</summary>
public static class YaraStringCompiler
{
    /// <summary>
    /// Compile-time pathology rejection (BLUEPRINT §3): a hex string with no constraining
    /// byte anywhere ("{ ?? ?? }", or only negations) has no anchoring literal at all and
    /// would force an NFA attempt at every buffer offset; that is rejected rather than
    /// accepted-and-slow. A nibble wildcard ("4?") still constrains 16 of 256 values and
    /// counts as an anchor.
    /// </summary>
    private static bool HasAnchorByte(HexSequence seq) =>
        seq.Nodes.Any(n => n switch
        {
            HexByteNode b => b.Mask != 0 && !b.Negated,
            HexAltNode alt => alt.Branches.Any(HasAnchorByte),
            _ => false,
        });

    public static CompiledStringSet? Compile(
        IReadOnlyList<(int RuleIndex, YaraStringDecl Decl)> strings,
        string fileName,
        List<Diagnostic> diagnostics)
    {
        var infos = new List<CompiledStringInfo>();
        var sensitive = new List<LiteralVariant>();
        var folded = new List<LiteralVariant>();
        var nfaStrings = new List<NfaStringEntry>();
        bool failed = false;

        for (int index = 0; index < strings.Count; index++)
        {
            var (ruleIndex, decl) = strings[index];
            infos.Add(new CompiledStringInfo(ruleIndex, decl.Identifier,
                decl.Modifiers.Has(StringModifierKind.Private)));
            string owner = $"${decl.Identifier}";

            switch (decl)
            {
                case TextStringDecl text:
                    foreach (var variant in LiteralVariantGenerator.Expand(index, text))
                    {
                        if (variant.Bytes.Length == 0)
                        {
                            continue; // parser already rejected empty strings
                        }
                        (variant.Nocase ? folded : sensitive).Add(variant);
                    }
                    break;

                case HexStringDecl hex:
                {
                    if (!HasAnchorByte(hex.Sequence))
                    {
                        diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.UnanchoredPattern,
                            $"hex string {owner} at {decl.Location} contains no fixed byte to anchor the search " +
                            "and is rejected as pathological",
                            fileName, decl.Location));
                        failed = true;
                        break;
                    }
                    var program = NfaBuilder.FromHex(hex.Sequence, owner, fileName, decl.Location, diagnostics);
                    if (program is null)
                    {
                        failed = true;
                        break;
                    }
                    if (!ValidateProgram(program, owner, decl.Location))
                    {
                        failed = true;
                        break;
                    }
                    nfaStrings.Add(new NfaStringEntry(index, program, Fullword: false, VariantEncoding.Ascii));
                    break;
                }

                case RegexStringDecl regex:
                {
                    var ast = RegexParser.Parse(regex.Pattern, regex.CaseInsensitive, regex.DotMatchesAll,
                        owner, fileName, decl.Location, diagnostics);
                    if (ast is null)
                    {
                        failed = true;
                        break;
                    }
                    var m = regex.Modifiers;
                    bool wantAscii = m.Has(StringModifierKind.Ascii) || !m.Has(StringModifierKind.Wide);
                    bool wantWide = m.Has(StringModifierKind.Wide);
                    bool fullword = m.Has(StringModifierKind.Fullword);
                    foreach (var (wide, enc) in new[] { (false, VariantEncoding.Ascii), (true, VariantEncoding.Wide) })
                    {
                        if ((wide && !wantWide) || (!wide && !wantAscii))
                        {
                            continue;
                        }
                        var program = NfaBuilder.FromRegex(ast, wide, owner, fileName, decl.Location, diagnostics);
                        if (program is null || !ValidateProgram(program, owner, decl.Location))
                        {
                            failed = true;
                            break;
                        }
                        nfaStrings.Add(new NfaStringEntry(index, program, fullword, enc));
                    }
                    break;
                }
            }
        }

        if (failed)
        {
            return null;
        }

        // Folded patterns are stored pre-folded so hits in the folded automaton are exact.
        var foldedPatternBytes = folded.Select(v => Fold(v.Bytes)).ToList();
        return new CompiledStringSet(
            infos,
            sensitive.Count > 0 ? new AhoCorasick(sensitive.Select(v => v.Bytes).ToList()) : null,
            sensitive.ToArray(),
            folded.Count > 0 ? new AhoCorasick(foldedPatternBytes) : null,
            folded.ToArray(),
            nfaStrings);

        bool ValidateProgram(NfaProgram program, string owner, SourceLocation location)
        {
            if (program.MinLength == 0)
            {
                // A pattern that can match zero bytes matches everywhere, which is never
                // what a rule author meant and would flood the match table.
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.EmptyString,
                    $"pattern of {owner} at {location} can match empty content and is rejected",
                    fileName, location));
                return false;
            }
            return true;
        }
    }

    internal static byte[] Fold(byte[] bytes)
    {
        var f = new byte[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            f[i] = FoldByte(bytes[i]);
        }
        return f;
    }

    internal static byte FoldByte(byte b) =>
        b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;
}
