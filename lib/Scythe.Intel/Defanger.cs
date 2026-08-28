namespace Scythe.Intel;

using System.Text.RegularExpressions;

/// <summary>
/// Restores defanged indicator values. Defanging is how feeds ship live indicators without
/// making them clickable; miss a form and that feed silently yields nothing (task brief).
///
/// Restoration runs BEFORE validation, and whether anything changed is recorded on the
/// indicator.
///
/// Handled forms (all case-insensitive):
///   Schemes:    hxxp:// → http://, hxxps:// → https://, fxp:// → ftp://,
///               meow:// → http://, meows:// → https://
///   Dots:       [.]  (.)  {.}  [dot]  (dot)  {dot}   → "."  (optionally space-padded:
///               "evil [dot] com" → "evil.com"; "1.2.3[.]4" → "1.2.3.4")
///   At-signs:   [@]  (@)  {@}  [at]  (at)  {at}      → "@"  (optionally space-padded)
///   Colons:     [:]  → ":"   and   [://]  (://)      → "://"   (so "hxxp[:]//" restores)
///
/// Deliberately NOT handled: bare space-separated "evil dot com" without brackets — too
/// ambiguous against legitimate free text.
///
/// All patterns here are fixed and author-controlled; no attacker-supplied pattern is ever
/// compiled, so there is no backtracking hazard (each regex is a finite alternation with
/// bounded whitespace runs).
/// </summary>
internal static partial class Defanger
{
    // "meows" and "hxxps" are folded into their shorter forms by replacing only the scheme
    // token: hxxp→http keeps the trailing "s" intact, so hxxps→https for free. fxp/meow need
    // a lookahead so a word like "meowing" in a comment field is untouched — the scheme must
    // be followed by ":" or a defanged "[:]".
    [GeneratedRegex(@"hxxp", RegexOptions.IgnoreCase)]
    private static partial Regex SchemeHxxp();

    [GeneratedRegex(@"\bfxp(?=s?\s*[\[\(\{]?:)", RegexOptions.IgnoreCase)]
    private static partial Regex SchemeFxp();

    [GeneratedRegex(@"\bmeows(?=\s*[\[\(\{]?:)", RegexOptions.IgnoreCase)]
    private static partial Regex SchemeMeows();

    [GeneratedRegex(@"\bmeow(?=\s*[\[\(\{]?:)", RegexOptions.IgnoreCase)]
    private static partial Regex SchemeMeow();

    // "[://]" or "(://)" as one unit.
    [GeneratedRegex(@"[\[\(\{]:\/\/[\]\)\}]")]
    private static partial Regex BracketSchemeSep();

    [GeneratedRegex(@"[\[\(\{]:[\]\)\}]")]
    private static partial Regex BracketColon();

    // Mismatched pairs like "[.)" are accepted on purpose: feeds hand-defang and typo these,
    // and there is no legitimate value where "[." starts anything meaningful.
    [GeneratedRegex(@"[ \t]*[\[\(\{][ \t]*(?:\.|dot)[ \t]*[\]\)\}][ \t]*", RegexOptions.IgnoreCase)]
    private static partial Regex BracketDot();

    [GeneratedRegex(@"[ \t]*[\[\(\{][ \t]*(?:@|at)[ \t]*[\]\)\}][ \t]*", RegexOptions.IgnoreCase)]
    private static partial Regex BracketAt();

    /// <summary>Restores <paramref name="value"/>; <paramref name="wasDefanged"/> is true when
    /// anything changed.</summary>
    public static string Restore(string value, out bool wasDefanged)
    {
        var s = value;
        s = SchemeHxxp().Replace(s, "http");
        s = SchemeFxp().Replace(s, "ftp");
        s = SchemeMeows().Replace(s, "https");
        s = SchemeMeow().Replace(s, "http");
        s = BracketSchemeSep().Replace(s, "://");
        s = BracketColon().Replace(s, ":");
        s = BracketDot().Replace(s, ".");
        s = BracketAt().Replace(s, "@");
        wasDefanged = !string.Equals(s, value, StringComparison.Ordinal);
        return s;
    }
}
