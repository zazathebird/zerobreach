namespace ZeroBreach.Rules.Linting.Patterns;

/// <summary>
/// Minimal AST over the .NET regex dialect, used only for lint-side analysis (anchoring,
/// witness generation, required-literal measurement). It is *not* a matcher — matching is
/// done by <see cref="System.Text.RegularExpressions.Regex"/>, the engine the host itself
/// uses on these patterns — so a construct this model does not understand degrades to
/// <see cref="PatternUnsupported"/> and the affected analysis skips, it never guesses.
/// </summary>
internal abstract record PatternNode;

internal sealed record PatternLiteral(char Ch) : PatternNode;

/// <summary>Matches any character (<c>.</c>). Whether it matches newline is irrelevant to
/// the analyses this AST feeds.</summary>
internal sealed record PatternAny : PatternNode;

internal sealed record PatternConcat(IReadOnlyList<PatternNode> Items) : PatternNode
{
    public static readonly PatternConcat Empty = new(Array.Empty<PatternNode>());
}

internal sealed record PatternAlternation(IReadOnlyList<PatternNode> Branches) : PatternNode;

/// <summary><paramref name="Max"/> is <see cref="int.MaxValue"/> for unbounded.</summary>
internal sealed record PatternRepeat(PatternNode Child, int Min, int Max) : PatternNode;

internal sealed record PatternGroup(PatternNode Child) : PatternNode;

internal enum PatternAnchorKind
{
    Start,          // ^ or \A
    End,            // $, \z or \Z
    WordBoundary,   // \b
    NotWordBoundary // \B
}

internal sealed record PatternAnchor(PatternAnchorKind Kind) : PatternNode;

/// <summary>A construct the analysis model does not represent (lookaround, backreference,
/// conditional, \p category…). Analyses treat it as opaque.</summary>
internal sealed record PatternUnsupported(string What) : PatternNode;

/// <summary>
/// A character class, stored as inclusive ranges plus a negation flag. ASCII-oriented:
/// shorthand classes (<c>\d</c>, <c>\w</c>, <c>\s</c>) expand to their ASCII ranges, which
/// is exact enough for witness picking and literal measurement over Windows-path content.
/// </summary>
internal sealed record PatternCharClass : PatternNode
{
    /// <summary>Characters probed, in order, when picking a deterministic sample member.</summary>
    private const string SampleCandidates =
        "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ .-_/\\:@!#%&'*+,;=?~\"<>()[]{}^$|";

    private readonly IReadOnlyList<(char Lo, char Hi)> _ranges;

    public PatternCharClass(IReadOnlyList<(char Lo, char Hi)> ranges, bool negated, bool exact)
    {
        _ranges = ranges;
        Negated = negated;
        Exact = exact;
    }

    public bool Negated { get; }

    /// <summary>False when the class contained constructs the range model cannot carry
    /// (Unicode categories, class subtraction). Membership answers are then unreliable
    /// and <see cref="Sample"/> declines to pick.</summary>
    public bool Exact { get; }

    public bool Contains(char c)
    {
        bool inRanges = false;
        foreach (var (lo, hi) in _ranges)
        {
            if (c >= lo && c <= hi)
            {
                inRanges = true;
                break;
            }
        }
        return inRanges != Negated;
    }

    /// <summary>First candidate character the class accepts, or null when none does (or
    /// when membership is unreliable). Deterministic by construction.</summary>
    public char? Sample()
    {
        if (!Exact)
        {
            return null;
        }
        foreach (char c in SampleCandidates)
        {
            if (Contains(c))
            {
                return c;
            }
        }
        return null;
    }

    public static PatternCharClass Digit() => new(new[] { ('0', '9') }, negated: false, exact: true);

    public static PatternCharClass Word() => new(
        new[] { ('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_') }, negated: false, exact: true);

    public static PatternCharClass Space() => new(
        new[] { (' ', ' '), ('\t', '\t'), ('\n', '\n'), ('\v', '\v'), ('\f', '\f'), ('\r', '\r') },
        negated: false, exact: true);

    public static PatternCharClass Negate(PatternCharClass cls) =>
        new(cls._ranges, !cls.Negated, cls.Exact);
}
