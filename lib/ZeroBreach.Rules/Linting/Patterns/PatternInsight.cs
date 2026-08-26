using System.Text;

namespace ZeroBreach.Rules.Linting.Patterns;

/// <summary>
/// The three analyses the linter runs over a parsed pattern. All are deliberately
/// conservative: when the model cannot decide, each errs in the direction that cannot
/// hide a defect — see each method's contract for which direction that is.
/// </summary>
internal static class PatternInsight
{
    /// <summary>Witnesses longer than this are refused; a pattern demanding one is not a
    /// realistic indicator and the swallow check honestly skips it.</summary>
    public const int MaxWitnessLength = 4096;

    /// <summary>
    /// True when every way through the pattern begins at a start anchor (<c>^</c> or
    /// <c>\A</c>). Errs toward "not anchored": an unsupported construct in leading
    /// position is not credited as an anchor, so a false "anchored" cannot hide an open
    /// allowlist — the failure direction that matters (BLUEPRINT §9).
    /// </summary>
    public static bool StartsAnchored(PatternNode node) => node switch
    {
        PatternAnchor a => a.Kind == PatternAnchorKind.Start,
        PatternGroup g => StartsAnchored(g.Child),
        PatternAlternation alt => AllBranches(alt, StartsAnchored),
        PatternConcat concat => FirstMaterial(concat.Items) is { } first && StartsAnchored(first),
        PatternRepeat r => r.Min >= 1 && StartsAnchored(r.Child),
        _ => false,
    };

    /// <summary>Mirror of <see cref="StartsAnchored"/> for <c>$</c> / <c>\z</c> / <c>\Z</c>.</summary>
    public static bool EndsAnchored(PatternNode node) => node switch
    {
        PatternAnchor a => a.Kind == PatternAnchorKind.End,
        PatternGroup g => EndsAnchored(g.Child),
        PatternAlternation alt => AllBranches(alt, EndsAnchored),
        PatternConcat concat => LastMaterial(concat.Items) is { } last && EndsAnchored(last),
        PatternRepeat r => r.Min >= 1 && EndsAnchored(r.Child),
        _ => false,
    };

    private static bool AllBranches(PatternAlternation alt, Func<PatternNode, bool> test)
    {
        foreach (var branch in alt.Branches)
        {
            if (!test(branch))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Skips empty concats (inline flag toggles) when finding the edge atom.</summary>
    private static PatternNode? FirstMaterial(IReadOnlyList<PatternNode> items)
    {
        foreach (var item in items)
        {
            if (item is not PatternConcat { Items.Count: 0 })
            {
                return item;
            }
        }
        return null;
    }

    private static PatternNode? LastMaterial(IReadOnlyList<PatternNode> items)
    {
        for (int i = items.Count - 1; i >= 0; i--)
        {
            if (items[i] is not PatternConcat { Items.Count: 0 })
            {
                return items[i];
            }
        }
        return null;
    }

    /// <summary>
    /// Builds one concrete string the pattern is intended to match: literals verbatim,
    /// first alternation branch, minimum repetitions (at least one for <c>+</c>), a
    /// deterministic sample member per class. Null when any piece is beyond the model.
    /// The caller must verify the witness against the *real* compiled regex before using
    /// it — zero-width assertions (<c>\b</c>) are emitted as nothing and can make the
    /// generated string a non-match, and a wrong witness must never produce a finding.
    /// </summary>
    public static string? TryBuildWitness(PatternNode node)
    {
        var sb = new StringBuilder();
        return Append(node, sb) ? sb.ToString() : null;

        static bool Append(PatternNode n, StringBuilder sb)
        {
            switch (n)
            {
                case PatternLiteral lit:
                    sb.Append(lit.Ch);
                    return true;
                case PatternAny:
                    sb.Append('a');
                    return true;
                case PatternCharClass cls:
                    if (cls.Sample() is not { } sample)
                    {
                        return false;
                    }
                    sb.Append(sample);
                    return true;
                case PatternAnchor:
                    return true; // zero-width; validation against the real regex decides
                case PatternGroup g:
                    return Append(g.Child, sb);
                case PatternConcat concat:
                    foreach (var item in concat.Items)
                    {
                        if (!Append(item, sb))
                        {
                            return false;
                        }
                    }
                    return true;
                case PatternAlternation alt:
                    return Append(alt.Branches[0], sb);
                case PatternRepeat rep:
                    // Minimum repetitions: one copy for +, n for {n,m}, zero when the
                    // whole repeat is optional — the shortest string the author intended.
                    for (int i = 0; i < rep.Min; i++)
                    {
                        if (!Append(rep.Child, sb) || sb.Length > MaxWitnessLength)
                        {
                            return false;
                        }
                    }
                    return sb.Length <= MaxWitnessLength;
                default:
                    return false; // PatternUnsupported and anything unforeseen
            }
        }
    }

    /// <summary>
    /// Length of the longest run of contiguous, mandatory literal characters present in
    /// every match. This is the "anchoring literal" an indicator needs to avoid colliding
    /// with the world; below four characters is automatically suspect (BLUEPRINT §9).
    /// Conservative: alternation and unsupported constructs may undercount (producing at
    /// worst an unnecessary warning), never overcount (which would hide a weak indicator).
    /// </summary>
    public static int LongestRequiredLiteralRun(PatternNode node) => Measure(node).Best;

    /// <summary>Literal-run shape of one node: the best guaranteed run anywhere inside,
    /// the guaranteed runs touching its left and right edges (so runs can merge across
    /// concatenation), whether the node is nothing but a fixed-length literal, and that
    /// fixed length. Zero-width nodes are literal of length 0 — transparent to runs.</summary>
    private readonly record struct LitInfo(int Best, int Prefix, int Suffix, bool WholeLiteral, int Length);

    private static LitInfo Measure(PatternNode node)
    {
        switch (node)
        {
            case PatternLiteral:
                return new LitInfo(1, 1, 1, WholeLiteral: true, Length: 1);

            case PatternAnchor:
                return new LitInfo(0, 0, 0, WholeLiteral: true, Length: 0);

            case PatternGroup g:
                return Measure(g.Child);

            case PatternConcat concat:
            {
                int best = 0, prefix = 0, cur = 0, length = 0;
                bool wholeLiteral = true, prefixDone = false;
                foreach (var item in concat.Items)
                {
                    var info = Measure(item);
                    best = Math.Max(best, info.Best);
                    if (info.WholeLiteral)
                    {
                        cur += info.Length;
                        length += info.Length;
                        if (!prefixDone)
                        {
                            prefix += info.Length;
                        }
                    }
                    else
                    {
                        best = Math.Max(best, cur + info.Prefix);
                        if (!prefixDone)
                        {
                            prefix += info.Prefix;
                            prefixDone = true;
                        }
                        cur = info.Suffix;
                        wholeLiteral = false;
                    }
                    best = Math.Max(best, cur);
                }
                if (wholeLiteral)
                {
                    return new LitInfo(Math.Max(best, length), length, length, true, length);
                }
                return new LitInfo(best, prefix, cur, false, 0);
            }

            case PatternAlternation alt:
            {
                // Guaranteed length across branches is the weakest branch. Content may
                // differ between branches; for indicator quality each branch is its own
                // indicator, so length is the honest property to compose on.
                int best = int.MaxValue, prefix = int.MaxValue, suffix = int.MaxValue;
                bool allWhole = true;
                int commonLength = -1;
                foreach (var branch in alt.Branches)
                {
                    var info = Measure(branch);
                    best = Math.Min(best, info.Best);
                    prefix = Math.Min(prefix, info.Prefix);
                    suffix = Math.Min(suffix, info.Suffix);
                    allWhole &= info.WholeLiteral;
                    commonLength = commonLength == -1 || commonLength == info.Length
                        ? info.Length
                        : -2;
                }
                if (allWhole && commonLength >= 0)
                {
                    return new LitInfo(best, prefix, suffix, true, commonLength);
                }
                return new LitInfo(best, prefix, suffix, false, 0);
            }

            case PatternRepeat rep:
            {
                var child = Measure(rep.Child);
                if (rep.Min == 0)
                {
                    // Entirely optional: contributes nothing guaranteed and interrupts
                    // any run flowing through it.
                    return new LitInfo(0, 0, 0, false, 0);
                }
                if (child.WholeLiteral)
                {
                    int guaranteed = SaturatingMultiply(child.Length, rep.Min);
                    bool fixedLength = rep.Min == rep.Max;
                    return new LitInfo(
                        Math.Max(child.Best, guaranteed), guaranteed, guaranteed,
                        fixedLength, fixedLength ? guaranteed : 0);
                }
                return new LitInfo(child.Best, child.Prefix, child.Suffix, false, 0);
            }

            default:
                // PatternAny, PatternCharClass, PatternUnsupported: not literal.
                return new LitInfo(0, 0, 0, false, 0);
        }
    }

    private static int SaturatingMultiply(int a, int b)
    {
        long product = (long)a * b;
        return product > int.MaxValue ? int.MaxValue : (int)product;
    }
}
