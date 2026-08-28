using Scythe.Rules.Sigma.Yaml;

namespace Scythe.Rules.Sigma;

/// <summary>A node of a compiled <c>condition</c> expression. Evaluation is Kleene
/// three-valued: a definite answer that does not depend on an Incomplete sub-result stays
/// definite; anything else propagates Incomplete with its reason.</summary>
internal abstract class ConditionNode
{
    public abstract TriState Evaluate(SigmaEvalContext ctx);
}

internal sealed class ItemRefNode(DetectionItem item) : ConditionNode
{
    public override TriState Evaluate(SigmaEvalContext ctx) => item.Evaluate(ctx);
}

internal sealed class NotNode(ConditionNode operand) : ConditionNode
{
    public override TriState Evaluate(SigmaEvalContext ctx)
    {
        var r = operand.Evaluate(ctx);
        if (r.IsIncomplete)
        {
            // not(unknown) is unknown — flipping it would turn a budget failure into a
            // confident verdict, in either direction.
            return r;
        }
        return r.IsTrue ? TriState.False : TriState.True;
    }
}

internal sealed class AndNode(ConditionNode left, ConditionNode right) : ConditionNode
{
    public override TriState Evaluate(SigmaEvalContext ctx)
    {
        var l = left.Evaluate(ctx);
        if (l.IsFalse)
        {
            // Sound short-circuit: false AND anything is false regardless of the right
            // side, even a right side that would have been Incomplete.
            return TriState.False;
        }
        var r = right.Evaluate(ctx);
        if (r.IsFalse)
        {
            return TriState.False;
        }
        if (l.IsIncomplete)
        {
            return l;
        }
        if (r.IsIncomplete)
        {
            return r;
        }
        return TriState.True;
    }
}

internal sealed class OrNode(ConditionNode left, ConditionNode right) : ConditionNode
{
    public override TriState Evaluate(SigmaEvalContext ctx)
    {
        var l = left.Evaluate(ctx);
        if (l.IsTrue)
        {
            return TriState.True;
        }
        var r = right.Evaluate(ctx);
        if (r.IsTrue)
        {
            return TriState.True;
        }
        if (l.IsIncomplete)
        {
            return l;
        }
        if (r.IsIncomplete)
        {
            return r;
        }
        return TriState.False;
    }
}

/// <summary>
/// <c>N of targets</c> / <c>any of targets</c> / <c>all of targets</c>. Targets are
/// resolved at compile time (declaration order — deterministic). Kleene counting: the
/// answer is definite as soon as it no longer depends on the Incomplete targets.
/// </summary>
internal sealed class OfNode(int minimum, bool requireAll, DetectionItem[] targets) : ConditionNode
{
    public override TriState Evaluate(SigmaEvalContext ctx)
    {
        if (requireAll)
        {
            string? incomplete = null;
            foreach (var item in targets)
            {
                var r = item.Evaluate(ctx);
                if (r.IsFalse)
                {
                    return TriState.False;
                }
                if (r.IsIncomplete)
                {
                    incomplete ??= r.Reason;
                }
            }
            return incomplete is null ? TriState.True : TriState.Incomplete(incomplete);
        }

        int matched = 0;
        int unknown = 0;
        string? reason = null;
        foreach (var item in targets)
        {
            var r = item.Evaluate(ctx);
            if (r.IsTrue)
            {
                matched++;
                if (matched >= minimum)
                {
                    return TriState.True;
                }
            }
            else if (r.IsIncomplete)
            {
                unknown++;
                reason ??= r.Reason;
            }
        }
        // Not enough definite hits. If even counting every unknown as a hit cannot reach
        // the threshold, the answer is a trustworthy false; otherwise it is Incomplete.
        return matched + unknown < minimum
            ? TriState.False
            : TriState.Incomplete(reason!);
    }
}

/// <summary>
/// Recursive-descent parser for <c>condition</c> strings: <c>and</c>/<c>or</c>/<c>not</c>
/// (in ascending binding order or → and → not), parentheses, selection references, and
/// <c>N|any|all of them|name|pattern*</c>. Keywords are lowercase, as in the reference
/// grammar; selection names resolve case-sensitively. Errors throw
/// <see cref="SigmaCompileException"/> with a position inside the condition string.
/// </summary>
internal sealed class SigmaConditionParser
{
    private readonly record struct Token(string Text, int Offset);

    private readonly List<Token> _tokens;
    private readonly YamlPosition _basePosition;
    private readonly IReadOnlyList<DetectionItem> _items;
    private readonly IReadOnlyDictionary<string, DetectionItem> _byName;
    private int _index;

    private static readonly string[] Keywords = ["and", "or", "not", "of", "them", "all", "any"];

    private SigmaConditionParser(
        string text,
        YamlPosition basePosition,
        IReadOnlyList<DetectionItem> items,
        IReadOnlyDictionary<string, DetectionItem> byName)
    {
        _basePosition = basePosition;
        _items = items;
        _byName = byName;
        _tokens = Tokenize(text, basePosition);
    }

    public static ConditionNode Parse(
        string text,
        YamlPosition basePosition,
        IReadOnlyList<DetectionItem> items,
        IReadOnlyDictionary<string, DetectionItem> byName)
    {
        var parser = new SigmaConditionParser(text, basePosition, items, byName);
        if (parser._tokens.Count == 0)
        {
            throw new SigmaCompileException("condition is empty", basePosition);
        }
        var node = parser.ParseOr();
        if (parser._index < parser._tokens.Count)
        {
            var stray = parser._tokens[parser._index];
            throw new SigmaCompileException(
                $"unexpected '{stray.Text}' after the end of the condition expression",
                parser.PositionOf(stray));
        }
        return node;
    }

    private static List<Token> Tokenize(string text, YamlPosition basePosition)
    {
        var tokens = new List<Token>();
        int i = 0;
        while (i < text.Length)
        {
            char c = text[i];
            if (c is ' ' or '\t' or '\n')
            {
                i++;
                continue;
            }
            if (c is '(' or ')')
            {
                tokens.Add(new Token(c.ToString(), i));
                i++;
                continue;
            }
            if (char.IsAsciiLetterOrDigit(c) || c is '_' or '*' or '?')
            {
                int start = i;
                while (i < text.Length
                    && (char.IsAsciiLetterOrDigit(text[i]) || text[i] is '_' or '*' or '?'))
                {
                    i++;
                }
                tokens.Add(new Token(text[start..i], start));
                continue;
            }
            throw new SigmaCompileException(
                $"unexpected character '{c}' in condition",
                new YamlPosition(basePosition.Line, basePosition.Column + i));
        }
        return tokens;
    }

    private YamlPosition PositionOf(Token token) =>
        new(_basePosition.Line, _basePosition.Column + token.Offset);

    private bool TryPeek(out Token token)
    {
        if (_index < _tokens.Count)
        {
            token = _tokens[_index];
            return true;
        }
        token = default;
        return false;
    }

    private Token Expect(string what)
    {
        if (_index >= _tokens.Count)
        {
            throw new SigmaCompileException(
                $"condition ends where {what} was expected",
                new YamlPosition(_basePosition.Line, _basePosition.Column));
        }
        return _tokens[_index++];
    }

    private ConditionNode ParseOr()
    {
        var node = ParseAnd();
        while (TryPeek(out var t) && t.Text == "or")
        {
            _index++;
            node = new OrNode(node, ParseAnd());
        }
        return node;
    }

    private ConditionNode ParseAnd()
    {
        var node = ParseNot();
        while (TryPeek(out var t) && t.Text == "and")
        {
            _index++;
            node = new AndNode(node, ParseNot());
        }
        return node;
    }

    private ConditionNode ParseNot()
    {
        if (TryPeek(out var t) && t.Text == "not")
        {
            _index++;
            return new NotNode(ParseNot());
        }
        return ParsePrimary();
    }

    private ConditionNode ParsePrimary()
    {
        var token = Expect("a selection name, 'not', a quantifier, or '('");
        if (token.Text == "(")
        {
            var inner = ParseOr();
            var close = Expect("')'");
            if (close.Text != ")")
            {
                throw new SigmaCompileException($"expected ')', found '{close.Text}'", PositionOf(close));
            }
            return inner;
        }
        if (token.Text == ")")
        {
            throw new SigmaCompileException("unexpected ')'", PositionOf(token));
        }

        bool isAll = token.Text == "all";
        bool isAny = token.Text == "any";
        bool isCount = token.Text.Length > 0 && token.Text.All(char.IsAsciiDigit);
        if (isAll || isAny || isCount)
        {
            var of = Expect("'of'");
            if (of.Text != "of")
            {
                throw new SigmaCompileException(
                    $"expected 'of' after '{token.Text}', found '{of.Text}'", PositionOf(of));
            }
            return ParseOfTargets(token, isAll, isCount);
        }

        if (Array.IndexOf(Keywords, token.Text) >= 0)
        {
            throw new SigmaCompileException(
                $"unexpected keyword '{token.Text}' in condition", PositionOf(token));
        }
        if (!_byName.TryGetValue(token.Text, out var item))
        {
            throw new SigmaCompileException(
                $"condition references unknown selection '{token.Text}'", PositionOf(token));
        }
        return new ItemRefNode(item);
    }

    private ConditionNode ParseOfTargets(Token quantifier, bool isAll, bool isCount)
    {
        var target = Expect("'them', a selection name, or a name pattern");
        DetectionItem[] targets;
        if (target.Text == "them")
        {
            targets = _items.ToArray();
        }
        else if (target.Text.Contains('*') || target.Text.Contains('?'))
        {
            targets = _items.Where(i => WildcardMatches(i.Name, target.Text)).ToArray();
            if (targets.Length == 0)
            {
                // A quantifier over nothing would compile to a rule that can never fire —
                // indistinguishable from a passing scan. Refuse loudly instead.
                throw new SigmaCompileException(
                    $"'{target.Text}' matches no selection name", PositionOf(target));
            }
        }
        else if (_byName.TryGetValue(target.Text, out var single))
        {
            targets = [single];
        }
        else
        {
            throw new SigmaCompileException(
                $"condition references unknown selection '{target.Text}'", PositionOf(target));
        }

        if (isAll)
        {
            return new OfNode(targets.Length, requireAll: true, targets);
        }
        int minimum = 1;
        if (isCount)
        {
            if (!int.TryParse(quantifier.Text, out minimum) || minimum < 1)
            {
                throw new SigmaCompileException(
                    $"invalid quantifier '{quantifier.Text}'", PositionOf(quantifier));
            }
            if (minimum > targets.Length)
            {
                // Statically unsatisfiable — "N of" fewer than N selections is a rule
                // that silently never matches. Same refusal as an empty pattern.
                throw new SigmaCompileException(
                    $"'{quantifier.Text} of {target.Text}' requires {minimum} selections but only {targets.Length} match",
                    PositionOf(quantifier));
            }
        }
        return new OfNode(minimum, requireAll: false, targets);
    }

    /// <summary>Case-sensitive glob over selection names ('*'/'?'), matching the
    /// case-sensitive name resolution used for direct references.</summary>
    internal static bool WildcardMatches(string name, string pattern)
    {
        int t = 0;
        int p = 0;
        int starP = -1;
        int starT = 0;
        while (t < name.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || pattern[p] == name[t]))
            {
                p++;
                t++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                starP = p;
                p++;
                starT = t;
            }
            else if (starP >= 0)
            {
                p = starP + 1;
                starT++;
                t = starT;
            }
            else
            {
                return false;
            }
        }
        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }
        return p == pattern.Length;
    }
}
