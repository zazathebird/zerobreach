namespace Scythe.Rules.Linting.Patterns;

/// <summary>
/// Parses the common subset of the .NET regex dialect into <see cref="PatternNode"/>s.
/// Runs only on patterns that already compiled under <c>System.Text.RegularExpressions</c>
/// (compile failures are their own finding first), so a hard parse failure here is rare;
/// when it happens, or when a construct is beyond the model, the caller gets
/// null / <see cref="PatternUnsupported"/> and the dependent analysis skips honestly.
/// </summary>
internal static class PatternParser
{
    /// <summary>Parses <paramref name="pattern"/>; null when the structure could not be
    /// modelled at all (the analyses relying on it then simply do not run).</summary>
    public static PatternNode? TryParse(string pattern)
    {
        try
        {
            var cursor = new Cursor(pattern);
            var node = ParseAlternation(cursor);
            return cursor.AtEnd ? node : null;
        }
        catch (UnparseableException)
        {
            return null;
        }
    }

    private sealed class UnparseableException : Exception;

    private sealed class Cursor
    {
        private readonly string _s;
        public int Pos;

        public Cursor(string s) => _s = s;

        public bool AtEnd => Pos >= _s.Length;
        public char Peek() => _s[Pos];
        public char PeekAt(int offset) => Pos + offset < _s.Length ? _s[Pos + offset] : '\0';
        public char Next() => _s[Pos++];

        public bool TryEat(char c)
        {
            if (!AtEnd && Peek() == c)
            {
                Pos++;
                return true;
            }
            return false;
        }
    }

    private static PatternNode ParseAlternation(Cursor c)
    {
        var branches = new List<PatternNode> { ParseConcat(c) };
        while (c.TryEat('|'))
        {
            branches.Add(ParseConcat(c));
        }
        return branches.Count == 1 ? branches[0] : new PatternAlternation(branches);
    }

    private static PatternNode ParseConcat(Cursor c)
    {
        var items = new List<PatternNode>();
        while (!c.AtEnd && c.Peek() != '|' && c.Peek() != ')')
        {
            var atom = ParseAtom(c);
            items.Add(ApplyQuantifier(c, atom));
        }
        return items.Count == 1 ? items[0] : new PatternConcat(items);
    }

    private static PatternNode ApplyQuantifier(Cursor c, PatternNode atom)
    {
        if (c.AtEnd)
        {
            return atom;
        }

        int min, max;
        switch (c.Peek())
        {
            case '*': c.Next(); min = 0; max = int.MaxValue; break;
            case '+': c.Next(); min = 1; max = int.MaxValue; break;
            case '?': c.Next(); min = 0; max = 1; break;
            case '{':
                if (!TryParseCountedQuantifier(c, out min, out max))
                {
                    return atom; // '{' without a valid counter is a literal, as in .NET
                }
                break;
            default:
                return atom;
        }

        c.TryEat('?'); // laziness does not change what can match, only in what order
        return new PatternRepeat(atom, min, max);
    }

    private static bool TryParseCountedQuantifier(Cursor c, out int min, out int max)
    {
        // Only commits (consumes) when the full {n} / {n,} / {n,m} shape is present.
        min = 0;
        max = 0;
        int probe = c.Pos + 1; // past '{'
        int ReadNumber(ref int at)
        {
            int start = at;
            long value = 0;
            while (at < int.MaxValue && probeChar(at) is >= '0' and <= '9')
            {
                value = value * 10 + (probeChar(at) - '0');
                if (value > int.MaxValue)
                {
                    return -1;
                }
                at++;
            }
            return at == start ? -1 : (int)value;
        }
        char probeChar(int at) => c.PeekAt(at - c.Pos);

        int n = ReadNumber(ref probe);
        if (n < 0)
        {
            return false;
        }
        min = n;
        max = n;
        if (probeChar(probe) == ',')
        {
            probe++;
            if (probeChar(probe) == '}')
            {
                max = int.MaxValue;
            }
            else
            {
                int m = ReadNumber(ref probe);
                if (m < 0)
                {
                    return false;
                }
                max = m;
            }
        }
        if (probeChar(probe) != '}')
        {
            return false;
        }
        c.Pos = probe + 1;
        return true;
    }

    private static PatternNode ParseAtom(Cursor c)
    {
        char ch = c.Next();
        return ch switch
        {
            '(' => ParseGroup(c),
            '[' => ParseCharClass(c),
            '.' => new PatternAny(),
            '^' => new PatternAnchor(PatternAnchorKind.Start),
            '$' => new PatternAnchor(PatternAnchorKind.End),
            '\\' => ParseEscape(c),
            ')' or '|' => throw new UnparseableException(), // callers stop before these
            '*' or '+' or '?' => throw new UnparseableException(), // quantifier with no atom
            _ => new PatternLiteral(ch),
        };
    }

    private static PatternNode ParseGroup(Cursor c)
    {
        if (c.TryEat('?'))
        {
            if (c.AtEnd)
            {
                throw new UnparseableException();
            }
            char kind = c.Peek();
            switch (kind)
            {
                case ':': // (?:...)
                    c.Next();
                    return FinishGroup(c, unsupported: null);
                case '>': // atomic (?>...) — same language, different search order
                    c.Next();
                    return FinishGroup(c, unsupported: null);
                case '=' or '!': // lookahead
                    c.Next();
                    return FinishGroup(c, unsupported: "lookahead");
                case '<':
                    // (?<name>...) capture, or (?<=...) / (?<!...) lookbehind.
                    if (c.PeekAt(1) is '=' or '!')
                    {
                        c.Next();
                        c.Next();
                        return FinishGroup(c, unsupported: "lookbehind");
                    }
                    SkipUntil(c, '>');
                    return FinishGroup(c, unsupported: null);
                case '\'': // (?'name'...)
                    c.Next();
                    SkipUntil(c, '\'');
                    return FinishGroup(c, unsupported: null);
                case '(': // conditional (?(...)...)
                    ConsumeBalanced(c);
                    return new PatternUnsupported("conditional");
                default:
                    // Inline options: (?imnsx-imnsx) toggles, or (?imnsx:...) scoped.
                    while (!c.AtEnd && c.Peek() is not (':' or ')'))
                    {
                        c.Next();
                    }
                    if (c.TryEat(':'))
                    {
                        return FinishGroup(c, unsupported: null);
                    }
                    if (c.TryEat(')'))
                    {
                        return PatternConcat.Empty; // zero-width flag toggle
                    }
                    throw new UnparseableException();
            }
        }
        return FinishGroup(c, unsupported: null);
    }

    private static PatternNode FinishGroup(Cursor c, string? unsupported)
    {
        var inner = ParseAlternation(c);
        if (!c.TryEat(')'))
        {
            throw new UnparseableException();
        }
        return unsupported is null ? new PatternGroup(inner) : new PatternUnsupported(unsupported);
    }

    private static void SkipUntil(Cursor c, char terminator)
    {
        c.Next(); // the '<' or '\''
        while (!c.AtEnd && c.Peek() != terminator)
        {
            c.Next();
        }
        if (!c.TryEat(terminator))
        {
            throw new UnparseableException();
        }
    }

    /// <summary>Consumes the remainder of an already-opened <c>(</c>…<c>)</c> without
    /// interpreting it — used for conditionals, which the model does not represent.</summary>
    private static void ConsumeBalanced(Cursor c)
    {
        int depth = 1;
        bool inClass = false;
        while (!c.AtEnd)
        {
            char ch = c.Next();
            if (ch == '\\' && !c.AtEnd)
            {
                c.Next();
            }
            else if (inClass)
            {
                inClass = ch != ']';
            }
            else if (ch == '[')
            {
                inClass = true;
            }
            else if (ch == '(')
            {
                depth++;
            }
            else if (ch == ')' && --depth == 0)
            {
                return;
            }
        }
        throw new UnparseableException();
    }

    private static PatternNode ParseEscape(Cursor c)
    {
        if (c.AtEnd)
        {
            throw new UnparseableException();
        }
        char ch = c.Next();
        switch (ch)
        {
            case 'd': return PatternCharClass.Digit();
            case 'D': return PatternCharClass.Negate(PatternCharClass.Digit());
            case 'w': return PatternCharClass.Word();
            case 'W': return PatternCharClass.Negate(PatternCharClass.Word());
            case 's': return PatternCharClass.Space();
            case 'S': return PatternCharClass.Negate(PatternCharClass.Space());
            case 'b': return new PatternAnchor(PatternAnchorKind.WordBoundary);
            case 'B': return new PatternAnchor(PatternAnchorKind.NotWordBoundary);
            case 'A': return new PatternAnchor(PatternAnchorKind.Start);
            case 'z' or 'Z': return new PatternAnchor(PatternAnchorKind.End);
            case 'G': return new PatternUnsupported(@"\G");
            case 'n': return new PatternLiteral('\n');
            case 'r': return new PatternLiteral('\r');
            case 't': return new PatternLiteral('\t');
            case 'f': return new PatternLiteral('\f');
            case 'v': return new PatternLiteral('\v');
            case 'e': return new PatternLiteral('\x1b');
            case 'a': return new PatternLiteral('\a');
            case '0': return new PatternLiteral('\0');
            case 'x': return new PatternLiteral(ReadHexLiteral(c, 2));
            case 'u': return new PatternLiteral(ReadHexLiteral(c, 4));
            case 'c':
                if (c.AtEnd)
                {
                    throw new UnparseableException();
                }
                return new PatternLiteral((char)(char.ToUpperInvariant(c.Next()) & 0x1F));
            case 'p' or 'P':
                if (c.TryEat('{'))
                {
                    while (!c.AtEnd && c.Peek() != '}')
                    {
                        c.Next();
                    }
                    if (!c.TryEat('}'))
                    {
                        throw new UnparseableException();
                    }
                }
                return new PatternUnsupported(@"\p category");
            case 'k':
                if (c.TryEat('<'))
                {
                    while (!c.AtEnd && c.Peek() != '>')
                    {
                        c.Next();
                    }
                    if (!c.TryEat('>'))
                    {
                        throw new UnparseableException();
                    }
                }
                return new PatternUnsupported("backreference");
            case >= '1' and <= '9':
                return new PatternUnsupported("backreference");
            default:
                // Identity escape: \. \\ \$ \[ … the escaped character itself.
                return new PatternLiteral(ch);
        }
    }

    private static char ReadHexLiteral(Cursor c, int digits)
    {
        int value = 0;
        for (int i = 0; i < digits; i++)
        {
            if (c.AtEnd || !Uri.IsHexDigit(c.Peek()))
            {
                throw new UnparseableException();
            }
            value = (value << 4) + Convert.ToInt32(c.Next().ToString(), 16);
        }
        return (char)value;
    }

    private static PatternNode ParseCharClass(Cursor c)
    {
        bool negated = c.TryEat('^');
        var ranges = new List<(char Lo, char Hi)>();
        bool exact = true;
        bool first = true;

        while (true)
        {
            if (c.AtEnd)
            {
                throw new UnparseableException(); // unterminated class
            }
            if (c.Peek() == ']' && !first)
            {
                c.Next();
                break;
            }
            first = false;

            // .NET class subtraction: [a-z-[aeiou]]. The range model cannot carry it;
            // consume it and mark the class inexact so no analysis trusts membership.
            if (c.Peek() == '-' && c.PeekAt(1) == '[')
            {
                c.Next();
                c.Next();
                int depth = 1;
                while (!c.AtEnd && depth > 0)
                {
                    char sub = c.Next();
                    if (sub == '\\' && !c.AtEnd)
                    {
                        c.Next();
                    }
                    else if (sub == '[')
                    {
                        depth++;
                    }
                    else if (sub == ']')
                    {
                        depth--;
                    }
                }
                exact = false;
                continue;
            }

            var (lo, isClass) = ReadClassMember(c, ref exact);
            if (isClass)
            {
                continue; // shorthand already merged into ranges
            }

            if (!c.AtEnd && c.Peek() == '-' && c.PeekAt(1) != ']' && c.PeekAt(1) != '\0' && c.PeekAt(1) != '[')
            {
                c.Next(); // '-'
                var (hi, hiIsClass) = ReadClassMember(c, ref exact);
                if (hiIsClass || hi < lo)
                {
                    throw new UnparseableException();
                }
                ranges.Add((lo, hi));
            }
            else
            {
                ranges.Add((lo, lo));
            }
        }

        return new PatternCharClass(ranges, negated, exact);

        (char Ch, bool IsClass) ReadClassMember(Cursor cur, ref bool exactRef)
        {
            char ch = cur.Next();
            if (ch != '\\')
            {
                return (ch, false);
            }
            if (cur.AtEnd)
            {
                throw new UnparseableException();
            }
            char esc = cur.Next();
            switch (esc)
            {
                case 'd': ranges.Add(('0', '9')); return ('\0', true);
                case 'w':
                    ranges.Add(('a', 'z'));
                    ranges.Add(('A', 'Z'));
                    ranges.Add(('0', '9'));
                    ranges.Add(('_', '_'));
                    return ('\0', true);
                case 's':
                    ranges.Add((' ', ' '));
                    ranges.Add(('\t', '\t'));
                    ranges.Add(('\n', '\n'));
                    ranges.Add(('\v', '\v'));
                    ranges.Add(('\f', '\f'));
                    ranges.Add(('\r', '\r'));
                    return ('\0', true);
                case 'D' or 'W' or 'S' or 'p' or 'P':
                    // A negated shorthand inside a class union cannot be expressed as
                    // added ranges; mark inexact rather than approximate.
                    if (esc is 'p' or 'P' && cur.TryEat('{'))
                    {
                        while (!cur.AtEnd && cur.Peek() != '}')
                        {
                            cur.Next();
                        }
                        if (!cur.TryEat('}'))
                        {
                            throw new UnparseableException();
                        }
                    }
                    exactRef = false;
                    return ('\0', true);
                case 'n': return ('\n', false);
                case 'r': return ('\r', false);
                case 't': return ('\t', false);
                case 'f': return ('\f', false);
                case 'v': return ('\v', false);
                case 'e': return ('\x1b', false);
                case 'a': return ('\a', false);
                case 'b': return ('\b', false); // inside a class, \b is backspace
                case '0': return ('\0', false);
                case 'x': return (ReadHexLiteral(cur, 2), false);
                case 'u': return (ReadHexLiteral(cur, 4), false);
                default: return (esc, false);
            }
        }
    }
}
