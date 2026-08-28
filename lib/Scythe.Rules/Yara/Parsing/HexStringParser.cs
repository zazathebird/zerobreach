namespace Scythe.Rules.Yara.Parsing;

/// <summary>
/// Parses the body of a hex string, starting just after the opening '{'. This runs on raw
/// source text rather than the token stream because hex bytes ("4D 5A") would otherwise lex
/// as numbers and identifiers.
///
/// Structural rules enforced here, following the reference implementation:
///  - a hex string cannot begin or end with a jump;
///  - a jump's bounds must satisfy min &lt;= max;
///  - unbounded jumps are not allowed inside alternations (their length would be ambiguous);
///  - alternation nesting is capped so a hostile file cannot recurse the parser.
/// </summary>
public static class HexStringParser
{
    /// <summary>Alternation nesting cap. Real rules nest once or twice; a hostile file
    /// nesting hundreds deep is trying to exhaust the compiler.</summary>
    public const int MaxAlternationDepth = 16;

    /// <summary>Bounded jumps expand to NFA states, so their width is capped. The reference
    /// accepts wider jumps only in restricted contexts; 4096 covers observed corpus use.</summary>
    public const int MaxJumpLength = 4096;

    public static HexSequence? Parse(YaraLexer lexer, string fileName, List<Diagnostic> diagnostics)
    {
        var p = new Parser(lexer.Source, lexer.Position, lexer.Location, fileName, diagnostics);
        var seq = p.ParseTop();
        lexer.Reposition(p.Position, p.Line, p.Column);
        return seq;
    }

    private sealed class Parser
    {
        private readonly string _s;
        private readonly string _fileName;
        private readonly List<Diagnostic> _diagnostics;
        private int _pos;
        private int _line;
        private int _col;
        private bool _failed;

        public Parser(string source, int pos, SourceLocation loc, string fileName, List<Diagnostic> diagnostics)
        {
            _s = source;
            _pos = pos;
            _line = loc.Line;
            _col = loc.Column;
            _fileName = fileName;
            _diagnostics = diagnostics;
        }

        public int Position => _pos;
        public int Line => _line;
        public int Column => _col;

        private char Current => _pos < _s.Length ? _s[_pos] : '\0';
        private char Peek() => _pos + 1 < _s.Length ? _s[_pos + 1] : '\0';
        private SourceLocation Loc => new(_line, _col);

        private void Advance()
        {
            if (_pos >= _s.Length)
            {
                return;
            }
            if (_s[_pos] == '\n')
            {
                _line++;
                _col = 1;
            }
            else
            {
                _col++;
            }
            _pos++;
        }

        private void Error(DiagnosticCode code, string message, SourceLocation loc)
        {
            _failed = true;
            _diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, code, message, _fileName, loc));
        }

        private void SkipTrivia()
        {
            while (true)
            {
                char c = Current;
                if (c is ' ' or '\t' or '\r' or '\n')
                {
                    Advance();
                    continue;
                }
                if (c == '/' && Peek() == '/')
                {
                    while (Current is not ('\n' or '\0'))
                    {
                        Advance();
                    }
                    continue;
                }
                if (c == '/' && Peek() == '*')
                {
                    var loc = Loc;
                    Advance(); Advance();
                    bool closed = false;
                    while (Current != '\0')
                    {
                        if (Current == '*' && Peek() == '/')
                        {
                            Advance(); Advance();
                            closed = true;
                            break;
                        }
                        Advance();
                    }
                    if (!closed)
                    {
                        Error(DiagnosticCode.UnterminatedComment, "unterminated /* comment inside hex string", loc);
                    }
                    continue;
                }
                return;
            }
        }

        public HexSequence? ParseTop()
        {
            var start = Loc;
            var seq = ParseSequence(depth: 0, terminator: '}');
            SkipTrivia();
            if (Current == '}')
            {
                Advance();
            }
            else
            {
                Error(DiagnosticCode.UnterminatedHexString, $"unterminated hex string at {start}", start);
                return null;
            }
            if (_failed)
            {
                return null;
            }
            if (seq.Nodes.Count == 0)
            {
                Error(DiagnosticCode.EmptyString, "hex string is empty", start);
                return null;
            }
            if (seq.Nodes[0] is HexJumpNode || seq.Nodes[^1] is HexJumpNode)
            {
                Error(DiagnosticCode.InvalidHexJump, "a hex string cannot start or end with a jump", start);
                return null;
            }
            return seq;
        }

        private HexSequence ParseSequence(int depth, char terminator)
        {
            var nodes = new List<HexNode>();
            while (true)
            {
                SkipTrivia();
                char c = Current;
                if (c == '\0' || c == terminator || (terminator == '|' && c == ')') || c == '}' || c == ')' || c == '|')
                {
                    return new HexSequence(nodes);
                }
                if (c == '[')
                {
                    var jump = ParseJump(insideAlternation: depth > 0);
                    if (jump is not null)
                    {
                        nodes.Add(jump);
                    }
                    continue;
                }
                if (c == '(')
                {
                    var alt = ParseAlternation(depth);
                    if (alt is not null)
                    {
                        nodes.Add(alt);
                    }
                    continue;
                }
                var b = ParseByte();
                if (b is null)
                {
                    // Unparseable content: consume one character so we cannot loop forever,
                    // and let the caller decide the string failed.
                    Advance();
                    if (_failed && _diagnostics.Count > 200)
                    {
                        return new HexSequence(nodes);
                    }
                    continue;
                }
                nodes.Add(b);
            }
        }

        private HexAltNode? ParseAlternation(int depth)
        {
            var loc = Loc;
            if (depth + 1 > MaxAlternationDepth)
            {
                Error(DiagnosticCode.NestingTooDeep,
                    $"hex string alternation nested deeper than {MaxAlternationDepth} at {loc}", loc);
                // Consume the '(' so recovery makes progress.
                Advance();
                return null;
            }
            Advance(); // '('
            var branches = new List<HexSequence> { ParseSequence(depth + 1, '|') };
            while (true)
            {
                SkipTrivia();
                if (Current == '|')
                {
                    Advance();
                    branches.Add(ParseSequence(depth + 1, '|'));
                    continue;
                }
                if (Current == ')')
                {
                    Advance();
                    break;
                }
                Error(DiagnosticCode.UnterminatedHexString, $"unterminated alternation at {loc}", loc);
                return null;
            }
            foreach (var branch in branches)
            {
                if (branch.Nodes.Count == 0)
                {
                    Error(DiagnosticCode.SyntaxError, $"empty alternation branch at {loc}", loc);
                    return null;
                }
            }
            return new HexAltNode(branches);
        }

        private HexJumpNode? ParseJump(bool insideAlternation)
        {
            var loc = Loc;
            Advance(); // '['
            SkipTrivia();
            int? min = null, max = null;
            bool sawDash = false;

            if (char.IsAsciiDigit(Current))
            {
                min = ReadInt(loc);
            }
            SkipTrivia();
            if (Current == '-')
            {
                sawDash = true;
                Advance();
                SkipTrivia();
                if (char.IsAsciiDigit(Current))
                {
                    max = ReadInt(loc);
                }
            }
            SkipTrivia();
            if (Current != ']')
            {
                Error(DiagnosticCode.InvalidHexJump, $"malformed jump at {loc}; expected forms are [n], [n-m], [n-], [-m], [-]", loc);
                // Recover to the closing bracket if one exists nearby.
                while (Current is not (']' or '}' or '\0'))
                {
                    Advance();
                }
                if (Current == ']')
                {
                    Advance();
                }
                return null;
            }
            Advance(); // ']'

            // [n] is an exact jump; [n-] and [-] are unbounded.
            if (!sawDash)
            {
                if (min is null)
                {
                    Error(DiagnosticCode.InvalidHexJump, $"empty jump at {loc}", loc);
                    return null;
                }
                max = min;
            }
            min ??= 0;

            if (max is int m)
            {
                if (m < min.Value)
                {
                    Error(DiagnosticCode.InvalidHexJump, $"jump [{min}-{m}] at {loc} has min greater than max", loc);
                    return null;
                }
                if (m > MaxJumpLength)
                {
                    Error(DiagnosticCode.PatternTooComplex,
                        $"jump of up to {m} bytes at {loc} exceeds the supported maximum of {MaxJumpLength}", loc);
                    return null;
                }
            }
            else if (insideAlternation)
            {
                Error(DiagnosticCode.InvalidHexJump, $"unbounded jump at {loc} is not allowed inside an alternation", loc);
                return null;
            }
            return new HexJumpNode(min.Value, max);
        }

        private int ReadInt(SourceLocation loc)
        {
            long v = 0;
            while (char.IsAsciiDigit(Current))
            {
                v = v * 10 + (Current - '0');
                if (v > int.MaxValue)
                {
                    Error(DiagnosticCode.InvalidHexJump, $"jump length out of range at {loc}", loc);
                    v = int.MaxValue;
                }
                Advance();
            }
            return (int)v;
        }

        private HexByteNode? ParseByte()
        {
            var loc = Loc;
            bool negated = false;
            if (Current == '~')
            {
                negated = true;
                Advance();
                SkipTrivia();
            }
            char hi = Current;
            if (!IsNibble(hi))
            {
                Error(DiagnosticCode.SyntaxError,
                    $"unexpected character '{Printable(hi)}' in hex string at {loc}", loc);
                return null;
            }
            Advance();
            char lo = Current;
            if (!IsNibble(lo))
            {
                Error(DiagnosticCode.SyntaxError,
                    $"hex byte at {loc} needs two digits (or '?' wildcards); found '{Printable(lo)}'", loc);
                return null;
            }
            Advance();

            byte value = 0, mask = 0;
            if (hi != '?')
            {
                value |= (byte)(HexVal(hi) << 4);
                mask |= 0xF0;
            }
            if (lo != '?')
            {
                value |= (byte)HexVal(lo);
                mask |= 0x0F;
            }
            if (negated && mask == 0)
            {
                Error(DiagnosticCode.SyntaxError, $"'~??' at {loc} would match nothing", loc);
                return null;
            }
            return new HexByteNode(value, mask, negated);
        }

        private static bool IsNibble(char c) => char.IsAsciiHexDigit(c) || c == '?';

        private static int HexVal(char c) =>
            c <= '9' ? c - '0' : (char.ToLowerInvariant(c) - 'a' + 10);

        private static string Printable(char c) =>
            c == '\0' ? "end of file" : char.IsControl(c) ? $"\\x{(int)c:X2}" : c.ToString();
    }
}
