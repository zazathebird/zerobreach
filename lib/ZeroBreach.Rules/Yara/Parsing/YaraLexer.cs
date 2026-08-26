using System.Text;

namespace ZeroBreach.Rules.Yara.Parsing;

/// <summary>
/// Hand-written lexer for YARA source. Notable corners, all of which follow the reference
/// implementation:
///  - `\` is YARA's integer division operator, so `/` unambiguously begins a regex literal
///    (after `//` and `/*` comments are ruled out).
///  - Text-string escapes are exactly \t \n \r \" \\ and \xNN; anything else is an error,
///    because a silently mis-unescaped pattern is a pattern that never matches.
///  - Identifiers are capped at <see cref="MaxIdentifierLength"/> (the reference cap), so a
///    hostile file with a megabyte identifier produces a diagnostic, not a megabyte token.
/// </summary>
public sealed class YaraLexer
{
    /// <summary>Reference YARA caps identifiers at 128 characters.</summary>
    public const int MaxIdentifierLength = 128;

    private readonly string _source;
    private readonly string _fileName;
    private readonly List<Diagnostic> _diagnostics;
    private int _pos;
    private int _line = 1;
    private int _col = 1;

    public YaraLexer(string source, string fileName, List<Diagnostic> diagnostics)
    {
        _source = source;
        _fileName = fileName;
        _diagnostics = diagnostics;
    }

    public int Position => _pos;
    public SourceLocation Location => new(_line, _col);

    /// <summary>Used by the hex-string sub-parser to hand control back after consuming raw text.</summary>
    public void Reposition(int pos, int line, int col)
    {
        _pos = pos;
        _line = line;
        _col = col;
    }

    public string Source => _source;

    private char Current => _pos < _source.Length ? _source[_pos] : '\0';
    private char Peek(int ahead = 1) => _pos + ahead < _source.Length ? _source[_pos + ahead] : '\0';

    private void Advance()
    {
        if (_pos >= _source.Length)
        {
            return;
        }
        if (_source[_pos] == '\n')
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

    private void Error(DiagnosticCode code, string message, SourceLocation loc) =>
        _diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, code, message, _fileName, loc));

    public YaraToken Next()
    {
        SkipTrivia();
        var loc = Location;
        char c = Current;

        if (c == '\0')
        {
            return new YaraToken(TokenKind.EndOfFile, "", loc);
        }

        if (char.IsAsciiLetter(c) || c == '_')
        {
            return LexIdentifier(loc);
        }
        if (char.IsAsciiDigit(c))
        {
            return LexNumber(loc);
        }

        switch (c)
        {
            case '$':
            case '#':
            case '@':
            case '!':
                // `!=` must win over a `!` string-length prefix.
                if (c == '!' && Peek() == '=')
                {
                    Advance(); Advance();
                    return new YaraToken(TokenKind.Ne, "!=", loc);
                }
                return LexStringRef(loc);
            case '"':
                return LexString(loc);
            case '/':
                return LexRegex(loc);
            case '{': Advance(); return new YaraToken(TokenKind.LBrace, "{", loc);
            case '}': Advance(); return new YaraToken(TokenKind.RBrace, "}", loc);
            case '(': Advance(); return new YaraToken(TokenKind.LParen, "(", loc);
            case ')': Advance(); return new YaraToken(TokenKind.RParen, ")", loc);
            case '[': Advance(); return new YaraToken(TokenKind.LBracket, "[", loc);
            case ']': Advance(); return new YaraToken(TokenKind.RBracket, "]", loc);
            case ':': Advance(); return new YaraToken(TokenKind.Colon, ":", loc);
            case ',': Advance(); return new YaraToken(TokenKind.Comma, ",", loc);
            case '.':
                Advance();
                if (Current == '.')
                {
                    Advance();
                    return new YaraToken(TokenKind.DotDot, "..", loc);
                }
                return new YaraToken(TokenKind.Dot, ".", loc);
            case '=':
                Advance();
                if (Current == '=')
                {
                    Advance();
                    return new YaraToken(TokenKind.Eq, "==", loc);
                }
                return new YaraToken(TokenKind.Assign, "=", loc);
            case '<':
                Advance();
                if (Current == '=') { Advance(); return new YaraToken(TokenKind.Le, "<=", loc); }
                if (Current == '<') { Advance(); return new YaraToken(TokenKind.Shl, "<<", loc); }
                return new YaraToken(TokenKind.Lt, "<", loc);
            case '>':
                Advance();
                if (Current == '=') { Advance(); return new YaraToken(TokenKind.Ge, ">=", loc); }
                if (Current == '>') { Advance(); return new YaraToken(TokenKind.Shr, ">>", loc); }
                return new YaraToken(TokenKind.Gt, ">", loc);
            case '+': Advance(); return new YaraToken(TokenKind.Plus, "+", loc);
            case '-': Advance(); return new YaraToken(TokenKind.Minus, "-", loc);
            case '*': Advance(); return new YaraToken(TokenKind.Star, "*", loc);
            case '\\': Advance(); return new YaraToken(TokenKind.Backslash, "\\", loc);
            case '%': Advance(); return new YaraToken(TokenKind.Percent, "%", loc);
            case '&': Advance(); return new YaraToken(TokenKind.Amp, "&", loc);
            case '|': Advance(); return new YaraToken(TokenKind.Pipe, "|", loc);
            case '^': Advance(); return new YaraToken(TokenKind.Caret, "^", loc);
            case '~': Advance(); return new YaraToken(TokenKind.Tilde, "~", loc);
            default:
                Error(DiagnosticCode.UnexpectedCharacter,
                    $"unexpected character '{(char.IsControl(c) ? $"\\x{(int)c:X2}" : c.ToString())}'", loc);
                Advance();
                // Recover by continuing with the next token so one stray byte does not
                // suppress every later diagnostic in the file.
                return Next();
        }
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
                var loc = Location;
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
                    Error(DiagnosticCode.UnterminatedComment, "unterminated /* comment", loc);
                }
                continue;
            }
            return;
        }
    }

    private YaraToken LexIdentifier(SourceLocation loc)
    {
        int start = _pos;
        while (char.IsAsciiLetterOrDigit(Current) || Current == '_')
        {
            Advance();
        }
        string text = _source[start.._pos];
        if (text.Length > MaxIdentifierLength)
        {
            Error(DiagnosticCode.IdentifierTooLong,
                $"identifier is {text.Length} characters long; the maximum is {MaxIdentifierLength}", loc);
            text = text[..MaxIdentifierLength];
        }
        return new YaraToken(TokenKind.Identifier, text, loc);
    }

    private YaraToken LexStringRef(SourceLocation loc)
    {
        char prefix = Current;
        Advance();
        int start = _pos;
        while (char.IsAsciiLetterOrDigit(Current) || Current == '_')
        {
            Advance();
        }
        string name = _source[start.._pos];
        if (name.Length > MaxIdentifierLength)
        {
            Error(DiagnosticCode.IdentifierTooLong,
                $"string identifier is {name.Length} characters long; the maximum is {MaxIdentifierLength}", loc);
            name = name[..MaxIdentifierLength];
        }
        if (prefix == '$' && Current == '*')
        {
            // `$a*` — the star is part of the token only when directly adjacent, so that
            // `$a * 2` (nonsense, but must not silently become a wildcard) still lexes as
            // a multiplication and fails in the parser with a useful position.
            Advance();
            return new YaraToken(TokenKind.StringIdWildcard, name, loc);
        }
        var kind = prefix switch
        {
            '$' => TokenKind.StringId,
            '#' => TokenKind.StringCountId,
            '@' => TokenKind.StringOffsetId,
            _ => TokenKind.StringLengthId,
        };
        return new YaraToken(kind, name, loc);
    }

    private YaraToken LexNumber(SourceLocation loc)
    {
        int start = _pos;
        if (Current == '0' && (Peek() is 'x' or 'X'))
        {
            Advance(); Advance();
            int digitsStart = _pos;
            while (char.IsAsciiHexDigit(Current))
            {
                Advance();
            }
            string hex = _source[digitsStart.._pos];
            if (hex.Length == 0 || !ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out ulong hv))
            {
                Error(DiagnosticCode.InvalidNumber, $"invalid hexadecimal literal '{_source[start.._pos]}'", loc);
                return new YaraToken(TokenKind.IntegerLiteral, _source[start.._pos], loc, 0);
            }
            return new YaraToken(TokenKind.IntegerLiteral, _source[start.._pos], loc, unchecked((long)hv));
        }
        if (Current == '0' && (Peek() is 'o' or 'O'))
        {
            Advance(); Advance();
            long value = 0;
            int digits = 0;
            bool overflow = false;
            while (Current is >= '0' and <= '7')
            {
                value = unchecked(value * 8 + (Current - '0'));
                if (++digits > 21) { overflow = true; }
                Advance();
            }
            if (digits == 0 || overflow)
            {
                Error(DiagnosticCode.InvalidNumber, $"invalid octal literal '{_source[start.._pos]}'", loc);
                value = 0;
            }
            return new YaraToken(TokenKind.IntegerLiteral, _source[start.._pos], loc, value);
        }

        while (char.IsAsciiDigit(Current))
        {
            Advance();
        }

        // A dot followed by a digit makes this a double; a lone dot is left for `..` ranges.
        if (Current == '.' && char.IsAsciiDigit(Peek()))
        {
            Advance();
            while (char.IsAsciiDigit(Current))
            {
                Advance();
            }
            string dtext = _source[start.._pos];
            if (!double.TryParse(dtext, System.Globalization.CultureInfo.InvariantCulture, out double dv))
            {
                Error(DiagnosticCode.InvalidNumber, $"invalid number '{dtext}'", loc);
                dv = 0;
            }
            return new YaraToken(TokenKind.DoubleLiteral, dtext, loc, DoubleValue: dv);
        }

        string text = _source[start.._pos];
        if (!long.TryParse(text, out long iv))
        {
            Error(DiagnosticCode.InvalidNumber, $"integer '{text}' is out of range", loc);
            iv = 0;
        }

        // KB / MB size suffixes (decimal literals only, as in the reference grammar).
        if (Current == 'K' && Peek() == 'B')
        {
            Advance(); Advance();
            iv = MultiplyGuarded(iv, 1024, loc, text + "KB");
            text += "KB";
        }
        else if (Current == 'M' && Peek() == 'B')
        {
            Advance(); Advance();
            iv = MultiplyGuarded(iv, 1024 * 1024, loc, text + "MB");
            text += "MB";
        }
        return new YaraToken(TokenKind.IntegerLiteral, text, loc, iv);
    }

    private long MultiplyGuarded(long value, long factor, SourceLocation loc, string text)
    {
        try
        {
            return checked(value * factor);
        }
        catch (OverflowException)
        {
            Error(DiagnosticCode.InvalidNumber, $"integer '{text}' is out of range", loc);
            return 0;
        }
    }

    private YaraToken LexString(SourceLocation loc)
    {
        Advance(); // opening quote
        var bytes = new List<byte>();
        while (true)
        {
            char c = Current;
            if (c == '"')
            {
                Advance();
                return new YaraToken(TokenKind.StringLiteral, "", loc, Bytes: bytes.ToArray());
            }
            if (c is '\0' or '\n')
            {
                Error(DiagnosticCode.UnterminatedString, $"unterminated string at {loc}", loc);
                return new YaraToken(TokenKind.StringLiteral, "", loc, Bytes: bytes.ToArray());
            }
            if (c == '\\')
            {
                var escLoc = Location;
                Advance();
                char e = Current;
                switch (e)
                {
                    case 't': bytes.Add((byte)'\t'); Advance(); break;
                    case 'n': bytes.Add((byte)'\n'); Advance(); break;
                    case 'r': bytes.Add((byte)'\r'); Advance(); break;
                    case '"': bytes.Add((byte)'"'); Advance(); break;
                    case '\\': bytes.Add((byte)'\\'); Advance(); break;
                    case 'x':
                        Advance();
                        char h1 = Current, h2 = Peek();
                        if (char.IsAsciiHexDigit(h1) && char.IsAsciiHexDigit(h2))
                        {
                            bytes.Add((byte)(HexVal(h1) * 16 + HexVal(h2)));
                            Advance(); Advance();
                        }
                        else
                        {
                            Error(DiagnosticCode.InvalidEscapeSequence,
                                $"\\x must be followed by two hexadecimal digits at {escLoc}", escLoc);
                        }
                        break;
                    default:
                        Error(DiagnosticCode.InvalidEscapeSequence,
                            $"invalid escape sequence '\\{e}' at {escLoc}; valid escapes are \\t \\n \\r \\\" \\\\ \\xNN", escLoc);
                        Advance();
                        break;
                }
                continue;
            }
            // Non-ASCII characters in a source string are stored as their UTF-8 bytes,
            // matching how the reference reads rule files as raw bytes.
            if (c <= 0x7F)
            {
                bytes.Add((byte)c);
                Advance();
            }
            else
            {
                bytes.AddRange(Encoding.UTF8.GetBytes(c.ToString()));
                Advance();
            }
        }
    }

    private static int HexVal(char c) =>
        c <= '9' ? c - '0' : (char.ToLowerInvariant(c) - 'a' + 10);

    private YaraToken LexRegex(SourceLocation loc)
    {
        Advance(); // opening '/'
        var sb = new StringBuilder();
        while (true)
        {
            char c = Current;
            if (c == '/')
            {
                Advance();
                break;
            }
            if (c is '\0' or '\n')
            {
                Error(DiagnosticCode.UnterminatedRegex, $"unterminated regular expression at {loc}", loc);
                return new YaraToken(TokenKind.RegexLiteral, sb.ToString(), loc);
            }
            if (c == '\\')
            {
                // Keep the escape intact for the regex compiler; `\/` unescapes here since
                // the slash only needs escaping to survive the literal delimiters.
                Advance();
                if (Current == '/')
                {
                    sb.Append('/');
                    Advance();
                }
                else
                {
                    sb.Append('\\');
                    if (Current != '\0')
                    {
                        sb.Append(Current);
                        Advance();
                    }
                }
                continue;
            }
            sb.Append(c);
            Advance();
        }
        bool i = false, s = false;
        while (Current is 'i' or 's')
        {
            if (Current == 'i') { i = true; }
            else { s = true; }
            Advance();
        }
        return new YaraToken(TokenKind.RegexLiteral, sb.ToString(), loc, RegexI: i, RegexS: s);
    }
}
