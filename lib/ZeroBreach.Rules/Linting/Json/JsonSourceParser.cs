using System.Globalization;
using System.Text;

namespace ZeroBreach.Rules.Linting.Json;

/// <summary>
/// Hand-written JSON parser that tracks line/column for every token. Accepts strict JSON
/// plus <c>//</c> and <c>/* */</c> comments, because the rule files this lints are
/// maintained by hand and shipped as JSONC (BLUEPRINT §9). Deliberately rejected:
/// trailing commas, unquoted keys, single quotes — the conservative reading of "JSON with
/// comments", and each rejection carries a message saying exactly what was found.
/// </summary>
public static class JsonSourceParser
{
    /// <summary>Nesting ceiling. A rule file is two levels deep; 64 is beyond any honest
    /// content and keeps a hostile file from recursing the parser off the stack.</summary>
    public const int MaxDepth = 64;

    public static JsonParseResult Parse(string text)
    {
        var parser = new Cursor(text);
        try
        {
            parser.SkipTrivia();
            var root = parser.ParseValue(depth: 0);
            parser.SkipTrivia();
            if (!parser.AtEnd)
            {
                return JsonParseResult.Failure(
                    $"unexpected content after the end of the JSON document: '{parser.Describe()}'",
                    parser.Location);
            }
            return JsonParseResult.Success(root);
        }
        catch (JsonSourceException ex)
        {
            return JsonParseResult.Failure(ex.Message, ex.Location);
        }
    }

    /// <summary>Internal control flow only; callers always receive a <see cref="JsonParseResult"/>.</summary>
    private sealed class JsonSourceException : Exception
    {
        public JsonSourceException(string message, LintLocation location) : base(message) =>
            Location = location;

        public LintLocation Location { get; }
    }

    private sealed class Cursor
    {
        private readonly string _text;
        private int _pos;
        private int _line = 1;
        private int _column = 1;

        public Cursor(string text) => _text = text;

        public bool AtEnd => _pos >= _text.Length;

        public LintLocation Location => new(_line, _column);

        public string Describe()
        {
            if (AtEnd)
            {
                return "end of file";
            }
            char c = _text[_pos];
            return char.IsControl(c) ? $"U+{(int)c:X4}" : c.ToString();
        }

        private char Peek() => _text[_pos];

        private char Advance()
        {
            char c = _text[_pos++];
            if (c == '\n')
            {
                _line++;
                _column = 1;
            }
            else
            {
                _column++;
            }
            return c;
        }

        [System.Diagnostics.CodeAnalysis.DoesNotReturn]
        private void Fail(string message) => throw new JsonSourceException(message, Location);

        [System.Diagnostics.CodeAnalysis.DoesNotReturn]
        private void FailAt(string message, LintLocation location) =>
            throw new JsonSourceException(message, location);

        /// <summary>Skips whitespace and comments — the "C" in JSONC.</summary>
        public void SkipTrivia()
        {
            while (!AtEnd)
            {
                char c = Peek();
                if (c is ' ' or '\t' or '\r' or '\n')
                {
                    Advance();
                }
                else if (c == '/' && _pos + 1 < _text.Length && _text[_pos + 1] == '/')
                {
                    while (!AtEnd && Peek() != '\n')
                    {
                        Advance();
                    }
                }
                else if (c == '/' && _pos + 1 < _text.Length && _text[_pos + 1] == '*')
                {
                    var start = Location;
                    Advance();
                    Advance();
                    bool closed = false;
                    while (!AtEnd)
                    {
                        if (Peek() == '*' && _pos + 1 < _text.Length && _text[_pos + 1] == '/')
                        {
                            Advance();
                            Advance();
                            closed = true;
                            break;
                        }
                        Advance();
                    }
                    if (!closed)
                    {
                        FailAt("unterminated /* comment", start);
                    }
                }
                else
                {
                    break;
                }
            }
        }

        public JsonSourceValue ParseValue(int depth)
        {
            if (depth > MaxDepth)
            {
                Fail($"nesting deeper than {MaxDepth} levels");
            }
            if (AtEnd)
            {
                Fail("unexpected end of file where a value was expected");
            }

            char c = Peek();
            return c switch
            {
                '{' => ParseObject(depth),
                '[' => ParseArray(depth),
                '"' => ParseString(),
                't' or 'f' => ParseKeyword(),
                'n' => ParseKeyword(),
                '-' or (>= '0' and <= '9') => ParseNumber(),
                '\'' => throw new JsonSourceException(
                    "single-quoted strings are not JSON; use double quotes", Location),
                _ => throw new JsonSourceException(
                    $"expected a value, found '{Describe()}'", Location),
            };
        }

        private JsonSourceValue ParseObject(int depth)
        {
            var start = Location;
            Advance(); // '{'
            var properties = new List<JsonSourceProperty>();
            SkipTrivia();
            if (!AtEnd && Peek() == '}')
            {
                Advance();
                return new JsonSourceObject(properties, start);
            }

            while (true)
            {
                SkipTrivia();
                if (AtEnd)
                {
                    FailAt("unterminated object: missing '}'", start);
                }
                if (Peek() != '"')
                {
                    Fail(Peek() switch
                    {
                        '}' => "trailing comma before '}'",
                        '\'' => "single-quoted strings are not JSON; use double quotes",
                        _ => $"expected a quoted property name, found '{Describe()}'",
                    });
                }
                var nameLocation = Location;
                var name = (JsonSourceString)ParseString();
                SkipTrivia();
                if (AtEnd || Peek() != ':')
                {
                    Fail($"expected ':' after property name \"{name.Value}\"");
                }
                Advance(); // ':'
                SkipTrivia();
                var value = ParseValue(depth + 1);
                properties.Add(new JsonSourceProperty(name.Value, nameLocation, value));

                SkipTrivia();
                if (AtEnd)
                {
                    FailAt("unterminated object: missing '}'", start);
                }
                char next = Advance();
                if (next == '}')
                {
                    return new JsonSourceObject(properties, start);
                }
                if (next != ',')
                {
                    Fail($"expected ',' or '}}' inside object, found '{next}'");
                }
            }
        }

        private JsonSourceValue ParseArray(int depth)
        {
            var start = Location;
            Advance(); // '['
            var items = new List<JsonSourceValue>();
            SkipTrivia();
            if (!AtEnd && Peek() == ']')
            {
                Advance();
                return new JsonSourceArray(items, start);
            }

            while (true)
            {
                SkipTrivia();
                if (AtEnd)
                {
                    FailAt("unterminated array: missing ']'", start);
                }
                if (Peek() == ']')
                {
                    Fail("trailing comma before ']'");
                }
                items.Add(ParseValue(depth + 1));
                SkipTrivia();
                if (AtEnd)
                {
                    FailAt("unterminated array: missing ']'", start);
                }
                char next = Advance();
                if (next == ']')
                {
                    return new JsonSourceArray(items, start);
                }
                if (next != ',')
                {
                    Fail($"expected ',' or ']' inside array, found '{next}'");
                }
            }
        }

        private JsonSourceValue ParseString()
        {
            var start = Location;
            Advance(); // opening quote
            var sb = new StringBuilder();
            while (true)
            {
                if (AtEnd)
                {
                    FailAt("unterminated string", start);
                }
                char c = Advance();
                if (c == '"')
                {
                    return new JsonSourceString(sb.ToString(), start);
                }
                if (c == '\n')
                {
                    FailAt("unterminated string (newline inside string literal)", start);
                }
                if (char.IsControl(c))
                {
                    Fail($"raw control character U+{(int)c:X4} inside string; use an escape");
                }
                if (c != '\\')
                {
                    sb.Append(c);
                    continue;
                }

                // Escape sequence. The location reported for a bad one is the backslash's.
                if (AtEnd)
                {
                    FailAt("unterminated string", start);
                }
                char esc = Advance();
                switch (esc)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        int code = 0;
                        for (int i = 0; i < 4; i++)
                        {
                            if (AtEnd || !Uri.IsHexDigit(Peek()))
                            {
                                Fail("\\u escape needs exactly four hex digits");
                            }
                            code = (code << 4) + Convert.ToInt32(Advance().ToString(), 16);
                        }
                        // Surrogate halves are appended as-is; a valid pair recombines
                        // naturally in the UTF-16 string being built.
                        sb.Append((char)code);
                        break;
                    default:
                        Fail($"invalid escape sequence '\\{esc}'");
                        break;
                }
            }
        }

        private JsonSourceValue ParseKeyword()
        {
            var start = Location;
            var sb = new StringBuilder();
            while (!AtEnd && char.IsAsciiLetter(Peek()))
            {
                sb.Append(Advance());
            }
            string word = sb.ToString();
            return word switch
            {
                "true" => new JsonSourceBoolean(true, start),
                "false" => new JsonSourceBoolean(false, start),
                "null" => new JsonSourceNull(start),
                _ => throw new JsonSourceException($"unexpected token '{word}'", start),
            };
        }

        private JsonSourceValue ParseNumber()
        {
            var start = Location;
            var sb = new StringBuilder();
            if (!AtEnd && Peek() == '-')
            {
                sb.Append(Advance());
            }
            while (!AtEnd && (char.IsAsciiDigit(Peek()) || Peek() is '.' or 'e' or 'E' or '+' or '-'))
            {
                sb.Append(Advance());
            }
            string raw = sb.ToString();
            if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out double value))
            {
                FailAt($"invalid number '{raw}'", start);
            }
            return new JsonSourceNumber(value, raw, start);
        }
    }
}
