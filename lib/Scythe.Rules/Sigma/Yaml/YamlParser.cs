using System.Globalization;
using System.Text;

namespace Scythe.Rules.Sigma.Yaml;

/// <summary>
/// Minimal YAML reader for the Sigma subset: block and flow mappings/sequences, plain and
/// quoted scalars (with number/boolean/null typing), comments, and literal/folded block
/// scalars. Anchors (&amp;), aliases (*), tags (!) and multiple documents are rejected
/// explicitly with a position — never silently misread. Malformed input throws
/// <see cref="YamlFormatException"/>, which the compiler converts to a Failed result.
/// </summary>
internal sealed class YamlParser
{
    /// <summary>Ceiling on structural nesting. Sigma rules nest four or five levels; an
    /// input past this is a mistake or an attack on the parser, not a rule.</summary>
    internal const int MaxNestingDepth = 16;

    /// <summary>A content line: indentation stripped, blank/comment-only lines removed.</summary>
    private sealed class Line
    {
        public required int Number;    // 1-based line number in the raw source
        public required int RawIndex;  // index into _raw, for block-scalar re-reading
        public required int Indent;    // count of leading spaces
        public required string Text;   // content after the indent (comments NOT stripped)
    }

    private readonly string[] _raw;
    private readonly List<Line> _lines = [];
    private int _index;

    private YamlParser(string source)
    {
        _raw = source.Split('\n');
        bool sawDocumentStart = false;
        bool sawDocumentEnd = false;
        for (int i = 0; i < _raw.Length; i++)
        {
            string raw = _raw[i].TrimEnd('\r');
            _raw[i] = raw;
            int indent = 0;
            while (indent < raw.Length && raw[indent] == ' ')
            {
                indent++;
            }
            if (indent < raw.Length && raw[indent] == '\t')
            {
                // YAML forbids tabs in indentation, and a tab that silently counted as one
                // column would shift the whole structure of the rule.
                throw new YamlFormatException("tab character in indentation (YAML requires spaces)",
                    new YamlPosition(i + 1, indent + 1));
            }
            string text = raw[indent..];
            if (text.Length == 0 || text[0] == '#')
            {
                continue;
            }
            string trimmed = text.TrimEnd();
            if (trimmed == "---")
            {
                if (sawDocumentStart || _lines.Count > 0)
                {
                    throw new YamlFormatException(
                        "multiple YAML documents in one source are not supported ('---')",
                        new YamlPosition(i + 1, indent + 1));
                }
                sawDocumentStart = true;
                continue;
            }
            if (trimmed == "...")
            {
                sawDocumentEnd = true;
                continue;
            }
            if (sawDocumentEnd)
            {
                throw new YamlFormatException("content after end-of-document marker ('...')",
                    new YamlPosition(i + 1, indent + 1));
            }
            _lines.Add(new Line { Number = i + 1, RawIndex = i, Indent = indent, Text = text });
        }
    }

    public static YamlNode ParseDocument(string source)
    {
        var parser = new YamlParser(source);
        if (parser._lines.Count == 0)
        {
            throw new YamlFormatException("document contains no content", new YamlPosition(1, 1));
        }
        var node = parser.ParseNode(depth: 0);
        if (parser._index < parser._lines.Count)
        {
            var stray = parser._lines[parser._index];
            throw new YamlFormatException("unexpected content after the document root node",
                new YamlPosition(stray.Number, stray.Indent + 1));
        }
        return node;
    }

    private Line Current => _lines[_index];
    private bool AtEnd => _index >= _lines.Count;
    private Line? Peek => AtEnd ? null : _lines[_index];

    private static void CheckDepth(int depth, YamlPosition at)
    {
        if (depth > MaxNestingDepth)
        {
            throw new YamlFormatException($"nesting depth exceeds {MaxNestingDepth}", at);
        }
    }

    /// <summary>Parses the block node starting at the current line, whose indent defines
    /// the block's indent.</summary>
    private YamlNode ParseNode(int depth)
    {
        var line = Current;
        CheckDepth(depth, new YamlPosition(line.Number, line.Indent + 1));
        return IsSequenceItem(line.Text)
            ? ParseBlockSequence(line.Indent, depth)
            : ParseMappingOrScalar(line.Indent, depth);
    }

    private static bool IsSequenceItem(string text) =>
        text == "-" || text.StartsWith("- ", StringComparison.Ordinal);

    private YamlNode ParseBlockSequence(int indent, int depth)
    {
        var seq = new YamlSequence { Position = new YamlPosition(Current.Number, indent + 1) };
        while (!AtEnd && Current.Indent == indent && IsSequenceItem(Current.Text))
        {
            var line = Current;
            string rest = line.Text == "-" ? "" : line.Text[2..];
            int extra = 0;
            while (extra < rest.Length && rest[extra] == ' ')
            {
                extra++;
            }
            rest = rest[extra..];
            if (rest.Length == 0 || rest[0] == '#')
            {
                // "- " with the value on following, deeper-indented lines (or an empty item).
                _index++;
                if (!AtEnd && Current.Indent > indent)
                {
                    seq.Items.Add(ParseNode(depth + 1));
                }
                else
                {
                    seq.Items.Add(new YamlScalar
                    {
                        Value = null,
                        Position = new YamlPosition(line.Number, indent + 2),
                    });
                }
            }
            else
            {
                // Inline item ("- value", "- key: v" with continuations, "- [flow]").
                // Rewriting the current line to start at the item content and re-entering
                // ParseNode handles every form uniformly, including "- key: v" followed by
                // sibling keys indented to the content column.
                int contentIndent = indent + 2 + extra;
                line.Indent = contentIndent;
                line.Text = rest;
                seq.Items.Add(ParseNode(depth + 1));
            }
        }
        if (!AtEnd && Current.Indent > indent)
        {
            throw new YamlFormatException("unexpected indentation inside sequence",
                new YamlPosition(Current.Number, Current.Indent + 1));
        }
        return seq;
    }

    private YamlNode ParseMappingOrScalar(int indent, int depth)
    {
        var first = Current;
        if (!TryFindKey(first, out _, out _))
        {
            // No "key:" on the line — a scalar document / sequence item.
            var scalar = ParseValueOnLine(first, first.Indent, depth);
            _index++;
            if (!AtEnd && Current.Indent > indent)
            {
                throw new YamlFormatException(
                    "multi-line plain scalars are not supported (unexpected indentation after scalar)",
                    new YamlPosition(Current.Number, Current.Indent + 1));
            }
            return scalar;
        }

        var map = new YamlMapping { Position = new YamlPosition(first.Number, indent + 1) };
        while (!AtEnd && Current.Indent >= indent)
        {
            var line = Current;
            if (line.Indent > indent)
            {
                throw new YamlFormatException("unexpected indentation",
                    new YamlPosition(line.Number, line.Indent + 1));
            }
            if (IsSequenceItem(line.Text))
            {
                throw new YamlFormatException("unexpected sequence item inside mapping",
                    new YamlPosition(line.Number, line.Indent + 1));
            }
            if (!TryFindKey(line, out string key, out int restStart))
            {
                throw new YamlFormatException("expected 'key:' in mapping",
                    new YamlPosition(line.Number, line.Indent + 1));
            }
            var keyPos = new YamlPosition(line.Number, line.Indent + 1);
            foreach (var existing in map.Entries)
            {
                if (string.Equals(existing.Key, key, StringComparison.Ordinal))
                {
                    // Last-wins would silently discard half a rule; refuse instead.
                    throw new YamlFormatException($"duplicate mapping key '{key}'", keyPos);
                }
            }

            int valueCol = restStart;
            string rest = line.Text[restStart..];
            int lead = 0;
            while (lead < rest.Length && rest[lead] == ' ')
            {
                lead++;
            }
            valueCol += lead;
            rest = rest[lead..].TrimEnd();

            YamlNode value;
            if (rest.Length == 0 || rest[0] == '#')
            {
                _index++;
                if (!AtEnd && Current.Indent > indent)
                {
                    value = ParseNode(depth + 1);
                }
                else if (!AtEnd && Current.Indent == indent && IsSequenceItem(Current.Text))
                {
                    // A block sequence indented level with its key is valid YAML and common
                    // in real Sigma rules ("fields:\n- a\n- b").
                    value = ParseBlockSequence(indent, depth + 1);
                }
                else
                {
                    value = new YamlScalar { Value = null, Position = keyPos };
                }
            }
            else if (rest[0] is '|' or '>')
            {
                value = ParseBlockScalar(line, indent, rest, valueCol);
            }
            else
            {
                var savedText = line.Text;
                line.Indent = line.Indent + valueCol;
                line.Text = savedText[valueCol..];
                value = ParseValueOnLine(line, line.Indent, depth + 1);
                _index++;
                if (!AtEnd && Current.Indent > indent)
                {
                    throw new YamlFormatException(
                        "multi-line plain scalars are not supported (unexpected indentation after value)",
                        new YamlPosition(Current.Number, Current.Indent + 1));
                }
            }
            map.Entries.Add(new YamlMapEntry(key, keyPos, value));
        }
        return map;
    }

    /// <summary>Finds "key:" on a line: a plain or quoted key followed by ':' and a space
    /// or end of line. Returns false when the line holds no mapping key (a plain scalar).</summary>
    private static bool TryFindKey(Line line, out string key, out int restStart)
    {
        string text = line.Text;
        key = "";
        restStart = 0;
        int i = 0;
        if (text[0] is '"' or '\'')
        {
            key = ReadQuotedScalar(text, ref i, line.Number, line.Indent);
            while (i < text.Length && text[i] == ' ')
            {
                i++;
            }
            if (i >= text.Length || text[i] != ':')
            {
                // A quoted scalar with no following ':' is a value, not a key — e.g. a
                // quoted keyword inside a block sequence ("- 'mimikatz'").
                return false;
            }
            restStart = i + 1;
            return true;
        }
        for (; i < text.Length; i++)
        {
            char c = text[i];
            if (c == ':' && (i + 1 == text.Length || text[i + 1] == ' '))
            {
                key = text[..i].TrimEnd();
                if (key.Length == 0)
                {
                    throw new YamlFormatException("empty mapping key",
                        new YamlPosition(line.Number, line.Indent + 1));
                }
                restStart = i + 1;
                return true;
            }
            if (c == '#' && i > 0 && text[i - 1] == ' ')
            {
                return false; // comment starts before any key colon
            }
        }
        return false;
    }

    /// <summary>Parses an inline value: flow collection, quoted scalar, or plain scalar.
    /// Rejects anchors/aliases/tags here — the single most likely YAML feature to appear
    /// by accident, because an unquoted Sigma wildcard value starting with '*' is an alias
    /// in real YAML.</summary>
    private YamlNode ParseValueOnLine(Line line, int startColumnIndent, int depth)
    {
        string text = line.Text;
        var pos = new YamlPosition(line.Number, startColumnIndent + 1);
        CheckDepth(depth, pos);
        char c = text[0];
        switch (c)
        {
            case '&':
                throw new YamlFormatException("YAML anchors ('&') are not supported", pos);
            case '*':
                throw new YamlFormatException(
                    "YAML aliases ('*') are not supported; quote the value if a literal '*' wildcard is intended", pos);
            case '!':
                throw new YamlFormatException("YAML tags ('!') are not supported", pos);
            case '%':
                throw new YamlFormatException("YAML directives ('%') are not supported", pos);
            case '[' or '{':
            {
                int i = 0;
                var node = ParseFlowNode(text, ref i, line.Number, startColumnIndent, depth);
                SkipSpaces(text, ref i);
                if (i < text.Length && text[i] != '#')
                {
                    throw new YamlFormatException("unexpected content after flow collection",
                        new YamlPosition(line.Number, startColumnIndent + i + 1));
                }
                return node;
            }
            case '"' or '\'':
            {
                int i = 0;
                string value = ReadQuotedScalar(text, ref i, line.Number, startColumnIndent);
                SkipSpaces(text, ref i);
                if (i < text.Length && text[i] != '#')
                {
                    throw new YamlFormatException("unexpected content after quoted scalar",
                        new YamlPosition(line.Number, startColumnIndent + i + 1));
                }
                return new YamlScalar { Value = value, WasQuoted = true, Position = pos };
            }
            default:
            {
                string plain = StripComment(text).TrimEnd();
                return new YamlScalar { Value = InterpretPlain(plain), Position = pos };
            }
        }
    }

    private YamlNode ParseFlowNode(string text, ref int i, int lineNumber, int columnIndent, int depth)
    {
        var pos = new YamlPosition(lineNumber, columnIndent + i + 1);
        CheckDepth(depth, pos);
        char c = text[i];
        switch (c)
        {
            case '[':
            {
                var seq = new YamlSequence { Position = pos };
                i++;
                SkipSpaces(text, ref i);
                if (i < text.Length && text[i] == ']')
                {
                    i++;
                    return seq;
                }
                while (true)
                {
                    if (i >= text.Length)
                    {
                        throw new YamlFormatException(
                            "unterminated flow sequence (flow collections must close on the same line)", pos);
                    }
                    seq.Items.Add(ParseFlowNode(text, ref i, lineNumber, columnIndent, depth + 1));
                    SkipSpaces(text, ref i);
                    if (i >= text.Length)
                    {
                        throw new YamlFormatException(
                            "unterminated flow sequence (flow collections must close on the same line)", pos);
                    }
                    if (text[i] == ',')
                    {
                        i++;
                        SkipSpaces(text, ref i);
                        continue;
                    }
                    if (text[i] == ']')
                    {
                        i++;
                        return seq;
                    }
                    throw new YamlFormatException("expected ',' or ']' in flow sequence",
                        new YamlPosition(lineNumber, columnIndent + i + 1));
                }
            }
            case '{':
            {
                var map = new YamlMapping { Position = pos };
                i++;
                SkipSpaces(text, ref i);
                if (i < text.Length && text[i] == '}')
                {
                    i++;
                    return map;
                }
                while (true)
                {
                    if (i >= text.Length)
                    {
                        throw new YamlFormatException(
                            "unterminated flow mapping (flow collections must close on the same line)", pos);
                    }
                    var keyPos = new YamlPosition(lineNumber, columnIndent + i + 1);
                    string key;
                    if (text[i] is '"' or '\'')
                    {
                        key = ReadQuotedScalar(text, ref i, lineNumber, columnIndent);
                    }
                    else
                    {
                        int start = i;
                        while (i < text.Length && text[i] != ':' && text[i] != ',' && text[i] != '}')
                        {
                            i++;
                        }
                        key = text[start..i].Trim();
                    }
                    SkipSpaces(text, ref i);
                    if (i >= text.Length || text[i] != ':')
                    {
                        throw new YamlFormatException("expected ':' after key in flow mapping", keyPos);
                    }
                    i++;
                    SkipSpaces(text, ref i);
                    if (i >= text.Length)
                    {
                        throw new YamlFormatException(
                            "unterminated flow mapping (flow collections must close on the same line)", pos);
                    }
                    var value = ParseFlowNode(text, ref i, lineNumber, columnIndent, depth + 1);
                    map.Entries.Add(new YamlMapEntry(key, keyPos, value));
                    SkipSpaces(text, ref i);
                    if (i >= text.Length)
                    {
                        throw new YamlFormatException(
                            "unterminated flow mapping (flow collections must close on the same line)", pos);
                    }
                    if (text[i] == ',')
                    {
                        i++;
                        SkipSpaces(text, ref i);
                        continue;
                    }
                    if (text[i] == '}')
                    {
                        i++;
                        return map;
                    }
                    throw new YamlFormatException("expected ',' or '}' in flow mapping",
                        new YamlPosition(lineNumber, columnIndent + i + 1));
                }
            }
            case '"' or '\'':
            {
                string value = ReadQuotedScalar(text, ref i, lineNumber, columnIndent);
                return new YamlScalar { Value = value, WasQuoted = true, Position = pos };
            }
            case '&':
                throw new YamlFormatException("YAML anchors ('&') are not supported", pos);
            case '*':
                throw new YamlFormatException(
                    "YAML aliases ('*') are not supported; quote the value if a literal '*' wildcard is intended", pos);
            case '!':
                throw new YamlFormatException("YAML tags ('!') are not supported", pos);
            default:
            {
                int start = i;
                while (i < text.Length && text[i] is not (',' or ']' or '}'))
                {
                    if (text[i] == '#' && i > start && text[i - 1] == ' ')
                    {
                        throw new YamlFormatException("comments are not allowed inside flow collections",
                            new YamlPosition(lineNumber, columnIndent + i + 1));
                    }
                    i++;
                }
                string plain = text[start..i].Trim();
                if (plain.Length == 0)
                {
                    throw new YamlFormatException("empty value in flow collection", pos);
                }
                return new YamlScalar { Value = InterpretPlain(plain), Position = pos };
            }
        }
    }

    /// <summary>Reads a literal (|) or folded (&gt;) block scalar. Content is taken from the
    /// raw line array because blank lines and '#' inside a block scalar are content, not
    /// structure. Only the chomping indicators '-' and '+' are supported.</summary>
    private YamlNode ParseBlockScalar(Line headerLine, int keyIndent, string header, int headerCol)
    {
        bool folded = header[0] == '>';
        char chomp = ' ';
        int h = 1;
        if (h < header.Length && (header[h] == '-' || header[h] == '+'))
        {
            chomp = header[h];
            h++;
        }
        // Anything else on the header line other than a comment (notably an explicit
        // indentation digit) is outside the subset — refuse rather than misread.
        string tail = header[h..].TrimStart();
        if (tail.Length > 0 && tail[0] != '#')
        {
            throw new YamlFormatException(
                $"unsupported block scalar header '{header}' (only '|', '>', and '-'/'+' chomping are supported)",
                new YamlPosition(headerLine.Number, headerLine.Indent + headerCol + 1));
        }

        var pos = new YamlPosition(headerLine.Number, headerLine.Indent + headerCol + 1);
        int blockIndent = -1;
        var collected = new List<string>();
        int raw = headerLine.RawIndex + 1;
        int lastConsumed = headerLine.RawIndex;
        for (; raw < _raw.Length; raw++)
        {
            string rawLine = _raw[raw];
            int indent = 0;
            while (indent < rawLine.Length && rawLine[indent] == ' ')
            {
                indent++;
            }
            if (indent == rawLine.Length)
            {
                collected.Add(""); // blank line inside (or trailing) the block
                lastConsumed = raw;
                continue;
            }
            if (blockIndent < 0)
            {
                if (indent <= keyIndent)
                {
                    break; // block is empty; this line belongs to the enclosing structure
                }
                blockIndent = indent;
            }
            if (indent < blockIndent)
            {
                break;
            }
            collected.Add(rawLine[blockIndent..]);
            lastConsumed = raw;
        }

        // Advance the content-line cursor past everything the block consumed.
        _index++; // past the header line
        while (!AtEnd && Current.RawIndex <= lastConsumed)
        {
            _index++;
        }

        // Trailing blank lines participate only with '+' chomping.
        int coreCount = collected.Count;
        while (coreCount > 0 && collected[coreCount - 1].Length == 0)
        {
            coreCount--;
        }
        string body;
        if (folded)
        {
            // Folded: adjacent non-empty lines join with a space, blank lines become '\n'.
            // (The "more-indented lines stay literal" refinement is outside the subset.)
            var sb = new StringBuilder();
            bool previousWasContent = false;
            for (int k = 0; k < coreCount; k++)
            {
                if (collected[k].Length == 0)
                {
                    sb.Append('\n');
                    previousWasContent = false;
                }
                else
                {
                    if (previousWasContent)
                    {
                        sb.Append(' ');
                    }
                    sb.Append(collected[k]);
                    previousWasContent = true;
                }
            }
            body = sb.ToString();
        }
        else
        {
            body = string.Join("\n", collected.Take(coreCount));
        }
        string value = chomp switch
        {
            '-' => body,
            '+' => string.Join("\n", collected) + (collected.Count > 0 ? "\n" : ""),
            _ => body.Length > 0 ? body + "\n" : "",
        };
        return new YamlScalar { Value = value, WasQuoted = true, Position = pos };
    }

    private static void SkipSpaces(string text, ref int i)
    {
        while (i < text.Length && text[i] == ' ')
        {
            i++;
        }
    }

    /// <summary>Removes a trailing comment from a plain scalar. '#' opens a comment only
    /// at the start of the value or after a space — "a#b" is content.</summary>
    private static string StripComment(string text)
    {
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '#' && (i == 0 || text[i - 1] == ' '))
            {
                return text[..i];
            }
        }
        return text;
    }

    /// <summary>Reads a quoted scalar starting at text[i] (the opening quote); i ends just
    /// past the closing quote. Single quotes escape only '' and keep backslashes literal —
    /// which is why Sigma rules single-quote Windows paths. Double quotes process escapes.</summary>
    private static string ReadQuotedScalar(string text, ref int i, int lineNumber, int columnIndent)
    {
        char quote = text[i];
        var openPos = new YamlPosition(lineNumber, columnIndent + i + 1);
        i++;
        var sb = new StringBuilder();
        while (true)
        {
            if (i >= text.Length)
            {
                throw new YamlFormatException(
                    $"unterminated {(quote == '"' ? "double" : "single")}-quoted string", openPos);
            }
            char c = text[i];
            if (c == quote)
            {
                if (quote == '\'' && i + 1 < text.Length && text[i + 1] == '\'')
                {
                    sb.Append('\'');
                    i += 2;
                    continue;
                }
                i++;
                return sb.ToString();
            }
            if (quote == '"' && c == '\\')
            {
                if (i + 1 >= text.Length)
                {
                    throw new YamlFormatException("unterminated escape sequence",
                        new YamlPosition(lineNumber, columnIndent + i + 1));
                }
                char e = text[i + 1];
                switch (e)
                {
                    case '0': sb.Append('\0'); break;
                    case 't': sb.Append('\t'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'x':
                    case 'u':
                    {
                        int digits = e == 'x' ? 2 : 4;
                        if (i + 2 + digits > text.Length
                            || !int.TryParse(text.AsSpan(i + 2, digits), NumberStyles.HexNumber,
                                CultureInfo.InvariantCulture, out int code))
                        {
                            throw new YamlFormatException($"invalid \\{e} escape sequence",
                                new YamlPosition(lineNumber, columnIndent + i + 1));
                        }
                        sb.Append((char)code);
                        i += digits;
                        break;
                    }
                    default:
                        throw new YamlFormatException($"unsupported escape sequence '\\{e}'",
                            new YamlPosition(lineNumber, columnIndent + i + 1));
                }
                i += 2;
                continue;
            }
            sb.Append(c);
            i++;
        }
    }

    /// <summary>Types a plain scalar: null/boolean/integer/float, else string. Quoted
    /// scalars never come through here — they are always strings.</summary>
    internal static object? InterpretPlain(string s)
    {
        switch (s)
        {
            case "" or "~" or "null" or "Null" or "NULL":
                return null;
            case "true" or "True" or "TRUE":
                return true;
            case "false" or "False" or "FALSE":
                return false;
        }
        char first = s[0];
        if (first is (>= '0' and <= '9') or '-' or '+' or '.')
        {
            if ((s.StartsWith("0x", StringComparison.Ordinal) || s.StartsWith("0X", StringComparison.Ordinal))
                && long.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long hex))
            {
                return hex;
            }
            if (long.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long integer))
            {
                return integer;
            }
            // Restrict float parsing to plain numeric shapes so "1.2.3.4", dates and
            // "Infinity" stay strings.
            bool numericShape = true;
            foreach (char c in s)
            {
                if (c is not ((>= '0' and <= '9') or '-' or '+' or '.' or 'e' or 'E'))
                {
                    numericShape = false;
                    break;
                }
            }
            if (numericShape && double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out double d))
            {
                return d;
            }
        }
        return s;
    }
}
