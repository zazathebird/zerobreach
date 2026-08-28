using System.Text;
using Scythe.Rules.Yara.Parsing;

namespace Scythe.Rules.Yara.Matching;

/// <summary>
/// Parser for YARA's regex dialect: literals, classes, `.`; `* + ? {n} {n,} {n,m}` with
/// lazy variants; alternation; groups (plain and `(?:`); escapes `\d \D \w \W \s \S`,
/// control escapes and `\xNN`; assertions `^ $ \b \B`. Backreferences and lookaround do
/// not exist in the dialect and are rejected — which is also what makes the whole engine
/// implementable without backtracking.
///
/// Pathology is rejected here rather than discovered at scan time (BLUEPRINT §3): counted
/// repetitions above <see cref="MaxCountedRepeat"/> and unbounded quantifiers nested inside
/// unbounded quantifiers both fail compilation.
/// </summary>
internal static class RegexParser
{
    /// <summary>Reference YARA's RE_MAX_RANGE is 4096; counted repeats expand into NFA
    /// states, so this also bounds compiled size.</summary>
    public const int MaxCountedRepeat = 4096;

    public static RegexNode? Parse(
        string pattern,
        bool caseInsensitive,
        bool dotMatchesAll,
        string owner,
        string fileName,
        SourceLocation location,
        List<Diagnostic> diagnostics)
    {
        var p = new Parser(pattern, caseInsensitive, dotMatchesAll, owner, fileName, location, diagnostics);
        var node = p.ParseAlternation(0);
        if (node is null)
        {
            return null;
        }
        if (!p.AtEnd)
        {
            p.Error($"unexpected '{p.CurrentChar}'");
            return null;
        }
        if (HasNestedUnboundedQuantifier(node, insideUnbounded: false))
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.CatastrophicPattern,
                $"regex of {owner} at {location} nests an unbounded quantifier inside another unbounded quantifier; " +
                "this shape is pathological on hostile input and is rejected",
                fileName, location));
            return null;
        }
        return node;
    }

    /// <summary>(a+)+ and friends. The Pike VM is immune to catastrophic backtracking, but
    /// the shape is still rejected: it is always a rule-authoring mistake, and rejecting it
    /// keeps the guarantee independent of engine internals.</summary>
    private static bool HasNestedUnboundedQuantifier(RegexNode node, bool insideUnbounded) => node switch
    {
        RegexRepeat r => (r.Max is null && insideUnbounded) ||
                         HasNestedUnboundedQuantifier(r.Body, insideUnbounded || r.Max is null),
        RegexConcat c => c.Nodes.Any(n => HasNestedUnboundedQuantifier(n, insideUnbounded)),
        RegexAlternation a => a.Branches.Any(n => HasNestedUnboundedQuantifier(n, insideUnbounded)),
        _ => false,
    };

    private sealed class Parser(
        string pattern,
        bool caseInsensitive,
        bool dotMatchesAll,
        string owner,
        string fileName,
        SourceLocation location,
        List<Diagnostic> diagnostics)
    {
        private int _pos;

        public bool AtEnd => _pos >= pattern.Length;
        public char CurrentChar => _pos < pattern.Length ? pattern[_pos] : '\0';

        public void Error(string message)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.InvalidRegex,
                $"invalid regex of {owner} at {location}, position {_pos + 1}: {message}",
                fileName, location));
        }

        public RegexNode? ParseAlternation(int depth)
        {
            if (depth > 64)
            {
                Error("groups nested too deeply");
                return null;
            }
            var branches = new List<RegexNode>();
            var first = ParseConcat(depth);
            if (first is null)
            {
                return null;
            }
            branches.Add(first);
            while (CurrentChar == '|')
            {
                _pos++;
                var next = ParseConcat(depth);
                if (next is null)
                {
                    return null;
                }
                branches.Add(next);
            }
            return branches.Count == 1 ? branches[0] : new RegexAlternation(branches);
        }

        private RegexNode? ParseConcat(int depth)
        {
            var nodes = new List<RegexNode>();
            while (!AtEnd && CurrentChar != '|' && CurrentChar != ')')
            {
                var atom = ParseAtom(depth);
                if (atom is null)
                {
                    return null;
                }
                var repeated = ParseQuantifier(atom);
                if (repeated is null)
                {
                    return null;
                }
                nodes.Add(repeated);
            }
            return nodes.Count == 1 ? nodes[0] : new RegexConcat(nodes);
        }

        private RegexNode? ParseQuantifier(RegexNode atom)
        {
            int min;
            int? max;
            switch (CurrentChar)
            {
                case '*': min = 0; max = null; _pos++; break;
                case '+': min = 1; max = null; _pos++; break;
                case '?': min = 0; max = 1; _pos++; break;
                case '{':
                {
                    // `{` without a valid bound spec is a literal brace in the reference
                    // dialect; look ahead before committing.
                    int save = _pos;
                    _pos++;
                    if (!TryParseBounds(out min, out max))
                    {
                        _pos = save;
                        return atom;
                    }
                    break;
                }
                default:
                    return atom;
            }
            if (atom is RegexAssertion)
            {
                Error("a quantifier cannot follow an assertion");
                return null;
            }
            bool lazy = false;
            if (CurrentChar == '?')
            {
                lazy = true;
                _pos++;
            }
            if (max is int m && m < min)
            {
                Error($"repetition {{{min},{m}}} has min greater than max");
                return null;
            }
            if (min > MaxCountedRepeat || max > MaxCountedRepeat)
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.PatternTooComplex,
                    $"regex of {owner} at {location}: repetition bound exceeds the maximum of {MaxCountedRepeat}",
                    fileName, location));
                return null;
            }
            return new RegexRepeat(atom, min, max, lazy);
        }

        private bool TryParseBounds(out int min, out int? max)
        {
            min = 0;
            max = null;
            if (!char.IsAsciiDigit(CurrentChar))
            {
                return false;
            }
            min = ReadInt();
            if (CurrentChar == '}')
            {
                _pos++;
                max = min;
                return true;
            }
            if (CurrentChar != ',')
            {
                return false;
            }
            _pos++;
            if (CurrentChar == '}')
            {
                _pos++;
                max = null;
                return true;
            }
            if (!char.IsAsciiDigit(CurrentChar))
            {
                return false;
            }
            max = ReadInt();
            if (CurrentChar != '}')
            {
                return false;
            }
            _pos++;
            return true;
        }

        private int ReadInt()
        {
            long v = 0;
            while (char.IsAsciiDigit(CurrentChar))
            {
                v = Math.Min(v * 10 + (CurrentChar - '0'), int.MaxValue);
                _pos++;
            }
            return (int)v;
        }

        private RegexNode? ParseAtom(int depth)
        {
            char c = CurrentChar;
            switch (c)
            {
                case '(':
                {
                    _pos++;
                    if (CurrentChar == '?')
                    {
                        _pos++;
                        if (CurrentChar == ':')
                        {
                            _pos++;
                        }
                        else
                        {
                            Error($"unsupported group '(?{CurrentChar}'; only plain and (?: groups exist in this dialect");
                            return null;
                        }
                    }
                    var inner = ParseAlternation(depth + 1);
                    if (inner is null)
                    {
                        return null;
                    }
                    if (CurrentChar != ')')
                    {
                        Error("unterminated group");
                        return null;
                    }
                    _pos++;
                    return inner;
                }
                case '[':
                    return ParseClass();
                case '.':
                    _pos++;
                    return new RegexClass(dotMatchesAll ? ByteSet.All() : ByteSet.AllExceptNewline());
                case '^':
                    _pos++;
                    return new RegexAssertion(RegexAssertionKind.BufferStart);
                case '$':
                    _pos++;
                    return new RegexAssertion(RegexAssertionKind.BufferEnd);
                case '\\':
                    return ParseEscape(inClass: false);
                case '*':
                case '+':
                case '?':
                    Error($"'{c}' has nothing to repeat");
                    return null;
                default:
                    _pos++;
                    return LiteralNode(c);
            }
        }

        /// <summary>A source character above 0x7F stands for its UTF-8 bytes, matching how
        /// the reference consumes rule files as raw bytes.</summary>
        private RegexNode LiteralNode(char c)
        {
            if (c <= 0x7F)
            {
                return MakeLiteral((byte)c);
            }
            var bytes = Encoding.UTF8.GetBytes(c.ToString());
            return new RegexConcat(bytes.Select(MakeLiteral).ToList());
        }

        private RegexNode MakeLiteral(byte b)
        {
            if (caseInsensitive && (char.IsAsciiLetterLower((char)b) || char.IsAsciiLetterUpper((char)b)))
            {
                var set = new ByteSet();
                set.Add(b);
                set.AddAsciiCaseVariants();
                return new RegexClass(set);
            }
            return new RegexLiteral(b);
        }

        private RegexNode? ParseClass()
        {
            _pos++; // '['
            bool negated = false;
            if (CurrentChar == '^')
            {
                negated = true;
                _pos++;
            }
            var set = new ByteSet();
            bool first = true;
            while (true)
            {
                if (AtEnd)
                {
                    Error("unterminated character class");
                    return null;
                }
                char c = CurrentChar;
                if (c == ']' && !first)
                {
                    _pos++;
                    break;
                }
                first = false;

                int? lo = null;
                if (c == '\\')
                {
                    var esc = ParseEscape(inClass: true);
                    switch (esc)
                    {
                        case null:
                            return null;
                        case RegexClass rc:
                            set.AddSet(rc.Set);
                            continue;
                        case RegexLiteral rl:
                            lo = rl.Value;
                            break;
                        default:
                            Error("invalid escape in character class");
                            return null;
                    }
                }
                else
                {
                    if (c > 0xFF)
                    {
                        Error("non-Latin characters are not supported inside a class; use \\xNN byte values");
                        return null;
                    }
                    lo = (byte)c;
                    _pos++;
                }

                if (CurrentChar == '-' && _pos + 1 < pattern.Length && pattern[_pos + 1] != ']')
                {
                    _pos++; // '-'
                    int? hi;
                    if (CurrentChar == '\\')
                    {
                        var esc = ParseEscape(inClass: true);
                        if (esc is RegexLiteral rl)
                        {
                            hi = rl.Value;
                        }
                        else
                        {
                            Error("a class shorthand cannot be a range endpoint");
                            return null;
                        }
                    }
                    else
                    {
                        char hc = CurrentChar;
                        if (hc > 0xFF)
                        {
                            Error("non-Latin characters are not supported inside a class");
                            return null;
                        }
                        hi = (byte)hc;
                        _pos++;
                    }
                    if (hi < lo)
                    {
                        Error($"class range out of order");
                        return null;
                    }
                    set.AddRange((byte)lo.Value, (byte)hi.Value);
                }
                else
                {
                    set.Add((byte)lo.Value);
                }
            }

            if (caseInsensitive)
            {
                set.AddAsciiCaseVariants();
            }
            if (negated)
            {
                set.Invert();
            }
            if (set.IsEmpty)
            {
                Error("character class matches nothing");
                return null;
            }
            return new RegexClass(set);
        }

        private RegexNode? ParseEscape(bool inClass)
        {
            _pos++; // '\'
            char c = CurrentChar;
            _pos++;
            switch (c)
            {
                case 'd': return new RegexClass(ByteSet.Digit());
                case 'D': return Negate(ByteSet.Digit());
                case 'w': return new RegexClass(ByteSet.Word());
                case 'W': return Negate(ByteSet.Word());
                case 's': return new RegexClass(ByteSet.Space());
                case 'S': return Negate(ByteSet.Space());
                case 'b' when !inClass: return new RegexAssertion(RegexAssertionKind.WordBoundary);
                case 'B' when !inClass: return new RegexAssertion(RegexAssertionKind.NotWordBoundary);
                case 'n': return MakeLiteral((byte)'\n');
                case 'r': return MakeLiteral((byte)'\r');
                case 't': return MakeLiteral((byte)'\t');
                case 'f': return MakeLiteral((byte)'\f');
                case 'v': return MakeLiteral((byte)'\v');
                case 'a': return MakeLiteral(0x07);
                case '0': return MakeLiteral(0x00);
                case 'x':
                {
                    if (_pos + 1 < pattern.Length + 1 &&
                        _pos < pattern.Length && char.IsAsciiHexDigit(pattern[_pos]) &&
                        _pos + 1 < pattern.Length && char.IsAsciiHexDigit(pattern[_pos + 1]))
                    {
                        int v = Convert.ToInt32(pattern.Substring(_pos, 2), 16);
                        _pos += 2;
                        // \xNN inside a class stays a literal even under nocase: the author
                        // named an exact byte value.
                        return new RegexLiteral((byte)v);
                    }
                    Error("\\x must be followed by two hexadecimal digits");
                    return null;
                }
                case '\0':
                    Error("dangling backslash at end of pattern");
                    return null;
                default:
                    if (char.IsAsciiLetterOrDigit(c))
                    {
                        // Unknown alphanumeric escapes are reserved (\1 backreferences do
                        // not exist here); reject them loudly rather than guessing.
                        Error($"unsupported escape '\\{c}'");
                        return null;
                    }
                    return LiteralNode(c);
            }

            static RegexClass Negate(ByteSet s)
            {
                s.Invert();
                return new RegexClass(s);
            }
        }
    }
}
