using System.Text;

namespace Scythe.Rules.Yara.Parsing;

/// <summary>
/// Recursive-descent parser for YARA source files. Produces an AST plus a full diagnostic
/// list: parsing continues past errors (panic-mode recovery to the next rule) so a technician
/// fixing a downloaded rule set sees every problem in one pass, not one problem per run.
/// </summary>
public sealed class YaraParser
{
    /// <summary>Expression nesting cap: recovery for hostile input like ten thousand open
    /// parentheses, which must produce a diagnostic and not a stack overflow.</summary>
    public const int MaxExpressionDepth = 200;

    /// <summary>Past this many *error* diagnostics the file is junk (or hostile) and
    /// continuing only burns time; parsing stops with a final marker diagnostic.
    /// Warnings do not count — a large corpus can legitimately warn thousands of times.</summary>
    public const int MaxDiagnostics = 500;

    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition", "contains",
        "defined", "endswith", "entrypoint", "false", "filesize", "for", "fullword", "global",
        "icontains", "iendswith", "iequals", "import", "in", "include", "int16", "int16be",
        "int32", "int32be", "int8", "int8be", "istartswith", "matches", "meta", "nocase",
        "none", "not", "of", "or", "private", "rule", "startswith", "strings", "them", "true",
        "uint16", "uint16be", "uint32", "uint32be", "uint8", "uint8be", "wide", "xor",
    };

    private static readonly Dictionary<string, IntReadKind> IntReadKinds = new(StringComparer.Ordinal)
    {
        ["uint8"] = IntReadKind.UInt8, ["uint16"] = IntReadKind.UInt16, ["uint32"] = IntReadKind.UInt32,
        ["int8"] = IntReadKind.Int8, ["int16"] = IntReadKind.Int16, ["int32"] = IntReadKind.Int32,
        ["uint8be"] = IntReadKind.UInt8Be, ["uint16be"] = IntReadKind.UInt16Be, ["uint32be"] = IntReadKind.UInt32Be,
        ["int8be"] = IntReadKind.Int8Be, ["int16be"] = IntReadKind.Int16Be, ["int32be"] = IntReadKind.Int32Be,
    };

    private readonly string _fileName;
    private readonly List<Diagnostic> _diagnostics;
    private readonly YaraLexer _lexer;
    private YaraToken _current;
    private YaraToken? _peeked;
    private int _depth;

    private sealed class ParseAbort : Exception;
    private sealed class TooManyErrors : Exception;

    private YaraParser(string source, string fileName, List<Diagnostic> diagnostics)
    {
        _fileName = fileName;
        _diagnostics = diagnostics;
        _lexer = new YaraLexer(source, fileName, diagnostics);
        _current = _lexer.Next();
    }

    /// <summary>Parses one source file. Diagnostics (errors and warnings) are appended to
    /// <paramref name="diagnostics"/>; the returned AST contains every rule that parsed,
    /// which callers must not use if any error-severity diagnostic was produced.</summary>
    public static YaraFileAst ParseFile(string source, string fileName, List<Diagnostic> diagnostics)
    {
        var parser = new YaraParser(source, fileName, diagnostics);
        try
        {
            return parser.ParseFileBody();
        }
        catch (TooManyErrors)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.TooManyDiagnostics,
                $"more than {MaxDiagnostics} problems; giving up on this file", fileName, parser._current.Location));
            return new YaraFileAst(fileName, [], [], []);
        }
    }

    // ------------------------------------------------------------------ token plumbing

    private int _errorScanIndex;
    private int _errorCount;

    private void Advance()
    {
        // Incremental error tally so the cap check stays O(1) amortised even when a big
        // corpus produces thousands of warnings.
        while (_errorScanIndex < _diagnostics.Count)
        {
            if (_diagnostics[_errorScanIndex++].Severity == DiagnosticSeverity.Error)
            {
                _errorCount++;
            }
        }
        if (_errorCount > MaxDiagnostics)
        {
            throw new TooManyErrors();
        }
        if (_peeked is not null)
        {
            _current = _peeked;
            _peeked = null;
        }
        else
        {
            _current = _lexer.Next();
        }
    }

    /// <summary>One extra token of lookahead. Never call where a hex string could start:
    /// it would tokenise the hex body as ordinary tokens.</summary>
    private YaraToken Peek()
    {
        _peeked ??= _lexer.Next();
        return _peeked;
    }

    private void Error(DiagnosticCode code, string message, SourceLocation? loc = null) =>
        _diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, code, message, _fileName, loc ?? _current.Location));

    private void Warn(DiagnosticCode code, string message, SourceLocation loc) =>
        _diagnostics.Add(new Diagnostic(DiagnosticSeverity.Warning, code, message, _fileName, loc));

    private string Describe(YaraToken t) => t.Kind switch
    {
        TokenKind.EndOfFile => "end of file",
        TokenKind.StringLiteral => "string literal",
        TokenKind.RegexLiteral => "regular expression",
        TokenKind.StringId => $"${t.Text}",
        TokenKind.StringIdWildcard => $"${t.Text}*",
        TokenKind.StringCountId => $"#{t.Text}",
        TokenKind.StringOffsetId => $"@{t.Text}",
        TokenKind.StringLengthId => $"!{t.Text}",
        _ => $"'{t.Text}'",
    };

    private void Expect(TokenKind kind, string what)
    {
        if (_current.Kind != kind)
        {
            Error(DiagnosticCode.SyntaxError, $"expected {what} but found {Describe(_current)} at {_current.Location}");
            throw new ParseAbort();
        }
        Advance();
    }

    private string ExpectIdentifier(string what)
    {
        if (_current.Kind != TokenKind.Identifier || Keywords.Contains(_current.Text))
        {
            Error(DiagnosticCode.SyntaxError, $"expected {what} but found {Describe(_current)} at {_current.Location}");
            throw new ParseAbort();
        }
        string name = _current.Text;
        Advance();
        return name;
    }

    private bool TryWord(string word)
    {
        if (_current.IsWord(word))
        {
            Advance();
            return true;
        }
        return false;
    }

    private void ExpectWord(string word)
    {
        if (!TryWord(word))
        {
            Error(DiagnosticCode.SyntaxError, $"expected '{word}' but found {Describe(_current)} at {_current.Location}");
            throw new ParseAbort();
        }
    }

    // ------------------------------------------------------------------ file structure

    private YaraFileAst ParseFileBody()
    {
        var includes = new List<IncludeDirective>();
        var imports = new List<ImportDirective>();
        var rules = new List<YaraRuleAst>();

        while (_current.Kind != TokenKind.EndOfFile)
        {
            try
            {
                if (_current.IsWord("include"))
                {
                    var loc = _current.Location;
                    Advance();
                    if (_current.Kind != TokenKind.StringLiteral)
                    {
                        Error(DiagnosticCode.SyntaxError, $"expected a quoted path after 'include' at {_current.Location}");
                        throw new ParseAbort();
                    }
                    includes.Add(new IncludeDirective(Encoding.UTF8.GetString(_current.Bytes!), loc));
                    Advance();
                }
                else if (_current.IsWord("import"))
                {
                    var loc = _current.Location;
                    Advance();
                    if (_current.Kind != TokenKind.StringLiteral)
                    {
                        Error(DiagnosticCode.SyntaxError, $"expected a quoted module name after 'import' at {_current.Location}");
                        throw new ParseAbort();
                    }
                    imports.Add(new ImportDirective(Encoding.UTF8.GetString(_current.Bytes!), loc));
                    Advance();
                }
                else if (_current.IsWord("rule") || _current.IsWord("private") || _current.IsWord("global"))
                {
                    rules.Add(ParseRule());
                }
                else
                {
                    Error(DiagnosticCode.SyntaxError,
                        $"expected 'rule', 'import' or 'include' but found {Describe(_current)} at {_current.Location}");
                    throw new ParseAbort();
                }
            }
            catch (ParseAbort)
            {
                RecoverToNextRule();
            }
        }
        return new YaraFileAst(_fileName, includes, imports, rules);
    }

    /// <summary>Panic-mode recovery: skip until something that can start a top-level
    /// construct, tracking brace depth so a 'rule' inside a condition does not fool us.</summary>
    private void RecoverToNextRule()
    {
        int braces = 0;
        while (_current.Kind != TokenKind.EndOfFile)
        {
            if (_current.Kind == TokenKind.LBrace)
            {
                braces++;
            }
            else if (_current.Kind == TokenKind.RBrace)
            {
                if (braces > 0)
                {
                    braces--;
                }
                // A closing brace at depth zero ends the broken rule; resume after it.
                else
                {
                    Advance();
                    return;
                }
            }
            else if (braces == 0 &&
                     (_current.IsWord("rule") || _current.IsWord("private") || _current.IsWord("global") ||
                      _current.IsWord("import") || _current.IsWord("include")))
            {
                return;
            }
            Advance();
        }
    }

    private YaraRuleAst ParseRule()
    {
        bool isPrivate = false, isGlobal = false;
        var startLoc = _current.Location;
        while (true)
        {
            if (TryWord("private"))
            {
                isPrivate = true;
            }
            else if (TryWord("global"))
            {
                isGlobal = true;
            }
            else
            {
                break;
            }
        }
        ExpectWord("rule");
        var name = ExpectIdentifier("a rule name");

        var tags = new List<string>();
        if (_current.Kind == TokenKind.Colon)
        {
            Advance();
            do
            {
                var tagLoc = _current.Location;
                var tag = ExpectIdentifier("a tag name");
                if (tags.Contains(tag))
                {
                    Error(DiagnosticCode.DuplicateTag, $"duplicated tag '{tag}' at {tagLoc}", tagLoc);
                }
                else
                {
                    tags.Add(tag);
                }
            } while (_current.Kind == TokenKind.Identifier && !Keywords.Contains(_current.Text));
            if (tags.Count == 0)
            {
                Error(DiagnosticCode.SyntaxError, $"expected at least one tag after ':' at {_current.Location}");
                throw new ParseAbort();
            }
        }

        Expect(TokenKind.LBrace, "'{'");

        var meta = new List<MetaEntry>();
        var strings = new List<YaraStringDecl>();
        bool sawMeta = false;

        if (_current.IsWord("meta"))
        {
            sawMeta = true;
            Advance();
            Expect(TokenKind.Colon, "':' after 'meta'");
            do
            {
                meta.Add(ParseMetaEntry());
            } while (_current.Kind == TokenKind.Identifier && !Keywords.Contains(_current.Text));
            if (meta.Count == 0)
            {
                Error(DiagnosticCode.SyntaxError, $"'meta' section is empty at {_current.Location}");
                throw new ParseAbort();
            }
        }

        if (_current.IsWord("strings"))
        {
            var stringsLoc = _current.Location;
            Advance();
            Expect(TokenKind.Colon, "':' after 'strings'");
            while (_current.Kind is TokenKind.StringId or TokenKind.StringIdWildcard)
            {
                strings.Add(ParseStringDecl());
            }
            if (strings.Count == 0)
            {
                // A silently empty strings section would compile to a rule that can never
                // match, which is indistinguishable from a passing scan. Reject loudly.
                Error(DiagnosticCode.EmptyStringsSection, $"'strings' section at {stringsLoc} declares no strings", stringsLoc);
                throw new ParseAbort();
            }
        }

        ExpectWord("condition");
        Expect(TokenKind.Colon, "':' after 'condition'");
        _depth = 0;
        var condition = ParseExpression();
        Expect(TokenKind.RBrace, "'}' closing the rule");

        if (!sawMeta)
        {
            // Public corpora are inconsistent about meta; surfaced as a warning so a set
            // can adopt a house style without this library taking a side.
            Warn(DiagnosticCode.NoMetaSection, $"rule '{name}' has no meta section", startLoc);
        }
        return new YaraRuleAst(name, isPrivate, isGlobal, tags, meta, strings, condition, startLoc);
    }

    private MetaEntry ParseMetaEntry()
    {
        var loc = _current.Location;
        var key = ExpectIdentifier("a meta key");
        Expect(TokenKind.Assign, "'=' in meta entry");
        MetaValue value;
        switch (_current.Kind)
        {
            case TokenKind.StringLiteral:
                value = new StringMetaValue(Encoding.UTF8.GetString(_current.Bytes!));
                Advance();
                break;
            case TokenKind.IntegerLiteral:
                value = new IntegerMetaValue(_current.IntegerValue);
                Advance();
                break;
            case TokenKind.Minus:
                Advance();
                if (_current.Kind != TokenKind.IntegerLiteral)
                {
                    Error(DiagnosticCode.SyntaxError, $"expected a number after '-' at {_current.Location}");
                    throw new ParseAbort();
                }
                value = new IntegerMetaValue(-_current.IntegerValue);
                Advance();
                break;
            default:
                if (TryWord("true"))
                {
                    value = new BooleanMetaValue(true);
                }
                else if (TryWord("false"))
                {
                    value = new BooleanMetaValue(false);
                }
                else
                {
                    Error(DiagnosticCode.SyntaxError,
                        $"meta value must be a string, integer or boolean; found {Describe(_current)} at {_current.Location}");
                    throw new ParseAbort();
                }
                break;
        }
        return new MetaEntry(key, value, loc);
    }

    // ------------------------------------------------------------------ string section

    private YaraStringDecl ParseStringDecl()
    {
        var loc = _current.Location;
        if (_current.Kind == TokenKind.StringIdWildcard)
        {
            Error(DiagnosticCode.SyntaxError, $"'${_current.Text}*' at {loc}: wildcards are only valid in string sets, not declarations", loc);
            throw new ParseAbort();
        }
        string identifier = _current.Text; // may be "" — the anonymous string
        Advance();
        Expect(TokenKind.Assign, "'=' in string declaration");

        switch (_current.Kind)
        {
            case TokenKind.StringLiteral:
            {
                byte[] bytes = _current.Bytes!;
                Advance();
                var mods = ParseModifiers(StringKind.Text, loc);
                if (bytes.Length == 0)
                {
                    Error(DiagnosticCode.EmptyString, $"string ${identifier} at {loc} is empty", loc);
                }
                if (mods.Has(StringModifierKind.Base64 | StringModifierKind.Base64Wide) && bytes.Length < 3)
                {
                    // Fewer than 3 plaintext bytes leave no base64 character fully
                    // determined across all alignments; the reference rejects this too.
                    Error(DiagnosticCode.Base64StringTooShort,
                        $"string ${identifier} at {loc}: base64 strings must be at least 3 bytes long", loc);
                }
                return new TextStringDecl(identifier, mods, loc, bytes);
            }
            case TokenKind.RegexLiteral:
            {
                string pattern = _current.Text;
                bool i = _current.RegexI, s = _current.RegexS;
                Advance();
                var mods = ParseModifiers(StringKind.Regex, loc);
                // The `nocase` modifier and the /i flag are equivalent; fold them together.
                if (mods.Has(StringModifierKind.Nocase))
                {
                    i = true;
                }
                if (pattern.Length == 0)
                {
                    Error(DiagnosticCode.EmptyString, $"regex ${identifier} at {loc} is empty", loc);
                }
                return new RegexStringDecl(identifier, mods, loc, pattern, i, s);
            }
            case TokenKind.LBrace:
            {
                // The lexer is positioned just after '{'; hand the raw text to the hex parser.
                var seq = HexStringParser.Parse(_lexer, _fileName, _diagnostics);
                _peeked = null;
                _current = _lexer.Next();
                var mods = ParseModifiers(StringKind.Hex, loc);
                if (seq is null)
                {
                    throw new ParseAbort();
                }
                return new HexStringDecl(identifier, mods, loc, seq);
            }
            default:
                Error(DiagnosticCode.SyntaxError,
                    $"expected a quoted string, /regex/ or {{ hex }} after '=' at {_current.Location}");
                throw new ParseAbort();
        }
    }

    private enum StringKind { Text, Regex, Hex }

    private StringModifiers ParseModifiers(StringKind kind, SourceLocation stringLoc)
    {
        var kinds = StringModifierKind.None;
        byte xorMin = 0, xorMax = 255;
        string? base64Alphabet = null;

        while (_current.Kind == TokenKind.Identifier)
        {
            var word = _current.Text;
            var loc = _current.Location;
            StringModifierKind flag;
            switch (word)
            {
                case "nocase": flag = StringModifierKind.Nocase; break;
                case "wide": flag = StringModifierKind.Wide; break;
                case "ascii": flag = StringModifierKind.Ascii; break;
                case "fullword": flag = StringModifierKind.Fullword; break;
                case "private": flag = StringModifierKind.Private; break;
                case "xor": flag = StringModifierKind.Xor; break;
                case "base64": flag = StringModifierKind.Base64; break;
                case "base64wide": flag = StringModifierKind.Base64Wide; break;
                default:
                    return Finish();
            }
            Advance();

            if ((kinds & flag) != 0)
            {
                Error(DiagnosticCode.DuplicateModifier, $"duplicate modifier '{word}' at {loc}", loc);
            }
            kinds |= flag;

            bool allowed = kind switch
            {
                StringKind.Text => true,
                StringKind.Regex => flag is StringModifierKind.Nocase or StringModifierKind.Wide
                    or StringModifierKind.Ascii or StringModifierKind.Fullword or StringModifierKind.Private,
                _ => flag is StringModifierKind.Private,
            };
            if (!allowed)
            {
                Error(DiagnosticCode.InvalidModifierForStringKind,
                    $"modifier '{word}' at {loc} cannot be applied to a {kind switch { StringKind.Regex => "regex", StringKind.Hex => "hex", _ => "text" }} string", loc);
            }

            if (flag == StringModifierKind.Xor && _current.Kind == TokenKind.LParen)
            {
                Advance();
                (xorMin, xorMax) = ParseXorRange(loc);
            }
            else if (flag is StringModifierKind.Base64 or StringModifierKind.Base64Wide && _current.Kind == TokenKind.LParen)
            {
                Advance();
                if (_current.Kind != TokenKind.StringLiteral)
                {
                    Error(DiagnosticCode.InvalidBase64Alphabet, $"expected a quoted alphabet after '{word}(' at {_current.Location}");
                    throw new ParseAbort();
                }
                var alphabet = Encoding.UTF8.GetString(_current.Bytes!);
                if (alphabet.Length != 64)
                {
                    Error(DiagnosticCode.InvalidBase64Alphabet,
                        $"base64 alphabet at {_current.Location} has {alphabet.Length} characters; it must have exactly 64", _current.Location);
                }
                else if (alphabet.Distinct().Count() != 64)
                {
                    Error(DiagnosticCode.InvalidBase64Alphabet,
                        $"base64 alphabet at {_current.Location} contains repeated characters", _current.Location);
                }
                else
                {
                    base64Alphabet = alphabet;
                }
                Advance();
                Expect(TokenKind.RParen, "')' closing the alphabet");
            }
        }
        return Finish();

        StringModifiers Finish()
        {
            ValidateModifierCombination(kinds, stringLoc);
            if ((kinds & StringModifierKind.Xor) == 0)
            {
                xorMin = xorMax = 0;
            }
            return new StringModifiers(kinds, xorMin, xorMax, base64Alphabet);
        }
    }

    private (byte, byte) ParseXorRange(SourceLocation loc)
    {
        long lo = ReadXorBound();
        long hi = lo;
        if (_current.Kind == TokenKind.Minus)
        {
            Advance();
            hi = ReadXorBound();
        }
        Expect(TokenKind.RParen, "')' closing the xor range");
        if (lo < 0 || lo > 255 || hi < 0 || hi > 255 || lo > hi)
        {
            Error(DiagnosticCode.InvalidXorRange, $"xor range ({lo}-{hi}) at {loc} must satisfy 0 <= min <= max <= 255", loc);
            return (0, 255);
        }
        return ((byte)lo, (byte)hi);

        long ReadXorBound()
        {
            if (_current.Kind != TokenKind.IntegerLiteral)
            {
                Error(DiagnosticCode.InvalidXorRange, $"expected a number in xor range at {_current.Location}");
                throw new ParseAbort();
            }
            long v = _current.IntegerValue;
            Advance();
            return v;
        }
    }

    /// <summary>Rejects modifier combinations the reference rejects, because each pair here
    /// has contradictory semantics (e.g. xor of a case-folded string is not well defined).</summary>
    private void ValidateModifierCombination(StringModifierKind kinds, SourceLocation loc)
    {
        void Conflict(StringModifierKind a, StringModifierKind b, string an, string bn)
        {
            if ((kinds & a) != 0 && (kinds & b) != 0)
            {
                Error(DiagnosticCode.InvalidModifierCombination,
                    $"modifiers '{an}' and '{bn}' at {loc} cannot be used together", loc);
            }
        }
        Conflict(StringModifierKind.Nocase, StringModifierKind.Xor, "nocase", "xor");
        Conflict(StringModifierKind.Nocase, StringModifierKind.Base64, "nocase", "base64");
        Conflict(StringModifierKind.Nocase, StringModifierKind.Base64Wide, "nocase", "base64wide");
        Conflict(StringModifierKind.Xor, StringModifierKind.Base64, "xor", "base64");
        Conflict(StringModifierKind.Xor, StringModifierKind.Base64Wide, "xor", "base64wide");
        Conflict(StringModifierKind.Fullword, StringModifierKind.Base64, "fullword", "base64");
        Conflict(StringModifierKind.Fullword, StringModifierKind.Base64Wide, "fullword", "base64wide");
    }

    // ------------------------------------------------------------------ expressions
    //
    // Operator precedence, loosest binding first (matches the reference grammar):
    //   1. or
    //   2. and
    //   3. not, defined              (unary; binds looser than comparisons, so
    //                                 `not 1 == 2` is `not (1 == 2)`)
    //   4. == != < <= > >= contains icontains startswith istartswith endswith iendswith
    //      iequals matches
    //   5. |
    //   6. ^
    //   7. &
    //   8. << >>
    //   9. + -
    //  10. * \ %                     (YARA's division operator is backslash)
    //  11. unary - ~
    // `N of (...)` and `$a at/in ...` bind at primary level.

    private YaraExpression ParseExpression() => ParseOr();

    private void EnterDepth()
    {
        if (++_depth > MaxExpressionDepth)
        {
            Error(DiagnosticCode.NestingTooDeep,
                $"expression nested deeper than {MaxExpressionDepth} at {_current.Location}");
            throw new ParseAbort();
        }
    }

    private YaraExpression ParseOr()
    {
        EnterDepth();
        var left = ParseAnd();
        while (_current.IsWord("or"))
        {
            var loc = _current.Location;
            Advance();
            left = new BinaryExpr(loc, BinaryOp.Or, left, ParseAnd());
        }
        _depth--;
        return left;
    }

    private YaraExpression ParseAnd()
    {
        EnterDepth();
        var left = ParseNot();
        while (_current.IsWord("and"))
        {
            var loc = _current.Location;
            Advance();
            left = new BinaryExpr(loc, BinaryOp.And, left, ParseNot());
        }
        _depth--;
        return left;
    }

    private YaraExpression ParseNot()
    {
        EnterDepth();
        try
        {
            if (_current.IsWord("not"))
            {
                var loc = _current.Location;
                Advance();
                return new UnaryExpr(loc, UnaryOp.Not, ParseNot());
            }
            if (_current.IsWord("defined"))
            {
                var loc = _current.Location;
                Advance();
                return new UnaryExpr(loc, UnaryOp.Defined, ParseNot());
            }
            return ParseComparison();
        }
        finally
        {
            _depth--;
        }
    }

    private static readonly Dictionary<string, BinaryOp> WordComparisons = new(StringComparer.Ordinal)
    {
        ["contains"] = BinaryOp.Contains,
        ["icontains"] = BinaryOp.IContains,
        ["startswith"] = BinaryOp.StartsWith,
        ["istartswith"] = BinaryOp.IStartsWith,
        ["endswith"] = BinaryOp.EndsWith,
        ["iendswith"] = BinaryOp.IEndsWith,
        ["iequals"] = BinaryOp.IEquals,
        ["matches"] = BinaryOp.Matches,
    };

    private YaraExpression ParseComparison()
    {
        EnterDepth();
        var left = ParseBitOr();
        while (true)
        {
            BinaryOp op;
            var loc = _current.Location;
            switch (_current.Kind)
            {
                case TokenKind.Eq: op = BinaryOp.Eq; break;
                case TokenKind.Ne: op = BinaryOp.Ne; break;
                case TokenKind.Lt: op = BinaryOp.Lt; break;
                case TokenKind.Le: op = BinaryOp.Le; break;
                case TokenKind.Gt: op = BinaryOp.Gt; break;
                case TokenKind.Ge: op = BinaryOp.Ge; break;
                case TokenKind.Identifier when WordComparisons.TryGetValue(_current.Text, out var wop):
                    op = wop;
                    break;
                default:
                    _depth--;
                    return left;
            }
            Advance();
            var right = ParseBitOr();
            if (op == BinaryOp.Matches && right is not RegexLiteralExpr)
            {
                Error(DiagnosticCode.MisplacedRegexLiteral,
                    $"the right side of 'matches' at {loc} must be a /regex/ literal", loc);
            }
            left = new BinaryExpr(loc, op, left, right);
        }
    }

    private YaraExpression ParseBitOr()
    {
        EnterDepth();
        var left = ParseBitXor();
        while (_current.Kind == TokenKind.Pipe)
        {
            var loc = _current.Location;
            Advance();
            left = new BinaryExpr(loc, BinaryOp.BitOr, left, ParseBitXor());
        }
        _depth--;
        return left;
    }

    private YaraExpression ParseBitXor()
    {
        EnterDepth();
        var left = ParseBitAnd();
        while (_current.Kind == TokenKind.Caret)
        {
            var loc = _current.Location;
            Advance();
            left = new BinaryExpr(loc, BinaryOp.BitXor, left, ParseBitAnd());
        }
        _depth--;
        return left;
    }

    private YaraExpression ParseBitAnd()
    {
        EnterDepth();
        var left = ParseShift();
        while (_current.Kind == TokenKind.Amp)
        {
            var loc = _current.Location;
            Advance();
            left = new BinaryExpr(loc, BinaryOp.BitAnd, left, ParseShift());
        }
        _depth--;
        return left;
    }

    private YaraExpression ParseShift()
    {
        EnterDepth();
        var left = ParseAdditive();
        while (_current.Kind is TokenKind.Shl or TokenKind.Shr)
        {
            var op = _current.Kind == TokenKind.Shl ? BinaryOp.Shl : BinaryOp.Shr;
            var loc = _current.Location;
            Advance();
            left = new BinaryExpr(loc, op, left, ParseAdditive());
        }
        _depth--;
        return left;
    }

    private YaraExpression ParseAdditive()
    {
        EnterDepth();
        var left = ParseMultiplicative();
        while (_current.Kind is TokenKind.Plus or TokenKind.Minus)
        {
            var op = _current.Kind == TokenKind.Plus ? BinaryOp.Add : BinaryOp.Sub;
            var loc = _current.Location;
            Advance();
            left = new BinaryExpr(loc, op, left, ParseMultiplicative());
        }
        _depth--;
        return left;
    }

    private YaraExpression ParseMultiplicative()
    {
        EnterDepth();
        var left = ParseUnaryArith();
        while (true)
        {
            BinaryOp op;
            switch (_current.Kind)
            {
                case TokenKind.Star: op = BinaryOp.Mul; break;
                case TokenKind.Backslash: op = BinaryOp.Div; break;
                // `50% of them` — the percent belongs to a quantifier, not a modulo.
                case TokenKind.Percent when !Peek().IsWord("of"): op = BinaryOp.Mod; break;
                default:
                    _depth--;
                    return left;
            }
            var loc = _current.Location;
            Advance();
            left = new BinaryExpr(loc, op, left, ParseUnaryArith());
        }
    }

    private YaraExpression ParseUnaryArith()
    {
        EnterDepth();
        try
        {
            if (_current.Kind == TokenKind.Minus)
            {
                var loc = _current.Location;
                Advance();
                return new UnaryExpr(loc, UnaryOp.Negate, ParseUnaryArith());
            }
            if (_current.Kind == TokenKind.Tilde)
            {
                var loc = _current.Location;
                Advance();
                return new UnaryExpr(loc, UnaryOp.BitNot, ParseUnaryArith());
            }
            return ParsePostfix();
        }
        finally
        {
            _depth--;
        }
    }

    /// <summary>Parses a primary expression, then checks for the `of` / `% of` quantifier
    /// forms, which take a plain expression as their count.</summary>
    private YaraExpression ParsePostfix()
    {
        var primary = ParsePrimary();

        if (_current.IsWord("of"))
        {
            var loc = _current.Location;
            Advance();
            return ParseOfTail(new ExprQuantifier(primary.Location, primary), loc);
        }
        if (_current.Kind == TokenKind.Percent && Peek().IsWord("of"))
        {
            var qloc = _current.Location;
            Advance(); // %
            Advance(); // of
            return ParseOfTail(new PercentQuantifier(qloc, primary), qloc);
        }
        return primary;
    }

    private YaraExpression ParseOfTail(Quantifier quantifier, SourceLocation loc)
    {
        var set = ParseStringSet();
        RangeExpr? inRange = null;
        if (_current.IsWord("in"))
        {
            Advance();
            inRange = ParseRange();
        }
        return new OfExpr(loc, quantifier, set, inRange);
    }

    private StringSet ParseStringSet()
    {
        var loc = _current.Location;
        if (TryWord("them"))
        {
            return new ThemSet(loc);
        }
        Expect(TokenKind.LParen, "'(' opening a string set");
        var items = new List<StringSetItem>();
        while (true)
        {
            var itemLoc = _current.Location;
            switch (_current.Kind)
            {
                case TokenKind.StringId:
                    items.Add(new StringSetItem(_current.Text, IsWildcard: false, itemLoc));
                    Advance();
                    break;
                case TokenKind.StringIdWildcard:
                    items.Add(new StringSetItem(_current.Text, IsWildcard: true, itemLoc));
                    Advance();
                    break;
                default:
                    Error(DiagnosticCode.SyntaxError,
                        $"expected a string identifier in set but found {Describe(_current)} at {itemLoc}", itemLoc);
                    throw new ParseAbort();
            }
            if (_current.Kind == TokenKind.Comma)
            {
                Advance();
                continue;
            }
            Expect(TokenKind.RParen, "')' closing the string set");
            return new ListSet(loc, items);
        }
    }

    private RangeExpr ParseRange()
    {
        var loc = _current.Location;
        Expect(TokenKind.LParen, "'(' opening a range");
        var low = ParseBitOr();
        Expect(TokenKind.DotDot, "'..' in range");
        var high = ParseBitOr();
        Expect(TokenKind.RParen, "')' closing the range");
        return new RangeExpr(loc, low, high);
    }

    private YaraExpression ParsePrimary()
    {
        EnterDepth();
        try
        {
            var loc = _current.Location;
            switch (_current.Kind)
            {
                case TokenKind.IntegerLiteral:
                {
                    long v = _current.IntegerValue;
                    Advance();
                    return new IntegerLiteralExpr(loc, v);
                }
                case TokenKind.DoubleLiteral:
                {
                    double v = _current.DoubleValue;
                    Advance();
                    return new DoubleLiteralExpr(loc, v);
                }
                case TokenKind.StringLiteral:
                {
                    var bytes = _current.Bytes!;
                    Advance();
                    return new StringLiteralExpr(loc, bytes, Encoding.UTF8.GetString(bytes));
                }
                case TokenKind.RegexLiteral:
                {
                    var expr = new RegexLiteralExpr(loc, _current.Text, _current.RegexI, _current.RegexS);
                    Advance();
                    return expr;
                }
                case TokenKind.LParen:
                {
                    Advance();
                    var inner = ParseExpression();
                    Expect(TokenKind.RParen, "')'");
                    return inner;
                }
                case TokenKind.StringId:
                {
                    string name = _current.Text;
                    Advance();
                    if (_current.IsWord("at"))
                    {
                        Advance();
                        // `at` takes an arithmetic expression, not a boolean one.
                        return new StringAtExpr(loc, name, ParseBitOr());
                    }
                    if (_current.IsWord("in"))
                    {
                        Advance();
                        return new StringInExpr(loc, name, ParseRange());
                    }
                    return new StringMatchExpr(loc, name);
                }
                case TokenKind.StringCountId:
                {
                    string name = _current.Text;
                    Advance();
                    RangeExpr? range = null;
                    if (_current.IsWord("in"))
                    {
                        Advance();
                        range = ParseRange();
                    }
                    return new StringCountExpr(loc, name, range);
                }
                case TokenKind.StringOffsetId:
                case TokenKind.StringLengthId:
                {
                    bool isOffset = _current.Kind == TokenKind.StringOffsetId;
                    string name = _current.Text;
                    Advance();
                    YaraExpression? index = null;
                    if (_current.Kind == TokenKind.LBracket)
                    {
                        Advance();
                        index = ParseBitOr();
                        Expect(TokenKind.RBracket, "']'");
                    }
                    return isOffset
                        ? new StringOffsetExpr(loc, name, index)
                        : new StringLengthExpr(loc, name, index);
                }
                case TokenKind.Identifier:
                    return ParseIdentifierPrimary(loc);
                default:
                    Error(DiagnosticCode.SyntaxError,
                        $"expected an expression but found {Describe(_current)} at {loc}", loc);
                    throw new ParseAbort();
            }
        }
        finally
        {
            _depth--;
        }
    }

    private YaraExpression ParseIdentifierPrimary(SourceLocation loc)
    {
        string word = _current.Text;
        switch (word)
        {
            case "true":
                Advance();
                return new BoolLiteralExpr(loc, true);
            case "false":
                Advance();
                return new BoolLiteralExpr(loc, false);
            case "filesize":
                Advance();
                return new FilesizeExpr(loc);
            case "entrypoint":
                Advance();
                return new EntrypointExpr(loc);
            case "any":
            case "all":
            case "none":
            {
                Advance();
                Quantifier q = word switch
                {
                    "any" => new AnyQuantifier(loc),
                    "all" => new AllQuantifier(loc),
                    _ => new NoneQuantifier(loc),
                };
                ExpectWord("of");
                return ParseOfTail(q, loc);
            }
            case "for":
                return ParseFor(loc);
            case "them":
                Error(DiagnosticCode.SyntaxError, $"'them' at {loc} is only valid after 'of'", loc);
                throw new ParseAbort();
        }

        if (IntReadKinds.TryGetValue(word, out var readKind))
        {
            Advance();
            Expect(TokenKind.LParen, $"'(' after '{word}'");
            var offset = ParseBitOr();
            Expect(TokenKind.RParen, "')'");
            return new IntReadExpr(loc, readKind, offset);
        }

        if (Keywords.Contains(word))
        {
            Error(DiagnosticCode.SyntaxError, $"unexpected keyword '{word}' at {loc}", loc);
            throw new ParseAbort();
        }

        // A plain identifier: a loop variable or a reference to another rule. A dotted path
        // (pe.entry_point) is a module reference; keep the whole path for the validator.
        Advance();
        if (_current.Kind == TokenKind.Dot)
        {
            var sb = new StringBuilder(word);
            while (_current.Kind == TokenKind.Dot)
            {
                Advance();
                sb.Append('.');
                sb.Append(ExpectIdentifier("an identifier after '.'"));
            }
            // Module value references can carry calls/subscripts; consume a balanced tail
            // so one unsupported module reference yields one diagnostic, not a cascade.
            while (_current.Kind is TokenKind.LParen or TokenKind.LBracket)
            {
                SkipBalanced();
                if (_current.Kind == TokenKind.Dot)
                {
                    Advance();
                    sb.Append('.');
                    sb.Append(ExpectIdentifier("an identifier after '.'"));
                }
            }
            return new IdentifierExpr(loc, sb.ToString());
        }
        return new IdentifierExpr(loc, word);
    }

    private void SkipBalanced()
    {
        var open = _current.Kind;
        var close = open == TokenKind.LParen ? TokenKind.RParen : TokenKind.RBracket;
        int depth = 0;
        while (_current.Kind != TokenKind.EndOfFile)
        {
            if (_current.Kind == open)
            {
                depth++;
            }
            else if (_current.Kind == close && --depth == 0)
            {
                Advance();
                return;
            }
            Advance();
        }
        Error(DiagnosticCode.SyntaxError, $"unterminated '{(open == TokenKind.LParen ? "(" : "[")}' at {_current.Location}");
        throw new ParseAbort();
    }

    private YaraExpression ParseFor(SourceLocation loc)
    {
        ExpectWord("for");
        Quantifier quantifier;
        var qloc = _current.Location;
        if (TryWord("any"))
        {
            quantifier = new AnyQuantifier(qloc);
        }
        else if (TryWord("all"))
        {
            quantifier = new AllQuantifier(qloc);
        }
        else if (TryWord("none"))
        {
            quantifier = new NoneQuantifier(qloc);
        }
        else
        {
            var count = ParsePrimary();
            if (_current.Kind == TokenKind.Percent)
            {
                Advance();
                quantifier = new PercentQuantifier(qloc, count);
            }
            else
            {
                quantifier = new ExprQuantifier(qloc, count);
            }
        }

        if (TryWord("of"))
        {
            var set = ParseStringSet();
            Expect(TokenKind.Colon, "':' in for expression");
            Expect(TokenKind.LParen, "'(' opening the for body");
            var body = ParseExpression();
            Expect(TokenKind.RParen, "')' closing the for body");
            return new ForOfExpr(loc, quantifier, set, body);
        }

        var variable = ExpectIdentifier("a loop variable");
        ExpectWord("in");
        var iterable = ParseForIterable();
        Expect(TokenKind.Colon, "':' in for expression");
        Expect(TokenKind.LParen, "'(' opening the for body");
        var forBody = ParseExpression();
        Expect(TokenKind.RParen, "')' closing the for body");
        return new ForInExpr(loc, quantifier, variable, iterable, forBody);
    }

    private ForIterable ParseForIterable()
    {
        var loc = _current.Location;
        Expect(TokenKind.LParen, "'(' opening the iterable");
        var first = ParseBitOr();
        if (_current.Kind == TokenKind.DotDot)
        {
            Advance();
            var high = ParseBitOr();
            Expect(TokenKind.RParen, "')' closing the range");
            return new RangeIterable(loc, new RangeExpr(loc, first, high));
        }
        var items = new List<YaraExpression> { first };
        while (_current.Kind == TokenKind.Comma)
        {
            Advance();
            items.Add(ParseBitOr());
        }
        Expect(TokenKind.RParen, "')' closing the enumeration");
        return new EnumIterable(loc, items);
    }
}
