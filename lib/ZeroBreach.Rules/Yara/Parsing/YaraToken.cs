namespace ZeroBreach.Rules.Yara.Parsing;

public enum TokenKind
{
    EndOfFile,
    Identifier,          // possibly a keyword; the parser checks against the reserved set
    StringId,            // $name (name may be empty for the anonymous `$`)
    StringIdWildcard,    // $name* — only meaningful inside a string set
    StringCountId,       // #name (or bare `#`)
    StringOffsetId,      // @name (or bare `@`)
    StringLengthId,      // !name (or bare `!`)
    IntegerLiteral,
    DoubleLiteral,
    StringLiteral,       // carries unescaped bytes
    RegexLiteral,        // carries pattern text and flags

    LBrace, RBrace, LParen, RParen, LBracket, RBracket,
    Colon, Comma, Dot, DotDot,
    Assign,              // =
    Eq, Ne, Lt, Le, Gt, Ge,
    Plus, Minus, Star, Backslash, Percent,     // YARA's division operator is `\`
    Amp, Pipe, Caret, Tilde, Shl, Shr,
}

public sealed record YaraToken(
    TokenKind Kind,
    string Text,
    SourceLocation Location,
    long IntegerValue = 0,
    double DoubleValue = 0,
    byte[]? Bytes = null,        // StringLiteral: unescaped byte value
    bool RegexI = false,
    bool RegexS = false)
{
    public bool Is(TokenKind kind) => Kind == kind;

    /// <summary>True when this token is the exact identifier/keyword <paramref name="word"/>.
    /// YARA keywords are case-sensitive.</summary>
    public bool IsWord(string word) => Kind == TokenKind.Identifier && Text == word;
}
