namespace ZeroBreach.Rules.Yara.Parsing;

// The parsed, structurally validated form of one .yar source file. Parsing produces this;
// matching (A2) and evaluation (A3) consume the compiled form built from it in A4.

public sealed record YaraFileAst(
    string FileName,
    IReadOnlyList<IncludeDirective> Includes,
    IReadOnlyList<ImportDirective> Imports,
    IReadOnlyList<YaraRuleAst> Rules);

public sealed record IncludeDirective(string Path, SourceLocation Location);

public sealed record ImportDirective(string Module, SourceLocation Location);

public sealed record YaraRuleAst(
    string Name,
    bool IsPrivate,
    bool IsGlobal,
    IReadOnlyList<string> Tags,
    IReadOnlyList<MetaEntry> Meta,
    IReadOnlyList<YaraStringDecl> Strings,
    YaraExpression Condition,
    SourceLocation Location);

public sealed record MetaEntry(string Key, MetaValue Value, SourceLocation Location);

public abstract record MetaValue;
public sealed record StringMetaValue(string Value) : MetaValue;
public sealed record IntegerMetaValue(long Value) : MetaValue;
public sealed record BooleanMetaValue(bool Value) : MetaValue;

// ---------------------------------------------------------------- string declarations

[Flags]
public enum StringModifierKind
{
    None = 0,
    Nocase = 1 << 0,
    Wide = 1 << 1,
    Ascii = 1 << 2,
    Fullword = 1 << 3,
    Xor = 1 << 4,
    Base64 = 1 << 5,
    Base64Wide = 1 << 6,
    Private = 1 << 7,
}

/// <summary>Modifier set for one string. Xor bounds are meaningful only when
/// <see cref="StringModifierKind.Xor"/> is present; a bare `xor` means the full 0-255 range.
/// A null alphabet means the standard base64 alphabet.</summary>
public sealed record StringModifiers(
    StringModifierKind Kinds,
    byte XorMin = 0,
    byte XorMax = 0,
    string? Base64Alphabet = null)
{
    public bool Has(StringModifierKind kind) => (Kinds & kind) != 0;
    public static StringModifiers None { get; } = new(StringModifierKind.None);
}

/// <summary>One entry in a rule's strings section. <paramref name="Identifier"/> is the name
/// without the leading '$'; the empty string is YARA's anonymous string, usable only through
/// `them` / wildcard sets.</summary>
public abstract record YaraStringDecl(
    string Identifier,
    StringModifiers Modifiers,
    SourceLocation Location);

/// <summary>A quoted text string. The value is kept as raw bytes because \xNN escapes can
/// produce any byte value and matching is over bytes, not characters.</summary>
public sealed record TextStringDecl(
    string Identifier,
    StringModifiers Modifiers,
    SourceLocation Location,
    byte[] ValueBytes) : YaraStringDecl(Identifier, Modifiers, Location);

public sealed record RegexStringDecl(
    string Identifier,
    StringModifiers Modifiers,
    SourceLocation Location,
    string Pattern,
    bool CaseInsensitive,
    bool DotMatchesAll) : YaraStringDecl(Identifier, Modifiers, Location);

public sealed record HexStringDecl(
    string Identifier,
    StringModifiers Modifiers,
    SourceLocation Location,
    HexSequence Sequence) : YaraStringDecl(Identifier, Modifiers, Location);

// ---------------------------------------------------------------- hex string structure

public abstract record HexNode;

/// <summary>A single byte position. Matches when (input &amp; Mask) == Value, inverted when
/// <paramref name="Negated"/> (YARA's `~` prefix). `??` is Mask 0; `?4` / `4?` are nibble
/// masks 0x0F / 0xF0.</summary>
public sealed record HexByteNode(byte Value, byte Mask, bool Negated = false) : HexNode;

/// <summary>A jump `[Min-Max]`. Max is null for an unbounded jump `[n-]` / `[-]`.</summary>
public sealed record HexJumpNode(int Min, int? Max) : HexNode;

public sealed record HexAltNode(IReadOnlyList<HexSequence> Branches) : HexNode;

public sealed record HexSequence(IReadOnlyList<HexNode> Nodes);

// ---------------------------------------------------------------- condition expressions

public abstract record YaraExpression(SourceLocation Location);

public sealed record BoolLiteralExpr(SourceLocation Location, bool Value) : YaraExpression(Location);
public sealed record IntegerLiteralExpr(SourceLocation Location, long Value) : YaraExpression(Location);
public sealed record DoubleLiteralExpr(SourceLocation Location, double Value) : YaraExpression(Location);

/// <summary>A quoted string literal in a condition (rhs of `contains` etc.). Kept as both
/// bytes (for byte-accurate comparison) and text (for diagnostics).</summary>
public sealed record StringLiteralExpr(SourceLocation Location, byte[] ValueBytes, string Text) : YaraExpression(Location);

/// <summary>Rhs of a `matches` operator.</summary>
public sealed record RegexLiteralExpr(SourceLocation Location, string Pattern, bool CaseInsensitive, bool DotMatchesAll) : YaraExpression(Location);

public sealed record FilesizeExpr(SourceLocation Location) : YaraExpression(Location);
public sealed record EntrypointExpr(SourceLocation Location) : YaraExpression(Location);

public enum IntReadKind
{
    UInt8, UInt16, UInt32, Int8, Int16, Int32,
    UInt8Be, UInt16Be, UInt32Be, Int8Be, Int16Be, Int32Be,
}

/// <summary>uint8(offset) family. Little-endian unless the Be variant (BLUEPRINT §4.3);
/// a read past the end of the buffer is undefined, which is false in boolean context.</summary>
public sealed record IntReadExpr(SourceLocation Location, IntReadKind Kind, YaraExpression Offset) : YaraExpression(Location);

/// <summary>`$a` used as a boolean. Empty name is the `$` placeholder inside a
/// `for ... of` body.</summary>
public sealed record StringMatchExpr(SourceLocation Location, string StringName) : YaraExpression(Location);

public sealed record RangeExpr(SourceLocation Location, YaraExpression Low, YaraExpression High) : YaraExpression(Location);

/// <summary>`#a`, optionally `#a in (range)` which counts only matches whose offset falls
/// inside the range. Empty name is the `#` placeholder in a `for ... of` body.</summary>
public sealed record StringCountExpr(SourceLocation Location, string StringName, RangeExpr? InRange) : YaraExpression(Location);

/// <summary>`@a[i]`; a missing subscript means index 1. 1-indexed; out of range is undefined
/// (false in boolean context), never an error.</summary>
public sealed record StringOffsetExpr(SourceLocation Location, string StringName, YaraExpression? Index) : YaraExpression(Location);

/// <summary>`!a[i]`; same indexing rules as <see cref="StringOffsetExpr"/>.</summary>
public sealed record StringLengthExpr(SourceLocation Location, string StringName, YaraExpression? Index) : YaraExpression(Location);

/// <summary>`$a at expr` — an offset test (a match starting exactly there), not a prefix test.</summary>
public sealed record StringAtExpr(SourceLocation Location, string StringName, YaraExpression Offset) : YaraExpression(Location);

/// <summary>`$a in (low..high)` — some match starts within the inclusive range.</summary>
public sealed record StringInExpr(SourceLocation Location, string StringName, RangeExpr Range) : YaraExpression(Location);

public enum UnaryOp { Not, Defined, Negate, BitNot }

public sealed record UnaryExpr(SourceLocation Location, UnaryOp Op, YaraExpression Operand) : YaraExpression(Location);

public enum BinaryOp
{
    Or, And,
    Eq, Ne, Lt, Le, Gt, Ge,
    Contains, IContains, StartsWith, IStartsWith, EndsWith, IEndsWith, IEquals, Matches,
    BitOr, BitXor, BitAnd,
    Shl, Shr,
    Add, Sub,
    Mul, Div, Mod,
}

public sealed record BinaryExpr(SourceLocation Location, BinaryOp Op, YaraExpression Left, YaraExpression Right) : YaraExpression(Location);

/// <summary>A bare identifier in a condition: either a loop variable or a reference to
/// another rule in the same set. The validator resolves which; anything else is an error.</summary>
public sealed record IdentifierExpr(SourceLocation Location, string Name) : YaraExpression(Location);

// ------------------------------------------------------------------ of / for constructs

public abstract record Quantifier(SourceLocation Location);
public sealed record AnyQuantifier(SourceLocation Location) : Quantifier(Location);
public sealed record AllQuantifier(SourceLocation Location) : Quantifier(Location);
public sealed record NoneQuantifier(SourceLocation Location) : Quantifier(Location);
public sealed record ExprQuantifier(SourceLocation Location, YaraExpression Count) : Quantifier(Location);
public sealed record PercentQuantifier(SourceLocation Location, YaraExpression Percent) : Quantifier(Location);

public abstract record StringSet(SourceLocation Location);
public sealed record ThemSet(SourceLocation Location) : StringSet(Location);

public sealed record StringSetItem(string Name, bool IsWildcard, SourceLocation Location);
public sealed record ListSet(SourceLocation Location, IReadOnlyList<StringSetItem> Items) : StringSet(Location);

/// <summary>`N of (set)`, optionally restricted: `N of them in (range)`.</summary>
public sealed record OfExpr(SourceLocation Location, Quantifier Quantifier, StringSet Set, RangeExpr? InRange) : YaraExpression(Location);

/// <summary>`for Q of (set) : ( body )`; the body may use the `$`/`#`/`@`/`!` placeholders.</summary>
public sealed record ForOfExpr(SourceLocation Location, Quantifier Quantifier, StringSet Set, YaraExpression Body) : YaraExpression(Location);

public abstract record ForIterable(SourceLocation Location);
public sealed record RangeIterable(SourceLocation Location, RangeExpr Range) : ForIterable(Location);
public sealed record EnumIterable(SourceLocation Location, IReadOnlyList<YaraExpression> Items) : ForIterable(Location);

/// <summary>`for Q v in (iterable) : ( body )`.</summary>
public sealed record ForInExpr(SourceLocation Location, Quantifier Quantifier, string Variable, ForIterable Iterable, YaraExpression Body) : YaraExpression(Location);
