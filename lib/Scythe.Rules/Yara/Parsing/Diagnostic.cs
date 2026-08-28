namespace Scythe.Rules.Yara.Parsing;

public enum DiagnosticSeverity
{
    /// <summary>Compilation fails. A malformed rule file never compiles to "a rule that
    /// matches nothing" — it fails loudly, with position.</summary>
    Error,

    /// <summary>Compiles, but suspicious. Surfaced so a technician fixing a downloaded
    /// rule set sees the whole picture.</summary>
    Warning,
}

/// <summary>Stable identifiers for every diagnostic the YARA front end can produce.
/// Codes are part of the public surface: the host filters and counts on them.</summary>
public enum DiagnosticCode
{
    // Lexical / syntactic
    UnexpectedCharacter,
    UnterminatedString,
    UnterminatedRegex,
    UnterminatedHexString,
    UnterminatedComment,
    InvalidEscapeSequence,
    InvalidNumber,
    SyntaxError,
    IdentifierTooLong,
    NestingTooDeep,

    // Structural validation
    DuplicateRuleName,
    DuplicateStringIdentifier,
    DuplicateMetaKey,
    UndefinedStringReference,
    UnreferencedString,
    WildcardMatchesNothing,
    EmptyStringsSection,
    ThemWithNoStrings,
    UndefinedRuleReference,
    ForwardRuleReference,
    RuleReferenceCycle,
    DuplicateLoopVariable,
    AnonymousStringOutsideLoop,
    MisplacedRegexLiteral,
    TooManyDiagnostics,
    InvalidModifierCombination,
    InvalidModifierForStringKind,
    DuplicateModifier,
    InvalidXorRange,
    InvalidBase64Alphabet,
    Base64StringTooShort,
    EmptyString,
    InvalidHexJump,
    UnsupportedModule,
    UnresolvedInclude,
    IncludeCycle,
    IncludeDepthExceeded,

    // Pathology rejected at compile time (BLUEPRINT §3)
    PatternTooComplex,
    UnanchoredPattern,
    CatastrophicPattern,
    InvalidRegex,

    // Warnings
    NoMetaSection,
    DuplicateTag,
}

public readonly record struct SourceLocation(int Line, int Column)
{
    public override string ToString() => $"line {Line}, column {Column}";
}

/// <summary>
/// One problem found while compiling rule content. Messages are read by a technician at a
/// client's desk: they name the file, the position and the offending construct.
/// </summary>
public sealed record Diagnostic(
    DiagnosticSeverity Severity,
    DiagnosticCode Code,
    string Message,
    string FileName,
    SourceLocation Location)
{
    public override string ToString() =>
        $"{FileName}({Location.Line},{Location.Column}): {Severity switch { DiagnosticSeverity.Error => "error", _ => "warning" }} {Code}: {Message}";
}
