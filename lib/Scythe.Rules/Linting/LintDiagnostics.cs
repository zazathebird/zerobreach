namespace Scythe.Rules.Linting;

/// <summary>
/// Severity of a lint finding. The scale is wider than the YARA compiler's because the
/// linter has one defect class — a universal allowlist — that is strictly worse than any
/// other error: it silently blinds every check downstream of it while the tool keeps
/// reporting success. That gets <see cref="Critical"/>, the highest severity there is.
/// </summary>
public enum LintSeverity
{
    /// <summary>Nothing is wrong, but a check could not run and the reader should know.
    /// A silently skipped check is indistinguishable from a passing one.</summary>
    Info,

    /// <summary>Suspicious but not proven broken. Does not fail CI unless the caller
    /// opts in (<c>--fail-on-warning</c>).</summary>
    Warning,

    /// <summary>A defect. Fails CI.</summary>
    Error,

    /// <summary>A defect that fails open — it suppresses detections while everything
    /// still reports success. Fails CI.</summary>
    Critical,
}

/// <summary>Stable identifiers for every finding the linter can produce. Codes are part
/// of the public surface: CI filters and counts on them, so values never get renumbered.</summary>
public enum LintCode
{
    // Structure of the rule file itself.

    /// <summary>A key or value does not have the shape BLUEPRINT §9 defines
    /// (e.g. a set whose value is not an array of strings).</summary>
    SchemaViolation,

    /// <summary>The same key appears twice in one JSON object. JSON parsers silently keep
    /// one of the two, which is exactly how a narrow allowlist gets replaced by a wide one
    /// without anyone noticing; the linter refuses to pick.</summary>
    DuplicateKey,

    /// <summary>The same entry appears twice in one set.</summary>
    DuplicateEntry,

    /// <summary>An indicator set with no entries. It matches nothing, which looks exactly
    /// like a passing scan.</summary>
    EmptyIndicatorSet,

    // The patterns themselves.

    /// <summary>The entry is not a compilable regex. It matches nothing — the same silent
    /// failure mode as an empty set.</summary>
    RegexDoesNotCompile,

    /// <summary>A literal backslash followed by a regex-class letter: almost always
    /// <c>\\d</c> written where <c>\d</c> was meant, one JSON escaping level too deep.
    /// The entry compiles and silently never matches.</summary>
    DoubleEscapedClass,

    /// <summary>The pattern exceeded the per-pattern match budget against bait input.
    /// Rules run against attacker-authored content; a pattern that backtracks
    /// catastrophically is a denial of service on the scan itself.</summary>
    CatastrophicBacktracking,

    // Allowlists — these fail open, so they get the strictest checks.

    /// <summary>The allowlist entry matched every one of a set of deliberately unrelated
    /// canary strings. It suppresses everything.</summary>
    UniversalAllowlist,

    /// <summary>The allowlist entry is not anchored at both ends. Allowlists are compared
    /// against attacker-controlled values; an unanchored entry lets malware allowlist
    /// itself by choosing its own name.</summary>
    UnanchoredAllowlist,

    /// <summary>An allowlist entry matches a string its own detection set exists to catch,
    /// making that detection branch unreachable.</summary>
    AllowlistSwallowsDetection,

    // Indicator quality.

    /// <summary>The indicator's longest required literal is shorter than the minimum.
    /// Short or literal-free indicators collide with legitimate software.</summary>
    IndicatorTooShort,

    /// <summary>The indicator matches the name of a real, common product, vendor or
    /// process. This is how a detection list kills a healthy application.</summary>
    IndicatorCollidesWithLegitimateName,

    // Cross-references.

    /// <summary>A reference names a set or allowlist that does not exist in the file.
    /// The consumer of that name finds nothing — a detection that fails silently.</summary>
    DanglingReference,

    /// <summary>A set or allowlist that nothing references. Either it is dead weight or a
    /// reference to it was lost — both are worth a human look.</summary>
    OrphanSet,

    /// <summary>No reference data was supplied (no <c>references</c> key in the file and
    /// no external manifest), so orphan/dangling analysis did not run. Emitted so the
    /// skipped check is visible, not silent.</summary>
    ReferenceAnalysisInactive,
}

/// <summary>Line/column position within the linted file, 1-based.</summary>
public readonly record struct LintLocation(int Line, int Column)
{
    /// <summary>Position used for file-level findings that have no single token.</summary>
    public static LintLocation FileLevel => new(1, 1);

    public override string ToString() => $"line {Line}, column {Column}";
}

/// <summary>
/// One problem found in a rule file. Messages are read by a technician at a client's
/// desk: they name the file, the key, the offending entry and the position.
/// </summary>
/// <param name="SetName">The set or allowlist the finding is about, when it is about one.</param>
/// <param name="Entry">The offending entry's text, when the finding is about one entry.</param>
public sealed record LintFinding(
    LintSeverity Severity,
    LintCode Code,
    string Message,
    string FileName,
    LintLocation Location,
    string? SetName = null,
    string? Entry = null)
{
    public override string ToString() =>
        $"{FileName}({Location.Line},{Location.Column}): {SeverityWord} {Code}: {Message}";

    private string SeverityWord => Severity switch
    {
        LintSeverity.Critical => "critical",
        LintSeverity.Error => "error",
        LintSeverity.Warning => "warning",
        _ => "info",
    };
}
