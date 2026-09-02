namespace Scythe.Rules.Linting;

public static class LintDefaults
{
    public static readonly TimeSpan PerPatternTimeout = BudgetDefaults.PerPatternDeadline;

    public static readonly TimeSpan TotalDeadline = TimeSpan.FromSeconds(60);

    public const int MinIndicatorLiteralLength = 4;

    public const long MaxInputBytes = 16L * 1024 * 1024;
}

/// <summary>
/// The two on-disk shapes a rule file can take. The linter was written against
/// <see cref="Nested"/>; the file the PowerShell engine actually ships is <see cref="Flat"/>,
/// and the reader has to know which it is reading because the same JSON means different
/// things under each.
/// </summary>
public enum RuleFileShape
{
    /// <summary>
    /// The BLUEPRINT §9 shape: every top-level key is an array of pattern strings, allowlists
    /// live under the reserved <c>fp_allowlists</c> object, and any other value type is a
    /// schema violation.
    /// </summary>
    Nested,

    /// <summary>
    /// The shape of <c>data/detection_signatures.json</c>: one flat object whose values are
    /// arrays of strings, arrays of rule objects (regex-bearing fields named
    /// <c>Pattern</c>/<c>pattern</c> or ending in <c>Rx</c>/<c>Regex</c>/<c>_rule</c>),
    /// single regex strings, arrays of numbers, plain objects of thresholds, and
    /// <c>_comment*</c> strings that document the entry after them. Allowlists are not
    /// distinguishable by position — the host decides which names it feeds to its allowlist
    /// joiner, so they arrive by name through <see cref="LintOptions.AllowlistNames"/>.
    /// </summary>
    Flat,
}

public sealed record LintOptions
{
    public static LintOptions Default { get; } = new();

    public TimeSpan PerPatternTimeout { get; init; } = LintDefaults.PerPatternTimeout;

    public TimeSpan TotalDeadline { get; init; } = LintDefaults.TotalDeadline;

    public int MinIndicatorLiteralLength { get; init; } = LintDefaults.MinIndicatorLiteralLength;

    public IReadOnlyList<string> AdditionalCollisionNames { get; init; } = Array.Empty<string>();

    /// <summary>Set names the host consumes, for orphan/dangling analysis. Names in
    /// <see cref="AllowlistNames"/> count as consumed too.</summary>
    public IReadOnlyList<string> ExternalReferences { get; init; } = Array.Empty<string>();

    public RuleFileShape Shape { get; init; } = RuleFileShape.Nested;

    /// <summary>
    /// Top-level sets to lint as allowlists regardless of where they sit in the file. In a
    /// <see cref="RuleFileShape.Flat"/> file this is the only way an allowlist is recognised,
    /// and it must come from what the host really does — the names it passes to its allowlist
    /// joiner — not from a naming convention, because a set that <i>looks</i> like an allowlist
    /// but is consumed as an indicator (or the reverse) gets exactly the wrong checks.
    /// </summary>
    public IReadOnlyCollection<string> AllowlistNames { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Sets whose entries the host matches as literal substrings (it escapes them before
    /// matching, or expands them as paths) rather than compiling them as regexes. The linter
    /// escapes each entry before it compiles it, so a path like <c>$env:APPDATA\Roaming</c>
    /// is not reported as an unrecognised escape, and runs the collision corpus against the
    /// escaped form — which is exactly the substring match the host performs.
    /// </summary>
    public IReadOnlyCollection<string> LiteralSets { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Sets whose entries the host compares as whole values — <c>-contains</c>, <c>-in</c>,
    /// <c>-eq</c>, a hashtable key, or a path handed to <c>Test-Path</c>. Checked as
    /// <c>^escaped$</c>: a literal <c>.bat</c> in an extension list does not collide with
    /// "Adobe Acrobat", and a path list is not a detection an allowlist can swallow.
    /// </summary>
    public IReadOnlyCollection<string> EqualitySets { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Sets whose entries are <c>-like</c> globs: the host turns <c>*</c> into <c>.*</c> and
    /// anchors the whole thing. The linter performs the same translation, so
    /// <c>lsassy*</c> is checked as the whole-name glob it is and not as the regex
    /// <c>lsass</c> followed by optional <c>y</c>, which would collide with lsass.exe.
    /// </summary>
    public IReadOnlyCollection<string> WildcardSets { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Sets whose entries name legitimate or structural things by design — system image
    /// names a masquerade check compares against, LOLBin names, file extensions, kill-chain
    /// stage keywords. The detection is a context mismatch the host computes, so "this entry
    /// matches real software" is the point, not a defect: the collision corpus, the literal
    /// length floor and the swallowed-detection pairing do not apply. Compile, budget and
    /// duplicate checks still do.
    /// </summary>
    public IReadOnlyCollection<string> ReferenceSets { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Allowlists matched against text whose location the attacker does not choose — install
    /// paths, signer names — where the host's rule is component anchoring (an entry begins
    /// and ends at a path separator or a real anchor) rather than <c>^…$</c>. An entry that
    /// is not even component-anchored is reported as a warning instead of an error. Every
    /// other allowlist is compared against an attacker-chosen value and keeps the strict
    /// rule.
    /// </summary>
    public IReadOnlyCollection<string> SubstringAllowlists { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Collisions with the legitimate-name corpus that a maintainer has reviewed and kept,
    /// each with the reason. A matching finding is reported at Info with the reason
    /// appended, so it stays visible without failing the lint. The entry must match
    /// exactly: editing the pattern re-opens the question.
    /// </summary>
    public IReadOnlyList<AcceptedCollision> AcceptedCollisions { get; init; } = Array.Empty<AcceptedCollision>();
}

/// <summary>One reviewed collision: the set and exact entry it applies to, and why it stays.</summary>
public sealed record AcceptedCollision(string Set, string Entry, string Why);
