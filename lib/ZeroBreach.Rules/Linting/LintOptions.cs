namespace ZeroBreach.Rules.Linting;

/// <summary>Default budget values for one lint run, as named constants (BLUEPRINT §3).</summary>
public static class LintDefaults
{
    /// <summary>Ceiling for one pattern's matching work against one probe string. Matches
    /// the engine-wide per-pattern budget so the linter rejects what the scanner would
    /// have to abort.</summary>
    public static readonly TimeSpan PerPatternTimeout = BudgetDefaults.PerPatternDeadline;

    /// <summary>Wall-clock ceiling for the whole lint run. Generous because this runs in
    /// CI, not inside a scan — but still finite: rule files are content someone edits,
    /// and an edit must not be able to hang the pipeline.</summary>
    public static readonly TimeSpan TotalDeadline = TimeSpan.FromSeconds(60);

    /// <summary>Indicators whose longest required literal is shorter than this are
    /// suspect (BLUEPRINT §9: "fewer than four characters is automatically suspect").</summary>
    public const int MinIndicatorLiteralLength = 4;

    /// <summary>Refuse rule files larger than this before parsing.</summary>
    public const long MaxInputBytes = 16L * 1024 * 1024;
}

/// <summary>
/// Knobs for one lint run. The defaults are the product's defaults; the extension points
/// exist so CI can grow the collision corpus from a real fleet inventory and tell the
/// linter which sets the host actually consumes.
/// </summary>
public sealed record LintOptions
{
    public static LintOptions Default { get; } = new();

    /// <summary>Per-pattern, per-probe match budget. Exceeding it is a
    /// <see cref="LintCode.CatastrophicBacktracking"/> finding.</summary>
    public TimeSpan PerPatternTimeout { get; init; } = LintDefaults.PerPatternTimeout;

    /// <summary>Whole-run ceiling. Exceeding it yields <see cref="OperationState.Incomplete"/>
    /// with the reason — never a silently shortened lint reported as clean.</summary>
    public TimeSpan TotalDeadline { get; init; } = LintDefaults.TotalDeadline;

    /// <summary>See <see cref="LintDefaults.MinIndicatorLiteralLength"/>.</summary>
    public int MinIndicatorLiteralLength { get; init; } = LintDefaults.MinIndicatorLiteralLength;

    /// <summary>Names appended to the built-in collision corpus
    /// (<see cref="CollisionCorpus.StarterNames"/>). The owner should feed a real fleet
    /// inventory in here.</summary>
    public IReadOnlyList<string> AdditionalCollisionNames { get; init; } = Array.Empty<string>();

    /// <summary>Set/allowlist names referenced from outside the file — the names the host
    /// itself consumes. Participates in orphan/dangling analysis alongside the file's own
    /// <c>references</c> key.</summary>
    public IReadOnlyList<string> ExternalReferences { get; init; } = Array.Empty<string>();
}
