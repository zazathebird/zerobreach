namespace ZeroBreach.Diff;

/// <summary>Caller-supplied knobs for a diff.</summary>
/// <param name="MaxBaselineAge">
/// Maximum acceptable age of the baseline, measured against the <em>current run's</em>
/// timestamp (not wall-clock now — results must be deterministic). A baseline older than this
/// produces a warning in the result. Null disables the staleness check.
/// </param>
public sealed record DiffOptions(
    TimeSpan? MaxBaselineAge = null);
