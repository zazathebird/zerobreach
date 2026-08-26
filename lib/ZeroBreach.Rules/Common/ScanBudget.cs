namespace ZeroBreach.Rules;

/// <summary>
/// Resource ceilings for one scan operation (BLUEPRINT §3). Everything in this layer
/// processes attacker-authored content; exceeding any bound yields
/// <see cref="OperationState.Incomplete"/> with the reason — never a silent Ok.
/// </summary>
/// <param name="Deadline">Wall-clock ceiling for the whole operation.</param>
/// <param name="MaxInputBytes">Inputs larger than this are refused (Incomplete), not scanned.</param>
/// <param name="MaxMatches">Stop collecting matches past this; hitting it is Incomplete.</param>
/// <param name="MaxNestingDepth">Ceiling for nested containers / nested structures.</param>
public sealed record ScanBudget(
    TimeSpan Deadline,
    long MaxInputBytes,
    int MaxMatches,
    int MaxNestingDepth)
{
    public static ScanBudget Default => new(
        BudgetDefaults.PerFileDeadline,
        BudgetDefaults.MaxInputBytes,
        BudgetDefaults.MaxMatches,
        BudgetDefaults.MaxNestingDepth);
}

/// <summary>Default budget values from BLUEPRINT §3, as named constants.</summary>
public static class BudgetDefaults
{
    /// <summary>Ceiling for a single pattern's matching work within one buffer.</summary>
    public static readonly TimeSpan PerPatternDeadline = TimeSpan.FromMilliseconds(150);

    /// <summary>Ceiling for one file across all rules.</summary>
    public static readonly TimeSpan PerFileDeadline = TimeSpan.FromSeconds(5);

    public const long MaxInputBytes = 64L * 1024 * 1024;

    public const int MaxMatches = 10_000;

    public const int MaxNestingDepth = 8;
}
