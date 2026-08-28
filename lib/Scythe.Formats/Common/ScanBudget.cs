namespace Scythe.Formats;

/// <summary>
/// Resource budget for a single operation over attacker-authored content (BLUEPRINT §3).
/// Every public entry point in this layer takes one. Exceeding any bound yields
/// <see cref="OperationState.Incomplete"/> with the reason — never a silent <c>Ok</c>.
/// </summary>
/// <param name="Deadline">Wall-clock ceiling for the whole operation.</param>
/// <param name="MaxInputBytes">Refuse input beyond this size.</param>
/// <param name="MaxMatches">Stop collecting results past this.</param>
/// <param name="MaxNestingDepth">Cap for containers and nested structures (e.g. the PE resource tree).</param>
public sealed record ScanBudget(
    TimeSpan Deadline,
    long MaxInputBytes,
    int MaxMatches,
    int MaxNestingDepth);

/// <summary>Default budget values from BLUEPRINT §3, as named constants — never literals at call sites.</summary>
public static class BudgetDefaults
{
    /// <summary>150 ms per single pattern match.</summary>
    public static readonly TimeSpan SinglePatternDeadline = TimeSpan.FromMilliseconds(150);

    /// <summary>5 s per file across all rules.</summary>
    public static readonly TimeSpan PerFileDeadline = TimeSpan.FromSeconds(5);

    /// <summary>64 MiB of input.</summary>
    public const long MaxInputBytes = 64L * 1024 * 1024;

    /// <summary>10 000 collected matches.</summary>
    public const int MaxMatches = 10_000;

    /// <summary>Nesting depth 8.</summary>
    public const int MaxNestingDepth = 8;

    /// <summary>The default per-file budget.</summary>
    public static ScanBudget Default => new(PerFileDeadline, MaxInputBytes, MaxMatches, MaxNestingDepth);
}
