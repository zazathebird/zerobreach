using System.Diagnostics;

namespace Scythe.ShellItems;

/// <summary>Per-call budget state. The stopwatch is the only clock in the library and never reaches a result.</summary>
internal sealed class ParseContext
{
    private readonly Stopwatch _clock = Stopwatch.StartNew();

    public ParseContext(ScanBudget budget)
    {
        Budget = budget;
    }

    public ScanBudget Budget { get; }

    public bool DeadlineExpired => _clock.Elapsed >= Budget.Deadline;

    public string DeadlineReason(string where) =>
        $"Deadline: {Budget.Deadline.TotalMilliseconds:0} ms elapsed {where}";

    public string MaxMatchesReason(string what) =>
        $"MaxMatches: more than {Budget.MaxMatches} {what}";

    public string MaxNestingDepthReason(int depth, string what) =>
        $"MaxNestingDepth: {what} sits at depth {depth}, budget allows {Budget.MaxNestingDepth}";
}

/// <summary>An early exit from one parse step; null means the step completed.</summary>
internal sealed record Problem(LinkResultState State, string Message, long? Position)
{
    public static Problem Incomplete(string reason) => new(LinkResultState.Incomplete, reason, null);

    public static Problem Failed(string message, long position) => new(LinkResultState.Failed, message, position);
}
