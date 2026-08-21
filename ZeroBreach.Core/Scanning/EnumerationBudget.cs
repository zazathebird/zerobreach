using System.Diagnostics;

namespace ZeroBreach.Core.Scanning;

/// <summary>
/// Item/time budget for one enumeration walk. Spec §4 ("the single most important
/// architectural lesson"): budgets must scale with the number of things walked, so callers
/// create ONE budget PER profile / per walk via <see cref="ScanContext.CreateBudget"/> —
/// never one shared budget across N profiles. A walk cut short must signal it: when
/// <see cref="TryConsume"/> returns false, the caller is REQUIRED to report the check as
/// Inconclusive (helper: <see cref="FindingSinkExtensions.CompleteOrInconclusive"/>),
/// never as clean.
/// </summary>
public sealed class EnumerationBudget
{
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly TimeSpan _maxTime;

    public EnumerationBudget(int maxItems, TimeSpan maxTime)
    {
        MaxItems = maxItems;
        _maxTime = maxTime;
    }

    public int MaxItems { get; }
    public int Consumed { get; private set; }
    public bool Exhausted { get; private set; }
    public string? ExhaustedReason { get; private set; }

    /// <summary>Consume one unit. Returns false (and latches Exhausted) when the walk
    /// must stop. Once exhausted, stays exhausted.</summary>
    public bool TryConsume()
    {
        if (Exhausted) return false;
        if (Consumed >= MaxItems)
        {
            Exhausted = true;
            ExhaustedReason = $"item budget exhausted ({MaxItems} items)";
            return false;
        }
        if (_clock.Elapsed > _maxTime)
        {
            Exhausted = true;
            ExhaustedReason = $"time budget exhausted ({_maxTime.TotalSeconds:0}s, {Consumed} items walked)";
            return false;
        }
        Consumed++;
        return true;
    }
}
