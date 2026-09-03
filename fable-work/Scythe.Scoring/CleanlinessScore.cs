namespace Scythe.Scoring;

/// <summary>
/// The report's headline number. <b>Range 0–100; higher is cleaner.</b> 100 is a run whose
/// attempted checks all completed and found nothing; 0 is a run whose findings exhausted the
/// range, or in which no check was attempted at all.
/// </summary>
/// <remarks>
/// <para>
/// The type is named for its direction so no call site can assume the other one. It is never a
/// bare number: <see cref="Contributions"/> sum exactly to <see cref="Value"/> and name what
/// moved it, and <see cref="WeightsVersion"/> says which arithmetic produced it.
/// </para>
/// <para>
/// Composition, in the integer domain (<see cref="ScoreWeights"/>):
/// <list type="number">
/// <item>start at <see cref="Maximum"/>;</item>
/// <item>deduct count × weight for each severity, stopping at <see cref="Minimum"/>;</item>
/// <item>scale what remains by the share of <i>attempted</i> checks (Completed + Inconclusive)
/// that completed, rounding down, so any inconclusive check keeps the score below the maximum
/// and a run in which nothing was attempted scores the minimum.</item>
/// </list>
/// Coverage participates downward only, and only through step 3, so it is always separable from
/// findings in the contributions.
/// </para>
/// </remarks>
/// <param name="Value">Between <see cref="Minimum"/> and <see cref="Maximum"/> inclusive.</param>
/// <param name="Contributions">In composition order: baseline, findings by severity descending, saturation if it happened, coverage. Their effects sum to <paramref name="Value"/>.</param>
/// <param name="WeightsVersion"><see cref="ScoreWeights.Version"/> at the time of composition.</param>
public sealed record CleanlinessScore(
    int Value,
    IReadOnlyList<ScoreContribution> Contributions,
    string WeightsVersion)
{
    /// <summary>The bottom of the range: the least clean.</summary>
    public const int Minimum = 0;

    /// <summary>The top of the range: the cleanest. Reachable only when every attempted check completed and nothing was found.</summary>
    public const int Maximum = 100;
}
