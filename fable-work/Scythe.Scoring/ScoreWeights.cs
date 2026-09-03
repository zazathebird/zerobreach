namespace Scythe.Scoring;

/// <summary>
/// Every constant the score composition uses, in one place, so a report can explain them and a
/// single edit changes them. None is caller-supplied: a caller who can set a weight to zero can
/// make findings disappear from the score while leaving them in the list.
/// </summary>
/// <remarks>
/// <para>
/// All arithmetic in this project is done in the <b>integer domain</b> (<see cref="long"/> for
/// the sums, <see cref="int"/> for the points). No weight is fractional, no division produces a
/// fraction that is carried, and the result is byte-identical on every platform by construction
/// rather than by care.
/// </para>
/// <para>
/// The values are <b>estimates</b>, not measurements: no real run record has been scored
/// (reference/07.5_unverifiable.md). Any change to any constant here is a change to
/// <see cref="Version"/>, and the version travels in every <see cref="CleanlinessScore"/>, so
/// two scores from different weightings are never compared silently.
/// </para>
/// </remarks>
public static class ScoreWeights
{
    /// <summary>
    /// Identifies this set of constants. Bump it whenever any value below changes; a score carries
    /// it so a provider comparing this month's figure to last month's can see whether the
    /// arithmetic behind them is the same.
    /// </summary>
    public const string Version = "1";

    /// <summary>Points deducted per finding at each severity. Strictly increasing; none zero.</summary>
    public const int InformationalWeight = 1;
    public const int LowWeight = 2;
    public const int MediumWeight = 5;
    public const int HighWeight = 15;
    public const int CriticalWeight = 40;

    /// <summary>
    /// How hard inconclusive coverage bears on the score, in hundredths. At 100 the achievable
    /// maximum scales exactly with the share of attempted checks that completed: a run with a
    /// third of its attempted checks inconclusive can reach at most two thirds of the range,
    /// whatever its findings. Lower values soften that; 0 would switch coverage off and is not
    /// a value this constant may take.
    /// </summary>
    public const int CoverageWeightHundredths = 100;

    /// <summary>
    /// The weight for one severity level, or null for a value that is not one of the five. Null
    /// rather than a throw or a default: a weight invented for an undefined level would score a
    /// finding the record model cannot describe.
    /// </summary>
    public static int? WeightFor(Severity severity) => severity switch
    {
        Severity.Informational => InformationalWeight,
        Severity.Low => LowWeight,
        Severity.Medium => MediumWeight,
        Severity.High => HighWeight,
        Severity.Critical => CriticalWeight,
        _ => null,
    };
}
