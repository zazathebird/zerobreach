namespace Scythe.Scoring;

/// <summary>
/// The product's five severity levels, in ascending order. The ordering is meaningful: the
/// score weights in <see cref="ScoreWeights"/> are strictly increasing along it, and the
/// severity counts are reported along it. Do not reorder casually (reference/07_records.md §7).
/// </summary>
/// <remarks>
/// The record model (reference/07_records.md) names the enum but does not list its members;
/// the five levels and their order are taken from the only place in the package that
/// enumerates them, the severity mapping table in reference/15.1_interchange.md §15.1.5.
/// This is the projection of that enum the rollup consumes, not a second copy of the model —
/// see <see cref="RollupInput"/>.
/// </remarks>
public enum Severity
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
