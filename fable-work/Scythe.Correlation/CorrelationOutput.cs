namespace Scythe.Correlation;

/// <summary>
/// The result of one chain assembly. Every list is sorted by a stated key, so two runs over the
/// same findings render byte-identically through <see cref="CanonicalWriter"/>.
/// </summary>
/// <param name="Chains">Components of two or more findings, ordered by <see cref="Chain.FirstFindingId"/> (ordinal).</param>
/// <param name="UnchainedFindingIds">Findings in no chain, ordinal order.</param>
/// <param name="Census">Every entity referenced by any finding, in <see cref="Entity.Ordering"/> order.</param>
/// <param name="RejectedTargets">Typed targets that did not normalise, by finding id (ordinal).</param>
public sealed record CorrelationOutput(
    IReadOnlyList<Chain> Chains,
    IReadOnlyList<string> UnchainedFindingIds,
    IReadOnlyList<EntityCensusEntry> Census,
    IReadOnlyList<RejectedTarget> RejectedTargets);
