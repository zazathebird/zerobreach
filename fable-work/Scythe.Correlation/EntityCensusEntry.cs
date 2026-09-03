namespace Scythe.Correlation;

/// <summary>How many findings reference an entity, relative to the common-noun threshold.</summary>
public enum EntityReferenceClass
{
    /// <summary>Exactly one finding references it. It joins nothing.</summary>
    Single,

    /// <summary>Two or more findings, up to and including <see cref="ChainBuilder.CommonNounThreshold"/>. It draws edges.</summary>
    Shared,

    /// <summary>More findings than the threshold. A common noun; it draws no edges.</summary>
    CommonNoun,
}

/// <summary>
/// One row of the run's entity census: an entity, every finding that references it, and its class.
/// The census is public so that a consumer wanting per-entity groups instead of connected
/// components can build them without a second extraction.
/// </summary>
/// <param name="Entity">The entity, in its reported spelling (ordinal-smallest of the spellings seen).</param>
/// <param name="FindingIds">Distinct referencing finding ids, ordinal order.</param>
/// <param name="Class">Its position relative to the threshold.</param>
public sealed record EntityCensusEntry(Entity Entity, IReadOnlyList<string> FindingIds, EntityReferenceClass Class);
