namespace Scythe.Correlation;

/// <summary>
/// The projection of one finding that chain assembly needs. The caller maps each record-model
/// <c>Finding</c> onto one of these; all the findings handed to one <see cref="ChainBuilder.Build"/>
/// call must come from <b>one</b> run record (process identifiers do not survive the boundary).
/// </summary>
/// <param name="Id">The finding's stable identifier. Must be unique within the run; ordinal
/// comparison of it is the final tie-break for every ordering this library produces.</param>
/// <param name="Description">Free text. Entities in it are recognised by shape.</param>
/// <param name="Target">The typed target, or null when the finding has none.</param>
/// <param name="Anchor">
/// An <b>ordering</b> input for first-finding nomination and nothing else. The record model
/// currently carries no per-artifact time — every finding is stamped with the run's time
/// (reference/07_records.md rule 1) — so a caller either passes null or passes the same value for
/// every finding, and nomination falls through to the id. If a future revision of the record
/// adds a per-artifact time, it goes here. It never participates in grouping.
/// </param>
public sealed record FindingReference(
    string Id,
    string Description,
    EntityReference? Target,
    DateTimeOffset? Anchor = null);
