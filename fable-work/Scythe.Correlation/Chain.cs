namespace Scythe.Correlation;

/// <summary>
/// One connected component of two or more findings.
/// </summary>
/// <param name="FirstFindingId">
/// The nominated first finding: the member with the earliest <see cref="FindingReference.Anchor"/>,
/// anchored members before unanchored ones, then the ordinal-smallest id. Total, and independent
/// of the order findings arrived in.
/// </param>
/// <param name="MemberFindingIds">Every member, ordinal order.</param>
/// <param name="JoiningEntities">
/// Only the entities that drew an edge inside this chain — shared by two or more members and
/// below the common-noun threshold — in <see cref="Entity.Ordering"/> order. Entities a member
/// mentions alone are not here; the census has them.
/// </param>
public sealed record Chain(
    string FirstFindingId,
    IReadOnlyList<string> MemberFindingIds,
    IReadOnlyList<Entity> JoiningEntities);
