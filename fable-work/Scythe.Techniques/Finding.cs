namespace Scythe.Techniques;

/// <summary>
/// The slice of a finding the resolver needs. The record model itself belongs to K3; a caller
/// projects each of its findings onto this shape.
/// </summary>
/// <param name="FindingId">
/// The caller's key for the finding, echoed on every resolution so the caller can line results
/// up. Required and non-empty; the resolver does not require it to be unique.
/// </param>
/// <param name="CheckId">
/// The producing check's identifier, matched exactly (ordinal) against the check mappings.
/// Null when the finding names no producing check.
/// </param>
/// <param name="Description">
/// The finding's description, which the keyword strategy searches. Null when the finding has
/// none; the keyword strategy then declines rather than matching the empty string.
/// </param>
/// <param name="ExplicitIdentifier">
/// An identifier the check attached deliberately. Null when the finding carries none. A
/// non-null value that is not a well-formed identifier, or is absent from the map, makes the
/// finding unresolved — it never falls through to a weaker strategy.
/// </param>
/// <remarks>
/// One identifier per finding. Some observations genuinely correspond to two techniques; that
/// multi-identifier shape is a known future extension (K4 open question 1) and is not modelled
/// here because it changes the rollup arithmetic.
/// </remarks>
public sealed record Finding(
    string FindingId,
    string? CheckId,
    string? Description,
    string? ExplicitIdentifier);

/// <summary>
/// A producing check's declared mapping: every finding from <paramref name="CheckId"/> that
/// carries no explicit identifier corresponds to <paramref name="Identifier"/>.
/// </summary>
/// <remarks>
/// One identifier per check, for the same reason as one per finding. Two mappings for the same
/// check that agree are accepted as one; two that disagree are a construction failure.
/// </remarks>
public sealed record CheckMapping(string CheckId, string Identifier);
