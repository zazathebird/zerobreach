namespace Scythe.Correlation;

/// <summary>One recognised entity in a piece of free text, with where it was found.</summary>
/// <param name="Entity">The normalised entity.</param>
/// <param name="Offset">Character offset of the recognised token in the text.</param>
/// <param name="Length">Length of the recognised token in characters.</param>
public sealed record EntityMention(Entity Entity, int Offset, int Length);
