namespace Scythe.Techniques;

/// <summary>One validated entry of the technique reference map.</summary>
/// <param name="Identifier">The technique or sub-technique identifier.</param>
/// <param name="Name">Human-readable name, as written in the map.</param>
/// <param name="Category">The category the technique belongs to, as written in the map.</param>
/// <param name="Url">
/// The reference URL exactly as written in the map. Validated as a well-formed absolute
/// http(s) URL at load; kept as the original string rather than a <see cref="Uri"/> so that
/// no normalisation is applied to what the curator wrote. Never fetched.
/// </param>
public sealed record TechniqueEntry(
    TechniqueIdentifier Identifier,
    string Name,
    string Category,
    string Url);
