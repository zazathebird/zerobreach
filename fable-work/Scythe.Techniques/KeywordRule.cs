namespace Scythe.Techniques;

/// <summary>
/// One rule of the keyword strategy: a finding whose description contains
/// <see cref="Keyword"/> (ordinal, case-insensitive) resolves to <see cref="Identifier"/>.
/// </summary>
/// <param name="Ordinal">Zero-based position in the map file's <c>rules</c> array. First match wins.</param>
public sealed record KeywordRule(
    int Ordinal,
    string Keyword,
    TechniqueIdentifier Identifier)
{
    public bool Matches(string description) =>
        description.Contains(Keyword, StringComparison.OrdinalIgnoreCase);
}
