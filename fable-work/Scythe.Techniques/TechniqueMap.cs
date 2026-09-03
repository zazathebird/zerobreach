namespace Scythe.Techniques;

/// <summary>
/// A loaded and validated technique reference map. Only <see cref="TechniqueMapLoader"/>
/// constructs one, so every invariant the loader checks — identifier format, parent present for
/// every sub-technique, no duplicates, every rule's identifier present — holds here.
/// </summary>
public sealed class TechniqueMap
{
    private readonly Dictionary<string, TechniqueEntry> _byIdentifier;

    internal TechniqueMap(IReadOnlyList<TechniqueEntry> entries, IReadOnlyList<KeywordRule> rules)
    {
        Entries = entries;
        Rules = rules;
        _byIdentifier = new Dictionary<string, TechniqueEntry>(entries.Count, StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            _byIdentifier.Add(entry.Identifier.Value, entry);
        }
    }

    /// <summary>
    /// Entries sorted ordinally on the identifier string. Ordinal order is also the natural
    /// numeric order for this format, because the digit fields are fixed-width and zero-padded;
    /// do not replace it with a culture-sensitive comparison.
    /// </summary>
    public IReadOnlyList<TechniqueEntry> Entries { get; }

    /// <summary>Keyword rules in file order, which is the order the resolver applies them.</summary>
    public IReadOnlyList<KeywordRule> Rules { get; }

    public int Count => Entries.Count;

    /// <summary>Exact, case-sensitive lookup. A near-miss is absent, by design.</summary>
    public bool TryGetEntry(string identifier, out TechniqueEntry entry)
    {
        if (_byIdentifier.TryGetValue(identifier, out var found))
        {
            entry = found;
            return true;
        }

        entry = null!;
        return false;
    }

    public bool Contains(string identifier) => _byIdentifier.ContainsKey(identifier);
}
