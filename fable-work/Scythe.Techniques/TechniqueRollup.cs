namespace Scythe.Techniques;

/// <summary>A name and how many times it was counted.</summary>
public sealed record CountedName(string Name, int Count);

/// <summary>A strategy and how many findings it resolved.</summary>
public sealed record StrategyCount(ResolutionStrategy Strategy, int Count);

/// <summary>An unresolved reason and how many findings carry it.</summary>
public sealed record UnresolvedReasonCount(UnresolvedReason Reason, int Count);

/// <summary>
/// The per-run rollup: counts by identifier and by category, the identifiers seen, and the
/// unresolved findings as their own group.
/// </summary>
/// <remarks>
/// <para><b>Two counting members per axis, and they disagree on purpose.</b> A sub-technique
/// identifier rolls up to its parent as well as counting itself: two findings tagged
/// <c>T1234.001</c> mean both that <c>T1234</c> was observed twice and that <c>T1234.001</c> was
/// observed twice, and both facts are wanted. So:</para>
/// <list type="bullet">
/// <item><see cref="DirectCountsByIdentifier"/> and <see cref="DirectCountsByCategory"/> count
/// each resolved finding exactly once, under the identifier it resolved to and that entry's
/// category. <b>These sum to <see cref="ResolvedCount"/>.</b></item>
/// <item><see cref="RolledUpCountsByIdentifier"/> and <see cref="RolledUpCountsByCategory"/>
/// additionally count each sub-technique finding under its parent identifier and the parent's
/// category. <b>These do not sum to the finding count, and are not meant to</b> — a finding on
/// a sub-technique is counted twice, once at each level. When the parent and sub-technique
/// share a category, that category is counted twice for the one finding too.</item>
/// </list>
/// <para>Unresolved findings are never folded into a category. They are reported under
/// <see cref="Unresolved"/> with their reasons, and <see cref="UnresolvedCount"/> plus
/// <see cref="ResolvedCount"/> equals <see cref="FindingCount"/>.</para>
/// <para>Every list is sorted ordinally on its name. For identifiers that is also numeric
/// order, because the digit fields are fixed-width and zero-padded — do not replace it with a
/// culture-sensitive comparison.</para>
/// </remarks>
public sealed class TechniqueRollup
{
    private TechniqueRollup(
        int findingCount,
        int resolvedCount,
        IReadOnlyList<CountedName> directByIdentifier,
        IReadOnlyList<CountedName> rolledUpByIdentifier,
        IReadOnlyList<CountedName> directByCategory,
        IReadOnlyList<CountedName> rolledUpByCategory,
        IReadOnlyList<string> identifiersSeen,
        IReadOnlyList<string> identifiersSeenIncludingParents,
        IReadOnlyList<StrategyCount> countsByStrategy,
        IReadOnlyList<UnresolvedFinding> unresolved,
        IReadOnlyList<UnresolvedReasonCount> unresolvedCountsByReason)
    {
        FindingCount = findingCount;
        ResolvedCount = resolvedCount;
        DirectCountsByIdentifier = directByIdentifier;
        RolledUpCountsByIdentifier = rolledUpByIdentifier;
        DirectCountsByCategory = directByCategory;
        RolledUpCountsByCategory = rolledUpByCategory;
        IdentifiersSeen = identifiersSeen;
        IdentifiersSeenIncludingParents = identifiersSeenIncludingParents;
        CountsByStrategy = countsByStrategy;
        Unresolved = unresolved;
        UnresolvedCountsByReason = unresolvedCountsByReason;
    }

    public int FindingCount { get; }

    public int ResolvedCount { get; }

    public int UnresolvedCount => FindingCount - ResolvedCount;

    /// <summary>Each resolved finding once, under the identifier it resolved to. Sums to <see cref="ResolvedCount"/>.</summary>
    public IReadOnlyList<CountedName> DirectCountsByIdentifier { get; }

    /// <summary>
    /// Direct counts plus, for every sub-technique finding, one count under its parent. Does
    /// <b>not</b> sum to <see cref="ResolvedCount"/>; see the type remarks.
    /// </summary>
    public IReadOnlyList<CountedName> RolledUpCountsByIdentifier { get; }

    /// <summary>Each resolved finding once, under its entry's category. Sums to <see cref="ResolvedCount"/>.</summary>
    public IReadOnlyList<CountedName> DirectCountsByCategory { get; }

    /// <summary>
    /// Direct counts plus, for every sub-technique finding, one count under the parent's
    /// category. Does <b>not</b> sum to <see cref="ResolvedCount"/>; see the type remarks.
    /// </summary>
    public IReadOnlyList<CountedName> RolledUpCountsByCategory { get; }

    /// <summary>Distinct identifiers findings resolved to, sorted ordinally.</summary>
    public IReadOnlyList<string> IdentifiersSeen { get; }

    /// <summary><see cref="IdentifiersSeen"/> plus the parent of every sub-technique in it, sorted ordinally.</summary>
    public IReadOnlyList<string> IdentifiersSeenIncludingParents { get; }

    /// <summary>How many findings each strategy resolved, in chain order. Sums to <see cref="ResolvedCount"/>.</summary>
    public IReadOnlyList<StrategyCount> CountsByStrategy { get; }

    /// <summary>The unresolved findings, in input order, each with its reason. Never omitted.</summary>
    public IReadOnlyList<UnresolvedFinding> Unresolved { get; }

    /// <summary>Unresolved findings grouped by reason, in enum order. Sums to <see cref="UnresolvedCount"/>.</summary>
    public IReadOnlyList<UnresolvedReasonCount> UnresolvedCountsByReason { get; }

    public static TechniqueRollup Build(IReadOnlyList<FindingResolution> resolutions, TechniqueMap map)
    {
        ArgumentNullException.ThrowIfNull(resolutions);
        ArgumentNullException.ThrowIfNull(map);

        var directById = new Dictionary<string, int>(StringComparer.Ordinal);
        var rolledById = new Dictionary<string, int>(StringComparer.Ordinal);
        var directByCategory = new Dictionary<string, int>(StringComparer.Ordinal);
        var rolledByCategory = new Dictionary<string, int>(StringComparer.Ordinal);
        var byStrategy = new Dictionary<ResolutionStrategy, int>();
        var byReason = new Dictionary<UnresolvedReason, int>();
        var unresolved = new List<UnresolvedFinding>();
        var resolvedCount = 0;

        foreach (var resolution in resolutions)
        {
            if (resolution is UnresolvedFinding u)
            {
                unresolved.Add(u);
                Increment(byReason, u.Reason);
                continue;
            }

            var r = (ResolvedFinding)resolution;
            resolvedCount++;
            Increment(byStrategy, r.Strategy);

            var id = r.Entry.Identifier;
            Increment(directById, id.Value);
            Increment(rolledById, id.Value);
            Increment(directByCategory, r.Entry.Category);
            Increment(rolledByCategory, r.Entry.Category);

            if (id.IsSubTechnique)
            {
                // The loader guarantees the parent exists; the rollup rule depends on it.
                Increment(rolledById, id.ParentValue);
                if (map.TryGetEntry(id.ParentValue, out var parent))
                {
                    Increment(rolledByCategory, parent.Category);
                }
            }
        }

        return new TechniqueRollup(
            resolutions.Count,
            resolvedCount,
            Sorted(directById),
            Sorted(rolledById),
            Sorted(directByCategory),
            Sorted(rolledByCategory),
            SortedKeys(directById),
            SortedKeys(rolledById),
            Enum.GetValues<ResolutionStrategy>()
                .OrderBy(s => (int)s)
                .Select(s => new StrategyCount(s, byStrategy.GetValueOrDefault(s)))
                .ToList(),
            unresolved,
            Enum.GetValues<UnresolvedReason>()
                .OrderBy(s => (int)s)
                .Select(s => new UnresolvedReasonCount(s, byReason.GetValueOrDefault(s)))
                .ToList());
    }

    private static void Increment<TKey>(Dictionary<TKey, int> counts, TKey key) where TKey : notnull
    {
        counts[key] = counts.GetValueOrDefault(key) + 1;
    }

    // Ordinal, deliberately; see the type remarks.
    private static List<CountedName> Sorted(Dictionary<string, int> counts)
    {
        var list = counts.Select(kv => new CountedName(kv.Key, kv.Value)).ToList();
        list.Sort(static (a, b) => string.CompareOrdinal(a.Name, b.Name));
        return list;
    }

    private static List<string> SortedKeys(Dictionary<string, int> counts)
    {
        var list = counts.Keys.ToList();
        list.Sort(StringComparer.Ordinal);
        return list;
    }
}
