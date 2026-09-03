using System.Diagnostics;

namespace Scythe.Correlation;

/// <summary>
/// Turns the findings of one run record into chains: connected components of the graph whose
/// vertices are findings and whose edges are shared entities, after the common-noun cap has
/// removed over-referenced entities (reference/07.1_linking.md, "Chains" and "The common-noun
/// threshold").
/// </summary>
/// <remarks>
/// Grouping is on entities and only on entities. <see cref="FindingReference.Anchor"/> is read in
/// exactly one place — first-finding nomination — and never to decide membership; see
/// reference/07_records.md rule 1 for why a time-window grouping would fuse every run into one chain.
/// </remarks>
public static class ChainBuilder
{
    /// <summary>
    /// An entity referenced by more distinct findings than this is a common noun, not a link.
    /// </summary>
    /// <remarks>
    /// The shell interpreter's path, the scripting host, the temp directory and the startup registry
    /// keys are named by dozens of unrelated checks; because grouping is transitive across shared
    /// entities, one uncapped common noun fuses the whole run into a single chain. At exactly this
    /// many findings an entity still links them; at one more it links nothing.
    /// <para>
    /// <b>Provisional.</b> No real run records exist yet (reference/07.5_unverifiable.md), so ten is
    /// an estimate — a small double-digit figure — not a measurement. It should be set from a
    /// census over real records: how many findings a typical run produces and how often each entity
    /// recurs; when that is done, this comment should say which fleet's runs it came from. It is an
    /// absolute count rather than a fraction of the run's findings because an absolute count is
    /// easier to reason about and to test on both sides; the fraction alternative is worth revisiting
    /// if runs of 20 and 2 000 findings turn out to need different behaviour. It is deliberately
    /// not configurable through the API: a caller who can raise it can set it to infinity and
    /// reintroduce the failure it exists to prevent.
    /// </para>
    /// </remarks>
    public const int CommonNounThreshold = 10;

    /// <summary>
    /// Assembles chains from the findings of <b>one</b> run record.
    /// </summary>
    /// <returns>
    /// <see cref="CorrelationResultState.Failed"/> for a null list, a null element, a missing id or a
    /// duplicate id (position = the offending index); <see cref="CorrelationResultState.Incomplete"/>
    /// when the budget's byte, match or deadline ceiling is hit — never a partial chain set.
    /// </returns>
    public static CorrelationResult<CorrelationOutput> Build(IReadOnlyList<FindingReference>? findings, ScanBudget? budget = null)
    {
        budget ??= ScanBudget.Default;
        if (findings is null) return CorrelationResult<CorrelationOutput>.Failed("findings list is null");

        var stopwatch = Stopwatch.StartNew();

        // Validate ids and measure the input before touching any text.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        long inputBytes = 0;
        for (var i = 0; i < findings.Count; i++)
        {
            var finding = findings[i];
            if (finding is null) return CorrelationResult<CorrelationOutput>.Failed($"finding at index {i} is null", i);
            if (string.IsNullOrEmpty(finding.Id)) return CorrelationResult<CorrelationOutput>.Failed($"finding at index {i} has no id", i);
            if (!seen.Add(finding.Id))
            {
                return CorrelationResult<CorrelationOutput>.Failed($"finding id '{finding.Id}' occurs more than once (second at index {i})", i);
            }

            inputBytes += 2L * ((finding.Description?.Length ?? 0) + (finding.Target?.Value?.Length ?? 0));
        }

        if (inputBytes > budget.MaxInputBytes)
        {
            return CorrelationResult<CorrelationOutput>.Incomplete(
                null, $"descriptions and targets total {inputBytes} bytes; budget allows {budget.MaxInputBytes}");
        }

        // Work in id order from here on, so nothing downstream can depend on arrival order.
        var ordered = findings.OrderBy(f => f.Id, StringComparer.Ordinal).ToArray();
        var indexOf = new Dictionary<string, int>(ordered.Length, StringComparer.Ordinal);
        for (var i = 0; i < ordered.Length; i++) indexOf[ordered[i].Id] = i;

        // Census: entity -> referencing finding indices, plus the ordinal-smallest spelling seen.
        var census = new Dictionary<Entity, (SortedSet<int> Findings, string Spelling)>();
        var rejected = new List<RejectedTarget>();
        var remainingMatches = budget.MaxMatches;
        var mentions = new List<EntityMention>();

        for (var i = 0; i < ordered.Length; i++)
        {
            var finding = ordered[i];
            if (stopwatch.Elapsed > budget.Deadline)
            {
                return CorrelationResult<CorrelationOutput>.Incomplete(
                    null, $"deadline of {budget.Deadline.TotalMilliseconds:0} ms exceeded after {i} of {ordered.Length} findings");
            }

            if (finding.Target is not null)
            {
                var target = EntityNormaliser.Normalise(finding.Target.Kind, finding.Target.Value);
                if (target.IsOk)
                {
                    if (remainingMatches <= 0) return MatchesExhausted(budget);
                    remainingMatches--;
                    Record(census, target.Value!, i);
                }
                else
                {
                    rejected.Add(new RejectedTarget(finding.Id, finding.Target.Kind, finding.Target.Value ?? "", target.Reason ?? "did not normalise"));
                }
            }

            if (!string.IsNullOrEmpty(finding.Description))
            {
                mentions.Clear();
                var stop = EntityExtractor.ExtractInto(finding.Description, budget, stopwatch, remainingMatches, mentions);
                if (stop is not null) return CorrelationResult<CorrelationOutput>.Incomplete(null, $"finding '{finding.Id}': {stop}");
                remainingMatches -= mentions.Count;
                foreach (var mention in mentions) Record(census, mention.Entity, i);
            }
        }

        // Classify the whole census before drawing any edge: the cap is a property of the run.
        var entries = new List<(Entity Entity, SortedSet<int> Findings, EntityReferenceClass Class)>(census.Count);
        foreach (var (entity, (refs, spelling)) in census)
        {
            var reported = new Entity(entity.Kind, spelling);
            var cls = refs.Count == 1 ? EntityReferenceClass.Single
                : refs.Count <= CommonNounThreshold ? EntityReferenceClass.Shared
                : EntityReferenceClass.CommonNoun;
            entries.Add((reported, refs, cls));
        }

        entries.Sort((a, b) => Entity.Ordering.Compare(a.Entity, b.Entity));

        // Connected components over the Shared entities only.
        var parent = new int[ordered.Length];
        for (var i = 0; i < parent.Length; i++) parent[i] = i;
        foreach (var (_, refs, cls) in entries)
        {
            if (cls != EntityReferenceClass.Shared) continue;
            var first = -1;
            foreach (var index in refs)
            {
                if (first < 0) first = index;
                else Union(parent, first, index);
            }
        }

        var members = new Dictionary<int, List<int>>();
        for (var i = 0; i < ordered.Length; i++)
        {
            var root = Find(parent, i);
            if (!members.TryGetValue(root, out var list)) members[root] = list = [];
            list.Add(i);
        }

        var chains = new List<Chain>();
        var unchained = new List<string>();
        foreach (var (root, list) in members)
        {
            if (list.Count < 2)
            {
                unchained.Add(ordered[list[0]].Id);
                continue;
            }

            // list is already in ascending index order, which is ascending ordinal id order.
            var joining = new List<Entity>();
            foreach (var (entity, refs, cls) in entries)
            {
                if (cls == EntityReferenceClass.Shared && Find(parent, refs.Min) == root) joining.Add(entity);
            }

            var first = list[0];
            for (var k = 1; k < list.Count; k++)
            {
                if (NominationOrder(ordered[list[k]], ordered[first]) < 0) first = list[k];
            }

            chains.Add(new Chain(ordered[first].Id, list.Select(i => ordered[i].Id).ToArray(), joining));
        }

        chains.Sort((a, b) => string.CompareOrdinal(a.FirstFindingId, b.FirstFindingId));
        unchained.Sort(StringComparer.Ordinal);
        rejected.Sort((a, b) => string.CompareOrdinal(a.FindingId, b.FindingId));

        var censusOut = entries
            .Select(e => new EntityCensusEntry(e.Entity, e.Findings.Select(i => ordered[i].Id).ToArray(), e.Class))
            .ToArray();

        return CorrelationResult<CorrelationOutput>.Ok(new CorrelationOutput(chains, unchained, censusOut, rejected));
    }

    /// <summary>
    /// The nomination order: earliest anchor first, anchored before unanchored, then ordinal id.
    /// Anchors compare by instant, so two spellings of one moment in different offsets are equal.
    /// </summary>
    public static int NominationOrder(FindingReference a, FindingReference b)
    {
        if (a.Anchor.HasValue && b.Anchor.HasValue)
        {
            var byAnchor = a.Anchor.Value.CompareTo(b.Anchor.Value);
            if (byAnchor != 0) return byAnchor;
        }
        else if (a.Anchor.HasValue) return -1;
        else if (b.Anchor.HasValue) return 1;

        return string.CompareOrdinal(a.Id, b.Id);
    }

    private static CorrelationResult<CorrelationOutput> MatchesExhausted(ScanBudget budget) =>
        CorrelationResult<CorrelationOutput>.Incomplete(null, $"more than {budget.MaxMatches} entity mentions; budget allows {budget.MaxMatches}");

    private static void Record(Dictionary<Entity, (SortedSet<int> Findings, string Spelling)> census, Entity entity, int finding)
    {
        if (census.TryGetValue(entity, out var existing))
        {
            existing.Findings.Add(finding);
            if (string.CompareOrdinal(entity.Value, existing.Spelling) < 0) census[entity] = (existing.Findings, entity.Value);
        }
        else
        {
            census[entity] = (new SortedSet<int> { finding }, entity.Value);
        }
    }

    private static int Find(int[] parent, int i)
    {
        while (parent[i] != i)
        {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }

        return i;
    }

    private static void Union(int[] parent, int a, int b)
    {
        var ra = Find(parent, a);
        var rb = Find(parent, b);
        if (ra == rb) return;
        // Attach the larger root index under the smaller so the representative is the
        // ordinal-smallest member — not required for correctness, but it keeps traversal
        // independent of edge order.
        if (ra < rb) parent[rb] = ra;
        else parent[ra] = rb;
    }
}
