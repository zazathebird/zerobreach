using System.Diagnostics;

namespace Scythe.Techniques;

/// <summary>
/// Resolves findings to technique identifiers through the ordered chain in
/// reference/07.4_technique_map.md: explicit identifier, then the producing check's mapping,
/// then the keyword rules. The first strategy to produce an answer wins, and an identifier from
/// the first two strategies that is absent from the map does not fall through.
/// </summary>
public sealed class TechniqueResolver
{
    private readonly Dictionary<string, TechniqueIdentifier> _checkMappings;

    private TechniqueResolver(TechniqueMap map, Dictionary<string, TechniqueIdentifier> checkMappings)
    {
        Map = map;
        _checkMappings = checkMappings;
    }

    public TechniqueMap Map { get; }

    public int CheckMappingCount => _checkMappings.Count;

    /// <summary>
    /// Builds a resolver. Check mappings are validated for shape here — a malformed identifier
    /// or two disagreeing mappings for one check is a construction failure — but an identifier
    /// absent from the map is <em>not</em>: that surfaces per finding as
    /// <see cref="UnresolvedReason.CheckIdentifierAbsentFromMap"/>, which is exactly the signal
    /// that the map is older than the checks and needs updating.
    /// </summary>
    public static TechniqueResult<TechniqueResolver> Create(TechniqueMap map, IReadOnlyList<CheckMapping> checkMappings)
    {
        ArgumentNullException.ThrowIfNull(map);
        ArgumentNullException.ThrowIfNull(checkMappings);

        var byCheck = new Dictionary<string, TechniqueIdentifier>(StringComparer.Ordinal);
        for (var i = 0; i < checkMappings.Count; i++)
        {
            var mapping = checkMappings[i];
            if (mapping is null)
            {
                return TechniqueResult<TechniqueResolver>.Failed($"checkMappings[{i}] is null");
            }

            if (string.IsNullOrEmpty(mapping.CheckId))
            {
                return TechniqueResult<TechniqueResolver>.Failed($"checkMappings[{i}]: check id is missing or empty");
            }

            if (!TechniqueIdentifier.TryParse(mapping.Identifier, out var identifier, out var problem))
            {
                return TechniqueResult<TechniqueResolver>.Failed(
                    $"checkMappings[{i}] (check '{mapping.CheckId}'): identifier {problem}");
            }

            if (byCheck.TryGetValue(mapping.CheckId, out var existing))
            {
                if (existing.Value != identifier.Value)
                {
                    return TechniqueResult<TechniqueResolver>.Failed(
                        $"checkMappings[{i}] (check '{mapping.CheckId}'): declares {identifier.Value} but an earlier mapping declares {existing.Value}; one identifier per check");
                }

                continue;
            }

            byCheck.Add(mapping.CheckId, identifier);
        }

        return TechniqueResult<TechniqueResolver>.Ok(new TechniqueResolver(map, byCheck));
    }

    /// <summary>
    /// Resolves every finding in input order and rolls the results up. Cut short by the budget,
    /// the result is <see cref="TechniqueResultState.Incomplete"/> carrying the findings that
    /// were processed — never an <see cref="TechniqueResultState.Ok"/> with fewer results.
    /// </summary>
    public TechniqueResult<TechniqueRun> ResolveAll(IReadOnlyList<Finding> findings, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(findings);
        budget ??= ScanBudget.Default;
        var clock = Stopwatch.StartNew();

        var resolutions = new List<FindingResolution>(Math.Min(findings.Count, budget.MaxMatches));
        for (var i = 0; i < findings.Count; i++)
        {
            if (i >= budget.MaxMatches)
            {
                return TechniqueResult<TechniqueRun>.Incomplete(
                    new TechniqueRun(resolutions, TechniqueRollup.Build(resolutions, Map)),
                    $"run has {findings.Count} findings; budget allows {budget.MaxMatches}, and only those were resolved");
            }

            if (clock.Elapsed >= budget.Deadline)
            {
                return TechniqueResult<TechniqueRun>.Incomplete(
                    new TechniqueRun(resolutions, TechniqueRollup.Build(resolutions, Map)),
                    $"deadline of {budget.Deadline} reached at finding {i} of {findings.Count}; only the earlier findings were resolved");
            }

            var finding = findings[i];
            if (finding is null)
            {
                return TechniqueResult<TechniqueRun>.Failed($"findings[{i}] is null");
            }

            if (string.IsNullOrEmpty(finding.FindingId))
            {
                return TechniqueResult<TechniqueRun>.Failed($"findings[{i}]: finding id is missing or empty");
            }

            resolutions.Add(Resolve(finding));
        }

        return TechniqueResult<TechniqueRun>.Ok(new TechniqueRun(resolutions, TechniqueRollup.Build(resolutions, Map)));
    }

    /// <summary>Runs the chain for one finding. Pure; never throws for any finding content.</summary>
    public FindingResolution Resolve(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var attempts = new List<StrategyAttempt>(3);

        // 1. Explicit identifier. Present means it wins or the finding is unresolved; only
        //    absence lets the chain continue.
        if (finding.ExplicitIdentifier is not null)
        {
            if (!TechniqueIdentifier.TryParse(finding.ExplicitIdentifier, out var explicitId, out var problem))
            {
                attempts.Add(new StrategyAttempt(ResolutionStrategy.ExplicitIdentifier, $"explicit identifier {problem}"));
                return new UnresolvedFinding(
                    finding.FindingId,
                    UnresolvedReason.ExplicitIdentifierMalformed,
                    $"explicitly tagged with '{finding.ExplicitIdentifier}', which is not a well-formed identifier; not falling through to weaker strategies",
                    attempts);
            }

            if (Map.TryGetEntry(explicitId.Value, out var explicitEntry))
            {
                return new ResolvedFinding(finding.FindingId, explicitEntry, ResolutionStrategy.ExplicitIdentifier, null);
            }

            attempts.Add(new StrategyAttempt(ResolutionStrategy.ExplicitIdentifier, $"{explicitId.Value} is absent from the map"));
            return new UnresolvedFinding(
                finding.FindingId,
                UnresolvedReason.ExplicitIdentifierAbsentFromMap,
                $"explicitly tagged {explicitId.Value} but absent from the map; not falling through to weaker strategies",
                attempts);
        }

        attempts.Add(new StrategyAttempt(ResolutionStrategy.ExplicitIdentifier, "finding carries no explicit identifier"));

        // 2. The producing check's declared mapping. Same absence rule.
        if (string.IsNullOrEmpty(finding.CheckId))
        {
            attempts.Add(new StrategyAttempt(ResolutionStrategy.CheckMapping, "finding names no producing check"));
        }
        else if (!_checkMappings.TryGetValue(finding.CheckId, out var checkId))
        {
            attempts.Add(new StrategyAttempt(ResolutionStrategy.CheckMapping, $"check '{finding.CheckId}' declares no mapping"));
        }
        else if (Map.TryGetEntry(checkId.Value, out var checkEntry))
        {
            return new ResolvedFinding(finding.FindingId, checkEntry, ResolutionStrategy.CheckMapping, null);
        }
        else
        {
            attempts.Add(new StrategyAttempt(ResolutionStrategy.CheckMapping, $"check '{finding.CheckId}' declares {checkId.Value}, which is absent from the map"));
            return new UnresolvedFinding(
                finding.FindingId,
                UnresolvedReason.CheckIdentifierAbsentFromMap,
                $"check '{finding.CheckId}' declares {checkId.Value} but it is absent from the map; not falling through to keyword rules",
                attempts);
        }

        // 3. Keyword rules, in file order; first match wins. The description is never scanned
        //    for identifier-shaped text — "T1234" in a sentence is a word, not a tag.
        if (finding.Description is null)
        {
            attempts.Add(new StrategyAttempt(ResolutionStrategy.KeywordRule, "finding has no description"));
        }
        else if (Map.Rules.Count == 0)
        {
            attempts.Add(new StrategyAttempt(ResolutionStrategy.KeywordRule, "map declares no keyword rules"));
        }
        else
        {
            foreach (var rule in Map.Rules)
            {
                if (rule.Matches(finding.Description))
                {
                    // The loader guarantees every rule's identifier is in the map.
                    Map.TryGetEntry(rule.Identifier.Value, out var ruleEntry);
                    return new ResolvedFinding(finding.FindingId, ruleEntry, ResolutionStrategy.KeywordRule, rule.Ordinal);
                }
            }

            attempts.Add(new StrategyAttempt(ResolutionStrategy.KeywordRule, $"none of the {Map.Rules.Count} keyword rules matched the description"));
        }

        var declined = string.Join("; ", attempts.Select(a => $"{a.Strategy}: {a.Declined}"));
        return new UnresolvedFinding(
            finding.FindingId,
            UnresolvedReason.NoStrategyProduced,
            $"no strategy produced an identifier ({declined})",
            attempts);
    }
}
