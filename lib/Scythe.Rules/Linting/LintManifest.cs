using Scythe.Rules.Linting.Json;

namespace Scythe.Rules.Linting;

/// <summary>
/// What the host tells the linter about itself. None of it is derivable from the rule file
/// alone: a flat file carries no positional cue for "allowlist", and only the host knows
/// whether it escapes an entry before matching, expands it as a path, or treats it as a
/// glob. The object form:
/// <code>
/// { "shape": "flat" | "nested",
///   "consumed": [...],            set names the host reads (orphan/dangling analysis)
///   "allowlists": [...],          sets that suppress detections (count as consumed)
///   "literal_sets": [...],        matched as escaped substrings
///   "equality_sets": [...],       compared as whole values (-contains, -in, Test-Path)
///   "wildcard_sets": [...],       -like globs the host anchors and translates
///   "reference_sets": [...],      legitimate names by design; no collision/length checks
///   "substring_allowlists": [...], path-shaped allowlists held to component anchoring
///   "accepted_collisions": [ { "set": "...", "entry": "...", "why": "..." } ] }
/// </code>
/// The original form, a bare JSON array, is the <c>consumed</c> list alone. Every key is
/// optional; <c>_comment*</c> keys are documentation; any other unknown key is refused so a
/// typo cannot quietly disable the section it was meant to fill.
/// </summary>
public sealed record LintManifest(
    RuleFileShape? Shape,
    IReadOnlyList<string> Consumed,
    IReadOnlyList<string> Allowlists,
    IReadOnlyList<string> LiteralSets,
    IReadOnlyList<string> EqualitySets,
    IReadOnlyList<string> WildcardSets,
    IReadOnlyList<string> ReferenceSets,
    IReadOnlyList<string> SubstringAllowlists,
    IReadOnlyList<AcceptedCollision> AcceptedCollisions)
{
    public static LintManifest Empty { get; } = new(
        null, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(),
        Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(),
        Array.Empty<AcceptedCollision>());

    /// <summary>Merges this manifest onto <paramref name="options"/>: lists are unioned,
    /// the shape is applied only when the manifest states one.</summary>
    public LintOptions Apply(LintOptions options)
    {
        var consumed = new List<string>(options.ExternalReferences);
        foreach (var name in Consumed.Concat(Allowlists))
        {
            if (!consumed.Contains(name, StringComparer.Ordinal))
            {
                consumed.Add(name);
            }
        }

        var accepted = new List<AcceptedCollision>(options.AcceptedCollisions);
        accepted.AddRange(AcceptedCollisions);

        return options with
        {
            Shape = Shape ?? options.Shape,
            ExternalReferences = consumed,
            AllowlistNames = Union(options.AllowlistNames, Allowlists),
            LiteralSets = Union(options.LiteralSets, LiteralSets),
            EqualitySets = Union(options.EqualitySets, EqualitySets),
            WildcardSets = Union(options.WildcardSets, WildcardSets),
            ReferenceSets = Union(options.ReferenceSets, ReferenceSets),
            SubstringAllowlists = Union(options.SubstringAllowlists, SubstringAllowlists),
            AcceptedCollisions = accepted,
        };
    }

    private static HashSet<string> Union(IEnumerable<string> a, IEnumerable<string> b)
    {
        var set = new HashSet<string>(a, StringComparer.Ordinal);
        set.UnionWith(b);
        return set;
    }

    /// <summary>Parses manifest text. Returns null and writes the reason to
    /// <paramref name="error"/> on any problem — an unreadable manifest must not lint as
    /// "no manifest".</summary>
    public static LintManifest? Parse(string text, string path, TextWriter error)
    {
        var parse = JsonSourceParser.Parse(text);
        if (parse.State != OperationState.Ok)
        {
            error.WriteLine(
                $"error: manifest '{path}' is not valid JSON " +
                $"({parse.ErrorLocation.Line},{parse.ErrorLocation.Column}): {parse.Message}");
            return null;
        }

        if (parse.Root is JsonSourceArray legacy)
        {
            return ReadNames(legacy, "manifest", path, error) is { } names
                ? Empty with { Consumed = names }
                : null;
        }

        if (parse.Root is not JsonSourceObject obj)
        {
            error.WriteLine($"error: manifest '{path}' must be a JSON array of set names or an object (shape, consumed, allowlists, literal_sets, equality_sets, wildcard_sets, reference_sets, substring_allowlists, accepted_collisions)");
            return null;
        }

        var manifest = Empty;
        foreach (var property in obj.Properties)
        {
            if (property.Name.StartsWith(RuleFileReader.CommentKeyPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            if (property.Name == "shape")
            {
                if (property.Value is not JsonSourceString shapeText ||
                    TryParseShape(shapeText.Value) is not { } shape)
                {
                    error.WriteLine($"error: manifest '{path}' 'shape' must be \"flat\" or \"nested\"");
                    return null;
                }
                manifest = manifest with { Shape = shape };
                continue;
            }

            if (property.Name == "accepted_collisions")
            {
                if (property.Value is not JsonSourceArray list ||
                    ReadAcceptedCollisions(list, path, error) is not { } accepted)
                {
                    if (property.Value is not JsonSourceArray)
                    {
                        error.WriteLine($"error: manifest '{path}' 'accepted_collisions' must be an array of {{ set, entry, why }} objects");
                    }
                    return null;
                }
                manifest = manifest with { AcceptedCollisions = accepted };
                continue;
            }

            if (property.Name is "consumed" or "allowlists" or "literal_sets" or "equality_sets"
                or "wildcard_sets" or "reference_sets" or "substring_allowlists")
            {
                if (property.Value is not JsonSourceArray array)
                {
                    error.WriteLine($"error: manifest '{path}' '{property.Name}' must be an array of set names");
                    return null;
                }
                if (ReadNames(array, property.Name, path, error) is not { } names)
                {
                    return null;
                }
                manifest = property.Name switch
                {
                    "consumed" => manifest with { Consumed = names },
                    "allowlists" => manifest with { Allowlists = names },
                    "literal_sets" => manifest with { LiteralSets = names },
                    "equality_sets" => manifest with { EqualitySets = names },
                    "wildcard_sets" => manifest with { WildcardSets = names },
                    "reference_sets" => manifest with { ReferenceSets = names },
                    _ => manifest with { SubstringAllowlists = names },
                };
                continue;
            }

            error.WriteLine($"error: manifest '{path}' has an unknown key '{property.Name}' (expected shape, consumed, allowlists, literal_sets, equality_sets, wildcard_sets, reference_sets, substring_allowlists, accepted_collisions)");
            return null;
        }

        return manifest;
    }

    private static RuleFileShape? TryParseShape(string text) => text switch
    {
        "flat" => RuleFileShape.Flat,
        "nested" => RuleFileShape.Nested,
        _ => null,
    };

    private static IReadOnlyList<string>? ReadNames(
        JsonSourceArray array, string what, string path, TextWriter error)
    {
        var names = new List<string>(array.Items.Count);
        foreach (var item in array.Items)
        {
            if (item is not JsonSourceString s)
            {
                error.WriteLine(
                    $"error: manifest '{path}' {what} entry at ({item.Location.Line},{item.Location.Column}) is not a string");
                return null;
            }
            names.Add(s.Value);
        }
        return names;
    }

    private static IReadOnlyList<AcceptedCollision>? ReadAcceptedCollisions(
        JsonSourceArray array, string path, TextWriter error)
    {
        var accepted = new List<AcceptedCollision>(array.Items.Count);
        foreach (var item in array.Items)
        {
            if (item is not JsonSourceObject obj)
            {
                error.WriteLine($"error: manifest '{path}' accepted_collisions entry at ({item.Location.Line},{item.Location.Column}) is not an object");
                return null;
            }
            string? set = null, entry = null, why = null;
            foreach (var field in obj.Properties)
            {
                if (field.Value is not JsonSourceString s)
                {
                    error.WriteLine($"error: manifest '{path}' accepted_collisions field '{field.Name}' at ({field.Value.Location.Line},{field.Value.Location.Column}) is not a string");
                    return null;
                }
                switch (field.Name)
                {
                    case "set": set = s.Value; break;
                    case "entry": entry = s.Value; break;
                    case "why": why = s.Value; break;
                    default:
                        error.WriteLine($"error: manifest '{path}' accepted_collisions has an unknown field '{field.Name}' (expected set, entry, why)");
                        return null;
                }
            }
            if (set is null || entry is null || string.IsNullOrWhiteSpace(why))
            {
                error.WriteLine($"error: manifest '{path}' accepted_collisions entry at ({item.Location.Line},{item.Location.Column}) needs set, entry and a non-empty why — an accepted collision without a reason is a suppression");
                return null;
            }
            accepted.Add(new AcceptedCollision(set, entry, why));
        }
        return accepted;
    }
}
