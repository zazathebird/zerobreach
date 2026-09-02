using Scythe.Rules.Linting.Json;

namespace Scythe.Rules.Linting;

/// <summary>One pattern entry with the position of its string literal in the file.</summary>
public sealed record RuleEntry(string Value, LintLocation Location);

/// <summary>A named set — either an indicator set or an allowlist. <paramref name="Entries"/>
/// holds the pattern strings the linter can check; <paramref name="ItemCount"/> counts the
/// JSON items the set carries, which is larger when a flat-shape set holds rule objects or
/// numbers that are not patterns. Emptiness is judged on the item count: a set of 22 port
/// numbers has no patterns but is not empty.</summary>
public sealed record RuleSet(string Name, LintLocation NameLocation, IReadOnlyList<RuleEntry> Entries, int ItemCount)
{
    public RuleSet(string name, LintLocation nameLocation, IReadOnlyList<RuleEntry> entries)
        : this(name, nameLocation, entries, entries.Count) { }
}

/// <summary>One target of a <c>references</c> declaration: <paramref name="Consumer"/> is
/// the host-side name doing the referencing (a phase or check), <paramref name="Target"/>
/// the set or allowlist name it names.</summary>
public sealed record RuleReference(string Consumer, RuleEntry Target);

/// <summary>
/// The BLUEPRINT §9 rule-file shape, position-annotated:
/// every top-level key whose value is an array of strings is an indicator set;
/// <c>fp_allowlists</c> maps allowlist names to arrays of regex entries;
/// <c>references</c> (optional) maps consumer names to the set/allowlist names they use,
/// and is what powers orphan/dangling analysis.
/// </summary>
public sealed class RuleFile
{
    public RuleFile(
        IReadOnlyList<RuleSet> indicatorSets,
        IReadOnlyList<RuleSet> allowlists,
        IReadOnlyList<RuleReference> references,
        bool hasReferenceKey)
    {
        IndicatorSets = indicatorSets;
        Allowlists = allowlists;
        References = references;
        HasReferenceKey = hasReferenceKey;
    }

    public IReadOnlyList<RuleSet> IndicatorSets { get; }
    public IReadOnlyList<RuleSet> Allowlists { get; }
    public IReadOnlyList<RuleReference> References { get; }

    /// <summary>True when the file declared a <c>references</c> key at all — even an empty
    /// one. Distinguishes "author opted in to reference tracking" from "no data".</summary>
    public bool HasReferenceKey { get; }
}

/// <summary>
/// Maps a parsed JSON tree onto <see cref="RuleFile"/>, emitting findings for every
/// structural violation. Malformed pieces are reported and excluded from the model —
/// but the findings already fail CI, so nothing malformed ever passes silently.
/// </summary>
public static class RuleFileReader
{
    /// <summary>Reserved top-level key holding the allowlists (BLUEPRINT §9).</summary>
    public const string AllowlistsKey = "fp_allowlists";

    /// <summary>Reserved top-level key holding reference declarations.</summary>
    public const string ReferencesKey = "references";

    /// <summary>Prefix of a flat-shape key whose string value is documentation, not a set.</summary>
    public const string CommentKeyPrefix = "_comment";

    public static RuleFile Read(JsonSourceValue root, string fileName, List<LintFinding> findings) =>
        Read(root, fileName, findings, LintOptions.Default);

    public static RuleFile Read(
        JsonSourceValue root, string fileName, List<LintFinding> findings, LintOptions options)
    {
        var indicatorSets = new List<RuleSet>();
        var allowlists = new List<RuleSet>();
        var references = new List<RuleReference>();
        bool hasReferenceKey = false;

        if (root is not JsonSourceObject rootObject)
        {
            findings.Add(new LintFinding(
                LintSeverity.Error, LintCode.SchemaViolation,
                "the rule file's top level must be a JSON object of named sets",
                fileName, root.Location));
            return new RuleFile(indicatorSets, allowlists, references, hasReferenceKey);
        }

        var seenTopLevel = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in rootObject.Properties)
        {
            if (!seenTopLevel.Add(property.Name))
            {
                // A duplicate key is a real hazard, not a style nit: whichever parser the
                // host uses will silently keep one of the two definitions.
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.DuplicateKey,
                    $"key \"{property.Name}\" appears more than once; the second definition would silently replace the first",
                    fileName, property.NameLocation, SetName: property.Name));
                continue; // first definition stays authoritative for the rest of the lint
            }

            switch (property.Name)
            {
                case AllowlistsKey:
                    ReadNamedSets(property, fileName, "allowlist", allowlists, findings);
                    break;
                case ReferencesKey:
                    hasReferenceKey = true;
                    ReadReferences(property, fileName, references, findings);
                    break;
                default:
                    var target = options.AllowlistNames.Contains(property.Name) ? allowlists : indicatorSets;
                    if (options.Shape == RuleFileShape.Flat)
                    {
                        ReadFlatSet(property, fileName, target, findings);
                    }
                    else
                    {
                        ReadIndicatorSet(property, fileName, target, findings);
                    }
                    break;
            }
        }

        return new RuleFile(indicatorSets, allowlists, references, hasReferenceKey);
    }

    private static void ReadIndicatorSet(
        JsonSourceProperty property, string fileName, List<RuleSet> sets, List<LintFinding> findings)
    {
        if (property.Value is not JsonSourceArray array)
        {
            findings.Add(new LintFinding(
                LintSeverity.Error, LintCode.SchemaViolation,
                $"indicator set \"{property.Name}\" must be an array of pattern strings",
                fileName, property.Value.Location, SetName: property.Name));
            return;
        }
        sets.Add(new RuleSet(property.Name, property.NameLocation,
            ReadEntries(array, property.Name, fileName, findings)));
    }

    /// <summary>
    /// The field-name convention that marks a regex inside a flat-shape rule object:
    /// <c>Pattern</c> / <c>pattern</c>, or a name ending in <c>Rx</c>, <c>Regex</c>,
    /// <c>regex</c> or <c>_rule</c>. Everything else in a rule object (names, severities,
    /// descriptions, registry paths, expanded-path lists, thresholds) is data the host reads
    /// literally, and linting it as a regex would report its own prose as a broken pattern.
    /// </summary>
    public static bool IsPatternField(string fieldName) =>
        fieldName is "Pattern" or "pattern" ||
        fieldName.EndsWith("Rx", StringComparison.Ordinal) ||
        fieldName.EndsWith("Regex", StringComparison.Ordinal) ||
        fieldName.EndsWith("regex", StringComparison.Ordinal) ||
        fieldName.EndsWith("_rule", StringComparison.Ordinal);

    private static void ReadFlatSet(
        JsonSourceProperty property, string fileName, List<RuleSet> sets, List<LintFinding> findings)
    {
        switch (property.Value)
        {
            case JsonSourceString when property.Name.StartsWith(CommentKeyPrefix, StringComparison.Ordinal):
                return; // documentation for the key after it; not a set

            case JsonSourceString s:
                // A single regex string ("c2_named_pipe_regex"): one entry, one item.
                sets.Add(new RuleSet(property.Name, property.NameLocation,
                    new[] { new RuleEntry(s.Value, s.Location) }, 1));
                return;

            case JsonSourceArray array:
            {
                var entries = new List<RuleEntry>();
                foreach (var item in array.Items)
                {
                    switch (item)
                    {
                        case JsonSourceString str:
                            entries.Add(new RuleEntry(str.Value, str.Location));
                            break;
                        case JsonSourceObject rule:
                            foreach (var field in rule.Properties)
                            {
                                if (field.Value is JsonSourceString fs && IsPatternField(field.Name))
                                {
                                    entries.Add(new RuleEntry(fs.Value, fs.Location));
                                }
                            }
                            break;
                        // Numbers (port lists), booleans, nulls and nested arrays carry no
                        // pattern; they count as items so the set is not reported empty.
                    }
                }
                sets.Add(new RuleSet(property.Name, property.NameLocation, entries, array.Items.Count));
                return;
            }

            case JsonSourceObject obj:
            {
                // A threshold/baseline object ("dbx_current_baseline"): declared, so a host
                // reference to it is not dangling; its regex-named string fields are linted.
                var entries = new List<RuleEntry>();
                foreach (var field in obj.Properties)
                {
                    if (field.Value is JsonSourceString fs && IsPatternField(field.Name))
                    {
                        entries.Add(new RuleEntry(fs.Value, fs.Location));
                    }
                }
                sets.Add(new RuleSet(property.Name, property.NameLocation, entries, obj.Properties.Count));
                return;
            }

            default:
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.SchemaViolation,
                    $"set \"{property.Name}\" is a bare {Describe(property.Value)}; a flat-shape set must be a string, an array or an object",
                    fileName, property.Value.Location, SetName: property.Name));
                return;
        }
    }

    private static string Describe(JsonSourceValue value) => value switch
    {
        JsonSourceNumber => "number",
        JsonSourceBoolean => "boolean",
        JsonSourceNull => "null",
        _ => value.GetType().Name,
    };

    private static void ReadNamedSets(
        JsonSourceProperty property, string fileName, string kind,
        List<RuleSet> sets, List<LintFinding> findings)
    {
        if (property.Value is not JsonSourceObject obj)
        {
            findings.Add(new LintFinding(
                LintSeverity.Error, LintCode.SchemaViolation,
                $"\"{property.Name}\" must be an object mapping {kind} names to arrays of pattern strings",
                fileName, property.Value.Location, SetName: property.Name));
            return;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var inner in obj.Properties)
        {
            if (!seen.Add(inner.Name))
            {
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.DuplicateKey,
                    $"{kind} \"{inner.Name}\" appears more than once inside \"{property.Name}\"; the second definition would silently replace the first",
                    fileName, inner.NameLocation, SetName: inner.Name));
                continue;
            }
            if (inner.Value is not JsonSourceArray array)
            {
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.SchemaViolation,
                    $"{kind} \"{inner.Name}\" must be an array of pattern strings",
                    fileName, inner.Value.Location, SetName: inner.Name));
                continue;
            }
            sets.Add(new RuleSet(inner.Name, inner.NameLocation,
                ReadEntries(array, inner.Name, fileName, findings)));
        }
    }

    private static void ReadReferences(
        JsonSourceProperty property, string fileName,
        List<RuleReference> references, List<LintFinding> findings)
    {
        if (property.Value is not JsonSourceObject obj)
        {
            findings.Add(new LintFinding(
                LintSeverity.Error, LintCode.SchemaViolation,
                $"\"{ReferencesKey}\" must be an object mapping consumer names to arrays of set names",
                fileName, property.Value.Location, SetName: ReferencesKey));
            return;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var consumer in obj.Properties)
        {
            if (!seen.Add(consumer.Name))
            {
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.DuplicateKey,
                    $"consumer \"{consumer.Name}\" appears more than once inside \"{ReferencesKey}\"",
                    fileName, consumer.NameLocation, SetName: consumer.Name));
                continue;
            }
            if (consumer.Value is not JsonSourceArray array)
            {
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.SchemaViolation,
                    $"reference list for \"{consumer.Name}\" must be an array of set names",
                    fileName, consumer.Value.Location, SetName: consumer.Name));
                continue;
            }
            foreach (var target in ReadEntries(array, consumer.Name, fileName, findings))
            {
                references.Add(new RuleReference(consumer.Name, target));
            }
        }
    }

    private static List<RuleEntry> ReadEntries(
        JsonSourceArray array, string setName, string fileName, List<LintFinding> findings)
    {
        var entries = new List<RuleEntry>(array.Items.Count);
        foreach (var item in array.Items)
        {
            if (item is JsonSourceString s)
            {
                entries.Add(new RuleEntry(s.Value, s.Location));
            }
            else
            {
                findings.Add(new LintFinding(
                    LintSeverity.Error, LintCode.SchemaViolation,
                    $"entry in \"{setName}\" must be a string",
                    fileName, item.Location, SetName: setName));
            }
        }
        return entries;
    }
}
