using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Scythe.Techniques;

/// <summary>
/// Loads and strictly validates a technique reference map (reference/07.4_technique_map.md).
/// </summary>
/// <remarks>
/// <para>The file is a UTF-8 JSON object with two fields:</para>
/// <code>
/// {
///   "entries": [ { "id": "T1234", "name": "...", "category": "...", "url": "https://..." }, ... ],
///   "rules":   [ { "keyword": "...", "id": "T1234" }, ... ]
/// }
/// </code>
/// <para><c>entries</c> is required (an empty array is a valid, empty map). <c>rules</c> is
/// optional and defaults to no rules. Every other field, at any level, is a load failure: an
/// unknown field means the file was written against a different schema and something in it is
/// being dropped. Nothing is trimmed, nothing is case-folded, and nothing is fetched — the URL
/// check is a string check.</para>
/// </remarks>
public static class TechniqueMapLoader
{
    /// <summary>A keyword shorter than this cannot be specific enough to be a rule.</summary>
    public const int MinimumKeywordLength = 4;

    /// <summary>Ceiling on the length of any single string field, in UTF-16 code units.</summary>
    public const int MaxFieldLength = 4096;

    /// <summary>
    /// Deliberately generic descriptions. A keyword rule that matches any of these would match a
    /// large share of an ordinary run and resolve it all to one identifier, which looks like
    /// success and is not. Checked at load, so the rule is rejected where it is curated rather
    /// than discovered as a skewed census.
    /// </summary>
    public static readonly IReadOnlyList<string> KeywordRuleCanaries = new[]
    {
        "The value was found on the system.",
        "A file was created in the user directory.",
        "The process could not be read.",
        "An entry is present in the record.",
        "Data was written to the path.",
        "The service name and the account name were checked.",
        "The registry key holds a default setting.",
        "A network address appears in the log.",
    };

    private const string EntriesField = "entries";
    private const string RulesField = "rules";
    private const string IdField = "id";
    private const string NameField = "name";
    private const string CategoryField = "category";
    private const string UrlField = "url";
    private const string KeywordField = "keyword";

    /// <summary>Convenience overload for a map already held as text; encodes as UTF-8.</summary>
    public static TechniqueResult<TechniqueMap> Load(string json, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(json);
        return Load(Encoding.UTF8.GetBytes(json), budget);
    }

    public static TechniqueResult<TechniqueMap> Load(ReadOnlyMemory<byte> json, ScanBudget? budget = null)
    {
        budget ??= ScanBudget.Default;
        var clock = Stopwatch.StartNew();

        if (json.Length > budget.MaxInputBytes)
        {
            return TechniqueResult<TechniqueMap>.Incomplete(
                null,
                $"map file is {json.Length} bytes; budget allows {budget.MaxInputBytes}");
        }

        // A UTF-8 byte order mark is not JSON, and the reader rejects it, but a map file saved
        // from an editor on Windows will carry one. Skip it; positions stay file-relative.
        var bomLength = HasUtf8Bom(json.Span) ? Utf8Bom.Length : 0;
        json = json[bomLength..];

        // Pass one: a token walk with the reader, so a depth overrun (a budget) can be told
        // apart from a syntax error (malformed input) and so a syntax error carries the byte
        // offset it happened at. JsonDocument reports neither cleanly.
        var syntax = CheckSyntax(json.Span, budget, bomLength);
        if (syntax is not null)
        {
            return syntax;
        }

        using var document = ParseDocument(json, budget);
        if (document is null)
        {
            // Pass one accepted the bytes, so this cannot happen; refuse rather than throw.
            return TechniqueResult<TechniqueMap>.Failed("map file could not be parsed as JSON");
        }

        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return TechniqueResult<TechniqueMap>.Failed(
                $"map file root is a JSON {Describe(root.ValueKind)}; expected an object with '{EntriesField}' and optional '{RulesField}'");
        }

        JsonElement? entriesElement = null;
        JsonElement? rulesElement = null;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                return TechniqueResult<TechniqueMap>.Failed($"map file root: field '{property.Name}' appears twice");
            }

            switch (property.Name)
            {
                case EntriesField:
                    entriesElement = property.Value;
                    break;
                case RulesField:
                    rulesElement = property.Value;
                    break;
                default:
                    return TechniqueResult<TechniqueMap>.Failed(
                        $"map file root: unknown field '{property.Name}'; the file was written against a different schema");
            }
        }

        if (entriesElement is null)
        {
            return TechniqueResult<TechniqueMap>.Failed($"map file root: required field '{EntriesField}' is missing");
        }

        var entriesResult = ReadEntries(entriesElement.Value, budget, clock, out var entries);
        if (entriesResult is not null)
        {
            return entriesResult;
        }

        var rulesResult = ReadRules(rulesElement, entries, budget, clock, out var rules);
        if (rulesResult is not null)
        {
            return rulesResult;
        }

        var sorted = entries.Values.ToList();
        // Ordinal on the identifier string. For this format that is also numeric order,
        // because every digit field is fixed-width and zero-padded. Not culture-sensitive.
        sorted.Sort(static (a, b) => string.CompareOrdinal(a.Identifier.Value, b.Identifier.Value));

        return TechniqueResult<TechniqueMap>.Ok(new TechniqueMap(sorted, rules));
    }

    private static ReadOnlySpan<byte> Utf8Bom => [0xEF, 0xBB, 0xBF];

    private static bool HasUtf8Bom(ReadOnlySpan<byte> bytes) => bytes.StartsWith(Utf8Bom);

    private static TechniqueResult<TechniqueMap>? CheckSyntax(ReadOnlySpan<byte> bytes, ScanBudget budget, int baseOffset)
    {
        if (IsEmptyOrJsonWhitespace(bytes))
        {
            return TechniqueResult<TechniqueMap>.Failed("map file is empty", baseOffset);
        }

        // The JSON reader validates UTF-8 only when a string is materialised, which would turn
        // a bad byte in a name into an exception deep inside the schema walk. Check the whole
        // input first, and say where the first bad byte is.
        var badUtf8 = FirstInvalidUtf8Offset(bytes);
        if (badUtf8 >= 0)
        {
            var at = baseOffset + badUtf8;
            return TechniqueResult<TechniqueMap>.Failed($"map file is not valid UTF-8 at offset 0x{at:X}", at);
        }

        // The reader's own MaxDepth is set one past the budget so that the budget check below
        // fires first, on the token that crossed the line, and the catch is left with syntax
        // errors only.
        var options = new JsonReaderOptions
        {
            MaxDepth = budget.MaxNestingDepth + 1,
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
        };
        var reader = new Utf8JsonReader(bytes, isFinalBlock: true, new JsonReaderState(options));

        try
        {
            while (reader.Read())
            {
                // CurrentDepth reports a Start token at its parent's depth; the reader's own
                // limit counts the container being opened. Use the latter so the budget means
                // "containers open at once", the same thing the reader's MaxDepth means.
                var depth = reader.CurrentDepth
                    + (reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray ? 1 : 0);
                if (depth > budget.MaxNestingDepth)
                {
                    return TechniqueResult<TechniqueMap>.Incomplete(
                        null,
                        $"map file nests deeper than the budget's {budget.MaxNestingDepth} levels at offset 0x{baseOffset + reader.TokenStartIndex:X}");
                }
            }
        }
        catch (JsonException ex)
        {
            var position = baseOffset + reader.BytesConsumed;
            return TechniqueResult<TechniqueMap>.Failed(
                $"map file is not well-formed JSON at offset 0x{position:X}: {FirstLine(ex.Message)}",
                position);
        }

        return null;
    }

    private static bool IsEmptyOrJsonWhitespace(ReadOnlySpan<byte> bytes)
    {
        foreach (var b in bytes)
        {
            if (b is not ((byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r'))
            {
                return false;
            }
        }

        return true;
    }

    private static int FirstInvalidUtf8Offset(ReadOnlySpan<byte> bytes)
    {
        var offset = 0;
        while (offset < bytes.Length)
        {
            var status = System.Text.Rune.DecodeFromUtf8(bytes[offset..], out _, out var consumed);
            if (status != System.Buffers.OperationStatus.Done)
            {
                return offset;
            }

            offset += consumed;
        }

        return -1;
    }

    private static JsonDocument? ParseDocument(ReadOnlyMemory<byte> json, ScanBudget budget)
    {
        var options = new JsonDocumentOptions
        {
            MaxDepth = budget.MaxNestingDepth + 1,
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
        };

        try
        {
            return JsonDocument.Parse(json, options);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static TechniqueResult<TechniqueMap>? ReadEntries(
        JsonElement element,
        ScanBudget budget,
        Stopwatch clock,
        out Dictionary<string, TechniqueEntry> entries)
    {
        entries = new Dictionary<string, TechniqueEntry>(StringComparer.Ordinal);

        if (element.ValueKind != JsonValueKind.Array)
        {
            return TechniqueResult<TechniqueMap>.Failed(
                $"'{EntriesField}' is a JSON {Describe(element.ValueKind)}; expected an array");
        }

        var count = element.GetArrayLength();
        if (count > budget.MaxMatches)
        {
            return TechniqueResult<TechniqueMap>.Incomplete(
                null,
                $"map declares {count} entries; budget allows {budget.MaxMatches}");
        }

        // Two entries that differ only in case are duplicates by the reference's rule. The
        // format check already rejects lower case, so this comparer is belt-and-braces: it
        // keeps the rule true even if the format check is ever relaxed.
        var seenFolded = new Dictionary<string, (int Index, string Value)>(StringComparer.OrdinalIgnoreCase);

        var index = 0;
        foreach (var item in element.EnumerateArray())
        {
            if (clock.Elapsed >= budget.Deadline)
            {
                return TechniqueResult<TechniqueMap>.Incomplete(
                    null,
                    $"deadline of {budget.Deadline} reached while reading {EntriesField}[{index}]");
            }

            var where = $"{EntriesField}[{index}]";
            var problem = ReadEntry(item, where, out var entry);
            if (problem is not null)
            {
                return TechniqueResult<TechniqueMap>.Failed(problem);
            }

            if (seenFolded.TryGetValue(entry.Identifier.Value, out var first))
            {
                return TechniqueResult<TechniqueMap>.Failed(
                    $"{where} ({entry.Identifier.Value}): duplicate of {EntriesField}[{first.Index}] ({first.Value})");
            }

            seenFolded.Add(entry.Identifier.Value, (index, entry.Identifier.Value));
            entries.Add(entry.Identifier.Value, entry);
            index++;
        }

        // Parents are checked after the whole array is read: a parent may legitimately be
        // listed after its sub-techniques.
        index = 0;
        foreach (var entry in entries.Values)
        {
            if (entry.Identifier.IsSubTechnique && !entries.ContainsKey(entry.Identifier.ParentValue))
            {
                return TechniqueResult<TechniqueMap>.Failed(
                    $"{EntriesField}[{index}] ({entry.Identifier.Value}): sub-technique's parent {entry.Identifier.ParentValue} is absent from the map; the rollup requires the parent to exist");
            }

            index++;
        }

        return null;
    }

    private static string? ReadEntry(JsonElement item, string where, out TechniqueEntry entry)
    {
        entry = null!;

        if (item.ValueKind != JsonValueKind.Object)
        {
            return $"{where}: is a JSON {Describe(item.ValueKind)}; expected an object";
        }

        string? id = null, name = null, category = null, url = null;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in item.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                return $"{where}: field '{property.Name}' appears twice";
            }

            switch (property.Name)
            {
                case IdField:
                    if (!TryString(property, where, out id, out var idProblem)) return idProblem;
                    break;
                case NameField:
                    if (!TryString(property, where, out name, out var nameProblem)) return nameProblem;
                    break;
                case CategoryField:
                    if (!TryString(property, where, out category, out var categoryProblem)) return categoryProblem;
                    break;
                case UrlField:
                    if (!TryString(property, where, out url, out var urlProblem)) return urlProblem;
                    break;
                default:
                    return $"{where}{Label(id)}: unknown field '{property.Name}'; the file was written against a different schema";
            }
        }

        if (id is null)
        {
            return $"{where}: required field '{IdField}' is missing";
        }

        if (!TechniqueIdentifier.TryParse(id, out var identifier, out var problem))
        {
            return $"{where}: identifier {problem}";
        }

        var tag = $"{where} ({identifier.Value})";

        var nameProblemText = CheckText(name, NameField, tag);
        if (nameProblemText is not null) return nameProblemText;

        var categoryProblemText = CheckText(category, CategoryField, tag);
        if (categoryProblemText is not null) return categoryProblemText;

        var urlProblemText = CheckText(url, UrlField, tag) ?? CheckUrl(url!, tag);
        if (urlProblemText is not null) return urlProblemText;

        entry = new TechniqueEntry(identifier, name!, category!, url!);
        return null;
    }

    private static TechniqueResult<TechniqueMap>? ReadRules(
        JsonElement? element,
        Dictionary<string, TechniqueEntry> entries,
        ScanBudget budget,
        Stopwatch clock,
        out List<KeywordRule> rules)
    {
        rules = new List<KeywordRule>();

        if (element is null)
        {
            return null;
        }

        if (element.Value.ValueKind != JsonValueKind.Array)
        {
            return TechniqueResult<TechniqueMap>.Failed(
                $"'{RulesField}' is a JSON {Describe(element.Value.ValueKind)}; expected an array");
        }

        var count = element.Value.GetArrayLength();
        if (count > budget.MaxMatches)
        {
            return TechniqueResult<TechniqueMap>.Incomplete(
                null,
                $"map declares {count} keyword rules; budget allows {budget.MaxMatches}");
        }

        var index = 0;
        foreach (var item in element.Value.EnumerateArray())
        {
            if (clock.Elapsed >= budget.Deadline)
            {
                return TechniqueResult<TechniqueMap>.Incomplete(
                    null,
                    $"deadline of {budget.Deadline} reached while reading {RulesField}[{index}]");
            }

            var where = $"{RulesField}[{index}]";
            var problem = ReadRule(item, where, index, entries, rules, out var rule);
            if (problem is not null)
            {
                return TechniqueResult<TechniqueMap>.Failed(problem);
            }

            rules.Add(rule);
            index++;
        }

        return null;
    }

    private static string? ReadRule(
        JsonElement item,
        string where,
        int ordinal,
        Dictionary<string, TechniqueEntry> entries,
        List<KeywordRule> earlier,
        out KeywordRule rule)
    {
        rule = null!;

        if (item.ValueKind != JsonValueKind.Object)
        {
            return $"{where}: is a JSON {Describe(item.ValueKind)}; expected an object";
        }

        string? keyword = null, id = null;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in item.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                return $"{where}: field '{property.Name}' appears twice";
            }

            switch (property.Name)
            {
                case KeywordField:
                    if (!TryString(property, where, out keyword, out var keywordProblem)) return keywordProblem;
                    break;
                case IdField:
                    if (!TryString(property, where, out id, out var idProblem)) return idProblem;
                    break;
                default:
                    return $"{where}{Label(keyword)}: unknown field '{property.Name}'; the file was written against a different schema";
            }
        }

        if (id is null)
        {
            return $"{where}: required field '{IdField}' is missing";
        }

        if (!TechniqueIdentifier.TryParse(id, out var identifier, out var idText))
        {
            return $"{where}: identifier {idText}";
        }

        var tag = $"{where} ({identifier.Value})";

        if (!entries.ContainsKey(identifier.Value))
        {
            return $"{tag}: rule's identifier is absent from the map's entries";
        }

        var keywordProblemText = CheckText(keyword, KeywordField, tag);
        if (keywordProblemText is not null) return keywordProblemText;

        if (keyword!.Length < MinimumKeywordLength)
        {
            return $"{tag}: keyword '{keyword}' is {keyword.Length} characters; rules need at least {MinimumKeywordLength} to be specific enough";
        }

        foreach (var canary in KeywordRuleCanaries)
        {
            if (canary.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return $"{tag}: keyword '{keyword}' matches the generic canary description \"{canary}\"; a rule this broad would resolve most of a run to one identifier";
            }
        }

        // A later rule whose keyword contains an earlier keyword can never fire: any
        // description it matches already matched the earlier rule. Same keyword twice is the
        // degenerate case. Rejecting it makes "first match wins" mean something at curation time.
        foreach (var previous in earlier)
        {
            if (keyword.Contains(previous.Keyword, StringComparison.OrdinalIgnoreCase))
            {
                return $"{tag}: keyword '{keyword}' is unreachable; {RulesField}[{previous.Ordinal}] ({previous.Identifier.Value}) with keyword '{previous.Keyword}' matches every description this rule would";
            }
        }

        rule = new KeywordRule(ordinal, keyword, identifier);
        return null;
    }

    private static bool TryString(JsonProperty property, string where, out string? value, out string problem)
    {
        if (property.Value.ValueKind == JsonValueKind.String)
        {
            value = property.Value.GetString();
            problem = string.Empty;
            return true;
        }

        value = null;
        problem = $"{where}: field '{property.Name}' is a JSON {Describe(property.Value.ValueKind)}; expected a string";
        return false;
    }

    /// <summary>
    /// Required, non-empty, not whitespace-only, not padded, not over the length ceiling.
    /// </summary>
    /// <remarks>
    /// Padding is rejected rather than trimmed because two categories that differ only by a
    /// trailing space would otherwise become two categories in the rollup, one of them a
    /// phantom with a single member.
    /// </remarks>
    private static string? CheckText(string? value, string field, string tag)
    {
        if (value is null)
        {
            return $"{tag}: required field '{field}' is missing";
        }

        if (value.Length == 0)
        {
            return $"{tag}: field '{field}' is empty";
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            return $"{tag}: field '{field}' is whitespace only";
        }

        if (value.Length != value.Trim().Length)
        {
            return $"{tag}: field '{field}' has surrounding whitespace; fields are not trimmed";
        }

        if (value.Length > MaxFieldLength)
        {
            return $"{tag}: field '{field}' is {value.Length} characters; the ceiling is {MaxFieldLength}";
        }

        return null;
    }

    /// <summary>
    /// String validation only. On Unix, <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
    /// accepts a bare path like <c>/x</c> as an absolute file URI, so "absolute" alone is not
    /// enough — a reference URL is an http(s) URL with a host.
    /// </summary>
    private static string? CheckUrl(string url, string tag)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return $"{tag}: field '{UrlField}' is not a well-formed absolute URL: '{Clip(url)}'";
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            return $"{tag}: field '{UrlField}' has scheme '{uri.Scheme}'; a reference URL is http or https: '{Clip(url)}'";
        }

        if (uri.Host.Length == 0)
        {
            return $"{tag}: field '{UrlField}' has no host: '{Clip(url)}'";
        }

        return null;
    }

    private static string Label(string? id) => id is null ? string.Empty : $" ({id})";

    private static string Clip(string text) => text.Length <= 80 ? text : text[..77] + "...";

    private static string FirstLine(string message)
    {
        var end = message.IndexOfAny(['\r', '\n']);
        return end < 0 ? message : message[..end];
    }

    private static string Describe(JsonValueKind kind) => kind switch
    {
        JsonValueKind.Object => "object",
        JsonValueKind.Array => "array",
        JsonValueKind.String => "string",
        JsonValueKind.Number => "number",
        JsonValueKind.True or JsonValueKind.False => "boolean",
        JsonValueKind.Null => "null",
        _ => "value",
    };
}
