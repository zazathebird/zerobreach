using System.Text;
using System.Text.RegularExpressions;
using Scythe.Rules.Sigma.Yaml;

namespace Scythe.Rules.Sigma;

/// <summary>Internal compile-time failure with position; converted by the compiler into a
/// Failed <see cref="SigmaCompileResult"/>. Never escapes the public API.</summary>
internal sealed class SigmaCompileException(string message, YamlPosition position)
    : Exception(message)
{
    public YamlPosition Position { get; } = position;
}

/// <summary>
/// Compiles one Sigma rule (YAML text) into a <see cref="CompiledSigmaRule"/>. Malformed
/// input yields a Failed result with the line and column — never a rule that silently
/// matches nothing. Unsupported value modifiers are a compile-time failure (the task
/// brief's recommended answer to its open question), because degrading them at evaluation
/// would run every record through a rule that cannot answer.
/// </summary>
public static class SigmaCompiler
{
    /// <summary>Sanity ceiling for one regex value. A longer pattern is a mistake or an
    /// attack on the compiler, not a detection.</summary>
    public const int MaxRegexLength = 4096;

    private static readonly string[] SupportedModifierNames =
        ["contains", "startswith", "endswith", "re", "all", "base64", "base64offset", "cidr", "windash"];

    private static readonly string[] AggregationFunctions =
        ["count", "min", "max", "avg", "sum", "near"];

    public static SigmaCompileResult Compile(string source, string sourceName = "<sigma-rule>")
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(sourceName);
        try
        {
            var rule = CompileCore(source);
            return new SigmaCompileResult
            {
                State = OperationState.Ok,
                Rule = rule,
                Diagnostics = [],
            };
        }
        catch (YamlFormatException ex)
        {
            return Fail(sourceName, ex.RawMessage, ex.Position);
        }
        catch (SigmaCompileException ex)
        {
            return Fail(sourceName, ex.Message, ex.Position);
        }
    }

    private static SigmaCompileResult Fail(string sourceName, string message, YamlPosition position)
    {
        var diagnostic = new SigmaDiagnostic(sourceName, message, position.Line, position.Column);
        return new SigmaCompileResult
        {
            State = OperationState.Failed,
            Reason = diagnostic.ToString(),
            Rule = null,
            Diagnostics = [diagnostic],
        };
    }

    private static CompiledSigmaRule CompileCore(string source)
    {
        var rootNode = YamlParser.ParseDocument(source);
        if (rootNode is not YamlMapping root)
        {
            throw new SigmaCompileException("a Sigma rule must be a YAML mapping", rootNode.Position);
        }

        string title = RequireString(root, "title");
        string? id = OptionalString(root, "id");
        string? level = OptionalString(root, "level");
        string? status = OptionalString(root, "status");
        var logsource = ReadLogsource(root);
        var tags = ReadStringList(root, "tags");
        var fields = ReadStringList(root, "fields");

        var detectionNode = root.Find("detection")
            ?? throw new SigmaCompileException("rule has no 'detection' section", root.Position);
        if (detectionNode is not YamlMapping detection)
        {
            throw new SigmaCompileException("'detection' must be a mapping", detectionNode.Position);
        }

        // Pass 1: named detection items, in declaration order (determinism).
        var items = new List<DetectionItem>();
        var byName = new Dictionary<string, DetectionItem>(StringComparer.Ordinal);
        YamlNode? conditionValue = null;
        YamlPosition conditionPosition = detection.Position;
        string? timeframe = null;
        foreach (var entry in detection.Entries)
        {
            if (string.Equals(entry.Key, "condition", StringComparison.OrdinalIgnoreCase))
            {
                conditionValue = entry.Value;
                conditionPosition = entry.KeyPosition;
                continue;
            }
            if (string.Equals(entry.Key, "timeframe", StringComparison.OrdinalIgnoreCase))
            {
                timeframe = ScalarText(entry.Value, "timeframe");
                continue;
            }
            ValidateItemName(entry.Key, entry.KeyPosition);
            var item = CompileDetectionItem(entry.Key, items.Count, entry.Value);
            items.Add(item);
            byName.Add(entry.Key, item);
        }
        if (items.Count == 0)
        {
            throw new SigmaCompileException(
                "'detection' declares no selections (only condition/timeframe)", detection.Position);
        }
        if (conditionValue is null)
        {
            throw new SigmaCompileException("'detection' has no 'condition'", detection.Position);
        }

        // Pass 2: the condition — a single string, or a list of strings OR-ed together
        // (the v1 spec's multi-condition form).
        var conditionStrings = new List<(string Text, YamlPosition Position)>();
        if (conditionValue is YamlSequence conditionList)
        {
            if (conditionList.Items.Count == 0)
            {
                throw new SigmaCompileException("condition list is empty", conditionList.Position);
            }
            foreach (var element in conditionList.Items)
            {
                conditionStrings.Add((ScalarText(element, "condition")
                    ?? throw new SigmaCompileException("condition entry is null", element.Position),
                    element.Position));
            }
        }
        else
        {
            conditionStrings.Add((ScalarText(conditionValue, "condition")
                ?? throw new SigmaCompileException("condition is null", conditionPosition),
                conditionValue.Position));
        }

        ConditionNode? conditionRoot = null;
        string? aggregationText = null;
        foreach (var (text, position) in conditionStrings)
        {
            string expressionText = text;
            // Everything after the first '|' is the aggregation/correlation part
            // ("| count() by User > 5", "| near ..."). It is parsed for shape and kept,
            // but not evaluated: the rule reports Incomplete at evaluation time.
            int pipe = text.IndexOf('|');
            if (pipe >= 0)
            {
                expressionText = text[..pipe];
                string aggregation = text[(pipe + 1)..].Trim();
                ValidateAggregation(aggregation, new YamlPosition(position.Line, position.Column + pipe + 1));
                aggregationText ??= aggregation;
            }
            var node = SigmaConditionParser.Parse(expressionText, position, items, byName);
            conditionRoot = conditionRoot is null ? node : new OrNode(conditionRoot, node);
        }

        return new CompiledSigmaRule(
            title, id, level, status, logsource, tags, fields,
            items.ToArray(), conditionRoot!, aggregationText, timeframe);
    }

    private static void ValidateAggregation(string aggregation, YamlPosition position)
    {
        if (aggregation.Length == 0)
        {
            throw new SigmaCompileException("empty aggregation expression after '|'", position);
        }
        int end = 0;
        while (end < aggregation.Length && char.IsAsciiLetter(aggregation[end]))
        {
            end++;
        }
        string function = aggregation[..end];
        if (Array.IndexOf(AggregationFunctions, function) < 0)
        {
            throw new SigmaCompileException(
                $"unrecognised aggregation function '{function}' (supported for parsing: {string.Join(", ", AggregationFunctions)})",
                position);
        }
    }

    private static void ValidateItemName(string name, YamlPosition position)
    {
        // Names must survive the condition tokenizer: identifier characters only, not a
        // reserved word, not digit-leading (a leading digit would read as a quantifier).
        if (name.Length == 0)
        {
            throw new SigmaCompileException("empty selection name", position);
        }
        if (name is "and" or "or" or "not" or "of" or "them" or "all" or "any")
        {
            throw new SigmaCompileException(
                $"selection name '{name}' is a reserved condition keyword", position);
        }
        if (char.IsAsciiDigit(name[0]))
        {
            throw new SigmaCompileException(
                $"selection name '{name}' must not start with a digit", position);
        }
        foreach (char c in name)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '_')
            {
                throw new SigmaCompileException(
                    $"selection name '{name}' contains unsupported character '{c}' (use letters, digits, '_')",
                    position);
            }
        }
    }

    private static DetectionItem CompileDetectionItem(string name, int index, YamlNode value)
    {
        switch (value)
        {
            case YamlMapping map:
                return new MapDetectionItem
                {
                    Name = name,
                    Index = index,
                    Groups = [CompileFieldGroup(map)],
                };
            case YamlSequence seq:
            {
                if (seq.Items.Count == 0)
                {
                    throw new SigmaCompileException($"selection '{name}' is an empty list", seq.Position);
                }
                if (seq.Items[0] is YamlMapping)
                {
                    // List of maps: OR across the maps.
                    var groups = new List<FieldTest[]>();
                    foreach (var element in seq.Items)
                    {
                        if (element is not YamlMapping elementMap)
                        {
                            throw new SigmaCompileException(
                                $"selection '{name}' mixes mappings and plain values in one list",
                                element.Position);
                        }
                        groups.Add(CompileFieldGroup(elementMap));
                    }
                    return new MapDetectionItem { Name = name, Index = index, Groups = groups.ToArray() };
                }
                // List of scalars: keywords, matched against every field value.
                var keywords = new List<ValueMatcher>();
                foreach (var element in seq.Items)
                {
                    if (element is not YamlScalar scalar)
                    {
                        throw new SigmaCompileException(
                            $"selection '{name}' mixes mappings and plain values in one list",
                            element.Position);
                    }
                    keywords.Add(CompileKeyword(scalar));
                }
                return new KeywordDetectionItem { Name = name, Index = index, Keywords = keywords.ToArray() };
            }
            case YamlScalar scalar:
                // A single bare scalar is a one-keyword selection.
                return new KeywordDetectionItem
                {
                    Name = name,
                    Index = index,
                    Keywords = [CompileKeyword(scalar)],
                };
            default:
                throw new SigmaCompileException($"selection '{name}' has an unsupported shape", value.Position);
        }
    }

    private static ValueMatcher CompileKeyword(YamlScalar scalar)
    {
        string? text = scalar.AsString;
        if (text is null)
        {
            throw new SigmaCompileException("null cannot be used as a keyword", scalar.Position);
        }
        // Keywords match anywhere in any value: contains semantics, wildcards honoured.
        var tokens = ParseSigmaValue(text, windash: false);
        WrapAnchor(tokens, ValueAnchor.Contains);
        return new GlobMatcher(tokens.ToArray(), windash: false);
    }

    private static FieldTest[] CompileFieldGroup(YamlMapping map)
    {
        if (map.Entries.Count == 0)
        {
            throw new SigmaCompileException("selection mapping is empty", map.Position);
        }
        var tests = new List<FieldTest>();
        foreach (var entry in map.Entries)
        {
            tests.Add(CompileFieldTest(entry.Key, entry.KeyPosition, entry.Value));
        }
        return tests.ToArray();
    }

    private enum ValueAnchor
    {
        Exact,
        Contains,
        StartsWith,
        EndsWith,
    }

    private sealed class ModifierSet
    {
        public ValueAnchor Anchor;
        public bool All;
        public bool Re;
        public bool Cidr;
        public bool Windash;
        public bool Base64;
        public bool Base64Offset;
    }

    private static FieldTest CompileFieldTest(string key, YamlPosition keyPosition, YamlNode value)
    {
        string[] parts = key.Split('|');
        string fieldName = parts[0].Trim();
        if (fieldName.Length == 0)
        {
            throw new SigmaCompileException($"empty field name in '{key}'", keyPosition);
        }
        var mods = ParseModifiers(parts, keyPosition);

        var valueScalars = new List<YamlScalar>();
        switch (value)
        {
            case YamlScalar s:
                valueScalars.Add(s);
                break;
            case YamlSequence seq:
            {
                if (seq.Items.Count == 0)
                {
                    throw new SigmaCompileException($"'{key}' has an empty value list", seq.Position);
                }
                foreach (var element in seq.Items)
                {
                    if (element is not YamlScalar es)
                    {
                        throw new SigmaCompileException(
                            $"'{key}' values must be scalars", element.Position);
                    }
                    valueScalars.Add(es);
                }
                break;
            }
            default:
                throw new SigmaCompileException(
                    $"'{key}' must map to a value or a list of values", value.Position);
        }

        var matchers = new List<ValueMatcher>();
        foreach (var scalar in valueScalars)
        {
            matchers.AddRange(CompileValue(scalar, mods));
        }
        return new FieldTest
        {
            FieldName = fieldName,
            MatchAll = mods.All,
            Matchers = matchers.ToArray(),
        };
    }

    private static ModifierSet ParseModifiers(string[] keyParts, YamlPosition position)
    {
        var mods = new ModifierSet();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 1; i < keyParts.Length; i++)
        {
            string modifier = keyParts[i].Trim();
            if (!seen.Add(modifier))
            {
                throw new SigmaCompileException($"duplicate value modifier '{modifier}'", position);
            }
            switch (modifier)
            {
                case "contains":
                    SetAnchor(mods, ValueAnchor.Contains, modifier, position);
                    break;
                case "startswith":
                    SetAnchor(mods, ValueAnchor.StartsWith, modifier, position);
                    break;
                case "endswith":
                    SetAnchor(mods, ValueAnchor.EndsWith, modifier, position);
                    break;
                case "all":
                    mods.All = true;
                    break;
                case "re":
                    mods.Re = true;
                    break;
                case "cidr":
                    mods.Cidr = true;
                    break;
                case "windash":
                    mods.Windash = true;
                    break;
                case "base64":
                    mods.Base64 = true;
                    break;
                case "base64offset":
                    mods.Base64Offset = true;
                    break;
                default:
                    // Compile-time refusal (task brief's recommendation): a modifier this
                    // engine cannot evaluate must not degrade into a rule that answers.
                    throw new SigmaCompileException(
                        $"unsupported value modifier '{modifier}' (supported: {string.Join(", ", SupportedModifierNames)})",
                        position);
            }
        }

        // Combination rules: transforms and anchors combine; the self-contained matchers
        // (re, cidr) accept only 'all'.
        if (mods.Base64 && mods.Base64Offset)
        {
            throw new SigmaCompileException(
                "'base64' and 'base64offset' cannot be combined", position);
        }
        if (mods.Re && (mods.Anchor != ValueAnchor.Exact || mods.Cidr || mods.Windash || mods.Base64 || mods.Base64Offset))
        {
            throw new SigmaCompileException(
                "'re' cannot be combined with other value modifiers (except 'all')", position);
        }
        if (mods.Cidr && (mods.Anchor != ValueAnchor.Exact || mods.Re || mods.Windash || mods.Base64 || mods.Base64Offset))
        {
            throw new SigmaCompileException(
                "'cidr' cannot be combined with other value modifiers (except 'all')", position);
        }
        if (mods.Windash && (mods.Base64 || mods.Base64Offset))
        {
            throw new SigmaCompileException(
                "'windash' cannot be combined with base64 modifiers", position);
        }
        return mods;
    }

    private static void SetAnchor(ModifierSet mods, ValueAnchor anchor, string modifier, YamlPosition position)
    {
        if (mods.Anchor != ValueAnchor.Exact)
        {
            throw new SigmaCompileException(
                $"conflicting anchor modifier '{modifier}' (only one of contains/startswith/endswith)",
                position);
        }
        mods.Anchor = anchor;
    }

    /// <summary>Compiles one value under a modifier set into one or more matchers
    /// (base64offset expands to its three alignment variants; everything else is one).</summary>
    private static IEnumerable<ValueMatcher> CompileValue(YamlScalar scalar, ModifierSet mods)
    {
        if (scalar.Value is null && !scalar.WasQuoted)
        {
            // `Field: null` — matches a present field whose value is null. Modifiers make
            // no sense on the null test and are refused rather than ignored.
            if (mods.Anchor != ValueAnchor.Exact || mods.All || mods.Re || mods.Cidr
                || mods.Windash || mods.Base64 || mods.Base64Offset)
            {
                throw new SigmaCompileException(
                    "value modifiers cannot be applied to null", scalar.Position);
            }
            yield return NullValueMatcher.Instance;
            yield break;
        }

        string text = scalar.AsString
            ?? throw new SigmaCompileException("unexpected null value", scalar.Position);

        if (mods.Re)
        {
            if (scalar.Value is not string)
            {
                throw new SigmaCompileException("'re' requires a string value", scalar.Position);
            }
            if (text.Length > MaxRegexLength)
            {
                throw new SigmaCompileException(
                    $"regex value exceeds {MaxRegexLength} characters", scalar.Position);
            }
            Regex regex;
            try
            {
                // Case-sensitive, unanchored, invariant — reference `re` semantics. The
                // per-pattern deadline is baked into the Regex so a catastrophic
                // backtrack on attacker-authored text is cut off and surfaces as
                // Incomplete, never as a silent non-match.
                regex = new Regex(text, RegexOptions.CultureInvariant, BudgetDefaults.PerPatternDeadline);
            }
            catch (ArgumentException ex)
            {
                throw new SigmaCompileException($"invalid regex: {ex.Message}", scalar.Position);
            }
            yield return new RegexValueMatcher(regex, text);
            yield break;
        }

        if (mods.Cidr)
        {
            yield return CompileCidr(text, scalar.Position);
            yield break;
        }

        if (mods.Base64 || mods.Base64Offset)
        {
            // The value is data to encode; wildcards have no meaning inside base64 and
            // are refused (reference behaviour) rather than encoded literally.
            var dataTokens = ParseSigmaValue(text, windash: false);
            if (dataTokens.Any(t => t.Kind != GlobTokenKind.Literal))
            {
                throw new SigmaCompileException(
                    "wildcards cannot be used with base64 modifiers", scalar.Position);
            }
            // Rebuild the unescaped data from the (unfolded) source text: escapes are
            // resolved, so re-parse literally. Fold happens after encoding.
            string data = UnescapeToLiteral(text);
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            string[] variants = mods.Base64Offset
                ? Base64OffsetVariants(bytes)
                : [Convert.ToBase64String(bytes)];
            foreach (var variant in variants)
            {
                var tokens = LiteralTokens(variant, windash: false);
                WrapAnchor(tokens, mods.Anchor);
                yield return new GlobMatcher(tokens.ToArray(), windash: false);
            }
            yield break;
        }

        var plainTokens = ParseSigmaValue(text, mods.Windash);
        WrapAnchor(plainTokens, mods.Anchor);
        yield return new GlobMatcher(plainTokens.ToArray(), mods.Windash);
    }

    private static CidrMatcher CompileCidr(string text, YamlPosition position)
    {
        int slash = text.IndexOf('/');
        if (slash <= 0 || slash == text.Length - 1)
        {
            throw new SigmaCompileException(
                $"'{text}' is not CIDR notation (expected address/prefix)", position);
        }
        string addressPart = text[..slash];
        string prefixPart = text[(slash + 1)..];
        if (!System.Net.IPAddress.TryParse(addressPart, out var address)
            || (!addressPart.Contains(':') && addressPart.Count(c => c == '.') != 3))
        {
            throw new SigmaCompileException(
                $"'{addressPart}' is not a valid IP address", position);
        }
        int maxBits = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        if (!int.TryParse(prefixPart, out int prefix) || prefix < 0 || prefix > maxBits)
        {
            throw new SigmaCompileException(
                $"'{prefixPart}' is not a valid prefix length (0-{maxBits})", position);
        }
        return new CidrMatcher(address, prefix);
    }

    /// <summary>The reference base64offset transformation: for each of the three
    /// alignment phases, encode the value behind an i-byte pad and slice off the
    /// characters whose bits mix with the unknown neighbours. The offsets are taken from
    /// the reference implementation (sigmac/pySigma), not re-derived.</summary>
    internal static string[] Base64OffsetVariants(byte[] value)
    {
        int[] startOffsets = [0, 2, 3];
        int[] endOffsets = [0, -3, -2]; // 0 = no trim
        var variants = new string[3];
        for (int i = 0; i < 3; i++)
        {
            byte[] padded = new byte[value.Length + i];
            for (int p = 0; p < i; p++)
            {
                padded[p] = (byte)' ';
            }
            value.CopyTo(padded, i);
            string encoded = Convert.ToBase64String(padded);
            int start = startOffsets[i];
            int end = endOffsets[(value.Length + i) % 3];
            variants[i] = encoded[start..(encoded.Length + end)];
        }
        return variants;
    }

    /// <summary>Parses a Sigma value string into glob tokens, applying Sigma escaping:
    /// <c>\*</c>/<c>\?</c> are literal wildcard characters, <c>\\</c> is one backslash,
    /// and a lone backslash before anything else is itself literal (so Windows paths
    /// written with single backslashes mean what they say). Literals are pre-folded.</summary>
    private static List<GlobToken> ParseSigmaValue(string text, bool windash)
    {
        var tokens = new List<GlobToken>(text.Length);
        int i = 0;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '\\' && i + 1 < text.Length && text[i + 1] is '\\' or '*' or '?')
            {
                tokens.Add(new GlobToken(GlobTokenKind.Literal, SigmaText.Fold(text[i + 1], windash)));
                i += 2;
            }
            else if (c == '*')
            {
                // Collapse runs of stars — "**" matches exactly what "*" matches, and
                // collapsing keeps the backtracking matcher linear in pattern length.
                if (tokens.Count == 0 || tokens[^1].Kind != GlobTokenKind.Star)
                {
                    tokens.Add(GlobToken.Star);
                }
                i++;
            }
            else if (c == '?')
            {
                tokens.Add(GlobToken.AnyChar);
                i++;
            }
            else
            {
                tokens.Add(new GlobToken(GlobTokenKind.Literal, SigmaText.Fold(c, windash)));
                i++;
            }
        }
        return tokens;
    }

    /// <summary>The same escape resolution as <see cref="ParseSigmaValue"/> for a value
    /// already checked to contain no wildcards, returning the raw text (unfolded — this
    /// feeds the base64 encoder, which is byte-exact).</summary>
    private static string UnescapeToLiteral(string text)
    {
        var sb = new StringBuilder(text.Length);
        int i = 0;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '\\' && i + 1 < text.Length && text[i + 1] is '\\' or '*' or '?')
            {
                sb.Append(text[i + 1]);
                i += 2;
            }
            else
            {
                sb.Append(c);
                i++;
            }
        }
        return sb.ToString();
    }

    private static List<GlobToken> LiteralTokens(string text, bool windash)
    {
        var tokens = new List<GlobToken>(text.Length);
        foreach (char c in text)
        {
            tokens.Add(new GlobToken(GlobTokenKind.Literal, SigmaText.Fold(c, windash)));
        }
        return tokens;
    }

    private static void WrapAnchor(List<GlobToken> tokens, ValueAnchor anchor)
    {
        bool needLeading = anchor is ValueAnchor.Contains or ValueAnchor.EndsWith;
        bool needTrailing = anchor is ValueAnchor.Contains or ValueAnchor.StartsWith;
        if (needLeading && (tokens.Count == 0 || tokens[0].Kind != GlobTokenKind.Star))
        {
            tokens.Insert(0, GlobToken.Star);
        }
        if (needTrailing && (tokens.Count == 0 || tokens[^1].Kind != GlobTokenKind.Star))
        {
            tokens.Add(GlobToken.Star);
        }
    }

    private static SigmaLogsource ReadLogsource(YamlMapping root)
    {
        var node = root.Find("logsource")
            ?? throw new SigmaCompileException("rule has no 'logsource' section", root.Position);
        if (node is not YamlMapping map)
        {
            throw new SigmaCompileException("'logsource' must be a mapping", node.Position);
        }
        string? product = null;
        string? category = null;
        string? service = null;
        foreach (var entry in map.Entries)
        {
            string? text = ScalarText(entry.Value, entry.Key);
            switch (entry.Key.ToLowerInvariant())
            {
                case "product":
                    product = text;
                    break;
                case "category":
                    category = text;
                    break;
                case "service":
                    service = text;
                    break;
                default:
                    // 'definition' and friends are documentation; ignore.
                    break;
            }
        }
        return new SigmaLogsource(product, category, service);
    }

    private static string RequireString(YamlMapping root, string key)
    {
        var node = root.Find(key)
            ?? throw new SigmaCompileException($"rule has no '{key}'", root.Position);
        return ScalarText(node, key)
            ?? throw new SigmaCompileException($"'{key}' must not be null", node.Position);
    }

    private static string? OptionalString(YamlMapping root, string key)
    {
        var node = root.Find(key);
        return node is null ? null : ScalarText(node, key);
    }

    private static string? ScalarText(YamlNode node, string what)
    {
        if (node is not YamlScalar scalar)
        {
            throw new SigmaCompileException($"'{what}' must be a scalar value", node.Position);
        }
        return scalar.AsString;
    }

    private static IReadOnlyList<string> ReadStringList(YamlMapping root, string key)
    {
        var node = root.Find(key);
        switch (node)
        {
            case null:
                return [];
            case YamlScalar scalar:
                return scalar.AsString is string single ? [single] : [];
            case YamlSequence seq:
            {
                var list = new List<string>();
                foreach (var element in seq.Items)
                {
                    if (ScalarText(element, key) is string s)
                    {
                        list.Add(s);
                    }
                }
                return list;
            }
            default:
                throw new SigmaCompileException($"'{key}' must be a list", node.Position);
        }
    }
}
