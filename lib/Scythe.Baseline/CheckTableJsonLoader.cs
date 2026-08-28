using System.Text.Json;

namespace Scythe.Baseline;

/// <summary>Result of loading a check table from JSON. Failed means the table is unusable and
/// nothing may be evaluated from it; <see cref="Table"/> is null if and only if Failed.</summary>
public sealed record TableLoadResult
{
    public required EvaluationState State { get; init; }
    public CheckTable? Table { get; init; }
    public required IReadOnlyList<CheckTableError> Errors { get; init; }
}

/// <summary>
/// Loads a check table from JSON — the format this library defines for tables shipped as data.
/// Strict by design: unknown properties, missing required fields, and values whose JSON type
/// disagrees with the check's declared type are all loud errors, because this file is edited by
/// people who are not the author of this library and a typo must never become a silently
/// disabled or silently different check. A table that fails to load evaluates nothing.
///
/// Shape:
/// <code>
/// {
///   "checks": [
///     {
///       "id": "PWD-001",
///       "title": "Minimum password length",
///       "settingKey": "Security\\MinimumPasswordLength",
///       "type": "integer",                          // integer | boolean | string
///       "comparison": { "kind": "atLeast", "floor": 14 },
///           // or { "kind": "equals", "value": ... } / { "kind": "notEquals", "value": ... }
///           // or { "kind": "oneOf", "values": [...] } / { "kind": "noneOf", "values": [...] }
///       "severity": "high",                         // low | medium | high | critical
///       "remediation": "Set the policy to 14 or more.",
///       "absence": "nonCompliant",                  // "compliant" | "nonCompliant"
///           // or { "rule": "default", "value": ... }
///       "caseSensitive": true,                      // required for string checks
///       "instancing": "single",                     // single | multi (default single)
///       "emptyInstances": "undetermined",           // required for multi: compliant | nonCompliant | undetermined
///       "appliesWhen": { "contextKey": "Role", "anyOf": ["Server"] }   // optional
///     }
///   ]
/// }
/// </code>
/// </summary>
public static class CheckTableJsonLoader
{
    public static TableLoadResult Load(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = false,
            });
        }
        catch (JsonException ex)
        {
            // Line numbers are zero-based in JsonException; report one-based for the technician.
            var where = ex.LineNumber is { } line
                ? $" at line {line + 1}, position {(ex.BytePositionInLine ?? 0) + 1}"
                : "";
            return Failed(new CheckTableError(null, $"malformed JSON{where}: {ex.Message}"));
        }

        using (document)
        {
            var errors = new List<CheckTableError>();
            var checks = new List<BaselineCheck>();

            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Failed(new CheckTableError(null, "root must be an object with a 'checks' array"));

            JsonElement? checksElement = null;
            foreach (var property in root.EnumerateObject())
            {
                if (property.Name == "checks")
                    checksElement = property.Value;
                else
                    errors.Add(new CheckTableError(null, $"unknown property '{property.Name}' at root"));
            }

            if (checksElement is not { ValueKind: JsonValueKind.Array } checksArray)
            {
                errors.Add(new CheckTableError(null, "'checks' array is missing"));
                return Failed(errors);
            }

            var index = 0;
            foreach (var element in checksArray.EnumerateArray())
            {
                var check = LoadCheck(element, index, errors);
                if (check is not null)
                    checks.Add(check);
                index++;
            }

            // A shipped table with zero checks verifies nothing, and its evaluation output is
            // indistinguishable at a glance from a clean run. A file like that is an authoring
            // mistake (wrong file, mangled export), so it fails loudly rather than loading as
            // "a table with no checks".
            if (index == 0)
                errors.Add(new CheckTableError(null, "'checks' array is empty — a table with no checks verifies nothing"));

            if (errors.Count > 0)
                return Failed(errors);

            // Structural load succeeded; now apply the same semantic validation the evaluator
            // applies, so a bad table fails at load rather than at first use.
            var table = new CheckTable(checks);
            var semanticErrors = CheckTableValidator.Validate(table);
            if (semanticErrors.Count > 0)
                return Failed(semanticErrors);

            return new TableLoadResult
            {
                State = EvaluationState.Ok,
                Table = table,
                Errors = Array.Empty<CheckTableError>(),
            };
        }
    }

    private static BaselineCheck? LoadCheck(JsonElement element, int index, List<CheckTableError> errors)
    {
        var where = $"checks[{index}]";
        if (element.ValueKind != JsonValueKind.Object)
        {
            errors.Add(new CheckTableError(null, $"{where}: must be an object"));
            return null;
        }

        // First pass: collect properties, rejecting unknowns so a typo like "remediaton" is
        // caught instead of leaving the real field missing.
        var known = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        var allowed = new[]
        {
            "id", "title", "settingKey", "type", "comparison", "severity", "remediation",
            "absence", "caseSensitive", "instancing", "emptyInstances", "appliesWhen",
        };
        var before = errors.Count;
        foreach (var property in element.EnumerateObject())
        {
            if (!allowed.Contains(property.Name, StringComparer.Ordinal))
                errors.Add(new CheckTableError(null, $"{where}: unknown property '{property.Name}'"));
            else if (!known.TryAdd(property.Name, property.Value))
                errors.Add(new CheckTableError(null, $"{where}: duplicate property '{property.Name}'"));
        }

        var id = RequireString(known, "id", where, errors);
        var title = RequireString(known, "title", where, errors);
        var settingKey = RequireString(known, "settingKey", where, errors);
        var remediation = RequireString(known, "remediation", where, errors);
        var kind = LoadKind(known, where, errors);
        var severity = LoadSeverity(known, where, errors);
        var comparison = kind is { } k1 ? LoadComparison(known, k1, where, errors) : null;
        var absence = kind is { } k2 ? LoadAbsence(known, k2, where, errors) : null;
        var caseSensitivity = LoadCaseSensitivity(known, where, errors);
        var (instancing, emptyInstances) = LoadInstancing(known, where, errors);
        var appliesWhen = LoadAppliesWhen(known, where, errors);

        if (errors.Count > before)
            return null;

        return new BaselineCheck
        {
            Id = id!,
            Title = title!,
            SettingKey = settingKey!,
            ExpectedKind = kind!.Value,
            Comparison = comparison!,
            Severity = severity!.Value,
            Remediation = remediation!,
            Absence = absence!,
            Instancing = instancing,
            EmptyInstances = emptyInstances,
            CaseSensitivity = caseSensitivity,
            AppliesWhen = appliesWhen,
        };
    }

    private static string? RequireString(
        Dictionary<string, JsonElement> known, string name, string where, List<CheckTableError> errors)
    {
        if (!known.TryGetValue(name, out var element))
        {
            errors.Add(new CheckTableError(null, $"{where}: required property '{name}' is missing"));
            return null;
        }
        if (element.ValueKind != JsonValueKind.String)
        {
            errors.Add(new CheckTableError(null, $"{where}.{name}: must be a string"));
            return null;
        }
        return element.GetString()!;
    }

    private static SettingValueKind? LoadKind(
        Dictionary<string, JsonElement> known, string where, List<CheckTableError> errors)
    {
        var text = RequireString(known, "type", where, errors);
        return text switch
        {
            null => null,
            "integer" => SettingValueKind.Integer,
            "boolean" => SettingValueKind.Boolean,
            "string" => SettingValueKind.String,
            _ => AddNull<SettingValueKind?>(errors, $"{where}.type: '{text}' is not one of integer, boolean, string"),
        };
    }

    private static Severity? LoadSeverity(
        Dictionary<string, JsonElement> known, string where, List<CheckTableError> errors)
    {
        var text = RequireString(known, "severity", where, errors);
        return text switch
        {
            null => null,
            "low" => Severity.Low,
            "medium" => Severity.Medium,
            "high" => Severity.High,
            "critical" => Severity.Critical,
            _ => AddNull<Severity?>(errors, $"{where}.severity: '{text}' is not one of low, medium, high, critical"),
        };
    }

    private static CheckComparison? LoadComparison(
        Dictionary<string, JsonElement> known, SettingValueKind kind, string where, List<CheckTableError> errors)
    {
        if (!known.TryGetValue("comparison", out var element))
        {
            errors.Add(new CheckTableError(null, $"{where}: required property 'comparison' is missing"));
            return null;
        }
        if (element.ValueKind != JsonValueKind.Object)
        {
            errors.Add(new CheckTableError(null, $"{where}.comparison: must be an object"));
            return null;
        }

        var comparisonKind = element.TryGetProperty("kind", out var kindElement) && kindElement.ValueKind == JsonValueKind.String
            ? kindElement.GetString()
            : null;
        if (comparisonKind is null)
        {
            errors.Add(new CheckTableError(null, $"{where}.comparison: 'kind' string is missing"));
            return null;
        }

        switch (comparisonKind)
        {
            case "equals":
            case "notEquals":
            {
                if (!element.TryGetProperty("value", out var valueElement))
                {
                    errors.Add(new CheckTableError(null, $"{where}.comparison: '{comparisonKind}' requires 'value'"));
                    return null;
                }
                var value = LoadValue(valueElement, kind, $"{where}.comparison.value", errors);
                if (value is null)
                    return null;
                return comparisonKind == "equals" ? CheckComparison.EqualTo(value) : CheckComparison.NotEqualTo(value);
            }

            case "atLeast":
            {
                if (!element.TryGetProperty("floor", out var floorElement)
                    || floorElement.ValueKind != JsonValueKind.Number
                    || !floorElement.TryGetInt64(out var floor))
                {
                    errors.Add(new CheckTableError(null, $"{where}.comparison: 'atLeast' requires an integer 'floor'"));
                    return null;
                }
                return CheckComparison.AtLeast(floor);
            }

            case "oneOf":
            case "noneOf":
            {
                if (!element.TryGetProperty("values", out var valuesElement)
                    || valuesElement.ValueKind != JsonValueKind.Array)
                {
                    errors.Add(new CheckTableError(null, $"{where}.comparison: '{comparisonKind}' requires a 'values' array"));
                    return null;
                }
                var values = new List<SettingValue>();
                var itemIndex = 0;
                var before = errors.Count;
                foreach (var item in valuesElement.EnumerateArray())
                {
                    var value = LoadValue(item, kind, $"{where}.comparison.values[{itemIndex}]", errors);
                    if (value is not null)
                        values.Add(value);
                    itemIndex++;
                }
                if (errors.Count > before)
                    return null;
                return comparisonKind == "oneOf"
                    ? new OneOfComparison(values)
                    : new NoneOfComparison(values);
            }

            default:
                errors.Add(new CheckTableError(null,
                    $"{where}.comparison.kind: '{comparisonKind}' is not one of equals, notEquals, atLeast, oneOf, noneOf"));
                return null;
        }
    }

    private static AbsenceRule? LoadAbsence(
        Dictionary<string, JsonElement> known, SettingValueKind kind, string where, List<CheckTableError> errors)
    {
        if (!known.TryGetValue("absence", out var element))
        {
            errors.Add(new CheckTableError(null, $"{where}: required property 'absence' is missing"));
            return null;
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            return element.GetString() switch
            {
                "compliant" => AbsenceRule.Compliant,
                "nonCompliant" => AbsenceRule.NonCompliant,
                var text => AddNull<AbsenceRule>(errors,
                    $"{where}.absence: '{text}' is not one of compliant, nonCompliant (use {{\"rule\": \"default\", \"value\": ...}} for a default)"),
            };
        }

        if (element.ValueKind == JsonValueKind.Object)
        {
            var rule = element.TryGetProperty("rule", out var ruleElement) && ruleElement.ValueKind == JsonValueKind.String
                ? ruleElement.GetString()
                : null;
            if (rule != "default")
            {
                errors.Add(new CheckTableError(null, $"{where}.absence: object form requires \"rule\": \"default\""));
                return null;
            }
            if (!element.TryGetProperty("value", out var valueElement))
            {
                errors.Add(new CheckTableError(null, $"{where}.absence: 'default' requires 'value'"));
                return null;
            }
            var value = LoadValue(valueElement, kind, $"{where}.absence.value", errors);
            return value is null ? null : AbsenceRule.MeansDefault(value);
        }

        errors.Add(new CheckTableError(null, $"{where}.absence: must be a string or an object"));
        return null;
    }

    private static StringCase? LoadCaseSensitivity(
        Dictionary<string, JsonElement> known, string where, List<CheckTableError> errors)
    {
        if (!known.TryGetValue("caseSensitive", out var element))
            return null;    // Required-for-string is enforced by CheckTableValidator.
        if (element.ValueKind is JsonValueKind.True or JsonValueKind.False)
            return element.GetBoolean() ? StringCase.Sensitive : StringCase.Insensitive;
        errors.Add(new CheckTableError(null, $"{where}.caseSensitive: must be true or false"));
        return null;
    }

    private static (CheckInstancing, EmptyInstancesRule?) LoadInstancing(
        Dictionary<string, JsonElement> known, string where, List<CheckTableError> errors)
    {
        var instancing = CheckInstancing.SingleInstance;
        if (known.TryGetValue("instancing", out var element))
        {
            var text = element.ValueKind == JsonValueKind.String ? element.GetString() : null;
            switch (text)
            {
                case "single": instancing = CheckInstancing.SingleInstance; break;
                case "multi": instancing = CheckInstancing.MultiInstance; break;
                default:
                    errors.Add(new CheckTableError(null, $"{where}.instancing: must be 'single' or 'multi'"));
                    break;
            }
        }

        EmptyInstancesRule? emptyRule = null;
        if (known.TryGetValue("emptyInstances", out var emptyElement))
        {
            var text = emptyElement.ValueKind == JsonValueKind.String ? emptyElement.GetString() : null;
            emptyRule = text switch
            {
                "compliant" => EmptyInstancesRule.EmptyIsCompliant,
                "nonCompliant" => EmptyInstancesRule.EmptyIsNonCompliant,
                "undetermined" => EmptyInstancesRule.EmptyIsUndetermined,
                _ => AddNull<EmptyInstancesRule?>(errors,
                    $"{where}.emptyInstances: must be one of compliant, nonCompliant, undetermined"),
            };
        }
        return (instancing, emptyRule);
    }

    private static ApplicabilityCondition? LoadAppliesWhen(
        Dictionary<string, JsonElement> known, string where, List<CheckTableError> errors)
    {
        if (!known.TryGetValue("appliesWhen", out var element))
            return null;
        if (element.ValueKind != JsonValueKind.Object)
        {
            errors.Add(new CheckTableError(null, $"{where}.appliesWhen: must be an object"));
            return null;
        }

        string? contextKey = null;
        List<string>? anyOf = null;
        var before = errors.Count;
        foreach (var property in element.EnumerateObject())
        {
            switch (property.Name)
            {
                case "contextKey" when property.Value.ValueKind == JsonValueKind.String:
                    contextKey = property.Value.GetString();
                    break;
                case "anyOf" when property.Value.ValueKind == JsonValueKind.Array:
                    anyOf = new List<string>();
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                            anyOf.Add(item.GetString()!);
                        else
                            errors.Add(new CheckTableError(null, $"{where}.appliesWhen.anyOf: entries must be strings"));
                    }
                    break;
                default:
                    errors.Add(new CheckTableError(null,
                        $"{where}.appliesWhen: unknown or mistyped property '{property.Name}'"));
                    break;
            }
        }
        if (contextKey is null || anyOf is null)
            errors.Add(new CheckTableError(null, $"{where}.appliesWhen: requires 'contextKey' string and 'anyOf' array"));
        if (errors.Count > before)
            return null;
        return new ApplicabilityCondition(contextKey!, anyOf!);
    }

    /// <summary>Parses a JSON value against the check's declared type. The JSON type must agree:
    /// a quoted "5" for an integer check is an error, never a silent coercion.</summary>
    private static SettingValue? LoadValue(
        JsonElement element, SettingValueKind kind, string where, List<CheckTableError> errors)
    {
        switch (kind)
        {
            case SettingValueKind.Integer:
                if (element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out var integer))
                    return SettingValue.OfInteger(integer);
                errors.Add(new CheckTableError(null, $"{where}: expected an integer, got {DescribeJson(element)}"));
                return null;

            case SettingValueKind.Boolean:
                if (element.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    return SettingValue.OfBoolean(element.GetBoolean());
                errors.Add(new CheckTableError(null, $"{where}: expected true or false, got {DescribeJson(element)}"));
                return null;

            case SettingValueKind.String:
                if (element.ValueKind == JsonValueKind.String)
                    return SettingValue.OfString(element.GetString()!);
                errors.Add(new CheckTableError(null, $"{where}: expected a string, got {DescribeJson(element)}"));
                return null;

            default:
                errors.Add(new CheckTableError(null, $"{where}: unknown declared type"));
                return null;
        }
    }

    private static string DescribeJson(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Number => "a number",
        JsonValueKind.String => $"the string {element.GetRawText()}",
        JsonValueKind.True or JsonValueKind.False => "a boolean",
        JsonValueKind.Null => "null",
        JsonValueKind.Array => "an array",
        JsonValueKind.Object => "an object",
        _ => element.ValueKind.ToString(),
    };

    private static T? AddNull<T>(List<CheckTableError> errors, string message)
    {
        errors.Add(new CheckTableError(null, message));
        return default;
    }

    private static TableLoadResult Failed(CheckTableError error) => Failed(new[] { error });

    private static TableLoadResult Failed(IReadOnlyList<CheckTableError> errors) => new()
    {
        State = EvaluationState.Failed,
        Table = null,
        Errors = errors,
    };
}
