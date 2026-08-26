namespace ZeroBreach.Intel;

using System.Text.Json;

/// <summary>
/// MISP JSON event export reader: <c>Event.Attribute[]</c> plus
/// <c>Event.Object[].Attribute[]</c>, in document order.
///
/// Attribute-level problems are rejections with reasons (the feed still yields its good
/// attributes); a document that is not a MISP event at all is <see cref="OperationState.Failed"/>.
///
/// MISP-specific semantics, all reported rather than silent:
///   - <c>to_ids: false</c> means the analyst marked the value not-for-detection. Feeding it
///     into matching would override the analyst; using the feed while ignoring the flag is
///     exactly the kind of silent decision this module must not make. Rejected with a reason.
///   - <c>deleted: true</c> attributes are tombstones, rejected with a reason.
///   - Composite types (<c>filename|sha256</c>, <c>domain|ip</c>) split into one candidate per
///     part. The <c>port</c> part of <c>ip-…|port</c> and the data half of <c>regkey|value</c>
///     are not indicator kinds in this model and are dropped *by design* alongside the kept
///     part — the indicator the feed asserts (the IP, the key) survives.
/// </summary>
internal static class MispReader
{
    private const int MaxJsonDepth = 64;

    /// <summary>Simple (non-composite) MISP attribute types → candidate types.</summary>
    private static readonly Dictionary<string, CandidateType> TypeMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["md5"] = CandidateType.Md5,
        ["sha1"] = CandidateType.Sha1,
        ["sha256"] = CandidateType.Sha256,
        ["ip-src"] = CandidateType.IpAny,
        ["ip-dst"] = CandidateType.IpAny,
        ["domain"] = CandidateType.Domain,
        ["hostname"] = CandidateType.Domain,
        ["url"] = CandidateType.Url,
        ["uri"] = CandidateType.Url,
        ["filename"] = CandidateType.FilenameOrPath,
        ["regkey"] = CandidateType.RegistryKey,
        ["mutex"] = CandidateType.Mutex,
        ["email"] = CandidateType.EmailAddress,
        ["email-src"] = CandidateType.EmailAddress,
        ["email-dst"] = CandidateType.EmailAddress,
    };

    /// <summary>Composite parts that are legitimately not indicators (see class doc).</summary>
    private static readonly HashSet<string> IgnoredCompositeParts = new(StringComparer.OrdinalIgnoreCase)
    {
        "port", "value",
    };

    public static FeedReadResult Read(string content)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = MaxJsonDepth });
        }
        catch (JsonException e)
        {
            return FeedReadResult.Fail(StixReader.FormatJsonError(e));
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("Event", out var evt)
                || evt.ValueKind != JsonValueKind.Object)
            {
                return FeedReadResult.Fail("MISP document has no 'Event' object at the root");
            }

            // Event threat level becomes each indicator's severity (Indicator.Severity doc).
            var severity = ReadThreatLevel(evt);

            var candidates = new List<Candidate>();
            var rejections = new List<ReaderRejection>();

            if (evt.TryGetProperty("Attribute", out var attrs) && attrs.ValueKind == JsonValueKind.Array)
            {
                foreach (var attr in attrs.EnumerateArray())
                    ReadAttribute(attr, severity, candidates, rejections);
            }
            if (evt.TryGetProperty("Object", out var objects) && objects.ValueKind == JsonValueKind.Array)
            {
                foreach (var obj in objects.EnumerateArray())
                {
                    if (obj.ValueKind != JsonValueKind.Object)
                        continue;
                    if (obj.TryGetProperty("Attribute", out var objAttrs)
                        && objAttrs.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var attr in objAttrs.EnumerateArray())
                            ReadAttribute(attr, severity, candidates, rejections);
                    }
                }
            }

            return FeedReadResult.Ok(candidates, rejections);
        }
    }

    private static void ReadAttribute(
        JsonElement attr, string? severity, List<Candidate> candidates, List<ReaderRejection> rejections)
    {
        if (attr.ValueKind != JsonValueKind.Object)
            return;

        if (!TryGetString(attr, "type", out var type) || !TryGetString(attr, "value", out var value))
        {
            rejections.Add(new ReaderRejection(
                attr.GetRawText(), "attribute missing 'type' or 'value'"));
            return;
        }

        if (attr.TryGetProperty("deleted", out var deleted) && deleted.ValueKind == JsonValueKind.True)
        {
            rejections.Add(new ReaderRejection(value, "attribute is marked deleted"));
            return;
        }
        if (attr.TryGetProperty("to_ids", out var toIds) && toIds.ValueKind == JsonValueKind.False)
        {
            rejections.Add(new ReaderRejection(value, "attribute marked to_ids=false (not for detection)"));
            return;
        }

        var category = TryGetString(attr, "category", out var cat) && cat.Length > 0 ? cat : null;
        var comment = TryGetString(attr, "comment", out var com) && com.Length > 0 ? com : null;
        var label = (category, comment) switch
        {
            (null, null) => (string?)null,
            (not null, null) => category,
            (null, not null) => comment,
            _ => category + " | " + comment,
        };

        if (!type.Contains('|'))
        {
            if (!TypeMap.TryGetValue(type, out var candType))
            {
                rejections.Add(new ReaderRejection(value, $"unmapped MISP attribute type '{type}'"));
                return;
            }
            candidates.Add(new Candidate(candType, value, label, Confidence: null, severity, Expiry: null));
            return;
        }

        // Composite: "filename|sha256" with value "evil.exe|<hash>".
        var typeParts = type.Split('|');
        var valueParts = value.Split('|');
        if (typeParts.Length != valueParts.Length)
        {
            rejections.Add(new ReaderRejection(value,
                $"composite attribute '{type}' has {typeParts.Length} type parts but {valueParts.Length} value parts"));
            return;
        }
        // Validate every part before emitting any: a half-usable composite would otherwise
        // emit one candidate and reject the same raw value too.
        var parts = new List<Candidate>();
        for (var i = 0; i < typeParts.Length; i++)
        {
            if (IgnoredCompositeParts.Contains(typeParts[i]))
                continue;
            if (!TypeMap.TryGetValue(typeParts[i], out var partType))
            {
                rejections.Add(new ReaderRejection(value,
                    $"unmapped MISP attribute type '{type}' (part '{typeParts[i]}')"));
                return;
            }
            parts.Add(new Candidate(partType, valueParts[i], label, Confidence: null, severity, Expiry: null));
        }
        if (parts.Count == 0)
        {
            rejections.Add(new ReaderRejection(value,
                $"composite attribute '{type}' has no indicator-bearing part"));
            return;
        }
        candidates.AddRange(parts);
    }

    /// <summary>MISP <c>threat_level_id</c>: 1=high, 2=medium, 3=low, 4=undefined. Exports
    /// carry it as a JSON string; a number is accepted too. Unknown ids pass through as
    /// <c>threat_level_id=N</c> rather than being invented or dropped.</summary>
    private static string? ReadThreatLevel(JsonElement evt)
    {
        if (!evt.TryGetProperty("threat_level_id", out var el))
            return null;
        string? raw = el.ValueKind switch
        {
            JsonValueKind.String => el.GetString(),
            JsonValueKind.Number => el.TryGetInt32(out var n) ? n.ToString() : null,
            _ => null,
        };
        return raw switch
        {
            "1" => "high",
            "2" => "medium",
            "3" => "low",
            "4" => "undefined",
            null => null,
            _ => "threat_level_id=" + raw,
        };
    }

    private static bool TryGetString(JsonElement obj, string property, out string value)
    {
        if (obj.TryGetProperty(property, out var el) && el.ValueKind == JsonValueKind.String)
        {
            value = el.GetString()!;
            return true;
        }
        value = string.Empty;
        return false;
    }
}
