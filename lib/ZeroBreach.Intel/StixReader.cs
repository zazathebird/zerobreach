namespace ZeroBreach.Intel;

using System.Globalization;
using System.Text.Json;

/// <summary>
/// STIX 2.x bundle reader. Consumes the <c>objects</c> array, extracts objects with
/// <c>type == "indicator"</c>, and parses each one's <c>pattern</c> through
/// <see cref="StixPatternParser"/>.
///
/// Objects of other types (malware, relationship, identity, …) are a normal part of a bundle
/// and are skipped without a rejection — they are not indicator candidates, so skipping them
/// is not dropping an indicator. Everything about an *indicator* object that cannot be used,
/// though, is a named rejection: unsupported pattern_type, revoked, missing pattern,
/// unsupported pattern construct, unparseable metadata.
/// </summary>
internal static class StixReader
{
    /// <summary>JsonDocument's own depth ceiling. Deeper input is hostile for this format
    /// (real bundles nest 4–5 levels) and fails loudly with a position via JsonException.</summary>
    private const int MaxJsonDepth = 64;

    public static FeedReadResult Read(string content)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = MaxJsonDepth });
        }
        catch (JsonException e)
        {
            return FeedReadResult.Fail(FormatJsonError(e));
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return FeedReadResult.Fail("STIX document root is not a JSON object");
            if (!root.TryGetProperty("objects", out var objects) || objects.ValueKind != JsonValueKind.Array)
                return FeedReadResult.Fail("STIX bundle has no 'objects' array");

            var candidates = new List<Candidate>();
            var rejections = new List<ReaderRejection>();

            foreach (var obj in objects.EnumerateArray())
            {
                if (obj.ValueKind != JsonValueKind.Object)
                    continue;
                if (!TryGetString(obj, "type", out var type) || type != "indicator")
                    continue;

                var display = TryGetString(obj, "id", out var id) ? id : "(indicator without id)";

                if (obj.TryGetProperty("revoked", out var revoked)
                    && revoked.ValueKind == JsonValueKind.True)
                {
                    // The STIX spec says a revoked object must no longer be used; keeping it
                    // would resurrect a withdrawn indicator, silently dropping it would hide
                    // that the feed withdrew something. Reported, not used.
                    rejections.Add(new ReaderRejection(display, "indicator is revoked"));
                    continue;
                }

                if (TryGetString(obj, "pattern_type", out var patternType)
                    && !string.Equals(patternType, "stix", StringComparison.OrdinalIgnoreCase))
                {
                    rejections.Add(new ReaderRejection(display,
                        $"unsupported pattern_type '{patternType}' (only 'stix' is supported)"));
                    continue;
                }

                if (!TryGetString(obj, "pattern", out var pattern) || pattern.Length == 0)
                {
                    rejections.Add(new ReaderRejection(display, "indicator has no pattern"));
                    continue;
                }

                if (!StixPatternParser.TryParse(pattern, out var comparisons, out var reason))
                {
                    rejections.Add(new ReaderRejection(pattern, reason!));
                    continue;
                }

                // Metadata is parsed before emitting candidates so that a bad valid_until
                // rejects the whole indicator loudly rather than quietly shedding its expiry.
                DateTimeOffset? expiry = null;
                if (TryGetString(obj, "valid_until", out var validUntil))
                {
                    if (!DateTimeOffset.TryParse(validUntil, CultureInfo.InvariantCulture,
                            DateTimeStyles.RoundtripKind, out var parsed))
                    {
                        rejections.Add(new ReaderRejection(display,
                            $"unparseable valid_until timestamp '{validUntil}'"));
                        continue;
                    }
                    expiry = parsed;
                }

                int? confidence = null;
                if (obj.TryGetProperty("confidence", out var conf))
                {
                    if (conf.ValueKind != JsonValueKind.Number || !conf.TryGetInt32(out var c))
                    {
                        rejections.Add(new ReaderRejection(display, "confidence is not an integer"));
                        continue;
                    }
                    confidence = c;
                }

                var label = BuildLabel(obj);

                foreach (var (candType, value) in comparisons)
                {
                    candidates.Add(new Candidate(
                        candType, value, label, confidence, Severity: null, expiry));
                }
            }

            return FeedReadResult.Ok(candidates, rejections);
        }
    }

    /// <summary>Label = indicator name, then its labels[] joined: <c>name [a, b]</c>.</summary>
    private static string? BuildLabel(JsonElement obj)
    {
        var name = TryGetString(obj, "name", out var n) ? n : null;
        string? labels = null;
        if (obj.TryGetProperty("labels", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            var parts = new List<string>();
            foreach (var item in arr.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                    parts.Add(item.GetString()!);
            }
            if (parts.Count > 0)
                labels = "[" + string.Join(", ", parts) + "]";
        }
        return (name, labels) switch
        {
            (null, null) => null,
            (not null, null) => name,
            (null, not null) => labels,
            _ => name + " " + labels,
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

    /// <summary>JsonException positions are zero-based; report one-based like every other
    /// error in this package.</summary>
    internal static string FormatJsonError(JsonException e)
    {
        var line = (e.LineNumber ?? 0) + 1;
        var col = (e.BytePositionInLine ?? 0) + 1;
        return $"malformed JSON at line {line}, column {col}: {TrimNetPositionSuffix(e.Message)}";
    }

    /// <summary>System.Text.Json appends its own zero-based "LineNumber: n | BytePositionInLine:
    /// m" tail; strip it so the message carries exactly one (one-based) position.</summary>
    private static string TrimNetPositionSuffix(string message)
    {
        var idx = message.IndexOf(" LineNumber:", StringComparison.Ordinal);
        if (idx > 0)
            message = message[..idx].TrimEnd();
        return message;
    }
}
