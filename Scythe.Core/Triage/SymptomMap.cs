using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Scythe.Core.Triage;

/// <summary>One symptom-database entry that fired against the technician's description:
/// which phrases hit, which detection categories that implies, and why (shown to the
/// operator — the mapping must always be explainable, never a black box).</summary>
public sealed class SymptomMatch
{
    /// <summary>The database entry that fired.</summary>
    public required string SymptomName { get; init; }

    /// <summary>Which of the entry's phrases were found in the input.</summary>
    public required IReadOnlyList<string> MatchedPhrases { get; init; }

    /// <summary>Scanner group names this symptom maps to (already validated against the
    /// scanner's real category list — unknown names are dropped and surfaced as
    /// <see cref="TriagePlan.Warnings"/>).</summary>
    public required IReadOnlyList<string> Categories { get; init; }

    /// <summary>Why these categories — shown to the operator alongside the plan.</summary>
    public required string Rationale { get; init; }

    /// <summary>QUICK | FULL | DEEP, or null when the entry suggests no depth.</summary>
    public string? SuggestedDepth { get; init; }
}

/// <summary>
/// The derived scan plan for a symptom description (spec §2 custom scans, driven from
/// operator triage input instead of hand-picked flags).
///
/// Fallback rule (spec §6.7 spirit — "couldn't determine" must never quietly shrink
/// coverage): when NOTHING matches, <see cref="Categories"/> is EMPTY, which means
/// "run every category", and <see cref="Mode"/> is FULL. The fallback is always a
/// BROAD scan, never a silently narrow one.
/// </summary>
public sealed class TriagePlan
{
    public required IReadOnlyList<SymptomMatch> Matches { get; init; }

    /// <summary>Input lines (trimmed, non-empty) in which no phrase from any fired entry
    /// occurs — shown to the operator so unrecognized symptoms are visible, not silently
    /// dropped.</summary>
    public required IReadOnlyList<string> UnmatchedInput { get; init; }

    /// <summary>Distinct union of the fired entries' categories, validated against the
    /// scanner's real group names. EMPTY means "run everything" (broad fallback).</summary>
    public required IReadOnlyList<string> Categories { get; init; }

    /// <summary>Deepest suggested depth across fired entries (QUICK &lt; FULL &lt; DEEP);
    /// FULL when nothing matched or nothing suggested a depth. Never shallower than FULL —
    /// a triage that suspects an infection never earns a QUICK scan.</summary>
    public required string Mode { get; init; }

    /// <summary>Data-quality notes surfaced at analysis time, e.g. a symptom entry naming
    /// a category this build's scanner does not have (the category is dropped from the
    /// plan and disclosed here, per spec §6.7: nothing vanishes silently).</summary>
    public required IReadOnlyList<string> Warnings { get; init; }

    /// <summary>Converts the plan into a runnable custom-scan profile: Mode, Only (null —
    /// i.e. every category — when <see cref="Categories"/> is empty), and a Description
    /// summarizing the matched symptoms for the report metadata.</summary>
    public Scanning.ScanProfile ToProfile(string name) => new()
    {
        Name = name,
        Description = Matches.Count == 0
            ? "symptom triage: no known symptom matched — broad scan of every category (fallback is broad, never narrow)"
            : "symptom triage: " + string.Join(", ", Matches.Select(m => m.SymptomName)),
        Mode = Mode,
        Only = Categories.Count > 0 ? Categories.ToList() : null,
    };
}

/// <summary>
/// Symptom-to-scan-plan mapping (spec §2 custom scans; data-file philosophy of spec §3):
/// a curated database of how technicians and end-users DESCRIBE infections in plain
/// language ("ransom note on desktop", "fans maxed out", "mouse moving by itself"),
/// each mapped to the detection categories worth scanning and a suggested depth.
///
/// Same philosophy as the signature files: the phrase database is DATA — an embedded
/// JSON resource (Triage/symptoms.json) plus optional operator extension files — never
/// logic inline in the engine, so it stays editable and auditable without a rebuild.
/// Matching is deterministic and fully offline: case-insensitive substring matching of
/// curated phrases against the normalized input, no scoring, no model, no network.
///
/// Depth policy: database entries suggest FULL or DEEP only. QUICK is accepted by the
/// schema but the computed <see cref="TriagePlan.Mode"/> is clamped to never fall below
/// FULL — describing a suspected infection never earns a shallower-than-FULL scan.
/// </summary>
public sealed class SymptomMap
{
    private readonly List<SymptomEntry> _entries = new();
    private readonly List<string> _loadErrors = new();

    /// <summary>Problems found while loading symptom data (bad JSON, empty phrase lists,
    /// invalid depth values). Non-fatal — well-formed entries still load — but must be
    /// shown to the operator, never swallowed (spec §6.7).</summary>
    public IReadOnlyList<string> LoadErrors => _loadErrors;

    /// <summary>Loads the embedded Triage/symptoms.json database.</summary>
    public static SymptomMap LoadEmbedded()
    {
        var map = new SymptomMap();
        var asm = typeof(SymptomMap).Assembly;
        var res = asm.GetManifestResourceNames()
            .FirstOrDefault(r => r.EndsWith(".Triage.symptoms.json", StringComparison.OrdinalIgnoreCase));
        if (res is null)
        {
            map._loadErrors.Add("embedded Triage/symptoms.json resource not found");
            return map;
        }
        try
        {
            using var stream = asm.GetManifestResourceStream(res)!;
            using var reader = new StreamReader(stream);
            map.MergeJson(reader.ReadToEnd(), res);
        }
        catch (Exception ex)
        {
            map._loadErrors.Add($"{res}: {ex.Message}");
        }
        return map;
    }

    /// <summary>Loads an operator extension file (same JSON shape as the embedded
    /// database). Parse problems land in <see cref="LoadErrors"/>; unknown JSON property
    /// names are rejected rather than ignored, same rationale as
    /// <see cref="Scanning.ScanProfile"/> — a misspelled field that silently vanished
    /// would make triage quietly different from what the operator wrote.</summary>
    public void LoadFile(string path)
    {
        try { MergeJson(File.ReadAllText(path), path); }
        catch (Exception ex) { _loadErrors.Add($"{path}: {ex.Message}"); }
    }

    /// <summary>
    /// Derives a scan plan from a free-text symptom description.
    ///
    /// Semantics: the input is normalized (lowercased, whitespace collapsed); a database
    /// entry fires when ANY of its phrases occurs as a case-insensitive substring of the
    /// normalized text. Categories are the distinct union of fired entries' categories,
    /// validated against <paramref name="validCategories"/> (the scanner's real group
    /// names) — an entry naming an unknown category has it dropped AND disclosed via
    /// <see cref="TriagePlan.Warnings"/>. Input lines no fired entry's phrase occurs in
    /// are returned as <see cref="TriagePlan.UnmatchedInput"/>.
    ///
    /// Zero matches → empty Categories (= run everything) at FULL depth: the fallback is
    /// a BROAD scan, never a silently narrow one (spec §6.7 spirit — an unrecognized
    /// description must widen coverage, not shrink it).
    /// </summary>
    public TriagePlan Analyze(string freeText, IReadOnlyCollection<string> validCategories)
    {
        var text = freeText ?? string.Empty;
        var normalizedText = Normalize(text);
        var lines = text.Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0)
            .ToList();

        var matches = new List<SymptomMatch>();
        var fired = new List<SymptomEntry>();
        var categories = new List<string>();
        var warnings = new List<string>();

        foreach (var entry in _entries)
        {
            var hits = entry.Phrases
                .Where(p => normalizedText.Contains(p.Normalized, StringComparison.Ordinal))
                .Select(p => p.Original)
                .ToList();
            if (hits.Count == 0) continue;

            fired.Add(entry);
            var entryCategories = new List<string>();
            foreach (var c in entry.Categories)
            {
                // Validate against the scanner's REAL group names, and emit the scanner's
                // canonical casing so the resulting profile round-trips cleanly.
                var canonical = validCategories.FirstOrDefault(
                    v => string.Equals(v, c, StringComparison.OrdinalIgnoreCase));
                if (canonical is null)
                {
                    var warning = $"symptom '{entry.Name}' names unknown category '{c}' — ignored";
                    if (!warnings.Contains(warning)) warnings.Add(warning);
                    continue;
                }
                if (!entryCategories.Contains(canonical, StringComparer.Ordinal))
                    entryCategories.Add(canonical);
                if (!categories.Contains(canonical, StringComparer.Ordinal))
                    categories.Add(canonical);
            }

            matches.Add(new SymptomMatch
            {
                SymptomName = entry.Name,
                MatchedPhrases = hits,
                Categories = entryCategories,
                Rationale = entry.Rationale,
                SuggestedDepth = entry.Depth,
            });
        }

        // A line is "unmatched" when no phrase from any FIRED entry occurs in it — those
        // are symptoms the database did not recognize, shown to the operator explicitly.
        var unmatched = lines
            .Where(line =>
            {
                var normalizedLine = Normalize(line);
                return !fired.Any(e => e.Phrases.Any(
                    p => normalizedLine.Contains(p.Normalized, StringComparison.Ordinal)));
            })
            .ToList();

        // Deepest suggested depth wins; clamped so the plan is never shallower than FULL.
        var rank = DepthRank("FULL");
        foreach (var m in matches)
            if (m.SuggestedDepth is not null)
                rank = Math.Max(rank, DepthRank(m.SuggestedDepth));

        return new TriagePlan
        {
            Matches = matches,
            UnmatchedInput = unmatched,
            Categories = categories,
            Mode = rank >= DepthRank("DEEP") ? "DEEP" : "FULL",
            Warnings = warnings,
        };
    }

    private static int DepthRank(string depth) => depth switch
    {
        "QUICK" => 0,
        "FULL" => 1,
        "DEEP" => 2,
        _ => 1,
    };

    /// <summary>Lowercase, whitespace collapsed to single spaces — the one normalization
    /// applied to both the input text and every database phrase, so matching stays
    /// deterministic and layout-insensitive.</summary>
    private static string Normalize(string text) =>
        Regex.Replace(text, @"\s+", " ").Trim().ToLowerInvariant();

    private void MergeJson(string json, string sourceName)
    {
        SymptomFile? doc;
        try
        {
            doc = JsonSerializer.Deserialize<SymptomFile>(json, JsonOpts);
        }
        catch (JsonException ex)
        {
            _loadErrors.Add(
                $"{sourceName}: not valid symptom JSON: {ex.Message} " +
                "(note: unknown property names are rejected on purpose — check spelling)");
            return;
        }
        if (doc?.Symptoms is null)
        {
            _loadErrors.Add($"{sourceName}: no 'symptoms' array found");
            return;
        }

        foreach (var s in doc.Symptoms)
        {
            if (string.IsNullOrWhiteSpace(s.Name))
            {
                _loadErrors.Add($"{sourceName}: symptom entry with empty name skipped");
                continue;
            }
            if (s.Phrases is null || s.Phrases.Count == 0)
            {
                _loadErrors.Add($"{sourceName}: symptom '{s.Name}' has no phrases — skipped");
                continue;
            }
            if (s.Categories is null || s.Categories.Count == 0)
            {
                _loadErrors.Add($"{sourceName}: symptom '{s.Name}' has no categories — skipped");
                continue;
            }

            var phrases = new List<(string Original, string Normalized)>();
            foreach (var p in s.Phrases)
            {
                if (string.IsNullOrWhiteSpace(p))
                {
                    _loadErrors.Add($"{sourceName}: symptom '{s.Name}' has an empty phrase — phrase skipped");
                    continue;
                }
                phrases.Add((p, Normalize(p)));
            }
            if (phrases.Count == 0)
            {
                _loadErrors.Add($"{sourceName}: symptom '{s.Name}' has no usable phrases — skipped");
                continue;
            }

            string? depth = s.Depth?.Trim().ToUpperInvariant();
            if (depth is not null and not ("QUICK" or "FULL" or "DEEP"))
            {
                _loadErrors.Add(
                    $"{sourceName}: symptom '{s.Name}' has invalid depth '{s.Depth}' " +
                    "(expected QUICK, FULL, or DEEP) — depth ignored");
                depth = null;
            }

            _entries.Add(new SymptomEntry
            {
                Name = s.Name.Trim(),
                Phrases = phrases,
                Categories = s.Categories.Where(c => !string.IsNullOrWhiteSpace(c)).Select(c => c.Trim()).ToList(),
                Depth = depth,
                Rationale = s.Rationale?.Trim() ?? string.Empty,
            });
        }
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private sealed class SymptomEntry
    {
        public required string Name { get; init; }
        public required List<(string Original, string Normalized)> Phrases { get; init; }
        public required List<string> Categories { get; init; }
        public string? Depth { get; init; }
        public required string Rationale { get; init; }
    }

    private sealed class SymptomFile
    {
        public List<SymptomJson>? Symptoms { get; set; }
    }

    private sealed class SymptomJson
    {
        public string? Name { get; set; }
        public List<string>? Phrases { get; set; }
        public List<string>? Categories { get; set; }
        public string? Depth { get; set; }
        public string? Rationale { get; set; }
    }
}
