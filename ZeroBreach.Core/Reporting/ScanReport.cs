using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroBreach.Core.Model;
using ZeroBreach.Core.Scanning;

namespace ZeroBreach.Core.Reporting;

/// <summary>Full machine-readable run report (spec §7): metadata, findings, check statuses
/// (including every inconclusive/unchecked item), summary.</summary>
public sealed class ScanReport
{
    [JsonPropertyName("tool")] public string Tool { get; init; } = "ZeroBreach Scan Engine";
    [JsonPropertyName("version")] public required string Version { get; init; }
    [JsonPropertyName("host")] public required string Host { get; init; }
    [JsonPropertyName("started_utc")] public required DateTime StartedUtc { get; init; }
    [JsonPropertyName("mode")] public required string Mode { get; init; }

    /// <summary>Optional engagement metadata for MSP/IR workflows (spec §7). Null when not
    /// supplied — the serializer omits null, so pre-existing report consumers are unaffected.</summary>
    [JsonPropertyName("case_id")] public string? CaseId { get; init; }
    [JsonPropertyName("operator")] public string? Operator { get; init; }

    [JsonPropertyName("findings")] public required List<FindingJson> Findings { get; init; }
    [JsonPropertyName("checks")] public required List<CheckJson> Checks { get; init; }

    /// <summary>Per-phase wall-clock timings (spec §7). Null when the caller did not supply
    /// them — the serializer omits null, so pre-existing report consumers are unaffected.</summary>
    [JsonPropertyName("phases")] public List<PhaseJson>? Phases { get; init; }

    /// <summary>Present when a baseline diff was applied: what it suppressed and any sanity
    /// warnings. A diffed report must never be indistinguishable from a clean one — hidden
    /// findings reading as clean in the artifact of record is the §6.7 sin.</summary>
    [JsonPropertyName("baseline")] public BaselineJson? Baseline { get; init; }

    [JsonPropertyName("summary")] public required SummaryJson Summary { get; init; }

    public sealed class BaselineJson
    {
        [JsonPropertyName("path")] public required string Path { get; init; }
        [JsonPropertyName("host")] public required string Host { get; init; }
        [JsonPropertyName("created_utc")] public DateTime CreatedUtc { get; init; }
        [JsonPropertyName("suppressed")] public int Suppressed { get; init; }
        [JsonPropertyName("warnings")] public required List<string> Warnings { get; init; }
    }

    public sealed class PhaseJson
    {
        [JsonPropertyName("phase")] public int Phase { get; init; }
        [JsonPropertyName("name")] public required string Name { get; init; }
        [JsonPropertyName("elapsed_seconds")] public double ElapsedSeconds { get; init; }
        [JsonPropertyName("findings")] public int Findings { get; init; }
    }

    public sealed class CheckJson
    {
        [JsonPropertyName("phase")] public int Phase { get; init; }
        [JsonPropertyName("check")] public required string Check { get; init; }
        [JsonPropertyName("outcome")] public required string Outcome { get; init; }
        [JsonPropertyName("detail")] public string? Detail { get; init; }
    }

    public sealed class SummaryJson
    {
        [JsonPropertyName("critical")] public int Critical { get; init; }
        [JsonPropertyName("high")] public int High { get; init; }
        [JsonPropertyName("possible")] public int Possible { get; init; }
        [JsonPropertyName("info")] public int Info { get; init; }
        [JsonPropertyName("checks_completed")] public int ChecksCompleted { get; init; }
        [JsonPropertyName("checks_inconclusive")] public int ChecksInconclusive { get; init; }
        [JsonPropertyName("checks_skipped")] public int ChecksSkipped { get; init; }
        [JsonPropertyName("elapsed_seconds")] public double ElapsedSeconds { get; init; }
        [JsonPropertyName("verdict")] public required string Verdict { get; init; }
    }

    public static ScanReport Build(string version, string mode, DateTime startedUtc,
        IReadOnlyList<Finding> findings, IReadOnlyList<CheckStatus> checks, ScanSummary summary,
        IReadOnlyList<PhaseTiming>? phaseTimings = null,
        string? caseId = null, string? operatorName = null,
        BaselineJson? baseline = null) => new()
    {
        Version = version,
        Host = Environment.MachineName,
        StartedUtc = startedUtc,
        Mode = mode,
        CaseId = caseId,
        Operator = operatorName,
        Baseline = baseline,
        Findings = findings.Select(FindingJson.From).ToList(),
        Checks = checks.Select(c => new CheckJson
        {
            Phase = c.Phase,
            Check = c.Check,
            Outcome = c.Outcome.ToString().ToLowerInvariant(),
            Detail = c.Detail,
        }).ToList(),
        Phases = phaseTimings?.Select(t => new PhaseJson
        {
            Phase = t.Phase,
            Name = t.Name,
            ElapsedSeconds = Math.Round(t.Elapsed.TotalSeconds, 3),
            Findings = t.FindingCount,
        }).ToList(),
        Summary = new SummaryJson
        {
            Critical = summary.Critical, High = summary.High,
            Possible = summary.Possible, Info = summary.Info,
            ChecksCompleted = summary.ChecksCompleted,
            ChecksInconclusive = summary.ChecksInconclusive,
            ChecksSkipped = summary.ChecksSkipped,
            ElapsedSeconds = summary.Elapsed.TotalSeconds,
            Verdict = summary.Verdict,
        },
    };

    public string ToJson() => JsonSerializer.Serialize(this, JsonOpts);

    /// <summary>STEALTH output (spec §2): the whole report as one gzip-compressed JSON blob.</summary>
    public void WriteCompressed(string path)
    {
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.SmallestSize);
        gz.Write(Encoding.UTF8.GetBytes(ToJson()));
    }

    /// <summary>Reads back a saved report — plain .json or the STEALTH .json.gz blob
    /// (spec §2/§7): a stealth run's only output must be consumable later without rescanning.
    /// Gzip is detected by content (magic bytes 0x1F 0x8B), not by extension, so a renamed
    /// blob still loads.</summary>
    public static ScanReport Load(string path)
    {
        var raw = File.ReadAllBytes(path);
        if (raw.Length >= 2 && raw[0] == 0x1F && raw[1] == 0x8B)
        {
            try
            {
                using var input = new MemoryStream(raw);
                using var gz = new GZipStream(input, CompressionMode.Decompress);
                using var decompressed = new MemoryStream();
                gz.CopyTo(decompressed);
                raw = decompressed.ToArray();
            }
            catch (InvalidDataException ex)
            {
                throw new InvalidDataException($"'{path}' is not a valid scan report: {ex.Message}", ex);
            }
        }
        try
        {
            return JsonSerializer.Deserialize<ScanReport>(raw, JsonOpts)
                ?? throw new InvalidDataException($"'{path}' does not contain a scan report.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"'{path}' is not a valid scan report: {ex.Message}", ex);
        }
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
