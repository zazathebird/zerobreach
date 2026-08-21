using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroBreach.Core.Model;

namespace ZeroBreach.Core.Reporting;

/// <summary>Baseline-diff support (spec §2): a saved set of finding ids from a prior run.
/// Diff mode only works because finding ids are deterministic (spec §5).</summary>
public sealed class Baseline
{
    [JsonPropertyName("host")] public required string Host { get; init; }
    [JsonPropertyName("created_utc")] public required DateTime CreatedUtc { get; init; }
    [JsonPropertyName("finding_ids")] public required HashSet<string> FindingIds { get; init; }

    public static Baseline FromFindings(IEnumerable<Finding> findings) => new()
    {
        Host = Environment.MachineName,
        CreatedUtc = DateTime.UtcNow,
        FindingIds = findings.Select(f => f.Id).ToHashSet(StringComparer.OrdinalIgnoreCase),
    };

    public void Save(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));

    public static Baseline Load(string path)
    {
        var loaded = JsonSerializer.Deserialize<Baseline>(File.ReadAllText(path))
            ?? throw new InvalidDataException($"baseline file {path} is empty or malformed");
        // The serializer builds a default-comparer set; rewrap so id matching stays
        // case-insensitive even for hand-edited baseline files.
        return new Baseline
        {
            Host = loaded.Host,
            CreatedUtc = loaded.CreatedUtc,
            FindingIds = new HashSet<string>(loaded.FindingIds, StringComparer.OrdinalIgnoreCase),
        };
    }

    /// <summary>Splits findings into new-vs-known. Known findings are suppressed from the
    /// main report but their count is always disclosed (a baseline must not silently hide).</summary>
    public (IReadOnlyList<Finding> New, int Suppressed) Diff(IReadOnlyList<Finding> findings)
    {
        var fresh = findings.Where(f => !FindingIds.Contains(f.Id)).ToList();
        return (fresh, findings.Count - fresh.Count);
    }

    /// <summary>Maximum baseline age before a staleness warning is emitted.</summary>
    private static readonly TimeSpan StaleAfter = TimeSpan.FromDays(30);

    /// <summary>Tolerated clock skew before a future-dated CreatedUtc is treated as suspect.</summary>
    private static readonly TimeSpan ClockSkewTolerance = TimeSpan.FromMinutes(5);

    /// <summary>Sanity warnings the operator must see before this baseline is allowed to
    /// suppress findings (a wrong baseline hides real findings — spec §6.7 spirit).
    /// Pure function: the caller supplies <paramref name="nowUtc"/>, so results are
    /// deterministic and testable. Returns an empty list when the baseline looks sane.</summary>
    public IReadOnlyList<string> SafetyWarnings(string currentHost, DateTime nowUtc)
    {
        var warnings = new List<string>();

        if (!string.Equals(Host, currentHost, StringComparison.OrdinalIgnoreCase))
        {
            warnings.Add(
                $"baseline was created on host '{Host}' but this scan is running on '{currentHost}' " +
                "— a foreign baseline can suppress real findings on this machine");
        }

        var age = nowUtc - CreatedUtc;
        if (age > StaleAfter)
        {
            warnings.Add(
                $"baseline is {(int)age.TotalDays} days old — the machine may have drifted far from " +
                "it; refresh with --save-baseline after reviewing a full scan");
        }
        else if (CreatedUtc - nowUtc > ClockSkewTolerance)
        {
            warnings.Add(
                $"baseline timestamp {CreatedUtc:u} is in the future relative to this scan " +
                $"({nowUtc:u}) — clock skew or an edited baseline file");
        }

        return warnings;
    }
}
