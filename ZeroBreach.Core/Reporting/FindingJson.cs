using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroBreach.Core.Model;

namespace ZeroBreach.Core.Reporting;

/// <summary>Wire shape for a finding — snake_case field names exactly per spec §5.</summary>
public sealed class FindingJson
{
    [JsonPropertyName("id")] public required string Id { get; init; }
    [JsonPropertyName("severity")] public required string Severity { get; init; }
    [JsonPropertyName("description")] public required string Description { get; init; }
    [JsonPropertyName("target")] public required string Target { get; init; }
    [JsonPropertyName("fix_action")] public required string FixAction { get; init; }
    [JsonPropertyName("fix_param")] public string? FixParam { get; init; }
    [JsonPropertyName("mitre")] public MitreJson? Mitre { get; init; }
    [JsonPropertyName("group")] public required string Group { get; init; }
    [JsonPropertyName("vendor_trusted")] public bool VendorTrusted { get; init; }
    [JsonPropertyName("hash_confirmed")] public bool HashConfirmed { get; init; }
    [JsonPropertyName("check")] public string? Check { get; init; }

    /// <summary>Present only when in-run escalation armed the indicator that surfaced this
    /// finding: the id of the earlier finding it descends from. Such a finding is real, but it
    /// is not independent evidence, and the correlation pass does not let it corroborate.</summary>
    [JsonPropertyName("derived_from")] public string? DerivedFrom { get; init; }

    public sealed class MitreJson
    {
        [JsonPropertyName("technique_id")] public required string TechniqueId { get; init; }
        [JsonPropertyName("technique_name")] public required string TechniqueName { get; init; }
        [JsonPropertyName("tactic")] public required string Tactic { get; init; }
    }

    public static FindingJson From(Finding f) => new()
    {
        Id = f.Id,
        Severity = f.Severity.ToString().ToUpperInvariant(),
        Description = f.Description,
        Target = f.Target,
        FixAction = f.FixAction.ToWire(),
        FixParam = f.FixParam,
        Mitre = f.Mitre is null ? null : new MitreJson
        {
            TechniqueId = f.Mitre.TechniqueId,
            TechniqueName = f.Mitre.TechniqueName,
            Tactic = f.Mitre.Tactic,
        },
        Group = f.Group,
        VendorTrusted = f.VendorTrusted,
        HashConfirmed = f.HashConfirmed,
        Check = f.Check,
        DerivedFrom = f.DerivedFromFindingId,
    };

    public static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string ToJsonLine(Finding f) => JsonSerializer.Serialize(From(f), Options);
}
