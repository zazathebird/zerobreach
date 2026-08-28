using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Scythe.Core.Scanning;

namespace Scythe.Core.Triage;

/// <summary>Post-scan deeper-pass generator: the leads gathered during a run become a DEEP
/// follow-up scan profile plus an IOC file, written beside the reports. The follow-up is
/// GENERATED, never auto-run — the CLI asks the operator before chaining (spec §6 spirit:
/// scan scope changes are operator decisions). Everything written here is detection-only
/// input: loading the IOC file lands its indicators in the custom.* sets at POSSIBLE
/// severity with no fix action (see <see cref="Signatures.SignatureDb.LoadIocFile"/>).</summary>
public sealed class FollowUpPlan
{
    /// <summary>Null when <paramref name="leads"/> is empty — no leads, no follow-up to offer.</summary>
    public static FollowUpPlan? Build(IReadOnlyList<Lead> leads) =>
        leads.Count == 0 ? null : new FollowUpPlan { Leads = leads };

    public required IReadOnlyList<Lead> Leads { get; init; }

    /// <summary>A follow-up is always the deepest preset: the point of the second pass is to
    /// look harder at a machine the first pass already found suspicious.</summary>
    public string Mode => "DEEP";

    /// <summary>Writes three files into <paramref name="dir"/>: <c>{stem}-leads.json</c>
    /// (full lead records: indicator, kind, source_finding_id, source_phase, source_severity),
    /// <c>{stem}-leads.iocs.txt</c> (one indicator per line, '#' header comment saying where
    /// it came from), and <c>{stem}-followup.profile.json</c> (a <see cref="ScanProfile"/>:
    /// mode DEEP, no category narrowing — a follow-up widens, never narrows — iocFile pointing
    /// at the .iocs.txt by filename so the pair can travel together, description naming the
    /// source scan stem). Returns the three paths.</summary>
    public (string LeadsPath, string IocPath, string ProfilePath) Write(string dir, string stem)
    {
        var leadsPath = Path.Combine(dir, $"{stem}-leads.json");
        var iocName = $"{stem}-leads.iocs.txt";
        var iocPath = Path.Combine(dir, iocName);
        var profilePath = Path.Combine(dir, $"{stem}-followup.profile.json");

        File.WriteAllText(leadsPath,
            JsonSerializer.Serialize(Leads.Select(LeadJson.From).ToList(), JsonOpts));

        // Plain-text IOC list in the exact shape SignatureDb.LoadIocFile reads back:
        // '#' comments, one indicator per line, classified by shape on load.
        var ioc = new StringBuilder();
        ioc.AppendLine($"# Scythe adaptive-scan leads: {Leads.Count} indicator(s) derived mid-scan " +
                       $"from findings of scan '{stem}'.");
        ioc.AppendLine($"# Detection-only (spec §6.6): a hit reports a POSSIBLE finding with no fix action. " +
                       $"Full provenance in {stem}-leads.json.");
        foreach (var lead in Leads)
            ioc.AppendLine(lead.Indicator);
        File.WriteAllText(iocPath, ioc.ToString());

        // Built through ScanProfile itself so the output is loadable by ScanProfile.Load by
        // construction. No Only/Skip on purpose: a follow-up widens the scan, never narrows it.
        var profile = new ScanProfile
        {
            Name = $"{stem}-followup",
            Description = $"auto-generated deeper follow-up from the leads of scan '{stem}' — " +
                          "generated only, never auto-run; the operator decides whether to chain it",
            Mode = Mode,
            IocFile = iocName, // by filename: relative paths resolve against the profile's own directory
        };
        File.WriteAllText(profilePath, profile.ToJson());

        return (leadsPath, iocPath, profilePath);
    }

    /// <summary>Wire shape for one lead — snake_case field names per the repo's report
    /// conventions (see FindingJson / ScanReport).</summary>
    private sealed class LeadJson
    {
        [JsonPropertyName("indicator")] public required string Indicator { get; init; }
        [JsonPropertyName("kind")] public required string Kind { get; init; }
        [JsonPropertyName("source_finding_id")] public required string SourceFindingId { get; init; }
        [JsonPropertyName("source_phase")] public int SourcePhase { get; init; }
        [JsonPropertyName("source_severity")] public required string SourceSeverity { get; init; }

        public static LeadJson From(Lead l) => new()
        {
            Indicator = l.Indicator,
            Kind = l.Kind.ToString().ToLowerInvariant(),
            SourceFindingId = l.SourceFindingId,
            SourcePhase = l.SourcePhase,
            SourceSeverity = l.SourceSeverity.ToString().ToUpperInvariant(),
        };
    }

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
}
