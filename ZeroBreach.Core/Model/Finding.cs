using System.Security.Cryptography;
using System.Text;

namespace ZeroBreach.Core.Model;

/// <summary>A single scan finding, shaped per spec §5.</summary>
public sealed class Finding
{
    /// <summary>Stable deterministic id — see <see cref="ComputeId"/>.</summary>
    public required string Id { get; init; }

    public required Severity Severity { get; init; }

    public required string Description { get; init; }

    /// <summary>File path / registry key / process / task name affected.</summary>
    public required string Target { get; init; }

    public FixAction FixAction { get; init; } = FixAction.None;

    /// <summary>Command/path needed to apply FixAction, if any.</summary>
    public string? FixParam { get; init; }

    public MitreRef? Mitre { get; init; }

    /// <summary>Category label matching spec §3 groups.</summary>
    public required string Group { get; init; }

    /// <summary>Set when the target matched the "vendor trusted" soft-list (§6.3).
    /// Displayed as a trust badge; the finding stays fully actionable.</summary>
    public bool VendorTrusted { get; init; }

    /// <summary>True only when the artifact's cryptographic hash matched a known-bad hash.
    /// Gates delete-vs-quarantine preference (§6.4): anything not hash-confirmed is
    /// quarantined instead of deleted.</summary>
    public bool HashConfirmed { get; init; }

    /// <summary>Name of the check that produced this finding (for reports/inconclusive cross-ref).</summary>
    public string? Check { get; init; }

    /// <summary>Set by the engine (never by a scanner) when this finding was surfaced by an
    /// indicator that in-run escalation armed from an EARLIER finding — the id of that source
    /// finding. Such a finding is not independent evidence: it exists because the engine went
    /// looking for it, so the cross-phase correlation pass must not count it as agreement
    /// (that would be circular corroboration, inflating severity from a single original
    /// signal). Null for everything an operator-supplied IOC or a shipped signature found.</summary>
    public string? DerivedFromFindingId { get; internal set; }

    /// <summary>
    /// Deterministic finding identity (spec §5): SHA-256 over the full identity of the thing
    /// found — group + target + discriminator. Never a bare filename, never random or
    /// per-run, so baseline diffs work and same-named artifacts don't collide.
    /// The discriminator distinguishes multiple findings on one target
    /// (e.g. registry value name, rule id, task action).
    /// </summary>
    public static string ComputeId(string group, string target, string discriminator)
    {
        // Normalize case: registry/file paths on Windows are case-insensitive, and the same
        // artifact must produce the same id from run to run. The \u001f unit separators keep
        // the three identity parts unambiguous (written as escapes on purpose — a literal
        // control char here is invisible and reads as missing).
        var identity = $"{group.ToLowerInvariant()}\u001f{target.ToLowerInvariant()}\u001f{discriminator.ToLowerInvariant()}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(identity));
        return Convert.ToHexString(hash.AsSpan(0, 16)).ToLowerInvariant();
    }
}
