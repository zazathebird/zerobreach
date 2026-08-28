using System.Text.Json;
using System.Text.Json.Serialization;
using Scythe.Core.Util;

namespace Scythe.Remediation;

/// <summary>
/// Reversible file remediation (spec §6.4): move into a vault folder with a neutralized
/// name plus a JSON manifest holding the original path, so the action can be undone.
/// </summary>
public sealed class QuarantineVault
{
    private readonly string _root;

    public QuarantineVault(string? root = null) => _root = root ?? ScythePaths.VaultDir;

    public sealed class Manifest
    {
        [JsonPropertyName("quarantine_id")] public required string QuarantineId { get; init; }
        [JsonPropertyName("original_path")] public required string OriginalPath { get; init; }
        [JsonPropertyName("vault_file")] public required string VaultFile { get; init; }
        [JsonPropertyName("sha256")] public string? Sha256 { get; init; }
        [JsonPropertyName("size_bytes")] public long SizeBytes { get; init; }
        [JsonPropertyName("finding_id")] public string? FindingId { get; init; }
        [JsonPropertyName("quarantined_utc")] public DateTime QuarantinedUtc { get; init; }
    }

    /// <summary>Moves the file into the vault. Throws on failure (caller logs the outcome).</summary>
    public Manifest Quarantine(string filePath, string? findingId)
    {
        var full = Path.GetFullPath(filePath);
        var info = new FileInfo(full);
        if (!info.Exists) throw new FileNotFoundException("file to quarantine does not exist", full);

        Directory.CreateDirectory(_root);
        var qid = $"{DateTime.UtcNow:yyyyMMddHHmmss}_{Guid.NewGuid():N}"[..28];
        var vaultFile = Path.Combine(_root, qid + ".quar");

        var manifest = new Manifest
        {
            QuarantineId = qid,
            OriginalPath = full,
            VaultFile = vaultFile,
            Sha256 = FileHasher.Sha256(full),
            SizeBytes = info.Length,
            FindingId = findingId,
            QuarantinedUtc = DateTime.UtcNow,
        };

        // Write the manifest FIRST: if the move then fails halfway, the manifest still
        // records where the file belongs.
        File.WriteAllText(ManifestPath(qid), JsonSerializer.Serialize(manifest, Indented));
        File.Move(full, vaultFile);
        return manifest;
    }

    /// <summary>Restores a quarantined file to its original location. Refuses to overwrite.</summary>
    public Manifest Restore(string quarantineId)
    {
        var manifest = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(ManifestPath(quarantineId)))
            ?? throw new InvalidDataException("manifest unreadable");
        if (!File.Exists(manifest.VaultFile))
            throw new FileNotFoundException("vault file missing", manifest.VaultFile);
        if (File.Exists(manifest.OriginalPath))
            throw new IOException($"a file already exists at {manifest.OriginalPath}; not overwriting");

        Directory.CreateDirectory(Path.GetDirectoryName(manifest.OriginalPath)!);
        File.Move(manifest.VaultFile, manifest.OriginalPath);
        return manifest;
    }

    /// <summary>Permanently deletes a quarantined file and its manifest. Irreversible — the CLI
    /// gates this behind the same typed confirmation as remediation (spec §6.9) and logs it to
    /// the action log. Refuses to delete anything the manifest points at outside the vault root.</summary>
    public Manifest Purge(string quarantineId)
    {
        // Reject ids that could traverse out of the vault before touching disk (spec §6.2:
        // destructive paths must never be steerable outside their sanctioned target set).
        if (string.IsNullOrEmpty(quarantineId)
            || quarantineId.Contains("..", StringComparison.Ordinal)
            || quarantineId.Contains('/')
            || quarantineId.Contains('\\'))
        {
            throw new ArgumentException("quarantine id must be a bare id, not a path", nameof(quarantineId));
        }

        var manifest = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(ManifestPath(quarantineId)))
            ?? throw new InvalidDataException("manifest unreadable");

        // Containment check BEFORE deleting anything: a tampered manifest whose vault_file
        // points outside the vault root must never turn purge into an arbitrary-file delete.
        var rootFull = Path.GetFullPath(_root);
        var rootPrefix = rootFull.EndsWith(Path.DirectorySeparatorChar)
            ? rootFull
            : rootFull + Path.DirectorySeparatorChar;
        var vaultFileFull = Path.GetFullPath(manifest.VaultFile);
        if (!vaultFileFull.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"manifest vault_file '{manifest.VaultFile}' is outside the vault root; refusing to purge");

        // Orphaned manifest (vault file already gone) is cleanup, not an error.
        if (File.Exists(vaultFileFull)) File.Delete(vaultFileFull);
        File.Delete(ManifestPath(quarantineId));
        return manifest;
    }

    /// <summary>Integrity state of one vaulted item as judged by <see cref="VerifyAll"/>.</summary>
    public enum VaultItemState { Ok, HashMismatch, FileMissing, HashUnknown }

    /// <summary>One item's verification result: the manifest it was checked against, the
    /// state, and a human-readable detail line for the operator's evidence record.</summary>
    public sealed record VaultVerification(Manifest Manifest, VaultItemState State, string Detail);

    /// <summary>Integrity-checks every vaulted file against its manifest's recorded SHA-256,
    /// so an operator can prove quarantined evidence is intact (companion to the
    /// tamper-evident action log, spec §6.10). Read-only — never modifies the vault.</summary>
    public IReadOnlyList<VaultVerification> VerifyAll()
    {
        var result = new List<VaultVerification>();
        foreach (var m in List()) // corrupt manifests are already skipped by List()
        {
            if (!File.Exists(m.VaultFile))
            {
                result.Add(new VaultVerification(m, VaultItemState.FileMissing,
                    $"vault file '{m.VaultFile}' does not exist"));
                continue;
            }
            if (string.IsNullOrEmpty(m.Sha256))
            {
                result.Add(new VaultVerification(m, VaultItemState.HashUnknown,
                    "manifest records no sha256 (file was unreadable or over the hash budget when "
                    + "quarantined); integrity cannot be proven either way"));
                continue;
            }
            var actual = FileHasher.Sha256(m.VaultFile);
            if (actual is null)
            {
                // A check that couldn't run must not report OK (spec §6.5).
                result.Add(new VaultVerification(m, VaultItemState.HashUnknown,
                    "vault file could not be hashed (unreadable or over the hash budget); "
                    + "integrity cannot be proven either way"));
                continue;
            }
            result.Add(string.Equals(m.Sha256, actual, StringComparison.OrdinalIgnoreCase)
                ? new VaultVerification(m, VaultItemState.Ok, "sha256 matches manifest")
                : new VaultVerification(m, VaultItemState.HashMismatch,
                    $"expected sha256 {m.Sha256}, actual {actual}"));
        }
        return result;
    }

    public IReadOnlyList<Manifest> List()
    {
        if (!Directory.Exists(_root)) return Array.Empty<Manifest>();
        var result = new List<Manifest>();
        foreach (var mf in Directory.EnumerateFiles(_root, "*.manifest.json"))
        {
            try
            {
                if (JsonSerializer.Deserialize<Manifest>(File.ReadAllText(mf)) is { } m) result.Add(m);
            }
            catch { /* corrupt manifest is still listed nowhere better; skip */ }
        }
        return result;
    }

    private string ManifestPath(string qid) => Path.Combine(_root, qid + ".manifest.json");

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
}
