using System.Text.Json;
using ZeroBreach.Remediation;
using static ZeroBreach.Tests.TestHelpers;

namespace ZeroBreach.Tests;

/// <summary>Spec §6.4 — reversible by construction: vault + manifest with original path.</summary>
public class QuarantineVaultTests
{
    [Fact]
    public void Quarantine_moves_file_and_writes_manifest()
    {
        var scratch = NewScratchDir();
        var vault = new QuarantineVault(Path.Combine(scratch, "vault"));
        var victim = Path.Combine(scratch, "payload.exe");
        File.WriteAllText(victim, "MZ-fake");

        var m = vault.Quarantine(victim, "finding-1");

        Assert.False(File.Exists(victim));
        Assert.True(File.Exists(m.VaultFile));
        Assert.EndsWith(".quar", m.VaultFile); // neutralized extension
        Assert.Equal(Path.GetFullPath(victim), m.OriginalPath);
        Assert.Single(vault.List());
    }

    [Fact]
    public void Restore_puts_the_file_back()
    {
        var scratch = NewScratchDir();
        var vault = new QuarantineVault(Path.Combine(scratch, "vault"));
        var victim = Path.Combine(scratch, "payload.exe");
        File.WriteAllText(victim, "content-123");

        var m = vault.Quarantine(victim, null);
        var restored = vault.Restore(m.QuarantineId);

        Assert.True(File.Exists(victim));
        Assert.Equal("content-123", File.ReadAllText(victim));
        Assert.Equal(m.QuarantineId, restored.QuarantineId);
    }

    [Fact]
    public void Restore_refuses_to_overwrite_an_existing_file()
    {
        var scratch = NewScratchDir();
        var vault = new QuarantineVault(Path.Combine(scratch, "vault"));
        var victim = Path.Combine(scratch, "payload.exe");
        File.WriteAllText(victim, "original");

        var m = vault.Quarantine(victim, null);
        File.WriteAllText(victim, "recreated meanwhile");

        Assert.Throws<IOException>(() => vault.Restore(m.QuarantineId));
        Assert.Equal("recreated meanwhile", File.ReadAllText(victim));
    }

    [Fact]
    public void Purge_removes_vault_file_and_manifest()
    {
        var scratch = NewScratchDir();
        var vaultRoot = Path.Combine(scratch, "vault");
        var vault = new QuarantineVault(vaultRoot);
        var victim = Path.Combine(scratch, "payload.exe");
        File.WriteAllText(victim, "MZ-fake");

        var m = vault.Quarantine(victim, "finding-1");
        var purged = vault.Purge(m.QuarantineId);

        Assert.Equal(m.QuarantineId, purged.QuarantineId);
        Assert.False(File.Exists(m.VaultFile));
        Assert.False(File.Exists(Path.Combine(vaultRoot, m.QuarantineId + ".manifest.json")));
        Assert.Empty(vault.List());
    }

    [Fact]
    public void Purge_refuses_manifest_pointing_outside_the_vault_root()
    {
        // Spec §6.2 hard-block spirit: a tampered manifest must never turn purge into an
        // arbitrary-file delete outside the vault.
        var scratch = NewScratchDir();
        var vaultRoot = Path.Combine(scratch, "vault");
        Directory.CreateDirectory(vaultRoot);
        var vault = new QuarantineVault(vaultRoot);

        var outsideVictim = Path.Combine(scratch, "innocent.txt");
        File.WriteAllText(outsideVictim, "do not delete me");

        var tampered = new QuarantineVault.Manifest
        {
            QuarantineId = "evil-id",
            OriginalPath = Path.Combine(scratch, "whatever.exe"),
            VaultFile = outsideVictim, // points OUTSIDE the vault root
        };
        File.WriteAllText(
            Path.Combine(vaultRoot, "evil-id.manifest.json"),
            JsonSerializer.Serialize(tampered));

        Assert.Throws<InvalidOperationException>(() => vault.Purge("evil-id"));
        Assert.True(File.Exists(outsideVictim));
        Assert.Equal("do not delete me", File.ReadAllText(outsideVictim));
    }

    [Fact]
    public void Purge_of_unknown_id_throws()
    {
        var scratch = NewScratchDir();
        var vault = new QuarantineVault(Path.Combine(scratch, "vault"));

        Assert.ThrowsAny<IOException>(() => vault.Purge("nonexistent-id"));
    }

    [Fact]
    public void Purge_of_orphaned_manifest_still_removes_the_manifest()
    {
        var scratch = NewScratchDir();
        var vaultRoot = Path.Combine(scratch, "vault");
        var vault = new QuarantineVault(vaultRoot);
        var victim = Path.Combine(scratch, "payload.exe");
        File.WriteAllText(victim, "MZ-fake");

        var m = vault.Quarantine(victim, null);
        File.Delete(m.VaultFile); // orphan the manifest

        var purged = vault.Purge(m.QuarantineId);

        Assert.Equal(m.QuarantineId, purged.QuarantineId);
        Assert.False(File.Exists(Path.Combine(vaultRoot, m.QuarantineId + ".manifest.json")));
        Assert.Empty(vault.List());
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("..")]
    public void Purge_rejects_ids_that_look_like_paths(string badId)
    {
        var scratch = NewScratchDir();
        var vault = new QuarantineVault(Path.Combine(scratch, "vault"));

        Assert.Throws<ArgumentException>(() => vault.Purge(badId));
    }

    // Spec §6.10 companion: VerifyAll lets the operator prove vaulted evidence is intact.

    [Fact]
    public void VerifyAll_reports_ok_for_freshly_quarantined_file()
    {
        var scratch = NewScratchDir();
        var vault = new QuarantineVault(Path.Combine(scratch, "vault"));
        var victim = Path.Combine(scratch, "payload.exe");
        File.WriteAllText(victim, "MZ-fake");

        var m = vault.Quarantine(victim, "finding-1");
        var results = vault.VerifyAll();

        var v = Assert.Single(results);
        Assert.Equal(m.QuarantineId, v.Manifest.QuarantineId);
        Assert.Equal(QuarantineVault.VaultItemState.Ok, v.State);
    }

    [Fact]
    public void VerifyAll_reports_mismatch_with_both_hashes_when_vault_file_is_tampered()
    {
        var scratch = NewScratchDir();
        var vault = new QuarantineVault(Path.Combine(scratch, "vault"));
        var victim = Path.Combine(scratch, "payload.exe");
        File.WriteAllText(victim, "MZ-fake");

        var m = vault.Quarantine(victim, null);
        File.WriteAllText(m.VaultFile, "TAMPERED"); // evidence altered in the vault
        var tamperedHash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(m.VaultFile)))
            .ToLowerInvariant();

        var v = Assert.Single(vault.VerifyAll());
        Assert.Equal(QuarantineVault.VaultItemState.HashMismatch, v.State);
        Assert.Contains(m.Sha256!, v.Detail); // expected hash named in the detail
        Assert.Contains(tamperedHash, v.Detail); // actual hash named in the detail
    }

    [Fact]
    public void VerifyAll_reports_file_missing_when_vault_file_is_deleted()
    {
        var scratch = NewScratchDir();
        var vault = new QuarantineVault(Path.Combine(scratch, "vault"));
        var victim = Path.Combine(scratch, "payload.exe");
        File.WriteAllText(victim, "MZ-fake");

        var m = vault.Quarantine(victim, null);
        File.Delete(m.VaultFile);

        var v = Assert.Single(vault.VerifyAll());
        Assert.Equal(QuarantineVault.VaultItemState.FileMissing, v.State);
    }

    [Fact]
    public void VerifyAll_reports_hash_unknown_when_manifest_has_no_sha256()
    {
        // Spec §6.5 spirit: a check that cannot run must not report OK.
        var scratch = NewScratchDir();
        var vaultRoot = Path.Combine(scratch, "vault");
        Directory.CreateDirectory(vaultRoot);
        var vault = new QuarantineVault(vaultRoot);

        var vaultFile = Path.Combine(vaultRoot, "nohash-id.quar");
        File.WriteAllText(vaultFile, "MZ-fake");
        var noHash = new QuarantineVault.Manifest
        {
            QuarantineId = "nohash-id",
            OriginalPath = Path.Combine(scratch, "payload.exe"),
            VaultFile = vaultFile, // sha256 deliberately absent
        };
        File.WriteAllText(
            Path.Combine(vaultRoot, "nohash-id.manifest.json"),
            JsonSerializer.Serialize(noHash));

        var v = Assert.Single(vault.VerifyAll());
        Assert.Equal(QuarantineVault.VaultItemState.HashUnknown, v.State);
        Assert.True(File.Exists(vaultFile)); // read-only: nothing was touched
    }

    [Fact]
    public void VerifyAll_on_nonexistent_vault_returns_empty_and_creates_nothing()
    {
        var scratch = NewScratchDir();
        var vaultRoot = Path.Combine(scratch, "vault"); // never created
        var vault = new QuarantineVault(vaultRoot);

        Assert.Empty(vault.VerifyAll());
        Assert.False(Directory.Exists(vaultRoot)); // strictly read-only, even of an empty vault
    }
}
