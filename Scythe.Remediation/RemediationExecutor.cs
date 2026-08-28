using System.Diagnostics;
using Microsoft.Win32;
using Scythe.Core.Model;

namespace Scythe.Remediation;

public enum ItemStatus
{
    Done,
    DoneQuarantinedInsteadOfDeleted,
    Blocked,
    RefusedDisplayOnly,
    Failed,
}

public sealed record ItemResult(Finding Finding, ItemStatus Status, string Detail);

/// <summary>
/// Applies a confirmed remediation batch. Defense in depth — this class re-enforces the
/// gates even if a caller/UI is buggy:
///  • typed confirmation is validated HERE, not only in the UI (§6.9);
///  • the protected-targets hard block runs immediately before every action (§6.2);
///  • non-hash-confirmed deletes are downgraded to quarantine (§6.4);
///  • run_command is never executed, period (§6.8);
///  • the concurrency guard uses set-then-finally-reset (§6.6/§6.8);
///  • every attempt and outcome goes to the hash-chained action log (§6.10).
/// </summary>
public sealed class RemediationExecutor
{
    private int _remediationInProgress; // guard flag, spec §6.8 — only touched via Interlocked + finally

    private readonly ActionLog _log;
    private readonly QuarantineVault _vault;

    public RemediationExecutor(ActionLog log, QuarantineVault vault)
    {
        _log = log;
        _vault = vault;
    }

    public bool RemediationInProgress => Volatile.Read(ref _remediationInProgress) == 1;

    public IReadOnlyList<ItemResult> ExecuteBatch(IReadOnlyList<Finding> batch, string? typedConfirmation)
    {
        if (!ConfirmationGate.IsConfirmed(typedConfirmation))
            throw new InvalidOperationException(
                $"remediation refused: operator did not type {ConfirmationGate.RequiredWord}");

        if (Interlocked.CompareExchange(ref _remediationInProgress, 1, 0) != 0)
            throw new InvalidOperationException("another remediation batch is already running");

        try
        {
            _log.Append("batch_start", $"{batch.Count} item(s)", "ok",
                "typed confirmation accepted");
            var results = new List<ItemResult>(batch.Count);
            foreach (var finding in batch)
                results.Add(ExecuteOne(finding));
            _log.Append("batch_end", $"{batch.Count} item(s)", "ok",
                $"{results.Count(r => r.Status is ItemStatus.Done or ItemStatus.DoneQuarantinedInsteadOfDeleted)} applied, " +
                $"{results.Count(r => r.Status == ItemStatus.Blocked)} blocked, " +
                $"{results.Count(r => r.Status == ItemStatus.Failed)} failed");
            return results;
        }
        finally
        {
            // §6.8: every path away from the destructive section resets the guard.
            Interlocked.Exchange(ref _remediationInProgress, 0);
        }
    }

    private ItemResult ExecuteOne(Finding f)
    {
        var target = f.FixParam ?? f.Target;

        if (!f.FixAction.IsExecutable())
        {
            var why = f.FixAction == FixAction.RunCommand
                ? "run_command is display-only: read it, decide, run it by hand (spec §6.8)"
                : "no executable fix action";
            _log.Append(f.FixAction.ToWire(), target, "refused", why, f.Id);
            return new ItemResult(f, ItemStatus.RefusedDisplayOnly, why);
        }

        // §6.2 — hard block, checked at the moment of action, no override path exists.
        var verdict = ProtectedTargets.Check(f.FixAction, target);
        if (verdict.Blocked)
        {
            _log.Append(f.FixAction.ToWire(), target, "blocked", verdict.Reason, f.Id);
            return new ItemResult(f, ItemStatus.Blocked, verdict.Reason!);
        }

        try
        {
            switch (f.FixAction)
            {
                case FixAction.DeleteFile when !f.HashConfirmed:
                {
                    // §6.4 — not hash-confirmed known-bad ⇒ reversible action instead.
                    var m = _vault.Quarantine(target, f.Id);
                    _log.Append("quarantine(downgraded_from_delete)", target, "ok",
                        $"vault={m.VaultFile}", f.Id);
                    return new ItemResult(f, ItemStatus.DoneQuarantinedInsteadOfDeleted,
                        $"not hash-confirmed → quarantined to {m.VaultFile} (restorable)");
                }
                case FixAction.DeleteFile:
                {
                    File.Delete(target);
                    _log.Append("delete_file", target, "ok", "hash-confirmed known-bad", f.Id);
                    return new ItemResult(f, ItemStatus.Done, "deleted");
                }
                case FixAction.Quarantine:
                {
                    var m = _vault.Quarantine(target, f.Id);
                    _log.Append("quarantine", target, "ok", $"vault={m.VaultFile}", f.Id);
                    return new ItemResult(f, ItemStatus.Done, $"quarantined to {m.VaultFile}");
                }
                case FixAction.DeleteRegistryValue:
                {
                    DeleteRegistryValue(target);
                    _log.Append("delete_registry_value", target, "ok", null, f.Id);
                    return new ItemResult(f, ItemStatus.Done, "registry value removed");
                }
                case FixAction.KillProcess:
                {
                    KillProcessVerified(target);
                    _log.Append("kill_process", target, "ok", null, f.Id);
                    return new ItemResult(f, ItemStatus.Done, "process terminated");
                }
                default:
                    throw new InvalidOperationException($"unreachable action {f.FixAction}");
            }
        }
        catch (Exception ex)
        {
            _log.Append(f.FixAction.ToWire(), target, "failed", ex.Message, f.Id);
            return new ItemResult(f, ItemStatus.Failed, ex.Message);
        }
    }

    /// <summary>Deletes exactly one registry VALUE (never a key). Target form:
    /// "HIVE\Key\Path::ValueName" — the same form ProtectedTargets.CheckRegistry vets.</summary>
    private static void DeleteRegistryValue(string target)
    {
        var sep = target.LastIndexOf("::", StringComparison.Ordinal);
        if (sep < 0) throw new ArgumentException(@"registry target must be HIVE\Key\Path::ValueName");
        var keyPath = target[..sep];
        var valueName = target[(sep + 2)..];

        var slash = keyPath.IndexOf('\\');
        if (slash < 0) throw new ArgumentException("registry target has no key path");
        var hiveName = keyPath[..slash].ToUpperInvariant();
        var subKey = keyPath[(slash + 1)..];

        var hive = hiveName switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
            "HKCU" or "HKEY_CURRENT_USER" => Registry.CurrentUser,
            "HKU" or "HKEY_USERS" => Registry.Users,
            "HKCR" or "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
            _ => throw new ArgumentException($"unsupported hive {hiveName}"),
        };

        using var key = hive.OpenSubKey(subKey, writable: true)
            ?? throw new IOException($"key not found: {keyPath}");
        key.DeleteValue(valueName, throwOnMissingValue: true);
    }

    /// <summary>Kills a process only when the live process's name still matches the name
    /// recorded at scan time ("pid:name") — PIDs get reused; never kill on PID alone.</summary>
    private static void KillProcessVerified(string target)
    {
        var idx = target.IndexOf(':');
        var pid = int.Parse(target[..idx]);
        var expected = target[(idx + 1)..].Trim();
        if (expected.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) expected = expected[..^4];

        using var proc = Process.GetProcessById(pid);
        if (!string.Equals(proc.ProcessName, expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"pid {pid} is now '{proc.ProcessName}', expected '{expected}' — PID reused, refusing to kill");
        proc.Kill();
        proc.WaitForExit(5000);
    }
}
