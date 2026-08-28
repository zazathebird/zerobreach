using Microsoft.Win32;
using Scythe.Core.Model;
using Scythe.Remediation;
using static Scythe.Tests.TestHelpers;

namespace Scythe.Tests;

/// <summary>The executor re-enforces every §6 gate even against a buggy caller.</summary>
public class RemediationExecutorTests
{
    private static (RemediationExecutor exec, ActionLog log, string scratch) NewExecutor()
    {
        var scratch = NewScratchDir();
        var log = new ActionLog(Path.Combine(scratch, "log.jsonl"));
        return (new RemediationExecutor(log, new QuarantineVault(Path.Combine(scratch, "vault"))), log, scratch);
    }

    [Fact]
    public void Batch_without_typed_confirmation_is_refused_entirely()
    {
        var (exec, log, scratch) = NewExecutor();
        var file = Path.Combine(scratch, "a.exe");
        File.WriteAllText(file, "x");
        var batch = new[] { MakeFinding(Severity.Critical, FixAction.Quarantine, target: file) };

        Assert.Throws<InvalidOperationException>(() => exec.ExecuteBatch(batch, null));
        Assert.Throws<InvalidOperationException>(() => exec.ExecuteBatch(batch, "yes"));
        Assert.Throws<InvalidOperationException>(() => exec.ExecuteBatch(batch, "confirm"));
        Assert.True(File.Exists(file));            // nothing happened
        Assert.Empty(log.ReadAll());               // nothing was even attempted
    }

    [SkippableFact]
    public void Non_hash_confirmed_delete_is_downgraded_to_quarantine()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "remediation path semantics are Windows-only (protected dirs / registry)");
        var (exec, _, scratch) = NewExecutor();
        var file = Path.Combine(scratch, "suspect.exe");
        File.WriteAllText(file, "x");

        var results = exec.ExecuteBatch(
            new[] { MakeFinding(Severity.Critical, FixAction.DeleteFile, target: file, hashConfirmed: false) },
            "CONFIRM");

        Assert.Equal(ItemStatus.DoneQuarantinedInsteadOfDeleted, results[0].Status);
        Assert.False(File.Exists(file)); // moved to vault, not deleted — restorable
    }

    [SkippableFact]
    public void Hash_confirmed_delete_actually_deletes()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "remediation path semantics are Windows-only (protected dirs / registry)");
        var (exec, _, scratch) = NewExecutor();
        var file = Path.Combine(scratch, "knownbad.exe");
        File.WriteAllText(file, "x");

        var results = exec.ExecuteBatch(
            new[] { MakeFinding(Severity.Critical, FixAction.DeleteFile, target: file, hashConfirmed: true) },
            "CONFIRM");

        Assert.Equal(ItemStatus.Done, results[0].Status);
        Assert.False(File.Exists(file));
    }

    [Fact]
    public void Run_command_in_a_batch_is_refused_not_executed()
    {
        var (exec, log, _) = NewExecutor();
        var results = exec.ExecuteBatch(
            new[] { MakeFinding(Severity.Critical, FixAction.RunCommand, fixParam: "vssadmin list shadows") },
            "CONFIRM");

        Assert.Equal(ItemStatus.RefusedDisplayOnly, results[0].Status);
        Assert.Contains(log.ReadAll(), e => e.Result == "refused");
    }

    [Fact]
    public void Protected_target_is_blocked_at_the_moment_of_action()
    {
        var (exec, log, _) = NewExecutor();
        var winFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "definitely-not-deleted.dll");

        var results = exec.ExecuteBatch(
            new[] { MakeFinding(Severity.Critical, FixAction.DeleteFile, target: winFile, hashConfirmed: true) },
            "CONFIRM");

        Assert.Equal(ItemStatus.Blocked, results[0].Status);
        Assert.Contains(log.ReadAll(), e => e.Result == "blocked");
    }

    [SkippableFact]
    public void Guard_flag_resets_after_batch_including_failures()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "remediation path semantics are Windows-only (protected dirs / registry)");
        var (exec, _, scratch) = NewExecutor();
        // A file that does not exist → item fails, batch still completes and resets the guard.
        var results = exec.ExecuteBatch(
            new[] { MakeFinding(Severity.Critical, FixAction.Quarantine, target: Path.Combine(scratch, "ghost.exe")) },
            "CONFIRM");

        Assert.Equal(ItemStatus.Failed, results[0].Status);
        Assert.False(exec.RemediationInProgress); // §6.8 set-then-finally-reset
    }

    [SkippableFact]
    public void Every_outcome_lands_in_the_hash_chained_log()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "remediation path semantics are Windows-only (protected dirs / registry)");
        var (exec, log, scratch) = NewExecutor();
        var file = Path.Combine(scratch, "a.exe");
        File.WriteAllText(file, "x");

        exec.ExecuteBatch(new[] { MakeFinding(Severity.High, FixAction.Quarantine, target: file) }, "CONFIRM");

        var entries = log.ReadAll();
        Assert.Contains(entries, e => e.Action == "batch_start");
        Assert.Contains(entries, e => e.Action == "quarantine" && e.Result == "ok");
        Assert.Contains(entries, e => e.Action == "batch_end");
        Assert.True(log.Verify(out _, out _));
    }

    [SkippableFact]
    public void Registry_value_delete_removes_exactly_one_value()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "remediation path semantics are Windows-only (protected dirs / registry)");
        const string testKey = @"Software\ScytheEngineTests";
        using (var k = Registry.CurrentUser.CreateSubKey(testKey))
        {
            k.SetValue("EvilValue", "payload");
            k.SetValue("InnocentValue", "keep me");
        }

        try
        {
            var (exec, _, _) = NewExecutor();
            var results = exec.ExecuteBatch(
                new[] { MakeFinding(Severity.High, FixAction.DeleteRegistryValue,
                    fixParam: $@"HKCU\{testKey}::EvilValue", target: $@"HKCU\{testKey}") },
                "CONFIRM");

            Assert.Equal(ItemStatus.Done, results[0].Status);
            using var check = Registry.CurrentUser.OpenSubKey(testKey);
            Assert.Null(check!.GetValue("EvilValue"));
            Assert.Equal("keep me", check.GetValue("InnocentValue"));
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(testKey, throwOnMissingSubKey: false);
        }
    }
}
