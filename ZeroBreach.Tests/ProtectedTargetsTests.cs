using ZeroBreach.Core.Model;
using ZeroBreach.Remediation;

namespace ZeroBreach.Tests;

/// <summary>Spec §6.2 — the hardcoded hard block, no override.</summary>
public class ProtectedTargetsTests
{
    private static readonly string WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    [Fact]
    public void Core_os_directory_is_blocked_for_file_actions()
    {
        Assert.True(ProtectedTargets.Check(FixAction.DeleteFile, Path.Combine(WinDir, "System32", "svchost.exe")).Blocked);
        Assert.True(ProtectedTargets.Check(FixAction.Quarantine, Path.Combine(WinDir, "explorer.exe")).Blocked);
    }

    [SkippableFact]
    public void Windows_temp_carveout_is_allowed()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "protected-dir carve-outs need real Windows special folders");
        // Windows\Temp is a malware drop dir with no OS-critical files — deliberately allowed.
        var v = ProtectedTargets.Check(FixAction.Quarantine, Path.Combine(WinDir, "Temp", "dropper.exe"));
        Assert.False(v.Blocked);
    }

    [SkippableFact]
    public void User_profile_paths_are_allowed()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "off-Windows the protected-dir roots are empty and block everything (fail-closed)");
        var v = ProtectedTargets.Check(FixAction.DeleteFile, @"C:\Users\victim\AppData\Roaming\evil.exe");
        Assert.False(v.Blocked);
    }

    [Fact]
    public void Own_process_and_own_files_are_blocked()
    {
        Assert.True(ProtectedTargets.Check(FixAction.KillProcess, $"{Environment.ProcessId}:whatever").Blocked);
        var self = Environment.ProcessPath!;
        Assert.True(ProtectedTargets.Check(FixAction.DeleteFile, self).Blocked);
        Assert.True(ProtectedTargets.Check(FixAction.DeleteFile, Path.Combine(Path.GetDirectoryName(self)!, "anything.dll")).Blocked);
    }

    [Fact]
    public void Path_tricks_do_not_bypass_the_block()
    {
        // Guide §4.1: dot-dot traversal, mixed case, forward slashes, \\?\ prefix,
        // trailing dots/spaces — all must still block.
        Assert.True(ProtectedTargets.Check(FixAction.DeleteFile, Path.Combine(WinDir, @"System32\..\System32\evil.dll")).Blocked);
        Assert.True(ProtectedTargets.Check(FixAction.DeleteFile, Path.Combine(WinDir, "SYSTEM32", "EVIL.DLL").ToUpperInvariant()).Blocked);
        Assert.True(ProtectedTargets.Check(FixAction.DeleteFile, Path.Combine(WinDir, "System32", "x").Replace('\\', '/')).Blocked);
        Assert.True(ProtectedTargets.Check(FixAction.DeleteFile, @"\\?\" + Path.Combine(WinDir, "System32", "x")).Blocked);
        Assert.True(ProtectedTargets.Check(FixAction.DeleteFile, Path.Combine(WinDir, "System32", "evil.dll") + " . .").Blocked);
    }

    [Fact]
    public void Vault_and_action_log_area_is_blocked()
    {
        Assert.True(ProtectedTargets.Check(FixAction.DeleteFile, ZbPaths.ActionLogPath).Blocked);
        Assert.True(ProtectedTargets.Check(FixAction.Quarantine, Path.Combine(ZbPaths.VaultDir, "x.quar")).Blocked);
    }

    [Theory]
    [InlineData("system")]
    [InlineData("lsass")]
    [InlineData("winlogon")]
    [InlineData("csrss.exe")]   // .exe suffix tolerated
    [InlineData("MsMpEng")]     // security tooling, case-insensitive
    public void Critical_processes_are_blocked(string name) =>
        Assert.True(ProtectedTargets.Check(FixAction.KillProcess, $"1234:{name}").Blocked);

    [Theory]
    [InlineData("0:system")]
    [InlineData("4:system")]
    [InlineData("garbage")]        // malformed → block, never guess
    [InlineData(":noname")]
    [InlineData("99:")]
    public void Malformed_or_system_pid_kill_targets_are_blocked(string target) =>
        Assert.True(ProtectedTargets.Check(FixAction.KillProcess, target).Blocked);

    [Fact]
    public void Ordinary_process_kill_is_allowed()
    {
        Assert.False(ProtectedTargets.Check(FixAction.KillProcess, "4242:definitelymalware").Blocked);
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates::abc")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa::Security Packages")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon::Shell")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1::ProfileImagePath")]
    public void Protected_registry_areas_are_blocked(string target) =>
        Assert.True(ProtectedTargets.Check(FixAction.DeleteRegistryValue, target).Blocked);

    [Fact]
    public void Run_key_value_deletion_is_allowed()
    {
        var v = ProtectedTargets.Check(FixAction.DeleteRegistryValue,
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run::EvilUpdater");
        Assert.False(v.Blocked);
    }

    [Fact]
    public void Run_command_is_always_blocked_from_execution()
    {
        Assert.True(ProtectedTargets.Check(FixAction.RunCommand, "vssadmin delete shadows /all").Blocked);
    }
}
