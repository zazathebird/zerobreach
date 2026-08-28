using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Scythe.Core.Profiles;

/// <summary>
/// Opt-in loader for logged-off users' NTUSER.DAT hives (spec §4: never automatic, only
/// behind an explicit flag). Loads under a temporary HKU\SCYTHE_&lt;sid&gt; mount and always
/// unloads on dispose. Loading a hive is non-destructive but state-modifying, so failures
/// are reported per-profile and the profile stays "unchecked", never silently clean.
/// </summary>
public sealed class HiveLoader : IDisposable
{
    private readonly List<string> _mounted = new();

    /// <summary>Attempts to mount NTUSER.DAT for every profile whose hive isn't loaded.
    /// Returns per-profile failure reasons keyed by SID (empty = all requested loads worked).</summary>
    public IReadOnlyDictionary<string, string> LoadMissingHives(IEnumerable<UserProfile> profiles)
    {
        var failures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!PrivilegeUtil.TryEnableBackupRestorePrivileges(out var privErr))
        {
            foreach (var p in profiles.Where(p => !p.HiveMounted))
                failures[p.Sid] = $"cannot enable SeBackup/SeRestore privilege: {privErr}";
            return failures;
        }

        foreach (var profile in profiles.Where(p => !p.HiveMounted))
        {
            var ntuser = Path.Combine(profile.ProfilePath, "NTUSER.DAT");
            if (!File.Exists(ntuser))
            {
                failures[profile.Sid] = $"NTUSER.DAT not found at {ntuser}";
                continue;
            }

            var mountName = "SCYTHE_" + profile.Sid;
            var rc = NativeMethods.RegLoadKey(NativeMethods.HKEY_USERS, mountName, ntuser);
            if (rc != 0)
            {
                failures[profile.Sid] = $"RegLoadKey failed (win32 error {rc})";
                continue;
            }

            _mounted.Add(mountName);
            profile.HiveMounted = true;
            profile.HiveKeyName = mountName;
        }

        return failures;
    }

    public void Dispose()
    {
        foreach (var mountName in _mounted)
        {
            try { NativeMethods.RegUnLoadKey(NativeMethods.HKEY_USERS, mountName); }
            catch { /* best effort — hive unload failure leaves a stale mount, nothing destructive */ }
        }
        _mounted.Clear();
    }

    private static class NativeMethods
    {
        public static readonly UIntPtr HKEY_USERS = new(0x80000003u);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegLoadKey(UIntPtr hKey, string lpSubKey, string lpFile);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegUnLoadKey(UIntPtr hKey, string lpSubKey);
    }
}

internal static class PrivilegeUtil
{
    public static bool TryEnableBackupRestorePrivileges(out string? error)
    {
        error = null;
        return Enable("SeBackupPrivilege", ref error) & Enable("SeRestorePrivilege", ref error);
    }

    private static bool Enable(string privilege, ref string? error)
    {
        try
        {
            if (!LookupPrivilegeValue(null, privilege, out var luid))
            {
                error = $"{privilege}: lookup failed";
                return false;
            }

            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent(System.Security.Principal.TokenAccessLevels.AdjustPrivileges | System.Security.Principal.TokenAccessLevels.Query);
            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = 0x00000002, // SE_PRIVILEGE_ENABLED
            };
            if (!AdjustTokenPrivileges(identity.Token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) ||
                Marshal.GetLastWin32Error() != 0)
            {
                error = $"{privilege}: not held by this token (run elevated)";
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            error = $"{privilege}: {ex.Message}";
            return false;
        }
    }

    // Pack = 4: the native LUID is two DWORDs, so it sits at offset 4 — default packing
    // would align the long to offset 8 and the kernel would read a garbage LUID.
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);
}
