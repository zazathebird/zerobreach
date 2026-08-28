using Microsoft.Win32;

namespace Scythe.Core.Profiles;

/// <summary>One user profile from the ProfileList key (spec §4).</summary>
public sealed class UserProfile
{
    public required string Sid { get; init; }
    public required string ProfilePath { get; init; }
    public string UserName => Path.GetFileName(ProfilePath.TrimEnd('\\'));

    /// <summary>True if this profile's NTUSER.DAT is mounted under HKEY_USERS right now
    /// (logged-on user, or loaded by us via the opt-in hive loader).</summary>
    public bool HiveMounted { get; internal set; }

    /// <summary>The HKU subkey name where the hive is reachable: the SID for a logged-on
    /// user, or the temporary mount name when loaded by the opt-in loader.</summary>
    public string? HiveKeyName { get; internal set; }

    /// <summary>True for the profile of the account running the scan.</summary>
    public bool IsCurrentUser { get; init; }

    /// <summary>Opens the root of this profile's registry hive, or null when the hive is
    /// not mounted. Callers MUST report a Skipped/Inconclusive check status for profiles
    /// that return null — "didn't look" is never "clean" (spec §4).</summary>
    public RegistryKey? OpenHiveRoot()
    {
        if (!HiveMounted || HiveKeyName is null) return null;
        return Registry.Users.OpenSubKey(HiveKeyName, writable: false);
    }
}
