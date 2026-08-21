using System.Security.Principal;
using Microsoft.Win32;

namespace ZeroBreach.Core.Profiles;

/// <summary>Enumerates every user profile on the box via the registry ProfileList key
/// (spec §4) — never just the technician's own profile.</summary>
public static class ProfileEnumerator
{
    private const string ProfileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    /// <summary>Returns real user profiles (S-1-5-21-*), marking which hives are mounted.
    /// Returns an empty list plus <paramref name="error"/> when ProfileList itself could not
    /// be read — the caller must report that as inconclusive, not as "no profiles".</summary>
    public static IReadOnlyList<UserProfile> Enumerate(out string? error)
    {
        error = null;
        var result = new List<UserProfile>();
        string? currentSid = null;
        try { currentSid = WindowsIdentity.GetCurrent().User?.Value; }
        catch { /* identity unavailable — profiles still enumerable */ }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ProfileListKey);
            if (key is null)
            {
                error = "ProfileList registry key could not be opened";
                return result;
            }

            foreach (var sid in key.GetSubKeyNames())
            {
                // Only real local/domain user SIDs; service profiles (S-1-5-18/19/20) are
                // covered by machine-wide checks, not per-user persistence walks.
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;

                using var profKey = key.OpenSubKey(sid);
                var path = profKey?.GetValue("ProfileImagePath") as string;
                if (string.IsNullOrWhiteSpace(path)) continue;

                var profile = new UserProfile
                {
                    Sid = sid,
                    ProfilePath = Environment.ExpandEnvironmentVariables(path),
                    IsCurrentUser = string.Equals(sid, currentSid, StringComparison.OrdinalIgnoreCase),
                };

                try
                {
                    using var hku = Registry.Users.OpenSubKey(sid, writable: false);
                    if (hku is not null)
                    {
                        profile.HiveMounted = true;
                        profile.HiveKeyName = sid;
                    }
                }
                catch { /* not mounted / access denied — stays unmounted and gets reported as unchecked */ }

                result.Add(profile);
            }
        }
        catch (Exception ex)
        {
            error = $"ProfileList enumeration failed: {ex.Message}";
        }

        return result;
    }
}
