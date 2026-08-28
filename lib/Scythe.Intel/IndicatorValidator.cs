namespace Scythe.Intel;

using System.Net;
using System.Net.Sockets;

/// <summary>
/// Per-type validation and normalisation. Validation is the point of this module: anything
/// that fails is rejected with a reason — never silently dropped and never passed through,
/// because a malformed indicator that reaches the host's matching layer is either noise in a
/// client's report or a hazard (task brief).
///
/// No <c>System.Text.RegularExpressions</c> here at all: every check is a character loop, so
/// attacker-authored values cannot trigger backtracking however hostile they are.
/// </summary>
internal static class IndicatorValidator
{
    // URL scheme allowlist. Deliberately short: the host matches network indicators, and
    // anything else (javascript:, data:, file:) is more likely a feed defect than an IOC.
    private static readonly string[] AllowedUrlSchemes = { "http", "https", "ftp", "ftps" };

    // Known registry hives, long and short form, matched case-insensitively against the first
    // path component.
    private static readonly string[] RegistryHives =
    {
        "HKLM", "HKCU", "HKCR", "HKU", "HKCC",
        "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT",
        "HKEY_USERS", "HKEY_CURRENT_CONFIG",
    };

    /// <summary>Validates <paramref name="value"/> as <paramref name="type"/>. On success
    /// <paramref name="normalized"/> holds the canonical form; on failure
    /// <paramref name="reason"/> says why, in words a technician can act on.</summary>
    public static bool TryValidate(IndicatorType type, string value, out string normalized, out string? reason)
    {
        normalized = string.Empty;
        reason = null;
        switch (type)
        {
            case IndicatorType.Sha256:
                return ValidateHash(value, 64, "SHA-256", ref normalized, ref reason);
            case IndicatorType.Sha1:
                return ValidateHash(value, 40, "SHA-1", ref normalized, ref reason);
            case IndicatorType.Md5:
                return ValidateHash(value, 32, "MD5", ref normalized, ref reason);

            case IndicatorType.Ipv4:
                if (!IsStrictIpv4(value, out var v4Reason))
                {
                    reason = v4Reason;
                    return false;
                }
                normalized = value;
                return true;

            case IndicatorType.Ipv6:
                // Family check matters: IPAddress.TryParse happily reads "1.2.3.4" as v4.
                if (!value.Contains(':')
                    || !IPAddress.TryParse(value, out var ip6)
                    || ip6.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    reason = "not a valid IPv6 address";
                    return false;
                }
                normalized = ip6.ToString(); // canonical compressed lowercase form
                return true;

            case IndicatorType.Domain:
                if (!IsPlausibleDomain(value, out var domReason, out var domNorm))
                {
                    reason = domReason;
                    return false;
                }
                normalized = domNorm;
                return true;

            case IndicatorType.Url:
                return ValidateUrl(value, ref normalized, ref reason);

            case IndicatorType.Filename:
                if (value.IndexOfAny(new[] { '/', '\\' }) >= 0)
                {
                    reason = "filename must not contain path separators";
                    return false;
                }
                if (value.Contains(':'))
                {
                    reason = "filename must not contain ':'";
                    return false;
                }
                if (HasControlChars(value))
                {
                    reason = "filename contains control characters";
                    return false;
                }
                if (value is "." or "..")
                {
                    reason = "filename cannot be '.' or '..'";
                    return false;
                }
                normalized = value;
                return true;

            case IndicatorType.FilePath:
                if (value.IndexOfAny(new[] { '/', '\\' }) < 0)
                {
                    reason = "file path contains no path separator (use filename for a bare name)";
                    return false;
                }
                if (HasControlChars(value))
                {
                    reason = "file path contains control characters";
                    return false;
                }
                normalized = value;
                return true;

            case IndicatorType.RegistryKey:
                if (!StartsWithKnownHive(value))
                {
                    reason = "registry key must start with a known hive (HKLM, HKCU, HKCR, HKU, HKCC or long forms)";
                    return false;
                }
                if (HasControlChars(value))
                {
                    reason = "registry key contains control characters";
                    return false;
                }
                normalized = value;
                return true;

            case IndicatorType.Mutex:
                if (HasControlChars(value))
                {
                    reason = "mutex name contains control characters";
                    return false;
                }
                normalized = value;
                return true;

            case IndicatorType.EmailAddress:
                return ValidateEmail(value, ref normalized, ref reason);

            default:
                reason = $"unknown indicator type {type}";
                return false;
        }
    }

    /// <summary>
    /// Infers the type of a bare value (plain text feeds). Precedence, most-specific first —
    /// each step only fires on a shape the later steps cannot produce:
    ///   1. hex of length 64/40/32 → Sha256/Sha1/Md5
    ///   2. contains "://"         → Url (scheme then validated against the allowlist)
    ///   3. known hive prefix      → RegistryKey
    ///   4. strict dotted quad     → Ipv4
    ///   5. contains ':' + parses  → Ipv6
    ///   6. contains '@'           → EmailAddress
    ///   7. contains '/' or '\'    → FilePath
    ///   8. plausible domain       → Domain
    ///   9. otherwise              → unclassifiable, rejected with reason
    /// Note: plain text never infers Filename or Mutex — a bare token is indistinguishable
    /// from a domain ("evil.exe" classifies as Domain). Feeds that mean filenames must use a
    /// typed format. Documented in the handoff.
    /// </summary>
    public static bool TryInfer(string value, out IndicatorType type, out string? reason)
    {
        reason = null;
        if (IsHex(value))
        {
            switch (value.Length)
            {
                case 64: type = IndicatorType.Sha256; return true;
                case 40: type = IndicatorType.Sha1; return true;
                case 32: type = IndicatorType.Md5; return true;
            }
        }
        if (value.Contains("://")) { type = IndicatorType.Url; return true; }
        if (StartsWithKnownHive(value)) { type = IndicatorType.RegistryKey; return true; }
        if (IsStrictIpv4(value, out _)) { type = IndicatorType.Ipv4; return true; }
        if (value.Contains(':') && IPAddress.TryParse(value, out var ip)
            && ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            type = IndicatorType.Ipv6;
            return true;
        }
        if (value.Contains('@')) { type = IndicatorType.EmailAddress; return true; }
        if (value.Contains('/') || value.Contains('\\')) { type = IndicatorType.FilePath; return true; }
        if (IsPlausibleDomain(value, out _, out _)) { type = IndicatorType.Domain; return true; }

        type = default;
        reason = "unclassifiable: not a hash, IP, URL, email, path, registry key or plausible domain";
        return false;
    }

    /// <summary>Resolves an IP whose family the feed did not state.</summary>
    public static bool TryResolveIpFamily(string value, out IndicatorType type, out string? reason)
    {
        if (IsStrictIpv4(value, out _)) { type = IndicatorType.Ipv4; reason = null; return true; }
        if (value.Contains(':') && IPAddress.TryParse(value, out var ip)
            && ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            type = IndicatorType.Ipv6;
            reason = null;
            return true;
        }
        type = default;
        reason = "not a valid IPv4 or IPv6 address";
        return false;
    }

    private static bool ValidateHash(string value, int length, string name, ref string normalized, ref string? reason)
    {
        if (value.Length != length)
        {
            reason = $"{name} must be exactly {length} hexadecimal characters (got {value.Length})";
            return false;
        }
        if (!IsHex(value))
        {
            reason = $"{name} contains non-hexadecimal characters";
            return false;
        }
        normalized = value.ToLowerInvariant();
        return true;
    }

    private static bool ValidateUrl(string value, ref string normalized, ref string? reason)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            reason = "not a parseable absolute URL";
            return false;
        }
        if (Array.IndexOf(AllowedUrlSchemes, uri.Scheme) < 0)
        {
            reason = $"URL scheme '{uri.Scheme}' not in allowlist (http, https, ftp, ftps)";
            return false;
        }
        if (uri.Host.Length == 0)
        {
            reason = "URL has no host";
            return false;
        }
        // AbsoluteUri lowercases scheme and host and normalises a bare authority to end in
        // "/": "http://EVIL.com" → "http://evil.com/". Deterministic, so fine for dedup.
        normalized = uri.AbsoluteUri;
        return true;
    }

    private static bool ValidateEmail(string value, ref string normalized, ref string? reason)
    {
        var at = value.IndexOf('@');
        if (at <= 0 || at != value.LastIndexOf('@') || at == value.Length - 1)
        {
            reason = "email must contain exactly one '@' with text on both sides";
            return false;
        }
        var local = value[..at];
        var domain = value[(at + 1)..];
        if (local.Contains(' ') || HasControlChars(local))
        {
            reason = "email local part contains whitespace or control characters";
            return false;
        }
        if (!IsPlausibleDomain(domain, out var domReason, out var domNorm))
        {
            reason = $"email domain part invalid: {domReason}";
            return false;
        }
        // Local-part case is theoretically significant but no real mail system treats it so;
        // lowercase the whole address for a canonical form.
        normalized = local.ToLowerInvariant() + "@" + domNorm;
        return true;
    }

    /// <summary>
    /// Strict dotted-quad: exactly four decimal octets 0–255, no leading zeros. Rejecting
    /// leading zeros is deliberate: "1.2.3.010" parses as octal 8 in some stacks and decimal
    /// 10 in others, and an indicator that different consumers read as different addresses is
    /// worse than no indicator. Shorthand forms ("1.2.3") are rejected for the same reason.
    /// </summary>
    private static bool IsStrictIpv4(string value, out string? reason)
    {
        var parts = value.Split('.');
        if (parts.Length != 4)
        {
            reason = "not a valid IPv4 address (need exactly four dotted octets)";
            return false;
        }
        foreach (var p in parts)
        {
            if (p.Length is 0 or > 3)
            {
                reason = "not a valid IPv4 address (octet empty or too long)";
                return false;
            }
            foreach (var c in p)
            {
                if (c is < '0' or > '9')
                {
                    reason = "not a valid IPv4 address (non-digit in octet)";
                    return false;
                }
            }
            if (p.Length > 1 && p[0] == '0')
            {
                reason = "IPv4 octet has a leading zero (ambiguous octal/decimal reading)";
                return false;
            }
            if (int.Parse(p) > 255)
            {
                reason = "IPv4 octet exceeds 255";
                return false;
            }
        }
        reason = null;
        return true;
    }

    /// <summary>
    /// Domain plausibility: lowercased; a single trailing root dot is stripped; total length
    /// ≤ 253; at least two labels (a bare TLD is not an indicator); labels 1–63 chars of
    /// letters, digits, '-' or '_' (underscore allowed for service labels like _dmarc),
    /// not starting or ending with '-'; the final label at least two chars and not all
    /// digits (that shape is a malformed IP, not a TLD). Punycode xn-- labels pass naturally.
    /// </summary>
    private static bool IsPlausibleDomain(string value, out string? reason, out string normalized)
    {
        normalized = string.Empty;
        var s = value.ToLowerInvariant();
        if (s.EndsWith('.'))
            s = s[..^1];
        if (s.Length is 0 or > 253)
        {
            reason = "domain empty or longer than 253 characters";
            return false;
        }
        var labels = s.Split('.');
        if (labels.Length < 2)
        {
            reason = "domain has no dot (bare TLDs and single labels are not indicators)";
            return false;
        }
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63)
            {
                reason = "domain label empty or longer than 63 characters";
                return false;
            }
            if (label[0] == '-' || label[^1] == '-')
            {
                reason = "domain label starts or ends with '-'";
                return false;
            }
            foreach (var c in label)
            {
                var ok = c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
                if (!ok)
                {
                    reason = $"domain contains invalid character '{c}'";
                    return false;
                }
            }
        }
        var tld = labels[^1];
        if (tld.Length < 2)
        {
            reason = "domain top-level label shorter than two characters";
            return false;
        }
        var allDigits = true;
        foreach (var c in tld)
        {
            if (c is < '0' or > '9')
            {
                allDigits = false;
                break;
            }
        }
        if (allDigits)
        {
            reason = "domain top-level label is all digits (malformed IP, not a domain)";
            return false;
        }
        reason = null;
        normalized = s;
        return true;
    }

    private static bool StartsWithKnownHive(string value)
    {
        var sep = value.IndexOfAny(new[] { '\\', '/' });
        var first = sep < 0 ? value : value[..sep];
        foreach (var hive in RegistryHives)
        {
            if (string.Equals(first, hive, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool IsHex(string value)
    {
        if (value.Length == 0)
            return false;
        foreach (var c in value)
        {
            var ok = c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');
            if (!ok)
                return false;
        }
        return true;
    }

    private static bool HasControlChars(string value)
    {
        foreach (var c in value)
        {
            if (char.IsControl(c))
                return true;
        }
        return false;
    }
}
