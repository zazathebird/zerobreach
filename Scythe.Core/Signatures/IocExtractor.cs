using System.Text.RegularExpressions;

namespace Scythe.Core.Signatures;

/// <summary>Kinds of indicator <see cref="IocExtractor"/> can recognize in free-form text.</summary>
public enum IocKind { Sha256, Ipv4, Domain, Filename }

/// <summary>
/// One candidate indicator extracted from untrusted text. A candidate only — see the
/// spec §6.6 discipline on <see cref="IocExtractor"/>: nothing here is live until the
/// operator individually confirms it.
/// </summary>
public sealed record ExtractedIoc
{
    /// <summary>The normalized indicator (hashes and domains lowercased; filenames keep
    /// their original casing since matching downstream is case-insensitive anyway).</summary>
    public required string Value { get; init; }

    public required IocKind Kind { get; init; }

    /// <summary>The original (pre-refang) trimmed line the indicator came from, so the
    /// operator can judge each candidate in context before confirming it.</summary>
    public required string SourceLine { get; init; }

    /// <summary>Null, or a short reason the operator should be extra skeptical of this
    /// particular match (e.g. a private-range IP, a dotted quad that looks like a version).</summary>
    public string? Caution { get; init; }
}

/// <summary>
/// Pure, static IOC extractor for free-form untrusted text — a pasted alert, a threat-intel
/// writeup, a log excerpt.
///
/// Spec §6.6 context: extraction is deliberately DETECTION-STAGING ONLY — this class never
/// arms anything. Every extracted indicator requires individual operator confirmation in the
/// CLI before it enters the signature database, because text-extracted IOCs are low-precision
/// (version strings parse as valid IPs, a mentioned domain isn't necessarily malicious).
/// Auto-feeding these into a destructive matching path is exactly what §6.6 forbids.
///
/// Each line is refanged (hxxp → http, "[.]" → ".", etc.) for matching only; the reported
/// <see cref="ExtractedIoc.SourceLine"/> is always the original trimmed line. Results are
/// deduplicated case-insensitively by (kind, value), first occurrence wins. All regexes are
/// simple linear character-class patterns compiled with a match timeout, since the input is
/// untrusted (no pathological backtracking).
/// </summary>
public static class IocExtractor
{
    private const string ReservedCaution = "private/reserved address — unlikely to be a real C2 address";
    private const string VersionCaution = "may be a version number, not an address";

    private static readonly TimeSpan RxTimeout = TimeSpan.FromSeconds(1);

    /// <summary>Standalone 64-hex token (not embedded in a longer alphanumeric run).</summary>
    private static readonly Regex Sha256Rx = new(
        "(?<![0-9A-Za-z])[0-9a-fA-F]{64}(?![0-9A-Za-z])",
        RegexOptions.Compiled, RxTimeout);

    /// <summary>Dotted-quad candidate. Octet range is validated in code; the lookarounds
    /// reject quads embedded in longer dotted-numeric runs (e.g. 1.2.3.4.5) while still
    /// allowing a 'v' prefix, which is flagged with a caution instead.</summary>
    private static readonly Regex Ipv4Rx = new(
        @"(?<![.\d])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\.?\d)",
        RegexOptions.Compiled, RxTimeout);

    /// <summary>Dotted token of letters/digits/hyphens. Final-label shape (alphabetic, 2+
    /// chars) and the file-extension exclusion are validated in code. Matches the host part
    /// when it appears inside a URL, and never includes a trailing dot.</summary>
    private static readonly Regex DomainRx = new(
        @"(?<![\w.-])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w-])",
        RegexOptions.Compiled, RxTimeout);

    /// <summary>Token ending in a suspicious file extension — the same extension list
    /// <see cref="SignatureDb.LoadIocFile"/> uses to split filenames from domains. The tail
    /// lookahead rejects extensions followed by more labels (evil.js.example.com is a domain,
    /// not a .js file) while still allowing trailing sentence punctuation.</summary>
    private static readonly Regex FilenameRx = new(
        @"[^\s""'<>,;()\[\]{}]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|scr|sys|tmp|dat|zip|rar|7z|lnk|docm|xlsm)(?!\.?[\w-])",
        RegexOptions.Compiled | RegexOptions.IgnoreCase, RxTimeout);

    /// <summary>Blanks out the path, query and fragment of every URL-ish token in the line,
    /// leaving hosts (and ordinary prose) intact, so domain matching cannot pick names out of
    /// a URL path. Anything after the first '/' of a token that contains one is replaced with
    /// spaces — offsets are preserved, and the untouched line is still what the filename and
    /// hash passes read.</summary>
    private static string HostsOnly(string line)
    {
        var chars = line.ToCharArray();
        var tokenStart = 0;
        for (var i = 0; i <= chars.Length; i++)
        {
            if (i < chars.Length && !char.IsWhiteSpace(chars[i])) continue;

            // Token is [tokenStart, i). Blank from the first '/' that is not part of "://".
            for (var j = tokenStart; j < i; j++)
            {
                if (chars[j] != '/') continue;
                if (j + 1 < i && chars[j + 1] == '/' && j > tokenStart && chars[j - 1] == ':')
                {
                    j++;               // skip the scheme separator, keep scanning for the path
                    continue;
                }
                for (var k = j; k < i; k++) chars[k] = ' ';
                break;
            }
            tokenStart = i + 1;
        }
        return new string(chars);
    }

    /// <summary>Final labels that are web/document resource names rather than TLDs. A token
    /// ending in one is a page or file reference, not a host — and unlike
    /// <see cref="FileExtensions"/> these are NOT armed as filename indicators either: a bare
    /// "gate.php" is a path fragment, too generic to be an indicator of anything.</summary>
    private static readonly HashSet<string> NonDomainExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "php", "asp", "aspx", "jsp", "jspx", "cgi", "html", "htm", "shtml", "phtml",
        "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "pdf", "json", "xml",
    };

    /// <summary>Extensions excluded from domain matching (same list as
    /// <see cref="SignatureDb.LoadIocFile"/>) — a dotted token ending in one of these is a
    /// filename, not a domain.</summary>
    private static readonly HashSet<string> FileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "scr",
        "sys", "tmp", "dat", "zip", "rar", "7z", "lnk", "docm", "xlsm",
    };

    /// <summary>
    /// Extracts candidate IOCs from <paramref name="text"/>, line by line. Blank lines and
    /// '#' comment lines are ignored; null-ish/empty input yields an empty list. Every result
    /// is a candidate for operator review only (spec §6.6) — nothing returned here is armed.
    /// </summary>
    public static IReadOnlyList<ExtractedIoc> Extract(string text)
    {
        var results = new List<ExtractedIoc>();
        if (string.IsNullOrWhiteSpace(text)) return results;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in text.Split('\n'))
        {
            var sourceLine = raw.Trim();
            if (sourceLine.Length == 0 || sourceLine.StartsWith('#')) continue;

            var line = Refang(sourceLine);
            try
            {
                ExtractFromLine(line, sourceLine, results, seen);
            }
            catch (RegexMatchTimeoutException)
            {
                // Untrusted input tripped the defensive timeout — skip the line rather
                // than let a hostile paste stall the tool. Nothing armed, nothing lost
                // but one line of candidates.
            }
        }

        return results;
    }

    private static void ExtractFromLine(string line, string sourceLine, List<ExtractedIoc> results, HashSet<string> seen)
    {
        foreach (Match m in Sha256Rx.Matches(line))
            AddUnique(results, seen, IocKind.Sha256, m.Value.ToLowerInvariant(), sourceLine, caution: null);

        foreach (Match m in Ipv4Rx.Matches(line))
        {
            var octets = new int[4];
            var valid = true;
            for (var i = 0; i < 4; i++)
            {
                octets[i] = int.Parse(m.Groups[i + 1].Value);
                if (octets[i] > 255) valid = false;
            }
            if (!valid) continue;

            AddUnique(results, seen, IocKind.Ipv4, m.Value, sourceLine, IpCaution(line, m, octets));
        }

        // Only the HOST part of a URL is a domain. Without this, the path of
        // http://evil.com/gate.php parses as the "domain" gate.php — a dead indicator that
        // burns an operator confirmation and can never match anything at scan time.
        foreach (Match m in DomainRx.Matches(HostsOnly(line)))
        {
            var value = m.Value.ToLowerInvariant();
            var lastLabel = value[(value.LastIndexOf('.') + 1)..];
            if (lastLabel.Length < 2 || !lastLabel.All(char.IsAsciiLetter)) continue; // IPs, version-ish tokens
            if (FileExtensions.Contains(lastLabel)) continue;                         // filenames, handled below
            if (NonDomainExtensions.Contains(lastLabel)) continue;                    // page/resource names

            AddUnique(results, seen, IocKind.Domain, value, sourceLine, caution: null);
        }

        foreach (Match m in FilenameRx.Matches(line))
        {
            // A path (host share, C:\..., URL path) contributes just its final component.
            var value = m.Value;
            var cut = Math.Max(value.LastIndexOf('\\'), value.LastIndexOf('/'));
            if (cut >= 0) value = value[(cut + 1)..];
            if (value.Length == 0 || value.StartsWith('.')) continue;

            AddUnique(results, seen, IocKind.Filename, value, sourceLine, caution: null);
        }
    }

    private static void AddUnique(List<ExtractedIoc> results, HashSet<string> seen,
        IocKind kind, string value, string sourceLine, string? caution)
    {
        if (!seen.Add($"{kind}|{value}")) return; // case-insensitive by (kind, value); first occurrence wins
        results.Add(new ExtractedIoc { Value = value, Kind = kind, SourceLine = sourceLine, Caution = caution });
    }

    /// <summary>
    /// Why the operator should be extra skeptical of a dotted quad, or null for an ordinary
    /// public address. When both cautions apply they are joined with "; ", version first —
    /// deterministic, and both reasons reach the operator.
    /// </summary>
    private static string? IpCaution(string refangedLine, Match m, int[] o)
    {
        var version = refangedLine.Contains("version", StringComparison.OrdinalIgnoreCase)
                      || (m.Index > 0 && refangedLine[m.Index - 1] is 'v' or 'V');
        var reserved = IsPrivateOrReserved(o);

        if (version && reserved) return VersionCaution + "; " + ReservedCaution;
        if (version) return VersionCaution;
        if (reserved) return ReservedCaution;
        return null;
    }

    private static bool IsPrivateOrReserved(int[] o) =>
        o[0] == 0                                          // 0.0.0.0/8 "this network"
        || o[0] == 10                                      // 10.0.0.0/8 private
        || o[0] == 127                                     // 127.0.0.0/8 loopback
        || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)       // 172.16.0.0/12 private
        || (o[0] == 192 && o[1] == 168)                    // 192.168.0.0/16 private
        || (o[0] == 169 && o[1] == 254)                    // 169.254.0.0/16 link-local
        || (o[0] >= 224 && o[0] <= 239)                    // 224.0.0.0/4 multicast
        || (o[0] == 255 && o[1] == 255 && o[2] == 255 && o[3] == 255); // limited broadcast

    /// <summary>
    /// Undoes common defanging so indicators match — for matching ONLY; the reported
    /// <see cref="ExtractedIoc.SourceLine"/> always keeps the original defanged text.
    /// </summary>
    private static string Refang(string line)
    {
        var s = line.Replace("hxxp", "http", StringComparison.OrdinalIgnoreCase);
        s = s.Replace(" [dot] ", ".", StringComparison.OrdinalIgnoreCase);
        s = s.Replace("[dot]", ".", StringComparison.OrdinalIgnoreCase);
        s = s.Replace("[.]", ".").Replace("(.)", ".").Replace("{.}", ".");
        s = s.Replace("[:]", ":").Replace("[@]", "@");
        return s;
    }
}
