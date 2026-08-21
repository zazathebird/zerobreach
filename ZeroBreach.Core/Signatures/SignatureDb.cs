using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using ZeroBreach.Core.Model;

namespace ZeroBreach.Core.Signatures;

/// <summary>
/// All signature/indicator data, loaded at runtime — embedded defaults plus any external
/// rule files the operator supplies (spec §3: signatures never live inline in engine logic;
/// this also lets the operator define custom checks without a rebuild).
///
/// Data shape: named indicator SETS. Each scanner asks for the sets it understands, e.g.
/// <c>db.Set("c2.named_pipes")</c>. Unknown sets are simply empty, so a custom rules file
/// can extend any category. Custom IOC files (--ioc-file) land in the "custom.*" sets.
/// </summary>
public sealed class SignatureDb
{
    private readonly Dictionary<string, List<IndicatorEntry>> _sets = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _vendorTrusted = new();
    private readonly List<string> _loadErrors = new();

    public IReadOnlyList<string> LoadErrors => _loadErrors;

    /// <summary>Names of vendor-trusted (soft-list) products per spec §6.3 — matched
    /// case-insensitively as substrings of paths/product names. Badge only, never a skip.</summary>
    public IReadOnlyList<string> VendorTrusted => _vendorTrusted;

    public IReadOnlyList<IndicatorEntry> Set(string name) =>
        _sets.TryGetValue(name, out var list) ? list : Array.Empty<IndicatorEntry>();

    public IEnumerable<string> SetNames => _sets.Keys;

    /// <summary>Total match-timeout count across every indicator in every set. A timed-out
    /// indicator never evaluated (spec §6.7: "couldn't run" is never "clean"), so the CLI
    /// reports a nonzero total as an Inconclusive check instead of silent no-match.</summary>
    public long TotalMatchTimeouts() =>
        _sets.Values.Sum(list => list.Sum(e => (long)e.MatchTimeouts));

    public bool IsVendorTrusted(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate)) return false;
        return _vendorTrusted.Any(v => candidate.Contains(v, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Loads every embedded Signatures/*.json resource from the given assemblies.</summary>
    public void LoadEmbedded(params Assembly[] assemblies)
    {
        foreach (var asm in assemblies)
        foreach (var res in asm.GetManifestResourceNames().Where(r => r.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                using var stream = asm.GetManifestResourceStream(res)!;
                using var reader = new StreamReader(stream);
                MergeJson(reader.ReadToEnd(), res);
            }
            catch (Exception ex)
            {
                _loadErrors.Add($"{res}: {ex.Message}");
            }
        }
    }

    /// <summary>Loads an external rules file (same JSON shape as the embedded ones).</summary>
    public void LoadRulesFile(string path)
    {
        try { MergeJson(File.ReadAllText(path), path); }
        catch (Exception ex) { _loadErrors.Add($"{path}: {ex.Message}"); }
    }

    /// <summary>
    /// Loads a custom IOC file (spec §2): JSON (same shape as rules files) or plain text,
    /// one indicator per line, '#' comments. Text lines are classified by shape:
    /// 64-hex → custom.hashes, IPv4 → custom.ips, dotted name → custom.domains,
    /// anything else → custom.filenames. IOC hits are reported as findings through the
    /// normal severity/confirmation gates — an operator-supplied IOC never auto-arms a
    /// destructive action by itself (spec §6.6 discipline: indicators from text are
    /// low-precision, so IOC-derived findings default to POSSIBLE severity and
    /// FixAction.None unless hash-confirmed).
    /// </summary>
    public void LoadIocFile(string path)
    {
        try
        {
            var text = File.ReadAllText(path);
            if (text.TrimStart().StartsWith('{')) { MergeJson(text, path); return; }

            foreach (var raw in text.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;

                // Trailing-dot FQDN notation ("evil.com.") is valid DNS and common in intel
                // dumps; without the strip it fails the domain shape and lands in
                // custom.filenames as a dead indicator. Strip one trailing dot before
                // classification and store the stripped form.
                if (line.Length > 1 && line.EndsWith('.'))
                    line = line[..^1];

                string set;
                if (Regex.IsMatch(line, "^[0-9a-fA-F]{64}$"))
                    set = "custom.hashes";
                else if (Regex.IsMatch(line, "^([0-9a-fA-F]{32}|[0-9a-fA-F]{40})$"))
                {
                    // MD5/SHA-1: the engine matches SHA-256 only, so this could only sit in
                    // custom.filenames and never match. A dead indicator must be disclosed,
                    // not silently carried (spec §6.7).
                    _loadErrors.Add($"{path}: '{line}' looks like an MD5/SHA-1 hash — not supported (the engine matches SHA-256 only); line skipped");
                    continue;
                }
                else if (Regex.IsMatch(line, @"^\d{1,3}(\.\d{1,3}){3}$"))
                {
                    var octets = line.Split('.').Select(int.Parse).ToArray();
                    if (octets.Any(o => o > 255))
                    {
                        // Dotted-quad shape but not a real IPv4 address: it would never match
                        // anything — disclose the dead indicator instead of carrying it.
                        _loadErrors.Add($"{path}: '{line}' looks like an IPv4 address but has an octet greater than 255; line skipped");
                        continue;
                    }
                    // Normalize leading zeros ("192.168.001.001") to the canonical form
                    // netstat/socket APIs emit, or the literal never matches at scan time.
                    line = string.Join('.', octets);
                    set = "custom.ips";
                }
                else if (Regex.IsMatch(line, @"^[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}$") &&
                         !Regex.IsMatch(line, @"\.(exe|dll|ps1|bat|cmd|vbs|js|scr|sys|tmp|dat|zip|rar|7z|lnk|docm|xlsm)$", RegexOptions.IgnoreCase))
                    set = "custom.domains";
                else
                    set = "custom.filenames";

                Add(set, new IndicatorEntry
                {
                    Pattern = line,
                    Kind = set == "custom.hashes" ? MatchKind.Sha256 : MatchKind.Literal,
                    Severity = Severity.Possible,
                    Note = $"custom IOC from {Path.GetFileName(path)}",
                });
            }
        }
        catch (Exception ex)
        {
            _loadErrors.Add($"{path}: {ex.Message}");
        }
    }

    public void Add(string setName, IndicatorEntry entry)
    {
        if (!_sets.TryGetValue(setName, out var list))
            _sets[setName] = list = new List<IndicatorEntry>();
        list.Add(entry);
    }

    private void MergeJson(string json, string sourceName)
    {
        var doc = JsonSerializer.Deserialize<SignatureFile>(json, JsonOpts);
        if (doc is null) return;

        if (doc.VendorTrusted is not null)
            foreach (var v in doc.VendorTrusted.Where(v => !string.IsNullOrWhiteSpace(v)))
                if (!_vendorTrusted.Contains(v, StringComparer.OrdinalIgnoreCase))
                    _vendorTrusted.Add(v);

        if (doc.Sets is not null)
            foreach (var (setName, entries) in doc.Sets)
            foreach (var e in entries)
            {
                if (string.IsNullOrWhiteSpace(e.Pattern))
                {
                    _loadErrors.Add($"{sourceName}: empty pattern in set {setName}");
                    continue;
                }
                if (e.Kind == MatchKind.Regex)
                {
                    try { _ = new Regex(e.Pattern); }
                    catch (Exception rex) { _loadErrors.Add($"{sourceName}: bad regex '{e.Pattern}' in {setName}: {rex.Message}"); continue; }
                }
                Add(setName, e);
            }
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private sealed class SignatureFile
    {
        public Dictionary<string, List<IndicatorEntry>>? Sets { get; set; }
        public List<string>? VendorTrusted { get; set; }
    }
}
