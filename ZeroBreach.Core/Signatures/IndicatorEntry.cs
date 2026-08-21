using System.Text;
using System.Text.RegularExpressions;
using ZeroBreach.Core.Model;

namespace ZeroBreach.Core.Signatures;

public enum MatchKind
{
    /// <summary>Case-insensitive exact match, or substring when <see cref="IndicatorEntry.Substring"/> is set.</summary>
    Literal = 0,
    /// <summary>Wildcard pattern (* and ?), case-insensitive, matched against the whole input.</summary>
    Glob = 1,
    /// <summary>.NET regex, case-insensitive.</summary>
    Regex = 2,
    /// <summary>64-hex SHA-256 — compared case-insensitively against a computed hash.</summary>
    Sha256 = 3,
}

/// <summary>One indicator in a signature set. Severity/MITRE here are defaults the scanner
/// may use when raising a finding from this indicator.</summary>
public sealed class IndicatorEntry
{
    public required string Pattern { get; set; }
    public MatchKind Kind { get; set; } = MatchKind.Literal;
    public bool Substring { get; set; }

    public Severity Severity { get; set; } = Severity.Possible;
    public string? Technique { get; set; }
    public string? TechniqueName { get; set; }
    public string? Tactic { get; set; }
    public string? Note { get; set; }

    /// <summary>For content indicators (spec §3): the finding requires corroboration beyond
    /// a bare name/string mention — scanners must not raise above POSSIBLE on this
    /// indicator alone when set.</summary>
    public bool NeedsCorroboration { get; set; }

    private Regex? _compiled;
    private int _timeoutCount;

    /// <summary>
    /// Number of times evaluating this indicator hit the regex match timeout. A timed-out
    /// indicator never fired — "couldn't evaluate" must not be folded into "didn't match"
    /// (spec §6.7: a check that couldn't run is inconclusive, never silently clean), so the
    /// scan must disclose a nonzero total rather than report the covered items as clean.
    /// </summary>
    public int MatchTimeouts => _timeoutCount;

    public bool Matches(string? input)
    {
        if (string.IsNullOrEmpty(input)) return false;
        switch (Kind)
        {
            case MatchKind.Literal:
                return Substring
                    ? input.Contains(Pattern, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(input, Pattern, StringComparison.OrdinalIgnoreCase);
            case MatchKind.Sha256:
                return string.Equals(input, Pattern, StringComparison.OrdinalIgnoreCase);
            case MatchKind.Glob:
                _compiled ??= new Regex(GlobToRegex(Pattern),
                    RegexOptions.IgnoreCase | RegexOptions.Compiled,
                    TimeSpan.FromSeconds(2));
                try { return _compiled.IsMatch(input); }
                catch (RegexMatchTimeoutException)
                {
                    Interlocked.Increment(ref _timeoutCount);
                    return false;
                }
            case MatchKind.Regex:
                _compiled ??= new Regex(Pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled,
                    TimeSpan.FromSeconds(2));
                try { return _compiled.IsMatch(input); }
                catch (RegexMatchTimeoutException)
                {
                    Interlocked.Increment(ref _timeoutCount);
                    return false;
                }
            default:
                return false;
        }
    }

    /// <summary>Translates a glob (* and ?) into an anchored regex. Escapes every non-wildcard
    /// character individually — a blanket <see cref="Regex.Escape(string)"/> followed by
    /// <c>Replace(@"\*", ...)</c> mangles patterns containing a literal backslash before a
    /// wildcard (e.g. <c>C:\tools\*.exe</c>).</summary>
    private static string GlobToRegex(string pattern)
    {
        var sb = new StringBuilder(pattern.Length + 8).Append('^');
        foreach (var c in pattern)
        {
            switch (c)
            {
                case '*': sb.Append(".*"); break;
                case '?': sb.Append('.'); break;
                default: sb.Append(Regex.Escape(c.ToString())); break;
            }
        }
        return sb.Append('$').ToString();
    }

    public MitreRef? Mitre =>
        Technique is null ? null : new MitreRef(Technique, TechniqueName ?? Technique, Tactic ?? "");
}
