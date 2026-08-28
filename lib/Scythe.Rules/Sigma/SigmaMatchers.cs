using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Scythe.Rules.Sigma;

/// <summary>
/// Kleene tri-state outcome of one predicate during evaluation. <c>null</c> Value means
/// Incomplete and always carries a reason. Incomplete never collapses into false: a
/// predicate that could not run must not read as "did not match" (BLUEPRINT §2).
/// </summary>
internal readonly struct TriState
{
    private TriState(bool? value, string? reason)
    {
        Value = value;
        Reason = reason;
    }

    public bool? Value { get; }
    public string? Reason { get; }

    public bool IsTrue => Value == true;
    public bool IsFalse => Value == false;
    public bool IsIncomplete => Value is null;

    public static readonly TriState True = new(true, null);
    public static readonly TriState False = new(false, null);
    public static TriState Incomplete(string reason) => new(null, reason);
}

/// <summary>Character-level helpers shared by compile and match time.</summary>
internal static class SigmaText
{
    /// <summary>The windash character set: hyphen-minus, forward slash, en dash, em dash
    /// and horizontal bar. Windows command-line parsers accept all of these as a switch
    /// prefix, which is exactly what attackers exploit to dodge naive detections.</summary>
    internal static bool IsWindashDash(char c) => c is '-' or '/' or '–' or '—' or '―';

    /// <summary>Folds one character for comparison: optional windash dash-canonicalisation
    /// first, then invariant upper-casing (Sigma value comparison is case-insensitive by
    /// default). Folding *both* the pattern and the input over the full dash set is
    /// equivalent to the reference behaviour of expanding every dash in the pattern to
    /// all variants and OR-ing the expansion — but also handles mixed variants
    /// per-occurrence, which uniform textual expansion would miss.</summary>
    internal static char Fold(char c, bool windash)
    {
        if (windash && IsWindashDash(c))
        {
            return '-';
        }
        return char.ToUpperInvariant(c);
    }

    /// <summary>Invariant string form of a record field value. Null stays null (a present
    /// null field is distinct from a missing field). Booleans stringify lower-case so a
    /// boolean true in a record compares equal to YAML <c>true</c> in a rule.</summary>
    internal static string? Stringify(object? value) => value switch
    {
        null => null,
        string s => s,
        bool b => b ? "true" : "false",
        char[] c => new string(c),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };
}

internal enum GlobTokenKind
{
    /// <summary>One literal character (stored pre-folded).</summary>
    Literal,
    /// <summary>'*' — any run of characters, including empty.</summary>
    Star,
    /// <summary>'?' — exactly one character, any.</summary>
    AnyChar,
}

internal readonly record struct GlobToken(GlobTokenKind Kind, char Literal)
{
    public static readonly GlobToken Star = new(GlobTokenKind.Star, '\0');
    public static readonly GlobToken AnyChar = new(GlobTokenKind.AnyChar, '\0');
}

/// <summary>One compiled value test. Implementations are pure and thread-safe; only the
/// regex matcher can return Incomplete (budget). A null field value (field present, value
/// null) matches only the dedicated null matcher.</summary>
internal abstract class ValueMatcher
{
    public abstract TriState Matches(string? fieldValue);
}

/// <summary>Matches <c>Field: null</c> — the field is present with a null value. A missing
/// field never reaches any matcher (the field test returns false first): per the task
/// brief, missing is not a match and is distinct from present-with-null.</summary>
internal sealed class NullValueMatcher : ValueMatcher
{
    public static readonly NullValueMatcher Instance = new();

    private NullValueMatcher()
    {
    }

    public override TriState Matches(string? fieldValue) =>
        fieldValue is null ? TriState.True : TriState.False;
}

/// <summary>
/// Anchored glob match over the whole field value: literal characters plus '*' and '?'.
/// contains/startswith/endswith are expressed by the compiler as leading/trailing stars.
/// Comparison is case-insensitive (invariant upper-case fold); with windash, all dash
/// variants on both sides canonicalise to '-'. The single-star backtracking algorithm is
/// O(pattern × input) worst case — polynomial, so it cannot blow up the way a
/// backtracking regex can, and stays bounded by the field-test deadline checks.
/// </summary>
internal sealed class GlobMatcher : ValueMatcher
{
    private readonly GlobToken[] _pattern;
    private readonly bool _windash;

    /// <summary>Pattern literals must already be folded with <see cref="SigmaText.Fold"/>
    /// using the same <paramref name="windash"/> flag.</summary>
    public GlobMatcher(GlobToken[] pattern, bool windash)
    {
        _pattern = pattern;
        _windash = windash;
    }

    public override TriState Matches(string? fieldValue)
    {
        if (fieldValue is null)
        {
            return TriState.False;
        }
        return IsMatch(fieldValue) ? TriState.True : TriState.False;
    }

    private bool IsMatch(string input)
    {
        var pat = _pattern;
        int t = 0;
        int p = 0;
        int starP = -1;
        int starT = 0;
        while (t < input.Length)
        {
            if (p < pat.Length
                && (pat[p].Kind == GlobTokenKind.AnyChar
                    || (pat[p].Kind == GlobTokenKind.Literal
                        && pat[p].Literal == SigmaText.Fold(input[t], _windash))))
            {
                p++;
                t++;
            }
            else if (p < pat.Length && pat[p].Kind == GlobTokenKind.Star)
            {
                starP = p;
                p++;
                starT = t;
            }
            else if (starP >= 0)
            {
                // Backtrack: let the last star swallow one more input character.
                p = starP + 1;
                starT++;
                t = starT;
            }
            else
            {
                return false;
            }
        }
        while (p < pat.Length && pat[p].Kind == GlobTokenKind.Star)
        {
            p++;
        }
        return p == pat.Length;
    }
}

/// <summary>
/// The <c>re</c> modifier. Case-<b>sensitive</b> and unanchored (search semantics), per
/// reference Sigma — regex values are the one place Sigma is not case-insensitive by
/// default. The regex runs under <see cref="BudgetDefaults.PerPatternDeadline"/>; a
/// timeout is Incomplete, never false — an attacker who can stall the regex must not be
/// able to convert that stall into a clean verdict.
/// </summary>
internal sealed class RegexValueMatcher : ValueMatcher
{
    private readonly Regex _regex;
    private readonly string _pattern;

    public RegexValueMatcher(Regex regex, string pattern)
    {
        _regex = regex;
        _pattern = pattern;
    }

    public override TriState Matches(string? fieldValue)
    {
        if (fieldValue is null)
        {
            return TriState.False;
        }
        try
        {
            return _regex.IsMatch(fieldValue) ? TriState.True : TriState.False;
        }
        catch (RegexMatchTimeoutException)
        {
            return TriState.Incomplete(
                $"regex '{_pattern}' exceeded its {BudgetDefaults.PerPatternDeadline.TotalMilliseconds:0}ms match budget");
        }
    }
}

/// <summary>
/// The <c>cidr</c> modifier: the field value is an IP address inside the rule's network.
/// IPv4 and IPv6. An IPv4-mapped IPv6 record value ("::ffff:10.1.2.3") is compared as
/// IPv4 against an IPv4 network. A field value that is not an address of the network's
/// family is simply not in the network — false, not an error.
/// </summary>
internal sealed class CidrMatcher : ValueMatcher
{
    private readonly byte[] _network;
    private readonly int _prefixBits;
    private readonly AddressFamily _family;

    public CidrMatcher(IPAddress network, int prefixBits)
    {
        _network = network.GetAddressBytes();
        _prefixBits = prefixBits;
        _family = network.AddressFamily;
    }

    public override TriState Matches(string? fieldValue)
    {
        if (fieldValue is null)
        {
            return TriState.False;
        }
        string candidate = fieldValue.Trim();
        // IPAddress.TryParse is dangerously lenient for IPv4 ("1" parses as 0.0.0.1),
        // which on attacker-chosen text is a false-hit hazard. Require the conventional
        // shapes: dotted quad for v4, at least one colon for v6.
        if (!candidate.Contains(':') && candidate.Count(c => c == '.') != 3)
        {
            return TriState.False;
        }
        if (!IPAddress.TryParse(candidate, out var ip))
        {
            return TriState.False;
        }
        if (_family == AddressFamily.InterNetwork
            && ip.AddressFamily == AddressFamily.InterNetworkV6
            && ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }
        if (ip.AddressFamily != _family)
        {
            return TriState.False;
        }
        byte[] bytes = ip.GetAddressBytes();
        int fullBytes = _prefixBits / 8;
        for (int i = 0; i < fullBytes; i++)
        {
            if (bytes[i] != _network[i])
            {
                return TriState.False;
            }
        }
        int remainder = _prefixBits % 8;
        if (remainder != 0)
        {
            int mask = 0xFF << (8 - remainder);
            if ((bytes[fullBytes] & mask) != (_network[fullBytes] & mask))
            {
                return TriState.False;
            }
        }
        return TriState.True;
    }
}
