using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Scythe.Correlation;

/// <summary>
/// One pure normalisation function per entity kind (reference/07.1_linking.md, table of kinds).
/// Each makes two spellings of one thing compare equal without making two different things
/// compare equal; where the text does not denote an entity of the stated kind the result is
/// <see cref="CorrelationResultState.Failed"/> with a message a person can act on.
/// </summary>
/// <remarks>
/// Nothing here touches a disk, a registry, a resolver or the thread culture. Relative segments
/// are resolved textually; a host name and a literal address stay distinct; a mapped drive and
/// its UNC spelling stay distinct (the record carries no mapping and the library will not invent one).
/// </remarks>
public static class EntityNormaliser
{
    /// <summary>
    /// The longest text any normaliser will look at. 32 767 is the extended-length path ceiling on
    /// the target platform; nothing a host produced is longer, and a description carrying a longer
    /// path-shaped run is a hazard to bound rather than an entity to normalise.
    /// </summary>
    public const int MaxEntityTextLength = 32_767;

    private const string LongPathPrefix = @"\\?\";
    private const string LongPathUncPrefix = @"UNC\";
    private const string DevicePrefix = @"\\.\";
    private const string NtObjectPrefix = @"\??\";

    /// <summary>Characters that cannot appear in a path segment. ':' is allowed because it names an alternate data stream.</summary>
    private const string ForbiddenPathChars = "<>\"|?*";

    /// <summary>
    /// Registry value separator in the single-string form: a doubled separator, because a key name
    /// cannot contain a separator, so a doubled one is never key syntax. Text after the first
    /// occurrence is the value name; an empty remainder is the key's default value.
    /// </summary>
    public const string RegistryValueSeparator = @"\\";

    public static CorrelationResult<Entity> Normalise(EntityKind kind, string? text) => kind switch
    {
        EntityKind.Path => NormalisePath(text),
        EntityKind.RegistryPath => NormaliseRegistryPath(text),
        EntityKind.ProcessId => NormaliseProcessId(text),
        EntityKind.HostName => NormaliseHostName(text),
        EntityKind.NetworkPeer => NormaliseNetworkPeer(text),
        _ => CorrelationResult<Entity>.Failed($"unknown entity kind {(int)kind}"),
    };

    /// <summary>
    /// Whether two strings, read as the given kind, denote one entity. Answers
    /// <see cref="EntityComparison.NotComparable"/> when either does not normalise.
    /// </summary>
    public static EntityComparison Compare(EntityKind kind, string? a, string? b)
    {
        var left = Normalise(kind, a);
        var right = Normalise(kind, b);
        if (!left.IsOk || !right.IsOk) return EntityComparison.NotComparable;
        return left.Value!.Equals(right.Value!) ? EntityComparison.Same : EntityComparison.Different;
    }

    // ------------------------------------------------------------------ paths

    /// <summary>
    /// Drive-letter (<c>C:\dir\file</c>) and UNC (<c>\\server\share\dir\file</c>) forms, with the
    /// extended-length prefix (<c>\\?\C:\...</c>, <c>\\?\UNC\server\share\...</c>) folded onto the
    /// plain form. Separators are normalised to backslash, runs collapsed, a trailing separator
    /// removed (the drive root keeps its one separator so <c>C:\</c> stays distinguishable from a
    /// drive-relative <c>C:</c>), and <c>.</c> / <c>..</c> resolved textually with <c>..</c> clamped
    /// at the root. Relative and drive-relative paths are refused: nothing can say what they are
    /// relative to.
    /// </summary>
    public static CorrelationResult<Entity> NormalisePath(string? text)
    {
        if (text is null) return CorrelationResult<Entity>.Failed("path is null");
        var s = text.Trim();
        if (s.Length == 0) return CorrelationResult<Entity>.Failed("path is empty");
        if (s.Length > MaxEntityTextLength)
        {
            return CorrelationResult<Entity>.Failed(
                $"path is {s.Length} characters, above the {MaxEntityTextLength}-character ceiling");
        }

        s = s.Replace('/', '\\');

        if (s.StartsWith(LongPathPrefix, StringComparison.Ordinal))
        {
            var rest = s.Substring(LongPathPrefix.Length);
            s = rest.StartsWith(LongPathUncPrefix, StringComparison.OrdinalIgnoreCase)
                ? @"\\" + rest.Substring(LongPathUncPrefix.Length)
                : rest;
        }

        if (s.StartsWith(DevicePrefix, StringComparison.Ordinal))
        {
            return CorrelationResult<Entity>.Failed("device-namespace path (\\\\.\\) is not a file-system entity");
        }

        if (s.StartsWith(NtObjectPrefix, StringComparison.Ordinal))
        {
            return CorrelationResult<Entity>.Failed("NT object-manager path (\\??\\) is not a Win32 path");
        }

        if (s.StartsWith(@"\\", StringComparison.Ordinal)) return NormaliseUnc(s);

        if (s.Length >= 2 && IsAsciiLetter(s[0]) && s[1] == ':')
        {
            if (s.Length == 2 || s[2] != '\\')
            {
                return CorrelationResult<Entity>.Failed(
                    "drive-relative path has no root; it depends on a current directory the record does not carry",
                    2);
            }

            var root = char.ToUpperInvariant(s[0]) + @":\";
            return Resolve(root, s.AsSpan(3), 3);
        }

        return CorrelationResult<Entity>.Failed("not an absolute drive-letter or UNC path", 0);
    }

    private static CorrelationResult<Entity> NormaliseUnc(string s)
    {
        // Past the two leading separators. Runs of separators collapse, so \\\\server\share is
        // server + share, and \\server\\share likewise.
        var body = s.AsSpan(2);
        var segments = new List<(string Text, int Offset)>();
        SplitSegments(body, 2, segments);

        if (segments.Count == 0)
        {
            return CorrelationResult<Entity>.Failed("UNC path has no server component", 0);
        }

        var server = segments[0];
        if (server.Text == "?" || server.Text == ".")
        {
            return CorrelationResult<Entity>.Failed($"'\\\\{server.Text}\\' prefix is not followed by a recognised form", server.Offset);
        }

        var badServer = FirstForbidden(server.Text);
        if (badServer is not null)
        {
            return CorrelationResult<Entity>.Failed(
                $"UNC server '{server.Text}' contains {Describe(badServer.Value)}", server.Offset);
        }

        if (segments.Count == 1)
        {
            // A server alone is a host, not a file-system location; the caller said this was a
            // path, so the honest answer is that it is not one, rather than a HostName entity the
            // caller did not ask for.
            return CorrelationResult<Entity>.Failed(
                $"UNC path '\\\\{server.Text}' names a server but no share", server.Offset);
        }

        var share = segments[1];
        var badShare = FirstForbidden(share.Text);
        if (badShare is not null)
        {
            return CorrelationResult<Entity>.Failed(
                $"UNC share '{share.Text}' contains {Describe(badShare.Value)}", share.Offset);
        }

        var root = @"\\" + server.Text + @"\" + share.Text;
        return ResolveSegments(root, segments, 2, rootHasTrailingSeparator: false);
    }

    private static CorrelationResult<Entity> Resolve(string root, ReadOnlySpan<char> remainder, int baseOffset)
    {
        var segments = new List<(string Text, int Offset)>();
        SplitSegments(remainder, baseOffset, segments);
        return ResolveSegments(root, segments, 0, rootHasTrailingSeparator: true);
    }

    private static CorrelationResult<Entity> ResolveSegments(
        string root, List<(string Text, int Offset)> segments, int first, bool rootHasTrailingSeparator)
    {
        var stack = new List<string>();
        for (var i = first; i < segments.Count; i++)
        {
            var (seg, offset) = segments[i];
            if (seg == ".") continue;
            if (seg == "..")
            {
                // Textual resolution only: '..' above the root stays at the root, which is what
                // the platform does with the same string. There is no disk here to say otherwise.
                if (stack.Count > 0) stack.RemoveAt(stack.Count - 1);
                continue;
            }

            var bad = FirstForbidden(seg);
            if (bad is not null)
            {
                return CorrelationResult<Entity>.Failed(
                    $"path segment '{seg}' contains {Describe(bad.Value)}", offset);
            }

            stack.Add(seg);
        }

        if (stack.Count == 0) return CorrelationResult<Entity>.Ok(new Entity(EntityKind.Path, root));

        var builder = new StringBuilder(root.Length + 16 * stack.Count);
        builder.Append(root);
        if (!rootHasTrailingSeparator) builder.Append('\\');
        builder.Append(string.Join('\\', stack));
        return CorrelationResult<Entity>.Ok(new Entity(EntityKind.Path, builder.ToString()));
    }

    private static void SplitSegments(ReadOnlySpan<char> text, int baseOffset, List<(string Text, int Offset)> into)
    {
        var start = 0;
        for (var i = 0; i <= text.Length; i++)
        {
            if (i == text.Length || text[i] == '\\')
            {
                if (i > start) into.Add((text.Slice(start, i - start).ToString(), baseOffset + start));
                start = i + 1;
            }
        }
    }

    private static char? FirstForbidden(string segment)
    {
        foreach (var c in segment)
        {
            if (c < ' ' || ForbiddenPathChars.Contains(c)) return c;
        }

        return null;
    }

    private static string Describe(char c) =>
        c < ' ' ? $"control character U+{(int)c:X4}" : $"'{c}'";

    private static bool IsAsciiLetter(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');

    // --------------------------------------------------------------- registry

    private static readonly (string Spelling, string Hive)[] HiveSpellings =
    [
        ("HKEY_LOCAL_MACHINE", "HKLM"), ("HKLM", "HKLM"),
        ("HKEY_CURRENT_USER", "HKCU"), ("HKCU", "HKCU"),
        ("HKEY_CLASSES_ROOT", "HKCR"), ("HKCR", "HKCR"),
        ("HKEY_USERS", "HKU"), ("HKU", "HKU"),
        ("HKEY_CURRENT_CONFIG", "HKCC"), ("HKCC", "HKCC"),
    ];

    /// <summary>
    /// <c>HIVE\key\subkey</c>, optionally followed by <see cref="RegistryValueSeparator"/> and a
    /// value name. Hive abbreviations and long forms (and the PowerShell drive spelling
    /// <c>HKLM:</c>) fold to the abbreviation. Exactly one trailing separator is removed from a key;
    /// two trailing separators mean the key's default value, which is a different entity from the
    /// key. Forward slashes are <b>not</b> separators here — they are legal in key names.
    /// </summary>
    public static CorrelationResult<Entity> NormaliseRegistryPath(string? text)
    {
        if (text is null) return CorrelationResult<Entity>.Failed("registry path is null");
        var s = text.Trim();
        if (s.Length == 0) return CorrelationResult<Entity>.Failed("registry path is empty");
        if (s.Length > MaxEntityTextLength)
        {
            return CorrelationResult<Entity>.Failed(
                $"registry path is {s.Length} characters, above the {MaxEntityTextLength}-character ceiling");
        }

        var valueIndex = s.IndexOf(RegistryValueSeparator, StringComparison.Ordinal);
        var keyText = valueIndex < 0 ? s : s.Substring(0, valueIndex);
        var valueName = valueIndex < 0 ? null : s.Substring(valueIndex + RegistryValueSeparator.Length);

        if (valueName is null && keyText.EndsWith('\\')) keyText = keyText.Substring(0, keyText.Length - 1);

        var firstSeparator = keyText.IndexOf('\\');
        var hiveText = firstSeparator < 0 ? keyText : keyText.Substring(0, firstSeparator);
        if (hiveText.EndsWith(':')) hiveText = hiveText.Substring(0, hiveText.Length - 1);

        string? hive = null;
        foreach (var (spelling, abbreviation) in HiveSpellings)
        {
            if (string.Equals(spelling, hiveText, StringComparison.OrdinalIgnoreCase))
            {
                hive = abbreviation;
                break;
            }
        }

        if (hive is null)
        {
            return CorrelationResult<Entity>.Failed($"'{hiveText}' is not a recognised hive", 0);
        }

        return NormaliseRegistry(hive, firstSeparator < 0 ? "" : keyText.Substring(firstSeparator + 1), valueName, firstSeparator + 1);
    }

    /// <summary>
    /// The two-argument form for callers that hold the key path and value name separately. An
    /// empty <paramref name="valueName"/> is the key's default value; a null one means the key.
    /// </summary>
    public static CorrelationResult<Entity> NormaliseRegistryValue(string? keyPath, string? valueName)
    {
        var key = NormaliseRegistryPath(keyPath);
        if (!key.IsOk) return key;
        if (key.Value!.Value.Contains(RegistryValueSeparator, StringComparison.Ordinal))
        {
            return CorrelationResult<Entity>.Failed("key path already carries a value name");
        }

        if (valueName is null) return key;
        if (valueName.Length > MaxEntityTextLength || key.Value.Value.Length + valueName.Length > MaxEntityTextLength)
        {
            return CorrelationResult<Entity>.Failed("registry value name pushes the entity above the length ceiling");
        }

        var badValue = FirstControl(valueName);
        if (badValue is not null)
        {
            return CorrelationResult<Entity>.Failed($"registry value name contains {Describe(badValue.Value)}");
        }

        return CorrelationResult<Entity>.Ok(
            new Entity(EntityKind.RegistryPath, key.Value.Value + RegistryValueSeparator + valueName));
    }

    private static CorrelationResult<Entity> NormaliseRegistry(string hive, string keyRemainder, string? valueName, int keyOffset)
    {
        var builder = new StringBuilder(hive);
        if (keyRemainder.Length > 0)
        {
            var offset = keyOffset;
            foreach (var segment in keyRemainder.Split('\\'))
            {
                if (segment.Length == 0)
                {
                    // Cannot occur after the value split, but the guard costs nothing and
                    // documents the invariant.
                    return CorrelationResult<Entity>.Failed("registry key has an empty segment", offset);
                }

                var bad = FirstControl(segment);
                if (bad is not null)
                {
                    return CorrelationResult<Entity>.Failed(
                        $"registry key segment '{segment}' contains {Describe(bad.Value)}", offset);
                }

                builder.Append('\\').Append(segment);
                offset += segment.Length + 1;
            }
        }

        if (valueName is not null)
        {
            var bad = FirstControl(valueName);
            if (bad is not null)
            {
                return CorrelationResult<Entity>.Failed($"registry value name contains {Describe(bad.Value)}");
            }

            builder.Append(RegistryValueSeparator).Append(valueName);
        }

        return CorrelationResult<Entity>.Ok(new Entity(EntityKind.RegistryPath, builder.ToString()));
    }

    private static char? FirstControl(string text)
    {
        foreach (var c in text)
        {
            if (c < ' ') return c;
        }

        return null;
    }

    // ------------------------------------------------------------ process ids

    /// <summary>
    /// A live-process identifier: a positive integer. Zero is refused because it is both the idle
    /// process and the conventional "no process" sentinel, and a run full of checks that could not
    /// name a process must not fuse on it; negatives are refused because the platform never
    /// issues one. Only meaningful within one record — see <see cref="EntityKind.ProcessId"/>.
    /// </summary>
    public static CorrelationResult<Entity> NormaliseProcessId(int id)
    {
        if (id == 0)
        {
            return CorrelationResult<Entity>.Failed(
                "process identifier 0 is the idle-process / 'no process' sentinel, not a linkable process");
        }

        if (id < 0)
        {
            return CorrelationResult<Entity>.Failed($"process identifier {id} is negative; the platform never issues one");
        }

        return CorrelationResult<Entity>.Ok(new Entity(EntityKind.ProcessId, id.ToString(CultureInfo.InvariantCulture)));
    }

    /// <summary>The textual form: optional surrounding whitespace, then decimal digits only.</summary>
    public static CorrelationResult<Entity> NormaliseProcessId(string? text)
    {
        if (text is null) return CorrelationResult<Entity>.Failed("process identifier is null");
        var s = text.Trim();
        if (s.Length == 0) return CorrelationResult<Entity>.Failed("process identifier is empty");

        var negative = s[0] == '-';
        var digits = negative ? s.AsSpan(1) : s.AsSpan();
        if (digits.Length == 0) return CorrelationResult<Entity>.Failed("process identifier has a sign and no digits");
        foreach (var c in digits)
        {
            if (c < '0' || c > '9')
            {
                return CorrelationResult<Entity>.Failed($"process identifier '{s}' is not a decimal integer");
            }
        }

        if (digits.Length > 10 || !int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            return CorrelationResult<Entity>.Failed($"process identifier '{s}' is outside the 32-bit range the platform issues");
        }

        return NormaliseProcessId(negative ? -value : value);
    }

    // ------------------------------------------------------------- host names

    private const int MaxHostNameLength = 253;
    private const int MaxLabelLength = 63;

    /// <summary>
    /// A DNS-style name: one trailing dot removed, ASCII case folded to lower. Labels are letters,
    /// digits and hyphens, 1–63 characters, not starting or ending with a hyphen, 253 characters
    /// in all. A literal address is refused (it is a <see cref="EntityKind.NetworkPeer"/>), as is
    /// any non-ASCII label: the library does not apply IDNA, so it cannot say what such a name
    /// compares equal to.
    /// </summary>
    public static CorrelationResult<Entity> NormaliseHostName(string? text)
    {
        if (text is null) return CorrelationResult<Entity>.Failed("host name is null");
        var s = text.Trim();
        if (s.Length == 0) return CorrelationResult<Entity>.Failed("host name is empty");
        if (s.Length > MaxEntityTextLength)
        {
            return CorrelationResult<Entity>.Failed($"host name is {s.Length} characters, above the {MaxEntityTextLength}-character ceiling");
        }

        if (s.EndsWith('.')) s = s.Substring(0, s.Length - 1);
        if (s.Length == 0) return CorrelationResult<Entity>.Failed("host name is a single dot: no label at all");
        if (s.Length > MaxHostNameLength)
        {
            return CorrelationResult<Entity>.Failed($"host name is {s.Length} characters, above the {MaxHostNameLength}-character limit");
        }

        if (TryParseIPv4(s, out _) || LooksLikeIPv6(s))
        {
            return CorrelationResult<Entity>.Failed(
                $"'{s}' is a literal address, not a name; a NetworkPeer entity is distinct from a HostName", 0);
        }

        var offset = 0;
        foreach (var label in s.Split('.'))
        {
            var problem = LabelProblem(label);
            if (problem is not null)
            {
                return CorrelationResult<Entity>.Failed($"host name label '{label}': {problem}", offset);
            }

            offset += label.Length + 1;
        }

        return CorrelationResult<Entity>.Ok(new Entity(EntityKind.HostName, AsciiLower(s)));
    }

    internal static string? LabelProblem(string label)
    {
        if (label.Length == 0) return "empty label";
        if (label.Length > MaxLabelLength) return $"{label.Length} characters, above the 63-character label limit";
        if (label[0] == '-' || label[^1] == '-') return "starts or ends with a hyphen";
        foreach (var c in label)
        {
            if (c > 0x7F) return "non-ASCII character; the library does not apply IDNA";
            if (!IsAsciiLetter(c) && (c < '0' || c > '9') && c != '-') return $"contains '{c}'";
        }

        return null;
    }

    private static string AsciiLower(string s)
    {
        // ASCII-only by construction (LabelProblem refused anything else), so this is the
        // culture-independent fold by definition.
        return string.Create(s.Length, s, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                var c = source[i];
                span[i] = c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
            }
        });
    }

    // ---------------------------------------------------------- network peers

    /// <summary>
    /// A literal IPv4 or IPv6 address. IPv4 is four decimal octets 0–255 with no leading zeros
    /// (a leading zero is octal to some parsers and decimal to others, so the text is ambiguous
    /// and refused). IPv6 is parsed and re-rendered in its canonical compressed lower-case form;
    /// square brackets around it are removed. A port is not part of the entity and is refused, and
    /// so is the unspecified address (<c>0.0.0.0</c>, <c>::</c>), which is a sentinel, not a peer.
    /// </summary>
    public static CorrelationResult<Entity> NormaliseNetworkPeer(string? text)
    {
        if (text is null) return CorrelationResult<Entity>.Failed("network peer is null");
        var s = text.Trim();
        if (s.Length == 0) return CorrelationResult<Entity>.Failed("network peer is empty");
        if (s.Length > MaxEntityTextLength)
        {
            return CorrelationResult<Entity>.Failed($"network peer is {s.Length} characters, above the {MaxEntityTextLength}-character ceiling");
        }

        if (s.Length >= 2 && s[0] == '[' && s[^1] == ']') s = s.Substring(1, s.Length - 2);

        if (TryParseIPv4(s, out var v4))
        {
            return v4 == "0.0.0.0" ? UnspecifiedAddress(v4) : CorrelationResult<Entity>.Ok(new Entity(EntityKind.NetworkPeer, v4));
        }

        if (LooksLikeIPv6(s) && IPAddress.TryParse(s, out var parsed) && parsed.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // IPAddress.ToString renders the RFC 5952 compressed lower-case form. Parsing is a
            // pure string operation; no resolver is involved.
            var canonical = parsed.ToString();
            return canonical == "::" ? UnspecifiedAddress(canonical) : CorrelationResult<Entity>.Ok(new Entity(EntityKind.NetworkPeer, canonical));
        }

        return CorrelationResult<Entity>.Failed($"'{s}' is not a literal IPv4 or IPv6 address", 0);
    }

    /// <summary>
    /// The all-zero address is "no address" — the wildcard a listener binds, the value a field
    /// holds when nothing was recorded. It is the sentinel of hazard 4 (reference/00_shared.md §3):
    /// accepting it would let every finding with an unrecorded peer link on it.
    /// </summary>
    private static CorrelationResult<Entity> UnspecifiedAddress(string text) =>
        CorrelationResult<Entity>.Failed($"'{text}' is the unspecified address — a 'no address' sentinel, not a peer");

    /// <summary>Strict dotted-quad: exactly four decimal octets, no leading zeros, each 0–255.</summary>
    internal static bool TryParseIPv4(string s, out string canonical)
    {
        canonical = "";
        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (var part in parts)
        {
            if (part.Length == 0 || part.Length > 3) return false;
            if (part.Length > 1 && part[0] == '0') return false;
            var value = 0;
            foreach (var c in part)
            {
                if (c < '0' || c > '9') return false;
                value = value * 10 + (c - '0');
            }

            if (value > 255) return false;
        }

        canonical = string.Join('.', parts);
        return true;
    }

    /// <summary>Cheap shape test before handing a token to the address parser: two or more colons, hex/colon/dot/percent only.</summary>
    internal static bool LooksLikeIPv6(string s)
    {
        var colons = 0;
        foreach (var c in s)
        {
            if (c == ':') colons++;
            else if (!Uri.IsHexDigit(c) && c != '.' && c != '%' && !IsAsciiLetter(c) && (c < '0' || c > '9')) return false;
        }

        return colons >= 2;
    }
}
