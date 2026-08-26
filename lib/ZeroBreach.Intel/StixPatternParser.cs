namespace ZeroBreach.Intel;

/// <summary>
/// Parses the subset of STIX 2.x patterning this layer supports: one or more observation
/// expressions joined by OR, each containing one or more equality comparisons joined by OR:
///
///   [file:hashes.'SHA-256' = 'aa…' OR file:hashes.MD5 = 'bb…'] OR [domain-name:value = 'evil.com']
///
/// The task brief's open question is answered conservatively: full STIX patterning is a small
/// language (AND, NOT, LIKE, MATCHES, IN, FOLLOWEDBY, WITHIN, REPEATS, qualifiers) and
/// anything beyond OR-joined equality is reported as unsupported with the construct named —
/// never silently skipped and never half-extracted. A pattern of the form
/// <c>[a = 'x' AND b = 'y']</c> means the *conjunction* is the indicator; extracting the
/// pieces would fabricate two indicators the feed never asserted.
///
/// The whole pattern is likewise rejected if any one comparison in it is unsupported: the
/// pattern is one indicator object, and partially honouring it would misattribute what the
/// feed said.
/// </summary>
internal static class StixPatternParser
{
    /// <summary>Maps a lowercased STIX object path to a candidate type. Paths are compared
    /// with segment quotes stripped, so <c>file:hashes.'SHA-256'</c> and
    /// <c>file:hashes.SHA-256</c> are the same key.</summary>
    private static readonly Dictionary<string, CandidateType> PathMap = new(StringComparer.Ordinal)
    {
        ["file:hashes.sha-256"] = CandidateType.Sha256,
        ["file:hashes.sha256"] = CandidateType.Sha256,
        ["file:hashes.sha-1"] = CandidateType.Sha1,
        ["file:hashes.sha1"] = CandidateType.Sha1,
        ["file:hashes.md5"] = CandidateType.Md5,
        ["file:name"] = CandidateType.Filename,
        ["directory:path"] = CandidateType.FilePath,
        ["ipv4-addr:value"] = CandidateType.Ipv4,
        ["ipv6-addr:value"] = CandidateType.Ipv6,
        ["domain-name:value"] = CandidateType.Domain,
        ["url:value"] = CandidateType.Url,
        ["email-addr:value"] = CandidateType.EmailAddress,
        ["windows-registry-key:key"] = CandidateType.RegistryKey,
        ["mutex:name"] = CandidateType.Mutex,
    };

    /// <summary>Parses <paramref name="pattern"/>. True with at least one (type, value) pair on
    /// success; false with a reason naming the unsupported or malformed construct otherwise.</summary>
    public static bool TryParse(string pattern, out List<(CandidateType Type, string Value)> comparisons, out string? reason)
    {
        comparisons = new List<(CandidateType, string)>();
        reason = null;
        var pos = 0;

        while (true)
        {
            SkipWhitespace(pattern, ref pos);
            if (pos >= pattern.Length || pattern[pos] != '[')
            {
                reason = "pattern does not start with '[' where an observation expression was expected";
                return false;
            }
            pos++; // consume '['

            // Comparisons inside one observation, OR-joined.
            while (true)
            {
                SkipWhitespace(pattern, ref pos);
                if (!TryReadPath(pattern, ref pos, out var path))
                {
                    reason = "malformed object path in pattern";
                    return false;
                }
                SkipWhitespace(pattern, ref pos);

                // Only '=' is supported. Name the operator we saw so the rejection is actionable.
                if (pos >= pattern.Length)
                {
                    reason = "pattern ends where a comparison operator was expected";
                    return false;
                }
                if (pattern[pos] != '=')
                {
                    var op = ReadOperatorToken(pattern, pos);
                    reason = $"unsupported comparison operator '{op}' (only '=' equality is supported)";
                    return false;
                }
                pos++; // consume '='

                SkipWhitespace(pattern, ref pos);
                if (!TryReadQuotedValue(pattern, ref pos, out var value))
                {
                    reason = "malformed quoted value in pattern (expected 'single-quoted string')";
                    return false;
                }

                if (!PathMap.TryGetValue(NormalizePath(path), out var type))
                {
                    reason = $"unsupported STIX object path '{path}'";
                    return false;
                }
                comparisons.Add((type, value));

                SkipWhitespace(pattern, ref pos);
                if (pos < pattern.Length && pattern[pos] == ']')
                {
                    pos++; // consume ']'
                    break;
                }
                var joiner = ReadWord(pattern, ref pos);
                if (joiner.Equals("OR", StringComparison.OrdinalIgnoreCase))
                    continue;
                reason = joiner.Length == 0
                    ? "pattern ends inside an observation expression (missing ']')"
                    : $"unsupported construct '{joiner}' in pattern (only OR-joined equality comparisons are supported)";
                return false;
            }

            SkipWhitespace(pattern, ref pos);
            if (pos >= pattern.Length)
                break; // done
            var outerJoiner = ReadWord(pattern, ref pos);
            if (outerJoiner.Equals("OR", StringComparison.OrdinalIgnoreCase))
                continue;
            // Covers AND, FOLLOWEDBY and trailing qualifiers (WITHIN, REPEATS, START/STOP).
            reason = outerJoiner.Length == 0
                ? "unexpected character after observation expression"
                : $"unsupported construct '{outerJoiner}' after observation expression (only OR is supported)";
            return false;
        }

        if (comparisons.Count == 0)
        {
            reason = "pattern contains no comparisons";
            return false;
        }
        return true;
    }

    /// <summary>Lowercases and strips single/double quotes from path segments, so quoted hash
    /// algorithm names compare equal to unquoted ones.</summary>
    private static string NormalizePath(string path)
    {
        Span<char> buf = stackalloc char[path.Length];
        var n = 0;
        foreach (var c in path)
        {
            if (c is '\'' or '"')
                continue;
            buf[n++] = char.ToLowerInvariant(c);
        }
        return new string(buf[..n]);
    }

    /// <summary>Reads an object path: identifier characters plus ':' and '.', with quoted
    /// segments (<c>hashes.'SHA-256'</c>) passed through verbatim.</summary>
    private static bool TryReadPath(string s, ref int pos, out string path)
    {
        var start = pos;
        while (pos < s.Length)
        {
            var c = s[pos];
            if (c is '\'' or '"')
            {
                // Quoted segment: consume to the matching quote. STIX dictionary keys do not
                // contain escaped quotes, so a bare scan is enough.
                var quote = c;
                pos++;
                while (pos < s.Length && s[pos] != quote)
                    pos++;
                if (pos >= s.Length)
                {
                    path = string.Empty;
                    return false;
                }
                pos++; // closing quote
                continue;
            }
            if (char.IsLetterOrDigit(c) || c is ':' or '.' or '-' or '_')
            {
                pos++;
                continue;
            }
            break;
        }
        path = s[start..pos];
        return path.Length > 0 && path.Contains(':');
    }

    private static bool TryReadQuotedValue(string s, ref int pos, out string value)
    {
        value = string.Empty;
        if (pos >= s.Length || s[pos] != '\'')
            return false;
        pos++;
        var sb = new System.Text.StringBuilder();
        while (pos < s.Length)
        {
            var c = s[pos];
            if (c == '\\' && pos + 1 < s.Length)
            {
                // STIX string escapes: \' and \\ only.
                sb.Append(s[pos + 1]);
                pos += 2;
                continue;
            }
            if (c == '\'')
            {
                pos++;
                value = sb.ToString();
                return true;
            }
            sb.Append(c);
            pos++;
        }
        return false; // unterminated
    }

    private static string ReadWord(string s, ref int pos)
    {
        var start = pos;
        while (pos < s.Length && char.IsLetter(s[pos]))
            pos++;
        return s[start..pos];
    }

    /// <summary>Peeks the operator token at <paramref name="pos"/> for an error message,
    /// without advancing.</summary>
    private static string ReadOperatorToken(string s, int pos)
    {
        var end = pos;
        while (end < s.Length && !char.IsWhiteSpace(s[end]) && s[end] != '\'' && end - pos < 12)
            end++;
        return s[pos..end];
    }

    private static void SkipWhitespace(string s, ref int pos)
    {
        while (pos < s.Length && char.IsWhiteSpace(s[pos]))
            pos++;
    }
}
