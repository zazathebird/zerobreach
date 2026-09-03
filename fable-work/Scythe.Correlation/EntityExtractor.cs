using System.Diagnostics;

namespace Scythe.Correlation;

/// <summary>
/// Recognises entities in free text by shape (reference/07.1_linking.md). The text is scanned
/// once, left to right, as a sequence of tokens: a quoted span (<c>"..."</c> or <c>'...'</c> on
/// one line) is one token, otherwise a token runs to the next delimiter. Each token is classified
/// once and never re-scanned from an interior position.
/// </summary>
/// <remarks>
/// The recogniser is deliberately conservative. A bare two-label token (<c>setup.exe</c>,
/// <c>example.com</c>) is indistinguishable by shape from a file name, so it is not a host name
/// unless it is the authority of a URL; a bare number is not a process identifier unless a
/// <c>pid</c> keyword precedes it; a relative path is not a path. Where the shape is ambiguous the
/// extractor declines, because a wrong entity is a wrong edge, and a wrong edge joins findings
/// that have nothing to do with each other.
/// <para>
/// The known limitation is spaces: an unquoted path containing a space is recognised only up to
/// the space (<c>C:\Program Files\x.exe</c> yields <c>C:\Program</c>). That truncated entity is at
/// least consistent across findings, and when it is common it is exactly what the common-noun
/// cap in <see cref="ChainBuilder"/> absorbs. Producers that quote their paths get whole entities.
/// </para>
/// </remarks>
public static class EntityExtractor
{
    /// <summary>Characters that end an unquoted token. ':' is not one (drive letters, IPv6); '\' and '/' are not (paths).</summary>
    private const string Delimiters = "\"'<>|,;()[]{}=";

    /// <summary>Sentence punctuation stripped from the end of a token before classification.</summary>
    private const string TrailingPunctuation = ".,:;!?";

    private static readonly string[] ProcessKeywords = ["pid", "processid", "process-id", "process"];

    /// <summary>
    /// Every entity recognised in <paramref name="text"/>, in offset order. Mentions beyond
    /// <see cref="ScanBudget.MaxMatches"/> or a text beyond <see cref="ScanBudget.MaxInputBytes"/>
    /// (UTF-16 units × 2) yield <see cref="CorrelationResultState.Incomplete"/>.
    /// </summary>
    public static CorrelationResult<IReadOnlyList<EntityMention>> Extract(string? text, ScanBudget? budget = null)
    {
        budget ??= ScanBudget.Default;
        if (text is null) return CorrelationResult<IReadOnlyList<EntityMention>>.Ok([]);

        if ((long)text.Length * 2 > budget.MaxInputBytes)
        {
            return CorrelationResult<IReadOnlyList<EntityMention>>.Incomplete(
                null,
                $"text is {(long)text.Length * 2} bytes; budget allows {budget.MaxInputBytes}");
        }

        var mentions = new List<EntityMention>();
        var stopwatch = Stopwatch.StartNew();
        var outcome = ExtractInto(text, budget, stopwatch, budget.MaxMatches, mentions);
        return outcome is null
            ? CorrelationResult<IReadOnlyList<EntityMention>>.Ok(mentions)
            : CorrelationResult<IReadOnlyList<EntityMention>>.Incomplete(null, outcome);
    }

    /// <summary>
    /// Appends mentions to <paramref name="into"/>; returns null on success or the reason the
    /// scan stopped. <paramref name="remainingMatches"/> is the number of further mentions the
    /// caller's budget allows.
    /// </summary>
    internal static string? ExtractInto(string text, ScanBudget budget, Stopwatch stopwatch, int remainingMatches, List<EntityMention> into)
    {
        var position = 0;
        var checkCounter = 0;
        while (position < text.Length)
        {
            // The deadline is a wall-clock guard against pathological text; checking it every
            // 64 tokens keeps the cost off the ordinary path while still bounding the run.
            if ((++checkCounter & 63) == 0 && stopwatch.Elapsed > budget.Deadline)
            {
                return $"deadline of {budget.Deadline.TotalMilliseconds:0} ms exceeded while extracting entities";
            }

            var c = text[position];
            if (char.IsWhiteSpace(c))
            {
                position++;
                continue;
            }

            int tokenStart;
            int tokenLength;
            int next;

            if ((c == '"' || c == '\'') && TryFindClosingQuote(text, position, out var close))
            {
                tokenStart = position + 1;
                tokenLength = close - tokenStart;
                next = close + 1;
            }
            else if (Delimiters.Contains(c))
            {
                position++;
                continue;
            }
            else
            {
                tokenStart = position;
                var end = position;
                while (end < text.Length && !char.IsWhiteSpace(text[end]) && !Delimiters.Contains(text[end])) end++;
                tokenLength = end - tokenStart;
                next = end;
            }

            if (tokenLength > 0)
            {
                var mention = Classify(text, tokenStart, tokenLength, ref next);
                if (mention is not null)
                {
                    if (remainingMatches <= 0)
                    {
                        return $"more than {budget.MaxMatches} entity mentions; budget allows {budget.MaxMatches}";
                    }

                    into.Add(mention);
                    remainingMatches--;
                }
            }

            position = next;
        }

        return null;
    }

    private static bool TryFindClosingQuote(string text, int open, out int close)
    {
        var quote = text[open];
        for (var i = open + 1; i < text.Length; i++)
        {
            if (text[i] == quote)
            {
                close = i;
                return i > open + 1;
            }

            if (text[i] == '\n' || text[i] == '\r') break;
        }

        close = -1;
        return false;
    }

    /// <summary>
    /// Classifies one token. <paramref name="next"/> may be advanced when the token consumed a
    /// following token (the digits after a <c>pid</c> keyword).
    /// </summary>
    private static EntityMention? Classify(string text, int start, int length, ref int next)
    {
        // Trailing sentence punctuation, but never a '.' that is part of a '\.' or '\..' segment,
        // where stripping it would change what the path means.
        while (length > 0 && TrailingPunctuation.Contains(text[start + length - 1]))
        {
            if (text[start + length - 1] == '.' && EndsWithDotSegment(text, start, length)) break;
            length--;
        }

        if (length == 0 || length > EntityNormaliser.MaxEntityTextLength) return null;

        var token = text.Substring(start, length);

        // URL: the authority is unambiguous, so a two-label host is accepted here.
        var scheme = token.IndexOf("://", StringComparison.Ordinal);
        if (scheme > 0)
        {
            var authorityStart = scheme + 3;
            var authorityEnd = token.IndexOfAny(['/', '?', '#'], authorityStart);
            if (authorityEnd < 0) authorityEnd = token.Length;
            var authority = token.Substring(authorityStart, authorityEnd - authorityStart);
            var at = authority.LastIndexOf('@');
            if (at >= 0) authority = authority.Substring(at + 1);
            var peer = ClassifyEndpoint(authority, minimumLabels: 2);
            return peer is null ? null : new EntityMention(peer, start, length);
        }

        if (StartsWithHive(token))
        {
            var registry = EntityNormaliser.NormaliseRegistryPath(token);
            return registry.IsOk ? new EntityMention(registry.Value!, start, length) : null;
        }

        if (LooksLikePathStart(token))
        {
            var path = EntityNormaliser.NormalisePath(token);
            return path.IsOk ? new EntityMention(path.Value!, start, length) : null;
        }

        var pid = ClassifyProcessId(text, token, start, length, ref next);
        if (pid is not null) return pid;

        var endpoint = ClassifyEndpoint(token, minimumLabels: 3);
        return endpoint is null ? null : new EntityMention(endpoint, start, length);
    }

    private static bool EndsWithDotSegment(string text, int start, int length)
    {
        var end = start + length;
        if (length >= 2 && (text[end - 2] == '\\' || text[end - 2] == '/')) return true;
        return length >= 3 && text[end - 2] == '.' && (text[end - 3] == '\\' || text[end - 3] == '/');
    }

    private static bool StartsWithHive(string token)
    {
        var sep = token.IndexOfAny(['\\', ':']);
        var head = sep < 0 ? token : token.Substring(0, sep);
        return head.StartsWith("HK", StringComparison.OrdinalIgnoreCase)
            && EntityNormaliser.NormaliseRegistryPath(head).IsOk;
    }

    private static bool LooksLikePathStart(string token)
    {
        if (token.Length >= 3 && char.IsAsciiLetter(token[0]) && token[1] == ':' && (token[2] == '\\' || token[2] == '/')) return true;
        return token.Length >= 3 && ((token[0] == '\\' && token[1] == '\\') || (token[0] == '/' && token[1] == '/'));
    }

    private static EntityMention? ClassifyProcessId(string text, string token, int start, int length, ref int next)
    {
        foreach (var keyword in ProcessKeywords)
        {
            if (!token.StartsWith(keyword, StringComparison.OrdinalIgnoreCase)) continue;
            var rest = token.AsSpan(keyword.Length);
            if (rest.Length > 0 && (rest[0] == ':' || rest[0] == '#')) rest = rest.Slice(1);

            if (rest.Length > 0)
            {
                // Same-token form: pid:1234, pid#1234, pid1234.
                var inline = EntityNormaliser.NormaliseProcessId(rest.ToString());
                return inline.IsOk ? new EntityMention(inline.Value!, start, length) : null;
            }

            // Keyword alone: the next token must be the digits, possibly after a lone ':' or '='.
            var cursor = next;
            while (cursor < text.Length && (char.IsWhiteSpace(text[cursor]) || text[cursor] == ':' || text[cursor] == '=')) cursor++;
            var digitsStart = cursor;
            while (cursor < text.Length && char.IsAsciiDigit(text[cursor])) cursor++;
            if (cursor == digitsStart) return null;
            if (cursor < text.Length && !char.IsWhiteSpace(text[cursor]) && !Delimiters.Contains(text[cursor]) && !TrailingPunctuation.Contains(text[cursor])) return null;

            var following = EntityNormaliser.NormaliseProcessId(text.Substring(digitsStart, cursor - digitsStart));
            if (!following.IsOk) return null;
            next = cursor;
            return new EntityMention(following.Value!, start, cursor - start);
        }

        return null;
    }

    /// <summary>
    /// A literal address or a host name, with an optional <c>:port</c> stripped for IPv4 and names.
    /// A bracketed IPv6 has had its brackets removed by the delimiter set already.
    /// </summary>
    private static Entity? ClassifyEndpoint(string token, int minimumLabels)
    {
        if (token.Length == 0) return null;

        var core = token;
        var colon = core.LastIndexOf(':');
        if (colon > 0 && core.IndexOf(':') == colon && core.Length - colon - 1 is > 0 and <= 5 && AllDigits(core.AsSpan(colon + 1)))
        {
            core = core.Substring(0, colon);
        }

        if (EntityNormaliser.TryParseIPv4(core, out _))
        {
            var peer = EntityNormaliser.NormaliseNetworkPeer(core);
            return peer.IsOk ? peer.Value : null;
        }

        if (EntityNormaliser.LooksLikeIPv6(token))
        {
            var peer = EntityNormaliser.NormaliseNetworkPeer(token);
            return peer.IsOk ? peer.Value : null;
        }

        var name = core.EndsWith('.') ? core.Substring(0, core.Length - 1) : core;
        var labels = name.Split('.');
        if (labels.Length < minimumLabels) return null;
        var last = labels[^1];
        if (last.Length < 2 || !AllAsciiLetters(last)) return null;

        var host = EntityNormaliser.NormaliseHostName(core);
        return host.IsOk ? host.Value : null;
    }

    private static bool AllDigits(ReadOnlySpan<char> span)
    {
        foreach (var c in span)
        {
            if (!char.IsAsciiDigit(c)) return false;
        }

        return true;
    }

    private static bool AllAsciiLetters(string s)
    {
        foreach (var c in s)
        {
            if (!char.IsAsciiLetter(c)) return false;
        }

        return true;
    }
}
