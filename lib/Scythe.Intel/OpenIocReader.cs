namespace Scythe.Intel;

using System.Text;
using System.Xml;

/// <summary>
/// OpenIOC XML reader: walks <c>Indicator</c>/<c>IndicatorItem</c> trees and extracts items
/// whose <c>condition</c> is <c>is</c> (equality — the same conservative subset as the STIX
/// reader; <c>contains</c> and friends are substring semantics this model cannot represent as
/// a typed indicator, so they are rejected with the condition named).
///
/// Hardening: the reader is created with <see cref="DtdProcessing.Prohibit"/> and a null
/// resolver, so a DOCTYPE — and with it any internal or external entity, i.e. the whole
/// XXE/billion-laughs family — fails the document loudly with a position instead of being
/// expanded. Namespaces vary across OpenIOC producers (1.0 vs 1.1), so elements are matched
/// by local name only.
/// </summary>
internal static class OpenIocReader
{
    /// <summary>Context <c>search</c> paths → candidate types, case-insensitive because
    /// real-world OpenIOC files are inconsistent about casing.</summary>
    private static readonly Dictionary<string, CandidateType> SearchMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["FileItem/Md5sum"] = CandidateType.Md5,
        ["FileItem/Sha1sum"] = CandidateType.Sha1,
        ["FileItem/Sha256sum"] = CandidateType.Sha256,
        ["FileItem/FileName"] = CandidateType.Filename,
        ["FileItem/FullPath"] = CandidateType.FilePath,
        ["FileItem/FilePath"] = CandidateType.FilePath,
        ["DnsEntryItem/Host"] = CandidateType.Domain,
        ["Network/DNS"] = CandidateType.Domain,
        ["UrlHistoryItem/URL"] = CandidateType.Url,
        ["Network/URI"] = CandidateType.Url,
        ["PortItem/remoteIP"] = CandidateType.IpAny,
        ["Network/IP"] = CandidateType.IpAny,
        ["RegistryItem/KeyPath"] = CandidateType.RegistryKey,
        ["RegistryItem/Path"] = CandidateType.RegistryKey,
        ["ProcessItem/Mutex"] = CandidateType.Mutex,
        ["Mutex/Name"] = CandidateType.Mutex,
        ["Email/From"] = CandidateType.EmailAddress,
        ["Email/To"] = CandidateType.EmailAddress,
    };

    public static FeedReadResult Read(string content, IngestBudget budget)
    {
        var settings = new XmlReaderSettings
        {
            // The XXE guard. Prohibit makes any DOCTYPE an XmlException before anything is
            // expanded; the null resolver is belt-and-braces should the mode ever change.
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
            MaxCharactersInDocument = budget.MaxInputBytes,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
        };

        var candidates = new List<Candidate>();
        var rejections = new List<ReaderRejection>();

        try
        {
            using var stringReader = new StringReader(content);
            using var reader = XmlReader.Create(stringReader, settings);

            var sawRoot = false;
            var indicatorDepth = 0;

            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element && !sawRoot)
                {
                    sawRoot = true;
                    // A well-formed but non-OpenIOC document must not read as an empty (clean)
                    // feed — that is indistinguishable from a feed with nothing in it.
                    if (!reader.LocalName.Equals("ioc", StringComparison.OrdinalIgnoreCase)
                        && !reader.LocalName.Equals("OpenIOC", StringComparison.OrdinalIgnoreCase))
                    {
                        return FeedReadResult.Fail(
                            $"root element '{reader.LocalName}' is not an OpenIOC document (expected 'ioc' or 'OpenIOC')");
                    }
                    continue;
                }

                if (reader.NodeType == XmlNodeType.Element
                    && reader.LocalName == "Indicator"
                    && !reader.IsEmptyElement)
                {
                    indicatorDepth++;
                    if (indicatorDepth > budget.MaxNestingDepth)
                    {
                        return FeedReadResult.Incomplete(
                            $"Indicator nesting exceeds budget depth {budget.MaxNestingDepth}",
                            candidates, rejections);
                    }
                    continue;
                }
                if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName == "Indicator")
                {
                    indicatorDepth--;
                    continue;
                }

                if (reader.NodeType == XmlNodeType.Element && reader.LocalName == "IndicatorItem")
                    ReadIndicatorItem(reader, candidates, rejections);
            }

            if (!sawRoot)
                return FeedReadResult.Fail("document contains no root element");
        }
        catch (XmlException e)
        {
            // The DTD-prohibited exception carries no position (LineNumber 0); don't invent one.
            var position = e.LineNumber > 0 ? $" at line {e.LineNumber}, column {e.LinePosition}" : string.Empty;
            return FeedReadResult.Fail($"malformed XML{position}: {e.Message}");
        }

        return FeedReadResult.Ok(candidates, rejections);
    }

    private static void ReadIndicatorItem(
        XmlReader reader, List<Candidate> candidates, List<ReaderRejection> rejections)
    {
        var condition = reader.GetAttribute("condition");
        string? search = null;
        string? contentText = null;

        if (!reader.IsEmptyElement)
        {
            using var sub = reader.ReadSubtree();
            sub.Read(); // position on the IndicatorItem element itself
            while (sub.Read())
            {
                if (sub.NodeType != XmlNodeType.Element)
                    continue;
                if (sub.LocalName == "Context")
                {
                    search = sub.GetAttribute("search");
                }
                else if (sub.LocalName == "Content")
                {
                    if (sub.IsEmptyElement)
                    {
                        contentText = string.Empty;
                        continue;
                    }
                    // Collect text manually so reader positioning stays predictable; with DTDs
                    // prohibited only built-in entities can appear and those arrive as text.
                    var sb = new StringBuilder();
                    while (sub.Read())
                    {
                        if (sub.NodeType is XmlNodeType.Text or XmlNodeType.CDATA
                            or XmlNodeType.SignificantWhitespace or XmlNodeType.Whitespace)
                        {
                            sb.Append(sub.Value);
                        }
                        else if (sub.NodeType == XmlNodeType.EndElement)
                        {
                            break;
                        }
                    }
                    contentText = sb.ToString();
                }
            }
        }

        var display = contentText is { Length: > 0 } ? contentText
            : search is { Length: > 0 } ? search
            : "(IndicatorItem without content)";

        if (string.IsNullOrEmpty(condition))
        {
            rejections.Add(new ReaderRejection(display, "IndicatorItem has no condition attribute"));
            return;
        }
        if (!condition.Equals("is", StringComparison.OrdinalIgnoreCase))
        {
            rejections.Add(new ReaderRejection(display,
                $"unsupported condition '{condition}' (only 'is' equality is supported)"));
            return;
        }
        if (string.IsNullOrEmpty(search))
        {
            rejections.Add(new ReaderRejection(display, "IndicatorItem has no Context search attribute"));
            return;
        }
        if (string.IsNullOrEmpty(contentText))
        {
            rejections.Add(new ReaderRejection(display, "IndicatorItem has no Content value"));
            return;
        }
        if (!SearchMap.TryGetValue(search, out var type))
        {
            rejections.Add(new ReaderRejection(contentText, $"unmapped OpenIOC context search '{search}'"));
            return;
        }

        candidates.Add(new Candidate(
            type, contentText, Label: search, Confidence: null, Severity: null, Expiry: null));
    }
}
