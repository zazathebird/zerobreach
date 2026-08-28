namespace Scythe.Intel;

/// <summary>The four feed formats the normaliser understands.</summary>
public enum FeedFormat
{
    /// <summary>STIX 2.x bundle JSON (objects with <c>type == "indicator"</c>).</summary>
    Stix2Json,

    /// <summary>MISP JSON event export (<c>Event.Attribute[]</c> plus <c>Event.Object[].Attribute[]</c>).</summary>
    MispJson,

    /// <summary>OpenIOC XML (<c>Indicator</c>/<c>IndicatorItem</c> trees).</summary>
    OpenIocXml,

    /// <summary>Plain text, one indicator per line; <c>#</c> and <c>;</c> start comment lines.</summary>
    PlainText,
}

/// <summary>One input feed: an identity plus its raw content. Content is text in all four
/// formats; the caller decodes bytes to a string before handing it over.</summary>
public sealed record FeedSource(string Id, string Name, FeedFormat Format, string Content);
