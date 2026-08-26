namespace ZeroBreach.Intel;

/// <summary>
/// One validated, normalised indicator.
/// </summary>
/// <param name="Type">The indicator kind.</param>
/// <param name="Value">The normalised value: defang restored, canonical casing where the type
/// has one (hashes and domains lowercase, URLs with lowercase scheme and host).</param>
/// <param name="RawValue">The value exactly as the feed supplied it, for audit.</param>
/// <param name="SourceFeedId">Id of the feed this was first seen in (dedup preserves first-seen).</param>
/// <param name="SourceFeedName">Name of that feed.</param>
/// <param name="WasDefanged">True when defang restoration changed the raw value.</param>
/// <param name="Confidence">Confidence 0–100 if the feed supplied one (STIX <c>confidence</c>).</param>
/// <param name="Severity">Severity if the feed supplied one (MISP event threat level).</param>
/// <param name="Expiry">Expiry if the feed supplied one (STIX <c>valid_until</c>). An already
/// expired indicator is kept, with this set — the host decides what to do with it.</param>
/// <param name="Label">Free-text label/comment from the feed (STIX name+labels, MISP
/// category+comment, OpenIOC search path).</param>
public sealed record Indicator(
    IndicatorType Type,
    string Value,
    string RawValue,
    string SourceFeedId,
    string SourceFeedName,
    bool WasDefanged,
    int? Confidence,
    string? Severity,
    DateTimeOffset? Expiry,
    string? Label);
