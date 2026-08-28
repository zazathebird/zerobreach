namespace Scythe.Intel;

/// <summary>
/// What a reader knows about a value's type before validation. The first twelve entries map
/// 1:1 onto <see cref="IndicatorType"/>; the rest are hints resolved by the pipeline after
/// defang restoration (an IP family cannot be inferred from <c>1.2.3[.]4</c> until the
/// brackets are gone).
/// </summary>
internal enum CandidateType
{
    Sha256,
    Sha1,
    Md5,
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Filename,
    FilePath,
    RegistryKey,
    Mutex,
    EmailAddress,

    /// <summary>An IP whose family (v4/v6) the feed did not state (MISP <c>ip-src</c>,
    /// OpenIOC <c>PortItem/remoteIP</c>).</summary>
    IpAny,

    /// <summary>MISP <c>filename</c>: becomes <see cref="IndicatorType.FilePath"/> when the
    /// value contains a path separator, else <see cref="IndicatorType.Filename"/>.</summary>
    FilenameOrPath,

    /// <summary>Plain text line: type inferred entirely by validation.</summary>
    Infer,
}

/// <summary>One candidate indicator produced by a reader, before defang restoration and
/// validation.</summary>
internal sealed record Candidate(
    CandidateType Type,
    string RawValue,
    string? Label,
    int? Confidence,
    string? Severity,
    DateTimeOffset? Expiry);

/// <summary>A value a reader itself rejected (unsupported pattern, unmapped attribute type,
/// not-for-detection flag). Counted in the rejection report like a validation failure.</summary>
internal sealed record ReaderRejection(string RawValue, string Reason);

/// <summary>What a reader hands the pipeline for one feed.</summary>
internal sealed class FeedReadResult
{
    public OperationState State { get; }
    public string? Message { get; }
    public List<Candidate> Candidates { get; }
    public List<ReaderRejection> Rejections { get; }

    private FeedReadResult(OperationState state, string? message, List<Candidate> candidates, List<ReaderRejection> rejections)
    {
        State = state;
        Message = message;
        Candidates = candidates;
        Rejections = rejections;
    }

    public static FeedReadResult Ok(List<Candidate> candidates, List<ReaderRejection> rejections)
        => new(OperationState.Ok, null, candidates, rejections);

    /// <summary>Structural budget hit (e.g. nesting depth): keep what was read, mark incomplete.</summary>
    public static FeedReadResult Incomplete(string message, List<Candidate> candidates, List<ReaderRejection> rejections)
        => new(OperationState.Incomplete, message, candidates, rejections);

    /// <summary>Malformed document: zero partial results for this feed, by design.</summary>
    public static FeedReadResult Fail(string message)
        => new(OperationState.Failed, message, new List<Candidate>(), new List<ReaderRejection>());
}
