namespace Scythe.Paths;

/// <summary>
/// The result of normalising one Windows path string. Carries the canonical comparison form,
/// the original for display, the syntactic kind, the flags raised, and the full audit trail of
/// transformations applied. On <see cref="OperationState.Failed"/> no partial result is
/// exposed: every derived property is null/empty except <see cref="Original"/>,
/// <see cref="FailureReason"/>, and whatever transformations completed before the failure.
/// </summary>
public sealed class NormalizedPath
{
    internal NormalizedPath(
        OperationState state,
        string original,
        string? failureReason,
        PathKind kind,
        PathRootSpace rootSpace,
        PathFlags flags,
        string? normalizedDisplay,
        string? canonical,
        string? root,
        IReadOnlyList<string> segments,
        string? streamName,
        string? streamType,
        string? canonicalStream,
        IReadOnlyList<PathTransformation> transformations)
    {
        State = state;
        Original = original;
        FailureReason = failureReason;
        Kind = kind;
        RootSpace = rootSpace;
        Flags = flags;
        NormalizedDisplay = normalizedDisplay;
        Canonical = canonical;
        Root = root;
        Segments = segments;
        StreamName = streamName;
        StreamType = streamType;
        CanonicalStream = canonicalStream;
        Transformations = transformations;
    }

    /// <summary>Ok, or Failed with <see cref="FailureReason"/>. Normalisation itself never returns Incomplete; only comparisons do.</summary>
    public OperationState State { get; }

    /// <summary>The input exactly as supplied. Always preserved for display and logging.</summary>
    public string Original { get; }

    /// <summary>Why normalisation failed; null when <see cref="State"/> is Ok.</summary>
    public string? FailureReason { get; }

    /// <summary>The syntactic form the input arrived in (what the caller wrote).</summary>
    public PathKind Kind { get; }

    /// <summary>The namespace the path resolves into (what comparisons use).</summary>
    public PathRootSpace RootSpace { get; }

    /// <summary>Signals raised during normalisation. Evidence for the guard, never errors.</summary>
    public PathFlags Flags { get; }

    /// <summary>
    /// The normalised path with original casing preserved — the "Y" in "normalised from X to Y"
    /// log lines. Includes the stream suffix if one was present. Null when Failed.
    /// </summary>
    public string? NormalizedDisplay { get; }

    /// <summary>
    /// The invariant-lower-cased comparison form of the path (stream excluded — see
    /// <see cref="CanonicalStream"/>). Two strings naming the same location in different
    /// syntactic forms produce the same canonical. Null when Failed.
    /// </summary>
    public string? Canonical { get; }

    /// <summary>Canonical + canonical stream in one string, for logging.</summary>
    public string? CanonicalFull =>
        Canonical is null ? null : CanonicalStream is null ? Canonical : $"{Canonical}:{CanonicalStream}";

    /// <summary>
    /// Canonical root: <c>c:\</c>, <c>\\server\share</c>, <c>\\.\device</c>, <c>\\.\globalroot</c>,
    /// <c>\</c> (current drive), <c>c:</c> (drive-relative), or <c>""</c> (relative). Null when Failed.
    /// </summary>
    public string? Root { get; }

    /// <summary>Canonical (lower-cased) path segments below the root. Empty when Failed or at a bare root.</summary>
    public IReadOnlyList<string> Segments { get; }

    /// <summary>Alternate data stream name as written (may be empty for <c>::$DATA</c>-style suffixes); null when no stream.</summary>
    public string? StreamName { get; }

    /// <summary>Alternate data stream type as written (<c>$DATA</c> etc.); null when not specified or no stream.</summary>
    public string? StreamType { get; }

    /// <summary>
    /// Canonical stream identity, <c>name:$type</c> lower-cased with the type defaulted to
    /// <c>$data</c> — so <c>file:s</c> and <c>file:s:$DATA</c> agree. Null when there is no
    /// stream <em>or</em> the suffix named the default data stream (<c>::$DATA</c>), which is
    /// the file itself and therefore carries no distinct identity.
    /// </summary>
    public string? CanonicalStream { get; }

    /// <summary>Every rewrite applied, in order. Empty means the input was already canonical in form.</summary>
    public IReadOnlyList<PathTransformation> Transformations { get; }

    internal static NormalizedPath Failure(string original, string reason, IReadOnlyList<PathTransformation> transformations) =>
        new(OperationState.Failed, original, reason, PathKind.Relative, PathRootSpace.None, PathFlags.None,
            normalizedDisplay: null, canonical: null, root: null, segments: [],
            streamName: null, streamType: null, canonicalStream: null, transformations);
}
