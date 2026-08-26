namespace ZeroBreach.Formats.Pe;

/// <summary>
/// Result of <see cref="PeParser.Parse"/>.
///
/// State rules (BLUEPRINT §2/§6):
/// <list type="bullet">
/// <item><c>Failed</c> — the buffer is not a usable PE at all: no MZ, no PE signature, or the
/// DOS/NT headers themselves are truncated or lie in a way that leaves nothing to recover.
/// <see cref="Message"/> and <see cref="ErrorOffset"/> say where. <see cref="Image"/> is null.</item>
/// <item><c>Incomplete</c> — the headers parsed but something later was truncated, out of
/// bounds, cyclic, or over a cap/budget. <see cref="Image"/> and <see cref="Metrics"/> carry
/// everything recovered; <see cref="IncompleteReasons"/> lists every reason, and
/// <see cref="Message"/> joins them. This is never collapsed into <c>Ok</c>.</item>
/// <item><c>Ok</c> — everything declared by the file was read and validated.</item>
/// </list>
/// </summary>
public sealed record PeParseResult(
    OperationState State,
    string? Message,
    long? ErrorOffset,
    IReadOnlyList<string> IncompleteReasons,
    PeImage? Image,
    PeMetrics? Metrics)
{
    internal static PeParseResult Fail(string message, long offset) =>
        new(OperationState.Failed, message, offset, Array.Empty<string>(), null, null);

    internal static PeParseResult IncompleteWithoutImage(string reason) =>
        new(OperationState.Incomplete, reason, null, new[] { reason }, null, null);

    internal static PeParseResult FromParse(IReadOnlyList<string> reasons, PeImage image, PeMetrics metrics) =>
        reasons.Count == 0
            ? new(OperationState.Ok, null, null, Array.Empty<string>(), image, metrics)
            : new(OperationState.Incomplete, string.Join("; ", reasons), null, reasons, image, metrics);
}
