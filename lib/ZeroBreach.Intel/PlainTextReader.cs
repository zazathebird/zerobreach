namespace ZeroBreach.Intel;

/// <summary>
/// Plain text feeds: one indicator per line, type inferred by the pipeline after defang
/// restoration. Lines whose first non-blank character is <c>#</c> or <c>;</c> are comments;
/// blank lines are skipped. Neither is a rejection — a comment is not a failed indicator.
///
/// A plain text document has no structure to be malformed, so this reader never returns
/// <see cref="OperationState.Failed"/>; every non-comment line becomes a candidate and any
/// problem with it is reported by validation, per line, with a reason.
/// </summary>
internal static class PlainTextReader
{
    public static FeedReadResult Read(string content)
    {
        var candidates = new List<Candidate>();
        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r').Trim();
            if (line.Length == 0 || line[0] is '#' or ';')
                continue;
            candidates.Add(new Candidate(
                CandidateType.Infer, line, Label: null, Confidence: null, Severity: null, Expiry: null));
        }
        return FeedReadResult.Ok(candidates, new List<ReaderRejection>());
    }
}
