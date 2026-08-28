namespace Scythe.Rules.Linting;

/// <summary>
/// Outcome of linting one rule file.
/// <list type="bullet">
/// <item><see cref="OperationState.Ok"/> — every check ran; <see cref="Findings"/> is the
/// complete, deterministic list (sorted by position, then code, then message).</item>
/// <item><see cref="OperationState.Incomplete"/> — the run hit its deadline. Findings
/// collected so far are returned, and <see cref="Reason"/> says what did not run. CI must
/// treat this as a failure: an unfinished lint reported as clean is the exact failure mode
/// this linter exists to prevent.</item>
/// <item><see cref="OperationState.Failed"/> — the file is not parseable JSON (or not
/// readable at all). No findings; <see cref="Reason"/> carries the message with line and
/// column. A malformed file never lints to "no findings".</item>
/// </list>
/// </summary>
public sealed record LintResult(
    OperationState State,
    string? Reason,
    IReadOnlyList<LintFinding> Findings)
{
    /// <summary>True when any finding is at or above <paramref name="failAt"/>. The CLI
    /// maps this to its exit code (default threshold: <see cref="LintSeverity.Error"/>).</summary>
    public bool HasFindingAtOrAbove(LintSeverity failAt)
    {
        foreach (var finding in Findings)
        {
            if (finding.Severity >= failAt)
            {
                return true;
            }
        }
        return false;
    }
}
