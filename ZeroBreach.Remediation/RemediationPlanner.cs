using ZeroBreach.Core.Model;

namespace ZeroBreach.Remediation;

/// <summary>
/// Selection rules for remediation (spec §6.1 / §6.5). This is the ONLY place selection
/// logic lives, so the individual auto-select gate and every bulk action share one gate by
/// construction.
/// </summary>
public static class RemediationPlanner
{
    /// <summary>Spec §6.1: auto-select = CRITICAL/HIGH severity AND an executable
    /// destructive fix action — nothing else. POSSIBLE/INFO are never pre-queued.
    /// run_command findings are never queued (display-only, §6.8).</summary>
    public static bool QualifiesForAutoSelect(Finding f) =>
        f.Severity >= Severity.High && f.FixAction.IsExecutable();

    /// <summary>Manual selection of a single finding by the operator: allowed for any
    /// severity (spec §6.1 "can be acted on manually"), but only executable actions —
    /// run_command can never enter a batch.</summary>
    public static bool IsManuallySelectable(Finding f) => f.FixAction.IsExecutable();

    public static IReadOnlyList<Finding> AutoSelect(IEnumerable<Finding> findings) =>
        findings.Where(QualifiesForAutoSelect).ToList();

    /// <summary>Spec §6.5: every bulk "select all" filters on the SAME severity gate as
    /// auto-select. There is deliberately no bulk method that selects POSSIBLE/INFO —
    /// those must be toggled one at a time, each an individual operator decision.</summary>
    public static IReadOnlyList<Finding> BulkSelect(IEnumerable<Finding> findings) =>
        findings.Where(QualifiesForAutoSelect).ToList();
}
