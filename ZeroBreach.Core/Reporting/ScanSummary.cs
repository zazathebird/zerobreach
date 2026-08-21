using ZeroBreach.Core.Model;

namespace ZeroBreach.Core.Reporting;

/// <summary>End-of-run summary (spec §7) with a §6.7-honest verdict: the verdict never says
/// plain "clean" while any check was inconclusive or skipped.</summary>
public sealed class ScanSummary
{
    public required int Critical { get; init; }
    public required int High { get; init; }
    public required int Possible { get; init; }
    public required int Info { get; init; }
    public required int ChecksCompleted { get; init; }
    public required int ChecksInconclusive { get; init; }
    public required int ChecksSkipped { get; init; }
    public required TimeSpan Elapsed { get; init; }
    public required string Verdict { get; init; }

    public int Total => Critical + High + Possible + Info;

    public static ScanSummary Build(IReadOnlyList<Finding> findings, IReadOnlyList<CheckStatus> checks, TimeSpan elapsed)
    {
        int crit = findings.Count(f => f.Severity == Severity.Critical);
        int high = findings.Count(f => f.Severity == Severity.High);
        int poss = findings.Count(f => f.Severity == Severity.Possible);
        int info = findings.Count(f => f.Severity == Severity.Info);
        int inconclusive = checks.Count(c => c.Outcome == CheckOutcome.Inconclusive);
        int skipped = checks.Count(c => c.Outcome == CheckOutcome.Skipped);

        string verdict;
        if (crit > 0) verdict = "COMPROMISE INDICATORS PRESENT — treat this machine as compromised until proven otherwise";
        else if (high > 0) verdict = "HIGH-CONFIDENCE SUSPICIOUS ARTIFACTS FOUND — investigate before returning to service";
        else if (poss > 0) verdict = "POSSIBLE INDICATORS FOUND — operator review required";
        else if (inconclusive > 0 || skipped > 0)
            verdict = $"NO SUSPICIOUS FINDINGS{(info > 0 ? $" ({info} informational)" : "")}, BUT NOT A CLEAN BILL — " +
                      $"{inconclusive} check(s) inconclusive, {skipped} skipped/unchecked; those areas were NOT cleared";
        else if (info > 0)
            // "NO FINDINGS" above a findings table with rows in it would be a lie.
            verdict = $"{info} INFORMATIONAL FINDING(S) — nothing suspicious; review the info items; all checks completed";
        else verdict = "NO FINDINGS — all checks completed";

        return new ScanSummary
        {
            Critical = crit, High = high, Possible = poss, Info = info,
            ChecksCompleted = checks.Count(c => c.Outcome == CheckOutcome.Completed),
            ChecksInconclusive = inconclusive,
            ChecksSkipped = skipped,
            Elapsed = elapsed,
            Verdict = verdict,
        };
    }
}
