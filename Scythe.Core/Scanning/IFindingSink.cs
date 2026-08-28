using Scythe.Core.Model;

namespace Scythe.Core.Scanning;

/// <summary>Thread-safe receiver for findings and check statuses.</summary>
public interface IFindingSink
{
    void Report(Finding finding);
    void ReportCheck(CheckStatus status);
}

public static class FindingSinkExtensions
{
    public static void Completed(this IFindingSink sink, int phase, string check, string? detail = null) =>
        sink.ReportCheck(new CheckStatus(phase, check, CheckOutcome.Completed, detail));

    public static void Inconclusive(this IFindingSink sink, int phase, string check, string reason) =>
        sink.ReportCheck(new CheckStatus(phase, check, CheckOutcome.Inconclusive, reason));

    public static void Skipped(this IFindingSink sink, int phase, string check, string reason) =>
        sink.ReportCheck(new CheckStatus(phase, check, CheckOutcome.Skipped, reason));

    /// <summary>Standard end-of-walk report: Completed if the budget survived, otherwise
    /// Inconclusive with the budget's reason (spec §4/§6.7 — a cut-short walk is never clean).</summary>
    public static void CompleteOrInconclusive(this IFindingSink sink, int phase, string check,
        EnumerationBudget budget, string? scope = null)
    {
        if (budget.Exhausted)
            sink.Inconclusive(phase, check, scope is null
                ? $"walk cut short: {budget.ExhaustedReason}"
                : $"walk of {scope} cut short: {budget.ExhaustedReason}");
        else
            sink.Completed(phase, check, scope);
    }
}
