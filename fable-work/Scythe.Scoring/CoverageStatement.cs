namespace Scythe.Scoring;

/// <summary>
/// What the run looked at, as opposed to what it found. A first-class value beside the score,
/// never inside it, and built to be impossible to read past.
/// </summary>
/// <remarks>
/// <para>
/// The three status totals are separate and always sum to <see cref="InventorySize"/>. There is
/// deliberately <b>no</b> single figure — no rate, no percentage, no ratio — that combines them:
/// any such member would be the shortest thing to render, would land at the top of the report,
/// and would be read as "N% fine" whatever its definition said. A reflection test in the test
/// project fails the build the moment one is added. The reasoning is reference/07.2_scoring.md.
/// </para>
/// <para>
/// <b>Skipped and Inconclusive are treated differently by the score.</b> A skipped check is one
/// the run's mode did not include — an expected gap, reported here but not held against the
/// score. An inconclusive check is one that ran and could not finish — an unexpected gap that
/// depresses the score through <see cref="ScoreContribution"/>. This is an assumption
/// (K2 open question 3) recorded here so a reader can challenge it.
/// </para>
/// </remarks>
/// <param name="InventorySize">Checks in the inventory. The denominator nothing is dropped from.</param>
/// <param name="CompletedCount">Checks that ran to the end.</param>
/// <param name="InconclusiveCount">Checks that ran and could not finish. Never folded into <see cref="CompletedCount"/>.</param>
/// <param name="SkippedCount">Checks that did not run. Never folded into either of the others.</param>
/// <param name="InconclusiveReasons">Every distinct reason the inconclusive checks gave, with the checks that gave it. These are the operative content: "needed elevation" and "artifact locked" call for different responses.</param>
/// <param name="InconclusiveWithoutReason">Inconclusive checks that gave no reason. Non-empty means the statement cannot say why part of the host went unexamined, and the rollup is reported Incomplete.</param>
/// <param name="SkippedReasons">Every distinct reason the skipped checks gave, with the checks that gave it.</param>
/// <param name="SkippedWithoutReason">Skipped checks that gave no reason.</param>
/// <param name="Statement">The counts as one sentence, for the top of the report. Contains no percentage.</param>
public sealed record CoverageStatement(
    int InventorySize,
    int CompletedCount,
    int InconclusiveCount,
    int SkippedCount,
    IReadOnlyList<CoverageReason> InconclusiveReasons,
    IReadOnlyList<string> InconclusiveWithoutReason,
    IReadOnlyList<CoverageReason> SkippedReasons,
    IReadOnlyList<string> SkippedWithoutReason,
    string Statement);

/// <summary>One distinct reason string and the checks that gave it, ordered by check id ordinally.</summary>
/// <param name="Reason">The reason text as the inventory gave it, whitespace-trimmed. Never empty.</param>
/// <param name="CheckIds">The checks that gave exactly this reason.</param>
public sealed record CoverageReason(
    string Reason,
    IReadOnlyList<string> CheckIds);
