namespace Scythe.Scoring;

/// <summary>
/// What became of one check in the run (reference/07_records.md §7). Three distinct outcomes,
/// counted separately and never folded into one another.
/// </summary>
public enum CheckStatus
{
    /// <summary>The check ran to the end. Its findings, or the absence of them, are information.</summary>
    Completed = 0,

    /// <summary>
    /// The check ran and could not finish. It has produced <b>no information</b>: no finding
    /// from it means nothing was examined, not that nothing was there. Rule 2 of §7.
    /// </summary>
    Inconclusive = 1,

    /// <summary>The check was not run at all — typically because the run's mode did not include it.</summary>
    Skipped = 2,
}
