namespace ZeroBreach.Core.Model;

/// <summary>How a check ended. Spec §6.7: a check that couldn't actually run must surface as
/// a distinct state — never folded into "nothing found".</summary>
public enum CheckOutcome
{
    /// <summary>The check ran to completion over its full intended scope.</summary>
    Completed = 0,

    /// <summary>The check started but could not cover its scope (budget exhausted,
    /// log source disabled, access denied, walk cut short, crash).</summary>
    Inconclusive = 1,

    /// <summary>The check did not run at all for this target (e.g. a logged-off user's hive
    /// was not loaded because --load-hives wasn't given). Reported, never silent.</summary>
    Skipped = 2,
}

public sealed record CheckStatus(
    int Phase,
    string Check,
    CheckOutcome Outcome,
    /// <summary>What the check covered or why it couldn't (profile, path, reason).</summary>
    string? Detail = null);
