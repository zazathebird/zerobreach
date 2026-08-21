using ZeroBreach.Core.Profiles;
using ZeroBreach.Core.Signatures;

namespace ZeroBreach.Core.Scanning;

/// <summary>Everything a scanner needs. Scanners are READ-ONLY consumers of the machine:
/// nothing in this type (or in ZeroBreach.Core at all) exposes a destructive operation —
/// remediation lives exclusively in the ZeroBreach.Remediation module (spec §8).</summary>
public sealed class ScanContext
{
    public required ScanDepth Depth { get; init; }

    /// <summary>Time-window filter (spec §2): when set, checks that iterate artifacts by
    /// creation/modification time should only flag items newer than this.</summary>
    public DateTime? SinceUtc { get; init; }

    public required SignatureDb Signatures { get; init; }

    /// <summary>Every user profile on the box (spec §4). Scanners with per-user checks MUST
    /// iterate all of these, use one budget per profile, and report profiles whose hive
    /// isn't mounted as Skipped ("not checked"), never silently.</summary>
    public required IReadOnlyList<UserProfile> Profiles { get; init; }

    /// <summary>True when the operator passed the explicit opt-in flag to load logged-off
    /// users' hives. Informational for scanners (the CLI performs the loading).</summary>
    public bool HiveLoadingEnabled { get; init; }

    public IScanLogger Log { get; init; } = NullScanLogger.Instance;

    public CancellationToken Cancel { get; init; } = CancellationToken.None;

    /// <summary>Budget scale factor by depth (DEEP walks more than QUICK). Applied in
    /// <see cref="CreateBudget"/> so scanners just state their base numbers.</summary>
    public double BudgetScale { get; init; } = 1.0;

    /// <summary>Creates a fresh enumeration budget for ONE walk. Per spec §4, call this
    /// once per profile (or per independent walk target) — never share one budget across
    /// profiles. When the returned budget reports Exhausted, the check must end
    /// Inconclusive for that walk's scope.</summary>
    public EnumerationBudget CreateBudget(int baseMaxItems, TimeSpan baseMaxTime)
    {
        var items = Math.Max(1, (int)(baseMaxItems * BudgetScale));
        var time = TimeSpan.FromTicks((long)(baseMaxTime.Ticks * BudgetScale));
        return new EnumerationBudget(items, time);
    }

    /// <summary>True when the artifact timestamp passes the --since filter (always true
    /// when no filter is set). An artifact whose timestamp CANNOT be read is never excluded:
    /// unreadable/absent times are something malware can arrange, and a time-narrowed scan
    /// silently skipping such artifacts would be an evasion primitive (spec §6.7 spirit).</summary>
    public bool WithinTimeWindow(DateTime? utc) => SinceUtc is null || utc is null || utc >= SinceUtc;
}
