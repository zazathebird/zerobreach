namespace Scythe.Baseline;

/// <summary>
/// What an absent (unset) setting means for a specific check. Absent is not zero, and absent is
/// not automatically non-compliant: an unset setting means the platform default applies, and
/// whether that default is acceptable differs per setting. Every check must declare this
/// explicitly; there is deliberately no global fallback.
/// </summary>
public abstract record AbsenceRule
{
    private protected AbsenceRule() { }

    /// <summary>Absence is acceptable: the platform default for this setting is compliant.</summary>
    public static AbsenceRule Compliant { get; } = new AbsenceIsCompliant();

    /// <summary>Absence is a finding: this setting must be explicitly configured.</summary>
    public static AbsenceRule NonCompliant { get; } = new AbsenceIsNonCompliant();

    /// <summary>Absence means the platform default is <paramref name="defaultValue"/>;
    /// evaluate the check's comparison against that value.</summary>
    public static AbsenceRule MeansDefault(SettingValue defaultValue) => new AbsenceMeansDefault(defaultValue);
}

public sealed record AbsenceIsCompliant : AbsenceRule;

public sealed record AbsenceIsNonCompliant : AbsenceRule;

public sealed record AbsenceMeansDefault(SettingValue DefaultValue) : AbsenceRule;
