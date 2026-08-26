namespace ZeroBreach.Baseline;

/// <summary>
/// The comparison a check applies to the observed (or defaulted) value. Equality alone cannot
/// express "at least this strict": several real settings are ordinal, where a machine set to 6
/// must pass a check written against 5.
/// </summary>
public abstract record CheckComparison
{
    private protected CheckComparison() { }

    /// <summary>Short human-readable description used in result reasons.</summary>
    public abstract string Describe();

    public static CheckComparison EqualTo(SettingValue expected) => new EqualsComparison(expected);
    public static CheckComparison NotEqualTo(SettingValue expected) => new NotEqualsComparison(expected);
    public static CheckComparison AtLeast(long floor) => new AtLeastComparison(floor);
    public static CheckComparison OneOf(params SettingValue[] values) => new OneOfComparison(values);
    public static CheckComparison NoneOf(params SettingValue[] values) => new NoneOfComparison(values);
}

public sealed record EqualsComparison(SettingValue Expected) : CheckComparison
{
    public override string Describe() => "equals " + Expected.ToDisplay();
}

public sealed record NotEqualsComparison(SettingValue Expected) : CheckComparison
{
    public override string Describe() => "not-equals " + Expected.ToDisplay();
}

/// <summary>Numeric floor: the observed value passes when it is greater than or equal to
/// <paramref name="Floor"/>. Higher is stricter; a stricter machine must never fail.</summary>
public sealed record AtLeastComparison(long Floor) : CheckComparison
{
    public override string Describe() => "at-least " + Floor;
}

public sealed record OneOfComparison(IReadOnlyList<SettingValue> Values) : CheckComparison
{
    public override string Describe() => "one-of [" + string.Join(", ", Values.Select(v => v.ToDisplay())) + "]";
}

public sealed record NoneOfComparison(IReadOnlyList<SettingValue> Values) : CheckComparison
{
    public override string Describe() => "none-of [" + string.Join(", ", Values.Select(v => v.ToDisplay())) + "]";
}
