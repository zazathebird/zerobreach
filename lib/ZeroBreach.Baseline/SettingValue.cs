namespace ZeroBreach.Baseline;

/// <summary>The declared (and observed) type of a configuration setting value.</summary>
public enum SettingValueKind
{
    Integer,
    Boolean,
    String,
}

/// <summary>
/// A typed configuration value: integer, boolean or string. A small discriminated type is used
/// instead of <c>object</c> so that a type mismatch between an observation and a check's declared
/// type is a first-class, detectable state rather than a runtime cast surprise.
/// </summary>
public abstract record SettingValue
{
    private protected SettingValue() { }

    public abstract SettingValueKind Kind { get; }

    /// <summary>Rendering used in result reasons, read by a technician.</summary>
    public abstract string ToDisplay();

    public static SettingValue OfInteger(long value) => new IntegerValue(value);
    public static SettingValue OfBoolean(bool value) => new BooleanValue(value);
    public static SettingValue OfString(string value) => new StringValue(value);
}

public sealed record IntegerValue(long Value) : SettingValue
{
    public override SettingValueKind Kind => SettingValueKind.Integer;
    public override string ToDisplay() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
}

public sealed record BooleanValue(bool Value) : SettingValue
{
    public override SettingValueKind Kind => SettingValueKind.Boolean;
    public override string ToDisplay() => Value ? "true" : "false";
}

public sealed record StringValue(string Value) : SettingValue
{
    public override SettingValueKind Kind => SettingValueKind.String;
    public override string ToDisplay() => "\"" + Value + "\"";
}
