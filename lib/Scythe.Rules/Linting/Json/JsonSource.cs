namespace Scythe.Rules.Linting.Json;

/// <summary>
/// A parsed JSON value that remembers where it came from. The stock readers
/// (System.Text.Json) only surface line/column on failure; every lint finding needs a
/// position, so the linter carries its own small parser and keeps one per token.
/// </summary>
public abstract class JsonSourceValue
{
    protected JsonSourceValue(LintLocation location) => Location = location;

    /// <summary>Position of the value's first character in the source file.</summary>
    public LintLocation Location { get; }
}

public sealed class JsonSourceString : JsonSourceValue
{
    public JsonSourceString(string value, LintLocation location) : base(location) => Value = value;
    public string Value { get; }
}

public sealed class JsonSourceNumber : JsonSourceValue
{
    public JsonSourceNumber(double value, string raw, LintLocation location) : base(location)
    {
        Value = value;
        Raw = raw;
    }

    public double Value { get; }

    /// <summary>Original spelling, for error messages.</summary>
    public string Raw { get; }
}

public sealed class JsonSourceBoolean : JsonSourceValue
{
    public JsonSourceBoolean(bool value, LintLocation location) : base(location) => Value = value;
    public bool Value { get; }
}

public sealed class JsonSourceNull : JsonSourceValue
{
    public JsonSourceNull(LintLocation location) : base(location) { }
}

public sealed class JsonSourceArray : JsonSourceValue
{
    public JsonSourceArray(IReadOnlyList<JsonSourceValue> items, LintLocation location)
        : base(location) => Items = items;

    public IReadOnlyList<JsonSourceValue> Items { get; }
}

/// <summary>One <c>"name": value</c> pair. The name's own position is kept separately so
/// findings about a key (duplicate, orphaned set) point at the key, not the value.</summary>
public sealed record JsonSourceProperty(string Name, LintLocation NameLocation, JsonSourceValue Value);

public sealed class JsonSourceObject : JsonSourceValue
{
    public JsonSourceObject(IReadOnlyList<JsonSourceProperty> properties, LintLocation location)
        : base(location) => Properties = properties;

    /// <summary>Document order, duplicates preserved — duplicate detection is the
    /// linter's job, and picking a winner here would hide the defect.</summary>
    public IReadOnlyList<JsonSourceProperty> Properties { get; }
}

/// <summary>Outcome of one parse. Failed carries the message and position; it never
/// carries a partial tree — half a rule file is not a rule file.</summary>
public sealed record JsonParseResult(
    OperationState State,
    string? Message,
    LintLocation ErrorLocation,
    JsonSourceValue? Root)
{
    public static JsonParseResult Success(JsonSourceValue root) =>
        new(OperationState.Ok, null, default, root);

    public static JsonParseResult Failure(string message, LintLocation location) =>
        new(OperationState.Failed, message, location, null);
}
