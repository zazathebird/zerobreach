using System.Globalization;

namespace Scythe.Rules.Sigma.Yaml;

/// <summary>1-based line/column position inside a YAML source, for diagnostics.</summary>
internal readonly record struct YamlPosition(int Line, int Column)
{
    public override string ToString() => $"line {Line}, column {Column}";
}

/// <summary>
/// Thrown by the YAML reader on malformed input. Never escapes the public API:
/// <c>SigmaCompiler</c> catches it and converts it to a Failed result with position.
/// </summary>
internal sealed class YamlFormatException(string message, YamlPosition position)
    : Exception($"{message} at {position}")
{
    public YamlPosition Position { get; } = position;
    public string RawMessage { get; } = message;
}

internal abstract class YamlNode
{
    public required YamlPosition Position { get; init; }
}

/// <summary>
/// A scalar. <see cref="Value"/> is <c>string</c>, <c>long</c>, <c>double</c>, <c>bool</c>
/// or <c>null</c>. Quoted scalars are always strings — <c>'null'</c> is the four-character
/// word, only plain <c>null</c>/<c>~</c>/empty is the null value. That distinction is
/// load-bearing for Sigma's null matching.
/// </summary>
internal sealed class YamlScalar : YamlNode
{
    public object? Value { get; init; }
    public bool WasQuoted { get; init; }

    /// <summary>Invariant string form, for value comparison. Null stays null.</summary>
    public string? AsString => Value switch
    {
        null => null,
        string s => s,
        // YAML booleans stringify lower-case so `true` in a rule compares equal to a
        // boolean true in an event record once both sides are stringified.
        bool b => b ? "true" : "false",
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => Value.ToString(),
    };
}

internal sealed class YamlSequence : YamlNode
{
    public List<YamlNode> Items { get; } = [];
}

internal sealed record YamlMapEntry(string Key, YamlPosition KeyPosition, YamlNode Value);

/// <summary>A mapping. Entry order is preserved (determinism); duplicate keys are a parse
/// error rather than last-wins, because a duplicated selection silently replacing another
/// is exactly the kind of quiet rule corruption this layer must refuse.</summary>
internal sealed class YamlMapping : YamlNode
{
    public List<YamlMapEntry> Entries { get; } = [];

    public YamlNode? Find(string key)
    {
        foreach (var e in Entries)
        {
            if (string.Equals(e.Key, key, StringComparison.OrdinalIgnoreCase))
            {
                return e.Value;
            }
        }
        return null;
    }
}
