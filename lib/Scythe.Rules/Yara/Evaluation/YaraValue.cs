namespace Scythe.Rules.Yara.Evaluation;

/// <summary>Tri-state outcome of one rule against one buffer.</summary>
public enum RuleTriState
{
    False,
    True,

    /// <summary>The condition could not be fully decided — a referenced string's matching
    /// was budgeted out, a loop hit its iteration cap, or an operand was itself
    /// incomplete. Never collapsed into False: an incomplete rule on a clean-looking file
    /// is exactly the case the host must report honestly (BLUEPRINT §2).</summary>
    Incomplete,
}

internal enum ValueKind : byte
{
    Boolean,
    Integer,
    Double,
    Bytes,

    /// <summary>YARA's `undefined`: an out-of-range read, a missing index, an overflow.
    /// Propagates through arithmetic and comparison; false in boolean context. This is a
    /// *semantic* absence, distinct from <see cref="Incomplete"/>.</summary>
    Undefined,

    /// <summary>A budget was exhausted somewhere beneath this value. Propagates through
    /// everything except an operator that already decided the outcome without it
    /// (false and X, true or X).</summary>
    Incomplete,
}

/// <summary>Value produced by evaluating a condition subexpression.</summary>
internal readonly struct YaraValue
{
    public ValueKind Kind { get; }
    private readonly long _integer;
    private readonly double _double;
    private readonly byte[]? _bytes;
    public string? IncompleteReason { get; }

    private YaraValue(ValueKind kind, long integer = 0, double dbl = 0, byte[]? bytes = null, string? reason = null)
    {
        Kind = kind;
        _integer = integer;
        _double = dbl;
        _bytes = bytes;
        IncompleteReason = reason;
    }

    public static readonly YaraValue True = new(ValueKind.Boolean, 1);
    public static readonly YaraValue False = new(ValueKind.Boolean, 0);
    public static readonly YaraValue Undefined = new(ValueKind.Undefined);

    public static YaraValue Bool(bool b) => b ? True : False;
    public static YaraValue Int(long v) => new(ValueKind.Integer, v);
    public static YaraValue Dbl(double v) => new(ValueKind.Double, dbl: v);
    public static YaraValue Bytes(byte[] b) => new(ValueKind.Bytes, bytes: b);
    public static YaraValue Incomplete(string reason) => new(ValueKind.Incomplete, reason: reason);
    public static YaraValue Of(RuleTriState s, string reason = "referenced rule incomplete") => s switch
    {
        RuleTriState.True => True,
        RuleTriState.False => False,
        _ => Incomplete(reason),
    };

    public bool IsIncomplete => Kind == ValueKind.Incomplete;
    public bool IsUndefined => Kind == ValueKind.Undefined;

    public long AsInteger => _integer;
    public double AsDouble => Kind == ValueKind.Integer ? _integer : _double;
    public byte[] AsBytes => _bytes!;
    public bool AsBoolean => _integer != 0;

    /// <summary>Boolean coercion, reference semantics: numbers are true when non-zero,
    /// undefined is false, byte strings have no boolean meaning (undefined → false).</summary>
    public RuleTriState ToTriState() => Kind switch
    {
        ValueKind.Boolean => _integer != 0 ? RuleTriState.True : RuleTriState.False,
        ValueKind.Integer => _integer != 0 ? RuleTriState.True : RuleTriState.False,
        ValueKind.Double => _double != 0 ? RuleTriState.True : RuleTriState.False,
        ValueKind.Incomplete => RuleTriState.Incomplete,
        _ => RuleTriState.False,
    };
}
