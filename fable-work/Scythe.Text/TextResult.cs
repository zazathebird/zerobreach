namespace Scythe.Text;

/// <summary>
/// The three result states shared by every reader in the package (reference/00_shared.md §2).
/// </summary>
public enum TextResultState
{
    /// <summary>The operation completed and the answer is trustworthy.</summary>
    Ok,

    /// <summary>
    /// It ran but could not finish — budget exhausted, truncated input, unsupported variant,
    /// unrecognised version. Always carries a reason. Never an <see cref="Ok"/> with less in it.
    /// </summary>
    Incomplete,

    /// <summary>Malformed input. Carries a message, and a position where the format has one.</summary>
    Failed,
}

/// <summary>
/// The result of one detection or decode. Never throws for an expected outcome and never returns
/// a bare null to mean "didn't work".
/// </summary>
/// <remarks>
/// <see cref="TextResultState.Incomplete"/> may carry a partial <see cref="Value"/>: a strict
/// decode that refuses a byte still hands back the original bytes, and a reporting decode that
/// hits <see cref="ScanBudget.MaxMatches"/> hands back the text and runs gathered so far. A
/// caller must still treat it as an unfinished answer; it is not
/// <see cref="TextResultState.Ok"/> with fewer results.
/// </remarks>
public sealed class TextResult<T> where T : class
{
    private TextResult(TextResultState state, T? value, string? reason, long? position)
    {
        State = state;
        Value = value;
        Reason = reason;
        Position = position;
    }

    public TextResultState State { get; }

    /// <summary>Non-null for <see cref="TextResultState.Ok"/>; may be non-null for Incomplete.</summary>
    public T? Value { get; }

    /// <summary>Why the operation did not complete. Non-null unless <see cref="State"/> is Ok.</summary>
    public string? Reason { get; }

    /// <summary>Byte offset the failure is anchored to, where the operation has one.</summary>
    public long? Position { get; }

    public bool IsOk => State == TextResultState.Ok;

    public static TextResult<T> Ok(T value) =>
        new(TextResultState.Ok, value, null, null);

    public static TextResult<T> Incomplete(T? partial, string reason, long? position = null) =>
        new(TextResultState.Incomplete, partial, reason, position);

    public static TextResult<T> Failed(string message, long? position = null) =>
        new(TextResultState.Failed, null, message, position);
}
