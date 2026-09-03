namespace Scythe.Time;

/// <summary>
/// The three result states shared by every reader in the package (reference/00_shared.md §2).
/// </summary>
public enum TimeResultState
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
/// The result of one decode. Never throws for an expected outcome and never returns a bare null
/// to mean "didn't work".
/// </summary>
/// <remarks>
/// <see cref="TimeResultState.Incomplete"/> may carry a partial <see cref="Value"/> — the 32-bit
/// second counter of unstated signedness reports both readings that way. A caller must still
/// treat it as an unfinished answer; it is not <see cref="TimeResultState.Ok"/> with fewer
/// results.
/// </remarks>
public sealed class TimeResult<T> where T : class
{
    private TimeResult(TimeResultState state, T? value, string? reason, long? position)
    {
        State = state;
        Value = value;
        Reason = reason;
        Position = position;
    }

    public TimeResultState State { get; }

    /// <summary>Non-null for <see cref="TimeResultState.Ok"/>; may be non-null for Incomplete.</summary>
    public T? Value { get; }

    /// <summary>Why the operation did not complete. Non-null unless <see cref="State"/> is Ok.</summary>
    public string? Reason { get; }

    /// <summary>
    /// Byte or character offset the failure is anchored to, where the encoding has one. Null for
    /// the fixed-width scalar encodings, whose whole input is the field.
    /// </summary>
    public long? Position { get; }

    public bool IsOk => State == TimeResultState.Ok;

    public static TimeResult<T> Ok(T value) =>
        new(TimeResultState.Ok, value, null, null);

    public static TimeResult<T> Incomplete(T? partial, string reason) =>
        new(TimeResultState.Incomplete, partial, reason, null);

    public static TimeResult<T> Failed(string message, long? position = null) =>
        new(TimeResultState.Failed, null, message, position);
}
