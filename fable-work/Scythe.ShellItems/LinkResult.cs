namespace Scythe.ShellItems;

/// <summary>
/// The three result states shared by every reader in the package (reference/00_shared.md §2).
/// </summary>
public enum LinkResultState
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
/// The result of one read. Never throws for an expected outcome and never returns a bare null
/// to mean "didn't work".
/// </summary>
/// <remarks>
/// <see cref="LinkResultState.Incomplete"/> may carry a partial <see cref="Value"/> — a link
/// truncated mid-way carries the sections read before the truncation, and a jump list that ran
/// out of budget carries the entries gathered so far. A caller must still treat it as an
/// unfinished answer; it is not <see cref="LinkResultState.Ok"/> with fewer results.
/// </remarks>
public sealed class LinkResult<T> where T : class
{
    private LinkResult(LinkResultState state, T? value, string? reason, long? position)
    {
        State = state;
        Value = value;
        Reason = reason;
        Position = position;
    }

    public LinkResultState State { get; }

    /// <summary>Non-null for <see cref="LinkResultState.Ok"/>; may be non-null for Incomplete.</summary>
    public T? Value { get; }

    /// <summary>Why the operation did not complete. Non-null unless <see cref="State"/> is Ok.</summary>
    public string? Reason { get; }

    /// <summary>
    /// Byte offset the failure is anchored to, relative to the start of the input handed to the
    /// entry point. Null where the failure has no single position.
    /// </summary>
    public long? Position { get; }

    public bool IsOk => State == LinkResultState.Ok;

    public static LinkResult<T> Ok(T value) =>
        new(LinkResultState.Ok, value, null, null);

    public static LinkResult<T> Incomplete(T? partial, string reason) =>
        new(LinkResultState.Incomplete, partial, reason, null);

    public static LinkResult<T> Failed(string message, long? position = null) =>
        new(LinkResultState.Failed, null, message, position);
}
