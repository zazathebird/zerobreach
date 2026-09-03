namespace Scythe.Identity;

/// <summary>
/// The three result states shared by every reader in the package (reference/00_shared.md §2).
/// </summary>
public enum IdentityResultState
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
/// <see cref="IdentityResultState.Incomplete"/> may carry a partial <see cref="Value"/> — a
/// descriptor holding an unknown entry type is returned that way, with the entry kept raw and
/// the walk continued. A caller must still treat it as an unfinished answer; it is not
/// <see cref="IdentityResultState.Ok"/> with fewer results.
/// </remarks>
public sealed class IdentityResult<T> where T : class
{
    private IdentityResult(IdentityResultState state, T? value, string? reason, long? position)
    {
        State = state;
        Value = value;
        Reason = reason;
        Position = position;
    }

    public IdentityResultState State { get; }

    /// <summary>Non-null for <see cref="IdentityResultState.Ok"/>; may be non-null for Incomplete.</summary>
    public T? Value { get; }

    /// <summary>Why the operation did not complete. Non-null unless <see cref="State"/> is Ok.</summary>
    public string? Reason { get; }

    /// <summary>
    /// Byte offset (or character index for the string forms) the failure is anchored to,
    /// relative to the start of the buffer the caller handed in.
    /// </summary>
    public long? Position { get; }

    public bool IsOk => State == IdentityResultState.Ok;

    public static IdentityResult<T> Ok(T value) =>
        new(IdentityResultState.Ok, value, null, null);

    public static IdentityResult<T> Incomplete(T? partial, string reason) =>
        new(IdentityResultState.Incomplete, partial, reason, null);

    public static IdentityResult<T> Failed(string message, long? position = null) =>
        new(IdentityResultState.Failed, null, message, position);
}
