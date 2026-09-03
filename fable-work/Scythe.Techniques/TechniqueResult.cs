namespace Scythe.Techniques;

/// <summary>
/// The three result states shared by every reader in the package (reference/00_shared.md §2).
/// </summary>
public enum TechniqueResultState
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
/// The result of one operation. Never throws for an expected outcome and never returns a bare
/// null to mean "didn't work".
/// </summary>
/// <remarks>
/// <see cref="TechniqueResultState.Incomplete"/> may carry a partial <see cref="Value"/> — a
/// resolution run cut short by its budget returns the findings it did resolve that way. A caller
/// must still treat it as an unfinished answer; it is not <see cref="TechniqueResultState.Ok"/>
/// with fewer results.
/// </remarks>
public sealed class TechniqueResult<T> where T : class
{
    private TechniqueResult(TechniqueResultState state, T? value, string? reason, long? position)
    {
        State = state;
        Value = value;
        Reason = reason;
        Position = position;
    }

    public TechniqueResultState State { get; }

    /// <summary>Non-null for <see cref="TechniqueResultState.Ok"/>; may be non-null for Incomplete.</summary>
    public T? Value { get; }

    /// <summary>Why the operation did not complete. Non-null unless <see cref="State"/> is Ok.</summary>
    public string? Reason { get; }

    /// <summary>
    /// Byte offset the failure is anchored to, where the input has one. Populated for JSON
    /// syntax failures in the map file; null for semantic failures, whose message names the
    /// entry instead.
    /// </summary>
    public long? Position { get; }

    public bool IsOk => State == TechniqueResultState.Ok;

    public static TechniqueResult<T> Ok(T value) =>
        new(TechniqueResultState.Ok, value, null, null);

    public static TechniqueResult<T> Incomplete(T? partial, string reason) =>
        new(TechniqueResultState.Incomplete, partial, reason, null);

    public static TechniqueResult<T> Failed(string message, long? position = null) =>
        new(TechniqueResultState.Failed, null, message, position);
}
