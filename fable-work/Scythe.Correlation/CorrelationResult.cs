namespace Scythe.Correlation;

/// <summary>
/// The three result states shared by every reader in the package (reference/00_shared.md §2).
/// </summary>
public enum CorrelationResultState
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
/// In this project <see cref="CorrelationResultState.Incomplete"/> never carries a partial
/// <see cref="Value"/>: a chain set built from a subset of the run's edges is not "fewer chains",
/// it is different chains — components split where the missing edges would have joined them —
/// and a partial answer of that shape looks exactly like a complete one. The member is kept so
/// the shape stays identical to the other projects' result types.
/// </remarks>
public sealed class CorrelationResult<T> where T : class
{
    private CorrelationResult(CorrelationResultState state, T? value, string? reason, long? position)
    {
        State = state;
        Value = value;
        Reason = reason;
        Position = position;
    }

    public CorrelationResultState State { get; }

    /// <summary>Non-null for <see cref="CorrelationResultState.Ok"/>; may be non-null for Incomplete.</summary>
    public T? Value { get; }

    /// <summary>Why the operation did not complete. Non-null unless <see cref="State"/> is Ok.</summary>
    public string? Reason { get; }

    /// <summary>
    /// Where the failure is anchored, when the input has a position: the character offset into
    /// a string being normalised, or the index of the offending finding in the list handed to
    /// the chain builder. Null when there is no meaningful position.
    /// </summary>
    public long? Position { get; }

    public bool IsOk => State == CorrelationResultState.Ok;

    public static CorrelationResult<T> Ok(T value) =>
        new(CorrelationResultState.Ok, value, null, null);

    public static CorrelationResult<T> Incomplete(T? partial, string reason) =>
        new(CorrelationResultState.Incomplete, partial, reason, null);

    public static CorrelationResult<T> Failed(string message, long? position = null) =>
        new(CorrelationResultState.Failed, null, message, position);
}
