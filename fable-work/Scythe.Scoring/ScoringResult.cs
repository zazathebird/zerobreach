namespace Scythe.Scoring;

/// <summary>
/// The three result states shared by every reader in the package (reference/00_shared.md §2).
/// </summary>
public enum ScoringResultState
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
/// The result of one rollup. Never throws for an expected outcome and never returns a bare null
/// to mean "didn't work".
/// </summary>
/// <remarks>
/// <see cref="ScoringResultState.Incomplete"/> may carry a partial <see cref="Value"/> — a record
/// whose inconclusive checks gave no reason still has countable findings, and the partial rollup
/// carries them so the technician sees the numbers alongside the reason they are unfinished. A
/// caller must still treat it as an unfinished answer; it is not
/// <see cref="ScoringResultState.Ok"/> with fewer results.
/// </remarks>
public sealed class ScoringResult<T> where T : class
{
    private ScoringResult(ScoringResultState state, T? value, string? reason, long? position)
    {
        State = state;
        Value = value;
        Reason = reason;
        Position = position;
    }

    public ScoringResultState State { get; }

    /// <summary>Non-null for <see cref="ScoringResultState.Ok"/>; may be non-null for Incomplete.</summary>
    public T? Value { get; }

    /// <summary>Why the operation did not complete. Non-null unless <see cref="State"/> is Ok.</summary>
    public string? Reason { get; }

    /// <summary>
    /// The index into the record's check or finding list the failure is anchored to, where it has
    /// one; the message says which list. Null when the failure is about the record as a whole.
    /// </summary>
    public long? Position { get; }

    public bool IsOk => State == ScoringResultState.Ok;

    public static ScoringResult<T> Ok(T value) =>
        new(ScoringResultState.Ok, value, null, null);

    public static ScoringResult<T> Incomplete(T? partial, string reason) =>
        new(ScoringResultState.Incomplete, partial, reason, null);

    public static ScoringResult<T> Failed(string message, long? position = null) =>
        new(ScoringResultState.Failed, null, message, position);
}
