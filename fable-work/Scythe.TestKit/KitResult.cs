namespace Scythe.TestKit;

/// <summary>
/// The three result states shared by every reader in the package (reference/00_shared.md §2).
/// </summary>
public enum KitResultState
{
    /// <summary>The operation completed and the answer is trustworthy.</summary>
    Ok,

    /// <summary>
    /// It ran but could not finish — budget exhausted, truncated input, unsupported variant,
    /// unrecognised version. Always carries a reason. Never an <see cref="Ok"/> with less in it.
    /// In this project it is also the state of a differential run whose reference tool was
    /// absent: the comparison did not happen, and the reason says where the tool was looked for.
    /// </summary>
    Incomplete,

    /// <summary>Malformed input. Carries a message, and a position where the format has one.</summary>
    Failed,
}

/// <summary>
/// The result of one operation. Never throws for an expected outcome and never returns a bare
/// null to mean "didn't work". Same shape as every other project's result type.
/// </summary>
public sealed class KitResult<T> where T : class
{
    private KitResult(KitResultState state, T? value, string? reason, long? position)
    {
        State = state;
        Value = value;
        Reason = reason;
        Position = position;
    }

    public KitResultState State { get; }

    /// <summary>Non-null for <see cref="KitResultState.Ok"/>; may be non-null for Incomplete.</summary>
    public T? Value { get; }

    /// <summary>Why the operation did not complete. Non-null unless <see cref="State"/> is Ok.</summary>
    public string? Reason { get; }

    /// <summary>Byte offset the failure is anchored to, where the operation has one.</summary>
    public long? Position { get; }

    public bool IsOk => State == KitResultState.Ok;

    public static KitResult<T> Ok(T value) =>
        new(KitResultState.Ok, value, null, null);

    public static KitResult<T> Incomplete(T? partial, string reason) =>
        new(KitResultState.Incomplete, partial, reason, null);

    public static KitResult<T> Failed(string message, long? position = null) =>
        new(KitResultState.Failed, null, message, position);
}
