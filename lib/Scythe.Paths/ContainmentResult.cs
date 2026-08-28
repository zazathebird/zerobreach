namespace Scythe.Paths;

/// <summary>How a candidate path relates to a directory. Only meaningful on <see cref="OperationState.Ok"/>.</summary>
public enum ContainmentVerdict
{
    /// <summary>The candidate is provably not the directory and not under it.</summary>
    Outside,

    /// <summary>The candidate is strictly under the directory (or is a named stream on it).</summary>
    Inside,

    /// <summary>The candidate names the directory itself.</summary>
    Equal,
}

/// <summary>
/// The result of a containment check. Tri-state discipline (BLUEPRINT §2): an undecidable
/// relationship is <see cref="OperationState.Incomplete"/>, never a quiet false — and
/// <see cref="IsInside"/> is structurally incapable of being true unless the state is
/// <see cref="OperationState.Ok"/>. A guard must treat anything other than Ok/Outside as
/// "refuse the operation".
/// </summary>
public sealed class ContainmentResult
{
    private ContainmentResult(OperationState state, ContainmentVerdict? verdict, string? reason)
    {
        State = state;
        Verdict = verdict;
        Reason = reason;
    }

    /// <summary>Ok with a <see cref="Verdict"/>; Incomplete when the strings cannot prove the relationship; Failed on malformed input.</summary>
    public OperationState State { get; }

    /// <summary>The relationship; null unless <see cref="State"/> is <see cref="OperationState.Ok"/>.</summary>
    public ContainmentVerdict? Verdict { get; }

    /// <summary>Why the check is Incomplete/Failed, or why an Ok verdict is Outside. Null for Inside/Equal.</summary>
    public string? Reason { get; }

    /// <summary>
    /// True when the candidate is provably the directory or under it. Deliberately includes
    /// <see cref="ContainmentVerdict.Equal"/>: a guard protecting a directory must also refuse
    /// destructive operations on the directory itself. Never true unless <see cref="State"/> is Ok.
    /// </summary>
    public bool IsInside =>
        State == OperationState.Ok && Verdict is ContainmentVerdict.Inside or ContainmentVerdict.Equal;

    internal static ContainmentResult Inside() =>
        new(OperationState.Ok, ContainmentVerdict.Inside, reason: null);

    internal static ContainmentResult Equal() =>
        new(OperationState.Ok, ContainmentVerdict.Equal, reason: null);

    internal static ContainmentResult Outside(string reason) =>
        new(OperationState.Ok, ContainmentVerdict.Outside, reason);

    internal static ContainmentResult Undecidable(string reason) =>
        new(OperationState.Incomplete, verdict: null, reason);

    internal static ContainmentResult Malformed(string reason) =>
        new(OperationState.Failed, verdict: null, reason);

    public override string ToString() =>
        State == OperationState.Ok ? $"{State}/{Verdict}" : $"{State}: {Reason}";
}
