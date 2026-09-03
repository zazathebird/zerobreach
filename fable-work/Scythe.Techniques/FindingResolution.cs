namespace Scythe.Techniques;

/// <summary>The strategies of the resolution chain, in the order the chain runs them.</summary>
public enum ResolutionStrategy
{
    /// <summary>An identifier carried on the finding by the check that produced it.</summary>
    ExplicitIdentifier = 1,

    /// <summary>The producing check's declared mapping.</summary>
    CheckMapping = 2,

    /// <summary>An ordered keyword rule matched the finding's description. The weakest strategy.</summary>
    KeywordRule = 3,
}

/// <summary>Why a finding could not be resolved. Each value calls for different curation work.</summary>
public enum UnresolvedReason
{
    /// <summary>The finding carried an explicit identifier that is not in the map. The map needs updating; the chain did not fall through.</summary>
    ExplicitIdentifierAbsentFromMap = 1,

    /// <summary>The finding carried an explicit identifier that is not well-formed. The check needs fixing; the chain did not fall through.</summary>
    ExplicitIdentifierMalformed = 2,

    /// <summary>The producing check declares an identifier that is not in the map. The map needs updating; the chain did not fall through.</summary>
    CheckIdentifierAbsentFromMap = 3,

    /// <summary>Every strategy declined. <see cref="UnresolvedFinding.Attempts"/> says why each one did.</summary>
    NoStrategyProduced = 4,
}

/// <summary>One strategy's refusal, recorded so the reason for an unresolved finding is specific.</summary>
public sealed record StrategyAttempt(ResolutionStrategy Strategy, string Declined);

/// <summary>
/// The outcome of resolving one finding. Exactly one of two shapes:
/// <see cref="ResolvedFinding"/> or <see cref="UnresolvedFinding"/>.
/// </summary>
/// <remarks>
/// There is deliberately no nullable identifier on this type. A caller reaches an identifier
/// only through <see cref="ResolvedFinding"/>, and reaches that only by handling the unresolved
/// case too — via <see cref="Match{T}"/>, or by pattern-matching on the two subtypes. Unresolved
/// is a real answer, not a missing one.
/// </remarks>
public abstract class FindingResolution
{
    private protected FindingResolution(string findingId)
    {
        FindingId = findingId;
    }

    public string FindingId { get; }

    public abstract bool IsResolved { get; }

    public abstract T Match<T>(Func<ResolvedFinding, T> resolved, Func<UnresolvedFinding, T> unresolved);
}

/// <summary>A finding resolved to an entry in the map, with the strategy that produced it.</summary>
public sealed class ResolvedFinding : FindingResolution
{
    internal ResolvedFinding(string findingId, TechniqueEntry entry, ResolutionStrategy strategy, int? ruleOrdinal)
        : base(findingId)
    {
        Entry = entry;
        Strategy = strategy;
        RuleOrdinal = ruleOrdinal;
    }

    public TechniqueEntry Entry { get; }

    public TechniqueIdentifier Identifier => Entry.Identifier;

    /// <summary>
    /// Which strategy produced the answer. A technician weighs an identifier from
    /// <see cref="ResolutionStrategy.ExplicitIdentifier"/> very differently from one a keyword
    /// rule found in a sentence; the report is expected to show the difference.
    /// </summary>
    public ResolutionStrategy Strategy { get; }

    /// <summary>The matching rule's ordinal when <see cref="Strategy"/> is <see cref="ResolutionStrategy.KeywordRule"/>; otherwise null.</summary>
    public int? RuleOrdinal { get; }

    public override bool IsResolved => true;

    public override T Match<T>(Func<ResolvedFinding, T> resolved, Func<UnresolvedFinding, T> unresolved) =>
        resolved(this);
}

/// <summary>A finding no strategy resolved, with the reason. Appears in the rollup as its own group.</summary>
public sealed class UnresolvedFinding : FindingResolution
{
    internal UnresolvedFinding(string findingId, UnresolvedReason reason, string detail, IReadOnlyList<StrategyAttempt> attempts)
        : base(findingId)
    {
        Reason = reason;
        Detail = detail;
        Attempts = attempts;
    }

    public UnresolvedReason Reason { get; }

    /// <summary>The reason in words, naming the identifier or check involved.</summary>
    public string Detail { get; }

    /// <summary>Every strategy that ran, in chain order, and why it declined.</summary>
    public IReadOnlyList<StrategyAttempt> Attempts { get; }

    public override bool IsResolved => false;

    public override T Match<T>(Func<ResolvedFinding, T> resolved, Func<UnresolvedFinding, T> unresolved) =>
        unresolved(this);
}
