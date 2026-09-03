namespace Scythe.Correlation;

/// <summary>The outcome of asking whether two strings denote the same entity.</summary>
public enum EntityComparison
{
    /// <summary>Both normalise, and to the same entity.</summary>
    Same,

    /// <summary>Both normalise, to different entities.</summary>
    Different,

    /// <summary>At least one does not normalise as the stated kind, so the question has no answer.</summary>
    NotComparable,
}
