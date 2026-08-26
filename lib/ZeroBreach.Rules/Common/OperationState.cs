namespace ZeroBreach.Rules;

/// <summary>
/// Tri-state outcome shared by every entry point in this layer (BLUEPRINT §2).
/// <see cref="Incomplete"/> is not <see cref="Ok"/> with fewer results: the host reports
/// coverage to a technician, and a truncated scan reported as clean is the single worst
/// failure this product can produce. Nothing in this library may collapse the two.
/// </summary>
public enum OperationState
{
    /// <summary>The operation completed and the answer is trustworthy.</summary>
    Ok,

    /// <summary>The operation ran but could not finish (budget exhausted, truncated input,
    /// unsupported variant). Always carries a reason.</summary>
    Incomplete,

    /// <summary>The input was malformed. Carries a message, with position where the format
    /// has one.</summary>
    Failed,
}
