namespace ZeroBreach.Intel;

/// <summary>
/// Tri-state outcome shared by every entry point in this package (BLUEPRINT §2).
/// <see cref="Incomplete"/> is not <see cref="Ok"/> with fewer results: a truncated ingest
/// reported as a clean one is the failure mode this product cannot have.
/// </summary>
public enum OperationState
{
    /// <summary>The operation completed and the answer is trustworthy.</summary>
    Ok,

    /// <summary>It ran but could not finish — budget exhausted, truncated input,
    /// unsupported variant. Carries a reason string.</summary>
    Incomplete,

    /// <summary>Malformed input. Carries a message with position where the format has one.</summary>
    Failed,
}
