namespace Scythe.Formats;

/// <summary>
/// Outcome of any entry point in this layer (BLUEPRINT §2).
/// <c>Incomplete</c> is not <c>Ok</c> with fewer results — the host reports coverage to a
/// technician, and a truncated parse reported as a complete one is the failure mode this
/// product cannot have. The two states are never collapsed.
/// </summary>
public enum OperationState
{
    /// <summary>The operation completed and the answer is trustworthy.</summary>
    Ok,

    /// <summary>
    /// The operation ran but could not finish — budget exhausted, truncated input,
    /// unsupported variant. Carries a reason string.
    /// </summary>
    Incomplete,

    /// <summary>Malformed input. Carries a message with the byte position where the format has one.</summary>
    Failed,
}
