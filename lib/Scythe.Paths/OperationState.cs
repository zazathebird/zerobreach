namespace Scythe.Paths;

/// <summary>
/// Outcome of an operation, per the shared result-type convention (BLUEPRINT §2).
/// Expected outcomes never throw and never surface as a bare null.
/// </summary>
public enum OperationState
{
    /// <summary>The operation completed and the answer is trustworthy.</summary>
    Ok,

    /// <summary>
    /// The operation ran but could not produce a definitive answer — for path comparison,
    /// this means the relationship cannot be proven from the strings alone (for example a
    /// relative path with no base directory, or a device-namespace path that may alias any
    /// location). A guard must treat this as "refuse", never as "not inside".
    /// </summary>
    Incomplete,

    /// <summary>Malformed input. Carries a message with position where the input has one.</summary>
    Failed,
}
