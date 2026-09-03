namespace Scythe.Identity;

/// <summary>
/// Where a well-known value's meaning holds. reference/11.3 §11.3, well-known values; the
/// distinction a caller reconciling across machines needs (brief Q3, open question 4).
/// </summary>
public enum IdentifierScope
{
    /// <summary>No table row matched. The canonical string is the complete answer.</summary>
    Unmatched,

    /// <summary>The same value on every machine.</summary>
    Fixed,

    /// <summary>A fixed leading prefix followed by a value the table does not constrain.</summary>
    FixedPrefix,

    /// <summary>Relative to a machine or a domain; the table cannot say which.</summary>
    MachineOrDomain,

    /// <summary>Relative to a domain.</summary>
    Domain,
}
