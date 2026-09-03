namespace Scythe.Identity;

/// <summary>The three states a list can be in. Never a possibly-empty collection.</summary>
public enum ListPresence
{
    /// <summary>Grants everything to everyone.</summary>
    NotPresent,

    /// <summary>Present, well-formed, no entries: grants nothing to anyone.</summary>
    Empty,

    /// <summary>What the entries say.</summary>
    Entries,
}

/// <summary>
/// Which of the two encodings a not-present list used. They are not quite equivalent to the
/// operating system, and a caller reconciling against a baseline may care.
/// </summary>
public enum AbsenceEncoding
{
    /// <summary>The present control bit is clear.</summary>
    ControlBitClear,

    /// <summary>The present control bit is set and the offset is zero.</summary>
    ControlBitSetOffsetZero,
}

/// <summary>The eight-byte list header, as read, plus what the walk found past the last entry.</summary>
/// <param name="Offset">Where the header sits, relative to the descriptor start.</param>
/// <param name="DeclaredSize">Total list size including this header.</param>
/// <param name="SurplusBytes">Bytes between the end of the last entry and the declared end. Skipped, never read as an entry.</param>
public sealed record ListHeader(
    int Offset,
    byte Revision,
    byte Reserved1,
    ushort DeclaredSize,
    ushort DeclaredCount,
    ushort Reserved2,
    int SurplusBytes);

/// <summary>
/// An access-control list as a sum type over <see cref="ListPresence"/>. Absence and emptiness
/// mean opposite things (reference/11.3 §11.3), so they are different types, not different counts.
/// </summary>
public abstract record AccessControlList(ListPresence Presence)
{
    /// <summary>The list is not there: everything is granted to everyone.</summary>
    /// <param name="IgnoredOffset">The header's offset field, kept for a caller reconciling encodings; not followed.</param>
    public sealed record NotPresent(AbsenceEncoding Encoding, uint IgnoredOffset)
        : AccessControlList(ListPresence.NotPresent);

    /// <summary>The list is there and has no entries: nothing is granted to anyone.</summary>
    public sealed record Empty(ListHeader Header)
        : AccessControlList(ListPresence.Empty);

    /// <summary>The list is there and its entries say what is granted.</summary>
    public sealed record Entries(ListHeader Header, IReadOnlyList<AccessControlEntry> Items)
        : AccessControlList(ListPresence.Entries);
}
