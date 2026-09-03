namespace Scythe.Identity;

/// <summary>Entry types this library decodes. reference/11.3 §11.3, entry types.</summary>
public enum EntryType : byte
{
    AccessAllowed = 0x00,
    AccessDenied = 0x01,
    SystemAudit = 0x02,
    SystemAlarm = 0x03,
    AccessAllowedObject = 0x05,
    AccessDeniedObject = 0x06,
    SystemAuditObject = 0x07,
    AccessAllowedCallback = 0x09,
    AccessDeniedCallback = 0x0A,
    AccessAllowedCallbackObject = 0x0B,
    AccessDeniedCallbackObject = 0x0C,
    SystemAuditCallback = 0x0D,
    SystemAuditCallbackObject = 0x0F,
    MandatoryLabel = 0x11,
    ResourceAttribute = 0x12,
    ScopedPolicyIdentifier = 0x13,
    ProcessTrustLabel = 0x14,
    AccessFilter = 0x15,
}

/// <summary>Entry flags. reference/11.3 §11.3, entry flags. The raw byte is kept alongside.</summary>
[Flags]
public enum EntryFlags : byte
{
    None = 0,
    ObjectInherit = 0x01,
    ContainerInherit = 0x02,
    NoPropagateInherit = 0x04,
    InheritOnly = 0x08,
    Inherited = 0x10,
    SuccessfulAccessAudit = 0x40,
    FailedAccessAudit = 0x80,
}

/// <summary>What the entry's mask field means, which decides whether the rights decoder ran over it.</summary>
public enum MaskInterpretation
{
    /// <summary>Access rights; <see cref="AccessControlEntry.Decoded.Rights"/> is populated.</summary>
    AccessRights,

    /// <summary>Mandatory-label policy bits; <see cref="AccessControlEntry.Decoded.LabelPolicy"/> is populated.</summary>
    MandatoryLabelPolicy,

    /// <summary>reference/11.3 gives no semantics for this type's mask. Kept raw, decoded as nothing.</summary>
    NotInterpreted,
}

/// <summary>Mandatory-label policy bits. reference/11.3 §11.3, mandatory label.</summary>
[Flags]
public enum LabelPolicy : uint
{
    None = 0,
    NoWriteUp = 0x1,
    NoReadUp = 0x2,
    NoExecuteUp = 0x4,
}

/// <summary>Object flags bits that decide which type identifiers an object-form entry carries.</summary>
[Flags]
public enum ObjectTypeFlags : uint
{
    None = 0,
    ObjectTypePresent = 0x1,
    InheritedObjectTypePresent = 0x2,
}

/// <summary>The object-form fields: the flags word and the two type identifiers, each present only when its bit is set.</summary>
public sealed record ObjectTypeIdentifiers(ObjectTypeFlags Flags, Guid? ObjectType, Guid? InheritedObjectType);

/// <summary>Bytes kept as they were, with where they sat relative to the descriptor start.</summary>
public sealed record RawBytes(int Offset, IReadOnlyList<byte> Bytes);

/// <summary>
/// One list entry. <see cref="Decoded"/> for the types §11.3 lays out; <see cref="Unknown"/> for
/// any other type byte, kept raw so the walk can continue and the descriptor can say it did not
/// see everything.
/// </summary>
/// <param name="Offset">Where the entry header sits, relative to the descriptor start.</param>
/// <param name="DeclaredSize">The entry's own size field, header included.</param>
public abstract record AccessControlEntry(int Offset, byte TypeByte, byte FlagsRaw, ushort DeclaredSize)
{
    /// <summary>An entry of a type this library lays out.</summary>
    /// <param name="Mask">The mask field as read; see <paramref name="MaskInterpretation"/>.</param>
    /// <param name="Rights">The mask decoded as rights, for the types that carry rights.</param>
    /// <param name="LabelPolicy">The mask decoded as label policy, for the mandatory-label type only.</param>
    /// <param name="IntegrityLevel">The trailer's final sub-authority, for the mandatory-label type only; null when the trailer has no sub-authorities.</param>
    /// <param name="ObjectTypes">The object-form fields, for the object-form types only.</param>
    /// <param name="Trailer">The trailer identifier.</param>
    /// <param name="ApplicationData">Whatever followed the trailer up to the declared size, for the types whose body is application-defined. Decoded as nothing.</param>
    /// <param name="SurplusBytes">Bytes past the decoded content for the other types. Skipped, never read as the next entry.</param>
    public sealed record Decoded(
        int Offset,
        byte TypeByte,
        byte FlagsRaw,
        ushort DeclaredSize,
        EntryType Type,
        EntryFlags Flags,
        uint Mask,
        MaskInterpretation MaskInterpretation,
        DecodedAccessMask? Rights,
        LabelPolicy? LabelPolicy,
        uint? IntegrityLevel,
        ObjectTypeIdentifiers? ObjectTypes,
        SecurityIdentifier Trailer,
        RawBytes? ApplicationData,
        int SurplusBytes)
        : AccessControlEntry(Offset, TypeByte, FlagsRaw, DeclaredSize);

    /// <summary>An entry whose type byte §11.3 does not lay out. The body after the four-byte header, untouched.</summary>
    public sealed record Unknown(
        int Offset,
        byte TypeByte,
        byte FlagsRaw,
        ushort DeclaredSize,
        RawBytes Body)
        : AccessControlEntry(Offset, TypeByte, FlagsRaw, DeclaredSize);
}
