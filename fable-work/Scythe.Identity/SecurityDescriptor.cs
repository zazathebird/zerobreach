namespace Scythe.Identity;

/// <summary>The four header offsets as read, relative to the descriptor start. Zero means absent.</summary>
public sealed record DescriptorOffsets(uint Owner, uint Group, uint SystemList, uint DiscretionaryList);

/// <summary>
/// A decoded self-relative descriptor. Reports what the structure says and decides nothing about
/// whether it is appropriate — that comparison is the host's, and the host has the context.
/// </summary>
/// <param name="ResourceManagerControl">The resource-manager byte, only when control bit 0x4000 says it is meaningful; null otherwise. Absent is not zero.</param>
/// <param name="ResourceManagerControlRaw">The byte as read, regardless.</param>
/// <param name="Owner">Null when the owner offset is zero.</param>
/// <param name="Group">Null when the group offset is zero.</param>
/// <param name="MaskKind">The object kind every rights mask was decoded under; null when the caller supplied none.</param>
public sealed record SecurityDescriptor(
    byte Revision,
    byte? ResourceManagerControl,
    byte ResourceManagerControlRaw,
    DescriptorControl Control,
    DescriptorOffsets Offsets,
    SecurityIdentifier? Owner,
    SecurityIdentifier? Group,
    AccessControlList SystemList,
    AccessControlList DiscretionaryList,
    ObjectKind? MaskKind);
