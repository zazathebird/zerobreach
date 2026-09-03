namespace Scythe.Identity;

/// <summary>
/// An access mask split into the bits whose meaning is fixed and the bits whose meaning depends
/// on the object kind. Names are the neutral ones from reference/11.3 §11.3, ordered by bit.
/// </summary>
/// <param name="Raw">The mask as read.</param>
/// <param name="Kind">The kind the low sixteen bits were decoded under; null when the caller supplied none.</param>
/// <param name="GenericAndStandardRights">Named high-half bits — meaningful regardless of kind.</param>
/// <param name="SpecificRaw">The low sixteen bits, always reported raw.</param>
/// <param name="SpecificRights">Named low-half bits under <paramref name="Kind"/>; null when there is no kind, because naming a right without knowing the object invents a fact.</param>
/// <param name="UnnamedBits">Bits set that no table names: reserved high bits always; low bits only when a kind was supplied and its table has no name for them.</param>
public sealed record DecodedAccessMask(
    uint Raw,
    ObjectKind? Kind,
    IReadOnlyList<string> GenericAndStandardRights,
    ushort SpecificRaw,
    IReadOnlyList<string>? SpecificRights,
    uint UnnamedBits);
