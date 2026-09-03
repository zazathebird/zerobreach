namespace Scythe.Identity;

/// <summary>
/// The object a descriptor is attached to. The low sixteen bits of an access mask mean nothing
/// without it (reference/11.3 §11.3, the access mask), and nothing in the descriptor says which,
/// so the caller supplies it — or supplies none and gets those bits raw.
/// </summary>
/// <remarks>
/// The five kinds are the ones §11.3 tables: file and directory share a column whose names differ
/// per kind ("read data" / "list contents"), so they are two kinds here. Adding a kind means
/// adding its sixteen-name table to <see cref="AccessMaskDecoder"/> with its source in a comment.
/// </remarks>
public enum ObjectKind
{
    File,
    Directory,
    RegistryKey,
    Service,
    Process,
}
