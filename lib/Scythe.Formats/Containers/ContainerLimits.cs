namespace Scythe.Formats.Containers;

/// <summary>
/// Explicit caps for container reading. Every count and size that drives a loop or an
/// allocation here comes from attacker-authored bytes, so each is capped by a named constant
/// (BLUEPRINT §3). Exceeding a cap yields <see cref="OperationState.Incomplete"/> with the
/// reason — never a hang or an out-of-memory crash.
/// </summary>
public static class ContainerLimits
{
    /// <summary>Maximum ZIP central-directory entries enumerated (also bounded by <see cref="ScanBudget.MaxMatches"/>).</summary>
    public const int MaxZipEntries = 10_000;

    /// <summary>
    /// Maximum expansion ratio (expanded bytes / compressed bytes) for a single entry.
    /// Deflate tops out around 1032:1, so a legitimate document never approaches this while a
    /// bomb blows straight through it.
    /// </summary>
    public const long MaxCompressionRatio = 100;

    /// <summary>
    /// The ratio guard only applies once an entry has expanded past this floor. A 10-byte
    /// entry expanding to 2 KiB is ratio 200 but harmless; without the floor, tiny legitimate
    /// entries trip the guard.
    /// </summary>
    public const long RatioGuardFloorBytes = 64 * 1024;

    /// <summary>Default cap on total expanded bytes across all reads sharing one <see cref="ExpansionGuard"/>.</summary>
    public const long MaxTotalExpandedBytes = 256L * 1024 * 1024;

    /// <summary>Chunk size for streaming decompression, so guards are checked every chunk, not at the end.</summary>
    public const int DecompressChunkBytes = 64 * 1024;

    /// <summary>
    /// The end-of-central-directory record is 22 bytes plus a comment of at most 65535 bytes,
    /// so it can sit at most this far from the end of the file. The backward search never
    /// scans further than this.
    /// </summary>
    public const int MaxEocdSearchBytes = 22 + 65_535;

    /// <summary>Maximum OLE directory entries parsed.</summary>
    public const int MaxOleDirectoryEntries = 4096;

    /// <summary>
    /// Maximum OLE directory-tree depth walked. This bounds recursion over the red-black
    /// sibling tree; real documents are a handful of levels deep. Distinct from
    /// <see cref="ScanBudget.MaxNestingDepth"/>, which bounds container-inside-container
    /// nesting, not the tree inside one container.
    /// </summary>
    public const int MaxOleTreeDepth = 64;

    /// <summary>Maximum bytes of any OOXML XML part ([Content_Types].xml, .rels) parsed as XML.</summary>
    public const int MaxOoxmlXmlBytes = 4 * 1024 * 1024;

    /// <summary>Maximum characters the XML reader will process from an OOXML metadata part.</summary>
    public const long MaxOoxmlXmlCharacters = 8L * 1024 * 1024;

    /// <summary>Maximum relationships read from a single .rels part.</summary>
    public const int MaxRelationships = 4096;
}
