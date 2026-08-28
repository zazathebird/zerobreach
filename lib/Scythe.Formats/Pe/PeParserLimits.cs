namespace Scythe.Formats.Pe;

/// <summary>
/// Explicit caps for structures whose counts come from the file itself. A PE header field is
/// attacker-controlled data; every count is capped by a named constant before it drives a loop
/// or an allocation. Exceeding a cap yields <see cref="OperationState.Incomplete"/> with the
/// reason — never a hang or an out-of-memory crash.
/// </summary>
public static class PeParserLimits
{
    /// <summary>
    /// Maximum sections read. The Windows loader itself refuses images with more than 96
    /// sections, so a larger count is corrupt by definition and the table is not read at all.
    /// </summary>
    public const int MaxSections = 96;

    /// <summary>The PE format defines exactly 16 data directories; a larger declared count is ignored.</summary>
    public const int MaxDataDirectories = 16;

    /// <summary>Maximum import descriptors (DLLs) walked.</summary>
    public const int MaxImportDescriptors = 4096;

    /// <summary>Maximum thunks (imported functions) walked per descriptor.</summary>
    public const int MaxThunksPerDescriptor = 65536;

    /// <summary>Maximum bytes read for any NUL-terminated name (DLL, function, forwarder, PDB path).</summary>
    public const int MaxNameLength = 4096;

    /// <summary>Maximum export-table function or name entries read.</summary>
    public const int MaxExportEntries = 65536;

    /// <summary>Maximum resource-tree nodes visited in total, across the whole tree.</summary>
    public const int MaxResourceNodes = 4096;

    /// <summary>
    /// Hard ceiling on resource-tree depth. The effective depth cap is the smaller of this and
    /// <see cref="ScanBudget.MaxNestingDepth"/>; a well-formed tree is only 3 levels deep.
    /// </summary>
    public const int MaxResourceDepth = 32;

    /// <summary>Maximum TLS callback addresses read.</summary>
    public const int MaxTlsCallbacks = 1024;

    /// <summary>Maximum debug directory entries read.</summary>
    public const int MaxDebugEntries = 64;

    /// <summary>
    /// A section with raw size zero is only flagged in metrics when its virtual size is at
    /// least this many bytes — one page. Below that it is ordinary uninitialised data.
    /// </summary>
    public const uint LargeVirtualSizeThreshold = 4096;
}
