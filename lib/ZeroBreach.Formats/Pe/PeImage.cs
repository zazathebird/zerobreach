namespace ZeroBreach.Formats.Pe;

/// <summary>The DOS header fields the host cares about. Magic is always 0x5A4D ("MZ") in a parsed image.</summary>
public sealed record PeDosHeader(ushort Magic, uint Lfanew);

/// <summary>COFF file header. All values are the raw on-disk numbers; the host interprets them.</summary>
public sealed record PeFileHeader(
    ushort Machine,
    ushort NumberOfSections,
    uint TimeDateStamp,
    uint PointerToSymbolTable,
    uint NumberOfSymbols,
    ushort SizeOfOptionalHeader,
    ushort Characteristics)
{
    /// <summary>
    /// The link timestamp as UTC, or null when the raw field is zero (reproducible builds
    /// store a hash here instead of a time; zero is "not set"). Derived deterministically
    /// from <see cref="TimeDateStamp"/> — no clock is consulted.
    /// </summary>
    public DateTimeOffset? TimeDateStampUtc =>
        TimeDateStamp == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(TimeDateStamp);
}

/// <summary>
/// Optional header, covering both PE32 (magic 0x10B) and PE32+ (magic 0x20B).
/// <paramref name="BaseOfData"/> exists only in PE32 and is null for PE32+.
/// Widths that differ between the two formats are stored at the wider (64-bit) width.
/// </summary>
public sealed record PeOptionalHeader(
    ushort Magic,
    bool IsPe32Plus,
    byte MajorLinkerVersion,
    byte MinorLinkerVersion,
    uint SizeOfCode,
    uint SizeOfInitializedData,
    uint SizeOfUninitializedData,
    uint AddressOfEntryPoint,
    uint BaseOfCode,
    uint? BaseOfData,
    ulong ImageBase,
    uint SectionAlignment,
    uint FileAlignment,
    ushort MajorOperatingSystemVersion,
    ushort MinorOperatingSystemVersion,
    ushort MajorImageVersion,
    ushort MinorImageVersion,
    ushort MajorSubsystemVersion,
    ushort MinorSubsystemVersion,
    uint Win32VersionValue,
    uint SizeOfImage,
    uint SizeOfHeaders,
    uint CheckSum,
    ushort Subsystem,
    ushort DllCharacteristics,
    ulong SizeOfStackReserve,
    ulong SizeOfStackCommit,
    ulong SizeOfHeapReserve,
    ulong SizeOfHeapCommit,
    uint LoaderFlags,
    uint NumberOfRvaAndSizes);

/// <summary>One data directory slot. <paramref name="Name"/> is the standard name for the index.</summary>
public sealed record PeDataDirectory(int Index, string Name, uint VirtualAddress, uint Size);

/// <summary>
/// One section table entry. <paramref name="Name"/> is the 8-byte field decoded as Latin-1 up to
/// the first NUL, so unusual bytes survive rather than collapsing to '?'.
/// </summary>
public sealed record PeSection(
    string Name,
    uint VirtualSize,
    uint VirtualAddress,
    uint SizeOfRawData,
    uint PointerToRawData,
    uint Characteristics);

/// <summary>
/// One imported function. Exactly one of <paramref name="Name"/> and <paramref name="Ordinal"/>
/// is set for a well-formed thunk; both may be null when the hint/name entry was unreadable
/// (reported as an Incomplete reason).
/// </summary>
public sealed record PeImportFunction(string? Name, ushort? Ordinal, ushort? Hint);

/// <summary>One imported DLL. <paramref name="Name"/> is null when the name RVA was unreadable.</summary>
public sealed record PeImportedDll(string? Name, IReadOnlyList<PeImportFunction> Functions);

/// <summary>
/// One export. <paramref name="Ordinal"/> is the biased ordinal (ordinal base + table index).
/// A forwarded export has <paramref name="Forwarder"/> set and no meaningful code RVA.
/// <paramref name="Rva"/> is null for an unused slot that still carries a name.
/// </summary>
public sealed record PeExportEntry(string? Name, uint Ordinal, uint? Rva, string? Forwarder);

/// <summary>The export directory: the image's own name, ordinal base, and its entries.</summary>
public sealed record PeExports(
    string? DllName,
    uint OrdinalBase,
    uint TimeDateStamp,
    IReadOnlyList<PeExportEntry> Entries);

/// <summary>A resource data leaf. <paramref name="Rva"/> is the RVA of the payload bytes.</summary>
public sealed record PeResourceData(uint Rva, uint Size, uint CodePage);

/// <summary>
/// A node in the resource tree. Directory nodes carry <paramref name="Children"/>; leaves carry
/// <paramref name="Data"/>. An entry has either a <paramref name="Name"/> (UTF-16 string) or a
/// numeric <paramref name="Id"/>; the root has neither.
/// </summary>
public sealed record PeResourceNode(
    string? Name,
    uint? Id,
    IReadOnlyList<PeResourceNode> Children,
    PeResourceData? Data);

/// <summary>
/// The certificate (security) directory. <paramref name="Offset"/> is a raw file offset — this
/// is the one directory whose "VirtualAddress" field is not an RVA. Presence is recorded even
/// when the range extends past the file (reported as an Incomplete reason); fetching the bytes
/// then returns null. No signature verification happens here — that needs Windows.
/// </summary>
public sealed record PeCertificateInfo(uint Offset, uint Size);

/// <summary>
/// One debug directory entry. For a CodeView (type 2) entry with an RSDS record, the PDB
/// GUID, age and path are decoded.
/// </summary>
public sealed record PeDebugEntry(
    uint Type,
    uint TimeDateStamp,
    uint SizeOfData,
    uint AddressOfRawData,
    uint PointerToRawData,
    Guid? PdbGuid,
    uint? PdbAge,
    string? PdbPath);

/// <summary>One decoded Rich-header entry: tool product id, build number, and use count.</summary>
public sealed record PeRichEntry(ushort ProductId, ushort BuildId, uint Count);

/// <summary>The undocumented Rich header, decoded with its XOR key. Null on the image when absent.</summary>
public sealed record PeRichHeader(uint XorKey, IReadOnlyList<PeRichEntry> Entries);

/// <summary>
/// TLS directory presence and the callback addresses (virtual addresses as stored, not RVAs).
/// <paramref name="Present"/> is true whenever the image has a TLS directory, even if the
/// callback array was empty or unreadable.
/// </summary>
public sealed record PeTlsInfo(bool Present, IReadOnlyList<ulong> CallbackAddresses);

/// <summary>Everything recovered from a static parse. Structure only — the derived numbers live in <see cref="PeMetrics"/>.</summary>
public sealed record PeImage(
    PeDosHeader DosHeader,
    PeFileHeader FileHeader,
    PeOptionalHeader OptionalHeader,
    IReadOnlyList<PeDataDirectory> DataDirectories,
    IReadOnlyList<PeSection> Sections,
    IReadOnlyList<PeImportedDll> Imports,
    PeExports? Exports,
    PeResourceNode? ResourceRoot,
    PeCertificateInfo? Certificate,
    IReadOnlyList<PeDebugEntry> DebugEntries,
    PeRichHeader? RichHeader,
    PeTlsInfo? Tls);
