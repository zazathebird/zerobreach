namespace ZeroBreach.Formats.Pe;

/// <summary>
/// Derived numbers for one section. Facts only — no verdicts. The host decides what a
/// high-entropy writable section means; the moment this library renders that verdict it
/// becomes untunable from outside.
/// </summary>
/// <param name="Index">Position in the section table.</param>
/// <param name="Name">The section name as parsed.</param>
/// <param name="Entropy">
/// Shannon entropy in bits per byte over the section's raw file bytes, clamped to the actual
/// buffer. Null — not 0.0 — when there are no readable raw bytes (raw size zero, or raw
/// pointer outside the file): 0.0 would read as "a run of one byte value", which is a
/// different fact entirely.
/// </param>
/// <param name="WritableAndExecutable">Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE set.</param>
/// <param name="ZeroRawSizeWithLargeVirtualSize">
/// Raw size is zero while virtual size is at least <see cref="PeParserLimits.LargeVirtualSizeThreshold"/>.
/// </param>
/// <param name="UncommonName">Name is not in <see cref="PeCommonSectionNames.Common"/> (ordinal, case-sensitive).</param>
public sealed record PeSectionMetrics(
    int Index,
    string Name,
    double? Entropy,
    bool WritableAndExecutable,
    bool ZeroRawSizeWithLargeVirtualSize,
    bool UncommonName);

/// <summary>
/// Anomaly metrics derived from a parsed image. Reported, never editorialised: there is
/// deliberately no IsPacked / IsSuspicious here.
///
/// Entropy definition (fixed, so numbers are comparable across runs): Shannon entropy with
/// log base 2 over the byte histogram of the natural window — the entire raw byte range of a
/// section for per-section entropy, the entire input buffer for whole-file entropy. Range is
/// [0, 8] bits per byte. A window with no bytes yields null, never 0.0.
/// </summary>
/// <param name="WholeFileEntropy">Entropy of the entire input buffer. Null only for an empty buffer.</param>
/// <param name="Sections">Per-section metrics, in section-table order.</param>
/// <param name="EntryPointOutsideAnySection">
/// AddressOfEntryPoint is non-zero and falls in no section's virtual range. A zero entry
/// point (common for DLLs and resource-only images) sets neither entry-point flag.
/// </param>
/// <param name="EntryPointInWritableSection">The entry point falls inside a section with IMAGE_SCN_MEM_WRITE.</param>
/// <param name="OverlayPresent">The file has bytes past all mapped content (see <paramref name="OverlayOffset"/>).</param>
/// <param name="OverlayOffset">
/// End of mapped content: the maximum of SizeOfHeaders and every section's raw end, each
/// clamped to the file. Bytes from here to end of file are the overlay. Note the certificate
/// directory conventionally lives in the overlay, so a signed file reports one.
/// </param>
/// <param name="OverlaySize">File length minus <paramref name="OverlayOffset"/>; zero when no overlay.</param>
/// <param name="ImportedDllCount">Number of import descriptors recovered.</param>
/// <param name="ImportedFunctionCount">Total imported functions (by name or ordinal) recovered.</param>
/// <param name="TlsCallbacksPresent">At least one TLS callback address was read.</param>
/// <param name="TlsCallbackCount">Number of TLS callback addresses read.</param>
public sealed record PeMetrics(
    double? WholeFileEntropy,
    IReadOnlyList<PeSectionMetrics> Sections,
    bool EntryPointOutsideAnySection,
    bool EntryPointInWritableSection,
    bool OverlayPresent,
    long OverlayOffset,
    long OverlaySize,
    int ImportedDllCount,
    int ImportedFunctionCount,
    bool TlsCallbacksPresent,
    int TlsCallbackCount);

/// <summary>
/// The section names treated as "common" for <see cref="PeSectionMetrics.UncommonName"/>.
/// Comparison is ordinal and case-sensitive: section names are byte strings, and a
/// case-variant of a stock name (".TEXT") is itself worth surfacing.
/// The list covers MSVC, MinGW/GCC, .NET, Delphi/Borland and common installer output.
/// </summary>
public static class PeCommonSectionNames
{
    /// <summary>The common-name set. Anything else is reported as uncommon; the host scores it.</summary>
    public static readonly IReadOnlySet<string> Common = new HashSet<string>(StringComparer.Ordinal)
    {
        ".text", ".rdata", ".data", ".bss", ".idata", ".edata", ".pdata", ".rsrc", ".reloc",
        ".tls", ".debug", ".xdata", ".ndata", ".didat", ".rodata", ".crt", ".CRT", ".sdata",
        ".srdata", ".00cfg", ".gfids", ".giats", ".gxfg", ".retplne", ".sxdata", ".textbss",
        ".cormeta", ".drectve", ".vsdata", ".apiset", ".mrdata", ".wpp_sf", ".shared",
        // Borland / Delphi
        "CODE", "DATA", "BSS", ".itext",
        // MinGW / Cygwin
        ".eh_fram", ".eh_frame", ".ctors", ".dtors", ".init", ".fini", ".gnu_deb", ".buildid",
    };
}
