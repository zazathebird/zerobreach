namespace ZeroBreach.Formats.Containers;

/// <summary>One part (file) of an OOXML package, with its resolved content type.</summary>
public sealed record OoxmlPartInfo
{
    /// <summary>Part name as spelled in the ZIP entry (no leading slash).</summary>
    public required string Name { get; init; }

    public required long CompressedSize { get; init; }

    public required long UncompressedSize { get; init; }

    /// <summary>From an Override match, else the extension Default; null when neither declares it.</summary>
    public required string? ContentType { get; init; }

    /// <summary>
    /// True for a VBA macro binary: content type <c>application/vnd.ms-office.vbaProject</c>
    /// or a name ending in <c>vbaProject.bin</c>. Presence is surfaced, bytes are handed
    /// over; what they contain is the host's problem (task brief).
    /// </summary>
    public required bool IsMacroPart { get; init; }

    public required bool IsEncrypted { get; init; }
}

/// <summary>One package-level relationship from <c>_rels/.rels</c>.</summary>
public sealed record OoxmlRelationship(string Id, string Type, string Target);

/// <summary>An OOXML package: a ZIP with a known part layout.</summary>
public sealed record OoxmlPackageInfo
{
    /// <summary>The underlying ZIP structure, anomalies and all.</summary>
    public required ZipArchiveInfo Zip { get; init; }

    /// <summary>Extension → content type, from [Content_Types].xml Default elements. Keys lower-cased.</summary>
    public required IReadOnlyDictionary<string, string> ContentTypeDefaults { get; init; }

    /// <summary>Part name (with leading slash, as spelled) → content type, from Override elements.</summary>
    public required IReadOnlyDictionary<string, string> ContentTypeOverrides { get; init; }

    /// <summary>Package-level relationships, in document order; empty when _rels/.rels is absent.</summary>
    public required IReadOnlyList<OoxmlRelationship> Relationships { get; init; }

    /// <summary>All content parts, in ZIP central-directory order.</summary>
    public required IReadOnlyList<OoxmlPartInfo> Parts { get; init; }

    /// <summary>Structural oddities that do not prevent reading (e.g. a missing _rels/.rels).</summary>
    public required IReadOnlyList<string> PackageAnomalies { get; init; }

    /// <summary>Target of the officeDocument relationship — the main document part — when declared.</summary>
    public required string? OfficeDocumentTarget { get; init; }

    public bool HasMacroPart => Parts.Any(p => p.IsMacroPart);

    /// <summary>The macro binary parts, if any (normally zero or one).</summary>
    public IReadOnlyList<OoxmlPartInfo> MacroParts => Parts.Where(p => p.IsMacroPart).ToList();
}

/// <summary>
/// Result of <see cref="OoxmlReader.Read"/>. <c>Failed</c> — not a ZIP, no
/// [Content_Types].xml (a ZIP but not an OOXML package), or metadata XML that is malformed
/// or tries to smuggle a DTD. <c>Incomplete</c> — the underlying ZIP or a metadata part
/// could not be fully read; never collapsed into <c>Ok</c>.
/// </summary>
public sealed record OoxmlReadResult(
    OperationState State,
    string? Message,
    IReadOnlyList<string> IncompleteReasons,
    OoxmlPackageInfo? Package)
{
    internal static OoxmlReadResult Fail(string message) =>
        new(OperationState.Failed, message, Array.Empty<string>(), null);

    internal static OoxmlReadResult IncompleteWithoutPackage(string reason) =>
        new(OperationState.Incomplete, reason, new[] { reason }, null);

    internal static OoxmlReadResult From(IReadOnlyList<string> reasons, OoxmlPackageInfo package) =>
        reasons.Count == 0
            ? new(OperationState.Ok, null, Array.Empty<string>(), package)
            : new(OperationState.Incomplete, string.Join("; ", reasons), reasons, package);
}
