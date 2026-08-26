using System.Xml;

namespace ZeroBreach.Formats.Containers;

/// <summary>
/// OOXML package reader (BLUEPRINT §7): modern Office files are ZIPs with a known part
/// layout. This resolves content types, package relationships, and — the part the host
/// cares most about — whether a VBA macro binary is present. Macro bytes are handed over
/// uninterpreted.
///
/// The metadata XML is parsed with DTDs prohibited and no resolver: a DOCTYPE inside
/// [Content_Types].xml is an XXE attempt against the scanner itself and fails loudly.
/// </summary>
public static class OoxmlReader
{
    public const string ContentTypesPartName = "[Content_Types].xml";
    public const string PackageRelsPartName = "_rels/.rels";
    public const string VbaProjectContentType = "application/vnd.ms-office.vbaProject";
    private const string OfficeDocumentRelationshipSuffix = "/officeDocument";

    /// <summary>Enumerates the package. Reads only the two metadata parts; content parts are enumerated, not read.</summary>
    public static OoxmlReadResult Read(byte[] data, ScanBudget budget, ExpansionGuard? guard = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(budget);
        guard ??= new ExpansionGuard();

        var zip = ZipReader.Read(data, budget);
        if (zip.State == OperationState.Failed)
        {
            return OoxmlReadResult.Fail($"not a ZIP, so not an OOXML package: {zip.Message}");
        }
        if (zip.Archive is null)
        {
            return OoxmlReadResult.IncompleteWithoutPackage(
                $"underlying ZIP could not be enumerated: {zip.Message}");
        }

        var reasons = new List<string>(zip.IncompleteReasons);
        var anomalies = new List<string>();

        ZipEntryInfo? contentTypesEntry = FindEntry(zip.Archive, ContentTypesPartName);
        if (contentTypesEntry is null)
        {
            return OoxmlReadResult.Fail("a ZIP but not an OOXML package: no [Content_Types].xml entry");
        }

        var contentTypesBytes = ReadMetadataPart(data, contentTypesEntry, budget, guard);
        if (contentTypesBytes.Result is not null)
        {
            return contentTypesBytes.Result;
        }

        Dictionary<string, string> defaults;
        Dictionary<string, string> overrides;
        try
        {
            (defaults, overrides) = ParseContentTypes(contentTypesBytes.Bytes!);
        }
        catch (XmlException ex)
        {
            return OoxmlReadResult.Fail(
                $"[Content_Types].xml is not well-formed XML (line {ex.LineNumber}, column {ex.LinePosition}): {ex.Message}");
        }

        var relationships = new List<OoxmlRelationship>();
        string? officeDocumentTarget = null;
        ZipEntryInfo? relsEntry = FindEntry(zip.Archive, PackageRelsPartName);
        if (relsEntry is null)
        {
            // Required by OPC, but its absence does not stop part enumeration or macro
            // detection — so it is an anomaly on a complete read, not an Incomplete.
            anomalies.Add("package has no _rels/.rels; relationships unavailable");
        }
        else
        {
            var relsBytes = ReadMetadataPart(data, relsEntry, budget, guard);
            if (relsBytes.Result is not null)
            {
                return relsBytes.Result;
            }
            try
            {
                relationships = ParseRelationships(relsBytes.Bytes!);
            }
            catch (XmlException ex)
            {
                return OoxmlReadResult.Fail(
                    $"_rels/.rels is not well-formed XML (line {ex.LineNumber}, column {ex.LinePosition}): {ex.Message}");
            }
            officeDocumentTarget = relationships
                .FirstOrDefault(r => r.Type.EndsWith(OfficeDocumentRelationshipSuffix, StringComparison.Ordinal))
                ?.Target;
        }

        var parts = new List<OoxmlPartInfo>();
        foreach (var entry in zip.Archive.Entries)
        {
            if (entry.IsDirectory)
            {
                continue;
            }
            string? contentType = ResolveContentType(entry.Name, defaults, overrides);
            bool isMacro =
                string.Equals(contentType, VbaProjectContentType, StringComparison.OrdinalIgnoreCase) ||
                entry.Name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase);
            if (entry.IsEncrypted)
            {
                // Present-but-unreadable must be visible at package level too: an encrypted
                // part is content the scan cannot see.
                reasons.Add($"part '{entry.Name}' is encrypted; content unreadable");
            }
            parts.Add(new OoxmlPartInfo
            {
                Name = entry.Name,
                CompressedSize = entry.CompressedSize,
                UncompressedSize = entry.UncompressedSize,
                ContentType = contentType,
                IsMacroPart = isMacro,
                IsEncrypted = entry.IsEncrypted,
            });
        }

        var package = new OoxmlPackageInfo
        {
            Zip = zip.Archive,
            ContentTypeDefaults = defaults,
            ContentTypeOverrides = overrides,
            Relationships = relationships,
            Parts = parts,
            PackageAnomalies = anomalies,
            OfficeDocumentTarget = officeDocumentTarget,
        };
        return OoxmlReadResult.From(reasons, package);
    }

    /// <summary>Reads one part's bytes by name (ordinal first, then case-insensitive, since OPC names are case-insensitive).</summary>
    public static ZipEntryDataResult ReadPart(byte[] data, OoxmlPackageInfo package, string partName, ScanBudget budget, ExpansionGuard? guard = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(partName);
        ArgumentNullException.ThrowIfNull(budget);

        ZipEntryInfo? entry = FindEntry(package.Zip, partName);
        if (entry is null)
        {
            return ZipEntryDataResult.NotRead(OperationState.Failed, $"package has no part named '{partName}'");
        }
        return ZipReader.ReadEntry(data, entry, budget, guard);
    }

    private static ZipEntryInfo? FindEntry(ZipArchiveInfo archive, string name)
    {
        foreach (var entry in archive.Entries)
        {
            if (string.Equals(entry.Name, name, StringComparison.Ordinal))
            {
                return entry;
            }
        }
        foreach (var entry in archive.Entries)
        {
            if (string.Equals(entry.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return entry;
            }
        }
        return null;
    }

    private static (OoxmlReadResult? Result, byte[]? Bytes) ReadMetadataPart(
        byte[] data,
        ZipEntryInfo entry,
        ScanBudget budget,
        ExpansionGuard guard)
    {
        if (entry.UncompressedSize > ContainerLimits.MaxOoxmlXmlBytes)
        {
            return (OoxmlReadResult.IncompleteWithoutPackage(
                $"metadata part '{entry.Name}' declares {entry.UncompressedSize} bytes, over the {ContainerLimits.MaxOoxmlXmlBytes}-byte XML cap"), null);
        }
        var read = ZipReader.ReadEntry(data, entry, budget, guard);
        if (read.State != OperationState.Ok || read.Bytes is null)
        {
            return (new OoxmlReadResult(
                read.State,
                $"metadata part '{entry.Name}' unreadable: {read.Reason}",
                read.State == OperationState.Incomplete
                    ? new[] { $"metadata part '{entry.Name}' unreadable: {read.Reason}" }
                    : Array.Empty<string>(),
                null), null);
        }
        if (read.Bytes.LongLength > ContainerLimits.MaxOoxmlXmlBytes)
        {
            return (OoxmlReadResult.IncompleteWithoutPackage(
                $"metadata part '{entry.Name}' expanded to {read.Bytes.LongLength} bytes, over the {ContainerLimits.MaxOoxmlXmlBytes}-byte XML cap"), null);
        }
        return (null, read.Bytes);
    }

    /// <summary>Hardened settings for attacker-authored XML: no DTDs, no resolver, bounded characters.</summary>
    private static XmlReaderSettings SafeXmlSettings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = ContainerLimits.MaxOoxmlXmlCharacters,
        MaxCharactersFromEntities = 0,
        IgnoreProcessingInstructions = true,
    };

    private static (Dictionary<string, string> Defaults, Dictionary<string, string> Overrides) ParseContentTypes(byte[] xml)
    {
        var defaults = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var stream = new MemoryStream(xml, writable: false);
        using var reader = XmlReader.Create(stream, SafeXmlSettings());
        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element)
            {
                continue;
            }
            if (reader.LocalName == "Default")
            {
                string? ext = reader.GetAttribute("Extension");
                string? type = reader.GetAttribute("ContentType");
                if (ext is not null && type is not null)
                {
                    defaults[ext.ToLowerInvariant()] = type;
                }
            }
            else if (reader.LocalName == "Override")
            {
                string? part = reader.GetAttribute("PartName");
                string? type = reader.GetAttribute("ContentType");
                if (part is not null && type is not null)
                {
                    overrides[part] = type;
                }
            }
        }
        return (defaults, overrides);
    }

    private static List<OoxmlRelationship> ParseRelationships(byte[] xml)
    {
        var relationships = new List<OoxmlRelationship>();
        using var stream = new MemoryStream(xml, writable: false);
        using var reader = XmlReader.Create(stream, SafeXmlSettings());
        while (reader.Read() && relationships.Count < ContainerLimits.MaxRelationships)
        {
            if (reader.NodeType != XmlNodeType.Element || reader.LocalName != "Relationship")
            {
                continue;
            }
            relationships.Add(new OoxmlRelationship(
                reader.GetAttribute("Id") ?? string.Empty,
                reader.GetAttribute("Type") ?? string.Empty,
                reader.GetAttribute("Target") ?? string.Empty));
        }
        return relationships;
    }

    /// <summary>Override by part name (spelled with a leading slash in the XML) wins over the extension default.</summary>
    private static string? ResolveContentType(
        string entryName,
        Dictionary<string, string> defaults,
        Dictionary<string, string> overrides)
    {
        if (overrides.TryGetValue("/" + entryName, out string? overridden))
        {
            return overridden;
        }
        int dot = entryName.LastIndexOf('.');
        if (dot >= 0 && dot < entryName.Length - 1 &&
            defaults.TryGetValue(entryName[(dot + 1)..], out string? byExtension))
        {
            return byExtension;
        }
        return null;
    }
}
