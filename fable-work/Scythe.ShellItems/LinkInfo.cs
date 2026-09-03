namespace Scythe.ShellItems;

public enum DriveType
{
    Unknown = 0,
    NoRootDirectory = 1,
    Removable = 2,
    Fixed = 3,
    Remote = 4,
    CdRom = 5,
    RamDisk = 6,
}

/// <summary>The VolumeID structure inside LinkInfo.</summary>
public sealed record VolumeId(
    uint Size,
    uint DriveTypeValue,
    uint SerialNumber,
    uint LabelOffset,
    uint? UnicodeLabelOffset,
    LinkString? Label,
    LinkString? UnicodeLabel)
{
    /// <summary>The documented drive type, or <see cref="ShellItems.DriveType.Unknown"/> for a value above 6 (check <see cref="DriveTypeValue"/>).</summary>
    public DriveType DriveType => DriveTypeValue <= 6 ? (DriveType)DriveTypeValue : DriveType.Unknown;
}

/// <summary>The CommonNetworkRelativeLink structure inside LinkInfo.</summary>
public sealed record CommonNetworkRelativeLink(
    uint Size,
    uint Flags,
    uint NetNameOffset,
    uint DeviceNameOffset,
    uint NetworkProviderTypeValue,
    LinkString? NetName,
    LinkString? DeviceName,
    LinkString? NetNameUnicode,
    LinkString? DeviceNameUnicode)
{
    public const uint ValidDeviceFlag = 0x1;
    public const uint ValidNetTypeFlag = 0x2;

    /// <summary>Non-null only when the ValidNetType flag says the field is meaningful.</summary>
    public uint? NetworkProviderType => (Flags & ValidNetTypeFlag) != 0 ? NetworkProviderTypeValue : null;
}

/// <summary>The LinkInfo section. Offsets are as stored, relative to the start of LinkInfo.</summary>
public sealed record LinkInfo(
    uint Size,
    uint HeaderSize,
    uint Flags,
    VolumeId? VolumeId,
    LinkString? LocalBasePath,
    CommonNetworkRelativeLink? NetworkRelativeLink,
    LinkString? CommonPathSuffix,
    LinkString? LocalBasePathUnicode,
    LinkString? CommonPathSuffixUnicode,
    string? LocalPath,
    string? NetworkPath)
{
    public const uint VolumeIdAndLocalBasePathFlag = 0x1;
    public const uint CommonNetworkRelativeLinkAndPathSuffixFlag = 0x2;

    /// <summary>True when the header size admits the two Unicode offset fields (≥ 0x24).</summary>
    public bool HasUnicodeOffsets => HeaderSize >= 0x24;
}
