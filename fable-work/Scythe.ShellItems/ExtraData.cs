namespace Scythe.ShellItems;

public static class ExtraDataSignature
{
    public const uint EnvironmentVariable = 0xA0000001;
    public const uint Console = 0xA0000002;
    public const uint Tracker = 0xA0000003;
    public const uint ConsoleCodePage = 0xA0000004;
    public const uint SpecialFolder = 0xA0000005;
    public const uint Darwin = 0xA0000006;
    public const uint IconEnvironment = 0xA0000007;
    public const uint ShimLayer = 0xA0000008;
    public const uint PropertyStore = 0xA0000009;
    public const uint KnownFolder = 0xA000000B;
    public const uint VistaAndAboveIdList = 0xA000000C;
}

/// <summary>One ExtraData block. <see cref="RawBytes"/> is the whole block including its size and signature.</summary>
public abstract record ExtraDataBlock(uint Size, uint Signature, byte[] RawBytes);

/// <summary>
/// The environment-variable (<c>0xA0000001</c>) and icon-environment (<c>0xA0000007</c>) blocks share
/// one layout: 260 code-page bytes then 520 UTF-16 bytes, each null-terminated inside its fixed extent.
/// </summary>
public sealed record EnvironmentStringsBlock(
    uint Size,
    uint Signature,
    byte[] RawBytes,
    LinkString AnsiTarget,
    LinkString UnicodeTarget) : ExtraDataBlock(Size, Signature, RawBytes)
{
    /// <summary>The Unicode copy; it is the one the shell uses when both are present.</summary>
    public string Target => UnicodeTarget.Value;

    /// <summary>True when the Latin-1 reading of the ANSI copy differs from the Unicode copy, ordinally.</summary>
    public bool AnsiAndUnicodeDisagree => !string.Equals(AnsiTarget.Value, UnicodeTarget.Value, StringComparison.Ordinal);
}

public sealed record KnownFolderBlock(
    uint Size,
    uint Signature,
    byte[] RawBytes,
    Guid KnownFolderId,
    uint Offset) : ExtraDataBlock(Size, Signature, RawBytes);

public sealed record SpecialFolderBlock(
    uint Size,
    uint Signature,
    byte[] RawBytes,
    uint SpecialFolderId,
    uint Offset) : ExtraDataBlock(Size, Signature, RawBytes);

/// <summary>The tracker block. The droid identifiers embed machine-identifying data; the caller decides what reaches a report.</summary>
public sealed record TrackerBlock(
    uint Size,
    uint Signature,
    byte[] RawBytes,
    uint Length,
    uint Version,
    LinkString MachineId,
    Guid DroidVolume,
    Guid DroidFile,
    Guid DroidBirthVolume,
    Guid DroidBirthFile) : ExtraDataBlock(Size, Signature, RawBytes);

public sealed record VistaIdListBlock(
    uint Size,
    uint Signature,
    byte[] RawBytes,
    LinkTargetIdList IdList) : ExtraDataBlock(Size, Signature, RawBytes);

/// <summary>
/// A block kept as <c>(signature, bytes)</c>: either a signature this reader does not decode, or a
/// known signature whose size did not match its documented layout — <see cref="Note"/> says which.
/// </summary>
public sealed record RawExtraDataBlock(
    uint Size,
    uint Signature,
    byte[] RawBytes,
    string? Note) : ExtraDataBlock(Size, Signature, RawBytes);
