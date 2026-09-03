namespace Scythe.ShellItems;

/// <summary>The LinkFlags field of the header (reference/04.3_shell_links.md). Undefined bits are preserved.</summary>
[Flags]
public enum LinkFlags : uint
{
    None = 0,
    HasLinkTargetIdList = 0x00000001,
    HasLinkInfo = 0x00000002,
    HasName = 0x00000004,
    HasRelativePath = 0x00000008,
    HasWorkingDir = 0x00000010,
    HasArguments = 0x00000020,
    HasIconLocation = 0x00000040,
    IsUnicode = 0x00000080,
    ForceNoLinkInfo = 0x00000100,
    HasExpString = 0x00000200,
    RunInSeparateProcess = 0x00000400,
    HasDarwinId = 0x00001000,
    RunAsUser = 0x00002000,
    HasExpIcon = 0x00004000,
    NoPidlAlias = 0x00008000,
    RunWithShimLayer = 0x00020000,
    ForceNoLinkTrack = 0x00040000,
    EnableTargetMetadata = 0x00080000,
    DisableLinkPathTracking = 0x00100000,
    DisableKnownFolderTracking = 0x00200000,
    DisableKnownFolderAlias = 0x00400000,
    AllowLinkToLink = 0x00800000,
    UnaliasOnSave = 0x01000000,
    PreferEnvironmentPath = 0x02000000,
    KeepLocalIdListForUncTarget = 0x04000000,
}
