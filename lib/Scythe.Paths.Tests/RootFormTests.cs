using Xunit;

namespace Scythe.Paths.Tests;

/// <summary>
/// Every root syntax Windows accepts: drive-absolute, drive-relative, root-relative, plain and
/// extended UNC, the \\?\ and \\.\ device prefixes, and GLOBALROOT. The critical property is
/// that different spellings of the same location land in the same comparison space with the
/// same canonical root.
/// </summary>
public sealed class RootFormTests
{
    private static NormalizedPath Ok(string path)
    {
        NormalizedPath result = PathNormalizer.Normalize(path);
        Assert.Equal(OperationState.Ok, result.State);
        return result;
    }

    // ------------------------------------------------------------------ drive forms

    [Fact]
    public void DriveAbsolute()
    {
        NormalizedPath p = Ok(@"C:\Windows");
        Assert.Equal(PathKind.DriveAbsolute, p.Kind);
        Assert.Equal(PathRootSpace.Drive, p.RootSpace);
        Assert.Equal(@"c:\", p.Root);
    }

    [Fact]
    public void BareDriveRoot()
    {
        NormalizedPath p = Ok(@"C:\");
        Assert.Equal(@"c:\", p.Canonical);
        Assert.Empty(p.Segments);
    }

    [Fact]
    public void DriveRelative_IsItsOwnKind_NotDriveAbsolute()
    {
        // "C:foo" means foo under C:'s current directory — an unknowable location. Conflating
        // it with C:\foo would let it slide past a guard on C:\.
        NormalizedPath p = Ok(@"C:foo\bar");
        Assert.Equal(PathKind.DriveRelative, p.Kind);
        Assert.Equal(PathRootSpace.DriveCurrentDirectory, p.RootSpace);
        Assert.Equal("c:", p.Root);
        Assert.Equal(@"c:foo\bar", p.Canonical);
    }

    [Fact]
    public void BareDriveRelative()
    {
        NormalizedPath p = Ok("C:");
        Assert.Equal(PathKind.DriveRelative, p.Kind);
        Assert.Equal("c:", p.Canonical);
        Assert.Empty(p.Segments);
    }

    [Fact]
    public void DriveRelative_KeepsLeadingParentSegments()
    {
        Assert.Equal(@"c:..", Ok(@"C:foo\..\..").Canonical);
    }

    [Fact]
    public void RootRelative_IsCurrentDriveSpace()
    {
        NormalizedPath p = Ok(@"\Windows\System32");
        Assert.Equal(PathKind.RootRelative, p.Kind);
        Assert.Equal(PathRootSpace.CurrentDrive, p.RootSpace);
        Assert.Equal(@"\", p.Root);
        Assert.Equal(@"\windows\system32", p.Canonical);
    }

    [Fact]
    public void Relative_HasEmptyRoot()
    {
        NormalizedPath p = Ok(@"foo\bar");
        Assert.Equal(PathKind.Relative, p.Kind);
        Assert.Equal(PathRootSpace.Relative, p.RootSpace);
        Assert.Equal("", p.Root);
        Assert.Equal(@"foo\bar", p.Canonical);
    }

    // ------------------------------------------------------------------ UNC

    [Fact]
    public void PlainUnc()
    {
        NormalizedPath p = Ok(@"\\Server\Share\Dir\file.txt");
        Assert.Equal(PathKind.Unc, p.Kind);
        Assert.Equal(PathRootSpace.Unc, p.RootSpace);
        Assert.Equal(@"\\server\share", p.Root);
        Assert.Equal(@"\\server\share\dir\file.txt", p.Canonical);
        Assert.Equal(new[] { "dir", "file.txt" }, p.Segments);
    }

    [Fact]
    public void BareUncShareRoot()
    {
        NormalizedPath p = Ok(@"\\server\share");
        Assert.Equal(@"\\server\share", p.Canonical);
        Assert.Empty(p.Segments);
    }

    [Fact]
    public void UncShareRoot_WithTrailingSeparator_RecordsItsRemoval()
    {
        NormalizedPath p = Ok(@"\\server\share\");
        Assert.Equal(@"\\server\share", p.Canonical);
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.TrailingSeparatorRemoved);
    }

    [Fact]
    public void Unc_ServerAndShare_AreCaseFoldedForComparison()
    {
        Assert.Equal(Ok(@"\\SRV\SHARE\x").Canonical, Ok(@"\\srv\share\X").Canonical);
    }

    [Fact]
    public void Unc_LoopbackServer_IsFlagged()
    {
        Assert.True(Ok(@"\\localhost\share\x").Flags.HasFlag(PathFlags.LoopbackUncServer));
        Assert.True(Ok(@"\\127.0.0.1\share\x").Flags.HasFlag(PathFlags.LoopbackUncServer));
        Assert.False(Ok(@"\\fileserver\share\x").Flags.HasFlag(PathFlags.LoopbackUncServer));
    }

    [Fact]
    public void Unc_AdministrativeShare_IsFlagged()
    {
        Assert.True(Ok(@"\\srv\C$\Windows").Flags.HasFlag(PathFlags.AdministrativeShare));
        Assert.True(Ok(@"\\srv\ADMIN$").Flags.HasFlag(PathFlags.AdministrativeShare));
        Assert.False(Ok(@"\\srv\data$x\y").Flags.HasFlag(PathFlags.AdministrativeShare));
        Assert.False(Ok(@"\\srv\share").Flags.HasFlag(PathFlags.AdministrativeShare));
    }

    // ------------------------------------------------------------------ \\?\ and \\.\ prefixes

    [Fact]
    public void VerbatimDrivePath_LandsInDriveSpace_AndIsFlagged()
    {
        NormalizedPath p = Ok(@"\\?\C:\Windows\System32");
        Assert.Equal(PathKind.Extended, p.Kind);
        Assert.Equal(PathRootSpace.Drive, p.RootSpace);
        Assert.Equal(@"c:\windows\system32", p.Canonical);
        Assert.True(p.Flags.HasFlag(PathFlags.VerbatimPrefix));
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.PrefixNormalized);
    }

    [Fact]
    public void VerbatimAndPlain_SameLocation_SameCanonical()
    {
        Assert.Equal(Ok(@"C:\Windows").Canonical, Ok(@"\\?\C:\Windows").Canonical);
    }

    [Fact]
    public void ForwardSlashSpelledPrefix_IsNotVerbatim()
    {
        // Real Windows only skips normalisation for a literal backslash \\?\ prefix; //?/ is an
        // ordinary device path. The flag must report what the caller actually wrote.
        NormalizedPath p = Ok("//?/C:/Windows");
        Assert.Equal(PathKind.Extended, p.Kind);
        Assert.Equal(@"c:\windows", p.Canonical);
        Assert.False(p.Flags.HasFlag(PathFlags.VerbatimPrefix));
    }

    [Fact]
    public void DeviceDotDrivePath_LandsInDriveSpace()
    {
        NormalizedPath p = Ok(@"\\.\C:\Windows");
        Assert.Equal(PathKind.Device, p.Kind);
        Assert.Equal(PathRootSpace.Drive, p.RootSpace);
        Assert.Equal(@"c:\windows", p.Canonical);
        Assert.False(p.Flags.HasFlag(PathFlags.VerbatimPrefix));
    }

    [Fact]
    public void DeviceName_LandsInDeviceSpace()
    {
        NormalizedPath p = Ok(@"\\.\PhysicalDrive0");
        Assert.Equal(PathKind.Device, p.Kind);
        Assert.Equal(PathRootSpace.Device, p.RootSpace);
        Assert.Equal(@"\\.\physicaldrive0", p.Root);
        Assert.Equal(@"\\.\physicaldrive0", p.Canonical);
        Assert.Empty(p.Segments);
    }

    [Fact]
    public void VerbatimVolumePath_IsDeviceSpace_WithDotCanonicalRoot()
    {
        NormalizedPath p = Ok(@"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\x");
        Assert.Equal(PathRootSpace.Device, p.RootSpace);
        Assert.Equal(@"\\.\volume{01234567-89ab-cdef-0123-456789abcdef}", p.Root);
        Assert.True(p.Flags.HasFlag(PathFlags.VerbatimPrefix));
    }

    [Fact]
    public void ExtendedUnc_LandsInUncSpace()
    {
        NormalizedPath p = Ok(@"\\?\UNC\Server\Share\Dir\x");
        Assert.Equal(PathKind.ExtendedUnc, p.Kind);
        Assert.Equal(PathRootSpace.Unc, p.RootSpace);
        Assert.Equal(@"\\server\share", p.Root);
        Assert.Equal(@"\\server\share\dir\x", p.Canonical);
        Assert.True(p.Flags.HasFlag(PathFlags.VerbatimPrefix));
    }

    [Fact]
    public void DeviceDotUnc_IsAlsoExtendedUnc()
    {
        NormalizedPath p = Ok(@"\\.\UNC\srv\share\x");
        Assert.Equal(PathKind.ExtendedUnc, p.Kind);
        Assert.Equal(@"\\srv\share\x", p.Canonical);
        Assert.False(p.Flags.HasFlag(PathFlags.VerbatimPrefix));
    }

    [Fact]
    public void ExtendedUnc_AndPlainUnc_SameCanonical()
    {
        Assert.Equal(Ok(@"\\srv\share\x").Canonical, Ok(@"\\?\UNC\SRV\Share\x").Canonical);
    }

    [Fact]
    public void GlobalRoot_IsItsOwnSpace()
    {
        NormalizedPath p = Ok(@"\\?\GLOBALROOT\Device\HarddiskVolume1\Windows");
        Assert.Equal(PathKind.GlobalRoot, p.Kind);
        Assert.Equal(PathRootSpace.GlobalRoot, p.RootSpace);
        Assert.Equal(@"\\.\globalroot", p.Root);
        Assert.Equal(@"\\.\globalroot\device\harddiskvolume1\windows", p.Canonical);
        Assert.Equal(new[] { "device", "harddiskvolume1", "windows" }, p.Segments);
    }

    [Fact]
    public void GlobalRoot_ViaDeviceDotPrefix()
    {
        NormalizedPath p = Ok(@"\\.\GLOBALROOT\Device\X");
        Assert.Equal(PathKind.GlobalRoot, p.Kind);
        Assert.Equal(@"\\.\globalroot\device\x", p.Canonical);
    }

    [Fact]
    public void VerbatimBareDrive_IsTheDriveRoot()
    {
        NormalizedPath p = Ok(@"\\?\C:");
        Assert.Equal(@"c:\", p.Canonical);
        Assert.Equal(PathRootSpace.Drive, p.RootSpace);
    }

    [Fact]
    public void DriveLetter_IsCaseFolded_InRoot()
    {
        Assert.Equal(Ok(@"c:\x").Root, Ok(@"C:\x").Root);
    }
}
