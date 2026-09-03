using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>The access mask: high half named always, low half only under a kind.</summary>
public sealed class AccessMaskTests
{
    private const uint Trio = 0x0002_0022; // read control + bits 0x0002 and 0x0020

    [Fact]
    public void TheMaskTrio_FileKindNamesWriteDataAndExecute()
    {
        var decoded = AccessMaskDecoder.Decode(Trio, ObjectKind.File);

        Assert.Equal(new[] { "Read control" }, decoded.GenericAndStandardRights);
        Assert.Equal(new[] { "Write data", "Execute" }, decoded.SpecificRights);
        Assert.Equal(0x0022, decoded.SpecificRaw);
        Assert.Equal(0u, decoded.UnnamedBits);
    }

    [Fact]
    public void TheMaskTrio_RegistryKindNamesSetValueAndCreateLink()
    {
        var decoded = AccessMaskDecoder.Decode(Trio, ObjectKind.RegistryKey);

        Assert.Equal(new[] { "Set value", "Create link" }, decoded.SpecificRights);
    }

    [Fact]
    public void TheMaskTrio_NoKindNamesOnlyTheGenericAndStandardBits()
    {
        // Revert: default to the file table when no kind is given, and this invents "Write data".
        var decoded = AccessMaskDecoder.Decode(Trio, null);

        Assert.Null(decoded.Kind);
        Assert.Equal(new[] { "Read control" }, decoded.GenericAndStandardRights);
        Assert.Null(decoded.SpecificRights);
        Assert.Equal(0x0022, decoded.SpecificRaw);
        Assert.Equal(0u, decoded.UnnamedBits);
    }

    [Fact]
    public void TheMaskTrio_ThreeResultsDiffer()
    {
        var file = AccessMaskDecoder.Decode(Trio, ObjectKind.File);
        var registry = AccessMaskDecoder.Decode(Trio, ObjectKind.RegistryKey);
        var none = AccessMaskDecoder.Decode(Trio, null);

        Assert.NotEqual(file.SpecificRights, registry.SpecificRights);
        Assert.NotNull(file.SpecificRights);
        Assert.NotNull(registry.SpecificRights);
        Assert.Null(none.SpecificRights);
        Assert.Equal(file.Raw, registry.Raw);
        Assert.Equal(file.Raw, none.Raw);
    }

    [Theory]
    [InlineData(0x0001_0000u, "Delete")]
    [InlineData(0x0002_0000u, "Read control")]
    [InlineData(0x0004_0000u, "Write discretionary list")]
    [InlineData(0x0008_0000u, "Write owner")]
    [InlineData(0x0010_0000u, "Synchronize")]
    [InlineData(0x0100_0000u, "Access system security")]
    [InlineData(0x0200_0000u, "Maximum allowed")]
    [InlineData(0x1000_0000u, "Generic all")]
    [InlineData(0x2000_0000u, "Generic execute")]
    [InlineData(0x4000_0000u, "Generic write")]
    [InlineData(0x8000_0000u, "Generic read")]
    public void EveryHighBitIsNamedWithoutAKind(uint bit, string name)
    {
        var decoded = AccessMaskDecoder.Decode(bit, null);

        Assert.Equal(new[] { name }, decoded.GenericAndStandardRights);
        Assert.Equal(0u, decoded.UnnamedBits);
    }

    [Theory]
    [InlineData(0x0020_0000u)]
    [InlineData(0x0040_0000u)]
    [InlineData(0x0080_0000u)]
    [InlineData(0x0400_0000u)]
    [InlineData(0x0800_0000u)]
    public void AReservedHighBitIsReportedUnnamed(uint bit)
    {
        var decoded = AccessMaskDecoder.Decode(bit, ObjectKind.File);

        Assert.Empty(decoded.GenericAndStandardRights);
        Assert.Equal(bit, decoded.UnnamedBits);
    }

    [Fact]
    public void ALowBitTheKindsTableDoesNotNameIsUnnamedUnderThatKindOnly()
    {
        // 0x0040 is "Delete child" on a file and nothing on a registry key.
        Assert.Equal(new[] { "Delete child" }, AccessMaskDecoder.Decode(0x0040, ObjectKind.File).SpecificRights);
        var registry = AccessMaskDecoder.Decode(0x0040, ObjectKind.RegistryKey);
        Assert.Empty(registry.SpecificRights!);
        Assert.Equal(0x0040u, registry.UnnamedBits);
    }

    [Fact]
    public void WithoutAKindTheLowHalfIsNeitherNamedNorCountedAsUnnamed()
    {
        var decoded = AccessMaskDecoder.Decode(0x0000_FFFF, null);

        Assert.Equal(0xFFFF, decoded.SpecificRaw);
        Assert.Null(decoded.SpecificRights);
        Assert.Equal(0u, decoded.UnnamedBits);
    }

    [Fact]
    public void FileAndDirectoryAreDifferentKindsWithDifferentNamesForTheSameBits()
    {
        Assert.Equal(new[] { "Read data", "Write data", "Append data", "Execute" }, AccessMaskDecoder.Decode(0x0027, ObjectKind.File).SpecificRights);
        Assert.Equal(new[] { "List contents", "Add file", "Add subdirectory", "Traverse" }, AccessMaskDecoder.Decode(0x0027, ObjectKind.Directory).SpecificRights);
    }

    [Theory]
    [InlineData(ObjectKind.RegistryKey, 0x0300u, "Force 64-bit view", "Force 32-bit view")]
    [InlineData(ObjectKind.Service, 0x0181u, "Query configuration", "Interrogate", "User-defined control")]
    [InlineData(ObjectKind.Process, 0x1C00u, "Query information", "Suspend and resume", "Query limited information")]
    [InlineData(ObjectKind.File, 0x0180u, "Read attributes", "Write attributes")]
    public void SpotCheckedKindTablesCarryTheReferenceNames(ObjectKind kind, uint mask, params string[] names)
    {
        Assert.Equal(names, AccessMaskDecoder.Decode(mask, kind).SpecificRights);
    }

    [Fact]
    public void NamesAreOrderedByBitRegardlessOfKind()
    {
        var decoded = AccessMaskDecoder.Decode(0xC001_0003, ObjectKind.Process);

        Assert.Equal(new[] { "Delete", "Generic write", "Generic read" }, decoded.GenericAndStandardRights);
        Assert.Equal(new[] { "Terminate", "Create thread" }, decoded.SpecificRights);
    }

    [Fact]
    public void AZeroMaskNamesNothing()
    {
        var decoded = AccessMaskDecoder.Decode(0, ObjectKind.File);

        Assert.Empty(decoded.GenericAndStandardRights);
        Assert.Empty(decoded.SpecificRights!);
        Assert.Equal(0u, decoded.UnnamedBits);
        Assert.Equal(0, decoded.SpecificRaw);
    }

    [Fact]
    public void FullControlUnderTheFileKindNamesEveryFileBit()
    {
        var decoded = AccessMaskDecoder.Decode(0x001F_01FF, ObjectKind.File);

        Assert.Equal(5, decoded.GenericAndStandardRights.Count);
        Assert.Equal(9, decoded.SpecificRights!.Count);
        Assert.Equal(0u, decoded.UnnamedBits);
    }
}
