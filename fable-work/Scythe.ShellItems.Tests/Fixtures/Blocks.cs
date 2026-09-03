using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests.Fixtures;

/// <summary>ExtraData block builders (reference/04.3 "ExtraData").</summary>
internal static class Blocks
{
    internal static readonly Guid DroidVolume = new("11111111-2222-3333-4444-555555555555");
    internal static readonly Guid DroidFile = new("66666666-7777-8888-9999-AAAAAAAAAAAA");
    internal static readonly Guid BirthVolume = new("BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF");
    internal static readonly Guid BirthFile = new("01234567-89AB-CDEF-0123-456789ABCDEF");
    internal static readonly Guid DocumentsFolder = new("FDD39AD0-238F-46AF-ADB4-6C85480369C7");

    internal static byte[] Block(uint signature, byte[] payload) =>
        Concat(U32((uint)(payload.Length + 8)), U32(signature), payload);

    /// <summary>A block whose size field says whatever the test needs.</summary>
    internal static byte[] WithSize(uint size, uint signature, byte[] payload) =>
        Concat(U32(size), U32(signature), payload);

    internal static byte[] Terminal => U32(0);

    internal static byte[] Environment(string ansi, string unicode, uint signature = ExtraDataSignature.EnvironmentVariable) =>
        Block(signature, Concat(Fixed(Latin1(ansi), 260), Fixed(Utf16(unicode), 520)));

    internal static byte[] IconEnvironment(string ansi, string unicode) =>
        Environment(ansi, unicode, ExtraDataSignature.IconEnvironment);

    internal static byte[] KnownFolder(Guid folderId, uint offset) =>
        Block(ExtraDataSignature.KnownFolder, Concat(Guid(folderId), U32(offset)));

    internal static byte[] SpecialFolder(uint folderId, uint offset) =>
        Block(ExtraDataSignature.SpecialFolder, Concat(U32(folderId), U32(offset)));

    internal static byte[] Tracker(string machineId = "workstation7") =>
        Block(ExtraDataSignature.Tracker, Concat(
            U32(0x58),
            U32(0),
            Fixed(Latin1(machineId), 16),
            Guid(DroidVolume),
            Guid(DroidFile),
            Guid(BirthVolume),
            Guid(BirthFile)));

    internal static byte[] Vista(params byte[][] items) =>
        Block(ExtraDataSignature.VistaAndAboveIdList, Concat(Concat(items), U16(0)));

    internal static byte[] Raw(uint signature, byte[] payload) => Block(signature, payload);
}
