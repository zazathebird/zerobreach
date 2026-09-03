using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests.Fixtures;

/// <summary>Builds a LinkInfo structure with consistent offsets; tests mutate the bytes afterwards to lie.</summary>
internal sealed class LinkInfoFixture
{
    public uint HeaderSize { get; init; } = 0x1C;

    public bool Local { get; init; } = true;

    public uint DriveType { get; init; } = 3;

    public uint SerialNumber { get; init; } = 0xDEADBEEF;

    public string Label { get; init; } = "OS";

    /// <summary>Use the 0x14 sentinel: the ANSI label is empty and a Unicode label follows.</summary>
    public bool UnicodeLabelSentinel { get; init; }

    public string? UnicodeLabel { get; init; }

    public string LocalBasePath { get; init; } = "C:\\Users\\readme.txt";

    public string Suffix { get; init; } = string.Empty;

    public string? LocalBasePathUnicode { get; init; }

    public string? SuffixUnicode { get; init; }

    public bool Network { get; init; }

    public string NetName { get; init; } = "\\\\server\\share";

    public string? DeviceName { get; init; }

    public uint? ProviderType { get; init; }

    public string? NetNameUnicode { get; init; }

    public string? DeviceNameUnicode { get; init; }

    /// <summary>Offsets (from the LinkInfo start) of the pieces, filled in by <see cref="Build"/>.</summary>
    public uint VolumeIdOffset { get; private set; }

    public uint LocalBasePathOffset { get; private set; }

    public uint NetworkLinkOffset { get; private set; }

    public uint SuffixOffset { get; private set; }

    public uint Size { get; private set; }

    public byte[] Build()
    {
        var unicodeHeader = HeaderSize >= 0x24;
        var body = new List<byte[]>();
        var cursor = HeaderSize;
        uint volumeOffset = 0, basePathOffset = 0, networkOffset = 0, basePathUnicodeOffset = 0, suffixUnicodeOffset = 0;

        if (Local)
        {
            volumeOffset = cursor;
            var volume = BuildVolume();
            body.Add(volume);
            cursor += (uint)volume.Length;

            basePathOffset = cursor;
            var basePath = Latin1Z(LocalBasePath);
            body.Add(basePath);
            cursor += (uint)basePath.Length;
        }

        if (Network)
        {
            networkOffset = cursor;
            var network = BuildNetworkLink();
            body.Add(network);
            cursor += (uint)network.Length;
        }

        var suffixOffset = cursor;
        var suffix = Latin1Z(Suffix);
        body.Add(suffix);
        cursor += (uint)suffix.Length;

        if (unicodeHeader)
        {
            if (Local)
            {
                basePathUnicodeOffset = cursor;
                var u = Utf16Z(LocalBasePathUnicode ?? LocalBasePath);
                body.Add(u);
                cursor += (uint)u.Length;
            }

            suffixUnicodeOffset = cursor;
            var su = Utf16Z(SuffixUnicode ?? Suffix);
            body.Add(su);
            cursor += (uint)su.Length;
        }

        var flags = (Local ? 1u : 0u) | (Network ? 2u : 0u);
        var header = Concat(U32(cursor), U32(HeaderSize), U32(flags), U32(volumeOffset), U32(basePathOffset), U32(networkOffset), U32(suffixOffset));
        if (unicodeHeader)
        {
            header = Concat(header, U32(basePathUnicodeOffset), U32(suffixUnicodeOffset), new byte[HeaderSize - 0x24]);
        }

        VolumeIdOffset = volumeOffset;
        LocalBasePathOffset = basePathOffset;
        NetworkLinkOffset = networkOffset;
        SuffixOffset = suffixOffset;
        Size = cursor;
        return Concat(header, Concat(body.ToArray()));
    }

    private byte[] BuildVolume()
    {
        if (UnicodeLabelSentinel)
        {
            var label = Utf16Z(UnicodeLabel ?? Label);
            return Concat(U32((uint)(20 + label.Length)), U32(DriveType), U32(SerialNumber), U32(0x14), U32(0x14), label);
        }

        var ansi = Latin1Z(Label);
        return Concat(U32((uint)(16 + ansi.Length)), U32(DriveType), U32(SerialNumber), U32(0x10), ansi);
    }

    private byte[] BuildNetworkLink()
    {
        var unicode = NetNameUnicode is not null;
        var flags = (DeviceName is not null ? 1u : 0u) | (ProviderType is not null ? 2u : 0u);
        var headerLength = unicode ? 0x1Cu : 0x14u;

        var netNameOffset = headerLength;
        var netName = Latin1Z(NetName);
        var cursor = netNameOffset + (uint)netName.Length;

        uint deviceOffset = 0;
        var device = Array.Empty<byte>();
        if (DeviceName is not null)
        {
            deviceOffset = cursor;
            device = Latin1Z(DeviceName);
            cursor += (uint)device.Length;
        }

        uint netUnicodeOffset = 0, deviceUnicodeOffset = 0;
        var netUnicode = Array.Empty<byte>();
        var deviceUnicode = Array.Empty<byte>();
        if (unicode)
        {
            netUnicodeOffset = cursor;
            netUnicode = Utf16Z(NetNameUnicode!);
            cursor += (uint)netUnicode.Length;
            if (DeviceNameUnicode is not null)
            {
                deviceUnicodeOffset = cursor;
                deviceUnicode = Utf16Z(DeviceNameUnicode);
                cursor += (uint)deviceUnicode.Length;
            }
        }

        var header = Concat(U32(cursor), U32(flags), U32(netNameOffset), U32(deviceOffset), U32(ProviderType ?? 0));
        if (unicode)
        {
            header = Concat(header, U32(netUnicodeOffset), U32(deviceUnicodeOffset));
        }

        return Concat(header, netName, device, netUnicode, deviceUnicode);
    }
}
