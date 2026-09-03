namespace Scythe.ShellItems;

public static partial class ShellLinkReader
{
    private const uint LinkInfoMinimumHeaderSize = 0x1C;
    private const uint LinkInfoUnicodeHeaderSize = 0x24;
    private const uint VolumeIdUnicodeLabelSentinel = 0x14;

    private static Problem? ParseLinkInfo(ByteReader file, ref long offset, Accumulator acc)
    {
        var start = offset;
        if (!file.TryU32(start, out var size))
        {
            return Problem.Incomplete($"truncated at 0x{start:X}: the LinkInfo size field is missing");
        }

        if (size < LinkInfoMinimumHeaderSize)
        {
            return Problem.Failed($"LinkInfo at 0x{start:X}: size {size} is smaller than the minimum header (0x1C)", start);
        }

        if (!file.Has(start, size))
        {
            return Problem.Incomplete($"truncated in LinkInfo at 0x{start:X}: declared {size} bytes, {file.Remaining(start)} available");
        }

        var info = file.Sub(start, size);
        info.TryU32(4, out var headerSize);

        // 0x1C means no Unicode offsets; anything from 0x24 up means both are present. Reading
        // the Unicode offsets out of a 0x1C header reads whatever follows it, silently.
        if (headerSize != LinkInfoMinimumHeaderSize && headerSize < LinkInfoUnicodeHeaderSize)
        {
            return Problem.Failed($"LinkInfo header size 0x{headerSize:X} at 0x{start + 4:X}: must be 0x1C or at least 0x24", start + 4);
        }

        if (headerSize > size)
        {
            return Problem.Failed($"LinkInfo header size 0x{headerSize:X} at 0x{start + 4:X} exceeds the LinkInfo size {size}", start + 4);
        }

        info.TryU32(0x08, out var flags);
        info.TryU32(0x0C, out var volumeIdOffset);
        info.TryU32(0x10, out var localBasePathOffset);
        info.TryU32(0x14, out var networkLinkOffset);
        info.TryU32(0x18, out var suffixOffset);
        uint? localBasePathUnicodeOffset = null;
        uint? suffixUnicodeOffset = null;
        if (headerSize >= LinkInfoUnicodeHeaderSize)
        {
            info.TryU32(0x1C, out var a);
            info.TryU32(0x20, out var b);
            localBasePathUnicodeOffset = a;
            suffixUnicodeOffset = b;
        }

        var hasLocal = (flags & LinkInfo.VolumeIdAndLocalBasePathFlag) != 0;
        var hasNetwork = (flags & LinkInfo.CommonNetworkRelativeLinkAndPathSuffixFlag) != 0;
        var structures = new List<(long Start, long End, string Name)>();
        Problem? problem;

        VolumeId? volumeId = null;
        if (hasLocal)
        {
            if ((problem = CheckOffset(info, start, headerSize, volumeIdOffset, 0x0C, "volume ID offset")) is not null)
            {
                return problem;
            }

            if ((problem = ParseVolumeId(info, start, volumeIdOffset, out volumeId)) is not null)
            {
                return problem;
            }

            structures.Add((volumeIdOffset, volumeIdOffset + volumeId!.Size, "VolumeID"));
        }
        else if (volumeIdOffset != 0 || localBasePathOffset != 0)
        {
            acc.Notes.Add($"LinkInfo at 0x{start:X}: flag 0x1 is clear but the volume ID / local base path offsets are non-zero; they were not followed");
        }

        CommonNetworkRelativeLink? networkLink = null;
        if (hasNetwork)
        {
            if ((problem = CheckOffset(info, start, headerSize, networkLinkOffset, 0x14, "common network relative link offset")) is not null)
            {
                return problem;
            }

            if ((problem = ParseNetworkRelativeLink(info, start, networkLinkOffset, out networkLink)) is not null)
            {
                return problem;
            }

            structures.Add((networkLinkOffset, networkLinkOffset + networkLink!.Size, "CommonNetworkRelativeLink"));
        }
        else if (networkLinkOffset != 0)
        {
            acc.Notes.Add($"LinkInfo at 0x{start:X}: flag 0x2 is clear but the common network relative link offset is non-zero; it was not followed");
        }

        LinkString? localBasePath = null;
        if (hasLocal)
        {
            if ((problem = CheckStringOffset(info, start, headerSize, structures, localBasePathOffset, 0x10, "local base path offset")) is not null
                || (problem = ReadCodePageString(info, start, localBasePathOffset, "local base path", out localBasePath)) is not null)
            {
                return problem;
            }
        }

        if ((problem = CheckStringOffset(info, start, headerSize, structures, suffixOffset, 0x18, "common path suffix offset")) is not null
            || (problem = ReadCodePageString(info, start, suffixOffset, "common path suffix", out var suffix)) is not null)
        {
            return problem;
        }

        LinkString? localBasePathUnicode = null;
        LinkString? suffixUnicode = null;
        if (headerSize >= LinkInfoUnicodeHeaderSize)
        {
            if (hasLocal)
            {
                if (localBasePathUnicodeOffset == 0)
                {
                    acc.Notes.Add($"LinkInfo at 0x{start:X}: header size 0x{headerSize:X} admits a Unicode local base path but its offset is 0; treated as absent");
                }
                else if ((problem = CheckStringOffset(info, start, headerSize, structures, localBasePathUnicodeOffset!.Value, 0x1C, "Unicode local base path offset")) is not null
                    || (problem = ReadUtf16String(info, start, localBasePathUnicodeOffset.Value, "Unicode local base path", out localBasePathUnicode)) is not null)
                {
                    return problem;
                }
            }

            if (suffixUnicodeOffset == 0)
            {
                acc.Notes.Add($"LinkInfo at 0x{start:X}: header size 0x{headerSize:X} admits a Unicode common path suffix but its offset is 0; treated as absent");
            }
            else if ((problem = CheckStringOffset(info, start, headerSize, structures, suffixUnicodeOffset!.Value, 0x20, "Unicode common path suffix offset")) is not null
                || (problem = ReadUtf16String(info, start, suffixUnicodeOffset.Value, "Unicode common path suffix", out suffixUnicode)) is not null)
            {
                return problem;
            }
        }

        var suffixText = suffixUnicode?.Value ?? suffix!.Value;
        string? localPath = null;
        if (hasLocal && localBasePath is not null)
        {
            localPath = (localBasePathUnicode?.Value ?? localBasePath.Value) + suffixText;
        }

        string? networkPath = null;
        if (hasNetwork && networkLink is not null)
        {
            var netName = networkLink.NetNameUnicode?.Value ?? networkLink.NetName?.Value ?? string.Empty;
            networkPath = JoinNetworkPath(netName, suffixText);
        }

        acc.LinkInfo = new LinkInfo(
            size,
            headerSize,
            flags,
            volumeId,
            localBasePath,
            networkLink,
            suffix,
            localBasePathUnicode,
            suffixUnicode,
            localPath,
            networkPath);
        offset = start + size;
        return null;
    }

    private static string JoinNetworkPath(string netName, string suffix)
    {
        if (suffix.Length == 0)
        {
            return netName;
        }

        if (netName.Length == 0)
        {
            return suffix;
        }

        return netName.EndsWith('\\') || suffix.StartsWith('\\') ? netName + suffix : netName + "\\" + suffix;
    }

    private static Problem? CheckOffset(ByteReader info, long start, uint headerSize, uint value, long fieldPosition, string name)
    {
        if (value < headerSize)
        {
            return Problem.Failed(
                $"LinkInfo {name} 0x{value:X} at 0x{start + fieldPosition:X} points into the LinkInfo header (before 0x{headerSize:X})",
                start + fieldPosition);
        }

        if (value >= info.Length)
        {
            return Problem.Failed(
                $"LinkInfo {name} 0x{value:X} at 0x{start + fieldPosition:X} points outside LinkInfo (size {info.Length})",
                start + fieldPosition);
        }

        return null;
    }

    private static Problem? CheckStringOffset(
        ByteReader info,
        long start,
        uint headerSize,
        List<(long Start, long End, string Name)> structures,
        uint value,
        long fieldPosition,
        string name)
    {
        var problem = CheckOffset(info, start, headerSize, value, fieldPosition, name);
        if (problem is not null)
        {
            return problem;
        }

        foreach (var (structStart, structEnd, structName) in structures)
        {
            if (value >= structStart && value < structEnd)
            {
                return Problem.Failed(
                    $"LinkInfo {name} 0x{value:X} at 0x{start + fieldPosition:X} points inside the {structName} structure (0x{structStart:X}..0x{structEnd:X})",
                    start + fieldPosition);
            }
        }

        return null;
    }

    private static Problem? ReadCodePageString(ByteReader info, long start, long offset, string name, out LinkString? value)
    {
        value = null;
        var nul = info.FindNullByte(offset);
        if (nul < 0)
        {
            return Problem.Failed($"LinkInfo {name} at 0x{start + offset:X} is not null-terminated within LinkInfo", start + offset);
        }

        value = LinkString.FromCodePage(info.Span[(int)offset..nul]);
        return null;
    }

    private static Problem? ReadUtf16String(ByteReader info, long start, long offset, string name, out LinkString? value)
    {
        value = null;
        var nul = info.FindNullChar(offset);
        if (nul < 0)
        {
            return Problem.Failed($"LinkInfo {name} at 0x{start + offset:X} is not null-terminated within LinkInfo", start + offset);
        }

        value = LinkString.FromUtf16(info.Span[(int)offset..nul]);
        return null;
    }

    private static Problem? ParseVolumeId(ByteReader info, long start, uint offset, out VolumeId? volumeId)
    {
        volumeId = null;
        var position = start + offset;
        if (!info.TryU32(offset, out var size))
        {
            return Problem.Failed($"VolumeID at 0x{position:X} does not fit its size field inside LinkInfo", position);
        }

        if (size < 0x10)
        {
            return Problem.Failed($"VolumeID at 0x{position:X}: size {size} is smaller than its 16-byte header", position);
        }

        if (!info.Has(offset, size))
        {
            return Problem.Failed($"VolumeID at 0x{position:X}: size {size} overruns LinkInfo ({info.Remaining(offset)} bytes remain)", position);
        }

        var volume = info.Sub(offset, size);
        volume.TryU32(4, out var driveType);
        volume.TryU32(8, out var serial);
        volume.TryU32(12, out var labelOffset);

        if (labelOffset == VolumeIdUnicodeLabelSentinel)
        {
            // The sentinel: the ANSI label is empty and a further offset names the Unicode label.
            if (!volume.TryU32(16, out var unicodeOffset))
            {
                return Problem.Failed($"VolumeID at 0x{position:X}: label offset is the 0x14 sentinel but the Unicode label offset field is missing", position + 12);
            }

            if (unicodeOffset < 0x14 || unicodeOffset >= size)
            {
                return Problem.Failed($"VolumeID at 0x{position:X}: Unicode label offset 0x{unicodeOffset:X} is outside the structure (size {size})", position + 16);
            }

            var nul = volume.FindNullChar(unicodeOffset);
            if (nul < 0)
            {
                return Problem.Failed($"VolumeID at 0x{position:X}: Unicode label is not null-terminated within the structure", position + unicodeOffset);
            }

            volumeId = new VolumeId(
                size,
                driveType,
                serial,
                labelOffset,
                unicodeOffset,
                LinkString.Empty(LinkStringEncoding.SystemCodePage),
                LinkString.FromUtf16(volume.Span[(int)unicodeOffset..nul]));
            return null;
        }

        if (labelOffset < 0x10 || labelOffset >= size)
        {
            return Problem.Failed($"VolumeID at 0x{position:X}: label offset 0x{labelOffset:X} is outside the structure (size {size})", position + 12);
        }

        var labelNul = volume.FindNullByte(labelOffset);
        if (labelNul < 0)
        {
            return Problem.Failed($"VolumeID at 0x{position:X}: label is not null-terminated within the structure", position + labelOffset);
        }

        volumeId = new VolumeId(size, driveType, serial, labelOffset, null, LinkString.FromCodePage(volume.Span[(int)labelOffset..labelNul]), null);
        return null;
    }

    private static Problem? ParseNetworkRelativeLink(ByteReader info, long start, uint offset, out CommonNetworkRelativeLink? link)
    {
        link = null;
        var position = start + offset;
        if (!info.TryU32(offset, out var size))
        {
            return Problem.Failed($"CommonNetworkRelativeLink at 0x{position:X} does not fit its size field inside LinkInfo", position);
        }

        if (size < 0x14)
        {
            return Problem.Failed($"CommonNetworkRelativeLink at 0x{position:X}: size {size} is smaller than its 20-byte header", position);
        }

        if (!info.Has(offset, size))
        {
            return Problem.Failed($"CommonNetworkRelativeLink at 0x{position:X}: size {size} overruns LinkInfo ({info.Remaining(offset)} bytes remain)", position);
        }

        var block = info.Sub(offset, size);
        block.TryU32(4, out var flags);
        block.TryU32(8, out var netNameOffset);
        block.TryU32(12, out var deviceNameOffset);
        block.TryU32(16, out var providerType);

        uint? netNameUnicodeOffset = null;
        uint? deviceNameUnicodeOffset = null;
        if (netNameOffset > 0x14)
        {
            // Only then do the two Unicode offset fields exist (reference/04.3).
            if (!block.TryU32(0x14, out var a) || !block.TryU32(0x18, out var b))
            {
                return Problem.Failed($"CommonNetworkRelativeLink at 0x{position:X}: net name offset 0x{netNameOffset:X} implies Unicode offset fields but the structure is {size} bytes", position + 8);
            }

            netNameUnicodeOffset = a;
            deviceNameUnicodeOffset = b;
        }

        var problem = ReadBlockString(block, position, netNameOffset, size, "net name", unicode: false, out var netName);
        if (problem is not null)
        {
            return problem;
        }

        LinkString? deviceName = null;
        var hasDevice = (flags & CommonNetworkRelativeLink.ValidDeviceFlag) != 0;
        if (hasDevice && (problem = ReadBlockString(block, position, deviceNameOffset, size, "device name", unicode: false, out deviceName)) is not null)
        {
            return problem;
        }

        LinkString? netNameUnicode = null;
        if (netNameUnicodeOffset is > 0
            && (problem = ReadBlockString(block, position, netNameUnicodeOffset.Value, size, "Unicode net name", unicode: true, out netNameUnicode)) is not null)
        {
            return problem;
        }

        LinkString? deviceNameUnicode = null;
        if (hasDevice && deviceNameUnicodeOffset is > 0
            && (problem = ReadBlockString(block, position, deviceNameUnicodeOffset.Value, size, "Unicode device name", unicode: true, out deviceNameUnicode)) is not null)
        {
            return problem;
        }

        link = new CommonNetworkRelativeLink(size, flags, netNameOffset, deviceNameOffset, providerType, netName, deviceName, netNameUnicode, deviceNameUnicode);
        return null;
    }

    private static Problem? ReadBlockString(ByteReader block, long position, uint offset, uint size, string name, bool unicode, out LinkString? value)
    {
        value = null;
        if (offset >= size)
        {
            return Problem.Failed($"CommonNetworkRelativeLink at 0x{position:X}: {name} offset 0x{offset:X} is outside the structure (size {size})", position);
        }

        var nul = unicode ? block.FindNullChar(offset) : block.FindNullByte(offset);
        if (nul < 0)
        {
            return Problem.Failed($"CommonNetworkRelativeLink at 0x{position:X}: {name} is not null-terminated within the structure", position + offset);
        }

        value = unicode ? LinkString.FromUtf16(block.Span[(int)offset..nul]) : LinkString.FromCodePage(block.Span[(int)offset..nul]);
        return null;
    }
}
