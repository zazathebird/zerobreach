namespace Scythe.ShellItems;

public static partial class ShellLinkReader
{
    public const uint FileEntryExtensionSignature = 0xBEEF0004;

    /// <summary>The "My Computer" root; contributes nothing to a reconstructed path.</summary>
    public static readonly Guid MyComputerClassId = new("20D04FE0-3AEA-1069-A2D8-08002B30309D");

    /// <summary>The "Network Places" root; contributes nothing, the network-location item that follows does.</summary>
    public static readonly Guid NetworkPlacesClassId = new("208D2C60-3AEA-1069-A2D7-08002B30309D");

    private static Problem? ParseIdList(ByteReader file, ref long offset, Accumulator acc, ParseContext ctx)
    {
        if (!file.TryU16(offset, out var size))
        {
            return Problem.Incomplete($"truncated at 0x{offset:X}: the item-ID list size field is missing");
        }

        var dataStart = offset + 2;
        if (!file.Has(dataStart, size))
        {
            return Problem.Incomplete(
                $"truncated in the item-ID list at 0x{dataStart:X}: declared {size} bytes, {file.Remaining(dataStart)} available");
        }

        var problem = ParseItems(file.Sub(dataStart, size), dataStart, ctx, out var list);
        if (problem is not null)
        {
            return problem;
        }

        acc.IdList = list;
        offset = dataStart + size;
        return null;
    }

    /// <summary>
    /// Walks a list of item IDs occupying exactly <paramref name="list"/>: each item is a
    /// <c>uint16</c> size (including itself) then data, and the last two bytes of the list must be
    /// the <c>0x0000</c> terminal ID. A size of 0 anywhere else, or of 1, cannot advance the walk
    /// and is refused.
    /// </summary>
    internal static Problem? ParseItems(ByteReader list, long baseOffset, ParseContext ctx, out LinkTargetIdList? result)
    {
        result = null;
        var items = new List<ShellItem>();
        var notes = new List<string>();
        long pos = 0;

        while (true)
        {
            var itemOffset = baseOffset + pos;
            if (!list.TryU16(pos, out var itemSize))
            {
                return Problem.Failed(
                    $"item-ID list at 0x{baseOffset:X}: the declared {list.Length} bytes end at list offset {pos} without a terminal ID",
                    itemOffset);
            }

            if (itemSize == 0)
            {
                if (pos + 2 == list.Length)
                {
                    break;
                }

                return Problem.Failed(
                    $"item at 0x{itemOffset:X} has size 0 at list offset {pos} of {list.Length}, which is not the terminal position; the walk cannot advance",
                    itemOffset);
            }

            if (itemSize == 1)
            {
                return Problem.Failed(
                    $"item at 0x{itemOffset:X} has size 1, which cannot hold its own size field; the walk cannot advance",
                    itemOffset);
            }

            if (!list.Has(pos + 2, itemSize - 2L))
            {
                return Problem.Failed(
                    $"item at 0x{itemOffset:X} declares {itemSize} bytes but the list has {list.Length - pos} left; the list size disagrees with the sum of its items",
                    itemOffset);
            }

            if (items.Count >= ctx.Budget.MaxMatches)
            {
                return Problem.Incomplete(ctx.MaxMatchesReason("item-ID entries"));
            }

            if (ctx.DeadlineExpired)
            {
                return Problem.Incomplete(ctx.DeadlineReason($"before the item at 0x{itemOffset:X}"));
            }

            items.Add(DecodeItem(list.Sub(pos + 2, itemSize - 2), itemOffset, notes));
            pos += itemSize;
        }

        string? path = null;
        var broken = false;
        foreach (var item in items)
        {
            if (!item.PathSegmentKnown)
            {
                broken = true;
                break;
            }

            if (item.PathSegment is not null)
            {
                path = JoinSegment(path, item.PathSegment);
            }
        }

        var completeness = items.Count == 0 ? PathCompleteness.None
            : broken ? PathCompleteness.Partial
            : path is null ? PathCompleteness.None
            : PathCompleteness.Complete;

        result = new LinkTargetIdList(list.Length, items, path, completeness, notes);
        return null;
    }

    private static string JoinSegment(string? path, string segment) =>
        path is null ? segment
        : path.EndsWith('\\') ? path + segment
        : path + "\\" + segment;

    private static ShellItem DecodeItem(ByteReader data, long itemOffset, List<string> notes)
    {
        var raw = data.Span.ToArray();
        if (raw.Length == 0)
        {
            notes.Add($"item at 0x{itemOffset:X}: empty item with no class-type byte; kept raw");
            return new ShellItem { ClassType = 0, Kind = ShellItemKind.Unknown, RawData = raw, PathSegmentKnown = false };
        }

        var classType = raw[0];
        return classType switch
        {
            0x1F => DecodeRootFolder(data, raw, itemOffset, notes),
            >= 0x20 and <= 0x2F => DecodeVolume(data, raw, itemOffset, notes),
            >= 0x30 and <= 0x3F => DecodeFileEntry(data, raw, itemOffset, notes),
            >= 0x40 and <= 0x4F => DecodeNetworkLocation(data, raw, itemOffset, notes),
            _ => Undecoded(classType, raw, itemOffset, notes),
        };
    }

    private static ShellItem Undecoded(byte classType, byte[] raw, long itemOffset, List<string> notes)
    {
        notes.Add($"item at 0x{itemOffset:X}: class type 0x{classType:X2} is not one this reader decodes; kept raw, path is partial");
        return new ShellItem { ClassType = classType, Kind = ShellItemKind.Unknown, RawData = raw, PathSegmentKnown = false };
    }

    private static ShellItem DecodeRootFolder(ByteReader data, byte[] raw, long itemOffset, List<string> notes)
    {
        if (!data.TryU8(1, out var sortIndex) || !data.TryGuid(2, out var classId))
        {
            notes.Add($"item at 0x{itemOffset:X}: root folder item is {raw.Length} bytes, needs 18 for its class identifier; path is partial");
            return new ShellItem { ClassType = raw[0], Kind = ShellItemKind.RootFolder, RawData = raw, PathSegmentKnown = false };
        }

        var known = classId == MyComputerClassId || classId == NetworkPlacesClassId;
        if (!known)
        {
            notes.Add($"item at 0x{itemOffset:X}: root folder {classId:D} is not a path root this reader knows; path is partial");
        }

        return new ShellItem
        {
            ClassType = raw[0],
            Kind = ShellItemKind.RootFolder,
            RawData = raw,
            PathSegmentKnown = known,
            SortIndex = sortIndex,
            RootFolderClassId = classId,
        };
    }

    private static ShellItem DecodeVolume(ByteReader data, byte[] raw, long itemOffset, List<string> notes)
    {
        // The drive string is null-terminated at data offset 1 (reference/04.3), the opposite of
        // the StringData convention.
        var nul = data.FindNullByte(1);
        if (nul < 0)
        {
            notes.Add($"item at 0x{itemOffset:X}: volume item has no null-terminated drive string; path is partial");
            return new ShellItem { ClassType = raw[0], Kind = ShellItemKind.Volume, RawData = raw, PathSegmentKnown = false };
        }

        var drive = LinkString.FromCodePage(data.Span[1..nul]).Value;
        if (drive.Length == 0)
        {
            notes.Add($"item at 0x{itemOffset:X}: volume item has an empty drive string; path is partial");
        }

        return new ShellItem
        {
            ClassType = raw[0],
            Kind = ShellItemKind.Volume,
            RawData = raw,
            PathSegmentKnown = drive.Length > 0,
            PathSegment = drive.Length > 0 ? drive : null,
            DriveString = drive,
        };
    }

    private static ShellItem DecodeFileEntry(ByteReader data, byte[] raw, long itemOffset, List<string> notes)
    {
        var classType = raw[0];
        var kind = (classType & 0x01) != 0 ? FileEntryKind.Directory : FileEntryKind.File;
        var unicodeName = (classType & 0x04) != 0;

        if (!data.Has(0, 12))
        {
            notes.Add($"item at 0x{itemOffset:X}: file entry is {raw.Length} bytes, needs 12 before its name; path is partial");
            return new ShellItem { ClassType = classType, Kind = ShellItemKind.FileEntry, RawData = raw, PathSegmentKnown = false, FileEntryKind = kind };
        }

        data.TryU32(2, out var fileSize);
        data.TryU32(6, out var dosDateTime);
        data.TryU16(10, out var attributes);

        // Primary name: null-terminated (not counted) at data offset 12.
        string primaryName;
        long end;
        if (unicodeName)
        {
            var nul = data.FindNullChar(12);
            if (nul < 0)
            {
                notes.Add($"item at 0x{itemOffset:X}: file entry's UTF-16 primary name is not null-terminated; path is partial");
                return new ShellItem { ClassType = classType, Kind = ShellItemKind.FileEntry, RawData = raw, PathSegmentKnown = false, FileEntryKind = kind, FileSize = fileSize, ModifiedDosDateTime = dosDateTime, FileAttributes = attributes };
            }

            primaryName = LinkString.FromUtf16(data.Span[12..nul]).Value;
            end = nul + 2;
        }
        else
        {
            var nul = data.FindNullByte(12);
            if (nul < 0)
            {
                notes.Add($"item at 0x{itemOffset:X}: file entry's primary name is not null-terminated; path is partial");
                return new ShellItem { ClassType = classType, Kind = ShellItemKind.FileEntry, RawData = raw, PathSegmentKnown = false, FileEntryKind = kind, FileSize = fileSize, ModifiedDosDateTime = dosDateTime, FileAttributes = attributes };
            }

            primaryName = LinkString.FromCodePage(data.Span[12..nul]).Value;
            end = nul + 1;
        }

        // Padding to a two-byte boundary, measured from the item start (the size field sits two
        // bytes before this data), then the extension blocks.
        var pos = end;
        if (((pos + 2) & 1) == 1)
        {
            pos++;
        }

        DecodeExtensionBlocks(data, pos, itemOffset, notes, out var extension, out var others);

        var segment = extension?.LongName ?? primaryName;
        if (segment.Length == 0)
        {
            notes.Add($"item at 0x{itemOffset:X}: file entry has an empty name; path is partial");
        }

        return new ShellItem
        {
            ClassType = classType,
            Kind = ShellItemKind.FileEntry,
            RawData = raw,
            PathSegmentKnown = segment.Length > 0,
            PathSegment = segment.Length > 0 ? segment : null,
            FileEntryKind = kind,
            FileSize = fileSize,
            ModifiedDosDateTime = dosDateTime,
            FileAttributes = attributes,
            PrimaryName = primaryName,
            Extension = extension,
            OtherExtensionBlocks = others,
        };
    }

    private static void DecodeExtensionBlocks(
        ByteReader data,
        long pos,
        long itemOffset,
        List<string> notes,
        out FileEntryExtension? extension,
        out List<RawExtensionBlock> others)
    {
        extension = null;
        others = [];

        while (data.Remaining(pos) >= 8)
        {
            data.TryU16(pos, out var size);
            data.TryU16(pos + 2, out var version);
            data.TryU32(pos + 4, out var signature);
            if (size < 8 || size > data.Remaining(pos))
            {
                notes.Add($"item at 0x{itemOffset:X}: extension block at item offset {pos + 2} declares {size} bytes with {data.Remaining(pos)} left; extension walk stopped");
                return;
            }

            var block = data.Sub(pos, size);
            if (signature == FileEntryExtensionSignature && extension is null)
            {
                extension = DecodeFileEntryExtension(block, size, version, itemOffset, notes);
            }
            else
            {
                others.Add(new RawExtensionBlock(size, version, signature, block.Span.ToArray()));
            }

            pos += size;
        }

        if (data.Remaining(pos) > 0)
        {
            notes.Add($"item at 0x{itemOffset:X}: {data.Remaining(pos)} trailing bytes after the last extension block");
        }
    }

    /// <summary>
    /// <c>0xBEEF0004</c>: the long name sits after a version-dependent fixed portion. Only the
    /// versions whose layout is known (3, 7, 8, 9) have their long name read; any other version
    /// keeps the block raw and says so, rather than reading a name from the wrong offset.
    /// </summary>
    private static FileEntryExtension DecodeFileEntryExtension(ByteReader block, ushort size, ushort version, long itemOffset, List<string> notes)
    {
        block.TryU32(8, out var creation);
        block.TryU32(12, out var access);

        ulong? fileReference = null;
        if (version >= 7 && version <= 9 && block.TryU64(20, out var reference))
        {
            fileReference = reference;
        }

        long nameOffset = version switch
        {
            3 => 20,
            7 => 38,
            8 => 42,
            9 => 46,
            _ => -1,
        };

        string? longName = null;
        if (nameOffset < 0)
        {
            notes.Add($"item at 0x{itemOffset:X}: 0xBEEF0004 extension version {version} is not one this reader decodes (3, 7, 8, 9); long name not read");
        }
        else if (nameOffset + 2 > size - 2)
        {
            notes.Add($"item at 0x{itemOffset:X}: 0xBEEF0004 extension of {size} bytes is too short for a version-{version} long name at offset {nameOffset}");
        }
        else
        {
            var nul = block.FindNullChar(nameOffset);
            if (nul < 0 || nul + 2 > size - 2)
            {
                notes.Add($"item at 0x{itemOffset:X}: 0xBEEF0004 long name is not null-terminated before the trailing offset field");
            }
            else
            {
                longName = LinkString.FromUtf16(block.Span[(int)nameOffset..nul]).Value;
            }
        }

        ushort? firstExtensionOffset = null;
        if (size >= 10 && block.TryU16(size - 2, out var first))
        {
            firstExtensionOffset = first;
        }

        return new FileEntryExtension(size, version, creation, access, fileReference, longName, firstExtensionOffset, block.Span.ToArray());
    }

    private static ShellItem DecodeNetworkLocation(ByteReader data, byte[] raw, long itemOffset, List<string> notes)
    {
        // Layout: class type (1), unknown (1), flags (1), then a null-terminated location; a
        // description follows when flag 0x80 is set and comments when 0x40 is. The reference
        // gives only the class range; the field offsets are recorded as a judgement call.
        if (!data.Has(0, 3))
        {
            notes.Add($"item at 0x{itemOffset:X}: network location item is {raw.Length} bytes, needs 3 before its location; path is partial");
            return new ShellItem { ClassType = raw[0], Kind = ShellItemKind.NetworkLocation, RawData = raw, PathSegmentKnown = false };
        }

        var flags = raw[2];
        var nul = data.FindNullByte(3);
        if (nul < 0)
        {
            notes.Add($"item at 0x{itemOffset:X}: network location is not null-terminated; path is partial");
            return new ShellItem { ClassType = raw[0], Kind = ShellItemKind.NetworkLocation, RawData = raw, PathSegmentKnown = false, NetworkFlags = flags };
        }

        var location = LinkString.FromCodePage(data.Span[3..nul]).Value;
        long pos = nul + 1;
        string? description = null;
        string? comments = null;

        if ((flags & 0x80) != 0)
        {
            var descNul = data.FindNullByte(pos);
            if (descNul >= 0)
            {
                description = LinkString.FromCodePage(data.Span[(int)pos..descNul]).Value;
                pos = descNul + 1;
            }
        }

        if ((flags & 0x40) != 0)
        {
            var commentNul = data.FindNullByte(pos);
            if (commentNul >= 0)
            {
                comments = LinkString.FromCodePage(data.Span[(int)pos..commentNul]).Value;
            }
        }

        if (location.Length == 0)
        {
            notes.Add($"item at 0x{itemOffset:X}: network location is empty; path is partial");
        }

        return new ShellItem
        {
            ClassType = raw[0],
            Kind = ShellItemKind.NetworkLocation,
            RawData = raw,
            PathSegmentKnown = location.Length > 0,
            PathSegment = location.Length > 0 ? location : null,
            NetworkFlags = flags,
            NetworkLocation = location,
            NetworkDescription = description,
            NetworkComments = comments,
        };
    }
}
