using System.Buffers.Binary;
using System.Globalization;

namespace Scythe.ShellItems;

/// <summary>
/// Reads the two jump-list containers. The <c>automaticDestinations-ms</c> entry point takes
/// stream bytes a compound-file reader has already extracted — this project does not read the
/// container itself, and takes no dependency on whichever sibling does.
/// </summary>
public static class JumpListReader
{
    public const int DestListHeaderSize = 32;
    public const int CustomDestinationsHeaderSize = 16;
    public const uint CustomDestinationsFooter = 0xBABFFBAB;

    /// <summary>
    /// Pairs each <c>DestList</c> entry with the link stream it names. Link streams are looked up
    /// by their hexadecimal names; <paramref name="linkStreams"/> may contain other streams, which
    /// are ignored.
    /// </summary>
    public static LinkResult<AutomaticDestinations> ReadAutomaticDestinations(
        ReadOnlySpan<byte> destList,
        IReadOnlyDictionary<string, byte[]> linkStreams,
        ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(linkStreams);
        var ctx = new ParseContext(budget ?? ScanBudget.Default);

        long total = destList.Length;
        foreach (var stream in linkStreams.Values)
        {
            total += stream.Length;
        }

        if (total > ctx.Budget.MaxInputBytes)
        {
            return LinkResult<AutomaticDestinations>.Incomplete(
                null,
                $"MaxInputBytes: DestList plus {linkStreams.Count} link streams total {total} bytes, budget allows {ctx.Budget.MaxInputBytes}");
        }

        var reader = new ByteReader(destList);
        if (reader.Length < DestListHeaderSize)
        {
            return LinkResult<AutomaticDestinations>.Incomplete(
                null,
                $"truncated DestList: {reader.Length} bytes present, the header needs {DestListHeaderSize}");
        }

        reader.TryU32(0, out var version);
        reader.TryU32(4, out var entryCount);
        reader.TryU32(8, out var pinnedCount);
        reader.TryU32(12, out var floatBits);
        reader.TryU32(16, out var lastEntryNumber);
        reader.TryU32(20, out var unknown1);
        reader.TryU64(24, out var lastRevision);
        var header = new DestListHeader(version, entryCount, pinnedCount, BitConverter.UInt32BitsToSingle(floatBits), lastEntryNumber, unknown1, lastRevision);

        var notes = new List<string>();
        var streamsByNumber = IndexLinkStreams(linkStreams, notes);
        var referenced = new HashSet<string>(StringComparer.Ordinal);
        var entries = new List<DestListEntry>();

        AutomaticDestinations Partial() =>
            new(header, entries.ToArray(), Unreferenced(streamsByNumber, referenced), notes.ToArray());

        // The stride is derived from the version, never from a constant, and the walk must land
        // exactly on the end of the stream (reference/04.3, §4.5 item 1).
        int fixedLength;
        int pathLengthOffset;
        int trailerLength;
        int accessCountOffset;
        switch (version)
        {
            case 1:
                fixedLength = 114;
                pathLengthOffset = 112;
                trailerLength = 0;
                accessCountOffset = -1;
                break;
            case 3:
            case 4:
                fixedLength = 130;
                pathLengthOffset = 128;
                trailerLength = 4;
                accessCountOffset = 116;
                break;
            default:
                return LinkResult<AutomaticDestinations>.Incomplete(
                    Partial(),
                    $"DestList version {version} is not one this reader knows (1, 3, 4); the entry layout was not decoded");
        }

        long pos = DestListHeaderSize;
        for (uint i = 0; i < entryCount; i++)
        {
            if (entries.Count >= ctx.Budget.MaxMatches)
            {
                return LinkResult<AutomaticDestinations>.Incomplete(Partial(), ctx.MaxMatchesReason("DestList entries"));
            }

            if (ctx.DeadlineExpired)
            {
                return LinkResult<AutomaticDestinations>.Incomplete(Partial(), ctx.DeadlineReason($"before DestList entry {i}"));
            }

            if (!reader.Has(pos, fixedLength))
            {
                return LinkResult<AutomaticDestinations>.Incomplete(
                    Partial(),
                    $"DestList entry {i} at 0x{pos:X}: the stream ends after {reader.Remaining(pos)} of the {fixedLength} fixed bytes; the header declared {entryCount} entries");
            }

            reader.TryU16(pos + pathLengthOffset, out var pathChars);
            var pathBytes = pathChars * 2L;
            var entryLength = fixedLength + pathBytes + trailerLength;
            if (!reader.Has(pos, entryLength))
            {
                return LinkResult<AutomaticDestinations>.Incomplete(
                    Partial(),
                    $"DestList entry {i} at 0x{pos:X}: a path of {pathChars} characters runs past the end of the stream ({reader.Remaining(pos + fixedLength)} bytes remain)");
            }

            reader.TryU64(pos, out var checksum);
            reader.TryGuid(pos + 8, out var newVolume);
            reader.TryGuid(pos + 24, out var newObject);
            reader.TryGuid(pos + 40, out var birthVolume);
            reader.TryGuid(pos + 56, out var birthObject);
            var machine = reader.Sub(pos + 72, 16);
            var machineNul = machine.FindNullByte(0);
            var machineName = LinkString.FromCodePage(machineNul < 0 ? machine.Span : machine.Span[..machineNul]);
            reader.TryU32(pos + 88, out var entryNumber);
            reader.TryU64(pos + 100, out var lastAccess);
            reader.TryI32(pos + 108, out var pinStatus);
            uint? accessCount = null;
            if (accessCountOffset >= 0 && reader.TryU32(pos + accessCountOffset, out var count))
            {
                accessCount = count;
            }

            reader.TrySlice(pos + fixedLength, pathBytes, out var pathSlice);
            var path = LinkString.FromUtf16(pathSlice);

            string? streamName = null;
            LinkResult<ShellLink>? link = null;
            if (streamsByNumber.TryGetValue(entryNumber, out var name))
            {
                streamName = name;
                referenced.Add(name);
                link = ShellLinkReader.ReadCore(linkStreams[name], ctx, depth: 2);
            }
            else
            {
                notes.Add($"DestList entry {entryNumber}: no link stream named {entryNumber:x}");
            }

            if (ctx.DeadlineExpired)
            {
                // Never emit a half-decoded entry: the one just read is dropped along with its link.
                return LinkResult<AutomaticDestinations>.Incomplete(
                    Partial(),
                    ctx.DeadlineReason($"while decoding DestList entry {i}; that entry is not emitted"));
            }

            entries.Add(new DestListEntry(
                pos,
                checksum,
                newVolume,
                newObject,
                birthVolume,
                birthObject,
                machineName,
                entryNumber,
                new FileTimeValue(lastAccess),
                pinStatus,
                accessCount,
                path,
                streamName,
                link));
            pos += entryLength;
        }

        if (pos != reader.Length)
        {
            return LinkResult<AutomaticDestinations>.Incomplete(
                Partial(),
                $"DestList: {entryCount} entries end at 0x{pos:X} but the stream is {reader.Length} bytes; the entry count or the version-{version} stride disagrees with the stream length");
        }

        return LinkResult<AutomaticDestinations>.Ok(Partial());
    }

    private static SortedDictionary<ulong, string> IndexLinkStreams(IReadOnlyDictionary<string, byte[]> linkStreams, List<string> notes)
    {
        var byNumber = new SortedDictionary<ulong, string>();
        var names = linkStreams.Keys.ToArray();
        Array.Sort(names, StringComparer.Ordinal);
        foreach (var name in names)
        {
            if (name.Length is < 1 or > 16 || !IsHex(name))
            {
                continue;
            }

            var number = ulong.Parse(name, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
            if (byNumber.TryGetValue(number, out var existing))
            {
                notes.Add($"link streams '{existing}' and '{name}' both name entry {number}; '{existing}' is used");
                continue;
            }

            byNumber[number] = name;
        }

        return byNumber;
    }

    private static bool IsHex(string name)
    {
        foreach (var c in name)
        {
            if (!Uri.IsHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    private static string[] Unreferenced(SortedDictionary<ulong, string> streams, HashSet<string> referenced)
    {
        var result = streams.Values.Where(n => !referenced.Contains(n)).ToArray();
        Array.Sort(result, StringComparer.Ordinal);
        return result;
    }

    /// <summary>
    /// Walks a <c>customDestinations-ms</c> file: a 16-byte header, link records located by their
    /// header signature and advanced by the length each parse consumed, then the footer.
    /// </summary>
    public static LinkResult<CustomDestinations> ReadCustomDestinations(ReadOnlySpan<byte> bytes, ScanBudget? budget = null)
    {
        var ctx = new ParseContext(budget ?? ScanBudget.Default);
        if (bytes.Length > ctx.Budget.MaxInputBytes)
        {
            return LinkResult<CustomDestinations>.Incomplete(
                null,
                $"MaxInputBytes: input is {bytes.Length} bytes, budget allows {ctx.Budget.MaxInputBytes}");
        }

        var reader = new ByteReader(bytes);
        if (reader.Length < CustomDestinationsHeaderSize)
        {
            return LinkResult<CustomDestinations>.Incomplete(
                null,
                $"truncated customDestinations-ms: {reader.Length} bytes present, the header needs {CustomDestinationsHeaderSize}");
        }

        reader.TryU32(0, out var version);
        reader.TryU32(4, out var unknown1);
        reader.TryU32(8, out var unknown2);
        reader.TryU32(12, out var declaredCount);

        Span<byte> signature = stackalloc byte[20];
        BinaryPrimitives.WriteUInt32LittleEndian(signature, (uint)ShellLinkReader.HeaderSize);
        ShellLinkReader.ShellLinkClassId.TryWriteBytes(signature[4..]);
        Span<byte> footer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(footer, CustomDestinationsFooter);

        var entries = new List<CustomDestinationEntry>();
        var notes = new List<string>();
        long skipped = 0;
        long? footerOffset = null;
        long pos = CustomDestinationsHeaderSize;

        CustomDestinations Partial() =>
            new(version, unknown1, unknown2, declaredCount, entries.ToArray(), footerOffset, skipped, notes.ToArray());

        while (pos < reader.Length)
        {
            var rest = bytes[(int)pos..];
            var nextLink = rest.IndexOf(signature);
            var nextFooter = rest.IndexOf(footer);

            if (nextFooter >= 0 && (nextLink < 0 || nextFooter < nextLink))
            {
                skipped += nextFooter;
                footerOffset = pos + nextFooter;
                pos = footerOffset.Value + 4;
                break;
            }

            if (nextLink < 0)
            {
                skipped += rest.Length;
                pos = reader.Length;
                break;
            }

            skipped += nextLink;
            var linkOffset = pos + nextLink;

            if (entries.Count >= ctx.Budget.MaxMatches)
            {
                return LinkResult<CustomDestinations>.Incomplete(Partial(), ctx.MaxMatchesReason("customDestinations-ms link records"));
            }

            if (ctx.DeadlineExpired)
            {
                return LinkResult<CustomDestinations>.Incomplete(Partial(), ctx.DeadlineReason($"before the link record at 0x{linkOffset:X}"));
            }

            var link = ShellLinkReader.ReadCore(bytes[(int)linkOffset..], ctx, depth: 2);
            if (ctx.DeadlineExpired)
            {
                return LinkResult<CustomDestinations>.Incomplete(
                    Partial(),
                    ctx.DeadlineReason($"while decoding the link record at 0x{linkOffset:X}; that record is not emitted"));
            }

            entries.Add(new CustomDestinationEntry(linkOffset, link));

            // Advance by what the parse consumed; a record that could not be parsed at all is
            // stepped past by its signature so the scan resynchronises on the next one.
            pos = link.Value is { Length: > 0 } parsed ? linkOffset + parsed.Length : linkOffset + 4;
        }

        if (footerOffset is null)
        {
            return LinkResult<CustomDestinations>.Incomplete(
                Partial(),
                $"customDestinations-ms: the footer 0x{CustomDestinationsFooter:X8} was not found after {entries.Count} link records; the container is truncated");
        }

        if (pos < reader.Length)
        {
            notes.Add($"{reader.Length - pos} bytes follow the footer at 0x{footerOffset:X}");
        }

        if (entries.Count != declaredCount)
        {
            return LinkResult<CustomDestinations>.Incomplete(
                Partial(),
                $"customDestinations-ms: the header declares {declaredCount} entries but {entries.Count} link records were found before the footer");
        }

        return LinkResult<CustomDestinations>.Ok(Partial());
    }
}
