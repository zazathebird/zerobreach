using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;

namespace Scythe.Formats.Containers;

/// <summary>
/// OLE compound file (CFB) reader — the container behind legacy Office documents
/// (BLUEPRINT §7). Parses the header, FAT/DIFAT/mini-FAT, and the directory tree; reads
/// streams through either allocation table. Enough to reach a macro storage; what a stream
/// contains is the host's problem.
///
/// Every chain walk carries a visited set and a step cap, because a cyclic FAT is the
/// cheapest possible way to hang a scanner.
/// </summary>
public static class OleReader
{
    /// <summary>D0 CF 11 E0 A1 B1 1A E1.</summary>
    internal static ReadOnlySpan<byte> Signature => new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

    private const uint MaxRegularSector = 0xFFFFFFFA;
    private const uint DifatSector = 0xFFFFFFFC;
    private const uint FatSector = 0xFFFFFFFD;
    private const uint EndOfChain = 0xFFFFFFFE;
    private const uint FreeSector = 0xFFFFFFFF;
    private const uint NoStream = 0xFFFFFFFF;

    private const int HeaderSize = 512;
    private const int DirectoryEntrySize = 128;
    private const int HeaderDifatEntries = 109;

    private sealed record ParsedEntry(
        int Index,
        string Name,
        byte RawType,
        uint Left,
        uint Right,
        uint Child,
        Guid Clsid,
        uint StartSector,
        ulong Size,
        bool Usable);

    /// <summary>Parses header, allocation tables and the directory tree. Reads no stream content.</summary>
    public static OleReadResult Read(byte[] data, ScanBudget budget)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(budget);

        if (data.LongLength > budget.MaxInputBytes)
        {
            return OleReadResult.IncompleteWithoutFile(
                $"input is {data.LongLength} bytes, over the {budget.MaxInputBytes}-byte budget; refused");
        }
        var clock = Stopwatch.StartNew();
        if (clock.Elapsed >= budget.Deadline)
        {
            return OleReadResult.IncompleteWithoutFile("deadline exhausted before reading began");
        }

        if (data.Length < HeaderSize)
        {
            return OleReadResult.Fail($"{data.Length} bytes is smaller than the 512-byte compound file header", 0);
        }
        if (!data.AsSpan(0, 8).SequenceEqual(Signature))
        {
            return OleReadResult.Fail("no compound file signature (D0 CF 11 E0 A1 B1 1A E1) at offset 0", 0);
        }
        if (U16(data, 28) != 0xFFFE)
        {
            return OleReadResult.Fail($"byte-order mark is 0x{U16(data, 28):X4}, expected 0xFFFE", 28);
        }

        ushort major = (ushort)U16(data, 26);
        int sectorShift = U16(data, 30);
        int miniShift = U16(data, 32);
        if (major != 3 && major != 4)
        {
            return OleReadResult.IncompleteWithoutFile($"compound file major version {major} not supported (3 and 4 only)");
        }
        // The spec fixes these per version; a file that contradicts its own version is
        // malformed, not a variant.
        int expectedShift = major == 3 ? 9 : 12;
        if (sectorShift != expectedShift)
        {
            return OleReadResult.Fail($"sector shift {sectorShift} contradicts major version {major} (expected {expectedShift})", 30);
        }
        if (miniShift != 6)
        {
            return OleReadResult.Fail($"mini sector shift is {miniShift}, spec requires 6", 32);
        }
        uint cutoff = U32(data, 56);
        if (cutoff != 4096)
        {
            return OleReadResult.Fail($"mini stream cutoff is {cutoff}, spec requires 4096", 56);
        }

        int sectorSize = 1 << sectorShift;
        int miniSectorSize = 1 << miniShift;
        // Sector n starts at (n+1) << shift for both versions (the v3 header fills exactly
        // one sector; the v4 header is padded out to one).
        long totalSectors = Math.Max(0, (data.LongLength - sectorSize + sectorSize - 1) / sectorSize);

        uint numFatSectors = U32(data, 44);
        uint firstDirSector = U32(data, 48);
        uint firstMiniFatSector = U32(data, 60);
        uint numMiniFatSectors = U32(data, 64);
        uint firstDifatSector = U32(data, 68);
        uint numDifatSectors = U32(data, 72);

        if (numFatSectors > totalSectors)
        {
            return OleReadResult.IncompleteWithoutFile(
                $"header declares {numFatSectors} FAT sectors but the file holds only {totalSectors} sectors; truncated or lying header");
        }

        var reasons = new List<string>();

        // --- DIFAT: the list of FAT sector ids. First 109 live in the header; the rest in
        // a dedicated chain where each sector's last field points to the next.
        var fatSectorIds = new List<uint>((int)numFatSectors);
        for (int i = 0; i < HeaderDifatEntries && fatSectorIds.Count < numFatSectors; i++)
        {
            uint id = U32(data, 76 + i * 4);
            if (id > MaxRegularSector)
            {
                return OleReadResult.Fail($"header DIFAT slot {i} holds special value 0x{id:X8} but {numFatSectors} FAT sectors were declared", 76 + i * 4);
            }
            fatSectorIds.Add(id);
        }
        if (fatSectorIds.Count < numFatSectors)
        {
            var visited = new HashSet<uint>();
            uint cur = firstDifatSector;
            uint steps = 0;
            int perDifat = sectorSize / 4 - 1;
            while (fatSectorIds.Count < numFatSectors)
            {
                if (cur > MaxRegularSector)
                {
                    reasons.Add($"DIFAT chain ends after {fatSectorIds.Count} of {numFatSectors} declared FAT sectors");
                    break;
                }
                if (!visited.Add(cur))
                {
                    return OleReadResult.Fail($"DIFAT chain cycles back to sector {cur}", SectorOffset(cur, sectorShift));
                }
                if (++steps > numDifatSectors + 1 || steps > totalSectors)
                {
                    reasons.Add($"DIFAT chain longer than its declared {numDifatSectors} sectors; stopped");
                    break;
                }
                long off = SectorOffset(cur, sectorShift);
                if (off + sectorSize > data.Length)
                {
                    reasons.Add($"DIFAT sector {cur} lies past the end of the file; truncated");
                    break;
                }
                for (int i = 0; i < perDifat && fatSectorIds.Count < numFatSectors; i++)
                {
                    uint id = U32(data, off + i * 4);
                    if (id > MaxRegularSector)
                    {
                        reasons.Add($"DIFAT sector {cur} slot {i} holds special value 0x{id:X8}; FAT list ends early");
                        break;
                    }
                    fatSectorIds.Add(id);
                }
                cur = U32(data, off + sectorSize - 4);
            }
        }

        // --- FAT: concatenation of the declared FAT sectors.
        int entriesPerSector = sectorSize / 4;
        var fat = new uint[fatSectorIds.Count * entriesPerSector];
        for (int s = 0; s < fatSectorIds.Count; s++)
        {
            long off = SectorOffset(fatSectorIds[s], sectorShift);
            if (off + sectorSize > data.Length)
            {
                return OleReadResult.IncompleteWithoutFile(
                    $"FAT sector {fatSectorIds[s]} lies past the end of the file at {data.Length}; truncated");
            }
            for (int i = 0; i < entriesPerSector; i++)
            {
                fat[s * entriesPerSector + i] = U32(data, off + i * 4);
            }
        }

        // --- Directory stream.
        var dirWalk = WalkFatChain(firstDirSector, fat, totalSectors);
        if (dirWalk.Error is not null)
        {
            return OleReadResult.Fail($"directory chain: {dirWalk.Error}", null);
        }
        var entries = new List<ParsedEntry?>();
        int maxEntries = ContainerLimits.MaxOleDirectoryEntries;
        bool capped = false;
        foreach (uint sector in dirWalk.Sectors)
        {
            long off = SectorOffset(sector, sectorShift);
            if (off + sectorSize > data.Length)
            {
                reasons.Add($"directory sector {sector} lies past the end of the file; directory truncated");
                break;
            }
            for (int j = 0; j < sectorSize / DirectoryEntrySize; j++)
            {
                if (entries.Count >= maxEntries)
                {
                    capped = true;
                    break;
                }
                entries.Add(ParseDirectoryEntry(data, off + j * DirectoryEntrySize, entries.Count, major, reasons));
            }
            if (capped)
            {
                reasons.Add($"directory holds more than the cap of {maxEntries} entries; remainder not read");
                break;
            }
        }
        if (entries.Count == 0)
        {
            return OleReadResult.Fail("directory stream holds no entries", null);
        }
        ParsedEntry? rootEntry = entries[0];
        if (rootEntry is null || rootEntry.RawType != 5)
        {
            return OleReadResult.Fail(
                $"first directory entry is not a root storage (type {(rootEntry is null ? "unusable" : rootEntry.RawType.ToString())})",
                null);
        }

        // --- Mini-FAT.
        var miniFatList = new List<uint>();
        if (numMiniFatSectors > 0 && firstMiniFatSector <= MaxRegularSector)
        {
            var walk = WalkFatChain(firstMiniFatSector, fat, Math.Min(numMiniFatSectors, totalSectors));
            if (walk.Error is not null)
            {
                return OleReadResult.Fail($"mini-FAT chain: {walk.Error}", null);
            }
            if (walk.Sectors.Count < numMiniFatSectors)
            {
                reasons.Add($"mini-FAT chain holds {walk.Sectors.Count} of {numMiniFatSectors} declared sectors");
            }
            foreach (uint sector in walk.Sectors)
            {
                long off = SectorOffset(sector, sectorShift);
                if (off + sectorSize > data.Length)
                {
                    reasons.Add($"mini-FAT sector {sector} lies past the end of the file; truncated");
                    break;
                }
                for (int i = 0; i < entriesPerSector; i++)
                {
                    miniFatList.Add(U32(data, off + i * 4));
                }
            }
        }

        // --- The mini stream itself: the root storage's FAT chain.
        uint[] miniStreamSectors = Array.Empty<uint>();
        if (rootEntry.Size > 0 && rootEntry.StartSector <= MaxRegularSector)
        {
            var walk = WalkFatChain(rootEntry.StartSector, fat, totalSectors);
            if (walk.Error is not null)
            {
                reasons.Add($"mini stream chain: {walk.Error}; small streams unreadable");
            }
            else
            {
                miniStreamSectors = walk.Sectors.ToArray();
            }
        }

        // --- Directory tree, in deterministic in-order traversal of the sibling tree.
        var treeVisited = new HashSet<uint>();
        var rootChildren = CollectChildren(rootEntry.Child, string.Empty, 1, entries, treeVisited, reasons, major);
        var root = new OleDirectoryEntryInfo
        {
            Index = 0,
            Name = rootEntry.Name,
            Path = string.Empty,
            RawType = rootEntry.RawType,
            Type = MapType(rootEntry.RawType),
            StartSector = rootEntry.StartSector,
            Size = rootEntry.Size,
            Clsid = rootEntry.Clsid,
            Children = rootChildren,
        };

        if (clock.Elapsed >= budget.Deadline)
        {
            reasons.Add("deadline exhausted during directory parse");
        }

        var file = new OleFileInfo
        {
            MajorVersion = major,
            SectorSize = sectorSize,
            MiniSectorSize = miniSectorSize,
            MiniStreamCutoff = cutoff,
            Root = root,
            Fat = fat,
            MiniFat = miniFatList.ToArray(),
            MiniStreamSectors = miniStreamSectors,
        };
        return OleReadResult.From(reasons, file);
    }

    /// <summary>
    /// Reads one stream's bytes through the FAT, or through the mini-FAT for streams below
    /// the cutoff. Memory is bounded by the chain walk itself — nothing is preallocated from
    /// the declared size, because declared sizes lie.
    /// </summary>
    public static OleStreamDataResult ReadStream(byte[] data, OleFileInfo file, OleDirectoryEntryInfo entry, ScanBudget budget)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(budget);

        if (entry.Type != OleEntryType.Stream)
        {
            return OleStreamDataResult.NotRead(
                OperationState.Failed,
                $"'{entry.Path}' is a {entry.Type}, not a stream");
        }
        var clock = Stopwatch.StartNew();
        long size = (long)entry.Size;
        long totalSectors = Math.Max(0, (data.LongLength - file.SectorSize + file.SectorSize - 1) / file.SectorSize);
        int sectorShift = file.SectorSize == 512 ? 9 : 12;

        if (size == 0)
        {
            return new OleStreamDataResult(OperationState.Ok, null, Array.Empty<byte>());
        }

        var output = new MemoryStream();
        if ((ulong)size < file.MiniStreamCutoff)
        {
            // Mini stream: mini sectors are 64-byte slices of the root storage's own stream,
            // so each read maps mini sector -> container sector -> file offset.
            uint cur = entry.StartSector;
            long remaining = size;
            var visited = new HashSet<uint>();
            while (remaining > 0)
            {
                if (clock.Elapsed >= budget.Deadline)
                {
                    return OleStreamDataResult.NotRead(OperationState.Incomplete, $"'{entry.Path}': deadline exhausted after {output.Length} bytes");
                }
                if (cur > MaxRegularSector)
                {
                    return OleStreamDataResult.NotRead(
                        OperationState.Incomplete,
                        $"'{entry.Path}': mini-FAT chain ends after {output.Length} of {size} declared bytes");
                }
                if (cur >= file.MiniFat.Length)
                {
                    return OleStreamDataResult.NotRead(
                        OperationState.Incomplete,
                        $"'{entry.Path}': mini-FAT chain references mini sector {cur}, beyond the {file.MiniFat.Length}-entry mini-FAT");
                }
                if (!visited.Add(cur))
                {
                    return OleStreamDataResult.NotRead(OperationState.Failed, $"'{entry.Path}': mini-FAT chain cycles back to mini sector {cur}");
                }
                long byteOffset = (long)cur * file.MiniSectorSize;
                long containerIndex = byteOffset / file.SectorSize;
                long within = byteOffset % file.SectorSize;
                if (containerIndex >= file.MiniStreamSectors.Length)
                {
                    return OleStreamDataResult.NotRead(
                        OperationState.Incomplete,
                        $"'{entry.Path}': mini sector {cur} lies beyond the {file.MiniStreamSectors.Length}-sector mini stream");
                }
                long fileOffset = SectorOffset(file.MiniStreamSectors[containerIndex], sectorShift) + within;
                int take = (int)Math.Min(file.MiniSectorSize, remaining);
                if (fileOffset + take > data.Length)
                {
                    return OleStreamDataResult.NotRead(
                        OperationState.Incomplete,
                        $"'{entry.Path}': mini sector {cur} maps past the end of the file at {data.Length}; truncated");
                }
                output.Write(data, (int)fileOffset, take);
                remaining -= take;
                cur = file.MiniFat[cur];
            }
        }
        else
        {
            uint cur = entry.StartSector;
            long remaining = size;
            var visited = new HashSet<uint>();
            long steps = 0;
            while (remaining > 0)
            {
                if (clock.Elapsed >= budget.Deadline)
                {
                    return OleStreamDataResult.NotRead(OperationState.Incomplete, $"'{entry.Path}': deadline exhausted after {output.Length} bytes");
                }
                if (cur > MaxRegularSector)
                {
                    return OleStreamDataResult.NotRead(
                        OperationState.Incomplete,
                        $"'{entry.Path}': FAT chain ends after {output.Length} of {size} declared bytes");
                }
                if (cur >= file.Fat.Length)
                {
                    return OleStreamDataResult.NotRead(
                        OperationState.Incomplete,
                        $"'{entry.Path}': FAT chain references sector {cur}, beyond the {file.Fat.Length}-entry FAT");
                }
                if (!visited.Add(cur) || ++steps > totalSectors)
                {
                    return OleStreamDataResult.NotRead(OperationState.Failed, $"'{entry.Path}': FAT chain cycles back to sector {cur}");
                }
                long off = SectorOffset(cur, sectorShift);
                int take = (int)Math.Min(file.SectorSize, remaining);
                if (off + take > data.Length)
                {
                    return OleStreamDataResult.NotRead(
                        OperationState.Incomplete,
                        $"'{entry.Path}': sector {cur} lies past the end of the file at {data.Length}; truncated");
                }
                output.Write(data, (int)off, take);
                remaining -= take;
                cur = file.Fat[cur];
            }
        }
        return new OleStreamDataResult(OperationState.Ok, null, output.ToArray());
    }

    private static (List<uint> Sectors, string? Error) WalkFatChain(uint start, uint[] fat, long maxSteps)
    {
        var sectors = new List<uint>();
        var visited = new HashSet<uint>();
        uint cur = start;
        while (cur <= MaxRegularSector)
        {
            if (!visited.Add(cur))
            {
                return (sectors, $"cycles back to sector {cur}");
            }
            if (sectors.Count >= maxSteps)
            {
                return (sectors, $"longer than the file's {maxSteps} sectors; lying or cyclic");
            }
            if (cur >= fat.Length)
            {
                return (sectors, $"references sector {cur}, beyond the {fat.Length}-entry FAT");
            }
            sectors.Add(cur);
            cur = fat[cur];
        }
        if (cur != EndOfChain)
        {
            return (sectors, $"terminates in special value 0x{cur:X8} instead of end-of-chain");
        }
        return (sectors, null);
    }

    private static ParsedEntry? ParseDirectoryEntry(byte[] data, long off, int index, ushort major, List<string> reasons)
    {
        int nameLen = U16(data, off + 64);
        byte rawType = data[off + 66];
        if (rawType == 0)
        {
            return null; // unused slot — a reference to it is an anomaly, handled at the reference
        }
        if (nameLen < 2 || nameLen > 64 || nameLen % 2 != 0)
        {
            reasons.Add($"directory entry {index}: name length {nameLen} is invalid (must be even, 2..64); entry unusable");
            return new ParsedEntry(index, string.Empty, rawType, NoStream, NoStream, NoStream, Guid.Empty, 0, 0, Usable: false);
        }
        string name = Encoding.Unicode.GetString(data, (int)off, nameLen - 2);
        ulong size = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan((int)(off + 120), 8));
        if (major == 3)
        {
            // Version 3 writers leave garbage in the high half; only the low 32 bits are real.
            size &= 0xFFFFFFFF;
        }
        return new ParsedEntry(
            index,
            name,
            rawType,
            U32(data, off + 68),
            U32(data, off + 72),
            U32(data, off + 76),
            new Guid(data.AsSpan((int)(off + 80), 16)),
            U32(data, off + 116),
            size,
            Usable: true);
    }

    /// <summary>
    /// In-order traversal of one storage's red-black sibling tree, iterative so a degenerate
    /// 4096-entry chain cannot exhaust the call stack. The visited set is shared across the
    /// whole build: an entry reachable twice means cross-linked trees, which is reported,
    /// not walked twice.
    /// </summary>
    private static IReadOnlyList<OleDirectoryEntryInfo> CollectChildren(
        uint firstChild,
        string parentPath,
        int depth,
        List<ParsedEntry?> entries,
        HashSet<uint> visited,
        List<string> reasons,
        ushort major)
    {
        var children = new List<OleDirectoryEntryInfo>();
        if (firstChild == NoStream)
        {
            return children;
        }
        if (depth > ContainerLimits.MaxOleTreeDepth)
        {
            reasons.Add($"storage '{parentPath}' exceeds the tree depth cap of {ContainerLimits.MaxOleTreeDepth}; children not walked");
            return children;
        }

        var stack = new Stack<uint>();
        uint cur = firstChild;
        while (cur != NoStream || stack.Count > 0)
        {
            while (cur != NoStream)
            {
                if (!TryResolve(cur, entries, visited, reasons, parentPath, out var node))
                {
                    cur = NoStream;
                    break;
                }
                stack.Push(cur);
                cur = node.Left;
            }
            if (stack.Count == 0)
            {
                break;
            }
            uint index = stack.Pop();
            var entry = entries[(int)index]!;
            string path = parentPath.Length == 0 ? entry.Name : parentPath + "/" + entry.Name;
            children.Add(new OleDirectoryEntryInfo
            {
                Index = entry.Index,
                Name = entry.Name,
                Path = path,
                RawType = entry.RawType,
                Type = MapType(entry.RawType),
                StartSector = entry.StartSector,
                Size = entry.Size,
                Clsid = entry.Clsid,
                Children = entry.RawType == 1
                    ? CollectChildren(entry.Child, path, depth + 1, entries, visited, reasons, major)
                    : Array.Empty<OleDirectoryEntryInfo>(),
            });
            cur = entry.Right;
        }
        return children;
    }

    private static bool TryResolve(
        uint index,
        List<ParsedEntry?> entries,
        HashSet<uint> visited,
        List<string> reasons,
        string parentPath,
        out ParsedEntry entry)
    {
        entry = null!;
        if (index >= entries.Count || entries[(int)index] is not { } parsed || !parsed.Usable)
        {
            reasons.Add($"storage '{parentPath}' references directory entry {index}, which is missing or unusable");
            return false;
        }
        if (!visited.Add(index))
        {
            reasons.Add($"directory tree cycles back to entry {index} ('{parsed.Name}'); branch not walked again");
            return false;
        }
        entry = parsed;
        return true;
    }

    private static OleEntryType MapType(byte raw) => raw switch
    {
        1 => OleEntryType.Storage,
        2 => OleEntryType.Stream,
        5 => OleEntryType.RootStorage,
        _ => OleEntryType.Unknown,
    };

    private static long SectorOffset(uint sector, int sectorShift) => ((long)sector + 1) << sectorShift;

    private static int U16(byte[] data, long offset) =>
        BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan((int)offset, 2));

    private static uint U32(byte[] data, long offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)offset, 4));
}
