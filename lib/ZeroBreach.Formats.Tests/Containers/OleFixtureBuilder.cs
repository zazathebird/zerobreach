using System.Text;

namespace ZeroBreach.Formats.Tests.Containers;

/// <summary>
/// Hand-assembles version-3 compound files (512-byte sectors) so tests control the exact
/// sector layout. Allocation order is deterministic: FAT-stream data sectors in call order,
/// then the mini stream's container sectors, then the mini-FAT, then the directory, then the
/// FAT itself — so <see cref="AddFatStream"/> can hand back real sector numbers immediately.
/// The result carries the file offsets of the FAT and directory tables so hostile tests can
/// patch single fields (cycles, wrong types) without re-deriving the layout.
/// </summary>
internal sealed class OleFixtureBuilder
{
    internal const int SectorSize = 512;
    internal const uint EndOfChain = 0xFFFFFFFE;
    internal const uint FreeSector = 0xFFFFFFFF;
    internal const uint FatSectorMark = 0xFFFFFFFD;
    internal const uint NoStream = 0xFFFFFFFF;

    private sealed record DirEntrySpec(string Name, byte Type, uint Left, uint Right, uint Child, uint Start, ulong Size);

    private readonly List<byte[]> _dataSectors = new();
    private readonly List<uint> _dataFatLinks = new(); // parallel: next-sector value for each data sector
    private readonly MemoryStream _miniData = new();
    private readonly List<uint> _miniFat = new();
    private readonly List<DirEntrySpec> _entries = new();
    private uint _rootChild = NoStream;

    internal sealed record Result(byte[] Bytes, int FatTableOffset, int DirTableOffset);

    /// <summary>Adds stream data in FAT space (for streams ≥ 4096 bytes). Returns the start sector.</summary>
    internal uint AddFatStream(byte[] data)
    {
        uint start = (uint)_dataSectors.Count;
        int count = Math.Max(1, (data.Length + SectorSize - 1) / SectorSize);
        for (int i = 0; i < count; i++)
        {
            var sector = new byte[SectorSize];
            int offset = i * SectorSize;
            int take = Math.Min(SectorSize, data.Length - offset);
            if (take > 0)
            {
                Array.Copy(data, offset, sector, 0, take);
            }
            _dataSectors.Add(sector);
            _dataFatLinks.Add(i == count - 1 ? EndOfChain : (uint)(_dataSectors.Count));
        }
        return start;
    }

    /// <summary>Adds stream data in mini-stream space (for streams &lt; 4096 bytes). Returns the start mini sector.</summary>
    internal uint AddMiniStream(byte[] data)
    {
        uint start = (uint)(_miniData.Length / 64);
        int count = Math.Max(1, (data.Length + 63) / 64);
        _miniData.Write(data);
        int pad = count * 64 - data.Length;
        for (int i = 0; i < pad; i++)
        {
            _miniData.WriteByte(0);
        }
        for (int i = 0; i < count; i++)
        {
            _miniFat.Add(i == count - 1 ? EndOfChain : start + (uint)i + 1);
        }
        return start;
    }

    /// <summary>Adds a directory entry. Index 0 is the auto-written root, so the first call here is entry 1.</summary>
    internal void AddDirEntry(string name, byte type, uint left, uint right, uint child, uint start, ulong size) =>
        _entries.Add(new DirEntrySpec(name, type, left, right, child, start, size));

    internal void SetRootChild(uint entryIndex) => _rootChild = entryIndex;

    internal Result Build()
    {
        // --- Allocate the remaining sectors, in the documented order.
        var sectors = new List<byte[]>(_dataSectors);
        var fat = new List<uint>(_dataFatLinks);

        // Mini stream container sectors (the root storage's own FAT chain).
        byte[] miniBytes = _miniData.ToArray();
        uint miniContainerStart = EndOfChain;
        if (miniBytes.Length > 0)
        {
            miniContainerStart = (uint)sectors.Count;
            int count = (miniBytes.Length + SectorSize - 1) / SectorSize;
            for (int i = 0; i < count; i++)
            {
                var sector = new byte[SectorSize];
                int take = Math.Min(SectorSize, miniBytes.Length - i * SectorSize);
                Array.Copy(miniBytes, i * SectorSize, sector, 0, take);
                sectors.Add(sector);
                fat.Add(i == count - 1 ? EndOfChain : (uint)sectors.Count);
            }
        }

        // Mini-FAT sector (tests stay under 128 mini sectors).
        uint miniFatStart = EndOfChain;
        uint miniFatCount = 0;
        if (_miniFat.Count > 0)
        {
            if (_miniFat.Count > SectorSize / 4)
            {
                throw new InvalidOperationException("fixture builder supports at most 128 mini sectors");
            }
            miniFatStart = (uint)sectors.Count;
            miniFatCount = 1;
            var sector = new byte[SectorSize];
            for (int i = 0; i < SectorSize / 4; i++)
            {
                WriteU32(sector, i * 4, i < _miniFat.Count ? _miniFat[i] : FreeSector);
            }
            sectors.Add(sector);
            fat.Add(EndOfChain);
        }

        // Directory sectors: root entry first, then the declared entries, 4 per sector.
        var allEntries = new List<DirEntrySpec>
        {
            new("Root Entry", 5, NoStream, NoStream, _rootChild, miniContainerStart, (ulong)miniBytes.Length),
        };
        allEntries.AddRange(_entries);
        int dirSectorCount = (allEntries.Count + 3) / 4;
        uint dirStart = (uint)sectors.Count;
        for (int s = 0; s < dirSectorCount; s++)
        {
            var sector = new byte[SectorSize];
            for (int j = 0; j < 4; j++)
            {
                int idx = s * 4 + j;
                if (idx < allEntries.Count)
                {
                    WriteDirEntry(sector, j * 128, allEntries[idx]);
                }
            }
            sectors.Add(sector);
            fat.Add(s == dirSectorCount - 1 ? EndOfChain : (uint)sectors.Count);
        }

        // FAT sectors last; they must describe themselves too.
        int entriesPerFatSector = SectorSize / 4;
        int fatSectorCount = 1;
        while (sectors.Count + fatSectorCount > fatSectorCount * entriesPerFatSector)
        {
            fatSectorCount++;
        }
        uint fatStart = (uint)sectors.Count;
        for (int i = 0; i < fatSectorCount; i++)
        {
            fat.Add(FatSectorMark);
        }
        while (fat.Count < fatSectorCount * entriesPerFatSector)
        {
            fat.Add(FreeSector);
        }
        for (int s = 0; s < fatSectorCount; s++)
        {
            var sector = new byte[SectorSize];
            for (int i = 0; i < entriesPerFatSector; i++)
            {
                WriteU32(sector, i * 4, fat[s * entriesPerFatSector + i]);
            }
            sectors.Add(sector);
        }

        // --- Header.
        var header = new byte[SectorSize];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(header, 0);
        WriteU16(header, 24, 0x003E);            // minor version
        WriteU16(header, 26, 3);                 // major version
        WriteU16(header, 28, 0xFFFE);            // byte order
        WriteU16(header, 30, 9);                 // sector shift (512)
        WriteU16(header, 32, 6);                 // mini sector shift (64)
        WriteU32(header, 44, (uint)fatSectorCount);
        WriteU32(header, 48, dirStart);
        WriteU32(header, 56, 4096);              // mini stream cutoff
        WriteU32(header, 60, miniFatStart);
        WriteU32(header, 64, miniFatCount);
        WriteU32(header, 68, EndOfChain);        // first DIFAT sector (none)
        WriteU32(header, 72, 0);                 // DIFAT sector count
        for (int i = 0; i < 109; i++)
        {
            WriteU32(header, 76 + i * 4, i < fatSectorCount ? fatStart + (uint)i : FreeSector);
        }

        var file = new MemoryStream();
        file.Write(header);
        foreach (var sector in sectors)
        {
            file.Write(sector);
        }
        return new Result(
            file.ToArray(),
            FatTableOffset: SectorSize + (int)fatStart * SectorSize,
            DirTableOffset: SectorSize + (int)dirStart * SectorSize);
    }

    private static void WriteDirEntry(byte[] sector, int off, DirEntrySpec e)
    {
        byte[] name = Encoding.Unicode.GetBytes(e.Name);
        if (name.Length > 62)
        {
            throw new InvalidOperationException("directory entry name too long for fixture");
        }
        name.CopyTo(sector, off);
        WriteU16(sector, off + 64, (ushort)(name.Length + 2)); // includes the UTF-16 terminator
        sector[off + 66] = e.Type;
        sector[off + 67] = 1;                                  // black
        WriteU32(sector, off + 68, e.Left);
        WriteU32(sector, off + 72, e.Right);
        WriteU32(sector, off + 76, e.Child);
        WriteU32(sector, off + 116, e.Start);
        WriteU64(sector, off + 120, e.Size);
    }

    internal static void WriteU16(byte[] b, int off, ushort v)
    {
        b[off] = (byte)(v & 0xFF);
        b[off + 1] = (byte)(v >> 8);
    }

    internal static void WriteU32(byte[] b, int off, uint v)
    {
        b[off] = (byte)(v & 0xFF);
        b[off + 1] = (byte)((v >> 8) & 0xFF);
        b[off + 2] = (byte)((v >> 16) & 0xFF);
        b[off + 3] = (byte)(v >> 24);
    }

    internal static void WriteU64(byte[] b, int off, ulong v)
    {
        WriteU32(b, off, (uint)(v & 0xFFFFFFFF));
        WriteU32(b, off + 4, (uint)(v >> 32));
    }
}
