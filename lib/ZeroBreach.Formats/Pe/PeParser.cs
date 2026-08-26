using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;

namespace ZeroBreach.Formats.Pe;

/// <summary>
/// Static Portable Executable parser (BLUEPRINT §6). Reads a byte buffer; nothing is loaded,
/// mapped, relocated or executed. Hostile input is the normal case: every field read is
/// bounds-checked, every file-supplied size and offset is validated in 64-bit arithmetic
/// before use, and no input — truncated, lying, cyclic or oversized — makes this throw.
/// </summary>
public static class PeParser
{
    /// <summary>
    /// Parse <paramref name="file"/> under <paramref name="budget"/>. Never throws on any
    /// input content; see <see cref="PeParseResult"/> for the state rules.
    /// </summary>
    public static PeParseResult Parse(ReadOnlyMemory<byte> file, ScanBudget budget)
    {
        ArgumentNullException.ThrowIfNull(budget);
        return new PeParseSession(file, budget).Run();
    }

    /// <summary>
    /// Fetch the certificate directory's raw bytes on demand (the parse itself records only
    /// presence, offset and size). Returns null when the recorded range does not lie fully
    /// inside <paramref name="file"/> — a lying header must not become an exception here.
    /// </summary>
    public static byte[]? GetCertificateBytes(ReadOnlyMemory<byte> file, PeCertificateInfo certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (certificate.Size == 0)
            return null;
        long end = (long)certificate.Offset + certificate.Size;
        if (certificate.Offset >= file.Length || end > file.Length)
            return null;
        return file.Span.Slice((int)certificate.Offset, (int)certificate.Size).ToArray();
    }
}

/// <summary>One parse over one buffer. Instance state is the buffer, the budget, the clock and the reason list.</summary>
internal sealed class PeParseSession
{
    // Data directory indexes (PE spec order).
    private const int DirExport = 0;
    private const int DirImport = 1;
    private const int DirResource = 2;
    private const int DirCertificate = 4;
    private const int DirDebug = 6;
    private const int DirTls = 9;

    private const uint ScnMemExecute = 0x2000_0000;
    private const uint ScnMemWrite = 0x8000_0000;

    private static readonly string[] DirectoryNames =
    {
        "Export", "Import", "Resource", "Exception", "Certificate", "BaseRelocation",
        "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
        "IAT", "DelayImport", "ClrRuntime", "Reserved",
    };

    private readonly ReadOnlyMemory<byte> _data;
    private readonly ScanBudget _budget;
    private readonly List<string> _reasons = new();
    private readonly Stopwatch _clock = new();
    private bool _deadlineReported;

    private long Length => _data.Length;
    private ReadOnlySpan<byte> Span => _data.Span;

    internal PeParseSession(ReadOnlyMemory<byte> data, ScanBudget budget)
    {
        _data = data;
        _budget = budget;
    }

    internal PeParseResult Run()
    {
        // Input-size budget: refuse before touching anything, distinctly — never a silent Ok.
        if (Length > _budget.MaxInputBytes)
            return PeParseResult.IncompleteWithoutImage(
                $"input is {Length} bytes; budget MaxInputBytes is {_budget.MaxInputBytes}");

        _clock.Start();

        // ---- DOS header -------------------------------------------------------------
        if (Length < 2)
            return PeParseResult.Fail($"file is {Length} byte(s); too short for the 2-byte MZ signature", 0);
        if (!TryU16(0, out ushort mzMagic) || mzMagic != 0x5A4D)
            return PeParseResult.Fail($"missing MZ signature at offset 0 (found 0x{ReadU16Unchecked(0):X4})", 0);
        if (Length < 0x40)
            return PeParseResult.Fail($"truncated DOS header: file is {Length} bytes, the header needs 64", Length);

        uint lfanew = ReadU32Unchecked(0x3C);
        if (lfanew > int.MaxValue || (long)lfanew + 4 > Length)
            return PeParseResult.Fail($"e_lfanew 0x{lfanew:X} points outside the {Length}-byte file", 0x3C);
        if (ReadU32Unchecked(lfanew) != 0x0000_4550) // "PE\0\0"
            return PeParseResult.Fail($"missing PE signature at offset 0x{lfanew:X}", lfanew);

        var dosHeader = new PeDosHeader(mzMagic, lfanew);

        // ---- COFF file header -------------------------------------------------------
        long coffOffset = lfanew + 4;
        if (coffOffset + 20 > Length)
            return PeParseResult.Fail($"truncated COFF file header at offset 0x{coffOffset:X}: need 20 bytes, file ends at 0x{Length:X}", coffOffset);

        var fileHeader = new PeFileHeader(
            Machine: ReadU16Unchecked(coffOffset),
            NumberOfSections: ReadU16Unchecked(coffOffset + 2),
            TimeDateStamp: ReadU32Unchecked(coffOffset + 4),
            PointerToSymbolTable: ReadU32Unchecked(coffOffset + 8),
            NumberOfSymbols: ReadU32Unchecked(coffOffset + 12),
            SizeOfOptionalHeader: ReadU16Unchecked(coffOffset + 16),
            Characteristics: ReadU16Unchecked(coffOffset + 18));

        // ---- Optional header --------------------------------------------------------
        long optOffset = coffOffset + 20;
        if (fileHeader.SizeOfOptionalHeader < 2)
            return PeParseResult.Fail($"SizeOfOptionalHeader is {fileHeader.SizeOfOptionalHeader}; no room for an optional-header magic", coffOffset + 16);
        if (optOffset + 2 > Length)
            return PeParseResult.Fail($"truncated optional header at offset 0x{optOffset:X}: magic does not fit", optOffset);

        ushort optMagic = ReadU16Unchecked(optOffset);
        if (optMagic is not (0x10B or 0x20B))
            return PeParseResult.Fail($"unknown optional-header magic 0x{optMagic:X} (expected 0x10B for PE32 or 0x20B for PE32+)", optOffset);
        bool isPe32Plus = optMagic == 0x20B;
        PeOptionalHeader optionalHeader;
        {
            int fixedSize = isPe32Plus ? 112 : 96;
            if (optOffset + fixedSize > Length)
                return PeParseResult.Fail(
                    $"truncated optional header: {(isPe32Plus ? "PE32+" : "PE32")} needs {fixedSize} bytes at offset 0x{optOffset:X}, file ends at 0x{Length:X}", Length);
            if (fileHeader.SizeOfOptionalHeader < fixedSize)
                return PeParseResult.Fail(
                    $"SizeOfOptionalHeader is {fileHeader.SizeOfOptionalHeader}, too small for the {(isPe32Plus ? "PE32+" : "PE32")} fixed fields ({fixedSize})", coffOffset + 16);

            optionalHeader = ReadOptionalHeader(optOffset, isPe32Plus, optMagic);
        }

        // ---- Data directories -------------------------------------------------------
        var directories = ReadDataDirectories(optOffset, isPe32Plus, fileHeader.SizeOfOptionalHeader,
            optionalHeader.NumberOfRvaAndSizes, out (uint Rva, uint Size)[] dirSlots);

        // ---- Section table ----------------------------------------------------------
        var sections = ReadSectionTable(optOffset + fileHeader.SizeOfOptionalHeader, fileHeader.NumberOfSections);

        // ---- Directory-driven structures (attacker-amplifiable; each is deadline-gated) ----
        var imports = Array.Empty<PeImportedDll>() as IReadOnlyList<PeImportedDll>;
        PeExports? exports = null;
        PeResourceNode? resourceRoot = null;
        PeCertificateInfo? certificate = null;
        IReadOnlyList<PeDebugEntry> debugEntries = Array.Empty<PeDebugEntry>();
        PeRichHeader? richHeader = null;
        PeTlsInfo? tls = null;

        var mapper = new RvaMapper(sections, optionalHeader.SizeOfHeaders, Length);

        if (!Deadline("directory parsing"))
        {
            if (!Deadline("import parsing"))
                imports = ParseImports(dirSlots[DirImport], mapper, isPe32Plus);
            if (!Deadline("export parsing"))
                exports = ParseExports(dirSlots[DirExport], mapper);
            if (!Deadline("resource parsing"))
                resourceRoot = ParseResources(dirSlots[DirResource], mapper);
            certificate = ParseCertificate(dirSlots[DirCertificate]);
            if (!Deadline("debug-directory parsing"))
                debugEntries = ParseDebug(dirSlots[DirDebug], mapper);
            richHeader = ParseRichHeader(lfanew);
            if (!Deadline("TLS parsing"))
                tls = ParseTls(dirSlots[DirTls], mapper, isPe32Plus, optionalHeader.ImageBase);
        }

        var image = new PeImage(dosHeader, fileHeader, optionalHeader, directories, sections,
            imports, exports, resourceRoot, certificate, debugEntries, richHeader, tls);

        // Metrics are bounded by the input size (already under MaxInputBytes), not by header
        // counts, so they are computed even when the deadline stopped the directory walks —
        // a partially parsed file still gets honest entropy/overlay numbers.
        var metrics = ComputeMetrics(image);

        return PeParseResult.FromParse(_reasons, image, metrics);
    }

    // ---------------------------------------------------------------- deadline / reasons

    /// <summary>
    /// True once the wall-clock budget is spent. The first trip records the reason with the
    /// stage name; callers then skip the stage. A zero deadline trips immediately — that is
    /// the canary the test suite relies on, so the comparison is deliberately >=.
    /// </summary>
    private bool Deadline(string stage)
    {
        if (_clock.Elapsed < _budget.Deadline)
            return false;
        if (!_deadlineReported)
        {
            _deadlineReported = true;
            _reasons.Add($"time budget of {_budget.Deadline.TotalMilliseconds:0}ms exceeded; {stage} and later structures skipped");
        }
        return true;
    }

    private void Reason(string text) => _reasons.Add(text);

    // ---------------------------------------------------------------- headers

    private PeOptionalHeader ReadOptionalHeader(long o, bool plus, ushort magic)
    {
        // Field offsets differ between PE32 and PE32+ from ImageBase onward; widths that
        // differ are stored at the wider (64-bit) width per the PeOptionalHeader contract.
        if (!plus)
        {
            return new PeOptionalHeader(
                Magic: magic, IsPe32Plus: false,
                MajorLinkerVersion: Span[(int)(o + 2)], MinorLinkerVersion: Span[(int)(o + 3)],
                SizeOfCode: ReadU32Unchecked(o + 4),
                SizeOfInitializedData: ReadU32Unchecked(o + 8),
                SizeOfUninitializedData: ReadU32Unchecked(o + 12),
                AddressOfEntryPoint: ReadU32Unchecked(o + 16),
                BaseOfCode: ReadU32Unchecked(o + 20),
                BaseOfData: ReadU32Unchecked(o + 24),
                ImageBase: ReadU32Unchecked(o + 28),
                SectionAlignment: ReadU32Unchecked(o + 32),
                FileAlignment: ReadU32Unchecked(o + 36),
                MajorOperatingSystemVersion: ReadU16Unchecked(o + 40),
                MinorOperatingSystemVersion: ReadU16Unchecked(o + 42),
                MajorImageVersion: ReadU16Unchecked(o + 44),
                MinorImageVersion: ReadU16Unchecked(o + 46),
                MajorSubsystemVersion: ReadU16Unchecked(o + 48),
                MinorSubsystemVersion: ReadU16Unchecked(o + 50),
                Win32VersionValue: ReadU32Unchecked(o + 52),
                SizeOfImage: ReadU32Unchecked(o + 56),
                SizeOfHeaders: ReadU32Unchecked(o + 60),
                CheckSum: ReadU32Unchecked(o + 64),
                Subsystem: ReadU16Unchecked(o + 68),
                DllCharacteristics: ReadU16Unchecked(o + 70),
                SizeOfStackReserve: ReadU32Unchecked(o + 72),
                SizeOfStackCommit: ReadU32Unchecked(o + 76),
                SizeOfHeapReserve: ReadU32Unchecked(o + 80),
                SizeOfHeapCommit: ReadU32Unchecked(o + 84),
                LoaderFlags: ReadU32Unchecked(o + 88),
                NumberOfRvaAndSizes: ReadU32Unchecked(o + 92));
        }

        return new PeOptionalHeader(
            Magic: magic, IsPe32Plus: true,
            MajorLinkerVersion: Span[(int)(o + 2)], MinorLinkerVersion: Span[(int)(o + 3)],
            SizeOfCode: ReadU32Unchecked(o + 4),
            SizeOfInitializedData: ReadU32Unchecked(o + 8),
            SizeOfUninitializedData: ReadU32Unchecked(o + 12),
            AddressOfEntryPoint: ReadU32Unchecked(o + 16),
            BaseOfCode: ReadU32Unchecked(o + 20),
            BaseOfData: null, // PE32+ has no BaseOfData
            ImageBase: ReadU64Unchecked(o + 24),
            SectionAlignment: ReadU32Unchecked(o + 32),
            FileAlignment: ReadU32Unchecked(o + 36),
            MajorOperatingSystemVersion: ReadU16Unchecked(o + 40),
            MinorOperatingSystemVersion: ReadU16Unchecked(o + 42),
            MajorImageVersion: ReadU16Unchecked(o + 44),
            MinorImageVersion: ReadU16Unchecked(o + 46),
            MajorSubsystemVersion: ReadU16Unchecked(o + 48),
            MinorSubsystemVersion: ReadU16Unchecked(o + 50),
            Win32VersionValue: ReadU32Unchecked(o + 52),
            SizeOfImage: ReadU32Unchecked(o + 56),
            SizeOfHeaders: ReadU32Unchecked(o + 60),
            CheckSum: ReadU32Unchecked(o + 64),
            Subsystem: ReadU16Unchecked(o + 68),
            DllCharacteristics: ReadU16Unchecked(o + 70),
            SizeOfStackReserve: ReadU64Unchecked(o + 72),
            SizeOfStackCommit: ReadU64Unchecked(o + 80),
            SizeOfHeapReserve: ReadU64Unchecked(o + 88),
            SizeOfHeapCommit: ReadU64Unchecked(o + 96),
            LoaderFlags: ReadU32Unchecked(o + 104),
            NumberOfRvaAndSizes: ReadU32Unchecked(o + 108));
    }

    /// <summary>
    /// Reads the data directory table. Returns the non-empty slots for reporting and fills
    /// <paramref name="slots"/> with all 16 (zeroed where absent or unreadable) for internal use.
    /// </summary>
    private IReadOnlyList<PeDataDirectory> ReadDataDirectories(
        long optOffset, bool plus, ushort sizeOfOptionalHeader, uint declaredCount, out (uint Rva, uint Size)[] slots)
    {
        slots = new (uint, uint)[PeParserLimits.MaxDataDirectories];
        long tableOffset = optOffset + (plus ? 112 : 96);

        int count = (int)Math.Min(declaredCount, PeParserLimits.MaxDataDirectories);
        if (declaredCount > PeParserLimits.MaxDataDirectories)
            Reason($"NumberOfRvaAndSizes is {declaredCount}; only the {PeParserLimits.MaxDataDirectories} defined directories are read");

        // The table must also fit inside the declared optional header and inside the file.
        int roomInHeader = (sizeOfOptionalHeader - (plus ? 112 : 96)) / 8;
        if (roomInHeader < count)
        {
            Reason($"SizeOfOptionalHeader {sizeOfOptionalHeader} leaves room for {roomInHeader} data directories; {count} declared");
            count = Math.Max(roomInHeader, 0);
        }

        var result = new List<PeDataDirectory>();
        for (int i = 0; i < count; i++)
        {
            long entry = tableOffset + i * 8L;
            if (entry + 8 > Length)
            {
                Reason($"data directory table truncated at entry {i} (offset 0x{entry:X}); remaining entries unread");
                break;
            }
            uint rva = ReadU32Unchecked(entry);
            uint size = ReadU32Unchecked(entry + 4);
            slots[i] = (rva, size);
            if (rva != 0 || size != 0)
                result.Add(new PeDataDirectory(i, DirectoryNames[i], rva, size));
        }
        return result;
    }

    private IReadOnlyList<PeSection> ReadSectionTable(long tableOffset, int declaredCount)
    {
        if (declaredCount > PeParserLimits.MaxSections)
        {
            // Beyond the loader's own limit the count is corrupt by definition; walking it
            // would just read garbage, so the table is not read at all (PeParserLimits).
            Reason($"section count {declaredCount} exceeds cap {PeParserLimits.MaxSections}; section table not read");
            return Array.Empty<PeSection>();
        }

        var sections = new List<PeSection>(declaredCount);
        for (int i = 0; i < declaredCount; i++)
        {
            long entry = tableOffset + i * 40L;
            if (entry + 40 > Length)
            {
                Reason($"section table truncated: entry {i} of {declaredCount} at offset 0x{entry:X} runs past end of file");
                break;
            }
            // Name: 8 bytes, Latin-1 up to the first NUL, so unusual bytes survive.
            var nameBytes = Span.Slice((int)entry, 8);
            int nul = nameBytes.IndexOf((byte)0);
            string name = Encoding.Latin1.GetString(nul < 0 ? nameBytes : nameBytes[..nul]);

            sections.Add(new PeSection(
                Name: name,
                VirtualSize: ReadU32Unchecked(entry + 8),
                VirtualAddress: ReadU32Unchecked(entry + 12),
                SizeOfRawData: ReadU32Unchecked(entry + 16),
                PointerToRawData: ReadU32Unchecked(entry + 20),
                Characteristics: ReadU32Unchecked(entry + 36)));
        }
        return sections;
    }

    // ---------------------------------------------------------------- imports

    private IReadOnlyList<PeImportedDll> ParseImports((uint Rva, uint Size) dir, RvaMapper map, bool plus)
    {
        if (dir.Rva == 0)
            return Array.Empty<PeImportedDll>();

        long? tableOffset = map.ToOffset(dir.Rva);
        if (tableOffset is null)
        {
            Reason($"import directory RVA 0x{dir.Rva:X} maps to no file data");
            return Array.Empty<PeImportedDll>();
        }

        var dlls = new List<PeImportedDll>();
        int i = 0;
        for (; i < PeParserLimits.MaxImportDescriptors; i++)
        {
            if (Deadline("import-descriptor walk"))
                break;
            long d = tableOffset.Value + i * 20L;
            if (d + 20 > Length)
            {
                Reason($"import descriptor {i} at offset 0x{d:X} runs past end of file; descriptor walk stopped");
                break;
            }
            uint originalFirstThunk = ReadU32Unchecked(d);
            uint nameRva = ReadU32Unchecked(d + 12);
            uint firstThunk = ReadU32Unchecked(d + 16);
            if (originalFirstThunk == 0 && ReadU32Unchecked(d + 4) == 0 && ReadU32Unchecked(d + 8) == 0
                && nameRva == 0 && firstThunk == 0)
                break; // all-zero terminator

            string? dllName = null;
            if (nameRva != 0)
            {
                dllName = ReadAsciiStringAtRva(map, nameRva, $"import descriptor {i} DLL name");
            }
            else
            {
                Reason($"import descriptor {i} has a zero name RVA");
            }

            // The import name table (OriginalFirstThunk) carries names/ordinals even after
            // binding; fall back to FirstThunk when the INT is absent, as the loader does.
            uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            var functions = new List<PeImportFunction>();
            if (thunkRva == 0)
            {
                Reason($"import descriptor {i} ({dllName ?? "<unnamed>"}) has no thunk array");
            }
            else
            {
                ParseThunks(map, thunkRva, plus, dllName ?? $"descriptor {i}", functions);
            }
            dlls.Add(new PeImportedDll(dllName, functions));
        }
        if (i == PeParserLimits.MaxImportDescriptors)
            Reason($"import descriptor count exceeds cap {PeParserLimits.MaxImportDescriptors}; descriptor walk stopped");
        return dlls;
    }

    private void ParseThunks(RvaMapper map, uint thunkRva, bool plus, string owner, List<PeImportFunction> into)
    {
        long? start = map.ToOffset(thunkRva);
        if (start is null)
        {
            Reason($"import thunk array RVA 0x{thunkRva:X} for {owner} maps to no file data");
            return;
        }
        int entrySize = plus ? 8 : 4;
        ulong ordinalFlag = plus ? 0x8000_0000_0000_0000 : 0x8000_0000;

        int t = 0;
        for (; t < PeParserLimits.MaxThunksPerDescriptor; t++)
        {
            if (Deadline("import-thunk walk"))
                return;
            long o = start.Value + (long)t * entrySize;
            if (o + entrySize > Length)
            {
                Reason($"import thunk array for {owner} runs past end of file at offset 0x{o:X}");
                return;
            }
            ulong value = plus ? ReadU64Unchecked(o) : ReadU32Unchecked(o);
            if (value == 0)
                return; // terminator

            if ((value & ordinalFlag) != 0)
            {
                // Import by ordinal: only the low 16 bits are the ordinal.
                into.Add(new PeImportFunction(null, (ushort)(value & 0xFFFF), null));
                continue;
            }

            ulong hintNameRva = value & ~ordinalFlag;
            if (hintNameRva > uint.MaxValue)
            {
                Reason($"import thunk 0x{value:X} for {owner} has bits set above the 32-bit RVA range");
                into.Add(new PeImportFunction(null, null, null));
                continue;
            }
            long? hn = map.ToOffset((uint)hintNameRva);
            if (hn is null || hn.Value + 2 > Length)
            {
                Reason($"import hint/name RVA 0x{hintNameRva:X} for {owner} maps to no file data");
                into.Add(new PeImportFunction(null, null, null));
                continue;
            }
            ushort hint = ReadU16Unchecked(hn.Value);
            string? name = ReadAsciiString(hn.Value + 2, $"import name for {owner}");
            into.Add(new PeImportFunction(name, null, hint));
        }
        Reason($"import thunk count for {owner} exceeds cap {PeParserLimits.MaxThunksPerDescriptor}; thunk walk stopped");
    }

    // ---------------------------------------------------------------- exports

    private PeExports? ParseExports((uint Rva, uint Size) dir, RvaMapper map)
    {
        if (dir.Rva == 0)
            return null;
        long? o = map.ToOffset(dir.Rva);
        if (o is null || o.Value + 40 > Length)
        {
            Reason($"export directory RVA 0x{dir.Rva:X} maps to no readable 40-byte directory");
            return null;
        }

        uint timeDateStamp = ReadU32Unchecked(o.Value + 4);
        uint nameRva = ReadU32Unchecked(o.Value + 12);
        uint ordinalBase = ReadU32Unchecked(o.Value + 16);
        uint numFuncs = ReadU32Unchecked(o.Value + 20);
        uint numNames = ReadU32Unchecked(o.Value + 24);
        uint addrFuncs = ReadU32Unchecked(o.Value + 28);
        uint addrNames = ReadU32Unchecked(o.Value + 32);
        uint addrOrds = ReadU32Unchecked(o.Value + 36);

        if (numFuncs > PeParserLimits.MaxExportEntries)
        {
            Reason($"export function count {numFuncs} exceeds cap {PeParserLimits.MaxExportEntries}; clamped");
            numFuncs = PeParserLimits.MaxExportEntries;
        }
        if (numNames > PeParserLimits.MaxExportEntries)
        {
            Reason($"export name count {numNames} exceeds cap {PeParserLimits.MaxExportEntries}; clamped");
            numNames = PeParserLimits.MaxExportEntries;
        }

        string? dllName = nameRva != 0 ? ReadAsciiStringAtRva(map, nameRva, "export DLL name") : null;

        uint[] funcRvas = ReadU32Array(map, addrFuncs, numFuncs, "export address table");
        uint[] nameRvas = ReadU32Array(map, addrNames, numNames, "export name pointer table");
        ushort[] nameOrds = ReadU16Array(map, addrOrds, numNames, "export ordinal table");

        // Names per function index, resolved up front so entry construction is one pass.
        var namesByIndex = new Dictionary<uint, List<string>>();
        int nameCount = Math.Min(nameRvas.Length, nameOrds.Length);
        for (int j = 0; j < nameCount; j++)
        {
            if (Deadline("export-name walk"))
                break;
            string? name = ReadAsciiStringAtRva(map, nameRvas[j], $"export name {j}");
            if (name is null)
                continue;
            uint index = nameOrds[j];
            if (index >= funcRvas.Length)
            {
                Reason($"export name '{name}' has ordinal-table index {index}, beyond the {funcRvas.Length}-entry address table");
                continue;
            }
            if (!namesByIndex.TryGetValue(index, out var list))
                namesByIndex[index] = list = new List<string>();
            list.Add(name);
        }

        long dirStart = dir.Rva;
        long dirEnd = (long)dir.Rva + dir.Size;
        var entries = new List<PeExportEntry>();
        for (uint i = 0; i < funcRvas.Length; i++)
        {
            uint rva = funcRvas[i];
            // An RVA back inside the export directory itself is a forwarder string, not code.
            string? forwarder = null;
            if (rva >= dirStart && rva < dirEnd)
                forwarder = ReadAsciiStringAtRva(map, rva, $"export forwarder for ordinal {ordinalBase + i}");

            namesByIndex.TryGetValue(i, out var names);
            if (names is null)
            {
                if (rva != 0)
                    entries.Add(new PeExportEntry(null, ordinalBase + i, rva, forwarder));
                // rva == 0 with no name is an unused slot: nothing to report.
                continue;
            }
            foreach (string name in names)
                entries.Add(new PeExportEntry(name, ordinalBase + i, rva == 0 ? null : rva, forwarder));
        }

        return new PeExports(dllName, ordinalBase, timeDateStamp, entries);
    }

    private uint[] ReadU32Array(RvaMapper map, uint rva, uint count, string what)
    {
        if (count == 0)
            return Array.Empty<uint>();
        long? o = map.ToOffset(rva);
        if (o is null)
        {
            Reason($"{what} RVA 0x{rva:X} maps to no file data");
            return Array.Empty<uint>();
        }
        long readable = Math.Min(count, (Length - o.Value) / 4);
        if (readable < count)
            Reason($"{what} truncated: {readable} of {count} entries readable");
        var result = new uint[readable];
        for (long i = 0; i < readable; i++)
            result[i] = ReadU32Unchecked(o.Value + i * 4);
        return result;
    }

    private ushort[] ReadU16Array(RvaMapper map, uint rva, uint count, string what)
    {
        if (count == 0)
            return Array.Empty<ushort>();
        long? o = map.ToOffset(rva);
        if (o is null)
        {
            Reason($"{what} RVA 0x{rva:X} maps to no file data");
            return Array.Empty<ushort>();
        }
        long readable = Math.Min(count, (Length - o.Value) / 2);
        if (readable < count)
            Reason($"{what} truncated: {readable} of {count} entries readable");
        var result = new ushort[readable];
        for (long i = 0; i < readable; i++)
            result[i] = ReadU16Unchecked(o.Value + i * 2);
        return result;
    }

    // ---------------------------------------------------------------- resources

    private PeResourceNode? ParseResources((uint Rva, uint Size) dir, RvaMapper map)
    {
        if (dir.Rva == 0)
            return null;
        long? baseOffset = map.ToOffset(dir.Rva);
        if (baseOffset is null)
        {
            Reason($"resource directory RVA 0x{dir.Rva:X} maps to no file data");
            return null;
        }

        // Cycle guard: offsets already entered as directory nodes. A resource tree that
        // references itself is a routine hostile input, not an exceptional one.
        var visited = new HashSet<uint>();
        int nodeCount = 0;
        int depthCap = Math.Min(PeParserLimits.MaxResourceDepth, _budget.MaxNestingDepth);

        return ReadResourceDirectory(baseOffset.Value, rel: 0, depth: 0, name: null, id: null,
            visited, ref nodeCount, depthCap);
    }

    private PeResourceNode ReadResourceDirectory(long baseOffset, uint rel, int depth, string? name, uint? id,
        HashSet<uint> visited, ref int nodeCount, int depthCap)
    {
        var empty = new PeResourceNode(name, id, Array.Empty<PeResourceNode>(), null);
        if (depth > depthCap)
        {
            Reason($"resource tree depth exceeds cap {depthCap}; subtree at offset 0x{rel:X} not descended");
            return empty;
        }
        if (!visited.Add(rel))
        {
            Reason($"resource directory at offset 0x{rel:X} referenced again (cycle); not descended");
            return empty;
        }
        if (++nodeCount > PeParserLimits.MaxResourceNodes)
        {
            Reason($"resource node count exceeds cap {PeParserLimits.MaxResourceNodes}; tree walk stopped");
            return empty;
        }

        long header = baseOffset + rel;
        if (header + 16 > Length)
        {
            Reason($"resource directory header at offset 0x{header:X} runs past end of file");
            return empty;
        }
        int namedCount = ReadU16Unchecked(header + 12);
        int idCount = ReadU16Unchecked(header + 14);
        int total = namedCount + idCount;

        var children = new List<PeResourceNode>(Math.Min(total, 64));
        for (int e = 0; e < total; e++)
        {
            if (Deadline("resource-tree walk"))
                break;
            long entry = header + 16 + e * 8L;
            if (entry + 8 > Length)
            {
                Reason($"resource directory entry {e} at offset 0x{entry:X} runs past end of file; remaining entries unread");
                break;
            }
            uint nameField = ReadU32Unchecked(entry);
            uint dataField = ReadU32Unchecked(entry + 4);

            string? childName = null;
            uint? childId = null;
            if ((nameField & 0x8000_0000) != 0)
                childName = ReadResourceName(baseOffset, nameField & 0x7FFF_FFFF);
            else
                childId = nameField;

            if ((dataField & 0x8000_0000) != 0)
            {
                children.Add(ReadResourceDirectory(baseOffset, dataField & 0x7FFF_FFFF, depth + 1,
                    childName, childId, visited, ref nodeCount, depthCap));
            }
            else
            {
                long dataEntry = baseOffset + dataField;
                if (dataEntry + 16 > Length)
                {
                    Reason($"resource data entry at offset 0x{dataEntry:X} runs past end of file");
                    children.Add(new PeResourceNode(childName, childId, Array.Empty<PeResourceNode>(), null));
                    continue;
                }
                if (++nodeCount > PeParserLimits.MaxResourceNodes)
                {
                    Reason($"resource node count exceeds cap {PeParserLimits.MaxResourceNodes}; tree walk stopped");
                    break;
                }
                var data = new PeResourceData(
                    Rva: ReadU32Unchecked(dataEntry),
                    Size: ReadU32Unchecked(dataEntry + 4),
                    CodePage: ReadU32Unchecked(dataEntry + 8));
                children.Add(new PeResourceNode(childName, childId, Array.Empty<PeResourceNode>(), data));
            }
        }
        return new PeResourceNode(name, id, children, null);
    }

    private string? ReadResourceName(long baseOffset, uint rel)
    {
        long o = baseOffset + rel;
        if (o + 2 > Length)
        {
            Reason($"resource name at offset 0x{o:X} runs past end of file");
            return null;
        }
        int chars = ReadU16Unchecked(o);
        long bytes = chars * 2L;
        if (o + 2 + bytes > Length)
        {
            Reason($"resource name at offset 0x{o:X} declares {chars} characters, running past end of file");
            return null;
        }
        return Encoding.Unicode.GetString(Span.Slice((int)(o + 2), (int)bytes));
    }

    // ---------------------------------------------------------------- certificate / debug / rich / TLS

    private PeCertificateInfo? ParseCertificate((uint Rva, uint Size) dir)
    {
        if (dir.Rva == 0 && dir.Size == 0)
            return null;
        // This is the one directory whose "VirtualAddress" is a raw file offset, not an RVA.
        var info = new PeCertificateInfo(dir.Rva, dir.Size);
        long end = (long)dir.Rva + dir.Size;
        if (dir.Rva >= Length || end > Length)
            Reason($"certificate directory [0x{dir.Rva:X}..0x{end:X}) extends past end of file (0x{Length:X} bytes)");
        return info;
    }

    private IReadOnlyList<PeDebugEntry> ParseDebug((uint Rva, uint Size) dir, RvaMapper map)
    {
        if (dir.Rva == 0)
            return Array.Empty<PeDebugEntry>();
        long? o = map.ToOffset(dir.Rva);
        if (o is null)
        {
            Reason($"debug directory RVA 0x{dir.Rva:X} maps to no file data");
            return Array.Empty<PeDebugEntry>();
        }
        const int entrySize = 28;
        if (dir.Size % entrySize != 0)
            Reason($"debug directory size {dir.Size} is not a multiple of {entrySize}; trailing bytes ignored");
        long count = dir.Size / entrySize;
        if (count > PeParserLimits.MaxDebugEntries)
        {
            Reason($"debug entry count {count} exceeds cap {PeParserLimits.MaxDebugEntries}; clamped");
            count = PeParserLimits.MaxDebugEntries;
        }

        var entries = new List<PeDebugEntry>((int)count);
        for (long i = 0; i < count; i++)
        {
            long e = o.Value + i * entrySize;
            if (e + entrySize > Length)
            {
                Reason($"debug directory entry {i} at offset 0x{e:X} runs past end of file; remaining entries unread");
                break;
            }
            uint type = ReadU32Unchecked(e + 12);
            uint sizeOfData = ReadU32Unchecked(e + 16);
            uint addressOfRawData = ReadU32Unchecked(e + 20);
            uint pointerToRawData = ReadU32Unchecked(e + 24);

            Guid? pdbGuid = null;
            uint? pdbAge = null;
            string? pdbPath = null;
            if (type == 2) // IMAGE_DEBUG_TYPE_CODEVIEW
            {
                // PointerToRawData is already a file offset; prefer it, fall back to the RVA.
                long? cv = pointerToRawData != 0 ? pointerToRawData : map.ToOffset(addressOfRawData);
                if (cv is null || cv.Value + 24 > Length || sizeOfData < 24)
                {
                    Reason($"debug entry {i}: CodeView record at offset 0x{cv ?? addressOfRawData:X} is unreadable or too small");
                }
                else if (ReadU32Unchecked(cv.Value) == 0x5344_5352) // "RSDS"
                {
                    pdbGuid = new Guid(Span.Slice((int)(cv.Value + 4), 16));
                    pdbAge = ReadU32Unchecked(cv.Value + 20);
                    long pathStart = cv.Value + 24;
                    long pathCap = Math.Min(Math.Min(sizeOfData - 24, PeParserLimits.MaxNameLength), Length - pathStart);
                    var pathBytes = Span.Slice((int)pathStart, (int)pathCap);
                    int nul = pathBytes.IndexOf((byte)0);
                    pdbPath = Encoding.UTF8.GetString(nul < 0 ? pathBytes : pathBytes[..nul]);
                }
            }
            entries.Add(new PeDebugEntry(type, ReadU32Unchecked(e + 4), sizeOfData,
                addressOfRawData, pointerToRawData, pdbGuid, pdbAge, pdbPath));
        }
        return entries;
    }

    private PeRichHeader? ParseRichHeader(uint lfanew)
    {
        // The Rich header is undocumented: "DanS" XOR key, entries, then "Rich" + key, all in
        // the DOS stub. A block that does not decode cleanly is treated as absent — absence
        // is not an anomaly and a garbled stub is not worth an Incomplete on its own.
        long scanEnd = Math.Min(lfanew, Length) - 8;
        for (long pos = 0x40; pos <= scanEnd; pos += 4)
        {
            if (ReadU32Unchecked(pos) != 0x6863_6952) // "Rich"
                continue;
            uint key = ReadU32Unchecked(pos + 4);
            long dans = -1;
            for (long d = pos - 8; d >= 0x40; d -= 4)
            {
                if ((ReadU32Unchecked(d) ^ key) == 0x536E_6144) // "DanS"
                {
                    dans = d;
                    break;
                }
            }
            if (dans < 0)
                continue;
            long entriesStart = dans + 16; // DanS + three padding dwords
            long entriesBytes = pos - entriesStart;
            if (entriesBytes < 0 || entriesBytes % 8 != 0)
                continue;

            var entries = new List<PeRichEntry>((int)(entriesBytes / 8));
            for (long e = entriesStart; e < pos; e += 8)
            {
                uint compId = ReadU32Unchecked(e) ^ key;
                uint count = ReadU32Unchecked(e + 4) ^ key;
                entries.Add(new PeRichEntry((ushort)(compId >> 16), (ushort)(compId & 0xFFFF), count));
            }
            return new PeRichHeader(key, entries);
        }
        return null;
    }

    private PeTlsInfo? ParseTls((uint Rva, uint Size) dir, RvaMapper map, bool plus, ulong imageBase)
    {
        if (dir.Rva == 0)
            return null;

        int structSize = plus ? 40 : 24;
        long? o = map.ToOffset(dir.Rva);
        if (o is null || o.Value + structSize > Length)
        {
            Reason($"TLS directory RVA 0x{dir.Rva:X} maps to no readable {structSize}-byte structure");
            return new PeTlsInfo(true, Array.Empty<ulong>());
        }

        // AddressOfCallBacks is a *virtual address*, not an RVA — subtract ImageBase to map it.
        ulong callbacksVa = plus ? ReadU64Unchecked(o.Value + 24) : ReadU32Unchecked(o.Value + 12);
        if (callbacksVa == 0)
            return new PeTlsInfo(true, Array.Empty<ulong>());
        if (callbacksVa < imageBase || callbacksVa - imageBase > uint.MaxValue)
        {
            Reason($"TLS callback array VA 0x{callbacksVa:X} does not fall inside the image (base 0x{imageBase:X})");
            return new PeTlsInfo(true, Array.Empty<ulong>());
        }

        long? arr = map.ToOffset((uint)(callbacksVa - imageBase));
        if (arr is null)
        {
            Reason($"TLS callback array VA 0x{callbacksVa:X} maps to no file data");
            return new PeTlsInfo(true, Array.Empty<ulong>());
        }

        int entrySize = plus ? 8 : 4;
        var callbacks = new List<ulong>();
        int c = 0;
        for (; c < PeParserLimits.MaxTlsCallbacks; c++)
        {
            long e = arr.Value + (long)c * entrySize;
            if (e + entrySize > Length)
            {
                Reason($"TLS callback array runs past end of file at offset 0x{e:X}");
                break;
            }
            ulong value = plus ? ReadU64Unchecked(e) : ReadU32Unchecked(e);
            if (value == 0)
                break;
            callbacks.Add(value);
        }
        if (c == PeParserLimits.MaxTlsCallbacks)
            Reason($"TLS callback count exceeds cap {PeParserLimits.MaxTlsCallbacks}; walk stopped");
        return new PeTlsInfo(true, callbacks);
    }

    // ---------------------------------------------------------------- metrics

    private PeMetrics ComputeMetrics(PeImage image)
    {
        var sections = image.Sections;
        var sectionMetrics = new List<PeSectionMetrics>(sections.Count);
        for (int i = 0; i < sections.Count; i++)
        {
            var s = sections[i];
            double? entropy = null;
            if (s.SizeOfRawData > 0)
            {
                long start = s.PointerToRawData;
                long declaredEnd = start + s.SizeOfRawData; // long math: cannot overflow
                long end = Math.Min(declaredEnd, Length);
                if (declaredEnd > Length)
                    Reason($"section '{s.Name}' raw data [0x{start:X}..0x{declaredEnd:X}) extends past end of file (0x{Length:X} bytes)");
                if (start < Length && end > start)
                    entropy = ShannonEntropy(Span.Slice((int)start, (int)(end - start)));
                // else: raw pointer entirely outside the file — no readable bytes, entropy null.
            }

            sectionMetrics.Add(new PeSectionMetrics(
                Index: i,
                Name: s.Name,
                Entropy: entropy,
                WritableAndExecutable: (s.Characteristics & ScnMemWrite) != 0 && (s.Characteristics & ScnMemExecute) != 0,
                ZeroRawSizeWithLargeVirtualSize: s.SizeOfRawData == 0 && s.VirtualSize >= PeParserLimits.LargeVirtualSizeThreshold,
                UncommonName: !PeCommonSectionNames.Common.Contains(s.Name)));
        }

        // Entry point: virtual containment uses max(VirtualSize, SizeOfRawData) — a section's
        // mapped extent is at least its raw data even when VirtualSize under-declares it.
        bool epOutside = false, epWritable = false;
        uint ep = image.OptionalHeader.AddressOfEntryPoint;
        if (ep != 0)
        {
            PeSection? containing = null;
            foreach (var s in sections)
            {
                long size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (ep >= s.VirtualAddress && ep < s.VirtualAddress + size)
                {
                    containing = s;
                    break;
                }
            }
            epOutside = containing is null;
            epWritable = containing is not null && (containing.Characteristics & ScnMemWrite) != 0;
        }

        // Overlay: everything past the end of all mapped content. Each candidate end is
        // clamped to the file so a lying section cannot manufacture a negative overlay.
        long mappedEnd = Math.Min((long)image.OptionalHeader.SizeOfHeaders, Length);
        foreach (var s in sections)
            mappedEnd = Math.Max(mappedEnd, Math.Min((long)s.PointerToRawData + s.SizeOfRawData, Length));
        long overlaySize = Length - mappedEnd;

        int functionCount = 0;
        foreach (var dll in image.Imports)
            functionCount += dll.Functions.Count;

        int tlsCallbacks = image.Tls?.CallbackAddresses.Count ?? 0;

        return new PeMetrics(
            WholeFileEntropy: ShannonEntropy(Span),
            Sections: sectionMetrics,
            EntryPointOutsideAnySection: epOutside,
            EntryPointInWritableSection: epWritable,
            OverlayPresent: overlaySize > 0,
            OverlayOffset: mappedEnd,
            OverlaySize: overlaySize,
            ImportedDllCount: image.Imports.Count,
            ImportedFunctionCount: functionCount,
            TlsCallbacksPresent: tlsCallbacks > 0,
            TlsCallbackCount: tlsCallbacks);
    }

    /// <summary>
    /// Shannon entropy, log base 2, over the full byte histogram of the window: [0, 8] bits
    /// per byte. An empty window yields null, never 0.0 — 0.0 means "a run of one byte value",
    /// which is a different fact entirely (PeMetrics contract).
    /// </summary>
    internal static double? ShannonEntropy(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
            return null;
        Span<int> counts = stackalloc int[256];
        counts.Clear();
        foreach (byte b in bytes)
            counts[b]++;
        double h = 0;
        double length = bytes.Length;
        foreach (int count in counts)
        {
            if (count == 0)
                continue;
            double p = count / length;
            h -= p * Math.Log2(p);
        }
        return h;
    }

    // ---------------------------------------------------------------- raw reads

    // "Unchecked" means the caller has already bounds-checked the range; offsets here are
    // always derived from a validated span. All reads are little-endian per the PE spec.
    private ushort ReadU16Unchecked(long offset) => BinaryPrimitives.ReadUInt16LittleEndian(Span.Slice((int)offset, 2));
    private uint ReadU32Unchecked(long offset) => BinaryPrimitives.ReadUInt32LittleEndian(Span.Slice((int)offset, 4));
    private ulong ReadU64Unchecked(long offset) => BinaryPrimitives.ReadUInt64LittleEndian(Span.Slice((int)offset, 8));

    private bool TryU16(long offset, out ushort value)
    {
        if (offset < 0 || offset + 2 > Length)
        {
            value = 0;
            return false;
        }
        value = ReadU16Unchecked(offset);
        return true;
    }

    private string? ReadAsciiStringAtRva(RvaMapper map, uint rva, string what)
    {
        long? o = map.ToOffset(rva);
        if (o is null)
        {
            Reason($"{what}: RVA 0x{rva:X} maps to no file data");
            return null;
        }
        return ReadAsciiString(o.Value, what);
    }

    /// <summary>
    /// NUL-terminated single-byte string, capped at <see cref="PeParserLimits.MaxNameLength"/>.
    /// Unterminated (EOF or cap hit first) is reported and yields null — a name silently cut
    /// short would compare unequal to the real one without anyone knowing why.
    /// </summary>
    private string? ReadAsciiString(long offset, string what)
    {
        long cap = Math.Min(offset + PeParserLimits.MaxNameLength, Length);
        var window = Span[(int)offset..(int)cap];
        int nul = window.IndexOf((byte)0);
        if (nul < 0)
        {
            Reason(cap == Length
                ? $"{what}: string at offset 0x{offset:X} is unterminated at end of file"
                : $"{what}: string at offset 0x{offset:X} exceeds the {PeParserLimits.MaxNameLength}-byte name cap");
            return null;
        }
        return Encoding.Latin1.GetString(window[..nul]);
    }
}

/// <summary>
/// Maps RVAs to file offsets through the section table. An RVA below SizeOfHeaders maps 1:1
/// (headers are mapped at file offset order); otherwise it must fall inside some section's
/// *raw* data range — bytes past SizeOfRawData exist only virtually (zero-filled by the
/// loader) and are not readable from the file. All arithmetic is 64-bit; a lying header can
/// never overflow here.
/// </summary>
internal sealed class RvaMapper
{
    private readonly IReadOnlyList<PeSection> _sections;
    private readonly long _sizeOfHeaders;
    private readonly long _fileLength;

    internal RvaMapper(IReadOnlyList<PeSection> sections, uint sizeOfHeaders, long fileLength)
    {
        _sections = sections;
        _sizeOfHeaders = sizeOfHeaders;
        _fileLength = fileLength;
    }

    /// <summary>File offset for <paramref name="rva"/>, or null when it maps to no file byte.</summary>
    internal long? ToOffset(uint rva)
    {
        if (rva < _sizeOfHeaders && rva < _fileLength)
            return rva;
        foreach (var s in _sections)
        {
            long delta = (long)rva - s.VirtualAddress;
            if (delta < 0 || delta >= s.SizeOfRawData)
                continue;
            long offset = s.PointerToRawData + delta;
            return offset < _fileLength ? offset : null;
        }
        return null;
    }
}
