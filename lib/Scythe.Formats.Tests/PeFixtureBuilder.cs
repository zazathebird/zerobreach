using System.Buffers.Binary;
using System.Text;

namespace Scythe.Formats.Tests;

/// <summary>Spec for one imported function in a fixture.</summary>
internal sealed record ImportFunc(string? Name, ushort? Ordinal, ushort Hint = 0)
{
    public static ImportFunc ByName(string name, ushort hint = 0) => new(name, null, hint);
    public static ImportFunc ByOrdinal(ushort ordinal) => new(null, ordinal);
}

/// <summary>Spec for one imported DLL in a fixture.</summary>
internal sealed class ImportDll
{
    public string Name { get; }
    public ImportFunc[] Funcs { get; }

    public ImportDll(string name, params ImportFunc[] funcs)
    {
        Name = name;
        Funcs = funcs;
    }
}

/// <summary>
/// Spec for one export slot. <see cref="Forwarder"/> non-null makes the slot a forwarder
/// (its RVA is pointed into the export directory range at the forwarder string).
/// </summary>
internal sealed record ExportSpec(string? Name, uint Rva, string? Forwarder = null);

/// <summary>Spec node for a resource tree fixture: directory when Children is set, leaf otherwise.</summary>
internal sealed class ResSpec
{
    public string? Name;
    public uint? Id;
    public List<ResSpec>? Children;
    public byte[]? Data;
    public uint CodePage;

    public static ResSpec Dir(object nameOrId, params ResSpec[] children) => Make(nameOrId, new List<ResSpec>(children), null, 0);
    public static ResSpec Leaf(object nameOrId, byte[] data, uint codePage = 0) => Make(nameOrId, null, data, codePage);

    private static ResSpec Make(object nameOrId, List<ResSpec>? children, byte[]? data, uint codePage)
    {
        var spec = new ResSpec { Children = children, Data = data, CodePage = codePage };
        if (nameOrId is string s)
            spec.Name = s;
        else
            spec.Id = Convert.ToUInt32(nameOrId);
        return spec;
    }
}

/// <summary>
/// Assembles a genuine minimal PE image, byte by byte, entirely in test code — no third-party
/// binaries. Layout is deterministic: e_lfanew is fixed at 0x100 (leaving the DOS stub free
/// for a Rich header), SizeOfHeaders is 0x400, sections are placed at 0x1000-aligned RVAs and
/// 0x200-aligned file offsets in the order added. Hostile knobs (count overrides) let tests
/// corrupt specific header fields without hand-computing offsets.
/// </summary>
internal sealed class PeFixtureBuilder
{
    public const int Lfanew = 0x100;
    public const uint FileAlignment = 0x200;
    public const uint SectionAlignment = 0x1000;
    public const uint HeadersSize = 0x400;

    // Section characteristics.
    public const uint Code = 0x6000_0020;          // CODE | EXECUTE | READ
    public const uint Data = 0x4000_0040;          // INITIALIZED_DATA | READ
    public const uint WritableData = 0xC000_0040;  // INITIALIZED_DATA | READ | WRITE
    public const uint WriteExecCode = 0xE000_0020; // CODE | EXECUTE | READ | WRITE

    private sealed record Sect(string Name, byte[] Raw, uint Characteristics, uint VirtualSize, uint Va, uint RawOffset);

    private readonly bool _pe32Plus;
    private readonly List<Sect> _sections = new();
    private readonly (uint Rva, uint Size)[] _dirs = new (uint, uint)[16];
    private uint _entryPoint;
    private byte[] _overlay = Array.Empty<byte>();
    private byte[]? _certificate;
    private List<(ushort Product, ushort Build, uint Count)>? _rich;

    /// <summary>Hostile knob: value written to NumberOfSections instead of the real count.</summary>
    public ushort? SectionCountOverride;

    /// <summary>Hostile knob: value written to NumberOfRvaAndSizes instead of 16.</summary>
    public uint? NumberOfRvaAndSizesOverride;

    /// <summary>COFF TimeDateStamp; zero means "not set" per the parser contract.</summary>
    public uint TimeDateStamp = 0x5F00_0000;

    public PeFixtureBuilder(bool pe32Plus = false) => _pe32Plus = pe32Plus;

    public bool IsPe32Plus => _pe32Plus;
    public ulong ImageBase => _pe32Plus ? 0x1_4000_0000UL : 0x0040_0000UL;
    public int CoffOffset => Lfanew + 4;
    public int OptionalHeaderOffset => CoffOffset + 20;
    public int OptionalHeaderFixedSize => _pe32Plus ? 112 : 96;
    public int SizeOfOptionalHeader => OptionalHeaderFixedSize + 16 * 8;
    public int SectionTableOffset => OptionalHeaderOffset + SizeOfOptionalHeader;

    private static uint AlignUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);

    /// <summary>The RVA the next AddSection call will assign — lets content reference itself.</summary>
    public uint NextVa()
    {
        if (_sections.Count == 0)
            return SectionAlignment;
        var last = _sections[^1];
        return AlignUp(last.Va + Math.Max(Math.Max(last.VirtualSize, (uint)last.Raw.Length), 1), SectionAlignment);
    }

    /// <summary>The file offset the next AddSection call will assign to its raw data.</summary>
    public uint NextRawOffset()
    {
        uint end = HeadersSize;
        foreach (var s in _sections)
            end = Math.Max(end, s.RawOffset + (uint)s.Raw.Length);
        return AlignUp(end, FileAlignment);
    }

    public uint AddSection(string name, byte[] raw, uint characteristics, uint? virtualSize = null)
    {
        uint va = NextVa();
        uint rawOffset = NextRawOffset();
        _sections.Add(new Sect(name, raw, characteristics, virtualSize ?? (uint)raw.Length, va, rawOffset));
        return va;
    }

    public void SetEntryPoint(uint rva) => _entryPoint = rva;

    public void SetDirectory(int index, uint rva, uint size) => _dirs[index] = (rva, size);

    public void AddOverlay(byte[] bytes) => _overlay = bytes;

    /// <summary>Certificate payload, appended at end of file; directory 4 gets its raw offset and size.</summary>
    public void AddCertificate(byte[] bytes) => _certificate = bytes;

    public void AddRichHeader(params (ushort Product, ushort Build, uint Count)[] entries) =>
        _rich = new List<(ushort, ushort, uint)>(entries);

    // ---------------------------------------------------------------- imports

    /// <summary>Builds an .idata section (descriptors, INT+IAT, hint/name blobs) and wires directory 1.</summary>
    public uint AddImports(params ImportDll[] dlls)
    {
        uint va = NextVa();
        int ptr = _pe32Plus ? 8 : 4;
        int descBytes = (dlls.Length + 1) * 20;

        var intRel = new int[dlls.Length];
        var iatRel = new int[dlls.Length];
        int cur = descBytes;
        for (int d = 0; d < dlls.Length; d++)
        {
            intRel[d] = cur;
            cur += (dlls[d].Funcs.Length + 1) * ptr;
        }
        for (int d = 0; d < dlls.Length; d++)
        {
            iatRel[d] = cur;
            cur += (dlls[d].Funcs.Length + 1) * ptr;
        }
        var hintNameRel = new Dictionary<(int Dll, int Func), int>();
        for (int d = 0; d < dlls.Length; d++)
        {
            for (int f = 0; f < dlls[d].Funcs.Length; f++)
            {
                if (dlls[d].Funcs[f].Name is not { } fname)
                    continue;
                hintNameRel[(d, f)] = cur;
                cur += 2 + fname.Length + 1;
                if (cur % 2 != 0)
                    cur++; // hint/name entries are even-aligned per the spec
            }
        }
        var dllNameRel = new int[dlls.Length];
        for (int d = 0; d < dlls.Length; d++)
        {
            dllNameRel[d] = cur;
            cur += dlls[d].Name.Length + 1;
        }

        var bytes = new byte[cur];
        for (int d = 0; d < dlls.Length; d++)
        {
            int e = d * 20;
            W32(bytes, e, va + (uint)intRel[d]);          // OriginalFirstThunk
            W32(bytes, e + 12, va + (uint)dllNameRel[d]); // Name
            W32(bytes, e + 16, va + (uint)iatRel[d]);     // FirstThunk
            for (int f = 0; f < dlls[d].Funcs.Length; f++)
            {
                var func = dlls[d].Funcs[f];
                ulong value = func.Ordinal is { } ord
                    ? (_pe32Plus ? 0x8000_0000_0000_0000UL : 0x8000_0000UL) | ord
                    : va + (ulong)hintNameRel[(d, f)];
                WritePtr(bytes, intRel[d] + f * ptr, value);
                WritePtr(bytes, iatRel[d] + f * ptr, value);
            }
            foreach (var ((dd, ff), rel) in hintNameRel)
            {
                if (dd != d)
                    continue;
                W16(bytes, rel, dlls[dd].Funcs[ff].Hint);
                WriteAscii(bytes, rel + 2, dlls[dd].Funcs[ff].Name!);
            }
            WriteAscii(bytes, dllNameRel[d], dlls[d].Name);
        }

        AddSection(".idata", bytes, Data);
        SetDirectory(1, va, (uint)descBytes);
        return va;
    }

    // ---------------------------------------------------------------- exports

    /// <summary>Builds an .edata section and wires directory 0. Directory size spans the whole section so forwarder strings fall inside it.</summary>
    public uint AddExports(string dllName, uint ordinalBase, params ExportSpec[] entries)
    {
        uint va = NextVa();
        int numFuncs = entries.Length;
        int numNames = entries.Count(e => e.Name is not null);

        int funcsRel = 40;
        int namesRel = funcsRel + numFuncs * 4;
        int ordsRel = namesRel + numNames * 4;
        int cur = ordsRel + numNames * 2;

        int dllNameRel = cur;
        cur += dllName.Length + 1;
        var nameRel = new Dictionary<int, int>();
        var fwdRel = new Dictionary<int, int>();
        for (int i = 0; i < entries.Length; i++)
        {
            if (entries[i].Name is { } n)
            {
                nameRel[i] = cur;
                cur += n.Length + 1;
            }
            if (entries[i].Forwarder is { } f)
            {
                fwdRel[i] = cur;
                cur += f.Length + 1;
            }
        }

        var bytes = new byte[cur];
        W32(bytes, 12, va + (uint)dllNameRel);
        W32(bytes, 16, ordinalBase);
        W32(bytes, 20, (uint)numFuncs);
        W32(bytes, 24, (uint)numNames);
        W32(bytes, 28, va + (uint)funcsRel);
        W32(bytes, 32, va + (uint)namesRel);
        W32(bytes, 36, va + (uint)ordsRel);

        int nameSlot = 0;
        for (int i = 0; i < entries.Length; i++)
        {
            uint rva = entries[i].Forwarder is not null ? va + (uint)fwdRel[i] : entries[i].Rva;
            W32(bytes, funcsRel + i * 4, rva);
            if (entries[i].Name is { } n)
            {
                W32(bytes, namesRel + nameSlot * 4, va + (uint)nameRel[i]);
                W16(bytes, ordsRel + nameSlot * 2, (ushort)i);
                WriteAscii(bytes, nameRel[i], n);
                nameSlot++;
            }
            if (entries[i].Forwarder is { } f)
                WriteAscii(bytes, fwdRel[i], f);
        }
        WriteAscii(bytes, dllNameRel, dllName);

        AddSection(".edata", bytes, Data);
        SetDirectory(0, va, (uint)cur);
        return va;
    }

    // ---------------------------------------------------------------- resources

    /// <summary>Builds an .rsrc section from a tree spec (the root's Children become the top level) and wires directory 2.</summary>
    public uint AddResources(params ResSpec[] topLevel)
    {
        uint va = NextVa();
        var root = new ResSpec { Children = new List<ResSpec>(topLevel) };

        // Layout passes: directory tables (preorder), data entries, name strings, payloads.
        var dirRel = new Dictionary<ResSpec, int>();
        var dataRel = new Dictionary<ResSpec, int>();
        var nameRel = new Dictionary<ResSpec, int>();
        var payloadRel = new Dictionary<ResSpec, int>();
        int cur = 0;

        void PlanDirs(ResSpec spec)
        {
            dirRel[spec] = cur;
            cur += 16 + 8 * spec.Children!.Count;
            foreach (var child in spec.Children!.Where(c => c.Children is not null))
                PlanDirs(child);
        }
        PlanDirs(root);

        void PlanRest(ResSpec spec)
        {
            foreach (var child in spec.Children!)
            {
                if (child.Name is not null)
                {
                    nameRel[child] = cur;
                    cur += 2 + 2 * child.Name.Length;
                }
                if (child.Children is not null)
                {
                    PlanRest(child);
                }
                else
                {
                    dataRel[child] = cur;
                    cur += 16;
                    payloadRel[child] = cur;
                    cur += child.Data!.Length;
                    cur = (cur + 3) & ~3;
                }
            }
        }
        PlanRest(root);

        var bytes = new byte[cur];
        void WriteDir(ResSpec spec)
        {
            int at = dirRel[spec];
            var named = spec.Children!.Where(c => c.Name is not null).ToList();
            var byId = spec.Children!.Where(c => c.Name is null).ToList();
            W16(bytes, at + 12, (ushort)named.Count);
            W16(bytes, at + 14, (ushort)byId.Count);
            int slot = 0;
            foreach (var child in named.Concat(byId)) // named entries first, per the spec
            {
                int e = at + 16 + slot * 8;
                if (child.Name is { } n)
                {
                    W32(bytes, e, 0x8000_0000u | (uint)nameRel[child]);
                    W16(bytes, nameRel[child], (ushort)n.Length);
                    Encoding.Unicode.GetBytes(n).CopyTo(bytes, nameRel[child] + 2);
                }
                else
                {
                    W32(bytes, e, child.Id!.Value);
                }
                if (child.Children is not null)
                {
                    W32(bytes, e + 4, 0x8000_0000u | (uint)dirRel[child]);
                    WriteDir(child);
                }
                else
                {
                    W32(bytes, e + 4, (uint)dataRel[child]);
                    int de = dataRel[child];
                    W32(bytes, de, va + (uint)payloadRel[child]); // DataRVA
                    W32(bytes, de + 4, (uint)child.Data!.Length);
                    W32(bytes, de + 8, child.CodePage);
                    child.Data.CopyTo(bytes, payloadRel[child]);
                }
                slot++;
            }
        }
        WriteDir(root);

        AddSection(".rsrc", bytes, Data);
        SetDirectory(2, va, (uint)cur);
        return va;
    }

    // ---------------------------------------------------------------- TLS / debug

    /// <summary>Builds a .tls section (callback array + directory struct) and wires directory 9. Callback values are VAs.</summary>
    public uint AddTls(params ulong[] callbackVas)
    {
        uint va = NextVa();
        int ptr = _pe32Plus ? 8 : 4;
        int arrayBytes = (callbackVas.Length + 1) * ptr;
        int structSize = _pe32Plus ? 40 : 24;

        var bytes = new byte[arrayBytes + structSize];
        for (int i = 0; i < callbackVas.Length; i++)
            WritePtr(bytes, i * ptr, callbackVas[i]);

        int s = arrayBytes;
        ulong callbacksVa = ImageBase + va; // array sits at the start of the section
        if (_pe32Plus)
            W64(bytes, s + 24, callbacksVa);
        else
            W32(bytes, s + 12, (uint)callbacksVa);

        AddSection(".tls", bytes, WritableData);
        SetDirectory(9, va + (uint)arrayBytes, (uint)structSize);
        return va;
    }

    /// <summary>Builds a debug section with one CodeView/RSDS entry and wires directory 6.</summary>
    public uint AddDebug(Guid pdbGuid, uint pdbAge, string pdbPath)
    {
        uint va = NextVa();
        uint rawOffset = NextRawOffset();
        byte[] pathBytes = Encoding.UTF8.GetBytes(pdbPath);
        int cvSize = 4 + 16 + 4 + pathBytes.Length + 1;

        var bytes = new byte[28 + cvSize];
        W32(bytes, 8, 0);                     // version
        W32(bytes, 12, 2);                    // IMAGE_DEBUG_TYPE_CODEVIEW
        W32(bytes, 16, (uint)cvSize);         // SizeOfData
        W32(bytes, 20, va + 28);              // AddressOfRawData
        W32(bytes, 24, rawOffset + 28);       // PointerToRawData (file offset)
        W32(bytes, 28, 0x5344_5352);          // "RSDS"
        pdbGuid.ToByteArray().CopyTo(bytes, 32);
        W32(bytes, 48, pdbAge);
        pathBytes.CopyTo(bytes, 52);

        AddSection(".scydbg", bytes, Data);
        SetDirectory(6, va, 28);
        return va;
    }

    // ---------------------------------------------------------------- build

    public byte[] Build()
    {
        long fileEnd = HeadersSize;
        foreach (var s in _sections)
            fileEnd = Math.Max(fileEnd, s.RawOffset + (long)s.Raw.Length);

        long overlayOffset = fileEnd;
        fileEnd += _overlay.Length;
        long certOffset = 0;
        if (_certificate is not null)
        {
            certOffset = (fileEnd + 7) & ~7L; // certificate table is 8-aligned
            fileEnd = certOffset + _certificate.Length;
        }

        var file = new byte[fileEnd];
        file[0] = (byte)'M';
        file[1] = (byte)'Z';
        W32(file, 0x3C, Lfanew);

        if (_rich is not null)
            WriteRich(file);

        W32(file, Lfanew, 0x0000_4550); // "PE\0\0"

        int coff = CoffOffset;
        W16(file, coff, _pe32Plus ? (ushort)0x8664 : (ushort)0x14C);
        W16(file, coff + 2, SectionCountOverride ?? (ushort)_sections.Count);
        W32(file, coff + 4, TimeDateStamp);
        W16(file, coff + 16, (ushort)SizeOfOptionalHeader);
        W16(file, coff + 18, 0x0102); // EXECUTABLE_IMAGE | 32BIT_MACHINE (raw value; host interprets)

        int o = OptionalHeaderOffset;
        W16(file, o, _pe32Plus ? (ushort)0x20B : (ushort)0x10B);
        file[o + 2] = 14; // linker major, arbitrary but non-zero
        W32(file, o + 16, _entryPoint);
        W32(file, o + 20, SectionAlignment); // BaseOfCode, arbitrary
        if (_pe32Plus)
        {
            W64(file, o + 24, ImageBase);
        }
        else
        {
            W32(file, o + 24, 2 * SectionAlignment); // BaseOfData, arbitrary
            W32(file, o + 28, (uint)ImageBase);
        }
        W32(file, o + 32, SectionAlignment);
        W32(file, o + 36, FileAlignment);
        W16(file, o + 48, 6); // MajorSubsystemVersion
        uint sizeOfImage = SectionAlignment;
        foreach (var s in _sections)
            sizeOfImage = Math.Max(sizeOfImage, AlignUp(s.Va + Math.Max(Math.Max(s.VirtualSize, (uint)s.Raw.Length), 1), SectionAlignment));
        W32(file, o + 56, sizeOfImage);
        W32(file, o + 60, HeadersSize);
        W16(file, o + 68, 3); // IMAGE_SUBSYSTEM_WINDOWS_CUI
        W32(file, o + (_pe32Plus ? 108 : 92), NumberOfRvaAndSizesOverride ?? 16);

        int dirTable = o + OptionalHeaderFixedSize;
        var dirs = ((uint Rva, uint Size)[])_dirs.Clone();
        if (_certificate is not null)
            dirs[4] = ((uint)certOffset, (uint)_certificate.Length);
        for (int i = 0; i < 16; i++)
        {
            W32(file, dirTable + i * 8, dirs[i].Rva);
            W32(file, dirTable + i * 8 + 4, dirs[i].Size);
        }

        int table = SectionTableOffset;
        for (int i = 0; i < _sections.Count; i++)
        {
            var s = _sections[i];
            int e = table + i * 40;
            Encoding.Latin1.GetBytes(s.Name.Length > 8 ? s.Name[..8] : s.Name).CopyTo(file, e);
            W32(file, e + 8, s.VirtualSize);
            W32(file, e + 12, s.Va);
            W32(file, e + 16, (uint)s.Raw.Length);
            W32(file, e + 20, s.Raw.Length > 0 ? s.RawOffset : 0);
            W32(file, e + 36, s.Characteristics);
            s.Raw.CopyTo(file, s.RawOffset);
        }

        _overlay.CopyTo(file, overlayOffset);
        _certificate?.CopyTo(file, certOffset);
        return file;
    }

    private void WriteRich(byte[] file)
    {
        // DanS at 0x80, three zero padding dwords, entries, "Rich", key — all XORed with the key.
        const uint key = 0x1234_5678;
        int at = 0x80;
        W32(file, at, 0x536E_6144 ^ key);
        W32(file, at + 4, key);
        W32(file, at + 8, key);
        W32(file, at + 12, key);
        int e = at + 16;
        foreach (var (product, build, count) in _rich!)
        {
            W32(file, e, (((uint)product << 16) | build) ^ key);
            W32(file, e + 4, count ^ key);
            e += 8;
        }
        W32(file, e, 0x6863_6952); // "Rich"
        W32(file, e + 4, key);
    }

    // ---------------------------------------------------------------- byte helpers

    private static void W16(byte[] buffer, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), value);

    private static void W32(byte[] buffer, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset), value);

    private static void W64(byte[] buffer, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset), value);

    private void WritePtr(byte[] buffer, int offset, ulong value)
    {
        if (_pe32Plus)
            W64(buffer, offset, value);
        else
            W32(buffer, offset, (uint)value);
    }

    private static void WriteAscii(byte[] buffer, int offset, string text) =>
        Encoding.Latin1.GetBytes(text).CopyTo(buffer, offset); // trailing NUL is the array's default 0
}
