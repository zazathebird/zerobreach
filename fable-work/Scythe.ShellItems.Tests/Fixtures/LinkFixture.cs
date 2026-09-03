using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests.Fixtures;

/// <summary>
/// Builds a complete shell link. Flags are derived from which sections are present, so a test
/// adds a section by setting it and lies about one by patching the built bytes.
/// </summary>
internal sealed class LinkFixture
{
    public bool Unicode { get; init; } = true;

    public LinkFlags ExtraFlags { get; init; }

    public byte[]? IdList { get; init; }

    public byte[]? LinkInfo { get; init; }

    public string? Name { get; init; }

    public string? RelativePath { get; init; }

    public string? WorkingDirectory { get; init; }

    public string? Arguments { get; init; }

    public string? IconLocation { get; init; }

    public List<byte[]> ExtraBlocks { get; init; } = [];

    /// <summary>The terminal block bytes; null omits them entirely.</summary>
    public byte[]? Terminal { get; init; } = Blocks.Terminal;

    public uint HeaderSizeField { get; init; } = 0x4C;

    public Guid ClassId { get; init; } = ShellLinkReader.ShellLinkClassId;

    public ulong CreationTime { get; init; }

    public ulong AccessTime { get; init; }

    public ulong WriteTime { get; init; }

    public uint FileAttributes { get; init; }

    public uint FileSize { get; init; }

    public int IconIndex { get; init; }

    public uint ShowCommand { get; init; } = 1;

    public ushort HotKey { get; init; }

    /// <summary>Offset of the first StringData count field, filled in by <see cref="Build"/>.</summary>
    public int StringDataOffset { get; private set; }

    /// <summary>Offset of the first ExtraData block, filled in by <see cref="Build"/>.</summary>
    public int ExtraDataOffset { get; private set; }

    public LinkFlags Flags
    {
        get
        {
            var flags = ExtraFlags;
            if (Unicode)
            {
                flags |= LinkFlags.IsUnicode;
            }

            if (IdList is not null)
            {
                flags |= LinkFlags.HasLinkTargetIdList;
            }

            if (LinkInfo is not null)
            {
                flags |= LinkFlags.HasLinkInfo;
            }

            if (Name is not null)
            {
                flags |= LinkFlags.HasName;
            }

            if (RelativePath is not null)
            {
                flags |= LinkFlags.HasRelativePath;
            }

            if (WorkingDirectory is not null)
            {
                flags |= LinkFlags.HasWorkingDir;
            }

            if (Arguments is not null)
            {
                flags |= LinkFlags.HasArguments;
            }

            if (IconLocation is not null)
            {
                flags |= LinkFlags.HasIconLocation;
            }

            return flags;
        }
    }

    public byte[] Build()
    {
        var header = Concat(
            U32(HeaderSizeField),
            Guid(ClassId),
            U32((uint)Flags),
            U32(FileAttributes),
            U64(CreationTime),
            U64(AccessTime),
            U64(WriteTime),
            U32(FileSize),
            I32(IconIndex),
            U32(ShowCommand),
            U16(HotKey),
            new byte[10]);

        var parts = new List<byte[]> { header };
        if (IdList is not null)
        {
            parts.Add(IdList);
        }

        if (LinkInfo is not null)
        {
            parts.Add(LinkInfo);
        }

        StringDataOffset = parts.Sum(p => p.Length);
        foreach (var text in new[] { Name, RelativePath, WorkingDirectory, Arguments, IconLocation })
        {
            if (text is not null)
            {
                parts.Add(Counted(text, Unicode));
            }
        }

        ExtraDataOffset = parts.Sum(p => p.Length);
        parts.AddRange(ExtraBlocks);
        if (Terminal is not null)
        {
            parts.Add(Terminal);
        }

        return Concat(parts.ToArray());
    }

    internal static byte[] Counted(string text, bool unicode) =>
        Concat(U16((ushort)text.Length), unicode ? Utf16(text) : Latin1(text));

    // 2023-11-14 15:26:45.1234567 UTC and two neighbours, as exact FILETIME ticks.
    internal const ulong CreationTicks = 133_444_492_051_234_567UL;
    internal const ulong AccessTicks = 133_444_492_051_234_568UL;
    internal const ulong WriteTicks = 133_444_492_051_234_569UL;

    /// <summary>The ordinary fixture: a local file with every section present.</summary>
    internal static LinkFixture Ordinary() => new()
    {
        IdList = Items.OrdinaryLocalList(),
        LinkInfo = new LinkInfoFixture { LocalBasePath = "C:\\Users\\readme.txt" }.Build(),
        Name = "Read me",
        RelativePath = "..\\readme.txt",
        WorkingDirectory = "C:\\Users",
        Arguments = "--verbose --log \"C:\\Temp\\out.log\"",
        IconLocation = "%SystemRoot%\\system32\\shell32.dll",
        CreationTime = CreationTicks,
        AccessTime = AccessTicks,
        WriteTime = WriteTicks,
        FileAttributes = 0x20,
        FileSize = 1234,
        IconIndex = -3,
        ShowCommand = 1,
        HotKey = 0x0341,
        ExtraBlocks = [Blocks.Tracker()],
    };

    internal static byte[] OrdinaryBytes() => Ordinary().Build();
}
