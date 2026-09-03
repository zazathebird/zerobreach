namespace Scythe.ShellItems;

/// <summary>
/// Reads one shell link (<c>.lnk</c>) out of bytes the caller supplies. Never opens a file,
/// never resolves the target, never throws for malformed input.
/// </summary>
public static partial class ShellLinkReader
{
    public const int HeaderSize = 0x4C;

    public static readonly Guid ShellLinkClassId = new("00021401-0000-0000-C000-000000000046");

    public static LinkResult<ShellLink> Read(ReadOnlySpan<byte> bytes, ScanBudget? budget = null)
    {
        var ctx = new ParseContext(budget ?? ScanBudget.Default);
        if (bytes.Length > ctx.Budget.MaxInputBytes)
        {
            return LinkResult<ShellLink>.Incomplete(
                null,
                $"MaxInputBytes: input is {bytes.Length} bytes, budget allows {ctx.Budget.MaxInputBytes}");
        }

        return ReadCore(bytes, ctx, depth: 1);
    }

    /// <summary>The parse proper; the jump-list reader calls this for each embedded link at depth 2.</summary>
    internal static LinkResult<ShellLink> ReadCore(ReadOnlySpan<byte> bytes, ParseContext ctx, int depth)
    {
        if (depth > ctx.Budget.MaxNestingDepth)
        {
            return LinkResult<ShellLink>.Incomplete(null, ctx.MaxNestingDepthReason(depth, "the shell link"));
        }

        var file = new ByteReader(bytes);
        var acc = new Accumulator();
        long offset = 0;

        var problem = ParseHeader(file, ref offset, acc);
        if (problem is null && ctx.DeadlineExpired)
        {
            problem = Problem.Incomplete(ctx.DeadlineReason("after the header"));
        }

        if (problem is null && acc.Header!.Flags.HasFlag(LinkFlags.HasLinkTargetIdList))
        {
            problem = ParseIdList(file, ref offset, acc, ctx);
        }

        if (problem is null && acc.Header!.Flags.HasFlag(LinkFlags.HasLinkInfo))
        {
            problem = ParseLinkInfo(file, ref offset, acc);
        }

        if (problem is null)
        {
            problem = ParseStringData(file, ref offset, acc);
        }

        if (problem is null)
        {
            problem = ParseExtraData(file, ref offset, acc, ctx, depth);
        }

        if (problem is null)
        {
            return LinkResult<ShellLink>.Ok(acc.Snapshot(offset));
        }

        return problem.State == LinkResultState.Failed
            ? LinkResult<ShellLink>.Failed(problem.Message, problem.Position)
            : LinkResult<ShellLink>.Incomplete(acc.Header is null ? null : acc.Snapshot(offset), problem.Message);
    }

    private static Problem? ParseHeader(ByteReader file, ref long offset, Accumulator acc)
    {
        if (file.Length == 0)
        {
            return Problem.Failed("empty input: a shell link is at least 76 bytes", 0);
        }

        if (!file.TryU32(0, out var headerSize))
        {
            return Problem.Incomplete($"truncated at offset 0: {file.Length} bytes present, the header size field needs 4");
        }

        if (headerSize != HeaderSize)
        {
            return Problem.Failed($"header size at offset 0 is 0x{headerSize:X8}, expected 0x0000004C", 0);
        }

        if (!file.TryGuid(4, out var classId))
        {
            return Problem.Incomplete($"truncated in the header at offset 4: {file.Length} bytes present, the class identifier needs 20");
        }

        if (classId != ShellLinkClassId)
        {
            return Problem.Failed($"class identifier at offset 4 is {classId:D}, expected {ShellLinkClassId:D}", 4);
        }

        if (!file.Has(0, HeaderSize))
        {
            return Problem.Incomplete($"truncated in the header: {file.Length} of 76 bytes present");
        }

        file.TryU32(0x14, out var flags);
        file.TryU32(0x18, out var attributes);
        file.TryU64(0x1C, out var creation);
        file.TryU64(0x24, out var access);
        file.TryU64(0x2C, out var write);
        file.TryU32(0x34, out var fileSize);
        file.TryI32(0x38, out var iconIndex);
        file.TryU32(0x3C, out var showCommand);
        file.TryU16(0x40, out var hotKey);
        file.TrySlice(0, HeaderSize, out var raw);

        acc.Header = new ShellLinkHeader(
            headerSize,
            classId,
            (LinkFlags)flags,
            attributes,
            new FileTimeValue(creation),
            new FileTimeValue(access),
            new FileTimeValue(write),
            fileSize,
            iconIndex,
            showCommand,
            hotKey,
            raw.ToArray());
        offset = HeaderSize;
        return null;
    }

    private static Problem? ParseStringData(ByteReader file, ref long offset, Accumulator acc)
    {
        var flags = acc.Header!.Flags;
        var unicode = acc.Header.IsUnicode;
        Problem? problem;

        // Fixed order, one per flag (reference/04.3 "StringData").
        if (flags.HasFlag(LinkFlags.HasName) && (problem = ReadCounted(file, ref offset, unicode, "NAME_STRING", out acc.Name)) is not null)
        {
            return problem;
        }

        if (flags.HasFlag(LinkFlags.HasRelativePath) && (problem = ReadCounted(file, ref offset, unicode, "RELATIVE_PATH", out acc.RelativePath)) is not null)
        {
            return problem;
        }

        if (flags.HasFlag(LinkFlags.HasWorkingDir) && (problem = ReadCounted(file, ref offset, unicode, "WORKING_DIR", out acc.WorkingDirectory)) is not null)
        {
            return problem;
        }

        if (flags.HasFlag(LinkFlags.HasArguments) && (problem = ReadCounted(file, ref offset, unicode, "COMMAND_LINE_ARGUMENTS", out acc.Arguments)) is not null)
        {
            return problem;
        }

        if (flags.HasFlag(LinkFlags.HasIconLocation) && (problem = ReadCounted(file, ref offset, unicode, "ICON_LOCATION", out acc.IconLocation)) is not null)
        {
            return problem;
        }

        return null;
    }

    /// <summary>
    /// The counted-string rule: <c>CountCharacters</c> then exactly that many characters, no
    /// terminator. An embedded null is data and is kept. Nothing here scans for a null.
    /// </summary>
    private static Problem? ReadCounted(ByteReader file, ref long offset, bool unicode, string name, out LinkString? value)
    {
        value = null;
        if (!file.TryU16(offset, out var count))
        {
            return Problem.Incomplete($"truncated at 0x{offset:X}: the {name} character count is missing");
        }

        var byteLength = unicode ? count * 2L : count;
        if (!file.TrySlice(offset + 2, byteLength, out var slice))
        {
            return Problem.Incomplete(
                $"truncated mid-string at 0x{offset + 2:X}: {name} declares {count} characters ({byteLength} bytes) but only {file.Remaining(offset + 2)} remain");
        }

        value = unicode ? LinkString.FromUtf16(slice) : LinkString.FromCodePage(slice);
        offset += 2 + byteLength;
        return null;
    }

    private sealed class Accumulator
    {
        public ShellLinkHeader? Header;
        public LinkTargetIdList? IdList;
        public LinkInfo? LinkInfo;
        public LinkString? Name;
        public LinkString? RelativePath;
        public LinkString? WorkingDirectory;
        public LinkString? Arguments;
        public LinkString? IconLocation;
        public readonly List<ExtraDataBlock> Extra = [];
        public readonly List<string> Notes = [];

        public ShellLink Snapshot(long consumed)
        {
            // Open question 3: when both the ID list and LinkInfo yield a path and they differ,
            // return both and say so; do not pick. Null when there is nothing to compare.
            var idPath = IdList is { PathCompleteness: PathCompleteness.Complete } ? IdList.Path : null;
            var infoPath = LinkInfo?.LocalPath ?? LinkInfo?.NetworkPath;
            bool? disagree = idPath is not null && infoPath is not null
                ? !string.Equals(idPath, infoPath, StringComparison.OrdinalIgnoreCase)
                : null;

            return new ShellLink(
                Header!,
                IdList,
                LinkInfo,
                Name,
                RelativePath,
                WorkingDirectory,
                Arguments,
                IconLocation,
                Extra.ToArray(),
                disagree,
                (int)consumed,
                Notes.ToArray());
        }
    }
}
