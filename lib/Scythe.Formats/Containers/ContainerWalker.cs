using System.Diagnostics;

namespace Scythe.Formats.Containers;

/// <summary>Which container format a buffer is, judged by signature and structure.</summary>
public enum ContainerKind
{
    Unknown = 0,
    Zip = 1,

    /// <summary>A ZIP that carries [Content_Types].xml — an OOXML package.</summary>
    Ooxml = 2,
    Ole = 3,
}

/// <summary>One container in the nesting tree produced by <see cref="ContainerWalker.Walk"/>.</summary>
public sealed record ContainerNode
{
    /// <summary>
    /// Location of this container: the empty string for the outermost buffer, then entry
    /// names joined with <c>!</c> (e.g. <c>attachments.zip!inner.zip</c>).
    /// </summary>
    public required string Path { get; init; }

    public required ContainerKind Kind { get; init; }

    /// <summary>Nesting depth: the outermost container is 1.</summary>
    public required int Depth { get; init; }

    /// <summary>State of reading <em>this</em> container's structure.</summary>
    public required OperationState State { get; init; }

    /// <summary>Reasons and anomalies for this container (structure-level, not walk-level).</summary>
    public required IReadOnlyList<string> Reasons { get; init; }

    /// <summary>ZIP entries or OLE streams enumerated in this container.</summary>
    public required int EntryCount { get; init; }

    /// <summary>For OOXML: a VBA macro binary part is present.</summary>
    public required bool HasMacroPart { get; init; }

    /// <summary>Nested containers found inside, in enumeration order.</summary>
    public required IReadOnlyList<ContainerNode> Children { get; init; }
}

/// <summary>
/// Result of a nested walk. <c>Ok</c> means every byte of every level was seen. Anything the
/// walk could not see — an encrypted entry, a corrupt inner archive, a guard or depth or
/// deadline cutoff — makes the whole result <c>Incomplete</c> with the path named, because
/// "scanned" must never be claimed for content that was not actually looked at.
/// </summary>
public sealed record ContainerWalkResult(
    OperationState State,
    string? Message,
    IReadOnlyList<string> IncompleteReasons,
    ContainerNode? Root);

/// <summary>
/// Walks containers inside containers, breadth-limited by <see cref="ScanBudget.MaxNestingDepth"/>
/// and bomb-limited by one <see cref="ExpansionGuard"/> shared across every level — a bomb
/// split across nesting levels is only visible in the aggregate.
/// </summary>
public static class ContainerWalker
{
    /// <summary>Signature sniff. Cheap and byte-anchored; OOXML is distinguished from plain ZIP after enumeration.</summary>
    public static ContainerKind Sniff(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 8 && data.StartsWith(OleReader.Signature))
        {
            return ContainerKind.Ole;
        }
        // PK\x03\x04 (entries) or PK\x05\x06 (empty archive: bare end-of-central-directory).
        if (data.Length >= 4 && data[0] == 0x50 && data[1] == 0x4B &&
            ((data[2] == 0x03 && data[3] == 0x04) || (data[2] == 0x05 && data[3] == 0x06)))
        {
            return ContainerKind.Zip;
        }
        return ContainerKind.Unknown;
    }

    public static ContainerWalkResult Walk(byte[] data, ScanBudget budget)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(budget);

        var clock = Stopwatch.StartNew();
        var guard = new ExpansionGuard();
        var walkReasons = new List<string>();

        if (Sniff(data) == ContainerKind.Unknown)
        {
            return new ContainerWalkResult(
                OperationState.Failed,
                "not a recognised container: no ZIP or OLE compound-file signature",
                Array.Empty<string>(),
                null);
        }

        ContainerNode root = WalkOne(data, string.Empty, 1, budget, guard, clock, walkReasons);

        // The root failing to parse fails the whole walk; anything unseen deeper down makes
        // the walk Incomplete. Only a walk that saw every byte of every level reports Ok.
        OperationState state = root.State == OperationState.Failed
            ? OperationState.Failed
            : walkReasons.Count == 0 && AllOk(root)
                ? OperationState.Ok
                : OperationState.Incomplete;
        return new ContainerWalkResult(
            state,
            state == OperationState.Ok ? null : string.Join("; ", walkReasons),
            walkReasons,
            root);
    }

    private static bool AllOk(ContainerNode node) =>
        node.State == OperationState.Ok && node.Children.All(AllOk);

    private static ContainerNode WalkOne(
        byte[] data,
        string path,
        int depth,
        ScanBudget budget,
        ExpansionGuard guard,
        Stopwatch clock,
        List<string> walkReasons)
    {
        string here = path.Length == 0 ? "(root)" : path;
        TimeSpan remaining = budget.Deadline - clock.Elapsed;
        if (remaining <= TimeSpan.Zero)
        {
            walkReasons.Add($"deadline exhausted before walking '{here}'");
            return Leaf(path, Sniff(data), depth, OperationState.Incomplete, new[] { "deadline exhausted" });
        }
        var levelBudget = budget with { Deadline = remaining };

        return Sniff(data) switch
        {
            ContainerKind.Ole => WalkOle(data, path, here, depth, levelBudget, guard, clock, budget, walkReasons),
            ContainerKind.Zip => WalkZip(data, path, here, depth, levelBudget, guard, clock, budget, walkReasons),
            _ => Leaf(path, ContainerKind.Unknown, depth, OperationState.Ok, Array.Empty<string>()),
        };
    }

    private static ContainerNode WalkZip(
        byte[] data,
        string path,
        string here,
        int depth,
        ScanBudget levelBudget,
        ExpansionGuard guard,
        Stopwatch clock,
        ScanBudget budget,
        List<string> walkReasons)
    {
        var zip = ZipReader.Read(data, levelBudget);
        if (zip.Archive is null)
        {
            string why = $"'{here}': {zip.Message}";
            walkReasons.Add(why);
            return Leaf(path, ContainerKind.Zip, depth, zip.State, new[] { zip.Message ?? "unreadable" });
        }

        var reasons = new List<string>(zip.IncompleteReasons);
        reasons.AddRange(zip.Archive.ArchiveAnomalies);
        foreach (string reason in zip.IncompleteReasons)
        {
            walkReasons.Add($"'{here}': {reason}");
        }

        // OOXML is a ZIP with a specific part: classify and detect the macro part, but keep
        // walking the entries like any ZIP so nested archives inside a document are found.
        bool isOoxml = zip.Archive.Entries.Any(e =>
            string.Equals(e.Name, OoxmlReader.ContentTypesPartName, StringComparison.OrdinalIgnoreCase));
        bool hasMacro = false;
        if (isOoxml)
        {
            var ooxml = OoxmlReader.Read(data, levelBudget, guard);
            hasMacro = ooxml.Package?.HasMacroPart ?? false;
            if (ooxml.Package is null)
            {
                walkReasons.Add($"'{here}': OOXML metadata unreadable: {ooxml.Message}");
                reasons.Add($"OOXML metadata unreadable: {ooxml.Message}");
            }
        }

        var children = new List<ContainerNode>();
        foreach (var entry in zip.Archive.Entries)
        {
            if (clock.Elapsed >= budget.Deadline)
            {
                walkReasons.Add($"deadline exhausted inside '{here}'");
                break;
            }
            if (entry.IsDirectory)
            {
                continue;
            }
            string childPath = path.Length == 0 ? entry.Name : path + "!" + entry.Name;
            if (entry.IsEncrypted)
            {
                // Content the walk cannot see: the whole result must say so.
                walkReasons.Add($"'{childPath}': encrypted entry; content not scanned");
                continue;
            }

            var read = ZipReader.ReadEntry(data, entry, budget with { Deadline = Remaining(budget, clock) }, guard);
            if (read.State != OperationState.Ok || read.Bytes is null)
            {
                walkReasons.Add($"'{childPath}': {read.Reason}");
                continue;
            }
            if (Sniff(read.Bytes) == ContainerKind.Unknown)
            {
                continue;
            }
            if (depth + 1 > budget.MaxNestingDepth)
            {
                walkReasons.Add(
                    $"'{childPath}' is a nested container at depth {depth + 1}, past the depth cap of {budget.MaxNestingDepth}; not walked");
                continue;
            }
            children.Add(WalkOne(read.Bytes, childPath, depth + 1, budget, guard, clock, walkReasons));
        }

        return new ContainerNode
        {
            Path = path,
            Kind = isOoxml ? ContainerKind.Ooxml : ContainerKind.Zip,
            Depth = depth,
            State = zip.State,
            Reasons = reasons,
            EntryCount = zip.Archive.Entries.Count,
            HasMacroPart = hasMacro,
            Children = children,
        };
    }

    private static ContainerNode WalkOle(
        byte[] data,
        string path,
        string here,
        int depth,
        ScanBudget levelBudget,
        ExpansionGuard guard,
        Stopwatch clock,
        ScanBudget budget,
        List<string> walkReasons)
    {
        var ole = OleReader.Read(data, levelBudget);
        if (ole.File is null)
        {
            walkReasons.Add($"'{here}': {ole.Message}");
            return Leaf(path, ContainerKind.Ole, depth, ole.State, new[] { ole.Message ?? "unreadable" });
        }
        foreach (string reason in ole.IncompleteReasons)
        {
            walkReasons.Add($"'{here}': {reason}");
        }

        var children = new List<ContainerNode>();
        int streamCount = 0;
        var stack = new Stack<OleDirectoryEntryInfo>();
        for (int i = ole.File.Root.Children.Count - 1; i >= 0; i--)
        {
            stack.Push(ole.File.Root.Children[i]);
        }
        while (stack.Count > 0)
        {
            var node = stack.Pop();
            if (node.Type == OleEntryType.Storage)
            {
                for (int i = node.Children.Count - 1; i >= 0; i--)
                {
                    stack.Push(node.Children[i]);
                }
                continue;
            }
            if (node.Type != OleEntryType.Stream)
            {
                continue;
            }
            streamCount++;
            if (clock.Elapsed >= budget.Deadline)
            {
                walkReasons.Add($"deadline exhausted inside '{here}'");
                break;
            }
            string childPath = path.Length == 0 ? node.Path : path + "!" + node.Path;
            // OLE streams are stored raw, but they still count against the shared expansion
            // guard: nesting multiplies resident bytes, and the guard bounds the aggregate.
            if (guard.WouldExceed((long)node.Size))
            {
                walkReasons.Add(
                    $"'{childPath}': {node.Size} bytes would pass the {guard.MaxTotalExpandedBytes}-byte total expansion cap; not read");
                continue;
            }
            var read = OleReader.ReadStream(data, ole.File, node, budget with { Deadline = Remaining(budget, clock) });
            if (read.State != OperationState.Ok || read.Bytes is null)
            {
                walkReasons.Add($"'{childPath}': {read.Reason}");
                continue;
            }
            guard.Commit(read.Bytes.LongLength);
            if (Sniff(read.Bytes) == ContainerKind.Unknown)
            {
                continue;
            }
            if (depth + 1 > budget.MaxNestingDepth)
            {
                walkReasons.Add(
                    $"'{childPath}' is a nested container at depth {depth + 1}, past the depth cap of {budget.MaxNestingDepth}; not walked");
                continue;
            }
            children.Add(WalkOne(read.Bytes, childPath, depth + 1, budget, guard, clock, walkReasons));
        }

        return new ContainerNode
        {
            Path = path,
            Kind = ContainerKind.Ole,
            Depth = depth,
            State = ole.State,
            Reasons = ole.IncompleteReasons,
            EntryCount = streamCount,
            HasMacroPart = false,
            Children = children,
        };
    }

    private static TimeSpan Remaining(ScanBudget budget, Stopwatch clock)
    {
        TimeSpan remaining = budget.Deadline - clock.Elapsed;
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    private static ContainerNode Leaf(string path, ContainerKind kind, int depth, OperationState state, IReadOnlyList<string> reasons) =>
        new()
        {
            Path = path,
            Kind = kind,
            Depth = depth,
            State = state,
            Reasons = reasons,
            EntryCount = 0,
            HasMacroPart = false,
            Children = Array.Empty<ContainerNode>(),
        };
}
