using static Scythe.ShellItems.Tests.Fixtures.Bytes;

namespace Scythe.ShellItems.Tests.Fixtures;

internal sealed class DestEntry
{
    public required uint Number { get; init; }

    public required string Path { get; init; }

    public ulong LastAccess { get; init; } = LinkFixture.WriteTicks;

    public int Pin { get; init; } = -1;

    public uint AccessCount { get; init; } = 1;

    public string Machine { get; init; } = "workstation7";

    public ulong Checksum { get; init; } = 0x0123456789ABCDEFUL;
}

/// <summary>DestList and customDestinations-ms builders (reference/04.3 "Jump lists").</summary>
internal static class JumpListFixtures
{
    internal static byte[] DestList(uint version, IReadOnlyList<DestEntry> entries, uint? declaredCount = null, uint pinnedCount = 0)
    {
        var lastNumber = entries.Count == 0 ? 0u : entries.Max(e => e.Number);
        var header = Concat(
            U32(version),
            U32(declaredCount ?? (uint)entries.Count),
            U32(pinnedCount),
            U32(0xBF800000), // -1.0f
            U32(lastNumber),
            U32(0),
            U64((ulong)entries.Count));

        var parts = new List<byte[]> { header };
        foreach (var entry in entries)
        {
            parts.Add(Entry(version, entry));
        }

        return Concat(parts.ToArray());
    }

    /// <summary>Entry stride: 114 + path for version 1; 130 + path + 4 for version 3 and above.</summary>
    internal static byte[] Entry(uint version, DestEntry e)
    {
        var common = Concat(
            U64(e.Checksum),
            Guid(Blocks.DroidVolume),
            Guid(Blocks.DroidFile),
            Guid(Blocks.BirthVolume),
            Guid(Blocks.BirthFile),
            Fixed(Latin1(e.Machine), 16),
            U32(e.Number),
            U32(0),
            U32(0xBF800000),
            U64(e.LastAccess),
            I32(e.Pin));
        var path = Utf16(e.Path);

        if (version == 1)
        {
            return Concat(common, U16((ushort)e.Path.Length), path);
        }

        return Concat(common, U32(0xFFFFFFFF), U32(e.AccessCount), U64(0), U16((ushort)e.Path.Length), path, U32(0));
    }

    internal static Dictionary<string, byte[]> Streams(params (uint Number, byte[] Link)[] links)
    {
        var streams = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (number, link) in links)
        {
            streams[number.ToString("x")] = link;
        }

        return streams;
    }

    internal static byte[] LinkTo(string path, string arguments) => new LinkFixture
    {
        IdList = Items.IdList(Items.Root(Items.MyComputer), Items.Volume("C:\\"), Items.FileEntry(path, directory: false, longName: path)),
        Arguments = arguments,
    }.Build();

    /// <summary>Three entries with matching link streams — the ordinary automatic jump list.</summary>
    internal static (byte[] DestList, Dictionary<string, byte[]> Streams) OrdinaryAutomatic(uint version = 3)
    {
        var entries = new[]
        {
            new DestEntry { Number = 1, Path = "C:\\Users\\a.txt", AccessCount = 4 },
            new DestEntry { Number = 2, Path = "C:\\Users\\b.txt", AccessCount = 2, Pin = 0 },
            new DestEntry { Number = 3, Path = "\\\\server\\share\\c.txt", AccessCount = 9 },
        };
        var streams = Streams(
            (1, LinkTo("a.txt", "--one")),
            (2, LinkTo("b.txt", "--two")),
            (3, LinkTo("c.txt", "--three")));
        return (DestList(version, entries), streams);
    }

    internal static byte[] Custom(uint declaredCount, IReadOnlyList<byte[]> links, bool footer = true, bool categoryGuidBeforeEach = true)
    {
        var parts = new List<byte[]> { U32(2), U32(0), U32(0), U32(declaredCount) };
        foreach (var link in links)
        {
            if (categoryGuidBeforeEach)
            {
                parts.Add(Guid(ShellLinkReader.ShellLinkClassId));
            }

            parts.Add(link);
        }

        if (footer)
        {
            parts.Add(U32(JumpListReader.CustomDestinationsFooter));
        }

        return Concat(parts.ToArray());
    }
}
