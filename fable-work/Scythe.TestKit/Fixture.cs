namespace Scythe.TestKit;

/// <summary>A named byte range recorded while the fixture was built. Offsets are relative to the buffer, never to the parent region.</summary>
public sealed record FixtureRegion(string Name, int Offset, int Length, string? Parent)
{
    /// <summary>One past the last byte of the region.</summary>
    public int End => Offset + Length;
}

/// <summary>
/// A named integer slot recorded while the fixture was built — a placeholder that was resolved,
/// a <c>Field</c> written with an immediate value, or a checksum slot. <see cref="Value"/> is the
/// bit pattern that was written (two's complement for a negative resolution); a mutation reads
/// the *current* value out of the buffer instead, so mutations compose.
/// </summary>
public sealed record FixtureField(string Name, int Offset, int Width, Endian Endian, ulong Value)
{
    public int End => Offset + Width;
}

/// <summary>A checksum slot and the region it was computed over.</summary>
public sealed record FixtureChecksum(string Field, string Region, ChecksumKind Kind);

/// <summary>
/// A built fixture: the bytes plus the map of named regions, fields and checksums recorded
/// during construction. The map is what the mutation library addresses.
/// </summary>
public sealed class Fixture
{
    private readonly byte[] bytes;
    private readonly Dictionary<string, FixtureRegion> regionsByName;
    private readonly Dictionary<string, FixtureField> fieldsByName;
    private readonly Dictionary<string, FixtureChecksum> checksumsByField;

    internal Fixture(
        byte[] bytes,
        IReadOnlyList<FixtureRegion> regions,
        IReadOnlyList<FixtureField> fields,
        IReadOnlyList<FixtureChecksum> checksums)
    {
        this.bytes = bytes;
        Regions = regions;
        Fields = fields;
        Checksums = checksums;
        regionsByName = regions.ToDictionary(r => r.Name, StringComparer.Ordinal);
        fieldsByName = fields.ToDictionary(f => f.Name, StringComparer.Ordinal);
        checksumsByField = checksums.ToDictionary(c => c.Field, StringComparer.Ordinal);
    }

    public int Length => bytes.Length;

    public ReadOnlyMemory<byte> Bytes => bytes;

    /// <summary>Regions in the order their bodies were opened.</summary>
    public IReadOnlyList<FixtureRegion> Regions { get; }

    /// <summary>Fields in the order their slots were reserved.</summary>
    public IReadOnlyList<FixtureField> Fields { get; }

    public IReadOnlyList<FixtureChecksum> Checksums { get; }

    /// <summary>A fresh copy of the bytes. Callers may mutate it; the fixture never changes.</summary>
    public byte[] ToArray() => (byte[])bytes.Clone();

    public bool HasRegion(string name) => regionsByName.ContainsKey(name);

    public bool HasField(string name) => fieldsByName.ContainsKey(name);

    public FixtureRegion Region(string name)
    {
        if (!regionsByName.TryGetValue(name, out var region))
        {
            throw new FixtureException($"no region named '{name}' was recorded; recorded regions: {Names(Regions.Select(r => r.Name))}");
        }

        return region;
    }

    public FixtureField Field(string name)
    {
        if (!fieldsByName.TryGetValue(name, out var field))
        {
            throw new FixtureException($"no field named '{name}' was recorded; recorded fields: {Names(Fields.Select(f => f.Name))}");
        }

        return field;
    }

    public bool TryChecksum(string field, out FixtureChecksum checksum) => checksumsByField.TryGetValue(field, out checksum!);

    /// <summary>The bytes of a region, as a fresh copy.</summary>
    public byte[] RegionBytes(string name)
    {
        var region = Region(name);
        return bytes.AsSpan(region.Offset, region.Length).ToArray();
    }

    /// <summary>The value a field currently holds in the buffer.</summary>
    public ulong ReadField(string name)
    {
        var field = Field(name);
        return FieldCodec.Read(bytes.AsSpan(field.Offset, field.Width), field.Width, field.Endian);
    }

    /// <summary>
    /// The same map over different bytes of the same length — the way to apply a second mutation
    /// on top of a first. A different length would leave regions pointing past the end, so it is
    /// refused; truncation is the end of a mutation chain, not a step in one.
    /// </summary>
    public Fixture WithBytes(byte[] replacement)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        if (replacement.Length != bytes.Length)
        {
            throw new FixtureException($"WithBytes needs {bytes.Length} bytes to fit the recorded map, got {replacement.Length}");
        }

        return new Fixture((byte[])replacement.Clone(), Regions, Fields, Checksums);
    }

    /// <summary>The ancestors of a region, nearest first.</summary>
    public IReadOnlyList<FixtureRegion> Ancestors(string name)
    {
        var chain = new List<FixtureRegion>();
        var current = Region(name);
        while (current.Parent is not null)
        {
            current = Region(current.Parent);
            chain.Add(current);
        }

        return chain;
    }

    internal static string Names(IEnumerable<string> names)
    {
        var list = names.ToList();
        return list.Count == 0 ? "(none)" : string.Join(", ", list.Select(n => "'" + n + "'"));
    }
}
