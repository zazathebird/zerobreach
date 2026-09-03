namespace Scythe.TestKit;

/// <summary>
/// Fluent, append-only construction of a byte buffer that records named regions and fields as it
/// writes, so that the mutation library can address "the length field of the root cell" rather
/// than a hand-computed offset. reference/17.1_builder.md.
/// </summary>
/// <remarks>
/// The rules the reference makes non-negotiable, and where each is enforced:
/// <list type="bullet">
/// <item><see cref="Build"/> throws on an unresolved placeholder — never a silent zero.</item>
/// <item>A second <see cref="Resolve"/> of the same placeholder throws (<see cref="Mark"/>).</item>
/// <item>A value too wide for its slot throws (<see cref="Mark"/>); nothing is truncated.</item>
/// <item>Region extents are buffer-relative even when nested.</item>
/// <item>The same script produces byte-identical output on every run: the builder holds no
/// clock, no randomness and no hash-order dependence (every map is keyed ordinally and every
/// list is kept in declaration order).</item>
/// </list>
/// </remarks>
public sealed partial class FixtureBuilder
{
    private readonly List<byte> buffer = new();
    private readonly List<FixtureRegion> regions = new();
    private readonly Dictionary<string, int> regionIndex = new(StringComparer.Ordinal);
    private readonly Stack<string> openRegions = new();
    private readonly List<Slot> slots = new();
    private readonly Dictionary<string, Slot> slotIndex = new(StringComparer.Ordinal);
    private readonly ScanBudget budget;

    public FixtureBuilder(Endian endian, ScanBudget? budget = null)
    {
        Endian = endian;
        this.budget = budget ?? ScanBudget.Default;
    }

    /// <summary>The byte order every integer and length prefix uses unless a call overrides it.</summary>
    public Endian Endian { get; }

    /// <summary>
    /// The offset the next byte will be written at. In an append-only builder this is always
    /// equal to <see cref="Length"/>; both names exist because a script reads better when it says
    /// which it means ("resolve to the position of the root" versus "resolve to the total length").
    /// </summary>
    public int Position => buffer.Count;

    public int Length => buffer.Count;

    /// <summary>Region nesting depth at this point in the script.</summary>
    public int Depth => openRegions.Count;

    // ---- structure --------------------------------------------------------------------------

    /// <summary>
    /// Runs <paramref name="body"/> and records the bytes it wrote as a region. Regions may nest;
    /// a nested region's parent is recorded so a mutation can point a child at its ancestor.
    /// </summary>
    public FixtureBuilder Region(string name, Action body)
    {
        ArgumentNullException.ThrowIfNull(body);
        return Region(name, _ => body());
    }

    public FixtureBuilder Region(string name, Action<FixtureBuilder> body)
    {
        ArgumentNullException.ThrowIfNull(body);
        RequireName(name, "region");
        if (regionIndex.ContainsKey(name))
        {
            throw new FixtureException($"region '{name}' was already recorded at offset {FieldCodec.Hex(regions[regionIndex[name]].Offset)}; region names must be unique");
        }

        if (openRegions.Count >= budget.MaxNestingDepth)
        {
            throw new FixtureException($"region '{name}' would nest {openRegions.Count + 1} deep; the budget allows {budget.MaxNestingDepth}");
        }

        string? parent = openRegions.Count == 0 ? null : openRegions.Peek();
        int start = buffer.Count;

        // Reserve the index slot before the body runs so that regions are listed in the order
        // they were opened — an outer region precedes the inner ones it contains.
        int index = regions.Count;
        regions.Add(new FixtureRegion(name, start, 0, parent));
        regionIndex[name] = index;
        openRegions.Push(name);
        try
        {
            body(this);
        }
        finally
        {
            openRegions.Pop();
        }

        regions[index] = new FixtureRegion(name, start, buffer.Count - start, parent);
        return this;
    }

    /// <summary>A recorded (and closed) region. Throws if the name is unknown or the region is still open.</summary>
    public FixtureRegion RegionOf(string name)
    {
        if (!regionIndex.TryGetValue(name, out int index))
        {
            throw new FixtureException($"no region named '{name}' has been recorded; recorded regions: {Fixture.Names(regions.Select(r => r.Name))}");
        }

        if (openRegions.Contains(name))
        {
            throw new FixtureException($"region '{name}' is still open; its length is not known until its body returns");
        }

        return regions[index];
    }

    /// <summary>Reserves <paramref name="width"/> bytes to be filled by a later <see cref="Resolve"/>.</summary>
    public FixtureBuilder Placeholder(string name, int width, Endian? endian = null)
    {
        Reserve(name, width, endian ?? Endian);
        return this;
    }

    /// <summary>A named integer written now, so that a mutation can address it later.</summary>
    public FixtureBuilder Field(string name, int width, long value, Endian? endian = null)
    {
        var slot = Reserve(name, width, endian ?? Endian);
        Mark(slot, value, "the immediate value");
        return this;
    }

    /// <summary>Fills a placeholder. Exactly one resolution per placeholder; the second throws.</summary>
    public FixtureBuilder Resolve(string name, long value)
    {
        var slot = SlotOf(name);
        RequireUnresolved(slot, "an immediate value");
        Mark(slot, value, "an immediate value");
        return this;
    }

    /// <summary>Resolves a placeholder to the current write position — "the next structure starts here".</summary>
    public FixtureBuilder ResolveToPosition(string name) => Resolve(name, Position);

    /// <summary>
    /// Resolves a placeholder to a value computed at <see cref="Build"/> time, after every byte
    /// has been written. This is what lets a header field depend on a region that is written
    /// later, and lets an outer size depend on an inner one: nothing is computed until the
    /// whole script has run, so declaration order cannot make the fixture inconsistent.
    /// </summary>
    public FixtureBuilder ResolveLater(string name, string description, Func<FixtureBuilder, long> compute)
    {
        ArgumentNullException.ThrowIfNull(compute);
        var slot = SlotOf(name);
        RequireUnresolved(slot, description);
        slot.Deferred = compute;
        slot.DeferredDescription = description;
        return this;
    }

    public FixtureBuilder ResolveToRegionStart(string name, string region) =>
        ResolveLater(name, $"the start of region '{region}'", b => b.RegionOf(region).Offset);

    public FixtureBuilder ResolveToRegionLength(string name, string region) =>
        ResolveLater(name, $"the length of region '{region}'", b => b.RegionOf(region).Length);

    public FixtureBuilder ResolveToRegionEnd(string name, string region) =>
        ResolveLater(name, $"the end of region '{region}'", b => b.RegionOf(region).End);

    /// <summary>Resolves to the final buffer length — the usual "total size" header field.</summary>
    public FixtureBuilder ResolveToLength(string name) =>
        ResolveLater(name, "the final buffer length", b => b.Length);

    // ---- build ------------------------------------------------------------------------------

    /// <summary>
    /// Applies every deferred resolution, then every checksum, and returns the fixture. Throws
    /// on an unresolved placeholder, a deferred value that does not fit, or a checksum over a
    /// region that was never recorded.
    /// </summary>
    public Fixture Build()
    {
        if (openRegions.Count > 0)
        {
            throw new FixtureException($"Build() called inside region '{openRegions.Peek()}'; close every region first");
        }

        // Deferred placeholders first, in declaration order, so that a checksum computed
        // afterwards covers the resolved values rather than the zeroed slots.
        foreach (var slot in slots)
        {
            if (slot.Deferred is not null && !slot.Resolved)
            {
                Mark(slot, slot.Deferred(this), slot.DeferredDescription!);
            }
        }

        var checksums = new List<FixtureChecksum>();
        foreach (var slot in slots)
        {
            if (slot.Checksum is null)
            {
                continue;
            }

            checksums.Add(slot.Checksum);
            if (!slot.Resolved)
            {
                var region = RegionOf(slot.Checksum.Region);
                Mark(slot, (long)slot.ComputeChecksum!(RegionBytesWithSlotZeroed(region, slot)), $"the {slot.Checksum.Kind} of region '{slot.Checksum.Region}'");
            }
        }

        var unresolved = slots.Where(s => !s.Resolved).Select(s => s.Name).ToList();
        if (unresolved.Count > 0)
        {
            throw new FixtureException($"Build() with {unresolved.Count} unresolved placeholder(s): {Fixture.Names(unresolved)}; every placeholder must be resolved, a silent zero would test the wrong value");
        }

        var fields = slots.Select(s => new FixtureField(s.Name, s.Offset, s.Width, s.Endian, s.Value)).ToList();
        return new Fixture(buffer.ToArray(), regions.ToList(), fields, checksums);
    }

    // ---- internals --------------------------------------------------------------------------

    private sealed class Slot
    {
        public required string Name { get; init; }

        public required int Offset { get; init; }

        public required int Width { get; init; }

        public required Endian Endian { get; init; }

        public bool Resolved { get; set; }

        public ulong Value { get; set; }

        public string? ResolvedAs { get; set; }

        public Func<FixtureBuilder, long>? Deferred { get; set; }

        public string? DeferredDescription { get; set; }

        public FixtureChecksum? Checksum { get; set; }

        public Func<byte[], ulong>? ComputeChecksum { get; set; }
    }

    private Slot Reserve(string name, int width, Endian endian)
    {
        RequireName(name, "field");
        if (!FieldCodec.IsSupportedWidth(width))
        {
            throw new FixtureException($"field '{name}': unsupported width {width}; use 1, 2, 4 or 8");
        }

        if (slotIndex.ContainsKey(name))
        {
            throw new FixtureException($"field '{name}' was already reserved at offset {FieldCodec.Hex(slotIndex[name].Offset)}; field names must be unique");
        }

        var slot = new Slot { Name = name, Offset = buffer.Count, Width = width, Endian = endian };
        slots.Add(slot);
        slotIndex[name] = slot;
        Zeroes(width);
        return slot;
    }

    private Slot SlotOf(string name)
    {
        if (!slotIndex.TryGetValue(name, out var slot))
        {
            throw new FixtureException($"no placeholder or field named '{name}' was reserved; reserved names: {Fixture.Names(slots.Select(s => s.Name))}");
        }

        return slot;
    }

    private static void RequireUnresolved(Slot slot, string attempt)
    {
        if (slot.Resolved)
        {
            throw new FixtureException($"placeholder '{slot.Name}' was already resolved to {FieldCodec.Hex(slot.Value, slot.Width)} ({slot.ResolvedAs}); a second resolution ({attempt}) is two intentions, not one");
        }

        if (slot.Deferred is not null)
        {
            throw new FixtureException($"placeholder '{slot.Name}' already has a deferred resolution ({slot.DeferredDescription}); a second resolution ({attempt}) is two intentions, not one");
        }

        if (slot.Checksum is not null)
        {
            throw new FixtureException($"'{slot.Name}' is a {slot.Checksum.Kind} slot over region '{slot.Checksum.Region}' and is filled at Build(); it cannot also be resolved ({attempt})");
        }
    }

    /// <summary>The one place a slot's bytes are written. Enforces single resolution and width.</summary>
    private void Mark(Slot slot, long value, string description)
    {
        if (slot.Resolved)
        {
            throw new FixtureException($"placeholder '{slot.Name}' was already resolved to {FieldCodec.Hex(slot.Value, slot.Width)} ({slot.ResolvedAs}); a second resolution ({description}) is two intentions, not one");
        }

        if (!FieldCodec.Fits(value, slot.Width))
        {
            throw new FixtureException($"placeholder '{slot.Name}' is {slot.Width} byte(s) wide and cannot hold {value} ({FieldCodec.Hex(value)}) from {description}; nothing was truncated");
        }

        ulong bits = FieldCodec.ToBits(value, slot.Width);
        Span<byte> span = stackalloc byte[slot.Width];
        FieldCodec.Write(span, slot.Width, slot.Endian, bits);
        for (int i = 0; i < slot.Width; i++)
        {
            buffer[slot.Offset + i] = span[i];
        }

        slot.Resolved = true;
        slot.Value = bits;
        slot.ResolvedAs = description;
    }

    private byte[] RegionBytesWithSlotZeroed(FixtureRegion region, Slot slot)
    {
        var bytes = new byte[region.Length];
        buffer.CopyTo(region.Offset, bytes, 0, region.Length);

        // A header checksum usually sits inside the header it covers, and every such format
        // computes it with the slot itself taken as zero. The slot is zero at this point anyway
        // (it has not been resolved), so this is a statement of the rule rather than a change.
        int overlapStart = Math.Max(slot.Offset, region.Offset);
        int overlapEnd = Math.Min(slot.Offset + slot.Width, region.End);
        for (int i = overlapStart; i < overlapEnd; i++)
        {
            bytes[i - region.Offset] = 0;
        }

        return bytes;
    }

    private static void RequireName(string name, string kind)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new FixtureException($"a {kind} needs a non-empty name");
        }
    }

    private static void RequireNonNegative(int count, string what)
    {
        if (count < 0)
        {
            throw new FixtureException($"{what} cannot be negative, got {count}");
        }
    }
}
