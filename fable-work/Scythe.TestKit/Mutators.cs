namespace Scythe.TestKit;

/// <summary>
/// The standard malformed variants (reference/17.2_mutations.md). Every mutator reads the
/// field's *current* value from the buffer rather than the recorded one, so mutations compose
/// through <see cref="Fixture.WithBytes"/>. Every mutator that finds it has nothing to change
/// throws rather than yielding the original — a no-op mutation makes a test pass for the
/// wrong reason, which is the one failure this kit exists to design out.
/// </summary>
public static class Mutators
{
    /// <summary>Sets a length field beyond the buffer: one past the buffer length, and all-ones for the width.</summary>
    public static Mutator LengthTooLong(string field) => fixture =>
    {
        var f = fixture.Field(field);
        return Distinct(fixture, f, "length field", "beyond the buffer", (ulong)fixture.Length + 1, FieldCodec.MaxUnsigned(f.Width));
    };

    /// <summary>Sets a length field one below its current value.</summary>
    public static Mutator LengthTooShort(string field) => fixture =>
    {
        var f = fixture.Field(field);
        ulong current = fixture.ReadField(field);
        if (current == 0)
        {
            throw new FixtureException($"LengthTooShort('{field}') cannot apply: the field is already 0 and has nothing below it");
        }

        return One(fixture, f, current - 1, $"length field '{field}' set one short, {Hex(current, f)} -> {Hex(current - 1, f)} (buffer is {Size(fixture)})");
    };

    /// <summary>Sets a length field to zero, the value that makes a parse loop stop advancing.</summary>
    public static Mutator LengthZero(string field) => fixture =>
    {
        var f = fixture.Field(field);
        ulong current = fixture.ReadField(field);
        if (current == 0)
        {
            throw new FixtureException($"LengthZero('{field}') cannot apply: the field is already 0");
        }

        return One(fixture, f, 0, $"length field '{field}' set to 0 from {Hex(current, f)} (buffer is {Size(fixture)})");
    };

    /// <summary>Points an offset field at the buffer length (the first byte that does not exist) and at all-ones.</summary>
    public static Mutator OffsetPastEnd(string field) => fixture =>
    {
        var f = fixture.Field(field);
        return Distinct(fixture, f, "offset field", "past the end", (ulong)fixture.Length, FieldCodec.MaxUnsigned(f.Width));
    };

    /// <summary>Points a structure's offset field at the start of the region containing it — a one-node cycle.</summary>
    public static Mutator OffsetToSelf(string field, string region) => fixture =>
    {
        var f = fixture.Field(field);
        var r = fixture.Region(region);
        ulong current = fixture.ReadField(field);
        if (current == (ulong)r.Offset)
        {
            throw new FixtureException($"OffsetToSelf('{field}', '{region}') cannot apply: the field already holds the start of '{region}' ({Hex(current, f)})");
        }

        return One(fixture, f, (ulong)r.Offset, $"offset field '{field}' pointed at its own structure '{region}' at {FieldCodec.Hex(r.Offset)} (was {Hex(current, f)})");
    };

    /// <summary>Points a child's offset field at each of its ancestors in turn — a cycle across levels.</summary>
    public static Mutator OffsetToParent(string field, string region) => fixture =>
    {
        var f = fixture.Field(field);
        var ancestors = fixture.Ancestors(region);
        if (ancestors.Count == 0)
        {
            throw new FixtureException($"OffsetToParent('{field}', '{region}') cannot apply: region '{region}' has no parent region");
        }

        ulong current = fixture.ReadField(field);
        var result = new List<Mutation>();
        foreach (var ancestor in ancestors)
        {
            if ((ulong)ancestor.Offset == current)
            {
                continue;
            }

            result.Add(One(fixture, f, (ulong)ancestor.Offset, $"offset field '{field}' in '{region}' pointed at ancestor '{ancestor.Name}' at {FieldCodec.Hex(ancestor.Offset)} (was {Hex(current, f)})")[0]);
        }

        if (result.Count == 0)
        {
            throw new FixtureException($"OffsetToParent('{field}', '{region}') cannot apply: the field already points at the only ancestor");
        }

        return result;
    };

    /// <summary>Multiplies a count field by <paramref name="factor"/>, saturating at the width's maximum.</summary>
    public static Mutator CountInflated(string field, ulong factor = 1000) => fixture =>
    {
        if (factor < 2)
        {
            throw new FixtureException($"CountInflated('{field}', {factor}) cannot apply: the factor must be at least 2");
        }

        var f = fixture.Field(field);
        ulong current = fixture.ReadField(field);
        if (current == 0)
        {
            throw new FixtureException($"CountInflated('{field}') cannot apply: the count is 0 and any multiple of it is still 0");
        }

        ulong max = FieldCodec.MaxUnsigned(f.Width);
        ulong inflated = current > max / factor ? max : current * factor;
        if (inflated == current)
        {
            throw new FixtureException($"CountInflated('{field}') cannot apply: the count already holds the width's maximum {Hex(current, f)}");
        }

        string how = inflated == max ? $"saturated at {Hex(max, f)}" : $"x{factor}";
        return One(fixture, f, inflated, $"count field '{field}' inflated {Hex(current, f)} -> {Hex(inflated, f)} ({how}; buffer is {Size(fixture)})");
    };

    /// <summary>
    /// Cuts the buffer at each boundary of the region in turn: at its start (nothing of the
    /// region), one byte before its end (the region one short), and at its end (the region
    /// complete but nothing after it). A cut that would leave the buffer whole is not a truncation
    /// and is not yielded.
    /// </summary>
    public static Mutator TruncateAt(string region) => fixture =>
    {
        var r = fixture.Region(region);
        var cuts = new List<(int At, string Why)>
        {
            (r.Offset, $"at the start of '{region}'"),
        };
        if (r.Length > 0)
        {
            cuts.Add((r.End - 1, $"one byte before the end of '{region}'"));
        }

        cuts.Add((r.End, $"at the end of '{region}'"));
        var result = Truncations(fixture, cuts);
        if (result.Count == 0)
        {
            throw new FixtureException($"TruncateAt('{region}') cannot apply: every boundary of the region is the buffer's own end ({Size(fixture)})");
        }

        return result;
    };

    /// <summary>Every distinct region boundary in the fixture, in ascending offset order.</summary>
    public static Mutator TruncateAtEveryBoundary() => fixture =>
    {
        if (fixture.Regions.Count == 0)
        {
            throw new FixtureException("TruncateAtEveryBoundary cannot apply: the fixture recorded no regions");
        }

        var cuts = new List<(int At, string Why)>();
        foreach (var r in fixture.Regions)
        {
            cuts.Add((r.Offset, $"at the start of '{r.Name}'"));
            if (r.Length > 0)
            {
                cuts.Add((r.End - 1, $"one byte before the end of '{r.Name}'"));
            }

            cuts.Add((r.End, $"at the end of '{r.Name}'"));
        }

        var result = Truncations(fixture, cuts.OrderBy(c => c.At).ToList());
        if (result.Count == 0)
        {
            throw new FixtureException($"TruncateAtEveryBoundary cannot apply: every region boundary is the buffer's own end ({Size(fixture)})");
        }

        return result;
    };

    /// <summary>
    /// For each checksum declared over the region: flips one bit of covered data outside the
    /// checksum slot, and separately flips one bit of the stored checksum. Either makes the
    /// stored value disagree with the bytes, so a reader that verifies must notice both.
    /// </summary>
    public static Mutator CorruptChecksum(string region) => fixture =>
    {
        fixture.Region(region);
        var declared = fixture.Checksums.Where(c => string.Equals(c.Region, region, StringComparison.Ordinal)).ToList();
        if (declared.Count == 0)
        {
            throw new FixtureException($"CorruptChecksum('{region}') cannot apply: no checksum was declared over '{region}'; declared checksums cover {Fixture.Names(fixture.Checksums.Select(c => c.Region))}");
        }

        var r = fixture.Region(region);
        var result = new List<Mutation>();
        foreach (var checksum in declared)
        {
            var slot = fixture.Field(checksum.Field);
            int? dataByte = null;
            for (int i = r.Offset; i < r.End; i++)
            {
                if (i < slot.Offset || i >= slot.End)
                {
                    dataByte = i;
                    break;
                }
            }

            if (dataByte is int at)
            {
                var bytes = fixture.ToArray();
                bytes[at] ^= 0x01;
                result.Add(new Mutation($"bit 0 of byte {FieldCodec.Hex(at)} flipped inside region '{region}', which is covered by {checksum.Kind} field '{checksum.Field}' (stored value left at {Hex(fixture.ReadField(checksum.Field), slot)})", bytes));
            }

            var stored = fixture.ToArray();
            stored[slot.Offset] ^= 0x01;
            result.Add(new Mutation($"bit 0 of the stored {checksum.Kind} '{checksum.Field}' at {FieldCodec.Hex(slot.Offset)} flipped (was {Hex(fixture.ReadField(checksum.Field), slot)}); region '{region}' left intact", stored));
        }

        return result;
    };

    /// <summary>One variant per byte of the region, each with that byte inverted (XOR 0xFF). Use on small regions.</summary>
    public static Mutator FlipByteIn(string region) => fixture =>
    {
        var r = fixture.Region(region);
        if (r.Length == 0)
        {
            throw new FixtureException($"FlipByteIn('{region}') cannot apply: the region is empty");
        }

        var result = new List<Mutation>(r.Length);
        for (int i = r.Offset; i < r.End; i++)
        {
            result.Add(FlipAt(fixture, i, $" in region '{region}'"));
        }

        return result;
    };

    /// <summary>One byte at an absolute offset inverted. An offset outside the buffer is an error.</summary>
    public static Mutator FlipByteAt(int offset) => fixture =>
    {
        if (offset < 0 || offset >= fixture.Length)
        {
            throw new FixtureException($"FlipByteAt({FieldCodec.Hex(offset)}) cannot apply: the buffer is {Size(fixture)}, valid offsets are 0x0..{FieldCodec.Hex(fixture.Length - 1)}");
        }

        return new[] { FlipAt(fixture, offset, string.Empty) };
    };

    /// <summary>
    /// Copies region <paramref name="b"/>'s bytes so they begin halfway through region
    /// <paramref name="a"/>, producing two overlapping structures. The original copy of
    /// <paramref name="b"/> stays where it was.
    /// </summary>
    public static Mutator Interleave(string a, string b) => fixture =>
    {
        var ra = fixture.Region(a);
        var rb = fixture.Region(b);
        if (ra.Length == 0 || rb.Length == 0)
        {
            throw new FixtureException($"Interleave('{a}', '{b}') cannot apply: both regions must be non-empty ('{a}' is {ra.Length} bytes, '{b}' is {rb.Length})");
        }

        if (ra.Offset < rb.End && rb.Offset < ra.End)
        {
            throw new FixtureException($"Interleave('{a}', '{b}') cannot apply: the regions already overlap ({Span(ra)} and {Span(rb)})");
        }

        int at = ra.Offset + ra.Length / 2;
        var bytes = fixture.ToArray();
        int count = Math.Min(rb.Length, bytes.Length - at);
        fixture.Bytes.Span.Slice(rb.Offset, count).CopyTo(bytes.AsSpan(at, count));
        if (bytes.AsSpan().SequenceEqual(fixture.Bytes.Span))
        {
            throw new FixtureException($"Interleave('{a}', '{b}') cannot apply: copying '{b}' over the second half of '{a}' changes no byte");
        }

        return new[] { new Mutation($"region '{b}' ({Span(rb)}) copied over {FieldCodec.Hex(at)}..{FieldCodec.Hex(at + count)}, overlapping the second half of '{a}' ({Span(ra)})", bytes) };
    };

    /// <summary>Points an offset field into the middle of another structure.</summary>
    public static Mutator OffsetInto(string field, string region) => fixture =>
    {
        var f = fixture.Field(field);
        var r = fixture.Region(region);
        if (r.Length < 2)
        {
            throw new FixtureException($"OffsetInto('{field}', '{region}') cannot apply: '{region}' is {r.Length} byte(s) long and has no interior");
        }

        ulong target = (ulong)(r.Offset + r.Length / 2);
        ulong current = fixture.ReadField(field);
        if (current == target)
        {
            throw new FixtureException($"OffsetInto('{field}', '{region}') cannot apply: the field already holds {Hex(target, f)}");
        }

        return One(fixture, f, target, $"offset field '{field}' pointed into the middle of '{region}' at {Hex(target, f)} (was {Hex(current, f)}; region is {Span(r)})");
    };

    /// <summary>Sets a recorded field to an explicit value.</summary>
    public static Mutator SetField(string field, ulong value, string? why = null) => fixture =>
    {
        var f = fixture.Field(field);
        if (value > FieldCodec.MaxUnsigned(f.Width))
        {
            throw new FixtureException($"SetField('{field}', {FieldCodec.Hex((long)value)}) cannot apply: the field is {f.Width} byte(s) wide");
        }

        ulong current = fixture.ReadField(field);
        if (current == value)
        {
            throw new FixtureException($"SetField('{field}', {Hex(value, f)}) cannot apply: the field already holds that value");
        }

        string suffix = why is null ? string.Empty : " — " + why;
        return One(fixture, f, value, $"field '{field}' set {Hex(current, f)} -> {Hex(value, f)}{suffix}");
    };

    /// <summary>A caller-supplied transformation, with the same no-op guard as the standard set.</summary>
    public static Mutator Custom(string description, Func<byte[], byte[]> transform) => fixture =>
    {
        ArgumentNullException.ThrowIfNull(transform);
        byte[] output = transform(fixture.ToArray());
        if (output.AsSpan().SequenceEqual(fixture.Bytes.Span))
        {
            throw new FixtureException($"custom mutation '{description}' cannot apply: it returned the input unchanged");
        }

        return new[] { new Mutation(description, output) };
    };

    // ---- helpers ----------------------------------------------------------------------------

    private static IReadOnlyList<Mutation> One(Fixture fixture, FixtureField f, ulong value, string description)
    {
        var bytes = fixture.ToArray();
        FieldCodec.Write(bytes.AsSpan(f.Offset, f.Width), f.Width, f.Endian, value);
        return new[] { new Mutation(description, bytes) };
    }

    private static IReadOnlyList<Mutation> Distinct(Fixture fixture, FixtureField f, string kind, string intent, params ulong[] candidates)
    {
        ulong current = fixture.ReadField(f.Name);
        ulong max = FieldCodec.MaxUnsigned(f.Width);
        var result = new List<Mutation>();
        var seen = new HashSet<ulong>();
        foreach (ulong candidate in candidates)
        {
            if (candidate > max || candidate == current || !seen.Add(candidate))
            {
                continue;
            }

            result.Add(One(fixture, f, candidate, $"{kind} '{f.Name}' set {intent}, {Hex(current, f)} -> {Hex(candidate, f)} (buffer is {Size(fixture)})")[0]);
        }

        if (result.Count == 0)
        {
            throw new FixtureException($"{kind} '{f.Name}' cannot be set {intent}: it already holds {Hex(current, f)} and no other value of its width qualifies (buffer is {Size(fixture)})");
        }

        return result;
    }

    private static IReadOnlyList<Mutation> Truncations(Fixture fixture, IReadOnlyList<(int At, string Why)> cuts)
    {
        var result = new List<Mutation>();
        var seen = new HashSet<int>();
        foreach (var (at, why) in cuts)
        {
            if (at >= fixture.Length || !seen.Add(at))
            {
                continue;
            }

            result.Add(new Mutation($"buffer truncated {why}: {fixture.Length} -> {at} bytes", fixture.Bytes.Span[..at].ToArray()));
        }

        return result;
    }

    private static Mutation FlipAt(Fixture fixture, int offset, string where)
    {
        var bytes = fixture.ToArray();
        byte was = bytes[offset];
        bytes[offset] = (byte)(was ^ 0xFF);
        return new Mutation($"byte at {FieldCodec.Hex(offset)}{where} inverted, 0x{was:X2} -> 0x{bytes[offset]:X2}", bytes);
    }

    private static string Hex(ulong value, FixtureField f) => FieldCodec.Hex(value, f.Width);

    private static string Size(Fixture fixture) => $"{FieldCodec.Hex(fixture.Length)} bytes";

    private static string Span(FixtureRegion r) => $"{FieldCodec.Hex(r.Offset)}..{FieldCodec.Hex(r.End)}";
}
