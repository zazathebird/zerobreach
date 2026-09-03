namespace Scythe.TestKit;

/// <summary>
/// A deterministic generator. Every entry point takes a seed, and the seed appears in every
/// failure message. The engine is SplitMix64 — a few multiplies and shifts with no dependence
/// on the runtime, so the same seed yields the same sequence across runs and across processes
/// (the pinned-sequence test in the kit's own suite is the proof).
/// </summary>
public sealed class Gen
{
    private const ulong Golden = 0x9E3779B97F4A7C15;
    private ulong state;

    public Gen(ulong seed)
    {
        Seed = seed;
        state = seed;
    }

    public ulong Seed { get; }

    public ulong NextU64()
    {
        state += Golden;
        return Mix(state);
    }

    public uint NextU32() => (uint)(NextU64() >> 32);

    public byte NextByte() => (byte)(NextU64() >> 56);

    public bool NextBool() => (NextU64() >> 63) != 0;

    /// <summary>A value in [minInclusive, maxExclusive).</summary>
    public int NextInt(int minInclusive, int maxExclusive)
    {
        if (maxExclusive <= minInclusive)
        {
            throw new FixtureException($"NextInt({minInclusive}, {maxExclusive}): the range is empty");
        }

        ulong range = (ulong)((long)maxExclusive - minInclusive);
        return (int)(minInclusive + (long)(NextU64() % range));
    }

    public byte[] NextBytes(int length)
    {
        RequireSize(length, "NextBytes");
        var bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = NextByte();
        }

        return bytes;
    }

    /// <summary>Between <paramref name="minLength"/> and <paramref name="maxLength"/> bytes inclusive.</summary>
    public byte[] NextBytes(int minLength, int maxLength)
    {
        RequireSize(minLength, "NextBytes");
        RequireSize(maxLength, "NextBytes");
        if (maxLength < minLength)
        {
            throw new FixtureException($"NextBytes({minLength}, {maxLength}): the maximum is below the minimum");
        }

        return NextBytes(NextInt(minLength, maxLength + 1));
    }

    /// <summary>Printable ASCII, 0x20..0x7E.</summary>
    public string NextAscii(int length)
    {
        RequireSize(length, "NextAscii");
        var chars = new char[length];
        for (int i = 0; i < length; i++)
        {
            chars[i] = (char)NextInt(0x20, 0x7F);
        }

        return new string(chars);
    }

    /// <summary>
    /// Well-formed UTF-16 of exactly <paramref name="length"/> code units: BMP scalars outside
    /// the surrogate range, with roughly one in sixteen positions becoming a supplementary-plane
    /// pair where two units remain. Never a lone surrogate — a fixture wanting one writes it
    /// deliberately with <see cref="FixtureBuilder.Utf16Le"/>.
    /// </summary>
    public string NextUtf16(int length)
    {
        RequireSize(length, "NextUtf16");
        var chars = new char[length];
        int i = 0;
        while (i < length)
        {
            if (length - i >= 2 && NextInt(0, 16) == 0)
            {
                int scalar = NextInt(0x10000, 0x10FFFF + 1);
                chars[i++] = (char)(0xD800 + ((scalar - 0x10000) >> 10));
                chars[i++] = (char)(0xDC00 + ((scalar - 0x10000) & 0x3FF));
                continue;
            }

            // 0x0020..0xD7FF then 0xE000..0xFFFD, skipping the surrogate block and the two
            // noncharacters at the top of the plane.
            int pick = NextInt(0x20, 0xD800 + (0xFFFE - 0xE000));
            chars[i++] = (char)(pick < 0xD800 ? pick : pick - 0xD800 + 0xE000);
        }

        return new string(chars);
    }

    // ---- one-shot entry points, each seeded ---------------------------------------------------

    /// <summary>Up to <paramref name="maxLength"/> bytes, length chosen by the seed.</summary>
    public static byte[] Bytes(ulong seed, int maxLength)
    {
        RequireSize(maxLength, "Gen.Bytes");
        return new Gen(seed).NextBytes(0, maxLength);
    }

    public static string Ascii(ulong seed, int maxLength)
    {
        RequireSize(maxLength, "Gen.Ascii");
        var g = new Gen(seed);
        return g.NextAscii(g.NextInt(0, maxLength + 1));
    }

    public static string Utf16(ulong seed, int maxLength)
    {
        RequireSize(maxLength, "Gen.Utf16");
        var g = new Gen(seed);
        return g.NextUtf16(g.NextInt(0, maxLength + 1));
    }

    /// <summary>Runs a builder script that draws its values from a seeded generator.</summary>
    public static Fixture Structured(ulong seed, Endian endian, Action<FixtureBuilder, Gen> script, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(script);
        var builder = new FixtureBuilder(endian, budget);
        script(builder, new Gen(seed));
        return builder.Build();
    }

    /// <summary>
    /// The input for case <paramref name="index"/> of a property run seeded with
    /// <paramref name="seed"/>. Case 0 is always the empty buffer and case 1 is always a
    /// full-length one, so those two corners are covered by every run; the rest are drawn from
    /// a per-case seed derived from the run seed and the index.
    /// </summary>
    public static byte[] Case(ulong seed, int index, int maxLength)
    {
        RequireSize(maxLength, "Gen.Case");
        if (index < 0)
        {
            throw new FixtureException($"Gen.Case: the case index cannot be negative, got {index}");
        }

        return index switch
        {
            0 => Array.Empty<byte>(),
            1 => new Gen(Derive(seed, index)).NextBytes(maxLength),
            _ => Bytes(Derive(seed, index), maxLength),
        };
    }

    public static ulong Derive(ulong seed, int index) => Mix(seed ^ Mix((ulong)index + 1));

    private static ulong Mix(ulong z)
    {
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB;
        return z ^ (z >> 31);
    }

    private static void RequireSize(int size, string what)
    {
        if (size < 0)
        {
            throw new FixtureException($"{what}: a size cannot be negative, got {size}");
        }
    }
}
