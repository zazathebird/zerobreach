using System.Diagnostics;

namespace Scythe.TestKit;

/// <summary>
/// The property harness: <see cref="ForAll"/> runs a check over seeded cases under a budget and
/// shrinks the first failure; the named methods are the properties that recur across the package
/// (reference/17.3_property_harness.md), each a one-liner for a consuming test.
/// </summary>
/// <remarks>
/// The budget binds as follows. <see cref="ScanBudget.Deadline"/> is the wall-clock ceiling for
/// the whole run (cases plus shrinking) — past it the outcome is Exhausted, never Holds.
/// <see cref="ScanBudget.MaxMatches"/> caps the cases run (Exhausted when the plan exceeds it)
/// and separately caps shrink evaluations. <see cref="ScanBudget.MaxInputBytes"/> bounds
/// <c>maxLength</c>; asking for more is a defect in the test and throws.
/// </remarks>
public static class Property
{
    /// <summary>
    /// Runs <paramref name="check"/> on each generated case. The check returns null when the
    /// property holds for that input and a description when it does not; an exception it throws
    /// counts as a failure too, with the exception named in the detail.
    /// </summary>
    public static PropertyReport ForAll(string name, ulong seed, int cases, int maxLength, Func<byte[], string?> check, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(check);
        var b = budget ?? ScanBudget.Default;
        if (cases < 0)
        {
            throw new FixtureException($"property '{name}': the case count cannot be negative, got {cases}");
        }

        if (maxLength < 0)
        {
            throw new FixtureException($"property '{name}': maxLength cannot be negative, got {maxLength}");
        }

        if (maxLength > b.MaxInputBytes)
        {
            throw new FixtureException($"property '{name}': maxLength {maxLength} exceeds the budget's MaxInputBytes {b.MaxInputBytes}");
        }

        var clock = Stopwatch.StartNew();
        int run = 0;
        for (int i = 0; i < cases; i++)
        {
            if (run >= b.MaxMatches)
            {
                return Exhausted(name, seed, maxLength, cases, run, $"case ceiling reached: the budget's MaxMatches is {b.MaxMatches}, {cases} cases were planned");
            }

            if (clock.Elapsed > b.Deadline)
            {
                return Exhausted(name, seed, maxLength, cases, run, $"deadline of {b.Deadline.TotalMilliseconds:0} ms passed after {run} cases");
            }

            byte[] input = Gen.Case(seed, i, maxLength);
            run++;
            string? detail = Evaluate(check, input);
            if (detail is null)
            {
                continue;
            }

            var shrunk = Shrinker.Shrink(input, candidate => Evaluate(check, candidate) is not null, b.MaxMatches);
            string? finalDetail = Evaluate(check, shrunk.Minimal) ?? detail;
            return new PropertyReport(name, seed, maxLength, cases, run, PropertyOutcome.Falsified, finalDetail, i, input, shrunk.Minimal, shrunk.Steps, shrunk.Evaluations, shrunk.Capped);
        }

        return new PropertyReport(name, seed, maxLength, cases, run, PropertyOutcome.Holds, null, null, null, null, 0, 0, false);
    }

    /// <summary>For any input, the reader returns; no exception escapes.</summary>
    public static PropertyReport NeverThrows(Action<byte[]> reader, ulong seed, int cases, int maxLength, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return ForAll("NeverThrows", seed, cases, maxLength, input =>
        {
            reader(input);
            return null;
        }, budget);
    }

    /// <summary>The same input twice yields byte-identical serialised output.</summary>
    public static PropertyReport Deterministic(Func<byte[], byte[]> serialise, ulong seed, int cases, int maxLength, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(serialise);
        return ForAll("Deterministic", seed, cases, maxLength, input =>
        {
            byte[] first = serialise(input);
            byte[] second = serialise(input);
            return Difference(first, second, "first run", "second run");
        }, budget);
    }

    /// <summary>
    /// No truncation of a fixture that reads <c>Ok</c> whole is reported as <c>Ok</c>. Runs the
    /// reader on the fixture cut at every recorded region boundary. If the whole fixture is not
    /// itself <c>Ok</c> the property is vacuous and the outcome is Exhausted, so a broken fixture
    /// cannot pass this by accident.
    /// </summary>
    public static PropertyReport IncompleteIsNotOk(Fixture fixture, Func<byte[], KitResultState> read)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        ArgumentNullException.ThrowIfNull(read);
        const string Name = "IncompleteIsNotOk";
        var whole = read(fixture.ToArray());
        if (whole != KitResultState.Ok)
        {
            return Exhausted(Name, 0, fixture.Length, 0, 0, $"vacuous: the untruncated fixture reads {whole}, so no truncation of it can show anything");
        }

        var truncations = Mutations.Apply(fixture, Mutators.TruncateAtEveryBoundary());
        for (int i = 0; i < truncations.Count; i++)
        {
            var state = read(truncations[i].Bytes);
            if (state == KitResultState.Ok)
            {
                return new PropertyReport(Name, 0, fixture.Length, truncations.Count, i + 1, PropertyOutcome.Falsified, $"{truncations[i].Description}: the reader reported Ok", i, truncations[i].Bytes, truncations[i].Bytes, 0, 0, false);
            }
        }

        return new PropertyReport(Name, 0, fixture.Length, truncations.Count, truncations.Count, PropertyOutcome.Holds, null, null, null, null, 0, 0, false);
    }

    /// <summary>
    /// Every parse returns within <paramref name="ceiling"/>. Each case runs on a pool thread and
    /// is abandoned if it overruns — .NET cannot stop it — so a hanging reader under test should
    /// be one that eventually returns, or the abandoned work outlives the test.
    /// </summary>
    public static PropertyReport Terminates(Action<byte[]> reader, ulong seed, int cases, int maxLength, TimeSpan ceiling, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return ForAll("Terminates", seed, cases, maxLength, input =>
        {
            var task = Task.Run(() => reader(input));
            if (!task.Wait(ceiling))
            {
                return $"did not return within {ceiling.TotalMilliseconds:0} ms";
            }

            return null;
        }, budget);
    }

    /// <summary>Where a task claims round-tripping: decode-then-encode reproduces the input exactly.</summary>
    public static PropertyReport RoundTrips(Func<byte[], byte[]?> roundTrip, ulong seed, int cases, int maxLength, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(roundTrip);
        return ForAll("RoundTrips", seed, cases, maxLength, input =>
        {
            byte[]? output = roundTrip(input);
            return output is null ? "round trip produced no output" : Difference(input, output, "input", "round-tripped output");
        }, budget);
    }

    /// <summary>
    /// Managed allocation for one read stays within <paramref name="floorBytes"/> +
    /// <paramref name="multiple"/> × input length. Each input is read once unmeasured (JIT and
    /// lazy statics) and then once measured on the calling thread. This is what catches a count
    /// field trusted before it was validated against the buffer.
    /// </summary>
    public static PropertyReport BoundedAllocation(Action<byte[]> reader, double multiple, long floorBytes, ulong seed, int cases, int maxLength, ScanBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if (multiple < 0 || floorBytes < 0)
        {
            throw new FixtureException($"BoundedAllocation: the multiple ({multiple}) and floor ({floorBytes}) cannot be negative");
        }

        return ForAll("BoundedAllocation", seed, cases, maxLength, input =>
        {
            reader(input);
            long before = GC.GetAllocatedBytesForCurrentThread();
            reader(input);
            long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            long allowed = floorBytes + (long)Math.Ceiling(multiple * input.Length);
            return allocated > allowed
                ? $"allocated {allocated} bytes for a {input.Length}-byte input; allowed {allowed} ({floorBytes} + {multiple} x length)"
                : null;
        }, budget);
    }

    // ---- helpers ----------------------------------------------------------------------------

    private static string? Evaluate(Func<byte[], string?> check, byte[] input)
    {
        try
        {
            return check((byte[])input.Clone());
        }
        catch (Exception e)
        {
            return $"threw {e.GetType().FullName}: {e.Message}";
        }
    }

    private static string? Difference(byte[] a, byte[] b, string nameA, string nameB)
    {
        int shorter = Math.Min(a.Length, b.Length);
        for (int i = 0; i < shorter; i++)
        {
            if (a[i] != b[i])
            {
                return $"{nameA} and {nameB} differ at offset {FieldCodec.Hex(i)}: 0x{a[i]:X2} vs 0x{b[i]:X2}";
            }
        }

        return a.Length == b.Length ? null : $"{nameA} is {a.Length} bytes, {nameB} is {b.Length}";
    }

    private static PropertyReport Exhausted(string name, ulong seed, int maxLength, int planned, int run, string reason) =>
        new(name, seed, maxLength, planned, run, PropertyOutcome.Exhausted, reason, null, null, null, 0, 0, false);
}
