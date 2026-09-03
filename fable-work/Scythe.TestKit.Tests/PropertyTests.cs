using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

public sealed class PropertyTests
{
    private const ulong Seed = 2024;

    [Fact]
    public void APropertyThatHoldsReportsHoldsAndRunsEveryCase()
    {
        var r = Property.ForAll("always", Seed, 50, 16, _ => null);

        Assert.Equal(PropertyOutcome.Holds, r.Outcome);
        Assert.True(r.Holds);
        Assert.Equal(50, r.CasesRun);
        Assert.Null(r.Counterexample);
        Assert.Contains("holds", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailingPropertyIsDetectedAndItsCounterexampleReported()
    {
        var r = Property.ForAll("no 0xFF", Seed, 200, 64, input => input.Contains((byte)0xFF) ? "contains 0xFF" : null);

        Assert.Equal(PropertyOutcome.Falsified, r.Outcome);
        Assert.False(r.Holds);
        Assert.NotNull(r.FailingCaseIndex);
        Assert.Contains((byte)0xFF, r.OriginalFailure!);
        Assert.Contains((byte)0xFF, r.Counterexample!);
        Assert.Equal("contains 0xFF", r.Detail);
        Assert.Equal(Gen.Case(Seed, r.FailingCaseIndex!.Value, 64), r.OriginalFailure);
    }

    [Fact]
    public void TheCounterexampleIsMinimisedToOneNonZeroByte()
    {
        var r = Property.ForAll("no 0xFF", Seed, 200, 64, input => input.Contains((byte)0xFF) ? "contains 0xFF" : null);

        Assert.Equal(0xFF, r.Counterexample![^1]);
        Assert.All(r.Counterexample[..^1], b => Assert.Equal(0, b));
        Assert.False(r.ShrinkCapped);
        Assert.True(r.Counterexample.Length <= r.OriginalFailure!.Length);
    }

    [Fact]
    public void ShrinkingReducesAFullLengthFailureToTheExactThreshold()
    {
        // Case 1 is always the full 64 bytes, so the first failure is known: halving 64 -> 32 -> 16
        // still fails, 8 does not; the tail then comes off 16 -> 11, and 10 does not fail.
        var r = Property.ForAll("short only", Seed, 10, 64, input => input.Length > 10 ? "too long" : null);

        Assert.Equal(PropertyOutcome.Falsified, r.Outcome);
        Assert.Equal(1, r.FailingCaseIndex);
        Assert.Equal(64, r.OriginalFailure!.Length);
        Assert.Equal(new byte[11], r.Counterexample);
        // 2 halvings + 5 tail trims, then one step per non-zero byte the zeroing phase cleared.
        Assert.Equal(7 + r.OriginalFailure.Take(11).Count(x => x != 0), r.ShrinkSteps);
    }

    [Fact]
    public void ShrinkingIsDeterministic()
    {
        static PropertyReport Run() => Property.ForAll("no 0xFF", Seed, 200, 64, input => input.Contains((byte)0xFF) ? "contains 0xFF" : null);

        var a = Run();
        var b = Run();

        Assert.Equal(a.Counterexample, b.Counterexample);
        Assert.Equal(a.ShrinkSteps, b.ShrinkSteps);
        Assert.Equal(a.ShrinkEvaluations, b.ShrinkEvaluations);
        Assert.Equal(a.Message, b.Message);
    }

    [Fact]
    public void TheMessageCarriesSeedCaseAndReproductionRecipe()
    {
        var r = Property.ForAll("no 0xFF", Seed, 200, 64, input => input.Contains((byte)0xFF) ? "contains 0xFF" : null);

        Assert.Contains("property 'no 0xFF' (seed 2024", r.Message, StringComparison.Ordinal);
        Assert.Contains("FALSIFIED at case " + r.FailingCaseIndex, r.Message, StringComparison.Ordinal);
        Assert.Contains($"Gen.Case(2024, {r.FailingCaseIndex}, 64)", r.Message, StringComparison.Ordinal);
        Assert.Contains("FF", r.Message, StringComparison.Ordinal);
        Assert.Equal(r.Message, r.ToString());
    }

    [Fact]
    public void AnExceptionFromTheCheckIsAFailureNamingTheExceptionType()
    {
        var r = Property.ForAll("throws on long input", Seed, 10, 16, input => input.Length > 3 ? throw new InvalidOperationException("boom") : null);

        Assert.Equal(PropertyOutcome.Falsified, r.Outcome);
        Assert.Contains("threw System.InvalidOperationException: boom", r.Detail, StringComparison.Ordinal);
        Assert.Equal(4, r.Counterexample!.Length);
    }

    [Fact]
    public void NeverThrowsCatchesAThrowingReaderAndPassesASafeOne()
    {
        var bad = Property.NeverThrows(input => { if (input.Length > 2) throw new IndexOutOfRangeException(); }, Seed, 100, 8);
        var good = Property.NeverThrows(_ => { }, Seed, 100, 8);

        Assert.Equal(PropertyOutcome.Falsified, bad.Outcome);
        Assert.Equal(new byte[3], bad.Counterexample);
        Assert.Contains("IndexOutOfRangeException", bad.Detail, StringComparison.Ordinal);
        Assert.Equal(PropertyOutcome.Holds, good.Outcome);
    }

    [Fact]
    public void DeterministicCatchesASerialiserThatDependsOnState()
    {
        int calls = 0;
        var bad = Property.Deterministic(input => { calls++; return new[] { (byte)calls }; }, Seed, 5, 8);
        var good = Property.Deterministic(input => (byte[])input.Clone(), Seed, 50, 8);

        Assert.Equal(PropertyOutcome.Falsified, bad.Outcome);
        Assert.Contains("first run and second run differ at offset 0x0", bad.Detail, StringComparison.Ordinal);
        Assert.Equal(PropertyOutcome.Holds, good.Outcome);
    }

    [Fact]
    public void DeterministicReportsALengthDifferenceToo()
    {
        int calls = 0;
        var r = Property.Deterministic(input => new byte[calls++ % 2], Seed, 5, 8);

        Assert.Equal(PropertyOutcome.Falsified, r.Outcome);
        Assert.Contains("is 0 bytes", r.Detail, StringComparison.Ordinal);
    }

    private static Fixture Framed() => new FixtureBuilder(Endian.Little)
        .Region("header", b => b.Placeholder("total", 4).ResolveToLength("total"))
        .Region("body", b => b.Ascii("payload"))
        .Build();

    private static KitResultState HonestReader(byte[] bytes)
    {
        if (bytes.Length < 4)
        {
            return KitResultState.Failed;
        }

        uint total = BitConverter.ToUInt32(bytes, 0);
        return bytes.Length < total ? KitResultState.Incomplete : KitResultState.Ok;
    }

    [Fact]
    public void IncompleteIsNotOkHoldsForAReaderThatChecksItsLength()
    {
        var r = Property.IncompleteIsNotOk(Framed(), HonestReader);

        // Boundaries: header start 0, header end-1 3, header end / body start 4, body end-1 10;
        // the body's end is the buffer's end and is not a truncation.
        Assert.Equal(PropertyOutcome.Holds, r.Outcome);
        Assert.Equal(4, r.CasesRun);
    }

    [Fact]
    public void IncompleteIsNotOkFalsifiesAReaderThatCallsATruncationOk()
    {
        var r = Property.IncompleteIsNotOk(Framed(), bytes => bytes.Length >= 4 ? KitResultState.Ok : KitResultState.Failed);

        Assert.Equal(PropertyOutcome.Falsified, r.Outcome);
        Assert.False(r.Holds);
        Assert.Contains("the reader reported Ok", r.Detail, StringComparison.Ordinal);
        Assert.Contains("buffer truncated", r.Detail, StringComparison.Ordinal);
        Assert.True(r.Counterexample!.Length < Framed().Length);
    }

    [Fact]
    public void IncompleteIsNotOkIsExhaustedNotHoldsWhenTheWholeFixtureIsNotOk()
    {
        var r = Property.IncompleteIsNotOk(Framed(), _ => KitResultState.Failed);

        Assert.Equal(PropertyOutcome.Exhausted, r.Outcome);
        Assert.False(r.Holds);
        Assert.Contains("vacuous", r.Detail, StringComparison.Ordinal);
        Assert.Contains("reads Failed", r.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void TerminatesCatchesAReaderThatOverrunsTheCeiling()
    {
        var bad = Property.Terminates(input => { if (input.Length > 0) Thread.Sleep(250); }, Seed, 3, 4, TimeSpan.FromMilliseconds(40));
        var good = Property.Terminates(_ => { }, Seed, 20, 4, TimeSpan.FromSeconds(1));

        Assert.Equal(PropertyOutcome.Falsified, bad.Outcome);
        Assert.Contains("did not return within 40 ms", bad.Detail, StringComparison.Ordinal);
        Assert.Single(bad.Counterexample!);
        Assert.Equal(PropertyOutcome.Holds, good.Outcome);
    }

    [Fact]
    public void RoundTripsCatchesALossyTripAndAMissingOutput()
    {
        var lossy = Property.RoundTrips(input => input.Length == 0 ? input : input[..^1], Seed, 20, 8);
        var missing = Property.RoundTrips(_ => null, Seed, 20, 8);
        var identity = Property.RoundTrips(input => (byte[])input.Clone(), Seed, 50, 8);

        Assert.Equal(PropertyOutcome.Falsified, lossy.Outcome);
        Assert.Contains("input is 1 bytes, round-tripped output is 0", lossy.Detail, StringComparison.Ordinal);
        Assert.Equal(PropertyOutcome.Falsified, missing.Outcome);
        Assert.Equal("round trip produced no output", missing.Detail);
        Assert.Equal(PropertyOutcome.Holds, identity.Outcome);
    }

    [Fact]
    public void BoundedAllocationCatchesAReaderThatTrustsACount()
    {
        static void Greedy(byte[] input) => GC.KeepAlive(new byte[input.Length * 200 + 1]);
        static void Frugal(byte[] input) => GC.KeepAlive((byte[])input.Clone());

        var bad = Property.BoundedAllocation(Greedy, multiple: 4, floorBytes: 64, Seed, 20, 64);
        var good = Property.BoundedAllocation(Frugal, multiple: 4, floorBytes: 1024, Seed, 20, 64);

        Assert.Equal(PropertyOutcome.Falsified, bad.Outcome);
        Assert.Contains("allocated", bad.Detail, StringComparison.Ordinal);
        Assert.Equal(PropertyOutcome.Holds, good.Outcome);
    }

    [Fact]
    public void BoundedAllocationRejectsNegativeBounds()
    {
        Assert.Throws<FixtureException>(() => Property.BoundedAllocation(_ => { }, -1, 0, Seed, 1, 1));
        Assert.Throws<FixtureException>(() => Property.BoundedAllocation(_ => { }, 1, -1, Seed, 1, 1));
    }

    [Fact]
    public void NegativeCaseCountsAndLengthsAreErrors()
    {
        Assert.Throws<FixtureException>(() => Property.ForAll("p", Seed, -1, 8, _ => null));
        Assert.Throws<FixtureException>(() => Property.ForAll("p", Seed, 1, -8, _ => null));
    }

    [Fact]
    public void ZeroCasesHoldsVacuouslyButSaysSo()
    {
        var r = Property.ForAll("p", Seed, 0, 8, _ => "would fail");

        Assert.Equal(PropertyOutcome.Holds, r.Outcome);
        Assert.Contains("0/0 cases", r.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheCheckReceivesACopySoItCannotCorruptTheCase()
    {
        var r = Property.ForAll("mutating check", Seed, 5, 8, input =>
        {
            if (input.Length > 0)
            {
                input[0] = 0xEE;
            }

            return null;
        });

        Assert.Equal(PropertyOutcome.Holds, r.Outcome);
        Assert.Equal(Gen.Case(Seed, 1, 8), Gen.Case(Seed, 1, 8));
    }

    [Fact]
    public void ShrinkerHalvesThenTrimsThenZeroes()
    {
        var r = Shrinker.Shrink(new byte[] { 1, 2, 0xFF, 4 }, c => c.Contains((byte)0xFF), 100);

        Assert.Equal(new byte[] { 0, 0, 0xFF }, r.Minimal);
        Assert.Equal(3, r.Steps);
        Assert.Equal(6, r.Evaluations);
        Assert.False(r.Capped);
    }

    [Fact]
    public void ShrinkerStopsAtItsEvaluationCeilingAndSaysSo()
    {
        var r = Shrinker.Shrink(new byte[] { 1, 2, 0xFF, 4 }, c => c.Contains((byte)0xFF), 2);

        Assert.True(r.Capped);
        Assert.Equal(2, r.Evaluations);
        Assert.Contains((byte)0xFF, r.Minimal);
    }

    [Fact]
    public void HexDumpTruncatesAfter64Bytes()
    {
        Assert.Equal("(empty)", PropertyReport.HexDump(Array.Empty<byte>()));
        Assert.Equal("01 FF", PropertyReport.HexDump(new byte[] { 1, 0xFF }));
        Assert.EndsWith("... (+36)", PropertyReport.HexDump(new byte[100]), StringComparison.Ordinal);
    }
}
