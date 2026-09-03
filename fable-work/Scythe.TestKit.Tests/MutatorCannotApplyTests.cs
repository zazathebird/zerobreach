using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

/// <summary>
/// Malformed input to the kit itself. A mutator that cannot apply must say so — never return the
/// input unchanged, because a no-op mutation makes the consuming test pass for the wrong reason.
/// </summary>
public sealed class MutatorCannotApplyTests
{
    private readonly Fixture fixture = SampleFixture.Build();

    private static Fixture ZeroField() => new FixtureBuilder(Endian.Little).Field("z", 2, 0).Pad(4).Build();

    private FixtureException CannotApply(Mutator mutator)
    {
        var e = Assert.Throws<FixtureException>(() => Mutations.Apply(fixture, mutator));
        Assert.Contains("cannot apply", e.Message, StringComparison.Ordinal);
        return e;
    }

    [Fact]
    public void LengthTooShortOnAZeroField()
    {
        var e = Assert.Throws<FixtureException>(() => Mutations.Apply(ZeroField(), Mutators.LengthTooShort("z")));
        Assert.Contains("already 0", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LengthZeroOnAZeroField()
    {
        Assert.Throws<FixtureException>(() => Mutations.Apply(ZeroField(), Mutators.LengthZero("z")));
    }

    [Fact]
    public void LengthTooLongWhenTheFieldAlreadyHoldsTheOnlyCandidate()
    {
        var f = new FixtureBuilder(Endian.Little).Field("n", 1, 0xFF).Pad(300).Build();

        var e = Assert.Throws<FixtureException>(() => Mutations.Apply(f, Mutators.LengthTooLong("n")));
        Assert.Contains("already holds 0xFF", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CountInflatedOnZeroOnMaxAndWithATrivialFactor()
    {
        Assert.Throws<FixtureException>(() => Mutations.Apply(ZeroField(), Mutators.CountInflated("z")));
        var max = new FixtureBuilder(Endian.Little).Field("m", 1, 0xFF).Build();
        Assert.Throws<FixtureException>(() => Mutations.Apply(max, Mutators.CountInflated("m")));
        Assert.Contains("at least 2", CannotApply(Mutators.CountInflated("count", 1)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void OffsetToSelfWhenItAlreadyDoes()
    {
        var f = new FixtureBuilder(Endian.Little).Region("r", b => b.Field("self", 1, 0)).Build();

        Assert.Throws<FixtureException>(() => Mutations.Apply(f, Mutators.OffsetToSelf("self", "r")));
    }

    [Fact]
    public void OffsetToParentOnATopLevelRegion()
    {
        Assert.Contains("has no parent region", CannotApply(Mutators.OffsetToParent("root_off", "root")).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TruncateAtARegionWhoseEveryBoundaryIsTheBufferEnd()
    {
        var f = new FixtureBuilder(Endian.Little).Pad(4).Region("empty_tail", () => { }).Build();

        Assert.Throws<FixtureException>(() => Mutations.Apply(f, Mutators.TruncateAt("empty_tail")));
    }

    [Fact]
    public void TruncateAtEveryBoundaryWithNoRegions()
    {
        var f = new FixtureBuilder(Endian.Little).Pad(4).Build();

        Assert.Throws<FixtureException>(() => Mutations.Apply(f, Mutators.TruncateAtEveryBoundary()));
    }

    [Fact]
    public void CorruptChecksumWhereNoneWasDeclaredNamesTheOnesThatWere()
    {
        var e = CannotApply(Mutators.CorruptChecksum("child"));

        Assert.Contains("no checksum was declared over 'child'", e.Message, StringComparison.Ordinal);
        Assert.Contains("'header'", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FlipByteInAnEmptyRegion()
    {
        var f = new FixtureBuilder(Endian.Little).Region("e", () => { }).Pad(1).Build();

        Assert.Throws<FixtureException>(() => Mutations.Apply(f, Mutators.FlipByteIn("e")));
    }

    [Theory]
    [InlineData(30)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void FlipByteAtAnOffsetOutsideTheBuffer(int offset)
    {
        var e = CannotApply(Mutators.FlipByteAt(offset));

        Assert.Contains("valid offsets are 0x0..0x1D", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void InterleaveOfOverlappingOrEmptyRegions()
    {
        Assert.Contains("already overlap", CannotApply(Mutators.Interleave("root", "child")).Message, StringComparison.Ordinal);
        var f = new FixtureBuilder(Endian.Little).Region("a", () => { }).Region("b", b => b.Pad(2)).Build();
        Assert.Throws<FixtureException>(() => Mutations.Apply(f, Mutators.Interleave("a", "b")));
    }

    [Fact]
    public void OffsetIntoARegionWithNoInterior()
    {
        var f = new FixtureBuilder(Endian.Little).Field("off", 1, 9).Region("one", b => b.U8(1)).Build();

        Assert.Throws<FixtureException>(() => Mutations.Apply(f, Mutators.OffsetInto("off", "one")));
    }

    [Fact]
    public void SetFieldToItsCurrentValueOrTooWide()
    {
        Assert.Contains("already holds", CannotApply(Mutators.SetField("count", 3)).Message, StringComparison.Ordinal);
        Assert.Contains("2 byte(s) wide", CannotApply(Mutators.SetField("count", 0x10000)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ACustomMutationThatChangesNothing()
    {
        Assert.Contains("returned the input unchanged", CannotApply(Mutators.Custom("identity", bytes => bytes)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ApplyRefusesANoOpFromARawMutatorDelegate()
    {
        Mutator sloppy = f => new[] { new Mutation("did nothing", f.ToArray()) };

        var e = Assert.Throws<FixtureException>(() => Mutations.Apply(fixture, sloppy));

        Assert.Contains("'did nothing' left the buffer unchanged", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownFieldOrRegionNameIsAnError()
    {
        Assert.Contains("no field named 'nope'", Assert.Throws<FixtureException>(() => Mutations.Apply(fixture, Mutators.LengthZero("nope"))).Message, StringComparison.Ordinal);
        Assert.Contains("no region named 'nope'", Assert.Throws<FixtureException>(() => Mutations.Apply(fixture, Mutators.TruncateAt("nope"))).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WithBytesOfADifferentLengthIsRefused()
    {
        var e = Assert.Throws<FixtureException>(() => fixture.WithBytes(new byte[3]));

        Assert.Contains("needs 30 bytes", e.Message, StringComparison.Ordinal);
    }
}
