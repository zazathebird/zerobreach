using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

/// <summary>Same script, same seed, same fixture: byte-identical output, asserted explicitly.</summary>
public sealed class DeterminismTests
{
    [Fact]
    public void TheSameBuilderScriptProducesIdenticalBytesAndMaps()
    {
        var a = SampleFixture.Build();
        var b = SampleFixture.Build();

        Assert.Equal(a.ToArray(), b.ToArray());
        Assert.Equal(a.Regions, b.Regions);
        Assert.Equal(a.Fields, b.Fields);
        Assert.Equal(a.Checksums, b.Checksums);
    }

    [Fact]
    public void TheSameMutatorsProduceIdenticalVariantsAndDescriptions()
    {
        Mutator[] Set() => new[]
        {
            Mutators.LengthTooLong("total_len"), Mutators.OffsetPastEnd("root_off"), Mutators.CountInflated("count"),
            Mutators.TruncateAtEveryBoundary(), Mutators.CorruptChecksum("header"), Mutators.FlipByteIn("child"),
            Mutators.Interleave("header", "child"), Mutators.OffsetToParent("child_off", "child"),
        };

        var a = Mutations.Apply(SampleFixture.Build(), Set());
        var b = Mutations.Apply(SampleFixture.Build(), Set());

        Assert.Equal(a.Count, b.Count);
        for (int i = 0; i < a.Count; i++)
        {
            Assert.Equal(a[i].Description, b[i].Description);
            Assert.Equal(a[i].Bytes, b[i].Bytes);
        }
    }

    [Fact]
    public void TheSameSeedProducesIdenticalStructuredFixtures()
    {
        static void Script(FixtureBuilder b, Gen g)
        {
            b.Region("hdr", () => b.Placeholder("n", 2).Crc32("body"));
            b.ResolveToRegionLength("n", "body");
            b.Region("body", () => b.Raw(g.NextBytes(g.NextInt(0, 40))).Utf16Le(g.NextUtf16(g.NextInt(0, 10))));
        }

        var a = Gen.Structured(77, Endian.Big, Script);
        var b = Gen.Structured(77, Endian.Big, Script);

        Assert.Equal(a.ToArray(), b.ToArray());
        Assert.Equal(a.Regions, b.Regions);
    }

    [Fact]
    public void TheSamePropertyRunProducesAnIdenticalReport()
    {
        static PropertyReport Run() => Property.NeverThrows(input => { if (input.Length > 5 && input[5] > 0x80) throw new InvalidOperationException(); }, 31337, 300, 32);

        var a = Run();
        var b = Run();

        Assert.Equal(PropertyOutcome.Falsified, a.Outcome);
        Assert.Equal(a.Message, b.Message);
        Assert.Equal(a.Counterexample, b.Counterexample);
        Assert.Equal(a.FailingCaseIndex, b.FailingCaseIndex);
    }

    [Fact]
    public void ChecksumsAreFunctionsOfTheBytesAlone()
    {
        var bytes = Gen.Bytes(5, 1000);

        Assert.Equal(Checksums.Crc32(bytes), Checksums.Crc32(bytes));
        Assert.Equal(Checksums.Sum(bytes, 2), Checksums.Sum(bytes, 2));
        Assert.Equal(Checksums.XorFold(bytes, 8, Endian.Big), Checksums.XorFold(bytes, 8, Endian.Big));
    }
}
