using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

public sealed class GenTests
{
    [Fact]
    public void Seed42ProducesThePinnedSequence()
    {
        // Computed independently (SplitMix64 in Python) — this is what pins the sequence across
        // runs and across processes: the expected bytes are constants, not a second call.
        var g = new Gen(42);

        Assert.Equal(new byte[] { 0xBD, 0x28, 0x47, 0x58, 0x09, 0xDE, 0x37, 0xCC }, g.NextBytes(8));
        Assert.Equal(0xBDD732262FEB6E95UL, new Gen(42).NextU64());
    }

    [Fact]
    public void TheSameSeedGivesTheSameSequenceFromTwoInstances()
    {
        var a = new Gen(7);
        var b = new Gen(7);

        Assert.Equal(a.NextBytes(64), b.NextBytes(64));
        Assert.Equal(a.NextAscii(20), b.NextAscii(20));
        Assert.Equal(a.NextUtf16(20), b.NextUtf16(20));
        Assert.Equal(a.NextInt(-5, 5), b.NextInt(-5, 5));
    }

    [Fact]
    public void DifferentSeedsGiveDifferentSequences()
    {
        Assert.NotEqual(new Gen(1).NextBytes(16), new Gen(2).NextBytes(16));
        Assert.NotEqual(Gen.Derive(1, 0), Gen.Derive(1, 1));
        Assert.NotEqual(Gen.Derive(1, 0), Gen.Derive(2, 0));
    }

    [Fact]
    public void NextIntStaysInsideItsRange()
    {
        var g = new Gen(3);
        for (int i = 0; i < 1000; i++)
        {
            int v = g.NextInt(-3, 4);
            Assert.InRange(v, -3, 3);
        }
    }

    [Fact]
    public void NextIntEmptyRangeIsAnError()
    {
        Assert.Throws<FixtureException>(() => new Gen(1).NextInt(5, 5));
        Assert.Throws<FixtureException>(() => new Gen(1).NextInt(6, 5));
    }

    [Fact]
    public void NegativeSizesAreCleanErrorsNotCrashes()
    {
        var g = new Gen(1);
        Assert.Contains("cannot be negative", Assert.Throws<FixtureException>(() => g.NextBytes(-1)).Message, StringComparison.Ordinal);
        Assert.Throws<FixtureException>(() => g.NextBytes(0, -1));
        Assert.Throws<FixtureException>(() => g.NextBytes(3, 2));
        Assert.Throws<FixtureException>(() => g.NextAscii(-1));
        Assert.Throws<FixtureException>(() => g.NextUtf16(-1));
        Assert.Throws<FixtureException>(() => Gen.Bytes(1, -1));
        Assert.Throws<FixtureException>(() => Gen.Ascii(1, -1));
        Assert.Throws<FixtureException>(() => Gen.Utf16(1, -1));
        Assert.Throws<FixtureException>(() => Gen.Case(1, 0, -1));
        Assert.Throws<FixtureException>(() => Gen.Case(1, -1, 4));
    }

    [Fact]
    public void RangedNextBytesRespectsBothBounds()
    {
        var g = new Gen(9);
        for (int i = 0; i < 200; i++)
        {
            Assert.InRange(g.NextBytes(2, 5).Length, 2, 5);
        }
    }

    [Fact]
    public void AsciiIsPrintable()
    {
        string s = new Gen(11).NextAscii(500);

        Assert.Equal(500, s.Length);
        Assert.All(s, c => Assert.InRange((int)c, 0x20, 0x7E));
    }

    [Fact]
    public void Utf16IsAlwaysWellFormedAndOfTheRequestedLength()
    {
        int pairs = 0;
        for (ulong seed = 0; seed < 200; seed++)
        {
            string s = new Gen(seed).NextUtf16(33);
            Assert.Equal(33, s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]))
                {
                    Assert.True(i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]), $"lone high surrogate at {i} for seed {seed}");
                    pairs++;
                    i++;
                }
                else
                {
                    Assert.False(char.IsLowSurrogate(s[i]), $"lone low surrogate at {i} for seed {seed}");
                    Assert.True(s[i] >= 0x20 && s[i] <= 0xFFFD, $"out-of-range unit U+{(int)s[i]:X4} for seed {seed}");
                }
            }
        }

        Assert.True(pairs > 0, "the generator never produced a supplementary-plane pair");
    }

    [Fact]
    public void OneShotEntryPointsRespectMaxLength()
    {
        for (ulong seed = 0; seed < 50; seed++)
        {
            Assert.InRange(Gen.Bytes(seed, 10).Length, 0, 10);
            Assert.InRange(Gen.Ascii(seed, 10).Length, 0, 10);
            Assert.InRange(Gen.Utf16(seed, 10).Length, 0, 10);
        }

        Assert.Empty(Gen.Bytes(5, 0));
    }

    [Fact]
    public void CaseZeroIsEmptyAndCaseOneIsFullLengthForEverySeed()
    {
        for (ulong seed = 0; seed < 20; seed++)
        {
            Assert.Empty(Gen.Case(seed, 0, 32));
            Assert.Equal(32, Gen.Case(seed, 1, 32).Length);
            Assert.InRange(Gen.Case(seed, 2, 32).Length, 0, 32);
        }
    }

    [Fact]
    public void CasesAreReproducibleFromSeedAndIndexAlone()
    {
        Assert.Equal(Gen.Case(99, 17, 64), Gen.Case(99, 17, 64));
        Assert.NotEqual(Gen.Case(99, 17, 64), Gen.Case(99, 18, 64));
    }

    [Fact]
    public void StructuredRunsTheScriptWithASeededGenerator()
    {
        static void Script(FixtureBuilder b, Gen g) => b.Field("n", 1, g.NextInt(1, 10)).Raw(g.NextBytes(4));

        var a = Gen.Structured(5, Endian.Little, Script);
        var b = Gen.Structured(5, Endian.Little, Script);
        var c = Gen.Structured(6, Endian.Little, Script);

        Assert.Equal(a.ToArray(), b.ToArray());
        Assert.NotEqual(a.ToArray(), c.ToArray());
        Assert.Equal(5, a.Length);
    }
}
