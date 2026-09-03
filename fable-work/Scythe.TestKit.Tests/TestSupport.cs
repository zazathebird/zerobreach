using Scythe.TestKit;
using Xunit;

namespace Scythe.TestKit.Tests;

/// <summary>Assertions the kit's own tests share.</summary>
internal static class TestSupport
{
    /// <summary>
    /// Asserts <paramref name="mutated"/> differs from <paramref name="original"/> at exactly the
    /// given offsets and nowhere else — the "exactly the intended difference and nothing else"
    /// bar from the brief, byte by byte.
    /// </summary>
    public static void AssertDiffersOnlyAt(byte[] original, byte[] mutated, params int[] offsets)
    {
        Assert.Equal(original.Length, mutated.Length);
        var expected = new HashSet<int>(offsets);
        for (int i = 0; i < original.Length; i++)
        {
            if (expected.Contains(i))
            {
                Assert.True(original[i] != mutated[i], $"offset 0x{i:X} was expected to change and did not");
            }
            else
            {
                Assert.True(original[i] == mutated[i], $"offset 0x{i:X} changed from 0x{original[i]:X2} to 0x{mutated[i]:X2} and should not have");
            }
        }
    }

    public static FixtureException Throws(Action action) => Assert.Throws<FixtureException>(action);
}
