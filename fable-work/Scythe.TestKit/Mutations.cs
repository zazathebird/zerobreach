namespace Scythe.TestKit;

/// <summary>Applies mutators to a fixture and hands the variants to xUnit.</summary>
public static class Mutations
{
    /// <summary>
    /// Runs every mutator and materialises the result, so a mutator that cannot apply throws
    /// here — at data-collection time — rather than silently contributing zero cases to a theory.
    /// Also refuses any variant whose bytes equal the original; that is the one thing a
    /// mutation must never be.
    /// </summary>
    public static IReadOnlyList<Mutation> Apply(Fixture fixture, params Mutator[] mutators)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        ArgumentNullException.ThrowIfNull(mutators);
        var result = new List<Mutation>();
        foreach (var mutator in mutators)
        {
            foreach (var mutation in mutator(fixture))
            {
                if (mutation.Bytes.AsSpan().SequenceEqual(fixture.Bytes.Span))
                {
                    throw new FixtureException($"mutation '{mutation.Description}' left the buffer unchanged; a no-op mutation makes a test pass for the wrong reason");
                }

                result.Add(mutation);
            }
        }

        return result;
    }

    /// <summary>Wraps mutations for <c>[MemberData]</c>.</summary>
    public static IEnumerable<object[]> TheoryData(IEnumerable<Mutation> mutations)
    {
        ArgumentNullException.ThrowIfNull(mutations);
        return mutations.Select(m => new object[] { m });
    }
}
