namespace Scythe.TestKit;

/// <summary>
/// One malformed variant of a fixture and a description of what was done to produce it. The
/// description is what a failing test prints, so it names the field, the old and new values and
/// the buffer size — never "mutation 7".
/// </summary>
public sealed record Mutation(string Description, byte[] Bytes)
{
    public override string ToString() => Description;
}

/// <summary>
/// A function from a built fixture to zero or more mutations. The standard set lives in
/// <see cref="Mutators"/>; a task with a format-specific hazard supplies its own and gets the
/// same reporting. A mutator that cannot apply to a fixture throws
/// <see cref="FixtureException"/> — never returns the input unchanged.
/// </summary>
public delegate IEnumerable<Mutation> Mutator(Fixture original);
