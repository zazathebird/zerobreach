namespace Scythe.TestKit;

/// <summary>
/// A fixture script or a mutation request that cannot be honoured: an unresolved placeholder at
/// build time, a placeholder resolved twice, a value too wide for its slot, a mutation aimed at a
/// field the fixture never recorded, a generator asked for a negative size.
/// </summary>
/// <remarks>
/// This kit deliberately throws here rather than returning a result. The package rule "never
/// throw for an expected outcome" is about readers facing input they did not author; a fixture
/// script is authored by the test that runs it, so every one of these is a defect in the test,
/// and the one thing a defective fixture must never do is quietly produce bytes. A test that
/// throws is visible; a test that passes against the wrong fixture is not.
/// </remarks>
public sealed class FixtureException : Exception
{
    public FixtureException(string message)
        : base(message)
    {
    }
}
