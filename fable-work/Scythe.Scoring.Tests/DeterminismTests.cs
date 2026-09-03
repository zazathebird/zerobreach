using Scythe.Scoring.Tests.Fixtures;
using Xunit;

namespace Scythe.Scoring.Tests;

/// <summary>Same record, same bytes out — whatever order the record's lists arrive in.</summary>
public sealed class DeterminismTests
{
    private static RecordBuilder Rich() =>
        new RecordBuilder()
            .Completed("autoruns", "services", "tasks", "Drivers", "wmi")
            .Inconclusive("hives", "needed elevation")
            .Inconclusive("mft", "artifact locked")
            .Inconclusive("usn", "needed elevation")
            .Skipped("browsers", "not in quick mode")
            .Finding("f-1", Severity.High, "autoruns")
            .Finding("f-2", Severity.Medium, "autoruns")
            .Finding("f-3", Severity.Medium, "services")
            .Finding("f-4", Severity.Low, "tasks")
            .Finding("f-5", Severity.Informational, "hives")
            .Finding("f-6", Severity.Critical, "Drivers")
            .Finding("f-7", Severity.Low, "wmi")
            .Finding("f-8", Severity.High, "usn");

    /// <summary>The brief's shuffle test. Reverted form: drop the <c>OrderBy</c> on the inventory in <c>Compute</c>.</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(42)]
    [InlineData(1234)]
    [InlineData(99991)]
    public void AShuffledRecordSerialisesByteIdentically(int seed)
    {
        var reference = RecordBuilder.Serialise(Rollup.Compute(Rich().Build()));
        var shuffled = RecordBuilder.Serialise(Rollup.Compute(Rich().BuildShuffled(seed)));

        Assert.Equal(reference, shuffled);
    }

    [Fact]
    public void TheShuffleActuallyChangesTheInputOrder()
    {
        // Negative control: a shuffle that returned the input order would make the test above vacuous.
        var original = Rich().Build();
        var shuffled = Rich().BuildShuffled(42);

        Assert.NotEqual(original.Checks.Select(c => c.Id), shuffled.Checks.Select(c => c.Id));
        Assert.NotEqual(original.Findings.Select(f => f.Id), shuffled.Findings.Select(f => f.Id));
    }

    [Fact]
    public void TheSameRecordTwiceIsByteIdentical()
    {
        var first = RecordBuilder.Serialise(Rollup.Compute(Rich().Build()));
        var second = RecordBuilder.Serialise(Rollup.Compute(Rich().Build()));

        Assert.Equal(first, second);
    }

    [Fact]
    public void AnIncompleteResultIsByteIdenticalAcrossShuffles()
    {
        var builder = Rich().Inconclusive("noreason-b", null).Inconclusive("noreason-a", "");

        var reference = RecordBuilder.Serialise(Rollup.Compute(builder.Build()));
        foreach (var seed in new[] { 3, 5, 8 })
        {
            Assert.Equal(reference, RecordBuilder.Serialise(Rollup.Compute(builder.BuildShuffled(seed))));
        }
    }

    [Fact]
    public void AFailedResultIsIdenticalAcrossRuns()
    {
        var input = Rich().Finding("orphan", Severity.Low, "nowhere").Build();

        Assert.Equal(RecordBuilder.Serialise(Rollup.Compute(input)), RecordBuilder.Serialise(Rollup.Compute(input)));
    }

    [Fact]
    public void ContributionOrderDoesNotDependOnFindingOrder()
    {
        var forward = Rollup.Compute(Rich().Build()).Value!.Score.Contributions;
        var shuffled = Rollup.Compute(Rich().BuildShuffled(11)).Value!.Score.Contributions;

        Assert.Equal(forward, shuffled);
    }

    [Fact]
    public void TheResultHoldsNoTimestampAndNoRandomness()
    {
        // No clock and no seed can appear in the output, so two runs a second apart must agree.
        var a = RecordBuilder.Serialise(Rollup.Compute(RecordBuilder.Ordinary().Build()));
        var b = RecordBuilder.Serialise(Rollup.Compute(RecordBuilder.Ordinary().Build()));

        Assert.Equal(a, b);
        Assert.DoesNotContain("2026", System.Text.Encoding.UTF8.GetString(a), StringComparison.Ordinal);
    }
}
