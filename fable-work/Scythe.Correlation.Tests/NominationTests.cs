using Scythe.Correlation.Tests.Fixtures;
using Xunit;
using static Scythe.Correlation.Tests.Fixtures.CorrelationFixtures;

namespace Scythe.Correlation.Tests;

/// <summary>First-finding nomination: earliest anchor, anchored before unanchored, then ordinal id.</summary>
public sealed class NominationTests
{
    [Fact]
    public void WithEqualAnchorsTheOrdinalSmallestIdIsFirst()
    {
        var output = Build(
        [
            Finding("F10", @"C:\x.exe"),
            Finding("F2", @"C:\x.exe"),
            Finding("F1", @"C:\x.exe"),
        ]);

        // Ordinal: "F1" < "F10" < "F2". A numeric-aware or culture comparison would differ.
        Assert.Equal("F1", output.Chains[0].FirstFindingId);
        Assert.Equal(["F1", "F10", "F2"], output.Chains[0].MemberFindingIds);
    }

    [Fact]
    public void TheIdTieBreakIsOrdinalNotCultural()
    {
        // Ordinal puts every upper-case letter before every lower-case one ('B' 0x42 < 'a' 0x61);
        // a culture-sensitive comparison puts 'a' before 'B'. Reverted form: string.Compare(a, b)
        // or StringComparer.CurrentCulture / InvariantCulture in NominationOrder.
        var output = Build(
        [
            Finding("a", @"C:\x.exe"),
            Finding("B", @"C:\x.exe"),
        ]);

        Assert.Equal("B", output.Chains[0].FirstFindingId);
        Assert.Equal(["B", "a"], output.Chains[0].MemberFindingIds);
        Assert.True(string.Compare("a", "B", StringComparison.InvariantCultureIgnoreCase) < 0, "negative control: a culture fold would order these the other way");
    }

    [Fact]
    public void AnEarlierAnchorWinsOverASmallerId()
    {
        var output = Build(
        [
            Finding("A", @"C:\x.exe", anchor: RunTime.AddMinutes(5)),
            Finding("B", @"C:\x.exe", anchor: RunTime),
        ]);

        Assert.Equal("B", output.Chains[0].FirstFindingId);
        Assert.Equal(["A", "B"], output.Chains[0].MemberFindingIds); // members stay in id order
    }

    [Fact]
    public void AnAnchoredMemberPrecedesAnUnanchoredOne()
    {
        var output = Build(
        [
            new FindingReference("A", @"C:\x.exe", null, Anchor: null),
            Finding("B", @"C:\x.exe", anchor: RunTime),
        ]);

        Assert.Equal("B", output.Chains[0].FirstFindingId);
    }

    [Fact]
    public void AllUnanchoredFallsThroughToTheId()
    {
        var output = Build(
        [
            new FindingReference("Z", @"C:\x.exe", null),
            new FindingReference("Y", @"C:\x.exe", null),
        ]);

        Assert.Equal("Y", output.Chains[0].FirstFindingId);
    }

    [Fact]
    public void AnchorsCompareAsInstantsNotAsSpellings()
    {
        var utc = new DateTimeOffset(2026, 9, 2, 10, 0, 0, TimeSpan.Zero);
        var sameInstantEast = utc.ToOffset(TimeSpan.FromHours(3));
        var output = Build(
        [
            Finding("B", @"C:\x.exe", anchor: sameInstantEast),
            Finding("A", @"C:\x.exe", anchor: utc),
        ]);

        Assert.Equal("A", output.Chains[0].FirstFindingId);
    }

    [Fact]
    public void NominationOrderIsTotalAndAntisymmetric()
    {
        FindingReference[] items =
        [
            new("b", "", null, null),
            new("a", "", null, null),
            new("c", "", null, RunTime),
            new("d", "", null, RunTime.AddSeconds(-1)),
            new("e", "", null, RunTime),
        ];

        foreach (var x in items)
        {
            foreach (var y in items)
            {
                var xy = ChainBuilder.NominationOrder(x, y);
                var yx = ChainBuilder.NominationOrder(y, x);
                Assert.Equal(Math.Sign(xy), -Math.Sign(yx));
                if (ReferenceEquals(x, y)) Assert.Equal(0, xy);
                else Assert.NotEqual(0, xy);
            }
        }

        var sorted = items.OrderBy(i => i, Comparer<FindingReference>.Create(ChainBuilder.NominationOrder)).Select(i => i.Id).ToArray();
        Assert.Equal(new[] { "d", "c", "e", "a", "b" }, sorted);
    }
}
