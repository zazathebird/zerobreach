using Scythe.Techniques.Tests.Fixtures;
using Xunit;
using static Scythe.Techniques.Tests.Fixtures.MapFixtures;

namespace Scythe.Techniques.Tests;

public sealed class DeterminismTests
{
    private static readonly Finding[] Mixed =
    {
        F("a", explicitId: "T1053.005"),
        F("b", explicitId: "T1053"),
        F("c", check: "check.psh"),
        F("d", description: "a run key"),
        F("e", explicitId: "T1547.001"),
        F("f", description: "unmatched"),
        F("g", explicitId: "T1999"),
        F("h", check: "check.newer"),
        F("i", explicitId: "bad"),
        F("j", description: "PowerShell and a scheduled task"),
    };

    [Fact]
    public void TheSameRunTwiceRendersByteIdentically()
    {
        var resolver = StandardResolver();

        var first = Render(resolver.ResolveAll(Mixed).Value!);
        var second = Render(StandardResolver().ResolveAll(Mixed).Value!);

        Assert.Equal(first, second);
    }

    [Fact]
    public void TheSameMapLoadedTwiceRendersByteIdentically()
    {
        Assert.Equal(RenderMap(Standard().LoadOk()), RenderMap(Standard().LoadOk()));
    }

    [Fact]
    public void ShuffledFindingsGiveByteIdenticalIdentifierSetsAndCategoryCounts()
    {
        var resolver = StandardResolver();
        var baseline = RenderCounts(resolver.ResolveAll(Mixed).Value!.Rollup);

        var rng = new Random(20260902);
        for (var i = 0; i < 8; i++)
        {
            var shuffled = Mixed.OrderBy(_ => rng.Next()).ToArray();
            Assert.Equal(baseline, RenderCounts(resolver.ResolveAll(shuffled).Value!.Rollup));
        }
    }

    [Fact]
    public void AMapWrittenInADifferentEntryOrderRendersIdentically()
    {
        var forward = MapFixtures.Standard().LoadOk();
        var reversed = new MapBuilder()
            .Entry("T1547.001", "Registry Run Keys / Startup Folder", DefenseEvasion)
            .Entry("T1547", "Boot or Logon Autostart Execution", Persistence)
            .Entry("T1059.001", "PowerShell", Execution)
            .Entry("T1059", "Command and Scripting Interpreter", Execution)
            .Entry("T1053.005", "Scheduled Task", Persistence)
            .Entry("T1053", "Scheduled Task/Job", Persistence)
            .Rule("scheduled task", "T1053.005")
            .Rule("powershell", "T1059.001")
            .Rule("run key", "T1547.001")
            .LoadOk();

        Assert.Equal(RenderMap(forward), RenderMap(reversed));
    }

    [Fact]
    public void TheResolutionListFollowsInputOrderNotIdentifierOrder()
    {
        // The counts are order-independent; the per-finding list is deliberately not, so a
        // caller can zip it against the findings it supplied.
        var run = StandardResolver().ResolveAll(Mixed.Reverse().ToArray()).Value!;

        Assert.Equal(Mixed.Reverse().Select(f => f.FindingId), run.Resolutions.Select(r => r.FindingId));
    }
}
