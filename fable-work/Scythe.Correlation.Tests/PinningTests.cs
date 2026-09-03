using Scythe.Correlation.Tests.Fixtures;
using Xunit;
using static Scythe.Correlation.Tests.Fixtures.CorrelationFixtures;

namespace Scythe.Correlation.Tests;

/// <summary>
/// The two rules the brief says will otherwise be "simplified" away by a later refactor. Each
/// test's name says which rule it defends, and each comment records the reverted form that makes
/// it fail so the next reader can repeat the demonstration.
/// </summary>
public sealed class PinningTests
{
    // ---------------------------------------------------------------- Rule 1

    [Fact]
    public void GroupingIsOnEntitiesNeverOnTime_SameTimestampAndNoSharedEntitiesProducesNoChains()
    {
        // Every finding in a real record carries the run's one timestamp. Reverted form (fails
        // this test): in ChainBuilder, after the entity edges, also Union() every pair of
        // findings whose Anchors are within some window of each other — or simply every pair
        // with equal Anchors. Either fuses all forty into one chain.
        var findings = AllDistinct(40, RunTime);

        var output = Build(findings);

        Assert.Empty(output.Chains);
        Assert.Equal(40, output.UnchainedFindingIds.Count);
    }

    [Fact]
    public void GroupingIsOnEntitiesNeverOnTime_NearbyAnchorsAndNoSharedEntitiesProduceNoChains()
    {
        // The textbook time-window clustering, with anchors one second apart, groups all of
        // these. Reverted form as above with any window of a second or more.
        var findings = new List<FindingReference>();
        for (var i = 0; i < 12; i++)
        {
            findings.Add(Finding($"T{i:D2}", $@"observed C:\Unique\{i}.exe", anchor: RunTime.AddSeconds(i)));
        }

        Assert.Empty(Build(findings).Chains);
    }

    [Fact]
    public void GroupingIsOnEntitiesNeverOnTime_AnchorsFarApartStillJoinOnASharedEntity()
    {
        // The other half: time never *prevents* an edge either.
        var output = Build(
        [
            Finding("A", @"C:\x.exe", anchor: RunTime),
            Finding("B", @"C:\x.exe", anchor: RunTime.AddDays(400)),
        ]);

        Assert.Single(output.Chains);
    }

    // ---------------------------------------------------------------- Rule 2

    [Fact]
    public void CommonNounCap_AnEntityReferencedByExactlyTheThresholdStillLinks()
    {
        // Reverted forms (each fails one side of this pair): change '<= CommonNounThreshold'
        // to '< CommonNounThreshold' in the classification (fails this test); remove the cap so
        // everything Shared (fails the next one).
        var findings = AllMentioning(ChainBuilder.CommonNounThreshold, @"C:\Windows\System32\cmd.exe");

        var output = Build(findings);

        var chain = Assert.Single(output.Chains);
        Assert.Equal(ChainBuilder.CommonNounThreshold, chain.MemberFindingIds.Count);
        var entry = Assert.Single(output.Census);
        Assert.Equal(EntityReferenceClass.Shared, entry.Class);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", Assert.Single(chain.JoiningEntities).Value);
    }

    [Fact]
    public void CommonNounCap_AnEntityReferencedByThresholdPlusOneLinksNothing()
    {
        var findings = AllMentioning(ChainBuilder.CommonNounThreshold + 1, @"C:\Windows\System32\cmd.exe");

        var output = Build(findings);

        Assert.Empty(output.Chains);
        Assert.Equal(ChainBuilder.CommonNounThreshold + 1, output.UnchainedFindingIds.Count);
        var entry = Assert.Single(output.Census);
        Assert.Equal(EntityReferenceClass.CommonNoun, entry.Class);
        Assert.Equal(ChainBuilder.CommonNounThreshold + 1, entry.FindingIds.Count);
    }

    [Fact]
    public void CommonNounCap_TheThresholdIsASmallDoubleDigitFigure()
    {
        // Open question 2. If this changes it should change because of a census over real
        // records, and the constant's comment should say so.
        Assert.InRange(ChainBuilder.CommonNounThreshold, 10, 99);
    }

    [Fact]
    public void CommonNounCap_CountsDistinctFindingsNotMentions()
    {
        // One finding mentioning the shell twenty times is one reference. Reverted form: count
        // mentions in Record(); then two findings join nothing.
        var repeated = string.Join(' ', Enumerable.Repeat(@"C:\Windows\System32\cmd.exe", ChainBuilder.CommonNounThreshold * 2));
        var output = Build(
        [
            Finding("A", repeated),
            Finding("B", @"C:\Windows\System32\cmd.exe"),
        ]);

        Assert.Single(output.Chains);
    }

    [Fact]
    public void CommonNounCap_AGenuineSharedPathStillChainsInTheresenceOfACommonNoun()
    {
        // Fifteen findings all name the shell; two of them also name one dropped binary. The
        // chain the binary implies must appear, with the binary as its only joining entity, and
        // the run must not fuse.
        var findings = AllMentioning(15, @"C:\Windows\System32\cmd.exe");
        findings[3] = findings[3] with { Description = findings[3].Description + @" spawned C:\Users\x\AppData\evil.exe" };
        findings[11] = findings[11] with { Target = EntityReference.Path(@"c:\users\X\appdata\EVIL.EXE") };

        var output = Build(findings);

        var chain = Assert.Single(output.Chains);
        Assert.Equal(["F003", "F011"], chain.MemberFindingIds);
        var joining = Assert.Single(chain.JoiningEntities);
        Assert.Equal(@"C:\Users\x\AppData\evil.exe", joining.Value);
        Assert.Equal(13, output.UnchainedFindingIds.Count);
        Assert.Contains(output.Census, e => e.Class == EntityReferenceClass.CommonNoun);
    }

    [Fact]
    public void CommonNounCap_IsAppliedToTheWholeRunBeforeAnyEdgeIsDrawn()
    {
        // If the cap were applied during traversal, the first N findings to be visited would
        // link before the entity crossed the threshold. Here the first two findings in id order
        // share nothing but the common noun; they must not be joined.
        var findings = AllMentioning(ChainBuilder.CommonNounThreshold + 5, @"C:\Windows\System32\cmd.exe");

        var output = Build(findings);

        Assert.Empty(output.Chains);
    }

    [Fact]
    public void CommonNounCap_ThousandsOfPathShapedSubstringsInOneFindingAreAbsorbedNotChained()
    {
        // Brief: "text containing thousands of path-shaped substrings (assert the extractor
        // terminates promptly and the cap absorbs the result rather than producing a chain of
        // everything)". 3 000 mentions of one path from one finding is one reference — it is
        // Single, and nothing joins. The same 3 000 across 3 000 findings would be CommonNoun.
        var text = string.Join(' ', Enumerable.Repeat(@"C:\Windows\Temp\noise.tmp", 3000));
        var others = AllDistinct(5);
        others.Add(Finding("NOISE", text));

        var output = Build(others);

        Assert.Empty(output.Chains);
        Assert.Equal(EntityReferenceClass.Single, output.Census.Single(e => e.Entity.Value == @"C:\Windows\Temp\noise.tmp").Class);
    }
}
