using Scythe.Correlation.Tests.Fixtures;
using Xunit;
using static Scythe.Correlation.Tests.Fixtures.CorrelationFixtures;

namespace Scythe.Correlation.Tests;

/// <summary>Malformed and awkward run input: nothing throws, every refusal says why.</summary>
public sealed class MalformedInputTests
{
    [Fact]
    public void ANullListIsFailed()
    {
        var result = ChainBuilder.Build(null);
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Contains("null", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ANullElementIsFailedWithItsIndex()
    {
        var result = ChainBuilder.Build([PathFinding("A", @"C:\x"), null!]);
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Equal(1, result.Position);
    }

    [Fact]
    public void AMissingIdIsFailedWithItsIndex()
    {
        Assert.Equal(1, ChainBuilder.Build([PathFinding("A", @"C:\x"), new FindingReference("", "x", null)]).Position);
        Assert.Equal(0, ChainBuilder.Build([new FindingReference(null!, "x", null)]).Position);
    }

    [Fact]
    public void ADuplicateIdIsFailedNamingTheIdAndTheSecondIndex()
    {
        var result = ChainBuilder.Build([PathFinding("A", @"C:\x"), PathFinding("B", @"C:\y"), PathFinding("A", @"C:\z")]);
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Contains("'A'", result.Reason, StringComparison.Ordinal);
        Assert.Equal(2, result.Position);
    }

    [Fact]
    public void IdsDifferingOnlyByCaseAreDistinctFindings()
    {
        // Ids are opaque and ordinal; folding them would be inventing a rule the record does not have.
        var output = Build([PathFinding("a", @"C:\x"), PathFinding("A", @"C:\x")]);
        Assert.Equal(["A", "a"], output.Chains[0].MemberFindingIds);
    }

    [Fact]
    public void ANullTargetAndAnEmptyDescriptionAreFine()
    {
        var output = Build([new FindingReference("A", "", null), new FindingReference("B", null!, null)]);
        Assert.Empty(output.Chains);
        Assert.Equal(["A", "B"], output.UnchainedFindingIds);
        Assert.Empty(output.RejectedTargets);
    }

    [Fact]
    public void ATargetThatDoesNotNormaliseIsReportedNotDropped()
    {
        var output = Build(
        [
            Finding("A", "", EntityReference.Path(@"relative\path")),
            Finding("B", "", EntityReference.HostName(".")),
            Finding("C", "", EntityReference.ProcessId(0)),
            Finding("D", "", EntityReference.ProcessId(-7)),
            Finding("E", "", EntityReference.Path(@"\\server")),
            Finding("F", "", new EntityReference(EntityKind.NetworkPeer, null!)),
        ]);

        Assert.Equal(6, output.RejectedTargets.Count);
        Assert.Equal(new[] { "A", "B", "C", "D", "E", "F" }, output.RejectedTargets.Select(r => r.FindingId).ToArray());
        Assert.All(output.RejectedTargets, r => Assert.False(string.IsNullOrEmpty(r.Message)));
        Assert.Contains("sentinel", output.RejectedTargets[2].Message, StringComparison.Ordinal);
        Assert.Empty(output.Census);
    }

    [Fact]
    public void AnUnknownEntityKindOnATargetIsRejectedNotThrown()
    {
        var output = Build([Finding("A", "", new EntityReference((EntityKind)99, "x"))]);
        var rejected = Assert.Single(output.RejectedTargets);
        Assert.Contains("unknown entity kind", rejected.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectedTargetsDoNotStopTheDescriptionFromLinking()
    {
        var output = Build(
        [
            Finding("A", @"also C:\x.exe", EntityReference.Path("bad")),
            Finding("B", @"C:\x.exe"),
        ]);

        Assert.Single(output.Chains);
        Assert.Single(output.RejectedTargets);
    }

    [Fact]
    public void AVeryLongPathShapedDescriptionDoesNotThrowOrLink()
    {
        var huge = @"C:\" + new string('z', 200_000);
        var output = Build([Finding("A", huge), Finding("B", huge)]);
        Assert.Empty(output.Chains);
        Assert.Empty(output.Census);
    }

    [Fact]
    public void AVeryLongPathTargetIsRejectedWithTheCeilingNamed()
    {
        var output = Build([Finding("A", "", EntityReference.Path(@"C:\" + new string('z', 40_000)))]);
        Assert.Contains("ceiling", Assert.Single(output.RejectedTargets).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void HostileDescriptionsNeverThrow()
    {
        string[] hostile =
        [
            "\0\0\0", "\"", "'", "\"\"\"", "''''", "C:", "C:\\", @"\\", @"\\\", @"\\?\", @"\\?\UNC\", @"\\.\", "HKLM\\", "HKLM\\\\", "HKLM\\\\\\\\",
            "pid", "pid:", "pid=", "PID -", "process", "://", "http://", "http://[", "[", "]", "[]", "[::]:", ":::::", "1.1.1.1:", "1.1.1.1:99999",
            new string('\\', 5000), new string(':', 5000), new string('.', 5000), string.Concat(Enumerable.Repeat(@"C:\..\", 3000)),
            "\uD800 C:\\lone\\surrogate.exe \uDC00",
        ];

        var findings = hostile.Select((text, i) => Finding($"H{i:D3}", text)).ToList();
        var result = ChainBuilder.Build(findings);
        Assert.Equal(CorrelationResultState.Ok, result.State);
    }

    [Fact]
    public void ThreeThousandRepeatedDotDotSegmentsResolveToTheRoot()
    {
        var output = Build([Finding("A", string.Concat(Enumerable.Repeat(@"C:\..\", 3000)) + "x.exe")]);
        Assert.Equal(@"C:\x.exe", Assert.Single(output.Census).Entity.Value);
    }
}
