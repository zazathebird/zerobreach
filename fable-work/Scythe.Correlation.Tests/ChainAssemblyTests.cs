using Scythe.Correlation.Tests.Fixtures;
using Xunit;
using static Scythe.Correlation.Tests.Fixtures.CorrelationFixtures;

namespace Scythe.Correlation.Tests;

/// <summary>Ordinary chain assembly: the happy path over authored runs.</summary>
public sealed class ChainAssemblyTests
{
    [Fact]
    public void TwoFindingsNamingOnePathInPlainAndExtendedLengthFormJoinOneChain()
    {
        // The brief's first test names "drive-letter and UNC form". The only UNC-shaped spelling
        // of a drive-letter path that can be equated textually is the extended-length prefix
        // form; a mapped drive's \\server\share spelling cannot (open question 6, and see
        // AMappedDriveAndItsUncSpellingAreDifferentEntities).
        var output = Build(
        [
            PathFinding("A", @"C:\Users\x\a.exe"),
            PathFinding("B", @"\\?\c:\users\X\A.EXE"),
        ]);

        var chain = Assert.Single(output.Chains);
        Assert.Equal(["A", "B"], chain.MemberFindingIds);
        var joining = Assert.Single(chain.JoiningEntities);
        Assert.Equal(EntityKind.Path, joining.Kind);
        Assert.Equal(@"C:\Users\x\a.exe", joining.Value);
    }

    [Fact]
    public void TwoSpellingsOfOneUncPathJoinAndTheEntityIsReportedOnce()
    {
        var output = Build(
        [
            PathFinding("A", @"\\SRV\Share\dir\file.exe"),
            PathFinding("B", @"\\?\UNC\srv\share\dir\file.exe"),
            Finding("C", "also touched //srv/share/dir/./file.exe today"),
        ]);

        var chain = Assert.Single(output.Chains);
        Assert.Equal(["A", "B", "C"], chain.MemberFindingIds);
        Assert.Single(chain.JoiningEntities);
    }

    [Fact]
    public void CaseAndSeparatorDifferentSpellingsJoin()
    {
        var output = Build(
        [
            PathFinding("A", @"C:\Windows\System32\cmd.exe"),
            PathFinding("B", "c:/WINDOWS/system32/CMD.EXE"),
        ]);

        Assert.Single(output.Chains);
    }

    [Fact]
    public void TheReportedSpellingIsTheOrdinalSmallestSeenWhateverTheArrivalOrder()
    {
        var a = PathFinding("A", @"c:\Tools\run.exe");
        var b = PathFinding("B", @"C:\tools\RUN.exe");
        var first = Build([a, b]).Chains[0].JoiningEntities[0].Value;
        var second = Build([b, a]).Chains[0].JoiningEntities[0].Value;
        Assert.Equal(first, second);
        Assert.Equal(@"C:\Tools\run.exe", first); // 'T' (0x54) sorts before 't' (0x74) ordinally
    }

    [Fact]
    public void ADirectoryAndAFileWithItsNamePlusASuffixDoNotJoin()
    {
        var output = Build(
        [
            PathFinding("A", @"C:\Temp\tool"),
            PathFinding("B", @"C:\Temp\tool.exe"),
            PathFinding("C", @"C:\Temp\tool2"),
        ]);

        Assert.Empty(output.Chains);
        Assert.Equal(["A", "B", "C"], output.UnchainedFindingIds);
    }

    [Fact]
    public void AMappedDriveAndAUncSpellingDoNotJoin()
    {
        var output = Build(
        [
            PathFinding("A", @"X:\dir\file"),
            PathFinding("B", @"\\server\share\dir\file"),
        ]);

        Assert.Empty(output.Chains);
    }

    [Fact]
    public void TargetAndDescriptionEntitiesBothLink()
    {
        var output = Build(
        [
            PathFinding("A", @"C:\Users\x\a.exe"),
            Finding("B", @"startup entry launches C:\Users\x\a.exe on logon"),
        ]);

        Assert.Single(output.Chains);
    }

    [Fact]
    public void OnlyJoiningEntitiesAreReportedNotEveryEntityAMemberMentions()
    {
        var output = Build(
        [
            Finding("A", @"C:\shared.exe and C:\only-a.exe"),
            Finding("B", @"C:\shared.exe and C:\only-b.exe"),
        ]);

        var chain = Assert.Single(output.Chains);
        var joining = Assert.Single(chain.JoiningEntities);
        Assert.Equal(@"C:\shared.exe", joining.Value);

        // The census still has all three, so a consumer can find the lone mentions.
        Assert.Equal(3, output.Census.Count);
        Assert.Equal(2, output.Census.Count(e => e.Class == EntityReferenceClass.Single));
    }

    [Fact]
    public void GroupingIsTransitiveAcrossSharedEntities()
    {
        var output = Build(
        [
            Finding("A", @"C:\x.exe"),
            Finding("B", @"C:\x.exe and HKLM\Software\Run\\U"),
            Finding("C", @"HKLM\Software\Run\\U"),
        ]);

        var chain = Assert.Single(output.Chains);
        Assert.Equal(["A", "B", "C"], chain.MemberFindingIds);
        Assert.Equal(2, chain.JoiningEntities.Count);
        Assert.Equal(EntityKind.Path, chain.JoiningEntities[0].Kind);
        Assert.Equal(EntityKind.RegistryPath, chain.JoiningEntities[1].Kind);
    }

    [Fact]
    public void SeparateComponentsAreSeparateChainsOrderedByFirstFinding()
    {
        var output = Build(
        [
            Finding("Q", @"C:\one.exe"),
            Finding("P", @"C:\two.exe"),
            Finding("R", @"C:\one.exe"),
            Finding("S", @"C:\two.exe"),
        ]);

        Assert.Equal(2, output.Chains.Count);
        Assert.Equal("P", output.Chains[0].FirstFindingId);
        Assert.Equal(["P", "S"], output.Chains[0].MemberFindingIds);
        Assert.Equal("Q", output.Chains[1].FirstFindingId);
        Assert.Equal(["Q", "R"], output.Chains[1].MemberFindingIds);
    }

    [Fact]
    public void RegistryShortAndLongFormsJoinButAKeyAndItsDefaultValueDoNot()
    {
        var output = Build(
        [
            Finding("A", "", EntityReference.RegistryPath(@"HKEY_LOCAL_MACHINE\Software\Foo")),
            Finding("B", "", EntityReference.RegistryPath(@"hklm\software\foo\")),
            Finding("C", "", EntityReference.RegistryPath(@"HKLM\Software\Foo\\")),
        ]);

        var chain = Assert.Single(output.Chains);
        Assert.Equal(["A", "B"], chain.MemberFindingIds);
        Assert.Equal(["C"], output.UnchainedFindingIds);
    }

    [Fact]
    public void AProcessIdentifierTargetLinksToAProseMentionWithinTheRun()
    {
        var output = Build(
        [
            Finding("A", "handle open", EntityReference.ProcessId(4412)),
            Finding("B", "socket owned by PID 4412 to 10.0.0.5"),
        ]);

        var chain = Assert.Single(output.Chains);
        Assert.Equal("4412", Assert.Single(chain.JoiningEntities).Value);
    }

    [Fact]
    public void AHostNameAndTheAddressItResolvesToDoNotJoin()
    {
        var output = Build(
        [
            Finding("A", "beacon", EntityReference.HostName("c2.evil.example")),
            Finding("B", "beacon", EntityReference.NetworkPeer("203.0.113.9")),
            Finding("C", "connected to c2.evil.example:443 and 203.0.113.9"),
        ]);

        // C links to both, so all three end up together — through C, not through any
        // equation of the name with the address. The joining set says so.
        var chain = Assert.Single(output.Chains);
        Assert.Equal(2, chain.JoiningEntities.Count);
        Assert.Equal(EntityKind.HostName, chain.JoiningEntities[0].Kind);
        Assert.Equal(EntityKind.NetworkPeer, chain.JoiningEntities[1].Kind);
    }

    [Fact]
    public void OneFindingReferencingAnEntityTwiceCountsOnceInTheCensus()
    {
        var output = Build(
        [
            Finding("A", @"C:\x.exe then C:\X.EXE again", EntityReference.Path(@"c:\x.exe")),
        ]);

        var entry = Assert.Single(output.Census);
        Assert.Equal(["A"], entry.FindingIds);
        Assert.Equal(EntityReferenceClass.Single, entry.Class);
        Assert.Empty(output.Chains);
    }

    [Fact]
    public void ZeroFindingsProduceAnEmptyOutput()
    {
        var output = Build([]);
        Assert.Empty(output.Chains);
        Assert.Empty(output.UnchainedFindingIds);
        Assert.Empty(output.Census);
        Assert.Empty(output.RejectedTargets);
    }

    [Fact]
    public void OneFindingIsUnchainedNotAChainOfOne()
    {
        var output = Build([PathFinding("A", @"C:\x.exe", @"also C:\y.exe")]);
        Assert.Empty(output.Chains);
        Assert.Equal(["A"], output.UnchainedFindingIds);
        Assert.Equal(2, output.Census.Count);
    }

    [Fact]
    public void TheCensusIsSortedByKindThenValue()
    {
        var output = Build(
        [
            Finding("A", @"10.0.0.9 c2.evil.example PID 5 HKLM\Z C:\b.exe C:\a.exe HKLM\A"),
        ]);

        var values = output.Census.Select(e => e.Entity.Kind + ":" + e.Entity.Value).ToArray();
        Assert.Equal(
            new[] { "Path:C:\\a.exe", "Path:C:\\b.exe", "RegistryPath:HKLM\\A", "RegistryPath:HKLM\\Z", "ProcessId:5", "HostName:c2.evil.example", "NetworkPeer:10.0.0.9" },
            values);
    }
}
