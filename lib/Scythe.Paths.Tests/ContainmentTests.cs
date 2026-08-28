using Xunit;

namespace Scythe.Paths.Tests;

/// <summary>
/// The headline API: is path A inside directory B. Segment-based (C:\FooBar is not inside
/// C:\Foo), form-blind (a \\?\ path IS inside its plain-form parent), and fail-closed
/// (anything unprovable is Incomplete, and IsInside can never be true off an Ok state).
/// </summary>
public sealed class ContainmentTests
{
    private static ContainmentResult Check(string candidate, string directory) =>
        PathContainment.IsInside(candidate, directory);

    private static void AssertVerdict(ContainmentVerdict expected, string candidate, string directory)
    {
        ContainmentResult r = Check(candidate, directory);
        Assert.Equal(OperationState.Ok, r.State);
        Assert.Equal(expected, r.Verdict);
    }

    // ------------------------------------------------------------------ the classic off-by-one

    [Fact]
    public void StringPrefix_ThatIsNotAParent_IsOutside()
    {
        // THE containment bypass: "C:\FooBar" starts with "C:\Foo" as a string but is a
        // sibling, not a child. This test is the reason the comparison is segment-based.
        ContainmentResult r = Check(@"C:\FooBar\x.txt", @"C:\Foo");
        Assert.Equal(OperationState.Ok, r.State);
        Assert.Equal(ContainmentVerdict.Outside, r.Verdict);
        Assert.False(r.IsInside);
    }

    [Fact]
    public void TheReverseDirection_IsAlsoOutside()
    {
        AssertVerdict(ContainmentVerdict.Outside, @"C:\Foo\x.txt", @"C:\FooBar");
    }

    [Fact]
    public void SharePrefixNames_AreNotConfused_OnUnc()
    {
        AssertVerdict(ContainmentVerdict.Outside, @"\\srv\share2\x", @"\\srv\share");
    }

    [Fact]
    public void SegmentPrefix_DeeperInThePath_IsAlsoOutside()
    {
        // The off-by-one is not only a root-level hazard: any segment along the way could be
        // string-prefix-confused with a sibling.
        AssertVerdict(ContainmentVerdict.Outside, @"C:\Windows\System32Extra\x.dll", @"C:\Windows\System32");
        AssertVerdict(ContainmentVerdict.Outside, @"\\srv\share\dirA\x", @"\\srv\share\dir");
    }

    // ------------------------------------------------------------------ basic verdicts

    [Fact]
    public void PathEqualToDirectory_IsEqual_AndCountsAsInside()
    {
        // Deliberate, pinned: a guard protecting C:\Foo must also refuse destroying C:\Foo
        // itself, so IsInside includes Equal. Callers who need the distinction have Verdict.
        ContainmentResult r = Check(@"C:\Foo", @"C:\Foo");
        Assert.Equal(ContainmentVerdict.Equal, r.Verdict);
        Assert.True(r.IsInside);
    }

    [Fact]
    public void OneLevelIn_IsInside()
    {
        ContainmentResult r = Check(@"C:\Foo\file.txt", @"C:\Foo");
        Assert.Equal(ContainmentVerdict.Inside, r.Verdict);
        Assert.True(r.IsInside);
    }

    [Fact]
    public void ManyLevelsIn_IsInside()
    {
        AssertVerdict(ContainmentVerdict.Inside, @"C:\Foo\a\b\c\d\e.txt", @"C:\Foo");
    }

    [Fact]
    public void Sibling_IsOutside()
    {
        AssertVerdict(ContainmentVerdict.Outside, @"C:\Users\x", @"C:\Windows");
    }

    [Fact]
    public void ParentOfTheDirectory_IsOutside()
    {
        AssertVerdict(ContainmentVerdict.Outside, @"C:\", @"C:\Windows");
    }

    [Fact]
    public void DifferentDrives_AreOutside()
    {
        AssertVerdict(ContainmentVerdict.Outside, @"D:\Foo\x", @"C:\Foo");
    }

    [Fact]
    public void EverythingOnTheDrive_IsInsideItsRoot()
    {
        AssertVerdict(ContainmentVerdict.Inside, @"C:\anything\at\all", @"C:\");
        AssertVerdict(ContainmentVerdict.Equal, @"C:\", @"C:\");
    }

    // ------------------------------------------------------------------ differing input forms

    [Fact]
    public void CaseDiffers_StillInside()
    {
        AssertVerdict(ContainmentVerdict.Inside, @"C:\FOO\BAR\baz.txt", @"c:\foo");
    }

    [Fact]
    public void ForwardSlashes_StillInside()
    {
        AssertVerdict(ContainmentVerdict.Inside, "C:/Foo/bar/x", @"C:\Foo");
    }

    [Fact]
    public void VerbatimPath_IsInsideItsPlainFormParent()
    {
        // Required by the brief, by name: \\?\C:\Foo\x IS inside C:\Foo.
        ContainmentResult r = Check(@"\\?\C:\Foo\x", @"C:\Foo");
        Assert.Equal(OperationState.Ok, r.State);
        Assert.True(r.IsInside);
    }

    [Fact]
    public void PlainPath_IsInsideItsVerbatimFormParent()
    {
        Assert.True(Check(@"C:\Foo\x", @"\\?\C:\Foo").IsInside);
    }

    [Fact]
    public void DeviceDotDrivePath_IsInsideItsPlainFormParent()
    {
        Assert.True(Check(@"\\.\C:\Foo\x", @"C:\Foo").IsInside);
    }

    [Fact]
    public void ExtendedUnc_IsInsideItsPlainUncParent()
    {
        Assert.True(Check(@"\\?\UNC\srv\share\dir\x", @"\\srv\share\dir").IsInside);
    }

    [Fact]
    public void UncContainment_Works()
    {
        AssertVerdict(ContainmentVerdict.Inside, @"\\SRV\Share\dir\file", @"\\srv\share");
        AssertVerdict(ContainmentVerdict.Equal, @"\\srv\share", @"\\SRV\SHARE");
        AssertVerdict(ContainmentVerdict.Outside, @"\\other\share\x", @"\\srv\share");
    }

    [Fact]
    public void DirectoryWithTrailingSeparator_ComparesTheSame()
    {
        Assert.True(Check(@"C:\Foo\x", @"C:\Foo\").IsInside);
    }

    [Fact]
    public void TraversalThatResolvesInside_IsInside()
    {
        Assert.True(Check(@"C:\Other\..\Foo\x", @"C:\Foo").IsInside);
    }

    [Fact]
    public void TraversalThatEscapes_IsOutside()
    {
        AssertVerdict(ContainmentVerdict.Outside, @"C:\Foo\..\Bar\x", @"C:\Foo");
    }

    // ------------------------------------------------------------------ streams

    [Fact]
    public void StreamOnAFileInside_IsInside()
    {
        Assert.True(Check(@"C:\Foo\file.txt:hidden", @"C:\Foo").IsInside);
    }

    [Fact]
    public void StreamOnTheDirectoryItself_IsInside()
    {
        // "C:\Foo:evil" stores data ON the protected directory — subordinate content.
        ContainmentResult r = Check(@"C:\Foo:evil", @"C:\Foo");
        Assert.Equal(ContainmentVerdict.Inside, r.Verdict);
        Assert.True(r.IsInside);
    }

    [Fact]
    public void DefaultDataStreamSuffix_OnTheDirectory_IsEqual()
    {
        AssertVerdict(ContainmentVerdict.Equal, @"C:\Foo::$DATA", @"C:\Foo");
    }

    [Fact]
    public void DirectoryArgumentWithNamedStream_IsUndecidable()
    {
        // A named stream is not a directory; nothing can be "inside" it. Refuse.
        ContainmentResult r = Check(@"C:\Foo\x", @"C:\Foo:stream");
        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.False(r.IsInside);
        Assert.Null(r.Verdict);
    }

    // ------------------------------------------------------------------ undecidable namespaces

    [Theory]
    [InlineData(@"relative\path")]
    [InlineData(@"..\x")]
    [InlineData(@"\rooted-on-unknown-drive")]
    [InlineData(@"C:drive-relative")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolume1\Windows\x")]
    public void UnresolvableCandidate_IsIncomplete_NeverAVerdict(string candidate)
    {
        ContainmentResult r = Check(candidate, @"C:\Windows");
        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.Null(r.Verdict);
        Assert.False(r.IsInside);
        Assert.NotNull(r.Reason);
    }

    [Theory]
    [InlineData(@"relative\dir")]
    [InlineData(@"C:reldir")]
    [InlineData(@"\\.\HarddiskVolume2")]
    public void UnresolvableDirectory_IsIncomplete(string directory)
    {
        Assert.Equal(OperationState.Incomplete, Check(@"C:\Windows\x", directory).State);
    }

    [Fact]
    public void LoopbackAdminShare_VersusLocalDrive_IsIncomplete()
    {
        // \\localhost\C$\Windows almost certainly IS C:\Windows. Outside would be the bypass;
        // Inside would be a guess. Undecidable from strings — refuse.
        ContainmentResult r = Check(@"\\localhost\C$\Windows\evil.exe", @"C:\Windows");
        Assert.Equal(OperationState.Incomplete, r.State);
        Assert.False(r.IsInside);
    }

    [Fact]
    public void AdminShareOnNamedServer_VersusDrive_IsAlsoIncomplete()
    {
        Assert.Equal(OperationState.Incomplete, Check(@"\\ws-042\C$\Windows\x", @"C:\Windows").State);
    }

    [Fact]
    public void OrdinaryRemoteShare_VersusLocalDrive_IsOutside()
    {
        // No alias signal: a plain remote share is not inside a local directory. Pinned so the
        // guard does not refuse every network operation.
        ContainmentResult r = Check(@"\\fileserver\projects\x", @"C:\Windows");
        Assert.Equal(OperationState.Ok, r.State);
        Assert.Equal(ContainmentVerdict.Outside, r.Verdict);
    }

    [Fact]
    public void SameLoopbackShare_OnBothSides_IsComparable()
    {
        // Both sides in the same UNC root: the alias question cancels out.
        Assert.True(Check(@"\\localhost\c$\Windows\x", @"\\localhost\c$\Windows").IsInside);
    }

    // ------------------------------------------------------------------ malformed input

    [Fact]
    public void MalformedCandidate_IsFailed_NotAVerdict()
    {
        ContainmentResult r = Check(@"C:\a<b", @"C:\");
        Assert.Equal(OperationState.Failed, r.State);
        Assert.Null(r.Verdict);
        Assert.False(r.IsInside);
        Assert.Contains("candidate", r.Reason);
    }

    [Fact]
    public void MalformedDirectory_IsFailed()
    {
        ContainmentResult r = Check(@"C:\x", @"C:\a|b");
        Assert.Equal(OperationState.Failed, r.State);
        Assert.Contains("directory", r.Reason);
    }

    // ------------------------------------------------------------------ structural fail-closed

    [Fact]
    public void IsInside_IsStructurallyFalse_OffTheOkState()
    {
        // The property, not just examples: across every non-Ok result we can produce,
        // IsInside must be false. Incomplete or Failed can NEVER authorise anything.
        (string candidate, string directory)[] nonOkPairs =
        {
            (@"rel\x", @"C:\Foo"),
            (@"C:rel", @"C:\Foo"),
            (@"\x", @"C:\Foo"),
            (@"\\.\PhysicalDrive0", @"C:\"),
            (@"\\?\GLOBALROOT\Device\H1\x", @"C:\"),
            (@"\\localhost\c$\x", @"C:\"),
            (@"C:\a<b", @"C:\"),
            (@"C:\x", @"bad|dir"),
            (@"C:\x", @"C:\Foo:stream"),
        };
        foreach ((string candidate, string directory) in nonOkPairs)
        {
            ContainmentResult r = Check(candidate, directory);
            Assert.NotEqual(OperationState.Ok, r.State);
            Assert.False(r.IsInside);
            Assert.Null(r.Verdict);
        }
    }

    [Fact]
    public void StringOverload_UsesTheSameEnvironmentForBothSides()
    {
        var env = new Dictionary<string, string> { ["ROOT"] = @"C:\Data" };
        Assert.True(PathContainment.IsInside(@"%ROOT%\sub\file", @"%ROOT%", env).IsInside);
    }
}
