using Xunit;

namespace ZeroBreach.Paths.Tests;

/// <summary>
/// Normalisation is a projection: applying it to its own output changes nothing, and the same
/// input always produces the identical result. Swept across a fixture set covering every path
/// form the library understands — if a new form is added, it belongs in this list.
/// </summary>
public sealed class IdempotenceAndDeterminismTests
{
    /// <summary>Valid inputs of every supported shape, including the awkward corners.</summary>
    public static TheoryData<string> Fixtures() => new()
    {
        // Drive-absolute, plain and messy.
        @"C:\Windows\System32",
        @"c:\windows",
        @"C:\",
        "C:/mixed/separators\\here",
        @"C:\a\\\b",
        @"C:\a\.\b\..\c",
        @"C:\..\..\clamped",
        @"C:\trailing\",
        @"C:\trailing.",
        @"C:\trailing ",
        @"C:\a.\b",
        @"C:\a..\b",
        @"C:\...\b",
        @"C:\a \b",
        @"C:\a \",          // load-bearing trailing separator (trailing-space name)
        @"C:\foo\...",
        // Drive-relative, root-relative, relative.
        "C:",
        @"C:foo\bar",
        @"C:foo\..\..",
        @"\rooted\on\current\drive",
        @"\",
        @"relative\path",
        ".",
        "..",
        @"..\..\x",
        @"a\..",
        // UNC in all forms.
        @"\\server\share",
        @"\\server\share\",
        @"\\SERVER\Share\Dir\file.txt",
        @"\\localhost\c$\Windows",
        @"\\?\UNC\srv\share\x",
        @"\\.\UNC\srv\share\x",
        // Device namespace and GLOBALROOT.
        @"\\?\C:\Windows\System32",
        @"\\?\C:",
        @"\\.\C:\x",
        @"\\.\PhysicalDrive0",
        @"\\.\pipe\name",
        @"\\?\Volume{0a1b2c3d-0000-0000-0000-100000000000}\x",
        @"\\?\GLOBALROOT\Device\HarddiskVolume1\Windows",
        @"\\.\GLOBALROOT",
        // Streams.
        @"C:\f.txt:stream",
        @"C:\f.txt:stream:$DATA",
        @"C:\f.txt::$DATA",
        @"C:\dir:$I30:$INDEX_ALLOCATION",
        @"C:\f:s...",           // path-end trim ahead of the stream split
        @"C:\file. :s",         // stream keeps the dotted-space name alive
        // Flags of every kind (flagged, not rewritten — so they must round-trip too).
        @"C:\PROGRA~1\x",
        @"C:\CON\NUL.txt",
        "C:\\Wind\u043Ews\\x",
        "C:\\Caf\u00E9",
        // Case preservation.
        @"C:\MiXeD\CaSe\PaTh",
    };

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void NormalizingTheDisplayForm_IsAFixpoint(string input)
    {
        NormalizedPath once = PathNormalizer.Normalize(input);
        Assert.Equal(OperationState.Ok, once.State);

        NormalizedPath twice = PathNormalizer.Normalize(once.NormalizedDisplay!);
        Assert.Equal(OperationState.Ok, twice.State);
        Assert.Equal(once.NormalizedDisplay, twice.NormalizedDisplay);
        Assert.Equal(once.Canonical, twice.Canonical);
        Assert.Equal(once.Root, twice.Root);
        Assert.Equal(once.Segments, twice.Segments);
        Assert.Equal(once.CanonicalStream, twice.CanonicalStream);
        Assert.Equal(once.RootSpace, twice.RootSpace);
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void SameInput_SameResult_EveryTime(string input)
    {
        NormalizedPath a = PathNormalizer.Normalize(input);
        NormalizedPath b = PathNormalizer.Normalize(input);
        Assert.Equal(a.State, b.State);
        Assert.Equal(a.Canonical, b.Canonical);
        Assert.Equal(a.NormalizedDisplay, b.NormalizedDisplay);
        Assert.Equal(a.Flags, b.Flags);
        Assert.Equal(a.Kind, b.Kind);
        Assert.Equal(a.Segments, b.Segments);
        Assert.Equal(
            a.Transformations.Select(t => (t.Kind, t.Before, t.After)),
            b.Transformations.Select(t => (t.Kind, t.Before, t.After)));
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void EveryFixture_IsSelfContainedInItsSpace(string input)
    {
        // Every Ok path is Equal to itself — the containment engine agrees with the
        // normaliser about identity for every comparable fixture.
        NormalizedPath p = PathNormalizer.Normalize(input);
        if (p.RootSpace is not (PathRootSpace.Drive or PathRootSpace.Unc) || p.CanonicalStream is not null)
            return; // undecidable spaces are covered by the containment suite
        ContainmentResult self = PathContainment.IsInside(p, p);
        Assert.Equal(OperationState.Ok, self.State);
        Assert.True(self.IsInside);
    }

    [Fact]
    public void EnvironmentExpansion_IsAlsoIdempotentThroughDisplay()
    {
        var env = new Dictionary<string, string> { ["SystemRoot"] = @"C:\Windows" };
        NormalizedPath once = PathNormalizer.Normalize(@"%SystemRoot%\System32", env);
        // The display form has no '%' left, so a second pass without the dictionary agrees.
        NormalizedPath twice = PathNormalizer.Normalize(once.NormalizedDisplay!);
        Assert.Equal(once.Canonical, twice.Canonical);
    }
}
