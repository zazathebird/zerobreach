namespace ZeroBreach.Paths;

/// <summary>
/// The containment check the guard is built on: <em>is path A inside directory B?</em>
/// Comparison happens on normalised forms, so <c>C:/Windows/x</c>, <c>C:\WINDOWS\.\x</c> and
/// <c>\\?\C:\Windows\x</c> all agree — and it is segment-based, never a string-prefix test, so
/// <c>C:\FooBar</c> is not inside <c>C:\Foo</c>.
///
/// Fail-closed by construction: any relationship the strings cannot prove — relative paths with
/// no base, device or object-manager namespaces that may alias a volume, loopback/administrative
/// UNC shares — is <see cref="OperationState.Incomplete"/>, which a guard must treat as refuse.
/// What pure string logic can never see (junctions, symlinks, SUBST drives, 8.3 aliases) is the
/// host's responsibility; the flags on the normalised paths carry the evidence it needs.
/// </summary>
public static class PathContainment
{
    /// <summary>Normalise both strings (with the same environment) and test containment.</summary>
    public static ContainmentResult IsInside(
        string candidate,
        string directory,
        IReadOnlyDictionary<string, string>? environment = null)
        => IsInside(PathNormalizer.Normalize(candidate, environment), PathNormalizer.Normalize(directory, environment));

    /// <summary>Test whether <paramref name="candidate"/> is inside (or is) <paramref name="directory"/>.</summary>
    public static ContainmentResult IsInside(NormalizedPath candidate, NormalizedPath directory)
    {
        if (candidate.State == OperationState.Failed)
            return ContainmentResult.Malformed($"candidate path is malformed: {candidate.FailureReason}");
        if (directory.State == OperationState.Failed)
            return ContainmentResult.Malformed($"directory path is malformed: {directory.FailureReason}");

        // A directory argument carrying a named stream does not denote a directory at all;
        // there is nothing to be "inside". (The default ::$DATA suffix carries no distinct
        // identity and normalises away, so it does not trip this.)
        if (directory.CanonicalStream is not null)
            return ContainmentResult.Undecidable(
                $"directory argument '{directory.Original}' names an alternate data stream, not a directory");

        // Only drive-absolute and UNC paths pin down a location from the string alone.
        // Everything else depends on state this library deliberately has no access to:
        // relative forms need a current directory; the device and object-manager namespaces
        // can alias any volume (\\.\HarddiskVolume2\... may BE C:\...). Undecidable, so the
        // guard refuses — an "Outside" here would be the classic bypass.
        if (Describe(candidate.RootSpace) is string candidateWhy)
            return ContainmentResult.Undecidable($"candidate path '{candidate.Original}' {candidateWhy}");
        if (Describe(directory.RootSpace) is string directoryWhy)
            return ContainmentResult.Undecidable($"directory path '{directory.Original}' {directoryWhy}");

        // A loopback or administrative-share UNC path may alias a local drive path (and vice
        // versa), so a cross-namespace comparison cannot prove Outside.
        const PathFlags aliasFlags = PathFlags.LoopbackUncServer | PathFlags.AdministrativeShare;
        if (candidate.RootSpace != directory.RootSpace &&
            ((candidate.Flags | directory.Flags) & aliasFlags) != 0)
        {
            return ContainmentResult.Undecidable(
                "a loopback or administrative UNC share may alias a local drive; the relationship cannot be proven from the strings");
        }

        if (candidate.RootSpace != directory.RootSpace)
            return ContainmentResult.Outside(
                $"different root namespaces ({candidate.RootSpace} vs {directory.RootSpace})");

        if (!string.Equals(candidate.Root, directory.Root, StringComparison.Ordinal))
            return ContainmentResult.Outside($"different roots ('{candidate.Root}' vs '{directory.Root}')");

        // Whole-segment prefix comparison. Segments are already canonical (lower-cased), so
        // ordinal equality is exact — and comparing per segment is precisely what makes
        // C:\FooBar land Outside C:\Foo instead of being swallowed by a string prefix test.
        IReadOnlyList<string> a = candidate.Segments;
        IReadOnlyList<string> d = directory.Segments;
        if (a.Count < d.Count)
            return ContainmentResult.Outside("candidate is shallower than the directory");
        for (int i = 0; i < d.Count; i++)
        {
            if (!string.Equals(a[i], d[i], StringComparison.Ordinal))
                return ContainmentResult.Outside($"paths diverge at segment {i} ('{a[i]}' vs '{d[i]}')");
        }

        if (a.Count > d.Count)
            return ContainmentResult.Inside();

        // Same segments. A named stream on the directory is subordinate content — inside.
        return candidate.CanonicalStream is not null ? ContainmentResult.Inside() : ContainmentResult.Equal();
    }

    /// <summary>Why a root space is not comparable; null for the comparable ones (Drive, Unc).</summary>
    private static string? Describe(PathRootSpace space) => space switch
    {
        PathRootSpace.Drive or PathRootSpace.Unc => null,
        PathRootSpace.Relative => "is relative and cannot be resolved without a base directory",
        PathRootSpace.CurrentDrive => "is rooted on an unknown current drive",
        PathRootSpace.DriveCurrentDirectory => "is relative to a drive's unknown current directory",
        PathRootSpace.Device => "is in the device namespace, which may alias any volume",
        PathRootSpace.GlobalRoot => "is in the object-manager namespace, which may alias any volume",
        _ => "did not normalise to a comparable namespace",
    };
}
