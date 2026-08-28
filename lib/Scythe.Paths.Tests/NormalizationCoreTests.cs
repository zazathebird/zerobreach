using Xunit;

namespace Scythe.Paths.Tests;

/// <summary>
/// The core rewrites: separator direction, duplicate separators, '.' and '..' segments,
/// trailing dots and spaces, case folding, and the audit trail that reports all of it.
/// </summary>
public sealed class NormalizationCoreTests
{
    private static NormalizedPath Ok(string path)
    {
        NormalizedPath result = PathNormalizer.Normalize(path);
        Assert.Equal(OperationState.Ok, result.State);
        return result;
    }

    // ------------------------------------------------------------------ separators

    [Fact]
    public void ForwardSlashes_BecomeBackslashes()
    {
        NormalizedPath p = Ok("C:/Windows/System32");
        Assert.Equal(@"c:\windows\system32", p.Canonical);
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.SeparatorsNormalized);
    }

    [Fact]
    public void MixedSlashes_BecomeBackslashes()
    {
        Assert.Equal(@"c:\a\b\c", Ok(@"C:\a/b\c").Canonical);
    }

    [Fact]
    public void DuplicateSeparators_Collapse()
    {
        NormalizedPath p = Ok(@"C:\a\\\b");
        Assert.Equal(@"c:\a\b", p.Canonical);
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.DuplicateSeparatorsCollapsed);
    }

    // ------------------------------------------------------------------ dot segments

    [Fact]
    public void SingleDotSegments_AreRemoved()
    {
        NormalizedPath p = Ok(@"C:\a\.\b\.");
        Assert.Equal(@"c:\a\b", p.Canonical);
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.DotSegmentsRemoved);
    }

    [Fact]
    public void DotDotSegments_ResolveAgainstParent()
    {
        NormalizedPath p = Ok(@"C:\a\b\..\c");
        Assert.Equal(@"c:\a\c", p.Canonical);
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.ParentSegmentsResolved);
    }

    [Fact]
    public void DotDot_PastTheRoot_IsClampedAndFlagged()
    {
        NormalizedPath p = Ok(@"C:\..\..\Windows");
        Assert.Equal(@"c:\windows", p.Canonical);
        Assert.True(p.Flags.HasFlag(PathFlags.ParentTraversalClamped));
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.ParentTraversalClamped);
    }

    [Fact]
    public void DotDot_PastUncShareRoot_IsClamped()
    {
        NormalizedPath p = Ok(@"\\server\share\..\..\x");
        Assert.Equal(@"\\server\share\x", p.Canonical);
        Assert.True(p.Flags.HasFlag(PathFlags.ParentTraversalClamped));
    }

    [Fact]
    public void DotDot_ResolvesToBareRoot()
    {
        Assert.Equal(@"c:\", Ok(@"C:\Windows\System32\..\..").Canonical);
    }

    [Fact]
    public void LeadingDotDot_OnRelativePath_IsPreserved()
    {
        // No root to clamp against: '..\..\x' really does mean two levels up from an unknown base.
        NormalizedPath p = Ok(@"..\..\x");
        Assert.Equal(@"..\..\x", p.Canonical);
        Assert.False(p.Flags.HasFlag(PathFlags.ParentTraversalClamped));
    }

    [Fact]
    public void RelativePath_ResolvingToNothing_RendersAsDot()
    {
        NormalizedPath p = Ok(@"a\..");
        Assert.Equal(".", p.Canonical);
        Assert.Equal(".", p.NormalizedDisplay);
        Assert.Empty(p.Segments);
    }

    // ------------------------------------------------------------------ trailing dots and spaces

    [Fact]
    public void TrailingDots_OnFinalComponent_AreStripped()
    {
        NormalizedPath p = Ok(@"C:\Windows...");
        Assert.Equal(@"c:\windows", p.Canonical);
        Assert.True(p.Flags.HasFlag(PathFlags.TrailingDotsOrSpacesStripped));
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.TrailingDotsAndSpacesTrimmed);
    }

    [Fact]
    public void TrailingSpacesAndDots_OnFinalComponent_AreStripped()
    {
        Assert.Equal(@"c:\file", Ok(@"C:\file . . ").Canonical);
    }

    [Fact]
    public void MiddleComponent_WithSingleTrailingDot_LosesIt()
    {
        // Documented Win32 rule: a segment ending in exactly one '.' loses it.
        Assert.Equal(@"c:\a\b", Ok(@"C:\a.\b").Canonical);
    }

    [Fact]
    public void MiddleComponent_WithTwoTrailingDots_IsUntouched()
    {
        // 'a..' is a legal name; only a single trailing period is trimmed mid-path.
        Assert.Equal(@"c:\a..\b", Ok(@"C:\a..\b").Canonical);
    }

    [Fact]
    public void MiddleComponent_AllDots_IsUntouched()
    {
        // Three or more periods is a valid (if hostile) name per the documented rules.
        Assert.Equal(@"c:\...\b", Ok(@"C:\...\b").Canonical);
    }

    [Fact]
    public void MiddleComponent_TrailingSpace_IsPreserved()
    {
        // Only the path end is space-trimmed; 'a ' mid-path stays addressable evidence.
        Assert.Equal(@"c:\a \b", Ok(@"C:\a \b").Canonical);
    }

    [Fact]
    public void FinalComponent_AllDots_CollapsesToParent()
    {
        Assert.Equal(@"c:\foo", Ok(@"C:\foo\...").Canonical);
    }

    [Fact]
    public void TrailingSeparator_ProtectsTrailingSpaceName()
    {
        // "C:\a \" is the only way to address a directory named "a " — the separator is
        // load-bearing and must survive in the display form.
        NormalizedPath p = Ok(@"C:\a \");
        Assert.Equal(@"c:\a ", p.Canonical);
        Assert.Equal(@"C:\a \", p.NormalizedDisplay);
        Assert.Equal(new[] { "a " }, p.Segments);
    }

    [Fact]
    public void TrailingSeparator_IsRemovedAndRecorded()
    {
        NormalizedPath p = Ok(@"C:\a\b\");
        Assert.Equal(@"c:\a\b", p.Canonical);
        Assert.Equal(@"C:\a\b", p.NormalizedDisplay);
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.TrailingSeparatorRemoved);
    }

    // ------------------------------------------------------------------ case

    [Fact]
    public void Canonical_IsInvariantLowerCase_DisplayKeepsOriginal()
    {
        NormalizedPath p = Ok(@"C:\Program Files\Vendor");
        Assert.Equal(@"c:\program files\vendor", p.Canonical);
        Assert.Equal(@"C:\Program Files\Vendor", p.NormalizedDisplay);
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.CaseFolded);
    }

    [Fact]
    public void SameLocation_DifferentCase_SameCanonical()
    {
        Assert.Equal(Ok(@"C:\WINDOWS\SYSTEM32").Canonical, Ok(@"c:\windows\system32").Canonical);
    }

    // ------------------------------------------------------------------ structure of the result

    [Fact]
    public void Segments_AreCanonicalAndOrdered()
    {
        NormalizedPath p = Ok(@"C:\Alpha\Beta\Gamma.txt");
        Assert.Equal(new[] { "alpha", "beta", "gamma.txt" }, p.Segments);
        Assert.Equal(@"c:\", p.Root);
    }

    [Fact]
    public void Original_IsAlwaysPreservedVerbatim()
    {
        const string ugly = @"C:/a//b\.\c\..\d.";
        Assert.Equal(ugly, PathNormalizer.Normalize(ugly).Original);
    }

    [Fact]
    public void AlreadyCanonicalPath_HasNoTransformations()
    {
        NormalizedPath p = Ok(@"c:\windows\system32");
        Assert.Empty(p.Transformations);
        Assert.Equal(@"c:\windows\system32", p.Canonical);
        Assert.Equal(@"c:\windows\system32", p.NormalizedDisplay);
    }

    [Fact]
    public void EveryTransformation_IsRecordedInPipelineOrder()
    {
        NormalizedPath p = Ok(@"C:/a//b/./c/../D.");
        // The audit trail is the guard's log line; the kinds must appear in rewrite order.
        var kinds = p.Transformations.Select(t => t.Kind).ToArray();
        Assert.Equal(new[]
        {
            TransformationKind.SeparatorsNormalized,
            TransformationKind.DuplicateSeparatorsCollapsed,
            TransformationKind.DotSegmentsRemoved,
            TransformationKind.ParentSegmentsResolved,
            TransformationKind.TrailingDotsAndSpacesTrimmed,
            TransformationKind.CaseFolded,
        }, kinds);
        Assert.Equal(@"c:\a\b\d", p.Canonical);
    }

    [Fact]
    public void TransformationSnapshots_ChainBeforeToAfter()
    {
        // Snapshots are taken at stage boundaries (see PathTransformation): each record either
        // continues from the previous record's After, or shares the previous record's boundary
        // exactly (several rewrite kinds inside one stage). Anything else would make the audit
        // log an incoherent story.
        NormalizedPath p = Ok(@"C:/a//./b/..\c\");
        var chain = p.Transformations.Where(t => t.Kind != TransformationKind.EnvironmentVariableExpanded).ToList();
        Assert.True(chain.Count >= 4);
        for (int i = 1; i < chain.Count; i++)
        {
            bool continues = chain[i].Before == chain[i - 1].After;
            bool sharesBoundary = chain[i].Before == chain[i - 1].Before && chain[i].After == chain[i - 1].After;
            Assert.True(continues || sharesBoundary,
                $"audit break between {chain[i - 1]} and {chain[i]}");
        }
    }

    [Fact]
    public void Normalization_NeverReturnsIncomplete()
    {
        // Normalisation is total: Ok or Failed. Incomplete belongs to comparison only.
        string[] inputs = { @"C:\x", "rel", @"\\s\sh", @"\\?\C:\x", "..", @"C:\bad<", "" };
        foreach (string input in inputs)
            Assert.NotEqual(OperationState.Incomplete, PathNormalizer.Normalize(input).State);
    }
}
