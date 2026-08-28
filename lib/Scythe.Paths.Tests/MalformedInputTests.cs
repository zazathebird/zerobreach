using System.Diagnostics;
using Xunit;

namespace Scythe.Paths.Tests;

/// <summary>
/// Malformed input fails loudly with a reason and never throws — a guard must never be crashed
/// by its input — plus the resource-bound canaries: the length ceiling is enforced, and a
/// maximum-size hostile input still completes promptly (the whole pipeline is a linear pass).
/// </summary>
public sealed class MalformedInputTests
{
    private static NormalizedPath Failed(string path)
    {
        NormalizedPath result = PathNormalizer.Normalize(path);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.NotNull(result.FailureReason);
        // No partial results on error: the failure exposes nothing that looks usable.
        Assert.Null(result.Canonical);
        Assert.Null(result.NormalizedDisplay);
        Assert.Null(result.Root);
        Assert.Empty(result.Segments);
        return result;
    }

    [Fact]
    public void EmptyPath_Fails()
    {
        Assert.Contains("empty", Failed("").FailureReason);
    }

    [Theory]
    [InlineData(@"C:\a<b")]
    [InlineData(@"C:\a>b")]
    [InlineData("C:\\a\"b")]
    [InlineData(@"C:\a|b")]
    [InlineData(@"C:\a*b")]
    [InlineData(@"C:\a?b")]
    public void IllegalCharacters_Fail_AndTheMessageNamesTheCharacter(string path)
    {
        NormalizedPath p = Failed(path);
        Assert.Contains("illegal character", p.FailureReason);
        Assert.Contains("U+", p.FailureReason);
    }

    [Fact]
    public void ControlCharacter_Fails()
    {
        Assert.Contains("U+0001", Failed("C:\\a\u0001b").FailureReason);
    }

    [Fact]
    public void WildcardsInVerbatimPath_StillFail()
    {
        // Real Windows would pass \\?\C:\a*b through to the file system; a guard has no
        // business accepting a wildcard as a concrete path. Fail-closed, pinned here.
        Assert.Contains("illegal character", Failed(@"\\?\C:\a*b").FailureReason);
    }

    [Theory]
    [InlineData(@"C:\dir:stream\file")]     // colon before the final component
    [InlineData(@"C:\dir:stream\")]         // stream syntax used as a directory
    public void ColonOutsideTheFinalComponent_Fails(string path)
    {
        Assert.Contains("colon", Failed(path).FailureReason);
    }

    [Theory]
    [InlineData(@"C:\file:")]         // empty stream name, no type
    [InlineData(@"C:\file::")]        // empty stream name and empty type
    [InlineData(@"C:\file:s:")]       // empty stream type
    [InlineData(@"C:\file:a:b:c")]    // too many colons
    [InlineData(@"C:\:stream")]       // stream on an empty component name
    public void MalformedStreamSuffixes_Fail(string path)
    {
        Failed(path);
    }

    [Theory]
    [InlineData(@"\\")]              // no server
    [InlineData(@"\\server")]        // no share
    [InlineData(@"\\server\")]       // still no share
    public void IncompleteUncRoots_Fail(string path)
    {
        Assert.Contains("UNC", Failed(path).FailureReason);
    }

    [Theory]
    [InlineData(@"\\?\")]
    [InlineData(@"\\.\")]
    public void BareDevicePrefixes_Fail(string path)
    {
        Assert.Contains("device", Failed(path).FailureReason);
    }

    [Fact]
    public void NonLetterDrive_Fails()
    {
        Assert.Contains("drive", Failed(@"1:\x").FailureReason);
    }

    [Fact]
    public void FailedResult_StillCarriesOriginalAndReason()
    {
        NormalizedPath p = PathNormalizer.Normalize(@"C:\a<b");
        Assert.Equal(@"C:\a<b", p.Original);
        Assert.Equal(OperationState.Failed, p.State);
    }

    // ------------------------------------------------------------------ resource-bound canaries

    [Fact]
    public void Canary_OverlongPath_IsRejectedNotProcessed()
    {
        // The explicit memory/work bound: one character past the ceiling fails.
        string over = @"C:\" + new string('a', PathLimits.MaxPathLength);
        NormalizedPath p = PathNormalizer.Normalize(over);
        Assert.Equal(OperationState.Failed, p.State);
        Assert.Contains(PathLimits.MaxPathLength.ToString(), p.FailureReason);
    }

    [Fact]
    public void PathAtExactlyTheCeiling_IsAccepted()
    {
        string exact = @"C:\" + new string('a', PathLimits.MaxPathLength - 3);
        Assert.Equal(PathLimits.MaxPathLength, exact.Length);
        Assert.Equal(OperationState.Ok, PathNormalizer.Normalize(exact).State);
    }

    [Fact]
    public void Canary_MaximumSizeHostileInput_CompletesPromptly()
    {
        // The known-pathological shape for naive resolvers: tens of thousands of alternating
        // "a\..\" segments, at the maximum accepted length. The linear pipeline must chew
        // through it comfortably; if this test slows down or hangs, the resource-safety
        // property has regressed. (Budget is generous to avoid CI flake: this is a hang
        // detector, not a benchmark.)
        var unit = @"a\..\";
        int repeats = (PathLimits.MaxPathLength - 4) / unit.Length;
        string hostile = @"C:\" + string.Concat(Enumerable.Repeat(unit, repeats)) + "x";
        Assert.True(hostile.Length <= PathLimits.MaxPathLength);

        var sw = Stopwatch.StartNew();
        NormalizedPath p = PathNormalizer.Normalize(hostile);
        sw.Stop();

        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\x", p.Canonical);
        Assert.True(sw.ElapsedMilliseconds < 2000,
            $"pathological input took {sw.ElapsedMilliseconds} ms — linear-pass guarantee has regressed");
    }

    [Fact]
    public void Canary_DeepTraversalPastRoot_IsClampedNotLooping()
    {
        string hostile = @"C:\" + string.Concat(Enumerable.Repeat(@"..\", 8000)) + "Windows";
        NormalizedPath p = PathNormalizer.Normalize(hostile);
        Assert.Equal(OperationState.Ok, p.State);
        Assert.Equal(@"c:\windows", p.Canonical);
        Assert.True(p.Flags.HasFlag(PathFlags.ParentTraversalClamped));
    }

    [Fact]
    public void NoInputEverThrows()
    {
        // Sweep of every malformed family: the guard's front door never throws.
        string[] hostile =
        {
            "", " ", ".", "..", ":", "::", ":::", "%", "%%", "%x%", @"\", @"\\", @"\\\", @"\\\\",
            @"\\?", @"\\.", @"\\?\", @"\\.\", @"\\?\UNC", @"\\?\UNC\", @"\\?\GLOBALROOT",
            "C:", @"C:\", "C", @"1:\x", @"C:\a<b", "C:\\a\u0000b", @"C:\f:", @"C:\f::", @"C:\:s",
            @"C:\con:con:con:con", new string('%', 200), new string(':', 200), new string('\\', 200),
            "\uFFFD\uFFFE", "\uD800",  // replacement char, lone surrogate
        };
        foreach (string input in hostile)
        {
            NormalizedPath p = PathNormalizer.Normalize(input); // must not throw
            Assert.True(p.State is OperationState.Ok or OperationState.Failed);
        }
    }
}
