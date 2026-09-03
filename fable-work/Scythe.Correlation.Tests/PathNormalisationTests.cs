using Scythe.Correlation.Tests.Fixtures;
using Xunit;

namespace Scythe.Correlation.Tests;

/// <summary>File-system path normalisation: reference/07.1_linking.md, first row of the kinds table.</summary>
public sealed class PathNormalisationTests
{
    private static string Path(string text) => CorrelationFixtures.Unwrap(EntityNormaliser.NormalisePath(text)).Value;

    [Fact]
    public void ADriveLetterPathKeepsItsSpellingWithTheDriveUpperCased() =>
        Assert.Equal(@"C:\Windows\System32\cmd.exe", Path(@"c:\Windows\System32\cmd.exe"));

    [Fact]
    public void ForwardSlashesBecomeBackslashes() =>
        Assert.Equal(@"C:\Windows\System32\cmd.exe", Path("C:/Windows/System32/cmd.exe"));

    [Fact]
    public void RepeatedSeparatorsCollapse() =>
        Assert.Equal(@"C:\Temp\x.exe", Path(@"C:\\\\Temp\\\\x.exe"));

    [Fact]
    public void ATrailingSeparatorIsRemoved() =>
        Assert.Equal(@"C:\Temp", Path(@"C:\Temp\"));

    [Fact]
    public void TheDriveRootKeepsItsOneSeparator()
    {
        // 'C:' alone is drive-relative and refused; the root must therefore stay 'C:\' or the
        // library would emit a spelling it refuses to read back.
        Assert.Equal(@"C:\", Path(@"C:\"));
        Assert.Equal(@"C:\", Path(@"C:\\\"));
    }

    [Fact]
    public void DotSegmentsAreDropped() =>
        Assert.Equal(@"C:\a\b", Path(@"C:\a\.\b\."));

    [Fact]
    public void DotDotSegmentsPopTextually() =>
        Assert.Equal(@"C:\a\c", Path(@"C:\a\b\..\c"));

    [Fact]
    public void DotDotAboveTheRootIsClampedAtTheRoot()
    {
        Assert.Equal(@"C:\x", Path(@"C:\..\..\x"));
        Assert.Equal(@"C:\", Path(@"C:\a\..\.."));
    }

    [Fact]
    public void UncPathsAreAcceptedInBothSeparatorDirections()
    {
        Assert.Equal(@"\\server\share\dir\file.exe", Path(@"\\server\share\dir\file.exe"));
        Assert.Equal(@"\\server\share\dir\file.exe", Path("//server/share/dir/./file.exe"));
    }

    [Fact]
    public void UncDotDotIsClampedAtTheShare() =>
        Assert.Equal(@"\\server\share\x", Path(@"\\server\share\..\..\x"));

    [Fact]
    public void UncShareRootHasNoTrailingSeparator() =>
        Assert.Equal(@"\\server\share", Path(@"\\server\share\"));

    [Fact]
    public void TheExtendedLengthPrefixFoldsOntoThePlainForm()
    {
        Assert.Equal(@"C:\Users\x\a.exe", Path(@"\\?\C:\Users\x\a.exe"));
        Assert.Equal(@"\\srv\sh\a.exe", Path(@"\\?\UNC\srv\sh\a.exe"));
        Assert.Equal(@"\\srv\sh\a.exe", Path(@"\\?\unc\srv\sh\a.exe"));
    }

    [Fact]
    public void AnAlternateDataStreamColonIsAllowedInASegment() =>
        Assert.Equal(@"C:\a\f.txt:Zone.Identifier", Path(@"C:\a\f.txt:Zone.Identifier"));

    [Fact]
    public void SurroundingWhitespaceIsTrimmed() =>
        Assert.Equal(@"C:\a", Path("  C:\\a \t"));

    [Fact]
    public void CaseAndSeparatorSpellingsCompareSame()
    {
        Assert.Equal(EntityComparison.Same, EntityNormaliser.Compare(EntityKind.Path, @"C:\Windows\System32\cmd.exe", "c:/WINDOWS/system32/CMD.EXE"));
        Assert.Equal(EntityComparison.Same, EntityNormaliser.Compare(EntityKind.Path, @"\\SERVER\Share\x", @"//server/share/X"));
    }

    [Fact]
    public void ADirectoryAndAFileNamedWithItsNamePlusASuffixAreDifferent()
    {
        // The second half of the normalisation rule: two different things must not compare equal.
        Assert.Equal(EntityComparison.Different, EntityNormaliser.Compare(EntityKind.Path, @"C:\Temp\tool", @"C:\Temp\tool.exe"));
        Assert.Equal(EntityComparison.Different, EntityNormaliser.Compare(EntityKind.Path, @"C:\Temp\tool", @"C:\Temp\tool2"));
        // ...while a trailing separator is only a spelling of the same location.
        Assert.Equal(EntityComparison.Same, EntityNormaliser.Compare(EntityKind.Path, @"C:\Temp\tool", @"C:\Temp\tool\"));
    }

    [Fact]
    public void AMappedDriveAndItsUncSpellingAreDifferentEntities()
    {
        // Open question 6: without a live machine nothing can prove X:\ is \\server\share, and
        // the record carries no mapping. The library must not pretend.
        Assert.Equal(EntityComparison.Different, EntityNormaliser.Compare(EntityKind.Path, @"X:\dir\file", @"\\server\share\dir\file"));
    }

    [Fact]
    public void TheKelvinSignIsNotALowerCaseK()
    {
        // Ordinal-ignore-case folds by upper-casing each unit: 'k' -> 'K' (U+004B) but U+212A is
        // already upper case and stays itself, so the two paths differ — as they do on NTFS.
        // Reverted form: compare with a.ToLower() == b.ToLower() (or ToLowerInvariant), whose
        // full case mapping takes U+212A to 'k' and merges the two. That is the culture-sensitive
        // fold the brief forbids, made visible without depending on the host locale.
        Assert.Equal(EntityComparison.Different, EntityNormaliser.Compare(EntityKind.Path, "C:\\\u212Aey.txt", @"C:\key.txt"));
        Assert.Equal(EntityComparison.Same, EntityNormaliser.Compare(EntityKind.Path, @"C:\Key.txt", @"C:\key.txt"));
    }

    [Fact]
    public void TheKelvinSignNegativeControl_ALowerCaseFoldWouldMergeThem()
    {
        // Proves the test above is not inert: the forbidden fold really does equate them.
        Assert.Equal("k", "\u212A".ToLowerInvariant());
        Assert.True(string.Equals("\u212Aey", "key".ToLowerInvariant(), StringComparison.Ordinal) == false);
        Assert.Equal("\u212Aey".ToLowerInvariant(), "key".ToLowerInvariant());
    }

    [Theory]
    [InlineData(null, "null")]
    [InlineData("", "empty")]
    [InlineData("   ", "empty")]
    [InlineData(@"foo\bar.exe", "not an absolute")]
    [InlineData(@".\foo", "not an absolute")]
    [InlineData("C:", "drive-relative")]
    [InlineData("C:foo", "drive-relative")]
    [InlineData(@"\\", "no server")]
    [InlineData(@"\\server", "names a server but no share")]
    [InlineData(@"\\server\", "names a server but no share")]
    [InlineData(@"\\.\PhysicalDrive0", "device-namespace")]
    [InlineData(@"\??\C:\x", "object-manager")]
    [InlineData(@"C:\a<b", "'<'")]
    [InlineData(@"C:\Temp\*.exe", "'*'")]
    [InlineData("C:\\a\u0001b", "U+0001")]
    [InlineData(@"\\ser|ver\share", "'|'")]
    [InlineData(@"\\server\sh""are\x", "'\"'")]
    public void MalformedPathsAreFailedWithTheReasonNamed(string? text, string reasonFragment)
    {
        var result = EntityNormaliser.NormalisePath(text);
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Null(result.Value);
        Assert.Contains(reasonFragment, result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailedPathCarriesThePositionOfTheOffendingSegment()
    {
        var result = EntityNormaliser.NormalisePath(@"C:\good\ba|d");
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Equal(8, result.Position);
    }

    [Fact]
    public void APathAboveTheLengthCeilingIsFailedNotTruncated()
    {
        var result = EntityNormaliser.NormalisePath(@"C:\" + new string('a', EntityNormaliser.MaxEntityTextLength));
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Contains("ceiling", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void APathExactlyAtTheLengthCeilingIsAccepted()
    {
        var text = @"C:\" + new string('a', EntityNormaliser.MaxEntityTextLength - 3);
        Assert.True(EntityNormaliser.NormalisePath(text).IsOk);
    }

    [Fact]
    public void CompareIsNotComparableWhenEitherSideDoesNotNormalise()
    {
        Assert.Equal(EntityComparison.NotComparable, EntityNormaliser.Compare(EntityKind.Path, @"C:\a", "relative"));
        Assert.Equal(EntityComparison.NotComparable, EntityNormaliser.Compare(EntityKind.Path, null, @"C:\a"));
    }
}
