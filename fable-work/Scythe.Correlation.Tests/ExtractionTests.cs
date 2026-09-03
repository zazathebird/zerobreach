using System.Diagnostics;
using Xunit;

namespace Scythe.Correlation.Tests;

/// <summary>Recognition of entities in free text, by shape.</summary>
public sealed class ExtractionTests
{
    private static IReadOnlyList<EntityMention> Extract(string text)
    {
        var result = EntityExtractor.Extract(text);
        Assert.Equal(CorrelationResultState.Ok, result.State);
        return result.Value!;
    }

    private static Entity Only(string text)
    {
        var mentions = Extract(text);
        Assert.Single(mentions);
        return mentions[0].Entity;
    }

    [Fact]
    public void ADriveLetterPathInProseIsRecognisedWhole()
    {
        var mention = Assert.Single(Extract(@"found C:\Windows\System32\cmd.exe running"));
        Assert.Equal(EntityKind.Path, mention.Entity.Kind);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", mention.Entity.Value);
        Assert.Equal(6, mention.Offset);
        Assert.Equal(27, mention.Length);
    }

    [Fact]
    public void AQuotedPathKeepsItsSpaces() =>
        Assert.Equal(@"C:\Program Files\Vendor\tool.exe", Only(@"launched ""C:\Program Files\Vendor\tool.exe"" at start").Value);

    [Fact]
    public void ASingleQuotedPathKeepsItsSpacesToo() =>
        Assert.Equal(@"C:\Program Files\tool.exe", Only(@"launched 'C:\Program Files\tool.exe' at start").Value);

    [Fact]
    public void AnUnquotedPathWithASpaceIsRecognisedOnlyUpToTheSpace()
    {
        // Documented limitation, pinned so a change to it is deliberate.
        Assert.Equal(@"C:\Program", Only(@"launched C:\Program Files\tool.exe").Value);
    }

    [Fact]
    public void SentencePunctuationAfterAPathIsNotPartOfIt()
    {
        Assert.Equal(@"C:\Temp\x.exe", Only(@"wrote to C:\Temp\x.exe.").Value);
        Assert.Equal(@"C:\Temp\x.exe", Only(@"wrote to C:\Temp\x.exe, then exited").Value);
        Assert.Equal(@"C:\Temp\x.exe", Only(@"wrote to (C:\Temp\x.exe)").Value);
        Assert.Equal(@"C:\Temp\x.exe", Only(@"path=C:\Temp\x.exe;").Value);
    }

    [Fact]
    public void ATrailingDotDotSegmentIsNotMistakenForPunctuation() =>
        Assert.Equal(@"C:\", Only(@"walked to C:\Temp\..").Value);

    [Fact]
    public void UncAndForwardSlashPathsAreRecognised()
    {
        Assert.Equal(@"\\srv\share\a.exe", Only(@"copied from \\srv\share\a.exe").Value);
        Assert.Equal(@"C:\a\b.exe", Only("copied from C:/a/b.exe").Value);
        Assert.Equal(@"\\srv\share\a.exe", Only("copied from //srv/share/a.exe").Value);
    }

    [Fact]
    public void ARelativePathIsNotAnEntity() =>
        Assert.Empty(Extract(@"relative bin\tool.exe and .\x and ..\y"));

    [Fact]
    public void ARegistryPathIsRecognisedInEitherHiveSpelling()
    {
        Assert.Equal(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            Only(@"Run key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run has an entry").Value);
        Assert.Equal(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\\Updater",
            Only(@"value HKLM\Software\Microsoft\Windows\CurrentVersion\Run\\Updater points elsewhere").Value);
    }

    [Fact]
    public void AWordStartingWithHkIsNotARegistryPath() =>
        Assert.Empty(Extract("the hkey was rotated; HKX\\Foo is nothing"));

    [Theory]
    [InlineData("process (PID 4412) opened the file", "4412")]
    [InlineData("pid=4412 opened it", "4412")]
    [InlineData("pid:4412 opened it", "4412")]
    [InlineData("pid#4412 opened it", "4412")]
    [InlineData("PID: 4412", "4412")]
    [InlineData("Process 4412 wrote", "4412")]
    [InlineData("process-id 4412 wrote", "4412")]
    public void AProcessIdentifierNeedsItsKeyword(string text, string expected)
    {
        var entity = Only(text);
        Assert.Equal(EntityKind.ProcessId, entity.Kind);
        Assert.Equal(expected, entity.Value);
    }

    [Fact]
    public void ABareNumberIsNotAProcessIdentifier() =>
        Assert.Empty(Extract("observed 4412 events in 17 seconds"));

    [Fact]
    public void ProcessKeywordFollowedByANonNumberIsNothing() =>
        Assert.Empty(Extract("process svchost started; pid unknown"));

    [Fact]
    public void ProcessIdentifierZeroInProseIsNotAnEntity() =>
        Assert.Empty(Extract("owner PID 0 and pid -3"));

    [Fact]
    public void AKeywordAndDigitsMentionSpansBoth()
    {
        var mention = Assert.Single(Extract("owner PID 4412."));
        Assert.Equal(6, mention.Offset);
        Assert.Equal(8, mention.Length);
    }

    [Fact]
    public void AThreeLabelHostNameIsRecognised()
    {
        var entity = Only("beacon to C2.Evil.Example. every hour");
        Assert.Equal(EntityKind.HostName, entity.Kind);
        Assert.Equal("c2.evil.example", entity.Value);
    }

    [Fact]
    public void ATwoLabelTokenIsAmbiguousWithAFileNameAndDeclined() =>
        Assert.Empty(Extract("ran setup.exe and contacted example.com"));

    [Fact]
    public void ATwoLabelHostInAUrlAuthorityIsRecognised()
    {
        Assert.Equal("evil.example", Only("fetched https://evil.example/payload.bin").Value);
        Assert.Equal("evil.example", Only("fetched https://user:pw@Evil.Example:8443/p?x=1").Value);
    }

    [Fact]
    public void AHostWithAPortLosesThePort() =>
        Assert.Equal("c2.evil.example", Only("connected to c2.evil.example:8443").Value);

    [Fact]
    public void AnIPv4PeerIsRecognisedWithOrWithoutAPort()
    {
        Assert.Equal("10.0.0.5", Only("connected to 10.0.0.5:443").Value);
        Assert.Equal("10.0.0.5", Only("connected to 10.0.0.5").Value);
        Assert.Equal(EntityKind.NetworkPeer, Only("connected to 10.0.0.5").Kind);
    }

    [Fact]
    public void ALeadingZeroOctetIsNeitherAPeerNorAHost() =>
        Assert.Empty(Extract("connected to 010.0.0.5"));

    [Fact]
    public void ABracketedIPv6PeerIsRecognised()
    {
        var entity = Only("peer [2001:DB8::1]:443 answered");
        Assert.Equal(EntityKind.NetworkPeer, entity.Kind);
        Assert.Equal("2001:db8::1", entity.Value);
    }

    [Fact]
    public void AUrlWithAnIPv6AuthorityIsAPeer() =>
        Assert.Equal("2001:db8::1", Only("fetched http://[2001:db8::1]/x").Value);

    [Fact]
    public void SeveralEntitiesInOneDescriptionAreAllReportedInOffsetOrder()
    {
        var mentions = Extract(@"HKLM\Software\Run\\U launches C:\Users\x\u.exe which beacons to c2.evil.example (PID 4412) at 10.0.0.5");
        Assert.Equal(5, mentions.Count);
        Assert.Equal(EntityKind.RegistryPath, mentions[0].Entity.Kind);
        Assert.Equal(EntityKind.Path, mentions[1].Entity.Kind);
        Assert.Equal(EntityKind.HostName, mentions[2].Entity.Kind);
        Assert.Equal(EntityKind.ProcessId, mentions[3].Entity.Kind);
        Assert.Equal(EntityKind.NetworkPeer, mentions[4].Entity.Kind);
        for (var i = 1; i < mentions.Count; i++) Assert.True(mentions[i].Offset > mentions[i - 1].Offset);
    }

    [Fact]
    public void EmptyAndNullTextYieldNothing()
    {
        Assert.Empty(Extract(""));
        Assert.Empty(Extract("   \n\t "));
        Assert.Empty(EntityExtractor.Extract(null).Value!);
    }

    [Fact]
    public void AnUnbalancedQuoteIsJustADelimiter() =>
        Assert.Equal(@"C:\a.exe", Only(@"he said ""C:\a.exe").Value);

    [Fact]
    public void AVeryLongPathShapedStringIsSkippedNotReturned()
    {
        var text = "saw " + @"C:\" + new string('a', 100_000) + " today";
        Assert.Empty(Extract(text));
    }

    [Fact]
    public void ThousandsOfPathShapedSubstringsTerminatePromptlyUnderTheDefaultBudget()
    {
        var text = string.Join(' ', Enumerable.Range(0, 3000).Select(i => $@"C:\a\b{i}.exe"));
        var stopwatch = Stopwatch.StartNew();
        var mentions = Extract(text);
        stopwatch.Stop();
        Assert.Equal(3000, mentions.Count);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5), $"took {stopwatch.Elapsed}");
    }

    [Fact]
    public void RepeatedSeparatorsInProseCollapse() =>
        Assert.Equal(@"C:\Temp\x.exe", Only(@"at C:\\\\Temp\\x.exe").Value);

    [Fact]
    public void AUncServerAloneIsNotAnEntity() =>
        Assert.Empty(Extract(@"share host \\fileserver was unreachable"));

    [Fact]
    public void TextContainingControlAndPathBreakingCharactersDoesNotThrow()
    {
        var text = "\u0000\u0001C:\\a\u0002.exe \"\"\"\" '' <>|,;()[]{}= HKLM\\\u0003 pid: pid:x pid:99999999999 :: [::] 1.2.3.4.5";
        var result = EntityExtractor.Extract(text);
        Assert.Equal(CorrelationResultState.Ok, result.State);
    }
}
