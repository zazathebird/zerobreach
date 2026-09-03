using Scythe.Correlation.Tests.Fixtures;
using Xunit;

namespace Scythe.Correlation.Tests;

/// <summary>Registry path and process identifier normalisation: rows two and three of the kinds table.</summary>
public sealed class RegistryAndProcessNormalisationTests
{
    private static string Registry(string text) => CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseRegistryPath(text)).Value;

    [Theory]
    [InlineData(@"HKEY_LOCAL_MACHINE\Software\Foo", @"HKLM\Software\Foo")]
    [InlineData(@"hklm\Software\Foo", @"HKLM\Software\Foo")]
    [InlineData(@"HKLM:\Software\Foo", @"HKLM\Software\Foo")]
    [InlineData(@"HKEY_CURRENT_USER\Software", @"HKCU\Software")]
    [InlineData(@"HKEY_CLASSES_ROOT\.exe", @"HKCR\.exe")]
    [InlineData(@"HKEY_USERS\S-1-5-18", @"HKU\S-1-5-18")]
    [InlineData(@"HKEY_CURRENT_CONFIG\System", @"HKCC\System")]
    [InlineData("HKLM", "HKLM")]
    [InlineData(@"HKLM\", "HKLM")]
    public void HiveSpellingsFoldToTheAbbreviation(string text, string expected) =>
        Assert.Equal(expected, Registry(text));

    [Fact]
    public void ShortAndLongHiveFormsCompareSame() =>
        Assert.Equal(EntityComparison.Same, EntityNormaliser.Compare(EntityKind.RegistryPath,
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"hklm\Software\microsoft\windows\currentversion\run"));

    [Fact]
    public void AForwardSlashIsPartOfAKeyNameNotASeparator() =>
        Assert.Equal(@"HKCR\MIME\Database\Content Type\application/json", Registry(@"HKCR\MIME\Database\Content Type\application/json"));

    [Fact]
    public void OneTrailingSeparatorIsRemovedFromAKey() =>
        Assert.Equal(@"HKLM\Software\Foo", Registry(@"HKLM\Software\Foo\"));

    [Fact]
    public void ADoubledSeparatorIntroducesTheValueName()
    {
        Assert.Equal(@"HKLM\Software\Foo\\Updater", Registry(@"HKLM\Software\Foo\\Updater"));
        Assert.Equal(EntityComparison.Same, EntityNormaliser.Compare(EntityKind.RegistryPath,
            @"HKEY_LOCAL_MACHINE\Software\Foo\\updater", @"HKLM\Software\Foo\\UPDATER"));
    }

    [Fact]
    public void AnEmptyValueNameIsTheDefaultValueAndIsNotTheKey()
    {
        // Awkward but valid: 'key\\' is the key's default value. It must neither throw nor
        // collapse into the key, which is a different entity.
        Assert.Equal(@"HKLM\Software\Foo\\", Registry(@"HKLM\Software\Foo\\"));
        Assert.Equal(EntityComparison.Different, EntityNormaliser.Compare(EntityKind.RegistryPath, @"HKLM\Software\Foo\\", @"HKLM\Software\Foo"));
        Assert.Equal(EntityComparison.Same, EntityNormaliser.Compare(EntityKind.RegistryPath, @"HKLM\Software\Foo\\", @"HKEY_LOCAL_MACHINE\Software\Foo\\"));
    }

    [Fact]
    public void AValueNameMayItselfContainSeparators() =>
        Assert.Equal(@"HKLM\Software\Foo\\a\b", Registry(@"HKLM\Software\Foo\\a\b"));

    [Fact]
    public void AValueOnTheHiveRootIsAccepted() =>
        Assert.Equal(@"HKLM\\x", Registry(@"HKLM\\x"));

    [Fact]
    public void TheTwoArgumentFormAgreesWithTheSingleStringForm()
    {
        var joined = CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseRegistryValue(@"HKEY_LOCAL_MACHINE\Software\Foo\", "Updater"));
        Assert.Equal(Registry(@"HKLM\Software\Foo\\Updater"), joined.Value);

        var defaultValue = CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseRegistryValue(@"HKLM\Software\Foo", ""));
        Assert.Equal(@"HKLM\Software\Foo\\", defaultValue.Value);

        var key = CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseRegistryValue(@"HKLM\Software\Foo", null));
        Assert.Equal(@"HKLM\Software\Foo", key.Value);
    }

    [Fact]
    public void TheTwoArgumentFormRefusesAKeyThatAlreadyCarriesAValue() =>
        Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseRegistryValue(@"HKLM\Foo\\a", "b").State);

    [Theory]
    [InlineData(null, "null")]
    [InlineData("", "empty")]
    [InlineData(@"Software\Foo", "not a recognised hive")]
    [InlineData(@"HKXX\Foo", "not a recognised hive")]
    [InlineData(@"C:\Windows", "not a recognised hive")]
    [InlineData("HKLM\\Foo\u0007", "U+0007")]
    [InlineData("HKLM\\Foo\\\\bar\u0001", "value name contains")]
    public void MalformedRegistryPathsAreFailedWithTheReasonNamed(string? text, string reasonFragment)
    {
        var result = EntityNormaliser.NormaliseRegistryPath(text);
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Contains(reasonFragment, result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ARegistryPathAboveTheLengthCeilingIsFailed()
    {
        var result = EntityNormaliser.NormaliseRegistryPath(@"HKLM\" + new string('k', EntityNormaliser.MaxEntityTextLength));
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Contains("ceiling", result.Reason, StringComparison.Ordinal);
    }

    // ---- process identifiers

    [Fact]
    public void APositiveProcessIdentifierNormalisesToItsDecimalDigits()
    {
        Assert.Equal("4412", CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseProcessId(4412)).Value);
        Assert.Equal("4412", CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseProcessId(" 4412 ")).Value);
        Assert.Equal("7", CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseProcessId("007")).Value);
    }

    [Fact]
    public void ProcessIdentifierZeroIsRefusedAsTheSentinel()
    {
        // Reverted form: accept zero. Then every check that could not name a process reports
        // PID 0, and the run fuses on it.
        var result = EntityNormaliser.NormaliseProcessId(0);
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Contains("sentinel", result.Reason, StringComparison.Ordinal);
        Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseProcessId("0").State);
    }

    [Fact]
    public void ANegativeProcessIdentifierIsRefused()
    {
        Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseProcessId(-5).State);
        Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseProcessId("-5").State);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("-")]
    [InlineData("12a")]
    [InlineData("4 412")]
    [InlineData("99999999999")]
    [InlineData("2147483648")]
    public void MalformedProcessIdentifierTextIsFailed(string? text) =>
        Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseProcessId(text).State);

    [Fact]
    public void TheLargestRepresentableIdentifierIsAccepted() =>
        Assert.Equal("2147483647", CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseProcessId("2147483647")).Value);
}
