namespace Scythe.Intel.Tests;

using Xunit;
using Scythe.Intel;

/// <summary>Per-type validation rules, each shown accepting and rejecting with a reason.</summary>
public class ValidatorTests
{
    private static void AssertValid(IndicatorType type, string value, string? expectedNormalized = null)
    {
        Assert.True(IndicatorValidator.TryValidate(type, value, out var normalized, out var reason),
            $"expected valid, got: {reason}");
        if (expectedNormalized is not null)
            Assert.Equal(expectedNormalized, normalized);
    }

    private static string AssertInvalid(IndicatorType type, string value)
    {
        Assert.False(IndicatorValidator.TryValidate(type, value, out _, out var reason));
        Assert.False(string.IsNullOrWhiteSpace(reason));
        return reason!;
    }

    // --- hashes ---

    [Fact]
    public void Hashes_RightLengthHex_Accepted_AndLowercased()
    {
        AssertValid(IndicatorType.Sha256, TestData.Sha256A.ToUpperInvariant(), TestData.Sha256A);
        AssertValid(IndicatorType.Sha1, TestData.Sha1A, TestData.Sha1A);
        AssertValid(IndicatorType.Md5, TestData.Md5A, TestData.Md5A);
    }

    [Fact]
    public void Hash_WrongLength_RejectedWithLengthInReason()
    {
        var reason = AssertInvalid(IndicatorType.Sha256, TestData.Sha1A); // 40 chars, not 64
        Assert.Contains("64", reason);
        Assert.Contains("40", reason);
    }

    [Fact]
    public void Hash_NonHex_Rejected()
    {
        var reason = AssertInvalid(IndicatorType.Md5, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        Assert.Contains("hex", reason, StringComparison.OrdinalIgnoreCase);
    }

    // --- IPs ---

    [Theory]
    [InlineData("1.2.3.4")]
    [InlineData("255.255.255.255")]
    [InlineData("0.0.0.0")]
    public void Ipv4_Valid_Accepted(string value) => AssertValid(IndicatorType.Ipv4, value);

    [Theory]
    [InlineData("1.2.3")]           // shorthand
    [InlineData("1.2.3.4.5")]
    [InlineData("1.2.3.256")]       // octet range
    [InlineData("1.2.3.010")]       // leading zero: octal/decimal ambiguity
    [InlineData("1.2.3.x")]
    public void Ipv4_Invalid_Rejected(string value) => AssertInvalid(IndicatorType.Ipv4, value);

    [Fact]
    public void Ipv6_Valid_Accepted_InCompressedForm()
        => AssertValid(IndicatorType.Ipv6, "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1");

    [Fact]
    public void Ipv6_DottedQuad_Rejected()
    {
        // IPAddress.TryParse would happily read "1.2.3.4"; the family check must refuse it.
        AssertInvalid(IndicatorType.Ipv6, "1.2.3.4");
    }

    // --- domains ---

    [Fact]
    public void Domain_Valid_Accepted_LowercasedAndRootDotStripped()
        => AssertValid(IndicatorType.Domain, "EVIL.Example.COM.", "evil.example.com");

    [Fact]
    public void Domain_ServiceUnderscoreLabel_Accepted()
        => AssertValid(IndicatorType.Domain, "_dmarc.example.com");

    [Theory]
    [InlineData("com")]              // bare TLD is not an indicator
    [InlineData("evil..com")]        // empty label
    [InlineData("-evil.com")]        // leading hyphen
    [InlineData("evil.c")]           // one-char TLD
    [InlineData("evil.123")]         // all-digit TLD: malformed IP, not a domain
    [InlineData("ev il.com")]        // invalid char
    public void Domain_Invalid_Rejected(string value) => AssertInvalid(IndicatorType.Domain, value);

    [Fact]
    public void Domain_LabelOver63Chars_Rejected()
        => AssertInvalid(IndicatorType.Domain, new string('a', 64) + ".com");

    // --- URLs ---

    [Fact]
    public void Url_Valid_Accepted_SchemeAndHostLowercased()
        => AssertValid(IndicatorType.Url, "HTTP://EVIL.example/Path", "http://evil.example/Path");

    [Fact]
    public void Url_Unparseable_Rejected()
        => AssertInvalid(IndicatorType.Url, "http://");

    [Fact]
    public void Url_SchemeOutsideAllowlist_RejectedWithSchemeNamed()
    {
        var reason = AssertInvalid(IndicatorType.Url, "javascript:alert(1)");
        Assert.Contains("javascript", reason);
    }

    // --- filenames and paths ---

    [Fact]
    public void Filename_Bare_Accepted() => AssertValid(IndicatorType.Filename, "evil.exe");

    [Theory]
    [InlineData(@"dir\evil.exe")]
    [InlineData("dir/evil.exe")]
    [InlineData("evil.exe:ads")]
    [InlineData(".")]
    [InlineData("..")]
    public void Filename_Invalid_Rejected(string value) => AssertInvalid(IndicatorType.Filename, value);

    [Fact]
    public void FilePath_WithSeparator_Accepted()
        => AssertValid(IndicatorType.FilePath, @"C:\Users\Public\evil.exe");

    [Fact]
    public void FilePath_WithoutSeparator_Rejected()
        => AssertInvalid(IndicatorType.FilePath, "evil.exe");

    // --- registry keys ---

    [Theory]
    [InlineData(@"HKLM\Software\Bad")]
    [InlineData(@"HKEY_CURRENT_USER\Software\Bad")]
    [InlineData(@"hklm\Software\Bad")]
    public void RegistryKey_KnownHive_Accepted(string value) => AssertValid(IndicatorType.RegistryKey, value);

    [Fact]
    public void RegistryKey_UnknownHive_RejectedWithHivesInReason()
    {
        var reason = AssertInvalid(IndicatorType.RegistryKey, @"SOFTWARE\Bad");
        Assert.Contains("hive", reason, StringComparison.OrdinalIgnoreCase);
    }

    // --- mutexes and emails ---

    [Fact]
    public void Mutex_ControlChars_Rejected() => AssertInvalid(IndicatorType.Mutex, "bad\u0001mutex");

    [Fact]
    public void Email_Valid_Accepted_Lowercased()
        => AssertValid(IndicatorType.EmailAddress, "Bad.Actor@EVIL.example", "bad.actor@evil.example");

    [Theory]
    [InlineData("no-at-sign.example")]
    [InlineData("two@@evil.example")]
    [InlineData("@evil.example")]
    [InlineData("x@")]
    [InlineData("x@com")] // bare-TLD domain part
    public void Email_Invalid_Rejected(string value) => AssertInvalid(IndicatorType.EmailAddress, value);
}

/// <summary>Plain-text type inference: precedence order pinned, most specific first.</summary>
public class TypeInferenceTests
{
    private static IndicatorType Infer(string value)
    {
        Assert.True(IndicatorValidator.TryInfer(value, out var type, out var reason),
            $"expected inference to succeed, got: {reason}");
        return type;
    }

    [Fact]
    public void HexLengths_InferHashTypes()
    {
        Assert.Equal(IndicatorType.Sha256, Infer(TestData.Sha256A));
        Assert.Equal(IndicatorType.Sha1, Infer(TestData.Sha1A));
        Assert.Equal(IndicatorType.Md5, Infer(TestData.Md5A));
    }

    [Fact]
    public void SchemeSeparator_InfersUrl() => Assert.Equal(IndicatorType.Url, Infer("http://evil.example/x"));

    [Fact]
    public void HivePrefix_InfersRegistryKey_BeforePathRule()
    {
        // Contains backslashes too — hive precedence must beat the FilePath rule.
        Assert.Equal(IndicatorType.RegistryKey, Infer(@"HKLM\Software\Bad"));
    }

    [Fact]
    public void DottedQuad_InfersIpv4() => Assert.Equal(IndicatorType.Ipv4, Infer("10.0.0.1"));

    [Fact]
    public void ColonHex_InfersIpv6() => Assert.Equal(IndicatorType.Ipv6, Infer("2001:db8::1"));

    [Fact]
    public void AtSign_InfersEmail() => Assert.Equal(IndicatorType.EmailAddress, Infer("a@evil.example"));

    [Fact]
    public void Separators_InferFilePath() => Assert.Equal(IndicatorType.FilePath, Infer(@"C:\bad\evil.exe"));

    [Fact]
    public void BareDottedName_InfersDomain_EvenWhenItLooksLikeAFilename()
    {
        // Judgement call pinned deliberately: a bare "evil.exe" in a plain-text feed is
        // indistinguishable from a domain, so it classifies as Domain. Typed formats must be
        // used for filenames. Documented in HANDOFF_D1.md.
        Assert.Equal(IndicatorType.Domain, Infer("evil.exe"));
    }

    [Fact]
    public void Unclassifiable_RejectedWithReason()
    {
        Assert.False(IndicatorValidator.TryInfer("%%%%", out _, out var reason));
        Assert.Contains("unclassifiable", reason);
    }
}
