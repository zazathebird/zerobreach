using Scythe.Correlation.Tests.Fixtures;
using Xunit;

namespace Scythe.Correlation.Tests;

/// <summary>Host name and network peer normalisation: the last two rows of the kinds table.</summary>
public sealed class NetworkNormalisationTests
{
    private static string Host(string text) => CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseHostName(text)).Value;

    private static string Peer(string text) => CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseNetworkPeer(text)).Value;

    [Fact]
    public void AHostNameIsLowerCasedAndLosesItsTrailingDot()
    {
        Assert.Equal("host.example.com", Host("Host.Example.COM."));
        Assert.Equal("host.example.com", Host("HOST.EXAMPLE.COM"));
    }

    [Fact]
    public void ASingleLabelHostNameIsAccepted() =>
        Assert.Equal("workstation01", Host("WORKSTATION01"));

    [Fact]
    public void HostNameSpellingsCompareSame() =>
        Assert.Equal(EntityComparison.Same, EntityNormaliser.Compare(EntityKind.HostName, "c2.Evil.example.", "C2.EVIL.EXAMPLE"));

    [Fact]
    public void ASingleDotIsRefused()
    {
        var result = EntityNormaliser.NormaliseHostName(".");
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Contains("single dot", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, "null")]
    [InlineData("", "empty")]
    [InlineData("example..com", "empty label")]
    [InlineData("example.com..", "empty label")]
    [InlineData("-bad.example", "hyphen")]
    [InlineData("bad-.example", "hyphen")]
    [InlineData("under_score.example", "contains '_'")]
    [InlineData("b\u00FCcher.example", "IDNA")]
    [InlineData("10.0.0.1", "literal address")]
    [InlineData("2001:db8::1", "literal address")]
    public void MalformedHostNamesAreFailedWithTheReasonNamed(string? text, string reasonFragment)
    {
        var result = EntityNormaliser.NormaliseHostName(text);
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Contains(reasonFragment, result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ALabelLongerThanSixtyThreeCharactersIsRefused()
    {
        Assert.True(EntityNormaliser.NormaliseHostName(new string('a', 63) + ".example").IsOk);
        Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseHostName(new string('a', 64) + ".example").State);
    }

    [Fact]
    public void ANameLongerThanTwoHundredFiftyThreeCharactersIsRefused()
    {
        var label = new string('a', 60);
        var ok = string.Join('.', label, label, label, label, "com"); // 4*60 + 4 + 3 = 247
        Assert.True(EntityNormaliser.NormaliseHostName(ok).IsOk);
        var tooLong = string.Join('.', label, label, label, label, new string('b', 10)); // 254
        Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseHostName(tooLong).State);
    }

    // ---- network peers

    [Fact]
    public void AnIPv4AddressIsAcceptedAsWritten() =>
        Assert.Equal("10.0.0.5", Peer("10.0.0.5"));

    [Fact]
    public void AnIPv6AddressIsRenderedInCompressedLowerCase()
    {
        Assert.Equal("2001:db8::1", Peer("2001:0DB8:0000:0000:0000:0000:0000:0001"));
        Assert.Equal("2001:db8::1", Peer("[2001:DB8::1]"));
        Assert.Equal(EntityComparison.Same, EntityNormaliser.Compare(EntityKind.NetworkPeer, "2001:db8:0:0::1", "2001:DB8::1"));
    }

    [Fact]
    public void ALiteralAddressAndANameAreDifferentEntitiesEvenForOneMachine()
    {
        // Reference: the library has no resolver and must not act as though it does. The two
        // kinds are different, so an Entity of each never compares equal whatever the text.
        var peer = CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseNetworkPeer("127.0.0.1"));
        var host = CorrelationFixtures.Unwrap(EntityNormaliser.NormaliseHostName("localhost"));
        Assert.NotEqual(peer, host);
        Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseNetworkPeer("localhost").State);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("10.0.0.5:443")]
    [InlineData("256.1.1.1")]
    [InlineData("01.2.3.4")]
    [InlineData("1.2.3")]
    [InlineData("1.2.3.4.5")]
    [InlineData("example.com")]
    [InlineData("2001:db8::zz")]
    public void MalformedPeersAreFailed(string? text) =>
        Assert.Equal(CorrelationResultState.Failed, EntityNormaliser.NormaliseNetworkPeer(text).State);

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("0000:0000:0000:0000:0000:0000:0000:0000")]
    public void TheUnspecifiedAddressIsASentinelNotAPeer(string text)
    {
        // Reverted form: drop the sentinel check and return Ok. Then every finding whose peer
        // field was never filled shares one entity and the run fuses on "no address".
        var result = EntityNormaliser.NormaliseNetworkPeer(text);
        Assert.Equal(CorrelationResultState.Failed, result.State);
        Assert.Contains("sentinel", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ALeadingZeroOctetIsAmbiguousAndRefused()
    {
        var result = EntityNormaliser.NormaliseNetworkPeer("010.0.0.5");
        Assert.Equal(CorrelationResultState.Failed, result.State);
    }
}
