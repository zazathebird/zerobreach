using Scythe.Identity.Tests.Fixtures;
using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>The binary identifier layout: ordinary, awkward and malformed.</summary>
public sealed class IdentifierBinaryTests
{
    [Fact]
    public void OneSubAuthorityDecodesToItsCanonicalString()
    {
        var sid = Fx.Value(Fx.Sid(18));

        Assert.Equal(1, sid.Revision);
        Assert.Equal(5UL, sid.Authority);
        Assert.Equal(new uint[] { 18 }, sid.SubAuthorities);
        Assert.Equal("S-1-5-18", sid.ToCanonicalString());
        Assert.Equal(12, sid.BinaryLength);
    }

    [Fact]
    public void ThreeSubAuthoritiesDecodeInOrder()
    {
        var sid = Fx.Value(Fx.Sid(80, 0xDEADBEEF, 7));

        Assert.Equal(new uint[] { 80, 0xDEADBEEF, 7 }, sid.SubAuthorities);
        Assert.Equal("S-1-5-80-3735928559-7", sid.ToCanonicalString());
        Assert.Equal(20, sid.BinaryLength);
    }

    [Fact]
    public void FiveSubAuthoritiesDecodeInOrder()
    {
        var sid = Fx.Value(Fx.DomainAccount(1105));

        Assert.Equal("S-1-5-21-1000001-2000002-3000003-1105", sid.ToCanonicalString());
        Assert.Equal(1105u, sid.RelativeIdentifier);
        Assert.Equal(28, sid.BinaryLength);
    }

    [Fact]
    public void SubAuthoritiesAreLittleEndian()
    {
        // 0x01020304 stored as 04 03 02 01. Revert: read big-endian and the value is 0x04030201.
        var bytes = new byte[] { 1, 1, 0, 0, 0, 0, 0, 5, 0x04, 0x03, 0x02, 0x01 };

        Assert.Equal(0x01020304u, Fx.Value(bytes).SubAuthorities[0]);
    }

    [Fact]
    public void TheAuthorityIsBigEndian_PinnedAboveThirtyTwoBits()
    {
        // Authority 0x0100_0000_0005 stored big-endian as 01 00 00 00 00 05. A little-endian
        // reading gives 0x0500_0000_0001 and renders "S-1-0x050000000001-7", so this fixture cannot
        // pass by accident. Revert: read the six bytes little-endian.
        var bytes = new byte[] { 1, 1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 7, 0, 0, 0 };
        var sid = Fx.Value(bytes);

        Assert.Equal(0x0100_0000_0005UL, sid.Authority);
        Assert.Equal("S-1-0x010000000005-7", sid.ToCanonicalString());
    }

    [Fact]
    public void TheAuthorityIsBigEndian_EvenForSmallValues()
    {
        // 5 stored as 00 00 00 00 00 05. Little-endian would read 0x0500_0000_0000, which is
        // exactly the "correct-looking on every ordinary value" failure §11.3 warns about, so the
        // small-value case is pinned too.
        var sid = Fx.Value(new byte[] { 1, 0, 0, 0, 0, 0, 0, 5 });

        Assert.Equal(5UL, sid.Authority);
        Assert.Equal("S-1-5", sid.ToCanonicalString());
    }

    [Fact]
    public void AnAuthorityAtExactlyThirtyTwoBitsRendersInDecimal()
    {
        Assert.Equal("S-1-4294967295", Fx.Value(Fx.SidOf(1, 0xFFFF_FFFF)).ToCanonicalString());
    }

    [Fact]
    public void AnAuthorityOnePastThirtyTwoBitsRendersAsTwelveHexDigits()
    {
        // Revert: render in decimal whenever it fits in 48 bits, and this reads "S-1-4294967296".
        Assert.Equal("S-1-0x000100000000", Fx.Value(Fx.SidOf(1, 0x1_0000_0000)).ToCanonicalString());
    }

    [Fact]
    public void TheLargestAuthorityRendersWithAllTwelveDigits()
    {
        Assert.Equal("S-1-0xFFFFFFFFFFFF-1", Fx.Value(Fx.SidOf(1, SecurityIdentifier.MaxAuthority, 1)).ToCanonicalString());
    }

    [Fact]
    public void ZeroSubAuthoritiesIsValid()
    {
        var sid = Fx.Value(Fx.SidOf(1, 5));

        Assert.Empty(sid.SubAuthorities);
        Assert.Null(sid.RelativeIdentifier);
        Assert.Equal(8, sid.BinaryLength);
    }

    [Fact]
    public void FifteenSubAuthoritiesIsTheMaximumAndIsValid()
    {
        var subs = Enumerable.Range(1, 15).Select(i => (uint)i).ToArray();
        var sid = Fx.Value(Fx.Sid(subs));

        Assert.Equal(subs, sid.SubAuthorities);
        Assert.Equal(68, sid.BinaryLength);
    }

    [Fact]
    public void AnUnrecognisedRevisionIsIncompleteAndCarriesThePartialValue()
    {
        // Revert: drop the revision check and this decodes Ok under a layout nobody has verified.
        var result = IdentifierDecoder.Decode(Fx.SidOf(2, 5, 18));

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.NotNull(result.Value);
        Assert.Equal("S-2-5-18", result.Value!.ToCanonicalString());
        Assert.False(result.Value.RevisionRecognised);
        Assert.Contains("revision 2", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void SurplusBytesAfterTheIdentifierAreIgnored()
    {
        var bytes = Fx.Sid(18).Concat(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }).ToArray();
        var sid = Fx.Value(bytes);

        Assert.Equal("S-1-5-18", sid.ToCanonicalString());
        Assert.Equal(12, sid.BinaryLength);
    }

    [Fact]
    public void ToBytesReproducesTheInput()
    {
        var input = Fx.SidOf(1, 0x0100_0000_0005, 21, 0xFFFF_FFFF, 0, 500);

        Assert.Equal(input, Fx.Value(input).ToBytes());
    }

    [Fact]
    public void ValueEqualityCoversRevisionAuthorityAndEverySubAuthority()
    {
        var a = Fx.Value(Fx.Sid(32, 544));
        Assert.Equal(a, Fx.Value(Fx.Sid(32, 544)));
        Assert.Equal(a.GetHashCode(), Fx.Value(Fx.Sid(32, 544)).GetHashCode());
        Assert.NotEqual(a, Fx.Value(Fx.Sid(32, 545)));
        Assert.NotEqual(a, Fx.Value(Fx.SidOf(1, 6, 32, 544)));
        Assert.NotEqual(a, Fx.Value(Fx.Sid(32)));
        Assert.NotEqual(a, IdentifierDecoder.Decode(Fx.SidOf(2, 5, 32, 544)).Value);
    }

    // ---- malformed ---------------------------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    public void ABufferShorterThanTheHeaderIsFailed(int length)
    {
        var result = IdentifierDecoder.Decode(new byte[length]);

        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Equal(0, result.Position);
        Assert.Contains("needs 8 bytes", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ASubAuthorityCountThatOverrunsTheBufferIsFailed()
    {
        // Count says 3, buffer holds 1. Revert: slice by count without checking, and this throws.
        var result = IdentifierDecoder.Decode(Fx.SidWithCount(3, 18));

        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Equal(1, result.Position);
        Assert.Contains("count 3 needs 20 bytes, buffer has 12", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ASubAuthorityCountAboveTheBoundIsFailedEvenWhenTheBufferIsLongEnough()
    {
        // Sixteen sub-authorities present, count 16: the bytes are all there, and the bound
        // still refuses. Revert: check only the buffer length and this decodes.
        var subs = Enumerable.Range(1, 16).Select(i => (uint)i).ToArray();
        var bytes = Fx.Sid(subs);

        var result = IdentifierDecoder.Decode(bytes);

        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Equal(1, result.Position);
        Assert.Contains("count 16 exceeds the bound of 15", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ACountOf255IsFailedOnTheBoundNotTheBuffer()
    {
        var result = IdentifierDecoder.Decode(Fx.SidWithCount(255, 18));

        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Contains("bound", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryTruncationOfAValidIdentifierIsFailedNotThrown()
    {
        var full = Fx.Sid(21, 1, 2, 3, 500);
        for (var length = 0; length < full.Length; length++)
        {
            var result = IdentifierDecoder.Decode(full.AsSpan(0, length));
            Assert.Equal(IdentityResultState.Failed, result.State);
        }
    }
}
