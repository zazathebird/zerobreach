using Scythe.Identity.Tests.Fixtures;
using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>The string form, both directions, and which inputs do not round-trip.</summary>
public sealed class IdentifierStringTests
{
    private static IdentifierParse ParseOk(string text) => Fx.Unwrap(IdentifierDecoder.Parse(text));

    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5")]
    [InlineData("S-1-0-0")]
    [InlineData("S-1-5-21-1000001-2000002-3000003-1105")]
    [InlineData("S-1-5-80-3735928559-7")]
    [InlineData("S-1-4294967295")]
    [InlineData("S-1-0x010000000005-7")]
    [InlineData("S-1-0xFFFFFFFFFFFF-1")]
    [InlineData("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15")]
    public void ACanonicalStringParsesAndRendersItselfBack(string text)
    {
        var parse = ParseOk(text);

        Assert.True(parse.WasCanonical);
        Assert.Equal(IdentifierStringForm.Canonical, parse.Form);
        Assert.Null(parse.Deviation);
        Assert.Equal(text, parse.Identifier!.ToCanonicalString());
    }

    [Fact]
    public void TheParsedValueMatchesTheBinaryDecodeOfTheSameIdentifier()
    {
        Assert.Equal(Fx.Value(Fx.DomainAccount(1105)), ParseOk("S-1-5-21-1000001-2000002-3000003-1105").Identifier);
        Assert.Equal(Fx.Value(Fx.SidOf(1, 0x0100_0000_0005, 7)), ParseOk("S-1-0x010000000005-7").Identifier);
    }

    [Fact]
    public void AHexAuthorityThatFitsInThirtyTwoBitsParsesAndReRendersInDecimal()
    {
        // Revert: treat any parse as canonical, and WasCanonical lies.
        var parse = ParseOk("S-1-0x000000000005-18");

        Assert.Equal(5UL, parse.Identifier!.Authority);
        Assert.Equal("S-1-5-18", parse.Identifier.ToCanonicalString());
        Assert.False(parse.WasCanonical);
        Assert.Equal(IdentifierStringForm.NonCanonical, parse.Form);
        Assert.Contains("hexadecimal but fits in 32 bits", parse.Deviation, StringComparison.Ordinal);
    }

    [Fact]
    public void ADecimalAuthorityAboveThirtyTwoBitsParsesAndReRendersInHex()
    {
        // The big-endian pinning value supplied as decimal: 0x010000000005 = 1099511627781.
        var parse = ParseOk("S-1-1099511627781-7");

        Assert.Equal(0x0100_0000_0005UL, parse.Identifier!.Authority);
        Assert.Equal("S-1-0x010000000005-7", parse.Identifier.ToCanonicalString());
        Assert.False(parse.WasCanonical);
        Assert.Contains("decimal but does not fit in 32 bits", parse.Deviation, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("S-1-0x10000000005-7", "digits")]
    [InlineData("S-1-0x01000000000a-7", "lower-case hexadecimal")]
    [InlineData("S-1-0X010000000005-7", "upper-case 'X'")]
    [InlineData("s-1-5-18", "lower-case 's'")]
    [InlineData("S-01-5-18", "leading zero in revision")]
    [InlineData("S-1-05-18", "leading zero in authority")]
    [InlineData("S-1-5-018", "leading zero in sub-authority 0")]
    public void ANonCanonicalSpellingParsesAndSaysWhatDeviated(string text, string deviation)
    {
        var parse = ParseOk(text);

        Assert.False(parse.WasCanonical);
        Assert.Equal(IdentifierStringForm.NonCanonical, parse.Form);
        Assert.Contains(deviation, parse.Deviation, StringComparison.Ordinal);
        // Re-parsing the canonical rendering is canonical: the deviation was spelling, not value.
        Assert.True(ParseOk(parse.Identifier!.ToCanonicalString()).WasCanonical);
    }

    [Fact]
    public void AZeroSubAuthorityIsNotALeadingZero()
    {
        Assert.True(ParseOk("S-1-5-0").WasCanonical);
    }

    [Fact]
    public void AnUnrecognisedRevisionIsIncompleteAndTheReRenderPreservesIt()
    {
        var result = IdentifierDecoder.Parse("S-2-5-18");

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.NotNull(result.Value);
        Assert.Equal("S-2-5-18", result.Value!.Identifier!.ToCanonicalString());
        Assert.Contains("revision 2", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AFixedWellKnownAbbreviationResolvesFully()
    {
        var parse = ParseOk("BA");

        Assert.Equal(IdentifierStringForm.WellKnownAbbreviation, parse.Form);
        Assert.Equal("S-1-5-32-544", parse.Identifier!.ToCanonicalString());
        Assert.Equal("BA", parse.Abbreviation);
        Assert.False(parse.WasCanonical);
        Assert.Equal(544u, parse.RelativeIdentifier);
    }

    [Fact]
    public void EveryFixedAbbreviationInTheTableResolvesToItsRow()
    {
        var count = 0;
        foreach (var entry in WellKnownIdentifiers.Entries.Where(e => e.Abbreviation is not null && e.Kind == WellKnownPatternKind.Exact))
        {
            var parse = ParseOk(entry.Abbreviation!);
            Assert.Equal(entry.Pattern, parse.Identifier!.ToCanonicalString());
            count++;
        }

        Assert.True(count >= 20, $"only {count} fixed abbreviations in the table");
    }

    [Fact]
    public void ADomainRelativeAbbreviationIsAPartialResultNotAGuess()
    {
        // Revert: resolve DA against a placeholder domain, and this decodes Ok with an invented value.
        var result = IdentifierDecoder.Parse("DA");

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.NotNull(result.Value);
        Assert.Equal(IdentifierStringForm.DomainRelativeAbbreviation, result.Value!.Form);
        Assert.Null(result.Value.Identifier);
        Assert.Equal(512u, result.Value.RelativeIdentifier);
        Assert.Equal("DA", result.Value.Abbreviation);
        Assert.Contains("domain prefix unavailable", result.Reason, StringComparison.Ordinal);
        Assert.Contains("S-1-5-21-*-*-*-512", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("LA", 500u)]
    [InlineData("LG", 501u)]
    [InlineData("DU", 513u)]
    [InlineData("DC", 515u)]
    [InlineData("DD", 516u)]
    [InlineData("EA", 519u)]
    public void EveryDomainRelativeAbbreviationKnowsItsRelativeIdentifier(string abbreviation, uint rid)
    {
        var result = IdentifierDecoder.Parse(abbreviation);

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Equal(rid, result.Value!.RelativeIdentifier);
        Assert.Null(result.Value.Identifier);
    }

    [Fact]
    public void AnAbbreviationTheTableDoesNotCarryIsIncompleteNotFailed()
    {
        // It might be a real abbreviation (DG, SA, PA…) the table does not have a row for, so this
        // is "unsupported", not "malformed".
        var result = IdentifierDecoder.Parse("ZZ");

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains("'ZZ'", result.Reason, StringComparison.Ordinal);
    }

    // ---- malformed ---------------------------------------------------------------------------

    [Theory]
    [InlineData("", 0)]
    [InlineData("S", 0)]
    [InlineData("X-1-5-18", 0)]
    [InlineData("ba", 0)]
    [InlineData("S1-5-18", 0)]
    [InlineData("S-", 2)]
    [InlineData("S-1", 2)]
    [InlineData("S-x-5-18", 2)]
    [InlineData("S-256-5-18", 2)]
    [InlineData("S-1--18", 4)]
    [InlineData("S-1-5-", 6)]
    [InlineData("S-1-5-18-", 9)]
    [InlineData("S-1-5-1a", 6)]
    [InlineData("S-1-5- 18", 6)]
    [InlineData(" S-1-5-18", 0)]
    [InlineData("S-1-0x-18", 4)]
    [InlineData("S-1-0x1000000000000-18", 4)]
    [InlineData("S-1-281474976710656-18", 4)]
    [InlineData("S-1-0xG-18", 4)]
    public void AMalformedStringIsFailedAtThePositionOfTheOffendingPart(string text, int position)
    {
        var result = IdentifierDecoder.Parse(text);

        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Equal(position, result.Position);
    }

    [Fact]
    public void ASubAuthorityAboveThirtyTwoBitsIsFailedNamingIt()
    {
        var result = IdentifierDecoder.Parse("S-1-5-21-4294967296-500");

        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Contains("sub-authority 1", result.Reason, StringComparison.Ordinal);
        Assert.Equal(9, result.Position);
    }

    [Fact]
    public void ASubAuthorityAtExactlyThirtyTwoBitsIsFine()
    {
        Assert.Equal(4294967295u, ParseOk("S-1-5-4294967295").Identifier!.SubAuthorities[0]);
    }

    [Fact]
    public void SixteenSubAuthoritiesIsFailedNamingTheCount()
    {
        var result = IdentifierDecoder.Parse("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16");

        Assert.Equal(IdentityResultState.Failed, result.State);
        Assert.Contains("count 16", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AStringPastTheByteBudgetIsIncompleteWithTheBudgetNamed()
    {
        var result = IdentifierDecoder.Parse("S-1-5-18", ScanBudget.Default with { MaxInputBytes = 4 });

        Assert.Equal(IdentityResultState.Incomplete, result.State);
        Assert.Contains("budget allows 4", result.Reason, StringComparison.Ordinal);
    }
}
