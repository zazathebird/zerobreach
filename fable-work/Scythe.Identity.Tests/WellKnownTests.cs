using Scythe.Identity.Tests.Fixtures;
using Xunit;

namespace Scythe.Identity.Tests;

/// <summary>The static table and the pattern match over it.</summary>
public sealed class WellKnownTests
{
    public static IEnumerable<object[]> ExactRows() =>
        WellKnownIdentifiers.Entries.Where(e => e.Kind == WellKnownPatternKind.Exact).Select(e => new object[] { e.Pattern, e.Name });

    [Theory]
    [MemberData(nameof(ExactRows))]
    public void EveryExactRowRendersItsName(string pattern, string name)
    {
        var sid = Fx.Unwrap(IdentifierDecoder.Parse(pattern)).Identifier!;
        var described = WellKnownIdentifiers.Describe(sid);

        Assert.Equal(name, described.DisplayName);
        Assert.Equal(IdentifierScope.Fixed, described.Scope);
        Assert.Equal(pattern, described.Canonical);
        Assert.NotNull(described.Entry);
    }

    [Fact]
    public void TheTableHasEveryRowTheReferenceLists()
    {
        // §11.3's table, counted row by row with the "/" rows expanded: 39 values or patterns.
        Assert.Equal(39, WellKnownIdentifiers.Entries.Count);
    }

    [Theory]
    [InlineData("S-1-0-0", "The null identifier")]
    [InlineData("S-1-1-0", "All users")]
    [InlineData("S-1-5-18", "The local system account")]
    [InlineData("S-1-5-32-544", "The local administrators group")]
    [InlineData("S-1-5-32-580", "The remote management users group")]
    [InlineData("S-1-15-2-2", "All restricted application packages")]
    [InlineData("S-1-16-0", "Integrity level: untrusted")]
    [InlineData("S-1-16-20480", "Integrity level: protected")]
    public void SpotCheckedRowsCarryTheReferenceNames(string text, string name)
    {
        Assert.Equal(name, WellKnownIdentifiers.Describe(Fx.Unwrap(IdentifierDecoder.Parse(text)).Identifier!).DisplayName);
    }

    [Fact]
    public void ADomainRelativeIdentifierMatchesItsPattern()
    {
        // Revert: match exactly and a never-seen domain cannot be named.
        var described = WellKnownIdentifiers.Describe(Fx.Value(Fx.DomainAccount(512)));

        Assert.Equal("Domain administrators group", described.DisplayName);
        Assert.Equal(IdentifierScope.Domain, described.Scope);
        Assert.Equal("S-1-5-21-*-*-*-512", described.Entry!.Pattern);
        Assert.Equal(512u, described.Entry.RelativeIdentifier);
    }

    [Theory]
    [InlineData(500u, "The built-in administrator account", IdentifierScope.MachineOrDomain)]
    [InlineData(501u, "The built-in guest account", IdentifierScope.MachineOrDomain)]
    [InlineData(512u, "Domain administrators group", IdentifierScope.Domain)]
    [InlineData(513u, "Domain users group", IdentifierScope.Domain)]
    [InlineData(515u, "Domain computers group", IdentifierScope.Domain)]
    [InlineData(516u, "Domain controllers group", IdentifierScope.Domain)]
    [InlineData(519u, "Enterprise administrators group", IdentifierScope.Domain)]
    public void EachDomainRelativeRowCarriesItsScope(uint rid, string name, IdentifierScope scope)
    {
        var described = WellKnownIdentifiers.Describe(Fx.Value(Fx.DomainAccount(rid)));

        Assert.Equal(name, described.DisplayName);
        Assert.Equal(scope, described.Scope);
    }

    [Fact]
    public void ADomainTripleMustBeExactlyThree()
    {
        // Two and four in the middle are not domain identifiers; the pattern does not stretch.
        Assert.Equal(IdentifierScope.Unmatched, WellKnownIdentifiers.Describe(Fx.Value(Fx.Sid(21, 1, 2, 512))).Scope);
        Assert.Equal(IdentifierScope.Unmatched, WellKnownIdentifiers.Describe(Fx.Value(Fx.Sid(21, 1, 2, 3, 4, 512))).Scope);
    }

    [Fact]
    public void AnOrdinaryDomainAccountIsUnmatchedAndThatIsAComplete_Answer()
    {
        var sid = Fx.Value(Fx.DomainAccount(1105));
        var described = WellKnownIdentifiers.Describe(sid);

        Assert.Equal(IdentifierScope.Unmatched, described.Scope);
        Assert.Null(described.Entry);
        Assert.Equal("S-1-5-21-1000001-2000002-3000003-1105", described.DisplayName);
        Assert.Equal(described.Canonical, described.DisplayName);
    }

    [Fact]
    public void APerServiceAccountMatchesByPrefix()
    {
        var described = WellKnownIdentifiers.Describe(Fx.Value(Fx.Sid(80, 1, 2, 3, 4, 5)));

        Assert.Equal("A per-service account", described.DisplayName);
        Assert.Equal(IdentifierScope.FixedPrefix, described.Scope);
        Assert.Equal("A virtual-machine account", WellKnownIdentifiers.Describe(Fx.Value(Fx.Sid(83, 0, 9))).DisplayName);
    }

    [Fact]
    public void APrefixRowNeedsAtLeastOneSubAuthorityAfterThePrefix()
    {
        // Revert: match on prefix alone and the bare prefix is named as an account.
        Assert.Equal(IdentifierScope.Unmatched, WellKnownIdentifiers.Describe(Fx.Value(Fx.Sid(80))).Scope);
    }

    [Fact]
    public void AnExactRowDoesNotMatchALongerIdentifierWithTheSamePrefix()
    {
        Assert.Equal(IdentifierScope.Unmatched, WellKnownIdentifiers.Describe(Fx.Value(Fx.Sid(32, 544, 1))).Scope);
        Assert.Equal(IdentifierScope.Unmatched, WellKnownIdentifiers.Describe(Fx.Value(Fx.Sid(32))).Scope);
    }

    [Fact]
    public void ADifferentAuthorityWithTheSameSubAuthoritiesIsUnmatched()
    {
        Assert.Equal(IdentifierScope.Unmatched, WellKnownIdentifiers.Describe(Fx.Value(Fx.SidOf(1, 6, 18))).Scope);
    }

    [Fact]
    public void AnUnrecognisedRevisionIsNeverMatched()
    {
        var sid = IdentifierDecoder.Decode(Fx.SidOf(2, 5, 18)).Value!;

        Assert.Equal(IdentifierScope.Unmatched, WellKnownIdentifiers.Describe(sid).Scope);
    }

    [Fact]
    public void TableRowsAreMutuallyExclusive()
    {
        foreach (var entry in WellKnownIdentifiers.Entries)
        {
            var value = WellKnownIdentifiers.ValueOf(entry) ?? Instantiate(entry);
            var matches = WellKnownIdentifiers.Entries.Where(e => e.Matches(value)).ToList();
            Assert.Single(matches);
            Assert.Same(entry, matches[0]);
        }
    }

    [Fact]
    public void AbbreviationsAreUniqueAndMapBackToTheirRow()
    {
        var withAbbreviation = WellKnownIdentifiers.Entries.Where(e => e.Abbreviation is not null).ToList();

        Assert.Equal(withAbbreviation.Count, withAbbreviation.Select(e => e.Abbreviation).Distinct(StringComparer.Ordinal).Count());
        foreach (var entry in withAbbreviation)
        {
            Assert.Same(entry, WellKnownIdentifiers.FromAbbreviation(entry.Abbreviation!));
        }

        Assert.Null(WellKnownIdentifiers.FromAbbreviation("ZZ"));
    }

    [Fact]
    public void ValueOfIsNullForPatternRows()
    {
        var pattern = WellKnownIdentifiers.Entries.First(e => e.Kind != WellKnownPatternKind.Exact);

        Assert.Null(WellKnownIdentifiers.ValueOf(pattern));
    }

    private static SecurityIdentifier Instantiate(WellKnownEntry entry)
    {
        var subs = new List<uint>(entry.Leading);
        if (entry.Kind == WellKnownPatternKind.DomainTriple)
        {
            subs.AddRange(new uint[] { 11, 22, 33 });
            subs.AddRange(entry.Trailing);
        }
        else
        {
            subs.Add(99);
        }

        return new SecurityIdentifier(1, entry.Authority, subs);
    }
}
