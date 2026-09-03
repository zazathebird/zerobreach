using Scythe.Techniques.Tests.Fixtures;
using Xunit;

namespace Scythe.Techniques.Tests;

/// <summary>Ordinary and awkward-but-valid map files.</summary>
public sealed class MapLoadingTests
{
    [Fact]
    public void TheStandardMapLoadsWithEverySectionPresent()
    {
        var map = MapFixtures.Standard().LoadOk();

        Assert.Equal(6, map.Count);
        Assert.Equal(3, map.Rules.Count);
        Assert.True(map.TryGetEntry("T1059.001", out var entry));
        Assert.Equal("PowerShell", entry.Name);
        Assert.Equal(MapFixtures.Execution, entry.Category);
        Assert.Equal("https://reference.example/techniques/T1059/001", entry.Url);
    }

    [Fact]
    public void EntriesAreSortedOrdinallyWhateverTheFileOrder()
    {
        var map = new MapBuilder()
            .Entry("T1547")
            .Entry("T1053.005")
            .Entry("T1059")
            .Entry("T1053")
            .Entry("T0999")
            .LoadOk();

        // Ordinal is numeric here because the digit fields are zero-padded: T0999 < T1053.
        Assert.Equal(new[] { "T0999", "T1053", "T1053.005", "T1059", "T1547" }, map.Entries.Select(e => e.Identifier.Value));
    }

    [Fact]
    public void LookupIsExactAndCaseSensitive()
    {
        var map = MapFixtures.Standard().LoadOk();

        Assert.True(map.Contains("T1053"));
        Assert.False(map.Contains("t1053"));
        Assert.False(map.Contains(" T1053"));
        Assert.False(map.Contains("T1053 "));
        Assert.False(map.TryGetEntry("T1053.05", out _));
    }

    [Fact]
    public void ASingleEntryMapLoads()
    {
        var map = new MapBuilder().Entry("T1234", "Only", "Cat", "http://x.example/").LoadOk();

        Assert.Equal(1, map.Count);
        Assert.Empty(map.Rules);
    }

    [Fact]
    public void AnEmptyMapLoadsWithoutFailing()
    {
        var result = new MapBuilder().Load();

        Assert.True(result.IsOk);
        Assert.Equal(0, result.Value!.Count);
        Assert.Empty(result.Value.Rules);
    }

    [Fact]
    public void AMissingRulesSectionMeansNoRules()
    {
        var map = new MapBuilder().Entry("T1234").LoadOk();

        Assert.Empty(map.Rules);
    }

    [Fact]
    public void AnEmptyRulesArrayLoads()
    {
        var map = new MapBuilder().Entry("T1234").WithEmptyRules().LoadOk();

        Assert.Empty(map.Rules);
    }

    [Fact]
    public void RulesKeepFileOrderAndCarryTheirOrdinal()
    {
        var map = MapFixtures.Standard().LoadOk();

        Assert.Equal(new[] { 0, 1, 2 }, map.Rules.Select(r => r.Ordinal));
        Assert.Equal(new[] { "scheduled task", "powershell", "run key" }, map.Rules.Select(r => r.Keyword));
        Assert.Equal("T1547.001", map.Rules[2].Identifier.Value);
    }

    [Fact]
    public void AParentListedAfterItsSubTechniqueIsAccepted()
    {
        // Awkward but valid: the orphan check runs over the whole array, not entry by entry.
        var map = new MapBuilder().Entry("T1053.005").Entry("T1053").LoadOk();

        Assert.Equal(2, map.Count);
    }

    [Fact]
    public void TheStringAndByteOverloadsAgree()
    {
        var builder = MapFixtures.Standard();

        var fromString = TechniqueMapLoader.Load(builder.Json());
        var fromBytes = TechniqueMapLoader.Load(builder.Bytes());

        Assert.True(fromString.IsOk);
        Assert.Equal(MapFixtures.RenderMap(fromBytes.Value!), MapFixtures.RenderMap(fromString.Value!));
    }

    [Fact]
    public void AByteOrderMarkPrefixedMapLoads()
    {
        var bytes = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(MapFixtures.Standard().Bytes()).ToArray();

        var result = TechniqueMapLoader.Load(bytes);

        Assert.True(result.IsOk, result.Reason);
        Assert.Equal(6, result.Value!.Count);
    }

    [Fact]
    public void TheUrlIsKeptExactlyAsWrittenNotNormalised()
    {
        // Uri would lower-case the host and add a trailing slash; the curator's text is what a
        // report shows.
        var map = new MapBuilder().Entry("T1234", url: "HTTPS://Reference.Example/T1234?x=1#frag").LoadOk();

        Assert.Equal("HTTPS://Reference.Example/T1234?x=1#frag", map.Entries[0].Url);
    }

    [Fact]
    public void FieldsWithInnerWhitespaceAndUnicodeAreAccepted()
    {
        var map = new MapBuilder().Entry("T1234", "Naïve — name with  spaces", "Défense Évasion").LoadOk();

        Assert.Equal("Naïve — name with  spaces", map.Entries[0].Name);
        Assert.Equal("Défense Évasion", map.Entries[0].Category);
    }

    [Fact]
    public void ALongButBoundedUrlLoads()
    {
        var url = "https://reference.example/" + new string('a', 3000);

        var map = new MapBuilder().Entry("T1234", url: url).LoadOk();

        Assert.Equal(url, map.Entries[0].Url);
    }

    [Fact]
    public void AKeywordAtExactlyTheMinimumLengthLoads()
    {
        var map = new MapBuilder().Entry("T1234").Rule("wmic", "T1234").LoadOk();

        Assert.Equal(TechniqueMapLoader.MinimumKeywordLength, map.Rules[0].Keyword.Length);
    }

    [Fact]
    public void ASpecificRuleBeforeAGenericOneIsReachableAndLoads()
    {
        // Negative control for the unreachable-rule check: the earlier keyword is the longer
        // one, so the later, shorter rule still has descriptions of its own to match.
        var map = new MapBuilder().Entry("T1234").Entry("T2345")
            .Rule("scheduled task", "T1234")
            .Rule("schtasks", "T2345")
            .LoadOk();

        Assert.Equal(2, map.Rules.Count);
    }

    [Theory]
    [InlineData("T1234", false, "T1234")]
    [InlineData("T1234.001", true, "T1234")]
    [InlineData("T0001.999", true, "T0001")]
    public void IdentifiersParseWithTheirParent(string text, bool sub, string parent)
    {
        Assert.True(TechniqueIdentifier.TryParse(text, out var id, out _));
        Assert.Equal(text, id.Value);
        Assert.Equal(sub, id.IsSubTechnique);
        Assert.Equal(parent, id.ParentValue);
        Assert.Equal(text, id.ToString());
    }
}
