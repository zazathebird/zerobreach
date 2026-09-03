using Scythe.Techniques.Tests.Fixtures;
using Xunit;

namespace Scythe.Techniques.Tests;

/// <summary>
/// Every strict-validation failure the reference names. Each one is <c>Failed</c> and the
/// message names the entry, because "invalid identifier" in a 1,200-entry map is not actionable.
/// </summary>
public sealed class MapValidationTests
{
    private static TechniqueResult<TechniqueMap> FailedLoad(MapBuilder builder)
    {
        var result = builder.Load();
        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Null(result.Value);
        Assert.NotNull(result.Reason);
        return result;
    }

    [Theory]
    [InlineData("t1234")]        // case variation
    [InlineData("T123")]         // missing leading zero
    [InlineData("T12345")]
    [InlineData("T1234.1")]
    [InlineData("T1234.01")]
    [InlineData("T1234.0001")]
    [InlineData("T1234-001")]
    [InlineData("T1234:001")]
    [InlineData("1234")]
    [InlineData("T1234.")]
    [InlineData(" T1234")]
    [InlineData("T1234 ")]
    [InlineData("T1234\t")]
    [InlineData("TA234")]
    [InlineData("T1234.00a")]
    [InlineData("T1234.001.001")]
    [InlineData("T١٢٣٤")]        // Arabic-Indic digits: char.IsDigit says yes, the format says no
    [InlineData("T１２３４")]     // full-width digits
    [InlineData("")]
    public void AMalformedIdentifierIsFailedNamingTheEntry(string id)
    {
        var result = FailedLoad(new MapBuilder().Entry("T0001").Entry(id));

        Assert.Contains("entries[1]", result.Reason, StringComparison.Ordinal);
        Assert.Contains($"'{id}'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ALowerCaseIdentifierNamesTheCaseProblem()
    {
        var result = FailedLoad(new MapBuilder().Entry("t1234"));

        Assert.Contains("lower-case", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingLeadingZeroNamesTheShortfall()
    {
        var result = FailedLoad(new MapBuilder().Entry("T123"));

        Assert.Contains("missing leading zero", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void SurroundingWhitespaceIsNamedAsSuch()
    {
        var result = FailedLoad(new MapBuilder().Entry(" T1234"));

        Assert.Contains("surrounding whitespace", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ASubTechniqueWithoutItsParentIsFailedNamingBoth()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1059").Entry("T1053.005"));

        Assert.Contains("T1053.005", result.Reason, StringComparison.Ordinal);
        Assert.Contains("parent T1053 is absent", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADuplicateIdentifierIsFailedNamingBothPositions()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").Entry("T2345").Entry("T1234"));

        Assert.Contains("entries[2] (T1234)", result.Reason, StringComparison.Ordinal);
        Assert.Contains("duplicate of entries[0]", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADuplicateDifferingOnlyInCaseIsFailed()
    {
        // The lower-case form already fails the format check; either way the file is rejected
        // and the message points at the second entry.
        var result = FailedLoad(new MapBuilder().Entry("T1234").Entry("t1234"));

        Assert.Contains("entries[1]", result.Reason, StringComparison.Ordinal);
    }

    public static IEnumerable<object[]> FieldProblems()
    {
        foreach (var field in new[] { "name", "category", "url" })
        {
            yield return new object[] { field, null!, "is missing" };
            yield return new object[] { field, "", "is empty" };
            yield return new object[] { field, "   ", "whitespace only" };
            yield return new object[] { field, " padded", "surrounding whitespace" };
            yield return new object[] { field, "padded ", "surrounding whitespace" };
        }
    }

    [Theory]
    [MemberData(nameof(FieldProblems))]
    public void AMissingEmptyOrPaddedFieldIsFailedNamingEntryAndField(string field, string? value, string expected)
    {
        var fields = new Dictionary<string, string?>
        {
            ["id"] = "T1234",
            ["name"] = "Name",
            ["category"] = "Cat",
            ["url"] = "https://x.example/",
        };
        fields[field] = value;
        var json = "{" + string.Join(",", fields.Where(kv => kv.Value is not null).Select(kv => $"{MapBuilder.Q(kv.Key)}:{MapBuilder.Q(kv.Value!)}")) + "}";

        var result = FailedLoad(new MapBuilder().RawEntry(json));

        Assert.Contains("entries[0] (T1234)", result.Reason, StringComparison.Ordinal);
        Assert.Contains($"'{field}'", result.Reason, StringComparison.Ordinal);
        Assert.Contains(expected, result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not a url")]
    [InlineData("/techniques/T1234")]          // absolute file URI on Unix; not a reference URL
    [InlineData("C:\\techniques\\T1234.html")]
    [InlineData("ftp://reference.example/T1234")]
    [InlineData("mailto:curator@example")]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://")]
    [InlineData("reference.example/T1234")]
    [InlineData("http:/reference.example")]
    public void AMalformedOrNonHttpUrlIsFailedNamingTheEntry(string url)
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234", url: url));

        Assert.Contains("entries[0] (T1234)", result.Reason, StringComparison.Ordinal);
        Assert.Contains("'url'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownFieldOnAnEntryIsFailedNamingEntryAndField()
    {
        var result = FailedLoad(new MapBuilder().RawEntry(
            "{\"id\":\"T1234\",\"name\":\"N\",\"category\":\"C\",\"url\":\"https://x.example/\",\"platform\":\"Windows\"}"));

        Assert.Contains("entries[0] (T1234)", result.Reason, StringComparison.Ordinal);
        Assert.Contains("unknown field 'platform'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AFieldDifferingOnlyInCaseIsUnknown()
    {
        var result = FailedLoad(new MapBuilder().RawEntry(
            "{\"Id\":\"T1234\",\"name\":\"N\",\"category\":\"C\",\"url\":\"https://x.example/\"}"));

        Assert.Contains("unknown field 'Id'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownFieldAtTheRootIsFailed()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").RootField("version", "3"));

        Assert.Contains("root", result.Reason, StringComparison.Ordinal);
        Assert.Contains("unknown field 'version'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownFieldOnARuleIsFailedNamingTheRule()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").RawRule(
            "{\"keyword\":\"schtasks\",\"id\":\"T1234\",\"weight\":2}"));

        Assert.Contains("rules[0]", result.Reason, StringComparison.Ordinal);
        Assert.Contains("unknown field 'weight'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADuplicateJsonKeyInAnEntryIsFailed()
    {
        var result = FailedLoad(new MapBuilder().RawEntry(
            "{\"id\":\"T1234\",\"name\":\"N\",\"name\":\"M\",\"category\":\"C\",\"url\":\"https://x.example/\"}"));

        Assert.Contains("entries[0]", result.Reason, StringComparison.Ordinal);
        Assert.Contains("'name' appears twice", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADuplicateJsonKeyAtTheRootIsFailed()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").RootField("entries", "[]"));

        Assert.Contains("'entries' appears twice", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEntryThatIsNotAnObjectIsFailed()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").RawEntry("42"));

        Assert.Contains("entries[1]", result.Reason, StringComparison.Ordinal);
        Assert.Contains("number", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AFieldOfTheWrongJsonTypeIsFailed()
    {
        var result = FailedLoad(new MapBuilder().RawEntry(
            "{\"id\":1234,\"name\":\"N\",\"category\":\"C\",\"url\":\"https://x.example/\"}"));

        Assert.Contains("'id' is a JSON number", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ANullFieldIsFailedNotTreatedAsAbsent()
    {
        var result = FailedLoad(new MapBuilder().RawEntry(
            "{\"id\":\"T1234\",\"name\":null,\"category\":\"C\",\"url\":\"https://x.example/\"}"));

        Assert.Contains("'name' is a JSON null", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ARootThatIsNotAnObjectIsFailed()
    {
        var result = TechniqueMapLoader.Load("[]");

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Contains("root is a JSON array", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void EntriesThatIsNotAnArrayIsFailed()
    {
        var result = TechniqueMapLoader.Load("{\"entries\":{}}");

        Assert.Equal(TechniqueResultState.Failed, result.State);
        Assert.Contains("'entries' is a JSON object", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingEntriesIsFailed()
    {
        var result = FailedLoad(new MapBuilder().WithoutEntries());

        Assert.Contains("'entries' is missing", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void RulesThatIsNotAnArrayIsFailed()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").RootField("rules", "\"schtasks\""));

        Assert.Contains("'rules' is a JSON string", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ARuleWhoseIdentifierIsAbsentFromTheEntriesIsFailed()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").Rule("schtasks", "T2345"));

        Assert.Contains("rules[0] (T2345)", result.Reason, StringComparison.Ordinal);
        Assert.Contains("absent from the map's entries", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ARuleWithAMalformedIdentifierIsFailed()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").Rule("schtasks", "t1234"));

        Assert.Contains("rules[0]", result.Reason, StringComparison.Ordinal);
        Assert.Contains("'t1234'", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ARuleMissingItsKeywordOrIdentifierIsFailed()
    {
        var noKeyword = FailedLoad(new MapBuilder().Entry("T1234").RawRule("{\"id\":\"T1234\"}"));
        var noId = FailedLoad(new MapBuilder().Entry("T1234").RawRule("{\"keyword\":\"schtasks\"}"));

        Assert.Contains("'keyword' is missing", noKeyword.Reason, StringComparison.Ordinal);
        Assert.Contains("'id' is missing", noId.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AKeywordBelowTheMinimumLengthIsFailed()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").Rule("wmi", "T1234"));

        Assert.Contains("rules[0] (T1234)", result.Reason, StringComparison.Ordinal);
        Assert.Contains("at least 4", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void APaddedKeywordIsFailedNotTrimmed()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").Rule("schtasks ", "T1234"));

        Assert.Contains("'keyword' has surrounding whitespace", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("file")]
    [InlineData("process")]
    [InlineData("the system")]
    [InlineData("registry key")]
    [InlineData("WAS WRITTEN")]
    public void AKeywordThatMatchesAGenericCanaryIsFailedNamingTheCanary(string keyword)
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").Rule(keyword, "T1234"));

        Assert.Contains("rules[0] (T1234)", result.Reason, StringComparison.Ordinal);
        Assert.Contains("canary", result.Reason, StringComparison.Ordinal);
        Assert.Contains("\"", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheCanaryListIsReviewableAndTheStandardRulesPassIt()
    {
        // The standard fixture's rules load, so the canaries are not so broad that every
        // reasonable rule trips them. That is the negative control for the theory above.
        Assert.NotEmpty(TechniqueMapLoader.KeywordRuleCanaries);
        Assert.Equal(3, MapFixtures.Standard().LoadOk().Rules.Count);
    }

    [Fact]
    public void ARepeatedKeywordIsFailedAsUnreachable()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").Entry("T2345")
            .Rule("schtasks", "T1234")
            .Rule("SCHTASKS", "T2345"));

        Assert.Contains("rules[1] (T2345)", result.Reason, StringComparison.Ordinal);
        Assert.Contains("unreachable", result.Reason, StringComparison.Ordinal);
        Assert.Contains("rules[0] (T1234)", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ALaterKeywordContainingAnEarlierOneIsFailedAsUnreachable()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").Entry("T2345")
            .Rule("schtasks", "T1234")
            .Rule("schtasks /create", "T2345"));

        Assert.Contains("rules[1] (T2345)", result.Reason, StringComparison.Ordinal);
        Assert.Contains("unreachable", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("name")]
    [InlineData("category")]
    [InlineData("url")]
    public void AFieldOverTheLengthCeilingIsFailedNamingTheField(string field)
    {
        var huge = field == "url" ? "https://x.example/" + new string('a', 5000) : new string('a', 5000);
        var builder = field switch
        {
            "name" => new MapBuilder().Entry("T1234", name: huge),
            "category" => new MapBuilder().Entry("T1234", category: huge),
            _ => new MapBuilder().Entry("T1234", url: huge),
        };

        var result = FailedLoad(builder);

        Assert.Contains($"'{field}' is 50", result.Reason, StringComparison.Ordinal);
        Assert.Contains("ceiling is 4096", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOverlongKeywordIsFailed()
    {
        var result = FailedLoad(new MapBuilder().Entry("T1234").Rule(new string('k', 5000), "T1234"));

        Assert.Contains("'keyword' is 5000", result.Reason, StringComparison.Ordinal);
    }
}
