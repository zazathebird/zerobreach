using Scythe.Rules.Linting;
using Scythe.Rules.Linting.Json;
using Xunit;

namespace Scythe.Rules.Tests.Linting;

public class JsonSourceParserTests
{
    private static JsonSourceValue ParseOk(string text)
    {
        var result = JsonSourceParser.Parse(text);
        Assert.Equal(OperationState.Ok, result.State);
        return result.Root!;
    }

    private static JsonParseResult ParseFail(string text)
    {
        var result = JsonSourceParser.Parse(text);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Null(result.Root);
        return result;
    }

    [Fact]
    public void ObjectMembersCarryExactPositions()
    {
        // Layout is load-bearing: assertions below name exact lines and columns.
        const string text = "{\n  \"alpha\": [\"one\"],\n  \"beta\": 2\n}";
        var root = Assert.IsType<JsonSourceObject>(ParseOk(text));

        Assert.Equal(2, root.Properties.Count);
        var alpha = root.Properties[0];
        Assert.Equal("alpha", alpha.Name);
        Assert.Equal(new LintLocation(2, 3), alpha.NameLocation);

        var array = Assert.IsType<JsonSourceArray>(alpha.Value);
        Assert.Equal(new LintLocation(2, 12), array.Location);
        var one = Assert.IsType<JsonSourceString>(Assert.Single(array.Items));
        Assert.Equal("one", one.Value);
        Assert.Equal(new LintLocation(2, 13), one.Location);

        var beta = root.Properties[1];
        Assert.Equal(new LintLocation(3, 3), beta.NameLocation);
        Assert.Equal(2d, Assert.IsType<JsonSourceNumber>(beta.Value).Value);
    }

    [Fact]
    public void ScalarsParse()
    {
        var root = Assert.IsType<JsonSourceArray>(
            ParseOk("[true, false, null, -12.5e2, \"s\"]"));
        Assert.True(Assert.IsType<JsonSourceBoolean>(root.Items[0]).Value);
        Assert.False(Assert.IsType<JsonSourceBoolean>(root.Items[1]).Value);
        Assert.IsType<JsonSourceNull>(root.Items[2]);
        Assert.Equal(-1250d, Assert.IsType<JsonSourceNumber>(root.Items[3]).Value);
        Assert.Equal("s", Assert.IsType<JsonSourceString>(root.Items[4]).Value);
    }

    [Fact]
    public void StringEscapesDecode()
    {
        var s = Assert.IsType<JsonSourceString>(
            ParseOk("\"a\\n\\t\\\"\\\\\\/\\u0041\\b\\f\\r\""));
        Assert.Equal("a\n\t\"\\/A\b\f\r", s.Value);
    }

    [Fact]
    public void SurrogatePairEscapesRecombine()
    {
        var s = Assert.IsType<JsonSourceString>(ParseOk("\"\\uD83D\\uDE00\""));
        Assert.Equal("\U0001F600", s.Value);
    }

    [Fact]
    public void LineAndBlockCommentsAreSkippedAndPositionsSurviveThem()
    {
        const string text = "// header\n{ /* inline */ \"key\": [] }";
        var root = Assert.IsType<JsonSourceObject>(ParseOk(text));
        Assert.Equal(new LintLocation(2, 16), root.Properties[0].NameLocation);
    }

    [Fact]
    public void DuplicateKeysAreBothPreserved()
    {
        var root = Assert.IsType<JsonSourceObject>(ParseOk("{\"k\": 1, \"k\": 2}"));
        Assert.Equal(2, root.Properties.Count);
        Assert.Equal("k", root.Properties[0].Name);
        Assert.Equal("k", root.Properties[1].Name);
    }

    [Fact]
    public void UnterminatedBlockCommentFailsAtItsStart()
    {
        var fail = ParseFail("{} /* never closed");
        Assert.Contains("unterminated /*", fail.Message);
        Assert.Equal(new LintLocation(1, 4), fail.ErrorLocation);
    }

    [Theory]
    [InlineData("{\"a\": 1,}")]
    [InlineData("[1, 2,]")]
    public void TrailingCommasAreRejected(string text)
    {
        Assert.Contains("trailing comma", ParseFail(text).Message);
    }

    [Fact]
    public void SingleQuotedStringsAreRejectedWithGuidance()
    {
        Assert.Contains("double quotes", ParseFail("{'a': 1}").Message);
    }

    [Fact]
    public void UnterminatedStringFailsAtItsOpeningQuote()
    {
        var fail = ParseFail("{\n  \"key\": \"never closed\n}");
        Assert.Contains("unterminated string", fail.Message);
        Assert.Equal(new LintLocation(2, 10), fail.ErrorLocation);
    }

    [Fact]
    public void InvalidEscapeIsNamed()
    {
        Assert.Contains("invalid escape sequence '\\q'", ParseFail("\"a\\qb\"").Message);
    }

    [Fact]
    public void RawControlCharacterInStringIsRejected()
    {
        Assert.Contains("U+0001", ParseFail("\"a\u0001b\"").Message);
    }

    [Fact]
    public void ContentAfterTheRootIsRejected()
    {
        Assert.Contains("after the end", ParseFail("{} {}").Message);
    }

    [Fact]
    public void MissingColonAndMissingCommaFailLoudly()
    {
        Assert.Contains("expected ':'", ParseFail("{\"a\" 1}").Message);
        Assert.Contains("expected ','", ParseFail("[1 2]").Message);
    }

    [Fact]
    public void NestingBeyondTheCapIsRejectedNotOverflowed()
    {
        string deep = new string('[', 80) + new string(']', 80);
        Assert.Contains("nesting", ParseFail(deep).Message);
    }
}
