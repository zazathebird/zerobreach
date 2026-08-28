using Scythe.Rules;
using Scythe.Rules.Sigma;
using Xunit;
using static Scythe.Rules.Tests.Sigma.SigmaTestHelpers;

namespace Scythe.Rules.Tests.Sigma;

/// <summary>
/// Compile-time failure behaviour: malformed input fails loudly with line/column and
/// never produces a rule object — a silently empty rule is indistinguishable from a
/// passing scan, which is the failure mode this product cannot have.
/// </summary>
public sealed class SigmaCompileTests
{
    private const string Preamble = "title: T\nlogsource:\n  product: windows\n";

    // ---- YAML-level failures ----------------------------------------------------------

    [Fact]
    public void UnterminatedQuote_FailsWithPosition()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 'oops\n  condition: sel");
        Assert.Contains("unterminated", d.Message, StringComparison.Ordinal);
        Assert.Equal(6, d.Line);
        Assert.Equal(8, d.Column);
    }

    [Fact]
    public void TabIndentation_IsRejected()
    {
        var d = MustFail("title: T\n\tlogsource: x");
        Assert.Contains("tab", d.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, d.Line);
    }

    [Fact]
    public void DuplicateMappingKey_IsRejected_NotLastWins()
    {
        // Last-wins would silently discard half the rule.
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1\n    F: 2\n  condition: sel");
        Assert.Contains("duplicate mapping key 'F'", d.Message, StringComparison.Ordinal);
        Assert.Equal(7, d.Line);
    }

    [Fact]
    public void UnquotedLeadingStar_IsRejectedAsYamlAlias_WithGuidance()
    {
        // '*foo' is a YAML alias; a Sigma wildcard value must be quoted. Misreading it
        // silently would corrupt the pattern.
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: *wild*\n  condition: sel");
        Assert.Contains("alias", d.Message, StringComparison.Ordinal);
        Assert.Contains("quote", d.Message, StringComparison.Ordinal);
        Assert.Equal(6, d.Line);
        Assert.Equal(8, d.Column);
    }

    [Fact]
    public void MultipleYamlDocuments_AreRejected()
    {
        var d = MustFail("title: A\n---\ntitle: B");
        Assert.Contains("multiple YAML documents", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EmptySource_Fails()
    {
        var d = MustFail("");
        Assert.Contains("no content", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ScalarRoot_IsNotARule()
    {
        var d = MustFail("just a string");
        Assert.Contains("must be a YAML mapping", d.Message, StringComparison.Ordinal);
    }

    // ---- structural failures ----------------------------------------------------------

    [Fact]
    public void MissingTitle_Fails()
    {
        var d = MustFail("logsource:\n  product: windows\ndetection:\n  sel:\n    F: 1\n  condition: sel");
        Assert.Contains("'title'", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingLogsource_Fails()
    {
        var d = MustFail("title: T\ndetection:\n  sel:\n    F: 1\n  condition: sel");
        Assert.Contains("'logsource'", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingDetection_Fails()
    {
        var d = MustFail("title: T\nlogsource:\n  product: windows");
        Assert.Contains("'detection'", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingCondition_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1");
        Assert.Contains("condition", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DetectionWithOnlyCondition_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  condition: sel");
        Assert.Contains("no selections", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EmptySelectionList_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel: []\n  condition: sel");
        Assert.Contains("empty list", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EmptyValueList_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: []\n  condition: sel");
        Assert.Contains("empty value list", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MixedMapAndScalarList_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    - F: 1\n    - 'keyword'\n  condition: sel");
        Assert.Contains("mixes mappings and plain values", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NullKeyword_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    - null\n  condition: sel");
        Assert.Contains("null cannot be used as a keyword", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReservedSelectionName_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  not:\n    F: 1\n  condition: not");
        Assert.Contains("reserved", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DigitLeadingSelectionName_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  1sel:\n    F: 1\n  condition: 1sel");
        Assert.Contains("must not start with a digit", d.Message, StringComparison.Ordinal);
    }

    // ---- modifier failures ------------------------------------------------------------

    [Fact]
    public void UnsupportedModifier_FailsAtCompileTime_NamingItAndTheSupportedSet()
    {
        // The task brief's open question, answered as recommended: compile-time refusal.
        var d = MustFail(Preamble + "detection:\n  sel:\n    F|utf16: 'x'\n  condition: sel");
        Assert.Contains("unsupported value modifier 'utf16'", d.Message, StringComparison.Ordinal);
        Assert.Contains("windash", d.Message, StringComparison.Ordinal); // supported set is listed
        Assert.Equal(6, d.Line);
    }

    [Fact]
    public void ConflictingAnchorModifiers_Fail()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F|contains|startswith: 'x'\n  condition: sel");
        Assert.Contains("conflicting anchor modifier", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReCombinedWithContains_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F|re|contains: 'x'\n  condition: sel");
        Assert.Contains("'re' cannot be combined", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CidrCombinedWithContains_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F|cidr|contains: '10.0.0.0/8'\n  condition: sel");
        Assert.Contains("'cidr' cannot be combined", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Base64AndBase64Offset_CannotCombine()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F|base64|base64offset: 'x'\n  condition: sel");
        Assert.Contains("cannot be combined", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void InvalidRegex_FailsWithPosition()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F|re: '[unclosed'\n  condition: sel");
        Assert.Contains("invalid regex", d.Message, StringComparison.Ordinal);
        Assert.Equal(6, d.Line);
    }

    [Fact]
    public void OverlongRegex_IsRejected()
    {
        string huge = new string('a', SigmaCompiler.MaxRegexLength + 1);
        var d = MustFail(Preamble + $"detection:\n  sel:\n    F|re: '{huge}'\n  condition: sel");
        Assert.Contains("exceeds", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WildcardWithBase64_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F|base64|contains: 'cmd*'\n  condition: sel");
        Assert.Contains("wildcards cannot be used with base64", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NullWithModifiers_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F|contains: null\n  condition: sel");
        Assert.Contains("cannot be applied to null", d.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("'not-cidr'")]
    [InlineData("'10.0.0.0'")]      // no prefix
    [InlineData("'10.0.0.0/33'")]   // v4 prefix out of range
    [InlineData("'2001:db8::/129'")]
    [InlineData("'999.0.0.0/8'")]
    public void InvalidCidrValues_Fail(string value)
    {
        var d = MustFail(Preamble + $"detection:\n  sel:\n    F|cidr: {value}\n  condition: sel");
        Assert.True(d.Message.Contains("not CIDR notation", StringComparison.Ordinal)
            || d.Message.Contains("not a valid", StringComparison.Ordinal),
            $"unexpected message: {d.Message}");
    }

    // ---- condition failures -----------------------------------------------------------

    [Fact]
    public void UnknownSelectionReference_FailsWithPosition()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1\n  condition: sel and missing");
        Assert.Contains("unknown selection 'missing'", d.Message, StringComparison.Ordinal);
        Assert.Equal(7, d.Line);
        // Column points inside the condition string at the offending token.
        Assert.Equal(14 + 8, d.Column);
    }

    [Fact]
    public void PatternMatchingNoSelection_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1\n  condition: 1 of nothing*");
        Assert.Contains("matches no selection name", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CountExceedingSelectionCount_IsStaticallyUnsatisfiable_AndFails()
    {
        // '3 of selection*' over two selections can never fire; a rule that silently
        // never matches is indistinguishable from a passing scan.
        var d = MustFail(Preamble +
            "detection:\n  selection1:\n    A: 1\n  selection2:\n    B: 2\n  condition: 3 of selection*");
        Assert.Contains("requires 3 selections but only 2 match", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DanglingOperator_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1\n  condition: sel and");
        Assert.Contains("condition ends", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnbalancedParenthesis_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1\n  condition: (sel");
        Assert.Contains("condition ends", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TrailingGarbageInCondition_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1\n  condition: sel sel");
        Assert.Contains("unexpected 'sel' after the end", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnexpectedCharacterInCondition_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1\n  condition: sel && sel");
        Assert.Contains("unexpected character '&'", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnrecognisedAggregationFunction_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1\n  condition: sel | frobnicate() > 5");
        Assert.Contains("unrecognised aggregation function 'frobnicate'", d.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EmptyAggregation_Fails()
    {
        var d = MustFail(Preamble + "detection:\n  sel:\n    F: 1\n  condition: sel |");
        Assert.Contains("empty aggregation", d.Message, StringComparison.Ordinal);
    }

    // ---- result-shape guarantees ------------------------------------------------------

    [Fact]
    public void FailedCompile_NeverCarriesARuleObject()
    {
        var result = SigmaCompiler.Compile("title: [broken", "broken.yml");
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Null(result.Rule);
        Assert.NotNull(result.Reason);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal("broken.yml", diagnostic.Source);
        // The rendered reason carries source and position for the technician.
        Assert.Contains("broken.yml", result.Reason, StringComparison.Ordinal);
        Assert.Contains("line", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void CompileIsDeterministic()
    {
        const string yaml = Preamble + "detection:\n  sel:\n    F|contains: 'x'\n  condition: sel";
        var first = SigmaCompiler.Compile(yaml);
        var second = SigmaCompiler.Compile(yaml);
        Assert.Equal(first.State, second.State);
        Assert.Equal(first.Rule!.Title, second.Rule!.Title);
        Assert.Equal(first.Rule.SelectionNames, second.Rule.SelectionNames);
    }
}
