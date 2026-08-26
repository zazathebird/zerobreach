using ZeroBreach.Rules;
using ZeroBreach.Rules.Sigma;
using Xunit;
using static ZeroBreach.Rules.Tests.Sigma.SigmaTestHelpers;

namespace ZeroBreach.Rules.Tests.Sigma;

/// <summary>Condition-expression semantics: boolean operators, precedence, quantifiers,
/// condition lists, and determinism.</summary>
public sealed class SigmaConditionTests
{
    private static CompiledSigmaRule TwoSelections(string condition) => MustCompile(
        "title: T\nlogsource:\n  product: windows\ndetection:\n" +
        "  selection1:\n    A: 1\n" +
        "  selection2:\n    B: 2\n" +
        $"  condition: {condition}");

    [Fact]
    public void AndOrNot_Work()
    {
        var andRule = TwoSelections("selection1 and selection2");
        AssertHit(andRule, ("A", 1), ("B", 2));
        AssertMiss(andRule, ("A", 1), ("B", 3));

        var orRule = TwoSelections("selection1 or selection2");
        AssertHit(orRule, ("A", 1));
        AssertHit(orRule, ("B", 2));
        AssertMiss(orRule, ("A", 9), ("B", 9));

        var notRule = TwoSelections("selection1 and not selection2");
        AssertHit(notRule, ("A", 1), ("B", 3));
        AssertMiss(notRule, ("A", 1), ("B", 2));
    }

    [Fact]
    public void Precedence_NotBindsTighterThanAnd_AndTighterThanOr()
    {
        // a or b and not c  ==  a or (b and (not c))
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  a:\n    A: 1\n  b:\n    B: 2\n  c:\n    C: 3\n" +
            "  condition: a or b and not c");
        AssertHit(rule, ("A", 1), ("C", 3));            // a alone wins even though c holds
        AssertHit(rule, ("B", 2));                       // b and not c
        AssertMiss(rule, ("B", 2), ("C", 3));            // b but c blocks
        AssertMiss(rule, ("C", 3));
    }

    [Fact]
    public void Parentheses_OverridePrecedence()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  a:\n    A: 1\n  b:\n    B: 2\n  c:\n    C: 3\n" +
            "  condition: (a or b) and c");
        AssertHit(rule, ("A", 1), ("C", 3));
        AssertHit(rule, ("B", 2), ("C", 3));
        AssertMiss(rule, ("A", 1));
    }

    [Fact]
    public void OneOfPattern_MatchesWhenAnyNamedSelectionMatches()
    {
        var rule = TwoSelections("1 of selection*");
        AssertHit(rule, ("A", 1));
        AssertHit(rule, ("B", 2));
        AssertMiss(rule, ("A", 0), ("B", 0));
    }

    [Fact]
    public void CountOfPattern_RequiresThatManySelections()
    {
        var rule = TwoSelections("2 of selection*");
        AssertHit(rule, ("A", 1), ("B", 2));
        AssertMiss(rule, ("A", 1));
        AssertMiss(rule, ("B", 2));
    }

    [Fact]
    public void AllOfThem_RequiresEverySelection()
    {
        var rule = TwoSelections("all of them");
        AssertHit(rule, ("A", 1), ("B", 2));
        AssertMiss(rule, ("A", 1));
    }

    [Fact]
    public void AnyOfThem_MatchesWhenAnySelectionMatches()
    {
        var rule = TwoSelections("any of them");
        AssertHit(rule, ("A", 1));
        AssertMiss(rule, ("A", 0), ("B", 0));
    }

    [Fact]
    public void AllOfPattern_ScopesToMatchingNames()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  selection1:\n    A: 1\n  selection2:\n    B: 2\n  filter:\n    C: 3\n" +
            "  condition: all of selection* and not filter");
        AssertHit(rule, ("A", 1), ("B", 2));
        AssertMiss(rule, ("A", 1), ("B", 2), ("C", 3));
        AssertMiss(rule, ("A", 1));
    }

    [Fact]
    public void OfSingleName_QuantifiesOverThatSelectionAlone()
    {
        var rule = TwoSelections("1 of selection1");
        AssertHit(rule, ("A", 1));
        AssertMiss(rule, ("B", 2));
    }

    [Fact]
    public void ConditionList_IsOrOfItsEntries()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  selection1:\n    A: 1\n  selection2:\n    B: 2\n" +
            "  condition:\n    - selection1\n    - selection2");
        AssertHit(rule, ("A", 1));
        AssertHit(rule, ("B", 2));
        AssertMiss(rule, ("A", 0), ("B", 0));
    }

    [Fact]
    public void SelectionNames_ResolveCaseSensitively()
    {
        // 'Selection' and 'selection' are different names; the condition must reference
        // the exact spelling (pinned to reference grammar behaviour).
        var diagnostic = MustFail(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  Selection:\n    A: 1\n  condition: selection");
        Assert.Contains("unknown selection 'selection'", diagnostic.Message, StringComparison.Ordinal);
    }

    // ---- determinism ------------------------------------------------------------------

    [Fact]
    public void SameRuleAndRecord_AlwaysProduceTheSameResult()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  sel:\n    CommandLine|contains: '-enc'\n    EventID: 4688\n" +
            "  filter:\n    User|startswith: 'SYSTEM'\n" +
            "  condition: sel and not filter");
        var record = Record(("EventID", 4688), ("CommandLine", "ps -enc AAA"), ("User", "bob"));
        var first = rule.Evaluate(record);
        for (int i = 0; i < 100; i++)
        {
            var again = rule.Evaluate(record);
            Assert.Equal(first.State, again.State);
            Assert.Equal(first.IsMatch, again.IsMatch);
            Assert.Equal(first.Reason, again.Reason);
        }
        Assert.True(first.IsMatch);
    }

    [Fact]
    public void RecordInsertionOrder_DoesNotChangeTheResult()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n" +
            "  sel:\n    A: 1\n    B: 2\n  condition: sel");
        var forward = new Dictionary<string, object?> { ["A"] = 1, ["B"] = 2 };
        var backward = new Dictionary<string, object?> { ["B"] = 2, ["A"] = 1 };
        Assert.Equal(rule.Evaluate(forward).IsMatch, rule.Evaluate(backward).IsMatch);
        Assert.True(rule.Evaluate(forward).IsMatch);
    }

    [Fact]
    public void CaseCollidingRecordKeys_ResolveDeterministically_RegardlessOfInsertionOrder()
    {
        // Two record keys that collide case-insensitively: the ordinal-smaller key wins,
        // independent of dictionary enumeration order.
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Field: 'kept'\n  condition: sel");
        var oneOrder = new Dictionary<string, object?> { ["Field"] = "kept", ["field"] = "shadowed" };
        var otherOrder = new Dictionary<string, object?> { ["field"] = "shadowed", ["Field"] = "kept" };
        var a = rule.Evaluate(oneOrder);
        var b = rule.Evaluate(otherOrder);
        Assert.Equal(a.IsMatch, b.IsMatch);
        Assert.True(a.IsMatch); // "Field" < "field" ordinally, so 'kept' is the visible value
    }

    [Fact]
    public void RuleMetadata_IsExposed()
    {
        var rule = MustCompile(
            "title: Suspicious Encoded Command\nid: 3bd3a2f2-0001-4a4b-b0ee-6a0023456789\n" +
            "status: experimental\nlevel: high\ntags:\n  - attack.execution\n" +
            "logsource:\n  product: windows\n" +
            "detection:\n  sel:\n    A: 1\n  condition: sel\n" +
            "fields:\n  - CommandLine\n  - User");
        Assert.Equal("Suspicious Encoded Command", rule.Title);
        Assert.Equal("3bd3a2f2-0001-4a4b-b0ee-6a0023456789", rule.Id);
        Assert.Equal("high", rule.Level);
        Assert.Equal("experimental", rule.Status);
        Assert.Equal(["attack.execution"], rule.Tags);
        Assert.Equal(["CommandLine", "User"], rule.Fields);
        Assert.Equal(["sel"], rule.SelectionNames);
        Assert.False(rule.RequiresCorrelation);
        var result = Eval(rule, ("A", 1));
        Assert.Equal("Suspicious Encoded Command", result.RuleTitle);
        Assert.Equal("3bd3a2f2-0001-4a4b-b0ee-6a0023456789", result.RuleId);
    }
}
