using System.Text;
using ZeroBreach.Rules;
using ZeroBreach.Rules.Yara;
using ZeroBreach.Rules.Yara.Evaluation;
using ZeroBreach.Rules.Yara.Matching;
using ZeroBreach.Rules.Yara.Parsing;
using Xunit;

namespace ZeroBreach.Rules.Tests.Yara;

public static class EvalHelper
{
    public static ScanResult Scan(string ruleSource, byte[] data, ScanBudget? budget = null, long? entrypoint = null)
    {
        var compiled = YaraCompiler.Compile([new YaraSource("test.yar", ruleSource)]);
        Assert.True(compiled.Rules is not null,
            "compile failed: " + string.Join("; ", compiled.Errors));
        return new YaraScanner().ScanBytes(compiled.Rules!, data, budget, entrypoint);
    }

    /// <summary>Asserts that a single-rule source fires (or not) against data. When a
    /// strings section is supplied, `and 0 of them` (always true) is appended so fixture
    /// strings unused by the condition under test do not trip the unreferenced-string
    /// rejection.</summary>
    public static void AssertFires(string condition, byte[] data, bool expected, string strings = "")
    {
        string src = strings.Length > 0
            ? $"rule t {{ strings: {strings} condition: ( {condition} ) and 0 of them }}"
            : $"rule t {{ condition: {condition} }}";
        var result = Scan(src, data);
        Assert.Empty(result.IncompleteRules);
        Assert.Equal(expected, result.Matches.Any(m => m.RuleName == "t"));
    }

    public static byte[] B(string s) => Encoding.ASCII.GetBytes(s);
}

public class OperatorEvaluationTests
{
    private static readonly byte[] Data = EvalHelper.B("abcdefgh");

    [Theory]
    // arithmetic (division is backslash)
    [InlineData("1 + 2 == 3", true)]
    [InlineData("5 - 7 == -2", true)]
    [InlineData("3 * 4 == 12", true)]
    [InlineData(@"10 \ 3 == 3", true)]
    [InlineData("10 % 3 == 1", true)]
    [InlineData("2MB == 2097152", true)]
    [InlineData("0x10 == 16", true)]
    [InlineData("0o17 == 15", true)]
    // comparison chain behaviour
    [InlineData("1 < 2", true)]
    [InlineData("2 <= 2", true)]
    [InlineData("3 > 4", false)]
    [InlineData("4 >= 5", false)]
    [InlineData("1 != 1", false)]
    // bitwise
    [InlineData("(0xF0 & 0x0F) == 0", true)]
    [InlineData("(0xF0 | 0x0F) == 0xFF", true)]
    [InlineData("(0xFF ^ 0x0F) == 0xF0", true)]
    [InlineData("(1 << 4) == 16", true)]
    [InlineData("(16 >> 4) == 1", true)]
    [InlineData("~0 == -1", true)]
    // boolean
    [InlineData("true and not false", true)]
    [InlineData("false or false", false)]
    [InlineData("not 1 == 2", true)]
    // string operators
    [InlineData(""" "hello" contains "ell" """, true)]
    [InlineData(""" "hello" icontains "ELL" """, true)]
    [InlineData(""" "hello" startswith "he" """, true)]
    [InlineData(""" "hello" istartswith "HE" """, true)]
    [InlineData(""" "hello" endswith "lo" """, true)]
    [InlineData(""" "hello" iendswith "LO" """, true)]
    [InlineData(""" "hello" iequals "HELLO" """, true)]
    [InlineData(""" "hello" matches /h.l+o/ """, true)]
    [InlineData(""" "hello" matches /^ell/ """, false)]
    // doubles
    [InlineData("1.5 + 1.5 == 3.0", true)]
    [InlineData("1 < 1.5", true)]
    public void OperatorProducesExpectedResult(string condition, bool expected) =>
        EvalHelper.AssertFires(condition, Data, expected);

    [Theory]
    // Division/modulo by zero and int overflow are undefined -> rule does not fire,
    // and its negation does not fire either.
    [InlineData(@"1 \ 0 == 0")]
    [InlineData("1 % 0 == 0")]
    [InlineData(@"not (1 \ 0 == 0)")]
    [InlineData("0x7FFFFFFFFFFFFFFF + 1 > 0")]
    [InlineData("1 << -1 == 0")]
    public void UndefinedArithmeticNeverFires(string condition) =>
        EvalHelper.AssertFires(condition, Data, false);

    [Fact]
    public void ShiftPastWordSizeIsZero() =>
        EvalHelper.AssertFires("(1 << 65) == 0 and (1024 >> 64) == 0", Data, true);
}

public class IntegerReadTests
{
    private static readonly byte[] Data = [0x4D, 0x5A, 0x90, 0x00, 0xFF, 0xFE, 0x80, 0x01];

    [Theory]
    [InlineData("uint16(0) == 0x5A4D", true)]     // little-endian
    [InlineData("uint16be(0) == 0x4D5A", true)]   // big-endian variant
    [InlineData("uint8(4) == 0xFF", true)]
    [InlineData("int8(4) == -1", true)]           // signed variant
    [InlineData("uint32(0) == 0x00905A4D", true)]
    [InlineData("uint32be(4) == 0xFFFE8001", true)]
    [InlineData("int16(4) == -257", true)]        // 0xFEFF as signed LE
    public void ReadsAreCorrect(string condition, bool expected) =>
        EvalHelper.AssertFires(condition, Data, expected);

    [Fact]
    public void ReadPastEndIsFalseNotException()
    {
        EvalHelper.AssertFires("uint32(6) == 0", Data, false);      // 2 bytes left, needs 4
        EvalHelper.AssertFires("uint8(100) == 0", Data, false);
        EvalHelper.AssertFires("uint8(-1) == 0", Data, false);
        // and the negation is equally false — undefined, not zero (pinned on reference)
        EvalHelper.AssertFires("not uint8(100) == 0", Data, false);
        EvalHelper.AssertFires("not defined uint8(100)", Data, true);
    }

    [Fact]
    public void FilesizeIsBufferLength() =>
        EvalHelper.AssertFires("filesize == 8", Data, true);

    [Fact]
    public void EntrypointIsUndefinedWithoutHostValueAndUsableWithIt()
    {
        var src = "rule t { condition: entrypoint == 5 }";
        var without = EvalHelper.Scan(src, Data);
        Assert.Empty(without.Matches);
        var with = EvalHelper.Scan(src, Data, entrypoint: 5);
        Assert.Single(with.Matches);
    }
}

public class StringQueryEvaluationTests
{
    // "ab" at offsets 0, 3, 6; overlapping pair at 10/11.
    private static readonly byte[] Data = EvalHelper.B("ab ab ab  aab");

    [Theory]
    [InlineData("$a", true)]
    [InlineData("$a at 0", true)]
    [InlineData("$a at 3", true)]
    [InlineData("$a at 1", false)]     // an offset test, not a prefix test
    [InlineData("$a in (2..4)", true)]
    [InlineData("$a in (1..2)", false)]
    [InlineData("@a == 0", true)]      // @a is @a[1]
    [InlineData("@a[2] == 3", true)]
    [InlineData("@a[9] == 0", false)]  // out of range: undefined, never an error
    [InlineData("!a[1] == 2", true)]
    [InlineData("!a[9] == 2", false)]
    [InlineData("@a[0] == 0", false)]  // 1-indexed: index 0 is undefined
    public void StringQueriesEvaluate(string condition, bool expected) =>
        EvalHelper.AssertFires(condition, Data, expected, """$a = "ab" """);

    [Fact]
    public void CountUsesNonOverlappingSemantics()
    {
        // 4 starting offsets (10 and 11 overlap), 4 non-overlapping? "aab": "ab" at 11 only.
        // Data offsets for "ab": 0, 3, 6, 11 -> all disjoint -> #a == 4.
        EvalHelper.AssertFires("#a == 4", Data, true, """$a = "ab" """);
        // Overlap case pinned explicitly (BLUEPRINT semantics, diverges from reference):
        EvalHelper.AssertFires("#a == 1", EvalHelper.B("aaa"), true, """$a = "aa" """);
        EvalHelper.AssertFires("#a == 2", EvalHelper.B("aaaa"), true, """$a = "aa" """);
    }

    [Fact]
    public void CountInRangeCountsOnlyThatRange() =>
        EvalHelper.AssertFires("#a in (0..5) == 2", Data, true, """$a = "ab" """);
}

public class OfAndForEvaluationTests
{
    private static readonly byte[] Data = EvalHelper.B("one two three");

    private const string Strings = """
        $a1 = "one"
        $a2 = "two"
        $b1 = "absent"
        """;

    [Theory]
    [InlineData("any of them", true)]
    [InlineData("all of them", false)]
    [InlineData("all of ($a*)", true)]
    [InlineData("2 of them", true)]
    [InlineData("3 of them", false)]
    [InlineData("2 of ($a1, $a2, $b1)", true)]
    [InlineData("none of ($b*)", true)]
    [InlineData("none of ($a*)", false)]
    [InlineData("0 of ($b*)", true)]
    // percent thresholds pinned against the reference: ceil(p*n/100)
    [InlineData("50% of them", true)]     // needs 2 of 3, have 2
    [InlineData("67% of them", false)]    // needs ceil(2.01)=3
    [InlineData("any of them in (0..6)", true)]
    [InlineData("any of them in (8..9)", false)]
    public void OfFormsEvaluate(string condition, bool expected) =>
        EvalHelper.AssertFires(condition, Data, expected, Strings);

    [Theory]
    [InlineData("for any of them : ( $ at 0 )", true)]
    [InlineData("for all of ($a*) : ( # == 1 )", true)]
    [InlineData("for any of them : ( ! > 100 )", false)]
    [InlineData("for all i in (1..2) : ( @a1[i] < 100 or @a2[i] < 100 )", false)] // @a1[2] undefined
    [InlineData("for all i in (1..1) : ( @a1[i] == 0 )", true)]
    [InlineData("for any i in (0,4,9) : ( uint8(i) == 0x74 )", true)] // 't' at 4
    [InlineData("for none i in (0..3) : ( uint8(i) == 0xFF )", true)]
    public void ForFormsEvaluate(string condition, bool expected) =>
        EvalHelper.AssertFires(condition, Data, expected, Strings);

    [Fact]
    public void NestedForLoopsEvaluate() =>
        EvalHelper.AssertFires(
            "for any i in (0..2) : ( for any j in (0..2) : ( uint8(i) == uint8(j + 4) ) )",
            EvalHelper.B("abcdadx"), true);

    [Fact]
    public void LoopIterationCapYieldsIncomplete()
    {
        // The evaluator-level budget canary: a loop over a huge range must be cut and
        // reported, never silently answered.
        var result = EvalHelper.Scan(
            "rule t { condition: for any i in (0..99999999) : ( uint8(i) == 0xFF ) }",
            EvalHelper.B("abc"));
        var inc = Assert.Single(result.IncompleteRules);
        Assert.Contains("cap", inc.Reason);
        Assert.Equal(OperationState.Incomplete, result.State);
    }

    [Fact]
    public void InvertedRangeIsIncompleteNotSilentlyFalse()
    {
        var result = EvalHelper.Scan("rule t { condition: for all i in (5..1) : ( true ) }", EvalHelper.B("x"));
        var inc = Assert.Single(result.IncompleteRules);
        Assert.Contains("lower bound", inc.Reason);
    }
}

public class RuleInteractionTests
{
    [Fact]
    public void PrivateRuleIsReferenceableButNeverReported()
    {
        var result = EvalHelper.Scan("""
            private rule helper { strings: $a = "magic" condition: $a }
            rule outer { condition: helper }
            """, EvalHelper.B("some magic here"));
        Assert.Single(result.Matches);
        Assert.Equal("outer", result.Matches[0].RuleName);
    }

    [Fact]
    public void RuleReferencesEvaluateInDependencyOrder()
    {
        var result = EvalHelper.Scan("""
            rule a { strings: $x = "one" condition: $x }
            rule b { condition: a and filesize > 0 }
            rule c { condition: b }
            """, EvalHelper.B("one"));
        Assert.Equal(["a", "b", "c"], result.Matches.Select(m => m.RuleName));
    }

    [Fact]
    public void GlobalRuleFailureSuppressesWholeFile()
    {
        var result = EvalHelper.Scan("""
            global rule gate { strings: $g = "required" condition: $g }
            rule hit { strings: $a = "present" condition: $a }
            """, EvalHelper.B("present but not the gate word"));
        // "hit" matched on its own, but the failed global suppresses it.
        Assert.Empty(result.Matches);
        Assert.Empty(result.IncompleteRules);
        Assert.Equal(OperationState.Ok, result.State);
    }

    [Fact]
    public void GlobalRulePassAllowsFileAndIsItselfReported()
    {
        var result = EvalHelper.Scan("""
            global rule gate { strings: $g = "present" condition: $g }
            rule hit { strings: $a = "present" condition: $a }
            """, EvalHelper.B("present"));
        Assert.Equal(["gate", "hit"], result.Matches.Select(m => m.RuleName));
    }

    [Fact]
    public void GlobalSuppressionIsScopedToItsSourceFile()
    {
        // Pinned decision (task brief open question): global is file-scoped, so a failing
        // global in file1 must not suppress file2's rules.
        var compiled = YaraCompiler.Compile([
            new YaraSource("file1.yar", """
                global rule gate { strings: $g = "missing!" condition: $g }
                rule one { strings: $a = "data" condition: $a }
                """),
            new YaraSource("file2.yar", """
                rule two { strings: $b = "data" condition: $b }
                """),
        ]);
        Assert.NotNull(compiled.Rules);
        var result = new YaraScanner().ScanBytes(compiled.Rules!, EvalHelper.B("data"));
        Assert.Equal(["two"], result.Matches.Select(m => m.RuleName));
    }

    [Fact]
    public void MatchCarriesTagsMetaAndStringOffsets()
    {
        var result = EvalHelper.Scan("""
            rule tagged : alpha beta {
                meta:
                    severity = 3
                    family = "testware"
                strings:
                    $a = "needle"
                    $p = "needle" private
                condition:
                    $a and $p
            }
            """, EvalHelper.B("a needle here"));
        var match = Assert.Single(result.Matches);
        Assert.Equal(["alpha", "beta"], match.Tags);
        Assert.Equal(2, match.Meta.Count);
        // Private strings never surface in the report.
        var s = Assert.Single(match.Strings);
        Assert.Equal("a", s.Identifier);
        Assert.Equal(new StringMatch(2, 6), Assert.Single(s.Matches));
    }
}

/// <summary>
/// The subtle A3 requirement: incompleteness must propagate honestly through boolean
/// logic. These tests drive the evaluator directly with a hand-built context so the
/// incomplete inputs are exact.
/// </summary>
public class IncompletenessPropagationTests
{
    private static readonly StringMatchSet CompleteEmpty = new()
    {
        Matches = [],
        Complete = true,
        NonOverlappingCount = 0,
    };

    private static readonly StringMatchSet IncompleteEmpty = new()
    {
        Matches = [],
        Complete = false,
        IncompleteReason = "pattern budget exhausted (synthetic)",
        NonOverlappingCount = 0,
    };

    private static readonly StringMatchSet CompleteHit = new()
    {
        Matches = [new StringMatch(0, 2)],
        Complete = true,
        NonOverlappingCount = 1,
    };

    private static RuleEvaluation Eval(string condition, params StringMatchSet[] stringResults)
    {
        var diags = new List<Diagnostic>();
        string strings = string.Join(" ", stringResults.Select((_, i) => $"$s{i} = \"pat{i}\""));
        var ast = YaraParser.ParseFile($"rule t {{ strings: {strings} condition: {condition} }}", "t.yar", diags);
        Assert.DoesNotContain(diags, d => d.Severity == DiagnosticSeverity.Error);
        var ctx = new EvaluationContext
        {
            Data = EvalHelper.B("pat0 pat1 pat2"),
            Strings = ast.Rules[0].Strings,
            MatchesForString = i => stringResults[i],
        };
        return ConditionEvaluator.Evaluate(ast.Rules[0].Condition, ctx);
    }

    [Fact]
    public void IncompleteStringAloneIsIncomplete()
    {
        var r = Eval("$s0", IncompleteEmpty);
        Assert.Equal(RuleTriState.Incomplete, r.State);
        Assert.Contains("budget", r.IncompleteReason);
    }

    [Fact]
    public void FalseAndIncompleteIsFalse() =>
        // false decides `and` regardless of the incomplete side — no false alarm here.
        Assert.Equal(RuleTriState.False, Eval("$s0 and $s1", CompleteEmpty, IncompleteEmpty).State);

    [Fact]
    public void IncompleteAndFalseIsFalse_RightOperandStillEvaluated() =>
        // The incomplete LEFT operand must not short-circuit to Incomplete: the right
        // operand is false, which decides the conjunction.
        Assert.Equal(RuleTriState.False, Eval("$s0 and $s1", IncompleteEmpty, CompleteEmpty).State);

    [Fact]
    public void TrueAndIncompleteIsIncomplete() =>
        Assert.Equal(RuleTriState.Incomplete, Eval("$s0 and $s1", CompleteHit, IncompleteEmpty).State);

    [Fact]
    public void TrueOrIncompleteIsTrue() =>
        Assert.Equal(RuleTriState.True, Eval("$s0 or $s1", CompleteHit, IncompleteEmpty).State);

    [Fact]
    public void IncompleteOrTrueIsTrue() =>
        Assert.Equal(RuleTriState.True, Eval("$s0 or $s1", IncompleteEmpty, CompleteHit).State);

    [Fact]
    public void FalseOrIncompleteIsIncomplete() =>
        Assert.Equal(RuleTriState.Incomplete, Eval("$s0 or $s1", CompleteEmpty, IncompleteEmpty).State);

    [Fact]
    public void NotIncompleteIsIncomplete() =>
        Assert.Equal(RuleTriState.Incomplete, Eval("not $s0", IncompleteEmpty).State);

    [Fact]
    public void IncompleteStringWithMatchesIsConfidentlyTrue()
    {
        // Matches already found are trustworthy even when matching was cut short:
        // the string is true, and so is the rule.
        var incompleteWithHit = new StringMatchSet
        {
            Matches = [new StringMatch(3, 4)],
            Complete = false,
            IncompleteReason = "cut short",
            NonOverlappingCount = 1,
        };
        Assert.Equal(RuleTriState.True, Eval("$s0", incompleteWithHit).State);
    }

    [Fact]
    public void CountOnIncompleteStringIsIncompleteEvenWithMatches()
    {
        // A partial count is a lower bound; comparing it would launder the truncation.
        var incompleteWithHit = new StringMatchSet
        {
            Matches = [new StringMatch(3, 4)],
            Complete = false,
            IncompleteReason = "cut short",
            NonOverlappingCount = 1,
        };
        Assert.Equal(RuleTriState.Incomplete, Eval("#s0 >= 1", incompleteWithHit).State);
    }

    [Fact]
    public void OfQuantifierCountsIncompleteHonestly()
    {
        // 2 of ($s0,$s1,$s2): one true, one incomplete, one false -> could still reach 2
        // -> Incomplete, not False.
        Assert.Equal(RuleTriState.Incomplete,
            Eval("2 of ($s0, $s1, $s2)", CompleteHit, IncompleteEmpty, CompleteEmpty).State);
        // 3 of them with one definite false -> impossible -> False, despite the incomplete.
        Assert.Equal(RuleTriState.False,
            Eval("3 of ($s0, $s1, $s2)", CompleteHit, IncompleteEmpty, CompleteEmpty).State);
    }

    [Fact]
    public void DeterministicAcrossRepeatedEvaluation()
    {
        for (int i = 0; i < 3; i++)
        {
            Assert.Equal(RuleTriState.Incomplete, Eval("$s0 and $s1", CompleteHit, IncompleteEmpty).State);
        }
    }
}
