using ZeroBreach.Rules.Yara.Parsing;
using Xunit;

namespace ZeroBreach.Rules.Tests.Yara;

public static class ParseHelper
{
    public static (YaraFileAst Ast, List<Diagnostic> Diagnostics) Parse(string source, string fileName = "test.yar")
    {
        var diagnostics = new List<Diagnostic>();
        var ast = YaraParser.ParseFile(source, fileName, diagnostics);
        var validator = new YaraValidator(diagnostics);
        validator.Validate([ast]);
        return (ast, diagnostics);
    }

    public static YaraRuleAst ParseSingleRule(string source)
    {
        var (ast, diagnostics) = Parse(source);
        var errors = diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.True(errors.Count == 0, "unexpected errors: " + string.Join("; ", errors));
        return Assert.Single(ast.Rules);
    }

    public static YaraExpression ParseCondition(string condition)
    {
        var rule = ParseSingleRule($"rule t {{ condition: {condition} }}");
        return rule.Condition;
    }

    public static void AssertError(string source, DiagnosticCode code)
    {
        var (_, diagnostics) = Parse(source);
        Assert.Contains(diagnostics, d => d.Severity == DiagnosticSeverity.Error && d.Code == code);
    }
}

public class RuleStructureTests
{
    [Fact]
    public void FullRuleParsesToExpectedShape()
    {
        var source = """
            rule Example_Rule : tag1 tag2
            {
                meta:
                    author      = "someone"
                    threshold   = 3
                    enabled     = true
                    negative    = -2

                strings:
                    $text  = "abc" nocase wide ascii fullword
                    $hex   = { 4D 5A ?? ?4 [4-8] ( 41 | 42 ) }
                    $re    = /ab[0-9]{2,4}cd/ nocase

                condition:
                    uint16(0) == 0x5A4D and $text and 2 of ($hex, $re) and filesize < 2MB
            }
            """;
        var rule = ParseHelper.ParseSingleRule(source);

        Assert.Equal("Example_Rule", rule.Name);
        Assert.Equal(["tag1", "tag2"], rule.Tags);
        Assert.False(rule.IsPrivate);
        Assert.False(rule.IsGlobal);

        Assert.Equal(4, rule.Meta.Count);
        Assert.Equal(new StringMetaValue("someone"), rule.Meta[0].Value);
        Assert.Equal(new IntegerMetaValue(3), rule.Meta[1].Value);
        Assert.Equal(new BooleanMetaValue(true), rule.Meta[2].Value);
        Assert.Equal(new IntegerMetaValue(-2), rule.Meta[3].Value);

        Assert.Equal(3, rule.Strings.Count);
        var text = Assert.IsType<TextStringDecl>(rule.Strings[0]);
        Assert.Equal("abc"u8.ToArray(), text.ValueBytes);
        Assert.True(text.Modifiers.Has(StringModifierKind.Nocase));
        Assert.True(text.Modifiers.Has(StringModifierKind.Wide));
        Assert.True(text.Modifiers.Has(StringModifierKind.Ascii));
        Assert.True(text.Modifiers.Has(StringModifierKind.Fullword));

        var hex = Assert.IsType<HexStringDecl>(rule.Strings[1]);
        Assert.Equal(6, hex.Sequence.Nodes.Count); // 4D 5A ?? ?4 [4-8] (41|42)

        var re = Assert.IsType<RegexStringDecl>(rule.Strings[2]);
        Assert.Equal("ab[0-9]{2,4}cd", re.Pattern);
        Assert.True(re.CaseInsensitive); // nocase folds into the /i flag
    }

    [Fact]
    public void PrivateAndGlobalModifiersParse()
    {
        var (ast, diags) = ParseHelper.Parse("""
            private rule a { condition: true }
            global rule b { condition: true }
            private global rule c { condition: true }
            """);
        Assert.DoesNotContain(diags, d => d.Severity == DiagnosticSeverity.Error);
        Assert.True(ast.Rules[0].IsPrivate);
        Assert.True(ast.Rules[1].IsGlobal);
        Assert.True(ast.Rules[2].IsPrivate);
        Assert.True(ast.Rules[2].IsGlobal);
    }

    [Fact]
    public void ImportAndIncludeDirectivesParse()
    {
        var (ast, diags) = ParseHelper.Parse("""
            import "pe"
            include "other.yar"
            rule a { condition: true }
            """);
        Assert.Equal("pe", Assert.Single(ast.Imports).Module);
        Assert.Equal("other.yar", Assert.Single(ast.Includes).Path);
        // An unimplemented module import is an explicit diagnostic, never a silent skip.
        Assert.Contains(diags, d => d.Code == DiagnosticCode.UnsupportedModule);
    }

    [Fact]
    public void CommentsInBothFormsAreIgnored()
    {
        var rule = ParseHelper.ParseSingleRule("""
            // line comment
            rule a /* inline */ {
                strings:
                    $x = "v" // trailing
                    /* block
                       spanning lines */
                condition: $x
            }
            """);
        Assert.Equal("a", rule.Name);
    }

    [Fact]
    public void RuleWithoutMetaGetsWarningOnly()
    {
        var (_, diags) = ParseHelper.Parse("rule a { condition: true }");
        var warning = Assert.Single(diags, d => d.Code == DiagnosticCode.NoMetaSection);
        Assert.Equal(DiagnosticSeverity.Warning, warning.Severity);
        Assert.DoesNotContain(diags, d => d.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void EscapeSequencesProduceExactBytes()
    {
        var rule = ParseHelper.ParseSingleRule("""rule a { strings: $x = "a\t\n\r\"\\\x00\xFF" condition: $x }""");
        var text = Assert.IsType<TextStringDecl>(rule.Strings[0]);
        Assert.Equal(new byte[] { (byte)'a', 9, 10, 13, (byte)'"', (byte)'\\', 0x00, 0xFF }, text.ValueBytes);
    }

    [Fact]
    public void InvalidEscapeIsRejectedWithPosition()
    {
        var (_, diags) = ParseHelper.Parse("""rule a { strings: $x = "a\qb" condition: $x }""");
        var d = Assert.Single(diags, d => d.Code == DiagnosticCode.InvalidEscapeSequence);
        Assert.Equal(1, d.Location.Line);
    }

    [Fact]
    public void XorRangeParses()
    {
        var rule = ParseHelper.ParseSingleRule("""rule a { strings: $x = "abcd" xor(0x10-0x20) condition: $x }""");
        var mods = rule.Strings[0].Modifiers;
        Assert.True(mods.Has(StringModifierKind.Xor));
        Assert.Equal(0x10, mods.XorMin);
        Assert.Equal(0x20, mods.XorMax);
    }

    [Fact]
    public void BareXorMeansFullKeyRange()
    {
        var rule = ParseHelper.ParseSingleRule("""rule a { strings: $x = "abcd" xor condition: $x }""");
        Assert.Equal(0, rule.Strings[0].Modifiers.XorMin);
        Assert.Equal(255, rule.Strings[0].Modifiers.XorMax);
    }

    [Fact]
    public void Base64CustomAlphabetParses()
    {
        var alphabet = "!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu";
        var rule = ParseHelper.ParseSingleRule($$"""rule a { strings: $x = "abcd" base64("{{alphabet}}") condition: $x }""");
        Assert.Equal(64, rule.Strings[0].Modifiers.Base64Alphabet!.Length);
    }

    [Fact]
    public void AnonymousStringsAreAllowedViaThem()
    {
        var rule = ParseHelper.ParseSingleRule("""rule a { strings: $ = "one" $ = "two" condition: all of them }""");
        Assert.Equal(2, rule.Strings.Count);
        Assert.All(rule.Strings, s => Assert.Equal("", s.Identifier));
    }
}

public class HexStringParseTests
{
    private static HexSequence ParseHex(string body)
    {
        var rule = ParseHelper.ParseSingleRule($"rule a {{ strings: $h = {{ {body} }} condition: $h }}");
        return Assert.IsType<HexStringDecl>(rule.Strings[0]).Sequence;
    }

    [Fact]
    public void PlainBytesParse()
    {
        var seq = ParseHex("4D 5A 90");
        Assert.Equal(
            [new HexByteNode(0x4D, 0xFF), new HexByteNode(0x5A, 0xFF), new HexByteNode(0x90, 0xFF)],
            seq.Nodes);
    }

    [Fact]
    public void NibbleWildcardsProduceMasks()
    {
        var seq = ParseHex("4D ?? ?4 4?");
        Assert.Equal(new HexByteNode(0x00, 0x00), seq.Nodes[1]);
        Assert.Equal(new HexByteNode(0x04, 0x0F), seq.Nodes[2]);
        Assert.Equal(new HexByteNode(0x40, 0xF0), seq.Nodes[3]);
    }

    [Fact]
    public void NegatedByteParses()
    {
        var seq = ParseHex("4D ~00 5A");
        Assert.Equal(new HexByteNode(0x00, 0xFF, Negated: true), seq.Nodes[1]);
    }

    [Fact]
    public void JumpFormsParse()
    {
        var seq = ParseHex("AA [4-8] [6] [10-] [-4] [-] BB");
        Assert.Equal(new HexJumpNode(4, 8), seq.Nodes[1]);
        Assert.Equal(new HexJumpNode(6, 6), seq.Nodes[2]);
        Assert.Equal(new HexJumpNode(10, null), seq.Nodes[3]);
        Assert.Equal(new HexJumpNode(0, 4), seq.Nodes[4]);
        Assert.Equal(new HexJumpNode(0, null), seq.Nodes[5]);
    }

    [Fact]
    public void NestedAlternationParses()
    {
        var seq = ParseHex("AA ( 41 | 42 ( 43 | 44 ) ) BB");
        var alt = Assert.IsType<HexAltNode>(seq.Nodes[1]);
        Assert.Equal(2, alt.Branches.Count);
        var inner = Assert.IsType<HexAltNode>(alt.Branches[1].Nodes[1]);
        Assert.Equal(2, inner.Branches.Count);
    }

    [Theory]
    [InlineData("[4-8] AA", DiagnosticCode.InvalidHexJump)]        // cannot start with a jump
    [InlineData("AA [4-8]", DiagnosticCode.InvalidHexJump)]        // cannot end with a jump
    [InlineData("AA [8-4] BB", DiagnosticCode.InvalidHexJump)]     // min > max
    [InlineData("AA ( 41 [1-] | 42 ) BB", DiagnosticCode.InvalidHexJump)] // unbounded jump in alternation
    [InlineData("AA [9999999] BB", DiagnosticCode.PatternTooComplex)]
    [InlineData("AA ~?? BB", DiagnosticCode.SyntaxError)]
    public void InvalidHexConstructsAreRejected(string body, DiagnosticCode code)
    {
        ParseHelper.AssertError($"rule a {{ strings: $h = {{ {body} }} condition: $h }}", code);
    }

    [Fact]
    public void UnterminatedHexStringReportsPosition()
    {
        var (_, diags) = ParseHelper.Parse("rule a { strings: $h = { 4D 5A \n condition: $h }");
        Assert.Contains(diags, d => d.Code is DiagnosticCode.UnterminatedHexString or DiagnosticCode.SyntaxError);
    }

    [Fact]
    public void HexModifiersOtherThanPrivateRejected()
    {
        ParseHelper.AssertError("rule a { strings: $h = { 4D 5A } nocase condition: $h }",
            DiagnosticCode.InvalidModifierForStringKind);
    }

    [Fact]
    public void DeeplyNestedAlternationIsRejectedNotOverflowed()
    {
        var open = string.Concat(Enumerable.Repeat("( 41 | ", 100));
        var close = string.Concat(Enumerable.Repeat(" )", 100));
        ParseHelper.AssertError($"rule a {{ strings: $h = {{ AA {open} 42 {close} BB }} condition: $h }}",
            DiagnosticCode.NestingTooDeep);
    }
}

/// <summary>
/// Each case pins one precedence level against its neighbour: the asserted shape would be
/// different if the two levels were swapped.
/// </summary>
public class OperatorPrecedenceTests
{
    private static BinaryExpr Bin(YaraExpression e) => Assert.IsType<BinaryExpr>(e);

    [Fact]
    public void AndBindsTighterThanOr()
    {
        // or(true, and(true, false)) — if or bound tighter this would be and(or(true,true), false)
        var e = Bin(ParseHelper.ParseCondition("true or true and false"));
        Assert.Equal(BinaryOp.Or, e.Op);
        Assert.Equal(BinaryOp.And, Bin(e.Right).Op);
    }

    [Fact]
    public void NotBindsTighterThanAnd()
    {
        // and(not(true), false) — not(and(true,false)) would differ
        var e = Bin(ParseHelper.ParseCondition("not true and false"));
        Assert.Equal(BinaryOp.And, e.Op);
        var not = Assert.IsType<UnaryExpr>(e.Left);
        Assert.Equal(UnaryOp.Not, not.Op);
    }

    [Fact]
    public void ComparisonBindsTighterThanNot()
    {
        // not(eq(1,2)) — (not 1) == 2 would be a type error in evaluation and a different shape here
        var not = Assert.IsType<UnaryExpr>(ParseHelper.ParseCondition("not 1 == 2"));
        Assert.Equal(BinaryOp.Eq, Bin(not.Operand).Op);
    }

    [Fact]
    public void BitOrBindsTighterThanComparison()
    {
        // eq(1, bitor(1,2)) — bitor(eq(..), 2) would differ
        var e = Bin(ParseHelper.ParseCondition("1 == 1 | 2"));
        Assert.Equal(BinaryOp.Eq, e.Op);
        Assert.Equal(BinaryOp.BitOr, Bin(e.Right).Op);
    }

    [Fact]
    public void BitXorBindsTighterThanBitOr()
    {
        var e = Bin(ParseHelper.ParseCondition("(1 | 2 ^ 3) == 0"));
        var or = Bin(e.Left);
        Assert.Equal(BinaryOp.BitOr, or.Op);
        Assert.Equal(BinaryOp.BitXor, Bin(or.Right).Op);
    }

    [Fact]
    public void BitAndBindsTighterThanBitXor()
    {
        var e = Bin(ParseHelper.ParseCondition("(2 ^ 4 & 1) == 0"));
        var xor = Bin(e.Left);
        Assert.Equal(BinaryOp.BitXor, xor.Op);
        Assert.Equal(BinaryOp.BitAnd, Bin(xor.Right).Op);
    }

    [Fact]
    public void ShiftBindsTighterThanBitAnd()
    {
        var e = Bin(ParseHelper.ParseCondition("(1 & 2 << 3) == 0"));
        var and = Bin(e.Left);
        Assert.Equal(BinaryOp.BitAnd, and.Op);
        Assert.Equal(BinaryOp.Shl, Bin(and.Right).Op);
    }

    [Fact]
    public void AdditiveBindsTighterThanShift()
    {
        var e = Bin(ParseHelper.ParseCondition("(1 << 2 + 3) == 0"));
        var shl = Bin(e.Left);
        Assert.Equal(BinaryOp.Shl, shl.Op);
        Assert.Equal(BinaryOp.Add, Bin(shl.Right).Op);
    }

    [Fact]
    public void MultiplicativeBindsTighterThanAdditive()
    {
        var e = Bin(ParseHelper.ParseCondition("(1 + 2 * 3) == 7"));
        var add = Bin(e.Left);
        Assert.Equal(BinaryOp.Add, add.Op);
        Assert.Equal(BinaryOp.Mul, Bin(add.Right).Op);
    }

    [Fact]
    public void UnaryMinusBindsTighterThanMultiply()
    {
        // mul(neg(2), 3) — neg(mul(2,3)) would differ
        var e = Bin(ParseHelper.ParseCondition("(-2 * 3) == -6"));
        var mul = Bin(e.Left);
        Assert.Equal(BinaryOp.Mul, mul.Op);
        var neg = Assert.IsType<UnaryExpr>(mul.Left);
        Assert.Equal(UnaryOp.Negate, neg.Op);
    }

    [Fact]
    public void BackslashIsDivision()
    {
        var e = Bin(ParseHelper.ParseCondition(@"(10 \ 2) == 5"));
        Assert.Equal(BinaryOp.Div, Bin(e.Left).Op);
    }

    [Fact]
    public void ParenthesesOverridePrecedence()
    {
        var e = Bin(ParseHelper.ParseCondition("((1 + 2) * 3) == 9"));
        var mul = Bin(e.Left);
        Assert.Equal(BinaryOp.Mul, mul.Op);
        Assert.Equal(BinaryOp.Add, Bin(mul.Left).Op);
    }
}

public class ConditionConstructTests
{
    [Fact]
    public void StringAtParsesAsOffsetTest()
    {
        var rule = ParseHelper.ParseSingleRule("""rule a { strings: $x = "v" condition: $x at 0 }""");
        var at = Assert.IsType<StringAtExpr>(rule.Condition);
        Assert.Equal("x", at.StringName);
        Assert.Equal(0L, Assert.IsType<IntegerLiteralExpr>(at.Offset).Value);
    }

    [Fact]
    public void StringInRangeParses()
    {
        var rule = ParseHelper.ParseSingleRule("""rule a { strings: $x = "v" condition: $x in (0..filesize) }""");
        var e = Assert.IsType<StringInExpr>(rule.Condition);
        Assert.IsType<FilesizeExpr>(e.Range.High);
    }

    [Fact]
    public void CountOffsetLengthParse()
    {
        var rule = ParseHelper.ParseSingleRule(
            """rule a { strings: $x = "v" condition: #x > 1 and @x[2] < 10 and !x[1] == 1 and @x == 0 }""");
        var and2 = Assert.IsType<BinaryExpr>(rule.Condition);
        // @x with no subscript is index 1
        var lastCmp = Assert.IsType<BinaryExpr>(and2.Right);
        var offset = Assert.IsType<StringOffsetExpr>(lastCmp.Left);
        Assert.Null(offset.Index);
    }

    [Fact]
    public void CountInRangeParses()
    {
        var rule = ParseHelper.ParseSingleRule("""rule a { strings: $x = "v" condition: #x in (0..9) > 0 }""");
        var cmp = Assert.IsType<BinaryExpr>(rule.Condition);
        var count = Assert.IsType<StringCountExpr>(cmp.Left);
        Assert.NotNull(count.InRange);
    }

    [Fact]
    public void OfFormsParse()
    {
        var src = """
            rule a {
                strings:
                    $a1 = "x"
                    $a2 = "y"
                    $b1 = "z"
                condition:
                    any of them and all of ($a*) and 2 of ($a1, $b1) and none of ($b*) and 50% of them
                    and any of them in (0..100)
            }
            """;
        var rule = ParseHelper.ParseSingleRule(src);
        Assert.NotNull(rule.Condition);
        // Walk down the left-assoc `and` chain collecting the OfExprs.
        var ofs = new List<OfExpr>();
        void Collect(YaraExpression e)
        {
            if (e is BinaryExpr { Op: BinaryOp.And } b)
            {
                Collect(b.Left);
                Collect(b.Right);
            }
            else if (e is OfExpr of)
            {
                ofs.Add(of);
            }
        }
        Collect(rule.Condition);
        Assert.Equal(6, ofs.Count);
        Assert.IsType<AnyQuantifier>(ofs[0].Quantifier);
        Assert.IsType<AllQuantifier>(ofs[1].Quantifier);
        Assert.IsType<ExprQuantifier>(ofs[2].Quantifier);
        Assert.IsType<NoneQuantifier>(ofs[3].Quantifier);
        Assert.IsType<PercentQuantifier>(ofs[4].Quantifier);
        Assert.NotNull(ofs[5].InRange);
    }

    [Fact]
    public void ForOfWithPlaceholdersParses()
    {
        var rule = ParseHelper.ParseSingleRule(
            """rule a { strings: $x = "v" $y = "w" condition: for any of them : ( $ at 0 and # > 0 ) }""");
        var forOf = Assert.IsType<ForOfExpr>(rule.Condition);
        Assert.IsType<ThemSet>(forOf.Set);
    }

    [Fact]
    public void ForInRangeAndEnumerationParse()
    {
        var rule = ParseHelper.ParseSingleRule(
            """rule a { strings: $x = "v" condition: for all i in (1..#x) : ( @x[i] < 100 ) and for any j in (1,2,3) : ( uint8(j) == 0 ) }""");
        var and = Assert.IsType<BinaryExpr>(rule.Condition);
        var f1 = Assert.IsType<ForInExpr>(and.Left);
        Assert.IsType<RangeIterable>(f1.Iterable);
        var f2 = Assert.IsType<ForInExpr>(and.Right);
        Assert.Equal(3, Assert.IsType<EnumIterable>(f2.Iterable).Items.Count);
    }

    [Fact]
    public void IntegerFunctionsParse()
    {
        var e = ParseHelper.ParseCondition("uint32be(uint16(0)) == int8(4)");
        var cmp = Assert.IsType<BinaryExpr>(e);
        var outer = Assert.IsType<IntReadExpr>(cmp.Left);
        Assert.Equal(IntReadKind.UInt32Be, outer.Kind);
        Assert.Equal(IntReadKind.UInt16, Assert.IsType<IntReadExpr>(outer.Offset).Kind);
    }

    [Fact]
    public void SizeSuffixesAndNumberBasesParse()
    {
        var e = ParseHelper.ParseCondition("filesize < 2MB and filesize > 4KB and uint8(0) == 0x1F and uint8(1) == 0o17");
        Assert.NotNull(e);
        var (_, diags) = ParseHelper.Parse("rule t { condition: filesize < 2MB }");
        Assert.DoesNotContain(diags, d => d.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void RuleReferenceParses()
    {
        var (ast, diags) = ParseHelper.Parse("""
            rule base { condition: true }
            rule derived { condition: base and filesize > 0 }
            """);
        Assert.DoesNotContain(diags, d => d.Severity == DiagnosticSeverity.Error);
        var and = Assert.IsType<BinaryExpr>(ast.Rules[1].Condition);
        Assert.Equal("base", Assert.IsType<IdentifierExpr>(and.Left).Name);
    }

    [Fact]
    public void StringLiteralComparisonsParse()
    {
        var e = ParseHelper.ParseCondition(""" "abc" contains "b" and "abc" matches /a.c/ """);
        Assert.NotNull(e);
    }
}

public class ValidationRejectionTests
{
    [Fact]
    public void UndefinedStringReferenceRejected() =>
        ParseHelper.AssertError("""rule a { strings: $x = "v" condition: $x and $missing }""",
            DiagnosticCode.UndefinedStringReference);

    [Fact]
    public void WildcardMatchingNothingRejected() =>
        ParseHelper.AssertError("""rule a { strings: $x = "v" condition: $x and any of ($zz*) }""",
            DiagnosticCode.WildcardMatchesNothing);

    [Fact]
    public void OfThemWithNoStringsRejected() =>
        ParseHelper.AssertError("rule a { condition: any of them }", DiagnosticCode.ThemWithNoStrings);

    [Fact]
    public void EmptyStringsSectionRejected() =>
        ParseHelper.AssertError("rule a { strings: condition: true }", DiagnosticCode.EmptyStringsSection);

    [Fact]
    public void DuplicateRuleNameRejected() =>
        ParseHelper.AssertError("rule a { condition: true } rule a { condition: false }",
            DiagnosticCode.DuplicateRuleName);

    [Fact]
    public void DuplicateStringIdentifierRejected() =>
        ParseHelper.AssertError("""rule a { strings: $x = "v" $x = "w" condition: all of them }""",
            DiagnosticCode.DuplicateStringIdentifier);

    [Fact]
    public void UnresolvedRuleReferenceRejected() =>
        ParseHelper.AssertError("rule a { condition: nonexistent_rule }", DiagnosticCode.UndefinedRuleReference);

    [Fact]
    public void ForwardRuleReferenceRejected() =>
        ParseHelper.AssertError("rule a { condition: b } rule b { condition: true }",
            DiagnosticCode.ForwardRuleReference);

    [Fact]
    public void SelfReferenceReportedAsCycle() =>
        ParseHelper.AssertError("rule a { condition: a }", DiagnosticCode.RuleReferenceCycle);

    [Fact]
    public void UnreferencedStringRejected() =>
        ParseHelper.AssertError("""rule a { strings: $x = "v" $unused = "w" condition: $x }""",
            DiagnosticCode.UnreferencedString);

    [Fact]
    public void ThemCountsAsReferencingEverything()
    {
        var (_, diags) = ParseHelper.Parse("""rule a { strings: $x = "v" $y = "w" condition: any of them }""");
        Assert.DoesNotContain(diags, d => d.Code == DiagnosticCode.UnreferencedString);
    }

    [Theory]
    [InlineData("nocase xor")]
    [InlineData("nocase base64")]
    [InlineData("xor base64")]
    [InlineData("fullword base64")]
    [InlineData("nocase base64wide")]
    public void MeaninglessModifierCombinationsRejected(string mods) =>
        ParseHelper.AssertError("rule a { strings: $x = \"abcd\" " + mods + " condition: $x }",
            DiagnosticCode.InvalidModifierCombination);

    [Fact]
    public void XorOnRegexRejected() =>
        ParseHelper.AssertError("rule a { strings: $x = /ab+/ xor condition: $x }",
            DiagnosticCode.InvalidModifierForStringKind);

    [Fact]
    public void DuplicateModifierRejected() =>
        ParseHelper.AssertError("""rule a { strings: $x = "v" wide wide condition: $x }""",
            DiagnosticCode.DuplicateModifier);

    [Fact]
    public void InvalidXorRangeRejected() =>
        ParseHelper.AssertError("""rule a { strings: $x = "abcd" xor(300) condition: $x }""",
            DiagnosticCode.InvalidXorRange);

    [Fact]
    public void ShortBase64StringRejected() =>
        ParseHelper.AssertError("""rule a { strings: $x = "ab" base64 condition: $x }""",
            DiagnosticCode.Base64StringTooShort);

    [Fact]
    public void WrongLengthBase64AlphabetRejected() =>
        ParseHelper.AssertError("""rule a { strings: $x = "abcd" base64("short") condition: $x }""",
            DiagnosticCode.InvalidBase64Alphabet);

    [Fact]
    public void EmptyTextStringRejected() =>
        ParseHelper.AssertError("""rule a { strings: $x = "" condition: $x }""", DiagnosticCode.EmptyString);

    [Fact]
    public void AnonymousReferenceOutsideLoopRejected() =>
        ParseHelper.AssertError("""rule a { strings: $ = "v" condition: $ }""",
            DiagnosticCode.AnonymousStringOutsideLoop);

    [Fact]
    public void DuplicateLoopVariableRejected() =>
        ParseHelper.AssertError(
            "rule a { condition: for any i in (1..2) : ( for any i in (1..2) : ( true ) ) }",
            DiagnosticCode.DuplicateLoopVariable);

    [Fact]
    public void DuplicateTagRejected() =>
        ParseHelper.AssertError("rule a : t t { condition: true }", DiagnosticCode.DuplicateTag);

    [Fact]
    public void MatchesRequiresRegexRhs() =>
        ParseHelper.AssertError(""" rule a { condition: "x" matches "y" } """,
            DiagnosticCode.MisplacedRegexLiteral);

    [Fact]
    public void ModuleReferenceWithoutImportRejected() =>
        ParseHelper.AssertError("rule a { condition: pe.entry_point > 0 }",
            DiagnosticCode.UndefinedRuleReference);

    [Fact]
    public void ModuleReferenceWithImportMarksRuleUnsupported()
    {
        var diagnostics = new List<Diagnostic>();
        var ast = YaraParser.ParseFile("""
            import "pe"
            rule a { condition: pe.entry_point > 0 }
            rule b { condition: true }
            """, "t.yar", diagnostics);
        var validator = new YaraValidator(diagnostics);
        validator.Validate([ast]);
        Assert.Contains("a", validator.RulesUsingUnsupportedModules);
        Assert.DoesNotContain("b", validator.RulesUsingUnsupportedModules);
        Assert.Contains("pe", validator.UnsupportedModules);
        Assert.DoesNotContain(diagnostics, d => d.Severity == DiagnosticSeverity.Error);
    }
}

public class DiagnosticQualityTests
{
    [Fact]
    public void UnterminatedStringReportsLineAndColumn()
    {
        var source = "rule a {\n  strings:\n    $x = \"never closed\n  condition: $x\n}";
        var (_, diags) = ParseHelper.Parse(source);
        var d = Assert.Single(diags, d => d.Code == DiagnosticCode.UnterminatedString);
        Assert.Equal(3, d.Location.Line);
        Assert.Equal(10, d.Location.Column);
        Assert.Contains("line 3", d.Message);
    }

    [Fact]
    public void AllDiagnosticsReportedNotJustFirst()
    {
        // Three rules, three distinct problems: recovery must surface every one.
        var source = """
            rule one { strings: $x = "v" condition: $x and $missing }
            rule two { strings: condition: true }
            rule three { condition: any of them }
            """;
        var (_, diags) = ParseHelper.Parse(source);
        Assert.Contains(diags, d => d.Code == DiagnosticCode.UndefinedStringReference);
        Assert.Contains(diags, d => d.Code == DiagnosticCode.EmptyStringsSection);
        Assert.Contains(diags, d => d.Code == DiagnosticCode.ThemWithNoStrings);
    }

    [Fact]
    public void ErrorsAndWarningsAreDistinguished()
    {
        var (_, diags) = ParseHelper.Parse("""
            import "pe"
            rule a { condition: true or $ }
            """);
        Assert.Contains(diags, d => d.Severity == DiagnosticSeverity.Warning && d.Code == DiagnosticCode.UnsupportedModule);
        Assert.Contains(diags, d => d.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void ToStringIncludesFilePositionAndCode()
    {
        var (_, diags) = ParseHelper.Parse("rule a { condition: }", "bad.yar");
        var text = diags.First(d => d.Severity == DiagnosticSeverity.Error).ToString();
        Assert.Contains("bad.yar", text);
        Assert.Contains("error", text);
    }
}

public class HostileInputTests
{
    [Fact]
    public void DeepParenthesesNestingProducesDiagnosticNotOverflow()
    {
        var deep = string.Concat(Enumerable.Repeat("(", 5000)) + "true" +
                   string.Concat(Enumerable.Repeat(")", 5000));
        ParseHelper.AssertError($"rule a {{ condition: {deep} }}", DiagnosticCode.NestingTooDeep);
    }

    [Fact]
    public void HugeIdentifierProducesDiagnostic()
    {
        var name = new string('x', 100_000);
        ParseHelper.AssertError($"rule {name} {{ condition: true }}", DiagnosticCode.IdentifierTooLong);
    }

    [Fact]
    public void UnterminatedCommentProducesDiagnostic() =>
        ParseHelper.AssertError("rule a { condition: true } /* never closed", DiagnosticCode.UnterminatedComment);

    [Fact]
    public void UnterminatedRegexProducesDiagnostic() =>
        ParseHelper.AssertError("rule a { strings: $r = /abc\n condition: $r }", DiagnosticCode.UnterminatedRegex);

    [Fact]
    public void GarbageBytesProduceDiagnosticsNotThrow()
    {
        var garbage = "rule \x01\x02 { \x7f condition: \xff }";
        var (_, diags) = ParseHelper.Parse(garbage);
        Assert.Contains(diags, d => d.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void ManyErrorsAreCappedInsteadOfUnbounded()
    {
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < 2000; i++)
        {
            sb.Append("rule r").Append(i).Append(" { condition: $nope }\n");
        }
        var (_, diags) = ParseHelper.Parse(sb.ToString());
        // Errors are capped (warnings are not — a large corpus may warn legitimately).
        int errors = diags.Count(d => d.Severity == DiagnosticSeverity.Error);
        Assert.True(errors <= YaraParser.MaxDiagnostics + 50, $"errors not capped: {errors}");
        Assert.Contains(diags, d => d.Code == DiagnosticCode.TooManyDiagnostics);
    }

    [Fact]
    public void ParsingIsDeterministic()
    {
        var source = """
            rule one { strings: $x = "v" condition: $x and $missing }
            rule two { strings: $a = { 4D ( 41 | 42 ) } condition: $a }
            """;
        var (_, first) = ParseHelper.Parse(source);
        var (_, second) = ParseHelper.Parse(source);
        Assert.Equal(first.Select(d => d.ToString()), second.Select(d => d.ToString()));
    }
}
