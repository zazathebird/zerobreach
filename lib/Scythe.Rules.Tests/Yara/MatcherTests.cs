using System.Text;
using Scythe.Rules;
using Scythe.Rules.Yara.Matching;
using Scythe.Rules.Yara.Parsing;
using Xunit;

namespace Scythe.Rules.Tests.Yara;

public static class MatchHelper
{
    public static (CompiledStringSet? Set, List<Diagnostic> Diagnostics) CompileStrings(string stringsSection)
    {
        var diagnostics = new List<Diagnostic>();
        var ast = YaraParser.ParseFile($"rule t {{ strings: {stringsSection} condition: any of them }}",
            "t.yar", diagnostics);
        if (diagnostics.Any(d => d.Severity == DiagnosticSeverity.Error))
        {
            return (null, diagnostics);
        }
        var strings = ast.Rules[0].Strings.Select(s => (0, s)).ToList();
        var set = YaraStringCompiler.Compile(strings, "t.yar", diagnostics);
        return (set, diagnostics);
    }

    public static StringScanResult Scan(string stringsSection, byte[] data, ScanBudget? budget = null)
    {
        var (set, diagnostics) = CompileStrings(stringsSection);
        Assert.True(set is not null,
            "compile failed: " + string.Join("; ", diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        return StringScanner.Scan(set!, data, budget ?? ScanBudget.Default);
    }

    public static IReadOnlyList<StringMatch> Matches(string stringsSection, byte[] data)
    {
        var result = Scan(stringsSection, data);
        Assert.Equal(OperationState.Ok, result.State);
        return result.PerString[0].Matches;
    }

    public static byte[] Bytes(string s) => Encoding.ASCII.GetBytes(s);

    public static byte[] Wide(string s)
    {
        var b = new byte[s.Length * 2];
        for (int i = 0; i < s.Length; i++)
        {
            b[i * 2] = (byte)s[i];
        }
        return b;
    }

    public static void AssertCompileError(string stringsSection, DiagnosticCode code)
    {
        var (set, diagnostics) = CompileStrings(stringsSection);
        Assert.Null(set);
        Assert.Contains(diagnostics, d => d.Severity == DiagnosticSeverity.Error && d.Code == code);
    }
}

public class TextModifierTests
{
    [Fact]
    public void PlainAsciiMatchesAtEveryStartingOffset()
    {
        var matches = MatchHelper.Matches("""$a = "ab" """, MatchHelper.Bytes("ab_ab_ab"));
        Assert.Equal(new[] { new StringMatch(0, 2), new StringMatch(3, 2), new StringMatch(6, 2) }, matches);
    }

    [Fact]
    public void MatchingIsCaseSensitiveByDefault()
    {
        Assert.Empty(MatchHelper.Matches("""$a = "ab" """, MatchHelper.Bytes("AB Ab aB")));
    }

    [Fact]
    public void NocaseMatchesAllCaseVariants()
    {
        var matches = MatchHelper.Matches("""$a = "ab" nocase""", MatchHelper.Bytes("AB Ab aB ab"));
        Assert.Equal(4, matches.Count);
    }

    [Fact]
    public void NocaseIsAsciiOnlyNotUnicodeAware()
    {
        // 0xC4/0xE4 are Ä/ä in Latin-1; ASCII-only nocase must not fold them.
        var (set, _) = MatchHelper.CompileStrings("""$a = "a\xC4b" nocase""");
        var result = StringScanner.Scan(set!, new byte[] { (byte)'A', 0xE4, (byte)'B' }, ScanBudget.Default);
        Assert.Empty(result.PerString[0].Matches);
        var hit = StringScanner.Scan(set!, new byte[] { (byte)'A', 0xC4, (byte)'B' }, ScanBudget.Default);
        Assert.Single(hit.PerString[0].Matches);
    }

    [Fact]
    public void WideMatchesUtf16leOnly()
    {
        var matches = MatchHelper.Matches("""$a = "ab" wide""", MatchHelper.Wide("xaby"));
        Assert.Equal(new[] { new StringMatch(2, 4) }, matches);
        Assert.Empty(MatchHelper.Matches("""$a = "ab" wide""", MatchHelper.Bytes("ab")));
    }

    [Fact]
    public void WideAsciiMatchesEitherEncodingAsSeparateMatches()
    {
        var data = MatchHelper.Bytes("ab..").Concat(MatchHelper.Wide("ab")).ToArray();
        var matches = MatchHelper.Matches("""$a = "ab" wide ascii""", data);
        Assert.Equal(new[] { new StringMatch(0, 2), new StringMatch(4, 4) }, matches);
    }

    [Fact]
    public void FullwordRequiresNonWordNeighbours()
    {
        var matches = MatchHelper.Matches("""$a = "cat" fullword""", MatchHelper.Bytes("cat catalog cat-x _cat 1cat"));
        // "cat" (0), "cat-x" (12) and "_cat" (19) qualify — fullword is isalnum-based, so
        // underscore is a boundary (pinned against the reference); "catalog" and "1cat" fail.
        Assert.Equal(new[] { new StringMatch(0, 3), new StringMatch(12, 3), new StringMatch(19, 3) }, matches);
    }

    [Fact]
    public void FullwordAtBufferStartAndEndCounts()
    {
        Assert.Single(MatchHelper.Matches("""$a = "cat" fullword""", MatchHelper.Bytes("cat")));
        Assert.Single(MatchHelper.Matches("""$a = "cat" fullword""", MatchHelper.Bytes("-cat")));
        Assert.Single(MatchHelper.Matches("""$a = "cat" fullword""", MatchHelper.Bytes("cat-")));
    }

    [Fact]
    public void WideFullwordUsesEncodedSpaceBoundaries()
    {
        // 'A\0' before the match is a wide alphanumeric: not fullword. Verified against
        // the reference: 'AB' before it (not a wide char) is fine.
        var blocked = MatchHelper.Wide("Acat");
        Assert.Empty(MatchHelper.Matches("""$a = "cat" wide fullword""", blocked));
        var allowed = MatchHelper.Bytes("AB").Concat(MatchHelper.Wide("cat")).ToArray();
        Assert.Single(MatchHelper.Matches("""$a = "cat" wide fullword""", allowed));
    }

    [Fact]
    public void XorSingleKeyMatches()
    {
        var data = MatchHelper.Bytes("..HELLO..").Select(b => (byte)(b ^ 0x2A)).ToArray();
        var matches = MatchHelper.Matches("""$a = "HELLO" xor(0x2A)""", data);
        Assert.Equal(new[] { new StringMatch(2, 5) }, matches);
    }

    [Fact]
    public void BareXorCoversAllKeysIncludingPlaintext()
    {
        var xored = MatchHelper.Bytes("HELLO").Select(b => (byte)(b ^ 0x91)).ToArray();
        var data = MatchHelper.Bytes("HELLO|").Concat(xored).ToArray();
        var matches = MatchHelper.Matches("""$a = "HELLO" xor""", data);
        Assert.Equal(new[] { new StringMatch(0, 5), new StringMatch(6, 5) }, matches);
    }

    [Fact]
    public void XorRangeExcludesKeysOutsideIt()
    {
        var xored = MatchHelper.Bytes("HELLO").Select(b => (byte)(b ^ 0x91)).ToArray();
        Assert.Empty(MatchHelper.Matches("""$a = "HELLO" xor(1-16)""", xored));
    }

    [Fact]
    public void XorWithFullwordChecksRawNeighbours()
    {
        // Verified against the reference: neighbours are tested as raw bytes, not decoded.
        var data = MatchHelper.Bytes("ZHELLOZ").Select(b => (byte)(b ^ 0x04)).ToArray();
        var matches = MatchHelper.Matches("""$a = "HELLO" xor(0x04) fullword""", data);
        Assert.Single(matches); // raw neighbours are '^' (0x5E), which is not a word byte
    }

    [Fact]
    public void Base64MatchesAllThreePermutations()
    {
        // Permutations of "abcdef" pinned from the reference: YWJjZGVm / FiY2RlZ / hYmNkZW.
        foreach (var perm in new[] { "YWJjZGVm", "FiY2RlZ", "hYmNkZW" })
        {
            var data = MatchHelper.Bytes("??" + perm + "??");
            var matches = MatchHelper.Matches("""$a = "abcdef" base64""", data);
            Assert.True(matches.Count == 1 && matches[0].Offset == 2, $"permutation {perm} not found");
        }
    }

    [Fact]
    public void Base64DoesNotMatchThePlainForm()
    {
        Assert.Empty(MatchHelper.Matches("""$a = "abcdef" base64""", MatchHelper.Bytes("abcdef")));
    }

    [Fact]
    public void Base64WideMatchesWidenedEncodedForm()
    {
        var data = MatchHelper.Wide("YWJjZGVm");
        Assert.Single(MatchHelper.Matches("""$a = "abcdef" base64wide""", data));
        Assert.Empty(MatchHelper.Matches("""$a = "abcdef" base64""", data));
    }

    [Fact]
    public void Base64CombinedWithWideEncodesThePlaintextFirst()
    {
        // Pinned from the reference: "abcdef" base64 wide matches base64(UTF-16LE plaintext),
        // permutation 1 of which is EAYgBjAGQAZQBmA.
        var data = MatchHelper.Bytes("xxEAYgBjAGQAZQBmAyy");
        Assert.Single(MatchHelper.Matches("""$a = "abcdef" base64 wide""", data));
    }

    [Fact]
    public void Base64CustomAlphabetIsUsed()
    {
        // Standard alphabet with + and / swapped for - and _ (url-safe).
        var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        // ">>>" encodes to Pj4+ standard, Pj4- url-safe.
        var rule = $"""$a = ">>>" base64("{alphabet}")""";
        Assert.Single(MatchHelper.Matches(rule, MatchHelper.Bytes("Pj4-")));
        Assert.Empty(MatchHelper.Matches(rule, MatchHelper.Bytes("Pj4+")));
    }
}

public class CountingAndOrderTests
{
    [Fact]
    public void MatchListKeepsOnePerStartingOffsetButCountIsNonOverlapping()
    {
        // The deliberate split semantics (owner's decision): the match list stays
        // reference-compatible (offsets 0 and 1 both present), while # counts greedy
        // non-overlapping occurrences per BLUEPRINT §4.3 — here 1, where the reference
        // would count 2.
        var result = MatchHelper.Scan("""$a = "aa" """, MatchHelper.Bytes("aaa"));
        Assert.Equal(new[] { new StringMatch(0, 2), new StringMatch(1, 2) }, result.PerString[0].Matches);
        Assert.Equal(1, result.PerString[0].NonOverlappingCount);
    }

    [Fact]
    public void NonOverlappingCountAcrossDisjointMatches()
    {
        var result = MatchHelper.Scan("""$a = "aa" """, MatchHelper.Bytes("aa-aa-aaaa"));
        // list: 0,3,6,7,8 ; disjoint greedy: 0,3,6,8 -> 4
        Assert.Equal(5, result.PerString[0].Matches.Count);
        Assert.Equal(4, result.PerString[0].NonOverlappingCount);
    }

    [Fact]
    public void MatchesAreInAscendingOffsetOrder()
    {
        var data = MatchHelper.Bytes("xxABxxABxx");
        var matches = MatchHelper.Matches("""$a = "AB" wide ascii nocase""", data);
        for (int i = 1; i < matches.Count; i++)
        {
            Assert.True(matches[i - 1].CompareTo(matches[i]) < 0);
        }
    }

    [Fact]
    public void RepeatedScansAreDeterministic()
    {
        var (set, _) = MatchHelper.CompileStrings("""
            $a = "ab" nocase
            $b = { 61 ?? 63 }
            $c = /a[bc]+d/
            """);
        var data = MatchHelper.Bytes("abcd aBcd axcd abbbcd");
        var first = StringScanner.Scan(set!, data, ScanBudget.Default);
        var second = StringScanner.Scan(set!, data, ScanBudget.Default);
        for (int i = 0; i < first.PerString.Count; i++)
        {
            Assert.Equal(first.PerString[i].Matches, second.PerString[i].Matches);
            Assert.Equal(first.PerString[i].NonOverlappingCount, second.PerString[i].NonOverlappingCount);
        }
    }
}

public class HexMatchTests
{
    [Fact]
    public void PlainBytesMatch()
    {
        var matches = MatchHelper.Matches("$a = { 4D 5A }", new byte[] { 0x4D, 0x5A, 0x00, 0x4D, 0x5A });
        Assert.Equal(new[] { new StringMatch(0, 2), new StringMatch(3, 2) }, matches);
    }

    [Fact]
    public void FullByteWildcardMatchesAnything()
    {
        var matches = MatchHelper.Matches("$a = { 41 ?? 43 }", MatchHelper.Bytes("AxC AzC AC"));
        Assert.Equal(2, matches.Count);
    }

    [Fact]
    public void NibbleWildcardsMatchHalfBytes()
    {
        var matches = MatchHelper.Matches("$a = { 4? ?1 }", new byte[] { 0x4F, 0x21, 0x3F, 0x21 });
        Assert.Equal(new[] { new StringMatch(0, 2) }, matches);
    }

    [Fact]
    public void NegatedByteExcludesValue()
    {
        var matches = MatchHelper.Matches("$a = { 41 ~42 43 }", MatchHelper.Bytes("AxC ABC"));
        Assert.Equal(new[] { new StringMatch(0, 3) }, matches);
    }

    [Fact]
    public void BoundedJumpMatchesShortestSpan()
    {
        // Pinned from the reference: jumps are non-greedy; { 41 [0-2] 42 } on "ABB" is 2 bytes.
        var matches = MatchHelper.Matches("$a = { 41 [0-2] 42 }", MatchHelper.Bytes("ABB"));
        Assert.Equal(new[] { new StringMatch(0, 2) }, matches);
    }

    [Fact]
    public void JumpSpansGapsUpToItsBound()
    {
        var matches = MatchHelper.Matches("$a = { 41 [1-3] 42 }", MatchHelper.Bytes("A..B A....B AB"));
        Assert.Equal(new[] { new StringMatch(0, 4) }, matches);
    }

    [Fact]
    public void UnboundedJumpReachesFarContent()
    {
        var data = MatchHelper.Bytes("A" + new string('.', 100) + "B");
        var matches = MatchHelper.Matches("$a = { 41 [10-] 42 }", data);
        Assert.Equal(new[] { new StringMatch(0, 102) }, matches);
    }

    [Fact]
    public void AlternationMatchesEachBranch()
    {
        var matches = MatchHelper.Matches("$a = { 61 ( 41 | 42 43 ) 7A }", MatchHelper.Bytes("aAz aBCz aCz"));
        Assert.Equal(new[] { new StringMatch(0, 3), new StringMatch(4, 4) }, matches);
    }

    [Fact]
    public void NestedAlternationMatches()
    {
        var matches = MatchHelper.Matches("$a = { 61 ( 41 | 42 ( 43 | 44 ) ) 7A }",
            MatchHelper.Bytes("aAz aBCz aBDz aBz"));
        Assert.Equal(3, matches.Count);
    }

    [Fact]
    public void MatchAtBufferStartAndEndingAtFinalByte()
    {
        var matches = MatchHelper.Matches("$a = { 41 42 }", MatchHelper.Bytes("AB"));
        Assert.Equal(new[] { new StringMatch(0, 2) }, matches);
    }
}

public class RegexMatchTests
{
    [Fact]
    public void BasicClassAndRepetitionMatch()
    {
        // "ab12cd" matches (2 digits); "ab12345cd" does not (5 digits cannot satisfy {2,4}
        // and still leave "cd" adjacent).
        var matches = MatchHelper.Matches("$a = /ab[0-9]{2,4}cd/", MatchHelper.Bytes("xxab12cdyy ab12345cd"));
        Assert.Equal(new[] { new StringMatch(2, 6) }, matches);
    }

    [Fact]
    public void GreedyStarTakesLongestMatch()
    {
        // Pinned from the reference: /a.*b/ on "aXbYb" matches all 5 bytes.
        var matches = MatchHelper.Matches("$a = /a.*b/", MatchHelper.Bytes("aXbYb"));
        Assert.Equal(new[] { new StringMatch(0, 5) }, matches);
    }

    [Fact]
    public void LazyStarTakesShortestMatch()
    {
        // Pinned from the reference: /a.*?b/ on "aXbYb" matches 3 bytes.
        var matches = MatchHelper.Matches("$a = /a.*?b/", MatchHelper.Bytes("aXbYb"));
        Assert.Equal(new[] { new StringMatch(0, 3) }, matches);
    }

    [Fact]
    public void CaretAnchorsToBufferStart()
    {
        // Pinned from the reference: /^bc/ does not match inside "abc".
        Assert.Empty(MatchHelper.Matches("$a = /^bc/", MatchHelper.Bytes("abc")));
        Assert.Single(MatchHelper.Matches("$a = /^ab/", MatchHelper.Bytes("abc")));
    }

    [Fact]
    public void DollarAnchorsToBufferEnd()
    {
        Assert.Single(MatchHelper.Matches("$a = /bc$/", MatchHelper.Bytes("abc")));
        Assert.Empty(MatchHelper.Matches("$a = /ab$/", MatchHelper.Bytes("abc")));
    }

    [Fact]
    public void DotDoesNotCrossNewlineWithoutSFlag()
    {
        Assert.Empty(MatchHelper.Matches("$a = /a.b/", MatchHelper.Bytes("a\nb")));
        Assert.Single(MatchHelper.Matches("$a = /a.b/s", MatchHelper.Bytes("a\nb")));
    }

    [Fact]
    public void IFlagAndNocaseModifierFoldAsciiCase()
    {
        Assert.Single(MatchHelper.Matches("$a = /abc/i", MatchHelper.Bytes("xAbCx")));
        Assert.Single(MatchHelper.Matches("$a = /abc/ nocase", MatchHelper.Bytes("xABCx")));
    }

    [Fact]
    public void WordBoundaryAssertionsWork()
    {
        var matches = MatchHelper.Matches(@"$a = /\bcat\b/", MatchHelper.Bytes("cat catalog -cat-"));
        Assert.Equal(new[] { new StringMatch(0, 3), new StringMatch(13, 3) }, matches);
    }

    [Fact]
    public void EscapedClassesMatch()
    {
        Assert.Single(MatchHelper.Matches(@"$a = /\d{3}-\d{4}/", MatchHelper.Bytes("call 555-1234 now")));
        // One match per starting offset, like the reference: "ab cd" and "b cd".
        Assert.Equal(new[] { new StringMatch(0, 5), new StringMatch(1, 4) },
            MatchHelper.Matches(@"$a = /\w+\s\w+/", MatchHelper.Bytes("ab cd")));
    }

    [Fact]
    public void WideRegexMatchesUtf16Content()
    {
        var matches = MatchHelper.Matches("$a = /cat[0-9]/ wide", MatchHelper.Wide("xcat7x"));
        Assert.Equal(new[] { new StringMatch(2, 8) }, matches);
    }

    [Fact]
    public void RegexFullwordAppliesBoundaries()
    {
        var matches = MatchHelper.Matches("$a = /cat/ fullword", MatchHelper.Bytes("cat catalog"));
        Assert.Equal(new[] { new StringMatch(0, 3) }, matches);
    }

    [Fact]
    public void AlternationPrefersEarlierBranch()
    {
        // Both branches match at offset 0; leftmost-first semantics pick the first (longer).
        var matches = MatchHelper.Matches("$a = /(abc|ab)/", MatchHelper.Bytes("abc"));
        Assert.Equal(new[] { new StringMatch(0, 3) }, matches);
    }
}

public class BoundaryBufferTests
{
    [Fact]
    public void ZeroByteBufferMatchesNothingCleanly()
    {
        var result = MatchHelper.Scan("""$a = "x" $h = { 41 } $r = /ab/""", []);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.All(result.PerString, s => Assert.Empty(s.Matches));
    }

    [Fact]
    public void OneByteBufferMatchesSingleBytePatterns()
    {
        var result = MatchHelper.Scan("""$a = "A" $h = { 41 }""", MatchHelper.Bytes("A"));
        Assert.Single(result.PerString[0].Matches);
        Assert.Single(result.PerString[1].Matches);
    }
}

public class MatchingBudgetTests
{
    [Fact]
    public void OversizedInputYieldsIncompleteNotScan()
    {
        var budget = ScanBudget.Default with { MaxInputBytes = 8 };
        var result = MatchHelper.Scan("""$a = "x" """, MatchHelper.Bytes("xxxxxxxxxxxx"), budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("byte budget", result.Reason);
        Assert.All(result.PerString, s => Assert.False(s.Complete));
    }

    [Fact]
    public void MatchCapYieldsIncompleteNotOk()
    {
        var budget = ScanBudget.Default with { MaxMatches = 5 };
        var result = MatchHelper.Scan("""$a = "a" """, MatchHelper.Bytes(new string('a', 100)), budget);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("match cap", result.Reason);
        Assert.True(result.PerString[0].Matches.Count <= 5);
        Assert.False(result.PerString[0].Complete);
    }

    [Fact]
    public void SlowPatternIsBudgetedOutAsIncompleteNeverNoMatch()
    {
        // An unanchorable scan: every offset is a candidate and each attempt walks a long
        // window. The per-pattern deadline must cut it and say so.
        var data = new byte[2 * 1024 * 1024];
        Array.Fill(data, (byte)'a');
        var result = MatchHelper.Scan("$a = /a{2000}b/", data);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.False(result.PerString[0].Complete);
        Assert.Contains("budget", result.PerString[0].IncompleteReason);
    }

    [Fact]
    public void WholeScanDeadlineStopsLiteralPass()
    {
        var budget = ScanBudget.Default with { Deadline = TimeSpan.Zero };
        var data = new byte[1024 * 1024];
        var result = MatchHelper.Scan("""$a = "needle" """, data, budget);
        Assert.Equal(OperationState.Incomplete, result.State);
    }

    [Fact]
    public void BudgetCanary_KnownPathologicalPatternIsRejectedAtCompileTime()
    {
        // The canary required by BLUEPRINT §3: a classic catastrophic-backtracking shape.
        // If this assertion ever passes compilation, the resource-safety section has
        // silently become a no-op.
        MatchHelper.AssertCompileError("$a = /(a+)+b/", DiagnosticCode.CatastrophicPattern);
        MatchHelper.AssertCompileError("$a = /([a-z]*)*x/", DiagnosticCode.CatastrophicPattern);
    }

    [Fact]
    public void OversizedCountedRepetitionRejected()
    {
        MatchHelper.AssertCompileError("$a = /x{9999}y/", DiagnosticCode.PatternTooComplex);
    }

    [Fact]
    public void NfaStateExplosionRejected()
    {
        MatchHelper.AssertCompileError("$a = /(abcdefghij){4000}/", DiagnosticCode.PatternTooComplex);
    }

    [Fact]
    public void AllWildcardHexStringRejectedAsUnanchored()
    {
        MatchHelper.AssertCompileError("$a = { ?? ?? ?? }", DiagnosticCode.UnanchoredPattern);
        MatchHelper.AssertCompileError("$a = { ~00 [2-4] ?? }", DiagnosticCode.UnanchoredPattern);
    }

    [Fact]
    public void EmptyMatchingRegexRejected()
    {
        MatchHelper.AssertCompileError("$a = /a*/", DiagnosticCode.EmptyString);
    }
}
