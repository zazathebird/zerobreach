using ZeroBreach.Rules;
using ZeroBreach.Rules.Sigma;
using Xunit;
using static ZeroBreach.Rules.Tests.Sigma.SigmaTestHelpers;

namespace ZeroBreach.Rules.Tests.Sigma;

/// <summary>Value-matching semantics: modifiers, wildcards, null-vs-missing, case
/// insensitivity, lists, multi-valued fields, keywords.</summary>
public sealed class SigmaMatchTests
{
    private static CompiledSigmaRule DetectionRule(string detectionBody)
    {
        // detectionBody lines must be indented by two spaces already.
        string yaml = "title: T\nlogsource:\n  product: windows\ndetection:\n" + detectionBody;
        return MustCompile(yaml);
    }

    // ---- plain values, wildcards, exact anchoring -------------------------------------

    [Fact]
    public void PlainValue_MatchesWholeValue_CaseInsensitively()
    {
        var rule = DetectionRule("  sel:\n    User: 'admin'\n  condition: sel");
        AssertHit(rule, ("User", "admin"));
        AssertHit(rule, ("User", "ADMIN"));
        AssertMiss(rule, ("User", "administrator")); // anchored: not a prefix test
        AssertMiss(rule, ("User", "xadmin"));
    }

    [Fact]
    public void FieldNameLookup_IsCaseInsensitive()
    {
        var rule = DetectionRule("  sel:\n    commandline|contains: 'foo'\n  condition: sel");
        AssertHit(rule, ("CommandLine", "run foo now"));
        AssertHit(rule, ("COMMANDLINE", "foo"));
        AssertMiss(rule, ("OtherField", "foo"));
    }

    [Fact]
    public void StarWildcard_MatchesAnyRun_IncludingEmpty()
    {
        var rule = DetectionRule("  sel:\n    Image: '*\\svchost.exe'\n  condition: sel");
        AssertHit(rule, ("Image", @"C:\Windows\System32\svchost.exe"));
        AssertHit(rule, ("Image", @"\svchost.exe"));
        AssertMiss(rule, ("Image", "svchost.exe"));       // '*' must still leave '\svchost.exe'
        AssertMiss(rule, ("Image", @"C:\svchost.exe.bak"));
    }

    [Fact]
    public void QuestionMarkWildcard_MatchesExactlyOneCharacter()
    {
        var rule = DetectionRule("  sel:\n    File: 'file?.txt'\n  condition: sel");
        AssertHit(rule, ("File", "file1.txt"));
        AssertHit(rule, ("File", "fileX.txt"));
        AssertMiss(rule, ("File", "file.txt"));
        AssertMiss(rule, ("File", "file12.txt"));
    }

    [Fact]
    public void EscapedWildcard_IsLiteral()
    {
        var rule = DetectionRule("  sel:\n    F: 'a\\*b'\n  condition: sel");
        AssertHit(rule, ("F", "a*b"));
        AssertMiss(rule, ("F", "aXb"));
    }

    [Fact]
    public void SingleBackslash_BeforeNonWildcard_IsLiteral()
    {
        // Sigma escaping: single '\' before a non-wildcard means itself, so Windows paths
        // written naturally in rules mean what they say.
        var rule = DetectionRule("  sel:\n    Path: 'C:\\Windows\\cmd.exe'\n  condition: sel");
        AssertHit(rule, ("Path", @"C:\Windows\cmd.exe"));
        AssertMiss(rule, ("Path", "C:Windowscmd.exe"));
    }

    [Fact]
    public void DoubleBackslash_IsOneLiteralBackslash()
    {
        var rule = DetectionRule("  sel:\n    Path: 'C:\\\\Windows'\n  condition: sel");
        AssertHit(rule, ("Path", @"C:\Windows"));
        AssertMiss(rule, ("Path", @"C:\\Windows"));
    }

    // ---- contains / startswith / endswith ---------------------------------------------

    [Fact]
    public void Contains_MatchesSubstring_CaseInsensitively()
    {
        var rule = DetectionRule("  sel:\n    CommandLine|contains: '-enc'\n  condition: sel");
        AssertHit(rule, ("CommandLine", "powershell -ENC SQBFAFgA"));
        AssertHit(rule, ("CommandLine", "-enc"));
        AssertMiss(rule, ("CommandLine", "powershell -e n c"));
    }

    [Fact]
    public void StartsWith_AnchorsAtStartOnly()
    {
        var rule = DetectionRule("  sel:\n    User|startswith: 'SYSTEM'\n  condition: sel");
        AssertHit(rule, ("User", "SYSTEM"));
        AssertHit(rule, ("User", "system-account"));
        AssertMiss(rule, ("User", "NT SYSTEM"));
    }

    [Fact]
    public void EndsWith_AnchorsAtEndOnly()
    {
        var rule = DetectionRule("  sel:\n    Image|endswith: '\\rundll32.exe'\n  condition: sel");
        AssertHit(rule, ("Image", @"C:\Windows\rundll32.exe"));
        AssertMiss(rule, ("Image", @"C:\Windows\rundll32.exe.bak"));
    }

    // ---- value lists and 'all' --------------------------------------------------------

    [Fact]
    public void ValueList_IsOr()
    {
        var rule = DetectionRule("  sel:\n    EventID:\n      - 4624\n      - 4625\n  condition: sel");
        AssertHit(rule, ("EventID", 4624));
        AssertHit(rule, ("EventID", 4625));
        AssertMiss(rule, ("EventID", 4688));
    }

    [Fact]
    public void MultipleKeys_AreAnd()
    {
        var rule = DetectionRule(
            "  sel:\n    EventID: 4688\n    CommandLine|contains: '-enc'\n  condition: sel");
        AssertHit(rule, ("EventID", 4688), ("CommandLine", "x -enc y"));
        AssertMiss(rule, ("EventID", 4688), ("CommandLine", "benign"));
        AssertMiss(rule, ("EventID", 1), ("CommandLine", "x -enc y"));
    }

    [Fact]
    public void AllModifier_TurnsValueListIntoAnd()
    {
        var rule = DetectionRule(
            "  sel:\n    CommandLine|contains|all:\n      - '-nop'\n      - '-enc'\n  condition: sel");
        AssertHit(rule, ("CommandLine", "ps -nop -w hidden -enc AAA"));
        AssertMiss(rule, ("CommandLine", "ps -nop"));
        AssertMiss(rule, ("CommandLine", "ps -enc AAA"));
    }

    [Fact]
    public void SelectionAsListOfMaps_IsOrAcrossTheMaps()
    {
        var rule = DetectionRule(
            "  sel:\n    - EventID: 1\n      Image|endswith: '\\a.exe'\n    - EventID: 7\n  condition: sel");
        AssertHit(rule, ("EventID", 1), ("Image", @"C:\a.exe"));
        AssertHit(rule, ("EventID", 7), ("Image", @"C:\b.exe"));
        AssertMiss(rule, ("EventID", 1), ("Image", @"C:\b.exe"));
    }

    // ---- null versus missing ----------------------------------------------------------

    [Fact]
    public void NullValue_MatchesPresentNullField_NotMissingField()
    {
        var rule = DetectionRule("  sel:\n    ParentImage: null\n  condition: sel");
        // Present with null value: a match.
        AssertHit(rule, ("ParentImage", null));
        // Missing entirely: not a match (task brief pins missing as distinct from null).
        AssertMiss(rule, ("OtherField", "x"));
        // Present with a real value: not a match.
        AssertMiss(rule, ("ParentImage", @"C:\explorer.exe"));
    }

    [Fact]
    public void MissingField_NeverSatisfiesAnyValueTest()
    {
        var rule = DetectionRule("  sel:\n    CommandLine|contains: 'x'\n  condition: sel");
        AssertMiss(rule); // empty record
        // Null value is not "contains x" either.
        AssertMiss(rule, ("CommandLine", null));
    }

    [Fact]
    public void EmptyString_IsDistinctFromNull()
    {
        var empty = DetectionRule("  sel:\n    F: ''\n  condition: sel");
        AssertHit(empty, ("F", ""));
        AssertMiss(empty, ("F", null));

        var isNull = DetectionRule("  sel:\n    F: null\n  condition: sel");
        AssertMiss(isNull, ("F", ""));
        AssertHit(isNull, ("F", null));
    }

    // ---- typed record values ----------------------------------------------------------

    [Fact]
    public void NumbersAndStrings_CompareByInvariantStringForm()
    {
        var rule = DetectionRule("  sel:\n    EventID: 4688\n  condition: sel");
        AssertHit(rule, ("EventID", 4688));
        AssertHit(rule, ("EventID", 4688L));
        AssertHit(rule, ("EventID", "4688"));
        AssertMiss(rule, ("EventID", 4689));
    }

    [Fact]
    public void BooleanValues_Match_CaseInsensitively()
    {
        var rule = DetectionRule("  sel:\n    Elevated: true\n  condition: sel");
        AssertHit(rule, ("Elevated", true));
        AssertHit(rule, ("Elevated", "True"));
        AssertMiss(rule, ("Elevated", false));
    }

    [Fact]
    public void MultiValuedRecordField_MatchesIfAnyElementMatches()
    {
        var rule = DetectionRule("  sel:\n    Hashes|contains: 'SHA256='\n  condition: sel");
        AssertHit(rule, ("Hashes", new object?[] { "MD5=abc", "SHA256=def" }));
        AssertMiss(rule, ("Hashes", new object?[] { "MD5=abc", "IMPHASH=def" }));
    }

    // ---- keyword selections -----------------------------------------------------------

    [Fact]
    public void KeywordList_MatchesAnyKeywordInAnyField()
    {
        var rule = DetectionRule("  keywords:\n    - 'mimikatz'\n    - 'sekurlsa::'\n  condition: keywords");
        AssertHit(rule, ("CommandLine", "run Mimikatz now"), ("User", "bob"));
        AssertHit(rule, ("Details", "privilege::debug sekurlsa::logonpasswords"));
        AssertMiss(rule, ("CommandLine", "notepad.exe"), ("User", "bob"));
    }

    [Fact]
    public void Keyword_WithWildcard_IsHonoured()
    {
        var rule = DetectionRule("  keywords:\n    - 'lsass?dmp'\n  condition: keywords");
        AssertHit(rule, ("CommandLine", "procdump -ma lsass.dmp"));
        AssertHit(rule, ("CommandLine", "lsass_dmp"));
        AssertMiss(rule, ("CommandLine", "lsassdmp"));
    }

    // ---- windash ----------------------------------------------------------------------

    [Theory]
    [InlineData("-nop")]
    [InlineData("/nop")]
    [InlineData("–nop")] // en dash U+2013
    [InlineData("—nop")] // em dash U+2014
    [InlineData("―nop")] // horizontal bar U+2015
    public void Windash_MatchesEveryDashVariant(string actual)
    {
        var rule = DetectionRule("  sel:\n    CommandLine|windash|contains: '-nop'\n  condition: sel");
        AssertHit(rule, ("CommandLine", $"powershell {actual} -w hidden"));
    }

    [Fact]
    public void Windash_HandlesMixedVariantsPerOccurrence()
    {
        var rule = DetectionRule("  sel:\n    CommandLine|windash|contains: '-nop -enc'\n  condition: sel");
        // Different variants for different occurrences in the same value.
        AssertHit(rule, ("CommandLine", "ps /nop –enc AAA"));
        AssertMiss(rule, ("CommandLine", "ps nop enc"));
    }

    [Fact]
    public void Windash_AlsoCanonicalisesSlashesWrittenInTheRule()
    {
        var rule = DetectionRule("  sel:\n    CommandLine|windash|contains: '/q'\n  condition: sel");
        AssertHit(rule, ("CommandLine", "wevtutil cl Security -q"));
    }

    [Fact]
    public void WithoutWindash_DashVariantsDoNotMatch()
    {
        var rule = DetectionRule("  sel:\n    CommandLine|contains: '-nop'\n  condition: sel");
        AssertMiss(rule, ("CommandLine", "powershell /nop"));
        AssertMiss(rule, ("CommandLine", "powershell –nop"));
    }

    // ---- re ---------------------------------------------------------------------------

    [Fact]
    public void Re_IsUnanchoredSearch()
    {
        var rule = DetectionRule("  sel:\n    CommandLine|re: '[0-9]{4}'\n  condition: sel");
        AssertHit(rule, ("CommandLine", "abc 1234 def"));
        AssertMiss(rule, ("CommandLine", "abc 123 def"));
    }

    [Fact]
    public void Re_IsCaseSensitive_UnlikePlainValues()
    {
        // Pinned: reference Sigma regexes are the one value form that is case-sensitive
        // by default.
        var rule = DetectionRule("  sel:\n    CommandLine|re: 'Invoke-Mimikatz'\n  condition: sel");
        AssertHit(rule, ("CommandLine", "Invoke-Mimikatz -DumpCreds"));
        AssertMiss(rule, ("CommandLine", "invoke-mimikatz -DumpCreds"));
    }

    [Fact]
    public void Re_ListIsOr()
    {
        var rule = DetectionRule("  sel:\n    F|re:\n      - 'aaa[0-9]'\n      - 'bbb[0-9]'\n  condition: sel");
        AssertHit(rule, ("F", "xx aaa1"));
        AssertHit(rule, ("F", "xx bbb2"));
        AssertMiss(rule, ("F", "aaa bbb"));
    }

    [Fact]
    public void Re_NullFieldValue_IsNotAMatch()
    {
        var rule = DetectionRule("  sel:\n    F|re: '.*'\n  condition: sel");
        AssertMiss(rule, ("F", null));
    }

    // ---- cidr -------------------------------------------------------------------------

    [Fact]
    public void Cidr_Ipv4_InsideAndOutside()
    {
        var rule = DetectionRule("  sel:\n    DestinationIp|cidr: '192.168.0.0/16'\n  condition: sel");
        AssertHit(rule, ("DestinationIp", "192.168.4.20"));
        AssertHit(rule, ("DestinationIp", "192.168.255.255"));
        AssertMiss(rule, ("DestinationIp", "192.169.0.1"));
        AssertMiss(rule, ("DestinationIp", "10.0.0.1"));
    }

    [Fact]
    public void Cidr_Ipv4_NonOctetAlignedPrefix()
    {
        var rule = DetectionRule("  sel:\n    Ip|cidr: '10.0.0.0/9'\n  condition: sel");
        AssertHit(rule, ("Ip", "10.127.0.1"));
        AssertMiss(rule, ("Ip", "10.128.0.1"));
    }

    [Fact]
    public void Cidr_Ipv6_InsideAndOutside()
    {
        var rule = DetectionRule("  sel:\n    Ip|cidr: '2001:db8::/32'\n  condition: sel");
        AssertHit(rule, ("Ip", "2001:db8::1"));
        AssertHit(rule, ("Ip", "2001:0db8:ffff::42"));
        AssertMiss(rule, ("Ip", "2001:db9::1"));
    }

    [Fact]
    public void Cidr_ValueList_IsOr()
    {
        var rule = DetectionRule(
            "  sel:\n    Ip|cidr:\n      - '10.0.0.0/8'\n      - 'fe80::/10'\n  condition: sel");
        AssertHit(rule, ("Ip", "10.1.2.3"));
        AssertHit(rule, ("Ip", "fe80::1234"));
        AssertMiss(rule, ("Ip", "172.16.0.1"));
    }

    [Fact]
    public void Cidr_NonAddressText_IsNotAMatch()
    {
        var rule = DetectionRule("  sel:\n    Ip|cidr: '0.0.0.0/0'\n  condition: sel");
        AssertMiss(rule, ("Ip", "not-an-ip"));
        // IPAddress.TryParse would read "1" as 0.0.0.1 — lenient integer forms must not
        // count as addresses on attacker-chosen text.
        AssertMiss(rule, ("Ip", "1"));
        AssertMiss(rule, ("Ip", ""));
        AssertMiss(rule, ("Ip", null));
    }

    [Fact]
    public void Cidr_Ipv4MappedIpv6RecordValue_MatchesIpv4Network()
    {
        var rule = DetectionRule("  sel:\n    Ip|cidr: '192.168.0.0/16'\n  condition: sel");
        AssertHit(rule, ("Ip", "::ffff:192.168.1.1"));
    }

    // ---- base64 / base64offset --------------------------------------------------------

    [Fact]
    public void Base64_MatchesEncodedValue()
    {
        // base64("cmd.exe") == "Y21kLmV4ZQ=="
        var rule = DetectionRule("  sel:\n    CommandLine|base64|contains: 'cmd.exe'\n  condition: sel");
        AssertHit(rule, ("CommandLine", "run Y21kLmV4ZQ== now"));
        AssertMiss(rule, ("CommandLine", "run cmd.exe now")); // the plain text itself is not the target
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Base64Offset_MatchesAtEveryAlignment(int prefixLength)
    {
        // The encoded stream carries the value behind 0, 1 or 2 preceding bytes; plain
        // base64 only ever matches one of the three alignments, base64offset matches all.
        var rule = DetectionRule("  sel:\n    CommandLine|base64offset|contains: 'http://evil.example'\n  condition: sel");
        string plaintext = new string('A', prefixLength) + "http://evil.example/payload";
        string encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(plaintext));
        AssertHit(rule, ("CommandLine", $"powershell -enc {encoded}"));
    }

    [Fact]
    public void Base64Offset_DoesNotMatchUnrelatedBase64()
    {
        var rule = DetectionRule("  sel:\n    CommandLine|base64offset|contains: 'http://evil.example'\n  condition: sel");
        string benign = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("completely unrelated text"));
        AssertMiss(rule, ("CommandLine", benign));
    }

    [Fact]
    public void PlainBase64_MissesShiftedAlignment_WhichBase64OffsetCatches()
    {
        // This is the whole reason base64offset exists; if the offset variants ever
        // regress to plain base64, this pins the difference.
        var plain = DetectionRule("  sel:\n    C|base64|contains: 'http://evil.example'\n  condition: sel");
        var offset = DetectionRule("  sel:\n    C|base64offset|contains: 'http://evil.example'\n  condition: sel");
        string shifted = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("Xhttp://evil.example/x"));
        AssertMiss(plain, ("C", shifted));
        AssertHit(offset, ("C", shifted));
    }

    // ---- logsource --------------------------------------------------------------------

    [Fact]
    public void Logsource_GatesEvaluation_WhenRecordSourceIsSupplied()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4624\n  condition: sel");
        var record = Record(("EventID", 4624));

        var applies = rule.Evaluate(record, new SigmaLogsource(Product: "Windows", Service: "Security"));
        Assert.Equal(OperationState.Ok, applies.State);
        Assert.True(applies.IsMatch);
        Assert.True(applies.LogsourceMatched);

        var wrongProduct = rule.Evaluate(record, new SigmaLogsource(Product: "linux", Service: "security"));
        Assert.Equal(OperationState.Ok, wrongProduct.State);
        Assert.False(wrongProduct.IsMatch);
        Assert.False(wrongProduct.LogsourceMatched);

        // A record source that omits a component the rule requires cannot satisfy it.
        var missingService = rule.Evaluate(record, new SigmaLogsource(Product: "windows"));
        Assert.False(missingService.IsMatch);
        Assert.False(missingService.LogsourceMatched);
    }

    [Fact]
    public void Logsource_ComponentsTheRuleOmits_AreWildcards()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel");
        var result = rule.Evaluate(Record(("EventID", 1)),
            new SigmaLogsource(Product: "windows", Category: "process_creation", Service: "sysmon"));
        Assert.True(result.IsMatch);
    }

    [Fact]
    public void NoRecordLogsource_MeansNoGating()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel");
        var result = rule.Evaluate(Record(("EventID", 1)));
        Assert.True(result.IsMatch);
        Assert.True(result.LogsourceMatched);
    }

    // ---- field name map ---------------------------------------------------------------

    [Fact]
    public void FieldNameMap_RedirectsRuleFieldToRecordField()
    {
        var rule = MustCompile(
            "title: T\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image|endswith: '\\cmd.exe'\n  condition: sel");
        var options = new SigmaEvaluationOptions
        {
            FieldNameMap = new Dictionary<string, string> { ["Image"] = "ProcessPath" },
        };
        var record = Record(("ProcessPath", @"C:\Windows\cmd.exe"));
        var mapped = rule.Evaluate(record, options: options);
        Assert.True(mapped.IsMatch);
        // Without the map the rule field name is looked up directly and misses.
        var unmapped = rule.Evaluate(record);
        Assert.False(unmapped.IsMatch);
    }
}
