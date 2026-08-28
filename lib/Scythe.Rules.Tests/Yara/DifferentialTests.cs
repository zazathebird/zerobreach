using System.Diagnostics;
using System.Text;
using Scythe.Rules;
using Scythe.Rules.Yara.Matching;
using Xunit;

namespace Scythe.Rules.Tests.Yara;

/// <summary>
/// Differential tests against the reference implementation (the `yara` CLI), when present.
/// Each fixture is compiled and scanned by both engines and the per-string match offsets
/// are compared. When the binary is absent these tests pass vacuously — CI on the owner's
/// machine should have yara installed for them to bite (see HANDOFF_FABLE2.md).
/// </summary>
public class DifferentialMatchTests
{
    private static readonly string? YaraPath = FindYara();

    private static string? FindYara()
    {
        foreach (var p in new[] { "/usr/bin/yara", "/usr/local/bin/yara" })
        {
            if (File.Exists(p))
            {
                return p;
            }
        }
        return null;
    }

    /// <summary>Runs the reference CLI and returns each string's match offsets.</summary>
    private static Dictionary<string, List<int>> RunReference(string ruleSource, byte[] data)
    {
        string dir = Path.Combine(Path.GetTempPath(), "scythe-yara-diff-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string rulePath = Path.Combine(dir, "rule.yar");
            string dataPath = Path.Combine(dir, "data.bin");
            File.WriteAllText(rulePath, ruleSource);
            File.WriteAllBytes(dataPath, data);

            var psi = new ProcessStartInfo(YaraPath!, $"-s \"{rulePath}\" \"{dataPath}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi)!;
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(30_000);
            Assert.True(proc.ExitCode is 0 or 1, $"yara failed: {stderr}");

            var offsets = new Dictionary<string, List<int>>();
            foreach (var line in stdout.Split('\n'))
            {
                // match lines look like: 0x2:$a: YWJj...
                var trimmed = line.TrimEnd('\r');
                if (!trimmed.StartsWith("0x", StringComparison.Ordinal))
                {
                    continue;
                }
                int colon = trimmed.IndexOf(':');
                int colon2 = trimmed.IndexOf(':', colon + 1);
                if (colon < 0 || colon2 < 0)
                {
                    continue;
                }
                int offset = Convert.ToInt32(trimmed[2..colon], 16);
                string name = trimmed[(colon + 1)..colon2].TrimStart('$');
                if (!offsets.TryGetValue(name, out var list))
                {
                    offsets[name] = list = [];
                }
                list.Add(offset);
            }
            return offsets;
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static void AssertSameOffsets(string stringsSection, byte[] data)
    {
        if (YaraPath is null)
        {
            return; // reference binary not installed; vacuous here, exercised on CI
        }
        string ruleSource = $"rule t {{ strings: {stringsSection} condition: any of them }}";

        var (set, diags) = MatchHelper.CompileStrings(stringsSection);
        Assert.True(set is not null, "our compile failed: " + string.Join("; ", diags));
        var ours = StringScanner.Scan(set!, data, ScanBudget.Default);
        Assert.Equal(OperationState.Ok, ours.State);

        var reference = RunReference(ruleSource, data);

        for (int i = 0; i < set!.StringCount; i++)
        {
            var info = set.StringInfo(i);
            var ourOffsets = ours.PerString[i].Matches.Select(m => m.Offset).Distinct().ToList();
            var refOffsets = reference.TryGetValue(info.Identifier, out var r) ? r.Distinct().Order().ToList() : [];
            Assert.True(ourOffsets.SequenceEqual(refOffsets),
                $"${info.Identifier}: ours [{string.Join(",", ourOffsets)}] vs reference [{string.Join(",", refOffsets)}] " +
                $"on data {Convert.ToHexString(data[..Math.Min(64, data.Length)])}");
        }
    }

    public static IEnumerable<object[]> Fixtures()
    {
        static object[] F(string strings, byte[] data) => [strings, data];
        byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

        yield return F("""$a = "hello" """, Ascii("say hello, hello!"));
        yield return F("""$a = "aa" """, Ascii("aaaaa"));
        yield return F("""$a = "Mixed" nocase""", Ascii("mixed MIXED MiXeD mixEd"));
        yield return F("""$a = "wide" wide""", MatchHelper.Wide("some wide text"));
        yield return F("""$a = "both" wide ascii""", Ascii("both.").Concat(MatchHelper.Wide("both")).ToArray());
        yield return F("""$a = "word" fullword""", Ascii("word sword words word. word_ 2word (word)"));
        yield return F("""$a = "w" fullword""", Ascii("w wx w-w xw w"));
        yield return F("""$a = "cat" wide fullword""", MatchHelper.Wide("Acat cat catx cat"));
        yield return F("""$a = "secret" xor""", Ascii("secret.").Concat(Ascii("secret.").Select(b => (byte)(b ^ 0x5A))).ToArray());
        yield return F("""$a = "secret" xor(1-10)""", Ascii("secret.").Concat(Ascii("secret.").Select(b => (byte)(b ^ 0x07))).ToArray());
        yield return F("""$a = "payload" base64""", Ascii("xx cGF5bG9hZA xx GF5bG9hZ xx BheWxvYWQ xx"));
        yield return F("""$a = "payload" base64wide""", MatchHelper.Wide("+cGF5bG9hZA+"));
        yield return F("""$a = "payload" base64 wide""", Ascii("xcABhAHkAbABvAGEAZAAx"));
        yield return F("$a = { 4D 5A 90 }", new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x4D, 0x5A, 0x90 });
        yield return F("$a = { 4D ?? 90 }", new byte[] { 0x4D, 0x11, 0x90, 0x4D, 0x22, 0x90, 0x4D, 0x22, 0x91 });
        yield return F("$a = { 4? ?A }", new byte[] { 0x41, 0x2A, 0x51, 0x1A, 0x4F, 0xAA });
        yield return F("$a = { 41 [2-4] 42 }", Ascii("A..B A...B A....B A.B AB"));
        yield return F("$a = { 41 [0-] 42 }", Ascii("A-------B-B"));
        yield return F("$a = { 61 ( 41 | 42 43 ) 7A }", Ascii("aAz aBCz aCz aBz"));
        yield return F("$a = { 41 ~00 42 }", new byte[] { 0x41, 0x00, 0x42, 0x41, 0x7F, 0x42 });
        yield return F("$a = /ab[0-9]{2,4}cd/", Ascii("ab12cd ab123cd ab12345cd abcd"));
        yield return F("$a = /a.*b/", Ascii("aXbYb"));
        yield return F("$a = /a.*?b/", Ascii("aXbYb"));
        yield return F("$a = /^MZ/", Ascii("MZ..MZ"));
        yield return F("$a = /end$/", Ascii("the end"));
        yield return F(@"$a = /\bcat\b/", Ascii("cat catalog -cat- bobcat"));
        yield return F(@"$a = /\d+\.\d+/", Ascii("v 1.25 and 33.4."));
        yield return F("$a = /hex[a-f0-9]{2}/i", Ascii("HEXab hexZZ HeX99"));
        yield return F("$a = /wide[0-9]/ wide", MatchHelper.Wide("xxwide7yy"));
        yield return F("$a = /(abc|ab|a)d/", Ascii("abcd abd ad"));
        yield return F("$a = /a(b|c)*d/", Ascii("ad abd abcbcd axd"));
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void MatchOffsetsAgreeWithReference(string stringsSection, byte[] data) =>
        AssertSameOffsets(stringsSection, data);

    [Fact]
    public void SeededRandomDataAgreesWithReference()
    {
        if (YaraPath is null)
        {
            return;
        }
        // Deterministic pseudo-random buffer with planted needles.
        var rng = new Random(0xBEEF);
        var data = new byte[64 * 1024];
        rng.NextBytes(data);
        var needle = Encoding.ASCII.GetBytes("N33dle!");
        foreach (int pos in new[] { 0, 1000, 30_000, data.Length - needle.Length })
        {
            needle.CopyTo(data, pos);
        }
        AssertSameOffsets("""
            $a = "N33dle!"
            $b = "n33DLE!" nocase
            $c = { 4E 33 33 ?? 6C 65 }
            $d = /N[0-9]{2}dle/
            """, data);
    }
}
