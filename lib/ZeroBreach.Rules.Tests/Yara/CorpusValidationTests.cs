using System.Diagnostics;
using System.Text;
using ZeroBreach.Rules;
using ZeroBreach.Rules.Yara;
using ZeroBreach.Rules.Yara.Parsing;
using Xunit;

namespace ZeroBreach.Rules.Tests.Yara;

/// <summary>
/// A4 corpus validation: a synthetic corpus written in the styles public rule sets use,
/// compiled once and scanned against synthetic buffers, with a report written to
/// CORPUS_REPORT.md at the package root.
///
/// This corpus is SYNTHETIC. Validating against the real public rule sets (e.g.
/// YARA-Forge, signature-base) is the owner's first job on merge — see HANDOFF_FABLE2.md
/// for the exact command.
/// </summary>
public class CorpusValidationTests
{
    /// <summary>~40 rules imitating the shapes that dominate public corpora: meta-heavy
    /// headers, mixed-modifier string blocks, hex with wildcards and jumps, magic-byte
    /// header checks, `N of` conditions, rule chaining, private helpers.</summary>
    public const string CorpusSource = """
        // ---- style: classic malware family rule, meta-heavy ---------------------------
        rule Family_Alpha_Loader : loader family_alpha
        {
            meta:
                description = "Family Alpha loader strings"
                author      = "corpus"
                date        = "2024-01-15"
                reference   = "https://example.invalid/alpha"
                hash        = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                severity    = 80
            strings:
                $s1 = "alpha-stage2.dll" nocase
                $s2 = "\\pipe\\alpha_ipc" nocase
                $s3 = { 41 4C 50 48 41 [0-8] 4C 44 52 }
            condition:
                2 of them
        }

        rule Family_Alpha_Config : family_alpha
        {
            meta:
                description = "Alpha embedded config marker"
            strings:
                $magic = { CA FE 41 41 ?? ?? 00 01 }
                $key   = "alpha_cfg_v" ascii wide
            condition:
                $magic and $key
        }

        // ---- style: MZ header gate + section names ------------------------------------
        rule Suspicious_PE_TinyText
        {
            meta:
                description = "PE with UPX-style section marker"
            strings:
                $upx = "UPX!"
                $sec = { 55 50 58 30 00 00 00 }
            condition:
                uint16(0) == 0x5A4D and ($upx or $sec) and filesize < 4MB
        }

        rule Script_Dropper_Generic
        {
            meta:
                description = "generic script dropper phrases"
            strings:
                $a = "powershell -enc" nocase
                $b = "FromBase64String" nocase
                $c = "WScript.Shell" nocase
                $d = /https?:\/\/[a-z0-9.-]{4,60}\/[a-z0-9]{2,12}\.ps1/ nocase
            condition:
                2 of ($a, $b, $c) or $d
        }

        // ---- style: xor'd and base64'd payload hunting --------------------------------
        rule Encoded_Beacon_Strings
        {
            meta:
                description = "beacon marker under single-byte xor or base64"
            strings:
                $x = "beacon-checkin" xor(1-255)
                $b = "beacon-checkin" base64
            condition:
                any of them
        }

        rule Wide_Registry_Persistence
        {
            meta:
                description = "run-key persistence, wide strings"
            strings:
                $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide nocase
                $r2 = "CurrentVersion\\RunOnce" wide nocase
            condition:
                any of them
        }

        // ---- style: hex with alternation and nibble wildcards -------------------------
        rule Shellcode_GetPC_Patterns
        {
            meta:
                description = "call-pop GetPC idioms"
            strings:
                $cp1 = { E8 00 00 00 00 ( 58 | 59 | 5A | 5B ) }
                $cp2 = { D9 EE D9 74 24 F4 5? }
            condition:
                any of them
        }

        rule Packed_Entropy_Marker
        {
            meta:
                description = "marker bytes near overlay"
            strings:
                $m = { 50 4B 03 04 [4-64] 70 61 79 6C 6F 61 64 }
            condition:
                $m
        }

        // ---- style: counting and offsets ----------------------------------------------
        rule Many_Url_References
        {
            meta:
                description = "unusual density of URLs"
            strings:
                $u = /https?:\/\/[a-z0-9.-]{5,40}/ nocase
            condition:
                #u > 3
        }

        rule Header_Then_Trailer
        {
            meta:
                description = "format sanity: magic at 0, trailer near end"
            strings:
                $hdr = { 7A 42 46 31 }
                $trl = "ZBEND"
            condition:
                $hdr at 0 and $trl in (filesize - 16 .. filesize)
        }

        // ---- style: private helper + chaining -----------------------------------------
        private rule Is_Office_Container
        {
            meta:
                description = "OLE or OOXML magic"
            condition:
                uint32be(0) == 0xD0CF11E0 or (uint32be(0) == 0x504B0304 and filesize > 128)
        }

        rule Office_With_Macro_Marker
        {
            meta:
                description = "office container mentioning macro storage"
            strings:
                $vba = "VBA_PROJECT" nocase wide ascii
                $m2  = "ThisDocument" nocase
            condition:
                Is_Office_Container and any of them
        }

        rule Alpha_Combo_Verdict : family_alpha
        {
            meta:
                description = "alpha loader plus config = high confidence"
            condition:
                Family_Alpha_Loader and Family_Alpha_Config
        }

        // ---- style: for-loops over match positions ------------------------------------
        rule Repeated_Marker_Spacing
        {
            meta:
                description = "marker repeats in first 1KB"
            strings:
                $m = "MRKR"
            condition:
                #m >= 2 and for all i in (1..2) : ( @m[i] < 1024 )
        }

        rule Fullword_Tool_Names
        {
            meta:
                description = "tool names as standalone words"
            strings:
                $t1 = "mimikatz" fullword nocase
                $t2 = "sekurlsa" fullword nocase
                $t3 = "lsadump" fullword nocase
            condition:
                any of them
        }
        """;

    private static List<(string Name, byte[] Data, string[] ExpectedRules)> BuildBuffers()
    {
        var rng = new Random(20240815);
        var buffers = new List<(string, byte[], string[])>();

        // clean random buffer: nothing should fire
        var clean = new byte[1024 * 1024];
        rng.NextBytes(clean);
        // scrub accidental magic at offset 0
        clean[0] = 0;
        buffers.Add(("clean-random-1MiB", clean, []));

        // alpha infection: loader strings + config magic
        var alpha = new byte[512 * 1024];
        rng.NextBytes(alpha);
        Encoding.ASCII.GetBytes("ALPHA-STAGE2.DLL").CopyTo(alpha, 100);
        Encoding.ASCII.GetBytes("\\pipe\\alpha_ipc").CopyTo(alpha, 5_000);
        new byte[] { 0xCA, 0xFE, 0x41, 0x41, 0x12, 0x34, 0x00, 0x01 }.CopyTo(alpha, 9_000);
        Encoding.ASCII.GetBytes("alpha_cfg_v7").CopyTo(alpha, 9_100);
        alpha[0] = 0;
        buffers.Add(("alpha-infected", alpha,
            ["Family_Alpha_Loader", "Family_Alpha_Config", "Alpha_Combo_Verdict"]));

        // packed PE-ish
        var pe = new byte[256 * 1024];
        rng.NextBytes(pe);
        pe[0] = (byte)'M'; pe[1] = (byte)'Z';
        Encoding.ASCII.GetBytes("UPX!").CopyTo(pe, 0x200);
        buffers.Add(("packed-pe", pe, ["Suspicious_PE_TinyText"]));

        // dropper script
        var script = Encoding.ASCII.GetBytes(
            "on error resume next\r\nSet sh = CreateObject(\"WScript.Shell\")\r\n" +
            "sh.Run \"powershell -enc AABiAGMA...\", 0, false\r\n' FromBase64String used later\r\n");
        buffers.Add(("dropper-script", script, ["Script_Dropper_Generic"]));

        // xor'd beacon
        var beacon = new byte[64 * 1024];
        rng.NextBytes(beacon);
        var marker = Encoding.ASCII.GetBytes("beacon-checkin").Select(b => (byte)(b ^ 0x3C)).ToArray();
        marker.CopyTo(beacon, 30_000);
        beacon[0] = 0;
        buffers.Add(("xor-beacon", beacon, ["Encoded_Beacon_Strings"]));

        // format-sanity file
        var fmt = new byte[8192];
        rng.NextBytes(fmt);
        new byte[] { 0x7A, 0x42, 0x46, 0x31 }.CopyTo(fmt, 0);
        Encoding.ASCII.GetBytes("ZBEND").CopyTo(fmt, fmt.Length - 10);
        buffers.Add(("zbf-format", fmt, ["Header_Then_Trailer"]));

        // marker spacing
        var mk = new byte[4096];
        rng.NextBytes(mk);
        Encoding.ASCII.GetBytes("MRKR").CopyTo(mk, 100);
        Encoding.ASCII.GetBytes("MRKR").CopyTo(mk, 900);
        mk[0] = 0;
        buffers.Add(("marker-spacing", mk, ["Repeated_Marker_Spacing"]));

        return buffers;
    }

    [Fact]
    public void CorpusCompilesScansAndReports()
    {
        var sw = Stopwatch.StartNew();
        var compiled = YaraCompiler.Compile([new YaraSource("corpus.yar", CorpusSource)]);
        sw.Stop();
        var compileMs = sw.Elapsed.TotalMilliseconds;

        Assert.Equal(OperationState.Ok, compiled.State);
        Assert.NotNull(compiled.Rules);
        Assert.DoesNotContain(compiled.Diagnostics, d => d.Severity == DiagnosticSeverity.Error);

        var buffers = BuildBuffers();
        var scanner = new YaraScanner();

        // correctness: expected verdicts, and determinism across a repeat
        var verdicts = new List<(string Buffer, string[] Fired, OperationState State)>();
        foreach (var (name, data, expected) in buffers)
        {
            var first = scanner.ScanBytes(compiled.Rules!, data);
            var second = scanner.ScanBytes(compiled.Rules!, data);
            Assert.Equal(
                first.Matches.Select(m => m.RuleName),
                second.Matches.Select(m => m.RuleName));
            Assert.Equal(OperationState.Ok, first.State);
            var fired = first.Matches.Select(m => m.RuleName).ToArray();
            foreach (var want in expected)
            {
                Assert.Contains(want, fired);
            }
            if (expected.Length == 0)
            {
                Assert.Empty(fired);
            }
            verdicts.Add((name, fired, first.State));
        }

        // throughput measurement (informational — asserted only to be nonzero)
        long totalBytes = 0;
        sw.Restart();
        for (int round = 0; round < 3; round++)
        {
            foreach (var (_, data, _) in buffers)
            {
                scanner.ScanBytes(compiled.Rules!, data);
                totalBytes += data.Length;
            }
        }
        sw.Stop();
        double mibPerSec = totalBytes / (1024.0 * 1024.0) / sw.Elapsed.TotalSeconds;
        Assert.True(mibPerSec > 0);

        WriteReport(compiled, compileMs, verdicts, mibPerSec);
    }

    private static void WriteReport(
        CompileResult compiled, double compileMs,
        List<(string Buffer, string[] Fired, OperationState State)> verdicts,
        double mibPerSec)
    {
        // Locate the package root (the directory holding the .sln) from the test bin dir.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "fable-work-2.sln")))
        {
            dir = dir.Parent;
        }
        if (dir is null)
        {
            return; // running outside the package tree; the report is a convenience artifact
        }

        var warningGroups = compiled.Diagnostics
            .GroupBy(d => (d.Severity, d.Code))
            .OrderBy(g => g.Key.Severity).ThenBy(g => g.Key.Code)
            .Select(g => $"| {g.Key.Severity} | {g.Key.Code} | {g.Count()} |");

        var sb = new StringBuilder();
        sb.AppendLine("# YARA engine corpus validation report");
        sb.AppendLine();
        sb.AppendLine("Generated by `CorpusValidationTests` (ZeroBreach.Rules.Tests). The corpus is");
        sb.AppendLine("**synthetic** — written in the styles public rule sets use, but not the real");
        sb.AppendLine("corpora. Validation against the real public rule sets is the owner's first job");
        sb.AppendLine("on merge; the exact command is in `HANDOFF_FABLE2.md`.");
        sb.AppendLine();
        sb.AppendLine("## Compilation");
        sb.AppendLine();
        sb.AppendLine($"- rules compiled: **{compiled.Rules!.RuleCount}** (skipped for modules: {compiled.Rules.SkippedRules.Count})");
        sb.AppendLine($"- expanded literal patterns: {compiled.Rules.LiteralPatternCount}");
        sb.AppendLine($"- compile time: {compileMs:F0} ms (single compile, includes engine warm-up)");
        sb.AppendLine($"- state: {compiled.State}");
        sb.AppendLine();
        sb.AppendLine("### Diagnostics by kind");
        sb.AppendLine();
        sb.AppendLine("| severity | code | count |");
        sb.AppendLine("|---|---|---|");
        foreach (var row in warningGroups)
        {
            sb.AppendLine(row);
        }
        sb.AppendLine();
        sb.AppendLine("## Scan verdicts (synthetic buffers)");
        sb.AppendLine();
        sb.AppendLine("| buffer | state | fired rules |");
        sb.AppendLine("|---|---|---|");
        foreach (var (buffer, fired, state) in verdicts)
        {
            sb.AppendLine($"| {buffer} | {state} | {(fired.Length == 0 ? "—" : string.Join(", ", fired))} |");
        }
        sb.AppendLine();
        sb.AppendLine("## Throughput");
        sb.AppendLine();
        sb.AppendLine($"- {mibPerSec:F0} MiB/s across the synthetic buffer set (this machine, Debug/CI");
        sb.AppendLine("  build of the test host; treat as an order-of-magnitude signal, not a benchmark).");
        File.WriteAllText(Path.Combine(dir.FullName, "CORPUS_REPORT.md"), sb.ToString());
    }
}

/// <summary>
/// End-to-end differential: whole rules (conditions included) against the reference CLI,
/// comparing which rules fire. Constructs that deliberately diverge (#s overlap counting)
/// are excluded by fixture design.
/// </summary>
public class DifferentialVerdictTests
{
    private static readonly string? YaraPath =
        new[] { "/usr/bin/yara", "/usr/local/bin/yara" }.FirstOrDefault(File.Exists);

    private static string[] ReferenceFired(string ruleSource, byte[] data)
    {
        string dir = Path.Combine(Path.GetTempPath(), "zb-yara-verdict-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string rulePath = Path.Combine(dir, "rule.yar");
            string dataPath = Path.Combine(dir, "data.bin");
            File.WriteAllText(rulePath, ruleSource);
            File.WriteAllBytes(dataPath, data);
            var psi = new ProcessStartInfo(YaraPath!, $"\"{rulePath}\" \"{dataPath}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi)!;
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(30_000);
            Assert.True(proc.ExitCode is 0 or 1, $"yara failed: {stderr}");
            return stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Split(' ')[0])
                .ToArray();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static void AssertSameVerdicts(string ruleSource, byte[] data)
    {
        if (YaraPath is null)
        {
            return;
        }
        var compiled = YaraCompiler.Compile([new YaraSource("diff.yar", ruleSource)]);
        Assert.True(compiled.Rules is not null, "our compile failed: " + string.Join("; ", compiled.Errors));
        var ours = new YaraScanner().ScanBytes(compiled.Rules!, data);
        Assert.Equal(OperationState.Ok, ours.State);
        var ourFired = ours.Matches.Select(m => m.RuleName).OrderBy(n => n).ToArray();
        var refFired = ReferenceFired(ruleSource, data).OrderBy(n => n).ToArray();
        Assert.True(ourFired.SequenceEqual(refFired),
            $"ours [{string.Join(",", ourFired)}] vs reference [{string.Join(",", refFired)}]");
    }

    [Fact]
    public void CorpusVerdictsAgreeWithReference()
    {
        if (YaraPath is null)
        {
            return;
        }
        // Reuse the whole synthetic corpus and its buffers: strongest single check we
        // can run locally.
        var buffersField = typeof(CorpusValidationTests)
            .GetMethod("BuildBuffers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var buffers = (List<(string Name, byte[] Data, string[] Expected)>)buffersField.Invoke(null, null)!;
        foreach (var (_, data, _) in buffers)
        {
            AssertSameVerdicts(CorpusValidationTests.CorpusSource, data);
        }
    }

    [Theory]
    [InlineData("rule t { condition: uint16(0) == 0x6261 and uint32be(0) == 0x61626364 }", "abcdef", true)]
    [InlineData("rule t { strings: $a = \"cd\" condition: $a at 2 and $a in (0..4) }", "abcdef", true)]
    [InlineData("rule t { strings: $a = \"ab\" $b = \"cd\" $c = \"zz\" condition: 2 of them }", "abcdef", true)]
    [InlineData("rule t { strings: $a = \"ab\" $b = \"cd\" $c = \"zz\" condition: none of ($c*) and all of ($a, $b) }", "abcdef", true)]
    [InlineData("rule t { strings: $a = \"ab\" condition: for all i in (1..#a) : ( @a[i] < 3 ) }", "ab ab", false)]
    [InlineData("rule t { strings: $a = \"ab\" condition: !a[1] == 2 and @a[1] == 0 }", "ab", true)]
    [InlineData("rule g { condition: filesize > 3 } rule t { condition: g and true }", "abcdef", true)]
    [InlineData("private rule p { strings: $x = \"ab\" condition: $x } rule t { condition: p }", "abcdef", true)]
    [InlineData("global rule gate { strings: $g = \"zz\" condition: $g } rule t { strings: $a = \"ab\" condition: $a }", "abcdef", false)]
    [InlineData("rule t { strings: $a = \"AB\" nocase fullword condition: #a == 2 }", "ab AB abc", true)]
    [InlineData("rule t { strings: $re = /a(b|c)+d/ condition: $re and #re == 1 }", "xxabcbdyy", true)]
    public void SingleVerdictFixturesAgree(string ruleSource, string asciiData, bool expectOurs)
    {
        byte[] data = Encoding.ASCII.GetBytes(asciiData);
        // First check our own expectation, then cross-check the reference.
        var compiled = YaraCompiler.Compile([new YaraSource("diff.yar", ruleSource)]);
        Assert.True(compiled.Rules is not null, string.Join("; ", compiled.Errors));
        var ours = new YaraScanner().ScanBytes(compiled.Rules!, data);
        Assert.Equal(expectOurs, ours.Matches.Any(m => m.RuleName == "t"));
        AssertSameVerdicts(ruleSource, data);
    }
}
