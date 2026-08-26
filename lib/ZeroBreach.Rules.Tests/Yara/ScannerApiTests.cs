using System.Text;
using ZeroBreach.Rules;
using ZeroBreach.Rules.Yara;
using ZeroBreach.Rules.Yara.Parsing;
using Xunit;

namespace ZeroBreach.Rules.Tests.Yara;

public class CompilerApiTests
{
    [Fact]
    public void MalformedSourceFailsWithNoRuleSet()
    {
        var result = YaraCompiler.Compile([new YaraSource("bad.yar", "rule broken { condition: }")]);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Null(result.Rules); // never "a rule set that matches nothing"
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void CleanSourceCompilesOk()
    {
        var result = YaraCompiler.Compile([new YaraSource("ok.yar", """
            rule a { meta: x = 1 strings: $s = "abc" condition: $s }
            """)]);
        Assert.Equal(OperationState.Ok, result.State);
        Assert.NotNull(result.Rules);
        Assert.Equal(1, result.Rules!.RuleCount);
    }

    [Fact]
    public void UnimplementedModuleImportIsExplicitIncompleteNeverSilentSkip()
    {
        var result = YaraCompiler.Compile([new YaraSource("mod.yar", """
            import "pe"
            rule uses_pe { condition: pe.entry_point > 0 }
            rule plain { strings: $s = "abc" condition: $s }
            """)]);
        Assert.Equal(OperationState.Incomplete, result.State);
        Assert.Contains("pe", result.Reason);
        Assert.NotNull(result.Rules);
        Assert.Equal(["uses_pe"], result.Rules!.SkippedRules);
        Assert.Equal(1, result.Rules.RuleCount);

        // And the scan surfaces the skipped rule as incomplete every time.
        var scan = new YaraScanner().ScanBytes(result.Rules, "abc"u8.ToArray());
        Assert.Equal(OperationState.Incomplete, scan.State);
        Assert.Contains(scan.IncompleteRules, r => r.RuleName == "uses_pe" && r.Reason.Contains("module"));
        Assert.Single(scan.Matches, m => m.RuleName == "plain");
    }

    [Fact]
    public void ReferenceToModuleSkippedRuleBecomesIncompleteNotFalse()
    {
        var result = YaraCompiler.Compile([new YaraSource("mod.yar", """
            import "pe"
            rule uses_pe { condition: pe.entry_point > 0 }
            rule depends { condition: uses_pe }
            """)]);
        Assert.NotNull(result.Rules);
        var scan = new YaraScanner().ScanBytes(result.Rules!, "abc"u8.ToArray());
        Assert.Contains(scan.IncompleteRules, r => r.RuleName == "depends");
        Assert.Empty(scan.Matches);
    }

    [Fact]
    public void IncludesResolveThroughCallerSuppliedResolver()
    {
        string? resolved = null;
        var result = YaraCompiler.Compile(
            [new YaraSource("main.yar", """
                include "lib.yar"
                rule uses_lib { condition: lib_rule }
                """)],
            (path, from) =>
            {
                resolved = $"{path}<-{from}";
                return path == "lib.yar" ? "rule lib_rule { strings: $x = \"inc\" condition: $x }" : null;
            });
        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal("lib.yar<-main.yar", resolved);
        var scan = new YaraScanner().ScanBytes(result.Rules!, "inc"u8.ToArray());
        Assert.Equal(["lib_rule", "uses_lib"], scan.Matches.Select(m => m.RuleName));
    }

    [Fact]
    public void UnresolvedIncludeFailsLoudly()
    {
        var result = YaraCompiler.Compile([new YaraSource("main.yar", "include \"missing.yar\"\nrule a { condition: true }")]);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains(result.Errors, d => d.Code == DiagnosticCode.UnresolvedInclude);
    }

    [Fact]
    public void IncludeCycleIsRejected()
    {
        var result = YaraCompiler.Compile(
            [new YaraSource("main.yar", "include \"a.yar\"\nrule m { condition: true }")],
            (path, _) => path switch
            {
                "a.yar" => "include \"b.yar\"\nrule a { condition: true }",
                "b.yar" => "include \"a.yar\"\nrule b { condition: true }",
                _ => null,
            });
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains(result.Errors, d => d.Code == DiagnosticCode.IncludeCycle);
    }

    [Fact]
    public void RuleCountCapIsEnforced()
    {
        var sb = new StringBuilder();
        for (int i = 0; i <= YaraCompiler.MaxRules; i++)
        {
            sb.Append("rule r").Append(i).Append(" { condition: filesize > 0 }\n");
        }
        var result = YaraCompiler.Compile([new YaraSource("big.yar", sb.ToString())]);
        Assert.Equal(OperationState.Failed, result.State);
        Assert.Contains("cap", result.Reason);
    }

    [Fact]
    public void CompiledSetSizeIsReported()
    {
        var result = YaraCompiler.Compile([new YaraSource("x.yar", """
            rule a { strings: $s = "abcd" xor condition: $s }
            """)]);
        // xor expands to 256 concrete patterns; the host can see that.
        Assert.Equal(256, result.Rules!.LiteralPatternCount);
    }
}

public class ScannerApiTests
{
    private static CompiledRuleSet CompileFixture()
    {
        var result = YaraCompiler.Compile([new YaraSource("fixture.yar", """
            rule text_hit : tagged { meta: kind = "text" strings: $a = "alpha" condition: $a }
            rule hex_hit { strings: $h = { DE AD BE EF } condition: $h }
            rule regex_hit { strings: $r = /gamma[0-9]+/ condition: $r }
            rule combo { strings: $a = "alpha" $r = /gamma[0-9]+/ condition: $a and $r and filesize > 10 }
            rule miss { strings: $m = "not present" condition: $m }
            """)]);
        Assert.Equal(OperationState.Ok, result.State);
        return result.Rules!;
    }

    private static readonly byte[] FixtureData =
        Encoding.ASCII.GetBytes("alpha ").Concat(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF })
            .Concat(Encoding.ASCII.GetBytes(" gamma42 end")).ToArray();

    [Fact]
    public void CompileOnceScanManyEndToEnd()
    {
        var compiled = CompileFixture();
        var scanner = new YaraScanner();
        for (int i = 0; i < 3; i++)
        {
            var result = scanner.ScanBytes(compiled, FixtureData);
            Assert.Equal(OperationState.Ok, result.State);
            Assert.Equal(["text_hit", "hex_hit", "regex_hit", "combo"], result.Matches.Select(m => m.RuleName));
        }
    }

    [Fact]
    public void ConcurrentScansOverOneCompiledSetAgree()
    {
        var compiled = CompileFixture();
        var scanner = new YaraScanner();
        var baseline = Render(scanner.ScanBytes(compiled, FixtureData));

        var buffers = new List<byte[]> { FixtureData };
        var rng = new Random(42);
        for (int i = 0; i < 8; i++)
        {
            var buf = new byte[4096];
            rng.NextBytes(buf);
            Encoding.ASCII.GetBytes("alpha gamma7").CopyTo(buf, i * 100);
            buffers.Add(buf);
        }
        var expected = buffers.Select(b => Render(scanner.ScanBytes(compiled, b))).ToList();

        Parallel.For(0, 64, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
        {
            int which = i % buffers.Count;
            var result = Render(scanner.ScanBytes(compiled, buffers[which]));
            Assert.Equal(expected[which], result);
        });
        Assert.Equal(baseline, Render(scanner.ScanBytes(compiled, FixtureData)));

        static string Render(ScanResult r) =>
            r.State + "|" + string.Join(";", r.Matches.Select(m =>
                m.RuleName + ":" + string.Join(",", m.Strings.Select(s =>
                    s.Identifier + "@" + string.Join("+", s.Matches.Select(x => $"{x.Offset}:{x.Length}"))))))
            + "|" + string.Join(";", r.IncompleteRules.Select(i => i.RuleName));
    }

    [Fact]
    public void BudgetExhaustionNamesUnfinishedRules()
    {
        var result = YaraCompiler.Compile([new YaraSource("slow.yar", """
            rule fast { strings: $f = "alpha" condition: $f }
            rule slow { strings: $s = /a{2000}b/ condition: $s }
            """)]);
        Assert.Equal(OperationState.Ok, result.State);
        var data = new byte[2 * 1024 * 1024];
        Array.Fill(data, (byte)'a');
        "alpha!"u8.ToArray().CopyTo(data, 1000);

        var scan = new YaraScanner().ScanBytes(result.Rules!, data);
        Assert.Equal(OperationState.Incomplete, scan.State);
        // The bad rule is isolated: the fast rule still reports, the slow one is named.
        Assert.Contains(scan.Matches, m => m.RuleName == "fast");
        var inc = Assert.Single(scan.IncompleteRules);
        Assert.Equal("slow", inc.RuleName);
        Assert.Contains("budget", inc.Reason);
    }

    [Fact]
    public void DisableOptionSkipsBudgetOffendersOnLaterScans()
    {
        var result = YaraCompiler.Compile([new YaraSource("slow.yar", """
            rule fast { strings: $f = "alpha" condition: $f }
            rule slow { strings: $s = /a{2000}b/ condition: $s }
            """)]);
        var data = new byte[2 * 1024 * 1024];
        Array.Fill(data, (byte)'a');
        "alpha!"u8.ToArray().CopyTo(data, 1000);

        var scanner = new YaraScanner(new YaraScannerOptions(DisableRulesExceedingBudget: true));
        var first = scanner.ScanBytes(result.Rules!, data);
        Assert.Contains(first.IncompleteRules, r => r.RuleName == "slow" && r.Reason.Contains("budget"));

        var second = scanner.ScanBytes(result.Rules!, data);
        var inc = Assert.Single(second.IncompleteRules);
        Assert.Equal("slow", inc.RuleName);
        Assert.Contains("disabled", inc.Reason);
        Assert.Contains(second.Matches, m => m.RuleName == "fast");
    }

    [Fact]
    public void DefaultScannerNeverDisablesRules()
    {
        var result = YaraCompiler.Compile([new YaraSource("slow.yar", """
            rule slow { strings: $s = /a{2000}b/ condition: $s }
            """)]);
        var data = new byte[2 * 1024 * 1024];
        Array.Fill(data, (byte)'a');
        var scanner = new YaraScanner();
        scanner.ScanBytes(result.Rules!, data);
        var second = scanner.ScanBytes(result.Rules!, data);
        var inc = Assert.Single(second.IncompleteRules);
        Assert.DoesNotContain("disabled", inc.Reason);
    }

    [Fact]
    public void MatchCapNamesTheProblem()
    {
        var result = YaraCompiler.Compile([new YaraSource("many.yar", """
            rule many { strings: $a = "aa" condition: #a > 0 }
            """)]);
        var data = new byte[4096];
        Array.Fill(data, (byte)'a');
        var scan = new YaraScanner().ScanBytes(result.Rules!, data, ScanBudget.Default with { MaxMatches = 10 });
        Assert.Equal(OperationState.Incomplete, scan.State);
        Assert.Contains("match cap", scan.Reason);
        // #a is a truncated lower bound, so the rule must be incomplete, not fired.
        Assert.Contains(scan.IncompleteRules, r => r.RuleName == "many");
    }

    [Fact]
    public void ScanIsDeterministicAcrossManyRuns()
    {
        var compiled = CompileFixture();
        var scanner = new YaraScanner();
        var renders = Enumerable.Range(0, 5)
            .Select(_ => string.Join("|", scanner.ScanBytes(compiled, FixtureData).Matches
                .Select(m => m.RuleName + ":" + string.Join(",", m.Strings.SelectMany(s => s.Matches).Select(x => x.Offset)))))
            .Distinct()
            .ToList();
        Assert.Single(renders);
    }
}
