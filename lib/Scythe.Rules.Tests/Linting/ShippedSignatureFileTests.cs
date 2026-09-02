using System.Text;
using System.Text.RegularExpressions;
using Scythe.Rules.Linting;
using Xunit;
using Xunit.Abstractions;

namespace Scythe.Rules.Tests.Linting;

/// <summary>
/// Lints the signature file the PowerShell engine actually ships,
/// <c>data/detection_signatures.json</c>, with the allowlist and consumed-set names read
/// from the engine's own call sites. This is the linter's first real job (BLUEPRINT §10
/// item 6) and the only place the two are held together: a set the engine asks for that the
/// file does not carry is a phase that silently finds nothing, and an allowlist widened to
/// match everything is a phase that silently suppresses everything.
/// </summary>
public class ShippedSignatureFileTests
{
    private readonly ITestOutputHelper _output;

    public ShippedSignatureFileTests(ITestOutputHelper output) => _output = output;

    public const string SignatureFile = "data/detection_signatures.json";
    public const string ManifestFile = "data/signature_lint_manifest.json";

    /// <summary>Matches <c>Get-Sig 'name'</c> and <c>Join-AllowRegex 'name'</c> with a
    /// constant string argument. The PowerShell suite asserts every call site is a constant
    /// (tools/tests/Test-Signature-Lint.ps1), which is what makes this scan complete.</summary>
    private static readonly Regex CallSite = new(
        @"\b(?<fn>Get-Sig|Join-AllowRegex)\s+(?:-Name\s+)?['""](?<name>[A-Za-z0-9_]+)['""]",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>A loader line that binds a Get-Sig / Join-AllowRegex result to a variable:
    /// <c>$KNOWN_RAT_PROCS = Get-Sig 'known_rat_procs'</c>. Such a name is consumed only if
    /// the variable is used somewhere other than that line — the loader pulls every set it
    /// knows about, so the pull itself proves nothing.</summary>
    private static readonly Regex Assignment = new(
        @"^\s*\$(?:global:)?(?<var>[A-Za-z_][A-Za-z0-9_]*)\s*=",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static string RepoRoot
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Scythe.sln")))
            {
                dir = dir.Parent;
            }
            return dir?.FullName
                ?? throw new InvalidOperationException("Scythe.sln not found above the test directory; this test runs inside the repository");
        }
    }

    public static IEnumerable<string> EngineSourceFiles()
    {
        string root = RepoRoot;
        yield return Path.Combine(root, "Scythe-V23.ps1");
        foreach (var module in Directory.GetFiles(Path.Combine(root, "engine"), "*.ps1").OrderBy(p => p, StringComparer.Ordinal))
        {
            yield return module;
        }
    }

    public sealed record EngineScan(
        IReadOnlyList<string> Consumed,
        IReadOnlyList<string> Allowlists,
        IReadOnlyList<string> PulledButUnused);

    /// <summary>
    /// Reads the engine's own call sites. A name pulled straight inside a phase counts as
    /// consumed. A name the loader binds to a variable counts only if that variable is read
    /// on some other non-comment line of the loader or a phase module — otherwise the set is
    /// dead data the linter should report as an orphan.
    /// </summary>
    public static EngineScan ScanEngineCallSites()
    {
        var sources = EngineSourceFiles().Select(f => File.ReadAllLines(f)).ToList();
        var loaderLines = sources[0];

        var consumed = new SortedSet<string>(StringComparer.Ordinal);
        var allowlists = new SortedSet<string>(StringComparer.Ordinal);
        var boundTo = new Dictionary<string, List<string>>(StringComparer.Ordinal); // name -> variables

        for (int fileIndex = 0; fileIndex < sources.Count; fileIndex++)
        {
            foreach (var line in sources[fileIndex])
            {
                var calls = CallSite.Matches(line);
                if (calls.Count == 0)
                {
                    continue;
                }
                var assignment = fileIndex == 0 ? Assignment.Match(line) : Match.Empty;
                foreach (Match m in calls)
                {
                    string name = m.Groups["name"].Value;
                    if (m.Groups["fn"].Value == "Join-AllowRegex")
                    {
                        allowlists.Add(name);
                    }
                    if (assignment.Success)
                    {
                        if (!boundTo.TryGetValue(name, out var vars))
                        {
                            boundTo[name] = vars = new List<string>();
                        }
                        vars.Add(assignment.Groups["var"].Value);
                    }
                    else
                    {
                        consumed.Add(name);
                    }
                }
            }
        }

        var unused = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var (name, vars) in boundTo)
        {
            if (consumed.Contains(name))
            {
                continue;
            }
            bool used = vars.Any(v => VariableIsRead(v, sources));
            if (used)
            {
                consumed.Add(name);
            }
            else
            {
                unused.Add(name);
            }
        }

        return new EngineScan(consumed.ToList(), allowlists.ToList(), unused.ToList());
    }

    private static bool VariableIsRead(string variable, List<string[]> sources)
    {
        var use = new Regex(@"\$(?:global:)?" + Regex.Escape(variable) + @"\b",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        foreach (var lines in sources)
        {
            foreach (var line in lines)
            {
                string trimmed = line.TrimStart();
                if (trimmed.StartsWith('#') || CallSite.IsMatch(line))
                {
                    continue; // a comment, or the pull itself
                }
                if (use.IsMatch(line))
                {
                    return true;
                }
            }
        }
        return false;
    }

    public static LintOptions BuildOptions()
    {
        var errors = new StringWriter();
        var manifest = LintManifest.Parse(
            File.ReadAllText(Path.Combine(RepoRoot, ManifestFile)), ManifestFile, errors);
        Assert.True(manifest is not null, errors.ToString());

        var scan = ScanEngineCallSites();
        var fromSource = LintManifest.Empty with { Consumed = scan.Consumed, Allowlists = scan.Allowlists };
        return fromSource.Apply(manifest!.Apply(LintOptions.Default));
    }

    [Fact]
    public void TheEngineScanFindsTheCallSitesItExistsToFind()
    {
        // If a refactor renamed Get-Sig or changed the quoting, this scan would return
        // nothing, orphan analysis would flag every set, dangling analysis would run against
        // an empty list, and the flat file's allowlists would all be linted as indicators.
        // Pin the floor at well below today's counts (139 consumed / 37 allowlists on
        // 2026-09-02) so growth never trips it and collapse always does.
        var scan = ScanEngineCallSites();
        Assert.True(scan.Consumed.Count >= 100, $"only {scan.Consumed.Count} consumed set names found");
        Assert.True(scan.Allowlists.Count >= 30, $"only {scan.Allowlists.Count} allowlist names found");
        Assert.Subset(new HashSet<string>(scan.Consumed), new HashSet<string>(scan.Allowlists));
        _output.WriteLine("pulled by the loader but read by no phase: " +
            (scan.PulledButUnused.Count == 0 ? "(none)" : string.Join(", ", scan.PulledButUnused)));
    }

    [Fact]
    public void TheManifestOnlyNamesSetsTheFileCarries()
    {
        var options = BuildOptions();
        Assert.Equal(RuleFileShape.Flat, options.Shape);

        string json = File.ReadAllText(Path.Combine(RepoRoot, SignatureFile));
        var findings = new List<LintFinding>();
        var parse = Scythe.Rules.Linting.Json.JsonSourceParser.Parse(json);
        Assert.Equal(OperationState.Ok, parse.State);
        var file = RuleFileReader.Read(parse.Root!, SignatureFile, findings, options);
        var declared = new HashSet<string>(
            file.IndicatorSets.Concat(file.Allowlists).Select(s => s.Name), StringComparer.Ordinal);

        // A literal_sets entry naming a set that does not exist is a typo that silently
        // leaves the real set under the regex checks.
        var unknown = options.LiteralSets.Where(n => !declared.Contains(n)).ToList();
        Assert.True(unknown.Count == 0, "literal_sets names sets the file does not carry: " + string.Join(", ", unknown));
    }

    [Fact]
    public void TheShippedSignatureFileLintsClean()
    {
        var options = BuildOptions();
        string json = File.ReadAllText(Path.Combine(RepoRoot, SignatureFile));
        var result = RuleFileLinter.Lint(json, Path.GetFileName(SignatureFile), options);

        var report = new StringWriter();
        LintReport.WriteText(result, Path.GetFileName(SignatureFile), report);
        _output.WriteLine(report.ToString());

        Assert.True(result.State == OperationState.Ok, "lint did not complete: " + result.Reason);

        var failing = result.Findings.Where(f => f.Severity >= LintSeverity.Error).ToList();
        var sb = new StringBuilder();
        foreach (var f in failing)
        {
            sb.AppendLine(f.ToString());
        }
        Assert.True(failing.Count == 0, $"{failing.Count} finding(s) at Error or above:\n{sb}");

        // Warnings do not fail the lint, but they must not grow unnoticed either: 170 on
        // 2026-09-02, almost all of them the bare-word entries of trusted_root_ca_issuers,
        // native_messaging_benign_hosts and hidden_task_benign_paths that the manifest
        // documents as heuristic by design. Lower this as those lists are tightened; raise it
        // only with a CHANGELOG entry saying which new entries earned the warnings.
        int warnings = result.Findings.Count(f => f.Severity == LintSeverity.Warning);
        Assert.True(warnings <= WarningCeiling, $"{warnings} warnings, ceiling is {WarningCeiling}; see the report above");
    }

    public const int WarningCeiling = 185;
}
