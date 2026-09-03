using Scythe.Rules.Linting.Json;

namespace Scythe.Rules.Linting;

/// <summary>
/// The CI entry point, as a library method. The integration rules for this work package
/// allow no new project (and therefore no new executable), so the console front end is
/// one call away: <c>public static int Main(string[] args) =&gt;
/// Scythe.Rules.Linting.LintTool.Run(args, Console.Out, Console.Error);</c>
///
/// Exit codes — stable, CI scripts key on them:
/// <list type="bullet">
/// <item><b>0</b> — linted completely, nothing at or above the failure threshold.</item>
/// <item><b>1</b> — linted completely, findings at or above the threshold
/// (errors and criticals; warnings too with <c>--fail-on-warning</c>).</item>
/// <item><b>2</b> — the lint did not complete: bad usage, unreadable file, unparseable
/// JSON, or budget exhaustion. An incomplete lint must never look like a clean one.</item>
/// </list>
/// </summary>
public static class LintTool
{
    public const int ExitClean = 0;
    public const int ExitFindings = 1;
    public const int ExitDidNotComplete = 2;

    private const string Usage =
        "usage: scythe-lint <rulefile.json> [--format text|json] [--fail-on-warning] [--manifest <file>]\n" +
        "  --format text|json   output style (default: text)\n" +
        "  --fail-on-warning    exit 1 on warning-level findings too\n" +
        "  --manifest <file>    what the host says about itself: a JSON array of the set\n" +
        "                       names it consumes, or an object with \"shape\" (flat|nested),\n" +
        "                       \"consumed\", \"allowlists\", \"literal_sets\", ... and\n" +
        "                       \"accepted_findings\" ([{ code, set, entry, why }] — reviewed\n" +
        "                       findings reported at Info with the reason)";

    public static int Run(string[] args, TextWriter stdout, TextWriter stderr)
    {
        string? rulePath = null;
        string format = "text";
        bool failOnWarning = false;
        string? manifestPath = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--format":
                    if (++i >= args.Length || (args[i] != "text" && args[i] != "json"))
                    {
                        stderr.WriteLine("error: --format needs 'text' or 'json'");
                        return ExitDidNotComplete;
                    }
                    format = args[i];
                    break;
                case "--fail-on-warning":
                    failOnWarning = true;
                    break;
                case "--manifest":
                    if (++i >= args.Length)
                    {
                        stderr.WriteLine("error: --manifest needs a file path");
                        return ExitDidNotComplete;
                    }
                    manifestPath = args[i];
                    break;
                case "--help" or "-h":
                    stdout.WriteLine(Usage);
                    return ExitClean;
                default:
                    if (args[i].StartsWith('-') || rulePath is not null)
                    {
                        stderr.WriteLine($"error: unexpected argument '{args[i]}'");
                        stderr.WriteLine(Usage);
                        return ExitDidNotComplete;
                    }
                    rulePath = args[i];
                    break;
            }
        }

        if (rulePath is null)
        {
            stderr.WriteLine(Usage);
            return ExitDidNotComplete;
        }

        var options = LintOptions.Default;
        if (manifestPath is not null)
        {
            if (LoadManifest(manifestPath, stderr) is not { } manifest)
            {
                return ExitDidNotComplete;
            }
            options = manifest.Apply(options);
        }

        string jsonText;
        try
        {
            jsonText = File.ReadAllText(rulePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                       or ArgumentException or NotSupportedException)
        {
            stderr.WriteLine($"error: cannot read '{rulePath}': {ex.Message}");
            return ExitDidNotComplete;
        }

        string fileName = Path.GetFileName(rulePath);
        var result = RuleFileLinter.Lint(jsonText, fileName, options);

        if (format == "json")
        {
            LintReport.WriteJson(result, fileName, stdout);
        }
        else
        {
            LintReport.WriteText(result, fileName, stdout);
        }

        if (result.State != OperationState.Ok)
        {
            return ExitDidNotComplete;
        }
        var threshold = failOnWarning ? LintSeverity.Warning : LintSeverity.Error;
        return result.HasFindingAtOrAbove(threshold) ? ExitFindings : ExitClean;
    }

    private static LintManifest? LoadManifest(string path, TextWriter stderr)
    {
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                       or ArgumentException or NotSupportedException)
        {
            stderr.WriteLine($"error: cannot read manifest '{path}': {ex.Message}");
            return null;
        }
        return LintManifest.Parse(text, path, stderr);
    }
}
