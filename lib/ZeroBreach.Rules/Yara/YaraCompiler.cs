using ZeroBreach.Rules.Yara.Matching;
using ZeroBreach.Rules.Yara.Parsing;

namespace ZeroBreach.Rules.Yara;

/// <summary>One rule source: a name for diagnostics plus the .yar text.</summary>
public sealed record YaraSource(string Name, string Content);

/// <summary>
/// Resolves an `include "path"` directive to source text, or null when it cannot be
/// resolved. Supplied by the caller so this library never touches the file system —
/// the host decides what an include path means (task brief A1's open question).
/// </summary>
public delegate string? YaraIncludeResolver(string includePath, string includingFileName);

/// <summary>Result of compiling a rule set. Failed means the set is unusable and
/// <see cref="Rules"/> is null: a malformed rule file never becomes "a rule set that
/// matches nothing". Incomplete means the set compiled but some rules were excluded for
/// unimplemented modules — usable, with the gap named.</summary>
public sealed class CompileResult
{
    public required OperationState State { get; init; }
    public string? Reason { get; init; }
    public CompiledRuleSet? Rules { get; init; }
    public required IReadOnlyList<Diagnostic> Diagnostics { get; init; }

    public IEnumerable<Diagnostic> Errors =>
        Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error);
}

public static class YaraCompiler
{
    /// <summary>Ceiling on rules per compiled set; a set past this is a mistake or an
    /// attack on the compiler, and the failure names the number.</summary>
    public const int MaxRules = 50_000;

    /// <summary>Ceiling on expanded literal patterns (xor expands 256-fold).</summary>
    public const int MaxLiteralPatterns = 2_000_000;

    public const int MaxIncludeDepth = 16;

    /// <summary>Compilation runs on a dedicated thread with a large stack: rule files are
    /// attacker-adjacent input, and deep (but cap-respecting) recursion in parsing and NFA
    /// analysis must never take down the host process.</summary>
    private const int CompileStackBytes = 64 * 1024 * 1024;

    public static CompileResult Compile(IEnumerable<YaraSource> sources, YaraIncludeResolver? includeResolver = null)
    {
        CompileResult? result = null;
        var thread = new Thread(() => result = CompileCore(sources.ToList(), includeResolver), CompileStackBytes)
        {
            IsBackground = true,
        };
        thread.Start();
        thread.Join();
        return result!;
    }

    private static CompileResult CompileCore(List<YaraSource> sources, YaraIncludeResolver? includeResolver)
    {
        var diagnostics = new List<Diagnostic>();
        var files = new List<YaraFileAst>();
        var visitedIncludes = new HashSet<string>(StringComparer.Ordinal);

        foreach (var source in sources)
        {
            ParseWithIncludes(source, includeResolver, diagnostics, files, visitedIncludes, depth: 0);
        }

        var validator = new YaraValidator(diagnostics);
        validator.Validate(files);

        if (diagnostics.Any(d => d.Severity == DiagnosticSeverity.Error))
        {
            return new CompileResult
            {
                State = OperationState.Failed,
                Reason = "rule compilation failed; see diagnostics",
                Diagnostics = diagnostics,
                Rules = null,
            };
        }

        // Flatten rules (minus module-dependent ones) and their strings.
        var compiledRules = new List<CompiledRule>();
        var flatStrings = new List<(int RuleIndex, YaraStringDecl Decl)>();
        var skipped = new List<string>();
        foreach (var file in files)
        {
            foreach (var rule in file.Rules)
            {
                if (validator.RulesUsingUnsupportedModules.Contains(rule.Name))
                {
                    skipped.Add(rule.Name);
                    continue;
                }
                int ruleIndex = compiledRules.Count;
                compiledRules.Add(new CompiledRule(rule, file.FileName, flatStrings.Count, rule.Strings.Count));
                foreach (var decl in rule.Strings)
                {
                    flatStrings.Add((ruleIndex, decl));
                }
            }
        }

        if (compiledRules.Count > MaxRules)
        {
            return Failed($"rule set has {compiledRules.Count} rules, over the cap of {MaxRules}");
        }

        var stringSet = YaraStringCompiler.Compile(flatStrings, "<set>", diagnostics);
        if (stringSet is null || diagnostics.Any(d => d.Severity == DiagnosticSeverity.Error))
        {
            return new CompileResult
            {
                State = OperationState.Failed,
                Reason = "string compilation failed; see diagnostics",
                Diagnostics = diagnostics,
                Rules = null,
            };
        }
        if (stringSet.LiteralPatternCount > MaxLiteralPatterns)
        {
            return Failed($"rule set expands to {stringSet.LiteralPatternCount} literal patterns, over the cap of {MaxLiteralPatterns}");
        }

        var ruleSet = new CompiledRuleSet(compiledRules, stringSet, skipped,
            validator.UnsupportedModules.ToList());
        bool incomplete = skipped.Count > 0 || validator.UnsupportedModules.Count > 0;
        return new CompileResult
        {
            State = incomplete ? OperationState.Incomplete : OperationState.Ok,
            Reason = incomplete
                ? $"modules not implemented: {string.Join(", ", validator.UnsupportedModules)}; " +
                  $"{skipped.Count} rule(s) excluded and reported as incomplete at scan time"
                : null,
            Rules = ruleSet,
            Diagnostics = diagnostics,
        };

        CompileResult Failed(string reason)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.PatternTooComplex,
                reason, "<set>", new SourceLocation(0, 0)));
            return new CompileResult
            {
                State = OperationState.Failed,
                Reason = reason,
                Diagnostics = diagnostics,
                Rules = null,
            };
        }
    }

    private static void ParseWithIncludes(
        YaraSource source,
        YaraIncludeResolver? resolver,
        List<Diagnostic> diagnostics,
        List<YaraFileAst> files,
        HashSet<string> visited,
        int depth)
    {
        var ast = YaraParser.ParseFile(source.Content, source.Name, diagnostics);

        // Included rules are inserted before the including file's own rules, so backward
        // rule references from the includer into the include resolve. (Include position
        // within the file is not honoured — flagged in the handoff.)
        foreach (var include in ast.Includes)
        {
            if (depth >= MaxIncludeDepth)
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.IncludeDepthExceeded,
                    $"includes nested deeper than {MaxIncludeDepth} at {include.Location}",
                    source.Name, include.Location));
                continue;
            }
            if (!visited.Add(include.Path))
            {
                // Including the same file twice is tolerated (first inclusion wins) only
                // when it is not a cycle back into an ancestor; either way, parsing it
                // again would duplicate every rule, so it is reported and skipped.
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.IncludeCycle,
                    $"include \"{include.Path}\" at {include.Location} was already included (duplicate or cycle)",
                    source.Name, include.Location));
                continue;
            }
            string? content = resolver?.Invoke(include.Path, source.Name);
            if (content is null)
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.UnresolvedInclude,
                    $"include \"{include.Path}\" at {include.Location} could not be resolved" +
                    (resolver is null ? " (no include resolver was supplied)" : ""),
                    source.Name, include.Location));
                continue;
            }
            ParseWithIncludes(new YaraSource(include.Path, content), resolver, diagnostics, files, visited, depth + 1);
        }
        files.Add(ast);
    }
}
