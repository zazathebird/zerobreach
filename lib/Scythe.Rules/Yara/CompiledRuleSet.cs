using Scythe.Rules.Yara.Matching;
using Scythe.Rules.Yara.Parsing;

namespace Scythe.Rules.Yara;

/// <summary>One rule ready for evaluation: its AST plus where its strings live in the
/// flattened compiled string set.</summary>
internal sealed record CompiledRule(
    YaraRuleAst Ast,
    string SourceFile,
    int FirstStringOrdinal,
    int StringCount)
{
    public string Name => Ast.Name;
}

/// <summary>
/// An immutable compiled rule set: compile once, scan many times, share freely across
/// threads. Nothing in here is mutated by scanning.
/// </summary>
public sealed class CompiledRuleSet
{
    internal IReadOnlyList<CompiledRule> Rules { get; }
    internal CompiledStringSet StringSet { get; }

    /// <summary>Rules excluded because they reference modules this engine does not
    /// implement; scanning reports them as incomplete, never silently absent.</summary>
    public IReadOnlyList<string> SkippedRules { get; }

    /// <summary>The unimplemented modules that caused the skips.</summary>
    public IReadOnlyList<string> UnsupportedModules { get; }

    internal CompiledRuleSet(
        IReadOnlyList<CompiledRule> rules,
        CompiledStringSet stringSet,
        IReadOnlyList<string> skippedRules,
        IReadOnlyList<string> unsupportedModules)
    {
        Rules = rules;
        StringSet = stringSet;
        SkippedRules = skippedRules;
        UnsupportedModules = unsupportedModules;
    }

    public int RuleCount => Rules.Count;

    /// <summary>Total concrete literal patterns across the set — the number the host
    /// should watch when loading a big corpus (xor strings expand 256-fold).</summary>
    public int LiteralPatternCount => StringSet.LiteralPatternCount;

    public IEnumerable<string> RuleNames => Rules.Select(r => r.Name);
}
