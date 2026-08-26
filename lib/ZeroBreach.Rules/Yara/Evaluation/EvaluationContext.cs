using ZeroBreach.Rules.Yara.Matching;
using ZeroBreach.Rules.Yara.Parsing;

namespace ZeroBreach.Rules.Yara.Evaluation;

/// <summary>
/// Everything one rule's condition needs at evaluation time. The context is per-scan and
/// mutable only in its loop-variable scope; the compiled inputs it points at are shared
/// and immutable.
/// </summary>
public sealed class EvaluationContext
{
    /// <summary>The scanned buffer (for filesize and the integer-reading functions).</summary>
    public required ReadOnlyMemory<byte> Data { get; init; }

    /// <summary>The rule's string declarations, in declaration order.</summary>
    public required IReadOnlyList<YaraStringDecl> Strings { get; init; }

    /// <summary>Match results for the rule's strings, by declaration ordinal.</summary>
    public required Func<int, StringMatchSet> MatchesForString { get; init; }

    /// <summary>Resolves a rule reference to its (memoised) result. Null when the rule set
    /// has no references, in which case any reference evaluates as undefined.</summary>
    public Func<string, RuleTriState?>? RuleLookup { get; init; }

    /// <summary>Optional entry point supplied by the host (needs PE/ELF knowledge this
    /// engine does not have); `entrypoint` is undefined without it.</summary>
    public long? Entrypoint { get; init; }

    /// <summary>Memoised programs for condition-level `matches` regexes; a null program
    /// means the pattern failed to compile and evaluates as undefined.</summary>
    internal readonly Dictionary<RegexLiteralExpr, NfaProgram?> RegexCache = new(ReferenceEqualityComparer.Instance);

    /// <summary>Absolute Stopwatch timestamp after which evaluation reports Incomplete.</summary>
    public long DeadlineTimestamp { get; init; } = long.MaxValue;

    // Loop variables are scoped strictly by the for-expressions being evaluated.
    internal readonly Dictionary<string, long> LoopVariables = new(StringComparer.Ordinal);

    /// <summary>Ordinal of the string bound to `$`/`#`/`@`/`!` placeholders inside a
    /// `for ... of` body; -1 outside one.</summary>
    internal int CurrentStringOrdinal = -1;
}
