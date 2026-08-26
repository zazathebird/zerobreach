namespace ZeroBreach.Rules.Yara.Parsing;

/// <summary>
/// Structural validation across a set of parsed files: reference resolution, cycle
/// detection, and every "must reject at compile time" rule from the task brief. Runs after
/// parsing so that one file's syntax errors do not hide another file's semantic errors.
/// </summary>
public sealed class YaraValidator
{
    private readonly List<Diagnostic> _diagnostics;

    /// <summary>Modules this engine implements. Currently empty: any `import` is reported
    /// and its dependent rules are excluded (an explicit Incomplete at compile — never a
    /// silent skip).</summary>
    public static readonly IReadOnlySet<string> ImplementedModules = new HashSet<string>();

    public YaraValidator(List<Diagnostic> diagnostics) => _diagnostics = diagnostics;

    /// <summary>Rule names that reference an unimplemented module and therefore cannot be
    /// compiled. Populated by <see cref="Validate"/>.</summary>
    public HashSet<string> RulesUsingUnsupportedModules { get; } = new(StringComparer.Ordinal);

    /// <summary>Unimplemented modules that were imported anywhere in the set.</summary>
    public SortedSet<string> UnsupportedModules { get; } = new(StringComparer.Ordinal);

    private void Error(YaraFileAst file, DiagnosticCode code, string message, SourceLocation loc) =>
        _diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, code, message, file.FileName, loc));

    private void Warn(YaraFileAst file, DiagnosticCode code, string message, SourceLocation loc) =>
        _diagnostics.Add(new Diagnostic(DiagnosticSeverity.Warning, code, message, file.FileName, loc));

    public void Validate(IReadOnlyList<YaraFileAst> files)
    {
        // Rule identifiers share one namespace across the whole compiled set, matching the
        // reference behaviour of compiling several sources together.
        var ruleOrder = new Dictionary<string, int>(StringComparer.Ordinal);
        var allRules = new List<(YaraFileAst File, YaraRuleAst Rule)>();
        foreach (var file in files)
        {
            foreach (var rule in file.Rules)
            {
                if (!ruleOrder.TryAdd(rule.Name, allRules.Count))
                {
                    Error(file, DiagnosticCode.DuplicateRuleName,
                        $"duplicate rule name '{rule.Name}' at {rule.Location}", rule.Location);
                    continue;
                }
                allRules.Add((file, rule));
            }
        }

        foreach (var file in files)
        {
            foreach (var import in file.Imports)
            {
                if (!ImplementedModules.Contains(import.Module))
                {
                    UnsupportedModules.Add(import.Module);
                    Warn(file, DiagnosticCode.UnsupportedModule,
                        $"module '{import.Module}' at {import.Location} is not implemented by this engine; rules using it will be reported as incomplete, not skipped",
                        import.Location);
                }
            }
        }

        var references = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        int errorBudget = YaraParser.MaxDiagnostics;
        int errorCount = 0, scanIndex = 0;
        for (int i = 0; i < allRules.Count; i++)
        {
            // Incremental error tally: O(1) amortised even over a 50k-rule corpus.
            while (scanIndex < _diagnostics.Count)
            {
                if (_diagnostics[scanIndex++].Severity == DiagnosticSeverity.Error)
                {
                    errorCount++;
                }
            }
            if (errorCount > errorBudget)
            {
                var (f, r) = allRules[i];
                _diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.TooManyDiagnostics,
                    $"more than {errorBudget} problems; validation stopped at rule '{r.Name}'",
                    f.FileName, r.Location));
                return;
            }
            var (file, rule) = allRules[i];
            var refs = ValidateRule(file, rule, i, ruleOrder, allRules);
            references[rule.Name] = refs;
        }

        DetectCycles(allRules, references, ruleOrder);
    }

    private List<string> ValidateRule(
        YaraFileAst file,
        YaraRuleAst rule,
        int ruleIndex,
        Dictionary<string, int> ruleOrder,
        List<(YaraFileAst File, YaraRuleAst Rule)> allRules)
    {
        // Duplicate string identifiers. Anonymous strings ($) may repeat; named ones may not.
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in rule.Strings)
        {
            if (s.Identifier.Length > 0 && !names.Add(s.Identifier))
            {
                Error(file, DiagnosticCode.DuplicateStringIdentifier,
                    $"duplicate string identifier '${s.Identifier}' in rule '{rule.Name}' at {s.Location}", s.Location);
            }
        }

        var ctx = new WalkContext(file, rule, ruleIndex, ruleOrder, allRules);
        Walk(rule.Condition, ctx);

        // Every string must be reachable from the condition (reference behaviour: an
        // unreferenced string is an error, because it usually means a typo in the condition).
        if (!ctx.AllStringsReferenced)
        {
            foreach (var s in rule.Strings)
            {
                bool referenced = s.Identifier.Length == 0
                    ? ctx.AllStringsReferenced // anonymous strings are reachable only via `them`/wildcards
                    : ctx.ReferencedStrings.Contains(s.Identifier) ||
                      ctx.WildcardPrefixes.Any(p => s.Identifier.StartsWith(p, StringComparison.Ordinal));
                if (!referenced)
                {
                    Error(file, DiagnosticCode.UnreferencedString,
                        $"string ${s.Identifier} in rule '{rule.Name}' at {s.Location} is never referenced by the condition",
                        s.Location);
                }
            }
        }
        return ctx.RuleRefs;
    }

    private sealed class WalkContext(
        YaraFileAst file,
        YaraRuleAst rule,
        int ruleIndex,
        Dictionary<string, int> ruleOrder,
        List<(YaraFileAst File, YaraRuleAst Rule)> allRules)
    {
        public YaraFileAst File => file;
        public YaraRuleAst Rule => rule;
        public int RuleIndex => ruleIndex;
        public Dictionary<string, int> RuleOrder => ruleOrder;
        public List<(YaraFileAst File, YaraRuleAst Rule)> AllRules => allRules;

        public readonly HashSet<string> ReferencedStrings = new(StringComparer.Ordinal);
        public readonly List<string> WildcardPrefixes = [];
        public bool AllStringsReferenced;
        public readonly List<string> RuleRefs = [];
        public readonly List<string> LoopVariables = [];
        public int ForOfDepth;
    }

    private void Walk(YaraExpression expr, WalkContext ctx)
    {
        switch (expr)
        {
            case StringMatchExpr e:
                CheckStringRef(e.StringName, e.Location, ctx);
                break;
            case StringCountExpr e:
                CheckStringRef(e.StringName, e.Location, ctx);
                if (e.InRange is not null)
                {
                    Walk(e.InRange.Low, ctx);
                    Walk(e.InRange.High, ctx);
                }
                break;
            case StringOffsetExpr e:
                CheckStringRef(e.StringName, e.Location, ctx);
                if (e.Index is not null)
                {
                    Walk(e.Index, ctx);
                }
                break;
            case StringLengthExpr e:
                CheckStringRef(e.StringName, e.Location, ctx);
                if (e.Index is not null)
                {
                    Walk(e.Index, ctx);
                }
                break;
            case StringAtExpr e:
                CheckStringRef(e.StringName, e.Location, ctx);
                Walk(e.Offset, ctx);
                break;
            case StringInExpr e:
                CheckStringRef(e.StringName, e.Location, ctx);
                Walk(e.Range.Low, ctx);
                Walk(e.Range.High, ctx);
                break;
            case UnaryExpr e:
                Walk(e.Operand, ctx);
                break;
            case BinaryExpr e:
                Walk(e.Left, ctx);
                Walk(e.Right, ctx);
                break;
            case IntReadExpr e:
                Walk(e.Offset, ctx);
                break;
            case IdentifierExpr e:
                CheckIdentifier(e, ctx);
                break;
            case OfExpr e:
                CheckQuantifier(e.Quantifier, ctx);
                CheckStringSet(e.Set, ctx);
                if (e.InRange is not null)
                {
                    Walk(e.InRange.Low, ctx);
                    Walk(e.InRange.High, ctx);
                }
                break;
            case ForOfExpr e:
                CheckQuantifier(e.Quantifier, ctx);
                CheckStringSet(e.Set, ctx);
                ctx.ForOfDepth++;
                Walk(e.Body, ctx);
                ctx.ForOfDepth--;
                break;
            case ForInExpr e:
                CheckQuantifier(e.Quantifier, ctx);
                switch (e.Iterable)
                {
                    case RangeIterable r:
                        Walk(r.Range.Low, ctx);
                        Walk(r.Range.High, ctx);
                        break;
                    case EnumIterable en:
                        foreach (var item in en.Items)
                        {
                            Walk(item, ctx);
                        }
                        break;
                }
                if (ctx.LoopVariables.Contains(e.Variable))
                {
                    Error(ctx.File, DiagnosticCode.DuplicateLoopVariable,
                        $"loop variable '{e.Variable}' at {e.Location} shadows an enclosing loop variable", e.Location);
                }
                ctx.LoopVariables.Add(e.Variable);
                Walk(e.Body, ctx);
                ctx.LoopVariables.RemoveAt(ctx.LoopVariables.Count - 1);
                break;
            case RangeExpr e:
                Walk(e.Low, ctx);
                Walk(e.High, ctx);
                break;
            default:
                break; // literals, filesize, entrypoint
        }
    }

    private void CheckQuantifier(Quantifier q, WalkContext ctx)
    {
        switch (q)
        {
            case ExprQuantifier e:
                Walk(e.Count, ctx);
                break;
            case PercentQuantifier p:
                Walk(p.Percent, ctx);
                break;
        }
    }

    private void CheckStringSet(StringSet set, WalkContext ctx)
    {
        switch (set)
        {
            case ThemSet t:
                if (ctx.Rule.Strings.Count == 0)
                {
                    Error(ctx.File, DiagnosticCode.ThemWithNoStrings,
                        $"'them' at {t.Location} in rule '{ctx.Rule.Name}', which declares no strings", t.Location);
                }
                ctx.AllStringsReferenced = true;
                break;
            case ListSet list:
                foreach (var item in list.Items)
                {
                    if (item.IsWildcard)
                    {
                        bool any = ctx.Rule.Strings.Any(s =>
                            s.Identifier.StartsWith(item.Name, StringComparison.Ordinal));
                        if (!any)
                        {
                            Error(ctx.File, DiagnosticCode.WildcardMatchesNothing,
                                $"'${item.Name}*' at {item.Location} matches no string in rule '{ctx.Rule.Name}'", item.Location);
                        }
                        if (item.Name.Length == 0)
                        {
                            ctx.AllStringsReferenced = true;
                        }
                        else
                        {
                            ctx.WildcardPrefixes.Add(item.Name);
                        }
                    }
                    else
                    {
                        CheckStringRef(item.Name, item.Location, ctx);
                    }
                }
                break;
        }
    }

    private void CheckStringRef(string name, SourceLocation loc, WalkContext ctx)
    {
        if (name.Length == 0)
        {
            // `$` / `#` / `@` / `!` placeholders are only meaningful while iterating strings.
            if (ctx.ForOfDepth == 0)
            {
                Error(ctx.File, DiagnosticCode.AnonymousStringOutsideLoop,
                    $"anonymous string reference at {loc} is only valid inside a 'for ... of' body", loc);
            }
            return;
        }
        if (!ctx.Rule.Strings.Any(s => s.Identifier == name))
        {
            Error(ctx.File, DiagnosticCode.UndefinedStringReference,
                $"undefined string '${name}' referenced at {loc} in rule '{ctx.Rule.Name}'", loc);
            return;
        }
        ctx.ReferencedStrings.Add(name);
    }

    private void CheckIdentifier(IdentifierExpr e, WalkContext ctx)
    {
        int dot = e.Name.IndexOf('.');
        if (dot >= 0)
        {
            string module = e.Name[..dot];
            if (ctx.File.Imports.Any(i => i.Module == module))
            {
                if (!ImplementedModules.Contains(module))
                {
                    // The rule is structurally fine but cannot be evaluated; the compiler
                    // reports the whole set Incomplete and names this rule.
                    RulesUsingUnsupportedModules.Add(ctx.Rule.Name);
                }
                return;
            }
            Error(ctx.File, DiagnosticCode.UndefinedRuleReference,
                $"unknown identifier '{e.Name}' at {e.Location}; module '{module}' was not imported", e.Location);
            return;
        }

        if (ctx.LoopVariables.Contains(e.Name))
        {
            return;
        }

        if (ctx.RuleOrder.TryGetValue(e.Name, out int targetIndex))
        {
            ctx.RuleRefs.Add(e.Name);
            // The reference resolves rule identifiers as it compiles, so a rule can only
            // see rules defined before it. A forward reference gets its own diagnostic
            // (rather than "unknown identifier") because the fix — reordering — is not obvious.
            if (targetIndex > ctx.RuleIndex)
            {
                Error(ctx.File, DiagnosticCode.ForwardRuleReference,
                    $"rule '{e.Name}' is referenced at {e.Location} before its definition", e.Location);
            }
            return;
        }

        Error(ctx.File, DiagnosticCode.UndefinedRuleReference,
            $"unknown identifier '{e.Name}' at {e.Location} in rule '{ctx.Rule.Name}'", e.Location);
    }

    private void DetectCycles(
        List<(YaraFileAst File, YaraRuleAst Rule)> allRules,
        Dictionary<string, List<string>> references,
        Dictionary<string, int> ruleOrder)
    {
        // Colour-marking DFS. Forward references are already errors, so a cycle can only
        // arise via a self-reference — but this check is kept general as a backstop: if the
        // ordering rule is ever relaxed, cycles must still be impossible to compile.
        var state = new Dictionary<string, int>(StringComparer.Ordinal); // 0 unvisited, 1 in-stack, 2 done
        var stack = new List<string>();

        foreach (var (_, rule) in allRules)
        {
            if (!state.ContainsKey(rule.Name))
            {
                Visit(rule.Name);
            }
        }

        void Visit(string name)
        {
            state[name] = 1;
            stack.Add(name);
            foreach (var target in references.TryGetValue(name, out var refs) ? refs : [])
            {
                if (!state.TryGetValue(target, out int s))
                {
                    Visit(target);
                }
                else if (s == 1)
                {
                    int start = stack.IndexOf(target);
                    string cycle = string.Join(" -> ", stack.Skip(start).Append(target));
                    var (file, rule) = allRules[ruleOrder[name]];
                    _diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, DiagnosticCode.RuleReferenceCycle,
                        $"rule references form a cycle: {cycle}", file.FileName, rule.Location));
                }
            }
            stack.RemoveAt(stack.Count - 1);
            state[name] = 2;
        }
    }
}
