using System.Diagnostics;
using ZeroBreach.Rules.Yara.Matching;
using ZeroBreach.Rules.Yara.Parsing;

namespace ZeroBreach.Rules.Yara.Evaluation;

/// <summary>Outcome of one rule's condition, with the reason when incomplete.</summary>
public sealed record RuleEvaluation(RuleTriState State, string? IncompleteReason)
{
    public static readonly RuleEvaluation True = new(RuleTriState.True, null);
    public static readonly RuleEvaluation False = new(RuleTriState.False, null);
}

/// <summary>
/// Evaluates a rule's condition AST against the match set and file context.
///
/// Two distinct "absences" flow through here and must not be conflated:
///  - `undefined` (out-of-range read, missing match index): reference semantics, false in
///    boolean context;
///  - `incomplete` (a budget was exhausted somewhere): must surface as
///    <see cref="RuleTriState.Incomplete"/>, never as a confident false. Short-circuiting
///    respects this: `false and X` is false no matter what X was, but `incomplete and X`
///    forces X to be evaluated, because a false X still decides the outcome.
/// </summary>
public static class ConditionEvaluator
{
    /// <summary>Iteration cap for `for` loops: a rule iterating a 64 MiB range would stall
    /// the scan; past the cap the rule reports Incomplete, never a silent answer.</summary>
    public const int MaxLoopIterations = 100_000;

    public static RuleEvaluation Evaluate(YaraExpression condition, EvaluationContext ctx)
    {
        var value = Eval(condition, ctx);
        return value.ToTriState() switch
        {
            RuleTriState.True => RuleEvaluation.True,
            RuleTriState.False => RuleEvaluation.False,
            _ => new RuleEvaluation(RuleTriState.Incomplete, value.IncompleteReason ?? "condition incomplete"),
        };
    }

    private static YaraValue Eval(YaraExpression expr, EvaluationContext ctx) => expr switch
    {
        BoolLiteralExpr b => YaraValue.Bool(b.Value),
        IntegerLiteralExpr i => YaraValue.Int(i.Value),
        DoubleLiteralExpr d => YaraValue.Dbl(d.Value),
        StringLiteralExpr s => YaraValue.Bytes(s.ValueBytes),
        RegexLiteralExpr => YaraValue.Undefined, // only meaningful as the rhs of `matches`
        FilesizeExpr => YaraValue.Int(ctx.Data.Length),
        EntrypointExpr => ctx.Entrypoint is long ep ? YaraValue.Int(ep) : YaraValue.Undefined,
        IntReadExpr r => EvalIntRead(r, ctx),
        StringMatchExpr m => EvalStringMatch(m, ctx),
        StringCountExpr c => EvalStringCount(c, ctx),
        StringOffsetExpr o => EvalOffsetOrLength(o.StringName, o.Index, o.Location, isOffset: true, ctx),
        StringLengthExpr l => EvalOffsetOrLength(l.StringName, l.Index, l.Location, isOffset: false, ctx),
        StringAtExpr a => EvalStringAt(a, ctx),
        StringInExpr i => EvalStringIn(i, ctx),
        UnaryExpr u => EvalUnary(u, ctx),
        BinaryExpr b => EvalBinary(b, ctx),
        IdentifierExpr id => EvalIdentifier(id, ctx),
        OfExpr of => EvalOf(of, ctx),
        ForOfExpr f => EvalForOf(f, ctx),
        ForInExpr f => EvalForIn(f, ctx),
        _ => YaraValue.Undefined,
    };

    // ------------------------------------------------------------------ string queries

    private static int ResolveOrdinal(string name, EvaluationContext ctx)
    {
        if (name.Length == 0)
        {
            return ctx.CurrentStringOrdinal; // `$` placeholder; validator guarantees a loop
        }
        for (int i = 0; i < ctx.Strings.Count; i++)
        {
            if (ctx.Strings[i].Identifier == name)
            {
                return i;
            }
        }
        return -1;
    }

    private static YaraValue EvalStringMatch(StringMatchExpr expr, EvaluationContext ctx)
    {
        int ordinal = ResolveOrdinal(expr.StringName, ctx);
        if (ordinal < 0)
        {
            return YaraValue.Undefined;
        }
        var ms = ctx.MatchesForString(ordinal);
        if (ms.Matches.Count > 0)
        {
            return YaraValue.True; // matches already found are trustworthy even if cut short
        }
        return ms.Complete
            ? YaraValue.False
            : YaraValue.Incomplete(ms.IncompleteReason ?? "string matching did not finish");
    }

    private static YaraValue EvalStringCount(StringCountExpr expr, EvaluationContext ctx)
    {
        int ordinal = ResolveOrdinal(expr.StringName, ctx);
        if (ordinal < 0)
        {
            return YaraValue.Undefined;
        }
        var ms = ctx.MatchesForString(ordinal);
        if (!ms.Complete)
        {
            // The count is a lower bound; any use of it would launder a truncated scan.
            return YaraValue.Incomplete(ms.IncompleteReason ?? "string matching did not finish");
        }
        if (expr.InRange is null)
        {
            return YaraValue.Int(ms.NonOverlappingCount);
        }
        var range = EvalRange(expr.InRange, ctx);
        if (range.Error is not null)
        {
            return range.Error.Value;
        }
        // Non-overlapping count restricted to matches starting inside the range,
        // consistent with the BLUEPRINT counting rule for plain #s.
        int count = 0;
        long nextFree = long.MinValue;
        foreach (var m in ms.Matches)
        {
            if (m.Offset >= range.Low && m.Offset <= range.High && m.Offset >= nextFree)
            {
                count++;
                nextFree = m.End;
            }
        }
        return YaraValue.Int(count);
    }

    private static YaraValue EvalOffsetOrLength(
        string name, YaraExpression? indexExpr, SourceLocation loc, bool isOffset, EvaluationContext ctx)
    {
        int ordinal = ResolveOrdinal(name, ctx);
        if (ordinal < 0)
        {
            return YaraValue.Undefined;
        }
        long index = 1; // @a is @a[1]
        if (indexExpr is not null)
        {
            var v = Eval(indexExpr, ctx);
            if (v.IsIncomplete || v.IsUndefined)
            {
                return v;
            }
            if (v.Kind != ValueKind.Integer)
            {
                return YaraValue.Undefined;
            }
            index = v.AsInteger;
        }
        if (index < 1)
        {
            return YaraValue.Undefined; // 1-indexed; zero and negatives are undefined, not errors
        }
        var ms = ctx.MatchesForString(ordinal);
        if (index > ms.Matches.Count)
        {
            // With an unfinished scan a later match might exist; without one this is the
            // reference's out-of-range-is-undefined rule.
            return ms.Complete
                ? YaraValue.Undefined
                : YaraValue.Incomplete(ms.IncompleteReason ?? "string matching did not finish");
        }
        var match = ms.Matches[(int)index - 1];
        return YaraValue.Int(isOffset ? match.Offset : match.Length);
    }

    private static YaraValue EvalStringAt(StringAtExpr expr, EvaluationContext ctx)
    {
        int ordinal = ResolveOrdinal(expr.StringName, ctx);
        if (ordinal < 0)
        {
            return YaraValue.Undefined;
        }
        var offset = Eval(expr.Offset, ctx);
        if (offset.IsIncomplete || offset.IsUndefined)
        {
            return offset;
        }
        if (offset.Kind != ValueKind.Integer)
        {
            return YaraValue.Undefined;
        }
        var ms = ctx.MatchesForString(ordinal);
        // An offset test, not a prefix test: some match must start exactly there.
        foreach (var m in ms.Matches)
        {
            if (m.Offset == offset.AsInteger)
            {
                return YaraValue.True;
            }
            if (m.Offset > offset.AsInteger)
            {
                break; // sorted
            }
        }
        return ms.Complete
            ? YaraValue.False
            : YaraValue.Incomplete(ms.IncompleteReason ?? "string matching did not finish");
    }

    private static YaraValue EvalStringIn(StringInExpr expr, EvaluationContext ctx)
    {
        int ordinal = ResolveOrdinal(expr.StringName, ctx);
        if (ordinal < 0)
        {
            return YaraValue.Undefined;
        }
        var range = EvalRange(expr.Range, ctx);
        if (range.Error is not null)
        {
            return range.Error.Value;
        }
        var ms = ctx.MatchesForString(ordinal);
        foreach (var m in ms.Matches)
        {
            if (m.Offset >= range.Low && m.Offset <= range.High)
            {
                return YaraValue.True;
            }
        }
        return ms.Complete
            ? YaraValue.False
            : YaraValue.Incomplete(ms.IncompleteReason ?? "string matching did not finish");
    }

    private readonly record struct RangeResult(long Low, long High, YaraValue? Error);

    private static RangeResult EvalRange(RangeExpr range, EvaluationContext ctx)
    {
        var lo = Eval(range.Low, ctx);
        if (lo.IsIncomplete || lo.IsUndefined)
        {
            return new RangeResult(0, 0, lo);
        }
        var hi = Eval(range.High, ctx);
        if (hi.IsIncomplete || hi.IsUndefined)
        {
            return new RangeResult(0, 0, hi);
        }
        if (lo.Kind != ValueKind.Integer || hi.Kind != ValueKind.Integer)
        {
            return new RangeResult(0, 0, YaraValue.Undefined);
        }
        if (lo.AsInteger > hi.AsInteger)
        {
            // The reference reports this as a per-rule scan error; Incomplete-with-reason
            // is this engine's honest equivalent (the rule gets no confident answer).
            return new RangeResult(0, 0,
                YaraValue.Incomplete($"range lower bound {lo.AsInteger} is greater than upper bound {hi.AsInteger} at {range.Location}"));
        }
        return new RangeResult(lo.AsInteger, hi.AsInteger, null);
    }

    // ------------------------------------------------------------------ scalar operators

    private static YaraValue EvalIntRead(IntReadExpr expr, EvaluationContext ctx)
    {
        var offsetValue = Eval(expr.Offset, ctx);
        if (offsetValue.IsIncomplete || offsetValue.IsUndefined)
        {
            return offsetValue;
        }
        if (offsetValue.Kind != ValueKind.Integer)
        {
            return YaraValue.Undefined;
        }
        long offset = offsetValue.AsInteger;
        int size = expr.Kind switch
        {
            IntReadKind.UInt8 or IntReadKind.Int8 or IntReadKind.UInt8Be or IntReadKind.Int8Be => 1,
            IntReadKind.UInt16 or IntReadKind.Int16 or IntReadKind.UInt16Be or IntReadKind.Int16Be => 2,
            _ => 4,
        };
        var data = ctx.Data.Span;
        if (offset < 0 || offset + size > data.Length)
        {
            return YaraValue.Undefined; // reading past the end is false-in-context, not an exception
        }
        var span = data.Slice((int)offset, size);
        bool be = expr.Kind is IntReadKind.UInt8Be or IntReadKind.UInt16Be or IntReadKind.UInt32Be
            or IntReadKind.Int8Be or IntReadKind.Int16Be or IntReadKind.Int32Be;
        ulong raw = 0;
        if (be)
        {
            foreach (var b in span)
            {
                raw = (raw << 8) | b;
            }
        }
        else
        {
            for (int i = size - 1; i >= 0; i--)
            {
                raw = (raw << 8) | span[i];
            }
        }
        bool signed = expr.Kind is IntReadKind.Int8 or IntReadKind.Int16 or IntReadKind.Int32
            or IntReadKind.Int8Be or IntReadKind.Int16Be or IntReadKind.Int32Be;
        long value = signed
            ? size switch { 1 => (sbyte)raw, 2 => (short)raw, _ => (int)raw }
            : (long)raw;
        return YaraValue.Int(value);
    }

    private static YaraValue EvalUnary(UnaryExpr expr, EvaluationContext ctx)
    {
        var v = Eval(expr.Operand, ctx);
        switch (expr.Op)
        {
            case UnaryOp.Not:
                if (v.IsIncomplete)
                {
                    return v;
                }
                if (v.IsUndefined)
                {
                    return YaraValue.Undefined; // `not undefined` stays undefined (pinned)
                }
                return YaraValue.Bool(v.ToTriState() != RuleTriState.True);
            case UnaryOp.Defined:
                return v.IsIncomplete ? v : YaraValue.Bool(!v.IsUndefined);
            case UnaryOp.Negate:
                if (v.IsIncomplete || v.IsUndefined)
                {
                    return v;
                }
                return v.Kind switch
                {
                    ValueKind.Integer => v.AsInteger == long.MinValue ? YaraValue.Undefined : YaraValue.Int(-v.AsInteger),
                    ValueKind.Double => YaraValue.Dbl(-v.AsDouble),
                    _ => YaraValue.Undefined,
                };
            default: // BitNot
                if (v.IsIncomplete || v.IsUndefined)
                {
                    return v;
                }
                return v.Kind == ValueKind.Integer ? YaraValue.Int(~v.AsInteger) : YaraValue.Undefined;
        }
    }

    private static YaraValue EvalBinary(BinaryExpr expr, EvaluationContext ctx)
    {
        if (expr.Op is BinaryOp.And or BinaryOp.Or)
        {
            return EvalBoolean(expr, ctx);
        }

        var left = Eval(expr.Left, ctx);
        if (left.IsIncomplete)
        {
            return left;
        }
        var right = Eval(expr.Right, ctx);
        if (right.IsIncomplete)
        {
            return right;
        }

        if (expr.Op == BinaryOp.Matches)
        {
            return EvalMatches(left, expr.Right as RegexLiteralExpr, ctx);
        }
        if (left.IsUndefined || right.IsUndefined)
        {
            return YaraValue.Undefined;
        }

        return expr.Op switch
        {
            BinaryOp.Eq or BinaryOp.Ne or BinaryOp.Lt or BinaryOp.Le or BinaryOp.Gt or BinaryOp.Ge =>
                EvalComparison(expr.Op, left, right),
            BinaryOp.Contains or BinaryOp.IContains or BinaryOp.StartsWith or BinaryOp.IStartsWith
                or BinaryOp.EndsWith or BinaryOp.IEndsWith or BinaryOp.IEquals =>
                EvalBytesOp(expr.Op, left, right),
            _ => EvalArithmetic(expr.Op, left, right),
        };
    }

    /// <summary>Kleene logic with a twist: an Incomplete operand does not short-circuit,
    /// because the other side may still decide the answer (false decides `and`, true
    /// decides `or`). Only a decided operand short-circuits.</summary>
    private static YaraValue EvalBoolean(BinaryExpr expr, EvaluationContext ctx)
    {
        var left = Eval(expr.Left, ctx).ToTriStateWithReason(out string? leftReason);
        if (expr.Op == BinaryOp.And)
        {
            if (left == RuleTriState.False)
            {
                return YaraValue.False;
            }
            var right = Eval(expr.Right, ctx).ToTriStateWithReason(out string? rightReason);
            if (right == RuleTriState.False)
            {
                return YaraValue.False;
            }
            if (left == RuleTriState.True && right == RuleTriState.True)
            {
                return YaraValue.True;
            }
            return YaraValue.Incomplete(leftReason ?? rightReason ?? "operand incomplete");
        }
        else
        {
            if (left == RuleTriState.True)
            {
                return YaraValue.True;
            }
            var right = Eval(expr.Right, ctx).ToTriStateWithReason(out string? rightReason);
            if (right == RuleTriState.True)
            {
                return YaraValue.True;
            }
            if (left == RuleTriState.False && right == RuleTriState.False)
            {
                return YaraValue.False;
            }
            return YaraValue.Incomplete(leftReason ?? rightReason ?? "operand incomplete");
        }
    }

    private static RuleTriState ToTriStateWithReason(this YaraValue v, out string? reason)
    {
        reason = v.IsIncomplete ? v.IncompleteReason ?? "operand incomplete" : null;
        return v.ToTriState();
    }

    private static YaraValue EvalComparison(BinaryOp op, YaraValue left, YaraValue right)
    {
        int cmp;
        if (left.Kind == ValueKind.Bytes && right.Kind == ValueKind.Bytes)
        {
            cmp = left.AsBytes.AsSpan().SequenceCompareTo(right.AsBytes);
        }
        else if (IsNumeric(left) && IsNumeric(right))
        {
            if (left.Kind == ValueKind.Integer && right.Kind == ValueKind.Integer)
            {
                cmp = left.AsInteger.CompareTo(right.AsInteger);
            }
            else
            {
                cmp = left.AsDouble.CompareTo(right.AsDouble);
            }
        }
        else if (left.Kind == ValueKind.Boolean && right.Kind == ValueKind.Boolean)
        {
            cmp = left.AsBoolean.CompareTo(right.AsBoolean);
        }
        else
        {
            return YaraValue.Undefined;
        }
        return YaraValue.Bool(op switch
        {
            BinaryOp.Eq => cmp == 0,
            BinaryOp.Ne => cmp != 0,
            BinaryOp.Lt => cmp < 0,
            BinaryOp.Le => cmp <= 0,
            BinaryOp.Gt => cmp > 0,
            _ => cmp >= 0,
        });
    }

    private static bool IsNumeric(YaraValue v) => v.Kind is ValueKind.Integer or ValueKind.Double;

    private static YaraValue EvalBytesOp(BinaryOp op, YaraValue left, YaraValue right)
    {
        if (left.Kind != ValueKind.Bytes || right.Kind != ValueKind.Bytes)
        {
            return YaraValue.Undefined;
        }
        byte[] l = left.AsBytes, r = right.AsBytes;
        bool insensitive = op is BinaryOp.IContains or BinaryOp.IStartsWith or BinaryOp.IEndsWith or BinaryOp.IEquals;
        if (insensitive)
        {
            l = YaraStringCompiler.Fold(l);
            r = YaraStringCompiler.Fold(r);
        }
        return YaraValue.Bool(op switch
        {
            BinaryOp.Contains or BinaryOp.IContains => l.AsSpan().IndexOf(r) >= 0,
            BinaryOp.StartsWith or BinaryOp.IStartsWith => l.AsSpan().StartsWith(r),
            BinaryOp.EndsWith or BinaryOp.IEndsWith => l.AsSpan().EndsWith(r),
            _ => l.AsSpan().SequenceEqual(r),
        });
    }

    private static YaraValue EvalMatches(YaraValue left, RegexLiteralExpr? regex, EvaluationContext ctx)
    {
        if (regex is null || left.IsUndefined)
        {
            return YaraValue.Undefined;
        }
        if (left.Kind != ValueKind.Bytes)
        {
            return YaraValue.Undefined;
        }
        if (!ctx.RegexCache.TryGetValue(regex, out var program))
        {
            // Compile failures were already reported at rule-compile time (A4 validates
            // every condition regex); a failure here evaluates as undefined.
            var scratch = new List<Diagnostic>();
            var ast = RegexParser.Parse(regex.Pattern, regex.CaseInsensitive, regex.DotMatchesAll,
                "matches operand", "<condition>", regex.Location, scratch);
            program = ast is null
                ? null
                : NfaBuilder.FromRegex(ast, wide: false, "matches operand", "<condition>", regex.Location, scratch);
            ctx.RegexCache[regex] = program;
        }
        if (program is null)
        {
            return YaraValue.Undefined;
        }
        var bytes = left.AsBytes;
        if (program.MinLength == 0)
        {
            return YaraValue.True; // an empty-matchable pattern matches any subject
        }
        if (bytes.Length < program.MinLength)
        {
            return YaraValue.False;
        }
        var vm = new PikeVm(program);
        int lastStart = program.AnchoredAtStart ? 0 : bytes.Length - program.MinLength;
        for (int off = 0; off <= lastStart; off++)
        {
            if (program.FirstBytesContain(bytes[off]))
            {
                int end = program.MaxLength is int max ? Math.Min(bytes.Length, off + max) : bytes.Length;
                if (vm.MatchAt(bytes, off, end) >= 0)
                {
                    return YaraValue.True;
                }
            }
        }
        return YaraValue.False;
    }

    private static YaraValue EvalArithmetic(BinaryOp op, YaraValue left, YaraValue right)
    {
        if (op is BinaryOp.BitAnd or BinaryOp.BitOr or BinaryOp.BitXor or BinaryOp.Shl or BinaryOp.Shr)
        {
            if (left.Kind != ValueKind.Integer || right.Kind != ValueKind.Integer)
            {
                return YaraValue.Undefined;
            }
            long a = left.AsInteger, b = right.AsInteger;
            return op switch
            {
                BinaryOp.BitAnd => YaraValue.Int(a & b),
                BinaryOp.BitOr => YaraValue.Int(a | b),
                BinaryOp.BitXor => YaraValue.Int(a ^ b),
                // Shifts follow the reference: negative counts are undefined, counts past
                // the word size yield zero rather than C#'s modulo-64 behaviour.
                BinaryOp.Shl => b < 0 ? YaraValue.Undefined : b >= 64 ? YaraValue.Int(0) : YaraValue.Int(a << (int)b),
                _ => b < 0 ? YaraValue.Undefined : b >= 64 ? YaraValue.Int(0) : YaraValue.Int(a >> (int)b),
            };
        }

        if (!IsNumeric(left) || !IsNumeric(right))
        {
            return YaraValue.Undefined;
        }
        if (left.Kind == ValueKind.Double || right.Kind == ValueKind.Double)
        {
            double x = left.AsDouble, y = right.AsDouble;
            return op switch
            {
                BinaryOp.Add => YaraValue.Dbl(x + y),
                BinaryOp.Sub => YaraValue.Dbl(x - y),
                BinaryOp.Mul => YaraValue.Dbl(x * y),
                BinaryOp.Div => y == 0 ? YaraValue.Undefined : YaraValue.Dbl(x / y),
                _ => YaraValue.Undefined, // % is integer-only
            };
        }
        long l = left.AsInteger, r = right.AsInteger;
        try
        {
            return op switch
            {
                BinaryOp.Add => YaraValue.Int(checked(l + r)),
                BinaryOp.Sub => YaraValue.Int(checked(l - r)),
                BinaryOp.Mul => YaraValue.Int(checked(l * r)),
                BinaryOp.Div => r == 0 || (l == long.MinValue && r == -1) ? YaraValue.Undefined : YaraValue.Int(l / r),
                _ => r == 0 ? YaraValue.Undefined : YaraValue.Int(l % r),
            };
        }
        catch (OverflowException)
        {
            return YaraValue.Undefined; // overflow is undefined, matching the reference
        }
    }

    private static YaraValue EvalIdentifier(IdentifierExpr expr, EvaluationContext ctx)
    {
        if (ctx.LoopVariables.TryGetValue(expr.Name, out long value))
        {
            return YaraValue.Int(value);
        }
        var result = ctx.RuleLookup?.Invoke(expr.Name);
        return result is RuleTriState s
            ? YaraValue.Of(s, $"referenced rule '{expr.Name}' was incomplete")
            : YaraValue.Undefined;
    }

    // ------------------------------------------------------------------ of / for

    private static List<int> ResolveSet(StringSet set, EvaluationContext ctx)
    {
        var ordinals = new List<int>();
        switch (set)
        {
            case ThemSet:
                for (int i = 0; i < ctx.Strings.Count; i++)
                {
                    ordinals.Add(i);
                }
                break;
            case ListSet list:
                foreach (var item in list.Items)
                {
                    if (item.IsWildcard)
                    {
                        for (int i = 0; i < ctx.Strings.Count; i++)
                        {
                            if (ctx.Strings[i].Identifier.StartsWith(item.Name, StringComparison.Ordinal) &&
                                !ordinals.Contains(i))
                            {
                                ordinals.Add(i);
                            }
                        }
                    }
                    else
                    {
                        int ordinal = ResolveOrdinal(item.Name, ctx);
                        if (ordinal >= 0 && !ordinals.Contains(ordinal))
                        {
                            ordinals.Add(ordinal);
                        }
                    }
                }
                break;
        }
        return ordinals;
    }

    private readonly record struct QuantifierThreshold(long Required, bool IsNone, YaraValue? Error);

    private static QuantifierThreshold ResolveQuantifier(Quantifier q, int setSize, EvaluationContext ctx)
    {
        switch (q)
        {
            case AnyQuantifier:
                return new QuantifierThreshold(1, false, null);
            case AllQuantifier:
                return new QuantifierThreshold(setSize, false, null);
            case NoneQuantifier:
                return new QuantifierThreshold(0, true, null);
            case ExprQuantifier e:
            {
                var v = Eval(e.Count, ctx);
                if (v.IsIncomplete || v.IsUndefined)
                {
                    return new QuantifierThreshold(0, false, v);
                }
                if (v.Kind != ValueKind.Integer || v.AsInteger < 0)
                {
                    return new QuantifierThreshold(0, false, YaraValue.Undefined);
                }
                return new QuantifierThreshold(v.AsInteger, false, null);
            }
            default:
            {
                var p = (PercentQuantifier)q;
                var v = Eval(p.Percent, ctx);
                if (v.IsIncomplete || v.IsUndefined)
                {
                    return new QuantifierThreshold(0, false, v);
                }
                if (v.Kind != ValueKind.Integer || v.AsInteger < 0 || v.AsInteger > 100)
                {
                    return new QuantifierThreshold(0, false, YaraValue.Undefined);
                }
                // Pinned against the reference: the required count is ceil(p * n / 100)
                // (33% of 3 needs 1, 50% of 3 needs 2).
                long required = (v.AsInteger * setSize + 99) / 100;
                return new QuantifierThreshold(required, false, null);
            }
        }
    }

    /// <summary>Combines per-item tri-states against a threshold with honest treatment of
    /// incomplete items: True only when enough items are definitely true, False only when
    /// even counting every incomplete item as true would fall short.</summary>
    private static YaraValue CombineQuantified(
        QuantifierThreshold threshold, long trues, long incompletes, string? firstReason)
    {
        if (threshold.IsNone)
        {
            if (trues > 0)
            {
                return YaraValue.False;
            }
            return incompletes > 0
                ? YaraValue.Incomplete(firstReason ?? "some items incomplete")
                : YaraValue.True;
        }
        if (trues >= threshold.Required)
        {
            return YaraValue.True;
        }
        if (trues + incompletes < threshold.Required)
        {
            return YaraValue.False;
        }
        return YaraValue.Incomplete(firstReason ?? "some items incomplete");
    }

    private static YaraValue EvalOf(OfExpr expr, EvaluationContext ctx)
    {
        var ordinals = ResolveSet(expr.Set, ctx);
        var threshold = ResolveQuantifier(expr.Quantifier, ordinals.Count, ctx);
        if (threshold.Error is not null)
        {
            return threshold.Error.Value;
        }
        (long lo, long hi)? range = null;
        if (expr.InRange is not null)
        {
            var r = EvalRange(expr.InRange, ctx);
            if (r.Error is not null)
            {
                return r.Error.Value;
            }
            range = (r.Low, r.High);
        }

        long trues = 0, incompletes = 0;
        string? firstReason = null;
        foreach (int ordinal in ordinals)
        {
            var ms = ctx.MatchesForString(ordinal);
            bool hit = range is (long lo, long hi)
                ? ms.Matches.Any(m => m.Offset >= lo && m.Offset <= hi)
                : ms.Matches.Count > 0;
            if (hit)
            {
                trues++;
            }
            else if (!ms.Complete)
            {
                incompletes++;
                firstReason ??= ms.IncompleteReason;
            }
        }
        return CombineQuantified(threshold, trues, incompletes, firstReason);
    }

    private static YaraValue EvalForOf(ForOfExpr expr, EvaluationContext ctx)
    {
        var ordinals = ResolveSet(expr.Set, ctx);
        var threshold = ResolveQuantifier(expr.Quantifier, ordinals.Count, ctx);
        if (threshold.Error is not null)
        {
            return threshold.Error.Value;
        }
        long trues = 0, incompletes = 0;
        string? firstReason = null;
        int previous = ctx.CurrentStringOrdinal;
        try
        {
            foreach (int ordinal in ordinals)
            {
                ctx.CurrentStringOrdinal = ordinal;
                var result = Eval(expr.Body, ctx).ToTriStateWithReason(out string? reason);
                if (result == RuleTriState.True)
                {
                    trues++;
                }
                else if (result == RuleTriState.Incomplete)
                {
                    incompletes++;
                    firstReason ??= reason;
                }
            }
        }
        finally
        {
            ctx.CurrentStringOrdinal = previous;
        }
        return CombineQuantified(threshold, trues, incompletes, firstReason);
    }

    private static YaraValue EvalForIn(ForInExpr expr, EvaluationContext ctx)
    {
        long trues = 0, incompletes = 0;
        long total;
        string? firstReason = null;

        if (expr.Iterable is RangeIterable rangeIterable)
        {
            var range = EvalRange(rangeIterable.Range, ctx);
            if (range.Error is not null)
            {
                return range.Error.Value;
            }
            total = range.High - range.Low + 1;
            var threshold0 = ResolveQuantifier(expr.Quantifier, (int)Math.Min(total, int.MaxValue), ctx);
            if (threshold0.Error is not null)
            {
                return threshold0.Error.Value;
            }
            if (total > MaxLoopIterations)
            {
                return YaraValue.Incomplete(
                    $"loop at {expr.Location} iterates {total} times, over the cap of {MaxLoopIterations}");
            }
            long iteration = 0;
            for (long i = range.Low; i <= range.High; i++, iteration++)
            {
                if ((iteration & 0x3FF) == 0 && Stopwatch.GetTimestamp() > ctx.DeadlineTimestamp)
                {
                    return YaraValue.Incomplete($"evaluation deadline exhausted in loop at {expr.Location}");
                }
                var result = EvalLoopBody(expr, i, ctx).ToTriStateWithReason(out string? reason);
                if (result == RuleTriState.True)
                {
                    trues++;
                    // `any` can decide early; the skipped items cannot change a True.
                    if (!threshold0.IsNone && trues >= threshold0.Required)
                    {
                        return YaraValue.True;
                    }
                    if (threshold0.IsNone)
                    {
                        return YaraValue.False;
                    }
                }
                else if (result == RuleTriState.Incomplete)
                {
                    incompletes++;
                    firstReason ??= reason;
                }
            }
            return CombineQuantified(threshold0, trues, incompletes, firstReason);
        }

        var items = ((EnumIterable)expr.Iterable).Items;
        total = items.Count;
        var threshold = ResolveQuantifier(expr.Quantifier, items.Count, ctx);
        if (threshold.Error is not null)
        {
            return threshold.Error.Value;
        }
        foreach (var item in items)
        {
            var value = Eval(item, ctx);
            if (value.IsIncomplete)
            {
                incompletes++;
                firstReason ??= value.IncompleteReason;
                continue;
            }
            RuleTriState result;
            string? reason = null;
            if (value.IsUndefined || value.Kind != ValueKind.Integer)
            {
                result = RuleTriState.False; // an undefined iterator item cannot satisfy the body
            }
            else
            {
                result = EvalLoopBody(expr, value.AsInteger, ctx).ToTriStateWithReason(out reason);
            }
            if (result == RuleTriState.True)
            {
                trues++;
            }
            else if (result == RuleTriState.Incomplete)
            {
                incompletes++;
                firstReason ??= reason;
            }
        }
        return CombineQuantified(threshold, trues, incompletes, firstReason);
    }

    private static YaraValue EvalLoopBody(ForInExpr expr, long value, EvaluationContext ctx)
    {
        ctx.LoopVariables[expr.Variable] = value;
        try
        {
            return Eval(expr.Body, ctx);
        }
        finally
        {
            ctx.LoopVariables.Remove(expr.Variable);
        }
    }
}
