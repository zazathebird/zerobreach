namespace ZeroBreach.Diff.Tests;

using Xunit;
using static TestData;

public sealed class DeterminismTests
{
    /// <summary>A representative mixed pair: all four finding sets and several coverage deltas.</summary>
    private static (List<Finding> BaselineFindings, List<CheckResult> BaselineChecks,
                    List<Finding> CurrentFindings, List<CheckResult> CurrentChecks) MixedInputs()
    {
        var baselineFindings = new List<Finding>
        {
            Finding("f-b", description: "resolved later"),
            Finding("f-a", severity: FindingSeverity.Low),
            Finding("f-c", description: "persists"),
            Finding("f-d", properties: new Dictionary<string, string> { ["hash"] = "aaa" }),
        };
        var baselineChecks = new List<CheckResult>
        {
            Check("chk.b"),
            Check("chk.a", CheckStatus.Inconclusive, "timeout"),
            Check("chk.gone"),
        };
        var currentFindings = new List<Finding>
        {
            Finding("f-d", properties: new Dictionary<string, string> { ["hash"] = "bbb" }),
            Finding("f-e", description: "brand new"),
            Finding("f-a", severity: FindingSeverity.High),
            Finding("f-c", description: "persists"),
        };
        var currentChecks = new List<CheckResult>
        {
            Check("chk.new"),
            Check("chk.a"),
            Check("chk.b", CheckStatus.NotRun, "skipped"),
        };
        return (baselineFindings, baselineChecks, currentFindings, currentChecks);
    }

    [Fact]
    public void OutputsAreSortedOrdinallyById()
    {
        var (bf, bc, cf, cc) = MixedInputs();
        var result = BaselineDiff.Diff(BaselineRun(bf, bc), Run(cf, cc));

        Assert.Equal(OperationState.Ok, result.State);
        // f-e new; f-b resolved; f-c persisting; f-a and f-d changed (sorted: f-a before f-d).
        Assert.Equal(new[] { "f-e" }, result.NewFindings.Select(f => f.Id));
        Assert.Equal(new[] { "f-b" }, result.ResolvedFindings.Select(f => f.Id));
        Assert.Equal(new[] { "f-c" }, result.PersistingFindings.Select(f => f.Id));
        Assert.Equal(new[] { "f-a", "f-d" }, result.ChangedFindings.Select(c => c.Current.Id));
        // chk.a improvement, chk.b regression, chk.gone removed, chk.new added — ordinal order.
        Assert.Equal(new[] { "chk.a", "chk.b", "chk.gone", "chk.new" },
            result.CoverageDeltas.Select(d => d.CheckId));
    }

    [Fact]
    public void ShuffledInputOrder_ProducesIdenticalOutput()
    {
        var (bf, bc, cf, cc) = MixedInputs();
        var reference = Render(BaselineDiff.Diff(BaselineRun(bf, bc), Run(cf, cc)));

        var rng = new Random(20260822); // seeded: the test itself must be deterministic
        for (var round = 0; round < 20; round++)
        {
            Shuffle(bf, rng);
            Shuffle(bc, rng);
            Shuffle(cf, rng);
            Shuffle(cc, rng);
            var shuffled = Render(BaselineDiff.Diff(BaselineRun(bf, bc), Run(cf, cc)));
            Assert.Equal(reference, shuffled);
        }
    }

    [Fact]
    public void SameInputTwice_ByteIdenticalRendering()
    {
        var (bf, bc, cf, cc) = MixedInputs();
        var first = Render(BaselineDiff.Diff(
            BaselineRun(bf, bc), Run(cf, cc), new DiffOptions(TimeSpan.FromDays(7))));
        var second = Render(BaselineDiff.Diff(
            BaselineRun(bf, bc), Run(cf, cc), new DiffOptions(TimeSpan.FromDays(7))));

        Assert.Equal(first, second);
    }

    [Fact]
    public void InputsAreNotMutated()
    {
        var (bf, bc, cf, cc) = MixedInputs();
        var baseline = BaselineRun(bf, bc);
        var current = Run(cf, cc);
        var baselineBefore = Render(baseline);
        var currentBefore = Render(current);

        _ = BaselineDiff.Diff(baseline, current, new DiffOptions(TimeSpan.FromDays(7)));

        // Deep renders walk every value in stored order, so any mutation of the lists, the
        // records, or the property bags — including reordering — changes the render.
        Assert.Equal(baselineBefore, Render(baseline));
        Assert.Equal(currentBefore, Render(current));
    }

    [Fact]
    public void FailedDiff_DoesNotMutateInputsEither()
    {
        var baseline = BaselineRun(findings: new[] { Finding("f1") }, machine: "machine-A");
        var current = Run(findings: new[] { Finding("f2") }, machine: "machine-B");
        var before = Render(baseline) + Render(current);

        _ = BaselineDiff.Diff(baseline, current);

        Assert.Equal(before, Render(baseline) + Render(current));
    }

    [Fact]
    public void LargeInputs_DiffCompletesQuickly()
    {
        // A few thousand findings a side is the stated scale; the dictionary join is O(n+m),
        // and this guards against an accidental quadratic join creeping in. Generous bound so
        // the test is not flaky on a slow runner.
        var baselineFindings = Enumerable.Range(0, 5000)
            .Select(i => Finding($"f-{i:D5}", description: $"finding {i}")).ToList();
        var currentFindings = Enumerable.Range(2500, 5000)
            .Select(i => Finding($"f-{i:D5}", description: $"finding {i}")).ToList();
        var checks = Enumerable.Range(0, 200).Select(i => Check($"chk-{i:D3}")).ToList();

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result = BaselineDiff.Diff(
            BaselineRun(baselineFindings, checks), Run(currentFindings, checks));
        stopwatch.Stop();

        Assert.Equal(OperationState.Ok, result.State);
        Assert.Equal(2500, result.NewFindings.Count);
        Assert.Equal(2500, result.ResolvedFindings.Count);
        Assert.Equal(2500, result.PersistingFindings.Count);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5),
            $"diff of 5000 findings a side took {stopwatch.Elapsed}");
    }

    private static void Shuffle<T>(IList<T> list, Random rng)
    {
        for (var i = list.Count - 1; i > 0; i--)
        {
            var j = rng.Next(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }
}
