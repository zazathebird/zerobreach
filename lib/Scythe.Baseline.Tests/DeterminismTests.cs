namespace Scythe.Baseline.Tests;

/// <summary>Determinism and purity: same inputs always produce the same output in the same
/// order, dictionary insertion order never leaks into results, and neither input is mutated.</summary>
public sealed class DeterminismTests
{
    private static CheckTable BuildTable() => TestData.Table(
        TestData.IntegerCheck(id: "T-1", settingKey: "K1", comparison: CheckComparison.AtLeast(2)),
        TestData.StringCheck(StringCase.Insensitive, id: "T-2", settingKey: "K2"),
        TestData.MultiIntegerCheck(id: "T-3", settingKey: "K3", comparison: CheckComparison.AtLeast(5)),
        TestData.IntegerCheck(id: "T-4", settingKey: "K4"));

    private static BaselineObservations BuildObservations(bool reverseInsertion)
    {
        var singles = new (string, SettingObservation)[]
        {
            ("K1", SettingObservation.Present(SettingValue.OfInteger(7))),
            ("K2", SettingObservation.Present(SettingValue.OfString("expected"))),
            ("K4", SettingObservation.ReadFailed("access denied")),
        };
        var instances = new (string, SettingObservation)[]
        {
            ("if-a", SettingObservation.Present(SettingValue.OfInteger(1))),
            ("if-b", SettingObservation.Present(SettingValue.OfInteger(9))),
            ("if-c", SettingObservation.Present(SettingValue.OfInteger(2))),
        };
        if (reverseInsertion)
        {
            Array.Reverse(singles);
            Array.Reverse(instances);
        }

        var singleMap = new Dictionary<string, SettingObservation>(StringComparer.Ordinal);
        foreach (var (key, observation) in singles)
            singleMap[key] = observation;
        var instanceMap = new Dictionary<string, SettingObservation>(StringComparer.Ordinal);
        foreach (var (id, observation) in instances)
            instanceMap[id] = observation;

        return new BaselineObservations(singleMap,
            new Dictionary<string, IReadOnlyDictionary<string, SettingObservation>> { ["K3"] = instanceMap });
    }

    /// <summary>Flattens everything order-sensitive about a result into comparable lines.
    /// (Record equality does not compare list contents, so the projection is explicit.)</summary>
    private static string[] Canonical(EvaluationResult evaluation) =>
        new[] { $"state={evaluation.State} rollup={evaluation.Rollup}" }
        .Concat(evaluation.Results.SelectMany(r =>
            new[] { $"{r.CheckId}|{r.Status}|{r.Severity}|{r.Reason}|{r.ObservedValue?.ToDisplay()}" }
            .Concat(r.InstanceOutcomes.Select(o => $"  {o.InstanceId}|{o.Status}|{o.Reason}"))))
        .ToArray();

    [Fact]
    public void RepeatedRuns_ProduceIdenticalOutput()
    {
        var table = BuildTable();
        var observations = BuildObservations(reverseInsertion: false);
        var context = TestData.Context(("Role", "Workstation"));

        var first = Canonical(BaselineEvaluator.Evaluate(table, observations, context));
        for (var run = 0; run < 5; run++)
        {
            Assert.Equal(first, Canonical(BaselineEvaluator.Evaluate(table, observations, context)));
        }
    }

    [Fact]
    public void DictionaryInsertionOrder_DoesNotLeakIntoTheOutput()
    {
        var table = BuildTable();
        var forward = BaselineEvaluator.Evaluate(table, BuildObservations(false), MachineContext.Empty);
        var reversed = BaselineEvaluator.Evaluate(table, BuildObservations(true), MachineContext.Empty);

        Assert.Equal(Canonical(forward), Canonical(reversed));

        // And the output order is the table's order, not the observations'.
        Assert.Equal(new[] { "T-1", "T-2", "T-3", "T-4" }, forward.Results.Select(r => r.CheckId));
    }

    [Fact]
    public void NeitherInputIsMutated()
    {
        var table = BuildTable();
        var observations = BuildObservations(false);
        var contextMap = new Dictionary<string, string> { ["Role"] = "Server" };
        var context = new MachineContext(contextMap);

        // Snapshot every mutable container by copy; the records themselves are immutable.
        var tableChecksBefore = table.Checks.ToArray();
        var singlesBefore = observations.Settings.ToDictionary(kv => kv.Key, kv => kv.Value);
        var instancesBefore = observations.InstanceSettings.ToDictionary(
            kv => kv.Key, kv => kv.Value.ToDictionary(i => i.Key, i => i.Value));
        var contextBefore = contextMap.ToDictionary(kv => kv.Key, kv => kv.Value);

        BaselineEvaluator.Evaluate(table, observations, context);

        Assert.Equal(tableChecksBefore, table.Checks);
        Assert.Equal(singlesBefore.Count, observations.Settings.Count);
        foreach (var (key, value) in singlesBefore)
            Assert.Same(value, observations.Settings[key]);
        Assert.Equal(instancesBefore.Count, observations.InstanceSettings.Count);
        foreach (var (key, inner) in instancesBefore)
        {
            Assert.Equal(inner.Count, observations.InstanceSettings[key].Count);
            foreach (var (id, value) in inner)
                Assert.Same(value, observations.InstanceSettings[key][id]);
        }
        Assert.Equal(contextBefore, contextMap);
    }

    [Fact]
    public void LoaderIsDeterministic_SameJsonSameTable()
    {
        const string json = """
            {
              "checks": [
                {
                  "id": "D-1",
                  "title": "t",
                  "settingKey": "k",
                  "type": "integer",
                  "comparison": { "kind": "oneOf", "values": [1, 2, 3] },
                  "severity": "low",
                  "remediation": "r",
                  "absence": "compliant"
                }
              ]
            }
            """;
        var first = CheckTableJsonLoader.Load(json);
        var second = CheckTableJsonLoader.Load(json);
        Assert.Equal(EvaluationState.Ok, first.State);
        Assert.Equal(EvaluationState.Ok, second.State);
        Assert.Equal(first.Table!.Checks.Count, second.Table!.Checks.Count);
        var a = Assert.IsType<OneOfComparison>(first.Table.Checks[0].Comparison);
        var b = Assert.IsType<OneOfComparison>(second.Table.Checks[0].Comparison);
        Assert.Equal(a.Values, b.Values);
    }
}
