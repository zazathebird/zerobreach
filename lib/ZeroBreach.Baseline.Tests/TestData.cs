namespace ZeroBreach.Baseline.Tests;

/// <summary>Builders for well-formed fixtures. Each test then perturbs exactly the field it is
/// about, so a failure points at the semantics under test rather than at fixture plumbing.</summary>
internal static class TestData
{
    /// <summary>A valid single-instance integer check; every field overridable.</summary>
    public static BaselineCheck IntegerCheck(
        string id = "INT-001",
        string settingKey = "Policy\\SomeInteger",
        CheckComparison? comparison = null,
        AbsenceRule? absence = null,
        Severity severity = Severity.Medium,
        ApplicabilityCondition? appliesWhen = null) => new()
    {
        Id = id,
        Title = "An integer setting",
        SettingKey = settingKey,
        ExpectedKind = SettingValueKind.Integer,
        Comparison = comparison ?? CheckComparison.EqualTo(SettingValue.OfInteger(1)),
        Severity = severity,
        Remediation = "Set the value.",
        Absence = absence ?? AbsenceRule.NonCompliant,
        AppliesWhen = appliesWhen,
    };

    /// <summary>A valid single-instance boolean check.</summary>
    public static BaselineCheck BooleanCheck(
        string id = "BOOL-001",
        string settingKey = "Policy\\SomeBoolean",
        CheckComparison? comparison = null,
        AbsenceRule? absence = null) => new()
    {
        Id = id,
        Title = "A boolean setting",
        SettingKey = settingKey,
        ExpectedKind = SettingValueKind.Boolean,
        Comparison = comparison ?? CheckComparison.EqualTo(SettingValue.OfBoolean(true)),
        Severity = Severity.High,
        Remediation = "Enable the setting.",
        Absence = absence ?? AbsenceRule.NonCompliant,
    };

    /// <summary>A valid single-instance string check. Case sensitivity is a required argument on
    /// purpose: no test should inherit an accidental default for the thing several tests pin.</summary>
    public static BaselineCheck StringCheck(
        StringCase caseSensitivity,
        string id = "STR-001",
        string settingKey = "Policy\\SomeString",
        CheckComparison? comparison = null,
        AbsenceRule? absence = null) => new()
    {
        Id = id,
        Title = "A string setting",
        SettingKey = settingKey,
        ExpectedKind = SettingValueKind.String,
        Comparison = comparison ?? CheckComparison.EqualTo(SettingValue.OfString("Expected")),
        Severity = Severity.Low,
        Remediation = "Set the string.",
        Absence = absence ?? AbsenceRule.NonCompliant,
        CaseSensitivity = caseSensitivity,
    };

    /// <summary>A valid multi-instance integer check.</summary>
    public static BaselineCheck MultiIntegerCheck(
        string id = "MULTI-001",
        string settingKey = "Interface\\SomeInteger",
        CheckComparison? comparison = null,
        AbsenceRule? absence = null,
        EmptyInstancesRule emptyInstances = EmptyInstancesRule.EmptyIsUndetermined) => new()
    {
        Id = id,
        Title = "A per-instance integer setting",
        SettingKey = settingKey,
        ExpectedKind = SettingValueKind.Integer,
        Comparison = comparison ?? CheckComparison.AtLeast(2),
        Severity = Severity.High,
        Remediation = "Fix the interface.",
        Absence = absence ?? AbsenceRule.NonCompliant,
        Instancing = CheckInstancing.MultiInstance,
        EmptyInstances = emptyInstances,
    };

    public static CheckTable Table(params BaselineCheck[] checks) => new(checks);

    /// <summary>Observations with only single-instance settings.</summary>
    public static BaselineObservations Observed(params (string Key, SettingObservation Observation)[] settings)
    {
        var map = new Dictionary<string, SettingObservation>(StringComparer.Ordinal);
        foreach (var (key, observation) in settings)
            map[key] = observation;
        return new BaselineObservations(map, new Dictionary<string, IReadOnlyDictionary<string, SettingObservation>>());
    }

    /// <summary>Observations with one multi-instance setting key.</summary>
    public static BaselineObservations ObservedInstances(
        string settingKey, params (string InstanceId, SettingObservation Observation)[] instances)
    {
        var inner = new Dictionary<string, SettingObservation>(StringComparer.Ordinal);
        foreach (var (instanceId, observation) in instances)
            inner[instanceId] = observation;
        return new BaselineObservations(
            new Dictionary<string, SettingObservation>(),
            new Dictionary<string, IReadOnlyDictionary<string, SettingObservation>> { [settingKey] = inner });
    }

    public static MachineContext Context(params (string Key, string Value)[] properties)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in properties)
            map[key] = value;
        return new MachineContext(map);
    }

    /// <summary>Evaluates a single check against observations and returns its one result,
    /// asserting the evaluation itself succeeded.</summary>
    public static CheckResult EvaluateOne(
        BaselineCheck check, BaselineObservations observations, MachineContext? context = null)
    {
        var evaluation = BaselineEvaluator.Evaluate(Table(check), observations, context ?? MachineContext.Empty);
        Assert.Equal(EvaluationState.Ok, evaluation.State);
        var result = Assert.Single(evaluation.Results);
        Assert.Equal(check.Id, result.CheckId);
        return result;
    }
}
