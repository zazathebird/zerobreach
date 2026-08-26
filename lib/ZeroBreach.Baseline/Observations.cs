namespace ZeroBreach.Baseline;

/// <summary>
/// What the host actually read for one setting. Three distinct states: a value was present,
/// the setting was explicitly absent (unset), or the read itself failed. Absent and read-failed
/// must never be conflated — the first is a fact about the machine, the second is a gap in
/// what was verified.
/// </summary>
public abstract record SettingObservation
{
    private protected SettingObservation() { }

    public static SettingObservation Present(SettingValue value) => new ObservedPresent(value);
    public static SettingObservation Absent { get; } = new ObservedAbsent();
    public static SettingObservation ReadFailed(string reason) => new ObservedReadFailed(reason);
}

public sealed record ObservedPresent(SettingValue Value) : SettingObservation;

public sealed record ObservedAbsent : SettingObservation;

public sealed record ObservedReadFailed(string Reason) : SettingObservation;

/// <summary>
/// Everything the host observed on one visit. <see cref="Settings"/> holds single-instance
/// settings keyed by setting key; <see cref="InstanceSettings"/> holds multi-instance settings
/// keyed by setting key, then by instance identifier.
///
/// A setting key entirely missing from the relevant map is a fourth situation, distinct from an
/// explicit <see cref="ObservedAbsent"/>: the host never reported on it at all, and the check
/// evaluates to Undetermined. An empty inner dictionary in <see cref="InstanceSettings"/> means
/// the host looked and found zero instances, which is governed by the check's
/// <see cref="EmptyInstancesRule"/>.
///
/// Setting-key lookup uses the supplied dictionaries' own key comparers; the host should build
/// them with the comparer its setting keys need (typically OrdinalIgnoreCase on Windows).
/// </summary>
public sealed record BaselineObservations(
    IReadOnlyDictionary<string, SettingObservation> Settings,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, SettingObservation>> InstanceSettings)
{
    public static BaselineObservations Empty { get; } = new(
        new Dictionary<string, SettingObservation>(),
        new Dictionary<string, IReadOnlyDictionary<string, SettingObservation>>());
}
