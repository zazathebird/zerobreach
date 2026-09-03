using System.Text;
using System.Text.Json;

namespace Scythe.Techniques.Tests.Fixtures;

/// <summary>
/// Builds map files programmatically. Every entry and rule is emitted as JSON text, and the
/// <c>Raw*</c> members inject arbitrary text so a test can produce exactly the malformation it
/// means to test — an unknown field, a duplicate key, a number where a string belongs.
/// </summary>
public sealed class MapBuilder
{
    private readonly List<string> _entries = new();
    private readonly List<string> _rules = new();
    private readonly List<string> _rootFields = new();
    private bool _emitRules;
    private bool _omitEntries;

    public MapBuilder Entry(string id, string? name = null, string category = "Persistence", string? url = null)
    {
        name ??= $"Name of {id}";
        url ??= $"https://reference.example/techniques/{id.Replace('.', '/')}";
        return RawEntry($"{{\"id\":{Q(id)},\"name\":{Q(name)},\"category\":{Q(category)},\"url\":{Q(url)}}}");
    }

    public MapBuilder RawEntry(string json)
    {
        _entries.Add(json);
        return this;
    }

    public MapBuilder Rule(string keyword, string id) => RawRule($"{{\"keyword\":{Q(keyword)},\"id\":{Q(id)}}}");

    public MapBuilder RawRule(string json)
    {
        _emitRules = true;
        _rules.Add(json);
        return this;
    }

    /// <summary>Emit an empty <c>rules</c> array even when no rule was added.</summary>
    public MapBuilder WithEmptyRules()
    {
        _emitRules = true;
        return this;
    }

    public MapBuilder RootField(string name, string rawJsonValue)
    {
        _rootFields.Add($"{Q(name)}:{rawJsonValue}");
        return this;
    }

    public MapBuilder WithoutEntries()
    {
        _omitEntries = true;
        return this;
    }

    public string Json()
    {
        var parts = new List<string>();
        if (!_omitEntries)
        {
            parts.Add($"\"entries\":[{string.Join(",", _entries)}]");
        }

        if (_emitRules)
        {
            parts.Add($"\"rules\":[{string.Join(",", _rules)}]");
        }

        parts.AddRange(_rootFields);
        return "{" + string.Join(",", parts) + "}";
    }

    public byte[] Bytes() => Encoding.UTF8.GetBytes(Json());

    public TechniqueResult<TechniqueMap> Load(ScanBudget? budget = null) => TechniqueMapLoader.Load(Bytes(), budget);

    /// <summary>Loads and asserts <c>Ok</c>, so a fixture problem fails loudly at the fixture.</summary>
    public TechniqueMap LoadOk()
    {
        var result = Load();
        if (!result.IsOk)
        {
            throw new InvalidOperationException($"fixture map did not load: {result.State}: {result.Reason}");
        }

        return result.Value!;
    }

    /// <summary>JSON string literal.</summary>
    public static string Q(string value) => JsonSerializer.Serialize(value);
}

public static class MapFixtures
{
    public const string Persistence = "Persistence";
    public const string Execution = "Execution";
    public const string DefenseEvasion = "Defense Evasion";

    /// <summary>
    /// Three techniques, three sub-techniques, three keyword rules. T1547.001's category
    /// deliberately differs from its parent's so category roll-up can be observed.
    /// </summary>
    public static MapBuilder Standard() => new MapBuilder()
        .Entry("T1053", "Scheduled Task/Job", Persistence)
        .Entry("T1053.005", "Scheduled Task", Persistence)
        .Entry("T1059", "Command and Scripting Interpreter", Execution)
        .Entry("T1059.001", "PowerShell", Execution)
        .Entry("T1547", "Boot or Logon Autostart Execution", Persistence)
        .Entry("T1547.001", "Registry Run Keys / Startup Folder", DefenseEvasion)
        .Rule("scheduled task", "T1053.005")
        .Rule("powershell", "T1059.001")
        .Rule("run key", "T1547.001");

    public static readonly IReadOnlyList<CheckMapping> StandardCheckMappings = new[]
    {
        new CheckMapping("check.schtasks", "T1053.005"),
        new CheckMapping("check.psh", "T1059.001"),
        new CheckMapping("check.runkeys", "T1547.001"),
        new CheckMapping("check.autostart", "T1547"),
        // Declares an identifier the standard map does not carry: the "map is older than the
        // checks" case from the brief's open question 5.
        new CheckMapping("check.newer", "T1999"),
    };

    public static TechniqueResolver StandardResolver(IReadOnlyList<CheckMapping>? mappings = null)
    {
        var result = TechniqueResolver.Create(Standard().LoadOk(), mappings ?? StandardCheckMappings);
        if (!result.IsOk)
        {
            throw new InvalidOperationException($"fixture resolver did not build: {result.Reason}");
        }

        return result.Value!;
    }

    public static Finding F(string id, string? check = null, string? description = null, string? explicitId = null) =>
        new(id, check, description, explicitId);

    /// <summary>A stable text rendering of a whole run, for byte-identical comparison.</summary>
    public static string Render(TechniqueRun run)
    {
        var sb = new StringBuilder();
        foreach (var r in run.Resolutions)
        {
            sb.Append(r.Match(
                ok => $"{ok.FindingId}=>{ok.Identifier.Value}/{ok.Strategy}/{ok.RuleOrdinal?.ToString() ?? "-"}\n",
                un => $"{un.FindingId}=>UNRESOLVED/{un.Reason}/{un.Detail}/{string.Join("|", un.Attempts.Select(a => a.Strategy + ":" + a.Declined))}\n"));
        }

        sb.Append(RenderCounts(run.Rollup));
        return sb.ToString();
    }

    /// <summary>The order-independent part of a rollup: the counts and sets, not the per-finding list.</summary>
    public static string RenderCounts(TechniqueRollup rollup)
    {
        var sb = new StringBuilder();
        sb.Append("findings=").Append(rollup.FindingCount).Append(" resolved=").Append(rollup.ResolvedCount).Append('\n');
        Append(sb, "directId", rollup.DirectCountsByIdentifier);
        Append(sb, "rolledId", rollup.RolledUpCountsByIdentifier);
        Append(sb, "directCat", rollup.DirectCountsByCategory);
        Append(sb, "rolledCat", rollup.RolledUpCountsByCategory);
        sb.Append("seen=").Append(string.Join(",", rollup.IdentifiersSeen)).Append('\n');
        sb.Append("seen+=").Append(string.Join(",", rollup.IdentifiersSeenIncludingParents)).Append('\n');
        sb.Append("strategy=").Append(string.Join(",", rollup.CountsByStrategy.Select(s => $"{s.Strategy}:{s.Count}"))).Append('\n');
        sb.Append("reasons=").Append(string.Join(",", rollup.UnresolvedCountsByReason.Select(s => $"{s.Reason}:{s.Count}"))).Append('\n');
        return sb.ToString();
    }

    private static void Append(StringBuilder sb, string label, IReadOnlyList<CountedName> counts)
    {
        sb.Append(label).Append('=').Append(string.Join(",", counts.Select(c => $"{c.Name}:{c.Count}"))).Append('\n');
    }

    public static string RenderMap(TechniqueMap map)
    {
        var sb = new StringBuilder();
        foreach (var e in map.Entries)
        {
            sb.Append(e.Identifier.Value).Append('|').Append(e.Name).Append('|').Append(e.Category).Append('|').Append(e.Url).Append('\n');
        }

        foreach (var r in map.Rules)
        {
            sb.Append(r.Ordinal).Append('|').Append(r.Keyword).Append('|').Append(r.Identifier.Value).Append('\n');
        }

        return sb.ToString();
    }
}
