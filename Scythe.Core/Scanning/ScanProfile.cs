using System.Text.Json;
using System.Text.Json.Serialization;

namespace Scythe.Core.Scanning;

/// <summary>
/// An operator-authored custom scan definition (spec §2 "custom scans"): a JSON file that
/// names a reusable combination of depth, time window, category selection, and extra
/// signature/IOC inputs, loaded with <c>--profile</c> and created with <c>--save-profile</c>.
///
/// A profile only chooses WHICH read-only checks run and how deep — it deliberately cannot
/// touch anything safety-relevant:
///  - no <c>--load-hives</c> (spec §4: loading logged-off users' hives is an explicit
///    per-run opt-in, never something a config file switches on),
///  - no <c>--interactive</c>, no baseline paths (per-run decisions),
///  - nothing in the §6 remediation model (severity gate, protected targets, confirmation).
/// Categories a profile excludes are still reported as Skipped checks, never silently
/// absent (spec §6.7).
///
/// Unknown JSON properties are rejected rather than ignored: a misspelled "skip" that
/// silently vanished would make the scan quietly broader or narrower than the operator
/// believes it is.
/// </summary>
public sealed class ScanProfile
{
    public string? Name { get; init; }
    public string? Description { get; init; }

    /// <summary>QUICK | FULL | DEEP | STEALTH (same values as --mode).</summary>
    public string? Mode { get; init; }

    /// <summary>Time-window filter, same meaning as --since-hours.</summary>
    public int? SinceHours { get; init; }

    /// <summary>Run ONLY these detection categories (scanner group names). Mutually
    /// exclusive with <see cref="Skip"/>.</summary>
    public List<string>? Only { get; init; }

    /// <summary>Run everything EXCEPT these detection categories.</summary>
    public List<string>? Skip { get; init; }

    /// <summary>Custom IOC file (--ioc-file); relative paths resolve against the profile
    /// file's own directory so a profile can travel with its IOC list.</summary>
    public string? IocFile { get; init; }

    /// <summary>Extra signature rules file (--rules); relative paths resolve like
    /// <see cref="IocFile"/>.</summary>
    public string? RulesFile { get; init; }

    /// <summary>Also write an HTML report (--html).</summary>
    public bool? Html { get; init; }

    private static readonly string[] ValidModes = { "QUICK", "FULL", "DEEP", "STEALTH" };

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Loads and validates a profile. Throws <see cref="InvalidDataException"/>
    /// with an operator-readable message on any problem — a broken profile must fail the
    /// run, never fall back to scanning with different settings than the operator asked for.</summary>
    public static ScanProfile Load(string path)
    {
        string text;
        try { text = File.ReadAllText(path); }
        catch (Exception ex) { throw new InvalidDataException($"cannot read profile '{path}': {ex.Message}"); }

        ScanProfile profile;
        try
        {
            profile = JsonSerializer.Deserialize<ScanProfile>(text, JsonOpts)
                      ?? throw new InvalidDataException($"profile '{path}' is empty");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(
                $"profile '{path}' is not valid: {ex.Message} " +
                "(note: unknown property names are rejected on purpose — check spelling against the documented fields)");
        }

        var mode = profile.Mode?.ToUpperInvariant();
        if (mode is not null && !ValidModes.Contains(mode))
            throw new InvalidDataException(
                $"profile '{path}': invalid mode '{profile.Mode}' (expected QUICK, FULL, DEEP, or STEALTH)");

        if (profile.SinceHours is < 0)
            throw new InvalidDataException($"profile '{path}': sinceHours must be non-negative");

        if (profile.Only is { Count: > 0 } && profile.Skip is { Count: > 0 })
            throw new InvalidDataException(
                $"profile '{path}': 'only' and 'skip' cannot both be set — pick one way to select categories");

        // An empty list is the one shape that silently means something other than what the
        // profile text suggests (it would be ignored and the scan would run broader) — reject
        // it like the CLI rejects `--only ","`, per this type's own hard-error rule.
        if (profile.Only is { Count: 0 } || profile.Skip is { Count: 0 })
            throw new InvalidDataException(
                $"profile '{path}': 'only'/'skip' must name at least one category — omit the field entirely to mean \"no selection\"");

        var dir = Path.GetDirectoryName(Path.GetFullPath(path))!;
        return new ScanProfile
        {
            Name = profile.Name,
            Description = profile.Description,
            Mode = mode,
            SinceHours = profile.SinceHours,
            Only = profile.Only,
            Skip = profile.Skip,
            IocFile = Resolve(dir, profile.IocFile),
            RulesFile = Resolve(dir, profile.RulesFile),
            Html = profile.Html,
        };
    }

    /// <summary>Serializes for saving. Core stays read-only (spec §8 audit): the caller
    /// (CLI) writes the file to the operator-chosen path.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, JsonOpts);

    private static string? Resolve(string profileDir, string? file) =>
        file is null ? null : Path.GetFullPath(file, profileDir);
}
