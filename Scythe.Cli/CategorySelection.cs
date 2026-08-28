using Scythe.Core.Scanning;

namespace Scythe.Cli;

/// <summary>Turns --only/--skip (or a profile's selection) into the excluded-group set for
/// <see cref="PhaseRunner"/>. Names are validated against the REAL scanner list: a typo'd
/// --skip that silently matched nothing would scan more than intended; a typo'd --only
/// would scan nothing while looking deliberate.</summary>
public static class CategorySelection
{
    /// <summary>Returns the groups to exclude (null = run everything), or sets
    /// <paramref name="error"/> when a requested category doesn't exist.</summary>
    public static IReadOnlyCollection<string>? ComputeExcluded(
        IReadOnlyList<IScanner> scanners,
        IReadOnlyList<string> only, IReadOnlyList<string> skip,
        out string? error)
    {
        error = null;
        var knownGroups = scanners.Select(s => s.Group).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unknown = only.Concat(skip).Where(g => !knownGroups.Contains(g)).ToList();
        if (unknown.Count > 0)
        {
            error = $"unknown detection categor{(unknown.Count == 1 ? "y" : "ies")}: " +
                $"{string.Join(", ", unknown)} (valid: {string.Join(", ", scanners.OrderBy(s => s.Phase).Select(s => s.Group))})";
            return null;
        }

        if (only.Count > 0)
            return scanners.Select(s => s.Group)
                .Where(g => !only.Contains(g, StringComparer.OrdinalIgnoreCase)).ToList();
        if (skip.Count > 0)
            return skip;
        return null;
    }
}
