namespace Scythe.TestKit;

/// <summary>Whether a reference tool was found, and if not, exactly where it was looked for.</summary>
public sealed record ToolProbe(string Tool, bool Found, string? Path, string Reason);

/// <summary>Locates a reference implementation on the developer's machine (reference/17.4_differential.md).</summary>
public static class ExternalTool
{
    /// <summary>
    /// Looks at each caller-supplied candidate path, then at each directory of
    /// <paramref name="searchPath"/> (the process PATH when null). The kit knows nothing about
    /// any specific tool; the caller says what to look for.
    /// </summary>
    public static ToolProbe Find(string tool, IEnumerable<string>? candidates = null, string? searchPath = null)
    {
        if (string.IsNullOrEmpty(tool))
        {
            throw new FixtureException("ExternalTool.Find needs a tool name");
        }

        var looked = new List<string>();
        foreach (string candidate in candidates ?? Array.Empty<string>())
        {
            looked.Add(candidate);
            if (File.Exists(candidate))
            {
                return new ToolProbe(tool, true, candidate, $"'{tool}' found at {candidate}");
            }
        }

        string path = searchPath ?? Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        var names = OperatingSystem.IsWindows() && !tool.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? new[] { tool, tool + ".exe" }
            : new[] { tool };
        foreach (string directory in path.Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (string name in names)
            {
                string full = System.IO.Path.Combine(directory, name);
                looked.Add(full);
                if (File.Exists(full))
                {
                    return new ToolProbe(tool, true, full, $"'{tool}' found at {full}");
                }
            }
        }

        string where = looked.Count == 0 ? "nowhere (no candidates and an empty search path)" : string.Join(", ", looked);
        return new ToolProbe(tool, false, null, $"reference tool '{tool}' not found; looked at: {where}");
    }
}
