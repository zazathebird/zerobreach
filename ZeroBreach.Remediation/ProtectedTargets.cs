using ZeroBreach.Core.Model;

namespace ZeroBreach.Remediation;

/// <summary>
/// Spec §6.2: a HARDCODED protected-targets list that is a hard block with NO override.
/// There is deliberately no configuration input, no flag, and no API to bypass a Blocked
/// verdict. Every destructive code path must call <see cref="Check"/> immediately before
/// acting — not only the planner.
/// </summary>
public static class ProtectedTargets
{
    public readonly record struct Verdict(bool Blocked, string? Reason)
    {
        public static readonly Verdict Allowed = new(false, null);
        public static Verdict Block(string reason) => new(true, reason);
    }

    /// <summary>File-system directories protected recursively (core OS).</summary>
    private static readonly string[] ProtectedDirs = BuildProtectedDirs();

    /// <summary>The one carve-out under %WINDIR%: Windows\Temp is a common malware drop
    /// location and contains no OS-critical files.</summary>
    private static readonly string[] AllowedSubDirs = { Env(@"%WINDIR%\Temp") };

    /// <summary>Processes that must never be killed by this tool: OS-critical (killing them
    /// crashes or bricks the session) and security tooling (an IR tool must not be usable
    /// to switch off protection).</summary>
    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "smss", "csrss", "wininit", "winlogon", "services", "lsass",
        "svchost", "dwm", "fontdrvhost", "conhost", "registry", "memcompression",
        // security tooling
        "msmpeng", "nissrv", "securityhealthservice", "sense", "mssense", "wdnissvc",
    };

    /// <summary>Registry key path fragments (case-insensitive) protected against value
    /// deletion: certificate trust store, LSA/boot/code-integrity config, and values whose
    /// deletion (rather than repair) bricks login. These need manual, informed repair —
    /// exactly what run_command display-only findings are for.</summary>
    private static readonly string[] ProtectedRegistryFragments =
    {
        @"\microsoft\systemcertificates",
        @"\control\lsa",
        @"\control\securebo",          // SecureBoot
        @"\control\ci\",
        @"\currentversion\profilelist",
        @"bcd00000000",
        @"\currentversion\winlogon",   // Shell / Userinit must be repaired, never deleted
    };

    /// <summary>Single entry point: is this destructive action against this target blocked?
    /// <paramref name="target"/> is a file path for file actions, a
    /// "HIVE\Key\Path::ValueName" string for registry value deletion, and a
    /// "pid:processName" pair for process kills.</summary>
    public static Verdict Check(FixAction action, string target)
    {
        return action switch
        {
            FixAction.DeleteFile or FixAction.Quarantine => CheckFile(target),
            FixAction.DeleteRegistryValue => CheckRegistry(target),
            FixAction.KillProcess => CheckProcess(target),
            FixAction.RunCommand => Verdict.Block("run_command is display-only and is never executed by the engine"),
            FixAction.None => Verdict.Block("finding has no executable fix action"),
            _ => Verdict.Block($"unknown action {action}"),
        };
    }

    public static Verdict CheckFile(string path)
    {
        string full;
        try { full = NormalizePath(path); }
        catch { return Verdict.Block("unparseable path"); }

        // The tool must never act on itself: executable, its directory, vault, action log.
        var self = Environment.ProcessPath;
        if (self is not null)
        {
            if (PathEquals(full, self) || IsUnder(full, Path.GetDirectoryName(self)!))
                return Verdict.Block("target is the scan tool's own file/directory");
        }
        if (IsUnder(full, ZbPaths.DataRoot))
            return Verdict.Block("target is inside the quarantine vault / action log area");

        if (AllowedSubDirs.Any(a => IsUnder(full, a)))
            return Verdict.Allowed;

        foreach (var dir in ProtectedDirs)
            if (PathEquals(full, dir) || IsUnder(full, dir))
                return Verdict.Block($"target is inside protected OS area {dir}");

        return Verdict.Allowed;
    }

    public static Verdict CheckRegistry(string keyAndValue)
    {
        var lower = keyAndValue.ToLowerInvariant();
        foreach (var frag in ProtectedRegistryFragments)
            if (lower.Contains(frag))
                return Verdict.Block($"registry target matches protected area '{frag.Trim('\\')}'");
        return Verdict.Allowed;
    }

    public static Verdict CheckProcess(string pidAndName)
    {
        // Expected form "pid:name"; block outright when malformed — never guess a kill target.
        var idx = pidAndName.IndexOf(':');
        if (idx <= 0 || !int.TryParse(pidAndName[..idx], out var pid))
            return Verdict.Block("kill target must be 'pid:processName'");
        var name = pidAndName[(idx + 1)..].Trim();
        if (name.Length == 0) return Verdict.Block("kill target has no process name");

        if (pid is 0 or 4) return Verdict.Block("system process");
        if (pid == Environment.ProcessId) return Verdict.Block("target is the scan tool's own process");

        var bare = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        if (ProtectedProcessNames.Contains(bare))
            return Verdict.Block($"'{bare}' is an OS-critical or security process");

        return Verdict.Allowed;
    }

    private static string[] BuildProtectedDirs()
    {
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return new[]
        {
            windir, // whole %WINDIR% minus the Temp carve-out above
            Env(@"%ProgramFiles%\Windows Defender"),
            Env(@"%ProgramData%\Microsoft\Windows Defender"),
        };
    }

    /// <summary>Resolves the comparison form of a path so prefix checks can't be dodged by
    /// syntax: strips the \\?\ extended prefix, normalizes . and .. segments and slashes,
    /// expands 8.3 short names (PROGRA~1) when the file exists, and drops trailing
    /// dots/spaces the Win32 layer would silently ignore.</summary>
    private static string NormalizePath(string path)
    {
        var p = path.Trim().Trim('"');
        if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) p = @"\\" + p[8..];
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];

        var full = Path.GetFullPath(p).TrimEnd('.', ' ');

        // 8.3 short names (C:\PROGRA~1\...) only resolve for paths that exist — and a
        // destructive action on a nonexistent path is a no-op anyway.
        if (full.Contains('~'))
        {
            var buffer = new char[short.MaxValue];
            var len = GetLongPathNameW(full, buffer, buffer.Length);
            if (len > 0 && len < buffer.Length) full = new string(buffer, 0, (int)len);
        }

        // Symlinks/junctions anywhere in the path (a junction pointing into System32 must
        // still block). Best-effort: only possible for files that exist and can be opened.
        try
        {
            if (File.Exists(full))
            {
                using var handle = File.OpenHandle(full, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                var buffer = new char[short.MaxValue];
                var len = GetFinalPathNameByHandleW(handle, buffer, buffer.Length, 0);
                if (len > 0 && len < buffer.Length)
                {
                    var resolved = new string(buffer, 0, (int)len);
                    if (resolved.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) resolved = @"\\" + resolved[8..];
                    else if (resolved.StartsWith(@"\\?\", StringComparison.Ordinal)) resolved = resolved[4..];
                    full = resolved;
                }
            }
        }
        catch { /* unopenable file: fall back to the syntactically normalized path */ }

        return full;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern uint GetLongPathNameW(string lpszShortPath, char[] lpszLongPath, int cchBuffer);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
        char[] lpszFilePath, int cchFilePath, uint dwFlags);

    private static string Env(string s) => Environment.ExpandEnvironmentVariables(s);

    private static bool PathEquals(string a, string b) =>
        string.Equals(Path.TrimEndingDirectorySeparator(a), Path.TrimEndingDirectorySeparator(b),
            StringComparison.OrdinalIgnoreCase);

    private static bool IsUnder(string path, string dir)
    {
        var d = Path.TrimEndingDirectorySeparator(dir);
        return path.StartsWith(d + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}
