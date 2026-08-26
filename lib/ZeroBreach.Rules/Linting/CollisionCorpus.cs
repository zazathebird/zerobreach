namespace ZeroBreach.Rules.Linting;

/// <summary>
/// Names of real, common software: processes, products and vendors a healthy Windows
/// fleet actually runs. No indicator may match any of these — this is how a detection
/// list ends up deleting a client's working application because a malware family borrowed
/// a common word (BLUEPRINT §9).
///
/// This is a <em>starter</em> corpus. The owner should extend it from a real fleet
/// inventory via <see cref="LintOptions.AdditionalCollisionNames"/> — the richer this
/// list, the earlier a collision is caught.
/// </summary>
public static class CollisionCorpus
{
    public static IReadOnlyList<string> StarterNames { get; } = new[]
    {
        // Windows system processes.
        "explorer.exe", "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe",
        "csrss.exe", "smss.exe", "conhost.exe", "dwm.exe", "taskhostw.exe",
        "spoolsv.exe", "wininit.exe", "rundll32.exe", "msiexec.exe", "notepad.exe",
        "powershell.exe", "cmd.exe", "mmc.exe", "regedit.exe", "wmiprvse.exe",
        // Common application processes.
        "chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe", "winword.exe",
        "excel.exe", "powerpnt.exe", "teams.exe", "onedrive.exe", "acrord32.exe",
        "code.exe", "devenv.exe", "slack.exe", "zoom.exe", "vlc.exe",
        "7zfm.exe", "steam.exe", "spotify.exe", "dropbox.exe", "javaw.exe",
        "python.exe", "node.exe", "putty.exe", "winscp.exe", "teamviewer.exe",
        // Product and vendor names as they appear in paths and metadata.
        "Microsoft", "Windows Defender", "Microsoft Office", "Google", "Google Chrome",
        "Mozilla Firefox", "Adobe", "Adobe Acrobat", "Oracle", "Intel", "NVIDIA",
        "Realtek", "Logitech", "Hewlett-Packard", "Dell", "Lenovo", "VMware",
        "Cisco", "Citrix", "Dropbox", "Zoom", "Slack Technologies", "Valve",
        "Common Files", "Program Files", "WindowsApps",
    };
}
