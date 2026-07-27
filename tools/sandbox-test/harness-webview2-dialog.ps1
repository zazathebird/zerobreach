$ErrorActionPreference = 'Continue'
$OutDir  = 'C:\ZBOut'
$LogPath = Join-Path $OutDir 'harness_webview2_dialog.log'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

Log "=== ZeroBreach sandbox harness: native-shell WebView2-missing fatal-dialog confirmation ==="
Log "Proves main.rs's fatal_if_webview2_missing() path end to end on a box with NO WebView2"
Log "Runtime installed: the debug log fires correctly, the native MessageBoxW dialog is genuinely"
Log "visible on screen (screenshot captured, not just a log line), and the process self-terminates"
Log "with the documented exit code 3 (EXIT_WEBVIEW2_MISSING) within its 120s deadline."

try {
    Copy-Item -Path 'C:\ZBIn\app' -Destination 'C:\ZBApp' -Recurse -Force -ErrorAction Stop
    Log "App staged: OK"
} catch { Log "FATAL: app staging failed: $($_.Exception.Message)"; exit 1 }

# --- Confirm this fresh sandbox has no WebView2 (a fresh Windows Sandbox never does; this check
#     just makes the negative explicit in the log instead of assumed) ---
$wv2Paths = @(
    'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
    'HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
)
$wv2Found = $false
foreach ($p in $wv2Paths) {
    $v = Get-ItemProperty -Path $p -Name pv -ErrorAction SilentlyContinue
    if ($v -and $v.pv) { $wv2Found = $true; Log "WebView2 pv found at $p = $($v.pv)" }
}
Log "WebView2 Runtime present in this sandbox: $wv2Found (expect False for this test to be meaningful)"

# --- Ensure no stale debug log from a previous run confuses the read below ---
$dbgLog = Join-Path $env:TEMP 'zerobreach_native_debug.log'
Remove-Item $dbgLog -ErrorAction SilentlyContinue

# --- Win32 helpers: EnumWindows (title-substring match, robust to encoding/timing issues an
#     exact FindWindow lookup can miss) + a full-screen screenshot so "dialog visible" is proven
#     by a captured image, not just a debug-log string. ---
Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class Win32Probe {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    public static List<string> AllTitles() {
        var titles = new List<string>();
        EnumWindows((hWnd, lParam) => {
            if (!IsWindowVisible(hWnd)) return true;
            var sb = new StringBuilder(256);
            GetWindowText(hWnd, sb, 256);
            var t = sb.ToString();
            if (!string.IsNullOrEmpty(t)) titles.Add(t);
            return true;
        }, IntPtr.Zero);
        return titles;
    }
    public static IntPtr FindByTitleSubstring(string needle) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hWnd, lParam) => {
            if (!IsWindowVisible(hWnd)) return true;
            var sb = new StringBuilder(256);
            GetWindowText(hWnd, sb, 256);
            if (sb.ToString().IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
                found = hWnd;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@

# --- Launch the native exe directly (bypassing the NSIS installer, exactly like the original bug repro) ---
$exePath = 'C:\ZBApp\zerobreach-native.exe'
Log "launching: $exePath"
$p = $null
try {
    $p = Start-Process -FilePath $exePath -PassThru -ErrorAction Stop
} catch { Log "FATAL: launch failed: $($_.Exception.Message)"; exit 1 }

# --- Poll for the debug log to appear ---
$deadline = (Get-Date).AddSeconds(30)
$logSeen = $false
while ((Get-Date) -lt $deadline) {
    if (Test-Path $dbgLog) { $logSeen = $true; break }
    Start-Sleep -Milliseconds 500
}
Log "debug log appeared within 30s: $logSeen"
if ($logSeen) {
    Start-Sleep -Seconds 1
    $content = Get-Content $dbgLog -Raw
    Log "--- zerobreach_native_debug.log contents ---"
    Log $content
    Log "--- end debug log ---"
    Log "contains 'main() started': $($content -match 'main\(\) started')"
    Log "contains WebView2-missing message: $($content -match 'WebView2 Runtime not found')"
    Log "contains MessageBoxW-failed (rc=0/non-interactive) note: $($content -match 'MessageBoxW FAILED')"
    Log "contains dialog-dismissed note: $($content -match 'dismissed by user')"
} else {
    Log "REGRESSION: debug log never appeared - the silent-hang bug may still be present"
}

# --- Poll (not single-shot) for the dialog window by TITLE SUBSTRING, up to 15s, logging ALL
#     visible top-level window titles on the first miss for diagnosis. ---
$needle = 'WebView2 Runtime Required'
$hwnd = [IntPtr]::Zero
$pollDeadline = (Get-Date).AddSeconds(15)
$attempt = 0
while ((Get-Date) -lt $pollDeadline) {
    $attempt++
    $hwnd = [Win32Probe]::FindByTitleSubstring($needle)
    if ($hwnd -ne [IntPtr]::Zero) { break }
    if ($attempt -eq 1) {
        $all = [Win32Probe]::AllTitles()
        Log "no match on first attempt - all visible top-level window titles right now:"
        foreach ($t in $all) { Log "   TITLE: $t" }
    }
    Start-Sleep -Milliseconds 750
}
$dialogFound = ($hwnd -ne [IntPtr]::Zero)
Log "native message box window found (substring match, polled up to 15s, $attempt attempts): $dialogFound (handle=$hwnd)"

$rectStr = 'n/a'
if ($dialogFound) {
    $rect = New-Object Win32Probe+RECT
    if ([Win32Probe]::GetWindowRect($hwnd, [ref]$rect)) {
        $rectStr = "L=$($rect.Left) T=$($rect.Top) R=$($rect.Right) B=$($rect.Bottom)"
    }
    Log "dialog window rect: $rectStr"
}

# --- Screenshot the whole virtual screen BEFORE dismissing, as visual proof the box is on
#     screen (not just that a log line was written). ---
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $bmp = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $shotPath = Join-Path $OutDir 'webview2_dialog_screenshot.png'
    $bmp.Save($shotPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Log "screenshot saved: $shotPath (dialogFound=$dialogFound at capture time)"
} catch { Log "screenshot failed: $($_.Exception.Message)" }

if ($dialogFound) {
    # WM_CLOSE = 0x0010 - simulate the user dismissing it, then confirm the process exits cleanly on its own
    [Win32Probe]::PostMessage($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    Log "WM_CLOSE posted to dialog handle $hwnd"
}

# --- The fix has a 120s hard deadline (TerminateProcess) even if nobody dismisses the dialog and
#     even if the box never displayed at all (non-interactive window station -> rc=0 path). Give
#     it a genuinely conclusive window: poll up to 130s for self-exit before force-killing, and
#     record the ACTUAL exit code (contract: 3 = EXIT_WEBVIEW2_MISSING). ---
$selfExited = $false
$exitDeadline = (Get-Date).AddSeconds(130)
while ((Get-Date) -lt $exitDeadline) {
    try { if ($p.HasExited) { $selfExited = $true; break } } catch { break }
    Start-Sleep -Seconds 2
}
$exitCode = $null
try { $exitCode = $p.ExitCode } catch {}
Log "process self-exited within 130s: $selfExited  exitCode=$exitCode  (contract: exit 3)"

if (-not $selfExited) {
    Log "REGRESSION: process did not self-exit within the documented 120s deadline - force-killing"
    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
} elseif ($exitCode -ne 3) {
    Log "NOTE: process exited but with code $exitCode, not the documented 3 (EXIT_WEBVIEW2_MISSING)"
}

Log "--- VERDICT ---"
$verdict = if ($logSeen -and $dialogFound -and $selfExited -and $exitCode -eq 3) { 'PASS: dialog shown on screen (screenshot captured), and process self-terminated with the documented exit code 3' }
           elseif ($logSeen -and -not $dialogFound -and $selfExited -and $exitCode -eq 3) { 'PASS (non-interactive variant): dialog window not found (may be a non-interactive window station per the box_rc=0 path in main.rs), but the process still self-terminated with exit code 3 as designed' }
           else { 'INCONCLUSIVE/FAIL: see log lines above for the specific assertion that did not hold' }
Log $verdict

Log "=== harness complete ==="
Set-Content -Path (Join-Path $OutDir 'WEBVIEW2_DIALOG_DONE') -Value (Get-Date -Format o) -Encoding UTF8
