#Requires -Version 5.1
<#
.SYNOPSIS
    ZeroBreach V23 "Kraken Console" — Pure PowerShell HTTP Server
    No Python required. Self-hosted GUI via System.Net.HttpListener + SSE.
.DESCRIPTION
    Starts a local HTTP listener, serves the cyberpunk frontend, and bridges to
    ZeroBreach-V23.ps1 scan engine in real-time via Server-Sent Events (SSE).
    Admin elevation is handled automatically.
.PARAMETER Port
    HTTP port (default 0 = auto-find free port)
.PARAMETER NoBrowser
    Skip auto-opening the browser
#>
[CmdletBinding()]
param(
    [int]$Port      = 0,
    [switch]$NoBrowser
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

# ── Self-elevation ──────────────────────────────────────────────────────────────
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[ZeroBreach] Requesting elevation...' -ForegroundColor Cyan
    $argStr = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Port -gt 0) { $argStr += " -Port $Port" }
    if ($NoBrowser)  { $argStr += " -NoBrowser" }
    Start-Process powershell $argStr -Verb RunAs
    exit
}

# ── Paths ──────────────────────────────────────────────────────────────────────
# Keep the script dir as CWD even after UAC elevation (elevation can drop to System32).
Set-Location -LiteralPath $PSScriptRoot
$script:ROOT      = $PSScriptRoot

# ── Portability: strip Mark-of-the-Web ─────────────────────────────────────────
# A downloaded/transferred copy carries Zone.Identifier ADS on every extracted file.
# -ExecutionPolicy Bypass covers our own scripts, but unblock the runtime tree anyway
# so nothing downstream (engine spawn, data loads, browser-served assets) can trip on
# zone marks on a foreign box. Runtime files only — reports/ and dev folders skipped.
try {
    Get-ChildItem -LiteralPath $script:ROOT -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.ps1','.bat','.md' } | Unblock-File -ErrorAction SilentlyContinue
    foreach ($sub in @('engine', 'gui', 'data')) {
        $dir = Join-Path $script:ROOT $sub
        if (Test-Path $dir) {
            Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.ps1','.js','.css','.html','.json' } |
                Unblock-File -ErrorAction SilentlyContinue
        }
    }
} catch {}
$script:SCAN_PS   = Join-Path $ROOT 'ZeroBreach-V23.ps1'
$script:GUI_DIR   = Join-Path $ROOT 'gui'
$script:REPORTS   = Join-Path $ROOT 'reports'
if (-not (Test-Path $script:REPORTS)) {
    try {
        New-Item -ItemType Directory -Path $script:REPORTS -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host ('[ZeroBreach] FATAL: cannot create reports folder at ' + $script:REPORTS) -ForegroundColor Red
        Write-Host ('             ' + $_.Exception.Message) -ForegroundColor Red
        Write-Host '             The drive may be read-only or ejected. Copy ZeroBreach to a writable location.' -ForegroundColor Yellow
        exit 1
    }
}

# ── Durable logging ─────────────────────────────────────────────────────────────
# Post-run validation needs more than the (ephemeral) browser/console. Two files in reports\:
#   • server_console_*.log — main-thread server console (banners, listener/request errors),
#     captured via Start-Transcript; Stop-Transcript runs in the accept-loop finally.
#   • server_events_*.log  — the FULL SSE event stream (every log_line, finding, [FIX] line,
#     and the remediation_complete applied/failed/skipped/blocked summary), teed to disk by
#     Enqueue/REnqueue inside the scan + remediation runspaces (their output never hits the
#     console — it only flows to the in-memory EventLog → SSE → browser, so a transcript alone
#     would miss it). Path is carried on $script:State.EventLogFile so both runspaces can reach it.
$script:LOG_STAMP   = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:EVENT_LOG   = Join-Path $script:REPORTS ('server_events_{0}.log'  -f $script:LOG_STAMP)
$script:CONSOLE_LOG = Join-Path $script:REPORTS ('server_console_{0}.log' -f $script:LOG_STAMP)
try { Start-Transcript -LiteralPath $script:CONSOLE_LOG -Force -ErrorAction Stop | Out-Null } catch {}

# ── MITRE ATT&CK map (loaded once; injected into the scan runspace for tagging) ─
# data/*.json is NOT AMSI-scanned, so this is safe to load at runtime.
$script:MITRE_MAP = $null
$mitrePath = Join-Path $ROOT 'data\mitre_mapping.json'
if (Test-Path $mitrePath) {
    try { $script:MITRE_MAP = Get-Content -LiteralPath $mitrePath -Raw -ErrorAction Stop | ConvertFrom-Json }
    catch { $script:MITRE_MAP = $null }
}

# ── Shared State (synchronized — accessed by multiple runspaces) ───────────────
$script:State = [hashtable]::Synchronized(@{
    Running      = $false
    ScanComplete = $false
    Phase        = 0
    PhaseTotal   = 115
    PhaseName    = ''
    Section      = ''
    Mode         = 'FULL'
    Elapsed      = 0
    StartTime    = [datetime]::MinValue
    LineCount    = 0
    ResultsPath  = ''
    Listening    = $true
    EventLogFile = $script:EVENT_LOG   # durable tee of the SSE event stream (set above); read by Enqueue/REnqueue
    ScanEpoch    = 0      # bumped each time EventLog is cleared for a new scan; SSE clients rewind on change
    Process      = $null
    EngineReport = ''     # filename of the engine's rich KrakenBaseline_*.json from the last scan
    Remediating  = $false
    EventLog     = [System.Collections.ArrayList]::Synchronized(
                       [System.Collections.ArrayList]::new())
    Findings     = [System.Collections.ArrayList]::Synchronized(
                       [System.Collections.ArrayList]::new())
    ThreatCounts = [hashtable]::Synchronized(@{
        RAT=0; Rootkit=0; Ransomware=0; Keylogger=0; Worm=0
        Miner=0; Trojan=0; Spyware=0; Fileless=0; Other=0
    })
})

# ── MIME types ─────────────────────────────────────────────────────────────────
$script:MIME = @{
    '.html' = 'text/html; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
    '.js'   = 'application/javascript; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'
    '.ico'  = 'image/x-icon'
    '.png'  = 'image/png'
    '.svg'  = 'image/svg+xml'
    '.woff2'= 'font/woff2'
    '.woff' = 'font/woff'
    '.ttf'  = 'font/ttf'
}

# ── Classification patterns (used by main thread and embedded in SCAN_SCRIPT) ──
$script:SEV_PATTERNS = [ordered]@{
    CRITICAL = [regex]'\[CRIT\]|CRITICAL|\[!!\]|THREAT BANNER|IOC HIT|BLATANT'
    HIGH     = [regex]'\[HIGH\]|HIGH SEVERITY|\[WARN\]|SUSPICIOUS'
    POSSIBLE = [regex]'\[POSSIBLE\]|POSSIBLE|FLAGGED|ANOMAL'
    CLEAN    = [regex]'\[OK\s*\]|CLEAN|NO .* FOUND|->\s*\[OK\s*\]'
    INFO     = [regex]'\[INFO\]|\[VER\]|EXECUTED|EVALUATED'
    HUNT     = [regex]'\[HUNT\]|SCANNING|CHECKING|AUDITING'
}

$script:PHASE_RE = [regex]'PHASE\s+(\d+)[^\d]'

# ── Helpers ────────────────────────────────────────────────────────────────────
function Get-FreePort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    $p = $l.LocalEndpoint.Port
    $l.Stop()
    return $p
}

function Write-JsonResponse {
    param($Ctx, [string]$Body, [int]$Code = 200)
    try {
        $r = $Ctx.Response
        $r.StatusCode    = $Code
        $r.ContentType   = 'application/json; charset=utf-8'
        $r.Headers['Access-Control-Allow-Origin']  = '*'
        $r.Headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $r.ContentLength64 = $bytes.Length
        $r.OutputStream.Write($bytes, 0, $bytes.Length)
        $r.OutputStream.Close()
    } catch {}
}

function Send-StaticFile {
    param($Ctx, [string]$FilePath)
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        Write-JsonResponse $Ctx '{"error":"not found"}' 404
        return
    }
    $ext  = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $mime = $script:MIME[$ext]
    if (-not $mime) { $mime = 'application/octet-stream' }
    try {
        $r = $Ctx.Response
        $r.StatusCode  = 200
        $r.ContentType = $mime
        $r.Headers['Access-Control-Allow-Origin'] = '*'
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $r.ContentLength64 = $bytes.Length
        $r.OutputStream.Write($bytes, 0, $bytes.Length)
        $r.OutputStream.Close()
    } catch {}
}

function Write-DownloadResponse {
    param($Ctx, [string]$Body, [string]$ContentType, [string]$FileName)
    try {
        $r = $Ctx.Response
        $r.StatusCode  = 200
        $r.ContentType = $ContentType
        $r.Headers['Access-Control-Allow-Origin'] = '*'
        $r.Headers['Content-Disposition'] = "attachment; filename=`"$FileName`""
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $r.ContentLength64 = $bytes.Length
        $r.OutputStream.Write($bytes, 0, $bytes.Length)
        $r.OutputStream.Close()
    } catch {}
}

# Build a self-contained HTML report from the current scan findings.
function Get-HtmlReport {
    $findings = @($script:State.Findings)
    $sevColor = @{ CRITICAL='#ff3838'; HIGH='#ff9500'; POSSIBLE='#ffd60a'; INFO='#6b7280'; CLEAN='#39ff9a' }
    $counts   = $script:State.ThreatCounts
    $total    = $findings.Count
    $sevRank  = @{ CRITICAL=0; HIGH=1; POSSIBLE=2; INFO=3; CLEAN=4 }
    $sorted   = $findings | Sort-Object @{ Expression = { $r = $sevRank["$($_.severity)"]; if ($null -ne $r) { $r } else { 9 } } }

    $rows = foreach ($f in $sorted) {
        $sev  = "$($f.severity)"
        $col  = $sevColor[$sev]; if (-not $col) { $col = '#6b7280' }
        $desc = [System.Net.WebUtility]::HtmlEncode("$($f.line)")
        $type = [System.Net.WebUtility]::HtmlEncode("$($f.threat_type)")
        $mitreCell = ''
        if ($f.mitre -and $f.mitre.id) {
            $mid = [System.Net.WebUtility]::HtmlEncode("$($f.mitre.id)")
            $mnm = [System.Net.WebUtility]::HtmlEncode("$($f.mitre.name)")
            $url = "$($f.mitre.url)"; if (-not $url) { $url = "https://attack.mitre.org/techniques/$($f.mitre.id -replace '\.','/')/" }
            $mitreCell = "<a href='$([System.Net.WebUtility]::HtmlEncode($url))' target='_blank' title='$mnm'>$mid</a>"
        }
        "<tr><td><span class='badge' style='background:$col'>$sev</span></td><td>PH$($f.phase)</td><td>$type</td><td>$mitreCell</td><td>$desc</td></tr>"
    }

    $tally = foreach ($k in @('RAT','Rootkit','Ransomware','Keylogger','Worm','Miner','Trojan','Spyware','Fileless','Other')) {
        $v = [int]$counts[$k]
        if ($v -gt 0) { "<span class='chip'>$k <b>$v</b></span>" }
    }

    $genAt = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    @"
<!doctype html><html><head><meta charset="utf-8"><title>ZeroBreach Report — $($env:COMPUTERNAME)</title>
<style>
body{background:#05080c;color:#cde3f0;font-family:"Segoe UI",system-ui,monospace;margin:0;padding:28px}
h1{color:#00d9ff;letter-spacing:3px;font-size:22px;margin:0 0 4px}
.meta{color:#7d97a8;font-size:12px;margin-bottom:18px}
.chips{margin:14px 0 22px}
.chip{display:inline-block;background:#0d1620;border:1px solid #1b2b3a;border-radius:14px;padding:4px 11px;margin:3px;font-size:12px;color:#9fc1d6}
.chip b{color:#00d9ff;margin-left:4px}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{border:1px solid #16222e;padding:7px 9px;text-align:left;vertical-align:top}
th{background:#0c1622;color:#6fb6d8;text-transform:uppercase;letter-spacing:1px;font-size:11px}
tr:nth-child(even){background:#080f16}
.badge{color:#03121a;font-weight:700;padding:2px 8px;border-radius:4px;font-size:11px}
a{color:#00d9ff;text-decoration:none}a:hover{text-decoration:underline}
.empty{color:#39ff9a;padding:30px;text-align:center}
</style></head><body>
<h1>◈ ZEROBREACH V23 — INCIDENT REPORT</h1>
<div class="meta">Host: $([System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME)) &nbsp;·&nbsp; Mode: $($script:State.Mode) &nbsp;·&nbsp; Findings: $total &nbsp;·&nbsp; Generated: $genAt</div>
<div class="chips">$($tally -join '')</div>
$(if ($total -gt 0) { "<table><tr><th>Severity</th><th>Phase</th><th>Threat</th><th>ATT&CK</th><th>Detail</th></tr>$($rows -join '')</table>" } else { "<div class='empty'>✓ NO FINDINGS — SYSTEM APPEARS CLEAN</div>" })
</body></html>
"@
}

function Get-CsvReport {
    $findings = @($script:State.Findings)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('"Severity","Phase","ThreatType","ATTACK_ID","ATTACK_Name","Detail","Timestamp"')
    foreach ($f in $findings) {
        $mid = if ($f.mitre -and $f.mitre.id) { "$($f.mitre.id)" } else { '' }
        $mnm = if ($f.mitre -and $f.mitre.name) { "$($f.mitre.name)" } else { '' }
        $cells = @("$($f.severity)", "PH$($f.phase)", "$($f.threat_type)", $mid, $mnm, "$($f.line)", "$($f.timestamp)")
        $line = ($cells | ForEach-Object { '"' + ($_ -replace '"','""') + '"' }) -join ','
        [void]$sb.AppendLine($line)
    }
    return $sb.ToString()
}

# Main-thread MITRE resolver (mirrors the runspace copy; uses $script:MITRE_MAP).
function Resolve-MitreMain {
    param([string]$Line, [string]$ThreatType, $Phase)
    $map = $script:MITRE_MAP
    if (-not $map) { return $null }
    $ll = "$Line".ToLower()
    $id = $null
    foreach ($p in $map.keyword_map.PSObject.Properties) {
        if ($p.Name -eq '_comment') { continue }
        if ($ll.Contains($p.Name)) { $id = [string]$p.Value; break }
    }
    if (-not $id -and $ThreatType) {
        $arr = $map.threat_type_map.$ThreatType
        if ($arr) { $id = [string]$arr[0] }
    }
    if (-not $id -and $Phase -gt 0) {
        # Mirror of the runspace Resolve-Mitre: exact (possibly fractional) phase key
        # first, then the integer phase's entry.
        $pe = $map.phase_map."PHASE $Phase"
        if (-not ($pe -and $pe.techniques)) { $pe = $map.phase_map."PHASE $([int][math]::Floor([double]$Phase))" }
        if ($pe -and $pe.techniques) { $id = [string]$pe.techniques[0] }
    }
    if (-not $id) { return $null }
    $t = $map.techniques.$id
    if (-not $t) { return @{ id = $id; name = $id; tactic = ''; url = '' } }
    $tactic = if ($t.tactics) { [string]$t.tactics[0] } else { '' }
    return @{ id = $id; name = $t.name; tactic = $tactic; url = $t.url }
}

# ── Trusted vendor (RMM partner) allowlist ──────────────────────────────────────
# Datto / CentraStage / Kaseya are legitimate managed-services partner tooling, NOT malware.
# Returns a reason if a finding is just this tooling doing its normal job, else ''. This is a
# *soft* signal (suppresses auto-selection + labels it; the operator can still act manually) —
# unlike Test-ProtectedTarget which is a hard block. Uses judgment: a vendor-named artifact in a
# suspicious location, or with an independent malicious signal, is NOT trusted (stays flagged).
function Test-VendorTrusted {
    param([string]$Action, [string]$Param, [string]$Target, [string]$Desc)
    $p = "$Param"; $hay = "$p`n$Target`n$Desc"
    if ($hay -notmatch '(?i)(centrastage|datto|kaseya|aemagent|cagservice|agentmon|kworking)') { return '' }
    # Vendor name in a user temp/download/cache location is suspicious for RMM — let it flag.
    if ($p -match '(?i)\\(Temp|Downloads|INetCache|Temporary Internet Files|Content\.Outlook)\\') { return '' }
    # Independent strong malicious signal overrides the trust (use judgment — flag if off).
    if ($hay -match '(?i)(known\s*malware|sha256 matches|matches known|masquerad|hollow|injected|mimikatz|cobalt\s*strike|reverse\s*shell|ransom|\blsass\b|keylog)') { return '' }
    return 'Datto/CentraStage/Kaseya RMM — trusted partner tooling'
}

# ── SAFETY: protected-resource guard ────────────────────────────────────────────
# Priority #1 — the tool must NEVER remediate (or even auto-select) anything that would
# damage the system. Returns a human reason if the fix would touch a protected resource,
# else ''. Deliberately conservative: a real threat in one of these locations is *audited*
# but never auto-acted-on (the operator handles it manually). Mirrored verbatim in the
# REMEDIATE_SCRIPT runspace below — keep both copies in sync.
function Test-ProtectedTarget {
    param([string]$Action, [string]$Param, [string]$Target, [string]$Desc)
    $p = "$Param"; $t = "$Target"; $d = "$Desc"
    $hay = "$p`n$t`n$d"

    # Certificate trust store — deleting root/CA certs breaks TLS / Windows Update / code-signing.
    if ($p -match '(?i)Cert:\\' -or $hay -match '(?i)(root\s+ca|trusted\s+root|certificate\s+(store|authority))') {
        return 'certificate trust store (deleting breaks HTTPS / code-signing)'
    }
    # Windows / system directories and shell/system files.
    if ($p -match '(?i)^[a-z]:\\windows\\' -or $p -match '(?i)\\(System32|SysWOW64|WinSxS)\\') {
        return 'Windows system directory'
    }
    if ($p -match '(?i)\\(desktop\.ini|iconcache\.db|thumbs\.db|ntuser\.dat|usrclass\.dat)' -or $p -match '(?i)\.library-ms$') {
        return 'Windows shell/system file'
    }
    # User shell / git / ssh / cloud config (dotfiles in the profile, or known config dirs).
    if ($p -match '(?i)\\Users\\[^\\]+\\\.[^\\]+$' -or
        $p -match '(?i)\\\.(ssh|gnupg|aws|azure|kube|docker|config)\\' -or
        $p -match '(?i)\\\.(bashrc|bash_profile|bash_history|profile|zshrc|gitconfig|npmrc|claude\.json)($|[^a-z])' -or
        $p -match '(?i)\\\.claude\\') {
        return 'user shell/git/ssh/cloud config (dotfile)'
    }
    # SafeBoot registry — deleting it breaks Safe Mode boot.
    if ($p -match '(?i)\\SafeBoot') { return 'SafeBoot registry (deleting breaks Safe Mode)' }
    # Core OS registry hives.
    if ($Action -match '(?i)DeleteReg' -and $p -match '(?i)\\(SYSTEM\\CurrentControlSet\\(Services|Control)|Microsoft\\Windows NT\\CurrentVersion\\(Winlogon|Image File Execution Options|SystemRestore)|Cryptography)') {
        return 'core OS registry'
    }
    # Critical processes / the IR tool itself (KillProcess). FixParam is a PID, so match the name in the description.
    if ($Action -eq 'KillProcess' -and $d -match '(?i)(\b(System|smss|csrss|wininit|winlogon|services|lsass|svchost|dwm|fontdrvhost|explorer|powershell|pwsh|conhost|RuntimeBroker|MsMpEng)\b|claude|zerobreach)') {
        return 'critical system process or the IR tool itself'
    }
    return ''
}

# Load the engine's rich report and normalize its findings to the frontend shape,
# enriching each with a MITRE tag. Carries FixAction/FixParam so the GUI can remediate.
# Findings touching a protected resource are tagged so the UI won't auto-select them and
# the remediation runspace will hard-block them.
function Get-EngineReportFindings {
    param([string]$ReportPath)
    $out = [System.Collections.ArrayList]::new()
    try {
        $report = (Get-Content -LiteralPath $ReportPath -Raw) | ConvertFrom-Json
    } catch { return @() }
    $i = 0
    foreach ($f in @($report.Findings)) {
        $sev = "$($f.Severity)".ToUpper()
        $tt  = "$($f.ThreatType)"; if (-not $tt) { $tt = $null }
        $phNum = 0; $pm = [regex]::Match("$($f.Phase)", '\d+(?:\.\d+)?'); if ($pm.Success) { $phNum = if ($pm.Value.Contains('.')) { [double]$pm.Value } else { [int]$pm.Value } }
        $line = if ($f.Target) { "$($f.Description) -> $($f.Target)" } else { "$($f.Description)" }
        $mit  = Resolve-MitreMain $line $tt $phNum
        $prot = Test-ProtectedTarget "$($f.FixAction)" "$($f.FixParam)" "$($f.Target)" "$($f.Description)"
        $vend = Test-VendorTrusted   "$($f.FixAction)" "$($f.FixParam)" "$($f.Target)" "$($f.Description)"
        [void]$out.Add([ordered]@{
            id               = "$($f.ID)"
            line             = $line
            severity         = $sev
            threat_type      = $tt
            phase            = $phNum
            group            = "$($f.Group)"
            fix_action       = "$($f.FixAction)"
            fix_param        = "$($f.FixParam)"
            protected        = [bool]$prot
            protected_reason = $prot
            vendor_trusted   = [bool]$vend
            vendor_reason    = $vend
            mitre            = $mit
            mitre_id         = if ($mit) { $mit.id } else { $null }
            timestamp        = "$($f.Timestamp)"
        })
        $i++
    }
    return @($out)
}

function Read-RequestBody {
    param($Ctx)
    try {
        $sr = [System.IO.StreamReader]::new(
            $Ctx.Request.InputStream, [System.Text.Encoding]::UTF8)
        return $sr.ReadToEnd()
    } catch { return '{}' }
}

function Get-SysInfoJson {
    try {
        $cpuObj = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
        $cpu    = if ($cpuObj) {
            ($cpuObj | Measure-Object LoadPercentage -Average).Average
        } else { 0 }

        $osObj  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $ramPct = if ($osObj -and $osObj.TotalVisibleMemorySize -gt 0) {
            [math]::Round(
                ($osObj.TotalVisibleMemorySize - $osObj.FreePhysicalMemory) /
                $osObj.TotalVisibleMemorySize * 100, 1)
        } else { 0 }

        $defender = (Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled

        return [ordered]@{
            hostname  = $env:COMPUTERNAME
            username  = $env:USERNAME
            os        = if ($osObj) { $osObj.Caption } else { 'Windows' }
            cpu       = [math]::Round([double]($cpu), 1)
            ram_used  = $ramPct
            defender  = [bool]$defender
        } | ConvertTo-Json -Compress
    } catch {
        return '{"error":"sysinfo unavailable"}'
    }
}

# ── Background runspace launcher ────────────────────────────────────────────────
function Start-Runspace {
    param([string]$Script, [hashtable]$Vars = @{})
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rs.Open()
    foreach ($k in $Vars.Keys) {
        $rs.SessionStateProxy.SetVariable($k, $Vars[$k])
    }
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($Script)
    $null = $ps.BeginInvoke()
    return $ps
}

# ── SSE Stream Script (self-contained, runs in its own runspace) ───────────────
# Variables injected: $SseState (SharedState hashtable), $SseCtx (HttpListenerContext)
$script:SSE_SCRIPT = @'
$response = $SseCtx.Response
$response.StatusCode = 200
$response.ContentType = 'text/event-stream; charset=utf-8'
$response.Headers['Cache-Control']       = 'no-cache, no-store'
$response.Headers['X-Accel-Buffering']   = 'no'
$response.Headers['Access-Control-Allow-Origin'] = '*'
$response.Headers['Connection']          = 'keep-alive'
$response.SendChunked = $true

$enc    = [System.Text.Encoding]::UTF8
$stream = $response.OutputStream

function Push {
    param([string]$Data)
    $bytes = $enc.GetBytes("data: $Data`n`n")
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
}

function Ping {
    $bytes = $enc.GetBytes(": ka`n`n")
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
}

# Send initial sync so page-reload during a scan gets full state
$syncObj = [ordered]@{
    type          = 'sync'
    running       = $SseState.Running
    scan_complete = $SseState.ScanComplete
    phase         = $SseState.Phase
    phase_total   = $SseState.PhaseTotal
    phase_name    = $SseState.PhaseName
    elapsed       = $SseState.Elapsed
    threat_counts = $SseState.ThreatCounts
    findings_count = $SseState.Findings.Count
}
Push ($syncObj | ConvertTo-Json -Compress -Depth 3)

$idx   = 0
$epoch = $SseState.ScanEpoch
$last  = [datetime]::Now

try {
    while ($SseState.Listening) {
        # A new scan clears EventLog and bumps ScanEpoch. Rewinding on the epoch
        # change (rather than on count comparison) is robust regardless of how fast
        # the new scan refills the log — the old count-compare guard could miss the
        # boundary where the refilled count momentarily equalled the stale cursor and
        # silently drop the new scan's first events for an already-open tab.
        if ($SseState.ScanEpoch -ne $epoch) { $idx = 0; $epoch = $SseState.ScanEpoch }
        $count = $SseState.EventLog.Count
        if ($idx -gt $count) { $idx = 0 }   # extra safety: cursor past end (shouldn't happen)
        while ($idx -lt $count) {
            Push $SseState.EventLog[$idx]
            $idx++
        }
        if (([datetime]::Now - $last).TotalSeconds -gt 20) {
            Ping
            $last = [datetime]::Now
        }
        Start-Sleep -Milliseconds 40
    }
} catch {
    # client disconnected — normal exit
} finally {
    try { $stream.Close() }    catch {}
    try { $response.Close() }  catch {}
}
'@

# ── Scan Engine Script (self-contained, runs in its own runspace) ──────────────
# Variables injected: $ScanState, $ScanConfig (hashtable), $ScanPsPath, $ScanReports
$script:SCAN_SCRIPT = @'
# ── Inline classification (can't reference main-script functions from runspace) ─
# NOTE: named $SEV_RX, not $SEV — PowerShell variables are case-insensitive, so a
# dict named $SEV is SHADOWED inside Classify by its local `$sev = 'INFO'`, making
# $SEV.Keys read the string 'INFO' (→ $null) and every line classify as INFO. This
# exact bug shipped and silently killed severity classification for weeks.
$SEV_RX = [ordered]@{
    CRITICAL = [regex]'\[CRIT\]|CRITICAL|\[!!\]|THREAT BANNER|IOC HIT|BLATANT'
    HIGH     = [regex]'\[HIGH\]|HIGH SEVERITY|\[WARN\]|SUSPICIOUS'
    POSSIBLE = [regex]'\[POSSIBLE\]|POSSIBLE|FLAGGED|ANOMAL'
    CLEAN    = [regex]'\[OK\s*\]|CLEAN|NO .* FOUND|->\s*\[OK\s*\]'
    INFO     = [regex]'\[INFO\]|\[VER\]|EXECUTED|EVALUATED'
    HUNT     = [regex]'\[HUNT\]|SCANNING|CHECKING|AUDITING'
}

$TKW = @{
    RAT        = @('rat','c2','beacon','asyncrat','njrat','remcos','darkcomet')
    Rootkit    = @('rootkit','kernel driver','bootkit','mbr','hidden process')
    Ransomware = @('ransomware','ransom','extension velocity','high entropy','ransom note')
    Keylogger  = @('keylogger','keystroke','clipboard')
    Worm       = @('worm','autorun','usb spread','network share')
    Miner      = @('cryptominer','miner','cpu abuse','xmrig')
    Trojan     = @('trojan','dropper','downloader','loader')
    Spyware    = @('spyware','adware','pup','info-stealer','stealer')
    Fileless   = @('fileless','base64 blob','registry payload','amsi bypass','etw')
    Other      = @('backdoor','exploit','cve-','lolbin','uac bypass')
}

# Captures fractional phases (55.5, 74.5/.6/.7, 99.5) as well as integers — they are
# real plan steps with their own banners, findings and MITRE map entries.
$PREX = [regex]'PHASE\s+(\d+(?:\.\d+)?)[^\d]'

# Plan-derived ceilings — must mirror the engine loader's $PhasePlan switch
# (QUICK 1-30, FULL 1-80, DEEP/PARANOID/STEALTH 1-115). Fractional phases
# interpolate within these bounds rather than adding to the total.
$MODE_PHASES = @{ QUICK=30; FULL=80; DEEP=115; PARANOID=115; STEALTH=115 }

function Classify {
    param([string]$L)
    $sev = 'INFO'
    foreach ($k in $SEV_RX.Keys) { if ($SEV_RX[$k].IsMatch($L)) { $sev = $k; break } }
    $ll = $L.ToLower()
    $tt = $null
    foreach ($k in $TKW.Keys) {
        foreach ($kw in $TKW[$k]) { if ($ll.Contains($kw)) { $tt = $k; break } }
        if ($tt) { break }
    }
    return @{ sev = $sev; tt = $tt }
}

function Enqueue {
    param([hashtable]$Ev)
    $json = $Ev | ConvertTo-Json -Compress -Depth 4
    [void]$ScanState.EventLog.Add($json)
    # Tee to the durable event log (runspace output never reaches the console — see header).
    if ($ScanState.EventLogFile) {
        $line = ('{0} {1}{2}' -f (Get-Date -Format 'HH:mm:ss'), $json, [Environment]::NewLine)
        for ($i = 0; $i -lt 3; $i++) {
            try { [System.IO.File]::AppendAllText($ScanState.EventLogFile, $line); break } catch { Start-Sleep -Milliseconds 15 }
        }
    }
}

# ── MITRE ATT&CK resolution ($MitreMap injected from the main thread; may be $null) ─
# Fallback chain mirrors data/mitre_mapping.json's intent: most-specific keyword first,
# then the threat-type category, then the phase's dominant technique.
function Resolve-Mitre {
    param([string]$Line, [string]$ThreatType, $Phase)
    if (-not $MitreMap) { return $null }
    $ll = $Line.ToLower()
    $id = $null
    foreach ($p in $MitreMap.keyword_map.PSObject.Properties) {
        if ($p.Name -eq '_comment') { continue }
        if ($ll.Contains($p.Name)) { $id = [string]$p.Value; break }
    }
    if (-not $id -and $ThreatType) {
        $arr = $MitreMap.threat_type_map.$ThreatType
        if ($arr) { $id = [string]$arr[0] }
    }
    if (-not $id -and $Phase -gt 0) {
        # Fractional phases (55.5, 74.5, ...) have their own map keys; fall back to
        # the integer phase's entry when a fractional key is absent.
        $pe = $MitreMap.phase_map."PHASE $Phase"
        if (-not ($pe -and $pe.techniques)) { $pe = $MitreMap.phase_map."PHASE $([int][math]::Floor([double]$Phase))" }
        if ($pe -and $pe.techniques) { $id = [string]$pe.techniques[0] }
    }
    if (-not $id) { return $null }
    $t = $MitreMap.techniques.$id
    if (-not $t) { return @{ id = $id; name = $id; tactic = ''; url = '' } }
    $tactic = if ($t.tactics) { [string]$t.tactics[0] } else { '' }
    return @{ id = $id; name = $t.name; tactic = $tactic; url = $t.url }
}

# ── Extract config ──────────────────────────────────────────────────────────────
$mode     = if ($ScanConfig.mode)    { "$($ScanConfig.mode)" }   else { 'FULL' }
$hours    = if ($null -ne $ScanConfig.hours) { [int]$ScanConfig.hours } else { 0 }
$doHtml   = [bool]$ScanConfig.html_report
$paranoid = [bool]$ScanConfig.paranoid
$stealth  = [bool]$ScanConfig.stealth
$iocFile  = "$($ScanConfig.ioc_file)"

# ── Reset state for new scan ────────────────────────────────────────────────────
$ScanState.Mode         = $mode
$ScanState.PhaseTotal   = if ($MODE_PHASES[$mode]) { $MODE_PHASES[$mode] } else { 115 }
$ScanState.Phase        = 0
$ScanState.PhaseName    = ''
$ScanState.Section      = ''
$ScanState.Elapsed      = 0
$ScanState.LineCount    = 0
$ScanState.ResultsPath  = ''
$ScanState.Running      = $true
$ScanState.ScanComplete = $false
$ScanState.StartTime    = [datetime]::Now
$ScanState.Findings.Clear()
$ScanState.EventLog.Clear()
$ScanState.ScanEpoch++   # signal already-open SSE tabs to rewind to event 0 for this new scan
foreach ($k in @($ScanState.ThreatCounts.Keys)) { $ScanState.ThreatCounts[$k] = 0 }

# ── Build PowerShell command ────────────────────────────────────────────────────
$psArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$ScanPsPath`""
$psArgs += " -Mode $mode -Hours $hours -Auto -OutDir `"$ScanReports`""
if ($doHtml)   { $psArgs += ' -Html' }
if ($paranoid) { $psArgs += ' -Paranoid' }
if ($stealth)  { $psArgs += ' -Stealth' }
if ($iocFile -and (Test-Path $iocFile)) { $psArgs += " -IocFile `"$iocFile`"" }

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName               = 'powershell.exe'
$psi.Arguments              = $psArgs
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.UseShellExecute        = $false
$psi.CreateNoWindow         = $true
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8

$proc = $null
try {
    $proc = [System.Diagnostics.Process]::Start($psi)
    $ScanState.Process = $proc

    # Drain stderr asynchronously so its buffer never fills and deadlocks the child
    $proc.BeginErrorReadLine()

    # STEALTH mode: the engine suppresses all formatted output and emits a single
    # compressed-JSON audit blob to stdout at the very end. We buffer raw lines and
    # parse that blob after exit (see post-loop block) instead of classifying text.
    $stealthLines = [System.Collections.Generic.List[string]]::new()
    if ($stealth) {
        Enqueue @{ type='log_line'; text='[STEALTH] Silent scan running — output is suppressed; results arrive at completion.'; severity='INFO'; phase=0; elapsed=0 }
    }

    while (-not $proc.StandardOutput.EndOfStream) {
        if (-not $ScanState.Running) {
            try { $proc.Kill() } catch {}
            break
        }

        $raw = $proc.StandardOutput.ReadLine()
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }

        if ($stealth) { $stealthLines.Add($raw); continue }

        $elapsed = [int]([datetime]::Now - $ScanState.StartTime).TotalSeconds
        $ScanState.Elapsed = $elapsed

        # Structured finding line — the engine's Add-Finding emits one compact-JSON
        # line per registered finding in GUI runs ("[FINDING] {...}"). This is the
        # authoritative live-finding source: exact severity, no text-regex guessing.
        # The raw JSON line never reaches the log view.
        if ($raw.StartsWith('[FINDING] ')) {
            $fobj = $null
            try { $fobj = $raw.Substring(10) | ConvertFrom-Json } catch {}
            if ($fobj) {
                $fsev = "$($fobj.sev)".ToUpper()
                if ($fsev -in @('CRITICAL','HIGH','POSSIBLE')) {
                    $pnum = $ScanState.Phase
                    $pm2 = $PREX.Match("$($fobj.phase) ")
                    if ($pm2.Success) {
                        $pv2 = $pm2.Groups[1].Value
                        $pnum = if ($pv2.Contains('.')) { [double]$pv2 } else { [int]$pv2 }
                    }
                    # Canonical threat bucket: engine ThreatType is free text — try the
                    # 10 canonical names first, then keyword-classify type+description.
                    $ttRaw = "$($fobj.tt)"
                    $tt2 = $null
                    foreach ($k in $TKW.Keys) { if ($ttRaw -match "^$k") { $tt2 = $k; break } }
                    if (-not $tt2) { $tt2 = (Classify ("$ttRaw $($fobj.desc)")).tt }
                    if (-not $tt2) { $tt2 = 'Other' }
                    $mit = Resolve-Mitre "$($fobj.desc)" $tt2 $pnum
                    $f = [ordered]@{
                        type        = 'finding'
                        id          = $ScanState.Findings.Count
                        line        = ('[{0}] {1}' -f $fsev, "$($fobj.desc)")
                        severity    = $fsev
                        threat_type = $tt2
                        phase       = $pnum
                        mitre       = $mit
                        mitre_id    = if ($mit) { $mit.id } else { $null }
                        fix_action  = "$($fobj.fix)"
                        target      = "$($fobj.target)"
                        timestamp   = [datetime]::Now.ToString('HH:mm:ss')
                    }
                    [void]$ScanState.Findings.Add($f)
                    if ($ScanState.ThreatCounts.ContainsKey($tt2)) { $ScanState.ThreatCounts[$tt2]++ }
                    else { $ScanState.ThreatCounts['Other']++ }
                    Enqueue $f
                }
                continue
            }
        }

        # Phase number
        $pm = $PREX.Match($raw)
        $phaseChanged = $false
        if ($pm.Success) {
            # Keep the decimal on fractional phases so they advance the counter (and
            # force the scan_state emit below) instead of truncating to the previous
            # integer phase and looking like a stall.
            $pv = $pm.Groups[1].Value
            $newPhase = if ($pv.Contains('.')) { [double]$pv } else { [int]$pv }
            if ($newPhase -ne $ScanState.Phase) { $ScanState.Phase = $newPhase; $phaseChanged = $true }
        }

        # Phase name from banner lines like  "──── PHASE 5 ── Description ────"
        if ($raw.Contains('PHASE') -and $raw.Contains([char]0x2500)) {
            $parts = $raw -split [char]0x2500
            if ($parts.Count -ge 3) {
                $ScanState.PhaseName = ($parts[2].Trim().Trim([char]0x2500)).Trim()
            }
        }

        # Force an immediate scan_state on every phase change so the UI counter can't
        # "skip" fast (sub-second) phases — the periodic %12 broadcast below alone lets
        # several phases pass between emits, making the counter jump (e.g. 94 -> 97).
        if ($phaseChanged) {
            Enqueue @{
                type          = 'scan_state'
                phase         = $ScanState.Phase
                phase_total   = $ScanState.PhaseTotal
                phase_name    = $ScanState.PhaseName
                section       = $ScanState.Section
                elapsed       = $elapsed
                threat_counts = $ScanState.ThreatCounts
                running       = $true
            }
        }

        $cl = Classify $raw
        $ScanState.LineCount++

        # Log event for every line
        Enqueue @{
            type     = 'log_line'
            text     = $raw
            severity = $cl.sev
            phase    = $ScanState.Phase
            elapsed  = $elapsed
        }

        # Finding events come exclusively from the structured "[FINDING] {...}" lines
        # intercepted above — creating them from text-severity matches here too would
        # double-count every detection. Classify is kept only for log-line coloring.

        # Periodic scan_state broadcast
        if ($ScanState.LineCount % 12 -eq 0) {
            Enqueue @{
                type          = 'scan_state'
                phase         = $ScanState.Phase
                phase_total   = $ScanState.PhaseTotal
                phase_name    = $ScanState.PhaseName
                section       = $ScanState.Section
                elapsed       = $elapsed
                threat_counts = $ScanState.ThreatCounts
                running       = $true
            }
        }
    }

    $proc.WaitForExit()

    # ── STEALTH post-processing: parse the engine's JSON audit blob into findings ──
    if ($stealth -and $ScanState.Running) {
        $ScanState.Elapsed = [int]([datetime]::Now - $ScanState.StartTime).TotalSeconds
        $jsonLine = $null
        for ($i = $stealthLines.Count - 1; $i -ge 0; $i--) {
            $cand = $stealthLines[$i].Trim()
            if ($cand.StartsWith('{') -and $cand.EndsWith('}')) { $jsonLine = $cand; break }
        }
        if (-not $jsonLine -and $stealthLines.Count -gt 0) {
            # Fallback: blob may be split across lines — join and try.
            $joined = ($stealthLines -join '').Trim()
            if ($joined.StartsWith('{') -and $joined.EndsWith('}')) { $jsonLine = $joined }
        }
        if ($jsonLine) {
            try {
                $audit = $jsonLine | ConvertFrom-Json
                foreach ($ef in @($audit.Findings)) {
                    $sev = "$($ef.Severity)".ToUpper()
                    $tt  = "$($ef.ThreatType)"
                    if (-not $tt) { $tt = $null }
                    $phNum = 0
                    $pm2 = [regex]::Match("$($ef.Phase)", '\d+(?:\.\d+)?')
                    if ($pm2.Success) { $phNum = if ($pm2.Value.Contains('.')) { [double]$pm2.Value } else { [int]$pm2.Value } }
                    $line = if ($ef.Target) { "[$sev] $($ef.Description) -> $($ef.Target)" } else { "[$sev] $($ef.Description)" }

                    Enqueue @{ type='log_line'; text=$line; severity=$sev; phase=$phNum; elapsed=$ScanState.Elapsed }

                    if ($sev -in @('CRITICAL','HIGH','POSSIBLE')) {
                        $mit = Resolve-Mitre $line $tt $phNum
                        $f = [ordered]@{
                            type        = 'finding'
                            id          = $ScanState.Findings.Count
                            line        = $line
                            severity    = $sev
                            threat_type = $tt
                            phase       = $phNum
                            mitre       = $mit
                            mitre_id    = if ($mit) { $mit.id } else { $null }
                            timestamp   = [datetime]::Now.ToString('HH:mm:ss')
                        }
                        [void]$ScanState.Findings.Add($f)
                        if ($tt) {
                            if ($ScanState.ThreatCounts.ContainsKey($tt)) { $ScanState.ThreatCounts[$tt]++ }
                            else { $ScanState.ThreatCounts['Other']++ }
                        }
                        Enqueue $f
                    }
                }
                $ScanState.Phase = $ScanState.PhaseTotal
            } catch {
                Enqueue @{ type='log_line'; text="[SCAN ERROR] STEALTH JSON parse failed: $($_.Exception.Message)"; severity='CRITICAL'; phase=0; elapsed=$ScanState.Elapsed }
            }
        } else {
            Enqueue @{ type='log_line'; text='[SCAN ERROR] STEALTH mode produced no parseable JSON output.'; severity='CRITICAL'; phase=0; elapsed=$ScanState.Elapsed }
        }
    }

} catch {
    Enqueue @{
        type     = 'log_line'
        text     = "[SCAN ERROR] $($_.Exception.Message)"
        severity = 'CRITICAL'
        phase    = $ScanState.Phase
        elapsed  = $ScanState.Elapsed
    }
} finally {
    $ScanState.Running    = $false
    $ScanState.ScanComplete = $true

    # Save JSON report
    $ts = [datetime]::Now.ToString('yyyyMMdd_HHmmss')
    $rp = Join-Path $ScanReports "audit_$ts.json"
    try {
        $json = [ordered]@{
            findings      = @($ScanState.Findings)
            threat_counts = $ScanState.ThreatCounts
            mode          = $ScanState.Mode
            elapsed       = $ScanState.Elapsed
            timestamp     = [datetime]::Now.ToString('o')
        } | ConvertTo-Json -Depth 6
        # UTF-8 *without* BOM, via .NET so it's identical on PS 5.1 and 7.
        # A BOM would break strict JSON parsers (incl. browser JSON.parse); 5.1's
        # -Encoding utf8 adds one, and 'utf8BOM' isn't a valid value on 5.1.
        [System.IO.File]::WriteAllText($rp, $json, (New-Object System.Text.UTF8Encoding($false)))
        $ScanState.ResultsPath = $rp
    } catch {}

    # Locate the engine's *rich* report (KrakenBaseline_*.json holds FixAction/FixParam
    # per finding) written by this run — used by GUI remediation.
    $engineReport = ''
    try {
        $kb = Get-ChildItem -LiteralPath $ScanReports -Filter 'KrakenBaseline_*.json' -ErrorAction SilentlyContinue |
              Where-Object { $_.LastWriteTime -ge $ScanState.StartTime.AddSeconds(-5) } |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($kb) { $engineReport = $kb.Name }
    } catch {}
    $ScanState.EngineReport = $engineReport

    # Final state broadcast
    Enqueue @{
        type          = 'scan_state'
        phase         = $ScanState.Phase
        phase_total   = $ScanState.PhaseTotal
        phase_name    = $ScanState.PhaseName
        section       = $ScanState.Section
        elapsed       = $ScanState.Elapsed
        threat_counts = $ScanState.ThreatCounts
        running       = $false
    }

    # Complete event
    Enqueue @{
        type           = 'scan_complete'
        findings_count = $ScanState.Findings.Count
        threat_counts  = $ScanState.ThreatCounts
        elapsed        = $ScanState.Elapsed
        results_path   = $ScanState.ResultsPath
        engine_report  = $engineReport
    }
}
'@

# ── Remediation Script (self-contained runspace) ───────────────────────────────
# Applies the engine's FixAction/FixParam for selected findings from a rich report.
# This mirrors ZeroBreach-V23.ps1's Invoke-FixMode switch; the server is admin and is
# the documented remediation driver. Variables injected: $RemState, $RemReports,
# $ReportPath (validated inside reports/), $FixIds (string[]).
$script:REMEDIATE_SCRIPT = @'
function REnqueue {
    param([hashtable]$Ev)
    $json = $Ev | ConvertTo-Json -Compress -Depth 4
    [void]$RemState.EventLog.Add($json)
    if ($RemState.EventLogFile) {
        $line = ('{0} {1}{2}' -f (Get-Date -Format 'HH:mm:ss'), $json, [Environment]::NewLine)
        for ($i = 0; $i -lt 3; $i++) {
            try { [System.IO.File]::AppendAllText($RemState.EventLogFile, $line); break } catch { Start-Sleep -Milliseconds 15 }
        }
    }
}
function RLog { param([string]$Text, [string]$Sev = 'INFO') REnqueue @{ type='log_line'; text=$Text; severity=$Sev; phase=0; elapsed=0 } }

# SAFETY: hard backstop — mirror of Test-ProtectedTarget (main thread). The tool must NEVER
# damage the system, so even a manually-selected finding is refused if it touches a protected
# resource. Keep in sync with the main-thread copy in Get-EngineReportFindings's vicinity.
function Test-RProtected {
    param([string]$Action, [string]$Param, [string]$Target, [string]$Desc)
    $p = "$Param"; $t = "$Target"; $d = "$Desc"; $hay = "$p`n$t`n$d"
    if ($p -match '(?i)Cert:\\' -or $hay -match '(?i)(root\s+ca|trusted\s+root|certificate\s+(store|authority))') { return 'certificate trust store' }
    if ($p -match '(?i)^[a-z]:\\windows\\' -or $p -match '(?i)\\(System32|SysWOW64|WinSxS)\\') { return 'Windows system directory' }
    if ($p -match '(?i)\\(desktop\.ini|iconcache\.db|thumbs\.db|ntuser\.dat|usrclass\.dat)' -or $p -match '(?i)\.library-ms$') { return 'Windows shell/system file' }
    if ($p -match '(?i)\\Users\\[^\\]+\\\.[^\\]+$' -or $p -match '(?i)\\\.(ssh|gnupg|aws|azure|kube|docker|config)\\' -or $p -match '(?i)\\\.(bashrc|bash_profile|bash_history|profile|zshrc|gitconfig|npmrc|claude\.json)($|[^a-z])' -or $p -match '(?i)\\\.claude\\') { return 'user shell/git/ssh/cloud config (dotfile)' }
    if ($p -match '(?i)\\SafeBoot') { return 'SafeBoot registry (breaks Safe Mode)' }
    if ($Action -match '(?i)DeleteReg' -and $p -match '(?i)\\(SYSTEM\\CurrentControlSet\\(Services|Control)|Microsoft\\Windows NT\\CurrentVersion\\(Winlogon|Image File Execution Options|SystemRestore)|Cryptography)') { return 'core OS registry' }
    if ($Action -eq 'KillProcess' -and $d -match '(?i)(\b(System|smss|csrss|wininit|winlogon|services|lsass|svchost|dwm|fontdrvhost|explorer|powershell|pwsh|conhost|RuntimeBroker|MsMpEng)\b|claude|zerobreach)') { return 'critical system process or the IR tool itself' }
    return ''
}

$RemState.Remediating = $true
$applied = 0; $failed = 0; $skipped = 0; $blocked = 0
try {
    if (-not (Test-Path -LiteralPath $ReportPath)) { RLog "[REMEDIATE] Report not found: $ReportPath" 'CRITICAL'; return }
    $report = (Get-Content -LiteralPath $ReportPath -Raw) | ConvertFrom-Json
    $idset = @{}; foreach ($id in @($FixIds)) { $idset["$id"] = $true }
    $sel = @($report.Findings) | Where-Object { $idset.ContainsKey("$($_.ID)") }
    RLog ("[REMEDIATE] {0} action(s) selected from {1}." -f $sel.Count, [System.IO.Path]::GetFileName($ReportPath)) 'INFO'

    foreach ($f in $sel) {
        $desc = "$($f.Description)"; if ($desc.Length -gt 70) { $desc = $desc.Substring(0,67) + '...' }

        # HARD BLOCK: never touch a protected resource, no matter what was selected.
        $why = Test-RProtected "$($f.FixAction)" "$($f.FixParam)" "$($f.Target)" "$($f.Description)"
        if ($why) {
            RLog "[BLOCKED] protected ($why) — refusing $($f.FixAction): $desc" 'POSSIBLE'
            $blocked++
            continue
        }

        RLog "[FIX] $desc" 'HUNT'
        $ok = $false
        try {
            switch ("$($f.FixAction)") {
                'DeleteFile' {
                    if (Test-Path -LiteralPath $f.FixParam) {
                        Remove-Item -LiteralPath $f.FixParam -Recurse -Force -ErrorAction Stop
                        if (Test-Path -LiteralPath $f.FixParam) {
                            $rpk = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
                            $cur = Get-ItemPropertyValue $rpk "PendingFileRenameOperations" -ErrorAction SilentlyContinue
                            if ($null -eq $cur) { $cur = @() }
                            Set-ItemProperty $rpk "PendingFileRenameOperations" ([string[]]($cur) + @("\??\$($f.FixParam)", "")) -Type MultiString -Force -ErrorAction SilentlyContinue
                            RLog "  -> locked; queued for reboot deletion." 'POSSIBLE'
                        } else { RLog "  -> deleted: $($f.FixParam)" 'OK' }
                        $ok = $true
                    } else { RLog "  -> already absent." 'OK'; $ok = $true }
                }
                'DeleteReg' {
                    $pts = "$($f.FixParam)" -split "\|", 2
                    if ($pts.Count -eq 2) {
                        Remove-ItemProperty -Path $pts[0] -Name $pts[1] -Force -ErrorAction SilentlyContinue
                        RLog "  -> reg value removed: $($pts[1])" 'OK'; $ok = $true
                    } else { RLog "  -> malformed reg target." 'POSSIBLE'; $failed++ }
                }
                'DeleteRegKey' {
                    if (Test-Path -LiteralPath $f.FixParam) {
                        Remove-Item -LiteralPath $f.FixParam -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path -LiteralPath $f.FixParam)) { RLog "  -> reg key deleted." 'OK'; $ok = $true }
                        else { RLog "  -> reg key delete failed." 'POSSIBLE'; $failed++ }
                    } else { RLog "  -> key already absent." 'OK'; $ok = $true }
                }
                'KillProcess' {
                    $procId = [int]"$($f.FixParam)"
                    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
                    if ($p) {
                        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 300
                        if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) { RLog "  -> terminated PID $procId ($($p.Name))" 'OK'; $ok = $true }
                        else { RLog "  -> kill failed PID $procId" 'POSSIBLE'; $failed++ }
                    } else { RLog "  -> process already gone." 'OK'; $ok = $true }
                }
                'RunCmd' {
                    # FixParam is generated by our own engine into the trusted report file.
                    $sb = [scriptblock]::Create("$($f.FixParam)")
                    & $sb | Out-Null
                    RLog "  -> command executed." 'OK'; $ok = $true
                }
                'Quarantine' {
                    $src = "$($f.FixParam)"
                    if (-not (Test-Path -LiteralPath $src)) { RLog "  -> already absent." 'OK'; $ok = $true }
                    else {
                        $vault = Join-Path $RemReports 'quarantine'
                        if (-not (Test-Path $vault)) { New-Item -Path $vault -ItemType Directory -Force | Out-Null }
                        $sha  = (Get-FileHash -LiteralPath $src -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        $stub = ([System.IO.Path]::GetFileName($src)) -replace '[^a-zA-Z0-9._-]','_'
                        $tag  = "{0}_{1}" -f (Get-Date -Format 'yyyyMMddHHmmssfff'), $stub
                        $dest = Join-Path $vault "$tag.quar"
                        $moved = $false
                        try { Move-Item -LiteralPath $src -Destination $dest -Force -ErrorAction Stop; $moved = $true }
                        catch {
                            try { Copy-Item -LiteralPath $src -Destination $dest -Force -ErrorAction Stop } catch {}
                            $rpk = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
                            $cur = Get-ItemPropertyValue $rpk "PendingFileRenameOperations" -ErrorAction SilentlyContinue
                            if ($null -eq $cur) { $cur = @() }
                            Set-ItemProperty $rpk "PendingFileRenameOperations" ([string[]]($cur) + @("\??\$src", "")) -Type MultiString -Force -ErrorAction SilentlyContinue
                        }
                        $manifest = @{
                            OriginalPath = $src; QuarantinedAs = $dest; SHA256 = $sha
                            ThreatType = "$($f.ThreatType)"; Severity = "$($f.Severity)"; Description = "$($f.Description)"
                            QuarantinedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                            RebootQueuedForOriginal = (-not $moved)
                            RestoreNote = "Move-Item '$dest' '$src' -Force"
                        }
                        $manifest | ConvertTo-Json | Set-Content -LiteralPath "$dest.json" -Encoding UTF8 -ErrorAction SilentlyContinue
                        if ($moved) { RLog "  -> quarantined -> $dest" 'OK' } else { RLog "  -> copied to vault; original queued for reboot deletion." 'POSSIBLE' }
                        $ok = $true
                    }
                }
                'Info'  { RLog "  -> informational; review manually." 'INFO'; $skipped++; $ok = $true }
                default { RLog "  -> no automated action for this finding." 'INFO'; $skipped++; $ok = $true }
            }
        } catch {
            RLog "  -> ERROR: $($_.Exception.Message)" 'CRITICAL'; $failed++
        }
        if ($ok -and ("$($f.FixAction)" -notin @('Info','None',''))) { $applied++ }
    }
} catch {
    RLog "[REMEDIATE] FATAL: $($_.Exception.Message)" 'CRITICAL'
} finally {
    $RemState.Remediating = $false
    REnqueue @{ type='remediation_complete'; applied=$applied; failed=$failed; skipped=$skipped; blocked=$blocked }
    RLog "[REMEDIATE] Complete — applied:$applied  failed:$failed  skipped:$skipped  blocked(protected):$blocked" 'OK'
}
'@

# ── HTTP Request Router ────────────────────────────────────────────────────────
function Handle-Request {
    param($Ctx)

    $req    = $Ctx.Request
    $path   = $req.Url.AbsolutePath
    $method = $req.HttpMethod

    # CORS preflight
    if ($method -eq 'OPTIONS') {
        $Ctx.Response.StatusCode = 204
        $Ctx.Response.Headers['Access-Control-Allow-Origin']  = '*'
        $Ctx.Response.Headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        $Ctx.Response.Headers['Access-Control-Allow-Headers'] = 'Content-Type'
        try { $Ctx.Response.Close() } catch {}
        return
    }

    switch -Regex ($path) {

        '^/$' {
            Send-StaticFile $Ctx (Join-Path $script:GUI_DIR 'templates\index.html')
        }

        '^/static/' {
            $rel = $path -replace '^/static/', ''
            $rel = $rel -replace '/', '\'
            Send-StaticFile $Ctx (Join-Path $script:GUI_DIR "static\$rel")
        }

        '^/api/sysinfo$' {
            Write-JsonResponse $Ctx (Get-SysInfoJson)
        }

        '^/api/state$' {
            $s = [ordered]@{
                running       = $script:State.Running
                phase         = $script:State.Phase
                phase_total   = $script:State.PhaseTotal
                phase_name    = $script:State.PhaseName
                elapsed       = $script:State.Elapsed
                threat_counts = $script:State.ThreatCounts
                scan_complete = $script:State.ScanComplete
            }
            Write-JsonResponse $Ctx ($s | ConvertTo-Json -Compress -Depth 3)
        }

        '^/api/findings$' {
            Write-JsonResponse $Ctx (@($script:State.Findings) | ConvertTo-Json -Depth 5)
        }

        '^/api/report$' {
            # Rich engine findings (with FixAction + MITRE) for the GUI; ?name=<file> or latest.
            $name = "$($req.QueryString['name'])"
            if (-not $name) { $name = $script:State.EngineReport }
            $name = [System.IO.Path]::GetFileName("$name")
            if ($name -notmatch '^(KrakenBaseline_|audit_).*\.json$') { Write-JsonResponse $Ctx '{"error":"invalid report name"}' 400; return }
            $p = Join-Path $script:REPORTS $name
            if (-not (Test-Path -LiteralPath $p)) { Write-JsonResponse $Ctx '{"error":"report not found"}' 404; return }
            Write-JsonResponse $Ctx (@(Get-EngineReportFindings $p) | ConvertTo-Json -Depth 5)
        }

        '^/api/remediate$' {
            if ($method -ne 'POST') { Write-JsonResponse $Ctx '{"error":"POST required"}' 405; return }
            if ($script:State.Running)     { Write-JsonResponse $Ctx '{"error":"scan in progress"}' 400; return }
            if ($script:State.Remediating) { Write-JsonResponse $Ctx '{"error":"remediation already running"}' 400; return }

            $parsed = (Read-RequestBody $Ctx) | ConvertFrom-Json -ErrorAction SilentlyContinue
            if (-not $parsed) { Write-JsonResponse $Ctx '{"error":"invalid JSON"}' 400; return }

            # Security: report must be a recognized file inside reports/ (basename only).
            $reportName = [System.IO.Path]::GetFileName("$($parsed.report)")
            if ($reportName -notmatch '^(KrakenBaseline_|audit_).*\.json$') { Write-JsonResponse $Ctx '{"error":"invalid report"}' 400; return }
            $reportPath = Join-Path $script:REPORTS $reportName
            if (-not (Test-Path -LiteralPath $reportPath)) { Write-JsonResponse $Ctx '{"error":"report not found"}' 404; return }

            $ids = @($parsed.ids) | Where-Object { $_ }
            if (-not $ids -or @($ids).Count -eq 0) { Write-JsonResponse $Ctx '{"error":"no findings selected"}' 400; return }

            Start-Runspace -Script $script:REMEDIATE_SCRIPT -Vars @{
                RemState   = $script:State
                RemReports = $script:REPORTS
                ReportPath = $reportPath
                FixIds     = @($ids)
            } | Out-Null
            Write-JsonResponse $Ctx '{"status":"started"}'
        }

        '^/api/export/html$' {
            $stamp = [datetime]::Now.ToString('yyyyMMdd_HHmmss')
            Write-DownloadResponse $Ctx (Get-HtmlReport) 'text/html; charset=utf-8' "zerobreach_report_$stamp.html"
        }

        '^/api/export/csv$' {
            $stamp = [datetime]::Now.ToString('yyyyMMdd_HHmmss')
            Write-DownloadResponse $Ctx (Get-CsvReport) 'text/csv; charset=utf-8' "zerobreach_findings_$stamp.csv"
        }

        '^/api/ioc$' {
            $iocJson = Join-Path $script:REPORTS 'custom_iocs.json'   # canonical, for the manager UI
            $iocText = Join-Path $script:REPORTS 'custom_iocs.ioc'    # engine -IocFile format (prefixed lines)
            $iocDefault = Join-Path $script:ROOT 'data\ioc_defaults.json'

            if ($method -eq 'POST') {
                $parsed = (Read-RequestBody $Ctx) | ConvertFrom-Json -ErrorAction SilentlyContinue
                if (-not $parsed) { Write-JsonResponse $Ctx '{"error":"invalid JSON"}' 400; return }
                $cats = @{
                    hashes  = @($parsed.hashes)  | Where-Object { $_ }
                    ips     = @($parsed.ips)     | Where-Object { $_ }
                    domains = @($parsed.domains) | Where-Object { $_ }
                    regex   = @($parsed.regex)   | Where-Object { $_ }
                    files   = @($parsed.files)   | Where-Object { $_ }
                }
                try {
                    # JSON sidecar (UI reload)
                    $out = [ordered]@{
                        hashes  = @($cats.hashes);  ips    = @($cats.ips); domains = @($cats.domains)
                        regex   = @($cats.regex);   files  = @($cats.files)
                        version = 'V23'; updated = [datetime]::Now.ToString('yyyy-MM-dd')
                    }
                    $u8 = New-Object System.Text.UTF8Encoding($false)
                    [System.IO.File]::WriteAllText($iocJson, ($out | ConvertTo-Json -Depth 4), $u8)

                    # Engine text format: prefixed so files/domains never collide on auto-detect.
                    $lines = [System.Collections.Generic.List[string]]::new()
                    $lines.Add('# ZeroBreach custom IOCs — generated by IOC Manager')
                    foreach ($h in $cats.hashes)  { $lines.Add("hash:$h") }
                    foreach ($i in $cats.ips)     { $lines.Add("ip:$i") }
                    foreach ($d in $cats.domains) { $lines.Add("domain:$d") }
                    foreach ($r in $cats.regex)   { $lines.Add("regex:$r") }
                    foreach ($f in $cats.files)   { $lines.Add("file:$f") }
                    [System.IO.File]::WriteAllText($iocText, ($lines -join "`r`n"), $u8)

                    $count = $cats.hashes.Count + $cats.ips.Count + $cats.domains.Count + $cats.regex.Count + $cats.files.Count
                    Write-JsonResponse $Ctx (@{ status='saved'; path=$iocText; json_path=$iocJson; count=$count } | ConvertTo-Json -Compress)
                } catch {
                    Write-JsonResponse $Ctx (@{ error="$($_.Exception.Message)" } | ConvertTo-Json -Compress) 500
                }
                return
            }

            # GET — return the saved set if present, else the shipped defaults.
            $src = if (Test-Path $iocJson) { $iocJson } else { $iocDefault }
            $activeText = if (Test-Path $iocText) { $iocText } else { '' }
            if (Test-Path $src) {
                try {
                    $obj = (Get-Content -LiteralPath $src -Raw) | ConvertFrom-Json
                    $obj | Add-Member -NotePropertyName '_path'   -NotePropertyValue $activeText -Force
                    $obj | Add-Member -NotePropertyName '_custom' -NotePropertyValue ([bool](Test-Path $iocJson)) -Force
                    Write-JsonResponse $Ctx ($obj | ConvertTo-Json -Depth 4)
                } catch {
                    Write-JsonResponse $Ctx (Get-Content -LiteralPath $src -Raw)
                }
            } else {
                Write-JsonResponse $Ctx '{"hashes":[],"ips":[],"domains":[],"regex":[],"files":[],"_path":"","_custom":false}'
            }
        }

        '^/api/scan/start$' {
            if ($method -ne 'POST') { Write-JsonResponse $Ctx '{"error":"POST required"}' 405; return }
            if ($script:State.Running) { Write-JsonResponse $Ctx '{"error":"scan already running"}' 400; return }

            $body   = Read-RequestBody $Ctx
            $parsed = $body | ConvertFrom-Json -ErrorAction SilentlyContinue
            $cfg    = @{}
            if ($parsed) {
                $parsed.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }
            }

            Start-Runspace -Script $script:SCAN_SCRIPT -Vars @{
                ScanState   = $script:State
                ScanConfig  = $cfg
                ScanPsPath  = $script:SCAN_PS
                ScanReports = $script:REPORTS
                MitreMap    = $script:MITRE_MAP
            } | Out-Null

            Write-JsonResponse $Ctx '{"status":"started"}'
        }

        '^/api/scan/abort$' {
            $script:State.Running = $false
            $p = $script:State.Process
            if ($p -and -not $p.HasExited) { try { $p.Kill() } catch {} }
            Write-JsonResponse $Ctx '{"status":"aborted"}'
        }

        '^/api/events$' {
            # SSE — hand off to a background runspace; do NOT close response
            Start-Runspace -Script $script:SSE_SCRIPT -Vars @{
                SseCtx   = $Ctx
                SseState = $script:State
            } | Out-Null
        }

        '^/favicon\.ico$' {
            $Ctx.Response.StatusCode = 204
            try { $Ctx.Response.Close() } catch {}
        }

        default {
            Write-JsonResponse $Ctx '{"error":"not found"}' 404
        }
    }
}

# ── Main ───────────────────────────────────────────────────────────────────────
if ($Port -eq 0) { $Port = Get-FreePort }

$Listener = [System.Net.HttpListener]::new()
$Listener.Prefixes.Add("http://localhost:$Port/")

try { $Listener.Start() }
catch [System.Net.HttpListenerException] {
    # Locked-down machine: the URL namespace may need an explicit reservation.
    Write-Host ('[ZeroBreach] Listener blocked (' + $_.Exception.Message + '); adding URL ACL...') -ForegroundColor Yellow
    $acl = "http://localhost:$Port/"
    & netsh http add urlacl url=$acl "user=$env:USERDOMAIN\$env:USERNAME" | Out-Null
    try { $Listener.Start() }
    catch {
        Write-Host ('[ZeroBreach] Failed to start listener after URL ACL: ' + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host ('[ZeroBreach] Failed to start listener: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}

$Url = "http://localhost:$Port"

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║    ZEROBREACH V23 — KRAKEN CONSOLE               ║" -ForegroundColor Cyan
Write-Host "  ║    HTTP Server: $($Url.PadRight(34))║" -ForegroundColor Cyan
Write-Host "  ║    Press Ctrl+C to stop                          ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host ('[ZeroBreach] Serving GUI at ' + $Url) -ForegroundColor Green
Write-Host ('[ZeroBreach] Scan engine: ' + $script:SCAN_PS) -ForegroundColor DarkCyan

if (-not $NoBrowser) {
    $urlCapture = $Url
    # Don't open the browser on a fixed timer — poll until the server actually answers
    # a request, THEN launch. This both (a) guarantees the first browser paint never
    # races the listener and (b) pre-warms the static-file path, fixing the occasional
    # blank/grey screen seen right after the UAC launch. The accept loop (below, on the
    # main thread) serves these probe requests.
    $null = Start-Job -ArgumentList $urlCapture {
        param($u)
        for ($i = 0; $i -lt 50; $i++) {
            try {
                $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 2
                if ($r.StatusCode -eq 200) { break }
            } catch { Start-Sleep -Milliseconds 150 }
        }
        Start-Process $u
    }
}

# ── Accept loop ────────────────────────────────────────────────────────────────
try {
    while ($script:State.Listening) {
        try {
            $ctx = $Listener.GetContext()
            Handle-Request $ctx
        }
        catch [System.Net.HttpListenerException] {
            if ($script:State.Listening) {
                Write-Host ('[ZeroBreach] Listener error: ' + $_.Exception.Message) -ForegroundColor Red
            }
            break
        }
        catch {
            $errPath = if ($null -ne $ctx) { $ctx.Request.Url.AbsolutePath } else { 'unknown' }
            Write-Host ('[ZeroBreach] Request error on ' + $errPath + ': ' + $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}
finally {
    $script:State.Listening = $false
    try { $Listener.Stop(); $Listener.Close() } catch {}
    Write-Host '[ZeroBreach] Server stopped.' -ForegroundColor Cyan
    if ($script:EVENT_LOG)   { Write-Host ('[ZeroBreach] Event log:   ' + $script:EVENT_LOG)   -ForegroundColor DarkCyan }
    if ($script:CONSOLE_LOG) { Write-Host ('[ZeroBreach] Console log: ' + $script:CONSOLE_LOG) -ForegroundColor DarkCyan }
    try { Stop-Transcript | Out-Null } catch {}
}
