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
    ScanFailed   = $false   # engine died (non-zero exit / no phase output) — NOT a clean result
    FailReason   = ''
    ExitCode     = $null
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
    Listening    = $true
    EventLogFile = $script:EVENT_LOG   # durable tee of the SSE event stream (set above); read by Enqueue/REnqueue
    ScanEpoch    = 0      # bumped each time EventLog is cleared for a new scan; SSE clients rewind on change
    Process      = $null
    EngineReport = ''     # filename of the engine's rich KrakenBaseline_*.json from the last scan
    Remediating  = $false
    EventLog     = [System.Collections.ArrayList]::Synchronized(
                       [System.Collections.ArrayList]::new())
    # audit M2: EventLog is a BOUNDED ring. It used to grow for the whole 115-phase
    # scan and every new SSE client replayed it from index 0, so a few browser
    # refreshes during a DEEP run meant re-serialising tens of thousands of lines
    # each time. EventLogBase = how many entries have been trimmed off the front,
    # so an SSE cursor stays an ABSOLUTE event index across trims. Nothing is lost
    # for forensics: every event is also teed to $script:EVENT_LOG on disk.
    EventLogBase = 0
    EventLogMax  = 6000   # trim once the list exceeds this
    EventLogKeep = 4000   # ...back down to this
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

# ── Request authentication (audit C1) ──────────────────────────────────────────
# This API deletes files, kills processes and runs commands AS ADMIN. Before this
# guard it had no authentication at all and answered every caller with
# `Access-Control-Allow-Origin: *`, so any web page the operator happened to have
# open could sweep loopback for the /api/sysinfo oracle and then POST /api/remediate.
# Two independent barriers now stand in that path:
#   1. a per-launch random token, required on every /api/* request; and
#   2. an Origin check on every route — browsers attach Origin to cross-site
#      requests, and any value other than this server's own is refused outright.
# The token rides in the query string (?t=) because EventSource cannot set headers;
# an X-ZB-Token header is honoured too, for callers that can send one.
# Crypto RNG, not Get-Random: Get-Random is a seeded System.Random, and a token an
# attacker can predict is the same as no token at all. 32 bytes -> 64 hex chars.
$script:AUTH_TOKEN = $(
    $rngBytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    try   { $rng.GetBytes($rngBytes) }
    finally { $rng.Dispose() }
    -join ($rngBytes | ForEach-Object { $_.ToString('x2') })
)

# Populated in Main once the port is known. Only the exact origin this server is
# reachable at is ever allowed — 'localhost' is deliberately NOT in the list, because
# the listener is bound to 127.0.0.1 and http.sys rejects any other Host outright.
$script:ALLOWED_ORIGINS = @()

# Sent on every response. The CSP is what keeps a compromised box from feeding this
# admin-privileged page third-party JavaScript (audit C3) — every asset is local now,
# so 'self' is the whole allowlist. 'unsafe-inline' stays because index.html carries
# the inline boot watchdog and themes.js sets theme vars as an inline body style.
$script:SECURITY_HEADERS = [ordered]@{
    'X-Content-Type-Options' = 'nosniff'
    'Referrer-Policy'        = 'no-referrer'
    'X-Frame-Options'        = 'DENY'
    'Content-Security-Policy' = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
}

function Add-SecurityHeaders {
    param($Response)
    try {
        foreach ($h in $script:SECURITY_HEADERS.Keys) {
            $Response.Headers[$h] = $script:SECURITY_HEADERS[$h]
        }
    } catch {}
}

function Test-RequestAuth {
    param($Ctx)
    $tok = $Ctx.Request.QueryString['t']
    if ([string]::IsNullOrEmpty($tok)) { $tok = $Ctx.Request.Headers['X-ZB-Token'] }
    if ([string]::IsNullOrEmpty($tok)) { return $false }
    # Ordinal compare — never culture-fold a secret.
    return [string]::Equals([string]$tok, $script:AUTH_TOKEN, [System.StringComparison]::Ordinal)
}

function Test-RequestOrigin {
    param($Ctx)
    # Same-origin GETs carry no Origin header at all; browsers do attach it to every
    # cross-site request and to same-origin POSTs. Absent = allow, foreign = refuse.
    $origin = $Ctx.Request.Headers['Origin']
    if ([string]::IsNullOrEmpty($origin)) { return $true }
    return ($script:ALLOWED_ORIGINS -contains $origin)
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
        Add-SecurityHeaders $r
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
        Add-SecurityHeaders $r
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
        Add-SecurityHeaders $r
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

# CSV cell hardening. Quoting alone does NOT stop formula injection: Excel/LibreOffice/Sheets
# strip the quotes and then evaluate a cell whose first character is = + - @ (or a leading tab/CR,
# which some parsers skip before applying the same rule). Finding text is malware-controlled —
# file names, task names, registry values — and the product's workflow is to export findings and
# send them to a client, so the payload detonates on a DIFFERENT machine than the one scanned.
# Prefixing with an apostrophe forces text interpretation; the apostrophe is not shown as data.
function ConvertTo-CsvSafeCell {
    param([string]$Value)
    $v = "$Value"
    if ($v -match '^[=+\-@\t\r\n]') { $v = "'" + $v }
    return '"' + ($v -replace '"','""') + '"'
}

function Get-CsvReport {
    $findings = @($script:State.Findings)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('"Severity","Phase","ThreatType","ATTACK_ID","ATTACK_Name","Detail","Timestamp"')
    foreach ($f in $findings) {
        $mid = if ($f.mitre -and $f.mitre.id) { "$($f.mitre.id)" } else { '' }
        $mnm = if ($f.mitre -and $f.mitre.name) { "$($f.mitre.name)" } else { '' }
        $cells = @("$($f.severity)", "PH$($f.phase)", "$($f.threat_type)", $mid, $mnm, "$($f.line)", "$($f.timestamp)")
        $line = ($cells | ForEach-Object { ConvertTo-CsvSafeCell $_ }) -join ','
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
# ── Guard input normalisation (audit H7) ───────────────────────────────────────
# Test-ProtectedTarget used to regex the RAW FixParam string, so a path that merely
# LOOKED different slipped past. Testing proved the unanchored (System32|SysWOW64|
# WinSxS) clause already caught 8.3 short names, UNC admin shares, \\?\, GLOBALROOT,
# %SystemRoot%, .. traversal and trailing spaces — but NOT forward slashes:
# "C:/Windows/System32/evil.exe" and "C:/Users/bob/.ssh/id_rsa" were both ALLOWED.
# Everything the guard tests now goes through here first.
function ConvertTo-GuardPath {
    param([string]$Path)
    $q = "$Path"
    if ([string]::IsNullOrWhiteSpace($q)) { return '' }
    $q = $q.Trim()
    $q = $q -replace '/', '\'                                  # the confirmed bypass
    try { $q = [Environment]::ExpandEnvironmentVariables($q) } catch {}
    $q = $q -replace '(?i)^\\\\\?\\GLOBALROOT\\', '\'          # \\?\GLOBALROOT\Device\...
    $q = $q -replace '(?i)^\\\\\?\\UNC\\', '\\'                # \\?\UNC\host\share
    $q = $q -replace '(?i)^\\\\\?\\', ''                       # \\?\C:\...
    # Canonicalise real filesystem paths (resolves .., trailing dots/spaces, doubled
    # separators). Only single-letter drive paths — never PS drives like HKLM:\ or Cert:\.
    if ($q -match '^[a-zA-Z]:\\') {
        try { $q = [System.IO.Path]::GetFullPath($q) } catch {}
    }
    return $q
}

# ── Destructive RunCmd content inspection (audit H7b) ──────────────────────────
# RunCmd is the single most dangerous action (executed via [scriptblock]::Create),
# and the guard never looked at the command STRING at all — only at path-shaped
# params. Every one of `vssadmin delete shadows /all`, `cipher /w:C`, `wbadmin delete
# catalog`, `bcdedit /set safeboot minimal`, `Stop-Service WinDefend` and
# `net user administrator <pw>` passed untouched.
#
# These patterns are deliberately DIRECTION-AWARE. The engine legitimately emits
# `netsh advfirewall reset`, `Set-MpPreference -DisableRealtimeMonitoring $false`,
# `bcdedit /set {default} recoveryenabled Yes` and `Stop-Service WinRM` as real
# remediations — blocking those would break the product. Only the sabotage direction
# is matched. Anything added here must be checked against the engine's own RunCmd
# inventory first.
$script:RUNCMD_DESTRUCTIVE = @(
    @{ rx = '(?i)vssadmin[^\n]*\bdelete\b[^\n]*\bshadow';               why = 'deletes volume shadow copies (destroys rollback + ransomware recovery)' }
    @{ rx = '(?i)(wmic[^\n]*shadowcopy[^\n]*delete|Win32_ShadowCopy[^\n]*(Delete|Remove))'; why = 'deletes volume shadow copies via WMI' }
    @{ rx = '(?i)\bwbadmin\b[^\n]*\bdelete\b';                          why = 'deletes the Windows backup catalog' }
    @{ rx = '(?i)\bbcdedit\b[^\n]*\bsafeboot\b';                        why = 'alters Safe Mode boot configuration' }
    @{ rx = '(?i)\bbcdedit\b[^\n]*recoveryenabled[^\n]*\bno\b';         why = 'disables Windows recovery' }
    @{ rx = '(?i)\bbcdedit\b[^\n]*bootstatuspolicy[^\n]*ignoreallfailures'; why = 'suppresses boot failure recovery' }
    @{ rx = '(?i)Set-MpPreference[^\n]*-Disable\w*[^\n]*\$?true';       why = 'disables Microsoft Defender protection' }
    @{ rx = '(?i)Add-MpPreference[^\n]*-Exclusion';                     why = 'adds a Defender exclusion (evasion, not remediation)' }
    @{ rx = '(?i)(Stop-Service|sc(\.exe)?\s+(stop|delete)|net\s+stop)[^\n]*\b(WinDefend|Sense|WdNisSvc|SecurityHealthService)\b'; why = 'stops or deletes a Defender service' }
    @{ rx = '(?i)\bcipher\b[^\n]*\/w';                                  why = 'securely wipes free space (anti-forensic, irreversible)' }
    @{ rx = '(?i)\b(format|diskpart)\b[^\n]*(\/(fs|q|y)\b|clean)';      why = 'formats or wipes a disk' }
    @{ rx = '(?i)(wevtutil[^\n]*\bcl\b|Clear-EventLog|Remove-EventLog)'; why = 'clears Windows event logs (anti-forensic)' }
    @{ rx = '(?i)(net\s+user\s+\S+\s+\S+|New-LocalUser|net\s+localgroup[^\n]*administrators[^\n]*\/add|Add-LocalGroupMember[^\n]*Administrators)'; why = 'creates or alters a local account / grants admin' }
    @{ rx = '(?i)netsh[^\n]*advfirewall[^\n]*\bstate\s+off';            why = 'turns the Windows firewall off' }
    @{ rx = '(?i)Set-NetFirewallProfile[^\n]*-Enabled\s+\$?false';      why = 'turns the Windows firewall off' }
    @{ rx = '(?i)\bicacls\b[^\n]*\/reset[^\n]*\/t';                     why = 'recursively resets ACLs (CLAUDE.md forbids this outright)' }
    @{ rx = '(?i)\btakeown\b[^\n]*\/f[^\n]*\/r';                        why = 'recursively takes ownership of a tree' }
    @{ rx = '(?i)reg(\.exe)?\s+delete[^\n]*HK(LM|EY_LOCAL_MACHINE)\\(SOFTWARE|SYSTEM)\s*(\/f)?\s*$'; why = 'deletes an entire registry hive' }
    @{ rx = '(?i)EnableLUA[^\n]*(-Value\s*0|\s0\s*$)';                  why = 'disables UAC' }
    @{ rx = '(?i)(Remove-Item|rd|rmdir|del)\b[^\n]*\b[a-z]:\\(\s|$|["'']|\\\*)'; why = 'recursive delete at a drive root' }
    @{ rx = '(?i)(Remove-Item|rd|rmdir|del)\b[^\n]*[a-z]:\\Windows\\?\s*["'']?\s*(-recurse|\/s)'; why = 'recursive delete of the Windows directory' }
)

# A RunCmd FixParam is a COMMAND, and the path rules in the protected-target guard
# match a path MENTIONED anywhere in a string. Those two facts together blocked the
# engine's own repairs: restoring a hijacked Winlogon Userinit writes the value
# 'C:\Windows\system32\userinit.exe,', so the guard saw "\system32\", called it a
# Windows-system-directory write, and refused — every time, on every box (audit M1,
# same class as STICKY_*). The path rules are therefore applied to a RunCmd only when
# the command carries a verb that can actually mutate what it names. Everything in
# $RUNCMD_DESTRUCTIVE above still applies unconditionally.
$script:RUNCMD_MUTATING = '(?i)(Remove-Item|Remove-ItemProperty|Rename-Item|Move-Item|Set-Content|Add-Content|Clear-Content|Out-File|New-Item|Copy-Item|Set-Acl|Invoke-Expression|\biex\b|Start-Process|\bicacls\b|\btakeown\b|\battrib\b|\bcacls\b|\b(del|erase|rd|rmdir|move|ren|rename|copy|xcopy|robocopy)\s|\breg(\.exe)?\s+(delete|add)\b|\bcmd(\.exe)?\b|\bpowershell(\.exe)?\b|\bpwsh(\.exe)?\b|>)'

function Test-DestructiveRunCmd {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return '' }
    foreach ($r in $script:RUNCMD_DESTRUCTIVE) {
        if ($Cmd -match $r.rx) { return $r.why }
    }
    return ''
}

# KillProcess guard lists. The name form is matched against the FixParam's name field
# (whole-string, optional .exe); the description form is the bare-PID fallback.
$script:KILL_CRITICAL_NAME_RX = '(?i)^(System|smss|csrss|wininit|winlogon|services|lsass|svchost|dwm|fontdrvhost|explorer|powershell|pwsh|conhost|RuntimeBroker|MsMpEng)(\.exe)?$|(?i)(claude|zerobreach)'
$script:KILL_CRITICAL_DESC_RX = '(?i)(\b(System|smss|csrss|wininit|winlogon|services|lsass|svchost|dwm|fontdrvhost|explorer|powershell|pwsh|conhost|RuntimeBroker|MsMpEng)\b|claude|zerobreach)'

function Test-ProtectedTarget {
    param([string]$Action, [string]$Param, [string]$Target, [string]$Desc)
    # Normalise BEFORE any pattern test (audit H7).
    $p = ConvertTo-GuardPath "$Param"; $t = "$Target"; $d = "$Desc"
    $hay = "$p`n$t`n$d"

    # RunCmd carries a command, not a path — inspect the command itself (audit H7b).
    if ($Action -eq 'RunCmd') {
        $bad = Test-DestructiveRunCmd "$Param"
        if ($bad) { return "destructive command — $bad" }
        # A command that only NAMES a protected path (e.g. writing the correct
        # userinit.exe value back into Winlogon) is not a write to it — see the
        # $script:RUNCMD_MUTATING comment. No mutating verb, no path check.
        if ("$Param" -notmatch $script:RUNCMD_MUTATING) { return '' }
    }

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
    # Core OS registry hives. One exception (audit M1): a Debugger or GlobalFlag
    # VALUE under Image File Execution Options *is* the sticky-keys/IFEO backdoor,
    # and deleting that value restores stock behaviour — it is the fix, not damage.
    # The KEY itself stays protected (DeleteRegKey), as does every other value.
    if ($Action -match '(?i)DeleteReg' -and $p -match '(?i)\\(SYSTEM\\CurrentControlSet\\(Services|Control)|Microsoft\\Windows NT\\CurrentVersion\\(Winlogon|Image File Execution Options|SystemRestore)|Cryptography)') {
        $ifeoValueFix = ($Action -eq 'DeleteReg' -and
                         $p -match '(?i)\\Image File Execution Options\\' -and
                         $p -match '(?i)\|\s*(Debugger|GlobalFlag)\s*$')
        if (-not $ifeoValueFix) { return 'core OS registry' }
    }
    # Critical processes / the IR tool itself (KillProcess). Since H5 the FixParam is
    # "pid|name|startTicks" (Get-KillParam), so the authoritative process NAME is right
    # there — use it, and fall back to the description only for a bare-PID (older)
    # report. Matching the prose was blocking real kills: "SYSTEM-level process running
    # from user path: evil.exe" is a finding ABOUT malware, not about the System
    # process, and it was refused every time (audit M1).
    if ($Action -eq 'KillProcess') {
        $kpName = ''
        $kpParts = "$Param" -split '\|'
        if ($kpParts.Count -ge 2) { $kpName = "$($kpParts[1])".Trim() }
        if ($kpName) {
            if ($kpName -match $script:KILL_CRITICAL_NAME_RX) { return 'critical system process or the IR tool itself' }
        } elseif ($d -match $script:KILL_CRITICAL_DESC_RX) {
            return 'critical system process or the IR tool itself'
        }
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

# ── IOC ingestion validation (audit M6) ────────────────────────────────────────
# POST /api/ioc used to write caller strings straight into custom_iocs.ioc as
# "<prefix>:<value>" lines. Two holes: (1) a value containing CR/LF injected extra
# IOC lines, and the engine's Import-CustomIocs treats any unprefixed line it can't
# classify as a REGEX — so a "domain" could smuggle in a pattern; (2) regex entries
# were never compiled or bounded, so a catastrophic-backtracking pattern hung the
# NEXT scan from inside the engine. Everything is validated per category here, and
# whatever is rejected is reported back to the operator rather than silently dropped.
$script:MAX_BODY_BYTES  = 4MB
$script:IOC_MAX_PER_CAT = 2000
$script:IOC_MAX_LEN     = 512
$script:IOC_MAX_REGEX   = 200

function Test-IocRegexSafe {
    # Returns '' when the pattern is safe, else the reason it was refused.
    param([string]$Pattern)
    $rx = $null
    try {
        $rx = New-Object System.Text.RegularExpressions.Regex(
                  $Pattern,
                  [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
                  [timespan]::FromMilliseconds(150))
    } catch { return 'not a valid regular expression' }
    # Bait strings shaped to detonate nested quantifiers. The match timeout is what
    # actually catches it — a pattern that can't finish 150 ms against these will
    # not finish against a real filesystem walk either.
    $bait = @(
        ('a' * 96) + '!'
        ('ab' * 48) + '!'
        'C:\Users\operator\AppData\Local\Temp\' + ('x' * 64) + '.exe'
        ('0123456789' * 12) + ' '
    )
    foreach ($b in $bait) {
        try { [void]$rx.IsMatch($b) }
        catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
            return 'too slow (catastrophic backtracking) — it would hang the next scan'
        }
        catch { return 'failed to evaluate' }
    }
    return ''
}

function Test-IocIpValue {
    param([string]$V)
    $addr = $V; $bits = $null
    if ($V.Contains('/')) {
        $parts = $V -split '/', 2
        $addr = $parts[0]; $bits = $parts[1]
    }
    $ip = [System.Net.IPAddress]::Any
    if (-not [System.Net.IPAddress]::TryParse($addr, [ref]$ip)) { return $false }
    if ($null -ne $bits) {
        $n = 0
        if (-not [int]::TryParse($bits, [ref]$n)) { return $false }
        $max = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { 128 } else { 32 }
        if ($n -lt 0 -or $n -gt $max) { return $false }
    }
    return $true
}

function ConvertTo-IocSet {
    # Validate + normalise a posted IOC set. Returns @{ Set = <ordered categories>;
    # Rejected = <list of "value — reason"> }.
    param($Parsed)
    $rejected = [System.Collections.Generic.List[string]]::new()
    $set = [ordered]@{
        hashes = [System.Collections.Generic.List[string]]::new()
        ips     = [System.Collections.Generic.List[string]]::new()
        domains = [System.Collections.Generic.List[string]]::new()
        regex   = [System.Collections.Generic.List[string]]::new()
        files   = [System.Collections.Generic.List[string]]::new()
    }
    foreach ($cat in @('hashes','ips','domains','regex','files')) {
        $seen = @{}
        foreach ($raw in @($Parsed.$cat)) {
            if ($null -eq $raw) { continue }
            $v = "$raw"
            if ($set[$cat].Count -ge $script:IOC_MAX_PER_CAT) {
                $rejected.Add("$cat — more than $script:IOC_MAX_PER_CAT entries; the rest were dropped")
                break
            }
            # Line breaks and control characters are the injection vector — refuse the
            # whole value rather than stripping, so nothing is silently rewritten.
            if ($v -match '[\x00-\x1F\x7F]') { $rejected.Add("$($v -replace '[\x00-\x1F\x7F]','?') — contains a line break or control character"); continue }
            $v = $v.Trim()
            if (-not $v) { continue }
            $cap = if ($cat -eq 'regex') { $script:IOC_MAX_REGEX } else { $script:IOC_MAX_LEN }
            if ($v.Length -gt $cap) { $rejected.Add("$($v.Substring(0,40))… — longer than $cap characters"); continue }

            $why = ''
            switch ($cat) {
                'hashes'  { if ($v -notmatch '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$') { $why = 'not an MD5/SHA1/SHA256 hash' } else { $v = $v.ToLower() } }
                'ips'     { if (-not (Test-IocIpValue $v)) { $why = 'not an IP address or CIDR range' } }
                'domains' { if ($v -notmatch '^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,63}$') { $why = 'not a domain name' } else { $v = $v.ToLower() } }
                'regex'   { $why = Test-IocRegexSafe $v }
                'files'   { if ($v.Length -gt 260) { $why = 'longer than a Windows path' } }
            }
            if ($why) { $rejected.Add("$v — $why"); continue }
            $key = $v.ToLower()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $set[$cat].Add($v)
        }
    }
    return @{ Set = $set; Rejected = $rejected }
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
        } | ConvertTo-Json -Compress
    } catch {
        return '{"error":"sysinfo unavailable"}'
    }
}

# ── Background runspace launcher ────────────────────────────────────────────────
# audit M2: every /api/events connection starts a runspace, so a browser refresh used
# to leak one permanently — nothing was ever disposed. Handles are tracked here and
# reaped once their script has returned (the SSE loop ends when the client's socket
# dies, at the latest on the 20 s keep-alive write).
$script:RUNSPACES = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())

function Clear-FinishedRunspaces {
    foreach ($e in @($script:RUNSPACES)) {
        if (-not $e.Handle.IsCompleted) { continue }
        try { [void]$e.PS.EndInvoke($e.Handle) } catch {}
        try { $e.PS.Runspace.Dispose() } catch {}
        try { $e.PS.Dispose() } catch {}
        try { $script:RUNSPACES.Remove($e) } catch {}
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
    [void]$script:RUNSPACES.Add(@{ PS = $ps; Handle = $handle })
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
$response.Headers['X-Content-Type-Options'] = 'nosniff'
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
    scan_failed   = $SseState.ScanFailed
    fail_reason   = $SseState.FailReason
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

        # audit M2: $idx is an ABSOLUTE event index and the log is a bounded ring, so
        # translate through EventLogBase. Snapshot the pending slice under the list's
        # lock, then write to the socket OUTSIDE it — a slow client must never stall
        # the scan runspace's Enqueue.
        $batch   = [System.Collections.Generic.List[string]]::new()
        $dropped = 0
        $sync    = $SseState.EventLog.SyncRoot
        [System.Threading.Monitor]::Enter($sync)
        try {
            $base  = [int]$SseState.EventLogBase
            $count = $base + $SseState.EventLog.Count
            if ($idx -gt $count) { $idx = 0 }   # extra safety: cursor past end (shouldn't happen)
            if ($idx -lt $base)  { $dropped = $base - $idx; $idx = $base }
            while ($idx -lt $count) {
                $batch.Add([string]$SseState.EventLog[$idx - $base])
                $idx++
            }
        } finally { [System.Threading.Monitor]::Exit($sync) }

        if ($dropped -gt 0) {
            Push (@{ type='log_line'; severity='INFO'; phase=0; elapsed=$SseState.Elapsed
                     text="[LOG] $dropped earlier line(s) trimmed from the live buffer — the full log is on disk." } |
                  ConvertTo-Json -Compress)
        }
        foreach ($b in $batch) { Push $b }
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
    # audit M2: add + trim as one atomic step, under the SAME SyncRoot the SSE
    # reader takes, so a client can never index into a list that is mid-trim.
    $sync = $ScanState.EventLog.SyncRoot
    [System.Threading.Monitor]::Enter($sync)
    try {
        [void]$ScanState.EventLog.Add($json)
        if ($ScanState.EventLog.Count -gt $ScanState.EventLogMax) {
            $drop = $ScanState.EventLog.Count - $ScanState.EventLogKeep
            $ScanState.EventLog.RemoveRange(0, $drop)
            $ScanState.EventLogBase += $drop
        }
    } finally { [System.Threading.Monitor]::Exit($sync) }
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
# SECURITY (C1): $mode is interpolated UNQUOTED into the child argument string below, so it
# MUST be constrained to the exact engine mode enum. Without this, a caller (e.g. a CSRF POST
# from any page the operator visits — the listener has wildcard CORS) could smuggle extra engine
# parameters like "-Schedule DAILY -SmtpTo attacker@evil" → a SYSTEM scheduled task that emails
# the incident report out. Anything not on the allowlist falls back to FULL.
$mode     = if ($ScanConfig.mode) { ("$($ScanConfig.mode)").Trim().ToUpper() } else { 'FULL' }
if ($mode -notin @('QUICK','FULL','DEEP','PARANOID','STEALTH')) { $mode = 'FULL' }
$hours    = if ($null -ne $ScanConfig.hours) { [int]$ScanConfig.hours } else { 0 }
$doHtml   = [bool]$ScanConfig.html_report
$paranoid = [bool]$ScanConfig.paranoid
$stealth  = [bool]$ScanConfig.stealth
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
$ScanState.ScanFailed   = $false
$ScanState.FailReason   = ''
$ScanState.ExitCode     = $null
$ScanState.StartTime    = [datetime]::Now
$ScanState.Findings.Clear()
$ScanState.EventLog.Clear()
$ScanState.EventLogBase = 0   # cursors are absolute indices; clearing resets the origin
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
# Engine-exit verdict, set after WaitForExit and consumed in the finally (audit H2).
$engineFailed = $false
$failReason   = ''
$engineStderr = ''
$engineExit   = $null
try {
    $proc = [System.Diagnostics.Process]::Start($psi)
    $ScanState.Process = $proc

    # Drain stderr asynchronously so its buffer never fills and deadlocks the child.
    # BeginErrorReadLine() with no ErrorDataReceived handler drained it straight to
    # /dev/null, which is how an engine that died at load looked identical to a clean
    # machine (audit H2). ReadToEndAsync hands the draining to .NET — deadlock-free,
    # no PowerShell event pump needed inside this runspace — and keeps the text.
    $stderrTask = $proc.StandardError.ReadToEndAsync()

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
            if ($newPhase -ne $ScanState.Phase) {
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

    # ── Engine exit verdict (audit H2) ────────────────────────────────────────────
    # A false all-clear is the worst failure an IR tool can produce, so anything
    # other than a clean exit is reported as a FAILED scan, never as a finished one.
    # An operator abort is not a failure: $ScanState.Running is already $false there.
    $wasAborted = -not $ScanState.Running
    $engineExit = -1
    try { $engineExit = $proc.ExitCode } catch {}
    $ScanState.ExitCode = $engineExit
    try { $engineStderr = $stderrTask.Result } catch { $engineStderr = '' }

    if (-not $wasAborted) {
        if ($engineExit -ne 0) {
            $engineFailed = $true
            $failReason   = "scan engine exited with code $engineExit"
        }
        elseif ($ScanState.PhaseIdx -le 0) {
            # Exit 0 but not a single PHASE header parsed: the engine never really ran
            # (AMSI blocking the script at load is the documented case). Nothing was
            # scanned, so there is nothing to call clean.
            $engineFailed = $true
            $failReason   = 'scan engine produced no phase output — nothing was actually scanned'
        }
    }

    if ($engineStderr) {
        # stderr is the single most useful artifact when a field scan goes wrong; it
        # now reaches both the GUI log and the durable server event log.
        foreach ($eline in ($engineStderr -split "`r?`n")) {
            if ($eline.Trim()) {
                Enqueue @{
                    type     = 'log_line'
                    text     = "[ENGINE STDERR] $eline"
                    severity = $(if ($engineFailed) { 'CRITICAL' } else { 'HIGH' })
                    phase    = $ScanState.Phase
                    elapsed  = $ScanState.Elapsed
                }
            }
        }
    }

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
                    # audit M4: canonicalise the threat bucket exactly like the live
                    # [FINDING] path. The engine's ThreatType is free text; this block
                    # used to pass it through raw and skip the tally entirely when it
                    # was empty, so STEALTH threat counters undercounted findings_count.
                    $ttRaw = "$($ef.ThreatType)"
                    $tt = $null
                    foreach ($k in $TKW.Keys) { if ($ttRaw -match "^$k") { $tt = $k; break } }
                    if (-not $tt) { $tt = (Classify ("$ttRaw $($ef.Description)")).tt }
                    if (-not $tt) { $tt = 'Other' }
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
                            # audit M4: carry the same fix_action/target the live path
                            # sets, or the GUI falls back to inferAction()'s text guess
                            # and the remediation view loses the engine's real verdict.
                            fix_action  = "$($ef.FixAction)"
                            target      = "$($ef.Target)"
                            timestamp   = [datetime]::Now.ToString('HH:mm:ss')
                        }
                        [void]$ScanState.Findings.Add($f)
                        if ($ScanState.ThreatCounts.ContainsKey($tt)) { $ScanState.ThreatCounts[$tt]++ }
                        else { $ScanState.ThreatCounts['Other']++ }
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
    # The engine never got to run (couldn't spawn, stream died mid-read...). That is a
    # failed scan, not an empty one (audit H2).
    $engineFailed = $true
    $failReason   = "scan aborted by server error: $($_.Exception.Message)"
} finally {
    $ScanState.Running    = $false
    $ScanState.ScanComplete = $true
    $ScanState.ScanFailed = $engineFailed
    $ScanState.FailReason = $failReason

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

    # Completion event. A failed engine emits scan_failed and NEVER scan_complete —
    # the GUI's clean-bill-of-health banner hangs off scan_complete, and a scan that
    # did not run must never reach it (audit H2).
    if ($engineFailed) {
        Enqueue @{
            type           = 'scan_failed'
            reason         = $failReason
            exit_code      = $engineExit
            stderr         = $engineStderr
            findings_count = $ScanState.Findings.Count
            threat_counts  = $ScanState.ThreatCounts
            elapsed        = $ScanState.Elapsed
            phase          = $ScanState.Phase
            results_path   = $ScanState.ResultsPath
            engine_report  = $engineReport
        }
        Enqueue @{
            type     = 'log_line'
            text     = "[SCAN FAILED] $failReason — results are INCOMPLETE and must not be read as a clean result."
            severity = 'CRITICAL'
            phase    = $ScanState.Phase
            elapsed  = $ScanState.Elapsed
        }
    } else {
        Enqueue @{
            type           = 'scan_complete'
            findings_count = $ScanState.Findings.Count
            threat_counts  = $ScanState.ThreatCounts
            elapsed        = $ScanState.Elapsed
            results_path   = $ScanState.ResultsPath
            engine_report  = $engineReport
        }
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
    # audit M2 — mirror of Enqueue's bounded ring (see the main-thread state block).
    $sync = $RemState.EventLog.SyncRoot
    [System.Threading.Monitor]::Enter($sync)
    try {
        [void]$RemState.EventLog.Add($json)
        if ($RemState.EventLog.Count -gt $RemState.EventLogMax) {
            $drop = $RemState.EventLog.Count - $RemState.EventLogKeep
            $RemState.EventLog.RemoveRange(0, $drop)
            $RemState.EventLogBase += $drop
        }
    } finally { [System.Threading.Monitor]::Exit($sync) }
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
# Mirrors ConvertTo-GuardPath / Test-DestructiveRunCmd / Test-ProtectedTarget from the
# main thread. CLAUDE.md requires these stay in sync — change one, change the other.
function ConvertTo-RGuardPath {
    param([string]$Path)
    $q = "$Path"
    if ([string]::IsNullOrWhiteSpace($q)) { return '' }
    $q = $q.Trim()
    $q = $q -replace '/', '\'
    try { $q = [Environment]::ExpandEnvironmentVariables($q) } catch {}
    $q = $q -replace '(?i)^\\\\\?\\GLOBALROOT\\', '\'
    $q = $q -replace '(?i)^\\\\\?\\UNC\\', '\\'
    $q = $q -replace '(?i)^\\\\\?\\', ''
    if ($q -match '^[a-zA-Z]:\\') {
        try { $q = [System.IO.Path]::GetFullPath($q) } catch {}
    }
    return $q
}

$RUNCMD_DESTRUCTIVE_R = @(
    @{ rx = '(?i)vssadmin[^\n]*\bdelete\b[^\n]*\bshadow';               why = 'deletes volume shadow copies (destroys rollback + ransomware recovery)' }
    @{ rx = '(?i)(wmic[^\n]*shadowcopy[^\n]*delete|Win32_ShadowCopy[^\n]*(Delete|Remove))'; why = 'deletes volume shadow copies via WMI' }
    @{ rx = '(?i)\bwbadmin\b[^\n]*\bdelete\b';                          why = 'deletes the Windows backup catalog' }
    @{ rx = '(?i)\bbcdedit\b[^\n]*\bsafeboot\b';                        why = 'alters Safe Mode boot configuration' }
    @{ rx = '(?i)\bbcdedit\b[^\n]*recoveryenabled[^\n]*\bno\b';         why = 'disables Windows recovery' }
    @{ rx = '(?i)\bbcdedit\b[^\n]*bootstatuspolicy[^\n]*ignoreallfailures'; why = 'suppresses boot failure recovery' }
    @{ rx = '(?i)Set-MpPreference[^\n]*-Disable\w*[^\n]*\$?true';       why = 'disables Microsoft Defender protection' }
    @{ rx = '(?i)Add-MpPreference[^\n]*-Exclusion';                     why = 'adds a Defender exclusion (evasion, not remediation)' }
    @{ rx = '(?i)(Stop-Service|sc(\.exe)?\s+(stop|delete)|net\s+stop)[^\n]*\b(WinDefend|Sense|WdNisSvc|SecurityHealthService)\b'; why = 'stops or deletes a Defender service' }
    @{ rx = '(?i)\bcipher\b[^\n]*\/w';                                  why = 'securely wipes free space (anti-forensic, irreversible)' }
    @{ rx = '(?i)\b(format|diskpart)\b[^\n]*(\/(fs|q|y)\b|clean)';      why = 'formats or wipes a disk' }
    @{ rx = '(?i)(wevtutil[^\n]*\bcl\b|Clear-EventLog|Remove-EventLog)'; why = 'clears Windows event logs (anti-forensic)' }
    @{ rx = '(?i)(net\s+user\s+\S+\s+\S+|New-LocalUser|net\s+localgroup[^\n]*administrators[^\n]*\/add|Add-LocalGroupMember[^\n]*Administrators)'; why = 'creates or alters a local account / grants admin' }
    @{ rx = '(?i)netsh[^\n]*advfirewall[^\n]*\bstate\s+off';            why = 'turns the Windows firewall off' }
    @{ rx = '(?i)Set-NetFirewallProfile[^\n]*-Enabled\s+\$?false';      why = 'turns the Windows firewall off' }
    @{ rx = '(?i)\bicacls\b[^\n]*\/reset[^\n]*\/t';                     why = 'recursively resets ACLs (CLAUDE.md forbids this outright)' }
    @{ rx = '(?i)\btakeown\b[^\n]*\/f[^\n]*\/r';                        why = 'recursively takes ownership of a tree' }
    @{ rx = '(?i)reg(\.exe)?\s+delete[^\n]*HK(LM|EY_LOCAL_MACHINE)\\(SOFTWARE|SYSTEM)\s*(\/f)?\s*$'; why = 'deletes an entire registry hive' }
    @{ rx = '(?i)EnableLUA[^\n]*(-Value\s*0|\s0\s*$)';                  why = 'disables UAC' }
    @{ rx = '(?i)(Remove-Item|rd|rmdir|del)\b[^\n]*\b[a-z]:\\(\s|$|["'']|\\\*)'; why = 'recursive delete at a drive root' }
    @{ rx = '(?i)(Remove-Item|rd|rmdir|del)\b[^\n]*[a-z]:\\Windows\\?\s*["'']?\s*(-recurse|\/s)'; why = 'recursive delete of the Windows directory' }
)

# A RunCmd FixParam is a COMMAND, and the path rules in the protected-target guard
# match a path MENTIONED anywhere in a string. Those two facts together blocked the
# engine's own repairs: restoring a hijacked Winlogon Userinit writes the value
# 'C:\Windows\system32\userinit.exe,', so the guard saw "\system32\", called it a
# Windows-system-directory write, and refused — every time, on every box (audit M1,
# same class as STICKY_*). The path rules are therefore applied to a RunCmd only when
# the command carries a verb that can actually mutate what it names. Everything in
# $RUNCMD_DESTRUCTIVE_R above still applies unconditionally.
$RUNCMD_MUTATING_R = '(?i)(Remove-Item|Remove-ItemProperty|Rename-Item|Move-Item|Set-Content|Add-Content|Clear-Content|Out-File|New-Item|Copy-Item|Set-Acl|Invoke-Expression|\biex\b|Start-Process|\bicacls\b|\btakeown\b|\battrib\b|\bcacls\b|\b(del|erase|rd|rmdir|move|ren|rename|copy|xcopy|robocopy)\s|\breg(\.exe)?\s+(delete|add)\b|\bcmd(\.exe)?\b|\bpowershell(\.exe)?\b|\bpwsh(\.exe)?\b|>)'

function Test-RDestructiveRunCmd {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return '' }
    foreach ($r in $RUNCMD_DESTRUCTIVE_R) {
        if ($Cmd -match $r.rx) { return $r.why }
    }
    return ''
}

$KILL_CRITICAL_NAME_RX_R = '(?i)^(System|smss|csrss|wininit|winlogon|services|lsass|svchost|dwm|fontdrvhost|explorer|powershell|pwsh|conhost|RuntimeBroker|MsMpEng)(\.exe)?$|(?i)(claude|zerobreach)'
$KILL_CRITICAL_DESC_RX_R = '(?i)(\b(System|smss|csrss|wininit|winlogon|services|lsass|svchost|dwm|fontdrvhost|explorer|powershell|pwsh|conhost|RuntimeBroker|MsMpEng)\b|claude|zerobreach)'

function Test-RProtected {
    param([string]$Action, [string]$Param, [string]$Target, [string]$Desc)
    $p = ConvertTo-RGuardPath "$Param"; $t = "$Target"; $d = "$Desc"; $hay = "$p`n$t`n$d"
    if ($Action -eq 'RunCmd') {
        $badCmd = Test-RDestructiveRunCmd "$Param"
        if ($badCmd) { return "destructive command — $badCmd" }
        if ("$Param" -notmatch $RUNCMD_MUTATING_R) { return '' }
    }
    if ($p -match '(?i)Cert:\\' -or $hay -match '(?i)(root\s+ca|trusted\s+root|certificate\s+(store|authority))') { return 'certificate trust store' }
    if ($p -match '(?i)^[a-z]:\\windows\\' -or $p -match '(?i)\\(System32|SysWOW64|WinSxS)\\') { return 'Windows system directory' }
    if ($p -match '(?i)\\(desktop\.ini|iconcache\.db|thumbs\.db|ntuser\.dat|usrclass\.dat)' -or $p -match '(?i)\.library-ms$') { return 'Windows shell/system file' }
    if ($p -match '(?i)\\Users\\[^\\]+\\\.[^\\]+$' -or $p -match '(?i)\\\.(ssh|gnupg|aws|azure|kube|docker|config)\\' -or $p -match '(?i)\\\.(bashrc|bash_profile|bash_history|profile|zshrc|gitconfig|npmrc|claude\.json)($|[^a-z])' -or $p -match '(?i)\\\.claude\\') { return 'user shell/git/ssh/cloud config (dotfile)' }
    if ($p -match '(?i)\\SafeBoot') { return 'SafeBoot registry (breaks Safe Mode)' }
    if ($Action -match '(?i)DeleteReg' -and $p -match '(?i)\\(SYSTEM\\CurrentControlSet\\(Services|Control)|Microsoft\\Windows NT\\CurrentVersion\\(Winlogon|Image File Execution Options|SystemRestore)|Cryptography)') {
        $ifeoValueFix = ($Action -eq 'DeleteReg' -and $p -match '(?i)\\Image File Execution Options\\' -and $p -match '(?i)\|\s*(Debugger|GlobalFlag)\s*$')
        if (-not $ifeoValueFix) { return 'core OS registry' }
    }
    if ($Action -eq 'KillProcess') {
        $kpName = ''; $kpParts = "$Param" -split '\|'
        if ($kpParts.Count -ge 2) { $kpName = "$($kpParts[1])".Trim() }
        if ($kpName) { if ($kpName -match $KILL_CRITICAL_NAME_RX_R) { return 'critical system process or the IR tool itself' } }
        elseif ($d -match $KILL_CRITICAL_DESC_RX_R) { return 'critical system process or the IR tool itself' }
    }
    return ''
}

function Get-RRegVal {
    # Mirror of the engine's Get-RegVal. Get-ItemPropertyValue throws a *terminating*
    # error when the value is absent, which -EA SilentlyContinue does NOT suppress
    # (CLAUDE.md rule). PendingFileRenameOperations usually does not exist on a healthy
    # machine, so the raw cmdlet threw into the per-finding catch the FIRST time a
    # locked file needed queueing: logged "-> ERROR:", counted as failed, and the
    # reboot-delete was never queued — while Quarantine had already copied the file to
    # the vault, leaving the original live on disk (audit H10).
    param([string]$Path, [string]$Name)
    try { Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop } catch { $null }
}

function Add-RPendingDelete {
    # Queue a locked file for deletion at next boot. Returns $true if queued.
    param([string]$Target)
    try {
        $rpk = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $cur = Get-RRegVal $rpk "PendingFileRenameOperations"
        if ($null -eq $cur) { $cur = @() }
        Set-ItemProperty $rpk "PendingFileRenameOperations" ([string[]]($cur) + @("\??\$Target", "")) -Type MultiString -Force -ErrorAction Stop
        return $true
    } catch { return $false }
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
                    $dtgt = "$($f.FixParam)"
                    if (-not (Test-Path -LiteralPath $dtgt)) {
                        RLog "  -> already absent." 'OK'; $ok = $true
                    } else {
                        $ditem = Get-Item -LiteralPath $dtgt -Force -ErrorAction Stop

                        # audit H6: this action is DeleteFILE. -Recurse was being passed, so a
                        # FixParam that resolved to a directory deleted the whole tree, and a
                        # junction planted at a flagged path could turn one approved deletion
                        # into mass data loss. Refuse anything that is not a plain file.
                        if ($ditem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                            RLog "  -> BLOCKED: target is a reparse point (junction/symlink), not a file: $dtgt" 'CRITICAL'
                            $blocked++
                        }
                        elseif ($ditem.PSIsContainer) {
                            RLog "  -> BLOCKED: target is a directory; DeleteFile will not delete trees: $dtgt" 'CRITICAL'
                            $blocked++
                        }
                        else {
                            # audit H6/H7: the guard above ran on the raw string. Re-run it on the
                            # fully-resolved path so a path that only LOOKS innocuous cannot slip
                            # a protected target past it.
                            $dfull = $ditem.FullName
                            $why2  = Test-RProtected 'DeleteFile' $dfull "$($f.Target)" "$($f.Description)"
                            if ($why2) {
                                RLog "[BLOCKED] resolved path is protected ($why2): $dfull" 'CRITICAL'
                                $blocked++
                            } else {
                                Remove-Item -LiteralPath $dfull -Force -ErrorAction Stop
                                if (Test-Path -LiteralPath $dfull) {
                                    if (Add-RPendingDelete $dfull) { RLog "  -> locked; queued for reboot deletion." 'POSSIBLE' }
                                    else { RLog "  -> locked and could NOT be queued for reboot deletion — still on disk." 'CRITICAL'; $failed++ }
                                } else { RLog "  -> deleted: $dfull" 'OK' }
                                $ok = $true
                            }
                        }
                    }
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
                    # FixParam is "<pid>|<name>|<startTicks>" (see Get-KillParam). PIDs are
                    # recycled, and remediation runs long after the scan, so the process
                    # holding this PID now may be something else entirely (audit H5).
                    $kp = "$($f.FixParam)" -split '\|'
                    $procId = 0
                    if (-not [int]::TryParse($kp[0].Trim(), [ref]$procId) -or $procId -le 0) {
                        RLog "  -> malformed KillProcess target: $($f.FixParam)" 'POSSIBLE'; $skipped++
                    } else {
                        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
                        if (-not $p) {
                            RLog "  -> process already gone." 'OK'; $ok = $true
                        } else {
                            $idOk = $true; $why = ''
                            if ($kp.Count -ge 3) {
                                $wantName  = "$($kp[1])"
                                $wantTicks = [int64]0
                                [void][int64]::TryParse("$($kp[2])", [ref]$wantTicks)
                                $haveTicks = [int64]0
                                try { $haveTicks = $p.StartTime.Ticks } catch { $haveTicks = 0 }
                                if ($wantName -and $p.ProcessName -ne $wantName) {
                                    $idOk = $false
                                    $why  = "now '$($p.ProcessName)', scan flagged '$wantName'"
                                }
                                elseif ($wantTicks -gt 0 -and $haveTicks -gt 0 -and $haveTicks -ne $wantTicks) {
                                    $idOk = $false
                                    $why  = 'same name but a different start time'
                                }
                            } else {
                                RLog "  -> NOTE: finding carries a bare PID (older report); identity cannot be verified." 'POSSIBLE'
                            }

                            if (-not $idOk) {
                                # Refuse. Killing the wrong process is worse than not killing.
                                RLog "  -> SKIPPED: PID $procId is no longer the flagged process ($why). PID was recycled." 'POSSIBLE'
                                $skipped++
                            } else {
                                Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                                Start-Sleep -Milliseconds 300
                                if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) { RLog "  -> terminated PID $procId ($($p.Name))" 'OK'; $ok = $true }
                                else { RLog "  -> kill failed PID $procId" 'POSSIBLE'; $failed++ }
                            }
                        }
                    }
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
                            # audit H10: this used the raw Get-ItemPropertyValue, which threw on
                            # the common case (value absent) and skipped the queue entirely —
                            # leaving a copy in the vault AND the original live on disk.
                            if (-not (Add-RPendingDelete $src)) {
                                RLog "  -> WARNING: original is locked and could NOT be queued for reboot deletion — it is still live on disk." 'CRITICAL'
                            }
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
                # audit M3: neither of these may set $ok. The trailing counter reads $ok
                # as "a real action ran", and an unrecognised FixAction is not in the
                # Info/None/'' exclusion list — so it was counted as skipped AND applied,
                # and remediation_complete never reconciled.
                'Info'  { RLog "  -> informational; review manually." 'INFO'; $skipped++ }
                default { RLog "  -> no automated action for FixAction '$($f.FixAction)'." 'INFO'; $skipped++ }
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

    # ── C1 gate ────────────────────────────────────────────────────────────────
    # Origin lockdown covers EVERY route, static assets included. A request with no
    # Origin header is a same-origin navigation or a local tool; one carrying a
    # foreign Origin is a cross-site caller and gets nothing.
    if (-not (Test-RequestOrigin $Ctx)) {
        Write-JsonResponse $Ctx '{"error":"forbidden","detail":"cross-origin request refused"}' 403
        return
    }

    # Preflight: no cross-origin caller is welcome here, so answer with no
    # Access-Control-Allow-* headers at all. A cross-site fetch fails at this step.
    if ($method -eq 'OPTIONS') {
        $Ctx.Response.StatusCode = 204
        Add-SecurityHeaders $Ctx.Response
        try { $Ctx.Response.Close() } catch {}
        return
    }

    # Launch token on the privileged surface. Static assets stay open deliberately:
    # a tokenless browser must still be able to load the page so it can TELL the
    # operator what is wrong instead of showing a dead grey screen.
    if ($path -like '/api/*' -and -not (Test-RequestAuth $Ctx)) {
        Write-JsonResponse $Ctx '{"error":"unauthorized","detail":"missing or invalid launch token"}' 401
        return
    }

    # Body size ceiling (audit M6). Every POST body is read into a string and parsed;
    # the largest legitimate one is an IOC set or a scan profile. Refuse before
    # reading so a bad or hostile caller can't make the console allocate at will.
    if ($method -eq 'POST' -and $req.ContentLength64 -gt $script:MAX_BODY_BYTES) {
        Write-JsonResponse $Ctx '{"error":"payload too large"}' 413
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
                scan_failed   = $script:State.ScanFailed
                fail_reason   = $script:State.FailReason
                exit_code     = $script:State.ExitCode
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

            # Claim the slot synchronously (audit H9). This one matters more than the
            # scan slot: two remediation passes racing through the same destructive fix
            # list is the failure mode, and C1 showed a hostile page could fire them
            # deliberately.
            $script:State.Remediating = $true

            try {
                Start-Runspace -Script $script:REMEDIATE_SCRIPT -Vars @{
                    RemState   = $script:State
                    RemReports = $script:REPORTS
                    ReportPath = $reportPath
                    FixIds     = @($ids)
                } | Out-Null
            } catch {
                $script:State.Remediating = $false
                Write-JsonResponse $Ctx '{"error":"failed to start remediation"}' 500
                return
            }
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
                # audit M6 — nothing reaches custom_iocs.ioc unvalidated.
                $vetted   = ConvertTo-IocSet $parsed
                $rejected = @($vetted.Rejected)
                $cats = @{
                    hashes  = @($vetted.Set.hashes);  ips   = @($vetted.Set.ips)
                    domains = @($vetted.Set.domains); regex = @($vetted.Set.regex)
                    files   = @($vetted.Set.files)
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
                    Write-JsonResponse $Ctx (@{
                        status = 'saved'; path = $iocText; json_path = $iocJson; count = $count
                        rejected = $rejected.Count
                        rejected_detail = @($rejected | Select-Object -First 20)
                        accepted = @{
                            hashes = @($cats.hashes); ips = @($cats.ips); domains = @($cats.domains)
                            regex  = @($cats.regex);  files = @($cats.files)
                        }
                    } | ConvertTo-Json -Compress -Depth 4)
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

            # Claim the slot HERE, synchronously, before the runspace is launched
            # (audit H9). The runspace used to set Running itself, so two POSTs landing
            # before it scheduled would both pass the check above and spawn an engine —
            # two processes writing the same reports/ directory.
            $script:State.Running = $true

            try {
                Start-Runspace -Script $script:SCAN_SCRIPT -Vars @{
                    ScanState   = $script:State
                    ScanConfig  = $cfg
                    ScanPsPath  = $script:SCAN_PS
                    ScanReports = $script:REPORTS
                    MitreMap    = $script:MITRE_MAP
                } | Out-Null
            } catch {
                # Never leave the slot claimed by a runspace that never started.
                $script:State.Running = $false
                Write-JsonResponse $Ctx '{"error":"failed to start scan"}' 500
                return
            }

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
# Bound to the literal loopback address, not 'localhost': http.sys matches the request's
# Host header against this prefix, so a DNS-rebound hostname is refused with a 400
# before any handler runs (audit C1).
$Listener.Prefixes.Add("http://127.0.0.1:$Port/")
$script:ALLOWED_ORIGINS = @("http://127.0.0.1:$Port")

try { $Listener.Start() }
catch [System.Net.HttpListenerException] {
    # Locked-down machine: the URL namespace may need an explicit reservation.
    Write-Host ('[ZeroBreach] Listener blocked (' + $_.Exception.Message + '); adding URL ACL...') -ForegroundColor Yellow
    $acl = "http://127.0.0.1:$Port/"
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

$Url      = "http://127.0.0.1:$Port"
$UrlToken = "$Url/?t=$script:AUTH_TOKEN"

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║    ZEROBREACH V23 — KRAKEN CONSOLE               ║" -ForegroundColor Cyan
Write-Host "  ║    HTTP Server: $($Url.PadRight(34))║" -ForegroundColor Cyan
Write-Host "  ║    Press Ctrl+C to stop                          ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host ('[ZeroBreach] Serving GUI at ' + $Url) -ForegroundColor Green
Write-Host ('[ZeroBreach] Scan engine: ' + $script:SCAN_PS) -ForegroundColor DarkCyan
Write-Host ''
Write-Host '  [ZeroBreach] This console requires a launch token. Open THIS exact URL:' -ForegroundColor Yellow
Write-Host ("  $UrlToken") -ForegroundColor White
Write-Host '  (A new token is minted every launch. Without it the API answers 401.)' -ForegroundColor DarkGray
Write-Host ''

if (-not $NoBrowser) {
    $urlCapture   = $Url
    $tokenCapture = $UrlToken
    # Don't open the browser on a fixed timer — poll until the server actually answers
    # a request, THEN launch. This both (a) guarantees the first browser paint never
    # races the listener and (b) pre-warms the static-file path, fixing the occasional
    # blank/grey screen seen right after the UAC launch. The accept loop (below, on the
    # main thread) serves these probe requests.
    $null = Start-Job -ArgumentList $urlCapture, $tokenCapture {
        param($u, $ut)
        for ($i = 0; $i -lt 50; $i++) {
            try {
                $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 2
                if ($r.StatusCode -eq 200) { break }
            } catch { Start-Sleep -Milliseconds 150 }
        }
        # Probe the tokenless root (static, always 200); launch the tokenised URL.
        Start-Process $ut
    }
}

# ── Accept loop ────────────────────────────────────────────────────────────────
try {
    while ($script:State.Listening) {
        try {
            $ctx = $null
            $ctx = $Listener.GetContext()
            Handle-Request $ctx
            Clear-FinishedRunspaces   # audit M2 — reap disconnected SSE runspaces
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
