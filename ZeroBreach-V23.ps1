# ZeroBreach-V22.ps1 — Monolithic Omni-Tier Forensic Exorcist
# CONSOLIDATED: V21 + Debug Pass 2 + Phases 106-107 + Schedule + HTML/CSV export

#Requires -Version 5.1
<#
.SYNOPSIS
    Project Kraken // ZeroBreach V22 — Omni-Tier Forensic Exorcist
    Author: Patrick McClevarty / Gannon MSP
.DESCRIPTION
    107-Phase Malware IR Engine. Modes: QUICK/FULL/DEEP/PARANOID/STEALTH.
    HTML+TXT+JSON reports. Baseline diff. Custom IOC import.
    MSP triggers: msp/staples/gannon at any prompt.
    Rollback snapshot created before any fixes.
    V22 CHANGES: Debug Pass 2 (10 bug fixes), Phase 106 minidump artifact scan,
    Phase 107 event log threat hunt (4624/4688/7045), -Schedule param (daily/weekly
    task + email report), HTML print + export-to-CSV, free-text scan window entry,
    YARA 10MB cap, worm share scan depth cap, RunCmd safety (ScriptBlock eval),
    expanded C2/ngrok/Cloudflare tunnel IOC list.
    Threat types: Trojans, Worms, Keyloggers, RATs, Ransomware, Rootkits,
                  Cryptominers, Spyware/PUPs, Bootkits, Fileless, Adware,
                  Backdoors, Browser Hijackers, Info-Stealers, LoLBin, COM Hijacks,
                  WMI Persistence, Process Hollowing, Named Pipe Backdoors,
                  UAC Bypass, AppDomainManager, PrintNightmare, ClickOnce,
                  Stolen/Leaked Certs, Container/WSL Escape,
                  Memory Dump Artifacts, Event Log Anomalous Logons/Processes.
.PARAMETER Stealth     Silent — no banners, JSON to stdout only
.PARAMETER Paranoid    Lower thresholds — POSSIBLE escalated to HIGH
.PARAMETER IocFile     Path to custom IOC text file
.PARAMETER Baseline    Path to baseline JSON for diff
.PARAMETER Mode        QUICK|FULL|DEEP|PARANOID|STEALTH (skip menu)
.PARAMETER Hours       Scan window hours (skip menu; 0 = all time)
.PARAMETER Auto        Skip all menus, use param defaults
.PARAMETER Html        Generate HTML report in addition to TXT
.PARAMETER OutDir      Output directory (default: Desktop)
.PARAMETER Schedule    Register as scheduled task: DAILY or WEEKLY
.PARAMETER SmtpTo      Email address for scheduled task reports
.PARAMETER SmtpFrom    Sender address for scheduled task reports
.PARAMETER SmtpServer  SMTP server for scheduled task reports
#>

[CmdletBinding()]
param(
    [switch]$Stealth,
    [switch]$Paranoid,
    [string]$IocFile   = "",
    [string]$Baseline  = "",
    [ValidateSet("","QUICK","FULL","DEEP","PARANOID","STEALTH")]
    [string]$Mode      = "",
    [int]   $Hours     = -1,
    [switch]$Auto,
    [switch]$Html,
    [string]$OutDir    = "",
    [ValidateSet("","DAILY","WEEKLY")]
    [string]$Schedule  = "",
    [string]$SmtpTo    = "",
    [string]$SmtpFrom  = "",
    [string]$SmtpServer= ""
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

# ── Global resilience trap ────────────────────────────────────────────────────
# A terminating error anywhere (unhandled .NET exception, throw, null .Substring,
# out-of-range index, ConvertFrom-Json -Stop, a hung cmdlet that faults, etc.)
# would otherwise kill the whole engine mid-scan and silently skip every remaining
# phase — the tool would appear to "stop" in an error state. This trap LOGS the
# failure and RESUMES at the next statement, so a scan always runs to completion.
# Local try/catch still takes precedence; this only catches what nothing handled.
# It is fully defensive — it must never throw out of itself.
$global:RECOVERED_ERRORS = [System.Collections.Generic.List[string]]::new()
# Record a trapped (recovered) terminating error. Shared by the script-scope trap
# below AND by the per-phase-group inner traps (Universal/Advanced/Integrity), so a
# single phase's terminating fault resumes at the NEXT phase instead of skipping the
# rest of its PhasePlan block. (Defined before the trap so the trap body can call it.)
function Write-RecoveredError {
    param($ErrorRecord)
    try {
        $em   = $ErrorRecord.Exception.Message
        $pos  = (("" + $ErrorRecord.InvocationInfo.PositionMessage) -replace "`r?`n"," ").Trim()
        $line = "RECOVERED ERROR: $em | $pos"
        $global:RECOVERED_ERRORS.Add($line)
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log $line }
        if (-not $global:STEALTH_MODE) { Write-Host "  [!] $line" -ForegroundColor DarkYellow }
    } catch {}
}
trap { Write-RecoveredError $_; continue }

# ── Elevation — pass all params ───────────────────────────────────────────────
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[CRITICAL] INSUFFICIENT PRIVILEGES. INITIATING ELEVATION..." -ForegroundColor Red
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Stealth)    { $argList += " -Stealth" }
    if ($Paranoid)   { $argList += " -Paranoid" }
    if ($Auto)       { $argList += " -Auto" }
    if ($Html)       { $argList += " -Html" }
    if ($Mode)       { $argList += " -Mode $Mode" }
    if ($Hours -ge 0){ $argList += " -Hours $Hours" }
    if ($IocFile)    { $argList += " -IocFile `"$IocFile`"" }
    if ($Baseline)   { $argList += " -Baseline `"$Baseline`"" }
    if ($OutDir)     { $argList += " -OutDir `"$OutDir`"" }
    # -Schedule/-Smtp* MUST be forwarded too: registering a scheduled task is the one
    # realistic reason to run this from a NON-admin shell, and dropping them here made the
    # elevated child skip the schedule block entirely while printing no error at all.
    if ($Schedule)   { $argList += " -Schedule $Schedule" }
    if ($SmtpTo)     { $argList += " -SmtpTo `"$SmtpTo`"" }
    if ($SmtpFrom)   { $argList += " -SmtpFrom `"$SmtpFrom`"" }
    if ($SmtpServer) { $argList += " -SmtpServer `"$SmtpServer`"" }
    Start-Process powershell $argList -Verb RunAs; exit
}

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Drawing       -ErrorAction SilentlyContinue

# ── Schedule Registration — runs before any scan logic ────────────────────────
if ($Schedule -and $Schedule -ne "") {
    $taskName   = "ZeroBreach_V22_Scheduled"
    $scriptPath = $PSCommandPath
    $argBase    = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Auto -Html -Mode FULL -Hours 0"
    if ($OutDir)     { $argBase += " -OutDir `"$OutDir`"" }
    if ($SmtpTo)     { $argBase += " -SmtpTo `"$SmtpTo`" -SmtpFrom `"$SmtpFrom`" -SmtpServer `"$SmtpServer`"" }
    $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argBase
    $trigger = if ($Schedule -eq "DAILY") {
        New-ScheduledTaskTrigger -Daily -At "02:00AM"
    } else {
        New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Monday -At "02:00AM"
    }
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 3) -RunOnlyIfIdle $false -WakeToRun $false
    $principal= New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Force -ErrorAction SilentlyContinue | Out-Null
    $chk = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($chk) {
        Write-Host "[ZeroBreach V22] Scheduled task '$taskName' registered ($Schedule at 02:00). Run: SYSTEM" -ForegroundColor Green
    } else {
        Write-Host "[ZeroBreach V22] WARNING: Task registration failed — check permissions." -ForegroundColor Red
    }
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════
$global:MSP_MODE       = $false
$global:STEALTH_MODE   = [bool]$Stealth
$global:PARANOID_MODE  = [bool]$Paranoid
$global:HTML_REPORT    = [bool]$Html
$global:GUI_MODE       = $false
$global:ScanMode       = "FULL"
$global:TIME_LIMIT     = [datetime]::MinValue
$global:TW_LABEL       = ""   # set by -Hours param or interactive menu; blank triggers the menu
$global:START_TIME     = Get-Date
$global:TotalAnomalies = 0
$global:KillCount      = 0
$global:VerifyFails    = 0
$global:VSSDeleted     = $false
$global:RansomwareRisk = 0
$global:KeyloggerHits  = 0
$global:RootkitHits    = 0
$global:RATHits        = 0
$global:MinerHits      = 0
$global:WormHits       = 0
$global:SpywareHits    = 0
$global:TrojanHits     = 0
$global:EMAIL_PHISH_SEEN = $false   # set by Phase 74.6 when Defender history names a phishing/redirector family
$global:BackdoorHits   = 0
$global:UACBypassHits  = 0
$global:PhaseTimings   = [System.Collections.Generic.List[hashtable]]::new()
$global:CustomIocs     = @{ Hashes=@(); Domains=@(); IPs=@(); Regex=@(); Files=@() }
$global:BaselineDelta  = [System.Collections.Generic.List[hashtable]]::new()
$global:PSVersionMajor = $PSVersionTable.PSVersion.Major
$global:OS_VERSION     = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
$global:IS_LEGACY_OS   = ($global:OS_VERSION -match "Windows 7|Server 2008|Server 2012")

# ── Kill-switch / live GUI state ─────────────────────────────────────────────
$global:SKIP_SLOW_OUTPUT = $false   # [K] toggles this — kills typewriter/quantum delays mid-phase
# Non-interactive run (GUI server, redirected stdout, or -Auto): suppress all char-by-char
# animations and dramatic pauses — emit each line ONCE, cleanly. The decrypt/glitch/typewriter
# effects only suit a real attached console; piped to the web UI they render as garbage
# "random character" lines. This makes scans far faster and the log readable.
$redir = $false; try { $redir = [Console]::IsOutputRedirected } catch {}
$global:NONINTERACTIVE = ($Auto -or $redir)
if ($global:NONINTERACTIVE) { $global:SKIP_SLOW_OUTPUT = $true }
# Redirected stdout (GUI server) defaults to the OEM codepage on PS 5.1, so box-drawing
# banners arrive as mojibake in the web UI. Match the server's UTF-8 reader. Attached
# consoles keep their native codepage (changing it there garbles the interactive view).
if ($redir) {
    try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
}
# Bind the Security module (Get-AuthenticodeSignature / Get-Acl) up front, before the
# known AccessControl.ObjectSecurity TypeData collision can degrade them mid-scan.
try { Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue } catch {}

# ── Output flood guard ───────────────────────────────────────────────────────
# A single over-broad detection can match tens of thousands of benign files
# (e.g. Phase 18 hidden+system, Phase 94 .xsl). Without a cap, each one emits a
# 12-line threat banner + a finding event — drowning the console, ballooning the
# transcript to 25 MB+, and flooding the web UI's SSE stream until the browser
# main thread saturates and the page freezes. Cap per-category banners and
# per-group findings; roll the remainder into a single summary line.
$global:BANNER_COUNTS       = @{}
$global:BANNER_CATEGORY_CAP = 25     # full threat banners per category, then summarize
$global:GROUP_COUNTS        = @{}
$global:FINDING_GROUP_CAP   = 100    # individual findings per group, then roll up
$global:GUI_LIVE_FORM    = $null    # WinForms form reference for live scan dashboard
$global:GUI_LIVE_TREE    = $null    # TreeView ref for live finding updates
$global:GUI_LIVE_LOG     = $null    # RichTextBox ref for live log stream
$global:GUI_PHASE_LBL    = $null    # Label showing current phase
$global:GUI_PROG_BAR     = $null    # ProgressBar
$global:GUI_RISK_LBL     = $null    # Live findings counter label
$global:GUI_KILL_BTN     = $null    # Kill slow output button reference
$global:TOTAL_PHASES     = 80       # Updated after PhasePlan is set
$global:CURRENT_PHASE_NUM= 0
$global:SCAN_COMPLETE    = $false
# ── Per-phase wall-clock profiling ────────────────────────────────────────────
# Stop-PhaseTiming closes out the phase currently in flight and emits one clean
# stdout line ("PHASE N — <name> took X.Xs") so timings flow through SSE into the
# console/report. Show-PhaseHeader closes the previous phase + starts the next.
$global:PHASE_SW         = $null    # active [System.Diagnostics.Stopwatch]
$global:PHASE_TIMING_LBL = ""       # label of the phase currently being timed
$global:PHASE_TIMINGS    = [System.Collections.Generic.List[object]]::new()
$global:SHELL_KILL_JOB   = $null    # Background job watching for K keypress
$global:SHELL_KILL_FLAG  = $null    # Temp file path used as IPC flag for K keypress

# Audit result store — each item is a hashtable describing a finding
$global:AuditFindings  = [System.Collections.Generic.List[hashtable]]::new()

$HOST_NAME  = $env:COMPUTERNAME
$USER_NAME  = $env:USERNAME
$STAMP      = Get-Date -Format 'yyyyMMdd_HHmmss'
# Project root for engine/ modules — $PSScriptRoot inside a dot-sourced engine\*.ps1
# resolves to engine\, so modules must use this instead. Must be set UNCONDITIONALLY
# (Phase 66's self-file guard depends on it even when -OutDir is passed).
$global:ZB_ROOT = $PSScriptRoot
if ($OutDir -and (Test-Path $OutDir -IsValid)) {
    if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }
    $OUT_ROOT = $OutDir
} else {
    # USB-portable default: write next to the script, not the user's Desktop.
    $OUT_ROOT = Join-Path $PSScriptRoot 'reports'
    if (-not (Test-Path $OUT_ROOT)) { New-Item -Path $OUT_ROOT -ItemType Directory -Force | Out-Null }
}
$REPORT_PATH   = Join-Path $OUT_ROOT "KrakenReport_$STAMP.txt"
$HTML_PATH     = Join-Path $OUT_ROOT "KrakenReport_$STAMP.html"
$AUDIT_JSON    = Join-Path $env:TEMP "ZeroBreach_AuditCache_$(Get-Date -Format 'yyyyMMdd').json"
$BASELINE_PATH = Join-Path $OUT_ROOT "KrakenBaseline_$STAMP.json"
$SNAPSHOT_PATH = Join-Path $OUT_ROOT "KrakenSnapshot_$STAMP.reg"
$LOG_LINES  = [System.Collections.Generic.List[string]]::new()
$rng        = [System.Random]::new()

# Severity constants
$SEV_CRITICAL = "CRITICAL"   # Blatant malware — warn if deselected
$SEV_HIGH     = "HIGH"       # Likely malicious
$SEV_POSSIBLE = "POSSIBLE"   # Suspicious, may be FP
$SEV_INFO     = "INFO"       # Hardening / informational

# ══════════════════════════════════════════════════════════════════════════════
#  COLOUR HELPERS (MSP mode swaps to Gannon orange where possible)
# ══════════════════════════════════════════════════════════════════════════════
function Get-AccentColor {
    if ($global:MSP_MODE) { return "DarkYellow" } else { return "Cyan" }
}
function Get-WarnColor {
    if ($global:MSP_MODE) { return "Yellow" } else { return "Yellow" }
}
function Get-HitColor {
    return "Red"
}

# ══════════════════════════════════════════════════════════════════════════════
#  VISUAL ENGINE
# ══════════════════════════════════════════════════════════════════════════════
function Write-Log { param([string]$Line); $script:LOG_LINES.Add($Line) }

function Invoke-GuiDoEvents {
    if ($null -ne $global:GUI_LIVE_FORM -and -not $global:GUI_LIVE_FORM.IsDisposed) {
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Out-Typewriter {
    param([string]$Text, [string]$Level="INFO", [int]$Speed=16)
    if ($global:STEALTH_MODE) { $script:LOG_LINES.Add("[$Level] $Text"); return }
    if ($global:MSP_MODE -or $global:SKIP_SLOW_OUTPUT) { $Speed = 0 }
    $ts = (Get-Date).ToString("HH:mm:ss.fff")
    # Stream to live GUI log if active
    if ($null -ne $global:GUI_LIVE_LOG -and -not $global:GUI_LIVE_LOG.IsDisposed) {
        $col = switch ($Level) {
            "CRIT" { [System.Drawing.Color]::FromArgb(255,80,80) }
            "WARN" { [System.Drawing.Color]::Yellow }
            "GOOD" { [System.Drawing.Color]::LimeGreen }
            "HUNT" { [System.Drawing.Color]::FromArgb(255,160,0) }
            "FIND" { [System.Drawing.Color]::FromArgb(255,50,50) }
            default { [System.Drawing.Color]::FromArgb(160,160,160) }
        }
        $logLine = "[$ts][$Level] $Text"
        $global:GUI_LIVE_LOG.SelectionStart  = $global:GUI_LIVE_LOG.TextLength
        $global:GUI_LIVE_LOG.SelectionLength = 0
        $global:GUI_LIVE_LOG.SelectionColor  = $col
        $global:GUI_LIVE_LOG.AppendText("$logLine`r`n")
        $global:GUI_LIVE_LOG.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
    $prefix = ""; $color = "DarkGray"
    switch ($Level) {
        "INFO" { $prefix = "[$ts] [SYS] "; $color = "DarkGray"   }
        "WARN" { $prefix = "[$ts] [WRN] "; $color = "Yellow"     }
        "CRIT" { $prefix = "[$ts] [!!!] "; $color = "Red"        }
        "GOOD" { $prefix = "[$ts] [OK ] "; $color = "Green"      }
        "ACT"  { $prefix = "[$ts] [EXE] "; $color = "Magenta"    }
        "VER"  { $prefix = "[$ts] [CHK] "; $color = (Get-AccentColor) }
        "DATA" { $prefix = "[$ts] [DAT] "; $color = "DarkCyan"   }
        "HUNT" { $prefix = "[$ts] [HNT] "; $color = if ($global:MSP_MODE) { "DarkYellow" } else { "DarkYellow" } }
        "FIND" { $prefix = "[$ts] [HIT] "; $color = "Red"        }
    }
    Write-Host $prefix -NoNewline -ForegroundColor $color
    if ($Speed -eq 0) {
        Write-Host $Text -ForegroundColor $color
    } else {
        foreach ($c in $Text.ToCharArray()) {
            Write-Host $c -NoNewline -ForegroundColor $color
            Start-Sleep -Milliseconds $Speed
        }
        Write-Host ""
    }
    Write-Log "$prefix$Text"
}

function Out-Decrypt {
    param([string]$Text, [string]$Prefix="  [DECRYPTING] ", [int]$Delay=8)
    if ($global:STEALTH_MODE) { $script:LOG_LINES.Add("$Prefix$Text"); return }
    if ($global:MSP_MODE -or $global:SKIP_SLOW_OUTPUT -or $global:NONINTERACTIVE) { Write-Host "$Prefix$Text" -ForegroundColor (Get-AccentColor); Write-Log "$Prefix$Text"; return }
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#`$%^&*<>!?~"
    $arr = $Text.ToCharArray(); $display = [char[]]::new($arr.Length)
    for ($i=0; $i -lt $arr.Length; $i++) { $display[$i] = $chars[$rng.Next($chars.Length)] }
    for ($i=0; $i -lt $arr.Length; $i++) {
        for ($c=0; $c -lt 3; $c++) {
            $display[$i] = $chars[$rng.Next($chars.Length)]
            Write-Host "`r$Prefix" -NoNewline -ForegroundColor DarkGray
            Write-Host (-join $display) -NoNewline -ForegroundColor DarkCyan
            Start-Sleep -Milliseconds ($Delay / 2)
        }
        $display[$i] = $arr[$i]
        Write-Host "`r$Prefix" -NoNewline -ForegroundColor DarkGray
        Write-Host (-join $display) -NoNewline -ForegroundColor (Get-AccentColor)
        Start-Sleep -Milliseconds $Delay
    }
    Write-Host ""; Write-Log "$Prefix$Text"
}

function Out-Glitch {
    param([string]$Text, [ConsoleColor]$Color = "Red")
    if ($global:STEALTH_MODE) { $script:LOG_LINES.Add("  $Text"); return }
    if ($global:MSP_MODE -or $global:SKIP_SLOW_OUTPUT -or $global:NONINTERACTIVE) { Write-Host "  $Text" -ForegroundColor $Color; Write-Log "  $Text"; return }
    $glitchChars = "▓▒░█▄▀■□▪▫◆◇●○"
    $arr = $Text.ToCharArray()
    for ($pass = 0; $pass -lt 3; $pass++) {
        $corrupted = $arr | ForEach-Object { if ($rng.NextDouble() -lt 0.3) { $glitchChars[$rng.Next($glitchChars.Length)] } else { $_ } }
        Write-Host "`r  " -NoNewline; Write-Host (-join $corrupted) -NoNewline -ForegroundColor DarkRed
        Start-Sleep -Milliseconds 50
    }
    Write-Host "`r  " -NoNewline; Write-Host $Text -ForegroundColor $Color; Write-Log "  $Text"
}

function Out-ThreatBanner {
    param([string]$Category, [string]$Detail)
    if ($global:STEALTH_MODE) { $script:LOG_LINES.Add("THREAT: $Category | $Detail"); return }
    # ── Flood guard: cap full banners per category so one noisy detection can't
    #    drown the console / transcript / web-UI stream. ──────────────────────
    if ($null -eq $global:BANNER_COUNTS) { $global:BANNER_COUNTS = @{} }
    $bcap = if ($global:BANNER_CATEGORY_CAP) { $global:BANNER_CATEGORY_CAP } else { 25 }
    $bn = [int]$global:BANNER_COUNTS[$Category]; $global:BANNER_COUNTS[$Category] = $bn + 1
    if ($bn -ge $bcap) {
        if ($bn -eq $bcap) {
            Write-Host "  ☣  $Category — banner output capped at $bcap; further hits are counted, not drawn." -ForegroundColor DarkYellow
            Write-Log "THREAT: $Category | (banner output capped at $bcap; further occurrences suppressed)"
        }
        return
    }
    $ac = Get-AccentColor
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║  ☣  THREAT: " -NoNewline -ForegroundColor Red
    Write-Host $Category.PadRight(58) -NoNewline -ForegroundColor Yellow
    Write-Host "║" -ForegroundColor Red
    Write-Host "  ║  " -NoNewline -ForegroundColor Red
    $d = $Detail.Substring(0,[Math]::Min(72,$Detail.Length))
    Write-Host $d.PadRight(72) -NoNewline -ForegroundColor White
    Write-Host "  ║" -ForegroundColor Red
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""; Write-Log "THREAT: $Category | $Detail"
}

function Invoke-QuantumBar {
    param($TaskName, $Steps = 15, $MsEach = 90)
    if ($global:STEALTH_MODE) { return }
    if ($global:NONINTERACTIVE) {
        $ts = (Get-Date).ToString("HH:mm:ss.fff")
        Write-Host "[$ts] [PRG] $TaskName ... done (100%)" -ForegroundColor Green
        return
    }
    if ($global:MSP_MODE -or $global:SKIP_SLOW_OUTPUT) { $MsEach = 0 }
    $ts = (Get-Date).ToString("HH:mm:ss.fff"); $prefix = "[$ts] [PRG] "; $width = 30
    $spinChars = @("⠋","⠙","⠸","⠴","⠦","⠇"); $spinIdx = 0
    for ($i = 1; $i -le $Steps; $i++) {
        if ($global:SKIP_SLOW_OUTPUT) { break }   # kill switch — bail immediately
        $pct = [Math]::Floor(($i / $Steps) * 100)
        $f = [Math]::Floor(($pct / 100) * $width); $e = $width - $f
        $bar = ("█" * $f) + ("▒" * [Math]::Min(1,$e)) + ("░" * [Math]::Max(0,$e-1))
        $spin = $spinChars[$spinIdx % $spinChars.Count]
        Write-Host "`r$prefix" -NoNewline -ForegroundColor DarkGray
        Write-Host "$spin " -NoNewline -ForegroundColor Yellow
        Write-Host "$TaskName " -NoNewline -ForegroundColor Magenta
        Write-Host "[$bar] $pct%" -NoNewline -ForegroundColor (Get-AccentColor)
        $spinIdx++
        if ($MsEach -gt 0) { Start-Sleep -Milliseconds $MsEach }
        Invoke-GuiDoEvents
    }
    Write-Host "`r$prefix" -NoNewline -ForegroundColor DarkGray
    Write-Host "✓ $TaskName [$("█"*$width)] 100%" -ForegroundColor Green
    Invoke-GuiDoEvents
}

function Show-SectionBanner {
    param([string]$Title, [string]$Icon = "◈")
    if ($global:STEALTH_MODE) { Write-Log "=== $Title ==="; return }
    $ac = Get-AccentColor; $line = "─" * 78
    Write-Host ""; Write-Host "  $line" -ForegroundColor DarkCyan
    Write-Host "  $Icon  " -NoNewline -ForegroundColor Yellow; Write-Host $Title -ForegroundColor $ac
    Write-Host "  $line" -ForegroundColor DarkCyan; Write-Log "=== $Title ==="
    if (-not $global:GUI_MODE) { Test-ShellKillFlag }   # check K-flag at every section
    Invoke-GuiDoEvents
}

function Stop-PhaseTiming {
    # Closes the phase currently in flight (if any) and emits one clean timing
    # line. Safe to call repeatedly / when no phase is active. Parse-clean, no
    # carriage-returns or scramble — flows straight through SSE.
    if ($null -eq $global:PHASE_SW) { return }
    $global:PHASE_SW.Stop()
    $secs = [Math]::Round($global:PHASE_SW.Elapsed.TotalSeconds, 1)
    $lbl  = $global:PHASE_TIMING_LBL
    $global:PHASE_TIMINGS.Add([pscustomobject]@{ Phase = $lbl; Seconds = $secs })
    # STEALTH mode keeps stdout JSON-only; record + log the timing but no console line.
    if (-not $global:STEALTH_MODE) {
        Write-Host ("  ⏱  {0} took {1}s" -f $lbl, $secs) -ForegroundColor DarkGray
    }
    Write-Log ("TIMING: {0} took {1}s" -f $lbl, $secs)
    $global:PHASE_SW = $null
    $global:PHASE_TIMING_LBL = ""
}

function Show-PhaseHeader {
    param([string]$Phase, [string]$Desc, [string]$Category = "")
    # Close out the previous phase's wall-clock before announcing the next one.
    Stop-PhaseTiming
    $global:PHASE_TIMING_LBL = "$Phase — $Desc"
    $global:PHASE_SW = [System.Diagnostics.Stopwatch]::StartNew()
    if ($global:STEALTH_MODE) { Write-Log "PHASE: $Phase | $Desc"; return }
    $catStr = if ($Category) { " · $Category" } else { "" }
    Write-Host ""; Write-Host "  ┌─[ " -NoNewline -ForegroundColor DarkRed
    Write-Host "$Phase$catStr" -NoNewline -ForegroundColor Red
    Write-Host " ]" -NoNewline -ForegroundColor DarkRed
    Write-Host ("─" * [Math]::Max(2, 62 - $Phase.Length - $catStr.Length)) -ForegroundColor DarkRed
    Write-Host "  │  " -NoNewline -ForegroundColor DarkRed; Write-Host $Desc -ForegroundColor Yellow
    if ($global:PARANOID_MODE) {
        Write-Host "  │  " -NoNewline -ForegroundColor DarkRed
        Write-Host "[PARANOID — POSSIBLE escalated to HIGH]" -ForegroundColor DarkMagenta
    }
    Write-Host "  └" -NoNewline -ForegroundColor DarkRed; Write-Host ("─" * 70) -ForegroundColor DarkRed
    Write-Log "PHASE: $Phase | $Desc"
    # ── Live GUI updates ──────────────────────────────────────────────────────
    $global:CURRENT_PHASE_NUM++
    if ($null -ne $global:GUI_PHASE_LBL -and -not $global:GUI_PHASE_LBL.IsDisposed) {
        $global:GUI_PHASE_LBL.Text = "  $Phase  ·  $Desc"
    }
    if ($null -ne $global:GUI_PROG_BAR -and -not $global:GUI_PROG_BAR.IsDisposed) {
        $pct = [Math]::Min(100, [Math]::Round(($global:CURRENT_PHASE_NUM / $global:TOTAL_PHASES) * 100))
        $global:GUI_PROG_BAR.Value = $pct
    }
    Invoke-GuiDoEvents
}

function Show-ThreatCategoryHeader {
    param([string]$Category, [string]$Description)
    if ($global:STEALTH_MODE) { Write-Log "=== THREAT MODULE: $Category ==="; return }
    Write-Host ""; Write-Host ("▓"*80) -ForegroundColor DarkRed
    Write-Host "  ▶▶▶  " -NoNewline -ForegroundColor Red; Write-Host $Category -NoNewline -ForegroundColor Yellow
    Write-Host "  DETECTION MODULE" -ForegroundColor Red
    Write-Host "  $Description" -ForegroundColor DarkGray
    Write-Host ("▓"*80) -ForegroundColor DarkRed; Write-Log "=== THREAT MODULE: $Category ==="
}

# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT FINDING REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════
function Add-Finding {
    param(
        [string]$ID,
        [string]$Phase,
        [string]$ThreatType,
        [string]$Severity,
        [string]$Description,
        [string]$Target,
        [string]$FixAction,
        [string]$FixParam = "",
        [string]$Group = ""
    )
    if ($global:PARANOID_MODE -and $Severity -eq "POSSIBLE") { $Severity = "HIGH" }
    foreach ($existing in $global:AuditFindings) { if ($existing.ID -eq $ID) { return } }
    # ── Flood guard: cap individual findings per group; roll the rest into one
    #    summary so a noisy phase can't push 20k+ finding events to the web UI. ─
    $grpKey = if ($Group) { $Group } else { $Phase }
    if ($ID -notmatch '^GROUPCAP_') {
        if ($null -eq $global:GROUP_COUNTS) { $global:GROUP_COUNTS = @{} }
        $gcap = if ($global:FINDING_GROUP_CAP) { $global:FINDING_GROUP_CAP } else { 100 }
        $gn = [int]$global:GROUP_COUNTS[$grpKey]; $global:GROUP_COUNTS[$grpKey] = $gn + 1
        if ($gn -ge $gcap) {
            if ($gn -eq $gcap) {
                Add-Finding -ID "GROUPCAP_$($grpKey -replace '[^a-zA-Z0-9]','')" -Phase $Phase `
                    -ThreatType $ThreatType -Severity "INFO" `
                    -Description "${grpKey}: capped at $gcap items to keep the scan responsive; additional matches suppressed. Narrow the time window or review this location manually." `
                    -Target $grpKey -FixAction "None" -FixParam "" -Group $grpKey
            }
            return
        }
    }
    $global:AuditFindings.Add(@{
        ID          = $ID
        Phase       = $Phase
        ThreatType  = $ThreatType
        Severity    = $Severity
        Description = $Description
        Target      = $Target
        FixAction   = $FixAction
        FixParam    = $FixParam
        Group       = if ($Group) { $Group } else { $Phase }
        Selected    = ($Severity -ne "INFO")
        Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    })
    $global:TotalAnomalies++
    # ── Structured finding stream (GUI runs) ─────────────────────────────────
    # Human-readable phase output carries no severity tags, so the web server
    # cannot classify findings from text. Emit one machine-readable JSON line per
    # registered finding; the server turns it into an exact-severity SSE `finding`
    # event. Runtime data only — no signature literals (AMSI-safe). STEALTH keeps
    # stdout to the single audit blob.
    if ($global:NONINTERACTIVE -and -not $global:STEALTH_MODE) {
        try {
            $fj = @{ id = $ID; sev = $Severity; phase = $Phase; tt = $ThreatType
                     desc = $Description; target = $Target; fix = $FixAction; group = $grpKey } |
                  ConvertTo-Json -Compress
            Write-Host "[FINDING] $fj"
        } catch {}
    }
    # ── Live tree update ──────────────────────────────────────────────────────
    if ($null -ne $global:GUI_LIVE_TREE -and -not $global:GUI_LIVE_TREE.IsDisposed) {
        $finding = $global:AuditFindings[$global:AuditFindings.Count - 1]
        $grpName = $finding.Group
        # Find or create group node
        $gNode = $null
        foreach ($n in $global:GUI_LIVE_TREE.Nodes) { if ($n.Name -eq $grpName) { $gNode = $n; break } }
        if ($null -eq $gNode) {
            $gNode = New-Object System.Windows.Forms.TreeNode
            $gNode.Name = $grpName; $gNode.Text = $grpName
            $gNode.ForeColor = [System.Drawing.Color]::FromArgb(100,180,255)
            $gNode.Checked = $true
            $global:GUI_LIVE_TREE.Nodes.Add($gNode) | Out-Null
        }
        # Add child node
        $cNode = New-Object System.Windows.Forms.TreeNode
        $pfx = switch ($Severity) { "CRITICAL" { "☣ CRIT  " } "HIGH" { "▲ HIGH  " } "POSSIBLE" { "? POSS  " } default { "  INFO  " } }
        $d = $Description; if ($d.Length -gt 85) { $d = $d.Substring(0,82) + "..." }
        $cNode.Text = "$pfx $d"
        $cNode.Checked = ($Severity -ne "INFO")
        $cNode.ForeColor = switch ($Severity) {
            "CRITICAL" { [System.Drawing.Color]::FromArgb(255,80,80)   }
            "HIGH"     { [System.Drawing.Color]::FromArgb(255,160,0)   }
            "POSSIBLE" { [System.Drawing.Color]::FromArgb(255,220,50)  }
            default    { [System.Drawing.Color]::FromArgb(130,130,130) }
        }
        $cNode.Tag = $finding
        $gNode.Nodes.Add($cNode) | Out-Null
        # Update group label color to worst severity
        $hasCrit = ($gNode.Nodes | Where-Object { $_.Tag -is [hashtable] -and ([hashtable]$_.Tag).Severity -eq "CRITICAL" }).Count -gt 0
        $hasHigh = ($gNode.Nodes | Where-Object { $_.Tag -is [hashtable] -and ([hashtable]$_.Tag).Severity -eq "HIGH" }).Count -gt 0
        $critN = ($gNode.Nodes | Where-Object { $_.Tag -is [hashtable] -and ([hashtable]$_.Tag).Severity -eq "CRITICAL" }).Count
        $highN = ($gNode.Nodes | Where-Object { $_.Tag -is [hashtable] -and ([hashtable]$_.Tag).Severity -eq "HIGH" }).Count
        $tag = if ($critN -gt 0) { "  [$critN CRITICAL]" } elseif ($highN -gt 0) { "  [$highN HIGH]" } else { "" }
        $gNode.Text = "$grpName$tag"
        $gNode.ForeColor = if ($hasCrit) { [System.Drawing.Color]::FromArgb(255,80,80) } `
                           elseif ($hasHigh) { [System.Drawing.Color]::FromArgb(255,160,0) } `
                           else { [System.Drawing.Color]::FromArgb(100,180,255) }
        $gNode.Expand()
        # Update risk header label
        if ($null -ne $global:GUI_RISK_LBL -and -not $global:GUI_RISK_LBL.IsDisposed) {
            $cC = ($global:AuditFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
            $hC = ($global:AuditFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
            $pC = ($global:AuditFindings | Where-Object { $_.Severity -eq "POSSIBLE" }).Count
            $global:GUI_RISK_LBL.Text = "  LIVE FINDINGS: $($global:AuditFindings.Count)  ·  ☣ CRITICAL: $cC  ▲ HIGH: $hC  ? POSSIBLE: $pC"
            $global:GUI_RISK_LBL.ForeColor = if ($cC -gt 0) { [System.Drawing.Color]::FromArgb(255,80,80) } `
                                             elseif ($hC -gt 0) { [System.Drawing.Color]::FromArgb(255,160,0) } `
                                             else { [System.Drawing.Color]::Yellow }
        }
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Start-ShellKillWatcher {
    # Writes a persistent note to console and polls for K keypress via non-blocking check
    # Uses a background job that sets a file flag, main thread polls it
    $flagFile = Join-Path $env:TEMP "ZeroBreach_KillFlag_$(Get-Date -Format 'yyyyMMddHHmmss').tmp"
    $global:SHELL_KILL_FLAG = $flagFile
    $job = Start-Job -ScriptBlock {
        param($flag)
        while ($true) {
            if ([System.Console]::KeyAvailable) {
                $k = [System.Console]::ReadKey($true)
                if ($k.KeyChar -eq 'k' -or $k.KeyChar -eq 'K') {
                    [System.IO.File]::WriteAllText($flag, "kill")
                    break
                }
            }
            Start-Sleep -Milliseconds 150
        }
    } -ArgumentList $flagFile
    Write-Host "  [SHELL] Press " -NoNewline -ForegroundColor DarkGray
    Write-Host "K" -NoNewline -ForegroundColor Yellow
    Write-Host " at any time to toggle fast mode (kill slow output)." -ForegroundColor DarkGray
    return $job
}

function Test-ShellKillFlag {
    if ($global:SHELL_KILL_FLAG -and (Test-Path $global:SHELL_KILL_FLAG)) {
        if (-not $global:SKIP_SLOW_OUTPUT) {
            $global:SKIP_SLOW_OUTPUT = $true
            Write-Host ""
            Write-Host "  [K] FAST MODE ENGAGED — SLOW OUTPUT KILLED." -ForegroundColor Yellow
        }
        Remove-Item $global:SHELL_KILL_FLAG -Force -ErrorAction SilentlyContinue
        # Restart watcher for toggling back on
        $global:SHELL_KILL_JOB = Start-ShellKillWatcher
    }
}
function Stop-PhaseTimer  { param([hashtable]$T); $global:PhaseTimings.Add(@{ Phase=$T.Phase; Seconds=[Math]::Round(((Get-Date)-$T.Start).TotalSeconds,2) }) }

# ══════════════════════════════════════════════════════════════════════════════
#  REMEDIATION ENGINE — REMOVED 2026-07-22
#  Invoke-VerifiedAnnihilation / Invoke-VerifiedRegScrub / Invoke-SectorScan /
#  Invoke-RegSectorScan / Reset-FilePermissions were dead code with zero call sites
#  anywhere in the repo (the real remediation switch lives in engine\FixMode.ps1's
#  Invoke-FixMode and its mirror in ZeroBreach-Server.ps1's $script:REMEDIATE_SCRIPT).
#  Reset-FilePermissions ran an unscoped `icacls /reset /T` on a caller-supplied path —
#  exactly the whole-drive catastrophe FP round 5 removed from Phase 108. Per user rule
#  #1, a destructive lever that exists can eventually be wired up by mistake; deleted.
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════
# Anchored user-writable-path tests (2026-07-22 review, findings #4/#5/#6/#7).
# CLAUDE.md hard rule: anchor folder-name tests to path COMPONENTS, never bare
# substrings. A bare "AppData|Temp" also matches Store package names (the historical
# WhatsAppDesktop auto-kill), vendor folders like "Temperature Monitor"/"Templates",
# and "C:\Program Files\Tempest\...". Several call sites gate an AUTO-SELECTED
# KillProcess / service-delete / task-unregister on this test, so an unanchored match
# there is a rule-#1 violation, not just noise. WindowsApps is a signed Store root —
# it lives under Program Files but holds user-installed apps, so exclude it explicitly.
$global:USER_PATH_RE       = '\\(AppData|Temp)\\'
$global:USER_PATH_WIDE_RE  = '\\(AppData|Temp|Downloads|Desktop)\\'
$global:WINDOWSAPPS_RE     = '\\Program Files( \(x86\))?\\WindowsApps\\'

# Stable short ID for finding keys derived from free text (paths, DNS names, ACL identities).
# [string]::GetHashCode() is randomised PER PROCESS on .NET Core / .NET 5+ (i.e. under pwsh 7),
# so any finding ID built from it changes on every run and the -Baseline diff reports the same
# finding as "new" forever. FNV-1a over UTF-8 is deterministic across processes AND runtimes.
# uint64 accumulator + explicit 32-bit mask: PS 5.1 throws on [uint32] multiply overflow.
function Get-StableId {
    param([string]$Text)
    $h = [uint64]2166136261
    foreach ($b in [Text.Encoding]::UTF8.GetBytes("$Text")) {
        $h = ($h -bxor [uint64]$b)
        # 4294967295 written in decimal on purpose: PowerShell parses the literal 0xFFFFFFFF
        # as [int] -1 (32-bit signed overflow), and [uint64](-1) then throws.
        $h = ($h * [uint64]16777619) -band [uint64]4294967295
    }
    return ('{0:x8}' -f $h)
}

function Test-InScope {
    param($ItemTime)
    if ($null -eq $ItemTime) { return $true }
    try {
        $dt = [datetime]$ItemTime
        if ($global:TIME_LIMIT -eq [datetime]::MinValue) { return $true }
        return ($dt -ge $global:TIME_LIMIT)
    } catch { return $true }
}

function Get-FileEntropy {
    param([string]$FilePath, [int]$SampleBytes = 1048576)   # cap the read at 1 MB — entropy of the
    try {                                                     # leading sample is representative for
        $fs = [System.IO.File]::OpenRead($FilePath)           # packed/encrypted detection and avoids
        try {                                                 # reading huge files fully into memory.
            $len = [int][Math]::Min($fs.Length, [long]$SampleBytes)
            if ($len -lt 256) { return 0.0 }
            $bytes = New-Object byte[] $len
            $read = 0; while ($read -lt $len) { $n = $fs.Read($bytes, $read, $len - $read); if ($n -le 0) { break }; $read += $n }
            if ($read -lt 256) { return 0.0 }
        } finally { $fs.Dispose() }
        $freq = @{}
        for ($i = 0; $i -lt $read; $i++) { $b = $bytes[$i]; $freq[$b] = if ($freq.ContainsKey($b)) { $freq[$b]+1 } else { 1 } }
        $entropy = 0.0
        foreach ($count in $freq.Values) { $p = $count/$read; $entropy -= $p*[Math]::Log($p,2) }
        return [Math]::Round($entropy,4)
    } catch { return 0.0 }
}

# Content-signature matcher (AMSI-safe — rules live in data\detection_signatures.json).
# Reads a small text-ish file and returns the highest-severity matching rule, or Hit=$false.
function Test-ContentRules {
    param([string]$FilePath, $Rules, [int]$MaxBytes = 5242880)
    if (-not $Rules -or @($Rules).Count -eq 0) { return @{ Hit = $false } }
    try {
        $fi = Get-Item -LiteralPath $FilePath -ErrorAction Stop
        if ($fi.Length -eq 0 -or $fi.Length -gt $MaxBytes) { return @{ Hit = $false } }
        $text = [System.IO.File]::ReadAllText($FilePath)
    } catch { return @{ Hit = $false } }
    $rank = @{ "CRITICAL" = 3; "HIGH" = 2; "POSSIBLE" = 1 }
    $best = $null
    foreach ($r in $Rules) {
        try {
            if ($text -match $r.Pattern) {
                if ($null -eq $best -or [int]$rank[$r.Severity] -gt [int]$rank[$best.Severity]) {
                    $best = @{ Hit = $true; Name = $r.Name; Severity = $r.Severity }
                }
            }
        } catch {}
    }
    if ($best) { return $best } else { return @{ Hit = $false } }
}

# ── Bounded recursive file enumeration (PERFORMANCE) ─────────────────────────
# Whole-profile / AppData walks were the #1 cause of phases hanging the web UI:
# Get-ChildItem -Recurse over $env:USERPROFILE drags in browser caches, Teams,
# OneDrive, node_modules etc. — often hundreds of thousands of files. Get-ScanFiles
# does a manual, prunable walk that (a) caps total files, (b) enforces a wall-clock
# deadline so no single phase can run away, (c) prunes known giant low-signal cache
# dirs, (d) skips reparse points (junction loops) and OneDrive cloud-only placeholder
# files (reading those would trigger a download storm). Returns FileInfo[] so callers
# keep using .FullName/.Name/.Extension/.Length/.LastWriteTime/.DirectoryName.
$global:SCAN_MAX_FILES   = 20000   # hard cap on files examined per call
$global:SCAN_DEADLINE_S  = 20      # wall-clock budget (seconds) per call
# Per-scan enumeration memo (WS4): many phases re-walk identical root sets
# (e.g. dump/stego both walk TEMP+LOCALAPPDATA+USERPROFILE; the Phases-3 foreach-$root
# loops re-walk trees Phases-1/2 already walked). The engine is audit-only in -Auto so the
# filesystem is static for a run, and it spawns fresh per scan, so this script-scope memo is
# naturally scan-scoped. Keyed on the FULL param tuple → only byte-identical calls share a
# result; the cached array is never mutated by callers (they filter into new collections).
$global:SCAN_FILE_CACHE      = @{}
$global:SCAN_FILE_CACHE_HITS = 0
$global:SCAN_FILE_CACHE_ON   = -not $env:ZB_NOCACHE   # kill-switch: PRESENCE-based — any value (even "0") disables; unset = on
# Authenticode signature audits (Get-AuthSig) build the full cert chain, which by
# default does ONLINE revocation checks (CRL/OCSP). On a box where those servers are
# slow/unreachable each call blocks for the network timeout, and the blocking native
# call also makes Ctrl+C unresponsive. Loops over hundreds of signed binaries can run
# for an hour. Bound any such loop with this shared budget + file cap. (See Phase 98.)
$global:SIG_AUDIT_DEADLINE_S = 25  # wall-clock budget (seconds) for a per-file sig loop
$global:SIG_AUDIT_MAX_FILES  = 150 # hard cap on signed binaries verified per such loop
$global:SCAN_PRUNE_DIRS  = @(
    'node_modules','winsxs','$recycle.bin','system volume information','windows.old',
    'servicing','driverstore','assembly',
    'inetcache','cache','cache2','code cache','codecache','gpucache','service worker',
    'cachestorage','dawncache','blob_storage','indexeddb','media cache','crashpad',
    'minidump','cef','gpucache','shadercache','componentstore'
)
function Get-ScanFiles {
    param(
        [string[]]$Path,
        [string]$Filter = '*',
        [switch]$TimeScoped,                                # apply Test-InScope during the walk
        [int]$MaxFiles      = $global:SCAN_MAX_FILES,
        [int]$DeadlineSecs  = $global:SCAN_DEADLINE_S,
        [string[]]$PruneDirs = $global:SCAN_PRUNE_DIRS
    )
    # Per-scan memo: only byte-identical (roots, filter, timescope, caps, prune) calls share.
    # Roots keep CALLER ORDER in the key (no sort): under the MaxFiles/deadline truncation the
    # walk order decides WHICH files make the cut, so same-set-different-order calls must not
    # alias. (All current multi-root aliases pass identical order — this guards future sites.)
    $ck = ((@($Path) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() }) -join '|') +
          "|F=$Filter|T=$([bool]$TimeScoped)|M=$MaxFiles|D=$DeadlineSecs|P=" +
          ((@($PruneDirs) | Sort-Object) -join ',')
    if ($global:SCAN_FILE_CACHE_ON -and $global:SCAN_FILE_CACHE.ContainsKey($ck)) { $global:SCAN_FILE_CACHE_HITS++; return ,$global:SCAN_FILE_CACHE[$ck] }
    $results  = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $deadline = [datetime]::UtcNow.AddSeconds($DeadlineSecs)
    $prune    = @{}; foreach ($d in $PruneDirs) { $prune[$d.ToLower()] = $true }
    foreach ($root in $Path) {
        if (-not $root) { continue }
        try { if (-not (Test-Path -LiteralPath $root)) { continue } } catch { continue }
        $stack = New-Object System.Collections.Generic.Stack[string]
        try { $stack.Push((Convert-Path -LiteralPath $root)) } catch { continue }
        while ($stack.Count -gt 0) {
            if ([datetime]::UtcNow -ge $deadline -or $results.Count -ge $MaxFiles) {
                $arr = $results.ToArray()
                # Cache only DETERMINISTIC truncations: a MaxFiles cap cuts at the same file every
                # time on a static tree, but a deadline hit is load-dependent — caching it would
                # poison every later identical call with a partial set a fresh budgeted walk may beat.
                if ($global:SCAN_FILE_CACHE_ON -and $results.Count -ge $MaxFiles) { $global:SCAN_FILE_CACHE[$ck] = $arr }
                return ,$arr
            }
            $dir = $stack.Pop()
            try {
                foreach ($f in [System.IO.Directory]::EnumerateFiles($dir, $Filter)) {
                    if ($results.Count -ge $MaxFiles) { break }
                    try {
                        $fi   = New-Object System.IO.FileInfo $f
                        $attr = [int]$fi.Attributes
                        if ($attr -band 0x1000)   { continue }   # Offline (cloud-only)
                        if ($attr -band 0x400000) { continue }   # RecallOnDataAccess (OneDrive placeholder)
                        if ($TimeScoped -and -not (Test-InScope $fi.LastWriteTime)) { continue }
                        $results.Add($fi)
                    } catch {}
                }
            } catch {}
            try {
                foreach ($sd in [System.IO.Directory]::EnumerateDirectories($dir)) {
                    $leaf = [System.IO.Path]::GetFileName($sd).ToLower()
                    if ($prune.ContainsKey($leaf)) { continue }
                    try {
                        $di = New-Object System.IO.DirectoryInfo $sd
                        if ([int]$di.Attributes -band [int][IO.FileAttributes]::ReparsePoint) { continue }
                    } catch {}
                    $stack.Push($sd)
                }
            } catch {}
        }
    }
    $arr = $results.ToArray()
    if ($global:SCAN_FILE_CACHE_ON) { $global:SCAN_FILE_CACHE[$ck] = $arr }   # ZB_NOCACHE runs stay truly cache-free
    return ,$arr
}

# Per-scan Win32_Process snapshot memo (WS4): 7 phases each ran their own full
# Win32_Process WMI enumeration. Unlike the filesystem (static in audit mode) the process
# table DOES change during a run, so entries expire after PROC_SNAP_TTL_S: adjacent phase
# clusters (3+4; 99+99.5+102) share one enumeration, while phases minutes apart still see
# fresh data. Shares the ZB_NOCACHE kill-switch via SCAN_FILE_CACHE_ON. Same `return ,$arr`
# single-item pipe trap as Get-ScanFiles — callers must wrap in parens: `(Get-ProcSnapshot) |
# Where-Object …`, never `Get-ProcSnapshot | …`. Phase 56 (WMI-vs-Get-Process rootkit delta)
# deliberately does NOT use this: its two enumerations must be captured at the same instant,
# or a snapshot even seconds stale fabricates CRITICAL rootkit discrepancy findings.
$global:PROC_SNAP_CACHE = $null
$global:PROC_SNAP_AT    = [datetime]::MinValue
$global:PROC_SNAP_TTL_S = 90
$global:PROC_SNAP_HITS  = 0
function Get-ProcSnapshot {
    if ($global:SCAN_FILE_CACHE_ON -and $null -ne $global:PROC_SNAP_CACHE -and
        ([datetime]::UtcNow - $global:PROC_SNAP_AT).TotalSeconds -lt $global:PROC_SNAP_TTL_S) {
        $global:PROC_SNAP_HITS++
        return ,$global:PROC_SNAP_CACHE
    }
    $snap = @(Get-WmiObject Win32_Process -ErrorAction SilentlyContinue)
    if ($global:SCAN_FILE_CACHE_ON) { $global:PROC_SNAP_CACHE = $snap; $global:PROC_SNAP_AT = [datetime]::UtcNow }
    return ,$snap
}

function Get-ExtensionRisk {
    param([string]$ExtPath)
    # Returns: CRITICAL, HIGH, POSSIBLE, or CLEAN
    $manifestFile = Get-ChildItem -Path "$ExtPath\*\manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $manifestFile) {
        $manifestFile = Get-ChildItem -Path "$ExtPath\manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $manifestFile) { return @{Risk="POSSIBLE"; Name="Unknown Extension"; Reason="No manifest found"} }
    try {
        $mData = Get-Content $manifestFile.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        $name = if ($mData.name) { $mData.name } else { "Unknown" }
        $perms = ($mData.permissions -join " ").ToLower()
        # CRITICAL: known malicious extension names or permissions.
        # Name list is DATA ($BROWSER_EXT_ADWARE, data\detection_signatures.json) — an inline
        # literal list of adware vendor names is exactly the AMSI liability WS1 externalized.
        foreach ($bad in $BROWSER_EXT_ADWARE) {
            if ($name.ToLower() -match [regex]::Escape($bad)) {
                return @{Risk="CRITICAL"; Name=$name; Reason="Known adware/hijacker: $bad"}
            }
        }
        # HIGH: dangerous permission combos
        $dangerPerms = @("nativeMessaging","debugger","proxy","webRequest.*webRequestBlocking","clipboardRead.*all_urls","tabs.*cookies.*all_urls")
        foreach ($dp in $dangerPerms) {
            if ($perms -match $dp) {
                return @{Risk="HIGH"; Name=$name; Reason="Dangerous permission: $dp"}
            }
        }
        # POSSIBLE: broad permissions
        if ($perms -match "<all_urls>|webRequestBlocking|nativeMessaging") {
            return @{Risk="POSSIBLE"; Name=$name; Reason="Broad host/network access permissions"}
        }
        # POSSIBLE (WS7): a manifest update_url pointing away from the browser vendor's own
        # official update endpoint means the extension is (or was) side-loaded/distributed
        # outside the store's normal update channel. A self-hosted enterprise update server is
        # also legitimate, so this stays review-only — never escalated above POSSIBLE, never
        # auto-removed. $TRUSTED_EXT_UPDATE_RE is DATA (trusted_extension_update_hosts).
        if ($mData.update_url -and "$($mData.update_url)" -notmatch $TRUSTED_EXT_UPDATE_RE) {
            return @{Risk="POSSIBLE"; Name=$name; Reason="update_url points outside known browser-vendor update endpoints: $($mData.update_url)"}
        }
        return @{Risk="CLEAN"; Name=$name; Reason=""}
    } catch {
        return @{Risk="POSSIBLE"; Name="Parse Error"; Reason="Could not read manifest"}
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  IOC DATABASES (V21 — expanded)
# ══════════════════════════════════════════════════════════════════════════════
# Signatures live in data\detection_signatures.json so this script body holds no
# malware-signature literals (those would trip AMSI/Defender). Data files read via
# Get-Content|ConvertFrom-Json are NOT AMSI-scanned. Edit signatures there, not here.
$SigPath = Join-Path $PSScriptRoot 'data\detection_signatures.json'
if (Test-Path -LiteralPath $SigPath) {
    try   { $SIG = Get-Content -LiteralPath $SigPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { $SIG = $null; Write-Host "[ZeroBreach] WARNING: could not parse $SigPath ($($_.Exception.Message))" -ForegroundColor Red }
} else {
    $SIG = $null
    Write-Host "[ZeroBreach] WARNING: signature file missing: $SigPath - many detections disabled." -ForegroundColor Red
}
function Get-Sig([string]$Name) { if ($SIG -and $null -ne $SIG.$Name) { @($SIG.$Name) } else { @() } }
$KNOWN_MINER_PROCS      = Get-Sig 'known_miner_procs'
$KNOWN_RAT_PROCS        = Get-Sig 'known_rat_procs'
$KNOWN_C2_DOMAINS       = Get-Sig 'known_c2_domains'
$KNOWN_KEYLOGGER_PROCS  = Get-Sig 'known_keylogger_procs'
$RANSOMWARE_EXTENSIONS  = Get-Sig 'ransomware_extensions'
$STRATUM_PORTS          = Get-Sig 'stratum_ports'
$SUSPICIOUS_DNS_DOMAINS = Get-Sig 'suspicious_dns_domains'
$RAT_CONFIG_PATHS       = @((Get-Sig 'rat_config_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$RAT_REG_PATHS          = Get-Sig 'rat_reg_paths'
$TROJAN_FILE_PATTERNS   = Get-Sig 'trojan_file_patterns'
$UAC_BYPASS_REGS        = Get-Sig 'uac_bypass_regs'
$YARA_LITE_RULES        = Get-Sig 'yara_lite_rules'
$AUTO_ELEVATE_BINS      = Get-Sig 'auto_elevate_bins'
$LOLBAS_EXPANDED        = Get-Sig 'lolbas_expanded'
$SCRIPT_OWN_STRINGS     = Get-Sig 'script_own_strings'
$KNOWN_MALWARE_HASHES   = @((Get-Sig 'known_malware_hashes') | ForEach-Object { "$_".ToLower().Trim() })
$EMAIL_PHISHING_TROJANS = Get-Sig 'email_phishing_trojans'
$EMAIL_CONTENT_RULES    = Get-Sig 'email_content_rules'
$EMAIL_SCAN_PATHS       = @((Get-Sig 'email_scan_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$EMAIL_ATTACH_EXTS      = @((Get-Sig 'email_attach_extensions') | ForEach-Object { "$_".ToLower() })
$EMAIL_LURE_PATTERNS    = Get-Sig 'email_lure_filename_patterns'
$PROACTIVE_PERSIST_REGS = Get-Sig 'proactive_persistence_regs'
$PROACTIVE_OFFICE_KEYS  = Get-Sig 'proactive_office_keys'
$PROACTIVE_LURE_EXTS    = @((Get-Sig 'proactive_lure_extensions') | ForEach-Object { "$_".ToLower() })
# FP-suppression allowlists (benign-but-noisy patterns, not malware signatures). Joined into a
# single case-insensitive alternation regex each; empty -> "(?!)" (matches nothing) so an absent
# key never suppresses anything. See "fp_allowlists" in data/detection_signatures.json.
function Join-AllowRegex([string]$Name) { $a = @(Get-Sig $Name); if ($a.Count) { ($a -join '|') } else { '(?!)' } }
$TRUSTED_ROOT_CA_RE     = Join-AllowRegex 'trusted_root_ca_issuers'
$BEACON_BENIGN_DOM_RE   = Join-AllowRegex 'beacon_benign_domain_suffixes'   # Phase 59 (anchored suffixes)
$CLOAKED_BENIGN_RE      = Join-AllowRegex 'cloaked_benign_names'
$INFOSTEALER_BENIGN_RE  = Join-AllowRegex 'infostealer_benign_paths'
$SAFEBOOT_DEFAULTS      = @((Get-Sig 'safeboot_default_entries') | ForEach-Object { "$_".ToLower() })
$C2_NAMED_PIPE_RE       = if (@(Get-Sig 'c2_named_pipe_regex').Count) { @(Get-Sig 'c2_named_pipe_regex')[0] } else { '(?!)' }
$HIDDEN_TASK_BENIGN_RE  = Join-AllowRegex 'hidden_task_benign_paths'
$RUNKEY_BENIGN_RE       = Join-AllowRegex 'runkey_benign_values'     # Phase 20 (OneDrive/OS cleanup RunOnce)
$KEYLOG_BENIGN_RE       = Join-AllowRegex 'keylogger_benign_paths'   # Phase 48 (py.typed-class library files)
$YARA_BENIGN_RE         = Join-AllowRegex 'yara_benign_paths'        # Phase 90 (JIT/renderer runtime DLLs)
$SCT_BENIGN_RE          = Join-AllowRegex 'sct_benign_paths'         # Phase 94 (library test scriptlets)
$MINERCFG_BENIGN_RE     = Join-AllowRegex 'miner_config_benign_paths' # Phase 63 (LGHUB-class app configs)
# Allowlist VETO (2026-07-22 review #26). The package-manager-tree allowlists above key on
# folder names ("node_modules", "site-packages") that an attacker can simply create, letting a
# dropper self-allowlist out of an auto-selectable finding. Real dev trees do not live in the
# download/handoff staging dirs, so a benign-path match found THERE is ignored. pip genuinely
# builds under %TEMP%\pip-*, so those are carved back out rather than flooding a dev box.
$global:ALLOW_VETO_RE   = '\\(Downloads|Public)\\|\\Temp\\(?!pip-|pip_|build\\)'
# Apply an allowlist honestly: benign-path match AND not sitting in a staging dir.
function Test-BenignPath {
    param([string]$Path, [string]$AllowRegex)
    if (-not $Path) { return $false }
    if ($Path -notmatch $AllowRegex) { return $false }
    return ($Path -notmatch $global:ALLOW_VETO_RE)
}
$SPOOLDLL_BENIGN_RE     = Join-AllowRegex 'spooler_benign_dlls'      # Phase 96 (catalog-signed MS printer resources)
$BITS_SUSP_REMOTE_RE    = if (@(Get-Sig 'bits_suspicious_remote_regex').Count) { @(Get-Sig 'bits_suspicious_remote_regex')[0] } else { '(?!)' }
$BITS_SUSP_LOCAL_RE     = if (@(Get-Sig 'bits_suspicious_local_regex').Count) { @(Get-Sig 'bits_suspicious_local_regex')[0] } else { '(?!)' }

# WS2 detection-coverage expansion (2026-07-01) — all externalized data, AMSI-safe.
# Consumed by: Phase 55.5 (BYOVD), Phase 53 (ransom-note names/content), Phase 62
# (anchored C2/banking pipe second pass), Phase 69 (mutex probe), Phase 99.5 (cmdline
# heuristics). Every one of these detections uses FixAction Info/Quarantine only — none
# is auto-destructive on a healthy box (see CLAUDE.md rule #1).
$BYOVD_DRIVER_NAMES        = @((Get-Sig 'byovd_driver_names') | ForEach-Object { "$_".ToLower() })  # Phase 55.5
$BYOVD_DRIVER_SHA256       = Get-Sig 'byovd_driver_sha256'          # Phase 55.5 (SHA256 confirm)
$RANSOM_NOTE_FILENAMES     = Get-Sig 'ransom_note_filenames'        # Phase 53 (known-family note names)
$RANSOM_NOTE_CONTENT_RULES = Get-Sig 'ransom_note_content_rules'    # Phase 53 (renamed-note content)
$BANKING_NAMED_PIPES       = Get-Sig 'banking_named_pipes'          # Phase 62 (TrickBot-class pipe)
$C2_PIPE_REGEX_ANCHORED    = Get-Sig 'c2_pipe_regex_anchored'       # Phase 62 (anchored framework pipes)
$KNOWN_MALWARE_MUTEXES     = Get-Sig 'known_malware_mutexes'        # Phase 69 (single-instance mutexes)
$LOADER_BEHAVIOR_RULES     = Get-Sig 'loader_behavior_rules'        # Phase 99.5
$BANKING_BEHAVIOR_RULES    = Get-Sig 'banking_behavior_rules'       # Phase 99.5
$INFOSTEALER_BEHAVIOR_RULES= Get-Sig 'infostealer_behavior_rules'  # Phase 99.5
$INHIBIT_RECOVERY_RULES    = Get-Sig 'inhibit_recovery_rules'       # Phase 99.5
$ALL_MALWARE_CMDLINE_RULES = @($LOADER_BEHAVIOR_RULES + $BANKING_BEHAVIOR_RULES + $INFOSTEALER_BEHAVIOR_RULES + $INHIBIT_RECOVERY_RULES)

# WS0 orphan-key wiring (2026-07-02) — the WS1/WS2 keys below were merged into
# data/detection_signatures.json but never consumed (BLUEPRINT §7 item 7). Wired here;
# every NEW file/pipe/path/domain check they drive is FixAction Info (CLAUDE.md rule #1);
# the Phase 6 process-IOC additions mirror that phase's existing KillProcess posture
# (unambiguous malware family names only). The P67/68/82/89/98/106 keys replace inline
# literals 1:1 (AMSI-liability removal, same behavior).
$ADWARE_PUP_REGS           = Get-Sig 'adware_pup_regs'               # Phase 67 (was inline)
$INFOSTEALER_PROCS         = Get-Sig 'infostealer_procs'             # Phase 68 (was inline, +14 families)
$TUNNELING_TOOLS           = Get-Sig 'tunneling_tools'               # Phase 82 (was inline)
$TUNNELING_TOOLS_DUALUSE   = Get-Sig 'tunneling_tools_dualuse'       # Phase 82 dual-use subset -> POSSIBLE (user sign-off 2026-07-04)
$STEGO_TOOLS               = Get-Sig 'stego_tools'                   # Phase 89 (was inline)
$LEAKED_CERT_ISSUERS       = Get-Sig 'leaked_cert_issuers'           # Phase 98 (was inline)
$CRED_DUMP_TOOLS           = Get-Sig 'cred_dump_tools'               # Phase 106 (was inline)
$KEYLOGGER_REG_PATHS       = Get-Sig 'keylogger_reg_paths'           # Phase 48 (was inline — WS5)
$KEYLOGGER_FILE_PATTERNS   = Get-Sig 'keylogger_file_patterns'       # Phase 48 (was inline — WS5)
$BROWSER_EXT_ADWARE        = @((Get-Sig 'browser_ext_adware_names') | ForEach-Object { "$_".ToLower() })  # Get-ExtensionRisk (was inline — WS5)

# ── WS6 (2026-07-22) detection expansion — consumed by the new fractional phases ──
# Credential/identity theft, modern intrusion TTPs, persistence+evasion depth. All DATA.
$COM_TYPELIB_ROOTS         = Get-Sig 'com_typelib_hijack_roots'          # Phase 21.5
$IFEO_REG_ROOTS            = Get-Sig 'ifeo_reg_roots'                    # Phase 21.5
$SECURITY_TOOL_PROCS       = @((Get-Sig 'security_tool_process_names') | ForEach-Object { "$_".ToLower() })  # Phase 21.5
$INJECTION_DLL_POINTS      = Get-Sig 'injection_dll_reg_points'          # Phase 22.5
$NETSH_HELPER_ROOT         = @(Get-Sig 'netsh_helper_reg_root')[0]       # Phase 22.5
$CRED_DUMP_ARTIFACTS       = Get-Sig 'credential_dump_artifacts'         # Phase 44.5
$DPAPI_THEFT_PATHS         = @((Get-Sig 'dpapi_theft_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })  # Phase 44.5
$CRED_THEFT_CMD_RULES      = Get-Sig 'cred_theft_cmdline_rules'          # Phase 44.5
$RDP_HARDENING_CHECKS      = Get-Sig 'rdp_hardening_checks'              # Phase 45.5
$HIDDEN_ACCOUNT_REG        = @(Get-Sig 'hidden_account_reg_path')[0]     # Phase 42.5
$SUSPICIOUS_ACCOUNT_RE     = Join-AllowRegex 'suspicious_account_name_patterns'  # Phase 42.5
$RUNMRU_REG_PATH           = @(Get-Sig 'runmru_reg_path')[0]             # Phase 68.5
$CLIPBOARD_LURE_RULES      = Get-Sig 'clipboard_lure_rules'              # Phase 68.5
$RMM_TOOL_BINARIES         = @((Get-Sig 'rmm_tool_binaries') | ForEach-Object { "$_".ToLower() })           # Phase 82.5
$RMM_SUSPICIOUS_PATH_RE    = @(Get-Sig 'rmm_suspicious_path_regex')[0]   # Phase 82.5
$CLOUD_TOKEN_PATHS         = @((Get-Sig 'cloud_token_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })  # Phase 100.5
$TOKEN_STAGING_PATTERNS    = Get-Sig 'token_staging_name_patterns'       # Phase 100.5
$TIMESTOMP_EXTENSIONS      = @((Get-Sig 'timestomp_extensions') | ForEach-Object { "$_".ToLower() })        # Phase 17.5
$WS6_HARDENING_ACTIONS     = Get-Sig 'ws6_hardening_actions'             # Phase 45.5 (operator-only hardening set)
$LOADER_PROCS              = Get-Sig 'loader_procs'                  # Phase 6 (loader/botnet proc IOC)
$BANKING_TROJAN_PROCS      = Get-Sig 'banking_trojan_procs'          # Phase 6 (banking-trojan proc IOC)
$C2_PIPE_PATTERNS          = Get-Sig 'c2_pipe_patterns'              # Phase 62 (framework-name pipe pass)
$C2_CONFIG_RULES           = Get-Sig 'c2_config_rules'               # Phase 68 (C2 artifact filename rules)
$LOADER_DROP_PATH_RULES    = Get-Sig 'loader_drop_path_rules'        # Phase 68 (family drop-path rules)
$BYOVD_CERT_TBS_HASHES     = Get-Sig 'byovd_cert_tbs_hashes'         # Phase 55.5 (cert-TBS confirm)
$INFOSTEALER_TARGET_PATHS  = @((Get-Sig 'infostealer_target_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })  # Phase 100

# ── WS7 (2026-07-25) detection expansion — DLL side-loading, .lnk downloader payloads,
# extension update_url, clipboard clipper, cloud IMDS theft, npm/pip postinstall exfil.
# All DATA. Every detection here is POSSIBLE/HIGH + FixAction Info unless a literal-name-only
# match justifies more (see each phase body for the exact gating — CLAUDE.md rule #1).
$SIDELOAD_TARGET_DLLS      = @((Get-Sig 'sideload_target_dll_names') | ForEach-Object { "$_".ToLower() })       # Phase 32.5
$SIDELOAD_TARGET_EXES      = @((Get-Sig 'commonly_sideloaded_exe_names') | ForEach-Object { "$_".ToLower() })   # Phase 32.5
$TRUSTED_EXT_UPDATE_RE     = Join-AllowRegex 'trusted_extension_update_hosts'                                   # Phase 8 (Get-ExtensionRisk)
$CLIPPER_CLIPBOARD_API_RULES = Get-Sig 'clipper_clipboard_api_regex'   # Phase 49.5
$CLIPPER_CRYPTO_ADDR_RULES   = Get-Sig 'clipper_crypto_address_regex' # Phase 49.5
$CLOUD_AGENT_ALLOW_NAMES   = @((Get-Sig 'cloud_agent_allowlist_names') | ForEach-Object { "$_".ToLower() })     # Phase 36.5
$CLOUD_AGENT_ALLOW_PATH_RE = if (@(Get-Sig 'cloud_agent_allowlist_path_regex').Count) { @(Get-Sig 'cloud_agent_allowlist_path_regex')[0] } else { '(?!)' }  # Phase 36.5
$NPM_POSTINSTALL_TRUSTED_RE = Join-AllowRegex 'npm_postinstall_trusted_hosts'                                   # Phase 10.6

# ── WS8 (2026-07-25) detection expansion — GPP cached-password (cpassword) decrypt, Kerberoasting
# / AS-REP roasting event triage, Outlook forward+hide (BEC) rule audit, SSH authorized_keys
# backdoor audit, Office add-in sideload. All DATA. The GPP regex + AES key below are exactly what
# every GPP-password-harvesting tool (PowerSploit Get-GPPPassword, CrackMapExec gpp_autologin)
# embeds inline — precisely the AMSI trip-wire CLAUDE.md rule #1 exists to keep out of the .ps1.
$GPP_CPASSWORD_RE       = if (@(Get-Sig 'gpp_cpassword_regex').Count) { @(Get-Sig 'gpp_cpassword_regex')[0] } else { '(?!)' }  # Phase 87.5
$GPP_PREF_XML_NAMES     = Get-Sig 'gpp_preference_xml_names'        # Phase 87.5
$GPP_AES_KEY_BYTES      = [byte[]]@((Get-Sig 'gpp_cpassword_aes_key_bytes') | ForEach-Object { [byte]$_ })  # Phase 87.5 (MS-GPPREF published key)

# ── WS9 (2026-07-26) detection expansion — PsExec/PAExec/RemCom literal service-name match
# (Phase 107 7045 extension), WSL Linux-side cron/dotfile persistence staging (Phase 101
# extension), MSIX/App Installer sideloading abuse (Phase 97.5, new), Chrome/Edge
# App-Bound-Encryption-bypass cookie-theft tooling (Phase 100.5 extension), Pass-the-Hash /
# NewCredentials logon triage (Phase 107 4624 extension), ComHandler scheduled-task trigger
# cross-correlated with COM hijack (Phase 104 extension + Phase 105 correlation). All DATA.
$LATERAL_MOVEMENT_SVC_NAMES = @((Get-Sig 'lateral_movement_service_names') | ForEach-Object { "$_".ToLower() })  # Phase 107 (7045)
$WSL_DEV_BENIGN_RE          = Join-AllowRegex 'wsl_dev_benign_commands'   # Phase 101 (cron/dotfile FP suppression)
$ABE_BYPASS_TOOL_NAMES      = @((Get-Sig 'abe_bypass_tool_names') | ForEach-Object { "$_".ToLower() })            # Phase 100.5

# TWO C2 domain sets — kept separate ON PURPOSE (rule #1):
#  * $MALWARE_C2_DOMAINS = point-in-time loader/infostealer C2 (scifimond.com, polse.us …) —
#    odd unique strings, ~zero FP surface, SAFE for the Phase 34 DNS-cache HIGH+RunCmd path.
#  * $ALL_C2_DOMAINS = the above PLUS $KNOWN_C2_DOMAINS, which is deliberately broad LOLBin /
#    tunneling infra (raw.githubusercontent.com, ngrok, tailscale, trycloudflare, nip.io …).
#    A healthy dev box resolves those constantly, so this set is used ONLY by Phase 36's
#    reverse-DNS-of-an-ACTIVE-connection check (a live socket to that infra is a real signal;
#    a stale DNS-cache entry is not). Never feed $ALL_C2_DOMAINS into a DNS-cache/auto-fire path.
$MALWARE_C2_DOMAINS        = @(@(Get-Sig 'loader_c2_domains') + @(Get-Sig 'infostealer_c2_domains'))  # Phase 34 (safe HIGH)
$ALL_C2_DOMAINS            = @(@($KNOWN_C2_DOMAINS) + @($MALWARE_C2_DOMAINS))                          # Phase 36 (reverse-DNS only)

# SHA1 of a certificate's TBS (to-be-signed) DER block — matches LOLDrivers TBS hashes,
# which stay stable across polymorphic driver variants where the file SHA256 changes.
# Minimal DER walk: outer SEQUENCE header, then the first child element IS the TBS
# (tag+length+content). Returns $null on any parse/IO oddity — callers treat that as
# "no confirmation", never as a finding.
function Get-CertTbsSha1([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    try {
        $raw = $Cert.RawData
        # Skip the outer SEQUENCE tag+length to land on the TBS element.
        $i = 1
        $b = $raw[$i]
        if ($b -band 0x80) { $i += 1 + ($b -band 0x7F) } else { $i += 1 }
        # TBS element: tag at $i, then its own length field, then content.
        $j = $i + 1
        $lb = $raw[$j]
        if ($lb -band 0x80) {
            $n = $lb -band 0x7F; $len = 0
            for ($k = 1; $k -le $n; $k++) { $len = ($len * 256) + $raw[$j + $k] }
            $hdr = 2 + $n
        } else { $len = $lb; $hdr = 2 }
        # Sanity-bound the length: a malformed/hostile cert could encode a multi-GB $len, and
        # New-Object byte[] would attempt a giant alloc (OutOfMemoryException is not reliably
        # caught by try/catch in PS 5.1). The TBS can never exceed the cert's own DER length.
        if ($len -lt 0 -or ($i + $hdr + $len) -gt $raw.Length) { return $null }
        $tbs = New-Object byte[] ($hdr + $len)
        [Array]::Copy($raw, $i, $tbs, 0, $tbs.Length)
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        try { (($sha1.ComputeHash($tbs) | ForEach-Object { $_.ToString('X2') }) -join '') } finally { $sha1.Dispose() }
    } catch { $null }
}

# ══════════════════════════════════════════════════════════════════════════════
#  PERMISSION / INTEGRITY BASELINE (V23 — externalized, AMSI-safe)
#  Drives phases 108-115 (FORENSIC PERMISSION & INTEGRITY AUDIT). Path/key/owner
#  data only — no malware signatures — so it stays out of the script body.
# ══════════════════════════════════════════════════════════════════════════════
$PermPath = Join-Path $PSScriptRoot 'data\permission_baseline.json'
if (Test-Path -LiteralPath $PermPath) {
    try   { $PERM = Get-Content -LiteralPath $PermPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { $PERM = $null; Write-Host "[ZeroBreach] WARNING: could not parse $PermPath ($($_.Exception.Message))" -ForegroundColor Red }
} else {
    $PERM = $null
    Write-Host "[ZeroBreach] WARNING: permission baseline missing: $PermPath - permission/integrity phases limited." -ForegroundColor Yellow
}
function Get-Perm([string]$Name) { if ($PERM -and $null -ne $PERM.$Name) { @($PERM.$Name) } else { @() } }

# Expand %WINDIR% / %ProgramFiles% / %SystemDrive% style tokens to real paths.
function Expand-EnvPath { param([string]$P)
    if (-not $P) { return $P }
    [System.Environment]::ExpandEnvironmentVariables($P)
}

# Return any ACL access rules that grant write-class rights to a weak identity.
# Works for both filesystem and registry ACLs (both expose .Access with
# IdentityReference / AccessControlType / *Rights). $WeakIds = substrings to flag.
function Get-WeakAces { param($Acl, [string[]]$WeakIds, [string]$RightsRegex = 'Write|Modify|FullControl|ChangePermissions|TakeOwnership|CreateFiles|AppendData|SetValue|CreateSubKey|WriteKey')
    if ($null -eq $Acl -or $null -eq $Acl.Access) { return @() }
    $out = @()
    foreach ($ace in $Acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $rights = "$($ace.FileSystemRights)$($ace.RegistryRights)"
        if ($rights -notmatch $RightsRegex) { continue }
        $idr = "$($ace.IdentityReference)"
        foreach ($w in $WeakIds) {
            if ($idr -like "*$w*") { $out += $ace; break }
        }
    }
    return $out
}

# $global:SIG_CACHE memoizes Get-SignatureVerdict's hashtable verdicts (below);
# $global:AUTHSIG_CACHE memoizes Get-AuthSig's raw Signature objects. Both are per-scan
# memos (WS4): the same binary is signature-checked by multiple phases (System32 sets,
# process paths, startup targets), and each uncached check builds the full cert chain
# with online CRL/OCSP revocation lookups that can block ~15s. The filesystem is static
# in audit-only -Auto runs, so a scan-scoped memo is safe. Both honour the ZB_NOCACHE
# kill-switch via $global:SCAN_FILE_CACHE_ON. The SIG_AUDIT_* loop budgets are untouched:
# a cache hit is instant, so the wall-clock deadline simply stops biting.
$global:SIG_CACHE          = @{}
$global:AUTHSIG_CACHE      = @{}
$global:AUTHSIG_CACHE_HITS = 0
function Get-AuthSig([string]$Path) {
    # Safe wrapper. Get-AuthenticodeSignature throws a *terminating* error on a
    # locked / in-use file, which -ErrorAction SilentlyContinue does NOT suppress;
    # left unhandled it unwinds to a trap and skips phases. Catch it here so callers
    # just get $null. -LiteralPath also avoids wildcard expansion on bracketed paths.
    # A cached $null (locked/unreadable file) is a real entry — ContainsKey, never truthiness.
    $ck = "$Path".ToLowerInvariant()
    if ($global:SCAN_FILE_CACHE_ON -and $global:AUTHSIG_CACHE.ContainsKey($ck)) {
        $global:AUTHSIG_CACHE_HITS++
        return $global:AUTHSIG_CACHE[$ck]
    }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop } catch { $sig = $null }
    if ($global:SCAN_FILE_CACHE_ON) { $global:AUTHSIG_CACHE[$ck] = $sig }
    return $sig
}
function Get-RegVal {
    # Safe wrapper. Get-ItemPropertyValue throws a *terminating* error when the named
    # value is absent ("Property X does not exist"), which -ErrorAction SilentlyContinue
    # does NOT suppress; left unhandled it unwinds to the script trap and is logged as a
    # noisy "RECOVERED ERROR" (and on grouped phases could skip detections). Catch it here
    # so callers just get $null for a missing/locked value. Never call Get-ItemPropertyValue
    # raw — use Get-RegVal.
    param([string]$Path, [string]$Name)
    try { Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop } catch { $null }
}
# Tri-state post-condition check for FixMode's DeleteFile/DeleteRegKey/Quarantine (mirrors
# ZeroBreach-Server.ps1's Test-RPathGone for the GUI runspace — same bug, same fix, both paths).
# A bare Test-Path returns $false on an ACCESS-DENIED path exactly like it does on a genuinely
# missing one, so it can lie in both directions here: skip a removal attempt entirely because
# the pre-check claims "already absent" on a file/key it just could not read, or report a
# still-armed persistence mechanism as removed because the post-check hit the same denial.
# ItemNotFoundException is the only exception that means "genuinely gone"; anything else
# (UnauthorizedAccessException, a sharing violation, ...) must report 'unknown', never 'gone'.
function Test-PathGone {
    param([string]$Path)
    try {
        $null = Get-Item -LiteralPath $Path -ErrorAction Stop
        return 'present'
    } catch [System.Management.Automation.ItemNotFoundException] {
        return 'gone'
    } catch {
        return 'unknown'
    }
}
# Tamper-evident hash-chained remediation audit trail — console-mode mirror of
# ZeroBreach-Server.ps1's Add-RAuditEntry/Test-RPathGone pair. Kept in sync deliberately: the GUI
# rollback snapshot was missing entirely until the two paths were audited together (2026-07-22),
# so any safety/audit feature added to one remediation path now always gets its console twin.
$global:AuditLogPath = $null
$global:AuditPrevHash = ('0' * 64)
$global:AuditSeq = 0
function Add-AuditEntry {
    param([string]$Id, [string]$ThreatType, [string]$Severity, [string]$Action, [string]$Target, [string]$Result, [string]$Detail)
    if (-not $global:AuditLogPath) { return }
    $global:AuditSeq++
    $entry = [ordered]@{
        seq = $global:AuditSeq
        ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffK')
        id = $Id; threatType = $ThreatType; severity = $Severity
        action = $Action; target = $Target; result = $Result; detail = $Detail
        prevHash = $global:AuditPrevHash
    }
    $json = $entry | ConvertTo-Json -Compress
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($global:AuditPrevHash + $json)) }
    finally { $sha256.Dispose() }
    $hash = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })   # manual hex join — [Convert]::ToHexString is .NET 5+ only, unavailable on live 5.1
    $entry.hash = $hash
    $line = ($entry | ConvertTo-Json -Compress) + [Environment]::NewLine
    for ($i = 0; $i -lt 3; $i++) {
        try { [System.IO.File]::AppendAllText($global:AuditLogPath, $line); break } catch { Start-Sleep -Milliseconds 15 }
    }
    $global:AuditPrevHash = $hash
}
# Registry-key last-write time. The registry provider's RegistryKey objects expose no
# LastWriteTime property (.NET has none) — reading it needs the RegQueryInfoKey Win32 API.
# Read-only query; returns a local [datetime] or $null (missing key / access denied / API
# failure). Callers treat $null as "no time signal" (Test-InScope admits $null), so a
# failure degrades to the pre-P/Invoke behaviour, never to a dropped detection. Phase 39
# uses this as the root-CA install-time signal an attacker cannot fake; Phases 26/27/85
# use it to make their registry-key time-scope filters real.
try {
    Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class ZBRegInfo { [DllImport("advapi32.dll", EntryPoint="RegQueryInfoKeyW", CharSet=CharSet.Unicode)] public static extern int RegQueryInfoKey(IntPtr hKey, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime); }
"@ -ErrorAction SilentlyContinue
} catch {}
function Get-RegKeyLastWriteTime {
    # $Key: a [Microsoft.Win32.RegistryKey] (e.g. straight from Get-ChildItem on a hive —
    # no reopen, and the caller's key is NOT closed here) or a PS-provider path string
    # (HKLM:\… / HKCU:\…) which is opened read-only via the provider and closed after.
    param($Key)
    $k = $null; $opened = $false
    try {
        if ($Key -is [Microsoft.Win32.RegistryKey]) { $k = $Key }
        else {
            $k = Get-Item -LiteralPath "$Key" -ErrorAction Stop
            $opened = $true
            if ($k -isnot [Microsoft.Win32.RegistryKey]) { return $null }
        }
        [long]$ft = 0
        $rc = [ZBRegInfo]::RegQueryInfoKey($k.Handle.DangerousGetHandle(),
            [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [ref]$ft)
        if ($rc -eq 0 -and $ft -gt 0) { return [datetime]::FromFileTime($ft) }
    } catch {}
    finally { if ($opened -and $k -is [Microsoft.Win32.RegistryKey]) { try { $k.Close() } catch {} } }
    return $null
}
function Get-WinEventSafe {
    # Safe wrapper. Get-WinEvent -FilterHashtable throws a *terminating* error that
    # -ErrorAction SilentlyContinue does NOT suppress when a ProviderName/LogName isn't
    # registered on the box ("The parameter is incorrect") — left unhandled it unwinds to
    # the script trap and is logged as a noisy "RECOVERED ERROR". Catch it so callers get
    # an empty array. Never call Get-WinEvent -FilterHashtable raw in a phase body.
    param([hashtable]$Filter, [int]$MaxEvents = 0)
    try {
        if ($MaxEvents -gt 0) { Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop }
        else                  { Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop }
    } catch { @() }
}
function Get-FileHashSafe {
    # Get-FileHash lives in Microsoft.PowerShell.Utility; on a box with a corrupted
    # module/type environment it can fail to auto-load ("the term 'Get-FileHash' is not
    # recognized"), which unwinds to the script trap as a noisy RECOVERED ERROR and breaks
    # hash-based detection. Compute SHA256 directly via .NET (always available, no module
    # dependency). Returns uppercase hex (matching Get-FileHash's .Hash), or $null on a
    # locked/unreadable file. Never call Get-FileHash raw in a phase body — use this.
    param([string]$Path)
    $sha = $null; $fs = $null
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs  = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        ([BitConverter]::ToString($sha.ComputeHash($fs))) -replace '-',''
    } catch { $null }
    finally { if ($fs) { $fs.Dispose() }; if ($sha) { $sha.Dispose() } }
}
function Get-SignatureVerdict { param([string]$FilePath)
    if ($global:SCAN_FILE_CACHE_ON -and $global:SIG_CACHE.ContainsKey($FilePath)) { return $global:SIG_CACHE[$FilePath] }
    $result = @{ Status='Unknown'; Signer=''; Trusted=$false; IsMs=$false; Exists=$false }
    try {
        if (Test-Path -LiteralPath $FilePath) {
            $result.Exists = $true
            $sig = Get-AuthSig $FilePath
            if ($sig) {
                $result.Status = "$($sig.Status)"
                $subj = if ($sig.SignerCertificate) { "$($sig.SignerCertificate.Subject)" } else { "" }
                $result.Signer = $subj
                $trusted = Get-Perm 'trusted_signers'
                foreach ($t in $trusted) { if ($subj -like "*$t*") { $result.Trusted = $true; break } }
                if ($subj -match 'Microsoft') { $result.IsMs = $true }
            }
        }
    } catch {}
    if ($global:SCAN_FILE_CACHE_ON) { $global:SIG_CACHE[$FilePath] = $result }
    return $result
}

# Classify a finding for the remediation selection-mode presets:
#   Recommended = high-confidence, worth acting on (CRIT/HIGH with a concrete fix)
#   Safe        = remediation will not delete user data / break the OS (reversible)
# Returns 'RECOMMENDED+SAFE','RECOMMENDED','SAFE', or '' .
function Get-FixClass { param([string]$Severity, [string]$FixAction)
    $destructive = @('DeleteFile','DeleteReg')          # data/registry loss
    $safe        = @('Info','RunCmd','KillProcess','Quarantine')
    $isSafe = ($safe -contains $FixAction)
    $isRec  = (($Severity -eq 'CRITICAL' -or $Severity -eq 'HIGH') -and $FixAction -ne 'Info')
    $tag = @()
    if ($isRec)  { $tag += 'RECOMMENDED' }
    if ($isSafe) { $tag += 'SAFE' }
    ($tag -join '+')
}

# ══════════════════════════════════════════════════════════════════════════════
#  IOC FILE IMPORT (V21)
# ══════════════════════════════════════════════════════════════════════════════
function Import-CustomIocs {
    param([string]$IocFilePath)
    if (-not (Test-Path $IocFilePath)) { return $false }
    try {
        $lines = Get-Content $IocFilePath -ErrorAction Stop
        foreach ($raw in $lines) {
            $line = $raw.Trim()
            if (-not $line -or $line.StartsWith("#")) { continue }
            if ($line -match "^(hash|md5|sha1|sha256):(.+)$") { $global:CustomIocs.Hashes += $matches[2].Trim().ToLower() }
            elseif ($line -match "^(domain|host):(.+)$")      { $global:CustomIocs.Domains += $matches[2].Trim().ToLower() }
            elseif ($line -match "^(ip|cidr):(.+)$")          { $global:CustomIocs.IPs += $matches[2].Trim() }
            elseif ($line -match "^(regex|pattern):(.+)$")    { $global:CustomIocs.Regex += $matches[2].Trim() }
            elseif ($line -match "^file:(.+)$")               { $global:CustomIocs.Files += $matches[1].Trim() }
            else {
                if ($line -match "^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$") { $global:CustomIocs.Hashes += $line.ToLower() }
                elseif ($line -match "^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")                 { $global:CustomIocs.IPs += $line }
                elseif ($line -match "^[a-z0-9.\-]+\.[a-z]{2,}$")                          { $global:CustomIocs.Domains += $line.ToLower() }
                else { $global:CustomIocs.Regex += $line }
            }
        }
        return $true
    } catch { return $false }
}

# ══════════════════════════════════════════════════════════════════════════════
#  ██ TACTICAL BOOT MENU (V21)
# ══════════════════════════════════════════════════════════════════════════════
$THREAT = ""

# Apply CLI param overrides first
if ($Mode) {
    $global:ScanMode = $Mode
    if ($Mode -eq "STEALTH")  { $global:STEALTH_MODE  = $true }
    if ($Mode -eq "PARANOID") { $global:PARANOID_MODE = $true }
}
if ($Hours -ge 0) {
    if ($Hours -eq 0) { $global:TIME_LIMIT = [datetime]::MinValue; $global:TW_LABEL = "ALL TIME" }
    else              { $global:TIME_LIMIT = (Get-Date).AddHours(-$Hours); $global:TW_LABEL = "LAST $Hours HOURS" }
}
# Auto/Stealth runs without -Hours: default to ALL TIME so TW_LABEL is never blank
if (-not $global:TW_LABEL -and ($Auto -or $Stealth)) { $global:TW_LABEL = "ALL TIME" }
if ($IocFile -and (Import-CustomIocs -IocFilePath $IocFile)) {
    $ic = $global:CustomIocs.Hashes.Count + $global:CustomIocs.Domains.Count + $global:CustomIocs.IPs.Count + $global:CustomIocs.Regex.Count
    if (-not $global:STEALTH_MODE) { Write-Host "  [IOC IMPORT] Loaded $ic indicators from $IocFile" -ForegroundColor Cyan }
}

if (-not ($global:STEALTH_MODE -or $Auto)) {
    Clear-Host
    Write-Host ""
    Write-Host ("▓"*80) -ForegroundColor DarkRed
    Write-Host ""
    Write-Host "         ██╗  ██╗██████╗  █████╗ ██╗  ██╗███████╗███╗   ██╗" -ForegroundColor Red
    Write-Host "         ██║ ██╔╝██╔══██╗██╔══██╗██║ ██╔╝██╔════╝████╗  ██║" -ForegroundColor Red
    Write-Host "         █████╔╝ ██████╔╝███████║█████╔╝ █████╗  ██╔██╗ ██║" -ForegroundColor DarkRed
    Write-Host "         ██╔═██╗ ██╔══██╗██╔══██║██╔═██╗ ██╔══╝  ██║╚██╗██║" -ForegroundColor DarkRed
    Write-Host "         ██║  ██╗██║  ██║██║  ██║██║  ██╗███████╗██║ ╚████║" -ForegroundColor DarkGray
    Write-Host "         ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    Z E R O B R E A C H  ·  V 2 2  ·  S Y N D I C A T E   B U I L D" -ForegroundColor Yellow
    Write-Host "         G A N N O N   M S P   I N C .   ·   P R O J E C T   K R A K E N" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ("▓"*80) -ForegroundColor DarkRed
    Write-Host ""
    Write-Host "  107-PHASE OMNI-TIER FORENSIC EXORCIST — AUDIT + REMEDIATION ENGINE" -ForegroundColor DarkGray
    Write-Host "  Trojans · Worms · Keyloggers · RATs · Ransomware · Rootkits · UAC Bypass" -ForegroundColor DarkGray
    Write-Host "  Spyware · Adware · Botnets · Fileless · C2 Beacons · Miners · Phishing" -ForegroundColor DarkGray
    Write-Host "  YARA-Lite · LOLBAS+ · MoTW · Stolen Certs · AppDomainManager · ClickOnce" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  HOST: $HOST_NAME  |  USER: $USER_NAME  |  OS: $($global:OS_VERSION)" -ForegroundColor DarkCyan
    Write-Host "  PSVer: $($global:PSVersionMajor)  |  Legacy: $(if($global:IS_LEGACY_OS){'YES'}else{'NO'})  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ("═"*80) -ForegroundColor DarkCyan
    Write-Host ""

    function Test-MspTrigger { param([string]$In)
        if ($In -match "^(msp|staples|gannon|fast)$") {
            $global:MSP_MODE = $true
            Write-Host "  [MSP FAST MODE — GANNON ORANGE ENGAGED]" -ForegroundColor DarkYellow
            return $true
        }; return $false
    }

    # UI Selection
    Write-Host "  ┌─ SELECT INTERFACE ─────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   [1]  SHELL  (console — RDP-friendly, all features)                  │" -ForegroundColor DarkCyan
    Write-Host "  │   [2]  GUI    (WinForms checkbox tree)                                 │" -ForegroundColor DarkCyan
    Write-Host "  │   Type  msp / staples / gannon  to enable fast mode                   │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""
    while ($true) {
        Write-Host "  UI MODE> " -NoNewline -ForegroundColor Yellow
        $uiSel = (Read-Host).Trim().ToLower()
        if (Test-MspTrigger $uiSel) { continue }
        if ($uiSel -match "^2") { $global:GUI_MODE = $true; break }
        else                    { $global:GUI_MODE = $false; break }
    }

    # Time Window
    if (-not $global:TW_LABEL) {
        Write-Host ""
        Write-Host "  ┌─ SCAN TEMPORAL WINDOW ─────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
        Write-Host "  │   [1]  Last 1 Hour        [2]  Last 6 Hours                           │" -ForegroundColor DarkCyan
        Write-Host "  │   [3]  Last 24 Hours       [4]  Last 7 Days                           │" -ForegroundColor DarkCyan
        Write-Host "  │   [5]  Last 30 Days        [0]  ALL TIME (no filter) ← default        │" -ForegroundColor DarkCyan
        Write-Host "  │   Or enter any number of hours directly (e.g. 48, 168, 720)           │" -ForegroundColor DarkCyan
        Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
        Write-Host ""
        while ($true) {
            Write-Host "  TIME WINDOW> " -NoNewline -ForegroundColor Yellow
            $twSel = (Read-Host).Trim().ToLower()
            if (Test-MspTrigger $twSel) { continue }
            switch ($twSel) {
                "1"  { $global:TIME_LIMIT=(Get-Date).AddHours(-1);   $global:TW_LABEL="LAST 1 HOUR";   break }
                "2"  { $global:TIME_LIMIT=(Get-Date).AddHours(-6);   $global:TW_LABEL="LAST 6 HOURS";  break }
                "3"  { $global:TIME_LIMIT=(Get-Date).AddHours(-24);  $global:TW_LABEL="LAST 24 HOURS"; break }
                "4"  { $global:TIME_LIMIT=(Get-Date).AddDays(-7);    $global:TW_LABEL="LAST 7 DAYS";   break }
                "5"  { $global:TIME_LIMIT=(Get-Date).AddDays(-30);   $global:TW_LABEL="LAST 30 DAYS";  break }
                {"0","","all","alltime","all time" -contains $_} {
                    $global:TIME_LIMIT=[datetime]::MinValue; $global:TW_LABEL="ALL TIME"; break
                }
                default {
                    if ($twSel -match "^\d+$" -and [int]$twSel -gt 0) {
                        $h = [int]$twSel
                        $global:TIME_LIMIT=(Get-Date).AddHours(-$h); $global:TW_LABEL="LAST $h HOURS"; break
                    }
                    $global:TIME_LIMIT=[datetime]::MinValue; $global:TW_LABEL="ALL TIME"; break
                }
            }
            if ($global:TW_LABEL) { break }
        }
    }

    # Scan Mode
    if (-not $Mode) {
        Write-Host ""
        Write-Host "  ┌─ DEPLOYMENT MODE ──────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
        Write-Host "  │   [1]  QUICK     — Core 30 phases  (~2 min, fast triage)              │" -ForegroundColor DarkCyan
        Write-Host "  │   [2]  FULL      — All 80 phases   (default, comprehensive)           │" -ForegroundColor DarkCyan
        Write-Host "  │   [3]  DEEP      — All 105 phases  (+ APT, YARA, memory analysis)     │" -ForegroundColor DarkCyan
        Write-Host "  │   [4]  PARANOID  — DEEP + lower thresholds (POSSIBLE→HIGH)            │" -ForegroundColor DarkCyan
        Write-Host "  │   [5]  STEALTH   — Silent, JSON-only, no banners                      │" -ForegroundColor DarkCyan
        Write-Host "  │   [B]  Baseline diff   [I]  Import IOC file                           │" -ForegroundColor DarkCyan
        Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
        Write-Host ""
        while ($true) {
            Write-Host "  MODE> " -NoNewline -ForegroundColor DarkGray
            $sel = (Read-Host).Trim().ToLower()
            if (Test-MspTrigger $sel) { continue }
            switch ($sel) {
                "1"  { $global:ScanMode="QUICK";    $THREAT="Quick Triage (30 phases)";         break }
                "2"  { $global:ScanMode="FULL";     $THREAT="Full 80-Phase Malware Sweep";       break }
                ""   { $global:ScanMode="FULL";     $THREAT="Full 80-Phase Malware Sweep";       break }
                "3"  { $global:ScanMode="DEEP";     $THREAT="Deep 105-Phase APT Hunt";           break }
                "4"  { $global:ScanMode="PARANOID"; $global:PARANOID_MODE=$true; $THREAT="Paranoid 105-Phase"; break }
                "5"  { $global:ScanMode="STEALTH";  $global:STEALTH_MODE=$true;  $THREAT="Stealth JSON";       break }
                "b"  {
                    Write-Host "  BASELINE PATH> " -NoNewline -ForegroundColor Yellow
                    $bp = (Read-Host).Trim('"')
                    if (Test-Path $bp) { $Baseline=$bp; Write-Host "  [BASELINE LOADED]" -ForegroundColor Cyan }
                    else { Write-Host "  File not found." -ForegroundColor Red }
                    continue
                }
                "i"  {
                    Write-Host "  IOC FILE PATH> " -NoNewline -ForegroundColor Yellow
                    $ip2 = (Read-Host).Trim('"')
                    if (Import-CustomIocs -IocFilePath $ip2) {
                        $cnt = $global:CustomIocs.Hashes.Count+$global:CustomIocs.Domains.Count+$global:CustomIocs.IPs.Count+$global:CustomIocs.Regex.Count
                        Write-Host "  [IOCs LOADED] $cnt indicators" -ForegroundColor Cyan
                    } else { Write-Host "  IOC load failed." -ForegroundColor Red }
                    continue
                }
            }
            if ($THREAT) { break }
        }
    }
}

# Phase plan
if (-not $global:ScanMode) { $global:ScanMode = "FULL" }
if (-not $global:TW_LABEL) { $global:TIME_LIMIT=[datetime]::MinValue; $global:TW_LABEL="ALL TIME" }
$PhasePlan = switch ($global:ScanMode) {
    "QUICK"    { @{ Min=1; Max=30;  Universal=$false; Advanced=$false; Integrity=$false } }
    "FULL"     { @{ Min=1; Max=80;  Universal=$false; Advanced=$false; Integrity=$false } }
    "DEEP"     { @{ Min=1; Max=115; Universal=$true;  Advanced=$true;  Integrity=$true  } }
    "PARANOID" { @{ Min=1; Max=115; Universal=$true;  Advanced=$true;  Integrity=$true  } }
    "STEALTH"  { @{ Min=1; Max=115; Universal=$true;  Advanced=$true;  Integrity=$true  } }
    default    { @{ Min=1; Max=80;  Universal=$false; Advanced=$false; Integrity=$false } }
}
# QUICK is now a REAL gate (BLUEPRINT §7.8). Every mode except QUICK runs the full 1-80 span
# (DEEP+ add the Universal 81-89 + Advanced 90-115). QUICK runs a reduced 30-phase triage set;
# the other 54 phases in 1-80 are wrapped `if (-not $global:QUICK_MODE) { ... }` in
# engine/Phases-1/2.ps1. The KEPT QUICK set (MUST stay exactly $PhasePlan.Max = 30 phases —
# phase_total honesty; the server mirrors QUICK=30):
#   1,3,4,5,6,10,20,21,23,27,28,29,30,31,33,35,41,42,45,51,53,54,56,62,64,69,70,72,74.6,75
# Invariant baked into the wraps: 51 is KEPT because 53 reuses its $ransomScanFiles walk.
# If you change the wrap set, update Max above AND the server's $MODE_PHASES QUICK entry.
$global:QUICK_MODE = ($global:ScanMode -eq 'QUICK')

# ── Full console transcript (interactive runs) ────────────────────────────────
# Captures EVERYTHING printed to the console to reports/KrakenConsole_<stamp>.log so
# the operator never has to copy from the window. Skipped in STEALTH (JSON stdout)
# and harmlessly skipped where the host can't transcribe (e.g. the GUI runspace).
$global:TRANSCRIPT_ON = $false
$TRANSCRIPT_PATH = Join-Path $OUT_ROOT "KrakenConsole_$STAMP.log"
if (-not $global:STEALTH_MODE) {
    try {
        Start-Transcript -Path $TRANSCRIPT_PATH -Force -ErrorAction Stop | Out-Null
        $global:TRANSCRIPT_ON = $true
    } catch { $global:TRANSCRIPT_ON = $false }
}

if (-not $global:STEALTH_MODE) {
    Clear-Host
    Write-Host ""
    Write-Host ("▓"*80) -ForegroundColor DarkRed
    Write-Host "    ◤◤◤  P R O J E C T   K R A K E N   V 2 2   ·   A U D I T   I N I T  ◥◥◥" -ForegroundColor Red
    Write-Host ("▓"*80) -ForegroundColor DarkRed
    $ac = Get-AccentColor
    Write-Host "  MODE      : " -NoNewline -ForegroundColor DarkGray; Write-Host "$($global:ScanMode) (phases $($PhasePlan.Min)-$($PhasePlan.Max))" -ForegroundColor $ac
    Write-Host "  WINDOW    : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:TW_LABEL -ForegroundColor Yellow
    Write-Host "  INTERFACE : " -NoNewline -ForegroundColor DarkGray; Write-Host $(if($global:GUI_MODE){"WinForms GUI"}else{"Shell Console"}) -ForegroundColor $ac
    Write-Host "  PARANOID  : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:PARANOID_MODE -ForegroundColor $(if($global:PARANOID_MODE){"Magenta"}else{"DarkGray"})
    $cic2=$global:CustomIocs.Hashes.Count+$global:CustomIocs.Domains.Count+$global:CustomIocs.IPs.Count+$global:CustomIocs.Regex.Count
    Write-Host "  IOC COUNT : " -NoNewline -ForegroundColor DarkGray; Write-Host "$cic2 custom indicators" -ForegroundColor $(if($cic2-gt 0){"Cyan"}else{"DarkGray"})
    Write-Host "  BASELINE  : " -NoNewline -ForegroundColor DarkGray; Write-Host $(if($Baseline){"DIFF — $Baseline"}else{"none"}) -ForegroundColor $(if($Baseline){"Cyan"}else{"DarkGray"})
    Write-Host "  REPORT    : " -NoNewline -ForegroundColor DarkGray; Write-Host $REPORT_PATH -ForegroundColor DarkGray
    if ($global:TRANSCRIPT_ON) { Write-Host "  CONSOLE LOG: " -NoNewline -ForegroundColor DarkGray; Write-Host $TRANSCRIPT_PATH -ForegroundColor DarkGray }
    if ($global:HTML_REPORT) { Write-Host "  HTML      : " -NoNewline -ForegroundColor DarkGray; Write-Host $HTML_PATH -ForegroundColor DarkGray }
    Write-Host ("▓"*80) -ForegroundColor DarkRed
    Write-Host ""
    Write-Host "  TIP: Press " -NoNewline -ForegroundColor DarkGray
    Write-Host "[K]" -NoNewline -ForegroundColor Yellow
    Write-Host " at any time to toggle fast mode and kill slow output." -ForegroundColor DarkGray
    Write-Host ""
    Out-Typewriter "INITIALIZING FORENSIC KERNEL..." "INFO"
    Invoke-QuantumBar "LOADING HEURISTIC SIGNATURES & IOC DATABASES" 20 80
    Out-Typewriter "KERNEL READY. COMMENCING $($global:ScanMode) AUDIT — PHASES $($PhasePlan.Min) THROUGH $($PhasePlan.Max)." "GOOD"
}
Write-Log "ZEROBREACH V22 AUDIT START | $HOST_NAME | $(Get-Date) | MODE:$($global:ScanMode) | WINDOW:$($global:TW_LABEL) | PARANOID:$($global:PARANOID_MODE)"

# ── Launch GUI dashboard BEFORE scan (findings populate live) ─────────────────
if ($global:GUI_MODE -and -not $global:STEALTH_MODE) {
    $global:TOTAL_PHASES = $PhasePlan.Max
    Show-LiveScanDashboard | Out-Null
}

# ── Shell kill watcher ────────────────────────────────────────────────────────
if (-not $global:GUI_MODE -and -not $global:STEALTH_MODE -and -not $Auto) {
    $global:SHELL_KILL_JOB = Start-ShellKillWatcher
}

# ══════════════════════════════════════════════════════════════════════════════
#  CUSTOM IOC WIRE-UP (2026-07-22 review #17)
#  Import-CustomIocs has always filled all five buckets, but only .Hashes was ever
#  read (Phase 90) — an operator who added a known-bad domain/IP/regex/filename via
#  -IocFile or the GUI IOC Manager got a counter that went up and zero coverage.
#  Merged here, AFTER every import path (CLI param + interactive menu) and BEFORE the
#  engine modules are dot-sourced, so the phases below see one combined list.
#  Domains join the *narrow* malware-C2 list, not the broad LOLBin list: the operator
#  explicitly declared these malicious, so a DNS-cache hit is a real HIGH, and that is
#  the list Phase 34 is allowed to fire on (see the $MALWARE_C2_DOMAINS note above).
# ══════════════════════════════════════════════════════════════════════════════
if ($global:CustomIocs.Domains.Count -gt 0) {
    $MALWARE_C2_DOMAINS = @(@($MALWARE_C2_DOMAINS) + @($global:CustomIocs.Domains) | Select-Object -Unique)
    $ALL_C2_DOMAINS     = @(@($ALL_C2_DOMAINS)     + @($global:CustomIocs.Domains) | Select-Object -Unique)
}
# Pre-compile the operator's free-form regex IOCs once. A bad pattern from a hand-edited
# IOC file must not take the scan down, so each is validated here and dropped with a warning
# rather than throwing inside a phase loop.
$global:CustomIocRegexOk = @()
foreach ($cre in @($global:CustomIocs.Regex)) {
    if (-not $cre) { continue }
    try { [void][regex]::new($cre); $global:CustomIocRegexOk += $cre }
    catch { Write-Host "[ZeroBreach] WARNING: ignoring invalid custom IOC regex: $cre" -ForegroundColor DarkYellow }
}
# Normalise the operator's filename IOCs to bare lowercase leaf names for comparison.
$global:CustomIocFileNames = @(@($global:CustomIocs.Files) | ForEach-Object {
    try { [IO.Path]::GetFileName("$_").ToLower() } catch { "$_".ToLower() }
} | Where-Object { $_ })

# ══════════════════════════════════════════════════════════════════════════════
#  ENGINE MODULES — dot-sourced in execution order into THIS scope (variables,
#  functions and the resilience trap all carry across module boundaries exactly
#  as they did inline). Split at section banners; phases stay in numeric order.
#  RULES (see CLAUDE.md):
#   • any `exit` inside engine/*.ps1 that must stop the ENGINE has to be
#     [Environment]::Exit(N) — a plain `exit` in a dot-sourced file only returns
#     to this loader, which then runs the NEXT module (hangs -Auto on FixMode).
#   • $PSScriptRoot inside engine/*.ps1 resolves to engine\, not the project
#     root — use $global:ZB_ROOT (set near the top of this loader) instead.
#   • every module keeps its UTF-8 BOM.
# ══════════════════════════════════════════════════════════════════════════════
. "$PSScriptRoot\engine\Phases-1.ps1"
. "$PSScriptRoot\engine\Phases-2.ps1"
. "$PSScriptRoot\engine\Phases-3.ps1"
. "$PSScriptRoot\engine\Summary.ps1"
. "$PSScriptRoot\engine\FixMode.ps1"
