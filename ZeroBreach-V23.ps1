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
trap {
    try {
        $em   = $_.Exception.Message
        $pos  = (("" + $_.InvocationInfo.PositionMessage) -replace "`r?`n"," ").Trim()
        $line = "RECOVERED ERROR: $em | $pos"
        $global:RECOVERED_ERRORS.Add($line)
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log $line }
        if (-not $global:STEALTH_MODE) { Write-Host "  [!] $line" -ForegroundColor DarkYellow }
    } catch {}
    continue
}

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
$AUDIT_JSON    = Join-Path $OUT_ROOT "ZeroBreach_AuditCache_$(Get-Date -Format 'yyyyMMdd').json"
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
#  REMEDIATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-VerifiedAnnihilation {
    param([string]$Path, [bool]$IsDirectory = $false)
    Out-Decrypt -Text $Path -Prefix "  [TARGET LOCKED] "
    try { Remove-Item -Path $Path -Recurse -Force -Confirm:$false -ErrorAction Stop }
    catch {
        cmd.exe /c "del /f /s /q `"$Path`" >nul 2>&1"
        if ($IsDirectory) { cmd.exe /c "rmdir /s /q `"$Path`" >nul 2>&1" }
    }
    Start-Sleep -Milliseconds 100
    if (Test-Path $Path) {
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
            $target  = "\??\$Path"
            $cur     = Get-ItemPropertyValue -Path $regPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
            if ($null -eq $cur) { $cur = @() }
            Set-ItemProperty -Path $regPath -Name "PendingFileRenameOperations" -Value ([string[]]($cur) + @($target, "")) -Type MultiString -Force -ErrorAction Stop
            Out-Typewriter "KERNEL HOOKED: QUEUED FOR NEXT REBOOT." "WARN"; $global:KillCount++
        } catch { $global:VerifyFails++ }
    } else { $global:KillCount++ }
}

function Invoke-VerifiedRegScrub {
    param([string]$Path, [string]$Name)
    Out-Decrypt -Text "$Path\$Name" -Prefix "  [REG NODE] "
    Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 100
    $check = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $check.$Name) { $global:VerifyFails++ } else { $global:KillCount++ }
}

function Invoke-SectorScan {
    param([string]$Path, [bool]$IsDirectory = $false)
    $ts = (Get-Date).ToString("HH:mm:ss.fff")
    Write-Host "[$ts] [SYS] " -NoNewline -ForegroundColor DarkGray
    Write-Host "AUDITING: " -NoNewline -ForegroundColor (Get-AccentColor); Write-Host $Path -ForegroundColor DarkGray
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds ($rng.Next(500,1200)) }
    if (Test-Path $Path) {
        Out-Typewriter "  -> SECTOR EXISTS — FLAGGED." "WARN"
        # In audit mode, we only add findings — no deletion
    } else { Out-Typewriter "  -> [OK] SECTOR ABSENT." "GOOD" }
}

function Invoke-RegSectorScan {
    param([string]$Path, [string]$Name)
    $ts = (Get-Date).ToString("HH:mm:ss.fff")
    Write-Host "[$ts] [SYS] " -NoNewline -ForegroundColor DarkGray
    Write-Host "REG CHECK: " -NoNewline -ForegroundColor Magenta; Write-Host "$Path\$Name" -ForegroundColor DarkGray
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds ($rng.Next(400,900)) }
    $check = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $check.$Name) {
        Out-Typewriter "  -> ANOMALY: $Name = $($check.$Name)" "CRIT"; return $true
    } else { Out-Typewriter "  -> [OK] KEY ABSENT/CLEAN." "GOOD"; return $false }
}

function Reset-FilePermissions {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        $acl = Get-Acl $Path -ErrorAction Stop
        $acl.SetAccessRuleProtection($false, $true)
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        cmd.exe /c "icacls `"$Path`" /reset /T /Q >nul 2>&1"
        Out-Typewriter "  -> PERMISSIONS RESET: $Path" "VER"
    } catch { Out-Typewriter "  -> PERM RESET FAILED: $Path" "WARN" }
}

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════
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
    $results  = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $deadline = [datetime]::UtcNow.AddSeconds($DeadlineSecs)
    $prune    = @{}; foreach ($d in $PruneDirs) { $prune[$d.ToLower()] = $true }
    foreach ($root in $Path) {
        if (-not $root) { continue }
        try { if (-not (Test-Path -LiteralPath $root)) { continue } } catch { continue }
        $stack = New-Object System.Collections.Generic.Stack[string]
        try { $stack.Push((Convert-Path -LiteralPath $root)) } catch { continue }
        while ($stack.Count -gt 0) {
            if ([datetime]::UtcNow -ge $deadline -or $results.Count -ge $MaxFiles) { return ,$results.ToArray() }
            $dir = $stack.Pop()
            try {
                foreach ($f in [System.IO.Directory]::EnumerateFiles($dir, $Filter)) {
                    if ($results.Count -ge $MaxFiles -or [datetime]::UtcNow -ge $deadline) { break }
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
    return ,$results.ToArray()
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
        # CRITICAL: known malicious extension names or permissions
        $knownBad = @("web of trust","superfish","browsefox","conduit","searchprotect","savefrom","coupon server","ebates","honey","browsing protection","webdiscover","trovi","istartsurf","searchqu","delta search","babylon","iminent","visualbee")
        foreach ($bad in $knownBad) {
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
# WS1 — name-lists externalized out of engine/*.ps1 (AMSI/portability). One key per phase.
$C2_PIPE_PATTERNS       = Get-Sig 'c2_pipe_patterns'      # Phase 62
$ADWARE_PUP_REGS        = Get-Sig 'adware_pup_regs'       # Phase 67
$INFOSTEALER_PROCS      = Get-Sig 'infostealer_procs'     # Phase 68
$TUNNELING_TOOLS        = Get-Sig 'tunneling_tools'       # Phase 82
$STEGO_TOOLS            = Get-Sig 'stego_tools'           # Phase 89
$LEAKED_CERT_ISSUERS    = Get-Sig 'leaked_cert_issuers'   # Phase 98
$CRED_DUMP_TOOLS        = Get-Sig 'cred_dump_tools'       # Phase 106

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

# Authenticode verdict for a file: returns a hashtable {Status, Signer, Trusted, IsMs}.
# Cached per-path to avoid re-verifying the same binary across phases.
$global:SIG_CACHE = @{}
function Get-SignatureVerdict { param([string]$FilePath)
    if ($global:SIG_CACHE.ContainsKey($FilePath)) { return $global:SIG_CACHE[$FilePath] }
    $result = @{ Status='Unknown'; Signer=''; Trusted=$false; IsMs=$false; Exists=$false }
    try {
        if (Test-Path -LiteralPath $FilePath) {
            $result.Exists = $true
            $sig = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction SilentlyContinue
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
    $global:SIG_CACHE[$FilePath] = $result
    return $result
}

# Raw Authenticode signature, cached per-path. Get-AuthenticodeSignature throws a
# *terminating* error on locked / in-use files (e.g. a running process's own .exe, or
# CBS temp binaries in System32) which -ErrorAction SilentlyContinue does NOT suppress —
# those bubbled to the global trap as repeated "RECOVERED ERROR" log spam and cost time.
# Here the throw is swallowed and the verdict cached so the same binary is verified once
# across all phases. Returns the native Signature object, or $null when it could not be
# read. IMPORTANT: callers must treat $null as "undetermined / skip", never as "unsigned",
# so locked legitimate OS files are not mis-flagged as rootkits.
$global:AUTHSIG_CACHE = @{}
function Get-AuthSig { param([string]$FilePath)
    if (-not $FilePath) { return $null }
    if ($global:AUTHSIG_CACHE.ContainsKey($FilePath)) { return $global:AUTHSIG_CACHE[$FilePath] }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop } catch { $sig = $null }
    $global:AUTHSIG_CACHE[$FilePath] = $sig
    return $sig
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


# ──────────────────────────────────────────────────────────────────────────────
#  ENGINE MODULES - dot-sourced into THIS scope (same vars/funcs/trap apply).
#  Split from the former monolith; see ENGINE_SPLIT_PLAN.md. Order is execution order.
#  Loader keeps param()/elevation/globals/helpers/Get-Sig (all $PSScriptRoot usage).
# ──────────────────────────────────────────────────────────────────────────────
. (Join-Path $PSScriptRoot 'engine\Phases-1.ps1')
. (Join-Path $PSScriptRoot 'engine\Phases-2.ps1')
. (Join-Path $PSScriptRoot 'engine\Phases-3.ps1')
. (Join-Path $PSScriptRoot 'engine\Summary.ps1')
. (Join-Path $PSScriptRoot 'engine\FixMode.ps1')
