# NOTE - Detection vocabulary in this file is deliberate.
# Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
# named malware families, are detection category labels, operator-facing report text, or
# MITRE ATT&CK tactic names (a published standard). Scythe is a defensive incident-
# response tool; these strings are what it reports, not what it does. See CLAUDE.md,
# "The detection vocabulary is deliberate". Do not sanitise them.

# Scythe-V22.ps1 — Monolithic Omni-Tier Forensic Exorcist
# CONSOLIDATED: V21 + Debug Pass 2 + Phases 106-107 + Schedule + HTML/CSV export

#Requires -Version 5.1
<#
.SYNOPSIS
    Project Kraken // Scythe V22 — Omni-Tier Forensic Exorcist
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
    [ValidateSet("","QUICK","FULL","DEEP","PARANOID","STEALTH","HUNT")]
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
    Start-Process powershell $argList -Verb RunAs; exit
}

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Drawing       -ErrorAction SilentlyContinue

# ── Schedule Registration — runs before any scan logic ────────────────────────
if ($Schedule -and $Schedule -ne "") {
    $taskName   = "Scythe_V22_Scheduled"

    # A machine scheduled before the rename still carries a task under the old product
    # name. Left alone it keeps firing alongside the new one - two scans a night, and the
    # old one points at a script path that no longer exists. Remove it before registering.
    $legacyTaskName = "ZeroBreach_V22_Scheduled"
    if (Get-ScheduledTask -TaskName $legacyTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $legacyTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[Scythe V22] Removed the pre-rename scheduled task '$legacyTaskName'." -ForegroundColor Yellow
    }

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
        Write-Host "[Scythe V22] Scheduled task '$taskName' registered ($Schedule at 02:00). Run: SYSTEM" -ForegroundColor Green
    } else {
        Write-Host "[Scythe V22] WARNING: Task registration failed — check permissions." -ForegroundColor Red
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
$global:SCYTHE_ROOT = $PSScriptRoot

# ── Bitness / WOW64 truth (ADVERSARY_ANALYSIS.md E2) ──────────────────────────
# On x64 Windows a 32-bit process is LIED TO by the OS: C:\Windows\System32 silently
# redirects to SysWOW64, and HKLM\SOFTWARE redirects to Wow6432Node. A scanner running
# 32-bit is therefore auditing a different operating system than the one it reports on —
# the real System32 and the real HKLM run keys are in the half it cannot see. That is a
# free evasion for an attacker and, more likely, an accident: a technician's 32-bit shell,
# an RMM agent that spawns x86, or a PS2EXE build compiled for x86 all hand it over.
#
# We do NOT auto-relaunch. A relaunch would orphan the redirected stdout the server is
# reading (the GUI would see the scan die), so the engine instead records the condition,
# routes its own System32 / HKLM access through the non-redirected views below, and
# reports CRITICAL from engine\Phases-0.ps1 so the operator knows which legacy phases to
# distrust.
$global:SCYTHE_IS_WOW64 = ((-not [Environment]::Is64BitProcess) -and [Environment]::Is64BitOperatingSystem)
# The REAL System32, reachable from either bitness. Sysnative exists only for 32-bit
# processes on x64 and is the documented escape hatch from file-system redirection.
$global:SCYTHE_SYS32 = if ($global:SCYTHE_IS_WOW64) { Join-Path $env:WINDIR 'Sysnative' } else { Join-Path $env:WINDIR 'System32' }
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
$AUDIT_JSON    = Join-Path $env:TEMP "Scythe_AuditCache_$(Get-Date -Format 'yyyyMMdd').json"
$BASELINE_PATH = Join-Path $OUT_ROOT "KrakenBaseline_$STAMP.json"
# audit H1: this used to be a single .reg file built by concatenating five `reg export`
# outputs behind a banner line. regedit /S requires "Windows Registry Editor Version 5.00"
# as the FIRST line, so that bundle could never be imported — the advertised safety net
# did not work. It is now a folder holding each export as its own valid .reg plus a
# generated Restore.cmd.
$SNAPSHOT_DIR  = Join-Path $OUT_ROOT "KrakenSnapshot_$STAMP"
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
# ══════════════════════════════════════════════════════════════════════════════
#  RunCmd FixParam SAFETY — single-quoted literal escaping
# ══════════════════════════════════════════════════════════════════════════════
# RunCmd FixParams are executed via [scriptblock]::Create($f.FixParam); & $sb — functionally
# Invoke-Expression, at admin privilege. Phases build those command strings by interpolating
# ATTACKER-NAMED artifacts (scheduled tasks, WMI __EventFilter/__EventConsumer names, service
# keys, Defender exclusion paths, firewall rule names, IFEO subkeys, file paths) into
# single-quoted PowerShell literals. An unescaped apostrophe in any of them closes the literal
# and everything after it executes — turning a CORRECT detection of a REAL threat into code
# execution the moment the operator approves the fix.
#
# Verified with the shipped code: a task named  Updater';Write-Host 'x';#  makes the Phase 64
# FixParam parse into TWO statements. Phase 29 (which already escaped) parses into one.
#
# Doubling the apostrophe is the COMPLETE fix for a single-quoted literal — PowerShell performs
# no other escape processing inside '...'. Always wrap the interpolation in single quotes:
#     -FixParam "Unregister-ScheduledTask -TaskName '$(ConvertTo-PsLiteral $t.TaskName)' ..."
# NEVER use this for a double-quoted literal or for an unquoted argument — neither is safe.
function ConvertTo-PsLiteral {
    param([string]$Value)
    return ("$Value" -replace "'", "''")
}

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
    $flagFile = Join-Path $env:TEMP "Scythe_KillFlag_$(Get-Date -Format 'yyyyMMddHHmmss').tmp"
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
            $cur     = Get-RegVal -Path $regPath -Name "PendingFileRenameOperations"
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
# Per-scan enumeration memo (WS4): many phases re-walk identical root sets
# (e.g. dump/stego both walk TEMP+LOCALAPPDATA+USERPROFILE; the Phases-3 foreach-$root
# loops re-walk trees Phases-1/2 already walked). The engine is audit-only in -Auto so the
# filesystem is static for a run, and it spawns fresh per scan, so this script-scope memo is
# naturally scan-scoped. Keyed on the FULL param tuple → only byte-identical calls share a
# result; the cached array is never mutated by callers (they filter into new collections).
$global:SCAN_FILE_CACHE      = @{}
$global:SCAN_FILE_CACHE_HITS = 0
$global:SCAN_FILE_CACHE_ON   = -not $env:SCYTHE_NOCACHE   # kill-switch: PRESENCE-based — any value (even "0") disables; unset = on
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
    if ($global:SCAN_FILE_CACHE_ON) { $global:SCAN_FILE_CACHE[$ck] = $arr }   # SCYTHE_NOCACHE runs stay truly cache-free
    return ,$arr
}

# Per-scan Win32_Process snapshot memo (WS4): 7 phases each ran their own full
# Win32_Process WMI enumeration. Unlike the filesystem (static in audit mode) the process
# table DOES change during a run, so entries expire after PROC_SNAP_TTL_S: adjacent phase
# clusters (3+4; 99+99.5+102) share one enumeration, while phases minutes apart still see
# fresh data. Shares the SCYTHE_NOCACHE kill-switch via SCAN_FILE_CACHE_ON. Same `return ,$arr`
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
    catch { $SIG = $null; Write-Host "[Scythe] WARNING: could not parse $SigPath ($($_.Exception.Message))" -ForegroundColor Red }
} else {
    $SIG = $null
    Write-Host "[Scythe] WARNING: signature file missing: $SigPath - many detections disabled." -ForegroundColor Red
}
# ══════════════════════════════════════════════════════════════════════════════
#  SIGNATURE-SET INTEGRITY GATE  (WS7 · ADVERSARY_ANALYSIS.md E1)
# ══════════════════════════════════════════════════════════════════════════════
# data\detection_signatures.json is a plain file sitting next to the engine, read at
# runtime with no authentication, and on a box the attacker owns it is writable. The
# fp_allowlists block fails OPEN by design (an allowlist SUPPRESSES detections), so the
# cheapest possible attack on this tool is not to delete a detection — a missing key
# fails closed to '(?!)' and is conspicuous — but to WIDEN one entry to '.*'. Every
# phase downstream of that key then suppresses everything it finds and still prints its
# normal [OK ] banner. A clean bill of health from a blinded scanner is the single worst
# output an IR tool can produce.
#
# The allowlists are therefore sanitised HERE, before Join-AllowRegex compiles them a
# few lines below. Two checks, neither of which needs a key, a manifest or a network:
#   1. the pattern must COMPILE. A broken regex would otherwise throw at match time,
#      unwind to the resilience trap, and silently kill the rest of its phase.
#   2. the pattern must not be UNIVERSAL. The canaries below share no common substring,
#      so a pattern matching all five cannot be a meaningful FP allowlist — it is either
#      an attack or a typo, and both blind the same phases.
# A pattern that blows the 150 ms match budget is refused too: an allowlist is evaluated
# against attacker-authored text, so catastrophic backtracking here is a DoS on the scan
# (same rule the signature suite enforces for detection patterns).
#
# Refusals FAIL CLOSED — the entry is dropped, so the phase goes NOISY rather than
# BLIND — and are reported as findings by engine\Phases-0.ps1. Nothing is silently
# repaired: the operator is told the signature set was modified.
$global:SCYTHE_SIG_TAMPER = [System.Collections.Generic.List[string]]::new()

function Test-AllowPatternSafety {
    # Returns 'ok' | 'nocompile' | 'universal' | 'timeout'. Never throws.
    param([string]$Pattern)
    $rx = $null
    try { $rx = New-Object System.Text.RegularExpressions.Regex(
                    $Pattern,
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
                    [TimeSpan]::FromMilliseconds(150)) }
    catch { return 'nocompile' }
    # Deliberately unrelated strings: a path, a registry key, a digit, a nonsense word,
    # a product name. No legitimate FP-suppression pattern matches every one of these.
    $canaries = @(
        'C:\Windows\System32\svchost.exe',
        'HKLM:\SOFTWARE\Vendor\Product',
        '9',
        'zqx',
        'Some Product Name 2026'
    )
    foreach ($c in $canaries) {
        try { if (-not $rx.IsMatch($c)) { return 'ok' } }
        catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { return 'timeout' }
        catch { return 'nocompile' }
    }
    return 'universal'
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
function Join-AllowRegex {
    # THE choke point for every FP allowlist in the engine, and therefore the place the
    # integrity gate has to live: an allowlist SUPPRESSES detections, so it fails OPEN.
    # Widening one entry to '.*' silently switches off every phase that consumes this key
    # while the scan still prints its [OK ] banner (ADVERSARY_ANALYSIS.md E1). Each
    # pattern is checked before it is compiled in; refusals FAIL CLOSED (the entry is
    # dropped, so the phase goes NOISY rather than BLIND) and are reported as CRITICAL
    # findings by engine\Phases-0.ps1. An absent key still yields '(?!)', which suppresses
    # nothing — that behaviour is unchanged and load-bearing.
    param([string]$Name)
    $a = @(Get-Sig $Name)
    if (-not $a.Count) { return '(?!)' }
    $keep = New-Object System.Collections.Generic.List[string]
    foreach ($pat in $a) {
        $p = "$pat"
        if ([string]::IsNullOrWhiteSpace($p)) {
            $global:SCYTHE_SIG_TAMPER.Add("${Name}: empty pattern dropped (an empty alternation branch matches everything)")
            continue
        }
        switch (Test-AllowPatternSafety $p) {
            'ok'        { $keep.Add($p) }
            'nocompile' { $global:SCYTHE_SIG_TAMPER.Add("${Name}: pattern does not compile and was dropped -> $p") }
            'universal' { $global:SCYTHE_SIG_TAMPER.Add("${Name}: UNIVERSAL pattern dropped — it would have suppressed EVERY detection that uses this allowlist -> $p") }
            'timeout'   { $global:SCYTHE_SIG_TAMPER.Add("${Name}: pattern exceeded the 150 ms match budget and was dropped (catastrophic backtracking) -> $p") }
        }
    }
    if ($keep.Count -eq 0) { return '(?!)' }
    return ($keep -join '|')
}
$TRUSTED_ROOT_CA_RE     = Join-AllowRegex 'trusted_root_ca_issuers'
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
$SPOOLDLL_BENIGN_RE     = Join-AllowRegex 'spooler_benign_dlls'      # Phase 96 (catalog-signed MS printer resources)
$BITS_SUSP_REMOTE_RE    = if (@(Get-Sig 'bits_suspicious_remote_regex').Count) { @(Get-Sig 'bits_suspicious_remote_regex')[0] } else { '(?!)' }
$BITS_SUSP_LOCAL_RE     = if (@(Get-Sig 'bits_suspicious_local_regex').Count) { @(Get-Sig 'bits_suspicious_local_regex')[0] } else { '(?!)' }
# WS6 (phases 116-133) FP allowlists — NOT signatures (CLAUDE.md AMSI rule): an empty
# key becomes '(?!)', which suppresses nothing, so a missing list can never blind a phase.
$NATIVE_MSG_BENIGN_RE   = Join-AllowRegex 'native_messaging_benign_hosts'  # Phase 117
$SIDELOAD_BENIGN_RE     = Join-AllowRegex 'sideload_benign_paths'          # Phase 119
$OFFICE_ADDIN_BENIGN_RE = Join-AllowRegex 'office_addin_benign_paths'      # Phase 121
$EXEC_EVID_BENIGN_RE    = Join-AllowRegex 'exec_evidence_benign_paths'     # Phase 123
$SHELLEXT_BENIGN_RE     = Join-AllowRegex 'shell_extension_benign_dlls'    # Phase 127
$WEBHOOK_BENIGN_RE      = Join-AllowRegex 'webhook_c2_benign_paths'        # Phase 130
$PACKEDSCRIPT_BENIGN_RE = Join-AllowRegex 'packed_script_benign_paths'     # Phase 131
# ── WS7 HUNT band (phases 134-162) ───────────────────────────────────────────
$HUNT_TASK_BENIGN_RE    = Join-AllowRegex 'hunt_task_benign_paths'         # Phase 134
$HUNT_SERVICE_BENIGN_RE = Join-AllowRegex 'hunt_service_benign_names'      # Phase 135
$HUNT_PPID_BENIGN_RE    = Join-AllowRegex 'hunt_ppid_benign_paths'         # Phase 136
$HUNT_DRIVER_BENIGN_RE  = Join-AllowRegex 'hunt_driver_benign_names'       # Phase 138
$HUNT_TIMESTOMP_BENIGN_RE = Join-AllowRegex 'hunt_timestomp_benign_paths'  # Phase 139
$HUNT_FILENAME_BENIGN_RE  = Join-AllowRegex 'hunt_filename_benign_paths'   # Phase 140
$HUNT_MEMORY_BENIGN_RE  = Join-AllowRegex 'hunt_memory_benign_paths'       # Phases 141/143
# ── WS7 phases 147 / 157 / 158 / 159 (2026-08-30) ────────────────────────────
# Same contract as every block above: detection lists via Get-Sig, FP allowlists via
# Join-AllowRegex (missing key -> '(?!)', which suppresses nothing). The *_raw lists hold
# $env: variables and are expanded HERE, once, rather than in the phase body.
$CLOUD_CRED_PATHS         = @((Get-Sig 'cloud_cred_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$CLOUD_CRED_NEVER_READ    = Get-Sig 'cloud_cred_never_read'                # Phase 147
$CLOUD_CRED_TEXT_FORMATS  = Get-Sig 'cloud_cred_text_formats'              # Phase 147
$CLOUD_CRED_CONTENT_RULES = Get-Sig 'cloud_cred_content_rules'             # Phase 147
$CLOUD_CRED_STAGING_DIRS  = @((Get-Sig 'cloud_cred_staging_dirs_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$CLOUD_CRED_STAGED_NAMES  = Get-Sig 'cloud_cred_staged_names'              # Phase 147
$CLOUD_CRED_ACCESS_TOOLS  = Get-Sig 'cloud_cred_access_tools'              # Phase 147
$CLOUD_CRED_BENIGN_RE     = Join-AllowRegex 'cloud_cred_benign_paths'      # Phase 147
$PERSIST_DROPPER_EXTS     = @((Get-Sig 'persist_dropper_extensions') | ForEach-Object { "$_".ToLower() })
$PERSIST_DROPPER_RULES    = Get-Sig 'persist_dropper_content_rules'        # Phase 157
$PERSIST_PROFILER_BENIGN_RE = Join-AllowRegex 'persist_profiler_benign_names'        # Phase 157
$PERSIST_DLL_BENIGN_RE      = Join-AllowRegex 'persist_dll_benign_paths'             # Phase 157
$PERSIST_TRIGGER_BENIGN_RE  = Join-AllowRegex 'persist_service_trigger_benign_names' # Phase 157
$DEVTOOL_PATHS            = @((Get-Sig 'devtool_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$DEVTOOL_HOOK_RULES       = Get-Sig 'devtool_hook_rules'                   # Phase 158
$DEVTOOL_GITCONFIG_RULES  = Get-Sig 'devtool_gitconfig_rules'              # Phase 158
$DEVTOOL_STARTUP_RULES    = Get-Sig 'devtool_vscode_startup_rules'         # Phase 158
$DEVTOOL_REGISTRY_RULES   = Get-Sig 'devtool_registry_rules'               # Phase 158
$DEVTOOL_BENIGN_RE        = Join-AllowRegex 'devtool_benign_paths'         # Phase 158
$ESP_EXPECTED_PATHS       = Get-Sig 'esp_expected_paths'                   # Phase 159
$ESP_BOOT_BINARIES        = @((Get-Sig 'esp_boot_binaries') | ForEach-Object { "$_".ToLower() })
$BCD_UNSAFE_FLAGS         = Get-Sig 'bcd_unsafe_flags'                     # Phase 159
# Object, not a list: Get-Sig always wraps, so index through @(...) — a bare [0] on a
# single-element return would index the first CHARACTER of a string (CLAUDE.md 5.1 rule).
$DBX_BASELINE             = @(Get-Sig 'dbx_current_baseline')[0]           # Phase 159
# ── WS7 phase 146 — PE structural analysis (2026-08-30) ──────────────────────
$PE_SCAN_ROOTS_HOT        = @((Get-Sig 'pe_scan_roots_hot_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$PE_SCAN_ROOTS_APP        = @((Get-Sig 'pe_scan_roots_app_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$PE_EXTENSIONS            = @((Get-Sig 'pe_extensions') | ForEach-Object { "$_".ToLower() })
$PE_PROBE_EXTENSIONS      = @((Get-Sig 'pe_probe_extensions') | ForEach-Object { "$_".ToLower() })
$PE_PACKER_SECTIONS       = Get-Sig 'pe_packer_section_names'              # Phase 146 S3
$PE_IMPORT_TRIADS         = Get-Sig 'pe_import_triads'                     # Phase 146 S9
$PE_MASQUERADE_NAMES      = Get-Sig 'pe_masquerade_names'                  # Phase 146 C5
# pe_transient_paths is a POSITIVE match list, so it is joined HERE rather than through
# Join-AllowRegex. Join-AllowRegex fails closed to '(?!)' on a missing key — correct for a
# suppression list, exactly wrong for this one, where failing closed would silently switch
# off a scoring signal instead of making the phase noisy.
$PE_TRANSIENT_RE          = if (@(Get-Sig 'pe_transient_paths').Count) {
    '(' + ((@(Get-Sig 'pe_transient_paths')) -join '|') + ')'
} else { '(?!)' }
$PE_PACKER_BENIGN_RE      = Join-AllowRegex 'pe_packer_benign_paths'       # Phase 146
# Object, not a list — index through @(...) so a single-element return is not indexed as a string.
$PE_SCORE                 = @(Get-Sig 'pe_score_thresholds')[0]            # Phase 146
# Native binaries that never host managed code. Anchored to the whole process NAME
# (System.Diagnostics.Process.Name carries no extension), because an unanchored
# substring would match e.g. "notepad++" and half of Program Files — the exact class
# of bug that auto-killed healthy signed apps in Phase 47 (CLAUDE.md path-anchoring rule).
$KILLCHAIN_STAGES = Get-Sig 'killchain_stages'                             # Phase 160
# Core Windows image names, anchored to a whole filename. Phase 144 flags a process
# carrying one of these names while running from outside a system directory.
$SYSTEM_IMAGE_NAMES_RE = if (@(Get-Sig 'system_image_names').Count) {
    '^(' + ((@(Get-Sig 'system_image_names') | ForEach-Object { [regex]::Escape("$_") }) -join '|') + ')$'
} else { '(?!)' }
$CLR_UNEXPECTED_HOSTS_RE = if (@(Get-Sig 'clr_unexpected_hosts').Count) {
    '^(' + ((@(Get-Sig 'clr_unexpected_hosts') | ForEach-Object { [regex]::Escape("$_") }) -join '|') + ')$'
} else { '(?!)' }

# ── WS7 phases 148-152 — lateral movement / credential dumping / AD (task F2) ─
# Same contract as every block above. The *_raw list is expanded HERE, once.
$LATERAL_EXEC_PARENTS     = Get-Sig 'lateral_remote_exec_parents'          # Phase 148
$LATERAL_EXEC_CHILDREN    = @((Get-Sig 'lateral_remote_exec_children') | ForEach-Object { "$_".ToLower() })
$LATERAL_DCOM_RULES       = Get-Sig 'lateral_dcom_rules'                   # Phase 148
$LATERAL_TASK_RULES       = Get-Sig 'lateral_remote_task_rules'            # Phase 148
$LATERAL_ADMIN_SHARES     = @((Get-Sig 'lateral_admin_shares') | ForEach-Object { "$_".ToLower() })
$LATERAL_EXEC_BENIGN_RE   = Join-AllowRegex 'lateral_remote_exec_benign_cmdlines'  # Phase 148
$LATERAL_SRC_BENIGN_RE    = Join-AllowRegex 'lateral_share_benign_sources'         # Phase 148
$CREDDUMP_CMDLINE_RULES   = Get-Sig 'creddump_cmdline_rules'               # Phase 149
$CREDDUMP_HIVE_NAMES      = Get-Sig 'creddump_hive_names'                  # Phase 149
$CREDDUMP_HIVE_BENIGN_RE  = Join-AllowRegex 'creddump_hive_benign_paths'   # Phase 149
$CREDDUMP_SEARCH_ROOTS    = @((Get-Sig 'creddump_search_roots_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$CREDDUMP_THRESH          = @(Get-Sig 'creddump_thresholds')[0]            # Phase 149
$KERB_THRESH              = @(Get-Sig 'kerberos_ticket_thresholds')[0]     # Phase 150
$KERB_ETYPE_RULES         = Get-Sig 'kerberos_weak_etype_rules'            # Phase 150
$KERB_ETYPE_BENIGN_RE     = Join-AllowRegex 'kerberos_etype_benign_services'       # Phase 150
$OUTBOUND_SESSION_KEYS    = Get-Sig 'outbound_session_keys'                # Phase 151
$OUTBOUND_SECRET_NAMES    = Get-Sig 'outbound_session_secret_names'        # Phase 151
$OUTBOUND_SESSION_FILES   = @((Get-Sig 'outbound_session_files_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$OUTBOUND_FILE_RULES      = Get-Sig 'outbound_session_file_rules'          # Phase 151
$OUTBOUND_BENIGN_RE       = Join-AllowRegex 'outbound_session_benign_paths'        # Phase 151
$LOGON_THRESH             = @(Get-Sig 'logon_anomaly_thresholds')[0]       # Phase 152
$LOGON_ACCT_BENIGN_RE     = Join-AllowRegex 'logon_benign_accounts'        # Phase 152
$LOGON_EXPLICIT_BENIGN_RE = Join-AllowRegex 'logon_explicit_cred_benign_procs'     # Phase 152

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
$LOADER_PROCS              = Get-Sig 'loader_procs'                  # Phase 6 (loader/botnet proc IOC)
$BANKING_TROJAN_PROCS      = Get-Sig 'banking_trojan_procs'          # Phase 6 (banking-trojan proc IOC)
$C2_PIPE_PATTERNS          = Get-Sig 'c2_pipe_patterns'              # Phase 62 (framework-name pipe pass)
$C2_CONFIG_RULES           = Get-Sig 'c2_config_rules'               # Phase 68 (C2 artifact filename rules)
$LOADER_DROP_PATH_RULES    = Get-Sig 'loader_drop_path_rules'        # Phase 68 (family drop-path rules)
$BYOVD_CERT_TBS_HASHES     = Get-Sig 'byovd_cert_tbs_hashes'         # Phase 55.5 (cert-TBS confirm)
$INFOSTEALER_TARGET_PATHS  = @((Get-Sig 'infostealer_target_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })  # Phase 100
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

# ── WS6 expansion (2026-08-19) — phases 116-133, engine/Phases-4.ps1 ──────────
# "More malware families + the files/apps that actually get modified." Everything
# below is DATA (AMSI-safe); the new phases are DEEP+ only and, per CLAUDE.md rule
# #1, every finding they raise is FixAction Info/Quarantine/DeleteReg-on-a-clearly-
# malicious-value — none is a destructive auto-select on a healthy box.
$BROWSER_POLICY_KEYS       = Get-Sig 'browser_policy_keys'           # Phase 116
$BROWSER_POLICY_DISABLE    = Get-Sig 'browser_policy_disable_values' # Phase 116
$BROWSER_PREF_RULES        = Get-Sig 'browser_pref_rules'            # Phase 116
$FIREFOX_POLICY_RULES      = Get-Sig 'firefox_policy_rules'          # Phase 116
$BROWSER_ARG_ABUSE_RULES   = Get-Sig 'browser_arg_abuse_rules'       # Phase 116/117/118
$NATIVE_MSG_KEYS           = Get-Sig 'native_messaging_keys'         # Phase 117
$LNK_HIJACK_RULES          = Get-Sig 'lnk_hijack_rules'              # Phase 118
$SIDELOAD_DLL_NAMES        = @((Get-Sig 'sideload_dll_names') | ForEach-Object { "$_".ToLower() })   # Phase 119
$SIDELOAD_SCAN_ROOTS       = @((Get-Sig 'sideload_scan_roots_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$ELECTRON_APP_PATHS        = @((Get-Sig 'electron_app_paths_raw') | ForEach-Object { @{ Path = $ExecutionContext.InvokeCommand.ExpandString($_.path); App = $_.app } })  # Phase 120
$ELECTRON_TAMPER_RULES     = Get-Sig 'electron_tamper_rules'         # Phase 120
$OFFICE_ADDIN_KEYS         = Get-Sig 'office_addin_keys'             # Phase 121
$OFFICE_PERF_KEYS          = Get-Sig 'office_perf_keys'              # Phase 121
$OFFICE_TEMPLATE_PATHS     = @((Get-Sig 'office_template_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$OFFICE_ADDIN_EXTENSIONS   = @((Get-Sig 'office_addin_extensions') | ForEach-Object { "$_".ToLower() })
$MONITORED_APP_ROOTS       = @((Get-Sig 'monitored_app_roots_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })  # Phase 122
$EXEC_EVIDENCE_SUSPECT_RE  = if (@(Get-Sig 'exec_evidence_suspect_path_regex').Count) { @(Get-Sig 'exec_evidence_suspect_path_regex')[0] } else { '(?!)' }  # Phase 123
$CLICKFIX_RUNMRU_RULES     = Get-Sig 'clickfix_runmru_rules'         # Phase 124
$MRU_FORENSIC_KEYS         = Get-Sig 'mru_forensic_keys'             # Phase 124
$CLIPPER_WALLET_RULES      = Get-Sig 'clipper_wallet_rules'          # Phase 125
$CLIPPER_API_RULES         = Get-Sig 'clipper_api_rules'             # Phase 125
$EXTENDED_AUTOSTART_POINTS = Get-Sig 'extended_autostart_points'     # Phase 126
$WINSOCK_LSP_BENIGN        = @((Get-Sig 'winsock_lsp_benign') | ForEach-Object { "$_".ToLower() })   # Phase 126
$SHELL_EXTENSION_KEYS      = Get-Sig 'shell_extension_keys'          # Phase 127
$REMOTE_ACCESS_PRODUCTS    = Get-Sig 'remote_access_products'        # Phase 128
$REMOTE_ACCESS_PARTNERS    = @((Get-Sig 'remote_access_partner_vendors') | ForEach-Object { "$_".ToLower() })
$REMOTE_ACCESS_SUSP_CTX    = Get-Sig 'remote_access_suspicious_context'
$EXFIL_STAGING_TOOLS       = Get-Sig 'exfil_staging_tools'           # Phase 129
$EXFIL_CONFIG_RULES        = Get-Sig 'exfil_config_rules'            # Phase 129
$EXFIL_ARCHIVE_RULES       = Get-Sig 'exfil_archive_rules'           # Phase 129
$WEBHOOK_C2_RULES          = Get-Sig 'webhook_c2_rules'              # Phase 130
$PACKED_SCRIPT_INDICATORS  = Get-Sig 'packed_script_indicators'      # Phase 131
$WEBSHELL_ROOTS            = @((Get-Sig 'webshell_roots_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })  # Phase 132
$WEBSHELL_EXTENSIONS       = @((Get-Sig 'webshell_extensions') | ForEach-Object { "$_".ToLower() })
$WEBSHELL_CONTENT_RULES    = Get-Sig 'webshell_content_rules'        # Phase 132
$WIPER_PROCS               = Get-Sig 'wiper_procs'                   # Phase 133
$DESTRUCTIVE_BEHAVIOR_RULES= Get-Sig 'destructive_behavior_rules'    # Phase 133
$LATERAL_MOVEMENT_ARTIFACTS= Get-Sig 'lateral_movement_artifacts'    # Phase 133

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
    catch { $PERM = $null; Write-Host "[Scythe] WARNING: could not parse $PermPath ($($_.Exception.Message))" -ForegroundColor Red }
} else {
    $PERM = $null
    Write-Host "[Scythe] WARNING: permission baseline missing: $PermPath - permission/integrity phases limited." -ForegroundColor Yellow
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
# ── Per-file Authenticode memo (WS4, 2026-08-19) ─────────────────────────────
# THE most expensive single operation in the engine: Get-AuthenticodeSignature builds the
# full certificate chain, which by default performs ONLINE revocation checks (CRL/OCSP).
# On a box whose network is slow, filtered or (very much the point of this tool) actively
# tampered with, each call blocks for the timeout.
#
# 14 call sites across 13 phases verify OVERLAPPING file sets — Temp/Downloads/AppData
# binaries are re-verified by the Temp sweep, the persistence phases, the infostealer
# scan, the hollow-process scan and the leaked-cert scan, so the same handful of files is
# paid for five or six times. Memoise on the full path.
#
# Scan-scoped by construction: the engine is audit-only under -Auto and spawns fresh per
# scan, so a file's signature cannot change underneath a run. Shares the SCYTHE_NOCACHE
# kill-switch with the other memos. $null (unreadable/locked file) is cached too — that is
# a real, repeatable answer and re-asking costs the same timeout.
$global:AUTHSIG_CACHE      = @{}
$global:AUTHSIG_CACHE_HITS = 0
$global:AUTHSIG_CACHE_MAX  = 20000   # bound the memo: a signature object holds a cert chain

function Get-AuthSig([string]$Path) {
    # Safe wrapper. Get-AuthenticodeSignature throws a *terminating* error on a
    # locked / in-use file, which -ErrorAction SilentlyContinue does NOT suppress;
    # left unhandled it unwinds to a trap and skips phases. Catch it here so callers
    # just get $null. -LiteralPath also avoids wildcard expansion on bracketed paths.
    if (-not $Path) { return $null }
    $ck = "$Path".ToLowerInvariant()
    if ($global:SCAN_FILE_CACHE_ON -and $global:AUTHSIG_CACHE.ContainsKey($ck)) {
        $global:AUTHSIG_CACHE_HITS++
        return $global:AUTHSIG_CACHE[$ck]
    }
    $sigResult = $null
    try { $sigResult = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop } catch { $sigResult = $null }
    if ($global:SCAN_FILE_CACHE_ON -and $global:AUTHSIG_CACHE.Count -lt $global:AUTHSIG_CACHE_MAX) {
        $global:AUTHSIG_CACHE[$ck] = $sigResult
    }
    return $sigResult
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
function Get-RegVal64 {
    # Read a value through the explicit 64-bit registry view, bypassing WOW64 redirection.
    # Get-ItemPropertyValue has no -View parameter, so a 32-bit engine reading
    # HKLM:\SOFTWARE\...\Run silently gets Wow6432Node's copy and misses the real one
    # (ADVERSARY_ANALYSIS.md E2). Hive is 'LocalMachine' | 'CurrentUser' | 'Users' |
    # 'ClassesRoot'; SubKey is the path WITHOUT the hive prefix. Returns $null on any
    # failure, exactly like Get-RegVal — never throws into the resilience trap.
    param([string]$Hive, [string]$SubKey, [string]$Name)
    $base = $null; $key = $null
    try {
        $h = [Microsoft.Win32.RegistryHive]::$Hive
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, [Microsoft.Win32.RegistryView]::Registry64)
        $key  = $base.OpenSubKey($SubKey)
        if ($null -eq $key) { return $null }
        return $key.GetValue($Name)
    } catch { return $null }
    finally {
        if ($key)  { try { $key.Close()  } catch {} }
        if ($base) { try { $base.Close() } catch {} }
    }
}
function Get-RegNames64 {
    # Value names under a key, through the 64-bit view. Returns @() on failure.
    param([string]$Hive, [string]$SubKey)
    $base = $null; $key = $null
    try {
        $h = [Microsoft.Win32.RegistryHive]::$Hive
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, [Microsoft.Win32.RegistryView]::Registry64)
        $key  = $base.OpenSubKey($SubKey)
        if ($null -eq $key) { return @() }
        return @($key.GetValueNames())
    } catch { return @() }
    finally {
        if ($key)  { try { $key.Close()  } catch {} }
        if ($base) { try { $base.Close() } catch {} }
    }
}
function Get-RegSubKeys64 {
    # Subkey names under a key, through the 64-bit view. Returns @() on failure.
    param([string]$Hive, [string]$SubKey)
    $base = $null; $key = $null
    try {
        $h = [Microsoft.Win32.RegistryHive]::$Hive
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, [Microsoft.Win32.RegistryView]::Registry64)
        $key  = $base.OpenSubKey($SubKey)
        if ($null -eq $key) { return @() }
        return @($key.GetSubKeyNames())
    } catch { return @() }
    finally {
        if ($key)  { try { $key.Close()  } catch {} }
        if ($base) { try { $base.Close() } catch {} }
    }
}
function ConvertTo-CsvSafeCell {
    # Neutralise CSV/Excel formula injection (audit H8). Correct CSV quoting does NOT
    # help: Excel strips the quotes and then evaluates a leading = + - @ tab or CR as a
    # formula. The Description column is malware-controlled text (file names, task
    # names, registry values), and exporting findings to CSV and mailing them to a
    # client is this product's actual workflow — so the formula executes on a DIFFERENT
    # machine than the one being remediated. Mirror of the server's copy in
    # Scythe-Server.ps1; keep both in sync.
    param([string]$Value)
    $v = "$Value"
    if ($v -match '^[=+\-@\t\r\n]') { $v = "'" + $v }
    return '"' + ($v -replace '"','""') + '"'
}
# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM-DAMAGE GUARD — THIRD COPY (audit, 2026-08-19)
#  Invoke-FixMode is the FOURTH executor in this product and until now it had none
#  of the three layers of defence the server path has: the server tags protected
#  findings, the GUI refuses to tick them, and the remediation runspace refuses to
#  run them. An operator driving the engine's own interactive fix mode on a client
#  machine had no such backstop at all. These are mirrors of ConvertTo-GuardPath /
#  Test-DestructiveRunCmd / Test-ProtectedTarget in Scythe-Server.ps1 — the three
#  copies MUST stay in sync, and tools/tests/Test-GuardMirrorSync.ps1 fails if they
#  diverge on any vector. Read the server's copies for the reasoning behind each rule.
# ══════════════════════════════════════════════════════════════════════════════
$global:RUNCMD_DESTRUCTIVE_E = @(
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
$global:RUNCMD_MUTATING_E = '(?i)(Remove-Item|Remove-ItemProperty|Rename-Item|Move-Item|Set-Content|Add-Content|Clear-Content|Out-File|New-Item|Copy-Item|Set-Acl|Invoke-Expression|\biex\b|Start-Process|\bicacls\b|\btakeown\b|\battrib\b|\bcacls\b|\b(del|erase|rd|rmdir|move|ren|rename|copy|xcopy|robocopy)\s|\breg(\.exe)?\s+(delete|add)\b|\bcmd(\.exe)?\b|\bpowershell(\.exe)?\b|\bpwsh(\.exe)?\b|>)'
$global:KILL_CRITICAL_NAME_RX_E = '(?i)^(System|smss|csrss|wininit|winlogon|services|lsass|svchost|dwm|fontdrvhost|explorer|powershell|pwsh|conhost|RuntimeBroker|MsMpEng)(\.exe)?$|(?i)(claude|scythe)'
$global:KILL_CRITICAL_DESC_RX_E = '(?i)(\b(System|smss|csrss|wininit|winlogon|services|lsass|svchost|dwm|fontdrvhost|explorer|powershell|pwsh|conhost|RuntimeBroker|MsMpEng)\b|claude|scythe)'

function ConvertTo-EGuardPath {
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

function Test-EDestructiveRunCmd {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return '' }
    foreach ($r in $global:RUNCMD_DESTRUCTIVE_E) {
        if ($Cmd -match $r.rx) { return $r.why }
    }
    return ''
}

function Test-EProtected {
    param([string]$Action, [string]$Param, [string]$Target, [string]$Desc)
    # Normalise BEFORE any pattern test (audit H7).
    $p = ConvertTo-EGuardPath "$Param"; $t = "$Target"; $d = "$Desc"
    $hay = "$p`n$t`n$d"

    # RunCmd carries a command, not a path — inspect the command itself (audit H7b).
    if ($Action -eq 'RunCmd') {
        $bad = Test-EDestructiveRunCmd "$Param"
        if ($bad) { return "destructive command — $bad" }
        # A command that only NAMES a protected path (e.g. writing the correct
        # userinit.exe value back into Winlogon) is not a write to it — see the
        # $global:RUNCMD_MUTATING_E comment. No mutating verb, no path check.
        if ("$Param" -notmatch $global:RUNCMD_MUTATING_E) { return '' }
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
            if ($kpName -match $global:KILL_CRITICAL_NAME_RX_E) { return 'critical system process or the IR tool itself' }
        } elseif ($d -match $global:KILL_CRITICAL_DESC_RX_E) {
            return 'critical system process or the IR tool itself'
        }
    }
    return ''
}

function Get-KillParam {
    # Builds the FixParam for a KillProcess finding. A bare PID is not enough: the
    # operator remediates minutes or hours after the scan, and Windows recycles PIDs
    # freely, so "kill the miner" could kill whatever now holds that number (audit H5).
    # Bind the PID to the identity observed at detection time; both executors (the
    # server runspace and Invoke-FixMode) re-check it and skip on a mismatch.
    #
    # Format: "<pid>|<processName>|<startTimeTicks>". Falls back to a bare PID when the
    # process has already exited or its start time is unreadable (a protected process
    # denies StartTime) — the executors treat that as legacy/unverifiable and say so.
    # NOTE: never name a local $pid here — it is an automatic variable (CLAUDE.md rule).
    param($Id)
    $pidNum = 0
    if (-not [int]::TryParse("$Id", [ref]$pidNum) -or $pidNum -le 0) { return "$Id" }
    try {
        $pp = Get-Process -Id $pidNum -ErrorAction Stop
        $ticks = 0
        try { $ticks = $pp.StartTime.Ticks } catch { $ticks = 0 }
        if ($ticks -gt 0) { return ('{0}|{1}|{2}' -f $pidNum, $pp.ProcessName, $ticks) }
        return ('{0}|{1}|0' -f $pidNum, $pp.ProcessName)
    } catch { return "$pidNum" }
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
    if ($global:SIG_CACHE.ContainsKey($FilePath)) { return $global:SIG_CACHE[$FilePath] }
    $result = @{ Status='Unknown'; Signer=''; Trusted=$false; IsMs=$false; Exists=$false }
    try {
        if (Test-Path -LiteralPath $FilePath) {
            $result.Exists = $true
            # Through the wrapper on purpose: shares the Authenticode memo, and the
            # wrapper is what makes a locked file return $null instead of throwing.
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
    $global:SIG_CACHE[$FilePath] = $result
    return $result
}

# Classify a finding for the remediation selection-mode presets:
#   Recommended = high-confidence, worth acting on (CRIT/HIGH with a concrete fix)
#   Safe        = remediation will not delete user data / break the OS (reversible)
# Returns 'RECOMMENDED+SAFE','RECOMMENDED','SAFE', or '' .
function Get-FixClass { param([string]$Severity, [string]$FixAction)
    # Blast-radius classification. Tags are consumed by FixMode.ps1's "RECOMMENDED" and
    # "SAFE ONLY" presets via -match, so tag names must stay substring-distinct from each other.
    #
    # SAFE means "cannot damage the box if this finding turns out to be a false positive."
    # RunCmd is NOT safe and never was: it is arbitrary PowerShell assembled by the phases, and
    # Test-ProtectedTarget does no content inspection on it (empirically confirmed — every one of
    # vssadmin/bcdedit/cipher/wbadmin/reg-delete passes the guard untouched). Labelling it SAFE
    # put `vssadmin delete shadows /all` one click behind a button captioned "SAFE ONLY".
    # KillProcess is not data loss, but it can destabilise a live box, so it earns neither tag.
    # $destructive was previously assigned and never read — it is now load-bearing.
    $destructive = @('DeleteFile','DeleteReg','DeleteRegKey','RunCmd')  # irreversible, or arbitrary code
    $safe        = @('Info','Quarantine')                               # no-op, or reversible via the vault
    $isSafe = ($safe -contains $FixAction)
    $isDest = ($destructive -contains $FixAction)
    $isRec  = (($Severity -eq 'CRITICAL' -or $Severity -eq 'HIGH') -and $FixAction -ne 'Info')
    $tag = @()
    if ($isRec)  { $tag += 'RECOMMENDED' }
    if ($isSafe) { $tag += 'SAFE' }
    if ($isDest) { $tag += 'DESTRUCTIVE' }
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
        Write-Host "  │   [3]  DEEP      — All 133 phases  (+ APT, YARA, extended band)       │" -ForegroundColor DarkCyan
        Write-Host "  │   [4]  PARANOID  — DEEP + lower thresholds (POSSIBLE→HIGH)            │" -ForegroundColor DarkCyan
        Write-Host "  │   [5]  STEALTH   — Silent, JSON-only, no banners                      │" -ForegroundColor DarkCyan
        Write-Host "  │   [6]  HUNT      — DEEP + 134-162: memory, rootkit cross-view, AD,    │" -ForegroundColor DarkCyan
        Write-Host "  │                    cloud creds, timeline. Slowest, most thorough.     │" -ForegroundColor DarkCyan
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
                "3"  { $global:ScanMode="DEEP";     $THREAT="Deep 133-Phase APT Hunt";           break }
                "4"  { $global:ScanMode="PARANOID"; $global:PARANOID_MODE=$true; $THREAT="Paranoid 133-Phase"; break }
                "5"  { $global:ScanMode="STEALTH";  $global:STEALTH_MODE=$true;  $THREAT="Stealth JSON";       break }
                "6"  { $global:ScanMode="HUNT";     $THREAT="Threat Hunt (162 phases)";       break }
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
    "DEEP"     { @{ Min=1; Max=133; Universal=$true;  Advanced=$true;  Integrity=$true; Extended=$true } }
    "PARANOID" { @{ Min=1; Max=133; Universal=$true;  Advanced=$true;  Integrity=$true; Extended=$true } }
    "STEALTH"  { @{ Min=1; Max=133; Universal=$true;  Advanced=$true;  Integrity=$true; Extended=$true } }
    # HUNT — the threat-hunting / DFIR tier, above PARANOID. Everything DEEP runs, plus the
    # WS7 band 134-162: cross-view rootkit detection, process-memory inspection, PE structural
    # analysis, cloud+DevOps credential theft, lateral-movement and AD artifacts, anti-forensic
    # tampering, the remaining persistence surface, supply-chain/dev tooling, UEFI, and finally
    # attack-chain correlation + the super-timeline. It is deliberately NOT folded into DEEP:
    # the band walks process memory and hashes the ESP, so it costs real wall-clock and must
    # stay an explicit operator choice. PARANOID escalation is independent and still applies.
    "HUNT"     { @{ Min=1; Max=162; Universal=$true;  Advanced=$true;  Integrity=$true; Extended=$true; Hunt=$true } }
    default    { @{ Min=1; Max=80;  Universal=$false; Advanced=$false; Integrity=$false } }
}
# QUICK is now a REAL gate (BLUEPRINT §7.8). Every mode except QUICK runs the full 1-80 span
# (DEEP+ add the Universal 81-89, Advanced 90-115 and Extended 116-133). QUICK runs a reduced
# 30-phase triage set;
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
Write-Log "SCYTHE V22 AUDIT START | $HOST_NAME | $(Get-Date) | MODE:$($global:ScanMode) | WINDOW:$($global:TW_LABEL) | PARANOID:$($global:PARANOID_MODE)"

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
#  ENGINE MODULES — dot-sourced in execution order into THIS scope (variables,
#  functions and the resilience trap all carry across module boundaries exactly
#  as they did inline). Split at section banners; phases stay in numeric order.
#  RULES (see CLAUDE.md):
#   • any `exit` inside engine/*.ps1 that must stop the ENGINE has to be
#     [Environment]::Exit(N) — a plain `exit` in a dot-sourced file only returns
#     to this loader, which then runs the NEXT module (hangs -Auto on FixMode).
#   • $PSScriptRoot inside engine/*.ps1 resolves to engine\, not the project
#     root — use $global:SCYTHE_ROOT (set near the top of this loader) instead.
#   • every module keeps its UTF-8 BOM.
# ══════════════════════════════════════════════════════════════════════════════
. "$PSScriptRoot\engine\Phases-0.ps1"
. "$PSScriptRoot\engine\Phases-1.ps1"
. "$PSScriptRoot\engine\Phases-2.ps1"
. "$PSScriptRoot\engine\Phases-3.ps1"
. "$PSScriptRoot\engine\Phases-4.ps1"
. "$PSScriptRoot\engine\Phases-5.ps1"
. "$PSScriptRoot\engine\Phases-6.ps1"
. "$PSScriptRoot\engine\Phases-7.ps1"
. "$PSScriptRoot\engine\Summary.ps1"
. "$PSScriptRoot\engine\FixMode.ps1"
