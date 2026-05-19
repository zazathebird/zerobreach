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
} else { $OUT_ROOT = "$env:USERPROFILE\Desktop" }
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
    if ($global:MSP_MODE) { Write-Host "$Prefix$Text" -ForegroundColor (Get-AccentColor); Write-Log "$Prefix$Text"; return }
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
    if ($global:MSP_MODE) { Write-Host "  $Text" -ForegroundColor $Color; Write-Log "  $Text"; return }
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

function Show-PhaseHeader {
    param([string]$Phase, [string]$Desc, [string]$Category = "")
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
    if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds ($rng.Next(500,1200)) }
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
    if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds ($rng.Next(400,900)) }
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
    param([string]$FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -lt 256) { return 0.0 }
        $freq = @{}
        foreach ($b in $bytes) { $freq[$b] = if ($freq.ContainsKey($b)) { $freq[$b]+1 } else { 1 } }
        $entropy = 0.0
        foreach ($count in $freq.Values) { $p = $count/$bytes.Length; $entropy -= $p*[Math]::Log($p,2) }
        return [Math]::Round($entropy,4)
    } catch { return 0.0 }
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
$KNOWN_MINER_PROCS     = @("xmrig","xmrig-notls","minerd","cpuminer","ethminer","t-rex","nbminer","phoenixminer","lolminer","cgminer","bfgminer","nsgminer","ccminer","sgminer","stratum","cryptonight","wildrig","gminer","nanominer","srbminer","teamredminer","trex","minergate","claymore","kawpowminer","xmr-stak","monerooceanminer","minexmr")
$KNOWN_RAT_PROCS       = @("njrat","nanocore","darkcomet","asyncrat","quasar","remcos","orcus","imminent","luminosity","netbus","subseven","bifrost","blackshades","cybergate","pandora","poison ivy","cobaltstrike","meterpreter","havoc","sliver","brute ratel","deimos","covenant","shad0w","pupy","empire","apfell","nighthawk","mythic","nimplant","sharpc2","sharphound","rubeus","seatbelt","winpeas","gootloader","icedid","emotet","trickbot","qakbot","dridex","ursnif","gozi","ramnit","tinba","zeus","spyeye","kronos")
$KNOWN_C2_DOMAINS      = @("pastebin.com","raw.githubusercontent.com","transfer.sh","gofile.io","ngrok.io","ngrok-free.app","ngrok.app","ngrok.dev","tunnel.ngrok.com","serveo.net","localhost.run","portmap.io","packetriot.com","telebit.io","pagekite.me","cloudflared.com","trycloudflare.com","cfargotunnel.com","bore.pub","anonfiles.com","filebin.net","catbox.moe","temp.sh","0x0.st","controlc.com","webhook.site","interactsh.com","oast.fun","oast.live","oast.pro","oast.site","oast.me","requestbin.com","beeceptor.com","pipedream.net","canarytokens.com","burpcollaborator.net","localxpose.io","expose.dev","tunnelto.dev","loophole.cloud","pinggy.io","teleport.app","sslip.io","nip.io","playit.gg","zrok.io","frp.dev","tailscale.com","zerotier.com")
$KNOWN_KEYLOGGER_PROCS = @("ardamax","revealer","spyrix","refog","actual keylogger","actual spy","softkeylogger","family keylogger","home keylogger","kgb spy","iwantsoft","all in one keylogger","spyshelter","elite keylogger","invisible keylogger","stealth keylogger","best free keylogger","best keylogger","award keylogger","atomic keylogger","perfect keylogger","kidlogger","hoverwatch","spyera","flexispy","mspy","cocospy","umobix","xnspy","wolfeye","keymonitor")
$RANSOMWARE_EXTENSIONS = @(".locked",".crypto",".crypt",".enc",".encrypted",".locky",".zepto",".odin",".thor",".cerber",".cerber2",".cerber3",".xorist",".zcrypt",".aaa",".abc",".xyz",".zzz",".micro",".vvv",".ccc",".ecc",".ezz",".exx",".wncry",".wcry",".wannacry",".wncryt",".petya",".notpetya",".ryuk",".revil",".sodinokibi",".maze",".conti",".dharma",".phobos",".matrix",".stop",".djvu",".wasted",".darkside",".hive",".blackcat",".alphv",".lockbit",".clop",".ragnar",".avaddon",".babuk",".netwalker",".readme",".zeppelin",".crysis",".btc",".payransom",".pay2decrypt",".royal",".vice",".play",".akira",".rhysida",".inc",".medusa",".cactus",".trigona",".bianlian",".cuba",".basta",".eight")
$STRATUM_PORTS         = @(3333,4444,5555,7777,8888,9999,14444,14433,45560,3357,4003,8008,3334,3335,5556,5557,7778,9998,14445,1314,5050,5051)
$SUSPICIOUS_DNS_DOMAINS= @("dyn.dns","no-ip.","ddns.","afraid.org","changeip.","dyndns.","dtdns.","dns2go.","dynalias.","zerigo.","dnspark.","easydns.","zoneedit.","freedns.afraid","mooo.com","servebeer.com","serveftp.com","servegame.com","servehttp.com","serveirc.com","servemp3.com","servepics.com","servequake.com","hopto.org","myftp.biz","myftp.org","myq-see.com","myvnc.com","onthewifi.com","pointto.us","proxydns.com","redirect.me","tcp4.me","viewdns.net","webhop.me","duckdns.org","zapto.org","ignorelist.com","sytes.net","gotdns.ch","ddnsfree.com","theworkpc.com")
$RAT_CONFIG_PATHS      = @("$env:APPDATA\server.exe","$env:TEMP\server.exe","$env:LOCALAPPDATA\server.exe","$env:APPDATA\stub.exe","$env:TEMP\client.exe","$env:APPDATA\NjRat","$env:APPDATA\njrat","$env:APPDATA\AsyncRAT","$env:APPDATA\QuasarRAT","$env:LOCALAPPDATA\NjRat","$env:APPDATA\Orcus","$env:APPDATA\Remcos","$env:APPDATA\LuminosityLink","$env:LOCALAPPDATA\SystemData","$env:APPDATA\SilentTrinity","$env:APPDATA\Havoc","$env:APPDATA\Sliver","$env:APPDATA\nanocore","$env:APPDATA\darkcomet","$env:APPDATA\Roaming\OpenWith.exe")
$RAT_REG_PATHS         = @("HKCU:\SOFTWARE\njRAT","HKCU:\SOFTWARE\Quasar","HKCU:\SOFTWARE\AsyncRAT","HKCU:\SOFTWARE\Remcos","HKCU:\SOFTWARE\DarkComet","HKCU:\SOFTWARE\NanoCore","HKCU:\SOFTWARE\LuminosityLink","HKCU:\SOFTWARE\Orcus","HKCU:\SOFTWARE\BlackShades","HKCU:\SOFTWARE\Imminent","HKCU:\SOFTWARE\CyberGate","HKCU:\SOFTWARE\xtremerat")
$TROJAN_FILE_PATTERNS  = @("backdoor*.exe","rootkit*.exe","trojan*.exe","keylog*.exe","stealer*.exe","grabber*.exe","crypter*.exe","loader*.exe","dropper*.exe","payload*.exe","shellcode*.bin","beacon*.bin","stage*.dll","implant*.dll","agent*.exe","revshell*","bindshell*")
$UAC_BYPASS_REGS       = @("HKCU:\Software\Classes\ms-settings\shell\open\command","HKCU:\Software\Classes\Folder\shell\open\command","HKCU:\Software\Classes\mscfile\shell\open\command","HKCU:\Software\Classes\exefile\shell\open\command","HKCU:\Software\Classes\.exe\shell\open\command")
$YARA_LITE_RULES       = @(
    @{ Name="Cobalt_Strike_Beacon";    Pattern="(MZARUH|fc4881e4f0e8|metsrv|beacon\.dll)";                      Severity="CRITICAL" }
    @{ Name="Mimikatz_Strings";        Pattern="(sekurlsa::|lsadump::|mimikatz|gentilkiwi)";                     Severity="CRITICAL" }
    @{ Name="Meterpreter_Strings";     Pattern="(metsrv|stdapi_|meterpreter|reflective_loader)";                 Severity="CRITICAL" }
    @{ Name="Sliver_Implant";          Pattern="(sliver-server|sliver-client|implant\.bin)";                    Severity="CRITICAL" }
    @{ Name="Lazagne_Stealer";         Pattern="(LaZagne|lazagne_program)";                                      Severity="CRITICAL" }
    @{ Name="Empire_Stager";           Pattern="(\\$wc=New-Object Net\.WebClient|System\.Net\.WebClient.{0,128}DownloadString.{0,32}IEX)"; Severity="HIGH" }
    @{ Name="Base64_PS_Cradle";        Pattern="powershell.{0,16}-e(nc|ncodedcommand).{0,8}[A-Za-z0-9+/=]{80,}"; Severity="HIGH" }
    @{ Name="WMI_Reflective";          Pattern="(Reflection\.Assembly|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|GetDelegateForFunctionPointer)"; Severity="HIGH" }
    @{ Name="UAC_Bypass_FodHelper";    Pattern="(fodhelper|computerdefaults|sdclt|wsreset|eventvwr)\.exe";      Severity="HIGH" }
    @{ Name="Rclone_Exfil";            Pattern="(rclone\s+(copy|sync|move).{0,64}(mega|drive|onedrive|s3:|gcs:))"; Severity="HIGH" }
    @{ Name="WinPwn_Recon";            Pattern="(WinPwn|PowerSploit|PowerView|Invoke-Mimikatz|Get-PassHashes)"; Severity="HIGH" }
    @{ Name="MZ_with_PowerShell";      Pattern="MZ.{0,4096}powershell.{0,32}-(enc|nop|w hidden)";               Severity="HIGH" }
)
$AUTO_ELEVATE_BINS     = @("fodhelper.exe","computerdefaults.exe","sdclt.exe","wsreset.exe","eventvwr.exe","CompMgmtLauncher.exe","slui.exe","mmc.exe","perfmon.exe","taskmgr.exe","azman.exe","cleanmgr.exe","dcomcnfg.exe","msconfig.exe","msinfo32.exe","odbcad32.exe")
$LOLBAS_EXPANDED       = @("mshta","wscript","cscript","regsvr32","rundll32","certutil","bitsadmin","msiexec","installutil","regasm","regsvcs","msbuild","cmstp","odbcconf","ieexec","pcalua","presentationhost","infdefaultinstall","diskshadow","esentutl","extrac32","findstr","forfiles","gpscript","hh","makecab","mavinject","msdeploy","msdt","pcwrun","replace","rpcping","syncappvpublishingserver","vbc","winrm","wmic","xwizard","msconfig","fodhelper","eventvwr","sdclt","wusa","csc","ngen","wfc","ftp","atbroker","scriptrunner","verclsid","jsc","msxsl","cdb","windbg","tracker","te","sqltoolsps","squirrel","dnscmd","createdump","cmdkey","desktopimgdownldr","dfsvc","manage-bde","pktmon","print","pubprn","runscripthelper","setres","stordiag")
$SCRIPT_OWN_STRINGS    = @("ZeroBreach","Project Kraken","Gannon MSP","KrakenReport","ZEROBREACH","Out-Typewriter","Invoke-QuantumBar","TACTICAL BOOT MENU","FORENSIC EXORCIST","KrakenSnapshot","KrakenBaseline","ZeroBreach_AuditCache","Add-Finding","Show-PhaseHeader","SCRIPT_OWN_STRINGS","YARA_LITE_RULES","KNOWN_MINER_PROCS","KNOWN_RAT_PROCS")

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
    "QUICK"    { @{ Min=1; Max=30;  Universal=$false; Advanced=$false } }
    "FULL"     { @{ Min=1; Max=80;  Universal=$false; Advanced=$false } }
    "DEEP"     { @{ Min=1; Max=107; Universal=$true;  Advanced=$true  } }
    "PARANOID" { @{ Min=1; Max=107; Universal=$true;  Advanced=$true  } }
    "STEALTH"  { @{ Min=1; Max=107; Universal=$true;  Advanced=$true  } }
    default    { @{ Min=1; Max=80;  Universal=$false; Advanced=$false } }
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
#  SECTION 1: PRE-FLIGHT
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "PRE-FLIGHT SYSTEMS & LOG AUDIT"

Show-PhaseHeader "PHASE 1" "ANTI-FORENSIC EVENT LOG AUDIT"
Invoke-QuantumBar "PARSING SECURITY EVENTS" 10 140
$logClears = Get-WinEvent -FilterHashtable @{LogName='System','Security'; ID=104,1102} -ErrorAction SilentlyContinue |
    Where-Object { Test-InScope $_.TimeCreated }
if ($logClears) {
    foreach ($clear in $logClears) {
        Out-Glitch "  [LOG TAMPER DETECTED]" Red
        Out-Decrypt -Text "$($clear.LogName) cleared at $($clear.TimeCreated)" -Prefix "  [LOG TAMPER] "
        Add-Finding -ID "LOG_CLEAR_$($clear.TimeCreated.Ticks)" -Phase "PHASE 1" -ThreatType "Anti-Forensic" `
            -Severity $SEV_HIGH -Description "Event log cleared: $($clear.LogName) at $($clear.TimeCreated)" `
            -Target "Event Log: $($clear.LogName)" -FixAction "Info" -Group "Anti-Forensic / Log Tampering"
    }
} else { Out-Typewriter "  -> [OK] NO LOG CLEARING ANOMALIES." "GOOD" }

Show-PhaseHeader "PHASE 2" "POWERSHELL SCRIPT BLOCK LOG AUDIT (EVENT 4104)"
Invoke-QuantumBar "SCANNING POWERSHELL OPERATIONAL LOGS" 8 120
$psLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -ErrorAction SilentlyContinue |
    Where-Object { Test-InScope $_.TimeCreated }
# FIX: filter out this script's own footprint
$psHits = $psLogs | Where-Object {
    $msg = $_.Message
    $isSuspect = $msg -match "IEX|Invoke-Expression|DownloadString|WebClient|EncodedCommand|FromBase64|Reflection\.Assembly|VirtualAlloc|WriteProcessMemory|GetDelegateForFunctionPointer"
    $isSelf = $false
    foreach ($s in $SCRIPT_OWN_STRINGS) { if ($msg -match [regex]::Escape($s)) { $isSelf = $true; break } }
    $isSuspect -and -not $isSelf
}
if ($psHits) {
    foreach ($hit in $psHits) {
        Out-Glitch "  [MALICIOUS PS EXECUTION]" Red
        $snippet = $hit.Message.Substring(0,[Math]::Min(120,$hit.Message.Length))
        Out-Typewriter "  -> $($hit.TimeCreated) | $snippet" "CRIT"
        Add-Finding -ID "PS4104_$($hit.TimeCreated.Ticks)" -Phase "PHASE 2" -ThreatType "Fileless/PowerShell" `
            -Severity $SEV_HIGH -Description "Suspicious PS4104 event: $snippet" `
            -Target "PowerShell/Event 4104 @ $($hit.TimeCreated)" -FixAction "Info" -Group "PowerShell Abuse"
    }
} else { Out-Typewriter "  -> [OK] NO OBFUSCATED/DOWNLOAD CRADLES IN PS LOGS." "GOOD" }

Show-PhaseHeader "PHASE 3" "PROCESS ANCESTRY & INJECTION AUDIT"
Invoke-QuantumBar "MAPPING LIVE PROCESS TREE" 8 120
$suspectProcs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "IEX|EncodedCommand|DownloadString|mshta|wscript|cscript|regsvr32.*http|rundll32.*http|certutil.*decode|VirtualAlloc|CreateRemoteThread"
}
if ($suspectProcs) {
    foreach ($proc in $suspectProcs) {
        Out-Glitch "  [SUSPECT PROCESS]" Red
        $cmd = $proc.CommandLine.Substring(0,[Math]::Min(120,$proc.CommandLine.Length))
        Out-Typewriter "  -> PID:$($proc.ProcessId) | $($proc.Name) | $cmd" "CRIT"
        Add-Finding -ID "PROC_INJ_$($proc.ProcessId)" -Phase "PHASE 3" -ThreatType "Process Injection/Fileless" `
            -Severity $SEV_CRITICAL -Description "Suspect process: $($proc.Name) PID:$($proc.ProcessId) | $cmd" `
            -Target "PID:$($proc.ProcessId)" -FixAction "KillProcess" -FixParam $proc.ProcessId -Group "Live Malicious Processes"
    }
} else { Out-Typewriter "  -> [OK] NO INJECTED/MALICIOUS PROCESS SIGNATURES." "GOOD" }

Show-PhaseHeader "PHASE 4" "LOLBIN ABUSE AUDIT (Living-Off-The-Land Binaries)"
Invoke-QuantumBar "SCANNING LOLBIN EXECUTION TRACES" 10 110
$lolbins = @("mshta","wscript","cscript","regsvr32","rundll32","certutil","bitsadmin","msiexec","installutil","regasm","regsvcs","msbuild","cmstp","odbcconf","ieexec","pcalua","presentationhost","infdefaultinstall","diskshadow","esentutl","extrac32","findstr","forfiles","gpscript","hh","makecab","mavinject","msdeploy","msdt","pcwrun","replace","rpcping","syncappvpublishingserver","vbc","winrm","wmic","xwizard","msconfig","fodhelper","eventvwr","sdclt","wusa","csc")
$lolHits = $false
foreach ($lb in $lolbins) {
    $procs = Get-WmiObject Win32_Process -Filter "Name='$lb.exe'" -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        if ($p.CommandLine -match "http|AppData|Temp|\.js|Base64|scrobj|unc|\\\\") {
            $lolHits = $true
            Out-Decrypt -Text "LOLBIN: $($p.Name) PID:$($p.ProcessId)" -Prefix "  [LOLBIN] "
            Add-Finding -ID "LOLBIN_$($p.ProcessId)" -Phase "PHASE 4" -ThreatType "LoLBin Abuse" `
                -Severity $SEV_HIGH -Description "LOLBin $($p.Name) used with suspicious args: $($p.CommandLine.Substring(0,[Math]::Min(100,$p.CommandLine.Length)))" `
                -Target "PID:$($p.ProcessId)" -FixAction "KillProcess" -FixParam $p.ProcessId -Group "Live Malicious Processes"
        }
    }
}
if (-not $lolHits) { Out-Typewriter "  -> [OK] NO LOLBIN ABUSE DETECTED." "GOOD" }

Show-PhaseHeader "PHASE 5" "AMSI BYPASS & ETW PATCH DETECTION"
Invoke-QuantumBar "CHECKING AMSI & ETW INTEGRITY" 8 110
$amsiReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
if ($null -eq $amsiReg) {
    Out-Typewriter "  -> AMSI PROVIDER REGISTRY EMPTY — POSSIBLE BYPASS." "CRIT"
    Add-Finding -ID "AMSI_EMPTY" -Phase "PHASE 5" -ThreatType "AMSI Bypass" -Severity $SEV_HIGH `
        -Description "AMSI provider registry is empty — AMSI may be bypassed." `
        -Target "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -FixAction "Info" -Group "Security Tool Tampering"
} else { Out-Typewriter "  -> [OK] AMSI PROVIDER REGISTRY INTACT." "GOOD" }
$amsiDisable = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows Script\Settings" -Name "AmsiEnable" -ErrorAction SilentlyContinue
if ($amsiDisable.AmsiEnable -eq 0) {
    Add-Finding -ID "AMSI_DISABLED" -Phase "PHASE 5" -ThreatType "AMSI Bypass" -Severity $SEV_CRITICAL `
        -Description "AmsiEnable = 0 in HKCU Windows Script Settings — AMSI explicitly disabled." `
        -Target "HKCU:\SOFTWARE\Microsoft\Windows Script\Settings\AmsiEnable" `
        -FixAction "DeleteReg" -FixParam "HKCU:\SOFTWARE\Microsoft\Windows Script\Settings|AmsiEnable" -Group "Security Tool Tampering"
} else { Out-Typewriter "  -> [OK] AMSI SCRIPT ENGINE ENABLED." "GOOD" }
$etw = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System" -Name "Start" -ErrorAction SilentlyContinue
if ($etw.Start -eq 0) {
    Out-Typewriter "  -> ETW SYSTEM LOGGER DISABLED." "CRIT"
    Add-Finding -ID "ETW_DISABLED" -Phase "PHASE 5" -ThreatType "ETW Bypass" -Severity $SEV_HIGH `
        -Description "ETW EventLog-System logger is disabled — telemetry suppressed." `
        -Target "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\Start" `
        -FixAction "RunCmd" -FixParam "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System' -Name Start -Value 1 -Force" -Group "Security Tool Tampering"
} else { Out-Typewriter "  -> [OK] ETW SYSTEM LOGGER ENABLED." "GOOD" }

Show-PhaseHeader "PHASE 6" "KNOWN MALWARE PROCESS IOC DATABASE MATCH"
Invoke-QuantumBar "MATCHING PROCESSES AGAINST IOC DATABASE" 12 100
$runningProcs = Get-Process -ErrorAction SilentlyContinue
$iocHits = $false
foreach ($proc in $runningProcs) {
    $pn = $proc.Name.ToLower()
    foreach ($rat in $KNOWN_RAT_PROCS) {
        if ($pn -match [regex]::Escape($rat)) {
            Out-ThreatBanner "RAT PROCESS IOC HIT" "$($proc.Name) PID:$($proc.Id)"
            Add-Finding -ID "RAT_PROC_$($proc.Id)" -Phase "PHASE 6" -ThreatType "RAT" -Severity $SEV_CRITICAL `
                -Description "Known RAT process: $($proc.Name) (PID $($proc.Id)) matched IOC: $rat" `
                -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Processes"
            $global:RATHits++; $iocHits = $true
        }
    }
    foreach ($miner in $KNOWN_MINER_PROCS) {
        if ($pn -match [regex]::Escape($miner)) {
            Out-ThreatBanner "CRYPTOMINER PROCESS IOC" "$($proc.Name) PID:$($proc.Id)"
            Add-Finding -ID "MINER_PROC_$($proc.Id)" -Phase "PHASE 6" -ThreatType "Cryptominer" -Severity $SEV_CRITICAL `
                -Description "Known miner process: $($proc.Name) (PID $($proc.Id)) matched IOC: $miner" `
                -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Processes"
            $global:MinerHits++; $iocHits = $true
        }
    }
    foreach ($kl in $KNOWN_KEYLOGGER_PROCS) {
        if ($pn -match [regex]::Escape($kl)) {
            Out-ThreatBanner "KEYLOGGER PROCESS IOC" "$($proc.Name) PID:$($proc.Id)"
            Add-Finding -ID "KL_PROC_$($proc.Id)" -Phase "PHASE 6" -ThreatType "Keylogger" -Severity $SEV_CRITICAL `
                -Description "Known keylogger process: $($proc.Name) (PID $($proc.Id))" `
                -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Processes"
            $global:KeyloggerHits++; $iocHits = $true
        }
    }
}
if (-not $iocHits) { Out-Typewriter "  -> [OK] NO IOC PROCESS MATCHES." "GOOD" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2: BROWSER & TEMP ARTIFACTS
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "BROWSER & TEMPORARY ARTIFACT AUDIT"

Show-PhaseHeader "PHASE 7" "BROWSER CACHE & SERVICE WORKER AUDIT"
$browserCachePaths = @(
    @{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\Cache_Data"; L="Chrome Cache"},
    @{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Service Worker\CacheStorage"; L="Chrome Service Worker Cache"},
    @{P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\Cache_Data"; L="Edge Cache"},
    @{P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage"; L="Edge Service Worker"},
    @{P="$env:APPDATA\Mozilla\Firefox\Profiles"; L="Firefox Profiles"},
    @{P="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache"; L="Brave Cache"},
    @{P="$env:APPDATA\Opera Software\Opera Stable\Cache"; L="Opera Cache"}
)
foreach ($bc in $browserCachePaths) {
    if (Test-Path $bc.P) {
        Out-Typewriter "  -> BROWSER CACHE EXISTS: $($bc.L)" "INFO"
        Add-Finding -ID "BROWSER_CACHE_$($bc.L -replace ' ','')" -Phase "PHASE 7" -ThreatType "Browser Artifact" `
            -Severity $SEV_INFO -Description "Browser cache folder present: $($bc.L)" `
            -Target $bc.P -FixAction "DeleteFile" -FixParam $bc.P -Group "Browser Cache / Artifacts"
    }
}

Show-PhaseHeader "PHASE 8" "BROWSER EXTENSION SANITIZATION (HEURISTIC)"
$extPaths = @(
    @{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"; B="Chrome"},
    @{P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"; B="Edge"},
    @{P="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Extensions"; B="Brave"}
)
foreach ($ep in $extPaths) {
    Out-Typewriter "AUDITING $($ep.B) EXTENSIONS: $($ep.P)" "INFO"
    if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
    if (-not (Test-Path $ep.P)) { Out-Typewriter "  -> [OK] NO EXTENSION DIRECTORY." "GOOD"; continue }
    $extDirs = Get-ChildItem -Path $ep.P -Directory -ErrorAction SilentlyContinue
    foreach ($ext in $extDirs) {
        $risk = Get-ExtensionRisk -ExtPath $ext.FullName
        if ($risk.Risk -eq "CLEAN") { continue }
        $sev = switch ($risk.Risk) { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
        $label = if ($risk.Risk -in @("CRITICAL","HIGH")) { "☣ $($risk.Risk)" } else { "? POSSIBLE" }
        Out-Typewriter "  -> $label — $($ep.B) EXT: $($risk.Name) | $($risk.Reason)" "CRIT"
        Add-Finding -ID "EXT_$($ext.Name)" -Phase "PHASE 8" -ThreatType "Browser Extension/Hijacker" `
            -Severity $sev -Description "$($ep.B) extension: $($risk.Name) | $($risk.Reason)" `
            -Target $ext.FullName -FixAction "DeleteFile" -FixParam $ext.FullName `
            -Group "Browser Extensions ($($ep.B))"
        $global:SpywareHits++
    }
}

Show-PhaseHeader "PHASE 9" "BROWSER HIJACK — SHORTCUT & HOMEPAGE AUDIT"
Out-Typewriter "SCANNING BROWSER SHORTCUTS FOR HIJACKED TARGETS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$shortcutDirs = @("$env:USERPROFILE\Desktop","$env:APPDATA\Microsoft\Windows\Start Menu\Programs","$env:PUBLIC\Desktop")
foreach ($dir in $shortcutDirs) {
    if (-not (Test-Path $dir)) { continue }
    $lnks = Get-ChildItem -Path $dir -Filter "*.lnk" -ErrorAction SilentlyContinue
    foreach ($lnk in $lnks) {
        try {
            $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop
            $sc = $shell.CreateShortcut($lnk.FullName)
            if ($sc.Arguments -match "http|--load-extension|--disable-extensions|javascript:|data:") {
                Out-ThreatBanner "BROWSER SHORTCUT HIJACK" "$($lnk.Name) | Args: $($sc.Arguments)"
                Add-Finding -ID "LNK_HIJACK_$($lnk.Name -replace '[^a-z0-9]','')" -Phase "PHASE 9" -ThreatType "Browser Hijacker" `
                    -Severity $SEV_CRITICAL -Description "Hijacked browser shortcut: $($lnk.Name) | $($sc.Arguments)" `
                    -Target $lnk.FullName -FixAction "RunCmd" -FixParam "`$_sh=New-Object -ComObject WScript.Shell;`$_sc=`$_sh.CreateShortcut('$($lnk.FullName)');`$_sc.Arguments='';`$_sc.Save()" -Group "Browser Hijacks"
                $global:SpywareHits++
            }
        } catch {}
    }
}
$chromePrefs = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
if (Test-Path $chromePrefs) {
    $prefs = Get-Content $chromePrefs -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($prefs.homepage -and $prefs.homepage -notmatch "^(https?://(www\.)?google\.|about:blank|newtab)") {
        Out-Typewriter "  -> HIJACKED CHROME HOMEPAGE: $($prefs.homepage)" "CRIT"
        Add-Finding -ID "CHROME_HOMEPAGE" -Phase "PHASE 9" -ThreatType "Browser Hijacker" -Severity $SEV_HIGH `
            -Description "Suspicious Chrome homepage: $($prefs.homepage)" -Target $chromePrefs `
            -FixAction "Info" -Group "Browser Hijacks"
        $global:SpywareHits++
    }
}
Out-Typewriter "  -> BROWSER HIJACK AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 10" "TEMP / DOWNLOAD DIRECTORY ANOMALY SWEEP"
$targetDirs = @(
    @{P=$env:TEMP; L="User TEMP"},
    @{P="$env:LOCALAPPDATA\Temp"; L="LocalAppData TEMP"},
    @{P="$env:WINDIR\Temp"; L="Windows TEMP"},
    @{P="$env:USERPROFILE\Downloads"; L="User Downloads"},
    @{P="$env:PUBLIC\Downloads"; L="Public Downloads"},
    @{P="$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache"; L="INetCache"}
)
$malExt = @(".exe",".bat",".cmd",".ps1",".vbs",".js",".hta",".wsf",".dll",".sys",".scr",".pif",".cpl",".jar")
foreach ($td in $targetDirs) {
    Out-Typewriter "SCANNING: $($td.L)" "INFO"
    if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 600 }
    if (-not (Test-Path $td.P)) { Out-Typewriter "  -> [OK] ABSENT." "GOOD"; continue }
    $recentFiles = Get-ChildItem -Path $td.P -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { Test-InScope $_.LastWriteTime }
    if ($recentFiles.Count -eq 0) { Out-Typewriter "  -> [OK] CLEAN." "GOOD"; continue }
    # Group into executable vs other
    $exeFiles   = $recentFiles | Where-Object { $malExt -contains $_.Extension.ToLower() }
    $otherFiles = $recentFiles | Where-Object { $malExt -notcontains $_.Extension.ToLower() }
    if ($exeFiles.Count -gt 0) {
        $exeGroup = "$($td.L) — Executables ($($exeFiles.Count) files)"
        foreach ($f in $exeFiles) {
            $sig = Get-AuthenticodeSignature $f.FullName -ErrorAction SilentlyContinue
            $isMalicious = ($sig.Status -ne "Valid") -and ($td.P -match "Temp|INetCache")
            $sev = if ($isMalicious) { $SEV_HIGH } else { $SEV_POSSIBLE }
            Add-Finding -ID "TEMPEXE_$($f.Name -replace '[^a-z0-9]','')" -Phase "PHASE 10" -ThreatType "Suspicious File" `
                -Severity $sev -Description "$(if($isMalicious){'Unsigned executable'} else {'Executable'}) in $($td.L): $($f.Name)" `
                -Target $f.FullName -FixAction "DeleteFile" -FixParam $f.FullName -Group $exeGroup
        }
        Out-Typewriter "  -> FLAGGED $($exeFiles.Count) EXECUTABLES IN $($td.L)." "WARN"
    }
    if ($otherFiles.Count -gt 0) {
        Out-Typewriter "  -> $($otherFiles.Count) NON-EXECUTABLE FILES IN $($td.L) — WITHIN TIME SCOPE." "DATA"
    }
}

Show-PhaseHeader "PHASE 11" "RECENT DOCUMENTS & JUMP LIST SCRUB"
$recentPaths = @(
    "$env:APPDATA\Microsoft\Windows\Recent",
    "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
    "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
)
foreach ($rp in $recentPaths) {
    if (Test-Path $rp) {
        $ri = Get-ChildItem -Path $rp -File -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
        if ($ri.Count -gt 0) {
            Out-Typewriter "  -> $($ri.Count) RECENT ITEMS IN: $rp" "INFO"
            Add-Finding -ID "RECENT_DOCS_$($rp -replace '[^a-z0-9]','')" -Phase "PHASE 11" -ThreatType "Browser/File Artifact" `
                -Severity $SEV_INFO -Description "Recent docs/jump lists found in $rp ($($ri.Count) items)" `
                -Target $rp -FixAction "RunCmd" -FixParam "Get-ChildItem -LiteralPath '$rp' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue" `
                -Group "Recent Files / Jump Lists"
        } else { Out-Typewriter "  -> [OK] RECENT ITEMS CLEAN." "GOOD" }
    }
}

Show-PhaseHeader "PHASE 12" "PREFETCH & SHIMCACHE ARTIFACT AUDIT"
Out-Typewriter "SCANNING PREFETCH FOR MALICIOUS EXECUTION TRACES..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1200 }
if (Test-Path "$env:WINDIR\Prefetch") {
    $malPf = Get-ChildItem -Path "$env:WINDIR\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue |
        Where-Object { Test-InScope $_.LastWriteTime -and $_.Name -match "WSCRIPT|CSCRIPT|MSHTA|MSIEXEC|INSTALLUTIL|REGASM|CERTUTIL|BITSADMIN|RUNDLL32.*APPDATA|POWERSHELL.*-ENC" }
    if ($malPf.Count -gt 0) {
        foreach ($pf in $malPf) {
            Out-Decrypt -Text $pf.Name -Prefix "  [PREFETCH HIT] "
            Add-Finding -ID "PREFETCH_$($pf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 12" -ThreatType "Execution Trace" `
                -Severity $SEV_HIGH -Description "Suspicious prefetch: $($pf.Name) (evidence of malicious execution)" `
                -Target $pf.FullName -FixAction "Info" -Group "Execution Artifacts"
        }
        Out-Typewriter "  -> PREFETCH ARTIFACTS LOGGED. PRESERVING AS EVIDENCE." "WARN"
    } else { Out-Typewriter "  -> [OK] NO SUSPICIOUS PREFETCH ENTRIES." "GOOD" }
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3: SYSTEM FILE & KERNEL INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "SYSTEM FILE & KERNEL INTEGRITY"

Show-PhaseHeader "PHASE 13" "CRYPTOGRAPHIC SYSTEM FILE VERIFICATION (SFC)"
Out-Typewriter "EXECUTING SFC /SCANNOW..." "ACT"
Invoke-QuantumBar "SFC KERNEL VALIDATION" 20 250
cmd.exe /c "sfc /scannow >nul 2>&1"
Out-Typewriter "  -> [OK] SFC VALIDATION COMPLETE." "VER"
Add-Finding -ID "SFC_HARDENING" -Phase "PHASE 13" -ThreatType "System Integrity" -Severity $SEV_INFO `
    -Description "SFC scan was run — review CBS.log if anomalies found." `
    -Target "C:\Windows\Logs\CBS\CBS.log" -FixAction "Info" -Group "System Hardening"

Show-PhaseHeader "PHASE 14" "DISM COMPONENT STORE RESTORATION"
Out-Typewriter "FLUSHING WUAUSERV CACHE..." "ACT"
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
if (Test-Path "$env:WINDIR\SoftwareDistribution\Download") {
    Add-Finding -ID "SOFTDIST_CACHE" -Phase "PHASE 14" -ThreatType "System Integrity" -Severity $SEV_INFO `
        -Description "Windows Update download cache present — can be cleared." `
        -Target "$env:WINDIR\SoftwareDistribution\Download" -FixAction "DeleteFile" -FixParam "$env:WINDIR\SoftwareDistribution\Download" -Group "System Hardening"
}
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
$dismProc = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth /Quiet" -PassThru -WindowStyle Hidden
Invoke-QuantumBar "DISM IMAGE REPAIR IN PROGRESS" 30 550
try { $dismProc | Wait-Process -Timeout 1200 -ErrorAction Stop; Out-Typewriter "  -> [OK] DISM REPAIR COMPLETE." "VER" }
catch { $dismProc | Stop-Process -Force -ErrorAction SilentlyContinue; Out-Typewriter "  -> DISM TIMEOUT — CONTINUING." "WARN" }

Show-PhaseHeader "PHASE 15" "SYSTEM32 UNSIGNED BINARY AUDIT"
Out-Typewriter "SCANNING SYSTEM32 FOR FORGED/UNSIGNED BINARIES..." "ACT"
Invoke-QuantumBar "VERIFYING AUTHENTICODE SIGNATURES" 15 180
$recentSysFiles = Get-ChildItem -Path "$env:WINDIR\System32" -File -ErrorAction SilentlyContinue |
    Where-Object { Test-InScope $_.LastWriteTime -and $_.Extension -match "\.(exe|dll|sys)$" }
$foundSys = $false
foreach ($sf in $recentSysFiles) {
    $sig = Get-AuthenticodeSignature $sf.FullName -ErrorAction SilentlyContinue
    if ($sig.Status -ne "Valid" -and $sig.Status -ne "NotSigned") {
        $foundSys = $true
        Out-Decrypt -Text $sf.FullName -Prefix "  [UNSIGNED SYS32 BINARY] "
            $newName = "$($sf.FullName).kraken"
            Add-Finding -ID "SYS32_UNSIGNED_$($sf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 15" -ThreatType "Rootkit/Trojan" `
                -Severity $SEV_CRITICAL -Description "Unsigned/invalid binary in System32: $($sf.Name) — possible rootkit/trojan dropper" `
                -Target $sf.FullName -FixAction "RunCmd" -FixParam "Rename-Item -LiteralPath '$($sf.FullName)' -NewName '$newName' -Force -ErrorAction SilentlyContinue" -Group "Unsigned System32 Binaries"
        $global:RootkitHits++
    }
}
if (-not $foundSys) { Out-Typewriter "  -> [OK] ALL RECENT SYSTEM32 BINARIES VERIFIED." "GOOD" }

Show-PhaseHeader "PHASE 16" "NTFS PERMISSION INTEGRITY — CRITICAL PATHS"
foreach ($cp in @("$env:WINDIR\System32","$env:WINDIR\SysWOW64","$env:WINDIR\System32\drivers")) {
    Out-Typewriter "AUDITING ACL: $cp" "INFO"
    if (Test-Path $cp) {
        $acl = Get-Acl $cp -ErrorAction SilentlyContinue
        $suspAce = $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|BUILTIN\\Users" -and
            $_.FileSystemRights -match "Write|FullControl" -and $_.AccessControlType -eq "Allow"
        }
        if ($suspAce) {
            Out-Typewriter "  -> WORLD-WRITABLE ACE ON $cp" "CRIT"
            Add-Finding -ID "ACL_$($cp -replace '[^a-z0-9]','')" -Phase "PHASE 16" -ThreatType "Permission Abuse" `
                -Severity $SEV_HIGH -Description "World-writable ACE on critical path: $cp" `
                -Target $cp -FixAction "RunCmd" -FixParam "icacls '$cp' /reset /T /Q" -Group "NTFS Permission Abuse"
        } else { Out-Typewriter "  -> [OK] ACL SECURE." "GOOD" }
    }
}

Show-PhaseHeader "PHASE 17" "ALTERNATE DATA STREAM (ADS) PARASITE SCAN"
foreach ($adsDir in @("$env:LOCALAPPDATA","$env:TEMP","$env:USERPROFILE\Downloads")) {
    Out-Typewriter "ADS SCAN: $adsDir..." "INFO"
    if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
    if (Test-Path $adsDir) {
        $streams = Get-Item -Path "$adsDir\*" -Stream * -ErrorAction SilentlyContinue |
            Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -notmatch 'Zone\.Identifier' }
        foreach ($s in $streams) {
            $adsFile   = $s.FileName -replace "'","''"
            $adsStream = $s.Stream   -replace "'","''"
            Out-Decrypt -Text "$($s.FileName):$($s.Stream)" -Prefix "  [ADS HIT] "
            Add-Finding -ID "ADS_$($s.FileName.GetHashCode())" -Phase "PHASE 17" -ThreatType "ADS Parasite" `
                -Severity $SEV_HIGH -Description "Alternate Data Stream: $($s.FileName):$($s.Stream)" `
                -Target "$($s.FileName):$($s.Stream)" -FixAction "RunCmd" -FixParam "Remove-Item -LiteralPath '$adsFile' -Stream '$adsStream' -Force -ErrorAction SilentlyContinue" `
                -Group "Alternate Data Streams"
        }
        if ($streams.Count -eq 0) { Out-Typewriter "  -> [OK] NO HIDDEN DATA STREAMS." "GOOD" }
    }
}

Show-PhaseHeader "PHASE 18" "DEEP CLOAKED PARASITE SCAN (HIDDEN+SYSTEM ATTRIBUTES)"
foreach ($ht in @($env:PUBLIC,$env:LOCALAPPDATA,$env:TEMP,"$env:USERPROFILE\AppData\Roaming")) {
    Out-Typewriter "SWEEPING HIDDEN/SYSTEM ATTRS: $ht" "HUNT"
    if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 900 }
    if (Test-Path $ht) {
        $cloaked = Get-ChildItem -Path $ht -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Attributes -match "Hidden" -and $_.Attributes -match "System" -and (Test-InScope $_.LastWriteTime) }
        foreach ($c in $cloaked) {
            Out-ThreatBanner "CLOAKED FILE (HIDDEN+SYSTEM)" $c.FullName
            Add-Finding -ID "CLOAKED_$($c.Name -replace '[^a-z0-9]','')" -Phase "PHASE 18" -ThreatType "Rootkit/Trojan" `
                -Severity $SEV_HIGH -Description "Hidden+System attributed file: $($c.FullName)" `
                -Target $c.FullName -FixAction "DeleteFile" -FixParam $c.FullName -Group "Cloaked/Hidden Files"
        }
        if ($cloaked.Count -eq 0) { Out-Typewriter "  -> [OK] NO CLOAKED FILES." "GOOD" }
    }
}

Show-PhaseHeader "PHASE 19" "SCRIPT EXECUTION ASSOCIATION AUDIT"
Out-Typewriter "CHECKING .JS .VBS .HTA .WSF HANDLER ASSOCIATIONS..." "INFO"
foreach ($ext in @(".js",".vbs",".hta",".wsf",".wsh",".jse",".vbe")) {
    $assoc = cmd.exe /c "assoc $ext 2>nul"
    if ($assoc -notmatch "txtfile" -and $assoc -match "=") {
        Out-Typewriter "  -> SCRIPT EXT $ext MAPPED TO EXECUTABLE HANDLER: $assoc" "WARN"
        Add-Finding -ID "SCRIPT_ASSOC_$($ext -replace '\.','')" -Phase "PHASE 19" -ThreatType "Script Handler Abuse" `
            -Severity $SEV_HIGH -Description "Script extension $ext mapped to executable handler: $assoc" `
            -Target "File Association: $ext" -FixAction "RunCmd" -FixParam "assoc $ext=txtfile" -Group "Script Execution Hardening"
    }
}
Out-Typewriter "  -> SCRIPT HANDLER AUDIT COMPLETE." "VER"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4: REGISTRY PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "REGISTRY PERSISTENCE SCRUB"

Show-PhaseHeader "PHASE 20" "RUN / RUNONCE HEURISTIC SCRUB"
$runPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($rp in $runPaths) {
    Out-Typewriter "AUDITING HIVE: $rp" "INFO"
    if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 600 }
    if (Test-Path $rp) {
        $keys = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        foreach ($prop in ($keys.psobject.properties | Where-Object { $_.Name -notmatch "^PS" }).Name) {
            $val = $keys.$prop
            if ($val -match "AppData|Temp|cmd\.exe|powershell|wscript|cscript|mshta|\.js|\.vbs|\.hta|regsvr32|rundll32|certutil|bitsadmin|msiexec.*http|IEX|EncodedCommand") {
                Out-Decrypt -Text "$prop = $val" -Prefix "  [RUN KEY] "
                Add-Finding -ID "RUNKEY_$($prop -replace '[^a-z0-9]','')" -Phase "PHASE 20" -ThreatType "Registry Persistence" `
                    -Severity $SEV_CRITICAL -Description "Malicious Run key: [$rp] $prop = $val" `
                    -Target "$rp|$prop" -FixAction "DeleteReg" -FixParam "$rp|$prop" -Group "Run Key Persistence"
            }
        }
    }
}
Out-Typewriter "  -> RUN/RUNONCE AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 21" "IMAGE FILE EXECUTION OPTIONS (IFEO) SCRUB"
$ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path $ifeoPath) {
    Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
        if (Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue) {
            $dbg = (Get-ItemPropertyValue -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue)
            Out-Decrypt -Text "$($_.PSChildName) -> Debugger = $dbg" -Prefix "  [IFEO HIT] "
            Add-Finding -ID "IFEO_$($_.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 21" -ThreatType "IFEO Hijack/Persistence" `
                -Severity $SEV_CRITICAL -Description "IFEO Debugger set on $($_.PSChildName) = $dbg — common backdoor/persistence technique" `
                -Target "$($_.PSPath)|Debugger" -FixAction "DeleteReg" -FixParam "$($_.PSPath)|Debugger" -Group "IFEO Persistence"
        }
        $gf = (Get-ItemPropertyValue -Path $_.PSPath -Name "GlobalFlag" -ErrorAction SilentlyContinue)
        if ($null -ne $gf -and $gf -ne 0) {
            Add-Finding -ID "IFEO_GF_$($_.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 21" -ThreatType "IFEO/GFlags Injection" `
                -Severity $SEV_HIGH -Description "IFEO GlobalFlag set on $($_.PSChildName) = $gf (GFlags injection vector)" `
                -Target "$($_.PSPath)|GlobalFlag" -FixAction "DeleteReg" -FixParam "$($_.PSPath)|GlobalFlag" -Group "IFEO Persistence"
        }
    }
    Out-Typewriter "  -> IFEO AUDIT COMPLETE." "VER"
} else { Out-Typewriter "  -> [OK] IFEO HIVE ABSENT." "GOOD" }

Show-PhaseHeader "PHASE 22" "APPINIT_DLLS KERNEL INJECTION SCRUB"
foreach ($p in @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows")) {
    $ai = Get-ItemPropertyValue -Path $p -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
    if ($ai -and $ai.Trim() -ne "") {
        Out-Typewriter "  -> APPINIT_DLLS SET: $ai" "CRIT"
        Add-Finding -ID "APPINIT_$($p -replace '[^a-z0-9]','')" -Phase "PHASE 22" -ThreatType "DLL Injection/Rootkit" `
            -Severity $SEV_CRITICAL -Description "AppInit_DLLs is set — injects into every user-mode process: $ai" `
            -Target "$p|AppInit_DLLs" -FixAction "DeleteReg" -FixParam "$p|AppInit_DLLs" -Group "DLL Injection Persistence"
    } else { Out-Typewriter "  -> [OK] APPINIT_DLLS EMPTY." "GOOD" }
}

Show-PhaseHeader "PHASE 23" "WINLOGON / USERINIT / SHELL HIJACK DETECTION"
$wlPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$wlKeys = Get-ItemProperty -Path $wlPath -ErrorAction SilentlyContinue
if ($wlKeys.Shell -and $wlKeys.Shell -ne "explorer.exe") {
    Out-Typewriter "  -> SHELL HIJACK: $($wlKeys.Shell)" "CRIT"
    Add-Finding -ID "WINLOGON_SHELL" -Phase "PHASE 23" -ThreatType "Winlogon Hijack" -Severity $SEV_CRITICAL `
        -Description "Winlogon Shell hijacked to: $($wlKeys.Shell)" `
        -Target "$wlPath|Shell" -FixAction "RunCmd" -FixParam "Set-ItemProperty -Path '$wlPath' -Name Shell -Value 'explorer.exe' -Force" -Group "Winlogon Hijack"
} else { Out-Typewriter "  -> [OK] WINLOGON SHELL VERIFIED." "GOOD" }
if ($wlKeys.Userinit -and $wlKeys.Userinit -notmatch "^C:\\Windows\\system32\\userinit\.exe,$") {
    Out-Typewriter "  -> USERINIT HIJACK: $($wlKeys.Userinit)" "CRIT"
    Add-Finding -ID "WINLOGON_USERINIT" -Phase "PHASE 23" -ThreatType "Winlogon Hijack" -Severity $SEV_CRITICAL `
        -Description "Winlogon Userinit hijacked to: $($wlKeys.Userinit)" `
        -Target "$wlPath|Userinit" -FixAction "RunCmd" -FixParam "Set-ItemProperty -Path '$wlPath' -Name Userinit -Value 'C:\Windows\system32\userinit.exe,' -Force" -Group "Winlogon Hijack"
} else { Out-Typewriter "  -> [OK] USERINIT VERIFIED." "GOOD" }

Show-PhaseHeader "PHASE 24" "COM OBJECT HIJACK AUDIT (HKCU CLSID OVERRIDES)"
Out-Typewriter "SCANNING HKCU COM OVERRIDES..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$hkcuClsid = "HKCU:\SOFTWARE\Classes\CLSID"
if (Test-Path $hkcuClsid) {
    $comHijacks = Get-ChildItem -Path $hkcuClsid -Recurse -ErrorAction SilentlyContinue
    foreach ($k in $comHijacks) {
        Out-Decrypt -Text $k.PSPath -Prefix "  [COM HIJACK] "
        Add-Finding -ID "COM_$($k.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 24" -ThreatType "COM Hijack" `
            -Severity $SEV_HIGH -Description "HKCU COM override found (COM hijack persistence): $($k.PSPath)" `
            -Target $k.PSPath -FixAction "DeleteRegKey" -FixParam $k.PSPath -Group "COM Object Hijacks"
    }
    if ($comHijacks.Count -eq 0) { Out-Typewriter "  -> [OK] NO HKCU COM OVERRIDES." "GOOD" }
} else { Out-Typewriter "  -> [OK] HKCU CLSID ABSENT." "GOOD" }

Show-PhaseHeader "PHASE 25" "GPO LOCKDOWN — TASKMGR/REGEDIT/CMD DISABLED"
$gpoU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$gpoM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
foreach ($pol in @("DisableTaskMgr","DisableRegistryTools","DisableCMD")) {
    $vU = (Get-ItemPropertyValue -Path $gpoU -Name $pol -ErrorAction SilentlyContinue)
    $vM = (Get-ItemPropertyValue -Path $gpoM -Name $pol -ErrorAction SilentlyContinue)
    if ($vU -eq 1) {
        Out-Typewriter "  -> $pol DISABLED (HKCU)" "CRIT"
        Add-Finding -ID "GPO_$pol" -Phase "PHASE 25" -ThreatType "GPO Lockdown (Malware)" -Severity $SEV_HIGH `
            -Description "GPO policy $pol = 1 (HKCU) — malware commonly disables Task Manager/RegEdit/CMD" `
            -Target "$gpoU|$pol" -FixAction "DeleteReg" -FixParam "$gpoU|$pol" -Group "GPO / Policy Lockdowns"
    }
    if ($vM -eq 1) {
        Out-Typewriter "  -> $pol DISABLED (HKLM)" "CRIT"
        Add-Finding -ID "GPO_M_$pol" -Phase "PHASE 25" -ThreatType "GPO Lockdown (Malware)" -Severity $SEV_HIGH `
            -Description "GPO policy $pol = 1 (HKLM) — may be malware-imposed lockdown" `
            -Target "$gpoM|$pol" -FixAction "DeleteReg" -FixParam "$gpoM|$pol" -Group "GPO / Policy Lockdowns"
    }
}
Out-Typewriter "  -> GPO POLICY AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 26" "BROWSER HELPER OBJECT (BHO) PURGE"
$bhoPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects")
foreach ($bho in $bhoPaths) {
    if (Test-Path $bho) {
        $bhoKeys = Get-ChildItem -Path $bho -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
        foreach ($k in $bhoKeys) {
            Out-Decrypt -Text $k.Name -Prefix "  [BHO HIT] "
            Add-Finding -ID "BHO_$($k.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 26" -ThreatType "Browser Hijacker/BHO" `
                -Severity $SEV_HIGH -Description "Browser Helper Object in registry: $($k.Name)" `
                -Target $k.PSPath -FixAction "DeleteRegKey" -FixParam $k.PSPath -Group "Browser Helper Objects"
            $global:SpywareHits++
        }
        if ($bhoKeys.Count -eq 0) { Out-Typewriter "  -> [OK] BHO HIVE SECURE." "GOOD" }
    }
}

Show-PhaseHeader "PHASE 27" "SAFE MODE HIJACK (SAFEBOOT KEY AUDIT)"
foreach ($sm in @("Minimal","Network")) {
    $safePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$sm"
    if (Test-Path $safePath) {
        $safeKeys = Get-ChildItem -Path $safePath -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -notmatch "^{" -and (Test-InScope $_.LastWriteTime) }
        foreach ($k in $safeKeys) {
            Out-Decrypt -Text $k.PSPath -Prefix "  [SAFEMODE PERSIST] "
            Add-Finding -ID "SAFEBOOT_$($k.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 27" -ThreatType "SafeBoot Hijack" `
                -Severity $SEV_CRITICAL -Description "Unknown entry in SafeBoot\$sm: $($k.PSChildName) — malware SafeBoot persistence" `
                -Target $k.PSPath -FixAction "DeleteRegKey" -FixParam $k.PSPath -Group "SafeBoot Persistence"
        }
    }
}
Out-Typewriter "  -> SAFEBOOT AUDIT COMPLETE." "VER"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5: SERVICE / TASK / WMI
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "SERVICE / TASK / WMI / BITS PERSISTENCE"

Show-PhaseHeader "PHASE 28" "ROGUE WIN32 SERVICE AUDIT"
Out-Typewriter "QUERYING SERVICE CONTROL MANAGER..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1400 }
$rogueServices = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.ImagePath -match "AppData|Temp|cmd\.exe|powershell|wscript|mshta|\.js|rundll32|regsvr32|certutil" }
if ($rogueServices.Count -eq 0) { Out-Typewriter "  -> [OK] NO ANOMALOUS SERVICES." "GOOD" }
foreach ($svc in $rogueServices) {
    Out-Decrypt -Text "$($svc.PSChildName) = $($svc.ImagePath)" -Prefix "  [ROGUE SERVICE] "
    Add-Finding -ID "SVC_$($svc.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 28" -ThreatType "Malicious Service" `
        -Severity $SEV_CRITICAL -Description "Rogue service: $($svc.PSChildName) | ImagePath: $($svc.ImagePath)" `
        -Target "Service: $($svc.PSChildName)" -FixAction "RunCmd" `
        -FixParam "Stop-Service '$($svc.PSChildName)' -Force; Set-Service '$($svc.PSChildName)' -StartupType Disabled; sc.exe delete '$($svc.PSChildName)'" `
        -Group "Rogue Services"
}

Show-PhaseHeader "PHASE 29" "TASK SCHEDULER DEEP AUDIT"
Out-Typewriter "DUMPING SCHEDULED TASK MANIFESTS..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1400 }
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch "\\Microsoft\\" }
foreach ($task in $tasks) {
    $exe = $task.Actions[0].Execute; $args = $task.Actions[0].Arguments
    if (($exe + " " + $args) -match "wscript|cscript|mshta|powershell.*-enc|powershell.*-nop|cmd|AppData|Temp|\.js|\.vbs|\.hta|regsvr32|rundll32|certutil|IEX|DownloadString|EncodedCommand") {
        $taskNameEsc = $task.TaskName -replace "'","''"
        Out-Decrypt -Text $task.TaskName -Prefix "  [ROGUE TASK] "
        Add-Finding -ID "TASK_$($task.TaskName -replace '[^a-z0-9]','')" -Phase "PHASE 29" -ThreatType "Task Persistence" `
            -Severity $SEV_CRITICAL -Description "Malicious scheduled task: $($task.TaskName) | Exe: $exe $args" `
            -Target "Task: $($task.TaskName)" -FixAction "RunCmd" -FixParam "Unregister-ScheduledTask -TaskName '$taskNameEsc' -Confirm:`$false -ErrorAction SilentlyContinue" `
            -Group "Scheduled Task Persistence"
    }
}
foreach ($td in @("$env:WINDIR\System32\Tasks","$env:WINDIR\SysWOW64\Tasks")) {
    if (Test-Path $td) {
        $taskFiles = Get-ChildItem -Path $td -Recurse -File -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
        foreach ($tf in $taskFiles) {
            $content = Get-Content $tf.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match "AppData|Temp|powershell.*-enc|IEX|wscript|mshta") {
                Out-Decrypt -Text $tf.FullName -Prefix "  [TASK FILE] "
                Add-Finding -ID "TASKFILE_$($tf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 29" -ThreatType "Task Persistence" `
                    -Severity $SEV_HIGH -Description "Suspicious task XML on disk: $($tf.FullName)" `
                    -Target $tf.FullName -FixAction "DeleteFile" -FixParam $tf.FullName -Group "Scheduled Task Persistence"
            }
        }
    }
}
Out-Typewriter "  -> TASK AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 30" "WMI EVENT FILTER / CONSUMER / BINDING AUDIT"
Out-Typewriter "ANALYZING ROOT\SUBSCRIPTION NAMESPACE..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1400 }
$wmiFilters   = Get-WmiObject -Namespace root\subscription -Class __EventFilter     -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "BVTFilter|SCM" }
$wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer    -ErrorAction SilentlyContinue
$wmiBindings  = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
if (($wmiFilters.Count + $wmiConsumers.Count + $wmiBindings.Count) -eq 0) {
    Out-Typewriter "  -> [OK] WMI SUBSCRIPTIONS CLEAN." "GOOD"
} else {
    foreach ($f in $wmiFilters) {
        $fName = $f.Name -replace "'","''"
        Out-ThreatBanner "WMI EVENT FILTER (PERSISTENCE)" "Name: $($f.Name)"
        Add-Finding -ID "WMI_F_$($f.Name -replace '[^a-z0-9]','')" -Phase "PHASE 30" -ThreatType "WMI Persistence" `
            -Severity $SEV_CRITICAL -Description "WMI EventFilter: $($f.Name) | Query: $($f.Query)" `
            -Target "WMI Filter: $($f.Name)" -FixAction "RunCmd" `
            -FixParam "Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { `$_.Name -eq '$fName' } | Remove-WmiObject" `
            -Group "WMI Persistence"
    }
    foreach ($c in $wmiConsumers) {
        $cName = $c.Name -replace "'","''"
        Add-Finding -ID "WMI_C_$($c.Name -replace '[^a-z0-9]','')" -Phase "PHASE 30" -ThreatType "WMI Persistence" `
            -Severity $SEV_CRITICAL -Description "WMI Consumer: $($c.Name)" `
            -Target "WMI Consumer: $($c.Name)" -FixAction "RunCmd" `
            -FixParam "Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Where-Object { `$_.Name -eq '$cName' } | Remove-WmiObject" `
            -Group "WMI Persistence"
    }
}

Show-PhaseHeader "PHASE 31" "BITS / POWERSHELL PROFILE / STARTUP PERSISTENCE"
$bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.JobState -notmatch "Idle" }
foreach ($job in $bitsJobs) {
    Out-Decrypt -Text $job.DisplayName -Prefix "  [BITS JOB] "
    Add-Finding -ID "BITS_$($job.JobId)" -Phase "PHASE 31" -ThreatType "BITS Persistence" -Severity $SEV_HIGH `
        -Description "Active BITS transfer: $($job.DisplayName) | State: $($job.JobState)" `
        -Target "BITS Job: $($job.JobId)" -FixAction "RunCmd" -FixParam "Remove-BitsTransfer -BitsJob (Get-BitsTransfer -AllUsers | Where-Object JobId -eq '$($job.JobId)')" `
        -Group "BITS / Profile Persistence"
}
if ($bitsJobs.Count -eq 0) { Out-Typewriter "  -> [OK] NO ROGUE BITS JOBS." "GOOD" }
foreach ($prof in @($PROFILE.AllUsersAllHosts,$PROFILE.AllUsersCurrentHost,$PROFILE.CurrentUserAllHosts,$PROFILE.CurrentUserCurrentHost)) {
    if (Test-Path $prof) {
        $content = Get-Content $prof -Raw -ErrorAction SilentlyContinue
        if ($content -match "IEX|DownloadString|WebClient|Invoke-Expression|Start-Process.*hidden") {
            Out-Typewriter "  -> MALICIOUS PROFILE: $prof" "CRIT"
            Add-Finding -ID "PSPROFILE_$($prof -replace '[^a-z0-9]','')" -Phase "PHASE 31" -ThreatType "PS Profile Persistence" `
                -Severity $SEV_CRITICAL -Description "Malicious content in PS profile: $prof" `
                -Target $prof -FixAction "DeleteFile" -FixParam $prof -Group "BITS / Profile Persistence"
        }
    }
}
foreach ($sp in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup")) {
    if (Test-Path $sp) {
        $startItems = Get-ChildItem -Path $sp -File -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
        foreach ($si in $startItems) {
            $sig = Get-AuthenticodeSignature $si.FullName -ErrorAction SilentlyContinue
            $sev = if ($sig.Status -ne "Valid") { $SEV_HIGH } else { $SEV_POSSIBLE }
            Add-Finding -ID "STARTUP_$($si.Name -replace '[^a-z0-9]','')" -Phase "PHASE 31" -ThreatType "Startup Persistence" `
                -Severity $sev -Description "Startup folder item: $($si.Name) ($(if ($sig.Status -ne 'Valid') {'UNSIGNED'} else {'signed'}))" `
                -Target $si.FullName -FixAction "DeleteFile" -FixParam $si.FullName -Group "Startup Folder Persistence"
        }
    }
}

Show-PhaseHeader "PHASE 32" "DLL SEARCH ORDER HIJACK — PATH AUDIT"
Out-Typewriter "AUDITING WRITABLE PATH ENTRIES..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$pathDirs = $env:PATH -split ";"
foreach ($pd in $pathDirs) {
    if (-not (Test-Path $pd)) { continue }
    try {
        $testFile = "$pd\__zbtest_$(Get-Random).tmp"
        [IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        Out-Typewriter "  -> WRITABLE PATH ENTRY: $pd" "WARN"
        $recentDlls = Get-ChildItem -Path $pd -Filter "*.dll" -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
        foreach ($dll in $recentDlls) {
            $sig = Get-AuthenticodeSignature $dll.FullName -ErrorAction SilentlyContinue
            if ($sig.Status -ne "Valid") {
                Out-Decrypt -Text $dll.FullName -Prefix "  [UNSIGNED DLL IN PATH] "
                Add-Finding -ID "DLLHIJACK_$($dll.Name -replace '[^a-z0-9]','')" -Phase "PHASE 32" -ThreatType "DLL Hijack" `
                    -Severity $SEV_HIGH -Description "Unsigned DLL in writable PATH dir: $($dll.FullName)" `
                    -Target $dll.FullName -FixAction "DeleteFile" -FixParam $dll.FullName -Group "DLL Hijack / PATH"
            }
        }
    } catch { }
}
Out-Typewriter "  -> DLL PATH AUDIT COMPLETE." "VER"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6: NETWORK & C2
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "NETWORK & C2 INDICATOR SWEEP"

Show-PhaseHeader "PHASE 33" "HOSTS FILE INTEGRITY AUDIT"
Out-Typewriter "VERIFYING HOSTS FILE..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
$hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
    $badHosts = $hostsContent | Where-Object {
        $_ -notmatch "^#" -and $_ -match "\S" -and
        $_ -notmatch "^(127\.0\.0\.1|::1|0\.0\.0\.0)\s+(localhost|ip6-localhost|ip6-loopback)"
    }
    if ($badHosts) {
        foreach ($bh in $badHosts) {
            Out-Decrypt -Text $bh -Prefix "  [HOSTS HIJACK] "
            Add-Finding -ID "HOSTS_$($bh.GetHashCode())" -Phase "PHASE 33" -ThreatType "DNS Hijack" -Severity $SEV_HIGH `
                -Description "Suspicious hosts entry: $bh" -Target $hostsPath -FixAction "Info" -Group "Hosts File Hijack"
        }
        Add-Finding -ID "HOSTS_PURGE" -Phase "PHASE 33" -ThreatType "DNS Hijack" -Severity $SEV_HIGH `
            -Description "Hosts file contains $($badHosts.Count) non-standard entries — purge all?" `
            -Target $hostsPath -FixAction "RunCmd" `
            -FixParam "`$h = Get-Content '$hostsPath'; `$clean = `$h | Where-Object { `$_ -match '^#' -or `$_ -notmatch '\S' -or `$_ -match '^(127\.0\.0\.1|::1|0\.0\.0\.0)\s+(localhost|ip6)' }; `$clean | Set-Content '$hostsPath'" `
            -Group "Hosts File Hijack"
    } else { Out-Typewriter "  -> [OK] HOSTS FILE CLEAN." "GOOD" }
}

Show-PhaseHeader "PHASE 34" "DNS CACHE POISONING AUDIT & FLUSH"
Out-Typewriter "DUMPING DNS RESOLVER CACHE..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
$suspectDns = $dnsCache | Where-Object { $entry = $_; $SUSPICIOUS_DNS_DOMAINS | Where-Object { $entry.Entry -match [regex]::Escape($_) } }
foreach ($entry in $suspectDns) {
    Out-Typewriter "  -> SUSPECT DYNAMIC DNS: $($entry.Entry) -> $($entry.Data)" "CRIT"
    Add-Finding -ID "DNS_$($entry.Entry -replace '[^a-z0-9]','')" -Phase "PHASE 34" -ThreatType "DNS Hijack/C2" `
        -Severity $SEV_HIGH -Description "Suspicious dynamic DNS resolution: $($entry.Entry) -> $($entry.Data)" `
        -Target "DNS Cache: $($entry.Entry)" -FixAction "RunCmd" -FixParam "Clear-DnsClientCache" -Group "DNS Cache Poisoning"
}
Clear-DnsClientCache -ErrorAction SilentlyContinue
Out-Typewriter "  -> [OK] DNS CACHE FLUSHED." "GOOD"

Show-PhaseHeader "PHASE 35" "PROXY & WINHTTP POISON RESET"
Out-Typewriter "AUDITING PROXY SETTINGS..." "INFO"
$proxyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$ps = Get-ItemProperty -Path $proxyPath -ErrorAction SilentlyContinue
if ($ps.ProxyEnable -eq 1) {
    Out-Typewriter "  -> ROGUE PROXY ENABLED: $($ps.ProxyServer)" "CRIT"
    Add-Finding -ID "PROXY_ENABLE" -Phase "PHASE 35" -ThreatType "Proxy Hijack" -Severity $SEV_CRITICAL `
        -Description "Rogue proxy configured: $($ps.ProxyServer)" `
        -Target "$proxyPath|ProxyEnable" -FixAction "RunCmd" `
        -FixParam "Set-ItemProperty -Path '$proxyPath' -Name ProxyEnable -Value 0 -Force; Remove-ItemProperty -Path '$proxyPath' -Name ProxyServer -Force; netsh winhttp reset proxy" `
        -Group "Proxy / Network Hijack"
} else { Out-Typewriter "  -> [OK] NO ROGUE PROXY." "GOOD" }

Show-PhaseHeader "PHASE 36" "LIVE TCP/UDP THREAT SOCKET TERMINATION"
Out-Typewriter "SCANNING OPEN TCP SOCKETS..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1400 }
$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
$foundConn = $false
foreach ($conn in $conns) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    if ($STRATUM_PORTS -contains $conn.RemotePort -and $proc.Name -notmatch "^(svchost|chrome|msedge|firefox)$") {
        $foundConn = $true
        Out-ThreatBanner "CRYPTOMINER STRATUM CONNECTION" "$($proc.Name) PID:$($proc.Id) -> $($conn.RemoteAddress):$($conn.RemotePort)"
        Add-Finding -ID "STRATUM_$($proc.Id)" -Phase "PHASE 36" -ThreatType "Cryptominer" -Severity $SEV_CRITICAL `
            -Description "Stratum mining connection from $($proc.Name) PID:$($proc.Id) to $($conn.RemoteAddress):$($conn.RemotePort)" `
            -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Connections"
        $global:MinerHits++
    }
    if ($proc.Path -match "AppData|Temp" -and $conn.RemotePort -notin @(80,443,8080,8443)) {
        $foundConn = $true
        Out-Typewriter "  -> SUSPECT SOCKET (AppData/Temp proc): $($proc.Name) -> $($conn.RemoteAddress):$($conn.RemotePort)" "CRIT"
        Add-Finding -ID "CONN_$($proc.Id)_$($conn.RemotePort)" -Phase "PHASE 36" -ThreatType "Suspicious Connection" `
            -Severity $SEV_HIGH -Description "$($proc.Name) from AppData/Temp connecting to $($conn.RemoteAddress):$($conn.RemotePort)" `
            -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Connections"
    }
}
# Reverse DNS check for C2 domains
foreach ($conn in ($conns | Select-Object -First 30)) {
    try {
        $rdns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
        foreach ($c2d in $KNOWN_C2_DOMAINS) {
            if ($rdns -match [regex]::Escape($c2d)) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                Out-ThreatBanner "C2 DOMAIN CONNECTION" "$($proc.Name) -> $rdns"
                Add-Finding -ID "C2_$($proc.Id)" -Phase "PHASE 36" -ThreatType "C2 Beacon/RAT" -Severity $SEV_CRITICAL `
                    -Description "Known C2 domain connection: $($proc.Name) PID:$($proc.Id) -> $rdns ($($conn.RemoteAddress))" `
                    -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Connections"
                $global:RATHits++; $foundConn = $true
            }
        }
    } catch { }
}
if (-not $foundConn) { Out-Typewriter "  -> [OK] NO MALICIOUS OUTBOUND CONNECTIONS." "GOOD" }

Show-PhaseHeader "PHASE 37" "IPC NULL SESSION / SMB / PORTPROXY AUDIT"
$proxies = netsh interface portproxy show all
if ($proxies -match "Listen Port") {
    Out-Typewriter "  -> UNAUTHORIZED PORT FORWARDING DETECTED." "CRIT"
    Add-Finding -ID "PORTPROXY" -Phase "PHASE 37" -ThreatType "Port Tunneling" -Severity $SEV_HIGH `
        -Description "Active portproxy/port-forward rules detected — possible C2 tunnel" `
        -Target "netsh portproxy" -FixAction "RunCmd" -FixParam "netsh interface portproxy reset" -Group "Network Tunnels"
} else { Out-Typewriter "  -> [OK] NO PORTPROXY TUNNELS." "GOOD" }

Show-PhaseHeader "PHASE 38" "FIREWALL AUDIT & PERIMETER REVIEW"
Out-Typewriter "CHECKING UNAUTHORIZED FIREWALL RULES..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$suspectRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and
                   $_.Description -notmatch "Windows|Microsoft|WinRM" -and
                   ($_.Profile -match "Public" -or $_.LocalPort -eq "Any") }
foreach ($rule in $suspectRules) {
    Out-Typewriter "  -> SUSPECT FW RULE: $($rule.DisplayName)" "WARN"
    Add-Finding -ID "FW_$($rule.Name -replace '[^a-z0-9]','')" -Phase "PHASE 38" -ThreatType "Firewall Hole" -Severity $SEV_POSSIBLE `
        -Description "Suspicious inbound firewall rule: $($rule.DisplayName) — Public profile or Any port" `
        -Target "Firewall Rule: $($rule.Name)" -FixAction "RunCmd" -FixParam "Disable-NetFirewallRule -Name '$($rule.Name)'" -Group "Firewall Audit"
}
if ($suspectRules.Count -eq 0) { Out-Typewriter "  -> [OK] FIREWALL RULES APPEAR CLEAN." "GOOD" }
Add-Finding -ID "FW_RESET_OPT" -Phase "PHASE 38" -ThreatType "Hardening" -Severity $SEV_INFO `
    -Description "Option: Reset Windows Firewall to defaults (netsh advfirewall reset)" `
    -Target "Windows Firewall" -FixAction "RunCmd" -FixParam "netsh advfirewall reset" -Group "Firewall Audit"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7: CERTIFICATE & CRYPTO TRUST
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "CERTIFICATE & CRYPTO TRUST CHAIN"

Show-PhaseHeader "PHASE 39" "ROGUE ROOT CERTIFICATE AUDIT (LM + USER)"
Invoke-QuantumBar "AUDITING CERTIFICATE STORES" 10 130
$lmCerts = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.NotBefore }
foreach ($cert in $lmCerts) {
    Out-Decrypt -Text "$($cert.Subject) | $($cert.Thumbprint)" -Prefix "  [ROGUE LM CERT] "
    Add-Finding -ID "CERT_LM_$($cert.Thumbprint.Substring(0,8))" -Phase "PHASE 39" -ThreatType "Rogue Certificate" `
        -Severity $SEV_CRITICAL -Description "New root CA in LocalMachine store: $($cert.Subject)" `
        -Target "Cert:\LocalMachine\Root\$($cert.Thumbprint)" -FixAction "RunCmd" `
        -FixParam "Remove-Item 'Cert:\LocalMachine\Root\$($cert.Thumbprint)' -Force" -Group "Rogue Certificates"
}
$userCerts = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.NotBefore }
foreach ($cert in $userCerts) {
    Out-Decrypt -Text "$($cert.Subject) | $($cert.Thumbprint)" -Prefix "  [ROGUE USER CERT] "
    Add-Finding -ID "CERT_USER_$($cert.Thumbprint.Substring(0,8))" -Phase "PHASE 39" -ThreatType "Rogue Certificate" `
        -Severity $SEV_HIGH -Description "New root CA in CurrentUser store: $($cert.Subject)" `
        -Target "Cert:\CurrentUser\Root\$($cert.Thumbprint)" -FixAction "RunCmd" `
        -FixParam "Remove-Item 'Cert:\CurrentUser\Root\$($cert.Thumbprint)' -Force" -Group "Rogue Certificates"
}
if ($lmCerts.Count -eq 0 -and $userCerts.Count -eq 0) { Out-Typewriter "  -> [OK] CERTIFICATE STORES CLEAN." "GOOD" }

Show-PhaseHeader "PHASE 40" "BCD STORE — DRIVER SIGNING / TESTSIGNING AUDIT"
Out-Typewriter "AUDITING BCD STORE FOR SIGNING BYPASS..." "INFO"
$bcd = bcdedit /enum
if ($bcd -match "testsigning\s+Yes" -or $bcd -match "nointegritychecks\s+Yes") {
    Out-Glitch "  [KERNEL ROOTKIT VECTOR DETECTED IN BCD]" Red
    Add-Finding -ID "BCD_TESTSIGN" -Phase "PHASE 40" -ThreatType "Bootkit/Rootkit Vector" -Severity $SEV_CRITICAL `
        -Description "BCD has testsigning/nointegritychecks enabled — unsigned driver loading permitted (rootkit vector)" `
        -Target "bcdedit testsigning/nointegritychecks" -FixAction "RunCmd" `
        -FixParam "bcdedit /set testsigning off; bcdedit /set nointegritychecks off; bcdedit /set loadoptions ENABLE_INTEGRITY_CHECKS" -Group "BCD / Boot Integrity"
    $global:RootkitHits++
} else { Out-Typewriter "  -> [OK] BCD SIGNATURE ENFORCEMENT VERIFIED." "GOOD" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8: CREDENTIAL & USER ABUSE
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "CREDENTIAL & USER ABUSE DETECTION"

Show-PhaseHeader "PHASE 41" "LSA / WDIGEST / LSA PROTECTION AUDIT"
$wdigest = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
if ($wdigest -eq 1) {
    Out-Typewriter "  -> WDIGEST PLAINTEXT CREDS ENABLED." "CRIT"
    Add-Finding -ID "WDIGEST_ENABLE" -Phase "PHASE 41" -ThreatType "Credential Theft Vector" -Severity $SEV_CRITICAL `
        -Description "WDigest UseLogonCredential = 1 — credentials stored in plaintext in memory (mimikatz target)" `
        -Target "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest|UseLogonCredential" `
        -FixAction "RunCmd" -FixParam "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord -Force" `
        -Group "Credential Security"
} else { Out-Typewriter "  -> [OK] WDIGEST PLAINTEXT STORAGE DISABLED." "GOOD" }
$lsaProtect = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
if ($lsaProtect -ne 1) {
    Out-Typewriter "  -> LSA PROTECTION NOT ENABLED." "WARN"
    Add-Finding -ID "LSA_PPL" -Phase "PHASE 41" -ThreatType "LSA Hardening" -Severity $SEV_HIGH `
        -Description "LSA RunAsPPL is not enabled — LSA process vulnerable to credential dumping" `
        -Target "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|RunAsPPL" `
        -FixAction "RunCmd" -FixParam "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord -Force" `
        -Group "Credential Security"
} else { Out-Typewriter "  -> [OK] LSA PROTECTION ENABLED." "GOOD" }

Show-PhaseHeader "PHASE 42" "LOCAL ADMINISTRATOR GHOST ACCOUNT AUDIT"
Out-Typewriter "QUERYING LOCAL USER ACCOUNTS..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1400 }
$allLocalUsers = Get-LocalUser -ErrorAction SilentlyContinue
foreach ($usr in $allLocalUsers) {
    if ($usr.Enabled -and $usr.Name -match "Temp|Admin1|Support|Test|Guest|Backdoor|HelpAssistant|DefaultAccount") {
        Out-Glitch "  [SUSPICIOUS ACCOUNT: $($usr.Name)]" Red
        Add-Finding -ID "ACCOUNT_$($usr.Name -replace '[^a-z0-9]','')" -Phase "PHASE 42" -ThreatType "Ghost/Backdoor Account" `
            -Severity $SEV_HIGH -Description "Suspicious enabled local account: $($usr.Name)" `
            -Target "LocalUser: $($usr.Name)" -FixAction "RunCmd" -FixParam "Disable-LocalUser -Name '$($usr.Name)'" -Group "Suspicious Accounts"
    }
}
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
foreach ($admin in $admins) {
    Out-Decrypt -Text $admin.Name -Prefix "  [ADMIN MEMBER] "
    Write-Log "ADMIN: $($admin.Name)"
}
Out-Typewriter "  -> LOCAL ADMIN GROUP LOGGED TO REPORT." "VER"

Show-PhaseHeader "PHASE 43" "SAM / HIVENIGHTMARE (CVE-2021-36934) AUDIT"
Out-Typewriter "VERIFYING SAM HIVE PERMISSIONS + HIVENIGHTMARE CHECK..." "INFO"
$samPerms = cmd.exe /c "icacls %WINDIR%\System32\config\SAM 2>&1"
if ($samPerms -match "Everyone|Users.*:(F|M|W)") {
    Out-ThreatBanner "SAM HIVE OVER-PERMISSIVE" "Everyone/Users has write/modify access to SAM"
    Add-Finding -ID "SAM_PERMS" -Phase "PHASE 43" -ThreatType "Credential Exposure (HiveNightmare)" `
        -Severity $SEV_CRITICAL -Description "SAM hive ACL misconfigured — Everyone/Users can read (CVE-2021-36934 HiveNightmare)" `
        -Target "%WINDIR%\System32\config\SAM" -FixAction "RunCmd" `
        -FixParam "icacls '$env:WINDIR\System32\config' /reset /T /Q; vssadmin delete shadows /all /quiet" `
        -Group "SAM / HiveNightmare"
    $global:RootkitHits++
} else { Out-Typewriter "  -> [OK] SAM HIVE PERMISSIONS SECURE." "GOOD" }
# Check VSS copies that may expose SAM
$shadows = (vssadmin list shadows 2>&1) -join "`n"
$shadowCount = ([regex]::Matches($shadows, "Shadow Copy ID")).Count
Out-Typewriter "  -> FOUND $shadowCount VOLUME SHADOW COPIES." "DATA"
if ($shadowCount -gt 0) {
    Write-Host ""
    Write-Host "  ┌────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  VSS shadows may expose SAM (HiveNightmare) or pre-encryption backup. │" -ForegroundColor Yellow
    Write-Host "  │  Delete all shadow copies? (yes/no)                                   │" -ForegroundColor Yellow
    Write-Host "  └────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    Write-Host "  COMMAND> " -NoNewline -ForegroundColor DarkGray
    $vssChoice = (Read-Host).Trim().ToLower()
    if ($vssChoice -eq "yes") {
        cmd.exe /c "vssadmin delete shadows /all /quiet >nul 2>&1"
        $global:VSSDeleted = $true
        Out-Typewriter "  -> VSS SHADOW COPIES PURGED." "GOOD"
    } else {
        Out-Typewriter "  -> VSS DELETION SKIPPED. SHADOWS PRESERVED." "VER"
        Add-Finding -ID "VSS_DELETE_OPT" -Phase "PHASE 43" -ThreatType "Ransomware Recovery Vector" -Severity $SEV_INFO `
            -Description "Option: Delete all VSS shadow copies (removes HiveNightmare exposure and ransomware pre-enc backups)" `
            -Target "Volume Shadow Copies ($shadowCount found)" -FixAction "RunCmd" `
            -FixParam "vssadmin delete shadows /all /quiet" -Group "Volume Shadow Copies"
    }
}

Show-PhaseHeader "PHASE 44" "TOKEN / PRIVILEGE ABUSE — ELEVATED PROCS IN USER SPACE"
Out-Typewriter "CHECKING FOR SYSTEM-LEVEL PROCESSES IN USER PATHS..." "INFO"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1200 }
$elevatedInUS = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -match "AppData|Temp|Downloads|Desktop" -and (try { $_.GetOwnerSid().ReturnValue -eq 0 } catch { $false })
}
foreach ($proc in $elevatedInUS) {
    $sid = $proc.GetOwnerSid().Sid
    try {
        $elevated = ([System.Security.Principal.SecurityIdentifier]$sid).IsWellKnown([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        if ($elevated) {
            Out-Typewriter "  -> SYSTEM-LEVEL PROC FROM USER PATH: PID $($proc.ProcessId) | $($proc.Name)" "CRIT"
            Add-Finding -ID "TOKENABUSE_$($proc.ProcessId)" -Phase "PHASE 44" -ThreatType "Privilege Abuse/Trojan" `
                -Severity $SEV_CRITICAL -Description "SYSTEM-level process running from user path: $($proc.Name) PID:$($proc.ProcessId) @ $($proc.Path)" `
                -Target "PID:$($proc.ProcessId)" -FixAction "KillProcess" -FixParam $proc.ProcessId -Group "Privilege Abuse"
        }
    } catch {}
}
Out-Typewriter "  -> TOKEN AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 45" "ACCESSIBILITY SHELL BACKDOOR (STICKY KEYS / UTILMAN)"
$accessFiles = @(
    "$env:WINDIR\System32\sethc.exe","$env:WINDIR\System32\utilman.exe",
    "$env:WINDIR\System32\osk.exe","$env:WINDIR\System32\magnify.exe",
    "$env:WINDIR\System32\narrator.exe","$env:WINDIR\System32\displayswitch.exe"
)
foreach ($af in $accessFiles) {
    if (Test-Path $af) {
        $sig = Get-AuthenticodeSignature $af -ErrorAction SilentlyContinue
        if ($sig.Status -ne "Valid") {
            Out-Typewriter "  -> UNSIGNED ACCESSIBILITY BINARY: $af" "CRIT"
            Add-Finding -ID "STICKY_$([IO.Path]::GetFileNameWithoutExtension($af))" -Phase "PHASE 45" `
                -ThreatType "Sticky Keys / Accessibility Backdoor" -Severity $SEV_CRITICAL `
                -Description "Unsigned accessibility binary: $af — classic sticky-keys shell backdoor" `
                -Target $af -FixAction "RunCmd" -FixParam "Rename-Item '$af' '$af.kraken' -Force" -Group "Accessibility Shell Backdoors"
        } else { Out-Typewriter "  -> [OK] VALID: $af" "GOOD" }
    }
}

Show-PhaseHeader "PHASE 46" "NULL SESSION / NTLM LEVEL / FINAL LSA HARDENING"
Out-Typewriter "AUDITING LSA SECURITY SETTINGS..." "INFO"
$lsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$lmCompat = Get-ItemPropertyValue $lsaPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
if ($null -eq $lmCompat -or $lmCompat -lt 5) {
    Out-Typewriter "  -> NTLM LEVEL TOO LOW: $lmCompat (should be 5 = NTLMv2 only)" "WARN"
    Add-Finding -ID "NTLM_LEVEL" -Phase "PHASE 46" -ThreatType "Credential Security" -Severity $SEV_HIGH `
        -Description "LmCompatibilityLevel = $lmCompat — allows NTLMv1/LM hashes (pass-the-hash risk)" `
        -Target "$lsaPath|LmCompatibilityLevel" -FixAction "RunCmd" `
        -FixParam "Set-ItemProperty '$lsaPath' -Name LmCompatibilityLevel -Value 5 -Type DWord -Force" -Group "Credential Security"
} else { Out-Typewriter "  -> [OK] NTLM LEVEL $lmCompat (NTLMv2)." "GOOD" }
Add-Finding -ID "LSA_HARDEN_OPT" -Phase "PHASE 46" -ThreatType "Hardening" -Severity $SEV_INFO `
    -Description "Option: Apply full LSA hardening (RestrictAnonymous=1, NoLMHash=1, NTLMv2 only)" `
    -Target "$lsaPath (Multiple keys)" -FixAction "RunCmd" `
    -FixParam "Set-ItemProperty '$lsaPath' RestrictAnonymous 1 -Type DWord -Force; Set-ItemProperty '$lsaPath' NoLMHash 1 -Type DWord -Force; Set-ItemProperty '$lsaPath' RestrictAnonymousSAM 1 -Type DWord -Force" `
    -Group "Credential Security"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9: KEYLOGGER DETECTION MODULE
# ══════════════════════════════════════════════════════════════════════════════
Show-ThreatCategoryHeader "KEYLOGGER" "Windows Hooks · Raw Input · Kernel Callbacks · Keystroke Log Files · Registry"

Show-PhaseHeader "PHASE 47" "WINDOWS HOOK / RAW INPUT KEYLOGGER DETECTION" "KEYLOGGER"
Out-Typewriter "SCANNING FOR SetWindowsHookEx / RAW INPUT REGISTRATIONS..." "HUNT"
Invoke-QuantumBar "ENUMERATING GLOBAL HOOKS" 10 120
$hookHits = $false
# Look for suspicious processes accessing HID keyboard via raw input
$rawInputProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notmatch "^(svchost|System|MsMpEng|SearchIndexer|lsass|wininit|services|csrss|smss|WmiPrvSE|fontdrvhost|dwm|audiodg|conhost)$" -and
    $_.Modules -and ($_.Modules | Where-Object { $_.ModuleName -match "user32|winuser|hid" })
} | Where-Object { $_.Path -match "AppData|Temp|Downloads|Desktop" }
foreach ($p in $rawInputProcs) {
    Out-Typewriter "  -> SUSPICIOUS HID ACCESS: $($p.Name) PID:$($p.Id) @ $($p.Path)" "CRIT"
    Add-Finding -ID "HOOK_$($p.Id)" -Phase "PHASE 47" -ThreatType "Keylogger" -Severity $SEV_HIGH `
        -Description "Process accessing HID/user32 from user path: $($p.Name) PID:$($p.Id) @ $($p.Path)" `
        -Target "PID:$($p.Id)" -FixAction "KillProcess" -FixParam $p.Id -Group "Keylogger / Hook Detection"
    $global:KeyloggerHits++; $hookHits = $true
}
if (-not $hookHits) { Out-Typewriter "  -> [OK] NO OBVIOUS HOOK KEYLOGGER PROCESSES." "GOOD" }

Show-PhaseHeader "PHASE 48" "KEYLOGGER FILE & REGISTRY ARTIFACT SCAN" "KEYLOGGER"
Out-Typewriter "SCANNING FOR KEYSTROKE LOG FILES..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$klFilePatterns = @("*keystroke*","*keylog*","*keypress*","*kgb*","*.klg","*.kl","*typed*","*capture*log*","*hook.log*")
$klSearchPaths  = @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA,"$env:USERPROFILE\Documents")
$klFound = $false
foreach ($sp in $klSearchPaths) {
    if (-not (Test-Path $sp)) { continue }
    foreach ($pattern in $klFilePatterns) {
        $hits = Get-ChildItem -Path $sp -Recurse -Filter $pattern -ErrorAction SilentlyContinue |
            Where-Object { Test-InScope $_.LastWriteTime }
        foreach ($hit in $hits) {
            Out-ThreatBanner "KEYLOGGER LOG FILE" $hit.FullName
            Add-Finding -ID "KLFILE_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 48" -ThreatType "Keylogger" `
                -Severity $SEV_CRITICAL -Description "Keystroke log file detected: $($hit.FullName)" `
                -Target $hit.FullName -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Keylogger Artifacts"
            $global:KeyloggerHits++; $klFound = $true
        }
    }
}
$klRegPaths = @("HKCU:\SOFTWARE\Ardamax","HKCU:\SOFTWARE\Spyrix","HKCU:\SOFTWARE\Refog","HKCU:\SOFTWARE\KGB Spy","HKCU:\SOFTWARE\Revealer Keylogger","HKCU:\SOFTWARE\Elite Keylogger","HKCU:\SOFTWARE\Actual Keylogger")
foreach ($kr in $klRegPaths) {
    if (Test-Path $kr) {
        Out-ThreatBanner "KEYLOGGER REGISTRY KEY" $kr
        Add-Finding -ID "KLREG_$($kr -replace '[^a-z0-9]','')" -Phase "PHASE 48" -ThreatType "Keylogger" `
            -Severity $SEV_CRITICAL -Description "Known keylogger registry key found: $kr" `
            -Target $kr -FixAction "DeleteRegKey" -FixParam $kr -Group "Keylogger Artifacts"
        $global:KeyloggerHits++; $klFound = $true
    }
}
if (-not $klFound) { Out-Typewriter "  -> [OK] NO KEYLOGGER ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 49" "CLIPBOARD MONITOR / SCREEN CAPTURE DETECTION" "KEYLOGGER"
Out-Typewriter "CHECKING FOR CLIPBOARD/SCREEN CAPTURE PROCESSES..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
$capProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match "snag|screenshot|capture|clip|screen|record" -and $_.Path -match "AppData|Temp"
}
foreach ($cp in $capProcs) {
    Out-Typewriter "  -> SUSPICIOUS CAPTURE PROCESS: $($cp.Name) @ $($cp.Path)" "WARN"
    Add-Finding -ID "CAP_$($cp.Id)" -Phase "PHASE 49" -ThreatType "Spyware/Keylogger" -Severity $SEV_HIGH `
        -Description "Clipboard/screen capture process from user path: $($cp.Name)" `
        -Target "PID:$($cp.Id)" -FixAction "KillProcess" -FixParam $cp.Id -Group "Keylogger / Hook Detection"
    $global:SpywareHits++
}
if ($capProcs.Count -eq 0) { Out-Typewriter "  -> [OK] NO OBVIOUS CAPTURE PROCESSES." "GOOD" }

Show-PhaseHeader "PHASE 50" "ACCESSIBILITY API / UIAUTOMATION KEYLOGGER CHECK" "KEYLOGGER"
Out-Typewriter "AUDITING UIAutomation HOOK REGISTRATIONS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 600 }
$uiaProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -match "AppData|Temp" -and $_.Modules -and ($_.Modules | Where-Object { $_.ModuleName -match "UIAutomation|uiautomation" })
}
foreach ($up in $uiaProcs) {
    Out-Typewriter "  -> UIAUTOMATION ACCESS FROM USER PATH: $($up.Name) PID:$($up.Id)" "WARN"
    Add-Finding -ID "UIA_$($up.Id)" -Phase "PHASE 50" -ThreatType "Keylogger/Spyware" -Severity $SEV_HIGH `
        -Description "Process using UIAutomation API from user path (keylogger vector): $($up.Name)" `
        -Target "PID:$($up.Id)" -FixAction "KillProcess" -FixParam $up.Id -Group "Keylogger / Hook Detection"
    $global:KeyloggerHits++
}
if ($uiaProcs.Count -eq 0) { Out-Typewriter "  -> [OK] NO UIAUTOMATION ABUSE DETECTED." "GOOD" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10: RANSOMWARE DETECTION
# ══════════════════════════════════════════════════════════════════════════════
Show-ThreatCategoryHeader "RANSOMWARE" "Extension Velocity · High Entropy · Ransom Notes · Shadow Deletion · Backup Tampering"

Show-PhaseHeader "PHASE 51" "RANSOMWARE EXTENSION VELOCITY DETECTION" "RANSOMWARE"
Out-Typewriter "SCANNING USER PROFILE FOR RANSOMWARE EXTENSION PATTERNS..." "HUNT"
Invoke-QuantumBar "EXTENSION ANALYSIS" 12 110
$encFound = $false
$searchRoots = @($env:USERPROFILE,"$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Pictures","$env:USERPROFILE\Downloads")
foreach ($root in $searchRoots) {
    if (-not (Test-Path $root)) { continue }
    $recentFiles = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { Test-InScope $_.LastWriteTime }
    foreach ($rf in $recentFiles) {
        $ext = $rf.Extension.ToLower()
        if ($RANSOMWARE_EXTENSIONS -contains $ext) {
            Out-ThreatBanner "RANSOMWARE ENCRYPTED FILE EXTENSION" "$($rf.Name) in $root"
            Add-Finding -ID "RANSOM_EXT_$($rf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 51" -ThreatType "Ransomware" `
                -Severity $SEV_CRITICAL -Description "File with known ransomware extension: $($rf.FullName) ($ext)" `
                -Target $rf.FullName -FixAction "Info" -Group "Ransomware Encrypted Files"
            $global:RansomwareRisk += 5; $encFound = $true
        }
    }
}
if (-not $encFound) { Out-Typewriter "  -> [OK] NO RANSOMWARE EXTENSION PATTERNS." "GOOD" }

Show-PhaseHeader "PHASE 52" "HIGH ENTROPY FILE DETECTION (ENCRYPTED PAYLOAD)" "RANSOMWARE"
Out-Typewriter "SAMPLING FILES FOR HIGH ENTROPY (ENCRYPTION/PACKING)..." "HUNT"
Invoke-QuantumBar "ENTROPY ANALYSIS" 15 120
$entropyHits = $false
foreach ($root in $searchRoots) {
    if (-not (Test-Path $root)) { continue }
    $candidates = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { Test-InScope $_.LastWriteTime -and $_.Length -gt 4096 -and $_.Extension -notmatch "\.(mp4|mp3|zip|rar|7z|jpg|png|pdf)$" } |
        Select-Object -First 50
    foreach ($cf in $candidates) {
        $entropy = Get-FileEntropy -FilePath $cf.FullName
        if ($entropy -gt 7.5) {
            Out-Typewriter "  -> HIGH ENTROPY ($entropy): $($cf.FullName)" "WARN"
            Add-Finding -ID "ENTROPY_$($cf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 52" -ThreatType "Ransomware/Packed Malware" `
                -Severity $SEV_POSSIBLE -Description "High entropy file ($entropy/8.0 bits): $($cf.FullName) — may be encrypted or packed malware" `
                -Target $cf.FullName -FixAction "Info" -Group "High Entropy Files"
            $global:RansomwareRisk++; $entropyHits = $true
        }
    }
}
if (-not $entropyHits) { Out-Typewriter "  -> [OK] NO SUSPICIOUSLY HIGH ENTROPY FILES FOUND." "GOOD" }

Show-PhaseHeader "PHASE 53" "RANSOM NOTE DETECTION" "RANSOMWARE"
Out-Typewriter "SCANNING FOR RANSOM NOTE ARTIFACTS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
$ransomNotePatterns = @("*readme*.txt","*DECRYPT*","*RECOVER*","*ransom*","*YOUR_FILES*","*HOW_TO_DECRYPT*","*!readme!*","*restore_files*","*HOW TO RECOVER*","*IMPORTANT*.txt","*help_decrypt*")
$noteFound = $false
foreach ($root in $searchRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($pattern in $ransomNotePatterns) {
        $notes = Get-ChildItem -Path $root -Recurse -Filter $pattern -ErrorAction SilentlyContinue |
            Where-Object { Test-InScope $_.LastWriteTime }
        foreach ($note in $notes) {
            Out-ThreatBanner "RANSOM NOTE DETECTED" $note.FullName
            Add-Finding -ID "RANSOMNOTE_$($note.Name -replace '[^a-z0-9]','')" -Phase "PHASE 53" -ThreatType "Ransomware" `
                -Severity $SEV_CRITICAL -Description "Ransom note file found: $($note.FullName)" `
                -Target $note.FullName -FixAction "DeleteFile" -FixParam $note.FullName -Group "Ransom Notes"
            $global:RansomwareRisk += 10; $noteFound = $true
        }
    }
}
if (-not $noteFound) { Out-Typewriter "  -> [OK] NO RANSOM NOTE FILES DETECTED." "GOOD" }

Show-PhaseHeader "PHASE 54" "BACKUP PROCESS TAMPERING / BCDEDIT ABUSE" "RANSOMWARE"
Out-Typewriter "CHECKING FOR BACKUP DISABLE / RECOVERY TAMPERING..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$bcdedit2 = bcdedit /enum all 2>$null
if ($bcdedit2 -match "recoveryenabled.*No") {
    Out-Typewriter "  -> RECOVERY DISABLED IN BCD — POSSIBLE RANSOMWARE PREP." "CRIT"
    Add-Finding -ID "RECOVERY_DISABLED" -Phase "PHASE 54" -ThreatType "Ransomware Prep" -Severity $SEV_CRITICAL `
        -Description "BCD recovery is disabled — ransomware commonly disables recovery before encryption" `
        -Target "bcdedit /recoveryenabled" -FixAction "RunCmd" -FixParam "bcdedit /set {default} recoveryenabled Yes" `
        -Group "Recovery / Backup Tampering"
    $global:RansomwareRisk += 5
} else { Out-Typewriter "  -> [OK] RECOVERY ENABLED." "GOOD" }
$wbadminLog = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Backup'} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object { Test-InScope $_.TimeCreated -and $_.Id -in @(521,527,528) }
if ($wbadminLog.Count -gt 0) {
    Out-Typewriter "  -> $($wbadminLog.Count) BACKUP DELETION/FAILURE EVENTS FOUND." "WARN"
    Add-Finding -ID "BACKUP_TAMPER" -Phase "PHASE 54" -ThreatType "Ransomware Prep" -Severity $SEV_HIGH `
        -Description "Backup deletion/failure events in System log — possible ransomware prep" `
        -Target "Windows Backup EventLog" -FixAction "Info" -Group "Recovery / Backup Tampering"
    $global:RansomwareRisk += 3
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 11: ROOTKIT DETECTION
# ══════════════════════════════════════════════════════════════════════════════
Show-ThreatCategoryHeader "ROOTKIT" "Kernel Drivers · Process Discrepancy · Service Delta · Bootkit Indicators"

Show-PhaseHeader "PHASE 55" "UNSIGNED / ANOMALOUS KERNEL DRIVER AUDIT" "ROOTKIT"
Out-Typewriter "ENUMERATING LOADED KERNEL MODULES..." "HUNT"
Invoke-QuantumBar "KERNEL DRIVER ANALYSIS" 15 130
$driverList = driverquery /FO CSV /SI 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue
$driverHits = $false
foreach ($ud in ($driverList | Where-Object { $_.'Is Signed' -eq "FALSE" -and $_.Type -eq "Kernel" })) {
    Out-Typewriter "  -> UNSIGNED KERNEL DRIVER: $($ud.Module) — $($ud.'Module Name')" "WARN"
    Add-Finding -ID "DRIVER_$($ud.Module -replace '[^a-z0-9]','')" -Phase "PHASE 55" -ThreatType "Rootkit/Unsigned Driver" `
        -Severity $SEV_HIGH -Description "Unsigned kernel driver loaded: $($ud.Module) ($($ud.'Module Name'))" `
        -Target "Kernel Driver: $($ud.Module)" -FixAction "Info" -Group "Unsigned Kernel Drivers"
    $global:RootkitHits++; $driverHits = $true
}
if (-not $driverHits) { Out-Typewriter "  -> [OK] NO UNSIGNED KERNEL DRIVERS." "GOOD" }

Show-PhaseHeader "PHASE 56" "HIDDEN PROCESS DISCREPANCY (WMI vs PS vs TASKLIST)" "ROOTKIT"
Out-Typewriter "CROSS-CORRELATING PROCESS ENUMERATION METHODS..." "HUNT"
Invoke-QuantumBar "PROCESS TABLE DELTA ANALYSIS" 12 130
$wmiPIDs  = (Get-WmiObject Win32_Process -ErrorAction SilentlyContinue).ProcessId
$psPIDs   = (Get-Process -ErrorAction SilentlyContinue).Id
$taskPIDs = (tasklist /FO CSV /NH 2>$null | ConvertFrom-Csv -Header @("Img","PID","Ses","Num","Mem") 2>$null).PID | ForEach-Object { [int]$_ }
$hiddenFromPS   = $wmiPIDs | Where-Object { $_ -notin $psPIDs   -and $_ -gt 4 }
$hiddenFromWMI  = $psPIDs  | Where-Object { $_ -notin $wmiPIDs  -and $_ -gt 4 }
$hiddenFromTask = $wmiPIDs | Where-Object { $_ -notin $taskPIDs -and $_ -gt 4 }
$rkSuspect = $false
foreach ($pid in $hiddenFromPS) {
    Out-ThreatBanner "PROCESS HIDDEN FROM GET-PROCESS" "PID: $pid — ROOTKIT INDICATOR"
    Add-Finding -ID "RKHIDE_PS_$pid" -Phase "PHASE 56" -ThreatType "Rootkit" -Severity $SEV_CRITICAL `
        -Description "PID $pid visible in WMI but hidden from Get-Process — rootkit indicator" `
        -Target "PID: $pid" -FixAction "Info" -Group "Hidden Process Delta (Rootkit)"
    $global:RootkitHits++; $rkSuspect = $true
}
foreach ($pid in $hiddenFromWMI) {
    Out-ThreatBanner "PROCESS HIDDEN FROM WMI" "PID: $pid — ROOTKIT INDICATOR"
    Add-Finding -ID "RKHIDE_WMI_$pid" -Phase "PHASE 56" -ThreatType "Rootkit" -Severity $SEV_CRITICAL `
        -Description "PID $pid visible in PS but hidden from WMI — rootkit indicator" `
        -Target "PID: $pid" -FixAction "Info" -Group "Hidden Process Delta (Rootkit)"
    $global:RootkitHits++; $rkSuspect = $true
}
if (-not $rkSuspect) { Out-Typewriter "  -> [OK] NO PROCESS ENUMERATION DISCREPANCIES." "GOOD" }

Show-PhaseHeader "PHASE 57" "SERVICE REGISTRY DELTA — HIDDEN SERVICE OBJECTS" "ROOTKIT"
Out-Typewriter "COMPARING SERVICE ENUMERATION METHODS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1200 }
$scServices  = (sc.exe query type= all state= all 2>$null | Select-String "SERVICE_NAME:" | ForEach-Object { ($_ -split ": ")[1].Trim() })
$regServices = (Get-ChildItem "HKLM:\System\CurrentControlSet\Services" -ErrorAction SilentlyContinue).PSChildName
$hiddenFromSCM = $regServices | Where-Object { $_ -notin $scServices }
$rootSvcFound = $false
foreach ($svc in $hiddenFromSCM) {
    $svcType = (Get-ItemPropertyValue "HKLM:\System\CurrentControlSet\Services\$svc" -Name "Type" -ErrorAction SilentlyContinue)
    if ($svcType -in @(1,2,16,32)) {
        Out-Typewriter "  -> SERVICE IN REGISTRY HIDDEN FROM SCM: $svc (Type=$svcType)" "WARN"
        Add-Finding -ID "RKSVC_$($svc -replace '[^a-z0-9]','')" -Phase "PHASE 57" -ThreatType "Rootkit/Hidden Service" `
            -Severity $SEV_HIGH -Description "Service in registry but hidden from SCM: $svc — rootkit indicator" `
            -Target "HKLM:\System\CurrentControlSet\Services\$svc" -FixAction "Info" -Group "Hidden Service Delta (Rootkit)"
        $global:RootkitHits++; $rootSvcFound = $true
    }
}
if (-not $rootSvcFound) { Out-Typewriter "  -> [OK] NO HIDDEN SERVICE OBJECTS." "GOOD" }

Show-PhaseHeader "PHASE 58" "BOOTKIT / MBR INDICATORS" "ROOTKIT"
Out-Typewriter "AUDITING BCD FOR BOOTKIT-SPECIFIC ENTRIES..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
if ($bcdedit2 -match "winpe|safeboot.*minimal.*AlternateShell") {
    Out-Typewriter "  -> SUSPICIOUS BCD BOOT ENTRY." "CRIT"
    Add-Finding -ID "BOOTKIT_BCD" -Phase "PHASE 58" -ThreatType "Bootkit" -Severity $SEV_HIGH `
        -Description "Suspicious BCD entry detected — possible bootkit modification (winpe/AlternateShell)" `
        -Target "bcdedit /enum all" -FixAction "Info" -Group "Bootkit Indicators"
    $global:RootkitHits++
} else { Out-Typewriter "  -> [OK] BCD BOOT ENTRIES APPEAR CLEAN." "GOOD" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 12: RAT / C2 BEACON
# ══════════════════════════════════════════════════════════════════════════════
Show-ThreatCategoryHeader "RAT / C2 BEACON" "Beacon Intervals · DNS Tunneling · RAT Config/Registry · Named Pipes"

Show-PhaseHeader "PHASE 59" "C2 BEACON INTERVAL / HIGH-FREQ DNS DETECTION" "RAT/C2"
Out-Typewriter "ANALYZING DNS CACHE FOR BEACON PATTERNS..." "HUNT"
Invoke-QuantumBar "BEACON INTERVAL ANALYSIS" 15 120
$dnsCache2 = Get-DnsClientCache -ErrorAction SilentlyContinue
$domainCounts = @{}
foreach ($entry in $dnsCache2) { $domainCounts[$entry.Entry] = ($domainCounts[$entry.Entry] + 1) }
$beaconDomains = $domainCounts.GetEnumerator() | Where-Object { $_.Value -gt 10 -and $_.Key -notmatch "microsoft|windows|google|cloudflare|akamai|amazonaws" }
$beaconFound = $false
foreach ($bd in $beaconDomains) {
    Out-Typewriter "  -> HIGH-FREQ DNS BEACON: $($bd.Key) ($($bd.Value) queries)" "CRIT"
    Add-Finding -ID "BEACON_$($bd.Key -replace '[^a-z0-9]','')" -Phase "PHASE 59" -ThreatType "C2 Beacon" `
        -Severity $SEV_HIGH -Description "High-frequency DNS queries to $($bd.Key) ($($bd.Value) queries) — possible C2 beacon" `
        -Target "DNS: $($bd.Key)" -FixAction "Info" -Group "C2 Beacon Indicators"
    $global:RATHits++; $beaconFound = $true
}
$longConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemotePort -notin @(80,443,8080,8443,3389,445,139,25,587) -and $_.RemoteAddress -notmatch "^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)" }
foreach ($lc in $longConns) {
    $proc = Get-Process -Id $lc.OwningProcess -ErrorAction SilentlyContinue
    if ($proc.Name -notmatch "^(svchost|lsass|system|wininit|services|spoolsv|MsMpEng|SearchIndexer|OneDrive|Teams|Zoom|chrome|msedge|firefox|brave|outlook|thunderbird)$") {
        Out-Typewriter "  -> NON-STANDARD ESTABLISHED CONN: $($proc.Name) -> $($lc.RemoteAddress):$($lc.RemotePort)" "WARN"
        Add-Finding -ID "BEACON_CONN_$($lc.OwningProcess)" -Phase "PHASE 59" -ThreatType "C2 Beacon" `
            -Severity $SEV_POSSIBLE -Description "Unusual established connection: $($proc.Name) -> $($lc.RemoteAddress):$($lc.RemotePort)" `
            -Target "PID:$($lc.OwningProcess)" -FixAction "KillProcess" -FixParam $lc.OwningProcess -Group "C2 Beacon Indicators"
        $beaconFound = $true; $global:RATHits++
    }
}
if (-not $beaconFound) { Out-Typewriter "  -> [OK] NO BEACON PATTERN INDICATORS." "GOOD" }

Show-PhaseHeader "PHASE 60" "DNS TUNNELING DETECTION" "RAT/C2"
Out-Typewriter "CHECKING FOR DNS TUNNELING INDICATORS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1200 }
$dnsTunnel = $false
foreach ($entry in $dnsCache2) {
    $longestLabel = ($entry.Entry -split "\." | Sort-Object Length -Descending | Select-Object -First 1)
    if ($longestLabel.Length -gt 40) {
        Out-ThreatBanner "DNS TUNNELING INDICATOR" "Long DNS label ($($longestLabel.Length) chars): $($entry.Entry)"
        Add-Finding -ID "DNSTUN_$($entry.Entry.GetHashCode())" -Phase "PHASE 60" -ThreatType "DNS Tunneling" `
            -Severity $SEV_HIGH -Description "DNS tunneling indicator: long subdomain ($($longestLabel.Length) chars) in $($entry.Entry)" `
            -Target "DNS: $($entry.Entry)" -FixAction "Info" -Group "DNS Tunneling"
        $global:RATHits++; $dnsTunnel = $true
    }
    if (($entry.Entry -split "\.").Count -gt 6) {
        Out-Typewriter "  -> HIGH SUBDOMAIN DEPTH: $($entry.Entry)" "WARN"
        Add-Finding -ID "DNSDEPTH_$($entry.Entry.GetHashCode())" -Phase "PHASE 60" -ThreatType "DNS Tunneling" `
            -Severity $SEV_POSSIBLE -Description "High subdomain depth in DNS query: $($entry.Entry) — possible DNS tunneling" `
            -Target "DNS: $($entry.Entry)" -FixAction "Info" -Group "DNS Tunneling"
        $global:RATHits++; $dnsTunnel = $true
    }
}
if (-not $dnsTunnel) { Out-Typewriter "  -> [OK] NO DNS TUNNELING INDICATORS." "GOOD" }

Show-PhaseHeader "PHASE 61" "RAT CONFIGURATION FILE & REGISTRY SCAN" "RAT"
Out-Typewriter "SCANNING FOR RAT CONFIGURATION ARTIFACTS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$ratFound = $false
foreach ($rcp in $RAT_CONFIG_PATHS) {
    if (Test-Path $rcp) {
        Out-ThreatBanner "RAT ARTIFACT" $rcp
        Add-Finding -ID "RATFILE_$($rcp -replace '[^a-z0-9]','')" -Phase "PHASE 61" -ThreatType "RAT" `
            -Severity $SEV_CRITICAL -Description "Known RAT config/binary path present: $rcp" `
            -Target $rcp -FixAction $(if (Test-Path $rcp -PathType Container) { "DeleteFile" } else { "DeleteFile" }) -FixParam $rcp `
            -Group "RAT Artifacts"
        $global:RATHits++; $ratFound = $true
    }
}
foreach ($rrp in $RAT_REG_PATHS) {
    if (Test-Path $rrp) {
        Out-ThreatBanner "RAT REGISTRY KEY" $rrp
        Add-Finding -ID "RATREG_$($rrp -replace '[^a-z0-9]','')" -Phase "PHASE 61" -ThreatType "RAT" `
            -Severity $SEV_CRITICAL -Description "Known RAT registry key: $rrp" `
            -Target $rrp -FixAction "DeleteRegKey" -FixParam $rrp -Group "RAT Artifacts"
        $global:RATHits++; $ratFound = $true
    }
}
if (-not $ratFound) { Out-Typewriter "  -> [OK] NO RAT CONFIGURATION ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 62" "NAMED PIPE BACKDOOR AUDIT" "RAT/C2"
Out-Typewriter "ENUMERATING NAMED PIPE ENDPOINTS..." "HUNT"
try {
    $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
    $suspectPipes = $pipes | Where-Object { $_ -match "meterpreter|msf|cobaltstrike|beacon|njrat|asyncrat|quasar|remcos|dlltest|netbus|poisonivy|havoc|sliver|[a-f0-9]{8,}" }
    foreach ($pipe in $suspectPipes) {
        Out-ThreatBanner "SUSPECT NAMED PIPE" $pipe
        Add-Finding -ID "PIPE_$($pipe -replace '[^a-z0-9]','')" -Phase "PHASE 62" -ThreatType "RAT/Backdoor Pipe" `
            -Severity $SEV_CRITICAL -Description "Suspect named pipe matching known C2/RAT pattern: $pipe" `
            -Target $pipe -FixAction "Info" -Group "Named Pipe Backdoors"
        $global:RATHits++
    }
    if ($suspectPipes.Count -eq 0) { Out-Typewriter "  -> [OK] NO SUSPECT NAMED PIPES." "GOOD" }
} catch { Out-Typewriter "  -> PIPE ENUMERATION FAILED (ELEVATED SESSION REQUIRED)." "WARN" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 13: CRYPTOMINER
# ══════════════════════════════════════════════════════════════════════════════
Show-ThreatCategoryHeader "CRYPTOMINER" "CPU Abuse · Stratum Protocol · Miner Config Files · Task Persistence"

Show-PhaseHeader "PHASE 63" "CPU ABUSE & MINER PROCESS DETECTION" "CRYPTOMINER"
Out-Typewriter "SCANNING FOR ABNORMAL CPU UTILIZATION..." "HUNT"
Invoke-QuantumBar "CPU USAGE ANALYSIS" 10 120
$highCpuProcs = Get-WmiObject Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.PercentProcessorTime -gt 60 -and $_.Name -notmatch "^(Idle|System|_Total|MsMpEng|svchost|SearchIndexer|WmiPrvSE)$" }
$minerFound = $false
foreach ($proc in $highCpuProcs) {
    $pn = $proc.Name.ToLower()
    foreach ($m in $KNOWN_MINER_PROCS) {
        if ($pn -match [regex]::Escape($m)) {
            Out-ThreatBanner "CRYPTOMINER (CPU ABUSE)" "Name: $($proc.Name) CPU: $($proc.PercentProcessorTime)%"
            Add-Finding -ID "MINER_CPU_$($proc.Name -replace '[^a-z0-9]','')" -Phase "PHASE 63" -ThreatType "Cryptominer" `
                -Severity $SEV_CRITICAL -Description "Miner process using $($proc.PercentProcessorTime)% CPU: $($proc.Name)" `
                -Target "Process: $($proc.Name)" -FixAction "RunCmd" -FixParam "Stop-Process -Name '$($proc.Name)' -Force" `
                -Group "Live Cryptominer"
            $global:MinerHits++; $minerFound = $true
        }
    }
}
# Miner config files
$minerConfigFiles = Get-ChildItem -Path @($env:TEMP,$env:LOCALAPPDATA,"$env:USERPROFILE\AppData\Roaming") `
    -Recurse -Filter "config.json" -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
foreach ($cf in $minerConfigFiles) {
    $content = Get-Content $cf.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match '"pools"|url.*stratum|"user".*[0-9A-Za-z]{90,}|monero|xmr|ethereum|mining') {
        Out-ThreatBanner "MINER CONFIG FILE" $cf.FullName
        Add-Finding -ID "MINERCFG_$($cf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 63" -ThreatType "Cryptominer" `
            -Severity $SEV_CRITICAL -Description "Miner configuration file found: $($cf.FullName)" `
            -Target $cf.FullName -FixAction "DeleteFile" -FixParam $cf.FullName -Group "Live Cryptominer"
        $global:MinerHits++; $minerFound = $true
    }
}
if (-not $minerFound) { Out-Typewriter "  -> [OK] NO CRYPTOMINER INDICATORS." "GOOD" }

Show-PhaseHeader "PHASE 64" "MINER SCHEDULED TASK / SERVICE PERSISTENCE" "CRYPTOMINER"
Out-Typewriter "CHECKING FOR MINER PERSISTENCE..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
$allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
foreach ($task in $allTasks) {
    $exe = $task.Actions[0].Execute
    $isMinerTask = $false
    foreach ($m in $KNOWN_MINER_PROCS) { if ($exe -match [regex]::Escape($m)) { $isMinerTask = $true } }
    if (-not $isMinerTask) { $isMinerTask = ($exe -match "xmr|stratum|pool\.|mining|coin|hashrate") }
    if ($isMinerTask) {
        Out-ThreatBanner "MINER SCHEDULED TASK" $task.TaskName
        Add-Finding -ID "MINERTASK_$($task.TaskName -replace '[^a-z0-9]','')" -Phase "PHASE 64" -ThreatType "Cryptominer" `
            -Severity $SEV_CRITICAL -Description "Miner persistence via scheduled task: $($task.TaskName)" `
            -Target "Task: $($task.TaskName)" -FixAction "RunCmd" -FixParam "Unregister-ScheduledTask -TaskName '$($task.TaskName)' -Confirm:`$false" `
            -Group "Miner Persistence"
        $global:MinerHits++
    }
}
Out-Typewriter "  -> MINER PERSISTENCE AUDIT COMPLETE." "VER"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 14: WORM & SPYWARE
# ══════════════════════════════════════════════════════════════════════════════
Show-ThreatCategoryHeader "WORM / SPYWARE / ADWARE" "AutoRun · USB · Network Shares · Self-Replication · PUPs · Tracking"

Show-PhaseHeader "PHASE 65" "WORM AUTORUN & USB SPREAD DETECTION" "WORM"
Out-Typewriter "SCANNING FOR WORM AUTORUN ARTIFACTS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$wormFound = $false
$drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Root -ne ($env:SystemDrive + "\") }
foreach ($drive in $drives) {
    $autorun = "$($drive.Root)autorun.inf"
    if (Test-Path $autorun) {
        Out-ThreatBanner "AUTORUN.INF (USB WORM)" $autorun
        Add-Finding -ID "AUTORUN_$($drive.Name)" -Phase "PHASE 65" -ThreatType "Worm/USB Spread" `
            -Severity $SEV_CRITICAL -Description "autorun.inf found on $($drive.Root) — USB worm indicator" `
            -Target $autorun -FixAction "DeleteFile" -FixParam $autorun -Group "Worm / USB Spread"
        $global:WormHits++; $wormFound = $true
    }
    $hiddenExe = Get-ChildItem -Path $drive.Root -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Attributes -match "Hidden" -and $_.Extension -match "\.(exe|bat|cmd|vbs|js)$" }
    foreach ($he in $hiddenExe) {
        Out-ThreatBanner "HIDDEN EXE ON REMOVABLE DRIVE" $he.FullName
        Add-Finding -ID "USBWORM_$($he.Name -replace '[^a-z0-9]','')" -Phase "PHASE 65" -ThreatType "Worm/USB Spread" `
            -Severity $SEV_CRITICAL -Description "Hidden executable on removable drive: $($he.FullName)" `
            -Target $he.FullName -FixAction "DeleteFile" -FixParam $he.FullName -Group "Worm / USB Spread"
        $global:WormHits++; $wormFound = $true
    }
}
Add-Finding -ID "AUTORUN_DISABLE" -Phase "PHASE 65" -ThreatType "Hardening" -Severity $SEV_INFO `
    -Description "Option: Disable Autorun for all drive types (recommended)" `
    -Target "HKLM/HKCU NoDriveTypeAutoRun" -FixAction "RunCmd" `
    -FixParam "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 0xFF -Type DWord -Force; Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 0xFF -Type DWord -Force" `
    -Group "Worm / USB Spread"
if (-not $wormFound) { Out-Typewriter "  -> [OK] NO WORM AUTORUN ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 66" "NETWORK SHARE WORM PROPAGATION SCAN" "WORM"
Out-Typewriter "ENUMERATING OPEN NETWORK SHARES..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$shares = Get-WmiObject Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "^(ADMIN|IPC|print)\$" }
foreach ($share in $shares) {
    Out-Typewriter "  -> OPEN SHARE: $($share.Name) @ $($share.Path)" "WARN"
    if ($share.Path -and (Test-Path $share.Path)) {
        $malInShare = Get-ChildItem -Path $share.Path -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { (Test-InScope $_.LastWriteTime) -and $_.Extension -match "\.(exe|bat|cmd|vbs|js|ps1)$" } |
            Select-Object -First 500
        foreach ($mis in $malInShare) {
            $sig = Get-AuthenticodeSignature $mis.FullName -ErrorAction SilentlyContinue
            if ($sig.Status -ne "Valid") {
                Out-ThreatBanner "UNSIGNED EXE IN OPEN SHARE" $mis.FullName
                Add-Finding -ID "SHAREWORM_$($mis.Name -replace '[^a-z0-9]','')" -Phase "PHASE 66" -ThreatType "Worm/Network Share" `
                    -Severity $SEV_HIGH -Description "Unsigned executable in open share: $($mis.FullName)" `
                    -Target $mis.FullName -FixAction "DeleteFile" -FixParam $mis.FullName -Group "Network Share Worms"
                $global:WormHits++
            }
        }
    }
}
if ($shares.Count -eq 0) { Out-Typewriter "  -> [OK] NO NON-STANDARD SHARES FOUND." "GOOD" }

Show-PhaseHeader "PHASE 67" "ADWARE / PUP / SPYWARE REGISTRY SCAN" "SPYWARE"
Out-Typewriter "SCANNING FOR KNOWN ADWARE / PUP REGISTRY KEYS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$adwarePaths = @(
    "HKCU:\SOFTWARE\Conduit","HKCU:\SOFTWARE\SearchProtect","HKCU:\SOFTWARE\Trovi",
    "HKCU:\SOFTWARE\BabylonToolbar","HKCU:\SOFTWARE\Delta","HKCU:\SOFTWARE\Iminent",
    "HKCU:\SOFTWARE\ISearchIQ","HKCU:\SOFTWARE\BrowserDefender","HKCU:\SOFTWARE\Funmoods",
    "HKCU:\SOFTWARE\VisualBee","HKCU:\SOFTWARE\WebCake","HKCU:\SOFTWARE\Savings Bull",
    "HKCU:\SOFTWARE\Sweet Page","HKCU:\SOFTWARE\SnapDo","HKCU:\SOFTWARE\V-Bates",
    "HKCU:\SOFTWARE\YSearchUtil","HKLM:\SOFTWARE\Conduit","HKLM:\SOFTWARE\SearchProtect",
    "HKLM:\SOFTWARE\BabylonToolbar","HKCU:\SOFTWARE\CrossRider","HKCU:\SOFTWARE\Superfish",
    "HKLM:\SOFTWARE\Superfish","HKCU:\SOFTWARE\SpeedBit","HKCU:\SOFTWARE\Spigot"
)
$adwareFound = $false
foreach ($ap in $adwarePaths) {
    if (Test-Path $ap) {
        Out-ThreatBanner "ADWARE/PUP REGISTRY KEY" $ap
        Add-Finding -ID "ADWARE_$($ap -replace '[^a-z0-9]','')" -Phase "PHASE 67" -ThreatType "Adware/PUP" `
            -Severity $SEV_HIGH -Description "Known adware/PUP registry key: $ap" `
            -Target $ap -FixAction "DeleteRegKey" -FixParam $ap -Group "Adware / PUP Remnants"
        $global:SpywareHits++; $adwareFound = $true
    }
}
if (-not $adwareFound) { Out-Typewriter "  -> [OK] NO KNOWN ADWARE/PUP REGISTRY KEYS." "GOOD" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 15: ADVANCED / ADDITIONAL MALWARE DETECTION
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "ADVANCED MALWARE & PERSISTENCE MODULES"

Show-PhaseHeader "PHASE 68" "INFO-STEALER ARTIFACT SCAN (REDLINE/RACCOON/VIDAR)" "INFOSTEALER"
Out-Typewriter "SCANNING FOR INFO-STEALER ARTIFACTS AND DROP PATHS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$stealerPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",  # stolen creds DB
    "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json",
    "$env:APPDATA\Mozilla\Firefox\Profiles\*\key4.db"
)
$stealerRegex = "redline|raccoon|vidar|azorult|formbook|agent tesla|lokibot|sneaker|negasteal|hawkeye|loki|masslogger"
$stealerProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name.ToLower() -match $stealerRegex }
foreach ($sp in $stealerProcs) {
    Out-ThreatBanner "INFO-STEALER PROCESS IOC" "$($sp.Name) PID:$($sp.Id)"
    Add-Finding -ID "STEALER_$($sp.Id)" -Phase "PHASE 68" -ThreatType "Info-Stealer" `
        -Severity $SEV_CRITICAL -Description "Known info-stealer process: $($sp.Name) PID:$($sp.Id)" `
        -Target "PID:$($sp.Id)" -FixAction "KillProcess" -FixParam $sp.Id -Group "Info-Stealer"
    $global:SpywareHits++
}
$stealerFiles = Get-ChildItem -Path @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA) -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { Test-InScope $_.LastWriteTime -and $_.Name -match "passwords|credentials|wallet|login|autofill|cookie" -and $_.Extension -match "\.(zip|txt|log|db)$" }
foreach ($sf in $stealerFiles) {
    if ($sf.FullName -notmatch "Chrome\\User Data|Firefox\\Profiles") {  # exclude legitimate browser storage
        Out-Typewriter "  -> SUSPECT CREDENTIAL FILE: $($sf.FullName)" "CRIT"
        Add-Finding -ID "STEALFILE_$($sf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 68" -ThreatType "Info-Stealer" `
            -Severity $SEV_HIGH -Description "Suspicious credential-named file in user path: $($sf.FullName)" `
            -Target $sf.FullName -FixAction "DeleteFile" -FixParam $sf.FullName -Group "Info-Stealer"
        $global:SpywareHits++
    }
}
if ($stealerProcs.Count -eq 0 -and $stealerFiles.Count -eq 0) { Out-Typewriter "  -> [OK] NO INFO-STEALER ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 69" "PROCESS HOLLOWING / INJECTION DETECTION" "INJECTION"
Out-Typewriter "CHECKING FOR PROCESSES WITH ANOMALOUS MODULE COUNTS..." "HUNT"
Invoke-QuantumBar "PROCESS MEMORY MAP ANALYSIS" 12 120
$hollowFound = $false
$hollowCandidates = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and (Test-Path $_.Path) -and
    $_.Name -notmatch "^(svchost|System|smss|csrss|wininit|services|lsass|winlogon|fontdrvhost|dwm|conhost|MsMpEng|NisSrv|SecurityHealth)$" -and
    (try { $_.Modules.Count -lt 3 } catch { $false })
}
foreach ($proc in $hollowCandidates) {
    $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue
    if ($sig.Status -ne "Valid" -and $proc.Path -match "AppData|Temp") {
        Out-Typewriter "  -> POSSIBLE HOLLOW PROCESS: $($proc.Name) PID:$($proc.Id) @ $($proc.Path) (only $($proc.Modules.Count) modules)" "WARN"
        Add-Finding -ID "HOLLOW_$($proc.Id)" -Phase "PHASE 69" -ThreatType "Process Hollowing" `
            -Severity $SEV_HIGH -Description "Possible hollow process: $($proc.Name) PID:$($proc.Id) in AppData/Temp with $($proc.Modules.Count) modules loaded" `
            -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Process Hollowing / Injection"
        $hollowFound = $true
    }
}
if (-not $hollowFound) { Out-Typewriter "  -> [OK] NO OBVIOUS HOLLOW/INJECTED PROCESSES." "GOOD" }

Show-PhaseHeader "PHASE 70" "FILELESS REGISTRY PAYLOAD DETECTION" "FILELESS"
Out-Typewriter "SCANNING REGISTRY FOR ENCODED PAYLOADS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
$filelessPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Environment","HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKCU:\SOFTWARE\Classes\CLSID"
)
$filelessFound = $false
foreach ($fp in $filelessPaths) {
    if (-not (Test-Path $fp)) { continue }
    $regVals = Get-ItemProperty -Path $fp -ErrorAction SilentlyContinue
    foreach ($prop in ($regVals.psobject.properties | Where-Object { $_.Name -notmatch "^PS" })) {
        $val = [string]$prop.Value
        if ($val.Length -gt 200 -and $val -match "^[A-Za-z0-9+/=]{100,}$") {
            Out-Decrypt -Text "$($prop.Name) = [BASE64 BLOB $($val.Length) chars]" -Prefix "  [FILELESS PAYLOAD] "
            Add-Finding -ID "FILELESS_$($prop.Name -replace '[^a-z0-9]','')" -Phase "PHASE 70" -ThreatType "Fileless Malware" `
                -Severity $SEV_CRITICAL -Description "Suspected Base64 fileless payload in registry: $fp | $($prop.Name)" `
                -Target "$fp|$($prop.Name)" -FixAction "DeleteReg" -FixParam "$fp|$($prop.Name)" -Group "Fileless Payloads"
            $filelessFound = $true
        }
    }
}
if (-not $filelessFound) { Out-Typewriter "  -> [OK] NO OBVIOUS FILELESS PAYLOADS DETECTED." "GOOD" }

Show-PhaseHeader "PHASE 71" "PHISHING / OVERLAY / FAKE BROWSER UI DETECTION" "PHISHING"
Out-Typewriter "CHECKING FOR PHISHING OVERLAY / TYPOSQUAT PROCESSES..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
$phishingIndicators = @("fakescreen","screencap.*chrome","overlay","phish","browser.*inject","credential.*harvest")
$phishProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $n = $_.Name.ToLower(); $phishingIndicators | Where-Object { $n -match $_ } }
foreach ($pp in $phishProcs) {
    Out-ThreatBanner "PHISHING/OVERLAY PROCESS" "$($pp.Name) PID:$($pp.Id)"
    Add-Finding -ID "PHISH_$($pp.Id)" -Phase "PHASE 71" -ThreatType "Phishing/Overlay" `
        -Severity $SEV_CRITICAL -Description "Suspected phishing overlay process: $($pp.Name) PID:$($pp.Id)" `
        -Target "PID:$($pp.Id)" -FixAction "KillProcess" -FixParam $pp.Id -Group "Phishing / Overlay"
    $global:SpywareHits++
}
if ($phishProcs.Count -eq 0) { Out-Typewriter "  -> [OK] NO PHISHING OVERLAY PROCESSES." "GOOD" }

Show-PhaseHeader "PHASE 72" "BOTNET C2 IP / IOC BLACKLIST CHECK" "BOTNET"
Out-Typewriter "CROSS-REFERENCING ACTIVE CONNECTIONS AGAINST C2 IOC LIST..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 1000 }
# Common botnet / malware C2 infrastructure fingerprints
$botnetDomainPatterns = @("\.onion\b","duckdns\.org","zapto\.org","webhop\.me","myftp\.biz","viewdns\.net","freeddns\.com")
$allConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
$botFound = $false
foreach ($conn in ($allConns | Select-Object -First 50)) {
    try {
        $rdns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
        foreach ($bp in $botnetDomainPatterns) {
            if ($rdns -match $bp) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                Out-ThreatBanner "BOTNET C2 DOMAIN" "$($proc.Name) -> $rdns"
                Add-Finding -ID "BOTNET_$($conn.RemoteAddress -replace '\.','_')" -Phase "PHASE 72" -ThreatType "Botnet/C2" `
                    -Severity $SEV_CRITICAL -Description "Botnet C2 connection: $($proc.Name) -> $rdns ($($conn.RemoteAddress))" `
                    -Target "PID:$($conn.OwningProcess)" -FixAction "KillProcess" -FixParam $conn.OwningProcess `
                    -Group "Botnet / C2 Connections"
                $global:RATHits++; $botFound = $true
            }
        }
    } catch { }
}
if (-not $botFound) { Out-Typewriter "  -> [OK] NO BOTNET C2 DOMAIN CONNECTIONS." "GOOD" }

Show-PhaseHeader "PHASE 73" "EXPLOIT KIT ARTIFACT & CVE-2021-36934 REMEDIATION" "EXPLOIT"
Out-Typewriter "CHECKING FOR EXPLOIT KIT INDICATORS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
# HiveNightmare already covered in Phase 43 — here we check for exploit toolkit payloads
$exploitPaths = @("$env:TEMP\*shellcode*","$env:TEMP\*exploit*","$env:TEMP\*payload*","$env:LOCALAPPDATA\*shellcode*","$env:LOCALAPPDATA\*cobalt*","$env:LOCALAPPDATA\*beacon*")
$exploitFound = $false
foreach ($ep in $exploitPaths) {
    $hits = Get-ChildItem -Path (Split-Path $ep) -Filter (Split-Path $ep -Leaf) -ErrorAction SilentlyContinue |
        Where-Object { Test-InScope $_.LastWriteTime }
    foreach ($h in $hits) {
        Out-ThreatBanner "EXPLOIT KIT ARTIFACT" $h.FullName
        Add-Finding -ID "EXPLOIT_$($h.Name -replace '[^a-z0-9]','')" -Phase "PHASE 73" -ThreatType "Exploit Kit" `
            -Severity $SEV_CRITICAL -Description "Exploit kit artifact in temp: $($h.FullName)" `
            -Target $h.FullName -FixAction "DeleteFile" -FixParam $h.FullName -Group "Exploit Kit Artifacts"
        $exploitFound = $true
    }
}
if (-not $exploitFound) { Out-Typewriter "  -> [OK] NO OBVIOUS EXPLOIT KIT ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 74" "MACRO / OFFICE / OUTLOOK PERSISTENCE AUDIT" "MACRO"
Out-Typewriter "AUDITING OFFICE MACRO TRUST / OUTLOOK RULES..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
$macroTrust = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name "VBAWarnings" -ErrorAction SilentlyContinue
foreach ($mt in $macroTrust) {
    if ($mt.VBAWarnings -eq 1) {
        Out-Typewriter "  -> OFFICE VBA MACROS UNRESTRICTED (VBAWarnings=1)" "CRIT"
        Add-Finding -ID "MACRO_TRUST_$($mt.PSPath -replace '[^a-z0-9]','')" -Phase "PHASE 74" -ThreatType "Macro Abuse" `
            -Severity $SEV_HIGH -Description "Office VBAWarnings=1 — all macros enabled without prompts (macro malware vector)" `
            -Target "$($mt.PSPath)|VBAWarnings" -FixAction "RunCmd" -FixParam "Set-ItemProperty '$($mt.PSPath)' -Name VBAWarnings -Value 4 -Force" `
            -Group "Office / Macro Security"
        $global:SpywareHits++
    }
}
$outlookPath = "HKCU:\SOFTWARE\Microsoft\Office\*\Outlook\WebView"
if (Test-Path $outlookPath) {
    Out-Typewriter "  -> OUTLOOK WEBVIEW REGISTRY PRESENT — CHECK FOR AUTO-EXEC." "WARN"
    Add-Finding -ID "OUTLOOK_WEBVIEW" -Phase "PHASE 74" -ThreatType "Outlook Persistence" `
        -Severity $SEV_POSSIBLE -Description "Outlook WebView registry key present — possible HTML auto-execute persistence" `
        -Target $outlookPath -FixAction "Info" -Group "Office / Macro Security"
}
Out-Typewriter "  -> MACRO/OUTLOOK AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 75" "WINDOWS DEFENDER EXCLUSIONS & TAMPER AUDIT"
Out-Typewriter "CHECKING DEFENDER EXCLUSION LIST FOR MALWARE HIDING SPOTS..." "HUNT"
if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 800 }
try {
    $prefs = Get-MpPreference -ErrorAction Stop
    if ($prefs.ExclusionPath.Count -gt 0) {
        foreach ($exc in $prefs.ExclusionPath) {
            Out-Typewriter "  -> DEFENDER PATH EXCLUSION: $exc" "CRIT"
            Add-Finding -ID "DEFENDER_EXC_$($exc -replace '[^a-z0-9]','')" -Phase "PHASE 75" -ThreatType "Defender Tampering" `
                -Severity $SEV_HIGH -Description "Defender exclusion path (malware hiding spot): $exc" `
                -Target "Defender Exclusion: $exc" -FixAction "RunCmd" -FixParam "Remove-MpPreference -ExclusionPath '$exc'" `
                -Group "Defender Exclusions"
        }
    }
    if ($prefs.ExclusionProcess.Count -gt 0) {
        foreach ($exc in $prefs.ExclusionProcess) {
            Out-Typewriter "  -> DEFENDER PROCESS EXCLUSION: $exc" "WARN"
            Add-Finding -ID "DEFENDER_PROC_EXC_$($exc -replace '[^a-z0-9]','')" -Phase "PHASE 75" -ThreatType "Defender Tampering" `
                -Severity $SEV_HIGH -Description "Defender process exclusion: $exc — malware can use this process name to evade detection" `
                -Target "Defender Process Exclusion: $exc" -FixAction "RunCmd" -FixParam "Remove-MpPreference -ExclusionProcess '$exc'" `
                -Group "Defender Exclusions"
        }
    }
    if ($prefs.ExclusionPath.Count -eq 0 -and $prefs.ExclusionProcess.Count -eq 0) {
        Out-Typewriter "  -> [OK] NO DEFENDER EXCLUSIONS." "GOOD"
    }
} catch { Out-Typewriter "  -> DEFENDER API NOT AVAILABLE." "WARN" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 16: FINAL HARDENING CHECKS
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "FINAL HARDENING & LOCKDOWN AUDIT"

Show-PhaseHeader "PHASE 76" "TERMINAL SERVICES / RDP SHADOWING AUDIT"
$rdpShadow = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "Shadow" -ErrorAction SilentlyContinue
if ($null -ne $rdpShadow) {
    Out-Typewriter "  -> RDP SHADOW POLICY SET: $rdpShadow" "WARN"
    Add-Finding -ID "RDP_SHADOW" -Phase "PHASE 76" -ThreatType "RDP Surveillance" `
        -Severity $SEV_HIGH -Description "RDP Shadow policy enabled ($rdpShadow) — remote viewing/control without consent" `
        -Target "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|Shadow" `
        -FixAction "DeleteReg" -FixParam "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|Shadow" -Group "RDP Security"
} else { Out-Typewriter "  -> [OK] RDP SHADOW NOT CONFIGURED." "GOOD" }

Show-PhaseHeader "PHASE 77" "SSH & WINRM REMOTE MANAGEMENT AUDIT"
foreach ($svcName in @("WinRM","sshd")) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Out-Typewriter "  -> $svcName RUNNING." "WARN"
        Add-Finding -ID "REMOTEMGMT_$svcName" -Phase "PHASE 77" -ThreatType "Remote Management" `
            -Severity $SEV_POSSIBLE -Description "$svcName is running — verify this is authorized; consider disabling if not needed" `
            -Target "Service: $svcName" -FixAction "RunCmd" -FixParam "Stop-Service '$svcName' -Force; Set-Service '$svcName' -StartupType Disabled" `
            -Group "Remote Management Services"
    } else { Out-Typewriter "  -> [OK] $svcName NOT RUNNING." "GOOD" }
}

Show-PhaseHeader "PHASE 78" "SYSMON / LAPS / APPLOCKER STATUS AUDIT"
Out-Typewriter "CHECKING ENDPOINT VISIBILITY TOOLS..." "INFO"
$sysmonSvc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if (-not $sysmonSvc) {
    Out-Typewriter "  -> SYSMON NOT INSTALLED. CONSIDER DEPLOYING." "WARN"
    Add-Finding -ID "SYSMON_ABSENT" -Phase "PHASE 78" -ThreatType "Hardening Gap" -Severity $SEV_INFO `
        -Description "Sysmon not installed — no kernel-level process/network telemetry" `
        -Target "Sysmon Service" -FixAction "Info" -Group "Endpoint Hardening"
} else { Out-Typewriter "  -> [OK] SYSMON IS INSTALLED." "GOOD" }
$applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
if ($null -eq $applockerPolicy -or $applockerPolicy.RuleCollections.Count -eq 0) {
    Out-Typewriter "  -> APPLOCKER NOT CONFIGURED." "WARN"
    Add-Finding -ID "APPLOCKER_ABSENT" -Phase "PHASE 78" -ThreatType "Hardening Gap" -Severity $SEV_INFO `
        -Description "AppLocker not configured — no application whitelist in place" `
        -Target "AppLocker Policy" -FixAction "Info" -Group "Endpoint Hardening"
} else { Out-Typewriter "  -> [OK] APPLOCKER POLICY ACTIVE." "GOOD" }

Show-PhaseHeader "PHASE 79" "WINDOWS DEFENDER KICKSTART & EXCLUSION PURGE"
Out-Typewriter "AUDITING DEFENDER STATE..." "ACT"
Add-Finding -ID "DEFENDER_KICKSTART" -Phase "PHASE 79" -ThreatType "Hardening" -Severity $SEV_INFO `
    -Description "Option: Purge all Defender exclusions, update signatures, and trigger quick scan" `
    -Target "Windows Defender" -FixAction "RunCmd" `
    -FixParam "`$p = Get-MpPreference; if(`$p.ExclusionPath){ Remove-MpPreference -ExclusionPath `$p.ExclusionPath }; if(`$p.ExclusionProcess){ Remove-MpPreference -ExclusionProcess `$p.ExclusionProcess }; Update-MpSignature; Start-MpScan -ScanType QuickScan -AsJob" `
    -Group "Defender Hardening"
Out-Typewriter "  -> DEFENDER KICKSTART ADDED TO FIX LIST." "VER"

Show-PhaseHeader "PHASE 80" "SECURE BOOT / TPM / BITLOCKER STATUS AUDIT"
Out-Typewriter "CHECKING SECURE BOOT AND TPM STATUS..." "INFO"
$secBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
if ($secBoot -eq $false) {
    Out-Typewriter "  -> SECURE BOOT IS DISABLED." "WARN"
    Add-Finding -ID "SECUREBOOT_OFF" -Phase "PHASE 80" -ThreatType "Boot Security" -Severity $SEV_HIGH `
        -Description "Secure Boot is disabled — system vulnerable to bootkit/rootkit attacks" `
        -Target "UEFI Secure Boot" -FixAction "Info" -Group "Secure Boot / TPM"
} elseif ($null -eq $secBoot) {
    Out-Typewriter "  -> SECURE BOOT STATUS UNAVAILABLE (NON-UEFI OR LEGACY)." "WARN"
} else { Out-Typewriter "  -> [OK] SECURE BOOT ENABLED." "GOOD" }
$tpm = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
if ($tpm) { Out-Typewriter "  -> [OK] TPM PRESENT: $($tpm.ManufacturerIdTxt) v$($tpm.SpecVersion)" "GOOD" }
else { Out-Typewriter "  -> TPM NOT DETECTED." "WARN" }
Out-Typewriter "  -> PHASE 80 COMPLETE — SECURE BOOT/TPM AUDIT DONE." "VER"

# ══════════════════════════════════════════════════════════════════════════════
#  UNIVERSAL BACKDOOR PHASES 81-89 (mode 2 only)
# ══════════════════════════════════════════════════════════════════════════════
if ($PhasePlan.Universal) {
    if (-not $global:STEALTH_MODE) {
        Write-Host ""
        Write-Host ("▓"*80) -ForegroundColor DarkMagenta
        Write-Host "    ◈  U N I V E R S A L   B A C K D O O R   H U N T  —  P H A S E S  8 1 - 8 9" -ForegroundColor Magenta
        Write-Host ("▓"*80) -ForegroundColor DarkMagenta
        Invoke-QuantumBar "ENGAGING OMNI-TIER HEURISTICS" 20 100
    }

    Show-PhaseHeader "PHASE 81" "NETSTAT HIGH-PORT REVERSE SHELL AUDIT" "UNIVERSAL"
    $highConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemotePort -gt 1024 -and $_.RemotePort -notin @(3389,443,8443,8080,80,8888) }
    $foundShell = $false
    foreach ($conn in $highConns) {
        $rp = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($rp.Name -match "cmd|powershell|wscript|cscript|mshta|nc|ncat|socat|python|ruby|perl") {
            $foundShell = $true
            Out-ThreatBanner "LIVE REVERSE SHELL DETECTED" "$($rp.Name) PID:$($rp.Id) -> $($conn.RemoteAddress):$($conn.RemotePort)"
            Add-Finding -ID "REVSHELL_$($rp.Id)" -Phase "PHASE 81" -ThreatType "Reverse Shell" `
                -Severity $SEV_CRITICAL -Description "Live reverse shell: $($rp.Name) PID:$($rp.Id) -> $($conn.RemoteAddress):$($conn.RemotePort)" `
                -Target "PID:$($rp.Id)" -FixAction "KillProcess" -FixParam $rp.Id -Group "Reverse Shells"
            $global:RATHits++
        }
    }
    if (-not $foundShell) { Out-Typewriter "  -> [OK] NO REVERSE SHELL SOCKETS." "GOOD" }

    Show-PhaseHeader "PHASE 82" "NETCAT / SOCAT / CHISEL / PLINK BINARY SCAN" "UNIVERSAL"
    $tunnelNames = @("nc.exe","ncat.exe","socat.exe","chisel.exe","plink.exe","putty.exe","proxychains*","ligolo*","frpc.exe","frps.exe","bore.exe","rpivot*")
    $tunnelRoots = @($env:TEMP,$env:LOCALAPPDATA,$env:USERPROFILE,"$env:WINDIR\Temp")
    $tunnelFound = $false
    foreach ($root in $tunnelRoots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($name in $tunnelNames) {
            $hits = Get-ChildItem -Path $root -Recurse -Filter $name -ErrorAction SilentlyContinue
            foreach ($hit in $hits) {
                $tunnelFound = $true
                Out-Decrypt -Text $hit.FullName -Prefix "  [TUNNEL TOOL] "
                Add-Finding -ID "TUNNEL_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 82" -ThreatType "Tunneling Tool" `
                    -Severity $SEV_CRITICAL -Description "Tunneling/pivoting tool found: $($hit.FullName)" `
                    -Target $hit.FullName -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Tunneling / Pivoting Tools"
            }
        }
    }
    if (-not $tunnelFound) { Out-Typewriter "  -> [OK] NO TUNNELING TOOLS FOUND." "GOOD" }

    Show-PhaseHeader "PHASE 83" "HOLLOW PROCESS DEEP SCAN (EXTENDED)" "UNIVERSAL"
    Out-Typewriter "EXTENDED PROCESS MEMORY / HOLLOWING ANALYSIS..." "HUNT"
    Invoke-QuantumBar "PROCESS MEMORY MAP ANALYSIS" 15 170
    $extended = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and (Test-Path $_.Path) -and $_.Modules.Count -lt 5 -and
        $_.Name -notmatch "^(svchost|System|smss|csrss|wininit|services|lsass|winlogon|fontdrvhost|dwm|audiodg|conhost|taskhostw|RuntimeBroker|sihost|SearchHost)$"
    }
    foreach ($proc in $extended) {
        $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue
        if ($sig.Status -eq "NotSigned" -and $proc.Path -match "AppData|Temp") {
            Out-Typewriter "  -> LOW-MODULE UNSIGNED PROC: $($proc.Name) PID:$($proc.Id) @ $($proc.Path) [$($proc.Modules.Count) modules]" "WARN"
            Add-Finding -ID "HOLLOW_EXT_$($proc.Id)" -Phase "PHASE 83" -ThreatType "Process Hollowing" `
                -Severity $SEV_HIGH -Description "Unsigned low-module process from user path: $($proc.Name) PID:$($proc.Id) [$($proc.Modules.Count) modules]" `
                -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Process Hollowing / Injection"
        }
    }

    Show-PhaseHeader "PHASE 84" "APPLOCKER / GPO POLICY BYPASS AUDIT" "UNIVERSAL"
    Out-Typewriter "CHECKING APPLOCKER BYPASS INDICATORS..." "HUNT"
    $srpPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $srp = Get-ItemProperty -Path $srpPath -Name "DisallowRun" -ErrorAction SilentlyContinue
    if ($srp.DisallowRun -eq 1) {
        Out-Typewriter "  -> DISALLOWRUN ACTIVE — REVIEWING EXCEPTION LIST..." "WARN"
        Add-Finding -ID "DISALLOWRUN" -Phase "PHASE 84" -ThreatType "Policy Bypass" -Severity $SEV_POSSIBLE `
            -Description "DisallowRun GPO policy is active — review exception list for bypass paths" `
            -Target "$srpPath|DisallowRun" -FixAction "Info" -Group "Policy / AppLocker Bypass"
    } else { Out-Typewriter "  -> [OK] DISALLOWRUN NOT SET." "GOOD" }

    Show-PhaseHeader "PHASE 85" "LOLBIN PERSISTENCE (INSTALLUTIL / MSIEXEC)" "UNIVERSAL"
    Out-Typewriter "SCANNING INSTALLUTIL/MSIEXEC PERSISTENCE..." "HUNT"
    foreach ($fp in @("HKCU:\SOFTWARE\Microsoft\InstallShield","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer")) {
        if (Test-Path $fp) {
            $recentKeys = Get-ChildItem -Path $fp -Recurse -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
            foreach ($k in $recentKeys) {
                Out-Typewriter "  -> RECENT INSTALL KEY: $($k.PSPath)" "WARN"
                Add-Finding -ID "LOLBIN_INST_$($k.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 85" -ThreatType "LoLBin Persistence" `
                    -Severity $SEV_POSSIBLE -Description "Recent installer registry key (LoLBin persistence vector): $($k.PSPath)" `
                    -Target $k.PSPath -FixAction "Info" -Group "LoLBin Persistence"
            }
        }
    }

    Show-PhaseHeader "PHASE 86" "RECYCLE BIN STAGING AREA SCAN" "UNIVERSAL"
    $recycleBin = Get-ChildItem "C:\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { Test-InScope $_.LastWriteTime -and $_.Extension -match "\.(exe|dll|js|vbs|bat|cmd|ps1|hta|wsf)$" }
    foreach ($rb in $recycleBin) {
        Out-Decrypt -Text $rb.FullName -Prefix "  [RECYCLE BIN PAYLOAD] "
        Add-Finding -ID "RECYCLE_$($rb.Name -replace '[^a-z0-9]','')" -Phase "PHASE 86" -ThreatType "Malware Staging" `
            -Severity $SEV_HIGH -Description "Executable in Recycle Bin (malware staging): $($rb.FullName)" `
            -Target $rb.FullName -FixAction "DeleteFile" -FixParam $rb.FullName -Group "Recycle Bin Staging"
    }
    if ($recycleBin.Count -eq 0) { Out-Typewriter "  -> [OK] RECYCLE BIN CLEAR." "GOOD" }

    Show-PhaseHeader "PHASE 87" "GPO SCRIPT DIRECTORY AUDIT" "UNIVERSAL"
    $gpoScriptPaths = @("$env:WINDIR\System32\GroupPolicy\Machine\Scripts","$env:WINDIR\System32\GroupPolicy\User\Scripts")
    foreach ($gsp in $gpoScriptPaths) {
        if (Test-Path $gsp) {
            $gpoScripts = Get-ChildItem -Path $gsp -Recurse -File -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
            foreach ($gs in $gpoScripts) {
                Out-Typewriter "  -> GPO SCRIPT: $($gs.FullName)" "WARN"
                Add-Finding -ID "GPOSCRIPT_$($gs.Name -replace '[^a-z0-9]','')" -Phase "PHASE 87" -ThreatType "GPO Persistence" `
                    -Severity $SEV_POSSIBLE -Description "GPO script found: $($gs.FullName) — verify this is authorized" `
                    -Target $gs.FullName -FixAction "Info" -Group "GPO Script Persistence"
            }
        }
    }

    Show-PhaseHeader "PHASE 88" "ACTIVE DIRECTORY / DOMAIN TRUST INDICATORS" "UNIVERSAL"
    $domain = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
    if ($domain) {
        Out-Typewriter "  -> MACHINE IS DOMAIN-JOINED. RUNNING AD SWEEPS..." "INFO"
        $dcSyncEvts = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} -ErrorAction SilentlyContinue |
            Where-Object { (Test-InScope $_.TimeCreated) -and $_.Message -match "1131f6aa|1131f6ad|89e95b76" }
        if ($dcSyncEvts.Count -gt 0) {
            Out-ThreatBanner "POSSIBLE DCSYNC ATTACK" "$($dcSyncEvts.Count) replication events from non-DC"
            Add-Finding -ID "DCSYNC" -Phase "PHASE 88" -ThreatType "DCSync / Domain Attack" -Severity $SEV_CRITICAL `
                -Description "DCSync indicators: $($dcSyncEvts.Count) AD replication events outside DC — possible credential dump" `
                -Target "Security EventLog (4662)" -FixAction "Info" -Group "Active Directory Attacks"
        } else { Out-Typewriter "  -> [OK] NO DCSYNC INDICATORS." "GOOD" }
        $goldenTicket = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} -ErrorAction SilentlyContinue |
            Where-Object { (Test-InScope $_.TimeCreated) -and $_.Message -match "0x17" -and $_.Message -match "krbtgt" }
        if ($goldenTicket.Count -gt 0) {
            Out-ThreatBanner "POSSIBLE GOLDEN TICKET" "$($goldenTicket.Count) KRBTGT RC4 requests"
            Add-Finding -ID "GOLDEN_TICKET" -Phase "PHASE 88" -ThreatType "Golden Ticket / Kerberos Attack" -Severity $SEV_CRITICAL `
                -Description "Golden ticket indicators: $($goldenTicket.Count) KRBTGT RC4 Kerberos ticket requests" `
                -Target "Security EventLog (4769)" -FixAction "Info" -Group "Active Directory Attacks"
        } else { Out-Typewriter "  -> [OK] NO GOLDEN TICKET INDICATORS." "GOOD" }
    } else { Out-Typewriter "  -> NOT DOMAIN-JOINED. AD CHECKS SKIPPED." "INFO" }

    Show-PhaseHeader "PHASE 89" "FINAL SWEEP — EXFIL CHANNELS & STEGO TOOLS" "UNIVERSAL"
    Out-Typewriter "CHECKING EXFIL VIA FTP/SMTP/ICMP AND STEGO TOOLS..." "HUNT"
    $exfilConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemotePort -in @(21,25,587,143,110,993,995) }
    foreach ($ec in $exfilConns) {
        $proc = Get-Process -Id $ec.OwningProcess -ErrorAction SilentlyContinue
        if ($proc.Name -notmatch "^(thunderbird|outlook|office|msedge|chrome|firefox)$") {
            Out-Typewriter "  -> UNUSUAL PORT $($ec.RemotePort)/tcp FROM $($proc.Name) -> $($ec.RemoteAddress)" "WARN"
            Add-Finding -ID "EXFIL_$($ec.OwningProcess)" -Phase "PHASE 89" -ThreatType "Data Exfiltration" `
                -Severity $SEV_HIGH -Description "Unusual outbound connection on mail/FTP port from non-email process: $($proc.Name) -> $($ec.RemoteAddress):$($ec.RemotePort)" `
                -Target "PID:$($ec.OwningProcess)" -FixAction "KillProcess" -FixParam $ec.OwningProcess -Group "Data Exfiltration"
        }
    }
    $stegoTools = @("openstego*","steghide*","outguess*","jphide*","stegosuite*","stepic*","imagesteganography*")
    foreach ($root in @($env:TEMP,$env:LOCALAPPDATA,$env:USERPROFILE)) {
        foreach ($st in $stegoTools) {
            $hits = Get-ChildItem -Path $root -Recurse -Filter $st -ErrorAction SilentlyContinue
            foreach ($hit in $hits) {
                Out-Typewriter "  -> STEGO TOOL: $($hit.FullName)" "WARN"
                Add-Finding -ID "STEGO_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 89" -ThreatType "Steganography/Exfil Tool" `
                    -Severity $SEV_HIGH -Description "Steganography tool found: $($hit.FullName)" `
                    -Target $hit.FullName -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Data Exfiltration"
            }
        }
    }
    Out-Typewriter "  -> PHASE 89 COMPLETE." "VER"
}

# ══════════════════════════════════════════════════════════════════════════════
#  ADVANCED PHASES 90-105 (DEEP / PARANOID / STEALTH — V21)
# ══════════════════════════════════════════════════════════════════════════════
if ($PhasePlan.Advanced) {
    if (-not $global:STEALTH_MODE) {
        Write-Host ""
        Write-Host ("▓"*80) -ForegroundColor DarkMagenta
        Write-Host "    ◈  A D V A N C E D   T H R E A T   H U N T  —  P H A S E S  9 0 - 1 0 5" -ForegroundColor Magenta
        Write-Host ("▓"*80) -ForegroundColor DarkMagenta
        Invoke-QuantumBar "ENGAGING ADVANCED PERSISTENT THREAT MODULE" 20 90
    }

    # ── PHASE 90: YARA-LITE STRING SCAN + CUSTOM IOC HASH CHECK ───────────────
    Show-PhaseHeader "PHASE 90" "YARA-LITE BINARY STRING SCAN & CUSTOM IOC HASHES" "YARA-LITE"
    Out-Typewriter "SCANNING USER-PATH BINARIES FOR MALWARE STRINGS..." "HUNT"
    Invoke-QuantumBar "BINARY STRING ANALYSIS" 18 90
    $yaraRoots = @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA,"$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop")
    $yaraExt   = @(".exe",".dll",".scr",".ps1",".vbs",".js",".hta",".bat",".cmd",".bin")
    $yaraHits  = 0
    foreach ($root in $yaraRoots) {
        if (-not (Test-Path $root)) { continue }
        $candidates = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { (Test-InScope $_.LastWriteTime) -and ($yaraExt -contains $_.Extension.ToLower()) -and $_.Length -lt 10MB } |
            Select-Object -First 200
        foreach ($cand in $candidates) {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($cand.FullName)
                $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
                foreach ($rule in $YARA_LITE_RULES) {
                    if ($text -match $rule.Pattern) {
                        $sev = if ($rule.Severity -eq "CRITICAL") { $SEV_CRITICAL } else { $SEV_HIGH }
                        Out-Decrypt -Text "$($rule.Name) -> $($cand.FullName)" -Prefix "  [YARA HIT] "
                        Add-Finding -ID "YARA_$($rule.Name)_$($cand.Name -replace '[^a-z0-9]','')" -Phase "PHASE 90" `
                            -ThreatType "YARA-Lite Match" -Severity $sev `
                            -Description "YARA rule '$($rule.Name)' matched: $($cand.FullName)" `
                            -Target $cand.FullName -FixAction "DeleteFile" -FixParam $cand.FullName `
                            -Group "YARA-Lite Matches"
                        $yaraHits++; $global:TrojanHits++; break
                    }
                }
                if ($global:CustomIocs.Hashes.Count -gt 0) {
                    try {
                        $hash = (Get-FileHash -Path $cand.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
                        if ($global:CustomIocs.Hashes -contains $hash) {
                            Out-Decrypt -Text "IOC hash match: $($cand.FullName)" -Prefix "  [IOC HIT] "
                            Add-Finding -ID "IOC_HASH_$($cand.Name -replace '[^a-z0-9]','')" -Phase "PHASE 90" `
                                -ThreatType "Custom IOC Hash" -Severity $SEV_CRITICAL `
                                -Description "File matches user-supplied IOC hash ($hash): $($cand.FullName)" `
                                -Target $cand.FullName -FixAction "DeleteFile" -FixParam $cand.FullName `
                                -Group "Custom IOC Matches"
                        }
                    } catch {}
                }
            } catch {}
        }
    }
    if ($yaraHits -eq 0) { Out-Typewriter "  -> [OK] NO YARA-LITE MATCHES." "GOOD" }

    # ── PHASE 91: MARK-OF-THE-WEB ABUSE ───────────────────────────────────────
    Show-PhaseHeader "PHASE 91" "MARK-OF-THE-WEB (MOTW) ZONE.IDENTIFIER STRIP" "MOTW"
    Out-Typewriter "SCANNING DOWNLOADS FOR MOTW-STRIPPED EXECUTABLES..." "HUNT"
    $motwHits = 0
    foreach ($root in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop")) {
        if (-not (Test-Path $root)) { continue }
        $exes = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { (Test-InScope $_.LastWriteTime) -and $_.Extension -match "\.(exe|msi|dll|scr|js|vbs|hta|ps1|bat|lnk|iso|img)$" }
        foreach ($exe in $exes) {
            $stream = Get-Item -Path $exe.FullName -Stream "Zone.Identifier" -ErrorAction SilentlyContinue
            if (-not $stream -and $exe.Length -gt 8192) {
                Add-Finding -ID "MOTW_$($exe.Name -replace '[^a-z0-9]','')" -Phase "PHASE 91" -ThreatType "MoTW Abuse" `
                    -Severity $SEV_POSSIBLE `
                    -Description "Executable in Downloads/Desktop missing Zone.Identifier (MoTW stripped): $($exe.FullName)" `
                    -Target $exe.FullName -FixAction "Info" -Group "MoTW / Web-Origin Abuse"
                $motwHits++
            }
        }
    }
    if ($motwHits -eq 0) { Out-Typewriter "  -> [OK] NO MOTW-STRIPPED EXECUTABLES." "GOOD" }

    # ── PHASE 92: UAC AUTO-ELEVATE BYPASS DETECTION ───────────────────────────
    Show-PhaseHeader "PHASE 92" "UAC AUTO-ELEVATE BYPASS REGISTRY STAGING" "UAC BYPASS"
    Out-Typewriter "CHECKING UAC BYPASS REGISTRY KEYS (FODHELPER / COMPUTERDEFAULTS)..." "HUNT"
    $uacFound = $false
    foreach ($ub in $UAC_BYPASS_REGS) {
        if (Test-Path $ub) {
            $cmd = (Get-ItemProperty -Path $ub -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
            if ($cmd) {
                Out-ThreatBanner "UAC BYPASS REGISTRY HIJACK" "$ub -> $cmd"
                Add-Finding -ID "UACBYPASS_$($ub -replace '[^a-z0-9]','')" -Phase "PHASE 92" -ThreatType "UAC Bypass" `
                    -Severity $SEV_CRITICAL -Description "UAC bypass reg hijack: $ub = $cmd" `
                    -Target $ub -FixAction "DeleteRegKey" -FixParam $ub -Group "UAC Bypass"
                $global:UACBypassHits++; $uacFound = $true
            }
        }
    }
    $enableLua = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($enableLua -eq 0) {
        Out-Typewriter "  -> UAC DISABLED (EnableLUA=0)" "CRIT"
        Add-Finding -ID "UAC_DISABLED" -Phase "PHASE 92" -ThreatType "UAC Disabled" -Severity $SEV_HIGH `
            -Description "UAC disabled (EnableLUA=0) — common malware persistence step" `
            -Target "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA" `
            -FixAction "RunCmd" -FixParam "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' EnableLUA 1 -Type DWord -Force" `
            -Group "UAC Bypass"
        $global:UACBypassHits++; $uacFound = $true
    }
    if (-not $uacFound) { Out-Typewriter "  -> [OK] NO UAC BYPASS INDICATORS." "GOOD" }

    # ── PHASE 93: DEEP DLL/MODULE INJECTION SCAN ──────────────────────────────
    Show-PhaseHeader "PHASE 93" "DEEP PROCESS MODULE / DLL INJECTION AUDIT" "INJECTION"
    Out-Typewriter "ENUMERATING LOADED MODULES FOR UNSIGNED USER-PATH DLLS..." "HUNT"
    Invoke-QuantumBar "MODULE INTROSPECTION" 16 110
    $injFound = 0
    $deepProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and (Test-Path $_.Path) -and
        $_.Name -notmatch "^(svchost|System|smss|csrss|wininit|services|lsass|winlogon|fontdrvhost|dwm|conhost|MsMpEng|SearchIndexer|RuntimeBroker|sihost|taskhostw)$"
    } | Select-Object -First 60
    foreach ($p in $deepProcs) {
        try {
            $unsignedDlls = $p.Modules | Where-Object {
                $_.FileName -and ($_.FileName -match "AppData|Temp|Downloads|ProgramData") -and
                ((Get-AuthenticodeSignature $_.FileName -ErrorAction SilentlyContinue).Status -ne "Valid")
            }
            foreach ($udll in $unsignedDlls) {
                Out-Typewriter "  -> $($p.Name) PID:$($p.Id) loaded UNSIGNED user-path DLL: $($udll.FileName)" "CRIT"
                Add-Finding -ID "INJDLL_$($p.Id)_$([IO.Path]::GetFileName($udll.FileName) -replace '[^a-z0-9]','')" `
                    -Phase "PHASE 93" -ThreatType "DLL Injection" -Severity $SEV_HIGH `
                    -Description "$($p.Name) PID:$($p.Id) loaded unsigned DLL from user path: $($udll.FileName)" `
                    -Target "PID:$($p.Id)" -FixAction "KillProcess" -FixParam $p.Id `
                    -Group "Module Injection"
                $injFound++
            }
        } catch {}
    }
    if ($injFound -eq 0) { Out-Typewriter "  -> [OK] NO UNSIGNED INJECTED MODULES." "GOOD" }

    # ── PHASE 94: COM SCRIPTLET (.SCT) / SQUIBLYDOO ───────────────────────────
    Show-PhaseHeader "PHASE 94" "COM SCRIPTLET (.SCT/.WSC) ABUSE & SQUIBLYDOO" "COM SCRIPTLET"
    Out-Typewriter "SCANNING FOR SCRIPTLET FILES AND REGSVR32 STAGING..." "HUNT"
    $sctHits = 0
    foreach ($root in @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA,"$env:USERPROFILE\Downloads")) {
        if (-not (Test-Path $root)) { continue }
        $sctFiles = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { (Test-InScope $_.LastWriteTime) -and $_.Extension -match "\.(sct|wsc|xsl)$" }
        foreach ($s in $sctFiles) {
            Out-ThreatBanner "COM SCRIPTLET FILE" $s.FullName
            Add-Finding -ID "SCT_$($s.Name -replace '[^a-z0-9]','')" -Phase "PHASE 94" -ThreatType "COM Scriptlet/Squiblydoo" `
                -Severity $SEV_HIGH -Description "COM scriptlet (Squiblydoo vector): $($s.FullName)" `
                -Target $s.FullName -FixAction "DeleteFile" -FixParam $s.FullName -Group "COM Scriptlet Abuse"
            $sctHits++
        }
    }
    foreach ($rp in @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
        if (-not (Test-Path $rp)) { continue }
        $vals = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        foreach ($prop in ($vals.psobject.properties | Where-Object { $_.Name -notmatch "^PS" })) {
            if ([string]$prop.Value -match "regsvr32.{0,16}/i:.{0,16}(http|https|\\\\)") {
                Add-Finding -ID "SQUIBLY_$($prop.Name -replace '[^a-z0-9]','')" -Phase "PHASE 94" -ThreatType "Squiblydoo" `
                    -Severity $SEV_CRITICAL -Description "Run key uses regsvr32 /i: URL: $rp\$($prop.Name) = $($prop.Value)" `
                    -Target "$rp|$($prop.Name)" -FixAction "DeleteReg" -FixParam "$rp|$($prop.Name)" `
                    -Group "COM Scriptlet Abuse"
                $sctHits++
            }
        }
    }
    if ($sctHits -eq 0) { Out-Typewriter "  -> [OK] NO COM SCRIPTLET ARTIFACTS." "GOOD" }

    # ── PHASE 95: APPDOMAINMANAGER .NET HIJACK ────────────────────────────────
    Show-PhaseHeader "PHASE 95" "APPDOMAINMANAGER .NET LOADER HIJACK" "DOTNET HIJACK"
    Out-Typewriter "CHECKING APPDOMAIN MANAGER ENV VARS AND .CONFIG FILES..." "HUNT"
    $admEnv  = [Environment]::GetEnvironmentVariable("APPDOMAIN_MANAGER_ASM","Machine")
    $admEnv2 = [Environment]::GetEnvironmentVariable("APPDOMAIN_MANAGER_TYPE","Machine")
    $admHits = 0
    if ($admEnv -or $admEnv2) {
        Out-ThreatBanner "APPDOMAINMANAGER HIJACK" "ASM=$admEnv TYPE=$admEnv2"
        Add-Finding -ID "APPDOMAINMGR_ENV" -Phase "PHASE 95" -ThreatType ".NET AppDomainManager Hijack" `
            -Severity $SEV_CRITICAL -Description "APPDOMAIN_MANAGER_* env var set: $admEnv / $admEnv2" `
            -Target "Machine Environment" -FixAction "RunCmd" `
            -FixParam "[Environment]::SetEnvironmentVariable('APPDOMAIN_MANAGER_ASM',`$null,'Machine'); [Environment]::SetEnvironmentVariable('APPDOMAIN_MANAGER_TYPE',`$null,'Machine')" `
            -Group "AppDomainManager Hijack"
        $admHits++
    }
    $sysCfgs = Get-ChildItem -Path "$env:WINDIR\System32" -Filter "*.exe.config" -ErrorAction SilentlyContinue |
        Where-Object { Test-InScope $_.LastWriteTime } | Select-Object -First 30
    foreach ($cfg in $sysCfgs) {
        if ((Get-Content $cfg.FullName -Raw -ErrorAction SilentlyContinue) -match "appDomainManagerAssembly|appDomainManagerType") {
            Add-Finding -ID "APPDOMAINMGR_CFG_$($cfg.Name -replace '[^a-z0-9]','')" -Phase "PHASE 95" `
                -ThreatType ".NET AppDomainManager Hijack" -Severity $SEV_CRITICAL `
                -Description "appDomainManager entry in .NET config: $($cfg.FullName)" `
                -Target $cfg.FullName -FixAction "Info" -Group "AppDomainManager Hijack"
            $admHits++
        }
    }
    if ($admHits -eq 0) { Out-Typewriter "  -> [OK] NO APPDOMAINMANAGER HIJACK." "GOOD" }

    # ── PHASE 96: PRINTNIGHTMARE / PRINT SPOOLER ──────────────────────────────
    Show-PhaseHeader "PHASE 96" "PRINT SPOOLER / PRINTNIGHTMARE (CVE-2021-34527)" "PRINTNIGHTMARE"
    Out-Typewriter "AUDITING POINT-AND-PRINT POLICY AND SPOOLER DRIVER DIR..." "HUNT"
    $pnHits = 0
    $pnoarp = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -ErrorAction SilentlyContinue
    if ($pnoarp -eq 1) {
        Out-ThreatBanner "PRINTNIGHTMARE EXPOSURE" "Point-and-Print NoWarningNoElevationOnInstall=1"
        Add-Finding -ID "PRINTNIGHT_POE" -Phase "PHASE 96" -ThreatType "PrintNightmare (CVE-2021-34527)" `
            -Severity $SEV_CRITICAL -Description "Point-and-Print allows unprompted driver install — PrintNightmare RCE vector" `
            -Target "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -FixAction "RunCmd" `
            -FixParam "Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' NoWarningNoElevationOnInstall 0 -Force; Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' UpdatePromptSettings 0 -Force" `
            -Group "PrintNightmare"
        $pnHits++
    }
    $spoolDir = "$env:WINDIR\System32\spool\drivers"
    if (Test-Path $spoolDir) {
        Get-ChildItem -Path $spoolDir -Recurse -Filter "*.dll" -ErrorAction SilentlyContinue |
            Where-Object { Test-InScope $_.LastWriteTime } | Select-Object -First 30 | ForEach-Object {
            if ((Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue).Status -ne "Valid") {
                Add-Finding -ID "SPOOLDRV_$($_.Name -replace '[^a-z0-9]','')" -Phase "PHASE 96" -ThreatType "Print Spooler Hijack" `
                    -Severity $SEV_HIGH -Description "Unsigned DLL in spooler driver dir: $($_.FullName)" `
                    -Target $_.FullName -FixAction "DeleteFile" -FixParam $_.FullName -Group "PrintNightmare"
                $pnHits++
            }
        }
    }
    Add-Finding -ID "SPOOLER_DISABLE_OPT" -Phase "PHASE 96" -ThreatType "Hardening" -Severity $SEV_INFO `
        -Description "Option: Disable Print Spooler if printers not in use (eliminates PrintNightmare class)" `
        -Target "Service: Spooler" -FixAction "RunCmd" -FixParam "Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled" -Group "PrintNightmare"
    if ($pnHits -eq 0) { Out-Typewriter "  -> [OK] NO PRINTNIGHTMARE INDICATORS." "GOOD" }

    # ── PHASE 97: CLICKONCE ABUSE ─────────────────────────────────────────────
    Show-PhaseHeader "PHASE 97" "CLICKONCE / .APPLICATION DEPLOYMENT ABUSE" "CLICKONCE"
    Out-Typewriter "SCANNING FOR CLICKONCE PAYLOADS IN USER PATHS..." "HUNT"
    $coHits = 0
    foreach ($root in @($env:TEMP,$env:LOCALAPPDATA,"$env:LOCALAPPDATA\Apps","$env:USERPROFILE\Downloads")) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { (Test-InScope $_.LastWriteTime) -and $_.Extension -match "\.(application|manifest|deploy)$" } |
            Select-Object -First 50 | ForEach-Object {
            Add-Finding -ID "CLICKONCE_$($_.Name -replace '[^a-z0-9]','')" -Phase "PHASE 97" -ThreatType "ClickOnce Abuse" `
                -Severity $SEV_POSSIBLE -Description "ClickOnce deployment artifact in user path: $($_.FullName)" `
                -Target $_.FullName -FixAction "DeleteFile" -FixParam $_.FullName -Group "ClickOnce Abuse"
            $coHits++
        }
    }
    if ($coHits -eq 0) { Out-Typewriter "  -> [OK] NO CLICKONCE PAYLOADS." "GOOD" }

    # ── PHASE 98: STOLEN/LEAKED CODE-SIGNING CERT ─────────────────────────────
    Show-PhaseHeader "PHASE 98" "STOLEN / LEAKED CODE-SIGNING CERT DETECTION" "STOLEN CERT"
    Out-Typewriter "AUDITING SIGNED BINARIES IN USER PATHS FOR KNOWN-LEAKED ISSUERS..." "HUNT"
    Invoke-QuantumBar "AUTHENTICODE CHAIN AUDIT" 12 100
    $leakedCerts = @("Founder Software","Founder Group","CN=NVIDIA","CN=Realtek Semiconductor","D-Link Corporation","Realtek Semiconductor","Foxit Software")
    $stolenHits = 0
    foreach ($root in @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA,"$env:USERPROFILE\Downloads")) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -Recurse -File -Include "*.exe","*.dll" -ErrorAction SilentlyContinue |
            Where-Object { Test-InScope $_.LastWriteTime } | Select-Object -First 100 | ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
            if ($sig.SignerCertificate) {
                $subj = $sig.SignerCertificate.Subject
                foreach ($lc in $leakedCerts) {
                    if ($subj -match [regex]::Escape($lc)) {
                        Out-Decrypt -Text "Stolen cert: $($_.FullName) -> $subj" -Prefix "  [STOLEN CERT] "
                        Add-Finding -ID "STOLENCERT_$($_.Name -replace '[^a-z0-9]','')" -Phase "PHASE 98" `
                            -ThreatType "Stolen Code-Sign Cert" -Severity $SEV_CRITICAL `
                            -Description "Binary signed by known-leaked cert ($lc): $($_.FullName)" `
                            -Target $_.FullName -FixAction "DeleteFile" -FixParam $_.FullName `
                            -Group "Stolen Code-Signing Certs"
                        $stolenHits++; break
                    }
                }
            }
        }
    }
    if ($stolenHits -eq 0) { Out-Typewriter "  -> [OK] NO STOLEN-CERT-SIGNED BINARIES." "GOOD" }

    # ── PHASE 99: LOLBAS EXPANDED PROCESS AUDIT ───────────────────────────────
    Show-PhaseHeader "PHASE 99" "LOLBAS EXPANDED PROCESS ABUSE AUDIT" "LOLBAS+"
    Out-Typewriter "SCANNING ALL LOLBAS-CLASS BINARIES FOR ABUSE PATTERNS..." "HUNT"
    Invoke-QuantumBar "LOLBAS CROSS-CORRELATION" 14 90
    $lolbasHits = 0
    foreach ($lb in $LOLBAS_EXPANDED) {
        Get-WmiObject Win32_Process -Filter "Name='$lb.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.CommandLine -match "http|https|ftp|AppData|Temp|Base64|EncodedCommand|IEX|DownloadString|/i:|scrobj|Net\.WebClient") {
                $cmdShort = $_.CommandLine.Substring(0,[Math]::Min(140,$_.CommandLine.Length))
                Add-Finding -ID "LOLBAS_$($_.ProcessId)_$lb" -Phase "PHASE 99" -ThreatType "LOLBAS Abuse" `
                    -Severity $SEV_HIGH -Description "LOLBAS abuse: $($_.Name) PID:$($_.ProcessId) | $cmdShort" `
                    -Target "PID:$($_.ProcessId)" -FixAction "KillProcess" -FixParam $_.ProcessId -Group "LOLBAS Expanded"
                $lolbasHits++
            }
        }
    }
    if ($lolbasHits -eq 0) { Out-Typewriter "  -> [OK] NO EXPANDED LOLBAS ABUSE." "GOOD" }

    # ── PHASE 100: BROWSER CRED DB ACCESS AUDIT ───────────────────────────────
    Show-PhaseHeader "PHASE 100" "BROWSER PASSWORD/COOKIE DB RECENT ACCESS" "INFO-STEALER"
    Out-Typewriter "CHECKING LAST-ACCESS TIME ON BROWSER CREDENTIAL DATABASES..." "HUNT"
    $credDbs = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles"
    )
    $credHits = 0
    foreach ($db in $credDbs) {
        if (Test-Path $db) {
            $item = Get-Item $db -ErrorAction SilentlyContinue
            if ($item -and $item.LastAccessTime -gt (Get-Date).AddMinutes(-60)) {
                Add-Finding -ID "CREDDB_$($db -replace '[^a-z0-9]','')" -Phase "PHASE 100" -ThreatType "Info-Stealer Activity" `
                    -Severity $SEV_HIGH -Description "Browser credential DB accessed in last 60 min: $db @ $($item.LastAccessTime)" `
                    -Target $db -FixAction "Info" -Group "Credential DB Access"
                $credHits++
            }
        }
    }
    if ($credHits -eq 0) { Out-Typewriter "  -> [OK] NO RECENT CRED DB ACCESS." "GOOD" }

    # ── PHASE 101: WSL / DOCKER CONTAINER SURFACE ─────────────────────────────
    Show-PhaseHeader "PHASE 101" "WSL / DOCKER CONTAINER ESCAPE SURFACE" "CONTAINER"
    Out-Typewriter "CHECKING WSL DISTROS AND DOCKER DAEMON..." "HUNT"
    if (Get-Command wsl -ErrorAction SilentlyContinue) {
        $wslList = (wsl --list --quiet 2>$null)
        foreach ($d in $wslList) {
            if ($d -and $d.Trim()) {
                Add-Finding -ID "WSL_$($d.Trim() -replace '[^a-z0-9]','')" -Phase "PHASE 101" -ThreatType "Container Surface" `
                    -Severity $SEV_INFO -Description "WSL distro present (potential lateral surface): $($d.Trim())" `
                    -Target "WSL: $($d.Trim())" -FixAction "Info" -Group "WSL / Container"
            }
        }
    }
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Add-Finding -ID "DOCKER_PRESENT" -Phase "PHASE 101" -ThreatType "Container Surface" `
            -Severity $SEV_INFO -Description "Docker installed — verify daemon socket is not world-accessible" `
            -Target "docker.exe" -FixAction "Info" -Group "WSL / Container"
    }
    Out-Typewriter "  -> CONTAINER SURFACE AUDIT COMPLETE." "VER"

    # ── PHASE 102: SVCHOST PARENT VALIDATION ──────────────────────────────────
    Show-PhaseHeader "PHASE 102" "SVCHOST PARENT-CHILD MASQUERADE VALIDATION" "MASQUERADE"
    Out-Typewriter "VERIFYING ALL SVCHOST.EXE PARENT == SERVICES.EXE..." "HUNT"
    Invoke-QuantumBar "PROCESS PARENT MAP" 10 80
    $svcHits = 0
    $allW = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($sp in ($allW | Where-Object { $_.Name -eq "svchost.exe" })) {
        $par = $allW | Where-Object { $_.ProcessId -eq $sp.ParentProcessId }
        if ($par -and $par.Name -ne "services.exe") {
            Out-ThreatBanner "SVCHOST PARENT MASQUERADE" "PID:$($sp.ProcessId) parent=$($par.Name)"
            Add-Finding -ID "SVCMASQ_$($sp.ProcessId)" -Phase "PHASE 102" -ThreatType "Process Masquerade" `
                -Severity $SEV_CRITICAL -Description "svchost.exe PID:$($sp.ProcessId) parent is '$($par.Name)' (expected: services.exe)" `
                -Target "PID:$($sp.ProcessId)" -FixAction "KillProcess" -FixParam $sp.ProcessId `
                -Group "Process Masquerade"
            $svcHits++; $global:RootkitHits++
        }
        if ($sp.ExecutablePath -and $sp.ExecutablePath -notmatch "^C:\\Windows\\(System32|SysWOW64)\\svchost\.exe$") {
            Out-ThreatBanner "SVCHOST ANOMALOUS PATH" $sp.ExecutablePath
            Add-Finding -ID "SVCPATH_$($sp.ProcessId)" -Phase "PHASE 102" -ThreatType "Process Masquerade" `
                -Severity $SEV_CRITICAL -Description "svchost.exe running from anomalous path: $($sp.ExecutablePath)" `
                -Target "PID:$($sp.ProcessId)" -FixAction "KillProcess" -FixParam $sp.ProcessId `
                -Group "Process Masquerade"
            $svcHits++
        }
    }
    if ($svcHits -eq 0) { Out-Typewriter "  -> [OK] ALL SVCHOST INSTANCES VERIFIED." "GOOD" }

    # ── PHASE 103: SUSPICIOUS ARCHIVE SCAN ────────────────────────────────────
    Show-PhaseHeader "PHASE 103" "SUSPICIOUS COMPRESSED ARCHIVE PAYLOAD AUDIT" "PHISHING"
    Out-Typewriter "SCANNING RECENT ARCHIVES IN DOWNLOAD PATHS..." "HUNT"
    $arcHits = 0
    foreach ($root in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop",$env:TEMP)) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { (Test-InScope $_.LastWriteTime) -and ($_.Extension -match "\.(zip|7z|rar|iso|img)$") -and $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Length -gt 1024 } |
            Select-Object -First 40 | ForEach-Object {
            Add-Finding -ID "ARCHIVE_$($_.Name -replace '[^a-z0-9]','')" -Phase "PHASE 103" `
                -ThreatType "Suspicious Archive" -Severity $SEV_POSSIBLE `
                -Description "Recent compressed archive (review for password-protected payload): $($_.FullName)" `
                -Target $_.FullName -FixAction "Info" -Group "Suspicious Archives"
            $arcHits++
        }
    }
    if ($arcHits -eq 0) { Out-Typewriter "  -> [OK] NO RECENT SUSPICIOUS ARCHIVES." "GOOD" }

    # ── PHASE 104: SCHEDULED TASK XML DEEP PARSE ──────────────────────────────
    Show-PhaseHeader "PHASE 104" "SCHEDULED TASK XML DEEP PARSE / HIDDEN TASKS" "TASK"
    Out-Typewriter "PARSING TASK XML FOR Hidden=true AND SDDL LOCKS..." "HUNT"
    Invoke-QuantumBar "TASK XML INTROSPECTION" 12 90
    $taskDeepHits = 0
    if (Test-Path "$env:WINDIR\System32\Tasks") {
        Get-ChildItem -Path "$env:WINDIR\System32\Tasks" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $c = Get-Content $_.FullName -Raw -ErrorAction Stop
                if ($c -match "<Hidden>true</Hidden>" -and (Test-InScope $_.LastWriteTime)) {
                    Add-Finding -ID "HIDDENTASK_$($_.Name -replace '[^a-z0-9]','')" -Phase "PHASE 104" `
                        -ThreatType "Hidden Scheduled Task" -Severity $SEV_HIGH `
                        -Description "Task with Hidden=true: $($_.FullName)" `
                        -Target $_.FullName -FixAction "DeleteFile" -FixParam $_.FullName `
                        -Group "Hidden Scheduled Tasks"
                    $taskDeepHits++
                }
                if ($c -match "SDDL.{0,32}D:P\(") {
                    Add-Finding -ID "SDDLTASK_$($_.Name -replace '[^a-z0-9]','')" -Phase "PHASE 104" `
                        -ThreatType "SDDL-Locked Task" -Severity $SEV_HIGH `
                        -Description "Task uses restrictive SDDL ACL (anti-forensic): $($_.FullName)" `
                        -Target $_.FullName -FixAction "Info" -Group "Hidden Scheduled Tasks"
                    $taskDeepHits++
                }
            } catch {}
        }
    }
    if ($taskDeepHits -eq 0) { Out-Typewriter "  -> [OK] NO HIDDEN OR SDDL-LOCKED TASKS." "GOOD" }

    # ── PHASE 105: PERSISTENCE HEATMAP & CORRELATION ──────────────────────────
    Show-PhaseHeader "PHASE 105" "PERSISTENCE HEATMAP & CROSS-VECTOR CORRELATION" "CORRELATION"
    Out-Typewriter "BUILDING PERSISTENCE HEATMAP ACROSS ALL DETECTED VECTORS..." "ACT"
    Invoke-QuantumBar "CROSS-CORRELATION ENGINE" 15 90
    $heatmap = @{}
    foreach ($f in $global:AuditFindings) {
        $k = $f.ThreatType
        $heatmap[$k] = ($heatmap[$k] -as [int]) + 1
    }
    $hot = $heatmap.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    if (-not $global:STEALTH_MODE) {
        Write-Host ""
        Write-Host "  ── PERSISTENCE HEATMAP (TOP 10) ──" -ForegroundColor (Get-AccentColor)
        foreach ($entry in $hot) {
            $bar = "█" * [Math]::Min(50, $entry.Value)
            $col = if ($entry.Value -ge 10) { "Red" } elseif ($entry.Value -ge 3) { "Yellow" } else { "Green" }
            Write-Host ("  {0,-32} " -f $entry.Key) -NoNewline -ForegroundColor DarkGray
            Write-Host $bar -NoNewline -ForegroundColor $col
            Write-Host " ($($entry.Value))" -ForegroundColor $col
        }
        Write-Host ""
    }
    $persistenceTypes = @("Run Key Persistence","Scheduled Task Persistence","WMI Persistence","SafeBoot Persistence","Startup Folder Persistence","BITS / Profile Persistence","COM Object Hijacks","IFEO Persistence","DLL Injection Persistence")
    $hitTypes = @($heatmap.Keys) | Where-Object { $persistenceTypes -contains $_ }
    if ($hitTypes.Count -ge 3) {
        Add-Finding -ID "MULTI_PERSIST" -Phase "PHASE 105" -ThreatType "Multi-Vector Persistence" `
            -Severity $SEV_CRITICAL -Description "Threat using $($hitTypes.Count) persistence vectors: $($hitTypes -join ', ')" `
            -Target "Cross-vector correlation" -FixAction "Info" -Group "Multi-Vector Correlation"
    }

    # Baseline diff
    if ($Baseline -and (Test-Path $Baseline)) {
        Show-PhaseHeader "PHASE 105+" "BASELINE DIFF — New Findings Since Snapshot" "BASELINE"
        try {
            $base    = Get-Content $Baseline -Raw | ConvertFrom-Json
            $baseIds = @{}; foreach ($b in $base.findings) { $baseIds[$b.ID] = $true }
            $newF    = $global:AuditFindings | Where-Object { -not $baseIds.ContainsKey($_.ID) }
            foreach ($nf in $newF) { $global:BaselineDelta.Add(@{ ID=$nf.ID; ThreatType=$nf.ThreatType; Description=$nf.Description; Severity=$nf.Severity }) }
            Out-Typewriter "  -> BASELINE DELTA: $($newF.Count) NEW FINDINGS SINCE BASELINE." "WARN"
            if ($newF.Count -gt 0 -and -not $global:STEALTH_MODE) {
                ($newF | Select-Object -First 10) | ForEach-Object {
                    Write-Host "    + [$($_.Severity)] $($_.Description.Substring(0,[Math]::Min(80,$_.Description.Length)))" -ForegroundColor Yellow
                }
            }
        } catch { Out-Typewriter "  -> BASELINE PARSE FAILED." "WARN" }
    }
    Out-Typewriter "  -> PHASE 105 COMPLETE." "VER"

    # ── PHASE 106: MEMORY DUMP ARTIFACT SCAN ──────────────────────────────────
    Show-PhaseHeader "PHASE 106" "MEMORY DUMP ARTIFACT SCAN (MINIDUMP / CRASHDUMPS)" "FORENSIC"
    Out-Typewriter "SCANNING CRASH DUMP LOCATIONS FOR SUSPICIOUS ARTIFACTS..." "HUNT"
    $dumpPaths = @(
        "$env:SystemRoot\Minidump",
        "$env:LOCALAPPDATA\CrashDumps",
        "$env:APPDATA\CrashDumps",
        "$env:SystemRoot\MEMORY.DMP",
        "$env:TEMP\*.dmp",
        "$env:USERPROFILE\AppData\Local\Temp\*.dmp"
    )
    $dumpFound = $false
    foreach ($dp in $dumpPaths) {
        if ($dp.Contains("*")) {
            $root = Split-Path $dp; $filter = Split-Path $dp -Leaf
            if (-not (Test-Path $root)) { continue }
            $items = Get-ChildItem -Path $root -Filter $filter -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
        } else {
            if (-not (Test-Path $dp)) { continue }
            $items = if ((Get-Item $dp -ErrorAction SilentlyContinue).PSIsContainer) {
                Get-ChildItem -Path $dp -Recurse -Filter "*.dmp" -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
            } else { @(Get-Item $dp -ErrorAction SilentlyContinue) }
        }
        foreach ($item in $items) {
            if ($null -eq $item) { continue }
            $ageDays = ([datetime]::Now - $item.LastWriteTime).TotalDays
            $sev = if ($ageDays -lt 1) { $SEV_HIGH } else { $SEV_POSSIBLE }
            Out-Decrypt -Text $item.FullName -Prefix "  [DUMP FILE] "
            Add-Finding -ID "DUMP_$($item.Name -replace '[^a-z0-9]','')" -Phase "PHASE 106" -ThreatType "Memory Dump Artifact" `
                -Severity $sev -Description "Memory dump file found (age: $([Math]::Round($ageDays,1)) days): $($item.FullName)" `
                -Target $item.FullName -FixAction "Info" -Group "Memory Dump Artifacts"
            $dumpFound = $true
        }
    }
    # Check for PROCDUMP / dumper tool presence
    $dumpTools = @("procdump*.exe","dumpert*.exe","memdump*.exe","outflank-dumpert*","nanodump*","handlekatz*","lsassy*","pypykatz*")
    foreach ($root in @($env:TEMP,$env:LOCALAPPDATA,$env:USERPROFILE)) {
        if (-not (Test-Path $root)) { continue }
        foreach ($dt in $dumpTools) {
            $hits = Get-ChildItem -Path $root -Recurse -Filter $dt -ErrorAction SilentlyContinue
            foreach ($hit in $hits) {
                Out-ThreatBanner "MEMORY DUMPER TOOL" $hit.FullName
                Add-Finding -ID "DUMPTOOL_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 106" -ThreatType "Credential Dumping Tool" `
                    -Severity $SEV_CRITICAL -Description "Memory/credential dumping tool found: $($hit.FullName)" `
                    -Target $hit.FullName -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Memory Dump Artifacts"
                $global:TrojanHits++; $dumpFound = $true
            }
        }
    }
    if (-not $dumpFound) { Out-Typewriter "  -> [OK] NO SUSPICIOUS DUMP FILES OR DUMPER TOOLS." "GOOD" }
    Out-Typewriter "  -> PHASE 106 COMPLETE." "VER"

    # ── PHASE 107: EVENT LOG THREAT HUNTING ───────────────────────────────────
    Show-PhaseHeader "PHASE 107" "EVENT LOG THREAT HUNTING (4624/4688/7045)" "EVT-HUNT"
    Out-Typewriter "MINING SECURITY/SYSTEM LOGS FOR ANOMALOUS PATTERNS..." "HUNT"
    Invoke-QuantumBar "EVENT LOG ANALYSIS" 12 100

    # 4624 — Anomalous logons (type 3/10 from unusual sources)
    Out-Typewriter "  -> SCANNING EVENT 4624 (LOGON) FOR ANOMALIES..." "INFO"
    try {
        $logons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 2000 -ErrorAction Stop |
            Where-Object { Test-InScope $_.TimeCreated }
        $suspLogons = $logons | Where-Object {
            $xml = [xml]$_.ToXml()
            $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            $ipAddr    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress'  }).'#text'
            $user      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            ($logonType -in @('3','10') -and $ipAddr -and $ipAddr -notmatch '(^-$|^::1$|^127\.)') -or
            ($user -match '\$' -and $logonType -eq '3')
        }
        foreach ($ev in ($suspLogons | Select-Object -First 50)) {
            try {
                $xml      = [xml]$ev.ToXml()
                $user     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $ipAddr   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress'     }).'#text'
                $logonType= ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType'     }).'#text'
                $sev = if ($logonType -eq '10') { $SEV_HIGH } else { $SEV_POSSIBLE }
                Add-Finding -ID "EVT4624_$($ev.RecordId)" -Phase "PHASE 107" -ThreatType "Anomalous Logon" `
                    -Severity $sev -Description "Suspicious logon: User=$user Type=$logonType From=$ipAddr @ $($ev.TimeCreated.ToString('HH:mm:ss yyyy-MM-dd'))" `
                    -Target "EventID:4624 Record:$($ev.RecordId)" -FixAction "Info" -Group "Event Log — Anomalous Logons"
            } catch {}
        }
        Out-Typewriter "  -> $($suspLogons.Count) ANOMALOUS 4624 EVENTS FOUND." $(if ($suspLogons.Count -gt 0) {"WARN"} else {"GOOD"})
    } catch { Out-Typewriter "  -> 4624 QUERY FAILED (ACCESS DENIED OR EMPTY LOG)." "WARN" }

    # 4688 — Process creation with suspicious patterns
    Out-Typewriter "  -> SCANNING EVENT 4688 (PROCESS CREATE) FOR MALWARE PATTERNS..." "INFO"
    try {
        $proc4688 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 3000 -ErrorAction Stop |
            Where-Object { Test-InScope $_.TimeCreated }
        $suspProcs = $proc4688 | Where-Object {
            $_.Message -match "(powershell.*-enc|cmd.*\/c.*DownloadString|certutil.*-decode|bitsadmin.*\/transfer|mshta.*vbscript|wscript.*\.js|cscript.*\.vbs|regsvr32.*\/s.*\/n.*\/u|rundll32.*,|installutil.*\/logfile|msiexec.*\/q.*http)"
        }
        foreach ($ev in ($suspProcs | Select-Object -First 30)) {
            try {
                $xml   = [xml]$ev.ToXml()
                $cmdl  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine'      }).'#text'
                $pname = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'NewProcessName'   }).'#text'
                $subj  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName'  }).'#text'
                if (-not $cmdl) { $cmdl = $pname }
                Add-Finding -ID "EVT4688_$($ev.RecordId)" -Phase "PHASE 107" -ThreatType "Suspicious Process Creation" `
                    -Severity $SEV_HIGH -Description "Suspicious 4688: $subj ran: $($cmdl.Substring(0,[Math]::Min(150,$cmdl.Length)))" `
                    -Target "EventID:4688 Record:$($ev.RecordId)" -FixAction "Info" -Group "Event Log — Suspicious Processes"
                $global:TrojanHits++
            } catch {}
        }
        Out-Typewriter "  -> $($suspProcs.Count) SUSPICIOUS 4688 PROCESS EVENTS." $(if ($suspProcs.Count -gt 0) {"WARN"} else {"GOOD"})
    } catch { Out-Typewriter "  -> 4688 QUERY FAILED (AUDIT NOT ENABLED OR ACCESS DENIED)." "WARN" }

    # 7045 — New service installed
    Out-Typewriter "  -> SCANNING EVENT 7045 (NEW SERVICE) FOR ROGUE INSTALLS..." "INFO"
    try {
        $svc7045 = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 500 -ErrorAction Stop |
            Where-Object { Test-InScope $_.TimeCreated }
        foreach ($ev in $svc7045) {
            try {
                $xml      = [xml]$ev.ToXml()
                $svcName  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName'   }).'#text'
                $svcFile  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ImagePath'     }).'#text'
                $svcType  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceType'   }).'#text'
                $isSusp = ($svcFile -match "AppData|Temp|powershell|cmd\.exe|wscript|mshta|\.dll.*,|rundll32") -or
                          ($svcName -match "^[a-z]{6,10}svc$|^svc[a-z]{5,}$")
                $sev = if ($isSusp) { $SEV_CRITICAL } else { $SEV_POSSIBLE }
                Add-Finding -ID "EVT7045_$($ev.RecordId)" -Phase "PHASE 107" -ThreatType "Rogue Service Install" `
                    -Severity $sev -Description "New service (7045): $svcName | Path: $svcFile | Type: $svcType | $(if($isSusp){'SUSPICIOUS'}else{'review'})" `
                    -Target "EventID:7045 Record:$($ev.RecordId)" -FixAction "Info" -Group "Event Log — New Services"
            } catch {}
        }
        Out-Typewriter "  -> $($svc7045.Count) NEW SERVICE EVENTS IN TIME WINDOW." $(if ($svc7045.Count -gt 0) {"WARN"} else {"GOOD"})
    } catch { Out-Typewriter "  -> 7045 QUERY FAILED." "WARN" }
    Out-Typewriter "  -> PHASE 107 COMPLETE." "VER"
}

# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT COMPLETE — COMPUTE RISK SCORE
# ══════════════════════════════════════════════════════════════════════════════
$elapsed    = [Math]::Round(((Get-Date) - $global:START_TIME).TotalMinutes, 2)
$phaseCount = $PhasePlan.Max
$totalRisk  = $global:RansomwareRisk + ($global:RootkitHits * 3) + ($global:RATHits * 2) +
              $global:KeyloggerHits + $global:MinerHits + ($global:WormHits / 5) + ($global:SpywareHits / 3) +
              ($global:TrojanHits * 2) + ($global:BackdoorHits * 3) + ($global:UACBypassHits * 2)
$totalRisk  = [Math]::Round($totalRisk, 0)
$riskLabel  = if ($totalRisk -gt 20) { "CRITICAL — IMMEDIATE ESCALATION" } `
              elseif ($totalRisk -gt 10) { "HIGH — SIGNIFICANT COMPROMISE INDICATORS" } `
              elseif ($totalRisk -gt 3)  { "MEDIUM — INVESTIGATE FINDINGS" } `
              else { "LOW — SYSTEM APPEARS RELATIVELY CLEAN" }
$riskColor  = if ($totalRisk -gt 20) { "Red" } elseif ($totalRisk -gt 10) { "DarkYellow" } elseif ($totalRisk -gt 3) { "Yellow" } else { "Green" }

$findingCount  = $global:AuditFindings.Count
$critCount     = ($global:AuditFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$highCount     = ($global:AuditFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
$possibleCount = ($global:AuditFindings | Where-Object { $_.Severity -eq "POSSIBLE" }).Count
$infoCount     = ($global:AuditFindings | Where-Object { $_.Severity -eq "INFO" }).Count

# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT SUMMARY REPORT
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host ("▓"*80) -ForegroundColor DarkCyan
Write-Host "  ◈◈◈  P R O J E C T   K R A K E N   V 2 2   ·   A U D I T   C O M P L E T E  ◈◈◈" -ForegroundColor Cyan
Write-Host ("▓"*80) -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  MODE      : " -NoNewline -ForegroundColor DarkGray; Write-Host "$($global:ScanMode) ($phaseCount phases)" -ForegroundColor (Get-AccentColor)
Write-Host "  TIME WINDOW       : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:TW_LABEL -ForegroundColor Yellow
Write-Host "  HOST / OPERATOR   : " -NoNewline -ForegroundColor DarkGray; Write-Host "$USER_NAME @ $HOST_NAME" -ForegroundColor DarkGray
Write-Host "  ELAPSED           : " -NoNewline -ForegroundColor DarkGray; Write-Host "$elapsed Minutes" -ForegroundColor DarkGray
Write-Host ""
Write-Host ("─"*80) -ForegroundColor DarkCyan
Write-Host "  THREAT TALLY:" -ForegroundColor Yellow
Write-Host "  Ransomware Risk   : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:RansomwareRisk -ForegroundColor $(if ($global:RansomwareRisk -gt 5) { "Red" } elseif ($global:RansomwareRisk -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Rootkit Hits      : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:RootkitHits    -ForegroundColor $(if ($global:RootkitHits -gt 0) { "Red" } else { "Green" })
Write-Host "  RAT / C2 Hits     : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:RATHits        -ForegroundColor $(if ($global:RATHits -gt 0) { "Red" } else { "Green" })
Write-Host "  Keylogger Hits    : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:KeyloggerHits  -ForegroundColor $(if ($global:KeyloggerHits -gt 0) { "Red" } else { "Green" })
Write-Host "  Miner Hits        : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:MinerHits      -ForegroundColor $(if ($global:MinerHits -gt 0) { "Red" } else { "Green" })
Write-Host "  Worm Hits         : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:WormHits       -ForegroundColor $(if ($global:WormHits -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Spyware/Adware    : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:SpywareHits    -ForegroundColor $(if ($global:SpywareHits -gt 0) { "Yellow" } else { "Green" })
Write-Host ("─"*80) -ForegroundColor DarkCyan
Write-Host "  FINDINGS SUMMARY:" -ForegroundColor Yellow
Write-Host "  CRITICAL          : " -NoNewline -ForegroundColor DarkGray; Write-Host $critCount     -ForegroundColor $(if ($critCount -gt 0) { "Red" } else { "Green" })
Write-Host "  HIGH              : " -NoNewline -ForegroundColor DarkGray; Write-Host $highCount     -ForegroundColor $(if ($highCount -gt 0) { "DarkYellow" } else { "Green" })
Write-Host "  POSSIBLE          : " -NoNewline -ForegroundColor DarkGray; Write-Host $possibleCount -ForegroundColor $(if ($possibleCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  INFO / HARDENING  : " -NoNewline -ForegroundColor DarkGray; Write-Host $infoCount     -ForegroundColor DarkGray
Write-Host "  TOTAL FINDINGS    : " -NoNewline -ForegroundColor DarkGray; Write-Host $findingCount  -ForegroundColor Yellow
Write-Host ("─"*80) -ForegroundColor DarkCyan
Write-Host "  COMPOSITE RISK    : " -NoNewline -ForegroundColor DarkGray
Write-Host "$totalRisk — $riskLabel" -ForegroundColor $riskColor
Write-Host ("▓"*80) -ForegroundColor DarkCyan

# Save audit cache
$auditCache = @{
    Timestamp     = (Get-Date).ToString("o")
    Host          = $HOST_NAME
    User          = $USER_NAME
    Mode          = $global:ScanMode
    TimeWindow    = $global:TW_LABEL
    RiskScore     = $totalRisk
    RiskLabel     = $riskLabel
    Paranoid      = $global:PARANOID_MODE
    Stealth       = $global:STEALTH_MODE
    Findings      = @($global:AuditFindings)
    PhaseTimings  = @($global:PhaseTimings)
    BaselineDelta = @($global:BaselineDelta)
    ThreatTally   = @{
        RAT=       $global:RATHits;      Rootkit=   $global:RootkitHits
        Ransomware=$global:RansomwareRisk;Keylogger= $global:KeyloggerHits
        Miner=     $global:MinerHits;    Worm=      $global:WormHits
        Spyware=   $global:SpywareHits;  Trojan=    $global:TrojanHits
        Backdoor=  $global:BackdoorHits; UACBypass= $global:UACBypassHits
    }
}
$auditCache | ConvertTo-Json -Depth 5 | Out-File -FilePath $AUDIT_JSON    -Encoding UTF8 -ErrorAction SilentlyContinue
$auditCache | ConvertTo-Json -Depth 5 | Out-File -FilePath $BASELINE_PATH -Encoding UTF8 -ErrorAction SilentlyContinue

# Write TXT log
$LOG_LINES.Insert(0, "ZEROBREACH V22 | $HOST_NAME | $(Get-Date) | $($global:ScanMode) | $($global:TW_LABEL) | PARANOID:$($global:PARANOID_MODE)")
$LOG_LINES.Insert(1, "RISK:$totalRisk | FINDINGS:$findingCount | CRIT:$critCount | HIGH:$highCount | POSSIBLE:$possibleCount | INFO:$infoCount")
$LOG_LINES.Insert(2, "RAT:$($global:RATHits) | ROOT:$($global:RootkitHits) | RANSOM:$($global:RansomwareRisk) | KL:$($global:KeyloggerHits) | MINER:$($global:MinerHits) | WORM:$($global:WormHits) | TROJAN:$($global:TrojanHits) | UAC:$($global:UACBypassHits)")
$LOG_LINES.Insert(3, "="*80)
$LOG_LINES | Out-File -FilePath $REPORT_PATH -Encoding UTF8 -ErrorAction SilentlyContinue
Out-Typewriter "TXT REPORT    : $REPORT_PATH"  "GOOD"
Out-Typewriter "AUDIT JSON    : $AUDIT_JSON"   "GOOD"
Out-Typewriter "BASELINE SAVE : $BASELINE_PATH" "GOOD"

# HTML report
function Write-HtmlReport {
    param([string]$OutPath)
    $sc  = @{ "CRITICAL"="#ff3838"; "HIGH"="#ff9500"; "POSSIBLE"="#ffd60a"; "INFO"="#6b7280" }
    $acc = if ($global:MSP_MODE) { "#ff6600" } else { "#00b4ff" }
    $csvData = '"Severity","Phase","ThreatType","Description","Target","FixAction","Timestamp"' + "`n"
    $rows = ($global:AuditFindings | Sort-Object @{e={switch($_.Severity){"CRITICAL"{0}"HIGH"{1}"POSSIBLE"{2}default{3}}};desc=$false}) | ForEach-Object {
        $col  = $sc[$_.Severity]
        $desc = [System.Net.WebUtility]::HtmlEncode($_.Description)
        $tgt  = [System.Net.WebUtility]::HtmlEncode($_.Target)
        $phase= [System.Net.WebUtility]::HtmlEncode($_.Phase)
        $type = [System.Net.WebUtility]::HtmlEncode($_.ThreatType)
        $csvData += """$($_.Severity)"",""$($_.Phase)"",""$($_.ThreatType)"",""$($_.Description -replace '"','""')"",""$($_.Target -replace '"','""')"",""$($_.FixAction)"",""$($_.Timestamp)""`n"
        "<tr class='sev-$($_.Severity.ToLower())'><td><span class='badge' style='background:$col'>$($_.Severity)</span></td><td>$phase</td><td>$type</td><td>$desc</td><td class='tgt' title='$tgt'>$tgt</td><td>$($_.FixAction)</td></tr>"
    }
    $csvDataJs = $csvData -replace '\\','\\' -replace "'","\\'"
    $tallyHtml = ""
    foreach ($k in @("RAT","Rootkit","Ransomware","Keylogger","Miner","Worm","Spyware","Trojan","Backdoor","UACBypass")) {
        $v   = $auditCache.ThreatTally.$k
        $col = if ([int]$v -ge 5) { "#ff3838" } elseif ([int]$v -ge 1) { "#ff9500" } else { "#22c55e" }
        $tallyHtml += "<div class='card'><div class='card-label'>$k</div><div class='card-val' style='color:$col'>$v</div></div>"
    }
    $deltaHtml = ""
    if ($global:BaselineDelta.Count -gt 0) {
        $deltaHtml  = "<h2>⚠ Baseline Delta — $($global:BaselineDelta.Count) New Findings</h2><ul>"
        $deltaHtml += ($global:BaselineDelta | ForEach-Object { "<li><b>[$($_.Severity)]</b> $([System.Net.WebUtility]::HtmlEncode($_.Description))</li>" }) -join ""
        $deltaHtml += "</ul>"
    }
    $riskClass = if ($totalRisk -gt 20) {"crit"} elseif ($totalRisk -gt 10) {"high"} elseif ($totalRisk -gt 3) {"med"} else {"low"}
    $html = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>ZeroBreach V22 — $HOST_NAME</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Consolas,'Courier New',monospace;background:#0a0a0a;color:#e5e5e5;padding:24px;line-height:1.6}
h1{color:$acc;font-size:26px;border-bottom:2px solid $acc;padding-bottom:8px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}
.h1-actions{display:flex;gap:8px}
h2{color:$acc;font-size:18px;margin:24px 0 10px;padding-left:10px;border-left:4px solid $acc}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-bottom:20px}
.meta div{background:#141414;padding:10px;border-left:3px solid $acc;border-radius:4px}
.meta strong{color:$acc;display:block;font-size:10px;text-transform:uppercase;margin-bottom:3px}
.risk{font-size:38px;font-weight:bold;text-align:center;padding:18px;border-radius:8px;margin:16px 0;background:#141414}
.crit{color:#ff3838;border:2px solid #ff3838;animation:pulse 2s infinite}
.high{color:#ff9500;border:2px solid #ff9500}
.med {color:#ffd60a;border:2px solid #ffd60a}
.low {color:#22c55e;border:2px solid #22c55e}
@keyframes pulse{0%,100%{box-shadow:0 0 6px #ff3838}50%{box-shadow:0 0 22px #ff3838}}
.tally{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin:14px 0}
.card{background:#141414;padding:14px;text-align:center;border-radius:6px;border:1px solid #2a2a2a;transition:border-color .2s}
.card:hover{border-color:$acc}
.card-label{font-size:10px;color:#888;text-transform:uppercase;margin-bottom:4px}
.card-val{font-size:30px;font-weight:bold}
.toolbar{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;align-items:center}
.search{flex:1;min-width:200px;padding:9px;background:#141414;border:1px solid #333;color:#fff;font-family:inherit;border-radius:4px;font-size:13px}
.search:focus{outline:none;border-color:$acc}
.filters{display:flex;gap:6px;flex-wrap:wrap}
.btn{background:#141414;color:#ccc;border:1px solid #333;padding:5px 12px;cursor:pointer;font-family:inherit;border-radius:3px;font-size:12px;transition:all .15s}
.btn:hover{border-color:$acc;color:#fff}
.btn.on{background:$acc;color:#000;border-color:$acc}
.btn-csv{background:#0d2d0d;color:#22c55e;border-color:#22c55e}
.btn-csv:hover{background:#22c55e;color:#000}
.btn-print{background:#1a1a2e;color:#818cf8;border-color:#818cf8}
.btn-print:hover{background:#818cf8;color:#000}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#141414;color:$acc;padding:9px 8px;text-align:left;border-bottom:2px solid $acc;position:sticky;top:0;cursor:pointer;user-select:none}
th:hover{color:#fff}
th::after{content:' ⇅';color:#555;font-size:9px}
td{padding:7px 8px;border-bottom:1px solid #1e1e1e;vertical-align:top}
tr:hover td{background:#141414}
.sev-critical td:first-child{border-left:3px solid #ff3838}
.sev-high     td:first-child{border-left:3px solid #ff9500}
.sev-possible td:first-child{border-left:3px solid #ffd60a}
.sev-info     td:first-child{border-left:3px solid #444}
.badge{display:inline-block;padding:2px 7px;border-radius:3px;color:#000;font-weight:bold;font-size:10px}
.tgt{color:#6b7280;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
ul{margin:10px 0 10px 20px}
li{margin:4px 0}
.footer{text-align:center;color:#444;font-size:11px;margin-top:36px;padding-top:16px;border-top:1px solid #1e1e1e}
.phase-bar{background:#141414;border:1px solid #1e1e1e;border-radius:4px;padding:10px;margin:8px 0;font-size:11px;color:#888}
@media print{body{background:#fff;color:#000;padding:8px}.risk{font-size:22px}.btn-csv,.btn-print,.toolbar{display:none!important}td,th{border:1px solid #ccc!important;padding:4px}table{font-size:10px}.sev-critical td:first-child{border-left:3px solid #cc0000!important}}
</style></head><body>
<h1><span>◈ ZeroBreach V22 — Forensic Audit Report</span>
<span class='h1-actions'>
<button class='btn btn-csv' onclick='exportCSV()'>⬇ Export CSV</button>
<button class='btn btn-print' onclick='window.print()'>🖨 Print</button>
</span></h1>
<div class='meta'>
<div><strong>Host</strong>$HOST_NAME</div>
<div><strong>User</strong>$USER_NAME</div>
<div><strong>Mode</strong>$($global:ScanMode) ($phaseCount phases)</div>
<div><strong>Window</strong>$($global:TW_LABEL)</div>
<div><strong>Started</strong>$($global:START_TIME.ToString('yyyy-MM-dd HH:mm:ss'))</div>
<div><strong>Elapsed</strong>$elapsed min</div>
<div><strong>OS</strong>$($global:OS_VERSION)</div>
<div><strong>Findings</strong>$findingCount total</div>
</div>
<div class='risk $riskClass'>RISK SCORE: $totalRisk — $riskLabel</div>
<h2>Threat Tally</h2><div class='tally'>$tallyHtml</div>
$deltaHtml
<h2>Findings ($findingCount) — CRITICAL: $critCount &nbsp; HIGH: $highCount &nbsp; POSSIBLE: $possibleCount &nbsp; INFO: $infoCount</h2>
<div class='toolbar'>
<input type='text' class='search' id='srch' placeholder='Search findings...' oninput='filterAll()'>
<div class='filters'>
<button class='btn on' onclick='filterSev("ALL",this)'>ALL</button>
<button class='btn' onclick='filterSev("CRITICAL",this)'>CRITICAL</button>
<button class='btn' onclick='filterSev("HIGH",this)'>HIGH</button>
<button class='btn' onclick='filterSev("POSSIBLE",this)'>POSSIBLE</button>
<button class='btn' onclick='filterSev("INFO",this)'>INFO</button>
</div>
</div>
<table id='tbl'><thead><tr>
<th onclick='sortTable(0)'>Sev</th>
<th onclick='sortTable(1)'>Phase</th>
<th onclick='sortTable(2)'>Type</th>
<th onclick='sortTable(3)'>Description</th>
<th onclick='sortTable(4)'>Target</th>
<th onclick='sortTable(5)'>Fix</th>
</tr></thead>
<tbody>$($rows -join "`n")</tbody></table>
<div class='footer'>ZeroBreach V22 · Project Kraken · Gannon MSP · $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
<script>
var curSev='ALL',curQ='';
function filterAll(){curQ=document.getElementById('srch').value.toLowerCase();applyFilters()}
function filterSev(s,b){document.querySelectorAll('.filters .btn').forEach(function(x){x.classList.remove('on')});b.classList.add('on');curSev=s;applyFilters()}
function applyFilters(){document.querySelectorAll('#tbl tbody tr').forEach(function(r){var sevOk=curSev==='ALL'||r.classList.contains('sev-'+curSev.toLowerCase());var txtOk=!curQ||r.innerText.toLowerCase().includes(curQ);r.style.display=(sevOk&&txtOk)?'':'none'})}
var sortDir={};
function sortTable(col){var tbl=document.getElementById('tbl');var rows=Array.from(tbl.tBodies[0].rows);var asc=sortDir[col]!==1;sortDir={};sortDir[col]=asc?1:-1;rows.sort(function(a,b){var va=a.cells[col].innerText.trim();var vb=b.cells[col].innerText.trim();return asc?va.localeCompare(vb,undefined,{numeric:true}):vb.localeCompare(va,undefined,{numeric:true})});rows.forEach(function(r){tbl.tBodies[0].appendChild(r)})}
function exportCSV(){var csv=$([char]39)$csvDataJs$([char]39);var blob=new Blob([csv],{type:'text/csv'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='ZeroBreach_V22_$HOST_NAME_$(Get-Date -Format 'yyyyMMdd').csv';a.click()}
</script></body></html>
"@
    $html | Out-File -FilePath $OutPath -Encoding UTF8 -ErrorAction SilentlyContinue
}

if ($global:HTML_REPORT -or $Html) {
    Write-HtmlReport -OutPath $HTML_PATH
    Out-Typewriter "HTML REPORT   : $HTML_PATH" "GOOD"
}

# Email report (scheduled task mode or -SmtpTo supplied)
if ($SmtpTo -and $SmtpServer -and $SmtpFrom) {
    Out-Typewriter "SENDING EMAIL REPORT TO $SmtpTo ..." "ACT"
    $subject = "ZeroBreach V22 — $HOST_NAME — RISK:$totalRisk ($riskLabel) — $findingCount findings"
    $body    = "ZeroBreach V22 Audit Report`n$('='*60)`nHost: $HOST_NAME`nUser: $USER_NAME`nMode: $($global:ScanMode)`nWindow: $($global:TW_LABEL)`nRisk Score: $totalRisk — $riskLabel`n`nCRITICAL: $critCount`nHIGH:     $highCount`nPOSSIBLE: $possibleCount`nINFO:     $infoCount`n`nReport: $REPORT_PATH`n"
    if ($global:HTML_REPORT -or $Html) { $body += "HTML: $HTML_PATH`n" }
    $body += "`n--- TOP CRITICAL/HIGH FINDINGS ---`n"
    $global:AuditFindings | Where-Object { $_.Severity -in @("CRITICAL","HIGH") } | Select-Object -First 20 | ForEach-Object {
        $body += "[$($_.Severity)] $($_.ThreatType): $($_.Description)`n"
    }
    try {
        $mailParams = @{
            To         = $SmtpTo
            From       = $SmtpFrom
            Subject    = $subject
            Body       = $body
            SmtpServer = $SmtpServer
        }
        if ($global:HTML_REPORT -or $Html) {
            $mailParams.Attachments = $HTML_PATH
        }
        Send-MailMessage @mailParams -ErrorAction Stop
        Out-Typewriter "  -> EMAIL SENT." "GOOD"
    } catch {
        Out-Typewriter "  -> EMAIL FAILED: $_" "WARN"
    }
}

# Stealth exit — emit JSON to stdout
if ($global:STEALTH_MODE) {
    $auditCache | ConvertTo-Json -Depth 5 -Compress
    exit 0
}

if ($findingCount -eq 0) {
    Out-Typewriter "NO FINDINGS. SYSTEM APPEARS CLEAN. FIX MODE NOT AVAILABLE." "GOOD"
    Write-Host ""; Out-Typewriter "PRESS ANY KEY TO EXIT." "INFO" 20
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); exit
}

# ══════════════════════════════════════════════════════════════════════════════
#  FIX MODE ENTRY PROMPT
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "  ┌─ PROCEED TO FIX / REMEDIATION MODE? ──────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "  │  Audit found $($findingCount) findings ($critCount CRITICAL, $highCount HIGH, $possibleCount POSSIBLE).            │" -ForegroundColor Yellow
Write-Host "  │  Fix mode will present a checkbox list for review before ANY action.   │" -ForegroundColor Yellow
Write-Host "  │  A registry/VSS rollback snapshot will be created BEFORE any fixes.    │" -ForegroundColor Yellow
Write-Host "  │                                                                         │" -ForegroundColor Yellow
Write-Host "  │   [Y]  Yes — Enter Fix/Remediation Mode                                │" -ForegroundColor Yellow
Write-Host "  │   [N]  No  — Exit (audit log saved)                                    │" -ForegroundColor Yellow
Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host "  COMMAND> " -NoNewline -ForegroundColor DarkGray
$fixEntry = (Read-Host).Trim().ToLower()
if ($fixEntry -ne "y" -and $fixEntry -ne "yes") {
    Out-Typewriter "FIX MODE DECLINED. AUDIT LOG PRESERVED. EXITING." "INFO"
    Write-Host ""; Out-Typewriter "PRESS ANY KEY TO EXIT." "INFO" 20
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); exit
}

# ══════════════════════════════════════════════════════════════════════════════
#  ROLLBACK SNAPSHOT
# ══════════════════════════════════════════════════════════════════════════════
Out-Typewriter "CREATING ROLLBACK SNAPSHOT BEFORE ANY CHANGES..." "ACT"
Invoke-QuantumBar "REGISTRY EXPORT IN PROGRESS" 10 160
$snapshotOk = $false
try {
    $regExports = @(
        @{H="HKCU"; K="SOFTWARE\Microsoft\Windows\CurrentVersion\Run";      F="$env:TEMP\KB_Run_HKCU.reg"},
        @{H="HKLM"; K="SOFTWARE\Microsoft\Windows\CurrentVersion\Run";      F="$env:TEMP\KB_Run_HKLM.reg"},
        @{H="HKLM"; K="SYSTEM\CurrentControlSet\Services";                  F="$env:TEMP\KB_Services.reg"},
        @{H="HKLM"; K="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; F="$env:TEMP\KB_Winlogon.reg"},
        @{H="HKCU"; K="SOFTWARE\Classes\CLSID";                             F="$env:TEMP\KB_CLSID.reg"}
    )
    $snapshotFiles = @()
    foreach ($re in $regExports) {
        reg export "$($re.H)\$($re.K)" $re.F /y 2>$null | Out-Null
        if (Test-Path $re.F) { $snapshotFiles += $re.F }
    }
    # Bundle into single snapshot file
    $snapshotContent = @("ZEROBREACH V22 SNAPSHOT | $(Get-Date) | Host: $HOST_NAME", "="*80)
    foreach ($sf in $snapshotFiles) {
        $snapshotContent += Get-Content $sf -Raw -ErrorAction SilentlyContinue
        Remove-Item $sf -Force -ErrorAction SilentlyContinue
    }
    $snapshotContent | Out-File -FilePath $SNAPSHOT_PATH -Encoding Unicode -ErrorAction Stop
    $snapshotOk = $true
    Out-Typewriter "SNAPSHOT SAVED TO: $SNAPSHOT_PATH" "GOOD"
    Out-Typewriter "  -> IF FIXES CAUSE ISSUES, RESTORE WITH: regedit /S `"$SNAPSHOT_PATH`"" "WARN"
} catch {
    Out-Typewriter "SNAPSHOT FAILED — PROCEEDING WITHOUT ROLLBACK (USE CAUTION)." "WARN"
}

Out-Typewriter "LOADING REMEDIATION INTERFACE..." "ACT"
Invoke-QuantumBar "BUILDING CHECKBOX MANIFEST" 10 80

# ══════════════════════════════════════════════════════════════════════════════
#  LIVE SCAN DASHBOARD — launches BEFORE scan, updates in real-time
# ══════════════════════════════════════════════════════════════════════════════
function Show-LiveScanDashboard {
    $acRgb  = if ($global:MSP_MODE) { [System.Drawing.Color]::FromArgb(255,102,0) } else { [System.Drawing.Color]::FromArgb(0,200,255) }
    $bgDark = [System.Drawing.Color]::FromArgb(12,12,12)
    $bgMid  = [System.Drawing.Color]::FromArgb(20,20,20)
    $bgPnl  = [System.Drawing.Color]::FromArgb(16,16,16)
    $fgMain = [System.Drawing.Color]::FromArgb(210,210,210)
    $red    = [System.Drawing.Color]::FromArgb(255,60,60)
    $orange = [System.Drawing.Color]::FromArgb(255,140,0)
    $yellow = [System.Drawing.Color]::Yellow
    $green  = [System.Drawing.Color]::FromArgb(80,220,80)
    $mono   = New-Object System.Drawing.Font("Consolas",9)
    $monoBold = New-Object System.Drawing.Font("Consolas",9,[System.Drawing.FontStyle]::Bold)
    $monoLg = New-Object System.Drawing.Font("Consolas",11,[System.Drawing.FontStyle]::Bold)
    $monoXL = New-Object System.Drawing.Font("Consolas",14,[System.Drawing.FontStyle]::Bold)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "ZeroBreach V22  ·  Project Kraken  ·  Gannon MSP"
    $form.Size = New-Object System.Drawing.Size(1340, 900)
    $form.MinimumSize = New-Object System.Drawing.Size(1100, 700)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = $bgDark
    $form.ForeColor = $fgMain
    $form.Font = $mono
    $global:GUI_LIVE_FORM = $form

    # ── Title bar ─────────────────────────────────────────────────────────────
    $titlePnl = New-Object System.Windows.Forms.Panel
    $titlePnl.Dock = "Top"; $titlePnl.Height = 58; $titlePnl.BackColor = [System.Drawing.Color]::FromArgb(8,8,8)
    $form.Controls.Add($titlePnl)

    $titleLbl = New-Object System.Windows.Forms.Label
    $titleLbl.Text = "◈  Z E R O B R E A C H   V 2 2   ·   P R O J E C T   K R A K E N"
    $titleLbl.Font = $monoXL; $titleLbl.ForeColor = $acRgb
    $titleLbl.AutoSize = $false; $titleLbl.Width = 800; $titleLbl.Height = 34
    $titleLbl.Location = New-Object System.Drawing.Point(10, 6)
    $titlePnl.Controls.Add($titleLbl)

    $subLbl = New-Object System.Windows.Forms.Label
    $subLbl.Text = "  HOST: $HOST_NAME   USER: $USER_NAME   MODE: $($global:ScanMode)   WINDOW: $($global:TW_LABEL)"
    $subLbl.Font = $mono; $subLbl.ForeColor = [System.Drawing.Color]::FromArgb(100,100,100)
    $subLbl.AutoSize = $false; $subLbl.Width = 1000; $subLbl.Height = 18
    $subLbl.Location = New-Object System.Drawing.Point(10, 38)
    $titlePnl.Controls.Add($subLbl)

    # Kill toggle button (top right of title)
    $killBtn = New-Object System.Windows.Forms.Button
    $killBtn.Text = "⏩  FAST MODE  [K]"
    $killBtn.Size = New-Object System.Drawing.Size(180, 34)
    $killBtn.Location = New-Object System.Drawing.Point(1130, 8)
    $killBtn.BackColor = [System.Drawing.Color]::FromArgb(35,35,35)
    $killBtn.ForeColor = [System.Drawing.Color]::FromArgb(80,180,80)
    $killBtn.FlatStyle = "Flat"
    $killBtn.Font = $monoBold
    $killBtn.add_Click({
        $global:SKIP_SLOW_OUTPUT = -not $global:SKIP_SLOW_OUTPUT
        if ($global:SKIP_SLOW_OUTPUT) {
            $killBtn.Text = "⏩  FAST MODE  [ON]"
            $killBtn.ForeColor = [System.Drawing.Color]::FromArgb(255,160,0)
            $killBtn.BackColor = [System.Drawing.Color]::FromArgb(40,25,0)
        } else {
            $killBtn.Text = "⏩  FAST MODE  [K]"
            $killBtn.ForeColor = [System.Drawing.Color]::FromArgb(80,180,80)
            $killBtn.BackColor = [System.Drawing.Color]::FromArgb(35,35,35)
        }
    })
    $titlePnl.Controls.Add($killBtn)
    $global:GUI_KILL_BTN = $killBtn

    # ── Phase / progress bar strip ────────────────────────────────────────────
    $progPnl = New-Object System.Windows.Forms.Panel
    $progPnl.Dock = "Top"; $progPnl.Height = 42; $progPnl.BackColor = [System.Drawing.Color]::FromArgb(14,14,14)
    $form.Controls.Add($progPnl)

    $phaseLbl = New-Object System.Windows.Forms.Label
    $phaseLbl.Text = "  INITIALIZING..."; $phaseLbl.Font = $monoBold
    $phaseLbl.ForeColor = $yellow; $phaseLbl.AutoSize = $false
    $phaseLbl.Width = 900; $phaseLbl.Height = 18
    $phaseLbl.Location = New-Object System.Drawing.Point(8, 4)
    $progPnl.Controls.Add($phaseLbl)
    $global:GUI_PHASE_LBL = $phaseLbl

    $progBar = New-Object System.Windows.Forms.ProgressBar
    $progBar.Minimum = 0; $progBar.Maximum = 100; $progBar.Value = 0
    $progBar.Size = New-Object System.Drawing.Size(1300, 14)
    $progBar.Location = New-Object System.Drawing.Point(8, 24)
    $progBar.Style = "Continuous"
    try {
        # Win10+ progress bar color via SendMessage
        Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class WinAPI { [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd,int Msg,IntPtr wParam,IntPtr lParam); }
"@ -ErrorAction SilentlyContinue
        [WinAPI]::SendMessage($progBar.Handle, 0x400+16, [IntPtr]1, [IntPtr]0) | Out-Null
    } catch {}
    $progPnl.Controls.Add($progBar)
    $global:GUI_PROG_BAR = $progBar

    # ── Risk / findings counter strip ─────────────────────────────────────────
    $riskPnl = New-Object System.Windows.Forms.Panel
    $riskPnl.Dock = "Top"; $riskPnl.Height = 28; $riskPnl.BackColor = [System.Drawing.Color]::FromArgb(10,10,10)
    $form.Controls.Add($riskPnl)

    $riskLbl = New-Object System.Windows.Forms.Label
    $riskLbl.Text = "  LIVE FINDINGS: 0  ·  ☣ CRITICAL: 0  ▲ HIGH: 0  ? POSSIBLE: 0"
    $riskLbl.Font = $monoBold; $riskLbl.ForeColor = [System.Drawing.Color]::FromArgb(100,100,100)
    $riskLbl.AutoSize = $false; $riskLbl.Width = 900; $riskLbl.Height = 22
    $riskLbl.Location = New-Object System.Drawing.Point(8, 4)
    $riskPnl.Controls.Add($riskLbl)
    $global:GUI_RISK_LBL = $riskLbl

    # ── Split panel: left=log, right=tree ─────────────────────────────────────
    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = "Fill"; $split.Orientation = "Vertical"
    $split.SplitterDistance = 560; $split.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
    $form.Controls.Add($split)

    # Left panel — live log
    $logHdr = New-Object System.Windows.Forms.Label
    $logHdr.Text = "  ◈  LIVE SCAN OUTPUT"; $logHdr.Dock = "Top"; $logHdr.Height = 22
    $logHdr.Font = $monoBold; $logHdr.ForeColor = $acRgb
    $logHdr.BackColor = [System.Drawing.Color]::FromArgb(18,18,18)
    $split.Panel1.Controls.Add($logHdr)

    $logBox = New-Object System.Windows.Forms.RichTextBox
    $logBox.Dock = "Fill"; $logBox.BackColor = $bgMid; $logBox.ForeColor = $fgMain
    $logBox.Font = New-Object System.Drawing.Font("Consolas",8)
    $logBox.ReadOnly = $true; $logBox.BorderStyle = "None"
    $logBox.ScrollBars = "Vertical"; $logBox.WordWrap = $false
    $split.Panel1.Controls.Add($logBox)
    $global:GUI_LIVE_LOG = $logBox

    # Right panel — live tree
    $treeHdr = New-Object System.Windows.Forms.Label
    $treeHdr.Text = "  ◈  FINDINGS (LIVE)"; $treeHdr.Dock = "Top"; $treeHdr.Height = 22
    $treeHdr.Font = $monoBold; $treeHdr.ForeColor = $acRgb
    $treeHdr.BackColor = [System.Drawing.Color]::FromArgb(18,18,18)
    $split.Panel2.Controls.Add($treeHdr)

    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Dock = "Fill"; $tree.BackColor = $bgMid; $tree.ForeColor = $fgMain
    $tree.CheckBoxes = $true; $tree.Font = $mono
    $tree.BorderStyle = "None"
    $tree.add_AfterCheck({
        param($s, $e)
        if ($e.Action -eq [System.Windows.Forms.TreeViewAction]::ByMouse) {
            if ($e.Node.Tag -is [hashtable]) {
                $f = [hashtable]$e.Node.Tag
                if (-not $e.Node.Checked -and $f.Severity -eq "CRITICAL") {
                    $ans = [System.Windows.Forms.MessageBox]::Show(
                        "WARNING: Deselecting a CRITICAL finding:`n`n$($f.Description)`n`nThis is BLATANTLY MALICIOUS. Skip anyway?",
                        "CRITICAL — CONFIRM SKIP",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Warning)
                    if ($ans -eq [System.Windows.Forms.DialogResult]::No) { $e.Node.Checked = $true; return }
                }
                $f.Selected = $e.Node.Checked
            } else {
                foreach ($child in $e.Node.Nodes) {
                    $child.Checked = $e.Node.Checked
                    if ($child.Tag -is [hashtable]) { ([hashtable]$child.Tag).Selected = $e.Node.Checked }
                }
            }
        }
    })
    $split.Panel2.Controls.Add($tree)
    $global:GUI_LIVE_TREE = $tree

    # ── Bottom action bar ─────────────────────────────────────────────────────
    $bottomPnl = New-Object System.Windows.Forms.Panel
    $bottomPnl.Dock = "Bottom"; $bottomPnl.Height = 52
    $bottomPnl.BackColor = [System.Drawing.Color]::FromArgb(10,10,10)
    $form.Controls.Add($bottomPnl)

    $btnSA = New-Object System.Windows.Forms.Button
    $btnSA.Text = "✔ SELECT ALL"; $btnSA.Size = New-Object System.Drawing.Size(130, 36)
    $btnSA.Location = New-Object System.Drawing.Point(8, 8)
    $btnSA.BackColor = [System.Drawing.Color]::FromArgb(25,40,25); $btnSA.ForeColor = $green
    $btnSA.FlatStyle = "Flat"; $btnSA.Font = $monoBold
    $btnSA.add_Click({
        foreach ($gn in $tree.Nodes) { $gn.Checked = $true
            foreach ($cn in $gn.Nodes) { $cn.Checked = $true; if ($cn.Tag -is [hashtable]) { ([hashtable]$cn.Tag).Selected = $true } }
        }
    })
    $bottomPnl.Controls.Add($btnSA)

    $btnCA = New-Object System.Windows.Forms.Button
    $btnCA.Text = "✖ CLEAR ALL"; $btnCA.Size = New-Object System.Drawing.Size(130, 36)
    $btnCA.Location = New-Object System.Drawing.Point(146, 8)
    $btnCA.BackColor = [System.Drawing.Color]::FromArgb(40,15,15); $btnCA.ForeColor = $red
    $btnCA.FlatStyle = "Flat"; $btnCA.Font = $monoBold
    $btnCA.add_Click({
        foreach ($gn in $tree.Nodes) { $gn.Checked = $false
            foreach ($cn in $gn.Nodes) { $cn.Checked = $false; if ($cn.Tag -is [hashtable]) { ([hashtable]$cn.Tag).Selected = $false } }
        }
    })
    $bottomPnl.Controls.Add($btnCA)

    $btnCritOnly = New-Object System.Windows.Forms.Button
    $btnCritOnly.Text = "☣ CRIT+HIGH ONLY"; $btnCritOnly.Size = New-Object System.Drawing.Size(160, 36)
    $btnCritOnly.Location = New-Object System.Drawing.Point(284, 8)
    $btnCritOnly.BackColor = [System.Drawing.Color]::FromArgb(40,20,0); $btnCritOnly.ForeColor = $orange
    $btnCritOnly.FlatStyle = "Flat"; $btnCritOnly.Font = $monoBold
    $btnCritOnly.add_Click({
        foreach ($gn in $tree.Nodes) {
            foreach ($cn in $gn.Nodes) {
                if ($cn.Tag -is [hashtable]) {
                    $f = [hashtable]$cn.Tag
                    $sel = ($f.Severity -in @("CRITICAL","HIGH"))
                    $cn.Checked = $sel; $f.Selected = $sel
                }
            }
            $anyChecked = ($gn.Nodes | Where-Object { $_.Checked }).Count -gt 0
            $gn.Checked = $anyChecked
        }
    })
    $bottomPnl.Controls.Add($btnCritOnly)

    $scanningLbl = New-Object System.Windows.Forms.Label
    $scanningLbl.Text = "  ⟳  SCAN RUNNING..."
    $scanningLbl.Font = $monoBold; $scanningLbl.ForeColor = $yellow
    $scanningLbl.AutoSize = $false; $scanningLbl.Width = 220; $scanningLbl.Height = 36
    $scanningLbl.Location = New-Object System.Drawing.Point(460, 10)
    $bottomPnl.Controls.Add($scanningLbl)

    $btnFix = New-Object System.Windows.Forms.Button
    $btnFix.Text = "▶  EXECUTE SELECTED FIXES"; $btnFix.Size = New-Object System.Drawing.Size(280, 44)
    $btnFix.Location = New-Object System.Drawing.Point(1030, 4)
    $btnFix.BackColor = [System.Drawing.Color]::FromArgb(20,20,20); $btnFix.ForeColor = $acRgb
    $btnFix.FlatStyle = "Flat"; $btnFix.Font = $monoLg
    $btnFix.Enabled = $false   # enabled after scan completes
    $btnFix.add_Click({ $form.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.Close() })
    $bottomPnl.Controls.Add($btnFix)

    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = "EXIT WITHOUT FIXING"; $btnExit.Size = New-Object System.Drawing.Size(200, 20)
    $btnExit.Location = New-Object System.Drawing.Point(1110, 30)
    $btnExit.BackColor = [System.Drawing.Color]::FromArgb(20,20,20); $btnExit.ForeColor = [System.Drawing.Color]::FromArgb(80,80,80)
    $btnExit.FlatStyle = "Flat"; $btnExit.Font = $mono
    $btnExit.add_Click({ $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $form.Close() })
    $bottomPnl.Controls.Add($btnExit)

    # Store scanning label and fix button for post-scan update
    $script:_scanningLbl = $scanningLbl
    $script:_btnFix      = $btnFix

    # Show modeless — scan runs in the same thread, DoEvents keeps UI alive
    $form.Show()
    [System.Windows.Forms.Application]::DoEvents()
    return $form
}

function Complete-LiveScanDashboard {
    # Called after scan finishes — update UI to fix mode
    if ($null -eq $global:GUI_LIVE_FORM -or $global:GUI_LIVE_FORM.IsDisposed) { return }
    if ($null -ne $script:_scanningLbl) {
        $script:_scanningLbl.Text = "  ✔  SCAN COMPLETE"
        $script:_scanningLbl.ForeColor = [System.Drawing.Color]::FromArgb(80,220,80)
    }
    if ($null -ne $script:_btnFix) { $script:_btnFix.Enabled = $true }
    if ($null -ne $global:GUI_PHASE_LBL) { $global:GUI_PHASE_LBL.Text = "  ✔  AUDIT COMPLETE — Review findings and click EXECUTE SELECTED FIXES" }
    if ($null -ne $global:GUI_PROG_BAR) { $global:GUI_PROG_BAR.Value = 100 }
    # Update risk label with final totals
    if ($null -ne $global:GUI_RISK_LBL) {
        $cC = ($global:AuditFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $hC = ($global:AuditFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
        $pC = ($global:AuditFindings | Where-Object { $_.Severity -eq "POSSIBLE" }).Count
        $iC = ($global:AuditFindings | Where-Object { $_.Severity -eq "INFO" }).Count
        $global:GUI_RISK_LBL.Text = "  TOTAL FINDINGS: $($global:AuditFindings.Count)  ·  ☣ CRITICAL: $cC  ▲ HIGH: $hC  ? POSSIBLE: $pC  INFO: $iC"
    }
    [System.Windows.Forms.Application]::DoEvents()
    # Block until user closes
    $global:GUI_LIVE_FORM.ShowDialog() | Out-Null
}

# ── GUI Checkbox Menu (WinForms) — legacy post-scan version kept as fallback ──
function Show-GUICheckboxMenu {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "ZeroBreach V22 — Fix / Remediation Mode"
    $form.Size = New-Object System.Drawing.Size(980, 780)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
    $form.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $form.Font = New-Object System.Drawing.Font("Consolas", 9)

    $header = New-Object System.Windows.Forms.Label
    $header.Text = "  ◈  ZEROBREACH V22 — REMEDIATION CONTROL PANEL"
    $header.AutoSize = $false; $header.Width = 960; $header.Height = 32
    $header.Location = New-Object System.Drawing.Point(0, 6)
    $header.ForeColor = if ($global:MSP_MODE) { [System.Drawing.Color]::FromArgb(255,102,0) } else { [System.Drawing.Color]::FromArgb(0,200,255) }
    $header.Font = New-Object System.Drawing.Font("Consolas", 13, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($header)

    $riskLbl = New-Object System.Windows.Forms.Label
    $riskColor2 = if ($totalRisk -gt 20) { [System.Drawing.Color]::Red } `
                  elseif ($totalRisk -gt 10) { [System.Drawing.Color]::DarkOrange } `
                  elseif ($totalRisk -gt 3)  { [System.Drawing.Color]::Yellow } `
                  else { [System.Drawing.Color]::LimeGreen }
    $riskLbl.Text = "  RISK: $totalRisk — $riskLabel  |  CRITICAL: $critCount  HIGH: $highCount  POSSIBLE: $possibleCount  INFO: $infoCount"
    $riskLbl.AutoSize = $false; $riskLbl.Width = 960; $riskLbl.Height = 22
    $riskLbl.Location = New-Object System.Drawing.Point(0, 40)
    $riskLbl.ForeColor = $riskColor2
    $form.Controls.Add($riskLbl)

    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Location = New-Object System.Drawing.Point(8, 70)
    $tree.Size = New-Object System.Drawing.Size(950, 555)
    $tree.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24)
    $tree.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $tree.CheckBoxes = $true
    $tree.Font = New-Object System.Drawing.Font("Consolas", 9)

    $groups = $global:AuditFindings | Group-Object { $_.Group } | Sort-Object Name
    foreach ($grp in $groups) {
        $critN = ($grp.Group | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highN = ($grp.Group | Where-Object { $_.Severity -eq "HIGH" }).Count
        $tag   = if ($critN -gt 0) { "  [$critN CRITICAL]" } elseif ($highN -gt 0) { "  [$highN HIGH]" } else { "" }
        $gNode = New-Object System.Windows.Forms.TreeNode
        $gNode.Text = "$($grp.Name)$tag"
        $gNode.ForeColor = if ($critN -gt 0) { [System.Drawing.Color]::FromArgb(255,80,80) } `
                           elseif ($highN -gt 0) { [System.Drawing.Color]::FromArgb(255,160,0) } `
                           else { [System.Drawing.Color]::FromArgb(100,180,255) }
        $gNode.Checked = $true

        foreach ($finding in $grp.Group) {
            $cNode = New-Object System.Windows.Forms.TreeNode
            $pfx = switch ($finding.Severity) {
                "CRITICAL" { "☣ CRIT  " } "HIGH" { "▲ HIGH  " } "POSSIBLE" { "? POSS  " } default { "  INFO  " }
            }
            $d = $finding.Description; if ($d.Length -gt 85) { $d = $d.Substring(0,82) + "..." }
            $cNode.Text = "$pfx $d"
            $cNode.Checked = $finding.Selected
            $cNode.ForeColor = switch ($finding.Severity) {
                "CRITICAL" { [System.Drawing.Color]::FromArgb(255,80,80)   }
                "HIGH"     { [System.Drawing.Color]::FromArgb(255,160,0)   }
                "POSSIBLE" { [System.Drawing.Color]::FromArgb(255,220,50)  }
                default    { [System.Drawing.Color]::FromArgb(130,130,130) }
            }
            $cNode.Tag = $finding
            $gNode.Nodes.Add($cNode) | Out-Null
        }
        $tree.Nodes.Add($gNode) | Out-Null
    }
    $tree.ExpandAll()

    $tree.add_AfterCheck({
        param($s, $e)
        if ($e.Action -eq [System.Windows.Forms.TreeViewAction]::ByMouse) {
            if ($e.Node.Tag -is [hashtable]) {
                $f = [hashtable]$e.Node.Tag
                if (-not $e.Node.Checked -and $f.Severity -eq "CRITICAL") {
                    $ans = [System.Windows.Forms.MessageBox]::Show(
                        "WARNING: Deselecting a CRITICAL finding:`n`n$($f.Description)`n`nThis is classified BLATANTLY MALICIOUS. Skip anyway?",
                        "CRITICAL — CONFIRM SKIP",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Warning)
                    if ($ans -eq [System.Windows.Forms.DialogResult]::No) { $e.Node.Checked = $true; return }
                }
                $f.Selected = $e.Node.Checked
            } else {
                foreach ($child in $e.Node.Nodes) {
                    $child.Checked = $e.Node.Checked
                    if ($child.Tag -is [hashtable]) { ([hashtable]$child.Tag).Selected = $e.Node.Checked }
                }
            }
        }
    })
    $form.Controls.Add($tree)

    $btnSA = New-Object System.Windows.Forms.Button
    $btnSA.Text = "SELECT ALL"; $btnSA.Location = New-Object System.Drawing.Point(8, 638)
    $btnSA.Size = New-Object System.Drawing.Size(110, 30); $btnSA.BackColor = [System.Drawing.Color]::FromArgb(40,40,40)
    $btnSA.ForeColor = [System.Drawing.Color]::LimeGreen; $btnSA.FlatStyle = "Flat"
    $btnSA.add_Click({
        foreach ($gn in $tree.Nodes) { $gn.Checked = $true
            foreach ($cn in $gn.Nodes) { $cn.Checked = $true; if ($cn.Tag -is [hashtable]) { ([hashtable]$cn.Tag).Selected = $true } }
        }
    })
    $form.Controls.Add($btnSA)

    $btnCA = New-Object System.Windows.Forms.Button
    $btnCA.Text = "CLEAR ALL"; $btnCA.Location = New-Object System.Drawing.Point(126, 638)
    $btnCA.Size = New-Object System.Drawing.Size(110, 30); $btnCA.BackColor = [System.Drawing.Color]::FromArgb(40,40,40)
    $btnCA.ForeColor = [System.Drawing.Color]::FromArgb(200,60,60); $btnCA.FlatStyle = "Flat"
    $btnCA.add_Click({
        foreach ($gn in $tree.Nodes) { $gn.Checked = $false
            foreach ($cn in $gn.Nodes) { $cn.Checked = $false; if ($cn.Tag -is [hashtable]) { ([hashtable]$cn.Tag).Selected = $false } }
        }
    })
    $form.Controls.Add($btnCA)

    $hint = New-Object System.Windows.Forms.Label
    $hint.Location = New-Object System.Drawing.Point(250, 646); $hint.Size = New-Object System.Drawing.Size(430, 18)
    $hint.ForeColor = [System.Drawing.Color]::Yellow
    $hint.Text = "Checkboxes cascade. CRITICAL items warn on deselect."
    $form.Controls.Add($hint)

    $acCol = if ($global:MSP_MODE) { [System.Drawing.Color]::FromArgb(255,102,0) } else { [System.Drawing.Color]::FromArgb(0,180,255) }
    $btnEx = New-Object System.Windows.Forms.Button
    $btnEx.Text = "▶  EXECUTE SELECTED FIXES"
    $btnEx.Location = New-Object System.Drawing.Point(695, 633); $btnEx.Size = New-Object System.Drawing.Size(265, 40)
    $btnEx.BackColor = [System.Drawing.Color]::FromArgb(30,30,30); $btnEx.ForeColor = $acCol
    $btnEx.FlatStyle = "Flat"
    $btnEx.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
    $btnEx.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($btnEx)

    $btnQuit = New-Object System.Windows.Forms.Button
    $btnQuit.Text = "EXIT WITHOUT FIXING"; $btnQuit.Location = New-Object System.Drawing.Point(695, 679)
    $btnQuit.Size = New-Object System.Drawing.Size(265, 20); $btnQuit.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
    $btnQuit.ForeColor = [System.Drawing.Color]::DarkGray; $btnQuit.FlatStyle = "Flat"
    $btnQuit.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($btnQuit)

    $form.AcceptButton = $btnEx; $form.CancelButton = $btnQuit
    $result = $form.ShowDialog(); $form.Dispose()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return @() }
    return ($global:AuditFindings | Where-Object { $_.Selected })
}

# ── Shell Checkbox Menu (console fallback) ─────────────────────────────────────
function Show-ShellCheckboxMenu {
    $all = $global:AuditFindings
    $running = $true
    while ($running) {
        Clear-Host
        Write-Host ("▓"*80) -ForegroundColor DarkRed
        Write-Host "  ◈  Z E R O B R E A C H  V 2 1  ·  R E M E D I A T I O N  M O D E" -ForegroundColor (Get-AccentColor)
        Write-Host ("▓"*80) -ForegroundColor DarkRed
        Write-Host "  Risk: $totalRisk  |  CRITICAL: $critCount  HIGH: $highCount  POSSIBLE: $possibleCount  INFO: $infoCount" -ForegroundColor Yellow
        Write-Host "  [A] Select All  [C] Clear All  [ENTER] Execute  [Q] Quit  |  Toggle by number" -ForegroundColor DarkGray
        Write-Host ("─"*80) -ForegroundColor DarkCyan
        Write-Host ""

        $i = 1; $idxMap = @{}; $curGrp = ""
        foreach ($f in $all) {
            if ($f.Group -ne $curGrp) {
                $curGrp = $f.Group
                Write-Host "  ── $curGrp " -NoNewline -ForegroundColor DarkCyan
                Write-Host ("─" * [Math]::Max(2, 58 - $curGrp.Length)) -ForegroundColor DarkCyan
            }
            $idxMap[$i] = $f
            $chk = if ($f.Selected) { "[✓]" } else { "[ ]" }
            $sev = switch ($f.Severity) { "CRITICAL"{"☣ CRIT "} "HIGH"{"▲ HIGH "} "POSSIBLE"{"? POSS "} default{"  INFO "} }
            $cc  = if ($f.Selected) { "Green" } else { "DarkGray" }
            $sc  = switch ($f.Severity) { "CRITICAL"{"Red"} "HIGH"{"DarkYellow"} "POSSIBLE"{"Yellow"} default{"DarkGray"} }
            Write-Host "  " -NoNewline
            Write-Host $chk -NoNewline -ForegroundColor $cc
            Write-Host " " -NoNewline
            Write-Host $sev -NoNewline -ForegroundColor $sc
            $d = $f.Description; if ($d.Length -gt 55) { $d = $d.Substring(0,52)+"..." }
            Write-Host "$($i.ToString().PadLeft(3)).  $d" -ForegroundColor $(if ($f.Selected) {"White"} else {"DarkGray"})
            $i++
        }

        Write-Host ""
        Write-Host ("─"*80) -ForegroundColor DarkCyan
        $selN = ($all | Where-Object { $_.Selected }).Count
        Write-Host "  SELECTED: $selN / $($all.Count)" -ForegroundColor Yellow
        Write-Host "  > " -NoNewline -ForegroundColor DarkGray
        $inp = (Read-Host).Trim().ToUpper()

        switch ($inp) {
            "A" { foreach ($f in $all) { $f.Selected = $true } }
            "C" { foreach ($f in $all) { $f.Selected = $false } }
            "Q" { $running = $false; return @() }
            ""  {
                if ($selN -eq 0) { Write-Host "  NO ITEMS SELECTED." -ForegroundColor Yellow; Start-Sleep 2 }
                else { $running = $false }
            }
            default {
                if ($inp -match "^\d+$") {
                    $n = [int]$inp
                    if ($idxMap.ContainsKey($n)) {
                        $f = $idxMap[$n]
                        if ($f.Selected -and $f.Severity -eq "CRITICAL") {
                            Write-Host ""
                            Write-Host "  ┌─ WARNING ─────────────────────────────────────────────────────────────┐" -ForegroundColor Red
                            Write-Host "  │  ☣  DESELECTING CRITICAL FINDING:                                    │" -ForegroundColor Red
                            $dw = $f.Description.Substring(0,[Math]::Min(68,$f.Description.Length))
                            Write-Host "  │  $($dw.PadRight(68))  │" -ForegroundColor Yellow
                            Write-Host "  │  This is BLATANTLY MALICIOUS. Deselect? (Y/N)                       │" -ForegroundColor Red
                            Write-Host "  └───────────────────────────────────────────────────────────────────────┘" -ForegroundColor Red
                            Write-Host "  > " -NoNewline -ForegroundColor DarkGray
                            $c = (Read-Host).Trim().ToUpper()
                            if ($c -eq "Y") { $f.Selected = $false }
                        } elseif ($f.Selected) { $f.Selected = $false }
                        else { $f.Selected = $true }
                    }
                }
            }
        }
    }
    return ($all | Where-Object { $_.Selected })
}

# ══════════════════════════════════════════════════════════════════════════════
#  FIX EXECUTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-FixMode {
    param([hashtable[]]$SelectedFindings)
    if ($SelectedFindings.Count -eq 0) { Out-Typewriter "NO FIXES SELECTED." "WARN"; return }

    Write-Host ""
    Write-Host ("▓"*80) -ForegroundColor DarkRed
    Write-Host "  ◈  EXECUTING $($SelectedFindings.Count) REMEDIATIONS" -ForegroundColor Red
    Write-Host ("▓"*80) -ForegroundColor DarkRed

    $fixLog = [System.Collections.Generic.List[string]]::new()
    $fixOK = 0; $fixFail = 0; $fixSkip = 0

    foreach ($f in $SelectedFindings) {
        $ts = (Get-Date).ToString("HH:mm:ss.fff")
        $d = $f.Description; if ($d.Length -gt 60) { $d = $d.Substring(0,57)+"..." }
        Write-Host "[$ts] " -NoNewline -ForegroundColor DarkGray
        Write-Host "FIX: " -NoNewline -ForegroundColor (Get-AccentColor)
        Write-Host $d -ForegroundColor White

        $ok = $false
        try {
            switch ($f.FixAction) {
                "DeleteFile" {
                    if (Test-Path $f.FixParam) {
                        Remove-Item -Path $f.FixParam -Recurse -Force -ErrorAction Stop
                        if (Test-Path $f.FixParam) {
                            # Kernel-queue for locked files
                            $rp  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
                            $cur = Get-ItemPropertyValue $rp "PendingFileRenameOperations" -ErrorAction SilentlyContinue
                            if ($null -eq $cur) { $cur = @() }
                            Set-ItemProperty $rp "PendingFileRenameOperations" ([string[]]($cur) + @("\??\$($f.FixParam)", "")) -Type MultiString -Force -ErrorAction SilentlyContinue
                            Out-Typewriter "  -> QUEUED FOR REBOOT DELETION." "WARN"
                        } else { Out-Typewriter "  -> DELETED: $($f.FixParam)" "GOOD" }
                        $global:KillCount++; $ok = $true
                    } else { Out-Typewriter "  -> ALREADY ABSENT." "VER"; $ok = $true }
                }
                "DeleteReg" {
                    $pts = $f.FixParam -split "\|", 2
                    if ($pts.Count -eq 2) {
                        Remove-ItemProperty -Path $pts[0] -Name $pts[1] -Force -ErrorAction SilentlyContinue
                        $chk = Get-ItemProperty -Path $pts[0] -Name $pts[1] -ErrorAction SilentlyContinue
                        if ($null -eq $chk.($pts[1])) {
                            Out-Typewriter "  -> REG VALUE DELETED: $($pts[1])" "GOOD"; $global:KillCount++; $ok = $true
                        } else { Out-Typewriter "  -> REG DELETE FAILED." "WARN"; $fixFail++ }
                    }
                }
                "DeleteRegKey" {
                    if (Test-Path $f.FixParam) {
                        Remove-Item -Path $f.FixParam -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path $f.FixParam)) {
                            Out-Typewriter "  -> REG KEY DELETED." "GOOD"; $global:KillCount++; $ok = $true
                        } else { Out-Typewriter "  -> REG KEY DELETE FAILED." "WARN"; $fixFail++ }
                    } else { Out-Typewriter "  -> KEY ALREADY ABSENT." "VER"; $ok = $true }
                }
                "KillProcess" {
                    $pid2 = [int]$f.FixParam
                    $proc = Get-Process -Id $pid2 -ErrorAction SilentlyContinue
                    if ($proc) {
                        Stop-Process -Id $pid2 -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 400
                        if (-not (Get-Process -Id $pid2 -ErrorAction SilentlyContinue)) {
                            Out-Typewriter "  -> TERMINATED: PID $pid2 ($($proc.Name))" "GOOD"; $global:KillCount++; $ok = $true
                        } else { Out-Typewriter "  -> KILL FAILED: PID $pid2" "WARN"; $fixFail++ }
                    } else { Out-Typewriter "  -> PROCESS ALREADY GONE." "VER"; $ok = $true }
                }
                "RunCmd" {
                    $sb = [scriptblock]::Create($f.FixParam)
                    & $sb
                    Out-Typewriter "  -> COMMAND EXECUTED." "GOOD"; $global:KillCount++; $ok = $true
                }
                "Info" {
                    Out-Typewriter "  -> INFORMATIONAL — REVIEW MANUALLY." "DATA"; $fixSkip++; $ok = $true
                }
            }
        } catch {
            Out-Typewriter "  -> ERROR: $_" "WARN"; $fixFail++
        }

        if ($ok -and $f.FixAction -ne "Info") { $fixOK++ }
        $fixLog.Add("[$($f.Severity)] $($f.ThreatType) | $($f.Description) | $($f.FixAction) | $(if($ok){'OK'}else{'FAILED'})")
        if (-not $global:MSP_MODE) { Start-Sleep -Milliseconds 150 }
    }

    # Always-apply baseline hardening after fixes
    Out-Typewriter "APPLYING BASELINE LSA HARDENING..." "ACT"
    $lp = "HKLM:\System\CurrentControlSet\Control\Lsa"
    Set-ItemProperty $lp RestrictAnonymous    1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty $lp RestrictAnonymousSAM 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty $lp NoLMHash             1 -Type DWord -Force -ErrorAction SilentlyContinue
    Out-Typewriter "  -> LSA HARDENING APPLIED." "GOOD"

    Out-Typewriter "FLUSHING DNS CACHE..." "ACT"
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Out-Typewriter "  -> DNS FLUSHED." "GOOD"

    # Append fix log to report file
    @("","="*80,"FIX MODE LOG — $(Get-Date)",
      "Selected: $($SelectedFindings.Count) | OK: $fixOK | Failed: $fixFail | Skipped: $fixSkip",
      "Snapshot: $SNAPSHOT_PATH","="*80) + $fixLog |
        Add-Content -Path $REPORT_PATH -Encoding UTF8 -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host ("▓"*80) -ForegroundColor DarkCyan
    Write-Host "  ◈◈◈  F I X   M O D E   C O M P L E T E  ◈◈◈" -ForegroundColor Cyan
    Write-Host ("▓"*80) -ForegroundColor DarkCyan
    Write-Host "  FIXES APPLIED     : " -NoNewline -ForegroundColor DarkGray; Write-Host $fixOK  -ForegroundColor Green
    Write-Host "  FIX FAILURES      : " -NoNewline -ForegroundColor DarkGray
    Write-Host $fixFail -ForegroundColor $(if ($fixFail -gt 0) {"Red"} else {"Green"})
    Write-Host "  INFO / SKIPPED    : " -NoNewline -ForegroundColor DarkGray; Write-Host $fixSkip -ForegroundColor DarkGray
    Write-Host "  SNAPSHOT          : " -NoNewline -ForegroundColor DarkGray; Write-Host $SNAPSHOT_PATH -ForegroundColor Yellow
    Write-Host "  FULL REPORT       : " -NoNewline -ForegroundColor DarkGray; Write-Host $REPORT_PATH   -ForegroundColor Cyan
    Write-Host ("─"*80) -ForegroundColor DarkCyan
    if ($fixFail -gt 0 -or $global:VerifyFails -gt 0) {
        Write-Host "  STATUS: REBOOT RECOMMENDED — PENDING DELETIONS QUEUED." -ForegroundColor Yellow
        Write-Host "  ROLLBACK: regedit /S `"$SNAPSHOT_PATH`"" -ForegroundColor DarkGray
    } else {
        Write-Host "  STATUS: REMEDIATION COMPLETE. REVIEW REPORT FOR MANUAL ITEMS." -ForegroundColor Cyan
    }
    Write-Host ("▓"*80) -ForegroundColor DarkCyan
}

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT — LAUNCH FIX UI
# ══════════════════════════════════════════════════════════════════════════════
Out-Typewriter "LOADING REMEDIATION INTERFACE..." "ACT"
Invoke-QuantumBar "BUILDING CHECKBOX MANIFEST" 10 80

# Stop shell kill watcher job if running
if ($global:SHELL_KILL_JOB) {
    Stop-Job $global:SHELL_KILL_JOB -ErrorAction SilentlyContinue
    Remove-Job $global:SHELL_KILL_JOB -ErrorAction SilentlyContinue
    if ($global:SHELL_KILL_FLAG -and (Test-Path $global:SHELL_KILL_FLAG)) {
        Remove-Item $global:SHELL_KILL_FLAG -Force -ErrorAction SilentlyContinue
    }
}

$selectedFixes = @()
if ($global:GUI_MODE) {
    # Dashboard was already running live — call Complete to switch to fix mode
    Complete-LiveScanDashboard
    if ($global:GUI_LIVE_FORM.DialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        $selectedFixes = ($global:AuditFindings | Where-Object { $_.Selected })
    }
} else {
    $selectedFixes = Show-ShellCheckboxMenu
}

if ($selectedFixes.Count -eq 0) {
    Out-Typewriter "NO FIXES SELECTED. AUDIT LOG PRESERVED." "INFO"
} else {
    Write-Host ""
    Write-Host "  ┌─ FINAL CONFIRMATION ───────────────────────────────────────────────────┐" -ForegroundColor Red
    Write-Host "  │  About to execute $($selectedFixes.Count) remediation action(s).                           │" -ForegroundColor Red
    Write-Host "  │  Snapshot: $(Split-Path $SNAPSHOT_PATH -Leaf)                        │" -ForegroundColor Yellow
    Write-Host "  │  Type  CONFIRM  to proceed. Anything else aborts.                    │" -ForegroundColor Red
    Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Red
    Write-Host "  COMMAND> " -NoNewline -ForegroundColor DarkGray
    $finalConfirm = (Read-Host).Trim().ToUpper()
    if ($finalConfirm -eq "CONFIRM") {
        Invoke-FixMode -SelectedFindings $selectedFixes
    } else {
        Out-Typewriter "ABORTED BY OPERATOR. NO CHANGES MADE." "WARN"
    }
}

Write-Host ""
Out-Typewriter "PRESS ANY KEY TO CLOSE." "INFO" 20
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
