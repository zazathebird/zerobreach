trap { Write-RecoveredError $_; continue }   # module-level resilience: a terminating error resumes at the NEXT phase in THIS module, not the next dot-sourced module (see CLAUDE.md engine-split rule)
# ══════════════════════════════════════════════════════════════════════════════
#  MODULE-LOCAL HELPERS
#  (EVIDENCE_ENGINE_PLAN P4/P5 + A13/A14, and the Phase-10 false-positive tune)
#  Defined here, after the module trap and before any phase body, so they exist in every
#  mode — Phase 10 is a member of the 30-phase QUICK set and uses Test-ZbP10BenignPath.
#  All locals are $zb*-prefixed: the engine is ONE dot-sourced scope and PowerShell
#  variables are case-insensitive, so an unprefixed local can silently reassign the
#  loader's param() switches (a local $auto once disabled the whole engine).
# ══════════════════════════════════════════════════════════════════════════════

# ── Phase 10 benign-path gate (user-approved 2026-07-26) ─────────────────────────────────
# Phase 10 flagged EVERY executable-extension file under %TEMP% as HIGH + DeleteFile and
# consulted no benign-path list at all. On this workstation that was 92 of the box's 94
# AUTO-SELECTED destructive findings, every one of them inert tool debris under
# %TEMP%\claude\ — a live rule #1 exposure (a destructive action auto-firing on a healthy box).
#
# Test-BenignPath is the project-standard gate and is called FIRST, unchanged. Read what its
# veto actually does before touching this: $global:ALLOW_VETO_RE deliberately IGNORES an
# allowlist match found anywhere under \Temp\ or \Downloads\, because those allowlists key on
# folder names an attacker can simply create. Phase 10's entire scope IS \Temp\ / \Downloads\ /
# INetCache, so Test-BenignPath on its own can never downgrade anything in this phase. A second,
# deliberately narrow list is therefore permitted to override the veto, and three things keep
# that honest:
#   * every pattern is anchored to whole path COMPONENTS ('\temp\claude\', never bare 'claude'),
#   * a hit only ever DOWNGRADES to INFO + FixAction Info — the file is still reported, so an
#     attacker who mkdir's %TEMP%\claude\ loses auto-SELECTION, not detection (the standing
#     "downgrade, never delete the detection" rule), and
#   * the phase's content-based PE-masquerade sniff is NOT gated on this at all, so a renamed
#     payload parked in an allowlisted cache is still identified by its bytes.
# Both keys live in data\detection_signatures.json (AMSI rule). A missing key yields '(?!)'
# from Join-AllowRegex, which matches nothing — i.e. the pre-fix behaviour, never a wider one.
$global:ZB_P10_BENIGN_RE     = Join-AllowRegex 'temp_exe_benign_paths'
$global:ZB_P10_STAGING_OK_RE = Join-AllowRegex 'temp_exe_staging_toolcache_paths'
function Test-ZbP10BenignPath {
    param([string]$zbPath)
    if (-not $zbPath) { return $false }
    if (Test-BenignPath -Path $zbPath -AllowRegex $global:ZB_P10_BENIGN_RE) { return $true }
    return ($zbPath -match $global:ZB_P10_STAGING_OK_RE)
}

# ── Shared .lnk resolver (EVIDENCE_ENGINE_PLAN P4 / A13) ────────────────────────────────
# Phase 10.5 built a NEW WScript.Shell COM object per shortcut; Phase 11 now parses the whole
# Recent folder (hundreds of shortcuts), so the COM object is created once and reused.
# Returns $null on ANY failure — callers must treat $null as "unknown", never as "clean".
$global:ZB_LNK_SHELL = $null
function Get-ZbLnkInfo {
    param([string]$zbLnkPath)
    if (-not $zbLnkPath) { return $null }
    if ($null -eq $global:ZB_LNK_SHELL) {
        try { $global:ZB_LNK_SHELL = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch { return $null }
    }
    try {
        $zbSc = $global:ZB_LNK_SHELL.CreateShortcut($zbLnkPath)
        if ($null -eq $zbSc) { return $null }
        return [pscustomobject]@{
            LnkPath    = $zbLnkPath
            TargetPath = "$($zbSc.TargetPath)"
            Arguments  = "$($zbSc.Arguments)"
            WorkingDir = "$($zbSc.WorkingDirectory)"
        }
    } catch { return $null }
}

# ── Fail-closed "is this path still on disk?" probe (EVIDENCE_ENGINE_PLAN P4) ────────────
# Returns 'present' | 'missing' | 'unknown'. It NEVER Test-Path's a UNC path or a volume that
# is not attached: Test-Path against an unreachable UNC throws a TERMINATING IOException that
# -ErrorAction SilentlyContinue does NOT suppress, and inside a dot-sourced module that unwinds
# to the module trap and skips every remaining phase (CLAUDE.md). Textual tests come first, and
# anything that cannot be answered locally is 'unknown' — it is never reported as evidence of
# deletion, because "couldn't read it" is not "gone" (fail-closed rule).
$global:ZB_READY_DRIVES = $null
function Get-ZbPathPresence {
    param([string]$zbTarget)
    if (-not $zbTarget) { return 'unknown' }
    if ($zbTarget -match '^\\\\')     { return 'unknown' }   # UNC — do not touch it
    if ($zbTarget -notmatch '^[A-Za-z]:\\') { return 'unknown' }   # shell folder / relative / KNOWNFOLDER GUID
    if ($null -eq $global:ZB_READY_DRIVES) {
        $global:ZB_READY_DRIVES = @{}
        try {
            foreach ($zbDrv in [System.IO.DriveInfo]::GetDrives()) {
                try { if ($zbDrv.IsReady) { $global:ZB_READY_DRIVES[$zbDrv.Name.Substring(0,1).ToUpper()] = "$($zbDrv.DriveType)" } } catch {}
            }
        } catch {}
    }
    $zbLetter = $zbTarget.Substring(0,1).ToUpper()
    if (-not $global:ZB_READY_DRIVES.ContainsKey($zbLetter)) { return 'unknown' }   # removable/absent volume
    if ("$($global:ZB_READY_DRIVES[$zbLetter])" -eq 'Network')  { return 'unknown' }   # mapped drive — same hazard as UNC
    try { if (Test-Path -LiteralPath $zbTarget) { return 'present' } else { return 'missing' } } catch { return 'unknown' }
}

# ── P1 multi-user FILESYSTEM plumbing (Stage 7) ─────────────────────────────────────────
# Every filesystem phase in this module used bare $env:TEMP / $env:APPDATA / $env:LOCALAPPDATA /
# $env:USERPROFILE. The engine self-elevates with RunAs, so on a standard-user endpoint (the
# normal MSP case) the technician supplies ADMIN credentials and those variables resolve to the
# TECHNICIAN's profile — every per-user file check was looking at the wrong profile and reporting
# clean. These two helpers do the plumbing once, so each site stays a two-line change.
#
#   Get-ZbUserRootsM1  Collects one or more NAMED folders (the Get-UserPaths property names:
#                      Temp, LocalAppData, AppData, Downloads, Desktop, Documents, Recent,
#                      INetCache, Startup, Programs, Profile, OneDrive, ...) from EVERY reachable
#                      human profile, in deterministic SID order, ready for a SINGLE Get-ScanFiles
#                      call. The single-call shape is used wherever it fits because
#                      Get-ScanFiles' MaxFiles/DeadlineSecs are PER CALL: wrapping one call in a
#                      per-profile loop multiplies a phase's wall clock by the profile count
#                      (8 profiles x 20 s = 160 s in ONE phase; a terminal server would hang).
#                      Unreachable profiles are dropped here and never re-probed — Test-Path on an
#                      unreachable UNC profile stalled 42 s on a live box and can throw a
#                      TERMINATING IOException that -EA SilentlyContinue does not suppress.
#                      MACHINE-wide roots ($env:WINDIR, $env:ProgramData, $env:PUBLIC,
#                      $env:ALLUSERSPROFILE, Program Files) are deliberately NOT produced here:
#                      callers add them exactly once, outside the profile set, tagged [MACHINE].
#
#   Get-ZbOwnerM1      Attributes a file returned by that single call back to its profile by
#                      LONGEST-prefix match on ProfilePath (longest, not first: C:\Users\bob and
#                      C:\Users\bob.DOMAIN both prefix-match a file under the latter). Returns
#                      User + Sid, defaulting to MACHINE for anything outside every profile.
#
# The M1 suffix is not decoration: the engine is ONE dot-sourced scope shared with Phases-2 and
# Phases-3, so a bare Get-ZbUserRoots defined in two modules would silently resolve to whichever
# module was dot-sourced last.
#
# CALLERS MUST WRAP THE RESULT IN @(). PS 5.1 unrolls a one-element array return to a scalar.
# Deliberately NOT `return ,$arr` — that is exactly the Get-ScanFiles trap this codebase already
# has a hard rule against, and it must not be reintroduced by a helper.
function Get-ZbUserRootsM1 {
    param([string[]]$Kind)
    $zbOut = @()
    foreach ($zbH in @(@(Get-UserHives) | Sort-Object -Property Sid)) {
        if (-not $zbH.ProfileReachable) { continue }
        $zbU = Get-UserPaths $zbH
        if (-not $zbU) { continue }
        foreach ($zbK in $Kind) {
            $zbV = "$($zbU.$zbK)"
            if ($zbV) { $zbOut += $zbV }
        }
    }
    return @($zbOut | Select-Object -Unique)
}
function Get-ZbOwnerM1 {
    param([string]$zbFull)
    $zbUser = 'MACHINE'; $zbSid = 'MACHINE'; $zbBest = -1
    if ($zbFull) {
        $zbLc = "$zbFull".ToLowerInvariant()
        foreach ($zbH in @(Get-UserHives)) {
            $zbPp = "$($zbH.ProfilePath)".ToLowerInvariant()
            if (-not $zbPp) { continue }
            if ($zbLc.StartsWith($zbPp) -and $zbPp.Length -gt $zbBest) {
                $zbUser = "$($zbH.User)"; $zbSid = "$($zbH.Sid)"; $zbBest = $zbPp.Length
            }
        }
    }
    return [pscustomobject]@{ User = $zbUser; Sid = $zbSid }
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1: PRE-FLIGHT
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "PRE-FLIGHT SYSTEMS & LOG AUDIT"

Show-PhaseHeader "PHASE 1" "ANTI-FORENSIC EVENT LOG AUDIT"
Invoke-QuantumBar "PARSING SECURITY EVENTS" 10 140
$logClears = Get-WinEventSafe @{LogName='System','Security'; ID=104,1102} |
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

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 2" "POWERSHELL SCRIPT BLOCK LOG AUDIT (EVENT 4104)"
Invoke-QuantumBar "SCANNING POWERSHELL OPERATIONAL LOGS" 8 120
$psLogs = Get-WinEventSafe @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
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

}   # end QUICK-skip block
Show-PhaseHeader "PHASE 3" "PROCESS ANCESTRY & INJECTION AUDIT"
Invoke-QuantumBar "MAPPING LIVE PROCESS TREE" 8 120
# Split STRONG (unambiguous — obfuscation/injection API names/decode flags in a command line is
# never routine) from WEAK (a bare LOLBin tool name with no argument qualifier at all — the rare
# legitimate legacy-HTA/WSH-logon-script case looks identical to this at the substring level).
# Mirrors the STRONG/WEAK split Phase 29's task-action check already uses for the same reason.
# `\bIEX\b` (word-boundary) so this doesn't substring-match "iexplore.exe" — bare `IEX` matched
# every ordinary launch of Internet Explorer / an embedded WebBrowser control (rule #1 regression
# caught in review, never shipped).
$procInjStrongRe = '\bIEX\b|EncodedCommand|DownloadString|regsvr32[^;]*http|rundll32[^;]*http|certutil[^;]*decode|VirtualAlloc|CreateRemoteThread'
$procInjWeakRe   = '\bmshta\b|\bwscript\b|\bcscript\b'
$suspectProcs = (Get-ProcSnapshot) | Where-Object {
    $_.CommandLine -match $procInjStrongRe -or $_.CommandLine -match $procInjWeakRe
}
if ($suspectProcs) {
    foreach ($proc in $suspectProcs) {
        Out-Glitch "  [SUSPECT PROCESS]" Red
        $cmd = $proc.CommandLine.Substring(0,[Math]::Min(120,$proc.CommandLine.Length))
        $isStrong = ($proc.CommandLine -match $procInjStrongRe)
        Out-Typewriter "  -> PID:$($proc.ProcessId) | $($proc.Name) | $cmd" "CRIT"
        if ($isStrong) {
            Add-Finding -ID "PROC_INJ_$($proc.ProcessId)" -Phase "PHASE 3" -ThreatType "Process Injection/Fileless" `
                -Severity $SEV_CRITICAL -Description "Suspect process: $($proc.Name) PID:$($proc.ProcessId) | $cmd" `
                -Target "PID:$($proc.ProcessId)" -FixAction "KillProcess" -FixParam $proc.ProcessId -Group "Live Malicious Processes"
        } else {
            Add-Finding -ID "PROC_INJ_$($proc.ProcessId)" -Phase "PHASE 3" -ThreatType "Process Injection/Fileless" `
                -Severity $SEV_POSSIBLE -Description "LOLBin tool running with no further qualifier — could be a legacy HTA/WSH logon or print script (review, not auto-killed): $($proc.Name) PID:$($proc.ProcessId) | $cmd" `
                -Target "PID:$($proc.ProcessId)" -FixAction "Info" -Group "Live Malicious Processes"
        }
    }
} else { Out-Typewriter "  -> [OK] NO INJECTED/MALICIOUS PROCESS SIGNATURES." "GOOD" }

Show-PhaseHeader "PHASE 4" "LOLBIN ABUSE AUDIT (Living-Off-The-Land Binaries)"
Invoke-QuantumBar "SCANNING LOLBIN EXECUTION TRACES" 10 110
$lolbins = @("mshta","wscript","cscript","regsvr32","rundll32","certutil","bitsadmin","msiexec","installutil","regasm","regsvcs","msbuild","cmstp","odbcconf","ieexec","pcalua","presentationhost","infdefaultinstall","diskshadow","esentutl","extrac32","findstr","forfiles","gpscript","hh","makecab","mavinject","msdeploy","msdt","pcwrun","replace","rpcping","syncappvpublishingserver","vbc","winrm","wmic","xwizard","msconfig","fodhelper","eventvwr","sdclt","wusa","csc")
$lolHits = $false
# One WMI enumeration + case-insensitive name lookup instead of one filtered
# Get-WmiObject query per LOLBIN name (was ~46 WMI round-trips per scan).
$lolSet = @{}; foreach ($lb in $lolbins) { $lolSet["$lb.exe"] = $true }
# msiexec/forfiles are routinely and legitimately invoked from AppData/Temp — every third-party
# installer (Chrome, Zoom, Adobe, Slack, ...) stages its MSI under %TEMP% and runs
# `msiexec /i "...\AppData\Local\Temp\...\installer.msi"`, and Temp-cleanup maintenance scripts
# commonly shell `forfiles /p "...AppData\Local\Temp" ...` — a bare AppData/Temp substring match
# on either is a routine healthy-box action, not evidence of abuse (rule #1, caught in adversarial
# FP audit 2026-07-26). For those two specifically, AppData/Temp alone no longer qualifies; every
# other LOLBin in the list keeps the original broader trigger (mshta/wscript/etc. running from a
# staging path IS still comparatively unusual).
$lolAppDataTempOnlyOk = @{ 'msiexec.exe' = $true; 'forfiles.exe' = $true }
$lolStrongRe = 'http|\.js|Base64|scrobj|unc|\\\\'
$lolWeakRe   = 'AppData|Temp'
foreach ($p in (Get-ProcSnapshot)) {
    if (-not $lolSet.ContainsKey($p.Name)) { continue }
    $lolStrongHit = ($p.CommandLine -match $lolStrongRe)
    $lolWeakHit   = (-not $lolAppDataTempOnlyOk.ContainsKey($p.Name)) -and ($p.CommandLine -match $lolWeakRe)
    if ($lolStrongHit -or $lolWeakHit) {
        $lolHits = $true
        Out-Decrypt -Text "LOLBIN: $($p.Name) PID:$($p.ProcessId)" -Prefix "  [LOLBIN] "
        Add-Finding -ID "LOLBIN_$($p.ProcessId)" -Phase "PHASE 4" -ThreatType "LoLBin Abuse" `
            -Severity $SEV_HIGH -Description "LOLBin $($p.Name) used with suspicious args: $($p.CommandLine.Substring(0,[Math]::Min(100,$p.CommandLine.Length)))" `
            -Target "PID:$($p.ProcessId)" -FixAction "KillProcess" -FixParam $p.ProcessId -Group "Live Malicious Processes"
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
# P1 multi-user: this was a bare HKCU: read, so under the elevated technician session it
# inspected the TECHNICIAN's hive and an AmsiEnable=0 planted in the victim's profile was
# invisible — the exact false all-clear this workstream exists to remove. Walked per profile
# now. The ID was the FIXED STRING "AMSI_DISABLED": Add-Finding's de-dupe would have kept only
# the first user's hit, so it now carries the SID. Severity/FixAction are unchanged for a
# normally-mounted hive; only the reg-loaded case is capped (see below).
$zbAmsiOff = 0
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }   # not mounted and loading is off: we could not look
    $zbAmsiKey = "$($zbHive.HivePath)\SOFTWARE\Microsoft\Windows Script\Settings"
    if (-not (Test-Path $zbAmsiKey)) { continue }
    $zbAmsiVal = Get-RegVal -Path $zbAmsiKey -Name "AmsiEnable"
    if ($null -eq $zbAmsiVal -or $zbAmsiVal -ne 0) { continue }
    $zbAmsiOff++
    # A FixParam must never point into a ZB_UH_* mount: remediation runs later, in the server's
    # remediation runspace, long after that mount is gone. Reg-loaded profiles get the operator
    # commands in the description instead (rule #1's own prescription).
    $zbAmsiAct = "DeleteReg"
    $zbAmsiFp  = "$zbAmsiKey|AmsiEnable"
    $zbAmsiExtra = ""
    $zbAmsiSev = $SEV_CRITICAL
    if ($zbHive.Source -eq 'RegLoad') {
        $zbAmsiAct = "Info"
        $zbAmsiFp  = ""
        $zbAmsiSev = $SEV_HIGH   # contract: a reg-loaded (logged-off) hive caps at HIGH + Info
        $zbAmsiExtra = " That profile's hive is only temporarily mounted by this scan, so remove it by hand: reg load HKU\ZBFIX '$($zbHive.NtUserDat)' ; Remove-ItemProperty -Path 'Registry::HKEY_USERS\ZBFIX\SOFTWARE\Microsoft\Windows Script\Settings' -Name AmsiEnable -Force ; reg unload HKU\ZBFIX"
    }
    Out-Typewriter "  -> AMSI DISABLED FOR USER: $($zbHive.User)" "CRIT"
    Add-Finding -ID "AMSI_DISABLED_$(Get-StableId "$($zbHive.Sid)|$zbAmsiKey")" -Phase "PHASE 5" -ThreatType "AMSI Bypass" -Severity $zbAmsiSev `
        -Description "User $($zbHive.User) [hive source: $($zbHive.Source)]: AmsiEnable = 0 in that user's Windows Script Settings — AMSI explicitly disabled for them.$zbAmsiExtra" `
        -Target "[$($zbHive.User)] $zbAmsiKey\AmsiEnable" `
        -FixAction $zbAmsiAct -FixParam $zbAmsiFp -Group "Security Tool Tampering"
}
if ($zbAmsiOff -eq 0) { Out-Typewriter "  -> [OK] AMSI SCRIPT ENGINE ENABLED (ALL READABLE PROFILES)." "GOOD" }
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
    # WS0 wiring: loader/botnet + banking-trojan family names (Pikabot/Bumblebee/QBot/DanaBot/...).
    # Same KillProcess posture as the sibling IOC loops above — these names never occur in
    # legitimate processes, so a hit on a healthy box is impossible by construction.
    foreach ($ldr in $LOADER_PROCS) {
        if ($pn -match [regex]::Escape($ldr)) {
            Out-ThreatBanner "LOADER/BOTNET PROCESS IOC" "$($proc.Name) PID:$($proc.Id)"
            Add-Finding -ID "LOADER_PROC_$($proc.Id)" -Phase "PHASE 6" -ThreatType "Loader/Botnet" -Severity $SEV_CRITICAL `
                -Description "Known malware-loader process: $($proc.Name) (PID $($proc.Id)) matched IOC: $ldr" `
                -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Processes"
            $global:TrojanHits++; $iocHits = $true
        }
    }
    foreach ($bt in $BANKING_TROJAN_PROCS) {
        if ($pn -match [regex]::Escape($bt)) {
            Out-ThreatBanner "BANKING TROJAN PROCESS IOC" "$($proc.Name) PID:$($proc.Id)"
            Add-Finding -ID "BANKTROJ_PROC_$($proc.Id)" -Phase "PHASE 6" -ThreatType "Banking Trojan" -Severity $SEV_CRITICAL `
                -Description "Known banking-trojan process: $($proc.Name) (PID $($proc.Id)) matched IOC: $bt" `
                -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Processes"
            $global:TrojanHits++; $iocHits = $true
        }
    }
}
if (-not $iocHits) { Out-Typewriter "  -> [OK] NO IOC PROCESS MATCHES." "GOOD" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2: BROWSER & TEMP ARTIFACTS
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "BROWSER & TEMPORARY ARTIFACT AUDIT"

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 7" "BROWSER CACHE & SERVICE WORKER AUDIT"
# P1 multi-user: every path here is PER-USER. Under the elevated technician session
# $env:LOCALAPPDATA / $env:APPDATA resolved to the TECHNICIAN's profile, so the victim's
# browsers were never inventoried. Paths are now {TOKEN} templates expanded per profile via
# Get-UserPaths / Expand-UserPathTemplate (folder redirection safe).
# This phase is pure INVENTORY, not a detection: 8 profiles x 7 browsers would be 56 identical
# INFO rows. Operator-approved 2026-07-26: the per-folder detail stays on the console/log and
# the FINDINGS collapse to ONE aggregate row. FixAction is Info — the old INFO+DeleteFile
# pairing hung a destructive action off a finding that reports nothing wrong.
$browserCacheTemplates = @(
    @{P="{LOCALAPPDATA}\Google\Chrome\User Data\Default\Cache\Cache_Data"; L="Chrome Cache"},
    @{P="{LOCALAPPDATA}\Google\Chrome\User Data\Default\Service Worker\CacheStorage"; L="Chrome Service Worker Cache"},
    @{P="{LOCALAPPDATA}\Microsoft\Edge\User Data\Default\Cache\Cache_Data"; L="Edge Cache"},
    @{P="{LOCALAPPDATA}\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage"; L="Edge Service Worker"},
    @{P="{APPDATA}\Mozilla\Firefox\Profiles"; L="Firefox Profiles"},
    @{P="{LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\Default\Cache"; L="Brave Cache"},
    @{P="{APPDATA}\Opera Software\Opera Stable\Cache"; L="Opera Cache"}
)
$zbBcProfiles = 0     # profiles we could actually look at
$zbBcSeen     = 0     # total cache folders found
$zbBcParts    = @()   # per-user summary fragments
$zbBcIdParts  = @()   # SID|label pairs -> deterministic aggregate ID
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    $zbBcProfiles++
    $zbBcHere = @()
    foreach ($bc in $browserCacheTemplates) {
        $zbPath = Expand-UserPathTemplate $bc.P $zbUp
        if (-not $zbPath) { continue }
        if (-not (Test-Path $zbPath)) { continue }
        Out-Typewriter "  -> BROWSER CACHE EXISTS: [$($zbHive.User)] $($bc.L)" "INFO"
        Write-Log "Browser cache present: [$($zbHive.User)] $($bc.L) -> $zbPath"
        $zbBcHere    += $bc.L
        $zbBcIdParts += "$($zbHive.Sid)|$($bc.L)"
        $zbBcSeen++
    }
    if ($zbBcHere.Count -gt 0) {
        $zbBcParts += "$($zbHive.User) ($($zbBcHere.Count) browsers: $($zbBcHere -join ', '))"
    }
}
if ($zbBcSeen -gt 0) {
    Add-Finding -ID "BROWSER_CACHE_INVENTORY_$(Get-StableId ((@($zbBcIdParts) | Sort-Object) -join ';'))" `
        -Phase "PHASE 7" -ThreatType "Browser Artifact" -Severity $SEV_INFO `
        -Description "Browser cache folders present for $($zbBcParts.Count) of $zbBcProfiles profiles: $($zbBcParts -join '; ')." `
        -Target "Browser cache inventory ($($zbBcParts.Count) profile(s))" `
        -FixAction "Info" -Group "Browser Cache / Artifacts"
} else {
    Out-Typewriter "  -> [OK] NO BROWSER CACHE FOLDERS FOUND." "GOOD"
}

Show-PhaseHeader "PHASE 8" "BROWSER EXTENSION SANITIZATION (HEURISTIC)"
# P1 multi-user: every path here is PER-USER, so under the elevated technician session this
# audited the TECHNICIAN's Chrome/Edge/Brave and an adware extension in the VICTIM's profile was
# structurally invisible. Paths are now {TOKEN} templates expanded per profile through
# Get-UserPaths / Expand-UserPathTemplate (folder-redirection safe).
# ID: "EXT_<extension id>" is the Chrome extension GUID, which is IDENTICAL for the same
# extension in every profile — Add-Finding's de-dupe would have kept only the first user's copy.
# It now carries the SID (same shape as the Phase 24 COM migration).
# Grading, both branches and both fix actions are untouched.
$extTemplates = @(
    @{P="{LOCALAPPDATA}\Google\Chrome\User Data\Default\Extensions"; B="Chrome"},
    @{P="{LOCALAPPDATA}\Microsoft\Edge\User Data\Default\Extensions"; B="Edge"},
    @{P="{LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\Default\Extensions"; B="Brave"}
)
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($ep in $extTemplates) {
        $zbExtRoot = Expand-UserPathTemplate $ep.P $zbUp
        if (-not $zbExtRoot) { continue }
        Out-Typewriter "AUDITING $($ep.B) EXTENSIONS: [$($zbHive.User)] $zbExtRoot" "INFO"
        if (-not (Test-Path $zbExtRoot)) { Out-Typewriter "  -> [OK] NO EXTENSION DIRECTORY." "GOOD"; continue }
        # The cosmetic 800 ms interactive pause moved BELOW the existence test: it used to run per
        # browser unconditionally, which on an 8-profile box would be 24 sleeps (19 s) of pure
        # theatre in interactive mode. Servers set NONINTERACTIVE and never paid it either way.
        if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
        $extDirs = Get-ChildItem -Path $zbExtRoot -Directory -ErrorAction SilentlyContinue
        foreach ($ext in $extDirs) {
            $risk = Get-ExtensionRisk -ExtPath $ext.FullName
            if ($risk.Risk -eq "CLEAN") { continue }
            $zbExtId = "EXT_$($ext.Name)_$(Get-StableId "$($zbHive.Sid)")"
            # Only a NAME match against the known adware/hijacker list (CRITICAL) is confident enough to
            # auto-delete an extension. The permission-based heuristics (nativeMessaging / <all_urls> /
            # webRequest -> HIGH/POSSIBLE) fire on MANY legit extensions (password managers, Google Docs
            # Offline, ad blockers), so those are surfaced for REVIEW only (POSSIBLE + Info), never removed.
            if ($risk.Risk -eq "CRITICAL") {
                Out-Typewriter "  -> ☣ CRITICAL — [$($zbHive.User)] $($ep.B) EXT: $($risk.Name) | $($risk.Reason)" "CRIT"
                Add-Finding -ID $zbExtId -Phase "PHASE 8" -ThreatType "Browser Extension/Hijacker" `
                    -Severity $SEV_CRITICAL -Description "User $($zbHive.User): $($ep.B) extension (known adware/hijacker): $($risk.Name) | $($risk.Reason)" `
                    -Target "[$($zbHive.User)] $($ext.FullName)" -FixAction "DeleteFile" -FixParam $ext.FullName `
                    -Group "Browser Extensions ($($ep.B))"
            } else {
                Out-Typewriter "  -> ? POSSIBLE — [$($zbHive.User)] $($ep.B) EXT: $($risk.Name) | $($risk.Reason)" "WARN"
                Add-Finding -ID $zbExtId -Phase "PHASE 8" -ThreatType "Browser Extension/Hijacker" `
                    -Severity $SEV_POSSIBLE -Description "User $($zbHive.User): $($ep.B) extension with broad/powerful permissions ($($risk.Reason)) — review only; many legitimate extensions request these, so it is NOT auto-removed: $($risk.Name)" `
                    -Target "[$($zbHive.User)] $($ext.FullName)" -FixAction "Info" -Group "Browser Extensions ($($ep.B))"
            }
            $global:SpywareHits++
        }
    }
}

Show-PhaseHeader "PHASE 9" "BROWSER HIJACK — SHORTCUT & HOMEPAGE AUDIT"
Out-Typewriter "SCANNING BROWSER SHORTCUTS FOR HIJACKED TARGETS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
# P1 multi-user: Desktop and the Start-Menu Programs folder are PER-USER (a hijacked browser
# shortcut is planted in the profile of whoever clicks it), so the technician's elevated session
# never saw the victim's. $env:PUBLIC\Desktop is MACHINE scope and is enumerated exactly ONCE,
# outside the profile set, so an 8-profile box does not report a public-desktop hijack 8 times.
# ID: "LNK_HIJACK_<flattened filename>" was filename-only and identical for every profile's copy
# of e.g. "Google Chrome.lnk" — Add-Finding's de-dupe silently dropped all but the first. It is
# now derived from SID + full path. Grading and the RunCmd repair are unchanged.
$zbScTargets = @()
$zbScTargets += @{ Path = "$env:PUBLIC\Desktop"; User = 'MACHINE'; Sid = 'MACHINE' }
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($zbR in @($zbUp.Desktop, $zbUp.Programs)) {
        if ($zbR) { $zbScTargets += @{ Path = "$zbR"; User = $zbHive.User; Sid = $zbHive.Sid } }
    }
}
foreach ($zbSt in $zbScTargets) {
    $dir = $zbSt.Path
    if (-not (Test-Path $dir)) { continue }
    $lnks = Get-ChildItem -Path $dir -Filter "*.lnk" -ErrorAction SilentlyContinue
    foreach ($lnk in $lnks) {
        try {
            $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop
            $sc = $shell.CreateShortcut($lnk.FullName)
            if ($sc.Arguments -match "http|--load-extension|--disable-extensions|javascript:|data:") {
                Out-ThreatBanner "BROWSER SHORTCUT HIJACK" "[$($zbSt.User)] $($lnk.Name) | Args: $($sc.Arguments)"
                # A Windows filename may legally contain a single quote, and whoever planted the
                # hijacked shortcut chose this filename — double it so the path cannot break out
                # of the single-quoted string in the generated fix command.
                $lnkPathEsc = "$($lnk.FullName)" -replace "'","''"
                Add-Finding -ID "LNK_HIJACK_$(Get-StableId "$($zbSt.Sid)|$($lnk.FullName)")" -Phase "PHASE 9" -ThreatType "Browser Hijacker" `
                    -Severity $SEV_CRITICAL -Description "User $($zbSt.User): hijacked browser shortcut: $($lnk.Name) | $($sc.Arguments)" `
                    -Target "[$($zbSt.User)] $($lnk.FullName)" -FixAction "RunCmd" -FixParam "`$_sh=New-Object -ComObject WScript.Shell;`$_sc=`$_sh.CreateShortcut('$lnkPathEsc');`$_sc.Arguments='';`$_sc.Save()" -Group "Browser Hijacks"
                $global:SpywareHits++
            }
        } catch {}
    }
}
# Chrome's Preferences file is per-user too. ID "CHROME_HOMEPAGE" was a FIXED STRING, so on a
# multi-profile box the de-dupe would have reported exactly one user's hijacked homepage.
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    $chromePrefs = Expand-UserPathTemplate "{LOCALAPPDATA}\Google\Chrome\User Data\Default\Preferences" $zbUp
    if (-not $chromePrefs) { continue }
    if (Test-Path $chromePrefs) {
        $prefs = Get-Content $chromePrefs -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($prefs.homepage -and $prefs.homepage -notmatch "^(https?://(www\.)?google\.|about:blank|newtab)") {
            Out-Typewriter "  -> HIJACKED CHROME HOMEPAGE [$($zbHive.User)]: $($prefs.homepage)" "CRIT"
            Add-Finding -ID "CHROME_HOMEPAGE_$(Get-StableId "$($zbHive.Sid)")" -Phase "PHASE 9" -ThreatType "Browser Hijacker" -Severity $SEV_HIGH `
                -Description "User $($zbHive.User): suspicious Chrome homepage: $($prefs.homepage)" -Target "[$($zbHive.User)] $chromePrefs" `
                -FixAction "Info" -Group "Browser Hijacks"
            $global:SpywareHits++
        }
    }
}
Out-Typewriter "  -> BROWSER HIJACK AUDIT COMPLETE." "VER"

}   # end QUICK-skip block
Show-PhaseHeader "PHASE 10" "TEMP / DOWNLOAD DIRECTORY ANOMALY SWEEP"
# P1 multi-user. Four of these six roots are PER-USER, so under the elevated technician session
# this phase swept the TECHNICIAN's Temp/Downloads/INetCache and reported the victim's profile
# clean — proven on this box: two files planted in a second profile surfaced only as POSSIBLE
# by-catch from an unrelated worm phase instead of HIGH from here.
#
# $env:WINDIR\Temp and $env:PUBLIC\Downloads are MACHINE scope and are added exactly ONCE,
# OUTSIDE the profile loop and tagged [MACHINE]. Left inside, a 2-profile box would report every
# Windows-TEMP hit twice and an 8-profile box eight times.
#
# NOTHING about the grading, the allowlist gate, the ordering of the benign-path test, the shared
# signature budget or the masquerade sniff changes here — this is a plumbing change to a phase
# that is already the single biggest FP contributor in the engine (35 of this box's ~42 raw
# auto-destructive findings, essentially all transient %TEMP% harness debris). Note in particular
# that Test-BenignPath is STRUCTURALLY INCAPABLE of downgrading anything in this phase
# ($global:ALLOW_VETO_RE vetoes every allowlist match found under \Temp\ or \Downloads\, which is
# this phase's entire scope) — that is why the narrow, component-anchored, downgrade-only
# Test-ZbP10BenignPath gate exists at the top of this module. Do not "route through
# Test-BenignPath" here expecting it to help; it will silently do nothing.
#
# The severity gate deliberately still tests the RESOLVED PATH ($td.P -match "Temp|INetCache"),
# not the label, so it stays byte-identical to the pre-P1 logic. A profile whose Temp is
# redirected somewhere without "Temp" in its name therefore grades POSSIBLE instead of HIGH —
# i.e. it fails toward LESS auto-destruction, which is the correct direction.
$targetDirs = @()
foreach ($zbHive in @(@(Get-UserHives) | Sort-Object -Property Sid)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($zbTd in @(
        ,@($zbUp.Temp,         'User TEMP')
        ,@($(if ($zbUp.LocalAppData) { Join-Path $zbUp.LocalAppData 'Temp' } else { $null }), 'LocalAppData TEMP')
        ,@($zbUp.Downloads,    'User Downloads')
        ,@($zbUp.INetCache,    'INetCache')
    )) {
        if (-not $zbTd[0]) { continue }
        $targetDirs += @{ P = "$($zbTd[0])"; L = $zbTd[1]; U = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
    }
}
# MACHINE-wide roots: added ONCE, never inside the profile loop.
$targetDirs += @{ P = "$env:WINDIR\Temp";       L = "Windows TEMP";     U = 'MACHINE'; Sid = 'MACHINE' }
$targetDirs += @{ P = "$env:PUBLIC\Downloads";  L = "Public Downloads"; U = 'MACHINE'; Sid = 'MACHINE' }
# .com added 2026-07-26: it is a genuinely executable Windows extension and its absence meant even
# EICAR (written as eicar.com) sailed through this sweep untouched. NOTE this list is now only the
# CHEAP first pass — files it misses are still content-sniffed for a PE header below, so a renamed
# payload no longer escapes just because its extension is not enumerated here.
$malExt = @(".exe",".com",".bat",".cmd",".ps1",".vbs",".js",".hta",".wsf",".dll",".sys",".scr",".pif",".cpl",".jar")
# Bounded sig loop — Get-AuthSig can block on online cert-revocation (CRL/OCSP), and with
# -Hours 0 the temp/download/INetCache dirs can hold thousands of cached executables. Cap
# total checks + wall-clock across ALL target dirs so a slow/offline revocation responder
# can't hang the phase for hours (this was the real DEEP-mode hang; see Phase 98).
$sigSeen = 0
$sigSw   = [System.Diagnostics.Stopwatch]::StartNew()
$sigBudgetHit = $false
# Masquerade-sniff budget. Declared OUT HERE, not inside the per-directory loop: a per-directory
# budget would be 6 dirs x (2000 files / 30s) = 12,000 sniffs and up to 3 MINUTES of added wall
# clock. Measured cost is ~27ms/file (Defender scans every File.Open; the 8-byte read is free),
# so this must be shared across all target dirs exactly like $sigSeen/$sigSw above.
$masqSeen = 0
$masqSw   = [System.Diagnostics.Stopwatch]::StartNew()
$masqBudgetHit = $false
# On a default Windows profile $env:TEMP and "$env:LOCALAPPDATA\Temp" are the SAME directory, so
# the sweep walked it twice and spent HALF the shared SIG_AUDIT budget re-verifying files it had
# already graded — which is why a TEMP full of debris meant Downloads and INetCache were never
# reached at all (measured on this box 2026-07-26). Skip a target whose resolved path was
# already covered.
$tdSeen = @{}
foreach ($td in $targetDirs) {
    if ($sigBudgetHit) { break }
    Out-Typewriter "SCANNING: [$($td.U)] $($td.L)" "INFO"
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
    if (-not (Test-Path $td.P)) { Out-Typewriter "  -> [OK] ABSENT." "GOOD"; continue }
    $tdKey = "$($td.P)"
    try { $tdKey = (Convert-Path -LiteralPath $td.P) } catch {}
    $tdKey = "$tdKey".TrimEnd('\').ToLowerInvariant()
    if ($tdSeen.ContainsKey($tdKey)) { Out-Typewriter "  -> [OK] SAME DIRECTORY AS AN EARLIER TARGET — ALREADY SWEPT." "GOOD"; continue }
    $tdSeen[$tdKey] = $true
    $recentFiles = Get-ScanFiles -Path $td.P -TimeScoped
    if ($recentFiles.Count -eq 0) { Out-Typewriter "  -> [OK] CLEAN." "GOOD"; continue }
    # Group into executable vs other
    $exeFiles   = $recentFiles | Where-Object { $malExt -contains $_.Extension.ToLower() }
    $otherFiles = $recentFiles | Where-Object { $malExt -notcontains $_.Extension.ToLower() }
    if ($exeFiles.Count -gt 0) {
        $exeGroup = "[$($td.U)] $($td.L) — Executables ($($exeFiles.Count) files)"
        $benignGroup = "[$($td.U)] $($td.L) — Allowlisted tool/runtime caches"
        $benignSeen = 0
        foreach ($f in $exeFiles) {
            # Benign-path gate FIRST, before the signature budget is spent (2026-07-26, user-
            # approved). Two reasons for the ordering: an allowlisted file is graded INFO
            # regardless of its signature, so the Authenticode call is pure waste; and with 500+
            # tool-cache files in %TEMP% the 150-file SIG_AUDIT budget was being burned entirely
            # on debris, which then set $sigBudgetHit and aborted the sweep of the REMAINING
            # target directories before Downloads/INetCache were ever reached.
            if (Test-ZbP10BenignPath $f.FullName) {
                $benignSeen++
                Add-Finding -ID "TEMPEXEOK_$(Get-StableId $f.FullName)" -Phase "PHASE 10" -ThreatType "Suspicious File" `
                    -Severity $SEV_INFO -Description "User $($td.U): executable-extension file inside a known tool/runtime cache tree in $($td.L) — reported, but downgraded out of the auto-selected set by the Phase 10 benign-path allowlist (still reviewable; the content-based PE-masquerade sniff below is NOT gated on this): $($f.FullName)" `
                    -Target "[$($td.U)] $($f.FullName)" -FixAction "Info" -Group $benignGroup
                continue
            }
            if ($sigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
                $sigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
                $sigBudgetHit = $true; break
            }
            $sigSeen++
            $asig = Get-AuthSig $f.FullName
            $isMalicious = ($asig.Status -ne "Valid") -and ($td.P -match "Temp|INetCache")
            $sev = if ($isMalicious) { $SEV_HIGH } else { $SEV_POSSIBLE }
            # ID was "TEMPEXE_<flattened filename>" — filename-only, so the SAME debris filename in
            # two profiles collapsed to ONE finding through Add-Finding's de-dupe and the second
            # user's copy was silently dropped. Now keyed on SID + full path.
            Add-Finding -ID "TEMPEXE_$(Get-StableId "$($td.Sid)|$($f.FullName)")" -Phase "PHASE 10" -ThreatType "Suspicious File" `
                -Severity $sev -Description "User $($td.U): $(if($isMalicious){'unsigned executable'} else {'executable'}) in $($td.L): $($f.Name)" `
                -Target "[$($td.U)] $($f.FullName)" -FixAction "DeleteFile" -FixParam $f.FullName -Group $exeGroup
        }
        Out-Typewriter "  -> FLAGGED $($exeFiles.Count - $benignSeen) EXECUTABLES IN [$($td.U)] $($td.L)$(if ($benignSeen) { " ($benignSeen allowlisted tool-cache files downgraded to INFO)" })." "WARN"
    }
    if ($otherFiles.Count -gt 0) {
        Out-Typewriter "  -> $($otherFiles.Count) NON-EXECUTABLE FILES IN [$($td.U)] $($td.L) — WITHIN TIME SCOPE." "DATA"
        # ...but "non-executable" was decided purely by FILENAME. Sniff the actual bytes: a real PE
        # binary wearing a non-executable extension in a temp/download/cache dir is masquerading.
        # Before this, such a file was counted in the line above and then dropped on the floor —
        # a live sandbox run had a real banking trojan sitting in Downloads as "*.exe.vir" and the
        # engine reported it only as one of "8 non-executable files" (2026-07-26).
        # HIGH so it cannot be missed, FixAction Info so no auto-select can ever act on it
        # (rule #1) — installers do legitimately ship payload blobs with odd extensions.
        # Bounded like every other bulk file loop in this phase; 8 bytes read per file. The budget
        # is PHASE-wide (declared above the target-dir loop), not per-directory.
        foreach ($of in $otherFiles) {
            if ($masqSeen -ge 2000 -or $masqSw.Elapsed.TotalSeconds -ge 30) { $masqBudgetHit = $true; break }
            if ($of.Length -lt 64 -or $of.Length -ge 100MB) { continue }
            $masqSeen++
            if (Test-IsPeFile $of.FullName) {
                Add-Finding -ID "MASQPE_$(Get-StableId $of.FullName)" -Phase "PHASE 10" `
                    -ThreatType "Masquerading Executable" -Severity $SEV_HIGH `
                    -Description "User $($td.U): file is a real Windows PE executable but carries a non-executable extension ('$($of.Extension)') in $($td.L): $($of.FullName) — classic rename-to-evade delivery. Review before acting." `
                    -Target "[$($td.U)] $($of.FullName)" -FixAction "Info" -Group "Masquerading Executables"
                $global:TrojanHits++
            }
        }
    }
}
$sigSw.Stop()
$masqSw.Stop()
if ($sigBudgetHit) {
    Out-Typewriter ("  -> [INFO] TEMP-EXE SIG BUDGET REACHED ({0} binaries / {1}s) — partial scan." -f $sigSeen, [Math]::Round($sigSw.Elapsed.TotalSeconds,1)) "WARN"
}
if ($masqBudgetHit) {
    Out-Typewriter ("  -> [INFO] MASQUERADE SNIFF BUDGET REACHED ({0} files / {1}s) — partial scan." -f $masqSeen, [Math]::Round($masqSw.Elapsed.TotalSeconds,1)) "WARN"
}
if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
# WS7: malicious .lnk downloader payload detection. Given its own fractional phase (10.5) and
# placed inside the non-QUICK wrap — Phase 10 itself is a member of the 30-phase QUICK set, and
# this adds real new work (a WScript.Shell COM object per candidate .lnk) plus new FP surface, so
# per the "new detections get a fractional phase inside an existing non-QUICK block" rule it must
# NOT silently ride along inside QUICK's Phase 10 body. Downloads/Desktop/Startup are walked
# because that is where a downloader lure/persistence .lnk lands. Resolves target+args via the
# same WScript.Shell COM approach Phase 9 uses for browser-shortcut hijacks, then requires the
# actual download/execute CRADLE shape (encoded command, DownloadString/DownloadFile/IEX, or a
# LOLBIN-with-URL invocation) — a bare "-windowstyle hidden" is a routine flag for countless
# benign silent background launchers (vendor updaters, tray helpers, IT maintenance scripts) and
# is deliberately NOT sufficient on its own to fire this. HIGH + Info (never auto-deleted — the
# user may have just legitimately clicked something and this needs a human look first).
Show-PhaseHeader "PHASE 10.5" "MALICIOUS LNK/SHORTCUT DOWNLOADER SWEEP"
Out-Typewriter "SCANNING SHORTCUTS FOR DOWNLOADER/LOADER PAYLOADS..." "HUNT"
# STRONG/WEAK split (2026-07-26 adversarial FP audit, same pattern as Phase 3/29): the
# mshta/wscript/cscript+URL combo is a rare, high-signal shape and stays HIGH. A bare
# -EncodedCommand blob or DownloadString/IEX is NOT — vendors routinely ship shortcuts that
# launch `powershell.exe -EncodedCommand <blob>` specifically to dodge .lnk argument-quoting
# problems (not to hide malice), and the official Chocolatey/Scoop bootstrap one-liners (a
# real MSP-technician "save the install command as a shortcut" workflow) are literally
# `iex (New-Object Net.WebClient).DownloadString('https://...')` from vendor documentation —
# both would have auto-fired HIGH with zero corroboration otherwise.
$lnkDownloaderStrongRe = '(?i)(mshta|wscript|cscript)(\.exe)?\b[^\r\n]*https?://'
$lnkDownloaderWeakRe   = '(?i)(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,})|(DownloadString|DownloadFile|\bIEX\b|Invoke-Expression)'
# P1 multi-user: Downloads / Desktop / the per-user Startup folder are exactly where a downloader
# lure or persistence .lnk lands in the VICTIM's profile, and all three resolved to the
# technician's under RunAs. Collected across every reachable profile and passed to a SINGLE
# Get-ScanFiles call — its MaxFiles/DeadlineSecs are PER CALL, so a per-profile loop would
# multiply this phase's wall clock by the profile count. $env:PUBLIC\Desktop and the all-users
# Startup folder are MACHINE scope and are added exactly once.
$lnkDirs = @(@(Get-ZbUserRootsM1 -Kind @('Downloads','Desktop','Startup')) + @(
    "$env:PUBLIC\Desktop",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
) | Where-Object { $_ } | Select-Object -Unique)
$lnkFiles = (Get-ScanFiles -Path $lnkDirs -Filter '*.lnk' -TimeScoped)
$lnkFound = $false
foreach ($lf in $lnkFiles) {
    # Attribute the file back to the profile it came out of (longest-prefix match), so the
    # operator can see WHOSE shortcut this is. The ID is already full-path derived, so it gains
    # per-user uniqueness for free now that the path names a different user.
    $zbLnkOwn = Get-ZbOwnerM1 $lf.FullName
    try {
        $lnkShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
        $lnkSc = $lnkShell.CreateShortcut($lf.FullName)
        $lnkBlob = "$($lnkSc.TargetPath) $($lnkSc.Arguments)"
        $lnkStrong = ($lnkBlob -match $lnkDownloaderStrongRe)
        $lnkWeak   = ($lnkBlob -match $lnkDownloaderWeakRe)
        if ($lnkStrong -or $lnkWeak) {
            $lnkFound = $true
            Out-ThreatBanner "MALICIOUS LNK DOWNLOADER" "[$($zbLnkOwn.User)] $($lf.Name) | $lnkBlob"
            if ($lnkStrong) {
                Add-Finding -ID "LNKDL_$(Get-StableId $lf.FullName)" -Phase "PHASE 10.5" -ThreatType "Malicious LNK/Downloader" `
                    -Severity $SEV_HIGH -Description "User $($zbLnkOwn.User): shortcut resolves to an mshta/wscript/cscript-with-URL download cradle (review — the user may have just clicked something legitimate, so this is not auto-deleted): $($lf.Name) -> $lnkBlob" `
                    -Target "[$($zbLnkOwn.User)] $($lf.FullName)" -FixAction "Info" -Group "Malicious LNK Payloads"
            } else {
                Add-Finding -ID "LNKDL_$(Get-StableId $lf.FullName)" -Phase "PHASE 10.5" -ThreatType "Malicious LNK/Downloader" `
                    -Severity $SEV_POSSIBLE -Description "User $($zbLnkOwn.User): shortcut resolves to an encoded-command / DownloadString-IEX pattern — common in both malicious downloaders AND legitimate vendor/RMM shortcuts and official install one-liners (Chocolatey/Scoop), so this alone is weak evidence: $($lf.Name) -> $lnkBlob" `
                    -Target "[$($zbLnkOwn.User)] $($lf.FullName)" -FixAction "Info" -Group "Malicious LNK Payloads"
            }
        }
    } catch {}
}
if (-not $lnkFound) { Out-Typewriter "  -> [OK] NO MALICIOUS LNK DOWNLOADER PAYLOADS." "GOOD" }

Show-PhaseHeader "PHASE 10.6" "NPM/PIP POSTINSTALL SUPPLY-CHAIN EXFIL SWEEP"
Out-Typewriter "CHECKING FRESHLY-MODIFIED package.json FOR POSTINSTALL EXFIL CRADLES..." "HUNT"
# WS7: single highest-FP-risk item in this batch — deliberately the NARROWEST possible trigger.
# Only package.json files MODIFIED within the current scan time window (a fresh `npm install`,
# not a walk of the whole node_modules tree every run — Test-InScope on LastWriteTime does
# that). Within an in-scope file, only the literal scripts.postinstall / scripts.preinstall
# string values are checked (never the rest of the manifest) for a download command aimed at a
# raw IP or a host NOT on the known-benign install-time host allowlist (electron-builder,
# playwright, puppeteer and node-gyp all legitimately fetch prebuilt binaries at install time).
$npmDownloadCmdRe   = '(?i)\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b'
$npmDownloadTargetRe = '(?i)(https?://)([^\s"''\\]+)'
$npmRawIpRe         = '^(\d{1,3}\.){3}\d{1,3}([:/]|$)'
# P1 multi-user: all four roots were the technician's profile. Every reachable profile's roots go
# into ONE Get-ScanFiles call (its MaxFiles/DeadlineSecs are PER CALL, so the total walk budget is
# shared across profiles rather than multiplied by them). No machine-wide root belongs here — a
# freshly-installed package.json is by definition a per-user artifact.
$npmPkgFiles = (Get-ScanFiles -Path @(Get-ZbUserRootsM1 -Kind @('Profile','Documents','Desktop','Downloads')) -Filter 'package.json' -TimeScoped)
$npmHits = 0
foreach ($pf in $npmPkgFiles) {
    $zbNpmOwn = Get-ZbOwnerM1 $pf.FullName
    # node_modules/*/package.json is dependency metadata, not the project being installed — the
    # SCAN_PRUNE_DIRS list already prunes node_modules from the walk, but guard explicitly in
    # case a caller ever widens PruneDirs, since THIS is the exact tree this phase must not scan.
    if ($pf.FullName -match '\\node_modules\\') { continue }
    $pkgJson = $null
    try { $pkgJson = Get-Content -LiteralPath $pf.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { continue }
    foreach ($scriptKey in @('postinstall','preinstall')) {
        $scriptVal = $null
        if ($pkgJson.scripts -and $pkgJson.scripts.PSObject.Properties[$scriptKey]) { $scriptVal = "$($pkgJson.scripts.$scriptKey)" }
        if (-not $scriptVal -or $scriptVal -notmatch $npmDownloadCmdRe) { continue }
        $urlMatch = [regex]::Match($scriptVal, $npmDownloadTargetRe)
        if (-not $urlMatch.Success) { continue }
        $urlHost = ($urlMatch.Groups[2].Value -split '[/:]')[0]
        if (-not $urlHost) { continue }
        $isRawIp = ($urlHost -match $npmRawIpRe)
        $isTrusted = (-not $isRawIp) -and ($urlHost -match $NPM_POSTINSTALL_TRUSTED_RE)
        if ($isTrusted) { continue }
        $npmHits++
        Out-Decrypt -Text "[$($zbNpmOwn.User)] $($pf.FullName) [$scriptKey] -> $urlHost" -Prefix "  [NPM POSTINSTALL EXFIL] "
        Add-Finding -ID "NPMPOST_$(Get-StableId "$($pf.FullName)|$scriptKey")" -Phase "PHASE 10.6" -ThreatType "Supply Chain Compromise" `
            -Severity $SEV_POSSIBLE -Description "User $($zbNpmOwn.User): package.json $scriptKey runs a download command against $(if ($isRawIp) { 'a raw IP address' } else { "an untrusted host ($urlHost)" }) — review before running npm/pip install again: $($pf.FullName) | $scriptKey = $scriptVal" `
            -Target "[$($zbNpmOwn.User)] $($pf.FullName)" -FixAction "Info" -Group "Supply Chain / Postinstall Exfil"
    }
}
if ($npmHits -eq 0) { Out-Typewriter "  -> [OK] NO SUSPICIOUS NPM/PIP POSTINSTALL SCRIPTS." "GOOD" }

Show-PhaseHeader "PHASE 11" "RECENT ITEMS / JUMP LIST EXECUTION EVIDENCE"
# EVIDENCE_ENGINE_PLAN P4 / A13. This phase used to open the Recent + JumpList folders, COUNT
# the files, and emit one INFO finding whose ONLY action was a RunCmd that DELETED them — an
# incident-response tool shipping a one-click evidence-destruction button. Those .lnk files
# carry TargetPath, Arguments and WorkingDirectory, and they SURVIVE deletion of the file they
# point at, which makes Recent one of the few places "this executable ran and is now gone" is
# still recoverable after a payload self-deletes or a tech "cleans" the box.
#
# The deletion action is gone. The shortcuts are now PARSED, through the same WScript.Shell
# resolver Phase 10.5 uses (factored into Get-ZbLnkInfo at the top of this module).
#
# Grading — every outcome is non-destructive, and nothing here can be auto-selected:
#   * executable/script target, MISSING from disk, in a user-writable path -> POSSIBLE + Info.
#     "It ran, then it was deleted" is real evidence, but an uninstalled or portable app looks
#     identical, so it is corroboration, never a verdict.
#   * executable/script target that is still present -> INFO + Info (context for the timeline).
#   * ordinary documents -> not itemised; counted in the summary finding.
#   * target on a UNC path or a volume that is not attached -> counted as UNCHECKABLE, never
#     as "missing" (Get-ZbPathPresence refuses to Test-Path those; see its comment).
# Bounded by a deadline + count budget: Recent can hold thousands of entries.
# P1 multi-user: the Recent folder is the single most per-user artifact in Windows, and under the
# elevated technician session all three paths were the TECHNICIAN's — i.e. this evidence phase was
# reading the wrong person's execution history entirely. Walked per profile now, via
# Get-UserPaths' Recent property (redirection-aware; the jump-list containers are its children).
# Nothing machine-wide belongs here. Per-profile isolation is used rather than one Get-ScanFiles
# call because this site does not use Get-ScanFiles at all — it is a bounded Get-ChildItem over a
# single folder, and the parse budget below stays PHASE-wide (shared across profiles), so the
# wall-clock cost does NOT multiply by the profile count.
$zbRecentTargets = @()
foreach ($zbHive in @(@(Get-UserHives) | Sort-Object -Property Sid)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp -or -not $zbUp.Recent) { continue }
    foreach ($zbSub in @('', 'AutomaticDestinations', 'CustomDestinations')) {
        $zbRp = if ($zbSub) { Join-Path $zbUp.Recent $zbSub } else { "$($zbUp.Recent)" }
        $zbRecentTargets += @{ Path = $zbRp; User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
    }
}
# Executable/script extensions worth escalating on. These are ordinary Windows extensions, not
# malware signatures, so they stay inline (no AMSI exposure).
$zbRecentExecRe   = '\.(exe|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|scr|pif|cpl|msi|msp|jar|dll)$'
# Staging paths where a deleted executable is actually interesting. Anchored to whole path
# COMPONENTS (never bare substrings — a bare 'Desktop' once matched 'WhatsAppDesktop' under
# WindowsApps and got healthy signed apps killed). Desktop/Documents are deliberately NOT here:
# deleting an installer off your own Desktop is the single most ordinary thing a user does.
$zbRecentStagingRe = '\\(AppData|Temp|Downloads|Public)\\'
$zbRecentParsed = 0; $zbRecentExec = 0; $zbRecentGone = 0; $zbRecentUncheckable = 0; $zbRecentTotal = 0
$zbRecentSw = [System.Diagnostics.Stopwatch]::StartNew()
$zbRecentBudgetHit = $false
$zbRecentUsers = @{}
foreach ($zbRt in $zbRecentTargets) {
    if ($zbRecentBudgetHit) { break }
    $rp = $zbRt.Path
    if (-not (Test-Path -LiteralPath $rp)) { continue }
    $ri = @(Get-ChildItem -LiteralPath $rp -File -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime })
    $zbRecentTotal += $ri.Count
    if ($ri.Count -gt 0) { $zbRecentUsers["$($zbRt.User)"] = $true }
    if ($ri.Count -eq 0) { Out-Typewriter "  -> [OK] NO IN-SCOPE RECENT ITEMS: [$($zbRt.User)] $rp" "GOOD"; continue }
    Out-Typewriter "  -> $($ri.Count) RECENT ITEMS IN: [$($zbRt.User)] $rp" "INFO"
    foreach ($zbLnk in $ri) {
        if ($zbRecentParsed -ge 1500 -or $zbRecentSw.Elapsed.TotalSeconds -ge 25) { $zbRecentBudgetHit = $true; break }
        # Only genuine .lnk shortcuts resolve through WScript.Shell. The jump-list containers
        # (*.automaticDestinations-ms / *.customDestinations-ms) are OLE compound files —
        # parsing those is Tier B in EVIDENCE_ENGINE_PLAN and explicitly out of scope here.
        if ("$($zbLnk.Extension)" -notmatch '^\.lnk$') { continue }
        $zbRecentParsed++
        $zbInfo = Get-ZbLnkInfo $zbLnk.FullName
        if ($null -eq $zbInfo) { continue }
        $zbTgt = "$($zbInfo.TargetPath)"
        if (-not $zbTgt) { continue }
        $zbPresence = Get-ZbPathPresence $zbTgt
        if ($zbPresence -eq 'unknown') { $zbRecentUncheckable++ }
        if ("$zbTgt" -notmatch $zbRecentExecRe) { continue }
        $zbRecentExec++
        $zbLnkDesc = "Recent-items shortcut '$($zbLnk.Name)' (last used $($zbLnk.LastWriteTime)) -> target: $zbTgt | args: $($zbInfo.Arguments) | workdir: $($zbInfo.WorkingDir) | target on disk: $zbPresence"
        if ($zbPresence -eq 'missing' -and $zbTgt -match $zbRecentStagingRe) {
            $zbRecentGone++
            Out-Decrypt -Text "[$($zbRt.User)] $($zbLnk.Name) -> $zbTgt" -Prefix "  [EXECUTED, NOW DELETED] "
            # ID was derived from the TARGET path only. Two users who both ran the same now-deleted
            # binary would collapse into one finding via Add-Finding's de-dupe, hiding the second
            # user's execution evidence entirely — so the SID is now part of the key.
            Add-Finding -ID "RECENTGONE_$(Get-StableId "$($zbRt.Sid)|$zbTgt")" -Phase "PHASE 11" -ThreatType "Execution Trace" `
                -Severity $SEV_POSSIBLE -Description "User $($zbRt.User): EXECUTION EVIDENCE — an executable/script in a user-writable staging path was opened from Explorer and is NO LONGER on disk. This survives the payload, but an uninstalled or portable app produces the identical artifact, so corroborate before acting. Nothing is deleted by this finding. $zbLnkDesc" `
                -Target "[$($zbRt.User)] $($zbLnk.FullName)" -FixAction "Info" -Group "Recent Items — Execution Evidence"
        } else {
            Add-Finding -ID "RECENTEXE_$(Get-StableId $zbLnk.FullName)" -Phase "PHASE 11" -ThreatType "Execution Trace" `
                -Severity $SEV_INFO -Description "User $($zbRt.User): executable/script opened from Explorer (timeline context). $zbLnkDesc" `
                -Target "[$($zbRt.User)] $($zbLnk.FullName)" -FixAction "Info" -Group "Recent Items — Executable Targets"
        }
    }
}
$zbRecentSw.Stop()
if ($zbRecentTotal -gt 0) {
    # ONE aggregate row across every profile (the same operator-approved collapse Phase 7 uses for
    # its browser-cache inventory) — a per-profile summary would be N identical INFO rows.
    Add-Finding -ID "RECENT_EVIDENCE_SUMMARY" -Phase "PHASE 11" -ThreatType "Browser/File Artifact" -Severity $SEV_INFO `
        -Description "Recent-items evidence across $($zbRecentUsers.Count) profile(s) ($((@($zbRecentUsers.Keys) | Sort-Object) -join ', ')): $zbRecentTotal in-scope item(s), $zbRecentParsed .lnk shortcut(s) parsed, $zbRecentExec with executable/script targets, $zbRecentGone whose target is missing from a user-writable staging path, $zbRecentUncheckable whose target could not be checked (UNC path or a volume that is not attached — often removable media). These artifacts are EVIDENCE and are deliberately never deleted by this tool.$(if ($zbRecentBudgetHit) { ' PARTIAL RESULT — parse budget reached; more shortcuts remain unparsed.' })" `
        -Target "Recent-items evidence ($($zbRecentUsers.Count) profile(s))" -FixAction "Info" -Group "Recent Items — Execution Evidence"
}
if ($zbRecentGone -eq 0) { Out-Typewriter "  -> [OK] NO 'RAN THEN DELETED' EXECUTABLE TARGETS IN RECENT ITEMS." "GOOD" }

# EVIDENCE_ENGINE_PLAN P5. The old title was "PREFETCH & SHIMCACHE ARTIFACT AUDIT" but the body
# only ever read Prefetch — nothing in the engine parses the AppCompatCache. ShimCache binary
# parsing is Tier B in the plan and explicitly out of scope, so the TITLE is corrected rather
# than the check faked; a phase must never advertise a check it did not run.
Show-PhaseHeader "PHASE 12" "PREFETCH EXECUTION-TRACE AUDIT"
Out-Typewriter "SCANNING PREFETCH FOR EXECUTION TRACES..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1200 }
# P5: two alternatives in the old regex COULD NOT MATCH — 'RUNDLL32.*APPDATA' and
# 'POWERSHELL.*-ENC'. A prefetch filename is NAME.EXE-<8 hex>.pf: it carries no path and no
# command line, so nothing containing APPDATA or -ENC can ever appear in one. They are DELETED
# rather than "repaired" to bare RUNDLL32|POWERSHELL, because rundll32 and powershell run on
# every healthy Windows box (this scanner is itself a powershell.exe execution) — a bare name
# match would be a guaranteed false positive, not a detection. These are Microsoft binary
# names, not malware signatures, so the list stays inline: pushing it to data would add a
# silent-total-detection-loss failure mode if the key were ever missing.
$zbPfLolbinRe = 'WSCRIPT|CSCRIPT|MSHTA|MSIEXEC|INSTALLUTIL|REGASM|CERTUTIL|BITSADMIN'
if (Test-Path -LiteralPath "$env:WINDIR\Prefetch") {
    $zbPfAll = @(Get-ChildItem -LiteralPath "$env:WINDIR\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue)
    if ($zbPfAll.Count -eq 0) {
        # Never print a clean result for a check that could not have fired. An empty/unreadable
        # Prefetch folder means either the prefetcher is disabled or purged (an anti-forensic
        # signal in its own right) or this process cannot read it — not "no executions".
        Out-Typewriter "  -> PREFETCH DIRECTORY PRESENT BUT NO .pf FILES READABLE — RESULT IS NOT 'CLEAN'." "WARN"
        Add-Finding -ID "PREFETCH_UNAVAILABLE" -Phase "PHASE 12" -ThreatType "Execution Trace" `
            -Severity $SEV_INFO -Description "Prefetch directory exists but contains no readable .pf files. Execution-trace evidence for this box is UNAVAILABLE, not clean: the prefetcher may be disabled (EnablePrefetcher=0, common on servers), the folder may have been purged (anti-forensic), or this process may lack read access. Treat any 'no execution trace' conclusion for this scan as unproven." `
            -Target "$env:WINDIR\Prefetch" -FixAction "Info" -Group "Execution Artifacts"
    } else {
        $zbPfScoped = @($zbPfAll | Where-Object { Test-InScope $_.LastWriteTime })
        # ── (1) LOLBIN execution traces (existing detection, dead alternatives removed) ──────
        $malPf = @($zbPfScoped | Where-Object { $_.Name -match $zbPfLolbinRe })
        if ($malPf.Count -gt 0) {
            foreach ($pf in $malPf) {
                Out-Decrypt -Text $pf.Name -Prefix "  [PREFETCH HIT] "
                # LOLBIN prefetch only proves the binary ran at some point — legit on most machines — so
                # this is corroborating evidence, not a standalone HIGH. POSSIBLE (shown, not auto-selected).
                Add-Finding -ID "PREFETCH_$($pf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 12" -ThreatType "Execution Trace" `
                    -Severity $SEV_POSSIBLE -Description "LOLBIN execution trace in prefetch: $($pf.Name) — last execution approx $($pf.LastWriteTime) (corroborating evidence — verify context)" `
                    -Target $pf.FullName -FixAction "Info" -Group "Execution Artifacts"
            }
            Out-Typewriter "  -> PREFETCH ARTIFACTS LOGGED. PRESERVING AS EVIDENCE." "WARN"
        } else { Out-Typewriter "  -> [OK] NO SUSPICIOUS LOLBIN PREFETCH ENTRIES." "GOOD" }

        # ── (2) A14: prefetch <-> filesystem correlation ("it ran, and it is now gone") ─────
        # No binary parsing needed: the .pf FILENAME carries the image name and LastWriteTime is
        # approximately the last execution. If that image is nowhere on disk, something executed
        # here that no longer exists. The caveat is large and stays in every finding: uninstalled
        # software, portable apps run from removable media, installer stubs and per-user tools all
        # produce this legitimately. Graded INFO + Info — evidence for the timeline, never a
        # verdict, never auto-selectable.
        #
        # DEEP+ ONLY ($PhasePlan.Advanced). Establishing "nowhere on disk" honestly needs a full
        # executable index of System32/SysWOW64/Program Files x2/ProgramData/the user profile,
        # measured on this box at ~40s through Get-ScanFiles. That is a real cost, so it is
        # confined to the modes that already budget for deep work rather than being paid on every
        # FULL scan. QUICK never reaches this phase at all (Phase 12 is inside the non-QUICK wrap).
        $zbPfCand = New-Object System.Collections.Generic.List[object]
        if (-not $PhasePlan.Advanced) {
            Out-Typewriter "  -> PREFETCH/FILESYSTEM CORRELATION SKIPPED (DEEP+ ONLY — needs a full executable index)." "INFO"
        } else {
        if ($null -eq $global:ZB_PROCNAME_SET) {
            $global:ZB_PROCNAME_SET = @{}
            foreach ($zbSp in (Get-ProcSnapshot)) { $global:ZB_PROCNAME_SET["$($zbSp.Name)".ToLower()] = $true }
        }
        # Explicit [regex]::Match rather than -match/$Matches: $Matches is an AUTOMATIC variable
        # shared across this module's single dot-sourced scope, so a later phase reading it would
        # see whatever the last operator here left behind.
        $zbPfNameRx = [regex]'^(.+)-[0-9A-Fa-f]{7,16}\.pf$'
        foreach ($zbPf in $zbPfScoped) {
            if ($zbPfCand.Count -ge 400) { break }
            $zbPfM = $zbPfNameRx.Match("$($zbPf.Name)")
            if (-not $zbPfM.Success) { continue }
            $zbImg = $zbPfM.Groups[1].Value
            # Only .exe images: the presence index below is built with an '*.exe' filter, and
            # widening it to every file class would turn a bounded walk into a whole-disk one.
            if ("$zbImg" -notmatch '\.exe$') { continue }
            $zbImgLc = "$zbImg".ToLower()
            if ($global:ZB_PROCNAME_SET.ContainsKey($zbImgLc)) { continue }   # running right now
            $zbSysHit = $false
            foreach ($zbProbe in @("$env:WINDIR\System32\$zbImg", "$env:WINDIR\SysWOW64\$zbImg", "$env:WINDIR\$zbImg")) {
                try { if (Test-Path -LiteralPath $zbProbe) { $zbSysHit = $true; break } } catch {}
            }
            if ($zbSysHit) { continue }
            $zbPfCand.Add($zbPf)
        }
        if ($zbPfCand.Count -gt 0) {
            # One bounded index of executable NAMES, built lazily and only when a candidate
            # survived the cheap probes above. $env:WINDIR is deliberately not a root: it would
            # re-walk System32/SysWOW64 (already indexed) and doubled the measured cost.
            # P1 multi-user — THE most consequential filesystem migration in this module, because
            # this index is not a detection scope, it is the EVIDENCE BASE for a negative claim.
            # The old root list ended in a bare $env:USERPROFILE, i.e. the TECHNICIAN's profile
            # under RunAs. Every executable that lives in a VICTIM's profile (the overwhelmingly
            # common place for per-user installs: Teams, Slack, Discord, Zoom, VS Code, Chrome's
            # updater, every Electron app, every portable tool) was therefore absent from the
            # index, so its prefetch entry was reported as "executed on this box but no file of
            # that name now exists" — the phase MANUFACTURED execution evidence out of a scoping
            # bug, on a completely healthy standard-user endpoint.
            #
            # The five MACHINE-wide roots are unchanged and enumerated exactly ONCE. Every
            # reachable profile's root is added after them, in deterministic SID order.
            $zbIdxProfRoots = @(Get-ZbUserRootsM1 -Kind @('Profile'))
            # Fail-safe: if no profile resolved (SYSTEM context with an odd ProfileList, or every
            # profile unreachable) fall back to the pre-P1 root so the index is never NARROWER
            # than it used to be — a narrower index is precisely what fabricates evidence.
            if ($zbIdxProfRoots.Count -eq 0 -and $env:USERPROFILE) { $zbIdxProfRoots = @("$env:USERPROFILE") }
            $zbIdxRoots = @(@(
                    "$env:WINDIR\System32", "$env:WINDIR\SysWOW64",
                    $env:ProgramFiles, ${env:ProgramFiles(x86)},
                    $env:ProgramData
                ) + $zbIdxProfRoots | Where-Object { $_ } | Select-Object -Unique)
            # Budget scaled with the profile count. The 60 s / 60 000-file budget was measured at
            # 40.2 s against ONE (large) profile; leaving it fixed would mean that on any
            # multi-profile box the walk truncates, the fail-closed branch below fires and the
            # correlation never runs at all. Scaling keeps the check alive without an unbounded
            # cost, and it is DEEP+ only ($PhasePlan.Advanced) so FULL scans pay nothing.
            # Non-default MaxFiles/DeadlineSecs change the Get-ScanFiles cache key — harmless
            # here, this call site is unique in the engine.
            $zbIdxMax      = [Math]::Min(200000, 60000 + 20000 * [Math]::Max(0, $zbIdxProfRoots.Count - 1))
            $zbIdxDeadline = [Math]::Min(150,       60 +    20 * [Math]::Max(0, $zbIdxProfRoots.Count - 1))
            $zbIdxSw = [System.Diagnostics.Stopwatch]::StartNew()
            $zbIdxFiles = Get-ScanFiles -Path $zbIdxRoots -Filter '*.exe' -MaxFiles $zbIdxMax -DeadlineSecs $zbIdxDeadline
            $zbIdxSw.Stop()
            # Fail closed. If the walk was truncated by either budget the index is INCOMPLETE, so
            # "not in the index" no longer means "not on disk" — reporting it would manufacture
            # evidence out of a budget hit. Skip the whole correlation and say so.
            $zbIdxTrunc = ($zbIdxFiles.Count -ge $zbIdxMax) -or ($zbIdxSw.Elapsed.TotalSeconds -ge $zbIdxDeadline)
            if ($zbIdxTrunc) {
                Out-Typewriter "  -> PREFETCH/FILESYSTEM CORRELATION SKIPPED — EXECUTABLE INDEX INCOMPLETE." "WARN"
                Add-Finding -ID "PREFETCH_CORR_SKIPPED" -Phase "PHASE 12" -ThreatType "Execution Trace" `
                    -Severity $SEV_INFO -Description "Prefetch-to-filesystem correlation was SKIPPED: the executable index over $($zbIdxRoots.Count) root(s) ($($zbIdxProfRoots.Count) user profile(s)) hit its budget ($($zbIdxFiles.Count) files / $([Math]::Round($zbIdxSw.Elapsed.TotalSeconds,1))s) and is incomplete, so 'executable no longer on disk' could not be established without guessing. $($zbPfCand.Count) prefetch entries went unchecked." `
                    -Target "$env:WINDIR\Prefetch" -FixAction "Info" -Group "Execution Artifacts"
            } else {
                $zbIdxNames = @{}
                foreach ($zbIf in $zbIdxFiles) { $zbIdxNames["$($zbIf.Name)".ToLower()] = $true }
                $zbGone = 0
                foreach ($zbPf in $zbPfCand) {
                    if ($zbGone -ge 60) { break }
                    $zbPfM = $zbPfNameRx.Match("$($zbPf.Name)")
                    if (-not $zbPfM.Success) { continue }
                    $zbImg = $zbPfM.Groups[1].Value
                    if ($zbIdxNames.ContainsKey("$zbImg".ToLower())) { continue }
                    $zbGone++
                    Add-Finding -ID "PFGONE_$(Get-StableId $zbPf.Name)" -Phase "PHASE 12" -ThreatType "Execution Trace" `
                        -Severity $SEV_INFO -Description "EXECUTION EVIDENCE — '$zbImg' executed on this box (last run approx $($zbPf.LastWriteTime), per its prefetch entry) but no file of that name now exists in System32, SysWOW64, Program Files, Program Files (x86), ProgramData or ANY of the $($zbIdxProfRoots.Count) reachable user profile(s) on this machine. CAVEAT: uninstalled software, installer stubs, portable apps run from removable media and per-user tools all produce this legitimately — this is timeline context, not a verdict. Evidence only; nothing is deleted." `
                        -Target $zbPf.FullName -FixAction "Info" -Group "Execution Artifacts — Vanished Executables"
                }
                if ($zbGone -gt 0) {
                    Out-Typewriter "  -> $zbGone PREFETCH ENTRIES REFER TO EXECUTABLES NO LONGER ON DISK (evidence, not a verdict)." "DATA"
                } else {
                    Out-Typewriter "  -> [OK] EVERY IN-SCOPE PREFETCH ENTRY STILL HAS ITS EXECUTABLE ON DISK." "GOOD"
                }
            }
        }
        }   # end DEEP+ ($PhasePlan.Advanced) prefetch/filesystem correlation
    }
} else {
    Out-Typewriter "  -> PREFETCH DIRECTORY ABSENT — EXECUTION-TRACE EVIDENCE UNAVAILABLE." "WARN"
    Add-Finding -ID "PREFETCH_ABSENT" -Phase "PHASE 12" -ThreatType "Execution Trace" `
        -Severity $SEV_INFO -Description "No $env:WINDIR\Prefetch directory. Prefetch-based execution evidence is UNAVAILABLE for this box (prefetcher disabled, or the folder was removed) — any 'no execution trace' conclusion from this scan is unproven, not clean." `
        -Target "$env:WINDIR\Prefetch" -FixAction "Info" -Group "Execution Artifacts"
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3: SYSTEM FILE & KERNEL INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "SYSTEM FILE & KERNEL INTEGRITY"

Show-PhaseHeader "PHASE 13" "CRYPTOGRAPHIC SYSTEM FILE VERIFICATION (SFC)"
if ($Auto -or $global:GUI_MODE -or $global:STEALTH_MODE) {
    # sfc /scannow runs 5-15 min with no streamable progress — in server/GUI/auto
    # runs that reads as a hung phase (the exact failure the perf work targets).
    # Skip the inline repair and surface it as a one-click manual action instead.
    Out-Typewriter "  -> SFC SKIPPED IN AUTO/GUI MODE (5-15 min op; offered as a manual fix)." "INFO"
    Add-Finding -ID "SFC_HARDENING" -Phase "PHASE 13" -ThreatType "System Integrity" -Severity $SEV_INFO `
        -Description "SFC integrity scan skipped in automated/GUI mode (5-15 min). Run it on demand, then review CBS.log." `
        -Target "C:\Windows\Logs\CBS\CBS.log" -FixAction "RunCmd" -FixParam "sfc /scannow" -Group "System Hardening"
} else {
    Out-Typewriter "EXECUTING SFC /SCANNOW..." "ACT"
    Invoke-QuantumBar "SFC KERNEL VALIDATION" 20 250
    cmd.exe /c "sfc /scannow >nul 2>&1"
    Out-Typewriter "  -> [OK] SFC VALIDATION COMPLETE." "VER"
    Add-Finding -ID "SFC_HARDENING" -Phase "PHASE 13" -ThreatType "System Integrity" -Severity $SEV_INFO `
        -Description "SFC scan was run — review CBS.log if anomalies found." `
        -Target "C:\Windows\Logs\CBS\CBS.log" -FixAction "Info" -Group "System Hardening"
}

Show-PhaseHeader "PHASE 14" "DISM COMPONENT STORE RESTORATION"
Out-Typewriter "FLUSHING WUAUSERV CACHE..." "ACT"
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
if (Test-Path "$env:WINDIR\SoftwareDistribution\Download") {
    Add-Finding -ID "SOFTDIST_CACHE" -Phase "PHASE 14" -ThreatType "System Integrity" -Severity $SEV_INFO `
        -Description "Windows Update download cache present — can be cleared." `
        -Target "$env:WINDIR\SoftwareDistribution\Download" -FixAction "DeleteFile" -FixParam "$env:WINDIR\SoftwareDistribution\Download" -Group "System Hardening"
}
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($Auto -or $global:GUI_MODE -or $global:STEALTH_MODE) {
    # DISM /RestoreHealth can run 10-20 min and may reach out to Windows Update —
    # same hung-phase problem in server/GUI/auto runs. Offer it as a manual fix.
    Out-Typewriter "  -> DISM /RESTOREHEALTH SKIPPED IN AUTO/GUI MODE (10-20 min op; offered as a manual fix)." "INFO"
    Add-Finding -ID "DISM_RESTOREHEALTH" -Phase "PHASE 14" -ThreatType "System Integrity" -Severity $SEV_INFO `
        -Description "DISM component-store repair skipped in automated/GUI mode (10-20 min, may contact Windows Update). Run on demand." `
        -Target "Component Store (WinSxS)" -FixAction "RunCmd" -FixParam "DISM /Online /Cleanup-Image /RestoreHealth" -Group "System Hardening"
} else {
    $dismProc = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth /Quiet" -PassThru -WindowStyle Hidden
    Invoke-QuantumBar "DISM IMAGE REPAIR IN PROGRESS" 30 550
    try { $dismProc | Wait-Process -Timeout 1200 -ErrorAction Stop; Out-Typewriter "  -> [OK] DISM REPAIR COMPLETE." "VER" }
    catch { $dismProc | Stop-Process -Force -ErrorAction SilentlyContinue; Out-Typewriter "  -> DISM TIMEOUT — CONTINUING." "WARN" }
}

Show-PhaseHeader "PHASE 15" "SYSTEM32 UNSIGNED BINARY AUDIT"
Out-Typewriter "SCANNING SYSTEM32 FOR FORGED/UNSIGNED BINARIES..." "ACT"
Invoke-QuantumBar "VERIFYING AUTHENTICODE SIGNATURES" 15 180
$recentSysFiles = Get-ChildItem -Path "$env:WINDIR\System32" -File -ErrorAction SilentlyContinue |
    Where-Object { Test-InScope $_.LastWriteTime -and $_.Extension -match "\.(exe|dll|sys)$" }
$foundSys = $false
# Bounded sig loop — with -Hours 0, top-level System32 yields thousands of .exe/.dll/.sys.
# MS-cert revocation is normally locally cached, but on an offline/proxied box Get-AuthSig
# can still block on CRL/OCSP; cap count + wall-clock so this can't hang (see Phase 98).
$sigSeen = 0
$sigSw   = [System.Diagnostics.Stopwatch]::StartNew()
$sigBudgetHit = $false
foreach ($sf in $recentSysFiles) {
    if ($sigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
        $sigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
        $sigBudgetHit = $true; break
    }
    $sigSeen++
    $asig = Get-AuthSig $sf.FullName
    $sigStatus = "$($asig.Status)"
    # Most System32 DLLs are CATALOG-signed (SignatureType=Catalog, Status=Valid) — those pass.
    # Of the remaining states, only an actual tamper signal (HashMismatch / NotTrusted publisher)
    # is a real rootkit indicator. An UnknownError/Incompatible/unverifiable status is what a
    # catalog-signed system file returns when the catalog can't be read (e.g. a transient corrupted
    # type/module env) — that previously flooded ~100 CRITICAL "rename System32 DLL" FPs. System32
    # is a Test-ProtectedTarget hard-block we never auto-act on, so an unverifiable result is
    # surfaced for REVIEW only (POSSIBLE + Info), never an auto-rename.
    if ($sigStatus -ne "Valid" -and $sigStatus -ne "NotSigned") {
        $foundSys = $true
        Out-Decrypt -Text $sf.FullName -Prefix "  [UNSIGNED SYS32 BINARY] "
        if ($sigStatus -eq "HashMismatch" -or $sigStatus -eq "NotTrusted") {
            $newName = "$($sf.FullName).kraken"
            # Currently non-exploitable only because every $sf.FullName here is under System32,
            # which Test-ProtectedTarget hard-blocks regardless — escape anyway so this doesn't
            # become the exploitable case the day that guard's regex is ever loosened.
            $sys32PathEsc = "$($sf.FullName)" -replace "'","''"
            $newNameEsc   = "$newName" -replace "'","''"
            Add-Finding -ID "SYS32_UNSIGNED_$($sf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 15" -ThreatType "Rootkit/Trojan" `
                -Severity $SEV_CRITICAL -Description "Tampered/untrusted binary in System32 ($sigStatus): $($sf.Name) — possible rootkit/trojan dropper" `
                -Target $sf.FullName -FixAction "RunCmd" -FixParam "Rename-Item -LiteralPath '$sys32PathEsc' -NewName '$newNameEsc' -Force -ErrorAction SilentlyContinue" -Group "Unsigned System32 Binaries"
            $global:RootkitHits++
        } else {
            Add-Finding -ID "SYS32_UNSIGNED_$($sf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 15" -ThreatType "Rootkit/Trojan" `
                -Severity $SEV_POSSIBLE -Description "System32 binary signature unverifiable ($sigStatus — often catalog-signed; review): $($sf.Name)" `
                -Target $sf.FullName -FixAction "Info" -Group "Unsigned System32 Binaries"
        }
    }
}
$sigSw.Stop()
if ($sigBudgetHit) {
    Out-Typewriter ("  -> [INFO] SYSTEM32 SIG BUDGET REACHED ({0} binaries / {1}s) — partial scan." -f $sigSeen, [Math]::Round($sigSw.Elapsed.TotalSeconds,1)) "WARN"
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
                -Severity $SEV_HIGH -Description "World-writable ACE on critical path: $cp — review manually. A recursive ACL reset on a system directory can break the OS, so this is NOT auto-applied. Suggested (run by hand after confirming): icacls '$cp' /reset /T /Q" `
                -Target $cp -FixAction "Info" -Group "NTFS Permission Abuse"
        } else { Out-Typewriter "  -> [OK] ACL SECURE." "GOOD" }
    }
}

Show-PhaseHeader "PHASE 17" "ALTERNATE DATA STREAM (ADS) PARASITE SCAN"
# P1 multi-user: all three roots were the technician's. An ADS parasite hidden in the victim's
# LocalAppData/Temp/Downloads was structurally invisible. Nothing machine-wide belongs here.
# Kept as a per-root loop (not a single Get-ScanFiles call) because this site does not use
# Get-ScanFiles at all — Get-Item -Stream is a NON-recursive single-folder enumeration, so its
# cost is O(files in one folder) per root and does not carry a per-call budget to multiply.
$zbAdsTargets = @()
foreach ($zbHive in @(@(Get-UserHives) | Sort-Object -Property Sid)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($zbR in @($zbUp.LocalAppData, $zbUp.Temp, $zbUp.Downloads)) {
        if ($zbR) { $zbAdsTargets += @{ Path = "$zbR"; User = "$($zbHive.User)" } }
    }
}
foreach ($zbAt in $zbAdsTargets) {
    $adsDir = $zbAt.Path
    Out-Typewriter "ADS SCAN: [$($zbAt.User)] $adsDir..." "INFO"
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
    if (Test-Path $adsDir) {
        # Skip benign OS/app-added streams. Windows tags downloaded files with Zone.Identifier AND a
        # 'SmartScreen' stream; browsers/cloud/macOS/AV add their own metadata streams. Flagging these
        # (e.g. on rufus.exe / a Win11 ISO) is a pure FP, so allowlist them. The real signal is an ADS
        # hiding *executable* content, not metadata — remaining hits are surfaced POSSIBLE (review).
        $benignStream = 'Zone\.Identifier|SmartScreen|^Afp_|com\.apple\.|com\.dropbox\.|OECustomProperty|encryptable|favicon|Win32App_|\$CmdTcID|KAVICHS|cdtag|ms-properties'
        $streams = Get-Item -Path "$adsDir\*" -Stream * -ErrorAction SilentlyContinue |
            Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -notmatch $benignStream }
        foreach ($s in $streams) {
            $adsFile   = $s.FileName -replace "'","''"
            $adsStream = $s.Stream   -replace "'","''"
            Out-Decrypt -Text "[$($zbAt.User)] $($s.FileName):$($s.Stream)" -Prefix "  [ADS HIT] "
            # ID is already full-path derived, so it gains per-user uniqueness for free now that
            # the path names a different profile. FixParam stays a bare, machine-parseable path —
            # the [User] tag must never leak into it.
            Add-Finding -ID "ADS_$(Get-StableId $s.FileName)" -Phase "PHASE 17" -ThreatType "ADS Parasite" `
                -Severity $SEV_POSSIBLE -Description "User $($zbAt.User): alternate Data Stream (review — most ADS are benign app/OS metadata; an ADS hiding executable content is the real signal): $($s.FileName):$($s.Stream)" `
                -Target "[$($zbAt.User)] $($s.FileName):$($s.Stream)" -FixAction "RunCmd" -FixParam "Remove-Item -LiteralPath '$adsFile' -Stream '$adsStream' -Force -ErrorAction SilentlyContinue" `
                -Group "Alternate Data Streams"
        }
        if ($streams.Count -eq 0) { Out-Typewriter "  -> [OK] NO HIDDEN DATA STREAMS." "GOOD" }
    }
}

Show-PhaseHeader "PHASE 17.5" "TIMESTOMP DETECTION — BACKDATED EXECUTABLE CONTENT"
Out-Typewriter "COMPARING CREATION vs WRITE TIMESTAMPS ON USER-PATH EXECUTABLES..." "HUNT"
# Time-stomping backdates a dropped file so it blends into the system image AND slips past
# every time-scoped phase in this engine. Detected structurally, so there is nothing to
# signature: a file whose CREATION time is far NEWER than its LAST-WRITE time was copied in
# with a forged write time, and a zeroed/epoch timestamp is a crude stomp. Deliberately NOT
# time-scoped (Test-InScope would filter out the very files whose timestamps are forged).
$tsHits = 0
$tsSigSeen = 0; $tsBudgetHit = $false; $tsSigSw = [System.Diagnostics.Stopwatch]::StartNew()
# P1 multi-user: four of these five roots were the technician's profile. $env:ProgramData is
# MACHINE scope and is added exactly ONCE, outside the profile set. Single Get-ScanFiles call
# across every profile (its MaxFiles/DeadlineSecs are PER CALL, so a per-profile loop would
# multiply this phase's wall clock by the profile count).
$tsRoots = @(@(Get-ZbUserRootsM1 -Kind @('Temp','LocalAppData','AppData','Downloads')) + @("$env:ProgramData") |
             Where-Object { $_ } | Select-Object -Unique)
$tsCandidates = (Get-ScanFiles -Path $tsRoots)
foreach ($tf in $tsCandidates) {
    $zbTsOwn = Get-ZbOwnerM1 $tf.FullName
    if ($TIMESTOMP_EXTENSIONS -notcontains $tf.Extension.ToLower()) { continue }
    $ct = $tf.CreationTimeUtc; $wt = $tf.LastWriteTimeUtc
    if ($null -eq $ct -or $null -eq $wt) { continue }
    $why = ''; $tsStrong = $false
    # LIVE-TUNED 2026-07-22: "created after last-write" is NOT a strong signal on its own —
    # it is the normal result of copying, extracting an archive, or restoring a backup, and it
    # fired on 9 files in one Chromium temp profile. It stays a POSSIBLE hint only. A zeroed /
    # pre-2000 timestamp is different: nothing legitimate on a modern box writes one, so that
    # is the case allowed to be auto-actionable.
    if ($wt.Year -lt 2000)      { $why = "last-write year $($wt.Year) — zeroed/epoch timestamp"; $tsStrong = $true }
    elseif ($ct.Year -lt 2000)  { $why = "creation year $($ct.Year) — zeroed/epoch timestamp"; $tsStrong = $true }
    elseif ($ct -gt $wt.AddDays(1)) { $why = "created $([int]($ct - $wt).TotalDays)d AFTER its last-write time (content predates the file)" }
    if (-not $why) { continue }
    $tsHits++
    # Timestamps alone are weak evidence (backup/restore, archive extraction and some
    # installers all reproduce this), so a validly signed file is review-only.
    # SIG_AUDIT budget: extracting one big archive can produce hundreds of timestamp
    # anomalies at once, and Authenticode blocks ~15s per file on CRL/OCSP.
    if ($tsSigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
        $tsSigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
        if (-not $tsBudgetHit) {
            $tsBudgetHit = $true
            Out-Typewriter "  -> SIGNATURE BUDGET REACHED — remaining timestamp anomalies not signature-verified." "WARN"
        }
        break
    }
    $tsSigSeen++
    $tsig = Get-AuthSig $tf.FullName
    $tsSigned = ($tsig -and $tsig.Status -eq 'Valid')
    # REVIEW 2026-07-22 (round 2): even the zeroed-timestamp case is NOT auto-actionable.
    # The DOS/ZIP epoch is 1980-01-01, so every file extracted from a zip built with a zeroed
    # date stamp — portable tools in Downloads, the whole of C:\ProgramData\chocolatey, Python
    # wheels built with SOURCE_DATE_EPOCH — carries a pre-2000 stamp on a perfectly healthy box.
    # A timestamp is corroborating evidence, never proof: this phase is now review-only in every
    # branch, and the HIGH grade is reserved for a zeroed stamp on a file sitting in a staging
    # dir, which still only asks the operator to look.
    $tsStaging = ($tf.FullName -match '\\(Temp|Downloads|Public)\\')
    if ($tsStrong -and -not $tsSigned -and $tsStaging) {
        Out-Decrypt -Text "[$($zbTsOwn.User)] $($tf.FullName)" -Prefix "  [TIMESTOMP] "
        Add-Finding -ID "TIMESTOMP_$(Get-StableId $tf.FullName)" -Phase "PHASE 17.5" -ThreatType "Timestomp / Anti-Forensics" `
            -Severity $SEV_HIGH -Description "User $($zbTsOwn.User): unsigned executable in a staging directory with a zeroed timestamp ($why) — corroborating evidence only; archive extraction also produces 1980 stamps, so verify before acting: $($tf.FullName)" `
            -Target "[$($zbTsOwn.User)] $($tf.FullName)" -FixAction "Info" -Group "Anti-Forensic Timestamps"
    } else {
        Add-Finding -ID "TIMESTOMP_$(Get-StableId $tf.FullName)" -Phase "PHASE 17.5" -ThreatType "Timestomp / Anti-Forensics" `
            -Severity $SEV_POSSIBLE -Description "User $($zbTsOwn.User): $(if ($tsSigned) { 'signed' } else { 'unsigned' }) executable with inconsistent timestamps ($why) — normally archive extraction, a copy or a restore; review only, never auto-acted: $($tf.FullName)" `
            -Target "[$($zbTsOwn.User)] $($tf.FullName)" -FixAction "Info" -Group "Anti-Forensic Timestamps"
    }
}
if ($tsHits -eq 0) { Out-Typewriter "  -> [OK] NO TIMESTAMP ANOMALIES." "GOOD" }

Show-PhaseHeader "PHASE 18" "DEEP CLOAKED PARASITE SCAN (HIDDEN+SYSTEM ATTRIBUTES)"
# P1 multi-user: three of the four roots were the technician's profile ($env:USERPROFILE\AppData\
# Roaming is just $env:APPDATA spelled the long way, and is now resolved redirection-aware via
# Get-UserPaths rather than assumed). $env:PUBLIC is MACHINE scope and is added exactly ONCE.
# Restructured from four separate Get-ScanFiles calls into ONE call over all roots: those budgets
# are PER CALL, so the old shape would have become (3 roots x N profiles) + 1 full-budget walks.
$zbCloakRoots = @(@("$env:PUBLIC") + @(Get-ZbUserRootsM1 -Kind @('LocalAppData','Temp','AppData')) |
                  Where-Object { $_ } | Select-Object -Unique)
foreach ($zbCr in $zbCloakRoots) { Out-Typewriter "SWEEPING HIDDEN/SYSTEM ATTRS: $zbCr" "HUNT" }
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 900 }
# Hidden+System is the NORMAL attribute set for many OS/shell housekeeping files
# (desktop.ini, IconCache.db, *.library-ms, thumbs.db, ntuser.*, *.lnk). Drop those via the
# benign-name allowlist so the phase stops flagging every shell file.
# Real cloaked malware is an executable / script / archive payload. A Hidden+System *data*
# file (.json/.db/.log/.dat/.profile/cache, or extension-less browser-profile files like
# "History"/"Login Data") is normal OS/app housekeeping, so only payload-type extensions are
# flagged here — everything else is skipped (the benign-name allowlist drops shell files first).
$cloaked = @((Get-ScanFiles -Path $zbCloakRoots -TimeScoped) |
    Where-Object {
        $_.Attributes -match "Hidden" -and $_.Attributes -match "System" -and
        $_.Name -notmatch $CLOAKED_BENIGN_RE -and
        $_.Extension -match "\.(exe|dll|sys|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|pif|cpl|ocx|jar|zip|rar|7z|cab|iso|img)$"
    })
foreach ($c in $cloaked) {
    $zbClOwn = Get-ZbOwnerM1 $c.FullName
    # A cloaked *executable/script* is a real rootkit/dropper signal (HIGH); a cloaked archive
    # or extension-less file is suspicious-but-weaker -> POSSIBLE (shown, not auto-selected).
    $cloakSev = if ($c.Extension -match "\.(exe|dll|sys|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|pif|cpl|ocx|jar)$") { $SEV_HIGH } else { $SEV_POSSIBLE }
    Out-ThreatBanner "CLOAKED FILE (HIDDEN+SYSTEM)" "[$($zbClOwn.User)] $($c.FullName)"
    # ID was "CLOAKED_<flattened filename>" — filename-only, so the same cloaked payload name
    # dropped into two profiles collapsed to ONE finding through Add-Finding's de-dupe and the
    # second user's copy was silently lost. Now keyed on SID + full path.
    Add-Finding -ID "CLOAKED_$(Get-StableId "$($zbClOwn.Sid)|$($c.FullName)")" -Phase "PHASE 18" -ThreatType "Rootkit/Trojan" `
        -Severity $cloakSev -Description "User $($zbClOwn.User): Hidden+System attributed file: $($c.FullName)" `
        -Target "[$($zbClOwn.User)] $($c.FullName)" -FixAction "DeleteFile" -FixParam $c.FullName -Group "Cloaked/Hidden Files"
}
if ($cloaked.Count -eq 0) { Out-Typewriter "  -> [OK] NO CLOAKED FILES." "GOOD" }

Show-PhaseHeader "PHASE 19" "SCRIPT EXECUTION ASSOCIATION AUDIT"
Out-Typewriter "CHECKING .JS .VBS .HTA .WSF HANDLER ASSOCIATIONS..." "INFO"
foreach ($ext in @(".js",".vbs",".hta",".wsf",".wsh",".jse",".vbe")) {
    $assoc = cmd.exe /c "assoc $ext 2>nul"
    if ($assoc -notmatch "txtfile" -and $assoc -match "=") {
        # NOTE: .js=JSFile, .vbs=VBSFile, .hta=htafile etc. are the DEFAULT Windows associations on
        # every box — their mere presence is NOT a threat, it's a hardening opportunity (remap to
        # txtfile so double-click can't execute). So this is POSSIBLE + opt-in RunCmd (shown for
        # review, never auto-applied), not a HIGH auto-selected finding. ~7 default-assoc FPs removed.
        Out-Typewriter "  -> SCRIPT EXT $ext MAPPED TO EXECUTABLE HANDLER: $assoc" "WARN"
        Add-Finding -ID "SCRIPT_ASSOC_$($ext -replace '\.','')" -Phase "PHASE 19" -ThreatType "Script Handler Abuse" `
            -Severity $SEV_POSSIBLE -Description "Script extension $ext uses the default executable handler ($assoc) — optional hardening: remap to txtfile" `
            -Target "File Association: $ext" -FixAction "RunCmd" -FixParam "assoc $ext=txtfile" -Group "Script Execution Hardening"
    }
}
Out-Typewriter "  -> SCRIPT HANDLER AUDIT COMPLETE." "VER"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4: REGISTRY PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════
}   # end QUICK-skip block
Show-SectionBanner "REGISTRY PERSISTENCE SCRUB"

Show-PhaseHeader "PHASE 20" "RUN / RUNONCE HEURISTIC SCRUB"
# P1 multi-user: the two HKLM roots (plus their WOW6432Node twins) are MACHINE scope and are
# enumerated exactly ONCE — a box with 8 profiles must not report a machine-wide Run value 8
# times. The former HKCU roots become hive-relative and are walked per profile, so a Run-key
# persistence living in the victim's profile is finally visible from the technician's elevated
# session. GRADING IS UNCHANGED: the $RUNKEY_BENIGN_RE allowlist branch and the AppData
# POSSIBLE branch are byte-identical in behaviour to before.
# ID: was "RUNKEY_<propname>", which already collided HKCU-vs-HKLM on a SINGLE-user box (one
# "Updater" value in each hive kept only whichever was seen first) and would have collapsed
# every user's copy into one. It now hashes SID|path|name.
$zbRunTargets = @()
foreach ($zbMp in @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce")) {
    $zbRunTargets += @{ Path = $zbMp; User = 'MACHINE'; Sid = 'MACHINE'; Src = 'HKLM' }
}
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }   # not mounted and loading is off: we could not look
    foreach ($zbRel in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                         'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
        $zbRunTargets += @{ Path = "$($zbHive.HivePath)\$zbRel"
                            User = $zbHive.User; Sid = $zbHive.Sid; Src = $zbHive.Source }
    }
}
$zbRunAudited = 0
foreach ($zbT in $zbRunTargets) {
    $rp = $zbT.Path
    Out-Typewriter "AUDITING HIVE: [$($zbT.User)] $rp" "INFO"
    # Cosmetic typewriter pacing only, capped at the original 6-root count: a terminal server
    # with 25 profiles would otherwise add ~30s of pure Start-Sleep to an interactive run.
    if ((-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) -and $zbRunAudited -lt 6) { Start-Sleep -Milliseconds 600 }
    $zbRunAudited++
    if (Test-Path $rp) {
        # A FixParam must never point into a ZB_UH_* mount — remediation runs later, in the
        # server's remediation runspace, long after that mount is gone.
        $zbRunAct    = "DeleteReg"
        $zbRunHint   = ""
        $zbRunSev    = $SEV_CRITICAL
        $zbRunMounted = ($zbT.Src -eq 'RegLoad')
        if ($zbRunMounted) {
            $zbRunAct  = "Info"
            $zbRunSev  = $SEV_HIGH   # contract: a reg-loaded (logged-off) hive caps at HIGH + Info
            $zbRunHint = " That profile's hive is only temporarily mounted by this scan — remove by hand with reg load HKU\ZBFIX / Remove-ItemProperty / reg unload HKU\ZBFIX."
        }
        $keys = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        foreach ($prop in ($keys.psobject.properties | Where-Object { $_.Name -notmatch "^PS" }).Name) {
            $val = $keys.$prop
            $zbRunId = "RUNKEY_$(Get-StableId "$($zbT.Sid)|$rp|$prop")"
            # Strong indicators (Temp / script host / encoded / LOLBin / remote) = CRITICAL auto-deletable.
            # Bare 'AppData' is NOT a strong signal on its own — Discord, Teams, Slack, OneDrive, Logitech
            # and most updaters legitimately autostart from AppData\Local, so an AppData-only value is
            # review-only (POSSIBLE + Info), never auto-removed. (The _DELETEME tripwire points at %TEMP%.)
            if ($val -match "Temp|cmd\.exe|powershell|wscript|cscript|mshta|\.js|\.vbs|\.hta|regsvr32|rundll32|certutil|bitsadmin|msiexec.*http|IEX|EncodedCommand") {
                # OS/OneDrive write their own cmd.exe+del cleanup RunOnce values — allowlisted
                # name=value pairs are review-only, never auto-DeleteReg on a healthy box.
                if ("$prop = $val" -match $RUNKEY_BENIGN_RE) {
                    Out-Decrypt -Text "[$($zbT.User)] $prop = $val" -Prefix "  [RUN KEY?] "
                    Add-Finding -ID $zbRunId -Phase "PHASE 20" -ThreatType "Registry Persistence" `
                        -Severity $SEV_POSSIBLE -Description "User $($zbT.User) [hive source: $($zbT.Src)]: Run key matches a known-benign OS cleanup entry (allowlisted — review only): [$rp] $prop = $val" `
                        -Target "[$($zbT.User)] $rp|$prop" -FixAction "Info" -Group "Run Key Persistence"
                } else {
                Out-Decrypt -Text "[$($zbT.User)] $prop = $val" -Prefix "  [RUN KEY] "
                Add-Finding -ID $zbRunId -Phase "PHASE 20" -ThreatType "Registry Persistence" `
                    -Severity $zbRunSev -Description "User $($zbT.User) [hive source: $($zbT.Src)]: malicious Run key: [$rp] $prop = $val$zbRunHint" `
                    -Target "[$($zbT.User)] $rp|$prop" -FixAction $zbRunAct -FixParam $(if ($zbRunMounted) { "" } else { "$rp|$prop" }) -Group "Run Key Persistence"
                }
            } elseif ($val -match "AppData") {
                Out-Decrypt -Text "[$($zbT.User)] $prop = $val" -Prefix "  [RUN KEY?] "
                Add-Finding -ID $zbRunId -Phase "PHASE 20" -ThreatType "Registry Persistence" `
                    -Severity $SEV_POSSIBLE -Description "User $($zbT.User) [hive source: $($zbT.Src)]: Run key launches from AppData (review — common for legitimate apps, so NOT auto-removed): [$rp] $prop = $val" `
                    -Target "[$($zbT.User)] $rp|$prop" -FixAction "Info" -Group "Run Key Persistence"
            }
        }
    }
}
Out-Typewriter "  -> RUN/RUNONCE AUDIT COMPLETE ($zbRunAudited HIVE ROOT(S))." "VER"

Show-PhaseHeader "PHASE 21" "IMAGE FILE EXECUTION OPTIONS (IFEO) SCRUB"
$ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path $ifeoPath) {
    Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
        if (Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue) {
            $dbg = (Get-RegVal -Path $_.PSPath -Name "Debugger")
            Out-Decrypt -Text "$($_.PSChildName) -> Debugger = $dbg" -Prefix "  [IFEO HIT] "
            Add-Finding -ID "IFEO_$($_.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 21" -ThreatType "IFEO Hijack/Persistence" `
                -Severity $SEV_CRITICAL -Description "IFEO Debugger set on $($_.PSChildName) = $dbg — common backdoor/persistence technique" `
                -Target "$($_.PSPath)|Debugger" -FixAction "DeleteReg" -FixParam "$($_.PSPath)|Debugger" -Group "IFEO Persistence"
        }
        $gf = (Get-RegVal -Path $_.PSPath -Name "GlobalFlag")
        if ($null -ne $gf -and $gf -ne 0) {
            Add-Finding -ID "IFEO_GF_$($_.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 21" -ThreatType "IFEO/GFlags Injection" `
                -Severity $SEV_HIGH -Description "IFEO GlobalFlag set on $($_.PSChildName) = $gf (GFlags injection vector)" `
                -Target "$($_.PSPath)|GlobalFlag" -FixAction "DeleteReg" -FixParam "$($_.PSPath)|GlobalFlag" -Group "IFEO Persistence"
        }
    }
    Out-Typewriter "  -> IFEO AUDIT COMPLETE." "VER"
} else { Out-Typewriter "  -> [OK] IFEO HIVE ABSENT." "GOOD" }

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 21.5" "SILENT-PROCESS-EXIT / EDR-BLINDING IFEO / COM TYPELIB HIJACK"
Out-Typewriter "AUDITING DEBUG-HOOK PERSISTENCE THE IFEO SCRUB DOES NOT COVER..." "HUNT"
# Phase 21 audits the classic IFEO Debugger/GlobalFlag values. This phase covers the three
# sibling techniques it does not: (a) SilentProcessExit, a separate hive with the same
# launch-on-exit power; (b) an IFEO entry aimed at a SECURITY product, which is not
# persistence at all but EDR blinding and deserves its own severity; (c) COM TypeLib
# hijacking, which Phase 24 misses because that phase only walks CLSID.
$ifeoExtra = 0
foreach ($ifr in $IFEO_REG_ROOTS) {
    if (-not (Test-Path -LiteralPath $ifr)) { continue }
    $isSilentExit = ($ifr -match 'SilentProcessExit')
    foreach ($k in (Get-ChildItem -Path $ifr -ErrorAction SilentlyContinue)) {
        $leaf = "$($k.PSChildName)".ToLower()
        $mon  = Get-RegVal -Path $k.PSPath -Name "MonitorProcess"
        $rep  = Get-RegVal -Path $k.PSPath -Name "ReportingMode"
        $dbg  = Get-RegVal -Path $k.PSPath -Name "Debugger"
        $isSecTool = ($SECURITY_TOOL_PROCS -contains $leaf)
        # $mon (MonitorProcess) is what actually launches something on exit; a ReportingMode-only
        # entry has nothing to launch, and the description below would read "launches ''".
        if ($isSilentExit -and $mon) {
            $ifeoExtra++
            Out-Decrypt -Text "$leaf -> MonitorProcess = $mon" -Prefix "  [SILENT-EXIT] "
            Add-Finding -ID "SILENTEXIT_$($k.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 21.5" `
                -ThreatType "SilentProcessExit Persistence" -Severity $SEV_CRITICAL `
                -Description "SilentProcessExit hook on '$($k.PSChildName)' launches '$mon' whenever that process exits — a launch-on-exit backdoor that the standard IFEO audit does not see." `
                -Target "$($k.PSPath)|MonitorProcess" -FixAction "DeleteRegKey" -FixParam "$($k.PSPath)" `
                -Group "IFEO / SilentProcessExit Persistence"
        }
        if ($isSecTool -and ($dbg -or $mon)) {
            $ifeoExtra++
            Out-ThreatBanner "EDR BLINDING VIA IFEO" "$leaf"
            # FixAction Info, not DeleteRegKey: the IFEO hive is matched by Test-ProtectedTarget as
            # "core OS registry", so a DeleteRegKey here is HARD-blocked on all three layers and
            # could never execute. Ship the command in the description instead (rule #1's own
            # prescription for an action the operator must run by hand).
            Add-Finding -ID "EDRBLIND_$($k.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 21.5" `
                -ThreatType "Security Tool Tampering" -Severity $SEV_CRITICAL `
                -Description "An IFEO/SilentProcessExit entry targets the SECURITY PRODUCT '$($k.PSChildName)' — this is not persistence, it is deliberate defence evasion (the product is hijacked or prevented from running). Debugger='$dbg' Monitor='$mon'. Remove by hand after confirming: Remove-Item -LiteralPath '$($k.PSPath)' -Recurse -Force" `
                -Target "$($k.PSPath)" -FixAction "Info" `
                -Group "Security Tool Tampering"
            $global:RootkitHits++
        }
    }
}
# COM TypeLib hijack: a per-user TypeLib entry shadowing a machine-wide one causes the
# referenced script/DLL to load whenever the COM object is instantiated. A win32-path
# TypeLib pointing at a script host or a user-writable path is the give-away.
# P1 multi-user: $COM_TYPELIB_ROOTS is a pure-HKCU list, so under the elevated technician
# session this walked the TECHNICIAN's class store and every other profile's TypeLib hijack was
# invisible. The HKCU: prefix is stripped defensively at the CALL SITE (an already-relative
# entry passes through unchanged, so old and new data both work and no data edit is needed),
# and the remaining Software\Classes\ segment is dropped because the per-user class store is a
# SEPARATE hive file (UsrClass.dat) exposed as ClassesHivePath — for a reg-loaded profile
# NTUSER.DAT's own Software\Classes is nearly empty (measured: 1 CLSID subkey vs 6).
# The LIVE-TUNED Teams Meeting Add-in exemption below is intact and now applies PER PROFILE:
# every profile with Teams reproduces that same signed-binary-under-AppData shape, and each is
# graded through the same $tlSigned test, so it stays POSSIBLE + Info for all of them.
foreach ($tlRoot in $COM_TYPELIB_ROOTS) {
    if ($tlRoot -notmatch 'TypeLib$') { continue }   # only the TypeLib hive holds win32/win64 leaves
    $zbTlRel = "$tlRoot" -replace '(?i)^HK(CU|EY_CURRENT_USER):?\\', ''
    $zbTlRel = $zbTlRel  -replace '(?i)^SOFTWARE\\Classes\\', ''
    foreach ($zbHive in @(Get-UserHives)) {
        if (-not $zbHive.ClassesHivePath) { continue }   # no per-user class store reachable: we could not look
        $tlPath = "$($zbHive.ClassesHivePath)\$zbTlRel"
        if (-not (Test-Path -LiteralPath $tlPath)) { continue }
        $zbTlUp = Get-UserPaths $zbHive
    # Depth 4, not 3: the path is TypeLib\{GUID}\<ver>\<lcid>\win32 — a depth of 3 stops one level
    # short and finds nothing. Scoped to the per-user class store deliberately: that hive holds only
    # overrides, so it stays small, and a per-user TypeLib shadowing a machine-wide one IS the hijack.
    foreach ($tl in (Get-ChildItem -Path $tlPath -Recurse -Depth 4 -ErrorAction SilentlyContinue)) {
        if ("$($tl.PSChildName)" -notmatch '^win(32|64)$') { continue }
        $tlVal = Get-RegVal -Path $tl.PSPath -Name '(default)'
        if (-not $tlVal) { continue }
        # LIVE-TUNED 2026-07-22: "resolves to a user-writable path" alone flagged the Microsoft
        # Teams Meeting Add-in, which legitimately registers a per-user TypeLib under AppData.
        # A SCRIPT target is the real hijack shape; a binary target only counts when it is not
        # validly signed. Everything else is review-only.
        $tlIsScript = ($tlVal -match '(?i)\.(js|jse|vbs|vbe|wsf|wsh|hta|sct|ps1)(\b|$)')
        if (-not $tlIsScript -and $tlVal -notmatch $global:USER_PATH_RE) { continue }
        # Resolve %APPDATA%/%USERPROFILE%/... against the TARGET user, not the technician —
        # otherwise the signature check would stat a path in the wrong profile (usually absent,
        # which silently promotes a signed Teams add-in from POSSIBLE to HIGH + DeleteRegKey).
        # Falls back to the old process-env expansion when the template resolver cannot help.
        $tlResolved = $null
        if ($zbTlUp) { $tlResolved = Expand-UserPathTemplate "$tlVal" $zbTlUp }
        if (-not $tlResolved) { $tlResolved = [Environment]::ExpandEnvironmentVariables("$tlVal") }
        $tlResolved = "$tlResolved".Trim('"')
        $tlSigned = $false
        if (-not $tlIsScript -and $tlResolved -and (Test-Path -LiteralPath $tlResolved)) {
            $tlSig = Get-AuthSig $tlResolved
            $tlSigned = ($tlSig -and $tlSig.Status -eq 'Valid')
        }
        $ifeoExtra++
        # PSPath comes back provider-qualified ("Microsoft.PowerShell.Core\Registry::HKEY_USERS\...").
        # Normalise to the short form: the server's Test-ProtectedTarget P1 guards (service hives,
        # and the HARD block on ZB_UH_*/ZB_UC_* mounts that no longer exist at remediation time) are
        # ANCHORED at '^Registry::', so a provider-qualified FixParam would slip straight past them.
        $zbTlPs = "$($tl.PSPath)" -replace '^Microsoft\.PowerShell\.Core\\Registry::', 'Registry::'
        $zbTlId = "TYPELIB_$(Get-StableId "$($zbHive.Sid)|$zbTlPs")"
        if ($tlSigned) {
            Add-Finding -ID $zbTlId -Phase "PHASE 21.5" `
                -ThreatType "COM TypeLib Hijack" -Severity $SEV_POSSIBLE `
                -Description "User $($zbHive.User) [hive source: $($zbHive.Source)]: per-user COM TypeLib entry points into a user-writable path but the target is validly signed (normal for per-user Office/Teams add-ins) — review only: $tlVal" `
                -Target "[$($zbHive.User)] $zbTlPs" -FixAction "Info" -Group "COM Hijack Persistence"
            continue
        }
        # A FixParam must never point into a ZB_UH_*/ZB_UC_* mount: remediation runs later, in
        # the server's remediation runspace, long after that mount is gone.
        $zbTlAct  = "DeleteRegKey"
        $zbTlFp   = $zbTlPs
        $zbTlHint = ""
        if ($zbHive.Source -eq 'RegLoad') {
            $zbTlAct  = "Info"
            $zbTlFp   = ""
            $zbTlHint = " That profile's class store is only temporarily mounted by this scan — remove by hand after re-mounting it (reg load / Remove-Item -Recurse / reg unload)."
        }
        Out-Decrypt -Text "[$($zbHive.User)] $zbTlPs -> $tlVal" -Prefix "  [TYPELIB HIJACK] "
        Add-Finding -ID $zbTlId -Phase "PHASE 21.5" `
            -ThreatType "COM TypeLib Hijack" -Severity $SEV_HIGH `
            -Description "User $($zbHive.User) [hive source: $($zbHive.Source)]: per-user COM TypeLib entry resolves to $(if ($tlIsScript) { 'a SCRIPT' } else { 'an unsigned binary' }) — loads on every instantiation of the COM object: $tlVal$zbTlHint" `
            -Target "[$($zbHive.User)] $zbTlPs" -FixAction $zbTlAct -FixParam $zbTlFp `
            -Group "COM Hijack Persistence"
    }
    }
}
if ($ifeoExtra -eq 0) { Out-Typewriter "  -> [OK] NO SILENT-EXIT / EDR-BLINDING / TYPELIB HIJACKS." "GOOD" }

Show-PhaseHeader "PHASE 22" "APPINIT_DLLS KERNEL INJECTION SCRUB"
foreach ($p in @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows")) {
    $ai = Get-RegVal -Path $p -Name "AppInit_DLLs"
    if ($ai -and $ai.Trim() -ne "") {
        Out-Typewriter "  -> APPINIT_DLLS SET: $ai" "CRIT"
        Add-Finding -ID "APPINIT_$($p -replace '[^a-z0-9]','')" -Phase "PHASE 22" -ThreatType "DLL Injection/Rootkit" `
            -Severity $SEV_CRITICAL -Description "AppInit_DLLs is set — injects into every user-mode process: $ai" `
            -Target "$p|AppInit_DLLs" -FixAction "DeleteReg" -FixParam "$p|AppInit_DLLs" -Group "DLL Injection Persistence"
    } else { Out-Typewriter "  -> [OK] APPINIT_DLLS EMPTY." "GOOD" }
}

Show-PhaseHeader "PHASE 22.5" "PROCESS-WIDE DLL LOAD POINTS (APPCERT / NETSH / WINSOCK LSP)"
Out-Typewriter "AUDITING THE REMAINING SYSTEM-WIDE DLL INJECTION REGISTRATIONS..." "HUNT"
# Phase 22 covers AppInit_DLLs. These are its siblings — every one of them makes Windows load
# an attacker DLL into OTHER processes, and all are effectively unused on a modern endpoint,
# so any value here is high-signal.
$injHits = 0
# AppCertDlls is a SUBKEY whose VALUES name the DLLs, not a value on Session Manager —
# reading it as a value returns $null unconditionally, so the check never fired.
$appCertKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
if (Test-Path -LiteralPath $appCertKey) {
    $acProps = Get-ItemProperty -LiteralPath $appCertKey -ErrorAction SilentlyContinue
    if ($acProps) {
        foreach ($ac in $acProps.PSObject.Properties) {
            if ($ac.Name -like 'PS*') { continue }
            $injHits++
            Out-ThreatBanner "APPCERTDLLS INJECTION POINT" "$($ac.Name) = $($ac.Value)"
            Add-Finding -ID "APPCERT_$($ac.Name -replace '[^a-z0-9]','')" -Phase "PHASE 22.5" `
                -ThreatType "DLL Injection/Rootkit" -Severity $SEV_CRITICAL `
                -Description "AppCertDlls entry '$($ac.Name)' loads $($ac.Value) into every process that calls CreateProcess. There is no legitimate modern use of this key." `
                -Target "$appCertKey|$($ac.Name)" -FixAction "DeleteReg" -FixParam "$appCertKey|$($ac.Name)" `
                -Group "DLL Injection Persistence"
            $global:RootkitHits++
        }
    }
}
foreach ($ip in $INJECTION_DLL_POINTS) {
    $iv = Get-RegVal -Path $ip.Path -Name $ip.Name
    if (-not $iv -or "$iv".Trim() -eq '') { continue }
    $injHits++
    Out-ThreatBanner "SYSTEM-WIDE DLL INJECTION POINT" "$($ip.Name) = $iv"
    Add-Finding -ID "INJDLL_$($ip.Name -replace '[^a-z0-9]','')_$(Get-StableId $ip.Path)" -Phase "PHASE 22.5" `
        -ThreatType "DLL Injection/Rootkit" -Severity $SEV_CRITICAL `
        -Description "$($ip.Why). Current value: $iv" `
        -Target "$($ip.Path)|$($ip.Name)" -FixAction "DeleteReg" -FixParam "$($ip.Path)|$($ip.Name)" `
        -Group "DLL Injection Persistence"
    $global:RootkitHits++
}
# netsh helper DLLs load into netsh.exe on every invocation — a quiet, long-lived foothold.
if ($NETSH_HELPER_ROOT -and (Test-Path -LiteralPath $NETSH_HELPER_ROOT)) {
    $nsProps = Get-ItemProperty -LiteralPath $NETSH_HELPER_ROOT -ErrorAction SilentlyContinue
    if ($nsProps) {
        foreach ($np in $nsProps.PSObject.Properties) {
            if ($np.Name -like 'PS*') { continue }
            $nsDll = "$($np.Value)"
            if (-not $nsDll) { continue }
            # Microsoft's own helpers live in System32 and are catalog-signed; anything else is notable.
            $nsResolved = [Environment]::ExpandEnvironmentVariables($nsDll)
            if ($nsResolved -match '(?i)^[A-Za-z]:\\Windows\\System32\\[^\\]+$' -or $nsResolved -notmatch '\\') { continue }
            $injHits++
            Add-Finding -ID "NETSHHELPER_$($np.Name -replace '[^a-z0-9]','')" -Phase "PHASE 22.5" `
                -ThreatType "Netsh Helper DLL Persistence" -Severity $SEV_HIGH `
                -Description "Non-System32 netsh helper DLL '$($np.Name)' = $nsDll — loads into netsh.exe every time it runs." `
                -Target "$NETSH_HELPER_ROOT|$($np.Name)" -FixAction "DeleteReg" -FixParam "$NETSH_HELPER_ROOT|$($np.Name)" `
                -Group "DLL Injection Persistence"
        }
    }
}
# Winsock LSPs are loaded into every network-capable process. A non-Microsoft LSP is rare
# enough on a modern box to be worth eyes, but legitimate VPN/AV products still ship them —
# review-only, never auto-acted (removing an LSP incorrectly breaks all networking).
try {
    $lspRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries"
    foreach ($lsp in (Get-ChildItem -Path $lspRoot -ErrorAction SilentlyContinue)) {
        $lspDll = Get-RegVal -Path $lsp.PSPath -Name 'PackedCatalogItem'
        if (-not $lspDll) { continue }
        $lspStr = -join ([char[]]$lspDll | Where-Object { [int]$_ -gt 31 -and [int]$_ -lt 127 })
        if (-not $lspStr -or $lspStr -match '(?i)\\system32\\(mswsock|rsvpsp|nlaapi|winrnr|napinsp|pnrpnsp|wshbth)\.dll') { continue }
        $injHits++
        Add-Finding -ID "LSP_$(Get-StableId $lspStr)" -Phase "PHASE 22.5" `
            -ThreatType "Winsock LSP" -Severity $SEV_POSSIBLE `
            -Description "Third-party Winsock LSP loaded into every networked process (often a legitimate VPN/AV, occasionally traffic-hijacking malware — verify, do NOT remove blindly: an incorrect LSP removal breaks all networking): $lspStr" `
            -Target "$($lsp.PSPath)" -FixAction "Info" -Group "DLL Injection Persistence"
    }
} catch {}
if ($injHits -eq 0) { Out-Typewriter "  -> [OK] NO SYSTEM-WIDE DLL LOAD POINTS SET." "GOOD" }

}   # end QUICK-skip block
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

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 24" "COM OBJECT HIJACK AUDIT (PER-USER CLSID OVERRIDES)"
Out-Typewriter "SCANNING PER-USER COM OVERRIDES (ALL READABLE PROFILES)..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
# WS9 correlation feed (Phase 105): confirmed-hijack CLSIDs, keyed independent of Severity — a
# PARANOID-mode run promotes every stored POSSIBLE finding to HIGH (Add-Finding's own escalation
# rule), which would make the benign "per-user CLSID, no HKLM twin" branch below storage-
# indistinguishable from a genuine HKLM-shadowing hijack if Phase 105 keyed off $f.Severity.
# NOTE: still keyed by bare CLSID GUID, because Phase 105 looks it up as $hijackedClsids[$ct.ClassId]
# from a ComHandler task's ClassId. If the SAME CLSID is hijacked in two profiles the map keeps the
# last one — the FINDINGS are per-user and complete; only the correlation's example path is one of them.
$global:ZB_ComHijackConfirmedClsids = @{}
# P1 multi-user: this read a bare HKCU:\SOFTWARE\Classes\CLSID, i.e. the TECHNICIAN's class store,
# so a COM hijack in the victim's profile was structurally invisible. Walked per profile via
# ClassesHivePath — NOT "$HivePath\Software\Classes": for a reg-loaded profile the real class
# registrations live in a separately mounted UsrClass.dat and NTUSER.DAT's own Software\Classes is
# nearly empty (measured: 1 CLSID subkey vs 6 for a live user). The "must shadow HKLM AND have a
# server override" gate is unchanged, as are both severities and both fix actions.
$comTopSeen = 0
$comShadow  = 0
$comHivesLooked = 0
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.ClassesHivePath) { continue }   # no per-user class store reachable: we could not look
    $hkcuClsid = "$($zbHive.ClassesHivePath)\CLSID"
    if (-not (Test-Path $hkcuClsid)) { continue }
    $comHivesLooked++
    # Per-user COM registration (<user>\Classes\CLSID) is NORMAL — Teams add-ins, Office, OneDrive,
    # .NET and shell extensions all register here. The actual COM-hijack technique (T1546.015) is a
    # per-user CLSID that SHADOWS a CLSID already registered in HKLM (so the per-user one wins at load
    # time). So: only enumerate top-level {GUID} keys (NOT -Recurse, which flooded every InprocServer32/
    # ProgID/TypeLib subkey as a separate finding), and escalate ONLY when the same CLSID exists in
    # HKLM. A purely per-user CLSID with no HKLM twin is review-only (POSSIBLE + Info), never auto-acted.
    $comTopKeys = @(Get-ChildItem -Path $hkcuClsid -ErrorAction SilentlyContinue)
    $comTopSeen += $comTopKeys.Count
    foreach ($k in $comTopKeys) {
        $guid = $k.PSChildName
        if ($guid -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { continue }   # only real CLSID GUID keys
        $shadowsHklm = (Test-Path "HKLM:\SOFTWARE\Classes\CLSID\$guid") -or `
                       (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID\$guid")
        $inproc = (Get-RegVal -Path "$($k.PSPath)\InprocServer32" -Name "(default)")
        if (-not $inproc) { $inproc = (Get-RegVal -Path "$($k.PSPath)\LocalServer32" -Name "(default)") }
        # ID was "COM_<guid>", which collapsed every profile's copy of a CLSID into ONE finding
        # via Add-Finding's de-dupe — it now carries the SID.
        $zbComId = "COM_$($guid -replace '[^a-z0-9]','')_$(Get-StableId "$($zbHive.Sid)")"
        # PSPath is provider-qualified; the server's Test-ProtectedTarget P1 guards (service hives,
        # and the HARD block on ZB_UC_* mounts that no longer exist at remediation time) are ANCHORED
        # at '^Registry::', so a provider-qualified FixParam would slip straight past them.
        $zbComPs = "$($k.PSPath)" -replace '^Microsoft\.PowerShell\.Core\\Registry::', 'Registry::'
        if ($shadowsHklm -and $inproc) {
            # Real hijack: a per-user CLSID overriding a system-registered COM object WITH an actual
            # server path (Inproc/LocalServer32). A CLSID that merely shadows HKLM but has NO server
            # override (null Inproc/Local) is not a functioning hijack — it's a benign per-user shell
            # CLSID key holding only settings/sub-keys (e.g. {031E4825-...}/{86ca1aa0-...}) — review only.
            Out-Decrypt -Text "[$($zbHive.User)] $zbComPs" -Prefix "  [COM HIJACK] "
            $comShadow++
            $global:ZB_ComHijackConfirmedClsids[$guid.ToUpper()] = $zbComPs
            # A FixParam must never point into a ZB_UC_* mount — remediation runs in a later process.
            $zbComAct  = "DeleteRegKey"
            $zbComFp   = $zbComPs
            $zbComHint = ""
            if ($zbHive.Source -eq 'RegLoad') {
                $zbComAct  = "Info"
                $zbComFp   = ""
                $zbComHint = " That profile's class store is only temporarily mounted by this scan — remove by hand after re-mounting it (reg load / Remove-Item -Recurse / reg unload)."
            }
            Add-Finding -ID $zbComId -Phase "PHASE 24" -ThreatType "COM Hijack" `
                -Severity $SEV_HIGH -Description "User $($zbHive.User) [hive source: $($zbHive.Source)]: per-user COM override SHADOWS an HKLM-registered CLSID with a per-user server override (COM hijack persistence): $guid -> $inproc$zbComHint" `
                -Target "[$($zbHive.User)] $zbComPs" -FixAction $zbComAct -FixParam $zbComFp -Group "COM Object Hijacks"
        } else {
            # Pure per-user registration (no HKLM twin) — normal for add-ins; surface for review only.
            Add-Finding -ID $zbComId -Phase "PHASE 24" -ThreatType "COM Hijack" `
                -Severity $SEV_POSSIBLE -Description "User $($zbHive.User) [hive source: $($zbHive.Source)]: per-user COM registration (review — usually a legit add-in): $guid -> $inproc" `
                -Target "[$($zbHive.User)] $zbComPs" -FixAction "Info" -Group "COM Object Hijacks"
        }
    }
}
if ($comHivesLooked -eq 0) { Out-Typewriter "  -> [OK] NO PER-USER CLSID STORE READABLE." "GOOD" }
elseif ($comTopSeen -eq 0) { Out-Typewriter "  -> [OK] NO PER-USER COM OVERRIDES." "GOOD" }
else { Out-Typewriter ("  -> COM AUDIT: {0} per-user CLSID(s) across {1} profile(s), {2} shadowing HKLM." -f $comTopSeen, $comHivesLooked, $comShadow) "VER" }

Show-PhaseHeader "PHASE 25" "GPO LOCKDOWN — TASKMGR/REGEDIT/CMD DISABLED"
# P1 multi-user: the per-user half read a bare HKCU:, i.e. the TECHNICIAN's hive — a
# ransomware/RAT lockdown of the VICTIM's Task Manager / RegEdit / CMD reported clean. The
# HKLM half is MACHINE scope and is still read exactly ONCE, outside the profile loop, so a
# box with 8 profiles reports a machine-wide lockdown once, not 8 times.
# ID: "GPO_<pol>" was per-policy only and would have collapsed every user's copy into one via
# Add-Finding's de-dupe; it now carries the SID. The HKLM twin "GPO_M_<pol>" is genuinely
# machine-unique and is left exactly as it was (baseline-stable).
$gpoM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$gpoRel = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
foreach ($pol in @("DisableTaskMgr","DisableRegistryTools","DisableCMD")) {
    foreach ($zbHive in @(Get-UserHives)) {
        if (-not $zbHive.HivePath) { continue }   # not mounted and loading is off: we could not look
        $gpoU = "$($zbHive.HivePath)\$gpoRel"
        $vU = (Get-RegVal -Path $gpoU -Name $pol)
        if ($vU -ne 1) { continue }
        # A FixParam must never point into a ZB_UH_* mount — remediation runs in a later process.
        $zbGpoAct  = "DeleteReg"
        $zbGpoFp   = "$gpoU|$pol"
        $zbGpoHint = ""
        if ($zbHive.Source -eq 'RegLoad') {
            $zbGpoAct  = "Info"
            $zbGpoFp   = ""
            $zbGpoHint = " That profile's hive is only temporarily mounted by this scan — clear by hand with reg load HKU\ZBFIX / Remove-ItemProperty / reg unload HKU\ZBFIX."
        }
        Out-Typewriter "  -> $pol DISABLED FOR USER $($zbHive.User)" "CRIT"
        Add-Finding -ID "GPO_$($pol)_$(Get-StableId "$($zbHive.Sid)")" -Phase "PHASE 25" -ThreatType "GPO Lockdown (Malware)" -Severity $SEV_HIGH `
            -Description "User $($zbHive.User) [hive source: $($zbHive.Source)]: GPO policy $pol = 1 in that user's hive — malware commonly disables Task Manager/RegEdit/CMD$zbGpoHint" `
            -Target "[$($zbHive.User)] $gpoU|$pol" -FixAction $zbGpoAct -FixParam $zbGpoFp -Group "GPO / Policy Lockdowns"
    }
    $vM = (Get-RegVal -Path $gpoM -Name $pol)
    if ($vM -eq 1) {
        Out-Typewriter "  -> $pol DISABLED (HKLM)" "CRIT"
        Add-Finding -ID "GPO_M_$pol" -Phase "PHASE 25" -ThreatType "GPO Lockdown (Malware)" -Severity $SEV_HIGH `
            -Description "[MACHINE] GPO policy $pol = 1 (HKLM, applies to every user) — may be malware-imposed lockdown" `
            -Target "[MACHINE] $gpoM|$pol" -FixAction "DeleteReg" -FixParam "$gpoM|$pol" -Group "GPO / Policy Lockdowns"
    }
}
Out-Typewriter "  -> GPO POLICY AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 26" "BROWSER HELPER OBJECT (BHO) PURGE"
$bhoPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects")
foreach ($bho in $bhoPaths) {
    if (Test-Path $bho) {
        # Registry keys have no .LastWriteTime property — that read was silently $null (admits
        # everything). Get-RegKeyLastWriteTime (RegQueryInfoKey) makes the time-scope filter real;
        # a $null (P/Invoke failure) still admits the key, so this only ever narrows, fail-open.
        $bhoKeys = Get-ChildItem -Path $bho -ErrorAction SilentlyContinue | Where-Object { Test-InScope (Get-RegKeyLastWriteTime $_) }
        foreach ($k in $bhoKeys) {
            Out-Decrypt -Text $k.Name -Prefix "  [BHO HIT] "
            # BHOs are a legacy IE hijack vector, but legitimate ones exist (Adobe PDF, Office/Lync,
            # Java, AV toolbars). A registered BHO alone isn't proof of a hijacker, so surface for
            # REVIEW (POSSIBLE + Info) rather than blanket-deleting every BHO key automatically.
            Add-Finding -ID "BHO_$($k.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 26" -ThreatType "Browser Hijacker/BHO" `
                -Severity $SEV_POSSIBLE -Description "Browser Helper Object registered (review — legit BHOs exist for Adobe/Office/Java/AV; NOT auto-removed): $($k.Name)" `
                -Target $k.PSPath -FixAction "Info" -Group "Browser Helper Objects"
            $global:SpywareHits++
        }
        if ($bhoKeys.Count -eq 0) { Out-Typewriter "  -> [OK] BHO HIVE SECURE." "GOOD" }
    }
}

}   # end QUICK-skip block
Show-PhaseHeader "PHASE 27" "SAFE MODE HIJACK (SAFEBOOT KEY AUDIT)"
foreach ($sm in @("Minimal","Network")) {
    $safePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$sm"
    if (Test-Path $safePath) {
        # Windows ships ~60-120 legitimate default SafeBoot\Minimal|Network entries (services,
        # service-groups, and *.sys drivers that must load in Safe Mode). Flagging them all CRITICAL +
        # DeleteRegKey would (absent the safety guard) offer to break Safe Mode boot. Skip the known
        # defaults; surface only *unrecognized* entries as POSSIBLE for manual review (the SafeBoot
        # registry is also a Test-ProtectedTarget hard-block, so this is purely noise reduction).
        # Key write time now read for real via RegQueryInfoKey (was a $null no-op property read).
        $safeKeys = Get-ChildItem -Path $safePath -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -notmatch "^{" -and (Test-InScope (Get-RegKeyLastWriteTime $_)) -and ($_.PSChildName.ToLower() -notin $SAFEBOOT_DEFAULTS) }
        foreach ($k in $safeKeys) {
            Out-Decrypt -Text $k.PSPath -Prefix "  [SAFEMODE PERSIST] "
            Add-Finding -ID "SAFEBOOT_$($k.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 27" -ThreatType "SafeBoot Hijack" `
                -Severity $SEV_POSSIBLE -Description "Unrecognized entry in SafeBoot\${sm}: $($k.PSChildName) — verify (possible SafeBoot persistence)" `
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1400 }
# Path test anchored to COMPONENTS (was a bare "AppData|Temp" substring, which also matched
# "C:\Program Files\Temperature Monitor\...", anything under a "Templates" folder, etc.), and
# `\.js` anchored so it no longer matches a ".json" config in an ImagePath. The two signals are
# now graded separately, because only one of them is safe to auto-fire a permanent service
# delete on (rule #1 — a legitimate signed backup/VPN helper installed under AppData must not
# be `sc.exe delete`d by an auto-select on a healthy box):
#   LOLBin / script-host ImagePath -> genuinely abnormal for a Win32 service -> CRITICAL + RunCmd
#   user-path ImagePath only       -> Authenticode decides: signed = POSSIBLE + Info (review only)
$svcLolbinRe   = 'cmd\.exe|powershell|wscript|cscript|mshta|\.js\b|\.vbs\b|rundll32|regsvr32|certutil'
$allServices   = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue
$rogueServices = @($allServices | Where-Object { $_.ImagePath -match $svcLolbinRe -or $_.ImagePath -match $global:USER_PATH_RE })
if ($rogueServices.Count -eq 0) { Out-Typewriter "  -> [OK] NO ANOMALOUS SERVICES." "GOOD" }
foreach ($svc in $rogueServices) {
    $svcLolbin = ($svc.ImagePath -match $svcLolbinRe)
    $svcSigned = $false
    if (-not $svcLolbin) {
        # Pull the bare binary out of the ImagePath (may be quoted and carry arguments).
        # Single call on an already-matched service — no SIG_AUDIT budget needed.
        $svcBin = ''
        if ("$($svc.ImagePath)" -match '([a-zA-Z]:\\[^"]+?\.(?:exe|sys|dll|com|scr))') { $svcBin = $Matches[1] }
        if ($svcBin -and (Test-Path -LiteralPath $svcBin)) {
            $ssig = Get-AuthSig $svcBin
            $svcSigned = ($ssig -and $ssig.Status -eq 'Valid')
        }
    }
    if ($svcSigned) {
        Out-Decrypt -Text "$($svc.PSChildName) = $($svc.ImagePath)" -Prefix "  [USER-PATH SERVICE] "
        Add-Finding -ID "SVC_$($svc.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 28" -ThreatType "Malicious Service" `
            -Severity $SEV_POSSIBLE -Description "Service runs from a user-writable path but its binary is validly signed (common for third-party helper services — review only, never auto-deleted): $($svc.PSChildName) | ImagePath: $($svc.ImagePath)" `
            -Target "Service: $($svc.PSChildName)" -FixAction "Info" -Group "Rogue Services"
        continue
    }
    Out-Decrypt -Text "$($svc.PSChildName) = $($svc.ImagePath)" -Prefix "  [ROGUE SERVICE] "
    # Double any embedded single quote before interpolating into the single-quoted PS
    # strings of the fix command — a registry key name is attacker-controllable text and
    # would otherwise break out of the string (same class as the Phase 26 .lnk fix).
    $svcNameEsc = "$($svc.PSChildName)" -replace "'","''"
    Add-Finding -ID "SVC_$($svc.PSChildName -replace '[^a-z0-9]','')" -Phase "PHASE 28" -ThreatType "Malicious Service" `
        -Severity $SEV_CRITICAL -Description "Rogue service: $($svc.PSChildName) | ImagePath: $($svc.ImagePath)" `
        -Target "Service: $($svc.PSChildName)" -FixAction "RunCmd" `
        -FixParam "Stop-Service '$svcNameEsc' -Force; Set-Service '$svcNameEsc' -StartupType Disabled; sc.exe delete '$svcNameEsc'" `
        -Group "Rogue Services"
}

Show-PhaseHeader "PHASE 29" "TASK SCHEDULER DEEP AUDIT"
Out-Typewriter "DUMPING SCHEDULED TASK MANIFESTS..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1400 }
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch "\\Microsoft\\" }
foreach ($task in $tasks) {
    $exe = $task.Actions[0].Execute; $args = $task.Actions[0].Arguments
    $taskAction = "$exe $args"
    # Split into STRONG and WEAK indicators. The old single regex matched a bare "cmd"
    # (hits any path containing those three letters), a bare "AppData|Temp" substring, and
    # an unanchored "\.js" (matches ".json") — and every match auto-fired an
    # Unregister-ScheduledTask at CRITICAL. Practically every third-party auto-updater
    # executes from AppData or shells through cmd.exe, so that is a healthy-box auto-action
    # (rule #1). The sibling task-XML content check below was already downgraded for this
    # exact reason; this brings the action check in line.
    #   STRONG = obfuscation / remote-payload / scriptlet execution — malicious in a task
    #   WEAK   = merely runs from a user path or shells via cmd.exe -> Authenticode decides
    $taskStrongRe = 'mshta|wscript|cscript|regsvr32|certutil|powershell[^;]*-enc|powershell[^;]*\benc\w*\b|powershell[^;]*-nop|\bIEX\b|DownloadString|DownloadFile|EncodedCommand|FromBase64String|\brundll32\b[^,]*,|scrobj|\.hta\b|\.vbs\b|\.jse\b|\.wsf\b'
    $taskWeakRe   = '\bcmd\.exe\b|\.js\b|' + $global:USER_PATH_RE
    $taskStrong   = ($taskAction -match $taskStrongRe)
    $taskWeak     = ($taskAction -match $taskWeakRe)
    if ($taskStrong -or $taskWeak) {
        $taskNameEsc = $task.TaskName -replace "'","''"
        $taskFix     = "Unregister-ScheduledTask -TaskName '$taskNameEsc' -Confirm:`$false -ErrorAction SilentlyContinue"
        $taskSigned  = $false
        $taskBinFound = $false
        if (-not $taskStrong -and $exe) {
            # Single sig call on an already-matched task — no SIG_AUDIT budget needed.
            $taskBin = [Environment]::ExpandEnvironmentVariables("$exe").Trim('"')
            if ($taskBin -and (Test-Path -LiteralPath $taskBin)) {
                $taskBinFound = $true
                $tsig = Get-AuthSig $taskBin
                $taskSigned = ($tsig -and $tsig.Status -eq 'Valid')
            }
        }
        if ($taskStrong) {
            Out-Decrypt -Text $task.TaskName -Prefix "  [ROGUE TASK] "
            Add-Finding -ID "TASK_$($task.TaskName -replace '[^a-z0-9]','')" -Phase "PHASE 29" -ThreatType "Task Persistence" `
                -Severity $SEV_CRITICAL -Description "Malicious scheduled task (obfuscated / remote-payload action): $($task.TaskName) | Exe: $taskAction" `
                -Target "Task: $($task.TaskName)" -FixAction "RunCmd" -FixParam $taskFix `
                -Group "Scheduled Task Persistence"
        } elseif ($taskSigned -or -not $taskBinFound) {
            # "binary not resolvable" is NOT evidence of anything: a bare `cmd.exe` with no path
            # and a stale task left by an uninstalled program both land here on a healthy box,
            # and auto-unregistering them is a destructive action on a clean machine.
            Add-Finding -ID "TASK_$($task.TaskName -replace '[^a-z0-9]','')" -Phase "PHASE 29" -ThreatType "Task Persistence" `
                -Severity $SEV_POSSIBLE -Description "Scheduled task runs from a user path / via cmd.exe and is $(if ($taskSigned) { 'validly signed' } else { 'pointing at a binary that could not be resolved' }) — normal for third-party updaters and for stale tasks left by uninstalled software; review only, never auto-unregistered: $($task.TaskName) | Exe: $taskAction" `
                -Target "Task: $($task.TaskName)" -FixAction "Info" -Group "Scheduled Task Persistence"
        } else {
            Out-Decrypt -Text $task.TaskName -Prefix "  [UNSIGNED TASK] "
            Add-Finding -ID "TASK_$($task.TaskName -replace '[^a-z0-9]','')" -Phase "PHASE 29" -ThreatType "Task Persistence" `
                -Severity $SEV_HIGH -Description "Scheduled task with an unsigned binary running from a user path / via cmd.exe: $($task.TaskName) | Exe: $taskAction" `
                -Target "Task: $($task.TaskName)" -FixAction "RunCmd" -FixParam $taskFix `
                -Group "Scheduled Task Persistence"
        }
    }
}
foreach ($td in @("$env:WINDIR\System32\Tasks","$env:WINDIR\SysWOW64\Tasks")) {
    if (Test-Path $td) {
        $taskFiles = Get-ChildItem -Path $td -Recurse -File -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
        foreach ($tf in $taskFiles) {
            # Skip first-party Windows tasks (\Tasks\Microsoft\...) — mirror the action-loop's
            # \Microsoft\ exclusion above. Their XML legitimately contains 'Temp'/'AppData' substrings
            # (CleanupTemporaryState, TempSignedLicenseExchange, Active Directory RMS Client, ...), so
            # the bare content heuristic floods them HIGH+DeleteFile on every healthy box.
            if ($tf.FullName -match '\\Tasks\\Microsoft\\') { continue }
            $content = Get-Content $tf.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match "AppData|Temp|powershell.*-enc|IEX|wscript|mshta") {
                Out-Decrypt -Text $tf.FullName -Prefix "  [TASK FILE] "
                # On-disk XML content match is a weak corroborating signal (the authoritative detection
                # is the action-based CRITICAL finding above) — review-only, never an auto-delete of a
                # task file (System32\Tasks is hard-protected anyway).
                Add-Finding -ID "TASKFILE_$($tf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 29" -ThreatType "Task Persistence" `
                    -Severity $SEV_POSSIBLE -Description "Task XML on disk references Temp/AppData/script host (review — weak signal; the action-based check flags genuinely-malicious non-Microsoft tasks): $($tf.FullName)" `
                    -Target $tf.FullName -FixAction "Info" -Group "Scheduled Task Persistence"
            }
        }
    }
}
Out-Typewriter "  -> TASK AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 30" "WMI EVENT FILTER / CONSUMER / BINDING AUDIT"
Out-Typewriter "ANALYZING ROOT\SUBSCRIPTION NAMESPACE..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1400 }
# EVIDENCE_ENGINE_PLAN P11 — this phase was a LIVE rule #1 violation, reproduced on this box:
# every WMI subscription object was graded CRITICAL + RunCmd (Remove-WmiObject), i.e. AUTO-
# SELECTED for destructive remediation. Filters were name-filtered by the substring test
# `-notmatch "BVTFilter|SCM"` and consumers had no filter at all, so a stock Windows install —
# which ships the "SCM Event Log Filter"/"SCM Event Log Consumer"/binding trio in
# root\subscription — produced an auto-selected "delete this" finding for the CONSUMER on a
# perfectly healthy machine. SCCM, Dell Command | Update, HP, Lenovo Vantage and several backup
# agents register subscriptions too.
#
# Two changes, per the user's decision 2026-07-26:
#  1. DEMOTED. An unallowlisted subscription is now POSSIBLE + FixAction Info, with the
#     Remove-WmiObject teardown put in the DESCRIPTION for an operator to run by hand. Nothing
#     in this phase can be auto-selected any more. There is no SCCM-managed box available to
#     re-grade against, which is precisely why the demotion — not a bigger allowlist — is the
#     safety mechanism.
#  2. ALLOWLISTED, but anchored to the ENTIRE benign shape. The old substring test was itself a
#     self-allowlisting hole: any filter named "SCM_Updater" was silently excluded. Each object
#     is now flattened to a composite `name|namespace|query` / `class|name|action` /
#     `filterRef|consumerRef` string and matched against ^...$-anchored patterns from
#     data\detection_signatures.json, so an attacker cannot get allowlisted by NAMING itself
#     after a vendor — the query/command line has to match too. "BVTFilter" is deliberately NOT
#     allowlisted: BVTFilter/BVTConsumer is the MSDN sample WMI-persistence malware copy-pastes.
#
# Also fixed: $wmiBindings was fetched and used only in a zero-count test. The
# __FilterToConsumerBinding is the object that actually ARMS the persistence — it now produces
# its own finding, and every suggested teardown removes BINDING first, then CONSUMER, then
# FILTER (the old generated fix deleted filter+consumer and orphaned the binding).
$WMI_ALLOW_FILTER_RE   = Join-AllowRegex 'wmi_subscription_allow_filters'
$WMI_ALLOW_CONSUMER_RE = Join-AllowRegex 'wmi_subscription_allow_consumers'
$WMI_ALLOW_BINDING_RE  = Join-AllowRegex 'wmi_subscription_allow_bindings'
# Flatten a WMI object's properties to a name->string map without touching a property that may
# not exist on the derived class (ManagementObject throws on a missing property, and -EA
# SilentlyContinue does not suppress that).
function Get-ZbWmiProps {
    param($zbObj)
    $zbMap = @{}
    try { foreach ($zbP in $zbObj.Properties) { $zbMap["$($zbP.Name)"] = "$($zbP.Value)" } } catch {}
    return $zbMap
}
function ConvertTo-ZbWmiFlat { param([string]$zbText) return (("$zbText" -replace '[\r\n]+',' ') -replace '\s{2,}',' ').Trim() }
$wmiFilters   = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter               -ErrorAction SilentlyContinue)
$wmiConsumers = @(Get-WmiObject -Namespace root\subscription -Class __EventConsumer             -ErrorAction SilentlyContinue)
$wmiBindings  = @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding   -ErrorAction SilentlyContinue)
$wmiAllowed = 0
$wmiFlagged = 0
if (($wmiFilters.Count + $wmiConsumers.Count + $wmiBindings.Count) -eq 0) {
    Out-Typewriter "  -> [OK] NO WMI EVENT SUBSCRIPTIONS PRESENT." "GOOD"
} else {
    foreach ($f in $wmiFilters) {
        $fp    = Get-ZbWmiProps $f
        $fName = "$($fp['Name'])"
        $fFlat = ConvertTo-ZbWmiFlat "$fName|$($fp['EventNamespace'])|$($fp['Query'])"
        if ($fFlat -match $WMI_ALLOW_FILTER_RE) { $wmiAllowed++; continue }
        $wmiFlagged++
        $fEsc = $fName -replace "'","''"
        Out-ThreatBanner "WMI EVENT FILTER (PERSISTENCE)" "Name: $fName"
        Add-Finding -ID "WMI_F_$(Get-StableId $fFlat)" -Phase "PHASE 30" -ThreatType "WMI Persistence" `
            -Severity $SEV_POSSIBLE `
            -Description "WMI EventFilter not on the known-good allowlist: '$fName' | namespace: $($fp['EventNamespace']) | query: $($fp['Query']). Management suites (SCCM, Dell/HP/Lenovo agents, backup products) DO register subscriptions legitimately, so this is review-only and is never auto-removed. If confirmed malicious, tear the subscription down in this order — BINDING first, then CONSUMER, then FILTER: Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { `$_.Filter -like '*`"$fEsc`"*' } | Remove-WmiObject ; then remove the consumer it referenced ; then Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { `$_.Name -eq '$fEsc' } | Remove-WmiObject" `
            -Target "WMI Filter: $fName" -FixAction "Info" -Group "WMI Persistence"
    }
    foreach ($c in $wmiConsumers) {
        $cp    = Get-ZbWmiProps $c
        $cName = "$($cp['Name'])"
        # The consumer's ACTION is what matters; the property differs per subclass. Pin all of
        # them into the composite so an allowlist entry has to match the command line / script /
        # event source too, not just the vendor-shaped name.
        $cActParts = New-Object System.Collections.Generic.List[string]
        foreach ($cKey in @('ExecutablePath','CommandLineTemplate','ScriptFileName','ScriptText','FileName','Text','SourceName','ToLine')) {
            if ($cp.ContainsKey($cKey) -and "$($cp[$cKey])") { $cActParts.Add("$cKey=$($cp[$cKey])") }
        }
        $cFlat = ConvertTo-ZbWmiFlat "$($c.__CLASS)|$cName|$($cActParts -join ';')"
        if ($cFlat -match $WMI_ALLOW_CONSUMER_RE) { $wmiAllowed++; continue }
        $wmiFlagged++
        $cEsc = $cName -replace "'","''"
        Out-ThreatBanner "WMI EVENT CONSUMER (PERSISTENCE)" "Name: $cName"
        Add-Finding -ID "WMI_C_$(Get-StableId $cFlat)" -Phase "PHASE 30" -ThreatType "WMI Persistence" `
            -Severity $SEV_POSSIBLE `
            -Description "WMI EventConsumer not on the known-good allowlist: [$($c.__CLASS)] '$cName' | action: $($cActParts -join '; '). Review-only — management/backup agents register consumers legitimately, so this is never auto-removed. If confirmed malicious, remove the BINDING that references it FIRST, then: Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Where-Object { `$_.Name -eq '$cEsc' } | Remove-WmiObject ; then the filter." `
            -Target "WMI Consumer: $cName" -FixAction "Info" -Group "WMI Persistence"
    }
    foreach ($b in $wmiBindings) {
        $bp    = Get-ZbWmiProps $b
        $bFlat = ConvertTo-ZbWmiFlat "$($bp['Filter'])|$($bp['Consumer'])"
        if ($bFlat -match $WMI_ALLOW_BINDING_RE) { $wmiAllowed++; continue }
        $wmiFlagged++
        $bfEsc = "$($bp['Filter'])"   -replace "'","''"
        $bcEsc = "$($bp['Consumer'])" -replace "'","''"
        Out-ThreatBanner "WMI FILTER-TO-CONSUMER BINDING (ARMED PERSISTENCE)" $bFlat
        Add-Finding -ID "WMI_B_$(Get-StableId $bFlat)" -Phase "PHASE 30" -ThreatType "WMI Persistence" `
            -Severity $SEV_POSSIBLE `
            -Description "WMI __FilterToConsumerBinding not on the known-good allowlist — this is the object that actually ARMS a WMI subscription; a filter or consumer on its own does nothing without it. Filter: $($bp['Filter']) -> Consumer: $($bp['Consumer']). Review-only, never auto-removed. Correct manual teardown order is BINDING, then CONSUMER, then FILTER: Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { `$_.Filter -eq '$bfEsc' -and `$_.Consumer -eq '$bcEsc' } | Remove-WmiObject" `
            -Target "WMI Binding: $($bp['Filter']) -> $($bp['Consumer'])" -FixAction "Info" -Group "WMI Persistence"
    }
    if ($wmiFlagged -eq 0) {
        Out-Typewriter "  -> [OK] WMI SUBSCRIPTIONS CLEAN ($wmiAllowed known-good object(s) allowlisted)." "GOOD"
    } else {
        Out-Typewriter "  -> $wmiFlagged UNRECOGNISED WMI SUBSCRIPTION OBJECT(S) FLAGGED FOR REVIEW ($wmiAllowed allowlisted)." "WARN"
    }
}

Show-PhaseHeader "PHASE 31" "BITS / POWERSHELL PROFILE / STARTUP PERSISTENCE"
$bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.JobState -notmatch "Idle" }
foreach ($job in $bitsJobs) {
    Out-Decrypt -Text $job.DisplayName -Prefix "  [BITS JOB] "
    # A BITS job is corroborating evidence, not a standalone HIGH — every Windows/Edge/Office/
    # Google updater uses BITS, so flagging all non-idle jobs floods CRITICAL FPs. Escalate to
    # HIGH + auto-removable only when a transfer's remote URL is a raw IP, or it stages an
    # executable/script into a user-writable path; otherwise POSSIBLE + Info (shown, not auto-acted).
    $bitsSusp = $false; $bitsWhy = ""
    foreach ($bf in @($job.FileList)) {
        if ("$($bf.RemoteName)" -match $BITS_SUSP_REMOTE_RE) { $bitsSusp = $true; $bitsWhy = "raw-IP remote: $($bf.RemoteName)"; break }
        if ("$($bf.LocalName)"  -match $BITS_SUSP_LOCAL_RE)  { $bitsSusp = $true; $bitsWhy = "stages executable to user path: $($bf.LocalName)"; break }
    }
    if ($bitsSusp) {
        Add-Finding -ID "BITS_$($job.JobId)" -Phase "PHASE 31" -ThreatType "BITS Persistence" -Severity $SEV_HIGH `
            -Description "Suspicious BITS transfer ($bitsWhy): $($job.DisplayName) | State: $($job.JobState)" `
            -Target "BITS Job: $($job.JobId)" -FixAction "RunCmd" -FixParam "Remove-BitsTransfer -BitsJob (Get-BitsTransfer -AllUsers | Where-Object JobId -eq '$($job.JobId)')" `
            -Group "BITS / Profile Persistence"
    } else {
        Add-Finding -ID "BITS_$($job.JobId)" -Phase "PHASE 31" -ThreatType "BITS Persistence" -Severity $SEV_POSSIBLE `
            -Description "Active BITS transfer (likely an app/OS updater — review): $($job.DisplayName) | State: $($job.JobState)" `
            -Target "BITS Job: $($job.JobId)" -FixAction "Info" `
            -Group "BITS / Profile Persistence"
    }
}
if ($bitsJobs.Count -eq 0) { Out-Typewriter "  -> [OK] NO ROGUE BITS JOBS." "GOOD" }
# P1 multi-user — PowerShell profile persistence.
#
# $PROFILE is a POWERSHELL AUTOMATIC VARIABLE describing THIS process, so its CurrentUser* members
# named the TECHNICIAN's profile scripts under RunAs and a profile.ps1 backdoor in the victim's
# Documents folder reported clean. NOTE THE NAMING HAZARD: the engine is ONE dot-sourced scope and
# PowerShell variables are case-insensitive, so any local called $profile WOULD SILENTLY DESTROY
# $PROFILE for this phase and every later one, with no error. Every local below is $zb*-prefixed.
#
# AllUsersAllHosts / AllUsersCurrentHost are MACHINE scope (they live under $PSHOME) and are
# enumerated exactly ONCE. The current user's CurrentUser* members are kept verbatim because they
# are authoritative for THIS host; for every other profile the equivalent paths must be
# CONSTRUCTED under that user's redirection-aware Documents folder — there is no way to ask
# PowerShell for another user's $PROFILE. Both the Windows PowerShell 5.1 (WindowsPowerShell) and
# the PowerShell 7 (PowerShell) directories are covered, with the AllHosts (profile.ps1) and the
# two CurrentHost names, deduped case-insensitively against the current user's real values.
$zbPsProfTargets = @()
foreach ($zbMp in @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost)) {
    if ($zbMp) { $zbPsProfTargets += @{ Path = "$zbMp"; User = 'MACHINE'; Sid = 'MACHINE' } }
}
foreach ($zbHive in @(@(Get-UserHives) | Sort-Object -Property Sid)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp -or -not $zbUp.Documents) { continue }
    $zbProfPaths = @()
    if ($zbHive.IsCurrent) {
        foreach ($zbCp in @($PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)) {
            if ($zbCp) { $zbProfPaths += "$zbCp" }
        }
    }
    foreach ($zbPsDir in @('WindowsPowerShell','PowerShell')) {
        foreach ($zbPsName in @('profile.ps1','Microsoft.PowerShell_profile.ps1','Microsoft.PowerShellISE_profile.ps1')) {
            try { $zbProfPaths += (Join-Path (Join-Path $zbUp.Documents $zbPsDir) $zbPsName) } catch {}
        }
    }
    $zbSeenProf = @{}
    foreach ($zbPp in $zbProfPaths) {
        if (-not $zbPp) { continue }
        $zbPpKey = "$zbPp".ToLowerInvariant()
        if ($zbSeenProf.ContainsKey($zbPpKey)) { continue }
        $zbSeenProf[$zbPpKey] = $true
        $zbPsProfTargets += @{ Path = "$zbPp"; User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
    }
}
foreach ($zbPt in $zbPsProfTargets) {
    $zbProfFile = $zbPt.Path
    if (Test-Path $zbProfFile) {
        $content = Get-Content $zbProfFile -Raw -ErrorAction SilentlyContinue
        if ($content -match "IEX|DownloadString|WebClient|Invoke-Expression|Start-Process.*hidden") {
            Out-Typewriter "  -> MALICIOUS PROFILE: [$($zbPt.User)] $zbProfFile" "CRIT"
            # ID was the flattened path, which happened to differ per user but only by accident of
            # the path text; keyed on SID + path now so it cannot collide.
            Add-Finding -ID "PSPROFILE_$(Get-StableId "$($zbPt.Sid)|$zbProfFile")" -Phase "PHASE 31" -ThreatType "PS Profile Persistence" `
                -Severity $SEV_CRITICAL -Description "User $($zbPt.User): malicious content in PS profile: $zbProfFile" `
                -Target "[$($zbPt.User)] $zbProfFile" -FixAction "DeleteFile" -FixParam $zbProfFile -Group "BITS / Profile Persistence"
        }
    }
}
# Startup FOLDER persistence. The per-user Startup folder is resolved redirection-aware from
# Get-UserPaths; the all-users Startup folder under $env:ALLUSERSPROFILE is MACHINE scope and is
# added exactly ONCE, outside the profile set.
$zbStartupTargets = @()
foreach ($zbHive in @(@(Get-UserHives) | Sort-Object -Property Sid)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp -or -not $zbUp.Startup) { continue }
    $zbStartupTargets += @{ Path = "$($zbUp.Startup)"; User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
}
$zbStartupTargets += @{ Path = "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"; User = 'MACHINE'; Sid = 'MACHINE' }
foreach ($zbSp in $zbStartupTargets) {
    $sp = $zbSp.Path
    if (Test-Path $sp) {
        $startItems = Get-ChildItem -Path $sp -File -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
        foreach ($si in $startItems) {
            # ID was "STARTUP_<flattened filename>" — filename-only. Every profile's copy of the
            # same startup shortcut name collapsed to ONE finding via Add-Finding's de-dupe, so on
            # a multi-profile box only the first user's persistence was ever reported. SID-keyed now.
            $zbStartupId = "STARTUP_$(Get-StableId "$($zbSp.Sid)|$($si.FullName)")"
            # .lnk shortcuts are never Authenticode-signed, so signing the shortcut itself flagged
            # every legitimate startup entry as UNSIGNED/HIGH. Judge the resolved TARGET instead;
            # an unresolvable target is review-only (POSSIBLE), never auto-deleted on a guess.
            if ($si.Extension -ieq '.lnk') {
                $tgt = $null
                try { $tgt = (New-Object -ComObject WScript.Shell).CreateShortcut($si.FullName).TargetPath } catch {}
                if (-not $tgt -or -not (Test-Path -LiteralPath $tgt)) {
                    Add-Finding -ID $zbStartupId -Phase "PHASE 31" -ThreatType "Startup Persistence" `
                        -Severity $SEV_POSSIBLE -Description "User $($zbSp.User): startup shortcut with unresolvable/missing target (review): $($si.Name) -> $(if ($tgt) { $tgt } else { '?' })" `
                        -Target "[$($zbSp.User)] $($si.FullName)" -FixAction "Info" -Group "Startup Folder Persistence"
                    continue
                }
                $asig = Get-AuthSig $tgt
                $tgtSusp = ($tgt -match '\\(AppData|Temp|Downloads|Desktop|Public|ProgramData)\\.*\.(exe|scr|com|pif)$') -or ($tgt -match '\.(js|vbs|bat|cmd|ps1|hta|wsf)$')
                # Unsigned target only stays HIGH when the target itself is in a drop location or is
                # a script — an unsigned app in Program Files is common and stays review-only.
                $sev = if ($asig.Status -ne 'Valid' -and $tgtSusp) { $SEV_HIGH } else { $SEV_POSSIBLE }
                Add-Finding -ID $zbStartupId -Phase "PHASE 31" -ThreatType "Startup Persistence" `
                    -Severity $sev -Description "User $($zbSp.User): startup shortcut: $($si.Name) -> $tgt (target $(if ($asig.Status -ne 'Valid') {'UNSIGNED'} else {'signed'}))$(if ($sev -ne $SEV_HIGH) { ' — POSSIBLE = review-only; select manually to remove the shortcut' })" `
                    -Target "[$($zbSp.User)] $($si.FullName)" -FixAction "DeleteFile" -FixParam $si.FullName -Group "Startup Folder Persistence"
                continue
            }
            $asig = Get-AuthSig $si.FullName
            $sev = if ($asig.Status -ne "Valid") { $SEV_HIGH } else { $SEV_POSSIBLE }
            Add-Finding -ID $zbStartupId -Phase "PHASE 31" -ThreatType "Startup Persistence" `
                -Severity $sev -Description "User $($zbSp.User): startup folder item: $($si.Name) ($(if ($asig.Status -ne 'Valid') {'UNSIGNED'} else {'signed'}))" `
                -Target "[$($zbSp.User)] $($si.FullName)" -FixAction "DeleteFile" -FixParam $si.FullName -Group "Startup Folder Persistence"
        }
    }
}

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 32" "DLL SEARCH ORDER HIJACK — PATH AUDIT"
Out-Typewriter "AUDITING WRITABLE PATH ENTRIES..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
$pathDirs = $env:PATH -split ";"
# SIG_AUDIT budget (CLAUDE.md: any loop calling Get-AuthSig over many files must carry it).
# Every writable PATH dir x every recent .dll is unbounded, and Authenticode performs online
# CRL/OCSP revocation checks that block ~15s each — a dev box with Git/Python/Node on PATH
# could stall this phase for many minutes. Mirrors the Phase 10/15 budget pattern.
$dllSigSeen = 0; $dllSigBudgetHit = $false
$dllSigSw   = [System.Diagnostics.Stopwatch]::StartNew()
foreach ($pd in $pathDirs) {
    if ($dllSigBudgetHit) { break }
    if (-not (Test-Path $pd)) { continue }
    # Skip OS system directories (System32/SysWOW64/WinSxS, all under %WINDIR%). They are admin-
    # writable by design and packed with catalog-signed DLLs — NOT the DLL-search-order hijack
    # vector (that's a NON-system writable dir earlier in PATH). Unsigned binaries planted in
    # System32 are already audited by Phase 15, so this is no coverage loss, just FP suppression.
    if ($pd.TrimEnd('\').ToLower().StartsWith($env:WINDIR.ToLower())) { continue }
    try {
        $testFile = "$pd\__zbtest_$(Get-Random).tmp"
        [IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        Out-Typewriter "  -> WRITABLE PATH ENTRY: $pd" "WARN"
        $recentDlls = Get-ChildItem -Path $pd -Filter "*.dll" -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.LastWriteTime }
        foreach ($dll in $recentDlls) {
            if ($dllSigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
                $dllSigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
                $dllSigBudgetHit = $true; break
            }
            $dllSigSeen++
            $asig = Get-AuthSig $dll.FullName
            if ($asig.Status -ne "Valid") {
                # An unsigned DLL in a writable PATH dir is corroborating evidence, NOT a standalone
                # auto-delete: legit dev tools (Git's mingw64\bin, Python, Node, Ruby) ship piles of
                # unsigned DLLs in their own install dirs that sit on PATH — auto-deleting them breaks
                # the install (rule #1: never damage the system). So POSSIBLE by default (surfaced for
                # review, never auto-selected), escalating to HIGH+DeleteFile only when the DLL sits in
                # a user-writable malware-staging dir (Temp/Downloads/AppData/ProgramData) — the actual
                # drop spots for a planted search-order-hijack DLL.
                $stagingDir = $dll.FullName -match '\\(temp|tmp|downloads|appdata|programdata|public)\\'
                Out-Decrypt -Text $dll.FullName -Prefix "  [UNSIGNED DLL IN PATH] "
                if ($stagingDir) {
                    Add-Finding -ID "DLLHIJACK_$($dll.Name -replace '[^a-z0-9]','')" -Phase "PHASE 32" -ThreatType "DLL Hijack" `
                        -Severity $SEV_HIGH -Description "Unsigned DLL in a user-writable PATH staging dir (possible search-order hijack): $($dll.FullName)" `
                        -Target $dll.FullName -FixAction "DeleteFile" -FixParam $dll.FullName -Group "DLL Hijack / PATH"
                } else {
                    Add-Finding -ID "DLLHIJACK_$($dll.Name -replace '[^a-z0-9]','')" -Phase "PHASE 32" -ThreatType "DLL Hijack" `
                        -Severity $SEV_POSSIBLE -Description "Unsigned DLL in a writable PATH dir (review — often a legit dev tool's own DLL): $($dll.FullName)" `
                        -Target $dll.FullName -FixAction "DeleteFile" -FixParam $dll.FullName -Group "DLL Hijack / PATH"
                }
            }
        }
    } catch { }
}
if ($dllSigBudgetHit) { Out-Typewriter "  -> SIGNATURE BUDGET REACHED — remaining PATH DLLs not signature-verified." "WARN" }
Out-Typewriter "  -> DLL PATH AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 32.5" "DLL SIDE-LOADING — SEARCH-ORDER HIJACK TARGET AUDIT"
Out-Typewriter "CHECKING SIGNED EXES FOR A CO-LOCATED HIJACK-TARGET DLL..." "HUNT"
# WS7 (T1574.002) — Phase 32 audits writable PATH dirs; this is the sibling technique: a
# well-known DLL-search-order-hijack TARGET filename (version.dll, dbghelp.dll, ...) dropped
# beside a legitimately-SIGNED EXE so the OS loader picks up the attacker DLL first instead of
# the real one. A bare unsigned-DLL-with-a-known-name hit is NOT enough on its own — portable
# apps (7-Zip/VLC/etc.) legitimately ship their own DLLs beside their EXE — so escalation to
# HIGH requires BOTH the DLL name AND the sibling EXE's own name to be on their respective
# lists AND the pair to sit directly in an AppData/Temp/ProgramData ROOT (not a nested,
# legitimate per-app install subfolder). Everything else stays POSSIBLE + Info (review only).
# P1 multi-user: four of the five walk roots were the technician's profile. $env:ProgramData is
# MACHINE scope and is added exactly ONCE. Single Get-ScanFiles call across all profiles.
$sideloadRoots = @(@(Get-ZbUserRootsM1 -Kind @('LocalAppData','AppData','Temp','Downloads')) + @($env:ProgramData) |
                   Where-Object { $_ } | Select-Object -Unique)
# $sideloadHardRoots is NOT a prefix list — it is used for an EXACT-ROOT equality test below
# ($sideloadHardRoots -contains $dirPath.TrimEnd('\').ToLower()), which is what distinguishes
# "the pair sits directly in an AppData/Temp/ProgramData ROOT" from "a nested, legitimate per-app
# install subfolder". That distinction is one of the two signals gating the HIGH escalation, so if
# it kept only the technician's roots it would simply NEVER match for any other profile and the
# escalation would silently stop firing there — a detection that looks present and is structurally
# dead. Every profile's LocalAppData/AppData/Temp is therefore included, machine ProgramData once.
# Note the Downloads root is deliberately absent here, exactly as before.
$sideloadHardRoots = @(@(Get-ZbUserRootsM1 -Kind @('LocalAppData','AppData','Temp')) + @($env:ProgramData) |
                       Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() } | Select-Object -Unique)
$candidateDlls = (Get-ScanFiles -Path $sideloadRoots -Filter '*.dll' -TimeScoped) | Where-Object { $SIDELOAD_TARGET_DLLS -contains $_.Name.ToLower() }
$sideloadSigSeen = 0; $sideloadSigBudgetHit = $false; $sideloadSigSw = [System.Diagnostics.Stopwatch]::StartNew()
$sideloadHits = 0
foreach ($cd in $candidateDlls) {
    if ($sideloadSigBudgetHit) { break }
    if ($sideloadSigSeen -ge $global:SIG_AUDIT_MAX_FILES -or $sideloadSigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
        $sideloadSigBudgetHit = $true; break
    }
    $sideloadSigSeen++
    $dllSig = Get-AuthSig $cd.FullName
    if ($dllSig -and $dllSig.Status -eq 'Valid') { continue }   # a validly-signed same-named DLL is a real vendor file, not a hijack
    $dirPath = $cd.DirectoryName
    $siblingExes = Get-ChildItem -LiteralPath $dirPath -Filter '*.exe' -File -ErrorAction SilentlyContinue
    foreach ($se in $siblingExes) {
        if ($sideloadSigSeen -ge $global:SIG_AUDIT_MAX_FILES -or $sideloadSigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
            $sideloadSigBudgetHit = $true; break
        }
        $sideloadSigSeen++
        $exeSig = Get-AuthSig $se.FullName
        if (-not ($exeSig -and $exeSig.Status -eq 'Valid')) { continue }   # base condition requires a SIGNED sibling EXE
        $exeNameLower  = $se.Name.ToLower()
        $isRootDir     = $sideloadHardRoots -contains $dirPath.TrimEnd('\').ToLower()
        $exeNameMatch  = $SIDELOAD_TARGET_EXES -contains $exeNameLower
        # A bare unsigned-DLL-with-a-known-name hit next to ANY signed EXE is not enough on its
        # own (portable/Electron apps routinely ship a same-named helper DLL beside a vendor EXE
        # the tool has never heard of) — require at least ONE corroborating signal (the sibling
        # EXE itself is a commonly-abused sideload target, OR the pair sits directly in an
        # AppData/Temp/ProgramData ROOT rather than a nested per-app install subfolder) before
        # emitting even the review-only POSSIBLE tier. HIGH still requires BOTH.
        if (-not ($exeNameMatch -or $isRootDir)) { continue }
        $sideloadHits++
        $zbSlOwn = Get-ZbOwnerM1 $cd.FullName
        if ($exeNameMatch -and $isRootDir) {
            Out-ThreatBanner "DLL SIDE-LOAD CANDIDATE" "[$($zbSlOwn.User)] $($se.Name) + $($cd.Name) in $dirPath"
            Add-Finding -ID "SIDELOAD_$(Get-StableId "$($cd.FullName)|$($se.FullName)")" -Phase "PHASE 32.5" -ThreatType "DLL Hijack" `
                -Severity $SEV_HIGH -Description "User $($zbSlOwn.User): unsigned hijack-target DLL '$($cd.Name)' sits beside signed, commonly-abused EXE '$($se.Name)' directly in $dirPath (not a nested install path) — classic DLL search-order side-load staging. Review, then quarantine the DLL by hand if confirmed malicious." `
                -Target "[$($zbSlOwn.User)] $($cd.FullName)" -FixAction "Info" -Group "DLL Side-Loading"
        } else {
            Out-Decrypt -Text "[$($zbSlOwn.User)] $($se.Name) + $($cd.Name) in $dirPath" -Prefix "  [SIDELOAD?] "
            Add-Finding -ID "SIDELOAD_$(Get-StableId "$($cd.FullName)|$($se.FullName)")" -Phase "PHASE 32.5" -ThreatType "DLL Hijack" `
                -Severity $SEV_POSSIBLE -Description "User $($zbSlOwn.User): unsigned DLL named '$($cd.Name)' (a common search-order-hijack target) sits beside signed EXE '$($se.Name)' in $dirPath ($(if ($exeNameMatch) { "EXE is on the commonly-abused sideload-target list" } else { "pair sits directly in an AppData/Temp/ProgramData root" })) — review; many portable/third-party apps legitimately ship their own DLLs beside their EXE, so this is not auto-acted on: $($cd.FullName)" `
                -Target "[$($zbSlOwn.User)] $($cd.FullName)" -FixAction "Info" -Group "DLL Side-Loading"
        }
    }
    if ($sideloadSigBudgetHit) { break }
}
if ($sideloadSigBudgetHit) { Out-Typewriter "  -> SIGNATURE BUDGET REACHED — remaining side-load candidates not fully verified." "WARN" }
if ($sideloadHits -eq 0) { Out-Typewriter "  -> [OK] NO DLL SIDE-LOAD CANDIDATES FOUND." "GOOD" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6: NETWORK & C2
# ══════════════════════════════════════════════════════════════════════════════
}   # end QUICK-skip block
Show-SectionBanner "NETWORK & C2 INDICATOR SWEEP"

Show-PhaseHeader "PHASE 33" "HOSTS FILE INTEGRITY AUDIT"
Out-Typewriter "VERIFYING HOSTS FILE..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
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
            Add-Finding -ID "HOSTS_$(Get-StableId $bh)" -Phase "PHASE 33" -ThreatType "DNS Hijack" -Severity $SEV_HIGH `
                -Description "Suspicious hosts entry: $bh" -Target $hostsPath -FixAction "Info" -Group "Hosts File Hijack"
        }
        Add-Finding -ID "HOSTS_PURGE" -Phase "PHASE 33" -ThreatType "DNS Hijack" -Severity $SEV_HIGH `
            -Description "Hosts file contains $($badHosts.Count) non-standard entries — purge all?" `
            -Target $hostsPath -FixAction "RunCmd" `
            -FixParam "`$h = Get-Content '$hostsPath'; `$clean = `$h | Where-Object { `$_ -match '^#' -or `$_ -notmatch '\S' -or `$_ -match '^(127\.0\.0\.1|::1|0\.0\.0\.0)\s+(localhost|ip6)' }; `$clean | Set-Content '$hostsPath'" `
            -Group "Hosts File Hijack"
    } else { Out-Typewriter "  -> [OK] HOSTS FILE CLEAN." "GOOD" }
}

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 34" "DNS CACHE POISONING AUDIT & FLUSH"
Out-Typewriter "DUMPING DNS RESOLVER CACHE..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
# WS0 wiring: the dyndns-provider list plus ONLY the specific point-in-time malware-C2 families
# ($MALWARE_C2_DOMAINS — exact odd strings, ~zero FP surface). Deliberately NOT $ALL_C2_DOMAINS:
# that set carries broad LOLBin/tunneling infra (github/ngrok/tailscale/…) which a healthy dev
# box resolves routinely, and this phase emits HIGH + an auto-selectable RunCmd — see the loader.
$allSuspectDns = @($SUSPICIOUS_DNS_DOMAINS) + @($MALWARE_C2_DOMAINS)
$suspectDns = $dnsCache | Where-Object { $entry = $_; $allSuspectDns | Where-Object { $entry.Entry -match [regex]::Escape($_) } }
foreach ($entry in $suspectDns) {
    Out-Typewriter "  -> SUSPECT DYNAMIC DNS: $($entry.Entry) -> $($entry.Data)" "CRIT"
    Add-Finding -ID "DNS_$($entry.Entry -replace '[^a-z0-9]','')" -Phase "PHASE 34" -ThreatType "DNS Hijack/C2" `
        -Severity $SEV_HIGH -Description "Suspicious dynamic DNS resolution: $($entry.Entry) -> $($entry.Data)" `
        -Target "DNS Cache: $($entry.Entry)" -FixAction "RunCmd" -FixParam "Clear-DnsClientCache" -Group "DNS Cache Poisoning"
}
Clear-DnsClientCache -ErrorAction SilentlyContinue
Out-Typewriter "  -> [OK] DNS CACHE FLUSHED." "GOOD"

}   # end QUICK-skip block
Show-PhaseHeader "PHASE 35" "PROXY & WINHTTP POISON RESET"
Out-Typewriter "AUDITING PROXY SETTINGS..." "INFO"
# P1 multi-user — THE WORST CASE IN THIS BATCH, now fixed. $proxyPath was a bare HKCU: read and
# the SAME variable was embedded TWICE in the RunCmd FixParam, so on a standard-user endpoint the
# remediation reset the TECHNICIAN's proxy and left the victim's hijack fully armed, while the
# finding text claimed the hijack was handled. $proxyPath is now rebuilt PER HIVE and the FixParam
# only ever names that user's own key.
# SECOND FIX: `netsh winhttp reset proxy` is MACHINE scope. It was welded onto the end of every
# per-user RunCmd, so on a multi-profile box it would have run once per profile. It is now a
# SEPARATE machine-level finding emitted exactly ONCE, and only when at least one profile is
# actually proxied — its blast radius is unchanged from today (it already fired whenever this
# phase fired) but it is no longer multiplied.
$zbProxyRel  = "Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$zbProxyHits = 0
$zbProxyPub  = 0    # profiles whose proxy resolves to a PUBLIC IP literal — the escalation gate
$zbProxyWho  = @()
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }   # not mounted and loading is off: we could not look
    $proxyPath = "$($zbHive.HivePath)\$zbProxyRel"
    if (-not (Test-Path $proxyPath)) { continue }
    $ps = Get-ItemProperty -Path $proxyPath -ErrorAction SilentlyContinue
    if ($ps.ProxyEnable -ne 1) { continue }
    $zbProxyHits++
    $zbProxyWho += "$($zbHive.User) -> $($ps.ProxyServer)"
    # ── Grading (operator decision, 2026-07-26) ───────────────────────────────────
    # ProxyEnable=1 means "a proxy is configured", NOT "a proxy is malicious". Pre-P1 this
    # produced ONE auto-selected CRITICAL + RunCmd (the technician's). Post-P1 it is one per
    # logged-on profile plus a machine-level one, so on a corporate box where every user has a
    # proxy it would auto-select N+1 destructive findings on a completely healthy machine —
    # a direct rule #1 violation that P1 multiplies.
    #
    # FAIL CLOSED: start at POSSIBLE + Info and escalate ONLY when a malicious shape is
    # positively confirmed. Never the reverse — an optimistic CRITICAL cleared on mismatch is
    # the exact pattern that made a malformed IOC CIDR match every connection.
    #
    # The confirmed signal is a PUBLIC IP LITERAL. Deliberately NOT "anything that isn't
    # RFC1918": the most common healthy corporate setting is an internal HOSTNAME
    # (proxy.corp.local:8080), which is not an RFC1918 address and would have false-positived.
    # Loopback is also excluded — corporate DLP, Fiddler and dev tooling all use 127.0.0.1,
    # and this operator's own box is a dev machine.
    $zbPxSev  = $SEV_POSSIBLE
    $zbPxAct  = "Info"
    $zbPxWhy  = "This is the shape of a legitimate corporate proxy (internal hostname or private address), so it is reported for review and NOT auto-cleared."
    # Escalation gate lives in the loader as Get-ProxyPublicIp so it is unit-testable — it decides
    # whether an auto-selected destructive RunCmd fires, so it gets its own test table.
    $zbPxPub = Get-ProxyPublicIp $ps.ProxyServer
    if ($zbPxPub) {
        $zbPxSev = $SEV_CRITICAL
        $zbPxAct = "RunCmd"
        $zbPxWhy = "The proxy points at the PUBLIC IP LITERAL $zbPxPub. A legitimate corporate proxy is an internal hostname or a private address, so this is the shape of a proxy hijack / traffic-interception relay."
    }
    # A FixParam must never point into a ZB_UH_* mount — remediation runs in a later process.
    $zbPxFp   = ""
    if ($zbPxAct -eq "RunCmd") {
        $zbPxFp = "Set-ItemProperty -Path '$proxyPath' -Name ProxyEnable -Value 0 -Force; Remove-ItemProperty -Path '$proxyPath' -Name ProxyServer -Force"
    }
    $zbPxHint = ""
    if ($zbHive.Source -eq 'RegLoad') {
        $zbPxAct  = "Info"
        $zbPxFp   = ""
        $zbPxSev  = $SEV_HIGH   # contract: a reg-loaded (logged-off) hive caps at HIGH + Info
        $zbPxHint = " That profile's hive is only temporarily mounted by this scan — clear by hand: reg load HKU\ZBFIX '$($zbHive.NtUserDat)' ; Set-ItemProperty -Path 'Registry::HKEY_USERS\ZBFIX\$zbProxyRel' -Name ProxyEnable -Value 0 -Force ; reg unload HKU\ZBFIX"
    }
    if ($zbPxPub) { $zbProxyPub++ }
    Out-Typewriter "  -> PROXY ENABLED FOR $($zbHive.User): $($ps.ProxyServer)" $(if ($zbPxPub) { "CRIT" } else { "WARN" })
    Add-Finding -ID "PROXY_ENABLE_$(Get-StableId "$($zbHive.Sid)|$proxyPath")" -Phase "PHASE 35" -ThreatType "Proxy Hijack" -Severity $zbPxSev `
        -Description "User $($zbHive.User) [hive source: $($zbHive.Source)]: proxy configured for that user: $($ps.ProxyServer). $zbPxWhy$zbPxHint" `
        -Target "[$($zbHive.User)] $proxyPath|ProxyEnable" -FixAction $zbPxAct -FixParam $zbPxFp `
        -Group "Proxy / Network Hijack" -EvidenceSource $zbHive.Source `
        -Confidence $(if ($zbPxPub) { "HIGH" } else { "LOW" })
}
if ($zbProxyHits -gt 0) {
    # Emitted ONCE, machine-scope. Split out of the per-user RunCmd above so it cannot run N times.
    # Graded on the same evidence as the per-user findings: `netsh winhttp reset proxy` is a real
    # configuration change, so it must not auto-select just because a corporate proxy exists.
    $zbPxMSev = $SEV_POSSIBLE
    $zbPxMAct = "Info"
    $zbPxMFp  = ""
    $zbPxMWhy = "No profile's proxy resolves to a public IP literal, so this looks like legitimate corporate configuration. The reset command is provided for an operator to run by hand: netsh winhttp reset proxy"
    if ($zbProxyPub -gt 0) {
        $zbPxMSev = $SEV_CRITICAL
        $zbPxMAct = "RunCmd"
        $zbPxMFp  = "netsh winhttp reset proxy"
        $zbPxMWhy = "$zbProxyPub profile(s) point at a PUBLIC IP literal, so the machine-wide WinHTTP proxy is reset too."
    }
    Add-Finding -ID "PROXY_WINHTTP_MACHINE" -Phase "PHASE 35" -ThreatType "Proxy Hijack" -Severity $zbPxMSev `
        -Description "[MACHINE] $zbProxyHits user profile(s) have a proxy configured ($($zbProxyWho -join '; ')). The machine-wide WinHTTP proxy is used by services and the OS itself, NOT per-user, so it is handled once here rather than per profile. $zbPxMWhy" `
        -Target "[MACHINE] WinHTTP proxy" -FixAction $zbPxMAct -FixParam $zbPxMFp `
        -Group "Proxy / Network Hijack" -Confidence $(if ($zbProxyPub -gt 0) { "HIGH" } else { "LOW" })
} else { Out-Typewriter "  -> [OK] NO ROGUE PROXY IN ANY READABLE PROFILE." "GOOD" }

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 36" "LIVE TCP/UDP THREAT SOCKET TERMINATION"
Out-Typewriter "SCANNING OPEN TCP SOCKETS..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1400 }
$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
$foundConn = $false
$connSigSeen = 0; $connSigBudgetHit = $false; $connSigSw = [System.Diagnostics.Stopwatch]::StartNew()
foreach ($conn in $conns) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    # Custom IOC: operator-supplied IPs/CIDRs (review #17 — this bucket was parsed and
    # counted but never consulted by any phase). Exact-IP match, plus a /N prefix compare
    # so a CIDR entry works without pulling in a subnet library.
    foreach ($cip in @($global:CustomIocs.IPs)) {
        $cipHit = $false
        if ($cip -like '*/*') {
            # FAIL CLOSED. The first cut set $cipHit = $true up front and cleared it only when a
            # byte mismatched — so a prefix that parsed to 0 (a typo like "10.0.0.0/abc", or an
            # explicit /0) broke out of the mask loop on the first iteration with the flag still
            # TRUE and matched EVERY established connection, emitting CRITICAL + KillProcess for
            # every connected process from one bad line in an IOC file. The flag is now only ever
            # raised after a full successful comparison, and a /0 or unparseable prefix is rejected
            # outright: an IOC that matches the entire internet is a typo, never an intention.
            $cipParts = $cip -split '/'
            $cipBits  = 0
            if (-not [int]::TryParse($cipParts[1], [ref]$cipBits)) { continue }
            try {
                $a = ([Net.IPAddress]::Parse($cipParts[0])).GetAddressBytes()
                $b = ([Net.IPAddress]::Parse("$($conn.RemoteAddress)")).GetAddressBytes()
                if ($a.Length -eq $b.Length -and $cipBits -ge 1 -and $cipBits -le ($a.Length * 8)) {
                    $cipOk = $true
                    for ($bi = 0; $bi -lt $a.Length; $bi++) {
                        $take = [Math]::Min(8, [Math]::Max(0, $cipBits - ($bi * 8)))
                        if ($take -eq 0) { break }
                        # -band 0xFF before the cast: 0xFF -shl 7 is 32640, and [byte] of that
                        # overflows — which silently broke every prefix that is not a /8 multiple.
                        $mask = [byte](((0xFF -shl (8 - $take)) -band 0xFF))
                        if (($a[$bi] -band $mask) -ne ($b[$bi] -band $mask)) { $cipOk = $false; break }
                    }
                    $cipHit = $cipOk
                }
            } catch { $cipHit = $false }
        } elseif ("$($conn.RemoteAddress)" -eq "$cip") { $cipHit = $true }
        if ($cipHit) {
            $foundConn = $true
            Out-ThreatBanner "CUSTOM IOC IP CONNECTION" "$($proc.Name) -> $($conn.RemoteAddress):$($conn.RemotePort)"
            Add-Finding -ID "IOC_IP_$(Get-StableId ("$($conn.RemoteAddress)|$($conn.OwningProcess)"))" -Phase "PHASE 36" `
                -ThreatType "Custom IOC" -Severity $SEV_CRITICAL `
                -Description "Established connection to an operator-supplied IOC address ($cip): $($proc.Name) PID:$($conn.OwningProcess) -> $($conn.RemoteAddress):$($conn.RemotePort)" `
                -Target "PID:$($conn.OwningProcess)" -FixAction "KillProcess" -FixParam $conn.OwningProcess `
                -Group "Live Malicious Connections"
            $global:RATHits++
            break
        }
    }
    if ($STRATUM_PORTS -contains $conn.RemotePort -and $proc.Name -notmatch "^(svchost|chrome|msedge|firefox)$") {
        $foundConn = $true
        Out-ThreatBanner "CRYPTOMINER STRATUM CONNECTION" "$($proc.Name) PID:$($proc.Id) -> $($conn.RemoteAddress):$($conn.RemotePort)"
        Add-Finding -ID "STRATUM_$($proc.Id)" -Phase "PHASE 36" -ThreatType "Cryptominer" -Severity $SEV_CRITICAL `
            -Description "Stratum mining connection from $($proc.Name) PID:$($proc.Id) to $($conn.RemoteAddress):$($conn.RemotePort)" `
            -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Connections"
        $global:MinerHits++
    }
    # Anchored to path COMPONENTS + WindowsApps excluded (was a bare "AppData|Temp"
    # substring). A user-path process holding a non-web socket is normal on a healthy box —
    # every Electron/updater app (Discord, Slack, Teams, Spotify) installs into
    # %LocalAppData% and talks on non-{80,443,8080,8443} ports — so the Authenticode
    # verdict, not the path, decides whether this is auto-actionable:
    #   validly signed -> POSSIBLE + Info  (shown, never auto-killed)
    #   unsigned/bad   -> HIGH + KillProcess
    if ($proc.Path -match $global:USER_PATH_RE -and $proc.Path -notmatch $global:WINDOWSAPPS_RE `
        -and $conn.RemotePort -notin @(80,443,8080,8443)) {
        $foundConn = $true
        # Budgeted: Authenticode does online CRL/OCSP checks that can block ~15s each, and
        # this loop walks every established connection.
        if ($connSigSeen -lt $global:SIG_AUDIT_MAX_FILES -and
            $connSigSw.Elapsed.TotalSeconds -lt $global:SIG_AUDIT_DEADLINE_S) {
            $connSigSeen++
            $csig = Get-AuthSig $proc.Path
        } else { $csig = $null; $connSigBudgetHit = $true }
        $connTrusted = ($csig -and $csig.Status -eq 'Valid')
        if ($connTrusted) {
            Out-Typewriter "  -> user-path proc w/ non-web socket (SIGNED — review only): $($proc.Name) -> $($conn.RemoteAddress):$($conn.RemotePort)" "WARN"
            Add-Finding -ID "CONN_$($proc.Id)_$($conn.RemotePort)" -Phase "PHASE 36" -ThreatType "Suspicious Connection" `
                -Severity $SEV_POSSIBLE -Description "Signed process in a user path holding a non-web connection: $($proc.Name) -> $($conn.RemoteAddress):$($conn.RemotePort) (normal for Electron/updater apps — review only, never auto-killed)" `
                -Target "PID:$($proc.Id)" -FixAction "Info" -Group "Live Malicious Connections"
        } else {
            Out-Typewriter "  -> SUSPECT SOCKET (unsigned user-path proc): $($proc.Name) -> $($conn.RemoteAddress):$($conn.RemotePort)" "CRIT"
            Add-Finding -ID "CONN_$($proc.Id)_$($conn.RemotePort)" -Phase "PHASE 36" -ThreatType "Suspicious Connection" `
                -Severity $SEV_HIGH -Description "Unsigned process in a user path connecting to $($conn.RemoteAddress):$($conn.RemotePort): $($proc.Name)" `
                -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Live Malicious Connections"
        }
    }
}
if ($connSigBudgetHit) { Out-Typewriter "  -> SIGNATURE BUDGET REACHED — remaining sockets graded without an Authenticode check." "WARN" }
# Reverse DNS check for C2 domains
foreach ($conn in ($conns | Select-Object -First 30)) {
    try {
        $rdns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
        foreach ($c2d in $ALL_C2_DOMAINS) {
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

Show-PhaseHeader "PHASE 36.5" "CLOUD INSTANCE METADATA SERVICE (IMDS) CREDENTIAL THEFT"
Out-Typewriter "CHECKING FOR NON-AGENT CONNECTIONS TO THE CLOUD METADATA ENDPOINT..." "HUNT"
# WS7 (T1552.005) — 169.254.169.254:80 is the AWS/Azure Instance Metadata Service; a process
# with access to it can pull the instance's IAM role / managed-identity credentials straight
# out of a plaintext HTTP response. HIGH-FP-RISK BY DESIGN: SSM/Azure/GCE guest agents, backup
# and RMM/monitoring agents poll this constantly on a healthy cloud VM — so this is graded
# ONLY against the owning process identity and is POSSIBLE + Info regardless of anything else,
# hard-gated on the allowlist (cloud_agent_allowlist_names / cloud_agent_allowlist_path_regex,
# plus the already-vetted rmm_tool_binaries list). Never auto-actionable.
$imdsConns = Get-NetTCPConnection -RemoteAddress '169.254.169.254' -RemotePort 80 -ErrorAction SilentlyContinue
$imdsHits = 0
foreach ($ic in @($imdsConns)) {
    $iproc = Get-Process -Id $ic.OwningProcess -ErrorAction SilentlyContinue
    if (-not $iproc) { continue }
    $iprocExeName = if ($iproc.Path) { (Split-Path -Leaf $iproc.Path).ToLower() } else { "$($iproc.Name)".ToLower() + '.exe' }
    $isAllowedName = ($CLOUD_AGENT_ALLOW_NAMES -contains $iprocExeName) -or ($RMM_TOOL_BINARIES -contains $iprocExeName)
    $isAllowedPath = ($iproc.Path -and "$($iproc.Path)" -match $CLOUD_AGENT_ALLOW_PATH_RE)
    if ($isAllowedName -or $isAllowedPath) { continue }
    $imdsHits++
    Out-Typewriter "  -> NON-AGENT PROCESS TALKING TO IMDS: $($iproc.Name) PID:$($iproc.Id) @ $($iproc.Path)" "WARN"
    Add-Finding -ID "IMDS_$($iproc.Id)" -Phase "PHASE 36.5" -ThreatType "Cloud Credential Theft" -Severity $SEV_POSSIBLE `
        -Description "Connection to the cloud Instance Metadata Service (169.254.169.254:80) from a process not on the cloud-agent allowlist — verify this is an authorized agent before assuming credential theft (deliberately high-FP-risk without a name/path allowlist match, so this is review-only): $($iproc.Name) PID:$($iproc.Id) @ $(if ($iproc.Path) { $iproc.Path } else { '?' })" `
        -Target "PID:$($iproc.Id)" -FixAction "Info" -Group "Cloud Credential Theft"
}
if ($imdsHits -eq 0) { Out-Typewriter "  -> [OK] NO NON-AGENT IMDS CONNECTIONS." "GOOD" }

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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
$suspectRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and
                   $_.Description -notmatch "Windows|Microsoft|WinRM" -and
                   ($_.Profile -match "Public" -or $_.LocalPort -eq "Any") }
foreach ($rule in $suspectRules) {
    Out-Typewriter "  -> SUSPECT FW RULE: $($rule.DisplayName)" "WARN"
    # Rule -Name (not DisplayName) is attacker-settable when the rule was created
    # programmatically and is interpolated into a single-quoted RunCmd string — escape it.
    $fwRuleNameEsc = "$($rule.Name)" -replace "'","''"
    Add-Finding -ID "FW_$($rule.Name -replace '[^a-z0-9]','')" -Phase "PHASE 38" -ThreatType "Firewall Hole" -Severity $SEV_POSSIBLE `
        -Description "Suspicious inbound firewall rule: $($rule.DisplayName) — Public profile or Any port" `
        -Target "Firewall Rule: $($rule.Name)" -FixAction "RunCmd" -FixParam "Disable-NetFirewallRule -Name '$fwRuleNameEsc'" -Group "Firewall Audit"
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
# Every Windows box ships ~100 legitimate trusted roots (Microsoft Trusted Root Program) + vendor
# driver roots. Flagging them all as "rogue/CRITICAL" buries the one that actually matters and would
# (absent the safety guard) offer to nuke the entire trust store. Allowlist well-known CA/vendor
# issuers -> INFO; only an *unrecognized* root is surfaced for review (POSSIBLE, not CRITICAL).
# TRUST DECISION IS NO LONGER NAME-BASED (2026-07-22 review #16). The Subject/Issuer text of a
# planted root is entirely attacker-controlled, so a bare-word allowlist ("microsoft", "windows",
# "amazon", ...) let a MITM root self-clear to INFO just by calling itself "CN=Microsoft Update CA".
# The authoritative local signal is membership of the Microsoft-managed AuthRoot store, which an
# attacker cannot join: Windows caches the Trusted Root Program's thumbprints under
# ...\SystemCertificates\AuthRoot\Certificates. Anything trusted as a root but absent from that
# cache was added locally (enterprise GPO, a vendor installer, or an adversary) and is worth eyes.
# The name list survives only to word the finding, never to clear it.
$authRootThumbs = @{}
foreach ($arKey in @(
    'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates',
    'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\AuthRoot\Certificates')) {
    try {
        foreach ($k in (Get-ChildItem -Path $arKey -ErrorAction SilentlyContinue)) {
            $authRootThumbs[$k.PSChildName.ToUpper()] = $true
        }
    } catch {}
}
# The store entry's INSTALL TIME is the signal an attacker cannot fake. PowerShell's registry
# provider exposes no LastWriteTime, so this reads it via the loader's Get-RegKeyLastWriteTime
# (RegQueryInfoKey P/Invoke, wired 2026-07-24 — the escalation branch below is now LIVE).
# On any P/Invoke/read failure this still returns $null and the branch degrades to inert,
# never to a false escalation. NOTE: CryptoAPI rewrites a cert entry's Blob value when it
# caches new cert properties, which also bumps the key's LastWriteTime — so "recently
# written" is evidence for REVIEW (HIGH + Info fix), not proof of a plant; the finding text
# says to verify provenance, and the cert store stays a 3-layer HARD block regardless.
$CERT_RECENT_DAYS = 30
function Get-CertStoreInstallTime {
    param([string]$StoreRegPath, [string]$Thumbprint)
    try {
        $kp = Join-Path $StoreRegPath $Thumbprint
        if (Test-Path -LiteralPath $kp) { return Get-RegKeyLastWriteTime $kp }
    } catch {}
    return $null
}
# ── P1 SCOPE LIMIT — DELIBERATELY NOT MIGRATED TO MULTI-USER (operator decision, 2026-07-26) ──
# Cert:\CurrentUser\Root is a PSDrive with no per-SID form, so covering every profile's personal
# root store would mean parsing raw certificate blobs straight out of each user's
# ...\SystemCertificates\Root\Certificates\<thumbprint>\Blob value — a large amount of new
# parsing for an Info-only payoff. That was declined. What is NOT acceptable is letting the
# result read as an all-users verdict when it is a single-user one, so the CurrentUser store's
# label, every CurrentUser finding description and the phase's clean line all now state the
# limit explicitly. (LocalMachine IS machine-wide and genuinely covers everyone.)
# The Id values are UNCHANGED on purpose — they are baked into the finding IDs and therefore
# into every -Baseline snapshot.
$zbCertUserLabel = "CurrentUser ($env:USERNAME — THE SCAN-CONTEXT USER ONLY)"
$zbCertScopeNote = " || SCOPE LIMIT: this store belongs ONLY to the account this scan runs as ($env:USERNAME). Because the engine self-elevates, that is the TECHNICIAN's account on a standard-user endpoint, NOT the logged-on victim's. Other profiles' personal root stores were NOT examined by this phase — a clean result here is not an all-users result."
$certStores = @(
    @{ Cert='Cert:\LocalMachine\Root'; Reg='HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'; Label='LocalMachine (machine-wide, applies to every user)'; Id='LM'   },
    @{ Cert='Cert:\CurrentUser\Root';  Reg='HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'; Label=$zbCertUserLabel; Id='USER' }
)
$certSeen = 0
foreach ($cs in $certStores) {
    $stCerts = Get-ChildItem $cs.Cert -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.NotBefore }
    $certSeen += @($stCerts).Count
    foreach ($cert in $stCerts) {
        $msManaged  = $authRootThumbs.ContainsKey("$($cert.Thumbprint)".ToUpper())
        $nameHint   = ("$($cert.Subject) $($cert.Issuer)" -match $TRUSTED_ROOT_CA_RE)
        $instTime   = Get-CertStoreInstallTime -StoreRegPath $cs.Reg -Thumbprint $cert.Thumbprint
        $freshInst  = ($instTime -and $instTime -gt (Get-Date).AddDays(-$CERT_RECENT_DAYS))
        # Windows' OS-BUILT-IN roots are not in the AuthRoot auto-update cache (that cache holds
        # the third-party program members), so AuthRoot membership alone graded ~40 perfectly
        # legitimate shipped roots as "not in the trust program" — a POSSIBLE flood on every
        # healthy box. Either signal clears a root; what an attacker CANNOT fake is the store
        # entry's install time, so that is what escalates, name allowlist or not.
        if (($msManaged -or $nameHint) -and -not $freshInst) {
            $certSev  = $SEV_INFO
            $certDesc = "Recognised root CA in the $($cs.Label) trust store: $($cert.Subject)"
        } elseif ($freshInst) {
            # Added/rewritten inside the scan window — the shape of an active MITM plant.
            # A matching vendor name does NOT clear this; that is exactly the evasion.
            $certSev  = $SEV_HIGH
            $certDesc = "Root CA trust entry INSTALLED/MODIFIED in the last $CERT_RECENT_DAYS days ($instTime) in the $($cs.Label) store — verify provenance before trusting$(if ($nameHint) { ' (the name resembles a well-known CA, but an attacker chooses that name freely — NOT proof)' }): $($cert.Subject)"
        } else {
            $certSev  = $SEV_POSSIBLE
            $certDesc = "Root CA trusted locally but not recognised (absent from the Microsoft AuthRoot cache and from the known-CA name list) in the $($cs.Label) store — normal for an enterprise/GPO or vendor root, but verify before trusting: $($cert.Subject)"
        }
        Out-Decrypt -Text "$($cert.Subject) | $($cert.Thumbprint)" -Prefix "  [ROOT CERT] "
        # FixAction Info, with the removal command in the description: the certificate trust
        # store is a Test-ProtectedTarget HARD block on all three layers anyway, so a RunCmd
        # here could never execute — this way the operator at least gets the exact command.
        Add-Finding -ID "CERT_$($cs.Id)_$($cert.Thumbprint.Substring(0,8))" -Phase "PHASE 39" -ThreatType "Rogue Certificate" `
            -Severity $certSev -Description "$certDesc || To remove by hand after verifying: Remove-Item '$($cs.Cert)\$($cert.Thumbprint)' -Force$(if ($cs.Id -eq 'USER') { $zbCertScopeNote })" `
            -Target "$($cs.Cert)\$($cert.Thumbprint)" -FixAction "Info" `
            -Group "Rogue Certificates"
    }
}
# Never print a clean result for a check that could not have fired for everyone: the per-user
# half of this phase saw exactly ONE profile's store, so the "clean" line must say so.
if ($certSeen -eq 0) { Out-Typewriter "  -> [OK] MACHINE ROOT STORE CLEAN; PER-USER ROOT STORE CLEAN FOR $env:USERNAME ONLY (OTHER PROFILES NOT EXAMINED)." "GOOD" }
else { Out-Typewriter "  -> NOTE: THE PER-USER ROOT STORE WAS READ FOR $env:USERNAME ONLY — OTHER PROFILES' PERSONAL ROOT STORES WERE NOT EXAMINED." "WARN" }

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
}   # end QUICK-skip block
Show-SectionBanner "CREDENTIAL & USER ABUSE DETECTION"

Show-PhaseHeader "PHASE 41" "LSA / WDIGEST / LSA PROTECTION AUDIT"
$wdigest = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"
if ($wdigest -eq 1) {
    Out-Typewriter "  -> WDIGEST PLAINTEXT CREDS ENABLED." "CRIT"
    Add-Finding -ID "WDIGEST_ENABLE" -Phase "PHASE 41" -ThreatType "Credential Theft Vector" -Severity $SEV_CRITICAL `
        -Description "WDigest UseLogonCredential = 1 — credentials stored in plaintext in memory (mimikatz target)" `
        -Target "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest|UseLogonCredential" `
        -FixAction "RunCmd" -FixParam "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord -Force" `
        -Group "Credential Security"
} else { Out-Typewriter "  -> [OK] WDIGEST PLAINTEXT STORAGE DISABLED." "GOOD" }
$lsaProtect = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1400 }
$allLocalUsers = Get-LocalUser -ErrorAction SilentlyContinue
foreach ($usr in $allLocalUsers) {
    if ($usr.Enabled -and $usr.Name -match "Temp|Admin1|Support|Test|Guest|Backdoor|HelpAssistant|DefaultAccount") {
        Out-Glitch "  [SUSPICIOUS ACCOUNT: $($usr.Name)]" Red
        # Name-pattern match can hit a legitimate primary account (e.g. 'Techsupport' contains
        # 'Support') — auto-disabling would lock a real user out, so the disable command is
        # operator-run only (CLAUDE.md rule #1: never auto-destructive on a healthy box).
        Add-Finding -ID "ACCOUNT_$($usr.Name -replace '[^a-z0-9]','')" -Phase "PHASE 42" -ThreatType "Ghost/Backdoor Account" `
            -Severity $SEV_HIGH -Description "Suspicious enabled local account: $($usr.Name) — verify with the owner; if unauthorized, disable manually: Disable-LocalUser -Name '$($usr.Name)' (NOT auto-applied — the name-pattern can match a legitimate primary account)" `
            -Target "LocalUser: $($usr.Name)" -FixAction "Info" -Group "Suspicious Accounts"
    }
}
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
foreach ($admin in $admins) {
    Out-Decrypt -Text $admin.Name -Prefix "  [ADMIN MEMBER] "
    Write-Log "ADMIN: $($admin.Name)"
}
Out-Typewriter "  -> LOCAL ADMIN GROUP LOGGED TO REPORT." "VER"

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 42.5" "HIDDEN & SHADOW ADMIN ACCOUNTS"
Out-Typewriter "CHECKING FOR ACCOUNTS HIDDEN FROM THE LOGON SCREEN..." "HUNT"
# Phase 42 flags suspiciously-NAMED enabled accounts. This phase covers what a careful
# intruder does instead: keep an ordinary-looking name and HIDE the account from the logon
# screen and Settings via SpecialAccounts\UserList, and/or hold Administrators membership
# through an entry that is not a local user at all.
$shadowHits = 0
if ($HIDDEN_ACCOUNT_REG -and (Test-Path -LiteralPath $HIDDEN_ACCOUNT_REG)) {
    $hidProps = Get-ItemProperty -LiteralPath $HIDDEN_ACCOUNT_REG -ErrorAction SilentlyContinue
    if ($hidProps) {
        foreach ($hp in $hidProps.PSObject.Properties) {
            if ($hp.Name -like 'PS*') { continue }
            # TryParse, not a cast: a non-numeric value threw a terminating error that the module
            # trap swallowed by skipping every remaining check in this phase.
            $hidVal = 0
            if (-not [int]::TryParse("$($hp.Value)", [ref]$hidVal)) { continue }
            if ($hidVal -ne 0) { continue }   # 0 = hidden from the logon UI
            $shadowHits++
            $hidUser = Get-LocalUser -Name $hp.Name -ErrorAction SilentlyContinue
            $hidIsAdmin = $false
            foreach ($am in (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)) {
                if ("$($am.Name)" -match "\\$([regex]::Escape($hp.Name))$") { $hidIsAdmin = $true; break }
            }
            Out-ThreatBanner "HIDDEN ACCOUNT" "$($hp.Name)$(if ($hidIsAdmin) { ' (ADMINISTRATOR)' })"
            Add-Finding -ID "HIDDENACCT_$($hp.Name -replace '[^a-z0-9]','')" -Phase "PHASE 42.5" `
                -ThreatType "Hidden / Shadow Admin Account" -Severity $(if ($hidIsAdmin) { $SEV_CRITICAL } else { $SEV_HIGH }) `
                -Description "Account '$($hp.Name)' is hidden from the logon screen and Settings via SpecialAccounts\UserList$(if ($hidIsAdmin) { ' AND is a member of Administrators' })$(if ($hidUser) { " (enabled=$($hidUser.Enabled), last logon $($hidUser.LastLogon))" } else { ' (no matching local user — stale entry or domain account)' }). Unhide with: Remove-ItemProperty '$HIDDEN_ACCOUNT_REG' -Name '$($hp.Name)'" `
                -Target "$HIDDEN_ACCOUNT_REG|$($hp.Name)" -FixAction "DeleteReg" -FixParam "$HIDDEN_ACCOUNT_REG|$($hp.Name)" `
                -Group "Suspicious Accounts"
        }
    }
}
# Accounts whose NAME matches the shadow-admin conventions (trailing $ to mimic a machine
# account, support_/healthcheck/backupadmin style service names). Review-only, exactly like
# Phase 42 — a name pattern must never disable a real user (rule #1).
foreach ($lu in (Get-LocalUser -ErrorAction SilentlyContinue)) {
    if (-not $lu.Enabled) { continue }
    if ("$($lu.Name)" -notmatch $SUSPICIOUS_ACCOUNT_RE) { continue }
    $shadowHits++
    Add-Finding -ID "SHADOWACCT_$($lu.Name -replace '[^a-z0-9]','')" -Phase "PHASE 42.5" `
        -ThreatType "Hidden / Shadow Admin Account" -Severity $SEV_POSSIBLE `
        -Description "Enabled local account '$($lu.Name)' matches a shadow-admin naming convention (machine-account-style trailing '$', or a generic service/support name intruders favour). Verify with the owner; if unauthorized: Disable-LocalUser -Name '$($lu.Name)'" `
        -Target "LocalUser: $($lu.Name)" -FixAction "Info" -Group "Suspicious Accounts"
}
# Administrators members that resolve to no local user AND no recognisable domain principal.
foreach ($am in (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)) {
    if ("$($am.ObjectClass)" -ne 'User') { continue }
    if ("$($am.PrincipalSource)" -in @('Local','ActiveDirectory','MicrosoftAccount','AzureAD')) { continue }
    $shadowHits++
    Add-Finding -ID "ORPHANADMIN_$(Get-StableId "$($am.Name)")" -Phase "PHASE 42.5" `
        -ThreatType "Hidden / Shadow Admin Account" -Severity $SEV_HIGH `
        -Description "Administrators contains '$($am.Name)' whose principal source is unresolvable ($($am.PrincipalSource)) — an orphaned SID retains admin rights and is a known persistence trick." `
        -Target "Administrators: $($am.Name)" -FixAction "Info" -Group "Suspicious Accounts"
}
if ($shadowHits -eq 0) { Out-Typewriter "  -> [OK] NO HIDDEN OR SHADOW ADMIN ACCOUNTS." "GOOD" }

Show-PhaseHeader "PHASE 43" "SAM / HIVENIGHTMARE (CVE-2021-36934) AUDIT"
Out-Typewriter "VERIFYING SAM HIVE PERMISSIONS + HIVENIGHTMARE CHECK..." "INFO"
$samPerms = cmd.exe /c "icacls %WINDIR%\System32\config\SAM 2>&1"
if ($samPerms -match "Everyone|Users.*:(F|M|W)") {
    Out-ThreatBanner "SAM HIVE OVER-PERMISSIVE" "Everyone/Users has write/modify access to SAM"
    Add-Finding -ID "SAM_PERMS" -Phase "PHASE 43" -ThreatType "Credential Exposure (HiveNightmare)" `
        -Severity $SEV_CRITICAL -Description "SAM hive ACL misconfigured — Everyone/Users can read (CVE-2021-36934 HiveNightmare). Manual remediation (NOT auto-applied — it resets config ACLs and the shadow purge is irreversible / removes restore points): icacls %WINDIR%\System32\config\*.* /reset , then 'vssadmin delete shadows /all /quiet' ONLY after confirming no shadow is needed for recovery." `
        -Target "%WINDIR%\System32\config\SAM" -FixAction "Info" `
        -Group "SAM / HiveNightmare"
    $global:RootkitHits++
} else { Out-Typewriter "  -> [OK] SAM HIVE PERMISSIONS SECURE." "GOOD" }
# Check VSS copies that may expose SAM
$shadows = (vssadmin list shadows 2>&1) -join "`n"
$shadowCount = ([regex]::Matches($shadows, "Shadow Copy ID")).Count
Out-Typewriter "  -> FOUND $shadowCount VOLUME SHADOW COPIES." "DATA"
if ($shadowCount -gt 0) {
    if ($Auto -or $global:GUI_MODE -or $global:STEALTH_MODE) {
        # No console stdin when spawned by the server/GUI — never auto-delete shadows.
        # Record the option as a finding and let remediation handle it.
        $vssChoice = "no"
    } else {
        Write-Host ""
        Write-Host "  ┌────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "  │  VSS shadows may expose SAM (HiveNightmare) or pre-encryption backup. │" -ForegroundColor Yellow
        Write-Host "  │  Delete all shadow copies? (yes/no)                                   │" -ForegroundColor Yellow
        Write-Host "  └────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host "  COMMAND> " -NoNewline -ForegroundColor DarkGray
        $vssChoice = (Read-Host).Trim().ToLower()
    }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1200 }
$elevatedInUS = (Get-ProcSnapshot) | Where-Object {
    # NB: try/catch is only valid as a *statement* in PS 5.1 — `(try{}catch{})` as a
    # sub-expression silently fails to parse and matches nothing. Keep it a statement.
    if ($_.Path -notmatch "AppData|Temp|Downloads|Desktop") { return $false }
    try { $_.GetOwnerSid().ReturnValue -eq 0 } catch { $false }
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

Show-PhaseHeader "PHASE 44.5" "CREDENTIAL ACCESS ARTIFACTS (LSASS DUMPS / HIVES / DPAPI)"
Out-Typewriter "HUNTING FOR CREDENTIAL-THEFT RESIDUE..." "HUNT"
# The dumping TOOL is usually long gone by the time anyone looks; the OUTPUT is what remains.
# An LSASS minidump or an exported SAM/SECURITY/SYSTEM hive on disk means credentials for this
# machine (and anything it can reach) must be considered compromised.
$credHits = 0
# P1 multi-user: five of these eight roots were the technician's profile — an LSASS minidump or an
# exported SAM hive staged in the VICTIM's Temp/Downloads/Desktop was invisible. $env:WINDIR\Temp,
# $env:ProgramData and $env:PUBLIC are MACHINE scope and are added exactly ONCE, outside the
# profile set. Single Get-ScanFiles call (its budget is PER CALL and must not be multiplied).
$credRoots = @(@(Get-ZbUserRootsM1 -Kind @('Temp','LocalAppData','AppData','Downloads','Desktop')) + @(
                 "$env:WINDIR\Temp", "$env:ProgramData", "$env:PUBLIC"
               ) | Where-Object { $_ } | Select-Object -Unique)
$credRe = ($CRED_DUMP_ARTIFACTS | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
$credFiles = (Get-ScanFiles -Path $credRoots)
# LIVE-TUNED 2026-07-22: the generic wordlist-style names below matched Chromium's own
# ZxcvbnData\passwords.txt (a password-STRENGTH dictionary). Those names are guesses, not
# evidence, so they are review-only; the specific artifact names (lsass dumps, exported hives,
# NTDS, kerberos tickets) keep their CRITICAL grade.
$credGenericRe = '^(hashes|hashdump.*|secretsdump.*|creds|passwords|wce)\.txt$'
foreach ($cf in $credFiles) {
    if ($cf.Name -notmatch $credRe) { continue }
    if (Test-BenignPath $cf.FullName $YARA_BENIGN_RE) { continue }   # package/library trees
    $credHits++
    $zbCredOwn = Get-ZbOwnerM1 $cf.FullName
    if ($cf.Name -match $credGenericRe) {
        Add-Finding -ID "CREDART_$(Get-StableId $cf.FullName)" -Phase "PHASE 44.5" `
            -ThreatType "Credential Access" -Severity $SEV_POSSIBLE `
            -Description "User $($zbCredOwn.User): file name matches a credential-dump output convention, but the name alone is weak evidence (password dictionaries and app data collide with it) — review, never auto-acted: $($cf.FullName)" `
            -Target "[$($zbCredOwn.User)] $($cf.FullName)" -FixAction "Info" -Group "Credential Access"
        continue
    }
    Out-ThreatBanner "CREDENTIAL DUMP ARTIFACT" "[$($zbCredOwn.User)] $($cf.FullName)"
    Add-Finding -ID "CREDART_$(Get-StableId $cf.FullName)" -Phase "PHASE 44.5" `
        -ThreatType "Credential Access" -Severity $SEV_CRITICAL `
        -Description "User $($zbCredOwn.User): credential-theft artifact on disk ($([Math]::Round($cf.Length/1KB)) KB): $($cf.FullName) — treat every credential used on this machine as compromised and force a reset." `
        -Target "[$($zbCredOwn.User)] $($cf.FullName)" -FixAction "Quarantine" -FixParam $cf.FullName -Group "Credential Access"
    $global:BackdoorHits++
}
# DPAPI master keys / Credential Manager blobs copied OUT of their protected home directory.
# The originals are normal; a copy anywhere else is theft staging.
# P1: this list shipped in %APPDATA% form but was expanded with ExpandString, which only
# understands the $env: spelling — so it resolved to a literal "%APPDATA%\..." path and has
# NEVER matched anything, on any box, ever. The data side now ships {TOKEN} templates
# ($DPAPI_THEFT_TEMPLATES) which are expanded per profile. Deliberately still LOG-ONLY and
# not a finding: a DPAPI store sitting in its own home directory is normal, and this
# detection is switching on for the first time — no severity/action escalation here.
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($zbTpl in $DPAPI_THEFT_TEMPLATES) {
        $zbPath = Expand-UserPathTemplate $zbTpl $zbUp
        if (-not $zbPath) { continue }
        if (-not (Test-Path -LiteralPath $zbPath)) { continue }
        Write-Log "DPAPI store present (normal): [$($zbHive.User)] $zbPath"
    }
}
# LIVE-TUNED 2026-07-22: the first cut flagged any GUID-named file under 64 KB in these roots
# and produced 99 HIGH+Quarantine findings on a healthy box — GUID filenames are ubiquitous
# (browser profiles, installer and package caches). Filename shape is now only the cheap
# PRE-FILTER; the finding requires the file to actually BE a DPAPI blob, confirmed by its magic
# header (version DWORD 0x02000000 followed by the provider GUID as UTF-16LE). That is not
# something a benign cache file collides with.
# P1 multi-user: Temp and Downloads were the technician's; $env:PUBLIC and $env:ProgramData are
# MACHINE scope and are added exactly ONCE.
$dpapiStaged = (Get-ScanFiles -Path @(@(Get-ZbUserRootsM1 -Kind @('Temp','Downloads')) + @("$env:PUBLIC", "$env:ProgramData") |
                                      Where-Object { $_ } | Select-Object -Unique))
foreach ($ds in $dpapiStaged) {
    if ($ds.Name -notmatch '^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$' -and
        $ds.Name -notmatch '^[0-9A-F]{32,}$') { continue }
    if ($ds.Length -gt 64KB -or $ds.Length -lt 24) { continue }
    $isDpapi = $false
    try {
        $fsD = [System.IO.File]::OpenRead($ds.FullName)
        try {
            $hdr = New-Object byte[] 24
            $readD = $fsD.Read($hdr, 0, 24)
            # 02 00 00 00 = DPAPI master-key/blob version, then a UTF-16LE GUID (ASCII hex + NULs).
            if ($readD -ge 24 -and $hdr[0] -eq 2 -and $hdr[1] -eq 0 -and $hdr[2] -eq 0 -and $hdr[3] -eq 0 -and
                $hdr[5] -eq 0 -and $hdr[7] -eq 0 -and $hdr[9] -eq 0) { $isDpapi = $true }
        } finally { $fsD.Dispose() }
    } catch { $isDpapi = $false }
    if (-not $isDpapi) { continue }
    $credHits++
    $zbDpOwn = Get-ZbOwnerM1 $ds.FullName
    Add-Finding -ID "DPAPISTAGE_$(Get-StableId $ds.FullName)" -Phase "PHASE 44.5" `
        -ThreatType "Credential Access" -Severity $SEV_HIGH `
        -Description "User $($zbDpOwn.User): a file with the DPAPI blob header is sitting outside its protected store — the staging step for offline credential decryption: $($ds.FullName)" `
        -Target "[$($zbDpOwn.User)] $($ds.FullName)" -FixAction "Quarantine" -FixParam $ds.FullName -Group "Credential Access"
}
# Live command lines performing credential access (comsvcs MiniDump, reg save of the hives,
# ntdsutil IFM, shadow-copy-for-hive-theft). Uses the shared process snapshot.
foreach ($cp in (Get-ProcSnapshot)) {
    $cl = "$($cp.CommandLine)"
    if (-not $cl) { continue }
    foreach ($cr in $CRED_THEFT_CMD_RULES) {
        if ($cl -notmatch $cr.Pattern) { continue }
        $credHits++
        $csev = switch ("$($cr.Severity)") { 'CRITICAL' { $SEV_CRITICAL } 'HIGH' { $SEV_HIGH } default { $SEV_POSSIBLE } }
        Out-ThreatBanner "CREDENTIAL ACCESS COMMAND" "$($cp.Name) (PID $($cp.ProcessId))"
        Add-Finding -ID "CREDCMD_$($cp.ProcessId)_$($cr.Name -replace '[^a-zA-Z0-9]','')" -Phase "PHASE 44.5" `
            -ThreatType "Credential Access" -Severity $csev `
            -Description "$($cr.Why) — PID $($cp.ProcessId) ($($cp.Name)): $($cl.Substring(0, [Math]::Min(220, $cl.Length)))" `
            -Target "PID:$($cp.ProcessId)" -FixAction $(if ($csev -eq $SEV_POSSIBLE) { "Info" } else { "KillProcess" }) `
            -FixParam $cp.ProcessId -Group "Credential Access"
        break
    }
}
if ($credHits -eq 0) { Out-Typewriter "  -> [OK] NO CREDENTIAL-ACCESS ARTIFACTS." "GOOD" }

}   # end QUICK-skip block
Show-PhaseHeader "PHASE 45" "ACCESSIBILITY SHELL BACKDOOR (STICKY KEYS / UTILMAN)"
# EVIDENCE_ENGINE_PLAN P12 — the accessibility binary set had THREE sources of truth: this
# hardcoded inline list of 6, data\permission_baseline.json (7, read by Phase 109 via Get-Perm)
# and data\detection_signatures.json (8, read by nothing at all). They had drifted, so hh.exe —
# the HTML-Help IFEO backdoor — was listed in the JSON and checked by neither phase, and editing
# that JSON had no effect on anything.
#
# The inline list is gone; this now reads data\detection_signatures.json via Get-Sig. That file
# is the canonical home: this is a DETECTION list (which binaries are backdoor targets), whereas
# permission_baseline.json is the ACL/owner baseline consumed by the perm-integrity phases
# 108-115. Phase 109 (Phases-3.ps1:1321) still reads the permission_baseline copy and must be
# migrated to Get-Sig in the same change — it is owned by another module, see the handoff notes.
#
# Two behaviour fixes that come with reading the full list: hh.exe lives in %WINDIR%, NOT
# System32 (Phase 109 probes System32 only, so it could never have found it), so both locations
# are probed; and grading is now the same tri-state Phase 109 uses — Get-AuthSig cannot see
# CATALOG signatures, so a bare `Status -ne "Valid"` on a newly-added binary would manufacture a
# CRITICAL + RunCmd auto-selected finding on a healthy box (rule #1). Only genuine tamper
# (validly signed by a NON-Microsoft publisher, or a hash mismatch / untrusted chain) is
# CRITICAL; merely unverifiable is POSSIBLE + Info.
$accessNames = @(Get-Sig 'accessibility_binaries')
if ($accessNames.Count -eq 0) {
    Out-Typewriter "  -> ACCESSIBILITY BINARY LIST UNAVAILABLE (signature data missing) — CHECK SKIPPED, NOT CLEAN." "WARN"
} else {
    foreach ($an in $accessNames) {
        # EVERY location the image exists in is checked, not just the first hit: hh.exe ships as
        # BOTH %WINDIR%\hh.exe (native) and %WINDIR%\SysWOW64\hh.exe, and replacing either is a
        # backdoor. IDs are path-derived so the three probes cannot collide.
        foreach ($af in @("$env:WINDIR\System32\$an", "$env:WINDIR\$an", "$env:WINDIR\SysWOW64\$an")) {
            $afExists = $false
            try { $afExists = Test-Path -LiteralPath $af } catch {}
            if (-not $afExists) { continue }
            $averd = Get-SignatureVerdict -FilePath $af
            if (($averd.Status -eq 'Valid' -and -not $averd.IsMs) -or $averd.Status -eq 'HashMismatch' -or $averd.Status -eq 'NotTrusted') {
                Out-Typewriter "  -> TAMPERED ACCESSIBILITY BINARY: $af (Status=$($averd.Status))" "CRIT"
                Add-Finding -ID "STICKY_$(Get-StableId $af)" -Phase "PHASE 45" `
                    -ThreatType "Sticky Keys / Accessibility Backdoor" -Severity $SEV_CRITICAL `
                    -Description "Accessibility binary is not a valid Microsoft-signed file (Status=$($averd.Status), Signer='$($averd.Signer)'): $af — classic sticky-keys/utilman shell backdoor giving a SYSTEM shell from the logon screen." `
                    -Target $af -FixAction "RunCmd" -FixParam "Rename-Item '$af' '$af.kraken' -Force" -Group "Accessibility Shell Backdoors"
            } elseif ($averd.Status -ne 'Valid') {
                Add-Finding -ID "STICKYX_$(Get-StableId $af)" -Phase "PHASE 45" `
                    -ThreatType "Sticky Keys / Accessibility Backdoor" -Severity $SEV_POSSIBLE `
                    -Description "Accessibility binary signature unverifiable in-process (Status=$($averd.Status)) — usually means it is CATALOG-signed rather than embedded-signed, which Get-AuthSig cannot see. Review only; not treated as a backdoor: $af" `
                    -Target $af -FixAction "Info" -Group "Accessibility Shell Backdoors"
            } else { Out-Typewriter "  -> [OK] VALID: $af" "GOOD" }
        }
    }
}

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 45.5" "RDP EXPOSURE & OPERATOR HARDENING SET"
Out-Typewriter "AUDITING REMOTE-ACCESS EXPOSURE AND ANTI-REINFECTION POSTURE..." "INFO"
# Everything this phase emits is OPERATOR-ONLY by design (user decision 2026-07-22): Info or
# POSSIBLE severity with a RunCmd, so the CRITICAL/HIGH auto-select can never fire any of it
# on a healthy box (rule #1). The GUI's APPLY HARDENING button selects them as a group.
$hardenExtra = 0
foreach ($rc in $RDP_HARDENING_CHECKS) {
    if (-not (Test-Path -LiteralPath $rc.Path)) { continue }
    $cur = Get-RegVal -Path $rc.Path -Name $rc.Name
    $needs = $false
    if ($rc.Compare -eq 'eq') { $needs = ("$cur" -ne "$($rc.SafeValue)") }
    else                      { $needs = ($null -eq $cur -or [int]$cur -lt [int]$rc.SafeValue) }
    if (-not $needs) { continue }
    $hardenExtra++
    Add-Finding -ID "RDPHARDEN_$($rc.Name -replace '[^a-z0-9]','')" -Phase "PHASE 45.5" `
        -ThreatType "Remote Access Exposure" -Severity $SEV_POSSIBLE `
        -Description "$($rc.Why). Current=$(if ($null -eq $cur) { '<unset>' } else { $cur }), hardened=$($rc.SafeValue). Operator-applied only." `
        -Target "$($rc.Path)|$($rc.Name)" -FixAction "RunCmd" `
        -FixParam "New-Item -Path '$($rc.Path)' -Force | Out-Null; Set-ItemProperty -Path '$($rc.Path)' -Name '$($rc.Name)' -Value $($rc.SafeValue) -Type DWord -Force" `
        -Group "Operator Hardening"
}
# The shared hardening set (LSA PPL, WDigest, SMB1, AutoRun, script-block logging, LLMNR, UAC).
foreach ($ha in $WS6_HARDENING_ACTIONS) {
    $curH = Get-RegVal -Path $ha.Path -Name $ha.Name
    # NoDriveTypeAutoRun and ConsentPromptBehaviorAdmin want an exact value; the rest are "at least".
    $needH = if ($ha.Id -in @('AUTORUN_OFF','UAC_ADMIN_PROMPT','WDIGEST_OFF','SMB1_OFF','LLMNR_OFF')) {
        ("$curH" -ne "$($ha.SafeValue)")
    } else {
        ($null -eq $curH -or [int]$curH -lt [int]$ha.SafeValue)
    }
    if (-not $needH) { continue }
    $hardenExtra++
    Add-Finding -ID "HARDEN6_$($ha.Id)" -Phase "PHASE 45.5" `
        -ThreatType "Hardening Opportunity" -Severity $SEV_INFO `
        -Description "$($ha.Why). Current=$(if ($null -eq $curH) { '<unset>' } else { $curH }), hardened=$($ha.SafeValue). Operator-applied only — reversible." `
        -Target "$($ha.Path)|$($ha.Name)" -FixAction "RunCmd" -FixParam "$($ha.Fix)" `
        -Group "Operator Hardening"
}
if ($hardenExtra -eq 0) { Out-Typewriter "  -> [OK] REMOTE-ACCESS AND HARDENING POSTURE ALREADY GOOD." "GOOD" }

Show-PhaseHeader "PHASE 46" "NULL SESSION / NTLM LEVEL / FINAL LSA HARDENING"
Out-Typewriter "AUDITING LSA SECURITY SETTINGS..." "INFO"
$lsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$lmCompat = Get-RegVal $lsaPath -Name "LmCompatibilityLevel"
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
} | Where-Object {
    # Anchor to PATH COMPONENTS — a bare 'Desktop' substring matched Store package names like
    # WhatsAppDesktop / DesktopAppInstaller under C:\Program Files\WindowsApps (store-signed,
    # ACL-protected — not a user path) and auto-KillProcess'd healthy apps.
    $_.Path -match '\\(AppData|Temp|Downloads|Desktop)\\' -and $_.Path -notlike "$env:ProgramFiles\WindowsApps\*"
}
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
$klFilePatterns = $KEYLOGGER_FILE_PATTERNS   # DATA (WS5) — see data\detection_signatures.json
# P1 multi-user: all four roots were the technician's profile, so a keylogger dropping its log
# into the VICTIM's AppData reported clean — the exact false all-clear this workstream removes.
# Nothing machine-wide belongs here. Single Get-ScanFiles call over every profile's roots (its
# MaxFiles/DeadlineSecs are PER CALL, so a per-profile loop would multiply the walk budget).
$klSearchPaths  = @(Get-ZbUserRootsM1 -Kind @('Temp','LocalAppData','AppData','Documents'))
# One bounded walk, anchored regex over all patterns (was 4 roots x 9 patterns = 36 recursions).
$klRegex = ($klFilePatterns | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
$klFound = $false
$klHits = (Get-ScanFiles -Path $klSearchPaths -TimeScoped) | Where-Object { $_.Name -match $klRegex }
foreach ($hit in $klHits) {
    $zbKlOwn = Get-ZbOwnerM1 $hit.FullName
    # ID was "KLFILE_<flattened filename>" — filename-only, and these ARE generic names
    # (keylog.txt, *.log), so two profiles holding the same name collapsed to ONE finding via
    # Add-Finding's de-dupe. Keyed on SID + full path now.
    $zbKlFileId = "KLFILE_$(Get-StableId "$($zbKlOwn.Sid)|$($hit.FullName)")"
    # Name heuristics (*typed*, *capture*log*) hit library marker files inside package-manager
    # trees (py.typed in site-packages et al.) — allowlisted paths are review-only.
    if (Test-BenignPath $hit.FullName $KEYLOG_BENIGN_RE) {
        Add-Finding -ID $zbKlFileId -Phase "PHASE 48" -ThreatType "Keylogger" `
            -Severity $SEV_POSSIBLE -Description "User $($zbKlOwn.User): file name resembles a keystroke log but sits in a package/library tree (likely a library file — review, not auto-deleted): $($hit.FullName)" `
            -Target "[$($zbKlOwn.User)] $($hit.FullName)" -FixAction "Info" -Group "Keylogger Artifacts"
        $klFound = $true
        continue
    }
    Out-ThreatBanner "KEYLOGGER LOG FILE" "[$($zbKlOwn.User)] $($hit.FullName)"
    Add-Finding -ID $zbKlFileId -Phase "PHASE 48" -ThreatType "Keylogger" `
        -Severity $SEV_CRITICAL -Description "User $($zbKlOwn.User): keystroke log file detected: $($hit.FullName)" `
        -Target "[$($zbKlOwn.User)] $($hit.FullName)" -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Keylogger Artifacts"
    $global:KeyloggerHits++; $klFound = $true
}
$klRegPaths = $KEYLOGGER_REG_PATHS   # DATA (WS5) — commercial-keylogger vendor keys, see data\detection_signatures.json
# P1 multi-user: every entry in that list is HKCU:\SOFTWARE\<vendor>, so under the elevated
# technician session this probed the TECHNICIAN's hive and a commercial keylogger installed in
# the victim's profile reported clean. The HKCU: prefix is stripped defensively at the CALL SITE
# (an already-relative entry passes through unchanged, so no data-file change is needed and old
# and new data both work), then each remainder is walked per profile.
# ID: "KLREG_<flattened path>" was identical for every user; it now carries the SID.
foreach ($kr in $klRegPaths) {
    $zbKlRel = "$kr" -replace '(?i)^HK(CU|EY_CURRENT_USER):?\\', ''
    foreach ($zbHive in @(Get-UserHives)) {
        if (-not $zbHive.HivePath) { continue }   # not mounted and loading is off: we could not look
        $zbKlPath = "$($zbHive.HivePath)\$zbKlRel"
        if (-not (Test-Path $zbKlPath)) { continue }
        # A FixParam must never point into a ZB_UH_* mount — remediation runs in a later process.
        $zbKlAct  = "DeleteRegKey"
        $zbKlFp   = $zbKlPath
        $zbKlHint = ""
        $zbKlSev  = $SEV_CRITICAL
        if ($zbHive.Source -eq 'RegLoad') {
            $zbKlAct  = "Info"
            $zbKlFp   = ""
            $zbKlSev  = $SEV_HIGH   # contract: a reg-loaded (logged-off) hive caps at HIGH + Info
            $zbKlHint = " That profile's hive is only temporarily mounted by this scan — remove by hand: reg load HKU\ZBFIX '$($zbHive.NtUserDat)' ; Remove-Item -LiteralPath 'Registry::HKEY_USERS\ZBFIX\$zbKlRel' -Recurse -Force ; reg unload HKU\ZBFIX"
        }
        Out-ThreatBanner "KEYLOGGER REGISTRY KEY" "[$($zbHive.User)] $zbKlPath"
        Add-Finding -ID "KLREG_$($zbKlRel -replace '[^a-z0-9]','')_$(Get-StableId "$($zbHive.Sid)")" -Phase "PHASE 48" -ThreatType "Keylogger" `
            -Severity $zbKlSev -Description "User $($zbHive.User) [hive source: $($zbHive.Source)]: known commercial-keylogger registry key found in that user's hive: $zbKlRel$zbKlHint" `
            -Target "[$($zbHive.User)] $zbKlPath" -FixAction $zbKlAct -FixParam $zbKlFp -Group "Keylogger Artifacts"
        $global:KeyloggerHits++; $klFound = $true
    }
}
if (-not $klFound) { Out-Typewriter "  -> [OK] NO KEYLOGGER ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 49" "CLIPBOARD MONITOR / SCREEN CAPTURE DETECTION" "KEYLOGGER"
Out-Typewriter "CHECKING FOR CLIPBOARD/SCREEN CAPTURE PROCESSES..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
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

Show-PhaseHeader "PHASE 49.5" "CLIPBOARD CRYPTOCURRENCY ADDRESS-SWAP (CLIPPER) DETECTION" "KEYLOGGER"
Out-Typewriter "CHECKING FOR CO-OCCURRING CLIPBOARD-API + CRYPTO-ADDRESS CONTENT..." "HUNT"
# WS7 (T1115) — clipper malware silently swaps a copied crypto address for the attacker's own.
# NEITHER a clipboard-API reference NOR a hardcoded crypto address literal is a finding alone
# (clipboard APIs are used by countless legitimate tools; a crypto address can legitimately
# appear in a wallet/browser cache) — this requires BOTH regex families to match NEAR each other
# in the SAME piece of content (proximity window, not "anywhere in up to a 2MB file" — a large
# deployment/diagnostic script can legitimately contain an unrelated clipboard helper thousands
# of lines away from an unrelated long alphanumeric token). The bare base58-shaped legacy-BTC
# pattern has no inherent checksum, so a plain character-class match can hit ordinary long
# alphanumeric identifiers (license keys, correlation IDs); validate it against Base58Check
# before counting it as an address hit.
$CLIPPER_PROXIMITY_CHARS = 500
function Test-Base58CheckAddress {
    param([string]$Addr)
    try {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        $num = [System.Numerics.BigInteger]::Zero
        foreach ($c in $Addr.ToCharArray()) {
            $idx = $alphabet.IndexOf($c)
            if ($idx -lt 0) { return $false }
            $num = $num * 58 + $idx
        }
        $bytes = $num.ToByteArray()
        [Array]::Reverse($bytes)   # BigInteger.ToByteArray is little-endian
        if ($bytes.Length -gt 0 -and $bytes[0] -eq 0) { $bytes = $bytes[1..($bytes.Length - 1)] }
        $leadingOnes = 0
        foreach ($c in $Addr.ToCharArray()) { if ($c -eq '1') { $leadingOnes++ } else { break } }
        $fullBytes = (@([byte]0) * $leadingOnes) + @($bytes)
        if ($fullBytes.Length -lt 25) { return $false }
        $payload  = $fullBytes[0..($fullBytes.Length - 5)]
        $checksum = $fullBytes[($fullBytes.Length - 4)..($fullBytes.Length - 1)]
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $calcChecksum = ($sha256.ComputeHash($sha256.ComputeHash($payload)))[0..3]
        for ($i = 0; $i -lt 4; $i++) { if ($calcChecksum[$i] -ne $checksum[$i]) { return $false } }
        return $true
    } catch {
        # Validation infra unavailable (e.g. BigInteger not loadable) — fail OPEN on the checksum
        # check specifically so this hardening pass never makes the underlying detection weaker
        # than before; the proximity requirement below still applies.
        return $true
    }
}
function Test-ClipperCoOccurrence {
    param([string]$Content)
    if (-not $Content) { return $false }
    $apiPositions = New-Object System.Collections.Generic.List[int]
    foreach ($r in $CLIPPER_CLIPBOARD_API_RULES) {
        foreach ($m in [regex]::Matches($Content, $r)) { $apiPositions.Add($m.Index) }
    }
    if ($apiPositions.Count -eq 0) { return $false }
    foreach ($r in $CLIPPER_CRYPTO_ADDR_RULES) {
        foreach ($m in [regex]::Matches($Content, $r)) {
            if ($m.Value -match '^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$' -and -not (Test-Base58CheckAddress $m.Value)) { continue }
            foreach ($ap in $apiPositions) {
                if ([Math]::Abs($m.Index - $ap) -le $CLIPPER_PROXIMITY_CHARS) { return $true }
            }
        }
    }
    return $false
}
$clipperHits = 0
# 1) Run / RunOnce values (HKCU + HKLM, 64/32)
# P1 multi-user: the HKLM roots are MACHINE scope and are enumerated exactly once (a box with
# 8 profiles must not report a machine-wide Run value 8 times); the former HKCU roots become
# hive-relative and are walked per profile, so a clipper living in the victim's profile is
# visible from the technician's elevated session. Grading logic below is unchanged.
$zbClipperRunTargets = @()
foreach ($zbMp in @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce")) {
    $zbClipperRunTargets += @{ Path = $zbMp; User = 'MACHINE'; Sid = 'MACHINE'; Src = 'HKLM' }
}
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }   # not mounted and loading is off: we could not look
    foreach ($zbRel in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                         'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
        $zbClipperRunTargets += @{ Path = "$($zbHive.HivePath)\$zbRel"
                                   User = $zbHive.User; Sid = $zbHive.Sid; Src = $zbHive.Source }
    }
}
foreach ($zbT in $zbClipperRunTargets) {
    $crp = $zbT.Path
    if (-not (Test-Path $crp)) { continue }
    $crKeys = Get-ItemProperty -Path $crp -ErrorAction SilentlyContinue
    if (-not $crKeys) { continue }
    foreach ($prop in ($crKeys.psobject.properties | Where-Object { $_.Name -notmatch "^PS" })) {
        $crVal = "$($prop.Value)"
        if (-not (Test-ClipperCoOccurrence $crVal)) { continue }
        $clipperHits++
        Out-ThreatBanner "CLIPPER CO-OCCURRENCE (RUN KEY)" "[$($zbT.User)] $crp|$($prop.Name)"
        Add-Finding -ID "CLIPPER_RUN_$(Get-StableId "$($zbT.Sid)|$crp|$($prop.Name)")" -Phase "PHASE 49.5" -ThreatType "Clipper/Crypto Hijacker" `
            -Severity $SEV_POSSIBLE -Description "User $($zbT.User) [hive source: $($zbT.Src)]: Run key value references BOTH a clipboard API and a hardcoded crypto address literal (possible clipboard-hijacking clipper — review): [$crp] $($prop.Name) = $crVal" `
            -Target "[$($zbT.User)] $crp|$($prop.Name)" -FixAction "Info" -Group "Clipboard Clipper Detection"
    }
}
# 2) Scheduled task command lines
$clipperTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
foreach ($ct in $clipperTasks) {
    $ctCmd = (@($ct.Actions) | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
    if (-not (Test-ClipperCoOccurrence $ctCmd)) { continue }
    $clipperHits++
    Out-ThreatBanner "CLIPPER CO-OCCURRENCE (SCHEDULED TASK)" $ct.TaskName
    Add-Finding -ID "CLIPPER_TASK_$(Get-StableId $ct.TaskName)" -Phase "PHASE 49.5" -ThreatType "Clipper/Crypto Hijacker" `
        -Severity $SEV_POSSIBLE -Description "Scheduled task action references BOTH a clipboard API and a hardcoded crypto address literal (possible clipboard-hijacking clipper — review): $($ct.TaskName) | $ctCmd" `
        -Target "Task: $($ct.TaskName)" -FixAction "Info" -Group "Clipboard Clipper Detection"
}
# 3) Recently-dropped scripts — excludes existing wallet/password-manager benign paths
# (infostealer_benign_paths) via Test-BenignPath so this does not re-flag what that
# allowlist already covers (CLAUDE.md: reuse, don't duplicate, an existing FP allowlist).
$clipperScriptExts  = @('.ps1','.vbs','.js','.bat','.cmd','.hta','.wsf','.py')
# P1 multi-user: five of the six roots were the technician's profile. $env:ProgramData is MACHINE
# scope and is added exactly ONCE. Single Get-ScanFiles call; the 500-file content-read cap below
# stays PHASE-wide (shared across profiles) rather than being multiplied per profile.
$clipperScriptRoots = @(@(Get-ZbUserRootsM1 -Kind @('Temp','LocalAppData','AppData','Downloads','Desktop')) + @($env:ProgramData) |
                        Where-Object { $_ } | Select-Object -Unique)
$clipperScriptFiles = (Get-ScanFiles -Path $clipperScriptRoots -TimeScoped) | Where-Object { $clipperScriptExts -contains $_.Extension.ToLower() }
$clipperFileSeen = 0
foreach ($csf in $clipperScriptFiles) {
    if ($clipperFileSeen -ge 500) { break }   # content-read volume cap — a bounded, fast check, not a signature-audit budget
    $clipperFileSeen++
    if (Test-BenignPath $csf.FullName $INFOSTEALER_BENIGN_RE) { continue }
    $csContent = $null
    try {
        $csFi = Get-Item -LiteralPath $csf.FullName -ErrorAction Stop
        if ($csFi.Length -eq 0 -or $csFi.Length -gt 2097152) { continue }   # 2MB cap
        $csContent = [System.IO.File]::ReadAllText($csf.FullName)
    } catch { continue }
    if (-not (Test-ClipperCoOccurrence $csContent)) { continue }
    $clipperHits++
    $zbCsOwn = Get-ZbOwnerM1 $csf.FullName
    Out-ThreatBanner "CLIPPER CO-OCCURRENCE (DROPPED SCRIPT)" "[$($zbCsOwn.User)] $($csf.FullName)"
    Add-Finding -ID "CLIPPER_FILE_$(Get-StableId $csf.FullName)" -Phase "PHASE 49.5" -ThreatType "Clipper/Crypto Hijacker" `
        -Severity $SEV_POSSIBLE -Description "User $($zbCsOwn.User): script references BOTH a clipboard API and a hardcoded crypto address literal (possible clipboard-hijacking clipper — review): $($csf.FullName)" `
        -Target "[$($zbCsOwn.User)] $($csf.FullName)" -FixAction "Info" -Group "Clipboard Clipper Detection"
}
if ($clipperHits -eq 0) { Out-Typewriter "  -> [OK] NO CLIPBOARD/CRYPTO CO-OCCURRENCE HITS." "GOOD" }

Show-PhaseHeader "PHASE 50" "ACCESSIBILITY API / UIAUTOMATION KEYLOGGER CHECK" "KEYLOGGER"
Out-Typewriter "AUDITING UIAutomation HOOK REGISTRATIONS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
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
}   # end QUICK-skip block
Show-ThreatCategoryHeader "RANSOMWARE" "Extension Velocity · High Entropy · Ransom Notes · Shadow Deletion · Backup Tampering"

Show-PhaseHeader "PHASE 51" "RANSOMWARE EXTENSION VELOCITY DETECTION" "RANSOMWARE"
Out-Typewriter "SCANNING USER PROFILE FOR RANSOMWARE EXTENSION PATTERNS..." "HUNT"
Invoke-QuantumBar "EXTENSION ANALYSIS" 12 110
$encFound = $false
# Scope to user-DOCUMENT folders, not the whole profile. Bare $env:USERPROFILE recursion pulls in
# AppData (browser caches, Teams, OneDrive) → multi-minute hang. Ransomware encrypts user data,
# which lives in these folders. One bounded walk is shared across phases 51/52/53.
# P1 multi-user: ransomware encrypts USER DATA, and all seven document roots resolved to the
# TECHNICIAN's profile under RunAs — so on a standard-user endpoint this phase, the entropy phase
# and the ransom-note phase were all inspecting a profile that was never encrypted, and reporting
# clean. Every reachable profile's document folders are now collected (redirection-aware, via
# Get-UserPaths, so a Documents folder redirected to a file server is followed rather than
# guessed). $env:PUBLIC is MACHINE scope and is added exactly ONCE.
#
# ONE Get-ScanFiles call, deliberately: this walk is SHARED with Phase 52 (entropy) and Phase 53
# (ransom notes) — see their comments — and its MaxFiles/DeadlineSecs are PER CALL, so a
# per-profile loop here would have multiplied THREE phases' wall clock by the profile count.
$searchRoots = @(@(Get-ZbUserRootsM1 -Kind @('Documents','Desktop','Pictures','Downloads','Videos','Music','OneDrive')) + @("$env:PUBLIC") |
                 Where-Object { $_ } | Select-Object -Unique)
# Redirection honesty. Get-UserPaths reports Redirected = $true (a folder resolved outside the
# profile root) or $null (UNKNOWN — the profile fell back to a constructed path and simply cannot
# tell). Reporting "clean" for a document folder that actually lives on a file server, or that we
# could not locate, is the false all-clear this workstream exists to remove, so the caveat is
# carried into the findings rather than left silent.
$zbRansomCaveat = @()
foreach ($zbHive in @(@(Get-UserHives) | Sort-Object -Property Sid)) {
    if (-not $zbHive.ProfileReachable) { $zbRansomCaveat += "$($zbHive.User) (profile unreachable — NOT scanned)"; continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { $zbRansomCaveat += "$($zbHive.User) (folders unresolvable — NOT scanned)"; continue }
    if ($zbUp.Redirected -eq $true) { $zbRansomCaveat += "$($zbHive.User) (folder redirection ACTIVE — some document folders live outside the profile)" }
    elseif ($null -eq $zbUp.Redirected) { $zbRansomCaveat += "$($zbHive.User) (redirection UNKNOWN — folders were constructed, not read from the hive)" }
}
$zbRansomNote = if ($zbRansomCaveat.Count -gt 0) { " COVERAGE CAVEAT: $($zbRansomCaveat -join '; ')." } else { "" }
$ransomScanFiles = Get-ScanFiles -Path $searchRoots -TimeScoped
foreach ($rf in $ransomScanFiles) {
    $ext = $rf.Extension.ToLower()
    if ($RANSOMWARE_EXTENSIONS -contains $ext) {
        $zbRfOwn = Get-ZbOwnerM1 $rf.FullName
        Out-ThreatBanner "RANSOMWARE ENCRYPTED FILE EXTENSION" "[$($zbRfOwn.User)] $($rf.Name) in $($rf.DirectoryName)"
        # ID was "RANSOM_EXT_<flattened filename>" — filename-only. Ransomware renames the SAME
        # document names in every profile it reaches, so Add-Finding's de-dupe would have reported
        # one user's encrypted files and silently dropped everyone else's. SID + path keyed now.
        Add-Finding -ID "RANSOM_EXT_$(Get-StableId "$($zbRfOwn.Sid)|$($rf.FullName)")" -Phase "PHASE 51" -ThreatType "Ransomware" `
            -Severity $SEV_CRITICAL -Description "User $($zbRfOwn.User): file with known ransomware extension: $($rf.FullName) ($ext)$zbRansomNote" `
            -Target "[$($zbRfOwn.User)] $($rf.FullName)" -FixAction "Info" -Group "Ransomware Encrypted Files"
        $global:RansomwareRisk += 5; $encFound = $true
    }
}
if (-not $encFound) { Out-Typewriter "  -> [OK] NO RANSOMWARE EXTENSION PATTERNS." "GOOD" }

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 52" "HIGH ENTROPY FILE DETECTION (ENCRYPTED PAYLOAD)" "RANSOMWARE"
Out-Typewriter "SAMPLING FILES FOR HIGH ENTROPY (ENCRYPTION/PACKING)..." "HUNT"
Invoke-QuantumBar "ENTROPY ANALYSIS" 15 120
$entropyHits = $false
# Reuse the single bounded walk from phase 51 (no second whole-tree recursion).
$candidates = $ransomScanFiles |
    Where-Object { $_.Length -gt 4096 -and $_.Extension -notmatch "\.(mp4|mp3|zip|rar|7z|jpg|png|pdf)$" } |
    Select-Object -First 50
foreach ($cf in $candidates) {
    $entropy = Get-FileEntropy -FilePath $cf.FullName
    if ($entropy -gt 7.5) {
        $zbEnOwn = Get-ZbOwnerM1 $cf.FullName
        Out-Typewriter "  -> HIGH ENTROPY ($entropy): [$($zbEnOwn.User)] $($cf.FullName)" "WARN"
        # $ransomScanFiles now spans EVERY profile (see Phase 51), so this filename-only ID would
        # have collapsed two users' identically-named files into one finding via Add-Finding's
        # de-dupe. SID + path keyed. Grading, threshold and FixAction are untouched.
        Add-Finding -ID "ENTROPY_$(Get-StableId "$($zbEnOwn.Sid)|$($cf.FullName)")" -Phase "PHASE 52" -ThreatType "Ransomware/Packed Malware" `
            -Severity $SEV_POSSIBLE -Description "User $($zbEnOwn.User): high entropy file ($entropy/8.0 bits): $($cf.FullName) — may be encrypted or packed malware" `
            -Target "[$($zbEnOwn.User)] $($cf.FullName)" -FixAction "Info" -Group "High Entropy Files"
        $global:RansomwareRisk++; $entropyHits = $true
    }
}
if (-not $entropyHits) { Out-Typewriter "  -> [OK] NO SUSPICIOUSLY HIGH ENTROPY FILES FOUND." "GOOD" }

}   # end QUICK-skip block
Show-PhaseHeader "PHASE 53" "RANSOM NOTE DETECTION" "RANSOMWARE"
Out-Typewriter "SCANNING FOR RANSOM NOTE ARTIFACTS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
# Filename patterns split by confidence (FP fix — rule #1: never auto-delete a healthy-box file):
#  STRONG  = tokens that essentially never occur in a benign filename -> CRITICAL + DeleteFile.
#  GENERIC = common English words that DO occur in legit files (readme.txt / IMPORTANT.txt / RECOVER)
#            -> only CRITICAL + DeleteFile if the file CONTENT also matches a ransom-note construct;
#            otherwise POSSIBLE + Info (shown, never auto-deleted). This stops e.g. Sysinternals'
#            readme.txt being auto-selected for deletion.
$strongNotePatterns  = @("*DECRYPT*","*ransom*","*YOUR_FILES*","*HOW_TO_DECRYPT*","*!readme!*","*restore_files*","*help_decrypt*") + $RANSOM_NOTE_FILENAMES  # WS2: + CISA-sourced known-family note filenames
$genericNotePatterns = @("*readme*.txt","*RECOVER*","*HOW TO RECOVER*","*IMPORTANT*.txt")
# Collapse patterns × N roots (was 55 full recursions) into ONE in-memory regex over the shared
# phase-51 walk. Wildcards -> regex: escape, then \* -> .*  (case-insensitive -match).
$strongRegex  = ($strongNotePatterns  | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
$genericRegex = ($genericNotePatterns | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
$noteFound = $false
# $ransomScanFiles now spans EVERY reachable profile (see Phase 51's P1 comment), so the
# filename-only IDs below had to be re-keyed: a ransom note is dropped with the SAME filename into
# every folder it reaches, which is precisely the case Add-Finding's de-dupe would have collapsed
# to a single finding — hiding every profile but the first. Grading is untouched.
foreach ($note in ($ransomScanFiles | Where-Object { $_.Name -match $strongRegex })) {
    $zbNtOwn = Get-ZbOwnerM1 $note.FullName
    Out-ThreatBanner "RANSOM NOTE DETECTED" "[$($zbNtOwn.User)] $($note.FullName)"
    Add-Finding -ID "RANSOMNOTE_$(Get-StableId "$($zbNtOwn.Sid)|$($note.FullName)")" -Phase "PHASE 53" -ThreatType "Ransomware" `
        -Severity $SEV_CRITICAL -Description "User $($zbNtOwn.User): ransom note file found: $($note.FullName)" `
        -Target "[$($zbNtOwn.User)] $($note.FullName)" -FixAction "DeleteFile" -FixParam $note.FullName -Group "Ransom Notes"
    $global:RansomwareRisk += 10; $noteFound = $true
}
foreach ($note in ($ransomScanFiles | Where-Object { $_.Name -match $genericRegex -and $_.Name -notmatch $strongRegex })) {
    $zbNtOwn = Get-ZbOwnerM1 $note.FullName
    $zbNoteId = "RANSOMNOTE_$(Get-StableId "$($zbNtOwn.Sid)|$($note.FullName)")"
    # Generic filename — confirm with content before treating as a real (deletable) note.
    $confirmed = $false
    if ($RANSOM_NOTE_CONTENT_RULES.Count -gt 0 -and $note.Length -lt 102400) {
        $confirmed = (Test-ContentRules -FilePath $note.FullName -Rules $RANSOM_NOTE_CONTENT_RULES).Hit
    }
    if ($confirmed) {
        Out-ThreatBanner "RANSOM NOTE DETECTED" "[$($zbNtOwn.User)] $($note.FullName)"
        Add-Finding -ID $zbNoteId -Phase "PHASE 53" -ThreatType "Ransomware" `
            -Severity $SEV_CRITICAL -Description "User $($zbNtOwn.User): ransom note (filename + content confirmed): $($note.FullName)" `
            -Target "[$($zbNtOwn.User)] $($note.FullName)" -FixAction "DeleteFile" -FixParam $note.FullName -Group "Ransom Notes"
        $global:RansomwareRisk += 10
    } else {
        Add-Finding -ID $zbNoteId -Phase "PHASE 53" -ThreatType "Ransomware" `
            -Severity $SEV_POSSIBLE -Description "User $($zbNtOwn.User): file name resembles a ransom note but content is not confirmed (likely a legitimate readme — review, do not auto-delete): $($note.FullName)" `
            -Target "[$($zbNtOwn.User)] $($note.FullName)" -FixAction "Info" -Group "Ransom Notes"
    }
    $noteFound = $true
}
# WS2: renamed-note detection — scan small text-like notes in the bounded ransom walk for
# ransom-note CONTENT constructs (catches notes that don't match a known filename). FixAction
# Info: content-only matches are weaker evidence than a filename hit, so never auto-delete.
if ($RANSOM_NOTE_CONTENT_RULES.Count -gt 0) {
    $noteSevMap = @{ "CRITICAL"=$SEV_CRITICAL; "HIGH"=$SEV_HIGH; "POSSIBLE"=$SEV_POSSIBLE }
    $noteTextFiles = @($ransomScanFiles | Where-Object { $_.Extension -match '^\.(txt|html?|hta|rtf)$' -and $_.Length -lt 102400 } | Select-Object -First 300)
    foreach ($tf in $noteTextFiles) {
        $cr = Test-ContentRules -FilePath $tf.FullName -Rules $RANSOM_NOTE_CONTENT_RULES
        if ($cr.Hit) {
            $zbTxOwn = Get-ZbOwnerM1 $tf.FullName
            Out-ThreatBanner "RANSOM NOTE CONTENT MATCH" "$($cr.Name): [$($zbTxOwn.User)] $($tf.FullName)"
            Add-Finding -ID "RANSOMTEXT_$(Get-StableId "$($zbTxOwn.Sid)|$($tf.FullName)")" -Phase "PHASE 53" -ThreatType "Ransomware" `
                -Severity $noteSevMap[$cr.Severity] -Description "User $($zbTxOwn.User): ransom-note content construct ($($cr.Name)) in: $($tf.FullName)" `
                -Target "[$($zbTxOwn.User)] $($tf.FullName)" -FixAction "Info" -Group "Ransom Notes"
            $global:RansomwareRisk += 5; $noteFound = $true
        }
    }
}
if (-not $noteFound) { Out-Typewriter "  -> [OK] NO RANSOM NOTE FILES DETECTED." "GOOD" }

Show-PhaseHeader "PHASE 54" "BACKUP PROCESS TAMPERING / BCDEDIT ABUSE" "RANSOMWARE"
Out-Typewriter "CHECKING FOR BACKUP DISABLE / RECOVERY TAMPERING..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
$bcdedit2 = bcdedit /enum all 2>$null
if ($bcdedit2 -match "recoveryenabled.*No") {
    Out-Typewriter "  -> RECOVERY DISABLED IN BCD — POSSIBLE RANSOMWARE PREP." "CRIT"
    Add-Finding -ID "RECOVERY_DISABLED" -Phase "PHASE 54" -ThreatType "Ransomware Prep" -Severity $SEV_CRITICAL `
        -Description "BCD recovery is disabled — ransomware commonly disables recovery before encryption" `
        -Target "bcdedit /recoveryenabled" -FixAction "RunCmd" -FixParam "bcdedit /set {default} recoveryenabled Yes" `
        -Group "Recovery / Backup Tampering"
    $global:RansomwareRisk += 5
} else { Out-Typewriter "  -> [OK] RECOVERY ENABLED." "GOOD" }
$wbadminLog = Get-WinEventSafe @{LogName='System'; ProviderName='Microsoft-Windows-Backup'} -MaxEvents 20 |
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

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
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

# ── PHASE 55.5: KNOWN-VULNERABLE SIGNED DRIVER AUDIT (BYOVD) ───────────────────
# Phase 55 only catches *unsigned* drivers; the real BYOVD risk is signed-but-vulnerable
# drivers (loaded as a kernel service to get kernel R/W and disable EDR). Match loaded/
# registered drivers against the LOLDrivers name list; confirm with SHA256 when present.
# All findings are FixAction Info (a vulnerable driver may be a legit utility — never
# auto-remove; the operator enables the MS Vulnerable Driver Blocklist / WDAC instead).
Show-PhaseHeader "PHASE 55.5" "KNOWN-VULNERABLE SIGNED DRIVER AUDIT (BYOVD)" "ROOTKIT"
Out-Typewriter "CROSS-REFERENCING DRIVERS AGAINST LOLDrivers BYOVD LIST..." "HUNT"
$byovdFound = $false
if ($BYOVD_DRIVER_NAMES.Count -gt 0) {
    $byovdSet = @{}; foreach ($n in $BYOVD_DRIVER_NAMES) { $byovdSet[$n] = $true }
    $byovdHashSet = @{}; foreach ($h in $BYOVD_DRIVER_SHA256) { $byovdHashSet["$($h.SHA256)".ToLower()] = $h.File }
    foreach ($drv in (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        $path = "$($drv.PathName)" -replace '^\\\?\?\\',''
        if (-not $path) { continue }
        $leaf = ([System.IO.Path]::GetFileName($path)).ToLower()
        if (-not $leaf -or -not $byovdSet.ContainsKey($leaf)) { continue }
        $loaded = ($drv.State -eq 'Running' -or $drv.Started)
        $sev = if ($loaded) { $SEV_CRITICAL } else { $SEV_HIGH }
        $hashNote = ""
        if (Test-Path $path) {
            $sha = (Get-FileHashSafe $path)
            if ($sha -and $byovdHashSet.ContainsKey($sha.ToLower())) { $hashNote = " [SHA256-confirmed]" }
            if (-not $hashNote -and @($BYOVD_CERT_TBS_HASHES).Count -gt 0) {
                # WS0 wiring: polymorphic BYOVD variants (TrueSightKiller-class) defeat file
                # hashes; the signing cert's TBS SHA1 stays stable across them. Single-file
                # sig call on an already-matched driver — no SIG_AUDIT budget needed.
                $drvSig = Get-AuthSig $path
                if ($drvSig.SignerCertificate) {
                    $tbs = Get-CertTbsSha1 $drvSig.SignerCertificate
                    if ($tbs -and @($BYOVD_CERT_TBS_HASHES | Where-Object { "$($_.TBS_SHA1)".ToUpper() -eq $tbs }).Count -gt 0) {
                        $hashNote = " [cert-TBS-confirmed]"
                    }
                }
            }
        }
        Out-ThreatBanner "VULNERABLE BYOVD DRIVER" "$leaf (loaded=$loaded)$hashNote"
        Add-Finding -ID "BYOVD_$($leaf -replace '[^a-z0-9]','')" -Phase "PHASE 55.5" -ThreatType "BYOVD / Vulnerable Driver" `
            -Severity $sev -Description "Known-vulnerable signed driver present$hashNote (loaded=$loaded): $leaf @ $path. Abused via BYOVD for kernel R/W to disable EDR / escalate. NOTE: may be a legitimate utility (MSI Afterburner/CPU-Z/etc.) — verify before removal; consider enabling the Microsoft Vulnerable Driver Blocklist / WDAC." `
            -Target $path -FixAction "Info" -Group "BYOVD Vulnerable Drivers"
        $global:RootkitHits++; $byovdFound = $true
    }
}
if (-not $byovdFound) { Out-Typewriter "  -> [OK] NO KNOWN-VULNERABLE BYOVD DRIVERS." "GOOD" }

}   # end QUICK-skip block
Show-PhaseHeader "PHASE 56" "HIDDEN PROCESS DISCREPANCY (WMI vs PS vs TASKLIST)" "ROOTKIT"
Out-Typewriter "CROSS-CORRELATING PROCESS ENUMERATION METHODS..." "HUNT"
Invoke-QuantumBar "PROCESS TABLE DELTA ANALYSIS" 12 130
# Raw enumeration ON PURPOSE — never switch to Get-ProcSnapshot here: this phase diffs the
# WMI process table against Get-Process captured at the same instant, and a cached snapshot
# even seconds stale would fabricate CRITICAL rootkit discrepancy findings.
$wmiPIDs  = (Get-WmiObject Win32_Process -ErrorAction SilentlyContinue).ProcessId
$psPIDs   = (Get-Process -ErrorAction SilentlyContinue).Id
$taskPIDs = (tasklist /FO CSV /NH 2>$null | ConvertFrom-Csv -Header @("Img","PID","Ses","Num","Mem") 2>$null).PID | ForEach-Object { [int]$_ }
$hiddenFromPS   = $wmiPIDs | Where-Object { $_ -notin $psPIDs   -and $_ -gt 4 }
$hiddenFromWMI  = $psPIDs  | Where-Object { $_ -notin $wmiPIDs  -and $_ -gt 4 }
$hiddenFromTask = $wmiPIDs | Where-Object { $_ -notin $taskPIDs -and $_ -gt 4 }
$rkSuspect = $false
# NB: loop var is $rkpid, NOT $pid — $PID is a READ-ONLY automatic variable (this process's
# id); `foreach ($pid ...)` throws "Cannot overwrite variable PID" the moment the list is
# non-empty, which is exactly when a rootkit discrepancy exists — silently killing this phase
# via the module trap. (PS variable names are case-insensitive, so $pid IS $PID.)
foreach ($rkpid in $hiddenFromPS) {
    Out-ThreatBanner "PROCESS HIDDEN FROM GET-PROCESS" "PID: $rkpid — ROOTKIT INDICATOR"
    Add-Finding -ID "RKHIDE_PS_$rkpid" -Phase "PHASE 56" -ThreatType "Rootkit" -Severity $SEV_CRITICAL `
        -Description "PID $rkpid visible in WMI but hidden from Get-Process — rootkit indicator" `
        -Target "PID: $rkpid" -FixAction "Info" -Group "Hidden Process Delta (Rootkit)"
    $global:RootkitHits++; $rkSuspect = $true
}
foreach ($rkpid in $hiddenFromWMI) {
    Out-ThreatBanner "PROCESS HIDDEN FROM WMI" "PID: $rkpid — ROOTKIT INDICATOR"
    Add-Finding -ID "RKHIDE_WMI_$rkpid" -Phase "PHASE 56" -ThreatType "Rootkit" -Severity $SEV_CRITICAL `
        -Description "PID $rkpid visible in PS but hidden from WMI — rootkit indicator" `
        -Target "PID: $rkpid" -FixAction "Info" -Group "Hidden Process Delta (Rootkit)"
    $global:RootkitHits++; $rkSuspect = $true
}
if (-not $rkSuspect) { Out-Typewriter "  -> [OK] NO PROCESS ENUMERATION DISCREPANCIES." "GOOD" }

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 57" "SERVICE REGISTRY DELTA — HIDDEN SERVICE OBJECTS" "ROOTKIT"
Out-Typewriter "COMPARING SERVICE ENUMERATION METHODS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1200 }
$scServices  = (sc.exe query type= all state= all 2>$null | Select-String "SERVICE_NAME:" | ForEach-Object { ($_ -split ": ")[1].Trim() })
$regServices = (Get-ChildItem "HKLM:\System\CurrentControlSet\Services" -ErrorAction SilentlyContinue).PSChildName
$hiddenFromSCM = $regServices | Where-Object { $_ -notin $scServices }
$rootSvcFound = $false
foreach ($svc in $hiddenFromSCM) {
    $svcType = (Get-RegVal "HKLM:\System\CurrentControlSet\Services\$svc" -Name "Type")
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
if ($bcdedit2 -match "winpe|safeboot.*minimal.*AlternateShell") {
    Out-Typewriter "  -> SUSPICIOUS BCD BOOT ENTRY." "CRIT"
    Add-Finding -ID "BOOTKIT_BCD" -Phase "PHASE 58" -ThreatType "Bootkit" -Severity $SEV_HIGH `
        -Description "Suspicious BCD entry detected — possible bootkit modification (winpe/AlternateShell)" `
        -Target "bcdedit /enum all" -FixAction "Info" -Group "Bootkit Indicators"
    $global:RootkitHits++
} else { Out-Typewriter "  -> [OK] BCD BOOT ENTRIES APPEAR CLEAN." "GOOD" }

}   # end QUICK-skip block
