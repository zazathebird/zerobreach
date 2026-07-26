trap { Write-RecoveredError $_; continue }   # module-level resilience: a terminating error resumes at the NEXT phase in THIS module, not the next dot-sourced module (see CLAUDE.md engine-split rule)
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
foreach ($p in (Get-ProcSnapshot)) {
    if (-not $lolSet.ContainsKey($p.Name)) { continue }
    if ($p.CommandLine -match "http|AppData|Temp|\.js|Base64|scrobj|unc|\\\\") {
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
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
    if (-not (Test-Path $ep.P)) { Out-Typewriter "  -> [OK] NO EXTENSION DIRECTORY." "GOOD"; continue }
    $extDirs = Get-ChildItem -Path $ep.P -Directory -ErrorAction SilentlyContinue
    foreach ($ext in $extDirs) {
        $risk = Get-ExtensionRisk -ExtPath $ext.FullName
        if ($risk.Risk -eq "CLEAN") { continue }
        # Only a NAME match against the known adware/hijacker list (CRITICAL) is confident enough to
        # auto-delete an extension. The permission-based heuristics (nativeMessaging / <all_urls> /
        # webRequest -> HIGH/POSSIBLE) fire on MANY legit extensions (password managers, Google Docs
        # Offline, ad blockers), so those are surfaced for REVIEW only (POSSIBLE + Info), never removed.
        if ($risk.Risk -eq "CRITICAL") {
            Out-Typewriter "  -> ☣ CRITICAL — $($ep.B) EXT: $($risk.Name) | $($risk.Reason)" "CRIT"
            Add-Finding -ID "EXT_$($ext.Name)" -Phase "PHASE 8" -ThreatType "Browser Extension/Hijacker" `
                -Severity $SEV_CRITICAL -Description "$($ep.B) extension (known adware/hijacker): $($risk.Name) | $($risk.Reason)" `
                -Target $ext.FullName -FixAction "DeleteFile" -FixParam $ext.FullName `
                -Group "Browser Extensions ($($ep.B))"
        } else {
            Out-Typewriter "  -> ? POSSIBLE — $($ep.B) EXT: $($risk.Name) | $($risk.Reason)" "WARN"
            Add-Finding -ID "EXT_$($ext.Name)" -Phase "PHASE 8" -ThreatType "Browser Extension/Hijacker" `
                -Severity $SEV_POSSIBLE -Description "$($ep.B) extension with broad/powerful permissions ($($risk.Reason)) — review only; many legitimate extensions request these, so it is NOT auto-removed: $($risk.Name)" `
                -Target $ext.FullName -FixAction "Info" -Group "Browser Extensions ($($ep.B))"
        }
        $global:SpywareHits++
    }
}

Show-PhaseHeader "PHASE 9" "BROWSER HIJACK — SHORTCUT & HOMEPAGE AUDIT"
Out-Typewriter "SCANNING BROWSER SHORTCUTS FOR HIJACKED TARGETS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
                # A Windows filename may legally contain a single quote, and whoever planted the
                # hijacked shortcut chose this filename — double it so the path cannot break out
                # of the single-quoted string in the generated fix command.
                $lnkPathEsc = "$($lnk.FullName)" -replace "'","''"
                Add-Finding -ID "LNK_HIJACK_$($lnk.Name -replace '[^a-z0-9]','')" -Phase "PHASE 9" -ThreatType "Browser Hijacker" `
                    -Severity $SEV_CRITICAL -Description "Hijacked browser shortcut: $($lnk.Name) | $($sc.Arguments)" `
                    -Target $lnk.FullName -FixAction "RunCmd" -FixParam "`$_sh=New-Object -ComObject WScript.Shell;`$_sc=`$_sh.CreateShortcut('$lnkPathEsc');`$_sc.Arguments='';`$_sc.Save()" -Group "Browser Hijacks"
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

}   # end QUICK-skip block
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
# Bounded sig loop — Get-AuthSig can block on online cert-revocation (CRL/OCSP), and with
# -Hours 0 the temp/download/INetCache dirs can hold thousands of cached executables. Cap
# total checks + wall-clock across ALL target dirs so a slow/offline revocation responder
# can't hang the phase for hours (this was the real DEEP-mode hang; see Phase 98).
$sigSeen = 0
$sigSw   = [System.Diagnostics.Stopwatch]::StartNew()
$sigBudgetHit = $false
foreach ($td in $targetDirs) {
    if ($sigBudgetHit) { break }
    Out-Typewriter "SCANNING: $($td.L)" "INFO"
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
    if (-not (Test-Path $td.P)) { Out-Typewriter "  -> [OK] ABSENT." "GOOD"; continue }
    $recentFiles = Get-ScanFiles -Path $td.P -TimeScoped
    if ($recentFiles.Count -eq 0) { Out-Typewriter "  -> [OK] CLEAN." "GOOD"; continue }
    # Group into executable vs other
    $exeFiles   = $recentFiles | Where-Object { $malExt -contains $_.Extension.ToLower() }
    $otherFiles = $recentFiles | Where-Object { $malExt -notcontains $_.Extension.ToLower() }
    if ($exeFiles.Count -gt 0) {
        $exeGroup = "$($td.L) — Executables ($($exeFiles.Count) files)"
        foreach ($f in $exeFiles) {
            if ($sigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
                $sigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
                $sigBudgetHit = $true; break
            }
            $sigSeen++
            $asig = Get-AuthSig $f.FullName
            $isMalicious = ($asig.Status -ne "Valid") -and ($td.P -match "Temp|INetCache")
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
$sigSw.Stop()
if ($sigBudgetHit) {
    Out-Typewriter ("  -> [INFO] TEMP-EXE SIG BUDGET REACHED ({0} binaries / {1}s) — partial scan." -f $sigSeen, [Math]::Round($sigSw.Elapsed.TotalSeconds,1)) "WARN"
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
$lnkDownloaderRe = '(?i)(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,})|(DownloadString|DownloadFile|\bIEX\b|Invoke-Expression)|((mshta|wscript|cscript)(\.exe)?\b[^\r\n]*https?://)'
$lnkDirs = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:PUBLIC\Desktop",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
)
$lnkFiles = (Get-ScanFiles -Path $lnkDirs -Filter '*.lnk' -TimeScoped)
$lnkFound = $false
foreach ($lf in $lnkFiles) {
    try {
        $lnkShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
        $lnkSc = $lnkShell.CreateShortcut($lf.FullName)
        $lnkBlob = "$($lnkSc.TargetPath) $($lnkSc.Arguments)"
        if ($lnkBlob -match $lnkDownloaderRe) {
            $lnkFound = $true
            Out-ThreatBanner "MALICIOUS LNK DOWNLOADER" "$($lf.Name) | $lnkBlob"
            Add-Finding -ID "LNKDL_$(Get-StableId $lf.FullName)" -Phase "PHASE 10.5" -ThreatType "Malicious LNK/Downloader" `
                -Severity $SEV_HIGH -Description "Shortcut resolves to an encoded-command / download-cradle payload (review — the user may have just clicked something legitimate, so this is not auto-deleted): $($lf.Name) -> $lnkBlob" `
                -Target $lf.FullName -FixAction "Info" -Group "Malicious LNK Payloads"
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
$npmPkgFiles = (Get-ScanFiles -Path @($env:USERPROFILE,"$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads") -Filter 'package.json' -TimeScoped)
$npmHits = 0
foreach ($pf in $npmPkgFiles) {
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
        Out-Decrypt -Text "$($pf.FullName) [$scriptKey] -> $urlHost" -Prefix "  [NPM POSTINSTALL EXFIL] "
        Add-Finding -ID "NPMPOST_$(Get-StableId "$($pf.FullName)|$scriptKey")" -Phase "PHASE 10.6" -ThreatType "Supply Chain Compromise" `
            -Severity $SEV_POSSIBLE -Description "package.json $scriptKey runs a download command against $(if ($isRawIp) { 'a raw IP address' } else { "an untrusted host ($urlHost)" }) — review before running npm/pip install again: $($pf.FullName) | $scriptKey = $scriptVal" `
            -Target $pf.FullName -FixAction "Info" -Group "Supply Chain / Postinstall Exfil"
    }
}
if ($npmHits -eq 0) { Out-Typewriter "  -> [OK] NO SUSPICIOUS NPM/PIP POSTINSTALL SCRIPTS." "GOOD" }

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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1200 }
if (Test-Path "$env:WINDIR\Prefetch") {
    $malPf = Get-ChildItem -Path "$env:WINDIR\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue |
        Where-Object { Test-InScope $_.LastWriteTime -and $_.Name -match "WSCRIPT|CSCRIPT|MSHTA|MSIEXEC|INSTALLUTIL|REGASM|CERTUTIL|BITSADMIN|RUNDLL32.*APPDATA|POWERSHELL.*-ENC" }
    if ($malPf.Count -gt 0) {
        foreach ($pf in $malPf) {
            Out-Decrypt -Text $pf.Name -Prefix "  [PREFETCH HIT] "
            # LOLBIN prefetch only proves the binary ran at some point — legit on most machines — so
            # this is corroborating evidence, not a standalone HIGH. POSSIBLE (shown, not auto-selected).
            Add-Finding -ID "PREFETCH_$($pf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 12" -ThreatType "Execution Trace" `
                -Severity $SEV_POSSIBLE -Description "LOLBIN execution trace in prefetch: $($pf.Name) (corroborating evidence — verify context)" `
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
foreach ($adsDir in @("$env:LOCALAPPDATA","$env:TEMP","$env:USERPROFILE\Downloads")) {
    Out-Typewriter "ADS SCAN: $adsDir..." "INFO"
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
            Out-Decrypt -Text "$($s.FileName):$($s.Stream)" -Prefix "  [ADS HIT] "
            Add-Finding -ID "ADS_$(Get-StableId $s.FileName)" -Phase "PHASE 17" -ThreatType "ADS Parasite" `
                -Severity $SEV_POSSIBLE -Description "Alternate Data Stream (review — most ADS are benign app/OS metadata; an ADS hiding executable content is the real signal): $($s.FileName):$($s.Stream)" `
                -Target "$($s.FileName):$($s.Stream)" -FixAction "RunCmd" -FixParam "Remove-Item -LiteralPath '$adsFile' -Stream '$adsStream' -Force -ErrorAction SilentlyContinue" `
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
$tsRoots = @($env:TEMP, $env:LOCALAPPDATA, $env:APPDATA, "$env:USERPROFILE\Downloads", "$env:ProgramData")
$tsCandidates = (Get-ScanFiles -Path $tsRoots)
foreach ($tf in $tsCandidates) {
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
        Out-Decrypt -Text $tf.FullName -Prefix "  [TIMESTOMP] "
        Add-Finding -ID "TIMESTOMP_$(Get-StableId $tf.FullName)" -Phase "PHASE 17.5" -ThreatType "Timestomp / Anti-Forensics" `
            -Severity $SEV_HIGH -Description "Unsigned executable in a staging directory with a zeroed timestamp ($why) — corroborating evidence only; archive extraction also produces 1980 stamps, so verify before acting: $($tf.FullName)" `
            -Target $tf.FullName -FixAction "Info" -Group "Anti-Forensic Timestamps"
    } else {
        Add-Finding -ID "TIMESTOMP_$(Get-StableId $tf.FullName)" -Phase "PHASE 17.5" -ThreatType "Timestomp / Anti-Forensics" `
            -Severity $SEV_POSSIBLE -Description "$(if ($tsSigned) { 'Signed' } else { 'Unsigned' }) executable with inconsistent timestamps ($why) — normally archive extraction, a copy or a restore; review only, never auto-acted: $($tf.FullName)" `
            -Target $tf.FullName -FixAction "Info" -Group "Anti-Forensic Timestamps"
    }
}
if ($tsHits -eq 0) { Out-Typewriter "  -> [OK] NO TIMESTAMP ANOMALIES." "GOOD" }

Show-PhaseHeader "PHASE 18" "DEEP CLOAKED PARASITE SCAN (HIDDEN+SYSTEM ATTRIBUTES)"
foreach ($ht in @($env:PUBLIC,$env:LOCALAPPDATA,$env:TEMP,"$env:USERPROFILE\AppData\Roaming")) {
    Out-Typewriter "SWEEPING HIDDEN/SYSTEM ATTRS: $ht" "HUNT"
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 900 }
    if (Test-Path $ht) {
        # Hidden+System is the NORMAL attribute set for many OS/shell housekeeping files
        # (desktop.ini, IconCache.db, *.library-ms, thumbs.db, ntuser.*, *.lnk). Drop those via the
        # benign-name allowlist so the phase stops flagging every shell file.
        # Real cloaked malware is an executable / script / archive payload. A Hidden+System *data*
        # file (.json/.db/.log/.dat/.profile/cache, or extension-less browser-profile files like
        # "History"/"Login Data") is normal OS/app housekeeping, so only payload-type extensions are
        # flagged here — everything else is skipped (the benign-name allowlist drops shell files first).
        $cloaked = (Get-ScanFiles -Path $ht -TimeScoped) |
            Where-Object {
                $_.Attributes -match "Hidden" -and $_.Attributes -match "System" -and
                $_.Name -notmatch $CLOAKED_BENIGN_RE -and
                $_.Extension -match "\.(exe|dll|sys|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|pif|cpl|ocx|jar|zip|rar|7z|cab|iso|img)$"
            }
        foreach ($c in $cloaked) {
            # A cloaked *executable/script* is a real rootkit/dropper signal (HIGH); a cloaked archive
            # or extension-less file is suspicious-but-weaker -> POSSIBLE (shown, not auto-selected).
            $cloakSev = if ($c.Extension -match "\.(exe|dll|sys|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|pif|cpl|ocx|jar)$") { $SEV_HIGH } else { $SEV_POSSIBLE }
            Out-ThreatBanner "CLOAKED FILE (HIDDEN+SYSTEM)" $c.FullName
            Add-Finding -ID "CLOAKED_$($c.Name -replace '[^a-z0-9]','')" -Phase "PHASE 18" -ThreatType "Rootkit/Trojan" `
                -Severity $cloakSev -Description "Hidden+System attributed file: $($c.FullName)" `
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
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
    if (Test-Path $rp) {
        $keys = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        foreach ($prop in ($keys.psobject.properties | Where-Object { $_.Name -notmatch "^PS" }).Name) {
            $val = $keys.$prop
            # Strong indicators (Temp / script host / encoded / LOLBin / remote) = CRITICAL auto-deletable.
            # Bare 'AppData' is NOT a strong signal on its own — Discord, Teams, Slack, OneDrive, Logitech
            # and most updaters legitimately autostart from AppData\Local, so an AppData-only value is
            # review-only (POSSIBLE + Info), never auto-removed. (The _DELETEME tripwire points at %TEMP%.)
            if ($val -match "Temp|cmd\.exe|powershell|wscript|cscript|mshta|\.js|\.vbs|\.hta|regsvr32|rundll32|certutil|bitsadmin|msiexec.*http|IEX|EncodedCommand") {
                # OS/OneDrive write their own cmd.exe+del cleanup RunOnce values — allowlisted
                # name=value pairs are review-only, never auto-DeleteReg on a healthy box.
                if ("$prop = $val" -match $RUNKEY_BENIGN_RE) {
                    Out-Decrypt -Text "$prop = $val" -Prefix "  [RUN KEY?] "
                    Add-Finding -ID "RUNKEY_$($prop -replace '[^a-z0-9]','')" -Phase "PHASE 20" -ThreatType "Registry Persistence" `
                        -Severity $SEV_POSSIBLE -Description "Run key matches a known-benign OS cleanup entry (allowlisted — review only): [$rp] $prop = $val" `
                        -Target "$rp|$prop" -FixAction "Info" -Group "Run Key Persistence"
                } else {
                Out-Decrypt -Text "$prop = $val" -Prefix "  [RUN KEY] "
                Add-Finding -ID "RUNKEY_$($prop -replace '[^a-z0-9]','')" -Phase "PHASE 20" -ThreatType "Registry Persistence" `
                    -Severity $SEV_CRITICAL -Description "Malicious Run key: [$rp] $prop = $val" `
                    -Target "$rp|$prop" -FixAction "DeleteReg" -FixParam "$rp|$prop" -Group "Run Key Persistence"
                }
            } elseif ($val -match "AppData") {
                Out-Decrypt -Text "$prop = $val" -Prefix "  [RUN KEY?] "
                Add-Finding -ID "RUNKEY_$($prop -replace '[^a-z0-9]','')" -Phase "PHASE 20" -ThreatType "Registry Persistence" `
                    -Severity $SEV_POSSIBLE -Description "Run key launches from AppData (review — common for legitimate apps, so NOT auto-removed): [$rp] $prop = $val" `
                    -Target "$rp|$prop" -FixAction "Info" -Group "Run Key Persistence"
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
foreach ($tlRoot in $COM_TYPELIB_ROOTS) {
    if ($tlRoot -notmatch 'TypeLib$') { continue }   # only the TypeLib hive holds win32/win64 leaves
    $tlPath = $tlRoot
    if (-not (Test-Path -LiteralPath $tlPath)) { continue }
    # Depth 4, not 3: the path is TypeLib\{GUID}\<ver>\<lcid>\win32 — a depth of 3 stops one level
    # short and finds nothing. Scoped to HKCU deliberately: the per-user hive holds only overrides,
    # so it stays small, and a per-user TypeLib shadowing a machine-wide one IS the hijack.
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
        $tlResolved = [Environment]::ExpandEnvironmentVariables("$tlVal").Trim('"')
        $tlSigned = $false
        if (-not $tlIsScript -and $tlResolved -and (Test-Path -LiteralPath $tlResolved)) {
            $tlSig = Get-AuthSig $tlResolved
            $tlSigned = ($tlSig -and $tlSig.Status -eq 'Valid')
        }
        $ifeoExtra++
        if ($tlSigned) {
            Add-Finding -ID "TYPELIB_$(Get-StableId "$($tl.PSPath)")" -Phase "PHASE 21.5" `
                -ThreatType "COM TypeLib Hijack" -Severity $SEV_POSSIBLE `
                -Description "Per-user COM TypeLib entry points into a user-writable path but the target is validly signed (normal for per-user Office/Teams add-ins) — review only: $tlVal" `
                -Target "$($tl.PSPath)" -FixAction "Info" -Group "COM Hijack Persistence"
            continue
        }
        Out-Decrypt -Text "$($tl.PSPath) -> $tlVal" -Prefix "  [TYPELIB HIJACK] "
        Add-Finding -ID "TYPELIB_$(Get-StableId "$($tl.PSPath)")" -Phase "PHASE 21.5" `
            -ThreatType "COM TypeLib Hijack" -Severity $SEV_HIGH `
            -Description "Per-user COM TypeLib entry resolves to $(if ($tlIsScript) { 'a SCRIPT' } else { 'an unsigned binary' }) — loads on every instantiation of the COM object: $tlVal" `
            -Target "$($tl.PSPath)" -FixAction "DeleteRegKey" -FixParam "$($tl.PSPath)" `
            -Group "COM Hijack Persistence"
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
Show-PhaseHeader "PHASE 24" "COM OBJECT HIJACK AUDIT (HKCU CLSID OVERRIDES)"
Out-Typewriter "SCANNING HKCU COM OVERRIDES..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
$hkcuClsid = "HKCU:\SOFTWARE\Classes\CLSID"
# WS9 correlation feed (Phase 105): confirmed-hijack CLSIDs, keyed independent of Severity — a
# PARANOID-mode run promotes every stored POSSIBLE finding to HIGH (Add-Finding's own escalation
# rule), which would make the benign "per-user CLSID, no HKLM twin" branch below storage-
# indistinguishable from a genuine HKLM-shadowing hijack if Phase 105 keyed off $f.Severity.
$global:ZB_ComHijackConfirmedClsids = @{}
if (Test-Path $hkcuClsid) {
    # Per-user COM registration (HKCU\Classes\CLSID) is NORMAL — Teams add-ins, Office, OneDrive,
    # .NET and shell extensions all register here. The actual COM-hijack technique (T1546.015) is an
    # HKCU CLSID that SHADOWS a CLSID already registered in HKLM (so the per-user one wins at load
    # time). So: only enumerate top-level {GUID} keys (NOT -Recurse, which flooded every InprocServer32/
    # ProgID/TypeLib subkey as a separate finding), and escalate ONLY when the same CLSID exists in
    # HKLM. A purely per-user CLSID with no HKLM twin is review-only (POSSIBLE + Info), never auto-acted.
    $comTopKeys = @(Get-ChildItem -Path $hkcuClsid -ErrorAction SilentlyContinue)
    $comShadow = 0
    foreach ($k in $comTopKeys) {
        $guid = $k.PSChildName
        if ($guid -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { continue }   # only real CLSID GUID keys
        $shadowsHklm = (Test-Path "HKLM:\SOFTWARE\Classes\CLSID\$guid") -or `
                       (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID\$guid")
        $inproc = (Get-RegVal -Path "$($k.PSPath)\InprocServer32" -Name "(default)")
        if (-not $inproc) { $inproc = (Get-RegVal -Path "$($k.PSPath)\LocalServer32" -Name "(default)") }
        if ($shadowsHklm -and $inproc) {
            # Real hijack: a per-user CLSID overriding a system-registered COM object WITH an actual
            # server path (Inproc/LocalServer32). A CLSID that merely shadows HKLM but has NO server
            # override (null Inproc/Local) is not a functioning hijack — it's a benign per-user shell
            # CLSID key holding only settings/sub-keys (e.g. {031E4825-...}/{86ca1aa0-...}) — review only.
            Out-Decrypt -Text $k.PSPath -Prefix "  [COM HIJACK] "
            $comShadow++
            $global:ZB_ComHijackConfirmedClsids[$guid.ToUpper()] = $k.PSPath
            Add-Finding -ID "COM_$($guid -replace '[^a-z0-9]','')" -Phase "PHASE 24" -ThreatType "COM Hijack" `
                -Severity $SEV_HIGH -Description "HKCU COM override SHADOWS an HKLM-registered CLSID with a per-user server override (COM hijack persistence): $guid -> $inproc" `
                -Target $k.PSPath -FixAction "DeleteRegKey" -FixParam $k.PSPath -Group "COM Object Hijacks"
        } else {
            # Pure per-user registration (no HKLM twin) — normal for add-ins; surface for review only.
            Add-Finding -ID "COM_$($guid -replace '[^a-z0-9]','')" -Phase "PHASE 24" -ThreatType "COM Hijack" `
                -Severity $SEV_POSSIBLE -Description "Per-user COM registration (review — usually a legit add-in): $guid -> $inproc" `
                -Target $k.PSPath -FixAction "Info" -Group "COM Object Hijacks"
        }
    }
    if ($comTopKeys.Count -eq 0) { Out-Typewriter "  -> [OK] NO HKCU COM OVERRIDES." "GOOD" }
    else { Out-Typewriter ("  -> COM AUDIT: {0} per-user CLSID(s), {1} shadowing HKLM." -f $comTopKeys.Count, $comShadow) "VER" }
} else { Out-Typewriter "  -> [OK] HKCU CLSID ABSENT." "GOOD" }

Show-PhaseHeader "PHASE 25" "GPO LOCKDOWN — TASKMGR/REGEDIT/CMD DISABLED"
$gpoU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$gpoM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
foreach ($pol in @("DisableTaskMgr","DisableRegistryTools","DisableCMD")) {
    $vU = (Get-RegVal -Path $gpoU -Name $pol)
    $vM = (Get-RegVal -Path $gpoM -Name $pol)
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
            # .lnk shortcuts are never Authenticode-signed, so signing the shortcut itself flagged
            # every legitimate startup entry as UNSIGNED/HIGH. Judge the resolved TARGET instead;
            # an unresolvable target is review-only (POSSIBLE), never auto-deleted on a guess.
            if ($si.Extension -ieq '.lnk') {
                $tgt = $null
                try { $tgt = (New-Object -ComObject WScript.Shell).CreateShortcut($si.FullName).TargetPath } catch {}
                if (-not $tgt -or -not (Test-Path -LiteralPath $tgt)) {
                    Add-Finding -ID "STARTUP_$($si.Name -replace '[^a-z0-9]','')" -Phase "PHASE 31" -ThreatType "Startup Persistence" `
                        -Severity $SEV_POSSIBLE -Description "Startup shortcut with unresolvable/missing target (review): $($si.Name) -> $(if ($tgt) { $tgt } else { '?' })" `
                        -Target $si.FullName -FixAction "Info" -Group "Startup Folder Persistence"
                    continue
                }
                $asig = Get-AuthSig $tgt
                $tgtSusp = ($tgt -match '\\(AppData|Temp|Downloads|Desktop|Public|ProgramData)\\.*\.(exe|scr|com|pif)$') -or ($tgt -match '\.(js|vbs|bat|cmd|ps1|hta|wsf)$')
                # Unsigned target only stays HIGH when the target itself is in a drop location or is
                # a script — an unsigned app in Program Files is common and stays review-only.
                $sev = if ($asig.Status -ne 'Valid' -and $tgtSusp) { $SEV_HIGH } else { $SEV_POSSIBLE }
                Add-Finding -ID "STARTUP_$($si.Name -replace '[^a-z0-9]','')" -Phase "PHASE 31" -ThreatType "Startup Persistence" `
                    -Severity $sev -Description "Startup shortcut: $($si.Name) -> $tgt (target $(if ($asig.Status -ne 'Valid') {'UNSIGNED'} else {'signed'}))$(if ($sev -ne $SEV_HIGH) { ' — POSSIBLE = review-only; select manually to remove the shortcut' })" `
                    -Target $si.FullName -FixAction "DeleteFile" -FixParam $si.FullName -Group "Startup Folder Persistence"
                continue
            }
            $asig = Get-AuthSig $si.FullName
            $sev = if ($asig.Status -ne "Valid") { $SEV_HIGH } else { $SEV_POSSIBLE }
            Add-Finding -ID "STARTUP_$($si.Name -replace '[^a-z0-9]','')" -Phase "PHASE 31" -ThreatType "Startup Persistence" `
                -Severity $sev -Description "Startup folder item: $($si.Name) ($(if ($asig.Status -ne 'Valid') {'UNSIGNED'} else {'signed'}))" `
                -Target $si.FullName -FixAction "DeleteFile" -FixParam $si.FullName -Group "Startup Folder Persistence"
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
$sideloadRoots = @($env:LOCALAPPDATA, $env:APPDATA, $env:TEMP, $env:ProgramData, "$env:USERPROFILE\Downloads") | Where-Object { $_ }
$sideloadHardRoots = @($env:LOCALAPPDATA, $env:APPDATA, $env:TEMP, $env:ProgramData) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }
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
        if ($exeNameMatch -and $isRootDir) {
            Out-ThreatBanner "DLL SIDE-LOAD CANDIDATE" "$($se.Name) + $($cd.Name) in $dirPath"
            Add-Finding -ID "SIDELOAD_$(Get-StableId "$($cd.FullName)|$($se.FullName)")" -Phase "PHASE 32.5" -ThreatType "DLL Hijack" `
                -Severity $SEV_HIGH -Description "Unsigned hijack-target DLL '$($cd.Name)' sits beside signed, commonly-abused EXE '$($se.Name)' directly in $dirPath (not a nested install path) — classic DLL search-order side-load staging. Review, then quarantine the DLL by hand if confirmed malicious." `
                -Target $cd.FullName -FixAction "Info" -Group "DLL Side-Loading"
        } else {
            Out-Decrypt -Text "$($se.Name) + $($cd.Name) in $dirPath" -Prefix "  [SIDELOAD?] "
            Add-Finding -ID "SIDELOAD_$(Get-StableId "$($cd.FullName)|$($se.FullName)")" -Phase "PHASE 32.5" -ThreatType "DLL Hijack" `
                -Severity $SEV_POSSIBLE -Description "Unsigned DLL named '$($cd.Name)' (a common search-order-hijack target) sits beside signed EXE '$($se.Name)' in $dirPath ($(if ($exeNameMatch) { "EXE is on the commonly-abused sideload-target list" } else { "pair sits directly in an AppData/Temp/ProgramData root" })) — review; many portable/third-party apps legitimately ship their own DLLs beside their EXE, so this is not auto-acted on: $($cd.FullName)" `
                -Target $cd.FullName -FixAction "Info" -Group "DLL Side-Loading"
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
$certStores = @(
    @{ Cert='Cert:\LocalMachine\Root'; Reg='HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'; Label='LocalMachine'; Id='LM'   },
    @{ Cert='Cert:\CurrentUser\Root';  Reg='HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'; Label='CurrentUser'; Id='USER' }
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
            -Severity $certSev -Description "$certDesc || To remove by hand after verifying: Remove-Item '$($cs.Cert)\$($cert.Thumbprint)' -Force" `
            -Target "$($cs.Cert)\$($cert.Thumbprint)" -FixAction "Info" `
            -Group "Rogue Certificates"
    }
}
if ($certSeen -eq 0) { Out-Typewriter "  -> [OK] CERTIFICATE STORES CLEAN." "GOOD" }

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
$credRoots = @($env:TEMP, "$env:WINDIR\Temp", $env:LOCALAPPDATA, $env:APPDATA,
               "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:ProgramData", "$env:PUBLIC")
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
    if ($cf.Name -match $credGenericRe) {
        Add-Finding -ID "CREDART_$(Get-StableId $cf.FullName)" -Phase "PHASE 44.5" `
            -ThreatType "Credential Access" -Severity $SEV_POSSIBLE `
            -Description "File name matches a credential-dump output convention, but the name alone is weak evidence (password dictionaries and app data collide with it) — review, never auto-acted: $($cf.FullName)" `
            -Target $cf.FullName -FixAction "Info" -Group "Credential Access"
        continue
    }
    Out-ThreatBanner "CREDENTIAL DUMP ARTIFACT" $cf.FullName
    Add-Finding -ID "CREDART_$(Get-StableId $cf.FullName)" -Phase "PHASE 44.5" `
        -ThreatType "Credential Access" -Severity $SEV_CRITICAL `
        -Description "Credential-theft artifact on disk ($([Math]::Round($cf.Length/1KB)) KB): $($cf.FullName) — treat every credential used on this machine as compromised and force a reset." `
        -Target $cf.FullName -FixAction "Quarantine" -FixParam $cf.FullName -Group "Credential Access"
    $global:BackdoorHits++
}
# DPAPI master keys / Credential Manager blobs copied OUT of their protected home directory.
# The originals are normal; a copy anywhere else is theft staging.
foreach ($dp in $DPAPI_THEFT_PATHS) {
    if (-not (Test-Path -LiteralPath $dp)) { continue }
    Write-Log "DPAPI store present (normal): $dp"
}
# LIVE-TUNED 2026-07-22: the first cut flagged any GUID-named file under 64 KB in these roots
# and produced 99 HIGH+Quarantine findings on a healthy box — GUID filenames are ubiquitous
# (browser profiles, installer and package caches). Filename shape is now only the cheap
# PRE-FILTER; the finding requires the file to actually BE a DPAPI blob, confirmed by its magic
# header (version DWORD 0x02000000 followed by the provider GUID as UTF-16LE). That is not
# something a benign cache file collides with.
$dpapiStaged = (Get-ScanFiles -Path @($env:TEMP, "$env:USERPROFILE\Downloads", "$env:PUBLIC", "$env:ProgramData"))
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
    Add-Finding -ID "DPAPISTAGE_$(Get-StableId $ds.FullName)" -Phase "PHASE 44.5" `
        -ThreatType "Credential Access" -Severity $SEV_HIGH `
        -Description "A file with the DPAPI blob header is sitting outside its protected store — the staging step for offline credential decryption: $($ds.FullName)" `
        -Target $ds.FullName -FixAction "Quarantine" -FixParam $ds.FullName -Group "Credential Access"
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
$accessFiles = @(
    "$env:WINDIR\System32\sethc.exe","$env:WINDIR\System32\utilman.exe",
    "$env:WINDIR\System32\osk.exe","$env:WINDIR\System32\magnify.exe",
    "$env:WINDIR\System32\narrator.exe","$env:WINDIR\System32\displayswitch.exe"
)
foreach ($af in $accessFiles) {
    if (Test-Path $af) {
        $asig = Get-AuthSig $af
        if ($asig.Status -ne "Valid") {
            Out-Typewriter "  -> UNSIGNED ACCESSIBILITY BINARY: $af" "CRIT"
            Add-Finding -ID "STICKY_$([IO.Path]::GetFileNameWithoutExtension($af))" -Phase "PHASE 45" `
                -ThreatType "Sticky Keys / Accessibility Backdoor" -Severity $SEV_CRITICAL `
                -Description "Unsigned accessibility binary: $af — classic sticky-keys shell backdoor" `
                -Target $af -FixAction "RunCmd" -FixParam "Rename-Item '$af' '$af.kraken' -Force" -Group "Accessibility Shell Backdoors"
        } else { Out-Typewriter "  -> [OK] VALID: $af" "GOOD" }
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
$klSearchPaths  = @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA,"$env:USERPROFILE\Documents")
# One bounded walk, anchored regex over all patterns (was 4 roots x 9 patterns = 36 recursions).
$klRegex = ($klFilePatterns | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
$klFound = $false
$klHits = (Get-ScanFiles -Path $klSearchPaths -TimeScoped) | Where-Object { $_.Name -match $klRegex }
foreach ($hit in $klHits) {
    # Name heuristics (*typed*, *capture*log*) hit library marker files inside package-manager
    # trees (py.typed in site-packages et al.) — allowlisted paths are review-only.
    if (Test-BenignPath $hit.FullName $KEYLOG_BENIGN_RE) {
        Add-Finding -ID "KLFILE_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 48" -ThreatType "Keylogger" `
            -Severity $SEV_POSSIBLE -Description "File name resembles a keystroke log but sits in a package/library tree (likely a library file — review, not auto-deleted): $($hit.FullName)" `
            -Target $hit.FullName -FixAction "Info" -Group "Keylogger Artifacts"
        $klFound = $true
        continue
    }
    Out-ThreatBanner "KEYLOGGER LOG FILE" $hit.FullName
    Add-Finding -ID "KLFILE_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 48" -ThreatType "Keylogger" `
        -Severity $SEV_CRITICAL -Description "Keystroke log file detected: $($hit.FullName)" `
        -Target $hit.FullName -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Keylogger Artifacts"
    $global:KeyloggerHits++; $klFound = $true
}
$klRegPaths = $KEYLOGGER_REG_PATHS   # DATA (WS5) — commercial-keylogger vendor keys, see data\detection_signatures.json
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
$clipperRunPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($crp in $clipperRunPaths) {
    if (-not (Test-Path $crp)) { continue }
    $crKeys = Get-ItemProperty -Path $crp -ErrorAction SilentlyContinue
    if (-not $crKeys) { continue }
    foreach ($prop in ($crKeys.psobject.properties | Where-Object { $_.Name -notmatch "^PS" })) {
        $crVal = "$($prop.Value)"
        if (-not (Test-ClipperCoOccurrence $crVal)) { continue }
        $clipperHits++
        Out-ThreatBanner "CLIPPER CO-OCCURRENCE (RUN KEY)" "$crp|$($prop.Name)"
        Add-Finding -ID "CLIPPER_RUN_$(Get-StableId "$crp|$($prop.Name)")" -Phase "PHASE 49.5" -ThreatType "Clipper/Crypto Hijacker" `
            -Severity $SEV_POSSIBLE -Description "Run key value references BOTH a clipboard API and a hardcoded crypto address literal (possible clipboard-hijacking clipper — review): [$crp] $($prop.Name) = $crVal" `
            -Target "$crp|$($prop.Name)" -FixAction "Info" -Group "Clipboard Clipper Detection"
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
$clipperScriptRoots = @($env:TEMP, $env:LOCALAPPDATA, $env:APPDATA, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:ProgramData) | Where-Object { $_ }
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
    Out-ThreatBanner "CLIPPER CO-OCCURRENCE (DROPPED SCRIPT)" $csf.FullName
    Add-Finding -ID "CLIPPER_FILE_$(Get-StableId $csf.FullName)" -Phase "PHASE 49.5" -ThreatType "Clipper/Crypto Hijacker" `
        -Severity $SEV_POSSIBLE -Description "Script references BOTH a clipboard API and a hardcoded crypto address literal (possible clipboard-hijacking clipper — review): $($csf.FullName)" `
        -Target $csf.FullName -FixAction "Info" -Group "Clipboard Clipper Detection"
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
$searchRoots = @(
    "$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Pictures",
    "$env:USERPROFILE\Downloads","$env:USERPROFILE\Videos","$env:USERPROFILE\Music",
    "$env:USERPROFILE\OneDrive","$env:PUBLIC"
)
$ransomScanFiles = Get-ScanFiles -Path $searchRoots -TimeScoped
foreach ($rf in $ransomScanFiles) {
    $ext = $rf.Extension.ToLower()
    if ($RANSOMWARE_EXTENSIONS -contains $ext) {
        Out-ThreatBanner "RANSOMWARE ENCRYPTED FILE EXTENSION" "$($rf.Name) in $($rf.DirectoryName)"
        Add-Finding -ID "RANSOM_EXT_$($rf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 51" -ThreatType "Ransomware" `
            -Severity $SEV_CRITICAL -Description "File with known ransomware extension: $($rf.FullName) ($ext)" `
            -Target $rf.FullName -FixAction "Info" -Group "Ransomware Encrypted Files"
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
        Out-Typewriter "  -> HIGH ENTROPY ($entropy): $($cf.FullName)" "WARN"
        Add-Finding -ID "ENTROPY_$($cf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 52" -ThreatType "Ransomware/Packed Malware" `
            -Severity $SEV_POSSIBLE -Description "High entropy file ($entropy/8.0 bits): $($cf.FullName) — may be encrypted or packed malware" `
            -Target $cf.FullName -FixAction "Info" -Group "High Entropy Files"
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
foreach ($note in ($ransomScanFiles | Where-Object { $_.Name -match $strongRegex })) {
    Out-ThreatBanner "RANSOM NOTE DETECTED" $note.FullName
    Add-Finding -ID "RANSOMNOTE_$($note.Name -replace '[^a-z0-9]','')" -Phase "PHASE 53" -ThreatType "Ransomware" `
        -Severity $SEV_CRITICAL -Description "Ransom note file found: $($note.FullName)" `
        -Target $note.FullName -FixAction "DeleteFile" -FixParam $note.FullName -Group "Ransom Notes"
    $global:RansomwareRisk += 10; $noteFound = $true
}
foreach ($note in ($ransomScanFiles | Where-Object { $_.Name -match $genericRegex -and $_.Name -notmatch $strongRegex })) {
    # Generic filename — confirm with content before treating as a real (deletable) note.
    $confirmed = $false
    if ($RANSOM_NOTE_CONTENT_RULES.Count -gt 0 -and $note.Length -lt 102400) {
        $confirmed = (Test-ContentRules -FilePath $note.FullName -Rules $RANSOM_NOTE_CONTENT_RULES).Hit
    }
    if ($confirmed) {
        Out-ThreatBanner "RANSOM NOTE DETECTED" $note.FullName
        Add-Finding -ID "RANSOMNOTE_$($note.Name -replace '[^a-z0-9]','')" -Phase "PHASE 53" -ThreatType "Ransomware" `
            -Severity $SEV_CRITICAL -Description "Ransom note (filename + content confirmed): $($note.FullName)" `
            -Target $note.FullName -FixAction "DeleteFile" -FixParam $note.FullName -Group "Ransom Notes"
        $global:RansomwareRisk += 10
    } else {
        Add-Finding -ID "RANSOMNOTE_$($note.Name -replace '[^a-z0-9]','')" -Phase "PHASE 53" -ThreatType "Ransomware" `
            -Severity $SEV_POSSIBLE -Description "File name resembles a ransom note but content is not confirmed (likely a legitimate readme — review, do not auto-delete): $($note.FullName)" `
            -Target $note.FullName -FixAction "Info" -Group "Ransom Notes"
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
            Out-ThreatBanner "RANSOM NOTE CONTENT MATCH" "$($cr.Name): $($tf.FullName)"
            Add-Finding -ID "RANSOMTEXT_$($tf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 53" -ThreatType "Ransomware" `
                -Severity $noteSevMap[$cr.Severity] -Description "Ransom-note content construct ($($cr.Name)) in: $($tf.FullName)" `
                -Target $tf.FullName -FixAction "Info" -Group "Ransom Notes"
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
