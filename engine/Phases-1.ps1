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
# Consolidated onto the shared LOLBAS list (was a near-duplicate inline 46-name
# list); single source of truth in data/detection_signatures.json (lolbas_expanded).
$lolbins = $LOLBAS_EXPANDED
$lolHits = $false
# One WMI enumeration + case-insensitive name lookup instead of one filtered
# Get-WmiObject query per LOLBIN name (was ~46 WMI round-trips per scan).
$lolSet = @{}; foreach ($lb in $lolbins) { $lolSet["$lb.exe"] = $true }
foreach ($p in (Get-WmiObject Win32_Process -ErrorAction SilentlyContinue)) {
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
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
$shortcutDirs = @("$env:USERPROFILE\Desktop","$env:APPDATA\Microsoft\Windows\Start Menu\Programs","$env:PUBLIC\Desktop")
$_lnkShell = $null
try { $_lnkShell = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch {}
if ($_lnkShell) {
    foreach ($dir in $shortcutDirs) {
        if (-not (Test-Path $dir)) { continue }
        $lnks = Get-ChildItem -Path $dir -Filter "*.lnk" -ErrorAction SilentlyContinue
        foreach ($lnk in $lnks) {
            try {
                $sc = $_lnkShell.CreateShortcut($lnk.FullName)
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
}
$chromePrefs = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
if (Test-Path $chromePrefs) {
    # Regex-extract homepage field instead of full ConvertFrom-Json — Preferences can be 20MB+
    # and PS 5.1 ConvertFrom-Json is O(n) slow on large files, causing a multi-minute hang.
    $chromeRaw = $null
    try { $chromeRaw = [System.IO.File]::ReadAllText($chromePrefs) } catch {}
    if ($chromeRaw) {
        $hpMatch = [regex]::Match($chromeRaw, '"homepage"\s*:\s*"([^"]+)"')
        if ($hpMatch.Success) {
            $hp = $hpMatch.Groups[1].Value
            if ($hp -notmatch '^(https?://(www\.)?google\.|about:blank|newtab)') {
                Out-Typewriter "  -> HIJACKED CHROME HOMEPAGE: $hp" "CRIT"
                Add-Finding -ID "CHROME_HOMEPAGE" -Phase "PHASE 9" -ThreatType "Browser Hijacker" -Severity $SEV_HIGH `
                    -Description "Suspicious Chrome homepage: $hp" -Target $chromePrefs `
                    -FixAction "Info" -Group "Browser Hijacks"
                $global:SpywareHits++
            }
        }
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
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
    if (-not (Test-Path $td.P)) { Out-Typewriter "  -> [OK] ABSENT." "GOOD"; continue }
    $recentFiles = Get-ScanFiles -Path $td.P -TimeScoped
    if ($recentFiles.Count -eq 0) { Out-Typewriter "  -> [OK] CLEAN." "GOOD"; continue }
    # Group into executable vs other
    $exeFiles   = $recentFiles | Where-Object { $malExt -contains $_.Extension.ToLower() }
    $otherFiles = $recentFiles | Where-Object { $malExt -notcontains $_.Extension.ToLower() }
    if ($exeFiles.Count -gt 0) {
        $exeGroup = "$($td.L) — Executables ($($exeFiles.Count) files)"
        # Severity by location — skip Get-AuthenticodeSignature (CRL network call, blocks per file)
        $sev = if ($td.P -match 'Temp|INetCache') { $SEV_HIGH } else { $SEV_POSSIBLE }
        foreach ($f in $exeFiles) {
            Add-Finding -ID "TEMPEXE_$($f.Name -replace '[^a-z0-9]','')" -Phase "PHASE 10" -ThreatType "Suspicious File" `
                -Severity $sev -Description "Executable in $($td.L): $($f.Name)" `
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1200 }
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
foreach ($sf in $recentSysFiles) {
    $sig = Get-AuthSig $sf.FullName
    if ($sig -and $sig.Status -ne "Valid" -and $sig.Status -ne "NotSigned") {
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
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
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
# Prune OS-managed app sandboxes ('packages' = Store apps, 'windowsapps' = MSIX): their
# app-data is legitimately Hidden+System and produced a ~15k-finding flood that bloated
# reports to 50MB and froze the UI. The real cloaked-malware signal is a Hidden+System
# *executable/script* (or an extensionless binary) in a user-writable path — so also gate
# on extension and cap total findings so no future tree can flood the report again.
$_p18Prune  = $global:SCAN_PRUNE_DIRS + @('packages','windowsapps','user data','default','extensions','local extension settings','managed extension storage','sync app settings')
$_p18Cap    = 200
$_cloakedN  = 0
$_p18Capped = $false
:p18roots foreach ($ht in @($env:PUBLIC,$env:LOCALAPPDATA,$env:TEMP,"$env:USERPROFILE\AppData\Roaming")) {
    if ($_cloakedN -ge $_p18Cap) { $_p18Capped = $true; break p18roots }
    Out-Typewriter "SWEEPING HIDDEN/SYSTEM ATTRS: $ht" "HUNT"
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 900 }
    if (Test-Path $ht) {
        $cloaked = @(Get-ScanFiles -Path $ht -TimeScoped -PruneDirs $_p18Prune |
            Where-Object {
                $_.Attributes -match "Hidden" -and $_.Attributes -match "System" -and
                (($malExt -contains $_.Extension.ToLower()) -or ($_.Extension -eq ''))
            })
        foreach ($c in $cloaked) {
            if ($_cloakedN -ge $_p18Cap) { $_p18Capped = $true; break }
            Out-ThreatBanner "CLOAKED FILE (HIDDEN+SYSTEM)" $c.FullName
            Add-Finding -ID "CLOAKED_$($c.Name -replace '[^a-z0-9]','')" -Phase "PHASE 18" -ThreatType "Rootkit/Trojan" `
                -Severity $SEV_HIGH -Description "Hidden+System executable/script: $($c.FullName)" `
                -Target $c.FullName -FixAction "DeleteFile" -FixParam $c.FullName -Group "Cloaked/Hidden Files"
            $_cloakedN++
        }
        if ($cloaked.Count -eq 0) { Out-Typewriter "  -> [OK] NO CLOAKED FILES." "GOOD" }
    }
}
if ($_p18Capped) { Out-Typewriter "  -> [!] CLOAKED-FILE CAP ($_p18Cap) REACHED — further hits suppressed; review the $_p18Cap above." "WARN" }

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
    if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
                -Severity $SEV_CRITICAL -Description "Unknown entry in SafeBoot\${sm}: $($k.PSChildName) — malware SafeBoot persistence" `
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1400 }
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
            $sig = Get-AuthSig $si.FullName
            $unsigned = (-not $sig -or $sig.Status -ne "Valid")
            $sev = if ($unsigned) { $SEV_HIGH } else { $SEV_POSSIBLE }
            Add-Finding -ID "STARTUP_$($si.Name -replace '[^a-z0-9]','')" -Phase "PHASE 31" -ThreatType "Startup Persistence" `
                -Severity $sev -Description "Startup folder item: $($si.Name) ($(if ($unsigned) {'UNSIGNED'} else {'signed'}))" `
                -Target $si.FullName -FixAction "DeleteFile" -FixParam $si.FullName -Group "Startup Folder Persistence"
        }
    }
}

Show-PhaseHeader "PHASE 32" "DLL SEARCH ORDER HIJACK — PATH AUDIT"
Out-Typewriter "AUDITING WRITABLE PATH ENTRIES..." "INFO"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
            $sig = Get-AuthSig $dll.FullName
            if ($sig -and $sig.Status -ne "Valid") {
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1400 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1400 }
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
$elevatedInUS = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
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

Show-PhaseHeader "PHASE 45" "ACCESSIBILITY SHELL BACKDOOR (STICKY KEYS / UTILMAN)"
$accessFiles = @(
    "$env:WINDIR\System32\sethc.exe","$env:WINDIR\System32\utilman.exe",
    "$env:WINDIR\System32\osk.exe","$env:WINDIR\System32\magnify.exe",
    "$env:WINDIR\System32\narrator.exe","$env:WINDIR\System32\displayswitch.exe"
)
foreach ($af in $accessFiles) {
    if (Test-Path $af) {
        $sig = Get-AuthSig $af
        if ($sig -and $sig.Status -ne "Valid") {
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
$klFilePatterns = @("*keystroke*","*keylog*","*keypress*","*kgb*","*.klg","*.kl","*hook.log*")
$klSearchPaths  = @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA,"$env:USERPROFILE\Documents")
# One bounded walk, anchored regex over all patterns (was 4 roots x 9 patterns = 36 recursions).
$klRegex = ($klFilePatterns | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
$klFound = $false
$klHits = Get-ScanFiles -Path $klSearchPaths -TimeScoped | Where-Object { $_.Name -match $klRegex }
foreach ($hit in $klHits) {
    Out-ThreatBanner "KEYLOGGER LOG FILE" $hit.FullName
    Add-Finding -ID "KLFILE_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 48" -ThreatType "Keylogger" `
        -Severity $SEV_CRITICAL -Description "Keystroke log file detected: $($hit.FullName)" `
        -Target $hit.FullName -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Keylogger Artifacts"
    $global:KeyloggerHits++; $klFound = $true
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

Show-PhaseHeader "PHASE 53" "RANSOM NOTE DETECTION" "RANSOMWARE"
Out-Typewriter "SCANNING FOR RANSOM NOTE ARTIFACTS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
$ransomNotePatterns = @("*readme*.txt","*DECRYPT*","*RECOVER*","*ransom*","*YOUR_FILES*","*HOW_TO_DECRYPT*","*!readme!*","*restore_files*","*HOW TO RECOVER*","*IMPORTANT*.txt","*help_decrypt*")
# Collapse 11 patterns × N roots (was 55 full recursions) into ONE in-memory regex over the
# shared phase-51 walk. Wildcards -> regex: escape, then \* -> .*  (case-insensitive -match).
$noteRegex = ($ransomNotePatterns | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
$noteFound = $false
$noteFiles = $ransomScanFiles | Where-Object { $_.Name -match $noteRegex }
foreach ($note in $noteFiles) {
    Out-ThreatBanner "RANSOM NOTE DETECTED" $note.FullName
    Add-Finding -ID "RANSOMNOTE_$($note.Name -replace '[^a-z0-9]','')" -Phase "PHASE 53" -ThreatType "Ransomware" `
        -Severity $SEV_CRITICAL -Description "Ransom note file found: $($note.FullName)" `
        -Target $note.FullName -FixAction "DeleteFile" -FixParam $note.FullName -Group "Ransom Notes"
    $global:RansomwareRisk += 10; $noteFound = $true
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1200 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
if ($bcdedit2 -match "winpe|safeboot.*minimal.*AlternateShell") {
    Out-Typewriter "  -> SUSPICIOUS BCD BOOT ENTRY." "CRIT"
    Add-Finding -ID "BOOTKIT_BCD" -Phase "PHASE 58" -ThreatType "Bootkit" -Severity $SEV_HIGH `
        -Description "Suspicious BCD entry detected — possible bootkit modification (winpe/AlternateShell)" `
        -Target "bcdedit /enum all" -FixAction "Info" -Group "Bootkit Indicators"
    $global:RootkitHits++
} else { Out-Typewriter "  -> [OK] BCD BOOT ENTRIES APPEAR CLEAN." "GOOD" }

