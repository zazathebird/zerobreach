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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1200 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
    # Match only specific C2/RAT framework pipe names (externalized to data — AMSI-safe + tunable).
    # The old inline pattern ended in "[a-f0-9]{8,}", which matched virtually every legitimate
    # Windows RPC/COM/GUID-named pipe -> ~100 CRITICAL false positives. Do NOT reintroduce a broad
    # hex/GUID catch-all here (see c2_named_pipe_regex note in detection_signatures.json).
    $suspectPipes = $pipes | Where-Object { $_ -match $C2_NAMED_PIPE_RE }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
$shares = Get-WmiObject Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "^(ADMIN|IPC|print)\$" }
# Bounded sig loop — up to 500 share binaries × Get-AuthSig, which can block on online
# cert-revocation (CRL/OCSP). Cap total checks + wall-clock across ALL shares so a slow
# responder (or a UNC share over a slow link) can't hang the phase (see Phase 98).
$sigSeen = 0
$sigSw   = [System.Diagnostics.Stopwatch]::StartNew()
$sigBudgetHit = $false
# The IR tool itself usually lives under a shared user profile (e.g. a "Users" share), so never
# flag — let alone offer to DELETE — the scanner's own files. Skip anything under our script root.
$selfRoot = $global:ZB_ROOT
# The local user-profiles tree (C:\Users) is frequently shared as "Users", but the exes under it
# are the operator's OWN downloads/installers/dev builds (7-Zip, app setups, PyInstaller dist\*.exe)
# — not a worm someone dropped into a foreign share. The worm-propagation concern is an unsigned
# PE that appeared in a share you DON'T control, so only those escalate to HIGH+DeleteFile; unsigned
# exes inside the local profiles tree are surfaced for review only (rule #1: never auto-delete the
# user's own files).
$usersRoot = Split-Path $env:USERPROFILE -Parent
foreach ($share in $shares) {
    if ($sigBudgetHit) { break }
    Out-Typewriter "  -> OPEN SHARE: $($share.Name) @ $($share.Path)" "WARN"
    if ($share.Path -and (Test-Path $share.Path)) {
        $malInShare = (Get-ScanFiles -Path $share.Path -TimeScoped) |
            Where-Object { $_.Extension -match "\.(exe|scr|com|pif|bat|cmd|vbs|js|ps1)$" } |
            Select-Object -First 500
        foreach ($mis in $malInShare) {
            if ($sigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
                $sigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
                $sigBudgetHit = $true; break
            }
            if ($selfRoot -and $mis.FullName -like "$selfRoot*") { continue }   # never flag our own files
            $sigSeen++
            $sig = Get-AuthSig $mis.FullName
            if ($sig.Status -ne "Valid") {
                if ($mis.Extension -match "\.(exe|scr|com|pif)$") {
                    if ($usersRoot -and $mis.FullName.ToLower().StartsWith($usersRoot.ToLower())) {
                        # Unsigned PE inside the local profiles tree — the user's own download/build, not
                        # a foreign worm. Surface for review; never auto-delete the user's installers.
                        Add-Finding -ID "SHAREWORM_$($mis.Name -replace '[^a-z0-9]','')" -Phase "PHASE 66" -ThreatType "Worm/Network Share" `
                            -Severity $SEV_POSSIBLE -Description "Unsigned executable in a shared user-profile path (review — usually the user's own download/build): $($mis.FullName)" `
                            -Target $mis.FullName -FixAction "Info" -Group "Network Share Worms"
                    } else {
                        # A real unsigned PE dropped in a foreign/public open share is the classic worm vector.
                        Out-ThreatBanner "UNSIGNED EXE IN OPEN SHARE" $mis.FullName
                        Add-Finding -ID "SHAREWORM_$($mis.Name -replace '[^a-z0-9]','')" -Phase "PHASE 66" -ThreatType "Worm/Network Share" `
                            -Severity $SEV_HIGH -Description "Unsigned executable in open share: $($mis.FullName)" `
                            -Target $mis.FullName -FixAction "DeleteFile" -FixParam $mis.FullName -Group "Network Share Worms"
                        $global:WormHits++
                    }
                } else {
                    # An unsigned *script* in a share is weak signal — a user's own profile share is full
                    # of their own .ps1/.bat/.js. Surface for review only; never auto-delete the user's scripts.
                    Add-Finding -ID "SHAREWORM_$($mis.Name -replace '[^a-z0-9]','')" -Phase "PHASE 66" -ThreatType "Worm/Network Share" `
                        -Severity $SEV_POSSIBLE -Description "Unsigned script in open share (review — often a user's own file): $($mis.FullName)" `
                        -Target $mis.FullName -FixAction "Info" -Group "Network Share Worms"
                }
            }
        }
    }
}
$sigSw.Stop()
if ($sigBudgetHit) {
    Out-Typewriter ("  -> [INFO] SHARE-WORM SIG BUDGET REACHED ({0} binaries / {1}s) — partial scan." -f $sigSeen, [Math]::Round($sigSw.Elapsed.TotalSeconds,1)) "WARN"
}
if ($shares.Count -eq 0) { Out-Typewriter "  -> [OK] NO NON-STANDARD SHARES FOUND." "GOOD" }

Show-PhaseHeader "PHASE 67" "ADWARE / PUP / SPYWARE REGISTRY SCAN" "SPYWARE"
Out-Typewriter "SCANNING FOR KNOWN ADWARE / PUP REGISTRY KEYS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
$stealerFiles = (Get-ScanFiles -Path @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA) -TimeScoped) |
    Where-Object { $_.Name -match "passwords|credentials|wallet|login|autofill|cookie" -and $_.Extension -match "\.(zip|txt|log|db)$" }
foreach ($sf in $stealerFiles) {
    # Exclude legitimate browser storage + known-benign dictionaries/caches (ZxcvbnData password
    # lists, *.LICENSE.txt, Edge Wallet bundles, Cef/EBWebView caches) — these are NOT creds dumps.
    if ($sf.FullName -match "Chrome\\User Data|Firefox\\Profiles" -or $sf.FullName -match $INFOSTEALER_BENIGN_RE) { continue }
    # A loose .txt/.log/.db merely *named* like a credential store is weak evidence and FP-prone;
    # treat it as POSSIBLE (shown, not auto-selected for destructive remediation). A creds *archive*
    # (.zip) staged in a user path is a stronger stealer signal -> keep HIGH.
    $stealSev = if ($sf.Extension -match "\.zip$") { $SEV_HIGH } else { $SEV_POSSIBLE }
    Out-Typewriter "  -> SUSPECT CREDENTIAL FILE: $($sf.FullName)" "CRIT"
    Add-Finding -ID "STEALFILE_$($sf.Name -replace '[^a-z0-9]','')" -Phase "PHASE 68" -ThreatType "Info-Stealer" `
        -Severity $stealSev -Description "Credential-named file in user path: $($sf.FullName)" `
        -Target $sf.FullName -FixAction "DeleteFile" -FixParam $sf.FullName -Group "Info-Stealer"
    $global:SpywareHits++
}
if ($stealerProcs.Count -eq 0 -and $stealerFiles.Count -eq 0) { Out-Typewriter "  -> [OK] NO INFO-STEALER ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 69" "PROCESS HOLLOWING / INJECTION DETECTION" "INJECTION"
Out-Typewriter "CHECKING FOR PROCESSES WITH ANOMALOUS MODULE COUNTS..." "HUNT"
Invoke-QuantumBar "PROCESS MEMORY MAP ANALYSIS" 12 120
$hollowFound = $false
$hollowCandidates = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    # try/catch must be a statement in PS 5.1 (see Phase 44) — `(try{}catch{})` as a
    # sub-expression parse-fails and the whole filter silently matches nothing.
    if (-not ($_.Path -and (Test-Path $_.Path))) { return $false }
    if ($_.Name -match "^(svchost|System|smss|csrss|wininit|services|lsass|winlogon|fontdrvhost|dwm|conhost|MsMpEng|NisSrv|SecurityHealth)$") { return $false }
    try { $_.Modules.Count -lt 3 } catch { $false }
}
foreach ($proc in $hollowCandidates) {
    $sig = Get-AuthSig $proc.Path
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
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
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
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

Show-PhaseHeader "PHASE 74.5" "EMAIL ATTACHMENT MALWARE SCAN (OUTLOOK CACHE)" "PHISHING"
Out-Typewriter "SCANNING OUTLOOK ATTACHMENT CACHE & EMAIL TEMP FOLDERS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
# Targeted attachment/diagnostic caches only — NOT the multi-GB OST/PST store (scanned elsewhere).
$emailAttachPaths = @($EMAIL_SCAN_PATHS) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue) } | Select-Object -Unique
$emailHits = 0
# Extensions worth content-scanning for HTML/JS smuggling & redirector payloads.
$emailTextExt = @(".htm",".html",".js",".jse",".vbs",".vbe",".hta",".wsf",".svg",".log",".txt",".xml")
foreach ($attachPath in $emailAttachPaths) {
    $emailFiles = (Get-ScanFiles -Path $attachPath -TimeScoped) |
        Where-Object { $_.Length -lt 50MB } | Select-Object -First 500
    $inCache = ($attachPath -match 'Olk\\Attachments|Content\.Outlook|Temporary Internet Files')
    foreach ($ef in $emailFiles) {
        $sev = $null; $reasons = @(); $threat = "Phishing / Email Trojan"
        $ext = $ef.Extension.ToLower()

        # 1) Known-malware hash match (strongest signal) — only hash small/medium files.
        if ($KNOWN_MALWARE_HASHES.Count -gt 0 -and $ef.Length -lt 25MB) {
            $fh = (Get-FileHashSafe $ef.FullName)
            if ($fh -and ($KNOWN_MALWARE_HASHES -contains $fh.ToLower())) {
                $sev = $SEV_CRITICAL; $reasons += "SHA256 matches known malware ($($fh.Substring(0,16))...)"
            }
        }

        # 2) Content signatures (HTML smuggling / JS redirector / obfuscated dropper).
        if ($emailTextExt -contains $ext) {
            $cr = Test-ContentRules -FilePath $ef.FullName -Rules $EMAIL_CONTENT_RULES
            if ($cr.Hit) {
                $reasons += "Malicious content signature: $($cr.Name)"
                $threat = "Phishing / Email Trojan ($($cr.Name))"
                if ($null -eq $sev -or $cr.Severity -eq $SEV_CRITICAL) { $sev = $cr.Severity }
            }
        }

        # 3) Executable/script dropped into an email attachment-extraction cache.
        if ($inCache -and ($EMAIL_ATTACH_EXTS -contains $ext)) {
            $reasons += "Executable/script extension ($ext) in email attachment cache"
            if ($null -eq $sev -or $sev -eq $SEV_POSSIBLE) { $sev = $SEV_HIGH }
        }

        # 4) Social-engineering lure filename (invoice/payment/setuppdf/voicemail/etc.).
        foreach ($pat in $EMAIL_LURE_PATTERNS) {
            if ($ef.Name -like $pat) {
                $reasons += "Phishing lure filename pattern: $pat"
                if ($null -eq $sev) { $sev = if ($EMAIL_ATTACH_EXTS -contains $ext) { $SEV_HIGH } else { $SEV_POSSIBLE } }
                break
            }
        }

        if ($sev) {
            $idSafe = ($ef.Name -replace '[^a-zA-Z0-9]','')
            $fixAct = if ($sev -eq $SEV_POSSIBLE) { "Info" } else { "Quarantine" }
            $lvl = if ($sev -eq $SEV_POSSIBLE) { "WARN" } else { "CRIT" }
            Out-Typewriter "  -> [$sev] EMAIL ARTIFACT: $($ef.Name)" $lvl
            Add-Finding -ID "EMAIL_${idSafe}_$($ef.Length)" -Phase "PHASE 74.5" -ThreatType $threat `
                -Severity $sev -Description "Email attachment threat: $($reasons -join '; ') [$($ef.FullName)]" `
                -Target $ef.FullName -FixAction $fixAct -FixParam $ef.FullName `
                -Group "Email / Phishing Threats"
            $global:TrojanHits++; $emailHits++
        }
    }
}
if ($emailHits -eq 0) { Out-Typewriter "  -> [OK] NO SUSPICIOUS EMAIL ARTIFACTS." "GOOD" }
Out-Typewriter "  -> EMAIL ATTACHMENT SCAN COMPLETE." "VER"

Show-PhaseHeader "PHASE 74.6" "MICROSOFT DEFENDER THREAT HISTORY CORRELATION" "DEFENDER"
Out-Typewriter "CORRELATING WITH WINDOWS DEFENDER DETECTION HISTORY..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
try {
    $threatNames = @{}
    foreach ($t in (Get-MpThreat -ErrorAction SilentlyContinue)) { $threatNames[[string]$t.ThreatID] = $t.ThreatName }
    $dets = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending)
    $defHits = 0
    foreach ($d in $dets) {
        if (-not (Test-InScope $d.InitialDetectionTime)) { continue }
        $tname = if ($threatNames.ContainsKey([string]$d.ThreatID)) { $threatNames[[string]$d.ThreatID] } else { "ThreatID $($d.ThreatID)" }
        $when  = try { ([datetime]$d.InitialDetectionTime).ToString('yyyy-MM-dd HH:mm') } catch { "unknown" }
        $emitted = $false
        foreach ($res in @($d.Resources)) {
            $path = ([string]$res) -replace '^(file|webfile|containerfile|amsi|behavior|process|regkey|fixpath|runkey):_?',''
            $onDisk = ($path -match '^[A-Za-z]:\\') -and (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)
            if ($onDisk) {
                Out-Typewriter "  -> RESIDUAL FILE STILL ON DISK: $path" "CRIT"
                Add-Finding -ID "DEFRES_$([Math]::Abs($path.GetHashCode()))" -Phase "PHASE 74.6" `
                    -ThreatType "Defender-Flagged Residual ($tname)" -Severity $SEV_CRITICAL `
                    -Description "Defender flagged '$tname' on $when but the file is STILL PRESENT: $path" `
                    -Target $path -FixAction "Quarantine" -FixParam $path -Group "Defender History / Residual Threats"
                $global:TrojanHits++; $emitted = $true
            } elseif ($path -match '^[A-Za-z]:\\') {
                Add-Finding -ID "DEFHIST_$([Math]::Abs(("$tname|$path").GetHashCode()))" -Phase "PHASE 74.6" `
                    -ThreatType "Defender Detection (handled)" -Severity $SEV_INFO `
                    -Description "Defender detected '$tname' on $when at $path (no longer on disk — verify quarantine)." `
                    -Target $path -FixAction "Info" -Group "Defender History / Residual Threats"
                $emitted = $true
            }
        }
        if ($emitted) { $defHits++ }
    }
    if ($defHits -eq 0) { Out-Typewriter "  -> [OK] NO DEFENDER DETECTIONS IN TIME WINDOW." "GOOD" }
    else { Out-Typewriter "  -> CORRELATED $defHits DEFENDER DETECTION(S)." "DATA" }
} catch {
    Out-Typewriter "  -> Defender history unavailable (module/cmdlet absent): $($_.Exception.Message)" "WARN"
}
Out-Typewriter "  -> DEFENDER HISTORY CORRELATION COMPLETE." "VER"

Show-PhaseHeader "PHASE 74.7" "PROACTIVE ANTI-REINFECTION HARDENING" "HARDEN"
Out-Typewriter "AUDITING ATTACKER-TARGETED FOOTHOLDS FOR PROACTIVE HARDENING..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
$hardenHits = 0
# (a) Office / Outlook macro & attachment security — primary phishing execution vector.
foreach ($ok in $PROACTIVE_OFFICE_KEYS) {
    try {
        if (-not (Test-Path -LiteralPath $ok.Path)) { continue }   # app not installed — skip
        $cur = (Get-ItemProperty -LiteralPath $ok.Path -Name $ok.Name -ErrorAction SilentlyContinue).$($ok.Name)
        if ($null -eq $cur -or [int]$cur -lt [int]$ok.SafeValue) {
            Add-Finding -ID "HARDEN_OFFICE_$(($ok.Path + $ok.Name) -replace '[^a-zA-Z0-9]','')" -Phase "PHASE 74.7" `
                -ThreatType "Macro/Attachment Exposure" -Severity $SEV_POSSIBLE `
                -Description "$($ok.Why). Current=$cur, hardened=$($ok.SafeValue)." `
                -Target "$($ok.Path)|$($ok.Name)" -FixAction "RunCmd" `
                -FixParam "New-Item -Path '$($ok.Path)' -Force | Out-Null; Set-ItemProperty -Path '$($ok.Path)' -Name '$($ok.Name)' -Value $($ok.SafeValue) -Type DWord -Force" `
                -Group "Proactive Hardening"
            $hardenHits++
        }
    } catch {}
}
# (b) Windows Script Host — disable .js/.vbs/.wsf double-click execution (commodity-malware delivery).
try {
    $wshPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
    $wshEnabled = (Get-ItemProperty -LiteralPath $wshPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($null -eq $wshEnabled -or [int]$wshEnabled -ne 0) {
        Add-Finding -ID "HARDEN_WSH_DISABLE" -Phase "PHASE 74.7" -ThreatType "Script Host Exposure" -Severity $SEV_INFO `
            -Description "Windows Script Host is enabled — .js/.jse/.vbs/.wsf files execute on double-click (top phishing delivery). Disabling blocks that vector." `
            -Target $wshPath -FixAction "RunCmd" `
            -FixParam "New-Item -Path '$wshPath' -Force | Out-Null; Set-ItemProperty -Path '$wshPath' -Name 'Enabled' -Value 0 -Type DWord -Force" `
            -Group "Proactive Hardening"
        $hardenHits++
    }
} catch {}
# (c) Defender posture + Attack Surface Reduction rules that kill the phishing-trojan kill chain.
try {
    $mp = Get-MpPreference -ErrorAction Stop
    if ([int]$mp.PUAProtection -ne 1) {
        Add-Finding -ID "HARDEN_PUA" -Phase "PHASE 74.7" -ThreatType "Defender Posture" -Severity $SEV_POSSIBLE `
            -Description "Defender PUA/PUP protection is not enabled (the SetupPDF alert was a PUA). Enable to block fake-installer PUPs." `
            -Target "Defender PUAProtection" -FixAction "RunCmd" -FixParam "Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue" `
            -Group "Proactive Hardening"
        $hardenHits++
    }
    # ASR rules: id => description + deployment mode. The 3 low-FP rules deploy in BLOCK; the 3
    # higher-FP rules (Office child procs / obfuscated scripts / Win32-from-macros) deploy in AUDIT
    # first so they LOG impact on business machines without breaking legit add-ins, macros or
    # minified scripts. Promote audit->block per-client once telemetry confirms no breakage.
    $asrRules = @(
        @{ Id="BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"; Desc="Block executable content from email client and webmail"; Mode="Block" },
        @{ Id="3B576869-A4EC-4529-8536-B80A7769E899"; Desc="Block Office apps from creating executable content"; Mode="Block" },
        @{ Id="D3E037E1-3EB8-44C8-A917-57927947596D"; Desc="Block JS/VBScript from launching downloaded executable content"; Mode="Block" },
        @{ Id="D4F940AB-401B-4EFC-AADC-AD5F3C50688A"; Desc="Block all Office apps from creating child processes"; Mode="Audit" },
        @{ Id="5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"; Desc="Block execution of potentially obfuscated scripts"; Mode="Audit" },
        @{ Id="92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"; Desc="Block Win32 API calls from Office macros"; Mode="Audit" }
    )
    # Current rule actions: 0/absent=Not configured, 1=Block, 2=Audit, 6=Warn.
    $asrActions = @{}
    for ($i=0; $i -lt @($mp.AttackSurfaceReductionRules_Ids).Count; $i++) {
        $asrActions[([string]@($mp.AttackSurfaceReductionRules_Ids)[$i]).ToUpper()] = [int]@($mp.AttackSurfaceReductionRules_Actions)[$i]
    }
    foreach ($rule in $asrRules) {
        $key = $rule.Id.ToUpper()
        $cur = if ($asrActions.ContainsKey($key)) { $asrActions[$key] } else { 0 }
        if ($rule.Mode -eq "Block") {
            if ($cur -eq 1) { continue }   # already enforcing — nothing to recommend
            $action = "Enabled"; $modeWord = "BLOCK"
        } else {
            if ($cur -eq 1 -or $cur -eq 2) { continue }   # already auditing or blocking — leave it
            $action = "AuditMode"; $modeWord = "AUDIT (log-only, breaks nothing)"
        }
        Add-Finding -ID "HARDEN_ASR_$($rule.Id -replace '[^A-Za-z0-9]','')" -Phase "PHASE 74.7" `
            -ThreatType "ASR Rule Not Enabled" -Severity $SEV_INFO `
            -Description "Attack Surface Reduction rule not set: $($rule.Desc). Recommended deployment: $modeWord. Breaks the phishing email->script->exe chain." `
            -Target "ASR $($rule.Id)" -FixAction "RunCmd" `
            -FixParam "Add-MpPreference -AttackSurfaceReductionRules_Ids '$($rule.Id)' -AttackSurfaceReductionRules_Actions $action -ErrorAction SilentlyContinue" `
            -Group "Proactive Hardening"
        $hardenHits++
    }
} catch {
    Out-Typewriter "  -> Defender preferences unavailable: $($_.Exception.Message)" "WARN"
}
if ($hardenHits -eq 0) { Out-Typewriter "  -> [OK] PROACTIVE HARDENING ALREADY IN PLACE." "GOOD" }
else { Out-Typewriter "  -> $hardenHits PROACTIVE HARDENING RECOMMENDATION(S) ADDED." "DATA" }
Out-Typewriter "  -> PROACTIVE HARDENING AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 75" "WINDOWS DEFENDER EXCLUSIONS & TAMPER AUDIT"
Out-Typewriter "CHECKING DEFENDER EXCLUSION LIST FOR MALWARE HIDING SPOTS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
try {
    $prefs = Get-MpPreference -ErrorAction Stop
    if ($prefs.ExclusionPath.Count -gt 0) {
        foreach ($exc in $prefs.ExclusionPath) {
            # A Defender exclusion IS a real evasion technique (T1562.001) worth surfacing, but it is
            # corroborating evidence — NOT a standalone auto-remediate. Legit RMM (Datto/CentraStage),
            # AV migrations and dev tools all add exclusions; auto-removing them changes security
            # posture and can break the excluded software (Defender may then quarantine its files).
            # So POSSIBLE + opt-in RunCmd: shown for operator review, never auto-selected/removed.
            Out-Typewriter "  -> DEFENDER PATH EXCLUSION: $exc" "CRIT"
            Add-Finding -ID "DEFENDER_EXC_$($exc -replace '[^a-z0-9]','')" -Phase "PHASE 75" -ThreatType "Defender Tampering" `
                -Severity $SEV_POSSIBLE -Description "Defender path exclusion (review — could be a malware hiding spot or a legit RMM/dev exclusion): $exc" `
                -Target "Defender Exclusion: $exc" -FixAction "RunCmd" -FixParam "Remove-MpPreference -ExclusionPath '$exc'" `
                -Group "Defender Exclusions"
        }
    }
    if ($prefs.ExclusionProcess.Count -gt 0) {
        foreach ($exc in $prefs.ExclusionProcess) {
            Out-Typewriter "  -> DEFENDER PROCESS EXCLUSION: $exc" "WARN"
            Add-Finding -ID "DEFENDER_PROC_EXC_$($exc -replace '[^a-z0-9]','')" -Phase "PHASE 75" -ThreatType "Defender Tampering" `
                -Severity $SEV_POSSIBLE -Description "Defender process exclusion (review — could aid evasion or be a legit RMM/dev exclusion): $exc" `
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
$rdpShadow = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "Shadow"
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
    trap { Write-RecoveredError $_; continue }   # localize faults: resume at next phase, not end-of-group
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
    # One bounded walk; anchored regex so "nc.exe" doesn't substring-match "sync.exe"
    # (was 4 roots x 12 names = 48 recursions, one over the entire user profile).
    $tunnelRegex = ($tunnelNames | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
    $tunnelFound = $false
    $tunnelHits = (Get-ScanFiles -Path $tunnelRoots) | Where-Object { $_.Name -match $tunnelRegex }
    foreach ($hit in $tunnelHits) {
        $tunnelFound = $true
        Out-Decrypt -Text $hit.FullName -Prefix "  [TUNNEL TOOL] "
        Add-Finding -ID "TUNNEL_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 82" -ThreatType "Tunneling Tool" `
            -Severity $SEV_CRITICAL -Description "Tunneling/pivoting tool found: $($hit.FullName)" `
            -Target $hit.FullName -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Tunneling / Pivoting Tools"
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
        $sig = Get-AuthSig $proc.Path
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
    $recycleBin = (Get-ScanFiles -Path "C:\`$Recycle.Bin" -TimeScoped) |
        Where-Object { $_.Extension -match "\.(exe|dll|js|vbs|bat|cmd|ps1|hta|wsf)$" }
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
        $dcSyncEvts = Get-WinEventSafe @{LogName='Security'; ID=4662} |
            Where-Object { (Test-InScope $_.TimeCreated) -and $_.Message -match "1131f6aa|1131f6ad|89e95b76" }
        if ($dcSyncEvts.Count -gt 0) {
            Out-ThreatBanner "POSSIBLE DCSYNC ATTACK" "$($dcSyncEvts.Count) replication events from non-DC"
            Add-Finding -ID "DCSYNC" -Phase "PHASE 88" -ThreatType "DCSync / Domain Attack" -Severity $SEV_CRITICAL `
                -Description "DCSync indicators: $($dcSyncEvts.Count) AD replication events outside DC — possible credential dump" `
                -Target "Security EventLog (4662)" -FixAction "Info" -Group "Active Directory Attacks"
        } else { Out-Typewriter "  -> [OK] NO DCSYNC INDICATORS." "GOOD" }
        $goldenTicket = Get-WinEventSafe @{LogName='Security'; ID=4769} |
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
    # One bounded walk + anchored regex (was 3 roots x 7 names = 21 recursions incl. whole profile).
    $stegoRegex = ($stegoTools | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
    $stegoHits = (Get-ScanFiles -Path @($env:TEMP,$env:LOCALAPPDATA,$env:USERPROFILE)) | Where-Object { $_.Name -match $stegoRegex }
    foreach ($hit in $stegoHits) {
        Out-Typewriter "  -> STEGO TOOL: $($hit.FullName)" "WARN"
        Add-Finding -ID "STEGO_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 89" -ThreatType "Steganography/Exfil Tool" `
            -Severity $SEV_HIGH -Description "Steganography tool found: $($hit.FullName)" `
            -Target $hit.FullName -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Data Exfiltration"
    }
    Out-Typewriter "  -> PHASE 89 COMPLETE." "VER"
}

# ══════════════════════════════════════════════════════════════════════════════
#  ADVANCED PHASES 90-105 (DEEP / PARANOID / STEALTH — V21)
# ══════════════════════════════════════════════════════════════════════════════
