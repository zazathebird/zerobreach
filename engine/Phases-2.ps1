trap { Write-RecoveredError $_; continue }   # module-level resilience: a terminating error resumes at the NEXT phase in THIS module, not the next dot-sourced module (see CLAUDE.md engine-split rule)
# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 12: RAT / C2 BEACON
# ══════════════════════════════════════════════════════════════════════════════
Show-ThreatCategoryHeader "RAT / C2 BEACON" "Beacon Intervals · DNS Tunneling · RAT Config/Registry · Named Pipes"

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 59" "C2 BEACON INTERVAL / HIGH-FREQ DNS DETECTION" "RAT/C2"
Out-Typewriter "ANALYZING DNS CACHE FOR BEACON PATTERNS..." "HUNT"
Invoke-QuantumBar "BEACON INTERVAL ANALYSIS" 15 120
$dnsCache2 = Get-DnsClientCache -ErrorAction SilentlyContinue
$domainCounts = @{}
foreach ($entry in $dnsCache2) { $domainCounts[$entry.Entry] = ($domainCounts[$entry.Entry] + 1) }
# Allowlist anchored to the registrable domain SUFFIX (data\detection_signatures.json).
# The beaconed name is entirely attacker-chosen, so the old bare-substring list was cleared
# by registering e.g. "microsoft-update-cdn.attacker.tld" — a self-allowlisting evasion.
$beaconDomains = $domainCounts.GetEnumerator() | Where-Object { $_.Value -gt 10 -and $_.Key -notmatch $BEACON_BENIGN_DOM_RE }
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
        Add-Finding -ID "DNSTUN_$(Get-StableId $entry.Entry)" -Phase "PHASE 60" -ThreatType "DNS Tunneling" `
            -Severity $SEV_HIGH -Description "DNS tunneling indicator: long subdomain ($($longestLabel.Length) chars) in $($entry.Entry)" `
            -Target "DNS: $($entry.Entry)" -FixAction "Info" -Group "DNS Tunneling"
        $global:RATHits++; $dnsTunnel = $true
    }
    if (($entry.Entry -split "\.").Count -gt 6) {
        Out-Typewriter "  -> HIGH SUBDOMAIN DEPTH: $($entry.Entry)" "WARN"
        Add-Finding -ID "DNSDEPTH_$(Get-StableId $entry.Entry)" -Phase "PHASE 60" -ThreatType "DNS Tunneling" `
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
# P1 multi-user: $RAT_CONFIG_TEMPLATES carries raw {TOKEN} templates. They used to be expanded
# ONCE at load time against the ELEVATED technician's environment, so on a standard-user
# endpoint every one of these paths pointed at the admin's profile and the victim's %APPDATA%
# was never looked at. Resolved per profile now. Severity/FixAction unchanged (CRITICAL +
# DeleteFile is safe here only because these are literal known-RAT names that never exist on a
# clean box) — and FixParam stays a bare machine-parseable path with NO "[User]" prefix.
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($zbTpl in $RAT_CONFIG_TEMPLATES) {
        $zbPath = Expand-UserPathTemplate $zbTpl $zbUp
        if (-not $zbPath) { continue }                       # unresolved token -> never emit
        if (-not (Test-Path -LiteralPath $zbPath)) { continue }
        Out-ThreatBanner "RAT ARTIFACT" "[$($zbHive.User)] $zbPath"
        Add-Finding -ID "RATFILE_$(Get-StableId "$($zbHive.Sid)|$zbPath")" -Phase "PHASE 61" -ThreatType "RAT" `
            -Severity $SEV_CRITICAL -Description "[$($zbHive.User)] Known RAT config/binary path present: $zbPath" `
            -Target "[$($zbHive.User)] $zbPath" -FixAction "DeleteFile" -FixParam $zbPath `
            -Group "RAT Artifacts"
        $global:RATHits++; $ratFound = $true
    }
}
# P1 multi-user: $RAT_REG_PATHS is 12 x "HKCU:\SOFTWARE\<ratname>", so pre-P1 this only ever
# looked in the ELEVATED TECHNICIAN's hive — on a standard-user endpoint the victim's RAT
# config key was never read at all. Strip the HKCU: prefix defensively (an entry that is
# already hive-relative passes through unchanged, so this is safe to apply blindly) and
# re-root it on every profile's hive. There is no HKLM entry in this list, so there is no
# machine-scope half to hoist out of the loop.
# The ID used to be built from the bare key path, which is IDENTICAL for every profile, so
# two infected users collided on one ID and Add-Finding's de-dupe silently dropped the
# second victim — it now carries the SID. Severity/FixAction unchanged (CRITICAL +
# DeleteRegKey is safe here only because these are literal known-RAT key names that never
# exist on a clean box), and FixParam stays a bare machine-parseable registry path with NO
# "[User]" prefix.
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }        # hive not mounted + loading off = "could not look"
    # A ZB_UH_* reg-load mount is gone by the time the server's remediation runspace runs, so a
    # DeleteRegKey FixParam pointing into it would silently target nothing. Offline hives get
    # operator-only Info + the literal commands, capped at HIGH (contract rule 7 / addendum 2).
    $zbRatOff = ($zbHive.Source -eq 'RegLoad')
    foreach ($rrp in $RAT_REG_PATHS) {
        $zbRatRel = "$rrp" -replace '(?i)^HK(CU|EY_CURRENT_USER):?\\', ''
        if (-not $zbRatRel) { continue }
        $zbRatPath = "$($zbHive.HivePath)\$zbRatRel"
        if (-not (Test-Path -LiteralPath $zbRatPath)) { continue }
        Out-ThreatBanner "RAT REGISTRY KEY" "[$($zbHive.User)] $zbRatPath"
        $zbRatSev  = if ($zbRatOff) { $SEV_HIGH } else { $SEV_CRITICAL }
        $zbRatFix  = if ($zbRatOff) { "Info" }    else { "DeleteRegKey" }
        $zbRatPrm  = if ($zbRatOff) { "" }        else { $zbRatPath }
        $zbRatDesc = "[$($zbHive.User)] Known RAT registry key: $zbRatPath"
        if ($zbRatOff) {
            $zbRatDesc += " || Read from the offline hive $($zbHive.NtUserDat); that mount does not survive this scan, so remove it by hand: reg load HKU\ZBFIX ""$($zbHive.NtUserDat)"" ; Remove-Item 'Registry::HKEY_USERS\ZBFIX\$zbRatRel' -Recurse -Force ; reg unload HKU\ZBFIX"
        }
        Add-Finding -ID "RATREG_$(Get-StableId "$($zbHive.Sid)|$zbRatPath")" -Phase "PHASE 61" -ThreatType "RAT" `
            -Severity $zbRatSev -Description $zbRatDesc `
            -Target "[$($zbHive.User)] $zbRatPath" -FixAction $zbRatFix -FixParam $zbRatPrm -Group "RAT Artifacts"
        $global:RATHits++; $ratFound = $true
    }
}
if (-not $ratFound) { Out-Typewriter "  -> [OK] NO RAT CONFIGURATION ARTIFACTS." "GOOD" }

}   # end QUICK-skip block
Show-PhaseHeader "PHASE 62" "NAMED PIPE BACKDOOR AUDIT" "RAT/C2"
Out-Typewriter "ENUMERATING NAMED PIPE ENDPOINTS..." "HUNT"
try {
    $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
    # Match only specific C2/RAT framework pipe names (externalized to data — AMSI-safe + tunable).
    # The old inline pattern ended in "[a-f0-9]{8,}", which matched virtually every legitimate
    # Windows RPC/COM/GUID-named pipe -> ~100 CRITICAL false positives. Do NOT reintroduce a broad
    # hex/GUID catch-all here (see c2_named_pipe_regex note in detection_signatures.json).
    $suspectPipes = @($pipes | Where-Object { $_ -match $C2_NAMED_PIPE_RE })
    $pipeHits = 0
    foreach ($pipe in $suspectPipes) {
        Out-ThreatBanner "SUSPECT NAMED PIPE" $pipe
        Add-Finding -ID "PIPE_$($pipe -replace '[^a-z0-9]','')" -Phase "PHASE 62" -ThreatType "RAT/Backdoor Pipe" `
            -Severity $SEV_CRITICAL -Description "Suspect named pipe matching known C2/RAT pattern: $pipe" `
            -Target $pipe -FixAction "Info" -Group "Named Pipe Backdoors"
        $global:RATHits++; $pipeHits++
    }
    # WS2: anchored C2-framework default-pipe regexes (CS msagent_/postex_, Havoc demon_pipe,
    # Covenant gruntsvc, PoshC2...) matched against the bare pipe LEAF, so legit RPC pipes
    # (srvsvc/wkssvc/...) only fire on the malicious _<digits> suffix. Plus TrickBot-class pipe.
    # These stay OFF the broad hex/GUID catch-all main deliberately removed (round-4 FP fix) —
    # anchored on the leaf keeps FPs near zero; all FixAction Info.
    $pSevMap = @{ "CRITICAL"=$SEV_CRITICAL; "HIGH"=$SEV_HIGH; "POSSIBLE"=$SEV_POSSIBLE }
    foreach ($pipe in $pipes) {
        if ($suspectPipes -contains $pipe) { continue }   # already reported above
        $leaf = $pipe.Substring($pipe.LastIndexOf('\') + 1)
        if (@($BANKING_NAMED_PIPES | Where-Object { $leaf -match [regex]::Escape($_) }).Count -gt 0) {
            Out-ThreatBanner "BANKING TROJAN PIPE" $pipe
            Add-Finding -ID "PIPEBANK_$($leaf -replace '[^a-z0-9]','')" -Phase "PHASE 62" -ThreatType "Banking Trojan Pipe" `
                -Severity $SEV_HIGH -Description "Named pipe matching banking-trojan pattern (TrickBot-class): $pipe" `
                -Target $pipe -FixAction "Info" -Group "Named Pipe Backdoors"
            $global:RATHits++; $pipeHits++; continue
        }
        $leafMatched = $false
        foreach ($r in $C2_PIPE_REGEX_ANCHORED) {
            if ($leaf -match $r.Pattern) {
                Out-ThreatBanner "C2 FRAMEWORK PIPE ($($r.Name))" $pipe
                Add-Finding -ID "PIPEC2_$($leaf -replace '[^a-z0-9]','')" -Phase "PHASE 62" -ThreatType "C2 Framework Pipe" `
                    -Severity $pSevMap[$r.Severity] -Description "Named pipe matches $($r.Name) default pattern: $pipe" `
                    -Target $pipe -FixAction "Info" -Group "Named Pipe Backdoors"
                $global:RATHits++; $pipeHits++; $leafMatched = $true; break
            }
        }
        if ($leafMatched) { continue }
        # WS0 wiring: framework-NAME pass (meterpreter/cobaltstrike/havoc/sliver/...). Each name
        # is bounded by non-alphanumeric edges so short tokens can't substring-match legit pipes
        # ("msf" must NOT hit the Windows Search pipe MsFteWds). FixAction Info — a pipe name is
        # triage evidence, not an auto-actionable target.
        foreach ($pat in $C2_PIPE_PATTERNS) {
            if ($leaf -match ('(^|[^a-z0-9])' + [regex]::Escape($pat) + '([^a-z0-9]|$)')) {
                Out-ThreatBanner "C2 FRAMEWORK PIPE NAME" $pipe
                Add-Finding -ID "PIPENAME_$($leaf -replace '[^a-z0-9]','')" -Phase "PHASE 62" -ThreatType "C2 Framework Pipe" `
                    -Severity $SEV_HIGH -Description "Named pipe contains C2/RAT framework name '$pat': $pipe" `
                    -Target $pipe -FixAction "Info" -Group "Named Pipe Backdoors"
                $global:RATHits++; $pipeHits++; break
            }
        }
    }
    if ($pipeHits -eq 0) { Out-Typewriter "  -> [OK] NO SUSPECT NAMED PIPES." "GOOD" }
} catch { Out-Typewriter "  -> PIPE ENUMERATION FAILED (ELEVATED SESSION REQUIRED)." "WARN" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 13: CRYPTOMINER
# ══════════════════════════════════════════════════════════════════════════════
Show-ThreatCategoryHeader "CRYPTOMINER" "CPU Abuse · Stratum Protocol · Miner Config Files · Task Persistence"

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
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
            # Process name is attacker-chosen (whoever named the binary) and interpolated into a
            # single-quoted RunCmd string an auto-selected CRITICAL finding can execute unattended
            # via PURGE — escape the embedded quote the same way Phase 29/ADS/LNK findings already do.
            $procNameEsc = "$($proc.Name)" -replace "'","''"
            Add-Finding -ID "MINER_CPU_$($proc.Name -replace '[^a-z0-9]','')" -Phase "PHASE 63" -ThreatType "Cryptominer" `
                -Severity $SEV_CRITICAL -Description "Miner process using $($proc.PercentProcessorTime)% CPU: $($proc.Name)" `
                -Target "Process: $($proc.Name)" -FixAction "RunCmd" -FixParam "Stop-Process -Name '$procNameEsc' -Force" `
                -Group "Live Cryptominer"
            $global:MinerHits++; $minerFound = $true
        }
    }
}
# Miner config files
# Get-ScanFiles, not a raw Get-ChildItem -Recurse (CLAUDE.md rule): this walks whole user
# roots, so it needs the file cap, wall-clock deadline, cache-dir pruning and OneDrive
# placeholder skip. Parenthesised because Get-ScanFiles returns `,$arr` — piping it directly
# hands the entire array to Where-Object as ONE item and the filter silently matches nothing.
# P1 multi-user: the three roots were $env:TEMP / $env:LOCALAPPDATA / "$env:USERPROFILE\AppData\
# Roaming", i.e. the ELEVATED TECHNICIAN's profile — on a standard-user endpoint the victim's
# miner config was never looked at. Roots are now resolved per profile via Get-UserPaths
# (Roaming is NOT constructed by hand: folder redirection genuinely moves AppData).
# SINGLE-CALL shape: Get-ScanFiles's MaxFiles/DeadlineSecs are PER CALL, so putting the call
# inside the profile loop would multiply wall-clock by the profile count (8 profiles x 20s).
# One walk over every profile's roots, then each file is attributed back to its owning root by
# LONGEST-prefix match. Severity/FixAction unchanged (CRITICAL + DeleteFile / POSSIBLE + Info).
$zbMinerRoots = @()
foreach ($zbHive in (@(Get-UserHives) | Sort-Object Sid)) {   # SID order -> stable memo key
    if (-not $zbHive.ProfileReachable) { continue }           # never re-probe reachability
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($zbR in @($zbUp.Temp, $zbUp.LocalAppData, $zbUp.AppData)) {
        if (-not $zbR) { continue }
        if (@($zbMinerRoots | Where-Object { "$($_.Root)".ToLowerInvariant() -eq "$zbR".ToLowerInvariant() }).Count -gt 0) { continue }
        $zbMinerRoots += [pscustomobject]@{ Root = "$zbR"; User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
    }
}
$minerConfigFiles = @()
if ($zbMinerRoots.Count -gt 0) {
    $minerConfigFiles = (Get-ScanFiles -Path @($zbMinerRoots | ForEach-Object { $_.Root }) `
        -Filter 'config.json' -TimeScoped)
}
foreach ($cf in $minerConfigFiles) {
    # Longest-prefix attribution (Temp nests inside LocalAppData, so shortest-match would lie).
    $zbCfUser = 'MACHINE'; $zbCfSid = 'MACHINE'; $zbCfLen = -1
    $zbCfLc = "$($cf.FullName)".ToLowerInvariant()
    foreach ($zbR in $zbMinerRoots) {
        $zbRl = "$($zbR.Root)".ToLowerInvariant()
        if ($zbRl.Length -gt $zbCfLen -and $zbCfLc.StartsWith($zbRl)) {
            $zbCfUser = "$($zbR.User)"; $zbCfSid = "$($zbR.Sid)"; $zbCfLen = $zbRl.Length
        }
    }
    $content = Get-Content $cf.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match '"pools"|url.*stratum|"user".*[0-9A-Za-z]{90,}|monero|xmr|ethereum|mining') {
        # ID was "MINERCFG_" + the filename with non-alphanumerics stripped — and the filename is
        # ALWAYS "config.json", so every hit on the box collapsed to the single ID
        # "MINERCFG_configjson" and Add-Finding's de-dupe dropped all but the first. That was
        # already wrong pre-P1 (two miner configs = one finding); with N profiles it would have
        # silently hidden every victim but one. Keyed on SID + full path now.
        if (Test-BenignPath $cf.FullName $MINERCFG_BENIGN_RE) {
            Add-Finding -ID "MINERCFG_$(Get-StableId "$zbCfSid|$($cf.FullName)")" -Phase "PHASE 63" -ThreatType "Cryptominer" `
                -Severity $SEV_POSSIBLE -Description "[$zbCfUser] config.json matches miner keywords but sits in a known app/library tree (likely an app config — review, not auto-deleted): $($cf.FullName)" `
                -Target "[$zbCfUser] $($cf.FullName)" -FixAction "Info" -Group "Live Cryptominer"
            continue
        }
        Out-ThreatBanner "MINER CONFIG FILE" "[$zbCfUser] $($cf.FullName)"
        # FixParam stays a bare machine-parseable path — the user lives in Target/Description.
        Add-Finding -ID "MINERCFG_$(Get-StableId "$zbCfSid|$($cf.FullName)")" -Phase "PHASE 63" -ThreatType "Cryptominer" `
            -Severity $SEV_CRITICAL -Description "[$zbCfUser] Miner configuration file found: $($cf.FullName)" `
            -Target "[$zbCfUser] $($cf.FullName)" -FixAction "DeleteFile" -FixParam $cf.FullName -Group "Live Cryptominer"
        $global:MinerHits++; $minerFound = $true
    }
}
if (-not $minerFound) { Out-Typewriter "  -> [OK] NO CRYPTOMINER INDICATORS." "GOOD" }

}   # end QUICK-skip block
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
        # Task name is attacker-chosen and interpolated into a single-quoted RunCmd string an
        # auto-selected CRITICAL finding can execute unattended via PURGE — same escaping already
        # used by the Phase 29 hidden-task RunCmd (CLAUDE.md rule #1: fail closed on injection).
        $taskNameEsc = "$($task.TaskName)" -replace "'","''"
        Add-Finding -ID "MINERTASK_$($task.TaskName -replace '[^a-z0-9]','')" -Phase "PHASE 64" -ThreatType "Cryptominer" `
            -Severity $SEV_CRITICAL -Description "Miner persistence via scheduled task: $($task.TaskName)" `
            -Target "Task: $($task.TaskName)" -FixAction "RunCmd" -FixParam "Unregister-ScheduledTask -TaskName '$taskNameEsc' -Confirm:`$false" `
            -Group "Miner Persistence"
        $global:MinerHits++
    }
}
Out-Typewriter "  -> MINER PERSISTENCE AUDIT COMPLETE." "VER"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 14: WORM & SPYWARE
# ══════════════════════════════════════════════════════════════════════════════
Show-ThreatCategoryHeader "WORM / SPYWARE / ADWARE" "AutoRun · USB · Network Shares · Self-Replication · PUPs · Tracking"

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
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
# P1 multi-user — DELIBERATE SPLIT (operator decision). This is a hardening WRITE, and
# hardening/lockdown actions are operator-only by rule #1; applying the HKCU half to EVERY
# profile on the box would materially widen the blast radius, so it stays single-user. What
# P1 fixes here is the silent ambiguity: pre-P1 "HKCU" meant "whoever the engine is elevated
# as", which on a standard-user endpoint is the TECHNICIAN, not the victim — the description
# now names that account explicitly. Severity/FixAction unchanged (INFO + RunCmd).
$zbAutoRunUser = "$env:USERDOMAIN\$env:USERNAME"
foreach ($zbHive in @(Get-UserHives)) { if ($zbHive.IsCurrent) { $zbAutoRunUser = "$($zbHive.User)"; break } }
Add-Finding -ID "AUTORUN_DISABLE" -Phase "PHASE 65" -ThreatType "Hardening" -Severity $SEV_INFO `
    -Description "Option: Disable Autorun for all drive types (recommended). SCOPE: the HKLM half covers every user on this machine; the HKCU half applies ONLY to '$zbAutoRunUser' — the account this scan is running as, which on a standard-user endpoint is the TECHNICIAN, not the logged-on user. Hardening is deliberately not written into other profiles' hives; to cover another user, run the HKCU command while logged on as them (or point it at Registry::HKEY_USERS\<their SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer)." `
    -Target "HKLM/HKCU NoDriveTypeAutoRun" -FixAction "RunCmd" `
    -FixParam "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 0xFF -Type DWord -Force; Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 0xFF -Type DWord -Force" `
    -Group "Worm / USB Spread"
if (-not $wormFound) { Out-Typewriter "  -> [OK] NO WORM AUTORUN ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 66" "NETWORK SHARE WORM PROPAGATION SCAN" "WORM"
Out-Typewriter "ENUMERATING OPEN NETWORK SHARES..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
$shares = Get-WmiObject Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^([A-Za-z]|ADMIN|IPC|print)\$$' }   # exclude drive-letter admin shares (C$/D$) too — scanning C$ walks the whole drive
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
# P1 multi-user (MIGRATE-LITE): the "local user-profiles tree" root was derived from the
# ELEVATED TECHNICIAN's own profile path (Split-Path $env:USERPROFILE -Parent), which is only
# ever correct when every profile on the box lives beside the technician's. On a machine whose
# profiles were relocated (ProfilesDirectory pointed at D:\Users, a redirected root, or a
# migrated box carrying two profile roots) that test silently failed and unsigned executables
# in a shared user profile escalated to HIGH + DeleteFile — the user's own installers, offered
# for auto-deletion (rule #1). Derived from the DISTINCT PARENTS of every real profile path now.
# Unreachable profiles are deliberately INCLUDED here: this is a pure string prefix test with no
# filesystem I/O (Split-Path does not touch the disk), and a broader list can only DOWNGRADE a
# finding to POSSIBLE/Info, never escalate one — so it fails closed in the safe direction.
$zbUserRoots = @()
$zbShareOwners = @()
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.ProfilePath) { continue }
    $zbShareOwners += [pscustomobject]@{ Prefix = "$($zbHive.ProfilePath)"; User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
    $zbPar = $null
    try { $zbPar = Split-Path "$($zbHive.ProfilePath)" -Parent } catch {}
    if (-not $zbPar) { continue }
    if (@($zbUserRoots | Where-Object { "$_".ToLowerInvariant() -eq "$zbPar".ToLowerInvariant() }).Count -gt 0) { continue }
    $zbUserRoots += "$zbPar"
}
# Fail closed: if the hive enumeration produced nothing usable, fall back to the pre-P1 root
# rather than losing the downgrade branch entirely (losing it would ESCALATE to DeleteFile).
if ($zbUserRoots.Count -eq 0 -and $env:USERPROFILE) {
    try { $zbUserRoots = @((Split-Path $env:USERPROFILE -Parent)) } catch { $zbUserRoots = @() }
}
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
            $asig = Get-AuthSig $mis.FullName
            if ($asig.Status -ne "Valid") {
                # This phase already reached OTHER users' files pre-P1 (a "Users" share walks the
                # whole profiles tree) — it just could not SAY whose file it was, and the ID was
                # the bare filename, so two profiles each holding "setup.exe" collided on one ID
                # and Add-Finding's de-dupe dropped the second victim silently. Attribute the hit
                # to the owning profile by longest ProfilePath prefix and key the ID on SID+path.
                $zbMisLc = "$($mis.FullName)".ToLowerInvariant()
                $zbMisUser = 'MACHINE'; $zbMisSid = 'MACHINE'; $zbMisLen = -1
                foreach ($zbSo in $zbShareOwners) {
                    $zbSoLc = "$($zbSo.Prefix)".ToLowerInvariant()
                    if ($zbSoLc -and $zbSoLc.Length -gt $zbMisLen -and $zbMisLc.StartsWith($zbSoLc)) {
                        $zbMisUser = "$($zbSo.User)"; $zbMisSid = "$($zbSo.Sid)"; $zbMisLen = $zbSoLc.Length
                    }
                }
                $zbMisId = "SHAREWORM_$(Get-StableId "$zbMisSid|$($mis.FullName)")"
                # Severity gate is UNCHANGED in meaning: "is this inside the local user-profiles
                # tree" — only the definition of that tree is now correct on any profile layout.
                $zbInUserTree = $false
                foreach ($zbUr in $zbUserRoots) {
                    if ($zbUr -and $zbMisLc.StartsWith("$zbUr".ToLowerInvariant())) { $zbInUserTree = $true; break }
                }
                if ($mis.Extension -match "\.(exe|scr|com|pif)$") {
                    if ($zbInUserTree) {
                        # Unsigned PE inside the local profiles tree — the user's own download/build, not
                        # a foreign worm. Surface for review; never auto-delete the user's installers.
                        Add-Finding -ID $zbMisId -Phase "PHASE 66" -ThreatType "Worm/Network Share" `
                            -Severity $SEV_POSSIBLE -Description "[$zbMisUser] Unsigned executable in a shared user-profile path (review — usually the user's own download/build): $($mis.FullName)" `
                            -Target "[$zbMisUser] $($mis.FullName)" -FixAction "Info" -Group "Network Share Worms"
                    } else {
                        # A real unsigned PE dropped in a foreign/public open share is the classic worm vector.
                        Out-ThreatBanner "UNSIGNED EXE IN OPEN SHARE" "[$zbMisUser] $($mis.FullName)"
                        # FixParam stays a bare machine-parseable path — user lives in Target/Description.
                        Add-Finding -ID $zbMisId -Phase "PHASE 66" -ThreatType "Worm/Network Share" `
                            -Severity $SEV_HIGH -Description "[$zbMisUser] Unsigned executable in open share: $($mis.FullName)" `
                            -Target "[$zbMisUser] $($mis.FullName)" -FixAction "DeleteFile" -FixParam $mis.FullName -Group "Network Share Worms"
                        $global:WormHits++
                    }
                } else {
                    # An unsigned *script* in a share is weak signal — a user's own profile share is full
                    # of their own .ps1/.bat/.js. Surface for review only; never auto-delete the user's scripts.
                    Add-Finding -ID $zbMisId -Phase "PHASE 66" -ThreatType "Worm/Network Share" `
                        -Severity $SEV_POSSIBLE -Description "[$zbMisUser] Unsigned script in open share (review — often a user's own file): $($mis.FullName)" `
                        -Target "[$zbMisUser] $($mis.FullName)" -FixAction "Info" -Group "Network Share Worms"
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
# WS0 wiring: externalized to data/detection_signatures.json 'adware_pup_regs' (AMSI-safe,
# same list). These keys never exist on a clean box, so DeleteRegKey stays safe to auto-select.
# P1 multi-user: $ADWARE_PUP_REGS is MIXED SCOPE — 20 HKCU + 4 HKLM — and the HKLM entries
# are INTERLEAVED, not grouped (HKLM:\SOFTWARE\Superfish sits near the END of the list), so a
# "the first N are per-user" split would be flat wrong. Split by PREFIX at RUNTIME instead:
# that works against both the current and any future version of the JSON, so a data file and
# a .ps1 that ship out of step cannot silently break, and it survives someone appending a new
# entry later. No data-file change is needed or wanted for this.
# The machine half is enumerated ONCE, outside the profile loop, tagged [MACHINE] — a box with
# 8 profiles must not report the same machine-wide key 8 times. Anything that is not HKCU is
# treated as machine scope (deliberately broader than a bare ^HKLM: test) so a future entry in
# some other root can never be silently dropped from the scan.
$zbAdwareUserRel = @($ADWARE_PUP_REGS |
    Where-Object { "$_" -match '(?i)^HK(CU|EY_CURRENT_USER):' } |
    ForEach-Object { "$_" -replace '(?i)^HK(CU|EY_CURRENT_USER):?\\', '' })
$zbAdwareMachine = @($ADWARE_PUP_REGS | Where-Object { "$_" -notmatch '(?i)^HK(CU|EY_CURRENT_USER):' })
$zbAdwareTargets = @()
foreach ($zbAp in $zbAdwareMachine) {
    if (-not $zbAp) { continue }
    $zbAdwareTargets += @{ Path = "$zbAp"; User = 'MACHINE'; Sid = 'MACHINE'; Off = $false }
}
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }        # hive not mounted + loading off = "could not look"
    foreach ($zbRel in $zbAdwareUserRel) {
        if (-not $zbRel) { continue }
        $zbAdwareTargets += @{ Path = "$($zbHive.HivePath)\$zbRel"
                               User = "$($zbHive.User)"
                               Sid  = "$($zbHive.Sid)"
                               Off  = ($zbHive.Source -eq 'RegLoad') }
    }
}
$adwareFound = $false
foreach ($zbAt in $zbAdwareTargets) {
    if (-not (Test-Path -LiteralPath $zbAt.Path)) { continue }
    Out-ThreatBanner "ADWARE/PUP REGISTRY KEY" "[$($zbAt.User)] $($zbAt.Path)"
    # A ZB_UH_* reg-load mount is gone by the time the server's remediation runspace runs, so a
    # DeleteRegKey FixParam pointing into it would silently target nothing (addendum rule 2).
    $zbAdFix = if ($zbAt.Off) { "Info" } else { "DeleteRegKey" }
    $zbAdPrm = if ($zbAt.Off) { "" }     else { "$($zbAt.Path)" }
    $zbAdDesc = "[$($zbAt.User)] Known adware/PUP registry key: $($zbAt.Path)"
    if ($zbAt.Off) { $zbAdDesc += " || Read from an offline hive; remove by hand with reg load HKU\ZBFIX / Remove-Item -Recurse -Force / reg unload HKU\ZBFIX." }
    Add-Finding -ID "ADWARE_$(Get-StableId "$($zbAt.Sid)|$($zbAt.Path)")" -Phase "PHASE 67" -ThreatType "Adware/PUP" `
        -Severity $SEV_HIGH -Description $zbAdDesc `
        -Target "[$($zbAt.User)] $($zbAt.Path)" -FixAction $zbAdFix -FixParam $zbAdPrm -Group "Adware / PUP Remnants"
    $global:SpywareHits++; $adwareFound = $true
}
if (-not $adwareFound) { Out-Typewriter "  -> [OK] NO KNOWN ADWARE/PUP REGISTRY KEYS (ALL PROFILES + MACHINE)." "GOOD" }

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 15: ADVANCED / ADDITIONAL MALWARE DETECTION
# ══════════════════════════════════════════════════════════════════════════════
Show-SectionBanner "ADVANCED MALWARE & PERSISTENCE MODULES"

Show-PhaseHeader "PHASE 68" "INFO-STEALER ARTIFACT SCAN (REDLINE/RACCOON/VIDAR)" "INFOSTEALER"
Out-Typewriter "SCANNING FOR INFO-STEALER ARTIFACTS AND DROP PATHS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
# WS0 wiring: stealer-family names externalized to 'infostealer_procs' (was a 12-name inline
# regex; the JSON list adds Lumma/StealC/Rhadamanthys/... = 14 more families).
$stealerRegex = @($INFOSTEALER_PROCS | ForEach-Object { [regex]::Escape($_) }) -join '|'
if (-not $stealerRegex) { $stealerRegex = '(?!)' }
$stealerProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name.ToLower() -match $stealerRegex }
foreach ($sp in $stealerProcs) {
    # A bare process-NAME substring is weak evidence, and the family list contains generic words
    # that collide with legit apps ("atomic" = Atomic Wallet, "aurora", "mystic", "loki"). Rule #1:
    # only AUTO-KILL when the binary is BOTH unsigned AND running from a user-writable path
    # (AppData/Temp/Downloads/user profile) — the actual staging shape of a real infostealer.
    # A validly-signed binary, one in Program Files/System, or a path we can't read (protected
    # process → $sp.Path $null) is downgraded to POSSIBLE + Info: shown for triage, never auto-acted.
    # Single-file sig call per hit (hits are rare) — no SIG_AUDIT budget needed.
    $spSignedValid = $false; $spUserPath = $false
    if ($sp.Path) {
        $spSignedValid = ((Get-AuthSig $sp.Path).Status -eq 'Valid')
        $spUserPath    = ($sp.Path -match '\\(AppData|Temp|Downloads)\\' -or $sp.Path -match '(?i)\\Users\\[^\\]+\\')
    }
    if (-not $spSignedValid -and $spUserPath) {
        Out-ThreatBanner "INFO-STEALER PROCESS IOC" "$($sp.Name) PID:$($sp.Id)"
        Add-Finding -ID "STEALER_$($sp.Id)" -Phase "PHASE 68" -ThreatType "Info-Stealer" `
            -Severity $SEV_CRITICAL -Description "Unsigned info-stealer-named process from user path: $($sp.Name) PID:$($sp.Id) @ $($sp.Path)" `
            -Target "PID:$($sp.Id)" -FixAction "KillProcess" -FixParam $sp.Id -Group "Info-Stealer"
    } else {
        Out-Typewriter "  -> STEALER-NAMED PROCESS (verify): $($sp.Name) PID:$($sp.Id)" "WARN"
        $why = if ($spSignedValid) { "binary is validly signed (likely legit app)" } elseif (-not $sp.Path) { "binary path not readable" } else { "binary is outside user-writable paths" }
        Add-Finding -ID "STEALER_$($sp.Id)" -Phase "PHASE 68" -ThreatType "Info-Stealer" `
            -Severity $SEV_POSSIBLE -Description "Process name matches info-stealer family but $($why) — verify: $($sp.Name) PID:$($sp.Id)$(if($sp.Path){" @ $($sp.Path)"})" `
            -Target "PID:$($sp.Id)" -FixAction "Info" -Group "Info-Stealer"
    }
    $global:SpywareHits++
}
# P1 multi-user: the walk was $env:TEMP / $env:LOCALAPPDATA / $env:APPDATA — the ELEVATED
# TECHNICIAN's profile, so on a standard-user endpoint the victim's stolen-credential drops and
# loader staging paths were never enumerated at all. Roots resolved per profile via
# Get-UserPaths (never hand-built: folder redirection genuinely moves AppData/LocalAppData).
# SINGLE-CALL shape — Get-ScanFiles's MaxFiles/DeadlineSecs are PER CALL, so a call inside the
# profile loop would multiply wall-clock by the profile count. Files are attributed back to the
# owning root by LONGEST-prefix match (Temp nests inside LocalAppData). $zbP68Roots is reused
# by BOTH consumers below (the credential-file loop and the drop-path rule loop).
$zbP68Roots = @()
foreach ($zbHive in (@(Get-UserHives) | Sort-Object Sid)) {   # SID order -> stable memo key
    if (-not $zbHive.ProfileReachable) { continue }           # never re-probe reachability
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($zbR in @($zbUp.Temp, $zbUp.LocalAppData, $zbUp.AppData)) {
        if (-not $zbR) { continue }
        if (@($zbP68Roots | Where-Object { "$($_.Root)".ToLowerInvariant() -eq "$zbR".ToLowerInvariant() }).Count -gt 0) { continue }
        $zbP68Roots += [pscustomobject]@{ Root = "$zbR"; User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
    }
}
$p68Files = @()
if ($zbP68Roots.Count -gt 0) {
    $p68Files = @((Get-ScanFiles -Path @($zbP68Roots | ForEach-Object { $_.Root }) -TimeScoped))
}
$stealerFiles = $p68Files |
    Where-Object { $_.Name -match "passwords|credentials|wallet|login|autofill|cookie" -and $_.Extension -match "\.(zip|txt|log|db)$" }
foreach ($sf in $stealerFiles) {
    # Exclude legitimate browser storage + known-benign dictionaries/caches (ZxcvbnData password
    # lists, *.LICENSE.txt, Edge Wallet bundles, Cef/EBWebView caches) — these are NOT creds dumps.
    # Routed through Test-BenignPath (not a bare -match) so this HIGH+DeleteFile finding gets the
    # same Downloads/Public/Temp staging-dir veto every other allowlist consumer gets — a bare
    # match here previously let an attacker self-allowlist a real credential dump by naming it
    # e.g. "stolen_passwords_mini-wallet.zip" with zero staging-dir check at all.
    if ($sf.FullName -match "Chrome\\User Data|Firefox\\Profiles" -or (Test-BenignPath $sf.FullName $INFOSTEALER_BENIGN_RE)) { continue }
    # A loose .txt/.log/.db merely *named* like a credential store is weak evidence and FP-prone;
    # treat it as POSSIBLE (shown, not auto-selected for destructive remediation). A creds *archive*
    # (.zip) staged in a user path is a stronger stealer signal -> keep HIGH.
    $stealSev = if ($sf.Extension -match "\.zip$") { $SEV_HIGH } else { $SEV_POSSIBLE }
    # Longest-prefix attribution back to the owning profile root.
    $zbSfUser = 'MACHINE'; $zbSfSid = 'MACHINE'; $zbSfLen = -1
    $zbSfLc = "$($sf.FullName)".ToLowerInvariant()
    foreach ($zbR in $zbP68Roots) {
        $zbRl = "$($zbR.Root)".ToLowerInvariant()
        if ($zbRl.Length -gt $zbSfLen -and $zbSfLc.StartsWith($zbRl)) {
            $zbSfUser = "$($zbR.User)"; $zbSfSid = "$($zbR.Sid)"; $zbSfLen = $zbRl.Length
        }
    }
    Out-Typewriter "  -> [$zbSfUser] SUSPECT CREDENTIAL FILE: $($sf.FullName)" "CRIT"
    # ID was the bare filename with non-alphanumerics stripped, so the SAME lure name under two
    # profiles ("passwords.txt") collided on one ID and Add-Finding's de-dupe dropped the second
    # victim — on a HIGH + DeleteFile finding. Keyed on SID + full path now.
    # FixParam stays a bare machine-parseable path; the user lives in Target/Description.
    Add-Finding -ID "STEALFILE_$(Get-StableId "$zbSfSid|$($sf.FullName)")" -Phase "PHASE 68" -ThreatType "Info-Stealer" `
        -Severity $stealSev -Description "[$zbSfUser] Credential-named file in user path: $($sf.FullName)" `
        -Target "[$zbSfUser] $($sf.FullName)" -FixAction "DeleteFile" -FixParam $sf.FullName -Group "Info-Stealer"
    $global:SpywareHits++
}
# WS0 wiring: known-family drop-path rules (Latrodectus/Matanbuchus/DarkGate) + C2 framework
# artifact-name rules (beacon.dll/metsrv/sliverpb/...) matched against file FULL PATHS. Reuses
# the $p68Files walk above plus ProgramData and the DarkGate staging roots. All FixAction Info —
# a path/name match is triage evidence (the Matanbuchus/DarkGate patterns CAN match a dev's own
# files, e.g. C:\temp\*.exe), never auto-actionable.
$dropRoots = @(@("$env:ProgramData","C:\temp","C:\tmpa") | Where-Object { $_ -and (Test-Path $_) })
$dropFiles = if ($dropRoots.Count) { @((Get-ScanFiles -Path $dropRoots -TimeScoped)) } else { @() }
$fileRuleSevMap = @{ "CRITICAL"=$SEV_CRITICAL; "HIGH"=$SEV_HIGH; "POSSIBLE"=$SEV_POSSIBLE }
$dropRuleHits = 0
$allFileRules = @(@($LOADER_DROP_PATH_RULES) + @($C2_CONFIG_RULES))
if ($allFileRules.Count -gt 0) {
    foreach ($f in @($p68Files + $dropFiles)) {
        foreach ($r in $allFileRules) {
            if ($f.FullName -match $r.Pattern) {
                # $dropRoots are machine-scope (ProgramData / C:\temp / C:\tmpa) and enumerated
                # exactly once outside the profile loop, so anything that matches no profile root
                # is correctly tagged [MACHINE] rather than reported once per profile.
                $zbDrUser = 'MACHINE'; $zbDrSid = 'MACHINE'; $zbDrLen = -1
                $zbDrLc = "$($f.FullName)".ToLowerInvariant()
                foreach ($zbR in $zbP68Roots) {
                    $zbRl = "$($zbR.Root)".ToLowerInvariant()
                    if ($zbRl.Length -gt $zbDrLen -and $zbDrLc.StartsWith($zbRl)) {
                        $zbDrUser = "$($zbR.User)"; $zbDrSid = "$($zbR.Sid)"; $zbDrLen = $zbRl.Length
                    }
                }
                $ruleTT = if ($r.Family) { "Loader Drop ($($r.Family))" } else { "C2 Framework Artifact" }
                Out-ThreatBanner "MALWARE DROP-PATH MATCH ($($r.Name))" "[$zbDrUser] $($f.FullName)"
                # ID was the bare filename — the same loader drop name under two profiles
                # collapsed to one finding. Keyed on SID + full path now.
                Add-Finding -ID "DROPRULE_$(Get-StableId "$zbDrSid|$($f.FullName)")" -Phase "PHASE 68" -ThreatType $ruleTT `
                    -Severity $fileRuleSevMap[$r.Severity] -Description "[$zbDrUser] $($r.Name): $($f.FullName)" `
                    -Target "[$zbDrUser] $($f.FullName)" -FixAction "Info" -Group "Loader / C2 Drop Artifacts"
                $global:TrojanHits++; $dropRuleHits++
                break   # one finding per file
            }
        }
    }
}
if ($stealerProcs.Count -eq 0 -and $stealerFiles.Count -eq 0 -and $dropRuleHits -eq 0) { Out-Typewriter "  -> [OK] NO INFO-STEALER ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 68.5" "CLICKFIX / FAKE-CAPTCHA CLIPBOARD LURE RESIDUE" "SOCIAL ENG"
Out-Typewriter "READING THE RUN-DIALOG HISTORY THE VICTIM ACTUALLY TYPED..." "HUNT"
# ClickFix / "paste this to prove you are human" is currently one of the highest-volume initial
# access techniques: the victim is instructed to press Win+R and paste an attacker-supplied
# command. The residue is RunMRU — a verbatim record of what went into the Run dialog. This is
# unusually high fidelity: no legitimate workflow puts an encoded PowerShell downloader there.
$clickHits = 0
# P1 multi-user: this is the single highest-evidentiary-value per-user key in the engine.
# RunMRU is a verbatim record of what the VICTIM typed into Win+R — reading the elevated
# technician's HKCU here is guaranteed to be empty, because the technician never pasted the
# attacker's command into their own Run box. Walk every profile's hive instead.
# Defensive strip: the data value is an absolute HKCU: path, so take the hive-relative tail
# (tolerating the HKEY_CURRENT_USER spelling) and re-root it on each profile's HivePath.
$zbMruRel = "$RUNMRU_REG_PATH" -replace '(?i)^HK(CU|EY_CURRENT_USER):?\\', ''
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $RUNMRU_REG_PATH -or -not $zbMruRel) { continue }
    if (-not $zbHive.HivePath) { continue }        # hive not mounted + loading off = "could not look"
    $zbMruPath = "$($zbHive.HivePath)\$zbMruRel"
    if (-not (Test-Path -LiteralPath $zbMruPath)) { continue }
    $mruProps = Get-ItemProperty -LiteralPath $zbMruPath -ErrorAction SilentlyContinue
    if (-not $mruProps) { continue }
    $zbMruProv = if ($zbHive.Source -eq 'RegLoad') { " [read from the offline hive $($zbHive.NtUserDat)]" } else { "" }
    foreach ($mp in $mruProps.PSObject.Properties) {
        if ($mp.Name -like 'PS*' -or $mp.Name -eq 'MRUList') { continue }
        $mruCmd = "$($mp.Value)"
        if (-not $mruCmd) { continue }
        $mruCmd = $mruCmd -replace '\\1$', ''      # RunMRU values carry a trailing \1
        foreach ($lr in $CLIPBOARD_LURE_RULES) {
            if ($mruCmd -notmatch $lr.Pattern) { continue }
            $clickHits++
            $lsev = switch ("$($lr.Severity)") { 'CRITICAL' { $SEV_CRITICAL } 'HIGH' { $SEV_HIGH } default { $SEV_POSSIBLE } }
            Out-ThreatBanner "CLICKFIX LURE IN RUN HISTORY" "[$($zbHive.User)] $($mp.Name): $($mruCmd.Substring(0, [Math]::Min(70, $mruCmd.Length)))"
            # The evidence is a registry VALUE, not a running process: deleting it destroys
            # the best proof of how the box was compromised. Info by design — the operator
            # should read it, then hunt what it downloaded.
            # ID carries the SID: two users pasting the SAME command previously collided on
            # one ID and Add-Finding's de-dupe silently dropped the second victim.
            Add-Finding -ID "CLICKFIX_$($mp.Name)_$(Get-StableId "$($zbHive.Sid)|$mruCmd")" -Phase "PHASE 68.5" `
                -ThreatType "Social Engineering / Initial Access" -Severity $lsev `
                -Description "[$($zbHive.User)]$zbMruProv $($lr.Why). This user pasted this into their Run dialog: $($mruCmd.Substring(0, [Math]::Min(240, $mruCmd.Length))) || THIS IS EVIDENCE OF HOW THE MACHINE WAS COMPROMISED — preserve it, then hunt the payload it fetched. Clear afterwards with: Remove-ItemProperty '$zbMruPath' -Name '$($mp.Name)'" `
                -Target "[$($zbHive.User)] $zbMruPath|$($mp.Name)" -FixAction "Info" -Group "ClickFix / Clipboard Lures"
            $global:TrojanHits++
            break
        }
    }
}
if ($clickHits -eq 0) { Out-Typewriter "  -> [OK] NO CLICKFIX LURE RESIDUE IN RUN HISTORY." "GOOD" }

}   # end QUICK-skip block
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
    $asig = Get-AuthSig $proc.Path
    if ($asig.Status -ne "Valid" -and $proc.Path -match $global:USER_PATH_RE -and $proc.Path -notmatch $global:WINDOWSAPPS_RE) {
        Out-Typewriter "  -> POSSIBLE HOLLOW PROCESS: $($proc.Name) PID:$($proc.Id) @ $($proc.Path) (only $($proc.Modules.Count) modules)" "WARN"
        Add-Finding -ID "HOLLOW_$($proc.Id)" -Phase "PHASE 69" -ThreatType "Process Hollowing" `
            -Severity $SEV_HIGH -Description "Possible hollow process: $($proc.Name) PID:$($proc.Id) in AppData/Temp with $($proc.Modules.Count) modules loaded" `
            -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Process Hollowing / Injection"
        $hollowFound = $true
    }
}
if (-not $hollowFound) { Out-Typewriter "  -> [OK] NO OBVIOUS HOLLOW/INJECTED PROCESSES." "GOOD" }

# WS2: known-malware mutex probe — try to open the single-instance mutexes used by specific
# families (Pikabot, Amadey...). Presence = active or residual infection. Very low FP (these
# names are unique to the malware). FixAction Info — a mutex handle isn't a file/reg to delete.
$mutexFound = $false
foreach ($mx in $KNOWN_MALWARE_MUTEXES) {
    foreach ($cand in @($mx, "Global\$mx", "Local\$mx")) {
        $exists = $false
        try { $m = [System.Threading.Mutex]::OpenExisting($cand); if ($m) { $exists = $true; $m.Dispose() } }
        catch [System.UnauthorizedAccessException] { $exists = $true }   # exists but ACL-protected
        catch { $exists = $false }                                       # not found / invalid name
        if ($exists) {
            Out-ThreatBanner "KNOWN-MALWARE MUTEX PRESENT" $cand
            Add-Finding -ID "MUTEX_$($mx -replace '[^a-zA-Z0-9]','')" -Phase "PHASE 69" -ThreatType "Active Malware Mutex" `
                -Severity $SEV_CRITICAL -Description "Known-malware single-instance mutex present ($cand) — indicates active or residual infection (Pikabot/Amadey-class)." `
                -Target $cand -FixAction "Info" -Group "Active Malware Mutex"
            $global:TrojanHits++; $mutexFound = $true
            break
        }
    }
}
if (-not $mutexFound) { Out-Typewriter "  -> [OK] NO KNOWN-MALWARE MUTEXES PRESENT." "GOOD" }

Show-PhaseHeader "PHASE 70" "FILELESS REGISTRY PAYLOAD DETECTION" "FILELESS"
Out-Typewriter "SCANNING REGISTRY FOR ENCODED PAYLOADS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 1000 }
# P1 multi-user: THREE of the four roots are per-user (Run, Environment, Classes\CLSID) and
# every one of them exists for EVERY profile, so pre-P1 this walked the elevated TECHNICIAN's
# hive exclusively and a Base64 payload staged in the victim's Run key or UserInitMprLogonScript
# was structurally invisible. The HKLM IFEO root is machine scope: enumerated ONCE, outside the
# profile loop, tagged [MACHINE].
# The Classes root uses ClassesHivePath, NOT HivePath\Software\Classes — for a reg-loaded
# profile the real per-user class registrations live in a separately-mounted UsrClass.dat and
# NTUSER.DAT's own Software\Classes is nearly empty (measured: 1 CLSID subkey vs 6).
# The ID was built from the bare VALUE NAME, so the same value name in two hives (or even in
# Run vs Environment) collided and Add-Finding's de-dupe silently dropped all but the first —
# it now carries the SID and the full key path. Severity/FixAction unchanged.
$zbFlTargets = @()
foreach ($zbFlMachine in @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")) {
    $zbFlTargets += @{ Path = $zbFlMachine; User = 'MACHINE'; Sid = 'MACHINE'; Off = $false }
}
foreach ($zbHive in @(Get-UserHives)) {
    $zbFlOff = ($zbHive.Source -eq 'RegLoad')
    if ($zbHive.HivePath) {                        # $null = "we could not look", not "nothing there"
        foreach ($zbRel in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run','Environment')) {
            $zbFlTargets += @{ Path = "$($zbHive.HivePath)\$zbRel"
                               User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)"; Off = $zbFlOff }
        }
    }
    if ($zbHive.ClassesHivePath) {
        $zbFlTargets += @{ Path = "$($zbHive.ClassesHivePath)\CLSID"
                           User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)"; Off = $zbFlOff }
    }
}
$filelessFound = $false
foreach ($zbFt in $zbFlTargets) {
    $fp = "$($zbFt.Path)"
    if (-not (Test-Path -LiteralPath $fp)) { continue }
    $regVals = Get-ItemProperty -LiteralPath $fp -ErrorAction SilentlyContinue
    foreach ($prop in ($regVals.psobject.properties | Where-Object { $_.Name -notmatch "^PS" })) {
        $val = [string]$prop.Value
        if ($val.Length -gt 200 -and $val -match "^[A-Za-z0-9+/=]{100,}$") {
            Out-Decrypt -Text "[$($zbFt.User)] $($prop.Name) = [BASE64 BLOB $($val.Length) chars]" -Prefix "  [FILELESS PAYLOAD] "
            # A ZB_UH_* reg-load mount is gone by the time the server's remediation runspace
            # runs, so a DeleteReg FixParam pointing into it would target nothing (addendum 2).
            $zbFlSev = if ($zbFt.Off) { $SEV_HIGH } else { $SEV_CRITICAL }
            $zbFlFix = if ($zbFt.Off) { "Info" }    else { "DeleteReg" }
            $zbFlPrm = if ($zbFt.Off) { "" }        else { "$fp|$($prop.Name)" }
            $zbFlDesc = "[$($zbFt.User)] Suspected Base64 fileless payload in registry: $fp | $($prop.Name)"
            if ($zbFt.Off) { $zbFlDesc += " || Read from an offline hive; remove by hand with reg load HKU\ZBFIX / Remove-ItemProperty / reg unload HKU\ZBFIX." }
            Add-Finding -ID "FILELESS_$(Get-StableId "$($zbFt.Sid)|$fp|$($prop.Name)")" -Phase "PHASE 70" -ThreatType "Fileless Malware" `
                -Severity $zbFlSev -Description $zbFlDesc `
                -Target "[$($zbFt.User)] $fp|$($prop.Name)" -FixAction $zbFlFix -FixParam $zbFlPrm -Group "Fileless Payloads"
            $filelessFound = $true
        }
    }
}
if (-not $filelessFound) { Out-Typewriter "  -> [OK] NO OBVIOUS FILELESS PAYLOADS DETECTED." "GOOD" }

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
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

}   # end QUICK-skip block
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

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 73" "EXPLOIT KIT ARTIFACT & CVE-2021-36934 REMEDIATION" "EXPLOIT"
Out-Typewriter "CHECKING FOR EXPLOIT KIT INDICATORS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
# HiveNightmare already covered in Phase 43 — here we check for exploit toolkit payloads
# P1 multi-user: the six globs were "$env:TEMP\*..." / "$env:LOCALAPPDATA\*..." — the ELEVATED
# TECHNICIAN's profile — so on a standard-user endpoint the victim's staged shellcode/beacon
# payloads were never looked at. Roots are resolved per profile via Get-UserPaths; the two
# pattern SETS stay exactly as they were (Temp: shellcode/exploit/payload, LocalAppData:
# shellcode/cobalt/beacon), and the walk stays NON-recursive on the root, same as before.
# Get-ChildItem here is bounded by construction (one directory level, a name filter), so this
# does not need the Get-ScanFiles budget the recursive sites use.
$zbExploitTargets = @()
foreach ($zbHive in (@(Get-UserHives) | Sort-Object Sid)) {
    if (-not $zbHive.ProfileReachable) { continue }           # never re-probe reachability
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($zbEr in @(
        [pscustomobject]@{ Root = $zbUp.Temp;         Pats = @('*shellcode*','*exploit*','*payload*') }
        [pscustomobject]@{ Root = $zbUp.LocalAppData; Pats = @('*shellcode*','*cobalt*','*beacon*') }
    )) {
        if (-not $zbEr.Root) { continue }
        foreach ($zbEp in $zbEr.Pats) {
            # De-dupe (root,pattern): if two profiles resolve to the same folder, or Temp and
            # LocalAppData collapse to one path, the same file must not be reported twice.
            if (@($zbExploitTargets | Where-Object {
                    "$($_.Root)".ToLowerInvariant() -eq "$($zbEr.Root)".ToLowerInvariant() -and $_.Pat -eq $zbEp
                }).Count -gt 0) { continue }
            $zbExploitTargets += [pscustomobject]@{ Root = "$($zbEr.Root)"; Pat = $zbEp
                                                    User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
        }
    }
}
$exploitFound = $false
foreach ($zbEt in $zbExploitTargets) {
    # -LiteralPath, not -Path: a resolved profile root can legitimately contain [ ] (a renamed
    # account folder), which -Path would treat as a wildcard character class and silently match
    # nothing. The wildcard we DO want stays where it belongs, in -Filter.
    $hits = Get-ChildItem -LiteralPath $zbEt.Root -Filter $zbEt.Pat -ErrorAction SilentlyContinue |
        Where-Object { Test-InScope $_.LastWriteTime }
    foreach ($h in $hits) {
        Out-ThreatBanner "EXPLOIT KIT ARTIFACT" "[$($zbEt.User)] $($h.FullName)"
        # ID was the bare filename — "payload.bin" under two profiles collided on one ID and
        # Add-Finding's de-dupe dropped the second victim, on a CRITICAL + DeleteFile finding.
        # FixParam stays a bare machine-parseable path.
        Add-Finding -ID "EXPLOIT_$(Get-StableId "$($zbEt.Sid)|$($h.FullName)")" -Phase "PHASE 73" -ThreatType "Exploit Kit" `
            -Severity $SEV_CRITICAL -Description "[$($zbEt.User)] Exploit kit artifact in temp: $($h.FullName)" `
            -Target "[$($zbEt.User)] $($h.FullName)" -FixAction "DeleteFile" -FixParam $h.FullName -Group "Exploit Kit Artifacts"
        $exploitFound = $true
    }
}
if (-not $exploitFound) { Out-Typewriter "  -> [OK] NO OBVIOUS EXPLOIT KIT ARTIFACTS." "GOOD" }

Show-PhaseHeader "PHASE 74" "MACRO / OFFICE / OUTLOOK PERSISTENCE AUDIT" "MACRO"
Out-Typewriter "AUDITING OFFICE MACRO TRUST / OUTLOOK RULES..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
# P1 multi-user: EVERY registry root in this phase is per-user, so pre-P1 the whole phase only
# ever examined the ELEVATED TECHNICIAN's hive. Three concrete consequences, all fixed here:
#   * VBAWarnings=1 in the VICTIM's Office config was never seen — and worse, the RunCmd
#     FixParam embedded the TECHNICIAN's PSPath, so an operator applying this HIGH auto-selected
#     fix would have hardened their OWN Office and left the victim's macros wide open.
#   * "OUTLOOK_WEBVIEW" was a FIXED-STRING ID, so even once every hive is walked Add-Finding's
#     de-dupe would keep exactly one finding across all users. It now carries the SID.
#   * The add-in ProgID -> CLSID resolution consulted HKCU:\SOFTWARE\Classes (the technician's).
#     It now uses each profile's ClassesHivePath — a reg-loaded profile's real class data lives
#     in a separately-mounted UsrClass.dat, and NTUSER.DAT's own Software\Classes is near-empty.
# The Office\*\*\Security and Office\*\Addins\* wildcard globbing is preserved verbatim; only
# the root changes. Severity/FixAction unchanged throughout (HIGH + RunCmd for VBAWarnings,
# POSSIBLE + Info for the rest).
# WS8 (T1137): VSTO/COM add-in sideload persistence. Add-ins are a legitimate, extremely common
# Office extensibility mechanism (Bloomberg/Reuters/CRM/PDF plugins all register exactly this
# way), so this is inventory + review, never HIGH/CRITICAL — POSSIBLE + Info only (rule #1: this
# heuristic alone must never drive an auto-select). Two vectors: (a) registered COM/VSTO add-ins
# under per-user Office Addins (LoadBehavior), resolved to their on-disk DLL via
# ProgID -> CLSID -> InprocServer32 (same resolution pattern as the Phase 24 COM hijack audit);
# (b) directly-loadable .wll/.xll binaries dropped into the standard per-user AddIns folder —
# %APPDATA%\Microsoft\AddIns IS the documented install location for legitimate Excel/Word XLL/WLL
# add-ins, so a hit there is routine, not proof of sideloading; still surfaced for review.
$addinFound = $false
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }        # hive not mounted + loading off = "could not look"

    # ── (1) Office macro trust ───────────────────────────────────────────────────────────
    $macroTrust = Get-ItemProperty "$($zbHive.HivePath)\SOFTWARE\Microsoft\Office\*\*\Security" -Name "VBAWarnings" -ErrorAction SilentlyContinue
    foreach ($mt in $macroTrust) {
        if ($mt.VBAWarnings -ne 1) { continue }
        # PSPath comes back provider-qualified ("Microsoft.PowerShell.Core\Registry::HKEY_USERS\...").
        # Both forms are accepted by Set-ItemProperty; normalise to the shorter one so the operator
        # can read the command. A WasMounted hive is HKEY_USERS\<SID>, which still exists long after
        # the engine exits — unlike a ZB_UH_* reg-load mount, handled below.
        $zbMtPath = "$($mt.PSPath)" -replace '^Microsoft\.PowerShell\.Core\\Registry::', 'Registry::'
        # The Office\*\* wildcard segments are user-writable key names, so they are attacker-
        # influenceable text being interpolated into a single-quoted RunCmd string that an
        # auto-selected HIGH finding can execute unattended. Same escaping the Phase 29/64
        # scheduled-task RunCmds already use (rule #1: fail closed on injection).
        $zbMtEsc = "$zbMtPath" -replace "'","''"
        $zbMtOff = ($zbHive.Source -eq 'RegLoad')
        $zbMtFix = if ($zbMtOff) { "Info" } else { "RunCmd" }
        $zbMtPrm = if ($zbMtOff) { "" }     else { "Set-ItemProperty '$zbMtEsc' -Name VBAWarnings -Value 4 -Force" }
        $zbMtDesc = "[$($zbHive.User)] Office VBAWarnings=1 — all macros enabled without prompts (macro malware vector)"
        if ($zbMtOff) { $zbMtDesc += " || Read from an offline hive that does not survive this scan; harden by hand while that user is logged on, or via reg load HKU\ZBFIX / Set-ItemProperty / reg unload HKU\ZBFIX." }
        Out-Typewriter "  -> [$($zbHive.User)] OFFICE VBA MACROS UNRESTRICTED (VBAWarnings=1)" "CRIT"
        Add-Finding -ID "MACRO_TRUST_$(Get-StableId "$($zbHive.Sid)|$zbMtPath")" -Phase "PHASE 74" -ThreatType "Macro Abuse" `
            -Severity $SEV_HIGH -Description $zbMtDesc `
            -Target "[$($zbHive.User)] $zbMtPath|VBAWarnings" -FixAction $zbMtFix -FixParam $zbMtPrm `
            -Group "Office / Macro Security"
        $global:SpywareHits++
    }

    # ── (2) Outlook WebView auto-exec persistence ────────────────────────────────────────
    $zbOwPattern = "$($zbHive.HivePath)\SOFTWARE\Microsoft\Office\*\Outlook\WebView"
    if (Test-Path -Path $zbOwPattern) {
        Out-Typewriter "  -> [$($zbHive.User)] OUTLOOK WEBVIEW REGISTRY PRESENT — CHECK FOR AUTO-EXEC." "WARN"
        Add-Finding -ID "OUTLOOK_WEBVIEW_$(Get-StableId "$($zbHive.Sid)")" -Phase "PHASE 74" -ThreatType "Outlook Persistence" `
            -Severity $SEV_POSSIBLE -Description "[$($zbHive.User)] Outlook WebView registry key present — possible HTML auto-execute persistence" `
            -Target "[$($zbHive.User)] $zbOwPattern" -FixAction "Info" -Group "Office / Macro Security"
    }

    # ── (3) Registered COM/VSTO Office add-ins ───────────────────────────────────────────
    $officeAddinKeys = @(Get-ChildItem -Path "$($zbHive.HivePath)\SOFTWARE\Microsoft\Office\*\Addins\*" -ErrorAction SilentlyContinue)
    foreach ($aik in $officeAddinKeys) {
        $lb = Get-RegVal -Path $aik.PSPath -Name 'LoadBehavior'
        if ($null -eq $lb) { continue }   # key exists but was never actually loaded — nothing to resolve
        $progId = $aik.PSChildName
        $clsidVal = $null; $clsidRoot = $null
        # ── (4) ProgID -> CLSID: this profile's OWN class store first, then the machine roots.
        # ClassesHivePath, never HivePath\Software\Classes (see the header comment).
        foreach ($zbClsRoot in @($zbHive.ClassesHivePath,'HKLM:\SOFTWARE\Classes','HKLM:\SOFTWARE\WOW6432Node\Classes')) {
            if (-not $zbClsRoot) { continue }
            $cv = Get-RegVal -Path "$zbClsRoot\$progId\CLSID" -Name '(default)'
            if ($cv) { $clsidVal = $cv; $clsidRoot = $zbClsRoot; break }
        }
        if (-not $clsidVal) { continue }   # can't resolve ProgID -> CLSID — fail closed, no finding
        $dllPath = Get-RegVal -Path "$clsidRoot\CLSID\$clsidVal\InprocServer32" -Name '(default)'
        if (-not $dllPath) { continue }
        $dllPath = [System.Environment]::ExpandEnvironmentVariables($dllPath)
        if (-not (Test-Path -LiteralPath $dllPath -ErrorAction SilentlyContinue)) { continue }
        $addinSig = Get-AuthSig $dllPath
        $addinUserPath = ($dllPath -match $global:USER_PATH_RE -and $dllPath -notmatch $global:WINDOWSAPPS_RE)
        if ($addinSig.Status -ne "Valid" -or $addinUserPath) {
            $addinFound = $true
            $addinWhy = if ($addinSig.Status -ne "Valid") { "unsigned" } else { "signed but AppData/Temp-hosted" }
            Out-Typewriter "  -> [$($zbHive.User)] OFFICE ADD-IN (review, $addinWhy): $progId LoadBehavior=$lb @ $dllPath" "WARN"
            Add-Finding -ID "ADDIN_$(Get-StableId "$($zbHive.Sid)|$progId|$dllPath")" -Phase "PHASE 74" -ThreatType "Office Add-in Sideload" `
                -Severity $SEV_POSSIBLE -Description "[$($zbHive.User)] Registered Office add-in '$progId' (LoadBehavior=$lb) resolves to a $addinWhy binary: $dllPath — legitimate add-ins (Bloomberg/CRM/PDF plugins) commonly register this exact way too; verify it is an add-in you installed." `
                -Target "[$($zbHive.User)] $dllPath" -FixAction "Info" -Group "Office Add-in Persistence"
        }
    }
}
# P1 multi-user: the loop above walks every profile's HIVE, but this folder scan was still
# Join-Path $env:APPDATA — the ELEVATED TECHNICIAN's %APPDATA%. On a standard-user endpoint the
# victim's %APPDATA%\Microsoft\AddIns was never opened, so a dropped .xll/.wll (a mainstream
# initial-access vector) was invisible. AppData comes from Get-UserPaths, never hand-built:
# folder redirection genuinely moves Roaming onto a file server.
# SINGLE-CALL shape: one Get-ScanFiles over every profile's AddIns folder, then longest-prefix
# attribution — a call per profile would multiply the PER-CALL budget by the profile count.
$zbAddinRoots = @()
foreach ($zbHive in (@(Get-UserHives) | Sort-Object Sid)) {
    if (-not $zbHive.ProfileReachable) { continue }           # never re-probe reachability
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp -or -not $zbUp.AppData) { continue }
    $zbAf = $null
    try { $zbAf = Join-Path "$($zbUp.AppData)" 'Microsoft\AddIns' } catch {}
    if (-not $zbAf) { continue }
    if (@($zbAddinRoots | Where-Object { "$($_.Root)".ToLowerInvariant() -eq "$zbAf".ToLowerInvariant() }).Count -gt 0) { continue }
    if (-not (Test-Path -LiteralPath $zbAf -ErrorAction SilentlyContinue)) { continue }
    $zbAddinRoots += [pscustomobject]@{ Root = "$zbAf"; User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
}
if ($zbAddinRoots.Count -gt 0) {
    $officeAddinFiles = (Get-ScanFiles -Path @($zbAddinRoots | ForEach-Object { $_.Root }) -TimeScoped) |
        Where-Object { $_.Extension -match '\.(wll|xll)$' }
    # Get-AuthSig does online CRL/OCSP revocation checks that can block ~15s each, and this loop
    # is now N profiles wide instead of one — so it carries the shared SIG_AUDIT budget like
    # every other multi-file sig loop in the engine (CLAUDE.md). A single-profile box hits the
    # same code path as before and the budget never trips (AddIns holds a handful of files).
    $zbOafSeen = 0
    $zbOafSw   = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($oaf in $officeAddinFiles) {
        if ($zbOafSeen -ge $global:SIG_AUDIT_MAX_FILES -or
            $zbOafSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
            Out-Typewriter "  -> [INFO] OFFICE ADD-IN SIG BUDGET REACHED — partial scan." "WARN"
            break
        }
        $zbOafSeen++
        $zbOafUser = 'MACHINE'; $zbOafSid = 'MACHINE'; $zbOafLen = -1
        $zbOafLc = "$($oaf.FullName)".ToLowerInvariant()
        foreach ($zbR in $zbAddinRoots) {
            $zbRl = "$($zbR.Root)".ToLowerInvariant()
            if ($zbRl.Length -gt $zbOafLen -and $zbOafLc.StartsWith($zbRl)) {
                $zbOafUser = "$($zbR.User)"; $zbOafSid = "$($zbR.Sid)"; $zbOafLen = $zbRl.Length
            }
        }
        $oafSig = Get-AuthSig $oaf.FullName
        $addinFound = $true
        $oafWhy = if ($oafSig.Status -ne "Valid") { "Unsigned" } else { "Signed" }
        Out-Typewriter "  -> [$zbOafUser] XLL/WLL ADD-IN BINARY ($oafWhy): $($oaf.FullName)" "WARN"
        Add-Finding -ID "ADDINFILE_$(Get-StableId "$zbOafSid|$($oaf.FullName)")" -Phase "PHASE 74" -ThreatType "Office Add-in Sideload" `
            -Severity $SEV_POSSIBLE -Description "[$zbOafUser] $oafWhy XLL/WLL Office add-in binary in the standard per-user AddIns folder (legitimate install location for user-installed add-ins — review, do not assume malicious): $($oaf.FullName)" `
            -Target "[$zbOafUser] $($oaf.FullName)" -FixAction "Info" -Group "Office Add-in Persistence"
    }
    $zbOafSw.Stop()
}
if (-not $addinFound) { Out-Typewriter "  -> [OK] NO SUSPICIOUS OFFICE ADD-IN BINARIES." "GOOD" }
Out-Typewriter "  -> MACRO/OUTLOOK AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 74.5" "EMAIL ATTACHMENT MALWARE SCAN (OUTLOOK CACHE)" "PHISHING"
Out-Typewriter "SCANNING OUTLOOK ATTACHMENT CACHE & EMAIL TEMP FOLDERS..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 800 }
# Targeted attachment/diagnostic caches only — NOT the multi-GB OST/PST store (scanned elsewhere).
# P1 multi-user: $EMAIL_SCAN_TEMPLATES carries raw {TOKEN} templates resolved PER PROFILE. This
# is the phishing entry point and the operator's primary ticket source, and expanding the list
# once against the ELEVATED technician's %LOCALAPPDATA% meant the victim's Outlook attachment
# cache was never scanned at all on a standard-user endpoint.
$zbEmailRoots = @()
foreach ($zbHive in (@(Get-UserHives) | Sort-Object Sid)) {      # SID order -> stable memo key
    if (-not $zbHive.ProfileReachable) { continue }              # never re-probe reachability
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    foreach ($zbTpl in $EMAIL_SCAN_TEMPLATES) {
        $zbPath = Expand-UserPathTemplate $zbTpl $zbUp
        if (-not $zbPath) { continue }                           # unresolved token -> never emit
        if (@($zbEmailRoots | Where-Object { "$($_.Root)".ToLowerInvariant() -eq "$zbPath".ToLowerInvariant() }).Count -gt 0) { continue }
        if (-not (Test-Path -LiteralPath $zbPath -ErrorAction SilentlyContinue)) { continue }
        $zbEmailRoots += [pscustomobject]@{
            Root    = "$zbPath"
            User    = "$($zbHive.User)"
            Sid     = "$($zbHive.Sid)"
            InCache = [bool]("$zbPath" -match 'Olk\\Attachments|Content\.Outlook|Temporary Internet Files')
        }
    }
}
$emailHits = 0
# Extensions worth content-scanning for HTML/JS smuggling & redirector payloads.
$emailTextExt = @(".htm",".html",".js",".jse",".vbs",".vbe",".hta",".wsf",".svg",".log",".txt",".xml")
# ONE bounded walk over every profile's roots: Get-ScanFiles's MaxFiles/DeadlineSecs are PER
# CALL, so a call inside the profile loop would multiply wall-clock by the profile count. Files
# are attributed back to their owning root by LONGEST-prefix match (the Outlook caches nest).
# Parens are mandatory — Get-ScanFiles ends `return ,$arr`, so bare-piping it hands the whole
# array over as ONE item and the filter silently matches everything (CLAUDE.md).
$zbEmailByRoot = @{}
if ($zbEmailRoots.Count -gt 0) {
    $zbEmailAll = (Get-ScanFiles -Path @($zbEmailRoots | ForEach-Object { $_.Root }) -TimeScoped) |
        Where-Object { $_.Length -lt 50MB }
    foreach ($zbEf in @($zbEmailAll)) {
        if (-not $zbEf) { continue }
        $zbFullLc = "$($zbEf.FullName)".ToLowerInvariant()
        $zbOwnKey = $null; $zbOwnLen = -1
        foreach ($zbR in $zbEmailRoots) {
            $zbRootLc = "$($zbR.Root)".ToLowerInvariant()
            if ($zbRootLc.Length -gt $zbOwnLen -and $zbFullLc.StartsWith($zbRootLc)) {
                $zbOwnKey = $zbRootLc; $zbOwnLen = $zbRootLc.Length
            }
        }
        if (-not $zbOwnKey) { continue }
        if (-not $zbEmailByRoot.ContainsKey($zbOwnKey)) { $zbEmailByRoot[$zbOwnKey] = New-Object System.Collections.ArrayList }
        $null = $zbEmailByRoot[$zbOwnKey].Add($zbEf)
    }
}
foreach ($zbOwn in $zbEmailRoots) {
    $zbOwnKey = "$($zbOwn.Root)".ToLowerInvariant()
    $emailFiles = @()
    # ContainsKey first: a missing hashtable key yields $null, and @($null) is a ONE-element
    # array holding $null, not an empty one.
    if ($zbEmailByRoot.ContainsKey($zbOwnKey)) { $emailFiles = @($zbEmailByRoot[$zbOwnKey] | Select-Object -First 500) }
    $inCache = $zbOwn.InCache
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
            Out-Typewriter "  -> [$sev] [$($zbOwn.User)] EMAIL ARTIFACT: $($ef.Name)" $lvl
            # ID = SID + PHYSICAL FILE IDENTITY (name + length + mtime), deliberately NOT the
            # full path. Two reasons, pulling in opposite directions:
            #  - The SID is REQUIRED: the same lure cached under two profiles used to collide on
            #    name+length, and Add-Finding's de-dupe silently dropped the second victim.
            #  - The PATH must be excluded: ...\Temporary Internet Files\Content.Outlook is a
            #    JUNCTION to ...\INetCache\Content.Outlook, and both are in the scan template
            #    list, so keying on FullName reported one physical file TWICE — as HIGH +
            #    Quarantine, where the second attempt would act on an already-quarantined file.
            #    Caught by live grading, 2026-07-26; keying on identity collapses the aliases
            #    back to one finding while keeping the per-user split.
            # Root order (INetCache before Temporary Internet Files) makes the canonical path win.
            # FixParam stays a bare machine-parseable path — the user lives in Target/Description.
            Add-Finding -ID "EMAIL_${idSafe}_$(Get-StableId "$($zbOwn.Sid)|$($ef.Name)|$($ef.Length)|$($ef.LastWriteTimeUtc.Ticks)")" -Phase "PHASE 74.5" -ThreatType $threat `
                -Severity $sev -Description "[$($zbOwn.User)] Email attachment threat: $($reasons -join '; ') [$($ef.FullName)]" `
                -Target "[$($zbOwn.User)] $($ef.FullName)" -FixAction $fixAct -FixParam $ef.FullName `
                -Group "Email / Phishing Threats"
            $global:TrojanHits++; $emailHits++
        }
    }
}
if ($emailHits -eq 0) { Out-Typewriter "  -> [OK] NO SUSPICIOUS EMAIL ARTIFACTS." "GOOD" }
Out-Typewriter "  -> EMAIL ATTACHMENT SCAN COMPLETE." "VER"

}   # end QUICK-skip block
Show-PhaseHeader "PHASE 74.6" "MICROSOFT DEFENDER THREAT HISTORY CORRELATION" "DEFENDER"
Out-Typewriter "CORRELATING WITH WINDOWS DEFENDER DETECTION HISTORY..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
try {
    $threatNames = @{}
    foreach ($t in (Get-MpThreat -ErrorAction SilentlyContinue)) { $threatNames[[string]$t.ThreatID] = $t.ThreatName }
    $dets = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending)

    # ── P7: phishing-family recognition, matched on the FAMILY component ──────────
    # $EMAIL_PHISHING_TROJANS was loaded but never read (review #51), and when it was
    # finally wired the match was StartsWith on the WHOLE label — so the operator's
    # single most common alert, Trojan:Win32/Wacatac.B!ml, could never match the list
    # entry Trojan:Script/Wacatac. Same family, different platform. Precompute the
    # family set once; generic families (Phish:HTML/Generic) are excluded so they
    # cannot swallow every Trojan:Win32/Generic!rfn on the box.
    $zbPhishFams = @{}
    $zbPhishRaw  = @()
    foreach ($pf in $EMAIL_PHISHING_TROJANS) {
        if (-not $pf) { continue }
        $zbLv = Get-DefenderVerdict $pf
        if ($zbLv.Parsed -and -not $zbLv.Generic -and $zbLv.Family) { $zbPhishFams["$($zbLv.Family)".ToLower()] = $true }
        $zbPhishRaw += "$pf"        # mixed-vendor labels keep whole-label prefix matching
    }

    # ── P8 pass 1: aggregate BY PATH ─────────────────────────────────────────────
    # Defender records one detection per event, so the same path appears many times
    # with different outcomes. Grading each row independently let Add-Finding's ID
    # dedup keep an arbitrary one — a "Remove Failed" could be masked by a later
    # "Quarantined" for the same file, or vice versa. Aggregate first, grade once,
    # from the row with the most recent status change (what is true NOW).
    $zbByPath = @{}
    foreach ($d in $dets) {
        if (-not (Test-InScope $d.InitialDetectionTime)) { continue }
        $tname = if ($threatNames.ContainsKey([string]$d.ThreatID)) { $threatNames[[string]$d.ThreatID] } else { "ThreatID $($d.ThreatID)" }
        $zbVerdict = Get-DefenderVerdict $tname

        $zbIsPhish = $false
        if ($zbVerdict.Family -and $zbPhishFams.ContainsKey("$($zbVerdict.Family)".ToLower())) { $zbIsPhish = $true }
        if (-not $zbIsPhish) {
            foreach ($pf in $zbPhishRaw) {
                if ("$tname".StartsWith("$pf", [StringComparison]::OrdinalIgnoreCase)) { $zbIsPhish = $true; break }
            }
        }
        if ($zbIsPhish) { $global:EMAIL_PHISH_SEEN = $true }

        # Defender's own account of what it did — read, not inferred from Test-Path.
        $zbStatId = 0
        try { $zbStatId = [int]$d.ThreatStatusID } catch { $zbStatId = 0 }
        $zbStatName = "status $zbStatId"
        $zbState    = 'unknown'
        if ($global:DEF_STATUS.ContainsKey($zbStatId)) {
            $zbStatName = "$($global:DEF_STATUS[$zbStatId].Name)"
            $zbState    = "$($global:DEF_STATUS[$zbStatId].State)"
        }
        $zbActionOk = $true
        if ($null -ne $d.ActionSuccess) { $zbActionOk = [bool]$d.ActionSuccess }
        if (-not $zbActionOk -and $zbState -eq 'remediated') { $zbState = 'failed' }
        $zbSrcId = -1
        try { $zbSrcId = [int]$d.DetectionSourceTypeID } catch { $zbSrcId = -1 }
        $zbSrcName = if ($global:DEF_SOURCE_TYPE.ContainsKey($zbSrcId)) { "$($global:DEF_SOURCE_TYPE[$zbSrcId])" } else { "source type $zbSrcId" }
        $zbRemTime = $null
        try { if ($d.RemediationTime) { $zbRemTime = [datetime]$d.RemediationTime } } catch { $zbRemTime = $null }
        $zbDetTime = $null
        try { if ($d.InitialDetectionTime) { $zbDetTime = [datetime]$d.InitialDetectionTime } } catch { $zbDetTime = $null }
        # Most recent evidence of state for this row.
        $zbSort = $null
        foreach ($zbT in @($d.LastThreatStatusChangeTime, $d.RemediationTime, $d.InitialDetectionTime)) {
            if (-not $zbT) { continue }
            $zbTd = $null
            try { $zbTd = [datetime]$zbT } catch { $zbTd = $null }
            if ($zbTd -and ((-not $zbSort) -or $zbTd -gt $zbSort)) { $zbSort = $zbTd }
        }

        foreach ($res in @($d.Resources)) {
            $zbRaw = [string]$res
            if (-not $zbRaw) { continue }
            # The resource PREFIX says what was detected and must not be discarded:
            # 'file:' means Defender acted on a file, so the file still being there is
            # meaningful; 'amsi:'/'behavior:'/'process:' means the CONTENT was blocked at
            # execution and the file surviving is expected. Stripping the prefix and
            # calling Test-Path is what graded 22 of this box's own scripts CRITICAL.
            $zbPfx = ''
            if ($zbRaw -match '^([A-Za-z]+):_?') { $zbPfx = "$($Matches[1])".ToLower() }
            $zbPath = $zbRaw -replace '^(file|webfile|containerfile|amsi|behavior|process|regkey|fixpath|runkey|internal):_?',''
            if ($zbPath -notmatch '^[A-Za-z]:\\') { continue }
            $zbFileRes = $global:DEF_FILE_RES_PREFIX.ContainsKey($zbPfx)
            # An absent or unrecognised prefix is treated as CONTENT — the non-escalating
            # side — so an unfamiliar Defender resource form fails safe.
            $zbKey = "$zbPath".ToLower()
            if (-not $zbByPath.ContainsKey($zbKey)) {
                $zbByPath[$zbKey] = @{
                    Path = $zbPath; Count = 0; Names = @{}; Procs = @{}; Sources = @{}; Statuses = @{}
                    Phish = $false; FileRes = $false; MaxRemTime = $null; FirstSeen = $null
                    LatestSort = $null; Verdict = $null; State = 'unknown'; StatusName = ''; SrcName = ''
                    Proc = ''; RemTime = $null; DetTime = $null
                }
            }
            $zbAgg = $zbByPath[$zbKey]
            $zbAgg.Count++
            $zbAgg.Names["$tname"] = $true
            $zbAgg.Statuses["$zbStatName"] = $true
            $zbAgg.Sources["$zbSrcName"] = $true
            if ($d.ProcessName) { $zbAgg.Procs["$($d.ProcessName)"] = $true }
            if ($zbIsPhish) { $zbAgg.Phish = $true }
            if ($zbFileRes) { $zbAgg.FileRes = $true }
            if ($zbRemTime -and ((-not $zbAgg.MaxRemTime) -or $zbRemTime -gt $zbAgg.MaxRemTime)) { $zbAgg.MaxRemTime = $zbRemTime }
            if ($zbDetTime -and ((-not $zbAgg.FirstSeen) -or $zbDetTime -lt $zbAgg.FirstSeen)) { $zbAgg.FirstSeen = $zbDetTime }
            if ((-not $zbAgg.LatestSort) -or ($zbSort -and $zbSort -gt $zbAgg.LatestSort)) {
                $zbAgg.LatestSort = $zbSort
                $zbAgg.Verdict    = $zbVerdict
                $zbAgg.State      = $zbState
                $zbAgg.StatusName = $zbStatName
                $zbAgg.SrcName    = $zbSrcName
                $zbAgg.Proc       = "$($d.ProcessName)"
                $zbAgg.RemTime    = $zbRemTime
                $zbAgg.DetTime    = $zbDetTime
            }
        }
    }

    # ── P8 pass 2: grade each path once ──────────────────────────────────────────
    $defHits = 0; $defResid = 0; $defDemoted = 0
    foreach ($zbKey in @($zbByPath.Keys)) {
        $zbAgg  = $zbByPath[$zbKey]
        $zbPath = "$($zbAgg.Path)"
        $zbV    = $zbAgg.Verdict
        if (-not $zbV) { $zbV = Get-DefenderVerdict '' }
        $zbNames = @($zbAgg.Names.Keys) -join ', '
        $when = if ($zbAgg.DetTime) { $zbAgg.DetTime.ToString('yyyy-MM-dd HH:mm') } else { 'unknown' }

        $zbOnDisk = $false
        try { $zbOnDisk = [bool](Test-Path -LiteralPath $zbPath -ErrorAction SilentlyContinue) } catch { $zbOnDisk = $false }
        $zbWrite = $null
        if ($zbOnDisk) {
            try {
                $zbFi = Get-Item -LiteralPath $zbPath -Force -ErrorAction SilentlyContinue
                if ($zbFi) { $zbWrite = $zbFi.LastWriteTime }
            } catch { $zbWrite = $null }
        }
        # A file written AFTER Defender acted is not the file Defender flagged — it was
        # rebuilt/recreated since. This is what a rebuilt obj\Debug\ artifact looks like.
        $zbRewritten = [bool]($zbWrite -and $zbAgg.MaxRemTime -and $zbWrite -gt $zbAgg.MaxRemTime)
        $zbPathClass = Get-DefenderPathClass $zbPath

        # Grading rationale, always carried in the description so the operator can see
        # WHY a finding was or was not escalated rather than trusting a bare severity.
        $zbCtx = @()
        $zbCtx += "Defender status: $($zbAgg.StatusName)"
        $zbCtx += "detection source: $($zbAgg.SrcName)"
        $zbCtx += if ($zbV.Suffix) { "confidence: !$($zbV.Suffix) ($($zbV.Tier))" } else { "confidence: signature-grade" }
        if ($zbV.Class -ne 'unknown') { $zbCtx += "class: $($zbV.Class)" }
        if ($zbPathClass -ne 'other') { $zbCtx += "path class: $zbPathClass" }
        if ($zbAgg.Count -gt 1)  { $zbCtx += "$($zbAgg.Count) detections on this path" }
        if ($zbAgg.Proc)         { $zbCtx += "Defender attributed the drop to: $($zbAgg.Proc)" }

        $zbSev = $SEV_INFO; $zbFix = 'Info'; $zbLvl = 'DATA'; $zbHead = ''; $zbBlockers = @()

        if (-not $zbAgg.FileRes) {
            # Content-only resource (AMSI / behaviour / process). Nothing was supposed to
            # be deleted; the file existing proves nothing. Report it as what it is.
            $zbHead = "script/process content blocked at execution"
            $zbSev  = if ($zbAgg.State -eq 'failed') { $SEV_POSSIBLE } else { $SEV_INFO }
            if ($zbSev -eq $SEV_POSSIBLE) { $zbLvl = 'WARN' }
        } elseif (-not $zbOnDisk) {
            $zbHead = "no longer on disk"
            $zbSev  = $SEV_INFO
        } elseif ($zbAgg.State -eq 'allowed') {
            # Somebody told Defender to permit this. Benign when an admin added the
            # exclusion; a classic defence-evasion step when the malware did.
            $zbHead = "Defender was told to ALLOW this threat and the file is present"
            $zbSev  = $SEV_POSSIBLE; $zbLvl = 'WARN'
            $zbBlockers += "verify who created this exclusion — an attacker-added allow is defence evasion"
        } else {
            # File resource, still present. Escalation requires EVERY gate to pass.
            if (-not ($zbAgg.State -eq 'failed' -or $zbAgg.State -eq 'pending')) {
                $zbBlockers += "Defender reports the threat was $("$($zbAgg.StatusName)".ToLower()) — remediation did not fail"
            }
            if ([int]$zbV.Rank -lt [int]$global:DEF_ESCALATE_MIN_RANK) {
                $zbBlockers += "verdict is $($zbV.Tier)-derived$(if ($zbV.Suffix) { " (!$($zbV.Suffix))" }), not signature-grade — this tier has a large false-positive share and may not auto-select a destructive action"
            }
            if ($zbV.DualUse) {
                $zbBlockers += "'$($zbV.Class)' is a dual-use class — commonly the technician's own tooling; confirm ownership before removing"
            }
            if ($zbPathClass -eq 'dev') {
                $zbBlockers += "path is developer build output or a source tree"
            }
            if ($zbPathClass -eq 'removable') {
                $zbBlockers += "path is on a non-system volume — not auto-actioned"
            }
            if ($zbRewritten) {
                $zbBlockers += "file was written $($zbWrite.ToString('yyyy-MM-dd HH:mm')) AFTER Defender's action at $($zbAgg.MaxRemTime.ToString('yyyy-MM-dd HH:mm')) — this is not the file Defender flagged"
            }
            if ($zbBlockers.Count -eq 0) {
                $zbHead = "RESIDUAL FILE STILL ON DISK — Defender's remediation FAILED"
                $zbSev = $SEV_CRITICAL; $zbFix = 'Quarantine'; $zbLvl = 'CRIT'
                $defResid++
            } else {
                $zbHead = "file remains at a Defender-flagged path"
                $zbSev = $SEV_POSSIBLE; $zbLvl = 'WARN'
                $defDemoted++
            }
        }

        $zbDesc = "Defender detected '$zbNames' on $when at $zbPath — $zbHead. [$($zbCtx -join '; ')]"
        if ($zbBlockers.Count) { $zbDesc += " NOT auto-selected because: $($zbBlockers -join '; ')." }
        if ($zbAgg.Phish) { $zbDesc += " Known email-phishing/redirector family: treat the mailbox as the entry point and apply the Phase 74.7 hardening." }
        $zbType = if ($zbAgg.Phish) { "Defender Detection — Phishing/Redirector family ($zbNames)" }
                  elseif ($zbSev -eq $SEV_CRITICAL) { "Defender-Flagged Residual ($zbNames)" }
                  else { "Defender Detection ($zbNames)" }
        # ID prefixes preserved from the pre-2026-07-26 grading so -Baseline diffs stay
        # continuous: DEFRES_ for a file-resource still present, DEFHIST_ otherwise.
        $zbId = if ($zbAgg.FileRes -and $zbOnDisk) { "DEFRES_$(Get-StableId $zbPath)" } else { "DEFHIST_$(Get-StableId ("$zbNames|$zbPath"))" }

        if ($zbSev -ne $SEV_INFO) { Out-Typewriter "  -> [$zbSev] $zbHead`: $zbPath" $zbLvl }
        Add-Finding -ID $zbId -Phase "PHASE 74.6" -ThreatType $zbType -Severity $zbSev `
            -Description $zbDesc -Target $zbPath -FixAction $zbFix `
            -FixParam $(if ($zbFix -eq 'Quarantine') { $zbPath } else { "" }) `
            -Group "Defender History / Residual Threats"
        if ($zbSev -eq $SEV_CRITICAL) { $global:TrojanHits++ }
        $defHits++
    }

    if ($defHits -eq 0) { Out-Typewriter "  -> [OK] NO DEFENDER DETECTIONS IN TIME WINDOW." "GOOD" }
    else {
        Out-Typewriter "  -> CORRELATED $defHits DEFENDER-FLAGGED PATH(S): $defResid UNREMEDIATED RESIDUAL(S), $defDemoted PRESENT BUT NOT CORROBORATED." "DATA"
    }
} catch {
    Out-Typewriter "  -> Defender history unavailable (module/cmdlet absent): $($_.Exception.Message)" "WARN"
}
Out-Typewriter "  -> DEFENDER HISTORY CORRELATION COMPLETE." "VER"

if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
Show-PhaseHeader "PHASE 74.7" "PROACTIVE ANTI-REINFECTION HARDENING" "HARDEN"
Out-Typewriter "AUDITING ATTACKER-TARGETED FOOTHOLDS FOR PROACTIVE HARDENING..." "HUNT"
if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 600 }
$hardenHits = 0
# (a) Office / Outlook macro & attachment security — primary phishing execution vector.
# P1 multi-user — DELIBERATE SPLIT (operator decision). The WRITE half stays single-user:
# hardening/lockdown is operator-only by rule #1, and pushing these values into every profile's
# hive materially widens the blast radius. What changes is that the description now NAMES the
# account the RunCmd actually touches — pre-P1 "HKCU" silently meant "the technician running the
# scan", which on a standard-user endpoint is not the person who gets phished, so the finding
# was nearly useless for the hardening's actual purpose. Severity/FixAction unchanged.
$zbHardenUser = "$env:USERDOMAIN\$env:USERNAME"
foreach ($zbHive in @(Get-UserHives)) { if ($zbHive.IsCurrent) { $zbHardenUser = "$($zbHive.User)"; break } }
foreach ($ok in $PROACTIVE_OFFICE_KEYS) {
    try {
        if (-not (Test-Path -LiteralPath $ok.Path)) { continue }   # app not installed — skip
        $cur = (Get-ItemProperty -LiteralPath $ok.Path -Name $ok.Name -ErrorAction SilentlyContinue).$($ok.Name)
        if ($null -eq $cur -or [int]$cur -lt [int]$ok.SafeValue) {
            Add-Finding -ID "HARDEN_OFFICE_$(($ok.Path + $ok.Name) -replace '[^a-zA-Z0-9]','')" -Phase "PHASE 74.7" `
                -ThreatType "Macro/Attachment Exposure" -Severity $SEV_POSSIBLE `
                -Description "[$zbHardenUser] $($ok.Why). Current=$cur, hardened=$($ok.SafeValue). SCOPE: this command writes ONLY the hive of '$zbHardenUser' — the account this scan is running as. Other profiles are audited read-only (see the matching audit findings); hardening is never written into another user's hive automatically." `
                -Target "$($ok.Path)|$($ok.Name)" -FixAction "RunCmd" `
                -FixParam "New-Item -Path '$($ok.Path)' -Force | Out-Null; Set-ItemProperty -Path '$($ok.Path)' -Name '$($ok.Name)' -Value $($ok.SafeValue) -Type DWord -Force" `
                -Group "Proactive Hardening"
            $hardenHits++
        }
    } catch {}
}
# (a1) AUDIT half of (a) — read the SAME settings out of every OTHER profile's hive. Reading
# carries no risk and it is what removes the false all-clear: pre-P1 a clean result here only
# ever meant "the technician's own Office is hardened". Read-only by design — INFO + Info, with
# the literal per-hive command in the description for an operator who chooses to apply it.
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }        # hive not mounted + loading off = "could not look"
    if ($zbHive.IsCurrent) { continue }            # already covered by the RunCmd finding above
    foreach ($ok in $PROACTIVE_OFFICE_KEYS) {
        try {
            $zbOkRel = "$($ok.Path)" -replace '(?i)^HK(CU|EY_CURRENT_USER):?\\', ''
            if (-not $zbOkRel) { continue }
            $zbOkPath = "$($zbHive.HivePath)\$zbOkRel"
            if (-not (Test-Path -LiteralPath $zbOkPath)) { continue }   # app not installed for this user
            $zbOkCur = Get-RegVal -Path $zbOkPath -Name $ok.Name
            if (-not ($null -eq $zbOkCur -or [int]$zbOkCur -lt [int]$ok.SafeValue)) { continue }
            Add-Finding -ID "HARDEN_OFFICE_$(Get-StableId "$($zbHive.Sid)|$zbOkPath|$($ok.Name)")" -Phase "PHASE 74.7" `
                -ThreatType "Macro/Attachment Exposure (other profile, audit)" -Severity $SEV_INFO `
                -Description "[$($zbHive.User)] $($ok.Why). Current=$zbOkCur, hardened=$($ok.SafeValue). AUDIT ONLY — this profile is not the account the scan runs as, so nothing is offered for automatic application. Apply by hand while that user is logged on, or directly: Set-ItemProperty -Path '$zbOkPath' -Name '$($ok.Name)' -Value $($ok.SafeValue) -Type DWord -Force" `
                -Target "[$($zbHive.User)] $zbOkPath|$($ok.Name)" -FixAction "Info" -Group "Proactive Hardening"
            $hardenHits++
        } catch {}
    }
}
# (a2) Autorun-surface inventory (review #51 — $PROACTIVE_PERSIST_REGS was loaded but never read).
# Not a detection: an INFO-level census of the autorun keys attackers actually use, with what
# each one currently holds, so the technician can eyeball the persistence surface in one place
# after remediation. Only non-empty keys are reported — an empty Run key is not news.
# P1 multi-user: this is the AUDIT/INVENTORY half of the phase and it covers ALL profiles —
# an autorun census that only ever listed the technician's own Run keys was worse than useless
# on a standard-user endpoint. $PROACTIVE_PERSIST_REGS is mixed scope (5 HKCU + 2 HKLM), split
# by PREFIX at runtime; the machine roots are enumerated ONCE, outside the profile loop, tagged
# [MACHINE], so an 8-profile box does not list HKLM\...\Run eight times. Anything that is not
# HKCU is treated as machine scope so a future entry cannot be silently dropped. INFO + Info
# throughout — reading carries no risk and nothing here is ever auto-applied.
$zbPersistTargets = @()
foreach ($pr in $PROACTIVE_PERSIST_REGS) {
    if ("$($pr.Path)" -match '(?i)^HK(CU|EY_CURRENT_USER):') { continue }
    $zbPersistTargets += @{ Path = "$($pr.Path)"; Why = "$($pr.Why)"; User = 'MACHINE'; Sid = 'MACHINE' }
}
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }        # hive not mounted + loading off = "could not look"
    foreach ($pr in $PROACTIVE_PERSIST_REGS) {
        if ("$($pr.Path)" -notmatch '(?i)^HK(CU|EY_CURRENT_USER):') { continue }
        $zbPrRel = "$($pr.Path)" -replace '(?i)^HK(CU|EY_CURRENT_USER):?\\', ''
        if (-not $zbPrRel) { continue }
        $zbPersistTargets += @{ Path = "$($zbHive.HivePath)\$zbPrRel"; Why = "$($pr.Why)"
                                User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
    }
}
foreach ($zbPt in $zbPersistTargets) {
    try {
        if (-not (Test-Path -LiteralPath $zbPt.Path)) { continue }
        $vals = @()
        $pp = Get-ItemProperty -LiteralPath $zbPt.Path -ErrorAction SilentlyContinue
        if ($pp) {
            foreach ($pv in $pp.PSObject.Properties) {
                if ($pv.Name -like 'PS*') { continue }   # provider noise (PSPath/PSParentPath/...)
                $vals += "$($pv.Name) = $($pv.Value)"
            }
        }
        if ($vals.Count -eq 0) { continue }
        Add-Finding -ID "AUTORUNSURF_$(Get-StableId "$($zbPt.Sid)|$($zbPt.Path)")" -Phase "PHASE 74.7" `
            -ThreatType "Autorun Surface (inventory)" -Severity $SEV_INFO `
            -Description "[$($zbPt.User)] $($zbPt.Why). $($vals.Count) entr$(if ($vals.Count -eq 1) {'y'} else {'ies'}) present: $(($vals | Select-Object -First 8) -join ' ;; ')$(if ($vals.Count -gt 8) { " ;; (+$($vals.Count - 8) more)" })" `
            -Target "[$($zbPt.User)] $($zbPt.Path)" -FixAction "Info" -Group "Proactive Hardening"
        $hardenHits++
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
# (b2) Script-lure file associations (review #51 — $PROACTIVE_LURE_EXTS was loaded but never read).
# Disabling WSH above blocks the interpreter; this closes the other half of the same vector by
# repointing the double-click handler for script/lure extensions at Notepad, so a .js or .hta
# attachment OPENS instead of RUNS. Per-extension and per-user (HKCU), fully reversible, and
# opt-in RunCmd at INFO — never auto-applied, because a shop with legitimate .vbs tooling would
# notice. Only offered for extensions currently mapped to an executing handler.
# P1 multi-user — DELIBERATE SPLIT (operator decision), and note this site has TWO different
# per-user keys, not one: it READS HKCU:\...\Explorer\FileExts\<ext>\UserChoice but its FixParam
# WRITES HKCU:\SOFTWARE\Classes\<ext>. Migrating only the read would have produced a finding out
# of the VICTIM's hive whose fix silently rewrote the TECHNICIAN's file associations — so both
# halves are kept together. The write block below is unchanged and stays single-user (hardening
# is operator-only, rule #1); the description now names the account it actually writes.
$zbLureUser = "$env:USERDOMAIN\$env:USERNAME"
foreach ($zbHive in @(Get-UserHives)) { if ($zbHive.IsCurrent) { $zbLureUser = "$($zbHive.User)"; break } }
foreach ($lx in $PROACTIVE_LURE_EXTS) {
    try {
        $lxKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$lx\UserChoice"
        $curProgId = Get-RegVal -Path $lxKey -Name 'ProgId'
        # Machine default when the user has made no explicit choice.
        if (-not $curProgId) { $curProgId = Get-RegVal -Path "HKLM:\SOFTWARE\Classes\$lx" -Name '(default)' }
        if (-not $curProgId) { continue }                       # extension not registered at all
        if ("$curProgId" -match '(?i)notepad|txtfile') { continue }   # already opens, does not run
        Add-Finding -ID "HARDEN_LURE_$($lx -replace '[^a-z0-9]','')" -Phase "PHASE 74.7" `
            -ThreatType "Script Lure Association" -Severity $SEV_INFO `
            -Description "[$zbLureUser] Double-clicking a '$lx' file currently EXECUTES it (handler: $curProgId) — the standard phishing-attachment delivery path. Repointing this extension at Notepad makes it open harmlessly for inspection. Reversible; not auto-applied. SCOPE: both the reported association and the fix belong to '$zbLureUser' — the account this scan is running as, which on a standard-user endpoint is the TECHNICIAN, not the person who receives the phish. Other profiles are audited read-only below." `
            -Target $lxKey -FixAction "RunCmd" `
            -FixParam "New-Item -Path 'HKCU:\SOFTWARE\Classes\$lx' -Force | Out-Null; Set-ItemProperty -Path 'HKCU:\SOFTWARE\Classes\$lx' -Name '(default)' -Value 'txtfile' -Force" `
            -Group "Proactive Hardening"
        $hardenHits++
    } catch {}
}
# (b3) AUDIT half of (b2) — the same UserChoice mapping read out of every OTHER profile's hive.
# Reading is exactly what the operator asked for and carries no risk; the fix is NOT offered for
# automatic application, so both halves stay coherent per profile (the literal command in the
# description targets THAT user's Classes root, never HKCU:). INFO + Info.
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }        # hive not mounted + loading off = "could not look"
    if ($zbHive.IsCurrent) { continue }            # already covered by the RunCmd finding above
    foreach ($lx in $PROACTIVE_LURE_EXTS) {
        try {
            $zbLxKey = "$($zbHive.HivePath)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$lx\UserChoice"
            $zbLxProgId = Get-RegVal -Path $zbLxKey -Name 'ProgId'
            if (-not $zbLxProgId) { continue }     # this user made no explicit choice — the machine
                                                   # default is already reported once, machine-wide
            if ("$zbLxProgId" -match '(?i)notepad|txtfile') { continue }   # already opens, does not run
            $zbLxClasses = if ($zbHive.ClassesHivePath) { "$($zbHive.ClassesHivePath)\$lx" } else { "Registry::HKEY_USERS\$($zbHive.Sid)\SOFTWARE\Classes\$lx" }
            Add-Finding -ID "HARDEN_LURE_$($lx -replace '[^a-z0-9]','')_$(Get-StableId "$($zbHive.Sid)")" -Phase "PHASE 74.7" `
                -ThreatType "Script Lure Association (other profile, audit)" -Severity $SEV_INFO `
                -Description "[$($zbHive.User)] Double-clicking a '$lx' file EXECUTES it for this user (handler: $zbLxProgId) — the standard phishing-attachment delivery path. AUDIT ONLY: this profile is not the account the scan runs as, so no fix is offered for automatic application. Apply by hand while that user is logged on, or directly: New-Item -Path '$zbLxClasses' -Force | Out-Null; Set-ItemProperty -Path '$zbLxClasses' -Name '(default)' -Value 'txtfile' -Force" `
                -Target "[$($zbHive.User)] $zbLxKey" -FixAction "Info" -Group "Proactive Hardening"
            $hardenHits++
        } catch {}
    }
}
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

Show-PhaseHeader "PHASE 74.8" "OUTLOOK MAILBOX FORWARD+HIDE (BEC) AUDIT" "PHISHING"
Out-Typewriter "INSPECTING LIVE OUTLOOK SESSION FOR FORWARD+HIDE RULES..." "HUNT"
# WS8 (T1114.003): after landing via BEC, an attacker adds an inbox rule that silently
# forwards/redirects incoming mail to an external address AND deletes or moves the message out
# of the Inbox — the actual evidence-hiding signature. A bare external-forward rule alone is
# common and legitimate (assistants, shared-inbox routing, personal-to-work forwarding), so only
# the CO-OCCURRENCE of forward+hide fires here. This is a broad net BY DESIGN — it does NOT
# require the rule to be scoped to invoice/wire-transfer subject matter (real "forward everything
# + hide" BEC rules often carry no subject/sender condition at all, to intercept the widest
# possible correspondence) — so it can also legitimately fire on a delegate/assistant workflow
# that forwards to a different domain and files the copy out of the Inbox. POSSIBLE + Info,
# review-only; the finding description says so explicitly.
# CRITICAL CONSTRAINT: only ever inspect an ALREADY-RUNNING Outlook via Marshal.GetActiveObject —
# never New-Object -ComObject Outlook.Application, which launches a fresh instance and can
# trigger a profile/MFA prompt on the technician's own interactive session.
# BOUNDED, like every other synchronous COM/native call in this codebase (Get-AuthSig's
# SIG_AUDIT budget, the WSL probe two phases earlier in this same diff): Outlook is routinely
# "Not Responding" on a real MSP endpoint (large PST/OST reindex, a modal dialog on the
# technician's own session, a hung add-in) while OUTLOOK.exe is still alive, so GetActiveObject
# succeeds and every subsequent property/method call is a synchronous out-of-process COM RPC
# that can block for as long as Outlook is unresponsive. The entire inspection runs in a
# background job with a hard wall-clock timeout so a hung Outlook cannot stall Phase 75-115.
$becHits = 0
$outlookRunning = [bool](Get-Process -Name 'OUTLOOK' -ErrorAction SilentlyContinue)
$becJobTimeoutS = 25
$becResults = $null
if ($outlookRunning) {
    $becJob = $null
    try {
        $becJob = Start-Job -ScriptBlock {
            $found = @()
            $outlookApp = $null
            try { $outlookApp = [Runtime.InteropServices.Marshal]::GetActiveObject('Outlook.Application') } catch { $outlookApp = $null }
            if (-not $outlookApp) { return $found }
            try {
                $olNs = $outlookApp.GetNamespace('MAPI')
                # Best-effort "corporate domain" set: every SMTP domain across the profile's own
                # configured accounts. A forward target outside this set counts as external.
                $ownDomains = @{}
                foreach ($acct in @($olNs.Accounts)) {
                    $sa = "$($acct.SmtpAddress)"
                    if ($sa -match '@([^@]+)$') { $ownDomains[$Matches[1].ToLower()] = $true }
                }
                $olStore = $olNs.DefaultStore
                $olRules = $olStore.GetRules()
                foreach ($rule in @($olRules)) {
                    if (-not $rule.Enabled) { continue }
                    $acts = $rule.Actions
                    $fwdTargets = @()
                    foreach ($actName in @('Forward','Redirect','ForwardAsAttachment')) {
                        try {
                            $a = $acts.$actName
                            if ($a -and $a.Enabled) { foreach ($rcp in @($a.Recipients)) { $fwdTargets += "$($rcp.Address)" } }
                        } catch {}
                    }
                    if ($fwdTargets.Count -eq 0) { continue }
                    $externalTargets = @($fwdTargets | Where-Object {
                        if ($_ -match '@([^@]+)$') { -not $ownDomains.ContainsKey($Matches[1].ToLower()) } else { $false }
                    })
                    if ($externalTargets.Count -eq 0) { continue }   # forwards, but only internally — not the BEC pattern
                    $hides = $false; $hideWhy = ""
                    try { if ($acts.Delete -and $acts.Delete.Enabled) { $hides = $true; $hideWhy = "deletes the message" } } catch {}
                    if (-not $hides) {
                        try {
                            if ($acts.MoveToFolder -and $acts.MoveToFolder.Enabled) {
                                $destName = "$($acts.MoveToFolder.Folder.Name)"
                                if ($destName -and $destName -ne 'Inbox') { $hides = $true; $hideWhy = "moves the message out of the Inbox to '$destName'" }
                            }
                        } catch {}
                    }
                    if (-not $hides) { continue }   # forward-only rule — common/legitimate, not flagged
                    $found += [PSCustomObject]@{ RuleName = "$($rule.Name)"; ExternalTargets = ($externalTargets -join ', '); HideWhy = $hideWhy }
                }
            } catch {} finally {
                try { [Runtime.InteropServices.Marshal]::ReleaseComObject($outlookApp) | Out-Null } catch {}
            }
            return $found
        }
        if (Wait-Job -Job $becJob -Timeout $becJobTimeoutS) {
            $becResults = @(Receive-Job -Job $becJob -ErrorAction SilentlyContinue)
        } else {
            Out-Typewriter "  -> OUTLOOK RULE INSPECTION TIMED OUT (${becJobTimeoutS}s, Outlook likely unresponsive) — SKIPPING." "WARN"
        }
    } catch {
        Out-Typewriter "  -> OUTLOOK RULE INSPECTION FAILED (JOB ERROR — SKIPPING)." "WARN"
    } finally {
        if ($becJob) { Stop-Job -Job $becJob -ErrorAction SilentlyContinue; Remove-Job -Job $becJob -Force -ErrorAction SilentlyContinue }
    }
} else {
    Out-Typewriter "  -> OUTLOOK NOT RUNNING — SKIPPING LIVE MAILBOX RULE AUDIT." "INFO"
}
foreach ($br in @($becResults)) {
    $becHits++
    Out-ThreatBanner "BEC FORWARD+HIDE RULE" "$($br.RuleName) -> $($br.ExternalTargets)"
    Add-Finding -ID "BEC_RULE_$(Get-StableId $br.RuleName)" -Phase "PHASE 74.8" -ThreatType "BEC / Mailbox Persistence" `
        -Severity $SEV_POSSIBLE -Description "Outlook inbox rule '$($br.RuleName)' BOTH forwards/redirects mail to an external address ($($br.ExternalTargets)) AND $($br.HideWhy) — this forward+hide combination is the actual BEC evidence-hiding signature (a bare external-forward rule alone is common and NOT flagged). This heuristic does not check what mail the rule targets, so a legitimate delegate/assistant rule (forward to a different domain, then file out of the Inbox) can also match — confirm with the mailbox owner before treating as compromise. Review in Outlook > Rules and remove if unauthorized." `
        -Target "Outlook Rule: $($br.RuleName)" -FixAction "Info" -Group "Outlook Rule Abuse (BEC)"
    $global:TrojanHits++
}
if ($outlookRunning -and $null -ne $becResults -and $becHits -eq 0) { Out-Typewriter "  -> [OK] NO FORWARD+HIDE RULES FOUND." "GOOD" }
Out-Typewriter "  -> OUTLOOK FORWARD+HIDE AUDIT COMPLETE." "VER"

Show-PhaseHeader "PHASE 74.9" "OFFICE MACRO DOCUMENT CONTENT ANALYSIS" "MACRO"
Out-Typewriter "INSPECTING OFFICE DOCUMENTS FOR EMBEDDED VBA MACROS..." "HUNT"
# Until now the engine checked whether macros were ALLOWED TO RUN (Phase 74's VBAWarnings /
# ASR registry posture) but never once opened a document to see whether a macro was actually
# PRESENT. A live sandbox run placed a real Word macro virus (W97M.Class.AU / VAMP_DEMO.doc) in
# Downloads and produced zero findings (2026-07-26) — macro documents are the dominant real-world
# initial-access vector, and this was a complete blind spot.
#
# Detection is by CONTENT, never extension alone: legacy Office files are OLE compound documents
# (D0CF11E0A1B11AE1) whose VBA project lives in a "_VBA_PROJECT" stream; modern ones are ZIP
# containers (PK\x03\x04) holding "vbaProject.bin". A .docx renamed to .doc, or vice versa, is
# therefore still classified correctly.
#
# Severity discipline (rule #1): a macro in a business document is completely normal, so mere
# presence is POSSIBLE. Only a macro combined with an AUTO-EXECUTING entry point or a
# shell/download API is HIGH. Both are FixAction Info — never auto-acted. Deleting a user's
# document because it contains a macro would be exactly the kind of damage rule #1 forbids.
# .rtf is deliberately NOT here: RTF is neither an OLE compound file nor a ZIP, so the magic-byte
# gate below discards every one. Listing it would only imply a coverage this phase does not have.
$docExt   = @('.doc','.docm','.dot','.dotm','.xls','.xlsm','.xlsb','.xlt','.xltm','.ppt','.pptm','.pot','.potm','.docx','.xlsx','.pptx')
# ORDER MATTERS: Get-ScanFiles walks these in sequence under ONE shared file/wall-clock budget, so
# whatever is last gets dropped on a busy box. The Outlook attachment cache is the highest-value
# root for macro-doc delivery (and the only one the $inMail escalation can fire on), so it goes
# first; %TEMP% is the noisiest and least valuable, so it goes last.
# P1 multi-user: every root here was the ELEVATED TECHNICIAN's ($env:LOCALAPPDATA /
# $env:USERPROFILE / $env:TEMP), so on a standard-user endpoint the macro document the VICTIM
# actually received was never opened — which is precisely the blind spot this phase exists to
# close. Roots come from Get-UserPaths per profile (INetCache and Downloads/Desktop are the two
# most commonly REDIRECTED folders on a managed box, so hand-building them would be wrong even
# for the current user). $env:PUBLIC\Downloads is machine-scope and added exactly ONCE.
# The documented priority order is preserved ACROSS profiles, not just within one: all Outlook
# caches first, then all Downloads, then all Desktops, then the machine root, then all Temps —
# because Get-ScanFiles walks the array in order under ONE shared budget and whatever is last
# gets dropped on a busy box.
$zbDocOwners = @()
$zbDocOutlook = @(); $zbDocDl = @(); $zbDocDesk = @(); $zbDocTmp = @()
foreach ($zbHive in (@(Get-UserHives) | Sort-Object Sid)) {   # SID order -> stable memo key
    if (-not $zbHive.ProfileReachable) { continue }           # never re-probe reachability
    $zbUp = Get-UserPaths $zbHive
    if (-not $zbUp) { continue }
    $zbDocOl = $null
    if ($zbUp.INetCache) { try { $zbDocOl = Join-Path "$($zbUp.INetCache)" 'Content.Outlook' } catch {} }
    # Redirected -eq $null means UNKNOWN (the profile resolved by constructed fallback), which is
    # NOT the same as "not redirected" — carried into the finding so a clean result from a folder
    # that may not be where the user's documents actually live is not read as an all-clear.
    $zbDocRedir = ''
    if ($zbUp.Redirected -eq $true) {
        $zbDocRedir = " || NOTE: this profile has REDIRECTED shell folders — documents may also live on a file server this scan did not walk."
    } elseif ($null -eq $zbUp.Redirected) {
        $zbDocRedir = " || NOTE: folder redirection for this profile is UNKNOWN (paths came from a constructed fallback, not the user's own shell-folder registration) — coverage of their real document folders is unproven."
    }
    foreach ($zbD in @(
        [pscustomobject]@{ Bucket = 'OL';   Path = $zbDocOl }
        [pscustomobject]@{ Bucket = 'DL';   Path = $zbUp.Downloads }
        [pscustomobject]@{ Bucket = 'DESK'; Path = $zbUp.Desktop }
        [pscustomobject]@{ Bucket = 'TMP';  Path = $zbUp.Temp }
    )) {
        if (-not $zbD.Path) { continue }
        if (@($zbDocOwners | Where-Object { "$($_.Root)".ToLowerInvariant() -eq "$($zbD.Path)".ToLowerInvariant() }).Count -gt 0) { continue }
        if (-not (Test-Path -LiteralPath "$($zbD.Path)" -ErrorAction SilentlyContinue)) { continue }
        $zbDocOwners += [pscustomobject]@{ Root = "$($zbD.Path)"; User = "$($zbHive.User)"
                                           Sid = "$($zbHive.Sid)"; Redir = $zbDocRedir }
        switch ($zbD.Bucket) {
            'OL'   { $zbDocOutlook += "$($zbD.Path)" }
            'DL'   { $zbDocDl      += "$($zbD.Path)" }
            'DESK' { $zbDocDesk    += "$($zbD.Path)" }
            'TMP'  { $zbDocTmp     += "$($zbD.Path)" }
        }
    }
}
$zbDocPublic = @()
foreach ($zbPd in @("$env:PUBLIC\Downloads")) {               # machine-wide, added ONCE
    if (-not $zbPd) { continue }
    if (-not (Test-Path -LiteralPath $zbPd -ErrorAction SilentlyContinue)) { continue }
    if (@($zbDocOwners | Where-Object { "$($_.Root)".ToLowerInvariant() -eq "$zbPd".ToLowerInvariant() }).Count -gt 0) { continue }
    $zbDocOwners += [pscustomobject]@{ Root = "$zbPd"; User = 'MACHINE'; Sid = 'MACHINE'; Redir = '' }
    $zbDocPublic += "$zbPd"
}
$docRoots = @($zbDocOutlook + $zbDocDl + $zbDocDesk + $zbDocPublic + $zbDocTmp)
$macroHits = 0
if ($docRoots.Count -gt 0) {
    $docFiles = Get-ScanFiles -Path $docRoots -TimeScoped
    $docCands = @($docFiles | Where-Object { ($docExt -contains $_.Extension.ToLower()) -and $_.Length -gt 512 -and $_.Length -lt 15MB })
    # Auto-executing VBA entry points: these run the moment the document is opened, which is what
    # turns "has a macro" into "is a delivery mechanism".
    $autoExecRe = '(?i)\b(AutoOpen|AutoExec|AutoClose|Auto_Open|Auto_Close|Document_Open|Document_Close|Workbook_Open|Workbook_Activate|DocumentOpen)\b'
    # Shell / download / staging APIs reachable from VBA. Deliberately EXCLUDES the bare words
    # 'powershell', 'cmd.exe', 'Shell(', 'CreateObject(', 'GetObject(' and 'Environ(' - for legacy
    # OLE files the document's own prose lives in the same byte space that gets searched, so an IT
    # runbook or support-ticket export that merely mentions PowerShell would escalate to HIGH.
    # What is kept are strings that are far more specific to a weaponised VBA project.
    $vbaBadApiRe = '(?i)(WScript\.Shell|ShellExecute|URLDownloadToFile|MSXML2\.(Server)?XMLHTTP|ADODB\.Stream|WinHttp\.WinHttpRequest|Scripting\.FileSystemObject|VirtualAlloc|CallWindowProc|RtlMoveMemory|Win32_Process)'
    $docSeen = 0; $docSw = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($doc in $docCands) {
        if ($docSeen -ge 400 -or $docSw.Elapsed.TotalSeconds -ge 45) {
            Out-Typewriter "  -> [INFO] MACRO-DOC BUDGET REACHED — partial scan." "WARN"
            break
        }
        $docSeen++
        try {
            $docBytes = [System.IO.File]::ReadAllBytes($doc.FullName)
            if ($docBytes.Length -lt 8) { continue }
            $isOle = ($docBytes[0] -eq 0xD0 -and $docBytes[1] -eq 0xCF -and $docBytes[2] -eq 0x11 -and $docBytes[3] -eq 0xE0 -and
                      $docBytes[4] -eq 0xA1 -and $docBytes[5] -eq 0xB1 -and $docBytes[6] -eq 0x1A -and $docBytes[7] -eq 0xE1)
            $isZip = ($docBytes[0] -eq 0x50 -and $docBytes[1] -eq 0x4B -and $docBytes[2] -eq 0x03 -and $docBytes[3] -eq 0x04)
            if (-not ($isOle -or $isZip)) { continue }
            # Latin1 keeps a 1:1 byte->char mapping (no lossy UTF-8 substitution). OLE directory
            # entry names are UTF-16, so a NUL-stripped copy is searched for those.
            $docRaw  = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($docBytes)
            $docFlat = $docRaw -replace "`0", ''
            $hasMacro = $false
            if ($isOle -and ($docFlat -match '_VBA_PROJECT' -or $docFlat -match 'VBA_PROJECT_CUR' -or $docRaw -match '_VBA_PROJECT')) { $hasMacro = $true }
            if ($isZip -and $docRaw -match 'vbaProject\.bin') { $hasMacro = $true }
            if (-not $hasMacro) { continue }
            # NAMING: these MUST NOT be $auto/$bad. PowerShell variables are case-insensitive and
            # every engine module dot-sources into the loader's ONE scope, so `$auto = ...` here
            # assigns the loader's [switch]$Auto parameter - the flag Summary.ps1 tests to decide
            # whether to [Environment]::Exit(0) instead of dropping into FixMode's interactive
            # Read-Host. A single macro-free document processed last would silently flip $Auto to
            # false and hang every server-driven scan. Caught in review 2026-07-26; the live run
            # that "passed" only did so because the auto-exec document happened to be processed
            # last. This is CLAUDE.md's case-insensitive-shadow rule, exactly.
            $vbaAutoExec = ($docFlat -match $autoExecRe)
            # Require TWO distinct suspicious APIs, not one: $docFlat is the WHOLE file, and for
            # legacy OLE the document's prose shares that byte space, so an IT runbook saved as
            # .doc that merely mentions a shell API would otherwise escalate to HIGH.
            $vbaApiHits = @([regex]::Matches($docFlat, $vbaBadApiRe) | ForEach-Object { $_.Value.ToLower() } | Select-Object -Unique)
            $vbaBadApi  = ($vbaApiHits.Count -ge 2)
            $inMail = ($doc.FullName -match '(?i)\\Content\.Outlook\\')
            # Longest-prefix attribution back to the owning root (Temp can nest under
            # LocalAppData, and Public\Downloads is machine-scope).
            $zbDocUser = 'MACHINE'; $zbDocSid = 'MACHINE'; $zbDocNote = ''; $zbDocLen = -1
            $zbDocLc = "$($doc.FullName)".ToLowerInvariant()
            foreach ($zbR in $zbDocOwners) {
                $zbRl = "$($zbR.Root)".ToLowerInvariant()
                if ($zbRl.Length -gt $zbDocLen -and $zbDocLc.StartsWith($zbRl)) {
                    $zbDocUser = "$($zbR.User)"; $zbDocSid = "$($zbR.Sid)"; $zbDocNote = "$($zbR.Redir)"; $zbDocLen = $zbRl.Length
                }
            }
            if ($vbaAutoExec -or $vbaBadApi) {
                $why = @()
                if ($vbaAutoExec) { $why += 'an auto-executing entry point (runs on open)' }
                if ($vbaBadApi)   { $why += "shell/download API strings ($($vbaApiHits.Count) distinct)" }
                if ($inMail)      { $why += 'and it arrived as an email attachment' }
                Out-ThreatBanner "MACRO DOCUMENT" "[$zbDocUser] $($doc.Name)"
                Add-Finding -ID "MACRODOC_$(Get-StableId "$zbDocSid|$($doc.FullName)")" -Phase "PHASE 74.9" `
                    -ThreatType "Malicious Macro Document" -Severity $SEV_HIGH `
                    -Description "[$zbDocUser] Office document contains an embedded VBA macro project WITH $($why -join ', '): $($doc.FullName). This is the dominant initial-access delivery shape. Open in Protected View only; do not enable content. Review-only — never auto-acted, because legitimate business documents also carry macros.$zbDocNote" `
                    -Target "[$zbDocUser] $($doc.FullName)" -FixAction "Info" -Group "Macro Documents"
                $global:TrojanHits++
            } else {
                Add-Finding -ID "MACRODOC_$(Get-StableId "$zbDocSid|$($doc.FullName)")" -Phase "PHASE 74.9" `
                    -ThreatType "Macro Document" -Severity $SEV_POSSIBLE `
                    -Description "[$zbDocUser] Office document contains an embedded VBA macro project (no auto-exec entry point or shell/download API string detected): $($doc.FullName). Macros are common in legitimate business documents — inventory/review only.$zbDocNote" `
                    -Target "[$zbDocUser] $($doc.FullName)" -FixAction "Info" -Group "Macro Documents"
            }
            $macroHits++
        } catch {}
    }
    $docSw.Stop()
    # These are script-scope (dot-sourced), so without this the LAST document's byte array plus its
    # two full string copies (up to ~75MB combined for a 15MB doc) stay rooted for the whole scan.
    $docBytes = $null; $docRaw = $null; $docFlat = $null
}
if ($macroHits -eq 0) { Out-Typewriter "  -> [OK] NO MACRO-BEARING DOCUMENTS FOUND." "GOOD" }
else { Out-Typewriter "  -> $macroHits MACRO-BEARING DOCUMENT(S) FOUND." "WARN" }

}   # end QUICK-skip block
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
            # $exc is live Defender config an attacker with prior admin access could have set —
            # a path containing a single quote breaks out of this RunCmd string. Escape it.
            $excEsc = "$exc" -replace "'","''"
            Add-Finding -ID "DEFENDER_EXC_$($exc -replace '[^a-z0-9]','')" -Phase "PHASE 75" -ThreatType "Defender Tampering" `
                -Severity $SEV_POSSIBLE -Description "Defender path exclusion (review — could be a malware hiding spot or a legit RMM/dev exclusion): $exc" `
                -Target "Defender Exclusion: $exc" -FixAction "RunCmd" -FixParam "Remove-MpPreference -ExclusionPath '$excEsc'" `
                -Group "Defender Exclusions"
        }
    }
    if ($prefs.ExclusionProcess.Count -gt 0) {
        foreach ($exc in $prefs.ExclusionProcess) {
            Out-Typewriter "  -> DEFENDER PROCESS EXCLUSION: $exc" "WARN"
            $excEsc = "$exc" -replace "'","''"
            Add-Finding -ID "DEFENDER_PROC_EXC_$($exc -replace '[^a-z0-9]','')" -Phase "PHASE 75" -ThreatType "Defender Tampering" `
                -Severity $SEV_POSSIBLE -Description "Defender process exclusion (review — could aid evasion or be a legit RMM/dev exclusion): $exc" `
                -Target "Defender Process Exclusion: $exc" -FixAction "RunCmd" -FixParam "Remove-MpPreference -ExclusionProcess '$excEsc'" `
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
if (-not $global:QUICK_MODE) {
    trap { Write-RecoveredError $_; continue }   # QUICK-skip block: inner trap resumes at next phase (CLAUDE.md engine-split rule)
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
# WS8 (T1098.004): SSH authorized_keys backdoor entry audit. A key added to
# administrators_authorized_keys or a user's .ssh\authorized_keys is a durable SSH login
# backdoor that survives password resets and is invisible to the account-lockout/password-audit
# phases — and it persists whether or not sshd happens to be running right now, so this check is
# unconditional. Surface only the key COMMENT labels (never the key material — the base64 blob
# itself is not evidence of who added it; the trailing "user@host" comment is the readable clue).
# FixAction Info: an authorized_keys line can be a legitimate admin/dev key, so this is triage
# evidence for the operator, never auto-removed.
$sshKeyFiles = @()
# $env:ProgramData is MACHINE scope — enumerated once, outside anything per-user.
$adminAuthKeysPath = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
if (Test-Path -LiteralPath $adminAuthKeysPath) { $sshKeyFiles += @{ Path = $adminAuthKeysPath; Owner = "MACHINE — SYSTEM (all administrators)" } }
# P1 multi-user (MIGRATE-LITE): the users root was Split-Path $env:USERPROFILE -Parent, i.e.
# derived from the ELEVATED TECHNICIAN's profile path. The INTENT was already all-users, but the
# derivation breaks the moment profiles do not live beside the technician's — a relocated
# ProfilesDirectory (D:\Users), a migrated box carrying two profile roots, or a technician
# signing in with a profile on a different volume. Every user's SSH backdoor key would then be
# missed while the phase still printed its green "NO SSH AUTHORIZED_KEYS FILES PRESENT" line —
# a false all-clear. Built from the DISTINCT PARENTS of the real profile paths now, so the
# directory walk still covers stale/orphaned profile folders that have no hive (the pre-P1
# coverage) while being correct on any layout.
# Unreachable profiles are excluded BEFORE any filesystem call: Get-UserHives sets
# ProfileReachable exactly once and Test-Path on an unreachable UNC path stalled 42s on this box
# and can throw a terminating IOException that -EA SilentlyContinue does NOT suppress.
$zbSshRoots = @()
$zbSshOwners = @()
foreach ($zbHive in @(Get-UserHives)) {
    if (-not $zbHive.ProfilePath) { continue }
    if (-not $zbHive.ProfileReachable) { continue }
    $zbSshOwners += [pscustomobject]@{ Prefix = "$($zbHive.ProfilePath)"; User = "$($zbHive.User)" }
    $zbPar = $null
    try { $zbPar = Split-Path "$($zbHive.ProfilePath)" -Parent } catch {}
    if (-not $zbPar) { continue }
    if (@($zbSshRoots | Where-Object { "$_".ToLowerInvariant() -eq "$zbPar".ToLowerInvariant() }).Count -gt 0) { continue }
    $zbSshRoots += "$zbPar"
}
if ($zbSshRoots.Count -eq 0 -and $env:USERPROFILE) {
    try { $zbSshRoots = @((Split-Path $env:USERPROFILE -Parent)) } catch { $zbSshRoots = @() }
}
foreach ($sshUsersRoot in $zbSshRoots) {
    if (-not $sshUsersRoot -or -not (Test-Path -LiteralPath $sshUsersRoot)) { continue }
    $sshUserDirs = Get-ChildItem -LiteralPath $sshUsersRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($sud in $sshUserDirs) {
        $uak = Join-Path $sud.FullName '.ssh\authorized_keys'
        if (-not (Test-Path -LiteralPath $uak)) { continue }
        if (@($sshKeyFiles | Where-Object { "$($_.Path)".ToLowerInvariant() -eq "$uak".ToLowerInvariant() }).Count -gt 0) { continue }
        # Prefer the real account name (DOMAIN\user) over the profile FOLDER leaf: the two differ
        # routinely (name changes, duplicate-profile ".DOMAIN" suffixes), and the folder leaf alone
        # does not tell the operator which ACCOUNT the backdoor key logs in as.
        $zbSshOwner = $sud.Name
        $zbSudLc = "$($sud.FullName)".ToLowerInvariant()
        foreach ($zbSo in $zbSshOwners) {
            if ("$($zbSo.Prefix)".ToLowerInvariant() -eq $zbSudLc) { $zbSshOwner = "$($zbSo.User)"; break }
        }
        $sshKeyFiles += @{ Path = $uak; Owner = $zbSshOwner }
    }
}
$sshBackdoorFound = $false
foreach ($skf in $sshKeyFiles) {
    $skLines = @(Get-Content -LiteralPath $skf.Path -ErrorAction SilentlyContinue | Where-Object { $_ -and $_.Trim() -and $_.Trim() -notmatch '^#' })
    if ($skLines.Count -eq 0) { continue }
    # Pull the trailing comment (typically "user@host") off each key line for a readable label;
    # fall back to the key type token if no comment is present.
    $skLabels = @($skLines | ForEach-Object {
        $skParts = $_.Trim() -split '\s+'
        if ($skParts.Count -ge 3) { $skParts[2] } elseif ($skParts.Count -ge 1) { $skParts[0] } else { "(unlabeled)" }
    })
    $sshBackdoorFound = $true
    Out-ThreatBanner "SSH AUTHORIZED_KEYS ENTRY" "$($skf.Owner): $($skLines.Count) key(s) — $($skLabels -join ', ')"
    # ID is derived from the FULL PATH, which now names a different user per profile, so it picks
    # up per-user uniqueness for free — no SID needed (contract rule 5).
    Add-Finding -ID "SSHKEYS_$(Get-StableId $skf.Path)" -Phase "PHASE 77" -ThreatType "SSH Key Backdoor" `
        -Severity $SEV_POSSIBLE -Description "[$($skf.Owner)] authorized_keys present with $($skLines.Count) key(s) — a durable SSH login backdoor that survives password resets. Key label(s): $($skLabels -join ', '). Verify every entry is a known admin/dev key: $($skf.Path)" `
        -Target "[$($skf.Owner)] $($skf.Path)" -FixAction "Info" -Group "Remote Management Services"
}
if (-not $sshBackdoorFound) { Out-Typewriter "  -> [OK] NO SSH AUTHORIZED_KEYS FILES PRESENT." "GOOD" }

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

}   # end QUICK-skip block
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
            # Downgraded from CRITICAL+auto-KillProcess (2026-07-26 adversarial FP audit, rule #1):
            # cmd.exe/powershell.exe/python.exe etc. holding ANY established connection to a
            # non-default port is routine on a healthy dev/business box (a local dev API, a
            # database client, a package-index mirror, a webhook test, VS Code's integrated
            # terminal) — interpreter name + destination port alone isn't corroboration, and
            # unlike file/artifact-based checks elsewhere in this engine, signature/path gating
            # doesn't help here (an attacker abusing a real reverse shell uses the system's own,
            # validly-signed cmd.exe/powershell.exe, not a dropped copy). Still surfaced
            # prominently for review, never auto-killed.
            Add-Finding -ID "REVSHELL_$($rp.Id)" -Phase "PHASE 81" -ThreatType "Reverse Shell" `
                -Severity $SEV_HIGH -Description "Possible reverse shell (review — interpreter/shell processes routinely hold non-standard-port connections on healthy dev boxes, so this needs a human look before acting): $($rp.Name) PID:$($rp.Id) -> $($conn.RemoteAddress):$($conn.RemotePort)" `
                -Target "PID:$($rp.Id)" -FixAction "Info" -Group "Reverse Shells"
            $global:RATHits++
        }
    }
    if (-not $foundShell) { Out-Typewriter "  -> [OK] NO REVERSE SHELL SOCKETS." "GOOD" }

    Show-PhaseHeader "PHASE 82" "NETCAT / SOCAT / CHISEL / PLINK BINARY SCAN" "UNIVERSAL"
    # WS0 wiring: externalized to 'tunneling_tools' (AMSI-safe, same list).
    $tunnelNames = $TUNNELING_TOOLS
    # P1 multi-user: the roots were $env:TEMP / $env:LOCALAPPDATA / $env:USERPROFILE — the
    # ELEVATED TECHNICIAN's profile — plus $env:WINDIR\Temp. On a standard-user endpoint the
    # attacker's netcat/chisel staged in the VICTIM's profile was never walked. Roots resolved
    # per profile via Get-UserPaths; $env:WINDIR\Temp is MACHINE scope and added exactly ONCE.
    # PREFIX DE-DUPE: Temp and LocalAppData normally nest INSIDE the profile root, so the pre-P1
    # array walked the same tree up to three times (only the bare-filename ID masked the
    # duplicate findings). With N profiles that waste is multiplied by N against a PER-CALL
    # budget, which would truncate the walk before it reaches the later profiles. A root already
    # covered by one taken earlier is skipped; Temp/LocalAppData are still added when redirection
    # has genuinely moved them outside the profile root.
    $zbTunnelRoots = @()
    foreach ($zbHive in (@(Get-UserHives) | Sort-Object Sid)) {   # SID order -> stable memo key
        if (-not $zbHive.ProfileReachable) { continue }           # never re-probe reachability
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbR in @($zbUp.Profile, $zbUp.Temp, $zbUp.LocalAppData)) {
            if (-not $zbR) { continue }
            $zbRlc = "$zbR".ToLowerInvariant()
            $zbCovered = $false
            foreach ($zbEx in $zbTunnelRoots) {
                $zbExLc = "$($zbEx.Root)".ToLowerInvariant()
                if ($zbRlc -eq $zbExLc -or $zbRlc.StartsWith($zbExLc.TrimEnd('\') + '\')) { $zbCovered = $true; break }
            }
            if ($zbCovered) { continue }
            $zbTunnelRoots += [pscustomobject]@{ Root = "$zbR"; User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
        }
    }
    foreach ($zbMr in @("$env:WINDIR\Temp")) {                    # machine-wide, added ONCE
        if (-not $zbMr) { continue }
        if (@($zbTunnelRoots | Where-Object { "$($_.Root)".ToLowerInvariant() -eq "$zbMr".ToLowerInvariant() }).Count -gt 0) { continue }
        $zbTunnelRoots += [pscustomobject]@{ Root = "$zbMr"; User = 'MACHINE'; Sid = 'MACHINE' }
    }
    # One bounded walk; anchored regex so "nc.exe" doesn't substring-match "sync.exe"
    # (was 4 roots x 12 names = 48 recursions, one over the entire user profile).
    $tunnelRegex = ($tunnelNames | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
    # Dual-use subset (PuTTY suite: putty/plink/pscp/psftp/pageant — legit admin SSH tooling):
    # POSSIBLE, so never auto-selected for the DeleteFile; operator can still act manually.
    # putty/plink sign-off 2026-07-04; rest of the suite added 2026-07-11 (new coverage, same grade).
    $tunnelDualRegex = (@($TUNNELING_TOOLS_DUALUSE) | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
    $tunnelFound = $false
    # Parens are mandatory — Get-ScanFiles ends `return ,$arr`, so bare-piping it hands the whole
    # array over as ONE item and the filter silently matches everything (CLAUDE.md).
    $tunnelHits = @()
    if ($zbTunnelRoots.Count -gt 0) {
        $tunnelHits = (Get-ScanFiles -Path @($zbTunnelRoots | ForEach-Object { $_.Root })) |
            Where-Object { $_.Name -match $tunnelRegex }
    }
    foreach ($hit in $tunnelHits) {
        $tunnelFound = $true
        # Longest-prefix attribution back to the owning root.
        $zbTuUser = 'MACHINE'; $zbTuSid = 'MACHINE'; $zbTuLen = -1
        $zbTuLc = "$($hit.FullName)".ToLowerInvariant()
        foreach ($zbR in $zbTunnelRoots) {
            $zbRl = "$($zbR.Root)".ToLowerInvariant()
            if ($zbRl.Length -gt $zbTuLen -and $zbTuLc.StartsWith($zbRl)) {
                $zbTuUser = "$($zbR.User)"; $zbTuSid = "$($zbR.Sid)"; $zbTuLen = $zbRl.Length
            }
        }
        Out-Decrypt -Text "[$zbTuUser] $($hit.FullName)" -Prefix "  [TUNNEL TOOL] "
        $tunnelSev = if ($tunnelDualRegex -and $hit.Name -match $tunnelDualRegex) { $SEV_POSSIBLE } else { $SEV_CRITICAL }
        # ID was the bare filename, so one "nc.exe" per profile collapsed to a single finding and
        # Add-Finding's de-dupe dropped every victim but the first — on a CRITICAL + DeleteFile.
        # FixParam stays a bare machine-parseable path.
        Add-Finding -ID "TUNNEL_$(Get-StableId "$zbTuSid|$($hit.FullName)")" -Phase "PHASE 82" -ThreatType "Tunneling Tool" `
            -Severity $tunnelSev -Description "[$zbTuUser] Tunneling/pivoting tool found: $($hit.FullName)" `
            -Target "[$zbTuUser] $($hit.FullName)" -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Tunneling / Pivoting Tools"
    }
    if (-not $tunnelFound) { Out-Typewriter "  -> [OK] NO TUNNELING TOOLS FOUND." "GOOD" }

        Show-PhaseHeader "PHASE 82.5" "REMOTE MONITORING TOOL ABUSE (UNAUTHORISED RMM)" "UNIVERSAL"
    Out-Typewriter "AUDITING REMOTE-ACCESS AGENTS FOR UNAUTHORISED DEPLOYMENT..." "HUNT"
    # USER RULE #2: Datto / CentraStage / Kaseya are this shop's own partner tooling and are
    # deliberately ABSENT from the data list. Everything that IS listed is still genuinely
    # dual-use — an MSP may legitimately run any of it — so a normal installed agent is INFO.
    # What escalates is the SHAPE of the deployment: a remote-access agent running from a
    # staging directory (Temp/Downloads/Public/ProgramData root) is how ransomware crews
    # maintain hands-on access, and no legitimate install lands there.
    $rmmHits = 0
    foreach ($rp in (Get-ProcSnapshot)) {
        $rname = "$($rp.Name)".ToLower()
        if ($RMM_TOOL_BINARIES -notcontains $rname) { continue }
        $rpath = "$($rp.ExecutablePath)"
        $rmmHits++
        $rSuspPath = ($rpath -and $rpath -match $RMM_SUSPICIOUS_PATH_RE)
        # Vendor-trusted partner tooling is protected by Test-VendorTrusted downstream too.
        if ($rSuspPath) {
            Out-ThreatBanner "RMM AGENT FROM A STAGING PATH" "$($rp.Name) @ $rpath"
            # POSSIBLE + Info, NOT HIGH + KillProcess. Running AnyDesk/TeamViewer QuickSupport
            # portable straight out of Downloads is one of the most common MSP workflows there
            # is — an auto-selected kill here would sever the very remote session the technician
            # is working in. Test-VendorTrusted covers only the Datto/CentraStage/Kaseya family,
            # so there is no downstream guard for these vendors either. Operator decides.
            Add-Finding -ID "RMMABUSE_$($rp.ProcessId)_$($rname -replace '[^a-z0-9]','')" -Phase "PHASE 82.5" `
                -ThreatType "Unauthorised Remote Access" -Severity $SEV_POSSIBLE `
                -Description "Remote-access agent '$($rp.Name)' (PID $($rp.ProcessId)) is running from a user-writable staging path: $rpath — an attacker-deployed foothold looks exactly like this, but so does a technician's own portable QuickSupport session. Confirm against your RMM inventory; if unauthorized: Stop-Process -Id $($rp.ProcessId) -Force" `
                -Target "PID:$($rp.ProcessId)" -FixAction "Info" `
                -Group "Remote Access Tooling"
        } else {
            Add-Finding -ID "RMMPRESENT_$($rp.ProcessId)_$($rname -replace '[^a-z0-9]','')" -Phase "PHASE 82.5" `
                -ThreatType "Remote Access Tooling (inventory)" -Severity $SEV_INFO `
                -Description "Remote-access/RMM agent present and running: $($rp.Name)$(if ($rpath) { " ($rpath)" }) — expected on a managed endpoint. Verify it is YOURS: an unexpected second remote-access product is a common intruder persistence method." `
                -Target "PID:$($rp.ProcessId)" -FixAction "Info" -Group "Remote Access Tooling"
        }
    }
    if ($rmmHits -eq 0) { Out-Typewriter "  -> [OK] NO REMOTE-ACCESS AGENTS RUNNING." "GOOD" }

Show-PhaseHeader "PHASE 83" "HOLLOW PROCESS DEEP SCAN (EXTENDED)" "UNIVERSAL"
    Out-Typewriter "EXTENDED PROCESS MEMORY / HOLLOWING ANALYSIS..." "HUNT"
    Invoke-QuantumBar "PROCESS MEMORY MAP ANALYSIS" 15 170
    $extended = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and (Test-Path $_.Path) -and $_.Modules.Count -lt 5 -and
        $_.Name -notmatch "^(svchost|System|smss|csrss|wininit|services|lsass|winlogon|fontdrvhost|dwm|audiodg|conhost|taskhostw|RuntimeBroker|sihost|SearchHost)$"
    }
    foreach ($proc in $extended) {
        $asig = Get-AuthSig $proc.Path
        if ($asig.Status -eq "NotSigned" -and $proc.Path -match $global:USER_PATH_RE -and $proc.Path -notmatch $global:WINDOWSAPPS_RE) {
            Out-Typewriter "  -> LOW-MODULE UNSIGNED PROC: $($proc.Name) PID:$($proc.Id) @ $($proc.Path) [$($proc.Modules.Count) modules]" "WARN"
            Add-Finding -ID "HOLLOW_EXT_$($proc.Id)" -Phase "PHASE 83" -ThreatType "Process Hollowing" `
                -Severity $SEV_HIGH -Description "Unsigned low-module process from user path: $($proc.Name) PID:$($proc.Id) [$($proc.Modules.Count) modules]" `
                -Target "PID:$($proc.Id)" -FixAction "KillProcess" -FixParam $proc.Id -Group "Process Hollowing / Injection"
        }
    }

    Show-PhaseHeader "PHASE 84" "APPLOCKER / GPO POLICY BYPASS AUDIT" "UNIVERSAL"
    Out-Typewriter "CHECKING APPLOCKER BYPASS INDICATORS..." "HUNT"
    # P1 multi-user: this policy value is PER USER, and the ID used to be the fixed string
    # "DISALLOWRUN" — so even once every hive is walked, Add-Finding's de-dupe would keep only
    # the first user. Hive-relative path + SID in the ID. Severity/FixAction unchanged.
    $zbSrpRel = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $zbSrpHit = $false
    foreach ($zbHive in @(Get-UserHives)) {
        if (-not $zbHive.HivePath) { continue }     # not mounted + loading off = "could not look"
        $zbSrpPath = "$($zbHive.HivePath)\$zbSrpRel"
        if (-not (Test-Path -LiteralPath $zbSrpPath)) { continue }
        # Get-RegVal, never raw Get-ItemPropertyValue/Get-ItemProperty -Name (terminating
        # "property does not exist" error that -EA SilentlyContinue does not suppress).
        $zbDisallow = Get-RegVal -Path $zbSrpPath -Name 'DisallowRun'
        if ("$zbDisallow" -ne '1') { continue }
        $zbSrpHit = $true
        Out-Typewriter "  -> [$($zbHive.User)] DISALLOWRUN ACTIVE — REVIEWING EXCEPTION LIST..." "WARN"
        Add-Finding -ID "DISALLOWRUN_$(Get-StableId "$($zbHive.Sid)|$zbSrpPath")" -Phase "PHASE 84" -ThreatType "Policy Bypass" -Severity $SEV_POSSIBLE `
            -Description "[$($zbHive.User)] DisallowRun GPO policy is active — review exception list for bypass paths" `
            -Target "[$($zbHive.User)] $zbSrpPath|DisallowRun" -FixAction "Info" -Group "Policy / AppLocker Bypass"
    }
    if (-not $zbSrpHit) { Out-Typewriter "  -> [OK] DISALLOWRUN NOT SET (ALL PROFILES)." "GOOD" }

    Show-PhaseHeader "PHASE 85" "LOLBIN PERSISTENCE (INSTALLUTIL / MSIEXEC)" "UNIVERSAL"
    Out-Typewriter "SCANNING INSTALLUTIL/MSIEXEC PERSISTENCE..." "HUNT"
    # P1 multi-user: both roots are per-user. The ID was built from the bare key leaf name, so
    # the same installer key under two profiles collided and only the first survived de-dupe.
    foreach ($zbHive in @(Get-UserHives)) {
        if (-not $zbHive.HivePath) { continue }     # not mounted + loading off = "could not look"
        foreach ($zbRel in @('SOFTWARE\Microsoft\InstallShield','SOFTWARE\Microsoft\Windows\CurrentVersion\Installer')) {
            $zbFp = "$($zbHive.HivePath)\$zbRel"
            if (-not (Test-Path -LiteralPath $zbFp)) { continue }
            # "Recent" is now backed by the real key write time (RegQueryInfoKey via the loader's
            # Get-RegKeyLastWriteTime) — the old $_.LastWriteTime read was $null (no such property),
            # so every installer key ever written surfaced as "recent" regardless of scan window.
            $recentKeys = Get-ChildItem -LiteralPath $zbFp -Recurse -ErrorAction SilentlyContinue | Where-Object { Test-InScope (Get-RegKeyLastWriteTime $_) }
            foreach ($k in $recentKeys) {
                Out-Typewriter "  -> [$($zbHive.User)] RECENT INSTALL KEY: $($k.PSPath)" "WARN"
                Add-Finding -ID "LOLBIN_INST_$(Get-StableId "$($zbHive.Sid)|$($k.PSPath)")" -Phase "PHASE 85" -ThreatType "LoLBin Persistence" `
                    -Severity $SEV_POSSIBLE -Description "[$($zbHive.User)] Recent installer registry key (LoLBin persistence vector): $($k.PSPath)" `
                    -Target "[$($zbHive.User)] $($k.PSPath)" -FixAction "Info" -Group "LoLBin Persistence"
            }
        }
    }

    Show-PhaseHeader "PHASE 86" "RECYCLE BIN STAGING AREA SCAN" "UNIVERSAL"
    $recycleBin = (Get-ScanFiles -Path "C:\`$Recycle.Bin" -TimeScoped) |
        Where-Object { $_.Extension -match "\.(exe|dll|js|vbs|bat|cmd|ps1|hta|wsf)$" }
    foreach ($rb in $recycleBin) {
        Out-Decrypt -Text $rb.FullName -Prefix "  [RECYCLE BIN PAYLOAD] "
        # POSSIBLE, not HIGH: recycled scripts/exes are routine on healthy boxes (users delete
        # their own tools/projects). Staging is a heuristic, not confirmed malware — the operator
        # can still select these manually for deletion; they are never auto-purged.
        Add-Finding -ID "RECYCLE_$($rb.Name -replace '[^a-z0-9]','')" -Phase "PHASE 86" -ThreatType "Malware Staging" `
            -Severity $SEV_POSSIBLE -Description "Executable in Recycle Bin (possible staging — review; users routinely delete their own scripts): $($rb.FullName)" `
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

    Show-PhaseHeader "PHASE 87.5" "GPP CACHED PASSWORD (CPASSWORD) AUDIT" "UNIVERSAL"
    Out-Typewriter "SCANNING GROUP POLICY PREFERENCES XML FOR CACHED CPASSWORD..." "HUNT"
    # WS8 (T1552.001 / MS14-025): Group Policy Preferences let an admin push a local account,
    # mapped drive, scheduled task, service, printer or ODBC data source with a
    # plaintext-equivalent password embedded in the Preferences XML, "encrypted" with a single
    # AES-256 key Microsoft published in MS-GPPREF §2.2.1.1 — the same key for every domain
    # everywhere, so there is no secret to protect. Any authenticated domain user can read
    # SYSVOL, so a non-empty cpassword attribute is a fully realized credential exposure, not a
    # heuristic — CRITICAL, unambiguous. FixAction stays Info (rule #1): this is a live GPO
    # artifact edited via Group Policy Management, not a file this endpoint scan should ever
    # touch — the real fix ("rotate the credential, delete the Preference item in GPMC") needs a
    # domain admin, not this box.
    function Get-GppDecryptedPassword {
        param([string]$CipherB64)
        if (-not $CipherB64) { return $null }
        try {
            $gppPad = (4 - ($CipherB64.Length % 4)) % 4
            $gppCipherBytes = [Convert]::FromBase64String($CipherB64 + ('=' * $gppPad))
            $gppAes = [System.Security.Cryptography.Aes]::Create()
            try {
                $gppAes.Key = $GPP_AES_KEY_BYTES
                $gppAes.IV  = New-Object byte[] 16   # MS-GPPREF specifies an all-zero IV
                $gppAes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $gppAes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                $gppDecryptor = $gppAes.CreateDecryptor()
                $gppPlainBytes = $gppDecryptor.TransformFinalBlock($gppCipherBytes, 0, $gppCipherBytes.Length)
                return [System.Text.Encoding]::Unicode.GetString($gppPlainBytes)
            } finally { $gppAes.Dispose() }
        } catch { return $null }
    }
    $gppRoots = @()
    if (Test-Path -LiteralPath "$env:WINDIR\System32\GroupPolicy\Machine\Preferences") { $gppRoots += "$env:WINDIR\System32\GroupPolicy\Machine\Preferences" }
    if (Test-Path -LiteralPath "$env:WINDIR\System32\GroupPolicy\User\Preferences") { $gppRoots += "$env:WINDIR\System32\GroupPolicy\User\Preferences" }
    if (Test-Path -LiteralPath "$env:ProgramData\Microsoft\Group Policy\History") { $gppRoots += "$env:ProgramData\Microsoft\Group Policy\History" }
    # SYSVOL is only reachable when domain-joined; the local caches above are checked regardless.
    $gppDomainJoined = $false
    try { $gppDomainJoined = [bool](Get-WmiObject Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
    if ($gppDomainJoined -and $env:USERDNSDOMAIN) {
        $gppSysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies"
        if (Test-Path -LiteralPath $gppSysvolPath -ErrorAction SilentlyContinue) { $gppRoots += $gppSysvolPath }
    }
    $gppFound = $false
    if ($gppRoots.Count -gt 0 -and $GPP_PREF_XML_NAMES.Count -gt 0) {
        foreach ($gppXmlName in $GPP_PREF_XML_NAMES) {
            $gppFiles = (Get-ScanFiles -Path $gppRoots -Filter $gppXmlName -MaxFiles 500 -DeadlineSecs 15)
            foreach ($gf in $gppFiles) {
                $gppContent = Get-Content -LiteralPath $gf.FullName -Raw -ErrorAction SilentlyContinue
                if (-not $gppContent) { continue }
                $gppMatches = [regex]::Matches($gppContent, $GPP_CPASSWORD_RE)
                foreach ($gm in $gppMatches) {
                    if ($gm.Groups.Count -lt 2 -or -not $gm.Groups[1].Value) { continue }   # empty cpassword="" — not a real exposure
                    $gppCipherVal = $gm.Groups[1].Value
                    $gppPlain = Get-GppDecryptedPassword $gppCipherVal
                    $gppFound = $true
                    Out-ThreatBanner "GPP CACHED PASSWORD (CPASSWORD)" $gf.FullName
                    $gppDetail = if ($gppPlain) { "decrypted credential present (redacted from console — see report)" } else { "cpassword present but could not be decoded automatically — verify manually" }
                    Add-Finding -ID "GPPCPW_$(Get-StableId "$($gf.FullName)|$gppCipherVal")" -Phase "PHASE 87.5" -ThreatType "GPP Cached Credential" `
                        -Severity $SEV_CRITICAL -Description "Group Policy Preferences file contains a cpassword attribute — $gppDetail. GPP encrypts with a single AES key Microsoft published for ALL domains (MS14-025); any authenticated user can decrypt it. File: $($gf.FullName)$(if ($gppPlain) { " || DECRYPTED VALUE (rotate this credential immediately): $gppPlain" })" `
                        -Target $gf.FullName -FixAction "Info" -Group "GPP Cached Credentials"
                    # No $global:*Hits bucket increment — matches Phase 88's DCSync/Golden Ticket
                    # precedent: AD/credential-access findings don't map cleanly onto the legacy
                    # RAT/Rootkit/Trojan/... risk-score buckets, so they're left uncounted there.
                }
            }
        }
    }
    if (-not $gppFound) { Out-Typewriter "  -> [OK] NO GPP CACHED PASSWORDS FOUND." "GOOD" }

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

    Show-PhaseHeader "PHASE 88.5" "KERBEROASTING / AS-REP ROASTING TRIAGE" "UNIVERSAL"
    # WS8: two independent Kerberos ticket-abuse queries. Computed separately from Phase 88's own
    # 4769 fetch (which filters straight down to krbtgt-only Golden Ticket candidates and
    # discards everything else) so this phase can see the FULL 4769 stream. Domain-joined gate
    # re-checked locally rather than trusting Phase 88's $domain to still be in scope, so this
    # phase stays correct even if the surrounding code is ever reordered.
    $roastDomainJoined = $false
    try { $roastDomainJoined = [bool](Get-WmiObject Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
    if ($roastDomainJoined) {
        Out-Typewriter "CHECKING FOR KERBEROASTING / AS-REP ROASTING BURSTS..." "HUNT"
        # (a) Kerberoasting — Event 4769, RC4 ticket encryption, non-krbtgt SPN, non-computer-account
        # requester. A single RC4 service-ticket request is completely normal (legacy app compat);
        # the actual signal is one account requesting tickets for 3+ DISTINCT SPNs inside a 5-minute
        # rolling window — the burst/distinct-SPN shape of Rubeus/GetUserSPNs, not routine use.
        $roastEvents = New-Object System.Collections.Generic.List[object]
        foreach ($ev in @(Get-WinEventSafe @{LogName='Security'; ID=4769} -MaxEvents 5000)) {
            if (-not (Test-InScope $ev.TimeCreated)) { continue }
            if ($ev.Message -notmatch 'Ticket Encryption Type:\s*0x17') { continue }   # RC4 only
            $svcM = [regex]::Match($ev.Message, '(?m)^\s*Service Name:\s*(\S+)')
            $usrM = [regex]::Match($ev.Message, '(?m)^\s*Account Name:\s*(\S+)')
            if (-not $svcM.Success -or -not $usrM.Success) { continue }
            $rSvc = $svcM.Groups[1].Value.Trim(); $rUsr = $usrM.Groups[1].Value.Trim()
            if (-not $rSvc -or $rSvc -eq '-' -or $rSvc.ToLower() -eq 'krbtgt' -or $rSvc.EndsWith('$')) { continue }   # exclude krbtgt + computer-account SPNs
            if (-not $rUsr -or $rUsr.EndsWith('$')) { continue }   # exclude computer-account requesters (noisy, not user-driven)
            $roastEvents.Add([pscustomobject]@{ User = $rUsr; Svc = $rSvc; Time = $ev.TimeCreated })
        }
        $roastHits = 0
        if ($roastEvents.Count -gt 0) {
            foreach ($rGrp in ($roastEvents | Group-Object User)) {
                $rSorted = @($rGrp.Group | Sort-Object Time)
                $rFlagged = $false
                for ($ri = 0; $ri -lt $rSorted.Count -and -not $rFlagged; $ri++) {
                    $rWindowEnd = $rSorted[$ri].Time.AddMinutes(5)
                    $rInWindow = @($rSorted | Where-Object { $_.Time -ge $rSorted[$ri].Time -and $_.Time -le $rWindowEnd })
                    $rDistinctSpns = @($rInWindow.Svc | Select-Object -Unique)
                    if ($rDistinctSpns.Count -ge 3) {
                        $rFlagged = $true
                        Out-ThreatBanner "POSSIBLE KERBEROASTING" "$($rGrp.Name): $($rDistinctSpns.Count) distinct SPNs in 5min"
                        Add-Finding -ID "KERBEROAST_$(Get-StableId "$($rGrp.Name)|$($rSorted[$ri].Time.Ticks)")" -Phase "PHASE 88.5" `
                            -ThreatType "Kerberoasting" -Severity $SEV_POSSIBLE `
                            -Description "Account '$($rGrp.Name)' requested RC4 service tickets for $($rDistinctSpns.Count) distinct SPNs within a 5-minute window starting $($rSorted[$ri].Time.ToString('yyyy-MM-dd HH:mm:ss')) — SPNs: $($rDistinctSpns -join ', '). Burst/distinct-SPN pattern consistent with a Kerberoasting tool (Rubeus/GetUserSPNs); a normal user does not request many services in this pattern." `
                            -Target "Security EventLog (4769) | $($rGrp.Name)" -FixAction "Info" -Group "Kerberos Ticket Abuse"
                        # No $global:*Hits bucket increment — matches Phase 88's DCSync/Golden
                        # Ticket precedent (AD/credential-access findings aren't bucketed there).
                        $roastHits++
                    }
                }
            }
        }
        # (b) AS-REP Roasting — Event 4768, Kerberos pre-authentication disabled or absent. Each
        # hit is single-event (no burst threshold needed — a preauth-disabled account is a static
        # AD attribute an attacker exploits, not a live burst pattern), so this stays POSSIBLE +
        # Info per-account rather than any auto-actionable severity.
        $asrepHits = 0
        foreach ($ev in @(Get-WinEventSafe @{LogName='Security'; ID=4768} -MaxEvents 5000)) {
            if (-not (Test-InScope $ev.TimeCreated)) { continue }
            $usrM2 = [regex]::Match($ev.Message, '(?m)^\s*Account Name:\s*(\S+)')
            if (-not $usrM2.Success) { continue }
            $aUsr = $usrM2.Groups[1].Value.Trim()
            if (-not $aUsr -or $aUsr -eq '-' -or $aUsr.EndsWith('$')) { continue }   # exclude computer accounts
            $preM = [regex]::Match($ev.Message, '(?m)^\s*Pre-Authentication Type:\s*(\S+)')
            $preAbsentOrZero = (-not $preM.Success) -or ($preM.Groups[1].Value.Trim() -eq '0')
            if (-not $preAbsentOrZero) { continue }
            $asrepHits++
            Out-ThreatBanner "POSSIBLE AS-REP ROASTING" "$aUsr @ $($ev.TimeCreated)"
            Add-Finding -ID "ASREPROAST_$(Get-StableId "$aUsr|$($ev.RecordId)")" -Phase "PHASE 88.5" `
                -ThreatType "AS-REP Roasting" -Severity $SEV_POSSIBLE `
                -Description "AS-REQ for '$aUsr' at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) shows Kerberos pre-authentication $(if ($preM.Success) { 'disabled (Pre-Authentication Type: 0)' } else { 'absent from the event' }) — consistent with an AS-REP Roasting attempt (Rubeus/GetNPUsers-class tooling) OR a legitimately preauth-disabled account. Verify the account's 'Do not require Kerberos preauthentication' setting." `
                -Target "Security EventLog (4768) | $aUsr" -FixAction "Info" -Group "Kerberos Ticket Abuse"
        }
        if ($roastHits -eq 0 -and $asrepHits -eq 0) { Out-Typewriter "  -> [OK] NO KERBEROASTING/AS-REP INDICATORS." "GOOD" }
    } else { Out-Typewriter "  -> NOT DOMAIN-JOINED. KERBEROASTING/AS-REP CHECKS SKIPPED." "INFO" }

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
    # WS0 wiring: externalized to 'stego_tools' (AMSI-safe, same list).
    $stegoTools = $STEGO_TOOLS
    # One bounded walk + anchored regex (was 3 roots x 7 names = 21 recursions incl. whole profile).
    $stegoRegex = ($stegoTools | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
    # P1 multi-user: the roots were $env:TEMP / $env:LOCALAPPDATA / $env:USERPROFILE — the
    # ELEVATED TECHNICIAN's profile — so a stego/exfil tool staged in the VICTIM's profile was
    # never walked. Resolved per profile via Get-UserPaths, with the same PREFIX DE-DUPE the
    # Phase 82 walk uses (Temp and LocalAppData normally nest inside the profile root, so the
    # pre-P1 array walked the same tree three times against a PER-CALL budget; with N profiles
    # that waste would truncate the walk before it reached the later profiles).
    $zbStegoRoots = @()
    foreach ($zbHive in (@(Get-UserHives) | Sort-Object Sid)) {   # SID order -> stable memo key
        if (-not $zbHive.ProfileReachable) { continue }           # never re-probe reachability
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbR in @($zbUp.Profile, $zbUp.Temp, $zbUp.LocalAppData)) {
            if (-not $zbR) { continue }
            $zbRlc = "$zbR".ToLowerInvariant()
            $zbCovered = $false
            foreach ($zbEx in $zbStegoRoots) {
                $zbExLc = "$($zbEx.Root)".ToLowerInvariant()
                if ($zbRlc -eq $zbExLc -or $zbRlc.StartsWith($zbExLc.TrimEnd('\') + '\')) { $zbCovered = $true; break }
            }
            if ($zbCovered) { continue }
            $zbStegoRoots += [pscustomobject]@{ Root = "$zbR"; User = "$($zbHive.User)"; Sid = "$($zbHive.Sid)" }
        }
    }
    # Parens kept — Get-ScanFiles ends `return ,$arr` and a bare pipe would hand the whole array
    # to Where-Object as ONE item (CLAUDE.md).
    $stegoHits = @()
    if ($zbStegoRoots.Count -gt 0) {
        $stegoHits = (Get-ScanFiles -Path @($zbStegoRoots | ForEach-Object { $_.Root })) |
            Where-Object { $_.Name -match $stegoRegex }
    }
    foreach ($hit in $stegoHits) {
        $zbStUser = 'MACHINE'; $zbStSid = 'MACHINE'; $zbStLen = -1
        $zbStLc = "$($hit.FullName)".ToLowerInvariant()
        foreach ($zbR in $zbStegoRoots) {
            $zbRl = "$($zbR.Root)".ToLowerInvariant()
            if ($zbRl.Length -gt $zbStLen -and $zbStLc.StartsWith($zbRl)) {
                $zbStUser = "$($zbR.User)"; $zbStSid = "$($zbR.Sid)"; $zbStLen = $zbRl.Length
            }
        }
        Out-Typewriter "  -> [$zbStUser] STEGO TOOL: $($hit.FullName)" "WARN"
        # ID was the bare filename — one steghide.exe per profile collapsed to a single finding
        # and Add-Finding's de-dupe dropped every victim but the first, on a HIGH + DeleteFile.
        # FixParam stays a bare machine-parseable path.
        Add-Finding -ID "STEGO_$(Get-StableId "$zbStSid|$($hit.FullName)")" -Phase "PHASE 89" -ThreatType "Steganography/Exfil Tool" `
            -Severity $SEV_HIGH -Description "[$zbStUser] Steganography tool found: $($hit.FullName)" `
            -Target "[$zbStUser] $($hit.FullName)" -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Data Exfiltration"
    }
    Out-Typewriter "  -> PHASE 89 COMPLETE." "VER"
}

# ══════════════════════════════════════════════════════════════════════════════
#  ADVANCED PHASES 90-105 (DEEP / PARANOID / STEALTH — V21)
# ══════════════════════════════════════════════════════════════════════════════
