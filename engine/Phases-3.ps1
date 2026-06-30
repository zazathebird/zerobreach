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
    $yaraExt   = @(".exe",".dll",".scr",".ps1",".vbs",".js",".hta",".bat",".cmd",".bin",".htm",".html",".jse",".vbe",".wsf",".svg")
    $yaraHits  = 0
    # Single bounded walk across all roots (was per-root recursion x5, -First 200 each).
    $candidates = Get-ScanFiles -Path $yaraRoots -TimeScoped |
        Where-Object { ($yaraExt -contains $_.Extension.ToLower()) -and $_.Length -lt 10MB } |
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
                # Content-signature pass (HTML smuggling / JS redirector / obfuscated dropper).
                if ($cand.Extension.ToLower() -in @(".htm",".html",".js",".jse",".vbs",".vbe",".hta",".wsf",".svg")) {
                    $cr = Test-ContentRules -FilePath $cand.FullName -Rules $EMAIL_CONTENT_RULES
                    if ($cr.Hit) {
                        Out-Decrypt -Text "$($cr.Name) -> $($cand.FullName)" -Prefix "  [CONTENT HIT] "
                        $fa = if ($cr.Severity -eq $SEV_POSSIBLE) { "Info" } else { "Quarantine" }
                        Add-Finding -ID "CONTENT_$($cr.Name)_$($cand.Name -replace '[^a-z0-9]','')" -Phase "PHASE 90" `
                            -ThreatType "Phishing / Smuggling Content" -Severity $cr.Severity `
                            -Description "Content rule '$($cr.Name)' matched: $($cand.FullName)" `
                            -Target $cand.FullName -FixAction $fa -FixParam $cand.FullName `
                            -Group "Phishing / Smuggling Content"
                        $yaraHits++; $global:TrojanHits++
                    }
                }
                # Built-in known-malware hash list + user-supplied custom IOC hashes.
                if (($KNOWN_MALWARE_HASHES.Count -gt 0 -or $global:CustomIocs.Hashes.Count -gt 0) -and $cand.Length -lt 25MB) {
                    try {
                        $hash = (Get-FileHash -Path $cand.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
                        if (($KNOWN_MALWARE_HASHES -contains $hash) -or ($global:CustomIocs.Hashes -contains $hash)) {
                            Out-Decrypt -Text "IOC hash match: $($cand.FullName)" -Prefix "  [IOC HIT] "
                            Add-Finding -ID "IOC_HASH_$($cand.Name -replace '[^a-z0-9]','')" -Phase "PHASE 90" `
                                -ThreatType "Known-Malware Hash" -Severity $SEV_CRITICAL `
                                -Description "File matches known-malware/IOC hash ($hash): $($cand.FullName)" `
                                -Target $cand.FullName -FixAction "Quarantine" -FixParam $cand.FullName `
                                -Group "Known-Malware Hash Matches"
                            $yaraHits++; $global:TrojanHits++
                        }
                    } catch {}
                }
            } catch {}
        }
    if ($yaraHits -eq 0) { Out-Typewriter "  -> [OK] NO YARA-LITE MATCHES." "GOOD" }

    # ── PHASE 91: MARK-OF-THE-WEB ABUSE ───────────────────────────────────────
    Show-PhaseHeader "PHASE 91" "MARK-OF-THE-WEB (MOTW) ZONE.IDENTIFIER STRIP" "MOTW"
    Out-Typewriter "SCANNING DOWNLOADS FOR MOTW-STRIPPED EXECUTABLES..." "HUNT"
    $motwHits = 0
    foreach ($root in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop")) {
        if (-not (Test-Path $root)) { continue }
        $exes = Get-ScanFiles -Path $root -TimeScoped |
            Where-Object { $_.Extension -match "\.(exe|msi|dll|scr|js|vbs|hta|ps1|bat|lnk|iso|img)$" }
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
                (($_s = Get-AuthSig $_.FileName) -and $_s.Status -ne "Valid")
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
        $sctFiles = Get-ScanFiles -Path $root -TimeScoped |
            Where-Object { $_.Extension -match "\.(sct|wsc|xsl)$" }
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
            $_s = Get-AuthSig $_.FullName
            if ($_s -and $_s.Status -ne "Valid") {
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
        Get-ScanFiles -Path $root -TimeScoped |
            Where-Object { $_.Extension -match "\.(application|manifest|deploy)$" } |
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
    $leakedCerts = $LEAKED_CERT_ISSUERS   # externalized to data (leaked_cert_issuers)
    $stolenHits = 0
    foreach ($root in @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA,"$env:USERPROFILE\Downloads")) {
        if (-not (Test-Path $root)) { continue }
        Get-ScanFiles -Path $root -TimeScoped |
            Where-Object { $_.Extension -match "\.(exe|dll)$" } | Select-Object -First 100 | ForEach-Object {
            $sig = Get-AuthSig $_.FullName
            if ($sig -and $sig.SignerCertificate) {
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
    # One WMI enumeration + name lookup instead of one filtered Get-WmiObject per
    # LOLBAS name. Map name -> original token so the finding ID keeps the $lb tag.
    $lolbasSet = @{}; foreach ($lb in $LOLBAS_EXPANDED) { $lolbasSet["$lb.exe"] = $lb }
    if ($lolbasSet.Count -gt 0) {
        foreach ($p in (Get-WmiObject Win32_Process -ErrorAction SilentlyContinue)) {
            $lb = $lolbasSet[$p.Name]
            if (-not $lb) { continue }
            if ($p.CommandLine -match "http|https|ftp|AppData|Temp|Base64|EncodedCommand|IEX|DownloadString|/i:|scrobj|Net\.WebClient") {
                $cmdShort = $p.CommandLine.Substring(0,[Math]::Min(140,$p.CommandLine.Length))
                Add-Finding -ID "LOLBAS_$($p.ProcessId)_$lb" -Phase "PHASE 99" -ThreatType "LOLBAS Abuse" `
                    -Severity $SEV_HIGH -Description "LOLBAS abuse: $($p.Name) PID:$($p.ProcessId) | $cmdShort" `
                    -Target "PID:$($p.ProcessId)" -FixAction "KillProcess" -FixParam $p.ProcessId -Group "LOLBAS Expanded"
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
        Get-ScanFiles -Path $root -TimeScoped |
            Where-Object { ($_.Extension -match "\.(zip|7z|rar|iso|img)$") -and $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Length -gt 1024 } |
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
    $dumpTools = $CRED_DUMP_TOOLS   # externalized to data (cred_dump_tools)
    # One bounded walk + anchored regex (was 3 roots x 8 names = 24 recursions incl. whole profile).
    $dumpRegex = ($dumpTools | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
    $dumpHits = Get-ScanFiles -Path @($env:TEMP,$env:LOCALAPPDATA,$env:USERPROFILE) | Where-Object { $_.Name -match $dumpRegex }
    foreach ($hit in $dumpHits) {
        Out-ThreatBanner "MEMORY DUMPER TOOL" $hit.FullName
        Add-Finding -ID "DUMPTOOL_$($hit.Name -replace '[^a-z0-9]','')" -Phase "PHASE 106" -ThreatType "Credential Dumping Tool" `
            -Severity $SEV_CRITICAL -Description "Memory/credential dumping tool found: $($hit.FullName)" `
            -Target $hit.FullName -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Memory Dump Artifacts"
        $global:TrojanHits++; $dumpFound = $true
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
#  FORENSIC PERMISSION & INTEGRITY AUDIT — PHASES 108-115 (DEEP/PARANOID/STEALTH)
#  "What got changed that never should have." ACLs, ownership, code signatures,
#  service & PATH privilege-escalation surface, and security-control tamper.
# ══════════════════════════════════════════════════════════════════════════════
if ($PhasePlan.Integrity) {
    if (-not $global:STEALTH_MODE) {
        Write-Host ""
        Write-Host ("▓"*80) -ForegroundColor DarkGreen
        Write-Host "    ◈  P E R M I S S I O N   &   I N T E G R I T Y   A U D I T  —  1 0 8 - 1 1 5" -ForegroundColor Green
        Write-Host ("▓"*80) -ForegroundColor DarkGreen
        Invoke-QuantumBar "ENGAGING FORENSIC INTEGRITY MODULE" 18 90
    }

    $WEAK_IDS       = Get-Perm 'weak_write_identities'
    $TRUSTED_OWNERS = Get-Perm 'trusted_file_owners'

    # ── PHASE 108: COMPREHENSIVE NTFS ACL & OWNERSHIP AUDIT ───────────────────
    Show-PhaseHeader "PHASE 108" "NTFS ACL & OWNERSHIP INTEGRITY (CRITICAL PATHS)" "PERMISSIONS"
    Out-Typewriter "AUDITING ACLs ON SYSTEM PATHS FOR WEAK / WORLD-WRITABLE ACES..." "HUNT"
    $aclPaths = @(Get-Perm 'critical_acl_paths' | ForEach-Object { Expand-EnvPath $_ }) | Where-Object { $_ } | Select-Object -Unique
    $aclFindings = 0
    foreach ($cp in $aclPaths) {
        if (-not (Test-Path -LiteralPath $cp)) { continue }
        Out-Typewriter "  ACL: $cp" "INFO"
        try {
            $acl  = Get-Acl -LiteralPath $cp -ErrorAction SilentlyContinue
            $weak = Get-WeakAces -Acl $acl -WeakIds $WEAK_IDS
            foreach ($ace in $weak) {
                $aclFindings++
                $idr = "$($ace.IdentityReference)"
                Out-Glitch "  [WEAK ACL] $cp <- $idr : $($ace.FileSystemRights)" Red
                Add-Finding -ID "ACL108_$([Math]::Abs(("$cp$idr").GetHashCode()))" -Phase "PHASE 108" -ThreatType "Permission Abuse / Privesc" `
                    -Severity $SEV_HIGH -Description "Weak ACE on protected path: '$idr' has '$($ace.FileSystemRights)' on $cp (privilege-escalation surface — a non-admin can replace SYSTEM-run files here)." `
                    -Target $cp -FixAction "RunCmd" -FixParam "icacls `"$cp`" /reset /T /C /Q" -Group "NTFS Permission Abuse"
            }
        } catch { Out-Typewriter "  -> ACL READ FAILED: $cp" "WARN" }
    }
    # Ownership of protected binaries — anything not owned by TrustedInstaller/SYSTEM/Admins = tamper
    foreach ($pf in @(Get-Perm 'protected_system_files' | ForEach-Object { Expand-EnvPath $_ })) {
        if (-not (Test-Path -LiteralPath $pf)) { continue }
        try {
            $o = (Get-Acl -LiteralPath $pf -ErrorAction SilentlyContinue).Owner
            if ($o -and (($TRUSTED_OWNERS | Where-Object { $o -like "*$_*" }).Count -eq 0)) {
                $aclFindings++
                Out-Glitch "  [OWNER TAMPER] $pf owned by $o" Red
                Add-Finding -ID "OWN108_$([Math]::Abs($pf.GetHashCode()))" -Phase "PHASE 108" -ThreatType "Ownership Tamper / Privesc" `
                    -Severity $SEV_CRITICAL -Description "Protected system file owned by untrusted principal '$o': $pf (ownership change is a common pre-replacement tamper step)." `
                    -Target $pf -FixAction "RunCmd" -FixParam "takeown /F `"$pf`" /A | Out-Null; icacls `"$pf`" /setowner `"NT SERVICE\TrustedInstaller`" /C /Q" -Group "Ownership Tampering"
            }
        } catch {}
    }
    if ($aclFindings -eq 0) { Out-Typewriter "  -> [OK] NO WEAK ACLs OR OWNERSHIP TAMPER ON CRITICAL PATHS." "GOOD" }

    # ── PHASE 109: SYSTEM BINARY INTEGRITY & CODE-SIGNATURE VERIFICATION ───────
    Show-PhaseHeader "PHASE 109" "SYSTEM BINARY INTEGRITY & SIGNATURE VERIFICATION" "INTEGRITY"
    Out-Typewriter "VERIFYING AUTHENTICODE / CATALOG SIGNATURES ON PROTECTED BINARIES..." "HUNT"
    Invoke-QuantumBar "CRYPTOGRAPHIC SIGNATURE CHECK" 14 100
    $sigBad = 0
    foreach ($pf in @(Get-Perm 'protected_system_files' | ForEach-Object { Expand-EnvPath $_ })) {
        if (-not (Test-Path -LiteralPath $pf)) { continue }
        $v = Get-SignatureVerdict -FilePath $pf
        # A core OS binary that is unsigned/invalid, OR a Microsoft-named file not signed by a trusted publisher = tamper.
        if ($v.Status -ne 'Valid') {
            $sigBad++
            Out-Glitch "  [INTEGRITY FAIL] $pf — signature: $($v.Status)" Red
            Add-Finding -ID "SIG109_$([Math]::Abs($pf.GetHashCode()))" -Phase "PHASE 109" -ThreatType "Binary Tamper / Integrity" `
                -Severity $SEV_CRITICAL -Description "Protected system binary failed signature check (Status=$($v.Status), Signer='$($v.Signer)'): $pf — possible replacement/patch. Verify with: sfc /scannow" `
                -Target $pf -FixAction "Info" -Group "System Binary Integrity"
        } elseif (-not $v.Trusted) {
            $sigBad++
            Out-Typewriter "  -> UNTRUSTED SIGNER on $pf : $($v.Signer)" "WARN"
            Add-Finding -ID "SIG109U_$([Math]::Abs($pf.GetHashCode()))" -Phase "PHASE 109" -ThreatType "Binary Tamper / Integrity" `
                -Severity $SEV_HIGH -Description "System binary signed by a non-trusted publisher '$($v.Signer)': $pf (expected Microsoft). Possible substitution." `
                -Target $pf -FixAction "Info" -Group "System Binary Integrity"
        }
    }
    if ($sigBad -gt 0) {
        Add-Finding -ID "SFC109" -Phase "PHASE 109" -ThreatType "Integrity Remediation" -Severity $SEV_HIGH `
            -Description "$sigBad protected binaries failed integrity verification — run System File Checker to restore originals from the component store." `
            -Target "System File Checker" -FixAction "RunCmd" -FixParam "sfc /scannow" -Group "System Binary Integrity"
        Out-Typewriter "  -> $sigBad BINARY INTEGRITY FAILURES — SFC RECOMMENDED." "CRIT"
    } else { Out-Typewriter "  -> [OK] ALL PROTECTED BINARIES VALIDLY SIGNED BY TRUSTED PUBLISHERS." "GOOD" }

    # Accessibility-binary backdoor cross-check (sethc/utilman replaced or IFEO-debugged)
    foreach ($ab in @(Get-Perm 'accessibility_binaries')) {
        $abPath = Expand-EnvPath "%WINDIR%\System32\$ab"
        if (Test-Path -LiteralPath $abPath) {
            $v = Get-SignatureVerdict -FilePath $abPath
            if ($v.Status -ne 'Valid' -or -not $v.IsMs) {
                Out-ThreatBanner "ACCESSIBILITY BACKDOOR SUSPECT" "$ab signature=$($v.Status)"
                Add-Finding -ID "ACCESS109_$ab" -Phase "PHASE 109" -ThreatType "Accessibility Backdoor" `
                    -Severity $SEV_CRITICAL -Description "Accessibility binary $ab is not a valid Microsoft signed file (Status=$($v.Status)) — classic logon-screen SYSTEM backdoor. Restore with sfc /scannow." `
                    -Target $abPath -FixAction "RunCmd" -FixParam "sfc /scannow" -Group "Accessibility Backdoors"
            }
        }
        $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$ab"
        if (Test-Path -LiteralPath $ifeo) {
            $dbg = (Get-ItemProperty -LiteralPath $ifeo -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($dbg) {
                Out-ThreatBanner "ACCESSIBILITY IFEO HIJACK" "$ab -> $dbg"
                Add-Finding -ID "IFEO109_$ab" -Phase "PHASE 109" -ThreatType "Accessibility Backdoor / IFEO" `
                    -Severity $SEV_CRITICAL -Description "IFEO Debugger set on accessibility binary $ab -> '$dbg' (logon-screen backdoor)." `
                    -Target $ifeo -FixAction "RunCmd" -FixParam "Remove-ItemProperty -LiteralPath '$ifeo' -Name Debugger -Force -ErrorAction SilentlyContinue" -Group "Accessibility Backdoors"
            }
        }
    }

    # ── PHASE 110: REGISTRY KEY ACL / WEAK-PERMISSION AUDIT ───────────────────
    Show-PhaseHeader "PHASE 110" "REGISTRY KEY ACL / WEAK-PERMISSION AUDIT" "PERMISSIONS"
    Out-Typewriter "AUDITING PERSISTENCE-KEY ACLs FOR NON-ADMIN WRITE ACCESS..." "HUNT"
    $regAcl = 0
    foreach ($rk in @(Get-Perm 'critical_reg_acl_keys')) {
        if (-not (Test-Path -LiteralPath $rk)) { continue }
        try {
            $racl = Get-Acl -LiteralPath $rk -ErrorAction SilentlyContinue
            $weak = Get-WeakAces -Acl $racl -WeakIds $WEAK_IDS
            foreach ($ace in $weak) {
                $idr = "$($ace.IdentityReference)"
                $regAcl++
                Out-Glitch "  [WEAK REG ACL] $rk <- $idr : $($ace.RegistryRights)" Red
                Add-Finding -ID "REGACL110_$([Math]::Abs(("$rk$idr").GetHashCode()))" -Phase "PHASE 110" -ThreatType "Registry Permission Abuse" `
                    -Severity $SEV_HIGH -Description "Persistence/privesc registry key writable by '$idr' ($($ace.RegistryRights)): $rk — non-admins can plant autostart entries." `
                    -Target $rk -FixAction "Info" -Group "Registry Permission Abuse"
            }
        } catch {}
    }
    if ($regAcl -eq 0) { Out-Typewriter "  -> [OK] NO WEAK ACLs ON PERSISTENCE REGISTRY KEYS." "GOOD" }

    # ── PHASE 111: SERVICE PRIVILEGE-ESCALATION AUDIT ─────────────────────────
    Show-PhaseHeader "PHASE 111" "SERVICE PRIVESC — UNQUOTED PATHS & WRITABLE BINARIES" "PRIVESC"
    Out-Typewriter "INSPECTING SERVICE IMAGE PATHS FOR PRIVILEGE-ESCALATION FLAWS..." "HUNT"
    Invoke-QuantumBar "SERVICE BINARY ACL ANALYSIS" 12 110
    $svcPriv = 0
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        $ip = "$($svc.PathName)".Trim()
        if (-not $ip) { continue }
        # Extract the executable path (strip quotes + trailing args)
        $exe = $null
        if ($ip -match '^\s*"([^"]+)"') { $exe = $matches[1] }
        elseif ($ip -match '^\s*([^\s]+\.exe)') { $exe = $matches[1] }
        else { $exe = ($ip -split '\s+')[0] }
        # Unquoted path with a space outside System32 = classic privesc
        if ($ip -notmatch '^\s*"' -and $ip -match '\s' -and $ip -match '\\' -and $ip -notmatch '^[A-Za-z]:\\Windows\\(System32|SysWOW64)\\') {
            $svcPriv++
            Out-Typewriter "  -> UNQUOTED SERVICE PATH: $($svc.Name) = $ip" "WARN"
            Add-Finding -ID "SVCUQ111_$($svc.Name)" -Phase "PHASE 111" -ThreatType "Unquoted Service Path / Privesc" `
                -Severity $SEV_HIGH -Description "Service '$($svc.Name)' ($($svc.DisplayName)) has an unquoted ImagePath with spaces: $ip — exploitable for privilege escalation via planted binary." `
                -Target "Service: $($svc.Name)" -FixAction "Info" -Group "Service Privilege Escalation"
        }
        # Writable service binary OR its directory = an unprivileged user can swap the SYSTEM binary
        if ($exe -and (Test-Path -LiteralPath $exe)) {
            try {
                $sacl = Get-Acl -LiteralPath $exe -ErrorAction SilentlyContinue
                $weak = Get-WeakAces -Acl $sacl -WeakIds $WEAK_IDS
                if ($weak.Count -gt 0) {
                    $svcPriv++
                    $idr = "$($weak[0].IdentityReference)"
                    Out-ThreatBanner "WRITABLE SERVICE BINARY (PRIVESC)" "$($svc.Name): $exe"
                    Add-Finding -ID "SVCBIN111_$($svc.Name)" -Phase "PHASE 111" -ThreatType "Writable Service Binary / Privesc" `
                        -Severity $SEV_CRITICAL -Description "Service '$($svc.Name)' runs '$exe' which is writable by '$idr' — a non-admin can replace it to gain $($svc.StartName) privileges." `
                        -Target $exe -FixAction "RunCmd" -FixParam "icacls `"$exe`" /reset /C /Q" -Group "Service Privilege Escalation"
                }
            } catch {}
        }
    }
    if ($svcPriv -eq 0) { Out-Typewriter "  -> [OK] NO SERVICE PRIVILEGE-ESCALATION FLAWS FOUND." "GOOD" }

    # ── PHASE 112: PATH & DLL-HIJACK SURFACE (WRITABLE DIRECTORIES) ────────────
    Show-PhaseHeader "PHASE 112" "PATH / DLL-HIJACK SURFACE — WRITABLE DIRECTORIES" "PRIVESC"
    Out-Typewriter "CHECKING SYSTEM PATH DIRECTORIES FOR NON-ADMIN WRITE ACCESS..." "HUNT"
    $pathDirs = @()
    try { $pathDirs += ([Environment]::GetEnvironmentVariable('Path','Machine') -split ';') } catch {}
    $pathDirs += @(Get-Perm 'system_path_extra_dirs' | ForEach-Object { Expand-EnvPath $_ })
    $pathDirs = $pathDirs | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim().TrimEnd('\') } | Select-Object -Unique
    $pathHits = 0
    foreach ($pd in $pathDirs) {
        if (-not (Test-Path -LiteralPath $pd)) { continue }
        try {
            $dacl = Get-Acl -LiteralPath $pd -ErrorAction SilentlyContinue
            $weak = Get-WeakAces -Acl $dacl -WeakIds $WEAK_IDS
            if ($weak.Count -gt 0) {
                $pathHits++
                $idr = "$($weak[0].IdentityReference)"
                Out-Glitch "  [WRITABLE PATH DIR] $pd <- $idr" Red
                Add-Finding -ID "PATH112_$([Math]::Abs($pd.GetHashCode()))" -Phase "PHASE 112" -ThreatType "DLL Hijack / PATH Privesc" `
                    -Severity $SEV_HIGH -Description "Directory on the system PATH is writable by '$idr': $pd — enables DLL/binary planting that elevated processes will load." `
                    -Target $pd -FixAction "RunCmd" -FixParam "icacls `"$pd`" /remove:g `"*S-1-1-0`" `"*S-1-5-11`" `"*S-1-5-32-545`" /C /Q" -Group "DLL Hijack Surface"
            }
        } catch {}
    }
    if ($pathHits -eq 0) { Out-Typewriter "  -> [OK] NO WRITABLE DIRECTORIES ON SYSTEM PATH." "GOOD" }

    # ── PHASE 113: RECENTLY MODIFIED PROTECTED SYSTEM FILES ───────────────────
    Show-PhaseHeader "PHASE 113" "RECENTLY MODIFIED / UNSIGNED FILES IN SYSTEM32 & DRIVERS" "INTEGRITY"
    Out-Typewriter "HUNTING FOR FILES CHANGED IN-WINDOW OR UNSIGNED IN PROTECTED DIRS..." "HUNT"
    Invoke-QuantumBar "SYSTEM DIRECTORY DELTA SCAN" 16 90
    $recentSys = 0
    $sysDirs = @((Expand-EnvPath "%WINDIR%\System32"), (Expand-EnvPath "%WINDIR%\System32\drivers"))
    foreach ($sd in $sysDirs) {
        if (-not (Test-Path -LiteralPath $sd)) { continue }
        $cands = Get-ChildItem -LiteralPath $sd -File -ErrorAction SilentlyContinue |
            Where-Object { ($_.Extension -match '\.(exe|dll|sys)$') -and (Test-InScope $_.LastWriteTime) } |
            Select-Object -First 400
        foreach ($f in $cands) {
            $v = Get-SignatureVerdict -FilePath $f.FullName
            if ($v.Status -ne 'Valid') {
                $recentSys++
                $sev = if ($f.Extension -match 'sys') { $SEV_CRITICAL } else { $SEV_HIGH }
                Out-Typewriter "  -> CHANGED+UNVERIFIED: $($f.FullName) [$($v.Status)] $($f.LastWriteTime)" "CRIT"
                Add-Finding -ID "RECSYS113_$([Math]::Abs($f.FullName.GetHashCode()))" -Phase "PHASE 113" -ThreatType "System File Tamper" `
                    -Severity $sev -Description "Recently-modified protected-directory file with failed signature ($($v.Status)): $($f.FullName) (modified $($f.LastWriteTime)). Driver/binary drop indicator." `
                    -Target $f.FullName -FixAction "Info" -Group "System File Tamper" }
        }
    }
    if ($recentSys -eq 0) { Out-Typewriter "  -> [OK] NO CHANGED/UNSIGNED FILES IN PROTECTED DIRS (IN WINDOW)." "GOOD" }

    # ── PHASE 114: SECURITY CONTROL HEALTH & TAMPER CONSOLIDATION ──────────────
    Show-PhaseHeader "PHASE 114" "SECURITY CONTROL HEALTH & TAMPER CONSOLIDATION" "DEFENSE"
    Out-Typewriter "VERIFYING AV / FIREWALL / LOGGING CONTROLS ARE INTACT..." "HUNT"
    $ctrlBad = 0
    foreach ($es in @(Get-Perm 'expected_running_services')) {
        $s = Get-Service -Name $es.name -ErrorAction SilentlyContinue
        if ($null -eq $s) { continue }   # not installed (e.g. Sysmon/Sense) — skip
        if ($s.Status -ne 'Running') {
            $ctrlBad++
            $sev = switch ($es.severity) { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } "POSSIBLE" { $SEV_POSSIBLE } default { $SEV_INFO } }
            Out-Typewriter "  -> SECURITY SERVICE NOT RUNNING: $($es.display) [$($s.Status)]" "WARN"
            Add-Finding -ID "CTRL114_$($es.name)" -Phase "PHASE 114" -ThreatType "Security Control Tamper" `
                -Severity $sev -Description "Security service '$($es.display)' ($($es.name)) is $($s.Status) — disabling AV/firewall/logging is a hallmark post-compromise action." `
                -Target "Service: $($es.name)" -FixAction "RunCmd" -FixParam "Set-Service -Name '$($es.name)' -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name '$($es.name)' -ErrorAction SilentlyContinue" -Group "Security Control Tamper"
        }
    }
    foreach ($dv in @(Get-Perm 'defender_tamper_values')) {
        if (Test-Path -LiteralPath $dv.key) {
            $cur = (Get-ItemProperty -LiteralPath $dv.key -Name $dv.name -ErrorAction SilentlyContinue).$($dv.name)
            if ($null -ne $cur -and [int]$cur -eq [int]$dv.bad) {
                $ctrlBad++
                Out-ThreatBanner "DEFENDER TAMPER" $dv.desc
                Add-Finding -ID "DEFTAMP114_$($dv.name)" -Phase "PHASE 114" -ThreatType "Defender Tamper" `
                    -Severity $SEV_CRITICAL -Description "$($dv.desc): $($dv.key)\$($dv.name) = $cur." `
                    -Target "$($dv.key)\$($dv.name)" -FixAction "RunCmd" -FixParam "Remove-ItemProperty -LiteralPath '$($dv.key)' -Name '$($dv.name)' -Force -ErrorAction SilentlyContinue" -Group "Security Control Tamper"
            }
        }
    }
    # Live Defender status (best-effort; cmdlet absent on some SKUs)
    try {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp) {
            if (-not $mp.RealTimeProtectionEnabled) {
                $ctrlBad++
                Add-Finding -ID "MP114_RTP" -Phase "PHASE 114" -ThreatType "Defender Tamper" -Severity $SEV_CRITICAL `
                    -Description "Defender real-time protection is OFF (Get-MpComputerStatus.RealTimeProtectionEnabled=False)." `
                    -Target "Defender Real-Time Protection" -FixAction "RunCmd" -FixParam "Set-MpPreference -DisableRealtimeMonitoring `$false -ErrorAction SilentlyContinue" -Group "Security Control Tamper"
            }
            if ($mp.AntivirusSignatureAge -gt 7) {
                Add-Finding -ID "MP114_SIGAGE" -Phase "PHASE 114" -ThreatType "Defender Health" -Severity $SEV_POSSIBLE `
                    -Description "Defender signatures are $($mp.AntivirusSignatureAge) days old — update before trusting AV verdicts." `
                    -Target "Defender Signatures" -FixAction "RunCmd" -FixParam "Update-MpSignature -ErrorAction SilentlyContinue" -Group "Security Control Tamper"
            }
        }
    } catch {}
    if ($ctrlBad -eq 0) { Out-Typewriter "  -> [OK] SECURITY CONTROLS INTACT AND RUNNING." "GOOD" }

    # ── PHASE 115: AUTORUN TARGET WRITABLE-PATH AUDIT (HIJACKABLE PERSISTENCE) ──
    Show-PhaseHeader "PHASE 115" "AUTORUN TARGET WRITABLE-PATH AUDIT (HIJACKABLE PERSISTENCE)" "PRIVESC"
    Out-Typewriter "CHECKING WHETHER AUTORUN TARGETS CAN BE OVERWRITTEN BY NON-ADMINS..." "HUNT"
    $autoHits = 0
    $autoKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($ak in $autoKeys) {
        if (-not (Test-Path -LiteralPath $ak)) { continue }
        $vals = Get-ItemProperty -LiteralPath $ak -ErrorAction SilentlyContinue
        foreach ($p in ($vals.psobject.properties | Where-Object { $_.Name -notmatch '^PS' })) {
            $cmd = [string]$p.Value
            $texe = $null
            if ($cmd -match '"([^"]+\.exe)"') { $texe = $matches[1] }
            elseif ($cmd -match '([A-Za-z]:\\[^,\s]+\.exe)') { $texe = $matches[1] }
            if ($texe -and (Test-Path -LiteralPath $texe)) {
                try {
                    $tacl = Get-Acl -LiteralPath $texe -ErrorAction SilentlyContinue
                    $weak = Get-WeakAces -Acl $tacl -WeakIds $WEAK_IDS
                    if ($weak.Count -gt 0) {
                        $autoHits++
                        $idr = "$($weak[0].IdentityReference)"
                        Out-ThreatBanner "HIJACKABLE AUTORUN TARGET" "$($p.Name): $texe"
                        Add-Finding -ID "AUTO115_$([Math]::Abs(("$ak$($p.Name)").GetHashCode()))" -Phase "PHASE 115" -ThreatType "Hijackable Autorun / Privesc" `
                            -Severity $SEV_HIGH -Description "HKLM autorun '$($p.Name)' runs '$texe' which is writable by '$idr' — a non-admin can replace it to run code at every boot/logon as the next user." `
                            -Target $texe -FixAction "RunCmd" -FixParam "icacls `"$texe`" /reset /C /Q" -Group "Hijackable Autoruns"
                    }
                } catch {}
            }
        }
    }
    if ($autoHits -eq 0) { Out-Typewriter "  -> [OK] NO HIJACKABLE AUTORUN TARGETS." "GOOD" }
    Out-Typewriter "  -> PERMISSION & INTEGRITY AUDIT COMPLETE (PHASES 108-115)." "VER"
}

