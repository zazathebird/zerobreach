# NOTE - Detection vocabulary in this file is deliberate.
# Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
# named malware families, are detection category labels, operator-facing report text, or
# MITRE ATT&CK tactic names (a published standard). ZeroBreach is a defensive incident-
# response tool; these strings are what it reports, not what it does. See CLAUDE.md,
# "The detection vocabulary is deliberate". Do not sanitise them.

trap { Write-RecoveredError $_; continue }   # module-level resilience: a terminating error resumes at the NEXT phase in THIS module, not the next dot-sourced module (see CLAUDE.md engine-split rule)

# ══════════════════════════════════════════════════════════════════════════════
#  EXTENDED THREAT BAND — PHASES 116-133  (DEEP / PARANOID / STEALTH only)
#
#  Two themes, both requested as WS6:
#    (a) MORE MALWARE FORMS — clipboard clippers, web shells, wipers, packed-script
#        droppers, chat/paste-site C2, exfil staging, unauthorised remote-access.
#    (b) THE FILES AND APPS THAT ACTUALLY GET MODIFIED — browser policy/preferences,
#        native-messaging hosts, shortcuts, sideloaded DLLs, Electron app cores,
#        Office add-ins/templates, installed-app binaries, and the execution
#        evidence (BAM/UserAssist/MuiCache/RunMRU) that proves something ran.
#
#  POSTURE (CLAUDE.md rule #1). This band ships **FixAction "Info"** by default, exactly
#  as the WS2 expansion did: it is new detection surface that has never seen a live FP
#  round, so nothing here may be auto-selected for a destructive fix. Three deliberate
#  exceptions, each an artifact that CANNOT exist benignly and whose removal restores
#  stock behaviour:
#     * Phase 118 — a .lnk carrying encoded PowerShell / a hidden downloader -> Quarantine
#                   (reversible: reports\quarantine\ + a .quar.json restore manifest)
#     * Phase 121 — the "Office test\Special\Perf" key                        -> DeleteRegKey
#     * Phase 130 — a chat-webhook exfil URL inside a chat client's own module -> Quarantine
#  AppCertDlls (Phase 126) is deliberately NOT one of them: it lives under
#  SYSTEM\CurrentControlSet\Control, which the guard refuses, and shipping a CRITICAL
#  finding that is always reported `blocked` is the exact anti-pattern audit M1 closed.
#
#  All literals live in data/detection_signatures.json (AMSI rule); this file carries
#  none. Allowlists come through Join-AllowRegex, so a missing key becomes '(?!)' and
#  can never blind a phase.
# ══════════════════════════════════════════════════════════════════════════════
if ($PhasePlan.Extended) {
    trap { Write-RecoveredError $_; continue }   # localize faults: resume at next phase, not end-of-group
    if (-not $global:STEALTH_MODE) {
        Write-Host ""
        Write-Host ("▓"*80) -ForegroundColor DarkCyan
        Write-Host "    ◈  E X T E N D E D   M A L W A R E   &   T A M P E R  —  1 1 6 - 1 3 3" -ForegroundColor Cyan
        Write-Host ("▓"*80) -ForegroundColor DarkCyan
        Invoke-QuantumBar "ENGAGING EXTENDED DETECTION MODULE" 20 90
    }

    # ── PHASE 116: BROWSER POLICY & PREFERENCE TAMPER ─────────────────────────
    Show-PhaseHeader "PHASE 116" "BROWSER POLICY & PREFERENCE TAMPER (FORCED EXTENSIONS / SEARCH HIJACK)" "BROWSER"
    Out-Typewriter "AUDITING BROWSER POLICY KEYS, PREFERENCES AND PROFILE OVERRIDES..." "HUNT"
    $polHits = 0
    foreach ($bp in @($BROWSER_POLICY_KEYS)) {
        if (-not (Test-Path -LiteralPath $bp.key)) { continue }
        $bsev = switch ("$($bp.severity)") { "HIGH" { $SEV_HIGH } "CRITICAL" { $SEV_CRITICAL } default { $SEV_POSSIBLE } }
        if ("$($bp.kind)" -eq 'forcelist') {
            $fl = Get-ItemProperty -LiteralPath $bp.key -ErrorAction SilentlyContinue
            if ($null -eq $fl) { continue }
            foreach ($fv in ($fl.psobject.properties | Where-Object { $_.Name -notmatch '^PS' })) {
                $polHits++
                Out-Typewriter "  -> POLICY-FORCED BROWSER ITEM: $($bp.browser) [$($fv.Name)] = $($fv.Value)" "WARN"
                Add-Finding -ID "BPOL116_$([Math]::Abs(("$($bp.key)$($fv.Name)").GetHashCode()))" -Phase "PHASE 116" `
                    -ThreatType "Browser Hijack / Adware" -Severity $bsev `
                    -Description "$($bp.browser) policy '$(Split-Path -Leaf $bp.key)' force-installs '$($fv.Value)'. A policy-forced extension or startup URL cannot be removed by the user, which is why adware and search hijackers use it — but a managed fleet sets these deliberately, so confirm with whoever owns the GPO/Intune policy before removing. Manual: Remove-ItemProperty -LiteralPath '$($bp.key)' -Name '$($fv.Name)'" `
                    -Target "$($bp.key)\$($fv.Name)" -FixAction "Info" -Group "Browser Policy Tamper"
            }
        } else {
            $pv = Get-RegVal -Path $bp.key -Name "$($bp.name)"
            if ($null -ne $pv -and "$pv".Trim()) {
                $polHits++
                Out-Typewriter "  -> BROWSER POLICY OVERRIDE: $($bp.browser) $($bp.name) = $pv" "WARN"
                Add-Finding -ID "BPOLV116_$([Math]::Abs(("$($bp.key)$($bp.name)").GetHashCode()))" -Phase "PHASE 116" `
                    -ThreatType "Browser Hijack / Adware" -Severity $bsev `
                    -Description "$($bp.browser) policy sets $($bp.name) = '$pv' — homepage/search-provider overrides delivered by policy are the persistent form of a browser hijack. Confirm it is your own management policy. Manual: Remove-ItemProperty -LiteralPath '$($bp.key)' -Name '$($bp.name)'" `
                    -Target "$($bp.key)\$($bp.name)" -FixAction "Info" -Group "Browser Policy Tamper"
            }
        }
    }
    foreach ($bd in @($BROWSER_POLICY_DISABLE)) {
        if (-not (Test-Path -LiteralPath $bd.key)) { continue }
        $dv = Get-RegVal -Path $bd.key -Name "$($bd.name)"
        if ($null -ne $dv -and [string]"$dv" -match '^\d+$' -and [int]$dv -eq [int]$bd.bad) {
            $polHits++
            Out-ThreatBanner "BROWSER PROTECTION DISABLED" "$($bd.desc)"
            Add-Finding -ID "BSAFE116_$([Math]::Abs(("$($bd.key)$($bd.name)").GetHashCode()))" -Phase "PHASE 116" `
                -ThreatType "Security Control Tamper" -Severity $SEV_HIGH `
                -Description "$($bd.desc) ($($bd.key)\$($bd.name) = $dv). Turning off Safe Browsing / SmartScreen is a standard step in an adware or fake-update install chain. Manual: Set-ItemProperty -LiteralPath '$($bd.key)' -Name '$($bd.name)' -Value 1" `
                -Target "$($bd.key)\$($bd.name)" -FixAction "Info" -Group "Browser Policy Tamper"
        }
    }
    # Chromium profile Preferences / Secure Preferences + Firefox policies.json / user.js
    $chromiumUserData = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
        "$env:LOCALAPPDATA\Vivaldi\User Data",
        "$env:APPDATA\Opera Software\Opera Stable"
    )
    foreach ($cud in $chromiumUserData) {
        if (-not (Test-Path -LiteralPath $cud)) { continue }
        $profDirs = @(Get-ChildItem -LiteralPath $cud -Directory -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } | Select-Object -First 8)
        foreach ($pd in $profDirs) {
            foreach ($pf in @('Preferences','Secure Preferences')) {
                $pfp = Join-Path $pd.FullName $pf
                if (-not (Test-Path -LiteralPath $pfp)) { continue }
                $pr = Test-ContentRules -FilePath $pfp -Rules $BROWSER_PREF_RULES
                if ($pr.Hit) {
                    $polHits++
                    $psev = switch ("$($pr.Severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
                    Out-Typewriter "  -> BROWSER PREFERENCE ANOMALY [$($pr.Name)]: $pfp" "WARN"
                    Add-Finding -ID "BPREF116_$([Math]::Abs("$pfp$($pr.Name)".GetHashCode()))" -Phase "PHASE 116" `
                        -ThreatType "Browser Hijack / Adware" -Severity $psev `
                        -Description "Chromium profile rule '$($pr.Name)' matched in $pfp — sideloaded extensions and startup/search overrides live in this file. Review the profile's extensions in the browser UI (chrome://extensions, edge://extensions)." `
                        -Target $pfp -FixAction "Info" -Group "Browser Preference Tamper"
                }
            }
        }
    }
    $ffTargets = @()
    foreach ($ffr in @("$env:PROGRAMFILES\Mozilla Firefox\distribution\policies.json",
                       "${env:PROGRAMFILES(X86)}\Mozilla Firefox\distribution\policies.json",
                       "$env:PROGRAMDATA\Mozilla\ManagedStorage")) {
        if ($ffr -and (Test-Path -LiteralPath $ffr)) { $ffTargets += $ffr }
    }
    $ffProfRoot = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path -LiteralPath $ffProfRoot) {
        foreach ($fp in @(Get-ChildItem -LiteralPath $ffProfRoot -Directory -ErrorAction SilentlyContinue | Select-Object -First 8)) {
            foreach ($fn in @('user.js','prefs.js')) {
                $fpp = Join-Path $fp.FullName $fn
                if (Test-Path -LiteralPath $fpp) { $ffTargets += $fpp }
            }
        }
    }
    foreach ($ft in $ffTargets) {
        $fr = Test-ContentRules -FilePath $ft -Rules $FIREFOX_POLICY_RULES
        if ($fr.Hit) {
            $polHits++
            Out-Typewriter "  -> FIREFOX POLICY/PREF ANOMALY [$($fr.Name)]: $ft" "WARN"
            Add-Finding -ID "FFPOL116_$([Math]::Abs("$ft$($fr.Name)".GetHashCode()))" -Phase "PHASE 116" `
                -ThreatType "Browser Hijack / Adware" -Severity $SEV_POSSIBLE `
                -Description "Firefox rule '$($fr.Name)' matched in $ft. Managed fleets ship policies.json on purpose — confirm this file is yours before changing it." `
                -Target $ft -FixAction "Info" -Group "Browser Preference Tamper"
        }
    }
    if ($polHits -eq 0) { Out-Typewriter "  -> [OK ] NO BROWSER POLICY OR PREFERENCE TAMPER." "GOOD" }

    # ── PHASE 117: BROWSER NATIVE-MESSAGING HOSTS & DEBUG-PORT ABUSE ───────────
    Show-PhaseHeader "PHASE 117" "NATIVE MESSAGING HOSTS & BROWSER DEBUG-PORT ABUSE" "BROWSER"
    Out-Typewriter "CHECKING EXTENSION-TO-NATIVE-BINARY BRIDGES AND LIVE BROWSER SWITCHES..." "HUNT"
    $nmHits = 0
    foreach ($nk in @($NATIVE_MSG_KEYS)) {
        if (-not (Test-Path -LiteralPath $nk)) { continue }
        foreach ($hostKey in @(Get-ChildItem -LiteralPath $nk -ErrorAction SilentlyContinue)) {
            $hostName = $hostKey.PSChildName
            if ($hostName -match $NATIVE_MSG_BENIGN_RE) { continue }
            $manifest = Get-RegVal -Path $hostKey.PSPath -Name '(default)'
            if (-not $manifest) { continue }
            $hostExe = ''
            try {
                if (Test-Path -LiteralPath $manifest) {
                    $mj = Get-Content -LiteralPath $manifest -Raw -ErrorAction Stop | ConvertFrom-Json
                    $hostExe = "$($mj.path)"
                    if ($hostExe -and -not [System.IO.Path]::IsPathRooted($hostExe)) {
                        $hostExe = Join-Path (Split-Path -Parent $manifest) $hostExe
                    }
                }
            } catch {}
            $userPath = ($hostExe -match '(?i)\\(AppData|Temp|Downloads|Users\\Public|ProgramData)\\')
            $unsigned = $false
            if ($hostExe -and (Test-Path -LiteralPath $hostExe)) {
                $nv = Get-SignatureVerdict $hostExe
                $unsigned = ($nv.Status -ne 'Valid')
            }
            $nsev = if ($unsigned -and $userPath) { $SEV_HIGH } else { $SEV_POSSIBLE }
            $nmHits++
            Out-Typewriter "  -> NATIVE MESSAGING HOST: $hostName -> $(if($hostExe){$hostExe}else{$manifest})" "WARN"
            Add-Finding -ID "NMH117_$([Math]::Abs("$nk$hostName".GetHashCode()))" -Phase "PHASE 117" `
                -ThreatType "Browser Hijack / Adware" -Severity $nsev `
                -Description "Unrecognised native-messaging host '$hostName' registered under $nk, bridging a browser extension to the local binary '$(if($hostExe){$hostExe}else{$manifest})'$(if($unsigned){' (executable is NOT validly signed)'}). This is how a malicious extension escapes the browser sandbox and runs code. Manual: Remove-Item -LiteralPath '$($hostKey.PSPath)' -Recurse" `
                -Target "$nk\$hostName" -FixAction "Info" -Group "Native Messaging Hosts"
        }
    }
    # Live browser command lines: --remote-debugging-port is the modern cookie-theft path
    # (it reads DECRYPTED cookies straight out of the running browser, so App-Bound /
    # DPAPI encryption of the cookie store never comes into it).
    $browserProcRx = '(?i)^(chrome|msedge|brave|vivaldi|opera|chromium|firefox)$'
    foreach ($bpr in @((Get-ProcSnapshot))) {
        if ("$($bpr.Name)" -replace '\.exe$','' -notmatch $browserProcRx) { continue }
        $bcl = "$($bpr.CommandLine)"
        if (-not $bcl) { continue }
        foreach ($bar in @($BROWSER_ARG_ABUSE_RULES)) {
            if ($bcl -match $bar.Pattern) {
                $nmHits++
                $asev = switch ("$($bar.Severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
                $bclShort = $bcl.Substring(0, [Math]::Min(160, $bcl.Length))
                Out-ThreatBanner "BROWSER SWITCH ABUSE" "$($bpr.Name) PID:$($bpr.ProcessId) | $($bar.Name)"
                Add-Finding -ID "BARG117_$($bpr.ProcessId)_$($bar.Name)" -Phase "PHASE 117" `
                    -ThreatType "Credential Theft / Session Hijack" -Severity $asev `
                    -Description "Running browser $($bpr.Name) (PID $($bpr.ProcessId)) was launched with '$($bar.Name)' — $($bar.Why). Command line: $bclShort" `
                    -Target "PID:$($bpr.ProcessId)" -FixAction "Info" -Group "Browser Switch Abuse"
                break
            }
        }
    }
    if ($nmHits -eq 0) { Out-Typewriter "  -> [OK ] NO UNRECOGNISED NATIVE HOSTS OR BROWSER SWITCH ABUSE." "GOOD" }

    # ── PHASE 118: SHORTCUT (.LNK) HIJACK & ARGUMENT INJECTION ────────────────
    Show-PhaseHeader "PHASE 118" "SHORTCUT (.LNK) HIJACK & ARGUMENT INJECTION" "PERSISTENCE"
    Out-Typewriter "RESOLVING DESKTOP / START-MENU / STARTUP SHORTCUT TARGETS..." "HUNT"
    $lnkHits = 0
    $lnkRoots = @(
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('CommonDesktopDirectory'),
        [Environment]::GetFolderPath('StartMenu'),
        [Environment]::GetFolderPath('CommonStartMenu'),
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup'),
        "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $wsh = $null
    try { $wsh = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch { $wsh = $null }
    if ($null -eq $wsh) {
        Out-Typewriter "  -> [INFO] WScript.Shell unavailable — shortcut targets not resolvable on this host." "INFO"
    } else {
        $lnkFiles = @((Get-ScanFiles -Path @($lnkRoots) -Filter '*.lnk' -MaxFiles 1500 -DeadlineSecs 15))
        foreach ($lf in ($lnkFiles | Select-Object -First 600)) {
            $sc = $null
            try { $sc = $wsh.CreateShortcut($lf.FullName) } catch { continue }
            if ($null -eq $sc) { continue }
            $lnkLine = "$($sc.TargetPath) $($sc.Arguments)"
            if (-not $lnkLine.Trim()) { continue }
            $lnkRule = $null
            foreach ($lr in @($LNK_HIJACK_RULES) + @($BROWSER_ARG_ABUSE_RULES)) {
                if ($lnkLine -match $lr.Pattern) { $lnkRule = $lr; break }
            }
            if ($null -eq $lnkRule) { continue }
            $lnkHits++
            $lsev = switch ("$($lnkRule.Severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
            # A shortcut whose ICON impersonates a document/browser while the target is a
            # script host is the phishing-LNK shape; call it out but do not escalate on it.
            $masq = ($sc.IconLocation -match '(?i)(shell32\.dll|imageres\.dll|chrome|msedge|firefox|winword|excel|acrord)' -and
                     $sc.TargetPath -match '(?i)\\(wscript|cscript|mshta|powershell|pwsh|cmd|rundll32|regsvr32)\.exe$')
            $lineShort = $lnkLine.Substring(0, [Math]::Min(200, $lnkLine.Length))
            Out-ThreatBanner "MALICIOUS SHORTCUT" "$($lf.Name) [$($lnkRule.Name)]"
            # Only the two unambiguous CRITICAL rules (encoded PowerShell / hidden
            # downloader) get a reversible Quarantine — everything else is Info, because a
            # Start-Menu shortcut is how the user launches real software.
            $lfix = if ($lsev -eq $SEV_CRITICAL) { "Quarantine" } else { "Info" }
            $lparam = if ($lfix -eq "Quarantine") { $lf.FullName } else { "" }
            Add-Finding -ID "LNK118_$([Math]::Abs("$($lf.FullName)$($lnkRule.Name)".GetHashCode()))" -Phase "PHASE 118" `
                -ThreatType "Malicious Shortcut / Phishing Payload" -Severity $lsev `
                -Description "Shortcut '$($lf.FullName)' matched rule '$($lnkRule.Name)'$(if($masq){' and its icon impersonates a document/browser while the target is a script host'}). Resolved target+arguments: $lineShort" `
                -Target $lf.FullName -FixAction $lfix -FixParam $lparam -Group "Malicious Shortcuts"
            $global:TrojanHits++
        }
        try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wsh) } catch {}
    }
    if ($lnkHits -eq 0) { Out-Typewriter "  -> [OK ] NO HIJACKED OR WEAPONISED SHORTCUTS." "GOOD" }

    # ── PHASE 119: DLL SIDELOADING IN APPLICATION DIRECTORIES ─────────────────
    Show-PhaseHeader "PHASE 119" "DLL SIDELOADING IN APPLICATION DIRECTORIES" "INJECTION"
    Out-Typewriter "LOOKING FOR UNSIGNED PROXY DLLS PLANTED BESIDE SIGNED EXECUTABLES..." "HUNT"
    $slHits = 0
    $slCandidates = @((Get-ScanFiles -Path $SIDELOAD_SCAN_ROOTS -Filter '*.dll'))
    $slTargets = @($slCandidates | Where-Object { $SIDELOAD_DLL_NAMES -contains $_.Name.ToLower() } | Select-Object -First 400)
    $slSw = [System.Diagnostics.Stopwatch]::StartNew(); $slChecked = 0
    foreach ($sl in $slTargets) {
        # Authenticode does online CRL/OCSP work — carry the shared signature budget.
        if ($slChecked -ge $global:SIG_AUDIT_MAX_FILES -or $slSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
            Out-Typewriter ("  -> [INFO] SIGNATURE BUDGET REACHED AFTER {0} FILES / {1}s — SIDELOAD AUDIT TRUNCATED." -f $slChecked, [Math]::Round($slSw.Elapsed.TotalSeconds,1)) "WARN"
            break
        }
        if ($sl.FullName -match $SIDELOAD_BENIGN_RE) { continue }
        $slChecked++
        $slVerdict = Get-SignatureVerdict $sl.FullName
        if ($slVerdict.Status -eq 'Valid') { continue }
        # The tell is an UNSIGNED proxy DLL sitting next to a SIGNED executable: the
        # signed app loads it by name, and the attacker inherits its identity, its
        # reputation and any allowlisting it enjoys.
        $slHostExe = $null
        foreach ($sx in @(Get-ChildItem -LiteralPath $sl.DirectoryName -Filter '*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 6)) {
            $sxv = Get-SignatureVerdict $sx.FullName
            if ($sxv.Status -eq 'Valid') { $slHostExe = @{ Path = $sx.FullName; Signer = $sxv.Signer }; break }
        }
        if ($null -eq $slHostExe) { continue }
        $slHits++
        Out-ThreatBanner "DLL SIDELOAD CANDIDATE" "$($sl.Name) beside $(Split-Path -Leaf $slHostExe.Path)"
        Add-Finding -ID "SIDELOAD119_$([Math]::Abs($sl.FullName.GetHashCode()))" -Phase "PHASE 119" `
            -ThreatType "DLL Sideloading / Proxy Execution" -Severity $SEV_HIGH `
            -Description "Unsigned '$($sl.Name)' (signature status: $($slVerdict.Status)) sits in '$($sl.DirectoryName)' beside the validly signed executable '$(Split-Path -Leaf $slHostExe.Path)' [$($slHostExe.Signer)]. That DLL name is a known sideloading target — the signed app will load it by name and run its code. Verify against the vendor's own install before acting; if it is malicious, quarantine it: Move-Item -LiteralPath '$($sl.FullName)' <vault>" `
            -Target $sl.FullName -FixAction "Info" -Group "DLL Sideloading"
        $global:TrojanHits++
    }
    if ($slHits -eq 0) { Out-Typewriter "  -> [OK ] NO SIDELOADED PROXY DLLS FOUND." "GOOD" }

    # ── PHASE 120: ELECTRON / CHAT-CLIENT & WALLET CORE TAMPER ────────────────
    Show-PhaseHeader "PHASE 120" "ELECTRON APP CORE TAMPER (CHAT CLIENTS / DESKTOP WALLETS)" "TAMPER"
    Out-Typewriter "CHECKING USER-WRITABLE APPLICATION CODE FOR INJECTED LOADERS..." "HUNT"
    $elHits = 0
    foreach ($ea in @($ELECTRON_APP_PATHS)) {
        if (-not $ea.Path -or -not (Test-Path -LiteralPath $ea.Path)) { continue }
        # Electron ships its program code in AppData, so patching the app needs no admin
        # rights and creates no new autostart entry — token and seed-phrase stealers
        # modify the client itself and let the user launch it for them.
        $elFiles = @((Get-ScanFiles -Path @($ea.Path) -Filter '*.js' -MaxFiles 4000 -DeadlineSecs 12))
        $elPick  = @($elFiles | Where-Object { $_.Length -lt 2MB } | Select-Object -First 250)
        foreach ($ef in $elPick) {
            $er = Test-ContentRules -FilePath $ef.FullName -Rules $ELECTRON_TAMPER_RULES
            if (-not $er.Hit) { continue }
            $elHits++
            $esev = switch ("$($er.Severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
            Out-ThreatBanner "APP CORE TAMPER" "$($ea.App): $($er.Name)"
            Add-Finding -ID "ELEC120_$([Math]::Abs("$($ef.FullName)$($er.Name)".GetHashCode()))" -Phase "PHASE 120" `
                -ThreatType "Application Tamper / Infostealer" -Severity $esev `
                -Description "$($ea.App) application code was modified: rule '$($er.Name)' matched in '$($ef.FullName)'. Reinstalling the client from the vendor replaces the patched files. Client mods (BetterDiscord/Vencord) trip the same check and are often installed on purpose — confirm with the user." `
                -Target $ef.FullName -FixAction "Info" -Group "Application Core Tamper"
            $global:SpywareHits++
        }
        # An unpacked 'app' folder beside app.asar overrides the packed archive — the
        # classic no-rebuild injection into an Electron client.
        foreach ($rd in @(Get-ChildItem -LiteralPath $ea.Path -Directory -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                          Where-Object { $_.Name -eq 'resources' } | Select-Object -First 6)) {
            $asar = Join-Path $rd.FullName 'app.asar'
            $unpk = Join-Path $rd.FullName 'app'
            if ((Test-Path -LiteralPath $asar) -and (Test-Path -LiteralPath $unpk)) {
                $elHits++
                Add-Finding -ID "ELECASAR120_$([Math]::Abs($rd.FullName.GetHashCode()))" -Phase "PHASE 120" `
                    -ThreatType "Application Tamper / Infostealer" -Severity $SEV_POSSIBLE `
                    -Description "$($ea.App) has an unpacked 'app' directory beside 'app.asar' in '$($rd.FullName)'. Electron loads the loose folder in preference to the signed archive, so this is the standard way to inject code into a chat client or wallet without rebuilding it. Legitimate client mods do the same thing — confirm intent, then reinstall from the vendor to clear it." `
                    -Target $unpk -FixAction "Info" -Group "Application Core Tamper"
            }
        }
    }
    if ($elHits -eq 0) { Out-Typewriter "  -> [OK ] APPLICATION CORES INTACT." "GOOD" }

    # ── PHASE 121: OFFICE ADD-IN / XLL / TEMPLATE TAMPER ──────────────────────
    Show-PhaseHeader "PHASE 121" "OFFICE ADD-IN / XLL / TEMPLATE TAMPER" "PERSISTENCE"
    Out-Typewriter "AUDITING OFFICE ADD-INS, STARTUP TEMPLATES AND THE 'OFFICE TEST' KEY..." "HUNT"
    $ofHits = 0
    # The 'Office test\Special\Perf' key loads an arbitrary DLL into EVERY Office app at
    # launch. No product creates it — this is the one Extended-band finding with a
    # destructive fix, and the guard permits it (it is not core-OS registry).
    foreach ($opk in @($OFFICE_PERF_KEYS)) {
        if (-not (Test-Path -LiteralPath $opk.key)) { continue }
        $ofHits++
        $perfDll = Get-RegVal -Path $opk.key -Name '(default)'
        Out-ThreatBanner "OFFICE TEST KEY BACKDOOR" "$($opk.key)"
        Add-Finding -ID "OFFPERF121_$([Math]::Abs("$($opk.key)".GetHashCode()))" -Phase "PHASE 121" `
            -ThreatType "Office Persistence" -Severity $SEV_CRITICAL `
            -Description "$($opk.desc) Registered DLL: '$(if($perfDll){$perfDll}else{'(default value empty)'})'." `
            -Target $opk.key -FixAction "DeleteRegKey" -FixParam $opk.key -Group "Office Persistence"
        $global:TrojanHits++
    }
    foreach ($oak in @($OFFICE_ADDIN_KEYS)) {
        if (-not (Test-Path -LiteralPath $oak)) { continue }
        foreach ($ad in @(Get-ChildItem -LiteralPath $oak -ErrorAction SilentlyContinue)) {
            $lb = Get-RegVal -Path $ad.PSPath -Name 'LoadBehavior'
            if ($null -eq $lb -or [string]"$lb" -notmatch '^\d+$') { continue }
            if ([int]$lb -ne 3 -and [int]$lb -ne 9) { continue }   # 3/9 = load at startup
            $mf = Get-RegVal -Path $ad.PSPath -Name 'Manifest'
            $fn = Get-RegVal -Path $ad.PSPath -Name 'FriendlyName'
            $where = "$mf"
            if (-not $where) {
                # No manifest (COM add-in) — resolve the ProgID to its InprocServer32 DLL.
                try {
                    $ips = "Registry::HKEY_CLASSES_ROOT\$($ad.PSChildName)\CLSID"
                    $clsid = Get-RegVal -Path $ips -Name '(default)'
                    if ($clsid) { $where = "$(Get-RegVal -Path "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid\InprocServer32" -Name '(default)')" }
                } catch {}
            }
            if (-not $where) { continue }
            if ($where -match $OFFICE_ADDIN_BENIGN_RE) { continue }
            $userWritable = ($where -match '(?i)\\(AppData|Temp|Downloads|Users\\Public|ProgramData)\\')
            if (-not $userWritable) { continue }
            $ofHits++
            Out-Typewriter "  -> OFFICE ADD-IN FROM USER-WRITABLE PATH: $($ad.PSChildName) -> $where" "WARN"
            Add-Finding -ID "OFFADD121_$([Math]::Abs("$oak$($ad.PSChildName)".GetHashCode()))" -Phase "PHASE 121" `
                -ThreatType "Office Persistence" -Severity $SEV_HIGH `
                -Description "Office add-in '$(if($fn){$fn}else{$ad.PSChildName})' (LoadBehavior=$lb, loads at every Office start) resolves to '$where' in a user-writable path. Legitimate add-ins install under Program Files. Manual: Set-ItemProperty -LiteralPath '$($ad.PSPath)' -Name LoadBehavior -Value 0" `
                -Target "$oak\$($ad.PSChildName)" -FixAction "Info" -Group "Office Persistence"
        }
    }
    # XLL/WLL are native DLLs Excel and Word load by extension — no macro trust prompt at
    # all, which is why they took over after macros were blocked by default in 2022.
    $ofScanRoots = @($env:APPDATA, $env:LOCALAPPDATA, $env:TEMP, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")
    $ofFiles = @((Get-ScanFiles -Path $ofScanRoots -TimeScoped))
    foreach ($of in @($ofFiles | Where-Object { $OFFICE_ADDIN_EXTENSIONS -contains $_.Extension.ToLower() } | Select-Object -First 120)) {
        if ($of.FullName -match $OFFICE_ADDIN_BENIGN_RE) { continue }
        $ofExt = $of.Extension.ToLower()
        $ofNative = ($ofExt -eq '.xll' -or $ofExt -eq '.wll')
        $ofsev = if ($ofNative) { $SEV_HIGH } else { $SEV_POSSIBLE }
        $ofHits++
        Add-Finding -ID "OFFEXT121_$([Math]::Abs($of.FullName.GetHashCode()))" -Phase "PHASE 121" `
            -ThreatType "Office Malware" -Severity $ofsev `
            -Description "$(if($ofNative){"Native Office add-in ($ofExt) — Excel/Word load these as DLLs with NO macro trust prompt"}else{"Macro-enabled Office file ($ofExt)"}) in a user-writable path: $($of.FullName). Quarantine command: Move-Item -LiteralPath '$($of.FullName)' <vault>" `
            -Target $of.FullName -FixAction "Info" -Group "Office Malware"
    }
    foreach ($otp in @($OFFICE_TEMPLATE_PATHS)) {
        if (-not (Test-Path -LiteralPath $otp)) { continue }
        $isDir = $false
        try { $isDir = (Get-Item -LiteralPath $otp -ErrorAction Stop).PSIsContainer } catch { continue }
        if ($isDir) {
            foreach ($sf in @(Get-ChildItem -LiteralPath $otp -File -ErrorAction SilentlyContinue | Select-Object -First 30)) {
                $ofHits++
                Add-Finding -ID "OFFSTART121_$([Math]::Abs($sf.FullName.GetHashCode()))" -Phase "PHASE 121" `
                    -ThreatType "Office Persistence" -Severity $SEV_POSSIBLE `
                    -Description "File present in an Office STARTUP folder: '$($sf.FullName)'. Anything here is opened automatically every time the application starts, which makes it a persistence location. Confirm the user or an add-in vendor put it there." `
                    -Target $sf.FullName -FixAction "Info" -Group "Office Persistence"
            }
        } else {
            # Normal.dotm / VbaProject.OTM carrying a VBA project: OOXML is a zip, so the
            # presence of vbaProject.bin is the macro tell without parsing the document.
            $hasVba = $false
            try {
                $otBytes = [System.IO.File]::ReadAllBytes($otp)
                if ($otBytes.Length -gt 4) {
                    $otText = [System.Text.Encoding]::ASCII.GetString($otBytes)
                    $hasVba = ($otText -match 'vbaProject\.bin' -or $otText -match 'VBA_PROJECT')
                }
            } catch {}
            if ($hasVba) {
                $ofHits++
                Add-Finding -ID "OFFTPL121_$([Math]::Abs($otp.GetHashCode()))" -Phase "PHASE 121" `
                    -ThreatType "Office Persistence" -Severity $SEV_POSSIBLE `
                    -Description "The global Office template '$otp' contains a VBA project. Macros here run on EVERY document opened in that application — a long-standing Office persistence trick. Users do also write their own template macros, so confirm before removing." `
                    -Target $otp -FixAction "Info" -Group "Office Persistence"
            }
        }
    }
    if ($ofHits -eq 0) { Out-Typewriter "  -> [OK ] NO OFFICE ADD-IN OR TEMPLATE TAMPER." "GOOD" }

    # ── PHASE 122: INSTALLED-APPLICATION BINARY INTEGRITY ─────────────────────
    Show-PhaseHeader "PHASE 122" "INSTALLED-APPLICATION BINARY INTEGRITY (PATCHED-AFTER-SIGNING)" "TAMPER"
    Out-Typewriter "VERIFYING SIGNATURES OF EXECUTABLES IN PER-USER APPLICATION INSTALLS..." "HUNT"
    $aiHits = 0
    $aiRoots = @($MONITORED_APP_ROOTS | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($aiRoots.Count -eq 0) {
        Out-Typewriter "  -> [INFO] NO PER-USER APPLICATION ROOTS PRESENT ON THIS BOX." "INFO"
    } else {
        $aiFiles = @((Get-ScanFiles -Path $aiRoots -Filter '*.exe' -MaxFiles 6000 -DeadlineSecs 15))
        $aiSw = [System.Diagnostics.Stopwatch]::StartNew(); $aiChecked = 0
        foreach ($ai in @($aiFiles | Select-Object -First 400)) {
            if ($aiChecked -ge $global:SIG_AUDIT_MAX_FILES -or $aiSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
                Out-Typewriter ("  -> [INFO] SIGNATURE BUDGET REACHED AFTER {0} FILES / {1}s — INTEGRITY AUDIT TRUNCATED." -f $aiChecked, [Math]::Round($aiSw.Elapsed.TotalSeconds,1)) "WARN"
                break
            }
            $aiChecked++
            $aiv = Get-SignatureVerdict $ai.FullName
            # HashMismatch is the unambiguous one: the file WAS signed and its bytes have
            # changed since. An unsigned per-user binary is ordinary, so it is not reported
            # here (Phase 119 covers the sideload shape, Phase 109 covers system binaries).
            if ($aiv.Status -ne 'HashMismatch' -and $aiv.Status -ne 'NotTrusted') { continue }
            $aiHits++
            $aisev = if ($aiv.Status -eq 'HashMismatch') { $SEV_HIGH } else { $SEV_POSSIBLE }
            Out-ThreatBanner "APPLICATION BINARY MODIFIED" "$($ai.Name) [$($aiv.Status)]"
            Add-Finding -ID "APPINT122_$([Math]::Abs($ai.FullName.GetHashCode()))" -Phase "PHASE 122" `
                -ThreatType "Binary Tamper / Integrity" -Severity $aisev `
                -Description "Installed application binary '$($ai.FullName)' has signature status '$($aiv.Status)'$(if($aiv.Signer){" (signer: $($aiv.Signer))"}) — the file was signed by its vendor and its bytes no longer match that signature, i.e. it was patched after release. Last written $($ai.LastWriteTime). Reinstall the application from the vendor to restore it." `
                -Target $ai.FullName -FixAction "Info" -Group "Application Binary Integrity"
            $global:TrojanHits++
        }
    }
    if ($aiHits -eq 0) { Out-Typewriter "  -> [OK ] APPLICATION BINARIES MATCH THEIR SIGNATURES." "GOOD" }

    # ── PHASE 123: EXECUTION EVIDENCE (BAM / USERASSIST / MUICACHE) ───────────
    Show-PhaseHeader "PHASE 123" "EXECUTION EVIDENCE MINING (BAM / USERASSIST / MUICACHE)" "FORENSIC"
    Out-Typewriter "MINING WINDOWS' OWN RECORD OF WHAT ACTUALLY EXECUTED..." "HUNT"
    $exHits = 0
    # These artifacts survive the payload deleting itself, which is exactly why they are
    # the best answer to "did anything run?" after a cleanup.
    $bamRoots = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"
    )
    $exSeen = @{}
    foreach ($br in $bamRoots) {
        if (-not (Test-Path -LiteralPath $br)) { continue }
        foreach ($sidKey in @(Get-ChildItem -LiteralPath $br -ErrorAction SilentlyContinue | Select-Object -First 40)) {
            $bv = Get-ItemProperty -LiteralPath $sidKey.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $bv) { continue }
            foreach ($bp in ($bv.psobject.properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -notmatch '^(Version|SequenceNumber)$' })) {
                # BAM stores NT device paths (\Device\HarddiskVolumeN\Users\...).
                $bamPath = "$($bp.Name)" -replace '^\\Device\\HarddiskVolume\d+', ''
                if (-not $bamPath -or $bamPath -notmatch $EXEC_EVIDENCE_SUSPECT_RE) { continue }
                if ($bamPath -match $EXEC_EVID_BENIGN_RE) { continue }
                if ($exSeen.ContainsKey($bamPath.ToLower())) { continue }
                $exSeen[$bamPath.ToLower()] = $true
                $stillThere = $false
                try { $stillThere = Test-Path -LiteralPath ("$env:SystemDrive" + $bamPath) } catch {}
                $exHits++
                Out-Typewriter "  -> EXECUTED FROM USER-WRITABLE PATH: $bamPath$(if(-not $stillThere){'  [FILE NO LONGER PRESENT]'})" "WARN"
                Add-Finding -ID "BAM123_$([Math]::Abs($bamPath.ToLower().GetHashCode()))" -Phase "PHASE 123" `
                    -ThreatType "Execution Evidence" -Severity $(if ($stillThere) { $SEV_POSSIBLE } else { $SEV_HIGH }) `
                    -Description "Windows' Background Activity Moderator recorded that '$bamPath' was EXECUTED on this machine (user SID $($sidKey.PSChildName)). It ran from a user-writable path.$(if(-not $stillThere){' The file is no longer on disk — a dropper that deleted itself after running leaves exactly this trace, and it is the strongest single indicator in this phase.'}else{' The file is still present; hash it and check it against your AV/VirusTotal.'})" `
                    -Target $bamPath -FixAction "Info" -Group "Execution Evidence"
            }
        }
    }
    # UserAssist: GUI-launched programs, value names ROT13-encoded.
    $uaRoot = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    if (Test-Path -LiteralPath $uaRoot) {
        foreach ($uaG in @(Get-ChildItem -LiteralPath $uaRoot -ErrorAction SilentlyContinue | Select-Object -First 12)) {
            $uaCount = Join-Path $uaG.PSPath 'Count'
            if (-not (Test-Path -LiteralPath $uaCount)) { continue }
            $uav = Get-ItemProperty -LiteralPath $uaCount -ErrorAction SilentlyContinue
            if ($null -eq $uav) { continue }
            foreach ($up in ($uav.psobject.properties | Where-Object { $_.Name -notmatch '^PS' })) {
                $rot = ''
                foreach ($ch in "$($up.Name)".ToCharArray()) {
                    $cc = [int][char]$ch
                    if     ($cc -ge 65 -and $cc -le 90)  { $rot += [char](65 + (($cc - 65 + 13) % 26)) }
                    elseif ($cc -ge 97 -and $cc -le 122) { $rot += [char](97 + (($cc - 97 + 13) % 26)) }
                    else   { $rot += $ch }
                }
                if ($rot -notmatch $EXEC_EVIDENCE_SUSPECT_RE) { continue }
                if ($rot -match $EXEC_EVID_BENIGN_RE) { continue }
                if ($exSeen.ContainsKey($rot.ToLower())) { continue }
                $exSeen[$rot.ToLower()] = $true
                $exHits++
                Add-Finding -ID "UA123_$([Math]::Abs($rot.ToLower().GetHashCode()))" -Phase "PHASE 123" `
                    -ThreatType "Execution Evidence" -Severity $SEV_POSSIBLE `
                    -Description "UserAssist records that '$rot' was launched from the shell (double-clicked or run from a shortcut) out of a user-writable path. That is the execution half of a phishing chain — pair it with the Phase 118 shortcut findings and the Phase 124 run-dialog history." `
                    -Target $rot -FixAction "Info" -Group "Execution Evidence"
            }
        }
    }
    # MuiCache + the Compatibility Assistant store: every EXE the shell has displayed.
    foreach ($mc in @("HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                      "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store")) {
        if (-not (Test-Path -LiteralPath $mc)) { continue }
        $mcv = Get-ItemProperty -LiteralPath $mc -ErrorAction SilentlyContinue
        if ($null -eq $mcv) { continue }
        foreach ($mp in ($mcv.psobject.properties | Where-Object { $_.Name -notmatch '^PS' })) {
            $mcPath = ("$($mp.Name)" -split '\.FriendlyAppName|\.ApplicationCompany')[0]
            if ($mcPath -notmatch $EXEC_EVIDENCE_SUSPECT_RE) { continue }
            if ($mcPath -match $EXEC_EVID_BENIGN_RE) { continue }
            if ($exSeen.ContainsKey($mcPath.ToLower())) { continue }
            $exSeen[$mcPath.ToLower()] = $true
            $exHits++
            Add-Finding -ID "MUI123_$([Math]::Abs($mcPath.ToLower().GetHashCode()))" -Phase "PHASE 123" `
                -ThreatType "Execution Evidence" -Severity $SEV_POSSIBLE `
                -Description "Shell cache ($(Split-Path -Leaf $mc)) records the executable '$mcPath' from a user-writable path. Corroborating evidence that it was present and run." `
                -Target $mcPath -FixAction "Info" -Group "Execution Evidence"
        }
    }
    if ($exHits -eq 0) { Out-Typewriter "  -> [OK ] NO EXECUTION EVIDENCE FROM USER-WRITABLE PATHS." "GOOD" }

    # ── PHASE 124: RUN-DIALOG / MRU FORENSICS (CLICKFIX & FAKE-CAPTCHA) ───────
    Show-PhaseHeader "PHASE 124" "RUN-DIALOG & MRU FORENSICS (CLICKFIX / FAKE-CAPTCHA INITIAL ACCESS)" "FORENSIC"
    Out-Typewriter "READING WHAT WAS TYPED OR PASTED INTO THE RUN DIALOG..." "HUNT"
    $mruHits = 0
    # 'ClickFix' is currently the dominant initial-access technique: a fake CAPTCHA or
    # browser-update page instructs the victim to press Win+R and paste a command. The
    # user runs the payload themselves, so there is no download, no attachment and no
    # exploit — and HKCU RunMRU is very often the only surviving evidence of it.
    foreach ($mk in @($MRU_FORENSIC_KEYS)) {
        if (-not (Test-Path -LiteralPath $mk.key)) { continue }
        $mv = Get-ItemProperty -LiteralPath $mk.key -ErrorAction SilentlyContinue
        if ($null -eq $mv) { continue }
        foreach ($mp in ($mv.psobject.properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -ne 'MRUList' -and $_.Name -ne 'MRUListEx' })) {
            $entry = "$($mp.Value)"
            if (-not $entry.Trim()) { continue }
            foreach ($cr in @($CLICKFIX_RUNMRU_RULES)) {
                if ($entry -notmatch $cr.Pattern) { continue }
                $mruHits++
                $csev = switch ("$($cr.Severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
                $entryShort = $entry.Substring(0, [Math]::Min(220, $entry.Length))
                Out-ThreatBanner "RUN-DIALOG PAYLOAD" "$($mk.desc): $($cr.Name)"
                # NEVER offer to delete an MRU value: it is the incident's evidence.
                Add-Finding -ID "MRU124_$([Math]::Abs("$($mk.key)$($mp.Name)$($cr.Name)".GetHashCode()))" -Phase "PHASE 124" `
                    -ThreatType "User-Executed Payload / Initial Access" -Severity $csev `
                    -Description "$($mk.desc) entry '$($mp.Name)' matched '$($cr.Name)': $entryShort — this command was typed or pasted by the user into Windows itself, which is the ClickFix / fake-CAPTCHA pattern. Treat the box as compromised from that timestamp and work forward. This value is EVIDENCE and is deliberately not offered for deletion; preserve it, and check Phase 123 for what actually executed." `
                    -Target "$($mk.key)\$($mp.Name)" -FixAction "Info" -Group "Run-Dialog Payloads"
                $global:TrojanHits++
                break
            }
        }
    }
    if ($mruHits -eq 0) { Out-Typewriter "  -> [OK ] NO SUSPICIOUS RUN-DIALOG OR MRU HISTORY." "GOOD" }

    # ── PHASE 125: CLIPBOARD CLIPPER (CRYPTO ADDRESS SWAP) ARTIFACTS ──────────
    Show-PhaseHeader "PHASE 125" "CLIPBOARD CLIPPER (CRYPTO ADDRESS SWAP) ARTIFACTS" "STEALER"
    Out-Typewriter "SEARCHING USER-PATH FILES FOR ATTACKER WALLET-ADDRESS TABLES..." "HUNT"
    $clHits = 0
    $clRoots = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")
    $clExt   = @('.ps1','.bat','.cmd','.vbs','.js','.jse','.py','.au3','.txt','.json','.ini','.cfg','.exe','.dll')
    $clFiles = @((Get-ScanFiles -Path $clRoots -TimeScoped))
    foreach ($cf in @($clFiles | Where-Object { ($clExt -contains $_.Extension.ToLower()) -and $_.Length -gt 64 -and $_.Length -lt 6MB } | Select-Object -First 220)) {
        if ($cf.FullName -match $WEBHOOK_BENIGN_RE) { continue }
        $clText = $null
        try {
            $clBytes = [System.IO.File]::ReadAllBytes($cf.FullName)
            $clText  = [System.Text.Encoding]::ASCII.GetString($clBytes)
        } catch { continue }
        if (-not $clText) { continue }
        # A single wallet address proves nothing (invoices, READMEs, donation links).
        # The clipper shape is a TABLE: several addresses, ideally across chains, so the
        # malware can swap whatever the victim copies. Require that density.
        $clAddrs = @{}; $clChains = @{}
        foreach ($cw in @($CLIPPER_WALLET_RULES)) {
            $cms = $null
            try { $cms = [regex]::Matches($clText, $cw.Pattern) } catch { $cms = $null }
            if ($null -eq $cms) { continue }
            foreach ($cm in $cms) {
                if ($clAddrs.Count -ge 64) { break }
                $clAddrs["$($cm.Value)"] = $true
                $clChains["$($cw.Kind)"] = $true
            }
        }
        if ($clAddrs.Count -lt 3 -and $clChains.Count -lt 2) { continue }
        $clApi = $false
        foreach ($ca in @($CLIPPER_API_RULES)) { if ($clText -match $ca.Pattern) { $clApi = $true; break } }
        $clsev = if ($clApi) { $SEV_HIGH } else { $SEV_POSSIBLE }
        $clHits++
        Out-ThreatBanner "CLIPBOARD CLIPPER CANDIDATE" "$($cf.Name) — $($clAddrs.Count) addresses / $($clChains.Count) chains"
        Add-Finding -ID "CLIP125_$([Math]::Abs($cf.FullName.GetHashCode()))" -Phase "PHASE 125" `
            -ThreatType "Cryptocurrency Clipper" -Severity $clsev `
            -Description "'$($cf.FullName)' contains a table of $($clAddrs.Count) distinct cryptocurrency addresses across $($clChains.Count) chain(s) ($(($clChains.Keys | Sort-Object) -join ', '))$(if($clApi){' TOGETHER WITH clipboard-API usage — that combination is a clipper: it watches the clipboard and swaps a copied wallet address for the attacker''s, so the victim pays them instead'}else{' but no clipboard API usage — review before acting; a price list or wallet backup looks similar'}). Warn the user NOT to trust any address pasted on this machine until it is cleared." `
            -Target $cf.FullName -FixAction "Info" -Group "Cryptocurrency Clipper"
        $global:SpywareHits++
    }
    if ($clHits -eq 0) { Out-Typewriter "  -> [OK ] NO CLIPBOARD-CLIPPER ARTIFACTS." "GOOD" }

    # ── PHASE 126: EXTENDED AUTOSTART SURFACE ─────────────────────────────────
    Show-PhaseHeader "PHASE 126" "EXTENDED AUTOSTART SURFACE (LSA / NETSH / PRINT / BOOT / ACTIVE SETUP)" "PERSISTENCE"
    Out-Typewriter "AUDITING THE AUTOSTART LOCATIONS BEYOND RUN, SERVICES AND TASKS..." "HUNT"
    $easHits = 0
    foreach ($eas in @($EXTENDED_AUTOSTART_POINTS)) {
        if (-not (Test-Path -LiteralPath $eas.key)) { continue }
        $eassev = switch ("$($eas.severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
        $easDefaults = @()
        if ($eas.default) { $easDefaults = @("$($eas.default)" -split '\|' | ForEach-Object { $_.Trim().ToLower() }) }
        switch ("$($eas.kind)") {
            'values' {
                $ev = Get-ItemProperty -LiteralPath $eas.key -ErrorAction SilentlyContinue
                if ($null -eq $ev) { break }
                foreach ($ep in ($ev.psobject.properties | Where-Object { $_.Name -notmatch '^PS' })) {
                    $evName = "$($ep.Name)".ToLower()
                    if ($easDefaults -contains $evName) { continue }
                    $easHits++
                    Out-ThreatBanner "EXTENDED AUTOSTART" "$(Split-Path -Leaf $eas.key): $($ep.Name)"
                    Add-Finding -ID "EAS126_$([Math]::Abs("$($eas.key)$($ep.Name)".GetHashCode()))" -Phase "PHASE 126" `
                        -ThreatType "Persistence — Extended Autostart" -Severity $eassev `
                        -Description "$($eas.desc) Non-default entry '$($ep.Name)' = '$($ep.Value)' under $($eas.key). Manual: Remove-ItemProperty -LiteralPath '$($eas.key)' -Name '$($ep.Name)' — this key sits under a protected hive, so the tool deliberately does not offer to change it for you (removing the wrong entry here can stop the machine booting or logging in)." `
                        -Target "$($eas.key)\$($ep.Name)" -FixAction "Info" -Group "Extended Autostart"
                }
            }
            'multistring' {
                $mvv = Get-RegVal -Path $eas.key -Name "$($eas.name)"
                if ($null -eq $mvv) { break }
                foreach ($mline in @($mvv)) {
                    $ml = "$mline".Trim()
                    if (-not $ml) { continue }
                    $mlKey = ($ml -replace '\.dll$','').ToLower()
                    if ($easDefaults -contains $mlKey -or $easDefaults -contains $ml.ToLower()) { continue }
                    $easHits++
                    Out-ThreatBanner "LSA / BOOT PACKAGE ADDED" "$($eas.name): $ml"
                    Add-Finding -ID "EASM126_$([Math]::Abs("$($eas.key)$($eas.name)$ml".GetHashCode()))" -Phase "PHASE 126" `
                        -ThreatType "Persistence — Extended Autostart" -Severity $eassev `
                        -Description "$($eas.desc) '$($eas.name)' contains the non-stock entry '$ml' (stock: $($eas.default)). Do NOT edit this blind — an incorrect value here prevents logon entirely. Boot to a known-good state or use a recovery console, and confirm the DLL's publisher first." `
                        -Target "$($eas.key)\$($eas.name)" -FixAction "Info" -Group "Extended Autostart"
                }
            }
            { $_ -eq 'subkeys_driver' -or $_ -eq 'subkeys_dll' } {
                $dllValName = if ($_ -eq 'subkeys_driver') { 'Driver' } else { 'DllName' }
                foreach ($sk in @(Get-ChildItem -LiteralPath $eas.key -ErrorAction SilentlyContinue | Select-Object -First 60)) {
                    if ($easDefaults -contains "$($sk.PSChildName)".ToLower()) { continue }
                    $skDll = Get-RegVal -Path $sk.PSPath -Name $dllValName
                    $easHits++
                    Add-Finding -ID "EASS126_$([Math]::Abs("$($eas.key)$($sk.PSChildName)".GetHashCode()))" -Phase "PHASE 126" `
                        -ThreatType "Persistence — Extended Autostart" -Severity $eassev `
                        -Description "$($eas.desc) Non-default entry '$($sk.PSChildName)' registers '$(if($skDll){$skDll}else{'(no DLL value)'})'. Print monitors and time providers load into SYSTEM services at boot, so verify the DLL's publisher before deciding." `
                        -Target "$($eas.key)\$($sk.PSChildName)" -FixAction "Info" -Group "Extended Autostart"
                }
            }
            'activesetup' {
                foreach ($asK in @(Get-ChildItem -LiteralPath $eas.key -ErrorAction SilentlyContinue | Select-Object -First 200)) {
                    $stub = Get-RegVal -Path $asK.PSPath -Name 'StubPath'
                    if (-not $stub) { continue }
                    if ("$stub" -notmatch '(?i)\\(AppData|Temp|Downloads|Users\\Public|ProgramData)\\' -and
                        "$stub" -notmatch '(?i)\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl)\b') { continue }
                    $easHits++
                    Out-ThreatBanner "ACTIVE SETUP STUBPATH" "$($asK.PSChildName)"
                    Add-Finding -ID "EASA126_$([Math]::Abs("$($asK.PSChildName)".GetHashCode()))" -Phase "PHASE 126" `
                        -ThreatType "Persistence — Extended Autostart" -Severity $SEV_HIGH `
                        -Description "$($eas.desc) Active Setup component '$($asK.PSChildName)' runs StubPath '$stub' the first time each user logs on — a quiet way to seed every profile on a shared machine. Manual: Remove-Item -LiteralPath '$($asK.PSPath)' -Recurse" `
                        -Target "$($asK.PSPath)" -FixAction "Info" -Group "Extended Autostart"
                }
            }
            'value_path' {
                $vpv = Get-RegVal -Path $eas.key -Name "$($eas.name)"
                if ($null -eq $vpv -or -not "$vpv".Trim()) { break }
                if ($easDefaults.Count -gt 0) {
                    $vpKey = ("$vpv".Trim() -replace '\.exe$','').ToLower()
                    if ($easDefaults -contains $vpKey -or $easDefaults -contains "$vpv".Trim().ToLower()) { break }
                }
                $easHits++
                Out-ThreatBanner "EXTENDED AUTOSTART VALUE" "$($eas.name) = $vpv"
                Add-Finding -ID "EASV126_$([Math]::Abs("$($eas.key)$($eas.name)".GetHashCode()))" -Phase "PHASE 126" `
                    -ThreatType "Persistence — Extended Autostart" -Severity $eassev `
                    -Description "$($eas.desc) $($eas.key)\$($eas.name) = '$vpv'. Manual: Remove-ItemProperty -LiteralPath '$($eas.key)' -Name '$($eas.name)'" `
                    -Target "$($eas.key)\$($eas.name)" -FixAction "Info" -Group "Extended Autostart"
            }
        }
    }
    # Winsock LSP catalog: a third-party layered provider sees every socket in the system.
    $lspRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries"
    foreach ($lspNode in @("$lspRoot", "${lspRoot}64")) {
        if (-not (Test-Path -LiteralPath $lspNode)) { continue }
        foreach ($lspE in @(Get-ChildItem -LiteralPath $lspNode -ErrorAction SilentlyContinue | Select-Object -First 60)) {
            $blob = Get-RegVal -Path $lspE.PSPath -Name 'PackedCatalogItem'
            if ($null -eq $blob) { continue }
            $lspPath = ''
            try {
                $lspBytes = [byte[]]$blob
                $take = [Math]::Min(512, $lspBytes.Length)
                $lspPath = ([System.Text.Encoding]::Unicode.GetString($lspBytes, 0, $take) -split "`0")[0]
            } catch { $lspPath = '' }
            if (-not $lspPath) { continue }
            $lspLeaf = ""
            try { $lspLeaf = (Split-Path -Leaf $lspPath).ToLower() } catch { $lspLeaf = "$lspPath".ToLower() }
            if ($WINSOCK_LSP_BENIGN -contains $lspLeaf) { continue }
            $easHits++
            Add-Finding -ID "LSP126_$([Math]::Abs("$lspPath".ToLower().GetHashCode()))" -Phase "PHASE 126" `
                -ThreatType "Persistence — Extended Autostart" -Severity $SEV_POSSIBLE `
                -Description "Third-party Winsock layered service provider registered: '$lspPath'. An LSP is loaded into every process that opens a socket and can read or rewrite traffic. Legacy AV, VPN and parental-control products still install them, so confirm the publisher before removing — and remove only with 'netsh winsock reset', never by deleting the catalog entry (that breaks all networking)." `
                -Target $lspPath -FixAction "Info" -Group "Extended Autostart"
        }
    }
    if ($easHits -eq 0) { Out-Typewriter "  -> [OK ] EXTENDED AUTOSTART SURFACE IS STOCK." "GOOD" }

    # ── PHASE 127: SHELL EXTENSION / CONTEXT-MENU / ICON-OVERLAY HIJACK ───────
    Show-PhaseHeader "PHASE 127" "SHELL EXTENSION / CONTEXT-MENU / ICON-OVERLAY HIJACK" "PERSISTENCE"
    Out-Typewriter "RESOLVING SHELL EXTENSION CLSIDS TO THEIR BACKING DLLS..." "HUNT"
    $shHits = 0
    foreach ($shk in @($SHELL_EXTENSION_KEYS)) {
        if (-not (Test-Path -LiteralPath $shk.key)) { continue }
        $clsids = @()
        if ("$($shk.kind)" -eq 'clsid_subkeys') {
            foreach ($csk in @(Get-ChildItem -LiteralPath $shk.key -ErrorAction SilentlyContinue | Select-Object -First 120)) {
                $cval = Get-RegVal -Path $csk.PSPath -Name '(default)'
                $cid = if ("$cval" -match '\{[0-9A-Fa-f-]{36}\}') { $matches[0] } elseif ("$($csk.PSChildName)" -match '\{[0-9A-Fa-f-]{36}\}') { $matches[0] } else { '' }
                if ($cid) { $clsids += ,@{ Id = $cid; Label = "$($csk.PSChildName)" } }
            }
        } else {
            $cv = Get-ItemProperty -LiteralPath $shk.key -ErrorAction SilentlyContinue
            if ($null -ne $cv) {
                foreach ($cp in ($cv.psobject.properties | Where-Object { $_.Name -notmatch '^PS' })) {
                    if ("$($cp.Name)" -match '\{[0-9A-Fa-f-]{36}\}') { $clsids += ,@{ Id = $matches[0]; Label = "$($cp.Value)" } }
                }
            }
        }
        foreach ($ci in $clsids) {
            $shDll = ''
            foreach ($hive in @('HKEY_CLASSES_ROOT','HKEY_CURRENT_USER\SOFTWARE\Classes')) {
                $ips = "Registry::$hive\CLSID\$($ci.Id)\InprocServer32"
                $v = Get-RegVal -Path $ips -Name '(default)'
                if ($v) { $shDll = "$v"; break }
            }
            if (-not $shDll) { continue }
            $shDllExp = [System.Environment]::ExpandEnvironmentVariables($shDll.Trim('"'))
            if ($shDllExp -match $SHELLEXT_BENIGN_RE) { continue }
            $shMissing = -not (Test-Path -LiteralPath $shDllExp)
            $shUserPath = ($shDllExp -match '(?i)\\(AppData|Temp|Downloads|Users\\Public)\\')
            $shUnsigned = $false
            if (-not $shMissing) {
                $shv = Get-SignatureVerdict $shDllExp
                $shUnsigned = ($shv.Status -ne 'Valid')
            }
            if (-not ($shMissing -or ($shUnsigned -and $shUserPath))) { continue }
            $shHits++
            $shsev = if ($shUnsigned -and $shUserPath) { $SEV_HIGH } else { $SEV_POSSIBLE }
            Out-ThreatBanner "SHELL EXTENSION ANOMALY" "$($ci.Label) -> $(Split-Path -Leaf $shDllExp)"
            Add-Finding -ID "SHEXT127_$([Math]::Abs("$($shk.key)$($ci.Id)".GetHashCode()))" -Phase "PHASE 127" `
                -ThreatType "Shell Extension Hijack" -Severity $shsev `
                -Description "Shell extension '$($ci.Label)' ($($shk.desc)) resolves CLSID $($ci.Id) to '$shDllExp'$(if($shMissing){' — the DLL is MISSING, which is either a leftover from an uninstall or a slot waiting for a payload to be dropped into it'}else{' — the DLL is unsigned and sits in a user-writable path'}). Explorer loads shell extensions into ITSELF, so this survives every autorun cleanup and almost nobody looks here. Manual: Remove-Item -LiteralPath '$($shk.key)\$($ci.Label)' -Recurse" `
                -Target "$($shk.key)\$($ci.Label)" -FixAction "Info" -Group "Shell Extension Hijack"
        }
    }
    if ($shHits -eq 0) { Out-Typewriter "  -> [OK ] NO SHELL EXTENSION HIJACKS." "GOOD" }

    # ── PHASE 128: UNAUTHORISED REMOTE-ACCESS / RMM TOOL AUDIT ────────────────
    Show-PhaseHeader "PHASE 128" "REMOTE-ACCESS & RMM TOOL INVENTORY (LEGITIMATE-TOOL ABUSE)" "ACCESS"
    Out-Typewriter "INVENTORYING REMOTE-CONTROL SOFTWARE INSTALLED ON THIS MACHINE..." "HUNT"
    $raHits = 0; $raInventory = 0
    # Attackers increasingly install real remote-control software instead of a RAT: it is
    # signed, it is allowlisted, and it looks exactly like IT doing its job. CLAUDE.md
    # rule #2 governs this phase — Datto / CentraStage / Kaseya and their peers are
    # PARTNER tooling, so anything on the partner list is reported as INVENTORY, never as
    # a threat, and nothing in this phase is ever auto-acted-on.
    $raProcs = @((Get-ProcSnapshot))
    foreach ($ra in @($REMOTE_ACCESS_PRODUCTS)) {
        $raFound = @(); $raPathHit = ''
        foreach ($rp in @($ra.paths)) {
            $rpx = $ExecutionContext.InvokeCommand.ExpandString($rp)
            if ($rpx -and (Test-Path -LiteralPath $rpx)) { $raFound += "installed: $rpx"; if (-not $raPathHit) { $raPathHit = $rpx } }
        }
        $raLive = @($raProcs | Where-Object { "$($_.Name)" -match [regex]::Escape("$($ra.proc)") })
        foreach ($rl in ($raLive | Select-Object -First 3)) {
            $raFound += "running: $($rl.Name) (PID $($rl.ProcessId))"
            if (-not $raPathHit -and $rl.ExecutablePath) { $raPathHit = "$($rl.ExecutablePath)" }
        }
        if ($raFound.Count -eq 0) { continue }
        $isPartner = $false
        foreach ($pv in $REMOTE_ACCESS_PARTNERS) { if ("$($ra.name)".ToLower() -match [regex]::Escape($pv)) { $isPartner = $true; break } }
        # Context beats identity: the same signed binary running out of Temp, Public or
        # the Recycle Bin, or renamed to one to three characters, is not an IT deployment.
        $raCtx = $null
        foreach ($rc in @($REMOTE_ACCESS_SUSP_CTX)) { if ($raPathHit -and $raPathHit -match $rc.Pattern) { $raCtx = $rc; break } }
        $rasev = if ($raCtx) { $SEV_HIGH } elseif ($isPartner) { $SEV_INFO } else { $SEV_POSSIBLE }
        $raHits++
        if ($rasev -eq $SEV_INFO) { $raInventory++ }
        $raVerdict = if ($raCtx) {
            "RUNNING FROM AN ABNORMAL LOCATION ($($raCtx.Name)) — a remote-control tool in this path was not deployed by IT."
        } elseif ($isPartner) {
            "Recognised MSP/RMM partner tooling — inventory only, not a threat (CLAUDE.md rule #2)."
        } else {
            "Confirm this is authorised. If your team did not deploy it, treat it as an attacker's remote access and remove it through its own uninstaller."
        }
        Add-Finding -ID "RMM128_$([Math]::Abs("$($ra.name)".GetHashCode()))" -Phase "PHASE 128" `
            -ThreatType "Remote Access Tool" -Severity $rasev `
            -Description "Remote-access product '$($ra.name)' detected — $($raFound -join '; '). $raVerdict" `
            -Target $(if ($raPathHit) { $raPathHit } else { "$($ra.name)" }) -FixAction "Info" -Group "Remote Access Tools"
        # Unattended-access configuration is the difference between "someone helped the
        # user once" and "someone can come back whenever they like".
        if ($ra.config -and $ra.unattended_rule -and $raPathHit) {
            foreach ($rcp in @($ra.paths)) {
                $rcx = $ExecutionContext.InvokeCommand.ExpandString($rcp)
                if (-not $rcx) { continue }
                $cfgFile = Join-Path $rcx "$($ra.config)"
                if (-not (Test-Path -LiteralPath $cfgFile)) { continue }
                $cfgTxt = ''
                try { $cfgTxt = Get-Content -LiteralPath $cfgFile -Raw -ErrorAction Stop } catch { $cfgTxt = '' }
                if ($cfgTxt -and $cfgTxt -match "$($ra.unattended_rule)") {
                    $raHits++
                    Out-ThreatBanner "UNATTENDED REMOTE ACCESS" "$($ra.name): $cfgFile"
                    Add-Finding -ID "RMMUA128_$([Math]::Abs($cfgFile.GetHashCode()))" -Phase "PHASE 128" `
                        -ThreatType "Remote Access Tool" -Severity $(if ($isPartner) { $SEV_POSSIBLE } else { $SEV_HIGH }) `
                        -Description "'$($ra.name)' is configured for UNATTENDED access in '$cfgFile' — a stored password or a fixed relay/gateway means someone can connect without the user accepting a prompt. Verify this matches your own deployment; if not, the operator has standing remote access to this machine." `
                        -Target $cfgFile -FixAction "Info" -Group "Remote Access Tools"
                }
            }
        }
    }
    if ($raHits -eq 0) { Out-Typewriter "  -> [OK ] NO REMOTE-ACCESS SOFTWARE PRESENT." "GOOD" }
    else { Out-Typewriter "  -> REMOTE-ACCESS INVENTORY: $raHits ENTRIES ($raInventory RECOGNISED PARTNER TOOLING)." "INFO" }

    # ── PHASE 129: EXFILTRATION STAGING & CLOUD-SYNC TOOL ABUSE ───────────────
    Show-PhaseHeader "PHASE 129" "EXFILTRATION STAGING & CLOUD-SYNC TOOL ABUSE" "EXFIL"
    Out-Typewriter "CHECKING FOR BULK-COPY TOOLING, CLOUD REMOTES AND STAGED ARCHIVES..." "HUNT"
    $exfHits = 0
    # Double-extortion crews copy the file shares out BEFORE they encrypt. rclone is the
    # tool of choice, and a configured cloud remote on an endpoint that is not a backup
    # server is the tell — the binary alone is a legitimate admin utility.
    foreach ($et in @($EXFIL_STAGING_TOOLS)) {
        $etLive = @($raProcs | Where-Object { "$($_.Name)" -replace '\.exe$','' -eq "$($et.proc)" })
        foreach ($el in ($etLive | Select-Object -First 2)) {
            $exfHits++
            $elCmd = "$($el.CommandLine)"
            $elShort = if ($elCmd) { $elCmd.Substring(0, [Math]::Min(180, $elCmd.Length)) } else { '(command line unavailable)' }
            Out-ThreatBanner "BULK-COPY TOOL RUNNING" "$($et.name) PID:$($el.ProcessId)"
            Add-Finding -ID "EXF129P_$($el.ProcessId)" -Phase "PHASE 129" `
                -ThreatType "Data Exfiltration" -Severity $SEV_HIGH `
                -Description "Bulk data-transfer tool '$($et.name)' is RUNNING (PID $($el.ProcessId)): $elShort. During an incident this is the exfiltration step; on a healthy box it is an admin copying files. Establish which before anything else — if data left, the disclosure obligations change." `
                -Target "PID:$($el.ProcessId)" -FixAction "Info" -Group "Exfiltration Staging"
        }
        foreach ($ec in @($et.config_raw)) {
            $ecx = $ExecutionContext.InvokeCommand.ExpandString($ec)
            if (-not $ecx -or -not (Test-Path -LiteralPath $ecx)) { continue }
            $ecIsDir = $false
            try { $ecIsDir = (Get-Item -LiteralPath $ecx -ErrorAction Stop).PSIsContainer } catch { continue }
            if ($ecIsDir) {
                $exfHits++
                Add-Finding -ID "EXF129D_$([Math]::Abs($ecx.GetHashCode()))" -Phase "PHASE 129" `
                    -ThreatType "Data Exfiltration" -Severity $SEV_POSSIBLE `
                    -Description "Cloud-transfer tool '$($et.name)' has state in '$ecx' — it has been installed and used on this machine. Confirm it is yours." `
                    -Target $ecx -FixAction "Info" -Group "Exfiltration Staging"
                continue
            }
            $ecr = Test-ContentRules -FilePath $ecx -Rules $EXFIL_CONFIG_RULES
            if (-not $ecr.Hit) { continue }
            $exfHits++
            $ecsev = switch ("$($ecr.Severity)") { "HIGH" { $SEV_HIGH } "CRITICAL" { $SEV_CRITICAL } default { $SEV_POSSIBLE } }
            Out-ThreatBanner "CLOUD REMOTE CONFIGURED" "$($et.name): $ecx"
            Add-Finding -ID "EXF129C_$([Math]::Abs("$ecx$($ecr.Name)".GetHashCode()))" -Phase "PHASE 129" `
                -ThreatType "Data Exfiltration" -Severity $ecsev `
                -Description "'$($et.name)' configuration '$ecx' matched '$($ecr.Name)' — a cloud storage remote is configured on this endpoint. Read the config and identify the destination account; if you do not recognise it, assume data was copied there and preserve the file as evidence before changing anything." `
                -Target $ecx -FixAction "Info" -Group "Exfiltration Staging"
        }
    }
    $stageRoots = @($env:TEMP, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:PUBLIC", $env:PROGRAMDATA)
    $stageFiles = @((Get-ScanFiles -Path $stageRoots -TimeScoped))
    foreach ($sf2 in @($stageFiles | Where-Object { $_.Extension -match '(?i)^\.(7z|zip|rar|00[0-9])$' } | Select-Object -First 200)) {
        foreach ($ar in @($EXFIL_ARCHIVE_RULES)) {
            if ($sf2.Name -notmatch $ar.Pattern) { continue }
            $exfHits++
            Add-Finding -ID "EXF129A_$([Math]::Abs($sf2.FullName.GetHashCode()))" -Phase "PHASE 129" `
                -ThreatType "Data Exfiltration" -Severity $SEV_POSSIBLE `
                -Description "Staged archive '$($sf2.FullName)' matched '$($ar.Name)' ($([Math]::Round($sf2.Length/1MB,1)) MB, written $($sf2.LastWriteTime)). Split multi-volume archives and dated bulk archives in a user-writable path are how a large data set is prepared to move through a size-limited channel. Check what is inside before deleting it." `
                -Target $sf2.FullName -FixAction "Info" -Group "Exfiltration Staging"
            break
        }
    }
    if ($exfHits -eq 0) { Out-Typewriter "  -> [OK ] NO EXFILTRATION STAGING INDICATORS." "GOOD" }

    # ── PHASE 130: CHAT / PASTE-SITE C2 & WEBHOOK EXFIL ───────────────────────
    Show-PhaseHeader "PHASE 130" "CHAT & PASTE-SITE C2 / WEBHOOK EXFILTRATION STRINGS" "C2"
    Out-Typewriter "SEARCHING USER-PATH FILES AND LIVE COMMAND LINES FOR WEBHOOK C2..." "HUNT"
    $whHits = 0
    # Modern stealers need no infrastructure at all: they POST the loot to a Discord
    # webhook or a Telegram bot. Both are TLS to a domain no corporate proxy blocks, so
    # the hard-coded URL inside the payload is often the only network-side evidence.
    $whRoots = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:PUBLIC)
    $whExt   = @('.ps1','.psm1','.bat','.cmd','.vbs','.vbe','.js','.jse','.wsf','.hta','.py','.au3','.ahk','.exe','.dll','.scr','.txt','.json','.xml','.lnk')
    $whFiles = @((Get-ScanFiles -Path $whRoots -TimeScoped))
    foreach ($wf in @($whFiles | Where-Object { ($whExt -contains $_.Extension.ToLower()) -and $_.Length -gt 32 -and $_.Length -lt 20MB } | Select-Object -First 400)) {
        if ($wf.FullName -match $WEBHOOK_BENIGN_RE) { continue }
        $wr = Test-ContentRules -FilePath $wf.FullName -Rules $WEBHOOK_C2_RULES -MaxBytes 20971520
        if (-not $wr.Hit) { continue }
        $whHits++
        $wsev = switch ("$($wr.Severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
        # A chat-webhook URL embedded in the chat client's OWN program files is the
        # token-stealer signature and cannot be a legitimate part of the client.
        $inClientCore = ($wf.FullName -match '(?i)\\AppData\\(Local|Roaming)\\(discord|discordcanary|discordptb|Slack|Microsoft\\Teams)\\' -and
                         "$($wr.Name)" -match '(?i)Webhook')
        $wfix = if ($inClientCore) { "Quarantine" } else { "Info" }
        $wparam = if ($wfix -eq "Quarantine") { $wf.FullName } else { "" }
        Out-ThreatBanner "WEBHOOK C2 / EXFIL STRING" "$($wr.Name) -> $($wf.Name)"
        Add-Finding -ID "WH130_$([Math]::Abs("$($wf.FullName)$($wr.Name)".GetHashCode()))" -Phase "PHASE 130" `
            -ThreatType "C2 / Data Exfiltration" -Severity $wsev `
            -Description "Rule '$($wr.Name)' matched in '$($wf.FullName)' — a hard-coded chat webhook, bot token or paste-site raw URL. Stealers use these as a zero-infrastructure C2 and exfil channel.$(if($inClientCore){' It is embedded in the chat client''s OWN program directory, which no legitimate build does — this is a token stealer patched into the client, and it is quarantined (reversibly).'}else{' Extract the URL, block it at the perimeter, and treat anything this file touched as exposed.'})" `
            -Target $wf.FullName -FixAction $wfix -FixParam $wparam -Group "Webhook C2 / Exfil"
        $global:SpywareHits++
    }
    foreach ($wp in $raProcs) {
        $wcl = "$($wp.CommandLine)"
        if (-not $wcl) { continue }
        foreach ($wr2 in @($WEBHOOK_C2_RULES)) {
            if ($wcl -notmatch $wr2.Pattern) { continue }
            $whHits++
            $wclShort = $wcl.Substring(0, [Math]::Min(180, $wcl.Length))
            Add-Finding -ID "WHP130_$($wp.ProcessId)_$($wr2.Name)" -Phase "PHASE 130" `
                -ThreatType "C2 / Data Exfiltration" -Severity $SEV_CRITICAL `
                -Description "LIVE process $($wp.Name) (PID $($wp.ProcessId)) has a webhook/bot C2 URL on its command line ('$($wr2.Name)'): $wclShort. This is exfiltration in progress or a beacon running right now." `
                -Target "PID:$($wp.ProcessId)" -FixAction "Info" -Group "Webhook C2 / Exfil"
            break
        }
    }
    if ($whHits -eq 0) { Out-Typewriter "  -> [OK ] NO WEBHOOK OR PASTE-SITE C2 STRINGS." "GOOD" }

    # ── PHASE 131: AUTOIT / PACKED-SCRIPT DROPPER AUDIT ───────────────────────
    Show-PhaseHeader "PHASE 131" "AUTOIT / PACKED-SCRIPT DROPPER AUDIT" "DROPPER"
    Out-Typewriter "LOOKING FOR SCRIPT INTERPRETERS AND COMPILED SCRIPT BLOBS IN USER PATHS..." "HUNT"
    $psdHits = 0
    # The interpreter is signed and clean; the malice lives in the script blob beside it.
    # That is the entire point of the technique — an AV verdict on the EXE tells you
    # nothing, so the pairing is what has to be detected.
    $psdRoots = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:PUBLIC, $env:PROGRAMDATA)
    $psdFiles = @((Get-ScanFiles -Path $psdRoots -TimeScoped))
    $psdInterpDirs = @{}
    foreach ($pf2 in @($psdFiles | Select-Object -First 4000)) {
        if ($pf2.FullName -match $PACKEDSCRIPT_BENIGN_RE) { continue }
        $pfExt = $pf2.Extension.ToLower()
        foreach ($pi in @($PACKED_SCRIPT_INDICATORS)) {
            if ("$($pi.Ext)".ToLower() -ne $pfExt) { continue }
            if ($pi.NameRx -and $pf2.Name -notmatch "$($pi.NameRx)") { continue }
            if ($pi.ContentRx) {
                # Content probe only for the packer-marker rule, and only on small files.
                if ($pf2.Length -gt 40MB) { continue }
                $pfText = $null
                try {
                    $pfBytes = [System.IO.File]::ReadAllBytes($pf2.FullName)
                    $pfText  = [System.Text.Encoding]::ASCII.GetString($pfBytes)
                } catch { continue }
                if (-not $pfText -or $pfText -notmatch "$($pi.ContentRx)") { continue }
            }
            if (-not $pi.NameRx -and -not $pi.ContentRx -and $pfExt -eq '.exe') { continue }
            $psdsev = switch ("$($pi.Severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
            if ($pi.NameRx) { $psdInterpDirs["$($pf2.DirectoryName)".ToLower()] = "$($pi.Name)" }
            $psdHits++
            Add-Finding -ID "PSD131_$([Math]::Abs("$($pf2.FullName)$($pi.Name)".GetHashCode()))" -Phase "PHASE 131" `
                -ThreatType "Packed-Script Dropper" -Severity $psdsev `
                -Description "'$($pi.Name)' matched '$($pf2.FullName)' — $($pi.Why). Written $($pf2.LastWriteTime). Check whether a matching script blob sits in the same directory; the interpreter on its own is legitimate software." `
                -Target $pf2.FullName -FixAction "Info" -Group "Packed-Script Droppers"
            break
        }
    }
    # Interpreter + script in the SAME directory is the dropper pairing, not a coincidence.
    foreach ($pf3 in @($psdFiles | Where-Object { $_.Extension -match '(?i)^\.(a3x|ahk|au3)$' } | Select-Object -First 200)) {
        $pdir = "$($pf3.DirectoryName)".ToLower()
        if (-not $psdInterpDirs.ContainsKey($pdir)) { continue }
        if ($pf3.FullName -match $PACKEDSCRIPT_BENIGN_RE) { continue }
        $psdHits++
        Out-ThreatBanner "SCRIPT DROPPER PAIRING" "$($pf3.Name) + $($psdInterpDirs[$pdir])"
        Add-Finding -ID "PSDPAIR131_$([Math]::Abs($pf3.FullName.GetHashCode()))" -Phase "PHASE 131" `
            -ThreatType "Packed-Script Dropper" -Severity $SEV_HIGH `
            -Description "Script blob '$($pf3.FullName)' sits in the same user-writable directory as a dropped '$($psdInterpDirs[$pdir])'. A signed interpreter plus its own script in Temp/AppData is the standard compiled-script dropper layout — the EXE will pass every AV check because the payload is the script beside it. Quarantine both together: Move-Item -LiteralPath '$($pf3.FullName)' <vault>" `
            -Target $pf3.FullName -FixAction "Info" -Group "Packed-Script Droppers"
        $global:TrojanHits++
    }
    if ($psdHits -eq 0) { Out-Typewriter "  -> [OK ] NO PACKED-SCRIPT DROPPER ARTIFACTS." "GOOD" }

    # ── PHASE 132: WEB SHELL & IIS / EXCHANGE BACKDOOR SCAN ───────────────────
    Show-PhaseHeader "PHASE 132" "WEB SHELL & IIS / EXCHANGE BACKDOOR SCAN" "WEBSHELL"
    Out-Typewriter "SCANNING WEB ROOTS AND EXCHANGE AUTH DIRECTORIES..." "HUNT"
    $wsHits = 0
    $wsRoots = @($WEBSHELL_ROOTS | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($wsRoots.Count -eq 0) {
        Out-Typewriter "  -> [OK ] NO WEB SERVER OR EXCHANGE CONTENT ON THIS MACHINE." "GOOD"
    } else {
        $wsFiles = @((Get-ScanFiles -Path $wsRoots -MaxFiles 12000 -DeadlineSecs 25))
        foreach ($wsf in @($wsFiles | Where-Object { ($WEBSHELL_EXTENSIONS -contains $_.Extension.ToLower()) -and $_.Length -lt 3MB } | Select-Object -First 800)) {
            $wsr = Test-ContentRules -FilePath $wsf.FullName -Rules $WEBSHELL_CONTENT_RULES
            if (-not $wsr.Hit) { continue }
            $wsHits++
            $wssev = switch ("$($wsr.Severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
            # Exchange's own auth directories are the ProxyShell/ProxyLogon drop site and
            # should contain no attacker-authored script at all.
            $inAuthDir = ($wsf.FullName -match '(?i)\\(FrontEnd\\HttpProxy\\(owa|ecp)\\auth|ClientAccess\\OAB)\\')
            Out-ThreatBanner "WEB SHELL" "$($wsr.Name) -> $($wsf.Name)"
            Add-Finding -ID "WS132_$([Math]::Abs("$($wsf.FullName)$($wsr.Name)".GetHashCode()))" -Phase "PHASE 132" `
                -ThreatType "Web Shell / Server Backdoor" -Severity $wssev `
                -Description "Web-shell rule '$($wsr.Name)' matched '$($wsf.FullName)' (written $($wsf.LastWriteTime)) — the file takes a value straight from the HTTP request and executes it, which no legitimate page does.$(if($inAuthDir){' It is inside an Exchange auth directory, the classic ProxyShell/ProxyLogon drop site — assume the server was exploited, not just infected.'}else{''}) Preserve it as evidence, then remove it and rotate every credential that server could reach. Quarantine command: Move-Item -LiteralPath '$($wsf.FullName)' <vault>" `
                -Target $wsf.FullName -FixAction "Info" -Group "Web Shells"
            $global:TrojanHits++
        }
        if ($wsHits -eq 0) { Out-Typewriter "  -> [OK ] NO WEB SHELLS IN THE SCANNED WEB ROOTS." "GOOD" }
    }

    # ── PHASE 133: WIPER / DESTRUCTIVE PAYLOAD & LATERAL-MOVEMENT ARTIFACTS ───
    Show-PhaseHeader "PHASE 133" "WIPER / DESTRUCTIVE PAYLOAD & LATERAL-MOVEMENT ARTIFACTS" "DESTRUCTIVE"
    Out-Typewriter "CHECKING FOR DESTRUCTIVE INTENT AND EVIDENCE OF REMOTE EXECUTION..." "HUNT"
    $dwHits = 0
    foreach ($dp in $raProcs) {
        $dpn = "$($dp.Name)".ToLower() -replace '\.exe$',''
        foreach ($wpn in @($WIPER_PROCS)) {
            if ($dpn -notmatch [regex]::Escape("$wpn")) { continue }
            $dwHits++
            Out-ThreatBanner "WIPER PROCESS" "$($dp.Name) PID:$($dp.ProcessId)"
            Add-Finding -ID "WIPE133_$($dp.ProcessId)" -Phase "PHASE 133" `
                -ThreatType "Wiper / Destructive Malware" -Severity $SEV_CRITICAL `
                -Description "Process '$($dp.Name)' (PID $($dp.ProcessId)) matches the known wiper family IOC '$wpn'. A wiper is not ransomware — there is no key and no recovery, so the response is to isolate the machine and restore from backup, not to negotiate or to wait. Kill it NOW if it is still running: Stop-Process -Id $($dp.ProcessId) -Force" `
                -Target "PID:$($dp.ProcessId)" -FixAction "Info" -Group "Destructive Payloads"
            break
        }
        $dcl = "$($dp.CommandLine)"
        if ($dcl) {
            foreach ($dr in @($DESTRUCTIVE_BEHAVIOR_RULES)) {
                if ($dcl -notmatch $dr.Pattern) { continue }
                $dwHits++
                $dsev = switch ("$($dr.Severity)") { "CRITICAL" { $SEV_CRITICAL } "HIGH" { $SEV_HIGH } default { $SEV_POSSIBLE } }
                $dclShort = $dcl.Substring(0, [Math]::Min(180, $dcl.Length))
                Add-Finding -ID "DESTR133_$($dp.ProcessId)_$($dr.Name)" -Phase "PHASE 133" `
                    -ThreatType "Wiper / Destructive Malware" -Severity $dsev `
                    -Description "Process $($dp.Name) (PID $($dp.ProcessId)) matched destructive rule '$($dr.Name)' — $($dr.Why). Command line: $dclShort" `
                    -Target "PID:$($dp.ProcessId)" -FixAction "Info" -Group "Destructive Payloads"
                break
            }
            foreach ($lm in @($LATERAL_MOVEMENT_ARTIFACTS)) {
                if ("$($lm.Rx)" -notmatch '\\b|\\\\' ) { continue }   # name-shaped rules are handled against files below
                if ($dcl -notmatch $lm.Rx) { continue }
                $dwHits++
                $lmsev = switch ("$($lm.Severity)") { "HIGH" { $SEV_HIGH } "CRITICAL" { $SEV_CRITICAL } default { $SEV_POSSIBLE } }
                $dclShort2 = $dcl.Substring(0, [Math]::Min(180, $dcl.Length))
                Add-Finding -ID "LATM133_$($dp.ProcessId)_$([Math]::Abs("$($lm.Name)".GetHashCode()))" -Phase "PHASE 133" `
                    -ThreatType "Lateral Movement" -Severity $lmsev `
                    -Description "Lateral-movement indicator '$($lm.Name)' on process $($dp.Name) (PID $($dp.ProcessId)) — $($lm.Why). Command line: $dclShort2. On a single endpoint this is evidence the box was reached FROM somewhere else, which widens the incident from one machine to the network." `
                    -Target "PID:$($dp.ProcessId)" -FixAction "Info" -Group "Lateral Movement"
                break
            }
        }
    }
    # PsExec-class service binaries land in System32 when someone executes remotely.
    $sysRoot = Join-Path $env:WINDIR 'System32'
    if (Test-Path -LiteralPath $sysRoot) {
        foreach ($sysf in @(Get-ChildItem -LiteralPath $sysRoot -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                            Where-Object { Test-InScope $_.CreationTime } | Select-Object -First 400)) {
            foreach ($lm2 in @($LATERAL_MOVEMENT_ARTIFACTS)) {
                if ("$($lm2.Rx)" -notmatch '^\(\?i\)\^') { continue }   # only the filename-shaped rules
                if ($sysf.Name -notmatch $lm2.Rx) { continue }
                $dwHits++
                Out-ThreatBanner "REMOTE-EXECUTION ARTIFACT" "$($sysf.Name)"
                Add-Finding -ID "LATF133_$([Math]::Abs($sysf.FullName.GetHashCode()))" -Phase "PHASE 133" `
                    -ThreatType "Lateral Movement" -Severity $(switch ("$($lm2.Severity)") { "HIGH" { $SEV_HIGH } "CRITICAL" { $SEV_CRITICAL } default { $SEV_POSSIBLE } }) `
                    -Description "'$($sysf.FullName)' (created $($sysf.CreationTime)) matches '$($lm2.Name)' — $($lm2.Why). Correlate the creation time with the Phase 107 service-install (7045) and logon (4624) events to find who connected and from where." `
                    -Target $sysf.FullName -FixAction "Info" -Group "Lateral Movement"
                break
            }
        }
    }
    if ($dwHits -eq 0) { Out-Typewriter "  -> [OK ] NO DESTRUCTIVE OR LATERAL-MOVEMENT ARTIFACTS." "GOOD" }

    Out-Typewriter "  -> EXTENDED MALWARE & TAMPER BAND COMPLETE (PHASES 116-133)." "VER"
}
