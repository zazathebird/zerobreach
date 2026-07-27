trap { Write-RecoveredError $_; continue }   # module-level resilience: a terminating error resumes at the NEXT phase in THIS module, not the next dot-sourced module (see CLAUDE.md engine-split rule)

# ══════════════════════════════════════════════════════════════════════════════
#  EVENT-LOG EVIDENCE HELPERS  (EVIDENCE_ENGINE_PLAN P2 / P3)
# ══════════════════════════════════════════════════════════════════════════════
# Module-scope helpers for Phase 107. Declared at the top of the module (after the
# resilience trap) so they exist regardless of which $PhasePlan blocks run.
# Names are $zb*/Get-Zb* prefixed: the engine is ONE dot-sourced scope and a local
# that happens to share letters with a loader param() silently reassigns it.

function Get-ZbEvtField {
    # Extract one <Data Name="X"> value from an EventLogRecord's raw XML, by NAME.
    #
    # Why not `[xml]$ev.ToXml()` (what Phase 107 shipped, TWICE per event): building an
    # XmlDocument per record costs ~26 ms/event on a real box. Measured live 2026-07-26
    # over 400 real Security/4624 records on this machine:
    #     [xml] DOM + Where-Object  10,278 ms
    #     ToXml() string + regex       124 ms   <- this function (83x faster)
    #     .Properties[n].Value          73 ms
    # Why not .Properties[n]: fastest, but POSITIONAL — the index of IpAddress within
    # 4624 is not a documented contract across Windows builds/locales, and a silent
    # off-by-one reads the wrong field with no error. Name-anchored is version-proof.
    # Why not $_.Message: it is a localised, human-formatted blob rendered by the
    # provider message DLL — matching detection regexes against it is locale-dependent
    # and matches decoration rather than field values.
    param([string]$Xml, [string]$Name)
    if (-not $Xml -or -not $Name) { return '' }
    $zbM = [regex]::Match($Xml, ('<Data Name=[''"]{0}[''"]\s*>(.*?)</Data>' -f [regex]::Escape($Name)), 'Singleline')
    if (-not $zbM.Success) { return '' }          # absent OR self-closing <Data Name="X"/> — both mean "no value"
    $zbV = $zbM.Groups[1].Value
    if (-not $zbV) { return '' }
    # ToXml() XML-escapes the payload; the [xml] path used to un-escape it for us.
    try { return [System.Net.WebUtility]::HtmlDecode($zbV) } catch { }
    return ((($zbV -replace '&lt;','<') -replace '&gt;','>' -replace '&quot;','"' -replace '&apos;',"'") -replace '&amp;','&')
}

function Get-ZbEvtQuery {
    # EVIDENCE_ENGINE_PLAN P2. Build a Get-WinEvent FilterHashtable with the engine's
    # -Hours window pushed INSIDE it.
    #
    # The bug this fixes: `Get-WinEvent -FilterHashtable @{...} -MaxEvents 2000 |
    # Where-Object { Test-InScope $_.TimeCreated }` takes the newest N records and THEN
    # applies the time filter, so on a busy box the operator's -Hours window silently
    # collapses to however far back N records happen to reach. Measured on this box
    # 2026-07-26: the newest 2000 x 4624 spanned 24.02 hours — i.e. a -Hours 24 scan was
    # already AT the truncation boundary, and any busier endpoint (or -Hours 48/168)
    # would have been quietly cut short with no warning anywhere.
    # StartTime inside the hashtable is compiled to server-side XPath and evaluated by
    # the EventLog service: correct AND cheaper (9.9s vs 14.2s for the same 552 results).
    #
    # Record caps (rule: every bulk loop carries a budget). When the query is time-bounded
    # the window itself is the bound, so the cap can be generous; with -Hours 0 (all time)
    # there is no bound at all, so the original newest-N sampling caps are retained.
    param([hashtable]$Filter, [int]$MaxScoped = 20000, [int]$MaxAllTime = 2000)
    $zbF = @{}
    foreach ($zbK in $Filter.Keys) { $zbF[$zbK] = $Filter[$zbK] }
    $zbMax = $MaxAllTime
    if ($null -ne $global:TIME_LIMIT -and $global:TIME_LIMIT -ne [datetime]::MinValue) {
        $zbF['StartTime'] = $global:TIME_LIMIT
        $zbMax = $MaxScoped
    }
    return @{ Filter = $zbF; Max = $zbMax; Scoped = ($zbF.ContainsKey('StartTime')) }
}

function Get-ZbProcAuditState {
    # EVIDENCE_ENGINE_PLAN P3. "Audit Process Creation" is OFF by default on Win10/11, and
    # command-line capture is a SECOND, INDEPENDENT policy. With either off, Phase 107's
    # 4688 regexes cannot possibly match — yet the phase printed "0 SUSPICIOUS 4688 PROCESS
    # EVENTS" in green, which is a lie: it is "we cannot see", not "nothing happened".
    #
    # Returns @{ Audit='ON'|'OFF'|'UNKNOWN'; AuditWhy; CmdLine='ON'|'OFF'; CmdLineRaw }
    #
    # Three sources, weakest last:
    #  1. Registry (Get-RegVal, never raw Get-ItemPropertyValue) for the cmdline policy.
    #  2. EMPIRICAL: does the Security log hold ANY 4688 at all? One record, no time bound.
    #     This is the only signal that cannot be wrong about what was really recorded, and
    #     it is completely locale- and policy-plumbing-independent.
    #  3. auditpol, matched on the subcategory GUID (stable worldwide) rather than the
    #     subcategory NAME (localised). The inclusion-setting VALUE is still localised, so
    #     it is only ever allowed to say OFF, never to override the empirical evidence, and
    #     an unrecognised value degrades to UNKNOWN — never to a clean result.
    $zbR = @{ Audit = 'UNKNOWN'; AuditWhy = ''; CmdLine = 'OFF'; CmdLineRaw = $null }

    $zbCl = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
    $zbR.CmdLineRaw = $zbCl
    if ($null -ne $zbCl -and "$zbCl" -eq '1') { $zbR.CmdLine = 'ON' }

    $zbAny4688 = @(Get-WinEventSafe @{LogName='Security'; Id=4688} -MaxEvents 1)

    $zbIncl = $null
    try {
        $zbApExe = Join-Path $env:SystemRoot 'System32\auditpol.exe'
        if (Test-Path -LiteralPath $zbApExe) {
            $zbAp = & $zbApExe /get "/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}" /r 2>$null
            foreach ($zbLn in @($zbAp)) {
                if ("$zbLn" -match '(?i)0CCE922B-69AE-11D9-BED3-505054503030') {
                    $zbCols = "$zbLn" -split ','
                    if ($zbCols.Count -ge 5) { $zbIncl = "$($zbCols[4])".Trim() }
                }
            }
        }
    } catch { $zbIncl = $null }

    # Localised "no auditing" vocabulary lives in data (AMSI rule); the English form is the
    # documented fallback so an absent key degrades to "cannot classify", not "clean".
    $zbOffRe = if (@(Get-Sig 'audit_policy_disabled_regex').Count) { @(Get-Sig 'audit_policy_disabled_regex')[0] } else { '(?i)^(no auditing|none)$' }

    if ($zbAny4688.Count -gt 0) {
        $zbR.Audit    = 'ON'
        $zbR.AuditWhy = 'the Security log contains 4688 records, so process-creation auditing is genuinely recording'
    } elseif ($null -eq $zbIncl) {
        $zbR.Audit    = 'UNKNOWN'
        $zbR.AuditWhy = 'auditpol output could not be read, and the Security log holds no 4688 records'
    } elseif ($zbIncl -eq '' -or $zbIncl -match $zbOffRe) {
        $zbR.Audit    = 'OFF'
        $zbR.AuditWhy = "auditpol reports Process Creation = '$zbIncl' (the Win10/11 default)"
    } else {
        $zbR.Audit    = 'UNKNOWN'
        $zbR.AuditWhy = "auditpol reports Process Creation = '$zbIncl', but the Security log holds no 4688 records at all (policy only just enabled, log cleared, or the value is a locale this build does not recognise)"
    }
    return $zbR
}

if ($PhasePlan.Advanced) {
    trap { Write-RecoveredError $_; continue }   # localize faults: resume at next phase, not end-of-group
    if (-not $global:STEALTH_MODE) {
        Write-Host ""
        Write-Host ("▓"*80) -ForegroundColor DarkMagenta
        Write-Host "    ◈  A D V A N C E D   T H R E A T   H U N T  —  P H A S E S  9 0 - 1 0 5" -ForegroundColor Magenta
        Write-Host ("▓"*80) -ForegroundColor DarkMagenta
        Invoke-QuantumBar "ENGAGING ADVANCED PERSISTENT THREAT MODULE" 20 90
    }

    # ── PHASE 90: YARA-LITE STRING SCAN + CUSTOM IOC HASH CHECK ───────────────
    if (Test-PhaseGate 90) {
    Show-PhaseHeader "PHASE 90" "YARA-LITE BINARY STRING SCAN & CUSTOM IOC HASHES" "YARA-LITE"
    Out-Typewriter "SCANNING USER-PATH BINARIES FOR MALWARE STRINGS..." "HUNT"
    Invoke-QuantumBar "BINARY STRING ANALYSIS" 18 90
    # ORDER MATTERS: Get-ScanFiles walks these in sequence under ONE shared file/wall-clock budget,
    # so whatever is last is simply never reached on a busy box (measured: the walk hit its 20,000
    # file cap and the sniff hit its deadline long before Downloads). Downloads and Desktop are the
    # delivery locations this content pass exists for — a real banking trojan sat in Downloads as
    # *.exe.vir — so they go FIRST. %TEMP% is a subtree of %LOCALAPPDATA% and the noisiest, so it
    # goes last (it is still covered, and Phase 10 sweeps the temp dirs independently).
    #
    # P1 multi-user: those five roots were the ELEVATED process's OWN environment, i.e. the
    # TECHNICIAN's profile on a standard-user endpoint — the deepest content-inspection pass in
    # the whole engine was reading the wrong person's Downloads and reporting the infected
    # profile clean. Roots are now collected for EVERY reachable profile and handed to the SAME
    # single Get-ScanFiles call, so the shared file/wall-clock budget is NOT multiplied by the
    # profile count (a per-profile call would be 8 x 20s on an 8-profile box). The ORDER
    # rationale above is preserved ACROSS profiles: every profile's Downloads+Desktop first,
    # then every profile's AppData/LocalAppData, then every profile's Temp last.
    # Get-UserPaths is memoized per SID, so the three passes cost one resolution per profile.
    $zbYaraHives  = @(@(Get-UserHives) | Sort-Object -Property Sid)   # SID order = stable memo key
    $zbYaraOwners = @{}    # lowercased root -> owning user, for attributing each hit back
    $yaraRoots    = @()
    foreach ($zbHive in $zbYaraHives) {
        if (-not $zbHive.ProfileReachable) { continue }   # never re-probe: 42s UNC stalls
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbR in @($zbUp.Downloads, $zbUp.Desktop)) {
            if (-not $zbR) { continue }
            $yaraRoots += $zbR
            $zbYaraOwners["$zbR".ToLowerInvariant()] = "$($zbHive.User)"
        }
    }
    foreach ($zbHive in $zbYaraHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbR in @($zbUp.AppData, $zbUp.LocalAppData)) {
            if (-not $zbR) { continue }
            $yaraRoots += $zbR
            $zbYaraOwners["$zbR".ToLowerInvariant()] = "$($zbHive.User)"
        }
    }
    foreach ($zbHive in $zbYaraHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        if (-not $zbUp.Temp) { continue }
        $yaraRoots += $zbUp.Temp
        $zbYaraOwners["$($zbUp.Temp)".ToLowerInvariant()] = "$($zbHive.User)"
    }
    $yaraRoots = @($yaraRoots | Select-Object -Unique)
    $yaraExt   = @(".exe",".com",".dll",".scr",".ps1",".vbs",".js",".hta",".bat",".cmd",".bin",".htm",".html",".jse",".vbe",".wsf",".svg")
    # Self-detection fix (2026-07-27, live-caught in P1 grading): five of the shipped rules are
    # bare THREAT-ACTOR-TOOL-NAME lists (no shellcode/hex, no encoded-blob, no invocation syntax),
    # so ANY text file that merely NAMES the tool — a comment, a finding description, another
    # security tool's OWN detection signatures, this engine's OWN source — matches identically to
    # a real delivered attack script. Proven live: this engine's own Phases-1.ps1 (Phase 48's WDigest
    # finding text says "mimikatz target") and Phases-3.ps1 (a Phase 107 comment says "Mimikatz-class")
    # both contain the bare word "mimikatz", so a Downloads-folder copy of ZeroBreach ITSELF — or any
    # other MSP/IR script that documents what it detects — was auto-Quarantined by Mimikatz_Strings.
    # Scoped to SCRIPT/TEXT extensions only: a real compiled .exe/.dll/.scr/.bin containing the bare
    # word "mimikatz" is a much rarer, much stronger signal and is NOT touched by this carve-out.
    $YARA_NAME_ONLY_RULES = @("Mimikatz_Strings","Meterpreter_Strings","Sliver_Implant","Lazagne_Stealer","WinPwn_Recon")
    $YARA_TEXT_ONLY_EXT   = @(".ps1",".vbs",".js",".jse",".vbe",".wsf",".hta",".bat",".cmd")
    $yaraHits  = 0
    $trojSigSeen = 0; $trojSigSw = [System.Diagnostics.Stopwatch]::StartNew()   # SIG_AUDIT budget (P90 name loop)
    # SIG_AUDIT budget for the YARA-hit Authenticode gate below. Deliberately created
    # STOPPED and Start()/Stop()ed around each Get-AuthSig call, so it measures CUMULATIVE
    # TIME SPENT IN AUTHENTICODE, not wall-clock since the phase began.
    # Why that matters (measured live 2026-07-26): the YARA gate does not run until AFTER the
    # magic-byte sniff and the per-file content read, which on this box take ~220s. A
    # StartNew()-at-phase-entry stopwatch is therefore already 200s past a 25s deadline when
    # the FIRST hit arrives, so the budget check is never once satisfied and not a single
    # signature is verified — the gate would then downgrade every hit, signed or not, as
    # "unverified" and quietly destroy the phase's real coverage. Cumulative call time bounds
    # exactly the cost the budget exists for (Authenticode's ~15s CRL/OCSP blocks) and is a
    # strictly tighter bound than wall-clock: BOTH the count cap and the time cap still apply.
    # NOTE: $trojSigSw above is a StartNew() wall-clock stopwatch with this same defect and is
    # left alone here (it gates a different detection that needs its own grading) — see the
    # report accompanying this change.
    $yaraSigSeen = 0; $yaraSigSw = New-Object System.Diagnostics.Stopwatch
    # Single bounded walk across all roots (was per-root recursion x5, -First 200 each).
    # Assigned to a variable first, never piped directly — Get-ScanFiles returns ,$arr (CLAUDE.md).
    $allScanned = Get-ScanFiles -Path $yaraRoots -TimeScoped

    # Extension match is the CHEAP first pass. It is no longer the only way in: a payload that is
    # renamed (.vir/.dat/.tmp), shipped extensionless, or given any extension not on this list used
    # to skip the YARA strings pass, the content rules AND the known-malware hash check entirely.
    # See Test-IsPeFile's comment for the live proof. Content now decides, not the filename.
    $byExt = @($allScanned | Where-Object { ($yaraExt -contains $_.Extension.ToLower()) -and $_.Length -lt 10MB })

    # Magic-byte pass over everything the extension list did NOT already claim. Sniffing reads 8
    # bytes per file, but on a real box these roots hold thousands of files, so it carries the same
    # deadline+count budget convention as the Get-AuthSig loops (see Phase 10/93/96/98).
    $magicSeen = 0; $magicSw = [System.Diagnostics.Stopwatch]::StartNew()
    $MAGIC_MAX_FILES = 4000; $MAGIC_DEADLINE_S = 45
    $byMagic = @()
    $magicBudgetHit = $false
    foreach ($f in $allScanned) {
        if ($magicSeen -ge $MAGIC_MAX_FILES -or $magicSw.Elapsed.TotalSeconds -ge $MAGIC_DEADLINE_S) { $magicBudgetHit = $true; break }
        if ($f.Length -ge 10MB -or $f.Length -lt 64) { continue }
        if ($yaraExt -contains $f.Extension.ToLower()) { continue }
        $magicSeen++
        if (Test-IsPeFile $f.FullName) { $byMagic += $f }
    }
    $magicSw.Stop()
    if ($magicBudgetHit) {
        Out-Typewriter ("  -> [INFO] MAGIC-BYTE SNIFF BUDGET REACHED ({0} files / {1}s) — partial." -f $magicSeen, [Math]::Round($magicSw.Elapsed.TotalSeconds,1)) "WARN"
    }

    # A real PE binary wearing a non-executable extension in a user staging dir is masquerading —
    # a strong, low-FP signal on its own. HIGH so it is impossible to miss, but FixAction Info:
    # rule #1 forbids shipping a destructive action that an auto-select could fire on a healthy
    # box, and a renamed-binary heuristic is exactly the kind of thing that needs a human look
    # first (installers legitimately ship payload blobs). Same HIGH+Info shape as Phase 10.5.
    # NOTE: Phase 10 mints the IDENTICAL MASQPE_<stableid> for files in the temp/download dirs both
    # phases cover, and Add-Finding dedupes by ID — so for those the call below is a silent no-op.
    # The counters must therefore NOT be incremented unconditionally, or the GUI's Trojan threat
    # counter double-counts every file both phases saw (caught in review 2026-07-26). Compare the
    # finding count before/after and only count what was actually added.
    # Owner attribution is by longest-prefix match on the ROOTS we built, not on ProfilePath:
    # folder redirection genuinely moves Downloads/Desktop/AppData onto a file server OUTSIDE
    # the profile root, and a ProfilePath test would then mislabel a real per-user hit as
    # [MACHINE]. The roots came from Get-UserPaths, so they are authoritative either way.
    foreach ($mf in $byMagic) {
        $zbOwner = 'MACHINE'; $zbOwnerLen = -1
        foreach ($zbK in @($zbYaraOwners.Keys)) {
            if ("$($mf.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                $zbOwner = $zbYaraOwners[$zbK]; $zbOwnerLen = $zbK.Length
            }
        }
        $beforeCount = $global:AuditFindings.Count
        Add-Finding -ID "MASQPE_$(Get-StableId $mf.FullName)" -Phase "PHASE 90" `
            -ThreatType "Masquerading Executable" -Severity $SEV_HIGH `
            -Description "[$zbOwner] File is a real Windows PE executable but carries a non-executable extension ('$($mf.Extension)') in a user staging path: $($mf.FullName) — classic rename-to-evade delivery. Review before acting." `
            -Target "[$zbOwner] $($mf.FullName)" -FixAction "Info" -Group "Masquerading Executables"
        if ($global:AuditFindings.Count -gt $beforeCount) { $yaraHits++; $global:TrojanHits++ }
    }
    if ($byMagic.Count -gt 0) { Out-Typewriter "  -> $($byMagic.Count) MISNAMED PE BINAR(IES) FOUND BY CONTENT." "WARN" }

    # Cap raised 200 -> 600: the old cap silently limited the DEEPEST content inspection in the
    # whole engine to an arbitrary 200-file subset across FIVE roots (TEMP, LOCALAPPDATA, APPDATA,
    # Downloads, Desktop) — trivially exceeded on any real box. The two sources get SEPARATE caps:
    # a single flood can otherwise crowd the other out entirely (600 magic hits on a Python/Store
    # heavy box would stop the extension-based YARA pass from running at all, and vice versa).
    $candidates = @(@($byMagic | Select-Object -First 200) + @($byExt | Select-Object -First 400))

    # Files that got here ONLY because of the magic-byte sniff were never previously subject to
    # this loop's pre-existing auto-destructive outcomes (YARA -> CRITICAL/HIGH + DeleteFile).
    # Two of the shipped YARA rules match plain PE IMPORT-TABLE strings (WMI_Reflective matches
    # VirtualAllocEx/WriteProcessMemory/CreateRemoteThread; UAC_Bypass_FodHelper matches any
    # binary that merely references eventvwr.exe), and installer bootstrappers, anti-cheat shims
    # and .NET hosting stubs legitimately contain those. An unsigned extensionless PE staged in
    # %TEMP% by a normal installer would therefore have become a HIGH + DeleteFile AUTO-SELECTED
    # finding on a healthy box — rule #1. Newly-reachable files are review-only; nothing is lost,
    # because every one of them already carries its own HIGH masquerade finding.
    $magicOnly = @{}
    foreach ($m in $byMagic) { $magicOnly[$m.FullName] = $true }
        foreach ($cand in $candidates) {
            # Attribute this candidate back to the profile whose root it came from (see the
            # comment above the $byMagic loop for why this keys on the roots, not ProfilePath).
            $zbOwner = 'MACHINE'; $zbOwnerLen = -1
            foreach ($zbK in @($zbYaraOwners.Keys)) {
                if ("$($cand.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                    $zbOwner = $zbYaraOwners[$zbK]; $zbOwnerLen = $zbK.Length
                }
            }
            try {
                $bytes = [System.IO.File]::ReadAllBytes($cand.FullName)
                $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
                foreach ($rule in $YARA_LITE_RULES) {
                    if ($text -match $rule.Pattern) {
                        # JIT/renderer runtime DLLs (SwiftShader etc.) legitimately contain
                        # VirtualAllocEx-class API strings; allowlisted paths are review-only.
                        if (Test-BenignPath $cand.FullName $YARA_BENIGN_RE) {
                            # P1: the ID was YARA_<rule>_<FILENAME>. With per-profile roots the same
                            # leaf name in two profiles hashed to ONE id and Add-Finding's de-dupe
                            # silently dropped the second user's hit — worse than not migrating.
                            # Hashing the full path makes it per-profile for free.
                            Add-Finding -ID "YARA_$($rule.Name)_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                                -ThreatType "YARA-Lite Match" -Severity $SEV_POSSIBLE `
                                -Description "[$zbOwner] YARA rule '$($rule.Name)' matched an allowlisted runtime/library file (JIT renderers legitimately contain these API strings — review only): $($cand.FullName)" `
                                -Target "[$zbOwner] $($cand.FullName)" -FixAction "Info" -Group "YARA-Lite Matches"
                            $yaraHits++; break
                        }
                        if ($magicOnly.ContainsKey($cand.FullName)) {
                            # Reachable only because of the magic-byte sniff — review-only (see the
                            # $magicOnly comment above; rule #1). It already carries a HIGH
                            # masquerade finding, so the operator still sees it prominently.
                            Add-Finding -ID "YARA_$($rule.Name)_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                                -ThreatType "YARA-Lite Match" -Severity $SEV_POSSIBLE `
                                -Description "[$zbOwner] YARA rule '$($rule.Name)' matched a file identified as an executable by CONTENT rather than extension: $($cand.FullName) — review-only, because this rule class also matches ordinary PE import-table strings in installers and runtime shims." `
                                -Target "[$zbOwner] $($cand.FullName)" -FixAction "Info" -Group "YARA-Lite Matches"
                            $yaraHits++; break
                        }
                        # ── AUTHENTICODE GATE (rule #1 — added 2026-07-26) ─────────────────
                        # YARA-lite matches API-name strings in file CONTENT. Legitimate
                        # system-administration, debugging and EDR tooling contains those
                        # strings BECAUSE THAT IS WHAT IT DOES: WMI_Reflective matches any PE
                        # whose import table references VirtualAllocEx/WriteProcessMemory/
                        # CreateRemoteThread, and UAC_Bypass_FodHelper matches any binary that
                        # merely mentions eventvwr.exe. Measured live on this box 2026-07-26:
                        # Phase 90 produced 18 auto-selected CRITICAL/HIGH + DeleteFile findings,
                        # 12 of them against Microsoft's own Authenticode-signed Sysinternals
                        # Suite in Downloads (ADInsight, Coreinfo, livekd, vmmap, Winobj...),
                        # plus Anthropic-signed "Claude Setup.exe" and a Microsoft-signed
                        # concrt140.dll — every one queued for automatic DELETION on a completely
                        # healthy machine. That is rule #1 verbatim.
                        #
                        # The decisive signal must be the Authenticode verdict, NOT the path.
                        # A path allowlist is attacker-satisfiable (drop the payload in a folder
                        # called "SysinternalsSuite") and does not generalise to client machines;
                        # $YARA_BENIGN_RE above stays as the narrow JIT-runtime carve-out it is,
                        # routed through Test-BenignPath so a staging-dir match is vetoed.
                        # Same precedent as the TROJNAME block below and Phases 36/69/83: where
                        # the action is destructive, the signature verdict decides whether the
                        # finding is auto-actionable.
                        #
                        #   Status 'Valid'  -> POSSIBLE + Info : demoted, never dropped. The
                        #                      finding still appears, with the rule's original
                        #                      severity and the signer stated in the description.
                        #   any other status-> grading UNCHANGED. "NotSigned" is NOT evidence of
                        #                      malice — Get-AuthSig cannot see CATALOG signatures,
                        #                      so many legitimate OS files report NotSigned. It is
                        #                      simply the absence of a positive trust signal, so
                        #                      the pre-existing behaviour is what applies.
                        #   not checked at all-> POSSIBLE + Info : fail closed. A guard whose
                        #                      input is missing (budget exhausted, file locked)
                        #                      must never fall through into the destructive path.
                        #
                        # Budgeted per CLAUDE.md: Authenticode does online CRL/OCSP revocation
                        # checks that block ~15s each, so this loop carries the $global:SIG_AUDIT_*
                        # deadline+count pair. The stopwatch is cumulative-call-time, not
                        # wall-clock-since-phase-start (see its declaration for the measurement
                        # that forced that). Get-AuthSig is additionally memoized in
                        # $global:AUTHSIG_CACHE (WS4), so a path already verified by an earlier
                        # phase returns instantly and costs the deadline nothing.
                        # Flags are raised only AFTER the check succeeds, never optimistically.
                        $yaraSigChecked = $false
                        $yaraSigValid   = $false
                        $yaraSigStatus  = ''
                        $yaraSigner     = ''
                        $ysig           = $null
                        if ($yaraSigSeen -lt $global:SIG_AUDIT_MAX_FILES -and
                            $yaraSigSw.Elapsed.TotalSeconds -lt $global:SIG_AUDIT_DEADLINE_S) {
                            $yaraSigSeen++
                            $yaraSigSw.Start()
                            try { $ysig = Get-AuthSig $cand.FullName } finally { $yaraSigSw.Stop() }
                            if ($ysig) {
                                $yaraSigChecked = $true
                                $yaraSigStatus  = "$($ysig.Status)"
                                if ($ysig.SignerCertificate) { $yaraSigner = "$($ysig.SignerCertificate.Subject)" }
                                if ($yaraSigStatus -eq 'Valid') { $yaraSigValid = $true }
                            }
                        }
                        $yaraSignerShort = $yaraSigner
                        if ($yaraSigner -match 'CN=([^,]+)') { $yaraSignerShort = $Matches[1].Trim('"') }
                        if ($yaraSigValid) {
                            Add-Finding -ID "YARA_$($rule.Name)_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                                -ThreatType "YARA-Lite Match" -Severity $SEV_POSSIBLE `
                                -Description "[$zbOwner] YARA rule '$($rule.Name)' (rule severity $($rule.Severity)) matched the CONTENT of a validly Authenticode-signed binary: $($cand.FullName) — signed by '$yaraSignerShort'. Demoted to review-only and never auto-acted-on: these rules match API-name strings that legitimate system-administration, debugging and security tooling contains by design. Verify the signer is expected for this machine before acting." `
                                -Target "[$zbOwner] $($cand.FullName)" -FixAction "Info" -Group "YARA-Lite Matches" `
                                -Signer $yaraSignerShort -SignatureStatus $yaraSigStatus
                            $yaraHits++; break
                        }
                        if (-not $yaraSigChecked) {
                            Add-Finding -ID "YARA_$($rule.Name)_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                                -ThreatType "YARA-Lite Match" -Severity $SEV_POSSIBLE `
                                -Description "[$zbOwner] YARA rule '$($rule.Name)' (rule severity $($rule.Severity)) matched: $($cand.FullName) — but the Authenticode signature could NOT be verified (file locked, or this phase's signature-check budget of $($global:SIG_AUDIT_MAX_FILES) files / $($global:SIG_AUDIT_DEADLINE_S)s was exhausted). Held at review-only rather than auto-acted-on, because an unverified signature is not a verdict. Re-check this file by hand: Get-AuthenticodeSignature '$($cand.FullName)'" `
                                -Target "[$zbOwner] $($cand.FullName)" -FixAction "Info" -Group "YARA-Lite Matches"
                            $yaraHits++; break
                        }
                        # Bare-name-rule self-detection carve-out (see $YARA_NAME_ONLY_RULES above).
                        # A genuine delivered Mimikatz/Meterpreter/Sliver/Lazagne/WinPwn script almost
                        # always ALSO embeds or fetches its payload — a long encoded blob (the same
                        # shape Base64_PS_Cradle already keys on) — so require that corroboration
                        # before a bare name match in a SCRIPT file is allowed to go destructive.
                        # Fails CLOSED the normal way round: no blob does not mean "definitely safe",
                        # it means "not yet corroborated", so it demotes to POSSIBLE, never suppresses.
                        if (($YARA_NAME_ONLY_RULES -contains $rule.Name) -and ($YARA_TEXT_ONLY_EXT -contains $cand.Extension.ToLower()) -and -not [regex]::IsMatch($text, '[A-Za-z0-9+/=]{200,}')) {
                            Add-Finding -ID "YARA_$($rule.Name)_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                                -ThreatType "YARA-Lite Match" -Severity $SEV_POSSIBLE `
                                -Description "[$zbOwner] YARA rule '$($rule.Name)' matched a bare tool-name string in a script/text file with no embedded encoded payload found: $($cand.FullName) — consistent with the name appearing in documentation, a comment, or another security/IR tool's OWN detection signatures rather than a delivered attack script. Review the surrounding context by hand before acting." `
                                -Target "[$zbOwner] $($cand.FullName)" -FixAction "Info" -Group "YARA-Lite Matches" -SignatureStatus $yaraSigStatus
                            $yaraHits++; break
                        }
                        # Checked, and NOT validly signed: original grading, unchanged.
                        # FixAction is Quarantine rather than DeleteFile (changed 2026-07-26):
                        # a content-string match is a heuristic, never a hash confirmation, and
                        # CLAUDE.md prefers the reversible action for anything not hash-confirmed.
                        # Severity and auto-selectability are identical, so no coverage is lost —
                        # only the operator's ability to undo a wrong call is gained.
                        $zbYaraSev = if ($rule.Severity -eq "CRITICAL") { $SEV_CRITICAL } else { $SEV_HIGH }
                        Out-Decrypt -Text "[$zbOwner] $($rule.Name) -> $($cand.FullName)" -Prefix "  [YARA HIT] "
                        Add-Finding -ID "YARA_$($rule.Name)_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                            -ThreatType "YARA-Lite Match" -Severity $zbYaraSev `
                            -Description "[$zbOwner] YARA rule '$($rule.Name)' matched: $($cand.FullName) — not validly signed (Authenticode status: $yaraSigStatus)." `
                            -Target "[$zbOwner] $($cand.FullName)" -FixAction "Quarantine" -FixParam $cand.FullName `
                            -Group "YARA-Lite Matches" -SignatureStatus $yaraSigStatus
                        $yaraHits++; $global:TrojanHits++; break
                    }
                }
                # Content-signature pass (HTML smuggling / JS redirector / obfuscated dropper).
                if ($cand.Extension.ToLower() -in @(".htm",".html",".js",".jse",".vbs",".vbe",".hta",".wsf",".svg")) {
                    $cr = Test-ContentRules -FilePath $cand.FullName -Rules $EMAIL_CONTENT_RULES
                    if ($cr.Hit) {
                        Out-Decrypt -Text "[$zbOwner] $($cr.Name) -> $($cand.FullName)" -Prefix "  [CONTENT HIT] "
                        $fa = if ($cr.Severity -eq $SEV_POSSIBLE) { "Info" } else { "Quarantine" }
                        Add-Finding -ID "CONTENT_$($cr.Name)_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                            -ThreatType "Phishing / Smuggling Content" -Severity $cr.Severity `
                            -Description "[$zbOwner] Content rule '$($cr.Name)' matched: $($cand.FullName)" `
                            -Target "[$zbOwner] $($cand.FullName)" -FixAction $fa -FixParam $cand.FullName `
                            -Group "Phishing / Smuggling Content"
                        $yaraHits++; $global:TrojanHits++
                    }
                }
                # Built-in known-malware hash list + user-supplied custom IOC hashes.
                if (($KNOWN_MALWARE_HASHES.Count -gt 0 -or $global:CustomIocs.Hashes.Count -gt 0) -and $cand.Length -lt 25MB) {
                    try {
                        $hash = (Get-FileHashSafe $cand.FullName).ToLower()
                        if (($KNOWN_MALWARE_HASHES -contains $hash) -or ($global:CustomIocs.Hashes -contains $hash)) {
                            Out-Decrypt -Text "[$zbOwner] IOC hash match: $($cand.FullName)" -Prefix "  [IOC HIT] "
                            # Path-hashed (was filename-only): per-profile unique, and it now uses
                            # the SAME id shape as the ungated sweep below, so one physical file
                            # reached by both passes cannot be reported twice.
                            Add-Finding -ID "IOC_HASH_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                                -ThreatType "Known-Malware Hash" -Severity $SEV_CRITICAL `
                                -Description "[$zbOwner] File matches known-malware/IOC hash ($hash): $($cand.FullName)" `
                                -Target "[$zbOwner] $($cand.FullName)" -FixAction "Quarantine" -FixParam $cand.FullName `
                                -Group "Known-Malware Hash Matches"
                            $yaraHits++; $global:TrojanHits++
                        }
                    } catch {}
                }
                # Known trojan/tooling FILENAME patterns (review #51 — $TROJAN_FILE_PATTERNS was
                # loaded but never read). Name alone is weak evidence: "agent*.exe"/"*invoice*.exe"
                # match plenty of legitimate software, so a validly signed binary is review-only
                # and only an unsigned one is auto-actionable — and even then Quarantine, which is
                # reversible, never DeleteFile (rule #1 / CLAUDE.md's Quarantine preference).
                foreach ($tfp in $TROJAN_FILE_PATTERNS) {
                    if (-not $tfp -or $cand.Name -notlike $tfp) { continue }
                    # SIG_AUDIT budget: patterns like agent*.exe / *invoice*.exe match freely and
                    # Authenticode blocks ~15s per file on CRL/OCSP.
                    if ($trojSigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
                        $trojSigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) { break }
                    $trojSigSeen++
                    $tsig = Get-AuthSig $cand.FullName
                    if ($tsig -and $tsig.Status -eq 'Valid') {
                        Add-Finding -ID "TROJNAME_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                            -ThreatType "Suspicious Filename" -Severity $SEV_POSSIBLE `
                            -Description "[$zbOwner] Filename matches a known malware/tooling naming pattern ('$tfp') but the binary is validly signed (review only, never auto-acted): $($cand.FullName)" `
                            -Target "[$zbOwner] $($cand.FullName)" -FixAction "Info" -Group "Suspicious Filenames"
                    } elseif ($magicOnly.ContainsKey($cand.FullName)) {
                        # Magic-sniffed file: newly reachable here, so keep it out of the
                        # auto-select path (rule #1 — see the $magicOnly comment above).
                        Add-Finding -ID "TROJNAME_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                            -ThreatType "Suspicious Filename" -Severity $SEV_POSSIBLE `
                            -Description "[$zbOwner] Unsigned file, identified as an executable by CONTENT rather than extension, whose name matches a known malware/tooling naming pattern ('$tfp'): $($cand.FullName) — review-only." `
                            -Target "[$zbOwner] $($cand.FullName)" -FixAction "Info" -Group "Suspicious Filenames"
                    } else {
                        Out-Decrypt -Text "[$zbOwner] trojan-pattern filename: $($cand.FullName)" -Prefix "  [NAME HIT] "
                        Add-Finding -ID "TROJNAME_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                            -ThreatType "Suspicious Filename" -Severity $SEV_HIGH `
                            -Description "[$zbOwner] Unsigned file whose name matches a known malware/tooling naming pattern ('$tfp'): $($cand.FullName)" `
                            -Target "[$zbOwner] $($cand.FullName)" -FixAction "Quarantine" -FixParam $cand.FullName `
                            -Group "Suspicious Filenames"
                        $global:TrojanHits++
                    }
                    $yaraHits++
                    break
                }
                # Custom IOC: operator-supplied FILENAMES (`file:` lines in the IOC file).
                # Quarantine rather than DeleteFile — reversible, and the operator declared
                # the name, not a hash, so a same-named innocent file is possible.
                if ($global:CustomIocFileNames.Count -gt 0 -and
                    $global:CustomIocFileNames -contains $cand.Name.ToLower()) {
                    Out-Decrypt -Text "[$zbOwner] IOC filename match: $($cand.FullName)" -Prefix "  [IOC HIT] "
                    Add-Finding -ID "IOC_FILE_$(Get-StableId $cand.FullName)" -Phase "PHASE 90" `
                        -ThreatType "Custom IOC" -Severity $SEV_HIGH `
                        -Description "[$zbOwner] File matches an operator-supplied IOC filename: $($cand.FullName)" `
                        -Target "[$zbOwner] $($cand.FullName)" -FixAction "Quarantine" -FixParam $cand.FullName `
                        -Group "Custom IOC Matches"
                    $yaraHits++; $global:TrojanHits++
                }
                # Custom IOC: operator-supplied REGEX, matched against the file's ASCII text
                # (already read above for the YARA-lite pass — no extra I/O) and its full path.
                foreach ($cre in $global:CustomIocRegexOk) {
                    try {
                        if ($text -match $cre -or $cand.FullName -match $cre) {
                            Out-Decrypt -Text "[$zbOwner] IOC regex match: $($cand.FullName)" -Prefix "  [IOC HIT] "
                            Add-Finding -ID "IOC_RE_$(Get-StableId ("$cre|$($cand.FullName)"))" -Phase "PHASE 90" `
                                -ThreatType "Custom IOC" -Severity $SEV_HIGH `
                                -Description "[$zbOwner] File matches operator-supplied IOC pattern '$cre': $($cand.FullName)" `
                                -Target "[$zbOwner] $($cand.FullName)" -FixAction "Quarantine" -FixParam $cand.FullName `
                                -Group "Custom IOC Matches"
                            $yaraHits++; $global:TrojanHits++; break
                        }
                    } catch {}
                }
            } catch {}
        }

    # ── UNGATED KNOWN-MALWARE / IOC HASH SWEEP ────────────────────────────────
    # A SHA256 comparison is EXACT: it cannot false-positive, so it is the one detection in the
    # engine that never had any business being restricted by filename. It used to live only
    # inside the extension-filtered $candidates loop above, which made the single highest-
    # confidence check in the product unreachable for exactly the files an attacker renames.
    # This pass covers every time-scoped file the walk saw, whatever it is called.
    # CRITICAL + Quarantine matches the in-loop behaviour: reversible, and a hash match is
    # confirmed malware, so auto-action is justified (rule #1 is about heuristics firing on a
    # HEALTHY box — a known-malware hash hit means the box is not healthy).
    if ($KNOWN_MALWARE_HASHES.Count -gt 0 -or $global:CustomIocs.Hashes.Count -gt 0) {
        $alreadyHashed = @{}
        foreach ($c in $candidates) { $alreadyHashed[$c.FullName] = $true }
        $hashSeen = 0; $hashSw = [System.Diagnostics.Stopwatch]::StartNew()
        $HASH_MAX_FILES = 3000; $HASH_DEADLINE_S = 60
        $hashBudgetHit = $false
        foreach ($hf in $allScanned) {
            if ($hashSeen -ge $HASH_MAX_FILES -or $hashSw.Elapsed.TotalSeconds -ge $HASH_DEADLINE_S) { $hashBudgetHit = $true; break }
            if ($alreadyHashed.ContainsKey($hf.FullName)) { continue }
            if ($hf.Length -ge 25MB -or $hf.Length -lt 1) { continue }
            $hashSeen++
            try {
                $h2 = (Get-FileHashSafe $hf.FullName)
                if (-not $h2) { continue }
                $h2 = $h2.ToLower()
                if (($KNOWN_MALWARE_HASHES -contains $h2) -or ($global:CustomIocs.Hashes -contains $h2)) {
                    $zbOwner = 'MACHINE'; $zbOwnerLen = -1
                    foreach ($zbK in @($zbYaraOwners.Keys)) {
                        if ("$($hf.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                            $zbOwner = $zbYaraOwners[$zbK]; $zbOwnerLen = $zbK.Length
                        }
                    }
                    Out-Decrypt -Text "[$zbOwner] IOC hash match (name-independent): $($hf.FullName)" -Prefix "  [IOC HIT] "
                    Add-Finding -ID "IOC_HASH_$(Get-StableId $hf.FullName)" -Phase "PHASE 90" `
                        -ThreatType "Known-Malware Hash" -Severity $SEV_CRITICAL `
                        -Description "[$zbOwner] File matches known-malware/IOC hash ($h2) despite a non-executable filename: $($hf.FullName)" `
                        -Target "[$zbOwner] $($hf.FullName)" -FixAction "Quarantine" -FixParam $hf.FullName `
                        -Group "Known-Malware Hash Matches"
                    $yaraHits++; $global:TrojanHits++
                }
            } catch {}
        }
        $hashSw.Stop()
        if ($hashBudgetHit) {
            Out-Typewriter ("  -> [INFO] IOC HASH SWEEP BUDGET REACHED ({0} files / {1}s) — partial." -f $hashSeen, [Math]::Round($hashSw.Elapsed.TotalSeconds,1)) "WARN"
        }
    }
    if ($yaraHits -eq 0) { Out-Typewriter "  -> [OK] NO YARA-LITE MATCHES." "GOOD" }
    }   # end Test-PhaseGate 90

    # ── PHASE 91: MARK-OF-THE-WEB ABUSE ───────────────────────────────────────
    if (Test-PhaseGate 91) {
    Show-PhaseHeader "PHASE 91" "MARK-OF-THE-WEB (MOTW) ZONE.IDENTIFIER STRIP" "MOTW"
    Out-Typewriter "SCANNING DOWNLOADS FOR MOTW-STRIPPED EXECUTABLES AND WEB-ORIGIN EVIDENCE..." "HUNT"
    # EVIDENCE_ENGINE_PLAN P6 / A10 — this phase already opened the right stream and threw the
    # answer away. It only ever tested for the ABSENCE of Zone.Identifier. When the stream is
    # PRESENT it carries ZoneId and, very often, HostUrl and ReferrerUrl — the download source
    # and the referring page. That is one of the few places a payload's ORIGIN survives the
    # payload itself (it is still there after self-deletion, after Defender quarantines the file,
    # and after a tech "cleaned it"). Verified live on this box 2026-07-26: real HostUrl +
    # ReferrerUrl pairs recovered from Downloads.
    #
    # Grading is by evidence, never destructive (rule #1 — a download origin is not an action):
    #   POSSIBLE : executable-class file, ZoneId >= 3 (Internet/Untrusted), and a HostUrl.
    #   INFO     : anything else carrying an origin URL — a normal download is not a finding.
    # Both are FixAction Info. The MoTW-STRIPPED detection below is unchanged in behaviour: it
    # is still gated on the original executable extension list and the original 8 KB floor.
    $motwHits = 0
    $zbMotwExecRe = "\.(exe|msi|dll|scr|js|vbs|hta|ps1|bat|lnk|iso|img)$"
    # Origin evidence is worth reading for the phishing DELIVERY vehicles too (archives are how
    # a payload arrives); this wider list is used ONLY for the read, never for the strip test.
    $zbMotwEvidRe = "\.(exe|msi|dll|scr|js|vbs|hta|ps1|bat|cmd|lnk|iso|img|zip|7z|rar|cab|jar|xll|wsf|jse|vbe)$"
    # Benign-origin demotion. Empty/absent key -> '(?!)' which matches nothing, so an absent key
    # suppresses nothing (fail-open on reporting, never fail-open on safety).
    $zbMotwBenignRe = if (@(Get-Sig 'motw_benign_origin_host_regex').Count) { @(Get-Sig 'motw_benign_origin_host_regex')[0] } else { '(?!)' }
    # Bulk-loop budget: one ADS probe + one small read per candidate file.
    $zbZoneSeen = 0; $zbZoneMax = 1500; $zbZoneDeadlineS = 30; $zbZoneCut = $false
    $zbZoneSw = [System.Diagnostics.Stopwatch]::StartNew()
    $zbOriginHits = 0
    # P1 multi-user: Downloads/Desktop were read from the ELEVATED process's environment, i.e.
    # the technician's own profile on a standard-user endpoint — so the one phase whose entire
    # purpose is "what did this user download" never looked at the user who downloaded it.
    # Roots now come from Get-UserPaths for EVERY reachable profile (redirection-aware: a
    # redirected Desktop on a file server resolves correctly, which a constructed
    # "$profile\Desktop" never would) and go to ONE Get-ScanFiles call, so the file/deadline
    # budget is not multiplied by the profile count. The stream-reading and grading logic below
    # is byte-for-byte unchanged; only the roots and the finding attribution differ.
    $zbMotwHives  = @(@(Get-UserHives) | Sort-Object -Property Sid)   # SID order = stable memo key
    $zbMotwOwners = @{}
    $zbMotwRoots  = @()
    foreach ($zbHive in $zbMotwHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbR in @($zbUp.Downloads, $zbUp.Desktop)) {
            if (-not $zbR) { continue }
            $zbMotwRoots += $zbR
            $zbMotwOwners["$zbR".ToLowerInvariant()] = "$($zbHive.User)"
        }
    }
    $zbMotwRoots = @($zbMotwRoots | Select-Object -Unique)
    $zbMotwCand  = Get-ScanFiles -Path $zbMotwRoots -TimeScoped   # assign first — Get-ScanFiles returns ,$arr (CLAUDE.md)
    $exes = @($zbMotwCand | Where-Object { $_.Extension -match $zbMotwEvidRe })
    foreach ($exe in $exes) {
        if ($zbZoneSeen -ge $zbZoneMax -or $zbZoneSw.Elapsed.TotalSeconds -gt $zbZoneDeadlineS) { $zbZoneCut = $true; break }
        $zbZoneSeen++
        # Longest-prefix attribution against the roots we built (not ProfilePath — a redirected
        # Downloads/Desktop lives outside the profile root and would read as [MACHINE]).
        $zbOwner = 'MACHINE'; $zbOwnerLen = -1
        foreach ($zbK in @($zbMotwOwners.Keys)) {
            if ("$($exe.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                $zbOwner = $zbMotwOwners[$zbK]; $zbOwnerLen = $zbK.Length
            }
        }
        $zbIsExec = ($exe.Extension -match $zbMotwExecRe)
        $stream = Get-Item -LiteralPath $exe.FullName -Stream "Zone.Identifier" -ErrorAction SilentlyContinue
        if (-not $stream) {
            if ($zbIsExec -and $exe.Length -gt 8192) {
                # ID was filename-only: "setup.exe" in two profiles collapsed to ONE id and
                # Add-Finding's de-dupe dropped the second user's hit. Path-hashed now.
                Add-Finding -ID "MOTW_$(Get-StableId $exe.FullName)" -Phase "PHASE 91" -ThreatType "MoTW Abuse" `
                    -Severity $SEV_POSSIBLE `
                    -Description "[$zbOwner] Executable in Downloads/Desktop missing Zone.Identifier (MoTW stripped): $($exe.FullName)" `
                    -Target "[$zbOwner] $($exe.FullName)" -FixAction "Info" -Group "MoTW / Web-Origin Abuse"
                $motwHits++
            }
            continue
        }
        # ── P6: the stream IS present — read it instead of discarding it ──────────
        $zbZoneTxt = ''
        try { $zbZoneTxt = ((Get-Content -LiteralPath $exe.FullName -Stream "Zone.Identifier" -ErrorAction SilentlyContinue) -join "`n") } catch { $zbZoneTxt = '' }
        if (-not $zbZoneTxt) { continue }
        $zbZoneId = ''; $zbHostUrl = ''; $zbRefUrl = ''
        $zbZm = [regex]::Match($zbZoneTxt, '(?im)^\s*ZoneId\s*=\s*(\d+)')
        if ($zbZm.Success) { $zbZoneId = $zbZm.Groups[1].Value }
        $zbZm = [regex]::Match($zbZoneTxt, '(?im)^\s*HostUrl\s*=\s*(\S.*?)\s*$')
        if ($zbZm.Success) { $zbHostUrl = $zbZm.Groups[1].Value }
        $zbZm = [regex]::Match($zbZoneTxt, '(?im)^\s*ReferrerUrl\s*=\s*(\S.*?)\s*$')
        if ($zbZm.Success) { $zbRefUrl = $zbZm.Groups[1].Value }
        # A bare ZoneId with no URL carries no origin — nothing to report, and reporting it
        # on every downloaded file would be pure noise.
        if (-not $zbHostUrl -and -not $zbRefUrl) { continue }
        $zbZoneNum = 0
        if ($zbZoneId) { [void][int]::TryParse($zbZoneId, [ref]$zbZoneNum) }
        $zbZoneName = switch ($zbZoneNum) {
            0       { 'Local machine' }
            1       { 'Local intranet' }
            2       { 'Trusted sites' }
            3       { 'Internet' }
            4       { 'Restricted / untrusted' }
            default { 'unspecified' }
        }
        $zbBenignOrigin = (($zbHostUrl -and $zbHostUrl -match $zbMotwBenignRe) -or ($zbRefUrl -and $zbRefUrl -match $zbMotwBenignRe))
        $zbSevZ = if ($zbIsExec -and $zbZoneNum -ge 3 -and $zbHostUrl -and -not $zbBenignOrigin) { $SEV_POSSIBLE } else { $SEV_INFO }
        # A known-benign origin on a non-executable is not worth a line at all.
        if ($zbBenignOrigin -and -not $zbIsExec) { continue }
        # SharePoint/Graph download URLs run to 1 KB+; keep the finding readable.
        $zbHostShort = if ($zbHostUrl.Length -gt 300) { $zbHostUrl.Substring(0,300) + '...[truncated]' } else { $zbHostUrl }
        $zbRefShort  = if ($zbRefUrl.Length  -gt 300) { $zbRefUrl.Substring(0,300)  + '...[truncated]' } else { $zbRefUrl }
        $zbZdesc = "[$zbOwner] Web-origin evidence recovered from the Zone.Identifier stream of $($exe.FullName): ZoneId=$(if ($zbZoneId) { $zbZoneId } else { '?' }) ($zbZoneName)"
        if ($zbHostShort) { $zbZdesc += " | HostUrl=$zbHostShort" }
        if ($zbRefShort)  { $zbZdesc += " | ReferrerUrl=$zbRefShort" }
        $zbZdesc += ". This is where the file was downloaded from, as recorded by the browser; it survives deletion of the payload. Evidence only - no action is proposed."
        Add-Finding -ID "MOTWORIGIN_$(Get-StableId $exe.FullName)" -Phase "PHASE 91" -ThreatType "Web Origin Evidence" `
            -Severity $zbSevZ -Description $zbZdesc `
            -Target "[$zbOwner] $($exe.FullName)" -FixAction "Info" -Group "MoTW / Web-Origin Abuse"
        $zbOriginHits++
    }
    if ($zbZoneCut) {
        Out-Typewriter ("  -> [INFO] ZONE.IDENTIFIER READ BUDGET REACHED ({0} files / {1}s) — partial." -f $zbZoneSeen, $zbZoneDeadlineS) "WARN"
    }
    if ($motwHits -eq 0) { Out-Typewriter "  -> [OK] NO MOTW-STRIPPED EXECUTABLES." "GOOD" }
    if ($zbOriginHits -gt 0) {
        Out-Typewriter "  -> $zbOriginHits FILE(S) CARRY RECOVERABLE WEB-ORIGIN (HostUrl/ReferrerUrl) EVIDENCE." "INFO"
    } else {
        Out-Typewriter "  -> NO WEB-ORIGIN URLS RECOVERABLE FROM ZONE.IDENTIFIER STREAMS IN SCOPE." "INFO"
    }
    }   # end Test-PhaseGate 91

    # ── PHASE 92: UAC AUTO-ELEVATE BYPASS DETECTION ───────────────────────────
    if (Test-PhaseGate 92) {
    Show-PhaseHeader "PHASE 92" "UAC AUTO-ELEVATE BYPASS REGISTRY STAGING" "UAC BYPASS"
    Out-Typewriter "CHECKING UAC BYPASS REGISTRY KEYS (FODHELPER / COMPUTERDEFAULTS)..." "HUNT"
    # P1 multi-user: UAC-bypass staging lives in the VICTIM's per-user CLASSES store BY
    # DEFINITION (Software\Classes\<handler>\shell\open\command). Pre-P1 this read HKCU:, which
    # inside the RunAs-elevated process is the TECHNICIAN's hive on a standard-user endpoint — so
    # the check was structurally incapable of firing on a real incident and always printed clean.
    #
    # ClassesHivePath, NOT "$($zbHive.HivePath)\Software\Classes": for a reg-loaded profile the
    # real per-user class registrations live in a SEPARATELY mounted UsrClass.dat, while the
    # NTUSER.DAT's own Software\Classes is nearly empty (measured: 1 CLSID subkey vs 6 for a live
    # user). Getting that wrong makes this blind for exactly the logged-off profiles P1 exists to
    # reach. The two shapes the helper hands back are:
    #   mounted (HKU)  -> Registry::HKEY_USERS\<SID>\Software\Classes   (segment ALREADY included)
    #   RegLoad        -> Registry::HKEY_USERS\ZB_UC_<hex>              (UsrClass.dat's root IS
    #                                                                    the classes root)
    # so each data entry is stripped of BOTH "HKCU:\" AND the leading "Software\Classes\" segment
    # before it is joined on — otherwise the mounted form would address
    # ...\Software\Classes\Software\Classes\ms-settings\... and silently never match.
    $uacFound = $false
    $zbUacTargets = @()
    foreach ($zbHive in @(Get-UserHives)) {
        # $null classes path = "we could not look", NOT "nothing there" — skip, never fall through.
        if (-not $zbHive.ClassesHivePath) { continue }
        foreach ($ub in $UAC_BYPASS_REGS) {
            # Defensive strip: an entry already stored hive-relative passes through unchanged.
            $zbUbRel = "$ub" -replace '(?i)^HK(CU|EY_CURRENT_USER):?\\', ''
            $zbUbRel = $zbUbRel -replace '(?i)^Software\\Classes\\', ''
            $zbUbRel = $zbUbRel -replace '^\\+', ''
            if (-not $zbUbRel) { continue }
            $zbUacTargets += @{ Path = "$($zbHive.ClassesHivePath)\$zbUbRel"; Rel = $zbUbRel
                                User = $zbHive.User; Sid = $zbHive.Sid; Src = $zbHive.Source
                                ClsFile = "$($zbHive.UsrClassDat)" }
        }
    }
    foreach ($zbT in $zbUacTargets) {
        $zbUbPath = "$($zbT.Path)"
        if (Test-Path $zbUbPath) {
            $cmd = (Get-ItemProperty -Path $zbUbPath -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
            if ($cmd) {
                Out-ThreatBanner "UAC BYPASS REGISTRY HIJACK" "[$($zbT.User)] $zbUbPath -> $cmd"
                # A ZB_UC_* mount is GONE by the time the server's remediation runspace runs (a
                # different process, long after the engine exited), so a FixParam pointing into
                # one would silently target nothing. Reg-loaded profiles therefore become
                # operator-run (rule #1's own prescription), capped at HIGH.
                $zbUacSev  = $SEV_CRITICAL
                $zbUacAct  = "DeleteRegKey"
                $zbUacPrm  = $zbUbPath
                $zbUacDesc = "[$($zbT.User)] UAC bypass reg hijack: $zbUbPath = $cmd"
                if ("$($zbT.Src)" -eq 'RegLoad') {
                    $zbUacSev = $SEV_HIGH
                    $zbUacAct = "Info"
                    $zbUacPrm = ""
                    $zbUacDesc = "[$($zbT.User)] UAC bypass reg hijack recovered from a LOGGED-OFF profile's UsrClass.dat (temporary mount; removed when this scan ended, so remediate by hand): $zbUbPath = $cmd | reg load HKU\ZBFIX `"$($zbT.ClsFile)`" ; Remove-Item -LiteralPath `"Registry::HKEY_USERS\ZBFIX\$($zbT.Rel)`" -Recurse -Force ; reg unload HKU\ZBFIX"
                }
                Add-Finding -ID "UACBYPASS_$(Get-StableId "$($zbT.Sid)|$zbUbPath")" -Phase "PHASE 92" -ThreatType "UAC Bypass" `
                    -Severity $zbUacSev -Description $zbUacDesc `
                    -Target "[$($zbT.User)] $zbUbPath" -FixAction $zbUacAct -FixParam $zbUacPrm -Group "UAC Bypass"
                $global:UACBypassHits++; $uacFound = $true
            }
        }
    }
    # Live auto-elevating-binary check (review #51 — $AUTO_ELEVATE_BINS was loaded but never read).
    # The registry staging above catches the hijack at rest; this catches the bypass mid-flight.
    # These binaries auto-elevate WITHOUT a UAC prompt, so malware launches one after hijacking a
    # protocol/class handler. A user-path or script-host image for one of these names is the
    # give-away — the genuine articles always live in System32/SysWOW64.
    foreach ($p in (Get-ProcSnapshot)) {
        $pname = "$($p.Name)"
        if (-not $pname -or $AUTO_ELEVATE_BINS -notcontains $pname) { continue }
        $pexe = "$($p.ExecutablePath)"
        # FAIL CLOSED: when ExecutablePath is unavailable we cannot prove the process is NOT the
        # genuine System32 binary, and this branch ends in an auto-selected KillProcess against
        # names that include taskmgr.exe, mmc.exe and msconfig.exe. No path => no finding.
        if (-not $pexe) { continue }
        if ($pexe -match '(?i)^[A-Za-z]:\\Windows\\(System32|SysWOW64)\\') { continue }   # the real one
        Out-ThreatBanner "AUTO-ELEVATING BINARY FROM NON-SYSTEM PATH" "$pname (PID $($p.ProcessId)) @ $pexe"
        Add-Finding -ID "AUTOELEV_$($p.ProcessId)_$($pname -replace '[^a-z0-9]','')" -Phase "PHASE 92" `
            -ThreatType "UAC Bypass" -Severity $SEV_HIGH `
            -Description "Auto-elevating Windows binary '$pname' running from a non-System32 path (PID $($p.ProcessId)): $(if ($pexe) { $pexe } else { '<path unavailable>' }) — these elevate without a UAC prompt, so a copy outside System32 is a classic bypass stager." `
            -Target "PID:$($p.ProcessId)" -FixAction "KillProcess" -FixParam $p.ProcessId -Group "UAC Bypass"
        $global:UACBypassHits++; $uacFound = $true
    }
    $enableLua = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
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
    }   # end Test-PhaseGate 92

    # ── PHASE 93: DEEP DLL/MODULE INJECTION SCAN ──────────────────────────────
    if (Test-PhaseGate 93) {
    Show-PhaseHeader "PHASE 93" "DEEP PROCESS MODULE / DLL INJECTION AUDIT" "INJECTION"
    Out-Typewriter "ENUMERATING LOADED MODULES FOR UNSIGNED USER-PATH DLLS..." "HUNT"
    Invoke-QuantumBar "MODULE INTROSPECTION" 16 110
    $injFound = 0
    $deepProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and (Test-Path $_.Path) -and
        $_.Name -notmatch "^(svchost|System|smss|csrss|wininit|services|lsass|winlogon|fontdrvhost|dwm|conhost|MsMpEng|SearchIndexer|RuntimeBroker|sihost|taskhostw)$"
    } | Select-Object -First 60
    # Bounded sig loop: Get-AuthSig can block on online cert-revocation (CRL/OCSP), and
    # 60 procs × many user-path DLLs is potentially hundreds of calls. Cap total checks +
    # enforce a wall-clock budget so a slow/offline revocation responder can't hang the
    # phase (see Phase 98). The cheap user-path regex filter runs first; only survivors
    # cost a signature check.
    $sigSeen = 0
    $sigSw   = [System.Diagnostics.Stopwatch]::StartNew()
    $sigBudgetHit = $false
    foreach ($p in $deepProcs) {
        if ($sigBudgetHit) { break }
        try {
            $candDlls = $p.Modules | Where-Object {
                $_.FileName -and ($_.FileName -match "AppData|Temp|Downloads|ProgramData")
            }
            foreach ($udll in $candDlls) {
                if ($sigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
                    $sigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
                    $sigBudgetHit = $true; break
                }
                $sigSeen++
                if ((Get-AuthSig $udll.FileName).Status -ne "Valid") {
                    Out-Typewriter "  -> $($p.Name) PID:$($p.Id) loaded UNSIGNED user-path DLL: $($udll.FileName)" "CRIT"
                    Add-Finding -ID "INJDLL_$($p.Id)_$([IO.Path]::GetFileName($udll.FileName) -replace '[^a-z0-9]','')" `
                        -Phase "PHASE 93" -ThreatType "DLL Injection" -Severity $SEV_HIGH `
                        -Description "$($p.Name) PID:$($p.Id) loaded unsigned DLL from user path: $($udll.FileName)" `
                        -Target "PID:$($p.Id)" -FixAction "KillProcess" -FixParam $p.Id `
                        -Group "Module Injection"
                    $injFound++
                }
            }
        } catch {}
    }
    $sigSw.Stop()
    if ($sigBudgetHit) {
        Out-Typewriter ("  -> [INFO] MODULE SIG BUDGET REACHED ({0} DLLs / {1}s) — partial scan." -f $sigSeen, [Math]::Round($sigSw.Elapsed.TotalSeconds,1)) "WARN"
    }
    if ($injFound -eq 0) { Out-Typewriter "  -> [OK] NO UNSIGNED INJECTED MODULES." "GOOD" }
    }   # end Test-PhaseGate 93

    # ── PHASE 94: COM SCRIPTLET (.SCT) / SQUIBLYDOO ───────────────────────────
    if (Test-PhaseGate 94) {
    Show-PhaseHeader "PHASE 94" "COM SCRIPTLET (.SCT/.WSC) ABUSE & SQUIBLYDOO" "COM SCRIPTLET"
    Out-Typewriter "SCANNING FOR SCRIPTLET FILES AND REGSVR32 STAGING..." "HUNT"
    $sctHits = 0
    # P1 multi-user: the four roots were the ELEVATED process's own Temp/LocalAppData/AppData/
    # Downloads — the technician's, not the victim's, on a standard-user endpoint. Roots are now
    # collected for EVERY reachable profile and passed to ONE Get-ScanFiles call so the
    # file/deadline budget is not multiplied by the profile count. Grading is untouched.
    $zbSctHives  = @(@(Get-UserHives) | Sort-Object -Property Sid)   # SID order = stable memo key
    $zbSctOwners = @{}
    $zbSctRoots  = @()
    foreach ($zbHive in $zbSctHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbR in @($zbUp.Temp, $zbUp.LocalAppData, $zbUp.AppData, $zbUp.Downloads)) {
            if (-not $zbR) { continue }
            $zbSctRoots += $zbR
            $zbSctOwners["$zbR".ToLowerInvariant()] = "$($zbHive.User)"
        }
    }
    $zbSctRoots = @($zbSctRoots | Select-Object -Unique)
    # NB: .sct/.wsc are scriptlet-specific. .xsl is overwhelmingly benign (every
    # lxml/Python/Office install ships thousands) so it is NOT matched by extension
    # alone — Squiblytwo (.xsl via wmic) is caught by the run-key/content checks below.
    $sctFiles = (Get-ScanFiles -Path $zbSctRoots -TimeScoped) |
        Where-Object { $_.Extension -match "\.(sct|wsc)$" }
    foreach ($s in $sctFiles) {
        # Longest-prefix attribution against the roots we built (not ProfilePath: a redirected
        # AppData/Downloads lives outside the profile root and would read as [MACHINE]).
        $zbOwner = 'MACHINE'; $zbOwnerLen = -1
        foreach ($zbK in @($zbSctOwners.Keys)) {
            if ("$($s.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                $zbOwner = $zbSctOwners[$zbK]; $zbOwnerLen = $zbK.Length
            }
        }
        # Library test fixtures (pywin32's Testpys.sct in site-packages etc.) are not
        # Squiblydoo staging — allowlisted package trees are review-only.
        if (Test-BenignPath $s.FullName $SCT_BENIGN_RE) {
            # ID was filename-only: the SAME fixture name under two profiles' site-packages
            # hashed to one id and the second user's hit was silently dropped by Add-Finding's
            # de-dupe. Path-hashed now, so it is per-profile for free.
            Add-Finding -ID "SCT_$(Get-StableId $s.FullName)" -Phase "PHASE 94" -ThreatType "COM Scriptlet/Squiblydoo" `
                -Severity $SEV_POSSIBLE -Description "[$zbOwner] COM scriptlet inside a package/library tree (likely a library test fixture — review, not auto-deleted): $($s.FullName)" `
                -Target "[$zbOwner] $($s.FullName)" -FixAction "Info" -Group "COM Scriptlet Abuse"
            $sctHits++
            continue
        }
        Out-ThreatBanner "COM SCRIPTLET FILE" "[$zbOwner] $($s.FullName)"
        Add-Finding -ID "SCT_$(Get-StableId $s.FullName)" -Phase "PHASE 94" -ThreatType "COM Scriptlet/Squiblydoo" `
            -Severity $SEV_HIGH -Description "[$zbOwner] COM scriptlet (Squiblydoo vector): $($s.FullName)" `
            -Target "[$zbOwner] $($s.FullName)" -FixAction "DeleteFile" -FixParam $s.FullName -Group "COM Scriptlet Abuse"
        $sctHits++
    }
    # P1 multi-user: the HKCU half of this pair was the technician's Run key, not the victim's.
    # The HKLM root is MACHINE scope — enumerated ONCE, outside the profile loop, tagged
    # [MACHINE], so a box with 8 profiles cannot report one machine-wide condition 8 times.
    # The scriptlet gate (regsvr32 /i: URL) below is unchanged.
    $zbSquibTargets = @()
    foreach ($zbRp in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
        $zbSquibTargets += @{ Path = $zbRp; User = 'MACHINE'; Sid = 'MACHINE'; Src = 'HKLM'; HiveFile = '' }
    }
    foreach ($zbHive in @(Get-UserHives)) {
        if (-not $zbHive.HivePath) { continue }   # not mounted + loading off = could not look
        foreach ($zbRel in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
            $zbSquibTargets += @{ Path = "$($zbHive.HivePath)\$zbRel"; User = $zbHive.User
                                  Sid = $zbHive.Sid; Src = $zbHive.Source; HiveFile = "$($zbHive.NtUserDat)" }
        }
    }
    foreach ($zbT in $zbSquibTargets) {
        $rp = "$($zbT.Path)"
        if (-not (Test-Path $rp)) { continue }
        $vals = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        foreach ($prop in ($vals.psobject.properties | Where-Object { $_.Name -notmatch "^PS" })) {
            if ([string]$prop.Value -match "regsvr32.{0,16}/i:.{0,16}(http|https|\\\\)") {
                # ID gains the SID. SQUIBLY_<propname> collided HKCU-vs-HKLM even BEFORE P1 (the
                # same value name in both roots hashed to one ID and Add-Finding's de-dupe
                # silently dropped the second); per-profile roots would have made that worse.
                # `|` stays the FixParam separator — registry paths cannot contain one, and the
                # Registry::HKEY_USERS\<SID>\... form introduces none.
                $zbSqSev  = $SEV_CRITICAL
                $zbSqAct  = "DeleteReg"
                $zbSqPrm  = "$rp|$($prop.Name)"
                $zbSqDesc = "[$($zbT.User)] Run key uses regsvr32 /i: URL: $rp\$($prop.Name) = $($prop.Value)"
                if ("$($zbT.Src)" -eq 'RegLoad') {
                    # The ZB_UH_* mount does not exist when the server's remediation runspace
                    # later runs, so hand the operator the literal commands instead.
                    $zbSqSev = $SEV_HIGH
                    $zbSqAct = "Info"
                    $zbSqPrm = ""
                    $zbSqDesc = "[$($zbT.User)] Run key uses regsvr32 /i: URL, recovered from a LOGGED-OFF profile's NTUSER.DAT (temporary mount; gone once this scan ended, so remediate by hand): $rp\$($prop.Name) = $($prop.Value) | reg load HKU\ZBFIX `"$($zbT.HiveFile)`" ; Remove-ItemProperty -LiteralPath `"Registry::HKEY_USERS\ZBFIX\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`" -Name `"$($prop.Name)`" -Force ; reg unload HKU\ZBFIX"
                }
                Add-Finding -ID "SQUIBLY_$(Get-StableId "$($zbT.Sid)|$rp|$($prop.Name)")" -Phase "PHASE 94" -ThreatType "Squiblydoo" `
                    -Severity $zbSqSev -Description $zbSqDesc `
                    -Target "[$($zbT.User)] $rp|$($prop.Name)" -FixAction $zbSqAct -FixParam $zbSqPrm `
                    -Group "COM Scriptlet Abuse"
                $sctHits++
            }
        }
    }
    if ($sctHits -eq 0) { Out-Typewriter "  -> [OK] NO COM SCRIPTLET ARTIFACTS." "GOOD" }
    }   # end Test-PhaseGate 94

    # ── PHASE 95: APPDOMAINMANAGER .NET HIJACK ────────────────────────────────
    if (Test-PhaseGate 95) {
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
    }   # end Test-PhaseGate 95

    # ── PHASE 96: PRINTNIGHTMARE / PRINT SPOOLER ──────────────────────────────
    if (Test-PhaseGate 96) {
    Show-PhaseHeader "PHASE 96" "PRINT SPOOLER / PRINTNIGHTMARE (CVE-2021-34527)" "PRINTNIGHTMARE"
    Out-Typewriter "AUDITING POINT-AND-PRINT POLICY AND SPOOLER DRIVER DIR..." "HUNT"
    $pnHits = 0
    $pnoarp = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall"
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
        # Bounded sig loop — Get-AuthSig can block on online cert-revocation (CRL/OCSP);
        # cap count + wall-clock so a slow responder can't stack up minutes (see Phase 98).
        $spoolDlls = Get-ChildItem -Path $spoolDir -Recurse -Filter "*.dll" -ErrorAction SilentlyContinue |
            Where-Object { Test-InScope $_.LastWriteTime } | Select-Object -First 30
        $sigSeen = 0
        $sigSw   = [System.Diagnostics.Stopwatch]::StartNew()
        $sigBudgetHit = $false
        foreach ($sd in $spoolDlls) {
            if ($sigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
                $sigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
                $sigBudgetHit = $true; break
            }
            $sigSeen++
            if ((Get-AuthSig $sd.FullName).Status -ne "Valid") {
                # MS printer RESOURCE DLLs are catalog-signed — invisible to Get-AuthSig, which
                # only reads embedded Authenticode — so they grade "unsigned" on healthy boxes.
                if ($sd.FullName -match $SPOOLDLL_BENIGN_RE) {
                    Add-Finding -ID "SPOOLDRV_$($sd.Name -replace '[^a-z0-9]','')" -Phase "PHASE 96" -ThreatType "Print Spooler Hijack" `
                        -Severity $SEV_POSSIBLE -Description "Known printer resource DLL without embedded signature (catalog-signed — review only): $($sd.FullName)" `
                        -Target $sd.FullName -FixAction "Info" -Group "PrintNightmare"
                } else {
                Add-Finding -ID "SPOOLDRV_$($sd.Name -replace '[^a-z0-9]','')" -Phase "PHASE 96" -ThreatType "Print Spooler Hijack" `
                    -Severity $SEV_HIGH -Description "Unsigned DLL in spooler driver dir: $($sd.FullName)" `
                    -Target $sd.FullName -FixAction "DeleteFile" -FixParam $sd.FullName -Group "PrintNightmare"
                $pnHits++
                }
            }
        }
        $sigSw.Stop()
        if ($sigBudgetHit) {
            Out-Typewriter ("  -> [INFO] SPOOLER SIG BUDGET REACHED ({0} DLLs / {1}s) — partial scan." -f $sigSeen, [Math]::Round($sigSw.Elapsed.TotalSeconds,1)) "WARN"
        }
    }
    Add-Finding -ID "SPOOLER_DISABLE_OPT" -Phase "PHASE 96" -ThreatType "Hardening" -Severity $SEV_INFO `
        -Description "Option: Disable Print Spooler if printers not in use (eliminates PrintNightmare class)" `
        -Target "Service: Spooler" -FixAction "RunCmd" -FixParam "Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled" -Group "PrintNightmare"
    if ($pnHits -eq 0) { Out-Typewriter "  -> [OK] NO PRINTNIGHTMARE INDICATORS." "GOOD" }
    }   # end Test-PhaseGate 96

    # ── PHASE 97: CLICKONCE ABUSE ─────────────────────────────────────────────
    if (Test-PhaseGate 97) {
    Show-PhaseHeader "PHASE 97" "CLICKONCE / .APPLICATION DEPLOYMENT ABUSE" "CLICKONCE"
    Out-Typewriter "SCANNING FOR CLICKONCE PAYLOADS IN USER PATHS..." "HUNT"
    $coHits = 0
    # P1 multi-user: the roots were the ELEVATED process's own environment (the technician's
    # profile on a standard-user endpoint). Collected for EVERY reachable profile now and passed
    # to ONE Get-ScanFiles call so the file/deadline budget is not multiplied by profile count.
    # The bare `(Get-ScanFiles ...) | Where | Select | ForEach-Object {}` STATEMENT this replaces
    # was the highest-risk shape in the module (a dropped paren makes ,$arr arrive as ONE item
    # and the filter silently matches everything) — it is now assigned first, then iterated.
    $zbCoHives  = @(@(Get-UserHives) | Sort-Object -Property Sid)   # SID order = stable memo key
    $zbCoOwners = @{}
    $zbCoRoots  = @()
    foreach ($zbHive in $zbCoHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        $zbCoPer = @($zbUp.Temp, $zbUp.LocalAppData, $zbUp.Downloads)
        # ...\AppData\Local\Apps is where ClickOnce actually deploys; kept as an explicit root
        # (as before) even though it is a LocalAppData subtree, so the walk reaches it early.
        if ($zbUp.LocalAppData) { $zbCoPer += (Join-Path $zbUp.LocalAppData 'Apps') }
        foreach ($zbR in $zbCoPer) {
            if (-not $zbR) { continue }
            $zbCoRoots += $zbR
            $zbCoOwners["$zbR".ToLowerInvariant()] = "$($zbHive.User)"
        }
    }
    $zbCoRoots = @($zbCoRoots | Select-Object -Unique)
    $zbCoFiles = (Get-ScanFiles -Path $zbCoRoots -TimeScoped) |
        Where-Object { $_.Extension -match "\.(application|manifest|deploy)$" }
    # The old `Select-Object -First 50` was a flood cap applied PER ROOT. A single global 50
    # across every profile would let one noisy profile starve the rest, so the cap is kept but
    # applied PER OWNER — same intent, same order of magnitude, honest under P1.
    $zbCoCount = @{}
    foreach ($zbCf in $zbCoFiles) {
        $zbOwner = 'MACHINE'; $zbOwnerLen = -1
        foreach ($zbK in @($zbCoOwners.Keys)) {
            if ("$($zbCf.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                $zbOwner = $zbCoOwners[$zbK]; $zbOwnerLen = $zbK.Length
            }
        }
        if (-not $zbCoCount.ContainsKey($zbOwner)) { $zbCoCount[$zbOwner] = 0 }
        if ($zbCoCount[$zbOwner] -ge 50) { continue }
        $zbCoCount[$zbOwner]++
        # ID was filename-only — "setup.application" exists under most profiles, so the second
        # user's hit was silently dropped by Add-Finding's de-dupe. Path-hashed now.
        Add-Finding -ID "CLICKONCE_$(Get-StableId $zbCf.FullName)" -Phase "PHASE 97" -ThreatType "ClickOnce Abuse" `
            -Severity $SEV_POSSIBLE -Description "[$zbOwner] ClickOnce deployment artifact in user path: $($zbCf.FullName)" `
            -Target "[$zbOwner] $($zbCf.FullName)" -FixAction "DeleteFile" -FixParam $zbCf.FullName -Group "ClickOnce Abuse"
        $coHits++
    }
    if ($coHits -eq 0) { Out-Typewriter "  -> [OK] NO CLICKONCE PAYLOADS." "GOOD" }
    }   # end Test-PhaseGate 97

    # ── PHASE 97.5: MSIX / APP INSTALLER SIDELOADING ABUSE ────────────────────
    # WS9: enterprise LOB apps and Intune legitimately sideload MSIX (SignatureKind
    # Developer/Enterprise/None instead of Store), so this is gated on publisher trust, not
    # sideload status alone — moderate FP risk, POSSIBLE + Info only, never escalated. To
    # suppress this for an org's own Intune-sideloaded LOB apps, add the internal PKI cert's
    # publisher Subject substring to trusted_signers in data/permission_baseline.json (the same
    # customization path used for every other allowlist in this codebase — no code change needed).
    if (Test-PhaseGate 97.5) {
    Show-PhaseHeader "PHASE 97.5" "MSIX / APP INSTALLER SIDELOADING ABUSE" "MSIX SIDELOAD"
    Out-Typewriter "AUDITING SIDELOADED MSIX/APPX PACKAGES FOR UNTRUSTED PUBLISHERS..." "HUNT"
    $msixHits = 0
    try {
        $trustedPubSigners = @(Get-Perm 'trusted_signers')
        # Get-AppxPackage is a documented source of long stalls when the AppX StateRepository
        # database is locked/corrupted or AppXSvc is degraded — a real-world occurrence a bare
        # try/catch does NOT protect against (a blocking call, not a throwing one). Bounded via
        # Start-Job + Wait-Job -Timeout, same convention as the WSL probe and Get-AuthSig budget
        # used elsewhere in this module, so a bad AppX repository state can't stall Phase 98-115.
        $msixJobTimeoutS = 20
        $appxJob = Start-Job -ScriptBlock {
            Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
                $_.SignatureKind -and $_.SignatureKind -ne 'Store'
            } | Select-Object -First 100 -Property PackageFullName, Publisher, SignatureKind, InstallDate
        }
        $appxPkgs = @()
        if (Wait-Job -Job $appxJob -Timeout $msixJobTimeoutS) {
            $appxPkgs = @(Receive-Job -Job $appxJob -ErrorAction SilentlyContinue | Where-Object { Test-InScope $_.InstallDate })
        } else {
            Out-Typewriter "  -> APPX ENUMERATION TIMED OUT (${msixJobTimeoutS}s, StateRepository likely locked/corrupted) — SKIPPING." "WARN"
        }
        Stop-Job -Job $appxJob -ErrorAction SilentlyContinue; Remove-Job -Job $appxJob -Force -ErrorAction SilentlyContinue
        foreach ($pkg in $appxPkgs) {
            $pub = "$($pkg.Publisher)"
            $trusted = $false
            foreach ($ts in $trustedPubSigners) { if ($pub -like "*$ts*") { $trusted = $true; break } }
            if ($trusted) { continue }
            $msixHits++
            Out-Typewriter "  -> SIDELOADED MSIX: $($pkg.PackageFullName) [$($pkg.SignatureKind)] Pub: $pub" "WARN"
            Add-Finding -ID "MSIX975_$(Get-StableId $pkg.PackageFullName)" -Phase "PHASE 97.5" `
                -ThreatType "MSIX Sideload Abuse" -Severity $SEV_POSSIBLE `
                -Description "Sideloaded MSIX/Appx package from a publisher not on the trusted-signer allowlist (SignatureKind=$($pkg.SignatureKind)): $($pkg.PackageFullName) | Publisher: $pub — enterprise LOB apps legitimately sideload via Intune/App Installer, so this is review-only; verify against your MDM's approved app list, or add the publisher substring to trusted_signers in data/permission_baseline.json to suppress it going forward." `
                -Target $pkg.PackageFullName -FixAction "Info" -Group "MSIX / App Installer Sideload"
        }
    } catch {}
    if ($msixHits -eq 0) { Out-Typewriter "  -> [OK] NO SUSPICIOUS SIDELOADED MSIX PACKAGES." "GOOD" }
    }   # end Test-PhaseGate 97.5

    # ── PHASE 98: STOLEN/LEAKED CODE-SIGNING CERT ─────────────────────────────
    if (Test-PhaseGate 98) {
    Show-PhaseHeader "PHASE 98" "STOLEN / LEAKED CODE-SIGNING CERT DETECTION" "STOLEN CERT"
    Out-Typewriter "AUDITING SIGNED BINARIES IN USER PATHS FOR KNOWN-LEAKED ISSUERS..." "HUNT"
    Invoke-QuantumBar "AUTHENTICODE CHAIN AUDIT" 12 100
    # WS0 wiring: externalized to 'leaked_cert_issuers' (AMSI-safe, same list).
    $leakedCerts = $LEAKED_CERT_ISSUERS
    $stolenHits = 0
    # Bounded loop: Get-AuthSig can block on online cert-revocation checks (CRL/OCSP),
    # so cap total binaries verified AND enforce a wall-clock budget across ALL roots —
    # otherwise hundreds of slow signature checks could hang the phase for an hour and
    # leave Ctrl+C unresponsive (the revocation call is a blocking native call).
    $sigSeen = 0
    $sigSw   = [System.Diagnostics.Stopwatch]::StartNew()
    $sigBudgetHit = $false
    # P1 multi-user: the four roots were the ELEVATED process's own environment. Collected for
    # EVERY reachable profile now and passed to ONE Get-ScanFiles call — the $global:SIG_AUDIT_*
    # deadline+count pair below was ALREADY shared across roots, so it stays a single budget and
    # is not multiplied by the profile count either (Authenticode blocks ~15s per CRL/OCSP call).
    $zbCertHives  = @(@(Get-UserHives) | Sort-Object -Property Sid)   # SID order = stable memo key
    $zbCertOwners = @{}
    $zbCertRoots  = @()
    foreach ($zbHive in $zbCertHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbR in @($zbUp.Temp, $zbUp.LocalAppData, $zbUp.AppData, $zbUp.Downloads)) {
            if (-not $zbR) { continue }
            $zbCertRoots += $zbR
            $zbCertOwners["$zbR".ToLowerInvariant()] = "$($zbHive.User)"
        }
    }
    $zbCertRoots = @($zbCertRoots | Select-Object -Unique)
    $sigCandidates = (Get-ScanFiles -Path $zbCertRoots -TimeScoped) |
        Where-Object { $_.Extension -match "\.(exe|dll)$" }
    foreach ($f in $sigCandidates) {
        if ($sigSeen -ge $global:SIG_AUDIT_MAX_FILES -or
            $sigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
            $sigBudgetHit = $true; break
        }
        $sigSeen++
        $asig = Get-AuthSig $f.FullName
        if ($asig.SignerCertificate) {
            $subj = $asig.SignerCertificate.Subject
            foreach ($lc in $leakedCerts) {
                if ($subj -match [regex]::Escape($lc)) {
                    $zbOwner = 'MACHINE'; $zbOwnerLen = -1
                    foreach ($zbK in @($zbCertOwners.Keys)) {
                        if ("$($f.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                            $zbOwner = $zbCertOwners[$zbK]; $zbOwnerLen = $zbK.Length
                        }
                    }
                    Out-Decrypt -Text "[$zbOwner] Stolen cert: $($f.FullName) -> $subj" -Prefix "  [STOLEN CERT] "
                    # ID was filename-only; the same dropped binary staged under two profiles
                    # collapsed to one id and the second was silently de-duped away.
                    Add-Finding -ID "STOLENCERT_$(Get-StableId $f.FullName)" -Phase "PHASE 98" `
                        -ThreatType "Stolen Code-Sign Cert" -Severity $SEV_CRITICAL `
                        -Description "[$zbOwner] Binary signed by known-leaked cert ($lc): $($f.FullName)" `
                        -Target "[$zbOwner] $($f.FullName)" -FixAction "DeleteFile" -FixParam $f.FullName `
                        -Group "Stolen Code-Signing Certs"
                    $stolenHits++; break
                }
            }
        }
    }
    $sigSw.Stop()
    if ($sigBudgetHit) {
        Out-Typewriter ("  -> [INFO] CERT AUDIT BUDGET REACHED ({0} binaries / {1}s) — partial scan." -f $sigSeen, [Math]::Round($sigSw.Elapsed.TotalSeconds,1)) "WARN"
    }
    if ($stolenHits -eq 0) { Out-Typewriter "  -> [OK] NO STOLEN-CERT-SIGNED BINARIES." "GOOD" }
    }   # end Test-PhaseGate 98

    # ── PHASE 99: LOLBAS EXPANDED PROCESS AUDIT ───────────────────────────────
    if (Test-PhaseGate 99) {
    Show-PhaseHeader "PHASE 99" "LOLBAS EXPANDED PROCESS ABUSE AUDIT" "LOLBAS+"
    Out-Typewriter "SCANNING ALL LOLBAS-CLASS BINARIES FOR ABUSE PATTERNS..." "HUNT"
    Invoke-QuantumBar "LOLBAS CROSS-CORRELATION" 14 90
    $lolbasHits = 0
    # One WMI enumeration + name lookup instead of one filtered Get-WmiObject per
    # LOLBAS name. Map name -> original token so the finding ID keeps the $lb tag.
    $lolbasSet = @{}; foreach ($lb in $LOLBAS_EXPANDED) { $lolbasSet["$lb.exe"] = $lb }
    # Same rule#1 fix as Phase 4 (2026-07-26 adversarial FP audit): msiexec/forfiles legitimately
    # and routinely run from AppData/Temp (every third-party MSI installer stages there; Temp
    # cleanup scripts shell forfiles against it) — a bare AppData/Temp match on either no longer
    # qualifies alone. Every other LOLBAS-class binary keeps the original broader trigger.
    $lolbasAppDataTempOnlyOk = @{ 'msiexec.exe' = $true; 'forfiles.exe' = $true }
    $lolbasStrongRe = "http|https|ftp|Base64|EncodedCommand|IEX|DownloadString|/i:|scrobj|Net\.WebClient"
    $lolbasWeakRe   = "AppData|Temp"
    if ($lolbasSet.Count -gt 0) {
        foreach ($p in (Get-ProcSnapshot)) {
            $lb = $lolbasSet[$p.Name]
            if (-not $lb) { continue }
            $lolbasStrongHit = ($p.CommandLine -match $lolbasStrongRe)
            $lolbasWeakHit   = (-not $lolbasAppDataTempOnlyOk.ContainsKey($p.Name)) -and ($p.CommandLine -match $lolbasWeakRe)
            if ($lolbasStrongHit -or $lolbasWeakHit) {
                $cmdShort = $p.CommandLine.Substring(0,[Math]::Min(140,$p.CommandLine.Length))
                Add-Finding -ID "LOLBAS_$($p.ProcessId)_$lb" -Phase "PHASE 99" -ThreatType "LOLBAS Abuse" `
                    -Severity $SEV_HIGH -Description "LOLBAS abuse: $($p.Name) PID:$($p.ProcessId) | $cmdShort" `
                    -Target "PID:$($p.ProcessId)" -FixAction "KillProcess" -FixParam $p.ProcessId -Group "LOLBAS Expanded"
                $lolbasHits++
            }
        }
    }
    if ($lolbasHits -eq 0) { Out-Typewriter "  -> [OK] NO EXPANDED LOLBAS ABUSE." "GOOD" }
    }   # end Test-PhaseGate 99

    # ── PHASE 99.5: MALWARE COMMAND-LINE HEURISTICS ───────────────────────────
    # One Win32_Process enumeration cross-checked against the externalized behavioral
    # command-line rules (loader / banking-trojan / infostealer / inhibit-recovery). All
    # FixAction Info — a running process needs operator triage, not an auto-kill (the rules
    # are heuristic and could match a legit admin one-liner).
    if (Test-PhaseGate 99.5) {
    Show-PhaseHeader "PHASE 99.5" "MALWARE COMMAND-LINE HEURISTICS (LOADER/BANKING/STEALER/RECOVERY)" "BEHAVIOR"
    Out-Typewriter "CROSS-CHECKING PROCESS COMMAND LINES AGAINST BEHAVIORAL RULES..." "HUNT"
    $cmdRuleSevMap = @{ "CRITICAL"=$SEV_CRITICAL; "HIGH"=$SEV_HIGH; "POSSIBLE"=$SEV_POSSIBLE }
    $cmdRuleHits = 0
    if ($ALL_MALWARE_CMDLINE_RULES.Count -gt 0) {
        foreach ($p in (Get-ProcSnapshot)) {
            $cl = $p.CommandLine
            if (-not $cl) { continue }
            foreach ($r in $ALL_MALWARE_CMDLINE_RULES) {
                if ($cl -match $r.Pattern) {
                    $clShort = $cl.Substring(0,[Math]::Min(140,$cl.Length))
                    Out-ThreatBanner "MALWARE CMDLINE ($($r.Name))" "$($p.Name) PID:$($p.ProcessId)"
                    Add-Finding -ID "CMDRULE_$($p.ProcessId)_$($r.Name -replace '[^a-zA-Z0-9]','')" -Phase "PHASE 99.5" -ThreatType "Malware Behavior" `
                        -Severity $cmdRuleSevMap[$r.Severity] -Description "$($r.Name): $($p.Name) PID:$($p.ProcessId) | $clShort" `
                        -Target "PID:$($p.ProcessId)" -FixAction "Info" -Group "Malware Command-Line Heuristics"
                    $cmdRuleHits++
                    break   # one finding per process
                }
            }
        }
    }
    if ($cmdRuleHits -eq 0) { Out-Typewriter "  -> [OK] NO MALICIOUS COMMAND-LINE PATTERNS." "GOOD" }
    }   # end Test-PhaseGate 99.5

    # ── PHASE 100: BROWSER CRED DB ACCESS AUDIT ───────────────────────────────
    if (Test-PhaseGate 100) {
    Show-PhaseHeader "PHASE 100" "BROWSER PASSWORD/COOKIE DB RECENT ACCESS" "INFO-STEALER"
    Out-Typewriter "CHECKING LAST-ACCESS TIME ON BROWSER CREDENTIAL DATABASES..." "HUNT"
    # WS0 wiring: target list externalized/expanded to 'infostealer_target_paths_raw' (31 paths —
    # all browsers, Telegram/Discord, FileZilla, crypto wallets; wildcards for multi-profile).
    # Severity is POSSIBLE across the board: a recent access-time on a store the OWNING app also
    # touches routinely (browser running -> Login Data always "recent") is indistinguishable from
    # a stealer read by timestamp alone — triage-visible, never red-flooding (FP round precedent).
    #
    # P1 multi-user: the list is now {TOKEN} TEMPLATES resolved PER PROFILE. Before P1 it was
    # expanded ONCE against the elevated process's own environment, i.e. the TECHNICIAN's profile
    # on a standard-user endpoint — so this phase audited the wrong person's browser stores and
    # reported the infected profile clean. Only the way each path is PRODUCED changed; the
    # wildcard resolution (multi-profile browsers) still goes through Get-Item's globbing, and
    # the grading below is untouched.
    $credHits = 0
    foreach ($zbHive in @(Get-UserHives)) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbTpl in $INFOSTEALER_TARGET_TEMPLATES) {
            $zbPath = Expand-UserPathTemplate $zbTpl $zbUp
            if (-not $zbPath) { continue }   # unresolved token -> never emit a half-built path
            foreach ($item in @(Get-Item $zbPath -ErrorAction SilentlyContinue)) {
                if ($item -and $item.LastAccessTime -gt (Get-Date).AddMinutes(-60)) {
                    Add-Finding -ID "CREDDB_$(Get-StableId "$($zbHive.Sid)|$($item.FullName)")" -Phase "PHASE 100" -ThreatType "Info-Stealer Activity" `
                        -Severity $SEV_POSSIBLE -Description "[$($zbHive.User)] Credential/wallet store accessed in last 60 min (may be the owning app itself — verify): $($item.FullName) @ $($item.LastAccessTime)" `
                        -Target "[$($zbHive.User)] $($item.FullName)" -FixAction "Info" -Group "Credential DB Access"
                    $credHits++
                }
            }
        }
    }
    if ($credHits -eq 0) { Out-Typewriter "  -> [OK] NO RECENT CRED DB ACCESS." "GOOD" }
    }   # end Test-PhaseGate 100

    # ── PHASE 100.5: CLOUD & SESSION TOKEN THEFT STAGING ───────────────────────
    # (this banner used to read "PHASE 101" — a mislabel: the header directly below it, and the
    #  ~160 lines of body that follow, are PHASE 100.5. Phase 101 starts further down. Comment
    #  text only; no code change.)
    if (Test-PhaseGate 100.5) {
        Show-PhaseHeader "PHASE 100.5" "CLOUD & SESSION TOKEN THEFT STAGING" "INFO-STEALER"
    Out-Typewriter "CHECKING CLOUD CREDENTIAL STORES AND EXFIL STAGING..." "HUNT"
    # Access tokens survive MFA, which is exactly why infostealers now target them ahead of
    # passwords. The token FILES existing is completely normal (any developer box has them), so
    # their mere presence is inventory, not a finding. What is never legitimate is a token store
    # COPIED into a staging/archive location, or an archive named like stealer loot.
    #
    # P1 multi-user: this list is now {TOKEN} TEMPLATES resolved PER PROFILE. It had NEVER fired
    # once — the raw data was written in %VAR% form but expanded with ExpandString, which only
    # understands the $env: form, so every entry stayed a literal "%USERPROFILE%\..." and matched
    # nothing. TOKENSTORES_PRESENT has therefore never appeared in any scan; it is switching on
    # for the first time here, so the grade stays deliberately conservative (INFO + Info).
    #
    # This is INVENTORY, not a detection, so it stays ONE aggregate finding naming which profile
    # holds which store — a box with 8 developer profiles must not emit 8x16 rows.
    $tokHits = 0
    $tokPresent = 0
    $zbTokRows  = @()      # "user|path" — the sorted set is what the finding ID hashes
    $zbTokByUser = @{}
    foreach ($zbHive in @(Get-UserHives)) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        $zbUser = "$($zbHive.User)"
        foreach ($zbTpl in $CLOUD_TOKEN_TEMPLATES) {
            $zbPath = Expand-UserPathTemplate $zbTpl $zbUp
            if (-not $zbPath) { continue }
            if (-not (Test-Path -LiteralPath $zbPath)) { continue }
            $tokPresent++
            $zbTokRows += "$zbUser|$zbPath"
            # Name the store by its template tail ('.aws\credentials'), not the leaf — half these
            # leaves are the useless word 'leveldb'.
            $zbStore = ($zbTpl -replace '^\{[A-Za-z_]+\}\\', '')
            if (-not $zbTokByUser.ContainsKey($zbUser)) { $zbTokByUser[$zbUser] = @() }
            $zbTokByUser[$zbUser] += $zbStore
            Write-Log "Cloud token store present (normal): [$zbUser] $zbPath"
        }
    }
    if ($tokPresent -gt 0) {
        $zbTokSorted  = @($zbTokRows | Sort-Object)
        $zbTokSummary = (@(@($zbTokByUser.Keys) | Sort-Object) | ForEach-Object {
            "$_ -> " + ((@(@($zbTokByUser[$_]) | Sort-Object -Unique)) -join ', ')
        }) -join ' ; '
        if ($zbTokSummary.Length -gt 900) { $zbTokSummary = $zbTokSummary.Substring(0,900) + ' ...' }
        $zbTokTag = $(if ($zbTokByUser.Count -eq 1) { "[$(@($zbTokByUser.Keys)[0])]" } else { "[$($zbTokByUser.Count) PROFILES]" })
        Add-Finding -ID "TOKENSTORES_$(Get-StableId ($zbTokSorted -join "`n"))" -Phase "PHASE 100.5" -ThreatType "Cloud Credential Exposure" `
            -Severity $SEV_INFO `
            -Description "$zbTokTag $tokPresent cloud/session token store(s) present across $($zbTokByUser.Count) user profile(s) (AWS/Azure/GCP/kube/npm/browser session data): $zbTokSummary. Normal for a developer or admin workstation — but if this box is confirmed compromised, every one of those tokens must be revoked, for EVERY profile listed, because an access token bypasses MFA." `
            -Target "$zbTokTag Cloud token stores" -FixAction "Info" -Group "Cloud Credential Exposure"
    }
    # Loot-shaped archives / dumps in staging locations.
    $tokRe = ($TOKEN_STAGING_PATTERNS | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
    # P1 multi-user: per-profile staging roots for EVERY reachable profile (sorted by SID so the
    # Get-ScanFiles memo key is stable), handed to ONE Get-ScanFiles call so the file/deadline
    # budget is not multiplied by the profile count.
    $zbTokHives = @(@(Get-UserHives) | Sort-Object -Property Sid)
    $tokRoots = @()
    foreach ($zbHive in $zbTokHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbR in @($zbUp.Temp, $zbUp.Downloads, $zbUp.LocalAppData)) {
            if ($zbR) { $tokRoots += $zbR }
        }
    }
    # PUBLIC and ProgramData are MACHINE-wide — added exactly once, OUTSIDE the profile loop.
    foreach ($zbR in @($env:PUBLIC, $env:ProgramData)) { if ($zbR) { $tokRoots += $zbR } }
    $tokRoots = @($tokRoots | Select-Object -Unique)
    $tokFiles = (Get-ScanFiles -Path $tokRoots -TimeScoped)
    foreach ($tf in $tokFiles) {
        if ($tf.Name -notmatch $tokRe) { continue }
        # Package-manager and app trees legitimately contain token*.json library fixtures.
        if (Test-BenignPath $tf.FullName $YARA_BENIGN_RE) { continue }
        $tokHits++
        # Name-only match => review-only. yt-dlp writes Downloads\cookies.txt, countless apps
        # write <app>\token.json, and quarantining either on a healthy box breaks the app. Only
        # the unambiguous loot names (exfil/loot/stealer-log) keep an actionable grade, and even
        # then Quarantine, which is reversible.
        $tokBlatant = ($tf.Name -match '(?i)(exfil|loot|stealer.?log)')
        # Attribute the file back to the profile that owns it (longest-prefix on ProfilePath);
        # anything under PUBLIC/ProgramData stays [MACHINE].
        $zbOwner = 'MACHINE'
        foreach ($zbHive in $zbTokHives) {
            if ($zbHive.ProfilePath -and
                "$($tf.FullName)".ToLowerInvariant().StartsWith("$($zbHive.ProfilePath)".ToLowerInvariant())) {
                $zbOwner = "$($zbHive.User)"; break
            }
        }
        Out-Decrypt -Text $tf.FullName -Prefix "  [TOKEN STAGING][$zbOwner] "
        # NOTE: the ID hashes the FULL path, so it already differs per profile — no separate SID
        # component needed. FixParam stays the bare machine-parseable path (no [user] prefix).
        Add-Finding -ID "TOKENSTAGE_$(Get-StableId $tf.FullName)" -Phase "PHASE 100.5" `
            -ThreatType "Info-Stealer / Token Theft" -Severity $(if ($tokBlatant) { $SEV_HIGH } else { $SEV_POSSIBLE }) `
            -Description "[$zbOwner] File named like credential/token exfil loot in a staging directory: $($tf.FullName) — infostealers collect browser cookies, wallets and cloud tokens into an archive here before upload.$(if (-not $tokBlatant) { ' The name alone is weak evidence (yt-dlp cookie exports and ordinary app token caches collide with it) — review, not auto-acted.' }) Revoke cloud sessions if confirmed." `
            -Target "[$zbOwner] $($tf.FullName)" -FixAction $(if ($tokBlatant) { "Quarantine" } else { "Info" }) -FixParam $tf.FullName `
            -Group "Cloud Credential Exposure"
        $global:SpywareHits++
    }
    if ($tokHits -eq 0) { Out-Typewriter "  -> [OK] NO TOKEN-THEFT STAGING ARTIFACTS." "GOOD" }

    # WS9: App-Bound-Encryption bypass / cookie-theft tooling. This 2024-2025 stealer generation
    # reads Chrome/Edge cookies+tokens via IPC to the browser's OWN elevation service instead of
    # touching Login Data/Cookies on disk, so the DB-access-time check above (and Phase 100) never
    # sees it. Seeded conservatively (see data/detection_signatures.json comment — public tool
    # names for this technique are sparse); gated on unsigned + user-writable path, never a bare
    # name match, to keep FP risk low. Checks BOTH currently-running processes and recently-present
    # files (a tool that already ran and exited leaves no process, only the dropped binary).
    $abeHits = 0
    if ($ABE_BYPASS_TOOL_NAMES.Count -gt 0) {
        $abeSigSeen = 0; $abeSigSw = [System.Diagnostics.Stopwatch]::StartNew()
        foreach ($p in (Get-ProcSnapshot)) {
            if ($abeSigSeen -ge $global:SIG_AUDIT_MAX_FILES -or $abeSigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) { break }
            $pname = "$($p.Name)".ToLower()
            if (-not $pname -or $ABE_BYPASS_TOOL_NAMES -notcontains $pname) { continue }
            $pexe = "$($p.ExecutablePath)"
            if (-not $pexe -or $pexe -notmatch $global:USER_PATH_WIDE_RE) { continue }   # must be user-writable
            $abeSigSeen++
            if ((Get-AuthSig $pexe).Status -eq 'Valid') { continue }   # signed -> not the bypass tool
            Out-ThreatBanner "APP-BOUND ENCRYPTION BYPASS TOOL (RUNNING)" "$($p.Name) PID:$($p.ProcessId) @ $pexe"
            Add-Finding -ID "ABEBYPASS_$($p.ProcessId)_$($p.Name -replace '[^a-z0-9]','')" -Phase "PHASE 100.5" `
                -ThreatType "Info-Stealer / Token Theft" -Severity $SEV_POSSIBLE `
                -Description "Running process matches a known Chrome/Edge App-Bound-Encryption-bypass cookie-theft tool name, unsigned, from a user-writable path: $pexe (PID $($p.ProcessId)) — this stealer generation reads cookies/tokens via IPC to the browser's elevation service, bypassing the credential-DB entirely." `
                -Target "PID:$($p.ProcessId)" -FixAction "Info" -Group "Cloud Credential Exposure"
            $abeHits++; $global:SpywareHits++
        }
        # P1 multi-user: this file half still walked the ELEVATED process's own Temp/LocalAppData/
        # AppData/Downloads (the $tokRoots staging scan above was migrated in an earlier stage;
        # this loop was not). Roots for EVERY reachable profile now, via ONE Get-ScanFiles call so
        # the file/deadline budget — and the shared $abeSigSw Authenticode budget — are not
        # multiplied by the profile count. $zbTokHives is the SID-sorted set built above.
        $zbAbeOwners = @{}
        $zbAbeRoots  = @()
        foreach ($zbHive in $zbTokHives) {
            if (-not $zbHive.ProfileReachable) { continue }
            $zbUp = Get-UserPaths $zbHive
            if (-not $zbUp) { continue }
            foreach ($zbR in @($zbUp.Temp, $zbUp.LocalAppData, $zbUp.AppData, $zbUp.Downloads)) {
                if (-not $zbR) { continue }
                $zbAbeRoots += $zbR
                $zbAbeOwners["$zbR".ToLowerInvariant()] = "$($zbHive.User)"
            }
        }
        $zbAbeRoots = @($zbAbeRoots | Select-Object -Unique)
        $abeFiles = (Get-ScanFiles -Path $zbAbeRoots -TimeScoped) | Where-Object { $ABE_BYPASS_TOOL_NAMES -contains $_.Name.ToLower() }
        foreach ($af in $abeFiles) {
            if ($abeSigSeen -ge $global:SIG_AUDIT_MAX_FILES -or $abeSigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) { break }
            $abeSigSeen++
            if ((Get-AuthSig $af.FullName).Status -eq 'Valid') { continue }
            $zbOwner = 'MACHINE'; $zbOwnerLen = -1
            foreach ($zbK in @($zbAbeOwners.Keys)) {
                if ("$($af.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                    $zbOwner = $zbAbeOwners[$zbK]; $zbOwnerLen = $zbK.Length
                }
            }
            Out-ThreatBanner "APP-BOUND ENCRYPTION BYPASS TOOL (FILE)" "[$zbOwner] $($af.FullName)"
            # ID already hashes the FULL path, so it is per-profile unique for free.
            Add-Finding -ID "ABEBYPASSFILE_$(Get-StableId $af.FullName)" -Phase "PHASE 100.5" `
                -ThreatType "Info-Stealer / Token Theft" -Severity $SEV_POSSIBLE `
                -Description "[$zbOwner] File matches a known Chrome/Edge App-Bound-Encryption-bypass cookie-theft tool name, unsigned, in a user-writable path: $($af.FullName) — this stealer generation reads cookies/tokens via IPC to the browser's elevation service, bypassing the credential-DB entirely." `
                -Target "[$zbOwner] $($af.FullName)" -FixAction "Info" -Group "Cloud Credential Exposure"
            $abeHits++; $global:SpywareHits++
        }
    }
    if ($abeHits -eq 0) { Out-Typewriter "  -> [OK] NO APP-BOUND-ENCRYPTION-BYPASS TOOLS DETECTED." "GOOD" }
    }   # end Test-PhaseGate 100.5

    # ── PHASE 101: WSL / DOCKER CONTAINER SURFACE ─────────────────────────────
    if (Test-PhaseGate 101) {
Show-PhaseHeader "PHASE 101" "WSL / DOCKER CONTAINER ESCAPE SURFACE" "CONTAINER"
    Out-Typewriter "CHECKING WSL DISTROS AND DOCKER DAEMON..." "HUNT"
    if (Get-Command wsl -ErrorAction SilentlyContinue) {
        # WS9: best-effort Linux-side persistence probe (cron + dotfiles). `wsl.exe` can hang
        # indefinitely against a stopped/broken distro that needs to initialize, so each call runs
        # in a background job with a hard per-call timeout, AND the whole probe (across every
        # distro) is capped by a shared wall-clock budget — mirrors the Get-AuthSig SIG_AUDIT
        # deadline+cap convention used elsewhere in this module (see Phase 90/93/96/98).
        function Get-WslBoundedOutput {
            param([string]$Distro, [string[]]$Cmd, [int]$TimeoutSec = 6)
            $job = $null
            try {
                $job = Start-Job -ScriptBlock {
                    param($d, $c) & wsl -d $d -- @c 2>$null
                } -ArgumentList $Distro, $Cmd
                if (Wait-Job -Job $job -Timeout $TimeoutSec) {
                    return Receive-Job -Job $job -ErrorAction SilentlyContinue
                }
                return $null
            } catch { return $null }
            finally { if ($job) { Stop-Job -Job $job -ErrorAction SilentlyContinue; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } }
        }
        function Test-PrivateOrLoopbackIp {
            param([string]$Ip)
            if ($Ip -match '^127\.') { return $true }
            if ($Ip -match '^10\.') { return $true }
            if ($Ip -match '^192\.168\.') { return $true }
            if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
            if ($Ip -eq '0.0.0.0') { return $true }
            return $false
        }
        # wsl.exe emits UTF-16LE. PS 5.1 decodes the child's stdout with the console code page, so
        # each distro name arrives with NUL bytes interleaved ("U b u n t u"). Stripping the NULs
        # recovers the name — deliberately NOT by reassigning [Console]::OutputEncoding, because the
        # loader sets that to UTF-8 for the whole redirected-stdout pipeline and flipping it here
        # would corrupt the parent's own output (CLAUDE.md: don't change one side of that alone).
        #
        # Second, worse bug: wsl.exe ships in System32 on EVERY Win11 box, so `Get-Command wsl`
        # always succeeds — and when the WSL feature is not installed, wsl.exe prints its install
        # PROMPT to stdout. Every one of those lines was being registered as a "WSL distro present"
        # finding; a live sandbox run emitted 5, reading "Press any key to install...", "Operation
        # aborted", "This prompt will time out in 60 seconds." (2026-07-26). Real WSL distro names
        # contain no whitespace, so anything with a space is prompt/error prose, not a distro.
        $wslList = @(@(& wsl.exe --list --quiet 2>$null) |
            ForEach-Object { ("$_" -replace "`0", '').Trim() } |
            Where-Object { $_ -and $_.Length -le 64 -and $_ -match '^[A-Za-z0-9][\w.+-]*$' })
        # \w (not [A-Za-z0-9._+-]) because UNDERSCORES are real: Oracle ships OracleLinux_7_9 /
        # OracleLinux_8_7 / OracleLinux_9_1 and they install under exactly those names, so the
        # tighter class silently dropped every Oracle distro. Verified to still accept
        # Ubuntu-22.04, kali-linux, docker-desktop-data, openSUSE-Leap-15.5, FedoraLinux-42.
        # Known gap: a hand-imported `wsl --import "Dev Box"` name contains a space and is dropped.
        # Accepted - this is an INFO-severity inventory finding, and allowing spaces would let the
        # install-prompt prose back in, which is the bug being fixed.
        $wslHits = 0
        $wslProbeDeadlineS = 20
        $wslSw = [System.Diagnostics.Stopwatch]::StartNew()
        foreach ($d in $wslList) {
            if ($d -and $d.Trim()) {
                $distroName = $d.Trim()
                Add-Finding -ID "WSL_$($distroName -replace '[^a-z0-9]','')" -Phase "PHASE 101" -ThreatType "Container Surface" `
                    -Severity $SEV_INFO -Description "WSL distro present (potential lateral surface): $distroName" `
                    -Target "WSL: $distroName" -FixAction "Info" -Group "WSL / Container"
                if ($wslSw.Elapsed.TotalSeconds -ge $wslProbeDeadlineS) { continue }   # budget exhausted — inventory only for the rest
                $cronOut = Get-WslBoundedOutput -Distro $distroName -Cmd @('crontab','-l')
                $dotOut  = Get-WslBoundedOutput -Distro $distroName -Cmd @('cat','.bashrc','.profile')
                $wslLines = @(@($cronOut) + @($dotOut) | Where-Object { $_ -and "$_".Trim() })
                # Suspicious pattern matched PER LINE (never the whole blob) — a benign line
                # elsewhere in the crontab/dotfile must not suppress a malicious line next to it.
                # Benign-allowlist check is likewise per-line and full-line-anchored (rule #13):
                # an attacker can't smuggle a chained malicious command past the anchor, and an
                # unrelated benign line can't blanket-suppress the whole file.
                # Raw-IP downloads to loopback/RFC1918 addresses are excluded outright — a dev
                # box's .bashrc/cron routinely health-checks a locally-running service or a
                # docker-compose container's bridge IP (curl http://127.0.0.1:8080/health), which
                # is a routine local workflow, not exfil/staging to an attacker-controlled host.
                $wslRealHits = @($wslLines | Where-Object {
                    $curlIpMatch = $false
                    if ($_ -match '(curl|wget)\b.*https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                        $curlIpMatch = -not (Test-PrivateOrLoopbackIp $Matches[2])
                    }
                    ($curlIpMatch -or ($_ -match '/mnt/c/[^\s]*\.exe\b')) -and ($_ -notmatch $WSL_DEV_BENIGN_RE)
                })
                if ($wslRealHits.Count -gt 0) {
                    $wslHits++
                    $sample = ($wslRealHits | Select-Object -First 2) -join ' | '
                    Add-Finding -ID "WSLPERSIST_$(Get-StableId $distroName)" -Phase "PHASE 101" `
                        -ThreatType "WSL Linux-Side Persistence" -Severity $SEV_POSSIBLE `
                        -Description "WSL distro '$distroName' crontab/.bashrc/.profile references a raw-IP download or a /mnt/c/...exe cross-launch into Windows: $($sample.Substring(0,[Math]::Min(160,$sample.Length))) — moderate FP risk (developer boxes routinely run npm/pip/yarn installers or call Windows utilities from cron/profile scripts), so review-only, never auto-acted." `
                        -Target "WSL: $distroName" -FixAction "Info" -Group "WSL / Container"
                }
            }
        }
        if ($wslHits -gt 0) { Out-Typewriter "  -> $wslHits WSL DISTRO(S) WITH SUSPICIOUS CRON/DOTFILE CONTENT (REVIEW)." "WARN" }
    }
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Add-Finding -ID "DOCKER_PRESENT" -Phase "PHASE 101" -ThreatType "Container Surface" `
            -Severity $SEV_INFO -Description "Docker installed — verify daemon socket is not world-accessible" `
            -Target "docker.exe" -FixAction "Info" -Group "WSL / Container"
    }
    Out-Typewriter "  -> CONTAINER SURFACE AUDIT COMPLETE." "VER"
    }   # end Test-PhaseGate 101

    # ── PHASE 102: SVCHOST PARENT VALIDATION ──────────────────────────────────
    if (Test-PhaseGate 102) {
    Show-PhaseHeader "PHASE 102" "SVCHOST PARENT-CHILD MASQUERADE VALIDATION" "MASQUERADE"
    Out-Typewriter "VERIFYING ALL SVCHOST.EXE PARENT == SERVICES.EXE..." "HUNT"
    Invoke-QuantumBar "PROCESS PARENT MAP" 10 80
    $svcHits = 0
    $allW = Get-ProcSnapshot
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
    }   # end Test-PhaseGate 102

    # ── PHASE 103: SUSPICIOUS ARCHIVE SCAN ────────────────────────────────────
    if (Test-PhaseGate 103) {
    Show-PhaseHeader "PHASE 103" "SUSPICIOUS COMPRESSED ARCHIVE PAYLOAD AUDIT" "PHISHING"
    Out-Typewriter "SCANNING RECENT ARCHIVES IN DOWNLOAD PATHS..." "HUNT"
    $arcHits = 0
    # P1 multi-user: Downloads/Desktop/Temp were the ELEVATED process's own — a phishing archive
    # in the VICTIM's Downloads was invisible. Roots for EVERY reachable profile now, through ONE
    # Get-ScanFiles call so the budget is not multiplied by the profile count. As in Phase 97 the
    # bare `(Get-ScanFiles ...) | ... | ForEach-Object {}` STATEMENT is replaced by an assignment
    # plus a foreach — one fewer place a dropped paren could make ,$arr arrive as a single item.
    $zbArcHives  = @(@(Get-UserHives) | Sort-Object -Property Sid)   # SID order = stable memo key
    $zbArcOwners = @{}
    $zbArcRoots  = @()
    foreach ($zbHive in $zbArcHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        foreach ($zbR in @($zbUp.Downloads, $zbUp.Desktop, $zbUp.Temp)) {
            if (-not $zbR) { continue }
            $zbArcRoots += $zbR
            $zbArcOwners["$zbR".ToLowerInvariant()] = "$($zbHive.User)"
        }
    }
    $zbArcRoots = @($zbArcRoots | Select-Object -Unique)
    $zbArcFiles = (Get-ScanFiles -Path $zbArcRoots -TimeScoped) |
        Where-Object { ($_.Extension -match "\.(zip|7z|rar|iso|img)$") -and $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Length -gt 1024 }
    # `Select-Object -First 40` was a PER-ROOT flood cap; kept as a PER-OWNER cap so one noisy
    # profile cannot starve the others out of the report (same intent, honest under P1).
    $zbArcCount = @{}
    foreach ($zbAf in $zbArcFiles) {
        $zbOwner = 'MACHINE'; $zbOwnerLen = -1
        foreach ($zbK in @($zbArcOwners.Keys)) {
            if ("$($zbAf.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                $zbOwner = $zbArcOwners[$zbK]; $zbOwnerLen = $zbK.Length
            }
        }
        if (-not $zbArcCount.ContainsKey($zbOwner)) { $zbArcCount[$zbOwner] = 0 }
        if ($zbArcCount[$zbOwner] -ge 40) { continue }
        $zbArcCount[$zbOwner]++
        # ID was filename-only — "invoice.zip" downloaded by two users collapsed to one id.
        Add-Finding -ID "ARCHIVE_$(Get-StableId $zbAf.FullName)" -Phase "PHASE 103" `
            -ThreatType "Suspicious Archive" -Severity $SEV_POSSIBLE `
            -Description "[$zbOwner] Recent compressed archive (review for password-protected payload): $($zbAf.FullName)" `
            -Target "[$zbOwner] $($zbAf.FullName)" -FixAction "Info" -Group "Suspicious Archives"
        $arcHits++
    }
    if ($arcHits -eq 0) { Out-Typewriter "  -> [OK] NO RECENT SUSPICIOUS ARCHIVES." "GOOD" }
    }   # end Test-PhaseGate 103

    # ── PHASE 104: SCHEDULED TASK XML DEEP PARSE ──────────────────────────────
    if (Test-PhaseGate 104) {
    Show-PhaseHeader "PHASE 104" "SCHEDULED TASK XML DEEP PARSE / HIDDEN TASKS" "TASK"
    Out-Typewriter "PARSING TASK XML FOR Hidden=true AND SDDL LOCKS..." "HUNT"
    Invoke-QuantumBar "TASK XML INTROSPECTION" 12 90
    $taskDeepHits = 0
    # WS9: ComHandler <ClassId> actions, consumed by Phase 105's correlation against Phase 24's
    # COM-hijack findings. Reset per-scan (script-scope, not accumulated across runs).
    $global:ZB_ComHandlerTasks = @()
    if (Test-Path "$env:WINDIR\System32\Tasks") {
        Get-ChildItem -Path "$env:WINDIR\System32\Tasks" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $c = Get-Content $_.FullName -Raw -ErrorAction Stop
                if ($c -match "<Hidden>true</Hidden>" -and (Test-InScope $_.LastWriteTime)) {
                    # Hidden=true is the NORMAL maintenance-task attr for first-party Windows,
                    # Google/MSI/.NET-NGEN and most app updaters. On its own it is weak signal,
                    # and the XML lives in the protected System32\Tasks store, so never auto-delete:
                    # known vendor path -> INFO, unrecognized -> POSSIBLE (surfaced for review).
                    $taskKnown = ($_.FullName -match $HIDDEN_TASK_BENIGN_RE)
                    Add-Finding -ID "HIDDENTASK_$($_.Name -replace '[^a-z0-9]','')" -Phase "PHASE 104" `
                        -ThreatType "Hidden Scheduled Task" -Severity ($(if ($taskKnown) { $SEV_INFO } else { $SEV_POSSIBLE })) `
                        -Description "$(if ($taskKnown) { 'Hidden=true on a recognized vendor maintenance task' } else { 'Hidden=true on an unrecognized task (review)' }): $($_.FullName)" `
                        -Target $_.FullName -FixAction "Info" `
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
                # WS9: ComHandler action — the task invokes a COM object by CLSID (a mechanism this
                # phase did not previously parse at all — it only checked Hidden=true/SDDL), which
                # blends in with tooling that only logs plain process-creation actions. Same
                # Microsoft-task-path skip as the Hidden check above (FP-round-5): first-party
                # maintenance tasks legitimately use built-in Microsoft ComHandler CLSIDs under
                # \Tasks\Microsoft\. On its own this is weak signal (POSSIBLE + Info); it becomes a
                # real finding only if Phase 105 correlates the SAME CLSID against a genuine Phase 24
                # COM-hijack.
                if ($c -match '(?is)<ComHandler>.*?<ClassId>\s*(\{[0-9A-Fa-f-]{36}\})\s*</ClassId>') {
                    # Capture $matches immediately on the successful -match, before any other
                    # regex op (incl. the -notmatch below) can touch the automatic variable.
                    $chClsid = $matches[1].ToUpper()
                    if ($_.FullName -notmatch $HIDDEN_TASK_BENIGN_RE) {
                        Add-Finding -ID "COMHANDLERTASK_$($_.Name -replace '[^a-z0-9]','')" -Phase "PHASE 104" `
                            -ThreatType "ComHandler Task Trigger" -Severity $SEV_POSSIBLE `
                            -Description "Scheduled task action invokes a COM object via ComHandler (ClassId $chClsid) rather than a plain process launch: $($_.FullName)" `
                            -Target $_.FullName -FixAction "Info" -Group "Hidden Scheduled Tasks"
                        $taskDeepHits++
                        $global:ZB_ComHandlerTasks += [pscustomobject]@{ TaskPath = $_.FullName; ClassId = $chClsid }
                    }
                }
            } catch {}
        }
    }
    if ($taskDeepHits -eq 0) { Out-Typewriter "  -> [OK] NO HIDDEN OR SDDL-LOCKED TASKS." "GOOD" }
    }   # end Test-PhaseGate 104

    # ── PHASE 105: PERSISTENCE HEATMAP & CORRELATION ──────────────────────────
    # NOTE: the conditional "PHASE 105+" baseline-diff header nested in this body is part of
    # phase 105, not a phase of its own, so it lives INSIDE this gate (as it always did inside
    # the $Baseline test). Phase 105 also correlates $global:ZB_ComHandlerTasks, which PHASE 104
    # populates: under a custom -Phases scan that selects 105 without 104 the variable is simply
    # unset, @() -> the correlation loop does not run. No error, just no correlation.
    if (Test-PhaseGate 105) {
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

    # WS9: ComHandler-task <-> COM-hijack cross-correlation. A scheduled task invoking a CLSID via
    # ComHandler (Phase 104) is unremarkable by itself — plenty of first-party/vendor tasks do this.
    # It becomes a real finding only when that SAME CLSID is also the target of a genuine HKCU
    # CLSID hijack Phase 24 already flagged (HKLM-shadowing WITH a server override — Phase 24's
    # own real-hijack bar, not its per-user-registration-only review case). Sourced from Phase 24's
    # dedicated $global:ZB_ComHijackConfirmedClsids feed — NOT from re-checking stored finding
    # Severity, because a PARANOID-mode run promotes every POSSIBLE finding to HIGH (Add-Finding's
    # own escalation rule), which would otherwise make Phase 24's benign "per-user CLSID, no HKLM
    # twin" case storage-indistinguishable from a confirmed hijack right when PARANOID operators
    # are relying most on this correlation's precision.
    $hijackedClsids = if ($global:ZB_ComHijackConfirmedClsids) { $global:ZB_ComHijackConfirmedClsids } else { @{} }
    if ($hijackedClsids.Count -gt 0) {
        foreach ($ct in @($global:ZB_ComHandlerTasks)) {
            $hjPath = $hijackedClsids[$ct.ClassId]
            if (-not $hjPath) { continue }
            Out-ThreatBanner "COMHANDLER TASK <-> COM HIJACK CORRELATION" "$($ct.TaskPath) -> $($ct.ClassId)"
            Add-Finding -ID "COMCORR_$(Get-StableId ("$($ct.TaskPath)|$($ct.ClassId)"))" -Phase "PHASE 105" `
                -ThreatType "Multi-Vector Correlation" -Severity $SEV_POSSIBLE `
                -Description "Scheduled task '$($ct.TaskPath)' triggers CLSID $($ct.ClassId) via ComHandler, and that SAME CLSID is a confirmed HKLM-shadowing COM hijack Phase 24 already flagged ($hjPath) — a scheduled task wired to fire a hijacked COM object is a stronger persistence signal than either finding alone; review both artifacts together." `
                -Target $ct.TaskPath -FixAction "Info" -Group "Multi-Vector Correlation"
        }
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
    }   # end Test-PhaseGate 105

    # ── PHASE 106: MEMORY DUMP ARTIFACT SCAN ──────────────────────────────────
    if (Test-PhaseGate 106) {
    Show-PhaseHeader "PHASE 106" "MEMORY DUMP ARTIFACT SCAN (MINIDUMP / CRASHDUMPS)" "FORENSIC"
    Out-Typewriter "SCANNING CRASH DUMP LOCATIONS FOR SUSPICIOUS ARTIFACTS..." "HUNT"
    # P1 multi-user: four of the six paths were per-USER (%LOCALAPPDATA%/%APPDATA%\CrashDumps,
    # %TEMP%\*.dmp) and resolved to the ELEVATED process's own profile — i.e. the technician's,
    # not the victim's, on a standard-user endpoint. They are now expanded per profile and each
    # entry carries its owner. The two %SystemRoot% paths are MACHINE scope and are added exactly
    # ONCE, outside the profile loop, so an 8-profile box cannot report MEMORY.DMP eight times.
    $zbDumpHives = @(@(Get-UserHives) | Sort-Object -Property Sid)
    $dumpPaths = @()
    foreach ($zbMp in @("$env:SystemRoot\Minidump", "$env:SystemRoot\MEMORY.DMP")) {
        if ($zbMp) { $dumpPaths += @{ Path = $zbMp; User = 'MACHINE' } }
    }
    foreach ($zbHive in $zbDumpHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        $zbDu = "$($zbHive.User)"
        if ($zbUp.LocalAppData) {
            $dumpPaths += @{ Path = (Join-Path $zbUp.LocalAppData 'CrashDumps'); User = $zbDu }
            # The original list carried BOTH %TEMP%\*.dmp and the constructed
            # ...\AppData\Local\Temp\*.dmp because a per-user TEMP override makes them differ.
            # Both are kept; a box where they are identical just yields the same files twice and
            # Add-Finding's (now path-derived) de-dupe collapses it.
            $dumpPaths += @{ Path = (Join-Path $zbUp.LocalAppData 'Temp\*.dmp'); User = $zbDu }
        }
        if ($zbUp.AppData) { $dumpPaths += @{ Path = (Join-Path $zbUp.AppData 'CrashDumps'); User = $zbDu } }
        if ($zbUp.Temp)    { $dumpPaths += @{ Path = (Join-Path $zbUp.Temp '*.dmp');         User = $zbDu } }
    }
    $dumpFound = $false
    foreach ($zbDpEntry in $dumpPaths) {
        $dp      = "$($zbDpEntry.Path)"
        $zbOwner = "$($zbDpEntry.User)"
        if (-not $dp) { continue }
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
            Out-Decrypt -Text "[$zbOwner] $($item.FullName)" -Prefix "  [DUMP FILE] "
            # ID was filename-only: every profile has ...\CrashDumps\<app>.<pid>.dmp, and
            # "MEMORY.DMP" is a fixed name — the second user's dump was silently de-duped away.
            Add-Finding -ID "DUMP_$(Get-StableId $item.FullName)" -Phase "PHASE 106" -ThreatType "Memory Dump Artifact" `
                -Severity $sev -Description "[$zbOwner] Memory dump file found (age: $([Math]::Round($ageDays,1)) days): $($item.FullName)" `
                -Target "[$zbOwner] $($item.FullName)" -FixAction "Info" -Group "Memory Dump Artifacts"
            $dumpFound = $true
        }
    }
    # Check for PROCDUMP / dumper tool presence
    # WS0 wiring: externalized to 'cred_dump_tools' (AMSI-safe, same list).
    $dumpTools = $CRED_DUMP_TOOLS
    # One bounded walk + anchored regex (was 3 roots x 8 names = 24 recursions incl. whole profile).
    $dumpRegex = ($dumpTools | ForEach-Object { '^' + [regex]::Escape($_).Replace('\*','.*') + '$' }) -join '|'
    # P1 multi-user: %TEMP%/%LOCALAPPDATA%/%USERPROFILE% were the ELEVATED process's own, so a
    # credential dumper parked in the victim's profile was never seen. Every reachable profile's
    # roots go into the SAME single Get-ScanFiles call (this walk is whole-profile-wide and NOT
    # -TimeScoped, so a per-profile call would multiply the most expensive walk in the phase).
    $zbDtOwners = @{}
    $zbDtRoots  = @()
    foreach ($zbHive in $zbDumpHives) {
        if (-not $zbHive.ProfileReachable) { continue }
        $zbUp = Get-UserPaths $zbHive
        if (-not $zbUp) { continue }
        # Profile root subsumes Temp/LocalAppData on a normal box; both are still listed because
        # a redirected LocalAppData or a per-user TEMP override can sit outside it.
        foreach ($zbR in @($zbUp.Profile, $zbUp.Temp, $zbUp.LocalAppData)) {
            if (-not $zbR) { continue }
            $zbDtRoots += $zbR
            $zbDtOwners["$zbR".ToLowerInvariant()] = "$($zbHive.User)"
        }
    }
    $zbDtRoots = @($zbDtRoots | Select-Object -Unique)
    $dumpHits = (Get-ScanFiles -Path $zbDtRoots) | Where-Object { $_.Name -match $dumpRegex }
    foreach ($hit in $dumpHits) {
        $zbOwner = 'MACHINE'; $zbOwnerLen = -1
        foreach ($zbK in @($zbDtOwners.Keys)) {
            if ("$($hit.FullName)".ToLowerInvariant().StartsWith($zbK) -and $zbK.Length -gt $zbOwnerLen) {
                $zbOwner = $zbDtOwners[$zbK]; $zbOwnerLen = $zbK.Length
            }
        }
        Out-ThreatBanner "MEMORY DUMPER TOOL" "[$zbOwner] $($hit.FullName)"
        # ID was filename-only — "procdump.exe" under two profiles hashed to ONE id and the
        # second user's copy was silently dropped, i.e. left un-remediated. Path-hashed now.
        Add-Finding -ID "DUMPTOOL_$(Get-StableId $hit.FullName)" -Phase "PHASE 106" -ThreatType "Credential Dumping Tool" `
            -Severity $SEV_CRITICAL -Description "[$zbOwner] Memory/credential dumping tool found: $($hit.FullName)" `
            -Target "[$zbOwner] $($hit.FullName)" -FixAction "DeleteFile" -FixParam $hit.FullName -Group "Memory Dump Artifacts"
        $global:TrojanHits++; $dumpFound = $true
    }
    if (-not $dumpFound) { Out-Typewriter "  -> [OK] NO SUSPICIOUS DUMP FILES OR DUMPER TOOLS." "GOOD" }
    Out-Typewriter "  -> PHASE 106 COMPLETE." "VER"
    }   # end Test-PhaseGate 106

    # ── PHASE 107: EVENT LOG THREAT HUNTING ───────────────────────────────────
    if (Test-PhaseGate 107) {
    Show-PhaseHeader "PHASE 107" "EVENT LOG THREAT HUNTING (4624/4688/7045)" "EVT-HUNT"
    Out-Typewriter "MINING SECURITY/SYSTEM LOGS FOR ANOMALOUS PATTERNS..." "HUNT"
    Invoke-QuantumBar "EVENT LOG ANALYSIS" 12 100

    # ── EVIDENCE_ENGINE_PLAN P2 ────────────────────────────────────────────────
    # All three queries below used to be raw `Get-WinEvent -FilterHashtable ... -MaxEvents N |
    # Where-Object { Test-InScope $_.TimeCreated }`. Three separate defects in one line:
    #   1. take-newest-N-then-filter silently truncated the operator's -Hours window (P2);
    #   2. raw Get-WinEvent bypassed the Get-WinEventSafe wrapper, so an unregistered
    #      LogName/Provider threw a TERMINATING error -EA SilentlyContinue does not suppress,
    #      which unwinds to the module trap and drops the rest of the phase (CLAUDE.md rule);
    #   3. [xml]$_.ToXml() was built TWICE per event (once in the filter, once to render the
    #      finding) at ~26 ms a time — 10.3 s per 400 records, measured live on this box.
    # Now: StartTime inside the hashtable (server-side XPath), Get-WinEventSafe, and ONE
    # name-anchored regex pass over the raw XML string per record. See the helpers at the top
    # of this module for the measurements behind each choice.
    $zbEvtDeadlineS = 45      # wall-clock budget for each per-record analysis loop

    # 4624 — Anomalous logons (type 3/9/10 from unusual sources)
    Out-Typewriter "  -> SCANNING EVENT 4624 (LOGON) FOR ANOMALIES..." "INFO"
    $zb4624Q    = Get-ZbEvtQuery @{LogName='Security'; Id=4624} 20000 2000
    $zb4624Evts = @(Get-WinEventSafe $zb4624Q.Filter -MaxEvents $zb4624Q.Max)
    if ($zb4624Evts.Count -ge $zb4624Q.Max) {
        Out-Typewriter ("  -> [INFO] 4624 RECORD CAP REACHED ({0}) — OLDER EVENTS IN THE WINDOW WERE NOT EXAMINED." -f $zb4624Q.Max) "WARN"
    }
    $zbSuspLogons = New-Object System.Collections.ArrayList
    $zb4624Sw = [System.Diagnostics.Stopwatch]::StartNew(); $zb4624Cut = $false
    foreach ($zbEv in $zb4624Evts) {
        if ($zb4624Sw.Elapsed.TotalSeconds -gt $zbEvtDeadlineS) { $zb4624Cut = $true; break }
        $zbXml = ''
        try { $zbXml = $zbEv.ToXml() } catch { continue }
        $zbLogonType = Get-ZbEvtField $zbXml 'LogonType'
        $zbIpAddr    = Get-ZbEvtField $zbXml 'IpAddress'
        $zbUser      = Get-ZbEvtField $zbXml 'TargetUserName'
        # WS9: LogonType 9 (NewCredentials — e.g. `runas /netonly`, and how Mimikatz-class
        # Pass-the-Hash tooling stages a token) added alongside 3/10. Reuses the SAME
        # non-local-IP gate as the existing types, which is deliberately conservative here:
        # a NewCredentials logon is generated LOCALLY on the source box, so IpAddress is
        # typically blank/local for it — this stays POSSIBLE (the else branch below), never
        # escalated, and a genuinely remote-sourced Type 9 is the strong, low-FP case.
        if ((($zbLogonType -in @('3','9','10')) -and $zbIpAddr -and ($zbIpAddr -notmatch '(^-$|^::1$|^127\.)')) -or
            ($zbUser -match '\$' -and $zbLogonType -eq '3')) {
            [void]$zbSuspLogons.Add([pscustomobject]@{
                RecordId = $zbEv.RecordId
                When     = $(if ($zbEv.TimeCreated) { $zbEv.TimeCreated.ToString('HH:mm:ss yyyy-MM-dd') } else { 'unknown time' })
                User     = $zbUser
                Ip       = $zbIpAddr
                Type     = $zbLogonType
            })
        }
    }
    if ($zb4624Cut) { Out-Typewriter ("  -> [INFO] 4624 ANALYSIS DEADLINE ({0}s) REACHED — RESULT IS PARTIAL." -f $zbEvtDeadlineS) "WARN" }
    foreach ($zbHit in ($zbSuspLogons | Select-Object -First 50)) {
        $zbSev4624 = if ($zbHit.Type -eq '10') { $SEV_HIGH } else { $SEV_POSSIBLE }
        $zbTypeNote = if ($zbHit.Type -eq '9') { ' [NewCredentials — possible Pass-the-Hash / runas /netonly]' } else { '' }
        Add-Finding -ID "EVT4624_$($zbHit.RecordId)" -Phase "PHASE 107" -ThreatType "Anomalous Logon" `
            -Severity $zbSev4624 -Description "Suspicious logon: User=$($zbHit.User) Type=$($zbHit.Type) From=$($zbHit.Ip) @ $($zbHit.When)$zbTypeNote" `
            -Target "EventID:4624 Record:$($zbHit.RecordId)" -FixAction "Info" -Group "Event Log — Anomalous Logons"
    }
    if ($zb4624Evts.Count -eq 0) {
        Out-Typewriter "  -> [INFO] NO 4624 RECORDS RETURNED (EMPTY/ROLLED LOG, ACCESS DENIED, OR NONE IN WINDOW) — ABSENCE PROVES NOTHING." "WARN"
    } else {
        Out-Typewriter "  -> $($zbSuspLogons.Count) ANOMALOUS 4624 EVENTS FOUND (OF $($zb4624Evts.Count) IN WINDOW)." $(if ($zbSuspLogons.Count -gt 0) {"WARN"} else {"GOOD"})
    }

    # ── 4688 — Process creation with suspicious patterns (EVIDENCE_ENGINE_PLAN P3) ──
    # "Audit Process Creation" is OFF by default on Win10/11, and command-line capture is a
    # SECOND, INDEPENDENT policy. Without the latter, 4688 carries no arguments at all, so the
    # patterns below (powershell -enc, certutil -decode, ...) CANNOT match — and the phase used
    # to print "0 SUSPICIOUS 4688 PROCESS EVENTS" in green anyway. Read both policy states, say
    # so explicitly, and never report a clean result for a check that could not have fired.
    Out-Typewriter "  -> SCANNING EVENT 4688 (PROCESS CREATE) FOR MALWARE PATTERNS..." "INFO"
    $zbAudit = Get-ZbProcAuditState
    $zbAuditBlind = ($zbAudit.Audit -ne 'ON')
    $zbCmdlBlind  = ($zbAudit.CmdLine -ne 'ON')
    if ($zbAuditBlind) {
        Out-Typewriter ("  -> [!] PROCESS-CREATION AUDITING: {0} — {1}" -f $zbAudit.Audit, $zbAudit.AuditWhy) "WARN"
        # Posture/visibility observation, NOT a threat: Info + FixAction Info so it can never be
        # auto-selected (rule #1 / plan §7.1). The enable command lives in the description for an
        # operator to run by hand — it is a system-configuration change and is not ours to make.
        Add-Finding -ID "EVT4688_AUDIT_BLIND" -Phase "PHASE 107" -ThreatType "Audit Visibility Gap" `
            -Severity $SEV_INFO `
            -Description ("BLIND CHECK: the Security-log process-creation (4688) hunt could not have produced a result. Audit Process Creation is {0} — {1}. This is the Windows 10/11 default, so it usually means 'never configured', not 'tampered with'; but it does mean a zero result from this check is NOT evidence of a clean machine. To enable it (operator action, changes system audit policy): auditpol.exe /set /subcategory:""{{0CCE922B-69AE-11D9-BED3-505054503030}}"" /success:enable /failure:enable" -f $zbAudit.Audit, $zbAudit.AuditWhy) `
            -Target "Security log / Audit Process Creation" -FixAction "Info" -Group "Event Log — Audit Coverage"
    }
    if ($zbCmdlBlind) {
        Out-Typewriter ("  -> [!] 4688 COMMAND-LINE CAPTURE: OFF (ProcessCreationIncludeCmdLine_Enabled = {0}) — 4688 RECORDS CARRY NO ARGUMENTS." -f $(if ($null -eq $zbAudit.CmdLineRaw) { 'not set' } else { $zbAudit.CmdLineRaw })) "WARN"
        Add-Finding -ID "EVT4688_CMDLINE_BLIND" -Phase "PHASE 107" -ThreatType "Audit Visibility Gap" `
            -Severity $SEV_INFO `
            -Description ("BLIND CHECK: 4688 command-line capture is disabled (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = {0}). Process-creation records therefore contain the image path but NO arguments, so every argument-based detection in this phase (encoded PowerShell, certutil decode, bitsadmin transfer, rundll32 exports, ...) is structurally unable to match. A zero result here is a visibility gap, not a clean bill of health. To enable it (operator action): reg add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f" -f $(if ($null -eq $zbAudit.CmdLineRaw) { 'absent' } else { $zbAudit.CmdLineRaw })) `
            -Target "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled" `
            -FixAction "Info" -Group "Event Log — Audit Coverage"
    }
    # LOLBIN/abuse command-line vocabulary: data-driven when the key exists, otherwise the
    # already-shipped literal (an absent key must never silently disable the detection).
    $zb4688Re = if (@(Get-Sig 'evt4688_suspicious_cmdline_regex').Count) { @(Get-Sig 'evt4688_suspicious_cmdline_regex')[0] } `
                else { "(powershell.*-enc|cmd.*\/c.*DownloadString|certutil.*-decode|bitsadmin.*\/transfer|mshta.*vbscript|wscript.*\.js|cscript.*\.vbs|regsvr32.*\/s.*\/n.*\/u|rundll32.*,|installutil.*\/logfile|msiexec.*\/q.*http)" }
    $zb4688Q    = Get-ZbEvtQuery @{LogName='Security'; Id=4688} 20000 3000
    $zb4688Evts = @(Get-WinEventSafe $zb4688Q.Filter -MaxEvents $zb4688Q.Max)
    if ($zb4688Evts.Count -ge $zb4688Q.Max) {
        Out-Typewriter ("  -> [INFO] 4688 RECORD CAP REACHED ({0}) — OLDER EVENTS IN THE WINDOW WERE NOT EXAMINED." -f $zb4688Q.Max) "WARN"
    }
    $zbSuspProcs = New-Object System.Collections.ArrayList
    $zb4688Sw = [System.Diagnostics.Stopwatch]::StartNew(); $zb4688Cut = $false
    foreach ($zbEv in $zb4688Evts) {
        if ($zb4688Sw.Elapsed.TotalSeconds -gt $zbEvtDeadlineS) { $zb4688Cut = $true; break }
        $zbXml = ''
        try { $zbXml = $zbEv.ToXml() } catch { continue }
        $zbCmdl  = Get-ZbEvtField $zbXml 'CommandLine'
        $zbPName = Get-ZbEvtField $zbXml 'NewProcessName'
        $zbSubj  = Get-ZbEvtField $zbXml 'SubjectUserName'
        # Match the EventData fields, not $_.Message: the rendered message is localised and
        # laden with template prose, so a regex over it matches decoration on an English box
        # and nothing at all on a German one.
        $zbMatchText = ("{0} {1}" -f $zbPName, $zbCmdl).Trim()
        if ($zbMatchText -match $zb4688Re) {
            [void]$zbSuspProcs.Add([pscustomobject]@{
                RecordId = $zbEv.RecordId; Cmdl = $zbCmdl; PName = $zbPName; Subj = $zbSubj
            })
        }
    }
    if ($zb4688Cut) { Out-Typewriter ("  -> [INFO] 4688 ANALYSIS DEADLINE ({0}s) REACHED — RESULT IS PARTIAL." -f $zbEvtDeadlineS) "WARN" }
    foreach ($zbHit in ($zbSuspProcs | Select-Object -First 30)) {
        $zbShown = if ($zbHit.Cmdl) { $zbHit.Cmdl } else { $zbHit.PName }
        $zbCmdNote = if (-not $zbHit.Cmdl) { ' [NOTE: command-line capture is disabled on this host — image path only, arguments unknown]' } else { '' }
        Add-Finding -ID "EVT4688_$($zbHit.RecordId)" -Phase "PHASE 107" -ThreatType "Suspicious Process Creation" `
            -Severity $SEV_HIGH -Description "Suspicious 4688: $($zbHit.Subj) ran: $("$zbShown".Substring(0,[Math]::Min(150,"$zbShown".Length)))$zbCmdNote" `
            -Target "EventID:4688 Record:$($zbHit.RecordId)" -FixAction "Info" -Group "Event Log — Suspicious Processes"
        $global:TrojanHits++
    }
    if ($zbSuspProcs.Count -gt 0) {
        Out-Typewriter "  -> $($zbSuspProcs.Count) SUSPICIOUS 4688 PROCESS EVENTS." "WARN"
    } elseif ($zbAuditBlind -or $zbCmdlBlind) {
        # Never a green "0 events" line for a check that was structurally unable to fire.
        Out-Typewriter ("  -> [!] 4688 CHECK WAS BLIND (AUDIT: {0} / CMDLINE CAPTURE: {1}) — NO CONCLUSION CAN BE DRAWN FROM ITS ZERO RESULT." -f $zbAudit.Audit, $zbAudit.CmdLine) "WARN"
    } else {
        Out-Typewriter "  -> 0 SUSPICIOUS 4688 PROCESS EVENTS (OF $($zb4688Evts.Count) IN WINDOW; AUDIT + COMMAND-LINE CAPTURE BOTH ON, SO THIS RESULT IS MEANINGFUL)." "GOOD"
    }

    # 7045 — New service installed
    Out-Typewriter "  -> SCANNING EVENT 7045 (NEW SERVICE) FOR ROGUE INSTALLS..." "INFO"
    $zb7045Q    = Get-ZbEvtQuery @{LogName='System'; Id=7045} 5000 500
    $zb7045Evts = @(Get-WinEventSafe $zb7045Q.Filter -MaxEvents $zb7045Q.Max)
    if ($zb7045Evts.Count -ge $zb7045Q.Max) {
        Out-Typewriter ("  -> [INFO] 7045 RECORD CAP REACHED ({0}) — OLDER EVENTS IN THE WINDOW WERE NOT EXAMINED." -f $zb7045Q.Max) "WARN"
    }
    $zb7045Sw = [System.Diagnostics.Stopwatch]::StartNew(); $zb7045Cut = $false
    foreach ($zbEv in $zb7045Evts) {
        if ($zb7045Sw.Elapsed.TotalSeconds -gt $zbEvtDeadlineS) { $zb7045Cut = $true; break }
        try {
            $zbXml    = $zbEv.ToXml()
            $svcName  = Get-ZbEvtField $zbXml 'ServiceName'
            $svcFile  = Get-ZbEvtField $zbXml 'ImagePath'
            $svcType  = Get-ZbEvtField $zbXml 'ServiceType'
            # WS9: literal PsExec/PAExec/RemCom/WinExeSvc service-name match, checked ALONGSIDE
            # (not replacing) the shape-regex heuristic below — the shape regex requires 6-10
            # lowercase letters before "svc", which does NOT match "psexesvc" (psexe is only 5
            # chars), so the single most common lateral-movement tool family was previously
            # invisible to this phase. Near-zero legitimate software installs a service
            # literally named PSEXESVC, so this alone justifies CRITICAL — but stays FixAction
            # Info: this is a historical event-log correlation, nothing live to safely act on.
            $isLateralTool = $false
            foreach ($lm in $LATERAL_MOVEMENT_SVC_NAMES) {
                if ($lm -and $svcName -and "$svcName".ToLower().StartsWith($lm)) { $isLateralTool = $true; break }
            }
            $isSusp = ($svcFile -match "AppData|Temp|powershell|cmd\.exe|wscript|mshta|\.dll.*,|rundll32") -or
                      ($svcName -match "^[a-z]{6,10}svc$|^svc[a-z]{5,}$") -or $isLateralTool
            $sev = if ($isSusp) { $SEV_CRITICAL } else { $SEV_POSSIBLE }
            $svcNote = if ($isLateralTool) { 'KNOWN LATERAL-MOVEMENT TOOL SERVICE NAME (PsExec/PAExec/RemCom-class)' } elseif ($isSusp) { 'SUSPICIOUS' } else { 'review' }
            Add-Finding -ID "EVT7045_$($zbEv.RecordId)" -Phase "PHASE 107" -ThreatType "Rogue Service Install" `
                -Severity $sev -Description "New service (7045): $svcName | Path: $svcFile | Type: $svcType | $svcNote" `
                -Target "EventID:7045 Record:$($zbEv.RecordId)" -FixAction "Info" -Group "Event Log — New Services"
        } catch {}
    }
    if ($zb7045Cut) { Out-Typewriter ("  -> [INFO] 7045 ANALYSIS DEADLINE ({0}s) REACHED — RESULT IS PARTIAL." -f $zbEvtDeadlineS) "WARN" }
    Out-Typewriter "  -> $($zb7045Evts.Count) NEW SERVICE EVENTS IN TIME WINDOW." $(if ($zb7045Evts.Count -gt 0) {"WARN"} else {"GOOD"})
    Out-Typewriter "  -> PHASE 107 COMPLETE." "VER"
    }   # end Test-PhaseGate 107
}

# ══════════════════════════════════════════════════════════════════════════════
#  FORENSIC PERMISSION & INTEGRITY AUDIT — PHASES 108-115 (DEEP/PARANOID/STEALTH)
#  "What got changed that never should have." ACLs, ownership, code signatures,
#  service & PATH privilege-escalation surface, and security-control tamper.
# ══════════════════════════════════════════════════════════════════════════════
if ($PhasePlan.Integrity) {
    trap { Write-RecoveredError $_; continue }   # localize faults: resume at next phase, not end-of-group
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
    # NOTE: $WEAK_IDS / $TRUSTED_OWNERS above are BLOCK-level (phases 108/110/111/112/115 all
    # read them) and stay OUTSIDE every Test-PhaseGate wrap, exactly as the group banner does —
    # otherwise a custom -Phases scan selecting only, say, 111 would run Get-WeakAces with an
    # unset -WeakIds.
    if (Test-PhaseGate 108) {
    Show-PhaseHeader "PHASE 108" "NTFS ACL & OWNERSHIP INTEGRITY (CRITICAL PATHS)" "PERMISSIONS"
    Out-Typewriter "AUDITING ACLs ON SYSTEM PATHS FOR WEAK / WORLD-WRITABLE ACES..." "HUNT"
    $aclPaths = @(Get-Perm 'critical_acl_paths' | ForEach-Object { Expand-EnvPath $_ }) | Where-Object { $_ } | Select-Object -Unique
    $aclFindings = 0
    foreach ($cp in $aclPaths) {
        if (-not (Test-Path -LiteralPath $cp)) { continue }
        # A bare drive root (C:\) ALWAYS carries a default ACE granting BUILTIN\Users create/append
        # rights — flagging it is a guaranteed FP, and 'icacls C:\ /reset /T' would recursively reset
        # ACLs across the entire volume (catastrophic). Never audit/auto-remediate a drive root here.
        if ($cp -match '^[A-Za-z]:\\?$') { continue }
        Out-Typewriter "  ACL: $cp" "INFO"
        try {
            $acl  = Get-Acl -LiteralPath $cp -ErrorAction SilentlyContinue
            $weak = Get-WeakAces -Acl $acl -WeakIds $WEAK_IDS
            foreach ($ace in $weak) {
                $aclFindings++
                $idr = "$($ace.IdentityReference)"
                Out-Glitch "  [WEAK ACL] $cp <- $idr : $($ace.FileSystemRights)" Red
                # Review-only: a recursive 'icacls /reset /T' on a protected system directory can
                # break the OS, so it is NEVER auto-applied. Surfaced as POSSIBLE + Info; the suggested
                # command is in the description for an operator to run by hand after confirming.
                Add-Finding -ID "ACL108_$(Get-StableId ("$cp$idr"))" -Phase "PHASE 108" -ThreatType "Permission Abuse / Privesc" `
                    -Severity $SEV_POSSIBLE -Description "Weak ACE on protected path: '$idr' has '$($ace.FileSystemRights)' on $cp (privilege-escalation surface — a non-admin could replace SYSTEM-run files here). Review manually; suggested fix (do NOT auto-apply — recursive reset can break the OS): icacls `"$cp`" /reset /T /C /Q" `
                    -Target $cp -FixAction "Info" -Group "NTFS Permission Abuse"
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
                Add-Finding -ID "OWN108_$(Get-StableId $pf)" -Phase "PHASE 108" -ThreatType "Ownership Tamper / Privesc" `
                    -Severity $SEV_CRITICAL -Description "Protected system file owned by untrusted principal '$o': $pf (ownership change is a common pre-replacement tamper step). Review manually; suggested fix (NOT auto-applied — changing owner on a system binary is invasive): takeown /F `"$pf`" /A && icacls `"$pf`" /setowner `"NT SERVICE\TrustedInstaller`" /C /Q" `
                    -Target $pf -FixAction "Info" -Group "Ownership Tampering"
            }
        } catch {}
    }
    if ($aclFindings -eq 0) { Out-Typewriter "  -> [OK] NO WEAK ACLs OR OWNERSHIP TAMPER ON CRITICAL PATHS." "GOOD" }
    }   # end Test-PhaseGate 108

    # ── PHASE 109: SYSTEM BINARY INTEGRITY & CODE-SIGNATURE VERIFICATION ───────
    if (Test-PhaseGate 109) {
    Show-PhaseHeader "PHASE 109" "SYSTEM BINARY INTEGRITY & SIGNATURE VERIFICATION" "INTEGRITY"
    Out-Typewriter "VERIFYING AUTHENTICODE / CATALOG SIGNATURES ON PROTECTED BINARIES..." "HUNT"
    Invoke-QuantumBar "CRYPTOGRAPHIC SIGNATURE CHECK" 14 100
    $sigBad = 0       # genuine tamper — drives the SFC recommendation
    $sigUnverif = 0   # signature unverifiable in-process — review-only
    foreach ($pf in @(Get-Perm 'protected_system_files' | ForEach-Object { Expand-EnvPath $_ })) {
        if (-not (Test-Path -LiteralPath $pf)) { continue }
        # Only PE files (.exe/.dll/.sys) carry an Authenticode/catalog signature. A non-PE entry in
        # the list (e.g. drivers\etc\hosts) is NEVER 'Valid' signed, so signature-checking it is a
        # guaranteed CRITICAL FP every run — hosts integrity is covered by its own poisoning phase.
        if ($pf -notmatch '\.(exe|dll|sys)$') { continue }
        $v = Get-SignatureVerdict -FilePath $pf
        if ($v.Status -eq 'Valid' -and $v.Trusted) { continue }
        # Split by status (cf. Phase 15): a real tamper signal (HashMismatch / NotTrusted publisher,
        # or a Valid sig from a non-trusted signer) is CRITICAL/HIGH. An UnknownError/NotSigned/
        # unverifiable status is what a catalog-signed OS file returns when the catalog can't be read
        # in-process (transient corrupted type/module env) — surface POSSIBLE + Info, never escalate.
        if ($v.Status -eq 'HashMismatch' -or $v.Status -eq 'NotTrusted') {
            $sigBad++
            Out-Glitch "  [INTEGRITY FAIL] $pf — signature: $($v.Status)" Red
            Add-Finding -ID "SIG109_$(Get-StableId $pf)" -Phase "PHASE 109" -ThreatType "Binary Tamper / Integrity" `
                -Severity $SEV_CRITICAL -Description "Protected system binary failed signature check (Status=$($v.Status), Signer='$($v.Signer)'): $pf — possible replacement/patch. Verify with: sfc /scannow" `
                -Target $pf -FixAction "Info" -Group "System Binary Integrity"
        } elseif ($v.Status -eq 'Valid' -and -not $v.Trusted) {
            $sigBad++
            Out-Typewriter "  -> UNTRUSTED SIGNER on $pf : $($v.Signer)" "WARN"
            Add-Finding -ID "SIG109U_$(Get-StableId $pf)" -Phase "PHASE 109" -ThreatType "Binary Tamper / Integrity" `
                -Severity $SEV_HIGH -Description "System binary signed by a non-trusted publisher '$($v.Signer)': $pf (expected Microsoft). Possible substitution." `
                -Target $pf -FixAction "Info" -Group "System Binary Integrity"
        } else {
            $sigUnverif++
            Add-Finding -ID "SIG109X_$(Get-StableId $pf)" -Phase "PHASE 109" -ThreatType "Binary Tamper / Integrity" `
                -Severity $SEV_POSSIBLE -Description "Protected system binary signature unverifiable (Status=$($v.Status) — usually catalog-signed but the catalog couldn't be read in-process; review): $pf" `
                -Target $pf -FixAction "Info" -Group "System Binary Integrity"
        }
    }
    if ($sigBad -gt 0) {
        Add-Finding -ID "SFC109" -Phase "PHASE 109" -ThreatType "Integrity Remediation" -Severity $SEV_HIGH `
            -Description "$sigBad protected binaries failed integrity verification — run System File Checker to restore originals from the component store." `
            -Target "System File Checker" -FixAction "RunCmd" -FixParam "sfc /scannow" -Group "System Binary Integrity"
        Out-Typewriter "  -> $sigBad BINARY INTEGRITY FAILURES — SFC RECOMMENDED." "CRIT"
    } elseif ($sigUnverif -gt 0) {
        Out-Typewriter "  -> $sigUnverif binary signature(s) unverifiable in-process (review only; not auto-acted)." "WARN"
    } else { Out-Typewriter "  -> [OK] ALL PROTECTED BINARIES VALIDLY SIGNED BY TRUSTED PUBLISHERS." "GOOD" }

    # Accessibility-binary backdoor cross-check (sethc/utilman replaced or IFEO-debugged).
    # P12 (EVIDENCE_ENGINE_PLAN §2): the list now comes from data\detection_signatures.json via
    # Get-Sig — the SINGLE canonical source. It previously came from permission_baseline.json via
    # Get-Perm, and the two had drifted: the (never-read) signature copy carries hh.exe and the
    # baseline did not, so the HTML-Help IFEO backdoor was listed in data but checked nowhere, and
    # editing the signature copy had no effect on anything. permission_baseline.json is the ACL/owner
    # baseline for the perm-integrity phases; a detection list does not belong in it.
    $abNames = @(Get-Sig 'accessibility_binaries')
    if ($abNames.Count -eq 0) {
        Out-Typewriter "  -> ACCESSIBILITY BINARY LIST UNAVAILABLE (signature data missing) — CHECK SKIPPED, NOT CLEAN." "WARN"
    }
    foreach ($ab in $abNames) {
        # hh.exe ships as %WINDIR%\hh.exe and %WINDIR%\SysWOW64\hh.exe and never in System32, so a
        # System32-only probe could never have found it. Every location is checked, not just the
        # first hit — replacing either image is equally a backdoor. The System32 finding IDs are
        # left EXACTLY as they were so -Baseline diffs are unaffected; the two additional locations
        # carry a suffix so the three probes cannot collide in Add-Finding's ID dedupe.
        foreach ($abLoc in @(
            @{ P = (Expand-EnvPath "%WINDIR%\System32\$ab"); S = '' },
            @{ P = (Expand-EnvPath "%WINDIR%\$ab");          S = '_WINDIR' },
            @{ P = (Expand-EnvPath "%WINDIR%\SysWOW64\$ab"); S = '_WOW64' }
        )) {
            $abPath = $abLoc.P
            $abHere = $false
            try { $abHere = Test-Path -LiteralPath $abPath } catch { $abHere = $false }
            if (-not $abHere) { continue }
            $v = Get-SignatureVerdict -FilePath $abPath
            # Genuine tamper (bad hash / untrusted) or a validly-signed-but-NON-Microsoft replacement
            # = real backdoor (CRITICAL + sfc restore). An unverifiable status (catalog unreadable
            # in-process) is review-only — don't FP a legit sethc/utilman as a backdoor.
            if (($v.Status -eq 'Valid' -and -not $v.IsMs) -or $v.Status -eq 'HashMismatch' -or $v.Status -eq 'NotTrusted') {
                Out-ThreatBanner "ACCESSIBILITY BACKDOOR SUSPECT" "$ab signature=$($v.Status)"
                Add-Finding -ID "ACCESS109_$ab$($abLoc.S)" -Phase "PHASE 109" -ThreatType "Accessibility Backdoor" `
                    -Severity $SEV_CRITICAL -Description "Accessibility binary $ab is not a valid Microsoft signed file (Status=$($v.Status), Signer='$($v.Signer)') at $abPath — classic logon-screen SYSTEM backdoor. Restore with sfc /scannow." `
                    -Target $abPath -FixAction "RunCmd" -FixParam "sfc /scannow" -Group "Accessibility Backdoors"
            } elseif ($v.Status -ne 'Valid') {
                Add-Finding -ID "ACCESS109X_$ab$($abLoc.S)" -Phase "PHASE 109" -ThreatType "Accessibility Backdoor" `
                    -Severity $SEV_POSSIBLE -Description "Accessibility binary $ab signature unverifiable in-process (Status=$($v.Status); usually catalog-signed — review): $abPath" `
                    -Target $abPath -FixAction "Info" -Group "Accessibility Backdoors"
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
    }   # end Test-PhaseGate 109

    # ── PHASE 110: REGISTRY KEY ACL / WEAK-PERMISSION AUDIT ───────────────────
    if (Test-PhaseGate 110) {
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
                Add-Finding -ID "REGACL110_$(Get-StableId ("$rk$idr"))" -Phase "PHASE 110" -ThreatType "Registry Permission Abuse" `
                    -Severity $SEV_HIGH -Description "Persistence/privesc registry key writable by '$idr' ($($ace.RegistryRights)): $rk — non-admins can plant autostart entries." `
                    -Target $rk -FixAction "Info" -Group "Registry Permission Abuse"
            }
        } catch {}
    }
    if ($regAcl -eq 0) { Out-Typewriter "  -> [OK] NO WEAK ACLs ON PERSISTENCE REGISTRY KEYS." "GOOD" }
    }   # end Test-PhaseGate 110

    # ── PHASE 111: SERVICE PRIVILEGE-ESCALATION AUDIT ─────────────────────────
    if (Test-PhaseGate 111) {
    Show-PhaseHeader "PHASE 111" "SERVICE PRIVESC — UNQUOTED PATHS & WRITABLE BINARIES" "PRIVESC"
    Out-Typewriter "INSPECTING SERVICE IMAGE PATHS FOR PRIVILEGE-ESCALATION FLAWS..." "HUNT"
    Invoke-QuantumBar "SERVICE BINARY ACL ANALYSIS" 12 110
    $svcPriv = 0
    # unquoted_path_whitelist is documented in data\permission_baseline.json and referenced by
    # coverage_matrix.json as this phase's suppression source, but nothing ever read it — the
    # phase flagged every unquoted service path with zero suppression. Now honoured. Ships empty
    # by design ("rare; keep tight"), so this changes nothing until an operator adds an entry.
    $unquotedAllow = @(Get-Perm 'unquoted_path_whitelist')
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
        $uqAllowed = $false
        foreach ($ua in $unquotedAllow) { if ($ua -and $ip -like "*$ua*") { $uqAllowed = $true; break } }
        if (-not $uqAllowed -and $ip -notmatch '^\s*"' -and $ip -match '\s' -and $ip -match '\\' -and $ip -notmatch '^[A-Za-z]:\\Windows\\(System32|SysWOW64)\\') {
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
                        -Severity $SEV_CRITICAL -Description "Service '$($svc.Name)' runs '$exe' which is writable by '$idr' — a non-admin can replace it to gain $($svc.StartName) privileges. Review manually; resetting the ACL may break the app's updater, so it is NOT auto-applied. Suggested: icacls `"$exe`" /reset /C /Q" `
                        -Target $exe -FixAction "Info" -Group "Service Privilege Escalation"
                }
            } catch {}
        }
    }
    if ($svcPriv -eq 0) { Out-Typewriter "  -> [OK] NO SERVICE PRIVILEGE-ESCALATION FLAWS FOUND." "GOOD" }
    }   # end Test-PhaseGate 111

    # ── PHASE 112: PATH & DLL-HIJACK SURFACE (WRITABLE DIRECTORIES) ────────────
    if (Test-PhaseGate 112) {
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
                Add-Finding -ID "PATH112_$(Get-StableId $pd)" -Phase "PHASE 112" -ThreatType "DLL Hijack / PATH Privesc" `
                    -Severity $SEV_HIGH -Description "Directory on the system PATH is writable by '$idr': $pd — enables DLL/binary planting that elevated processes will load. Review manually; stripping Users/Everyone here can break a legit app that owns this dir, so it is NOT auto-applied. Suggested: icacls `"$pd`" /remove:g `"*S-1-1-0`" `"*S-1-5-11`" `"*S-1-5-32-545`" /C /Q" `
                    -Target $pd -FixAction "Info" -Group "DLL Hijack Surface"
            }
        } catch {}
    }
    if ($pathHits -eq 0) { Out-Typewriter "  -> [OK] NO WRITABLE DIRECTORIES ON SYSTEM PATH." "GOOD" }
    }   # end Test-PhaseGate 112

    # ── PHASE 113: RECENTLY MODIFIED PROTECTED SYSTEM FILES ───────────────────
    if (Test-PhaseGate 113) {
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
                # A recently-changed file with a genuine tamper status (HashMismatch/NotTrusted) is a
                # strong drop indicator (CRITICAL for .sys, HIGH otherwise). An UnknownError/unverifiable
                # status on a catalog-signed file (in-process catalog read failure) is review-only —
                # being recently modified plus unverifiable is corroborating, not conclusive (POSSIBLE).
                $genuine = ($v.Status -eq 'HashMismatch' -or $v.Status -eq 'NotTrusted')
                $sev = if (-not $genuine) { $SEV_POSSIBLE } elseif ($f.Extension -match 'sys') { $SEV_CRITICAL } else { $SEV_HIGH }
                Out-Typewriter "  -> CHANGED+UNVERIFIED: $($f.FullName) [$($v.Status)] $($f.LastWriteTime)" "CRIT"
                Add-Finding -ID "RECSYS113_$(Get-StableId $f.FullName)" -Phase "PHASE 113" -ThreatType "System File Tamper" `
                    -Severity $sev -Description "Recently-modified protected-directory file with failed signature ($($v.Status)): $($f.FullName) (modified $($f.LastWriteTime)). Driver/binary drop indicator." `
                    -Target $f.FullName -FixAction "Info" -Group "System File Tamper" }
        }
    }
    if ($recentSys -eq 0) { Out-Typewriter "  -> [OK] NO CHANGED/UNSIGNED FILES IN PROTECTED DIRS (IN WINDOW)." "GOOD" }
    }   # end Test-PhaseGate 113

    # ── PHASE 114: SECURITY CONTROL HEALTH & TAMPER CONSOLIDATION ──────────────
    if (Test-PhaseGate 114) {
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
    }   # end Test-PhaseGate 114

    # ── PHASE 115: AUTORUN TARGET WRITABLE-PATH AUDIT (HIJACKABLE PERSISTENCE) ──
    if (Test-PhaseGate 115) {
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
                        Add-Finding -ID "AUTO115_$(Get-StableId ("$ak$($p.Name)"))" -Phase "PHASE 115" -ThreatType "Hijackable Autorun / Privesc" `
                            -Severity $SEV_HIGH -Description "HKLM autorun '$($p.Name)' runs '$texe' which is writable by '$idr' — a non-admin can replace it to run code at every boot/logon as the next user. Review manually; resetting the ACL may break the app's updater, so it is NOT auto-applied. Suggested: icacls `"$texe`" /reset /C /Q" `
                            -Target $texe -FixAction "Info" -Group "Hijackable Autoruns"
                    }
                } catch {}
            }
        }
    }
    if ($autoHits -eq 0) { Out-Typewriter "  -> [OK] NO HIJACKABLE AUTORUN TARGETS." "GOOD" }
    }   # end Test-PhaseGate 115
    # Group-level footer — stays OUTSIDE the per-phase gates, like the group banner at the top.
    Out-Typewriter "  -> PERMISSION & INTEGRITY AUDIT COMPLETE (PHASES 108-115)." "VER"
}

# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT COMPLETE — COMPUTE RISK SCORE
# ══════════════════════════════════════════════════════════════════════════════
