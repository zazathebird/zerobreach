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
$loader = Get-Content (Join-Path $root 'ZeroBreach-V23.ps1') -Raw
$srv    = Get-Content (Join-Path $root 'ZeroBreach-Server.ps1') -Raw
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
Assert-True 'loader  — ZB_IS_WOW64 computed'   ($loader -match '\$global:ZB_IS_WOW64\s*=\s*\(\(-not \[Environment\]::Is64BitProcess\)')
Assert-True 'loader  — ZB_SYS32 uses Sysnative' ($loader -match "ZB_SYS32.*Sysnative")
foreach ($fn in @('Get-RegVal64','Get-RegNames64','Get-RegSubKeys64')) {
    Assert-True "loader  — $fn defined" ($loader -match "function $fn\b")
    Assert-True "loader  — $fn uses the 64-bit registry view" `
        ($loader -match "(?s)function $fn\b.*?RegistryView\]::Registry64")
}
$p5 = Get-Content (Join-Path $root 'engine/Phases-5.ps1') -Raw
Assert-True 'Phase 134 reads TaskCache through the 64-bit view' `
    ($p5 -match '(?s)Get-ZbTaskTreeLeaves.*?Get-RegNames64')

# ── 7. Allowlist integrity gate (ADVERSARY_ANALYSIS E1) ──────────────────────
Assert-True 'loader  — Join-AllowRegex sanitises before compiling' `
    ($loader -match '(?s)function Join-AllowRegex.*?Test-AllowPatternSafety')
Assert-True 'loader  — refusals are recorded for reporting' `
    ($loader -match '(?s)function Join-AllowRegex.*?ZB_SIG_TAMPER')
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
foreach ($rel in @('engine/Phases-0.ps1','engine/Phases-5.ps1','engine/Phases-7.ps1')) {
    $src = Get-Content (Join-Path $root $rel) -Raw
    Assert-True "$rel — no raw Get-AuthenticodeSignature" (-not ($src -match '(?m)^\s*[^#]*Get-AuthenticodeSignature'))
    Assert-True "$rel — no raw Get-ItemPropertyValue"     (-not ($src -match '(?m)^\s*[^#]*Get-ItemPropertyValue'))
    Assert-True "$rel — no raw Get-WinEvent -FilterHashtable" (-not ($src -match 'Get-WinEvent\s+-FilterHashtable'))
    Assert-True "$rel — no raw Get-FileHash"              (-not ($src -match '(?m)[^-]Get-FileHash\b'))
    # Deliberate design constraint: no P/Invoke anywhere in this band. Declaring
    # OpenProcess/ReadProcessMemory/VirtualQueryEx is the code shape AV heuristics flag,
    # and an engine Defender blocks at load detects nothing at all.
    Assert-True "$rel — no P/Invoke (AMSI posture)"       (-not ($src -match 'DllImport|Add-Type\s+-TypeDefinition'))
    # Get-ScanFiles returns ,$arr — piping it delivers the whole array as ONE item.
    Assert-True "$rel — Get-ScanFiles is never piped directly" (-not ($src -match 'Get-ScanFiles[^\r\n]*\|\s*(Where|ForEach)'))
}

# ── 10. Cross-view phases must actually consult two sources ──────────────────
Assert-True 'Phase 134 — compares registry against Get-ScheduledTask' `
    ($p5 -match '(?s)PHASE 134.*?Get-ScheduledTask.*?Get-ZbTaskTreeLeaves|(?s)Get-ZbTaskTreeLeaves.*?PHASE 134.*?Get-ScheduledTask')
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
$loaderAst = Get-Ast 'ZeroBreach-V23.ps1'
$wanted = @('Test-AllowPatternSafety','Join-AllowRegex')
$defs = $loaderAst.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $wanted -contains $n.Name }, $true)
Assert-That 'both integrity functions extracted from the loader' $defs.Count 2
$global:ZB_SIG_TAMPER = New-Object System.Collections.Generic.List[string]
$script:SIGSTUB = $null
function Get-Sig([string]$Name) { if ($script:SIGSTUB -and $null -ne $script:SIGSTUB[$Name]) { @($script:SIGSTUB[$Name]) } else { @() } }
foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }

# (a) a healthy allowlist survives untouched
$script:SIGSTUB = @{ k = @('\\AppData\\Roaming\\Vendor\\', '\.tmp$') }
$global:ZB_SIG_TAMPER.Clear()
$r = Join-AllowRegex 'k'
Assert-True  'healthy allowlist compiles through unchanged' ($r -eq '\\AppData\\Roaming\\Vendor\\|\.tmp$')
Assert-That  'healthy allowlist records no tampering' $global:ZB_SIG_TAMPER.Count 0

# (b) THE ATTACK: one entry widened to '.*' must be refused, not honoured
$script:SIGSTUB = @{ k = @('\\AppData\\Roaming\\Vendor\\', '.*') }
$global:ZB_SIG_TAMPER.Clear()
$r = Join-AllowRegex 'k'
Assert-True  'universal pattern is DROPPED from the compiled allowlist' ($r -notmatch '\.\*')
Assert-True  'the legitimate sibling entry survives'  ($r -eq '\\AppData\\Roaming\\Vendor\\')
Assert-That  'the refusal is recorded for reporting'  $global:ZB_SIG_TAMPER.Count 1
Assert-True  'the refusal names the offending key'    ("$($global:ZB_SIG_TAMPER[0])" -match '^k:')
Assert-True  'the refusal is described as UNIVERSAL'  ("$($global:ZB_SIG_TAMPER[0])" -match 'UNIVERSAL')

# (c) other universal spellings are caught too — '.*' is not the only way to say it
foreach ($u in @('.+', '^.*$', '(?s).*', '[\s\S]*', '.*|foo', '')) {
    $script:SIGSTUB = @{ k = @($u) }
    $global:ZB_SIG_TAMPER.Clear()
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
$global:ZB_SIG_TAMPER.Clear()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$r = Join-AllowRegex 'k'
$sw.Stop()
Assert-True 'backtracking-bait pattern does not hang the load (<3s)' ($sw.Elapsed.TotalSeconds -lt 3)

# (f) an absent key still fails closed — the pre-existing contract must not regress
$script:SIGSTUB = @{}
Assert-That 'an absent allowlist key still yields (?!)' (Join-AllowRegex 'nope') '(?!)'

Write-Host "`n  $pass passed, $fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
