<#
.SYNOPSIS
    RUNTIME test for the WS7 synthesis band (engine/Phases-7.ps1, phases 160-162).

.DESCRIPTION
    Like Test-Extended-Smoke.ps1, this EXECUTES real engine code rather than inspecting
    it with the AST — it stubs the loader helpers, feeds a synthetic $global:AuditFindings
    set describing a plausible intrusion plus unrelated noise, dot-sources the real module,
    and asserts on what it produced.

    Correlation is pure logic with no Windows dependency, so unlike most of this engine it
    can be fully exercised on Linux. That makes it the one part of the HUNT band that is
    genuinely verified rather than merely parse-checked.
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

Write-Host "`n=== WS7 SYNTHESIS BAND (160-162) — RUNTIME ===" -ForegroundColor Cyan

# ── Loader stubs ─────────────────────────────────────────────────────────────
# Deliberately minimal. If the module starts depending on a helper that is not stubbed
# here, this test fails loudly rather than drifting away from the real loader.
$global:STEALTH_MODE = $true          # suppresses banner writes
$global:PARANOID_MODE = $false
$SEV_CRITICAL='CRITICAL'; $SEV_HIGH='HIGH'; $SEV_POSSIBLE='POSSIBLE'; $SEV_INFO='INFO'
$OUT_ROOT = Join-Path ([IO.Path]::GetTempPath()) "zbcorr_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $OUT_ROOT -Force | Out-Null
$STAMP = '20260819_120000'
$PhasePlan = @{ Hunt = $true }
function Write-RecoveredError { param($ErrorRecord) Write-Host "  [RECOVERED] $($ErrorRecord.Exception.Message)" -ForegroundColor DarkYellow; $script:recovered++ }
function Write-Log { param([string]$m) }
function Show-PhaseHeader { param([string]$Phase,[string]$Desc,[string]$Category="") }
function Stop-PhaseTiming { }
function Out-Typewriter { param([string]$t,[string]$k) }
function ConvertTo-CsvSafeCell { param([string]$v)
    if ($v -match '^[=+\-@\t\r]') { $v = "'" + $v }
    '"' + ($v -replace '"','""') + '"'
}
$script:recovered = 0
$global:AuditFindings = New-Object System.Collections.Generic.List[object]
$script:added = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param([string]$ID,[string]$Phase,[string]$ThreatType,[string]$Severity,[string]$Description,
          [string]$Target,[string]$FixAction,[string]$FixParam="",[string]$Group="")
    $o = @{ ID=$ID; Phase=$Phase; ThreatType=$ThreatType; Severity=$Severity; Description=$Description
            Target=$Target; FixAction=$FixAction; Group=$Group }
    $script:added.Add($o); $global:AuditFindings.Add($o)
}
# Real kill-chain stage table from the shipped signature DB — not a copy.
$sig = Get-Content (Join-Path $root 'data/detection_signatures.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$KILLCHAIN_STAGES = $sig.killchain_stages
Assert-True 'killchain_stages present in signature DB' ($KILLCHAIN_STAGES.Count -ge 6)

# ── Synthetic incident: one real chain + unrelated noise ─────────────────────
# The chain is linked ONLY by shared entities (a path, a PID) — never by time — which
# is the property phase 160 depends on.
$mal = if ($IsWindows) { 'C:\Users\bob\AppData\Roaming\svc32.exe' } else { 'C:\Users\bob\AppData\Roaming\svc32.exe' }
function Seed { param($ID,$Phase,$Type,$Sev,$Target,$Desc,$Group)
    $o=@{ID=$ID;Phase=$Phase;ThreatType=$Type;Severity=$Sev;Description=$Desc;Target=$Target;FixAction='Info';Group=$Group}
    $global:AuditFindings.Add($o)
}
Seed 'A1' 'PHASE 74.5' 'Email Phishing'      'HIGH'     "$mal" "Attachment dropped $mal from an Outlook cache" 'Email'
Seed 'A2' 'PHASE 20'   'Persistence'         'CRITICAL' "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\svc" "Run key points at $mal" 'Run Key'
Seed 'A3' 'PHASE 141'  'Process Injection'   'POSSIBLE' "PID:4242 $mal" "PID:4242 has unbacked threads; image $mal" 'Unbacked Memory'
Seed 'A4' 'PHASE 59'   'RAT / C2 Beacon'     'HIGH'     "PID:4242" "PID:4242 beaconing to evil-c2.xyz on a fixed interval" 'C2 Beacon'
Seed 'A5' 'PHASE 54'   'Ransomware'          'CRITICAL' "PID:4242" "PID:4242 deleted shadow copies (inhibit recovery)" 'Backup Tamper'
# Noise: unrelated, no shared entity with the chain and none with each other.
Seed 'N1' 'PHASE 67'   'Adware / PUP'        'POSSIBLE' "C:\Program Files\Foo\foo.dll"      "Adware registry entry for Foo" 'Adware'
Seed 'N2' 'PHASE 39'   'Certificate'         'POSSIBLE' "Cert:\LocalMachine\Root\ABC123"    "Unrecognised root CA" 'Certs'
Seed 'N3' 'PHASE 80'   'Hardening'           'INFO'     "TPM"                                "TPM not present" 'Hardening'

$before = $global:AuditFindings.Count
. (Join-Path $root 'engine/Phases-7.ps1')

Write-Host "`n-- results --" -ForegroundColor Cyan
Assert-That 'no recovered errors during execution' $script:recovered 0

$chains = @($script:added | Where-Object { $_.ID -like 'CHAIN160_*' })
Assert-True 'at least one correlated chain reported' ($chains.Count -ge 1)
Assert-That 'exactly one chain reported (noise did not fuse)' $chains.Count 1

if ($chains.Count -ge 1) {
    $d = "$($chains[0].Description)"
    Assert-True 'chain names the malicious binary'      ($d -match 'svc32\.exe')
    Assert-True 'chain includes the run-key finding'    ($d -match 'PHASE 20')
    Assert-True 'chain includes the C2 finding'         ($d -match 'PHASE 59')
    Assert-True 'chain includes the impact finding'     ($d -match 'PHASE 54')
    Assert-True 'chain EXCLUDES unrelated adware'       (-not ($d -match 'PHASE 67'))
    Assert-True 'chain EXCLUDES unrelated certificate'  (-not ($d -match 'PHASE 39'))
    Assert-True 'chain spans multiple kill-chain stages' ($d -match 'kill-chain stage')
    Assert-True 'chain reports Persistence stage'       ($d -match 'Persistence')
    Assert-True 'chain reports Impact stage'            ($d -match 'Impact')
    Assert-That 'chain finding is FixAction Info'       $chains[0].FixAction 'Info'
    Assert-True 'chain severity is not CRITICAL (never auto-selected)' ($chains[0].Severity -ne 'CRITICAL')
}

# Rule #1: nothing in this band may be auto-selected for a destructive fix.
$bad = @($script:added | Where-Object { $_.FixAction -ne 'Info' })
Assert-That 'every synthesis finding is FixAction Info' $bad.Count 0

# Phase 161/162 need files that exist; none of the synthetic paths do, so both must
# degrade cleanly rather than throwing or emitting a bogus timeline.
$tl = @($script:added | Where-Object { $_.ID -eq 'TL162_EXPORT' })
Assert-That 'no timeline written when no artifact resolves' $tl.Count 0
$pz = @($script:added | Where-Object { $_.ID -eq 'PZ161_EARLIEST' })
Assert-That 'no patient-zero claim when no artifact resolves' $pz.Count 0

# ── A "common noun" entity must NOT fuse the scan into one chain ────────────
# C:\Windows\System32\cmd.exe is mentioned by dozens of unrelated descriptions. Linking
# on it would merge everything into a single meaningless mega-chain, which is worse than
# no correlation at all — it buries the real chain inside noise. Phase 160 therefore
# refuses to link on any entity shared by more than 12 findings.
$script:added.Clear(); $global:AuditFindings.Clear()
for ($i = 1; $i -le 15; $i++) {
    Seed "C$i" "PHASE $((10 + $i))" "Misc Type $i" 'HIGH' "C:\Windows\System32\cmd.exe" `
         "Unrelated finding $i that happens to mention C:\Windows\System32\cmd.exe" "Group$i"
}
. (Join-Path $root 'engine/Phases-7.ps1')
$noiseChains = @($script:added | Where-Object { $_.ID -like 'CHAIN160_*' })
Assert-That 'a common-noun entity produces NO chain (no mega-fusion)' $noiseChains.Count 0

# ── Multi-stage coverage must be what promotes a low-severity chain ─────────
# Three POSSIBLE findings across three threat types score 6 + 6 = 12 on severity and
# type diversity alone, which is BELOW the reporting threshold of 14. They are only
# reported because they span kill-chain stages. This asserts the stage bonus exists;
# without it this chain is silently dropped and a real low-and-slow intrusion is missed.
$script:added.Clear(); $global:AuditFindings.Clear()
$q = 'C:\ProgramData\quiet\q.exe'
Seed 'Q1' 'PHASE 10' 'Dropper Artifact'  'POSSIBLE' "$q" "Suspicious binary staged at $q" 'Delivery'
Seed 'Q2' 'PHASE 31' 'Persistence'       'POSSIBLE' "$q" "Startup entry references $q"    'Persistence'
Seed 'Q3' 'PHASE 60' 'DNS Tunnel C2'     'POSSIBLE' "$q" "$q resolves high-entropy subdomains" 'C2'
. (Join-Path $root 'engine/Phases-7.ps1')
$quiet = @($script:added | Where-Object { $_.ID -like 'CHAIN160_*' })
Assert-That 'a low-severity chain is promoted by kill-chain stage coverage' $quiet.Count 1

# ── UNC paths must correlate too (lateral-movement findings name them) ──────
$script:added.Clear(); $global:AuditFindings.Clear()
Seed 'U1' 'PHASE 66' 'Worm' 'HIGH' '\\\\FS01\\public\\spread.exe' 'Worm copy found at \\\\FS01\\public\\spread.exe' 'Share Worm'
Seed 'U2' 'PHASE 29' 'Persistence' 'CRITICAL' 'Task \\ZB' 'Scheduled task action runs \\\\FS01\\public\\spread.exe' 'Task'
Seed 'U3' 'PHASE 59' 'RAT / C2 Beacon' 'HIGH' 'PID:99' 'Beacon from \\\\FS01\\public\\spread.exe to bad.top' 'C2'
. (Join-Path $root 'engine/Phases-7.ps1')
$unc = @($script:added | Where-Object { $_.ID -like 'CHAIN160_*' })
Assert-That 'UNC-path findings correlate into one chain' $unc.Count 1

# ── Phases 161/162 resolve real files, so they need a real Windows path ─────
# Get-ZbEntities matches drive-letter and UNC paths only — correct for a Windows-only
# tool, but it means a POSIX temp path is invisible to it. Rather than weaken the engine
# regex to make a test pass on Linux, these two assertions are declared Windows-only.
if (-not $IsWindows) {
    Write-Host "  [SKIP] phases 161/162 artifact resolution — Windows-only (POSIX paths are not file entities by design)" -ForegroundColor DarkYellow
    Remove-Item -LiteralPath $OUT_ROOT -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "`
  $pass passed, $fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
    if ($fail) { exit 1 } else { exit 0 }
}

$realFile = Join-Path $OUT_ROOT 'dropper_test.exe'
Set-Content -LiteralPath $realFile -Value 'inert test artifact' -Encoding ASCII
$script:added.Clear(); $global:AuditFindings.Clear()
Seed 'B1' 'PHASE 10' 'Trojan' 'HIGH' "$realFile" "Executable dropped in a temp directory: $realFile" 'Temp Drop'
Seed 'B2' 'PHASE 20' 'Persistence' 'HIGH' "HKCU\...\Run\x" "Run key points at $realFile" 'Run Key'
. (Join-Path $root 'engine/Phases-7.ps1')
$pz2 = @($script:added | Where-Object { $_.ID -eq 'PZ161_EARLIEST' })
Assert-That 'patient-zero reported when an artifact resolves' $pz2.Count 1
$tl2 = @($script:added | Where-Object { $_.ID -eq 'TL162_EXPORT' })
Assert-That 'timeline reported when an artifact resolves' $tl2.Count 1
if ($tl2.Count -eq 1) {
    $csv = "$($tl2[0].Target)"
    Assert-True 'timeline CSV exists on disk' (Test-Path -LiteralPath $csv)
    if (Test-Path -LiteralPath $csv) {
        $txt = Get-Content -LiteralPath $csv -Raw
        Assert-True 'timeline has a header row'   ($txt -match 'TimestampUTC,Severity')
        Assert-True 'timeline names the artifact' ($txt -match 'dropper_test\.exe')
        Assert-True 'timeline cells are quoted (CSV-injection safe)' ($txt -match '"\d{4}-\d{2}-\d{2}')
    }
}

Remove-Item -LiteralPath $OUT_ROOT -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`n  $pass passed, $fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
