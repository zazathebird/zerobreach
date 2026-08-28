<#
.SYNOPSIS
    Tests for tools\New-CoverageMatrix.ps1. Runs on Linux under pwsh 7 and on PS 5.1.

.DESCRIPTION
    Builds fixture engine modules in a temp directory (the real modules currently contain no
    failing case, so fixtures are the stronger proof — G6 brief), runs the tool against them,
    and asserts the matrix content: exact phase set in numeric order, fractional numbers kept,
    mode gates (including a null gate reported rather than defaulted), severities in rank
    order with dynamic expressions recorded, destructive fix actions, signature-key orphan
    lists in both directions, byte-identical reruns, and the exit-2 hard-failure paths.

    The shipped data\coverage_matrix.generated.json is the tool's output for these fixtures;
    one assertion compares it byte-for-byte against a fresh run, so the shipped file can
    never drift from what the tool produces. Regenerate it with -UpdateShippedMatrix after a
    deliberate output-format change.

    The fixture modules are code inside here-strings, which the parse check of THIS file does
    not validate — they are validated by the tool run itself, which hard-fails on any fixture
    parse error.

.PARAMETER ToolPath
    Path of the tool under test. Defaults to ..\New-CoverageMatrix.ps1; the fail-on-revert
    matrix points this at mutated copies.

.PARAMETER UpdateShippedMatrix
    Rewrite data\coverage_matrix.generated.json from the canonical fixture run before
    asserting against it.

.EXAMPLE
    pwsh tools/tests/Test-CoverageMatrix.ps1
#>
[CmdletBinding()]
param(
    [string]$ToolPath,

    [switch]$UpdateShippedMatrix
)

$ErrorActionPreference = 'Stop'

$script:ScythePass = 0
$script:ScytheFail = 0
$script:ScytheFailures = @()

function Assert-ScytheTrue {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:ScythePass = $script:ScythePass + 1
        Write-Host ('  ok    ' + $Name)
    }
    else {
        $script:ScytheFail = $script:ScytheFail + 1
        $script:ScytheFailures += $Name
        Write-Host ('  FAIL  ' + $Name)
    }
}

function Assert-ScytheEqual {
    param($Expected, $Actual, [string]$Name)
    Assert-ScytheTrue -Condition (('' + $Expected) -eq ('' + $Actual)) -Name ($Name + " (expected '$Expected', got '$Actual')")
}

$here = $PSScriptRoot
$projectRoot = Split-Path -Path (Split-Path -Path $here -Parent) -Parent
if ([string]::IsNullOrEmpty($ToolPath)) {
    $ToolPath = Join-Path -Path (Split-Path -Path $here -Parent) -ChildPath 'New-CoverageMatrix.ps1'
}
$shippedMatrix = Join-Path -Path (Join-Path -Path $projectRoot -ChildPath 'data') -ChildPath 'coverage_matrix.generated.json'

$tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('scythetest_coverage_' + $PID)
$fxDir = Join-Path -Path $tempDir -ChildPath 'modules'
$varDir = Join-Path -Path $tempDir -ChildPath 'variant'
New-Item -ItemType Directory -Path $fxDir -Force | Out-Null
New-Item -ItemType Directory -Path $varDir -Force | Out-Null
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# --------------------------------------------------------------------------------------------
# Fixture modules — between them: integer and fractional phase numbers, every mode gate, an
# ungated phase, several severities on one phase, destructive fix actions, signature reads,
# backtick continuations, calls nested in if/foreach, and preflight output above any header.
# --------------------------------------------------------------------------------------------

$moduleCore = @'
# Fixture module: core phases (integer + one fractional, QUICK/FULL gates).

if ($PhasePlan.Quick) {
    Write-PhaseHeader -Phase 1 -Title "SYSTEM INVENTORY" -Category "Inventory"
    $builds = Get-SignatureSet -Key "os_builds"
    Add-Finding -ID "P1_a" -Phase "PHASE 1" -ThreatType "Inventory" -Severity "INFO" `
                -Description "OS build recorded" -Target $env:COMPUTERNAME -FixAction "Info"
}

if ($PhasePlan.Quick) {
    Write-PhaseHeader -Phase 2 -Title "STARTUP ITEMS" -Category "Persistence"
    foreach ($item in $startupItems) {
        Add-Finding -ID "P2_a" -Phase "PHASE 2" -ThreatType "Persistence" -Severity "INFO" `
                    -Description "Startup entry" -Target $item -FixAction "Info"
        if ($item.Suspicious) {
            Add-Finding -ID "P2_b" -Phase "PHASE 2" -ThreatType "Persistence" `
                        -Severity "HIGH" -Description "Unsigned startup entry" `
                        -Target $item -FixAction "DisableEntry" -FixParam $item.Path
        }
    }
}

if ($PhasePlan.Full) {
    Write-PhaseHeader -Phase 9.5 -Title "SHADOW COPY AUDIT" -Category "Recovery"
    Add-Finding -ID "P9_a" -Phase "PHASE 9.5" -ThreatType "Recovery" -Severity "POSSIBLE" `
                -Description "Shadow copies disabled" -Target "VSS" -FixAction "Info"
}
'@

$moduleDeep = @'
# Fixture module: DEEP-band phases (dynamic severity, destructive fix, signature reads).

if ($PhasePlan.Deep) {
    Write-PhaseHeader -Phase 41 -Title "UNSIGNED DRIVERS" -Category "Drivers"
    $blocklist = Get-SignatureSet -Key "driver_blocklist"
    foreach ($drv in $drivers) {
        if ($found) {
            $sev = "CRITICAL"
            Add-Finding -ID "P41_a" -Phase "PHASE 41" -ThreatType "Drivers" -Severity $sev `
                        -Description "Blocklisted driver" -Target $drv.Path -FixAction "QuarantineFile" -FixParam $drv.Path
        }
        Add-Finding -ID "P41_b" -Phase "PHASE 41" -ThreatType "Drivers" -Severity "CRITICAL" `
                    -Description "Unsigned boot driver" -Target $drv.Path -FixAction "QuarantineFile"
    }
}

if ($PhasePlan.Deep) {
    Write-PhaseHeader -Phase 74.5 -Title "LOLBIN SWEEP" -Category "Execution"
    $lol = Get-SignatureSet -Key "lolbins"
    $ghost = Get-SignatureSet -Key "ghost_key"
    Add-Finding -ID "P74_a" -Phase "PHASE 74.5" -ThreatType "Execution" -Severity "HIGH" `
                -Description "LOLBin invocation trace" -Target "C:\Windows\Temp" -FixAction "Info"
}
'@

$moduleHunt = @'
# Fixture module: preflight output, an ungated phase, and a HUNT-band phase.

Add-Finding -ID "PRE_a" -Phase "PREFLIGHT" -ThreatType "Preflight" -Severity "INFO" `
            -Description "Preflight environment note" -Target "host" -FixAction "Info"

Write-PhaseHeader -Phase 12 -Title "ORPHAN SERVICE CHECK" -Category "Services"
Add-Finding -ID "P12_a" -Phase "PHASE 12" -ThreatType "Services" -Severity "POSSIBLE" `
            -Description "Service binary missing" -Target "svchost" -FixAction "Info"
Add-Finding -ID "P12_b" -Phase "PHASE 12" -ThreatType "Services" -Severity "INFO" `
            -Description "Service inventory note" -Target "svchost" -FixAction "Info"

if ($PhasePlan.Hunt) {
    Write-PhaseHeader -Phase 140 -Title "MEMORY STRINGS SWEEP" -Category "Memory"
    Add-Finding -ID "P140_a" -Phase "PHASE 140" -ThreatType "Memory" -Severity "HIGH" `
                -Description "Injected thread marker" -Target 4711 -FixAction "KillProcess"
}
'@

$signatures = @'
{
  "os_builds": ["10.0.19045", "10.0.22631"],
  "driver_blocklist": ["baddrv.sys"],
  "lolbins": ["certutil.exe", "mshta.exe"],
  "dead_weight": ["never-read.dat"]
}
'@

# Variant modules: ungated phases in lexical-trap order, a header behind a non-plan `if`
# inside a plan `if`, an or-gate, a duplicate phase number, a dynamic signature key, and a
# header whose phase number is an expression.
$variantA = @'
# Variant fixture A.

Write-PhaseHeader -Phase 10 -Title "TEN" -Category "CatA"
Add-Finding -ID "V10_a" -Phase "PHASE 10" -ThreatType "CatA" -Severity "INFO" `
            -Description "note" -Target "t" -FixAction "Info"

Write-PhaseHeader -Phase 2 -Title "TWO" -Category "CatA"

if ($PhasePlan.Deep) {
    if ($retryNeeded) {
        Write-PhaseHeader -Phase 50 -Title "FIFTY" -Category "CatB"
    }
}

if ($PhasePlan.Deep -or $PhasePlan.Hunt) {
    Write-PhaseHeader -Phase 60 -Title "SIXTY" -Category "CatB"
}
'@

$variantB = @'
# Variant fixture B.

if ($PhasePlan.Deep) {
    Write-PhaseHeader -Phase 50 -Title "FIFTY AGAIN" -Category "CatB"
    $set = Get-SignatureSet -Key $dynamicName
}

Write-PhaseHeader -Phase $n -Title "DYNAMIC" -Category "CatC"
'@

[System.IO.File]::WriteAllText((Join-Path -Path $fxDir -ChildPath 'Module-Core.ps1'), $moduleCore, $utf8NoBom)
[System.IO.File]::WriteAllText((Join-Path -Path $fxDir -ChildPath 'Module-Deep.ps1'), $moduleDeep, $utf8NoBom)
[System.IO.File]::WriteAllText((Join-Path -Path $fxDir -ChildPath 'Module-Hunt.ps1'), $moduleHunt, $utf8NoBom)
$sigPath = Join-Path -Path $fxDir -ChildPath 'signatures.json'
[System.IO.File]::WriteAllText($sigPath, $signatures, $utf8NoBom)
[System.IO.File]::WriteAllText((Join-Path -Path $varDir -ChildPath 'Variant-A.ps1'), $variantA, $utf8NoBom)
[System.IO.File]::WriteAllText((Join-Path -Path $varDir -ChildPath 'Variant-B.ps1'), $variantB, $utf8NoBom)

# --------------------------------------------------------------------------------------------
# The canonical run
# --------------------------------------------------------------------------------------------

Write-Host 'canonical fixture run'
$out1 = Join-Path -Path $tempDir -ChildPath 'matrix1.json'
& $ToolPath -Root $fxDir -SignaturePath $sigPath -OutPath $out1 -GeneratedFrom 'fixture-demo' 6>$null | Out-Null
Assert-ScytheEqual 0 ([int]$LASTEXITCODE) 'fixture run exits zero'
Assert-ScytheTrue (Test-Path -LiteralPath $out1) 'matrix file written'
$mx = Get-Content -LiteralPath $out1 -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-ScytheEqual 'fixture-demo' $mx.generated_from 'provenance pinned by -GeneratedFrom'

# 1. Exact phase set, in numeric order (the join asserts membership AND order at once).
$phaseKeys = @($mx.phases | ForEach-Object { $_.phase })
Assert-ScytheEqual '1|2|9.5|12|41|74.5|140' ($phaseKeys -join '|') 'exact phase set in numeric order'

# 2. Fractional phases keep decimals and sort numerically, not lexically.
Assert-ScytheTrue ($phaseKeys -contains '74.5') 'fractional phase 74.5 keeps its decimal'
Assert-ScytheTrue (-not ($phaseKeys -contains '74')) 'fractional phase is not floored to 74'
Assert-ScytheTrue (([array]::IndexOf($phaseKeys, '9.5')) -lt ([array]::IndexOf($phaseKeys, '12'))) 'numeric order: 9.5 before 12 (lexical inverts this)'
Assert-ScytheTrue (([array]::IndexOf($phaseKeys, '2')) -lt ([array]::IndexOf($phaseKeys, '140'))) 'numeric order: 2 before 140 (lexical inverts this)'

# 3. Mode gates: named per phase; an undetectable gate is null and reported, never defaulted.
$p1 = @($mx.phases | Where-Object { $_.phase -eq '1' })[0]
$p2 = @($mx.phases | Where-Object { $_.phase -eq '2' })[0]
$p95 = @($mx.phases | Where-Object { $_.phase -eq '9.5' })[0]
$p12 = @($mx.phases | Where-Object { $_.phase -eq '12' })[0]
$p41 = @($mx.phases | Where-Object { $_.phase -eq '41' })[0]
$p745 = @($mx.phases | Where-Object { $_.phase -eq '74.5' })[0]
$p140 = @($mx.phases | Where-Object { $_.phase -eq '140' })[0]
Assert-ScytheEqual 'Quick' $p1.mode_gate 'phase 1 gated on the Quick flag'
Assert-ScytheEqual 'Full' $p95.mode_gate 'phase 9.5 gated on the Full flag'
Assert-ScytheEqual 'Deep' $p41.mode_gate 'phase 41 gated on the Deep flag'
Assert-ScytheEqual 'Hunt' $p140.mode_gate 'phase 140 gated on the Hunt flag'
Assert-ScytheTrue ($null -eq $p12.mode_gate) 'ungated phase carries mode_gate null, not a default'
Assert-ScytheTrue (@($mx.summary.ungated_phases) -contains '12') 'ungated phase is reported in the summary'
Assert-ScytheEqual 1 @($mx.summary.ungated_phases).Count 'only the genuinely ungated phase is listed'

# Severities: rank order (POSSIBLE before INFO — alphabetical inverts that), dynamic kept.
Assert-ScytheEqual 'HIGH|INFO' (@($p2.severities) -join '|') 'several severities on one phase, in rank order'
Assert-ScytheEqual 'POSSIBLE|INFO' (@($p12.severities) -join '|') 'severities sorted by rank, not alphabetically'
Assert-ScytheEqual 'CRITICAL|dynamic' (@($p41.severities) -join '|') 'an expression severity is recorded as dynamic, not dropped'

# 5. Destructive fix actions are captured as such.
Assert-ScytheTrue (@($p41.fix_actions) -contains 'QuarantineFile') 'destructive fix action captured (QuarantineFile)'
Assert-ScytheTrue (@($p140.fix_actions) -contains 'KillProcess') 'destructive fix action captured (KillProcess)'
Assert-ScytheEqual 1 ([int]$mx.summary.phases_per_fix_action.QuarantineFile) 'per-fix-action summary counts the quarantining phase'

# Signature reads per phase, and the backtick-continued call landed on its phase.
Assert-ScytheEqual 'driver_blocklist' (@($p41.signature_keys) -join '|') 'signature key read is attributed to its phase'
Assert-ScytheEqual 'ghost_key|lolbins' (@($p745.signature_keys) -join '|') 'several signature keys on one phase'
Assert-ScytheEqual 2 ([int]$p2.finding_calls) 'backtick-continued call inside if/foreach is counted'

# 6. Orphan keys, both directions.
Assert-ScytheEqual 'ghost_key' (@($mx.summary.signature_keys_missing_from_file) -join '|') 'key read but missing from the file is flagged (a bug)'
Assert-ScytheEqual 'dead_weight' (@($mx.summary.signature_keys_unread) -join '|') 'key present but read by nothing is flagged (dead weight)'

# Preflight output above any header is counted, not attributed to a phase.
Assert-ScytheEqual 1 ([int]$mx.summary.unattributed_finding_calls) 'preflight finding call is counted as unattributed'

# QUICK skip flag and per-mode counts (ceilings 30/80/133/162).
Assert-ScytheTrue ($p41.skipped_in_quick) 'phase 41 marked skipped in QUICK'
Assert-ScytheTrue (-not $p2.skipped_in_quick) 'phase 2 not marked skipped in QUICK'
Assert-ScytheEqual 4 ([int]$mx.summary.phases_per_mode.QUICK) 'QUICK reaches four fixture phases'
Assert-ScytheEqual 6 ([int]$mx.summary.phases_per_mode.FULL) 'FULL reaches six fixture phases'
Assert-ScytheEqual 7 ([int]$mx.summary.phases_per_mode.HUNT) 'HUNT reaches all seven fixture phases'
Assert-ScytheEqual 3 ([int]$mx.summary.phases_per_module.'Module-Core.ps1') 'per-module count'
Assert-ScytheEqual 'Module-Core.ps1|Module-Deep.ps1|Module-Hunt.ps1' (@($mx.scan.modules) -join '|') 'scanned module list recorded'

# --------------------------------------------------------------------------------------------
# 4. Determinism: same input, byte-identical file — and the shipped file IS the tool output
# --------------------------------------------------------------------------------------------

Write-Host 'determinism'
$out2 = Join-Path -Path $tempDir -ChildPath 'matrix2.json'
& $ToolPath -Root $fxDir -SignaturePath $sigPath -OutPath $out2 -GeneratedFrom 'fixture-demo' 6>$null | Out-Null
$hash1 = (Get-FileHash -LiteralPath $out1 -Algorithm SHA256).Hash
$hash2 = (Get-FileHash -LiteralPath $out2 -Algorithm SHA256).Hash
Assert-ScytheEqual $hash1 $hash2 'running twice produces byte-identical output'

if ($UpdateShippedMatrix) {
    Copy-Item -LiteralPath $out1 -Destination $shippedMatrix -Force
    Write-Host ('  (rewrote ' + $shippedMatrix + ')')
}
Assert-ScytheTrue (Test-Path -LiteralPath $shippedMatrix) 'data/coverage_matrix.generated.json ships with the tool'
$hashShipped = (Get-FileHash -LiteralPath $shippedMatrix -Algorithm SHA256).Hash
Assert-ScytheEqual $hash1 $hashShipped 'shipped matrix is byte-identical to a fresh fixture run'

# Without -SignaturePath the orphan lists are null — "not checked" must not read as "clean".
$out3 = Join-Path -Path $tempDir -ChildPath 'matrix3.json'
& $ToolPath -Root $fxDir -OutPath $out3 -GeneratedFrom 'fixture-demo' 6>$null | Out-Null
$mx3 = Get-Content -LiteralPath $out3 -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-ScytheTrue ($null -eq $mx3.summary.signature_keys_missing_from_file) 'no signature file: missing-keys list is null, not empty'
Assert-ScytheTrue ($null -eq $mx3.summary.signature_keys_unread) 'no signature file: unread-keys list is null, not empty'

# --------------------------------------------------------------------------------------------
# Variant fixtures: gate walking, duplicates, dynamic key, dynamic header
# --------------------------------------------------------------------------------------------

Write-Host 'variant fixtures'
$outV = Join-Path -Path $tempDir -ChildPath 'matrixV.json'
& $ToolPath -Root $varDir -OutPath $outV -GeneratedFrom 'fixture-demo' 6>$null | Out-Null
$mv = Get-Content -LiteralPath $outV -Raw -Encoding UTF8 | ConvertFrom-Json
$vKeys = @($mv.phases | ForEach-Object { $_.phase })
Assert-ScytheEqual '2|10|50|50|60' ($vKeys -join '|') 'variant phase set (duplicate 50 listed twice)'
Assert-ScytheEqual '2|10' (@($mv.summary.ungated_phases) -join '|') 'ungated list numerically sorted (lexical gives 10 before 2)'
$v50 = @($mv.phases | Where-Object { $_.phase -eq '50' })
Assert-ScytheEqual 'Variant-A.ps1' $v50[0].module 'duplicate phases ordered by module'
Assert-ScytheEqual 'Deep' $v50[0].mode_gate 'a non-plan if between phase and gate is skipped, not treated as the gate'
$v60 = @($mv.phases | Where-Object { $_.phase -eq '60' })[0]
Assert-ScytheEqual 'Deep+Hunt' $v60.mode_gate 'an or-gate records every plan flag in the condition'
Assert-ScytheEqual '50' (@($mv.summary.duplicate_phases) -join '|') 'duplicate phase number reported'
Assert-ScytheEqual 1 ([int]$mv.summary.dynamic_signature_reads) 'expression signature key counted as dynamic, not recorded as a literal'
Assert-ScytheEqual 1 @($mv.summary.headers_unparsed).Count 'header with an expression phase number is reported'
Assert-ScytheTrue (('' + @($mv.summary.headers_unparsed)[0]) -like 'Variant-B.ps1:*') 'the unparsed header names its module and line'

# --------------------------------------------------------------------------------------------
# Hard failures: never an empty matrix, never the promoted filename
# --------------------------------------------------------------------------------------------

Write-Host 'hard failures (two refusal messages below are expected)'
$noFile = Join-Path -Path $tempDir -ChildPath 'should_not_exist.json'
& $ToolPath -Root $fxDir -PhaseHeaderCommand 'No-Such-Command' -OutPath $noFile 6>$null | Out-Null
Assert-ScytheEqual 2 ([int]$LASTEXITCODE) 'zero phase headers is a hard error, exit 2'
Assert-ScytheTrue (-not (Test-Path -LiteralPath $noFile)) 'zero phase headers writes no file'
$promoted = Join-Path -Path $tempDir -ChildPath 'coverage_matrix.json'
& $ToolPath -Root $fxDir -OutPath $promoted 6>$null | Out-Null
Assert-ScytheEqual 2 ([int]$LASTEXITCODE) 'refuses the promoted filename coverage_matrix.json, exit 2'
Assert-ScytheTrue (-not (Test-Path -LiteralPath $promoted)) 'the promoted filename is never written'

# --------------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------------

Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host ('{0} passed, {1} failed' -f $script:ScythePass, $script:ScytheFail)
if ($script:ScytheFail -gt 0) {
    Write-Host 'Failed assertions:'
    foreach ($f in $script:ScytheFailures) { Write-Host ('  - ' + $f) }
    exit 1
}
exit 0
