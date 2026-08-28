<#
.SYNOPSIS
    Tests for tools\Get-PhaseTimingReport.ps1. Runs on Linux under pwsh 7 and on PS 5.1.

.DESCRIPTION
    Works from fixtures\console_sample.log (log parsing, take-last, fractional phases, the
    cumulative distribution) and fixtures\run_small.json (budget gate, source preference,
    comparison against fixtures\run_before.json). Truncated-log and budget variants are
    derived into a temp directory at run time.

.EXAMPLE
    pwsh tools/tests/Test-PhaseTimingReport.ps1
#>
[CmdletBinding()]
param()

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
$tool = Join-Path -Path (Split-Path -Path $here -Parent) -ChildPath 'Get-PhaseTimingReport.ps1'
$fixtureDir = Join-Path -Path $here -ChildPath 'fixtures'
$logFx = Join-Path -Path $fixtureDir -ChildPath 'console_sample.log'
$smallFx = Join-Path -Path $fixtureDir -ChildPath 'run_small.json'
$beforeFx = Join-Path -Path $fixtureDir -ChildPath 'run_before.json'

$tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('scythetest_timing_' + $PID)
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# Empty budget table for runs where the gate must stay out of the way.
$noBudgetPath = Join-Path -Path $tempDir -ChildPath 'no_budget.json'
[System.IO.File]::WriteAllText($noBudgetPath, '{ "mode_totals": {}, "phase_budgets": {} }', $utf8NoBom)

# --------------------------------------------------------------------------------------------
# 1 + 2 + 4 + 6: the fixture log
# --------------------------------------------------------------------------------------------

Write-Host 'console log parsing'
$res = & $tool -LogPath $logFx -Budget $noBudgetPath -PassThru
Assert-ScytheEqual 'ConsoleLog' $res.Source 'log-only input reads the console log'
Assert-ScytheEqual 8 $res.PhaseCount 'fixture log parses to eight phases'
Assert-ScytheEqual 65 $res.TotalSeconds 'fixture log total is 65.0s'
Assert-ScytheEqual 0 ([int]$res.ExitCode) 'unbudgeted run exits zero'

$keys = @($res.Phases | ForEach-Object { $_.Key })
Assert-ScytheTrue ($keys -contains '74.5') 'fractional phase 74.5 keeps its decimal'
Assert-ScytheTrue (-not ($keys -contains '74')) 'fractional phase is not merged into 74'

$phase2 = @($res.Phases | Where-Object { $_.Key -eq '2' })[0]
Assert-ScytheEqual 3 $phase2.Seconds 'duplicate TIMING lines: the last value is kept'
Assert-ScytheEqual 1 $res.DuplicatesDiscarded 'one duplicate TIMING line was discarded'
$logText = [string]((& $tool -LogPath $logFx -Budget $noBudgetPath -Format Text) -join [Environment]::NewLine)
Assert-ScytheTrue ($logText.Contains('discarded')) 'text output says duplicates were discarded'

$shareSum = 0.0
foreach ($p in @($res.Phases)) { $shareSum = $shareSum + $p.Share }
Assert-ScytheTrue ([math]::Abs($shareSum - 100) -le 0.5) ('phase shares sum to 100 within rounding (' + $shareSum + ')')
Assert-ScytheEqual 5 $res.P80Count 'five phases account for 80% of the fixture total'

# --------------------------------------------------------------------------------------------
# 3. Truncated log: last phase started, never finished
# --------------------------------------------------------------------------------------------

Write-Host 'truncated log'
$truncPath = Join-Path -Path $tempDir -ChildPath 'truncated.log'
$truncated = (Get-Content -LiteralPath $logFx -Raw -Encoding UTF8) +
"[INFO] ================ PHASE 99 — EVENT LOG SWEEP ================`n[WARN] channel enumeration in progress"
[System.IO.File]::WriteAllText($truncPath, $truncated, $utf8NoBom)
$resTrunc = & $tool -LogPath $truncPath -Budget $noBudgetPath -PassThru
Assert-ScytheTrue ($resTrunc.Incomplete) 'truncated log is reported as incomplete, not thrown on'
Assert-ScytheTrue (@($resTrunc.IncompletePhases) -contains '99') 'the unfinished phase is named'
Assert-ScytheEqual 8 $resTrunc.PhaseCount 'unfinished phase contributes no timing'

# --------------------------------------------------------------------------------------------
# Source preference: run record wins over the log, and the output says so
# --------------------------------------------------------------------------------------------

Write-Host 'source preference'
$resBoth = & $tool -Path $smallFx -LogPath $logFx -Budget $noBudgetPath -PassThru
Assert-ScytheEqual 'RunRecord' $resBoth.Source 'run record preferred when both sources are given'
$bothText = [string]((& $tool -Path $smallFx -LogPath $logFx -Budget $noBudgetPath -Format Text) -join [Environment]::NewLine)
Assert-ScytheTrue ($bothText.Contains('run record')) 'text output names the source it used'
Assert-ScytheEqual 125 $resBoth.Shortfall 'DEEP record with 8 phases reports the 125-phase shortfall'

# --------------------------------------------------------------------------------------------
# 5. Budget gate: over exits non-zero, under exits zero
# --------------------------------------------------------------------------------------------

Write-Host 'budget gate'
$overPath = Join-Path -Path $tempDir -ChildPath 'budget_over.json'
[System.IO.File]::WriteAllText($overPath, '{ "mode_totals": { "DEEP": 100 }, "phase_budgets": {} }', $utf8NoBom)
$resOver = & $tool -Path $smallFx -Budget $overPath -PassThru
Assert-ScytheTrue ($resOver.OverBudget) 'a 216s DEEP run against a 100s budget is over'
Assert-ScytheEqual 1 ([int]$LASTEXITCODE) 'over-budget input exits non-zero'

$underPath = Join-Path -Path $tempDir -ChildPath 'budget_under.json'
[System.IO.File]::WriteAllText($underPath, '{ "mode_totals": { "DEEP": 10000 }, "phase_budgets": {} }', $utf8NoBom)
$resUnder = & $tool -Path $smallFx -Budget $underPath -PassThru
Assert-ScytheTrue (-not $resUnder.OverBudget) 'a 216s DEEP run against a 10000s budget is under'
Assert-ScytheEqual 0 ([int]$LASTEXITCODE) 'under-budget input exits zero'

$phaseBudgetPath = Join-Path -Path $tempDir -ChildPath 'budget_phase.json'
[System.IO.File]::WriteAllText($phaseBudgetPath, '{ "mode_totals": {}, "phase_budgets": { "41": 10 } }', $utf8NoBom)
$resPhase = & $tool -Path $smallFx -Budget $phaseBudgetPath -PassThru
Assert-ScytheEqual 1 @($resPhase.PhaseOverruns).Count 'per-phase budget overrun is reported'
Assert-ScytheEqual '41' @($resPhase.PhaseOverruns)[0].Key 'the overrun names the phase'
Assert-ScytheEqual 0 ([int]$LASTEXITCODE) 'per-phase overrun alone does not fail the gate (total only)'

# The shipped seed table: QUICK 120, everything else unbudgeted.
$seedPath = Join-Path -Path (Join-Path -Path (Split-Path -Path (Split-Path -Path $here -Parent) -Parent) -ChildPath 'data') -ChildPath 'phase_budgets.json'
Assert-ScytheTrue (Test-Path -LiteralPath $seedPath) 'data/phase_budgets.json ships with the tool'
$seed = Get-Content -LiteralPath $seedPath -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-ScytheEqual 120 ([int]$seed.mode_totals.QUICK) 'seed table carries the QUICK two-minute goal'
Assert-ScytheEqual 0 ([int]$seed.mode_totals.DEEP) 'seed table leaves other modes unbudgeted'

# --------------------------------------------------------------------------------------------
# Comparison: per-phase delta sorted by absolute change
# --------------------------------------------------------------------------------------------

Write-Host 'comparison'
$resCmp = & $tool -Path $smallFx -Compare $beforeFx -Budget $noBudgetPath -PassThru
Assert-ScytheTrue ($null -ne $resCmp.Comparison) '-Compare produces a delta table'
Assert-ScytheEqual '41' @($resCmp.Comparison)[0].Key 'delta table sorted by absolute change (biggest first)'
$row30 = @($resCmp.Comparison | Where-Object { $_.Key -eq '30' })[0]
Assert-ScytheEqual 18 $row30.Before 'common phase carries the comparison value'
Assert-ScytheEqual 48.9 $row30.After 'common phase carries the current value'
Assert-ScytheEqual 30.9 $row30.Delta 'common phase delta is the difference'
Assert-ScytheEqual 'both' $row30.Status 'common phase marked as present in both'
$row90 = @($resCmp.Comparison | Where-Object { $_.Key -eq '90' })[0]
Assert-ScytheEqual 'removed' $row90.Status 'phase only in the comparison run is marked removed'

# --------------------------------------------------------------------------------------------
# Renderings
# --------------------------------------------------------------------------------------------

Write-Host 'renderings'
$jsonText = [string]((& $tool -LogPath $logFx -Budget $noBudgetPath -Format Json) -join [Environment]::NewLine)
$roundTrip = $jsonText | ConvertFrom-Json
Assert-ScytheEqual 8 ([int]$roundTrip.PhaseCount) 'Json rendering round-trips'
$htmlText = [string]((& $tool -LogPath $logFx -Budget $noBudgetPath -Format Html) -join [Environment]::NewLine)
Assert-ScytheTrue ($htmlText.Contains('</html>')) 'Html rendering is complete'
Assert-ScytheTrue (-not $htmlText.Contains('<script')) 'Html rendering is static'
Assert-ScytheTrue ($htmlText.Contains('&lt;b&gt;TITLE')) 'hostile phase title is HTML-encoded'
Assert-ScytheTrue (-not $htmlText.Contains('<b>TITLE')) 'hostile phase title is not live markup'

# Missing sources are clear errors.
$threw = $false
try { & $tool -Budget $noBudgetPath -PassThru | Out-Null } catch { $threw = ($_.Exception.Message -like '*at least one source*') }
Assert-ScytheTrue $threw 'no source at all is rejected with a clear message'

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
