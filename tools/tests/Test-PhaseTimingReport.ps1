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

$script:ZbPass = 0
$script:ZbFail = 0
$script:ZbFailures = @()

function Assert-ZbTrue {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:ZbPass = $script:ZbPass + 1
        Write-Host ('  ok    ' + $Name)
    }
    else {
        $script:ZbFail = $script:ZbFail + 1
        $script:ZbFailures += $Name
        Write-Host ('  FAIL  ' + $Name)
    }
}

function Assert-ZbEqual {
    param($Expected, $Actual, [string]$Name)
    Assert-ZbTrue -Condition (('' + $Expected) -eq ('' + $Actual)) -Name ($Name + " (expected '$Expected', got '$Actual')")
}

$here = $PSScriptRoot
$tool = Join-Path -Path (Split-Path -Path $here -Parent) -ChildPath 'Get-PhaseTimingReport.ps1'
$fixtureDir = Join-Path -Path $here -ChildPath 'fixtures'
$logFx = Join-Path -Path $fixtureDir -ChildPath 'console_sample.log'
$smallFx = Join-Path -Path $fixtureDir -ChildPath 'run_small.json'
$beforeFx = Join-Path -Path $fixtureDir -ChildPath 'run_before.json'

$tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('zbtest_timing_' + $PID)
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
Assert-ZbEqual 'ConsoleLog' $res.Source 'log-only input reads the console log'
Assert-ZbEqual 8 $res.PhaseCount 'fixture log parses to eight phases'
Assert-ZbEqual 65 $res.TotalSeconds 'fixture log total is 65.0s'
Assert-ZbEqual 0 ([int]$res.ExitCode) 'unbudgeted run exits zero'

$keys = @($res.Phases | ForEach-Object { $_.Key })
Assert-ZbTrue ($keys -contains '74.5') 'fractional phase 74.5 keeps its decimal'
Assert-ZbTrue (-not ($keys -contains '74')) 'fractional phase is not merged into 74'

$phase2 = @($res.Phases | Where-Object { $_.Key -eq '2' })[0]
Assert-ZbEqual 3 $phase2.Seconds 'duplicate TIMING lines: the last value is kept'
Assert-ZbEqual 1 $res.DuplicatesDiscarded 'one duplicate TIMING line was discarded'
$logText = [string]((& $tool -LogPath $logFx -Budget $noBudgetPath -Format Text) -join [Environment]::NewLine)
Assert-ZbTrue ($logText.Contains('discarded')) 'text output says duplicates were discarded'

$shareSum = 0.0
foreach ($p in @($res.Phases)) { $shareSum = $shareSum + $p.Share }
Assert-ZbTrue ([math]::Abs($shareSum - 100) -le 0.5) ('phase shares sum to 100 within rounding (' + $shareSum + ')')
Assert-ZbEqual 5 $res.P80Count 'five phases account for 80% of the fixture total'

# --------------------------------------------------------------------------------------------
# 3. Truncated log: last phase started, never finished
# --------------------------------------------------------------------------------------------

Write-Host 'truncated log'
$truncPath = Join-Path -Path $tempDir -ChildPath 'truncated.log'
$truncated = (Get-Content -LiteralPath $logFx -Raw -Encoding UTF8) +
"[INFO] ================ PHASE 99 — EVENT LOG SWEEP ================`n[WARN] channel enumeration in progress"
[System.IO.File]::WriteAllText($truncPath, $truncated, $utf8NoBom)
$resTrunc = & $tool -LogPath $truncPath -Budget $noBudgetPath -PassThru
Assert-ZbTrue ($resTrunc.Incomplete) 'truncated log is reported as incomplete, not thrown on'
Assert-ZbTrue (@($resTrunc.IncompletePhases) -contains '99') 'the unfinished phase is named'
Assert-ZbEqual 8 $resTrunc.PhaseCount 'unfinished phase contributes no timing'

# --------------------------------------------------------------------------------------------
# Source preference: run record wins over the log, and the output says so
# --------------------------------------------------------------------------------------------

Write-Host 'source preference'
$resBoth = & $tool -Path $smallFx -LogPath $logFx -Budget $noBudgetPath -PassThru
Assert-ZbEqual 'RunRecord' $resBoth.Source 'run record preferred when both sources are given'
$bothText = [string]((& $tool -Path $smallFx -LogPath $logFx -Budget $noBudgetPath -Format Text) -join [Environment]::NewLine)
Assert-ZbTrue ($bothText.Contains('run record')) 'text output names the source it used'
Assert-ZbEqual 125 $resBoth.Shortfall 'DEEP record with 8 phases reports the 125-phase shortfall'

# --------------------------------------------------------------------------------------------
# 5. Budget gate: over exits non-zero, under exits zero
# --------------------------------------------------------------------------------------------

Write-Host 'budget gate'
$overPath = Join-Path -Path $tempDir -ChildPath 'budget_over.json'
[System.IO.File]::WriteAllText($overPath, '{ "mode_totals": { "DEEP": 100 }, "phase_budgets": {} }', $utf8NoBom)
$resOver = & $tool -Path $smallFx -Budget $overPath -PassThru
Assert-ZbTrue ($resOver.OverBudget) 'a 216s DEEP run against a 100s budget is over'
Assert-ZbEqual 1 ([int]$LASTEXITCODE) 'over-budget input exits non-zero'

$underPath = Join-Path -Path $tempDir -ChildPath 'budget_under.json'
[System.IO.File]::WriteAllText($underPath, '{ "mode_totals": { "DEEP": 10000 }, "phase_budgets": {} }', $utf8NoBom)
$resUnder = & $tool -Path $smallFx -Budget $underPath -PassThru
Assert-ZbTrue (-not $resUnder.OverBudget) 'a 216s DEEP run against a 10000s budget is under'
Assert-ZbEqual 0 ([int]$LASTEXITCODE) 'under-budget input exits zero'

$phaseBudgetPath = Join-Path -Path $tempDir -ChildPath 'budget_phase.json'
[System.IO.File]::WriteAllText($phaseBudgetPath, '{ "mode_totals": {}, "phase_budgets": { "41": 10 } }', $utf8NoBom)
$resPhase = & $tool -Path $smallFx -Budget $phaseBudgetPath -PassThru
Assert-ZbEqual 1 @($resPhase.PhaseOverruns).Count 'per-phase budget overrun is reported'
Assert-ZbEqual '41' @($resPhase.PhaseOverruns)[0].Key 'the overrun names the phase'
Assert-ZbEqual 0 ([int]$LASTEXITCODE) 'per-phase overrun alone does not fail the gate (total only)'

# The shipped seed table: QUICK 120, everything else unbudgeted.
$seedPath = Join-Path -Path (Join-Path -Path (Split-Path -Path (Split-Path -Path $here -Parent) -Parent) -ChildPath 'data') -ChildPath 'phase_budgets.json'
Assert-ZbTrue (Test-Path -LiteralPath $seedPath) 'data/phase_budgets.json ships with the tool'
$seed = Get-Content -LiteralPath $seedPath -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-ZbEqual 120 ([int]$seed.mode_totals.QUICK) 'seed table carries the QUICK two-minute goal'
Assert-ZbEqual 0 ([int]$seed.mode_totals.DEEP) 'seed table leaves other modes unbudgeted'

# --------------------------------------------------------------------------------------------
# Comparison: per-phase delta sorted by absolute change
# --------------------------------------------------------------------------------------------

Write-Host 'comparison'
$resCmp = & $tool -Path $smallFx -Compare $beforeFx -Budget $noBudgetPath -PassThru
Assert-ZbTrue ($null -ne $resCmp.Comparison) '-Compare produces a delta table'
Assert-ZbEqual '41' @($resCmp.Comparison)[0].Key 'delta table sorted by absolute change (biggest first)'
$row30 = @($resCmp.Comparison | Where-Object { $_.Key -eq '30' })[0]
Assert-ZbEqual 18 $row30.Before 'common phase carries the comparison value'
Assert-ZbEqual 48.9 $row30.After 'common phase carries the current value'
Assert-ZbEqual 30.9 $row30.Delta 'common phase delta is the difference'
Assert-ZbEqual 'both' $row30.Status 'common phase marked as present in both'
$row90 = @($resCmp.Comparison | Where-Object { $_.Key -eq '90' })[0]
Assert-ZbEqual 'removed' $row90.Status 'phase only in the comparison run is marked removed'

# --------------------------------------------------------------------------------------------
# Renderings
# --------------------------------------------------------------------------------------------

Write-Host 'renderings'
$jsonText = [string]((& $tool -LogPath $logFx -Budget $noBudgetPath -Format Json) -join [Environment]::NewLine)
$roundTrip = $jsonText | ConvertFrom-Json
Assert-ZbEqual 8 ([int]$roundTrip.PhaseCount) 'Json rendering round-trips'
$htmlText = [string]((& $tool -LogPath $logFx -Budget $noBudgetPath -Format Html) -join [Environment]::NewLine)
Assert-ZbTrue ($htmlText.Contains('</html>')) 'Html rendering is complete'
Assert-ZbTrue (-not $htmlText.Contains('<script')) 'Html rendering is static'
Assert-ZbTrue ($htmlText.Contains('&lt;b&gt;TITLE')) 'hostile phase title is HTML-encoded'
Assert-ZbTrue (-not $htmlText.Contains('<b>TITLE')) 'hostile phase title is not live markup'

# Missing sources are clear errors.
$threw = $false
try { & $tool -Budget $noBudgetPath -PassThru | Out-Null } catch { $threw = ($_.Exception.Message -like '*at least one source*') }
Assert-ZbTrue $threw 'no source at all is rejected with a clear message'

# --------------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------------

Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host ('{0} passed, {1} failed' -f $script:ZbPass, $script:ZbFail)
if ($script:ZbFail -gt 0) {
    Write-Host 'Failed assertions:'
    foreach ($f in $script:ZbFailures) { Write-Host ('  - ' + $f) }
    exit 1
}
exit 0
