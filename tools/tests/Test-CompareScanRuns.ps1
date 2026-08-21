<#
.SYNOPSIS
    Tests for tools\Compare-ScanRuns.ps1. Runs on Linux under pwsh 7 and on Windows PowerShell 5.1.

.DESCRIPTION
    Asserts against the -Format Object result; Text/Json/Html renderings are only inspected
    where the assertion is about the rendering itself (the empty-reference sentence, the
    mismatch warning placement). Fixtures:

      fixtures\run_before.json   the reference run
      fixtures\run_after.json    the current run — encodes all four buckets plus an ID-drift pair

    Variants (a QUICK-mode copy, an empty reference, a third run for the trend) are derived
    into a temp directory at run time.

.EXAMPLE
    pwsh tools/tests/Test-CompareScanRuns.ps1
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
$cmp = Join-Path -Path (Split-Path -Path $here -Parent) -ChildPath 'Compare-ScanRuns.ps1'
$fixtureDir = Join-Path -Path $here -ChildPath 'fixtures'
$beforeFx = Join-Path -Path $fixtureDir -ChildPath 'run_before.json'
$afterFx = Join-Path -Path $fixtureDir -ChildPath 'run_after.json'

$tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('zbtest_compare_' + $PID)
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Join-ZbIds {
    param($Items)
    return (@($Items | ForEach-Object { $_.ID } | Sort-Object) -join ',')
}

# --------------------------------------------------------------------------------------------
# 1 + 2 + risk: the four buckets, exactly, with directions
# --------------------------------------------------------------------------------------------

Write-Host 'default comparison'
$res = & $cmp -Reference $beforeFx -Current $afterFx

Assert-ZbEqual 'Compare' $res.Kind 'single current run produces a Compare result'
Assert-ZbEqual 3 $res.ResolvedCount 'three findings resolved'
Assert-ZbEqual 'P30_gone04,P30_gone05,P40_drift06' (Join-ZbIds $res.Resolved) 'resolved bucket membership exact'
Assert-ZbEqual 2 $res.NewCount 'two findings new'
Assert-ZbEqual 'P40_drift99,P50_new07' (Join-ZbIds $res.New) 'new bucket membership exact'
Assert-ZbEqual 1 $res.PersistentCount 'one finding persistent'
Assert-ZbEqual 'P10_keep01' (Join-ZbIds $res.Persistent) 'persistent bucket membership exact'
Assert-ZbEqual 2 $res.ChangedCount 'two findings changed severity'
Assert-ZbEqual -25 $res.RiskDelta 'risk score delta 120 -> 95 is -25'

$esc = @($res.Changed | Where-Object { $_.ID -eq 'P10_esc02' })
$deesc = @($res.Changed | Where-Object { $_.ID -eq 'P20_deesc03' })
Assert-ZbEqual 1 $esc.Count 'escalated finding is in the changed bucket'
Assert-ZbEqual 'POSSIBLE' $esc[0].From 'escalation reports the old severity'
Assert-ZbEqual 'HIGH' $esc[0].To 'escalation reports the new severity'
Assert-ZbEqual 'escalated' $esc[0].Direction 'POSSIBLE -> HIGH reads as escalated'
Assert-ZbEqual 'improved' $deesc[0].Direction 'CRITICAL -> POSSIBLE reads as improved'
$allOtherIds = (Join-ZbIds $res.Resolved) + ',' + (Join-ZbIds $res.New) + ',' + (Join-ZbIds $res.Persistent)
Assert-ZbTrue (-not $allOtherIds.Contains('P10_esc02')) 'a changed finding appears in no other bucket'

# --------------------------------------------------------------------------------------------
# 3. INFO excluded by default, included with -IncludeInfo
# --------------------------------------------------------------------------------------------

Write-Host 'INFO handling'
Assert-ZbTrue (-not (Join-ZbIds $res.Resolved).Contains('P90_info01')) 'INFO finding excluded from buckets by default'
$resInfo = & $cmp -Reference $beforeFx -Current $afterFx -IncludeInfo
Assert-ZbEqual 4 $resInfo.ResolvedCount '-IncludeInfo adds the resolved INFO finding'
Assert-ZbEqual 3 $resInfo.NewCount '-IncludeInfo adds the new INFO finding'
Assert-ZbTrue ((Join-ZbIds $resInfo.Resolved).Contains('P90_info01')) '-IncludeInfo: INFO finding present in resolved'
Assert-ZbEqual 1 $res.Reference.SeverityCounts.INFO 'run-level totals count INFO even when buckets exclude it'

# --------------------------------------------------------------------------------------------
# 4. GROUPCAP_* never appears in any bucket
# --------------------------------------------------------------------------------------------

foreach ($variant in @(@('default', $res), @('IncludeInfo', $resInfo))) {
    $ids = (Join-ZbIds $variant[1].Resolved) + ',' + (Join-ZbIds $variant[1].New) + ',' +
    (Join-ZbIds $variant[1].Persistent) + ',' + (@($variant[1].Changed | ForEach-Object { $_.ID }) -join ',')
    Assert-ZbTrue (-not $ids.Contains('GROUPCAP')) ('GROUPCAP_ rows in no bucket (' + $variant[0] + ')')
}

# --------------------------------------------------------------------------------------------
# 5. Mode mismatch warning — present when modes differ, absent when they match
# --------------------------------------------------------------------------------------------

Write-Host 'mode mismatch'
$quickRecord = Get-Content -LiteralPath $afterFx -Raw -Encoding UTF8 | ConvertFrom-Json
$quickRecord.Mode = 'QUICK'
$quickPath = Join-Path -Path $tempDir -ChildPath 'after_quick.json'
[System.IO.File]::WriteAllText($quickPath, (ConvertTo-Json -InputObject $quickRecord -Depth 6), $utf8NoBom)
$resQuick = & $cmp -Reference $beforeFx -Current $quickPath
Assert-ZbTrue (@($resQuick.Warnings).Count -ge 1) 'different modes emit a warning'
Assert-ZbTrue ((@($resQuick.Warnings) -join ' ').ToUpperInvariant().Contains('DIFFERENT MODES')) 'the warning names the mode mismatch'
Assert-ZbEqual 0 @($res.Warnings).Count 'matched modes and windows emit no warning'
$quickText = & $cmp -Reference $beforeFx -Current $quickPath -Format Text
$firstBang = ([string]$quickText).IndexOf('!!')
$firstBucket = ([string]$quickText).IndexOf('RESOLVED')
Assert-ZbTrue ($firstBang -ge 0 -and $firstBang -lt $firstBucket) 'text output prints the warning before any bucket'

# --------------------------------------------------------------------------------------------
# 6. Empty reference run: everything is new, said in one sentence
# --------------------------------------------------------------------------------------------

Write-Host 'empty reference'
$emptyRef = [pscustomobject]@{
    Timestamp = '2026-08-01T08:00:00.0000000-04:00'; Host = 'WORKSTATION-04'; User = 'ACME\tech'
    Mode = 'DEEP'; TimeWindow = 'LAST 24 HOURS'; RiskScore = 0; RiskLabel = 'CLEAN'
    Findings = @(); PhaseTimings = @(); RecoveredErrors = @(); BaselineDelta = @(); ThreatTally = [pscustomobject]@{}
}
$emptyRefPath = Join-Path -Path $tempDir -ChildPath 'empty_ref.json'
[System.IO.File]::WriteAllText($emptyRefPath, (ConvertTo-Json -InputObject $emptyRef -Depth 6), $utf8NoBom)
$resEmpty = & $cmp -Reference $emptyRefPath -Current $afterFx
Assert-ZbTrue ($resEmpty.ReferenceEmpty) 'empty reference sets ReferenceEmpty'
Assert-ZbEqual 5 $resEmpty.NewCount 'empty reference: every non-INFO current finding is new'
Assert-ZbEqual 0 $resEmpty.ResolvedCount 'empty reference: nothing to resolve'
$emptyText = [string](& $cmp -Reference $emptyRefPath -Current $afterFx -Format Text)
Assert-ZbTrue ($emptyText.Contains('are new rather than regressions')) 'empty reference: text says it in one sentence'
Assert-ZbTrue (-not $emptyText.Contains('P50_new07')) 'empty reference: text does not list the findings as regressions'

# --------------------------------------------------------------------------------------------
# 7. Identical runs: zero new, zero resolved
# --------------------------------------------------------------------------------------------

Write-Host 'identical runs'
$resSame = & $cmp -Reference $afterFx -Current $afterFx
Assert-ZbEqual 0 $resSame.NewCount 'identical runs: nothing new'
Assert-ZbEqual 0 $resSame.ResolvedCount 'identical runs: nothing resolved'
Assert-ZbEqual 0 $resSame.ChangedCount 'identical runs: nothing changed'
Assert-ZbEqual 5 $resSame.PersistentCount 'identical runs: everything (non-INFO) persistent'

# --------------------------------------------------------------------------------------------
# ID drift advisory (strict join + advisory, per the 2026-08-20 decision)
# --------------------------------------------------------------------------------------------

Write-Host 'ID drift advisory'
Assert-ZbEqual 1 @($res.IdDrift).Count 'one resolved/new pair shares target and category'
Assert-ZbEqual 'P40_drift06' @($res.IdDrift)[0].ResolvedId 'drift pair names the resolved ID'
Assert-ZbEqual 'P40_drift99' @($res.IdDrift)[0].NewId 'drift pair names the new ID'
Assert-ZbTrue ((Join-ZbIds $res.Resolved).Contains('P40_drift06')) 'drift pair still counted in resolved (strict join)'
$defaultText = [string](& $cmp -Reference $beforeFx -Current $afterFx -Format Text)
Assert-ZbTrue ($defaultText.Contains('POSSIBLE ID DRIFT')) 'text render carries the drift advisory'

# --------------------------------------------------------------------------------------------
# Trend mode: several current runs, ordered by timestamp, counts only
# --------------------------------------------------------------------------------------------

Write-Host 'trend'
$thirdRecord = Get-Content -LiteralPath $afterFx -Raw -Encoding UTF8 | ConvertFrom-Json
$thirdRecord.Timestamp = '2026-08-26T10:00:00.0000000-04:00'
$thirdRecord.Mode = 'HUNT'
$thirdRecord.RiskScore = 80
# name chosen so alphabetical order differs from timestamp order
$thirdPath = Join-Path -Path $tempDir -ChildPath 'a_third.json'
[System.IO.File]::WriteAllText($thirdPath, (ConvertTo-Json -InputObject $thirdRecord -Depth 6), $utf8NoBom)
$trend = & $cmp -Reference $beforeFx -Current @($thirdPath, $afterFx)
Assert-ZbEqual 'Trend' $trend.Kind 'several current runs produce a Trend result'
Assert-ZbEqual 3 @($trend.Runs).Count 'trend includes the reference plus both current runs'
Assert-ZbEqual 'run_before.json,run_after.json,a_third.json' (@($trend.Runs | ForEach-Object { $_.Path }) -join ',') 'trend rows are in timestamp order, not argument or name order'
Assert-ZbEqual 1 @($trend.Runs)[1].SeverityCounts.CRITICAL 'trend counts come from the run records'
Assert-ZbTrue ((@($trend.Warnings) -join ' ').Contains('different modes')) 'mixed-mode trend carries the comparability warning'

# --------------------------------------------------------------------------------------------
# Renderings: Json round-trips, Html is complete and encoded, -OutFile writes
# --------------------------------------------------------------------------------------------

Write-Host 'renderings'
$jsonText = [string](& $cmp -Reference $beforeFx -Current $afterFx -Format Json)
$roundTrip = $jsonText | ConvertFrom-Json
Assert-ZbEqual 'Compare' $roundTrip.Kind 'Json rendering round-trips'
Assert-ZbEqual 3 $roundTrip.ResolvedCount 'Json rendering carries the numbers'

$htmlOut = Join-Path -Path $tempDir -ChildPath 'cmp.html'
& $cmp -Reference $beforeFx -Current $afterFx -Format Html -OutFile $htmlOut | Out-Null
Assert-ZbTrue (Test-Path -LiteralPath $htmlOut) '-OutFile writes the Html rendering'
$htmlText = Get-Content -LiteralPath $htmlOut -Raw -Encoding UTF8
Assert-ZbTrue ($htmlText.Contains('</html>')) 'Html rendering is complete'
Assert-ZbTrue ($htmlText.Contains('escalated')) 'Html rendering shows the changed direction'
Assert-ZbTrue (-not $htmlText.Contains('<script')) 'Html rendering is static — no script blocks'
Assert-ZbTrue ($htmlText.Contains('&lt;img src=x')) 'hostile description is HTML-encoded in the rendering'
Assert-ZbTrue (-not $htmlText.Contains('<img src=x')) 'hostile description is not live markup'

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
