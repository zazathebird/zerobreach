<#
.SYNOPSIS
    Regression suite for the 2026-08-18 security audit fixes (C1, C3, H1-H10).
.DESCRIPTION
    Run from the PROJECT ROOT:  powershell -NoProfile -File tools\tests\Run-SecurityTests.ps1

    Every test extracts the real functions from the shipped source via the PowerShell
    AST rather than retyping them, so a test cannot silently drift from the code it
    guards. Nothing here touches the registry, the filesystem outside TEMP, or any
    live process other than the test host itself — safe to run on a working machine.

    Not covered here (needs a real Windows box): the live HttpListener, actual
    remediation execution, and anything under [NEEDS REPRO] in the audit.
#>
[CmdletBinding()]
param([switch]$SkipParse)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $root
Write-Host "ZeroBreach security regression suite — root: $root" -ForegroundColor Cyan

$tests = @(
    @{ Name = 'Parse + BOM (7 shipped files)';        File = 'Test-ParseAndBom.ps1';       Skip = $SkipParse }
    @{ Name = 'Embedded runspace here-strings';       File = 'Test-EmbeddedRunspaces.ps1'; Skip = $SkipParse }
    @{ Name = 'C1  token + Origin lockdown';          File = 'Test-C1-Auth.ps1' }
    @{ Name = 'H1  rollback snapshot artifacts';      File = 'Test-H1-Snapshot.ps1' }
    @{ Name = 'H2  engine exit / stderr verdict';     File = 'Test-H2-EngineExit.ps1' }
    @{ Name = 'H5  KillProcess identity re-check';    File = 'Test-H5-KillIdentity.ps1' }
    @{ Name = 'H7  guard normalisation + RunCmd';     File = 'Test-H7-Guard.ps1' }
    @{ Name = 'H7  main/mirror guard equivalence';    File = 'Test-GuardMirrorSync.ps1' }
    @{ Name = 'H8  CSV injection + report JS';        File = 'Test-H8-CsvInjection.ps1' }
    @{ Name = 'M   medium-tier fixes (M2-M8)';        File = 'Test-M-Tier.ps1' }
)

$failed = 0
foreach ($t in $tests) {
    if ($t.Skip) { Write-Host ("  SKIP  {0}" -f $t.Name) -ForegroundColor DarkGray; continue }
    $path = Join-Path $PSScriptRoot $t.File
    if (-not (Test-Path $path)) { Write-Host ("  MISS  {0} ({1})" -f $t.Name, $t.File) -ForegroundColor Red; $failed++; continue }

    $env:SCRATCH = [System.IO.Path]::GetTempPath()
    # Re-invoke with the SAME host that is running this file, so the suite behaves
    # identically under Windows PowerShell 5.1 and pwsh 7.
    $hostExe = (Get-Process -Id $PID).Path
    $out = & $hostExe -NoProfile -File $path 2>&1
    if ($LASTEXITCODE -ne 0 -or ($out -join "`n") -match '\bFAIL\b|\bdiverge\b.*[1-9]') {
        Write-Host ("  FAIL  {0}" -f $t.Name) -ForegroundColor Red
        $out | Select-Object -Last 20 | ForEach-Object { Write-Host "        $_" }
        $failed++
    } else {
        $tail = ($out | Where-Object { $_ -match 'passed|agree' } | Select-Object -Last 1)
        Write-Host ("  PASS  {0,-42} {1}" -f $t.Name, $tail) -ForegroundColor Green
    }
}

Pop-Location
if ($failed) {
    Write-Host "`n$failed test file(s) FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "`nAll security regression tests passed." -ForegroundColor Green
