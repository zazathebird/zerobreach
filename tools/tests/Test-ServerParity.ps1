<#
.SYNOPSIS
    Parity test for the mirrored mode->phase-ceiling tables.

.DESCRIPTION
    The phase ceiling per mode is declared in several places that must agree. This test
    EXTRACTS each declaration from its source at runtime — PowerShell AST for .ps1 files, a
    targeted regex for the Python server — and compares them. It never restates the expected
    numbers in its own body: a test carrying its own copy of the table passes forever after
    the real table changes.

    Tables covered now (extraction fully implemented):

      1. Scythe-Server.ps1   $MODE_PHASES hashtable                (root)
      2. _python/server.py       MODE_PHASES dict                      (root)
      3. Scythe-V23.ps1      $PhasePlan switch, Max= per mode      (root)
      4. tools/New-ScanReport.ps1        $script:ScytheModeCeiling         (this repo, always real)
      5. tools/Get-PhaseTimingReport.ps1 $script:ScytheModeCeiling         (this repo, always real)
      6. tools/New-CoverageMatrix.ps1    $script:ScytheModeCeiling         (this repo, always real)

    4–6 are new copies introduced by the G1/G3/G6 tools (the run record and the engine source
    only carry the mode string); this test exists so all copies are proven to agree.

    PENDING — shapes BLUEPRINT.md does not document, awaiting one paste each from the owner
    (decision 2026-08-20: ship documented scope now, stub the rest visibly):
      - the front-end ceiling default (file + declaration syntax)
      - the mode whitelist in each server
      - the severity tag table in each server (including the padded [OK ] form)
      - the category bucket table in each server
    Each has a disabled entry in $ScythePendingShapes below; enabling one without configuring it
    fails the run rather than passing vacuously.

    Without -Root, the three root declarations are exercised against generated fixtures that
    reproduce the BLUEPRINT §6 syntax, and a built-in fail-on-revert pass edits a fixture copy
    and asserts the mismatch is caught. With -Root, they run read-only against the real tree.

.PARAMETER Root
    Project root holding Scythe-Server.ps1, _python/server.py and Scythe-V23.ps1.
    Omit to run against generated fixtures (development mode).

.EXAMPLE
    pwsh tools/tests/Test-ServerParity.ps1                 # fixture mode, self-proving

.EXAMPLE
    powershell -File tools\tests\Test-ServerParity.ps1 -Root C:\src\scythe
#>
[CmdletBinding()]
param(
    [string]$Root
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

# --------------------------------------------------------------------------------------------
# Pending shapes — one paste each from the owner turns these on. Enabled-but-unconfigured is
# a failure, never a silent skip.
# --------------------------------------------------------------------------------------------

$ScythePendingShapes = @(
    @{ Name = 'front-end ceiling default'; Enabled = $false
       Need = 'file path + the declaration line(s), e.g. a JS object literal in gui/templates/index.html' },
    @{ Name = 'mode whitelist (PowerShell server)'; Enabled = $false
       Need = 'variable name + shape of the whitelist in Scythe-Server.ps1' },
    @{ Name = 'mode whitelist (Python server)'; Enabled = $false
       Need = 'variable name + shape of the whitelist in _python/server.py' },
    @{ Name = 'severity tag tables (both servers, incl. padded [OK ] form)'; Enabled = $false
       Need = 'variable names + shapes in both servers' },
    @{ Name = 'category bucket tables (both servers)'; Enabled = $false
       Need = 'variable names + shapes in both servers' }
)

# --------------------------------------------------------------------------------------------
# Extractors — pull each table out of its source at runtime
# --------------------------------------------------------------------------------------------

function Get-ScytheAst {
    param([string]$FilePath)
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw ("{0} does not parse: {1}" -f $FilePath, $parseErrors[0].Message)
    }
    return $ast
}

function Get-ScytheHashtableTable {
    # Extract @{ MODE = <int>; ... } assigned to a given variable name (any scope prefix).
    param([string]$FilePath, [string]$VariableName)
    $ast = Get-ScytheAst -FilePath $FilePath
    $assignments = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
    foreach ($assignment in $assignments) {
        $leftName = ($assignment.Left.Extent.Text -replace '^\$(script:|global:|local:)?', '')
        if ($leftName -ne $VariableName) { continue }
        $tables = $assignment.Right.FindAll({ param($node) $node -is [System.Management.Automation.Language.HashtableAst] }, $true)
        foreach ($table in $tables) {
            $result = @{}
            foreach ($pair in $table.KeyValuePairs) {
                $key = ('' + $pair.Item1.Extent.Text).Trim('"', "'").ToUpperInvariant()
                $valueAsts = $pair.Item2.FindAll({ param($node) $node -is [System.Management.Automation.Language.ConstantExpressionAst] }, $true)
                if (@($valueAsts).Count -gt 0 -and @($valueAsts)[0].Value -is [int]) {
                    $result[$key] = [int]@($valueAsts)[0].Value
                }
            }
            if ($result.Count -gt 0) { return $result }
        }
    }
    return @{}
}

function Get-ScythePythonDictTable {
    # Targeted regex for MODE_PHASES = {"QUICK": 30, ...} in the parked Python server.
    param([string]$FilePath, [string]$VariableName)
    $text = Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
    $dictMatch = [regex]::Match($text, [regex]::Escape($VariableName) + '\s*=\s*\{([^}]*)\}')
    $result = @{}
    if (-not $dictMatch.Success) { return $result }
    foreach ($pair in [regex]::Matches($dictMatch.Groups[1].Value, '"([A-Za-z_]+)"\s*:\s*(\d+)')) {
        $result[$pair.Groups[1].Value.ToUpperInvariant()] = [int]$pair.Groups[2].Value
    }
    return $result
}

function Get-ScythePhasePlanTable {
    # The engine declares the ceiling as a switch on the scan mode, one branch per mode, with
    # the ceiling in Max=. The default branch is not a mode and is skipped.
    param([string]$FilePath)
    $ast = Get-ScytheAst -FilePath $FilePath
    $switches = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.SwitchStatementAst] }, $true)
    foreach ($switchAst in $switches) {
        if ($switchAst.Condition.Extent.Text -notmatch 'ScanMode') { continue }
        $result = @{}
        foreach ($clause in $switchAst.Clauses) {
            $label = ('' + $clause.Item1.Extent.Text).Trim('"', "'").ToUpperInvariant()
            $tables = $clause.Item2.FindAll({ param($node) $node -is [System.Management.Automation.Language.HashtableAst] }, $true)
            foreach ($table in $tables) {
                foreach ($pair in $table.KeyValuePairs) {
                    if (('' + $pair.Item1.Extent.Text).Trim() -eq 'Max') {
                        $valueAsts = $pair.Item2.FindAll({ param($node) $node -is [System.Management.Automation.Language.ConstantExpressionAst] }, $true)
                        if (@($valueAsts).Count -gt 0) { $result[$label] = [int]@($valueAsts)[0].Value }
                    }
                }
            }
        }
        if ($result.Count -gt 0) { return $result }
    }
    return @{}
}

# --------------------------------------------------------------------------------------------
# Comparison — every table must be loaded and non-empty before it may agree with anything
# --------------------------------------------------------------------------------------------

function Compare-ScytheCeilingTables {
    # Returns a list of human-readable mismatch strings; empty means full parity.
    param($NamedTables)
    $problems = @()
    foreach ($entry in $NamedTables) {
        if ($null -eq $entry.Table -or $entry.Table.Count -eq 0) {
            $problems += ('{0}: table not found or empty — an unloaded table must fail, not agree vacuously' -f $entry.Name)
        }
    }
    if ($problems.Count -gt 0) { return $problems }
    $allModes = @{}
    foreach ($entry in $NamedTables) {
        foreach ($mode in $entry.Table.Keys) { $allModes[$mode] = $true }
    }
    foreach ($mode in ($allModes.Keys | Sort-Object)) {
        $seen = @{}
        foreach ($entry in $NamedTables) {
            if (-not $entry.Table.ContainsKey($mode)) {
                $problems += ('{0}: mode {1} missing (present elsewhere)' -f $entry.Name, $mode)
            }
            else {
                $seen[$entry.Name] = $entry.Table[$mode]
            }
        }
        $distinct = @($seen.Values | Sort-Object -Unique)
        if ($distinct.Count -gt 1) {
            $detail = @($seen.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $seen[$_] }) -join ', '
            $problems += ('mode {0} disagrees: {1}' -f $mode, $detail)
        }
    }
    return $problems
}

# --------------------------------------------------------------------------------------------
# Sources: fixtures reproducing the BLUEPRINT §6 syntax, or the real tree via -Root
# --------------------------------------------------------------------------------------------

$toolsDir = Split-Path -Path $PSScriptRoot -Parent
$fixtureMode = [string]::IsNullOrWhiteSpace($Root)
$tempDir = $null

if ($fixtureMode) {
    $tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('scythetest_parity_' + $PID)
    New-Item -ItemType Directory -Path (Join-Path -Path $tempDir -ChildPath '_python') -Force | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding($false)

    # Same syntax as BLUEPRINT §6, small files, not copies of real ones.
    $serverFixture = @'
# fixture: the PowerShell server's table, same declaration syntax
$MODE_PHASES = @{ QUICK=30; FULL=80; DEEP=133; PARANOID=133; STEALTH=133; HUNT=162 }
Write-Host "fixture server"
'@
    $pythonFixture = @'
# fixture: the parked Python server's table, same declaration syntax
MODE_PHASES = {"QUICK": 30, "FULL": 80, "DEEP": 133, "PARANOID": 133, "STEALTH": 133, "HUNT": 162}
print("fixture server")
'@
    $engineFixture = @'
# fixture: the engine's phase plan, same declaration syntax
$PhasePlan = switch ($global:ScanMode) {
    "QUICK"    { @{ Min=1; Max=30;  Label='Quick sweep' } }
    "FULL"     { @{ Min=1; Max=80;  Label='Full audit' } }
    "DEEP"     { @{ Min=1; Max=133; Label='Deep audit' } }
    "PARANOID" { @{ Min=1; Max=133; Label='Deep audit, raised severities' } }
    "STEALTH"  { @{ Min=1; Max=133; Label='Deep audit, quiet output' } }
    "HUNT"     { @{ Min=1; Max=162; Label='Hunt sweep' } }
    default    { @{ Min=1; Max=80;  Label='Fallback' } }
}
'@
    [System.IO.File]::WriteAllText((Join-Path -Path $tempDir -ChildPath 'Scythe-Server.ps1'), $serverFixture, $utf8)
    [System.IO.File]::WriteAllText((Join-Path -Path (Join-Path -Path $tempDir -ChildPath '_python') -ChildPath 'server.py'), $pythonFixture, $utf8)
    [System.IO.File]::WriteAllText((Join-Path -Path $tempDir -ChildPath 'Scythe-V23.ps1'), $engineFixture, $utf8)
    $Root = $tempDir
    Write-Host 'MODE: fixtures (give -Root <project root> to run against the real tree)'
}
else {
    Write-Host ('MODE: real tree at ' + $Root + ' (read-only)')
}

$serverPath = Join-Path -Path $Root -ChildPath 'Scythe-Server.ps1'
$pythonPath = Join-Path -Path (Join-Path -Path $Root -ChildPath '_python') -ChildPath 'server.py'
$enginePath = Join-Path -Path $Root -ChildPath 'Scythe-V23.ps1'

# --------------------------------------------------------------------------------------------
# Assertion 1: every declaration of the ceiling table agrees
# --------------------------------------------------------------------------------------------

Write-Host 'ceiling parity'
$tables = @(
    @{ Name = 'Scythe-Server.ps1 $MODE_PHASES'; Table = (Get-ScytheHashtableTable -FilePath $serverPath -VariableName 'MODE_PHASES') },
    @{ Name = '_python/server.py MODE_PHASES'; Table = (Get-ScythePythonDictTable -FilePath $pythonPath -VariableName 'MODE_PHASES') },
    @{ Name = 'Scythe-V23.ps1 $PhasePlan Max='; Table = (Get-ScythePhasePlanTable -FilePath $enginePath) },
    @{ Name = 'tools/New-ScanReport.ps1 ScytheModeCeiling'; Table = (Get-ScytheHashtableTable -FilePath (Join-Path -Path $toolsDir -ChildPath 'New-ScanReport.ps1') -VariableName 'ScytheModeCeiling') },
    @{ Name = 'tools/Get-PhaseTimingReport.ps1 ScytheModeCeiling'; Table = (Get-ScytheHashtableTable -FilePath (Join-Path -Path $toolsDir -ChildPath 'Get-PhaseTimingReport.ps1') -VariableName 'ScytheModeCeiling') },
    @{ Name = 'tools/New-CoverageMatrix.ps1 ScytheModeCeiling'; Table = (Get-ScytheHashtableTable -FilePath (Join-Path -Path $toolsDir -ChildPath 'New-CoverageMatrix.ps1') -VariableName 'ScytheModeCeiling') }
)

foreach ($entry in $tables) {
    Assert-ScytheTrue ($entry.Table.Count -gt 0) ('table loaded and non-empty: ' + $entry.Name)
}
$problems = @(Compare-ScytheCeilingTables -NamedTables $tables)
Assert-ScytheTrue ($problems.Count -eq 0) 'every declaration of the mode ceiling table agrees'
foreach ($p in $problems) { Write-Host ('        mismatch: ' + $p) }

# --------------------------------------------------------------------------------------------
# Built-in fail-on-revert: a divergent fixture copy must be caught (always runs from scratch
# copies, never touches -Root files)
# --------------------------------------------------------------------------------------------

Write-Host 'self-proof (fail-on-revert against scratch copies)'
$proofDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('scythetest_parity_proof_' + $PID)
New-Item -ItemType Directory -Path $proofDir -Force | Out-Null
$utf8proof = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path -Path $proofDir -ChildPath 'good.ps1'), '$MODE_PHASES = @{ QUICK=30; HUNT=162 }', $utf8proof)
[System.IO.File]::WriteAllText((Join-Path -Path $proofDir -ChildPath 'drifted.ps1'), '$MODE_PHASES = @{ QUICK=30; HUNT=161 }', $utf8proof)
[System.IO.File]::WriteAllText((Join-Path -Path $proofDir -ChildPath 'missing.ps1'), '$MODE_PHASES = @{ QUICK=30 }', $utf8proof)
[System.IO.File]::WriteAllText((Join-Path -Path $proofDir -ChildPath 'unrelated.ps1'), '$SOMETHING_ELSE = @{ A=1 }', $utf8proof)

$goodTable = Get-ScytheHashtableTable -FilePath (Join-Path -Path $proofDir -ChildPath 'good.ps1') -VariableName 'MODE_PHASES'
$driftTable = Get-ScytheHashtableTable -FilePath (Join-Path -Path $proofDir -ChildPath 'drifted.ps1') -VariableName 'MODE_PHASES'
$missingTable = Get-ScytheHashtableTable -FilePath (Join-Path -Path $proofDir -ChildPath 'missing.ps1') -VariableName 'MODE_PHASES'
$absentTable = Get-ScytheHashtableTable -FilePath (Join-Path -Path $proofDir -ChildPath 'unrelated.ps1') -VariableName 'MODE_PHASES'

$driftProblems = @(Compare-ScytheCeilingTables -NamedTables @(
        @{ Name = 'good'; Table = $goodTable }, @{ Name = 'drifted'; Table = $driftTable }))
Assert-ScytheTrue ($driftProblems.Count -gt 0) 'a one-unit ceiling drift is caught'
Assert-ScytheTrue ((@($driftProblems) -join ' ').Contains('HUNT')) 'the drift report names the disagreeing mode'

$missingProblems = @(Compare-ScytheCeilingTables -NamedTables @(
        @{ Name = 'good'; Table = $goodTable }, @{ Name = 'missing'; Table = $missingTable }))
Assert-ScytheTrue ($missingProblems.Count -gt 0) 'a mode missing from one table is caught'

$absentProblems = @(Compare-ScytheCeilingTables -NamedTables @(
        @{ Name = 'good'; Table = $goodTable }, @{ Name = 'absent'; Table = $absentTable }))
Assert-ScytheTrue ($absentProblems.Count -gt 0) 'an unloaded (empty) table fails instead of agreeing vacuously'

Remove-Item -Path $proofDir -Recurse -Force -ErrorAction SilentlyContinue
if ($fixtureMode -and $tempDir) { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }

# --------------------------------------------------------------------------------------------
# Pending shapes: reported loudly, and enabling one without configuring it is a failure
# --------------------------------------------------------------------------------------------

Write-Host ''
Write-Host 'PENDING (owner input needed — see HANDOFF_FABLE.md G5 entry):'
foreach ($shape in $ScythePendingShapes) {
    if ($shape.Enabled) {
        Assert-ScytheTrue $false ('pending shape enabled but not implemented: ' + $shape.Name)
    }
    else {
        Write-Host ('  todo  ' + $shape.Name + ' — needs: ' + $shape.Need)
    }
}

# --------------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------------

Write-Host ''
Write-Host ('{0} passed, {1} failed, {2} pending shapes' -f $script:ScythePass, $script:ScytheFail, @($ScythePendingShapes | Where-Object { -not $_.Enabled }).Count)
if ($script:ScytheFail -gt 0) {
    Write-Host 'Failed assertions:'
    foreach ($f in $script:ScytheFailures) { Write-Host ('  - ' + $f) }
    exit 1
}
exit 0
