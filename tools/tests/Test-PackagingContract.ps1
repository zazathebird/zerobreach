<#
.SYNOPSIS
    Tests for tools\prototype\Build-SingleFile.ps1 — the four packaging-contract properties.

.DESCRIPTION
    Asserts the properties PACKAGING_STUDY.md identifies as load-bearing, by running the
    prototype builder against fixture trees authored here at run time:

      1. Path resolution goes through the project-root global; any script-root expression
         outside the bootstrap assignment refuses the build, named with file and line.
      2. Rule data is staged as separate files; a script embedding a data file's content, or
         a package with no data files at all, refuses the build.
      3. The staged set is complete: every file the launcher and server reference is staged,
         and extracting zero references is itself a failure (no vacuous pass).
      4. The UTF-8 encoding declaration is present on both sides of the process boundary.

    The real launcher and server are outside this work package (BLUEPRINT scope), so the
    fixtures reproduce the documented shapes and the engine-specific names are parameters —
    the same pattern as the G5/G6 suites. With -Root, the builder additionally runs against
    the real tree, read-only, which is the owner's post-merge audit.

    The fixture scripts live in here-strings, which the parse check of THIS file does not
    validate; the builder parses them on every run and refuses a tree that does not parse.

.PARAMETER Root
    Optional: a real project tree to audit after the fixture proof.

.PARAMETER ToolPath
    Path of the builder under test. Defaults to ..\prototype\Build-SingleFile.ps1; the
    fail-on-revert matrix points this at mutated copies.

.PARAMETER ProjectRootVariable
    Name of the project-root global, passed through to the builder. Default ScytheRoot (the
    fixture convention; pass the real name with -Root).

.EXAMPLE
    pwsh tools/tests/Test-PackagingContract.ps1

.EXAMPLE
    powershell -File tools\tests\Test-PackagingContract.ps1 -Root C:\src\scythe -ProjectRootVariable <name>
#>
[CmdletBinding()]
param(
    [string]$Root,

    [string]$ToolPath,

    [string]$ProjectRootVariable = 'ScytheRoot'
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
if ([string]::IsNullOrEmpty($ToolPath)) {
    $ToolPath = Join-Path -Path (Join-Path -Path (Split-Path -Path $here -Parent) -ChildPath 'prototype') -ChildPath 'Build-SingleFile.ps1'
}
$tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('scythetest_packaging_' + $PID)
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
try { Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction SilentlyContinue } catch { }

# --------------------------------------------------------------------------------------------
# Fixture tree: the documented shapes — root-global bootstrap, root-based path resolution,
# encoding pinned on both sides, data as files
# --------------------------------------------------------------------------------------------

function Write-ScytheFile {
    param([string]$Path, [string]$Content)
    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

function New-ScythePackageFixture {
    param([string]$Dir)
    if (Test-Path -LiteralPath $Dir) { Remove-Item -Path $Dir -Recurse -Force }
    Write-ScytheFile -Path (Join-Path $Dir 'Launch-GUI.bat') -Content @'
@echo off
rem Scythe fixture launcher: elevate, then hand off to the server.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scythe-Server.ps1"
'@
    Write-ScytheFile -Path (Join-Path $Dir 'Scythe-Server.ps1') -Content @'
# Fixture server: seeds the root global once, then resolves everything through it.
$global:ScytheRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$mapPath    = Join-Path -Path $global:ScytheRoot -ChildPath 'data/mitre_mapping.json'
$indexPath  = Join-Path -Path $global:ScytheRoot -ChildPath 'gui/templates/index.html'
$enginePath = Join-Path -Path $global:ScytheRoot -ChildPath 'Scythe-V23.ps1'
$reportDir  = Join-Path -Path $global:ScytheRoot -ChildPath 'reports'
'@
    Write-ScytheFile -Path (Join-Path $Dir 'Scythe-V23.ps1') -Content @'
# Fixture engine entry.
$global:ScytheRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$sigPath = Join-Path -Path $global:ScytheRoot -ChildPath 'data/signatures.json'
. (Join-Path -Path $global:ScytheRoot -ChildPath 'engine/Module-Core.ps1')
'@
    Write-ScytheFile -Path (Join-Path (Join-Path $Dir 'engine') 'Module-Core.ps1') -Content @'
function Invoke-ScytheFixturePhase { param([int]$Phase) return $Phase }
'@
    Write-ScytheFile -Path (Join-Path (Join-Path $Dir 'data') 'mitre_mapping.json') -Content @'
{ "metadata": { "name": "fixture map" }, "tactics": { "TA0003": "Persistence" }, "techniques": { "T1547": { "name": "Boot Autostart", "tactics": ["Persistence"] } } }
'@
    Write-ScytheFile -Path (Join-Path (Join-Path $Dir 'data') 'signatures.json') -Content @'
{ "lolbins": ["certutil.exe", "mshta.exe"], "driver_blocklist": ["baddrv.sys"] }
'@
    Write-ScytheFile -Path (Join-Path (Join-Path (Join-Path $Dir 'gui') 'templates') 'index.html') -Content @'
<!DOCTYPE html><html><head><title>fixture</title></head><body>fixture UI</body></html>
'@
}

# Run the builder against a tree; returns exit code, captured output, stage dir, zip path.
$script:ScytheRunSeq = 0
function Invoke-ScytheBuild {
    param([string]$TreeDir)
    $script:ScytheRunSeq = $script:ScytheRunSeq + 1
    $stage = Join-Path -Path $tempDir -ChildPath ('stage_' + $script:ScytheRunSeq)
    $zip = Join-Path -Path $tempDir -ChildPath ('out_' + $script:ScytheRunSeq + '.zip')
    $lines = & $ToolPath -Root $TreeDir -OutPath $zip -StageDir $stage -KeepStage -ProjectRootVariable $ProjectRootVariable 6>&1
    return @{
        Exit   = [int]$LASTEXITCODE
        Output = [string](@($lines) -join "`n")
        Stage  = $stage
        Zip    = $zip
    }
}

$fxDir = Join-Path -Path $tempDir -ChildPath 'tree'

# --------------------------------------------------------------------------------------------
# The conforming tree builds, data stays files, the manifest is honest
# --------------------------------------------------------------------------------------------

Write-Host 'conforming tree'
New-ScythePackageFixture -Dir $fxDir
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 0 $res.Exit 'conforming tree builds (and the bootstrap root-global assignment is not flagged)'
Assert-ScytheTrue (Test-Path -LiteralPath $res.Zip) 'the single artifact exists'
Assert-ScytheTrue (Test-Path -LiteralPath (Join-Path (Join-Path $res.Stage 'data') 'mitre_mapping.json')) 'rule data staged as a separate file (property 2)'
Assert-ScytheTrue (-not ($res.Output -like '*reports*')) 'the runtime-created reports directory is not demanded from the staged set'

$manifestPath = Join-Path -Path $res.Stage -ChildPath 'manifest.json'
Assert-ScytheTrue (Test-Path -LiteralPath $manifestPath) 'manifest.json written into the package'
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-ScytheEqual 7 @($manifest.files).Count 'manifest lists every staged file'
$mapEntry = @($manifest.files | Where-Object { $_.path -eq 'data/mitre_mapping.json' })[0]
Assert-ScytheTrue ($null -ne $mapEntry) 'manifest carries the data file'
$realHash = (Get-FileHash -LiteralPath (Join-Path (Join-Path $res.Stage 'data') 'mitre_mapping.json') -Algorithm SHA256).Hash
Assert-ScytheEqual $realHash $mapEntry.sha256 'manifest hash matches the staged file'

$zipArchive = [System.IO.Compression.ZipFile]::OpenRead($res.Zip)
$zipNames = @($zipArchive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
$zipArchive.Dispose()
Assert-ScytheTrue ($zipNames -contains 'data/mitre_mapping.json') 'zip carries the rule data as a file entry'
Assert-ScytheTrue ($zipNames -contains 'manifest.json') 'zip carries the manifest'

# --------------------------------------------------------------------------------------------
# Property 1: path resolution through the root global
# --------------------------------------------------------------------------------------------

Write-Host 'property 1: path resolution'
New-ScythePackageFixture -Dir $fxDir
$serverPath = Join-Path -Path $fxDir -ChildPath 'Scythe-Server.ps1'
$serverText = Get-Content -LiteralPath $serverPath -Raw -Encoding UTF8
Write-ScytheFile -Path $serverPath -Content ($serverText + "`n" + '$dataPath = Join-Path -Path $PSScriptRoot -ChildPath ''data''' + "`n")
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 3 $res.Exit 'a script-root path expression outside the bootstrap refuses the build'
Assert-ScytheTrue ($res.Output -like '*path-resolution: Scythe-Server.ps1:*') 'the violation names the file and line'
Assert-ScytheTrue ($res.Output -like '*PSScriptRoot*') 'the violation names the offending variable'
Assert-ScytheTrue (-not (Test-Path -LiteralPath $res.Zip)) 'no package is produced on a contract violation'

New-ScythePackageFixture -Dir $fxDir
$enginePath = Join-Path -Path $fxDir -ChildPath 'Scythe-V23.ps1'
$engineText = Get-Content -LiteralPath $enginePath -Raw -Encoding UTF8
Write-ScytheFile -Path $enginePath -Content ($engineText + "`n" + '$whereAmI = $MyInvocation.MyCommand.Path' + "`n")
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 3 $res.Exit 'the engine entry script is audited too'
Assert-ScytheTrue ($res.Output -like '*path-resolution: Scythe-V23.ps1:*MyInvocation*') 'the engine violation names file and variable'

# --------------------------------------------------------------------------------------------
# Property 2: the data-file boundary
# --------------------------------------------------------------------------------------------

Write-Host 'property 2: data boundary'
New-ScythePackageFixture -Dir $fxDir
$mapRaw = Get-Content -LiteralPath (Join-Path (Join-Path $fxDir 'data') 'mitre_mapping.json') -Raw -Encoding UTF8
$serverText = Get-Content -LiteralPath $serverPath -Raw -Encoding UTF8
Write-ScytheFile -Path $serverPath -Content ($serverText + "`n" + '$embedded = @''' + "`n" + $mapRaw + "`n" + '''@' + "`n")
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 3 $res.Exit 'a script embedding rule-data content refuses the build'
Assert-ScytheTrue ($res.Output -like '*data-boundary*mitre_mapping.json*') 'the embed violation names the data file'

New-ScythePackageFixture -Dir $fxDir
Remove-Item -Path (Join-Path $fxDir 'data') -Recurse -Force
# The server still references data files, so drop those references too — this variant isolates
# the "no rule data at all" case from the completeness check.
Write-ScytheFile -Path $serverPath -Content @'
$global:ScytheRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$indexPath  = Join-Path -Path $global:ScytheRoot -ChildPath 'gui/templates/index.html'
$enginePath = Join-Path -Path $global:ScytheRoot -ChildPath 'Scythe-V23.ps1'
'@
Write-ScytheFile -Path (Join-Path $fxDir 'Scythe-V23.ps1') -Content @'
$global:ScytheRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
. (Join-Path -Path $global:ScytheRoot -ChildPath 'engine/Module-Core.ps1')
'@
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 3 $res.Exit 'a package with no rule data at all refuses the build'
Assert-ScytheTrue ($res.Output -like '*no rule data*') 'the no-data violation says what an empty ruleset means'

# --------------------------------------------------------------------------------------------
# Property 3: completeness of the staged set
# --------------------------------------------------------------------------------------------

Write-Host 'property 3: completeness'
New-ScythePackageFixture -Dir $fxDir
Remove-Item -Path (Join-Path (Join-Path (Join-Path $fxDir 'gui') 'templates') 'index.html') -Force
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 3 $res.Exit 'a referenced file missing from the staged set refuses the build'
Assert-ScytheTrue ($res.Output -like '*completeness*gui/templates/index.html*') 'the missing file is named'

New-ScythePackageFixture -Dir $fxDir
Write-ScytheFile -Path $serverPath -Content @'
$global:ScytheRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
'@
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 3 $res.Exit 'a server yielding zero extracted references refuses the build (no vacuous pass)'
Assert-ScytheTrue ($res.Output -like '*refusing a vacuous pass*') 'the vacuous case says the extractor, not the tree, is suspect'

New-ScythePackageFixture -Dir $fxDir
Write-ScytheFile -Path (Join-Path $fxDir 'Launch-GUI.bat') -Content @'
@echo off
powershell -NoProfile -File "%~dp0Scythe-Missing.ps1"
'@
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 3 $res.Exit 'a launcher invoking an unstaged script refuses the build'
Assert-ScytheTrue ($res.Output -like '*invokes Scythe-Missing.ps1*') 'the launcher violation names the missing script'

# --------------------------------------------------------------------------------------------
# Property 4: encoding agreement on both sides
# --------------------------------------------------------------------------------------------

Write-Host 'property 4: encoding'
New-ScythePackageFixture -Dir $fxDir
$engineText = Get-Content -LiteralPath $enginePath -Raw -Encoding UTF8
Write-ScytheFile -Path $enginePath -Content ($engineText -replace '(?m)^\[Console\]::OutputEncoding.*\r?\n', '')
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 3 $res.Exit 'a writer side without the encoding declaration refuses the build'
Assert-ScytheTrue ($res.Output -like '*encoding: Scythe-V23.ps1*writer*') 'the encoding violation names the writer side'

New-ScythePackageFixture -Dir $fxDir
$serverText = Get-Content -LiteralPath $serverPath -Raw -Encoding UTF8
Write-ScytheFile -Path $serverPath -Content ($serverText -replace '(?m)^\[Console\]::OutputEncoding.*\r?\n', '')
$res = Invoke-ScytheBuild -TreeDir $fxDir
Assert-ScytheEqual 3 $res.Exit 'a reader side without the encoding declaration refuses the build'
Assert-ScytheTrue ($res.Output -like '*encoding: Scythe-Server.ps1*reader*') 'the encoding violation names the reader side'

# --------------------------------------------------------------------------------------------
# Hard errors
# --------------------------------------------------------------------------------------------

Write-Host 'hard errors (two fatal messages below are expected)'
& $ToolPath -Root (Join-Path $tempDir 'no-such-tree') -OutPath (Join-Path $tempDir 'x.zip') 6>$null | Out-Null
Assert-ScytheEqual 2 ([int]$LASTEXITCODE) 'a missing tree is a hard error, exit 2'
New-ScythePackageFixture -Dir $fxDir
Remove-Item -Path $serverPath -Force
& $ToolPath -Root $fxDir -OutPath (Join-Path $tempDir 'y.zip') 6>$null | Out-Null
Assert-ScytheEqual 2 ([int]$LASTEXITCODE) 'a missing entry file is a hard error, exit 2'

# --------------------------------------------------------------------------------------------
# Real tree, when given
# --------------------------------------------------------------------------------------------

if (-not [string]::IsNullOrEmpty($Root)) {
    Write-Host ('real tree: ' + $Root + ' (read-only)')
    $realStage = Join-Path -Path $tempDir -ChildPath 'real_stage'
    $realZip = Join-Path -Path $tempDir -ChildPath 'real_out.zip'
    $lines = & $ToolPath -Root $Root -OutPath $realZip -StageDir $realStage -ProjectRootVariable $ProjectRootVariable 6>&1
    foreach ($ln in @($lines)) { Write-Host ('        ' + $ln) }
    Assert-ScytheEqual 0 ([int]$LASTEXITCODE) 'the real tree passes the packaging contract'
}
else {
    Write-Host 'real tree: skipped (give -Root <project root> and -ProjectRootVariable <real name>)'
}

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
