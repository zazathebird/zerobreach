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
    Name of the project-root global, passed through to the builder. Default ZbRoot (the
    fixture convention; pass the real name with -Root).

.EXAMPLE
    pwsh tools/tests/Test-PackagingContract.ps1

.EXAMPLE
    powershell -File tools\tests\Test-PackagingContract.ps1 -Root C:\src\zerobreach -ProjectRootVariable <name>
#>
[CmdletBinding()]
param(
    [string]$Root,

    [string]$ToolPath,

    [string]$ProjectRootVariable = 'ZbRoot'
)

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
if ([string]::IsNullOrEmpty($ToolPath)) {
    $ToolPath = Join-Path -Path (Join-Path -Path (Split-Path -Path $here -Parent) -ChildPath 'prototype') -ChildPath 'Build-SingleFile.ps1'
}
$tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('zbtest_packaging_' + $PID)
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
try { Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction SilentlyContinue } catch { }

# --------------------------------------------------------------------------------------------
# Fixture tree: the documented shapes — root-global bootstrap, root-based path resolution,
# encoding pinned on both sides, data as files
# --------------------------------------------------------------------------------------------

function Write-ZbFile {
    param([string]$Path, [string]$Content)
    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

function New-ZbPackageFixture {
    param([string]$Dir)
    if (Test-Path -LiteralPath $Dir) { Remove-Item -Path $Dir -Recurse -Force }
    Write-ZbFile -Path (Join-Path $Dir 'Launch-GUI.bat') -Content @'
@echo off
rem ZeroBreach fixture launcher: elevate, then hand off to the server.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ZeroBreach-Server.ps1"
'@
    Write-ZbFile -Path (Join-Path $Dir 'ZeroBreach-Server.ps1') -Content @'
# Fixture server: seeds the root global once, then resolves everything through it.
$global:ZbRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$mapPath    = Join-Path -Path $global:ZbRoot -ChildPath 'data/mitre_mapping.json'
$indexPath  = Join-Path -Path $global:ZbRoot -ChildPath 'gui/templates/index.html'
$enginePath = Join-Path -Path $global:ZbRoot -ChildPath 'ZeroBreach-V23.ps1'
$reportDir  = Join-Path -Path $global:ZbRoot -ChildPath 'reports'
'@
    Write-ZbFile -Path (Join-Path $Dir 'ZeroBreach-V23.ps1') -Content @'
# Fixture engine entry.
$global:ZbRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$sigPath = Join-Path -Path $global:ZbRoot -ChildPath 'data/signatures.json'
. (Join-Path -Path $global:ZbRoot -ChildPath 'engine/Module-Core.ps1')
'@
    Write-ZbFile -Path (Join-Path (Join-Path $Dir 'engine') 'Module-Core.ps1') -Content @'
function Invoke-ZbFixturePhase { param([int]$Phase) return $Phase }
'@
    Write-ZbFile -Path (Join-Path (Join-Path $Dir 'data') 'mitre_mapping.json') -Content @'
{ "metadata": { "name": "fixture map" }, "tactics": { "TA0003": "Persistence" }, "techniques": { "T1547": { "name": "Boot Autostart", "tactics": ["Persistence"] } } }
'@
    Write-ZbFile -Path (Join-Path (Join-Path $Dir 'data') 'signatures.json') -Content @'
{ "lolbins": ["certutil.exe", "mshta.exe"], "driver_blocklist": ["baddrv.sys"] }
'@
    Write-ZbFile -Path (Join-Path (Join-Path (Join-Path $Dir 'gui') 'templates') 'index.html') -Content @'
<!DOCTYPE html><html><head><title>fixture</title></head><body>fixture UI</body></html>
'@
}

# Run the builder against a tree; returns exit code, captured output, stage dir, zip path.
$script:ZbRunSeq = 0
function Invoke-ZbBuild {
    param([string]$TreeDir)
    $script:ZbRunSeq = $script:ZbRunSeq + 1
    $stage = Join-Path -Path $tempDir -ChildPath ('stage_' + $script:ZbRunSeq)
    $zip = Join-Path -Path $tempDir -ChildPath ('out_' + $script:ZbRunSeq + '.zip')
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
New-ZbPackageFixture -Dir $fxDir
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 0 $res.Exit 'conforming tree builds (and the bootstrap root-global assignment is not flagged)'
Assert-ZbTrue (Test-Path -LiteralPath $res.Zip) 'the single artifact exists'
Assert-ZbTrue (Test-Path -LiteralPath (Join-Path (Join-Path $res.Stage 'data') 'mitre_mapping.json')) 'rule data staged as a separate file (property 2)'
Assert-ZbTrue (-not ($res.Output -like '*reports*')) 'the runtime-created reports directory is not demanded from the staged set'

$manifestPath = Join-Path -Path $res.Stage -ChildPath 'manifest.json'
Assert-ZbTrue (Test-Path -LiteralPath $manifestPath) 'manifest.json written into the package'
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-ZbEqual 7 @($manifest.files).Count 'manifest lists every staged file'
$mapEntry = @($manifest.files | Where-Object { $_.path -eq 'data/mitre_mapping.json' })[0]
Assert-ZbTrue ($null -ne $mapEntry) 'manifest carries the data file'
$realHash = (Get-FileHash -LiteralPath (Join-Path (Join-Path $res.Stage 'data') 'mitre_mapping.json') -Algorithm SHA256).Hash
Assert-ZbEqual $realHash $mapEntry.sha256 'manifest hash matches the staged file'

$zipArchive = [System.IO.Compression.ZipFile]::OpenRead($res.Zip)
$zipNames = @($zipArchive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
$zipArchive.Dispose()
Assert-ZbTrue ($zipNames -contains 'data/mitre_mapping.json') 'zip carries the rule data as a file entry'
Assert-ZbTrue ($zipNames -contains 'manifest.json') 'zip carries the manifest'

# --------------------------------------------------------------------------------------------
# Property 1: path resolution through the root global
# --------------------------------------------------------------------------------------------

Write-Host 'property 1: path resolution'
New-ZbPackageFixture -Dir $fxDir
$serverPath = Join-Path -Path $fxDir -ChildPath 'ZeroBreach-Server.ps1'
$serverText = Get-Content -LiteralPath $serverPath -Raw -Encoding UTF8
Write-ZbFile -Path $serverPath -Content ($serverText + "`n" + '$dataPath = Join-Path -Path $PSScriptRoot -ChildPath ''data''' + "`n")
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 3 $res.Exit 'a script-root path expression outside the bootstrap refuses the build'
Assert-ZbTrue ($res.Output -like '*path-resolution: ZeroBreach-Server.ps1:*') 'the violation names the file and line'
Assert-ZbTrue ($res.Output -like '*PSScriptRoot*') 'the violation names the offending variable'
Assert-ZbTrue (-not (Test-Path -LiteralPath $res.Zip)) 'no package is produced on a contract violation'

New-ZbPackageFixture -Dir $fxDir
$enginePath = Join-Path -Path $fxDir -ChildPath 'ZeroBreach-V23.ps1'
$engineText = Get-Content -LiteralPath $enginePath -Raw -Encoding UTF8
Write-ZbFile -Path $enginePath -Content ($engineText + "`n" + '$whereAmI = $MyInvocation.MyCommand.Path' + "`n")
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 3 $res.Exit 'the engine entry script is audited too'
Assert-ZbTrue ($res.Output -like '*path-resolution: ZeroBreach-V23.ps1:*MyInvocation*') 'the engine violation names file and variable'

# --------------------------------------------------------------------------------------------
# Property 2: the data-file boundary
# --------------------------------------------------------------------------------------------

Write-Host 'property 2: data boundary'
New-ZbPackageFixture -Dir $fxDir
$mapRaw = Get-Content -LiteralPath (Join-Path (Join-Path $fxDir 'data') 'mitre_mapping.json') -Raw -Encoding UTF8
$serverText = Get-Content -LiteralPath $serverPath -Raw -Encoding UTF8
Write-ZbFile -Path $serverPath -Content ($serverText + "`n" + '$embedded = @''' + "`n" + $mapRaw + "`n" + '''@' + "`n")
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 3 $res.Exit 'a script embedding rule-data content refuses the build'
Assert-ZbTrue ($res.Output -like '*data-boundary*mitre_mapping.json*') 'the embed violation names the data file'

New-ZbPackageFixture -Dir $fxDir
Remove-Item -Path (Join-Path $fxDir 'data') -Recurse -Force
# The server still references data files, so drop those references too — this variant isolates
# the "no rule data at all" case from the completeness check.
Write-ZbFile -Path $serverPath -Content @'
$global:ZbRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$indexPath  = Join-Path -Path $global:ZbRoot -ChildPath 'gui/templates/index.html'
$enginePath = Join-Path -Path $global:ZbRoot -ChildPath 'ZeroBreach-V23.ps1'
'@
Write-ZbFile -Path (Join-Path $fxDir 'ZeroBreach-V23.ps1') -Content @'
$global:ZbRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
. (Join-Path -Path $global:ZbRoot -ChildPath 'engine/Module-Core.ps1')
'@
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 3 $res.Exit 'a package with no rule data at all refuses the build'
Assert-ZbTrue ($res.Output -like '*no rule data*') 'the no-data violation says what an empty ruleset means'

# --------------------------------------------------------------------------------------------
# Property 3: completeness of the staged set
# --------------------------------------------------------------------------------------------

Write-Host 'property 3: completeness'
New-ZbPackageFixture -Dir $fxDir
Remove-Item -Path (Join-Path (Join-Path (Join-Path $fxDir 'gui') 'templates') 'index.html') -Force
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 3 $res.Exit 'a referenced file missing from the staged set refuses the build'
Assert-ZbTrue ($res.Output -like '*completeness*gui/templates/index.html*') 'the missing file is named'

New-ZbPackageFixture -Dir $fxDir
Write-ZbFile -Path $serverPath -Content @'
$global:ZbRoot = $PSScriptRoot
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
'@
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 3 $res.Exit 'a server yielding zero extracted references refuses the build (no vacuous pass)'
Assert-ZbTrue ($res.Output -like '*refusing a vacuous pass*') 'the vacuous case says the extractor, not the tree, is suspect'

New-ZbPackageFixture -Dir $fxDir
Write-ZbFile -Path (Join-Path $fxDir 'Launch-GUI.bat') -Content @'
@echo off
powershell -NoProfile -File "%~dp0ZeroBreach-Missing.ps1"
'@
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 3 $res.Exit 'a launcher invoking an unstaged script refuses the build'
Assert-ZbTrue ($res.Output -like '*invokes ZeroBreach-Missing.ps1*') 'the launcher violation names the missing script'

# --------------------------------------------------------------------------------------------
# Property 4: encoding agreement on both sides
# --------------------------------------------------------------------------------------------

Write-Host 'property 4: encoding'
New-ZbPackageFixture -Dir $fxDir
$engineText = Get-Content -LiteralPath $enginePath -Raw -Encoding UTF8
Write-ZbFile -Path $enginePath -Content ($engineText -replace '(?m)^\[Console\]::OutputEncoding.*\r?\n', '')
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 3 $res.Exit 'a writer side without the encoding declaration refuses the build'
Assert-ZbTrue ($res.Output -like '*encoding: ZeroBreach-V23.ps1*writer*') 'the encoding violation names the writer side'

New-ZbPackageFixture -Dir $fxDir
$serverText = Get-Content -LiteralPath $serverPath -Raw -Encoding UTF8
Write-ZbFile -Path $serverPath -Content ($serverText -replace '(?m)^\[Console\]::OutputEncoding.*\r?\n', '')
$res = Invoke-ZbBuild -TreeDir $fxDir
Assert-ZbEqual 3 $res.Exit 'a reader side without the encoding declaration refuses the build'
Assert-ZbTrue ($res.Output -like '*encoding: ZeroBreach-Server.ps1*reader*') 'the encoding violation names the reader side'

# --------------------------------------------------------------------------------------------
# Hard errors
# --------------------------------------------------------------------------------------------

Write-Host 'hard errors (two fatal messages below are expected)'
& $ToolPath -Root (Join-Path $tempDir 'no-such-tree') -OutPath (Join-Path $tempDir 'x.zip') 6>$null | Out-Null
Assert-ZbEqual 2 ([int]$LASTEXITCODE) 'a missing tree is a hard error, exit 2'
New-ZbPackageFixture -Dir $fxDir
Remove-Item -Path $serverPath -Force
& $ToolPath -Root $fxDir -OutPath (Join-Path $tempDir 'y.zip') 6>$null | Out-Null
Assert-ZbEqual 2 ([int]$LASTEXITCODE) 'a missing entry file is a hard error, exit 2'

# --------------------------------------------------------------------------------------------
# Real tree, when given
# --------------------------------------------------------------------------------------------

if (-not [string]::IsNullOrEmpty($Root)) {
    Write-Host ('real tree: ' + $Root + ' (read-only)')
    $realStage = Join-Path -Path $tempDir -ChildPath 'real_stage'
    $realZip = Join-Path -Path $tempDir -ChildPath 'real_out.zip'
    $lines = & $ToolPath -Root $Root -OutPath $realZip -StageDir $realStage -ProjectRootVariable $ProjectRootVariable 6>&1
    foreach ($ln in @($lines)) { Write-Host ('        ' + $ln) }
    Assert-ZbEqual 0 ([int]$LASTEXITCODE) 'the real tree passes the packaging contract'
}
else {
    Write-Host 'real tree: skipped (give -Root <project root> and -ProjectRootVariable <real name>)'
}

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
