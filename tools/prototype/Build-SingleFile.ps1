<#
.SYNOPSIS
    Prototype standalone-package builder: one verified zip, or no zip at all.

.DESCRIPTION
    Build-SingleFile.ps1 implements the option PACKAGING_STUDY.md recommends: the package
    stays a zip-plus-launcher, but the build becomes a single deterministic artifact that
    REFUSES to exist when it violates the constraints the study identified. It:

      1. Stages exactly the runtime file set from -Root into a clean directory: the
         launcher, the server, the engine entry script, engine\*.ps1, data\*.json and
         gui\** — nothing else rides along.
      2. Runs the four packaging-contract checks against the staged files and fails the
         build (exit 3, every violation named with file and line) on any hit:
           - root-global discipline: no script-root expression in a launcher-role script
             outside the bootstrap assignment into the project-root global
           - data boundary: rule data staged as separate files, and no staged script
             embeds a data file's content
           - completeness: every file the launcher and server reference is staged; zero
             extracted references is itself a failure
           - encoding agreement: the UTF-8 declaration present on both sides of the
             process boundary (server reader, engine writer)
      3. Writes manifest.json (every staged file, size, SHA-256) into the package.
      4. Produces one zip.

    The input tree is read-only throughout. This is a parallel experiment — it does not
    touch tools\Build-Release.ps1, which remains the shipping path.

    The project-root global's name and the entry-file names are parameters because the real
    launcher is outside this work package's blueprint; the defaults are the documented /
    fixture conventions. Aim it at the real tree with the real names — arguments only, no
    code change.

.PARAMETER Root
    The tree to package. Never written to.

.PARAMETER OutPath
    The zip to produce. Default: ZeroBreach-Standalone.zip in the current directory.

.PARAMETER StageDir
    Where files are staged. Default: a temp directory, removed after the build unless
    -KeepStage.

.PARAMETER KeepStage
    Leave the staged directory in place (the contract test inspects it).

.PARAMETER ProjectRootVariable
    Name of the project-root global (the path choke point). Default ZbRoot.

.PARAMETER LauncherFile
.PARAMETER ServerFile
.PARAMETER EngineFile
    Entry-point file names at the root of the tree. Defaults Launch-GUI.bat,
    ZeroBreach-Server.ps1, ZeroBreach-V23.ps1.

.PARAMETER EncodingPattern
    Regex that recognises the console-encoding declaration. Default matches
    "...OutputEncoding = ...UTF8..." forms.

.PARAMETER PassThru
    Also emit the manifest object.

.EXAMPLE
    tools\prototype\Build-SingleFile.ps1 -Root . -OutPath dist\ZeroBreach-Standalone.zip

.EXAMPLE
    tools\prototype\Build-SingleFile.ps1 -Root C:\src\zerobreach -ProjectRootVariable KrakenRoot
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    [string]$OutPath,

    [string]$StageDir,

    [switch]$KeepStage,

    [string]$ProjectRootVariable = 'ZbRoot',

    [string]$LauncherFile = 'Launch-GUI.bat',

    [string]$ServerFile = 'ZeroBreach-Server.ps1',

    [string]$EngineFile = 'ZeroBreach-V23.ps1',

    [string]$EncodingPattern = '(?i)OutputEncoding\s*=\s*[^\r\n]*UTF-?8',

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

function Stop-ZbFatal {
    # Fatal text straight to the error line so `exit 2` actually runs (Write-Error under an
    # EAP of Stop would throw first).
    param([string]$Message)
    $host.UI.WriteErrorLine($Message)
    exit 2
}

function Get-ZbBareName {
    param($VariableExpression)
    return @(([string]$VariableExpression.VariablePath.UserPath) -split ':')[-1]
}

# --------------------------------------------------------------------------------------------
# Check 1: root-global discipline. A script-root expression ($PSScriptRoot, $PSCommandPath,
# $MyInvocation) is allowed only inside the assignment that seeds the project-root global —
# everywhere else it is a latent packed-layout bug (study §2).
# --------------------------------------------------------------------------------------------

function Get-ZbScriptRootViolation {
    param($Ast, [string]$RootVar, [string]$FileLabel)
    $bad = @()
    $vars = $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
    foreach ($v in @($vars)) {
        $bare = Get-ZbBareName -VariableExpression $v
        if (@('PSScriptRoot', 'PSCommandPath', 'MyInvocation') -notcontains $bare) { continue }
        $allowed = $false
        $node = $v.Parent
        while ($null -ne $node) {
            if ($node -is [System.Management.Automation.Language.AssignmentStatementAst]) {
                if ($node.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
                    if ((Get-ZbBareName -VariableExpression $node.Left) -eq $RootVar) { $allowed = $true }
                }
                break
            }
            $node = $node.Parent
        }
        if (-not $allowed) {
            $bad += ($FileLabel + ':' + $v.Extent.StartLineNumber + ' resolves a path from $' + $bare +
                ' instead of the ' + $RootVar + ' global')
        }
    }
    return , $bad
}

# --------------------------------------------------------------------------------------------
# Check 3 support: the relative paths a script actually opens — string literals inside
# Join-Path calls that build on the project-root global. Extracted from the real source,
# never restated.
# --------------------------------------------------------------------------------------------

function Get-ZbRootReference {
    param($Ast, [string]$RootVar)
    $out = @()
    $cmds = $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in @($cmds)) {
        $cmdName = $c.GetCommandName()
        if ($null -eq $cmdName -or $cmdName -ne 'Join-Path') { continue }
        $usesRoot = $false
        $vars = $c.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
        foreach ($v in @($vars)) {
            if ((Get-ZbBareName -VariableExpression $v) -eq $RootVar) { $usesRoot = $true }
        }
        if (-not $usesRoot) { continue }
        $strs = $c.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
        foreach ($s in @($strs)) {
            $val = [string]$s.Value
            if ($val -eq 'Join-Path') { continue }   # the command name itself
            $out += $val
        }
    }
    return , $out
}

# --------------------------------------------------------------------------------------------
# Collect and stage
# --------------------------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    Stop-ZbFatal -Message ('-Root not found or not a directory: ' + $Root)
}
$rootPath = (Resolve-Path -LiteralPath $Root).Path

foreach ($required in @($LauncherFile, $ServerFile, $EngineFile)) {
    if (-not (Test-Path -LiteralPath (Join-Path -Path $rootPath -ChildPath $required))) {
        Stop-ZbFatal -Message ('Entry file missing from the tree: ' + $required +
            ' (wrong -Root, or pass the real name via -LauncherFile / -ServerFile / -EngineFile)')
    }
}

if ([string]::IsNullOrEmpty($OutPath)) {
    $OutPath = Join-Path -Path ((Get-Location).Path) -ChildPath 'ZeroBreach-Standalone.zip'
}
if ([string]::IsNullOrEmpty($StageDir)) {
    $StageDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('zbstage_' + $PID)
}
if (Test-Path -LiteralPath $StageDir) { Remove-Item -Path $StageDir -Recurse -Force }
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

# The runtime file set, and nothing else: entry points, engine modules, rule data, GUI.
$relPaths = @($LauncherFile, $ServerFile, $EngineFile)
$engineDir = Join-Path -Path $rootPath -ChildPath 'engine'
if (Test-Path -LiteralPath $engineDir -PathType Container) {
    foreach ($f in @(Get-ChildItem -LiteralPath $engineDir -Filter '*.ps1' -File | Sort-Object -Property Name)) {
        $relPaths += ('engine/' + $f.Name)
    }
}
$dataDir = Join-Path -Path $rootPath -ChildPath 'data'
if (Test-Path -LiteralPath $dataDir -PathType Container) {
    foreach ($f in @(Get-ChildItem -LiteralPath $dataDir -Filter '*.json' -File | Sort-Object -Property Name)) {
        $relPaths += ('data/' + $f.Name)
    }
}
$guiDir = Join-Path -Path $rootPath -ChildPath 'gui'
if (Test-Path -LiteralPath $guiDir -PathType Container) {
    foreach ($f in @(Get-ChildItem -LiteralPath $guiDir -File -Recurse | Sort-Object -Property FullName)) {
        $rel = $f.FullName.Substring($guiDir.Length).TrimStart('/', '\').Replace('\', '/')
        $relPaths += ('gui/' + $rel)
    }
}

$stagedSet = @{}
foreach ($rel in $relPaths) {
    $src = Join-Path -Path $rootPath -ChildPath $rel
    $dst = Join-Path -Path $StageDir -ChildPath $rel
    $dstDir = [System.IO.Path]::GetDirectoryName($dst)
    if (-not (Test-Path -LiteralPath $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
    Copy-Item -LiteralPath $src -Destination $dst
    $stagedSet[$rel.ToLowerInvariant()] = $rel
}

# --------------------------------------------------------------------------------------------
# The contract checks, against the staged copies
# --------------------------------------------------------------------------------------------

$violations = @()

$serverStaged = Join-Path -Path $StageDir -ChildPath $ServerFile
$engineStaged = Join-Path -Path $StageDir -ChildPath $EngineFile
$launcherStaged = Join-Path -Path $StageDir -ChildPath $LauncherFile

$launcherRole = @(
    @{ Label = $ServerFile; Path = $serverStaged },
    @{ Label = $EngineFile; Path = $engineStaged }
)
$asts = @{}
foreach ($lr in $launcherRole) {
    $tk = $null
    $er = $null
    $asts[$lr.Label] = [System.Management.Automation.Language.Parser]::ParseFile($lr.Path, [ref]$tk, [ref]$er)
    if (@($er).Count -gt 0) {
        foreach ($e in @($er)) {
            $violations += ('parse: ' + $lr.Label + ':' + $e.Extent.StartLineNumber + ' ' + $e.Message)
        }
    }
}

# 1. Root-global discipline.
foreach ($lr in $launcherRole) {
    $found = Get-ZbScriptRootViolation -Ast $asts[$lr.Label] -RootVar $ProjectRootVariable -FileLabel $lr.Label
    foreach ($v in @($found)) { $violations += ('path-resolution: ' + $v) }
}

# 2. Data boundary: rule data as separate files, embedded in no script.
$stagedData = @(Get-ChildItem -LiteralPath $StageDir -Filter '*.json' -File -Recurse |
        Where-Object { $_.FullName.Replace('\', '/') -like '*/data/*' })
if ($stagedData.Count -eq 0) {
    $violations += ('data-boundary: no rule data files staged — a package without data/*.json scans with an empty ruleset and reports clean (study §3)')
}
$stagedScripts = @(Get-ChildItem -LiteralPath $StageDir -Include '*.ps1', '*.bat' -File -Recurse)
foreach ($df in $stagedData) {
    $dataStripped = ((Get-Content -LiteralPath $df.FullName -Raw -Encoding UTF8) -replace '\s', '')
    if ($dataStripped.Length -lt 40) { continue }
    $sampleStart = [int][math]::Floor(($dataStripped.Length - 40) / 2)
    $sample = $dataStripped.Substring($sampleStart, 40)
    foreach ($sf in $stagedScripts) {
        $scriptStripped = ((Get-Content -LiteralPath $sf.FullName -Raw -Encoding UTF8) -replace '\s', '')
        if ($scriptStripped.Contains($sample)) {
            $violations += ('data-boundary: ' + $sf.Name + ' embeds the content of ' + $df.Name +
                ' — rule text in a script body is scanned at load and has blocked the engine before (study §3)')
        }
    }
}

# 3. Completeness: everything the launcher and server open is staged. Only references with a
# file extension are required — extensionless ones (like the reports output directory) are
# created at runtime, not shipped.
$refCount = @{}
foreach ($lr in $launcherRole) {
    $refs = Get-ZbRootReference -Ast $asts[$lr.Label] -RootVar $ProjectRootVariable
    $refCount[$lr.Label] = @($refs).Count
    foreach ($ref in @($refs)) {
        $norm = $ref.Replace('\', '/').TrimStart('./')
        if ($norm -notmatch '\.[A-Za-z0-9]{1,5}$') { continue }
        if (-not $stagedSet.ContainsKey($norm.ToLowerInvariant())) {
            $violations += ('completeness: ' + $lr.Label + ' opens ' + $norm + ' but it is not in the staged set')
        }
    }
}
$launcherText = Get-Content -LiteralPath $launcherStaged -Raw -Encoding UTF8
# Strip batch path modifiers (%~dp0 and friends) so they do not glue onto the file name.
$launcherClean = $launcherText -replace '%~[a-zA-Z]*0', ''
$batRefs = @([regex]::Matches($launcherClean, '[-\w]+\.ps1') | ForEach-Object { $_.Value } | Select-Object -Unique)
foreach ($br in $batRefs) {
    if (-not $stagedSet.ContainsKey($br.ToLowerInvariant())) {
        $violations += ('completeness: ' + $LauncherFile + ' invokes ' + $br + ' but it is not in the staged set')
    }
}
# Zero extracted references means the extractor missed, not that nothing is needed.
if ($refCount[$ServerFile] -eq 0) {
    $violations += ('completeness: no ' + $ProjectRootVariable + '-based references extracted from ' + $ServerFile +
        ' — wrong -ProjectRootVariable, or the script shape changed; refusing a vacuous pass')
}
if (@($batRefs).Count -eq 0) {
    $violations += ('completeness: no .ps1 reference found in ' + $LauncherFile + '; refusing a vacuous pass')
}

# 4. Encoding agreement on both sides of the process boundary.
$serverText = Get-Content -LiteralPath $serverStaged -Raw -Encoding UTF8
$engineText = Get-Content -LiteralPath $engineStaged -Raw -Encoding UTF8
if (-not ($serverText -match $EncodingPattern)) {
    $violations += ('encoding: ' + $ServerFile + ' (reader side) declares no UTF-8 console encoding — a packed host that detaches the console falls back to the OEM code page and the live view becomes mojibake (study §4)')
}
if (-not ($engineText -match $EncodingPattern)) {
    $violations += ('encoding: ' + $EngineFile + ' (writer side) declares no UTF-8 console encoding (study §4)')
}

if ($violations.Count -gt 0) {
    foreach ($v in $violations) { Write-Host ('CONTRACT ' + $v) }
    Write-Host ('Build refused: ' + $violations.Count + ' contract violation(s). No package was produced.')
    if (-not $KeepStage) { Remove-Item -Path $StageDir -Recurse -Force -ErrorAction SilentlyContinue }
    exit 3
}

# --------------------------------------------------------------------------------------------
# Manifest and zip
# --------------------------------------------------------------------------------------------

$manifestFiles = @()
foreach ($key in @($stagedSet.Keys | Sort-Object)) {
    $rel = $stagedSet[$key]
    $full = Join-Path -Path $StageDir -ChildPath $rel
    $manifestFiles += [ordered]@{
        path   = $rel.Replace('\', '/')
        bytes  = [long](Get-Item -LiteralPath $full).Length
        sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    }
}
$manifest = [ordered]@{
    package = [System.IO.Path]::GetFileName($OutPath)
    root_variable = $ProjectRootVariable
    files   = $manifestFiles
}
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path -Path $StageDir -ChildPath 'manifest.json'),
    (ConvertTo-Json -InputObject $manifest -Depth 5), $utf8NoBom)

try { Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction SilentlyContinue } catch { }
$outDir = [System.IO.Path]::GetDirectoryName($OutPath)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
if (Test-Path -LiteralPath $OutPath) { Remove-Item -LiteralPath $OutPath -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($StageDir, $OutPath)

Write-Host ('Staged ' + $manifestFiles.Count + ' file(s); all four packaging-contract checks passed.')
Write-Host ('Wrote ' + $OutPath)
if (-not $KeepStage) { Remove-Item -Path $StageDir -Recurse -Force -ErrorAction SilentlyContinue }
if ($PassThru) { $manifest }
exit 0
