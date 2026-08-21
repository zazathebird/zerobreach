<#
.SYNOPSIS
    Generate data\integrity_manifest.json — the SHA256 pin for every engine module and
    data file that ships in a release.

.DESCRIPTION
    engine\Phases-0.ps1 verifies this manifest before phase 1 runs. Without it the
    scanner cannot tell whether its own signature database has been edited, and the
    FP-allowlist block fails OPEN: widening one allowlist entry to '.*' silently
    suppresses every detection that uses it while the scan still prints [OK ] banners
    (ADVERSARY_ANALYSIS.md E1).

    Run this at RELEASE time, from a clean tree, after all edits are final.
    tools\Build-Release.ps1 should invoke it before staging.

    The manifest is not a signature — anyone who can edit the data files can also
    regenerate the manifest. It defeats the realistic attack (tamper with the copy on
    a client machine, or with a USB copy in transit) but not a determined attacker
    who owns the build host. Authenticode-sign the release for that.

.PARAMETER Root
    Project root. Defaults to the parent of this script's directory.

.PARAMETER Verify
    Verify the existing manifest instead of writing a new one. Exit code 1 on mismatch,
    so it can gate CI.
#>
[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [switch]$Verify
)

$ErrorActionPreference = 'Stop'

# Everything whose contents change what the engine detects. Deliberately includes the
# engine modules themselves: a phase body edited to `return` early is as effective a
# blinding as an allowlist of '.*', and costs the attacker exactly as little.
$targets = @(
    'ZeroBreach-V23.ps1'
    'ZeroBreach-Server.ps1'
    'engine\Phases-0.ps1'
    'engine\Phases-1.ps1'
    'engine\Phases-2.ps1'
    'engine\Phases-3.ps1'
    'engine\Phases-4.ps1'
    'engine\Phases-5.ps1'
    'engine\Phases-6.ps1'
    'engine\Phases-7.ps1'
    'engine\Summary.ps1'
    'engine\FixMode.ps1'
    'data\detection_signatures.json'
    'data\mitre_mapping.json'
    'data\permission_baseline.json'
    'data\ioc_defaults.json'
)

function Get-Sha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs  = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try { ([BitConverter]::ToString($sha.ComputeHash($fs))) -replace '-','' }
    finally { $fs.Dispose(); $sha.Dispose() }
}

$manifestPath = Join-Path $Root 'data\integrity_manifest.json'

if ($Verify) {
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        Write-Host "[FAIL] no manifest at $manifestPath" -ForegroundColor Red; exit 1
    }
    $man  = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $bad  = 0
    foreach ($p in @($man.files.PSObject.Properties)) {
        $abs = Join-Path $Root $p.Name
        if (-not (Test-Path -LiteralPath $abs)) {
            Write-Host "[FAIL] missing: $($p.Name)" -ForegroundColor Red; $bad++; continue
        }
        $got = Get-Sha256 $abs
        if ($got -ne "$($p.Value)".ToUpper()) {
            Write-Host "[FAIL] modified: $($p.Name)" -ForegroundColor Red
            Write-Host "         expected $($p.Value)" -ForegroundColor DarkGray
            Write-Host "         found    $got" -ForegroundColor DarkGray
            $bad++
        }
    }
    if ($bad -eq 0) { Write-Host "[OK] all $(@($man.files.PSObject.Properties).Count) files match the manifest." -ForegroundColor Green; exit 0 }
    Write-Host "[FAIL] $bad file(s) do not match the manifest." -ForegroundColor Red
    exit 1
}

$files = [ordered]@{}
$missing = @()
foreach ($t in $targets) {
    $abs = Join-Path $Root $t
    if (-not (Test-Path -LiteralPath $abs)) { $missing += $t; continue }
    # Store with forward slashes so the manifest is identical whichever platform built it;
    # Join-Path on Windows accepts both, and the Linux test suite reads it too.
    $files[($t -replace '\\','/')] = Get-Sha256 $abs
}

if ($missing.Count) {
    Write-Host "[WARN] not found, omitted from manifest:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }
}

$manifest = [ordered]@{
    schema    = 'zerobreach.integrity/1'
    generated = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    algorithm = 'SHA256'
    note      = 'Verified by engine/Phases-0.ps1 before phase 1. Regenerate after any edit to a listed file: tools/New-IntegrityManifest.ps1'
    files     = $files
}

# UTF8 without BOM — this is a data file, read by ConvertFrom-Json on both servers and
# by the Linux test suite. (The .ps1 BOM rule applies to scripts, not to data.)
$json = $manifest | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($manifestPath, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "[OK] wrote $manifestPath — $($files.Count) files pinned." -ForegroundColor Green
foreach ($k in $files.Keys) { Write-Host ("       {0}  {1}" -f $files[$k].Substring(0,16), $k) -ForegroundColor DarkGray }
