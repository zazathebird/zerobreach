# ══════════════════════════════════════════════════════════════════════════════
#  ZeroBreach — Build-Release.ps1
#  Packages a clean, portable runtime zip you can copy/download/transfer to any
#  Windows 10/11 box and run with Launch-GUI.bat. Runtime files only — no reports,
#  no dev docs, no parked Python server, no work-rig folders.
#
#  Usage (from the project root or anywhere):
#      powershell -ExecutionPolicy Bypass -File tools\Build-Release.ps1
#      … -OutDir D:\usb            # write the zip somewhere else (e.g. straight to a stick)
#      … -IncludePython            # also pack the parked _python/ server
#      … -SkipValidation           # pack without the parse/JSON gate (not recommended)
#
#  Output:  dist\ZeroBreach-V23_<yyyyMMdd_HHmmss>.zip  +  .sha256 sidecar
#  The zip extracts to a single ZeroBreach\ folder. Runs on PS 5.1+ (uses
#  System.IO.Compression, no external tools).
# ══════════════════════════════════════════════════════════════════════════════
param(
    [string]$OutDir = '',
    [switch]$IncludePython,
    [switch]$SkipValidation
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot   # tools\ → project root
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }

Write-Host "`n[Build-Release] Project root: $root"

# ── Manifest: what a runtime copy needs ─────────────────────────────────────────
$requiredFiles = @(
    'Launch-GUI.bat'
    'ZeroBreach-Server.ps1'
    'ZeroBreach-V23.ps1'
    'README.md'
    'engine\Phases-1.ps1'
    'engine\Phases-2.ps1'
    'engine\Phases-3.ps1'
    'engine\Summary.ps1'
    'engine\FixMode.ps1'
    'gui\templates\index.html'
    'gui\static\css\main.css'
    'gui\static\css\fx.css'
    'gui\static\js\app.js'
    'gui\static\js\sound.js'
    'gui\static\js\themes.js'
    'gui\static\js\fx.js'
    'gui\static\js\kraken.js'
    'data\detection_signatures.json'
    'data\mitre_mapping.json'
    'data\ioc_defaults.json'
    'data\permission_baseline.json'
)
# Optional extras packed if present (not fatal when missing)
$optionalFiles = @('data\coverage_matrix.json')

$missing = @($requiredFiles | Where-Object { -not (Test-Path (Join-Path $root $_)) })
if ($missing.Count) {
    Write-Host "[Build-Release] FATAL — required files missing:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    exit 1
}
Write-Host "[Build-Release] Manifest OK ($($requiredFiles.Count) required files present)"

# ── Validation gate (parse + BOM on scripts, JSON validity on data) ─────────────
if (-not $SkipValidation) {
    $psFiles = $requiredFiles | Where-Object { $_ -like '*.ps1' }
    foreach ($rel in $psFiles) {
        $p = Join-Path $root $rel
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$errs)
        if ($errs.Count) {
            Write-Host "[Build-Release] FATAL — $rel has $($errs.Count) parse error(s):" -ForegroundColor Red
            $errs | Select-Object -First 3 | ForEach-Object { Write-Host "    $($_.Message)" -ForegroundColor Red }
            exit 1
        }
        $b = [System.IO.File]::ReadAllBytes($p)
        if (-not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)) {
            Write-Host "[Build-Release] FATAL — $rel is missing its UTF-8 BOM (see CLAUDE.md rules)" -ForegroundColor Red
            exit 1
        }
    }
    foreach ($rel in ($requiredFiles + $optionalFiles | Where-Object { $_ -like '*.json' })) {
        $p = Join-Path $root $rel
        if (-not (Test-Path $p)) { continue }
        try { $null = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json } catch {
            Write-Host "[Build-Release] FATAL — $rel is not valid JSON: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "[Build-Release] Validation OK (parse + BOM on $($psFiles.Count) scripts, JSON checked)"
}

# ── Stage into a temp folder (single ZeroBreach\ folder inside the zip) ─────────
$stage = Join-Path ([System.IO.Path]::GetTempPath()) "ZeroBreach_release_$stamp"
$stageRoot = Join-Path $stage 'ZeroBreach'
New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null

foreach ($rel in ($requiredFiles + ($optionalFiles | Where-Object { Test-Path (Join-Path $root $_) }))) {
    $src = Join-Path $root $rel
    $dst = Join-Path $stageRoot $rel
    $dstDir = Split-Path -Parent $dst
    if (-not (Test-Path $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
    Copy-Item -LiteralPath $src -Destination $dst -Force
}

if ($IncludePython) {
    $py = Join-Path $root '_python'
    if (Test-Path $py) {
        Copy-Item -LiteralPath $py -Destination (Join-Path $stageRoot '_python') -Recurse -Force
        Write-Host "[Build-Release] Included _python\ (parked server)"
    }
}

# Empty reports\ placeholder so the extracted tree is immediately writable-tested
New-Item -ItemType Directory -Path (Join-Path $stageRoot 'reports') -Force | Out-Null

# ── Zip it ───────────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$zipPath = Join-Path $OutDir "ZeroBreach-V23_$stamp.zip"
if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zipPath,
    [System.IO.Compression.CompressionLevel]::Optimal, $false)

Remove-Item -LiteralPath $stage -Recurse -Force

# SHA256 sidecar — verify integrity after any transfer
$hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
[System.IO.File]::WriteAllText("$zipPath.sha256", "$hash  $(Split-Path -Leaf $zipPath)`r`n",
    (New-Object System.Text.UTF8Encoding($false)))

$sizeMb = [Math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 2)
Write-Host "`n[Build-Release] DONE" -ForegroundColor Green
Write-Host "    Zip:    $zipPath  ($sizeMb MB)"
Write-Host "    SHA256: $hash"
Write-Host @'

    Deploy: copy the zip to the target box (or USB) →
            right-click the zip → Properties → Unblock (clears SmartScreen/MotW) →
            Extract All → open ZeroBreach\ → double-click Launch-GUI.bat → approve UAC.
'@
