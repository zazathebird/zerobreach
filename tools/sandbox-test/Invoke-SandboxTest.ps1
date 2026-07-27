<#
.SYNOPSIS
  Orchestrates a Windows Sandbox run of one of the two reusable harnesses in this folder.

.DESCRIPTION
  Stages the requested payload (either a freshly-built native-app .exe + engine-root, or the
  live repo's engine/server/gui/data as engine-root), writes a .wsb pointing at a scratch work
  directory, verifies no stale vmmemWindowsSandbox is running (restarting vmcompute if one is,
  per CLAUDE.md's Windows Sandbox rules), launches the sandbox, and polls for the harness's own
  completion marker file. It does NOT interpret the results - read the resulting *.log under
  WorkDir\<Stage>\out\ afterward (see README.md in this folder for what to look for).

  This script assumes it is being run FROM this repo checkout (native-app/ and the engine files
  are resolved relative to $PSScriptRoot\..\..). It requires: Windows Sandbox enabled, and for
  -Stage WebView2Dialog, a Rust/Node toolchain to rebuild native-app first.

.PARAMETER Stage
  MalwareDetection  - runs harness-malware-detection.ps1 (real theZoo malware content-detection
                       proof: masquerade rename, macro auto-exec, known-hash IOC). Needs internet
                       access from inside the sandbox (github.com + 7-zip.org) and can take
                       15-45+ minutes (sample download/extraction + a DEEP scan).
  WebView2Dialog    - runs harness-webview2-dialog.ps1 (native-shell WebView2-missing fatal
                       dialog confirmation). Fast (well under 5 minutes); rebuilds native-app
                       first unless -SkipBuild is passed.

.PARAMETER WorkDir
  Scratch directory for staged payloads + results. Defaults to tools\sandbox-test\work (already
  gitignored - malware samples and multi-hundred-KB reports do not belong in the repo).

.PARAMETER SkipBuild
  WebView2Dialog only: skip `npx tauri build --no-bundle` and reuse whatever .exe is already at
  native-app\src-tauri\target\release\zerobreach-native.exe. Fails loudly if that file is stale
  relative to main.rs, matching the CLAUDE.md lesson that this exact staleness produced an
  inconclusive result once already (2026-07-26 Stage D).

.PARAMETER TimeoutMinutes
  How long to poll for the harness's completion marker before giving up (does not kill the VM).
  Default 60.

.EXAMPLE
  .\Invoke-SandboxTest.ps1 -Stage WebView2Dialog
.EXAMPLE
  .\Invoke-SandboxTest.ps1 -Stage MalwareDetection -TimeoutMinutes 90
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('MalwareDetection', 'WebView2Dialog')]
    [string]$Stage,

    [string]$WorkDir = (Join-Path $PSScriptRoot 'work'),

    [switch]$SkipBuild,

    [int]$TimeoutMinutes = 60
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')

function Wait-NoSandboxRunning {
    $vm = Get-Process -Name 'vmmemWindowsSandbox' -ErrorAction SilentlyContinue
    if ($vm) {
        Write-Host "A vmmemWindowsSandbox process is already alive (PID $($vm.Id)) - Windows Sandbox is single-instance and won't boot a second VM. Restarting vmcompute to clear it (safe per CLAUDE.md; confirm no OTHER sandbox/Hyper-V workload is relying on it first)."
        Restart-Service vmcompute -Force
        $deadline = (Get-Date).AddSeconds(60)
        while ((Get-Process -Name 'vmmemWindowsSandbox' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
        }
        if (Get-Process -Name 'vmmemWindowsSandbox' -ErrorAction SilentlyContinue) {
            throw "vmmemWindowsSandbox is still running after a vmcompute restart - investigate before launching another sandbox."
        }
    }
}

function Wait-Marker {
    param([string]$MarkerPath, [int]$TimeoutMinutes, [string]$ProgressLogPath)
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $lastTail = ''
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $MarkerPath) { return $true }
        Start-Sleep -Seconds 10
        if ($ProgressLogPath -and (Test-Path $ProgressLogPath)) {
            $tail = (Get-Content $ProgressLogPath -Tail 1 -ErrorAction SilentlyContinue) -join ''
            if ($tail -and $tail -ne $lastTail) { Write-Host "  ...$tail"; $lastTail = $tail }
        }
    }
    return $false
}

Wait-NoSandboxRunning

if ($Stage -eq 'WebView2Dialog') {
    $stageDir = Join-Path $WorkDir 'webview2-dialog'
    $inDir    = Join-Path $stageDir 'in'
    $outDir   = Join-Path $stageDir 'out'
    New-Item -ItemType Directory -Force -Path "$inDir\app" | Out-Null
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $exePath = Join-Path $repoRoot 'native-app\src-tauri\target\release\zerobreach-native.exe'
    $mainRs  = Join-Path $repoRoot 'native-app\src-tauri\src\main.rs'
    if (-not $SkipBuild) {
        Write-Host "Rebuilding native-app from current source (npx tauri build --no-bundle)..."
        Push-Location (Join-Path $repoRoot 'native-app')
        try { & npx tauri build --no-bundle } finally { Pop-Location }
    }
    if (-not (Test-Path $exePath)) { throw "zerobreach-native.exe not found at $exePath - build it first (drop -SkipBuild)." }
    if ((Get-Item $exePath).LastWriteTime -lt (Get-Item $mainRs).LastWriteTime) {
        throw "STALE BUILD: $exePath predates $mainRs. This exact staleness produced an inconclusive Stage-D result on 2026-07-26 (the harness silently tested pre-hardening code). Rebuild (drop -SkipBuild) before testing."
    }
    Copy-Item $exePath (Join-Path $inDir 'app\zerobreach-native.exe') -Force
    Copy-Item (Join-Path $PSScriptRoot 'harness-webview2-dialog.ps1') (Join-Path $inDir 'harness-webview2-dialog.ps1') -Force

    $runCmd = @"
@echo off
echo LOGON_FIRED %DATE% %TIME%> C:\ZBOut\trace.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ZBIn\harness-webview2-dialog.ps1 > C:\ZBOut\stdout.txt 2> C:\ZBOut\stderr.txt
echo EXITCODE=%ERRORLEVEL%>> C:\ZBOut\trace.txt
"@
    Set-Content -Path (Join-Path $inDir 'run.cmd') -Value $runCmd -Encoding ASCII

    $wsb = @"
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$inDir</HostFolder>
      <SandboxFolder>C:\ZBIn</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$outDir</HostFolder>
      <SandboxFolder>C:\ZBOut</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c C:\ZBIn\run.cmd</Command>
  </LogonCommand>
</Configuration>
"@
    $wsbPath = Join-Path $stageDir 'run.wsb'
    Set-Content -Path $wsbPath -Value $wsb -Encoding ASCII

    Write-Host "Launching Windows Sandbox: $wsbPath"
    Start-Process -FilePath $wsbPath
    $marker = Join-Path $outDir 'WEBVIEW2_DIALOG_DONE'
    $ok = Wait-Marker -MarkerPath $marker -TimeoutMinutes $TimeoutMinutes -ProgressLogPath (Join-Path $outDir 'harness_webview2_dialog.log')
    if ($ok) {
        Write-Host "DONE. Results: $outDir\harness_webview2_dialog.log  (+ webview2_dialog_screenshot.png)"
    } else {
        Write-Host "TIMED OUT waiting for the completion marker after $TimeoutMinutes minutes - check $outDir manually; the sandbox VM was left running for inspection."
    }
}
elseif ($Stage -eq 'MalwareDetection') {
    $stageDir = Join-Path $WorkDir 'malware-detection'
    $inDir    = Join-Path $stageDir 'in'
    $outDir   = Join-Path $stageDir 'out'
    New-Item -ItemType Directory -Force -Path "$inDir\app\engine-root" | Out-Null
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    Write-Host "Staging current repo (engine/gui/data/server) as engine-root..."
    foreach ($d in @('engine', 'gui', 'data')) {
        Copy-Item (Join-Path $repoRoot $d) (Join-Path $inDir "app\engine-root\$d") -Recurse -Force
    }
    foreach ($f in @('ZeroBreach-Server.ps1', 'ZeroBreach-V23.ps1')) {
        Copy-Item (Join-Path $repoRoot $f) (Join-Path $inDir "app\engine-root\$f") -Force
    }
    Copy-Item (Join-Path $PSScriptRoot 'harness-malware-detection.ps1') (Join-Path $inDir 'harness-malware-detection.ps1') -Force

    $runCmd = @"
@echo off
echo LOGON_FIRED %DATE% %TIME%> C:\ZBOut\trace.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ZBIn\harness-malware-detection.ps1 > C:\ZBOut\stdout.txt 2> C:\ZBOut\stderr.txt
echo EXITCODE=%ERRORLEVEL%>> C:\ZBOut\trace.txt
"@
    Set-Content -Path (Join-Path $inDir 'run.cmd') -Value $runCmd -Encoding ASCII

    $wsb = @"
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$inDir</HostFolder>
      <SandboxFolder>C:\ZBIn</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$outDir</HostFolder>
      <SandboxFolder>C:\ZBOut</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c C:\ZBIn\run.cmd</Command>
  </LogonCommand>
</Configuration>
"@
    $wsbPath = Join-Path $stageDir 'run.wsb'
    Set-Content -Path $wsbPath -Value $wsb -Encoding ASCII

    Write-Host "Launching Windows Sandbox: $wsbPath (this stage downloads real malware and runs a DEEP scan - expect 15-45+ minutes)"
    Start-Process -FilePath $wsbPath
    $marker = Join-Path $outDir 'MALWARE_DETECTION_DONE'
    $ok = Wait-Marker -MarkerPath $marker -TimeoutMinutes $TimeoutMinutes -ProgressLogPath (Join-Path $outDir 'harness_malware_detection.log')
    if ($ok) {
        Write-Host "DONE. Results: $outDir\harness_malware_detection.log  (+ report_malware_detection.json, engine_reports\)"
    } else {
        Write-Host "TIMED OUT waiting for the completion marker after $TimeoutMinutes minutes - check $outDir manually; the sandbox VM was left running for inspection."
    }
}
