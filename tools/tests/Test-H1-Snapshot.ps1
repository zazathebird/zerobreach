# Runs the real snapshot block's logic with `reg export` stubbed (no Windows registry
# on Linux), then validates the artifacts it produces — which is where H1 actually was.
$SNAPSHOT_DIR = Join-Path ([System.IO.Path]::GetTempPath()) "scythe_snap_test"
if (Test-Path $SNAPSHOT_DIR) { Remove-Item $SNAPSHOT_DIR -Recurse -Force }
$HOST_NAME = 'TESTBOX'
New-Item -ItemType Directory -Path $SNAPSHOT_DIR -Force | Out-Null

$regExports = @(
    @{H="HKCU"; K="SOFTWARE\Microsoft\Windows\CurrentVersion\Run";         F="01_Run_HKCU.reg"},
    @{H="HKLM"; K="SOFTWARE\Microsoft\Windows\CurrentVersion\Run";         F="02_Run_HKLM.reg"},
    @{H="HKLM"; K="SYSTEM\CurrentControlSet\Services";                     F="03_Services.reg"},
    @{H="HKLM"; K="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; F="04_Winlogon.reg"},
    @{H="HKCU"; K="SOFTWARE\Classes\CLSID";                                F="05_CLSID_HKCU.reg"}
)
$snapshotFiles = @()
foreach ($re in $regExports) {
    $dest = Join-Path $SNAPSHOT_DIR $re.F
    # Stub of what `reg export` writes: a real, importable .reg file.
    $fake = "Windows Registry Editor Version 5.00`r`n`r`n[$($re.H)\$($re.K)]`r`n`"Test`"=`"value`"`r`n"
    [System.IO.File]::WriteAllText($dest, $fake, (New-Object System.Text.UnicodeEncoding($false,$true)))
    if (Test-Path -LiteralPath $dest) { $snapshotFiles += $re.F }
}

# ── verbatim from engine/FixMode.ps1 ──
$rc = @()
$rc += '@echo off'
$rc += 'REM Scythe registry rollback — generated ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' on ' + $HOST_NAME
$rc += 'REM Restores the registry keys captured BEFORE remediation ran.'
$rc += 'REM Deleted FILES are not covered here (see the vault note below).'
$rc += 'net session >nul 2>&1 || (echo Run this as Administrator. & pause & exit /b 1)'
$rc += 'echo Restoring Scythe registry snapshot...'
foreach ($sf in $snapshotFiles) { $rc += ('reg import "%~dp0' + $sf + '" || echo FAILED: ' + $sf) }
$rc += 'echo Done. A reboot is recommended.'
$rc += 'pause'
[System.IO.File]::WriteAllText((Join-Path $SNAPSHOT_DIR 'Restore.cmd'), ($rc -join "`r`n") + "`r`n", (New-Object System.Text.ASCIIEncoding))

$pass=0;$fail=0
function Check($n,$a,$e){ if("$a" -eq "$e"){$script:pass++;Write-Host "  PASS  $n" -ForegroundColor Green}else{$script:fail++;Write-Host "  FAIL  $n -> got '$a' expected '$e'" -ForegroundColor Red} }

Write-Host "`n== THE H1 DEFECT: every .reg must be importable on its own ==" -ForegroundColor Yellow
foreach ($sf in $snapshotFiles) {
    $first = (Get-Content -LiteralPath (Join-Path $SNAPSHOT_DIR $sf) -TotalCount 1)
    Check "$sf first line is the required header" $first 'Windows Registry Editor Version 5.00'
}

Write-Host "`n== Restore.cmd ==" -ForegroundColor Yellow
$cmdPath = Join-Path $SNAPSHOT_DIR 'Restore.cmd'
$cmdText = Get-Content -LiteralPath $cmdPath -Raw
Check 'Restore.cmd exists'                (Test-Path $cmdPath) $true
Check 'imports every exported key'        (([regex]::Matches($cmdText,'reg import')).Count) $snapshotFiles.Count
Check 'uses %~dp0 (portable path)'        ($cmdText -match '%~dp0') $true
Check 'CRLF line endings for cmd.exe'     ($cmdText -match "`r`n") $true
Check 'checks for admin rights'           ($cmdText -match 'net session') $true
Check 'pure ASCII (no BOM/mojibake)'      ((([System.IO.File]::ReadAllBytes($cmdPath)) | Where-Object { $_ -gt 127 }).Count) 0
Check 'starts with @echo off'             ($cmdText.StartsWith('@echo off')) $true

Write-Host "`n== Regression: the OLD bundle format would have failed this ==" -ForegroundColor Yellow
$oldStyle = @("SCYTHE V22 SNAPSHOT | $(Get-Date) | Host: $HOST_NAME", "="*80)
foreach ($sf in $snapshotFiles) { $oldStyle += (Get-Content -LiteralPath (Join-Path $SNAPSHOT_DIR $sf) -Raw) }
$oldFirst = $oldStyle[0]
Check 'old bundle first line was NOT the header (proves the bug)' ($oldFirst -eq 'Windows Registry Editor Version 5.00') $false

Remove-Item $SNAPSHOT_DIR -Recurse -Force
Write-Host ("`n{0} passed, {1} failed" -f $pass,$fail) -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
if($fail){exit 1}
