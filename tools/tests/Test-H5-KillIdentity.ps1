# Extract the real Get-KillParam from the shipped loader (no retyping).
$t=$null;$e=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path 'Scythe-V23.ps1').Path,[ref]$t,[ref]$e)
$fn=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-KillParam'},$true)
. ([scriptblock]::Create($fn[0].Extent.Text))
Write-Host "Extracted Get-KillParam from Scythe-V23.ps1" -ForegroundColor Cyan

# The executors' identity check, mirrored exactly as written in both copies.
function Test-KillIdentity {
    param([string]$FixParam, $LiveProc)
    $kp = "$FixParam" -split '\|'
    $procId = 0
    if (-not [int]::TryParse($kp[0].Trim(), [ref]$procId) -or $procId -le 0) { return 'MALFORMED' }
    if (-not $LiveProc) { return 'ALREADY_GONE' }
    if ($kp.Count -lt 3) { return 'UNVERIFIABLE' }
    $wantName = "$($kp[1])"; $wantTicks = [int64]0
    [void][int64]::TryParse("$($kp[2])", [ref]$wantTicks)
    $haveTicks = [int64]0
    try { $haveTicks = $LiveProc.StartTime.Ticks } catch { $haveTicks = 0 }
    if ($wantName -and $LiveProc.ProcessName -ne $wantName) { return 'SKIP_NAME_CHANGED' }
    if ($wantTicks -gt 0 -and $haveTicks -gt 0 -and $haveTicks -ne $wantTicks) { return 'SKIP_STARTTIME_CHANGED' }
    return 'KILL'
}

$pass=0;$fail=0
function Check($n,$a,$e){ if("$a" -eq "$e"){$script:pass++;Write-Host "  PASS  $n -> $a" -ForegroundColor Green}else{$script:fail++;Write-Host "  FAIL  $n -> got '$a' expected '$e'" -ForegroundColor Red} }

Write-Host "`n== Get-KillParam encoding ==" -ForegroundColor Yellow
$self = Get-KillParam $PID
Check 'encodes 3 parts for a live process' (($self -split '\|').Count) 3
Check 'first part is the PID'              (($self -split '\|')[0]) "$PID"
Check 'second part is the process name'    (($self -split '\|')[1]) (Get-Process -Id $PID).ProcessName
Check 'third part is a nonzero tick count' ((([int64](($self -split '\|')[2])) -gt 0)) $true
Check 'dead PID falls back to bare PID'    (Get-KillParam 999999) '999999'
Check 'garbage id returned as-is'          (Get-KillParam 'notanumber') 'notanumber'

Write-Host "`n== Identity re-validation at remediation time ==" -ForegroundColor Yellow
$me = Get-Process -Id $PID
Check 'same process -> KILL'  (Test-KillIdentity $self $me) 'KILL'
Check 'process exited -> ALREADY_GONE' (Test-KillIdentity $self $null) 'ALREADY_GONE'

# THE H5 BUG: PID recycled into a different process.
$recycled = "$PID|totally-different-name|$((Get-Process -Id $PID).StartTime.Ticks)"
Check 'PID recycled, new name -> SKIP' (Test-KillIdentity $recycled $me) 'SKIP_NAME_CHANGED'

# Same name, restarted process (start time differs) — e.g. malware relaunched.
$restarted = "$PID|$($me.ProcessName)|123456789"
Check 'same name, different start -> SKIP' (Test-KillIdentity $restarted $me) 'SKIP_STARTTIME_CHANGED'

Write-Host "`n== Backward compatibility with reports written before this change ==" -ForegroundColor Yellow
Check 'bare PID -> UNVERIFIABLE (not a crash)' (Test-KillIdentity "$PID" $me) 'UNVERIFIABLE'
Check 'empty FixParam -> MALFORMED'            (Test-KillIdentity '' $me) 'MALFORMED'
Check 'non-numeric FixParam -> MALFORMED'      (Test-KillIdentity 'abc|x|1' $me) 'MALFORMED'

Write-Host ("`n{0} passed, {1} failed" -f $pass,$fail) -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
