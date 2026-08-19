# Exercises the exact pattern the scan runspace now uses: ReadToEndAsync for stderr
# (deadlock-free, keeps the text) + ExitCode after WaitForExit + the verdict rules.
$pwsh = (Get-Process -Id $PID).Path

function Invoke-EngineLike {
    param([string]$Body, [int]$FakePhaseIdx, [bool]$Aborted = $false)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $pwsh
    $psi.Arguments = "-NoProfile -Command `"$Body`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $out = @()
    while (-not $proc.StandardOutput.EndOfStream) { $out += $proc.StandardOutput.ReadLine() }
    $proc.WaitForExit()

    $wasAborted = $Aborted
    $engineExit = -1
    try { $engineExit = $proc.ExitCode } catch {}
    try { $engineStderr = $stderrTask.Result } catch { $engineStderr = '' }

    $engineFailed = $false; $failReason = ''
    if (-not $wasAborted) {
        if ($engineExit -ne 0) { $engineFailed = $true; $failReason = "scan engine exited with code $engineExit" }
        elseif ($FakePhaseIdx -le 0) { $engineFailed = $true; $failReason = 'scan engine produced no phase output — nothing was actually scanned' }
    }
    [pscustomobject]@{ Exit=$engineExit; Failed=$engineFailed; Reason=$failReason; Stderr=$engineStderr.Trim(); OutLines=$out.Count }
}

$pass=0;$fail=0
function Check($n,$a,$e){ if("$a" -eq "$e"){$script:pass++;Write-Host "  PASS  $n" -ForegroundColor Green}else{$script:fail++;Write-Host "  FAIL  $n -> got '$a' expected '$e'" -ForegroundColor Red} }

Write-Host "`n== 1. Healthy engine: exit 0, real phase output ==" -ForegroundColor Yellow
$r = Invoke-EngineLike 'Write-Output \"PHASE 1 - test\"; exit 0' 30
Check 'exit code read'        $r.Exit 0
Check 'NOT flagged as failed' $r.Failed $false

Write-Host "`n== 2. AMSI-style death: exit 1, stderr, no stdout (the H2 scenario) ==" -ForegroundColor Yellow
$r = Invoke-EngineLike '[Console]::Error.WriteLine(\"ScriptContainedMaliciousContent\"); exit 1' 0
Check 'exit code 1 captured'      $r.Exit 1
Check 'flagged as FAILED'         $r.Failed $true
Check 'reason names the exit code' $r.Reason 'scan engine exited with code 1'
Check 'stderr PRESERVED (was discarded before)' $r.Stderr 'ScriptContainedMaliciousContent'
Check 'produced no stdout'        $r.OutLines 0

Write-Host "`n== 3. Silent lie: exit 0 but zero phases parsed ==" -ForegroundColor Yellow
$r = Invoke-EngineLike 'exit 0' 0
Check 'exit 0'                 $r.Exit 0
Check 'STILL flagged as failed' $r.Failed $true
Check 'reason explains it'      $r.Reason 'scan engine produced no phase output — nothing was actually scanned'

Write-Host "`n== 4. Operator abort is NOT a failure ==" -ForegroundColor Yellow
$r = Invoke-EngineLike 'exit 1' 0 $true
Check 'aborted run not flagged' $r.Failed $false

Write-Host "`n== 5. Large stderr does not deadlock (the reason BeginErrorReadLine existed) ==" -ForegroundColor Yellow
$r = Invoke-EngineLike '1..4000 | ForEach-Object { [Console]::Error.WriteLine(\"stderr flood line $_ padding padding padding padding\") }; exit 3' 5
Check 'completed without hanging' $r.Exit 3
Check 'flagged as failed'         $r.Failed $true
Check 'full stderr captured'      ($r.Stderr.Split([char]10).Count) 4000

Write-Host ("`n{0} passed, {1} failed" -f $pass,$fail) -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
