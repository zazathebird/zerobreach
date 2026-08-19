# Load the MAIN-THREAD guard from the file, and the RUNSPACE MIRROR from inside the
# REMEDIATE here-string, then assert they agree on every vector. CLAUDE.md requires
# these two copies stay in sync; this is the check for that.
$src=(Resolve-Path 'ZeroBreach-Server.ps1').Path
$t=$null;$e=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($src,[ref]$t,[ref]$e)

# --- main thread ---
foreach($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    @('ConvertTo-GuardPath','Test-DestructiveRunCmd','Test-ProtectedTarget') -contains $n.Name},$true)){
  . ([scriptblock]::Create($f.Extent.Text))
}
$a=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$script:RUNCMD_DESTRUCTIVE'},$true)
. ([scriptblock]::Create($a[0].Extent.Text))

# --- runspace mirror, pulled out of the here-string ---
$rem=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -eq '$script:REMEDIATE_SCRIPT'},$true)
$body=$rem[0].Right.Extent.Text
$body=$body.Substring(2); $body=$body.Substring(0,$body.LastIndexOf("'@"))
$rast=[System.Management.Automation.Language.Parser]::ParseInput($body,[ref]$null,[ref]$null)
foreach($f in $rast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    @('ConvertTo-RGuardPath','Test-RDestructiveRunCmd','Test-RProtected') -contains $n.Name},$true)){
  . ([scriptblock]::Create($f.Extent.Text))
}
$ra=$rast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$RUNCMD_DESTRUCTIVE_R'},$true)
. ([scriptblock]::Create($ra[0].Extent.Text))
Write-Host ("main: {0} patterns | mirror: {1} patterns" -f $script:RUNCMD_DESTRUCTIVE.Count, $RUNCMD_DESTRUCTIVE_R.Count) -ForegroundColor Cyan

$vectors=@(
 @('DeleteFile','C:/Windows/System32/evil.exe'), @('DeleteFile','C:\Windows\System32\evil.exe'),
 @('DeleteFile','C:/Users/bob/.ssh/id_rsa'),     @('DeleteFile','\\?\C:\Windows\System32\x.exe'),
 @('DeleteFile','%SystemRoot%\System32\x.exe'),  @('DeleteFile','C:\Users\bob\AppData\Local\Temp\ok.exe'),
 @('RunCmd','vssadmin delete shadows /all'),     @('RunCmd','netsh advfirewall reset'),
 @('RunCmd','cipher /w:C'),                      @('RunCmd','sfc /scannow'),
 @('RunCmd','Stop-Service WinDefend -Force'),    @('RunCmd','Stop-Service Spooler -Force'),
 @('RunCmd','wevtutil cl Security'),             @('RunCmd','Clear-DnsClientCache'),
 @('RunCmd','bcdedit /set {default} safeboot minimal'), @('RunCmd','bcdedit /set {default} recoveryenabled Yes'),
 @('RunCmd','Set-MpPreference -DisableRealtimeMonitoring $true'), @('RunCmd','Set-MpPreference -DisableRealtimeMonitoring $false'),
 @('RunCmd','net user administrator Pw123'),     @('RunCmd','Update-MpSignature'),
 @('KillProcess','4'),                           @('DeleteReg','HKLM:\SYSTEM\CurrentControlSet\Services\Foo|Bar')
)
$pass=0;$fail=0
foreach($v in $vectors){
  $m = Test-ProtectedTarget $v[0] $v[1] '' 'lsass.exe test description'
  $r = Test-RProtected      $v[0] $v[1] '' 'lsass.exe test description'
  $mB = [bool]$m; $rB = [bool]$r
  if($mB -eq $rB){ $pass++; Write-Host ("  PASS  agree({0,-7}) {1}" -f $(if($mB){'BLOCK'}else{'allow'}), $v[1].Substring(0,[Math]::Min(52,$v[1].Length))) -ForegroundColor Green }
  else { $fail++; Write-Host ("  FAIL  DIVERGE  {0}`n        main='{1}'`n        mirror='{2}'" -f $v[1],$m,$r) -ForegroundColor Red }
}
Write-Host ("`n{0} vectors agree, {1} diverge" -f $pass,$fail) -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
if($fail){exit 1}
