# Load all THREE copies of the system-damage guard and assert they agree on every
# vector: the main thread (ZeroBreach-Server.ps1), the runspace mirror (inside the
# $script:REMEDIATE_SCRIPT here-string), and the engine copy (ZeroBreach-V23.ps1,
# used by the interactive Invoke-FixMode — added 2026-08-19). CLAUDE.md requires all
# three stay in sync; this is the check for that.
$src=(Resolve-Path 'ZeroBreach-Server.ps1').Path
$t=$null;$e=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($src,[ref]$t,[ref]$e)

# --- main thread ---
foreach($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    @('ConvertTo-GuardPath','Test-DestructiveRunCmd','Test-ProtectedTarget') -contains $n.Name},$true)){
  . ([scriptblock]::Create($f.Extent.Text))
}
foreach($vn in @('$script:RUNCMD_DESTRUCTIVE','$script:RUNCMD_MUTATING','$script:KILL_CRITICAL_NAME_RX','$script:KILL_CRITICAL_DESC_RX')){
  $a=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq $vn},$true)
  if(-not $a){ Write-Host "  FAIL  main-thread $vn not found" -ForegroundColor Red; exit 1 }
  . ([scriptblock]::Create($a[0].Extent.Text))
}

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
foreach($vn in @('$RUNCMD_DESTRUCTIVE_R','$RUNCMD_MUTATING_R','$KILL_CRITICAL_NAME_RX_R','$KILL_CRITICAL_DESC_RX_R')){
  $ra=$rast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq $vn},$true)
  if(-not $ra){ Write-Host "  FAIL  runspace mirror $vn not found" -ForegroundColor Red; exit 1 }
  . ([scriptblock]::Create($ra[0].Extent.Text))
}
# --- engine copy (loader), used by Invoke-FixMode ---
$east=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path 'ZeroBreach-V23.ps1').Path,[ref]$null,[ref]$null)
foreach($f in $east.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    @('ConvertTo-EGuardPath','Test-EDestructiveRunCmd','Test-EProtected') -contains $n.Name},$true)){
  . ([scriptblock]::Create($f.Extent.Text))
}
foreach($vn in @('$global:RUNCMD_DESTRUCTIVE_E','$global:RUNCMD_MUTATING_E','$global:KILL_CRITICAL_NAME_RX_E','$global:KILL_CRITICAL_DESC_RX_E')){
  $ea=$east.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq $vn},$true)
  if(-not $ea){ Write-Host "  FAIL  engine copy $vn not found" -ForegroundColor Red; exit 1 }
  . ([scriptblock]::Create($ea[0].Extent.Text))
}
Write-Host ("main: {0} patterns | mirror: {1} | engine: {2}" -f $script:RUNCMD_DESTRUCTIVE.Count, $RUNCMD_DESTRUCTIVE_R.Count, $global:RUNCMD_DESTRUCTIVE_E.Count) -ForegroundColor Cyan

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
 @('KillProcess','4'),                           @('DeleteReg','HKLM:\SYSTEM\CurrentControlSet\Services\Foo|Bar'),
 # audit M1 — a RunCmd that merely NAMES a system path vs one that writes to it, and
 # the IFEO value exception. Both copies must agree on every one of these.
 @('RunCmd',"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -Value 'C:\Windows\system32\userinit.exe,' -Force"),
 @('RunCmd',"Remove-Item -LiteralPath 'C:\Windows\System32\drivers\evil.sys' -Force"),
 @('RunCmd',"Rename-Item 'C:\Windows\System32\sethc.exe' 'C:\Windows\System32\sethc.exe.kraken' -Force"),
 @('RunCmd','cmd.exe /c del C:\Windows\System32\config\SAM'),
 @('RunCmd',"Remove-Item 'C:\Users\bob\.ssh\id_rsa' -Force"),
 @('RunCmd',"Remove-Item 'Cert:\LocalMachine\Root\ABCDEF' -Force"),
 @('RunCmd','sfc /scannow'),
 @('DeleteReg','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe|Debugger'),
 @('DeleteReg','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe|SomethingElse'),
 @('DeleteRegKey','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe'),
 @('KillProcess','4321|evil|63080000'), @('KillProcess','4321|lsass|63080000'), @('KillProcess','4321|zerobreach|63080000')
)
$pass=0;$fail=0
foreach($v in $vectors){
  $m = Test-ProtectedTarget $v[0] $v[1] '' 'lsass.exe test description'
  $r = Test-RProtected      $v[0] $v[1] '' 'lsass.exe test description'
  $g = Test-EProtected      $v[0] $v[1] '' 'lsass.exe test description'
  $mB = [bool]$m; $rB = [bool]$r; $gB = [bool]$g
  if($mB -eq $rB -and $mB -eq $gB){ $pass++; Write-Host ("  PASS  agree({0,-7}) {1}" -f $(if($mB){'BLOCK'}else{'allow'}), $v[1].Substring(0,[Math]::Min(52,$v[1].Length))) -ForegroundColor Green }
  else { $fail++; Write-Host ("  FAIL  DIVERGE  {0}`n        main='{1}'`n        mirror='{2}'`n        engine='{3}'" -f $v[1],$m,$r,$g) -ForegroundColor Red }
}
Write-Host ("`n{0} vectors agree across all 3 copies, {1} diverge" -f $pass,$fail) -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
if($fail){exit 1}
