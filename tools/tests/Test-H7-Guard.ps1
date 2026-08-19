# Extract BOTH guard copies from the shipped source and test them side by side.
$src=(Resolve-Path 'ZeroBreach-Server.ps1').Path
$t=$null;$e=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($src,[ref]$t,[ref]$e)
$want='ConvertTo-GuardPath','Test-DestructiveRunCmd','Test-ProtectedTarget'
foreach($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $want -contains $n.Name},$true)){
  . ([scriptblock]::Create($f.Extent.Text))
}
# $script:RUNCMD_DESTRUCTIVE lives at file scope; lift its literal out of the source.
$assign=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$script:RUNCMD_DESTRUCTIVE'},$true)
. ([scriptblock]::Create($assign[0].Extent.Text))
Write-Host ("Loaded guard + {0} destructive patterns from source" -f $script:RUNCMD_DESTRUCTIVE.Count) -ForegroundColor Cyan

$pass=0;$fail=0
function Blocked($n,$action,$param,$target,$desc){
  $r = Test-ProtectedTarget $action $param $target $desc
  if($r){$script:pass++;Write-Host ("  PASS  BLOCKED  {0,-56} [{1}]" -f $n,$r.Substring(0,[Math]::Min(40,$r.Length))) -ForegroundColor Green}
  else{$script:fail++;Write-Host ("  FAIL  ALLOWED  {0}" -f $n) -ForegroundColor Red}
}
function Allowed($n,$action,$param,$target,$desc){
  $r = Test-ProtectedTarget $action $param $target $desc
  if(-not $r){$script:pass++;Write-Host ("  PASS  allowed  {0}" -f $n) -ForegroundColor Green}
  else{$script:fail++;Write-Host ("  FAIL  BLOCKED  {0}  -> {1}" -f $n,$r) -ForegroundColor Red}
}

Write-Host "`n== H7: the CONFIRMED forward-slash bypass ==" -ForegroundColor Yellow
Blocked 'C:/Windows/System32/evil.exe'        'DeleteFile' 'C:/Windows/System32/evil.exe' '' ''
Blocked 'C:/Users/bob/.ssh/id_rsa'            'DeleteFile' 'C:/Users/bob/.ssh/id_rsa' '' ''
Blocked 'mixed C:/Windows\System32/x.dll'     'DeleteFile' 'C:/Windows\System32/x.dll' '' ''

Write-Host "`n== H7: vectors the audit REFUTED — must stay blocked (no regression) ==" -ForegroundColor Yellow
Blocked 'backslash baseline'                  'DeleteFile' 'C:\Windows\System32\evil.exe' '' ''
Blocked '\\?\C:\Windows\System32\evil.exe'    'DeleteFile' '\\?\C:\Windows\System32\evil.exe' '' ''
Blocked '\\?\GLOBALROOT prefix'               'DeleteFile' '\\?\GLOBALROOT\Device\HarddiskVolume1\Windows\System32\evil.exe' '' ''
Blocked 'UNC admin share'                     'DeleteFile' '\\localhost\C$\Windows\System32\evil.exe' '' ''
Blocked '%SystemRoot% expansion'              'DeleteFile' '%SystemRoot%\System32\evil.exe' '' ''
Blocked '.. traversal'                        'DeleteFile' 'C:\Users\bob\..\..\Windows\System32\evil.exe' '' ''
Blocked 'trailing space'                      'DeleteFile' 'C:\Windows\System32\evil.exe ' '' ''
Blocked 'dotfile in profile'                  'DeleteFile' 'C:\Users\bob\.gitconfig' '' ''

Write-Host "`n== H7b: destructive RunCmd — every vector the audit proved passed untouched ==" -ForegroundColor Yellow
Blocked 'vssadmin delete shadows /all /quiet' 'RunCmd' 'vssadmin delete shadows /all /quiet' '' ''
Blocked 'cipher /w:C'                         'RunCmd' 'cipher /w:C' '' ''
Blocked 'wbadmin delete catalog'              'RunCmd' 'wbadmin delete catalog -quiet' '' ''
Blocked 'bcdedit /set safeboot minimal'       'RunCmd' 'bcdedit /set {default} safeboot minimal' '' ''
Blocked 'Stop-Service WinDefend'              'RunCmd' 'Stop-Service WinDefend -Force' '' ''
Blocked 'net user administrator <pw>'         'RunCmd' 'net user administrator Passw0rd123' '' ''
Blocked 'reg delete HKLM\SOFTWARE /f'         'RunCmd' 'reg delete HKLM\SOFTWARE /f' '' ''
Blocked 'netsh advfirewall state off'         'RunCmd' 'netsh advfirewall set allprofiles state off' '' ''

Write-Host "`n== H7b: more sabotage patterns ==" -ForegroundColor Yellow
Blocked 'wevtutil cl Security'                'RunCmd' 'wevtutil cl Security' '' ''
Blocked 'Clear-EventLog'                      'RunCmd' 'Clear-EventLog -LogName Security' '' ''
Blocked 'Set-MpPreference disable $true'      'RunCmd' 'Set-MpPreference -DisableRealtimeMonitoring $true' '' ''
Blocked 'Add-MpPreference exclusion'          'RunCmd' 'Add-MpPreference -ExclusionPath C:\malware' '' ''
Blocked 'icacls /reset /T'                    'RunCmd' 'icacls C:\ /reset /T' '' ''
Blocked 'bcdedit recoveryenabled No'          'RunCmd' 'bcdedit /set {default} recoveryenabled No' '' ''
Blocked 'Add-LocalGroupMember Administrators' 'RunCmd' 'Add-LocalGroupMember -Group Administrators -Member evil' '' ''
Blocked 'wmic shadowcopy delete'              'RunCmd' 'wmic shadowcopy delete' '' ''
Blocked 'EnableLUA 0'                         'RunCmd' "Set-ItemProperty 'HKLM:\SOFTWARE\...\System' EnableLUA -Value 0" '' ''

Write-Host "`n== NO FALSE POSITIVES: the engine's OWN RunCmd fixes must still run ==" -ForegroundColor Yellow
Allowed 'netsh advfirewall reset'             'RunCmd' 'netsh advfirewall reset' '' ''
Allowed 'Set-MpPreference disable $false'     'RunCmd' 'Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue' '' ''
Allowed 'bcdedit recoveryenabled Yes'         'RunCmd' 'bcdedit /set {default} recoveryenabled Yes' '' ''
Allowed 'Stop-Service WinRM (engine)'         'RunCmd' "Stop-Service 'WinRM' -Force; Set-Service 'WinRM' -StartupType Disabled" '' ''
Allowed 'Stop-Service Spooler'                'RunCmd' 'Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled' '' ''
Allowed 'sfc /scannow'                        'RunCmd' 'sfc /scannow' '' ''
Allowed 'DISM RestoreHealth'                  'RunCmd' 'DISM /Online /Cleanup-Image /RestoreHealth' '' ''
Allowed 'Clear-DnsClientCache'                'RunCmd' 'Clear-DnsClientCache' '' ''
Allowed 'netsh portproxy reset'               'RunCmd' 'netsh interface portproxy reset' '' ''
Allowed 'Unregister-ScheduledTask'            'RunCmd' "Unregister-ScheduledTask -TaskName 'Evil' -Confirm:`$false" '' ''
Allowed 'Remove-MpPreference exclusion'       'RunCmd' "Remove-MpPreference -ExclusionPath 'C:\bad'" '' ''
Allowed 'EnableLUA 1 (re-enable UAC)'         'RunCmd' "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' EnableLUA 1 -Type DWord -Force" '' ''
Allowed 'Update-MpSignature'                  'RunCmd' 'Update-MpSignature -ErrorAction SilentlyContinue' '' ''
Allowed 'Set-Service Automatic + Start'       'RunCmd' "Set-Service -Name 'WinDefend' -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name 'WinDefend'" '' ''
Allowed 'Disable-NetFirewallRule (one rule)'  'RunCmd' "Disable-NetFirewallRule -Name 'EvilRule'" '' ''
Allowed 'assoc .js=txtfile'                   'RunCmd' 'assoc .js=txtfile' '' ''
Allowed 'benign temp file delete'             'DeleteFile' 'C:\Users\bob\AppData\Local\Temp\evil.exe' '' ''

Write-Host ("`n{0} passed, {1} failed" -f $pass,$fail) -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
if ($fail) { exit 1 }
