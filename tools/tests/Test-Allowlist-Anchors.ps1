<#
.SYNOPSIS
    2026-09-02 lint round: the 170 warnings the signature linter reported on its first run
    against data/detection_signatures.json, and what fixed them.

.DESCRIPTION
    Guards five changes, all of the shape "a bare substring matched text the attacker chooses":

      §1  hidden_task_benign_paths / infostealer_benign_paths / hunt_task_benign_paths and the
          Temp-directory group entries are component-anchored. A task NAMED 'dell updater' or a
          file NAMED 'cefcache_passwords.txt' is no longer waved through.
      §2  native_messaging_benign_hosts entries are anchored host names, and phase 117 no longer
          stops at a trusted NAME - the host binary is examined regardless.
      §3  trusted_root_ca_issuers is not an allowlist any more. Phase 39 decides trust by
          thumbprint (data/trusted_root_program.json + AuthRoot); Resolve-RootCertTrust is run
          here against fake certificates, including the case that motivated the change (a root
          calling itself 'Windows Update Root' used to be INFO).
      §4  The five sets the loader pulled but no phase read are read now (74.6, 74.7, 90, 92),
          and every finding they produce is FixAction Info.
      §5  data/trusted_root_program.json is well-formed and shipped.

    Every regex and function is pulled out of the shipped source via the AST or the shipped
    JSON, so this test cannot drift from what it guards. Read-only.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$pass = 0; $fail = 0
function Assert-That { param([string]$Name,$Actual,$Expected)
    if ("$Actual" -ceq "$Expected") { $script:pass++ } else { $script:fail++; Write-Host "  FAIL  $Name`n        expected: $Expected`n        actual:   $Actual" -ForegroundColor Red } }
function Assert-True { param([string]$Name,$Cond) Assert-That $Name ([bool]$Cond) $true }

Write-Host "`n=== ALLOWLIST ANCHORS + THUMBPRINT ROOT TRUST (lint round 2026-09-02) ===" -ForegroundColor Cyan

$sig = Get-Content -LiteralPath (Join-Path $root 'data/detection_signatures.json') -Raw -Encoding UTF8 | ConvertFrom-Json
function Get-Joined([string]$Key) {
    # What Join-AllowRegex builds from a key, minus the integrity gate (tested elsewhere).
    $a = @($sig.$Key | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") })
    if (-not $a.Count) { return '(?!)' }
    return ($a -join '|')
}
$loaderText = Get-Content -LiteralPath (Join-Path $root 'Scythe-V23.ps1') -Raw -Encoding UTF8
$engineFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'engine') -Filter '*.ps1' | Sort-Object Name)
$engineText = ($engineFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 }) -join "`n"

# ── §1. Path allowlists are component-anchored ─────────────────────────────────────────────
$cases = @(
  @{ Key = 'hidden_task_benign_paths'
     Allow = @(
        'C:\Windows\System32\Tasks\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319',
        'C:\Windows\System32\Tasks\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup',
        'C:\Windows\System32\Tasks\GoogleUpdaterTaskSystem137.0.7106.0{A1B2C3D4-0000-0000-0000-000000000000}',
        'C:\Windows\System32\Tasks\GoogleSystem\GoogleUpdater\GoogleUpdaterTaskSystem138.0.1{A1B2C3D4-0000-0000-0000-000000000000}',
        'C:\Windows\System32\Tasks\GoogleUpdateTaskMachineCore{A1B2C3D4-0000-0000-0000-000000000000}',
        'C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTaskMachineCore{A1B2C3D4-0000-0000-0000-000000000000}',
        'C:\Windows\System32\Tasks\Adobe Acrobat Update Task',
        'C:\Windows\System32\Tasks\AdobeGCInvoker-1.0',
        'C:\Windows\System32\Tasks\OneDrive Standalone Update Task-S-1-5-21-1-2-3-1001',
        'C:\Windows\System32\Tasks\NVIDIA\NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}',
        'C:\Windows\System32\Tasks\NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}',
        'C:\Windows\System32\Tasks\Dell\SupportAssistAgent AutoUpdate',
        'C:\Windows\System32\Tasks\Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB',
        'C:\Windows\System32\Tasks\BraveSoftwareUpdateTaskMachineCore{A1B2C3D4-0000-0000-0000-000000000000}',
        'C:\Windows\System32\Tasks\DropboxUpdateTaskMachineUA')
     Deny = @(
        'C:\Windows\System32\Tasks\Dell Updater',                       # bare 'dell\b' used to match
        'C:\Windows\System32\Tasks\Lenovo Vantage Helper',
        'C:\Windows\System32\Tasks\Updates\GoogleUpdater',              # bare 'googleupdater' used to match
        'C:\Windows\System32\Tasks\adobegcinvoker-helper\stage',
        'C:\Windows\System32\Tasks\Microsoft Office\evil',
        'C:\Windows\System32\Tasks\OneDrive Standalone Update Task-S-1-5-21\payload',
        'C:\Windows\System32\Tasks\intelupdate') }
  @{ Key = 'infostealer_benign_paths'
     Allow = @(
        'C:\Users\j\AppData\Local\Microsoft\Edge\User Data\Default\Login Data',
        'C:\Users\j\AppData\Local\Google\Chrome\User Data\Default\Code Cache\js\wallet_login.txt',
        'C:\Users\j\AppData\Roaming\Slack\Cache\EBWebView\Default\passwords.log',
        'C:\Users\j\AppData\Local\Temp\pip-build\zxcvbndata\passwords.txt',
        'C:\Users\j\AppData\Local\Programs\App\resources\mini-wallet-login.txt',
        'C:\Users\j\AppData\Roaming\npm\node_modules\x\LICENSE\foo.license.txt',
        'C:\Users\j\AppData\Local\Microsoft\Edge\User Data\Default\Edge Wallet\autofill.db')
     Deny = @(
        'C:\Users\j\AppData\Local\Temp\cefcache_passwords.txt',        # bare 'cefcache' used to match
        'C:\Users\j\AppData\Roaming\edge wallet passwords.zip',          # bare 'edge wallet' used to match
        'C:\Users\j\AppData\Local\Temp\wallet-checkout\credentials.zip',
        'C:\Users\j\AppData\Local\Temp\zxcvbndata_cookies.db',
        'C:\Users\j\AppData\Local\Temp\autofill_login.db') }
  @{ Key = 'hunt_task_benign_paths'
     Allow = @('\MicrosoftEdgeUpdateTaskMachineCore{A1B2C3D4-0000-0000-0000-000000000000}', '\Microsoft\Windows\Flighting\OneSettings\RefreshCache')
     Deny  = @('\MicrosoftEdgeUpdateTask\evil', '\MicrosoftEdgeUpdateTaskMachineCore\stage') }
  @{ Key = 'sideload_benign_paths'
     Allow = @('C:\Users\j\AppData\Local\Temp\_MEI123456\python3.dll', 'C:\Users\j\AppData\Local\Temp\pip-build-abc\x.dll')
     Deny  = @('C:\Users\j\AppData\Local\Temp\pipevil.dll', 'C:\Users\j\AppData\Local\Temp\npm.dll') }
  @{ Key = 'exec_evidence_benign_paths'
     Allow = @('C:\Users\j\AppData\Local\Temp\_MEI98765\app.exe', 'C:\Users\j\AppData\Local\Temp\is-AB12C.tmp\setup.exe')
     Deny  = @('C:\Users\j\AppData\Local\Temp\nsis-loader.exe', 'C:\Users\j\AppData\Local\Temp\WinSAT.exe') }
  @{ Key = 'webhook_c2_benign_paths'
     Allow = @('C:\Users\j\AppData\Local\Temp\go-build123\b001\exe\a.out')
     Deny  = @('C:\Users\j\AppData\Local\Temp\pip.ps1') }
  @{ Key = 'shell_extension_benign_dlls'
     Allow = @('C:\Program Files\7-Zip\7-zip.dll', 'C:\Program Files (x86)\Microsoft Office\root\Office16\x.dll', 'C:\Program Files\Windows Defender\shellext.dll')
     Deny  = @('C:\Program Files\Evil Corp\x.dll', 'C:\Program Filesx\Microsoft\x.dll') }
)
foreach ($c in $cases) {
    $rx = Get-Joined $c.Key
    Assert-True "$($c.Key) loads and is not empty" ($rx -ne '(?!)')
    foreach ($a in $c.Allow) { Assert-True "$($c.Key) ALLOWS $a" ($a -match $rx) }
    foreach ($d in $c.Deny)  { Assert-True "$($c.Key) DENIES $d" (-not ($d -match $rx)) }
}
# Every entry of the three tightened lists begins at a separator and ends at a separator or the end.
foreach ($k in @('hidden_task_benign_paths','infostealer_benign_paths')) {
    foreach ($e in @($sig.$k)) {
        Assert-True "$k entry starts at a path component: $e" ($e -match '^\\\\')
        Assert-True "$k entry ends at a component or the end: $e" ($e -match '(\\\\|\$|\(\\\\\|\$\))$')
    }
}

# ── §2. Native-messaging hosts: anchored names, and the name no longer ends the check ──────
$nm = Get-Joined 'native_messaging_benign_hosts'
foreach ($a in @('com.microsoft.browsercore','com.google.chrome.example','com.1password.browserhelper','ch.protonmail.bridge')) { Assert-True "native_messaging ALLOWS $a" ($a -match $nm) }
foreach ($d in @('evil.com.microsoft.x','xcom.microsoft.foo','com.microsoft.','com.evil.helper','com.microsoftx.foo')) { Assert-True "native_messaging DENIES $d" (-not ($d -match $nm)) }
foreach ($e in @($sig.native_messaging_benign_hosts)) { Assert-True "native_messaging entry fully anchored: $e" ($e -match '^\^.*\$$') }
$p4 = Get-Content -LiteralPath (Join-Path $root 'engine/Phases-4.ps1') -Raw -Encoding UTF8
Assert-True 'phase 117 — no longer skips on the host NAME alone'          (-not ($p4 -match 'if \(\$hostName -match \$NATIVE_MSG_BENIGN_RE\) \{ continue \}'))
Assert-True 'phase 117 — a trusted name only excuses a non-hijacked host'  ($p4 -match 'if \(\$nameBenign -and -not \$hijacked\) \{ continue \}')
Assert-True 'phase 117 — the binary is resolved before the name decides'  ($p4.IndexOf('$hijacked = ($unsigned -and $userPath)') -lt $p4.IndexOf('if ($nameBenign -and -not $hijacked)'))
Assert-True 'phase 117 — carries the SIG_AUDIT budget on the sig loop'    ($p4 -match '\$nmSigSeen -lt \$global:SIG_AUDIT_MAX_FILES')

# ── §3. Root-store trust is decided by thumbprint ──────────────────────────────────────────
Assert-True 'loader — trusted_root_ca_issuers is no longer a Join-AllowRegex' (-not ($loaderText -match "Join-AllowRegex\s+'trusted_root_ca_issuers'"))
Assert-True 'loader — trusted_root_ca_issuers is read as reference words'    ($loaderText -match "Get-Sig\s+'trusted_root_ca_issuers'")
$man = Get-Content -LiteralPath (Join-Path $root 'data/signature_lint_manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True 'manifest — trusted_root_ca_issuers is a reference set'           (@($man.reference_sets) -contains 'trusted_root_ca_issuers')
Assert-True 'manifest — trusted_root_ca_issuers is not a substring allowlist' (-not (@($man.substring_allowlists) -contains 'trusted_root_ca_issuers'))

$e = $null
$loaderAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Scythe-V23.ps1'), [ref]$null, [ref]$e)
if ($e.Count) { throw "loader has parse errors" }
foreach ($fnName in @('Resolve-RootCertTrust','Get-TrustedRootIndex')) {
    $fn = @($loaderAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fnName }, $true))
    Assert-That "loader defines $fnName once" $fn.Count 1
    . ([scriptblock]::Create($fn[0].Extent.Text))
}
$SEV_HIGH = 'HIGH'; $SEV_INFO = 'INFO'; $SEV_POSSIBLE = 'POSSIBLE'
$TRUSTED_ROOTS = Get-Content -LiteralPath (Join-Path $root 'data/trusted_root_program.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$idx = Get-TrustedRootIndex
Assert-True 'index — program has 300+ SHA-256 entries'      ($idx.Sha256.Count -ge 300)
Assert-True 'index — Microsoft Root CA 2011 is Windows-shipped' ($idx.Sha1.ContainsKey('8F43288AD272F3103B6FB1428485EA3014C0BCFE'))
Assert-True 'index — Microsoft Root CA 2010 is Windows-shipped' ($idx.Sha1.ContainsKey('3B1EFD3A66EA28B16697394703A72CA340A05BD5'))
Assert-That 'index — four legacy roots'                       @($idx.Legacy).Count 4
$trcWords = @(@($sig.trusted_root_ca_issuers) | ForEach-Object { [regex]::Escape("$_") })
$nameRx = '\b(' + ($trcWords -join '|') + ')\b'

function New-FakeCert {
    param([string]$Cn, [string]$Serial = '1A', [datetime]$NotAfter = (Get-Date).AddYears(10), [bool]$HasKey = $false, [byte[]]$Raw = $null, [string]$Issuer = '')
    if (-not $Raw) { $Raw = [System.Text.Encoding]::ASCII.GetBytes("cert:${Cn}:${Serial}:$([guid]::NewGuid())") }
    $sha1 = ([BitConverter]::ToString([System.Security.Cryptography.SHA1]::Create().ComputeHash($Raw))) -replace '-',''
    $subj = "CN=$Cn, O=$Cn, C=US"
    $o = [pscustomobject]@{
        Thumbprint = $sha1; RawData = $Raw; Subject = $subj; Issuer = $(if ($Issuer) { $Issuer } else { $subj })
        SerialNumber = $Serial; NotBefore = (Get-Date).AddYears(-1); NotAfter = $NotAfter; HasPrivateKey = $HasKey
    }
    $o | Add-Member -MemberType ScriptMethod -Name GetNameInfo -Value { param($type, $forIssuer) $this.Subject -replace '^CN=([^,]+).*$','$1' }
    return $o
}
function Sha256Hex([byte[]]$b) { ([BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($b))) -replace '-','' }

# The bug that motivated the change: a rogue root named after Windows was INFO on name alone.
$rogue = New-FakeCert -Cn 'Windows Update Root'
$v = Resolve-RootCertTrust -Cert $rogue -Index $idx -AuthRootThumbs @{} -NameRx $nameRx
Assert-That 'rogue "Windows Update Root" — tier'     $v.Tier 'VendorName'
Assert-That 'rogue "Windows Update Root" — POSSIBLE' $v.Severity 'POSSIBLE'
# ...and with the private key on the box it is HIGH whatever it is called.
$v = Resolve-RootCertTrust -Cert (New-FakeCert -Cn 'DigiCert Global Root G2' -HasKey $true) -Index $idx -AuthRootThumbs @{} -NameRx $nameRx
Assert-That 'root with private key — tier' $v.Tier 'PrivateKey'
Assert-That 'root with private key — HIGH' $v.Severity 'HIGH'
# A program root is known by its SHA-256, whatever its name says.
$raw = [System.Text.Encoding]::ASCII.GetBytes('fake program root')
$idx2 = Get-TrustedRootIndex
$idx2.Sha256[(Sha256Hex $raw)] = @{ Name = 'Fake Program Root'; Status = 'Included' }
$v = Resolve-RootCertTrust -Cert (New-FakeCert -Cn 'Totally Unknown Name' -Raw $raw) -Index $idx2 -AuthRootThumbs @{} -NameRx $nameRx
Assert-That 'program root — tier by hash, not name' $v.Tier 'Program'
Assert-That 'program root — INFO'                   $v.Severity 'INFO'
$idx2.Sha256[(Sha256Hex $raw)] = @{ Name = 'Fake Program Root'; Status = 'Disabled' }
$v = Resolve-RootCertTrust -Cert (New-FakeCert -Cn 'Totally Unknown Name' -Raw $raw) -Index $idx2 -AuthRootThumbs @{} -NameRx $nameRx
Assert-That 'disabled program root — tier' $v.Tier 'Distrusted'
# Windows-shipped by SHA-1.
$raw3 = [System.Text.Encoding]::ASCII.GetBytes('fake shipped root')
$c3 = New-FakeCert -Cn 'Anything' -Raw $raw3
$idx2.Sha1[$c3.Thumbprint] = @{ Name = 'Fake Shipped Root' }
Assert-That 'shipped root — tier' (Resolve-RootCertTrust -Cert $c3 -Index $idx2 -AuthRootThumbs @{} -NameRx $nameRx).Tier 'Shipped'
# Legacy: exact CN + serial AND expired. The same name, still valid, does not qualify.
$v = Resolve-RootCertTrust -Cert (New-FakeCert -Cn 'Thawte Timestamping CA' -Serial '00' -NotAfter ([datetime]'2020-12-31')) -Index $idx -AuthRootThumbs @{} -NameRx $nameRx
Assert-That 'legacy Thawte TS root (expired) — tier' $v.Tier 'Legacy'
$v = Resolve-RootCertTrust -Cert (New-FakeCert -Cn 'Thawte Timestamping CA' -Serial '00' -NotAfter ([datetime]'2030-12-31')) -Index $idx -AuthRootThumbs @{} -NameRx $nameRx
Assert-True 'legacy name but still valid — NOT legacy' ($v.Tier -ne 'Legacy')
Assert-That 'legacy name but still valid — POSSIBLE'    $v.Severity 'POSSIBLE'
$v = Resolve-RootCertTrust -Cert (New-FakeCert -Cn 'Thawte Timestamping CA' -Serial '7F' -NotAfter ([datetime]'2020-12-31')) -Index $idx -AuthRootThumbs @{} -NameRx $nameRx
Assert-True 'legacy name, wrong serial — NOT legacy' ($v.Tier -ne 'Legacy')
# AuthRoot membership vouches for a root added to the program after the snapshot.
$c5 = New-FakeCert -Cn 'New CA 2027'
$v = Resolve-RootCertTrust -Cert $c5 -Index $idx -AuthRootThumbs @{ $c5.Thumbprint = $true } -NameRx $nameRx
Assert-That 'root also in AuthRoot — tier' $v.Tier 'AuthRoot'
# Nothing vouches: POSSIBLE Unknown.
$v = Resolve-RootCertTrust -Cert (New-FakeCert -Cn 'Zqx Interception Authority') -Index $idx -AuthRootThumbs @{} -NameRx $nameRx
Assert-That 'unknown root — tier'     $v.Tier 'Unknown'
Assert-That 'unknown root — POSSIBLE' $v.Severity 'POSSIBLE'
# No data file at all: degrades, never throws.
$v = Resolve-RootCertTrust -Cert (New-FakeCert -Cn 'Zqx') -Index (@{ Sha256 = @{}; Sha1 = @{}; Legacy = @() }) -AuthRootThumbs @{} -NameRx '(?!)'
Assert-That 'empty index — still classifies' $v.Tier 'Unknown'

# ── §4. The five formerly-orphaned sets are read, and their findings are Info ─────────────
function Get-AddFindings([string]$File) {
    $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root $File), [ref]$null, [ref]$e)
    if ($e.Count) { throw "$File has parse errors" }
    $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Finding' }, $true) | ForEach-Object {
        $cmd = $_; $h = @{ Text = $cmd.Extent.Text }
        for ($i = 0; $i -lt $cmd.CommandElements.Count; $i++) {
            $el = $cmd.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and ($i + 1) -lt $cmd.CommandElements.Count) {
                $h[$el.ParameterName] = $cmd.CommandElements[$i + 1].Extent.Text
            }
        }
        [pscustomobject]$h
    }
}
$wired = @(
  @{ Var = 'TROJAN_FILE_PATTERNS';   File = 'engine/Phases-3.ps1'; Id = 'TROJNAME_' },
  @{ Var = 'AUTO_ELEVATE_BINS';      File = 'engine/Phases-3.ps1'; Id = 'AUTOELEV_' },
  @{ Var = 'EMAIL_PHISHING_TROJANS'; File = 'engine/Phases-2.ps1'; Id = $null },
  @{ Var = 'PROACTIVE_PERSIST_REGS'; File = 'engine/Phases-2.ps1'; Id = 'AUTORUNSURF_' },
  @{ Var = 'PROACTIVE_LURE_EXTS';    File = 'engine/Phases-2.ps1'; Id = 'HARDEN_LURE_' }
)
foreach ($w in $wired) {
    $lines = @((Get-Content -LiteralPath (Join-Path $root $w.File) -Encoding UTF8) | Where-Object { $_ -notmatch '^\s*#' -and $_ -match ('\$' + $w.Var + '\b') })
    Assert-True "$($w.Var) is READ by $($w.File)" ($lines.Count -ge 1)
}
$f1 = @(Get-AddFindings 'engine/Phases-1.ps1'); $f2 = @(Get-AddFindings 'engine/Phases-2.ps1'); $f3 = @(Get-AddFindings 'engine/Phases-3.ps1')
$p39 = @($f1 | Where-Object { $_.Phase -eq '"PHASE 39"' })
Assert-True 'phase 39 — has findings' ($p39.Count -ge 3)
foreach ($f in $p39) { Assert-That "phase 39 finding is Info (cert store is guard-protected): $($f.ID)" $f.FixAction '"Info"' }
foreach ($pfx in @('TROJNAME_','AUTOELEV_')) {
    $fs = @($f3 | Where-Object { $_.ID -like "*$pfx*" })
    Assert-True "$pfx finding exists" ($fs.Count -ge 1)
    foreach ($f in $fs) { Assert-That "$pfx is Info (never met a fleet)" $f.FixAction '"Info"' }
}
$fs = @($f2 | Where-Object { $_.ID -like '*AUTORUNSURF_*' })
Assert-True 'AUTORUNSURF_ finding exists' ($fs.Count -ge 1)
foreach ($f in $fs) { Assert-That 'AUTORUNSURF_ is INFO + Info' "$($f.Severity)|$($f.FixAction)" '$SEV_INFO|"Info"' }
$fs = @($f2 | Where-Object { $_.ID -like '*HARDEN_LURE_*' })
Assert-True 'HARDEN_LURE_ finding exists' ($fs.Count -ge 1)
foreach ($f in $fs) { Assert-That 'HARDEN_LURE_ severity never reaches auto-select ($phishSev is INFO or POSSIBLE)' $f.Severity '$phishSev' }
$p2 = Get-Content -LiteralPath (Join-Path $root 'engine/Phases-2.ps1') -Raw -Encoding UTF8
Assert-True '74.7 — $phishSev is INFO or POSSIBLE only' ($p2 -match '\$phishSev = if \(\$global:EMAIL_PHISH_SEEN\) \{ \$SEV_POSSIBLE \} else \{ \$SEV_INFO \}')
Assert-True '74.6 — recognises the family component, not the whole label' ($p2 -match "\^\[A-Za-z\]\+:\[A-Za-z0-9_-\]\+/\(\[A-Za-z0-9_-\]\+\)")
Assert-True '74.6 — Generic is never a phishing family' ($p2 -match 'if \(\$fam -ne ''generic''\)')
Assert-True '74.7 — HKLM autorun keys read through the 64-bit view' ($p2 -match "Get-RegNames64 -Hive 'LocalMachine' -SubKey \`$prSub")
Assert-True 'phase 92 — fails closed on a missing ExecutablePath' ((Get-Content -LiteralPath (Join-Path $root 'engine/Phases-3.ps1') -Raw -Encoding UTF8) -match 'if \(-not \$aepExe\) \{ continue \}')
Assert-True 'phase 90 — name-pattern pass carries the SIG_AUDIT budget' ((Get-Content -LiteralPath (Join-Path $root 'engine/Phases-3.ps1') -Raw -Encoding UTF8) -match '\$trojSigSeen -ge \$global:SIG_AUDIT_MAX_FILES')

# ── §5. data/trusted_root_program.json is well-formed and shipped ─────────────────────────
Assert-True 'trusted roots — 300+ program entries' (@($TRUSTED_ROOTS.program).Count -ge 300)
$badSha = @($TRUSTED_ROOTS.program | Where-Object { "$($_.sha256)" -notmatch '^[0-9A-F]{64}$' -or "$($_.sha1)" -notmatch '^[0-9A-F]{40}$' })
Assert-That 'trusted roots — every program entry has SHA-1 and SHA-256' $badSha.Count 0
$badStatus = @($TRUSTED_ROOTS.program | Where-Object { "$($_.status)" -notin @('Included','Disabled','NotBefore') })
Assert-That 'trusted roots — every status is one phase 39 handles' $badStatus.Count 0
$badShipped = @($TRUSTED_ROOTS.windows_shipped | Where-Object { "$($_.sha1)" -notmatch '^[0-9A-F]{40}$' -or -not "$($_.name)" })
Assert-That 'trusted roots — windows_shipped well-formed' $badShipped.Count 0
foreach ($lg in @($TRUSTED_ROOTS.windows_shipped_legacy)) { Assert-True "trusted roots — legacy '$($lg.cn)' is expired by design" ([datetime]::Parse("$($lg.expires_before)", [System.Globalization.CultureInfo]::InvariantCulture) -lt [datetime]'2023-01-01') }
Assert-True 'Build-Release ships data\trusted_root_program.json' ((Get-Content -LiteralPath (Join-Path $root 'tools/Build-Release.ps1') -Raw) -match 'trusted_root_program\.json')
Assert-True 'tools/Update-TrustedRoots.ps1 exists' (Test-Path -LiteralPath (Join-Path $root 'tools/Update-TrustedRoots.ps1'))
$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'tools/Update-TrustedRoots.ps1'), [ref]$null, [ref]$e)
Assert-That 'tools/Update-TrustedRoots.ps1 parses' $e.Count 0

Write-Host "`n$pass passed, $fail failed"
if ($fail) { exit 1 } else { exit 0 }
