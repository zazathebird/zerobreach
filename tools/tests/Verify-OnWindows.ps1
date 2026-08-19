<#
.SYNOPSIS
    The Windows-only half of ZeroBreach's validation — everything that CANNOT be
    checked from the Linux dev box.
.DESCRIPTION
    Run from the PROJECT ROOT, in an ELEVATED Windows PowerShell 5.1 prompt:

        powershell -NoProfile -File tools\tests\Verify-OnWindows.ps1
        powershell -NoProfile -File tools\tests\Verify-OnWindows.ps1 -Live

    Sessions 2 and 3 of the 2026-08-18 audit were written and validated entirely on
    Linux under pwsh 7.4.6. Three things were therefore never executed even once:
    the real 5.1 parser, the reports\ ACL hardening (M9), and the netsh URL ACL
    add/remove fallback (M5). This script executes them.

    SAFETY: everything runs in a fresh directory under $env:TEMP, on a free
    high-numbered port, and is cleaned up. It does NOT run a scan, does NOT
    remediate anything, and touches no registry key, service or process.
    -Live additionally starts the real server on a loopback port and stops it.

    What this script CANNOT do is at the bottom — it prints the short list of
    things that still need your eyes in a browser.
#>
[CmdletBinding()]
param(
    [switch]$Live,          # also start the real server and exercise the HTTP surface
    [switch]$SkipSuite      # skip re-running Run-SecurityTests.ps1 under this host
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $root

$pass = 0; $fail = 0; $skip = 0
function Check { param([string]$Name, [bool]$Cond)
    if ($Cond) { $script:pass++; Write-Host "  ok    $Name" -ForegroundColor DarkGray }
    else       { $script:fail++; Write-Host "  FAIL  $Name" -ForegroundColor Red } }
function SkipCheck { param([string]$Name, [string]$Why)
    $script:skip++; Write-Host "  SKIP  $Name  ($Why)" -ForegroundColor Yellow }
function Section { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }

# ══ 0. Environment ═════════════════════════════════════════════════════════════
Section '0. Environment'
$isWin = ($env:OS -eq 'Windows_NT')
if (-not $isWin) {
    Write-Host '  This script only does anything on Windows. Nothing was run.' -ForegroundColor Red
    Pop-Location; exit 2
}
$psv = $PSVersionTable.PSVersion
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ("  host        : {0} {1}" -f $PSVersionTable.PSEdition, $psv)
Write-Host ("  elevated    : {0}" -f $isAdmin)
Write-Host ("  project root: {0}" -f $root)
if ($psv.Major -ne 5) {
    Write-Host '  NOTE: the engine ships on Windows PowerShell 5.1. Re-run this under 5.1 too —' -ForegroundColor Yellow
    Write-Host '        PS 7 parse-clean is NOT 5.1 parse-clean (the whole point of section 1).' -ForegroundColor Yellow
}

# ══ 1. Parse gate on the REAL runtime ══════════════════════════════════════════
# This is the single highest-value check in the file: the (try{}catch{}) sub-expression
# and the single-element array-unwrap traps only surface on the 5.1 parser/runtime.
Section '1. Parse + BOM on this host''s parser'
$shipped = @(
    'ZeroBreach-Server.ps1','ZeroBreach-V23.ps1',
    'engine\Phases-1.ps1','engine\Phases-2.ps1','engine\Phases-3.ps1',
    'engine\Summary.ps1','engine\FixMode.ps1'
)
foreach ($f in $shipped) {
    $p = Join-Path $root $f
    if (-not (Test-Path -LiteralPath $p)) { Check "$f exists" $false; continue }
    $bytes = [System.IO.File]::ReadAllBytes($p)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    Check "$f UTF-8 BOM intact" $bom
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count) {
        Check "$f parses on $psv" $false
        $errs | Select-Object -First 3 | ForEach-Object {
            Write-Host ("        line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) -ForegroundColor Red }
    } else { Check "$f parses on $psv" $true }
}

# ParseFile on the server does NOT reach the runspace here-strings — parse them too.
$srv = Get-Content (Join-Path $root 'ZeroBreach-Server.ps1') -Raw
$sAst = [System.Management.Automation.Language.Parser]::ParseInput($srv, [ref]$null, [ref]$null)
$hereAssigns = $sAst.FindAll({
    param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
              $n.Right.Extent.Text -like "@'*"
}, $true)
Check 'found the 3 runspace here-strings' ($hereAssigns.Count -ge 3)
foreach ($a in $hereAssigns) {
    $b = $a.Right.Extent.Text.Substring(2)
    $b = $b.Substring(0, $b.LastIndexOf("'@"))
    $ee = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($b, [ref]$null, [ref]$ee)
    Check ("{0} parses on {1}" -f $a.Left.Extent.Text, $psv) (-not ($ee -and $ee.Count))
}

# ══ 2. The Linux-side suite, re-run on this host ═══════════════════════════════
Section '2. Security regression suite under this host'
if ($SkipSuite) { SkipCheck 'Run-SecurityTests.ps1' '-SkipSuite' }
else {
    $out = & (Get-Process -Id $PID).Path -NoProfile -File (Join-Path $PSScriptRoot 'Run-SecurityTests.ps1') 2>&1
    $ok = ($LASTEXITCODE -eq 0)
    Check 'all regression tests pass on this host' $ok
    if (-not $ok) { $out | Select-Object -Last 25 | ForEach-Object { Write-Host "        $_" } }
}

# ══ 3. M9 — reports\ ACL hardening (NEVER executed before) ═════════════════════
Section '3. M9  Protect-ReportsDirectory round-trip (scratch dir)'
# Lift the real function out of the shipped server rather than retyping it.
$fnAst = $sAst.FindAll({
    param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
              $n.Name -in @('Protect-ReportsDirectory','Remove-OldServerLogs')
}, $true)
foreach ($f in $fnAst) { . ([scriptblock]::Create($f.Extent.Text)) }
Check 'Protect-ReportsDirectory extracted' ((Get-Command Protect-ReportsDirectory -EA SilentlyContinue) -ne $null)

$acDir = Join-Path $env:TEMP ("zb_acl_" + [Guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $acDir -Force | Out-Null
try {
    # Give BUILTIN\Users an explicit Modify ALLOW — the exact rule M9 exists to downgrade.
    $usersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $a0 = Get-Acl -LiteralPath $acDir
    $a0.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $usersSid, 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    Set-Acl -LiteralPath $acDir -AclObject $a0

    $before = @((Get-Acl -LiteralPath $acDir).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        "$($_.IdentityReference)" -match 'Users' -and
        ([int]$_.FileSystemRights -band [int][System.Security.AccessControl.FileSystemRights]::Modify) -ne 0 })
    Check 'scratch dir starts with a non-admin WRITE rule' ($before.Count -ge 1)

    $reason = Protect-ReportsDirectory -Path $acDir
    Check ("Protect-ReportsDirectory returned no error" + $(if($reason){" (got: $reason)"}else{''})) ($reason -eq '')

    $acl = Get-Acl -LiteralPath $acDir
    Check 'inheritance is now broken (SetAccessRuleProtection)' ($acl.AreAccessRulesProtected)

    $R = [System.Security.AccessControl.FileSystemRights]
    $writeMask = [int]($R::Write -bor $R::Modify -bor $R::FullControl -bor $R::Delete -bor
                       $R::DeleteSubdirectoriesAndFiles -bor $R::ChangePermissions -bor $R::TakeOwnership)
    $keep = @('S-1-5-18','S-1-5-32-544','S-1-3-0')
    $leftWritable = @($acl.Access | Where-Object {
        if ($_.AccessControlType -ne 'Allow') { return $false }
        $sid = ''
        try { $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = "$($_.IdentityReference)" }
        if ($keep -contains $sid) { return $false }
        (([int]$_.FileSystemRights) -band $writeMask) -ne 0 })
    Check 'no non-admin ALLOW rule keeps any write right' ($leftWritable.Count -eq 0)
    if ($leftWritable.Count) { $leftWritable | ForEach-Object { Write-Host ("        still writable: {0} = {1}" -f $_.IdentityReference, $_.FileSystemRights) -ForegroundColor Red } }

    $stillRead = @($acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and "$($_.IdentityReference)" -match 'Users' -and
        (([int]$_.FileSystemRights) -band [int]$R::ReadAndExecute) -ne 0 })
    # READ must survive: the operator opens exported reports from reports\ unelevated.
    Check 'non-admin READ access survives the lockdown' ($stillRead.Count -ge 1)

    Check 'SYSTEM / Administrators are untouched' (@($acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and (([int]$_.FileSystemRights) -band $writeMask) -ne 0 }).Count -ge 1)
} catch {
    Check "ACL round-trip threw: $($_.Exception.Message)" $false
} finally {
    Remove-Item -LiteralPath $acDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ══ 4. M10 — per-launch log retention ══════════════════════════════════════════
Section '4. M10  Remove-OldServerLogs retention'
$lgDir = Join-Path $env:TEMP ("zb_log_" + [Guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $lgDir -Force | Out-Null
try {
    $t0 = Get-Date
    foreach ($pat in @('server_console_','server_events_')) {
        for ($i = 0; $i -lt 25; $i++) {
            $p = Join-Path $lgDir ("{0}{1:d2}.log" -f $pat, $i)
            Set-Content -LiteralPath $p -Value "x" -Encoding ASCII
            (Get-Item -LiteralPath $p).LastWriteTime = $t0.AddMinutes(-$i)   # 00 = newest
        }
    }
    Set-Content -LiteralPath (Join-Path $lgDir 'KrakenBaseline_keepme.json') -Value '{}' -Encoding ASCII
    $removed = Remove-OldServerLogs -Path $lgDir -Keep 20
    Check 'pruner removed exactly 10 (5 of each pattern over the cap)' ($removed -eq 10)
    Check 'console logs left = 20' (@(Get-ChildItem -LiteralPath $lgDir -Filter 'server_console_*.log').Count -eq 20)
    Check 'events  logs left = 20' (@(Get-ChildItem -LiteralPath $lgDir -Filter 'server_events_*.log').Count -eq 20)
    Check 'the NEWEST log survived'  (Test-Path -LiteralPath (Join-Path $lgDir 'server_console_00.log'))
    Check 'the OLDEST log was culled' (-not (Test-Path -LiteralPath (Join-Path $lgDir 'server_console_24.log')))
    Check 'non-log files are never touched' (Test-Path -LiteralPath (Join-Path $lgDir 'KrakenBaseline_keepme.json'))
    Check '-KeepLogs 0 disables pruning entirely' ((Remove-OldServerLogs -Path $lgDir -Keep 0) -eq 0)
} catch {
    Check "log retention threw: $($_.Exception.Message)" $false
} finally {
    Remove-Item -LiteralPath $lgDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ══ 5. Listener bind + M5 URL ACL round-trip (NEVER executed before) ═══════════
Section '5. C1/M5  HttpListener bind + temporary URL ACL'
function Get-TestPort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop(); $p
}
$port = Get-TestPort
$prefix = "http://127.0.0.1:$port/"
$hl = [System.Net.HttpListener]::new()
$hl.Prefixes.Add($prefix)
$bound = $false
try { $hl.Start(); $bound = $true } catch { }
Check "binds $prefix without a reservation" $bound
if ($bound) { try { $hl.Stop(); $hl.Close() } catch {} }

if (-not $isAdmin) { SkipCheck 'netsh http add/delete urlacl' 'needs an elevated prompt' }
else {
    $aclPort = Get-TestPort
    $aclUrl  = "http://127.0.0.1:$aclPort/"
    $addOut = (& netsh http add urlacl url=$aclUrl "user=$env:USERDOMAIN\$env:USERNAME" 2>&1) -join ' '
    $added  = ($LASTEXITCODE -eq 0)
    Check "netsh http add urlacl succeeds ($aclUrl)" $added
    if (-not $added) { Write-Host "        $addOut" -ForegroundColor Red }
    else {
        $show = (& netsh http show urlacl url=$aclUrl 2>&1) -join ' '
        Check 'the reservation is really there' ($show -match [regex]::Escape($aclUrl))
        $delOut = (& netsh http delete urlacl url=$aclUrl 2>&1) -join ' '
        Check 'netsh http delete urlacl succeeds' ($LASTEXITCODE -eq 0)
        if ($LASTEXITCODE -ne 0) { Write-Host "        $delOut" -ForegroundColor Red }
        $show2 = (& netsh http show urlacl url=$aclUrl 2>&1) -join ' '
        # M5: nothing may be left behind on a client machine.
        Check 'nothing is left behind afterwards' (-not ($show2 -match [regex]::Escape($aclUrl)))
    }
}

# ══ 6. -Live: the real server over HTTP ════════════════════════════════════════
if (-not $Live) {
    Section '6. Live server surface'
    SkipCheck 'token auth / Origin / IOC validation over HTTP' 're-run with -Live'
} else {
    Section '6. Live server surface (-Live)'
    $livePort = Get-TestPort
    $logOut = Join-Path $env:TEMP ("zb_live_{0}.out" -f $livePort)
    $logErr = Join-Path $env:TEMP ("zb_live_{0}.err" -f $livePort)
    $proc = Start-Process -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @('-NoProfile','-File', (Join-Path $root 'ZeroBreach-Server.ps1'),
                        '-NoBrowser','-Port', $livePort) `
        -RedirectStandardOutput $logOut -RedirectStandardError $logErr `
        -WindowStyle Hidden -PassThru
    try {
        # The server prints http://127.0.0.1:PORT/?t=<64 hex>. Wait for it.
        $token = ''
        for ($i = 0; $i -lt 60 -and -not $token; $i++) {
            Start-Sleep -Milliseconds 500
            $txt = Get-Content -LiteralPath $logOut -Raw -ErrorAction SilentlyContinue
            $m = [regex]::Match("$txt", '\?t=([0-9a-fA-F]{16,})')
            if ($m.Success) { $token = $m.Groups[1].Value }
        }
        Check 'server started and printed a launch token' ($token -ne '')
        Check 'the token is 64 hex chars (RNGCryptoServiceProvider, not Get-Random)' ($token.Length -eq 64)

        function Try-Get {
            param([string]$Path, [hashtable]$Headers = @{})
            try {
                $r = Invoke-WebRequest -Uri ("http://127.0.0.1:$livePort" + $Path) -Headers $Headers `
                     -UseBasicParsing -TimeoutSec 10
                return [int]$r.StatusCode
            } catch {
                if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
                return -1
            }
        }
        if ($token) {
            Check 'static page loads WITHOUT a token (so it can explain itself)' ((Try-Get '/') -eq 200)
            Check '/api/state without a token is refused'                        ((Try-Get '/api/state') -eq 401)
            Check '/api/state WITH the token is served'                          ((Try-Get "/api/state?t=$token") -eq 200)
            Check 'a foreign Origin is refused even with the token' `
                ((Try-Get "/api/state?t=$token" @{ Origin = 'http://evil.example' }) -ne 200)
            Check 'a bad token is refused'                                       ((Try-Get '/api/state?t=deadbeef') -eq 401)

            # M6 — IOC ingestion must REFUSE (never strip) injected line breaks, and
            # must refuse a catastrophically-backtracking regex before it reaches a scan.
            $body = @{ hashes = @(); ips = @(); domains = @("good.example`r`nregex:.*"); regexes = @('(a+)+$'); files = @() } | ConvertTo-Json
            try {
                $r = Invoke-WebRequest -Uri "http://127.0.0.1:$livePort/api/ioc?t=$token" -Method POST `
                     -Body $body -ContentType 'application/json' -UseBasicParsing -TimeoutSec 15
                $j = $r.Content | ConvertFrom-Json
                $txt = "$($r.Content)"
                Check 'IOC POST answers rather than hanging' ($r.StatusCode -eq 200)
                Check 'the CRLF-injected domain is refused, not silently stripped' ($txt -notmatch 'regex:\.\*')
                Check 'the refusal is reported back to the operator' ($txt -match 'reject|refus|invalid')
            } catch {
                Check "IOC POST failed: $($_.Exception.Message)" $false
            }

            # M11 — a report name outside reports\ must never be honoured.
            try {
                $r = Invoke-WebRequest -Uri "http://127.0.0.1:$livePort/api/report?name=..\..\Windows\win.ini&t=$token" `
                     -UseBasicParsing -TimeoutSec 10
                Check 'path traversal on /api/report is refused' ($r.StatusCode -ne 200)
            } catch { Check 'path traversal on /api/report is refused' $true }
        }
    } finally {
        if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 800
        $tail = Get-Content -LiteralPath $logOut -Raw -ErrorAction SilentlyContinue
        if ("$tail" -match 'Could NOT remove the URL ACL') {
            Write-Host '  FAIL  server left a URL ACL behind — remove it by hand (see its output)' -ForegroundColor Red
            $fail++
        }
        Write-Host ("  server stdout: {0}" -f $logOut) -ForegroundColor DarkGray
    }
}

# ══ Summary + what a script cannot check ═══════════════════════════════════════
Write-Host ''
Write-Host ("{0} passed, {1} failed, {2} skipped" -f $pass, $fail, $skip) -ForegroundColor $(if($fail){'Red'}else{'Green'})

Section 'STILL NEEDS YOUR EYES — a script cannot check these'
@(
 '1.  Launch-GUI.bat -> GUI loads, NO orange "LAUNCH TOKEN MISSING" overlay.'
 '    Opening bare http://127.0.0.1:PORT/ (no ?t=) SHOULD show it.'
 '2.  CSP breaks nothing visually: themes, VFX tiers, the kraken cinematic, PURGE modal.'
 '    Anything blocked is named by directive in the browser console.'
 '3.  QUICK scan: counter runs 1..30 and stops at 30/30; phases advance; scan_complete fires.'
 '4.  Rename ZeroBreach-V23.ps1 briefly -> red "SCAN DID NOT COMPLETE" panel, NOT a green'
 '    all-clear. (H2 — the worst bug an IR tool can ship.)'
 '5.  Drop the CLAUDE.md tripwires -> FULL scan -> FINDINGS -> REMEDIATION -> type PURGE.'
 '    Protected targets must show as blocked and be un-tickable.'
 '6.  reports\KrakenSnapshot_<stamp>\Restore.cmd is generated and imports cleanly.'
 '7.  Open an exported HTML report from reports\ in a NON-elevated Explorer (read must'
 '    survive the M9 lockdown), and confirm Export CSV / search / filters / sorting work.'
 '8.  Remediate a report, edit that report on disk, remediate again -> 409 "report modified".'
 '9.  STEALTH mode still parses the compressed audit blob.'
 '10. Startup prints: reports\ ACL line (if any), log-retention line, quarantine footprint —'
 '    none of them erroring.'
) | ForEach-Object { Write-Host "  $_" }

Pop-Location
if ($fail) { exit 1 }
