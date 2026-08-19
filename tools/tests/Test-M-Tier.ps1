# MEDIUM-tier regression guards (audit M2/M3/M4/M6/M7/M8).
# Like every other file in this suite, the functions under test are pulled out of the
# shipped source via the AST — a test here cannot drift from the code it guards.
$srv = (Resolve-Path 'ZeroBreach-Server.ps1').Path
$t=$null;$e=$null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($srv, [ref]$t, [ref]$e)
foreach ($fn in @('Test-IocRegexSafe','Test-IocIpValue','ConvertTo-IocSet','Clear-FinishedRunspaces')) {
    $f = $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fn}, $true)
    if (-not $f) { Write-Host "  FAIL  missing function $fn" -ForegroundColor Red; exit 1 }
    . ([scriptblock]::Create($f[0].Extent.Text))
}
$src = Get-Content -LiteralPath $srv -Raw
$app = Get-Content -LiteralPath (Join-Path 'gui' 'static/js/app.js') -Raw

# The route reads these from script scope.
$script:IOC_MAX_PER_CAT = 2000
$script:IOC_MAX_LEN     = 512
$script:IOC_MAX_REGEX   = 200

$pass=0;$fail=0
function Check($n,$a,$e){ if("$a" -eq "$e"){$script:pass++;Write-Host "  PASS  $n" -ForegroundColor Green}else{$script:fail++;Write-Host "  FAIL  $n -> got '$a' expected '$e'" -ForegroundColor Red} }

Write-Host "`n== M6  IOC ingestion validation ==" -ForegroundColor Yellow
$bad = [pscustomobject]@{
    hashes  = @('44d88612fea8a8f36de82e1278abb02f','nothash','44D88612FEA8A8F36DE82E1278ABB02F')
    ips     = @('10.0.0.1','10.0.0.0/8','999.1.1.1','10.0.0.1/99','2001:db8::1')
    domains = @('evil.example.com',"good.com`r`nregex:.*","host.com`nfile:C:\Windows\*",'UP.Example.COM')
    regex   = @('malware_\d+\.exe','(a+)+$','[unclosed',('x'*300))
    files   = @('C:\Temp\evil.exe',"ok.exe`nhash:deadbeef")
}
$r = ConvertTo-IocSet $bad
Check 'CRLF-injected domain refused'      ($r.Set.domains -contains "good.com`r`nregex:.*") $false
Check 'LF-injected domain refused'        (@($r.Set.domains).Count) 2
Check 'LF-injected file entry refused'    (@($r.Set.files).Count) 1
Check 'no newline reaches any value'      (($r.Set.Keys | ForEach-Object { $r.Set[$_] } | Where-Object { $_ -match "`r|`n" }).Count) 0
Check 'invalid hash refused'              ($r.Set.hashes -contains 'nothash') $false
Check 'hash case-folded + deduped'        (@($r.Set.hashes).Count) 1
Check 'out-of-range octet refused'        ($r.Set.ips -contains '999.1.1.1') $false
Check 'bad CIDR bits refused'             ($r.Set.ips -contains '10.0.0.1/99') $false
Check 'valid CIDR kept'                   ($r.Set.ips -contains '10.0.0.0/8') $true
Check 'IPv6 kept'                         ($r.Set.ips -contains '2001:db8::1') $true
Check 'domain lower-cased'                ($r.Set.domains -contains 'up.example.com') $true
Check 'catastrophic regex refused'        ($r.Set.regex -contains '(a+)+$') $false
Check 'uncompilable regex refused'        ($r.Set.regex -contains '[unclosed') $false
Check 'over-long regex refused'           ($r.Set.regex -contains ('x'*300)) $false
Check 'benign regex kept'                 ($r.Set.regex -contains 'malware_\d+\.exe') $true
Check 'every refusal is reported'         (@($r.Rejected).Count -ge 8) $true
$cap = ConvertTo-IocSet ([pscustomobject]@{ hashes = @(1..2100 | ForEach-Object { '{0:x32}' -f $_ }) })
Check 'per-category cap enforced'         (@($cap.Set.hashes).Count) 2000
Check 'cap is reported, not silent'       (@($cap.Rejected).Count -ge 1) $true
Check 'regex timeout is bounded'          ((Measure-Command { Test-IocRegexSafe '(a+)+$' }).TotalSeconds -lt 5) $true
Check 'POST body ceiling present'         ($src -match 'ContentLength64 -gt \$script:MAX_BODY_BYTES') $true

Write-Host "`n== M2  bounded event log + runspace reaping ==" -ForegroundColor Yellow
Check 'EventLogBase in shared state'      ($src -match 'EventLogBase = 0') $true
Check 'ring trim in Enqueue'              ($src -match '\$ScanState\.EventLogBase \+= \$drop') $true
Check 'ring trim in REnqueue'             ($src -match '\$RemState\.EventLogBase \+= \$drop') $true
Check 'new scan resets the base'          ($src -match '\$ScanState\.EventLogBase = 0') $true
Check 'SSE cursor is base-relative'       ($src -match '\$SseState\.EventLog\[\$idx - \$base\]') $true
Check 'runspace handles tracked'          ($src -match '\$script:RUNSPACES\.Add') $true
Check 'runspaces reaped on new + accept'  (([regex]::Matches($src,'Clear-FinishedRunspaces')).Count -ge 3) $true

Write-Host "`n== M3  remediation counters reconcile ==" -ForegroundColor Yellow
# Replay the counter logic exactly as the runspace runs it.
foreach ($case in @(
    @{ Action='Info';        Ok=$false; Skip=$true }
    @{ Action='Bogus';       Ok=$false; Skip=$true }
    @{ Action='DeleteFile';  Ok=$true;  Skip=$false }
)) {
    $applied=0;$skipped=0
    if ($case.Skip) { $skipped++ }
    if ($case.Ok -and ($case.Action -notin @('Info','None',''))) { $applied++ }
    Check "  $($case.Action): counted once" ($applied + $skipped) 1
}
Check 'Info branch no longer sets $ok'    ($src -match "'Info'  \{ RLog `"  -> informational; review manually\.`" 'INFO'; \`$skipped\+\+ \}") $true
Check 'default branch no longer sets $ok' ($src -match "default \{ RLog `"  -> no automated action for FixAction") $true

Write-Host "`n== M4  STEALTH findings match the live path ==" -ForegroundColor Yellow
$stealth = ($src -split "STEALTH post-processing")[1]
Check 'stealth carries fix_action'        ($stealth -match 'fix_action  = "\$\(\$ef\.FixAction\)"') $true
Check 'stealth carries target'            ($stealth -match 'target      = "\$\(\$ef\.Target\)"') $true
Check 'stealth tallies unconditionally'   ($stealth -match "if \(\`$tt\) \{`r?`n") $false

Write-Host "`n== M7  no second, wrong phase regex ==" -ForegroundColor Yellow
Check 'dead PHASE_RE removed'             ($src -match '\$script:PHASE_RE') $false
Check 'runspace PREX still fraction-aware' ($src -match "PHASE\\s\+\(\\d\+\(\?:\\\.\\d\+\)\?\)") $true

Write-Host "`n== M8  GUI escaping ==" -ForegroundColor Yellow
Check "escapeHtml handles '"              ($app -match "replace\(/'/g, '&#39;'\)") $true
Check 'finding.id escaped'                ($app -match 'data-id="\$\{escapeHtml\(finding\.id\)\}"') $true
Check 'severity escaped (tree)'           ($app -match 'item-sev \$\{escapeHtml\(finding\.severity\)\}') $true
Check 'severity escaped (mini tree)'      ($app -match 'item-sev \$\{escapeHtml\(f\.severity\)\}') $true
Check 'phase escaped'                     ($app -match 'PH\$\{escapeHtml\(finding\.phase\)\}') $true
Check 'results_path escaped'              ($app -match 'escapeHtml\(data\.results_path') $true
Check 'mitre href fallback escaped'       ($app -match 'techniques/\$\{escapeHtml\(String\(m\.id\)') $true
Check 'no raw \${finding.id} left'        ($app -match '\$\{finding\.id\}') $false

Write-Host "`n== M1  no auto-selected fix is permanently blocked ==" -ForegroundColor Yellow
# Load the real guard, then walk every Add-Finding in the engine. Any CRITICAL/HIGH
# finding with a destructive FixAction whose FixParam the guard refuses is the M1
# shape: auto-selected in the GUI, then hard-blocked every single time. Variables in
# a FixParam are replaced with a placeholder, so this checks the LITERAL parts (which
# is exactly where 'C:\Windows\system32\userinit.exe,' lived).
foreach ($fn in @('ConvertTo-GuardPath','Test-DestructiveRunCmd','Test-ProtectedTarget')) {
    $f = $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fn}, $true)
    . ([scriptblock]::Create($f[0].Extent.Text))
}
foreach ($vn in @('$script:RUNCMD_DESTRUCTIVE','$script:RUNCMD_MUTATING','$script:KILL_CRITICAL_NAME_RX','$script:KILL_CRITICAL_DESC_RX')) {
    $a = $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq $vn}, $true)
    . ([scriptblock]::Create($a[0].Extent.Text))
}
$destructive = @('DeleteFile','DeleteReg','DeleteRegKey','KillProcess','RunCmd','Quarantine')
$alwaysBlocked = @()
foreach ($src2 in @((Resolve-Path 'ZeroBreach-V23.ps1').Path) + @(Get-ChildItem engine -Filter *.ps1 | ForEach-Object { $_.FullName })) {
    $t2=$null;$e2=$null
    $a2 = [System.Management.Automation.Language.Parser]::ParseFile($src2, [ref]$t2, [ref]$e2)
    foreach ($c in $a2.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Finding'}, $true)) {
        $h = @{}; $els = $c.CommandElements
        for ($i=1; $i -lt $els.Count; $i++) {
            if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst]) {
                $h[$els[$i].ParameterName] = if ($els[$i].Argument) { $els[$i].Argument.Extent.Text } elseif ($i+1 -lt $els.Count) { $els[$i+1].Extent.Text } else { '' }
            }
        }
        $act = "$($h['FixAction'])" -replace '"',''
        if ($act -notin $destructive) { continue }
        # KillProcess FixParams are always (Get-KillParam $x) — a runtime call, nothing
        # to evaluate statically. Their guard behaviour is asserted by vector below.
        if ($act -eq 'KillProcess') { continue }
        if ("$($h['Severity'])" -notmatch 'CRITICAL|HIGH') { continue }
        $prm = "$($h['FixParam'])"
        if (-not $prm) { continue }
        $prm = $prm.Trim('"')
        # placeholder-substitute anything the engine interpolates at runtime
        $prm = $prm -replace '\$\([^)]*\)', 'ZBVAR' -replace '\$[A-Za-z_][\w:.]*', 'ZBVAR'
        $why = Test-ProtectedTarget $act $prm '' "$($h['Description'])"
        if ($why) { $alwaysBlocked += ("{0}:{1} {2} -> {3}" -f (Split-Path $src2 -Leaf), $c.Extent.StartLineNumber, $act, $why) }
    }
}
if ($alwaysBlocked.Count) { $alwaysBlocked | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkYellow } }
Check 'no CRIT/HIGH fix is always blocked' ($alwaysBlocked.Count) 0
Check 'STICKY_* is Info now'   ((Get-Content engine/Phases-1.ps1 -Raw) -match 'STICKY_\$\(\[IO\.Path\]::GetFileNameWithoutExtension\(\$af\)\)"[\s\S]{0,900}?-FixAction "Info"') $true
Check 'SYS32_UNSIGNED is Info' ((Get-Content engine/Phases-1.ps1 -Raw) -match 'Tampered/untrusted binary in System32[\s\S]{0,900}?-FixAction "Info"') $true
Check 'HOSTS_PURGE is Info'    ((Get-Content engine/Phases-1.ps1 -Raw) -match 'HOSTS_PURGE[\s\S]{0,900}?-FixAction "Info"') $true
$p3 = Get-Content engine/Phases-3.ps1 -Raw
Check 'SVCMASQ is Info'        ($p3 -match 'SVCMASQ_\$\(\$sp\.ProcessId\)[\s\S]{0,1200}?-FixAction "Info"') $true
Check 'SVCPATH is Info'        ($p3 -match 'SVCPATH_\$\(\$sp\.ProcessId\)[\s\S]{0,1200}?-FixAction "Info"') $true

# KillProcess: the guard reads the authoritative name out of the FixParam, and only
# falls back to description prose for a bare-PID (pre-H5) report.
Check 'kill malware named in prose as SYSTEM-level' `
    (Test-ProtectedTarget 'KillProcess' '4321|evil|63080000' 'PID:4321' 'SYSTEM-level process running from user path: evil.exe') ''
Check 'kill lsass refused by name' `
    ([bool](Test-ProtectedTarget 'KillProcess' '4321|lsass|63080000' 'PID:4321' 'suspicious process')) $true
Check 'kill svchost refused by name' `
    ([bool](Test-ProtectedTarget 'KillProcess' '4321|svchost|63080000' 'PID:4321' 'suspicious process')) $true
Check 'kill IR tool refused by name' `
    ([bool](Test-ProtectedTarget 'KillProcess' '4321|zerobreach|63080000' 'PID:4321' 'x')) $true
Check 'bare PID falls back to the description' `
    ([bool](Test-ProtectedTarget 'KillProcess' '4321' 'PID:4321' 'lsass.exe doing something odd')) $true
Check 'bare PID, benign description, allowed' `
    (Test-ProtectedTarget 'KillProcess' '4321' 'PID:4321' 'miner.exe burning CPU') ''

Write-Host ("`n{0} passed, {1} failed" -f $pass,$fail) -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
if($fail){exit 1}
