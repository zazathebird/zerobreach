Stop-PhaseTiming   # close out the final phase's wall-clock
$elapsed    = [Math]::Round(((Get-Date) - $global:START_TIME).TotalMinutes, 2)
$phaseCount = $PhasePlan.Max
$totalRisk  = $global:RansomwareRisk + ($global:RootkitHits * 3) + ($global:RATHits * 2) +
              $global:KeyloggerHits + $global:MinerHits + ($global:WormHits / 5) + ($global:SpywareHits / 3) +
              ($global:TrojanHits * 2) + ($global:BackdoorHits * 3) + ($global:UACBypassHits * 2)
$totalRisk  = [Math]::Round($totalRisk, 0)
$riskLabel  = if ($totalRisk -gt 20) { "CRITICAL — IMMEDIATE ESCALATION" } `
              elseif ($totalRisk -gt 10) { "HIGH — SIGNIFICANT COMPROMISE INDICATORS" } `
              elseif ($totalRisk -gt 3)  { "MEDIUM — INVESTIGATE FINDINGS" } `
              else { "LOW — SYSTEM APPEARS RELATIVELY CLEAN" }
$riskColor  = if ($totalRisk -gt 20) { "Red" } elseif ($totalRisk -gt 10) { "DarkYellow" } elseif ($totalRisk -gt 3) { "Yellow" } else { "Green" }

$findingCount  = $global:AuditFindings.Count
$critCount     = ($global:AuditFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$highCount     = ($global:AuditFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
$possibleCount = ($global:AuditFindings | Where-Object { $_.Severity -eq "POSSIBLE" }).Count
$infoCount     = ($global:AuditFindings | Where-Object { $_.Severity -eq "INFO" }).Count

# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT SUMMARY REPORT
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host ("▓"*80) -ForegroundColor DarkCyan
Write-Host "  ◈◈◈  P R O J E C T   K R A K E N   V 2 2   ·   A U D I T   C O M P L E T E  ◈◈◈" -ForegroundColor Cyan
Write-Host ("▓"*80) -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  MODE      : " -NoNewline -ForegroundColor DarkGray; Write-Host "$($global:ScanMode) ($phaseCount phases)" -ForegroundColor (Get-AccentColor)
Write-Host "  TIME WINDOW       : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:TW_LABEL -ForegroundColor Yellow
Write-Host "  HOST / OPERATOR   : " -NoNewline -ForegroundColor DarkGray; Write-Host "$USER_NAME @ $HOST_NAME" -ForegroundColor DarkGray
Write-Host "  ELAPSED           : " -NoNewline -ForegroundColor DarkGray; Write-Host "$elapsed Minutes" -ForegroundColor DarkGray
Write-Host ""
Write-Host ("─"*80) -ForegroundColor DarkCyan
Write-Host "  THREAT TALLY:" -ForegroundColor Yellow
Write-Host "  Ransomware Risk   : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:RansomwareRisk -ForegroundColor $(if ($global:RansomwareRisk -gt 5) { "Red" } elseif ($global:RansomwareRisk -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Rootkit Hits      : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:RootkitHits    -ForegroundColor $(if ($global:RootkitHits -gt 0) { "Red" } else { "Green" })
Write-Host "  RAT / C2 Hits     : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:RATHits        -ForegroundColor $(if ($global:RATHits -gt 0) { "Red" } else { "Green" })
Write-Host "  Keylogger Hits    : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:KeyloggerHits  -ForegroundColor $(if ($global:KeyloggerHits -gt 0) { "Red" } else { "Green" })
Write-Host "  Miner Hits        : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:MinerHits      -ForegroundColor $(if ($global:MinerHits -gt 0) { "Red" } else { "Green" })
Write-Host "  Worm Hits         : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:WormHits       -ForegroundColor $(if ($global:WormHits -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Spyware/Adware    : " -NoNewline -ForegroundColor DarkGray; Write-Host $global:SpywareHits    -ForegroundColor $(if ($global:SpywareHits -gt 0) { "Yellow" } else { "Green" })
Write-Host ("─"*80) -ForegroundColor DarkCyan
Write-Host "  FINDINGS SUMMARY:" -ForegroundColor Yellow
Write-Host "  CRITICAL          : " -NoNewline -ForegroundColor DarkGray; Write-Host $critCount     -ForegroundColor $(if ($critCount -gt 0) { "Red" } else { "Green" })
Write-Host "  HIGH              : " -NoNewline -ForegroundColor DarkGray; Write-Host $highCount     -ForegroundColor $(if ($highCount -gt 0) { "DarkYellow" } else { "Green" })
Write-Host "  POSSIBLE          : " -NoNewline -ForegroundColor DarkGray; Write-Host $possibleCount -ForegroundColor $(if ($possibleCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  INFO / HARDENING  : " -NoNewline -ForegroundColor DarkGray; Write-Host $infoCount     -ForegroundColor DarkGray
Write-Host "  TOTAL FINDINGS    : " -NoNewline -ForegroundColor DarkGray; Write-Host $findingCount  -ForegroundColor Yellow
Write-Host ("─"*80) -ForegroundColor DarkCyan
Write-Host "  COMPOSITE RISK    : " -NoNewline -ForegroundColor DarkGray
Write-Host "$totalRisk — $riskLabel" -ForegroundColor $riskColor
Write-Host ("▓"*80) -ForegroundColor DarkCyan

# ── Per-phase profiling summary (slowest phases first) ────────────────────────
if ($global:PHASE_TIMINGS.Count -gt 0) {
    $slowest = $global:PHASE_TIMINGS | Sort-Object -Property Seconds -Descending | Select-Object -First 10
    $sumSecs = [Math]::Round((($global:PHASE_TIMINGS | Measure-Object -Property Seconds -Sum).Sum), 1)
    Write-Host ("─"*80) -ForegroundColor DarkCyan
    Write-Host "  PHASE TIMING — 10 SLOWEST (of $($global:PHASE_TIMINGS.Count) phases, $sumSecs s total):" -ForegroundColor Yellow
    foreach ($t in $slowest) {
        $tc = if ($t.Seconds -gt 10) { "Red" } elseif ($t.Seconds -gt 3) { "Yellow" } else { "DarkGray" }
        Write-Host ("  {0,6:N1}s  " -f $t.Seconds) -NoNewline -ForegroundColor $tc
        Write-Host $t.Phase -ForegroundColor DarkGray
    }
    Write-Host ("▓"*80) -ForegroundColor DarkCyan
}

# ── Resilience summary — errors the scan recovered from and continued past ─────
if ($global:RECOVERED_ERRORS.Count -gt 0) {
    Write-Host ("─"*80) -ForegroundColor DarkYellow
    Write-Host "  RESILIENCE — $($global:RECOVERED_ERRORS.Count) error(s) recovered (scan continued, see log):" -ForegroundColor DarkYellow
    foreach ($re in ($global:RECOVERED_ERRORS | Select-Object -First 15)) {
        Write-Host ("  [!] " + $re) -ForegroundColor DarkGray
    }
    if ($global:RECOVERED_ERRORS.Count -gt 15) { Write-Host "  ... and $($global:RECOVERED_ERRORS.Count - 15) more in the log." -ForegroundColor DarkGray }
    Write-Host ("▓"*80) -ForegroundColor DarkCyan
}

# Save audit cache
$auditCache = @{
    Timestamp     = (Get-Date).ToString("o")
    Host          = $HOST_NAME
    User          = $USER_NAME
    Mode          = $global:ScanMode
    TimeWindow    = $global:TW_LABEL
    RiskScore     = $totalRisk
    RiskLabel     = $riskLabel
    Paranoid      = $global:PARANOID_MODE
    Stealth       = $global:STEALTH_MODE
    Findings      = @($global:AuditFindings)
    PhaseTimings  = @($global:PHASE_TIMINGS)
    RecoveredErrors = @($global:RECOVERED_ERRORS)
    BaselineDelta = @($global:BaselineDelta)
    ThreatTally   = @{
        RAT=       $global:RATHits;      Rootkit=   $global:RootkitHits
        Ransomware=$global:RansomwareRisk;Keylogger= $global:KeyloggerHits
        Miner=     $global:MinerHits;    Worm=      $global:WormHits
        Spyware=   $global:SpywareHits;  Trojan=    $global:TrojanHits
        Backdoor=  $global:BackdoorHits; UACBypass= $global:UACBypassHits
    }
}
# UTF-8 *without* BOM, via .NET so it's identical on PS 5.1 and 7 and safe for any
# JSON parser. (5.1's -Encoding utf8 adds a BOM; 'utf8BOM' isn't valid on 5.1.)
$auditJson = $auditCache | ConvertTo-Json -Depth 5
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
try { [System.IO.File]::WriteAllText($AUDIT_JSON,    $auditJson, $utf8NoBom) } catch {}
try { [System.IO.File]::WriteAllText($BASELINE_PATH, $auditJson, $utf8NoBom) } catch {}

# Write TXT log
$LOG_LINES.Insert(0, "ZEROBREACH V22 | $HOST_NAME | $(Get-Date) | $($global:ScanMode) | $($global:TW_LABEL) | PARANOID:$($global:PARANOID_MODE)")
$LOG_LINES.Insert(1, "RISK:$totalRisk | FINDINGS:$findingCount | CRIT:$critCount | HIGH:$highCount | POSSIBLE:$possibleCount | INFO:$infoCount")
$LOG_LINES.Insert(2, "RAT:$($global:RATHits) | ROOT:$($global:RootkitHits) | RANSOM:$($global:RansomwareRisk) | KL:$($global:KeyloggerHits) | MINER:$($global:MinerHits) | WORM:$($global:WormHits) | TROJAN:$($global:TrojanHits) | UAC:$($global:UACBypassHits)")
$LOG_LINES.Insert(3, "="*80)
$LOG_LINES | Out-File -FilePath $REPORT_PATH -Encoding UTF8 -ErrorAction SilentlyContinue
Out-Typewriter "TXT REPORT    : $REPORT_PATH"  "GOOD"
Out-Typewriter "AUDIT JSON    : $AUDIT_JSON"   "GOOD"
Out-Typewriter "BASELINE SAVE : $BASELINE_PATH" "GOOD"

# HTML report
function Write-HtmlReport {
    param([string]$OutPath)
    $sc  = @{ "CRITICAL"="#ff3838"; "HIGH"="#ff9500"; "POSSIBLE"="#ffd60a"; "INFO"="#6b7280" }
    $acc = if ($global:MSP_MODE) { "#ff6600" } else { "#00b4ff" }
    $csvData = '"Severity","Phase","ThreatType","Description","Target","FixAction","Timestamp"' + "`n"
    $rows = ($global:AuditFindings | Sort-Object @{e={switch($_.Severity){"CRITICAL"{0}"HIGH"{1}"POSSIBLE"{2}default{3}}};desc=$false}) | ForEach-Object {
        $col  = $sc[$_.Severity]
        $desc = [System.Net.WebUtility]::HtmlEncode($_.Description)
        $tgt  = [System.Net.WebUtility]::HtmlEncode($_.Target)
        $phase= [System.Net.WebUtility]::HtmlEncode($_.Phase)
        $type = [System.Net.WebUtility]::HtmlEncode($_.ThreatType)
        $csvData += """$($_.Severity)"",""$($_.Phase)"",""$($_.ThreatType)"",""$($_.Description -replace '"','""')"",""$($_.Target -replace '"','""')"",""$($_.FixAction)"",""$($_.Timestamp)""`n"
        "<tr class='sev-$($_.Severity.ToLower())'><td><span class='badge' style='background:$col'>$($_.Severity)</span></td><td>$phase</td><td>$type</td><td>$desc</td><td class='tgt' title='$tgt'>$tgt</td><td>$($_.FixAction)</td></tr>"
    }
    $csvDataJs = $csvData -replace '\\','\\' -replace "'","\\'"
    $tallyHtml = ""
    foreach ($k in @("RAT","Rootkit","Ransomware","Keylogger","Miner","Worm","Spyware","Trojan","Backdoor","UACBypass")) {
        $v   = $auditCache.ThreatTally.$k
        $col = if ([int]$v -ge 5) { "#ff3838" } elseif ([int]$v -ge 1) { "#ff9500" } else { "#22c55e" }
        $tallyHtml += "<div class='card'><div class='card-label'>$k</div><div class='card-val' style='color:$col'>$v</div></div>"
    }
    $deltaHtml = ""
    if ($global:BaselineDelta.Count -gt 0) {
        $deltaHtml  = "<h2>⚠ Baseline Delta — $($global:BaselineDelta.Count) New Findings</h2><ul>"
        $deltaHtml += ($global:BaselineDelta | ForEach-Object { "<li><b>[$($_.Severity)]</b> $([System.Net.WebUtility]::HtmlEncode($_.Description))</li>" }) -join ""
        $deltaHtml += "</ul>"
    }
    $riskClass = if ($totalRisk -gt 20) {"crit"} elseif ($totalRisk -gt 10) {"high"} elseif ($totalRisk -gt 3) {"med"} else {"low"}
    $html = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>ZeroBreach V22 — $HOST_NAME</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Consolas,'Courier New',monospace;background:#0a0a0a;color:#e5e5e5;padding:24px;line-height:1.6}
h1{color:$acc;font-size:26px;border-bottom:2px solid $acc;padding-bottom:8px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}
.h1-actions{display:flex;gap:8px}
h2{color:$acc;font-size:18px;margin:24px 0 10px;padding-left:10px;border-left:4px solid $acc}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-bottom:20px}
.meta div{background:#141414;padding:10px;border-left:3px solid $acc;border-radius:4px}
.meta strong{color:$acc;display:block;font-size:10px;text-transform:uppercase;margin-bottom:3px}
.risk{font-size:38px;font-weight:bold;text-align:center;padding:18px;border-radius:8px;margin:16px 0;background:#141414}
.crit{color:#ff3838;border:2px solid #ff3838;animation:pulse 2s infinite}
.high{color:#ff9500;border:2px solid #ff9500}
.med {color:#ffd60a;border:2px solid #ffd60a}
.low {color:#22c55e;border:2px solid #22c55e}
@keyframes pulse{0%,100%{box-shadow:0 0 6px #ff3838}50%{box-shadow:0 0 22px #ff3838}}
.tally{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin:14px 0}
.card{background:#141414;padding:14px;text-align:center;border-radius:6px;border:1px solid #2a2a2a;transition:border-color .2s}
.card:hover{border-color:$acc}
.card-label{font-size:10px;color:#888;text-transform:uppercase;margin-bottom:4px}
.card-val{font-size:30px;font-weight:bold}
.toolbar{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;align-items:center}
.search{flex:1;min-width:200px;padding:9px;background:#141414;border:1px solid #333;color:#fff;font-family:inherit;border-radius:4px;font-size:13px}
.search:focus{outline:none;border-color:$acc}
.filters{display:flex;gap:6px;flex-wrap:wrap}
.btn{background:#141414;color:#ccc;border:1px solid #333;padding:5px 12px;cursor:pointer;font-family:inherit;border-radius:3px;font-size:12px;transition:all .15s}
.btn:hover{border-color:$acc;color:#fff}
.btn.on{background:$acc;color:#000;border-color:$acc}
.btn-csv{background:#0d2d0d;color:#22c55e;border-color:#22c55e}
.btn-csv:hover{background:#22c55e;color:#000}
.btn-print{background:#1a1a2e;color:#818cf8;border-color:#818cf8}
.btn-print:hover{background:#818cf8;color:#000}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#141414;color:$acc;padding:9px 8px;text-align:left;border-bottom:2px solid $acc;position:sticky;top:0;cursor:pointer;user-select:none}
th:hover{color:#fff}
th::after{content:' ⇅';color:#555;font-size:9px}
td{padding:7px 8px;border-bottom:1px solid #1e1e1e;vertical-align:top}
tr:hover td{background:#141414}
.sev-critical td:first-child{border-left:3px solid #ff3838}
.sev-high     td:first-child{border-left:3px solid #ff9500}
.sev-possible td:first-child{border-left:3px solid #ffd60a}
.sev-info     td:first-child{border-left:3px solid #444}
.badge{display:inline-block;padding:2px 7px;border-radius:3px;color:#000;font-weight:bold;font-size:10px}
.tgt{color:#6b7280;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
ul{margin:10px 0 10px 20px}
li{margin:4px 0}
.footer{text-align:center;color:#444;font-size:11px;margin-top:36px;padding-top:16px;border-top:1px solid #1e1e1e}
.phase-bar{background:#141414;border:1px solid #1e1e1e;border-radius:4px;padding:10px;margin:8px 0;font-size:11px;color:#888}
@media print{body{background:#fff;color:#000;padding:8px}.risk{font-size:22px}.btn-csv,.btn-print,.toolbar{display:none!important}td,th{border:1px solid #ccc!important;padding:4px}table{font-size:10px}.sev-critical td:first-child{border-left:3px solid #cc0000!important}}
</style></head><body>
<h1><span>◈ ZeroBreach V22 — Forensic Audit Report</span>
<span class='h1-actions'>
<button class='btn btn-csv' onclick='exportCSV()'>⬇ Export CSV</button>
<button class='btn btn-print' onclick='window.print()'>🖨 Print</button>
</span></h1>
<div class='meta'>
<div><strong>Host</strong>$HOST_NAME</div>
<div><strong>User</strong>$USER_NAME</div>
<div><strong>Mode</strong>$($global:ScanMode) ($phaseCount phases)</div>
<div><strong>Window</strong>$($global:TW_LABEL)</div>
<div><strong>Started</strong>$($global:START_TIME.ToString('yyyy-MM-dd HH:mm:ss'))</div>
<div><strong>Elapsed</strong>$elapsed min</div>
<div><strong>OS</strong>$($global:OS_VERSION)</div>
<div><strong>Findings</strong>$findingCount total</div>
</div>
<div class='risk $riskClass'>RISK SCORE: $totalRisk — $riskLabel</div>
<h2>Threat Tally</h2><div class='tally'>$tallyHtml</div>
$deltaHtml
<h2>Findings ($findingCount) — CRITICAL: $critCount &nbsp; HIGH: $highCount &nbsp; POSSIBLE: $possibleCount &nbsp; INFO: $infoCount</h2>
<div class='toolbar'>
<input type='text' class='search' id='srch' placeholder='Search findings...' oninput='filterAll()'>
<div class='filters'>
<button class='btn on' onclick='filterSev("ALL",this)'>ALL</button>
<button class='btn' onclick='filterSev("CRITICAL",this)'>CRITICAL</button>
<button class='btn' onclick='filterSev("HIGH",this)'>HIGH</button>
<button class='btn' onclick='filterSev("POSSIBLE",this)'>POSSIBLE</button>
<button class='btn' onclick='filterSev("INFO",this)'>INFO</button>
</div>
</div>
<table id='tbl'><thead><tr>
<th onclick='sortTable(0)'>Sev</th>
<th onclick='sortTable(1)'>Phase</th>
<th onclick='sortTable(2)'>Type</th>
<th onclick='sortTable(3)'>Description</th>
<th onclick='sortTable(4)'>Target</th>
<th onclick='sortTable(5)'>Fix</th>
</tr></thead>
<tbody>$($rows -join "`n")</tbody></table>
<div class='footer'>ZeroBreach V22 · Project Kraken · Gannon MSP · $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
<script>
var curSev='ALL',curQ='';
function filterAll(){curQ=document.getElementById('srch').value.toLowerCase();applyFilters()}
function filterSev(s,b){document.querySelectorAll('.filters .btn').forEach(function(x){x.classList.remove('on')});b.classList.add('on');curSev=s;applyFilters()}
function applyFilters(){document.querySelectorAll('#tbl tbody tr').forEach(function(r){var sevOk=curSev==='ALL'||r.classList.contains('sev-'+curSev.toLowerCase());var txtOk=!curQ||r.innerText.toLowerCase().includes(curQ);r.style.display=(sevOk&&txtOk)?'':'none'})}
var sortDir={};
function sortTable(col){var tbl=document.getElementById('tbl');var rows=Array.from(tbl.tBodies[0].rows);var asc=sortDir[col]!==1;sortDir={};sortDir[col]=asc?1:-1;rows.sort(function(a,b){var va=a.cells[col].innerText.trim();var vb=b.cells[col].innerText.trim();return asc?va.localeCompare(vb,undefined,{numeric:true}):vb.localeCompare(va,undefined,{numeric:true})});rows.forEach(function(r){tbl.tBodies[0].appendChild(r)})}
function exportCSV(){var csv=$([char]39)$csvDataJs$([char]39);var blob=new Blob([csv],{type:'text/csv'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='ZeroBreach_V22_$HOST_NAME_$(Get-Date -Format 'yyyyMMdd').csv';a.click()}
</script></body></html>
"@
    $html | Out-File -FilePath $OutPath -Encoding UTF8 -ErrorAction SilentlyContinue
}

if ($global:HTML_REPORT -or $Html) {
    Write-HtmlReport -OutPath $HTML_PATH
    Out-Typewriter "HTML REPORT   : $HTML_PATH" "GOOD"
}

# Email report (scheduled task mode or -SmtpTo supplied)
if ($SmtpTo -and $SmtpServer -and $SmtpFrom) {
    Out-Typewriter "SENDING EMAIL REPORT TO $SmtpTo ..." "ACT"
    $subject = "ZeroBreach V22 — $HOST_NAME — RISK:$totalRisk ($riskLabel) — $findingCount findings"
    $body    = "ZeroBreach V22 Audit Report`n$('='*60)`nHost: $HOST_NAME`nUser: $USER_NAME`nMode: $($global:ScanMode)`nWindow: $($global:TW_LABEL)`nRisk Score: $totalRisk — $riskLabel`n`nCRITICAL: $critCount`nHIGH:     $highCount`nPOSSIBLE: $possibleCount`nINFO:     $infoCount`n`nReport: $REPORT_PATH`n"
    if ($global:HTML_REPORT -or $Html) { $body += "HTML: $HTML_PATH`n" }
    $body += "`n--- TOP CRITICAL/HIGH FINDINGS ---`n"
    $global:AuditFindings | Where-Object { $_.Severity -in @("CRITICAL","HIGH") } | Select-Object -First 20 | ForEach-Object {
        $body += "[$($_.Severity)] $($_.ThreatType): $($_.Description)`n"
    }
    try {
        $mailParams = @{
            To         = $SmtpTo
            From       = $SmtpFrom
            Subject    = $subject
            Body       = $body
            SmtpServer = $SmtpServer
        }
        if ($global:HTML_REPORT -or $Html) {
            $mailParams.Attachments = $HTML_PATH
        }
        Send-MailMessage @mailParams -ErrorAction Stop
        Out-Typewriter "  -> EMAIL SENT." "GOOD"
    } catch {
        Out-Typewriter "  -> EMAIL FAILED: $_" "WARN"
    }
}

# Close the console transcript now — captures the full scan, summary, timing and
# report paths, and flushes the file before any exit or interactive fix-mode prompt.
if ($global:TRANSCRIPT_ON) {
    Out-Typewriter "CONSOLE LOG   : $TRANSCRIPT_PATH" "GOOD"
    try { Stop-Transcript | Out-Null } catch {}
    $global:TRANSCRIPT_ON = $false
}

# Stealth exit — emit JSON to stdout
if ($global:STEALTH_MODE) {
    $auditCache | ConvertTo-Json -Depth 5 -Compress
    [Environment]::Exit(0)   # dot-sourced: plain exit would fall through to FixMode
}

# Auto/server exit — audit + reports are written above. The server-spawned child has no
# console stdin, so every interactive fix-mode prompt below (fix entry, finding selector,
# final confirm, "press any key") would block forever. Remediation is driven by the GUI.
if ($Auto) {
    Out-Typewriter "AUDIT COMPLETE. $findingCount FINDINGS. REPORTS WRITTEN. (auto mode — fix handled by GUI)" "GOOD"
    [Environment]::Exit(0)   # dot-sourced: plain exit would fall through to FixMode
}

if ($findingCount -eq 0) {
    Out-Typewriter "NO FINDINGS. SYSTEM APPEARS CLEAN. FIX MODE NOT AVAILABLE." "GOOD"
    Write-Host ""; Out-Typewriter "PRESS ANY KEY TO EXIT." "INFO" 20
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); [Environment]::Exit(0)
}

