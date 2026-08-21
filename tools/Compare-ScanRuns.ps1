<#
.SYNOPSIS
    Answers "did the cleanup stick?" — compares two ZeroBreach run records, or trends several.

.DESCRIPTION
    Compare-ScanRuns.ps1 joins two run records on finding ID (the stable key across runs) and
    sorts every finding into four buckets:

        Resolved    in the reference run, gone from the current one — the good news, first
        New         in the current run only
        Persistent  in both runs at the same severity
        Changed     in both runs at a different severity, with the direction

    INFO findings are excluded unless -IncludeInfo (they drown the signal); GROUPCAP_* rows are
    always excluded — they are flood-guard metadata, not findings.

    The join is strictly on ID. Because most (not all) IDs are derived from the target, the
    result also carries a "possible ID drift" advisory: resolved/new pairs that share an
    identical Target and ThreatType, which are likely the same condition under a new ID. They
    stay in their buckets — the advisory exists so nobody counts them as a fix plus a
    regression without looking.

    When the two runs used different modes or time windows the result carries an explicit
    warning, rendered before anything else: findings "resolved" between a DEEP and a QUICK run
    may simply never have been looked for.

    Given several current runs (-Current b.json,c.json,d.json) the tool produces a severity
    trend table per run in timestamp order instead of a join.

.PARAMETER Reference
    The earlier run record — the baseline the question is asked against.

.PARAMETER Current
    One run record for a full comparison; several for a counts-only trend table.

.PARAMETER Format
    Object (default) emits the computed result to the pipeline. Text, Json and Html render the
    same object; -OutFile writes the rendering to disk, otherwise it is emitted as a string.

.PARAMETER IncludeInfo
    Include INFO findings in the buckets. Run-level severity totals always include them.

.PARAMETER OutFile
    Write the rendered output here. With -Format Object this writes the Json rendering
    alongside emitting the object.

.EXAMPLE
    tools\Compare-ScanRuns.ps1 -Reference reports\KrakenBaseline_20260812_090000.json `
                               -Current reports\audit_20260819_143221.json -Format Text

.EXAMPLE
    tools\Compare-ScanRuns.ps1 -Reference a.json -Current b.json,c.json,d.json -Format Text
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Reference,

    [Parameter(Mandatory = $true)]
    [string[]]$Current,

    [ValidateSet('Object', 'Text', 'Json', 'Html')]
    [string]$Format = 'Object',

    [switch]$IncludeInfo,

    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------------------------
# Shared shapes (same conventions as New-ScanReport.ps1; each tool stands alone by design)
# --------------------------------------------------------------------------------------------

$script:ZbSevRank = @{ CRITICAL = 0; HIGH = 1; POSSIBLE = 2; INFO = 3 }
$script:ZbOtherRank = 4

function Get-ZbProp {
    param($Object, [string]$Name, $Default)
    if ($null -eq $Object) { return $Default }
    $pp = $Object.PSObject.Properties[$Name]
    if ($null -ne $pp -and $null -ne $pp.Value) { return $pp.Value }
    return $Default
}

function Get-ZbFullPath {
    param([string]$AnyPath)
    if ([System.IO.Path]::IsPathRooted($AnyPath)) { return $AnyPath }
    return (Join-Path -Path (Get-Location).Path -ChildPath $AnyPath)
}

function Get-ZbSevKey {
    param([string]$Severity)
    $sevText = ('' + $Severity).Trim().ToUpperInvariant()
    if ($script:ZbSevRank.ContainsKey($sevText)) { return $sevText }
    return 'OTHER'
}

function Get-ZbSevRank {
    param([string]$Severity)
    $sevKey = Get-ZbSevKey -Severity $Severity
    if ($sevKey -eq 'OTHER') { return $script:ZbOtherRank }
    return $script:ZbSevRank[$sevKey]
}

function Test-ZbGroupCap {
    param($Finding)
    return (('' + (Get-ZbProp $Finding 'ID' '')) -like 'GROUPCAP_*')
}

function Format-ZbTimestamp {
    param($Value)
    if ($Value -is [datetime]) {
        return $Value.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.DateTimeOffset]) {
        return $Value.ToString('yyyy-MM-dd HH:mm:ss zzz', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return ('' + $Value)
}

function Get-ZbSortableTime {
    # For ordering runs. Falls back to zero so a record with a broken timestamp still renders.
    param($Value)
    if ($Value -is [datetime]) { return $Value.Ticks }
    $parsed = [System.DateTimeOffset]::MinValue
    if ([System.DateTimeOffset]::TryParse(('' + $Value),
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        return $parsed.UtcTicks
    }
    return 0
}

function ConvertTo-ZbHtml {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $encoded = [System.Net.WebUtility]::HtmlEncode($Text)
    return ($encoded -replace "'", '&#39;')
}

function Import-ZbRunRecord {
    param([string]$RecordPath, [string]$Label)
    $full = Get-ZbFullPath -AnyPath $RecordPath
    if (-not (Test-Path -LiteralPath $full)) {
        throw "$Label not found: $full"
    }
    $raw = Get-Content -LiteralPath $full -Raw -Encoding UTF8
    $record = $null
    try {
        $record = $raw | ConvertFrom-Json
    }
    catch {
        throw "$Label is not valid JSON ($full): $($_.Exception.Message)"
    }
    if ($null -eq $record -or $null -eq $record.PSObject.Properties['Findings']) {
        throw "$Label has no Findings array ($full). Is this really a run record?"
    }
    return $record
}

# --------------------------------------------------------------------------------------------
# Per-run digest: identity, totals (all severities, GROUPCAP excluded), and the working set
# --------------------------------------------------------------------------------------------

function New-ZbRunDigest {
    param($Record, [string]$SourcePath, [bool]$WithInfo)
    $real = @(@(Get-ZbProp $Record 'Findings' @()) | Where-Object { -not (Test-ZbGroupCap $_) })
    $counts = [ordered]@{ CRITICAL = 0; HIGH = 0; POSSIBLE = 0; INFO = 0; OTHER = 0 }
    foreach ($f in $real) {
        $sevKey = Get-ZbSevKey -Severity (Get-ZbProp $f 'Severity' '')
        $counts[$sevKey] = $counts[$sevKey] + 1
    }
    $working = $real
    if (-not $WithInfo) {
        $working = @($real | Where-Object { (Get-ZbSevKey -Severity (Get-ZbProp $_ 'Severity' '')) -ne 'INFO' })
    }
    return [pscustomobject]@{
        Path           = Split-Path -Path (Get-ZbFullPath -AnyPath $SourcePath) -Leaf
        Host           = '' + (Get-ZbProp $Record 'Host' '')
        Timestamp      = Format-ZbTimestamp -Value (Get-ZbProp $Record 'Timestamp' '')
        SortTicks      = Get-ZbSortableTime -Value (Get-ZbProp $Record 'Timestamp' '')
        Mode           = ('' + (Get-ZbProp $Record 'Mode' '')).ToUpperInvariant()
        TimeWindow     = '' + (Get-ZbProp $Record 'TimeWindow' '')
        RiskScore      = [int](Get-ZbProp $Record 'RiskScore' 0)
        SeverityCounts = [pscustomobject]$counts
        TotalFindings  = $real.Count
        Working        = $working
    }
}

function Select-ZbFindingSummary {
    param($Finding)
    return [pscustomobject]@{
        ID          = '' + (Get-ZbProp $Finding 'ID' '')
        Severity    = '' + (Get-ZbProp $Finding 'Severity' '')
        ThreatType  = '' + (Get-ZbProp $Finding 'ThreatType' '')
        Description = '' + (Get-ZbProp $Finding 'Description' '')
        Target      = '' + (Get-ZbProp $Finding 'Target' '')
    }
}

function Sort-ZbBySeverity {
    param($Items)
    return @($Items | Sort-Object -Property @{ Expression = { Get-ZbSevRank (Get-ZbProp $_ 'Severity' '') } }, @{ Expression = { '' + (Get-ZbProp $_ 'ID' '') } })
}

# --------------------------------------------------------------------------------------------
# The comparison itself
# --------------------------------------------------------------------------------------------

function New-ZbComparison {
    param($RefDigest, $CurDigest, [bool]$WithInfo)

    $warnings = @()
    if ($RefDigest.Mode -ne $CurDigest.Mode) {
        $warnings += ('THE TWO RUNS USED DIFFERENT MODES ({0} vs {1}). Different modes check different numbers of phases, so findings "resolved" here may simply never have been looked for in the smaller run. Do not treat this comparison as evidence of cleanup without re-running in the same mode.' -f $RefDigest.Mode, $CurDigest.Mode)
    }
    if ($RefDigest.TimeWindow -ne $CurDigest.TimeWindow) {
        $warnings += ('The two runs used different time windows ("{0}" vs "{1}"); activity-based findings are not comparable between them.' -f $RefDigest.TimeWindow, $CurDigest.TimeWindow)
    }

    $refById = @{}
    foreach ($f in $RefDigest.Working) { $refById[('' + (Get-ZbProp $f 'ID' ''))] = $f }
    $curById = @{}
    foreach ($f in $CurDigest.Working) { $curById[('' + (Get-ZbProp $f 'ID' ''))] = $f }

    $resolved = @()
    $newOnes = @()
    $persistent = @()
    $changed = @()

    foreach ($f in $RefDigest.Working) {
        $fid = '' + (Get-ZbProp $f 'ID' '')
        if (-not $curById.ContainsKey($fid)) { $resolved += $f }
    }
    foreach ($f in $CurDigest.Working) {
        $fid = '' + (Get-ZbProp $f 'ID' '')
        if (-not $refById.ContainsKey($fid)) {
            $newOnes += $f
            continue
        }
        $refSev = Get-ZbSevKey -Severity (Get-ZbProp $refById[$fid] 'Severity' '')
        $curSev = Get-ZbSevKey -Severity (Get-ZbProp $f 'Severity' '')
        if ($refSev -eq $curSev) {
            $persistent += $f
        }
        else {
            $direction = 'escalated'
            if ((Get-ZbSevRank -Severity $curSev) -gt (Get-ZbSevRank -Severity $refSev)) { $direction = 'improved' }
            $changed += [pscustomobject]@{
                ID          = $fid
                From        = '' + (Get-ZbProp $refById[$fid] 'Severity' '')
                To          = '' + (Get-ZbProp $f 'Severity' '')
                Direction   = $direction
                ThreatType  = '' + (Get-ZbProp $f 'ThreatType' '')
                Description = '' + (Get-ZbProp $f 'Description' '')
                Target      = '' + (Get-ZbProp $f 'Target' '')
            }
        }
    }

    # Possible ID drift: resolved/new pairs sharing an identical Target and ThreatType. They
    # stay in their buckets; this list exists so a renamed ID is reviewed, not double-counted.
    $drift = @()
    $newByKey = @{}
    foreach ($f in $newOnes) {
        $key = (('' + (Get-ZbProp $f 'Target' '')).ToUpperInvariant()) + '|' + (('' + (Get-ZbProp $f 'ThreatType' '')).ToUpperInvariant())
        if (-not $newByKey.ContainsKey($key)) { $newByKey[$key] = New-Object System.Collections.Generic.List[object] }
        $newByKey[$key].Add($f)
    }
    foreach ($f in @(Sort-ZbBySeverity -Items $resolved)) {
        $key = (('' + (Get-ZbProp $f 'Target' '')).ToUpperInvariant()) + '|' + (('' + (Get-ZbProp $f 'ThreatType' '')).ToUpperInvariant())
        if ($newByKey.ContainsKey($key) -and $newByKey[$key].Count -gt 0) {
            $mate = $newByKey[$key][0]
            $newByKey[$key].RemoveAt(0)
            $drift += [pscustomobject]@{
                ResolvedId = '' + (Get-ZbProp $f 'ID' '')
                NewId      = '' + (Get-ZbProp $mate 'ID' '')
                Target     = '' + (Get-ZbProp $f 'Target' '')
                ThreatType = '' + (Get-ZbProp $f 'ThreatType' '')
            }
        }
    }

    $refEmpty = ($RefDigest.TotalFindings -eq 0)

    return [pscustomobject]@{
        Kind            = 'Compare'
        Reference       = ($RefDigest | Select-Object Path, Host, Timestamp, Mode, TimeWindow, RiskScore, SeverityCounts, TotalFindings)
        Current         = ($CurDigest | Select-Object Path, Host, Timestamp, Mode, TimeWindow, RiskScore, SeverityCounts, TotalFindings)
        IncludeInfo     = $WithInfo
        Warnings        = $warnings
        ReferenceEmpty  = $refEmpty
        RiskDelta       = ($CurDigest.RiskScore - $RefDigest.RiskScore)
        Resolved        = @(Sort-ZbBySeverity -Items $resolved | ForEach-Object { Select-ZbFindingSummary $_ })
        New             = @(Sort-ZbBySeverity -Items $newOnes | ForEach-Object { Select-ZbFindingSummary $_ })
        Persistent      = @(Sort-ZbBySeverity -Items $persistent | ForEach-Object { Select-ZbFindingSummary $_ })
        Changed         = @($changed | Sort-Object -Property @{ Expression = { Get-ZbSevRank $_.To } }, @{ Expression = { $_.ID } })
        ResolvedCount   = $resolved.Count
        NewCount        = $newOnes.Count
        PersistentCount = $persistent.Count
        ChangedCount    = $changed.Count
        IdDrift         = $drift
    }
}

function New-ZbTrend {
    param($Digests)
    $ordered = @($Digests | Sort-Object -Property @{ Expression = { $_.SortTicks } }, @{ Expression = { $_.Path } })
    $warnings = @()
    $modes = @($ordered | ForEach-Object { $_.Mode } | Sort-Object -Unique)
    if ($modes.Count -gt 1) {
        $warnings += ('These runs used different modes ({0}); counts are not comparable across a mode change.' -f ($modes -join ', '))
    }
    $windows = @($ordered | ForEach-Object { $_.TimeWindow } | Sort-Object -Unique)
    if ($windows.Count -gt 1) {
        $warnings += ('These runs used different time windows ({0}); activity counts are not comparable.' -f ($windows -join '; '))
    }
    return [pscustomobject]@{
        Kind     = 'Trend'
        Warnings = $warnings
        Runs     = @($ordered | Select-Object Path, Host, Timestamp, Mode, TimeWindow, RiskScore, SeverityCounts, TotalFindings)
    }
}

# --------------------------------------------------------------------------------------------
# Renderers — everything below reads only the result object
# --------------------------------------------------------------------------------------------

function Format-ZbRunLine {
    param($RunInfo)
    return ('{0}  ({1}, "{2}", {3}, risk {4})' -f $RunInfo.Path, $RunInfo.Mode, $RunInfo.TimeWindow, $RunInfo.Timestamp, $RunInfo.RiskScore)
}

function ConvertTo-ZbText {
    param($Result)
    $out = New-Object System.Collections.Generic.List[string]

    if ($Result.Kind -eq 'Trend') {
        $out.Add('SEVERITY TREND — ' + @($Result.Runs)[0].Host)
        $out.Add('')
        foreach ($w in @($Result.Warnings)) { $out.Add('!! ' + $w); $out.Add('') }
        $out.Add(('{0,-34} {1,-9} {2,8} {3,8} {4,8} {5,8} {6,8} {7,6}' -f 'Run', 'Mode', 'CRIT', 'HIGH', 'POSS', 'INFO', 'OTHER', 'Risk'))
        foreach ($r in @($Result.Runs)) {
            $out.Add(('{0,-34} {1,-9} {2,8} {3,8} {4,8} {5,8} {6,8} {7,6}' -f $r.Path, $r.Mode, $r.SeverityCounts.CRITICAL, $r.SeverityCounts.HIGH, $r.SeverityCounts.POSSIBLE, $r.SeverityCounts.INFO, $r.SeverityCounts.OTHER, $r.RiskScore))
        }
        return ($out -join [Environment]::NewLine)
    }

    $out.Add('RUN COMPARISON — ' + $Result.Current.Host)
    $out.Add('Reference: ' + (Format-ZbRunLine -RunInfo $Result.Reference))
    $out.Add('Current:   ' + (Format-ZbRunLine -RunInfo $Result.Current))
    $out.Add('')
    foreach ($w in @($Result.Warnings)) { $out.Add('!! ' + $w); $out.Add('') }

    $deltaText = 'unchanged'
    if ($Result.RiskDelta -lt 0) { $deltaText = ('down {0}' -f (-$Result.RiskDelta)) }
    elseif ($Result.RiskDelta -gt 0) { $deltaText = ('up {0}' -f $Result.RiskDelta) }
    $infoText = 'INFO findings excluded (-IncludeInfo shows them)'
    if ($Result.IncludeInfo) { $infoText = 'INFO findings included' }
    $out.Add(('Risk score {0} -> {1} ({2}). {3} resolved, {4} new, {5} changed severity, {6} persistent. {7}.' -f $Result.Reference.RiskScore, $Result.Current.RiskScore, $deltaText, $Result.ResolvedCount, $Result.NewCount, $Result.ChangedCount, $Result.PersistentCount, $infoText))
    $out.Add('')
    $out.Add(('{0,-10} {1,6} {2,6} {3,6} {4,6} {5,6}' -f '', 'CRIT', 'HIGH', 'POSS', 'INFO', 'OTHER'))
    $out.Add(('{0,-10} {1,6} {2,6} {3,6} {4,6} {5,6}' -f 'Reference', $Result.Reference.SeverityCounts.CRITICAL, $Result.Reference.SeverityCounts.HIGH, $Result.Reference.SeverityCounts.POSSIBLE, $Result.Reference.SeverityCounts.INFO, $Result.Reference.SeverityCounts.OTHER))
    $out.Add(('{0,-10} {1,6} {2,6} {3,6} {4,6} {5,6}' -f 'Current', $Result.Current.SeverityCounts.CRITICAL, $Result.Current.SeverityCounts.HIGH, $Result.Current.SeverityCounts.POSSIBLE, $Result.Current.SeverityCounts.INFO, $Result.Current.SeverityCounts.OTHER))
    $out.Add('')

    if ($Result.ReferenceEmpty) {
        $out.Add(('The reference run recorded no findings, so all {0} current finding(s) are new rather than regressions — this is a first look at the machine, not evidence that things got worse. Render the current run with New-ScanReport.ps1 to review them.' -f $Result.NewCount))
        return ($out -join [Environment]::NewLine)
    }

    $out.Add(('RESOLVED ({0}) — present in the reference run, gone now' -f $Result.ResolvedCount))
    if ($Result.ResolvedCount -eq 0) { $out.Add('  (nothing has cleared)') }
    foreach ($f in @($Result.Resolved)) {
        $out.Add(('  [{0}] {1}  {2}' -f $f.Severity, $f.ID, $f.Description))
    }
    $out.Add('')
    $out.Add(('NEW ({0}) — not present in the reference run' -f $Result.NewCount))
    if ($Result.NewCount -eq 0) { $out.Add('  (nothing new)') }
    foreach ($f in @($Result.New)) {
        $out.Add(('  [{0}] {1}  {2}' -f $f.Severity, $f.ID, $f.Description))
    }
    $out.Add('')
    $out.Add(('CHANGED SEVERITY ({0})' -f $Result.ChangedCount))
    if ($Result.ChangedCount -eq 0) { $out.Add('  (no severity movement)') }
    foreach ($c in @($Result.Changed)) {
        $out.Add(('  {0}: {1} -> {2} ({3})  {4}' -f $c.ID, $c.From, $c.To, $c.Direction, $c.Description))
    }
    $out.Add('')
    $out.Add(('PERSISTENT: {0} finding(s) present in both runs at the same severity.' -f $Result.PersistentCount))

    if (@($Result.IdDrift).Count -gt 0) {
        $out.Add('')
        $out.Add(('POSSIBLE ID DRIFT ({0}) — review before reading the buckets above at face value:' -f @($Result.IdDrift).Count))
        foreach ($d in @($Result.IdDrift)) {
            $out.Add(('  resolved {0} and new {1} share the same target and category ({2}, {3}) — likely the same condition under a new ID, not a fix plus a regression.' -f $d.ResolvedId, $d.NewId, $d.Target, $d.ThreatType))
        }
    }
    return ($out -join [Environment]::NewLine)
}

function ConvertTo-ZbCompareHtml {
    param($Result)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.Append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.Append('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''">')
    $docTitle = 'Run comparison'
    if ($Result.Kind -eq 'Trend') { $docTitle = 'Severity trend' }
    [void]$sb.Append('<title>' + $docTitle + '</title><style>')
    [void]$sb.Append(@'
:root{--bg:#f5f6f8;--card:#fff;--fg:#1d2833;--muted:#5b6b7b;--line:#d8dee6;--accent:#20567a;--warnbg:#fdf3d7;--warnfg:#5c4a12;--warnline:#e0c26a;--good:#1d6b3a;--bad:#a11d11}
@media (prefers-color-scheme: dark){:root{--bg:#12161b;--card:#1a2027;--fg:#dde5ee;--muted:#94a4b5;--line:#2d3945;--accent:#7db4d8;--warnbg:#332b14;--warnfg:#e8d9a0;--warnline:#6b5a25;--good:#5dbd85;--bad:#e05a4e}}
*{box-sizing:border-box}html{background:var(--bg)}
body{margin:0;font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:64rem;margin:0 auto;padding:1.5rem 1rem 3rem}
h1{font-size:1.4rem}h2{font-size:1.1rem;color:var(--accent);margin:1.4rem 0 .5rem}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:1rem 1.2rem;margin-bottom:1rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:2px solid var(--line);padding:.3rem .5rem}
td{border-bottom:1px solid var(--line);padding:.35rem .5rem;vertical-align:top;overflow-wrap:anywhere}
td.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.warnbox{background:var(--warnbg);color:var(--warnfg);border:1px solid var(--warnline);border-radius:6px;padding:.6rem .8rem;margin-bottom:.6rem;font-weight:600}
.good{color:var(--good);font-weight:700}.bad{color:var(--bad);font-weight:700}
.note{color:var(--muted);font-size:.85rem}
@media print{html,body{background:#fff;color:#000}section{border:none;padding:.3rem 0}thead{display:table-header-group}tr{break-inside:avoid}}
'@)
    [void]$sb.Append('</style></head><body><main>')

    if ($Result.Kind -eq 'Trend') {
        [void]$sb.Append('<h1>Severity trend — ' + (ConvertTo-ZbHtml @($Result.Runs)[0].Host) + '</h1><section>')
        foreach ($w in @($Result.Warnings)) { [void]$sb.Append('<p class="warnbox">' + (ConvertTo-ZbHtml $w) + '</p>') }
        [void]$sb.Append('<table><thead><tr><th>Run</th><th>Mode</th><th>Window</th><th>Critical</th><th>High</th><th>Possible</th><th>Info</th><th>Other</th><th>Risk</th></tr></thead><tbody>')
        foreach ($r in @($Result.Runs)) {
            [void]$sb.Append('<tr><td>' + (ConvertTo-ZbHtml $r.Path) + '<div class="note">' + (ConvertTo-ZbHtml $r.Timestamp) + '</div></td><td>' + (ConvertTo-ZbHtml $r.Mode) + '</td><td>' + (ConvertTo-ZbHtml $r.TimeWindow) + '</td><td class="num">' + $r.SeverityCounts.CRITICAL + '</td><td class="num">' + $r.SeverityCounts.HIGH + '</td><td class="num">' + $r.SeverityCounts.POSSIBLE + '</td><td class="num">' + $r.SeverityCounts.INFO + '</td><td class="num">' + $r.SeverityCounts.OTHER + '</td><td class="num">' + $r.RiskScore + '</td></tr>')
        }
        [void]$sb.Append('</tbody></table></section></main></body></html>')
        return $sb.ToString()
    }

    [void]$sb.Append('<h1>Run comparison — ' + (ConvertTo-ZbHtml $Result.Current.Host) + '</h1>')
    [void]$sb.Append('<section><p><strong>Reference:</strong> ' + (ConvertTo-ZbHtml (Format-ZbRunLine -RunInfo $Result.Reference)) + '<br><strong>Current:</strong> ' + (ConvertTo-ZbHtml (Format-ZbRunLine -RunInfo $Result.Current)) + '</p>')
    foreach ($w in @($Result.Warnings)) { [void]$sb.Append('<p class="warnbox">' + (ConvertTo-ZbHtml $w) + '</p>') }
    $deltaClass = 'note'
    if ($Result.RiskDelta -lt 0) { $deltaClass = 'good' }
    elseif ($Result.RiskDelta -gt 0) { $deltaClass = 'bad' }
    [void]$sb.Append('<p>Risk score ' + $Result.Reference.RiskScore + ' &rarr; ' + $Result.Current.RiskScore + ' (<span class="' + $deltaClass + '">' + $(if ($Result.RiskDelta -gt 0) { '+' } else { '' }) + $Result.RiskDelta + '</span>). ')
    [void]$sb.Append('<span class="good">' + $Result.ResolvedCount + ' resolved</span>, <span class="bad">' + $Result.NewCount + ' new</span>, ' + $Result.ChangedCount + ' changed severity, ' + $Result.PersistentCount + ' persistent.</p>')

    if ($Result.ReferenceEmpty) {
        [void]$sb.Append('<p class="warnbox">The reference run recorded no findings, so every current finding is new rather than a regression — this is a first look at the machine, not evidence that things got worse.</p></section></main></body></html>')
        return $sb.ToString()
    }
    [void]$sb.Append('</section>')

    $buckets = @(
        @('Resolved — present before, gone now', $Result.Resolved),
        @('New — not present in the reference run', $Result.New)
    )
    foreach ($bucket in $buckets) {
        [void]$sb.Append('<section><h2>' + (ConvertTo-ZbHtml $bucket[0]) + ' (' + @($bucket[1]).Count + ')</h2>')
        if (@($bucket[1]).Count -eq 0) {
            [void]$sb.Append('<p class="note">None.</p>')
        }
        else {
            [void]$sb.Append('<table><thead><tr><th>Severity</th><th>ID</th><th>Description</th><th>Target</th></tr></thead><tbody>')
            foreach ($f in @($bucket[1])) {
                [void]$sb.Append('<tr><td>' + (ConvertTo-ZbHtml $f.Severity) + '</td><td>' + (ConvertTo-ZbHtml $f.ID) + '</td><td>' + (ConvertTo-ZbHtml $f.Description) + '</td><td>' + (ConvertTo-ZbHtml $f.Target) + '</td></tr>')
            }
            [void]$sb.Append('</tbody></table>')
        }
        [void]$sb.Append('</section>')
    }

    [void]$sb.Append('<section><h2>Changed severity (' + $Result.ChangedCount + ')</h2>')
    if ($Result.ChangedCount -eq 0) {
        [void]$sb.Append('<p class="note">No severity movement.</p>')
    }
    else {
        [void]$sb.Append('<table><thead><tr><th>ID</th><th>Was</th><th>Now</th><th>Direction</th><th>Description</th></tr></thead><tbody>')
        foreach ($c in @($Result.Changed)) {
            $dirClass = 'bad'
            if ($c.Direction -eq 'improved') { $dirClass = 'good' }
            [void]$sb.Append('<tr><td>' + (ConvertTo-ZbHtml $c.ID) + '</td><td>' + (ConvertTo-ZbHtml $c.From) + '</td><td>' + (ConvertTo-ZbHtml $c.To) + '</td><td class="' + $dirClass + '">' + (ConvertTo-ZbHtml $c.Direction) + '</td><td>' + (ConvertTo-ZbHtml $c.Description) + '</td></tr>')
        }
        [void]$sb.Append('</tbody></table>')
    }
    [void]$sb.Append('</section>')

    [void]$sb.Append('<section><p>' + $Result.PersistentCount + ' finding(s) persist at the same severity in both runs.</p>')
    if (@($Result.IdDrift).Count -gt 0) {
        [void]$sb.Append('<h2>Possible ID drift (' + @($Result.IdDrift).Count + ')</h2><p class="note">These resolved/new pairs share the same target and category — likely the same condition under a new ID, not a fix plus a regression.</p><table><thead><tr><th>Resolved ID</th><th>New ID</th><th>Target</th><th>Category</th></tr></thead><tbody>')
        foreach ($d in @($Result.IdDrift)) {
            [void]$sb.Append('<tr><td>' + (ConvertTo-ZbHtml $d.ResolvedId) + '</td><td>' + (ConvertTo-ZbHtml $d.NewId) + '</td><td>' + (ConvertTo-ZbHtml $d.Target) + '</td><td>' + (ConvertTo-ZbHtml $d.ThreatType) + '</td></tr>')
        }
        [void]$sb.Append('</tbody></table>')
    }
    [void]$sb.Append('</section></main></body></html>')
    return $sb.ToString()
}

# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------

$refRecord = Import-ZbRunRecord -RecordPath $Reference -Label 'Reference run record'
$refDigest = New-ZbRunDigest -Record $refRecord -SourcePath $Reference -WithInfo:$IncludeInfo

$curDigests = @()
foreach ($curPath in $Current) {
    $curRecord = Import-ZbRunRecord -RecordPath $curPath -Label 'Current run record'
    $curDigests += New-ZbRunDigest -Record $curRecord -SourcePath $curPath -WithInfo:$IncludeInfo
}

if ($curDigests.Count -gt 1) {
    $result = New-ZbTrend -Digests (@($refDigest) + $curDigests)
}
else {
    $result = New-ZbComparison -RefDigest $refDigest -CurDigest $curDigests[0] -WithInfo:$IncludeInfo
}

$rendered = $null
switch ($Format) {
    'Text' { $rendered = ConvertTo-ZbText -Result $result }
    'Json' { $rendered = ConvertTo-Json -InputObject $result -Depth 8 }
    'Html' { $rendered = ConvertTo-ZbCompareHtml -Result $result }
    default { }
}

if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
    $toWrite = $rendered
    if ($null -eq $toWrite) { $toWrite = ConvertTo-Json -InputObject $result -Depth 8 }
    $outFull = Get-ZbFullPath -AnyPath $OutFile
    $outDir = Split-Path -Path $outFull -Parent
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($outFull, $toWrite, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("Comparison written: {0}" -f $outFull)
}

if ($Format -eq 'Object') {
    $result
}
elseif ([string]::IsNullOrWhiteSpace($OutFile)) {
    $rendered
}
