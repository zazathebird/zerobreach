<#
.SYNOPSIS
    Shows where a ZeroBreach run's wall-clock actually goes, and gates it against a budget.

.DESCRIPTION
    Get-PhaseTimingReport.ps1 reads phase timings from a run record (-Path) or a server
    console log (-LogPath). When both are given the run record wins — the log covers the whole
    server session while the record covers one scan — and the output says which source it used.

    From the console log only the stable "TIMING: PHASE <n> — <title> took <x>s" form is
    parsed; the decorated console twin (leading spaces, stopwatch glyph) is ignored. Fractional
    phase numbers (74.5) are kept intact — they are real plan steps, not sub-steps.

    When the same phase carries several TIMING lines in one log (a re-run inside one server
    session), the tool keeps the LAST value and reports how many lines it discarded
    (decision 2026-08-20; the last value describes the most recent scan).

    The report gives the total, the slowest -Top phases with each one's share, how many phases
    account for 80% of the time, a shortfall warning when fewer phases reported than the mode's
    ceiling (a correctness signal wearing a performance costume), and a budget check against
    data\phase_budgets.json. The script exits non-zero when the mode's total budget is
    exceeded, so it can gate a release.

.PARAMETER Path
    A run record; its PhaseTimings array is the preferred source.

.PARAMETER LogPath
    A server console log (KrakenConsole_<stamp>.log); used when no run record is given.

.PARAMETER Compare
    An earlier run record. Produces a per-phase delta table sorted by absolute change, so a
    caching change can be attributed to specific phases rather than to a total.

.PARAMETER Budget
    Path to the budget table. Defaults to data\phase_budgets.json next to the project root.
    Missing file means no gate is applied (reported, not fatal).

.PARAMETER Format
    Text (default), Json, or Html. The rendering is emitted to the pipeline.

.PARAMETER Top
    How many of the slowest phases to list. Default 20.

.PARAMETER PassThru
    Emit the computed result object instead of a rendering, for tests and scripting. The exit
    code still reflects the budget gate.

.EXAMPLE
    tools\Get-PhaseTimingReport.ps1 -Path reports\audit_20260819_143221.json

.EXAMPLE
    tools\Get-PhaseTimingReport.ps1 -Path new.json -Compare old.json -Format Text -Top 10
#>
[CmdletBinding()]
param(
    [string]$Path,

    [string]$LogPath,

    [string]$Compare,

    [string]$Budget,

    [ValidateSet('Text', 'Json', 'Html')]
    [string]$Format = 'Text',

    [ValidateRange(1, 1000)]
    [int]$Top = 20,

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

# Phase ceiling per mode (another copy of the mirrored table — see HANDOFF_FABLE.md; the G5
# parity test is extended to read this file so all copies are proven to agree).
$script:ZbModeCeiling = @{ QUICK = 30; FULL = 80; DEEP = 133; PARANOID = 133; STEALTH = 133; HUNT = 162 }

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

function ConvertTo-ZbHtml {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $encoded = [System.Net.WebUtility]::HtmlEncode($Text)
    return ($encoded -replace "'", '&#39;')
}

function Get-ZbPhaseKey {
    # "PHASE 74.5 — TITLE" -> "74.5". The decimal is kept; truncating double-counts (§5).
    param([string]$Label)
    if ([string]::IsNullOrEmpty($Label)) { return $null }
    $m = [regex]::Match($Label, 'PHASE\s+(\d+(?:\.\d+)?)(?!\d)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Format-ZbSeconds {
    param([double]$Seconds)
    $whole = [int][math]::Floor($Seconds)
    $mins = [int][math]::Floor($whole / 60)
    $secs = $Seconds - ($mins * 60)
    if ($mins -gt 0) { return ('{0}m {1:0.0}s' -f $mins, $secs) }
    return ('{0:0.0}s' -f $Seconds)
}

function Format-ZbNum {
    param([double]$Value, [string]$Pattern = '0.0')
    return $Value.ToString($Pattern, [System.Globalization.CultureInfo]::InvariantCulture)
}

# --------------------------------------------------------------------------------------------
# Sources. Both produce the same shape: ordered list of { Key; Label; Seconds; Duplicates },
# plus bookkeeping. Take-last applies to both, for the same reason in both.
# --------------------------------------------------------------------------------------------

function Read-ZbTimingsFromRecord {
    param([string]$RecordPath)
    $full = Get-ZbFullPath -AnyPath $RecordPath
    if (-not (Test-Path -LiteralPath $full)) { throw "Run record not found: $full" }
    $record = $null
    try {
        $record = Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "Run record is not valid JSON ($full): $($_.Exception.Message)"
    }
    $agg = [ordered]@{}
    $dups = 0
    foreach ($t in @(Get-ZbProp $record 'PhaseTimings' @())) {
        $label = '' + (Get-ZbProp $t 'Phase' '')
        $key = Get-ZbPhaseKey -Label $label
        if ($null -eq $key) { $key = $label }
        $prevDups = 0
        if ($agg.Contains($key)) {
            $dups = $dups + 1
            $prevDups = $agg[$key].Duplicates + 1
        }
        $agg[$key] = [pscustomobject]@{
            Key        = $key
            Label      = $label
            Seconds    = [double](Get-ZbProp $t 'Seconds' 0)
            Duplicates = $prevDups
        }
    }
    return [pscustomobject]@{
        Source              = 'RunRecord'
        SourcePath          = $full
        Mode                = ('' + (Get-ZbProp $record 'Mode' '')).ToUpperInvariant()
        Entries             = @($agg.Values)
        DuplicatesDiscarded = $dups
        Incomplete          = $false
        IncompletePhases    = @()
    }
}

function Read-ZbTimingsFromLog {
    param([string]$ConsoleLogPath)
    $full = Get-ZbFullPath -AnyPath $ConsoleLogPath
    if (-not (Test-Path -LiteralPath $full)) { throw "Console log not found: $full" }
    $agg = [ordered]@{}
    $started = [ordered]@{}
    $dups = 0
    # Parse the TIMING: form only — the console twin carries box-drawing and leading spaces
    # that vary. A phase-start is any other line naming a phase (findings echo phase labels
    # too, so this over-collects on purpose: a phase named anywhere but never timed is worth
    # flagging as incomplete).
    $timingRx = [regex]'^TIMING:\s*(.+?)\s+took\s+([0-9]+(?:\.[0-9]+)?)s\s*$'
    $phaseRx = [regex]'PHASE\s+(\d+(?:\.\d+)?)(?!\d)'
    foreach ($line in [System.IO.File]::ReadLines($full)) {
        $tm = $timingRx.Match($line)
        if ($tm.Success) {
            $label = $tm.Groups[1].Value
            $key = Get-ZbPhaseKey -Label $label
            if ($null -eq $key) { $key = $label }
            $prevDups = 0
            if ($agg.Contains($key)) {
                $dups = $dups + 1
                $prevDups = $agg[$key].Duplicates + 1
            }
            $agg[$key] = [pscustomobject]@{
                Key        = $key
                Label      = $label
                Seconds    = [double]::Parse($tm.Groups[2].Value, [System.Globalization.CultureInfo]::InvariantCulture)
                Duplicates = $prevDups
            }
            continue
        }
        if ($line.Contains('took')) { continue }   # the decorated console twin of TIMING
        $pm = $phaseRx.Match($line)
        if ($pm.Success) { $started[$pm.Groups[1].Value] = $true }
    }
    $unfinished = @()
    foreach ($key in $started.Keys) {
        if (-not $agg.Contains($key)) { $unfinished += ('' + $key) }
    }
    return [pscustomobject]@{
        Source              = 'ConsoleLog'
        SourcePath          = $full
        Mode                = ''    # the log does not carry the mode
        Entries             = @($agg.Values)
        DuplicatesDiscarded = $dups
        Incomplete          = ($unfinished.Count -gt 0)
        IncompletePhases    = $unfinished
    }
}

# --------------------------------------------------------------------------------------------
# The result object — everything computed here, rendered later
# --------------------------------------------------------------------------------------------

function New-ZbTimingResult {
    param($SourceData, $BudgetTable, [string]$BudgetPath, $CompareData, [int]$TopN)

    $entries = @($SourceData.Entries | Sort-Object -Property @{ Expression = { - $_.Seconds } }, @{ Expression = { $_.Key } })
    $total = 0.0
    foreach ($e in $entries) { $total = $total + $e.Seconds }

    $phases = @()
    foreach ($e in $entries) {
        $share = 0.0
        if ($total -gt 0) { $share = [math]::Round(($e.Seconds / $total) * 100, 1) }
        $phases += [pscustomobject]@{
            Key        = $e.Key
            Label      = $e.Label
            Seconds    = [math]::Round($e.Seconds, 1)
            Share      = $share
            Duplicates = $e.Duplicates
        }
    }

    # Cumulative distribution: how many of the slowest phases cover 80% of the total.
    $p80 = 0
    if ($total -gt 0) {
        $cum = 0.0
        foreach ($e in $entries) {
            $p80 = $p80 + 1
            $cum = $cum + $e.Seconds
            if ($cum -ge ($total * 0.8)) { break }
        }
    }

    $mode = $SourceData.Mode
    $ceiling = $null
    if ($script:ZbModeCeiling.ContainsKey($mode)) { $ceiling = $script:ZbModeCeiling[$mode] }
    $shortfall = 0
    if ($null -ne $ceiling -and $phases.Count -lt $ceiling) { $shortfall = $ceiling - $phases.Count }

    # Budget check. Mode total of 0 means unbudgeted; per-phase budgets are optional.
    $modeBudget = 0.0
    $overBudget = $false
    $overBy = 0.0
    $phaseOverruns = @()
    if ($null -ne $BudgetTable) {
        $totals = Get-ZbProp $BudgetTable 'mode_totals' $null
        if ($null -ne $totals -and $mode) {
            $mb = Get-ZbProp $totals $mode 0
            $modeBudget = [double]$mb
            if ($modeBudget -gt 0 -and $total -gt $modeBudget) {
                $overBudget = $true
                $overBy = [math]::Round($total - $modeBudget, 1)
            }
        }
        $perPhase = Get-ZbProp $BudgetTable 'phase_budgets' $null
        if ($null -ne $perPhase) {
            foreach ($p in $phases) {
                $pb = [double](Get-ZbProp $perPhase $p.Key 0)
                if ($pb -gt 0 -and $p.Seconds -gt $pb) {
                    $phaseOverruns += [pscustomobject]@{ Key = $p.Key; Label = $p.Label; Seconds = $p.Seconds; Budget = $pb }
                }
            }
        }
    }

    # Per-phase delta against an earlier run, sorted by absolute change.
    $comparison = $null
    if ($null -ne $CompareData) {
        $beforeByKey = @{}
        foreach ($e in @($CompareData.Entries)) { $beforeByKey[$e.Key] = $e.Seconds }
        $afterByKey = @{}
        foreach ($e in $entries) { $afterByKey[$e.Key] = $e.Seconds }
        $allKeys = [ordered]@{}
        foreach ($k in $afterByKey.Keys) { $allKeys[$k] = $true }
        foreach ($k in $beforeByKey.Keys) { $allKeys[$k] = $true }
        $rows = @()
        foreach ($k in $allKeys.Keys) {
            $before = 0.0
            $after = 0.0
            $status = 'both'
            if ($beforeByKey.ContainsKey($k)) { $before = [double]$beforeByKey[$k] } else { $status = 'added' }
            if ($afterByKey.ContainsKey($k)) { $after = [double]$afterByKey[$k] } else { $status = 'removed' }
            $rows += [pscustomobject]@{
                Key    = '' + $k
                Before = [math]::Round($before, 1)
                After  = [math]::Round($after, 1)
                Delta  = [math]::Round($after - $before, 1)
                Status = $status
            }
        }
        $comparison = @($rows | Sort-Object -Property @{ Expression = { - [math]::Abs($_.Delta) } }, @{ Expression = { $_.Key } })
    }

    $exitCode = 0
    if ($overBudget) { $exitCode = 1 }

    return [pscustomobject]@{
        Kind                = 'PhaseTiming'
        Source              = $SourceData.Source
        SourcePath          = Split-Path -Path $SourceData.SourcePath -Leaf
        Mode                = $mode
        Ceiling             = $ceiling
        PhaseCount          = $phases.Count
        Shortfall           = $shortfall
        TotalSeconds        = [math]::Round($total, 1)
        Phases              = $phases
        TopPhases           = @($phases | Select-Object -First $TopN)
        P80Count            = $p80
        DuplicatesDiscarded = $SourceData.DuplicatesDiscarded
        Incomplete          = $SourceData.Incomplete
        IncompletePhases    = @($SourceData.IncompletePhases)
        BudgetPath          = $BudgetPath
        ModeBudget          = $modeBudget
        OverBudget          = $overBudget
        OverBy              = $overBy
        PhaseOverruns       = $phaseOverruns
        Comparison          = $comparison
        ExitCode            = $exitCode
    }
}

# --------------------------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------------------------

function ConvertTo-ZbTimingText {
    param($Result)
    $out = New-Object System.Collections.Generic.List[string]
    $sourceWord = 'run record'
    if ($Result.Source -eq 'ConsoleLog') { $sourceWord = 'console log' }
    $out.Add(('PHASE TIMING — from the {0} ({1})' -f $sourceWord, $Result.SourcePath))

    if ($Result.Mode) {
        if ($null -ne $Result.Ceiling) {
            if ($Result.Shortfall -gt 0) {
                $out.Add(('!! {0} mode plans {1} phases; only {2} reported timings. {3} phases missing — that is a correctness signal wearing a performance costume: find out why they did not run before trusting the total below.' -f $Result.Mode, $Result.Ceiling, $Result.PhaseCount, $Result.Shortfall))
            }
            else {
                $out.Add(('{0} mode: all {1} planned phases reported.' -f $Result.Mode, $Result.Ceiling))
            }
        }
        else {
            $out.Add(('Mode {0} (no known phase ceiling).' -f $Result.Mode))
        }
    }
    else {
        $out.Add('Mode unknown (console logs do not carry it) — no ceiling or budget gate applied.')
    }
    if ($Result.Incomplete) {
        $out.Add(('!! Log ends with unfinished work: phase(s) {0} started but never reported a timing. The scan was cut short or is still running.' -f (@($Result.IncompletePhases) -join ', ')))
    }
    $out.Add(('Total wall-clock: {0} across {1} phases.' -f (Format-ZbSeconds -Seconds $Result.TotalSeconds), $Result.PhaseCount))
    if ($Result.DuplicatesDiscarded -gt 0) {
        $out.Add(('Note: {0} duplicate TIMING line(s) for re-run phases were discarded; the last value per phase is used.' -f $Result.DuplicatesDiscarded))
    }
    $out.Add('')
    $out.Add(('Slowest {0}:' -f @($Result.TopPhases).Count))
    foreach ($p in @($Result.TopPhases)) {
        $dupNote = ''
        if ($p.Duplicates -gt 0) { $dupNote = ('  (re-run {0}x, last kept)' -f $p.Duplicates) }
        $out.Add(('  {0,8}s  {1,5}%  {2}{3}' -f (Format-ZbNum -Value $p.Seconds), (Format-ZbNum -Value $p.Share), $p.Label, $dupNote))
    }
    $out.Add('')
    $out.Add(('{0} of {1} phases account for 80% of the time — that is where optimisation effort pays.' -f $Result.P80Count, $Result.PhaseCount))

    if ($Result.ModeBudget -gt 0) {
        if ($Result.OverBudget) {
            $out.Add(('!! OVER BUDGET: {0} allows {1}; this run took {2} — over by {3}.' -f $Result.Mode, (Format-ZbSeconds -Seconds $Result.ModeBudget), (Format-ZbSeconds -Seconds $Result.TotalSeconds), (Format-ZbSeconds -Seconds $Result.OverBy)))
        }
        else {
            $out.Add(('Within budget: {0} allows {1}; this run took {2}.' -f $Result.Mode, (Format-ZbSeconds -Seconds $Result.ModeBudget), (Format-ZbSeconds -Seconds $Result.TotalSeconds)))
        }
    }
    else {
        $out.Add('No total budget set for this mode (0 = unbudgeted in the budget table) — no gate applied.')
    }
    foreach ($o in @($Result.PhaseOverruns)) {
        $out.Add(('!! Phase over budget: {0} took {1}s against a {2}s budget.' -f $o.Label, (Format-ZbNum -Value $o.Seconds), (Format-ZbNum -Value $o.Budget)))
    }

    if ($null -ne $Result.Comparison) {
        $out.Add('')
        $out.Add('Change per phase against the comparison run (sorted by absolute change):')
        $out.Add(('  {0,-8} {1,10} {2,10} {3,10}  {4}' -f 'Phase', 'Before(s)', 'After(s)', 'Delta(s)', ''))
        foreach ($row in @($Result.Comparison)) {
            $tag = ''
            if ($row.Status -eq 'added') { $tag = 'not in comparison run' }
            elseif ($row.Status -eq 'removed') { $tag = 'no longer runs' }
            $out.Add(('  {0,-8} {1,10} {2,10} {3,10}  {4}' -f $row.Key, (Format-ZbNum -Value $row.Before), (Format-ZbNum -Value $row.After), (Format-ZbNum -Value $row.Delta), $tag))
        }
    }
    return ($out -join [Environment]::NewLine)
}

function ConvertTo-ZbTimingHtml {
    param($Result)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.Append('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''">')
    [void]$sb.Append('<title>Phase timing — ' + (ConvertTo-ZbHtml $Result.SourcePath) + '</title><style>')
    [void]$sb.Append(@'
:root{--bg:#f5f6f8;--card:#fff;--fg:#1d2833;--muted:#5b6b7b;--line:#d8dee6;--accent:#20567a;--warnbg:#fdf3d7;--warnfg:#5c4a12;--warnline:#e0c26a;--bar:#20567a}
@media (prefers-color-scheme: dark){:root{--bg:#12161b;--card:#1a2027;--fg:#dde5ee;--muted:#94a4b5;--line:#2d3945;--accent:#7db4d8;--warnbg:#332b14;--warnfg:#e8d9a0;--warnline:#6b5a25;--bar:#7db4d8}}
*{box-sizing:border-box}html{background:var(--bg)}
body{margin:0;font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:60rem;margin:0 auto;padding:1.5rem 1rem 3rem}
h1{font-size:1.4rem}section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:1rem 1.2rem;margin-bottom:1rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{text-align:left;font-size:.75rem;text-transform:uppercase;color:var(--muted);border-bottom:2px solid var(--line);padding:.3rem .5rem}
td{border-bottom:1px solid var(--line);padding:.35rem .5rem;overflow-wrap:anywhere}
td.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.warnbox{background:var(--warnbg);color:var(--warnfg);border:1px solid var(--warnline);border-radius:6px;padding:.6rem .8rem;margin-bottom:.6rem;font-weight:600}
.bar{height:.5rem;background:var(--bar);border-radius:2px;min-width:1px}
.note{color:var(--muted);font-size:.85rem}
@media print{html,body{background:#fff;color:#000}section{border:none;padding:.3rem 0}thead{display:table-header-group}tr{break-inside:avoid}}
'@)
    [void]$sb.Append('</style></head><body><main><h1>Phase timing — ' + (ConvertTo-ZbHtml $Result.SourcePath) + '</h1><section>')
    if ($Result.Shortfall -gt 0) {
        [void]$sb.Append('<p class="warnbox">' + $Result.Mode + ' mode plans ' + $Result.Ceiling + ' phases; only ' + $Result.PhaseCount + ' reported. Find out why before trusting these totals.</p>')
    }
    if ($Result.Incomplete) {
        [void]$sb.Append('<p class="warnbox">Phase(s) ' + (ConvertTo-ZbHtml (@($Result.IncompletePhases) -join ', ')) + ' started but never finished — the log is cut short.</p>')
    }
    if ($Result.OverBudget) {
        [void]$sb.Append('<p class="warnbox">OVER BUDGET: ' + (ConvertTo-ZbHtml (Format-ZbSeconds -Seconds $Result.TotalSeconds)) + ' against ' + (ConvertTo-ZbHtml (Format-ZbSeconds -Seconds $Result.ModeBudget)) + ' allowed.</p>')
    }
    [void]$sb.Append('<p>Total <strong>' + (ConvertTo-ZbHtml (Format-ZbSeconds -Seconds $Result.TotalSeconds)) + '</strong> across ' + $Result.PhaseCount + ' phases; ' + $Result.P80Count + ' of them account for 80% of the time.</p>')
    if ($Result.DuplicatesDiscarded -gt 0) {
        [void]$sb.Append('<p class="note">' + $Result.DuplicatesDiscarded + ' duplicate TIMING line(s) discarded — last value per phase kept.</p>')
    }
    [void]$sb.Append('</section><section><table><thead><tr><th>Phase</th><th>Seconds</th><th>Share</th><th></th></tr></thead><tbody>')
    foreach ($p in @($Result.TopPhases)) {
        [void]$sb.Append('<tr><td>' + (ConvertTo-ZbHtml $p.Label) + '</td><td class="num">' + (Format-ZbNum -Value $p.Seconds) + '</td><td class="num">' + (Format-ZbNum -Value $p.Share) + '%</td><td style="width:30%"><div class="bar" style="width:' + (Format-ZbNum -Value $p.Share) + '%"></div></td></tr>')
    }
    [void]$sb.Append('</tbody></table></section>')
    if ($null -ne $Result.Comparison) {
        [void]$sb.Append('<section><table><thead><tr><th>Phase</th><th>Before</th><th>After</th><th>Delta</th><th></th></tr></thead><tbody>')
        foreach ($row in @($Result.Comparison)) {
            [void]$sb.Append('<tr><td>' + (ConvertTo-ZbHtml $row.Key) + '</td><td class="num">' + (Format-ZbNum -Value $row.Before) + '</td><td class="num">' + (Format-ZbNum -Value $row.After) + '</td><td class="num">' + (Format-ZbNum -Value $row.Delta) + '</td><td>' + (ConvertTo-ZbHtml $row.Status) + '</td></tr>')
        }
        [void]$sb.Append('</tbody></table></section>')
    }
    [void]$sb.Append('</main></body></html>')
    return $sb.ToString()
}

# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($Path) -and [string]::IsNullOrWhiteSpace($LogPath)) {
    throw 'Give at least one source: -Path <run record> or -LogPath <console log>.'
}

$sourceData = $null
if (-not [string]::IsNullOrWhiteSpace($Path)) {
    $sourceData = Read-ZbTimingsFromRecord -RecordPath $Path
    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        Write-Verbose 'Both sources given; using the run record (the log can span several scans).'
    }
}
else {
    $sourceData = Read-ZbTimingsFromLog -ConsoleLogPath $LogPath
}

$budgetPath = $Budget
if ([string]::IsNullOrWhiteSpace($budgetPath)) {
    $budgetPath = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'data/phase_budgets.json'
}
$budgetTable = $null
if (Test-Path -LiteralPath $budgetPath) {
    try {
        $budgetTable = Get-Content -LiteralPath $budgetPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Write-Warning ("Budget table at '{0}' is not valid JSON; no gate applied." -f $budgetPath)
    }
}
else {
    Write-Warning ("Budget table not found at '{0}'; no gate applied." -f $budgetPath)
}

$compareData = $null
if (-not [string]::IsNullOrWhiteSpace($Compare)) {
    $compareData = Read-ZbTimingsFromRecord -RecordPath $Compare
}

$result = New-ZbTimingResult -SourceData $sourceData -BudgetTable $budgetTable -BudgetPath $budgetPath -CompareData $compareData -TopN $Top

if ($PassThru) {
    $result
}
else {
    switch ($Format) {
        'Text' { ConvertTo-ZbTimingText -Result $result }
        'Json' { ConvertTo-Json -InputObject $result -Depth 8 }
        'Html' { ConvertTo-ZbTimingHtml -Result $result }
    }
}

exit $result.ExitCode
