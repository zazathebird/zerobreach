<#
.SYNOPSIS
    Renders a finished ZeroBreach run record into one self-contained HTML report.

.DESCRIPTION
    New-ScanReport.ps1 is a post-processing tool. It never runs during a scan: it reads a
    completed run record (reports\audit_<stamp>.json or the KrakenBaseline_ copy), computes a
    summary object, and writes a single HTML file with no external dependencies — every style
    and script is inlined, nothing reaches the network.

    The report is written for the technician standing at the client's desk: an executive
    summary in prose, a "what to do first" list grouped the way an operator triages, a
    technique/tactic rollup, the full findings table (grouped, collapsed, filterable), run
    health, and — when -Compare is given — what changed against a baseline run.

    Every number in the report is computed into the summary object first and rendered from it;
    -PassThru emits that object so tests can assert on the numbers without parsing HTML.

.PARAMETER Path
    Path to the run record JSON. Either report filename form is accepted. The file must parse
    as JSON and carry a Findings array; anything else is a terminating error up front.

.PARAMETER OutFile
    Where to write the HTML report. Defaults to the input path with '.json' swapped for
    '_report.html'.

.PARAMETER Compare
    Optional path to an earlier run record (typically a KrakenBaseline_ file). Findings are
    joined on ID — stable for the same condition across runs — never on Timestamp.

.PARAMETER Title
    Optional client-facing title, e.g. "Acme Ltd — August audit". Shown as the report heading.

.PARAMETER MappingPath
    Path to the technique reference map (data\mitre_mapping.json). Defaults to the copy that
    ships alongside this tool's project root. If the file is missing or unreadable the report
    is still produced: a visible notice is added and every finding lands in the "unmapped" row.

.PARAMETER Csv
    Also write the guarded CSV of findings alongside the report (same name, .csv extension).
    The CSV embedded behind the report's download button and this sidecar are the same text,
    and every cell passes through the formula-injection guard.

.PARAMETER PassThru
    Emit the computed summary object to the pipeline.

.EXAMPLE
    tools\New-ScanReport.ps1 -Path reports\audit_20260819_143221.json -Title "Acme Ltd — August audit"

.EXAMPLE
    tools\New-ScanReport.ps1 -Path reports\audit_20260819_143221.json `
                             -Compare reports\KrakenBaseline_20260812_090000.json -Csv -PassThru
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,

    [string]$OutFile,

    [string]$Compare,

    [string]$Title,

    [string]$MappingPath,

    [switch]$Csv,

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------------

# Severity display order. Anything not in this map is kept, ranked below INFO, and shown under
# its own label — never dropped (BLUEPRINT §3.3).
$script:ZbSevRank = @{ CRITICAL = 0; HIGH = 1; POSSIBLE = 2; INFO = 3 }
$script:ZbOtherRank = 4

# Phase ceiling per mode. NOTE: this is a copy of the table that already exists in four places
# (BLUEPRINT §6). A fifth copy is unavoidable here because the run record carries only the mode
# string — flagged in HANDOFF_FABLE.md so the owner can decide whether G5's parity test should
# cover this file too. An unknown mode simply suppresses the ceiling commentary.
$script:ZbModeCeiling = @{ QUICK = 30; FULL = 80; DEEP = 133; PARANOID = 133; STEALTH = 133; HUNT = 162 }

# --------------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------------

function Get-ZbProp {
    # Missing keys in the run record are legal (BLUEPRINT §3) — read them without StrictMode
    # explosions and without inventing values.
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
    # Normalised severity bucket: one of the four known levels, or OTHER for anything new.
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

function ConvertTo-ZbHtml {
    # HTML-encode on the way into markup. Description/Target came off the scanned machine.
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $encoded = [System.Net.WebUtility]::HtmlEncode($Text)
    return ($encoded -replace "'", '&#39;')
}

function Protect-ZbCsvCell {
    # The one formula-injection guard: every CSV cell in this tool goes through here.
    # A leading = + - @ TAB or CR is neutralised with a leading apostrophe, because correct
    # CSV quoting alone does not stop a spreadsheet evaluating the cell.
    param([string]$Value)
    if ($null -eq $Value) { $Value = '' }
    if ($Value.Length -gt 0) {
        $first = $Value[0]
        if ($first -eq '=' -or $first -eq '+' -or $first -eq '-' -or $first -eq '@' -or
            $first -eq [char]9 -or $first -eq [char]13) {
            $Value = "'" + $Value
        }
    }
    return '"' + ($Value -replace '"', '""') + '"'
}

function Format-ZbDuration {
    param([double]$Seconds)
    if ($Seconds -le 0) { return 'not recorded' }
    $whole = [int][math]::Floor($Seconds)
    $mins = [int][math]::Floor($whole / 60)
    $secs = $whole % 60
    if ($mins -gt 0) { return ('{0}m {1:d2}s' -f $mins, $secs) }
    return ('{0:0.0}s' -f $Seconds)
}

function Format-ZbNumber {
    # Invariant culture so a comma-decimal locale cannot corrupt embedded values.
    param([double]$Value, [string]$Pattern = '0.0')
    return $Value.ToString($Pattern, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Format-ZbTimestamp {
    # pwsh 7's ConvertFrom-Json turns ISO 8601 strings into [datetime]; Windows PowerShell 5.1
    # leaves them as strings. Normalise so the report shows the same thing on both runtimes,
    # and never a culture-dependent format.
    param($Value)
    if ($Value -is [datetime]) {
        return $Value.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.DateTimeOffset]) {
        return $Value.ToString('yyyy-MM-dd HH:mm:ss zzz', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return ('' + $Value)
}

function Test-ZbGroupCap {
    param($Finding)
    return (('' + (Get-ZbProp $Finding 'ID' '')) -like 'GROUPCAP_*')
}

function Get-ZbGroupLabel {
    # Group defaults to the Phase value when the engine left it blank.
    param($Finding)
    $label = '' + (Get-ZbProp $Finding 'Group' '')
    if ([string]::IsNullOrWhiteSpace($label)) { $label = '' + (Get-ZbProp $Finding 'Phase' '') }
    if ([string]::IsNullOrWhiteSpace($label)) { $label = '(ungrouped)' }
    return $label
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
# Technique resolution (BLUEPRINT §4) — keyword_map, then threat_type_map, then phase_map
# with the fractional key tried before the integer floor. First hit wins.
# --------------------------------------------------------------------------------------------

function Get-ZbPhaseKey {
    param([string]$Phase)
    if ([string]::IsNullOrEmpty($Phase)) { return $null }
    $m = [regex]::Match($Phase, '(\d+(?:\.\d+)?)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Resolve-ZbTechniques {
    param($Finding, $Map)
    # 1. keyword_map — lowercase substring match against the finding's text. _comment keys are
    #    documentation, not data (BLUEPRINT §4).
    $text = ('' + (Get-ZbProp $Finding 'Description' '')).ToLowerInvariant()
    $keywordMap = Get-ZbProp $Map 'keyword_map' $null
    if ($null -ne $keywordMap) {
        foreach ($entry in $keywordMap.PSObject.Properties) {
            if ($entry.Name -like '_comment*') { continue }
            if ($text.Contains($entry.Name.ToLowerInvariant())) { return @($entry.Value) }
        }
    }
    # 2. threat_type_map — by the finding's ThreatType, an opaque string.
    $threatType = '' + (Get-ZbProp $Finding 'ThreatType' '')
    $ttMap = Get-ZbProp $Map 'threat_type_map' $null
    if ($null -ne $ttMap -and $threatType.Length -gt 0) {
        $hit = $ttMap.PSObject.Properties[$threatType]
        if ($null -ne $hit) { return @($hit.Value) }
    }
    # 3. phase_map — fractional key first ("74.5"), then the integer floor ("74").
    $phaseMap = Get-ZbProp $Map 'phase_map' $null
    $phaseKey = Get-ZbPhaseKey -Phase ('' + (Get-ZbProp $Finding 'Phase' ''))
    if ($null -ne $phaseMap -and $null -ne $phaseKey) {
        $hit = $phaseMap.PSObject.Properties[$phaseKey]
        if ($null -ne $hit) { return @($hit.Value) }
        if ($phaseKey.Contains('.')) {
            $floorKey = $phaseKey.Substring(0, $phaseKey.IndexOf('.'))
            $hit = $phaseMap.PSObject.Properties[$floorKey]
            if ($null -ne $hit) { return @($hit.Value) }
        }
    }
    return @()
}

function Resolve-ZbTactic {
    # A finding counts once in the rollup: the first resolved technique that exists in the
    # techniques table decides its tactic. techniques[].tactics holds display names, not TA ids
    # — they are used as-is, which is the direction that does NOT need the inversion trap.
    param($Finding, $Map)
    if ($null -eq $Map) { return $null }
    $ids = @(Resolve-ZbTechniques -Finding $Finding -Map $Map)
    $techniques = Get-ZbProp $Map 'techniques' $null
    if ($null -eq $techniques) { return $null }
    foreach ($id in $ids) {
        $tech = $techniques.PSObject.Properties[('' + $id)]
        if ($null -ne $tech) {
            $tacticNames = @(Get-ZbProp $tech.Value 'tactics' @())
            if ($tacticNames.Count -gt 0) { return ('' + $tacticNames[0]) }
        }
    }
    return $null
}

# --------------------------------------------------------------------------------------------
# The report model: every number computed here, rendered later. -PassThru emits .Summary.
# --------------------------------------------------------------------------------------------

function New-ZbReportModel {
    param($Record, $Map, $Baseline, [string]$MapNotice)

    $allFindings = @(Get-ZbProp $Record 'Findings' @())
    $capRows = @($allFindings | Where-Object { Test-ZbGroupCap $_ })
    $real = @($allFindings | Where-Object { -not (Test-ZbGroupCap $_) })

    # ---- severity counts (flood-cap markers excluded — they are metadata, not findings) ----
    $sevCounts = [ordered]@{ CRITICAL = 0; HIGH = 0; POSSIBLE = 0; INFO = 0; OTHER = 0 }
    foreach ($f in $real) {
        $sevKey = Get-ZbSevKey -Severity (Get-ZbProp $f 'Severity' '')
        $sevCounts[$sevKey] = $sevCounts[$sevKey] + 1
    }

    # ---- groups, ordered the way an operator triages ----
    $rankMap = $script:ZbSevRank
    $groupInfos = @()
    foreach ($g in @($real | Group-Object -Property { Get-ZbGroupLabel $_ })) {
        $members = @($g.Group | Sort-Object -Property @{ Expression = { Get-ZbSevRank (Get-ZbProp $_ 'Severity' '') } }, @{ Expression = { '' + (Get-ZbProp $_ 'ID' '') } })
        $worst = $members[0]
        $groupInfos += [pscustomobject]@{
            Label        = $g.Name
            Count        = $members.Count
            WorstSevKey  = Get-ZbSevKey -Severity (Get-ZbProp $worst 'Severity' '')
            WorstSevText = '' + (Get-ZbProp $worst 'Severity' '')
            Rank         = Get-ZbSevRank -Severity (Get-ZbProp $worst 'Severity' '')
            Example      = '' + (Get-ZbProp $worst 'Description' '')
            Findings     = $members
        }
    }
    $groupsSorted = @($groupInfos | Sort-Object -Property @{ Expression = { $_.Rank } }, @{ Expression = { - $_.Count } }, @{ Expression = { $_.Label } })
    # INFO-only groups stay out of the action list (they are in the full table, collapsed).
    $topGroups = @($groupsSorted | Where-Object { $_.Rank -ne $rankMap['INFO'] } | Select-Object -First 10)

    # ---- tactic rollup: every tactic in the map file, plus an explicit unmapped row ----
    $rollup = [ordered]@{}
    $tacticsTable = Get-ZbProp $Map 'tactics' $null
    if ($null -ne $tacticsTable) {
        foreach ($tp in $tacticsTable.PSObject.Properties) {
            $rollup[('' + $tp.Value)] = [pscustomobject]@{ Tactic = ('' + $tp.Value); CRITICAL = 0; HIGH = 0; POSSIBLE = 0; INFO = 0; OTHER = 0; Total = 0 }
        }
    }
    $unmappedRow = [pscustomobject]@{ Tactic = 'Unmapped'; CRITICAL = 0; HIGH = 0; POSSIBLE = 0; INFO = 0; OTHER = 0; Total = 0 }
    $tacticById = @{}
    foreach ($f in $real) {
        $tacticName = Resolve-ZbTactic -Finding $f -Map $Map
        $row = $unmappedRow
        if ($null -ne $tacticName) {
            if (-not $rollup.Contains($tacticName)) {
                # A technique naming a tactic absent from the tactics table: render it as itself.
                $rollup[$tacticName] = [pscustomobject]@{ Tactic = $tacticName; CRITICAL = 0; HIGH = 0; POSSIBLE = 0; INFO = 0; OTHER = 0; Total = 0 }
            }
            $row = $rollup[$tacticName]
            $tacticById[('' + (Get-ZbProp $f 'ID' ''))] = $tacticName
        }
        $sevKey = Get-ZbSevKey -Severity (Get-ZbProp $f 'Severity' '')
        $row.$sevKey = $row.$sevKey + 1
        $row.Total = $row.Total + 1
    }
    $rollupRows = @(@($rollup.Values) + @($unmappedRow))

    # ---- phase timings, slowest first; retried phases summed with a repeat count ----
    $timingAgg = [ordered]@{}
    foreach ($t in @(Get-ZbProp $Record 'PhaseTimings' @())) {
        $phaseName = '' + (Get-ZbProp $t 'Phase' '')
        $secs = [double](Get-ZbProp $t 'Seconds' 0)
        if (-not $timingAgg.Contains($phaseName)) {
            $timingAgg[$phaseName] = [pscustomobject]@{ Phase = $phaseName; Seconds = 0.0; Runs = 0 }
        }
        $timingAgg[$phaseName].Seconds = $timingAgg[$phaseName].Seconds + $secs
        $timingAgg[$phaseName].Runs = $timingAgg[$phaseName].Runs + 1
    }
    $timings = @(@($timingAgg.Values) | Sort-Object -Property @{ Expression = { - $_.Seconds } }, @{ Expression = { $_.Phase } })
    $phaseCount = $timings.Count
    $wallClock = 0.0
    foreach ($t in $timings) { $wallClock = $wallClock + $t.Seconds }

    $mode = ('' + (Get-ZbProp $Record 'Mode' '')).ToUpperInvariant()
    $ceiling = $null
    if ($script:ZbModeCeiling.ContainsKey($mode)) { $ceiling = $script:ZbModeCeiling[$mode] }
    $shortfall = 0
    if ($null -ne $ceiling -and $phaseCount -lt $ceiling) { $shortfall = $ceiling - $phaseCount }

    # ---- the engine's own tally, cross-checked against a count we compute ourselves ----
    $ownTally = @{}
    foreach ($f in $real) {
        $tt = '' + (Get-ZbProp $f 'ThreatType' '')
        if (-not $ownTally.ContainsKey($tt)) { $ownTally[$tt] = 0 }
        $ownTally[$tt] = $ownTally[$tt] + 1
    }
    $tallyDiffs = @()
    $recTally = Get-ZbProp $Record 'ThreatTally' $null
    if ($null -ne $recTally) {
        foreach ($tp in $recTally.PSObject.Properties) {
            $mine = 0
            if ($ownTally.ContainsKey($tp.Name)) { $mine = $ownTally[$tp.Name] }
            if ([int]$tp.Value -ne $mine) {
                $tallyDiffs += ('{0}: record says {1}, computed {2}' -f $tp.Name, $tp.Value, $mine)
            }
        }
        foreach ($k in $ownTally.Keys) {
            if ($null -eq $recTally.PSObject.Properties[$k]) {
                $tallyDiffs += ('{0}: absent from ThreatTally, computed {1}' -f $k, $ownTally[$k])
            }
        }
    }

    # ---- comparison, joined on ID (stable across runs); Timestamp is never a join key ----
    $comparison = $null
    if ($null -ne $Baseline) {
        $baseReal = @(@(Get-ZbProp $Baseline 'Findings' @()) | Where-Object { -not (Test-ZbGroupCap $_) })
        $baseById = @{}
        foreach ($f in $baseReal) { $baseById[('' + (Get-ZbProp $f 'ID' ''))] = $f }
        $currentIds = @{}
        foreach ($f in $real) { $currentIds[('' + (Get-ZbProp $f 'ID' ''))] = $true }
        $newFindings = @($real | Where-Object { -not $baseById.ContainsKey(('' + (Get-ZbProp $_ 'ID' ''))) })
        $resolvedFindings = @($baseReal | Where-Object { -not $currentIds.ContainsKey(('' + (Get-ZbProp $_ 'ID' ''))) })
        $persisting = $real.Count - $newFindings.Count

        $seriousNow = $sevCounts['CRITICAL'] + $sevCounts['HIGH']
        $seriousBase = 0
        foreach ($f in $baseReal) {
            $sk = Get-ZbSevKey -Severity (Get-ZbProp $f 'Severity' '')
            if ($sk -eq 'CRITICAL' -or $sk -eq 'HIGH') { $seriousBase = $seriousBase + 1 }
        }
        $verdict = 'unchanged'
        if ($seriousNow -lt $seriousBase) { $verdict = 'improved' }
        elseif ($seriousNow -gt $seriousBase) { $verdict = 'worse' }
        else {
            $riskNow = [int](Get-ZbProp $Record 'RiskScore' 0)
            $riskBase = [int](Get-ZbProp $Baseline 'RiskScore' 0)
            if ($riskNow -lt $riskBase) { $verdict = 'improved' }
            elseif ($riskNow -gt $riskBase) { $verdict = 'worse' }
        }
        $comparison = [pscustomobject]@{
            BaselineTimestamp = Format-ZbTimestamp -Value (Get-ZbProp $Baseline 'Timestamp' '')
            NewCount          = $newFindings.Count
            ResolvedCount     = $resolvedFindings.Count
            PersistingCount   = $persisting
            SeriousNow        = $seriousNow
            SeriousBaseline   = $seriousBase
            Verdict           = $verdict
            NewIds            = @($newFindings | ForEach-Object { '' + (Get-ZbProp $_ 'ID' '') })
            ResolvedIds       = @($resolvedFindings | ForEach-Object { '' + (Get-ZbProp $_ 'ID' '') })
            NewFindings       = @($newFindings | Sort-Object -Property @{ Expression = { Get-ZbSevRank (Get-ZbProp $_ 'Severity' '') } }, @{ Expression = { '' + (Get-ZbProp $_ 'ID' '') } })
            ResolvedFindings  = @($resolvedFindings | Sort-Object -Property @{ Expression = { Get-ZbSevRank (Get-ZbProp $_ 'Severity' '') } }, @{ Expression = { '' + (Get-ZbProp $_ 'ID' '') } })
        }
    }

    $clean = ($sevCounts['CRITICAL'] -eq 0 -and $sevCounts['HIGH'] -eq 0)

    $summary = [pscustomobject]@{
        Title             = ''
        Host              = '' + (Get-ZbProp $Record 'Host' '')
        User              = '' + (Get-ZbProp $Record 'User' '')
        Mode              = $mode
        TimeWindow        = '' + (Get-ZbProp $Record 'TimeWindow' '')
        RunTimestamp      = Format-ZbTimestamp -Value (Get-ZbProp $Record 'Timestamp' '')
        RiskScore         = [int](Get-ZbProp $Record 'RiskScore' 0)
        RiskLabel         = '' + (Get-ZbProp $Record 'RiskLabel' '')
        TotalFindings     = $real.Count
        GroupCapCount     = $capRows.Count
        SeverityCounts    = [pscustomobject]@{
            CRITICAL = $sevCounts['CRITICAL']; HIGH = $sevCounts['HIGH']
            POSSIBLE = $sevCounts['POSSIBLE']; INFO = $sevCounts['INFO']; OTHER = $sevCounts['OTHER']
        }
        Clean             = $clean
        GroupCount        = $groupsSorted.Count
        TopGroups         = @($topGroups | Select-Object Label, Count, WorstSevText, Example)
        MappingLoaded     = ($null -ne $Map)
        MappingNotice     = $MapNotice
        TacticRollup      = $rollupRows
        MappedCount       = ($real.Count - $unmappedRow.Total)
        UnmappedCount     = $unmappedRow.Total
        PhaseTimingCount  = $phaseCount
        ModeCeiling       = $ceiling
        PhaseShortfall    = $shortfall
        WallClockSeconds  = [math]::Round($wallClock, 1)
        RecoveredErrors   = @(Get-ZbProp $Record 'RecoveredErrors' @())
        RecoveredErrorCount = @(Get-ZbProp $Record 'RecoveredErrors' @()).Count
        TallyAgrees       = ($tallyDiffs.Count -eq 0)
        TallyDifferences  = $tallyDiffs
        Comparison        = $comparison
        ExecutiveSummary  = ''
        OutFile           = ''
        CsvFile           = $null
    }

    return [pscustomobject]@{
        Summary    = $summary
        Real       = $real
        CapRows    = $capRows
        Groups     = $groupsSorted
        TopGroups  = $topGroups
        Rollup     = $rollupRows
        Timings    = $timings
        TacticById = $tacticById
        Comparison = $comparison
    }
}

# --------------------------------------------------------------------------------------------
# Executive summary — prose, generated from the numbers. Five or six sentences.
# --------------------------------------------------------------------------------------------

function New-ZbExecutiveSummary {
    param($Summary)
    $s = $Summary
    $sentences = @()

    # 1. Phases run, and whether any were skipped.
    if ($null -ne $s.ModeCeiling) {
        if ($s.PhaseShortfall -gt 0) {
            $sentences += ('The {0} scan reported timings for {1} of the {2} checks in its plan — {3} did not report, so treat this run as partial.' -f $s.Mode, $s.PhaseTimingCount, $s.ModeCeiling, $s.PhaseShortfall)
        }
        else {
            $sentences += ('The {0} scan completed all {1} checks in its plan.' -f $s.Mode, $s.ModeCeiling)
        }
    }
    else {
        $sentences += ('The {0} scan reported timings for {1} checks.' -f $s.Mode, $s.PhaseTimingCount)
    }

    # 2. Counts by severity — or the no-findings case, stated plainly.
    if ($s.TotalFindings -eq 0) {
        $sentences += 'It recorded no findings at all: by every check this mode runs, the machine came back clean.'
    }
    else {
        $countText = ('It recorded {0} findings: {1} critical, {2} high, {3} possible and {4} informational' -f $s.TotalFindings, $s.SeverityCounts.CRITICAL, $s.SeverityCounts.HIGH, $s.SeverityCounts.POSSIBLE, $s.SeverityCounts.INFO)
        if ($s.SeverityCounts.OTHER -gt 0) {
            $countText += (', plus {0} carrying a severity label this report does not recognise' -f $s.SeverityCounts.OTHER)
        }
        $sentences += ($countText + '.')

        # 3. Clean answer, or the single worst group.
        if ($s.Clean) {
            $sentences += 'Nothing rose above the "possible" level — there are no critical or high findings on this machine, and that is a clean result.'
        }
        elseif (@($s.TopGroups).Count -gt 0) {
            $tg = @($s.TopGroups)[0]
            $sentences += ('The most serious findings concentrate in "{0}": {1} finding(s), worst severity {2}.' -f $tg.Label, $tg.Count, $tg.WorstSevText)
        }
    }

    # 4. Better or worse than the comparison run, when one was given.
    if ($null -ne $s.Comparison) {
        $c = $s.Comparison
        $verdictText = 'broadly unchanged from'
        if ($c.Verdict -eq 'improved') { $verdictText = ('an improvement on' ) }
        elseif ($c.Verdict -eq 'worse') { $verdictText = ('worse than') }
        $sentences += ('Against the baseline run this is {0} last time: {1} new finding(s), {2} resolved, {3} unchanged, with critical-or-high findings moving from {4} to {5}.' -f $verdictText, $c.NewCount, $c.ResolvedCount, $c.PersistingCount, $c.SeriousBaseline, $c.SeriousNow)
    }

    # 5. Run health caveats worth a sentence.
    if ($s.RecoveredErrorCount -gt 0) {
        $sentences += ('The engine recovered from {0} internal error(s) mid-run; the results stand, but the run-health section lists them.' -f $s.RecoveredErrorCount)
    }
    if ($s.GroupCapCount -gt 0) {
        $sentences += ('{0} noisy group(s) hit the flood cap, so some repetitive rows were suppressed at scan time.' -f $s.GroupCapCount)
    }

    return ($sentences -join ' ')
}

# --------------------------------------------------------------------------------------------
# CSV — built in PowerShell so the guard is testable, embedded for the download button,
# and optionally written alongside the report.
# --------------------------------------------------------------------------------------------

function New-ZbFindingsCsv {
    param($Findings)
    $cols = @('ID', 'Severity', 'Phase', 'Group', 'ThreatType', 'Description', 'Target', 'FixAction', 'FixParam', 'Timestamp')
    $lines = New-Object System.Collections.Generic.List[string]
    $header = @($cols | ForEach-Object { Protect-ZbCsvCell -Value $_ }) -join ','
    $lines.Add($header)
    foreach ($f in $Findings) {
        $cells = @()
        foreach ($c in $cols) {
            $cells += Protect-ZbCsvCell -Value ('' + (Get-ZbProp $f $c ''))
        }
        $lines.Add(($cells -join ','))
    }
    return ($lines -join "`r`n")
}

# --------------------------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------------------------

function Get-ZbSevBadge {
    param([string]$SevText)
    $sevKey = Get-ZbSevKey -Severity $SevText
    $shown = $SevText
    if ([string]::IsNullOrWhiteSpace($shown)) { $shown = 'UNSET' }
    return ('<span class="badge sev-{0}">{1}</span>' -f $sevKey.ToLowerInvariant(), (ConvertTo-ZbHtml $shown))
}

function New-ZbReportHtml {
    param($Model, [string]$TitleText, [string]$CsvText, [string]$CsvName, [string]$SourceName)

    $s = $Model.Summary
    $sb = New-Object System.Text.StringBuilder

    $heading = $TitleText
    if ([string]::IsNullOrWhiteSpace($heading)) { $heading = 'Endpoint audit report — ' + $s.Host }

    # ---------- header ----------
    [void]$sb.Append('<header class="rpt-head">')
    [void]$sb.Append('<h1>' + (ConvertTo-ZbHtml $heading) + '</h1>')
    [void]$sb.Append('<div class="risk"><span class="risk-score">Risk score ' + $s.RiskScore + '</span>')
    if ($s.RiskLabel) { [void]$sb.Append('<span class="risk-label">' + (ConvertTo-ZbHtml $s.RiskLabel) + '</span>') }
    [void]$sb.Append('</div>')
    [void]$sb.Append('<dl class="meta">')
    $metaPairs = @(
        @('Machine', $s.Host), @('Run by', $s.User), @('Mode', $s.Mode),
        @('Time window', $s.TimeWindow), @('Run started', $s.RunTimestamp),
        @('Scan duration', (Format-ZbDuration -Seconds $s.WallClockSeconds))
    )
    foreach ($pair in $metaPairs) {
        [void]$sb.Append('<div><dt>' + (ConvertTo-ZbHtml $pair[0]) + '</dt><dd>' + (ConvertTo-ZbHtml ('' + $pair[1])) + '</dd></div>')
    }
    [void]$sb.Append('</dl></header>')

    # ---------- executive summary ----------
    [void]$sb.Append('<section><h2>Summary</h2>')
    [void]$sb.Append('<p class="exec">' + (ConvertTo-ZbHtml $s.ExecutiveSummary) + '</p>')
    [void]$sb.Append('</section>')

    # ---------- what to do first ----------
    [void]$sb.Append('<section><h2>What to do first</h2>')
    if (@($Model.TopGroups).Count -eq 0) {
        if ($s.TotalFindings -eq 0) {
            [void]$sb.Append('<p class="clean-note">No findings were recorded. There is nothing to action from this run.</p>')
        }
        else {
            [void]$sb.Append('<p class="clean-note">Everything recorded is informational — there is no priority action list for this run.</p>')
        }
    }
    else {
        [void]$sb.Append('<table class="plain"><thead><tr><th>#</th><th>Group</th><th>Worst severity</th><th>Findings</th><th>Example</th></tr></thead><tbody>')
        $rowNum = 0
        foreach ($g in $Model.TopGroups) {
            $rowNum++
            [void]$sb.Append('<tr><td>' + $rowNum + '</td><td>' + (ConvertTo-ZbHtml $g.Label) + '</td><td>' + (Get-ZbSevBadge $g.WorstSevText) + '</td><td class="num">' + $g.Count + '</td><td class="wrap">' + (ConvertTo-ZbHtml $g.Example) + '</td></tr>')
        }
        [void]$sb.Append('</tbody></table>')
        if (@($Model.Groups | Where-Object { $_.Rank -ne $script:ZbSevRank['INFO'] }).Count -gt 10) {
            [void]$sb.Append('<p class="note">Top 10 groups shown; the full findings table below has every group.</p>')
        }
    }
    [void]$sb.Append('</section>')

    # ---------- tactic rollup ----------
    [void]$sb.Append('<section><h2>Technique coverage by tactic</h2>')
    if (-not $s.MappingLoaded) {
        [void]$sb.Append('<p class="warnbox">' + (ConvertTo-ZbHtml $s.MappingNotice) + ' Every finding below is shown as unmapped.</p>')
    }
    [void]$sb.Append('<table class="plain rollup"><thead><tr><th>Tactic</th><th>Critical</th><th>High</th><th>Possible</th><th>Info</th><th>Other</th><th>Total</th></tr></thead><tbody>')
    foreach ($row in $Model.Rollup) {
        $cls = ''
        if ($row.Total -eq 0) { $cls = ' class="empty"' }
        elseif ($row.Tactic -eq 'Unmapped') { $cls = ' class="unmapped"' }
        [void]$sb.Append('<tr' + $cls + '><td>' + (ConvertTo-ZbHtml $row.Tactic) + '</td><td class="num">' + $row.CRITICAL + '</td><td class="num">' + $row.HIGH + '</td><td class="num">' + $row.POSSIBLE + '</td><td class="num">' + $row.INFO + '</td><td class="num">' + $row.OTHER + '</td><td class="num">' + $row.Total + '</td></tr>')
    }
    [void]$sb.Append('</tbody></table>')
    [void]$sb.Append('<p class="note">Empty rows are part of the story: those tactics were checked for and nothing was found. Findings no technique matches are counted in the Unmapped row so every total above reconciles with the summary.</p>')
    [void]$sb.Append('</section>')

    # ---------- full findings table ----------
    [void]$sb.Append('<section><h2>All findings</h2>')
    if ($s.TotalFindings -eq 0) {
        [void]$sb.Append('<p class="clean-note">The findings table is empty: this run recorded nothing on the machine.</p>')
    }
    else {
        if (@($Model.CapRows).Count -gt 0) {
            [void]$sb.Append('<div class="warnbox"><strong>Rows were suppressed at scan time.</strong> These groups hit the flood cap, so their counts here are floors, not totals:<ul>')
            foreach ($cap in $Model.CapRows) {
                [void]$sb.Append('<li>' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $cap 'Description' (Get-ZbProp $cap 'ID' '')))) + '</li>')
            }
            [void]$sb.Append('</ul></div>')
        }
        [void]$sb.Append('<div class="controls">')
        [void]$sb.Append('<input type="search" id="zb-search" placeholder="Filter groups (label or text)&hellip;" aria-label="Filter groups">')
        [void]$sb.Append('<span class="chips">')
        $chipDefs = @(
            @('CRITICAL', $s.SeverityCounts.CRITICAL), @('HIGH', $s.SeverityCounts.HIGH),
            @('POSSIBLE', $s.SeverityCounts.POSSIBLE), @('INFO', $s.SeverityCounts.INFO)
        )
        if ($s.SeverityCounts.OTHER -gt 0) { $chipDefs += , @('OTHER', $s.SeverityCounts.OTHER) }
        foreach ($chip in $chipDefs) {
            [void]$sb.Append('<label class="sevchip sev-' + $chip[0].ToLowerInvariant() + '"><input type="checkbox" value="' + $chip[0] + '" checked> ' + $chip[0] + ' <b>' + $chip[1] + '</b></label>')
        }
        [void]$sb.Append('</span>')
        [void]$sb.Append('<span class="orderer">Order groups by <button type="button" data-order="sev" class="on">severity</button><button type="button" data-order="size">size</button><button type="button" data-order="name">name</button></span>')
        [void]$sb.Append('<button type="button" id="zb-expand">Expand all</button><button type="button" id="zb-collapse">Collapse all</button>')
        [void]$sb.Append('<button type="button" id="zb-csv" title="Download every finding as CSV">Download CSV</button>')
        [void]$sb.Append('</div>')

        [void]$sb.Append('<table class="plain" id="zb-findings"><thead><tr><th>Severity</th><th>ID</th><th>Phase</th><th>Description</th><th>Target</th><th>Suggested action</th></tr></thead>')
        foreach ($g in $Model.Groups) {
            [void]$sb.Append('<tbody class="grp" data-rank="' + $g.Rank + '" data-count="' + $g.Count + '" data-label="' + (ConvertTo-ZbHtml $g.Label.ToLowerInvariant()) + '">')
            [void]$sb.Append('<tr class="ghead"><td colspan="6"><span class="tri" aria-hidden="true"></span>' + (ConvertTo-ZbHtml $g.Label) + ' ' + (Get-ZbSevBadge $g.WorstSevText) + ' <span class="gcount">' + $g.Count + ' finding' + $(if ($g.Count -ne 1) { 's' } else { '' }) + '</span></td></tr>')
            foreach ($f in $g.Findings) {
                $sevText = '' + (Get-ZbProp $f 'Severity' '')
                $sevKey = Get-ZbSevKey -Severity $sevText
                $action = '' + (Get-ZbProp $f 'FixAction' '')
                $fixParam = '' + (Get-ZbProp $f 'FixParam' '')
                if ($fixParam) { $action = $action + ' (' + $fixParam + ')' }
                [void]$sb.Append('<tr class="det" data-sev="' + $sevKey + '">')
                [void]$sb.Append('<td>' + (Get-ZbSevBadge $sevText) + '</td>')
                [void]$sb.Append('<td><code>' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $f 'ID' ''))) + '</code></td>')
                [void]$sb.Append('<td>' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $f 'Phase' ''))) + '</td>')
                [void]$sb.Append('<td class="wrap">' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $f 'Description' ''))) + '</td>')
                [void]$sb.Append('<td class="wrap"><code>' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $f 'Target' ''))) + '</code></td>')
                [void]$sb.Append('<td>' + (ConvertTo-ZbHtml $action) + '</td>')
                [void]$sb.Append('</tr>')
            }
            [void]$sb.Append('</tbody>')
        }
        [void]$sb.Append('</table>')
    }
    [void]$sb.Append('</section>')

    # ---------- run health ----------
    [void]$sb.Append('<section><h2>Run health</h2>')
    if ($s.PhaseShortfall -gt 0) {
        [void]$sb.Append('<p class="warnbox">This ' + (ConvertTo-ZbHtml $s.Mode) + ' run reported timings for ' + $s.PhaseTimingCount + ' of ' + $s.ModeCeiling + ' planned checks. ' + $s.PhaseShortfall + ' checks have no timing entry — coverage may be incomplete.</p>')
    }
    if (-not $s.TallyAgrees) {
        [void]$sb.Append('<p class="warnbox">The record&#39;s own category tally disagrees with a count computed from the findings; the computed counts are used throughout this report. Differences: ' + (ConvertTo-ZbHtml ($s.TallyDifferences -join '; ')) + '</p>')
    }
    [void]$sb.Append('<h3>Recovered errors (' + $s.RecoveredErrorCount + ')</h3>')
    if ($s.RecoveredErrorCount -eq 0) {
        [void]$sb.Append('<p class="note">The engine reported no recovered errors.</p>')
    }
    else {
        [void]$sb.Append('<p class="note">The engine hit these faults and continued. The run completed, but treat the affected areas with suspicion.</p><ul class="errs">')
        foreach ($e in $s.RecoveredErrors) {
            [void]$sb.Append('<li>' + (ConvertTo-ZbHtml ('' + $e)) + '</li>')
        }
        [void]$sb.Append('</ul>')
    }
    [void]$sb.Append('<h3>Where the time went</h3>')
    if (@($Model.Timings).Count -eq 0) {
        [void]$sb.Append('<p class="note">No phase timings were recorded.</p>')
    }
    else {
        [void]$sb.Append('<div class="scrollbox"><table class="plain"><thead><tr><th>Check</th><th>Seconds</th><th>Runs</th></tr></thead><tbody>')
        foreach ($t in $Model.Timings) {
            [void]$sb.Append('<tr><td class="wrap">' + (ConvertTo-ZbHtml $t.Phase) + '</td><td class="num">' + (Format-ZbNumber -Value $t.Seconds) + '</td><td class="num">' + $t.Runs + '</td></tr>')
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    [void]$sb.Append('</section>')

    # ---------- comparison ----------
    if ($null -ne $Model.Comparison) {
        $c = $Model.Comparison
        [void]$sb.Append('<section><h2>Changes since the baseline run</h2>')
        $verdictWord = 'is broadly unchanged'
        if ($c.Verdict -eq 'improved') { $verdictWord = 'has improved' }
        elseif ($c.Verdict -eq 'worse') { $verdictWord = 'has got worse' }
        [void]$sb.Append('<p>Compared with the baseline of ' + (ConvertTo-ZbHtml $c.BaselineTimestamp) + ', this machine ' + $verdictWord + ': <strong>' + $c.NewCount + ' new</strong>, <strong>' + $c.ResolvedCount + ' resolved</strong>, ' + $c.PersistingCount + ' present in both runs. Critical-or-high findings moved from ' + $c.SeriousBaseline + ' to ' + $c.SeriousNow + '.</p>')
        [void]$sb.Append('<h3>New in this run (' + $c.NewCount + ')</h3>')
        if ($c.NewCount -eq 0) {
            [void]$sb.Append('<p class="note">Nothing new appeared since the baseline.</p>')
        }
        else {
            [void]$sb.Append('<table class="plain"><thead><tr><th>Severity</th><th>ID</th><th>Description</th><th>Target</th></tr></thead><tbody>')
            foreach ($f in $c.NewFindings) {
                [void]$sb.Append('<tr><td>' + (Get-ZbSevBadge ('' + (Get-ZbProp $f 'Severity' ''))) + '</td><td><code>' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $f 'ID' ''))) + '</code></td><td class="wrap">' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $f 'Description' ''))) + '</td><td class="wrap"><code>' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $f 'Target' ''))) + '</code></td></tr>')
            }
            [void]$sb.Append('</tbody></table>')
        }
        [void]$sb.Append('<h3>Resolved since the baseline (' + $c.ResolvedCount + ')</h3>')
        if ($c.ResolvedCount -eq 0) {
            [void]$sb.Append('<p class="note">Nothing from the baseline run has cleared.</p>')
        }
        else {
            [void]$sb.Append('<table class="plain"><thead><tr><th>Severity</th><th>ID</th><th>Was</th></tr></thead><tbody>')
            foreach ($f in $c.ResolvedFindings) {
                [void]$sb.Append('<tr><td>' + (Get-ZbSevBadge ('' + (Get-ZbProp $f 'Severity' ''))) + '</td><td><code>' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $f 'ID' ''))) + '</code></td><td class="wrap">' + (ConvertTo-ZbHtml ('' + (Get-ZbProp $f 'Description' ''))) + '</td></tr>')
            }
            [void]$sb.Append('</tbody></table>')
        }
        [void]$sb.Append('</section>')
    }

    [void]$sb.Append('<footer class="rpt-foot">Generated ' + (ConvertTo-ZbHtml (Get-Date -Format 'yyyy-MM-dd HH:mm')) + ' from ' + (ConvertTo-ZbHtml $SourceName) + ' by New-ScanReport.ps1. This file is self-contained and makes no network requests.</footer>')

    $bodyHtml = $sb.ToString()

    # Data island for the inline script. Built with ConvertTo-Json -Compress and the single
    # mandated escape — never a chain of string replacements (see the brief: hand-escaping this
    # once silently killed every interactive feature for months).
    $dataJson = (ConvertTo-Json -Compress -InputObject @{ csv = $CsvText; csvName = $CsvName }) -replace '</', '<\/'

    $css = Get-ZbReportCss
    $js = Get-ZbReportJs
    $docTitle = $TitleText
    if ([string]::IsNullOrWhiteSpace($docTitle)) { $docTitle = 'Audit report — ' + $s.Host }

    $doc = New-Object System.Text.StringBuilder
    [void]$doc.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$doc.Append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    # Belt and braces on the no-network rule: even a hostile Description cannot make this page
    # fetch a remote resource.
    [void]$doc.Append('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; script-src ''unsafe-inline''; img-src data:">')
    [void]$doc.Append('<title>' + (ConvertTo-ZbHtml $docTitle) + '</title>')
    [void]$doc.Append('<style>' + $css + '</style></head><body><main>')
    [void]$doc.Append($bodyHtml)
    [void]$doc.Append('</main><script type="application/json" id="zb-data">' + $dataJson + '</script>')
    [void]$doc.Append('<script>' + $js + '</script></body></html>')
    return $doc.ToString()
}

function Get-ZbReportCss {
    return @'
:root{
  --bg:#f5f6f8; --card:#ffffff; --fg:#1d2833; --muted:#5b6b7b; --line:#d8dee6;
  --accent:#20567a; --warnbg:#fdf3d7; --warnfg:#5c4a12; --warnline:#e0c26a;
  --crit:#a11d11; --high:#b35a00; --poss:#6b6100; --info:#47586a; --other:#5b3d7a;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#12161b; --card:#1a2027; --fg:#dde5ee; --muted:#94a4b5; --line:#2d3945;
    --accent:#7db4d8; --warnbg:#332b14; --warnfg:#e8d9a0; --warnline:#6b5a25;
    --crit:#e05a4e; --high:#e08b3d; --poss:#c9b83a; --info:#8299b0; --other:#a986cf;
  }
}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:72rem;margin:0 auto;padding:1.5rem 1rem 3rem}
h1{font-size:1.5rem;margin:.2rem 0 .6rem}
h2{font-size:1.15rem;margin:0 0 .8rem;color:var(--accent)}
h3{font-size:1rem;margin:1.2rem 0 .4rem}
code{font-family:Consolas,"Cascadia Mono",Menlo,monospace;font-size:.9em;word-break:break-all}
section,header.rpt-head{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:1.1rem 1.25rem;margin-bottom:1rem}
.rpt-head .risk{margin:.3rem 0 .8rem}
.risk-score{font-weight:700;font-size:1.05rem;margin-right:.6rem}
.risk-label{border:1px solid var(--line);border-radius:4px;padding:.1rem .5rem;font-weight:600;letter-spacing:.03em}
dl.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:.5rem 1.2rem;margin:0}
dl.meta dt{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
dl.meta dd{margin:0;font-weight:600;overflow-wrap:anywhere}
p.exec{font-size:1.02rem;margin:0}
.badge{display:inline-block;border-radius:4px;padding:0 .45em;font-size:.75rem;font-weight:700;letter-spacing:.04em;color:#fff;white-space:nowrap}
.badge.sev-critical{background:var(--crit)} .badge.sev-high{background:var(--high)}
.badge.sev-possible{background:var(--poss)} .badge.sev-info{background:var(--info)}
.badge.sev-other{background:var(--other)}
@media (prefers-color-scheme: dark){ .badge{color:#10141a} }
table.plain{width:100%;border-collapse:collapse;font-size:.9rem}
table.plain th{text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:2px solid var(--line);padding:.35rem .5rem}
table.plain td{border-bottom:1px solid var(--line);padding:.4rem .5rem;vertical-align:top}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.wrap{overflow-wrap:anywhere}
tr.empty td{color:var(--muted)}
tr.unmapped td{font-style:italic}
.note{color:var(--muted);font-size:.85rem}
.clean-note{font-weight:600}
.warnbox{background:var(--warnbg);color:var(--warnfg);border:1px solid var(--warnline);border-radius:6px;padding:.6rem .8rem;font-size:.9rem}
.warnbox ul{margin:.4rem 0 0;padding-left:1.2rem}
ul.errs li{overflow-wrap:anywhere;margin-bottom:.3rem}
.scrollbox{max-height:24rem;overflow-y:auto;border:1px solid var(--line);border-radius:6px}
.scrollbox table.plain th{position:sticky;top:0;background:var(--card)}
.controls{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin-bottom:.8rem}
.controls input[type=search]{flex:1 1 14rem;min-width:10rem;padding:.35rem .6rem;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
.controls button{border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:6px;padding:.3rem .7rem;cursor:pointer;font:inherit;font-size:.85rem}
.controls button:hover{border-color:var(--accent)}
.controls button.on{border-color:var(--accent);color:var(--accent);font-weight:700}
.orderer{font-size:.85rem;color:var(--muted);display:inline-flex;gap:.3rem;align-items:center}
.chips{display:inline-flex;gap:.35rem;flex-wrap:wrap}
.sevchip{border:1px solid var(--line);border-radius:999px;padding:.15rem .6rem;font-size:.8rem;cursor:pointer;user-select:none}
.sevchip b{font-variant-numeric:tabular-nums}
.sevchip input{accent-color:var(--accent);vertical-align:-1px}
tbody.grp tr.ghead td{background:var(--bg);font-weight:600;cursor:pointer;border-bottom:1px solid var(--line)}
tbody.grp tr.ghead .gcount{color:var(--muted);font-weight:400;font-size:.85rem}
.tri{display:inline-block;width:.6em;height:.6em;margin-right:.5em;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(-45deg);transition:transform .15s}
tbody.grp.open .tri{transform:rotate(45deg)}
@media (prefers-reduced-motion: reduce){ .tri{transition:none} }
tbody.grp:not(.open) tr.det{display:none}
tbody.grp.gone-q,tbody.grp.gone-sev{display:none}
body.h-CRITICAL tr.det[data-sev="CRITICAL"]{display:none}
body.h-HIGH tr.det[data-sev="HIGH"]{display:none}
body.h-POSSIBLE tr.det[data-sev="POSSIBLE"]{display:none}
body.h-INFO tr.det[data-sev="INFO"]{display:none}
body.h-OTHER tr.det[data-sev="OTHER"]{display:none}
footer.rpt-foot{color:var(--muted);font-size:.8rem;text-align:center;padding:0 1rem}
@media print{
  html,body{background:#fff;color:#000}
  main{max-width:none;padding:0}
  section,header.rpt-head{border:none;border-radius:0;padding:.4rem 0;break-inside:auto}
  .controls,.tri{display:none}
  .scrollbox{max-height:none;overflow:visible;border:none}
  thead{display:table-header-group}
  tr{break-inside:avoid}
  td.wrap,dl.meta dd,ul.errs li{overflow-wrap:break-word;word-break:break-word}
  tbody.grp tr.det{display:table-row}
  .badge{color:#000;background:none;border:1px solid #000;padding:0 .3em}
  a{color:#000}
}
'@
}

function Get-ZbReportJs {
    return @'
(function () {
  'use strict';
  var data = JSON.parse(document.getElementById('zb-data').textContent);
  var body = document.body;
  function qsa(sel, el) { return Array.prototype.slice.call((el || document).querySelectorAll(sel)); }
  var table = document.getElementById('zb-findings');
  if (!table) { return; }  // empty run: nothing interactive except the page itself
  var groups = qsa('tbody.grp', table);

  groups.forEach(function (g) {
    var head = g.querySelector('tr.ghead');
    if (head) {
      head.addEventListener('click', function () { g.classList.toggle('open'); });
    }
  });
  document.getElementById('zb-expand').addEventListener('click', function () {
    groups.forEach(function (g) { g.classList.add('open'); });
  });
  document.getElementById('zb-collapse').addEventListener('click', function () {
    groups.forEach(function (g) { g.classList.remove('open'); });
  });

  function refreshCounts() {
    groups.forEach(function (g) {
      var rows = qsa('tr.det', g);
      var vis = rows.filter(function (tr) {
        return !body.classList.contains('h-' + tr.getAttribute('data-sev'));
      }).length;
      var c = g.querySelector('.gcount');
      if (c) {
        c.textContent = (vis === rows.length)
          ? rows.length + ' finding' + (rows.length === 1 ? '' : 's')
          : vis + ' of ' + rows.length + ' shown';
      }
      g.classList.toggle('gone-sev', vis === 0);
    });
  }
  qsa('.sevchip input').forEach(function (cb) {
    cb.addEventListener('change', function () {
      body.classList.toggle('h-' + cb.value, !cb.checked);
      refreshCounts();
    });
  });

  var box = document.getElementById('zb-search');
  var timer = null;
  box.addEventListener('input', function () {
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(function () {
      var q = box.value.trim().toLowerCase();
      groups.forEach(function (g) {
        var hit = !q || g.textContent.toLowerCase().indexOf(q) !== -1;
        g.classList.toggle('gone-q', !hit);
      });
    }, 150);
  });

  function orderBy(mode) {
    var sorted = groups.slice().sort(function (a, b) {
      if (mode === 'size') { return (+b.getAttribute('data-count')) - (+a.getAttribute('data-count')); }
      if (mode === 'name') { return a.getAttribute('data-label') < b.getAttribute('data-label') ? -1 : 1; }
      var r = (+a.getAttribute('data-rank')) - (+b.getAttribute('data-rank'));
      return r !== 0 ? r : (+b.getAttribute('data-count')) - (+a.getAttribute('data-count'));
    });
    sorted.forEach(function (g) { table.appendChild(g); });
  }
  qsa('button[data-order]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      qsa('button[data-order]').forEach(function (x) { x.classList.remove('on'); });
      btn.classList.add('on');
      orderBy(btn.getAttribute('data-order'));
    });
  });

  var csvBtn = document.getElementById('zb-csv');
  if (csvBtn) {
    csvBtn.addEventListener('click', function () {
      var blob = new Blob([data.csv], { type: 'text/csv' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = data.csvName;
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    });
  }

  refreshCounts();
})();
'@
}

# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------

$record = Import-ZbRunRecord -RecordPath $Path -Label 'Run record'
$sourceFull = Get-ZbFullPath -AnyPath $Path

# Resolve the technique map. Missing or broken → warn, keep going, mark everything unmapped.
$map = $null
$mapNotice = ''
$resolvedMapPath = $MappingPath
if ([string]::IsNullOrWhiteSpace($resolvedMapPath)) {
    $resolvedMapPath = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'data/mitre_mapping.json'
}
if (Test-Path -LiteralPath $resolvedMapPath) {
    try {
        $map = Get-Content -LiteralPath $resolvedMapPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        $map = $null
        $mapNotice = "The technique map at '$resolvedMapPath' could not be read as JSON."
    }
}
else {
    $mapNotice = "The technique map was not found at '$resolvedMapPath'."
}
if ($null -eq $map) {
    Write-Warning ($mapNotice + ' The report will be generated with every finding unmapped.')
}

$baseline = $null
if (-not [string]::IsNullOrWhiteSpace($Compare)) {
    $baseline = Import-ZbRunRecord -RecordPath $Compare -Label 'Baseline run record'
}

$model = New-ZbReportModel -Record $record -Map $map -Baseline $baseline -MapNotice $mapNotice
$model.Summary.Title = $Title
$model.Summary.ExecutiveSummary = New-ZbExecutiveSummary -Summary $model.Summary

# Output paths.
if ([string]::IsNullOrWhiteSpace($OutFile)) {
    if ($sourceFull -match '\.json$') { $OutFile = $sourceFull -replace '\.json$', '_report.html' }
    else { $OutFile = $sourceFull + '_report.html' }
}
$outFull = Get-ZbFullPath -AnyPath $OutFile
$outDir = Split-Path -Path $outFull -Parent
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
$csvName = [System.IO.Path]::GetFileNameWithoutExtension($outFull) + '.csv'

$csvText = New-ZbFindingsCsv -Findings $model.Real
$html = New-ZbReportHtml -Model $model -TitleText $Title -CsvText $csvText -CsvName $csvName -SourceName (Split-Path -Path $sourceFull -Leaf)

# Report and CSV are data files: UTF-8 without BOM (only .ps1 sources carry a BOM).
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outFull, $html, $utf8NoBom)
$model.Summary.OutFile = $outFull
Write-Host ("Report written: {0}" -f $outFull)

if ($Csv) {
    $csvFull = Join-Path -Path $outDir -ChildPath $csvName
    [System.IO.File]::WriteAllText($csvFull, $csvText, $utf8NoBom)
    $model.Summary.CsvFile = $csvFull
    Write-Host ("CSV written:    {0}" -f $csvFull)
}

if ($PassThru) {
    $model.Summary
}
