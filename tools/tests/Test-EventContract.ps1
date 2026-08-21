<#
.SYNOPSIS
    Contract test for the server -> browser event payloads.

.DESCRIPTION
    The SSE event contract (BLUEPRINT §6) is the one agreement three codebases must honour:
    both servers emit these events, the front end reads them. Drift is silent — a renamed
    payload field just makes part of the UI go blank.

    What runs today (decision 2026-08-20 — ship documented scope, stub the rest visibly):

      * The published contract is encoded once below ($ZbEventContract). This is the CONTRACT,
        not an extraction target — the §6 table is the specification the sources must meet.
        (The prohibition on restating source tables applies to the mirrored ceiling numbers,
        which Test-ServerParity.ps1 extracts; a contract test needs its contract.)
      * Comparison machinery: required-vs-available field checks with named reports, plus the
        non-empty guard (an unloaded field set must fail, not agree vacuously).
      * Built-in fail-on-revert: synthetic payload sets — one conforming, one with a field
        removed, one empty — prove the machinery catches what it claims to catch.
      * Sanity rules from §6 that are checkable against the contract itself: payload fields
        are snake_case (the run record is PascalCase — a real inconsistency, not a typo; do
        not "fix" it), and scan_complete / scan_failed are distinct events.

    PENDING — needs one paste each from the owner before the source-extraction assertions
    (brief items 6, 7, 8) can be implemented without guessing syntax:
      - how each server constructs each event payload (variable/emit-call shape)
      - which fields the front end reads off each event
      - the route list the front end calls, and the server's request-handler route table
      - the authenticated wrapper's name for /api/ calls
    Each has a disabled entry in $ZbPendingExtractors; enabling one unimplemented fails the
    run rather than passing vacuously.

.PARAMETER Root
    Reserved for the real-tree run once the pending extractors are configured. Accepted and
    recorded today so the invocation the owner will use is already the right one.

.EXAMPLE
    pwsh tools/tests/Test-EventContract.ps1
#>
[CmdletBinding()]
param(
    [string]$Root
)

$ErrorActionPreference = 'Stop'

$script:ZbPass = 0
$script:ZbFail = 0
$script:ZbFailures = @()

function Assert-ZbTrue {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:ZbPass = $script:ZbPass + 1
        Write-Host ('  ok    ' + $Name)
    }
    else {
        $script:ZbFail = $script:ZbFail + 1
        $script:ZbFailures += $Name
        Write-Host ('  FAIL  ' + $Name)
    }
}

# --------------------------------------------------------------------------------------------
# The published contract (BLUEPRINT §6). Fields are snake_case on purpose.
# --------------------------------------------------------------------------------------------

$ZbEventContract = [ordered]@{
    log_line             = @('text', 'severity', 'phase', 'elapsed')
    finding              = @('id', 'line', 'severity', 'threat_type', 'phase', 'mitre', 'mitre_id', 'fix_action', 'target', 'timestamp')
    scan_state           = @('phase', 'phase_total', 'phase_name', 'section', 'elapsed', 'threat_counts', 'running')
    scan_complete        = @('findings_count', 'threat_counts', 'elapsed', 'results_path', 'engine_report')
    scan_failed          = @()   # emitted INSTEAD OF scan_complete; the distinction is the contract
    remediation_complete = @('applied', 'failed', 'skipped', 'blocked')
    sync                 = @()   # full state snapshot on connect/reconnect; shape not enumerated in §6
}

$ZbPendingExtractors = @(
    @{ Name = 'PowerShell server payload construction per event'; Enabled = $false
       Need = 'the emit-call / hashtable shape used in ZeroBreach-Server.ps1 for one event (the rest follow the pattern)' },
    @{ Name = 'Python server payload construction per event'; Enabled = $false
       Need = 'the emit-call / dict shape used in _python/server.py for one event' },
    @{ Name = 'front-end event field reads'; Enabled = $false
       Need = 'how gui/templates/index.html reads an event (e.g. data.field vs destructuring), one example' },
    @{ Name = 'front-end route calls vs server request handler'; Enabled = $false
       Need = 'the /api/ route list shape in the front end and the request-handler dispatch shape in the PowerShell server' },
    @{ Name = 'authenticated /api/ wrapper'; Enabled = $false
       Need = 'the wrapper function name the front end must route every /api/ call through' }
)

# --------------------------------------------------------------------------------------------
# Machinery
# --------------------------------------------------------------------------------------------

function Compare-ZbFieldSets {
    # Required: the fields a reader depends on. Available: the fields a payload carries.
    # Returns human-readable problem strings; empty means the contract holds.
    param([string]$Context, $Required, $Available)
    $problems = @()
    if ($null -eq $Available) {
        $problems += ($Context + ': payload field set not loaded — must fail, not agree vacuously')
        return $problems
    }
    $availableSet = @{}
    foreach ($f in @($Available)) { $availableSet[('' + $f)] = $true }
    if (@($Required).Count -gt 0 -and $availableSet.Count -eq 0) {
        $problems += ($Context + ': payload carries no fields at all')
        return $problems
    }
    foreach ($f in @($Required)) {
        if (-not $availableSet.ContainsKey(('' + $f))) {
            $problems += ($Context + ': required field "' + $f + '" missing from payload')
        }
    }
    return $problems
}

# --------------------------------------------------------------------------------------------
# Contract sanity — checkable today, against the contract itself
# --------------------------------------------------------------------------------------------

Write-Host 'contract sanity'
Assert-ZbTrue (@($ZbEventContract.Keys).Count -ge 7) 'contract carries all seven documented events'
Assert-ZbTrue ($ZbEventContract.Contains('scan_complete') -and $ZbEventContract.Contains('scan_failed')) 'scan_complete and scan_failed are distinct events (a failed run must never render clean)'

$badCase = @()
foreach ($eventName in $ZbEventContract.Keys) {
    foreach ($field in @($ZbEventContract[$eventName])) {
        if ($field -cmatch '[A-Z]') { $badCase += ($eventName + '.' + $field) }
    }
    if ($eventName -cmatch '[A-Z]') { $badCase += $eventName }
}
Assert-ZbTrue ($badCase.Count -eq 0) 'events and payload fields are snake_case (the run record is PascalCase; both are correct, do not unify)'

# --------------------------------------------------------------------------------------------
# Built-in fail-on-revert: the machinery must catch what it claims to catch
# --------------------------------------------------------------------------------------------

Write-Host 'self-proof (synthetic payload sets)'

# A conforming synthetic server: every event carries at least the contract fields.
$conforming = @{}
foreach ($eventName in $ZbEventContract.Keys) {
    $conforming[$eventName] = @($ZbEventContract[$eventName]) + @('extra_internal_field')
}
$cleanProblems = @()
foreach ($eventName in $ZbEventContract.Keys) {
    $cleanProblems += Compare-ZbFieldSets -Context ('conforming.' + $eventName) -Required $ZbEventContract[$eventName] -Available $conforming[$eventName]
}
Assert-ZbTrue (@($cleanProblems).Count -eq 0) 'a conforming payload set passes (extra internal fields are allowed)'

# The revert case: scan_complete loses threat_counts — the browser banner logic goes blind.
$broken = @($conforming['scan_complete'] | Where-Object { $_ -ne 'threat_counts' })
$brokenProblems = @(Compare-ZbFieldSets -Context 'broken.scan_complete' -Required $ZbEventContract['scan_complete'] -Available $broken)
Assert-ZbTrue (@($brokenProblems).Count -eq 1) 'a removed payload field is caught'
Assert-ZbTrue ((@($brokenProblems) -join ' ').Contains('threat_counts')) 'the report names the missing field'

# The vacuous case: an unloaded field set must fail loudly.
$nullProblems = @(Compare-ZbFieldSets -Context 'unloaded.finding' -Required $ZbEventContract['finding'] -Available $null)
Assert-ZbTrue (@($nullProblems).Count -gt 0) 'an unloaded field set fails instead of agreeing vacuously'
$emptyProblems = @(Compare-ZbFieldSets -Context 'empty.finding' -Required $ZbEventContract['finding'] -Available @())
Assert-ZbTrue (@($emptyProblems).Count -gt 0) 'an empty field set fails instead of agreeing vacuously'

# --------------------------------------------------------------------------------------------
# Pending extractors
# --------------------------------------------------------------------------------------------

Write-Host ''
if (-not [string]::IsNullOrWhiteSpace($Root)) {
    Write-Host ('NOTE: -Root "' + $Root + '" recorded, but the source extractors below are not yet configured — nothing was read from the tree.')
}
Write-Host 'PENDING (owner input needed — see HANDOFF_FABLE.md G5 entry):'
foreach ($extractor in $ZbPendingExtractors) {
    if ($extractor.Enabled) {
        Assert-ZbTrue $false ('pending extractor enabled but not implemented: ' + $extractor.Name)
    }
    else {
        Write-Host ('  todo  ' + $extractor.Name + ' — needs: ' + $extractor.Need)
    }
}

# --------------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------------

Write-Host ''
Write-Host ('{0} passed, {1} failed, {2} pending extractors' -f $script:ZbPass, $script:ZbFail, @($ZbPendingExtractors | Where-Object { -not $_.Enabled }).Count)
if ($script:ZbFail -gt 0) {
    Write-Host 'Failed assertions:'
    foreach ($f in $script:ZbFailures) { Write-Host ('  - ' + $f) }
    exit 1
}
exit 0
