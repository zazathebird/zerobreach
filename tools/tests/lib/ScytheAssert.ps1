<#
.SYNOPSIS
    Shared assertion helpers for the Scythe test suite. Dot-source, don't run.

.DESCRIPTION
    . "$PSScriptRoot/lib/ScytheAssert.ps1"

    Every helper records a structured result — name, section, outcome, expected, actual, and
    the source location — into a collection; the console line is rendered FROM that record,
    never the other way round. Read the collection with Get-ScytheResults, write it to disk with
    Export-ScytheResults (JSON — the hand-off tools/tests/New-TestReport.ps1 consumes), and end
    the run with Complete-ScytheTestRun, which renders the summary and exits non-zero on any
    failure OR empty-input outcome.

    Outcomes: 'pass', 'fail', and 'empty'. 'empty' means the input never loaded — $null, or
    an empty string where a value was required. It exists because `-match ''` is true and
    `'' -eq ''` is true, so a table that failed to load makes comparisons pass for entirely
    the wrong reason; 'empty' is a failure with its own name, never a skip. To assert that
    something is genuinely empty, phrase it as a boolean: Assert-ScytheTrue ($x.Count -eq 0).

    Helper names are all several characters long, deliberately: single-letter function names
    lose command resolution to built-in aliases (H is Get-History) and the assertion silently
    never runs. Test-ScytheAssert.ps1 asserts this file defines no such name.
#>

# Dot-sourcing runs this in the caller's scope, so each test file gets its own state.
$script:ScytheAssertResults = New-Object System.Collections.ArrayList
$script:ScytheAssertSection = ''

function Reset-ScytheResults {
    # Start a fresh collection (used by the library's own tests).
    $script:ScytheAssertResults = New-Object System.Collections.ArrayList
    $script:ScytheAssertSection = ''
}

function Set-ScytheSection {
    # Group the assertions that follow under one heading, in the records and on the console.
    param([Parameter(Mandatory = $true)][string]$Name)
    $script:ScytheAssertSection = $Name
    Write-Host $Name
}

function Get-ScytheResults {
    # A snapshot copy — mutating the live collection after reading must not change what the
    # reader already holds.
    return , $script:ScytheAssertResults.ToArray()
}

function Get-ScytheCallSite {
    # The first stack frame outside this library: the test line that made the claim.
    $frames = @(Get-PSCallStack)
    foreach ($fr in $frames) {
        $sn = [string]$fr.ScriptName
        if ([string]::IsNullOrEmpty($sn)) { continue }
        if ([System.IO.Path]::GetFileName($sn) -ne 'ScytheAssert.ps1') {
            return @{ File = [System.IO.Path]::GetFileName($sn); Line = [int]$fr.ScriptLineNumber }
        }
    }
    return @{ File = ''; Line = 0 }
}

function Limit-ScytheText {
    # Failure output must carry the actual value, but a 100 KB actual helps nobody.
    param($Value)
    $text = '' + $Value
    if ($text.Length -gt 500) { return ($text.Substring(0, 500) + '…[truncated]') }
    return $text
}

function Add-ScytheResult {
    # The single recorder every helper goes through. The record is the result; the console
    # line is rendered from the record.
    param([string]$Name, [string]$Outcome, $Expected, $Actual)
    $site = Get-ScytheCallSite
    $rec = New-Object PSObject -Property @{
        Name     = $Name
        Section  = $script:ScytheAssertSection
        Outcome  = $Outcome
        Expected = (Limit-ScytheText -Value $Expected)
        Actual   = (Limit-ScytheText -Value $Actual)
        File     = [string]$site.File
        Line     = [int]$site.Line
    }
    [void]$script:ScytheAssertResults.Add($rec)
    if ($rec.Outcome -eq 'pass') {
        Write-Host ('  ok    ' + $rec.Name)
    }
    elseif ($rec.Outcome -eq 'empty') {
        Write-Host ('  EMPTY ' + $rec.Name + " — input was null or empty (expected '" + $rec.Expected + "'); treated as a failure")
    }
    else {
        Write-Host ('  FAIL  ' + $rec.Name + " (expected '" + $rec.Expected + "', got '" + $rec.Actual + "')")
    }
}

function Assert-ScytheTrue {
    param($Condition, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Condition) {
        Add-ScytheResult -Name $Name -Outcome 'empty' -Expected 'True' -Actual '(null)'
        return
    }
    if ([bool]$Condition) {
        Add-ScytheResult -Name $Name -Outcome 'pass' -Expected 'True' -Actual 'True'
    }
    else {
        Add-ScytheResult -Name $Name -Outcome 'fail' -Expected 'True' -Actual 'False'
    }
}

function Assert-ScytheFalse {
    param($Condition, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Condition) {
        Add-ScytheResult -Name $Name -Outcome 'empty' -Expected 'False' -Actual '(null)'
        return
    }
    if (-not [bool]$Condition) {
        Add-ScytheResult -Name $Name -Outcome 'pass' -Expected 'False' -Actual 'False'
    }
    else {
        Add-ScytheResult -Name $Name -Outcome 'fail' -Expected 'False' -Actual 'True'
    }
}

function Assert-ScytheEqual {
    # String-compared, like the suite has always done. A null or empty-string actual is the
    # 'empty' outcome even when the expected side is empty too — '' -eq '' passing is exactly
    # the failed-to-load trap this outcome exists for.
    param($Expected, $Actual, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Actual -or (('' + $Actual).Length -eq 0)) {
        Add-ScytheResult -Name $Name -Outcome 'empty' -Expected $Expected -Actual '(null or empty)'
        return
    }
    if (('' + $Expected) -eq ('' + $Actual)) {
        Add-ScytheResult -Name $Name -Outcome 'pass' -Expected $Expected -Actual $Actual
    }
    else {
        Add-ScytheResult -Name $Name -Outcome 'fail' -Expected $Expected -Actual $Actual
    }
}

function Assert-ScytheContains {
    param($Collection, $Item, [Parameter(Mandatory = $true)][string]$Name)
    $arr = @($Collection)
    if ($null -eq $Collection -or $arr.Count -eq 0) {
        Add-ScytheResult -Name $Name -Outcome 'empty' -Expected ('collection containing ''' + $Item + '''') -Actual '(null or empty collection)'
        return
    }
    if ($arr -contains $Item) {
        Add-ScytheResult -Name $Name -Outcome 'pass' -Expected ('contains ''' + $Item + '''') -Actual ('contains ''' + $Item + '''')
    }
    else {
        Add-ScytheResult -Name $Name -Outcome 'fail' -Expected ('contains ''' + $Item + '''') -Actual (@($arr | Select-Object -First 20) -join ', ')
    }
}

function Assert-ScytheMatch {
    # Both sides must be non-empty: -match '' is true, so an empty pattern (a pattern table
    # that failed to load) would match everything and pass for the wrong reason.
    param($Text, $Pattern, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Text -or (('' + $Text).Length -eq 0)) {
        Add-ScytheResult -Name $Name -Outcome 'empty' -Expected ('text matching ''' + $Pattern + '''') -Actual '(null or empty text)'
        return
    }
    if ($null -eq $Pattern -or (('' + $Pattern).Length -eq 0)) {
        Add-ScytheResult -Name $Name -Outcome 'empty' -Expected 'a non-empty pattern' -Actual '(null or empty pattern)'
        return
    }
    if (('' + $Text) -match $Pattern) {
        Add-ScytheResult -Name $Name -Outcome 'pass' -Expected ('matches ''' + $Pattern + '''') -Actual (Limit-ScytheText -Value $Text)
    }
    else {
        Add-ScytheResult -Name $Name -Outcome 'fail' -Expected ('matches ''' + $Pattern + '''') -Actual (Limit-ScytheText -Value $Text)
    }
}

function Assert-ScytheThrows {
    param([scriptblock]$Script, [string]$MessageLike, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Script) {
        Add-ScytheResult -Name $Name -Outcome 'empty' -Expected 'a script block that throws' -Actual '(null script block)'
        return
    }
    $threw = $false
    $msg = ''
    try { & $Script | Out-Null } catch { $threw = $true; $msg = $_.Exception.Message }
    if (-not $threw) {
        Add-ScytheResult -Name $Name -Outcome 'fail' -Expected 'a thrown error' -Actual 'no error was thrown'
        return
    }
    if (-not [string]::IsNullOrEmpty($MessageLike) -and -not ($msg -like $MessageLike)) {
        Add-ScytheResult -Name $Name -Outcome 'fail' -Expected ('error message like ''' + $MessageLike + '''') -Actual $msg
        return
    }
    Add-ScytheResult -Name $Name -Outcome 'pass' -Expected 'a thrown error' -Actual $msg
}

function Export-ScytheResults {
    # The machine-readable hand-off: a JSON array of the records, UTF-8 without BOM, for
    # New-TestReport.ps1 (or anything else that wants to gate on the suite).
    param([Parameter(Mandatory = $true)][string]$Path)
    $records = Get-ScytheResults
    $json = ConvertTo-Json -InputObject @($records) -Depth 4
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function Complete-ScytheTestRun {
    # Render the summary from the collection and exit: non-zero on any failure or
    # empty-input outcome. 'empty' is never a skip.
    param([string]$ExportPath)
    if (-not [string]::IsNullOrEmpty($ExportPath)) { Export-ScytheResults -Path $ExportPath }
    $records = Get-ScytheResults
    $passCount = @($records | Where-Object { $_.Outcome -eq 'pass' }).Count
    $failCount = @($records | Where-Object { $_.Outcome -eq 'fail' }).Count
    $emptyCount = @($records | Where-Object { $_.Outcome -eq 'empty' }).Count
    Write-Host ''
    Write-Host ('{0} passed, {1} failed, {2} empty-input' -f $passCount, $failCount, $emptyCount)
    $bad = @($records | Where-Object { $_.Outcome -ne 'pass' })
    if ($bad.Count -gt 0) {
        Write-Host 'Failed assertions:'
        foreach ($r in $bad) {
            Write-Host ('  - [' + $r.Outcome + '] ' + $r.Name + " (expected '" + $r.Expected + "', got '" + $r.Actual + "') at " + $r.File + ':' + $r.Line)
        }
        exit 1
    }
    exit 0
}
