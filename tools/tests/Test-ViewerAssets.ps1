<#
.SYNOPSIS
    Asset and policy assertions for the offline report viewer (gui/viewer.html + assets).

.DESCRIPTION
    Runs on Linux under pwsh 7 and on Windows PowerShell 5.1. These are source-level
    assertions against the three shipped files:

      1. No absolute http:/https: URL anywhere — the no-remote-origins product rule.
      2. Every <script src> and <link href> in viewer.html stays inside gui/static/.
      3. Every innerHTML assignment in viewer.js is fed by escHtml() in the same statement
         (or is a pure static literal). The scanner is itself proven against an embedded
         deliberately-unsafe sample — the "deliberately failing case" the brief requires.
      4. escHtml covers all five characters: & < > " ' — four is the usual mistake.
      5. The CSV guard's character class neutralises all six dangerous leading characters.

.EXAMPLE
    pwsh tools/tests/Test-ViewerAssets.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:ScythePass = 0
$script:ScytheFail = 0
$script:ScytheFailures = @()

function Assert-ScytheTrue {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:ScythePass = $script:ScythePass + 1
        Write-Host ('  ok    ' + $Name)
    }
    else {
        $script:ScytheFail = $script:ScytheFail + 1
        $script:ScytheFailures += $Name
        Write-Host ('  FAIL  ' + $Name)
    }
}

function Assert-ScytheEqual {
    param($Expected, $Actual, [string]$Name)
    Assert-ScytheTrue -Condition (('' + $Expected) -eq ('' + $Actual)) -Name ($Name + " (expected '$Expected', got '$Actual')")
}

$projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$htmlPath = Join-Path -Path $projectRoot -ChildPath 'gui/viewer.html'
$jsPath = Join-Path -Path $projectRoot -ChildPath 'gui/static/js/viewer.js'
$cssPath = Join-Path -Path $projectRoot -ChildPath 'gui/static/css/viewer.css'

$html = Get-Content -LiteralPath $htmlPath -Raw -Encoding UTF8
$js = Get-Content -LiteralPath $jsPath -Raw -Encoding UTF8
$css = Get-Content -LiteralPath $cssPath -Raw -Encoding UTF8

# --------------------------------------------------------------------------------------------
# 1. No remote origins, anywhere, in any of the three files
# --------------------------------------------------------------------------------------------

Write-Host 'no remote origins'
foreach ($pair in @(@('viewer.html', $html), @('viewer.js', $js), @('viewer.css', $css))) {
    $hits = [regex]::Matches($pair[1], '(?i)https?:')
    Assert-ScytheEqual 0 $hits.Count ('no http:/https: URL in ' + $pair[0])
}
Assert-ScytheEqual 0 ([regex]::Matches($html + $js + $css, '(?i)\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon)\b').Count) 'no network APIs used at all'
Assert-ScytheEqual 0 ([regex]::Matches($css, '(?i)@import|url\(').Count) 'viewer.css pulls in no other resources'

# --------------------------------------------------------------------------------------------
# 2. Every script src / link href stays inside gui/static/
# --------------------------------------------------------------------------------------------

Write-Host 'local references only'
$refs = [regex]::Matches($html, '(?i)<(?:script[^>]*\ssrc|link[^>]*\shref)\s*=\s*"([^"]+)"')
Assert-ScytheTrue ($refs.Count -ge 3) 'viewer.html references its stylesheet(s) and script'
foreach ($m in $refs) {
    $target = $m.Groups[1].Value
    Assert-ScytheTrue ($target -like 'static/*') ('reference stays inside gui/static/: ' + $target)
}
$mainLink = $html.IndexOf('href="static/css/main.css"')
$viewerLink = $html.IndexOf('href="static/css/viewer.css"')
Assert-ScytheTrue ($mainLink -ge 0 -and $viewerLink -ge 0 -and $mainLink -lt $viewerLink) 'main.css linked before viewer.css so product tokens win'

# --------------------------------------------------------------------------------------------
# 3. Every innerHTML write is fed by escHtml() in the same statement
# --------------------------------------------------------------------------------------------

function Get-ScytheInnerHtmlViolation {
    # Returns the offending statements: each ".innerHTML =" assignment whose statement text
    # (up to the terminating semicolon) neither calls escHtml( nor is a pure static literal.
    param([string]$JsText)
    $violations = @()
    $searchFrom = 0
    while ($true) {
        $idx = $JsText.IndexOf('.innerHTML', $searchFrom)
        if ($idx -lt 0) { break }
        $endIdx = $JsText.IndexOf(';', $idx)
        if ($endIdx -lt 0) { $endIdx = $JsText.Length - 1 }
        $statement = $JsText.Substring($idx, $endIdx - $idx + 1)
        $searchFrom = $idx + 10
        if ($statement -notmatch '=') { continue }   # a read, not a write
        if ($statement.Contains('escHtml(')) { continue }
        $rhs = ($statement -split '=', 2)[1].Trim().TrimEnd(';').Trim()
        # A pure static literal (no interpolation, no concatenation) carries no data.
        if ($rhs -match "^'[^'+]*'$") { continue }
        $violations += $statement
    }
    return $violations
}

Write-Host 'innerHTML discipline'
$bad = @(Get-ScytheInnerHtmlViolation -JsText $js)
Assert-ScytheEqual 0 $bad.Count 'every innerHTML write in viewer.js is escHtml-fed or static'
if ($bad.Count -gt 0) {
    foreach ($b in $bad) { Write-Host ('        offending: ' + $b) }
}

# The deliberately failing case: prove the scanner actually catches an unsafe write.
$unsafeSample = 'el.innerHTML = ' + "'<b>' + userValue + '</b>';"
$caught = @(Get-ScytheInnerHtmlViolation -JsText $unsafeSample)
Assert-ScytheEqual 1 $caught.Count 'scanner flags a deliberately unsafe innerHTML sample'
$safeSample = 'el.innerHTML = ' + "'<b>' + escHtml(userValue) + '</b>';"
Assert-ScytheEqual 0 (@(Get-ScytheInnerHtmlViolation -JsText $safeSample)).Count 'scanner passes the escaped twin of the same sample'

# --------------------------------------------------------------------------------------------
# 4. escHtml covers all five characters
# --------------------------------------------------------------------------------------------

Write-Host 'escaping helper'
$escStart = $js.IndexOf('function escHtml')
Assert-ScytheTrue ($escStart -ge 0) 'escHtml helper exists'
$escBody = $js.Substring($escStart, [math]::Min(600, $js.Length - $escStart))
foreach ($entity in @('&amp;', '&lt;', '&gt;', '&quot;', '&#39;')) {
    Assert-ScytheTrue ($escBody.Contains($entity)) ('escHtml emits ' + $entity)
}
foreach ($pattern in @('/&/g', '/</g', '/>/g', '/"/g', "/'/g")) {
    Assert-ScytheTrue ($escBody.Contains($pattern)) ('escHtml replaces ' + $pattern)
}

# --------------------------------------------------------------------------------------------
# 5. CSV guard neutralises all six dangerous leading characters
# --------------------------------------------------------------------------------------------

Write-Host 'csv guard'
$csvStart = $js.IndexOf('function csvCell')
Assert-ScytheTrue ($csvStart -ge 0) 'csvCell helper exists'
$csvBody = $js.Substring($csvStart, [math]::Min(600, $js.Length - $csvStart))
$classMatch = [regex]::Match($csvBody, '\^\[([^\]]+)\]')
Assert-ScytheTrue ($classMatch.Success) 'csvCell anchors a leading-character class'
$charClass = $classMatch.Groups[1].Value
foreach ($ch in @('=', '+', '\-', '@', '\t', '\r')) {
    Assert-ScytheTrue ($charClass.Contains($ch)) ('csv guard neutralises leading ' + $ch)
}
Assert-ScytheTrue ($csvBody.Contains('""')) 'csvCell doubles embedded quotes'

# --------------------------------------------------------------------------------------------
# Accessibility and responsiveness constraints that are checkable at source level
# --------------------------------------------------------------------------------------------

Write-Host 'constraints'
Assert-ScytheTrue ($css.Contains('prefers-reduced-motion')) 'viewer.css honours prefers-reduced-motion'
Assert-ScytheTrue ($css.Contains('focus-visible')) 'viewer.css keeps a visible focus indicator'
Assert-ScytheTrue ($css.Contains('prefers-color-scheme')) 'viewer.css carries a dark palette of its own'
Assert-ScytheTrue ($js.Contains('PAGE_SIZE')) 'flat view is paginated'
Assert-ScytheTrue ($js.Contains("state.open")) 'grouped view renders rows lazily (open-group map)'
Assert-ScytheTrue ($js.Contains('GROUPCAP_')) 'flood-cap markers are recognised and set aside'
Assert-ScytheTrue ($js.Contains('replaceState')) 'filter state is written to the URL fragment'
Assert-ScytheTrue ($js.Contains('decodeURIComponent')) 'fragment values are decoded defensively'

# --------------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------------

Write-Host ''
Write-Host ('{0} passed, {1} failed' -f $script:ScythePass, $script:ScytheFail)
if ($script:ScytheFail -gt 0) {
    Write-Host 'Failed assertions:'
    foreach ($f in $script:ScytheFailures) { Write-Host ('  - ' + $f) }
    exit 1
}
exit 0
