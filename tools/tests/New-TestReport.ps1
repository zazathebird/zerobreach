<#
.SYNOPSIS
    Renders exported test results as JUnit XML plus a one-page HTML summary, and gates.

.DESCRIPTION
    New-TestReport.ps1 consumes one or more result files written by Export-ScytheResults (in
    tools\tests\lib\ScytheAssert.ps1) and emits:

      - JUnit XML, one <testsuite> per input file, <testcase> per assertion. A 'fail'
        outcome becomes a <failure>, an 'empty' outcome (input never loaded) becomes an
        <error> — distinct in the XML, and both gate.
      - A self-contained HTML page: totals, per-section counts, and every non-pass with its
        expected value, actual value and source location. No scripts, no remote assets.

    Exit codes: 0 all pass; 1 any failure or empty-input outcome; 2 hard error (no input
    records — a suite that recorded nothing must never gate as green — or unreadable input).

.PARAMETER Path
    One or more result JSON files from Export-ScytheResults.

.PARAMETER JUnitPath
    Where the JUnit XML goes. Default: first input path with .junit.xml in place of .json.

.PARAMETER HtmlPath
    Where the HTML summary goes. Default: first input path with .html in place of .json.

.PARAMETER Title
    Heading for the HTML page and name of the JUnit root suite. Default "Scythe tests".

.EXAMPLE
    pwsh tools/tests/New-TestReport.ps1 -Path results.json

.EXAMPLE
    powershell -File tools\tests\New-TestReport.ps1 -Path a.json, b.json -JUnitPath junit.xml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path,

    [string]$JUnitPath,

    [string]$HtmlPath,

    [string]$Title = 'Scythe tests'
)

$ErrorActionPreference = 'Stop'

function Stop-ScytheFatal {
    # Same rationale as the other tools: Write-Error under an EAP of Stop throws before an
    # exit statement can run, so fatal text goes straight to the error line.
    param([string]$Message)
    $host.UI.WriteErrorLine($Message)
    exit 2
}

function ConvertTo-ScytheHtmlText {
    param($Value)
    $text = '' + $Value
    $text = $text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    return $text.Replace('"', '&quot;').Replace("'", '&#39;')
}

# --------------------------------------------------------------------------------------------
# Load
# --------------------------------------------------------------------------------------------

$suites = @()   # one entry per input file: Name + Records
$total = 0
foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) {
        Stop-ScytheFatal -Message ('Result file not found: ' + $p)
    }
    $parsed = $null
    try {
        $parsed = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Stop-ScytheFatal -Message ('Result file is not valid JSON: ' + $p + ' (' + $_.Exception.Message + ')')
    }
    $records = @($parsed)
    $suites += New-Object PSObject -Property @{
        Name    = [System.IO.Path]::GetFileNameWithoutExtension($p)
        Records = $records
    }
    $total = $total + $records.Count
}
if ($total -eq 0) {
    Stop-ScytheFatal -Message ('No results in ' + ($Path -join ', ') + '. A suite that recorded nothing must never gate as green.')
}

$allRecords = @($suites | ForEach-Object { $_.Records } | ForEach-Object { $_ })
$failCount = @($allRecords | Where-Object { $_.Outcome -eq 'fail' }).Count
$emptyCount = @($allRecords | Where-Object { $_.Outcome -eq 'empty' }).Count
$passCount = $total - $failCount - $emptyCount

if ([string]::IsNullOrEmpty($JUnitPath)) {
    $JUnitPath = [System.IO.Path]::ChangeExtension($Path[0], '.junit.xml')
}
if ([string]::IsNullOrEmpty($HtmlPath)) {
    $HtmlPath = [System.IO.Path]::ChangeExtension($Path[0], '.html')
}

# --------------------------------------------------------------------------------------------
# JUnit XML — written through XmlWriter so every name and value is escaped by the platform
# --------------------------------------------------------------------------------------------

$xmlSettings = New-Object System.Xml.XmlWriterSettings
$xmlSettings.Indent = $true
$xmlSettings.Encoding = New-Object System.Text.UTF8Encoding($false)
$xw = [System.Xml.XmlWriter]::Create($JUnitPath, $xmlSettings)
$xw.WriteStartDocument()
$xw.WriteStartElement('testsuites')
$xw.WriteAttributeString('name', $Title)
$xw.WriteAttributeString('tests', [string]$total)
$xw.WriteAttributeString('failures', [string]$failCount)
$xw.WriteAttributeString('errors', [string]$emptyCount)
foreach ($suite in $suites) {
    $sFail = @($suite.Records | Where-Object { $_.Outcome -eq 'fail' }).Count
    $sEmpty = @($suite.Records | Where-Object { $_.Outcome -eq 'empty' }).Count
    $xw.WriteStartElement('testsuite')
    $xw.WriteAttributeString('name', $suite.Name)
    $xw.WriteAttributeString('tests', [string]@($suite.Records).Count)
    $xw.WriteAttributeString('failures', [string]$sFail)
    $xw.WriteAttributeString('errors', [string]$sEmpty)
    foreach ($r in $suite.Records) {
        $classname = '' + $r.Section
        if ($classname.Length -eq 0) { $classname = '(no section)' }
        $xw.WriteStartElement('testcase')
        $xw.WriteAttributeString('name', ('' + $r.Name))
        $xw.WriteAttributeString('classname', $classname)
        $detail = "expected '" + $r.Expected + "', got '" + $r.Actual + "' at " + $r.File + ':' + $r.Line
        if ($r.Outcome -eq 'fail') {
            $xw.WriteStartElement('failure')
            $xw.WriteAttributeString('message', ('' + $r.Name))
            $xw.WriteAttributeString('type', 'AssertionFailure')
            $xw.WriteString($detail)
            $xw.WriteEndElement()
        }
        elseif ($r.Outcome -eq 'empty') {
            $xw.WriteStartElement('error')
            $xw.WriteAttributeString('message', ('' + $r.Name))
            $xw.WriteAttributeString('type', 'EmptyInput')
            $xw.WriteString($detail)
            $xw.WriteEndElement()
        }
        $xw.WriteEndElement()
    }
    $xw.WriteEndElement()
}
$xw.WriteEndElement()
$xw.WriteEndDocument()
$xw.Flush()
$xw.Close()

# --------------------------------------------------------------------------------------------
# HTML summary — static, self-contained, nothing remote
# --------------------------------------------------------------------------------------------

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<!DOCTYPE html>')
[void]$sb.AppendLine('<html lang="en">')
[void]$sb.AppendLine('<head>')
[void]$sb.AppendLine('<meta charset="utf-8">')
[void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
[void]$sb.AppendLine('<title>' + (ConvertTo-ScytheHtmlText -Value $Title) + '</title>')
[void]$sb.AppendLine('<style>')
[void]$sb.AppendLine(':root { --scythe-bg:#f7f7f5; --scythe-fg:#1c1c1a; --scythe-card:#ffffff; --scythe-line:#d8d8d4; --scythe-ok:#1a7f37; --scythe-bad:#b42318; --scythe-warn:#9a6700; }')
[void]$sb.AppendLine('@media (prefers-color-scheme: dark) { :root { --scythe-bg:#171716; --scythe-fg:#e6e6e2; --scythe-card:#211f1e; --scythe-line:#3a3a36; --scythe-ok:#4ac26b; --scythe-bad:#ff7b6f; --scythe-warn:#e3b341; } }')
[void]$sb.AppendLine('body { margin:0; padding:24px; background:var(--scythe-bg); color:var(--scythe-fg); font:15px/1.5 system-ui, "Segoe UI", sans-serif; }')
[void]$sb.AppendLine('h1 { font-size:20px; margin:0 0 4px; } .sub { opacity:.75; margin:0 0 20px; }')
[void]$sb.AppendLine('.tot { display:flex; gap:12px; flex-wrap:wrap; margin:0 0 20px; }')
[void]$sb.AppendLine('.pill { background:var(--scythe-card); border:1px solid var(--scythe-line); border-radius:8px; padding:10px 16px; }')
[void]$sb.AppendLine('.pill b { font-size:20px; display:block; }')
[void]$sb.AppendLine('.ok b { color:var(--scythe-ok); } .bad b { color:var(--scythe-bad); } .warn b { color:var(--scythe-warn); }')
[void]$sb.AppendLine('table { border-collapse:collapse; width:100%; background:var(--scythe-card); border:1px solid var(--scythe-line); border-radius:8px; margin:0 0 20px; }')
[void]$sb.AppendLine('th, td { text-align:left; padding:8px 12px; border-top:1px solid var(--scythe-line); vertical-align:top; word-break:break-word; }')
[void]$sb.AppendLine('thead th { border-top:0; font-size:13px; text-transform:uppercase; letter-spacing:.03em; opacity:.7; }')
[void]$sb.AppendLine('.o-fail { color:var(--scythe-bad); font-weight:600; } .o-empty { color:var(--scythe-warn); font-weight:600; }')
[void]$sb.AppendLine('.allok { border:1px solid var(--scythe-line); background:var(--scythe-card); border-radius:8px; padding:16px; color:var(--scythe-ok); font-weight:600; }')
[void]$sb.AppendLine('code { font-family:ui-monospace, Consolas, monospace; font-size:13px; }')
[void]$sb.AppendLine('</style>')
[void]$sb.AppendLine('</head>')
[void]$sb.AppendLine('<body>')
[void]$sb.AppendLine('<h1>' + (ConvertTo-ScytheHtmlText -Value $Title) + '</h1>')
[void]$sb.AppendLine('<p class="sub">' + (ConvertTo-ScytheHtmlText -Value (($suites | ForEach-Object { $_.Name }) -join ', ')) + '</p>')
[void]$sb.AppendLine('<div class="tot">')
[void]$sb.AppendLine('<div class="pill"><b>' + $total + '</b>assertions</div>')
[void]$sb.AppendLine('<div class="pill ok"><b>' + $passCount + '</b>passed</div>')
[void]$sb.AppendLine('<div class="pill bad"><b>' + $failCount + '</b>failed</div>')
[void]$sb.AppendLine('<div class="pill warn"><b>' + $emptyCount + '</b>empty-input</div>')
[void]$sb.AppendLine('</div>')

# Per-section counts.
$sections = @($allRecords | ForEach-Object { $s = '' + $_.Section; if ($s.Length -eq 0) { '(no section)' } else { $s } } | Select-Object -Unique)
[void]$sb.AppendLine('<table>')
[void]$sb.AppendLine('<thead><tr><th>Section</th><th>Passed</th><th>Failed</th><th>Empty-input</th></tr></thead>')
[void]$sb.AppendLine('<tbody>')
foreach ($sec in $sections) {
    $inSec = @($allRecords | Where-Object { ('' + $_.Section) -eq $sec -or (('' + $_.Section).Length -eq 0 -and $sec -eq '(no section)') })
    $sp = @($inSec | Where-Object { $_.Outcome -eq 'pass' }).Count
    $sf = @($inSec | Where-Object { $_.Outcome -eq 'fail' }).Count
    $se = @($inSec | Where-Object { $_.Outcome -eq 'empty' }).Count
    [void]$sb.AppendLine('<tr><td>' + (ConvertTo-ScytheHtmlText -Value $sec) + '</td><td>' + $sp + '</td><td>' + $sf + '</td><td>' + $se + '</td></tr>')
}
[void]$sb.AppendLine('</tbody>')
[void]$sb.AppendLine('</table>')

$bad = @($allRecords | Where-Object { $_.Outcome -ne 'pass' })
if ($bad.Count -eq 0) {
    [void]$sb.AppendLine('<div class="allok">All assertions passed.</div>')
}
else {
    [void]$sb.AppendLine('<table>')
    [void]$sb.AppendLine('<thead><tr><th>Outcome</th><th>Assertion</th><th>Expected</th><th>Actual</th><th>Where</th></tr></thead>')
    [void]$sb.AppendLine('<tbody>')
    foreach ($r in $bad) {
        $cls = 'o-fail'
        if ($r.Outcome -eq 'empty') { $cls = 'o-empty' }
        [void]$sb.AppendLine('<tr>' +
            '<td class="' + $cls + '">' + (ConvertTo-ScytheHtmlText -Value $r.Outcome) + '</td>' +
            '<td>' + (ConvertTo-ScytheHtmlText -Value $r.Name) + '</td>' +
            '<td><code>' + (ConvertTo-ScytheHtmlText -Value $r.Expected) + '</code></td>' +
            '<td><code>' + (ConvertTo-ScytheHtmlText -Value $r.Actual) + '</code></td>' +
            '<td><code>' + (ConvertTo-ScytheHtmlText -Value ($r.File + ':' + $r.Line)) + '</code></td>' +
            '</tr>')
    }
    [void]$sb.AppendLine('</tbody>')
    [void]$sb.AppendLine('</table>')
}
[void]$sb.AppendLine('</body>')
[void]$sb.AppendLine('</html>')

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($HtmlPath, $sb.ToString(), $utf8NoBom)

# --------------------------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------------------------

Write-Host ('{0} assertions: {1} passed, {2} failed, {3} empty-input.' -f $total, $passCount, $failCount, $emptyCount)
Write-Host ('Wrote ' + $JUnitPath + ' and ' + $HtmlPath)
if ($failCount -gt 0 -or $emptyCount -gt 0) { exit 1 }
exit 0
