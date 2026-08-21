<#
.SYNOPSIS
    Tests for tools\tests\lib\ZbAssert.ps1 and tools\tests\New-TestReport.ps1.

.DESCRIPTION
    The library under test cannot be trusted to judge itself, so this file carries its own
    two-helper meta-assertion pattern (the same one the existing suites use) and inspects the
    library's structured records directly. Covered: every helper's pass, fail and empty-input
    outcome (including the two traps the outcome exists for: '' -eq '' and -match ''), record
    plumbing (section, source location, actual value on failure, snapshot immutability), the
    no-single-letter-name rule via the AST, JUnit XML schema validation with counts
    cross-checked against the record collection, HTML escaping and the no-remote-assets rule,
    and the exit-code contract of both Complete-ZbTestRun and New-TestReport.ps1.

    The XSD and the child scripts live in here-strings, which the parse check of THIS file
    does not validate — the child scripts are validated by being run, and the XSD by the
    negative control (a deliberately invalid XML must fail validation).

.EXAMPLE
    pwsh tools/tests/Test-ZbAssert.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:TmPass = 0
$script:TmFail = 0
$script:TmFailures = @()

function Assert-TmTrue {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:TmPass = $script:TmPass + 1
        Write-Host ('  ok    ' + $Name)
    }
    else {
        $script:TmFail = $script:TmFail + 1
        $script:TmFailures += $Name
        Write-Host ('  FAIL  ' + $Name)
    }
}

function Assert-TmEqual {
    param($Expected, $Actual, [string]$Name)
    Assert-TmTrue -Condition (('' + $Expected) -eq ('' + $Actual)) -Name ($Name + " (expected '$Expected', got '$Actual')")
}

$here = $PSScriptRoot
$libPath = Join-Path -Path (Join-Path -Path $here -ChildPath 'lib') -ChildPath 'ZbAssert.ps1'
$reportTool = Join-Path -Path $here -ChildPath 'New-TestReport.ps1'
$tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('zbtest_assert_' + $PID)
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

. $libPath

function Get-TmLast {
    return (Get-ZbResults)[-1]
}

# --------------------------------------------------------------------------------------------
# Every helper: pass, fail, and the empty-input outcome
# --------------------------------------------------------------------------------------------

Write-Host 'outcomes'
Reset-ZbResults

Assert-ZbTrue -Condition $true -Name 'probe' 6>$null
Assert-TmEqual 'pass' (Get-TmLast).Outcome 'ZbTrue: true passes'
Assert-ZbTrue -Condition $false -Name 'probe' 6>$null
Assert-TmEqual 'fail' (Get-TmLast).Outcome 'ZbTrue: false fails'
Assert-ZbTrue -Condition $null -Name 'probe' 6>$null
Assert-TmEqual 'empty' (Get-TmLast).Outcome 'ZbTrue: null condition yields the empty outcome, not a pass or a plain fail'

Assert-ZbFalse -Condition $false -Name 'probe' 6>$null
Assert-TmEqual 'pass' (Get-TmLast).Outcome 'ZbFalse: false passes'
Assert-ZbFalse -Condition $true -Name 'probe' 6>$null
Assert-TmEqual 'fail' (Get-TmLast).Outcome 'ZbFalse: true fails'
Assert-ZbFalse -Condition $null -Name 'probe' 6>$null
Assert-TmEqual 'empty' (Get-TmLast).Outcome 'ZbFalse: null condition yields the empty outcome'

Assert-ZbEqual -Expected 5 -Actual 5 -Name 'probe' 6>$null
Assert-TmEqual 'pass' (Get-TmLast).Outcome 'ZbEqual: equal values pass'
Assert-ZbEqual -Expected 5 -Actual 6 -Name 'probe' 6>$null
Assert-TmEqual 'fail' (Get-TmLast).Outcome 'ZbEqual: unequal values fail'
Assert-TmEqual '5' (Get-TmLast).Expected 'ZbEqual: failure record carries the expected value'
Assert-TmEqual '6' (Get-TmLast).Actual 'ZbEqual: failure record carries the actual value'
Assert-ZbEqual -Expected 'x' -Actual $null -Name 'probe' 6>$null
Assert-TmEqual 'empty' (Get-TmLast).Outcome 'ZbEqual: null actual yields the empty outcome'
Assert-ZbEqual -Expected '' -Actual '' -Name 'probe' 6>$null
Assert-TmEqual 'empty' (Get-TmLast).Outcome "ZbEqual: '' -eq '' is the failed-to-load trap and yields empty, not pass"

Assert-ZbContains -Collection @('alpha', 'beta') -Item 'alpha' -Name 'probe' 6>$null
Assert-TmEqual 'pass' (Get-TmLast).Outcome 'ZbContains: present item passes'
Assert-ZbContains -Collection @('alpha', 'beta') -Item 'gamma' -Name 'probe' 6>$null
Assert-TmEqual 'fail' (Get-TmLast).Outcome 'ZbContains: absent item fails'
Assert-TmTrue ((Get-TmLast).Actual -like '*alpha*') 'ZbContains: failure record shows the collection content'
Assert-ZbContains -Collection $null -Item 'alpha' -Name 'probe' 6>$null
Assert-TmEqual 'empty' (Get-TmLast).Outcome 'ZbContains: null collection yields the empty outcome'
Assert-ZbContains -Collection @() -Item 'alpha' -Name 'probe' 6>$null
Assert-TmEqual 'empty' (Get-TmLast).Outcome 'ZbContains: empty collection yields the empty outcome'

Assert-ZbMatch -Text 'hello world' -Pattern 'wor' -Name 'probe' 6>$null
Assert-TmEqual 'pass' (Get-TmLast).Outcome 'ZbMatch: matching text passes'
Assert-ZbMatch -Text 'hello world' -Pattern 'zzz' -Name 'probe' 6>$null
Assert-TmEqual 'fail' (Get-TmLast).Outcome 'ZbMatch: non-matching text fails'
Assert-TmTrue ((Get-TmLast).Actual -like '*hello world*') 'ZbMatch: failure record carries the text'
Assert-ZbMatch -Text '' -Pattern 'x' -Name 'probe' 6>$null
Assert-TmEqual 'empty' (Get-TmLast).Outcome 'ZbMatch: empty text yields the empty outcome'
Assert-ZbMatch -Text 'hello' -Pattern '' -Name 'probe' 6>$null
Assert-TmEqual 'empty' (Get-TmLast).Outcome "ZbMatch: empty pattern yields empty — -match '' is true and must never pass"

Assert-ZbThrows -Script { throw 'boom goes the table' } -Name 'probe' 6>$null
Assert-TmEqual 'pass' (Get-TmLast).Outcome 'ZbThrows: a throwing block passes'
Assert-ZbThrows -Script { 1 } -Name 'probe' 6>$null
Assert-TmEqual 'fail' (Get-TmLast).Outcome 'ZbThrows: a quiet block fails'
Assert-ZbThrows -Script { throw 'boom goes the table' } -MessageLike 'boom*' -Name 'probe' 6>$null
Assert-TmEqual 'pass' (Get-TmLast).Outcome 'ZbThrows: message filter accepts the right message'
Assert-ZbThrows -Script { throw 'boom goes the table' } -MessageLike 'other*' -Name 'probe' 6>$null
Assert-TmEqual 'fail' (Get-TmLast).Outcome 'ZbThrows: message filter rejects the wrong message'
Assert-TmTrue ((Get-TmLast).Actual -like '*boom*') 'ZbThrows: the wrong-message failure carries the real message'
Assert-ZbThrows -Script $null -Name 'probe' 6>$null
Assert-TmEqual 'empty' (Get-TmLast).Outcome 'ZbThrows: null script block yields the empty outcome'

# --------------------------------------------------------------------------------------------
# Record plumbing: section, location, snapshots
# --------------------------------------------------------------------------------------------

Write-Host 'record plumbing'
Reset-ZbResults
Set-ZbSection -Name 'plumbing section' 6>$null
Assert-ZbTrue -Condition $true -Name 'probe' 6>$null
$rec = Get-TmLast
Assert-TmEqual 'plumbing section' $rec.Section 'the active section is recorded on each result'
Assert-TmEqual 'Test-ZbAssert.ps1' $rec.File 'the record carries the calling file, not the library'
Assert-TmTrue ($rec.Line -gt 0) 'the record carries a source line number'

$snapshot = Get-ZbResults
$countBefore = @($snapshot).Count
Assert-ZbTrue -Condition $true -Name 'probe' 6>$null
Assert-TmEqual $countBefore @($snapshot).Count 'Get-ZbResults returns a snapshot, not the live collection'
Assert-TmEqual ($countBefore + 1) (Get-ZbResults).Count 'the live collection did grow'
Reset-ZbResults
Assert-TmEqual 0 (Get-ZbResults).Count 'Reset-ZbResults empties the collection'

# --------------------------------------------------------------------------------------------
# No single-letter names in the library (aliases outrank functions; H is Get-History)
# --------------------------------------------------------------------------------------------

Write-Host 'name hygiene'
$tk = $null
$er = $null
$libAst = [System.Management.Automation.Language.Parser]::ParseFile($libPath, [ref]$tk, [ref]$er)
Assert-TmEqual 0 @($er).Count 'library parses clean'
$fnNodes = @($libAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
Assert-TmTrue ($fnNodes.Count -ge 10) ('library defines its functions (' + $fnNodes.Count + ' found) — the scan is not running on nothing')
$shortNames = @($fnNodes | Where-Object { $_.Name.Length -lt 2 })
Assert-TmEqual 0 $shortNames.Count 'no function name shorter than two characters'
$aliasCalls = @($libAst.FindAll({ param($n)
            ($n -is [System.Management.Automation.Language.CommandAst]) -and
            ($null -ne $n.GetCommandName()) -and
            (@('Set-Alias', 'New-Alias') -contains $n.GetCommandName())
        }, $true))
Assert-TmEqual 0 $aliasCalls.Count 'the library defines no aliases at all (an alias could smuggle a short name in)'

# --------------------------------------------------------------------------------------------
# Export + New-TestReport.ps1: JUnit XML against its schema, counts, escaping, gating
# --------------------------------------------------------------------------------------------

Write-Host 'report generation'
$hostileName = 'finding <img src=x onerror=alert(1)> & "quotes" ''apostrophe'''
Reset-ZbResults
Set-ZbSection -Name 'alpha' 6>$null
Assert-ZbTrue -Condition $true -Name 'alpha one' 6>$null
Assert-ZbTrue -Condition $true -Name 'alpha two' 6>$null
Set-ZbSection -Name 'beta' 6>$null
Assert-ZbEqual -Expected 'want-value-EXP' -Actual 'got-value-ACT' -Name $hostileName 6>$null
Assert-ZbMatch -Text '' -Pattern 'x' -Name 'beta empty probe' 6>$null

$resultsJson = Join-Path -Path $tempDir -ChildPath 'mixed_results.json'
Export-ZbResults -Path $resultsJson
Assert-TmTrue (Test-Path -LiteralPath $resultsJson) 'Export-ZbResults writes the file'
$exported = @(Get-Content -LiteralPath $resultsJson -Raw -Encoding UTF8 | ConvertFrom-Json)
Assert-TmEqual 4 $exported.Count 'export carries every record, passes included'

$junitPath = Join-Path -Path $tempDir -ChildPath 'mixed.junit.xml'
$htmlPath = Join-Path -Path $tempDir -ChildPath 'mixed.html'
& $reportTool -Path $resultsJson -JUnitPath $junitPath -HtmlPath $htmlPath -Title 'Mixed run' 6>$null | Out-Null
Assert-TmEqual 1 ([int]$LASTEXITCODE) 'report exits non-zero when any result is a failure'

# The schema the XML must satisfy. The negative control below proves the validator can fail.
$junitXsd = @'
<?xml version="1.0" encoding="utf-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:complexType name="detailType">
    <xs:simpleContent>
      <xs:extension base="xs:string">
        <xs:attribute name="message" type="xs:string" use="required"/>
        <xs:attribute name="type" type="xs:string" use="required"/>
      </xs:extension>
    </xs:simpleContent>
  </xs:complexType>
  <xs:element name="testsuites">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="testsuite" minOccurs="0" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="testcase" minOccurs="0" maxOccurs="unbounded">
                <xs:complexType>
                  <xs:sequence>
                    <xs:element name="failure" type="detailType" minOccurs="0"/>
                    <xs:element name="error" type="detailType" minOccurs="0"/>
                  </xs:sequence>
                  <xs:attribute name="name" type="xs:string" use="required"/>
                  <xs:attribute name="classname" type="xs:string" use="required"/>
                </xs:complexType>
              </xs:element>
            </xs:sequence>
            <xs:attribute name="name" type="xs:string" use="required"/>
            <xs:attribute name="tests" type="xs:integer" use="required"/>
            <xs:attribute name="failures" type="xs:integer" use="required"/>
            <xs:attribute name="errors" type="xs:integer" use="required"/>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
      <xs:attribute name="name" type="xs:string" use="required"/>
      <xs:attribute name="tests" type="xs:integer" use="required"/>
      <xs:attribute name="failures" type="xs:integer" use="required"/>
      <xs:attribute name="errors" type="xs:integer" use="required"/>
    </xs:complexType>
  </xs:element>
</xs:schema>
'@

function Test-TmXmlAgainstSchema {
    param([string]$XmlPath, [string]$Xsd)
    $reader = $null
    try {
        $schemaReader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($Xsd)))
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.ValidationType = [System.Xml.ValidationType]::Schema
        [void]$settings.Schemas.Add($null, $schemaReader)
        $reader = [System.Xml.XmlReader]::Create($XmlPath, $settings)
        while ($reader.Read()) { }
        return $true
    }
    catch { return $false }
    finally { if ($null -ne $reader) { $reader.Close() } }
}

Assert-TmTrue (Test-TmXmlAgainstSchema -XmlPath $junitPath -Xsd $junitXsd) 'JUnit XML validates against the schema'

# Negative control: the validator itself must be able to say no.
$badXmlPath = Join-Path -Path $tempDir -ChildPath 'bad.junit.xml'
[System.IO.File]::WriteAllText($badXmlPath, '<testsuites name="x" tests="1" failures="0" errors="0"><testsuite name="s" tests="1" failures="0" errors="0"><testcase name="only-a-name"/></testsuite></testsuites>', $utf8NoBom)
Assert-TmTrue (-not (Test-TmXmlAgainstSchema -XmlPath $badXmlPath -Xsd $junitXsd)) 'schema validation rejects a testcase missing classname (validator is live)'

# Counts in the XML cross-checked against the record collection.
$junit = [xml](Get-Content -LiteralPath $junitPath -Raw -Encoding UTF8)
$expFail = @($exported | Where-Object { $_.Outcome -eq 'fail' }).Count
$expEmpty = @($exported | Where-Object { $_.Outcome -eq 'empty' }).Count
Assert-TmEqual $exported.Count ([int]$junit.testsuites.tests) 'XML tests count matches the result collection'
Assert-TmEqual $expFail ([int]$junit.testsuites.failures) 'XML failures count matches the fail outcomes'
Assert-TmEqual $expEmpty ([int]$junit.testsuites.errors) 'XML errors count matches the empty-input outcomes'
$cases = @($junit.SelectNodes('//testcase'))
Assert-TmEqual $exported.Count $cases.Count 'one testcase per recorded assertion'
$failNodes = @($junit.SelectNodes('//testcase/failure'))
Assert-TmEqual 1 $failNodes.Count 'the fail outcome renders as a failure element'
Assert-TmEqual 'AssertionFailure' ('' + $failNodes[0].type) 'failure element typed AssertionFailure'
Assert-TmTrue (('' + $failNodes[0].'#text') -like '*want-value-EXP*') 'failure detail carries the expected value'
Assert-TmTrue (('' + $failNodes[0].'#text') -like '*got-value-ACT*') 'failure detail carries the actual value'
$errorNodes = @($junit.SelectNodes('//testcase/error'))
Assert-TmEqual 1 $errorNodes.Count 'the empty-input outcome renders as an error element, distinct from failure'
Assert-TmEqual 'EmptyInput' ('' + $errorNodes[0].type) 'error element typed EmptyInput'
$junitRaw = Get-Content -LiteralPath $junitPath -Raw -Encoding UTF8
Assert-TmTrue (-not $junitRaw.Contains('<img')) 'hostile assertion name is not live markup in the XML'

# HTML: escaping, values, locations, and nothing remote.
Assert-TmTrue (Test-Path -LiteralPath $htmlPath) 'HTML summary written'
$htmlRaw = Get-Content -LiteralPath $htmlPath -Raw -Encoding UTF8
Assert-TmTrue ($htmlRaw.Contains('&lt;img')) 'hostile assertion name is escaped in the HTML'
Assert-TmTrue (-not $htmlRaw.Contains('<img')) 'hostile assertion name is not live markup in the HTML'
Assert-TmTrue ($htmlRaw.Contains('want-value-EXP')) 'HTML failure row carries the expected value'
Assert-TmTrue ($htmlRaw.Contains('got-value-ACT')) 'HTML failure row carries the actual value'
Assert-TmTrue ($htmlRaw.Contains('Test-ZbAssert.ps1:')) 'HTML failure row carries the source location'
Assert-TmTrue (-not ($htmlRaw -match 'https?://')) 'HTML references no remote origin'
Assert-TmTrue (-not $htmlRaw.Contains('<script')) 'HTML carries no script'

# Exit-code contract of the report tool.
Reset-ZbResults
Assert-ZbTrue -Condition $true -Name 'lone pass' 6>$null
$greenJson = Join-Path -Path $tempDir -ChildPath 'green_results.json'
Export-ZbResults -Path $greenJson
& $reportTool -Path $greenJson -JUnitPath (Join-Path $tempDir 'green.xml') -HtmlPath (Join-Path $tempDir 'green.html') 6>$null | Out-Null
Assert-TmEqual 0 ([int]$LASTEXITCODE) 'report exits zero when everything passed'

Reset-ZbResults
Assert-ZbTrue -Condition $true -Name 'pass' 6>$null
Assert-ZbTrue -Condition $null -Name 'never loaded' 6>$null
$emptyOutcomeJson = Join-Path -Path $tempDir -ChildPath 'empty_outcome_results.json'
Export-ZbResults -Path $emptyOutcomeJson
& $reportTool -Path $emptyOutcomeJson -JUnitPath (Join-Path $tempDir 'eo.xml') -HtmlPath (Join-Path $tempDir 'eo.html') 6>$null | Out-Null
Assert-TmEqual 1 ([int]$LASTEXITCODE) 'report exits non-zero on an empty-input outcome — a failure, never a skip'

Write-Host 'zero-record hand-off (one refusal message below is expected)'
$noneJson = Join-Path -Path $tempDir -ChildPath 'none_results.json'
[System.IO.File]::WriteAllText($noneJson, '[]', $utf8NoBom)
$noneXml = Join-Path -Path $tempDir -ChildPath 'none.xml'
& $reportTool -Path $noneJson -JUnitPath $noneXml -HtmlPath (Join-Path $tempDir 'none.html') 6>$null | Out-Null
Assert-TmEqual 2 ([int]$LASTEXITCODE) 'a suite that recorded nothing is a hard error, exit 2'
Assert-TmTrue (-not (Test-Path -LiteralPath $noneXml)) 'no XML is written for zero records'

# --------------------------------------------------------------------------------------------
# Complete-ZbTestRun exit codes, proven in child scripts
# --------------------------------------------------------------------------------------------

Write-Host 'run completion'
$childA = ". '" + $libPath + "'" + "`n" +
    'Reset-ZbResults' + "`n" +
    "Assert-ZbTrue -Condition `$true -Name 'ok' 6>`$null" + "`n" +
    'Complete-ZbTestRun 6>$null'
$childAPath = Join-Path -Path $tempDir -ChildPath 'child_green.ps1'
[System.IO.File]::WriteAllText($childAPath, $childA, $utf8NoBom)
& $childAPath | Out-Null
Assert-TmEqual 0 ([int]$LASTEXITCODE) 'Complete-ZbTestRun exits zero on an all-pass run'

$childExport = Join-Path -Path $tempDir -ChildPath 'child_export.json'
$childB = ". '" + $libPath + "'" + "`n" +
    'Reset-ZbResults' + "`n" +
    "Assert-ZbTrue -Condition `$true -Name 'ok' 6>`$null" + "`n" +
    "Assert-ZbTrue -Condition `$false -Name 'broken' 6>`$null" + "`n" +
    "Complete-ZbTestRun -ExportPath '" + $childExport + "' 6>`$null"
$childBPath = Join-Path -Path $tempDir -ChildPath 'child_fail.ps1'
[System.IO.File]::WriteAllText($childBPath, $childB, $utf8NoBom)
& $childBPath | Out-Null
Assert-TmEqual 1 ([int]$LASTEXITCODE) 'Complete-ZbTestRun exits non-zero when a failure was recorded'
Assert-TmEqual 2 @(Get-Content -LiteralPath $childExport -Raw -Encoding UTF8 | ConvertFrom-Json).Count 'Complete-ZbTestRun -ExportPath writes the full record set'

$childC = ". '" + $libPath + "'" + "`n" +
    'Reset-ZbResults' + "`n" +
    "Assert-ZbTrue -Condition `$true -Name 'ok' 6>`$null" + "`n" +
    "Assert-ZbTrue -Condition `$null -Name 'never loaded' 6>`$null" + "`n" +
    'Complete-ZbTestRun 6>$null'
$childCPath = Join-Path -Path $tempDir -ChildPath 'child_empty.ps1'
[System.IO.File]::WriteAllText($childCPath, $childC, $utf8NoBom)
& $childCPath | Out-Null
Assert-TmEqual 1 ([int]$LASTEXITCODE) 'Complete-ZbTestRun exits non-zero on an empty-input outcome (failure, not skip)'

# --------------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------------

Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host ('{0} passed, {1} failed' -f $script:TmPass, $script:TmFail)
if ($script:TmFail -gt 0) {
    Write-Host 'Failed assertions:'
    foreach ($f in $script:TmFailures) { Write-Host ('  - ' + $f) }
    exit 1
}
exit 0
