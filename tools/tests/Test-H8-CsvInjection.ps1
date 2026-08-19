# Load the real ConvertTo-CsvSafeCell from the shipped loader.
$t=$null;$e=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path 'ZeroBreach-V23.ps1').Path,[ref]$t,[ref]$e)
$fn=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'ConvertTo-CsvSafeCell'},$true)
. ([scriptblock]::Create($fn[0].Extent.Text))

# Nasty findings: formula injection, quotes, backslashes, a newline, and a script breakout.
$findings = @(
  [pscustomobject]@{ Severity='CRITICAL'; Phase='10'; ThreatType='Trojan'; Description='evil.exe in Temp';        Target='C:\Temp\evil.exe'; FixAction='DeleteFile'; Timestamp='2026-08-18' }
  [pscustomobject]@{ Severity='HIGH';     Phase='20'; ThreatType='RAT';    Description='=cmd|''/c calc''!A1';      Target='C:\x';            FixAction='DeleteReg';  Timestamp='2026-08-18' }
  [pscustomobject]@{ Severity='HIGH';     Phase='21'; ThreatType='RAT';    Description='@SUM(1+1)*cmd';            Target='+1234';           FixAction='Info';       Timestamp='2026-08-18' }
  [pscustomobject]@{ Severity='POSSIBLE'; Phase='22'; ThreatType='Other';  Description="multi`nline `"quoted`" \path"; Target='-2+3';        FixAction='Info';       Timestamp='2026-08-18' }
  [pscustomobject]@{ Severity='POSSIBLE'; Phase='23'; ThreatType='Other';  Description='</script><img src=x onerror=alert(1)>'; Target='x'; FixAction='Info';       Timestamp='2026-08-18' }
)

$csvData = '"Severity","Phase","ThreatType","Description","Target","FixAction","Timestamp"' + "`n"
foreach ($f in $findings) {
    $csvData += (@($f.Severity,$f.Phase,$f.ThreatType,$f.Description,$f.Target,$f.FixAction,$f.Timestamp) |
                 ForEach-Object { ConvertTo-CsvSafeCell $_ }) -join ','
    $csvData += "`n"
}
$csvDataJs = ($csvData | ConvertTo-Json -Compress) -replace '</','<\/'
$js = "function exportCSV(){var csv=$csvDataJs;var blob=new Blob([csv],{type:'text/csv'});return csv;}`nconsole.log(exportCSV());"
[System.IO.File]::WriteAllText("$env:SCRATCH/gen2.js", $js, (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText("$env:SCRATCH/expected.csv", $csvData, (New-Object System.Text.UTF8Encoding($false)))

$pass=0;$fail=0
function Check($n,$a,$e){ if("$a" -eq "$e"){$script:pass++;Write-Host "  PASS  $n" -ForegroundColor Green}else{$script:fail++;Write-Host "  FAIL  $n -> got '$a' expected '$e'" -ForegroundColor Red} }

Write-Host "`n== CSV formula injection neutralised ==" -ForegroundColor Yellow
Check 'leading = prefixed'   (ConvertTo-CsvSafeCell "=cmd|'/c calc'!A1") '"''=cmd|''/c calc''!A1"'.Replace("''","'")
Check 'leading @ prefixed'   ((ConvertTo-CsvSafeCell '@SUM(1)').StartsWith('"''@')) $true
Check 'leading + prefixed'   ((ConvertTo-CsvSafeCell '+1234').StartsWith('"''+')) $true
Check 'leading - prefixed'   ((ConvertTo-CsvSafeCell '-2+3').StartsWith('"''-')) $true
Check 'leading tab prefixed' ((ConvertTo-CsvSafeCell "`tx").StartsWith('"''')) $true
Check 'benign text untouched' (ConvertTo-CsvSafeCell 'evil.exe in Temp') '"evil.exe in Temp"'
Check 'embedded quote doubled' (ConvertTo-CsvSafeCell 'say "hi"') '"say ""hi"""'

Write-Host "`n== script-element breakout ==" -ForegroundColor Yellow
Check 'no raw </script> in emitted JS' ($js -match '</script') $false
Write-Host ("`n{0} passed, {1} failed" -f $pass,$fail) -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
if($fail){exit 1}
