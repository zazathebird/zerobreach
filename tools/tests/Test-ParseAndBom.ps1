$files = @(
  'ZeroBreach-Server.ps1','ZeroBreach-V23.ps1',
  'engine/Phases-0.ps1','engine/Phases-1.ps1','engine/Phases-2.ps1','engine/Phases-3.ps1',
  'engine/Phases-4.ps1','engine/Phases-5.ps1','engine/Phases-6.ps1','engine/Phases-7.ps1',
  'engine/Summary.ps1','engine/FixMode.ps1'
)
$bad = 0
foreach ($f in $files) {
  if (-not (Test-Path $f)) { Write-Host "MISSING: $f" -ForegroundColor Red; $bad++; continue }
  $t=$null; $e=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $f).Path, [ref]$t, [ref]$e)
  $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $f).Path)
  $bom = ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
  if ($e.Count -gt 0) {
    $bad++
    Write-Host "PARSE FAIL: $f" -ForegroundColor Red
    $e | Select-Object -First 5 | ForEach-Object { Write-Host ("   line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) }
  } else {
    Write-Host ("PARSE OK  : {0}   BOM={1}" -f $f, $(if($bom){'yes'}else{'NO -- BROKEN'})) -ForegroundColor $(if($bom){'Green'}else{'Red'})
    if (-not $bom) { $bad++ }
  }
}
Write-Host ("`n{0}" -f $(if($bad -eq 0){'ALL 8 CLEAN'}else{"$bad FILE(S) WITH PROBLEMS"})) -ForegroundColor $(if($bad -eq 0){'Green'}else{'Red'})
