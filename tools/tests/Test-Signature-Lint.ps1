<#
.SYNOPSIS
    The contract between the engine, data/detection_signatures.json and the lib/ signature
    linter (lib/Scythe.Rules/Linting, run by dotnet test via ShippedSignatureFileTests).

.DESCRIPTION
    The C# test derives which sets the engine consumes and which are allowlists by scanning
    Scythe-V23.ps1 and engine/*.ps1 for Get-Sig 'name' / Join-AllowRegex 'name'. That scan is
    only complete if every call site really is a constant string, so this test walks the AST
    and asserts exactly that. It also checks data/signature_lint_manifest.json - the host's
    own description of HOW each set is matched - against the signature file: every name it
    lists exists, no set claims two match kinds, and every accepted finding quotes an entry
    that is still in the file. A manifest that names a set which no longer exists silently
    puts the real set back under the wrong checks; that is the failure this guards.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fail = 0; $pass = 0
function Assert-That { param([string]$Name,$Actual,$Expected)
    if ("$Actual" -eq "$Expected") { $script:pass++; Write-Host "  [PASS] $Name" -ForegroundColor DarkGreen }
    else { $script:fail++; Write-Host "  [FAIL] $Name — expected '$Expected', got '$Actual'" -ForegroundColor Red }
}
function Assert-True { param([string]$Name,$Cond) Assert-That $Name ([bool]$Cond) $true }

Write-Host "`n=== SIGNATURE LINT CONTRACT (engine call sites + lint manifest) ===" -ForegroundColor Cyan

# ── 1. Every Get-Sig / Join-AllowRegex call site is a constant string ─────────────────────
$files = @((Join-Path $root 'Scythe-V23.ps1')) + @(Get-ChildItem (Join-Path $root 'engine') -Filter '*.ps1' | Sort-Object Name | ForEach-Object { $_.FullName })
$constant = 0; $dynamic = New-Object System.Collections.Generic.List[string]
$names = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($f in $files) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tokens, [ref]$errors)
    Assert-That "parse-clean: $(Split-Path -Leaf $f)" $errors.Count 0
    $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                            $n.GetCommandName() -in @('Get-Sig','Join-AllowRegex') }, $true)
    foreach ($c in $calls) {
        # The two helper bodies themselves pass $Name through; everything else must be literal.
        $fn = $c.Parent
        while ($fn -and -not ($fn -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $fn = $fn.Parent }
        if ($fn -and $fn.Name -in @('Get-Sig','Join-AllowRegex')) { continue }
        $arg = $null
        for ($i = 1; $i -lt $c.CommandElements.Count; $i++) {
            $e = $c.CommandElements[$i]
            if ($e -is [System.Management.Automation.Language.CommandParameterAst]) { continue }
            $arg = $e; break
        }
        if ($arg -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $constant++; [void]$names.Add($arg.Value)
        } else {
            $dynamic.Add("$(Split-Path -Leaf $f):$($c.Extent.StartLineNumber): $($c.Extent.Text)")
        }
    }
}
Assert-That "no dynamic Get-Sig / Join-AllowRegex call site outside the two helpers" ($dynamic -join '; ') ''
Assert-True "constant call sites found (>= 170, was $constant)" ($constant -ge 170)

# ── 2. The manifest describes sets that exist, once each ─────────────────────────────────
$sigPath = Join-Path $root 'data\detection_signatures.json'
$manPath = Join-Path $root 'data\signature_lint_manifest.json'
$sig = Get-Content -LiteralPath $sigPath -Raw | ConvertFrom-Json
$man = Get-Content -LiteralPath $manPath -Raw | ConvertFrom-Json
$sigKeys = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($p in $sig.PSObject.Properties) { [void]$sigKeys.Add($p.Name) }
Assert-That "manifest shape is flat" $man.shape 'flat'

$sections = @('allowlists','literal_sets','equality_sets','wildcard_sets','reference_sets','substring_allowlists')
$kindSeen = @{}
foreach ($sec in $sections) {
    $list = @($man.$sec)
    $missing = @($list | Where-Object { -not $sigKeys.Contains($_) })
    Assert-That "manifest.$sec names only sets the file carries" ($missing -join ',') ''
    $dupes = @($list | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    Assert-That "manifest.$sec has no duplicate names" ($dupes -join ',') ''
    if ($sec -in @('literal_sets','equality_sets','wildcard_sets')) {
        foreach ($n in $list) {
            if ($kindSeen.ContainsKey($n)) { $kindSeen[$n] += ",$sec" } else { $kindSeen[$n] = $sec }
        }
    }
}
$twoKinds = @($kindSeen.GetEnumerator() | Where-Object { $_.Value -like '*,*' } | ForEach-Object { "$($_.Key)=$($_.Value)" })
Assert-That "no set claims two match kinds (literal / equality / wildcard)" ($twoKinds -join ';') ''

# Every allowlist the manifest relaxes to component anchoring is really an allowlist:
# either a Join-AllowRegex name in the engine or one of the manifest's own extra allowlists.
$engineAllow = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($f in $files) {
    foreach ($m in [regex]::Matches((Get-Content -LiteralPath $f -Raw), "Join-AllowRegex\s+'([A-Za-z0-9_]+)'")) { [void]$engineAllow.Add($m.Groups[1].Value) }
}
$notAllow = @($man.substring_allowlists | Where-Object { -not ($engineAllow.Contains($_) -or (@($man.allowlists) -contains $_)) })
Assert-That "every substring_allowlists entry is an allowlist (Join-AllowRegex or manifest.allowlists)" ($notAllow -join ',') ''

# ── 3. Accepted findings quote entries that are still in the file, verbatim ──────────────
# accepted_findings (2026-09-02) generalises accepted_collisions: {code, set, entry, why}, code one
# of the three codes the linter lets a maintainer accept. For AllowlistSwallowsDetection the
# set/entry name the ALLOWLIST side. A stale acceptance (rule edited, list renamed) is a bug here.
$okCodes = @('IndicatorCollidesWithLegitimateName','IndicatorTooShort','AllowlistSwallowsDetection')
Assert-True "manifest carries accepted_findings" ($null -ne $man.accepted_findings)
Assert-True "manifest no longer carries the legacy accepted_collisions key" ($null -eq $man.accepted_collisions)
$acSeen = @{}
foreach ($ac in @($man.accepted_findings)) {
    $tag = "accepted_findings.$($ac.code).$($ac.set)"
    Assert-True "$tag`: code is one the linter accepts" ($okCodes -contains "$($ac.code)")
    Assert-True "$tag`: has a reason" (-not [string]::IsNullOrWhiteSpace($ac.why))
    Assert-True "$tag`: names a set the file carries" ($sigKeys.Contains("$($ac.set)"))
    $dupKey = "$($ac.code)|$($ac.set)|$($ac.entry)"
    Assert-True "$tag`: not accepted twice" (-not $acSeen.ContainsKey($dupKey)); $acSeen[$dupKey] = $true
    $found = $false
    foreach ($item in @($sig.($ac.set))) {
        if ($item -is [string]) { if ($item -ceq $ac.entry) { $found = $true } }
        else { foreach ($p in $item.PSObject.Properties) { if ($p.Value -is [string] -and $p.Value -ceq $ac.entry) { $found = $true } } }
    }
    Assert-True "$tag`: entry still present verbatim" $found
}
Assert-True "accepted_findings covers every IndicatorTooShort the file has (>= 28)" (@($man.accepted_findings | Where-Object { $_.code -eq 'IndicatorTooShort' }).Count -ge 28)

# ── 4. The C# side reads the same two files this test just validated ─────────────────────
$cs = Get-Content -LiteralPath (Join-Path $root 'lib\Scythe.Rules.Tests\Linting\ShippedSignatureFileTests.cs') -Raw
Assert-True "ShippedSignatureFileTests lints data/detection_signatures.json" ($cs -match 'data/detection_signatures\.json')
Assert-True "ShippedSignatureFileTests reads data/signature_lint_manifest.json" ($cs -match 'data/signature_lint_manifest\.json')

Write-Host ("`n{0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 } else { exit 0 }
