<#
.SYNOPSIS
    Regenerates the phase coverage matrix by parsing the engine modules with the AST.

.DESCRIPTION
    New-CoverageMatrix.ps1 walks every .ps1 file under -Root (read-only — it parses, never
    writes into the root) and rebuilds the phase-by-phase map of what the engine checks:

      - phase number (fractional numbers like 74.5 keep their decimal), title, category
      - which module the phase lives in
      - the mode gate — the nearest enclosing `if` on a flag of the phase-plan object
      - the distinct severities and fix actions its finding calls can emit
      - which signature-set keys it reads
      - whether the phase is skipped in QUICK (number above the QUICK ceiling)

    The companion summary counts phases per module / per mode / per fix action, and — when
    -SignaturePath is given — lists every signature key read but not present in the file
    (a bug) and every key present but read by nothing (dead weight).

    A phase with no detectable mode gate is reported, in the output and on the console,
    rather than silently defaulted. A root that yields zero phase headers is a hard error
    (exit 2), never an empty matrix — an empty file that "diffs clean" would hide a wrong
    -Root or a renamed header command.

    Output is deterministic: same input, byte-identical file (the JSON is serialised by this
    script, not by ConvertTo-Json, so the bytes do not depend on the PowerShell version).
    The only provenance field is generated_from, and -GeneratedFrom pins it for tests.

    The finding call (Add-Finding) and the plan object ($PhasePlan) are the documented names
    and are the defaults. The phase-header and signature-lookup calls are not documented in
    BLUEPRINT.md, so their names — and their parameter names — are parameters too: aim the
    tool at the real tree with the real names once, no edit required.

.PARAMETER Root
    One or more files or directories to scan. A directory contributes the .ps1 files
    directly inside it (-Recurse to descend). Everything under -Root is read-only.

.PARAMETER OutPath
    Where the matrix is written. Defaults to data\coverage_matrix.generated.json next to the
    project root. Refuses to write the promoted file data\coverage_matrix.json — the main
    session diffs and promotes; this tool never overwrites the file being diffed against.

.PARAMETER SignaturePath
    The signature-set file (a JSON object; its top-level keys are the set names). Optional —
    without it the two orphan-key lists are null, not empty, so "not checked" cannot be
    misread as "nothing found".

.PARAMETER GeneratedFrom
    Value for the generated_from field. Default: the git commit of the first -Root entry,
    or "unknown" outside a repository. Tests pin this so output is byte-stable.

.PARAMETER PhaseHeaderCommand
    Name of the phase-header call. Default Write-PhaseHeader (the fixture convention — pass
    the real name when aiming at the real tree).

.PARAMETER FindingCommand
    Name of the finding call. Default Add-Finding (documented, BLUEPRINT §7).

.PARAMETER SignatureLookupCommand
    Name of the signature-lookup call. Default Get-SignatureSet (fixture convention).

.PARAMETER PlanVariable
    Name of the phase-plan variable whose members are the mode-gate flags. Default
    PhasePlan (documented, BLUEPRINT §6).

.PARAMETER PhaseParameter
.PARAMETER TitleParameter
.PARAMETER CategoryParameter
    Parameter names on the phase-header call. Defaults Phase / Title / Category.

.PARAMETER SignatureKeyParameter
    Parameter name carrying the set key on the signature-lookup call. Default Key.

.PARAMETER Recurse
    Descend into subdirectories of directory -Root entries.

.PARAMETER PassThru
    Also emit the computed matrix object, for tests and scripting.

.EXAMPLE
    tools\New-CoverageMatrix.ps1 -Root engine -SignaturePath data\signatures.json

.EXAMPLE
    tools\New-CoverageMatrix.ps1 -Root engine, ZeroBreach-V23.ps1 -PhaseHeaderCommand Write-Phase
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Root,

    [string]$OutPath,

    [string]$SignaturePath,

    [string]$GeneratedFrom,

    [string]$PhaseHeaderCommand = 'Write-PhaseHeader',

    [string]$FindingCommand = 'Add-Finding',

    [string]$SignatureLookupCommand = 'Get-SignatureSet',

    [string]$PlanVariable = 'PhasePlan',

    [string]$PhaseParameter = 'Phase',

    [string]$TitleParameter = 'Title',

    [string]$CategoryParameter = 'Category',

    [string]$SignatureKeyParameter = 'Key',

    [switch]$Recurse,

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

# Phase ceiling per mode (another copy of the mirrored table — see HANDOFF_FABLE.md; the G5
# parity test reads this file so all copies are proven to agree). Needed because "skipped in
# QUICK" and "phases per mode" are properties of the ceilings and the source carries only flags.
$script:ZbModeCeiling = @{ QUICK = 30; FULL = 80; DEEP = 133; PARANOID = 133; STEALTH = 133; HUNT = 162 }

# Display order for severities (BLUEPRINT §3.3). Unknown labels keep their row, after the known
# ones; 'dynamic' (an expression the parser cannot evaluate) sorts last.
$script:ZbSeverityRank = @{ CRITICAL = 0; HIGH = 1; POSSIBLE = 2; INFO = 3 }

$script:ZbInv = [System.Globalization.CultureInfo]::InvariantCulture

# --------------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------------

function Stop-ZbFatal {
    # Hard failure with a reliable exit code. Write-Error under an EAP of Stop throws before
    # `exit 2` can run, turning every documented exit-2 path into a 1 — so fatal text goes
    # straight to the error line instead of the error stream.
    param([string]$Message)
    $host.UI.WriteErrorLine($Message)
    exit 2
}

function Get-ZbSortedStrings {
    # Ordinal sort — Sort-Object is culture-sensitive and its 5.1 stability is undocumented,
    # and this file promises byte-identical output.
    param([string[]]$Values)
    $arr = @($Values)
    if ($arr.Count -le 1) { return , $arr }
    [System.Array]::Sort($arr, [System.StringComparer]::Ordinal)
    return , $arr
}

function Resolve-ZbArgumentText {
    # A literal argument's text, or $null when the argument is an expression the matrix must
    # record as dynamic rather than drop (BLUEPRINT §7).
    param($Ast)
    if ($null -eq $Ast) { return $null }
    if ($Ast -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
        return [string]$Ast.Value
    }
    if ($Ast -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
        if (@($Ast.NestedExpressions).Count -eq 0) { return [string]$Ast.Value }
        return $null
    }
    if ($Ast -is [System.Management.Automation.Language.ConstantExpressionAst]) {
        return [System.Convert]::ToString($Ast.Value, $script:ZbInv)
    }
    return $null
}

function Get-ZbNamedArguments {
    # Named parameters of a call as name → literal text ($null = present but dynamic).
    # Call sites use named parameters (BLUEPRINT §7); bare positional arguments are ignored.
    param($Command)
    $named = @{}
    $elements = @($Command.CommandElements)
    $idx = 1
    while ($idx -lt $elements.Count) {
        $el = $elements[$idx]
        if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
            $name = $el.ParameterName
            if ($null -ne $el.Argument) {
                # -Name:value form
                $named[$name] = Resolve-ZbArgumentText -Ast $el.Argument
                $idx = $idx + 1
            }
            elseif (($idx + 1) -lt $elements.Count -and
                    -not ($elements[$idx + 1] -is [System.Management.Automation.Language.CommandParameterAst])) {
                $named[$name] = Resolve-ZbArgumentText -Ast $elements[$idx + 1]
                $idx = $idx + 2
            }
            else {
                # A switch; the matrix has no use for its value, only its presence.
                $named[$name] = $null
                $idx = $idx + 1
            }
        }
        else {
            $idx = $idx + 1
        }
    }
    return $named
}

function Format-ZbPhaseKey {
    # Canonical phase key from a header argument: first number in the text, decimal kept
    # ("74.5"), integer-valued normalised ("47.0" → "47"). $null when there is no number.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $m = [regex]::Match($Text, '(\d+(?:\.\d+)?)')
    if (-not $m.Success) { return $null }
    $num = [double]::Parse($m.Groups[1].Value, $script:ZbInv)
    return $num.ToString('0.###', $script:ZbInv)
}

function Get-ZbPlanMembers {
    # Distinct plan-flag names referenced inside an expression ($PhasePlan.Deep → 'Deep').
    param($Ast, [string]$VariableName)
    $found = @{}
    $nodes = $Ast.FindAll({
            param($n)
            ($n -is [System.Management.Automation.Language.MemberExpressionAst]) -and
            ($n.Expression -is [System.Management.Automation.Language.VariableExpressionAst]) -and
            ($n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst])
        }, $true)
    foreach ($n in @($nodes)) {
        # Match with or without a scope qualifier ($PhasePlan, $script:PhasePlan, ...).
        $userPath = [string]$n.Expression.VariablePath.UserPath
        $bare = @($userPath -split ':')[-1]
        if ($bare -eq $VariableName) { $found[[string]$n.Member.Value] = $true }
    }
    $names = @($found.Keys | ForEach-Object { [string]$_ })
    return , (Get-ZbSortedStrings -Values $names)
}

function Get-ZbModeGate {
    # The nearest enclosing `if` clause whose condition tests a plan flag, walking outward
    # from the call. A clause on anything else ("if ($found)") is skipped, an `else` body is
    # not credited with the condition it escaped, and no gate at all returns $null — the
    # caller reports that rather than defaulting.
    param($Command, [string]$VariableName)
    $child = $Command
    $node = $Command.Parent
    while ($null -ne $node) {
        if ($node -is [System.Management.Automation.Language.IfStatementAst]) {
            foreach ($clause in $node.Clauses) {
                if ([object]::ReferenceEquals($clause.Item2, $child)) {
                    $flags = Get-ZbPlanMembers -Ast $clause.Item1 -VariableName $VariableName
                    if (@($flags).Count -gt 0) { return (@($flags) -join '+') }
                }
            }
        }
        $child = $node
        $node = $node.Parent
    }
    return $null
}

# --------------------------------------------------------------------------------------------
# Deterministic JSON writer. ConvertTo-Json changes indentation and escaping between
# PowerShell versions; the matrix is a file people diff, so the bytes are produced here.
# --------------------------------------------------------------------------------------------

function ConvertTo-ZbJsonString {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if ($ch -eq '"') { [void]$sb.Append('\"') }
        elseif ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($ch -eq "`n") { [void]$sb.Append('\n') }
        elseif ($ch -eq "`r") { [void]$sb.Append('\r') }
        elseif ($ch -eq "`t") { [void]$sb.Append('\t') }
        elseif ($code -lt 32) { [void]$sb.Append('\u' + $code.ToString('x4', $script:ZbInv)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-ZbJson {
    param($Value, [int]$Indent = 0)
    $pad = ' ' * $Indent
    $padIn = ' ' * ($Indent + 2)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } return 'false' }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return [System.Convert]::ToString($Value, $script:ZbInv)
    }
    if ($Value -is [string]) { return (ConvertTo-ZbJsonString -Text $Value) }
    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Count -eq 0) { return '{}' }
        $parts = @()
        foreach ($k in $Value.Keys) {
            $parts += ($padIn + (ConvertTo-ZbJsonString -Text ([string]$k)) + ': ' +
                (ConvertTo-ZbJson -Value $Value[$k] -Indent ($Indent + 2)))
        }
        return ('{' + "`n" + ($parts -join (",`n")) + "`n" + $pad + '}')
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
        if ($items.Count -eq 0) { return '[]' }
        $parts = @()
        foreach ($it in $items) {
            $parts += ($padIn + (ConvertTo-ZbJson -Value $it -Indent ($Indent + 2)))
        }
        return ('[' + "`n" + ($parts -join (",`n")) + "`n" + $pad + ']')
    }
    return (ConvertTo-ZbJsonString -Text ([string]$Value))
}

# --------------------------------------------------------------------------------------------
# Collect the module files
# --------------------------------------------------------------------------------------------

$moduleFiles = @()
foreach ($entry in $Root) {
    if (-not (Test-Path -LiteralPath $entry)) {
        Stop-ZbFatal -Message ('-Root entry not found: ' + $entry)
    }
    $resolved = (Resolve-Path -LiteralPath $entry).Path
    if (Test-Path -LiteralPath $resolved -PathType Container) {
        $found = @(Get-ChildItem -LiteralPath $resolved -Filter '*.ps1' -File -Recurse:$Recurse)
        foreach ($f in $found) { $moduleFiles += $f.FullName }
    }
    else {
        $moduleFiles += $resolved
    }
}
# Plain assignment on purpose: the sort helpers return ,$array, and @( ) around such a call
# nests the array instead of unwrapping it (BLUEPRINT §8.5). Same at every helper call below.
$moduleFiles = Get-ZbSortedStrings -Values @($moduleFiles | Select-Object -Unique)
if ($moduleFiles.Count -eq 0) {
    Stop-ZbFatal -Message ('No .ps1 files under -Root (' + ($Root -join ', ') + '). Nothing to scan.')
}

# Module display name: leaf file name, with the parent directory prepended only on a leaf
# collision, so the matrix does not churn when the tree moves between machines.
$leafCount = @{}
foreach ($mf in $moduleFiles) {
    $leaf = [System.IO.Path]::GetFileName($mf)
    if ($leafCount.ContainsKey($leaf)) { $leafCount[$leaf] = $leafCount[$leaf] + 1 } else { $leafCount[$leaf] = 1 }
}
$moduleNameOf = @{}
foreach ($mf in $moduleFiles) {
    $leaf = [System.IO.Path]::GetFileName($mf)
    if ($leafCount[$leaf] -gt 1) {
        $parent = [System.IO.Path]::GetFileName([System.IO.Path]::GetDirectoryName($mf))
        $moduleNameOf[$mf] = ($parent + '/' + $leaf)
    }
    else {
        $moduleNameOf[$mf] = $leaf
    }
}

# --------------------------------------------------------------------------------------------
# Parse and walk
# --------------------------------------------------------------------------------------------

$phaseEntries = @()          # one per header call
$headerProblems = @()        # headers whose phase number could not be read
$unattributedFindings = 0    # finding calls before any header in their file
$dynamicSignatureReads = 0   # lookup calls whose key is an expression
$allSignatureReads = @{}     # every literal key read anywhere (attributed or not)

foreach ($filePath in $moduleFiles) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($filePath, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -gt 0) {
        # A module that does not parse means findings the matrix cannot see. Loud beats wrong.
        foreach ($e in @($errors)) {
            $host.UI.WriteErrorLine(($moduleNameOf[$filePath]) + ':' + $e.Extent.StartLineNumber + ': ' + $e.Message)
        }
        exit 2
    }

    $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    $headers = @()
    $findingCalls = @()
    $sigCalls = @()
    foreach ($cmd in @($commands)) {
        $cmdName = $cmd.GetCommandName()
        if ($null -eq $cmdName) { continue }
        if ($cmdName -eq $PhaseHeaderCommand) { $headers += $cmd }
        elseif ($cmdName -eq $FindingCommand) { $findingCalls += $cmd }
        elseif ($cmdName -eq $SignatureLookupCommand) { $sigCalls += $cmd }
    }

    $moduleName = $moduleNameOf[$filePath]
    $fileEntries = @()
    foreach ($hdr in $headers) {
        $named = Get-ZbNamedArguments -Command $hdr
        $phaseKey = $null
        if ($named.ContainsKey($PhaseParameter)) { $phaseKey = Format-ZbPhaseKey -Text $named[$PhaseParameter] }
        if ($null -eq $phaseKey) {
            $headerProblems += ($moduleName + ':' + $hdr.Extent.StartLineNumber +
                ' header has no literal -' + $PhaseParameter + ' number')
            continue
        }
        $title = '(dynamic)'
        if ($named.ContainsKey($TitleParameter) -and $null -ne $named[$TitleParameter]) { $title = $named[$TitleParameter] }
        $category = '(dynamic)'
        if ($named.ContainsKey($CategoryParameter) -and $null -ne $named[$CategoryParameter]) { $category = $named[$CategoryParameter] }
        $fileEntries += New-Object PSObject -Property @{
            Key           = $phaseKey
            KeyNumber     = [double]::Parse($phaseKey, $script:ZbInv)
            Title         = $title
            Category      = $category
            Module        = $moduleName
            Line          = [int]$hdr.Extent.StartLineNumber
            Offset        = [int]$hdr.Extent.StartOffset
            Gate          = (Get-ZbModeGate -Command $hdr -VariableName $PlanVariable)
            Severities    = @{}
            FixActions    = @{}
            SignatureKeys = @{}
            FindingCalls  = 0
        }
    }
    $fileEntries = @($fileEntries | Sort-Object -Property Offset)

    # A call belongs to the nearest header above it in the same file; the matrix cares that
    # the call exists, not whether its branch executes (BLUEPRINT §7).
    foreach ($call in $findingCalls) {
        $owner = $null
        foreach ($fe in $fileEntries) { if ($fe.Offset -lt $call.Extent.StartOffset) { $owner = $fe } }
        if ($null -eq $owner) { $unattributedFindings = $unattributedFindings + 1; continue }
        $owner.FindingCalls = $owner.FindingCalls + 1
        $named = Get-ZbNamedArguments -Command $call
        if ($named.ContainsKey('Severity')) {
            $sev = $named['Severity']
            if ($null -eq $sev) { $sev = 'dynamic' }
            $owner.Severities[$sev] = $true
        }
        if ($named.ContainsKey('FixAction')) {
            $fix = $named['FixAction']
            if ($null -eq $fix) { $fix = 'dynamic' }
            $owner.FixActions[$fix] = $true
        }
    }

    foreach ($call in $sigCalls) {
        $named = Get-ZbNamedArguments -Command $call
        $key = $null
        if ($named.ContainsKey($SignatureKeyParameter)) { $key = $named[$SignatureKeyParameter] }
        if ($null -eq $key) { $dynamicSignatureReads = $dynamicSignatureReads + 1; continue }
        $allSignatureReads[$key] = $true
        $owner = $null
        foreach ($fe in $fileEntries) { if ($fe.Offset -lt $call.Extent.StartOffset) { $owner = $fe } }
        if ($null -ne $owner) { $owner.SignatureKeys[$key] = $true }
    }

    $phaseEntries += $fileEntries
}

if ($phaseEntries.Count -eq 0) {
    Stop-ZbFatal -Message ('No ' + $PhaseHeaderCommand + ' calls found under -Root (' + ($Root -join ', ') +
        '). Wrong root, or the header command has another name — pass it with -PhaseHeaderCommand. ' +
        'Refusing to write an empty matrix.')
}

# --------------------------------------------------------------------------------------------
# Order and shape the output
# --------------------------------------------------------------------------------------------

# Numeric phase order — a lexical sort puts 10 between 1 and 2 and the file stops diffing.
# Module, title and line break exact ties, so the order is fully determined. The index rides
# at the end of each key and the list is rebuilt from it: sorting a single string[] avoids the
# keys/items Array.Sort overload, which PowerShell binds to a converted copy of the items.
$sortKeys = @()
for ($i = 0; $i -lt $phaseEntries.Count; $i = $i + 1) {
    $pe = $phaseEntries[$i]
    $sortKeys += ($pe.KeyNumber.ToString('000000.000', $script:ZbInv) + '|' + $pe.Module + '|' + $pe.Title + '|' +
        $pe.Line.ToString('000000', $script:ZbInv) + '|' + $i.ToString('000000', $script:ZbInv))
}
$sortKeys = [string[]]$sortKeys
[System.Array]::Sort($sortKeys, [System.StringComparer]::Ordinal)
$sortedEntries = @()
foreach ($sk in $sortKeys) {
    $sortedEntries += $phaseEntries[[int]@($sk -split '\|')[-1]]
}
$phaseEntries = $sortedEntries

function Get-ZbRankedSeverities {
    param([hashtable]$Set)
    $keys = @()
    foreach ($k in $Set.Keys) {
        $rank = 90
        if ($script:ZbSeverityRank.ContainsKey($k)) { $rank = [int]$script:ZbSeverityRank[$k] }
        if ($k -eq 'dynamic') { $rank = 99 }
        $keys += ($rank.ToString('00', $script:ZbInv) + '|' + $k)
    }
    $keys = Get-ZbSortedStrings -Values $keys
    $out = @()
    foreach ($k in $keys) { $out += @($k -split '\|', 2)[1] }
    return , $out
}

$quickCeiling = [double]$script:ZbModeCeiling['QUICK']
$phaseList = @()
$ungated = @()
$keySeen = @{}
$duplicateKeys = @{}
foreach ($pe in $phaseEntries) {
    if ($keySeen.ContainsKey($pe.Key)) { $duplicateKeys[$pe.Key] = $true } else { $keySeen[$pe.Key] = $true }
    if ($null -eq $pe.Gate) { $ungated += $pe.Key }
    $row = [ordered]@{
        phase            = $pe.Key
        title            = $pe.Title
        category         = $pe.Category
        module           = $pe.Module
        mode_gate        = $pe.Gate
        severities       = (Get-ZbRankedSeverities -Set $pe.Severities)
        fix_actions      = (Get-ZbSortedStrings -Values @($pe.FixActions.Keys | ForEach-Object { [string]$_ }))
        signature_keys   = (Get-ZbSortedStrings -Values @($pe.SignatureKeys.Keys | ForEach-Object { [string]$_ }))
        finding_calls    = [int]$pe.FindingCalls
        skipped_in_quick = ($pe.KeyNumber -gt $quickCeiling)
    }
    $phaseList += , $row
}

# Per-module / per-mode / per-gate / per-fix-action counts.
$perModule = [ordered]@{}
foreach ($m in (Get-ZbSortedStrings -Values @($phaseEntries | ForEach-Object { $_.Module } | Select-Object -Unique))) {
    $perModule[$m] = @($phaseEntries | Where-Object { $_.Module -eq $m }).Count
}
$perMode = [ordered]@{}
foreach ($mode in (Get-ZbSortedStrings -Values @($script:ZbModeCeiling.Keys | ForEach-Object { [string]$_ }))) {
    $ceiling = [double]$script:ZbModeCeiling[$mode]
    $perMode[$mode] = @($phaseEntries | Where-Object { $_.KeyNumber -le $ceiling }).Count
}
$perGate = [ordered]@{}
foreach ($g in (Get-ZbSortedStrings -Values @($phaseEntries | Where-Object { $null -ne $_.Gate } | ForEach-Object { $_.Gate } | Select-Object -Unique))) {
    $perGate[$g] = @($phaseEntries | Where-Object { $_.Gate -eq $g }).Count
}
$perFix = [ordered]@{}
$allFixNames = @{}
foreach ($pe in $phaseEntries) { foreach ($fx in $pe.FixActions.Keys) { $allFixNames[[string]$fx] = $true } }
foreach ($fx in (Get-ZbSortedStrings -Values @($allFixNames.Keys | ForEach-Object { [string]$_ }))) {
    $perFix[$fx] = @($phaseEntries | Where-Object { $_.FixActions.ContainsKey($fx) }).Count
}

# Orphan keys, both directions, only when a signature file was given. Read-but-missing is a
# bug in the engine; present-but-unread is dead weight in the file. Null (not empty) when the
# check did not run.
$signatureFileName = $null
$missingKeys = $null
$unreadKeys = $null
if (-not [string]::IsNullOrEmpty($SignaturePath)) {
    if (-not (Test-Path -LiteralPath $SignaturePath)) {
        Stop-ZbFatal -Message ('-SignaturePath not found: ' + $SignaturePath)
    }
    $signatureFileName = [System.IO.Path]::GetFileName($SignaturePath)
    $sigJson = Get-Content -LiteralPath $SignaturePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $presentKeys = @{}
    foreach ($prop in @($sigJson.PSObject.Properties)) { $presentKeys[[string]$prop.Name] = $true }
    $missingKeys = @()
    foreach ($k in @($allSignatureReads.Keys | ForEach-Object { [string]$_ })) {
        if (-not $presentKeys.ContainsKey($k)) { $missingKeys += $k }
    }
    $unreadKeys = @()
    foreach ($k in @($presentKeys.Keys | ForEach-Object { [string]$_ })) {
        if (-not $allSignatureReads.ContainsKey($k)) { $unreadKeys += $k }
    }
    $missingKeys = Get-ZbSortedStrings -Values $missingKeys
    $unreadKeys = Get-ZbSortedStrings -Values $unreadKeys
}

# Numeric sort for the small key lists too.
function Get-ZbNumericKeySort {
    param([string[]]$Keys)
    $arr = @($Keys)
    if ($arr.Count -le 1) { return , $arr }
    # Same single-array sort technique as the phase list, for the same reason.
    $nums = @()
    for ($i = 0; $i -lt $arr.Count; $i = $i + 1) {
        $nums += (([double]::Parse($arr[$i], $script:ZbInv)).ToString('000000.000', $script:ZbInv) + '|' +
            $i.ToString('000000', $script:ZbInv))
    }
    $nums = [string[]]$nums
    [System.Array]::Sort($nums, [System.StringComparer]::Ordinal)
    $out = @()
    foreach ($n in $nums) { $out += $arr[[int]@($n -split '\|')[-1]] }
    return , $out
}
$ungated = Get-ZbNumericKeySort -Keys @($ungated | Select-Object -Unique)
$duplicates = Get-ZbNumericKeySort -Keys @($duplicateKeys.Keys | ForEach-Object { [string]$_ })

if ([string]::IsNullOrEmpty($GeneratedFrom)) {
    $GeneratedFrom = 'unknown'
    try {
        $gitDir = $moduleFiles[0]
        if (-not (Test-Path -LiteralPath $gitDir -PathType Container)) { $gitDir = [System.IO.Path]::GetDirectoryName($gitDir) }
        $commit = & git -C $gitDir rev-parse --short HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrEmpty($commit)) { $GeneratedFrom = [string]$commit }
    }
    catch { $GeneratedFrom = 'unknown' }
}

$matrix = [ordered]@{
    schema         = 'zerobreach-coverage-matrix/1'
    generated_from = $GeneratedFrom
    scan           = [ordered]@{
        phase_header_command     = $PhaseHeaderCommand
        finding_command          = $FindingCommand
        signature_lookup_command = $SignatureLookupCommand
        plan_variable            = $PlanVariable
        signature_file           = $signatureFileName
        modules                  = (Get-ZbSortedStrings -Values @($moduleNameOf.Values | ForEach-Object { [string]$_ } | Select-Object -Unique))
    }
    phases         = $phaseList
    summary        = [ordered]@{
        phase_count                      = $phaseEntries.Count
        phases_per_module                = $perModule
        phases_per_mode                  = $perMode
        phases_per_gate                  = $perGate
        phases_per_fix_action            = $perFix
        ungated_phases                   = $ungated
        duplicate_phases                 = $duplicates
        headers_unparsed                 = (Get-ZbSortedStrings -Values $headerProblems)
        unattributed_finding_calls       = [int]$unattributedFindings
        dynamic_signature_reads          = [int]$dynamicSignatureReads
        signature_keys_missing_from_file = $missingKeys
        signature_keys_unread            = $unreadKeys
    }
}

# --------------------------------------------------------------------------------------------
# Write
# --------------------------------------------------------------------------------------------

if ([string]::IsNullOrEmpty($OutPath)) {
    $projectRoot = Split-Path -Path $PSScriptRoot -Parent
    $OutPath = Join-Path -Path (Join-Path -Path $projectRoot -ChildPath 'data') -ChildPath 'coverage_matrix.generated.json'
}
if ([System.IO.Path]::GetFileName($OutPath) -eq 'coverage_matrix.json') {
    Stop-ZbFatal -Message ('Refusing to write coverage_matrix.json — that is the promoted file the main session ' +
        'diffs against. Write coverage_matrix.generated.json and promote by diff.')
}

$json = (ConvertTo-ZbJson -Value $matrix -Indent 0) + "`n"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$outDir = [System.IO.Path]::GetDirectoryName($OutPath)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
[System.IO.File]::WriteAllText($OutPath, $json, $utf8NoBom)

# --------------------------------------------------------------------------------------------
# Operator summary — what a technician needs before trusting the file
# --------------------------------------------------------------------------------------------

$fractionalCount = @($phaseEntries | Where-Object { $_.Key.Contains('.') }).Count
Write-Host ('Scanned ' + $moduleFiles.Count + ' module file(s); found ' + $phaseEntries.Count +
    ' phase(s), ' + $fractionalCount + ' fractional.')
if ($ungated.Count -gt 0) {
    Write-Host ('WARNING: ' + $ungated.Count + ' phase(s) have no detectable mode gate: ' + ($ungated -join ', ') +
        '. They are recorded with mode_gate null — check the engine, not this tool, first.')
}
if ($duplicates.Count -gt 0) {
    Write-Host ('WARNING: duplicate phase number(s): ' + ($duplicates -join ', ') + '. Both declarations are listed.')
}
foreach ($hp in @($headerProblems)) { Write-Host ('WARNING: ' + $hp) }
if ($unattributedFindings -gt 0) {
    Write-Host ('Note: ' + $unattributedFindings + ' finding call(s) sit above any phase header (preflight output).')
}
if ($null -ne $missingKeys -and @($missingKeys).Count -gt 0) {
    Write-Host ('WARNING: signature key(s) read by the engine but missing from ' + $signatureFileName + ': ' +
        (@($missingKeys) -join ', ') + '. Those lookups find nothing — that is a bug, not dead weight.')
}
if ($null -ne $unreadKeys -and @($unreadKeys).Count -gt 0) {
    Write-Host ('Note: signature key(s) present in ' + $signatureFileName + ' but read by nothing: ' +
        (@($unreadKeys) -join ', ') + '. Dead weight — candidates for removal.')
}
Write-Host ('Wrote ' + $OutPath)

if ($PassThru) { $matrix }
exit 0
