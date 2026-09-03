<#
.SYNOPSIS
    Regenerate data\trusted_root_program.json from the Microsoft Trusted Root Program report.

.DESCRIPTION
    Phase 39 decides whether a root certificate in Cert:\LocalMachine\Root or
    Cert:\CurrentUser\Root got there legitimately by THUMBPRINT, against the list this file
    holds, plus the machine's own AuthRoot store. The list is the CCADB's public report of
    every root in the Microsoft Trusted Root Program (Included / Disabled / NotBefore), and
    Microsoft changes it monthly, so it is a snapshot that has to be refreshed - this script
    is the only supported way to do that. It runs off Windows too (pwsh 7).

    The 'windows_shipped' and 'windows_shipped_legacy' blocks are NOT touched: they are the
    handful of Microsoft roots that ship inside Windows rather than through the CTL, verified
    against https://www.microsoft.com/pkiops/docs/repository.htm and KB 293781, and they
    change once a decade. Edit those by hand, with the source in the commit message.

    Nothing here is a malware signature; the file is a list of things that are ALLOWED.

.PARAMETER Source
    CSV report URL. Default: the CCADB "Included CA Certificate Report for Microsoft" CSV.

.PARAMETER OutFile
    Path to write. Default: <repo>\data\trusted_root_program.json.

.EXAMPLE
    pwsh -NoProfile -File tools\Update-TrustedRoots.ps1
#>
[CmdletBinding()]
param(
    [string]$Source  = 'https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV',
    [string]$OutFile = (Join-Path (Split-Path -Parent $PSScriptRoot) 'data\trusted_root_program.json')
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $OutFile)) { throw "missing $OutFile - this script refreshes the 'program' block of an existing file, it does not create one" }
$existing = Get-Content -LiteralPath $OutFile -Raw -Encoding UTF8 | ConvertFrom-Json

Write-Host "[Update-TrustedRoots] downloading $Source"
$csvText = (Invoke-WebRequest -Uri $Source -UseBasicParsing -TimeoutSec 120).Content
$rows = @($csvText | ConvertFrom-Csv)
if ($rows.Count -lt 200) { throw "only $($rows.Count) rows in the report - refusing to overwrite a $(@($existing.program).Count)-entry list with it" }

$required = @('Microsoft Status','CA Owner','CA Common Name or Certificate Name','SHA-1 Fingerprint','SHA-256 Fingerprint')
foreach ($col in $required) {
    if (-not ($rows[0].PSObject.Properties.Name -contains $col)) { throw "report has no '$col' column - the CCADB format changed; update this script before trusting its output" }
}

$program = New-Object System.Collections.Generic.List[object]
foreach ($r in $rows) {
    $sha1   = "$($r.'SHA-1 Fingerprint')".Trim().ToUpper()
    $sha256 = "$($r.'SHA-256 Fingerprint')".Trim().ToUpper()
    if ($sha1 -notmatch '^[0-9A-F]{40}$' -or $sha256 -notmatch '^[0-9A-F]{64}$') { throw "malformed fingerprint for '$($r.'CA Common Name or Certificate Name')'" }
    $status = "$($r.'Microsoft Status')".Trim()
    if ($status -notin @('Included','Disabled','NotBefore')) { throw "unexpected Microsoft Status '$status' - update phase 39's status handling before shipping this" }
    $program.Add([ordered]@{
        status = $status
        name   = "$($r.'CA Common Name or Certificate Name')".Trim()
        owner  = "$($r.'CA Owner')".Trim()
        sha1   = $sha1
        sha256 = $sha256
    })
}
$sorted = @($program | Sort-Object { $_.owner.ToLower() }, { $_.name.ToLower() })

# Write the file by hand so each entry stays on one line (ConvertTo-Json explodes every
# object over six lines and the diff becomes unreadable).
function Q([string]$s) { '"' + ($s -replace '\\','\\' -replace '"','\"') + '"' }
$sb = New-Object System.Text.StringBuilder
[void]$sb.Append("{`n")
[void]$sb.Append(' "_comment": ' + (Q "$($existing._comment)") + ",`n")
[void]$sb.Append(' "source": ' + (Q $Source) + ",`n")
[void]$sb.Append(' "retrieved": ' + (Q (Get-Date -Format 'yyyy-MM-dd')) + ",`n")
[void]$sb.Append(" `"windows_shipped`": [`n")
$ws = @($existing.windows_shipped)
for ($i = 0; $i -lt $ws.Count; $i++) {
    [void]$sb.Append('  {"name": ' + (Q "$($ws[$i].name)") + ', "sha1": ' + (Q "$($ws[$i].sha1)") + '}' + $(if ($i -lt $ws.Count - 1) { ",`n" } else { "`n" }))
}
[void]$sb.Append(" ],`n")
[void]$sb.Append(' "_comment_windows_shipped_legacy": ' + (Q "$($existing._comment_windows_shipped_legacy)") + ",`n")
[void]$sb.Append(" `"windows_shipped_legacy`": [`n")
$lg = @($existing.windows_shipped_legacy)
for ($i = 0; $i -lt $lg.Count; $i++) {
    [void]$sb.Append('  {"cn": ' + (Q "$($lg[$i].cn)") + ', "serial": ' + (Q "$($lg[$i].serial)") + ', "expires_before": ' + (Q "$($lg[$i].expires_before)") + '}' + $(if ($i -lt $lg.Count - 1) { ",`n" } else { "`n" }))
}
[void]$sb.Append(" ],`n")
[void]$sb.Append(" `"program`": [`n")
for ($i = 0; $i -lt $sorted.Count; $i++) {
    $e = $sorted[$i]
    [void]$sb.Append('  {"status": ' + (Q $e.status) + ', "name": ' + (Q $e.name) + ', "owner": ' + (Q $e.owner) + ', "sha1": ' + (Q $e.sha1) + ', "sha256": ' + (Q $e.sha256) + '}' + $(if ($i -lt $sorted.Count - 1) { ",`n" } else { "`n" }))
}
[void]$sb.Append(" ]`n}`n")

$text = $sb.ToString()
$null = $text | ConvertFrom-Json   # must round-trip before it replaces the shipped file
[System.IO.File]::WriteAllText($OutFile, $text, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[Update-TrustedRoots] wrote $($sorted.Count) program roots (was $(@($existing.program).Count)) to $OutFile"
