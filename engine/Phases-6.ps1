# NOTE - Detection vocabulary in this file is deliberate.
# Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
# named malware families, are detection category labels, operator-facing report text, or
# MITRE ATT&CK tactic names (a published standard). Scythe is a defensive incident-
# response tool; these strings are what it reports, not what it does. See CLAUDE.md,
# "The detection vocabulary is deliberate". Do not sanitise them.

trap { Write-RecoveredError $_; continue }   # module-level resilience (see CLAUDE.md engine-split rule)

# ══════════════════════════════════════════════════════════════════════════════
#  HUNT BAND — PHASES 146-159 — COMPLETE (2026-08-31)
#
#    146      PE structural analysis                               (task F3)
#    147      cloud identity + DevOps credential theft             (task F1)
#    148-152  lateral movement, credential dumping, Kerberos/NTLM  (task F2)
#    153-156  network-exposure posture, host-side only             (task F6)
#    157      remaining persistence surface                        (task F4)
#    158      supply chain + developer tooling                     (task F5)
#    159      UEFI / ESP integrity                                 (task F7)
#
#  148-152 (2026-08-31) narrow their brief the same way 159 and 153-156 narrowed
#  theirs, on two counts. First, DUPLICATION: phase 107 already owns the 7045 and
#  4624 records, 133 owns the lateral command lines, 106 owns .dmp files and dumper
#  tool names, 88 owns 4769/4662, and 41 owns WDigest and RunAsPPL — roughly twenty
#  sub-checks from the F2 brief were dropped or re-scoped rather than shipped as a
#  second opinion on an artifact another phase already reports. Second, REACH: the
#  domain-wide LDAP sweep the brief asked for (AS-REP roastable accounts, delegation
#  across every computer object, AdminSDHolder drift) is query-for-query what
#  BloodHound issues against the customer's directory, and ADCS ESC8 needs an HTTP
#  request to a customer server. Phase 150 reads THIS COMPUTER'S OWN object, one
#  result, timeouts set, and nothing else.
#
#  Phase 159 narrows its brief the same way 153-156 narrowed F6, and for the same
#  reason: it DOES NOT MOUNT the EFI System Partition and no switch is provided to
#  make it. The full reasoning is in the phase's own banner.
#
#  153-156 ARE BUILT (2026-08-22). They are the network-exposure band, and they are
#  HOST-SIDE ONLY: every check is a registry / WMI / CIM read of THIS machine's own
#  posture. They send no packets and they do not enumerate the LAN.
#
#  That is a deliberate narrowing of the original F6 scope ("LAN band, opt-in, requires
#  -ScanLan"). Reasons, recorded so nobody widens it back by accident:
#    * Scythe runs on client networks under an MSP contract. A tool that probes the
#      customer's LAN can trip the customer's own IDS and is indistinguishable, on the
#      wire, from the activity it exists to detect.
#    * Every finding below is answerable from the host's own configuration. Probing the
#      network adds no detection the registry cannot already supply.
#    * No -ScanLan switch is therefore needed and none is introduced; these run whenever
#      HUNT runs.
#
#  Band rule (CLAUDE.md): everything in 134-162 is FixAction "Info". Severity may still
#  be HIGH — HIGH + Info is never auto-selected, because auto-select requires a
#  DESTRUCTIVE FixAction. Several of these settings brick file sharing or logon if
#  written blind, so the remediation is operator-run and the exact command is in the
#  finding description.
# ══════════════════════════════════════════════════════════════════════════════
# ── Helpers for phases 147/157/158/159 ───────────────────────────────────────
# Defined unconditionally, before the $PhasePlan gate, so the AST tests can find them
# whatever mode the engine is in — same convention as the rest of the band.

function Test-ScytheNameRule {
    # True when $Name matches ANY regex in $Rules. Every match runs under the same 150 ms
    # budget Join-AllowRegex uses: these patterns come from data/detection_signatures.json
    # and are applied to attacker-authored text (file names, command lines, ESP paths), so
    # a catastrophic-backtracking pattern edited into the DB would otherwise be a denial of
    # service on the scan itself. A pattern that will not compile is skipped, not fatal.
    param([string]$Name, $Rules)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    foreach ($r in @($Rules)) {
        if ([string]::IsNullOrWhiteSpace("$r")) { continue }
        try {
            $rx = New-Object System.Text.RegularExpressions.Regex("$r",
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
                [TimeSpan]::FromMilliseconds(150))
            if ($rx.IsMatch($Name)) { return $true }
        } catch { continue }
    }
    return $false
}

function Test-ScytheTextRules {
    # Test-ContentRules reads a FILE. These phases also need the same {Name,Pattern,Severity}
    # rule shape applied to text that never touches disk — a registry value, bcdedit output,
    # a process command line, a package.json already in memory. Returns the highest-severity
    # matching rule, or $null. Same per-pattern 150 ms budget and the same fail-soft skip.
    param([string]$Text, $Rules)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $ruleRank = @{ "CRITICAL" = 3; "HIGH" = 2; "POSSIBLE" = 1 }
    $bestRule = $null
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        if ([string]::IsNullOrWhiteSpace("$($r.Pattern)")) { continue }
        try {
            $rx = New-Object System.Text.RegularExpressions.Regex("$($r.Pattern)",
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
                [TimeSpan]::FromMilliseconds(150))
            if (-not $rx.IsMatch($Text)) { continue }
        } catch { continue }
        if ($null -eq $bestRule -or [int]$ruleRank["$($r.Severity)"] -gt [int]$ruleRank["$($bestRule.Severity)"]) {
            $bestRule = $r
        }
    }
    return $bestRule
}

function Resolve-ScytheModulePath {
    # Registry persistence values name their module in every shape Windows accepts: quoted,
    # bare, %SystemRoot%-relative, with an export or ordinal after a comma, or a leaf name
    # that only resolves against System32. Normalise to a full path. Uses $global:SCYTHE_SYS32
    # rather than the literal System32 path, because a 32-bit engine is redirected to
    # SysWOW64 and would verify the wrong copy of the DLL (CLAUDE.md WOW64 rule).
    param([string]$Value)
    $v = "$Value".Trim()
    if ([string]::IsNullOrWhiteSpace($v)) { return "" }
    $v = $v.Trim('"').Trim()
    # rundll32-style "path,Export" / "path,#1" — keep the path half only.
    if ($v -match '^(?<p>[^,]+),[^\\/]*$') { $v = "$($Matches['p'])".Trim().Trim('"') }
    try { $v = [System.Environment]::ExpandEnvironmentVariables($v) } catch { }
    if ($v -match '^[A-Za-z]:[\\/]' -or $v -match '^\\\\') { return $v }
    if ([string]::IsNullOrWhiteSpace($global:SCYTHE_SYS32)) { return $v }
    return (Join-Path $global:SCYTHE_SYS32 $v)
}

$global:SCYTHE_P157_SIGSW      = $null
$global:SCYTHE_P157_SIGSEEN    = 0
$global:SCYTHE_P157_SIGSKIPPED = 0

function Test-ScytheUntrustedModule {
    # True when the module at $Path is missing, unresolvable, or not validly signed.
    # The MECHANISM existing is usually normal — Windows and several vendors register
    # netsh helpers, print monitors, time providers and LSPs legitimately. What makes one
    # a finding is the module behind it, so the signature verdict carries the weight here
    # and the path allowlist is kept deliberately small.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    if ($Path -match $PERSIST_DLL_BENIGN_RE) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    # Authenticode is the most expensive operation in the engine and this phase reaches it
    # from several branches over dozens of distinct modules. Carry the shared budget
    # (CLAUDE.md: any loop calling Get-AuthSig MUST carry $global:SIG_AUDIT_*). Past the
    # budget we return $false — "do not report" — because the alternative, treating an
    # unverifiable module as untrusted, would emit a HIGH finding for every remaining
    # mechanism the moment CRL/OCSP became unreachable.
    if ($null -eq $global:SCYTHE_P157_SIGSW) { $global:SCYTHE_P157_SIGSW = [System.Diagnostics.Stopwatch]::StartNew() }
    if ($global:SCYTHE_P157_SIGSEEN -ge $global:SIG_AUDIT_MAX_FILES -or
        $global:SCYTHE_P157_SIGSW.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
        $global:SCYTHE_P157_SIGSKIPPED++
        return $false
    }
    $global:SCYTHE_P157_SIGSEEN++
    $verdict = Get-SignatureVerdict $Path
    if ("$($verdict.Status)" -eq 'Valid') { return $false }
    return $true
}

function Get-ScytheRepoRoots {
    # Local repository roots, found from a FIXED SHALLOW list of the directories developers
    # actually keep code in, two levels deep, with no -Recurse anywhere. Deliberately not a
    # profile walk: a developer's profile holds hundreds of thousands of files under
    # node_modules and .venv, walking it blows the phase's wall-clock budget, and it finds
    # nothing the targeted roots do not. Capped so a machine with a very large number of
    # clones cannot stall the phase.
    # Memoised: phase 158 asks three times (extensions, git configs, package registries) and
    # the walk is the expensive part of the phase. The engine is audit-only under -Auto, so
    # the filesystem is static for a run.
    if ($null -ne $global:SCYTHE_REPO_ROOTS) { return ,$global:SCYTHE_REPO_ROOTS }
    # Documents, Desktop and Downloads are deliberately NOT walked. On a managed endpoint
    # they are commonly folder-redirected to a UNC share, which turns this into an SMB
    # directory walk over the network - slow, and a surprise for the customer's file server.
    # A developer's clones live in the source/repos/git/dev directories below.
    $names = @('source','source\repos','repos','git','Projects','projects','dev','src','code','work')
    $found = New-Object System.Collections.Generic.List[string]
    $walkSw = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($n in $names) {
        if ($found.Count -ge 60 -or $walkSw.Elapsed.TotalSeconds -ge 8) { break }
        $base = Join-Path $env:USERPROFILE $n
        if (-not (Test-Path -LiteralPath $base)) { continue }
        if (Test-Path -LiteralPath (Join-Path $base '.git')) { $found.Add($base) }
        $level1 = @()
        try { $level1 = @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction Stop) } catch { $level1 = @() }
        foreach ($d1 in $level1) {
            if ($found.Count -ge 60 -or $walkSw.Elapsed.TotalSeconds -ge 8) { break }
            $p1 = "$($d1.FullName)"
            if ($p1 -match $DEVTOOL_BENIGN_RE) { continue }
            if (Test-Path -LiteralPath (Join-Path $p1 '.git')) { $found.Add($p1); continue }
            $level2 = @()
            try { $level2 = @(Get-ChildItem -LiteralPath $p1 -Directory -ErrorAction Stop) } catch { $level2 = @() }
            foreach ($d2 in $level2) {
                if ($found.Count -ge 60) { break }
                $p2 = "$($d2.FullName)"
                if ($p2 -match $DEVTOOL_BENIGN_RE) { continue }
                if (Test-Path -LiteralPath (Join-Path $p2 '.git')) { $found.Add($p2) }
            }
        }
    }
    $walkSw.Stop()
    $global:SCYTHE_REPO_ROOTS = $found.ToArray()
    return ,$global:SCYTHE_REPO_ROOTS
}

function Get-ScytheEspRoot {
    # An ALREADY-REACHABLE path to the EFI System Partition, or '' if it has none.
    # This function deliberately mounts NOTHING. Assigning a system partition an access
    # path is a live change to a client machine's boot volume state, and "leave nothing
    # behind" is a standing rule for this product (audit M5/M9/M10). If the operator has
    # mounted the ESP themselves, the phase uses it; otherwise it reports that the
    # contents were not inventoried and hands over the exact commands.
    $accessPaths = @()
    try {
        foreach ($part in @(Get-Partition -ErrorAction Stop)) {
            if ("$($part.GptType)" -ne '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}') { continue }
            foreach ($ap in @($part.AccessPaths)) { if ("$ap") { $accessPaths += "$ap" } }
        }
    } catch { return "" }
    # Prefer a drive letter or a mounted folder; a raw \\?\Volume{...} GUID path is not
    # reachable through the FileSystem provider on every build, so it is only a fallback.
    foreach ($ap in $accessPaths) {
        if ($ap -notmatch '^[A-Za-z]:') { continue }
        if (Test-Path -LiteralPath $ap) { return $ap }
    }
    foreach ($ap in $accessPaths) {
        $ok = $false
        try { $ok = [bool](Test-Path -LiteralPath $ap -ErrorAction Stop) } catch { $ok = $false }
        if ($ok) { return $ap }
    }
    return ""
}

# ── PE structural parsing for phase 146 ──────────────────────────────────────
# Pure .NET reads over a byte array. NO P/Invoke and NO Add-Type: declaring memory APIs or
# compiling C# inline is the exact code shape AV heuristics flag, and an engine Defender
# blocks at load detects nothing at all (CLAUDE.md, and Test-Hunt-Band asserts it).
#
# lib/Scythe.Formats/Pe/ is the specification these mirror. Keep the two in step; its
# PeHostileTests enumerate the truncation cases these bounds exist for.
#
# A malformed PE is NORMAL INPUT here, not an error. Every function returns $null or a
# partial result rather than throwing — a hostile file must never reach the resilience trap
# and be reported as a RECOVERED ERROR.
#
# The Sections list is enumerated with a PLAIN foreach, never `@($Sections)`. The .NET
# 8.0.10 servicing regression (System.Linq.Expressions; PowerShell "Argument types do not
# match") breaks the @()-to-object-array binder on the PSObject-wrapped List[object] that
# New-Object returns, while plain foreach enumeration is unaffected. On an affected host
# the @() form made Read-ScythePeImports return $null for EVERY file (its try/catch ate
# the throw), which phase 146 scores as S8 "import table unreachable" — a wrong signal on
# every healthy signed binary. foreach over $null iterates zero times, so the wrapper
# bought nothing here. Caught by Test-Pe-Parser.ps1, which runs these functions for real.

function Open-ScythePeStream {
    # FileShare ReadWrite|Delete on purpose. [IO.File]::OpenRead requests FileShare.Read and
    # therefore FAILS on a file another process currently holds open for write — which is
    # precisely the live dropper this phase most wants to parse.
    param([string]$Path)
    try {
        return (New-Object System.IO.FileStream($Path,
            [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)))
    } catch { return $null }
}

function Read-ScytheRange {
    # Exactly $Count bytes from $Offset, or $null. FileStream.Read may return short on any
    # single call, so it loops until filled or EOF.
    param([System.IO.FileStream]$Stream, [long]$Offset, [int]$Count)
    if ($null -eq $Stream -or $Count -le 0 -or $Offset -lt 0 -or $Offset -ge $Stream.Length) { return $null }
    if (($Offset + $Count) -gt $Stream.Length) { $Count = [int]($Stream.Length - $Offset) }
    if ($Count -le 0) { return $null }
    $buf = New-Object byte[] $Count
    try {
        [void]$Stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        $got = 0
        while ($got -lt $Count) {
            $n = $Stream.Read($buf, $got, $Count - $got)
            if ($n -le 0) { break }
            $got += $n
        }
        if ($got -lt $Count) { return $null }
    } catch { return $null }
    return $buf
}

function Get-ScytheU16 {
    # Bounds-checked little-endian read. ToUInt16, never ToInt16 — a signed read of a high
    # field returns a negative number, every later bounds check then passes trivially, and the
    # parser reads from a nonsensical offset with no error anywhere.
    param([byte[]]$B, [long]$Off)
    if ($null -eq $B -or $Off -lt 0 -or ($Off + 2) -gt $B.Length) { return $null }
    return [long][System.BitConverter]::ToUInt16($B, [int]$Off)
}

function Get-ScytheU32 {
    # As above. Cast to [long] AT THE READ, not at the comparison: PS 5.1 promotes
    # UInt32 arithmetic inconsistently, and forcing 64-bit signed here makes every downstream
    # offset calculation behave.
    param([byte[]]$B, [long]$Off)
    if ($null -eq $B -or $Off -lt 0 -or ($Off + 4) -gt $B.Length) { return $null }
    return [long][System.BitConverter]::ToUInt32($B, [int]$Off)
}

function Read-ScytheAsciiAt {
    # NUL-terminated ASCII, length-capped. Uses [Array]::IndexOf — a native scan — rather than
    # a PowerShell character loop, which is roughly 50x slower and would by itself turn a 4 ms
    # import parse into a 200 ms one. Strips non-printables: an import or section name is
    # attacker-authored and ends up in the operator's console and the client report.
    param([byte[]]$B, [long]$Off, [int]$Max = 512)
    if ($null -eq $B -or $Off -lt 0 -or $Off -ge $B.Length) { return "" }
    $lim = [int][Math]::Min([long]$Max, ($B.Length - $Off))
    if ($lim -le 0) { return "" }
    $nul = [System.Array]::IndexOf($B, [byte]0, [int]$Off, $lim)
    $len = if ($nul -lt 0) { $lim } else { $nul - [int]$Off }
    if ($len -le 0) { return "" }
    return (([System.Text.Encoding]::ASCII.GetString($B, [int]$Off, $len)) -replace '[^\x20-\x7E]', '')
}

function Get-ScytheByteEntropy {
    # Shannon entropy (bits/byte, 0..8) over an ALREADY-READ buffer. Returns $null for an
    # empty window, because 0.0 is a real answer — a run of one byte value — and conflating it
    # with failure is what makes the loader's whole-file Get-FileEntropy unusable here.
    #
    # Deliberately NOT Get-FileEntropy: that one is path-based, always reads from offset 0,
    # opens with FileShare.Read, and counts into a hashtable. An [int[]]256 indexed by the byte
    # value is the same algorithm several times faster, and this phase runs it a few hundred
    # times. Phase 52 depends on the loader's version; leave it alone.
    param([byte[]]$Bytes, [int]$Offset = 0, [int]$Count = -1)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $null }
    if ($Count -lt 0) { $Count = $Bytes.Length - $Offset }
    if ($Offset -lt 0 -or $Count -le 0 -or ($Offset + $Count) -gt $Bytes.Length) { return $null }
    $freq = New-Object int[] 256
    $end  = $Offset + $Count
    for ($i = $Offset; $i -lt $end; $i++) { $freq[$Bytes[$i]]++ }
    $bits = 0.0
    $total = [double]$Count
    for ($v = 0; $v -lt 256; $v++) {
        $c = $freq[$v]
        if ($c -eq 0) { continue }
        $p = $c / $total
        $bits -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($bits, 4)
}

function ConvertTo-ScytheFileOffset {
    # File offset for a relative virtual address, or $null when the RVA maps to no byte in the
    # file. Mirrors lib/Scythe.Formats/Pe RvaMapper.
    #
    # The containment test is against SizeOfRawData, NOT VirtualSize, and that is the whole
    # point: an RVA inside VirtualSize but past SizeOfRawData is virtual-only and has no file
    # byte. Mapping it anyway reads whatever happens to follow that section on disk, which is
    # how a hand-crafted PE gets a static parser to report attacker-chosen bytes as imports.
    param([long]$Rva, $Sections, [long]$SizeOfHeaders, [long]$FileLength)
    if ($Rva -lt 0) { return $null }
    if ($Rva -lt $SizeOfHeaders -and $Rva -lt $FileLength) { return $Rva }
    foreach ($s in $Sections) {
        $delta = $Rva - [long]$s.VirtualAddress
        if ($delta -lt 0 -or $delta -ge [long]$s.SizeOfRawData) { continue }
        $off = [long]$s.PointerToRawData + $delta
        if ($off -ge 0 -and $off -lt $FileLength) { return $off }
        return $null
    }
    return $null
}

function Read-ScythePeImage {
    # Header, section table and overlay for one file. Returns $null when the file is not a PE
    # at all, otherwise a result object whose Partial flag says whether anything was truncated.
    # Never throws. Import parsing is a separate, more expensive pass (Read-ScythePeImports).
    param([string]$Path, [long]$FileLength)
    $peStream = $null
    try {
        $peStream = Open-ScythePeStream $Path
        if ($null -eq $peStream) { return $null }

        $hdr = Read-ScytheRange $peStream 0 ([int][Math]::Min($FileLength, 4096L))
        if ($null -eq $hdr -or $hdr.Length -lt 64) { return $null }
        if ((Get-ScytheU16 $hdr 0) -ne 0x5A4D) { return $null }          # no MZ: not a PE

        $lfanew = Get-ScytheU32 $hdr 0x3C
        # e_lfanew is a 32-bit attacker value. A real image keeps it under 0x400; refuse the
        # absurd rather than growing the read unboundedly to reach it.
        if ($null -eq $lfanew -or $lfanew -lt 4 -or $lfanew -gt 0x10000000) { return $null }
        if (($lfanew + 4) -gt $FileLength) { return $null }
        if (($lfanew + 512) -gt $hdr.Length) {
            $bigger = Read-ScytheRange $peStream 0 ([int][Math]::Min($FileLength, 65536L))
            if ($null -ne $bigger) { $hdr = $bigger }
        }
        if ((Get-ScytheU32 $hdr $lfanew) -ne 0x00004550) { return $null }  # no PE\0\0

        $coff = $lfanew + 4
        if (($coff + 20) -gt $hdr.Length) { return $null }
        $nSections = Get-ScytheU16 $hdr ($coff + 2)
        $timeStamp = Get-ScytheU32 $hdr ($coff + 4)
        $sizeOfOpt = Get-ScytheU16 $hdr ($coff + 16)
        if ($null -eq $nSections -or $null -eq $sizeOfOpt) { return $null }

        $opt = $coff + 20
        $magic = Get-ScytheU16 $hdr $opt
        if ($magic -ne 0x10B -and $magic -ne 0x20B) { return $null }       # not PE32 / PE32+
        $isPlus = ($magic -eq 0x20B)
        $minOpt = if ($isPlus) { 112 } else { 96 }
        if ($sizeOfOpt -lt $minOpt) { return $null }

        $entryRva     = Get-ScytheU32 $hdr ($opt + 16)
        $sizeOfHdrs   = Get-ScytheU32 $hdr ($opt + 60)
        $ddBase       = $opt + $(if ($isPlus) { 112 } else { 96 })
        $numRva       = Get-ScytheU32 $hdr ($opt + $(if ($isPlus) { 108 } else { 92 }))
        if ($null -eq $numRva) { $numRva = 0 }
        # Clamp to 16 AND to the room SizeOfOptionalHeader actually leaves: a malformed image
        # declaring four billion directories would otherwise drive a four-billion-iteration loop.
        $roomForDd = [long][Math]::Floor((($opt + $sizeOfOpt) - $ddBase) / 8)
        if ($numRva -gt 16) { $numRva = 16 }
        if ($numRva -gt $roomForDd) { $numRva = [long][Math]::Max(0, $roomForDd) }

        $importRva = 0; $certOff = 0; $certSize = 0; $hasClr = $false
        if ($numRva -ge 2) { $importRva = Get-ScytheU32 $hdr ($ddBase + 8) }
        if ($numRva -ge 5) {
            # DataDirectory[4] (Certificate) is the one entry in the whole format whose first
            # field is a raw FILE OFFSET, not an RVA. Getting this wrong is what makes every
            # signed binary on the machine look like it carries an overlay.
            $certOff  = Get-ScytheU32 $hdr ($ddBase + 32)
            $certSize = Get-ScytheU32 $hdr ($ddBase + 36)
        }
        if ($numRva -ge 15) {
            $clrRva = Get-ScytheU32 $hdr ($ddBase + 112)
            $hasClr = ($null -ne $clrRva -and $clrRva -gt 0)
        }
        if ($null -eq $importRva) { $importRva = 0 }
        if ($null -eq $certOff)   { $certOff = 0 }
        if ($null -eq $certSize)  { $certSize = 0 }

        # The section table sits at opt + SizeOfOptionalHeader, NOT at a fixed offset. The
        # loader uses the declared value, and malware sets it non-standard precisely to
        # desynchronise naive parsers from the loader.
        $secBase = $opt + $sizeOfOpt
        $maxSec  = 96
        if ($PE_SCORE -and $PE_SCORE.MaxSections) { $maxSec = [int]$PE_SCORE.MaxSections }
        $partial = $false
        if ($nSections -gt $maxSec) { $partial = $true }
        $secCount = [int][Math]::Min([long]$nSections, [long]$maxSec)
        $sections = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $secCount; $i++) {
            $e = $secBase + ($i * 40)
            if (($e + 40) -gt $hdr.Length) { $partial = $true; break }
            $nameBytes = New-Object byte[] 8
            [System.Array]::Copy($hdr, [int]$e, $nameBytes, 0, 8)
            $nul  = [System.Array]::IndexOf($nameBytes, [byte]0)
            $nlen = if ($nul -lt 0) { 8 } else { $nul }
            $sname = if ($nlen -le 0) { "" } else {
                ([System.Text.Encoding]::ASCII.GetString($nameBytes, 0, $nlen)) -replace '[^\x20-\x7E]', ''
            }
            $sections.Add([pscustomobject]@{
                Name             = $sname
                VirtualSize      = [long](Get-ScytheU32 $hdr ($e + 8))
                VirtualAddress   = [long](Get-ScytheU32 $hdr ($e + 12))
                SizeOfRawData    = [long](Get-ScytheU32 $hdr ($e + 16))
                PointerToRawData = [long](Get-ScytheU32 $hdr ($e + 20))
                Characteristics  = [long](Get-ScytheU32 $hdr ($e + 36))
            })
        }

        # Overlay: bytes past the end of everything the loader maps. Each candidate end is
        # clamped to the real file length first, or a section that lies about SizeOfRawData
        # produces a NEGATIVE overlay and a nonsense percentage in a client report.
        $mappedEnd = [Math]::Min([long]$sizeOfHdrs, $FileLength)
        foreach ($s in $sections) {
            $end = [Math]::Min(($s.PointerToRawData + $s.SizeOfRawData), $FileLength)
            if ($end -gt $mappedEnd) { $mappedEnd = $end }
        }
        $overlay = $FileLength - $mappedEnd
        # Subtract the Authenticode certificate table. Without this every signed binary on the
        # machine reports an overlay and the signal is pure noise.
        if ($certSize -gt 0 -and $certOff -ge $mappedEnd) { $overlay = $overlay - $certSize }
        if ($overlay -lt 0) { $overlay = 0 }

        return [pscustomobject]@{
            Path           = $Path
            Length         = $FileLength
            IsPlus         = $isPlus
            TimeDateStamp  = [long]$timeStamp
            EntryRva       = [long]$entryRva
            SizeOfHeaders  = [long]$sizeOfHdrs
            Sections       = $sections
            ImportRva      = [long]$importRva
            HasClr         = $hasClr
            CertSize       = [long]$certSize
            Overlay        = [long]$overlay
            Partial        = $partial
        }
    } catch {
        return $null
    } finally {
        if ($peStream) { try { $peStream.Dispose() } catch { } }
    }
}

function Read-ScythePeImports {
    # Import DLL count, function count and the set of imported function NAMES. Returns $null
    # when the directory cannot be reached. Reads the containing section ONCE and walks it in
    # memory — per-thunk seeks would be hundreds of syscalls per file.
    #
    # Every loop here is bounded twice: by a count cap and by a wall-clock deadline. An
    # unterminated descriptor or thunk array in a crafted file is otherwise an unbounded loop,
    # i.e. a denial of service against the scan itself.
    param($Image, [int]$DeadlineMs = 250, [switch]$NamesOnly)
    if ($null -eq $Image -or $Image.ImportRva -le 0) { return $null }
    $peStream = $null
    try {
        $impOff = ConvertTo-ScytheFileOffset $Image.ImportRva $Image.Sections $Image.SizeOfHeaders $Image.Length
        if ($null -eq $impOff) { return $null }
        # $winSection, not $host — $Host is a PowerShell automatic variable and assigning to it
        # is a runtime error (CLAUDE.md: never give a local the letters of a broader-scope name).
        $winSection = $null
        foreach ($s in $Image.Sections) {
            if ($impOff -ge $s.PointerToRawData -and $impOff -lt ($s.PointerToRawData + $s.SizeOfRawData)) {
                $winSection = $s; break
            }
        }
        if ($null -eq $winSection) { return $null }

        $peStream = Open-ScythePeStream $Image.Path
        if ($null -eq $peStream) { return $null }
        $winStart = [long]$winSection.PointerToRawData
        $winLen   = [int][Math]::Min([long]$winSection.SizeOfRawData, 524288L)
        $win      = Read-ScytheRange $peStream $winStart $winLen
        if ($null -eq $win) { return $null }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $dllCount = 0; $funcCount = 0; $truncated = $false
        $names = New-Object System.Collections.Generic.HashSet[string]
        $step  = if ($Image.IsPlus) { 8 } else { 4 }

        for ($di = 0; $di -lt 256; $di++) {
            if ($sw.Elapsed.TotalMilliseconds -gt $DeadlineMs) { $truncated = $true; break }
            $d = ($impOff - $winStart) + ($di * 20)
            if ($d -lt 0 -or ($d + 20) -gt $win.Length) { $truncated = $true; break }
            $oft  = Get-ScytheU32 $win $d
            $ts   = Get-ScytheU32 $win ($d + 4)
            $fc   = Get-ScytheU32 $win ($d + 8)
            $nRva = Get-ScytheU32 $win ($d + 12)
            $ft   = Get-ScytheU32 $win ($d + 16)
            if ($null -eq $oft) { $truncated = $true; break }
            if ($oft -eq 0 -and $ts -eq 0 -and $fc -eq 0 -and $nRva -eq 0 -and $ft -eq 0) { break }
            $dllCount++
            # OriginalFirstThunk when present, else FirstThunk — the loader's own fallback for
            # bound imports. Skipping it loses the imports of every bound system binary.
            $thunkRva = if ($oft -gt 0) { $oft } else { $ft }
            if ($thunkRva -le 0) { continue }
            $thunkOff = ConvertTo-ScytheFileOffset $thunkRva $Image.Sections $Image.SizeOfHeaders $Image.Length
            if ($null -eq $thunkOff) { continue }
            for ($ti = 0; $ti -lt 4096; $ti++) {
                if ($funcCount -ge 4096) { $truncated = $true; break }
                if (($ti % 256) -eq 0 -and $sw.Elapsed.TotalMilliseconds -gt $DeadlineMs) { $truncated = $true; break }
                $t = ($thunkOff - $winStart) + ($ti * $step)
                if ($t -lt 0 -or ($t + $step) -gt $win.Length) { $truncated = $true; break }
                $lo = Get-ScytheU32 $win $t
                $hi = if ($Image.IsPlus) { Get-ScytheU32 $win ($t + 4) } else { 0 }
                if ($null -eq $lo) { $truncated = $true; break }
                if ($lo -eq 0 -and $hi -eq 0) { break }
                $funcCount++
                # PE32+ thunks are read as TWO UInt32s rather than one UInt64: the ordinal flag
                # is bit 63, and [long] cannot hold 0x8000000000000000 without going negative.
                $byOrdinal = if ($Image.IsPlus) { (($hi -band 0x80000000) -ne 0) } else { (($lo -band 0x80000000) -ne 0) }
                if ($byOrdinal) { continue }
                if (-not $NamesOnly) { continue }
                $nameRva = if ($Image.IsPlus) { $lo } else { ($lo -band 0x7FFFFFFF) }
                $nameOff = ConvertTo-ScytheFileOffset ($nameRva + 2) $Image.Sections $Image.SizeOfHeaders $Image.Length
                if ($null -eq $nameOff) { continue }
                $rel = $nameOff - $winStart
                if ($rel -lt 0 -or $rel -ge $win.Length) { continue }
                $fn = Read-ScytheAsciiAt $win $rel 512
                if ($fn) { [void]$names.Add($fn) }
            }
            if ($funcCount -ge 4096) { $truncated = $true; break }
        }
        $sw.Stop()
        return [pscustomobject]@{
            DllCount  = $dllCount
            FuncCount = $funcCount
            Names     = $names
            Truncated = $truncated
        }
    } catch {
        return $null
    } finally {
        if ($peStream) { try { $peStream.Dispose() } catch { } }
    }
}

# ── Helpers for phases 148-152 (task F2) ─────────────────────────────────────
# Defined unconditionally, before the $PhasePlan gate, like the rest of the band.

$global:SCYTHE_EVT_CACHE = $null

function Get-ScytheEvents {
    # A memoised, SERVER-SIDE-FILTERED event pull.
    #
    # Every other event query in this engine filters time on the CLIENT: it asks for N
    # records and then drops the out-of-window ones with Test-InScope. On a domain
    # workstation with a large Security log that materialises hundreds of thousands of
    # records in the PowerShell pipeline first, and phases 148-152 need six separate
    # id-sets out of that one log. StartTime INSIDE the FilterHashtable compiles to an
    # XPath query the Event Log service evaluates itself, so the records never cross the
    # process boundary. Memoised per (log, id-set, cap) because the engine is audit-only
    # under -Auto and the log does not move underneath a run in any way that matters.
    #
    # Through Get-WinEventSafe, never raw: Get-WinEvent -FilterHashtable throws a
    # TERMINATING error on an unregistered log that -EA SilentlyContinue does not suppress,
    # and on a workstation with no Security-log access that is the normal case, not an
    # exceptional one.
    param([string]$LogName, [int[]]$Id, [int]$MaxEvents = 1500)
    if ($null -eq $global:SCYTHE_EVT_CACHE) { $global:SCYTHE_EVT_CACHE = @{} }
    $key = "$LogName|" + ((@($Id) | Sort-Object) -join ',') + "|$MaxEvents"
    if ($global:SCYTHE_EVT_CACHE.ContainsKey($key)) { return ,$global:SCYTHE_EVT_CACHE[$key] }
    $filter = @{ LogName = $LogName; Id = @($Id) }
    if ($null -ne $global:TIME_LIMIT -and $global:TIME_LIMIT -ne [datetime]::MinValue) {
        $filter['StartTime'] = $global:TIME_LIMIT
    }
    $evts = @(Get-WinEventSafe -Filter $filter -MaxEvents $MaxEvents)
    $global:SCYTHE_EVT_CACHE[$key] = $evts
    return ,$evts
}

function Get-ScytheEvtField {
    # One EventData field, read POSITIONALLY from .Properties with a named fallback.
    #
    # [xml]$e.ToXml() per record is the readable way and it is roughly two orders of
    # magnitude more expensive — on a 3000-record pull it is the whole cost of the phase.
    # .Properties is the same data already materialised. The catch is that the positional
    # layout is a property of the PROVIDER MANIFEST and has changed between Windows
    # versions before, and a silently-wrong index is far worse here than a slow phase: it
    # would put an account name in the source-address field of a client report. So the
    # positional read is validated, and a value that does not look like the field it claims
    # to be falls back to the named lookup FOR THAT RECORD ONLY. Fast path stays fast,
    # wrong path cannot stay wrong.
    param($Event, [int]$Index, [string]$Name, [string]$Validate = '')
    $val = $null
    try {
        $props = $Event.Properties
        if ($null -ne $props -and $Index -ge 0 -and $Index -lt $props.Count) {
            $val = "$($props[$Index].Value)"
        }
    } catch { $val = $null }
    if ($null -ne $val -and ($Validate -eq '' -or $val -match $Validate)) { return "$val" }
    try {
        $xml  = [xml]$Event.ToXml()
        $node = @($xml.Event.EventData.Data | Where-Object { "$($_.Name)" -eq $Name })
        if ($node.Count -gt 0) { return "$($node[0].'#text')" }
    } catch { }
    return "$val"
}

function Test-ScytheDomainJoined {
    # Phase 150 must degrade to silence on a workgroup machine, and most of the MSP fleet
    # this tool runs on IS workgroup. Win32_ComputerSystem.PartOfDomain is the cheap
    # authoritative answer and it is already in the snapshot on most runs.
    try {
        $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($null -eq $cs) { return $false }
        return [bool]$cs.PartOfDomain
    } catch { return $false }
}

function ConvertTo-ScytheSeverity {
    # Rule objects in data/detection_signatures.json carry a severity as a STRING. The band
    # repeats this switch in a dozen places; one function is one place to be wrong.
    param([string]$Name)
    switch ("$Name".ToUpper()) {
        "CRITICAL" { return $SEV_CRITICAL }
        "HIGH"     { return $SEV_HIGH }
        "POSSIBLE" { return $SEV_POSSIBLE }
        default    { return $SEV_INFO }
    }
}

function Invoke-ScytheConsoleTool {
    # stdout of a built-in console tool, as a string array, with a hard timeout.
    #
    # klist and cmdkey answer questions no registry read can (what tickets are in THIS
    # logon session; what credentials are in the user's vault), and both are read-only
    # Microsoft-signed binaries already on every Windows install. They are also the kind
    # of call that hangs forever against an unreachable KDC, so the process is started
    # detached and killed on the deadline rather than waited on. Returns @() on anything
    # unexpected — a missing tool is a normal answer, not an error.
    param([string]$File, [string]$Arguments = '', [int]$TimeoutMs = 8000)
    $psi = $null; $proc = $null
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $File
        $psi.Arguments              = $Arguments
        $psi.UseShellExecute        = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.CreateNoWindow         = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -eq $proc) { return @() }
        # ReadToEndAsync, not BeginOutputReadLine and not a blocking ReadToEnd: .NET keeps
        # draining the pipe (so a chatty tool cannot deadlock on a full buffer) and the text
        # is still there after the wait (audit H2's lesson, applied to a child we start).
        $stdout = $proc.StandardOutput.ReadToEndAsync()
        [void]$proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch { }
            return @()
        }
        $text = "$($stdout.Result)"
        if ([string]::IsNullOrWhiteSpace($text)) { return @() }
        return @($text -split "`r?`n")
    } catch {
        return @()
    } finally {
        if ($null -ne $proc) { try { $proc.Dispose() } catch { } }
    }
}

if ($PhasePlan.Hunt) {
    trap { Write-RecoveredError $_; continue }   # localize faults: resume at next phase, not end-of-group

    # ── PHASE 146: PE STRUCTURAL ANALYSIS ─────────────────────────────────────
    # Every other file phase asks two questions — does the path match, and is it
    # Authenticode-signed — and neither survives contact with a packed or novel sample.
    # This one parses the binary.
    #
    # THE SEVERITY DISCIPLINE IS THE WHOLE DESIGN. Packing is not malicious: half of
    # commercial software is packed, every installer looks like a dropper, and .NET
    # obfuscators are a legitimate product category. So structural signals are scored, not
    # reported. A lone high-entropy section scores 2 against a reporting floor of 7 — it
    # cannot produce a finding at all, let alone a HIGH one. HIGH additionally requires
    # independent CONTEXT (unsigned, transient path, recent) and three distinct structural
    # signals, because a packed file trips entropy, packer name, zero-raw and W+X as one
    # fact wearing four hats. A valid signature from a trusted signer caps the result at INFO.
    #
    # Cost is controlled by tiering, not by cutting checks: everything cheap runs on every
    # candidate, entropy and import names run only on files that already scored something,
    # and Authenticode — the most expensive operation in the engine — runs last and only on
    # files with a real structural score, under the shared SIG_AUDIT budget.
    Show-PhaseHeader "PHASE 146" "PE STRUCTURE, PACKING AND IMPORT-TABLE SHAPE" "MALWARE STRUCTURE"
    Out-Typewriter "PARSING EXECUTABLES INSTEAD OF PATTERN-MATCHING THEIR NAMES..." "HUNT"

    $peMinBytes  = 1024; $peMaxBytes = 104857600; $peMaxFiles = 400
    $peDeadline  = 250;  $peWinBytes = 8192;      $peMaxEntSec = 4
    if ($PE_SCORE) {
        if ($PE_SCORE.MinFileBytes)       { $peMinBytes  = [long]$PE_SCORE.MinFileBytes }
        if ($PE_SCORE.MaxFileBytes)       { $peMaxBytes  = [long]$PE_SCORE.MaxFileBytes }
        if ($PE_SCORE.MaxFilesParsed)     { $peMaxFiles  = [int]$PE_SCORE.MaxFilesParsed }
        if ($PE_SCORE.ParseDeadlineMs)    { $peDeadline  = [int]$PE_SCORE.ParseDeadlineMs }
        if ($PE_SCORE.EntropyWindowBytes) { $peWinBytes  = [int]$PE_SCORE.EntropyWindowBytes }
        if ($PE_SCORE.MaxEntropySections) { $peMaxEntSec = [int]$PE_SCORE.MaxEntropySections }
    }

    # Two walks, each with its own budget, so a browser-cache-heavy AppData cannot starve the
    # roots where an unsigned PE is anomalous by location alone. Assigned then iterated —
    # never piped: Get-ScanFiles returns ,$arr and a pipe delivers the whole array as ONE item.
    $peHotRoots = @(@($PE_SCAN_ROOTS_HOT) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    $peAppRoots = @(@($PE_SCAN_ROOTS_APP) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    $peFound = @()
    if ($peHotRoots.Count -gt 0) { $peFound += @(Get-ScanFiles -Path $peHotRoots -MaxFiles 6000 -DeadlineSecs 12) }
    if ($peAppRoots.Count -gt 0) { $peFound += @(Get-ScanFiles -Path $peAppRoots -MaxFiles 6000 -DeadlineSecs 12) }

    $peCandidates = New-Object System.Collections.Generic.List[object]
    foreach ($f in $peFound) {
        $flen = [long]$f.Length
        if ($flen -lt $peMinBytes -or $flen -gt $peMaxBytes) { continue }
        $fpath = "$($f.FullName)"
        if ($fpath -match $PE_PACKER_BENIGN_RE) { continue }
        $fext = "$($f.Extension)".ToLower()
        $isTransient = ($fpath -match $PE_TRANSIENT_RE)
        if ($PE_EXTENSIONS -notcontains $fext) {
            # A staged payload with a disguised name lives in the hot roots. Two bytes of
            # evidence is cheap; anything else with an unknown extension is skipped.
            if (-not $isTransient) { continue }
            if ($PE_PROBE_EXTENSIONS -notcontains $fext) { continue }
            $probeStream = Open-ScythePeStream $fpath
            if ($null -eq $probeStream) { continue }
            $probe = Read-ScytheRange $probeStream 0 2
            try { $probeStream.Dispose() } catch { }
            if ($null -eq $probe) { continue }
            if ((Get-ScytheU16 $probe 0) -ne 0x5A4D) { continue }
        }
        $peCandidates.Add([pscustomobject]@{
            Path = $fpath; Name = "$($f.Name)"; Length = $flen
            Written = $f.LastWriteTime; Transient = $isTransient
        })
    }

    # Prioritise before capping. A hard cap in directory order silently drops the interesting
    # files on a machine with a large AppData; transient-first then newest-first does not.
    $peOrdered = @(@($peCandidates) | Sort-Object -Property @{Expression = { -not $_.Transient }}, @{Expression = { $_.Written }; Descending = $true})
    $peTargets = @($peOrdered | Select-Object -First $peMaxFiles)
    $peDropped = $peOrdered.Count - $peTargets.Count

    if ($peTargets.Count -eq 0) {
        Out-Typewriter "  -> NO PE FILES FOUND IN THE SCANNED ROOTS." "GOOD"
    } else {
        Out-Typewriter "  -> PARSING $($peTargets.Count) PE FILE(S)..." "INFO"

        # ── Tier 1: header, sections, overlay, import COUNTS. Every candidate. ──
        $peParsed = New-Object System.Collections.Generic.List[object]
        foreach ($cand in $peTargets) {
            $img = Read-ScythePeImage -Path $cand.Path -FileLength $cand.Length
            if ($null -eq $img) { continue }

            $sig = New-Object System.Collections.Generic.List[string]
            $sc = 0
            foreach ($s in $img.Sections) {
                if (Test-ScytheNameRule -Name $s.Name -Rules $PE_PACKER_SECTIONS) {
                    if (-not $sig.Contains('S3')) { $sig.Add('S3'); $sc += 2 }
                }
                $zeroRawMin = 4096
                if ($PE_SCORE -and $PE_SCORE.ZeroRawMinVirtual) { $zeroRawMin = [long]$PE_SCORE.ZeroRawMinVirtual }
                if ($s.SizeOfRawData -eq 0 -and $s.VirtualSize -ge $zeroRawMin) {
                    if (-not $sig.Contains('S4')) { $sig.Add('S4'); $sc += 2 }
                }
                if ((($s.Characteristics -band 0x20000000) -ne 0) -and (($s.Characteristics -band 0x80000000) -ne 0)) {
                    if (-not $sig.Contains('S5')) { $sig.Add('S5'); $sc += 2 }
                }
            }
            # Entry point outside every section, or inside a writable one. Strongly abnormal
            # for a compiler-produced image and free to compute.
            $epSection = $null
            foreach ($s in $img.Sections) {
                if ($img.EntryRva -ge $s.VirtualAddress -and $img.EntryRva -lt ($s.VirtualAddress + [Math]::Max($s.VirtualSize, $s.SizeOfRawData))) {
                    $epSection = $s; break
                }
            }
            if ($img.EntryRva -gt 0) {
                if ($null -eq $epSection) { $sig.Add('S6'); $sc += 3 }
                elseif (($epSection.Characteristics -band 0x80000000) -ne 0) { $sig.Add('S6'); $sc += 3 }
            }
            $imports = Read-ScythePeImports -Image $img -DeadlineMs $peDeadline
            $lowImportMax = 5
            if ($PE_SCORE -and $PE_SCORE.LowImportMax) { $lowImportMax = [int]$PE_SCORE.LowImportMax }
            if ($null -eq $imports) {
                if ($img.ImportRva -gt 0) { $sig.Add('S8'); $sc += 2 }
            } elseif ((-not $img.HasClr) -and (-not $imports.Truncated) -and $imports.FuncCount -lt $lowImportMax) {
                # The CLR gate is mandatory, not optional: every .NET assembly imports exactly
                # one function (_CorExeMain from mscoree.dll), so without it this fires on
                # hundreds of healthy files.
                $sig.Add('S7'); $sc += 3
            }
            $ovMinBytes = 1048576; $ovMinRatio = 0.25
            if ($PE_SCORE) {
                if ($PE_SCORE.OverlayMinBytes) { $ovMinBytes = [long]$PE_SCORE.OverlayMinBytes }
                if ($PE_SCORE.OverlayMinRatio) { $ovMinRatio = [double]$PE_SCORE.OverlayMinRatio }
            }
            if ($img.Overlay -ge $ovMinBytes -and $img.Length -gt 0 -and (($img.Overlay / [double]$img.Length) -ge $ovMinRatio)) {
                $sig.Add('S10'); $sc += 1
            }
            if ($img.TimeDateStamp -eq 0) { $sig.Add('S11'); $sc += 1 }

            $peParsed.Add([pscustomobject]@{
                Cand = $cand; Image = $img; Imports = $imports
                Signals = $sig; S = $sc; C = 0; CSig = (New-Object System.Collections.Generic.List[string])
                Verdict = $null
            })
        }

        # ── Tier 2: entropy and import NAMES, only where Tier 1 scored or the path is hot. ──
        foreach ($p in $peParsed) {
            if ($p.S -eq 0 -and -not $p.Cand.Transient) { continue }
            $entStream = Open-ScythePeStream $p.Cand.Path
            if ($null -ne $entStream) {
                $entDone = 0
                foreach ($s in $p.Image.Sections) {
                    if ($entDone -ge $peMaxEntSec) { break }
                    if ($s.SizeOfRawData -lt 4096) { continue }
                    if ("$($s.Name)" -match '(?i)^\.rsrc$') { continue }   # PNGs and manifests: high by nature
                    $isExec = (($s.Characteristics -band 0x20000000) -ne 0)
                    $entDone++
                    # Two windows, not one: a packer stub sits at the section start with the
                    # payload after it, so a single leading window is the one arrangement that
                    # can be fooled.
                    $best = $null
                    foreach ($frac in @(0.0, 0.5)) {
                        $at = $s.PointerToRawData + [long]([Math]::Floor($s.SizeOfRawData * $frac))
                        $buf = Read-ScytheRange $entStream $at ([int][Math]::Min([long]$peWinBytes, $s.SizeOfRawData))
                        if ($null -eq $buf) { continue }
                        $e = Get-ScytheByteEntropy -Bytes $buf
                        if ($null -eq $e) { continue }
                        if ($null -eq $best -or $e -gt $best) { $best = $e }
                    }
                    if ($null -eq $best) { continue }
                    $thExec = 7.2; $thData = 7.5
                    if ($PE_SCORE) {
                        if ($PE_SCORE.EntropyExec) { $thExec = [double]$PE_SCORE.EntropyExec }
                        if ($PE_SCORE.EntropyData) { $thData = [double]$PE_SCORE.EntropyData }
                    }
                    if ($isExec -and $best -ge $thExec) {
                        if (-not $p.Signals.Contains('S1')) { $p.Signals.Add('S1'); $p.S = $p.S + 2 }
                    } elseif ((-not $isExec) -and $best -ge $thData) {
                        if (-not $p.Signals.Contains('S2')) { $p.Signals.Add('S2'); $p.S = $p.S + 1 }
                    }
                }
                try { $entStream.Dispose() } catch { }
            }
            $named = Read-ScythePeImports -Image $p.Image -DeadlineMs $peDeadline -NamesOnly
            if ($null -ne $named -and $named.Names.Count -gt 0) {
                foreach ($triad in @($PE_IMPORT_TRIADS)) {
                    if ($null -eq $triad) { continue }
                    $allPresent = $true
                    foreach ($fn in @($triad.All)) { if (-not $named.Names.Contains("$fn")) { $allPresent = $false; break } }
                    if (-not $allPresent) { continue }
                    if (-not $p.Signals.Contains('S9')) { $p.Signals.Add('S9'); $p.S = $p.S + 4 }
                    $p | Add-Member -NotePropertyName TriadName -NotePropertyValue "$($triad.Name)" -Force
                    break
                }
            }
        }
        $peCap = 12
        foreach ($p in $peParsed) { if ($p.S -gt $peCap) { $p.S = $peCap } }

        # ── Tier 3: Authenticode. Last, and only where a structural signal already fired. ──
        # This is the most expensive operation in the engine — the chain build does online
        # CRL/OCSP — so it carries the shared budget. Running it on all 400 would exhaust the
        # 25s allowance after ~20 files and leave the rest unclassified.
        $peSigSw = [System.Diagnostics.Stopwatch]::StartNew()
        $peSigSeen = 0; $peSigBudgetHit = $false
        foreach ($p in @(@($peParsed) | Where-Object { $_.S -ge 2 -or $_.Cand.Transient })) {
            if ($peSigSeen -ge $global:SIG_AUDIT_MAX_FILES -or $peSigSw.Elapsed.TotalSeconds -ge $global:SIG_AUDIT_DEADLINE_S) {
                $peSigBudgetHit = $true; break
            }
            $peSigSeen++
            $p.Verdict = Get-SignatureVerdict $p.Cand.Path
        }
        $peSigSw.Stop()
        if ($peSigBudgetHit) {
            Out-Typewriter "  -> SIGNATURE BUDGET REACHED AFTER $peSigSeen FILE(S) - PARTIAL PASS." "WARN"
        }

        # ── Context scoring and the findings. ──
        $peReported = 0; $peSuppressed = 0
        $thFloor = 7; $thPossible = 12; $thPossibleC = 3; $thHigh = 17; $thHighC = 6; $thHighSn = 3
        if ($PE_SCORE) {
            if ($PE_SCORE.ReportFloor)        { $thFloor     = [int]$PE_SCORE.ReportFloor }
            if ($PE_SCORE.PossibleMin)        { $thPossible  = [int]$PE_SCORE.PossibleMin }
            if ($PE_SCORE.PossibleMinContext) { $thPossibleC = [int]$PE_SCORE.PossibleMinContext }
            if ($PE_SCORE.HighMin)            { $thHigh      = [int]$PE_SCORE.HighMin }
            if ($PE_SCORE.HighMinContext)     { $thHighC     = [int]$PE_SCORE.HighMinContext }
            if ($PE_SCORE.HighMinSignals)     { $thHighSn    = [int]$PE_SCORE.HighMinSignals }
        }
        foreach ($p in $peParsed) {
            $cVal = 0
            $verdict = $p.Verdict
            $signerName = ''
            $trustedValid = $false
            if ($null -ne $verdict) {
                $signerName = "$($verdict.Signer)"
                $vStatus = "$($verdict.Status)"
                if ($vStatus -eq 'Valid') {
                    if ($verdict.Trusted -or $verdict.IsMs) { $trustedValid = $true }
                } elseif ([string]::IsNullOrWhiteSpace($signerName)) {
                    $p.CSig.Add('C1'); $cVal += 3          # no signature at all
                } else {
                    $p.CSig.Add('C2'); $cVal += 6          # asserts an identity that does not verify
                }
            }
            if ($p.Cand.Transient) { $p.CSig.Add('C3'); $cVal += 3 }
            if ($null -ne $global:TIME_LIMIT -and $p.Cand.Written -gt $global:TIME_LIMIT) { $p.CSig.Add('C4'); $cVal += 2 }
            if ((Test-ScytheNameRule -Name $p.Cand.Name -Rules $PE_MASQUERADE_NAMES) -and (-not ($null -ne $verdict -and $verdict.IsMs))) {
                $p.CSig.Add('C5'); $cVal += 3
            }
            $p.C = $cVal
            $peTotal = $p.S + $p.C
            $peSn = $p.Signals.Count

            # Signed-but-invalid is a different claim from "this looks packed" — it is "this
            # file asserts an identity and the assertion fails" — so it gets its own finding
            # regardless of score. Highest-value, lowest-FP output of the phase.
            if ($p.CSig.Contains('C2')) {
                Out-Typewriter "  -> SIGNED BUT INVALID: $($p.Cand.Path)" "CRIT"
                Add-Finding -ID "PE146_BADSIG_$([Math]::Abs("$($p.Cand.Path)".ToLower().GetHashCode()))" -Phase "PHASE 146" `
                    -ThreatType "Subvert Trust Controls" -Severity $SEV_POSSIBLE `
                    -Description "'$($p.Cand.Path)' carries an Authenticode signature naming '$signerName', and that signature does NOT verify (status: $($verdict.Status)). Nothing else in this scan distinguishes 'unsigned' from 'someone tried to look signed', and the second is far more interesting: an unsigned file is merely unattested, whereas this one makes a claim about its origin that fails checking. The benign causes are real and are the first thing to rule out: a truncated or partially-downloaded file, a binary patched by an installer or a licence tool after signing, and a certificate whose chain this machine cannot build because its trust store or network path is broken - which phases 36, 37 and 39 examine, and which is itself worth knowing. Check it directly: Get-AuthenticodeSignature '$($p.Cand.Path)' | Format-List Status, StatusMessage, SignerCertificate. If the status is HashMismatch the file was modified after it was signed, and the modification is the finding (MITRE T1553.002)." `
                    -Target $p.Cand.Path -FixAction "Info" -Group "PE Structure"
                $peReported++
            }

            if ($peTotal -lt $thFloor) { continue }
            if ($trustedValid -and $peTotal -lt $thPossible) { $peSuppressed++; continue }

            $peSev = $SEV_INFO
            if ($peTotal -ge $thHigh -and $p.C -ge $thHighC -and $peSn -ge $thHighSn) { $peSev = $SEV_HIGH }
            elseif ($peTotal -ge $thPossible -and $p.C -ge $thPossibleC) { $peSev = $SEV_POSSIBLE }
            # A valid signature from a trusted signer caps the result at INFO whatever the
            # score. Half of commercial software is packed and validly signed; reporting a
            # Themida-protected signed vendor agent as anything higher is the fastest way to
            # make an operator stop reading this phase. The accepted cost is stolen-certificate
            # malware, which other phases cover.
            if ($trustedValid) { $peSev = $SEV_INFO }

            $what = @()
            if ($p.Signals.Contains('S1')) { $what += 'a high-entropy executable section' }
            if ($p.Signals.Contains('S2')) { $what += 'a high-entropy data section' }
            if ($p.Signals.Contains('S3')) { $what += 'a known packer section name' }
            if ($p.Signals.Contains('S4')) { $what += 'a section allocated with no file content' }
            if ($p.Signals.Contains('S5')) { $what += 'a writable AND executable section' }
            if ($p.Signals.Contains('S6')) { $what += 'an entry point outside any section or in a writable one' }
            if ($p.Signals.Contains('S7')) { $what += 'fewer than five imported functions in a native binary' }
            if ($p.Signals.Contains('S8')) { $what += 'an import directory that maps to no file data' }
            if ($p.Signals.Contains('S9')) { $what += "the $($p.TriadName) import set" }
            if ($p.Signals.Contains('S10')) { $what += 'a large appended overlay' }
            if ($p.Signals.Contains('S11')) { $what += 'a zeroed build timestamp' }
            $whatStr = if ($what.Count) { ($what -join '; ') } else { 'no structural anomaly' }
            $ctx = @()
            if ($p.CSig.Contains('C1')) { $ctx += 'it is unsigned' }
            if ($p.CSig.Contains('C3')) { $ctx += 'it sits in a transient user-writable directory' }
            if ($p.CSig.Contains('C4')) { $ctx += 'it was written inside the scan window' }
            if ($p.CSig.Contains('C5')) { $ctx += 'it carries the name of a Windows system binary without a Microsoft signature' }
            $ctxStr = if ($ctx.Count) { ($ctx -join ', and ') } else { 'nothing about its situation is unusual' }
            $sigNote = if ($trustedValid) { " It is validly signed by '$signerName', which caps this finding at INFO however high the structural score: packing is a legitimate product category and a signed vendor binary that is packed is not a defect." } else { "" }

            Out-Typewriter "  -> PE STRUCTURE SCORE $peTotal (S=$($p.S) C=$($p.C)): $($p.Cand.Path)" $(if ($peSev -eq $SEV_HIGH) { "CRIT" } else { "WARN" })
            Add-Finding -ID "PE146_STRUCT_$([Math]::Abs("$($p.Cand.Path)".ToLower().GetHashCode()))" -Phase "PHASE 146" `
                -ThreatType "Obfuscated Files or Information" -Severity $peSev `
                -Description "'$($p.Cand.Path)' scored $peTotal on PE structural analysis (structure $($p.S), context $($p.C), $peSn distinct structural signals). Structure: $whatStr. Context: $ctxStr.$sigNote Read this as a WEIGHTED result, not a verdict: none of these signals is malicious on its own and this phase deliberately cannot report a file for a single one - packing in particular is normal, since half of commercial software is packed, every installer resembles a dropper, and .NET obfuscators are a product category people pay for. What raises a score is the COMBINATION of an unusual structure with an unusual situation. Next steps, in order: confirm what the file claims to be with Get-AuthenticodeSignature '$($p.Cand.Path)' | Format-List Status, SignerCertificate ; find out how it got there with Get-Item '$($p.Cand.Path)' | Format-List CreationTime, LastWriteTime, Length ; and submit the hash to your threat-intelligence provider rather than judging it from structure alone (MITRE T1027.002 for the packing signals, T1055 for the injection import set)." `
                -Target $p.Cand.Path -FixAction "Info" -Group "PE Structure"
            $peReported++
        }

        # Report what was VERIFIED, not only what failed — the band's own convention (phase 155).
        Out-Typewriter "  -> $($peParsed.Count) PE FILE(S) PARSED, $peReported REPORTED, $peSuppressed SIGNED-AND-SUPPRESSED." "GOOD"
        if ($peDropped -gt 0) {
            Out-Typewriter "  -> $peDropped CANDIDATE(S) BEYOND THE $peMaxFiles-FILE CAP WERE NOT PARSED." "WARN"
            Add-Finding -ID "PE146_CAPPED" -Phase "PHASE 146" `
                -ThreatType "Coverage" -Severity $SEV_INFO `
                -Description "Phase 146 found $($peOrdered.Count) candidate PE files and parsed the first $($peTargets.Count); $peDropped were not examined. The cap exists because parsing is bounded work and an unbounded scan is a scan that never finishes. Files are prioritised before the cap is applied - transient directories first, then most-recently-written - so the ones dropped are the least likely to matter, but this is reported rather than left silent because 'not examined' must never be read as 'clean'. If this machine is under active investigation, narrow the scan window with -Hours, or raise MaxFilesParsed in the pe_score_thresholds key." `
                -Target "Phase146Coverage" -FixAction "Info" -Group "PE Structure"
        }
    }

    # ── PHASE 147: CLOUD IDENTITY AND DEVOPS CREDENTIAL EXPOSURE ──────────────
    # Coverage before this phase stopped at browser password stores, FileZilla, WinSCP
    # and PuTTY — a 2015 threat model. On a managed endpoint the crown jewels are cloud
    # tokens: one stolen .azure token cache on one technician's laptop is every client
    # tenant, and it survives a password reset, because the token IS the credential.
    #
    # Two questions, and both matter: do these secrets exist here unprotected, and has
    # anything read or copied them. Existence alone is INFO — a developer workstation
    # legitimately has every one of these files. Severity comes from plaintext secret
    # material, a weak ACL, or a COPY sitting in a staging directory.
    Show-PhaseHeader "PHASE 147" "CLOUD TOKEN CACHES, SSH KEYS AND DEVOPS CREDENTIALS" "CREDENTIAL ACCESS"
    Out-Typewriter "INVENTORYING CLOUD AND DEVOPS CREDENTIAL MATERIAL..." "HUNT"

    $credPresent = New-Object System.Collections.Generic.List[string]
    foreach ($cp in $CLOUD_CRED_PATHS) {
        if ([string]::IsNullOrWhiteSpace($cp)) { continue }
        if ($cp -match $CLOUD_CRED_BENIGN_RE) { continue }
        if (-not (Test-Path -LiteralPath $cp)) { continue }
        $credPresent.Add($cp)
    }

    if ($credPresent.Count -eq 0) {
        Out-Typewriter "  -> NO CLOUD OR DEVOPS CREDENTIAL STORES FOUND." "GOOD"
    } else {
        Out-Typewriter "  -> $($credPresent.Count) CREDENTIAL STORE(S) PRESENT ON THIS HOST." "INFO"
        $credList = (@($credPresent) | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object -Unique) -join ', '
        Add-Finding -ID "CLOUD147_INVENTORY" -Phase "PHASE 147" `
            -ThreatType "Credential Access" -Severity $SEV_INFO `
            -Description "This host holds $($credPresent.Count) cloud or DevOps credential store(s): $credList. This is INVENTORY, not a defect — a developer or technician workstation legitimately has all of these, and the finding exists so that an operator responding to a compromise on this machine knows immediately which tenants, registries and repositories to treat as exposed. If this box is confirmed compromised, the correct response is to rotate rather than to delete: revoke the Azure/Entra refresh tokens (Revoke-AzureADUserAllRefreshToken or the equivalent Graph call), rotate the AWS access keys, regenerate the SSH keys and any package-registry tokens, and force a re-login of every CLI listed. A password reset alone does NOT invalidate a stolen token cache. The checks below look for the three things that turn this inventory into a finding: plaintext secret material, a permissive ACL, and a copy staged somewhere it does not belong." `
            -Target "CloudCredentialInventory" -FixAction "Info" -Group "Credential Exposure"
    }

    # (a) Plaintext secret material. Text formats only, and never the opaque token
    #     caches — reading a TokenBroker cache or an NGC key container makes this tool
    #     the credential-theft primitive it is looking for, and can invalidate the
    #     user's live session as a side effect.
    foreach ($cp in $credPresent) {
        if (Test-ScytheNameRule -Name $cp -Rules $CLOUD_CRED_NEVER_READ) { continue }
        $leaf = Split-Path $cp -Leaf
        if (-not (Test-ScytheNameRule -Name $leaf -Rules $CLOUD_CRED_TEXT_FORMATS)) { continue }
        $hit = Test-ContentRules -FilePath $cp -Rules $CLOUD_CRED_CONTENT_RULES -MaxBytes 1048576
        if (-not $hit.Hit) { continue }
        $credSev = switch ("$($hit.Severity)") { 'CRITICAL' { $SEV_CRITICAL } 'HIGH' { $SEV_HIGH } default { $SEV_POSSIBLE } }
        Out-Typewriter "  -> PLAINTEXT SECRET MATERIAL IN: $cp ($($hit.Name))" "CRIT"
        Add-Finding -ID "CLOUD147_PLAIN_$([Math]::Abs($cp.ToLower().GetHashCode()))" -Phase "PHASE 147" `
            -ThreatType "Credential Access" -Severity $credSev `
            -Description "'$cp' contains material matching the secret format '$($hit.Name)'. The matched text is deliberately NOT reproduced here — a finding that quotes the credential turns the client report into a second copy of it. What this means: the secret is on disk in plaintext, so anything running as this user reads it without a prompt, without touching LSASS, and without tripping a credential-access detection. Read the file yourself to confirm before acting. The honest false-positive cases: a placeholder or example value, a revoked key left in a config, and — for the PrivateKeyBlock rule — an ordinary passphrase-protected SSH key, which is exactly where a private key is supposed to be and is not a finding on its own. If it is live, rotate it at the provider rather than merely deleting the file, and move the secret to the platform's own store (aws configure sso, az login, git config --global credential.helper manager, npm login --auth-type=web)." `
            -Target $cp -FixAction "Info" -Group "Credential Exposure"
    }

    # (b) World-readable secrets. READ is the right-that-matters here, not write —
    #     the attacker does not need to modify an SSH key to use it.
    foreach ($cp in $credPresent) {
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $cp -ErrorAction Stop } catch { $acl = $null }
        if ($null -eq $acl) { continue }
        $weak = @(Get-WeakAces -Acl $acl -WeakIds @('Everyone','BUILTIN\Users','Authenticated Users','NT AUTHORITY\ANONYMOUS LOGON','Guests') -RightsRegex 'Read|Modify|FullControl')
        if ($weak.Count -eq 0) { continue }
        $who = (@($weak) | ForEach-Object { "$($_.IdentityReference)" } | Sort-Object -Unique) -join ', '
        Out-Typewriter "  -> CREDENTIAL STORE READABLE BY $who : $cp" "WARN"
        Add-Finding -ID "CLOUD147_ACL_$([Math]::Abs($cp.ToLower().GetHashCode()))" -Phase "PHASE 147" `
            -ThreatType "Credential Access" -Severity $SEV_POSSIBLE `
            -Description "'$cp' grants read access to: $who. Credential material in a user profile should be readable by that user and administrators only. A broad ACE here means any other local account — including a low-privilege service account, or a second user on a shared technician machine — can take the credential without any privilege escalation at all. Benign causes are common and worth checking first: a file copied from another machine or an archive carries the source ACL, and a profile relocated between disks can inherit the destination's permissions. Inspect with: Get-Acl '$cp' | Format-List. Tighten with: icacls '$cp' /inheritance:r /grant:r <owner>:(R,W) /grant:r Administrators:(F) /grant:r SYSTEM:(F)   — replacing <owner> with the account that owns the profile, not necessarily the account running this scan — and rotate the secret, because you cannot know whether it was already read." `
            -Target $cp -FixAction "Info" -Group "Credential Exposure"
    }

    # (c) Staged for exfiltration. No cloud CLI ever writes its token cache to Downloads.
    #     This is the branch that turns "a developer box has secrets" into "someone
    #     staged the secrets for collection", so the allowlist must never cover a
    #     staging directory (see the _comment on cloud_cred_benign_paths).
    $stagingRoots = @(@($CLOUD_CRED_STAGING_DIRS) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($stagingRoots.Count -gt 0) {
        $stagedFiles = @(Get-ScanFiles -Path $stagingRoots -MaxFiles 8000 -DeadlineSecs 15)
        foreach ($sf in $stagedFiles) {
            $sfPath = "$($sf.FullName)"
            if ($sfPath -match $CLOUD_CRED_BENIGN_RE) { continue }
            if (-not (Test-ScytheNameRule -Name "$($sf.Name)" -Rules $CLOUD_CRED_STAGED_NAMES)) { continue }
            Out-Typewriter "  -> CREDENTIAL MATERIAL STAGED OUTSIDE ITS HOME: $sfPath" "CRIT"
            Add-Finding -ID "CLOUD147_STAGED_$([Math]::Abs($sfPath.ToLower().GetHashCode()))" -Phase "PHASE 147" `
                -ThreatType "Collection / Exfiltration" -Severity $SEV_HIGH `
                -Description "'$sfPath' is a file named like cloud or DevOps credential material, sitting in a staging directory rather than in the location its own tool uses. No cloud CLI writes its credential store to Temp, Downloads, Desktop, Public or ProgramData — the AWS CLI writes to .aws, the Azure CLI to .azure, git to .git-credentials. A copy here was made by something else, and collection-into-a-staging-directory immediately before archive-and-upload is the standard shape of the exfiltration step (MITRE T1074.001, T1552.001). Check who made it and when: Get-Item '$sfPath' | Format-List CreationTime, LastWriteTime, Length. The benign cases are real and worth ruling out first — a technician manually backing up a config before a rebuild, a support bundle, or an unpacked archive. If it is not explained, treat the credentials named in the file as compromised and rotate them, then preserve the file as evidence before deleting it." `
                -Target $sfPath -FixAction "Info" -Group "Credential Exposure"
        }
    }

    # (d) Access evidence. az/aws/kubectl/gcloud are legitimate administration tools, so
    #     the rules anchor on the specific token-minting subcommand rather than the
    #     binary name; the named offensive tools are matched whole-word.
    $credProcs = @(Get-ProcSnapshot)
    foreach ($pr in $credProcs) {
        $cl = "$($pr.CommandLine)"
        if ([string]::IsNullOrWhiteSpace($cl)) { continue }
        if (-not (Test-ScytheNameRule -Name $cl -Rules $CLOUD_CRED_ACCESS_TOOLS)) { continue }
        $pname = "$($pr.Name)"; $ppid = "$($pr.ProcessId)"
        Out-Typewriter "  -> TOKEN-EXTRACTION COMMAND RUNNING: $pname (PID $ppid)" "CRIT"
        Add-Finding -ID "CLOUD147_ACCESS_$($ppid)_$([Math]::Abs($pname.ToLower().GetHashCode()))" -Phase "PHASE 147" `
            -ThreatType "Credential Access" -Severity $SEV_HIGH `
            -Description "Process '$pname' (PID $ppid) is running a command line that mints or lifts a cloud access token. The command line is recorded in the scan log rather than here, because it frequently contains the token or the tenant identifier. Why this matters: a token obtained this way is bearer credential — it works from anywhere, needs no password and no second factor, and stays valid until it expires or is explicitly revoked. Why it is very often benign: this is also exactly what a technician doing legitimate cloud administration runs, and what a CI agent or an infrastructure-as-code run does on every execution. The question to answer is WHOSE session it belongs to. Check the parent: Get-CimInstance Win32_Process -Filter 'ProcessId=$ppid' | Select-Object ParentProcessId, CommandLine, CreationDate   then confirm the user was at the keyboard. An interactive administration session is normal; the same command spawned from a browser, an Office application, a script host or a scheduled task is not." `
            -Target "PID:$ppid $pname" -FixAction "Info" -Group "Credential Exposure"
    }


    # ── PHASE 148: REMOTE-EXECUTION EVIDENCE (INBOUND LATERAL) ────────────────
    # Phases 66, 88, 76 and 77 answer "what can this host reach". Nothing before this one
    # answered the question a responder actually asks first: WAS THIS HOST REACHED, and by
    # whom. That matters more here than usual — the rig this tool is validated against is a
    # lab of deliberately infected peers, so inbound lateral evidence is the thing it is
    # built to produce.
    #
    # SCOPE, and it is narrow on purpose. Two phases already own most of the classic
    # indicators and a second opinion on one artifact is the mistake phase 157 shipped:
    #   * phase 107 owns the 7045 service-install record — every PsExec-class install is
    #     already reported there, with the image path and the service name.
    #   * phase 133 owns the lateral COMMAND LINES — wmic /node process call create,
    #     schtasks /s /create, ADMIN$ paths, and the PsExec service binaries in System32.
    # What neither of them can see is the PROCESS TREE (who is the parent of the shell that
    # is running right now) and the SHARE-ACCESS record (which remote address opened
    # ADMIN$). Those are this phase.
    Show-PhaseHeader "PHASE 148" "REMOTE-EXECUTION EVIDENCE — WHO REACHED THIS HOST" "LATERAL"
    Out-Typewriter "RECONSTRUCTING THE INBOUND SIDE OF LATERAL MOVEMENT..." "HUNT"
    $latHits = 0

    # (a) The process tree. Remote execution leaves a PARENT, not a file: whatever the
    #     framework is called, wmiexec ends up with a shell under WmiPrvSE and PSRemoting
    #     ends up with one under wsmprovhost. This only sees a session that is still live,
    #     which is a real limitation and is stated in the finding — the historical answer
    #     is 4688, and phase 107 already mines that.
    try {
        $latProcs = @(Get-ProcSnapshot)
        $latById  = @{}
        foreach ($lp in $latProcs) { $latById["$($lp.ProcessId)"] = $lp }
        foreach ($lp in $latProcs) {
            $childName = "$($lp.Name)".ToLower()
            if ($LATERAL_EXEC_CHILDREN -notcontains $childName) { continue }
            $par = $null
            if ($latById.ContainsKey("$($lp.ParentProcessId)")) { $par = $latById["$($lp.ParentProcessId)"] }
            if ($null -eq $par) { continue }
            $parName = "$($par.Name)".ToLower()
            $lrule = $null
            foreach ($lr in @($LATERAL_EXEC_PARENTS)) {
                if ("$($lr.Parent)".ToLower() -eq $parName) { $lrule = $lr; break }
            }
            if ($null -eq $lrule) { continue }
            $childCmd = "$($lp.CommandLine)"
            # Datto / CentraStage / Kaseya are legitimate partner tooling and they run
            # scripts through WMI and WinRM all day (CLAUDE.md user rule 2). Without this
            # the branch is unusable on a managed fleet — which is every fleet this runs on.
            if (-not [string]::IsNullOrWhiteSpace($childCmd) -and $childCmd -match $LATERAL_EXEC_BENIGN_RE) { continue }
            $latHits++
            $childShort = if ($childCmd.Length -gt 180) { $childCmd.Substring(0,180) } else { $childCmd }
            if ([string]::IsNullOrWhiteSpace($childShort)) { $childShort = '(command line unavailable)' }
            $lsev = ConvertTo-ScytheSeverity "$($lrule.Severity)"
            Out-Typewriter "  -> REMOTE-EXECUTION PARENT: $parName -> $childName (PID $($lp.ProcessId))" "CRIT"
            Add-Finding -ID "LAT148_TREE_$($lp.ProcessId)_$([Math]::Abs("$parName$childName".ToLower().GetHashCode()))" -Phase "PHASE 148" `
                -ThreatType "Lateral Movement" -Severity $lsev `
                -Description "'$childName' (PID $($lp.ProcessId)) is running as a child of '$parName' — $($lrule.Label). Command line: $childShort. Why this is the signal: a script host under the WMI provider or the WinRM host did not start from anybody's desktop; something on the network asked this machine to run it, and that widens the incident from one endpoint to whatever else that credential can reach (MITRE T1021.006, T1047). Why it is often benign: PowerShell Remoting and WMI are also how a technician administers a fleet and how several RMM products deliver scripts, so the question to answer is WHOSE session it was. Get the source: Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4624]]' -MaxEvents 50 | Where-Object Message -match 'Logon Type:\s+3' , then match the logon time to this process. Note the limitation — this branch sees only a session that is still running; for a session that has ended, phase 107's 4688 records are the evidence." `
                -Target "PID:$($lp.ProcessId) $childName" -FixAction "Info" -Group "Lateral Movement — Inbound"
        }
    } catch { Write-Log "PHASE 148: process-tree branch failed - $($_.Exception.Message)" }

    # (b) The DCOM activation primitives, by ProgID and by CLSID. A script that
    #     instantiates MMC20.Application by GUID never mentions the friendly name, and the
    #     GUID is the half that cannot be renamed.
    try {
        foreach ($dp in @(Get-ProcSnapshot)) {
            $dcl = "$($dp.CommandLine)"
            if ([string]::IsNullOrWhiteSpace($dcl)) { continue }
            $drule = Test-ScytheTextRules -Text $dcl -Rules $LATERAL_DCOM_RULES
            if ($null -eq $drule) { continue }
            if ($dcl -match $LATERAL_EXEC_BENIGN_RE) { continue }
            $latHits++
            $dclShort = if ($dcl.Length -gt 180) { $dcl.Substring(0,180) } else { $dcl }
            Out-Typewriter "  -> DCOM LATERAL PRIMITIVE IN A COMMAND LINE: $($drule.Name)" "CRIT"
            Add-Finding -ID "LAT148_DCOM_$($dp.ProcessId)_$([Math]::Abs("$($drule.Name)".ToLower().GetHashCode()))" -Phase "PHASE 148" `
                -ThreatType "Lateral Movement" -Severity (ConvertTo-ScytheSeverity "$($drule.Severity)") `
                -Description "Process '$($dp.Name)' (PID $($dp.ProcessId)) has a command line matching '$($drule.Name)'. Command line: $dclShort. These COM objects exist so that one machine can drive an application on another, and each of them has a method that ends in a new process — which makes them a remote-execution channel that creates no service, writes no file and is invisible to every autostart check in this scan (MITRE T1021.003). Legitimate use of these ProgIDs outside a developer's own tooling is rare enough to be worth explaining. Identify the caller: Get-CimInstance Win32_Process -Filter 'ProcessId=$($dp.ProcessId)' | Select-Object ParentProcessId, CreationDate, CommandLine ." `
                -Target "PID:$($dp.ProcessId) $($dp.Name)" -FixAction "Info" -Group "Lateral Movement — Inbound"
        }
    } catch { Write-Log "PHASE 148: DCOM command-line branch failed - $($_.Exception.Message)" }

    # (c) Scheduled task at a distance. Phase 29 audits task actions for script hosts and
    #     user-writable paths and phase 104 reads Hidden and SDDL — neither has a UNC term
    #     anywhere in it, so this is free ground rather than a third opinion.
    try {
        $latTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
        foreach ($lt in $latTasks) {
            foreach ($la in @($lt.Actions)) {
                $laStr = "$($la.Execute) $($la.Arguments)".Trim()
                if ([string]::IsNullOrWhiteSpace($laStr)) { continue }
                $trule = Test-ScytheTextRules -Text $laStr -Rules $LATERAL_TASK_RULES
                if ($null -eq $trule) { continue }
                if ($laStr -match $LATERAL_EXEC_BENIGN_RE) { continue }
                $latHits++
                Out-Typewriter "  -> TASK RUNS FROM A NETWORK PATH: $($lt.TaskPath)$($lt.TaskName)" "CRIT"
                Add-Finding -ID "LAT148_TASK_$([Math]::Abs("$($lt.TaskPath)$($lt.TaskName)".ToLower().GetHashCode()))" -Phase "PHASE 148" `
                    -ThreatType "Lateral Movement" -Severity (ConvertTo-ScytheSeverity "$($trule.Severity)") `
                    -Description "Scheduled task '$($lt.TaskPath)$($lt.TaskName)' matched '$($trule.Name)'. Action: $laStr. A task whose payload lives on another machine is the at-a-distance execution shape: the binary is never on this disk for a file scan to find, and whoever controls that share controls what this machine runs, every time the trigger fires (MITRE T1053.005, T1021.002). The benign cases are real — a login script on the domain SYSVOL share, a software-deployment task pointing at a distribution point — so confirm the share before acting. Inspect the whole definition, including who registered it and when: Export-ScheduledTask -TaskName '$($lt.TaskName)' -TaskPath '$($lt.TaskPath)' . Remove it only after that, with: Unregister-ScheduledTask -TaskName '$($lt.TaskName)' -TaskPath '$($lt.TaskPath)' -Confirm:`$false ." `
                    -Target "Task: $($lt.TaskPath)$($lt.TaskName)" -FixAction "Info" -Group "Lateral Movement — Inbound"
                break
            }
        }
    } catch { Write-Log "PHASE 148: remote-task branch failed - $($_.Exception.Message)" }

    # (d) The share-access record. This is the missing half of every PsExec-class
    #     technique: phase 107 reports that a service was installed, and 5140 says which
    #     remote address opened ADMIN$ to install it. Aggregated per (source, share) —
    #     one intrusion produces hundreds of these records and an operator needs the pair.
    try {
        $shareEvts = @(Get-ScytheEvents -LogName 'Security' -Id @(5140) -MaxEvents 2000)
        if ($shareEvts.Count -eq 0) {
            # Report the state, do not stay silent. "Audit File Share" is OFF by default, so
            # an empty result is ambiguous between "nothing happened" and "nothing was
            # recorded", and an un-run check that leaves no trace reads to an operator as a
            # pass (the same reasoning that made phase 159 announce an unmounted ESP).
            Out-Typewriter "  -> NO ADMINISTRATIVE-SHARE ACCESS RECORDED IN THE WINDOW." "INFO"
            Out-Typewriter "     (Audit File Share is OFF by default — absence here is not evidence of absence.)" "INFO"
        } else {
            $shareSeen = @{}
            foreach ($se in $shareEvts) {
                $srcIp = Get-ScytheEvtField -Event $se -Index 5 -Name 'IpAddress' -Validate '^(\d{1,3}(\.\d{1,3}){3}|[0-9A-Fa-f:]{2,45}|-)$'
                $shName = Get-ScytheEvtField -Event $se -Index 7 -Name 'ShareName' -Validate '^\\\\'
                $acct   = Get-ScytheEvtField -Event $se -Index 1 -Name 'SubjectUserName'
                if ($LATERAL_ADMIN_SHARES -notcontains "$shName".ToLower()) { continue }
                if ("$srcIp" -match $LATERAL_SRC_BENIGN_RE) { continue }
                $sk = "$srcIp|$shName"
                if ($shareSeen.ContainsKey($sk)) { $shareSeen[$sk].Count++; continue }
                $shareSeen[$sk] = [pscustomobject]@{ Src = "$srcIp"; Share = "$shName"; Acct = "$acct"; Count = 1; First = $se.TimeCreated }
            }
            foreach ($sk in @($shareSeen.Keys)) {
                $sv = $shareSeen[$sk]
                $latHits++
                Out-Typewriter "  -> ADMINISTRATIVE SHARE OPENED FROM THE NETWORK: $($sv.Share) from $($sv.Src)" "CRIT"
                Add-Finding -ID "LAT148_SHARE_$([Math]::Abs($sk.ToLower().GetHashCode()))" -Phase "PHASE 148" `
                    -ThreatType "Lateral Movement" -Severity $SEV_HIGH `
                    -Description "The administrative share '$($sv.Share)' was opened from $($sv.Src) as '$($sv.Acct)' — $($sv.Count) access record(s), first seen $($sv.First). The administrative shares are not used by ordinary file sharing: they are how a remote administrator, a backup agent, and every PsExec-class remote-execution tool put a payload onto this machine before starting it (MITRE T1021.002, T1570). Pair this with phase 107's 7045 service-install records — a service installed within a minute or two of this access, from a binary that is now gone, is the classic remote-execution sequence. If $($sv.Src) is not a management host you recognise, treat the account '$($sv.Acct)' as compromised and check where else it authenticated. To see the local path each access touched: Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=5145]]' -MaxEvents 200 | Format-List TimeCreated, Message ." `
                    -Target "$($sv.Share) from $($sv.Src)" -FixAction "Info" -Group "Lateral Movement — Inbound"
            }
        }
    } catch { Write-Log "PHASE 148: share-access branch failed - $($_.Exception.Message)" }

    if ($latHits -eq 0) { Out-Typewriter "  -> [OK ] NO INBOUND REMOTE-EXECUTION EVIDENCE." "GOOD" }

    # ── PHASE 149: CREDENTIAL-DUMPING ARTIFACTS ───────────────────────────────
    # Phase 106 walks the crash-dump directories for .dmp files and looks for the named
    # dumper tools; phase 41 checks the LSA hardening values. This phase covers what those
    # two cannot see: the TECHNIQUES that need no tool at all. comsvcs.dll MiniDump is the
    # important one — it is a Microsoft-signed DLL, already on the machine, invoked through
    # rundll32, and it produces a full LSASS image with nothing to detect on disk except
    # the output file. The rules therefore anchor on the technique, never on a tool name:
    # the tool gets renamed, the technique does not.
    #
    # The search roots deliberately EXCLUDE %TEMP% and the CrashDumps directories. Phase
    # 106 already walks those, and two findings for one .dmp is the duplication that made
    # phase 157 worse than either of its halves.
    Show-PhaseHeader "PHASE 149" "CREDENTIAL-DUMPING TECHNIQUES AND STAGED HIVES" "CREDENTIAL ACCESS"
    Out-Typewriter "LOOKING FOR THE NO-TOOLS-REQUIRED WAYS TO LIFT CREDENTIALS..." "HUNT"
    $cdHits = 0
    $cdMaxFiles  = if ($null -ne $CREDDUMP_THRESH) { [int]$CREDDUMP_THRESH.MaxFiles }     else { 400 }
    $cdMinBytes  = if ($null -ne $CREDDUMP_THRESH) { [long]$CREDDUMP_THRESH.DumpMinBytes } else { 20971520 }
    $cdMaxReport = if ($null -ne $CREDDUMP_THRESH) { [int]$CREDDUMP_THRESH.MaxReported }  else { 25 }

    # (a) The techniques, in live command lines.
    try {
        foreach ($cp in @(Get-ProcSnapshot)) {
            $ccl = "$($cp.CommandLine)"
            if ([string]::IsNullOrWhiteSpace($ccl)) { continue }
            $crule = Test-ScytheTextRules -Text $ccl -Rules $CREDDUMP_CMDLINE_RULES
            if ($null -eq $crule) { continue }
            $cdHits++
            $cclShort = if ($ccl.Length -gt 180) { $ccl.Substring(0,180) } else { $ccl }
            Out-ThreatBanner "CREDENTIAL-DUMPING COMMAND" "$($crule.Name) — PID $($cp.ProcessId)"
            Add-Finding -ID "CRED149_CMD_$($cp.ProcessId)_$([Math]::Abs("$($crule.Name)".ToLower().GetHashCode()))" -Phase "PHASE 149" `
                -ThreatType "Credential Access" -Severity (ConvertTo-ScytheSeverity "$($crule.Severity)") `
                -Description "Process '$($cp.Name)' (PID $($cp.ProcessId)) is running '$($crule.Name)'. Command line: $cclShort. Every rule in this set describes a way to obtain credentials that needs nothing the machine does not already have — a signed Microsoft DLL, a built-in console tool, or a shadow copy — which is why none of them is caught by anything that looks for malware on disk (MITRE T1003). Treat this as an active compromise until proven otherwise: every credential cached on this machine, including any domain account that has logged in, must be considered exposed. Capture the evidence before you kill anything, because the output file is the proof: Get-CimInstance Win32_Process -Filter 'ProcessId=$($cp.ProcessId)' | Select-Object CommandLine, CreationDate, ParentProcessId . The benign case exists and is narrow — a support engineer collecting a dump under vendor instruction — and it is answered by asking who was at the keyboard." `
                -Target "PID:$($cp.ProcessId) $($cp.Name)" -FixAction "Info" -Group "Credential Dumping"
        }
    } catch { Write-Log "PHASE 149: command-line branch failed - $($_.Exception.Message)" }

    # (b) Staged hive copies. SAM, SECURITY, SYSTEM and ntds.dit each have exactly one
    #     legitimate home. A copy anywhere else was made deliberately, and the only reason
    #     to copy one is to read the credentials out of it somewhere else.
    try {
        $cdRoots = @($CREDDUMP_SEARCH_ROOTS | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
        if ($cdRoots.Count -gt 0) {
            # Parenthesised, never piped: Get-ScanFiles returns ,$arr and a direct pipe
            # delivers the whole array as ONE item, so the filter matches everything.
            $cdFiles = @((Get-ScanFiles -Path $cdRoots -MaxFiles $cdMaxFiles))
            $cdReported = 0
            foreach ($cf in $cdFiles) {
                if ($cdReported -ge $cdMaxReport) { break }
                $cfPath = "$($cf.FullName)"
                if ($cfPath -match $CREDDUMP_HIVE_BENIGN_RE) { continue }
                if (-not (Test-ScytheNameRule -Name "$($cf.Name)" -Rules $CREDDUMP_HIVE_NAMES)) { continue }
                $cdHits++; $cdReported++
                Out-ThreatBanner "REGISTRY HIVE COPY" $cfPath
                Add-Finding -ID "CRED149_HIVE_$([Math]::Abs($cfPath.ToLower().GetHashCode()))" -Phase "PHASE 149" `
                    -ThreatType "Credential Access" -Severity $SEV_CRITICAL `
                    -Description "'$cfPath' is named like a registry hive or the Active Directory database, and it is not in the one place Windows keeps that file. Written $($cf.LastWriteTime), $([Math]::Round($cf.Length/1MB,1)) MB. SAM plus SYSTEM is every local password hash on this machine; SECURITY adds the cached domain credentials and the LSA secrets, which include service-account passwords in plaintext; ntds.dit plus SYSTEM is the entire domain (MITRE T1003.002, T1003.003). None of these can be copied while Windows is running without going through a shadow copy or a backup API, so this file is the product of a deliberate act. One benign case exists and is worth ruling out first: %WINDIR%\repair held genuine SAM and SYSTEM backups on Windows XP and Server 2003, so a hive there with a creation date from that era on a long-upgraded machine is a fossil rather than a theft — check the dates before you escalate. Otherwise: preserve it as evidence before deleting it, then rotate local accounts, every service account, and — if ntds.dit is involved — krbtgt, twice. Establish when and by whom: Get-Item '$cfPath' | Format-List CreationTime, LastWriteTime, Length   and   (Get-Acl '$cfPath').Owner ." `
                    -Target $cfPath -FixAction "Info" -Group "Credential Dumping"
            }
            # (c) A process image is big. An application crash dump is not. A multi-hundred-
            #     megabyte .dmp in Downloads is an LSASS image or a full-memory capture, and
            #     either way it holds credentials — this is scoped to the roots phase 106
            #     does not walk, so no dump is reported twice.
            $cdReported = 0
            foreach ($cf in $cdFiles) {
                if ($cdReported -ge $cdMaxReport) { break }
                $cfPath = "$($cf.FullName)"
                if ("$($cf.Extension)".ToLower() -ne '.dmp') { continue }
                if ($cfPath -match $CREDDUMP_HIVE_BENIGN_RE) { continue }
                $cfNamesLsa = ("$($cf.Name)" -match '(?i)lsa(ss)?')
                if (-not $cfNamesLsa -and [long]$cf.Length -lt $cdMinBytes) { continue }
                $cdHits++; $cdReported++
                $cfSev = if ($cfNamesLsa) { $SEV_CRITICAL } else { $SEV_HIGH }
                Out-Typewriter "  -> PROCESS-IMAGE DUMP OUTSIDE THE CRASH DIRECTORIES: $cfPath" "CRIT"
                Add-Finding -ID "CRED149_DUMP_$([Math]::Abs($cfPath.ToLower().GetHashCode()))" -Phase "PHASE 149" `
                    -ThreatType "Credential Access" -Severity $cfSev `
                    -Description "'$cfPath' is a $([Math]::Round($cf.Length/1MB,1)) MB memory dump sitting outside every directory Windows writes crash dumps to, last written $($cf.LastWriteTime). $(if ($cfNamesLsa) { 'Its name references the process that holds every credential in use on this machine.' } else { 'A dump this large is a process image or a full-memory capture, not an application crash report.' }) A dump of the LSA process contains the plaintext or reusable form of every credential that has authenticated since boot, and it is a FILE — it can be copied off the machine and cracked at leisure, which is exactly why this technique is preferred over running a credential tool in place (MITRE T1003.001). Confirm what it is before deleting it, because it is also the evidence: Get-Item '$cfPath' | Format-List *   and check which process wrote it against phase 107's 4688 records for the same minute. If it is a dump of the LSA process, every account cached here is compromised." `
                    -Target $cfPath -FixAction "Info" -Group "Credential Dumping"
            }
        }
    } catch { Write-Log "PHASE 149: staged-file branch failed - $($_.Exception.Message)" }

    # (d) The two registry writes that make dumping EASIER, which phase 41 does not cover.
    #     WDigest UseLogonCredential and LSA RunAsPPL are phase 41's and are not repeated.
    try {
        $draKey = 'SYSTEM\CurrentControlSet\Control\Lsa'
        $dra = Get-RegVal64 -Hive LocalMachine -SubKey $draKey -Name 'DisableRestrictedAdmin'
        if ($null -ne $dra -and [int]$dra -eq 1) {
            $cdHits++
            Out-Typewriter "  -> RESTRICTED ADMIN MODE IS DISABLED FOR RDP." "WARN"
            Add-Finding -ID "CRED149_RESTRICTADMIN" -Phase "PHASE 149" `
                -ThreatType "Credential Access" -Severity $SEV_HIGH `
                -Description "HKLM\$draKey\DisableRestrictedAdmin = 1. Restricted Admin mode lets an administrator connect over RDP without sending a reusable credential to the destination; turning it off means every RDP administration session leaves that administrator's credential in the memory of the machine they connected to, where anything with local admin can lift it. This value is written by an attacker who wants exactly that, and it is also written by administrators who found that Restricted Admin broke a tool that needed delegated credentials — so establish which before changing it. Note the trade-off honestly: enabling Restricted Admin protects the credential but enables pass-the-hash TO this host, so the correct answer on a managed fleet is usually Remote Credential Guard rather than either extreme. Read the current state with: Get-ItemProperty 'HKLM:\$draKey' -Name DisableRestrictedAdmin ." `
                -Target "HKLM\$draKey\DisableRestrictedAdmin" -FixAction "Info" -Group "Credential Dumping"
        }
        # WER LocalDumps aimed at the LSA process is not a hardening setting at all — it is
        # a standing instruction to Windows to dump credentials to disk on demand. Phase
        # 157 owns the WER *debugger* values; this is a different key and a different act.
        $werBase = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
        foreach ($werSub in @("$werBase\lsass.exe", $werBase)) {
            $werPath = Get-RegVal64 -Hive LocalMachine -SubKey $werSub -Name 'DumpFolder'
            $werType = Get-RegVal64 -Hive LocalMachine -SubKey $werSub -Name 'DumpType'
            if ($null -eq $werPath -and $null -eq $werType) { continue }
            $werIsLsa = ($werSub -match '(?i)lsass\.exe$')
            if (-not $werIsLsa -and ($null -eq $werType -or [int]$werType -ne 2)) { continue }
            $cdHits++
            Out-Typewriter "  -> WER LOCAL DUMPS CONFIGURED: $werSub" $(if ($werIsLsa) { "CRIT" } else { "WARN" })
            Add-Finding -ID "CRED149_WERDUMP_$([Math]::Abs($werSub.ToLower().GetHashCode()))" -Phase "PHASE 149" `
                -ThreatType "Credential Access" -Severity $(if ($werIsLsa) { $SEV_CRITICAL } else { $SEV_POSSIBLE }) `
                -Description "HKLM\$werSub is configured for local crash dumps (DumpFolder='$werPath', DumpType='$werType'). $(if ($werIsLsa) { 'It is scoped to the LSA process specifically, and there is no support scenario in which an administrator needs Windows to write a full image of that process to disk automatically. Configured this way, the attacker does not have to touch the process at all: they crash it, or wait, and Windows writes the credentials out for them.' } else { 'DumpType 2 is a FULL memory dump of any application that crashes, which means the contents of any process that handles credentials can land in this folder and stay there.' }) (MITRE T1003.001). Check the folder for what it has already collected: Get-ChildItem '$werPath' -ErrorAction SilentlyContinue | Sort-Object Length -Descending . Remove the setting once you have confirmed no crash-collection product owns it: Remove-Item 'HKLM:\$werSub' -Recurse ." `
                -Target "HKLM\$werSub" -FixAction "Info" -Group "Credential Dumping"
        }
        # Sysinternals writes an EULA-accepted value the first time a tool runs. It survives
        # the binary being deleted, which makes it execution evidence for a tool that is no
        # longer on disk — and procdump is the one that matters here.
        $pdEula = Get-RegVal64 -Hive CurrentUser -SubKey 'Software\Sysinternals\ProcDump' -Name 'EulaAccepted'
        if ($null -ne $pdEula) {
            $cdHits++
            Out-Typewriter "  -> PROCDUMP HAS BEEN RUN BY THIS USER AT SOME POINT." "WARN"
            Add-Finding -ID "CRED149_PROCDUMP_EULA" -Phase "PHASE 149" `
                -ThreatType "Credential Access" -Severity $SEV_POSSIBLE `
                -Description "HKCU\Software\Sysinternals\ProcDump\EulaAccepted exists, which means procdump has been run under this user account on this machine. The value is written on first run and is never cleaned up, so it survives the binary being deleted — this is execution evidence for a tool that phase 106's file scan can no longer find. procdump is a legitimate Microsoft diagnostic utility and an administrator or a developer may well have run it deliberately, so this is POSSIBLE and not an accusation. What makes it matter is the pairing: procdump plus a large .dmp in a user-writable directory, or procdump on a machine whose administrator does not recognise it, is the tool-plus-output pattern of an LSA dump. Ask when it ran: (Get-Item 'HKCU:\Software\Sysinternals\ProcDump').LastWriteTime ." `
                -Target "HKCU\Software\Sysinternals\ProcDump" -FixAction "Info" -Group "Credential Dumping"
        }
    } catch { Write-Log "PHASE 149: registry branch failed - $($_.Exception.Message)" }

    if ($cdHits -eq 0) { Out-Typewriter "  -> [OK ] NO CREDENTIAL-DUMPING ARTIFACTS OR ENABLING SETTINGS." "GOOD" }

    # ── PHASE 150: KERBEROS AND NTLM ABUSE SURFACE ────────────────────────────
    # SCOPE NARROWED, for the same reason phase 159 does not mount the ESP and the 153-156
    # band sends no packets. The F2 brief asked for an AS-REP-roastable / delegation /
    # AdminSDHolder sweep of the directory. That sweep is, query for query, what BloodHound
    # issues — run against the customer's own domain controllers, from an endpoint, under
    # an MSP contract, while the customer's detection stack is watching. A tool that cannot
    # be told apart on the wire from the thing it exists to detect is a liability to the
    # provider, and the finding it produces is a domain-wide fact that does not belong in a
    # single machine's report anyway.
    #
    # What survives is everything answerable WITHOUT enumerating anybody: the tickets in
    # this logon session (klist reads a local cache), this computer's OWN directory object
    # (one object, SizeLimit 1, timeouts set), and the local relay surface. ADCS ESC8 is
    # dropped outright — it requires an HTTP request to a customer server.
    Show-PhaseHeader "PHASE 150" "KERBEROS TICKET ANOMALIES AND NTLM RELAY SURFACE" "CREDENTIAL ACCESS"
    Out-Typewriter "READING THIS SESSION'S OWN TICKETS AND THIS MACHINE'S OWN AD OBJECT..." "HUNT"
    $kbHits = 0

    # The WebClient branch is deliberately OUTSIDE the domain gate: WebDAV coercion works
    # against a workgroup machine too, and the service has no desktop use either way.
    try {
        $wcSvc = Get-Service -Name 'WebClient' -ErrorAction SilentlyContinue
        if ($null -ne $wcSvc -and ("$($wcSvc.Status)" -eq 'Running' -or "$($wcSvc.StartType)" -eq 'Automatic')) {
            $kbHits++
            Out-Typewriter "  -> WEBCLIENT (WEBDAV) SERVICE IS ACTIVE ON A WORKSTATION." "WARN"
            Add-Finding -ID "KERB150_WEBCLIENT" -Phase "PHASE 150" `
                -ThreatType "Credential Access" -Severity $SEV_HIGH `
                -Description "The WebClient service is $($wcSvc.Status) with start type $($wcSvc.StartType). WebClient is the WebDAV redirector, and on a desktop it has essentially no use — almost nothing maps a WebDAV drive any more. What it does have is a property no other service has: it turns a UNC path into an HTTP request that carries the machine account's credential, and it does so over a channel where SMB signing does not apply. That makes this host a usable relay source the moment anything can make it touch an attacker-supplied path (MITRE T1187, T1557.001). The service is also started on demand by a mapped WebDAV drive or by SharePoint's Open-in-Explorer, so confirm nothing needs it first, then: Set-Service -Name WebClient -StartupType Disabled ; Stop-Service -Name WebClient . Phase 153 covers the SMB signing half of the same exposure and is the other thing to fix." `
                -Target "Service: WebClient" -FixAction "Info" -Group "Credential Access — Relay Surface"
        }
    } catch { Write-Log "PHASE 150: WebClient check failed - $($_.Exception.Message)" }

    if (-not (Test-ScytheDomainJoined)) {
        Out-Typewriter "  -> MACHINE IS NOT DOMAIN-JOINED — KERBEROS AND AD BRANCHES SKIPPED." "INFO"
    } else {
        # (a) The tickets this logon session is holding. klist reads a local cache; it asks
        #     the directory nothing and it works with no special rights.
        try {
            $kMax = if ($null -ne $KERB_THRESH) { [int]$KERB_THRESH.MaxTicketsParsed } else { 200 }
            $kHrs = if ($null -ne $KERB_THRESH) { [int]$KERB_THRESH.MaxTicketHours }   else { 720 }
            $klistOut = @(Invoke-ScytheConsoleTool -File 'klist.exe' -Arguments 'tickets' -TimeoutMs 8000)
            $kServer = ''; $kEtype = ''; $kStart = $null; $kEnd = $null; $kSeen = 0
            foreach ($kl in $klistOut) {
                if ($kSeen -ge $kMax) { break }
                if ($kl -match '^\s*#\d+>') {
                    $kServer = ''; $kEtype = ''; $kStart = $null; $kEnd = $null
                    continue
                }
                if ($kl -match '^\s*Server:\s*(?<v>\S.*?)\s*$')                          { $kServer = "$($Matches['v'])"; continue }
                if ($kl -match '^\s*KerbTicket Encryption Type:\s*(?<v>\S.*?)\s*$')      { $kEtype  = "$($Matches['v'])"; continue }
                # TryParse's RETURN VALUE decides, never the out-parameter. On failure it
                # writes DateTime.MinValue, not $null — take that as a parsed date and the
                # lifetime arithmetic yields two thousand years and this phase reports a
                # forged ticket on every healthy domain machine whose locale klist prints
                # dates in. The out-parameter is only trusted when the call said true.
                if ($kl -match '^\s*Start Time:\s*(?<v>\S.*?)\s*\(') {
                    $kTmp = [datetime]::MinValue
                    $kStart = if ([datetime]::TryParse("$($Matches['v'])", [ref]$kTmp)) { $kTmp } else { $null }
                    continue
                }
                if ($kl -notmatch '^\s*End Time:\s*(?<v>\S.*?)\s*\(') { continue }
                $kTmp = [datetime]::MinValue
                $kEnd = if ([datetime]::TryParse("$($Matches['v'])", [ref]$kTmp)) { $kTmp } else { $null }
                # End Time is the last line of the block this phase needs, so the ticket is
                # evaluated here rather than on the next #N> marker — a truncated final
                # block then simply never fires, instead of firing on half a ticket.
                if ([string]::IsNullOrWhiteSpace($kServer)) { continue }
                $kSeen++
                # A lifetime measured in months is not a policy setting anybody has; a real
                # KDC issues ten hours. The threshold sits far above every legitimate policy
                # so that crossing it is not a judgement call.
                if ($null -ne $kStart -and $null -ne $kEnd -and $kEnd -gt $kStart) {
                    $kLifeHrs = ($kEnd - $kStart).TotalHours
                    if ($kLifeHrs -gt $kHrs) {
                        $kbHits++
                        Out-ThreatBanner "FORGED KERBEROS TICKET" "$kServer — lifetime $([Math]::Round($kLifeHrs/24,1)) days"
                        Add-Finding -ID "KERB150_LIFETIME_$([Math]::Abs("$kServer".ToLower().GetHashCode()))" -Phase "PHASE 150" `
                            -ThreatType "Credential Access" -Severity $SEV_CRITICAL `
                            -Description "This logon session holds a Kerberos ticket for '$kServer' with a lifetime of $([Math]::Round($kLifeHrs/24,1)) days ($kStart to $kEnd). A domain controller issues a ticket that lives ten hours and renews for seven days; no policy in the field stretches a single ticket past a few days, because the lifetime is what limits the damage of a stolen one. A ticket like this was not issued by a KDC — it was minted offline with the krbtgt key and injected into this session, which is what a golden or silver ticket IS (MITRE T1558.001, T1558.002). If the server field names krbtgt, the domain key itself is compromised and the remediation is the double krbtgt password reset, with the second reset only after the first has replicated. Preserve the evidence first: klist tickets   from this session, and purge only afterwards with: klist purge . Phase 88 reports the 4769 side of the same attack from the domain controller's view." `
                            -Target "Kerberos ticket: $kServer" -FixAction "Info" -Group "Credential Access — Kerberos"
                        continue
                    }
                }
                if ([string]::IsNullOrWhiteSpace($kEtype)) { continue }
                if ("$kServer" -match $KERB_ETYPE_BENIGN_RE) { continue }
                $kRule = Test-ScytheTextRules -Text $kEtype -Rules $KERB_ETYPE_RULES
                if ($null -eq $kRule) { continue }
                $kbHits++
                Out-Typewriter "  -> WEAK TICKET ENCRYPTION: $kServer ($kEtype)" "WARN"
                Add-Finding -ID "KERB150_ETYPE_$([Math]::Abs("$kServer$kEtype".ToLower().GetHashCode()))" -Phase "PHASE 150" `
                    -ThreatType "Credential Access" -Severity (ConvertTo-ScytheSeverity "$($kRule.Severity)") `
                    -Description "The service ticket for '$kServer' held by this session uses '$kEtype' — $($kRule.Name). This matters because of what the ticket contains: a service ticket is encrypted with the service account's password hash, so anyone who can request one can attack that password offline, and RC4 is the encryption type an attacker asks for precisely because it is the one the cracker handles fastest (MITRE T1558.003). A ticket in this session is not itself an attack — the machine may simply be on a domain that still permits RC4, which is common and is the benign reading. What to check: whether the account behind '$kServer' is a service account with a human-chosen password, and whether the domain still allows RC4 at all. Look at what else this session holds with: klist tickets ." `
                    -Target "Kerberos ticket: $kServer" -FixAction "Info" -Group "Credential Access — Kerberos"
            }
            if ($kSeen -eq 0) { Out-Typewriter "  -> NO CACHED KERBEROS TICKETS READABLE IN THIS SESSION." "INFO" }
            else { Out-Typewriter "  -> $kSeen CACHED TICKET(S) EXAMINED." "DATA" }
        } catch { Write-Log "PHASE 150: klist branch failed - $($_.Exception.Message)" }

        # (b) THIS COMPUTER'S OWN directory object, and nothing else. One object, one
        #     result, both timeouts set. Unconstrained delegation on a workstation means
        #     any credential that touches it can be reused anywhere; resource-based
        #     constrained delegation configured on it means somebody else was granted the
        #     right to impersonate anyone TO this machine, which is a backdoor written in
        #     the directory rather than on the disk.
        try {
            $adFilter   = '(&(objectClass=computer)(sAMAccountName=' + $env:COMPUTERNAME + '$))'
            $adSearcher = [ADSISearcher]$adFilter
            $adSearcher.SizeLimit       = 1
            $adSearcher.ClientTimeout   = [TimeSpan]::FromSeconds(10)
            $adSearcher.ServerTimeLimit = [TimeSpan]::FromSeconds(10)
            [void]$adSearcher.PropertiesToLoad.Add('useraccountcontrol')
            [void]$adSearcher.PropertiesToLoad.Add('msds-allowedtoactonbehalfofotheridentity')
            [void]$adSearcher.PropertiesToLoad.Add('distinguishedname')
            $adRes = $adSearcher.FindOne()
            if ($null -eq $adRes) {
                Out-Typewriter "  -> THIS MACHINE'S OWN AD OBJECT WAS NOT READABLE." "INFO"
            } else {
                $adDn  = "$(@($adRes.Properties['distinguishedname'])[0])"
                $adHits = 0
                $adUac = 0
                $adUacRaw = @($adRes.Properties['useraccountcontrol'])
                if ($adUacRaw.Count -gt 0) { $adUac = [int]$adUacRaw[0] }
                # 0x80000 TRUSTED_FOR_DELEGATION. On a domain controller this is normal and
                # expected; on anything else it is the single most valuable misconfiguration
                # in a Windows network, so the finding says which this machine is.
                if (($adUac -band 0x80000) -ne 0) {
                    $adIsDc = $false
                    try { $adIsDc = ([int](Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole -ge 4) } catch { $adIsDc = $false }
                    $kbHits++; $adHits++
                    Out-Typewriter "  -> THIS MACHINE IS TRUSTED FOR UNCONSTRAINED DELEGATION." $(if ($adIsDc) { "INFO" } else { "CRIT" })
                    Add-Finding -ID "KERB150_UNCONSTRAINED" -Phase "PHASE 150" `
                        -ThreatType "Credential Access" -Severity $(if ($adIsDc) { $SEV_INFO } else { $SEV_CRITICAL }) `
                        -Description "This computer's directory object ($adDn) has TRUSTED_FOR_DELEGATION set in userAccountControl ($adUac). Unconstrained delegation means that when any account authenticates to this machine over Kerberos, its ticket-granting ticket is cached in this machine's memory — so local administrator here is domain administrator anywhere a domain administrator has connected, and an attacker only has to make one connect (MITRE T1558, T1187). $(if ($adIsDc) { 'This machine is a domain controller, where the flag is expected and normal — recorded so the reader knows the check ran and what it found, not as a fault.' } else { 'This machine is NOT a domain controller, and there is almost no remaining reason for a member server or workstation to hold this flag; the legitimate cases are old and were replaced by constrained delegation years ago.' }) Confirm with the directory team before changing anything, because clearing it breaks whatever was relying on it: Get-ADComputer '$env:COMPUTERNAME' -Properties TrustedForDelegation ." `
                        -Target "AD object: $adDn" -FixAction "Info" -Group "Credential Access — Kerberos"
                }
                $adRbcd = @($adRes.Properties['msds-allowedtoactonbehalfofotheridentity'])
                if ($adRbcd.Count -gt 0 -and $null -ne $adRbcd[0]) {
                    $kbHits++; $adHits++
                    Out-Typewriter "  -> RESOURCE-BASED CONSTRAINED DELEGATION IS CONFIGURED ON THIS MACHINE." "CRIT"
                    Add-Finding -ID "KERB150_RBCD" -Phase "PHASE 150" `
                        -ThreatType "Credential Access" -Severity $SEV_HIGH `
                        -Description "This computer's directory object ($adDn) has msDS-AllowedToActOnBehalfOfOtherIdentity populated. That attribute is a list of principals allowed to impersonate ANY user to this machine — including a domain administrator, and including accounts that have never logged in here. It is a legitimate feature, and it is also the standard privilege-escalation finish: an attacker who can write one attribute on a computer object gains full access to that computer without touching it, and the change lives in the directory where no endpoint scan can see it (MITRE T1134.001). This scan cannot tell you WHICH principal was granted the right without querying the directory, which it deliberately does not do. Read it from a management host: Get-ADComputer '$env:COMPUTERNAME' -Properties PrincipalsAllowedToDelegateToAccount . If the answer is not a service you deployed on purpose, treat it as a backdoor and remove it there." `
                        -Target "AD object: $adDn" -FixAction "Info" -Group "Credential Access — Kerberos"
                }
                if ($adHits -eq 0) { Out-Typewriter "  -> THIS MACHINE'S AD OBJECT CARRIES NO DELEGATION RIGHTS." "GOOD" }
            }
        } catch { Write-Log "PHASE 150: AD self-object branch failed - $($_.Exception.Message)" }
    }

    if ($kbHits -eq 0) { Out-Typewriter "  -> [OK ] NO KERBEROS OR RELAY-SURFACE ANOMALIES." "GOOD" }

    # ── PHASE 151: OUTBOUND LATERAL CAPABILITY ────────────────────────────────
    # Phase 148 asks who reached this host. This one asks the other question, and it is the
    # one an incident-response engagement is actually scoped by: if this machine is patient
    # zero, WHERE CAN IT GO. None of these findings is a compromise on its own — a saved
    # RDP destination is not malware — and the phase says so. The value is that the answer
    # is knowable in seconds, from the registry, on day one, instead of being reconstructed
    # from interviews on day three.
    #
    # winscp.ini is deliberately NOT read here: phase 129 already reads that file for cloud
    # remotes, and one file with two findings is the phase-157 mistake. The registry
    # session store is a different artifact and is this phase's.
    Show-PhaseHeader "PHASE 151" "OUTBOUND REACH — WHERE THIS MACHINE CAN GO NEXT" "LATERAL"
    Out-Typewriter "INVENTORYING SAVED DESTINATIONS, CREDENTIALS AND REMOTING TRUST..." "HUNT"
    $obHits = 0; $obInv = New-Object System.Collections.Generic.List[string]

    # (a) TrustedHosts. This one IS a finding: '*' disables the authentication of the
    #     SERVER by the client for every WinRM connection this machine makes.
    try {
        $thVal = Get-RegVal64 -Hive LocalMachine -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client' -Name 'TrustedHosts'
        if ([string]::IsNullOrWhiteSpace("$thVal")) {
            $thVal = Get-RegVal64 -Hive LocalMachine -SubKey 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'TrustedHosts'
        }
        if (-not [string]::IsNullOrWhiteSpace("$thVal")) {
            $thWild = ("$thVal".Trim() -eq '*')
            $obHits++
            Out-Typewriter "  -> WINRM TRUSTEDHOSTS IS SET: $thVal" $(if ($thWild) { "CRIT" } else { "WARN" })
            Add-Finding -ID "OUT151_TRUSTEDHOSTS" -Phase "PHASE 151" `
                -ThreatType "Lateral Movement" -Severity $(if ($thWild) { $SEV_HIGH } else { $SEV_POSSIBLE }) `
                -Description "The WinRM client TrustedHosts list on this machine is '$thVal'. TrustedHosts is what lets this machine connect to a remote host WITHOUT authenticating that host first, which is why it exists for workgroup administration and why it is dangerous: for every entry, this machine will hand its credential to whatever answers at that name. $(if ($thWild) { 'The value is the wildcard, so that is EVERY host on the network — anything that can win a name-resolution race, which phase 155 covers, can collect this credential.' } else { 'The list is explicit rather than a wildcard, which is the correct shape; confirm the named hosts are the management stations you expect.' }) On a domain-joined machine Kerberos authenticates the server mutually and TrustedHosts should normally be empty. Inspect and correct with: Get-Item WSMan:\localhost\Client\TrustedHosts   then   Set-Item WSMan:\localhost\Client\TrustedHosts -Value '' -Force ." `
                -Target "WinRM TrustedHosts" -FixAction "Info" -Group "Lateral Movement — Outbound"
        }
    } catch { Write-Log "PHASE 151: TrustedHosts check failed - $($_.Exception.Message)" }

    # (b) The saved-destination stores. Kind decides what is read: an MRU is inventoried,
    #     a SECRET store is additionally checked for a stored credential — by VALUE NAME
    #     only. The value itself is never read and never printed, for the same reason phase
    #     147 never opens a token cache: a finding that reproduces the credential turns the
    #     client report into a second copy of it.
    try {
        foreach ($ok in @($OUTBOUND_SESSION_KEYS)) {
            $okHive = "$($ok.Hive)"; $okSub = "$($ok.SubKey)"; $okKind = "$($ok.Kind)"
            $okSubs = @(Get-RegSubKeys64 -Hive $okHive -SubKey $okSub)
            $okVals = @(Get-RegNames64  -Hive $okHive -SubKey $okSub)
            if ($okSubs.Count -eq 0 -and $okVals.Count -eq 0) { continue }
            if ($okKind -eq 'MAPPED') {
                foreach ($md in $okSubs) {
                    $mdPath = Get-RegVal64 -Hive $okHive -SubKey "$okSub\$md" -Name 'RemotePath'
                    if ([string]::IsNullOrWhiteSpace("$mdPath")) { continue }
                    $obInv.Add("mapped drive ${md}: -> $mdPath")
                }
                continue
            }
            if ($okKind -eq 'VALUES') {
                foreach ($ov in $okVals) {
                    if ($ov -notmatch '^MRU') { continue }
                    $ovVal = Get-RegVal64 -Hive $okHive -SubKey $okSub -Name $ov
                    if ([string]::IsNullOrWhiteSpace("$ovVal")) { continue }
                    $obInv.Add("recent RDP: $ovVal")
                }
                continue
            }
            foreach ($os in $okSubs) {
                $obInv.Add("$($ok.Label): $os")
                if ($okKind -ne 'SECRET') { continue }
                $osVals = @(Get-RegNames64 -Hive $okHive -SubKey "$okSub\$os")
                $osSecret = @($osVals | Where-Object { Test-ScytheNameRule -Name "$_" -Rules $OUTBOUND_SECRET_NAMES })
                if ($osSecret.Count -eq 0) { continue }
                $obHits++
                Out-Typewriter "  -> SAVED SESSION WITH A STORED CREDENTIAL: $($ok.Label) / $os" "WARN"
                Add-Finding -ID "OUT151_SECRET_$([Math]::Abs("$okSub$os".ToLower().GetHashCode()))" -Phase "PHASE 151" `
                    -ThreatType "Credential Exposure" -Severity $SEV_HIGH `
                    -Description "The saved session '$os' under $($ok.Label) carries a stored-credential value ($($osSecret -join ', ')). The value itself has deliberately not been read: this phase reports that a credential is stored, never what it is. What makes this worth acting on is that these stores are not vaults — a session manager's saved password is obfuscated so the tool can replay it, which means anyone who can read the key can recover the plaintext, including any malware running as this user (MITRE T1555, T1552.002). The destination named by the session is also part of this machine's reach and should be added to the incident scope. Remove the stored secret and re-enter it as a key-based or vault-backed credential: the session store is under HKCU\$okSub\$os ." `
                    -Target "HKCU\$okSub\$os" -FixAction "Info" -Group "Lateral Movement — Outbound"
            }
        }
    } catch { Write-Log "PHASE 151: saved-session branch failed - $($_.Exception.Message)" }

    # (c) The file-backed connection managers. Same rule: the content rules match the
    #     ELEMENT that holds a secret, so a finding never reproduces the credential.
    try {
        foreach ($of in @($OUTBOUND_SESSION_FILES)) {
            if ([string]::IsNullOrWhiteSpace("$of")) { continue }
            if (-not (Test-Path -LiteralPath $of)) { continue }
            if ("$of" -match $OUTBOUND_BENIGN_RE) { continue }
            $obInv.Add("connection manager profile: $of")
            $ofr = Test-ContentRules -FilePath $of -Rules $OUTBOUND_FILE_RULES
            if (-not $ofr.Hit) { continue }
            $obHits++
            Out-Typewriter "  -> CONNECTION-MANAGER PROFILE WITH STORED PASSWORDS: $of" "WARN"
            Add-Finding -ID "OUT151_FILE_$([Math]::Abs("$of".ToLower().GetHashCode()))" -Phase "PHASE 151" `
                -ThreatType "Credential Exposure" -Severity (ConvertTo-ScytheSeverity "$($ofr.Severity)") `
                -Description "'$of' matched '$($ofr.Name)' — a connection manager's profile containing stored passwords. These files are the single highest-value target on an administrator's workstation: one file, every server the administrator manages, with a credential for each, encrypted under a scheme the tool itself has to be able to reverse (MITRE T1555.005). If this machine is compromised, treat every destination in this profile as reachable by the attacker and every credential in it as disclosed. The file is also the fastest way for YOU to scope the incident — open it and list the destinations. Rotate what it holds, then move the profile to a credential store the tool can read without keeping plaintext." `
                -Target $of -FixAction "Info" -Group "Lateral Movement — Outbound"
        }
    } catch { Write-Log "PHASE 151: session-file branch failed - $($_.Exception.Message)" }

    # (d) The credential vault, by target name only. cmdkey prints targets, never secrets.
    try {
        $ckOut = @(Invoke-ScytheConsoleTool -File 'cmdkey.exe' -Arguments '/list' -TimeoutMs 6000)
        # $Matches is scoped to the scriptblock it was set in, so a Where-Object that
        # matches and a ForEach-Object that reads $Matches[1] do not see the same thing.
        # An explicit loop is the only shape that is correct on 5.1.
        $ckTargets = New-Object System.Collections.Generic.List[string]
        foreach ($cl in $ckOut) {
            if ($cl -notmatch '^\s*Target:\s*(?<t>\S.*)$') { continue }
            $ckTargets.Add("$($Matches['t'])".Trim())
        }
        $ckDomain  = @(@($ckTargets) | Where-Object { $_ -match '(?i)^(Domain:target=|TERMSRV/)' })
        foreach ($ct in (@($ckTargets) | Select-Object -First 40)) { $obInv.Add("saved credential for $ct") }
        if ($ckDomain.Count -gt 0) {
            $obHits++
            Out-Typewriter "  -> $($ckDomain.Count) SAVED DOMAIN / RDP CREDENTIAL(S) IN THIS USER'S VAULT." "WARN"
            Add-Finding -ID "OUT151_CMDKEY" -Phase "PHASE 151" `
                -ThreatType "Credential Exposure" -Severity $SEV_POSSIBLE `
                -Description "This user's credential vault holds $($ckDomain.Count) saved domain or Remote Desktop credential(s): $(($ckDomain | Select-Object -First 8) -join '; '). Only the target names are listed — cmdkey does not print secrets and this phase does not try to recover them. Why it matters for scoping: a saved credential is replayed automatically, so anything running as this user can connect to those destinations without ever knowing the password, which is what makes 'the user's machine was compromised' and 'those servers were reachable' the same sentence (MITRE T1078, T1555.004). Why it is usually benign: saving an RDP credential is what the Remote Desktop client offers to do on every connection, so most of these were created by the user on purpose. Review and prune with: cmdkey /list   then   cmdkey /delete:<target> ." `
                -Target "Credential Manager (user vault)" -FixAction "Info" -Group "Lateral Movement — Outbound"
        }
    } catch { Write-Log "PHASE 151: credential-vault branch failed - $($_.Exception.Message)" }

    # The inventory is the deliverable even when nothing is wrong — the same reasoning as
    # phase 155 printing the name-resolution channels that were already correct. An
    # operator scoping an incident needs the list, and a phase that reports only failures
    # would print nothing here on the machines where the list matters most.
    if ($obInv.Count -gt 0) {
        Out-Typewriter "  -> THIS MACHINE HAS $($obInv.Count) RECORDED ROUTE(S) TO OTHER HOSTS." "DATA"
        foreach ($oi in ($obInv | Select-Object -First 15)) { Out-Typewriter "     - $oi" "DATA" }
        Add-Finding -ID "OUT151_INVENTORY" -Phase "PHASE 151" `
            -ThreatType "Attack Surface" -Severity $SEV_INFO `
            -Description "This machine records $($obInv.Count) route(s) to other hosts: $(($obInv | Select-Object -First 12) -join '; ')$(if ($obInv.Count -gt 12) { ' (and more)' } else { '' }). This is an inventory, not a finding — every item here is a normal artifact of somebody doing their job. It is in the report because it is the answer to the first question of any incident: if this endpoint is compromised, what else is in scope. Each destination named above should be checked before the engagement is closed, and each stored credential associated with one should be rotated." `
            -Target "Outbound reach inventory" -FixAction "Info" -Group "Lateral Movement — Outbound"
    }
    if ($obHits -eq 0) { Out-Typewriter "  -> [OK ] NO STORED CREDENTIALS OR OVER-WIDE REMOTING TRUST." "GOOD" }

    # ── PHASE 152: SESSION AND LOGON ANOMALIES ────────────────────────────────
    # Phase 107 already reports individual 4624 logons of type 3 and 10 from non-local
    # addresses, one finding per record. This phase deliberately emits NO per-record 4624
    # finding: a second opinion on the same event record would give one artifact two ids
    # and two severities, and phase 160 would then correlate them on the shared target as
    # though they were two independent facts — precisely what made phase 157 worse than
    # its parts. What is left to 152 is the AGGREGATE, which is a different question and
    # one that cannot be asked one record at a time: a spray is many accounts from one
    # source; a single failure is a typo.
    #
    # Every pull here goes through Get-ScytheEvents, which puts StartTime inside the
    # FilterHashtable so the Event Log service does the filtering. On a domain workstation
    # with a large Security log, the client-side alternative materialises hundreds of
    # thousands of records before the first comparison.
    Show-PhaseHeader "PHASE 152" "LOGON ANOMALIES — SPRAYS, EXPLICIT CREDENTIALS, NEW ADMINS" "EVT-HUNT"
    Out-Typewriter "AGGREGATING AUTHENTICATION RECORDS RATHER THAN LISTING THEM..." "HUNT"
    $lgHits = 0
    $lgMax     = if ($null -ne $LOGON_THRESH) { [int]$LOGON_THRESH.MaxEvents }             else { 3000 }
    $lgAccts   = if ($null -ne $LOGON_THRESH) { [int]$LOGON_THRESH.SprayDistinctAccounts } else { 5 }
    $lgWindow  = if ($null -ne $LOGON_THRESH) { [int]$LOGON_THRESH.SprayWindowMinutes }    else { 30 }
    $lgMinFail = if ($null -ne $LOGON_THRESH) { [int]$LOGON_THRESH.SprayMinFailures }      else { 10 }
    $lgReport  = if ($null -ne $LOGON_THRESH) { [int]$LOGON_THRESH.MaxReported }           else { 20 }

    # (a) The spray. Grouped by SOURCE, because that is what a spray has one of and a
    #     forgetful user does not: many distinct accounts, one origin, a short window.
    try {
        $failEvts = @(Get-ScytheEvents -LogName 'Security' -Id @(4625) -MaxEvents $lgMax)
        if ($failEvts.Count -eq 0) {
            Out-Typewriter "  -> NO FAILED-LOGON RECORDS IN THE WINDOW." "GOOD"
        } else {
            $lgBySrc = @{}
            foreach ($fe in $failEvts) {
                $feUser = Get-ScytheEvtField -Event $fe -Index 5  -Name 'TargetUserName'
                $feWks  = Get-ScytheEvtField -Event $fe -Index 13 -Name 'WorkstationName'
                $feIp   = Get-ScytheEvtField -Event $fe -Index 19 -Name 'IpAddress' -Validate '^(\d{1,3}(\.\d{1,3}){3}|[0-9A-Fa-f:]{2,45}|-)$'
                if ("$feUser" -match $LOGON_ACCT_BENIGN_RE) { continue }
                $feSrc = if (-not [string]::IsNullOrWhiteSpace("$feIp") -and "$feIp" -ne '-') { "$feIp" }
                         elseif (-not [string]::IsNullOrWhiteSpace("$feWks")) { "$feWks" }
                         else { 'local console' }
                if (-not $lgBySrc.ContainsKey($feSrc)) {
                    $lgBySrc[$feSrc] = [pscustomobject]@{
                        Count = 0
                        Users = (New-Object System.Collections.Generic.HashSet[string])
                        First = $fe.TimeCreated
                        Last  = $fe.TimeCreated
                    }
                }
                $agg = $lgBySrc[$feSrc]
                $agg.Count++
                [void]$agg.Users.Add("$feUser".ToLower())
                if ($fe.TimeCreated -lt $agg.First) { $agg.First = $fe.TimeCreated }
                if ($fe.TimeCreated -gt $agg.Last)  { $agg.Last  = $fe.TimeCreated }
            }
            $lgSprayed = 0
            foreach ($src in @($lgBySrc.Keys)) {
                if ($lgSprayed -ge $lgReport) { break }
                $agg = $lgBySrc[$src]
                if ($agg.Users.Count -lt $lgAccts -or $agg.Count -lt $lgMinFail) { continue }
                $spanMin = [Math]::Round(($agg.Last - $agg.First).TotalMinutes, 1)
                if ($spanMin -gt $lgWindow) { continue }
                $lgHits++; $lgSprayed++
                Out-ThreatBanner "PASSWORD SPRAY AGAINST THIS HOST" "$($agg.Users.Count) accounts from $src"
                Add-Finding -ID "LOGON152_SPRAY_$([Math]::Abs("$src".ToLower().GetHashCode()))" -Phase "PHASE 152" `
                    -ThreatType "Credential Access" -Severity $SEV_HIGH `
                    -Description "$($agg.Count) failed logons against $($agg.Users.Count) DISTINCT accounts arrived from '$src' inside $spanMin minute(s), between $($agg.First) and $($agg.Last). One person failing to log in produces many attempts against ONE account; many accounts from one source is a spray — a small number of common passwords tried against a list of user names, kept below the lockout threshold on purpose (MITRE T1110.003). The account list itself is worth reading: if it matches this organisation's real user names, the attacker already has a directory listing from somewhere. Check whether any attempt SUCCEEDED from the same source, because that is the finding that changes the response — search the 4624 records for '$src' with: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-2)} | Where-Object Message -match '$src' . Block '$src' at the firewall if it is not a host you own, and confirm the lockout policy is doing its job." `
                    -Target "Logon source: $src" -FixAction "Info" -Group "Logon Anomalies"
            }
            if ($lgSprayed -eq 0) { Out-Typewriter "  -> $($failEvts.Count) FAILED LOGON(S), NO SPRAY PATTERN." "GOOD" }
        }
    } catch { Write-Log "PHASE 152: 4625 branch failed - $($_.Exception.Message)" }

    # (b) Event 4648 — a logon with EXPLICITLY supplied credentials. On a managed endpoint
    #     the raw event is constant noise (runas, stored task passwords, every RMM agent),
    #     which is why the allowlist is on the calling image PATH — the safe kind — and why
    #     this is grouped per (process, target account) rather than reported per record.
    try {
        $explEvts = @(Get-ScytheEvents -LogName 'Security' -Id @(4648) -MaxEvents $lgMax)
        $lgByProc = @{}
        foreach ($ee in $explEvts) {
            $eeProc = Get-ScytheEvtField -Event $ee -Index 11 -Name 'ProcessName'
            $eeTgt  = Get-ScytheEvtField -Event $ee -Index 5  -Name 'TargetUserName'
            $eeSrv  = Get-ScytheEvtField -Event $ee -Index 8  -Name 'TargetServerName'
            if ("$eeProc" -match $LOGON_EXPLICIT_BENIGN_RE) { continue }
            if ("$eeTgt"  -match $LOGON_ACCT_BENIGN_RE)     { continue }
            $ek = "$eeProc|$eeTgt|$eeSrv"
            if (-not $lgByProc.ContainsKey($ek)) {
                $lgByProc[$ek] = [pscustomobject]@{ Proc = "$eeProc"; Target = "$eeTgt"; Server = "$eeSrv"; Count = 0; Last = $ee.TimeCreated }
            }
            $lgByProc[$ek].Count++
            if ($ee.TimeCreated -gt $lgByProc[$ek].Last) { $lgByProc[$ek].Last = $ee.TimeCreated }
        }
        $lgExpl = 0
        foreach ($ek in @($lgByProc.Keys)) {
            if ($lgExpl -ge $lgReport) { break }
            $ev = $lgByProc[$ek]
            $lgHits++; $lgExpl++
            Out-Typewriter "  -> EXPLICIT-CREDENTIAL LOGON: $($ev.Proc) as $($ev.Target) -> $($ev.Server)" "WARN"
            Add-Finding -ID "LOGON152_EXPLICIT_$([Math]::Abs($ek.ToLower().GetHashCode()))" -Phase "PHASE 152" `
                -ThreatType "Lateral Movement" -Severity $SEV_POSSIBLE `
                -Description "'$($ev.Proc)' supplied explicit credentials for account '$($ev.Target)' to '$($ev.Server)' — $($ev.Count) time(s), most recently $($ev.Last). Event 4648 fires when a process authenticates as somebody other than the logged-on user, which is exactly what a stolen credential looks like being used: the attacker has the credential, not the session, so every connection has to present it explicitly (MITRE T1078, T1550). The routine causes are runas, a scheduled task with a stored password, and an administration tool being pointed at a server — and the image paths that do that legitimately are already filtered out here, which is why this one surfaced. The question to answer is whether '$($ev.Proc)' has any business holding that account's password. If the target server is not one this machine normally administers, add it to the incident scope." `
                -Target "$($ev.Proc) as $($ev.Target)" -FixAction "Info" -Group "Logon Anomalies"
        }
        if ($lgExpl -eq 0) { Out-Typewriter "  -> NO UNEXPLAINED EXPLICIT-CREDENTIAL LOGONS." "GOOD" }
    } catch { Write-Log "PHASE 152: 4648 branch failed - $($_.Exception.Message)" }

    # (c) Accounts created, and accounts added to a privileged group. Two events, reported
    #     together because the pair is the finding: an account created and then made an
    #     administrator inside the same window is persistence being established, and it is
    #     one of the very few things in this band that is almost never benign on a
    #     workstation.
    try {
        $acctEvts = @(Get-ScytheEvents -LogName 'Security' -Id @(4720,4732) -MaxEvents 1000)
        # TWO PASSES, and the first one is not optional. Get-WinEvent returns NEWEST FIRST,
        # so the 4732 that added the account to Administrators arrives BEFORE the 4720 that
        # created it — a single pass would never see the pairing that is the whole point of
        # reading these two ids together, and the created-then-privileged case would be
        # reported as two unrelated POSSIBLEs on every machine where it happened.
        $newAccts = New-Object System.Collections.Generic.HashSet[string]
        foreach ($ae in $acctEvts) {
            if ([int]$ae.Id -ne 4720) { continue }
            $aeNew = Get-ScytheEvtField -Event $ae -Index 0 -Name 'TargetUserName'
            if (-not [string]::IsNullOrWhiteSpace("$aeNew")) { [void]$newAccts.Add("$aeNew".ToLower()) }
        }
        $lgAcct = 0
        foreach ($ae in $acctEvts) {
            if ($lgAcct -ge $lgReport) { break }
            $isCreate = ([int]$ae.Id -eq 4720)
            $aeWho    = if ($isCreate) { Get-ScytheEvtField -Event $ae -Index 0 -Name 'TargetUserName' }
                        else            { Get-ScytheEvtField -Event $ae -Index 0 -Name 'MemberName' }
            $aeBy     = if ($isCreate) { Get-ScytheEvtField -Event $ae -Index 4 -Name 'SubjectUserName' }
                        else            { Get-ScytheEvtField -Event $ae -Index 6 -Name 'SubjectUserName' }
            $aeGroup  = if ($isCreate) { '' } else { Get-ScytheEvtField -Event $ae -Index 2 -Name 'TargetUserName' }
            if ([string]::IsNullOrWhiteSpace("$aeWho")) { continue }
            # A group addition only matters here when the group is a privileged one. Users,
            # Remote Desktop Users and the rest are ordinary administration and reporting
            # them would bury the case that matters.
            if (-not $isCreate -and "$aeGroup" -notmatch '(?i)^(Administrators|Administradores|Administrateurs|Domain Admins|Enterprise Admins|Backup Operators)$') { continue }
            $aeAlsoNew = ((-not $isCreate) -and $newAccts.Contains("$aeWho".ToLower()))
            $lgHits++; $lgAcct++
            $aeSev = if ($aeAlsoNew) { $SEV_HIGH } else { $SEV_POSSIBLE }
            Out-Typewriter "  -> $(if ($isCreate) { 'ACCOUNT CREATED' } else { "ADDED TO $aeGroup" }): $aeWho (by $aeBy)" $(if ($aeAlsoNew) { "CRIT" } else { "WARN" })
            Add-Finding -ID "LOGON152_ACCT_$($ae.RecordId)" -Phase "PHASE 152" `
                -ThreatType "Persistence" -Severity $aeSev `
                -Description "$(if ($isCreate) { "Account '$aeWho' was CREATED" } else { "Account '$aeWho' was ADDED TO '$aeGroup'" }) by '$aeBy' at $($ae.TimeCreated).$(if ($aeAlsoNew) { ' This account was also created inside the same scan window — created and then made privileged is an attacker establishing a way back in that survives the original access being closed, and it is the single most common form of Windows persistence after a successful intrusion.' } else { '' }) On a workstation, local account changes are rare and every one of them should have a change record behind it (MITRE T1136.001, T1098). What to check: whether '$aeBy' is an administrator who intended this, and whether the new account has a password that meets policy. List what exists now and compare: Get-LocalUser | Format-Table Name, Enabled, LastLogon   and   Get-LocalGroupMember -Group 'Administrators' ." `
                -Target "Account: $aeWho" -FixAction "Info" -Group "Logon Anomalies"
        }
        if ($lgAcct -eq 0) { Out-Typewriter "  -> NO ACCOUNTS CREATED OR PRIVILEGED IN THE WINDOW." "GOOD" }
    } catch { Write-Log "PHASE 152: 4720/4732 branch failed - $($_.Exception.Message)" }

    if ($lgHits -eq 0) { Out-Typewriter "  -> [OK ] NO LOGON ANOMALIES." "GOOD" }

    # ── PHASE 153: SMB SERVER + AUTHENTICATION POSTURE ────────────────────────
    Show-PhaseHeader "PHASE 153" "SMB SIGNING, GUEST AUTH AND NULL-SESSION POSTURE" "HARDENING"
    Out-Typewriter "READING THE HOST'S OWN SMB CONFIGURATION..." "HUNT"

    $srvParams = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wksParams = 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $lsaKey    = 'SYSTEM\CurrentControlSet\Control\Lsa'

    # Server-side signing. "Enabled" is not "Required": a server that merely PERMITS
    # signing still completes an unsigned session when the client does not ask for it,
    # which is the precondition every relay technique depends on. Only Require closes it.
    $srvReq = Get-RegVal64 -Hive LocalMachine -SubKey $srvParams -Name 'RequireSecuritySignature'
    $srvEna = Get-RegVal64 -Hive LocalMachine -SubKey $srvParams -Name 'EnableSecuritySignature'
    if ($null -eq $srvReq -or [int]$srvReq -ne 1) {
        Out-Typewriter "  -> SMB SERVER SIGNING IS NOT REQUIRED." "CRIT"
        Add-Finding -ID "NET153_SRVSIGN" -Phase "PHASE 153" `
            -ThreatType "Credential Access / Relay" -Severity $SEV_HIGH `
            -Description "SMB server-side signing is not REQUIRED on this host (RequireSecuritySignature=$srvReq, EnableSecuritySignature=$srvEna). A server that only permits signing will still complete an unsigned session, and an unsigned SMB session can be relayed: an attacker who can coerce this machine — or any account on it — into authenticating elsewhere can forward that authentication to a third host and act as the user, without ever learning the password. Enabling signing is not sufficient; it must be required. Set it with: Set-SmbServerConfiguration -RequireSecuritySignature 1 -Force   (registry equivalent: HKLM\$srvParams\RequireSecuritySignature = 1). Set the client-side twin as well, under LanmanWorkstation. Expect a measurable throughput cost on large file transfers; that cost is the point of the control." `
            -Target "HKLM\$srvParams\RequireSecuritySignature" -FixAction "Info" -Group "Network Exposure"
    } else {
        Out-Typewriter "  -> SMB SERVER SIGNING REQUIRED." "GOOD"
    }

    $wksReq = Get-RegVal64 -Hive LocalMachine -SubKey $wksParams -Name 'RequireSecuritySignature'
    if ($null -eq $wksReq -or [int]$wksReq -ne 1) {
        Add-Finding -ID "NET153_WKSSIGN" -Phase "PHASE 153" `
            -ThreatType "Credential Access / Relay" -Severity $SEV_INFO `
            -Description "SMB client-side signing is not required (RequireSecuritySignature=$wksReq under LanmanWorkstation). This governs sessions this machine INITIATES. Without it, a poisoned name-resolution response can steer this host to an attacker-controlled server and the resulting session can be relayed onward. Set with: Set-SmbClientConfiguration -RequireSecuritySignature 1 -Force" `
            -Target "HKLM\$wksParams\RequireSecuritySignature" -FixAction "Info" -Group "Network Exposure"
    }

    # Insecure guest logon. This is what allows an unauthenticated peer to bind as
    # 'guest' and enumerate shares; it also silently downgrades to an unsigned,
    # unauthenticated session, so anything read over it is tamperable in transit.
    $guestAuth = Get-RegVal64 -Hive LocalMachine -SubKey $wksParams -Name 'AllowInsecureGuestAuth'
    if ($null -ne $guestAuth -and [int]$guestAuth -eq 1) {
        Out-Typewriter "  -> INSECURE GUEST AUTH IS ENABLED." "CRIT"
        Add-Finding -ID "NET153_GUESTAUTH" -Phase "PHASE 153" `
            -ThreatType "Initial Access / Exposure" -Severity $SEV_HIGH `
            -Description "AllowInsecureGuestAuth is enabled. Any host on the same network can open an SMB session to this machine as 'guest' with no credentials, enumerate the published share list, and read anything whose ACL grants Everyone or Guest. Guest sessions are additionally unsigned and unencrypted, so their contents can be modified in transit. Windows disables this by default; something set it. Disable with: Set-ItemProperty 'HKLM:\$wksParams' AllowInsecureGuestAuth 0   then confirm the Guest account itself is disabled (Get-LocalUser Guest)." `
            -Target "HKLM\$wksParams\AllowInsecureGuestAuth" -FixAction "Info" -Group "Network Exposure"
    } else {
        Out-Typewriter "  -> INSECURE GUEST AUTH DISABLED." "GOOD"
    }

    # The local Guest account itself, independent of the SMB policy above.
    $guestOn = $null
    try {
        $gu = Get-LocalUser -Name 'Guest' -ErrorAction Stop
        $guestOn = [bool]$gu.Enabled
    } catch { $guestOn = $null }
    if ($guestOn -eq $true) {
        Out-Typewriter "  -> LOCAL GUEST ACCOUNT IS ENABLED." "CRIT"
        Add-Finding -ID "NET153_GUESTACCT" -Phase "PHASE 153" `
            -ThreatType "Initial Access / Exposure" -Severity $SEV_HIGH `
            -Description "The built-in Guest account is ENABLED. Windows ships it disabled. Enabled, it is an unauthenticated foothold for share access and, on some configurations, for interactive logon. Disable with: Disable-LocalUser -Name Guest   and verify no share ACL still references it (phase 154 lists those)." `
            -Target "LocalUser\Guest" -FixAction "Info" -Group "Network Exposure"
    } elseif ($guestOn -eq $false) {
        Out-Typewriter "  -> LOCAL GUEST ACCOUNT DISABLED." "GOOD"
    }

    # Null-session (fully anonymous) access.
    $nullSess = Get-RegVal64 -Hive LocalMachine -SubKey $srvParams -Name 'RestrictNullSessAccess'
    $restrAnon = Get-RegVal64 -Hive LocalMachine -SubKey $lsaKey -Name 'RestrictAnonymous'
    $restrSam  = Get-RegVal64 -Hive LocalMachine -SubKey $lsaKey -Name 'RestrictAnonymousSAM'
    if ($null -eq $nullSess -or [int]$nullSess -ne 1) {
        Add-Finding -ID "NET153_NULLSESS" -Phase "PHASE 153" `
            -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
            -Description "RestrictNullSessAccess is not set to 1 (current: $nullSess). Anonymous sessions may reach the pipes and shares named in NullSessionPipes / NullSessionShares. Set: HKLM\$srvParams\RestrictNullSessAccess = 1, and empty the NullSessionPipes and NullSessionShares values unless a named application documents needing one." `
            -Target "HKLM\$srvParams\RestrictNullSessAccess" -FixAction "Info" -Group "Network Exposure"
    }
    if ($null -eq $restrSam -or [int]$restrSam -ne 1) {
        Add-Finding -ID "NET153_RESTRICTSAM" -Phase "PHASE 153" `
            -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
            -Description "RestrictAnonymousSAM is not 1 (current: $restrSam; RestrictAnonymous=$restrAnon). This governs whether an anonymous session can enumerate local account NAMES — the first step of any password-guessing or spraying attempt, because it turns a blind guess into a target list. Set HKLM\$lsaKey\RestrictAnonymousSAM = 1." `
            -Target "HKLM\$lsaKey\RestrictAnonymousSAM" -FixAction "Info" -Group "Network Exposure"
    }

    # SMB1. Present-but-disabled is fine; present-and-enabled is not.
    $smb1 = $null
    try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $smb1 = $null }
    if ($smb1 -eq $true) {
        Out-Typewriter "  -> SMB1 IS ENABLED." "CRIT"
        Add-Finding -ID "NET153_SMB1" -Phase "PHASE 153" `
            -ThreatType "Lateral Movement" -Severity $SEV_HIGH `
            -Description "SMB1 is enabled on this host. SMB1 cannot negotiate modern signing or encryption, is the transport several self-propagating families use to spread across a flat network, and has no remaining legitimate use outside specific legacy appliances. Disable with: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart   then reboot. If a legacy device genuinely requires it, isolate that device instead of keeping SMB1 on general workstations." `
            -Target "SMB1Protocol" -FixAction "Info" -Group "Network Exposure"
    } elseif ($smb1 -eq $false) {
        Out-Typewriter "  -> SMB1 DISABLED." "GOOD"
    }

    # ── PHASE 154: SHARE INVENTORY AND SHARE-LEVEL ACL AUDIT ──────────────────
    Show-PhaseHeader "PHASE 154" "PUBLISHED SHARES AND THEIR ACCESS CONTROL" "HARDENING"
    Out-Typewriter "ENUMERATING PUBLISHED SHARES AND THEIR ACLS..." "HUNT"

    $shares = @()
    try { $shares = @(Get-SmbShare -ErrorAction Stop) } catch { $shares = @() }

    if ($shares.Count -eq 0) {
        Out-Typewriter "  -> SHARE ENUMERATION RETURNED NOTHING." "WARN"
        Add-Finding -ID "NET154_NOSHARES" -Phase "PHASE 154" `
            -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
            -Description "Get-SmbShare returned no shares at all. Every Windows host normally publishes at least IPC$. Either the Server service is stopped (check: Get-Service LanmanServer) or the enumeration failed. Share posture could NOT be assessed this run." `
            -Target "Get-SmbShare" -FixAction "Info" -Group "Network Exposure"
    } else {
        # Anything that is not IPC$, ADMIN$ or a bare drive-letter admin share was
        # published deliberately and is the operator's responsibility to justify.
        $nonDefault = @($shares | Where-Object { $_.Name -notmatch '^(IPC\$|ADMIN\$|[A-Za-z]\$)$' })
        foreach ($sh in $nonDefault) {
            $shName = "$($sh.Name)"; $shPath = "$($sh.Path)"
            Out-Typewriter "  -> NON-DEFAULT SHARE: $shName -> $shPath" "WARN"
            Add-Finding -ID "NET154_SHARE_$([Math]::Abs($shName.ToLower().GetHashCode()))" -Phase "PHASE 154" `
                -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
                -Description "The share '$shName' publishes '$shPath' over the network. This is not a default Windows share, so it was created deliberately — confirm it is still required. A share rooted at a user profile directory, a drive root, or a directory containing credentials, backups or configuration is a direct data-exposure path and, if writable, a route to plant a startup or shortcut file that executes when a user logs in. Review with: Get-SmbShareAccess -Name '$shName'   and remove with: Remove-SmbShare -Name '$shName'" `
                -Target "SmbShare\$shName" -FixAction "Info" -Group "Network Exposure"
        }
        if ($nonDefault.Count -eq 0) { Out-Typewriter "  -> NO NON-DEFAULT SHARES PUBLISHED." "GOOD" }

        # Share-level ACEs granting an anonymous or universal principal. This is the
        # ACL that actually decides whether the guest session of phase 153 can read.
        foreach ($sh in $shares) {
            $shName = "$($sh.Name)"
            if ($shName -match '^(IPC\$)$') { continue }
            $aces = @()
            try { $aces = @(Get-SmbShareAccess -Name $shName -ErrorAction Stop) } catch { continue }
            foreach ($ace in $aces) {
                $acct = "$($ace.AccountName)"
                if ($acct -notmatch '(^|\\)(Everyone|ANONYMOUS LOGON|Guest|Guests|NT AUTHORITY\\ANONYMOUS LOGON)$') { continue }
                if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
                Out-Typewriter "  -> SHARE '$shName' GRANTS $acct : $($ace.AccessRight)" "CRIT"
                Add-Finding -ID "NET154_ACE_$([Math]::Abs(($shName + $acct).ToLower().GetHashCode()))" -Phase "PHASE 154" `
                    -ThreatType "Initial Access / Exposure" -Severity $SEV_HIGH `
                    -Description "The share '$shName' grants '$acct' $($ace.AccessRight) at the SHARE level. Combined with an enabled Guest account or insecure guest logon (phase 153), this is readable — and at Change or Full, writable — by any unauthenticated host on the same network. Effective access is the MORE RESTRICTIVE of the share ACL and the NTFS ACL, so a tight NTFS ACL may still be holding the line; do not assume it is. Review: Get-SmbShareAccess -Name '$shName'   and tighten: Revoke-SmbShareAccess -Name '$shName' -AccountName '$acct' -Force" `
                    -Target "SmbShare\$shName ACE:$acct" -FixAction "Info" -Group "Network Exposure"
            }
        }

        # Administrative shares. Removing them breaks a great deal of legitimate
        # management tooling, so this is reported as posture, never as a defect.
        $autoWks = Get-RegVal64 -Hive LocalMachine -SubKey $srvParams -Name 'AutoShareWks'
        if ($null -eq $autoWks -or [int]$autoWks -ne 0) {
            Add-Finding -ID "NET154_ADMINSHARES" -Phase "PHASE 154" `
                -ThreatType "Lateral Movement" -Severity $SEV_INFO `
                -Description "Administrative shares (C\$, ADMIN\$) are enabled (AutoShareWks=$autoWks). This is the Windows default and a great deal of legitimate management and backup tooling depends on it, so it is reported as posture rather than as a fault. It is also the most-used lateral-movement path on a flat network: any credential with local administrator rights on this host can write to the whole system drive remotely. The meaningful mitigations are not removing the share but: unique local administrator passwords per host (LAPS), the local-account network-logon restriction (FilterAdministratorToken), and blocking inbound 445 from anything but management infrastructure. Disable only on a host you are certain nothing manages: HKLM\$srvParams\AutoShareWks = 0." `
                -Target "HKLM\$srvParams\AutoShareWks" -FixAction "Info" -Group "Network Exposure"
        }
    }

    # ── PHASE 155: NAME-RESOLUTION POISONING SURFACE ──────────────────────────
    Show-PhaseHeader "PHASE 155" "BROADCAST NAME RESOLUTION AND NTLM EXPOSURE" "HARDENING"
    Out-Typewriter "CHECKING THE PROTOCOLS THAT LEAK AUTHENTICATION..." "HUNT"

    # When DNS fails, Windows falls back to asking the whole local segment "who is X?".
    # Any host may answer. Answering falsely redirects the requester to the responder
    # and coerces it into authenticating there — which is why these three protocols are
    # the standard path onto a host whose inbound ports are entirely closed.
    $llmnr = Get-RegVal64 -Hive LocalMachine -SubKey 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    if ($null -eq $llmnr -or [int]$llmnr -ne 0) {
        Out-Typewriter "  -> LLMNR IS NOT DISABLED." "CRIT"
        Add-Finding -ID "NET155_LLMNR" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_HIGH `
            -Description "LLMNR is not disabled (EnableMulticast=$llmnr). When DNS resolution fails — a typo, a stale mapped drive, a decommissioned server name — this host broadcasts the name to the entire local segment and trusts whoever answers first. An attacker on the same segment answers every query, and the host then authenticates to them, handing over an NTLMv2 response that can be cracked offline or relayed onward immediately. This works against a host with every inbound port closed, because the host initiates it. Disable: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0 (Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution)." `
            -Target "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast" -FixAction "Info" -Group "Network Exposure"
    } else {
        Out-Typewriter "  -> LLMNR DISABLED." "GOOD"
    }

    # NBT-NS, per interface. Option 2 = disabled. Anything else leaks the hostname
    # pre-auth and is the second poisoning channel.
    $nbtBad = @()
    foreach ($ifc in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces')) {
        $opt = Get-RegVal64 -Hive LocalMachine -SubKey "SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$ifc" -Name 'NetbiosOptions'
        if ($null -ne $opt -and [int]$opt -ne 2) { $nbtBad += "$ifc(=$opt)" }
    }
    if ($nbtBad.Count -gt 0) {
        Out-Typewriter "  -> NetBIOS-over-TCP ENABLED ON $($nbtBad.Count) INTERFACE(S)." "CRIT"
        Add-Finding -ID "NET155_NBTNS" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_HIGH `
            -Description "NetBIOS over TCP/IP is not disabled on: $($nbtBad -join ', ') (NetbiosOptions 2 = disabled). NBT-NS is the second broadcast name-resolution channel and is poisoned exactly as LLMNR is, with the same outcome — a coerced NTLM authentication to an attacker on the segment. It additionally discloses this machine's name to any unauthenticated peer that asks. Set NetbiosOptions = 2 on every interface under HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces, or via the adapter's IPv4 > Advanced > WINS tab." `
            -Target "NetBT\Parameters\Interfaces" -FixAction "Info" -Group "Network Exposure"
    } else {
        Out-Typewriter "  -> NetBIOS-over-TCP DISABLED ON ALL INTERFACES." "GOOD"
    }

    # mDNS — the third channel, and the one most often left on because it is newer
    # and is not covered by the classic LLMNR/NBT hardening guides.
    $mdns = Get-RegVal64 -Hive LocalMachine -SubKey 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS'
    if ($null -eq $mdns -or [int]$mdns -ne 0) {
        Add-Finding -ID "NET155_MDNS" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_INFO `
            -Description "mDNS is not explicitly disabled (EnableMDNS=$mdns). It is the third broadcast name-resolution channel, poisonable in the same way as LLMNR and NBT-NS, and it is frequently missed because most hardening baselines predate Windows enabling it by default. It also advertises this host's name and services to the whole segment, which defeats the invisibility a closed firewall appears to provide. Disable on a machine that shares nothing: HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0. Note this may affect discovery of network printers and cast devices." `
            -Target "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS" -FixAction "Info" -Group "Network Exposure"
    }

    # Outbound NTLM restriction and LM compatibility — what the coerced authentication
    # is actually worth once captured.
    $ntlmOut = Get-RegVal64 -Hive LocalMachine -SubKey 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'
    if ($null -eq $ntlmOut -or [int]$ntlmOut -lt 1) {
        Add-Finding -ID "NET155_NTLMOUT" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_INFO `
            -Description "Outbound NTLM is unrestricted (RestrictSendingNTLMTraffic=$ntlmOut). This is what makes a poisoned name response profitable: the host will send NTLM authentication to an arbitrary peer that claims the name. Setting 1 (audit) first shows what would break; 2 (deny all) stops it. Audit before enforcing — this breaks legitimate access to anything still authenticating with NTLM. Key: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic. Also confirm LmCompatibilityLevel is 5 so LM and NTLMv1 responses are never emitted." `
            -Target "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic" -FixAction "Info" -Group "Network Exposure"
    }
    $lmcompat = Get-RegVal64 -Hive LocalMachine -SubKey $lsaKey -Name 'LmCompatibilityLevel'
    if ($null -ne $lmcompat -and [int]$lmcompat -lt 5) {
        Add-Finding -ID "NET155_LMCOMPAT" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_HIGH `
            -Description "LmCompatibilityLevel is $lmcompat. Below 5 this host can emit LM or NTLMv1 responses, which are recoverable to the original password in a practical amount of time regardless of password strength — the cryptography, not the password, is the weakness. Set HKLM\$lsaKey\LmCompatibilityLevel = 5 (send NTLMv2 only, refuse LM and NTLM)." `
            -Target "HKLM\$lsaKey\LmCompatibilityLevel" -FixAction "Info" -Group "Network Exposure"
    }

    # ── PHASE 156: FIREWALL PROFILE AND ADVERTISED SERVICES ───────────────────
    Show-PhaseHeader "PHASE 156" "FIREWALL PROFILE AND WHAT THIS HOST ADVERTISES" "HARDENING"
    Out-Typewriter "READING FIREWALL PROFILES AND SERVICE ADVERTISEMENT..." "HUNT"

    # A closed firewall is a point-in-time claim. Record the profile per interface so
    # two runs can be diffed and a Public->Private flip is visible to the operator.
    try {
        foreach ($prof in @(Get-NetConnectionProfile -ErrorAction Stop)) {
            $cat = "$($prof.NetworkCategory)"; $alias = "$($prof.InterfaceAlias)"
            Out-Typewriter "  -> INTERFACE '$alias' IS IN THE '$cat' PROFILE." "INFO"
            if ($cat -eq 'Private' -or $cat -eq 'DomainAuthenticated') {
                Add-Finding -ID "NET156_PROFILE_$([Math]::Abs($alias.ToLower().GetHashCode()))" -Phase "PHASE 156" `
                    -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
                    -Description "Interface '$alias' is in the '$cat' network profile. The Private profile permits file and printer sharing, network discovery and remote management rules that the Public profile blocks — so the same machine has a materially larger attack surface on this network than it would on an untrusted one. On a shared, hotel, or otherwise uncontrolled network this should be Public. Change with: Set-NetConnectionProfile -InterfaceAlias '$alias' -NetworkCategory Public. Recorded per run so a profile change between scans is visible in a comparison." `
                    -Target "NetConnectionProfile\$alias" -FixAction "Info" -Group "Network Exposure"
            }
        }
    } catch {
        Out-Typewriter "  -> COULD NOT READ NETWORK PROFILES." "WARN"
    }

    # Inbound allow rules for the protocols that matter most on a workstation.
    $riskyPorts = @{ '445' = 'SMB'; '139' = 'NetBIOS session'; '135' = 'RPC endpoint mapper';
                     '3389' = 'RDP'; '5985' = 'WinRM (HTTP)'; '5986' = 'WinRM (HTTPS)' }
    try {
        $enabledIn = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop)
        foreach ($rule in $enabledIn) {
            $pf = $null
            try { $pf = $rule | Get-NetFirewallPortFilter -ErrorAction Stop } catch { continue }
            foreach ($lp in @($pf.LocalPort)) {
                $lpS = "$lp"
                if (-not $riskyPorts.ContainsKey($lpS)) { continue }
                $prof = "$($rule.Profile)"
                if ($prof -notmatch 'Public|Any') { continue }
                Add-Finding -ID "NET156_INBOUND_$($lpS)_$([Math]::Abs("$($rule.Name)".ToLower().GetHashCode()))" -Phase "PHASE 156" `
                    -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
                    -Description "Inbound TCP $lpS ($($riskyPorts[$lpS])) is allowed by the enabled firewall rule '$($rule.DisplayName)' on the '$prof' profile. On the Public profile this exposes the service to every host on an untrusted network. Review with: Get-NetFirewallRule -Name '$($rule.Name)' | Get-NetFirewallPortFilter   and scope it to management infrastructure with -RemoteAddress rather than disabling it outright if the service is genuinely needed." `
                    -Target "FirewallRule\$($rule.Name):$lpS" -FixAction "Info" -Group "Network Exposure"
            }
        }
    } catch {
        Out-Typewriter "  -> COULD NOT ENUMERATE FIREWALL RULES." "WARN"
    }

    # Delivery Optimization. Peering modes advertise the machine name and an open port
    # to the whole broadcast domain, from a host that may otherwise answer nothing.
    $doMode = Get-RegVal64 -Hive LocalMachine -SubKey 'SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode'
    if ($null -eq $doMode) {
        $doMode = Get-RegVal64 -Hive LocalMachine -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode'
    }
    if ($null -ne $doMode -and @(1,2,3) -contains [int]$doMode) {
        Out-Typewriter "  -> DELIVERY OPTIMIZATION PEERING IS ON (mode $doMode)." "WARN"
        Add-Finding -ID "NET156_DOPEER" -Phase "PHASE 156" `
            -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
            -Description "Delivery Optimization peer-to-peer is enabled (DODownloadMode=$doMode; modes 1, 2 and 3 all peer). To find peers it advertises this machine over mDNS with its hostname, both IP families and a listening TCP port (usually 7680) to the entire broadcast domain. The practical consequence is that a host whose firewall refuses every unicast probe still announces its own existence, name and an open port to anyone listening — the firewall creates an appearance of invisibility that this default-on service removes. Set DODownloadMode to 0 (HTTP only) or 99 (simple, no peering) on machines that should not be discoverable: HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode." `
            -Target "DODownloadMode" -FixAction "Info" -Group "Network Exposure"
    }

    Out-Typewriter "NETWORK-EXPOSURE BAND COMPLETE." "GOOD"

    # ── PHASE 157: THE REMAINING PERSISTENCE SURFACE ──────────────────────────
    # The autostart coverage in phases 20-35 and 90-105 is genuinely good. These are the
    # mechanisms it still does not reach: each is real, each is in the wild, and each
    # survives the reinstall of whatever the operator thinks the malware was.
    #
    # Every check below sits in its OWN try, so one failing registry read cannot cost
    # the other thirteen. Everything is FixAction "Info" — several of these live under
    # SYSTEM\CurrentControlSet\Control, which the remediation guard refuses outright, and
    # a CRITICAL finding with a destructive fix on a guard-protected target is
    # auto-selected in the GUI and then reported blocked on every machine (audit M1).
    Show-PhaseHeader "PHASE 157" "PROFILER, LOGON, SPOOLER AND WINSOCK PERSISTENCE" "PERSISTENCE"
    Out-Typewriter "WALKING THE PERSISTENCE MECHANISMS NOTHING ELSE CHECKS..." "HUNT"

    # 1. COR_PROFILER — loads an arbitrary DLL into EVERY .NET process on the machine.
    #    Phase 0 checks the engine's own environment; this is the machine-wide variant.
    try {
        $profSites = @(
            @{ Hive = 'LocalMachine'; Key = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; Label = 'HKLM machine environment' },
            @{ Hive = 'CurrentUser';  Key = 'Environment';                                                  Label = 'HKCU user environment' },
            @{ Hive = 'LocalMachine'; Key = 'SOFTWARE\Microsoft\.NETFramework';                             Label = 'HKLM .NETFramework' }
        )
        foreach ($ps in $profSites) {
            $enabled = Get-RegVal64 -Hive $ps.Hive -SubKey $ps.Key -Name 'COR_ENABLE_PROFILING'
            $clsid   = Get-RegVal64 -Hive $ps.Hive -SubKey $ps.Key -Name 'COR_PROFILER'
            $dll     = Get-RegVal64 -Hive $ps.Hive -SubKey $ps.Key -Name 'COR_PROFILER_PATH'
            if ($null -eq $dll) { $dll = Get-RegVal64 -Hive $ps.Hive -SubKey $ps.Key -Name 'CORECLR_PROFILER_PATH' }
            if ($null -eq $enabled -and $null -eq $clsid -and $null -eq $dll) { continue }
            # Explicitly DISABLED is not a finding. A profiler left behind by an uninstalled
            # APM agent sets COR_ENABLE_PROFILING=0 and nothing loads; reporting that as HIGH
            # is a false positive on every machine that ever had monitoring installed.
            if ($null -ne $enabled -and [int]$enabled -eq 0) { continue }
            # A CLSID with no path resolves to nothing, so the allowlist cannot apply and the
            # finding would name an empty file. Report only what can be pointed at.
            if ([string]::IsNullOrWhiteSpace("$dll")) { continue }
            $dllPath = Resolve-ScytheModulePath "$dll"
            if ($dllPath -and $dllPath -match $PERSIST_PROFILER_BENIGN_RE) {
                Out-Typewriter "  -> .NET PROFILER SET BY A KNOWN APM AGENT: $dllPath" "GOOD"
                continue
            }
            Out-Typewriter "  -> .NET PROFILER CONFIGURED IN $($ps.Label): $dllPath" "CRIT"
            Add-Finding -ID "PERS157_PROFILER_$([Math]::Abs("$($ps.Label)$dllPath".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence / Defense Evasion" -Severity $SEV_HIGH `
                -Description "A .NET profiler is configured in $($ps.Label) (COR_ENABLE_PROFILING=$enabled, COR_PROFILER=$clsid, path='$dllPath'). The CLR loads a profiler DLL into every managed process that starts while this is set, before any of that process's own code runs — so this is simultaneously persistence, privilege inheritance and injection into whatever managed service happens to launch next (MITRE T1574.012). It needs no service, no run key and no scheduled task, which is why nothing else in this scan finds it. The important benign case: application performance monitoring agents — AppDynamics, Dynatrace, New Relic, Datadog, Elastic, OpenTelemetry — set exactly this, machine-wide, on purpose, and this phase allowlists their install trees. If the path above is not one of those, resolve the DLL and check who signed it. Inspect with: Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' | Select-Object COR_*   and remove with Remove-ItemProperty on each COR_ value once you have confirmed no monitoring product owns it. Removing it takes effect for processes started afterwards; already-running processes keep the loaded profiler until they restart." `
                -Target "$($ps.Label)\COR_PROFILER" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: COR_PROFILER check failed - $($_.Exception.Message)" }

    # 3. SilentProcessExit MonitorProcess — persistence AND an LSASS-dumping primitive,
    #    because the monitor runs with the dying process's context available to it.
    try {
        $speRoot = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
        foreach ($tgt in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey $speRoot)) {
            $mon = Get-RegVal64 -Hive LocalMachine -SubKey "$speRoot\$tgt" -Name 'MonitorProcess'
            $rep = Get-RegVal64 -Hive LocalMachine -SubKey "$speRoot\$tgt" -Name 'ReportingMode'
            if ([string]::IsNullOrWhiteSpace("$mon") -and $null -eq $rep) { continue }
            Out-Typewriter "  -> SILENTPROCESSEXIT MONITOR ON '$tgt': $mon" "CRIT"
            Add-Finding -ID "PERS157_SPE_$([Math]::Abs("$tgt".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence / Credential Access" -Severity $SEV_HIGH `
                -Description "SilentProcessExit is configured for '$tgt' with MonitorProcess='$mon' (ReportingMode=$rep). Windows launches MonitorProcess whenever the named process exits unexpectedly, which gives an attacker two things at once: execution triggered by an event nobody watches, and — when the monitored process is lsass.exe and ReportingMode requests a dump — a full credential dump written by Windows Error Reporting itself, with no handle to LSASS ever opened by the attacker's code and therefore nothing for an EDR's LSASS-access rule to see (MITRE T1546.012, T1003.001). This key is essentially unused on a healthy workstation; almost any entry deserves an explanation. Read it with: Get-ItemProperty 'HKLM:\$speRoot\$tgt'   and, if unexplained, capture the whole subkey as evidence before removing it with: Remove-Item 'HKLM:\$speRoot\$tgt' -Recurse. If '$tgt' is lsass.exe, treat every credential on this machine as exposed and rotate accordingly." `
                -Target "HKLM\$speRoot\$tgt" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: SilentProcessExit check failed - $($_.Exception.Message)" }

    # 4. Windows Error Reporting debugger hooks — the sibling of IFEO, far less watched.
    try {
        $werSites = @(
            @{ Key = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting'; Name = 'ReflectDebugger' },
            @{ Key = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs'; Name = 'Debugger' }
            # Hangs\ReflectDebugger is deliberately absent: phase 126 covers exactly that
            # value. The two sites above are the ones it does not.
        )
        foreach ($ws in $werSites) {
            $dbg = Get-RegVal64 -Hive LocalMachine -SubKey $ws.Key -Name $ws.Name
            if ([string]::IsNullOrWhiteSpace("$dbg")) { continue }
            $dbgMod = Resolve-ScytheModulePath "$dbg"
            if (-not (Test-ScytheUntrustedModule $dbgMod)) { continue }
            Out-Typewriter "  -> WER $($ws.Name) HOOK: $dbg" "CRIT"
            Add-Finding -ID "PERS157_WER_$([Math]::Abs("$($ws.Key)$($ws.Name)".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence / Defense Evasion" -Severity $SEV_HIGH `
                -Description "Windows Error Reporting has $($ws.Name) = '$dbg', and that command does not resolve to a trusted-signed binary. WER launches this whenever an application crashes or hangs — the same execution primitive as an Image File Execution Options Debugger, on a key that almost nothing monitors and that no autostart viewer lists (MITRE T1546.012). An attacker who can also make a chosen process crash controls when it fires. The benign case is a real debugger: Visual Studio, WinDbg and some crash-reporting products register here legitimately, which is why this phase only reports a value whose target is missing or unsigned. Inspect with: Get-ItemProperty 'HKLM:\$($ws.Key)'   and remove with: Remove-ItemProperty 'HKLM:\$($ws.Key)' -Name '$($ws.Name)'   once you have confirmed no installed debugger owns it." `
                -Target "HKLM\$($ws.Key)\$($ws.Name)" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: WER debugger check failed - $($_.Exception.Message)" }

    # 5/6/7/8/9. The DLL-loading mechanisms. Same shape for all of them: enumerate the
    #    registered modules, resolve each to a file, and report the ones that are not
    #    trusted-signed. The mechanism existing is normal; an unsigned DLL in it is not.
    try {
        # Only the two sites phase 126 does NOT already cover. Its
        # extended_autostart_points key walks Netsh, Print\Monitors, W32Time\TimeProviders,
        # Active Setup, SCRNSAVE.EXE and the Winsock catalogue, and phase 126 runs whenever
        # HUNT runs ($PhasePlan.Extended is true for HUNT) — so duplicating them here produced
        # two findings with different IDs and different severities for one artifact, which
        # phase 160 would then correlate on the shared target as if it were two facts.
        $dllSites = @(
            @{ Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'; Sub = $false; Value = '';
               What = 'a delay-loaded shell service object'; Tag = 'SSODL';
               Why  = 'These CLSIDs are loaded into explorer.exe at every logon, in the interactive user context.' },
            @{ Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'; Sub = $false; Value = '';
               What = 'a SharedTaskScheduler entry'; Tag = 'STS';
               Why  = 'Loaded into explorer.exe at logon. Legacy, still honoured, and absent from every modern autostart listing.' }
        )
        foreach ($ds in $dllSites) {
            $entries = @()
            if ($ds.Sub) {
                foreach ($sk in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey $ds.Key)) {
                    $dv = Get-RegVal64 -Hive LocalMachine -SubKey "$($ds.Key)\$sk" -Name $ds.Value
                    if ("$dv") { $entries += @{ Name = $sk; Value = "$dv" } }
                }
            } else {
                foreach ($vn in @(Get-RegNames64 -Hive LocalMachine -SubKey $ds.Key)) {
                    $dv = Get-RegVal64 -Hive LocalMachine -SubKey $ds.Key -Name $vn
                    if ("$dv") { $entries += @{ Name = $vn; Value = "$dv" } }
                }
            }
            foreach ($en in $entries) {
                $mod = Resolve-ScytheModulePath "$($en.Value)"
                # A CLSID-valued entry (SSODL / SharedTaskScheduler) is not a path; resolve
                # it through InprocServer32 before judging it.
                if ("$($en.Value)" -match '^\{[0-9A-Fa-f-]{30,40}\}$' -or "$($en.Name)" -match '^\{[0-9A-Fa-f-]{30,40}\}$') {
                    $clsidKey = if ("$($en.Value)" -match '^\{') { "$($en.Value)" } else { "$($en.Name)" }
                    $inproc = Get-RegVal64 -Hive ClassesRoot -SubKey "CLSID\$clsidKey\InprocServer32" -Name ''
                    if ("$inproc") { $mod = Resolve-ScytheModulePath "$inproc" }
                }
                if (-not (Test-ScytheUntrustedModule $mod)) { continue }
                Out-Typewriter "  -> UNTRUSTED $($ds.Tag) MODULE: $($en.Name) -> $mod" "CRIT"
                Add-Finding -ID "PERS157_$($ds.Tag)_$([Math]::Abs("$($en.Name)$mod".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                    -ThreatType "Persistence / Hijack Execution Flow" -Severity $SEV_HIGH `
                    -Description "'$($en.Name)' registers $($ds.What) that resolves to '$mod', which is missing or is not trusted-signed. $($ds.Why) The registration itself is a normal Windows facility with legitimate users, so the signature verdict — not the mechanism — is the finding here; a signed vendor module in this slot is expected and this phase allowlists the security and virtualisation vendors that ship them. Confirm the module: Get-AuthenticodeSignature '$mod' | Format-List Status, SignerCertificate   and check when it appeared: Get-Item '$mod' | Format-List CreationTime, LastWriteTime. If it is unexplained, capture both the file and the registry key as evidence before removing the registration under 'HKLM\$($ds.Key)'. Do not simply delete the DLL while the registration remains — a missing module here can leave the spooler or Explorer failing on every start." `
                    -Target "HKLM\$($ds.Key)\$($en.Name)" -FixAction "Info" -Group "Persistence Surface"
            }
        }
    } catch { Write-Log "PHASE 157: DLL-loading mechanism sweep failed - $($_.Exception.Message)" }

    # 8b. Winsock LSP catalogue and AutodialDLL — both inject into networked processes.
    try {
        $wsParams = 'SYSTEM\CurrentControlSet\Services\WinSock2\Parameters'
        $autodial = Get-RegVal64 -Hive LocalMachine -SubKey $wsParams -Name 'AutodialDLL'
        $autoMod  = Resolve-ScytheModulePath "$autodial"
        $stockAutodial = Join-Path $global:SCYTHE_SYS32 'rasadhlp.dll'
        if ("$autodial" -and $autoMod -and ($autoMod -ne $stockAutodial) -and (Test-ScytheUntrustedModule $autoMod)) {
            Out-Typewriter "  -> AUTODIALDLL REPLACED: $autodial" "CRIT"
            Add-Finding -ID "PERS157_AUTODIAL" -Phase "PHASE 157" `
                -ThreatType "Persistence / Hijack Execution Flow" -Severity $SEV_HIGH `
                -Description "AutodialDLL is set to '$autodial' rather than the stock '$stockAutodial'. Windows loads this DLL into any process that makes a WinINet call and finds no connection — which on a normal desktop means it is loaded into browsers, updaters, Office and most management agents, in their own context (MITRE T1546). It has no legitimate third-party use that this project has seen. Confirm the current value with: Get-ItemProperty 'HKLM:\$wsParams' -Name AutodialDLL   and restore it with: Set-ItemProperty 'HKLM:\$wsParams' -Name AutodialDLL -Value '$stockAutodial'. Preserve the replacement DLL as evidence first — it is the payload, and its signature and compile timestamp are what date the intrusion." `
                -Target "HKLM\$wsParams\AutodialDLL" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: Winsock check failed - $($_.Exception.Message)" }

    # 10/11. Two single-value hijacks: the screen saver and the RDP initial program.
    try {
        $rdpKey = 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $initProg = Get-RegVal64 -Hive LocalMachine -SubKey $rdpKey -Name 'InitialProgram'
        $initMod  = Resolve-ScytheModulePath "$initProg"
        # Gated on the signature verdict like every other branch in this phase. Published-
        # application and kiosk deployments set InitialProgram deliberately, and on an RDS
        # session host an ungated check fires on every scan — which teaches operators to
        # ignore the phase.
        if ((-not [string]::IsNullOrWhiteSpace("$initProg")) -and (Test-ScytheUntrustedModule $initMod)) {
            Out-Typewriter "  -> RDP INITIALPROGRAM SET: $initProg" "CRIT"
            Add-Finding -ID "PERS157_RDPINIT" -Phase "PHASE 157" `
                -ThreatType "Persistence" -Severity $SEV_HIGH `
                -Description "The RDP listener has InitialProgram = '$initProg'. This command runs on EVERY remote desktop logon to this host, in the connecting user's session, before their shell. On a managed endpoint that means it fires whenever a technician connects — including the technician sent to investigate the machine. The value is empty on a stock Windows installation; a small number of kiosk and published-application deployments set it deliberately, and that is the benign case to rule out. Read the whole listener configuration with: Get-ItemProperty 'HKLM:\$rdpKey' | Select-Object InitialProgram, WorkDirectory, fInheritInitialProgram   and clear it with: Set-ItemProperty 'HKLM:\$rdpKey' -Name InitialProgram -Value ''   after recording the current value. Check the matching per-user Terminal Services profile settings too — the same override exists in Active Directory user properties." `
                -Target "HKLM\$rdpKey\InitialProgram" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: screen saver / RDP check failed - $($_.Exception.Message)" }

    # 12. A service that reads as disabled but starts on an event. This is the one that
    #     defeats the "I checked, the service is disabled" conclusion.
    try {
        $svcRoot = 'SYSTEM\CurrentControlSet\Services'
        $trigCount = 0
        foreach ($svc in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey $svcRoot)) {
            $start = Get-RegVal64 -Hive LocalMachine -SubKey "$svcRoot\$svc" -Name 'Start'
            if ($null -eq $start -or [int]$start -ne 4) { continue }
            $trig = @(Get-RegSubKeys64 -Hive LocalMachine -SubKey "$svcRoot\$svc\TriggerInfo")
            if ($trig.Count -eq 0) { continue }
            if ("$svc" -match $PERSIST_TRIGGER_BENIGN_RE) { continue }
            $img = Get-RegVal64 -Hive LocalMachine -SubKey "$svcRoot\$svc" -Name 'ImagePath'
            $trigCount++
            Out-Typewriter "  -> DISABLED SERVICE WITH START TRIGGERS: $svc" "WARN"
            Add-Finding -ID "PERS157_TRIGGER_$([Math]::Abs("$svc".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence / Defense Evasion" -Severity $SEV_POSSIBLE `
                -Description "Service '$svc' has Start=4 (Disabled) but carries $($trig.Count) TriggerInfo subkey(s). ImagePath: '$img'. A trigger-started service runs when its registered event occurs — a device arriving, an IP address appearing, a firewall port opening, an ETW event firing — regardless of what the Start value says, and the Services console displays it as Disabled the whole time. That is why this matters: 'I checked, the service is disabled' is a conclusion this configuration is specifically able to defeat. Windows itself ships several demand-start services in this shape and this phase allowlists the ones seen on stock and domain-managed builds, so treat this as a prompt to identify the service rather than as a detection. List the triggers with: sc.exe qtriggerinfo '$svc'   and inspect the image with: Get-AuthenticodeSignature '$img'. If the service is not recognised, delete the triggers with: sc.exe triggerinfo '$svc' delete   before deciding what to do with the service itself." `
                -Target "HKLM\$svcRoot\$svc\TriggerInfo" -FixAction "Info" -Group "Persistence Surface"
        }
        if ($trigCount -eq 0) { Out-Typewriter "  -> NO DISABLED-BUT-TRIGGERED SERVICES." "GOOD" }
    } catch { Write-Log "PHASE 157: service trigger check failed - $($_.Exception.Message)" }

    if ($global:SCYTHE_P157_SIGSKIPPED -gt 0) {
        Out-Typewriter "  -> SIGNATURE BUDGET REACHED - $($global:SCYTHE_P157_SIGSKIPPED) MODULE(S) NOT VERIFIED." "WARN"
        Add-Finding -ID "PERS157_SIGBUDGET" -Phase "PHASE 157" `
            -ThreatType "Coverage" -Severity $SEV_INFO `
            -Description "Phase 157 verified $($global:SCYTHE_P157_SIGSEEN) module signature(s) and then reached its budget, leaving $($global:SCYTHE_P157_SIGSKIPPED) module(s) UNVERIFIED. Those were not reported, so their absence from this report means 'not checked', not 'clean'. The budget exists because Authenticode verification builds the full certificate chain, which by default performs online revocation checks - on a machine whose network is slow, filtered, or (very much the point of this tool) actively tampered with, each call blocks for the timeout and an unbounded loop here would run for many minutes. If this machine is under active investigation, re-run the scan once name resolution and outbound HTTP are known good, or verify the remaining modules by hand from the persistence keys this phase enumerates." `
            -Target "Phase157Coverage" -FixAction "Info" -Group "Persistence Surface"
    }

    # 13. Shell file types that execute or coerce authentication when merely rendered.
    try {
        $dropRoots = @(@($env:TEMP, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:APPDATA\Microsoft\Windows\Start Menu") |
                       Where-Object { $_ -and (Test-Path -LiteralPath $_) })
        if ($dropRoots.Count -gt 0) {
            $dropFiles = @(Get-ScanFiles -Path $dropRoots -MaxFiles 6000 -DeadlineSecs 12)
            foreach ($df in $dropFiles) {
                if ($PERSIST_DROPPER_EXTS -notcontains "$($df.Extension)".ToLower()) { continue }
                $dfPath = "$($df.FullName)"
                $dhit = Test-ContentRules -FilePath $dfPath -Rules $PERSIST_DROPPER_RULES -MaxBytes 262144
                if (-not $dhit.Hit) { continue }
                Out-Typewriter "  -> SHELL DROPPER FILE: $dfPath ($($dhit.Name))" "CRIT"
                Add-Finding -ID "PERS157_DROPPER_$([Math]::Abs($dfPath.ToLower().GetHashCode()))" -Phase "PHASE 157" `
                    -ThreatType "Initial Access / Execution" -Severity $SEV_HIGH `
                    -Description "'$dfPath' is a $($df.Extension) shell file whose content matches '$($dhit.Name)'. These file types are plain text, are not treated as executables by mail gateways or by the mark-of-the-web prompt, and act when the file is opened — or, for .settingcontent-ms and .library-ms, when Explorer merely renders the folder containing it. Two techniques appear here: a DeepLink or URL pointing at an executable or a script host, which is direct execution (MITRE T1204.002); and an IconFile or url pointing at a UNC path, which makes Explorer authenticate to an attacker-controlled host and hand over a net-NTLMv2 response with no user interaction at all (MITRE T1187). Open it in a text editor — it is short and readable — and look at the target. The benign case is a legitimate shortcut to an internal file server, which is why the UNC rules do not distinguish a hostile host from a corporate one; check whether the server name is yours. Preserve the file as evidence, then delete it and check the browser or mail history for where it came from." `
                    -Target $dfPath -FixAction "Info" -Group "Persistence Surface"
            }
        }
    } catch { Write-Log "PHASE 157: shell dropper sweep failed - $($_.Exception.Message)" }

    # 14. AppDomainManager via a .config sidecar. Phase 95 covers the registry route only;
    #     the sidecar route needs no registry write at all, just a file next to the exe.
    try {
        $admRoots = @(@($env:TEMP, "$env:USERPROFILE\Downloads", "$env:APPDATA", "$env:LOCALAPPDATA", "$env:ProgramData") |
                      Where-Object { $_ -and (Test-Path -LiteralPath $_) })
        if ($admRoots.Count -gt 0) {
            $cfgFiles = @(Get-ScanFiles -Path $admRoots -Filter '*.config' -MaxFiles 6000 -DeadlineSecs 12)
            foreach ($cf in $cfgFiles) {
                if ("$($cf.Name)" -notmatch '(?i)\.exe\.config$') { continue }
                $cfPath = "$($cf.FullName)"
                $cfText = ''
                try { if ($cf.Length -lt 262144) { $cfText = [System.IO.File]::ReadAllText($cfPath) } } catch { $cfText = '' }
                if ($cfText -notmatch '(?i)appDomainManager(Assembly|Type)') { continue }
                Out-Typewriter "  -> APPDOMAINMANAGER SIDECAR: $cfPath" "CRIT"
                Add-Finding -ID "PERS157_ADM_$([Math]::Abs($cfPath.ToLower().GetHashCode()))" -Phase "PHASE 157" `
                    -ThreatType "Persistence / Hijack Execution Flow" -Severity $SEV_HIGH `
                    -Description "'$cfPath' declares an appDomainManagerAssembly or appDomainManagerType. A .NET application configuration file sitting next to a managed executable can name an assembly that the CLR loads and executes BEFORE the application's own entry point, in that application's identity and with its signature intact — the executable is untouched and still verifies, so a signature check on the binary tells you nothing (MITRE T1574.014). Phase 95 covers the registry route to the same technique; this is the sidecar route, which needs no registry write at all. Legitimate uses exist but are rare outside enterprise .NET applications with custom hosting. Read the file — it is XML and short — and identify the named assembly, then check where that assembly is and who signed it. Preserve both files as evidence before removing the configuration element." `
                    -Target $cfPath -FixAction "Info" -Group "Persistence Surface"
            }
        }
    } catch { Write-Log "PHASE 157: AppDomainManager sidecar sweep failed - $($_.Exception.Message)" }


    # ── PHASE 158: SUPPLY CHAIN AND DEVELOPER TOOLING ─────────────────────────
    # Untouched by all 133 earlier phases, and on a developer or technician workstation
    # it is the softest surface in the building — it is also how an MSP gets hit THROUGH
    # its own staff. An editor extension, a git hook or a weaponised .gitconfig runs
    # arbitrary code on an ordinary, unremarkable action and appears in no autostart list.
    #
    # The false-positive problem IS this phase. A developer box has thousands of these
    # files legitimately, so almost everything here is INFO and escalates only on a
    # concrete malicious construct — an encoded command, a downloader, a raw-IP URL, a
    # pipe into a shell. A stock .git\hooks directory of .sample files and a normal
    # VS Code install must produce zero findings; the test suite asserts exactly that.
    #
    # The typosquat check named in the original brief is deliberately NOT implemented.
    # It needs a curated list of very-popular package names to be meaningful, that list
    # is a standing maintenance commitment this project has not made, and a stale one
    # produces confident false accusations about a developer's own dependencies.
    Show-PhaseHeader "PHASE 158" "EDITOR EXTENSIONS, GIT HOOKS AND PACKAGE TOOLING" "SUPPLY CHAIN"
    Out-Typewriter "AUDITING DEVELOPER TOOLING FOR EXECUTION ON ORDINARY ACTIONS..." "HUNT"

    # (a) Editor extensions. An extension runs arbitrary code at editor startup, can be
    #     sideloaded from a .vsix with no signature requirement, and nobody audits them.
    try {
        $extRoots = @(@($DEVTOOL_PATHS) | Where-Object { $_ -match '(?i)extensions$' -and (Test-Path -LiteralPath $_) })
        foreach ($er in $extRoots) {
            $extDirs = @()
            try { $extDirs = @(Get-ChildItem -LiteralPath $er -Directory -ErrorAction Stop) } catch { $extDirs = @() }
            foreach ($ed in $extDirs) {
                $pkg = Join-Path $ed.FullName 'package.json'
                if (-not (Test-Path -LiteralPath $pkg)) { continue }
                if ($pkg -match $DEVTOOL_BENIGN_RE) { continue }
                $startHit = Test-ContentRules -FilePath $pkg -Rules $DEVTOOL_STARTUP_RULES -MaxBytes 1048576
                $hookHit  = Test-ContentRules -FilePath $pkg -Rules $DEVTOOL_HOOK_RULES    -MaxBytes 1048576
                # The extension's own entry bundle, checked against the EXISTING webhook/C2
                # rule set (phase 130's) rather than a second copy of it. One file per
                # extension and size-capped on purpose: these bundles are minified and can
                # be megabytes each, and reading every file of every extension is a
                # wall-clock problem with no extra detection in it.
                $extMain = ''
                try {
                    $pkgObj = Get-Content -LiteralPath $pkg -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ("$($pkgObj.main)") { $extMain = Join-Path $ed.FullName ("$($pkgObj.main)".Replace('/','\')) }
                } catch { $extMain = '' }
                if ($extMain -and (Test-Path -LiteralPath $extMain) -and -not ($extMain -match $WEBHOOK_BENIGN_RE)) {
                    $whHit = Test-ContentRules -FilePath $extMain -Rules $WEBHOOK_C2_RULES -MaxBytes 4194304
                    if ($whHit.Hit) {
                        Out-Typewriter "  -> EXTENSION BUNDLE CARRIES A CHAT-WEBHOOK C2 URL: $extMain" "CRIT"
                        Add-Finding -ID "SUPPLY158_EXTC2_$([Math]::Abs("$extMain".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                            -ThreatType "Supply Chain / Command and Control" -Severity $SEV_HIGH `
                            -Description "The entry bundle of editor extension '$($ed.Name)' — '$extMain' — contains a URL matching '$($whHit.Name)'. A chat-platform webhook is command-and-control that needs no attacker infrastructure at all: the endpoint is a legitimate, TLS-protected, generally-allowed service, so the traffic passes egress filtering and reputation checks that would stop a purpose-built C2 domain. Inside an editor extension it is also perfectly placed — the extension already has the developer's source tree, their tokens, and their terminal. The benign case is genuine and needs ruling out: an extension that legitimately posts notifications to Slack, Discord or Teams, and any extension that merely documents a webhook in a sample. Read the surrounding code: Select-String -Path '$extMain' -Pattern 'https' -SimpleMatch | Select-Object -First 20. If the extension has no reason to talk to a chat platform, uninstall it, then treat every credential this developer holds as exposed — see phase 147 for what that means in practice." `
                            -Target $extMain -FixAction "Info" -Group "Supply Chain"
                    }
                }
                if (-not $hookHit.Hit) { continue }
                $extSev = switch ("$($hookHit.Severity)") { 'CRITICAL' { $SEV_CRITICAL } 'HIGH' { $SEV_HIGH } default { $SEV_POSSIBLE } }
                $startNote = if ($startHit.Hit) { "It also activates at editor startup ($($startHit.Name)), so it runs whether or not the user opens a matching file." } else { "Its declared activation events are narrower than startup, so it runs only for matching files." }
                Out-Typewriter "  -> EXTENSION MANIFEST MATCHES '$($hookHit.Name)': $($ed.Name)" "CRIT"
                Add-Finding -ID "SUPPLY158_EXT_$([Math]::Abs("$($ed.FullName)".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                    -ThreatType "Supply Chain / Execution" -Severity $extSev `
                    -Description "Editor extension '$($ed.Name)' has a package.json matching '$($hookHit.Name)'. $startNote Extensions execute with the full rights of the user running the editor, are installed from a marketplace with limited review, and can be sideloaded from a .vsix with no signature requirement at all — so this is a genuine code-execution surface that no autostart listing shows. The honest false-positive case is large: many legitimate extensions shell out, spawn child processes, or fetch data over HTTP as part of their normal job (linters, language servers, container and cloud tooling all do). Read the manifest yourself: Get-Content '$pkg'   then look at what the extension actually ships in its out or dist directory. Check the publisher against the marketplace listing, and check the install date — an extension that appeared without the user installing it is the finding. Remove with: code --uninstall-extension <publisher.name>" `
                    -Target "$($ed.FullName)" -FixAction "Info" -Group "Supply Chain"
            }
        }
    } catch { Write-Log "PHASE 158: extension sweep failed - $($_.Exception.Message)" }

    # (b) Repository-local execution: .vscode/tasks.json runOn folderOpen, git hooks,
    #     package install scripts and MSBuild inline tasks. Repository roots are found
    #     from a fixed shallow list of developer directories, never a profile walk.
    try {
        $repoRoots = @(Get-ScytheRepoRoots)
        if ($repoRoots.Count -eq 0) {
            Out-Typewriter "  -> NO LOCAL REPOSITORIES FOUND IN THE USUAL DEVELOPER DIRECTORIES." "GOOD"
        }
        foreach ($repo in $repoRoots) {
            # .vscode/tasks.json — opening the repository is enough to execute this.
            $tasksJson = Join-Path $repo '.vscode\tasks.json'
            if (Test-Path -LiteralPath $tasksJson) {
                $tStart = Test-ContentRules -FilePath $tasksJson -Rules $DEVTOOL_STARTUP_RULES -MaxBytes 262144
                $tHook  = Test-ContentRules -FilePath $tasksJson -Rules $DEVTOOL_HOOK_RULES    -MaxBytes 262144
                if ($tStart.Hit -or $tHook.Hit) {
                    $tSev = if ($tHook.Hit) { switch ("$($tHook.Severity)") { 'CRITICAL' { $SEV_CRITICAL } 'HIGH' { $SEV_HIGH } default { $SEV_POSSIBLE } } } else { $SEV_POSSIBLE }
                    $tWhat = if ($tHook.Hit) { "$($tHook.Name)" } else { "$($tStart.Name)" }
                    Out-Typewriter "  -> REPOSITORY TASK RUNS ON OPEN: $tasksJson" "CRIT"
                    Add-Finding -ID "SUPPLY158_TASK_$([Math]::Abs($tasksJson.ToLower().GetHashCode()))" -Phase "PHASE 158" `
                        -ThreatType "Supply Chain / Execution" -Severity $tSev `
                        -Description "'$tasksJson' matches '$tWhat'. A task configured with runOn folderOpen executes when the repository is merely OPENED in the editor — no build, no debug, no user action beyond browsing to a folder. That makes a cloned repository a drive-by on a developer box, and it is a documented technique for exactly that (MITRE T1204.002). The benign case is real and common: many projects legitimately use folderOpen tasks to start a watcher, a dev server or a container. What separates them is the command. Read it: Get-Content '$tasksJson'. If the command downloads anything, decodes a blob, pipes into a shell, or references a raw IP address, treat the repository as hostile and do not open it again — check the clone URL and who suggested it." `
                        -Target $tasksJson -FixAction "Info" -Group "Supply Chain"
                }
            }
            # .git/hooks — a stock directory holds only .sample files and is silent here.
            $hookDir = Join-Path $repo '.git\hooks'
            if (Test-Path -LiteralPath $hookDir) {
                $hookFiles = @()
                try { $hookFiles = @(Get-ChildItem -LiteralPath $hookDir -File -ErrorAction Stop) } catch { $hookFiles = @() }
                foreach ($hf in $hookFiles) {
                    if ("$($hf.Name)" -match '(?i)\.sample$') { continue }
                    $hfPath = "$($hf.FullName)"
                    $hHit = Test-ContentRules -FilePath $hfPath -Rules $DEVTOOL_HOOK_RULES -MaxBytes 262144
                    if (-not $hHit.Hit) { continue }
                    $hSev = switch ("$($hHit.Severity)") { 'CRITICAL' { $SEV_CRITICAL } 'HIGH' { $SEV_HIGH } default { $SEV_POSSIBLE } }
                    Out-Typewriter "  -> GIT HOOK MATCHES '$($hHit.Name)': $hfPath" "CRIT"
                    Add-Finding -ID "SUPPLY158_HOOK_$([Math]::Abs($hfPath.ToLower().GetHashCode()))" -Phase "PHASE 158" `
                        -ThreatType "Supply Chain / Execution" -Severity $hSev `
                        -Description "Git hook '$($hf.Name)' in '$repo' matches '$($hHit.Name)'. Hooks execute on ordinary developer actions and nothing announces them: post-checkout and post-merge fire on git checkout and git pull, pre-commit on every commit. A hook is not transferred by git clone, so one that exists here was installed locally — by the developer, by a tool such as Husky or pre-commit, or by something else. That last case is the finding. The benign case dominates on a real developer machine and this phase is scoped to it deliberately: a stock .git\hooks directory contains only .sample files and produces nothing here. Read the hook: Get-Content '$hfPath'. Check whether a hook manager owns it — a Husky hook references .husky, a pre-commit hook references the pre-commit framework. If nothing explains it, preserve it as evidence and delete it; then check every other clone on this machine, because a hook installer usually visits more than one." `
                        -Target $hfPath -FixAction "Info" -Group "Supply Chain"
                }
            }
            # package.json install scripts — preinstall/postinstall run on npm install.
            $pkgJson = Join-Path $repo 'package.json'
            if (Test-Path -LiteralPath $pkgJson) {
                $pText = ''
                try { $pText = [System.IO.File]::ReadAllText($pkgJson) } catch { $pText = '' }
                if ($pText -match '(?i)"(preinstall|postinstall|prepare)"\s{0,4}:') {
                    $pHit = Test-ScytheTextRules -Text $pText -Rules $DEVTOOL_HOOK_RULES
                    if ($null -ne $pHit) {
                        $pSev = switch ("$($pHit.Severity)") { 'CRITICAL' { $SEV_CRITICAL } 'HIGH' { $SEV_HIGH } default { $SEV_POSSIBLE } }
                        Out-Typewriter "  -> INSTALL SCRIPT MATCHES '$($pHit.Name)': $pkgJson" "CRIT"
                        Add-Finding -ID "SUPPLY158_NPM_$([Math]::Abs($pkgJson.ToLower().GetHashCode()))" -Phase "PHASE 158" `
                            -ThreatType "Supply Chain / Execution" -Severity $pSev `
                            -Description "'$pkgJson' declares an install script and its content matches '$($pHit.Name)'. npm runs preinstall, postinstall and prepare automatically during npm install — the developer types one command and arbitrary code from the package tree executes, which is the delivery mechanism behind most published npm compromises (MITRE T1195.001). Legitimate install scripts are extremely common: native modules compile, tools install binaries, husky installs hooks. The rule that matched is what to look at, not the presence of the script. Read it: Get-Content '$pkgJson'. If it fetches from a URL, decodes a blob or pipes into a shell, do not run npm install in this repository; check the package against the registry, and check whether node_modules already contains the result of a previous install." `
                            -Target $pkgJson -FixAction "Info" -Group "Supply Chain"
                    }
                }
            }
            # MSBuild inline tasks — <UsingTask> with an inline <Code> block compiles and
            # runs C# during an ordinary build.
            $projFiles = @()
            try { $projFiles = @(Get-ChildItem -LiteralPath $repo -File -ErrorAction Stop | Where-Object { "$($_.Extension)" -match '(?i)^\.(csproj|vbproj|targets|props)$' }) } catch { $projFiles = @() }
            foreach ($pf in $projFiles) {
                $pfPath = "$($pf.FullName)"
                $pfText = ''
                try { if ($pf.Length -lt 1048576) { $pfText = [System.IO.File]::ReadAllText($pfPath) } } catch { $pfText = '' }
                if ($pfText -notmatch '(?i)<UsingTask') { continue }
                if ($pfText -notmatch '(?i)<Code\b') { continue }
                Out-Typewriter "  -> MSBUILD INLINE TASK: $pfPath" "WARN"
                Add-Finding -ID "SUPPLY158_MSBUILD_$([Math]::Abs($pfPath.ToLower().GetHashCode()))" -Phase "PHASE 158" `
                    -ThreatType "Supply Chain / Execution" -Severity $SEV_POSSIBLE `
                    -Description "'$pfPath' contains a UsingTask with an inline Code block. MSBuild compiles and executes that code during an ordinary build, in the developer's context, using a Microsoft-signed host binary — which is why msbuild.exe is a standard application-allowlisting bypass and why this shape is worth reading (MITRE T1127.001). It is also a completely legitimate MSBuild feature that build systems use routinely. Read the Code block: Get-Content '$pfPath'. Judge it on what it does — a build-time code generator or version stamper is normal; anything that reaches the network, touches the registry, or writes outside the build output is not, in a project file." `
                    -Target $pfPath -FixAction "Info" -Group "Supply Chain"
            }
        }
    } catch { Write-Log "PHASE 158: repository sweep failed - $($_.Exception.Message)" }

    # (c) Weaponised git configuration. core.fsmonitor is the important one: it fires on
    #     EVERY git command, so it is persistence that triggers dozens of times a day.
    try {
        $gitConfigs = @(@($DEVTOOL_PATHS) | Where-Object { $_ -match '(?i)(\.gitconfig|\\git\\config)$' -and (Test-Path -LiteralPath $_) })
        foreach ($repo in @(Get-ScytheRepoRoots)) {
            $rc = Join-Path $repo '.git\config'
            if (Test-Path -LiteralPath $rc) { $gitConfigs += $rc }
        }
        foreach ($gc in @($gitConfigs | Sort-Object -Unique)) {
            $gHit = Test-ContentRules -FilePath $gc -Rules $DEVTOOL_GITCONFIG_RULES -MaxBytes 262144
            if (-not $gHit.Hit) { continue }
            $gCmd = Test-ContentRules -FilePath $gc -Rules $DEVTOOL_HOOK_RULES -MaxBytes 262144
            $gSev = if ($gCmd.Hit -and "$($gCmd.Severity)" -eq 'HIGH') { $SEV_HIGH } elseif ("$($gHit.Severity)" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
            $gExtra = if ($gCmd.Hit) { " Its command content additionally matches '$($gCmd.Name)', which is what raises this above routine configuration." } else { "" }
            Out-Typewriter "  -> GIT CONFIG EXECUTES A COMMAND ('$($gHit.Name)'): $gc" "WARN"
            Add-Finding -ID "SUPPLY158_GITCFG_$([Math]::Abs("$gc".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                -ThreatType "Supply Chain / Persistence" -Severity $gSev `
                -Description "'$gc' matches '$($gHit.Name)'.$gExtra Several git configuration keys execute a command during ordinary operations: core.fsmonitor runs on EVERY git command, core.sshCommand on every fetch and push, diff textconv on every diff of a matching file, and filter clean/smudge on every checkout and commit of one. An alias beginning with ! is a shell command. So a weaponised git config is persistence that fires dozens of times a day, in the developer's context, and appears in no autostart listing (MITRE T1546). The benign case is ordinary: Git LFS installs clean and smudge filters, delta and diff-so-fancy install a pager, corporate setups set sshCommand, and Scalar and VFS for Git set fsmonitor. Read the file — it is short: Get-Content '$gc'. Identify the tool that owns each entry. Anything you cannot attribute, remove with: git config --global --unset <key>   (or --unset for a repository-local one), and check whether the same entry exists in the other config scopes: git config --list --show-origin" `
                -Target $gc -FixAction "Info" -Group "Supply Chain"
        }
    } catch { Write-Log "PHASE 158: git config check failed - $($_.Exception.Message)" }

    # (d) Package-registry redirection. An override here silently reroutes every install.
    try {
        $regFiles = @(@($DEVTOOL_PATHS) | Where-Object { $_ -match '(?i)(\.npmrc|NuGet\.Config)$' -and (Test-Path -LiteralPath $_) })
        foreach ($repo in @(Get-ScytheRepoRoots)) {
            foreach ($rn in @('.npmrc','NuGet.Config','nuget.config')) {
                $rp = Join-Path $repo $rn
                if (Test-Path -LiteralPath $rp) { $regFiles += $rp }
            }
        }
        foreach ($rf in @($regFiles | Sort-Object -Unique)) {
            $rHit = Test-ContentRules -FilePath $rf -Rules $DEVTOOL_REGISTRY_RULES -MaxBytes 262144
            if (-not $rHit.Hit) { continue }
            $rSev = switch ("$($rHit.Severity)") { 'CRITICAL' { $SEV_CRITICAL } 'HIGH' { $SEV_HIGH } default { $SEV_POSSIBLE } }
            Out-Typewriter "  -> PACKAGE REGISTRY OVERRIDE ('$($rHit.Name)'): $rf" "WARN"
            Add-Finding -ID "SUPPLY158_REGISTRY_$([Math]::Abs("$rf".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                -ThreatType "Supply Chain" -Severity $rSev `
                -Description "'$rf' matches '$($rHit.Name)' — it points package installs at a registry other than the vendor default, or over plain HTTP. Every dependency this machine installs then comes from that host, including transitive ones the developer never named, which is the delivery half of a dependency-confusion or registry-hijack attack (MITRE T1195.001). The benign case is the common one in an MSP context: a corporate Artifactory, Nexus, Azure Artifacts or GitHub Packages feed, or a scoped registry for internal packages. Verify the host is one of yours. Read it: Get-Content '$rf'   and cross-check the effective configuration with: npm config list   or   dotnet nuget list source. A plain-HTTP feed is worth fixing regardless of who owns it — it is trivially interceptable on a shared network, and this machine's network posture is what phases 153-156 just measured." `
                -Target $rf -FixAction "Info" -Group "Supply Chain"
        }
    } catch { Write-Log "PHASE 158: package registry check failed - $($_.Exception.Message)" }

    # (e) Jupyter kernel specs. argv[0] is what the notebook server actually launches.
    try {
        $kernelRoots = @(@($DEVTOOL_PATHS) | Where-Object { $_ -match '(?i)\\kernels$' -and (Test-Path -LiteralPath $_) })
        foreach ($kr in $kernelRoots) {
            $kdirs = @()
            try { $kdirs = @(Get-ChildItem -LiteralPath $kr -Directory -ErrorAction Stop) } catch { $kdirs = @() }
            foreach ($kd in $kdirs) {
                $kj = Join-Path $kd.FullName 'kernel.json'
                if (-not (Test-Path -LiteralPath $kj)) { continue }
                $kHit = Test-ContentRules -FilePath $kj -Rules $DEVTOOL_HOOK_RULES -MaxBytes 262144
                if (-not $kHit.Hit) { continue }
                Out-Typewriter "  -> JUPYTER KERNEL SPEC MATCHES '$($kHit.Name)': $kj" "CRIT"
                Add-Finding -ID "SUPPLY158_KERNEL_$([Math]::Abs("$kj".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                    -ThreatType "Supply Chain / Execution" -Severity $SEV_HIGH `
                    -Description "Jupyter kernel spec '$kj' matches '$($kHit.Name)'. The argv array in a kernel spec is the exact command the notebook server launches when a user selects that kernel — so replacing or adding one gives execution on an action the user reads as 'open a notebook', with no notebook content required. A kernel spec is a small JSON file in a per-user directory that nothing audits. The benign case: a kernel spec legitimately names a Python or Conda interpreter path, sometimes through a wrapper script. Read it: Get-Content '$kj'   and confirm argv[0] is an interpreter you expect. List all of them with: jupyter kernelspec list   and remove an unrecognised one with: jupyter kernelspec remove <name>" `
                    -Target $kj -FixAction "Info" -Group "Supply Chain"
            }
        }
    } catch { Write-Log "PHASE 158: jupyter kernel check failed - $($_.Exception.Message)" }


    # ── PHASE 159: UEFI / ESP INTEGRITY ───────────────────────────────────────
    # Phase 58 covers the MBR and phase 40 covers the BCD signing flags. Nothing until
    # now looked at the EFI System Partition, which is where a modern bootkit lives: it
    # is FAT32, so it carries no NTFS ACLs once mounted, it is excluded from most backup
    # and AV coverage, and code there runs before Windows — and therefore before every
    # other detection in this tool.
    #
    # THIS PHASE DOES NOT MOUNT THE ESP, and no switch is provided to make it. The
    # original F7 brief said to mount it read-only and unmount in a finally. That was
    # dropped for the same reason the F6 LAN band became host-side (see the banner at the
    # top of this file): Scythe runs on client machines under an MSP contract, assigning
    # and removing a system partition's access path is a live change to the boot volume's
    # mount state, and "leave nothing behind on a client machine" is a standing rule here
    # (audit M5/M9/M10). If the ESP already has an access path this phase reads it; if it
    # does not, it says so and hands the operator the exact commands. Everything else
    # below — Secure Boot, dbx currency, the BCD flags — is answerable without mounting
    # anything, which is most of the value.
    Show-PhaseHeader "PHASE 159" "SECURE BOOT, REVOCATION CURRENCY AND THE EFI PARTITION" "BOOT INTEGRITY"
    Out-Typewriter "READING FIRMWARE AND BOOT-CHAIN STATE..." "HUNT"

    # Firmware type first. Confirm-SecureBootUEFI THROWS on a legacy BIOS machine rather
    # than returning false, so the whole phase has to degrade cleanly on one.
    $sbState = $null
    $isUefi  = $true
    $sbError = ''
    try { $sbState = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    catch { $sbState = $null; $sbError = "$($_.Exception.Message)"; $isUefi = $false }
    # Confirm-SecureBootUEFI throws on a legacy-BIOS machine — but it also throws when the
    # cmdlet is unavailable, the module is blocked, or WMI is broken. Those are different
    # facts and reporting the second as the first is a confident false claim about the
    # hardware. $env:firmware_type is set by Windows and disambiguates them.
    $fwType = "$env:firmware_type"
    if ((-not $isUefi) -and $fwType -match '(?i)uefi') {
        $isUefi = $true
        Out-Typewriter "  -> SECURE BOOT STATE COULD NOT BE READ ON A UEFI MACHINE." "WARN"
        Add-Finding -ID "BOOT159_SB_UNREADABLE" -Phase "PHASE 159" `
            -ThreatType "Boot Integrity" -Severity $SEV_INFO `
            -Description "This machine reports firmware type '$fwType', so it boots via UEFI - but Confirm-SecureBootUEFI failed and the Secure Boot state could NOT be determined this run. The error was: $sbError. This is reported rather than treated as 'not UEFI', because saying a UEFI machine is legacy BIOS is a false statement about the hardware, and an unread check must never read as a pass. Common causes, in order: the SecureBoot PowerShell module is unavailable or blocked by policy; WMI is unhealthy (try 'winmgmt /verifyrepository'); or the scan is not running elevated, which this engine normally guarantees. Determine it by hand with: Confirm-SecureBootUEFI   and if that fails, msinfo32 reports both Secure Boot State and BIOS Mode on its System Summary page." `
            -Target "SecureBoot" -FixAction "Info" -Group "Boot Integrity"
    }

    if (-not $isUefi) {
        Out-Typewriter "  -> LEGACY BIOS / NON-UEFI BOOT — ESP AND SECURE BOOT CHECKS DO NOT APPLY." "INFO"
        Add-Finding -ID "BOOT159_LEGACYBIOS" -Phase "PHASE 159" `
            -ThreatType "Boot Integrity" -Severity $SEV_INFO `
            -Description "This machine does not boot via UEFI, so Secure Boot, the dbx revocation list and the EFI System Partition do not exist here and were not assessed. That is reported rather than skipped silently, because the absence of these checks in the report would otherwise read as a pass. A legacy-BIOS/MBR machine has no Secure Boot at all: nothing verifies the boot chain, and the MBR bootkit surface that phase 58 covers is the relevant one instead. On any machine still in service this is worth planning out — converting to UEFI/GPT with MBR2GPT and enabling Secure Boot removes an entire class of pre-boot persistence, and is also a prerequisite for the virtualisation-based protections this fleet may already be licensed for." `
            -Target "FirmwareType" -FixAction "Info" -Group "Boot Integrity"
    } else {
        # 1. Secure Boot state, and the specific combination that matters.
        $blOn = $null
        try {
            $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            $blOn = ("$($blv.ProtectionStatus)" -eq 'On')
        } catch { $blOn = $null }

        if ($sbState -eq $true) {
            Out-Typewriter "  -> SECURE BOOT IS ENABLED." "GOOD"
        } else {
            Out-Typewriter "  -> SECURE BOOT IS DISABLED ON A UEFI MACHINE." "CRIT"
            $blNote = if ($blOn -eq $true) {
                "BitLocker is ON on this volume, and that combination is the reason this is HIGH rather than a hardening note: BitLocker's default TPM-only protector seals the key to the measured boot state, so an attacker who can turn Secure Boot off and modify the boot chain is in a position to have the TPM release the key to a chain you did not authorise. Full-volume encryption is providing markedly less protection here than the operator believes."
            } elseif ($blOn -eq $false) {
                "BitLocker is not enabled on this volume, so no key is sealed to the boot measurements — but the pre-boot execution surface is open regardless."
            } else {
                "BitLocker status could not be read this run, so the interaction between the boot chain and any sealed volume key is unknown."
            }
            Add-Finding -ID "BOOT159_SECUREBOOT_OFF" -Phase "PHASE 159" `
                -ThreatType "Boot Integrity / Bootkit Vector" -Severity $SEV_HIGH `
                -Description "Secure Boot is DISABLED on a UEFI machine. With it off, the firmware executes whatever bootloader it finds on the EFI System Partition without checking a signature, which is the precondition for every modern bootkit — code that runs before Windows, before the kernel, and therefore before the driver-based protections every product in this fleet relies on. $blNote Benign causes are real and should be ruled out first: it is commonly turned off to install an unsigned driver, to dual-boot, or by an OEM firmware update that reset the setting. Re-enabling it is a firmware change, not a Windows one — reboot into UEFI setup and enable Secure Boot there. Confirm afterwards with: Confirm-SecureBootUEFI. If the machine will not boot with it on, the boot chain has been modified and that is itself the finding; repair with Windows recovery before re-enabling." `
                -Target "SecureBoot" -FixAction "Info" -Group "Boot Integrity"
        }

        # 2. dbx currency. BlackLotus and its successors depend on a stale revocation
        #    list — the vulnerable-but-signed bootloader they abuse is only stopped by a
        #    dbx entry. No exact size baseline is asserted (see the key's comment).
        try {
            $dbx = Get-SecureBootUEFI -Name dbx -ErrorAction Stop
            $dbxLen = 0
            try { $dbxLen = @($dbx.Bytes).Count } catch { $dbxLen = 0 }
            $minB = 4096
            if ($DBX_BASELINE -and $null -ne $DBX_BASELINE.MinBytes) { $minB = [int]$DBX_BASELINE.MinBytes }
            if ($dbxLen -gt 0 -and $dbxLen -lt $minB) {
                Out-Typewriter "  -> SECURE BOOT REVOCATION LIST IS A FACTORY STUB ($dbxLen bytes)." "CRIT"
                Add-Finding -ID "BOOT159_DBX_STALE" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity / Bootkit Vector" -Severity $SEV_HIGH `
                    -Description "The Secure Boot forbidden-signature database (dbx) is $dbxLen bytes, below the $minB-byte floor at which it is unambiguously the factory stub that has never been updated. dbx is the revocation list that makes Secure Boot mean anything: the bootloaders that bootkits abuse are legitimately signed, and the only thing that stops them loading is a dbx entry revoking them. An un-updated dbx therefore leaves Secure Boot enabled, reporting healthy, and not actually blocking the attack it exists to block. Apply the current revocation updates ($($DBX_BASELINE.ReferenceKb)) — read the guidance at $($DBX_BASELINE.ReferenceUrl) BEFORE applying, because the rollout is staged and applying it to a machine that still boots older media can make that media unbootable. Measure the current size with: (Get-SecureBootUEFI dbx).Bytes.Length" `
                    -Target "SecureBootUEFI\dbx" -FixAction "Info" -Group "Boot Integrity"
            } else {
                Out-Typewriter "  -> SECURE BOOT REVOCATION LIST PRESENT ($dbxLen bytes)." "INFO"
                Add-Finding -ID "BOOT159_DBX_SIZE" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity" -Severity $SEV_INFO `
                    -Description "The Secure Boot revocation list (dbx) is $dbxLen bytes. This is reported as a MEASUREMENT, not a verdict: dbx size varies legitimately by architecture, OEM and servicing level, and this tool deliberately ships no exact baseline, because a wrong one would produce a confident false finding on every healthy machine. What to do with it: compare it against another machine of the same model and build in this fleet — a host that is materially smaller than its peers is the one that has missed the revocation updates. The relevant guidance is $($DBX_BASELINE.ReferenceKb) at $($DBX_BASELINE.ReferenceUrl). Recorded per run, so a comparison between two scans shows whether the update was actually applied." `
                    -Target "SecureBootUEFI\dbx" -FixAction "Info" -Group "Boot Integrity"
            }
        } catch {
            Out-Typewriter "  -> COULD NOT READ THE dbx UEFI VARIABLE." "WARN"
            Write-Log "PHASE 159: Get-SecureBootUEFI dbx failed - $($_.Exception.Message)"
        }

        # 3. The ESP itself, only if it is already reachable.
        $espRoot = Get-ScytheEspRoot
        if ([string]::IsNullOrWhiteSpace($espRoot)) {
            Out-Typewriter "  -> EFI SYSTEM PARTITION IS NOT MOUNTED; CONTENTS NOT INVENTORIED." "INFO"
            Add-Finding -ID "BOOT159_ESP_UNMOUNTED" -Phase "PHASE 159" `
                -ThreatType "Boot Integrity" -Severity $SEV_INFO `
                -Description "The EFI System Partition has no access path on this machine, so its contents were NOT inventoried this run and no conclusion about them appears in this report. This tool does not mount it: assigning and removing a system partition's mount point is a live change to the boot volume's state on a client machine, and leaving nothing behind is a standing rule for this product. To inventory it by hand, from an elevated prompt: mountvol S: /S   then   Get-ChildItem S:\EFI -Recurse | Select-Object FullName, Length, LastWriteTime   and finally   mountvol S: /D   to remove the access path again. What you are looking for: any directory under \EFI other than Microsoft, Boot, and your hardware vendor's own; and any .efi file whose timestamp does not match the others. If you mount it, run this scan again while it is mounted and this phase will do the comparison for you." `
                -Target "EFISystemPartition" -FixAction "Info" -Group "Boot Integrity"
        } else {
            Out-Typewriter "  -> EFI SYSTEM PARTITION REACHABLE AT $espRoot" "INFO"
            $espEfi = Join-Path $espRoot 'EFI'
            $espEntries = New-Object System.Collections.Generic.List[object]
            # The partition ROOT first: a stray .efi or an extra top-level directory sitting
            # beside \EFI is exactly what a bootkit installer leaves, and walking only
            # \EFI\<dir> made it invisible.
            try {
                foreach ($re in @(Get-ChildItem -LiteralPath $espRoot -ErrorAction Stop)) {
                    if ("$($re.Name)" -match '(?i)^EFI$') { continue }
                    $espEntries.Add([pscustomobject]@{ Rel = "\$($re.Name)"; Full = "$($re.FullName)" })
                }
            } catch { }
            try {
                if (Test-Path -LiteralPath $espEfi) {
                    foreach ($ed in @(Get-ChildItem -LiteralPath $espEfi -ErrorAction Stop)) {
                        $espEntries.Add([pscustomobject]@{ Rel = "\EFI\$($ed.Name)"; Full = "$($ed.FullName)" })
                    }
                }
            } catch { }
            foreach ($ed in $espEntries) {
                $rel = "$($ed.Rel)"
                if (Test-ScytheNameRule -Name $rel -Rules $ESP_EXPECTED_PATHS) { continue }
                Out-Typewriter "  -> UNEXPECTED DIRECTORY ON THE ESP: $rel" "CRIT"
                Add-Finding -ID "BOOT159_ESP_UNEXPECTED_$([Math]::Abs("$rel".ToLower().GetHashCode()))" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity / Bootkit Vector" -Severity $SEV_HIGH `
                    -Description "'$rel' exists on the EFI System Partition and is not one of the directories that belong there — Windows uses \EFI\Microsoft and \EFI\Boot, and hardware vendors use their own named directory for firmware update and recovery tooling. A directory outside that set holds code the firmware can be pointed at, on a FAT32 volume with no ACLs, that most backup and AV coverage never looks at. The benign cases are worth checking first and are common on real hardware: a dual-boot Linux installation (\EFI\ubuntu, \EFI\grub, \EFI\systemd), a vendor recovery tool, or leftovers from a previous operating system on a reused disk. List it: Get-ChildItem '$($ed.Full)' -Recurse | Select-Object FullName, Length, LastWriteTime. Check the boot entry list against it: bcdedit /enum firmware. Preserve any unexplained .efi file before removing it — deleting the wrong thing here makes the machine unbootable, so change nothing until you can name what it is." `
                    -Target "$($ed.Full)" -FixAction "Info" -Group "Boot Integrity"
            }

            # Boot binaries: the ESP copy against the servicing copy under %WINDIR%.
            $servRoot = Join-Path $env:WINDIR 'Boot\EFI'
            foreach ($bn in $ESP_BOOT_BINARIES) {
                $espCopy = Join-Path $espEfi "Microsoft\Boot\$bn"
                $srvCopy = Join-Path $servRoot $bn
                if (-not (Test-Path -LiteralPath $espCopy)) { continue }
                if (-not (Test-Path -LiteralPath $srvCopy)) { continue }
                $h1 = Get-FileHashSafe $espCopy
                $h2 = Get-FileHashSafe $srvCopy
                if ($null -eq $h1 -or $null -eq $h2) { continue }
                if ("$h1" -eq "$h2") { continue }
                Out-Typewriter "  -> BOOT BINARY DIFFERS FROM ITS SERVICING COPY: $bn" "CRIT"
                Add-Finding -ID "BOOT159_ESP_MISMATCH_$([Math]::Abs("$bn".ToLower().GetHashCode()))" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity / Bootkit Vector" -Severity $SEV_HIGH `
                    -Description "The ESP copy of '$bn' does not match the servicing copy under '$servRoot'. Windows servicing keeps these two in step, so a divergence means something wrote the ESP copy outside servicing — which is precisely the shape of a bootkit installation, because the ESP copy is the one the firmware actually executes and the servicing copy is the one an integrity check is most likely to look at. ESP SHA256: $h1. Servicing SHA256: $h2. The benign cases: an in-flight or interrupted feature update, a dual-boot manager that replaced the Windows loader, and some OEM recovery tooling. Verify the signature of the ESP copy before anything else: Get-AuthenticodeSignature '$espCopy' | Format-List Status, SignerCertificate. If it is not validly Microsoft-signed, treat this machine as compromised below the operating system — a bootkit survives a Windows reinstall — and rebuild it rather than cleaning it. Do not simply overwrite the ESP copy; that destroys the evidence and may leave the machine unbootable." `
                    -Target $espCopy -FixAction "Info" -Group "Boot Integrity"
            }
        }

        # 4. BCD flags phase 40 does not cover. Phase 40 already handles testsigning and
        #    nointegritychecks and this deliberately does not repeat them.
        try {
            $bcdText = (& bcdedit /enum '{current}' 2>&1 | Out-String)
            if ("$bcdText" -match '(?i)^\s*$') { $bcdText = (& bcdedit /enum 2>&1 | Out-String) }
            foreach ($bf in @($BCD_UNSAFE_FLAGS)) {
                if ($null -eq $bf) { continue }
                $bMatch = $false
                try {
                    $brx = New-Object System.Text.RegularExpressions.Regex("$($bf.Pattern)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromMilliseconds(150))
                    $bMatch = $brx.IsMatch("$bcdText")
                } catch { $bMatch = $false }
                if (-not $bMatch) { continue }
                $bSev = switch ("$($bf.Severity)") { 'CRITICAL' { $SEV_CRITICAL } 'HIGH' { $SEV_HIGH } default { $SEV_POSSIBLE } }
                Out-Typewriter "  -> BCD FLAG: $($bf.Name)" "WARN"
                Add-Finding -ID "BOOT159_BCD_$([Math]::Abs("$($bf.Name)".ToLower().GetHashCode()))" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity" -Severity $bSev `
                    -Description "The boot configuration for the current entry matches '$($bf.Name)'. Phase 40 covers testsigning and nointegritychecks; this is one of the settings it does not. The one that matters most in this set is disableelamdrivers — it stops the early-launch anti-malware driver from loading, so the endpoint's own security product is blind for exactly the part of boot that a bootkit or a malicious driver uses, while the product itself still reports healthy once Windows is up. Kernel and boot debugging flags are the next most significant: they are legitimate developer settings, and they also disable protections and allow a debugger to attach to the kernel. Read the whole store: bcdedit /enum {current}. Benign cases are real — a developer machine, a driver-signing test rig, or a machine mid-troubleshooting. If it is not explained, clear the specific flag with bcdedit (for example: bcdedit /set {current} disableelamdrivers No) and reboot. Change one setting at a time and record the original value: a wrong bcdedit write is one of the few ways to make a machine unbootable from inside Windows, which is why nothing here carries an automated fix." `
                    -Target "BCD\$($bf.Name)" -FixAction "Info" -Group "Boot Integrity"
            }
        } catch { Write-Log "PHASE 159: BCD enumeration failed - $($_.Exception.Message)" }
    }

    Out-Typewriter "PERSISTENCE, SUPPLY-CHAIN AND BOOT-INTEGRITY BAND COMPLETE." "GOOD"

    if (-not $global:STEALTH_MODE) {
        Write-Host "  [i] Phases 146 and 148-152 are not built in this release (parallel work package)." -ForegroundColor DarkGray
    }
    Write-Log "PHASES 146, 148-152: module stub — parallel work package not yet merged."
}
