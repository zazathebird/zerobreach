<#
.SYNOPSIS
    RUNTIME test for phase 146's pure-.NET PE parser (engine/Phases-6.ps1).

.DESCRIPTION
    Like Test-Hunt-Correlation.ps1, this EXECUTES real engine code. It extracts the eight
    parser functions from the shipped module via the AST, builds genuine PE images byte by
    byte with a PowerShell port of lib/Scythe.Formats.Tests/PeFixtureBuilder.cs, writes them
    to TEMP, and asserts on what the parser returns.

    The parser's contract is "a malformed PE is NORMAL INPUT: return $null or a partial
    result, never throw" — so the core of this file is a truncation sweep that feeds the
    parser a well-formed image cut at EVERY byte boundary through the header region and
    asserts nothing ever escapes to the caller. A hostile file reaching the engine's
    resilience trap would be reported as a RECOVERED ERROR and skip the phase.

    A PE is a byte array, so unlike the rest of the HUNT band this is fully verifiable on
    Linux. It exists because phase 146 had never met a real PE before Windows validation
    (HANDOFF 2026-08-30).
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

Write-Host "`n=== PHASE 146 PE PARSER — RUNTIME (fixture-built PEs) ===" -ForegroundColor Cyan

# ── Extract the real parser functions from the shipped module ────────────────
$modPath = Join-Path $root 'engine/Phases-6.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($modPath, [ref]$null, [ref]$null)
$want = @('Open-ScythePeStream','Read-ScytheRange','Get-ScytheU16','Get-ScytheU32',
          'Read-ScytheAsciiAt','Get-ScytheByteEntropy','ConvertTo-ScytheFileOffset',
          'Read-ScythePeImage','Read-ScythePeImports')
foreach ($name in $want) {
    $fn = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                                    $n.Name -eq $name }, $true))
    Assert-That "extracted $name from the module" $fn.Count 1
    if ($fn.Count -eq 1) { . ([scriptblock]::Create($fn[0].Extent.Text)) }
}
# The one loader-fed variable the parser reads. Use the REAL thresholds, not a copy,
# so MaxSections here is the MaxSections a scan runs with.
$sig = Get-Content (Join-Path $root 'data/detection_signatures.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$PE_SCORE = $sig.pe_score_thresholds
Assert-True 'pe_score_thresholds present in signature DB' ($null -ne $PE_SCORE -and $PE_SCORE.MaxSections -ge 4)

$OUT = Join-Path ([IO.Path]::GetTempPath()) "scythepe_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $OUT -Force | Out-Null

# ── PowerShell port of PeFixtureBuilder.cs ───────────────────────────────────
# Same deterministic layout: e_lfanew 0x100, SizeOfHeaders 0x400, sections at
# 0x1000-aligned RVAs and 0x200-aligned file offsets in the order added. Hostile knobs
# (SectionCountOverride, NumRvaOverride, OptExtra, NoOft) corrupt one header field
# without hand-computing offsets. No UInt64 arithmetic anywhere — PS 5.1 bitwise
# operators promote inconsistently, so the PE32+ ordinal flag is written as raw bytes.
$LFANEW = 0x100; $FILE_ALIGN = 0x200; $SEC_ALIGN = 0x1000; $HDRS_SIZE = 0x400
$CHR_CODE = 0x60000020; $CHR_DATA = 0x40000040

function W16 { param([byte[]]$B,[long]$O,[long]$V)
    $B[$O] = [byte]($V -band 0xFF); $B[$O+1] = [byte](($V -shr 8) -band 0xFF) }
function W32 { param([byte[]]$B,[long]$O,[long]$V)
    for ($i=0; $i -lt 4; $i++) { $B[$O+$i] = [byte](($V -shr (8*$i)) -band 0xFF) } }
function WAscii { param([byte[]]$B,[long]$O,[string]$S)
    [System.Text.Encoding]::ASCII.GetBytes($S).CopyTo($B, $O) }  # trailing NUL is the array's default 0
function AlignUp { param([long]$V,[long]$A) return (($V + $A - 1) -band (-bnot ($A - 1))) }

function New-PeBuilder { param([switch]$Plus)
    return @{
        Plus = [bool]$Plus; Sections = New-Object System.Collections.Generic.List[object]
        DirRva = New-Object long[] 16; DirSize = New-Object long[] 16
        Overlay = [byte[]]@(); Cert = $null; EntryPoint = 0; TimeStamp = 0x5F000000
        SectionCountOverride = $null; NumRvaOverride = $null; OptExtra = 0
    }
}
function Get-PeNextVa { param($B)
    if ($B.Sections.Count -eq 0) { return [long]$SEC_ALIGN }
    $s = $B.Sections[$B.Sections.Count - 1]
    $span = [Math]::Max([Math]::Max($s.VirtualSize, [long]$s.Raw.Length), 1L)
    return (AlignUp ($s.Va + $span) $SEC_ALIGN)
}
function Get-PeNextRaw { param($B)
    $end = [long]$HDRS_SIZE
    foreach ($s in $B.Sections) { $end = [Math]::Max($end, $s.RawOffset + [long]$s.Raw.Length) }
    return (AlignUp $end $FILE_ALIGN)
}
function Add-PeSection { param($B,[string]$Name,[byte[]]$Raw,[long]$Chars,[long]$VirtualSize = -1)
    $va = Get-PeNextVa $B; $ro = Get-PeNextRaw $B
    if ($VirtualSize -lt 0) { $VirtualSize = [long]$Raw.Length }
    $B.Sections.Add(@{ Name=$Name; Raw=$Raw; Chars=$Chars; VirtualSize=$VirtualSize; Va=$va; RawOffset=$ro })
    return $va
}
function Write-PeThunk { param([byte[]]$Buf,[long]$O,[bool]$Plus,[long]$Value,[bool]$Ordinal)
    # Ordinal flag is the top bit of the pointer — bit 63 on PE32+, written as a raw byte.
    if ($Plus) {
        W32 $Buf $O ($Value -band 0xFFFFFFFFL)
        W32 $Buf ($O+4) 0
        if ($Ordinal) { $Buf[$O+7] = [byte]0x80 }
    } else {
        if ($Ordinal) { W32 $Buf $O (0x80000000L -bor $Value) } else { W32 $Buf $O $Value }
    }
}
function Add-PeImports { param($B, $Dlls, [switch]$NoOft)
    # $Dlls: array of @{ Name='kernel32.dll'; Funcs=@(@{Name='CreateFileW'}, @{Ordinal=17}) }
    $va = Get-PeNextVa $B
    $ptr = if ($B.Plus) { 8 } else { 4 }
    $descBytes = ($Dlls.Count + 1) * 20
    $intRel = New-Object long[] $Dlls.Count; $iatRel = New-Object long[] $Dlls.Count
    $cur = [long]$descBytes
    for ($d=0; $d -lt $Dlls.Count; $d++) { $intRel[$d] = $cur; $cur += ($Dlls[$d].Funcs.Count + 1) * $ptr }
    for ($d=0; $d -lt $Dlls.Count; $d++) { $iatRel[$d] = $cur; $cur += ($Dlls[$d].Funcs.Count + 1) * $ptr }
    $hintRel = @{}
    for ($d=0; $d -lt $Dlls.Count; $d++) {
        for ($f=0; $f -lt $Dlls[$d].Funcs.Count; $f++) {
            if (-not $Dlls[$d].Funcs[$f].ContainsKey('Name')) { continue }
            $hintRel["$d/$f"] = $cur
            $cur += 2 + $Dlls[$d].Funcs[$f].Name.Length + 1
            if (($cur % 2) -ne 0) { $cur++ }   # hint/name entries are even-aligned per the spec
        }
    }
    $dllNameRel = New-Object long[] $Dlls.Count
    for ($d=0; $d -lt $Dlls.Count; $d++) { $dllNameRel[$d] = $cur; $cur += $Dlls[$d].Name.Length + 1 }

    $bytes = New-Object byte[] $cur
    for ($d=0; $d -lt $Dlls.Count; $d++) {
        $e = $d * 20
        if (-not $NoOft) { W32 $bytes $e ($va + $intRel[$d]) }         # OriginalFirstThunk (0 = bound)
        W32 $bytes ($e+12) ($va + $dllNameRel[$d])                     # Name
        W32 $bytes ($e+16) ($va + $iatRel[$d])                         # FirstThunk
        for ($f=0; $f -lt $Dlls[$d].Funcs.Count; $f++) {
            $fn = $Dlls[$d].Funcs[$f]
            if ($fn.ContainsKey('Ordinal')) {
                Write-PeThunk $bytes ($intRel[$d] + $f*$ptr) $B.Plus ([long]$fn.Ordinal) $true
                Write-PeThunk $bytes ($iatRel[$d] + $f*$ptr) $B.Plus ([long]$fn.Ordinal) $true
            } else {
                $rel = $hintRel["$d/$f"]
                Write-PeThunk $bytes ($intRel[$d] + $f*$ptr) $B.Plus ($va + $rel) $false
                Write-PeThunk $bytes ($iatRel[$d] + $f*$ptr) $B.Plus ($va + $rel) $false
                WAscii $bytes ($rel + 2) $fn.Name                      # 2-byte hint stays 0
            }
        }
        WAscii $bytes $dllNameRel[$d] $Dlls[$d].Name
    }
    [void](Add-PeSection $B '.idata' $bytes $CHR_DATA)
    $B.DirRva[1] = $va; $B.DirSize[1] = $descBytes
    return $va
}
function Build-PeBytes { param($B)
    $optFixed = if ($B.Plus) { 112 } else { 96 }
    $sizeOfOpt = $optFixed + 128 + $B.OptExtra
    $fileEnd = [long]$HDRS_SIZE
    foreach ($s in $B.Sections) { $fileEnd = [Math]::Max($fileEnd, $s.RawOffset + [long]$s.Raw.Length) }
    $overlayOffset = $fileEnd; $fileEnd += $B.Overlay.Length
    $certOffset = 0L
    if ($null -ne $B.Cert) { $certOffset = ($fileEnd + 7) -band (-bnot 7L); $fileEnd = $certOffset + $B.Cert.Length }

    $file = New-Object byte[] $fileEnd
    $file[0] = [byte][char]'M'; $file[1] = [byte][char]'Z'
    W32 $file 0x3C $LFANEW
    W32 $file $LFANEW 0x00004550
    $coff = $LFANEW + 4
    W16 $file $coff $(if ($B.Plus) { 0x8664 } else { 0x14C })
    $nSec = if ($null -ne $B.SectionCountOverride) { $B.SectionCountOverride } else { $B.Sections.Count }
    W16 $file ($coff+2) $nSec
    W32 $file ($coff+4) $B.TimeStamp
    W16 $file ($coff+16) $sizeOfOpt
    W16 $file ($coff+18) 0x0102
    $o = $coff + 20
    W16 $file $o $(if ($B.Plus) { 0x20B } else { 0x10B })
    W32 $file ($o+16) $B.EntryPoint
    W32 $file ($o+32) $SEC_ALIGN
    W32 $file ($o+36) $FILE_ALIGN
    $sizeOfImage = [long]$SEC_ALIGN
    foreach ($s in $B.Sections) {
        $span = [Math]::Max([Math]::Max($s.VirtualSize, [long]$s.Raw.Length), 1L)
        $sizeOfImage = [Math]::Max($sizeOfImage, (AlignUp ($s.Va + $span) $SEC_ALIGN))
    }
    W32 $file ($o+56) $sizeOfImage
    W32 $file ($o+60) $HDRS_SIZE
    $numRva = if ($null -ne $B.NumRvaOverride) { $B.NumRvaOverride } else { 16 }
    W32 $file ($o + $(if ($B.Plus) { 108 } else { 92 })) $numRva
    $dirTable = $o + $optFixed
    for ($i=0; $i -lt 16; $i++) {
        $rva = $B.DirRva[$i]; $sz = $B.DirSize[$i]
        if ($i -eq 4 -and $null -ne $B.Cert) { $rva = $certOffset; $sz = $B.Cert.Length }
        W32 $file ($dirTable + $i*8) $rva
        W32 $file ($dirTable + $i*8 + 4) $sz
    }
    $table = $o + $sizeOfOpt
    for ($i=0; $i -lt $B.Sections.Count; $i++) {
        $s = $B.Sections[$i]; $e = $table + $i*40
        WAscii $file $e $(if ($s.Name.Length -gt 8) { $s.Name.Substring(0,8) } else { $s.Name })
        W32 $file ($e+8)  $s.VirtualSize
        W32 $file ($e+12) $s.Va
        W32 $file ($e+16) $s.Raw.Length
        W32 $file ($e+20) $(if ($s.Raw.Length -gt 0) { $s.RawOffset } else { 0 })
        W32 $file ($e+36) $s.Chars
        $s.Raw.CopyTo($file, $s.RawOffset)
    }
    if ($B.Overlay.Length -gt 0) { $B.Overlay.CopyTo($file, $overlayOffset) }
    if ($null -ne $B.Cert) { $B.Cert.CopyTo($file, $certOffset) }
    return ,$file
}
function Save-PeBytes { param([byte[]]$Bytes,[string]$Name)
    $p = Join-Path $OUT $Name
    [System.IO.File]::WriteAllBytes($p, $Bytes)
    return $p
}

# ── §1  Primitive reads ──────────────────────────────────────────────────────
Write-Host "`n-- §1 primitives --" -ForegroundColor Cyan
$buf = [byte[]](0xFF,0xFF,0xFF,0xFF,0x41,0x42,0x43,0x00,0x44)
Assert-That 'U32 of FF FF FF FF is POSITIVE 4294967295 (unsigned read)' (Get-ScytheU32 $buf 0) 4294967295
Assert-That 'U16 of FF FF is POSITIVE 65535 (unsigned read)'            (Get-ScytheU16 $buf 0) 65535
Assert-That 'U16 at the last valid offset reads'      (Get-ScytheU16 $buf 7) ([long]0x4400)
Assert-True 'U16 one past the edge returns $null'     ($null -eq (Get-ScytheU16 $buf 8))
Assert-True 'U32 past the edge returns $null'         ($null -eq (Get-ScytheU32 $buf 6))
Assert-True 'U32 at a negative offset returns $null'  ($null -eq (Get-ScytheU32 $buf -1))
Assert-True 'U32 on a $null buffer returns $null'     ($null -eq (Get-ScytheU32 $null 0))
Assert-That 'AsciiAt reads a NUL-terminated string'   (Read-ScytheAsciiAt $buf 4) 'ABC'
Assert-That 'AsciiAt honours the length cap'          (Read-ScytheAsciiAt $buf 4 2) 'AB'
Assert-That 'AsciiAt past the buffer returns ""'      (Read-ScytheAsciiAt $buf 99) ''
$dirty = [System.Text.Encoding]::ASCII.GetBytes('ok'); $dirty += [byte]0x07; $dirty += [byte]0x1B; $dirty += [byte]0
Assert-That 'AsciiAt strips non-printables (attacker-authored names reach the report)' (Read-ScytheAsciiAt $dirty 0) 'ok'

$uniform = New-Object byte[] 256; for ($i=0; $i -lt 256; $i++) { $uniform[$i] = [byte]$i }
Assert-That 'entropy of a uniform byte cycle is 8.0'  (Get-ScytheByteEntropy $uniform) 8
$flat = New-Object byte[] 512   # all zero
Assert-That 'entropy of a single-value run is 0.0, a REAL answer' (Get-ScytheByteEntropy $flat) 0
Assert-True 'entropy of an empty buffer is $null, not 0'          ($null -eq (Get-ScytheByteEntropy ([byte[]]@())))
Assert-True 'entropy window overrunning the buffer is $null'      ($null -eq (Get-ScytheByteEntropy $flat 500 100))
Assert-True 'entropy of a mid-buffer window works'                ((Get-ScytheByteEntropy $uniform 0 128) -eq 7)

# ── §2  RVA → file offset (the anti-attacker-chosen-bytes property) ─────────
Write-Host "`n-- §2 RVA mapping --" -ForegroundColor Cyan
$sec = @([pscustomobject]@{ Name='.text'; VirtualAddress=0x1000L; VirtualSize=0x2000L; SizeOfRawData=0x200L; PointerToRawData=0x400L; Characteristics=$CHR_CODE })
Assert-That 'RVA inside raw data maps to its file byte' (ConvertTo-ScytheFileOffset 0x1100 $sec 0x400 0x10000) 0x500
Assert-True 'RVA inside VirtualSize but PAST SizeOfRawData maps to NOTHING (virtual-only)' `
    ($null -eq (ConvertTo-ScytheFileOffset 0x1400 $sec 0x400 0x10000))
Assert-True 'RVA below SizeOfHeaders maps identity'   ((ConvertTo-ScytheFileOffset 0x80 $sec 0x400 0x10000) -eq 0x80)
Assert-True 'negative RVA returns $null'              ($null -eq (ConvertTo-ScytheFileOffset -5 $sec 0x400 0x10000))
Assert-True 'mapped offset past EOF returns $null'    ($null -eq (ConvertTo-ScytheFileOffset 0x1100 $sec 0x400 0x480))

# ── §3  A well-formed PE32 with imports parses correctly ─────────────────────
Write-Host "`n-- §3 well-formed PE32 --" -ForegroundColor Cyan
$b = New-PeBuilder
$text = New-Object byte[] 0x200; for ($i=0; $i -lt $text.Length; $i++) { $text[$i] = [byte](($i * 7) -band 0xFF) }
$textVa = Add-PeSection $b '.text' $text $CHR_CODE
$b.EntryPoint = $textVa
[void](Add-PeImports $b @(
    @{ Name='kernel32.dll'; Funcs=@(@{Name='CreateFileW'}, @{Name='VirtualAlloc'}, @{Ordinal=17}) },
    @{ Name='advapi32.dll'; Funcs=@(@{Name='RegOpenKeyExW'}) }
))
$good = Build-PeBytes $b
$goodPath = Save-PeBytes $good 'good32.exe'
$img = Read-ScythePeImage $goodPath $good.Length
Assert-True 'well-formed PE32 parses'                  ($null -ne $img)
if ($null -ne $img) {
    Assert-That 'not PE32+'                            $img.IsPlus $false
    Assert-That 'section count'                        $img.Sections.Count 2
    Assert-That 'section names in order'               (@($img.Sections | ForEach-Object { $_.Name }) -join ',') '.text,.idata'
    Assert-That 'entry RVA read'                       $img.EntryRva $textVa
    Assert-That 'no overlay on a clean image'          $img.Overlay 0
    Assert-That 'not partial'                          $img.Partial $false
    Assert-That 'no CLR directory'                     $img.HasClr $false
    Assert-True 'import RVA points into .idata'        ($img.ImportRva -eq $img.Sections[1].VirtualAddress)
    $imp = Read-ScythePeImports $img -NamesOnly
    Assert-True 'imports parsed'                       ($null -ne $imp)
    if ($null -ne $imp) {
        Assert-That 'DLL count'                        $imp.DllCount 2
        Assert-That 'function count includes ordinals' $imp.FuncCount 4
        Assert-That 'not truncated'                    $imp.Truncated $false
        Assert-True 'names include CreateFileW'        ($imp.Names.Contains('CreateFileW'))
        Assert-True 'names include RegOpenKeyExW'      ($imp.Names.Contains('RegOpenKeyExW'))
        Assert-That 'ordinal import contributes no name' $imp.Names.Count 3
    }
    $entS = $img.Sections[0]
    $secBytes = $good[($entS.PointerToRawData)..($entS.PointerToRawData + $entS.SizeOfRawData - 1)]
    Assert-True 'section entropy computable from parsed geometry' ($null -ne (Get-ScytheByteEntropy ([byte[]]$secBytes)))
}

# ── §4  PE32+ — ordinal flag is bit 63 and read as two U32s ──────────────────
Write-Host "`n-- §4 PE32+ --" -ForegroundColor Cyan
$b = New-PeBuilder -Plus
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
[void](Add-PeImports $b @(
    @{ Name='ntdll.dll'; Funcs=@(@{Name='NtCreateFile'}, @{Ordinal=88}, @{Name='NtOpenProcess'}) }
))
$p64 = Build-PeBytes $b
$p64Path = Save-PeBytes $p64 'good64.exe'
$img64 = Read-ScythePeImage $p64Path $p64.Length
Assert-True 'PE32+ parses'                             ($null -ne $img64)
if ($null -ne $img64) {
    Assert-That 'IsPlus set'                           $img64.IsPlus $true
    $imp64 = Read-ScythePeImports $img64 -NamesOnly
    Assert-True 'PE32+ imports parsed'                 ($null -ne $imp64)
    if ($null -ne $imp64) {
        Assert-That 'PE32+ function count'             $imp64.FuncCount 3
        Assert-That 'bit-63 ordinal contributes no name' $imp64.Names.Count 2
        Assert-True 'PE32+ names resolved'              ($imp64.Names.Contains('NtCreateFile') -and $imp64.Names.Contains('NtOpenProcess'))
    }
}

# ── §5  Bound imports: OriginalFirstThunk 0 falls back to FirstThunk ─────────
Write-Host "`n-- §5 bound-import fallback --" -ForegroundColor Cyan
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
[void](Add-PeImports $b @(@{ Name='user32.dll'; Funcs=@(@{Name='MessageBoxW'}) }) -NoOft)
$bnd = Build-PeBytes $b
$bndPath = Save-PeBytes $bnd 'bound32.exe'
$imgB = Read-ScythePeImage $bndPath $bnd.Length
$impB = if ($null -ne $imgB) { Read-ScythePeImports $imgB -NamesOnly } else { $null }
Assert-True 'bound import (OFT=0) still yields its function via FirstThunk' `
    ($null -ne $impB -and $impB.FuncCount -eq 1 -and $impB.Names.Contains('MessageBoxW'))

# ── §6  Certificate table vs overlay ─────────────────────────────────────────
Write-Host "`n-- §6 certificate / overlay --" -ForegroundColor Cyan
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$b.Cert = New-Object byte[] 0x300
$signed = Build-PeBytes $b
$signedPath = Save-PeBytes $signed 'signed32.exe'
$imgS = Read-ScythePeImage $signedPath $signed.Length
Assert-True 'signed fixture parses' ($null -ne $imgS)
if ($null -ne $imgS) {
    Assert-That 'certificate size read from DataDirectory[4]'          $imgS.CertSize 0x300
    Assert-That 'certificate table is NOT reported as an overlay'      $imgS.Overlay 0
}
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$b.Overlay = New-Object byte[] 100
$b.Cert = New-Object byte[] 0x80
$both = Build-PeBytes $b
$bothPath = Save-PeBytes $both 'overlay32.exe'
$imgO = Read-ScythePeImage $bothPath $both.Length
Assert-True 'overlay+cert fixture parses' ($null -ne $imgO)
if ($null -ne $imgO) {
    # The cert is 8-aligned after the overlay, so up to 7 padding bytes count toward it.
    Assert-True 'overlay reported is the real overlay, cert excluded (100..107)' `
        ($imgO.Overlay -ge 100 -and $imgO.Overlay -le 107)
}
# A section that lies about SizeOfRawData must clamp, never go negative.
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$b.Sections[0].Raw = New-Object byte[] 0x200   # raw stays real; the header will still say 0x200
$lie = Build-PeBytes $b
W32 $lie ($LFANEW + 4 + 20 + (96 + 128) + 16) 0x7FFFFFFF   # section 0 SizeOfRawData := huge
$liePath = Save-PeBytes $lie 'liar32.exe'
$imgL = Read-ScythePeImage $liePath $lie.Length
Assert-True 'section lying about SizeOfRawData parses' ($null -ne $imgL)
if ($null -ne $imgL) { Assert-True 'overlay is never negative' ($imgL.Overlay -ge 0) }

# ── §7  CLR directory flag ───────────────────────────────────────────────────
Write-Host "`n-- §7 CLR flag --" -ForegroundColor Cyan
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$b.DirRva[14] = 0x2000; $b.DirSize[14] = 0x48
$clr = Build-PeBytes $b
$clrPath = Save-PeBytes $clr 'clr32.exe'
$imgC = Read-ScythePeImage $clrPath $clr.Length
Assert-True 'CLR data directory sets HasClr' ($null -ne $imgC -and $imgC.HasClr)
Assert-True 'plain image has HasClr false'   ($null -ne $img -and -not $img.HasClr)

# ── §8  Hostile header knobs ─────────────────────────────────────────────────
Write-Host "`n-- §8 hostile knobs --" -ForegroundColor Cyan
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$b.SectionCountOverride = 65535
$many = Build-PeBytes $b
$manyPath = Save-PeBytes $many 'sections65535.exe'
$imgM = Read-ScythePeImage $manyPath $many.Length
Assert-True 'NumberOfSections=65535 still parses'       ($null -ne $imgM)
if ($null -ne $imgM) {
    Assert-That 'capped run is marked Partial'          $imgM.Partial $true
    Assert-True  "sections capped at MaxSections ($($PE_SCORE.MaxSections))" ($imgM.Sections.Count -le $PE_SCORE.MaxSections)
}
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$b.NumRvaOverride = 0xFFFFFFFFL
$hugeRva = Build-PeBytes $b
$hugeRvaPath = Save-PeBytes $hugeRva 'numrva4g.exe'
$imgR = Read-ScythePeImage $hugeRvaPath $hugeRva.Length
Assert-True 'NumberOfRvaAndSizes=4294967295 is clamped, parse completes' ($null -ne $imgR)
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$b.NumRvaOverride = 0
$noDirs = Build-PeBytes $b
$noDirsPath = Save-PeBytes $noDirs 'numrva0.exe'
$imgZ = Read-ScythePeImage $noDirsPath $noDirs.Length
Assert-True 'NumberOfRvaAndSizes=0 parses with no directories' ($null -ne $imgZ -and $imgZ.ImportRva -eq 0 -and $imgZ.CertSize -eq 0)
Assert-True 'no import directory means imports return $null'   ($null -eq (Read-ScythePeImports $imgZ -NamesOnly))
# Non-standard SizeOfOptionalHeader: the loader honours the declared value and so must we.
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$b.OptExtra = 8
$shifted = Build-PeBytes $b
$shiftedPath = Save-PeBytes $shifted 'optextra.exe'
$imgX = Read-ScythePeImage $shiftedPath $shifted.Length
Assert-True 'non-standard SizeOfOptionalHeader: section table found where DECLARED' `
    ($null -ne $imgX -and $imgX.Sections.Count -eq 1 -and $imgX.Sections[0].Name -eq '.text')
# Absurd e_lfanew: refused, not chased.
$lf = [byte[]]$good.Clone(); W32 $lf 0x3C 0x7FFFFFFF
Assert-True 'absurd e_lfanew is refused'  ($null -eq (Read-ScythePeImage (Save-PeBytes $lf 'lfanew_absurd.exe') $lf.Length))
$lf = [byte[]]$good.Clone(); W32 $lf 0x3C 2
Assert-True 'e_lfanew below 4 is refused' ($null -eq (Read-ScythePeImage (Save-PeBytes $lf 'lfanew_tiny.exe') $lf.Length))
$nm = [byte[]]$good.Clone(); $nm[0] = 0x50; $nm[1] = 0x4B      # 'PK' — a zip, the classic non-PE
Assert-True 'non-MZ file returns $null'   ($null -eq (Read-ScythePeImage (Save-PeBytes $nm 'notmz.bin') $nm.Length))
$bs = [byte[]]$good.Clone(); W16 $bs ($LFANEW + 4 + 20) 0x777  # optional-header magic neither 10B nor 20B
Assert-True 'unknown optional-header magic returns $null' ($null -eq (Read-ScythePeImage (Save-PeBytes $bs 'badmagic.exe') $bs.Length))

# ── §9  Import walk is bounded: crafted files must truncate, not hang/throw ──
Write-Host "`n-- §9 import DoS bounds --" -ForegroundColor Cyan
# (a) descriptor array with no terminator, running to the section edge
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$junk = New-Object byte[] 0x1000; for ($i=0; $i -lt $junk.Length; $i++) { $junk[$i] = 0xFF }
$junkVa = Add-PeSection $b '.bad' $junk $CHR_DATA
$b.DirRva[1] = $junkVa; $b.DirSize[1] = 20
$noterm = Build-PeBytes $b
$notermPath = Save-PeBytes $noterm 'noterm.exe'
$imgN = Read-ScythePeImage $notermPath $noterm.Length
$impN = if ($null -ne $imgN) { Read-ScythePeImports $imgN -NamesOnly } else { $null }
Assert-True 'unterminated descriptor array returns a TRUNCATED result, no throw' `
    ($null -ne $impN -and $impN.Truncated)
# (b) one descriptor whose thunk array never terminates
$b = New-PeBuilder
[void](Add-PeSection $b '.text' (New-Object byte[] 0x200) $CHR_CODE)
$evil = New-Object byte[] 0x8000; for ($i=0x100; $i -lt $evil.Length; $i++) { $evil[$i] = 0xFF }
$evilVa = Get-PeNextVa $b
W32 $evil 0  ($evilVa + 0x100)   # OriginalFirstThunk -> the 0xFF run
W32 $evil 12 ($evilVa + 0x40)    # Name -> zero bytes, empty string is fine
W32 $evil 16 ($evilVa + 0x100)   # FirstThunk
[void](Add-PeSection $b '.bad' $evil $CHR_DATA)
$b.DirRva[1] = $evilVa; $b.DirSize[1] = 40
$thunks = Build-PeBytes $b
$thunksPath = Save-PeBytes $thunks 'thunkbomb.exe'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$imgT = Read-ScythePeImage $thunksPath $thunks.Length
$impT = if ($null -ne $imgT) { Read-ScythePeImports $imgT -NamesOnly } else { $null }
$sw.Stop()
Assert-True 'unterminated thunk array truncates at the cap, no throw' `
    ($null -ne $impT -and $impT.Truncated -and $impT.FuncCount -le 4096)
Assert-True "thunk bomb finished inside 5s (took $([int]$sw.Elapsed.TotalMilliseconds)ms)" ($sw.Elapsed.TotalSeconds -lt 5)

# ── §10  Truncation sweep: EVERY header-region boundary, then sampled body ───
Write-Host "`n-- §10 truncation sweep --" -ForegroundColor Cyan
# Contract under test: cut anywhere, the parser returns $null or a Partial result and
# NEVER lets an exception escape. One escaped exception = one RECOVERED ERROR per
# hostile file in a live scan.
$threw = @(); $parsedNull = 0; $parsedOk = 0
$sweepPath = Join-Path $OUT 'sweep.bin'
$hdrEnd = [Math]::Min($good.Length, 0x260)   # DOS..section table for this fixture ends < 0x250
$lengths = @(0..$hdrEnd)
for ($L = $hdrEnd + 16; $L -lt $good.Length; $L += 16) { $lengths += $L }
$lengths += ($good.Length - 1)
foreach ($L in $lengths) {
    $cut = New-Object byte[] $L
    if ($L -gt 0) { [System.Array]::Copy($good, $cut, $L) }
    [System.IO.File]::WriteAllBytes($sweepPath, $cut)
    try {
        $r = Read-ScythePeImage $sweepPath $L
        if ($null -eq $r) { $parsedNull++ } else {
            $parsedOk++
            $null = Read-ScythePeImports $r -NamesOnly   # must also not throw on a partial image
        }
    } catch { $threw += $L }
}
Assert-That "no length in the sweep threw (lengths that threw: $($threw -join ','))" $threw.Count 0
Assert-True 'lengths below the 64-byte DOS header all return $null' ($parsedNull -ge 64)
Assert-True 'some truncations still yield a (partial) parse'        ($parsedOk -ge 1)
Assert-True 'full image at the end of the sweep parses'             ($null -ne (Read-ScythePeImage $goodPath $good.Length))
Write-Host "  [INFO] sweep: $($lengths.Count) lengths, $parsedNull null, $parsedOk parsed" -ForegroundColor DarkGray

# ── §11  Read-ScytheRange edge behaviour ─────────────────────────────────────
Write-Host "`n-- §11 stream range reads --" -ForegroundColor Cyan
$st = Open-ScythePeStream $goodPath
Assert-True 'stream opens'                            ($null -ne $st)
if ($null -ne $st) {
    Assert-True 'range read past EOF is clamped, delivers what exists' ((Read-ScytheRange $st ($good.Length - 8) 64).Length -eq 8)
    Assert-True 'range read AT EOF returns $null'      ($null -eq (Read-ScytheRange $st $good.Length 16))
    Assert-True 'negative offset returns $null'        ($null -eq (Read-ScytheRange $st -1 16))
    Assert-True 'zero count returns $null'             ($null -eq (Read-ScytheRange $st 0 0))
    $st.Dispose()
}
Assert-True 'range read on a $null stream returns $null' ($null -eq (Read-ScytheRange $null 0 16))
Assert-True 'opening a nonexistent path returns $null, no throw' ($null -eq (Open-ScythePeStream (Join-Path $OUT 'missing.exe')))

# ── Cleanup + verdict ────────────────────────────────────────────────────────
Remove-Item -LiteralPath $OUT -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
