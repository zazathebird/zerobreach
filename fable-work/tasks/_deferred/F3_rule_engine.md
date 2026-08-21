# F3 — YARA-compatible rule engine + Phase 146

**Priority 3.** `ADVERSARY_ANALYSIS.md` §B11 and §B8. Size: L.

## The problem

Today's "YARA-lite" is one regex per rule:

```json
{ "Name": "Cobalt_Strike_Beacon", "Pattern": "(MZARUH|fc4881e4f0e8|metsrv)", "Severity": "CRITICAL" }
```

matched against file text. It cannot express multiple strings with an N-of-M condition, hex
patterns with wildcards, `wide`/`ascii`/`nocase`/`fullword` modifiers, offset constraints,
`filesize` bounds, or the `uint16(0) == 0x5A4D` header test that stops a rule wasting time on
non-PE files.

That means **the entire public YARA rule ecosystem cannot be used**, and every rule must be
hand-degraded into a single regex that is simultaneously less precise and more expensive.

## What to build

### Part A — `engine/RuleEngine.ps1`

A rule matcher in pure PowerShell/.NET. **Do not bundle `yara64.exe`** — an unsigned third-party
scanner binary inside an MSP tool is an AV-reputation problem and a redistribution question, and
the matcher itself is not the hard part.

Rule format — JSON, because that is what this project already reads and it needs no parser:

```json
{
  "name": "CobaltStrike_Beacon_x64",
  "description": "...",
  "severity": "CRITICAL",
  "mitre": "T1071.001",
  "filesize_max": 5242880,
  "require_pe": true,
  "strings": [
    { "id": "$a", "type": "hex",  "value": "FC 48 81 E4 F0 FF FF FF ?? ??" },
    { "id": "$b", "type": "text", "value": "beacon.dll", "nocase": true },
    { "id": "$c", "type": "text", "value": "ReflectiveLoader", "wide": true, "ascii": true },
    { "id": "$d", "type": "regex", "value": "%[cs]%[cs]\\.dll" }
  ],
  "condition": { "op": "and", "of": [
      { "op": "count", "min": 2, "ids": ["$a","$b","$c"] },
      { "op": "string", "id": "$d" }
  ]}
}
```

Required capability, in priority order:

1. **`hex` with `??` wildcards** and `[n-m]` jumps. This is what makes real rules portable.
2. **Modifiers**: `nocase`, `wide` (UTF-16LE — match the pattern with a `\x00` between every
   byte), `ascii`, `fullword`.
3. **Conditions**: `and` / `or` / `not`, `count` (N of M), `string` (one specific id),
   `at` (offset), `in` (range).
4. **Guards**: `filesize_min` / `filesize_max` and `require_pe` (`MZ` at 0, valid `e_lfanew`,
   `PE\0\0`). These are what keep a rule pack from taking an hour.

Implementation notes that will save you a day:

- **Scan bytes once.** Read the file into a byte array (cap it — 8 MB is plenty, note truncation
  in the finding) and run every rule against that one buffer. Do not re-read per rule.
- For text and hex patterns, a **Boyer-Moore-Horspool** search over the byte array is roughly an
  order of magnitude faster than converting to a string and using `-match`, and it does not
  corrupt binary data through an encoding round-trip. Converting bytes to a .NET string with the
  wrong encoding is the classic way to make a byte pattern silently unmatchable.
- Compile regex strings **once** at load into `[regex]` objects **with a match timeout**. Every
  pattern here runs against attacker-authored content, so a catastrophic backtracking pattern is
  a denial of service against the scan itself. The existing suite already enforces a 150 ms
  budget with an `(a+)+$` canary — keep that.
- `Add-Type` for a C# fast path is tempting. **Do not**, unless you put the C# in a data file:
  P/Invoke and memory-scanning C# inside a `.ps1` is exactly the shape AV heuristics flag, and an
  engine Defender blocks at load detects nothing at all.

### Part B — Phase 146: PE structural analysis

Parse the binary instead of pattern-matching its name. Today every file phase asks only "does the
path match" and "is it Authenticode-signed", neither of which survives contact with a packed or
novel sample.

Parse from the byte buffer you already have:

- **Section entropy.** A `.text` section at >7.2 is packed. `Get-FileEntropy` exists but is
  whole-file; you need it per-section.
- **Packer section names**: `UPX0`, `.themida`, `.vmp0`, `.aspack`, `.enigma`, `.petite`.
- **`SizeOfRawData == 0` with a large `VirtualSize`** — a section that is allocated but has no
  file content, i.e. it gets filled at runtime.
- **Import table shape.** `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` in one
  binary is an injector regardless of its name. **Fewer than ~5 imports total** is an API-hashing
  loader — a normal program cannot do anything with five imports.
- **Overlay size** — data appended past the last section is where droppers keep their payload.
- **`TimeDateStamp`** in the future, or zeroed, or earlier than the file's own creation.
- **Signed-but-invalid**: the signature parses and names a real vendor but does not verify. Today
  nothing distinguishes "unsigned" from "someone tried to look signed", and the second is far
  more interesting.

Feed the scan set from `Get-ScanFiles` (never a raw recursive `Get-ChildItem`), and carry the
`$global:SIG_AUDIT_*` budget on any loop that also calls `Get-AuthSig` — Authenticode does online
CRL/OCSP checks that block ~15 s each.

## Severity discipline

Packing is **not** malicious. Half of commercial software is packed, every installer looks like a
dropper, and .NET obfuscators are a legitimate product category. A single structural signal is
`INFO`. Escalate on **combination**: packed **and** unsigned **and** in a user-writable path
**and** recently created. Write that scoring explicitly — do not let a single high-entropy section
produce a HIGH.

## Deliverables

- `engine/RuleEngine.ps1` (new; the loader will dot-source it before `Phases-1.ps1`).
- `data/yara_rules.json` seeded with 15-25 rules covering the families in the existing
  `yara_lite_rules` key, ported to the richer format.
- Phase 146 in `engine/Phases-6.ps1`.
- Tests: hex wildcards match a crafted buffer; `wide` finds a UTF-16 string; N-of-M conditions
  behave; `require_pe` rejects a text file; every rule regex survives backtracking bait; the
  `(a+)+$` canary proves the timeout test is not a no-op.
