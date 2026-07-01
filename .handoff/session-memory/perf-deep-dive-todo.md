---
name: perf-deep-dive-todo
description: Performance deep-dive of the ZeroBreach scan engine — file-walk hangs FIXED 2026-06-22 via Get-ScanFiles; server-side SSE/Defender latency still unprofiled
metadata: 
  node_type: memory
  type: project
  originSessionId: f2309b93-385c-4c8b-acf1-dfd7fe59d3a4
---

The user reported (2026-06-22) that some scan phases "take forever" and hang/crash the web UI during
incident response. **Root cause found + fixed the same day:** unbounded `Get-ChildItem -Recurse` over
`$env:USERPROFILE`/`LOCALAPPDATA`/`APPDATA` (browser caches, Teams, OneDrive, node_modules → 100k+
files), plus per-pattern×per-root loops re-walking the same tree 20–48× per phase.

**Fix (in `ZeroBreach-V23.ps1`):** new **`Get-ScanFiles`** helper — manual prunable walk with a hard
file cap (`$global:SCAN_MAX_FILES`=20000) + wall-clock deadline (`$global:SCAN_DEADLINE_S`=20s), prunes
cache dirs, skips reparse points + OneDrive cloud placeholders, time-windows during the walk, returns
`FileInfo[]`. ~17 hot walks converted; ransomware Phases 51/52/53 share ONE walk; per-pattern loops
collapsed to one walk + anchored regex (`^…$`, `\*`→`.*` — stops `nc.exe` matching `sync.exe`).
`Get-FileEntropy` now reads a 1 MB sample. Unit-tested (cap/prune/regex/entropy all verified).

**Update 2026-06-26 (Opus review of Sonnet's perf pass):** the 2026-06-22 `Get-ScanFiles` fix was
**incomplete** — its wall-clock deadline was only checked *between directories*, so a single huge flat
dir ran the inner `EnumerateFiles` loop to the 20k cap with no time check. Real run logs proved it:
**Phase 68 (info-stealer) 547s, Phase 48 (keylogger files) 475s, Phase 18 213s, Phase 10 127s.**
Sonnet's uncommitted edit added `-or [datetime]::UtcNow -ge $deadline` to the inner file loop
(`Get-ScanFiles` ~line 732) — the load-bearing fix that bounds all four (all route through the helper).
Sonnet also: removed per-file `Get-AuthenticodeSignature` from Phase 10 (CRL network call), regex-extracts
Chrome `homepage` instead of `ConvertFrom-Json` on 20MB Preferences, hoisted the WScript.Shell COM out of
the Phase 9 loop, and fixed a separate **silent-detection bug**: `Where-Object { … -and (try{}catch{}) }`
is invalid in PS5.1 (`try` not recognized → filter threw every item → Phases 44/69 detected nothing).

**Opus added on top (2026-06-26):** (1) **Phase 18 cloaked-file flood** — Sonnet's deadline bounds the
*walk* but not the *output*; Phase 18 still emitted ~21k "CLOAKED FILE" banners (legit Hidden+System Store
app-data) → 50MB reports + frozen UI. Fix: prune `packages`/`windowsapps`, gate to executable/script
exts (or extensionless), hard-cap 200 findings w/ labeled-break early-out. (2) **`Get-AuthSig`** cached,
terminating-error-swallowing wrapper (new ~line 905) now backs all 10 raw Authenticode sites — kills the
"RECOVERED ERROR" locked-file trap spam (in-use exes/CBS System32 temp files) and verifies each binary
once across phases. Callers treat `$null` (unreadable/locked) as skip, NOT unsigned, to avoid FP rootkit
hits. All changes parse-clean (AST). **Still unvalidated live** + SSE/Defender latency still unprofiled.
When adding a file-scanning phase, always use `Get-ScanFiles`; cap finding OUTPUT too, not just walk time.
Relates to [[email-phishing-detection-rebuild]].
