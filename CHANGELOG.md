# CHANGELOG — ZeroBreach V23

Historical bug-fix and tuning record, moved out of `CLAUDE.md` (which now carries the
consolidated **rules** only). Newest first. Every durable "never do X" lesson from these
entries lives in `CLAUDE.md` → **Critical Rules**; this file is the narrative backing.

---

## 2026-06-28 — UI phase-"skipping" (display artifact, NOT engine) + durable run logs (`c0477ae`)

User reported a live DEEP run "skipped MANY MANY phases (unless instant)." It did **not** — the
console log (`KrakenConsole_20260628_152000.log`) shows **all 115 phases ran contiguous, 0 RECOVERED
ERRORs**; many phases just run in 0–0.3s. Two **server-only** fixes (`ZeroBreach-Server.ps1`; engine
untouched; parse-clean PS 5.1 + 7, all here-strings, BOM intact):

| Bug | Root cause | Fix |
|---|---|---|
| **Phase counter appears to skip fast phases** (e.g. jumps 94→97) | The visible phase counter/progress bar updates **only** on `scan_state` (`app.js:205-211`), but the server emitted `scan_state` only every **12 log lines** (`%12`, scan runspace). A sub-second phase emits <12 lines, so several phases pass between emits → the counter jumps. | In the scan-runspace parse loop (next to `$PREX.Match`, ~`:669`) detect a phase-number change and **emit a `scan_state` immediately**, in addition to the `%12` cadence. **Not yet visually confirmed in-browser.** |
| **No durable post-run artifacts** | Validation/debug needs the full event stream on disk. | Added `reports\server_console_*.log` (main-thread console via `Start-Transcript`, stopped in the accept-loop `finally`) + `reports\server_events_*.log` (FULL SSE stream — every log_line/finding/`[FIX]` + remediation_complete summary, teed by `Enqueue`/`REnqueue`). Path on `$script:State.EventLogFile`. |

## 2026-06-25 — live DEEP run cleanup (recovered-error noise + the REAL Phase-68 flood)

A live admin `-Mode DEEP -Hours 0` run was re-run end-to-end and graded. Four classes of problem,
all in `ZeroBreach-V23.ps1`, all fixed + re-validated on a clean DEEP run. Three new **safe-wrapper**
helpers added next to `Get-AuthSig` (~`:942`); all raw call sites routed through them.

| Bug | Root cause | Fix |
|---|---|---|
| **7 "RECOVERED ERROR" lines** (GlobalFlag, DisableTaskMgr, UseLogonCredential, LmCompatibilityLevel, Property Type, Shadow, + a Get-WinEvent) | `Get-ItemPropertyValue ... -EA SilentlyContinue` throws a *terminating* error when the value is absent — `-EA SilentlyContinue` does NOT suppress it. Same for `Get-WinEvent -FilterHashtable` when a ProviderName isn't registered. | Added **`Get-RegVal`** (try/catch→`$null`) — routed all 14 `Get-ItemPropertyValue` sites. Added **`Get-WinEventSafe`** (try/catch→`@()`) — routed the 5 `-EA SilentlyContinue` `Get-WinEvent` sites. |
| **`Get-FileHash` not recognized** (`:3048`) | On a box with a corrupted module/type env, `Get-FileHash` can fail to auto-load → RECOVERED ERROR + broken hash detection. | Added **`Get-FileHashSafe`** — computes SHA256 via **.NET** (`[System.Security.Cryptography.SHA256]`); routed all 3 sites. Returns uppercase hex or `$null`. |
| **19,981-line Phase 68 "SUSPECT CREDENTIAL FILE" flood** (≈half the 4.5 MB log) | `Get-ScanFiles` ends with `return ,$results.ToArray()`. The unary comma makes it emit the whole `FileInfo[]` as **one** pipeline object. Piped **directly** into `Where-Object`, `$_` = the entire array → `$_.Name -match …` matches a subset → truthy → passes **every** file. | Wrapped **all 15 direct-pipe callers** in parens: `$x = (Get-ScanFiles …) \| Where-Object {…}`. Verified on PS 5.1: 3-path scan matches **2**, not 20000. |

(Note: the environmental "AuditToString is already present" TypeData RECOVERED ERROR at startup is a
machine-level duplicate types file, not an engine bug — benign, recovered.)

## 2026-06-22 — ~1hr hang at "phase 97" (Authenticode revocation)

**Scan hung ~1 hour; Ctrl+C wouldn't kill the shell.** Actually stalled in **Phase 98** (STOLEN CERT) —
`Get-AuthSig` on up to 100 exe/dll **per root × 4 roots ≈ 400 binaries** with NO cap. Authenticode
builds the cert chain → **online revocation checks (CRL/OCSP)**; when servers are slow each call
blocks ~15s → ~400×15s ≈ 1hr. The blocking native call also makes Ctrl+C unresponsive. Fix: budget
globals `$global:SIG_AUDIT_DEADLINE_S=25` / `$global:SIG_AUDIT_MAX_FILES=150` (~`:748`); bounded the
Phase 98/93/96 Authenticode loops with a shared stopwatch+counter ("… SIG BUDGET REACHED").

## 2026-06-23 — same Authenticode hang, 3 more phases (the real DEEP-mode hang)

The 06-22 fix only budgeted 93/96/98. A live `-Mode DEEP -Hours 0` run hung *again* (0-byte
transcript, blocked-not-spinning = network revocation). Three *other* multi-file `Get-AuthSig` loops
still had no budget, and `-Hours 0` makes `Test-InScope` pass everything.

| Phase | Root cause | Fix |
|---|---|---|
| **Phase 10** (TEMP/INetCache/Downloads exe, ~`:1449`) — *the actual culprit* | thousands of cached 3rd-party exe's whose revocation URLs aren't locally cached | shared `$global:SIG_AUDIT_*` budget across all 6 dirs |
| **Phase 15** (System32 top-level `.exe/.dll/.sys`, ~`:1578`) | thousands of files under `-Hours 0` | same budget guard |
| **Phase 66** (network-share worm, ~`:2678`) | up to 500 share binaries over slow UNC | same budget guard (shared across shares) |

VALIDATED LIVE 2026-06-23 (DEEP done 18.8min, 3 budget hits, no hang).

## 2026-06-22 — silent phase-skip via trap+continue

**Phases 99–107 silently skipped** mid-scan (log jumped 98→108). A locked `Temp\*.tmp` made
`Get-AuthenticodeSignature` throw a *terminating* error that `-EA SilentlyContinue` does NOT suppress;
it unwound to the **script-scope `trap { … continue }` (`:72`)**, whose `continue` resumes after the
whole `if ($PhasePlan.Advanced){…}` block. One locked file → 9 phases dropped.

Fix: added `Get-AuthSig` wrapper (try/catch, `-LiteralPath`); routed all 11 raw
`Get-AuthenticodeSignature` calls through it. Added a per-group inner `trap { Write-RecoveredError $_; continue }`
to the Universal/Advanced/Integrity blocks (inner-scope trap+continue resumes at the **next phase**).
VALIDATED LIVE 2026-06-23 (phases 1→115 contiguous, 44 & 69 ran).

## 2026-06-23 — `(try{}catch{})`-as-expression silently disabled 2 phases

`(try {…} catch {…})` as a *sub-expression* parses under PS 7 but is a **runtime error in Windows
PowerShell 5.1** (`try` isn't a valid expression keyword). Inside two `Where-Object` filters the error
was swallowed by global `-EA SilentlyContinue` → the **whole filter matched nothing**.

- **Phase 44** (TOKEN/PRIVILEGE ABUSE, `:2216`) — SYSTEM-level procs from user paths never flagged.
- **Phase 69** (PROCESS HOLLOWING, `:2814`) — hollow-process detection matched nothing.

Fix: restructured both so try/catch is a trailing **statement**; path pre-filter became early
`return $false`. Verified on real `powershell.exe` v5.1.

## 2026-06-06 — NEXT_STEPS Phase 0

| File | Bug | Fix |
|---|---|---|
| `ZeroBreach-V23.ps1` | Hard **parse error** at `:1445` — `"...\$sm:..."` parsed as a scoped variable ref, whole engine failed to load | `$sm:` → `${sm}` |
| `ZeroBreach-V23.ps1` | Engine blocked on Phase 43 VSS `Read-Host` (`:1811`); server child has no stdin → hung | Guarded with `if ($Auto -or $global:GUI_MODE -or $global:STEALTH_MODE) { $vssChoice="no" }` |
| `ZeroBreach-V23.ps1` | Fix-mode prompts also blocked in `-Auto` | `if ($Auto) { exit 0 }` right after the STEALTH JSON exit |
| `ZeroBreach-Server.ps1` | SSE loop's `$idx` never rewound after `EventLog.Clear()` → open tabs went silent on re-run | Rewind `$idx = 0` when `$idx -gt $count` |
| `gui/static/js/app.js` | Non-OK `/api/scan/start` ignored → UI stuck on `● SCANNING` | `.then()` throws on non-OK; `.catch()` resets state, shows `● ERROR` |

## 2025-05-19 — initial server/launch fixes

| File | Bug | Fix |
|---|---|---|
| `ZeroBreach-Server.ps1` | No UTF-8 BOM — PS5.1 read the file as Windows-1252, corrupting box-drawing char bytes | Added UTF-8 BOM (`EF BB BF`) |
| `ZeroBreach-Server.ps1` | `"[ZeroBreach]..."` inside `catch {}`/`finally {}` triggered a PS5.1 parser crash | Single-quoted strings + concatenation |
| `ZeroBreach-Server.ps1` | Stderr redirected but never read → child deadlocked when stderr buffer filled | Added `$proc.BeginErrorReadLine()` |
| `_python/server.py` | Paths pointed inside `_python/` instead of project root | Added `ROOT_DIR = BASE_DIR.parent` |
| `ZeroBreach-V23.ps1` | `$global:TW_LABEL = "ALL TIME"` at init hid the interactive time-window menu | Initialized to `""`; auto mode sets it explicitly |
| `Launch-GUI.bat` | Called nonexistent `PirateLife-GUI.ps1` | Rewrote to call `ZeroBreach-Server.ps1`; added `python` flag |

---

# Detection false-positive tuning (rounds 1–5)

All FP allowlists live in `data/detection_signatures.json` → `fp_allowlists` block (never inline
literals), loaded via `Join-AllowRegex`. Downgrade-to-POSSIBLE is preferred over deleting a
detection: only CRITICAL/HIGH are auto-selected for destructive remediation, so POSSIBLE is shown
but never auto-acted-on.

## Round 1 (2026-06-23) — top-3 capped-at-100 over-matchers (simulated vs `KrakenBaseline_20260623_135347.json`)

- **Phase 39 ROGUE ROOT CERTS** (`~:2098`): flagged ~100 legit roots CRITICAL. Now matched vs
  `trusted_root_ca_issuers` → known = INFO, unrecognized = POSSIBLE. **101 CRIT → 98 INFO + ~2 POSSIBLE.**
- **Phase 18 CLOAKED (HIDDEN+SYSTEM)** (`~:1653`): normal attr for desktop.ini/IconCache/*.library-ms.
  Drops `cloaked_benign_names`, only flags payload extensions. **101 → ~3.**
- **Phase 68 INFO-STEALER FILES** (`~:2796`): file merely *named* like a cred store. Excludes
  `infostealer_benign_paths`, downgrades loose .txt/.log/.db to POSSIBLE. **8/9 benign suppressed.**

## Round 2 (2026-06-23) — remaining CRITICAL floods + prefetch

- **Phase 27 SAFEBOOT HIJACK** (`~:1835`): offered to DeleteRegKey ~100 *default* Safe-Mode entries.
  Skips `safeboot_default_entries` (122 verified defaults); unrecognized → POSSIBLE. **101 → 0.**
- **Phase 62 NAMED PIPE BACKDOOR** (`~:2636`): pattern ended in `[a-f0-9]{8,}`, matching every legit
  RPC/GUID pipe. Replaced with externalized `c2_named_pipe_regex` (specific C2 framework pipe names —
  no broad catch-all). Also removed inline malware-name literals. **98 → 0.**
- **Phase 12 PREFETCH** (`~:1527`): a LOLBIN having run is corroborating, not standalone HIGH → POSSIBLE.

## Round 3 (2026-06-23) — remaining destructive floods (scheduled tasks + BITS)

- **Phase 104 HIDDEN SCHEDULED TASKS** (`~:3899`): Hidden=true is normal for MS/Google/updater tasks.
  Matches `hidden_task_benign_paths` → known = INFO, unrecognized = POSSIBLE; FixAction now `Info`.
  **57 HIGH DeleteFile → 0.**
- **Phase 31 BITS JOBS** (`~:1937`): every updater uses BITS. Now POSSIBLE+`Info` by default,
  escalating to HIGH+RunCmd only on raw-IP remote (`bits_suspicious_remote_regex`) or exec-to-userpath
  (`bits_suspicious_local_regex`). **49 HIGH → 0.**

> Rounds 1–3 were *simulated* against a stale report — see Round 4 for the runtime bug this hid.

## Round 4 (2026-06-26) — VALIDATED ON FRESH LIVE RUNS

Driven by fresh live `DEEP -Hours 0` runs. Before-run had **319 auto-selected destructive findings**;
round 4 cut that to **75** (final live run `KrakenBaseline_20260626_025617`) — a healthy low tail.

**THE BIG ONE — PS 5.1 `Get-Sig` string-indexing bug (`~:895/897/898`).** `Get-Sig` ends with
`@($SIG.$Name)`, but a function returning a **single-element** `@(...)` emits the bare scalar (PS
unwraps it). So `(Get-Sig 'bits_suspicious_remote_regex')[0]` indexed into the returned **string** →
its **first character** `'h'`. Then `$url -match 'h'` matched **every** `https://` URL → Phase 31
flagged **all 48 BITS jobs HIGH+RunCmd**. `c2_named_pipe_regex` had the identical bug (→ `'m'`),
silently breaking the round-2/3 fixes on real 5.1. Fixed all three to **`@(Get-Sig X)[0]`**.

Six other fixes (all downgrade-or-skip):

| Phase | Before | Fix |
|---|---|---|
| **32** DLL-hijack | 100 HIGH DeleteFile | Skip `%WINDIR%`; base → POSSIBLE, HIGH+DeleteFile only for DLLs in a user-writable staging dir |
| **66** share-worm | 68 HIGH DeleteFile | Skip `$PSScriptRoot`; unsigned scripts + exes in local `C:\Users` → POSSIBLE; HIGH reserved for a foreign/public share |
| **24** COM hijack | 15 HIGH DeleteRegKey | Top-level GUID keys only; HIGH only when HKCU CLSID shadows HKLM; per-user → POSSIBLE |
| **15** System32 sig | 100 CRIT RunCmd | Split by status: real tamper → CRIT; unverifiable (`UnknownError`) → POSSIBLE+Info |
| **19** script assoc | 7 HIGH RunCmd | `.js/.vbs` defaults → POSSIBLE + opt-in RunCmd |
| **75** Defender excl | 10 HIGH RunCmd | Path + process exclusions → POSSIBLE + opt-in RunCmd |

## Round 5 (2026-06-28) — VALIDATED ON LIVE DEEP RUNS

Headline bug: **Phase 108 offered `icacls "C:\" /reset /T /C /Q`** — a recursive ACL reset of the
whole C: drive — as a HIGH auto-applicable remediation, firing on **every** healthy box
(`%SystemDrive%\` is in `critical_acl_paths` + the root carries a default `BUILTIN\Users` append ACE).
A destructive-`FixParam` sweep found a whole family of siblings. Live auto-destructive **21 → 7**
(residual 7 all by-design). All downgrade-or-skip; the dangerous commands moved into the finding
**description** for manual use.

| Phase | Before | Fix |
|---|---|---|
| **108** ACL/owner | `icacls "C:\" /reset /T` (HIGH every run) + takeown (CRIT) | Skip bare drive-root (`^[A-Za-z]:\\?$`); weak-ACE → POSSIBLE+Info; ownership-tamper → CRIT but FixAction Info |
| **16, 43-SAM, 111, 112, 115** | `icacls /reset /T`, `vssadmin delete shadows /all`, ACL resets — auto-RunCmd | all → FixAction Info (command in description); severity kept |
| **109 / 113** | `hosts` (non-PE) flagged CRIT every run; `UnknownError` FPs; spurious `sfc /scannow` | Skip non-PE (`\.(exe\|dll\|sys)$`); status-split; SFC only on genuine tamper |
| **8** browser ext | Google Docs Offline auto-DeleteFile'd | only known-adware NAME → DeleteFile; permission-only → POSSIBLE+Info |
| **17** ADS | benign `SmartScreen` ADS stripped (HIGH RunCmd) | benign-stream allowlist + downgrade to POSSIBLE |
| **24** COM | benign per-user shell CLSIDs → DeleteRegKey | escalate only when `$shadowsHklm -and $inproc`; else POSSIBLE+Info |
| **20** Run-key | Discord/Teams/Logitech CRIT-DeleteReg'd (matched bare `AppData`) | drop bare `AppData`; AppData-only → POSSIBLE+Info; Temp/encoded/LOLBin stay CRIT |
| **26** BHO | every BHO HIGH DeleteRegKey | → POSSIBLE+Info |
| **29** task XML | legit `\Microsoft\Windows\…` tasks HIGH DeleteFile at `-Hours 0` | skip `\Tasks\Microsoft\`; weak content match → POSSIBLE+Info |
