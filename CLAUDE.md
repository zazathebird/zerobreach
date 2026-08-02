# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **`BLUEPRINT.md` is the product map** (architecture, data contracts, safety model, roadmap) —
> read it first for orientation. **Detailed bug-fix history and the FP-tuning rounds live in
> `CHANGELOG.md`.** This file keeps the durable **rules** only. When you fix something
> noteworthy, add a dated entry to `CHANGELOG.md` and, if it produces a new "never do X"
> lesson, a rule below.

## What This Project Is

ZeroBreach V23 "Kraken Console" is a **Windows-only MSP incident-response tool**: a PowerShell HTTP
server sits between a cyberpunk HTML/JS frontend and a PowerShell scan engine (`ZeroBreach-V23.ps1`)
that runs a numbered malware-detection phase pipeline — **~140 distinct phase headers as of
2026-07-26**, numbered 1–115 with 24 fractional insertions (see "Phase numbering + counts" below;
the old "~115 phases" figure was the *label ceiling*, not a count). A parked Python/Flask server
(`_python/server.py`) is an alternative to the PS server. The engine still self-identifies as "V22"
in some strings (scheduled task name `ZeroBreach_V22_Scheduled`, banners) — **intentional, not a bug
to fix.**

There are now **two shells over the same server + GUI**: `Launch-GUI.bat` (browser tab, the reference
entry point everything is validated against) and `native-app/` (a Tauri v2 `.exe` that spawns the
same unmodified `ZeroBreach-Server.ps1` and points a native window at it — see `native-app/README.md`).

## Launching

```powershell
Launch-GUI.bat            # Default — pure PowerShell server, no Python (recommended)
Launch-GUI.bat python     # Python/Flask server (needs deps installed first)
```

`Launch-GUI.bat` self-elevates to admin, then launches `ZeroBreach-Server.ps1`. On failure the window
stays open and writes `zerobreach_launch_error.log` to the project root. Requires Windows 10/11,
PowerShell 5.1+, admin rights.

The native shell is built from `native-app/` (`npm install` → `npx tauri build` →
`src-tauri/target/release/zerobreach-native.exe`). It requires the **WebView2 Runtime** at run time
and refuses to start without it (exit code 3 + a message box).

## Commands

There is **no test runner, linter or package manager for the engine** — it is plain PowerShell 5.1.
"Lint" here means *parse-check on the real 5.1 runtime*; "test" means *run a scan and grade the
output*. Run all of these from the project root.

**Parse-check (the mandatory gate — run after EVERY engine edit).** Prints nothing on success.
Use real `powershell.exe` 5.1, never `pwsh` 7: the failure modes that matter (single-element unwrap,
`(try{}catch{})` as a sub-expression, `,$arr`, Windows-1252 decoding of a BOM-less file) do not
reproduce on 7.

```powershell
# All 6 engine files + the server
foreach ($f in 'ZeroBreach-V23.ps1','ZeroBreach-Server.ps1','engine\Phases-1.ps1',
                'engine\Phases-2.ps1','engine\Phases-3.ps1','engine\Summary.ps1','engine\FixMode.ps1') {
  $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $f), [ref]$null, [ref]$e); if ($e) { "$f"; $e }
}
# BOM check — the first 3 bytes of every repo .ps1 MUST be 239 187 191 (EF BB BF)
Get-Content .\engine\Phases-1.ps1 -Encoding Byte -TotalCount 3
```

`ParseFile` on `ZeroBreach-Server.ps1` does **not** cover its `@'...'@` here-strings
(`$script:SCAN_SCRIPT` / `$script:REMEDIATE_SCRIPT` are runspace scripts) — a syntax error inside
one is invisible until it runs. Extract and `ParseInput`-check them separately after editing either.

**Run the engine headlessly** (no server, no GUI — the fastest edit→verify loop):

```powershell
powershell -ExecutionPolicy Bypass -File .\ZeroBreach-V23.ps1 -Mode FULL -Hours 0 -Auto
powershell -ExecutionPolicy Bypass -File .\ZeroBreach-V23.ps1 -Mode DEEP -Hours 0 -Auto -LoadUserHives
```

**Run ONE phase (the closest thing to a single-test run).** `-Phases` is an opt-in *additive*
filter layered on every existing gate — it can only narrow a run, never widen it, and an unset
value is a hard no-op. Fractional-safe:

```powershell
powershell -ExecutionPolicy Bypass -File .\ZeroBreach-V23.ps1 -Mode DEEP -Hours 0 -Auto -Phases "74.5"
powershell -ExecutionPolicy Bypass -File .\ZeroBreach-V23.ps1 -Mode DEEP -Hours 0 -Auto -Phases "20,29,68.5,105"
```

**Grade a run.** The engine writes `reports/KrakenBaseline_<stamp>.json` +
`reports/KrakenConsole_<stamp>.log`. The two checks that catch real regressions:

```powershell
# 1. Phase contiguity — a HARD GAP right after a RECOVERED ERROR means a module trap is missing
Select-String 'PHASE .* took|RECOVERED ERROR' .\reports\KrakenConsole_<stamp>.log
# 2. Auto-destructive count — CRITICAL/HIGH + a destructive FixAction (see rule #1)
$j = Get-Content .\reports\KrakenBaseline_<stamp>.json -Raw | ConvertFrom-Json
@($j.Findings | Where-Object { $_.Severity -in 'CRITICAL','HIGH' -and
   $_.FixAction -in 'DeleteFile','DeleteReg','DeleteRegKey','KillProcess','RunCmd','Quarantine' }).Count
```

**Sandbox / harness tests** (Windows Sandbox; see `tools/sandbox-test/README.md` and the harness
rules below before trusting any result):

```powershell
.\tools\sandbox-test\Invoke-SandboxTest.ps1 -Stage WebView2Dialog
.\tools\sandbox-test\Invoke-SandboxTest.ps1 -Stage MalwareDetection -TimeoutMinutes 90
```

**Frontend + native:**

```powershell
node --check gui\static\js\app.js          # syntax only
node tools\check-visuals.mjs               # headless-Chrome FX/theme audit → fx-audit/*.png
cd native-app; npm install; npx tauri build # then LAUNCH the .exe — compiling is not running
```

Check `$LASTEXITCODE` after every native command (`npx`, `cargo`, `node`) —
`$ErrorActionPreference='Stop'` does **not** apply to native exit codes, so a failed build silently
leaves a stale binary under test.

**Release zip** (validates parse + BOM + JSON of every runtime file, then writes
`dist/ZeroBreach-V23_<stamp>.zip` + a `.sha256` sidecar):

```powershell
powershell -ExecutionPolicy Bypass -File tools\Build-Release.ps1
powershell -ExecutionPolicy Bypass -File tools\Build-Release.ps1 -OutDir D:\ -IncludePython
```

## Architecture

**Data flow (both servers):** Browser → POST `/api/scan/start` → server spawns `ZeroBreach-V23.ps1`
→ stdout streamed line-by-line → parsed/classified → events pushed to frontend in real time.

**Three layers:**
1. **Server** — `ZeroBreach-Server.ps1` (default) or `_python/server.py`. Hosts the UI, manages scan
   state, spawns and reads the PS subprocess.
2. **`gui/static/js/app.js`** — all frontend logic; view switching (boot → config → scan →
   remediation). Native `EventSource('/api/events')` (SSE) — **matches the PS server; there is no
   SSE/SocketIO mismatch** (the Python server uses SocketIO, but it's parked).
3. **`ZeroBreach-V23.ps1`** — the scan engine. Called via subprocess; **not modified for UI changes.**

### File structure

```
├── Launch-GUI.bat              Entry point (self-elevates)
├── ZeroBreach-Server.ps1       Pure-PS HTTP server (default). HttpListener + SSE at /api/events.
│                               SAVED WITH UTF-8 BOM — do not remove (see rules).
├── ZeroBreach-V23.ps1          THIN LOADER (also BOM). param()/elevation/schedule/globals/ALL
│                               helpers/Get-Sig/Get-Perm/banner/resilience trap/menus, then
│                               dot-sources engine/* in execution order. Self-elevates via RunAs.
├── engine/                     Dot-sourced phase modules (each UTF-8 BOM). Split BY RANGE, not
│   │                           category — phases run in numeric order and reuse vars across
│   │                           phases; dot-sourcing into the loader's ONE scope preserves that.
│   ├── Phases-1.ps1            Sections 1-11, phases 1-58 (incl. 10.5/10.6/17.5/…/55.5)
│   ├── Phases-2.ps1            Sections 12-16 front, phases 59-89 (incl. 69 hollowing/injection
│   │                           + its WS2 mutex sub-probe, 74.5–74.9)
│   ├── Phases-3.ps1            if($PhasePlan.Advanced) 90-107 (incl. 97.5/99.5/100.5) +
│   │                           if($PhasePlan.Integrity) 108-115
│   ├── Summary.ps1             risk score + audit summary + stealth/auto exits
│   └── FixMode.ps1             fix-mode entry, rollback snapshot, Invoke-FixMode (WinForms UI)
├── gui/
│   ├── templates/index.html    Single-page app (the only copy; served by both servers)
│   └── static/
│       ├── css/main.css        Core styles + base :root CSS vars
│       ├── css/fx.css          VFX overlays, cmd palette, danger modal, cinematic FX toggles
│       ├── fx-preview.html     Standalone FX/theme harness driven by tools/check-visuals.mjs
│       ├── vendor/             GSAP + Chart.js vendored locally — NO CDN on an incident host
│       └── js/  (load order: sound → themes → fx → kraken → app)
│           ├── app.js          SSE client, views, cmd palette (Ctrl+K), PURGE modal, CINE_FX,
│           │                   postJSON() — the single CSRF-token choke point
│           ├── sound.js        ZBSound — synthesized Web Audio SFX (no audio files)
│           ├── themes.js       ZBThemes — 12 themes + secret KRAKEN theme (inline body CSS vars)
│           ├── fx.js           ZBFX — canvas renderers + intensity tiers OFF/LITE/FULL/MAX
│           └── kraken.js       ZBKraken — ~19s "kraken" unlock cinematic
├── native-app/                 Tauri v2 native shell (Milestone 1) — see native-app/README.md.
│                               src-tauri/src/main.rs spawns the UNMODIFIED server as a child.
│                               src-tauri/target/**/engine-root/ holds BUILD COPIES of the
│                               engine/server/gui — never edit those; they are build output.
├── tools/
│   ├── Build-Release.ps1       Portable release-zip builder (parse+BOM+JSON gate, SHA256 sidecar)
│   ├── check-visuals.mjs       Headless-Chrome FX/theme audit → writes fx-audit/*.png (gitignored)
│   └── sandbox-test/           Windows Sandbox harnesses + orchestrator (Invoke-SandboxTest.ps1
│                               -Stage WebView2Dialog|MalwareDetection). READ the harness rules
│                               below before trusting a result — these have reported false green.
├── _python/                    Parked Flask/SocketIO server + PyInstaller spec (see README there)
├── data/
│   ├── ioc_defaults.json            Default IOC list for -IocFile
│   ├── detection_signatures.json    Malware signatures + fp_allowlists. Loaded by Get-Sig. KEPT IN
│   │                                DATA so AMSI/Defender doesn't flag the engine (see rules).
│   ├── mitre_mapping.json           MITRE ATT&CK technique map (wired into findings)
│   ├── scan_categories.json         Build-Custom-Scan category → phase-list map, consumed by
│   │                                POST /api/scan/analyze-text to build the -Phases filter
│   ├── coverage_matrix.json         Phase-by-phase coverage/gap matrix (WS0 reference — re-audit
│   │                                pending; was generated against the work-rig engine)
│   └── permission_baseline.json     ACL/owner baseline for the perm-integrity phases (108-115)
└── reports/                    Auto-created; scan JSON, quarantine vault, durable server logs
```

For the Python server specifically, read `_python/README_CLAUDE_CODE.md` (full route table, SocketIO
payloads, PyInstaller notes).

### Scan Engine CLI (`ZeroBreach-V23.ps1`)

Self-elevates (`Start-Process -Verb RunAs`, re-passing args). Params:

| Param | Values | Notes |
|---|---|---|
| `-Mode` | `QUICK \| FULL \| DEEP \| PARANOID \| STEALTH \| TRIAGE` | Empty = interactive menu |
| `-Hours` | int | `0` = all time, `N` = last N hours, `-1` (default) = interactive menu |
| `-Auto` | switch | Skip all menus (servers always pass this) |
| `-Html` | switch | Also emit an HTML report |
| `-Stealth` / `-Paranoid` | switch | Equivalent to selecting that mode |
| `-OutDir` | path | Defaults to `reports/`; servers pass an absolute path |
| `-IocFile` | path | Custom IOC list (format mirrors `data/ioc_defaults.json`) |
| `-Baseline` | path | Prior-run baseline for diffing |
| `-Phases` | csv string | Build-Custom-Scan filter, fractional-safe (`"20,29,68.5,105"`). **Additive/narrowing only** — layered on top of every other gate, never widens a run; empty = hard no-op. Single choke point is `Test-PhaseGate` |
| `-LoadUserHives` | switch | P1: permit `reg load` of a **logged-off** user's `NTUSER.DAT`. OFF by default, never active in STEALTH. **Not reachable from the GUI** (see Outstanding Work) |
| `-Schedule` | `DAILY \| WEEKLY` | Registers a SYSTEM scheduled task (02:00), then **exits before scanning** |
| `-SmtpTo` / `-SmtpFrom` / `-SmtpServer` | string | Email delivery for scheduled runs |

**`TRIAGE` is a sixth real mode, not an alias.** It is "the QUICK 30-phase core **plus** everything
from 81 up": it reuses the `$global:QUICK_MODE` gate to drop the 54 non-triage phases in 1–80, then
forces Universal (81–89) + Advanced (90–107) + Integrity (108–115) **on** — the only way to reach
Phase 114, the Defender-tamper check. `FULL` stops at 80 and therefore gates out every phase an
alert triage actually needs (90 hash/YARA, 91 MoTW, 92 UAC-bypass, 99.5 cmdline heuristics, 105
correlation heatmap, 107 event-log hunting, 114). `$PhasePlan.Max` stays the **label** ceiling 115.
`$global:TRIAGE_MODE` is set but **no phase module reads it yet** — inert today by design.

### Output parsing + events

**Live findings come from structured lines, not text classification (since 2026-07-02).**
`Add-Finding` (loader) emits one `[FINDING] {compact JSON}` stdout line per registered finding
in non-interactive, non-stealth runs (base keys: `id, sev, phase, tt, desc, target, fix, group` —
plus up to 18 **optional P10 evidence keys**, emitted only when the phase supplies them:
`sha256, signer, sigstat, ftime, fage, fsize, zone, url, refurl, proc, pproc, esrc, etime, tname,
conf, verdict, corrob, caveat`; `ZeroBreach-V23.ps1:624-641,682`);
the server's scan runspace converts CRITICAL/HIGH/POSSIBLE ones into SSE `finding` events
(exact severity, canonical threat bucket, MITRE-resolved) and drops the raw JSON line from the
log view. **Never re-add a text-severity → finding path in the server** (it would double-count
every detection), and **never print findings to stdout except through `Add-Finding`.** The
engine's human-readable output carries no severity tags — the 2026-07-01 DEEP run produced 0
live finding events (empty threat counters + empty server `audit_*.json`) because the server
tried to regex-classify that text.

`Classify` (PS runspace) / `classify_line()` (`_python/server.py`) still severity-classify every
line, but **only for `log_line` coloring**: `[CRIT]`/`[WARN]`/`[OK ]` (padded — regex must allow
trailing space)/`[HUNT]`/`[INFO]` → `CRITICAL | HIGH | POSSIBLE | CLEAN | INFO | HUNT`; threat
keywords → `RAT | Rootkit | Ransomware | Keylogger | Worm | Miner | Trojan | Spyware | Fileless
| Other`.

### Phase numbering + counts

Phase headers are emitted by `Show-PhaseHeader "PHASE <n>" "<desc>" "<cat>"` (loader) and parsed as
`PHASE\s+(\d+(?:\.\d+)?)[^\d]` — **fractional phases keep their decimal** (since 2026-07-02): they
advance the GUI counter/progress as real plan steps, findings carry the true fractional phase, and
both `Resolve-Mitre` copies look up the fractional `phase_map` key first (integer-floor fallback).

**Ceiling ≠ count — do not conflate them.** `phase_total` is the plan *ceiling* per mode
(QUICK 30 / FULL 80 / TRIAGE + DEEP+ 115, mirroring the loader's `$PhasePlan.Max`, mirrored again in
the server's `$MODE_PHASES` = `@{QUICK=30; FULL=80; DEEP=115; PARANOID=115; STEALTH=115; TRIAGE=115}`
at `ZeroBreach-Server.ps1:948`). Because every expansion since WS2 has been inserted as a **fractional**
number, the highest label is still 115 while the number of headers that actually execute is larger:
as of 2026-07-26 the engine has **~140 distinct headers** (Phases-1: 70, 1–58 + 12 fractionals;
Phases-2: 40, 59–89 + 9 fractionals; Phases-3: 30, 90–115 + 97.5/99.5/100.5, plus a conditional
`PHASE 105+` baseline-diff banner). QUICK is the one mode where ceiling == count: it runs **exactly
30** ungated headers (the set is listed in the loader's `$PhasePlan` comment) and the server maps it
to a 1..30 index. Progress/`phase_total` stay honest because they track the *label*, not the count —
so never "fix" this by renumbering phases. **Re-count after adding a phase**
(`Show-PhaseHeader "PHASE` occurrences per module, and the QUICK-ungated set must stay at 30.)

### Auto-select, encoding, and the SSE event table

**Only CRITICAL/HIGH + a destructive FixAction is auto-selected
for remediation** — POSSIBLE is shown but never auto-acted-on (the lever behind every FP downgrade).
**Child stdout is UTF-8 end-to-end:** the loader sets `[Console]::OutputEncoding` to UTF-8 when
stdout is redirected; the server reads with `StandardOutputEncoding = UTF8`. Don't change either
side alone — a mismatch renders every box-drawing banner as mojibake in the GUI.

| Event (server→client) | Key payload fields |
|---|---|
| `log_line` | `text, severity, phase, elapsed` |
| `finding` | `id, line, severity, threat_type, phase, mitre {id,name,tactic,url}, mitre_id, fix_action, target, timestamp` — **plus the optional P10 evidence fields**, copied through under expanded names via `$EVMAP` (`ZeroBreach-Server.ps1:1182-1194`): `sha256, signer, signature_status, file_write_time, file_age_hours, file_size, zone_id, host_url, referrer_url, process_name, parent_process, evidence_source, event_time, threat_name, confidence, verdict, corroboration, caveat`. **`verdict = LIKELY-FALSE-POSITIVE` has behaviour attached — it suppresses auto-selection.** |
| `scan_state` | `phase, phase_total, phase_name, section, elapsed, threat_counts, running` |
| `scan_complete` | `findings_count, threat_counts, elapsed, results_path, engine_report` |
| `remediation_complete` | `applied, failed, skipped, blocked, snapshot` (rollback `.reg` path), `auditLog` (hash-chained `remediation_audit_*.jsonl` path) |
| `sync` (PS server) | Full state snapshot on connect/reconnect |

---

## CRITICAL RULES

These are hard constraints distilled from every past regression (`CHANGELOG.md` has the stories).
Violating one silently breaks a scan, hangs the tool, or damages a user's machine.

### Engine is split — edit the modules, and mind the two dot-source traps
- **The engine is `ZeroBreach-V23.ps1` (thin loader) + `engine/*.ps1` (dot-sourced phase modules).**
  Edit a **phase** in the matching `engine/*.ps1`; edit **globals/helpers/Get-Sig loads/elevation**
  in the loader. All modules dot-source into the loader's single scope, so cross-phase variables,
  functions and traps carry across exactly as when it was one file — but two gotchas bite ONLY after
  the split, so they are hard rules:
- **Every phase module needs its OWN top-level `trap { Write-RecoveredError $_; continue }`** (already
  in `Phases-1/2/3`). Reason: the loader's script-scope trap resumes at the next **dot-source
  statement** (i.e. the next MODULE), so a terminating error mid-module would otherwise skip **all its
  remaining phases**. This is exactly how the benign System32 ACL `AccessControl.ObjectSecurity`
  TypeData collision at Phase 16 silently dropped phases 17-58. A module-level (or grouped-block)
  trap makes `continue` resume at the next **phase** instead. Keep it as the module's first statement.
- **Wrapping a phase body in a NEW `{ }` block changes what `continue` resumes into — even though trap
  *scoping* is unchanged.** `continue` resumes at the next statement **in the block containing the
  trap**, so the block's statement granularity is the recovery granularity. Adding
  `if (Test-PhaseGate N) { <existing body> }` around ~134 phases (2026-07-27) silently coarsened
  recovery from **statement-level to phase-level in every scan**, custom or not. Measured on live 5.1:
  before, a recovered error cost one statement and the phase continued; after, it discards the entire
  remainder of the phase — up to ~450 lines in Phase 90 — **while still printing that phase's
  `PHASE N — … took Ns` timing line, so the log looks complete.** The System32 ACL TypeData collision
  is a real terminating error that fires on live boxes, so this is a live reduction in detections. If a
  refactor adds a brace around a phase body, either put a `trap { Write-RecoveredError $_; continue }`
  as the first statement **inside** the new block, or state the granularity change explicitly — do not
  let it ride as an unmeasured side effect of a mechanical edit.
- **Any `exit` inside `engine/*.ps1` that must stop the ENGINE has to be `[Environment]::Exit(N)`.**
  A plain `exit` in a dot-sourced file only returns to the loader, which then runs the NEXT module
  (this hung `-Auto`: `Summary.ps1`'s exit fell through into `FixMode.ps1`'s interactive prompt).
  Applied in `Summary.ps1` + `FixMode.ps1`. The loader's own `exit`s (elevation/schedule) are fine.
- **`$PSScriptRoot` inside a module resolves to `engine\`, not the project root** — use
  `$global:ZB_ROOT` (set unconditionally near the top of the loader) for project-root paths.
- **Keep all 6 files parse-clean on live `powershell.exe` 5.1 AND `pwsh` 7, UTF-8 BOM intact.** The
  split preserves numeric phase order; if you subdivide a module further, cut only at a `# SECTION N`
  banner (comment lines, never mid-statement).

### User rules (highest priority)
1. **The tool must NEVER auto-select or auto-apply anything that damages the system.** Never ship a
   destructive `FixParam` that an auto-select (CRITICAL/HIGH + destructive FixAction) can fire on a
   **healthy box** — no `icacls /reset /T`, `vssadmin delete shadows /all`, recursive deletes, or
   drive-root operations. Put the suggested command in the finding **description** and use
   `FixAction Info` so an operator runs it by hand.
   **"Not auto-selected" is NOT the same as "not one-click reachable" — there are TWO bulk paths.**
   `SELECT ALL` (`app.js:1273`) filters only on `protected` / `vendor_trusted` /
   `isLikelyFalsePositive` — **not on severity** — so an `INFO` finding carrying a destructive
   `FixParam` is queued by one click. Found live 2026-07-27: `VSS_DELETE_OPT`
   (`Phases-1.ps1:3038-3041`) still ships `-FixParam "vssadmin delete shadows /all /quiet"` — the exact
   command this rule names — at INFO, and SELECT ALL → PURGE destroys every restore point and
   VSS-backed backup on the box, on an incident host where they may be the only recovery path. Grade
   the destructive set against **SELECT ALL**, not just against the CRITICAL/HIGH auto-select.
2. **Datto / CentraStage / Kaseya are legitimate RMM partner tooling** — not malware. Still flag them
   if something is genuinely off (vendor name in a suspicious path, or an independent malicious signal).

### PowerShell engine safety (`ZeroBreach-V23.ps1`)
- **PowerShell variables are CASE-INSENSITIVE — never give a local the same letters as a
  broader-scope variable.** `$sev = 'INFO'` inside a function silently shadows a script-scope
  `$SEV` dictionary, so `$SEV.Keys` reads the *string* and returns `$null` — no error, the loop
  just never runs. This exact bug shipped in the server's `Classify` and killed ALL severity
  classification for weeks (every SSE line INFO). The dict is now `$SEV_RX`; when a lookup
  mysteriously returns nothing, check for a case-insensitive shadow first.
  **The engine's single dot-sourced scope makes this worse: a local in a phase body can assign the
  LOADER'S `param()` variables.** A new `$auto` in a phase body *is* the loader's `[switch]$Auto` —
  the flag `Summary.ps1` tests to decide whether to `[Environment]::Exit(0)` instead of falling
  through into `FixMode.ps1`'s interactive `Read-Host`. Clobbering it hangs every server-driven scan
  with no output and no error (caught in review 2026-07-26). Same hazard for `$mode`, `$hours`,
  `$html`, `$baseline`, `$schedule`, `$stealth`, `$paranoid`, `$outdir`, `$iocfile`, `$smtp*`.
  Prefix phase-local names (`$rk*`, `$zb*`) when in any doubt.
- **Never call these raw in a phase body — use the safe wrapper:** `Get-AuthenticodeSignature` →
  `Get-AuthSig`; `Get-ItemPropertyValue` → `Get-RegVal`; `Get-WinEvent -FilterHashtable` →
  `Get-WinEventSafe`; `Get-FileHash` → `Get-FileHashSafe`. `-EA SilentlyContinue` does **not** suppress
  the terminating "property/parameter" errors these throw; unhandled, they unwind to the script-scope
  trap and skip whole phase groups.
- **Never pipe `Get-ScanFiles` directly** into `Where-Object`/`ForEach-Object` — its `return ,$arr`
  makes the whole array arrive as **one** item, so the filter silently matches everything (or nothing).
  Wrap in parens `(Get-ScanFiles …) | …` or assign to a var first. `@(Get-ScanFiles …)` does NOT fix it.
- **Do NOT copy `return ,$arr` into new helpers — return a plain array and call it as `@(fn)`.**
  Measured on live 5.1 (5.1.26100.8875), `,$arr` is wrong in almost every natural spelling:

  | spelling | `return ,$arr` | plain `return $arr` |
  |---|---|---|
  | `@(fn).Count` (2 results) | **1** | 2 |
  | `@(fn)[0] -is [array]` | **True** — hands the WHOLE array to a caller expecting one item | False |
  | `foreach ($x in fn)` | **1 iteration** | 2 |
  | `fn \| Where-Object` | **1** | 2 |

  The only thing `,$arr` buys is stopping PS 5.1 unwrapping a **single**-element result to a scalar,
  and `@()` at the call site already fixes that (`@(fn).Count` = 1, correctly). `Get-ScanFiles`
  keeps `,$arr` only for compatibility with its 30 existing call sites. `Get-UserHives` deliberately
  does not. **This bit the P1 spec three times** — it recommended `@(Get-UserHives)[0]`, claimed bare
  `foreach` was safe, and divided a per-profile budget by `@(...).Count`, which would have been 1
  instead of N (2026-07-26).
- **Never `(fn …)[0]` when `fn` may return a single value** — PS 5.1 unwraps a single-element `@()`
  return to a scalar, so `[0]` indexes into a *string's first character*. Use `@(fn …)[0]` (force array,
  then index). Only a genuine array literal / `-split` result is safe to bare-index.
- **`try/catch` is statement-only in PS 5.1** — never use `(try{…}catch{…})` as a sub-expression
  (parses in PS 7, runtime-errors on 5.1). Restructure with early `return`s + a trailing try/catch.
- **Any loop calling `Get-AuthSig` over many files MUST carry the `$global:SIG_AUDIT_*` budget**
  (deadline + count) — `Get-ScanFiles`'s caps do NOT cover the downstream sig loop (Authenticode does
  online CRL/OCSP revocation checks that block ~15s each). Single-file/per-process call sites are fine.
- **Use `Get-ScanFiles`, never raw `Get-ChildItem -Recurse`** over a user/AppData root (it caps files +
  wall-clock, prunes cache dirs, skips OneDrive placeholders). Scope ransomware/doc scans to doc folders.
- **Anchor folder-name path tests to path COMPONENTS** (`'\\(AppData|Temp|Downloads|Desktop)\\'`),
  never bare substrings — a bare `Desktop` matched the Store *package names* `WhatsAppDesktop` /
  `DesktopAppInstaller` under `C:\Program Files\WindowsApps` and auto-KillProcess'd healthy signed
  apps (Phase 47, fixed 2026-07-02). Treat `WindowsApps` as a signed store root, not a user path.
- When bundling multiple phases under one `if ($PhasePlan.*)`, give the block its own inner
  `trap { Write-RecoveredError $_; continue }` (resumes at the next phase, not end-of-group).
- **Validate on live `powershell.exe` 5.1**, not a PS-7 simulation — the unwrap / `(try{})` /
  `,$arr` behaviors only surface on the real 5.1 runtime. Keep the engine **parse-clean on 5.1 + 7**
  and the **UTF-8 BOM** intact.

### Test harnesses, sandboxes and headless validation (all confirmed live 2026-07-26)
- **Every `.ps1` you write — including throwaway harnesses — must be ASCII + UTF-8 BOM, and must be
  parse-checked on real `powershell.exe` 5.1 BEFORE it is run.** A BOM-less `.ps1` containing an em
  dash is decoded by PS 5.1 as Windows-1252: the em dash's trailing byte becomes **U+201D, a curly
  quote**, which PS 5.1 honours as a real string delimiter. The file then fails to **parse**, so
  **zero statements execute — not even the first log line.** That is indistinguishable from a hang
  and cost an entire session of debugging. Belt and braces: keep harness source **plain ASCII** (no
  em dashes, smart quotes or box-drawing) **and** save it with the BOM — either alone would have
  prevented this, so do both. The repo `.ps1` files may use those characters precisely because their
  BOM is guaranteed; a scratch file's is not.
- **A script driving a hidden-window `LogonCommand` (Windows Sandbox, scheduled task, service) MUST
  redirect stdout AND stderr to a file.** With no console and no redirect, a parse error, a missing
  file or a thrown exception produces *nothing* anywhere — you cannot tell "failed instantly" from
  "still working". Make the first statement an unconditional line-flushed log write, so an empty log
  is itself proof the script body never ran.
- **Windows Sandbox does not reap its VM when you kill its processes.** `vmmemWindowsSandbox`
  survives indefinitely, and because Sandbox is single-instance the NEXT launch silently never boots
  — which looks exactly like a hang. `Restart-Service vmcompute -Force` clears it. **Always verify no
  sandbox VM is alive before launching another**, and only ever run one at a time.
- **theZoo malware archives are password-protected (`infected`), and `tar` cannot decrypt them — it
  writes 0-BYTE files and exits 0.** Any test that "places malware" must **assert non-zero file size
  and the expected magic bytes** before drawing any conclusion, or a meaningless clean result reads
  as a passing test. Use `7za` (bootstrap via `7zr` + the `7zXXXX-extra.7z` package) with
  `-pinfected`. Note `7zr.exe` handles **only** `.7z`, never `.zip`.
- **`POST /api/remediate` answers `{"status":"started"}` asynchronously — the HTTP response proves
  nothing was remediated.** Verify on the filesystem/registry AND in the durable
  `reports/server_events_*.log` (`applied` / `failed` / `skipped` / `blocked`) plus
  `reports/remediation_audit_*.jsonl`. Two calls back-to-back return **400
  `{"error":"remediation already running"}`** — sequence them ~30s apart.
- **PowerShell's `Invoke-RestMethod` sends no `Origin`/`Referer`**, so `Test-RequestAllowed` treats
  it as a non-browser client: headless API scripting against the server needs **no CSRF token**.
  Do not weaken the browser-facing gate to make a harness work.
- **A harness that only LOGS is not a test — it must have a failing state, and that state must have
  been observed.** `harness-malware-detection.ps1` logged 13 assertion counts A-M and then wrote its
  `*_DONE` marker unconditionally: every count could be `0` and the orchestrator still printed `DONE.`
  It produced the CHANGELOG's "clean PASS re-validated against current HEAD" while being incapable of
  reporting failure (2026-07-27). Requirements for every harness from now on: a computed **VERDICT**
  line, a **differentiated exit code**, **no completion marker on a failed or timed-out run**, and at
  least one deliberate break-it run proving the harness actually goes red. Assertions must also be
  *capable* of firing — one asserted the absence of a console banner the engine never emits under any
  condition, and another grepped for `hive` unanchored (matches `archive`) with no threshold.
- **Clear the output directory and the staged input tree before every harness run.** Two independent
  false-green paths from one session: a stale completion marker made a re-run report `DONE.` in
  milliseconds while the sandbox was still booting (and, because harnesses append with `Add-Content`,
  the operator then read the *previous* run's verdict); and `Copy-Item <src> <dst> -Recurse -Force`
  **nests instead of overwriting** once `<dst>` exists, so run 2 left the old `engine\Phases-1.ps1` in
  place and buried the new one at `engine\engine\` — the harness tested run 1's code forever. Also
  check `$LASTEXITCODE` after every native command (`npx`, `cargo`): `$ErrorActionPreference='Stop'`
  does **not** apply to native exit codes, so a failed build silently leaves a stale binary under test.
- **In a `cmd` line, `echo TEXT%VAR%>>file` writes NOTHING** — `cmd` consumes the digit immediately
  before `>>` as a redirection *handle*. Verified empirically: `echo EXITCODE=%ERRORLEVEL%>> f` appends
  nothing at all, which silently removed the only field distinguishing "the script failed to parse"
  from "it ran and finished" under a console-less `LogonCommand`. Put a space before the `>>`.
- **`Restart-Service vmcompute -Force` kills every Hyper-V VM and WSL2 distro on the host.** Never fire
  it unprompted from a harness. Detect the orphan, tell the operator, and let them confirm — and check
  for `WindowsSandboxClient`/`WindowsSandboxServer`, not just `vmmemWindowsSandbox`.

### AMSI / signatures
- **Never put malware-signature literals in the `.ps1`** — Defender AMSI blocks the engine at load
  (`ScriptContainedMaliciousContent`, exit 1, no output → "scan did nothing"). All signatures live in
  `data/detection_signatures.json`, loaded at runtime via `Get-Sig` (data files aren't AMSI-scanned).
- **FP allowlists are NOT signatures** — they go in the `fp_allowlists` block of that same JSON, loaded
  via `Join-AllowRegex` (empty key → `(?!)`, suppresses nothing). No new literal lists in the `.ps1`.
- **An allowlist entry matched against attacker-controllable text (run-key values, command lines,
  task actions) must pin the ENTIRE string to the exact benign shape** — `^…$` anchors, bounded
  wildcards like `[^"]*` (never `.*` spanning the name/value boundary). A name-only prefix pattern
  lets malware self-allowlist by naming its value e.g. "Uninstall OneDrive" (caught in review,
  2026-07-02). Path-only allowlists are fine — attackers don't control where OneDrive installs.
- **Prefer downgrade-to-POSSIBLE over deleting a detection.** POSSIBLE is shown but never auto-acted-on.

### Remediation safety (`ZeroBreach-Server.ps1` — engine stays audit-only in `-Auto`)
- **`Test-ProtectedTarget` = HARD block**, defense-in-depth across all 3 layers (server tags
  `protected`; frontend disables the checkbox + excludes from auto/Select-All/POST; the
  `$script:REMEDIATE_SCRIPT` runspace **refuses** even on manual override, reporting `blocked`). Covers
  cert trust store, `C:\Windows`/System32/SysWOW64/WinSxS, shell-system files, user dotfiles, SafeBoot +
  core OS registry, KillProcess of critical procs or the IR tool itself.
- **`Test-VendorTrusted` = SOFT signal** (centrastage/datto/kaseya/aemagent/…). Not auto-selected,
  green `✔ TRUSTED` badge, but **operator can still act**. A vendor name in a suspicious path OR with an
  independent malicious signal is **NOT** trusted and stays flagged.
- **Keep both functions in sync with their mirrors inside `$script:REMEDIATE_SCRIPT`.** Add new partner
  vendors to the `Test-VendorTrusted` regex. Re-grade the auto-destructive count (CRIT/HIGH +
  DeleteFile/DeleteReg/DeleteRegKey/KillProcess/RunCmd/Quarantine) from the baseline JSON after tuning.
- **Prefer `Quarantine` over `DeleteFile`** for anything not hash-confirmed malware (reversible: moved
  to `reports/quarantine/`, renamed `.quar`, with a `.quar.json` restore manifest).

### Server / display
- **The GUI phase counter is driven by `scan_state`: emitted on EVERY phase change plus a periodic
  `%12`-log-line tick** (the phase-change emit was added by `c0477ae` precisely because the `%12`
  tick alone skipped sub-second phases). Any new UI element that must track phase precisely hangs off
  the phase-change emit, never the tick. When a user
  reports "skipped phases," first grep the `KrakenConsole_*.log` for `PHASE N — … took` + `RECOVERED
  ERROR` — usually it's display cadence, not a dropped phase. **BUT since the engine split, a genuine
  skip IS possible**: if a phase module is missing its top-level `trap` (see the Engine-split rules), a
  terminating error drops every remaining phase in that module. Confirm by checking the log for a
  contiguous `PHASE N — … took` sequence — a hard gap (e.g. 16 → 59) right after a `RECOVERED ERROR`
  means a module trap is missing, not display cadence.
- **The phase counter is MONOTONIC — never let a parsed phase number move it backwards.**
  `Summary.ps1`'s end-of-run "10 SLOWEST" table prints `PHASE N — …` lines in *descending duration*
  order, and the phase regex matches every one of them: a finished DEEP reported 89/115 until this
  was fixed (2026-07-22). The server ignores a lower number (`ZeroBreach-Server.ps1:1220`
  `if ($newPhase -gt $ScanState.Phase)`, with `PhaseIdx` clamped to `PhaseTotal` at `:1226`); the
  parked Python server carries its own copy. Any new trailing output that
  mentions a phase is automatically safe because of this — keep it that way.
- **Never send `Access-Control-Allow-Origin: *`, and route every state-changing request through
  `Test-RequestAllowed` BEFORE the route table.** "Locally bound" is not "only the GUI can reach
  it" — every page in the operator's browser can too. Wildcard ACAO + a permissive OPTIONS
  preflight let any site `POST /api/remediate` and drive real destructive remediation, bypassing
  the typed-`PURGE` modal (found 2026-07-22). The gate lives ahead of the `switch -Regex` so a new
  POST route cannot forget it; the GUI attaches its token in the single `postJSON()` choke point.
- **A runspace cannot see the parent's functions.** `Classify`, `ConvertTo-Flag`, `Get-RegVal` etc.
  must be *re-declared inside* `$script:SCAN_SCRIPT` / `$script:REMEDIATE_SCRIPT`. A parent-only
  helper referenced from a runspace silently resolves to nothing.

### Fail closed, always
- **A match flag guarding a destructive action must be raised only AFTER the full check passes,
  never set optimistically and cleared on mismatch.** The custom-IOC CIDR matcher set "hit" up
  front, so a prefix that parsed to 0 (`10.0.0.0/abc`, or `/0`) exited the compare loop with the
  flag still set and matched EVERY connection — CRITICAL + KillProcess on every connected process
  from one typo in an IOC file (caught in review 2026-07-22, never shipped).
- **When a guard's input is missing, skip the finding — do not fall through into the action.**
  Phase 92 skipped its "is this the real System32 binary?" test when `ExecutablePath` was empty
  and went straight to KillProcess on names like `taskmgr.exe`.
- **Verifying a remediation must distinguish "gone" from "couldn't read it".** A helper that
  returns `$null` on any failure makes the verification PASS in exactly the case that matters:
  malware sets a DENY ACE on its own Run key, the delete fails silently, the read fails the same
  way, and the operator is told the persistence was removed. Report unverifiable as failure.
- **Test malformed input, not just wrong-but-well-formed input.** The CIDR unit test passed 15
  cases and still missed the bug, because every "bad" case had an unparseable *IP* — none had a
  valid IP with a bad *prefix*.
- **A guard flag must be SET by the code that CHECKS it — and every path between the set and the
  dispatch must reset it.** `/api/remediate` set `Remediating = $true` inside the spawned runspace,
  which `BeginInvoke` dispatches asynchronously; the measured gap between the route answering and the
  flag actually rising is **~74 ms for a trivial script** (100-200 ms for the real one), so plain
  *sequential* requests over loopback slip through — no true concurrency needed. Moving the set into
  the handler fixed that but created the mirror defect: `[System.IO.Path]::GetFileName()` **throws** on
  `| < >` or any control char (a .NET terminating throw `-EA` cannot suppress), and with no
  `try`/`finally` around the set→dispatch region the exception unwinds past every reset, leaving the
  flag stuck `$true` and **400-ing every future remediation for the life of the process**. Use a
  sentinel + `finally` (`try { …; $dispatched = $true } finally { if (-not $dispatched) { reset } }`),
  never a list of inline resets you have to keep complete. Note also that what makes the current
  check-then-set safe is that the accept loop is **single-threaded** (`GetContext` inline, no
  `BeginGetContext`) — there is no lock or `Interlocked` anywhere, so anyone who makes the server
  handle requests concurrently silently restores the race. `/api/scan/start` still has the original
  deferred-set defect (2026-07-27).
- **Never auto-feed IOCs extracted from untrusted text into a destructive path.** Build Custom Scan's
  "USE THIS SCAN" button merged every domain, IP and file path scraped from pasted prose straight into
  `custom_iocs.ioc` — which reaches CRITICAL + `KillProcess` on a reverse-DNS **substring** match, and
  HIGH + `Quarantine` on a bare **leaf filename** match. An operator pasting a Defender alert that
  merely mentions `security.microsoft.com`, a file-server IP and `chrome.exe` arms the next scan to
  auto-select killing every Microsoft-resolving process and quarantining every `chrome.exe` (caught in
  review 2026-07-27, before any live run). Extraction from prose is inherently low-precision — version
  strings like `Agent 1.0.0.1` parse as valid IPv4. IOC ingestion must stay a deliberate, reviewable,
  per-entry act, and anything auto-extracted must be capped well below the auto-select grade.

### Findings, IDs and new phases
- **Build finding IDs from `Get-StableId`, never `.GetHashCode()`.** `[string]::GetHashCode()` is
  randomised per process on .NET 5+/pwsh 7, so IDs derived from it change every run and the
  `-Baseline` diff reports the same finding as new forever (fixed at 16 sites, 2026-07-22).
- **An ID must be unique per THING FOUND, not per name.** `Add-Finding` de-dupes on ID with an
  early `return`, so a too-weak ID does not merely mislabel — it **silently discards** every later
  match. Real cases found 2026-07-26: `MINERCFG_$($f.Name -replace '[^a-z0-9]','')` where the name
  is *always* `config.json`, so every miner config on the box collapsed into one finding; and 9
  filename-only IDs in Phases-3 (`procdump.exe` in two profiles → one ID → the second user's copy
  left un-remediated). Hash the full path (or a real identity), plus the SID for anything per-user.
- **Adding a discriminator to an ID can EXPOSE latent duplicates the weaker ID was masking.**
  Phase 74.5 began reporting one physical file twice the moment the SID was added, because
  `...\Temporary Internet Files\Content.Outlook` is a **junction** to `...\INetCache\Content.Outlook`
  and both are in the scan list — at HIGH + `Quarantine`, so the second action would fire on an
  already-quarantined file. The SID did not cause it, it revealed it. When a site can reach the
  same object by two paths, key on identity (name + length + mtime), not on the path string.
- **Grade auto-destructive counts per phase AND with `%TEMP%` discounted.** On a dev box the raw
  total is dominated by transient test debris: 33 new `%TEMP%` files appeared between two scans run
  28 minutes apart (pytest dirs, VBCSCompiler, bisect harnesses), turning a correct change into an
  apparent +36 regression. Excluding that churn the healthy-box baseline is **7** — the figure
  `EVIDENCE_ENGINE_PLAN.md` §7 always claimed. **The 63 and 94 figures recorded in sessions 17/18
  were debris, not detections.** Note Git Bash's `/tmp` writes straight into `%TEMP%`, so do not put
  scratch files there during a grading window.
  **⚠ NO CURRENT BASELINE FIGURE IS TRUSTWORTHY (2026-07-27 audit).** Five numbers are in circulation
  (7 / 8 / 50 / 63 / 94), two pairs of them on mutually inconsistent bases, and the 94→63 / 92→50
  transitions **match no stored artifact**. The widely-quoted **8** predates the Phase 90 self-detect
  fix (post-fix it is **5**) and its artifact contains zero `PHASE 0` findings, so it predates the
  Stage 9 honesty findings too. Two of the "4 remaining by-design items" are not auto-destructive at
  all. **Re-measure before relying on any of them** — and do it on a **multi-profile** box: the dev box
  has 2 profiles and is blind by construction to the three ×N rule-#1 violations found in the P1
  migration.
- **New detections get a FRACTIONAL phase number inside an existing `if (-not $global:QUICK_MODE)`
  block.** QUICK is a real 30-phase gate whose count the server maps to a 1..30 progress index, and
  the plan ceilings (QUICK 30 / FULL 80 / DEEP+ 115) are wired into both servers — a fractional
  phase in the non-QUICK path changes none of that. Add the `phase_map` entry in
  `data/mitre_mapping.json` at the same time.
  **Verify the placement, don't assume it**: inserting "just before the next phase header" put
  three new phases immediately AFTER a `}   # end QUICK-skip block` line, so they ran in QUICK and
  pushed it to 33 (2026-07-22). Count it afterwards — the QUICK set must be exactly 30 headers.
- **A new detection is not done until it has been graded against a fresh DEEP baseline on a
  healthy box.** WS6's first cut pushed auto-destructive from 41 to 136: a GUID-filename DPAPI
  heuristic matched 99 benign cache files, "created-after-write" timestomping is simply what
  copying does, Teams registers a per-user COM TypeLib, and Chromium ships
  `ZxcvbnData\passwords.txt`. Static reasoning found none of these.
- **Hardening / lockdown / posture actions are OPERATOR-ONLY: `Info` or `POSSIBLE` + `RunCmd`.**
  Never `CRITICAL`/`HIGH` with a destructive action — that is the auto-select path and would fire
  on a healthy box (rule #1). The GUI's **SELECT HARDENING** button is the deliberate opt-in.
- **Apply benign-path allowlists through `Test-BenignPath`, not a bare `-match`.** Those lists key
  on folder names (`node_modules`, `site-packages`) that an attacker can simply create to
  self-allowlist; `Test-BenignPath` additionally vetoes a match found in a staging dir.
  **But know its blind spot: `$global:ALLOW_VETO_RE` vetoes allowlist matches under `\Downloads\`,
  `\Public\` and `\Temp\`** (the actual regex is
  `'\\(Downloads|Public)\\|\\Temp\\(?!pip-|pip_|build\\)'` — note it **exempts** `\Temp\pip-*`,
  `\Temp\pip_*` and `\Temp\build\`). In a phase scoped mostly to those directories, `Test-BenignPath`
  **cannot downgrade** and a fix that merely "routes through it" will silently do nothing. *Corrected
  2026-07-27: the earlier wording claimed this covered Phase 10's ENTIRE scope and was "structurally
  incapable" there — too strong. `INetCache` is also in Phase 10's scope (`Phases-1.ps1:600`) and
  contains none of those components, so `Test-BenignPath` is fully operative for it.* Call it first and
  unchanged, then add a
  separate, deliberately narrow, component-anchored, **downgrade-only** list to override the veto.
  And state the trade-off in the data comment: any allowlist scoped to `%TEMP%` is by definition
  attacker-satisfiable, because whoever can write there can create the directory. Keep such a hit a
  **downgrade to INFO, never a suppression** — the file stays a reported finding and only leaves the
  auto-destructive set (2026-07-26).
- **Never print a clean result for a check that could not have fired.** A green
  "0 SUSPICIOUS 4688 PROCESS EVENTS" from a box where Audit Process Creation is off — or where
  command-line capture (a *second, independent* policy) is off, so 4688 carries no arguments for the
  regexes to match — is worse than no output: it is a false all-clear on an incident host. Every
  check whose visibility depends on policy, log retention, file access or a mounted hive must
  determine that precondition and, when it fails, emit an explicit **"this check was blind"** finding
  instead of a clean line. Prefer an **empirical** precondition test over a configuration one
  (*does the log actually contain any 4688?* beats parsing `auditpol`, which is localised); where a
  config source is consulted it may act only as a **veto** — able to push the verdict toward
  "blind", never toward "clean" — and an unrecognised value degrades to UNKNOWN. This is the same
  principle as the remediation rule above: "couldn't check" and "nothing there" are different
  answers, and the plan's whole verdict layer depends on `UNPROVEN` being distinguishable from
  `CLEAN` (2026-07-26, Phases 12/91/107).
- **A shared budget spread across N roots silently zeroes coverage for roots 2..N — scale it, signal
  truncation, and NEVER conclude from a truncated walk.** Historically `Get-ScanFiles` capped at
  `SCAN_MAX_FILES = 20000` / `SCAN_DEADLINE_S = 20` and `return`ed the instant a cap was hit, walking
  roots **in the order given**. Measured on a live box: `C:\Users\<one-user>` alone yields **20,000
  files in 1.0 s**. When P1 changed ~20 filesystem sites from one profile to "all profiles in one
  call", the caps were not scaled — so on a multi-user box the first SID consumed the entire budget
  and every later profile got **zero** coverage, after which the phase printed
  `[OK] NO TUNNELING TOOLS FOUND.` (finding **P1-1**.) Three compounding traps: `-TimeScoped` does not
  help (under the
  default ALL TIME `Test-InScope` is unconditionally `$true`); machine-wide roots appended *after* the
  per-profile ones become unreachable; and a `break` on budget exhaustion (Phase 10) abandons the
  remainder with no `Add-Finding`, so the durable report has no record. **Phase 12
  (`Phases-1.ps1:1038-1068`) is the correct in-tree model** — it scales the budget by profile count,
  tests for truncation, and emits `PREFETCH_CORR_SKIPPED` instead of concluding. Also de-dupe nested
  roots by **prefix**, not exact string (`Temp` ⊂ `LocalAppData`; under OneDrive KFM `Documents` ⊂
  `OneDrive`) or the same tree is walked 2-3× out of the same budget (2026-07-27).

  > **⚠ STATE AS OF 2026-08-01 — half-fixed, UNCOMMITTED, and the helper is DEAD CODE.**
  > The working tree (`ZeroBreach-V23.ps1`, +131/−40, **not committed**) rewrites `Get-ScanFiles`
  > with (a) round-robin **fair-share** walking — one directory per root per rotation, per-root quota
  > `ceil(MaxFiles/N)`, quotas lifted once every root stalls so leftover budget is still spent;
  > single-root calls start relaxed and are byte-identical to the old behaviour for the ~30 legacy
  > call sites — (b) **scaled caps** when `N > 1` and the caller didn't pass caps explicitly
  > (`min(100000, 20000+10000*(N-1))` / `min(60, 20+6*(N-1))`), and (c) a **truncation signal**:
  > `$global:SCAN_FILES_TRUNCATED`, `Test-ScanTruncated`, `$global:SCAN_FILE_CACHE_TRUNC` (so cache
  > hits stay honest), plus an `Add-ScanGapFinding` helper emitting INFO + `FixAction Info` +
  > `Verdict UNPROVEN`.
  >
  > **`Test-ScanTruncated` and `Add-ScanGapFinding` have ZERO callers.** All 75 `Get-ScanFiles` call
  > sites (Phases-1: 30, Phases-2: 23, Phases-3: 22) ignore the flag, so the *false all-clear* half of
  > P1-1 is untouched: `Phases-3.ps1:1916` still prints `[OK] NO SUSPICIOUS DUMP FILES OR DUMPER
  > TOOLS.` and `Phases-2.ps1:2247` still prints `[OK] NO TUNNELING TOOLS FOUND.` on a truncated walk.
  > **The signal is per-call state — read it (or `Test-ScanTruncated`) IMMEDIATELY after the call,
  > before any other `Get-ScanFiles` runs**, and emit `Add-ScanGapFinding` *instead of*, never as well
  > as, the clean line. Prefix de-dupe of nested roots is still not implemented.
  >
  > **⚠ DO NOT COMMIT THIS WALK CHANGE BEFORE FIXING P1-2/P1-3/P1-4.** Budget exhaustion was
  > accidentally *masking* three rule-#1 violations. Giving profiles 2..N real files for the first
  > time makes them reachable **×N**: Phase 106 auto-deletes signed Microsoft ProcDump, Phase 31
  > auto-deletes every developer's PowerShell profile, Phase 74 writes hardening into other users'
  > hives. Landing the fix first makes a healthy multi-user box **strictly more dangerous than it is
  > today**.
- **Multiplying a per-user site by N profiles re-grades its severity — re-check rule #1 at the new
  cardinality.** A finding that was tolerable once per box may be intolerable N times. Three live
  cases from the P1 migration, none visible on the 2-profile dev box whose baseline is 8 (all three
  re-verified still open 2026-08-01): **Phase 106** `DUMPTOOL` (`Phases-3.ps1:1911-1913`) is CRITICAL
  + **DeleteFile** on a bare `procdump*.exe` glob with no signature gate — it
  deletes signed Microsoft Sysinternals ProcDump, per profile (Phase 90 documents this exact failure
  and fixed it with a sig gate; Phase 106 never got one — the whole block `1876-1915` contains no
  `Get-AuthSig` call); **Phase 31** (`Phases-1.ps1:2249-2255`) is CRITICAL + DeleteFile on
  `IEX|DownloadString|WebClient|Invoke-Expression|Start-Process.*hidden` — **broader than previously
  documented here**, and the documented init line for oh-my-posh, starship,
  zoxide and scoop — on a 5-developer box that is 5 auto-selected deletions of users' PowerShell
  profiles; **Phase 74** `MACRO_TRUST` (`Phases-2.ps1:979-982`) is HIGH + RunCmd **writing into other
  users' hives** (`Set-ItemProperty '<HKU\…\SID\…>' -Name VBAWarnings -Value 4`), which the
  sibling hardening sites at `Phases-2.ps1:1452/1562` deliberately refuse to do. *Nuance: Phase 74
  only reaches HIGH + RunCmd when `$zbHive.Source -ne 'RegLoad'` (`:973-975`) — a reg-loaded offline
  hive degrades to `Info`, so the ×N auto-select hazard is real for **mounted** (logged-on) hives
  only.* **A single-box,
  single-profile baseline cannot see any of this by construction** — grade multi-profile before
  claiming a per-user migration is safe (2026-07-27).
- **A written plan's premises are claims, not facts — measure them before implementing.**
  `EVIDENCE_ENGINE_PLAN.md` asserted `$_.Message` renders at 1–3 ms/event (it is ~0.01 ms; the real
  50× cost was a double `[xml]` DOM parse), recommended `.Properties[n].Value` (rejected — positional
  EventData indices are not a documented cross-build contract, and an off-by-one reads the wrong
  field with **no error**), and scoped P1 at "~6 phases" (a real audit found ~50 call sites). Fixing
  the stated symptom without checking the stated cause produces a change that is defensible on paper
  and wrong in the engine.

### GUI
- **Adding a cinematic effect = one `CINE_FX` entry in `app.js` + the matching `body.zbfx-<id>` CSS**
  in the "CINEMATIC FX TOGGLES" block of `fx.css`. Keep it theme-var-tinted (`--accent`/`--accent-2`/
  `--accent-glow`) and **OFF by default**. The cinematic layer is deliberately **independent** of the
  intensity tier — don't re-gate it on `body.fx-off`. Honor `prefers-reduced-motion`.

### New malware alerts
- **Use the `ingest-malware-alert` skill** (`.claude/skills/`) for every new AV/EDR alert — it extracts
  + sanitizes IOCs, adds AMSI-safe signatures to `data/detection_signatures.json`, extends the engine,
  and wires reversible quarantine, so coverage grows consistently.

---

## Key Subsystems (brief)

- **MITRE ATT&CK tagging** — server loads `data/mitre_mapping.json` into the scan runspace;
  `Resolve-Mitre`/`Resolve-MitreMain` resolve each finding (keyword → threat-type → phase map) and
  attach `mitre {id,name,tactic,url}`. Frontend renders a clickable `.item-mitre` badge.
- **HTTP routes** (`ZeroBreach-Server.ps1`, dispatch `switch -Regex` at `:1857`): `GET|POST
  /api/profiles` (scan profiles — **5** read-only built-ins at `:105-111` (Triage/Standard/Alert
  Triage/Incident/Silent) + user presets in `reports/scan_profiles.json`; save is
  upsert-by-name with fail-closed validation; built-ins deliberately carry **no `ioc_file` key** so
  applying one never blanks the IOC Manager's path. **POST bodies parse via `Read-JsonBody` —
  never inline `ConvertFrom-Json -EA SilentlyContinue`, which on PS 5.1 throws a terminating error
  on bad JSON and hangs the client with no response.** Sole exception: `/api/scan/start` (`:2207`)
  uses `Read-RequestBody` + an explicit `ConvertFrom-Json -EA Stop` inside a try/catch — it fails
  closed with a 400, so it is safe, but it is a real counterexample to "all POST bodies");
  `GET /api/export/html|csv` (server-rendered
  download from current findings); `GET|POST /api/ioc` (IOC Manager — POST writes both the JSON sidecar and
  `reports/custom_iocs.ioc` in the engine's **prefixed** text format `hash:`/`ip:`/`domain:`/`regex:`/
  `file:`, then feeds it to the next scan via `-IocFile`); `GET /api/report?name=<file>` (rich engine
  findings with `FixAction`/`FixParam`, MITRE-enriched; name validated `^(KrakenBaseline_|audit_).*\.json$`
  at `:1915`, same regex on the remediate body at `:2016`; `/api/report/diff` is stricter —
  `^KrakenBaseline_.*\.json$` at `:1942` — correctly, since diffs are baseline-only);
  `POST /api/remediate {report, ids[]}` (spawns `$script:REMEDIATE_SCRIPT`, mirrors the engine's
  `Invoke-FixMode` switch — DeleteFile/DeleteReg/DeleteRegKey/KillProcess/RunCmd/Quarantine **plus an
  `Info` arm** — streams
  `[FIX]` lines then `remediation_complete`; report path basename-locked to `reports/`; **responds
  `{"status":"started"}` immediately — see the harness rules for how to actually verify it**).
  **The two switches are NOT an exact mirror:** the server has a `default { …no automated action…
  $skipped++ }` arm (`:1787`) that `engine/FixMode.ps1`'s switch lacks — there, an unrecognized
  `FixAction` falls through silently with `$ok = $false` and is counted in *neither* applied, failed,
  nor skipped. Keep that in mind before adding a seventh action.
  Also live, and easy to miss when auditing the route table: `GET /api/csrf` (per-process token),
  `GET /api/findings` (live findings array), `GET /api/reports` (report file list),
  `GET /api/report/diff?a=&b=` (baseline compare), `GET|POST /api/schedule`, `GET /api/sysinfo`,
  `GET /api/state`, `GET /api/events`, `POST /api/scan/start|abort` (POST-only, 405 otherwise),
  `POST /api/scan/analyze-text` (`:2111` — Build Custom Scan text→IOC/category analysis, POST-only,
  50,000-char cap, calls `Get-TextScanAnalysis`), `GET /favicon.ico` (204), plus `/` and `/static/`.
- **Remediation audit trail** — both remediation paths append a tamper-evident hash-chained
  `reports/remediation_audit_<stamp>.jsonl`; the GUI path also writes a rollback `.reg` snapshot
  first when the launchpad checkbox is set. Read these, not the HTTP response, to confirm an action.
- **STEALTH mode** — engine emits one compressed-JSON audit blob to stdout instead of formatted text;
  the scan runspace buffers stdout when `stealth` is set and parses the blob after the child exits.
- **Email/phishing** (Phases 74.5/74.6/74.7) — attachment-cache scan (scoped to Outlook caches, NOT the
  multi-GB OST) → `Quarantine`; Defender threat-history correlation; proactive anti-reinfection
  hardening (Office/WSH/ASR, all opt-in `RunCmd`). Content rules match malicious *constructs*, not AV
  signature names. Driven by real Datto/Defender alerts. ASR: 3 low-FP rules Block, 3 higher-FP Audit;
  Office `VBAWarnings=2` (not 4).
- **WS2 detection expansion** (ported from the work-rig branch 2026-07-01, all **`FixAction Info`** — no
  new auto-destructive findings): **Phase 55.5** known-vulnerable signed-driver audit (BYOVD vs the
  LOLDrivers name list, SHA256-confirmed via `Get-FileHashSafe`); **Phase 53** extended known-family
  ransom-note filenames + a renamed-note *content*-rule pass; **Phase 62** anchored C2/banking named-pipe
  second pass (CS/Havoc/Covenant/PoshC2 default pipes matched on the bare leaf — deliberately does NOT
  reuse the broad `[a-f0-9]{8,}` catch-all that round-4 removed); **Phase 66** now excludes drive-letter
  admin shares (`C$`/`D$`) so the worm scan doesn't walk the whole drive; **Phase 69** known-malware
  single-instance mutex probe (Pikabot/Amadey); **Phase 99.5** (DEEP+ only) process command-line
  heuristics vs externalized loader/banking/infostealer/inhibit-recovery behavior rules. Signatures live
  in `data/detection_signatures.json` (WS2 keys: `byovd_*`, `known_malware_mutexes`, `ransom_note_*`,
  `c2_pipe_regex_anchored`, `banking_named_pipes`, `*_behavior_rules`, `inhibit_recovery_rules`, …).
- **WS6–WS9 detection expansion** (2026-07-22 / 2026-07-26) — 9 WS6 fractional phases (17.5 · 21.5 ·
  22.5 · 42.5 · 44.5 · 45.5 · 68.5 · 82.5 · 100.5) and 18 further WS7/WS8/WS9 techniques (10.5 · 10.6 ·
  32.5 · 36.5 · 49.5 · 74.8 · 87.5 · 88.5 · 97.5 + integer-phase extensions). Same contract as WS2:
  fractional numbering inside `if (-not $global:QUICK_MODE)`, signatures in data, MITRE `phase_map`
  entry per phase, hardening actions operator-only. `data/coverage_matrix.json` was last regenerated
  **2026-07-25 at 130 phases** — it is therefore **behind the current engine** and must be re-audited
  before it is trusted as a coverage source.
- **GUI feature layer** — 12 themes + secret KRAKEN (type "kraken" for a ~19s cinematic, sets
  `zb_god=1`); synthesized sound; canvas VFX; command palette (Ctrl+K); EXECUTE REMEDIATION requires
  typing `PURGE`. **MSP Mode**: type "msp"/"gannon"/"staples" pre-scan → `gannon-orange` theme + badge.
- **Boot self-heal** — inline watchdog in `index.html <head>` reloads once (capped at 2 via
  `sessionStorage.zb_boot_retry`) if `window.__ZB_BOOTED` isn't set within 9s; server polls
  `Invoke-WebRequest` until 200 before opening the browser.

## Remediation test tripwires (safe, benign — never commit)

To validate scan→findings→remediation **without real malware**, drop inert artifacts named
`ZeroBreach_TEST_DELETEME` that trip a detection phase with a known fix action, then run a FULL/DEEP
scan (all time) → FINDINGS → REMEDIATION → `PURGE`. `.bat`/`.cmd` are plain text (zero AV risk).

| Artifact | Detection | Severity | FixAction |
|---|---|---|---|
| `%TEMP%\ZeroBreach_TEST_DELETEME.bat` | Phase 10 — exe-ext in Temp | HIGH | `DeleteFile` |
| `Downloads\ZeroBreach_TEST_DELETEME.cmd` | Phase 10 — exe-ext in Downloads | POSSIBLE | `DeleteFile` |
| `HKCU:\…\Run\ZeroBreach_TEST_DELETEME` | Phase 20 — Run-key data matches `Temp` | CRITICAL | `DeleteReg` |
| `…\Content.Outlook\ZBTEST\invoice_…DELETEME.bat` | Phase 74.5 — attach-ext in Outlook cache | HIGH | `Quarantine` |
| Scheduled task `\ZeroBreach_TEST_DELETEME` (disabled) | Phase 29 — action matches `cmd` | CRITICAL | `RunCmd` |

```powershell
# Create
$b = "@echo off`r`nREM ZEROBREACH TEST TRIPWIRE - SAFE TO DELETE"
Set-Content "$env:TEMP\ZeroBreach_TEST_DELETEME.bat" $b -Encoding ASCII
Set-Content "$env:USERPROFILE\Downloads\ZeroBreach_TEST_DELETEME.cmd" $b -Encoding ASCII
New-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name ZeroBreach_TEST_DELETEME `
  -Value '"%TEMP%\ZeroBreach_TEST_DELETEME_noexec.exe" --zerobreach-test' -PropertyType String -Force
$c = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\INetCache\Content.Outlook\ZBTEST'
New-Item -ItemType Directory $c -Force | Out-Null
Set-Content (Join-Path $c 'invoice_ZeroBreach_TEST_DELETEME.bat') $b -Encoding ASCII
$s = New-ScheduledTaskSettingsSet; $s.Enabled = $false
Register-ScheduledTask ZeroBreach_TEST_DELETEME -Force -Settings $s `
  -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c rem ZeroBreach_TEST_DELETEME benign no-op')

# Cleanup
del "$env:TEMP\ZeroBreach_TEST_DELETEME.bat","$env:USERPROFILE\Downloads\ZeroBreach_TEST_DELETEME.cmd" 2>$null
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v ZeroBreach_TEST_DELETEME /f 2>$null
Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\Content.Outlook\ZBTEST" -Recurse -Force 2>$null
Unregister-ScheduledTask ZeroBreach_TEST_DELETEME -Confirm:$false 2>$null
```

## Known Gotchas

- **Admin elevation**: both servers + `Launch-GUI.bat` self-elevate.
- **Port**: PS server uses `Get-FreePort` (TcpListener on port 0); Python scans from 5000.
- **Encoding**: Python subprocess output uses `encoding="utf-8", errors="replace"`.
- **PS self-detection**: Phase 2 Script Block Logging may flag the script's own run — it has a
  self-filter; verify it works.
- **Native shell**: needs the WebView2 Runtime (exits 3 with a message box without it); writes
  `%TEMP%\zerobreach_native_debug.log`; only the window labelled `main` is wired to kill the child.
- **Duplicate engine copies**: `native-app/src-tauri/target/{debug,release}/engine-root/` contains
  full copies of `ZeroBreach-*.ps1`, `engine/`, `gui/`, `data/`. Repo-wide greps hit them — always
  check the path before editing, and never edit the copy.

## Outstanding Work

> Status as of **2026-07-27 (session 23)**. Work since 2026-07-22 lives on the branch
> **`session12/review-remediation-ws6`**, not `main` — check `git log`/`git status` before assuming
> anything here is merged.
>
> **⚠ READ `REVIEW_FINDINGS_2026-07-27.md` BEFORE TOUCHING ANY CODE. It is the active work queue and
> nothing in it is fixed yet.** Seven independent review agents audited the 8,834 insertions committed
> in the 24 h to 2026-07-27 and found defects in **every** area: **six rule-#1 violations**, **nine
> false-all-clear paths**, **two detection regressions**, a permanent-remediation-lockout bug, and a
> harness suite that is **structurally incapable of reporting failure** (which is why none of this was
> caught by the sign-offs below). Several "DONE / live-graded / clean PASS" claims recorded on
> 2026-07-27 are therefore **weaker than they read** — corrections are inline below and in
> `CHANGELOG.md`. The engine is parse-clean and functional; these are semantic defects, but three of
> them damage a healthy client machine and one makes a shipped feature's core promise false.
>
> The forward plan is `ENGINE_REWRITE_PLAN.md` (Rust evidence sidecar + incremental detection port
> behind a differential harness). **It is sequenced deliberately behind fixing the findings and
> repairing the harness** — see its §2.2 for why starting the rewrite first would be unsafe.
>
> **Re-verified 2026-08-01: `HEAD` is still `a8a9a99`. Nothing below has been committed since.**
> The only working-tree state is the uncommitted `Get-ScanFiles` rewrite in `ZeroBreach-V23.ps1`
> (see the P1-1 note below and the boxed warning in the shared-budget rule) and one untracked file,
> `ZEROBREACH_ENGINE_SPEC_FOR_REBUILD.md`. **That spec is referenced by no other document in the
> repo and is in tension with `ENGINE_REWRITE_PLAN.md`**: the plan's §2.1 argues the irreplaceable
> asset is the *tuning, not the code*, and prescribes an incremental Rust sidecar behind a
> differential harness; the spec's §8 recommends PowerShell as the rebuild target and closes by
> saying to start greenfield "with just a handful of high-signal checks." **Resolve which is
> authoritative before acting on either.** Note also that `ENGINE_REWRITE_PLAN.md` has only §0-§7 —
> the "§8 order" pointer below correctly refers to `EVIDENCE_ENGINE_PLAN.md`, not the rewrite plan.

The bulk of the original roadmap is **done** (scan-blocking prompts, re-run handling, MITRE, IOC
Manager, HTML/CSV export, STEALTH parsing, real remediation, safety guard, FP rounds 1–6, engine
split + WS2 port, live finding stream + UTF-8 pipeline, VFX/themes/sound, QUICK-as-a-real-gate,
scan profiles, portable release build, the 2026-07-22 review remediation + WS6, and the WS7/8/9
expansion). Since then:

- **P1 (multi-user hive coverage) — engine-side work (Stages 0-5, 7-9) done and live-graded.** The
  engine no longer scans only the technician's own elevated profile: registry + filesystem sites
  across all three phase modules now enumerate every reachable Windows profile (`Get-UserHives`/
  `Get-UserPaths`/`Expand-UserPathTemplate`, `-LoadUserHives` opt-in for logged-off hives), with
  flood control (`[MACHINE]` tagging, aggregated inventories), honesty findings for coverage gaps
  (`PROFILE_CENSUS_*`, `UNSCANNED_HIVE_*`, `UNREACHABLE_PROFILE_*`, `PROFILE_ENUM_TRUNCATED`,
  `HIVELOCK_*`), and a relabeled scan-context banner. Healthy-box auto-destructive baseline
  re-captured post-P1: **8** (DEEP `-LoadUserHives`) / **2** (QUICK). See `CHANGELOG.md` 2026-07-27
  for the finding-ID churn disclosure — **re-capture any `-Baseline` snapshot taken before commit
  `6e3522b`.** `zbtest2` stays planted as the standing multi-user test fixture; do not tear it down.
  **Stage 6's live end-to-end proof is DONE (2026-07-27, see CHANGELOG.md)**: `POST /api/remediate`
  against a real hive-mounted `HKU\<SID>` `FixParam` verified applied (registry gone,
  `reports/remediation_audit_*.jsonl` hash chain manually re-verified) and, against the same class
  of finding after the hive was unmounted, correctly `blocked` with the registry left untouched.
  That testing also caught and fixed a real TOCTOU race in `/api/remediate`'s `Remediating`
  concurrency guard (flag was set inside the spawned runspace, measurably late — see CHANGELOG).
  **⚠ CORRECTION (2026-07-27 audit): P1 is NOT done. The registry half works; the FILESYSTEM half is
  effectively a no-op on any multi-user box.** The ~20 migrated filesystem sites pass all profiles'
  roots to **one** `Get-ScanFiles` call whose caps were never scaled — measured live, a single profile
  exhausts the 20,000-file / 20-second budget in **~1 second**, so profiles 2..N get **zero**
  filesystem coverage and the phases then print `[OK] NO SUSPICIOUS DUMP FILES…` (finding **P1-1**, the
  highest-leverage fix in the queue). **P1-1 is now HALF-FIXED IN THE WORKING TREE AND UNCOMMITTED:**
  `Get-ScanFiles` has gained fair-share round-robin walking, scaled caps and a truncation signal, but
  `Test-ScanTruncated`/`Add-ScanGapFinding` have **zero callers** across all 75 call sites, so the
  false all-clear is unchanged — **and the change must not be committed before the three rule-#1
  violations below are fixed** (see the boxed warning in the shared-budget rule for why landing it
  first makes a multi-user box more dangerous). Also open: **three rule-#1 violations created by the ×N
  multiplication** (Phase 106 auto-deletes signed Microsoft ProcDump; Phase 31 auto-deletes every
  developer's PowerShell profile; Phase 74 writes hardening into other users' hives), a browser-
  extension ID that **silently discards** the Edge copy of a Chrome finding, a console-remediation path
  that **re-mounts every hive and never unloads them** (TEMPORARY PROFILE outage at the users' next
  logon), dead code that makes the hive-load-cap honesty finding **unreachable**, and — notably —
  **`-LoadUserHives` cannot be passed from the GUI at all**, though the server's own block message
  tells operators to use it. The baseline of **8** is real but was captured on a **2-profile** box and
  is blind to all three rule-#1 items by construction. Full detail: `REVIEW_FINDINGS_2026-07-27.md`
  §P6. `zbtest2` stays planted as the standing multi-user test fixture; do not tear it down.
- **Next major work: Rust evidence engine + Event Viewer / IR GUI.** Operator approved a rewrite on
  2026-07-27 and the plan is `ENGINE_REWRITE_PLAN.md`: a **read-only Rust sidecar** (`zb-evidence.exe`,
  reusing the Tauri toolchain already in `native-app/`) emitting the **same `[FINDING]` JSON lines the
  server already parses — so no server change is needed to accept it**, then an **incremental**
  detection port behind a differential PS-vs-Rust harness. **Destructive remediation stays in
  PowerShell** (an unsigned binary doing KillProcess/DeleteFile is the worst possible EDR profile, and
  this runs on *client* endpoints; the real mitigation is code signing, not AV exclusions). Scope
  decided: the IR GUI does **both live view and export package**. The evidence work maps onto
  `EVIDENCE_ENGINE_PLAN.md`'s A-series in its §8 order (A1 log-availability census first). **Blocked
  on a sensitive-data policy** (plan §5.5) before the exporter is built — event logs and browser
  history carry credentials and PII.
- **Native shell (Milestone 1) — built and live-verified.** Real `.exe` rendering the real GUI,
  Job-Object-tied child process (force-kill verified), WebView2 preflight. The Three.js 3D GUI
  redesign it is a stepping stone to has **not** been started.
- **Sandbox malware testing — DONE, re-validated against current HEAD 2026-07-27, harnesses now
  live in `tools/sandbox-test/` (not a scratchpad).** History: Stage A (FULL, tripwires + EICAR:
  80/80 phases, 0 recovered errors) and Stage B (DEEP × 2 against 5 real theZoo families incl.
  KRBanker: 115/115 phases, 0 recovered errors, auto-destructive set == the known tripwires) both
  passed 2026-07-26. Stage C ran: KRBanker's detonation failed (traced to a `tar` 0-byte-extraction
  bug, not env/arch), but the remediation applied/blocked split and hash-chained audit logs were
  real and correct. Stage F found its own samples were 0-byte (same `tar` bug) so its "clean"
  result was meaningless; Stage G fixed the extraction (`7za -pinfected`, hard-fail on any 0-byte
  sample) and was the actual proof malware IS caught by content. **Both open items from that round
  are now closed:** (1) the WebView2-missing dialog redo — the 2026-07-26 "inconclusive" result was
  proven to be a stale pre-hardening `.exe` (its debug-log wording didn't even match current
  `main.rs`), not a real bug; a fresh build + `tools/sandbox-test/harness-webview2-dialog.ps1`
  produced a fully conclusive PASS (screenshot-verified dialog on screen, exit code 3, see
  CHANGELOG 2026-07-27). (2) Re-validation of the content-detection fix against current HEAD
  (post-P1, post-Build-Custom-Scan) via `tools/sandbox-test/harness-malware-detection.ps1` — also a
  clean PASS: known-hash IOC match (incl. on `Invoice_2026_Q3.pdf`), masquerading-PE, macro
  auto-exec, and YARA-lite findings all fired correctly, P1's `-LoadUserHives` path was actively
  exercised with no interference, Build Custom Scan's `-Phases` filter stayed off as expected,
  auto-destructive = 10 (sane), 0 `RECOVERED ERROR`s across 490 phase-header lines. See CHANGELOG
  2026-07-27 for full numbers. Run either harness again via
  `tools/sandbox-test/Invoke-SandboxTest.ps1 -Stage WebView2Dialog|MalwareDetection`.
  **⚠ CORRECTION (2026-07-27 audit): that "clean PASS" is not evidence.
  `harness-malware-detection.ps1` only *logs* its 13 assertion counts — every one can be `0` and it
  still writes its `*_DONE` marker and prints `DONE.` It has no verdict line, no differentiated exit
  code, and no failing state. Compounding it: a stale marker makes a re-run report success in
  milliseconds while the sandbox is still booting; `Copy-Item -Recurse` nests rather than overwrites,
  so re-runs test a **stale engine**; a failed `npx tauri build` is undetected; and the sample-integrity
  gate aborts only if *every* sample is 0 bytes (the rule is per-sample) with magic bytes computed and
  then discarded. Four of the assertions cannot fail by construction — one greps for a console banner
  the engine never emits under any condition. The run happened; it could not have failed. Neither
  harness touches `/api/remediate`, so Stage C and P1 Stage 6 are **not reproducible from
  `tools/sandbox-test/`** despite being cited as live-proven. Repairing this is a prerequisite for
  everything else — see `REVIEW_FINDINGS_2026-07-27.md` §P4.**
- **Build Custom Scan (`5769ac6`) — shipped, and its core promise is currently false.** Paste text →
  `POST /api/scan/analyze-text` → category/IOC extraction → `-Phases` filter via `Test-PhaseGate`
  (wired into all ~139 phase gates; the mechanical edit is **verified byte-identical**, QUICK still
  exactly 30 headers, and **command injection is genuinely closed** — 23 payloads tested on live 5.1).
  But: **USE THIS SCAN auto-harvests IOCs from prose into CRITICAL+KillProcess / HIGH+Quarantine
  paths** (rule #1); the suggested `TRIAGE` mode **silently drops most of the phases the panel says it
  selected** (a pasted phishing alert never runs Phase 74.5, the flagship Outlook detection, and
  reports clean); and **a pasted SHA256 can never match**, because the only phases consuming custom
  IOC hashes/filenames/IPs (90 and 36) appear in no category. See §"P0"/"P1" of the findings doc.
- **Still open / unverified:** the user-driven **browser click-through** (destructive PURGE +
  protected HARD block, export downloads, IOC save→re-scan, STEALTH, live ticker/chips, banner
  glyphs); the **USB foreign-box field test**; the **NSIS installer** (built, never installed);
  `data/coverage_matrix.json` re-audit; `tools/Build-Release.ps1` has **no `native-app` awareness**.

**The prioritized roadmap lives in `BLUEPRINT.md` §7**; `HANDOFF.md` carries per-session state;
`NEXT_STEPS.md`/`UPGRADE_PLAN.md`/`NIGHT_RUN_PLAN.md`/`REVIEW_FINDINGS_2026-07-22.md` are historical
context only — do not action their task lists without re-checking them against the code.
