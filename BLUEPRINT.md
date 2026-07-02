# ZeroBreach V23 "Kraken Console" — Product Blueprint

> **The definitive top-level map of what this tool is, how it fits together, and where it goes
> next.** Rules live in `CLAUDE.md`; history lives in `CHANGELOG.md`; session state lives in
> `HANDOFF.md`. This file changes only when the product itself changes shape.
> Last structural update: 2026-07-02.

## 1. Mission

A **single-operator, USB-portable, zero-install Windows incident-response console** for MSP
techs. One double-click (`Launch-GUI.bat`) on any Windows 10/11 box gives you:

1. **Detect** — ~115 scan phases covering the full malware taxonomy (RAT/C2, ransomware,
   rootkits, keyloggers, worms, miners, trojans, spyware, fileless/LOLBins, persistence,
   credential theft, exfil, email/phishing, BYOVD, permission integrity).
2. **Decide** — findings triaged with severity, MITRE ATT&CK technique, threat type, a
   3-layer *protected-target* hard block, and a trusted-vendor soft signal, so an operator
   can trust the checklist.
3. **Act** — reversible, operator-confirmed remediation (Quarantine-first; type `PURGE` to
   execute), with a hard rule that **nothing auto-selected can ever damage a healthy system**.
4. **Report** — engine JSON/TXT/HTML + server-rendered HTML/CSV export + durable server logs.
5. **Look epic** — a cyberpunk cinematic frontend (12 themes + secret KRAKEN, synthesized
   sound, canvas VFX, command palette) that makes the scan *feel* like the event it is.

Non-goals: offensive tooling, host-AV evasion, darkweb/Tor intel, non-Windows targets.
The Python/Flask server is **parked** — PowerShell-only direction (see `_python/README_CLAUDE_CODE.md`).

## 2. Architecture

```
Launch-GUI.bat  (self-elevates → admin)
   └─ ZeroBreach-Server.ps1          pure-PS HttpListener server, SSE at /api/events
        ├─ serves gui/  (index.html + css + js: sound→themes→fx→kraken→app)
        ├─ scan runspace ── spawns ── powershell.exe ZeroBreach-V23.ps1 -Auto …
        │     stdout (UTF-8) ─→ parse loop ─→ SSE events ─→ browser
        ├─ remediation runspace ($script:REMEDIATE_SCRIPT — mirrors Invoke-FixMode)
        └─ reports/  (baseline JSON, HTML, console + SSE logs, quarantine vault)

ZeroBreach-V23.ps1  = THIN LOADER  (params/elevation/globals/ALL helpers/banner/menus)
   └─ dot-sources, in order, into ONE scope:
        engine/Phases-1.ps1   phases 1-58   (incl. 55.5 BYOVD)      ┐ each module has its
        engine/Phases-2.ps1   phases 59-89  (incl. 69, 74.5/.6/.7)  │ OWN top-level trap
        engine/Phases-3.ps1   phases 90-115 (incl. 99.5)            ┘ (see CLAUDE.md)
        engine/Summary.ps1    risk score + exits ([Environment]::Exit)
        engine/FixMode.ps1    interactive fix mode (console runs only)

data/    detection_signatures.json (signatures + fp_allowlists — AMSI rule: NEVER inline)
         mitre_mapping.json · ioc_defaults.json · coverage_matrix.json · permission_baseline.json
```

**Why this shape holds:** phases run in numeric order and share variables across phases, so
modules split **by range, not category**, and dot-source into one scope. All signature
literals live in `data/*.json` because AMSI blocks a `.ps1` containing them. Both `.ps1`
entry files + all engine modules are UTF-8 **with BOM**; JSON outputs are UTF-8 **no BOM**.

## 3. Data contracts

### Engine → server (stdout of the child process, UTF-8)
| Line shape | Meaning |
|---|---|
| `[FINDING] {compact JSON}` | **Authoritative live finding** — emitted by `Add-Finding` in non-interactive runs. Keys: `id, sev, phase, tt, desc, target, fix, group`. The server converts CRITICAL/HIGH/POSSIBLE into SSE `finding` events (exact severity, canonical threat bucket, MITRE-resolved) and never shows the raw line. |
| `PHASE N — …` banner / `PHASE N — … took X.Xs` | Phase tracking (`PHASE\s+(\d+(?:\.\d+)?)[^\d]` — fractional phases keep their decimal and advance the counter) + per-phase profiling. |
| everything else | `log_line` (severity regex-classified for coloring only — **never** into findings). |
| STEALTH mode | one compressed-JSON audit blob on stdout; server buffers + parses post-exit. |

### Server → browser (SSE `/api/events`)
| Event | Key fields |
|---|---|
| `log_line` | `text, severity, phase, elapsed` |
| `finding` | `id, line, severity, threat_type, phase, mitre{id,name,tactic,url}, mitre_id, fix_action, target, timestamp` |
| `scan_state` | `phase, phase_total, phase_name, section, elapsed, threat_counts, running` — emitted on **every phase change** + every 12 lines |
| `scan_complete` | `findings_count, threat_counts, elapsed, results_path, engine_report` |
| `remediation_complete` | `applied, failed, skipped, blocked` |
| `sync` | full state snapshot on (re)connect |

At `scan_complete` the frontend **replaces** its live findings list with the engine report
(`GET /api/report?name=KrakenBaseline_….json` — rich findings incl. `FixAction`/`FixParam`),
so the live stream drives the in-scan experience and the report drives triage/remediation.

### Other formats
- **IOC file** (`reports/custom_iocs.ioc`, fed via `-IocFile`): prefixed text — `hash:`/`ip:`/
  `domain:`/`regex:`/`file:` (mirrors `data/ioc_defaults.json`).
- **Quarantine manifest**: file moved to `reports/quarantine/*.quar` + `.quar.json` with
  original path, SHA256, restore command.
- **HTTP routes**: `/api/scan/start|abort`, `/api/state`, `/api/events`, `/api/report?name=`,
  `/api/remediate {report, ids[]}`, `/api/export/html|csv`, `/api/ioc` GET/POST, `/api/sysinfo`.

## 4. Safety model (the product's spine)

1. **Auto-select rule**: only CRITICAL/HIGH **+** a destructive FixAction is ever pre-ticked.
   POSSIBLE is shown, never auto-acted. Every FP-tuning round works by downgrading to
   POSSIBLE/Info, not deleting detections.
2. **Rule #1**: never ship a destructive `FixParam` an auto-select can fire on a **healthy
   box** (no `icacls /reset /T`, `vssadmin delete shadows /all`, drive-root or recursive
   deletes). Dangerous commands go in the *description* with `FixAction Info`.
3. **`Test-ProtectedTarget` = HARD block across 3 layers** (server tag → frontend disable →
   remediation-runspace refusal reporting `blocked`): cert store, Windows/System32/SysWOW64/
   WinSxS, shell-system files, user dotfiles, SafeBoot/core-OS registry, critical processes.
4. **`Test-VendorTrusted` = SOFT signal** (Datto/CentraStage/Kaseya/…): green badge, not
   auto-selected, operator can still act; suspicious path or independent malicious signal
   overrides the trust.
5. **Quarantine over DeleteFile** for anything not hash-confirmed. Fully reversible.
6. Engine in `-Auto` is **audit-only** — remediation happens only through the GUI's typed
   `PURGE` confirmation.

Regression metric: **auto-destructive count from a full `-Hours 0` DEEP baseline** — currently
**52**, all by-design (tripwires + posture items + known 1-off FPs awaiting user sign-off).
Re-grade after any severity/FixAction change.

## 5. Quality gates (all must pass before a change ships)

1. Parse-clean on **live PS 5.1** and PS 7 — all 6 engine files + server (+ the server's
   here-strings extracted and `ParseInput`-checked separately); UTF-8 BOM intact.
2. `node --check` on touched JS; FX audit `node tools/check-visuals.mjs` (PASS 13/13).
3. AMSI: engine spawns and streams (no `ScriptContainedMaliciousContent`).
4. Headless `-Auto` scan: contiguous `PHASE N — … took` sequence (no module-trap gaps),
   clean self-exit, reports written.
5. Auto-destructive re-grade vs. baseline (target: 52, and 0 system-damage FixParams).
6. Live GUI acceptance for UX-facing changes (`Launch-GUI.bat` as admin; tripwires in
   `CLAUDE.md` → "Remediation test tripwires").

## 6. Status snapshot — 2026-07-02

**Proven live:** the engine-split architecture end-to-end in the browser (2026-07-01 DEEP run:
115 phases contiguous, 0 recovered errors, ~9.5 min, clean exit); phase-counter fix `c0477ae`
**validated** from the SSE log (all 116 phase values 0→115, no jumps); FP tuning through
round 5 (52 auto-destructive, 0 damage ops); 3-layer safety guard incl. a real blocked
remediation POST; all server routes headless-validated.

**Fixed 2026-07-02 (this session, from the SSE-log analysis):** the live finding stream was
dead — engine finding lines carry no severity tags, so a full DEEP run produced **0** SSE
`finding` events / all-zero threat counts / an empty server `audit_*.json` while the engine
recorded 288 findings. Now: `Add-Finding` emits structured `[FINDING]` JSON lines and the
server converts them into exact-severity `finding` events (contract in §3). Also fixed:
child-process stdout mojibake (engine now sets UTF-8 console encoding when redirected); the
`[OK ]`-padding classifier miss; and the `$sev`/`$SEV` case-insensitive variable shadow that
had silently disabled ALL log-line severity classification since the server was written
(dict renamed `$SEV_RX`). Server text-severity finding path retired (double-count guard).
End-to-end server-driven validation scans confirmed finding events stream live with exact
severities, resolved MITRE, populated threat counts, and a non-empty `audit_*.json`.

**Open acceptance item (the one):** browser click-through of destructive remediation
(PURGE + protected HARD block), HTML/CSV export downloads, IOC save→re-scan, STEALTH run —
now also eyeballing the live finding ticker/chips + clean banner glyphs. Runbook in
`HANDOFF.md`.

## 7. Roadmap

### Now (current/next session)
- **Live GUI click-through** (user-driven; runbook in `HANDOFF.md`) — closes the last
  acceptance gap and visually confirms the new live-finding stream + UTF-8 banners.
- Push the unpushed local commits on `main`.

### Done 2026-07-02 — portable distribution
`tools/Build-Release.ps1` builds the transferable artifact: validates every script
(parse + BOM) and data file (JSON), stages runtime files only, writes
`dist/ZeroBreach-V23_<stamp>.zip` + SHA256 sidecar (`-OutDir` targets a USB directly;
`-IncludePython` optional). The server self-unblocks its runtime tree at startup
(Mark-of-the-Web). **Proven:** extracted release to a spaced path → server boots, GUI
serves HTTP 200, `/api/state` answers. Remaining field test: a real *foreign* box (not
the dev machine) per the item below.

### Next (high value, ordered)
1. **WS3 — FP-tune the WS2 detections** (55.5/53/62/66/69/99.5) from fresh live DEEP
   baselines; re-grade to hold 52 (or ask user sign-off on the known 1-off FP list in
   `HANDOFF.md`).
2. **Round-4/5 leftover FPs** needing user sign-off: P48/P94 Python LocalCache, P53
   Sysinternals readme, P63 LGHUB config, P90 scratchpad scripts, P96 printer-driver DLL,
   P20 bare-`AppData` Run-key term.
3. ~~**Per-phase progress truth**~~ **DONE 2026-07-02** — the server's phase regex now
   captures fractional phases (55.5, 74.5/.6/.7, 99.5); they advance the counter/progress
   as real plan steps, findings carry the true fractional phase, and MITRE resolves their
   dedicated `phase_map` keys (previously unreachable). `phase_total` stays the plan
   ceiling per mode (30/80/115, mirroring the loader's `$PhasePlan`).
4. **Scan profiles** — save/load named config presets (mode/hours/IOC file/flags) via a
   small JSON sidecar + GUI picker.
5. **Coverage matrix re-audit (WS0)** — `data/coverage_matrix.json` was generated against
   the work-rig engine; regenerate against `main` and publish the gap list.
6. **USB portability field test** — extract a `Build-Release.ps1` zip on a **non-dev** box
   (spaced path already proven locally); confirm SmartScreen/Unblock flow, URL-ACL fallback,
   and reports landing beside the extracted copy.

### Later
- **WS4 performance**: parallelize independent phases (runspace pools, PS-5.1-safe), cache
  CIM/signature lookups; target a sub-2-minute QUICK.
- **WS5 reporting**: richer executive summary, per-tactic MITRE rollup, trend/diff view
  across baselines (`-Baseline` is already wired).
- **Scheduled scans productized**: `-Schedule` + SMTP delivery hardening, plus a GUI panel.
- **Build**: zip-with-BAT distribution is DONE (`tools/Build-Release.ps1`). PyInstaller for
  the parked Python server stays deprioritized; optional polish: `assets/icon.ico`, a signed
  launcher, or PS2EXE if SmartScreen friction ever matters.
- **Fleet ideas** (multi-box): central drop-folder for baselines + a compare view.

## 8. Doc map

| File | Role |
|---|---|
| `BLUEPRINT.md` | This file — product shape + roadmap. Start here. |
| `CLAUDE.md` | Hard rules + subsystem reference for anyone editing code. |
| `HANDOFF.md` | Current session state + the live-GUI runbook. |
| `CHANGELOG.md` | Dated narrative of every fix/tuning round. |
| `NEXT_STEPS.md` / `UPGRADE_PLAN.md` | Historical work plans (superseded by §7; kept for context). |
| `_python/README_CLAUDE_CODE.md` | Parked Python server spec. |
