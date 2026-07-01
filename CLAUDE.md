# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repo.

> **Detailed bug-fix history and the 5 rounds of FP tuning live in `CHANGELOG.md`.** This file
> keeps the durable **rules** only. When you fix something noteworthy, add a dated entry to
> `CHANGELOG.md` and, if it produces a new "never do X" lesson, a rule below.

## What This Project Is

ZeroBreach V23 "Kraken Console" is a **Windows-only MSP incident-response tool**: a PowerShell HTTP
server sits between a cyberpunk HTML/JS frontend and a PowerShell scan engine (`ZeroBreach-V23.ps1`)
that runs **~115 phases** of malware detection. A parked Python/Flask server (`_python/server.py`) is
an alternative to the PS server. The engine still self-identifies as "V22" in some strings (scheduled
task name `ZeroBreach_V22_Scheduled`, banners) — **intentional, not a bug to fix.**

## Launching

```powershell
Launch-GUI.bat            # Default — pure PowerShell server, no Python (recommended)
Launch-GUI.bat python     # Python/Flask server (needs deps installed first)
```

`Launch-GUI.bat` self-elevates to admin, then launches `ZeroBreach-Server.ps1`. On failure the window
stays open and writes `zerobreach_launch_error.log` to the project root. Requires Windows 10/11,
PowerShell 5.1+, admin rights.

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
│   ├── Phases-1.ps1            Sections 1-11, phases 1-58 (incl. 55.5 BYOVD)
│   ├── Phases-2.ps1            Sections 12-16 front, phases 59-89 (incl. 69 mutex, 74.5/.6/.7)
│   ├── Phases-3.ps1            if($PhasePlan.Advanced) 90-105+ (incl. 99.5) + Integrity 108-115
│   ├── Summary.ps1             risk score + audit summary + stealth/auto exits
│   └── FixMode.ps1             fix-mode entry, rollback snapshot, Invoke-FixMode
├── gui/
│   ├── templates/index.html    Single-page app (the only copy; served by both servers)
│   └── static/
│       ├── css/main.css        Core styles + base :root CSS vars
│       ├── css/fx.css          VFX overlays, cmd palette, danger modal, cinematic FX toggles
│       └── js/  (load order: sound → themes → fx → kraken → app)
│           ├── app.js          SSE client, views, cmd palette (Ctrl+K), PURGE modal, CINE_FX
│           ├── sound.js        ZBSound — synthesized Web Audio SFX (no audio files)
│           ├── themes.js       ZBThemes — 12 themes + secret KRAKEN theme (inline body CSS vars)
│           ├── fx.js           ZBFX — canvas renderers + intensity tiers OFF/LITE/FULL/MAX
│           └── kraken.js       ZBKraken — ~19s "kraken" unlock cinematic
├── _python/                    Parked Flask/SocketIO server + PyInstaller spec (see README there)
├── data/
│   ├── ioc_defaults.json            Default IOC list for -IocFile
│   ├── detection_signatures.json    Malware signatures + fp_allowlists. Loaded by Get-Sig. KEPT IN
│   │                                DATA so AMSI/Defender doesn't flag the engine (see rules).
│   ├── mitre_mapping.json           MITRE ATT&CK technique map (wired into findings)
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
| `-Mode` | `QUICK \| FULL \| DEEP \| PARANOID \| STEALTH` | Empty = interactive menu |
| `-Hours` | int | `0` = all time, `N` = last N hours, `-1` (default) = interactive menu |
| `-Auto` | switch | Skip all menus (servers always pass this) |
| `-Html` | switch | Also emit an HTML report |
| `-Stealth` / `-Paranoid` | switch | Equivalent to selecting that mode |
| `-OutDir` | path | Defaults to `reports/`; servers pass an absolute path |
| `-IocFile` | path | Custom IOC list (format mirrors `data/ioc_defaults.json`) |
| `-Baseline` | path | Prior-run baseline for diffing |
| `-Schedule` | `DAILY \| WEEKLY` | Registers a SYSTEM scheduled task (02:00), then **exits before scanning** |
| `-SmtpTo` / `-SmtpFrom` / `-SmtpServer` | string | Email delivery for scheduled runs |

### Output parsing + events

`Classify` (PS runspace) / `classify_line()` (`_python/server.py`) apply two lookups:
- **Severity** via `SEVERITY_PATTERNS`: `[CRIT]`/`[WARN]`/`[OK]`/`[HUNT]`/`[INFO]` → `CRITICAL |
  HIGH | POSSIBLE | CLEAN | INFO | HUNT`.
- **Threat type** via `THREAT_MAP` → `RAT | Rootkit | Ransomware | Keylogger | Worm | Miner | Trojan
  | Spyware | Fileless | Other`.

Only `CRITICAL`/`HIGH`/`POSSIBLE` lines become `finding` events; all lines become `log_line` events.
Phase headers: `PHASE\s+(\d+)[^\d]`. **Only CRITICAL/HIGH + a destructive FixAction is auto-selected
for remediation** — POSSIBLE is shown but never auto-acted-on (the lever behind every FP downgrade).

| Event (server→client) | Key payload fields |
|---|---|
| `log_line` | `text, severity, phase, elapsed` |
| `finding` | `id, line, severity, threat_type, phase, mitre {id,name,tactic,url}, mitre_id, timestamp` |
| `scan_state` | `phase, phase_total, phase_name, section, elapsed, threat_counts, running` |
| `scan_complete` | `findings_count, threat_counts, elapsed, results_path, engine_report` |
| `remediation_complete` | `applied, failed, skipped, blocked` |
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
2. **Datto / CentraStage / Kaseya are legitimate RMM partner tooling** — not malware. Still flag them
   if something is genuinely off (vendor name in a suspicious path, or an independent malicious signal).

### PowerShell engine safety (`ZeroBreach-V23.ps1`)
- **Never call these raw in a phase body — use the safe wrapper:** `Get-AuthenticodeSignature` →
  `Get-AuthSig`; `Get-ItemPropertyValue` → `Get-RegVal`; `Get-WinEvent -FilterHashtable` →
  `Get-WinEventSafe`; `Get-FileHash` → `Get-FileHashSafe`. `-EA SilentlyContinue` does **not** suppress
  the terminating "property/parameter" errors these throw; unhandled, they unwind to the script-scope
  trap and skip whole phase groups.
- **Never pipe `Get-ScanFiles` directly** into `Where-Object`/`ForEach-Object` — its `return ,$arr`
  makes the whole array arrive as **one** item, so the filter silently matches everything (or nothing).
  Wrap in parens `(Get-ScanFiles …) | …` or assign to a var first. `@(Get-ScanFiles …)` does NOT fix it.
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
- When bundling multiple phases under one `if ($PhasePlan.*)`, give the block its own inner
  `trap { Write-RecoveredError $_; continue }` (resumes at the next phase, not end-of-group).
- **Validate on live `powershell.exe` 5.1**, not a PS-7 simulation — the unwrap / `(try{})` /
  `,$arr` behaviors only surface on the real 5.1 runtime. Keep the engine **parse-clean on 5.1 + 7**
  and the **UTF-8 BOM** intact.

### AMSI / signatures
- **Never put malware-signature literals in the `.ps1`** — Defender AMSI blocks the engine at load
  (`ScriptContainedMaliciousContent`, exit 1, no output → "scan did nothing"). All signatures live in
  `data/detection_signatures.json`, loaded at runtime via `Get-Sig` (data files aren't AMSI-scanned).
- **FP allowlists are NOT signatures** — they go in the `fp_allowlists` block of that same JSON, loaded
  via `Join-AllowRegex` (empty key → `(?!)`, suppresses nothing). No new literal lists in the `.ps1`.
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
- **The GUI phase counter is driven by `scan_state`, throttled to every 12 log lines** — any UI element
  that must track phase precisely needs a phase-change-triggered emit, not the `%12` tick. When a user
  reports "skipped phases," first grep the `KrakenConsole_*.log` for `PHASE N — … took` + `RECOVERED
  ERROR` — usually it's display cadence, not a dropped phase. **BUT since the engine split, a genuine
  skip IS possible**: if a phase module is missing its top-level `trap` (see the Engine-split rules), a
  terminating error drops every remaining phase in that module. Confirm by checking the log for a
  contiguous `PHASE N — … took` sequence — a hard gap (e.g. 16 → 59) right after a `RECOVERED ERROR`
  means a module trap is missing, not display cadence.

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
- **HTTP routes** (`ZeroBreach-Server.ps1`): `GET /api/export/html|csv` (server-rendered download from
  current findings); `GET|POST /api/ioc` (IOC Manager — POST writes both the JSON sidecar and
  `reports/custom_iocs.ioc` in the engine's **prefixed** text format `hash:`/`ip:`/`domain:`/`regex:`/
  `file:`, then feeds it to the next scan via `-IocFile`); `GET /api/report?name=<file>` (rich engine
  findings with `FixAction`/`FixParam`, MITRE-enriched; name validated `^(KrakenBaseline_|audit_).*\.json$`);
  `POST /api/remediate {report, ids[]}` (spawns `$script:REMEDIATE_SCRIPT`, mirrors the engine's
  `Invoke-FixMode` switch — DeleteFile/DeleteReg/DeleteRegKey/KillProcess/RunCmd/Quarantine — streams
  `[FIX]` lines then `remediation_complete`; report path basename-locked to `reports/`).
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

## Outstanding Work

The bulk of the roadmap is **done and merged** (scan-blocking prompts, re-run handling, MITRE, IOC
Manager, HTML/CSV export, STEALTH parsing, real remediation, safety guard, FP rounds 1–5, VFX/themes/
sound). **The last standing item is a full live admin `Launch-GUI.bat` browser run** exercising export
downloads, IOC save→scan, STEALTH, and destructive remediation end-to-end (server/API layer already
validated headless — see memory). Then: USB portability, per-phase progress parsing, scan profile
save/load. See `NEXT_STEPS.md` for the prioritized plan and `UPGRADE_PLAN.md` for the larger detection
upgrade. **Build**: test the PyInstaller spec, add `assets/icon.ico` + `version_info.txt`.
