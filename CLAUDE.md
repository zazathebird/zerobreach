# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

ZeroBreach V23 "Kraken Console" is a Windows-only MSP incident response tool with two interchangeable servers sitting between a cyberpunk HTML/JS frontend and a PowerShell scan engine (`ZeroBreach-V23.ps1`) that performs 107 phases of malware detection.

## Launching

```powershell
# Default — pure PowerShell server, no Python required (recommended)
Launch-GUI.bat

# Python/Flask server (needs deps installed first)
Launch-GUI.bat python
```

`Launch-GUI.bat` self-elevates to admin, then launches `ZeroBreach-Server.ps1`. Pass `python` or `py` as the first argument to use the Flask server instead. On failure the window stays open and writes `zerobreach_launch_error.log` to the project root.

## Two Server Modes

### Mode 1 — Pure PowerShell (default): `ZeroBreach-Server.ps1`
No Python required. Uses `System.Net.HttpListener` + Server-Sent Events (SSE) at `/api/events`. Spawns `ZeroBreach-V23.ps1` in a background runspace and streams its stdout via an in-process event log. The file is saved with a **UTF-8 BOM** — do not remove it. Without the BOM, PowerShell 5.1 reads the file as Windows-1252 and misparses the Unicode box-drawing characters in the startup banner (the bytes for `╔` include `0x94`, which Windows-1252 maps to `"`, corrupting all string parsing from that point on).

### Mode 2 — Python/Flask: `_python/server.py`
Flask + SocketIO bridge. Dependencies in `_python/requirements.txt` (`flask`, `flask-socketio`, `psutil`, `eventlet`).

```powershell
pip install -r _python\requirements.txt
python _python\server.py
```

**Critical path layout inside `_python/server.py`:**
```python
BASE_DIR = Path(__file__).parent           # _python/
ROOT_DIR = BASE_DIR.parent                 # project root
PS_SCRIPT   = ROOT_DIR / "ZeroBreach-V23.ps1"
REPORTS_DIR = ROOT_DIR / "reports"
# Flask is initialized with absolute paths:
template_folder = str(ROOT_DIR / "gui" / "templates")
static_folder   = str(ROOT_DIR / "gui" / "static")
```

Building the standalone .exe:
```powershell
pip install pyinstaller
pyinstaller _python\zerobreach.spec
# Output: dist/ZeroBreach.exe
```

Requirements: Python 3.10+, Windows 10/11, PowerShell 5.1+, admin rights.

## File Structure

```
zerobreach/
├── Launch-GUI.bat              <- Entry point. Double-click or run from admin shell.
├── ZeroBreach-Server.ps1       <- Pure-PS HTTP server (default, no Python needed)
├── ZeroBreach-V23.ps1          <- 107-phase PS scan engine
├── gui/
│   ├── templates/
│   │   └── index.html          <- Single-page app (the only copy; served by both servers)
│   └── static/
│       ├── css/main.css        <- Core styles + base CSS vars
│       ├── css/fx.css          <- VFX overlays, theme grid, cmd palette, danger modal, kraken cinematic
│       └── js/
│           ├── app.js          <- Main frontend logic (SSE client, views, integration)
│           ├── sound.js        <- ZBSound: synthesized Web Audio engine (no audio files)
│           ├── themes.js       <- ZBThemes: 12-theme engine + secret KRAKEN theme
│           ├── fx.js           <- ZBFX: canvas VFX renderers + intensity tiers + text FX
│           └── kraken.js       <- ZBKraken: the ~19s "kraken" unlock cinematic
├── _python/
│   ├── server.py               <- Flask/SocketIO server (alternative mode)
│   ├── requirements.txt
│   ├── zerobreach.spec         <- PyInstaller build spec
│   └── README_CLAUDE_CODE.md   <- Detailed Python-server guide (routes, events, tasks)
├── data/
│   ├── ioc_defaults.json            <- Default IOC list (ips/domains/files/hashes/regex) for -IocFile
│   ├── detection_signatures.json    <- Engine's built-in malware signatures (RAT/miner/keylogger
│   │                                   procs, C2 domains, ransomware exts, YARA-lite rules, LOLBAS).
│   │                                   Loaded at runtime by Get-Sig in ZeroBreach-V23.ps1. KEPT IN
│   │                                   DATA (not inline) so AMSI/Defender doesn't flag the script.
│   └── mitre_mapping.json           <- MITRE ATT&CK technique map (exists; not yet wired into findings)
└── reports/                    <- Auto-created at runtime, stores scan JSON results
```

When working on the Python server specifically, read `_python/README_CLAUDE_CODE.md` — it has the full HTTP route table, SocketIO event payloads, and the PyInstaller build notes in more detail than this file.

## Architecture

**Data flow (both modes):**
Browser → POST `/api/scan/start` → server spawns `ZeroBreach-V23.ps1` subprocess → stdout streamed line-by-line → parsed → events pushed to frontend in real-time.

**Three distinct layers:**
1. **Server** (`ZeroBreach-Server.ps1` or `_python/server.py`) — Hosts the web UI, manages scan state, spawns and reads the PS subprocess.
2. **`gui/static/js/app.js`** — All frontend logic. Manages view switching (boot → config → scan → remediation). Uses native `EventSource('/api/events')` (SSE) — matches the PS server. (No SocketIO; see correction below.)
3. **`ZeroBreach-V23.ps1`** — The actual scan engine. Called via subprocess with args built by `build_ps_command()` / `$psArgs`. Not modified directly for UI changes.

### Scan Engine CLI (`ZeroBreach-V23.ps1`)

The engine self-elevates (re-launches via `Start-Process -Verb RunAs`, re-passing all args) and accepts these parameters (`param()` block at the top of the file):

| Param | Values | Notes |
|---|---|---|
| `-Mode` | `QUICK \| FULL \| DEEP \| PARANOID \| STEALTH` | Empty = interactive menu |
| `-Hours` | int | `0` = all time, `N` = last N hours, `-1` (default) = interactive time-window menu |
| `-Auto` | switch | Skip all interactive menus (servers always pass this) |
| `-Html` | switch | Also emit an HTML report |
| `-Stealth` / `-Paranoid` | switch | Equivalent to selecting that mode |
| `-OutDir` | path | Defaults to `reports/`; servers pass an absolute path |
| `-IocFile` | path | Custom IOC list; format mirrors `data/ioc_defaults.json` |
| `-Baseline` | path | Prior-run baseline for diffing |
| `-Schedule` | `DAILY \| WEEKLY` | Registers a SYSTEM scheduled task (02:00) then **exits before scanning** |
| `-SmtpTo` / `-SmtpFrom` / `-SmtpServer` | string | Email delivery for scheduled runs |

Note the engine still self-identifies as "V22" in some strings (scheduled task name `ZeroBreach_V22_Scheduled`, banners) despite the V23 filename — this is intentional, not a bug to "fix".

## PowerShell Output Parsing — Critical Details

`classify_line()` in `_python/server.py` (and the inline `Classify` function in `ZeroBreach-Server.ps1`'s `SCAN_SCRIPT` runspace block) apply two independent lookups:
- **Severity** via `SEVERITY_PATTERNS` regexes: `[CRIT]`, `[WARN]`, `[OK]`, `[HUNT]`, `[INFO]`, etc. → `CRITICAL | HIGH | POSSIBLE | CLEAN | INFO | HUNT`
- **Threat type** via `THREAT_MAP` keyword lists → `RAT | Rootkit | Ransomware | Keylogger | Worm | Miner | Trojan | Spyware | Fileless | Other`

Only lines with severity `CRITICAL`, `HIGH`, or `POSSIBLE` become `finding` events. All lines become `log_line` events.

Phase headers: `PHASE_RE = re.compile(r"PHASE\s+(\d+)[^\d]")`. Phase names extracted from lines containing both `"PHASE"` and `"──"`.

**STEALTH mode:** PS outputs JSON to stdout instead of formatted text — neither server's parser handles this yet. Detect `config["stealth"] == True` and parse JSON instead of running `classify_line()`.

## SSE vs SocketIO — NOT a mismatch (corrected 2026-06-06)

Earlier docs claimed `app.js` "speaks SocketIO only" and needed reconciling with the PS
server's SSE. **This was wrong.** `gui/static/js/app.js:95` uses
`new EventSource('/api/events')` — native SSE, matching `ZeroBreach-Server.ps1`. The
transport already matches; there is nothing to reconcile. (The Python server uses SocketIO,
but the Python build is parked — see `NEXT_STEPS.md`.)

## Event Reference

| Event (server→client) | Key payload fields |
|---|---|
| `log_line` | `text, severity, phase, elapsed` |
| `finding` | `id, line, severity, threat_type, phase, timestamp` |
| `scan_state` | `phase, phase_total, phase_name, section, elapsed, threat_counts, running` |
| `scan_complete` | `findings_count, threat_counts, elapsed, results_path` |
| `sync` (SSE/PS server only) | Full state snapshot on connect/reconnect |

Client→server: `ping_state` (SocketIO) requests an immediate `scan_state` emit.

## GUI Feature Layer (added 2026-06-09, harvested from the deleted "gui from other project" folder)

The PirateLife React GUI was mined for its best ideas, ported to **vanilla JS** (no React), then
the folder was deleted. Four new JS modules load before `app.js` (order matters: sound → themes
→ fx → kraken → app):

- **`themes.js` (ZBThemes)** — 12 visible themes + secret **KRAKEN** theme, applied as inline CSS
  vars on `<body>` (wins over the legacy `body.theme-*` class rules, which remain in main.css but
  are superseded). Each theme carries a VFX profile + sound palette. Persisted: `zb_theme`,
  god-mode flag `zb_god`.
- **`fx.js` (ZBFX)** — full-viewport canvas renderers (matrix rain, linked particles, grid-floor,
  radar sweep, embers, starfield) + CSS overlay divs (scanlines/CRT/noise/vignette/aurora/alarm),
  gated by intensity tiers OFF/LITE/FULL/MAX (`zb_fx`, default `full`; LITE cap 0.55 runs static
  overlays only). Also exports `decrypt()` (scramble text reveal — used on view titles),
  `countUp()` (report/modal numbers), `shake()`.
- **`sound.js` (ZBSound)** — fully synthesized Web Audio SFX (UI blips, deploy, alerts,
  scan-complete chord, plus cinematic SFX: klaxon, thunk, shatter, sonar, kraken roar). Default ON;
  mute/volume in Settings (`zb_muted`, `zb_vol`). AudioContext unlocks on first user gesture.
- **`kraken.js` (ZBKraken)** — typing **"kraken"** anywhere triggers a ~19s skippable cinematic
  (target-lock → intrusion glitch → cipher-crack → glass shatter → 11,034m descent with sonar →
  tentacles/eyes/roar → neural-handshake veins → console reborn in the secret KRAKEN theme).
  Sets `zb_god=1`, unlocks the KRAKEN theme card + 🐙 ABYSSAL header badge + replay entry in the
  command palette.
- **In `app.js`**: command palette (**Ctrl+K** — views, scan actions, themes), danger-confirm
  modal (EXECUTE REMEDIATION requires typing `PURGE`), sound wiring throttled on scan events.
  The legacy `initParticles` background was removed (ZBFX replaces it).

## CSS Theme System

Base vars live in `:root` in `main.css`; **ZBThemes** (above) now drives theming by setting the
same vars inline on `<body>`. The old body-class themes (`.theme-orange/red/green`) still exist
in CSS but are cleared by the engine on every `apply()`.

**MSP Mode** activates by typing "msp", "gannon", or "staples" in the UI before scanning — applies the `gannon-orange` theme via ZBThemes, adds MSP badge.

## Bugs Fixed (2026-06-06) — NEXT_STEPS Phase 0

| File | Bug | Fix |
|---|---|---|
| `ZeroBreach-V23.ps1` | Hard **parse error** at `:1445` — `"...\$sm:..."` parsed as a scoped variable ref, so the whole engine failed to load (a scan would "do nothing") | `$sm:` → `${sm}` |
| `ZeroBreach-V23.ps1` | Engine blocked mid-scan on the Phase 43 VSS `Read-Host` (`:1811`); server-spawned child has no console stdin → hung forever | Guarded with `if ($Auto -or $global:GUI_MODE -or $global:STEALTH_MODE) { $vssChoice="no" }` (never auto-deletes shadows) |
| `ZeroBreach-V23.ps1` | Fix-mode prompts (3657/3673/3677/4178/4202/4374/4384) also blocked in `-Auto` | Added `if ($Auto) { reports already written; exit 0 }` right after the STEALTH JSON exit — auto mode exits before any fix-mode prompt is reached |
| `ZeroBreach-Server.ps1` | SSE loop's `$idx` never rewound after `EventLog.Clear()` on a new scan → already-open tabs went silent on re-run | Rewind `$idx = 0` when `$idx -gt $count` |
| `gui/static/js/app.js` | Non-OK `/api/scan/start` response ignored → UI stuck on `● SCANNING` forever | `.then()` throws on non-OK; `.catch()` resets `STATE.scanning`, shows `● ERROR` |

> Re-runs now work because the engine actually exits, so the scan runspace's `finally` clears
> `Running`. **Not yet validated live** — needs a Windows admin run of `Launch-GUI.bat` to
> confirm a scan reaches Phase 107 + a clean repeat run. All-`Auto`-guard check: the only
> remaining `Read-Host`/`ReadKey` hits are the `-Auto`-gated entry menus (`:713`) and the
> `-Auto`-gated shell-kill watcher (`:891`).

## Bugs Fixed (2025-05-19)

| File | Bug | Fix |
|---|---|---|
| `ZeroBreach-Server.ps1` | No UTF-8 BOM — PS5.1 read the file as Windows-1252, making box-drawing char bytes corrupt string state | Added UTF-8 BOM (`EF BB BF`) |
| `ZeroBreach-Server.ps1` | `"[ZeroBreach]..."` inside `catch {}` / `finally {}` triggered a PS5.1-specific parser crash | Changed to `'[ZeroBreach]...'` single-quoted strings + concatenation |
| `ZeroBreach-Server.ps1` | Stderr redirected but never read → child process deadlocked when stderr buffer filled | Added `$proc.BeginErrorReadLine()` to drain stderr asynchronously |
| `_python/server.py` | `PS_SCRIPT`, `REPORTS_DIR`, `template_folder`, `static_folder` all pointed inside `_python/` instead of project root | Added `ROOT_DIR = BASE_DIR.parent`; all paths now use `ROOT_DIR` |
| `ZeroBreach-V23.ps1` | `$global:TW_LABEL = "ALL TIME"` at init caused the interactive time-window menu to never display | Initialized to `""` (empty); auto mode sets `"ALL TIME"` explicitly |
| `Launch-GUI.bat` | Called nonexistent `PirateLife-GUI.ps1` | Rewrote to call `ZeroBreach-Server.ps1`; added `python` flag for Flask mode; stays open and logs errors on failure |

## AMSI / Defender — the engine must NOT carry signature literals (fixed 2026-06-06)

The #1 cause of "I clicked scan and nothing happened": **Windows Defender AMSI blocks
`ZeroBreach-V23.ps1` at load** (`ScriptContainedMaliciousContent`, exit 1, ~0.7s, no output)
because a malware hunter is full of signature strings (mimikatz, cobaltstrike, `sekurlsa::`,
`VirtualAlloc|WriteProcessMemory`, etc.) that AMSI can't distinguish from real malware. The
server then spawns it, gets nothing, and writes an empty `audit_*.json` → UI shows "complete."

**Fix / rule:** keep all malware-signature literals in **`data/*.json`**, loaded at runtime via
`Get-Content|ConvertFrom-Json` (data files are NOT AMSI-scanned). The IOC databases were moved to
`data/detection_signatures.json` and are loaded by `Get-Sig` (~`ZeroBreach-V23.ps1:639`). **Never
re-introduce signature literals into the `.ps1`.** ~15 inline attack-regexes remain (didn't trip
current defs but should be externalized for cross-machine robustness — see `UPGRADE_PLAN.md` WS1).
A Defender exclusion is NOT required. To AMSI-test, run the engine with a **path-only** command
line (signature words on a cmdline make Defender block the *spawn* with EPERM).

## Known Gotchas

- **STEALTH mode** outputs JSON, not formatted text — current parser ignores it (see above).
- **PS self-detection**: Phase 2 Script Block Logging may flag the script's own execution; the PS script has a self-filter but verify it works.
- **Admin elevation**: Both servers self-elevate. `Launch-GUI.bat` also checks admin before launching.
- **Encoding**: PS subprocess output uses `encoding="utf-8", errors="replace"` in the Python server.
- **Port**: `ZeroBreach-Server.ps1` uses `Get-FreePort` (TcpListener on port 0); `_python/server.py` uses `find_free_port()` scanning from 5000.
- **Frontend transport**: `app.js` uses native SSE (`EventSource('/api/events')`), matching the PS server. There is no SocketIO/SSE mismatch (this corrects an earlier note).

## Outstanding Work

> **Major detection/quality upgrade is planned in `UPGRADE_PLAN.md`** ("Opus treatment" — expand
> malware coverage, MITRE tagging, performance, externalize all signatures to `data/*.json`,
> using multiple sub-agents). Start there after a /clear. Phases 0 & 1 of `NEXT_STEPS.md` and the
> AMSI block are DONE (2026-06-06); the live Phase-107 GUI run is the last unvalidated item.

**Core (see `NEXT_STEPS.md` for the prioritized, PowerShell-only plan):** ~~scan-blocking `Read-Host` prompts~~ and ~~scan-state reset / re-run handling~~ are DONE (Phase 0, 2026-06-06 — pending a live admin run to validate). Remaining: **USB portability (Phase 1 — next)**, STEALTH mode JSON parsing, MITRE tagging via `data/mitre_mapping.json`, surface rollback snapshot path, wire `btn-execute` to actual remediation.

**UI:** ~~Cinematic VFX / themes / sound / command palette~~ DONE 2026-06-09 (see "GUI Feature
Layer" above). Remaining: per-phase progress parsing, MITRE ATT&CK tagging
(`data/mitre_mapping.json`), scan profile save/load, IOC Manager wired to `-IocFile` param,
`/api/export/html` HTML report endpoint.

**Build:** Test PyInstaller spec (`_python/zerobreach.spec`), add `assets/icon.ico`, create `version_info.txt` for .exe metadata.
