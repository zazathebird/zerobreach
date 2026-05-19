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
│   │   └── index.html          <- Single-page app (also a copy at gui/index.html)
│   └── static/
│       ├── css/main.css        <- All styles + theme CSS vars
│       └── js/app.js           <- All frontend logic (SocketIO client)
├── _python/
│   ├── server.py               <- Flask/SocketIO server (alternative mode)
│   ├── requirements.txt
│   └── zerobreach.spec         <- PyInstaller build spec
├── data/
│   └── mitre_mapping.json      <- ATT&CK mappings (not yet created)
└── reports/                    <- Auto-created at runtime, stores scan JSON results
```

## Architecture

**Data flow (both modes):**
Browser → POST `/api/scan/start` → server spawns `ZeroBreach-V23.ps1` subprocess → stdout streamed line-by-line → parsed → events pushed to frontend in real-time.

**Three distinct layers:**
1. **Server** (`ZeroBreach-Server.ps1` or `_python/server.py`) — Hosts the web UI, manages scan state, spawns and reads the PS subprocess.
2. **`gui/static/js/app.js`** — All frontend logic. Manages view switching (boot → config → scan → remediation). Currently uses SocketIO — not yet wired for the PS server's SSE transport.
3. **`ZeroBreach-V23.ps1`** — The actual scan engine. Called via subprocess with args built by `build_ps_command()` / `$psArgs`. Not modified directly for UI changes.

## PowerShell Output Parsing — Critical Details

`classify_line()` in `_python/server.py` (and the inline `Classify` function in `ZeroBreach-Server.ps1`'s `SCAN_SCRIPT` runspace block) apply two independent lookups:
- **Severity** via `SEVERITY_PATTERNS` regexes: `[CRIT]`, `[WARN]`, `[OK]`, `[HUNT]`, `[INFO]`, etc. → `CRITICAL | HIGH | POSSIBLE | CLEAN | INFO | HUNT`
- **Threat type** via `THREAT_MAP` keyword lists → `RAT | Rootkit | Ransomware | Keylogger | Worm | Miner | Trojan | Spyware | Fileless | Other`

Only lines with severity `CRITICAL`, `HIGH`, or `POSSIBLE` become `finding` events. All lines become `log_line` events.

Phase headers: `PHASE_RE = re.compile(r"PHASE\s+(\d+)[^\d]")`. Phase names extracted from lines containing both `"PHASE"` and `"──"`.

**STEALTH mode:** PS outputs JSON to stdout instead of formatted text — neither server's parser handles this yet. Detect `config["stealth"] == True` and parse JSON instead of running `classify_line()`.

## SSE vs SocketIO — Known Mismatch

`ZeroBreach-Server.ps1` pushes events via raw SSE at `/api/events`. `_python/server.py` pushes via SocketIO. `app.js` currently speaks SocketIO only. When using the PS server as the backend, the frontend transport layer needs to be reconciled (either add an SSE client path in `app.js` or wrap the SSE stream in a SocketIO-compatible shim).

## Event Reference

| Event (server→client) | Key payload fields |
|---|---|
| `log_line` | `text, severity, phase, elapsed` |
| `finding` | `id, line, severity, threat_type, phase, timestamp` |
| `scan_state` | `phase, phase_total, phase_name, section, elapsed, threat_counts, running` |
| `scan_complete` | `findings_count, threat_counts, elapsed, results_path` |
| `sync` (SSE/PS server only) | Full state snapshot on connect/reconnect |

Client→server: `ping_state` (SocketIO) requests an immediate `scan_state` emit.

## CSS Theme System

All colors are CSS variables in `:root`. Four themes toggled by body class:
- (none) — Kraken Blue `#00D4FF`
- `.theme-orange` — Gannon Orange `#FF6B00` (MSP mode)
- `.theme-red` — Threat Red `#FF0033`
- `.theme-green` — Ghost Green `#00FF88`

**MSP Mode** activates by typing "msp", "gannon", or "staples" in the UI before scanning — applies `.theme-orange`, disables typewriter delays, adds MSP badge.

## Bugs Fixed (2025-05-19)

| File | Bug | Fix |
|---|---|---|
| `ZeroBreach-Server.ps1` | No UTF-8 BOM — PS5.1 read the file as Windows-1252, making box-drawing char bytes corrupt string state | Added UTF-8 BOM (`EF BB BF`) |
| `ZeroBreach-Server.ps1` | `"[ZeroBreach]..."` inside `catch {}` / `finally {}` triggered a PS5.1-specific parser crash | Changed to `'[ZeroBreach]...'` single-quoted strings + concatenation |
| `ZeroBreach-Server.ps1` | Stderr redirected but never read → child process deadlocked when stderr buffer filled | Added `$proc.BeginErrorReadLine()` to drain stderr asynchronously |
| `_python/server.py` | `PS_SCRIPT`, `REPORTS_DIR`, `template_folder`, `static_folder` all pointed inside `_python/` instead of project root | Added `ROOT_DIR = BASE_DIR.parent`; all paths now use `ROOT_DIR` |
| `ZeroBreach-V23.ps1` | `$global:TW_LABEL = "ALL TIME"` at init caused the interactive time-window menu to never display | Initialized to `""` (empty); auto mode sets `"ALL TIME"` explicitly |
| `Launch-GUI.bat` | Called nonexistent `PirateLife-GUI.ps1` | Rewrote to call `ZeroBreach-Server.ps1`; added `python` flag for Flask mode; stays open and logs errors on failure |

## Known Gotchas

- **STEALTH mode** outputs JSON, not formatted text — current parser ignores it (see above).
- **PS self-detection**: Phase 2 Script Block Logging may flag the script's own execution; the PS script has a self-filter but verify it works.
- **Admin elevation**: Both servers self-elevate. `Launch-GUI.bat` also checks admin before launching.
- **Encoding**: PS subprocess output uses `encoding="utf-8", errors="replace"` in the Python server.
- **Port**: `ZeroBreach-Server.ps1` uses `Get-FreePort` (TcpListener on port 0); `_python/server.py` uses `find_free_port()` scanning from 5000.
- **Frontend transport mismatch**: `app.js` speaks SocketIO; the PS server uses raw SSE. Do not break the SocketIO client code until the SSE path is also implemented.

## Outstanding Work

**Core:** Reconcile frontend SSE vs SocketIO transport, STEALTH mode JSON parsing, surface rollback snapshot path to remediation view, wire `btn-execute` to actual remediation commands.

**UI:** Per-phase progress parsing, MITRE ATT&CK tagging (`data/mitre_mapping.json`), scan profile save/load, IOC Manager wired to `-IocFile` param, `/api/export/html` HTML report endpoint.

**Build:** Test PyInstaller spec (`_python/zerobreach.spec`), add `assets/icon.ico`, create `version_info.txt` for .exe metadata.
