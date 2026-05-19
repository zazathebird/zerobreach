# ZeroBreach V23 — Kraken Console
## Instructions for Claude Code (`_python/` subdirectory)

This document covers the Python/Flask server only. For the full project picture see `../CLAUDE.md`.

---

## WHAT THIS FOLDER IS

`_python/` contains the **optional** Flask/SocketIO server. It is one of two ways to serve the frontend — the other is `ZeroBreach-Server.ps1` (pure PowerShell, no Python needed, the default launch path).

---

## SETUP

```powershell
# From the project root:
pip install -r _python\requirements.txt
python _python\server.py
# Or via the launcher:
Launch-GUI.bat python
```

**Requirements:** Python 3.10+, Windows 10/11, admin rights.

---

## PATH LAYOUT — CRITICAL

`server.py` is in `_python/`, but all assets and the PS engine are in the **project root**. The file resolves this with:

```python
BASE_DIR = Path(__file__).parent       # _python/
ROOT_DIR = BASE_DIR.parent             # project root

PS_SCRIPT   = ROOT_DIR / "ZeroBreach-V23.ps1"
REPORTS_DIR = ROOT_DIR / "reports"

app = Flask(
    __name__,
    template_folder=str(ROOT_DIR / "gui" / "templates"),
    static_folder=str(ROOT_DIR / "gui" / "static"),
)
```

Do not change these back to relative strings — Flask resolves relative `template_folder`/`static_folder` from the module's location (`_python/`), which does not contain the GUI assets.

---

## POWERSHELL INTEGRATION

`build_ps_command()` assembles the subprocess call:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File <ROOT>/ZeroBreach-V23.ps1
  -Mode QUICK|FULL|DEEP|PARANOID|STEALTH
  -Hours 0          (0 = all time, N = last N hours)
  -Auto             (skip interactive menus)
  -OutDir <ROOT>/reports
  [-Html]           (generate HTML report)
  [-Paranoid]
  [-Stealth]
  [-IocFile path]
  [-Baseline path]
```

`run_scan()` streams stdout line-by-line into `classify_line()` → emits `log_line` / `finding` events via SocketIO. Stderr is merged into stdout (`stderr=subprocess.STDOUT`) to prevent the child process from blocking on a full stderr pipe.

**STEALTH mode** outputs JSON to stdout instead of formatted text — the current parser runs `classify_line()` on it anyway (incorrect but non-crashing). Fix: detect `config["stealth"] == True` and parse JSON.

---

## KEY FILES

| File | Purpose | Edit when |
|------|---------|-----------|
| `server.py` | Flask app, PS launcher, SocketIO bridge | Changing API routes, PS params, parsing logic |
| `requirements.txt` | Python deps | Adding packages |
| `zerobreach.spec` | PyInstaller build | Build config changes |
| `../gui/templates/index.html` | All HTML structure | Adding views, UI elements |
| `../gui/static/css/main.css` | All styling + CSS theme vars | Visual changes |
| `../gui/static/js/app.js` | All UI logic, socket handlers | Frontend behavior |

---

## SOCKET.IO EVENT REFERENCE

### Server → Client
| Event | Payload | Description |
|-------|---------|-------------|
| `connected` | `{status}` | On socket connect |
| `log_line` | `{text, severity, phase, elapsed}` | Every PS output line |
| `finding` | `{id, line, severity, threat_type, phase, timestamp}` | Threat detected |
| `scan_state` | `{phase, phase_total, phase_name, section, elapsed, threat_counts, running}` | Periodic state (1/sec via broadcaster thread) |
| `scan_complete` | `{findings_count, threat_counts, elapsed, results_path}` | PS process exited |

### Client → Server
| Event | Description |
|-------|-------------|
| `ping_state` | Request immediate `scan_state` emit |

### HTTP API
| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Serve HTML app |
| `/api/sysinfo` | GET | System info via psutil (hostname, CPU, RAM) |
| `/api/scan/start` | POST | Start scan with config JSON body |
| `/api/scan/abort` | POST | Kill PS subprocess |
| `/api/scan/state` | GET | Current scan state dict |
| `/api/findings` | GET | All findings array |
| `/api/reports` | GET | List saved report files |
| `/api/reports/<file>` | GET | Download specific report JSON |

---

## BUILDING THE .EXE

```powershell
pip install pyinstaller
pyinstaller _python\zerobreach.spec
# Output: dist/ZeroBreach.exe
```

The spec sets `uac_admin=True` for automatic elevation. Still needed:
- `assets/icon.ico` for the exe icon
- `version_info.txt` for exe metadata
- Test that hidden imports are complete (flask, flask_socketio, psutil, eventlet all need to be bundled)

---

## TASK LIST

### Priority 1 — Core
- [ ] **STEALTH mode JSON parsing**: Detect `config["stealth"]` and parse JSON stdout instead of `classify_line()`
- [ ] **Rollback snapshot path**: Parse the snapshot `.reg` path from PS output and surface it in the remediation view
- [ ] **Remediation execution**: Wire `btn-execute` to call PS remediation commands (or a second PS script reading the audit JSON)

### Priority 2 — UI
- [ ] **MITRE ATT&CK mapping**: Wire `data/mitre_mapping.json` to tag findings with technique IDs
- [ ] **Scan profiles**: Save/load named scan configs to localStorage or a JSON file
- [ ] **IOC Manager**: Wire `btn-ioc-add` / `btn-ioc-import` to update a local IOC list passed to PS via `-IocFile`
- [ ] **Report HTML export**: Add `/api/export/html` route rendering a standalone HTML report

### Priority 3 — Build
- [ ] Test `pyinstaller _python\zerobreach.spec` end-to-end
- [ ] Add `assets/icon.ico`
- [ ] Add `version_info.txt`

---

## KNOWN ISSUES

1. **STEALTH mode**: JSON output from PS is passed through `classify_line()` (incorrect). Needs dedicated JSON parser path.
2. **PS self-detection**: Phase 2 Script Block Logging may flag the script's own execution. PS script has a self-filter — verify it works in practice.
3. **Port**: `find_free_port()` scans from 5000 upward. Should be fine; if not, pass a specific port via env or arg.
4. **Admin elevation**: `server.py` must run as admin (the PS engine will re-prompt UAC otherwise). `Launch-GUI.bat` handles this for dev; `uac_admin=True` in the spec handles it for the .exe.
