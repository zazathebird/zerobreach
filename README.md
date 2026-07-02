# ZeroBreach V23 - "Kraken Console"

Windows-only MSP incident-response / malware-detection tool. A PowerShell scan engine
(~115 phases) behind a local web GUI, with MITRE ATT&CK tagging, a hard safety guard on
remediation, and reversible quarantine. Runs from any folder (USB-portable). Admin required.

---

## Quick start (the normal way)

1. Double-click **`Launch-GUI.bat`** (or run it from a terminal).
2. Approve the UAC prompt - it self-elevates to admin.
3. Your browser opens the Kraken Console. Click **Run / Start Scan**.
4. Watch findings stream live; a JSON report lands in **`reports\`** when done.

That is it. No install, no Python, no internet needed.

---

## Deploy to another machine (copy / download / USB)

The tool is a self-contained folder - PowerShell 5.1 (built into every Windows 10/11) is the
only dependency. Two ways to move it:

**A. Build a release zip (recommended - clean runtime files only):**
```powershell
powershell -ExecutionPolicy Bypass -File tools\Build-Release.ps1
```
This validates every script (parse + BOM) and data file (JSON), then writes
`dist\ZeroBreach-V23_<stamp>.zip` + a `.sha256` sidecar. Add `-OutDir D:\` to write straight
to a USB stick, `-IncludePython` to bundle the parked Flask server.

**B. Just copy the whole folder** (works fine; brings dev files and old reports along).

**On the target box:**
1. Copy the zip over (verify the `.sha256` if it traveled through email/cloud).
2. Right-click the zip → **Properties → Unblock** → OK. (Clears the Mark-of-the-Web that
   downloads/transfers stamp on files; skipping this can trigger SmartScreen warnings on
   first launch. The server also self-unblocks its runtime tree at startup as a fallback.)
3. **Extract All** → open the `ZeroBreach\` folder → double-click **`Launch-GUI.bat`** →
   approve UAC. Done - reports land in the extracted folder's `reports\`.

Needs: Windows 10/11, admin rights, a writable location (not a read-only/ejected drive).
No internet, no installs, no Defender exclusions (signatures live in `data\*.json`
specifically so AMSI doesn't flag the engine).

### Alternative server (optional, parked)
`Launch-GUI.bat python` uses the Flask/SocketIO server in `_python\` instead. This build is
**not maintained** right now - use the default PowerShell server.

---

## Requirements
- Windows 10/11, PowerShell 5.1+
- Administrator rights (auto-elevates)
- Nothing else for the default mode

---

## Scan modes
Pick in the GUI, or pass `-Mode` on the CLI.

| Mode | Roughly |
|---|---|
| `QUICK` | Fast pass, phases 1-30 |
| `FULL` | Standard full audit |
| `DEEP` | Full + deeper/slower checks |
| `PARANOID` | Most aggressive heuristics, more findings (and more noise) |
| `STEALTH` | Silent; engine emits one JSON blob, parsed into findings at completion |

**Time window:** how far back to look. `0` = all time, `N` = last N hours.

---

## Magic keywords (type into the GUI before scanning)
- `msp`, `gannon`, `staples`  ->  MSP mode: orange theme, MSP badge.
- `kraken`  ->  ...type it and see. (Skippable with ESC. Unlocks things.)
- `fast`  ->  kills typewriter/decrypt animations and dramatic pauses for a console run.

---

## The console itself (GUI features)

- **12 switchable themes** (Settings -> THEME): Kraken Blue, Gannon Orange, Threat Red,
  Ghost Green, Construct, WOPR, Grid, Outrun, Overwatch, Nebula, Cheyenne, Blacksite -
  plus one secret theme you have to earn.
- **Cinematic VFX layer**: matrix rain, particles, radar sweeps, scanlines/CRT per theme.
  Intensity in Settings: **OFF / LITE / FULL / MAXIMUM** (LITE for old laptops).
- **Synthesized sound** (no audio files): UI blips, threat alerts, scan-complete chime.
  Toggle + volume in Settings.
- **Ctrl+K command palette**: jump views, start/abort scans, switch themes from the keyboard.
- **Destructive-action gate**: EXECUTE REMEDIATION requires typing `PURGE` to confirm.

> The PowerShell engine streams clean structured data; all effects render client-side in the
> browser so they never slow the scan.

---

## Running the engine directly (CLI)
You can call the scan engine without the GUI:

```powershell
powershell -ExecutionPolicy Bypass -File .\ZeroBreach-V23.ps1 -Mode FULL -Hours 0 -Auto
```

Useful parameters (the `param()` block at the top of `ZeroBreach-V23.ps1`):

| Param | Values | Notes |
|---|---|---|
| `-Mode` | QUICK / FULL / DEEP / PARANOID / STEALTH | Empty = interactive menu |
| `-Hours` | int | `0` = all time, `N` = last N hours |
| `-Auto` | switch | Skip all menus (the GUI always uses this) |
| `-Html` | switch | Also write an HTML report |
| `-Paranoid` / `-Stealth` | switch | Same as choosing that mode |
| `-OutDir` | path | Where reports go (defaults to `.\reports`) |
| `-IocFile` | path | Custom indicator list (format: `data\ioc_defaults.json`) |
| `-Baseline` | path | Diff this run against a prior baseline JSON |
| `-Schedule` | DAILY / WEEKLY | Registers a 02:00 SYSTEM scheduled task, then exits |
| `-SmtpTo` / `-SmtpFrom` / `-SmtpServer` | string | Email delivery for scheduled runs |

The engine self-elevates if not already admin.

### Schedule an automated daily/weekly scan
```powershell
powershell -ExecutionPolicy Bypass -File .\ZeroBreach-V23.ps1 -Schedule DAILY -Html -OutDir .\reports
```

### Server options
`ZeroBreach-Server.ps1` accepts `-Port <n>` (default = auto-pick free port) and `-NoBrowser`.

---

## Where things live
```
Launch-GUI.bat              Entry point (double-click)
ZeroBreach-Server.ps1       Local web server (default)
ZeroBreach-V23.ps1          Scan-engine loader (dot-sources engine\)
engine\                     The ~115 scan phases + summary + fix mode
gui\                        Web UI (HTML/CSS/JS)
data\
  detection_signatures.json Built-in malware signatures (loaded at runtime)
  ioc_defaults.json         Default IOC list for -IocFile
  mitre_mapping.json        MITRE ATT&CK map (wired into findings + exports)
  permission_baseline.json  ACL baseline for the permission-integrity phases
tools\Build-Release.ps1     Portable release-zip builder (see Deploy above)
reports\                    Scan results, quarantine vault, server logs (auto-created)
_python\                    Alternate Flask server (parked)
```

---

## Notes / troubleshooting
- **"It scanned nothing / instantly said complete"** - was a Windows Defender/AMSI block;
  fixed by keeping signatures in `data\detection_signatures.json` (data files are not AMSI-
  scanned). No Defender exclusion needed.
- **Reports not appearing** - check the `reports\` folder is writable (not a read-only/ejected
  drive). The server prints a clear error and exits if it cannot write there.
- **On failure to launch** - `Launch-GUI.bat` stays open and writes `zerobreach_launch_error.log`.
- **Re-runs** - you can run multiple scans in a row; each clears state and streams fresh.

---

## Project docs (for development)
- `BLUEPRINT.md` - the product map: architecture, data contracts, safety model, roadmap. Start here.
- `CLAUDE.md` - hard rules, gotchas, parsing details for anyone editing code.
- `HANDOFF.md` - current session state + the live-GUI validation runbook.
- `CHANGELOG.md` - dated history of fixes and false-positive tuning rounds.
- `NEXT_STEPS.md` / `UPGRADE_PLAN.md` - historical plans (superseded by BLUEPRINT.md).