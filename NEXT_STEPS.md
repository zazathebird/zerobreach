# ZeroBreach — Next Steps (post-/clear handoff)

> **Read this first after a context clear.** It is the work plan for the PowerShell
> build of ZeroBreach. Written 2026-06-06. Companion to `CLAUDE.md`.
>
> **Status 2026-06-06:** Phases 0 & 1 below are DONE in code, and the AMSI/Defender block that
> made scans "do nothing" is FIXED (signatures moved to `data/detection_signatures.json`; engine
> verified running past AMSI). The big detection/quality expansion the user requested lives in
> **`UPGRADE_PLAN.md`** (use it after /clear). Last unvalidated item: a live Phase-107 GUI run.

---

## Session log 2026-06-06 (part 2) — output overhaul + VFX direction

**DONE this session** (all parse-clean, BOM intact, verified engine runs past AMSI):
- **AMSI fix** (see `CLAUDE.md` + `amsi-blocks-engine` memory): signatures moved to
  `data/detection_signatures.json`, loaded by `Get-Sig` (~`ZeroBreach-V23.ps1:639`).
- **Output overhaul** — the GUI was slow and full of garbage "random character" lines:
  - New `$global:NONINTERACTIVE` (true when `-Auto`, GUI, or stdout redirected — any GUI run),
    set near `V23:143`.
  - When NONINTERACTIVE, `Out-Decrypt` / `Out-Glitch` / `Out-Typewriter` / `Invoke-QuantumBar`
    each emit ONE clean line (no char-by-char, no `\r`, no scramble).
  - 41 dramatic `Start-Sleep` pauses now also skip in NONINTERACTIVE (were MSP-only).
- **Ultimate Performance power-plan feature: CONSIDERED then DROPPED** — robust revert on
  kill/shutdown is too fragile for a marginal gain. Don't implement unless asked again.
- **`README.md`** rewritten (UTF-8) with all operating methods.

### IMPORTANT new requirement — VFX is a MUST, render it in the FRONTEND
The user wants the tool to *look* like it's "doing serious scanning" — Hollywood-grade VFX, "go
nuts." The OLD vfx was PowerShell **console** animations (carriage-return scramble/typewriter);
piped through SSE to the browser those become garbage lines, which is why they were stripped from
engine output. **The correct home for VFX is the web frontend** (`gui/static/js/app.js` +
`gui/static/css/main.css`), client-side, fed by the engine's clean data stream. This keeps the
scan fast AND looks far better than console tricks. Engine must STAY clean — do not re-add console
animation to piped output.

**Next-session VFX workstream (user is emphatic — high priority):**
- Decryption/scramble text reveal on incoming `log_line` / `finding` lines (JS, per element).
- CRT / scanline / glitch / chromatic-aberration overlays (CSS).
- Animated per-phase progress (phase N/107, sweeping bars, spinners) driven by `scan_state`.
- Dramatic threat-alert reveals on `finding` events (flash/shake; optional sound).
- Optional matrix-rain / radar-sweep background; typewriter for headers.
- Keep it performant (`requestAnimationFrame`, CSS transforms, cap concurrent effects).

## Session log 2026-06-09 — frontend VFX workstream DONE (GUI feature port)

The "Hollywood-grade frontend VFX" requirement is **implemented** — harvested from the user's
"gui from other project" folder (PirateLife React GUI), ported to vanilla JS, folder deleted
afterwards. Full details in `CLAUDE.md` → "GUI Feature Layer". Summary:
- `gui/static/js/sound.js` — synthesized Web Audio SFX engine (default ON, Settings control).
- `gui/static/js/themes.js` — 12-theme engine + secret KRAKEN theme (inline vars on `<body>`).
- `gui/static/js/fx.js` — canvas VFX (rain/particles/gridfloor/radar/embers/starfield) + CSS
  overlays, OFF/LITE/FULL/MAX intensity tiers, decrypt/countUp/shake text FX.
- `gui/static/js/kraken.js` — ~19s "kraken" unlock cinematic → god mode + KRAKEN theme.
- `app.js` — Ctrl+K command palette, PURGE danger-confirm before remediation, sound wiring,
  view-title decrypt, count-up stats. Legacy `initParticles` removed.
- `gui/static/css/fx.css` — all companion styles. All 5 JS files pass `node --check`.
- **Not yet validated in a live browser run** — needs the acceptance run below.

## Consolidated "what's left" (priority order for the fresh session)
1. **Live acceptance run** — `Launch-GUI.bat` as admin → scan to Phase 107 → report in
   `reports/` → clean re-run. NOW ALSO COVERS: new GUI layer (themes, sound, VFX, Ctrl+K,
   typing `kraken`). (Done in code; never validated live end-to-end.)
2. ~~**Frontend VFX workstream**~~ — DONE 2026-06-09 (see session log above).
3. **`UPGRADE_PLAN.md`** — the big detection/quality expansion (WS0–WS6: inventory, finish AMSI
   hardening of ~15 inline regexes, detection coverage++, FP tuning, performance, MITRE tagging,
   remediation/STEALTH). Agents authorized; NO darkweb/Tor; signatures → `data/*.json` only.
4. Per-phase progress parsing, MITRE wiring (`data/mitre_mapping.json`), IOC Manager → `-IocFile`,
   `/api/export/html`, wire `btn-execute` remediation, STEALTH JSON parsing.

## Scope rule (hard constraint from the user)

**Work on the PowerShell files ONLY** for now:
- `ZeroBreach-Server.ps1` (HttpListener web server + SSE)
- `ZeroBreach-V23.ps1` (107-phase scan engine)
- `Launch-GUI.bat` (entry point)
- `gui/` (HTML/CSS/JS frontend — shared, fine to edit)

**Do NOT touch `_python/`.** The Flask/SocketIO build is parked. The user needs the
PowerShell tool working for use at work, and needs it to **run from a USB stick on any
Windows machine** via `Launch-GUI.bat`.

## Correction to CLAUDE.md (verified 2026-06-06)

CLAUDE.md says the frontend "speaks SocketIO" and there is an "SSE vs SocketIO mismatch."
**This is false in the current code.** `gui/static/js/app.js:95` uses
`new EventSource('/api/events')` — native SSE, matching the PS server's SSE output. There
is no transport mismatch and nothing to "reconcile." Do not waste time on it. (CLAUDE.md
has been corrected.)

---

## PHASE 0 — ✅ DONE (2026-06-06): make a single scan work + make re-runs work

**Status: COMPLETE.** All fixes below applied and both PS files parse clean
(`[Parser]::ParseFile` → 0 errors). Next session starts on **Phase 1 (USB portability)**.

What was changed:
- **Bug #1** — `ZeroBreach-V23.ps1:1811` VSS prompt now guarded
  (`if ($Auto -or $global:GUI_MODE -or $global:STEALTH_MODE) { $vssChoice="no" }`).
  Added an `if ($Auto) { ...; exit 0 }` early-exit right after the STEALTH JSON exit
  (~`:3654`), so in auto mode the engine writes reports and exits **before** any fix-mode
  prompt — covers the old 3657/3673/3677/4178/4202/4374/4384 prompts in one guard. The
  shell-kill ReadKey (`:472`) was already `-Auto`-gated at `:891`. Entry menus already gated
  at `:713`.
- **Bonus (blocker found while parse-checking):** `ZeroBreach-V23.ps1:1445` had `"...\$sm:..."`
  which PS parsed as a scoped variable ref — a hard parse error that stopped the **whole
  engine** from loading. Fixed to `${sm}`. (If a scan "did nothing," this may have been why,
  alongside Bug #1.)
- **Bug #2a** — primary fix is Bug #1 (engine now exits → runspace `finally` clears
  `Running`). Abort route (`:553`) already kills the child and clears the flag — reliable
  recovery. Frontend `app.js:284` now surfaces a non-OK `/api/scan/start` (resets
  `STATE.scanning`, shows `● ERROR`) instead of hanging on `● SCANNING`.
- **Bug #2b** — `ZeroBreach-Server.ps1` SSE loop now rewinds `$idx` to 0 when `EventLog.Count`
  shrinks (log cleared for a new scan), so already-open tabs keep streaming on re-run.

**Not yet done:** the live acceptance test (run `Launch-GUI.bat` on a real machine and watch a
scan reach Phase 107 + a clean re-run). Code is in place; needs a Windows admin run to confirm.

---

### Original plan (for reference)

Two bugs, both root-caused. Fixed in this order.

### Bug #1 — "Didn't scan a thing" → engine blocks on an interactive prompt mid-scan
**Root cause:** the scan engine is launched with `-Auto` and the *entry* menus are gated by
`-Auto`, but several `Read-Host`/`ReadKey` calls **inside the scan body are not gated**. The
first one hit is the Volume Shadow Copy prompt in Phase 43:

- `ZeroBreach-V23.ps1:1818` — `$vssChoice = (Read-Host).Trim().ToLower()` inside
  `if ($shadowCount -gt 0)` (true on virtually every real machine). The child process has no
  console stdin (`UseShellExecute=$false`, `CreateNoWindow=$true` in the server), so
  `Read-Host` blocks forever. No more lines stream, `scan_complete` never fires → UI shows
  "nothing happened."

**Other unguarded prompts (same fix needed):** `ZeroBreach-V23.ps1:3657` (ReadKey when
findingCount -eq 0), `:3673` (fix-mode entry), `:4178`, `:4374` (fix-mode selection).

**Fix:** guard every in-body prompt with `-Auto`/GUI mode and default to the **safe,
non-destructive** branch. For the VSS prompt:
```powershell
if ($shadowCount -gt 0) {
    if ($Auto -or $global:GUI_MODE -or $global:STEALTH_MODE) {
        $vssChoice = "no"          # never auto-delete shadows; just record the finding
    } else {
        Write-Host "  COMMAND> " -NoNewline -ForegroundColor DarkGray
        $vssChoice = (Read-Host).Trim().ToLower()
    }
    ...
}
```
Apply the same `if ($Auto) {<safe default>} else {<Read-Host>}` pattern at 3657/3673/4178/4374.
In `-Auto` mode the engine must run the audit, write its report/JSON, and `exit 0` **without
ever entering fix mode** (the GUI does remediation). After the clear, grep the whole file for
`Read-Host` and `ReadKey` and confirm every hit is `-Auto`-guarded — there may be more than
the five found so far.

### Bug #2 — Second run hangs on "running" forever
Two independent causes, both downstream of Bug #1:

**2a. `Running` flag never resets.** Set true in the scan runspace
(`ZeroBreach-Server.ps1:324`), reset only in the `finally` (`:440`) which runs only when the
reader loop exits — which never happens while the child is blocked. `/api/scan/start`
(`:533`) then rejects the re-run with HTTP 400 `{"error":"scan already running"}`, and
`app.js:284-288` ignores the status (only `.catch()`es network errors) after already
switching to the scanning view → "● SCANNING" forever.
- **Primary fix = fix Bug #1.** Once the engine exits, `finally` runs and the flag clears.
- **Defense in depth:** add a watchdog that always clears `Running` on child exit/timeout;
  make `/api/scan/abort` (`:552-557`) a reliable recovery path from a stuck UI.
- **Frontend:** in `app.js:284`, surface a non-OK response instead of hanging:
  ```js
  .then(r => { if (!r.ok) return r.json().then(j => { throw new Error(j.error || r.status); }); })
  .catch(e => { STATE.scanning = false; $('btn-abort').disabled = true;
                appendLogLine({ text:`[ERROR] Could not start scan: ${e}`, severity:'CRITICAL', phase:0 }); });
  ```

**2b. SSE goes silent for already-open tabs after a re-run.** Each scan calls
`$ScanState.EventLog.Clear()` (`ZeroBreach-Server.ps1:328`), but the SSE loop's local `$idx`
(~`:240`) only increases and is never reset when the log shrinks → `while ($idx -lt $count)`
never fires again. Fix:
```powershell
$count = $SseState.EventLog.Count
if ($idx -gt $count) { $idx = 0 }   # EventLog was cleared for a new scan
while ($idx -lt $count) { Push $SseState.EventLog[$idx]; $idx++ }
```

### Phase 0 acceptance test
1. `Launch-GUI.bat` → browser opens → click run → log lines + findings stream live →
   scan reaches Phase 107 → `scan_complete` fires → results JSON written under `reports/`.
2. Close the complete page, reopen, click run again → a fresh scan starts and streams (no
   "stuck on running").
3. Run twice in a row in the same tab → second run streams too (2b fix).

---

## PHASE 1 — USB portability — ✅ DONE in code (2026-06-06)

**Status: COMPLETE in code; pending the live admin run.** All items below applied; both
PS files parse clean (`[Parser]::ParseFile` → 0 errors).

| Pri | Issue | Where | Status |
|---|---|---|---|
| HIGH | `ZeroBreach-V23.ps1` saved without UTF-8 BOM | V23 file header | ✅ V23 now has UTF-8 BOM (`EF BB BF`) |
| HIGH | Reports default to Desktop, not the USB | `ZeroBreach-V23.ps1:165-169` | ✅ `$OUT_ROOT` = `-OutDir` if passed, else `Join-Path $PSScriptRoot 'reports'` |
| HIGH | UAC re-elevation fails on paths with spaces | `Launch-GUI.bat:8` | ✅ `%~f0` quoted, `-ArgumentList` array form |
| MED | `HttpListener` URL ACL on locked-down machines | `ZeroBreach-Server.ps1:599` | ✅ `netsh http add urlacl` fallback then retry |
| MED | `reports/` dir creation failure silent | `ZeroBreach-Server.ps1:41-46` | ✅ checks + prints FATAL and exits |
| MED | JSON encoding cross-machine parse risk | `Server.ps1:457-467`; `V23.ps1:3479-3484` | ✅ **UTF-8 *no-BOM*** via `[IO.File]::WriteAllText` + `UTF8Encoding($false)` — see note below |
| LOW | UAC elevation drops CWD to System32 | `-Verb RunAs` paths | ✅ Server `Set-Location $PSScriptRoot` (:37); V23 unaffected — all its paths are absolute (`$PSScriptRoot`/`$env:TEMP`/`$OUT_ROOT`) |

> **JSON encoding correction (2026-06-06):** the original plan said "use `utf8BOM`." That was
> wrong — `utf8BOM` is **not a valid `-Encoding` value in Windows PowerShell 5.1** (the primary
> target) and would crash the write, and a BOM on a JSON *data* file breaks strict parsers
> (browser `JSON.parse`). The BOM-on-script rationale (why the `.ps1` server file needs one)
> does **not** transfer to data files. Correct fix applied: write all JSON file outputs as
> **UTF-8 without BOM** via `[System.IO.File]::WriteAllText($path, $json, (New-Object
> System.Text.UTF8Encoding($false)))`, which behaves identically on PS 5.1 and 7. The remaining
> `ConvertTo-Json` calls (Server SSE/HTTP responses, `V23:3664` STEALTH `-Compress` stdout) are
> not file writes and were left alone.

**Already good (verified):** paths use `$PSScriptRoot`/`Join-Path`; elevation re-passes args;
`Get-FreePort` avoids port conflicts; no `Import-Module`/internet dependencies; gui/ + reports/
are script-relative.

**Remaining for Phase 0+1:** the **live acceptance test** — run `Launch-GUI.bat` as admin on a
real Windows machine (ideally from a USB stick with a space in the path) and confirm: a scan
reaches Phase 107, `scan_complete` fires, JSON lands in `reports/`, and a clean re-run works.

---

## PHASE 2 — Feature parity: bring ALL Python features into the PowerShell tool

**Answer to "are the Python features applicable to the PS tool?": yes — effectively 100%.**
Both servers are thin wrappers around the *same* `ZeroBreach-V23.ps1` engine serving the
*same* `gui/` frontend. Anything `_python/server.py` does is doable natively in PowerShell;
the only Python-specific pieces have direct .NET/PS equivalents:

| Python (`server.py`) feature | PowerShell equivalent | Status |
|---|---|---|
| SocketIO push | `HttpListener` + SSE `/api/events` | ✅ already in PS server |
| `/api/scan/start`, `/api/scan/abort` | same routes | ✅ present |
| `/api/sysinfo` via **psutil** | `Get-CimInstance` / `Get-Counter` (server already calls CIM at ~:151,156) | partial — confirm route exists/returns same shape |
| `/api/scan/state` | `$script:State` snapshot route | verify present |
| `/api/findings` | serve accumulated findings list | verify present |
| `/api/reports`, `/api/reports/<file>` | enumerate + stream from `reports/` | verify present |
| `classify_line()` severity/threat maps | inline `Classify` in the SCAN_SCRIPT runspace | ✅ mirror; keep in sync |
| STEALTH JSON output parsing | not handled in either server yet | TODO (both) |

**Action:** diff the route/event list in `_python/README_CLAUDE_CODE.md` against
`ZeroBreach-Server.ps1` and implement any missing endpoint **in PowerShell**. Use the Python
file as a *spec only* — do not run or build it. Target list (from the README): `/api/sysinfo`,
`/api/scan/state`, `/api/findings`, `/api/reports`, `/api/reports/<file>`, plus the
`scan_state` / `scan_complete` / `sync` events.

Also still-open from CLAUDE.md, all PS-side: STEALTH-mode JSON parsing, per-phase progress
parsing, MITRE tagging (now that `data/mitre_mapping.json` exists — wire findings →
technique IDs via its `keyword_map`/`threat_type_map`/`phase_map`), IOC Manager → `-IocFile`
(`data/ioc_defaults.json` is the format), `/api/export/html`, wire `btn-execute` to real
remediation, surface rollback-snapshot path.

### MITRE wiring note (the file is ready)
`data/mitre_mapping.json` exists and is validated (111 techniques, all 107 phases, 207
keyword mappings). To tag a finding: try `keyword_map` (substring match on the line /
ThreatType), then `threat_type_map` (the 10 categories), then `phase_map` (by "PHASE N");
resolve the resulting ID against `techniques` for display name + tactic + URL.

---

## PHASE 3 — DOWN THE LINE (not the immediate next session)

**Integrate the external GUI the user is dropping in.** The user has a GUI from another
project they've invested heavily in and prefer (its options/controls). Plan:
1. Wait until Phase 0 is solid (working single scan + repeatable re-runs) before starting.
2. When the file lands, inventory its features/controls and map each to an existing
   server route or a new one. Keep the SSE transport (`EventSource('/api/events')`) — adapt
   the new GUI to it rather than swapping transports.
3. Port incrementally: structure/markup → CSS theme vars → JS wiring to the existing
   `log_line`/`finding`/`scan_state`/`scan_complete` events. Preserve the working data flow.
4. Treat it as a frontend swap over a stable backend; do not regress Phase 0/1/2.

> User's words: add it "down the line once things are working better." Don't start it in the
> session that fixes the bugs.

---

## Quick reference — confirmed file:line anchors
- Scan-blocking `Read-Host`: `ZeroBreach-V23.ps1:1818` (+ 3657, 3673, 4178, 4374)
- Reports→Desktop default: `ZeroBreach-V23.ps1:166`
- `Running` set/reset: `ZeroBreach-Server.ps1:324` / `:440`; start gate `:533`; abort `:552-557`
- SSE idx loop / EventLog.Clear: `ZeroBreach-Server.ps1:~240` / `:328`
- Frontend SSE client: `gui/static/js/app.js:95`; start-scan fetch `:284-288`
- UAC re-elevation (batch): `Launch-GUI.bat:8`
