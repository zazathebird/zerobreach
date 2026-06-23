# RESUME HANDOFF — updated 2026-06-23

Everything is committed to **`main`** (local only — not pushed). Latest commit: `b8a13de`.

## Where we are

Today's work (all committed): MITRE tagging, IOC Manager, HTML/CSV export, STEALTH parsing,
**real GUI remediation**, benign test tripwires, a **system-damage safety guard (complete)**,
the trusted-vendor allowlist (Datto/CentraStage/Kaseya), and most recently **Cinematic FX
toggles + boot self-heal** (`b8a13de` — opt-in per-effect switches over the theme system; blank
/grey-screen-on-launch auto-reload; FX audit back to PASS 13/13). See CLAUDE.md → "Cinematic FX
toggles + boot self-heal".
The scan engine `ZeroBreach-V23.ps1` is deliberately untouched. See CLAUDE.md → "Feature wiring
completed 2026-06-23", "Remediation safety guard", and "Remediation test tripwires".

### Context: the live scan that drove the safety work
A real DEEP scan produced **1305 findings, ~772 auto-selected destructive — overwhelmingly FALSE
POSITIVES**, including dangerous ones (would delete 100 root CAs incl. Microsoft/Amazon, the user's
`.bashrc`/`.gitconfig`/`.claude.json`, IconCache, and KILL the running `claude` process). The
detection engine is NOT false-positive-tuned. **User's #1 priority: the tool must NEVER select or
apply anything that damages the system.**

## DONE & COMMITTED — system-damage safety guard (defense-in-depth, all 3 layers)
- `0cf6529` **Layers 1 + 3 (server):** `Test-ProtectedTarget` (main thread) tags every finding served
  to the GUI with `protected` + `protected_reason`; `Test-RProtected` (mirror in `$script:REMEDIATE_SCRIPT`)
  **hard-blocks** any fix on a protected resource regardless of selection, and reports a `blocked` count.
  Protects: certificate trust store, Windows/System32/SysWOW64/WinSxS, shell-system files
  (desktop.ini, IconCache.db, *.library-ms, ntuser.dat), user dotfiles (.bashrc/.gitconfig/.ssh/
  .claude.json/…), SafeBoot + core OS registry, and KillProcess of critical processes or the IR tool.
  Verified against the live report: blocks 285 destructive ops, still allows legit Temp/Downloads deletes.
- `127a765` **Layer 2 (frontend) + modal fix:** protected findings can never be ticked (checkbox
  disabled, excluded from auto-select / Select-All / the ids POSTed to `/api/remediate`); `🛡 PROTECTED`
  badge with reason tooltip; `onRemediationComplete` shows the blocked count. Completion modal now shows
  the engine report's real totals instead of the ~0 live SSE count.

Validation: server parses clean PS 5.1 + 7 (all here-strings); `node --check` clean; FX audit PASS 13/13.

## REMAINING TODO

### Detection false-positive tuning — round 1 DONE 2026-06-23 (engine)
The three highest-volume capped-at-100 over-matchers are now tuned (see CLAUDE.md → "Detection
false-positive tuning — engine, round 1"). Allowlists added to `data/detection_signatures.json`
`fp_allowlists` block (AMSI-safe), loaded via `Join-AllowRegex`. Simulated vs.
`KrakenBaseline_20260623_135347.json`:
- **Rogue Certificates** 101 CRITICAL → 98 INFO + ~2 POSSIBLE (well-known-root allowlist).
- **Cloaked/Hidden Files** 101 → ~3 (benign-name allowlist + payload-extension gate; skip data files).
- **Info-Stealer files** benign browser/app dictionaries suppressed; loose creds files → POSSIBLE.
- Already-fixed (no action): Phase 94 COM Scriptlet (`.sct/.wsc`-only), Phase 66 Share Worm (ext-filtered).
Engine parse-clean PS 5.1 + 7, BOM intact. **Not yet validated on a live admin run** (estimates simulated).

**Still open (round 2):** the remaining capped-100 groups not yet examined — *Execution Artifacts,
Event Log — New Services, SafeBoot Persistence, MoTW / Web-Origin Abuse, Named Pipe Backdoors* (97).
Same approach: allowlist/tighten, downgrade ambiguous to POSSIBLE, never auto-select-destructive.

### Live end-to-end validation (still pending from before)
A real admin `Launch-GUI.bat` run exercising: scan → MITRE badges → HTML/CSV download → IOC save→scan
→ STEALTH scan → and **remediation on the benign tripwires** (verify the `🛡 PROTECTED` items are
un-tickable and that blocked count shows if you force one). Tripwires: see CLAUDE.md.

## Validation commands
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File /tmp/zbparse.ps1 -F "<abs>\ZeroBreach-Server.ps1"   # ParseFile -> errors
powershell.exe -NoProfile -ExecutionPolicy Bypass -File /tmp/zbvalidate.ps1 -File "<abs>\ZeroBreach-Server.ps1" # extract @'...'@ here-strings, ParseInput each
node --check gui/static/js/app.js
node tools/check-visuals.mjs   # FX audit, expect PASS 13/13 (kill stray zb-vfx-profile browser first)
```
(zbparse.ps1/zbvalidate.ps1 are trivial to re-create — see their one-line jobs above.)

Newest engine report analyzed: `reports/KrakenBaseline_20260623_135347.json`.
Test tripwires (still on the machine, named `ZeroBreach_TEST_DELETEME`): recreate/cleanup in CLAUDE.md.
