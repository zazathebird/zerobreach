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

### Detection false-positive tuning (the root cause) — `ZeroBreach-V23.ps1`, `UPGRADE_PLAN.md` WS3
The safety guard makes the FP flood non-catastrophic, but the noise is the real usability problem.
The round-100 capped groups mean "matched everything in a location". Concrete over-matches seen on the
live report (engine work — higher risk, coordinate before editing):
- **Info-Stealer** matched `.node`/`.ses`/`.tmp` as "credential-named file".
- **COM Scriptlet Abuse** matched `.json`/`.db` (IconCache.db, WPA prefs) as "Squiblydoo".
- **Cloaked/Hidden Files** matched every hidden+system file (desktop.ini, IconCache, *.library-ms).
- **Network Share Worms** matched user dotfiles (.bashrc/.gitconfig/.claude.json) as "unsigned exe in open share".
- **Rogue Certificates** flagged every root CA as new/rogue (needs an allowlist of well-known roots + age/baseline logic).
Approach: tighten each phase's match criteria and/or downgrade to INFO; baseline-diff certs against a
known-good root set; don't treat dotfiles/JSON/DB as executables.

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
