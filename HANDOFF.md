# RESUME HANDOFF — updated 2026-06-28

Latest engine work: **FP-tune round 5** (2026-06-28). Engine `ZeroBreach-V23.ps1` touched ONLY for
FP severity/FixAction tuning — no scan-logic/coverage regression. See CLAUDE.md → "Round 5".
**Round 5 COMMITTED + PUSHED** as `b59a3e4` (2026-06-28) — parse-clean PS 5.1 (5.1.26100) + 7.6.3,
BOM intact.

## Round 5 (2026-06-28) — the Phase 108 `icacls C:\ /reset /T` catastrophe + ACL-cluster siblings
Driven by live `DEEP -Hours 1` runs (`_124244` before, `_132719` after). **Phase 108 offered a
recursive ACL reset of the ENTIRE C: drive (`icacls "C:\" /reset /T`) as a HIGH auto-remediation
that fires on every healthy box** — the exact system-damage rule #1 forbids. A `FixParam` sweep
found a sibling family. Cut live auto-destructive **21 → 7** (residual 7 all by-design: 2 `_DELETEME`
tripwires + 3 hardening posture items P41/P42/P46 + Logitech-via-rundll32 + a non-MS OneDC_Updater
task). All downgrade-or-skip; dangerous commands moved into finding *descriptions* (`FixAction Info`).
Fixed: **108/16/43/111/112/115** (ACL cluster → Info), **109/113** (skip non-PE `hosts`, status-split
UnknownError→POSSIBLE, SFC only on genuine tamper), **8** (browser ext), **17** (ADS SmartScreen),
**24** (COM needs Inproc+shadow), **20** (Run-key drop bare AppData), **26** (BHO → POSSIBLE), and
**29** (on-disk task-XML check now skips `\Tasks\Microsoft\` + downgraded to POSSIBLE — was flagging
legit Windows system tasks HIGH+DeleteFile, only visible at all-time `-Hours 0`).
Parse-clean PS 5.1 (5.1.26100) + 7.6.3, BOM intact.

Validated on THREE live runs: `-Hours 1` auto-destructive **21 → 7**; full `-Hours 0` all-time
**75 → 57** (`KrakenBaseline_20260628_133545`, before the Phase-29 fix — that removes ~4 more legit
`\Microsoft\` system-task DeleteFiles). **Sanity-confirmed: NO `icacls /reset /T`, NO `icacls "C:\`,
NO `/remove:g` in any destructive FixParam** at all-time scope (the only `vssadmin` hit is the INFO
opt-in VSS option). 0 recovered errors. The Phase-29 fix is parse-clean but post-dates the `_133545`
run, so a fresh `-Hours 0` re-grade would show ~53.

### Residual all-time auto-destructive (~53) — breakdown for the next session
- **By-design (leave):** ~34 **Phase-10 TEMP executables** (the user's own dev/analysis scripts +
  Claude scratchpad + `zb-vfx-profile` browser-temp + the `_DELETEME` tripwires — round-4 ruled
  "TEMP-exe = HIGH is intentional"); P20/P29/P74.5 `_DELETEME` tripwires; P41/P42/P46 security-posture
  hardening; AnyDesk/Ollama startup `.lnk` (P31, dual-use — worth surfacing); Logitech-via-rundll32
  + `OneDC_Updater` non-MS task (correct to surface).
- **Round-4-known 1-off FPs — NOT auto-tuned (each trades real detection coverage; need user sign-off):**
  P48/P94 Python `LocalCache`, P53 Sysinternals `readme.txt` (ransom-note heuristic), P63 LGHUB
  `config.json`, P90 claude-scratchpad `.ps1` (content-matched analysis scripts), P96
  `spool\drivers\…\PCL5URES.DLL` (legit printer driver — PrintNightmare heuristic, no signed-check).
  None is a flood; all are hard-protected where relevant. Ask the user before downgrading these.

### What's NOT done / next
- ~~COMMIT + PUSH round 5~~ DONE — `b59a3e4`, pushed to origin/main 2026-06-28.
- Optional: fresh `-Hours 0` re-grade to confirm the Phase-29 fix (~53) on a live 5.1 run.
- The original **live GUI end-to-end validation** (browser remediation on tripwires, MITRE badges,
  HTML/CSV export, IOC save→scan, STEALTH) is STILL pending — round 5 was engine/findings only.

---

## (historical) Round 4 and earlier

Everything below was committed to **`main`** and **PUSHED** to origin. Round 4 (`65782ce`):
Engine `ZeroBreach-V23.ps1` was touched ONLY for FP severity/allowlist tuning + one PS-5.1
runtime-bug fix — no scan-logic/coverage regression.

## Round 4 (2026-06-26) — VALIDATED ON FRESH LIVE RUNS (the big one)
Driven by **live admin `DEEP -Hours 0` runs** (not the stale 06-23 simulation). Cut auto-selected
**destructive** findings **319 → 75** (3 live runs: before `_022730`, after `_024320`/`_025617`).
The residual 75 are a healthy low-count tail (≤5 per phase, incl. deliberate tripwires) — no floods.
Highlights (full table in CLAUDE.md → "Round 4"):
- **PS-5.1 `Get-Sig` string-indexing bug** — `(Get-Sig X)[0]` indexed into the *unwrapped string*
  (→ first char `'h'`), so `-match 'h'` matched every https URL → Phase 31 flagged all 48 BITS jobs
  HIGH. Same bug broke the named-pipe regex. This silently broke the round-2/3 fixes **on the real
  5.1 runtime** (they were only simulated in PS 7). Fixed → `@(Get-Sig X)[0]`.
- Phase 32 (DLL-hijack), 66 (share-worm), 24 (COM), 15 (System32 sig), 19 (script assoc), 75
  (Defender excl) — all downgraded/skip-fixed so legit dev-tool DLLs, the user's own exes/scripts,
  Teams' per-user COM, catalog-signed System32 DLLs, Windows default assocs, and RMM exclusions are
  **never auto-selected for destructive remediation**. Every change is downgrade-or-skip only.
- All parse-clean PS 5.1 + 7 (0 errors), BOM intact, JSON valid; verified across 3 live runs.

### Residual 75 auto-destructive — triaged (NOT floods; your call on further tuning)
After round 4 the remaining destructive set is a low-count tail. Reviewed the live `_025617` report:
- **By-design / tripwires (leave):** P10 TEMP executables (×38 — incl. your own dev scripts
  `zbparse.ps1`/`transpile-check.js`/etc.; TEMP-exe=HIGH is intentional), the
  `ZeroBreach_TEST_DELETEME` Run-key/task/Outlook tripwires (P20/P29/P74.5), security-posture items
  (P41 RunAsPPL, P46 LmCompat, P42 Guest), AnyDesk/Ollama startup `.lnk` (P31 — dual-use, worth surfacing).
- **Minor 1-off FPs — judgment calls I deliberately did NOT auto-tune while you were AFK** (each trades
  detection coverage, so they want your sign-off):
  - **P20 Run-key (CRITICAL DeleteReg):** Discord / Teams / Logitech Download Assistant flagged
    because their `AppData\Local\…` Run value matches the `AppData|Temp|cmd|powershell` regex. Plain
    **AppData** is too broad a signal (every legit app autostarts from there). *Recommended:* drop the
    bare `AppData` term from the Run-key match (keep Temp/powershell/cmd/encoded) — the
    `..._DELETEME` tripwire still fires (it points at `%TEMP%`). I left it unchanged pending your OK.
  - 1-each CRITICAL/HIGH on legit files: Sysinternals `readme.txt` (P53 ransom-note heuristic),
    LGHUB `config.json` (P63), Python `LocalCache` (P48/P94), a few `\Microsoft\Windows\…` system
    tasks (P29 — System32\Tasks is hard-protected so never auto-acted), claude-scratchpad `.ps1` in
    TEMP (P90, content-matched my own analysis scripts). All low-volume; not worth coverage risk
    without your input.

None of the 75 is a flood and the safety guard hard-blocks the protected ones; the system-damage risk
the round addressed (mass auto-delete of System32 DLLs / dev tools / the user's own files) is gone.

## (historical) Rounds 1–3 context below

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

**Round 2 DONE** (`082106f`): SafeBoot Hijack (101→0), Named Pipe Backdoor (98→0), Prefetch (HIGH→
POSSIBLE). Event Log/MoTW verified already non-destructive.

**Round 3 DONE** (`b1b7252`): the last two destructive floods. *Hidden Scheduled Tasks* (Phase 104,
57 HIGH DeleteFile of legit Win/Google/MSI/.NET maintenance tasks → INFO/POSSIBLE + Info) and *BITS
jobs* (Phase 31, 49 HIGH RunCmd on normal OS/app-updater transfers → POSSIBLE + Info, escalate to
HIGH only on raw-IP remote or exec-to-userpath). See CLAUDE.md → "Round 3". Allowlists/regexes in
`data/detection_signatures.json`. **Verified stale-report claims hold in current source:** COM
Scriptlet (Phase 94) IS `.sct/.wsc`-only and Share Worm (Phase 66) IS ext-filtered — the report's
100/77 hits on IconCache/`.bashrc`/NTUSER.DAT are from a pre-fix build, not current code.

**FP tuning is now complete for every capped-100 + mid-volume (49–77) destructive flood in the saved
report.** Remaining destructive groups are small (≤27, e.g. User TEMP Executables — legit, that's
where the tripwires live). The big remaining item is the LIVE admin run below.

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
