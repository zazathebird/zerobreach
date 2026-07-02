# RESUME HANDOFF — updated 2026-07-02 (session 5: SSE-log analysis + live finding stream fix + BLUEPRINT)

> ## Session 5 (2026-07-02) — the promised log analysis, and what it found
> Analyzed the 2026-07-01 live GUI DEEP run artifacts (`server_events_20260701_185058.log`,
> `audit_20260701_190044.json`, `KrakenConsole_20260701_185111.log`):
> - **✅ Phase-counter fix `c0477ae` VALIDATED** — `scan_state` events carry all 116 phase values
>   0→115 with no gaps; the counter can no longer skip fast phases. (231 scan_state events total.)
> - **🐞 FOUND + FIXED: the live finding stream was dead.** The whole DEEP run produced **0** SSE
>   `finding` events and all-1266-lines-INFO classification, while the engine recorded **288
>   findings** — the engine's stdout finding lines (`[RUN KEY] …`) carry no severity tags for the
>   server's `Classify` regexes. That's also why `audit_20260701_190044.json` has `findings: []`
>   (it snapshots the server's live findings — NOT an "expected summary shape"). **Fix:**
>   `Add-Finding` now emits one `[FINDING] {compact JSON}` line per registered finding
>   (NONINTERACTIVE, non-stealth); the server intercepts those as the authoritative live-finding
>   source (exact severity, canonical threat bucket, MITRE, `fix_action`/`target` added to the
>   event) and the old text-severity→finding path was retired (would double-count). Frontend
>   needs no changes (audited: chips/ticker/badge consume `finding` events; sounds throttled;
>   completion still replaces the list from `/api/report`).
> - **🐞 FOUND + FIXED: mojibake in the GUI log** — child PS 5.1 wrote redirected stdout in the
>   OEM codepage while the server read UTF-8. Loader now sets `[Console]::OutputEncoding` UTF-8
>   when stdout is redirected. Also: `Classify` CLEAN regex now tolerates the padded `[OK ]` tag.
> - **Also:** early `Import-Module Microsoft.PowerShell.Security` in the loader (pre-empts the
>   ACL TypeData collision degrading `Get-AuthenticodeSignature`); **`BLUEPRINT.md` created** —
>   product map + data contracts + prioritized roadmap (start there); CLAUDE.md/NEXT_STEPS/
>   UPGRADE_PLAN refreshed to match.
> - **Remediation/export/IOC/STEALTH were NOT exercised** in the 07-01 run (SSE log ends at
>   `scan_complete`; no `[FIX]` lines) — the browser click-through below remains THE open item,
>   now also covering: live finding ticker/chips populate during the scan, banners render clean
>   (no `�`), and the completion modal's live counts are real.
>
> ### Session 5 validation (all on live PS 5.1.26100; server + engine parse-clean 5.1+7, BOMs intact)
> 1. **Headless engine QUICK** (server-style UTF-8 redirect): exit 0, **218 `[FINDING]` lines**
>    (12 CRIT / 9 HIGH / 175 POSSIBLE / 22 INFO), 0 mojibake, box-drawing banners clean.
> 2. **End-to-end server scan #1** (real `/api/scan/start` → SSE log `_013641`): **217 finding
>    events streamed live** with exact severities + resolved MITRE (`fix_action`/`target` on each),
>    threat_counts populated, `audit_20260702_014027.json` findings **217** (was `[]`). But all
>    log_lines still INFO → dug in → **found the `$sev`/`$SEV` case-insensitive variable shadow**:
>    `Classify`'s local `$sev='INFO'` shadowed the `$SEV` regex dict (PS vars are case-insensitive),
>    so severity classification had NEVER worked, on any run, ever. Dict renamed **`$SEV_RX`**.
> 3. **End-to-end server scan #2** (post-fix, SSE log `_014742`): **229 finding events**
>    (12 CRIT / 22 HIGH / 195 POSSIBLE), log_line severities finally real (69 CLEAN / 57 HUNT /
>    13 POSSIBLE / 4 HIGH / 3 CRIT / rest INFO), `audit_20260702_015127.json` findings **229**,
>    0 mojibake, 202s elapsed, clean scan_complete. Test server stopped after.
>
> **For the next browser run, additionally verify:** live intel ticker + threat chips populate
> DURING the scan; log lines are severity-colored + the CRITICAL/HIGH/POSSIBLE log filters work;
> banners show clean box-drawing (no `�`); completion modal live counts are no longer ~0.

# (session 4 record) — updated 2026-07-01 (engine split + WS2 detection port)

> **THIS SESSION shipped a major architecture change** — read the 2026-07-01 `CHANGELOG.md` entry and
> CLAUDE.md's new "Engine is split" rules before touching the engine. The monolith
> `ZeroBreach-V23.ps1` is now a thin loader dot-sourcing `engine/Phases-1/2/3.ps1` + `Summary.ps1` +
> `FixMode.ps1`. We took the work-rig branch's split architecture (it was the better long-term
> approach — multiple detection agents can now edit separate modules) but rebuilt it on `main`'s
> live-validated engine and its FP tuning, then merged the WS1/WS2 detection data and ported 6
> new/upgraded detections (all `FixAction Info`, no new auto-destructive findings).
>
> **Commits this session (local, unpushed):** `efee013` docs · `dcf8793` split · `585fe57` data merge ·
> `1894fa1` detection port · `29f5a0e` **the dot-source trap fix** · `3715fd8` docs. Plus the earlier
> unpushed `f198420` (docs). **Push when ready** (all validated headless; the outer repo's remote is
> `github.com/zazathebird/zerobreach`).
>
> **Validated headless:** parse-clean PS 5.1.26100 + 7.6.3 (all 6 files, BOM intact); FULL `-Auto` ran
> phases 1-80 contiguous + fractional phases, clean self-exit, reports written. DEEP (1-115) run was
> finishing at handoff — confirm 115 + re-grade auto-destructive from its baseline (target still 52).
>
 > **UPDATE 2026-07-01 PM — the live GUI run HAPPENED and the engine side PASSED.** User launched
> `Launch-GUI.bat` as admin and ran a **DEEP** scan in the browser: all **115 phases contiguous, 0
> RECOVERED ERRORS**, new phases (55.5/69/99.5) fired, clean exit ~9.5 min on the real PS 5.1 server
> (`http://localhost:1183`). Logs saved in `reports/` (timestamps `*_20260701_185*` / `_190044`).
> **NEXT SESSION: analyze those logs** — especially `server_events_20260701_185058.log` for (a) the
> phase-counter cadence (validate server fix `c0477ae` — did scan_state step 1→115 without jumping),
> and (b) whether remediation/export/IOC-save/STEALTH were exercised. **Also check:** the server's
> `audit_20260701_190044.json` shows `findings: []` while `KrakenBaseline_20260701_185111.json` has the
> real findings — confirm that's an expected summary shape, not a server-summary wiring gap. If the SSE
> log shows the user didn't click remediate/export, ask them to exercise those next GUI run.
>
> **OPEN ITEM (narrowed): browser click-through of destructive remediation (PURGE + protected HARD
> BLOCK), export downloads, IOC save→re-scan, STEALTH.** The scan/engine path is now proven live; these
> UX paths still need a confirming look (headless/API already validated them). Prep done (tripwires
> laid, server + engine parse-clean) — see "NEXT SESSION" runbook below.
>
> ### Session 3 (2026-07-01) — prep RE-VERIFIED, no code changes; ready to launch
> Re-checked all prep before handing off for the browser run:
> - **All 5 `_DELETEME` tripwires still present** (TEMP `.bat`, Downloads `.cmd`, HKCU Run value,
>   Outlook-cache `.bat`, disabled scheduled task) — no need to re-lay.
> - **`ZeroBreach-Server.ps1` parse-clean on PS 5.1.26100 AND 7.6.3**, UTF-8 BOM intact.
> - **`app.js` `node --check` clean.**
> - Git: **1 local commit ahead of origin — `f198420` (docs-only:** CLAUDE.md/CHANGELOG
>   consolidation, no code). User said **push later** — safe to push anytime, no code impact.
> - Nothing else changed this session. The live GUI click-through (runbook below) is untouched and
>   is the sole remaining task; the `c0477ae` phase-counter fix still needs its first in-browser look.

## Session 2 (2026-06-28 PM) — phase-"skipping" diagnosed (NOT an engine bug) + 2 server fixes — `c0477ae`
User watched a live DEEP run and reported it "skipped MANY MANY phases (unless instant)." Investigated
the in-progress + finished console log (`KrakenConsole_20260628_152000.log`): **all 115 phases ran
contiguous, 0 RECOVERED ERRORs** — nothing skipped at the engine level. Root cause was **frontend
display cadence**: the visible phase counter/progress bar updates only on `scan_state` (app.js
`:205-211`), but the server emitted `scan_state` only every 12 log lines (`%12`). A sub-second phase
emits <12 lines, so several phases pass between emits and the counter jumps (e.g. 94→97) — the fast
phases *look* skipped. Many phases genuinely ran in 0–0.3s on this box.

Two server-only changes committed (`c0477ae`, engine `ZeroBreach-V23.ps1` untouched; parse-clean PS
5.1 + 7, all 3 here-strings, BOM intact):
1. **Phase-skip display fix** — also emit `scan_state` immediately whenever the phase number changes
   (in the scan-runspace parse loop, next to the `$PREX.Match` at `~:669`), in addition to the `%12`
   cadence. Counter can no longer skip a phase. **Not yet visually confirmed in-browser** (fold into
   the live-GUI validation below).
2. **Durable run logs** — `reports\server_console_*.log` (main-thread console via `Start-Transcript`,
   stopped in the accept-loop `finally`) + `reports\server_events_*.log` (the FULL SSE stream — every
   log_line/finding/[FIX] line + remediation_complete, teed by `Enqueue`/`REnqueue` since runspace
   output never hits the console). Path carried on `$script:State.EventLogFile`. These give the next
   live-GUI session real post-run artifacts to debug from.

Fresh full-scope re-grade of `KrakenBaseline_20260628_152000.json` (DEEP `-Hours 0`): **855 findings,
52 auto-destructive** (matches the `_143641` baseline), breakdown all by-design/known-FP tail (P10×34
TEMP execs + tripwires, P20/P29/P74.5 `_DELETEME` tripwires, P41/42/46 hardening, P31 AnyDesk/Ollama
`.lnk`, round-4-known 1-offs P48/53/63/90/94/96). **0** drive-root/`icacls /reset /T`/`vssadmin delete
shadows`/`/remove:g` FixParams — round 5 holds at full scope. **NOT pushed** (commit is local on main;
push when convenient).

Latest engine work: **FP-tune round 5** (2026-06-28). Engine `ZeroBreach-V23.ps1` touched ONLY for
FP severity/FixAction tuning — no scan-logic/coverage regression. See CLAUDE.md → "Round 5".
**Round 5 COMMITTED + PUSHED** as `b59a3e4` (2026-06-28) — parse-clean PS 5.1 (5.1.26100) + 7.6.3,
BOM intact. **Live `-Hours 0` re-grade DONE** (`KrakenBaseline_20260628_143641`, auto-destructive 52,
Phase-29 fix confirmed, 0 drive-root/`icacls /reset` ops).

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
- ~~Fresh `-Hours 0` re-grade to confirm the Phase-29 fix~~ DONE — live `DEEP -Hours 0` run under
  PS 5.1.26100 (`KrakenBaseline_20260628_143641.json`, exit 0): **auto-destructive 52** (952 total),
  matching the predicted ~53 and down from 75 at the pre-round-5 all-time baseline `_133545`. Verified
  **0** `\Tasks\Microsoft\` tasks in the auto set (Phase-29 fix confirmed) and **0**
  `icacls /reset /T` / `icacls "C:\` / drive-root ops (the only icacls/vssadmin RunCmd is Phase 43's
  VSS option at INFO — not auto-selected). Residual 52 is all by-design: 34× Phase-10 TEMP execs
  (own dev scripts + tripwires), `_DELETEME` tripwires (P20/P29/P74.5), Logitech-via-rundll32,
  OneDC_Updater non-MS task, AnyDesk/Ollama startup `.lnk` (P31), P41/42/46 hardening, and the
  round-4-known 1-off FPs (P48/53/63/90/94/96 — still need user sign-off before downgrading).
- **THE ONE REMAINING ITEM → live GUI end-to-end validation.** Round 5 was engine/findings only;
  the browser+admin path has never been exercised. Runbook below.

## NEXT SESSION — live GUI end-to-end validation (the only open item)

**Prep already done (2026-06-28, this session):** all 5 benign `_DELETEME` tripwires are freshly
laid down on the box (TEMP `.bat`, Downloads `.cmd`, HKCU Run value, Outlook-cache `.bat`, disabled
scheduled task — verified present); `ZeroBreach-Server.ps1` parses clean PS 5.1 (5.1.26100) + 7.6.3,
BOM intact; `app.js` `node --check` clean. So the launch is ready — nothing else to set up.

**Split (decided with user — saves tokens, no loss to debugging):**
- **USER runs the browser click-through** (eyes-on, can't be driven headlessly here). The model's
  debug ability depends on *artifacts*, not who launched — so when something's off, the user pastes
  the server console / browser-console error, points at the report JSON, or drops a screenshot.
- **MODEL can do the API/server layer headlessly** (no browser) if desired BEFORE handing off, or to
  reproduce a bug the user hits: start the PS server, then hit `/api/export/html`, `/api/export/csv`,
  `/api/ioc` GET+POST (verify the `.ioc` prefixed-text emit — `hash:`/`ip:`/`domain:`/`regex:`/`file:`),
  `/api/report?name=KrakenBaseline_…`, `/api/remediate {report,ids[]}` (id-filter + the protected
  HARD-block → `blocked` count), and STEALTH JSON parsing. These are server-driver logic, browser-free.

**User runbook (what to click + what to capture):**
1. `Launch-GUI.bat` as admin (self-elevates; pure-PS server, no Python). Browser auto-opens.
   - If blank/grey screen: it self-heals (reloads ≤2×). If it stays blank, capture
     `zerobreach_launch_error.log` (project root) + browser console.
2. Config → **DEEP**, **All time** → start scan. Wait for `scan_complete`.
3. **FINDINGS view** — confirm: MITRE badges render (clickable `.item-mitre`); the `🛡 PROTECTED`
   items show a green/shield badge and their checkbox is **disabled** (can't tick); vendor items show
   `✔ TRUSTED`. The 5 `_DELETEME` tripwires should be present + tickable.
4. **Force-test the hard block:** the protected items must stay un-tickable even via Select-All; the
   completion modal should report a non-zero `blocked` count if you somehow POST one.
5. **REMEDIATION** → select ONLY the `_DELETEME` tripwires → type `PURGE` → EXECUTE. Confirm:
   TEMP `.bat` + Downloads `.cmd` deleted (DeleteFile), HKCU Run value removed (DeleteReg), scheduled
   task unregistered (RunCmd), Outlook-cache `.bat` moved to `reports\quarantine\` with a `.quar.json`
   manifest (Quarantine). `remediation_complete` shows applied/failed/skipped/blocked.
6. **Exports:** HTML + CSV download buttons produce files. **IOC Manager:** save a set → confirm
   `reports\custom_iocs.ioc` written in prefixed-text format → rescan picks it up via `-IocFile`.
7. **(optional) STEALTH** scan → confirm findings still parse (engine emits JSON, server buffers+parses).

**Capture for the model:** the `KrakenConsole_*.log` / server console, the `remediation_complete`
payload, the `reports\quarantine\*.quar.json`, and a screenshot of the FINDINGS view (badges +
disabled checkboxes). Re-lay tripwires between runs with the create block in CLAUDE.md → "Remediation
test tripwires" (cleanup block there too).

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
