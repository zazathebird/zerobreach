# Overnight Autonomous Run — Game Plan (2026-06-25, ~03:00)

> ### ⚠ HISTORICAL — a one-off plan for the night of 2026-06-25. Completed; nothing here is pending.
> The `Get-RegVal` / `Get-WinEventSafe` wrappers described below shipped and are now hard rules in
> `CLAUDE.md`. The status files it points at (`reports/NIGHT_RUN_RESULT.txt`,
> `reports/.night_run_status`) **no longer exist** — do not go looking for them, and do not treat
> this file as a runbook. Current state lives in `BLUEPRINT.md` §6/§7 and `HANDOFF.md`.

You went to bed. I have admin rights on this shell, so **I am driving the validation myself** —
you do **not** need to launch anything. Here's the plan and where to look in the morning.

## TL;DR for the morning
1. Open **`reports/NIGHT_RUN_RESULT.txt`** — single-file PASS/FAIL verdict I write at the end.
2. If PASS: changes are committed **and pushed** to `main`. Nothing for you to do.
3. If FAIL: I leave the tool in a **known-good (parse-clean, committed) state** and the result
   file explains exactly what's still open. I never push a broken engine.

## What I found in the last log (`KrakenConsole_20260624_145114.log`)
That run was on an **older working-tree state** than current `HEAD` (proven by line-number drift:
e.g. `Get-WinEvent` cited `:2493` vs current `:2503`, and Phase 68 lacked the extension filter).
Two real classes of problem were present and are the focus of tonight:

1. **7 "RECOVERED ERROR" lines** — `Get-ItemPropertyValue ... -EA SilentlyContinue` throws a
   *terminating* error when the registry value is absent (the trap pattern CLAUDE.md warns about);
   `-EA SilentlyContinue` does NOT suppress it. Plus one `Get-WinEvent -FilterHashtable` that throws
   "The parameter is incorrect" when a provider isn't registered. These are **still present in
   current HEAD** → genuine bugs → fixed tonight.
2. **19,981 "SUSPECT CREDENTIAL FILE" log-flood lines** (Phase 68). Current HEAD already filters
   these (name AND `.zip/.txt/.log/.db` ext) — I verified the current filter excludes the
   `.py/.pyc/.png` files that flooded. So this is already fixed in HEAD; tonight's run confirms it.

## Fixes I made (engine `ZeroBreach-V23.ps1` only)
- Added **`Get-RegVal`** safe wrapper (try/catch → `$null`) and routed all 14 raw
  `Get-ItemPropertyValue` call sites through it. Kills the 6 property "RECOVERED ERROR"s and
  prevents the other 8 latent ones on other machines.
- Added **`Get-WinEventSafe`** safe wrapper (try/catch → `@()`) and routed the 5
  `-EA SilentlyContinue` `Get-WinEvent -FilterHashtable` sites through it. Kills the
  "parameter is incorrect" RECOVERED ERROR. (The 3 `-EA Stop` sites were already in try/catch.)
- Both verified **parse-clean on PS 5.1 AND PS 7 (0 errors)**, BOM intact.

## Validation I'm running (myself, headless, as admin)
A real `-Mode DEEP -Hours 0 -Auto -Html` scan (same conditions as the failing run), repeated a few
times. Pass criteria for each run:
- **0** of the 7 fixed RECOVERED ERRORs (ideally 0 recovered errors total).
- Phase 68 **"SUSPECT CREDENTIAL FILE"** count is small (double/triple digits at most — not ~20k).
- Scan reaches the end (writes `KrakenBaseline_*.json` + transcript end) with no hang.

## Status flag files
- `reports/.night_run_status` — machine-readable: `RUNNING` / `PASS` / `FAIL` (+ run count).
- `reports/NIGHT_RUN_RESULT.txt` — human-readable final summary (read this first).
