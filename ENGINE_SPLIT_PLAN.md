# Engine Split — ✅ DONE 2026-06-29

> Self-contained handoff doc (lives in the repo so it survives a machine change). The split is
> **implemented and validated** (parse-clean ×6, headless `-Auto` run streamed phases across the
> module boundaries with no AMSI block, byte-exact reconstruction proved zero code loss). The
> original design (below) called for grouping phases by threat category — that was **rejected during
> implementation** because the 119 phases execute **linearly in numeric order** and reuse variables
> across phases (e.g. Phase 52 reuses Phase 51's `$ransomScanFiles`; Phase 58 reuses Phase 40's
> `$bcdedit2`; Phase 60 reuses Phase 59's `$dnsCache2`). Grouping by category would reorder execution
> and break that. **The split is by contiguous phase RANGE instead**, which preserves exact execution
> order and all cross-phase variables (every module is dot-sourced, in order, into the loader's
> single scope, so vars/functions/the resilience trap all carry across exactly as inline).

## AS-BUILT layout (2026-06-29)
```
ZeroBreach-V23.ps1     <- LOADER: lines 1-1175 of the old monolith (param(), elevation, schedule,
                          globals, ALL helpers, Add-Finding, remediation fns, Get-Sig/Get-Perm
                          loads, IOC import, banner, the resilience trap, ALL $PSScriptRoot usage)
                          + a dot-source block that loads the 5 modules in execution order.
engine/
  Phases-1.ps1         old lines 1176-2468  (sections 1-11: phases 1-~54)
  Phases-2.ps1         old lines 2469-3320  (sections 12-16 + universal backdoor phases 81-89)
  Phases-3.ps1         old lines 3321-4226  (advanced phases 90-105 + perm/integrity 108-115)
  Summary.ps1          old lines 4227-4541  (risk score + audit summary + the -Auto exit)
  FixMode.ps1          old lines 4542-5350  (fix-mode entry, rollback, live dashboard, fix engine)
data/*.json            signatures - unchanged
```
Every module carries a UTF-8 BOM. The loader keeps the `param()` block first and all
self-elevation/schedule logic (which `exit` before any scan), so the server/`Launch-GUI.bat`
interface is unchanged — they still spawn `ZeroBreach-V23.ps1` with the same args.

### ⚠ Dot-source `exit` gotcha (fixed — keep this rule)
`exit` / `exit 0` inside a dot-sourced module does **NOT** terminate the process — it only returns
to the loader, which then continues to the next dot-source. This broke `-Auto` mode (Summary's
`exit 0` fell through into `FixMode.ps1` and hung on the fix prompt). **Any `exit` in `engine/*.ps1`
that is meant to stop the whole engine MUST be `[Environment]::Exit(N)`.** Currently applied in
`Summary.ps1` (stealth/auto/no-findings exits) and `FixMode.ps1` (declined exit). The loader's own
`exit`s (elevation, schedule) are fine because they are not dot-sourced.

### To subdivide further later
`Phases-1/2/3` can be split again at any `# ════ SECTION N` banner (cut at the blank line before
the banner — comments only, never mid-statement). Keep Core/loader as the stable base.

---
## Original plan (for reference — category grouping was NOT used; see note above)

## Decision
Split the monolithic **`ZeroBreach-V23.ps1`** (~5,350 lines, 119 phases) into a **dot-sourced
`engine/` folder**. The user was offered monolith vs. split, chose the moderate split, then
delegated the final call to Claude with one hard requirement: **"runs identically on any system I
use it on."** A dot-sourced folder satisfies that as long as the constraints below hold.

**Why split:** the upcoming WS1–WS6 detection upgrade has multiple agents heavily editing detection
logic; they collide badly on one 5,350-line file. Separate files let agents own modules.

**Why it does NOT affect performance:** file count has **zero** runtime cost in PowerShell — the
same total code parses and runs. Scan speed comes from algorithms (the existing `Get-ScanFiles`
bounding/deadline work + the planned WS4 runspace parallelism), not file layout. **Do not split for
performance.**

**Why it was deferred (not done in the session that decided it):** a half-finished refactor of a
5,350-line engine would leave the tool broken on every machine — exactly the "runs identically
everywhere" failure to avoid. It needs a clean budget and the full validation loop.

## Target layout (one folder = still USB-portable as a unit)
```
ZeroBreach-V23.ps1        <- thin loader; keeps the param() block + self-elevation,
                             then dot-sources engine/* in a fixed order
engine/
  Core.ps1                globals, Get-Sig, Get-Perm, Get-ScanFiles, Add-Finding,
                          Show-PhaseHeader / phase timing, Test-ContentRules, Get-AuthSig,
                          Get-SignatureVerdict, Get-FileEntropy
  Phases-Forensic.ps1     group the 119 phases by threat category using data/coverage_matrix.json
  Phases-Persistence.ps1
  Phases-Network-C2.ps1
  Phases-Ransomware.ps1
  Phases-Credential.ps1
  Phases-Email.ps1        (74.5/74.6/74.7)
  Phases-Privesc-Integrity.ps1   (108–115)
  FixActions.ps1          the remediation/fix switch (~V23:4794+) incl. Quarantine action
data/*.json               signatures — unchanged
```
(Exact module grouping: derive category per phase from `data/coverage_matrix.json` threat_types /
tactics. Keep dot-source ORDER = Core first, then phase modules, then FixActions.)

## Non-negotiable constraints (where a refactor breaks the tool — verify EACH after)
1. **UTF-8 BOM on every `.ps1`** (PS5.1 misparses the box-drawing banner chars otherwise). Write via
   `[IO.File]::WriteAllText($p,$txt,(New-Object System.Text.UTF8Encoding($true)))`.
2. **All dot-source paths from `$PSScriptRoot`** (e.g. `. "$PSScriptRoot\engine\Core.ps1"`) so they
   resolve after self-elevation drops CWD to System32.
3. **Parse-clean**: `[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$null,[ref]$e)`
   → 0 errors on the loader AND every module.
4. **AMSI-clean**: signatures stay in `data/*.json`, never inline (see CLAUDE.md "AMSI / Defender").
   Re-test with a path-only command line (see validation loop).
5. **JSON outputs stay UTF-8 no-BOM** (`UTF8Encoding($false)`).
6. **Self-elevation re-passes all args**; the loader keeps the full `param()` block and the
   `Start-Process -Verb RunAs` re-launch.
7. **Single-folder USB portability** — the whole project folder copies as a unit; no absolute paths.

## Validation loop (run after the split — same as UPGRADE_PLAN.md)
1. Parse-check loader + all modules (0 errors).
2. AMSI: spawn engine with a path-only arg line, ~12s, confirm banner/phases stream and stderr has
   no `ScriptContainedMaliciousContent`.
3. Live GUI run: `Launch-GUI.bat` as admin → scan reaches the final phase (115) → JSON in `reports/`
   → clean re-run.

## After the split — resume the upgrade
Then do WS0 GAP 1 (if not already: backfill `phase_map` for 74.5/74.6/74.7/105+/108–115), then WS1
(externalize inline name-lists — see `WS0_COVERAGE_GAPS.md` GAP 2) and WS2 (new malware domains —
GAP 3). All keyed off `data/coverage_matrix.json`.
