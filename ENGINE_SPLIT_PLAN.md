# Engine Split Plan (approved 2026-06-29 — NOT yet executed)

> Self-contained handoff doc (lives in the repo so it survives a machine change). This is the
> finalized decision and exact plan for restructuring the scan engine. **Do this as its own
> validated workstream, BEFORE WS1–WS6**, and run the full validation loop end-to-end after.

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
