# Scythe — "Kraken Console"

Windows-only MSP incident-response / malware-detection tool. Scans a local machine for
indicators of compromise, triages findings with severity + MITRE ATT&CK tagging, and offers
reversible, operator-confirmed remediation behind a hard safety guard.

**Scythe ships as two engines that do the same job.**

| | Native engine (primary) | PowerShell engine (fallback) |
|---|---|---|
| What it is | `scythescan` — a single self-contained `win-x64` executable | `Scythe-V23.ps1` + `engine\*.ps1`, run by `powershell.exe` |
| Built from | C# / .NET 8 (`Scythe.*` projects) | PowerShell 5.1 |
| Delivery | Download one file, run it. No install, no .NET runtime. | Copy a folder, double-click `Launch-GUI.bat` |
| Detection surface | 10 scanners / 63 checks | 162 phases (`-Mode HUNT`) |
| Why it exists | The goal. One file a technician downloads and runs. | The escape hatch — see below. |

## Why two engines

The native exe is the product goal: one downloadable file, nothing to install.

The PowerShell engine exists because of a delivery problem, not a capability problem. An
**unsigned** single-file PE that enumerates processes, walks autoruns, reads event logs and
deletes files under an elevated token is — to any EDR — indistinguishable from malware by
behaviour alone. Until a code-signing identity exists and has accumulated reputation, that exe
should be *expected* to get quarantined on arrival at some client sites.

The PowerShell engine has the opposite profile: it runs inside `powershell.exe`, a Microsoft-signed
host binary, executing script text any EDR and any support tech can read. Worse first-run
experience, far better survivability on a hostile endpoint.

So: **native exe is the goal, PowerShell is the version that still works when the exe gets ripped
away by Defender.** Both are maintained. See `BLUEPRINT.md` §2 for the full reasoning and
`docs/_history/PACKAGING_STUDY.md` for the costed analysis behind it.

---

## Quick start

### Native engine
```powershell
scythescan --mode full
```
Single executable, self-elevates, writes a report next to itself. Exit codes: `0` clean,
`2` findings, `3` coverage gaps, `1` usage/operational error.

Add `--log <path>` to keep a plain-text transcript of the console alongside the reports —
written as the run happens, so a cancelled or crashed scan still leaves a readable file.
(Not to be confused with `scythescan log`, which is the tamper-evident record of remediation
actions.) `scythescan help` lists every option.

### PowerShell engine
1. Double-click **`Launch-GUI.bat`**.
2. Approve the UAC prompt — it self-elevates.
3. Your browser opens the Kraken Console. Click **Run / Start Scan**.
4. Findings stream live; a JSON report lands in **`reports\`**.

No install, no Python, no internet needed.

---

## Requirements

- Windows 10/11, or Server 2016/2019/2022
- Administrator rights (both engines self-elevate)
- **Native engine:** nothing else — the runtime is bundled (`SelfContained`, `win-x64`)
- **PowerShell engine:** PowerShell 5.1, built into every supported Windows

Windows 10 is supported deliberately, not as a legacy courtesy: Server 2016/2019/2022 are
Win10-lineage builds, so Win10 support *is* server support. See `BLUEPRINT.md` §6.

---

## Deploying the PowerShell engine to another machine

**A. Build a release zip (recommended):**
```powershell
powershell -ExecutionPolicy Bypass -File tools\Build-Release.ps1
```
Validates every script (parse + BOM) and data file (JSON), then writes
`dist\Scythe-V23_<stamp>.zip` + a `.sha256` sidecar. `-OutDir D:\` writes straight to USB.

**B. Copy the whole folder** — works, but brings dev files and old reports along.

**On the target box:** copy the zip over → right-click → **Properties → Unblock** → **Extract All**
→ double-click **`Launch-GUI.bat`** → approve UAC. Reports land in the extracted folder's
`reports\`. The server also self-unblocks its runtime tree at startup as a fallback.

---

## Scan modes

Pick in the GUI, or pass `-Mode` (PowerShell engine) / `--mode` (native `scythescan`) on the CLI.

**The two engines do not accept the same set.** `-Mode` takes all six below. **`--mode` accepts
only `QUICK`, `FULL`, `DEEP` and `STEALTH`** — the native engine has no PARANOID or HUNT and
hard-errors on them (`Scythe.Cli/CliOptions.cs`).

| Mode | Roughly | PS phase ceiling |
|---|---|---|
| `QUICK` | Fast high-signal triage | 30 |
| `FULL` | Standard full audit | 80 |
| `DEEP` | Full + deeper/slower checks | 133 |
| `PARANOID` | Most aggressive heuristics, more findings and more noise | 133 |
| `STEALTH` | Silent; engine emits one JSON blob, parsed at completion | 133 |
| `HUNT` | DEEP + the threat-hunting band (cross-view rootkit, anti-forensics, process memory, network exposure) | 162 |

**Time window:** how far back to look. `0` = all time, `N` = last N hours.

HUNT is deliberately not folded into DEEP — it walks process memory (phases 141-145), so it costs
real wall-clock and stays an explicit operator choice.

**162 is the phase-number ceiling, not the count that executes.** Phases 146-152 and 157-159 are
still stubs, so a HUNT run performs roughly 153 phases. The network-exposure phases 153-156 are
host-side reads only — they send no packets and do not enumerate the network.

---

## Safety model

The same rules bind both engines. Full detail in `CLAUDE.md`; the short version:

1. **Only CRITICAL/HIGH + a destructive fix action is ever auto-selected.** POSSIBLE and INFO
   are shown and never pre-ticked — including by "select all".
2. **Nothing auto-selected may damage a healthy machine.** No `icacls /reset /T`, no
   `vssadmin delete shadows /all`, no recursive or drive-root deletes. Dangerous commands go in
   the finding *description* with an Info-only action.
3. **Protected targets are a hard block with no override** — core OS directories, cert store,
   LSA/boot/code-integrity keys, OS-critical and security processes, and the tool's own files.
4. **Quarantine beats delete.** Anything not hash-confirmed is moved to a reversible vault with
   a restore manifest, not deleted.
5. **Never report clean for a check that could not run.** A disabled log source, an unloaded
   hive, an exhausted budget or an access denial reports *inconclusive*, never *clean*.
6. Remediation requires typed confirmation (`PURGE` in the GUI, `CONFIRM` in the CLI).

Trusted RMM vendors (Datto / CentraStage / Kaseya and friends) get a soft trust signal, not a
pass — a vendor name in a suspicious path, or any independent malicious signal, still flags.

---

## Magic keywords (GUI, type before scanning)

- `msp`, `gannon`, `staples` → MSP mode: orange theme, MSP badge.
- `kraken` → type it and see. Skippable with ESC.

(There is no `fast` keyword — README claimed one until 2026-08-22; it never existed in `app.js`.
Use the FX intensity tiers instead.)

## The console (PowerShell engine GUI)

12 switchable themes plus one secret; a cinematic VFX layer with OFF/LITE/FULL/MAXIMUM
intensity; synthesized sound with no audio files; a Ctrl+K command palette; and a
destructive-action gate that requires typing `PURGE`.

The engine streams clean structured data — all effects render client-side, so they never slow
the scan.

---

## Running the PowerShell engine directly

```powershell
powershell -ExecutionPolicy Bypass -File .\Scythe-V23.ps1 -Mode FULL -Hours 0 -Auto
```

| Param | Values | Notes |
|---|---|---|
| `-Mode` | QUICK / FULL / DEEP / PARANOID / STEALTH / HUNT | Empty = interactive menu |
| `-Hours` | int | `0` = all time, `N` = last N hours |
| `-Auto` | switch | Skip all menus (the GUI always passes this) |
| `-Html` | switch | Also write an HTML report |
| `-Paranoid` / `-Stealth` | switch | Same as choosing that mode |
| `-OutDir` | path | Where reports go (defaults to `.\reports`) |
| `-IocFile` | path | Custom indicator list (format: `data\ioc_defaults.json`) |
| `-Baseline` | path | Diff this run against a prior baseline JSON |
| `-Schedule` | DAILY / WEEKLY | Registers a 02:00 SYSTEM scheduled task, then exits |
| `-SmtpTo` / `-SmtpFrom` / `-SmtpServer` | string | Email delivery for scheduled runs |

`Scythe-Server.ps1` accepts `-Port <n>` (default: auto-pick a free port) and `-NoBrowser`.

---

## Where things live

```
Scythe.Cli/             Native engine entry point (scythescan)
Scythe.Core/            Finding model, ledger, budgets, profiles, signatures, reporting
Scythe.Scanners/        The 10 detection scanners + their signature JSON. Read-only.
Scythe.Remediation/     The only module that mutates the machine
Scythe.Tests/           xUnit suite

Launch-GUI.bat              PowerShell engine entry point (double-click)
Scythe-Server.ps1       Local web server for the PS engine
Scythe-V23.ps1          PS scan-engine loader (dot-sources engine\)
engine\                     The 162 PS scan phases + summary + fix mode
gui\                        Web UI (HTML/CSS/JS)

data\                       Signatures, MITRE map, IOC defaults, ACL baseline
tools\                      Release builder, report renderer, run compare, test suite
reports\                    Scan results, quarantine vault, server logs (auto-created)
docs\_history\              Audits, packaging study, superseded plans — dated records
_python\                    Alternate Flask server (parked)
```

---

## Troubleshooting

- **"It scanned nothing / instantly said complete"** — a Defender/AMSI block. The PS engine
  keeps every signature literal in `data\detection_signatures.json` precisely so AMSI does not
  flag it at load. No Defender exclusion should be needed; if one is, that is a bug worth
  reporting.
- **The native exe was quarantined on arrival** — expected until code signing is in place. Use
  the PowerShell engine at that site and see `BLUEPRINT.md` §2.
- **Reports not appearing** — check `reports\` is writable (not read-only or an ejected drive).
- **Launch failure** — `Launch-GUI.bat` stays open and writes `scythe_launch_error.log`.

---

## Project docs

| File | Role |
|---|---|
| `BLUEPRINT.md` | Product map: architecture, both engines, data contracts, safety model, roadmap. **Start here.** |
| `CLAUDE.md` | Hard rules and subsystem reference for anyone editing code. |
| `HANDOFF.md` | Current session state and validation runbooks. |
| `CHANGELOG.md` | Dated history of every fix and false-positive tuning round. |
| `TEST_LAB_GUIDE.md` | Building and running the malware test lab. |
| `INSTRUCTIONS_AI.md` | Native (`scythescan`) engine architecture + the catalog of all 63 checks. Native only. |
| `_ENGINE_SPEC_FOR_REBUILD.md` | Normative build contract for the native engine — read it for *why* a rule exists. |
| `ADVERSARY_ANALYSIS.md` | Adversarial assessment that produced the 134-162 band. **Historical — read its status banner first.** |
| `docs/ATTACK_LOG.md` | Authorized adversary-emulation log against the operator's own hardware; every technique that works becomes a detection. |
| `docs/attack-logs/` | Raw command logs and captures behind `ATTACK_LOG.md`. |
| `docs/_history/` | Audits, the packaging study, superseded plans. Dated records — read, don't rewrite. |
