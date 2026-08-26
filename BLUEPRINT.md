# ZeroBreach "Kraken Console" — Product Blueprint

> **The definitive top-level map of what this tool is, how it fits together, and where it goes
> next.** Rules live in `CLAUDE.md`; history lives in `CHANGELOG.md`; session state lives in
> `HANDOFF.md`. This file changes only when the product itself changes shape.
> Last structural update: 2026-08-20 — dual-engine restructure.

## 1. Mission

A **single-operator Windows incident-response tool** for MSP techs. A technician arrives at a
machine that is misbehaving, runs ZeroBreach, and gets:

1. **Detect** — indicators of compromise across the full malware taxonomy (RAT/C2, ransomware,
   rootkits, keyloggers, worms, miners, trojans, spyware, fileless/LOLBins, persistence,
   credential theft, exfil, email/phishing, BYOVD, permission integrity).
2. **Decide** — findings triaged with severity, MITRE ATT&CK technique, threat type, a
   protected-target hard block and a trusted-vendor soft signal, so the checklist can be trusted.
3. **Act** — reversible, operator-confirmed remediation (quarantine-first), with a hard rule that
   **nothing auto-selected can ever damage a healthy system**.
4. **Report** — structured JSON plus rendered HTML/CSV the provider hands to the client.

**Non-goals:** offensive tooling, host-AV evasion, darkweb/Tor intel, non-Windows targets,
anything that touches a remote machine. Resolve ambiguity toward the more conservative, more
clearly defensive interpretation.

## 2. Two engines, one product

ZeroBreach ships **two independent implementations of the same tool**. This is deliberate and
permanent, not a migration artifact.

| | Native engine — **primary** | PowerShell engine — **fallback** |
|---|---|---|
| Artifact | `zbscan`, one self-contained `win-x64` exe | `Launch-GUI.bat` + a folder of `.ps1` |
| Language | C# / .NET 8 | PowerShell 5.1 |
| Runtime dependency | None (runtime bundled) | `powershell.exe`, present on every Windows |
| Detection surface | 10 scanners / 63 checks | 162 phases |
| Operator UX | CLI, one downloadable file | Browser GUI, cinematic console |
| EDR posture | Unsigned new PE — **poor until signed** | Signed Microsoft host running readable script |

### Why the fallback exists

The native exe is the goal: one file a technician downloads and runs, nothing to install.

But the delivery problem is real and it is not about capability. From an EDR's point of view, a
ZeroBreach run is: an elevated process enumerates running processes and loaded modules, reads
autorun and service configuration across the registry, walks scheduled tasks and WMI
subscriptions, reads event logs, hashes files in user-writable paths, and — in remediation —
kills processes and deletes files. That is the canonical *security tool or malware, flip a coin*
profile.

The only things that push the coin toward "tool" are a known signer, accumulated reputation for
that signer and that binary, human-readable content, and prior allowlisting at the site.

- A **brand-new unsigned PE** has none of them, and hides its content besides. It should be
  *expected* to be quarantined on arrival or blocked at first run at some client sites.
- The **PowerShell engine** arrives inside `powershell.exe` — Microsoft-signed, universally
  allowlisted — running script text any EDR can inspect and any support tech can read over the
  phone.

So the native exe is what we ship, and the PowerShell engine is what still works when the exe
gets ripped away by Defender. **Both are maintained.** Full costed analysis in
`docs/_history/PACKAGING_STUDY.md` (finding 1 survives the move to C#; findings 2 and 3 do not —
see the superseding header on that file).

### Capability parity

**Goal: everything either engine can do, the other should be able to do**, with a documented
delta where a runtime genuinely cannot.

Today the parity gap runs the *opposite* way from what "native rebuild" suggests — the
PowerShell engine is far ahead on coverage and the native engine is ahead on architecture:

| Area | Native | PowerShell | Gap owner |
|---|---|---|---|
| Detection breadth | 10 scanners / 63 checks | 162 phases | **Native must catch up** |
| Safety model | Architectural read-only/destructive split, enforced by a source-grepping test | Three mirrored guard copies kept in sync by a test | Native is cleaner |
| Coverage honesty | Every check ends `Completed` / `Inconclusive` / `Skipped`; exit `3` on gaps | Phase-level recovery traps; no per-check status | **PS should adopt** |
| Finding identity | Deterministic `ComputeId(group, target, discriminator)` | Engine-assigned ids | **PS should adopt** |
| WOW64 correctness | N/A — always 64-bit by construction | Explicit `Get-RegVal64` / `ZB_SYS32` handling required | Native wins by design |
| Operator GUI | None (CLI only) | Full browser console | **Native gap, low priority** |
| Signature storage | Embedded resources + on-disk merge | On-disk `data/*.json` only | See §8 |

Closing the detection gap is the main body of work; the per-scanner roadmap is
`fable-work/tasks/_deferred/` (§9).

## 3. Architecture

### Native engine

```
zbscan  (single self-contained win-x64 executable)
   ├─ ZeroBreach.Cli          entry point, console output, interactive remediation/IOC/triage
   ├─ ZeroBreach.Core         finding model, check ledger, budgets, profiles, signature DB,
   │                          reporting, triage/escalation. No destructive operation exists here.
   ├─ ZeroBreach.Scanners     the 10 detection scanners, one file each, + signature JSON.
   │                          READ-ONLY by architecture.
   ├─ ZeroBreach.Remediation  the ONLY module that mutates the machine. Small and auditable.
   └─ ZeroBreach.Tests        xUnit, incl. ScannerReadOnlyAuditTests which greps Scanners/Core
                              sources and fails the build if a destructive API appears.
```

The read-only / destructive split is **architectural, not stylistic** — it is what keeps the
safety audit surface tiny. Never add a mutating call to Core, Scanners, or a scanner helper.

The ten scanners: `Persistence`, `C2`, `CredentialAccess`, `DefenseEvasion`, `RootkitBoot`,
`Ransomware`, `ContentScan`, `EmailResidue`, `EventLog`, `AclIntegrity`.

### PowerShell engine

```
Launch-GUI.bat  (self-elevates → admin)
   └─ ZeroBreach-Server.ps1          pure-PS HttpListener server, SSE at /api/events
        ├─ serves gui/  (index.html + css + js: sound→themes→fx→kraken→app)
        ├─ scan runspace ── spawns ── powershell.exe ZeroBreach-V23.ps1 -Auto …
        │     stdout (UTF-8) ─→ parse loop ─→ SSE events ─→ browser
        ├─ remediation runspace ($script:REMEDIATE_SCRIPT — mirrors Invoke-FixMode)
        └─ reports/  (baseline JSON, HTML, console + SSE logs, quarantine vault)

ZeroBreach-V23.ps1  = THIN LOADER  (params/elevation/globals/ALL helpers/banner/menus)
   └─ dot-sources, in order, into ONE scope:
        engine/Phases-0.ps1   PREFLIGHT — integrity + anti-blinding gate (every mode, no header)
        engine/Phases-1.ps1   phases 1-58    (incl. 55.5 BYOVD)          ┐ each module has its
        engine/Phases-2.ps1   phases 59-89   (incl. 69, 74.5/.6/.7)      │ OWN top-level trap
        engine/Phases-3.ps1   phases 90-115  (incl. 99.5) + integrity    │ (see CLAUDE.md)
        engine/Phases-4.ps1   phases 116-133 Extended malware + tamper   │
        engine/Phases-5.ps1   phases 134-145 HUNT cross-view + memory    │
        engine/Phases-6.ps1   153-156 network exposure; rest STUB (§9)  │
        engine/Phases-7.ps1   phases 160-162 synthesis / correlation     ┘
        engine/Summary.ps1    risk score + exits ([Environment]::Exit)
        engine/FixMode.ps1    interactive fix mode (console runs only)
```

**Why this shape holds:** phases run in numeric order and share variables across phases, so
modules split **by range, not category**, and dot-source into one scope. All signature literals
live in `data/*.json` because AMSI blocks a `.ps1` containing them. Entry files and engine
modules are UTF-8 **with BOM**; JSON outputs are UTF-8 **no BOM**.

## 4. Data contracts

### PS engine → server (child stdout, UTF-8)

| Line shape | Meaning |
|---|---|
| `[FINDING] {compact JSON}` | **Authoritative live finding** — emitted by `Add-Finding` in non-interactive runs. Keys: `id, sev, phase, tt, desc, target, fix, group`. The server converts CRITICAL/HIGH/POSSIBLE into SSE `finding` events and never shows the raw line. |
| `PHASE N — …` / `PHASE N — … took X.Xs` | Phase tracking (`PHASE\s+(\d+(?:\.\d+)?)[^\d]` — fractional phases keep their decimal and advance the counter) + per-phase profiling. |
| everything else | `log_line` — severity regex-classified **for colouring only**, never into findings. |
| STEALTH mode | one compressed-JSON audit blob on stdout; server buffers and parses post-exit. |

### Server → browser (SSE `/api/events`)

| Event | Key fields |
|---|---|
| `log_line` | `text, severity, phase, elapsed` |
| `finding` | `id, line, severity, threat_type, phase, mitre{id,name,tactic,url}, mitre_id, fix_action, target, timestamp` |
| `scan_state` | `phase, phase_total, phase_name, section, elapsed, threat_counts, running` — on every phase change + every 12 lines |
| `scan_complete` | `findings_count, threat_counts, elapsed, results_path, engine_report` |
| `scan_failed` | emitted **instead of** `scan_complete` when the engine fails |
| `remediation_complete` | `applied, failed, skipped, blocked` |
| `sync` | full state snapshot on (re)connect |

At `scan_complete` the frontend **replaces** its live findings list with the engine report, so
the live stream drives the in-scan experience and the report drives triage/remediation.

### Native engine exit codes

`0` clean · `2` findings · `3` coverage gaps (inconclusive/skipped/unchecked) · `1` usage or
operational error. **A narrowed or timed-out scan must never exit `0`.**

### Other formats

- **IOC file** (`reports/custom_iocs.ioc`, via `-IocFile`): prefixed text — `hash:` / `ip:` /
  `domain:` / `regex:` / `file:`.
- **Quarantine manifest**: file moved to `reports/quarantine/*.quar` + a `.quar.json` carrying
  original path, SHA256 and restore command.
- **HTTP routes** (PS server): `/api/scan/start|abort`, `/api/state`, `/api/events`,
  `/api/report?name=`, `/api/remediate {report, ids[]}`, `/api/export/html|csv`, `/api/ioc`
  GET/POST, `/api/profiles` GET/POST, `/api/sysinfo`.

## 5. Safety model (the product's spine)

These bind **both engines**. Enforcement mechanics differ; the rules do not.

1. **Auto-select rule** — only CRITICAL/HIGH **plus** an executable destructive fix action is
   ever pre-ticked. POSSIBLE/INFO are shown, never auto-acted, including by bulk "select all",
   which shares the same gate by construction. Every FP-tuning round works by downgrading to
   POSSIBLE/Info, never by deleting a detection.
2. **Rule #1** — never ship a destructive fix parameter that an auto-select can fire on a
   **healthy box**. No `icacls /reset /T`, no `vssadmin delete shadows /all`, no recursive or
   drive-root deletes. Dangerous commands go in the *description* with an Info-only action.
3. **Protected targets = hard block, no override** — core OS directories, cert trust store,
   LSA/boot/code-integrity keys, OS-critical and security processes, the tool's own files.
   Checked immediately before every destructive action, not only at planning time.
4. **Trusted vendors = soft signal** (Datto / CentraStage / Kaseya / AEM and friends) — green
   badge, not auto-selected, operator may still act. A vendor name in a suspicious path, or any
   independent malicious signal, overrides the trust.
5. **Reversible beats destructive** — a non-hash-confirmed delete is downgraded to quarantine by
   the executor itself, not merely by the caller.
6. **Never report clean for a check that could not run** — disabled log source, unloaded hive,
   exhausted budget, access denied, crash: emit inconclusive/skipped with the scope. A false
   all-clear is the worst bug an IR tool can ship.
7. **Typed confirmation before any remediation batch** — `PURGE` in the GUI, `CONFIRM` in the
   CLI — validated in the executor, not only in the UI. Every attempt and outcome is logged.
8. **Untrusted indicators never reach a destructive matching path** without individual operator
   confirmation. There is deliberately no "yes to all".

Regression metric: **auto-destructive count from a full `-Hours 0` DEEP baseline** — currently
**52** on the PS engine, all by design. Re-grade after any severity or fix-action change.

## 6. Platform support

**Windows 10 and 11, plus Server 2016 / 2019 / 2022.**

Win10 support is deliberate, not legacy courtesy: **Server 2016/2019/2022 are Win10-lineage
builds** (`10.0.14393` / `10.0.17763` / `10.0.20348`; only Server 2025 moved to the Win11 base).
Dropping Win10 would drop server support with it — and a DC or file server is the highest-value
box on any network this tool gets deployed to.

Neither engine contains OS-version gating today, and neither should acquire any without a
recorded reason. .NET 8 supports Win10 1607+ and Server 2012 R2+, which covers the fleet.

The stragglers still on Win10 are also disproportionately the *infected* ones — EOL, unpatched,
no ESU. An IR tool gets run on the sick machine.

## 7. Quality gates

**Native engine**
1. `dotnet build` clean; `dotnet test` green (Windows-only tests use `Skip.IfNot`, never
   weakened assertions).
2. `ScannerReadOnlyAuditTests` passes — no destructive API in Core or Scanners.
3. Exit-code discipline: a narrowed or timed-out scan never exits `0`.

**PowerShell engine**
1. Parse-clean on **live PS 5.1** and PS 7 — all engine modules + server (+ the server's
   here-strings extracted and checked separately); UTF-8 BOM intact.
2. `powershell -NoProfile -File tools\tests\Run-SecurityTests.ps1` — 617+ assertions.
3. `tools\tests\Verify-OnWindows.ps1` from an elevated 5.1 prompt before any release.
4. AMSI: engine spawns and streams, no `ScriptContainedMaliciousContent`.
5. Headless `-Auto` scan: contiguous `PHASE N — … took` sequence (no module-trap gaps), clean
   self-exit, reports written.
6. Auto-destructive re-grade vs baseline (target 52, and zero system-damage fix params).

**Both**
7. Live acceptance on a real Windows box for anything user-facing.

## 8. Signature storage — an open decision

The two engines store rule content differently, and this needs resolving:

- **PS engine:** `data/*.json` on disk, loaded at runtime. Non-negotiable there — signature
  literals inline in a `.ps1` get the engine AMSI-blocked at load, and the failure is *silent*
  (the tool "runs" and finds nothing).
- **Native engine:** `<EmbeddedResource Include="Signatures\*.json" />` — ~179KB of family
  names, C2 indicators and ransom-note text compiled into the assembly, with an on-disk
  `MergeJson` override path.

The AMSI argument does not apply to a compiled assembly, so embedding is not *unsafe* the way it
was in PowerShell. Two concerns remain and both are real:

1. **Static PE scanning.** A signature database welded into a single-file PE is a known way for
   security tools to be flagged as the malware they detect. Unproven for us — **this is a lab
   test, not a debate** (§10).
2. **Update/reputation coupling.** Every signature change means a new binary, a re-sign, and a
   reset of per-file SmartScreen reputation. The on-disk merge path already exists; making it
   the *primary* content channel decouples rule cadence from binary cadence.

**Working decision:** keep the embedded set as a baseline, promote the on-disk merge path to the
primary update channel, and let the lab test decide whether the embedded baseline shrinks.

## 9. Migration status

This repo is the build target. Source material is copied **in**; the origin repos are never
modified.

| Source | What | Status |
|---|---|---|
| `~/Downloads/engine1` | The five `ZeroBreach.*` C# projects, `docs/`, `INSTRUCTIONS_AI.md`, `_ENGINE_SPEC_FOR_REBUILD.md` | **Copied in** (session 16, committed `41e24d7`). Builds and tests green in this repo. |
| `~/Downloads/claude/fable-work` | G-series deliverables: `New-ScanReport.ps1`, `Compare-ScanRuns.ps1`, `Get-PhaseTimingReport.ps1`, `New-CoverageMatrix.ps1`, `gui/viewer.html`, test harness; plus `HANDOFF_FABLE.md` and `PACKAGING_STUDY.md` | **Copied in** (session 16, committed `e8eea6c`; `viewer.js`/`viewer.css` were missed and landed in session 18). All 8 tasks (G1-G8) confirmed complete 2026-08-26: 355 assertions green under `pwsh` 7.4.6, every suite fail-on-revert proven. |
| `zerobreach/fable-work` | F-series briefs (deferred): cloud/DevOps creds, lateral+AD+cred-dumping, rule engine, persistence surface, supply chain, LAN band, UEFI, packaging | **Already here — the only surviving copy.** Becomes the native scanner roadmap. |
| `~/Downloads/claude/fable-work-2` | The library layer beneath the engine: YARA parser/matcher/conditions/scan-API (A1-A4), Sigma engine (A5), PE structure parser (B1), ZIP/OLE/OOXML container reader (B2), Windows path normaliser (C1), signature/rule linter (C2), IOC feed normaliser — STIX/MISP/OpenIOC (D1), baseline diff engine (D2), configuration baseline evaluator (D3) | **Copied in 2026-08-26** to `lib/`, wired into `ZeroBreach.sln`. All 12 tasks complete; independently re-verified here, not taken on trust: 1,374 tests, 0 failed, 0 skipped, 0 warnings, with `yara` 4.5.5 present so the differential suites ran live. Solution total **1,664 passed / 14 skipped**. Nothing in `ZeroBreach.*` references it yet — see §10 item 6. |
| `~/Downloads/claude/fable-work-3` | The offline artifact layer and record production: Windows artifact readers (event log, registry hive, shell link, execution evidence), file-system metadata, embedded databases (SQLite, ESE), configuration/policy, storage + firmware inventory, image/package containers, message stores, analysis primitives, script structure, and the correlation/scoring/export/technique-map layer | **Specified 2026-08-26, not yet built.** 11 tracks / 30 tasks / 30 projects, all `net8.0` and Linux-testable. Replaces "ask Windows for it" with "read the documented on-disk format", which is what makes the whole layer developable off Windows. |

All origin repos are **read-only to this project**. They are also the packages a
safeguard-restricted assistant will work in, so their sanitized framing must not be disturbed.

The F-series briefs map onto native scanners roughly as: F1 → a new cloud-credential scanner ·
F2 → extends `CredentialAccessScanner` · F3 → extends `SignatureDb` · F4 → extends
`PersistenceScanner` · F5 → a supply-chain scanner · F6 → a LAN scanner · F7 → extends
`RootkitBootScanner` · F8 → superseded by the native csproj, fold into packaging docs. Exact
mapping is a follow-on audit.

## 10. Roadmap

### Now
1. ~~**Copy in the two source trees** (§9) and get `dotnet build` + `dotnet test` green in this
   repo.~~ **Done** — 290 passed / 14 skipped / 0 failed.
2. **Test lab, native engine survival test.** Before any malware: publish the real single-file
   exe, deliver it to a clean Win11 box the way a technician would (downloaded, mark-of-the-web
   intact), and find out whether Defender lets it land and lets it finish. Twenty minutes, zero
   risk, and it is a go/no-go on the entire delivery model. See `TEST_LAB_GUIDE.md`.
3. **Start the code-signing identity.** Longest lead time of anything on this list, and it gates
   every packaging option. Azure Trusted Signing is the cheapest credible route; validation
   takes days to weeks and needs a verifiable business history.
4. **Windows validation of the HUNT band** — phases 134-162 have never met the PS 5.1 parser, a
   live registry provider or a real process table. Expect the counter to reach 162 and an FP
   round on 136/139/141. **Now includes 153-156** (network-exposure band, built 2026-08-22):
   these read real registry values, so a Windows run is the first time their absence rules
   (absent vs zero vs default-applies) are exercised against a live provider — the single most
   likely place for them to be wrong.
4a. **Fill the remaining `Phases-6.ps1` stubs** — 146-152 and 157-159 are still the parallel work
   package. When filling them, apply the CLAUDE.md rule on stubs and test lists first.
5. **Windows validation of the Extended band** (116-133) — exercised only on Linux/pwsh so far.

### Next
6. **Wire up the `lib/` library layer.** ~~Copy it in~~ **done 2026-08-26** — six projects under
   `lib/`, in the solution, 1,664 tests green, shipped exe unchanged. What remains is the design
   decision, not a port: how `ZeroBreach.Rules` (YARA + Sigma) plugs into `ZeroBreach.Core`'s
   `SignatureDb` and the 10 scanners. Replacing hand-written JSON signatures with rule-corpus
   matching is the actual multiplier; having the library on disk is not. `ZeroBreach.Formats`
   (PE, containers) is what a `ContentScan`-style scanner needs to look *inside* a file rather
   than only at it. Prerequisite for item 7, not parallel to it.
   - **Start with the linter.** `ZeroBreach.Rules.Linting` independently re-implements five hard
     rules this repo learned the expensive way — the `Join-AllowRegex` universal-pattern canary
     set, the real-software-name collision corpus, the 150 ms backtracking budget, and the
     "allowlist must not swallow its own detection branch" check — and `LintTool` is already
     CLI-shaped with 0/1/2 exit codes. Pointing it at `data/detection_signatures.json` is the
     highest-value, lowest-risk wiring available, and it improves the **PS** engine from C#.
   - **One blocker, and it is ours:** the linter expects allowlists under an `fp_allowlists`
     object because `CLAUDE.md` says they live there. The shipped file has no such key — it is
     flat, and `Join-AllowRegex` reads flat names via `Get-Sig`. Decide which side moves before
     writing code against either.
7. **Close the detection parity gap** — port PS coverage into native scanners, F-series first,
   built on the item-6 library layer where a track maps onto one (YARA/Sigma → `SignatureDb`,
   PE/containers → `ContentScan`, path normaliser → the destructive-op guard, IOC normaliser →
   the IOC manager, baseline diff → cross-run comparison, config baseline → the FP-tuning bands).
8. **Per-check status in the PS engine** — adopt the native `Completed`/`Inconclusive`/`Skipped`
   discipline and a non-zero exit on coverage gaps. This is the single highest-value idea to
   flow *back* from the rebuild.
9. **Deterministic finding ids in the PS engine** — baseline diffing depends on identity
   stability.
10. **FP rounds on both new PS bands** — Extended and HUNT ship `Info` throughout precisely
   because they have never met a real fleet.
11. **Sign the PS scripts** once a certificate exists — improves AMSI/EDR posture and unlocks
    per-site `AllSigned` policies, with zero repackaging risk.

### Later
- Richer executive summary, per-tactic MITRE rollup, trend/diff view across baselines.
- Scheduled scans productized (`-Schedule` + SMTP hardening + a GUI panel).
- Fleet ideas: central drop-folder for baselines and a compare view.
- A native-engine operator UI, if the CLI ever proves insufficient.

## 11. Doc map

| File | Role |
|---|---|
| `BLUEPRINT.md` | This file — product shape + roadmap. Start here. |
| `CLAUDE.md` | Hard rules + subsystem reference for anyone editing code. |
| `HANDOFF.md` | Current session state + validation runbooks. |
| `CHANGELOG.md` | Dated narrative of every fix and tuning round. |
| `TEST_LAB_GUIDE.md` | Building and running the malware test lab. |
| `README.md` | Operator-facing quick start and deployment. |
| `docs/ATTACK_LOG.md` | Authorized adversary-emulation log against the operator's own hardware. Every technique that works becomes a detection; each entry ends with the phase that catches it. **Append-only, and it records refusals too.** |
| `docs/attack-logs/` | Raw command logs and captures behind `ATTACK_LOG.md`. |
| `docs/_history/` | Audits, packaging study, superseded plans. **Dated records — append, never rewrite.** |
| `fable-work/` | Deferred F-series scanner briefs, and the merged G-series operator tooling's own handoff/packaging docs (§9). |
| `lib/` | The merged library layer — `net8.0`, platform-neutral, Linux-testable. `lib/Directory.Build.props` documents why the directory boundary exists; do not change its target framework. |
| `docs/_history/HANDOFF_FABLE2.md` | Every judgement call, file list and test count from the library-layer package, per task. Read before wiring any of `lib/` into the engine. |
| `~/Downloads/claude/fable-work-2/` (outside this repo — §9) | The origin package for `lib/`. Kept as the sanitized standalone; its framing must not be disturbed. |
| `~/Downloads/claude/fable-work-3/` (outside this repo — §9) | The **offline artifact layer** package: 11 tracks / 30 tasks, specified but not built. Self-contained `CLAUDE.md`/`README.md`/`BLUEPRINT.md`, and `tools/check_register.py` for auditing its own writing register. |
| `_python/README_CLAUDE_CODE.md` | Parked Python server spec. |
