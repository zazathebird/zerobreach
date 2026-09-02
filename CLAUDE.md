# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repo.

> **`BLUEPRINT.md` is the product map** (architecture, data contracts, safety model, roadmap) —
> read it first for orientation. **Detailed bug-fix history and the FP-tuning rounds live in
> `CHANGELOG.md`.** This file keeps the durable **rules** only. When you fix something
> noteworthy, add a dated entry to `CHANGELOG.md` and, if it produces a new "never do X"
> lesson, a rule below.

## What This Project Is

Scythe is a **Windows-only MSP incident-response tool**, shipped as **two independent engines
that do the same job**:

1. **Native engine (primary)** — `scythescan`, a single self-contained `win-x64` executable built from
   the C# / .NET 8 `Scythe.*` projects. 10 scanners / 63 checks. This is the product goal: one
   file a technician downloads and runs, no install, no runtime.
2. **PowerShell engine (fallback)** — `Scythe-V23.ps1` + `engine/*.ps1` behind a PowerShell HTTP
   server and a cyberpunk HTML/JS frontend. **162 phases** (133 in DEEP, 162 in `-Mode HUNT`). A
   parked Python/Flask server (`_python/server.py`) is an alternative to the PS server.

**Both are maintained.** The fallback is not legacy — it exists because an *unsigned* new PE doing
IR work gets quarantined at client sites, while `powershell.exe` is a Microsoft-signed host running
inspectable script text. Native is the goal; PowerShell is what still works when Defender eats the
exe. Full reasoning in `BLUEPRINT.md` §2; costed analysis in `docs/_history/PACKAGING_STUDY.md`.

**Capability parity is the goal in both directions.** Today the PS engine leads on detection breadth
(162 phases vs 63 checks) and the native engine leads on architecture (read-only/destructive split,
per-check `Completed`/`Inconclusive`/`Skipped` status, deterministic finding ids). See the delta
table in `BLUEPRINT.md` §2.

The PS engine still self-identifies as "V22"/"V23" in some strings (scheduled task name
`Scythe_V22_Scheduled`, banners) — **intentional, not a bug to fix.**

### The project was renamed to Scythe on 2026-08-27 — the old name must not come back

Everything was called **ZeroBreach** until 2026-08-27. The rename was global and mechanical:
`ZeroBreach`/`ZEROBREACH`/`zerobreach` → `Scythe`/`SCYTHE`/`scythe`, and the short internal
prefixes with it — `ZB_ROOT` → `SCYTHE_ROOT`, `Get-ZbProp` → `Get-ScytheProp`, `zbApi()` →
`scytheApi()`, `ZBSound` → `ScytheSound`, `zbfx-*` → `scythefx-*`, `--zb-accent` →
`--scythe-accent`, `X-ZB-Token` → `X-SCYTHE-Token`, `zbscan` → `scythescan`. 1,405 name
occurrences and 243 distinct `zb`-stem identifiers across 377 files, plus 36 renamed paths.
Verified after: `dotnet build` 18 projects 0 warnings, `dotnet test` **1,664 passed / 0 failed /
14 skipped**, and the full PowerShell suite green.

Three things about it are durable rules, not history:

- **The old name survives in a closed list of places, and nowhere else.** Audited 2026-08-27
  after the push: the old product name appears in **9 files** and the `zb` stem in **3**. Audit
  at file granularity, not by occurrence count — the counts drift every time one of these
  documents describes the rename again, the file list does not. Run the case-insensitive search
  for the old product name and the `zb` identifier stem over the tree excluding `.git`,
  `_archive`, `bin` and `obj`, then confirm every hit is on this list:
  - **History and config, describing the past:** this section; the dated entries in
    `CHANGELOG.md`, `HANDOFF.md` and `docs/_history/SECURITY_AUDIT_2026-08-18.md`;
    `docs/MERGE_ARTIFACT_LAYER.md`, which names the pre-rename archive folders; the `.gitignore`
    rules naming the `zerobreach-main` drop that `_archive/` still holds; and `_archive/` itself.
  - **Shipped code, for backward compatibility — three sites**, listed in the bullet below.
  - **One test fixture:** `lib/Scythe.Rules.Tests/Yara/CorpusValidationTests.cs` keeps the
    trailer `"ZBEND"` and the label `zbf-format`. Its paired header is the hex bytes
    `7A 42 46 31`; renaming one half made a fictional format disagree with itself.

  `_archive/` is excluded on purpose: it is a 432 MB dump of the pre-rename repo including
  compiled build artifacts, and rewriting names inside it would be meaningless. Note the search
  is **case-sensitive by default in most tools and the stems are mixed-case** (`ZB_`, `Zb`,
  `zb`) — that is how `Test-ZbAssert.ps1` survived the first sweep.
- **`V22`/`V23` in strings stays.** `Scythe_V22_Scheduled`, the banners, `Scythe-V23.ps1` — the
  version self-identification was already deliberate before the rename and still is.
- **Shipped code may name the old product in exactly three places, and every one of them is
  backward compatibility with a machine that ran the pre-rename build. Do not add a fourth, and
  do not "clean up" these three** — each fails silently and badly:
  - `Scythe-V23.ps1` — the `-Schedule` branch unregisters a leftover `ZeroBreach_V22_Scheduled`
    task before registering the new one, so an existing deployment upgrades to one nightly scan
    rather than two.
  - `Scythe.Scanners/ContentScanScanner.cs` — the self-exclusion list carries the old
    quarantine/vault/report directory names. Drop them and the content scanner reports the tool's
    own quarantined evidence back as findings.
  - `data/detection_signatures.json` → `script_own_strings` — the Phase-2 script-block-logging
    self-filter. Drop the old spelling and the engine flags log entries written by its own
    already-deployed copy.

  Related and **accepted, not fixed**: `Scythe.Remediation/ScythePaths.cs` moved the data root
  from `%ProgramData%\ZeroBreach` to `%ProgramData%\Scythe`. An upgraded machine keeps its vault
  and its tamper-evident action log under the old root and the hash chain cannot span the move.
  The remedy is an operator renaming the directory before the first new run — a silent dual-root
  read would be worse.

The pre-rename tree is copied whole to `~/Downloads/claude/zerobreach-backup-prerename/`. Delete
it once the rename has been exercised on Windows.

### The detection vocabulary is deliberate — do not sanitise it

This tool's source contains words like *exfiltration*, *rootkit*, *keylogger*, *ransomware*,
*credential dumping* and named malware families. **That is correct and it must stay.** Recorded
here because it looks alarming out of context and the instinct to "tone it down" recurs:

- **~335 of them are operator-facing product surface** — `-ThreatType`, `-Group` and `-Description`
  values that appear in the client report. A technician needs to be told data may have left the
  machine. Vague wording makes the deliverable worse.
- **MITRE ATT&CK tactic names are a published standard.** "Exfiltration" is TA0010. Renaming it
  breaks interoperability with every other security product the provider runs.
- **Signature family names identify the thing being detected.** Renaming them breaks detection.

What *is* fair game, and has been done: gratuitous naming with no detection purpose (a dev-sync
script formerly called `exfiltrate.ps1`, now `tools/Publish-WorkBranch.ps1`), edgy banner text, and
comment prose that reads like malware branding. Internal identifiers and comments — yes. Operator
taxonomy, MITRE names and signature content — never.

**And vocabulary is the wrong lever for AV false positives anyway.** Static engines flag an unsigned
PE on *behaviour* — process enumeration, registry walking, file deletion under an elevated token —
not on nouns in `.rdata`. Strings matter for the **PowerShell** engine, because AMSI scans script
content at load (that is the entire reason signatures live in `data/*.json`), and barely at all for
the compiled binary. The real fixes, in order of effect: **code signing + publisher reputation**,
then **vendor false-positive submissions** (McAfee, Gen Digital/Norton and Microsoft all run free FP
portals for legitimate software), then string hygiene a distant third. Measure with a real scan on
the test rig before changing anything on suspicion.

## Launching

```powershell
Launch-GUI.bat            # Default — pure PowerShell server, no Python (recommended)
Launch-GUI.bat python     # Python/Flask server (needs deps installed first)
```

`Launch-GUI.bat` self-elevates to admin, then launches `Scythe-Server.ps1`. On failure the window
stays open and writes `scythe_launch_error.log` to the project root. Requires Windows 10/11,
PowerShell 5.1+, admin rights.

## Architecture

**Data flow (both servers):** Browser → POST `/api/scan/start` → server spawns `Scythe-V23.ps1`
→ stdout streamed line-by-line → parsed/classified → events pushed to frontend in real time.

**Three layers:**
1. **Server** — `Scythe-Server.ps1` (default) or `_python/server.py`. Hosts the UI, manages scan
   state, spawns and reads the PS subprocess.
2. **`gui/static/js/app.js`** — all frontend logic; view switching (boot → config → scan →
   remediation). Native `EventSource('/api/events')` (SSE) — **matches the PS server; there is no
   SSE/SocketIO mismatch** (the Python server uses SocketIO, but it's parked).
3. **`Scythe-V23.ps1`** — the scan engine. Called via subprocess; **not modified for UI changes.**

### File structure

```
├── Launch-GUI.bat              Entry point (self-elevates)
├── Scythe-Server.ps1       Pure-PS HTTP server (default). HttpListener + SSE at /api/events.
│                               SAVED WITH UTF-8 BOM — do not remove (see rules).
├── Scythe-V23.ps1          THIN LOADER (also BOM). param()/elevation/schedule/globals/ALL
│                               helpers/Get-Sig/Get-Perm/banner/resilience trap/menus, then
│                               dot-sources engine/* in execution order. Self-elevates via RunAs.
├── engine/                     Dot-sourced phase modules (each UTF-8 BOM). Split BY RANGE, not
│   │                           category — phases run in numeric order and reuse vars across
│   │                           phases; dot-sourcing into the loader's ONE scope preserves that.
│   ├── Phases-0.ps1            PREFLIGHT — self-integrity & anti-blinding gate. Runs in EVERY
│   │                           mode before phase 1; prints NO numbered PHASE header.
│   ├── Phases-1.ps1            Sections 1-11, phases 1-58 (incl. 55.5 BYOVD)
│   ├── Phases-2.ps1            Sections 12-16 front, phases 59-89 (incl. 69 mutex, 74.5/.6/.7)
│   ├── Phases-3.ps1            if($PhasePlan.Advanced) 90-105+ (incl. 99.5) + Integrity 108-115
│   ├── Phases-4.ps1            if($PhasePlan.Extended) 116-133 — WS6 extended malware + tamper
│   │                           band (browser/app/Office/shell tamper, execution evidence,
│   │                           clipper, RMM, exfil, webhook C2, droppers, web shells, wipers)
│   ├── Phases-5.ps1            if($PhasePlan.Hunt) 134-145 — cross-view rootkit detection
│   │                           (task/service/process/autostart/driver), anti-forensics
│   │                           (timestomp, filename/namespace), process memory (unbacked
│   │                           threads, unexpected CLR host, deleted module backing, image
│   │                           integrity, suspended processes)
│   ├── Phases-6.ps1            if($PhasePlan.Hunt) 146-159. 146-147 + 153-159 BUILT.
│   │                           146 (2026-08-30) PE structural analysis: pure-.NET header/
│   │                           section/import parsing, per-section entropy, SCORED not
│   │                           reported (a lone high-entropy section scores 2 of a 7-point
│   │                           floor; HIGH needs context + 3 distinct signals).
│   │                           147 (2026-08-30) cloud/DevOps credential theft: inventory,
│   │                           plaintext secrets, weak ACLs, staged copies, token-minting
│   │                           command lines. NEVER reads the opaque token caches.
│   │                           153-156 (2026-08-22) network-exposure band, HOST-SIDE ONLY
│   │                           (registry/CIM reads, sends no packets, no -ScanLan switch):
│   │                           SMB signing/guest/null-session, shares + share ACLs,
│   │                           LLMNR/NBT-NS/mDNS/NTLM, firewall + Delivery Optimization.
│   │                           157-159 (2026-08-30) persistence surface (COR_PROFILER,
│   │                           SilentProcessExit, WER, SSODL/SharedTaskScheduler,
│   │                           AutodialDLL, RDP InitialProgram, service triggers, shell
│   │                           droppers, AppDomainManager sidecar — NOT the six phase 126
│   │                           already owns); supply chain
│   │                           (extensions, tasks.json, git hooks/config, npm/NuGet
│   │                           registries, MSBuild inline tasks, Jupyter kernels); UEFI
│   │                           (Secure Boot, dbx, ESP, BCD) — MOUNTS NOTHING.
│   │                           148-152 (2026-08-31) lateral movement, credential
│   │                           dumping, Kerberos/NTLM, outbound reach, logon anomalies.
│   │                           Owns the process-tree and share-access side of inbound
│   │                           lateral (107 owns 7045/4624, 133 owns the command lines);
│   │                           the no-tools credential techniques (106 owns .dmp and the
│   │                           tool names, 41 owns WDigest/RunAsPPL); THIS COMPUTER'S OWN
│   │                           AD object only — NO DIRECTORY ENUMERATION, NO ADCS PROBE.
│   │                           Phases-6.ps1 has NO STUBS LEFT.
│   ├── Phases-7.ps1            if($PhasePlan.Hunt) 160-162 — SYNTHESIS. No new detection:
│   │                           attack-chain correlation, patient zero, timeline export
│   ├── Summary.ps1             risk score + audit summary + stealth/auto exits
│   └── FixMode.ps1             fix-mode entry, rollback snapshot, Invoke-FixMode
├── gui/
│   ├── templates/index.html    Single-page app (the only copy; served by both servers)
│   └── static/
│       ├── css/main.css        Core styles + base :root CSS vars
│       ├── css/fx.css          VFX overlays, cmd palette, danger modal, cinematic FX toggles
│       └── js/  (load order: sound → themes → fx → kraken → app)
│           ├── app.js          SSE client, views, cmd palette (Ctrl+K), PURGE modal, CINE_FX
│           ├── sound.js        ScytheSound — synthesized Web Audio SFX (no audio files)
│           ├── themes.js       ScytheThemes — 12 themes + secret KRAKEN theme (inline body CSS vars)
│           ├── fx.js           ScytheFX — canvas renderers + intensity tiers OFF/LITE/FULL/MAX
│           └── kraken.js       ScytheKraken — ~19s "kraken" unlock cinematic
├── _python/                    Parked Flask/SocketIO server + PyInstaller spec (see README there)
├── data/
│   ├── ioc_defaults.json            Default IOC list for -IocFile
│   ├── detection_signatures.json    Malware signatures + fp_allowlists. Loaded by Get-Sig. KEPT IN
│   │                                DATA so AMSI/Defender doesn't flag the engine (see rules).
│   ├── mitre_mapping.json           MITRE ATT&CK technique map (wired into findings)
│   ├── coverage_matrix.json         Phase-by-phase coverage/gap matrix (WS0 reference — re-audit
│   │                                pending; was generated against the work-rig engine)
│   └── permission_baseline.json     ACL/owner baseline for the perm-integrity phases (108-115)
└── reports/                    Auto-created; scan JSON, quarantine vault, durable server logs
```

For the Python server specifically, read `_python/README_CLAUDE_CODE.md` (full route table, SocketIO
payloads, PyInstaller notes).

### Scan Engine CLI (`Scythe-V23.ps1`)

Self-elevates (`Start-Process -Verb RunAs`, re-passing args). Params:

| Param | Values | Notes |
|---|---|---|
| `-Mode` | `QUICK \| FULL \| DEEP \| PARANOID \| STEALTH \| HUNT` | Empty = interactive menu. HUNT = DEEP + the 134-162 threat-hunting band (ceiling 162). |
| `-Hours` | int | `0` = all time, `N` = last N hours, `-1` (default) = interactive menu |
| `-Auto` | switch | Skip all menus (servers always pass this) |
| `-Html` | switch | Also emit an HTML report |
| `-Stealth` / `-Paranoid` | switch | Equivalent to selecting that mode |
| `-OutDir` | path | Defaults to `reports/`; servers pass an absolute path |
| `-IocFile` | path | Custom IOC list (format mirrors `data/ioc_defaults.json`) |
| `-Baseline` | path | Prior-run baseline for diffing |
| `-Schedule` | `DAILY \| WEEKLY` | Registers a SYSTEM scheduled task (02:00), then **exits before scanning** |
| `-SmtpTo` / `-SmtpFrom` / `-SmtpServer` | string | Email delivery for scheduled runs |

### Output parsing + events

**Live findings come from structured lines, not text classification (since 2026-07-02).**
`Add-Finding` (loader) emits one `[FINDING] {compact JSON}` stdout line per registered finding
in non-interactive, non-stealth runs (keys: `id, sev, phase, tt, desc, target, fix, group`);
the server's scan runspace converts CRITICAL/HIGH/POSSIBLE ones into SSE `finding` events
(exact severity, canonical threat bucket, MITRE-resolved) and drops the raw JSON line from the
log view. **Never re-add a text-severity → finding path in the server** (it would double-count
every detection), and **never print findings to stdout except through `Add-Finding`.** The
engine's human-readable output carries no severity tags — the 2026-07-01 DEEP run produced 0
live finding events (empty threat counters + empty server `audit_*.json`) because the server
tried to regex-classify that text.

`Classify` (PS runspace) / `classify_line()` (`_python/server.py`) still severity-classify every
line, but **only for `log_line` coloring**: `[CRIT]`/`[WARN]`/`[OK ]` (padded — regex must allow
trailing space)/`[HUNT]`/`[INFO]` → `CRITICAL | HIGH | POSSIBLE | CLEAN | INFO | HUNT`; threat
keywords → `RAT | Rootkit | Ransomware | Keylogger | Worm | Miner | Trojan | Spyware | Fileless
| Other`.
**The engine's bracket tag is AUTHORITATIVE; the prose keywords are a FALLBACK for untagged
lines only** (`$SEV_TAG` then `$SEV_RX`; `SEVERITY_TAGS` then `SEVERITY_PATTERNS` in the Python
mirror — keep the two in sync). Reason: the prose words are bare substrings and the engine prints
its own banners — `[HUNT] CHECKING FOR SUSPICIOUS DRIVERS...` classified HIGH and
`-> [OK ] NO ANOMALOUS SERVICES.` classified POSSIBLE, so a perfectly clean scan painted its own
progress log red (audit §5.1, fixed 2026-08-19). **Never move a bracket tag into the prose table
or a prose word into the tag table.** `Classify`'s threat bucket is only a *fallback* for a
finding whose own `tt` doesn't map — it cannot influence the threat chips from ordinary log lines.

Phase headers: `PHASE\s+(\d+(?:\.\d+)?)[^\d]` — **fractional phases (55.5, 74.5/.6/.7, 99.5) keep
their decimal** (since 2026-07-02): they advance the GUI counter/progress as real plan steps,
findings carry the true fractional phase, and both `Resolve-Mitre` copies look up the fractional
`phase_map` key first (integer-floor fallback). `phase_total` stays the plan ceiling per mode
(QUICK 30 / FULL 80 / DEEP+ 133 / HUNT 162, mirroring the loader's `$PhasePlan`).
**Only CRITICAL/HIGH + a destructive FixAction is auto-selected
for remediation** — POSSIBLE is shown but never auto-acted-on (the lever behind every FP downgrade).
**Child stdout is UTF-8 end-to-end:** the loader sets `[Console]::OutputEncoding` to UTF-8 when
stdout is redirected; the server reads with `StandardOutputEncoding = UTF8`. Don't change either
side alone — a mismatch renders every box-drawing banner as mojibake in the GUI.

| Event (server→client) | Key payload fields |
|---|---|
| `log_line` | `text, severity, phase, elapsed` |
| `finding` | `id, line, severity, threat_type, phase, mitre {id,name,tactic,url}, mitre_id, fix_action, target, timestamp` |
| `scan_state` | `phase, phase_total, phase_name, section, elapsed, threat_counts, running` |
| `scan_complete` | `findings_count, threat_counts, elapsed, results_path, engine_report` |
| `remediation_complete` | `applied, failed, skipped, blocked` |
| `sync` (PS server) | Full state snapshot on connect/reconnect |

---

## CRITICAL RULES

These are hard constraints distilled from every past regression (`CHANGELOG.md` has the stories).
Violating one silently breaks a scan, hangs the tool, or damages a user's machine.

### Engine is split — edit the modules, and mind the two dot-source traps
- **The engine is `Scythe-V23.ps1` (thin loader) + `engine/*.ps1` (dot-sourced phase modules).**
  Edit a **phase** in the matching `engine/*.ps1`; edit **globals/helpers/Get-Sig loads/elevation**
  in the loader. All modules dot-source into the loader's single scope, so cross-phase variables,
  functions and traps carry across exactly as when it was one file — but two gotchas bite ONLY after
  the split, so they are hard rules:
- **Every phase module needs its OWN top-level `trap { Write-RecoveredError $_; continue }`** (already
  in `Phases-1/2/3`). Reason: the loader's script-scope trap resumes at the next **dot-source
  statement** (i.e. the next MODULE), so a terminating error mid-module would otherwise skip **all its
  remaining phases**. This is exactly how the benign System32 ACL `AccessControl.ObjectSecurity`
  TypeData collision at Phase 16 silently dropped phases 17-58. A module-level (or grouped-block)
  trap makes `continue` resume at the next **phase** instead. Keep it as the module's first statement.
- **Any `exit` inside `engine/*.ps1` that must stop the ENGINE has to be `[Environment]::Exit(N)`.**
  A plain `exit` in a dot-sourced file only returns to the loader, which then runs the NEXT module
  (this hung `-Auto`: `Summary.ps1`'s exit fell through into `FixMode.ps1`'s interactive prompt).
  Applied in `Summary.ps1` + `FixMode.ps1`. The loader's own `exit`s (elevation/schedule) are fine.
- **`$PSScriptRoot` inside a module resolves to `engine\`, not the project root** — use
  `$global:SCYTHE_ROOT` (set unconditionally near the top of the loader) for project-root paths.
- **Keep all 6 files parse-clean on live `powershell.exe` 5.1 AND `pwsh` 7, UTF-8 BOM intact.** The
  split preserves numeric phase order; if you subdivide a module further, cut only at a `# SECTION N`
  banner (comment lines, never mid-statement).

### User rules (highest priority)
1. **The tool must NEVER auto-select or auto-apply anything that damages the system.** Never ship a
   destructive `FixParam` that an auto-select (CRITICAL/HIGH + destructive FixAction) can fire on a
   **healthy box** — no `icacls /reset /T`, `vssadmin delete shadows /all`, recursive deletes, or
   drive-root operations. Put the suggested command in the finding **description** and use
   `FixAction Info` so an operator runs it by hand.
2. **Datto / CentraStage / Kaseya are legitimate RMM partner tooling** — not malware. Still flag them
   if something is genuinely off (vendor name in a suspicious path, or an independent malicious signal).
3. **Always tell me when the best time to `/clear` is.** Proactively call it out — I should never
   have to ask. Say so the moment a natural context boundary arrives: a task is finished and
   verified, we're switching to an unrelated subsystem, a long debugging/log-dump thread has served
   its purpose, or the context is getting heavy enough to hurt answer quality. Say it plainly
   ("good point to `/clear`") and, in the same breath, list what must survive the reset — files
   touched, the current state, the next step — or write it to `CHANGELOG.md`/`HANDOFF.md` first so
   nothing is lost. If it is **not** a good time to clear (mid-edit, unsaved reasoning, an
   in-flight scan), say that too.

### PowerShell engine safety (`Scythe-V23.ps1`)
- **PowerShell variables are CASE-INSENSITIVE — never give a local the same letters as a
  broader-scope variable.** `$sev = 'INFO'` inside a function silently shadows a script-scope
  `$SEV` dictionary, so `$SEV.Keys` reads the *string* and returns `$null` — no error, the loop
  just never runs. This exact bug shipped in the server's `Classify` and killed ALL severity
  classification for weeks (every SSE line INFO). The dict is now `$SEV_RX`; when a lookup
  mysteriously returns nothing, check for a case-insensitive shadow first.
- **Never call these raw in a phase body — use the safe wrapper:** `Get-AuthenticodeSignature` →
  `Get-AuthSig`; `Get-ItemPropertyValue` → `Get-RegVal`; `Get-WinEvent -FilterHashtable` →
  `Get-WinEventSafe`; `Get-FileHash` → `Get-FileHashSafe`. `-EA SilentlyContinue` does **not** suppress
  the terminating "property/parameter" errors these throw; unhandled, they unwind to the script-scope
  trap and skip whole phase groups.
- **Never pipe `Get-ScanFiles` directly** into `Where-Object`/`ForEach-Object` — its `return ,$arr`
  makes the whole array arrive as **one** item, so the filter silently matches everything (or nothing).
  Wrap in parens `(Get-ScanFiles …) | …` or assign to a var first. `@(Get-ScanFiles …)` does NOT fix it.
- **Never `(fn …)[0]` when `fn` may return a single value** — PS 5.1 unwraps a single-element `@()`
  return to a scalar, so `[0]` indexes into a *string's first character*. Use `@(fn …)[0]` (force array,
  then index). Only a genuine array literal / `-split` result is safe to bare-index.
- **`@(...)` over a `New-Object`-built `List[object]` can THROW on a .NET 8.0.10 host**
  ("Argument types do not match", the October 2024 `System.Linq.Expressions` servicing
  regression; plain `foreach` enumeration is unaffected). Inside a function with its own
  try/catch the throw is silent and the function just returns `$null` — phase 146's import
  parse returned `$null` for every file and scored healthy binaries as "import table
  unreachable" (caught by `Test-Pe-Parser.ps1`, 2026-09-02). When the collection is a list
  the code itself built, enumerate it plainly; `@()` is for genuinely scalar-or-array values.
- **`try/catch` is statement-only in PS 5.1** — never use `(try{…}catch{…})` as a sub-expression
  (parses in PS 7, runtime-errors on 5.1). Restructure with early `return`s + a trailing try/catch.
- **Any loop calling `Get-AuthSig` over many files MUST carry the `$global:SIG_AUDIT_*` budget**
  (deadline + count) — `Get-ScanFiles`'s caps do NOT cover the downstream sig loop (Authenticode does
  online CRL/OCSP revocation checks that block ~15s each). Single-file/per-process call sites are fine.
- **Use `Get-ScanFiles`, never raw `Get-ChildItem -Recurse`** over a user/AppData root (it caps files +
  wall-clock, prunes cache dirs, skips OneDrive placeholders). Scope ransomware/doc scans to doc folders.
- **Anchor folder-name path tests to path COMPONENTS** (`'\\(AppData|Temp|Downloads|Desktop)\\'`),
  never bare substrings — a bare `Desktop` matched the Store *package names* `WhatsAppDesktop` /
  `DesktopAppInstaller` under `C:\Program Files\WindowsApps` and auto-KillProcess'd healthy signed
  apps (Phase 47, fixed 2026-07-02). Treat `WindowsApps` as a signed store root, not a user path.
- When bundling multiple phases under one `if ($PhasePlan.*)`, give the block its own inner
  `trap { Write-RecoveredError $_; continue }` (resumes at the next phase, not end-of-group).
- **Validate on live `powershell.exe` 5.1**, not a PS-7 simulation — the unwrap / `(try{})` /
  `,$arr` behaviors only surface on the real 5.1 runtime. Keep the engine **parse-clean on 5.1 + 7**
  and the **UTF-8 BOM** intact.

### AMSI / signatures
- **Never put malware-signature literals in the `.ps1`** — Defender AMSI blocks the engine at load
  (`ScriptContainedMaliciousContent`, exit 1, no output → "scan did nothing"). All signatures live in
  `data/detection_signatures.json`, loaded at runtime via `Get-Sig` (data files aren't AMSI-scanned).
- **FP allowlists are NOT signatures** — they live in that same JSON and load via `Join-AllowRegex`
  (empty key → `(?!)`, suppresses nothing). No new literal lists in the `.ps1`.
  **Correction (2026-08-26): they are NOT under an `fp_allowlists` block.** This file said so for
  a long time and it is wrong. `data/detection_signatures.json` is **flat** — 190 top-level keys,
  70 of them `_comment_*` strings — and `Join-AllowRegex` resolves a bare key name through
  `Get-Sig $Name`. Allowlist keys are distinguished by naming convention only (`*_benign_*`,
  `*_allow*`, `trusted_*`). A `_comment_fp_allowlists` marker string exists and is the likely
  source of the belief. This matters now because `lib/Scythe.Rules/Linting` was written to
  the documented schema and therefore cannot read the real file — one side has to move, and that
  is an open decision, not a bug to patch on sight.
- **An allowlist entry matched against attacker-controllable text (run-key values, command lines,
  task actions) must pin the ENTIRE string to the exact benign shape** — `^…$` anchors, bounded
  wildcards like `[^"]*` (never `.*` spanning the name/value boundary). A name-only prefix pattern
  lets malware self-allowlist by naming its value e.g. "Uninstall OneDrive" (caught in review,
  2026-07-02). Path-only allowlists are fine — attackers don't control where OneDrive installs.
- **Prefer downgrade-to-POSSIBLE over deleting a detection.** POSSIBLE is shown but never auto-acted-on.

### Remediation safety (`Scythe-Server.ps1` — engine stays audit-only in `-Auto`)
- **`Test-ProtectedTarget` = HARD block**, defense-in-depth across all 3 layers (server tags
  `protected`; frontend disables the checkbox + excludes from auto/Select-All/POST; the
  `$script:REMEDIATE_SCRIPT` runspace **refuses** even on manual override, reporting `blocked`). Covers
  cert trust store, `C:\Windows`/System32/SysWOW64/WinSxS, shell-system files, user dotfiles, SafeBoot +
  core OS registry, KillProcess of critical procs or the IR tool itself.
- **`Test-VendorTrusted` = SOFT signal** (centrastage/datto/kaseya/aemagent/…). Not auto-selected,
  green `✔ TRUSTED` badge, but **operator can still act**. A vendor name in a suspicious path OR with an
  independent malicious signal is **NOT** trusted and stays flagged.
- **Keep both functions in sync with their mirrors inside `$script:REMEDIATE_SCRIPT`.** Add new partner
  vendors to the `Test-VendorTrusted` regex. Re-grade the auto-destructive count (CRIT/HIGH +
  DeleteFile/DeleteReg/DeleteRegKey/KillProcess/RunCmd/Quarantine) from the baseline JSON after tuning.
- **Prefer `Quarantine` over `DeleteFile`** for anything not hash-confirmed malware (reversible: moved
  to `reports/quarantine/`, renamed `.quar`, with a `.quar.json` restore manifest).

### API auth + transport security (added 2026-08-18, audit C1/C3)
- **Every `/api/*` route requires the per-launch token.** The server mints it at startup
  (`$script:AUTH_TOKEN`, `RNGCryptoServiceProvider` — **never `Get-Random`**, which is a seeded
  `System.Random` and therefore guessable) and opens the browser at `/?t=<token>`. A new route is
  gated automatically by the `$path -like '/api/*'` check in `Handle-Request`; a new **frontend**
  call is not — **wrap every new fetch/EventSource URL in `scytheApi()`** or it will 401. Static assets
  stay ungated on purpose so a tokenless browser can still load the page and explain itself.
- **Never re-add an `Access-Control-Allow-*` header.** Same-origin needs no CORS, and `ACAO: *` on
  an elevated remediation API is what made a drive-by web page able to run commands as admin. The
  Origin check refuses any request whose `Origin` is present and not this server's own.
- **The listener binds `http://127.0.0.1:$Port/`, not `localhost`** — http.sys matches the Host
  header against the prefix, so this is what rejects a DNS-rebound hostname. Don't "fix" it back.
- **No remote origins in the GUI, ever.** Scripts, fonts and styles are vendored under
  `gui/static/js/vendor/` and `gui/static/css/fonts/`, and the CSP pins the page to `'self'`. This
  tool runs on boxes whose DNS/proxy/CA trust it is itself checking (phases 36/37/39). New assets
  get vendored and added to `$requiredFiles`/`$requiredDirs` in `tools/Build-Release.ps1`.

### Reporting the truth about a scan (added 2026-08-18, audit H2)
- **`scan_complete` means the engine finished. A failed engine emits `scan_failed`, never both.**
  The GUI's clean-bill-of-health banner hangs off `scan_complete`; a false all-clear is the worst
  bug an IR tool can ship. Failure = non-zero exit code **or** zero `PHASE` headers parsed (the
  documented AMSI-blocked-at-load case exits 1 with no output). An operator abort is not a failure.
- **Never call `BeginErrorReadLine()` without a handler** — that drains stderr to nothing. Use
  `StandardError.ReadToEndAsync()`: .NET keeps draining (so no buffer deadlock) and the text
  survives for the log.

### Guard mirrors + destructive-command inspection (added 2026-08-18, audit H5/H6/H7/H7b; extended 2026-08-19, M1)
- **The guard exists in THREE copies and they must change together:** the main thread
  (`ConvertTo-GuardPath` / `Test-DestructiveRunCmd` / `Test-ProtectedTarget` in
  `Scythe-Server.ps1`), the remediation runspace (`…-RGuardPath` / `Test-RDestructiveRunCmd` /
  `Test-RProtected`, inside `$script:REMEDIATE_SCRIPT`), and the **engine** (`ConvertTo-EGuardPath`
  / `Test-EDestructiveRunCmd` / `Test-EProtected` in the loader, used by `Invoke-FixMode` — the
  interactive CLI is the fourth executor and had no guard at all until 2026-08-19). The tables
  `$…RUNCMD_DESTRUCTIVE`, `$…RUNCMD_MUTATING`, `$…KILL_CRITICAL_NAME_RX`, `$…KILL_CRITICAL_DESC_RX`
  are mirrored too. `tools/tests/Test-GuardMirrorSync.ps1` compares all three on every vector and
  fails on divergence — run it after touching any copy. **It must also LOAD every table it relies
  on**: an unloaded regex is `$null`, `-match ''` is true, and the test then agrees for the wrong
  reason (caught 2026-08-19).
- **Normalise before you match.** Guards used to regex the raw `FixParam`, and
  `C:/Windows/System32/evil.exe` sailed straight through. Everything goes through
  `ConvertTo-GuardPath` first (separators, env vars, `\\?\`/GLOBALROOT prefixes, `GetFullPath`).
  PS drives (`HKLM:\`, `Cert:\`) deliberately skip `GetFullPath`.
- **The `RunCmd` blocklist is direction-aware, and that is not optional.** The engine legitimately
  emits `netsh advfirewall reset`, `Set-MpPreference -DisableRealtimeMonitoring $false`,
  `bcdedit /set {default} recoveryenabled Yes`, `Stop-Service WinRM|Spooler` and `EnableLUA 1` as
  **real remediations**. Only the sabotage direction may be matched. **Before adding a pattern,
  diff it against the engine's own RunCmd inventory** (`grep -o '-FixAction "RunCmd" -FixParam .*'
  engine/*.ps1`) or you will silently break a fix.
- **The `RunCmd` path rules only fire on a MUTATING command** (`$script:RUNCMD_MUTATING`). A command
  is not a path: restoring a hijacked Winlogon `Userinit` writes the value
  `C:\Windows\system32\userinit.exe,`, and matching that mention blocked the tool's own repair on
  every box (audit M1). Deleting/renaming/overwriting a protected path is still refused, and
  `$RUNCMD_DESTRUCTIVE` applies unconditionally. If you add a rule, keep it verb-anchored.
- **`KillProcess` FixParams are `pid|name|startTicks`** (built by `Get-KillParam`). Windows recycles
  PIDs and remediation runs long after the scan, so both executors re-verify identity and skip on a
  mismatch. A bare PID (old report) is honoured but logged as unverifiable. **The guard reads the
  critical-process list against that NAME field**, not the finding's prose — "SYSTEM-level process
  running from user path: evil.exe" is a finding about malware, and matching the word `SYSTEM` in
  the text refused the kill every time. A bare-PID report still falls back to the description.
- **Deleting the `Debugger`/`GlobalFlag` VALUE under Image File Execution Options is allowed** —
  that value *is* the sticky-keys/IFEO backdoor and removing it restores stock behaviour. The IFEO
  key itself (`DeleteRegKey`) and every other value under it stay protected.

### Never ship a fix that is auto-selected and then always blocked (added 2026-08-19, audit M1)
- A CRITICAL/HIGH finding with a destructive `FixAction` is **auto-selected** in the GUI. If its
  target is a protected resource, the operator sees the tool's headline detection pre-ticked and
  reported `blocked` — every time, on every machine. That teaches operators to distrust the guard,
  which is the one thing that must never happen. **The guard is not the thing to loosen; the
  remediation design is.** Put the exact manual command (plus an `sfc`/`DISM` restore path where
  it applies) in the finding's **description** and use `FixAction Info`. Done for `STICKY_*`,
  `SYS32_UNSIGNED`, `HOSTS_PURGE`, `SVCMASQ`/`SVCPATH`, `SOFTDIST_CACHE`.
- `tools/tests/Test-M-Tier.ps1` sweeps every `Add-Finding` in the engine via the AST and **fails if
  any CRIT/HIGH destructive fix is refused by the guard**, so the class cannot come back.
- **`DeleteFile` deletes a FILE**: no `-Recurse`, reparse points and directories refused, and the
  guard re-run on the *resolved* path. Use `-LiteralPath` everywhere — `-Path` globs, and malware
  filenames contain `[` and `*`.

### Embedding data in generated HTML/JS (added 2026-08-18, audit H8)
- **Never build a JS string literal with `-replace` chains.** `engine/Summary.ps1` embedded
  newline-separated CSV inside `'...'`, which is a syntax error — that silently killed the HTML
  report's *entire* inline `<script>` (export, search, filters, sorting) in every report ever
  generated. Use `ConvertTo-Json -Compress`, which emits a correctly escaped literal in one step,
  then `-replace '</','<\/'` so a finding containing `</script>` cannot break out of the element.
- **CSV cells go through `ConvertTo-CsvSafeCell`** (loader **and** server copies — keep in sync).
  Correct CSV quoting does not stop Excel evaluating a leading `= + - @ \t \r` as a formula, and
  exporting findings and mailing them to a client is this product's actual workflow.

### Untrusted input, retention and side-effects (added 2026-08-19, audit M2/M5/M6/M8/M9/M10)
- **Everything posted to `/api/ioc` is validated by `ConvertTo-IocSet` before it is written.** Line
  breaks and control characters are **refused, never stripped** — the engine's `Import-CustomIocs`
  treats an unclassifiable line as a **regex**, so a CRLF in a "domain" injects an arbitrary IOC.
  Regexes must compile *and* survive backtracking bait under a 150 ms match timeout (a catastrophic
  pattern otherwise hangs the next scan from inside the engine). Values are deduped, length-capped
  and capped at 2000 per category, and everything refused is reported to the operator — the GUI
  re-seeds its table from the set the server actually wrote. POST bodies over `$script:MAX_BODY_BYTES`
  get a 413.
- **`escapeHtml` in `app.js` escapes `& < > " '`** and every interpolation into `innerHTML` goes
  through it — including `finding.id`, `severity`, `phase` and `results_path`. Most engine IDs are
  sanitised, but `CTRL114_*`/`DEFTAMP114_*`/`CONTENT_*` come straight from `data/*.json`.
- **`$State.EventLog` is a bounded ring** (`EventLogMax`/`EventLogKeep`, with `EventLogBase` so an
  SSE cursor stays an absolute index across trims). Add+trim and the reader's slice take the same
  `SyncRoot`; the socket write happens **outside** the lock. Clearing the log must reset
  `EventLogBase`. Runspaces are tracked and disposed by `Clear-FinishedRunspaces` — `/api/events`
  starts one per connection, so a browser refresh used to leak one for the life of the console.
- **Leave nothing behind on a client machine.** The `netsh http add urlacl` fallback is removed on
  exit; `reports\` is ACL-hardened at startup (non-admin **write** downgraded to read-only, read
  kept so the operator can open exported reports unelevated); per-launch logs are pruned to the
  newest 20 (`-KeepLogs`). Quarantined malware is never auto-deleted — it is evidence — but its
  footprint is printed at startup.
- **Remediation re-hashes the report.** The SHA256 of each report this launch produced is recorded
  when the engine finishes writing it; `/api/remediate` refuses with 409 if the file changed. A
  report from an earlier launch is allowed but called out in the console.

### The engine must not trust its own inputs (WS7, added 2026-08-19)
- **`Join-AllowRegex` is the integrity choke point and must stay one.** Every FP allowlist in
  the engine passes through it, and an allowlist **fails open** — it SUPPRESSES detections. So
  the cheapest attack on this tool is not deleting a detection (a missing key fails closed to
  `(?!)` and is conspicuous) but **widening one entry to `.*`**: every phase downstream then
  suppresses everything it finds and still prints its `[OK ]` banner. `Join-AllowRegex` now
  refuses any pattern that does not compile, blows a 150 ms match budget, or is **universal**
  (matches five deliberately unrelated canary strings). Refusals **fail closed** — the entry is
  dropped so the phase goes NOISY, never BLIND — and land in `$global:SCYTHE_SIG_TAMPER`, which
  `engine/Phases-0.ps1` reports as CRITICAL. **Never move an allowlist off `Join-AllowRegex`**,
  and never "fix" a noisy phase by adding a broad pattern — the engine will now accuse itself of
  being compromised, correctly.
- **Never assume the engine is 64-bit.** There was exactly one WOW64-aware line in the whole
  tree before WS7. A 32-bit process on x64 Windows is lied to by the OS: `C:\Windows\System32`
  redirects to `SysWOW64` and `HKLM\SOFTWARE` to `Wow6432Node`, so the System32 audits (15/109/113)
  and every `HKLM\SOFTWARE` phase read the wrong half of the machine. This fires by ACCIDENT far
  more often than by attack (a technician's 32-bit shell, an x86 RMM agent, an x86 PS2EXE build).
  Use **`Get-RegVal64` / `Get-RegNames64` / `Get-RegSubKeys64`** for `HKLM\SOFTWARE` and
  `$global:SCYTHE_SYS32` for System32. `$global:SCYTHE_IS_WOW64` records the condition and Phase 0 reports
  it CRITICAL. **Do not add an auto-relaunch** — it would orphan the redirected stdout the server
  reads, and the GUI would see the scan die.
- **`engine/Phases-0.ps1` is PREFLIGHT, not a numbered phase.** It must never print a
  `PHASE <n>` header (the server's counter regex would see it and every mode's `phase_total`
  would be off by one) and it resets `$global:CURRENT_PHASE_NUM = 0` on the way out. Findings
  carry `-Phase "PREFLIGHT"`; `Resolve-Mitre` finds no numeric phase and falls back, which is
  correct for them.
- **The integrity manifest is a RELEASE artifact, not a committed file.** `tools/Build-Release.ps1`
  generates `data/integrity_manifest.json` before staging; it is `.gitignore`d because on a dev
  tree every edit invalidates it and Phase 0 would report CRITICAL tampering on every scan. Its
  absence is reported as INFO ("engine authenticity is UNVERIFIED this run"), which is the honest
  state for a working tree.

### HUNT band 134-162 (`engine/Phases-5/6/7.ps1`, added 2026-08-19)
- **`-Mode HUNT` sits above PARANOID with a ceiling of 162, and that ceiling is mirrored in FOUR
  places** — the loader's `$PhasePlan`, `$MODE_PHASES` in `Scythe-Server.ps1`, `MODE_PHASES`
  in `_python/server.py`, and the mode whitelist in both servers. `Test-Hunt-Band.ps1` checks them
  together. HUNT is deliberately NOT folded into DEEP: the band walks process memory (141-145), so
  it costs real wall-clock and must stay an explicit operator choice. (Phase 159 does now hash the ESP boot binaries against
  the servicing copies, built 2026-08-30 — but only when the ESP is already mounted, and it
  mounts nothing itself. Between 2026-08-22 and then this file and `README.md` claimed the
  capability while 159 was a stub; that was corrected rather than implemented at the time,
  because documenting a capability the engine does not have is the one error class an IR tool
  cannot afford.)
- **Every finding in 134-162 is `FixAction "Info"`. There are no exceptions and there must not
  be**, for a reason specific to this band: its best phases fire on healthy managed endpoints by
  construction. **An EDR is, by every signal phases 134-138 and 141-145 look for, a legitimate
  rootkit** — it hooks, it hides, it injects unbacked code into everything it protects. A
  CRITICAL + `KillProcess` on an EDR hook would be auto-selected in the GUI and would disarm the
  customer's actual security product. Info + `hunt_memory_benign_paths` + a live FP round first.
- **NO P/INVOKE IN THE ENGINE.** Every memory signal in 141-145 is reached through pure .NET
  (`ProcessThread.StartAddress`, `ProcessModule.BaseAddress`/`ModuleMemorySize`). Declaring
  `OpenProcess`/`ReadProcessMemory`/`VirtualQueryEx` is the exact code shape AV heuristics flag,
  and an engine Defender blocks at load detects **nothing at all** — the same failure mode the
  AMSI rule above exists for. `Test-Hunt-Band.ps1` asserts no `DllImport` and no
  `Add-Type -TypeDefinition` in the new modules. If a future phase genuinely needs a region walk,
  put the C# in a **data file** (data files are not AMSI-scanned) and document why.
- **Cross-view phases must consult two INDEPENDENT sources, and the disagreement IS the
  detection.** That is what lets them catch an implant nobody has a signature for. Phase 134
  (registry TaskCache vs `Get-ScheduledTask`) exists because **deleting a task's `SD` value hides
  it from `Get-ScheduledTask`, `schtasks` and the Task Scheduler UI while it keeps running** — no
  exploit, no driver, works fully patched, and it blinds phases 29 and 104. Do not "simplify" a
  cross-view phase down to one source.
- **Correlation (phase 160) links on shared ENTITIES, never on time.** `Add-Finding` stamps a
  finding with the time the SCAN ran, not when the artifact was created, so every finding in a run
  shares one timestamp and time-clustering would fuse the whole scan into one meaningless chain.
  It links on file paths (drive-letter **and UNC** — lateral findings name `\\server\share\x.exe`),
  PIDs, registry keys and network peers. **An entity shared by more than 12 findings is treated as
  a common noun, not a link** (`C:\Windows\System32\cmd.exe` appears in dozens of unrelated
  descriptions); without that cap one shared path fuses everything. Both properties are
  revert-proofed in `Test-Hunt-Correlation.ps1`.
- **A backtick immediately before a closing double-quote escapes it** and the string never
  terminates. Do not wrap inline commands in markdown backticks inside a `-Description` — use
  single quotes. This broke the build twice while writing this band.

### Network-exposure band 153-156 (`engine/Phases-6.ps1`, added 2026-08-22)
- **The band is HOST-SIDE and must stay host-side. There is no `-ScanLan` switch and none is to
  be added.** The original F6 brief specified "LAN band, opt-in, requires `-ScanLan`"; that scope
  was deliberately dropped. Every check is a registry or CIM read of the machine's own posture,
  sending **no packets** and enumerating **no network**. Two reasons, and both survive re-reading:
  Scythe runs on client networks under an MSP contract, and a tool that probes the customer's
  LAN can trip the customer's own IDS while being indistinguishable on the wire from what it
  exists to detect; and every finding here is answerable from the host's own registry, so probing
  buys no detection. `docs/ATTACK_LOG.md` is the evidence — everything learned by scanning that
  host from outside maps onto a value readable from inside it.
- **"Permits signing" is not "requires signing," and that distinction is why the band is
  host-side.** An external observer cannot tell them apart: a client that asks for signing gets it
  either way. Only `RequireSecuritySignature=1` closes SMB relay, and only a host-side read sees
  it. Any check whose answer differs between "what an outsider can observe" and "what the defender
  must verify" belongs here, not in a network probe.
- **Report the compliant state, not only the failures.** Phase 155 checks all three broadcast
  name-resolution channels (LLMNR / NBT-NS / mDNS) and prints the good ones. On the machine this
  band was written against, two of the three were already correct — a check that only reported
  failures would have printed nothing and taught the operator nothing about what was verified.
- Findings are `FixAction "Info"` like the rest of 134-162, but here for an additional reason:
  several of these settings (`LmCompatibilityLevel`, the LSA values, share removal) break file
  sharing or logon outright if written blind. The exact operator-run command goes in the
  description.

### Phases 147 / 157 / 158 / 159 (`engine/Phases-6.ps1`, added 2026-08-30)

- **Phase 159 does not mount the EFI System Partition, and no switch is to be added.** The F7
  brief said to mount it read-only with `mountvol` and unmount in a `finally`; that scope was
  dropped, for the same reason F6's LAN scan was. Assigning and removing a system partition's
  access path is a live change to a client machine's boot volume state, and *leave nothing
  behind on a client machine* is the standing rule (audit M5/M9/M10). If the ESP already has an
  access path the phase inventories `\EFI\` and compares each boot binary against the servicing
  copy under `%WINDIR%\Boot\EFI`; if it does not, the phase **says so in the report** and hands
  over the exact commands rather than staying silent — an un-run check that leaves no trace
  reads as a pass. Secure Boot state, `dbx` currency and the BCD flags need no mount, which is
  most of the value. `Test-Hunt-Band.ps1` asserts the module invokes no `mountvol`,
  `Add-PartitionAccessPath`, `Remove-PartitionAccessPath`, `Set-Partition`, `New-Partition` or
  `Format-Volume`.
- **`Confirm-SecureBootUEFI` throws on a legacy-BIOS machine rather than returning `$false`.**
  Wrap it; the whole phase must degrade cleanly and still report the boot mode.
- **Phase 159 must not duplicate phase 40.** Phase 40 owns `testsigning` and
  `nointegritychecks`; `bcd_unsafe_flags` covers only what it misses, `disableelamdrivers` being
  the important one. There is a test.
- **`dbx_current_baseline` is a floor, not a baseline, and that is deliberate.** dbx size varies
  legitimately by architecture, OEM and servicing level. `MinBytes` is the level below which the
  list is unambiguously the never-updated factory stub; anything above it is reported as a
  **measurement** to compare against a peer machine, not as a verdict. Do not "improve" this by
  hard-coding an exact size measured on one machine — a wrong baseline is a confident false
  finding on every healthy endpoint.
- **Phase 147 never reads the opaque credential stores.** `cloud_cred_never_read` covers
  TokenBroker, the NGC key containers, DPAPI master keys, Credential Manager and the
  MSAL/gcloud binary caches — existence and ACL only. Reading them makes this tool the
  credential-theft primitive it exists to find, and reading a TokenBroker cache can invalidate
  the user's live session. **And no finding in this band quotes the matched secret**: a finding
  that reproduces the credential turns the client report into a second copy of it.
- **Two allowlists here can switch off their own detection branch, and both are revert-proofed.**
  `cloud_cred_benign_paths` must never match Temp, Downloads, Desktop, Public or ProgramData —
  those are phase 147's staging directories, and branch (c) is what separates *a developer box
  has secrets* from *someone staged the secrets*. `devtool_benign_paths` must never carry a bare
  `\.git\` entry — phase 158's hook branch reads `.git\hooks`; only `objects`, `refs`, `logs`,
  `modules` and `lfs` are allowlisted. Same failure as phase 130's `discord` entry.
- **`persist_stubpath_benign_values` entries must be fully `^...$`-anchored.** Active Setup
  StubPath is a command line the attacker controls, so a prefix pattern lets malware
  self-allowlist by naming its command after a Microsoft one. Asserted.
- **Phase 158 reuses `webhook_c2_rules`, it does not grow a second copy** — and it must keep
  ignoring `.sample` git hooks, or every developer workstation reports findings. Both asserted.
- **The safe-wrapper assertions match INVOCATIONS via the AST, not the module text.** This band
  is `FixAction "Info"`, so the description *is* the remediation, and telling a technician to run
  `Get-AuthenticodeSignature <path>` is the correct instruction — a text match on the cmdlet name
  fires on that prose. `Test-Hunt-Band.ps1` §9 walks `CommandAst` nodes instead. If you add a
  cmdlet to that list, prove it bites by injecting a real call.
- **No typosquat check in phase 158, on purpose.** It needs a curated list of very-popular
  package names to mean anything; that list is a standing maintenance commitment this project
  has not made, and a stale one produces confident false accusations about a developer's own
  dependencies.

### Phases 148-152 (`engine/Phases-6.ps1`, added 2026-08-31)

- **Phase 150 does not enumerate the directory, and no switch is to be added.** The F2 brief
  asked for an AS-REP-roastable / unconstrained-delegation / RBCD / AdminSDHolder sweep across
  the domain. That sweep is, query for query, what BloodHound issues — against the customer's
  own domain controllers, from an endpoint, under an MSP contract, while the customer's
  detection stack is watching. Same reasoning that made 153-156 host-side and 159 mount
  nothing. What ships instead reads **this computer's own AD object**: one `[ADSISearcher]`,
  filtered on `sAMAccountName`, `SizeLimit 1`, both `ClientTimeout` and `ServerTimeLimit` set.
  ADCS ESC8 is dropped outright — it needs an HTTP request to a customer server.
  `Test-Hunt-Band.ps1` §16(d) asserts exactly one searcher, no `FindAll(`, no
  `objectClass=user` / `objectCategory=person` / `samAccountType=` filter, and no
  `Invoke-WebRequest` / `Invoke-RestMethod` / `Net.WebClient` / `System.Net.Sockets` anywhere
  in the module. The banned-token list deliberately omits *AdminSDHolder* and *adminCount*:
  the phase banner names them when it explains what was dropped, and banning the word would
  ban the explanation.
- **Roughly twenty sub-checks from the F2 brief were dropped because another phase owns them,
  and every one is revert-proofed in both directions.** 107 owns 7045 and per-record 4624;
  133 owns the `wmic /node`, `schtasks /s` and ADMIN$ **command lines** and the PsExec service
  binaries; 106 owns `.dmp` in the crash-dump directories and the dumper tool names; 41 owns
  WDigest `UseLogonCredential` and LSA `RunAsPPL`; 88 owns 4769/4662; 129 owns `winscp.ini`;
  153 owns SMB signing; `LmCompatibilityLevel` is already duplicated between 46 and 155 and
  must not gain a third. **Before adding anything to 148-152, grep the engine AND
  `data/detection_signatures.json` for the mechanism** — the reason 157 shipped six duplicates
  is that six of them lived in a data-driven table rather than in code.
- **Phase 152 emits no per-record 4624 finding, deliberately.** Phase 107 already reports one
  finding per logon record. A second would give one event two ids and two severities, and
  phase 160 would then correlate them on the shared target as two independent facts. 152 owns
  the **aggregate** instead — a spray is many accounts from one source, which cannot be seen
  one record at a time. Asserted.
- **Event queries put `StartTime` INSIDE the `FilterHashtable`.** Every older query in this
  engine pulls N records and filters with `Test-InScope` afterwards; on a domain workstation
  with a large Security log that materialises hundreds of thousands of records in the
  pipeline first. Inside the hashtable it compiles to XPath the Event Log service evaluates
  itself. `Get-ScytheEvents` is the single call site (asserted via the AST — the *comment*
  above it also names `Get-WinEventSafe`, so a text count says two) and it memoises per
  (log, id-set, cap).
- **`Get-ScytheEvtField` reads `.Properties` positionally and validates the result.**
  `[xml]$e.ToXml()` per record is two orders of magnitude more expensive and is the whole cost
  of the phase on a real log. But the positional layout is a property of the provider
  **manifest** and has moved between Windows versions, and a silently-wrong index would put an
  account name in the source-address column of a client report — so a value that fails its
  validation regex falls back to the named lookup **for that record only**.
- **Reading two event ids together needs TWO PASSES, because `Get-WinEvent` returns newest
  first.** The 4732 that added an account to Administrators arrives *before* the 4720 that
  created it, so a single pass never sees the pairing that is the entire reason for reading
  the pair. Phase 152 builds the created-account set first, then reports.
- **Two allowlists here can switch off their own detection branch, and both are asserted.**
  `logon_explicit_cred_benign_procs` (4648) must never match `cmd.exe`, `powershell.exe`,
  `wscript.exe` or anything under a user-writable path — a shell supplying somebody else's
  credential *is* the case the branch exists for. `creddump_hive_benign_paths` must never
  match Downloads, Public, ProgramData, PerfLogs or `%WINDIR%\Temp` — those are exactly where
  a staged SAM turns up. Same failure as phase 130's `discord` entry.
- **`lateral_remote_exec_benign_cmdlines` matches a COMMAND LINE, so every entry is fully
  `^...$`-anchored with bounded wildcards and no `.*`.** Datto / CentraStage / Kaseya run
  scripts through WMI and WinRM constantly and the phase is unusable on a managed fleet
  without this list — but a name-only prefix would let malware self-allowlist by naming its
  command after an RMM one. Asserted, including the `.*` ban.
- **`klist` and `cmdkey` run only through `Invoke-ScytheConsoleTool`.** They answer questions
  no registry read can, they are read-only Microsoft-signed binaries already on the box, and
  they hang forever against an unreachable KDC — so the helper starts them detached, drains
  stderr with `ReadToEndAsync` (audit H2, applied to a child we start), and **kills on the
  deadline** instead of waiting. Asserted.
- **`%WINDIR%\repair` is searched and deliberately NOT allowlisted.** Windows XP and Server
  2003 kept genuine SAM/SYSTEM backups there; modern builds leave it empty, so a hive in it
  is worth reporting, and the finding's own text tells the operator to check the dates before
  escalating rather than the allowlist silently deciding for them.
- **`$HOME` is a read-only automatic variable** — `foreach ($home in ...)` throws
  `Cannot overwrite variable HOME`. Same family as the one-letter helper names that lose to
  built-in aliases; it cost a test run here.

### Rule regexes must be run against REALISTIC content, not just compiled (added 2026-08-30)

Four rules shipped that could not fire, or fired on every healthy machine, and the suite did
not notice — because it compile-checked the pattern *strings* and grepped them for a keyword.
**A pattern that compiles is not a pattern that works.** `Test-Hunt-Band.ps1` §15 now runs each
rule set against realistic content and asserts both directions: silent on the healthy sample,
firing on the malicious one. Add a case there for every new rule set.

The two mistakes, both worth knowing by shape:

- **`bcdedit` pads the element name out to column 24**, so the gap before the value can be
  **twenty spaces**. `\s{1,8}` could not reach the value at all, and four of seven BCD rules
  were dead. Phase 40's existing `testsigning\s+Yes` has always used unbounded `\s+`; match it.
- **Match a value with `\S`, never `[^\r\n]`, when a negative lookahead precedes it.** With
  `[^\r\n]` the engine backtracks *into* the whitespace run, where `(?!true|false)` or
  `(?!\\Windows\\...)` trivially succeeds because the text there is spaces. That is what made
  `core.fsmonitor = true` — the value Git for Windows 2.37+ and Scalar write themselves — a
  HIGH finding, and made every healthy UEFI machine report a custom boot loader. `\S` closes it,
  because after a partial whitespace consumption the next character is whitespace and `\S`
  cannot match there.

### Do not duplicate a mechanism another phase already owns (added 2026-08-30)

Phase 157 shipped covering six mechanisms **phase 126 already walks** via
`extended_autostart_points` — netsh helpers, print monitors, W32Time time providers, Active
Setup StubPath, `SCRNSAVE.EXE` and the Winsock catalogue (126 also covers
`Protocol_Catalog9_64`, which 157 did not). Phase 126 runs whenever HUNT runs, because
`$PhasePlan.Extended` is true for HUNT. The result was two findings with different IDs and
different severities for one artifact — and **phase 160 then correlates them on the shared
target as though they were two independent facts**, which is worse than either alone.

The band's banner said it covered what "phases 20-35 and 90-105" miss; nobody checked 116-133.
**Before adding a mechanism to any phase, grep the whole engine AND `data/detection_signatures.json`
for it** — a mechanism can be owned by a data-driven table rather than by code, which is
exactly how these six were missed. `Test-Hunt-Band.ps1` revert-proofs all six in both
directions: re-adding one to 157 fails, and so does losing it from 126.

### `Out-Typewriter` has no `OK` level — use `GOOD` (added 2026-08-30)

The switch cases are `INFO / WARN / CRIT / GOOD / ACT / VER / DATA / HUNT / FIND`. `"OK"` falls
through to an empty prefix, so the line reaches the GUI **with no `[OK ]` bracket tag and no
timestamp**, and the server's `Classify` falls back to the prose keyword table — the exact
§5.1 audit bug where the engine's own banners painted a clean scan red. `GOOD` is what emits
`[OK ]`. 25 sites across `Phases-0/5/6/7` had it wrong; the test now refuses the whole band.

### When a stub becomes real, re-check every test list that names modules explicitly
- `Test-Hunt-Band.ps1` §9 (safe-wrapper discipline: no raw `Get-ItemPropertyValue` /
  `Get-AuthenticodeSignature` / `Get-FileHash`, no P/Invoke, no piped `Get-ScanFiles`) enumerated
  `Phases-0/5/7` and **omitted `Phases-6`**. That was harmless while `Phases-6` was an empty stub
  and became a blind spot the moment it carried 15 findings — the suite went on passing, for the
  wrong reason. Caught and fixed 2026-08-22 (112 → 118 assertions, the six new ones proven to fail
  by injecting a raw `Get-ItemPropertyValue` and an `Add-Type -TypeDefinition`).
- The general form: **an exclusion justified by a file being empty expires silently when the file
  is filled** — and nothing fails to tell you, because the suite still passes. Before filling any
  remaining stub (146-152 and 157-159, both in `Phases-6.ps1`, and any future module), grep the
  whole test tree for the module name and add it wherever its siblings already appear. Then prove
  the new assertions bite by injecting a violation — a list you extended but never tested against
  is the same blind spot one level up.


### Extended band 116-133 (`engine/Phases-4.ps1`, added 2026-08-19)
- **The band ships `FixAction "Info"` by default and that is deliberate.** It is new
  detection surface that has never been through a live FP round, so nothing in it may be
  auto-selected for a destructive fix. Exactly **three** exceptions exist, each an artifact
  that cannot occur benignly and whose removal restores stock behaviour: the
  `Office test\Special\Perf` key (`DeleteRegKey`), a `.lnk` carrying encoded PowerShell or a
  hidden downloader (`Quarantine`), and a chat webhook URL embedded in a chat client's own
  module tree (`Quarantine`). Each is verified against the real guard by
  `tools/tests/Test-Extended-Band.ps1` — **add a fourth only with the same proof.**
- **AppCertDlls is reported `Info` on purpose.** It lives under
  `SYSTEM\CurrentControlSet\Control`, which the guard refuses; shipping it as CRITICAL +
  `DeleteReg` would be auto-selected and then reported `blocked` on every box — the exact
  audit-M1 anti-pattern. Same reasoning for the LSA package values: a wrong edit there
  stops the machine logging in at all, so the finding carries the stock value and a warning
  instead of a fix.
- **`$PhasePlan.Extended` gates the band; the ceiling is mirrored in FOUR places** —
  the loader's `$PhasePlan`, `$MODE_PHASES` in `Scythe-Server.ps1`, `MODE_PHASES` in
  `_python/server.py`, and the `$ScanState.PhaseTotal` default. Change one, change all four
  (the test checks them together).

### Writing detection rules in `data/detection_signatures.json`
- **An FP allowlist must never swallow the case its own detection branch exists for.**
  Phase 130's allowlist covered `\AppData\Roaming\discord\`, which made its client-core
  `Quarantine` branch unreachable dead code — the branch existed precisely for a stealer
  patched into the client. Caught by the runtime smoke test, 2026-08-19. When you add an
  allowlist entry, re-read every branch downstream of it and ask which one you just
  disabled.
- **Audit escaping when you add a pattern.** These are JSON strings holding .NET regexes
  holding Windows paths, so `\` is escaped twice and it is very easy to write `\\d`
  (literal backslash + `d`) where you meant `\d`. `_MEI\\d+` silently disabled the whole
  PyInstaller allowlist. `Test-Extended-Band.ps1` asserts allowlists against realistic
  Windows paths — **add a case there for every new allowlist**, because a path-shaped rule
  cannot be exercised by the Linux fixture tree.
- **Do not anchor a rule with `$` if the phase matches it against a COMPOSED string.**
  `LNK-ScriptHostTarget` ended `\.exe$` but Phase 118 matches
  `"<TargetPath> <Arguments>"`, so the rule could never fire. Match a boundary
  (`("|\s|$)`) instead.
- **Every regex is matched against attacker-authored content** (web shells, dropped
  scripts, registry values), so a catastrophic-backtracking pattern is a denial of service
  on the scan itself. The suite runs each one against backtracking bait under a 150 ms
  timeout, with a `(a+)+$` canary so that section cannot silently become a no-op.
- **The five Phase-6 lists auto-kill on a bare substring match.** `known_rat_procs`,
  `known_miner_procs`, `known_keylogger_procs`, `loader_procs` and `banking_trojan_procs`
  become CRITICAL + `KillProcess`, which the GUI auto-selects. No entry may be a word that
  can occur inside a legitimate process name — `houdini` (SideFX Houdini) was caught and
  removed during the 2026-08-19 expansion. The suite asserts no entry collides with a list
  of real software names and that none is shorter than 4 characters.

### Authenticode memo (WS4, added 2026-08-19)
- **`Get-AuthSig` is memoised per path** (`$global:AUTHSIG_CACHE`, case-insensitive key,
  bounded by `AUTHSIG_CACHE_MAX`, sharing the `SCYTHE_NOCACHE` kill-switch). It is the engine's
  most expensive repeated operation — the cert chain build does online CRL/OCSP — and 14
  call sites across 13 phases verify overlapping file sets. A `$null` (locked file) result
  is cached too: that is a real answer and re-asking costs the same timeout.
- **`Get-SignatureVerdict` now calls `Get-AuthSig`, not `Get-AuthenticodeSignature`.**
  There must be exactly ONE raw `Get-AuthenticodeSignature` call in the tree — inside the
  wrapper. The suite asserts that count.

### Security regression suite
- `powershell -NoProfile -File tools\tests\Run-SecurityTests.ps1` from the project root — 1,500+
  assertions across 25 test files, covering C1/H1/H2/H5/H7/H7b/H8, M1-M11, the §5 FP anchors, the WS6 extended band + the WS7 HUNT band
  (incl. RUNTIME tests of correlation, of the signature-set integrity gate, and of the phase 146
  PE parser against fixture-built PEs — `Test-Pe-Parser.ps1`, a PS port of
  `PeFixtureBuilder.cs` with a byte-by-byte truncation sweep) + WS4 signature
  memo, the parse+BOM gate, and the embedded runspace here-strings.
- **`Test-Extended-Smoke.ps1` is the oldest of the tests that EXECUTE engine code**
  (`Test-Hunt-Correlation.ps1` and `Test-Pe-Parser.ps1` are the others). It runs
  `engine/Phases-4.ps1` against a generated fixture filesystem plus an in-memory registry
  (`ExtendedSmoke.Harness.ps1`), and it is what catches runtime faults the AST tests cannot see —
  it found five real bugs on the day the band was written. It runs on Linux, but fixture paths use
  `/`, so **path-shaped rules must additionally be asserted against realistic Windows paths in
  `Test-Extended-Band.ps1`.** The harness stubs ~20 loader helpers and verifies that stub contract
  against the loader via the AST, so a renamed helper fails the test instead of drifting. Every test pulls the real functions out of the shipped source
  **via the AST**, so a test cannot drift from the code it guards. **`ParseFile` on
  `Scythe-Server.ps1` does NOT validate the runspace here-strings** (`$script:SCAN_SCRIPT`,
  `SSE_SCRIPT`, `REMEDIATE_SCRIPT`) — `Test-EmbeddedRunspaces.ps1` is what catches a syntax error
  in those.
- **The suite runs on Linux. `tools\tests\Verify-OnWindows.ps1` is the other half** and must be run
  from an **elevated Windows PowerShell 5.1** prompt before a release: the real 5.1 parser, the
  `reports\` ACL hardening (M9), the `netsh http add/delete urlacl` fallback (M5), the log-retention
  pruner and an `HttpListener` bind. `-Live` additionally starts the real server on a loopback port
  and drives the token/Origin/IOC-validation/traversal surface over HTTP. It works only in TEMP and
  on a free port, runs no scan and remediates nothing, and it ends by printing the short list of
  things a script genuinely cannot check (GUI/CSP/PURGE/exports).
- **Two traps when writing a test here:** `-match` parses as TokenKind **`Imatch`**, not `Match`
  (case-insensitive is the default), so an AST search for `Match` silently finds nothing; and
  **one-letter helper functions collide with built-in aliases** — `H` is `Get-History` and aliases
  outrank functions in command resolution. Prove every new test fails when you revert the fix it
  guards, or it is agreeing for the wrong reason.

### Server / display
- **The GUI phase counter is driven by `scan_state`, throttled to every 12 log lines** — any UI element
  that must track phase precisely needs a phase-change-triggered emit, not the `%12` tick. When a user
  reports "skipped phases," first grep the `KrakenConsole_*.log` for `PHASE N — … took` + `RECOVERED
  ERROR` — usually it's display cadence, not a dropped phase. **BUT since the engine split, a genuine
  skip IS possible**: if a phase module is missing its top-level `trap` (see the Engine-split rules), a
  terminating error drops every remaining phase in that module. Confirm by checking the log for a
  contiguous `PHASE N — … took` sequence — a hard gap (e.g. 16 → 59) right after a `RECOVERED ERROR`
  means a module trap is missing, not display cadence.

### GUI
- **Adding a cinematic effect = one `CINE_FX` entry in `app.js` + the matching `body.scythefx-<id>` CSS**
  in the "CINEMATIC FX TOGGLES" block of `fx.css`. Keep it theme-var-tinted (`--accent`/`--accent-2`/
  `--accent-glow`) and **OFF by default**. The cinematic layer is deliberately **independent** of the
  intensity tier — don't re-gate it on `body.fx-off`. Honor `prefers-reduced-motion`.

### New malware alerts
- **Use the `ingest-malware-alert` skill** (`.claude/skills/`) for every new AV/EDR alert — it extracts
  + sanitizes IOCs, adds AMSI-safe signatures to `data/detection_signatures.json`, extends the engine,
  and wires reversible quarantine, so coverage grows consistently.

---

## Key Subsystems (brief)

- **MITRE ATT&CK tagging** — server loads `data/mitre_mapping.json` into the scan runspace;
  `Resolve-Mitre`/`Resolve-MitreMain` resolve each finding (keyword → threat-type → phase map) and
  attach `mitre {id,name,tactic,url}`. Frontend renders a clickable `.item-mitre` badge.
- **HTTP routes** (`Scythe-Server.ps1`): `GET|POST /api/profiles` (scan profiles — 4 read-only
  built-ins from `$script:PROFILE_BUILTINS` + user presets in `reports/scan_profiles.json`; save is
  upsert-by-name with fail-closed validation; built-ins deliberately carry **no `ioc_file` key** so
  applying one never blanks the IOC Manager's path. **All POST bodies parse via `Read-JsonBody` —
  never inline `ConvertFrom-Json -EA SilentlyContinue`, which on PS 5.1 throws a terminating error
  on bad JSON and hangs the client with no response**); `GET /api/export/html|csv` (server-rendered
  download from current findings); `GET|POST /api/ioc` (IOC Manager — POST writes both the JSON sidecar and
  `reports/custom_iocs.ioc` in the engine's **prefixed** text format `hash:`/`ip:`/`domain:`/`regex:`/
  `file:`, then feeds it to the next scan via `-IocFile`); `GET /api/report?name=<file>` (rich engine
  findings with `FixAction`/`FixParam`, MITRE-enriched; name validated `^(KrakenBaseline_|audit_).*\.json$`);
  `POST /api/remediate {report, ids[]}` (spawns `$script:REMEDIATE_SCRIPT`, mirrors the engine's
  `Invoke-FixMode` switch — DeleteFile/DeleteReg/DeleteRegKey/KillProcess/RunCmd/Quarantine — streams
  `[FIX]` lines then `remediation_complete`; report path basename-locked to `reports/`).
- **STEALTH mode** — engine emits one compressed-JSON audit blob to stdout instead of formatted text;
  the scan runspace buffers stdout when `stealth` is set and parses the blob after the child exits.
- **Email/phishing** (Phases 74.5/74.6/74.7) — attachment-cache scan (scoped to Outlook caches, NOT the
  multi-GB OST) → `Quarantine`; Defender threat-history correlation; proactive anti-reinfection
  hardening (Office/WSH/ASR, all opt-in `RunCmd`). Content rules match malicious *constructs*, not AV
  signature names. Driven by real Datto/Defender alerts. ASR: 3 low-FP rules Block, 3 higher-FP Audit;
  Office `VBAWarnings=2` (not 4).
- **WS2 detection expansion** (ported from the work-rig branch 2026-07-01, all **`FixAction Info`** — no
  new auto-destructive findings): **Phase 55.5** known-vulnerable signed-driver audit (BYOVD vs the
  LOLDrivers name list, SHA256-confirmed via `Get-FileHashSafe`); **Phase 53** extended known-family
  ransom-note filenames + a renamed-note *content*-rule pass; **Phase 62** anchored C2/banking named-pipe
  second pass (CS/Havoc/Covenant/PoshC2 default pipes matched on the bare leaf — deliberately does NOT
  reuse the broad `[a-f0-9]{8,}` catch-all that round-4 removed); **Phase 66** now excludes drive-letter
  admin shares (`C$`/`D$`) so the worm scan doesn't walk the whole drive; **Phase 69** known-malware
  single-instance mutex probe (Pikabot/Amadey); **Phase 99.5** (DEEP+ only) process command-line
  heuristics vs externalized loader/banking/infostealer/inhibit-recovery behavior rules. Signatures live
  in `data/detection_signatures.json` (WS2 keys: `byovd_*`, `known_malware_mutexes`, `ransom_note_*`,
  `c2_pipe_regex_anchored`, `banking_named_pipes`, `*_behavior_rules`, `inhibit_recovery_rules`, …).
- **GUI feature layer** — 12 themes + secret KRAKEN (type "kraken" for a ~19s cinematic, sets
  `scythe_god=1`); synthesized sound; canvas VFX; command palette (Ctrl+K); EXECUTE REMEDIATION requires
  typing `PURGE`. **MSP Mode**: type "msp"/"gannon"/"staples" pre-scan → `gannon-orange` theme + badge.
- **Boot self-heal** — inline watchdog in `index.html <head>` reloads once (capped at 2 via
  `sessionStorage.scythe_boot_retry`) if `window.__SCYTHE_BOOTED` isn't set within 9s; server polls
  `Invoke-WebRequest` until 200 before opening the browser.

## Remediation test tripwires (safe, benign — never commit)

To validate scan→findings→remediation **without real malware**, drop inert artifacts named
`Scythe_TEST_DELETEME` that trip a detection phase with a known fix action, then run a FULL/DEEP
scan (all time) → FINDINGS → REMEDIATION → `PURGE`. `.bat`/`.cmd` are plain text (zero AV risk).

| Artifact | Detection | Severity | FixAction |
|---|---|---|---|
| `%TEMP%\Scythe_TEST_DELETEME.bat` | Phase 10 — exe-ext in Temp | HIGH | `DeleteFile` |
| `Downloads\Scythe_TEST_DELETEME.cmd` | Phase 10 — exe-ext in Downloads | POSSIBLE | `DeleteFile` |
| `HKCU:\…\Run\Scythe_TEST_DELETEME` | Phase 20 — Run-key data matches `Temp` | CRITICAL | `DeleteReg` |
| `…\Content.Outlook\SCYTHETEST\invoice_…DELETEME.bat` | Phase 74.5 — attach-ext in Outlook cache | HIGH | `Quarantine` |
| Scheduled task `\Scythe_TEST_DELETEME` (disabled) | Phase 29 — action matches `cmd` | CRITICAL | `RunCmd` |

```powershell
# Create
$b = "@echo off`r`nREM SCYTHE TEST TRIPWIRE - SAFE TO DELETE"
Set-Content "$env:TEMP\Scythe_TEST_DELETEME.bat" $b -Encoding ASCII
Set-Content "$env:USERPROFILE\Downloads\Scythe_TEST_DELETEME.cmd" $b -Encoding ASCII
New-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name Scythe_TEST_DELETEME `
  -Value '"%TEMP%\Scythe_TEST_DELETEME_noexec.exe" --scythe-test' -PropertyType String -Force
$c = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\INetCache\Content.Outlook\SCYTHETEST'
New-Item -ItemType Directory $c -Force | Out-Null
Set-Content (Join-Path $c 'invoice_Scythe_TEST_DELETEME.bat') $b -Encoding ASCII
$s = New-ScheduledTaskSettingsSet; $s.Enabled = $false
Register-ScheduledTask Scythe_TEST_DELETEME -Force -Settings $s `
  -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c rem Scythe_TEST_DELETEME benign no-op')

# Cleanup
del "$env:TEMP\Scythe_TEST_DELETEME.bat","$env:USERPROFILE\Downloads\Scythe_TEST_DELETEME.cmd" 2>$null
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Scythe_TEST_DELETEME /f 2>$null
Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\Content.Outlook\SCYTHETEST" -Recurse -Force 2>$null
Unregister-ScheduledTask Scythe_TEST_DELETEME -Confirm:$false 2>$null
```

## Known Gotchas

- **Admin elevation**: both servers + `Launch-GUI.bat` self-elevate.
- **Port**: PS server uses `Get-FreePort` (TcpListener on port 0); Python scans from 5000.
- **Encoding**: Python subprocess output uses `encoding="utf-8", errors="replace"`.
- **PS self-detection**: Phase 2 Script Block Logging may flag the script's own run — it has a
  self-filter; verify it works.

## Outstanding Work

**The prioritized roadmap lives in `BLUEPRINT.md` §10** (§7 is the quality gates). Current session
state, including anything in flight, is the top entry of `HANDOFF.md`. This section is only the
short orientation.

Most of the roadmap is **done and merged** on both engines: scan-blocking prompts, re-run handling,
MITRE, IOC Manager, HTML/CSV export, STEALTH parsing, real remediation, the three-layer safety
guard, FP rounds 1-5, the engine split + WS2 port, the live finding stream + UTF-8 pipeline,
VFX/themes/sound, the extended band 116-133, the whole HUNT band 134-162, the preflight
integrity gate, and the native C# engine (10 scanners / 63 checks).

**What is actually outstanding:**

1. **Windows validation.** The whole 116-162 span has been exercised only on Linux/pwsh. It has
   never met the PS 5.1 parser, a live registry provider or a real process table. `Phases-6.ps1`
   153-156 is the newest and the most exposed here — its absence rules (absent vs zero vs
   default-applies) are pure theory until a real registry answers them.
2. **`tools\tests\Verify-OnWindows.ps1` from an elevated 5.1 prompt**, and the browser
   click-through: destructive remediation (PURGE + protected HARD block), export downloads, IOC
   save→re-scan, STEALTH, plus the live finding ticker/chips and clean-banner glyphs.
3. **FP rounds on the new bands.** Extended and HUNT ship `Info` throughout precisely because they
   have never met a real fleet.
4. **`engine/Phases-6.ps1` has no stubs left** (147 and 157-159 on 2026-08-30, 146 on
   2026-08-30, 148-152 on 2026-08-31). What remains from that work package is the *rule
   engine* half of F3: phase 146 parses PE structure with its own pure-.NET reader, while
   `lib/Scythe.Rules` already ships YARA and Sigma engines that nothing references. Fold
   146 onto `lib/` under item 6 rather than letting two rule engines diverge.
5. **Detection parity** — port PS coverage into the native scanners; and per-check status +
   deterministic finding ids flowing the other way, from native into PS.
6. **Wire up `lib/`** (BLUEPRINT.md §10 item 6). The copy-in is **done** (2026-08-26): YARA +
   Sigma rule engines, PE + container parsers, a Windows path normaliser, a signature/rule
   linter, an IOC feed normaliser and two diff/baseline engines are in `lib/`, in the solution,
   1,664 tests green. **Nothing in `Scythe.*` references them yet.** Item 5 (detection
   parity) should be built on top of this, not run as a separate track. Start with the linter
   against `data/detection_signatures.json` — but read the `fp_allowlists` note below first.

7. **The offline artifact layer — 37 projects, not yet written.** The work package lives at
   `~/Downloads/claude/scythe-work/` (sanitized, standalone, `Scythe.*` throughout); readers over
   documented on-disk formats that replace "ask Windows for it" with "read the format", so the
   layer is developable and testable off Windows. **`docs/MERGE_ARTIFACT_LAYER.md` is the
   receiving end** — what is coming, where it lands, what to check, and the rules for editing the
   package from this side. Read it before touching that folder. It sits under item 6 and feeds
   item 5.

`docs/_history/NEXT_STEPS.md` and `UPGRADE_PLAN.md` are historical context, not live plans.
