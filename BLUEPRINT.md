# ZeroBreach V23 "Kraken Console" — Product Blueprint

> **The definitive top-level map of what this tool is, how it fits together, and where it goes
> next.** Rules live in `CLAUDE.md`; history lives in `CHANGELOG.md`; session state lives in
> `HANDOFF.md`. This file changes only when the product itself changes shape.
> Last structural update: 2026-07-26 (native shell + phase-count correction).

## 1. Mission

A **single-operator, USB-portable, zero-install Windows incident-response console** for MSP
techs. One double-click (`Launch-GUI.bat`, or the native `zerobreach-native.exe`) on any
Windows 10/11 box gives you:

1. **Detect** — ~140 numbered scan phases (labels 1–115 plus 24 fractional insertions; the plan
   ceiling per mode is 30/80/115 — see `CLAUDE.md` → "Phase numbering + counts") covering the
   full malware taxonomy (RAT/C2, ransomware,
   rootkits, keyloggers, worms, miners, trojans, spyware, fileless/LOLBins, persistence,
   credential theft, exfil, email/phishing, BYOVD, permission integrity).
2. **Decide** — findings triaged with severity, MITRE ATT&CK technique, threat type, a
   3-layer *protected-target* hard block, and a trusted-vendor soft signal, so an operator
   can trust the checklist.
3. **Act** — reversible, operator-confirmed remediation (Quarantine-first; type `PURGE` to
   execute), with a hard rule that **nothing auto-selected can ever damage a healthy system**.
4. **Report** — engine JSON/TXT/HTML + server-rendered HTML/CSV export + durable server logs.
5. **Look epic** — a cyberpunk cinematic frontend (12 themes + secret KRAKEN, synthesized
   sound, canvas VFX, command palette) that makes the scan *feel* like the event it is.

Non-goals: offensive tooling, host-AV evasion, darkweb/Tor intel, non-Windows targets.
The Python/Flask server is **parked** — PowerShell-only direction (see `_python/README_CLAUDE_CODE.md`).

## 2. Architecture

```
Launch-GUI.bat  (self-elevates → admin)          native-app/  zerobreach-native.exe
   └─ ZeroBreach-Server.ps1          pure-PS HttpListener server, SSE at /api/events
        ↑  (the Tauri shell spawns this SAME, unmodified server as a Job-Object-tied child
        │   with -Port <free> -NoBrowser, then points a native window at localhost:<port>)
        ├─ serves gui/  (index.html + css + js: sound→themes→fx→kraken→app)
        ├─ scan runspace ── spawns ── powershell.exe ZeroBreach-V23.ps1 -Auto …
        │     stdout (UTF-8) ─→ parse loop ─→ SSE events ─→ browser
        ├─ remediation runspace ($script:REMEDIATE_SCRIPT — mirrors Invoke-FixMode)
        └─ reports/  (baseline JSON, HTML, console + SSE logs, quarantine vault,
                      hash-chained remediation_audit_*.jsonl)

ZeroBreach-V23.ps1  = THIN LOADER  (params/elevation/globals/ALL helpers/banner/menus)
   └─ dot-sources, in order, into ONE scope:
        engine/Phases-1.ps1   phases 1-58   (+12 fractional, incl. 55.5)  ┐ each module has
        engine/Phases-2.ps1   phases 59-89  (+9 fractional, 74.5-74.9)    │ its OWN top-level
        engine/Phases-3.ps1   phases 90-115 (+97.5/99.5/100.5)            ┘ trap (CLAUDE.md)
        engine/Summary.ps1    risk score + exits ([Environment]::Exit)
        engine/FixMode.ps1    interactive fix mode (console runs only)

data/    detection_signatures.json (signatures + fp_allowlists — AMSI rule: NEVER inline)
         mitre_mapping.json · ioc_defaults.json · coverage_matrix.json · permission_baseline.json
```

**Why this shape holds:** phases run in numeric order and share variables across phases, so
modules split **by range, not category**, and dot-source into one scope. All signature
literals live in `data/*.json` because AMSI blocks a `.ps1` containing them. Both `.ps1`
entry files + all engine modules are UTF-8 **with BOM**; JSON outputs are UTF-8 **no BOM**.

## 3. Data contracts

### Engine → server (stdout of the child process, UTF-8)
| Line shape | Meaning |
|---|---|
| `[FINDING] {compact JSON}` | **Authoritative live finding** — emitted by `Add-Finding` in non-interactive runs. Keys: `id, sev, phase, tt, desc, target, fix, group`. The server converts CRITICAL/HIGH/POSSIBLE into SSE `finding` events (exact severity, canonical threat bucket, MITRE-resolved) and never shows the raw line. |
| `PHASE N — …` banner / `PHASE N — … took X.Xs` | Phase tracking (`PHASE\s+(\d+(?:\.\d+)?)[^\d]` — fractional phases keep their decimal and advance the counter) + per-phase profiling. |
| everything else | `log_line` (severity regex-classified for coloring only — **never** into findings). |
| STEALTH mode | one compressed-JSON audit blob on stdout; server buffers + parses post-exit. |

### Server → browser (SSE `/api/events`)
| Event | Key fields |
|---|---|
| `log_line` | `text, severity, phase, elapsed` |
| `finding` | `id, line, severity, threat_type, phase, mitre{id,name,tactic,url}, mitre_id, fix_action, target, timestamp` |
| `scan_state` | `phase, phase_total, phase_name, section, elapsed, threat_counts, running` — emitted on **every phase change** + every 12 lines |
| `scan_complete` | `findings_count, threat_counts, elapsed, results_path, engine_report` |
| `remediation_complete` | `applied, failed, skipped, blocked` |
| `sync` | full state snapshot on (re)connect |

At `scan_complete` the frontend **replaces** its live findings list with the engine report
(`GET /api/report?name=KrakenBaseline_….json` — rich findings incl. `FixAction`/`FixParam`),
so the live stream drives the in-scan experience and the report drives triage/remediation.

### Other formats
- **IOC file** (`reports/custom_iocs.ioc`, fed via `-IocFile`): prefixed text — `hash:`/`ip:`/
  `domain:`/`regex:`/`file:` (mirrors `data/ioc_defaults.json`).
- **Quarantine manifest**: file moved to `reports/quarantine/*.quar` + `.quar.json` with
  original path, SHA256, restore command.
- **HTTP routes**: `/api/csrf`, `/api/scan/start|abort` (POST-only), `/api/state`, `/api/events`,
  `/api/findings`, `/api/report?name=`, `/api/reports`, `/api/report/diff?a=&b=`,
  `/api/remediate {report, ids[]}` (POST-only; replies `{"status":"started"}` **asynchronously** —
  verify in `reports/server_events_*.log`, and a second concurrent call 400s
  `remediation already running`), `/api/export/html|csv`, `/api/ioc` GET/POST, `/api/profiles`
  GET/POST, `/api/schedule` GET/POST, `/api/sysinfo`, `/favicon.ico`, plus `/` and `/static/`.
  Every non-GET/HEAD request passes `Test-RequestAllowed` (Origin/Referer lock + `X-ZB-Token`)
  **before** the route table; a client sending neither Origin nor Referer (curl,
  `Invoke-RestMethod`) is treated as non-browser and needs no token.

## 4. Safety model (the product's spine)

1. **Auto-select rule**: only CRITICAL/HIGH **+** a destructive FixAction is ever pre-ticked.
   POSSIBLE is shown, never auto-acted. Every FP-tuning round works by downgrading to
   POSSIBLE/Info, not deleting detections.
2. **Rule #1**: never ship a destructive `FixParam` an auto-select can fire on a **healthy
   box** (no `icacls /reset /T`, `vssadmin delete shadows /all`, drive-root or recursive
   deletes). Dangerous commands go in the *description* with `FixAction Info`.
3. **`Test-ProtectedTarget` = HARD block across 3 layers** (server tag → frontend disable →
   remediation-runspace refusal reporting `blocked`): cert store, Windows/System32/SysWOW64/
   WinSxS, shell-system files, user dotfiles, SafeBoot/core-OS registry, critical processes.
4. **`Test-VendorTrusted` = SOFT signal** (Datto/CentraStage/Kaseya/…): green badge, not
   auto-selected, operator can still act; suspicious path or independent malicious signal
   overrides the trust.
5. **Quarantine over DeleteFile** for anything not hash-confirmed. Fully reversible.
6. Engine in `-Auto` is **audit-only** — remediation happens only through the GUI's typed
   `PURGE` confirmation.

Regression metric: **auto-destructive count from a full `-Hours 0` DEEP baseline** (CRIT/HIGH +
DeleteFile/DeleteReg/DeleteRegKey/KillProcess/RunCmd/Quarantine). **The absolute number is
box-dependent — compare only against a baseline taken on the SAME machine**, and always inspect the
breakdown, never just the count. Reference points, all real runs:
**52** = pre-round-6 dev box · **39** = post-round-6 dev box (2026-07-02) · **25** = end of the
2026-07-22 review session · **100** = 2026-07-26 WS7-9 grading on this dev box at `-Hours 0`, of
which **87 are Phase-10 "suspicious file in TEMP" hits** on an accumulation-heavy dev machine
(explained, not a regression — WS7/8/9 themselves contributed **0**) · **6** = a clean Windows
Sandbox (4 auto-selected tripwire findings + 2 legacy hardening posture items). Re-grade after any
severity/FixAction change, and state which box the number came from.

## 5. Quality gates (all must pass before a change ships)

1. Parse-clean on **live PS 5.1** and PS 7 — all 6 engine files + server (+ the server's
   here-strings extracted and `ParseInput`-checked separately); UTF-8 BOM intact. **Any harness
   `.ps1` you write counts too** — ASCII + BOM, parse-checked before it is run (see `CLAUDE.md`
   → "Test harnesses, sandboxes and headless validation").
2. `node --check` on touched JS; FX audit `node tools/check-visuals.mjs` (PASS 13/13).
3. AMSI: engine spawns and streams (no `ScriptContainedMaliciousContent`).
4. Headless `-Auto` scan: contiguous `PHASE N — … took` sequence (no module-trap gaps),
   clean self-exit, reports written. After adding a phase: re-count the QUICK-ungated header set
   (must be exactly 30) and add the `data/mitre_mapping.json` `phase_map` entry.
5. Auto-destructive re-grade **vs. a baseline from the same machine** (§4), and 0 system-damage
   FixParams.
6. Live GUI acceptance for UX-facing changes (`Launch-GUI.bat` as admin; tripwires in
   `CLAUDE.md` → "Remediation test tripwires").
7. Touching `native-app/`: `npx tauri build` clean, and the built `.exe` actually launched once —
   Rust that compiles is not a shell that runs (WebView2, manifest and console-allocation
   failures all happen at run time, before any of our code logs anything).

## 6. Status snapshot

### 2026-07-27 (current) — post-audit

**⚠ Read `REVIEW_FINDINGS_2026-07-27.md` before trusting anything below or in §7.** Seven independent
review agents audited the 8,834 insertions committed in the 24 h to 2026-07-27 and found real defects
in **every** area. Nothing found is fixed yet. Headline items:

- **P1 (multi-user hive coverage) is NOT done, despite being signed off as such.** The registry half
  works. The **filesystem half is effectively a no-op on multi-user boxes**: ~20 migrated sites share
  one `Get-ScanFiles` call whose 20,000-file / 20-second budget is exhausted by a single profile in
  **~1 second** (measured), so profiles 2..N get zero coverage — and the phases then print `[OK]`.
- **Six rule-#1 violations** (the tool damaging a healthy box), including auto-deleting **signed
  Microsoft ProcDump**, auto-deleting **every developer's PowerShell profile** (`Invoke-Expression` is
  the oh-my-posh/starship/scoop init line), quarantining **ZeroBreach's own exported HTML report** in a
  self-seeding loop, auto-harvesting IOCs from pasted prose into KillProcess/Quarantine paths, and a
  live `vssadmin delete shadows /all /quiet` FixParam reachable via **SELECT ALL** (which filters on
  `protected`/`vendor_trusted` but **not severity**).
- **Nine false-all-clear paths** — the class CLAUDE.md's "never print a clean result for a check that
  could not have fired" rule exists to prevent.
- **Two detection regressions**, one affecting *every* scan: wrapping phases in `if (Test-PhaseGate N)`
  silently coarsened trap recovery from statement-level to phase-level across ~134 phases.
- **The sandbox harness cannot report failure** — it only logs counts and always writes its `DONE`
  marker. The 2026-07-27 "clean PASS re-validated against current HEAD" is therefore not evidence.
  Repairing it is the prerequisite for everything else.
- **No baseline figure is currently trustworthy.** Five are in circulation (7/8/50/63/94); the
  quoted **8** predates the Phase 90 fix (post-fix **5**) and the Stage 9 findings.

**Verified genuinely clean** (do not re-audit): Build Custom Scan's command-injection guard (23
payloads on live 5.1), its gate rewrite (AST diff of all 2,202 command nodes — byte-identical
predicates, QUICK still exactly 30), CSRF/XSS/backtracking, the `{TOKEN}` path migration, MITRE
`phase_map` coverage of all 139 phases, the WMI allowlist anchoring, P1's variable-shadowing and
`,$arr` discipline (60 call sites), and the server-side P1 remediation guards and their runspace
mirror. All 7 engine/server files parse clean on live 5.1 with BOM intact.

**Direction set 2026-07-27:** operator approved an engine rewrite. Plan is `ENGINE_REWRITE_PLAN.md` —
a **read-only Rust evidence sidecar** first (emitting the existing `[FINDING]` contract, so no server
change), then an **incremental** detection port behind a differential PS-vs-Rust harness; **destructive
remediation stays in PowerShell**. Sequenced deliberately behind the findings fixes and the harness
repair. Merge of `session12/review-remediation-ws6` → `main` decided: **after** the review fixes.

### 2026-07-26 (historical)

**Where the code is:** everything since 2026-07-22 sits on the branch
`session12/review-remediation-ws6`, **not merged to `main`**, and the working tree carries
uncommitted engine + `native-app` changes. Verify with `git log`/`git status` before assuming.

**Proven live since the 07-02 snapshot below:**
- **2026-07-22** review remediation (all 56 findings) + WS6 + UX pass, then 3 independent audit
  passes; DEEP 115 labels, 0 recovered errors.
- **2026-07-26** WS7/WS8/WS9 — 18 further techniques, graded on a fresh all-time DEEP
  (0 new auto-destructive from any new phase), plus remediation tri-state verification, a
  hash-chained remediation audit log, and 6 RunCmd command-injection fixes.
- **Native shell (Milestone 1)** — Tauri `.exe` screenshot-verified rendering the real GUI, child
  server tied to a Job Object (force-kill verified), WebView2 preflight added after a live
  silent-hang was reproduced on a WebView2-less machine.
- **Windows Sandbox infection testing, Stages A + B** — FULL 80/80 and DEEP 115/115, 0 recovered
  errors, against 5 real malware families (incl. KRBanker); auto-destructive set == the known
  tripwires.

**Not verified / not done:** Stage C (live detonation → rescan → remediation) and Stage D
(WebView2-fix confirmation) are written but were never run to completion; the browser
click-through; the USB foreign-box field test; the NSIS installer (built, never installed);
`data/coverage_matrix.json` (last regenerated 2026-07-25 at 130 phases — behind the engine);
`tools/Build-Release.ps1` has no `native-app` awareness; the Three.js 3D GUI is not started.

### 2026-07-02 (historical)

**Proven live:** the engine-split architecture end-to-end in the browser (2026-07-01 DEEP run:
115 phases contiguous, 0 recovered errors, ~9.5 min, clean exit); phase-counter fix `c0477ae`
**validated** from the SSE log (all 116 phase values 0→115, no jumps); FP tuning through
round 5 (52 auto-destructive, 0 damage ops); 3-layer safety guard incl. a real blocked
remediation POST; all server routes headless-validated.

**Fixed 2026-07-02 (this session, from the SSE-log analysis):** the live finding stream was
dead — engine finding lines carry no severity tags, so a full DEEP run produced **0** SSE
`finding` events / all-zero threat counts / an empty server `audit_*.json` while the engine
recorded 288 findings. Now: `Add-Finding` emits structured `[FINDING]` JSON lines and the
server converts them into exact-severity `finding` events (contract in §3). Also fixed:
child-process stdout mojibake (engine now sets UTF-8 console encoding when redirected); the
`[OK ]`-padding classifier miss; and the `$sev`/`$SEV` case-insensitive variable shadow that
had silently disabled ALL log-line severity classification since the server was written
(dict renamed `$SEV_RX`). Server text-severity finding path retired (double-count guard).
End-to-end server-driven validation scans confirmed finding events stream live with exact
severities, resolved MITRE, populated threat counts, and a non-empty `audit_*.json`.

**Open acceptance item (the one):** browser click-through of destructive remediation
(PURGE + protected HARD block), HTML/CSV export downloads, IOC save→re-scan, STEALTH run —
now also eyeballing the live finding ticker/chips + clean banner glyphs. Runbook in
`HANDOFF.md`.

## 7. Roadmap

### Now (2026-07-27 onward) — supersedes the list below

1. **Fix `REVIEW_FINDINGS_2026-07-27.md`**, in its stated order: P1-1 (the `Get-ScanFiles` truncation
   signal — highest leverage, five other findings collapse into it), then the six rule-#1 violations,
   then the lockout/host-damage items.
2. **Repair the sandbox harness so it can fail** (TEST-1…TEST-5), then extend it into the
   **differential PS-vs-Rust harness** the rewrite depends on. Acceptance: deliberately break a
   detection and confirm it goes red.
3. **Re-measure the healthy-box baseline** on a **multi-profile** box — the current dev box has 2
   profiles and is structurally blind to three of the rule-#1 findings.
4. **Merge `session12/review-remediation-ws6` → `main`** once 1-3 land.
5. **Stage 2 of `ENGINE_REWRITE_PLAN.md`** — `zb-evidence.exe`, the A-series in `EVIDENCE_ENGINE_PLAN.md`
   §8 order (A1 census first), delivering the operator's Event Viewer / IR GUI (**both live view and
   export package**). Blocked on a **sensitive-data policy** for the export path.
6. Then Stage 3: incremental detection port behind the diff.

Still open and unchanged from the list below: live GUI click-through, USB foreign-box field test,
NSIS installer, `data/coverage_matrix.json` re-audit, `Build-Release.ps1` native-app awareness,
Three.js 3D GUI, code signing.

### Now (as of 2026-07-26 — largely superseded by the list above)
- **Finish the sandbox test matrix** — Stage C (detonate KRBanker offline → DEEP rescan → two
  properly sequenced `/api/remediate` calls, one on tripwires and one probing a `protected`
  finding) and Stage D (confirm the WebView2 preflight fires on a WebView2-less box). Both
  harnesses exist; neither has completed a run. **One Windows Sandbox VM at a time**, and confirm
  no `vmmemWindowsSandbox` is alive before launching (see `CLAUDE.md` harness rules).
- **Decide the fate of the uncommitted working tree** (engine + `native-app` changes) and whether
  `session12/review-remediation-ws6` merges to `main`.
- **Live GUI click-through** (user-driven; runbook in `HANDOFF.md`) — still open, and now also
  needs to confirm the CSRF-token handshake (the GUI fetches `/api/csrf` at boot; a 403 on any POST
  means the token or the origin lock is misbehaving), the three previously-inert launchpad toggles
  (snapshot / baseline diff / CSV export), and the same pass inside the **native shell**.
- **USB field test on a real foreign box** — still open.
- **Native track (the stated priority):** the Three.js 3D GUI redesign that Milestone 1 is a
  stepping stone to; real branding (the icon is a placeholder); `tools/Build-Release.ps1` /
  `README.md` decision on whether the `.exe` replaces or coexists with `Launch-GUI.bat`.
- **`data/coverage_matrix.json` re-audit** — regenerated 2026-07-25 at 130 phases, so it no longer
  matches the engine.

### Done 2026-07-26 — WS7/8/9 detections, remediation correctness, native shell
Branch `session12/review-remediation-ws6` (**not merged to `main`**). Commits `c578c25`..`bb2a22d`:
**WS7/WS8/WS9** (18 further MITRE techniques, all fractional-phase, 0 new auto-destructive findings
from any of them) · **tri-state gone/present/unknown** remediation verification for
DeleteFile/DeleteRegKey/Quarantine in **both** paths, then DeleteReg in `FixMode.ps1` ·
**tamper-evident hash-chained remediation audit log** (`reports/remediation_audit_*.jsonl`, both
paths) · **6 RunCmd command-injection fixes** (unescaped single quote, 2 of them on auto-selected
CRITICAL paths) · rule-#1 auto-kill FP fixes + self-allowlist anchoring · LNK-downloader / LOLBin /
reverse-shell STRONG-vs-WEAK severity splits · **`native-app/` Tauri shell (Milestone 1)** plus its
hardening (Job Object kill-on-close, poison-safe locks, handle-leak fix) and the WebView2 preflight.
Five independent audit rounds drove most of the fixes. `data/coverage_matrix.json` was **not**
regenerated for WS7-9 — it is stale by design-debt, not by decision.

### Done 2026-07-22 — full review remediation + WS6 detections + UX pass
`REVIEW_FINDINGS_2026-07-22.md` applied in full (all 56 findings) — see `CHANGELOG.md` for the
narrative. Load-bearing outcomes: the two missing engine-module `trap`s restored; the server's
wildcard-CORS **cross-origin remediation hole** closed with an origin lock + per-process CSRF
token (verified live against a 6-case matrix); the anchored-path cluster (P28/29/36/69/83) fixed
so no auto-selected destructive action is gated on a bare `"AppData|Temp"` substring; the
rollback snapshot made a *valid* `.reg` file (it imported nothing before) and extended to
GUI-driven remediation, which previously took no snapshot at all.

**WS6 — 9 new fractional phases** (17.5 timestomp · 21.5 SilentProcessExit/EDR-blinding IFEO/COM
TypeLib · 22.5 AppCert/netsh/Winsock LSP · 42.5 hidden & shadow admin · 44.5 credential-access
artifacts · 45.5 RDP exposure + hardening set · 68.5 ClickFix/fake-CAPTCHA RunMRU residue ·
82.5 RMM abuse · 100.5 cloud/session token theft), 31 new AMSI-safe signature keys, all
MITRE-mapped. **Every hardening/lockdown action is operator-only** (Info/POSSIBLE + RunCmd, never
auto-selected — rule #1); the GUI's **SELECT HARDENING** button is the opt-in.

Live-validated: DEEP 115 phases, 0 recovered errors, **WS6 contributes 0 auto-destructive
findings**. Two WS6 FP floods were caught by that validation and tuned before shipping (a
GUID-filename DPAPI heuristic that hit 99 benign cache files — now requires the actual DPAPI
blob magic; and "created-after-write" timestomping, which is just what copying does — now
POSSIBLE-only, with the auto-actionable grade reserved for zeroed/epoch timestamps).

### Done 2026-07-02 — portable distribution
`tools/Build-Release.ps1` builds the transferable artifact: validates every script
(parse + BOM) and data file (JSON), stages runtime files only, writes
`dist/ZeroBreach-V23_<stamp>.zip` + SHA256 sidecar (`-OutDir` targets a USB directly;
`-IncludePython` optional). The server self-unblocks its runtime tree at startup
(Mark-of-the-Web). **Proven:** extracted release to a spaced path → server boots, GUI
serves HTTP 200, `/api/state` answers. Remaining field test: a real *foreign* box (not
the dev machine) per the item below.

### Next (high value, ordered)
1. ~~**WS3 — FP-tune the WS2 detections**~~ **DONE 2026-07-02** — fresh live DEEP baseline
   (`_143221`: 734 findings, 39 auto-destructive vs the 52 reference) shows the WS2 detections
   clean (only P53's Info-only name matches). FP round 6 cleared the remaining healthy-box
   auto-destructive tail with user sign-off (P20 OneDrive RunOnce, P31 .lnk target resolution,
   P42 account→Info, P47 WindowsApps substring, P48/P94 package trees, P86→POSSIBLE,
   P90 renderer DLLs) — see `CHANGELOG.md`.
2. ~~**Round-4/5 leftover FPs** needing user sign-off~~ **RESOLVED 2026-07-02** — all cleared
   in round 6: P48/P94 Python LocalCache + P90 scratchpad via package-tree allowlists; P53
   already content-confirm/Info; P63 LGHUB + P96 printer-resource DLLs (catalog-signed,
   invisible to Get-AuthSig) reappeared live in the `_192913` dev-profile re-run and were
   allowlisted the same day (`miner_config_benign_paths`, `spooler_benign_dlls`).
3. ~~**Per-phase progress truth**~~ **DONE 2026-07-02** — the server's phase regex now
   captures fractional phases (55.5, 74.5/.6/.7, 99.5); they advance the counter/progress
   as real plan steps, findings carry the true fractional phase, and MITRE resolves their
   dedicated `phase_map` keys (previously unreachable). `phase_total` stays the plan
   ceiling per mode (30/80/115, mirroring the loader's `$PhasePlan`).
4. ~~**Scan profiles**~~ **DONE 2026-07-02** — `GET|POST /api/profiles` (4 read-only
   built-ins + user profiles in `reports/scan_profiles.json`, fail-closed validation,
   upsert-by-name, 50 cap) + SCAN PROFILES picker in the config view. Shipped with a
   server-wide fix: malformed JSON in any POST body used to hang the client forever
   (PS 5.1 terminating `ConvertFrom-Json` error) — now `Read-JsonBody` + accept-loop
   500 net; `/api/scan/start` fails closed on a garbled config. See `CHANGELOG.md`.
5. ~~**Coverage matrix re-audit (WS0)**~~ **DONE 2026-07-02** — regenerated against main's
   split engine (121 phases, +55.5/+99.5, schema extended with module/mode_gate/severities/
   fix_actions; MITRE cross-checked). Gap list in the commit message (`fea1960`). Two
   discoveries became items 7–8 below.
6. **USB portability field test** — extract a `Build-Release.ps1` zip on a **non-dev** box
   (spaced path already proven locally); confirm SmartScreen/Unblock flow, URL-ACL fallback,
   and reports landing beside the extracted copy.
7. ~~**Wire the 15 orphaned signature keys**~~ **DONE 2026-07-02** — all 15 now consumed:
   P67 adware regs / P82 tunneling / P89 stego / P98 leaked certs / P106 cred-dump tools
   externalized 1:1 (inline AMSI-liability literals removed); P6 gains loader/botnet +
   banking-trojan process IOCs; P34/36 gain the extra C2 domain families; P55.5 gains a
   cert-TBS-SHA1 confirm (durable across polymorphic BYOVD variants); P62 a framework-NAME
   pipe pass; P68 the 14 new infostealer families + loader-drop/C2-config file rules; P100
   the full 31-path infostealer target list. A Fable review agent caught **2 rule-#1 auto-fire
   FPs before commit**: broad `known_c2_domains` (github/ngrok/tailscale) must NOT feed the
   Phase-34 DNS-cache HIGH+RunCmd path (split into `$MALWARE_C2_DOMAINS` for P34 vs
   `$ALL_C2_DOMAINS` for P36 reverse-DNS only); and generic stealer family words
   (atomic/aurora/mystic) auto-killing legit procs — P68 now auto-kills only unsigned + in a
   user-writable path (validated live: `Mystic_Light_Service` correctly downgraded to POSSIBLE,
   not killed). Parse-clean 5.1+7, BOM intact, full DEEP + FULL headless runs 0 recovered errors.
8. ~~**Make QUICK a real gate**~~ **DONE 2026-07-03** — QUICK now runs exactly 30 phases
   (`1,3,4,5,6,10,20,21,23,27,28,29,30,31,33,35,41,42,45,51,53,54,56,62,64,69,70,72,74.6,75` —
   cheap high-signal triage: process/IOC/run-key/task/service/pipe/net/Defender, deferring the
   expensive file-walks, sig-audits, and event-log mining). Mechanism: loader sets
   `$global:QUICK_MODE`; the other 54 phases in 1–80 are wrapped
   `if (-not $global:QUICK_MODE) { trap {…}; <body> }` (contiguous-run blocks, each with its own
   inner trap per the module-trap rule). `$PhasePlan.Max=30` flows to `TOTAL_PHASES`/Summary;
   server keeps `QUICK=30` and now reports a 1..30 `PhaseIdx` (count of distinct headers seen)
   as the `scan_state`/`sync`/`/api/state` `phase` in QUICK only — findings keep the true phase.
   Two Fable agents assisted: a cross-phase variable-leak audit (**0 leaks** — every kept phase
   self-contained or on loader globals; 51→53 `$ransomScanFiles` verified outside the wraps) and
   the server progress-index implementation. Validated live: headless QUICK runs exactly those 30
   phases, 0 recovered errors; FULL still runs the full 1–80 span. **Also fixed a latent
   pre-existing bug surfaced by the QUICK run:** Phase 56's rootkit loop used `foreach ($pid …)`
   — `$PID` is a read-only automatic, so the loop threw whenever a WMI/PS process discrepancy
   existed (exactly when it matters), silently killing hidden-process detection in every mode.
   Renamed to `$rkpid`.

### Later
- **WS4 performance** (in progress): **`Get-ScanFiles` per-scan enumeration memo DONE
  2026-07-04** — the 18 call sites re-walked the filesystem with no caching; a full-param-tuple
  memo (`$global:SCAN_FILE_CACHE`, `ZB_NOCACHE` kill-switch) collapsed 18/41 walks and cut DEEP
  wall-clock ~21% with the CRITICAL/HIGH set byte-identical (see CHANGELOG). **True phase
  parallelism is ruled out** — phases share variables across a single dot-sourced scope, so
  concurrent execution would race that state; not safe here. **`Win32_Process` snapshot memo DONE
  2026-07-21** — `Get-ProcSnapshot` (loader helper, 90s TTL because the process table is NOT
  static, shared `ZB_NOCACHE` kill-switch) collapsed 6 of the 7 full per-phase WMI process
  enumerations (Phases 3/4/44/99/99.5/102); Phase 56's WMI-vs-Get-Process rootkit delta stays on
  raw same-instant enumerations by design. Service lookups audited: only one full `Win32_Service`
  enum per scan (Phase 111 unquoted-path privesc) + cheap name-filtered `Get-Service` calls —
  nothing left to cache there. **Per-file signature caching DONE 2026-07-25** (`c578c25`:
  `$global:SIG_CACHE` + `$global:AUTHSIG_CACHE`, same `ZB_NOCACHE` kill-switch). The sub-2-minute
  QUICK target has not been re-measured since.
- **WS5 reporting**: executive summary, per-tactic MITRE rollup and baseline trend/compare shipped
  2026-07-25 (`c578c25`, server-rendered report + `/api/report/diff`). Open: fleet-level rollups.
- **Scheduled scans productized**: `-Schedule` + SMTP delivery hardening. `GET|POST /api/schedule`
  and its GUI panel exist (hardened in the 2026-07-22 round-2 pass); delivery hardening is open.
- **Build**: two distribution paths now — `tools/Build-Release.ps1` (portable zip + `Launch-GUI.bat`,
  **no `native-app` awareness yet**) and the Tauri NSIS installer (`native-app`, built but never
  installed/tested). PyInstaller for the parked Python server stays deprioritized. Open: real
  branding to replace the placeholder icon, code signing / SmartScreen.
- **Fleet ideas** (multi-box): central drop-folder for baselines + a compare view.

## 8. Doc map

| File | Role |
|---|---|
| `BLUEPRINT.md` | This file — product shape + roadmap. Start here. |
| `CLAUDE.md` | Hard rules + subsystem reference for anyone editing code. |
| `HANDOFF.md` | Per-session state + the live-GUI runbook. Newest session block on top. |
| `CHANGELOG.md` | Dated narrative of every fix/tuning round. |
| `README.md` | Operator-facing: quick start, deployment, CLI, GUI features. |
| `native-app/README.md` | Tauri native shell — build, run, debug, known gotchas. |
| `.claude/skills/ingest-malware-alert/SKILL.md` | Workflow for turning an AV/EDR alert into coverage. |
| `NEXT_STEPS.md` / `UPGRADE_PLAN.md` / `NIGHT_RUN_PLAN.md` | Historical work plans (superseded by §7; kept for context — **do not action their task lists**). |
| `REVIEW_FINDINGS_2026-07-22.md` | Closed review — all 56 findings applied 2026-07-22. Historical. |
| `TIME_LOG.md` | Effort estimate generated 2026-07-03; a point-in-time snapshot. |
| `client_alerts/` | Sanitized real-world alert intake (see the ingest skill). |
| `_python/README_CLAUDE_CODE.md` | Parked Python server spec — its task list is NOT current work. |
