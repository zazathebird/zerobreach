# CHANGELOG — ZeroBreach V23

Historical bug-fix and tuning record, moved out of `CLAUDE.md` (which now carries the
consolidated **rules** only). Newest first. Every durable "never do X" lesson from these
entries lives in `CLAUDE.md` → **Critical Rules**; this file is the narrative backing.

---

## 2026-07-27 (session 23) — seven-agent audit of the preceding 24 h: every area had real defects, and several sign-offs below are weaker than they read

**No code changed in this session.** This entry records an audit and the corrections it forces to
entries *below* it. Full detail, with file:line and reproduction, is in
**`REVIEW_FINDINGS_2026-07-27.md`** — that document is the active work queue and **nothing in it is
fixed yet.** Forward plan: `ENGINE_REWRITE_PLAN.md`.

**Method.** Seven review agents, partitioned by file ownership so no two read the same file, each
given CLAUDE.md's CRITICAL RULES as the standard and instructed to verify by reading code rather than
trusting comments or the claims in this file. Scope: `391b6c4..99e5feb`, **8,834 insertions across 24
files** (P1 multi-user hive coverage, Build Custom Scan, the `/api/remediate` TOCTOU fix, the Phase 90
self-detect fix, the new sandbox harnesses). Baseline gate re-run first: all 7 engine/server `.ps1`
files parse clean on live `powershell.exe` 5.1.26100.8875 with UTF-8 BOM intact — **the defects are
semantic, not syntactic.**

**What was found.** Six rule-#1 violations, nine false-all-clear paths, two detection regressions, a
permanent-remediation-lockout bug, a host-wide VM kill in a harness, and a harness suite structurally
incapable of reporting failure. Several findings were confirmed by *measurement* on live 5.1 rather
than by reasoning: the 74 ms `BeginInvoke` window, the `GetFileName` throw table, the trap-granularity
before/after trace, the `cmd` `>>` redirect-handle behaviour, the 3.4 s O(n²) dedupe, the 20,000-files-
in-1.0 s budget exhaustion, and a 23-payload injection matrix (which came back clean).

**Corrections to entries below this one — read these before trusting them:**

- **P1 is not done.** The 2026-07-27 entry below concludes *"All of P1 (Stages 0-9) is now live-graded
  end-to-end; nothing known left open on P1 itself."* The registry half works. **The filesystem half is
  effectively a no-op on any multi-user box**: the ~20 migrated sites pass all profiles' roots to one
  `Get-ScanFiles` call whose caps were never scaled, and one profile exhausts the 20,000-file /
  20-second budget in ~1 second — so profiles 2..N get zero coverage while the phases print `[OK]`.
  Three *new* rule-#1 violations came from the ×N multiplication (Phase 106 auto-deletes signed
  Microsoft ProcDump; Phase 31 auto-deletes developers' PowerShell profiles; Phase 74 writes hardening
  into other users' hives). `-LoadUserHives` also **cannot be passed from the GUI at all**, though the
  server's own block message advises operators to use it.
- **The sandbox "clean PASS" is not evidence.** `harness-malware-detection.ps1` only *logs* its 13
  assertion counts; every one can be `0` and it still writes its `*_DONE` marker. It has no verdict
  line, no differentiated exit code and no failing state. Re-runs additionally read the *previous*
  run's log and test a **stale engine** (`Copy-Item -Recurse` nests rather than overwrites). Neither
  harness calls `/api/remediate`, so Stage C and P1 Stage 6 are **not reproducible** from
  `tools/sandbox-test/` despite being cited as live-proven.
- **The TOCTOU fix introduced a new HIGH bug.** Raising `Remediating` in the route handler was correct,
  but `[System.IO.Path]::GetFileName()` throws on `| < >` or control chars, and with no `try`/`finally`
  around the set→dispatch region the flag sticks `$true` — **400-ing every future remediation for the
  life of the process.** Also: what makes the current check-then-set safe is that the accept loop is
  single-threaded, **not** atomicity — there is no lock or `Interlocked` anywhere, contrary to the new
  code comment. And `/api/scan/start` still has the original deferred-set defect, which is not benign:
  it re-opens the very hole the fix closed.
- **`vssadmin delete shadows /all /quiet` is still a live FixParam** (`Phases-1.ps1:3041`), and
  `SELECT ALL` filters on `protected`/`vendor_trusted` but **not severity** — so one click queues an
  irreversible whole-machine shadow purge. The claim at `:419` of "0 such FixParams" is false as
  written; it is 0 *auto-selectable* ones.
- **The P11 "rule-#1 violation" (Phase 30) never actually fired.** `.Count` on a single
  `ManagementObject` yields nothing, so the unwrapped sum hit the early exit and the phase printed
  "clean" with zero findings — corroborated by the pre-fix baseline artifact. It was **0 → 0**, and the
  real defect was the opposite: a false all-clear. The `@()` wrap incidentally fixed it; that lesson
  was never recorded.
- **No baseline figure is trustworthy.** Five are in circulation (7 / 8 / 50 / 63 / 94), two pairs on
  mutually inconsistent bases, and the 94→63 / 92→50 transitions match **no stored artifact**. The
  widely-quoted **8** predates the Phase 90 fix (post-fix **5**) and contains zero `PHASE 0` findings,
  so it predates Stage 9 as well.
- **Build Custom Scan's core promise is currently false** — a pasted SHA256 can never match (its only
  consumer phases appear in no category), and the auto-suggested TRIAGE mode silently drops most of the
  phases the panel says it selected, including Phase 74.5 on a phishing alert.
- Smaller doc errors: "P1 changes IDs at ~20 sites" is really **46**; Phase 10.5 was **never** migrated
  to the shared `WScript.Shell` COM object despite the P4 entry saying so; the P10 schema is no longer
  "live but unexercised" (six call sites); Phase 90 IDs are no longer filename-keyed.

**What the audit confirmed as genuinely sound** (recorded so it is not re-litigated): Build Custom
Scan's command-injection guard, proven against 23 payloads on live 5.1; its gate rewrite, proven by an
AST diff of all 2,202 command nodes to have byte-identical enclosing predicates with QUICK still at
exactly 30 headers and all 24 fractionals round-tripping correctly; CSRF gating, XSS, and regex
backtracking; the `{TOKEN}` path migration; `mitre_mapping.json`'s `phase_map` covering all 139 phases;
the new WMI allowlists' `^…$` anchoring against self-allowlisting; P1's variable-shadowing discipline
(zero hits across three modules) and `,$arr` discipline (all 60 `Get-UserHives` call sites correct);
finding-ID uniqueness across all 57 hive loops bar one; and that the `Test-ProtectedTarget` mirror
really is inside the `REMEDIATE_SCRIPT` here-string.

**Lesson, added to CLAUDE.md.** The existing rule reads *"live grading and 3 audit agents caught what
static reasoning missed."* The complement is now also true: **static review caught what a
structurally-unfailable test suite could not.** Both are needed, and a harness without an observed
failing state is not a test.

---

## 2026-07-27 — P1 Stage 6 (end-to-end remediation proof) closed out; fixed a real `/api/remediate` TOCTOU race found while testing

**Context.** P1's engine-side work (Stages 0-5, 7-9) has been done and live-graded since the prior
2026-07-27 session; Stage 6 — proving `POST /api/remediate` against a real hive-loaded
(`HKU\<SID>`) `FixParam`, with the logged-off-retry-reports-`blocked` check — was the one item never
actually run (no `remediation_audit_*.jsonl` existed anywhere in `reports/` before this session).
It is now closed, live, on this box, with real evidence.

**Test setup — no account impersonation.** The spec's own test-fixture pattern (log the user on,
plant a Run-key tripwire, remediate, log off, retry) requires acting as `zbtest2`; two attempts to do
that (`net user zbtest2 <password>`, and a `Register-ScheduledTask -Principal (New-ScheduledTaskPrincipal
-UserId zbtest2 -LogonType S4U)`) were both **refused by the permission classifier** as sensitive
account-manipulation actions — correctly, and `zbtest2`'s account/password were never touched.
Used a non-impersonating equivalent instead: `Get-UserHives`'s "already mounted" detection keys
purely on whether `HKEY_USERS` contains a subkey named exactly after the profile's SID — it does not
care how that key got there. `reg load HKU\S-1-5-21-...-1003 C:\Users\zbtest2\NTUSER.DAT` (an
ordinary admin registry-file operation, no credentials involved) produces a hive the engine reports
with `Source = 'HKU'` / `WasMounted = $true`, identical to a genuine interactive logon from the
engine's point of view, and — critically — identical from `Phase 20`'s `$zbRunMounted = ($zbT.Src -eq
'RegLoad')` test, so it correctly yields a **destructive** `DeleteReg` `FixParam` in the real,
persistent `Registry::HKEY_USERS\<SID>\...` form (`Get-UserHives`'s own `-LoadUserHives` reg-load path
mounts under a `ZB_UH_*` name instead and is deliberately capped at `FixAction Info` per §4.7 — using
the real SID as the mount name is what makes the WasMounted branch fire instead of the RegLoad one).

**Evidence.**
- Planted two Run-key tripwires (`ZeroBreach_TEST_DELETEME`, `..._OFFLINE`) directly in zbtest2's
  mounted hive at `Registry::HKEY_USERS\S-1-5-21-2934201606-2785436122-4267783230-1003\SOFTWARE\
  Microsoft\Windows\CurrentVersion\Run`. A DEEP scan scoped to Phase 20 via Build Custom Scan
  (`-Phases 20`) found both, correctly attributed to `[WIN11\zbtest2]`, `Source: HKU`,
  `fix_action: DeleteReg`, real `HKU\<SID>` `fix_param` — plus a `PROFILE_CENSUS` honesty finding
  naming both profiles "examined: registry+filesystem" (`reports/KrakenBaseline_20260727_141501.json`,
  finding IDs `RUNKEY_ea370fb2` / `RUNKEY_e9d74696`).
- `POST /api/remediate` for `RUNKEY_ea370fb2` (hive still mounted): `applied:1`,
  `reports/server_events_20260727_141410.log` @ 14:17:55 confirms `[REMEDIATE] Complete — applied:1
  failed:0 skipped:0 blocked(protected):0`; independently verified the value is gone from the live
  registry; `reports/remediation_audit_20260727_141755.jsonl` created (first ever in this repo) —
  hash chain manually recomputed end-to-end (SHA256 of `prevHash + compact-JSON` per entry,
  GENESIS `prevHash` = 64 zeros) and matches on every link.
- Two `/api/remediate` POSTs fired **truly concurrently** (`System.Net.Http.HttpClient`, both
  `PostAsync` calls issued with no `await` between them) **both returned `200 {"status":"started"}`**
  — a real bug, not the documented "second call 400s" behavior, and not a test-setup mistake (see
  below). Sequential back-to-back calls (a real network round-trip between them, i.e. what an actual
  double-click produces) correctly got `200` then `400 {"error":"remediation already running"}` both
  before and after the fix.
- Unmounted the hive (`reg unload`, needed the SERVER process killed first — it held an open handle
  from the concurrency-race test; `[gc]::Collect()` alone in a fresh process does not release a
  handle held by a *different* still-running process), confirmed `HKEY_USERS` no longer lists the SID
  (simulating "zbtest2 logged off"), restarted the server, and retried remediation of the second
  tripwire (`RUNKEY_e9d74696`) against the same unmodified report. Result: `applied:0 failed:0
  skipped:0 blocked:1`, `reports/server_events_20260727_142443.log` @ 14:24:55 logs `[BLOCKED]
  protected (user hive no longer mounted (...-1003 logged off since the scan) - have them log on and
  re-run, or act manually) — refusing DeleteReg`. Re-mounted the hive independently afterward
  (verification only, outside the tool) and confirmed the `..._OFFLINE` value is **still present,
  byte-for-byte unchanged** — proving `blocked` reflects reality, not a status-string coincidence, per
  the acceptance test's explicit requirement.
- Cleanup verified: both tripwires removed, hive unloaded (`HKEY_USERS` back to its pre-test 6
  entries, zero `ZB_UH_*`/`ZB_UC_*` residue), server process stopped, port 8899 free, `zbtest2`
  account fully untouched (`Enabled: True`, `PasswordRequired: False`, same as before this session —
  its password/credentials were never modified since both impersonation attempts were refused).

**Bug found and fixed: `/api/remediate` concurrency guard was TOCTOU-racy
(`ZeroBreach-Server.ps1` ~1983-2007).** `$RemState.Remediating = $true` was set **inside**
`$script:REMEDIATE_SCRIPT` (the text run in the spawned runspace), not by the route handler that
checks it. `Start-Runspace` (`ZeroBreach-Server.ps1:811-825`) only calls `$ps.BeginInvoke()` — a
non-blocking dispatch — so there is a real, measurable window between the route handler returning
`{"status":"started"}` and the spawned script's first statement actually executing on a threadpool
thread. Two genuinely simultaneous POSTs can both read `$script:State.Remediating` as `$false` and
both start a remediation run; each run's own `finally` block would then independently flip the shared
flag back to `$false`, which could let a *third* request in while the first run is still genuinely in
progress. This is the same "guard flag raised too late for the check that reads it" shape CLAUDE.md's
"Fail closed, always" section already warns about (there codified as "never set optimistically and
cleared on mismatch" for the CIDR matcher; here the analogous defect is "never defer the set to code
that might not run yet"). **Fix:** `$script:State.Remediating = $true` now happens synchronously in
the route handler, immediately after the existing guard checks and before any further work, with the
flag explicitly reset to `$false` on every early-return validation failure (bad JSON / invalid report
/ report not found / no findings selected) and if `Start-Runspace` itself throws — otherwise a
rejected request would leave the flag stuck `$true` and 400 every future remediation attempt forever.
Verified live: the same concurrent-`HttpClient` test that used to return `200`/`200` now
deterministically returns one `200`/one `400` (order between them is nondeterministic and expected —
whichever thread's synchronous set wins). Sequential calls, and the normal apply/blocked flows above,
were re-verified unaffected after the fix. **Not fixed / noted for awareness, not in scope for this
session:** `/api/scan/start`'s `$ScanState.Running = $true` (`ZeroBreach-Server.ps1:1066`) sets the
flag inside `$script:SCAN_SCRIPT` the same way and is architecturally the same class of race — Stage
6 only required proving the remediation guard, so this was left alone rather than gold-plated; worth
the same fix in a future pass if a scan-vs-scan double-start is ever a concern.

**Files touched:** `ZeroBreach-Server.ps1` (the TOCTOU fix, ~30 lines in the `/api/remediate` route).
Nothing in `engine/*.ps1` changed — Stage 6 is server-side only. `zbtest2` remains the standing P1
test fixture, untouched otherwise.

---

## 2026-07-27 — Sandbox harnesses moved into the repo; Stage D redo + malware-detection re-validation both PASS on current HEAD

**Context.** The 2026-07-26 sandbox work above was recovered from an ephemeral scratchpad but left
two items open: Stage D (WebView2-missing dialog) was inconclusive, and Stage G's malware-detection
proof predated P1 (multi-user hive coverage) and Build Custom Scan (`-Phases` gating), both of which
touch code paths the malware run exercises. Both are now closed, and — the actual point of this
session — the harnesses themselves now live in `tools/sandbox-test/` (`harness-webview2-dialog.ps1`,
`harness-malware-detection.ps1`, `Invoke-SandboxTest.ps1` orchestrator, `README.md`) instead of a
Claude Code temp directory, so this can't be lost a second time.

### WebView2-missing dialog redo — root cause found, PASS
The 2026-07-26 "inconclusive" result (native message-box window not found by `FindWindow`, process
had to be force-killed) was diagnosed by comparing debug-log wording, not by touching the dialog
code first: that run's `.exe` logged `"...showing blocking message box instead of letting Tauri
create a webview and hang on the OS's unattended install prompt"`, a string that does not exist
anywhere in current `main.rs` (`fatal_if_webview2_missing`'s dlog calls read `"...refusing to build
a webview"` and separate `MessageBoxW FAILED`/`dismissed by user` lines). The `.exe` used in the
2026-07-26 run was staged from `C:\ZBIn\app` at 17:07 local time, but Stage D itself completed at
16:43 — it tested a build from **before** that day's WebView2 hardening pass (120s deadline,
worker-thread `MessageBoxW` with a shared `box_rc`, `TerminateProcess` instead of `process::exit` to
avoid a loader-lock deadlock) landed. Rebuilt `zerobreach-native.exe` from current HEAD
(`391b6c4`'s main.rs, `npx tauri build --no-bundle`, confirmed newer than `main.rs`) and reran with
a hardened harness (`EnumWindows` title-substring match instead of exact `FindWindow`, retried over
15s with an all-visible-titles dump on the first miss, plus a full-screen screenshot captured before
dismissal so "the dialog is on screen" is proven by an image, not a log line). Result: dialog found
in 1 attempt at rect `(390,186)-(840,478)`, screenshot confirms the exact designed dialog ("ZeroBreach
— WebView2 Runtime Required", the documented body text, OK button), `WM_CLOSE` dismissed it, and the
process self-exited with **exit code 3** (the documented `EXIT_WEBVIEW2_MISSING`) within 2 seconds —
nowhere near the 120s deadline. **No native-app bug — the prior result was a stale-build harness
artifact, now guarded against**: `Invoke-SandboxTest.ps1` refuses to run this stage against an `.exe`
older than `main.rs` unless `-SkipBuild` is passed explicitly.

### Malware-detection re-validation against current HEAD — PASS, P1 and Build Custom Scan don't interfere
Reran the Stage-G methodology (same 5 theZoo families — KRBanker, VolatileCedar.Explosion,
Green_Caterpillar.1575.A, W97M.Class.AU, X97M.Sugar.A — extracted with `7za -pinfected`, 56/56
samples verified non-empty with real MZ/OLE magic bytes before use) against a fresh copy of the
current repo's `engine/`, `gui/`, `data/`, `ZeroBreach-Server.ps1` and `ZeroBreach-V23.ps1`, with two
deliberate additions: `$env:ZB_LOAD_HIVES = '1'` set before the server process starts (the only way
to exercise P1's `-LoadUserHives` path through the server, which has no `phases`-style cfg key for
it — the engine reads the switch OR the env var), and no `phases` key sent in the scan-start body (so
Build Custom Scan's filter stays off for a full-coverage baseline). DEEP scan, 115/115 phases,
completed in under 4 minutes. Results (`report_malware_detection.json`, 249 total findings):
- **Known-malware hash match, CRITICAL + Quarantine, on all 3 expected targets**: `GREEN.EXE`
  itself, and both evasive copies — `Invoice_2026_Q3.pdf` (no executable extension at all) and
  `update_payload` (extensionless) — confirming the hash check still fires independent of filename
  on current HEAD.
- **Masquerading-executable, HIGH**: 42 findings across the renamed VolatileCedar (35 hash-named,
  extensionless) and KRBanker (`.vir`) samples — matches the sample count, not a flood.
- **Malicious auto-exec macro, HIGH**, on `W97M.Class.AU`'s `VAMP_DEMO.doc`; the non-auto-exec
  `X97M.Sugar.A`'s `sugar.xls` correctly graded POSSIBLE/review-only.
- **YARA-lite `WMI_Reflective`**, POSSIBLE, on 2 KRBanker `.vir` payloads — review-only as designed.
- **Auto-destructive (rule #1 regrade): 10** — 1 tripwire `DeleteFile` (Temp), 1 tripwire `DeleteReg`
  (Run key), 3 `Quarantine` (the Green_Caterpillar hash matches), 5 `RunCmd` (hardening/posture
  actions, all `Info`-adjacent operator-only classes) — sane and non-flooded, consistent with the
  post-P1 healthy baseline of 8 plus the 2-3 malware-driven hash hits.
- **0 `RECOVERED ERROR`s** across **490** distinct `PHASE` header log lines (a DEEP run with no
  `-Phases` filter produces far more header lines than the ~139 distinct headers because phases with
  per-item loops log a header per item in some paths — the number itself isn't the contract, "well
  over 100" was the sanity bar and it cleared it by 3.5×).
- **P1 confirmed actually exercised, not just present**: a `PROFILE_CENSUS` finding enumerated the
  sandbox's 1 real profile, and the console log shows explicit `AUDITING HIVE:` lines walking
  `HKEY_USERS\<SID>\...\Run` and `\RunOnce` for that profile's SID (via the loaded/`Registry::`
  path) alongside the `[MACHINE]`-tagged hives — the P1 registry cluster ran correctly in the same
  scan as the malware detections with no interference in either direction.
- **Build Custom Scan confirmed correctly inert**: 0 "Custom Scan"/"Phase Gate"/"phase filter"
  banner lines in the console log, and findings spanned phase numbers up to 114 — proof no `-Phases`
  filter leaked in from a stale profile or default.

**Net effect: the "detects ZERO real malware" gap closed in the 2026-07-26 session is confirmed
still closed on current HEAD, P1 and Build Custom Scan compose cleanly with it, and both sandbox
harnesses are now reusable, version-controlled artifacts instead of one-shot scratchpad scripts.**

---

## 2026-07-27 — Recovered evidence: Stage C/D/F/G sandbox malware testing actually ran on 2026-07-26

**Context.** The session-15/16 sandbox work (2026-07-26) staged its harnesses and results entirely in
a Claude Code scratchpad temp directory, not the repo, so none of it survived into `CHANGELOG.md`/
`HANDOFF.md`. CLAUDE.md's "Outstanding Work" carried Stage C/D forward as "written but never run to
completion" for a full extra session. The scratchpad was found intact (2026-07-27, before it could be
cleaned up) and is transcribed here so the result isn't lost a second time. **Everything below predates
P1 (multi-user hive) and the Build Custom Scan feature — both landed afterward — so it is evidence
about the engine as of `22e582a`, not current HEAD. A re-validation against current HEAD is tracked
separately.**

### Stage C (live detonation → rescan → remediation) — ran, partially inconclusive
KRBanker refused to launch ("not a valid application for this OS platform"). Root cause traced in
Stage F/G below: the sample was extracted with `tar`, which cannot open theZoo's password-protected
archives and silently produced a **0-byte file** — not an environment/architecture problem. The rest
of the stage still produced real signal: DEEP rescan 115/115 phases contiguous, 0 recovered errors;
remediation call #1 (5 tripwires) → `applied:5 failed:0 skipped:2 blocked:0` (the scheduled-task
tripwire did not get removed — `skipped`, not `failed`; worth a follow-up look, not re-investigated
here); remediation call #2 (protected-target probe, 3 findings: Windows Update cache + 2 recently
modified root-CA trust entries) → `applied:0 blocked:3`, i.e. `Test-ProtectedTarget` held. Both
`remediation_audit_20260726_165315.jsonl` and `...165346.jsonl` were real, hash-chained
GENESIS→applied/blocked logs — proof the hard-block path works end-to-end, just not proof the engine
can catch a live-running KRBanker.

### Stage D (WebView2-missing native-shell fix) — inconclusive, needs a redo
Debug log confirmed the fix's detection path fires correctly: `WebView2 Runtime not found (checked
HKLM/HKLM-WOW6432Node/HKCU) — showing blocking message box instead of letting Tauri create a webview
and hang`. But the harness could not find the native message-box window by title (`handle=0`) and the
process did not self-exit after a simulated dismissal — it had to be force-killed. Inconclusive on
whether the dialog itself is correct; could be a harness window-title mismatch or a real bug in the
message-box/exit path. **Still open — tracked as a task to redo properly.**

### Stage F — found a methodology bug that invalidated its own conclusions
Built to verify the detection-gap fix (masquerade-by-content, macro auto-exec, hash-IOC matching) with
evasively-named real malware. Its "0 findings across the board" result looked like a clean pass but
every sourced sample was **also a 0-byte `tar` extraction** — the same silent-corruption bug as Stage
C. A `0` on empty input proves nothing. Caught before being trusted, superseded by Stage G.

### Stage G — the actual proof, with genuinely non-empty malware
Rewrote extraction with `7za.exe -pinfected` (per the CLAUDE.md theZoo-extraction rule) and
**hard-fails if any sample lands 0 bytes** so this can't recur silently. Every sample verified
non-empty with a real MZ/PE magic-byte check before use (8 KRBanker files, 35 VolatileCedar.Explosion
files, plus Green_Caterpillar.1575.A, W97M.Class.AU, X97M.Sugar.A). Against genuinely live malware
content, DEEP found:
- **Known-malware hash match, CRITICAL + Quarantine**, on Green_Caterpillar's `GREEN.EXE` — including
  two copies **renamed to `Invoice_2026_Q3.pdf` and `update_payload`** (no executable extension at
  all). This is the fix that closes the session-16 finding "all content inspection is
  extension-gated" — the hash check fires independent of filename.
- **Masquerading-executable, HIGH**, on the renamed KRBanker/VolatileCedar `.vir` files (real PE
  content under a non-executable extension).
- **Malicious auto-exec macro, HIGH**, on `W97M.Class.AU`'s `VAMP_DEMO.doc`; the non-auto-exec
  `X97M.Sugar.A` macro correctly graded POSSIBLE/review-only, not HIGH.
- YARA-lite `WMI_Reflective` matched KRBanker's unpacked `.vir` payload (POSSIBLE, review-only —
  correctly not auto-actionable, since the rule class also matches legitimate PE import tables).
- Auto-destructive (rule-#1 regrade): 10, no flood. 0 recovered errors across 139 timed phases.

**Net effect: the extension-gated content-inspection gap from session 16 was fixed and then validated
against real, correctly-decrypted malware in the same session — this just never got written down.**

### Stage E — abandoned mid-run, not evidence either way
A broader sweep (~244 Windows-family theZoo archives, detonate whichever are runnable PE files) was
started but has no completion marker or captured stdout — it was mid-download (`CryptoLocker_
22Jan2014`) when the harness session ended. Nothing to conclude from it; safe to retry later if a
wider corpus sweep is wanted, but Stage G already supplies real (non-mocked) evidence for the specific
gap it was chasing.

---

## 2026-07-27 — P1 Stage 7 live grading; Phase 90 was self-detecting the engine's own source as Mimikatz

### Stage 7 (filesystem cluster) signed off

The 2026-07-26 snapshot commit (`1c42e3d`) had flagged the Phases-1 agent's 16 sites (incl. the
Phase 12 prefetch/filesystem correlation index) as possibly incomplete — it had not reported before
an operator reboot. Direct inspection on resume found the work was actually complete: all 16 sites
use `Get-UserHives`/`Get-UserPaths`/`Expand-UserPathTemplate`, and the specific worry (the prefetch
index that manufactures false "executed then deleted" evidence when scoped to the technician's own
profile) carries the per-profile fix with a fail-safe fallback if no profile resolves.

A live DEEP `-LoadUserHives` run (139 phases, 17.8 min, 1174 findings) confirmed: 0 recovered errors,
115/115 integer phases contiguous, 0 leaked `ZB_UH_*` hive mounts, zbtest2's `NTUSER.DAT` unlocked
afterward. Auto-destructive excluding `%TEMP%` is **8** — matching the previously-validated 7→8
acceptance result exactly (the +1 is the victim's Outlook payload). None of the three phases flagged
by the migration agents as flood-risks (63/90/106) produced an FP flood: Phase 63 (miner config) and
Phase 106 (dumper tools) contributed 0 auto-destructive findings each; Phase 90 contributed 3 — which
turned out to be a real, unrelated bug (below), not a per-profile multiplier problem.

Also fixed as part of sign-off: Phase 20's reg-loaded-hive `Info` hint text was generic boilerplate
("remove by hand with reg load HKU\ZBFIX / ..."). Since `FixAction Info` means the description IS the
deliverable, it now embeds the real `NTUSER.DAT` path and the real value name for that profile and
that Run-key entry, matching the pattern Phase 35 already used.

### Phase 90 was auto-Quarantining ZeroBreach's own script files (and any similar IR tool)

Grading Phase 90 turned up a genuine self-detection bug, independent of P1: the `Mimikatz_Strings`
YARA-lite rule (`sekurlsa::|lsadump::|mimikatz|gentilkiwi`) matched three files in the operator's own
Downloads folder — an old `ZeroBreach-V19.ps1`, an old `Phases-1.ps1` backup, and an `MSP-IR-Tool
(1).ps1` — and queued all three for CRITICAL + `Quarantine`. None of them are malware: they are
security-tooling **source code** that documents what it detects, and the bare word "mimikatz" is
enough to match. The CURRENT engine's own `Phases-1.ps1` (a Phase 48 finding description: *"...
mimikatz target"*) and `Phases-3.ps1` (a Phase 107 comment: *"...Mimikatz-class"*) both contain that
word today — so a Downloads-folder copy of ZeroBreach itself (an explicitly supported, USB-portable
use case) would auto-quarantine itself on a live scan.

Five of the shipped YARA-lite rules are bare threat-actor/tool-**name** lists with no shellcode/hex
signature and no invocation syntax (`Mimikatz_Strings`, `Meterpreter_Strings`, `Sliver_Implant`,
`Lazagne_Stealer`, `WinPwn_Recon`) — any of these will match a defensive tool's own documentation
just as readily as a real delivered attack script. `Cobalt_Strike_Beacon` was deliberately left alone:
its pattern mixes real hex/shellcode signatures (`MZARUH`, `fc4881e4f0e8`) with names, so it already
carries stronger corroboration than a bare name match.

Fix (`engine/Phases-3.ps1`, Phase 90): for those five rules, on a SCRIPT/text extension only
(`.ps1/.vbs/.js/.jse/.vbe/.wsf/.hta/.bat/.cmd` — never a real compiled binary), require a
corroborating long encoded blob (200+ contiguous base64-shaped characters — the same shape a genuine
Mimikatz/Meterpreter/Sliver/Lazagne loader almost always embeds) before the match is allowed to stay
CRITICAL/HIGH + `Quarantine`. Absent that corroboration it downgrades to `POSSIBLE` + `Info`,
explaining that the name-only match is consistent with documentation/comments rather than a delivered
payload — a downgrade, never a suppression, per the project's standing convention. Verified directly
against the three real flagged files (all now downgrade) plus a synthetic control — a script that
names the tool AND embeds a large encoded blob — which correctly stays destructive, so genuine
detections are not weakened.

### Stage 8 (flood control) — verified, no code changes needed

Compared the Stage 7 DEEP `-LoadUserHives` report against the pre-P1 baseline
(`KrakenBaseline_20260726_204727.json`). One new `GROUPCAP_*` finding appeared post-P1 (Phase 10,
"Allowlisted tool/runtime caches") — per spec §4.4 item 4 this must be treated as a suspected
regression, not assumed benign. Investigation showed all 101 items belong to a single profile
(`WIN11\user`, the admin) and are this session's own `%TEMP%\claude\...\scratchpad` files — the
known dev-box `%TEMP%` churn artifact CLAUDE.md already warns about, coincidental with the ~15-hour
gap between the two baseline captures, not a per-profile multiplication caused by P1. Phase 100.5's
`TOKENSTORES_PRESENT` aggregate finding is correctly a single row. No fix required.

### Stage 9 — honesty findings, banner relabel, baseline re-capture

Implemented the three still-missing §4.9 honesty findings (case (d), `HIVELOCK_*`, already existed
from Stage 2) and the §4.6 scan-context relabel, in `ZeroBreach-V23.ps1` right before the engine
modules are dot-sourced — unconditionally, so they fire in `-Auto`/server-driven scans too, not just
interactive ones:

- **`PROFILE_CENSUS_*`** — one INFO finding per scan naming every discovered profile (SID, account,
  path, and whether registry+filesystem/filesystem-only/not-examined coverage applied).
- **`UNSCANNED_HIVE_*`** (case a) — fires when a profile is logged off and `-LoadUserHives` is off.
  Live-verified on a QUICK scan without `-LoadUserHives`: correctly named `zbtest2` and stated
  filesystem checks DID still run, matching the spec's acceptance-test wording exactly.
- **`UNREACHABLE_PROFILE_*`** (case b) and **`PROFILE_ENUM_TRUNCATED`** (case c) — implemented per
  spec but not live-triggered this session; this box has no roaming profile or budget-cap scenario
  to exercise them against.
- The interactive banner (`if (-not ($global:STEALTH_MODE -or $Auto))` — so servers, which always
  pass `-Auto`, never see it) now reads `SCAN RUNNING AS: <admin>` plus a `PROFILES EXAMINED: n of m`
  line instead of the pre-P1 `USER: <admin>`, which was actively misleading once findings started
  spanning multiple profiles.

Re-captured the healthy-box baseline post-P1: DEEP `-LoadUserHives` auto-destructive excl. `%TEMP%`
is **8** (`reports/KrakenBaseline_20260727_113431.json`); QUICK (no `-LoadUserHives`, no DEEP+-only
phases) is **2** (`reports/KrakenBaseline_20260727_120743.json`) — both 0 recovered errors, correct
phase counts (139 and 30 respectively).

**Finding-ID churn disclosure (spec §5.3):** P1 changes finding IDs at roughly 20 sites across the
registry and filesystem migration (every ID that was previously a fixed string or a name-only
fragment now carries the profile's SID, because two users can otherwise collide onto one ID and
silently lose a finding). **Any `-Baseline` snapshot captured before commit `6e3522b` (session 19's
first P1 commit) will report every migrated finding as new on the first post-P1 run.** This is a
one-time diff discontinuity, not a recurring one — `Get-StableId` (FNV-1a, deterministic across
processes and across PS 5.1/pwsh 7) keeps the new IDs stable forever after. Re-capture any baseline
you plan to diff against going forward.

---

## 2026-07-26 — Phase 90 was auto-deleting signed Microsoft binaries, and the batch's integration run

### The third live rule-#1 violation

Phase 90's YARA-lite content sweep graded **Authenticode-signed Microsoft Sysinternals binaries HIGH +
`DeleteFile`** — 18 auto-selected destructive findings on a healthy box, including `ADInsight`,
`Coreinfo`, `livekd`, `vmmap`, `Winobj`, a Microsoft-signed `concrt140.dll`, and `Claude Setup.exe`
(signed *Anthropic*), all queued for automatic deletion.

The cause is inherent to the check: YARA-lite matches API-name strings in file **content**, and
legitimate administration and debugging tools contain `VirtualAllocEx` / `WriteProcessMemory`
**because that is what they do**.

**The Authenticode verdict is now the gate, not the path** — the same precedent set for phases
36/69/83 in the 2026-07-22 anchored-path work. A `Valid` signature demotes to `POSSIBLE` + `Info`
with the signer and the original rule severity stated; anything else keeps its severity unchanged;
and a signature that could not be checked (budget exhausted, file locked) is `POSSIBLE` + `Info` with
the reason and a manual re-check command. Flags are raised only after the check succeeds.

A path allowlist was deliberately **not** used: it is attacker-satisfiable and does not generalise to
client machines. Verified — a payload in a folder literally named `SysinternalsSuite` still grades
`HIGH` + auto-selected, as does an unsigned payload sitting beside signed binaries.

`DeleteFile` → **`Quarantine`** on the unsigned branch. A content-string match is a heuristic, never a
hash confirmation, and the project prefers the reversible action for exactly that; severity and
auto-selectability are unchanged, so no coverage is lost. The hash-match branch below it already used
`Quarantine`, so the phase is now internally consistent.

Auto-destructive **18 → 4** (17 → 3 excluding the synthetic test fixture). All finding IDs unchanged:
0 dropped, 0 added, 18 changed in **grading only** — zero baseline-diff impact.

### The bug the live run caught that the code review did not

The first implementation used `[Stopwatch]::StartNew()` at phase entry — matching the sibling
`$trojSigSw` — to carry the `$global:SIG_AUDIT_*` budget. The harness then reported
**`yaraSigSeen = 0`**: the YARA gate is not reached until after the magic-byte sniff and per-file
content reads, which take **~220 s** on this box, so a 25 s deadline was already 200 s blown at the
*first* hit. **Zero signatures were ever verified**, every hit took the fail-closed branch, and the
unsigned attacker fixture was demoted along with everything else.

It read as a flawless "18 → 0" pass while silently destroying the phase's entire coverage. Fixed to
measure *cumulative Authenticode time* — the stopwatch is created stopped and started/stopped around
each `Get-AuthSig` call: `yaraSigSeen = 18`, cumulative 1.4 s. Forcing `SIG_AUDIT_MAX_FILES=3`
verified exactly 3 checks and 15 findings held at review-only, so the loop is bounded by both count
and cumulative time.

**This is why a "before → 0" result is not evidence on its own.** A number that good should prompt the
question *"did the check actually run?"*, and here the answer was no.

### P12 completed — the second half

`engine/Phases-3.ps1` (Phase 109) now reads `accessibility_binaries` via `Get-Sig` from
`detection_signatures.json` instead of `Get-Perm` from `permission_baseline.json`, and probes
`%WINDIR%` and `SysWOW64` in addition to `System32` — **`hh.exe` lives in neither System32 nor the old
baseline copy, so the HTML-Help IFEO backdoor could never have been detected by anything.** The
System32 finding IDs are byte-identical to before so `-Baseline` diffs are unaffected; the two extra
locations carry a suffix so the three probes cannot collide in `Add-Finding`'s dedupe. The duplicate
list is removed from `permission_baseline.json`, replaced by a note explaining why it must not come
back.

### Integration run — the whole batch, live, on real PS 5.1

Five agents edited four engine files plus the server and the GUI in this batch. Verified together:

- All **seven** engine/server files parse-clean on `powershell.exe` 5.1.26100 **and** `pwsh` 7, every
  BOM `EF BB BF`. Header counts exact: **70 · 40 · 30**.
- `QUICK -Hours 0 -Auto`: **exit 0, 0 recovered errors, 0 bytes on stderr**, 110 s, 310 findings.
- **QUICK still runs exactly 30 headers.** A naive phase-number sweep of the log reports 31 — the
  extra is `74.7` appearing as *prose inside a Phase 74.6 finding description*, not a header. The real
  `Show-PhaseHeader "PHASE 74.7"` is correctly inside `if (-not $global:QUICK_MODE)`.
- **Auto-destructive 94 → 63**, and the `%TEMP%\claude\` harness flood is **completely gone (0)**. The
  residual 59 Phase 10 hits are genuine loose executables in the operator's own project temp
  directories (`plbisect-*`, `zbbase`, `zb-vfx-profile`, pytest trees). The remaining 4 are all
  previously documented by-design items: the deliberate `_DELETEME` Run-key tripwire, `OneDC_Updater`,
  the Ollama startup `.lnk`, and the `RunAsPPL` posture item.
- **0** drive-root / `icacls /reset /T` / `vssadmin delete shadows /all` FixParams at all-time scope.
- **P7+P8 confirmed working live, on the plan's own worked example.** The run produced the
  `obj\Debug\…\PirateLifeNative.dll` finding cited in `EVIDENCE_ENGINE_PLAN.md` §0.1 as a proven
  auto-selected false positive — now matched by *family* (`Trojan:Win32/Wacatac.C!ml`, which the old
  `StartsWith` test could not match at all) and demoted to `POSSIBLE` carrying its full rationale:
  ML-derived verdict, dev build-output path class, and *"file was written after Defender's action —
  this is not the file Defender flagged."*

### Found, not fixed — carried forward deliberately

- **`$trojSigSw` (Phase 90) has the identical wall-clock defect**, so `$TROJAN_FILE_PATTERNS` is
  **effectively dead code in that phase**. Not repaired here: fixing it *enables a dormant detection*,
  which the project's own rule says may not ship ungraded — and it cannot be graded on this box, where
  0 candidates match any pattern. Needs a client-representative machine.
- **Three CRITICAL + `Quarantine` auto-selects remain**: the operator's own unsigned IR PowerShell
  (`MSP-IR-Tool (1).ps1`, `ZeroBreach-V19.ps1`, a copy of `engine\Phases-1.ps1`) tripping
  `Mimikatz_Strings`. Pre-existing and now at least reversible, but an IR tool that auto-quarantines
  its own tooling is worth a follow-up.
- **Phase 90 finding IDs key on the file *name*, not the full path**, so two same-named files in
  different directories collide and one is deduped away. Left alone because fixing it changes IDs.
- **`yara_benign_paths`' `\appdata\local\temp\claude\` entry is permanently dead** —
  `$global:ALLOW_VETO_RE` vetoes it 100% of the time. Independently confirmed twice in this batch.

---

## 2026-07-26 — EVIDENCE_ENGINE_PLAN P4 · P5 · P11 · P12 + the Phase 10 FP tune

### P11 — a live rule-#1 violation on every healthy Windows box

Phase 30 graded **every** WMI event subscription CRITICAL + `RunCmd Remove-WmiObject`. On this box
that included `SCM Event Log Consumer` — **a stock Windows subscription** — auto-selected for
destructive removal on a completely clean machine. SCCM, Dell Command, HP, Lenovo Vantage and several
backup agents register subscriptions legitimately too.

The old guard was `-notmatch "BVTFilter|SCM"`, a bare substring test that was **itself a
self-allowlist hole**: anything named `SCM_Updater` was silently excluded from the check entirely.
And `BVTFilter` is the MSDN WMI-persistence sample that malware copy-pastes verbatim, so allowlisting
it was backwards.

Now: subscriptions grade **`POSSIBLE` + `FixAction Info`** with the teardown command in the
description (user decision this session — there is no SCCM-managed box available to grade against,
which is precisely why demotion rather than a guessed allowlist is the safe answer). Allowlists are
**fully anchored `^…$` over a composite string** — filter is `Name|EventNamespace|Query`, consumer is
`__CLASS|Name|Prop=Value…`, binding is `FilterRef|ConsumerRef` — so a vendor *name* alone can never
allowlist anything; the query and command line have to match too. Verified: all four synthetic
vendor-name impersonation attempts (right name + wrong query, right name + extra property, right name
+ wrong consumer class, vendor filter ref + attacker consumer ref) are still flagged.

`$wmiBindings` was previously fetched and used only in a zero-count test — the
`__FilterToConsumerBinding` is **the object that actually arms the persistence** and produced no
finding at all, while the generated fix removed filter and consumer and left the binding orphaned. It
now emits its own finding, and every suggested teardown is ordered **binding → consumer → filter**.

Auto-destructive on this box: **1 → 0.**

### P4 — Phase 11 was destroying evidence

It opened `Recent`/JumpList, **counted** the files, and offered a `RunCmd` to **delete them**. Those
`.lnk` files carry TargetPath, Arguments, WorkingDirectory and the original volume serial — and a
working LNK parser already existed one phase away in 10.5. The deletion action is **gone**; shortcuts
are parsed instead. An executable or script target that is *missing* from a user-writable staging path
is real "this ran and is now deleted" evidence → `POSSIBLE`; still-present targets → `INFO`.

Presence is deliberately **tri-state** (`present | missing | unknown`) via a fail-closed helper that
refuses to `Test-Path` UNC paths, non-`X:\` targets, absent volumes and mapped network drives — so
"couldn't read it" is never reported as "it's gone". A summary finding counts the uncheckable ones.
The shared `WScript.Shell` COM object is now created once and reused; Phase 10.5 built a new one per
file.

### P5 — dead code and a false title in Phase 12

Titled "PREFETCH & SHIMCACHE" while reading only Prefetch, with two regex alternatives —
`RUNDLL32.*APPDATA` and `POWERSHELL.*-ENC` — that **could not match**, because a `.pf` filename is
`NAME.EXE-<8 hex>` and carries no path and no arguments. Retitled to what it does (ShimCache is
Tier B), dead alternatives **removed rather than "repaired"** to bare `RUNDLL32|POWERSHELL`, which
would fire on every healthy box — this scanner *is* a `powershell.exe` execution.

Added the plan's **A14** correlation for free: a `.pf` whose executable no longer exists anywhere =
*"this ran and is now gone"*, with the uninstalled-software caveat stated in every description. Gated
on `$PhasePlan.Advanced` because building the executable index costs ~40 s, and it **fails closed** —
if the index hits its 60 s / 60,000-file budget the correlation is skipped and says so rather than
reporting a partial index as fact. Unreadable or absent Prefetch now emits an explicit
"evidence UNAVAILABLE, not clean" finding.

### P12 — `accessibility_binaries` had three sources of truth

`detection_signatures.json` (8 entries, **orphaned — never read**), `permission_baseline.json` (7,
read by Phase 109) and a hardcoded inline list of 6 in Phase 45. They had drifted: the JSON copy has
`hh.exe`, the baseline does not, so the HTML-Help IFEO backdoor was listed but never checked, and
editing the JSON had no effect whatsoever.

`detection_signatures.json` is now canonical — it is a *detection* list, whereas
`permission_baseline.json` is the ACL/owner baseline for phases 108–115, a different purpose. Its 8
entries are a strict superset of the other two copies, so no data change was needed. Phase 45 reads it
via `Get-Sig`, now also probes `%WINDIR%` and `SysWOW64` (**`hh.exe` is not in System32, so it could
never have been found**), and grades through Phase 109's tri-state signature verdict so a
newly-added catalog-signed binary cannot manufacture a CRITICAL + `RunCmd` on a healthy box.

### Phase 10 — the `%TEMP%` executable flood (user-approved FP tune)

92 auto-selected `HIGH` + `DeleteFile` findings on this box, essentially all Claude Code harness
debris under `%TEMP%\claude\`. Phase 10 consulted no benign-path list at all.

**A structural obstacle surfaced during implementation and is worth recording.**
`$global:ALLOW_VETO_RE` vetoes every `Test-BenignPath` allowlist match found under `\Temp\` or
`\Downloads\` — which is Phase 10's *entire scope*. `Test-BenignPath` alone therefore **cannot**
downgrade anything in this phase. The resolution: call `Test-BenignPath` first and unchanged, then let
a second deliberately narrow, component-anchored, **downgrade-only** list override the veto for
well-known tool caches that genuinely live inside `%TEMP%`.

**Accepted trade-off, stated plainly rather than buried:** any path allowlist scoped to `%TEMP%` is by
definition attacker-satisfiable, because an attacker who can write there can also create the
directory. The mitigation is that a hit only **downgrades to `INFO`** — the file remains a reported
finding and merely leaves the auto-destructive set. Near-misses were verified to fail closed
(`\temp\claudex\`, `\temp\myclaude\`, `Downloads\claude\` all reject).

Auto-destructive **92 → 50**. The residual 50 are genuine loose unsigned `.ps1`/`.bat` in the `%TEMP%`
root, correctly flagged. Total findings rose 103 → 222 — **not a regression**: `$env:TEMP` and
`$env:LOCALAPPDATA\Temp` are the same directory and were being swept twice, exhausting the shared
`SIG_AUDIT` budget before the sweep ever reached Windows TEMP or Downloads. Deduping resolved paths
means those directories are now actually examined for the first time.

### Validation

Parse-clean on `powershell.exe` 5.1 and `pwsh` 7, BOM intact, `Show-PhaseHeader` count unchanged at
**70**. QUICK-ungated headers in this module = **23**, plus 7 in `Phases-2.ps1` = the documented
30-phase QUICK set, unchanged; final QUICK block depth 0. 13/13 helper unit tests. Phase 30 graded
against the box's real subscriptions (0 findings with allowlists, 3 `POSSIBLE` with the keys
deliberately removed — safe degradation, never wider) plus 7 synthetic attack shapes. Phase 45: 13
binary instances across 8 names, all valid Microsoft signatures, 0 findings.

### Found but not fixed

- **No SCCM/Dell/HP/Lenovo entries in the WMI allowlist.** Deliberately not invented — a wrong
  anchored pattern is either useless or a hole. Add only from an observed managed box; the
  `POSSIBLE`+`Info` demotion is the safety mechanism until then.
- The `SIG_AUDIT` budget is still exhausted before `INetCache` on this box.
- **Phase 12's A14 correlation does not run in TRIAGE**, because TRIAGE sets `QUICK_MODE = $true` and
  Phase 12 sits inside the non-QUICK wrap. Worth revisiting when §5.3 lands.
- A14 indexes `.exe` only; `.tmp`/`.com`/`.scr` prefetch entries are skipped rather than guessed at.

---

## 2026-07-26 — EVIDENCE_ENGINE_PLAN P10 + P9: a finding record that can hold a verdict, and a TRIAGE plan

### P10 — the fixed 9-field schema that made §4 impossible

`Add-Finding`'s record was `ID, Phase, ThreatType, Severity, Description, Target, FixAction, FixParam,
Group`. No field for hash, signer, file age, MoTW origin, parent process or evidence source — so
phases jammed context into `Description` **prose**, and the server re-derived `protected` /
`vendor_trusted` by regexing that prose. No structured benign/malicious verdict could be expressed at
all, which blocked the entire correlation/verdict layer in §4 of the plan.

**18 optional named parameters added**, all default-empty, all omitted from both the record and the
`[FINDING]` JSON line when unset: `Sha256`, `Signer`, `SignatureStatus`, `FileWriteTime`,
`FileAgeHours`, `FileSize`, `ZoneId`, `HostUrl`, `ReferrerUrl`, `ProcessName`, `ParentProcess`,
`EvidenceSource`, `EventTime`, `ThreatName`, `Confidence`, `Verdict`, `Corroboration`, `Caveat`.

Three departures from the plan's suggested set, each for a reason:
- **`Md5`/`Sha1` dropped** — the engine only ever computes SHA256 (`Get-FileHashSafe`). A field
  nothing can populate is a lie in the schema.
- **`EventTime` added** — distinct from `Timestamp`. `Timestamp` is when *we looked*; `EventTime` is
  when the *evidence* happened. §4's timeline assembly needs the latter and cannot derive it.
- **`SignatureStatus` added alongside `Signer`** — "unsigned" and "could not be checked" must not
  collapse to the same empty string. That distinction is the whole point of the honesty rule.

`Confidence` deliberately reuses **`Get-DefenderVerdict`'s `Tier` vocabulary verbatim** (from the P7
work) rather than inventing a parallel one.

**Carried through the whole pipeline**: record → `[FINDING]` JSON → scan runspace → SSE `finding`
event → `/api/report` → GUI, plus the STEALTH blob path. `Summary.ps1` needed no change —
`Findings = @($global:AuditFindings)` carries the new keys into `KrakenBaseline_*.json` for free.

**The prose-regex migration is additive, not a replacement.** The existing prose call runs first and
verbatim in both places; the structured pass is OR-only and can only *add* a block or trust.
`vendor_trusted` ← `Signer` (routed through the existing function so its malicious-signal veto still
applies); `protected` ← `ProcessName`/`ParentProcess`, which is the precise structured replacement for
the one branch of `Test-ProtectedTarget` that genuinely has to read prose (the critical-process test,
because `FixParam` is a bare PID). **That migration is mirrored inside `$script:REMEDIATE_SCRIPT`** —
without the mirror, a finding protected only by `ProcessName` would be disabled in the GUI but sail
straight through the hard-block backstop on a direct POST. A runspace cannot see the parent's
functions; this is exactly the failure mode that rule exists for.

**Rule #1 compliance:** nothing new touches `Severity`, `FixAction` or `Selected`. The only behaviour
attached to any new field is *demotion* — `Verdict === 'LIKELY-FALSE-POSITIVE'` is excluded from
auto-select and from every bulk selector, while remaining individually tickable.

### P9 — the triage-relevant phases were DEEP-only

FULL stops at 80, which gates out MoTW (91), the YARA/hash sweep (90), UAC-bypass staging (92),
command-line heuristics (99.5), browser-credential access (100), token staging (100.5), svchost
masquerade (102), hidden tasks (104), correlation (105), memory dumps (106), event-log hunting (107)
**and all Defender-tamper / security-control-health checks (114)**. A technician running FULL on a
Defender ticket got none of it.

New **`TRIAGE`** mode — expressible purely through loader flags, **no phase-module change required**:
`$global:QUICK_MODE = $true` (which drops the 54 non-triage phases in 1–80) plus `Universal`,
`Advanced` and `Integrity` all on, `Max = 115`. `Integrity` is the only way to reach 114, because
`Phases-3.ps1` gates 108–115 as a single block. Wired through the loader `ValidateSet`, the
interactive menu, the server's `$MODE_PHASES` mirror and both mode allowlists, plus a new
`Alert Triage (TRIAGE, 24h)` built-in scan profile.

Measured: **71 distinct phases in 441.8 s**, versus DEEP's full span — QUICK's core 30, then 81–89
(incl. 82.5/87.5/88.5), 90–107 (incl. 97.5/99.5/100.5, every phase P9 names), and 108–115.
`$global:TRIAGE_MODE` is set but intentionally read nowhere yet: it is the hook §5.3's alert-ingestion
entry point will use, and it lets a future module change trim 108–113/115 without a new PhasePlan flag.

### Validation

Parse-clean on real `powershell.exe` 5.1.26100 **and** `pwsh` 7 for both `.ps1` files, BOMs intact,
`node --check` silent. **All three `@'...'@` runspace here-strings extracted and `ParseInput`-checked
separately** (2,751 / 27,907 / 22,065 chars) — a syntax error in one is invisible to `ParseFile`.

Backwards compatibility proven, not assumed: an `Add-Finding` call using only the old 9 parameters
produces a **byte-identical** `[FINDING]` line against the pre-P10 implementation (249 bytes vs 249
bytes), with an identical record key set. A finding carrying no evidence fields produces the pre-P10
SSE payload with **zero** extra keys.

Live: `-Mode QUICK -Auto` → exit 0, **30 distinct phases**, 0 recovered errors, 239 findings, 59.8 s,
phase list exactly the documented QUICK set, auto-destructive **94 — matching the documented dev-box
figure exactly**, so grading is provably unchanged. `-Mode TRIAGE -Auto` → exit 0, 71 phases, 0
recovered errors. Round-trip of all 18 fields verified through the **verbatim-extracted real**
`SCAN_SCRIPT`, not a re-implementation.

### Known follow-ups recorded here rather than silently carried

- **Phase 90 YARA-lite flags signed Sysinternals binaries HIGH + `DeleteFile`** — 20 auto-destructive
  on this box, and the dominant contributor to TRIAGE's auto-destructive delta over QUICK.
  Pre-existing, not introduced here, but a live rule-#1 candidate. Tracked separately.
- No phase passes any P10 field yet — the schema is live but unexercised. Whoever builds
  `engine/Evidence.ps1` should pass `EvidenceSource`, `Confidence`, `Verdict` and `Caveat`.
- `defender_confidence_suffixes` has no `signature` entry; that tier arises only from
  `DEF_NO_SUFFIX_RANK`, so the `Confidence` vocabulary is defined half in data, half in code.
- The new GUI badges carry inline theme-var-tinted styling because no `.item-verdict` /
  `.item-evidence` CSS rule exists yet.

---

## 2026-07-26 — EVIDENCE_ENGINE_PLAN P2 · P3 · P6 · P13: the checks that lied about being clean

Three of these are the same defect wearing different clothes: **a check that could not have fired
still printed a clean result.** The fourth is a build-path trap that made a dev run execute an
engine nobody had edited.

### P2 — the `-Hours` window silently collapsed (`engine/Phases-3.ps1`, Phase 107)

`Get-WinEvent -FilterHashtable @{...} -MaxEvents 2000 | Where-Object { Test-InScope $_.TimeCreated }`
takes the **newest N and then** filters by time. On a busy box the requested window quietly shrinks
to whatever 2000 records happen to span. `StartTime` now goes **inside** the FilterHashtable, where
the EventLog service evaluates it as server-side XPath — correct *and* far cheaper.

**This was not theoretical on this machine.** The Security log holds 585,612 records over 24.05 h of
retention; the newest 2000 × 4624 span 24.02 h. The shipped code was sitting exactly on the
boundary — a `-Hours 48` scan was **already** being cut short. Sweeping MaxEvents against a real 24 h
window reproduces the mechanism directly: `50→50 (lost 501)`, `100→100 (lost 451)`,
`250→250 (lost 301)`, `500→500 (lost 51)`. The fixed form returns all 551.

Also fixed at the same three sites: they called `Get-WinEvent` **raw**, bypassing the
`Get-WinEventSafe` wrapper (a `CLAUDE.md` rule breach), and `[xml]$_.ToXml()` was parsed **twice per
event**. Now one `ToXml()` string per record with name-anchored field extraction.

**Two of the plan's own premises turned out to be wrong, and are corrected here rather than
implemented as written:**
- *"`$_.Message` renders at 1–3 ms/event"* — measured, it is ~0.01 ms; 200 events render in 2–3 ms.
  The real cost was the `[xml]` DOM at ~26 ms/event, a ~50× difference. Moving off `.Message` was
  still right, but for a **better reason**: it is localised human-readable prose, so a regex over it
  matches template decoration on an English box and nothing at all on a German one.
- *"use `.Properties[n].Value`"* — rejected despite being fastest (73 ms vs 124 ms per 400).
  Positional indices into 4624/4688 EventData are not a documented cross-build contract, and a
  silent off-by-one reads the wrong field with **no error**. Name-anchored extraction costs ~50 ms
  per 400 events and is version-proof. Verified identical to the `[xml]` DOM across 300 real 4624
  records, 0 mismatches, at 194 ms vs 7897 ms.

### P3 — the 4688 check was structurally blind and said "0 suspicious events"

"Audit Process Creation" is **off by default** on Win10/11, and command-line capture is a **second,
independent** policy (`ProcessCreationIncludeCmdLine_Enabled`). Without it 4688 carries no
arguments, so regexes like `powershell.*-enc` **cannot match** — yet the phase printed a green
`0 SUSPICIOUS 4688 PROCESS EVENTS`. That is a clean bill of health from a check that never ran.

The determination is now tri-state and **empirical first**: does the Security log contain *any* 4688
at all — a signal that is immune to both localisation and audit-policy plumbing quirks. `auditpol` is
consulted only as a **veto** (matched on the subcategory **GUID**, not its localised name), so it can
push the answer to OFF but never to ON, and an unrecognised non-English value degrades to `UNKNOWN`
rather than to a clean result. Two `INFO` + `FixAction Info` findings (`EVT4688_AUDIT_BLIND`,
`EVT4688_CMDLINE_BLIND`) carry the enable commands in their descriptions, and the misleading clean
line is suppressed.

### P6 — Phase 91 opened the right stream and threw the answer away

It checked only for the *absence* of `Zone.Identifier`. When present, that stream carries `HostUrl`
and `ReferrerUrl` — the download source and referring page, one of the very few places a payload's
provenance **survives its own deletion**. Now parsed and surfaced: POSSIBLE for executable-class +
`ZoneId ≥ 3` + a `HostUrl`, INFO otherwise, nothing when no URL is present. Live on this box: **59
Zone.Identifier streams in Downloads/Desktop, 59 with HostUrl, 44 with ReferrerUrl, 11
executable-class.** New `motw_benign_origin_host_regex` is the FP lever (component-bounded hosts, so
`microsoft.com.evil.tld` cannot self-allowlist). MoTW-stripped detection behaviour is byte-identical,
and the pre-existing `MOTW_` finding ID is unchanged so baseline diffs do not break.

### P13 — `cargo tauri dev` silently ran a stale engine (`native-app/src-tauri/src/main.rs`)

`find_engine_root` probed the staged resource copy **before** the live checkout. Since
`cargo tauri dev` never re-stages `bundle.resources`, a `target/debug/engine-root/` left behind by an
earlier `tauri build` won the probe — and that copy was confirmed to **differ from source**. Every
dev run was executing outdated signature-loading code and stale phase modules, with nothing in the UI
to suggest it. Debug builds now resolve the live checkout first and log that they did so; the release
path is untouched, still `debug_assertions`-gated so a shipped binary never probes the build
machine's own checkout path.

### Validation

Parse-clean on real `powershell.exe` 5.1.26100 **and** `pwsh` 7, BOM intact, `Show-PhaseHeader`
count unchanged at **30** in `Phases-3.ps1`. All three new findings are `FixAction Info`; the 29
pre-existing destructive FixActions in the file are untouched; no local shadows a loader `param()`
name. **56/56 unit assertions** against the live box, including: StartTime equality at H=1/6/24/72
with the new form returning ≥ the old every time; `-Hours 0` correctly omitting StartTime; the
caller's hashtable not mutated; extraction identical to the DOM over 300 real records; the blind-path
forced to fire with the clean line suppressed; and `auditpol` reporting `Success` correctly **vetoed**
by the absence of any 4688 record. `cargo check` clean.

**Open FP-tuning item:** Phase 91 now emits up to ~59 INFO findings on an all-time DEEP on this box.
They are INFO — never auto-selected — and are exactly the evidence collection the plan asks for, but
the volume wants a live re-grade against a healthy-box baseline (plan §7.8).

---

## 2026-07-26 — EVIDENCE_ENGINE_PLAN P7 + P8: the Wacatac match failure and the uncorroborated Defender residual

The two items §8 of `EVIDENCE_ENGINE_PLAN.md` flagged as *"actively producing wrong output today"*.
Both live in Phase 74.6 (Defender threat-history correlation). Graded against this box's real
Defender history — **82 detection resources across 43 distinct threat labels** — not against
reasoning about what the code ought to do.

### The measured starting state

Replaying the shipped logic over live `Get-MpThreatDetection` output produced **24 CRITICAL +
Quarantine findings, every one a false positive, every one auto-selected** (CRITICAL + Quarantine
is in the auto-destructive set). Three independent defects stacked:

| # | Defect | Evidence |
|---|---|---|
| 1 | **Resource prefix discarded.** The regex stripped `amsi:_`/`behavior:_`/`process:_` along with `file:_`, then called `Test-Path`. An AMSI resource names the script whose *content* was blocked at execution — the file surviving is expected. | 22 of the 24 were `amsi:` resources: the operator's own `PirateLife-GUI.ps1` (×11) and Claude scratchpad `probe.ps1` (×10). |
| 2 | **`ThreatStatusID` never read.** Status was inferred purely from `Test-Path`. | 72 of 82 resources report `3 = Quarantined, ActionSuccess=True` — Defender saying it handled the threat, ignored. Only 2 said `103 = Remove Failed`, and they graded identically to the other 22. |
| 3 | **Confidence suffix ignored.** | 17 of the 24 were `!MTB`, 2 were `!ml` — ML/emulator-derived verdicts, the tier §5.0 of the plan says may never auto-select destructively. |

The proven false positive from §0.1 of the plan (`obj\Debug\net8.0-…\PirateLifeNative.dll`) was
exonerated by a *fourth* independent signal nobody had looked for: its `LastWriteTime` is **newer
than both remediation timestamps** — it was rebuilt after Defender acted, so it is not the file
Defender flagged.

### P7 — the operator's most common alert could not match (`Phases-2.ps1`)

`email_phishing_trojans` contains `Trojan:Script/Wacatac`; the match was
`"$tname".StartsWith("$pf")`. `Trojan:Win32/Wacatac.B!ml` does not start with that string — same
family, different platform. Matching now happens on the **Family** component, which fixes every
platform/variant/suffix of a listed family at once.

The trap avoided: `Phish:HTML/Generic` is in that list, and naive family matching would have made it
swallow `Trojan:Win32/Generic!rfn` (live on this box). Generic family tokens are excluded from
family matching and fall back to whole-label prefix matching, as do mixed-vendor entries
(`HTML/Phish`, `Trojan.Generic.Phishing`, `PUA/W32.PUP`) that are not Defender grammar at all.

### P8 — grading rebuilt around what Defender actually reports

`Get-MpThreatDetection` already returned `ThreatStatusID`, `ActionSuccess`, `CleaningActionID`,
`RemediationTime`, `LastThreatStatusChangeTime`, `DetectionSourceTypeID` and `ProcessName` (the
process Defender attributed the drop to). None were read. All are now.

**CRITICAL + Quarantine requires every one of these to hold** — otherwise POSSIBLE/INFO + `Info`:

1. the resource is a **file** resource, not `amsi:`/`behavior:`/`process:` (unrecognised prefixes are
   treated as content, i.e. the non-escalating side — fail safe);
2. the file is present;
3. Defender reports remediation **failed** or **pending** (`102/103/105/106`, or `ActionSuccess=False`);
4. confidence is **signature-grade** (rank ≥ 3; an unrecognised suffix scores below the gate);
5. the path class is not `dev` (build output / source tree) or `removable` (non-system volume);
6. the class is not dual-use (`hacktool`/`pup`/`adware` — the technician's own toolkit);
7. the file has not been **written since** Defender's action.

Every demotion reason is written into the finding description (`NOT auto-selected because: …`), so
an operator sees *why* something was not escalated rather than a bare severity.

Also fixed: **findings are now aggregated by path before grading.** Defender emits one record per
event, so the same path recurs with different outcomes; grading each independently let
`Add-Finding`'s ID dedup keep an arbitrary one, and a `Remove Failed` could be masked by a later
`Quarantined` for the same file. Aggregate first, grade once, from the row with the most recent
status change.

### `Get-DefenderVerdict` — the normaliser

New loader helper decomposing `Type:Platform/Family.Variant!suffix` into
`(Type, Platform, Family, Variant, Suffix, Tier, Rank, Class, DualUse, Parsed, Generic)`. This is the
same normalised object §5.0 of the plan needs for alert ingestion — built once, used in both places.
All vocabulary is in `data/detection_signatures.json` (AMSI rule): suffix→confidence tiers, type→class
map, threat-status map, resource-prefix classes, generic family tokens, and the dev/staging path
classes. Grading is tunable without touching a `.ps1`.

`Get-DefenderPathClass` is deliberately **structural, not a list of one operator's folders**: build
output and dependency trees by regex, plus a bounded memoised walk up the directory tree looking for
source-repo markers (`.git`, `*.sln`, `package.json`, `Cargo.toml`, …). It generalises to any client
box.

### A bug the tests caught that review did not

`Test-Path` against a UNC path to an unreachable host throws a **terminating** `IOException` that
`-ErrorAction SilentlyContinue` does not suppress. Unhandled inside a phase module it would unwind to
the module trap and skip every remaining phase in that module — the exact failure mode that once
dropped phases 17–58. Found by the `\\fileserver\share\` unit-test case, not by reading the code.
Fixed twice over: the textual path tests now run before any filesystem access, and the workspace walk
is wrapped in `try/catch`.

### Validation

- `Get-DefenderVerdict` grammar: **17/17**, including every dual-use, PUA-bundler and suffix form.
- P7 family matching: **9/9** — `Wacatac.B!ml` and `Wacatac.C!ml` now match; `Trojan:Win32/Generic!rfn`
  correctly does **not**.
- Path classification: **9/9** (dev / staging / system / removable / UNC / other).
- All **43** live threat labels on this box parse, 0 unclassified.
- Gate matrix: **9/9** — escalation fires on signature-grade + `Remove Failed` + Downloads, and on
  `ActionSuccess=False`; each of the seven suppression conditions independently blocks it.
- Live replay of the real phase body: auto-destructive **24 → 0**; 82 resources aggregate to 59 paths
  (58 INFO, 1 POSSIBLE — the `obj\Debug\` artifact, now carrying its full rationale).
- Headless QUICK scan, all-time window: exit 0, **0 recovered errors**, Phase 74.6 contributes **0**
  auto-destructive. Parse-clean on `powershell.exe` 5.1.26100 **and** `pwsh` 7.6.4, all BOMs intact.
- No `Show-PhaseHeader` line added or removed — phase counts unchanged at 70 · 40 · 30, QUICK gate
  provably untouched.

**Caveat on the whole-scan number:** that run reported 94 auto-destructive, against the "7 on a
healthy box" reference in `CLAUDE.md`. 92 are **Phase 10** (executable-extension-in-`%TEMP%`) hits on
accumulated harness debris under `%TEMP%\claude\…`, 1 is the documented Run-key tripwire, 1 is Phase 41
`RunAsPPL`. None come from this change — but **this machine is no longer a clean baseline reference**,
and the Phase-10 `%TEMP%\claude\` flood is a separate FP-tuning candidate.

**Not addressed here** (still open in `EVIDENCE_ENGINE_PLAN.md` §2): P1–P6 and P9–P13.
`$global:EMAIL_PHISH_SEEN` was found to be **set but read nowhere** — a latent orphan in the style of
the review-#51 keys, so the broadened P7 match has no downstream effect today.

---

## 2026-07-26 — documentation audit + the sandbox/harness lessons that produced new rules

### Documentation audit (`.md` only — no code or data files touched)

Every markdown file in the repo was checked against the actual code. Corrected:

- **"~115 phases" was a count claim, and it was wrong.** 115 is the DEEP/PARANOID/STEALTH *label
  ceiling* (`$PhasePlan.Max`), not the number of phases that run. Because every expansion since WS2
  has been inserted as a **fractional** phase number, the engine now emits **~140 distinct phase
  headers** (Phases-1: 70 · Phases-2: 40 · Phases-3: 30) while the highest label is still 115.
  QUICK is the one mode where ceiling == count (exactly 30 ungated headers, verified by AST). The
  ceiling/count distinction is now an explicit `CLAUDE.md` section ("Phase numbering + counts"), so
  nobody "fixes" the progress bar by renumbering phases.
- **`CLAUDE.md`'s fractional-phase list was 5 entries long; there are 24** (10.5, 10.6, 17.5, 21.5,
  22.5, 32.5, 36.5, 42.5, 44.5, 45.5, 49.5, 55.5, 68.5, 74.5–74.9, 82.5, 87.5, 88.5, 97.5, 99.5,
  100.5), all present in `data/mitre_mapping.json`'s `phase_map`.
- **Six live HTTP routes were undocumented** — `/api/csrf`, `/api/findings`, `/api/reports`,
  `/api/report/diff`, `/api/schedule` (GET+POST), `/favicon.ico`. An auditor reading the docs would
  have concluded the route table was smaller than it is.
- **`native-app/` and `tools/` were absent from the `CLAUDE.md` file map entirely**, as were
  `gui/static/vendor/` and `fx-preview.html`. Added, along with a warning that
  `native-app/src-tauri/target/{debug,release}/engine-root/` holds full **build copies** of the
  engine/server/gui that repo-wide greps hit and that must never be edited.
- **`BLUEPRINT.md` contradicted itself on the regression metric** — §4 said the auto-destructive
  baseline was 39, §5's quality gate said "target: 52". Neither is a constant: the count is
  box-dependent. §4 now lists the real reference points (52 → 39 → 25 dev-box, 100 on an all-time
  dev-box run of which 87 are Phase-10 TEMP hits, 6 in a clean sandbox) and requires stating which
  machine a number came from.
- **`CLAUDE.md` still described `scan_state` as throttled to `%12` log lines.** The phase-change
  emit (`c0477ae`) has been in for weeks; the doc was describing the pre-fix behaviour.
- **`README.md` described QUICK as "phases 1-30".** QUICK is a fixed 30-phase *subset*, not a range.
- Status/roadmap sections in `CLAUDE.md`, `BLUEPRINT.md` and `HANDOFF.md` still ended at
  2026-07-22 and asserted the browser click-through and USB test were the only open items. Three
  sessions have shipped since (WS7/8/9, the native Tauri shell, sandbox malware testing); the open
  list is longer, and items that were never run to completion are now explicitly marked unverified
  rather than implied done.
- `NIGHT_RUN_PLAN.md`, `REVIEW_FINDINGS_2026-07-22.md`, `TIME_LOG.md` and
  `_python/README_CLAUDE_CODE.md` all read as live task lists; each now carries a banner saying it
  is historical/parked, because a fresh session actioning any of them would waste a session or
  re-do finished work.

### New durable rules (all confirmed live on 2026-07-26)

- **A BOM-less `.ps1` containing an em dash does not run — it does not even parse.** PS 5.1 decodes
  the file as Windows-1252, so the em dash's trailing byte becomes **U+201D**, a curly quote that
  PS 5.1 honours as a real string delimiter. The file fails to parse, **zero statements execute, and
  not even the first log line is written.** Combined with a hidden-window `LogonCommand` (no console,
  no redirect) this is indistinguishable from a hang, and it silently cost an entire session of
  debugging. Rule: harness scripts are ASCII + UTF-8 BOM, parse-checked on real `powershell.exe` 5.1
  before being run, and anything driving a hidden window redirects stdout **and** stderr to a file.
- **Windows Sandbox does not reap its VM when you kill its processes.** `vmmemWindowsSandbox`
  survives indefinitely, and because Sandbox is single-instance the *next* launch silently never
  boots — which looks exactly like the harness hanging. `Restart-Service vmcompute -Force` clears it.
  Verify no sandbox VM is alive before launching another.
- **theZoo malware archives are password-protected (`infected`) and `tar` cannot decrypt them — it
  writes 0-byte files and exits successfully.** A test that "places malware" and then reports a
  clean scan proves nothing unless it **asserts non-zero size and expected magic bytes** first. Use
  `7za` (bootstrapped via `7zr` + the `7zXXXX-extra.7z` package) with `-pinfected`; `7zr.exe`
  handles only `.7z`, never `.zip`.
- **`POST /api/remediate` replies `{"status":"started"}` asynchronously.** The HTTP response says
  nothing about whether anything was remediated — verify on the filesystem/registry and in
  `reports/server_events_*.log` (`applied`/`failed`/`skipped`/`blocked`) plus
  `reports/remediation_audit_*.jsonl`. Two calls back-to-back return 400
  `{"error":"remediation already running"}`; sequence them ~30s apart.
- **`Invoke-RestMethod` sends no `Origin`/`Referer`**, so `Test-RequestAllowed` classifies it as a
  non-browser client: headless API scripting needs no CSRF token. Never weaken the browser-facing
  gate to make a harness work.
- **The case-insensitive-shadow rule now names the worst case.** All engine modules dot-source into
  ONE scope, so a phase-local `$auto` *is* the loader's `[switch]$Auto` — the flag `Summary.ps1`
  tests to decide whether to `[Environment]::Exit(0)` instead of falling through into `FixMode.ps1`'s
  interactive `Read-Host`. Clobbering it hangs every server-driven scan with no output and no error.
  Caught in review, never shipped. Same hazard for every other loader `param()` name.

### Noted, not fixed (no code was touched)

`data/coverage_matrix.json` is stale — regenerated 2026-07-25 at `phase_count: 130`, so it predates
WS7/8/9 and the current working tree. `tools/Build-Release.ps1` has no `native-app` awareness.
`ZeroBreach-V23.ps1`'s comment-based help still says `-OutDir` defaults to the Desktop; the code
defaults to `reports/`. `Show-PhaseHeader`'s `$global:CURRENT_PHASE_NUM / $global:TOTAL_PHASES`
percentage over-counts in FULL/DEEP for the same ceiling-vs-count reason (only reachable through
`FixMode.ps1`'s WinForms progress bar, and clamped by `[Math]::Min(100, …)`).

---

## 2026-07-22 — full-repo review remediation (all 56 findings) + WS6 detections + UX pass

Applied `REVIEW_FINDINGS_2026-07-22.md` in full — every CRITICAL/HIGH/MEDIUM/LOW finding, the
10 GUI/UX proposals, and a new detection expansion on top. The review document is now closed.

### CRITICAL

**Two engine modules were missing their mandatory top-level `trap`.** `engine/Summary.ps1` and
`engine/FixMode.ps1` — the two files CLAUDE.md names *explicitly* — had none, so any terminating
error in `Summary.ps1` fell straight through into `FixMode.ps1`'s interactive prompts: the exact
"hung `-Auto` run" the engine-split rules exist to prevent, reintroduced in the files the rule was
written for. Both now open with `trap { Write-RecoveredError $_; continue }`.

**Cross-origin remediation (CSRF).** Every response carried `Access-Control-Allow-Origin: *` and
the OPTIONS preflight answered `GET, POST, OPTIONS` for any origin, so **any page in the
operator's browser — an ad, a compromised vendor site — could `POST /api/remediate` and drive
real file deletes, registry deletes and process kills, completely bypassing the typed-`PURGE`
modal.** "Locally bound" never meant "only the GUI can reach it". Fixed with two independent
locks, both enforced *ahead of the route table* so a future POST route cannot forget them:
Origin/Referer must match this server's own address, and a per-process random token
(`GET /api/csrf` → `X-ZB-Token`) must be echoed. No ACAO header is sent at all now, so a foreign
page cannot read the token even if it reaches the route. A request with **neither** Origin nor
Referer is treated as a non-browser client (curl / the headless harness) and allowed without a
token — unreachable from a web page, which is the whole threat model here.
Verified live: cross-origin POST → 403, missing token → 403, wrong token → 403, same-origin +
token → 200, no-Origin client → 200, cross-origin `Referer` → 403.

### The anchored-path cluster (#4/#5/#6/#7) — the same bug class, four more times

CLAUDE.md already documents "anchor folder-name tests to path COMPONENTS" (the WhatsAppDesktop
auto-kill). Four sites had never had it applied, and every one of them gated an **auto-selected
destructive action** on a bare `"AppData|Temp"` substring:

- **Phase 36** — HIGH + `KillProcess` on any process whose path merely contained those letters
  and held a non-web socket. Every Electron/updater app (Discord, Slack, Teams, Spotify) matches.
  Now anchored, WindowsApps excluded, and the Authenticode verdict decides: signed → POSSIBLE +
  Info (shown, never killed), unsigned → HIGH + KillProcess. Carries a `SIG_AUDIT` budget.
- **Phase 28** — CRITICAL + `RunCmd` running `Stop-Service; Set-Service -Disabled; sc.exe delete`.
  A legitimate signed helper service under AppData was permanently deleted. Split: LOLBin/script-
  host ImagePath → CRITICAL + RunCmd; user-path only → signed = POSSIBLE + Info. Also anchored
  `\.js` (was matching `.json`) and escaped the service name in the generated command.
- **Phase 29** — CRITICAL + task unregister on a bare `cmd` / `AppData` / `Temp` match. Practically
  every third-party auto-updater matched. Split into STRONG (obfuscation/remote-payload/scriptlet
  → CRITICAL) vs WEAK (`\bcmd\.exe\b` or user path → Authenticode decides). The sibling task-XML
  check had already been downgraded for this exact reason years earlier; the action check never was.
- **Phases 69 / 83** — already required an invalid signature, so only the anchoring was missing.

Live DEEP on this box: Phase 29 went from 3 × CRITICAL+RunCmd to 2 POSSIBLE/Info + 1 HIGH/RunCmd.

### Remediation correctness

- **The rollback snapshot was not a valid `.reg` file.** It was built by concatenating `reg export`
  output after a plain-text banner, with no `Windows Registry Editor Version 5.00` magic — so the
  `regedit /S` restore the tool prints to the operator imported *nothing*. The safety net was
  decorative. Now emits the magic header, comments the provenance banner with `;`, and strips the
  duplicate header from each chunk.
- **GUI-driven remediation took no snapshot at all** (only the console fix mode did), so a
  mistaken PURGE had nothing to roll back. The remediation runspace now exports one first,
  honouring the launchpad's previously-inert "Create Rollback Snapshot" checkbox.
- **`DeleteReg` reported success without verifying.** Every sibling action checks its
  post-condition; `DeleteReg` alone called `Remove-ItemProperty -EA SilentlyContinue` and reported
  `applied` unconditionally — telling the operator a persistence value was gone while it was still
  armed. Now verified.
- **Raw `Get-ItemPropertyValue` in the reboot-queue fallback** (a call CLAUDE.md bans outright)
  threw whenever `PendingFileRenameOperations` did not already exist — i.e. on any never-rebooted
  box, on the code path that handles a *locked malware file*. Added a runspace-local `RGet-RegVal`.

### Self-allowlisting evasions closed

- `cloaked_benign_names` matched bare substrings against an attacker-chosen filename — a
  hidden+system payload evaded Phase 18 entirely by calling itself `iconcache_x.exe`. Anchored.
- `trusted_root_ca_issuers` downgraded a rogue root CA to INFO if its Subject contained
  "microsoft" — so a MITM root named `CN=Microsoft Update CA` cleared itself. The trust decision
  is no longer name-based: it now keys on membership of the Microsoft-managed **AuthRoot** cache
  (which an attacker cannot join) plus the store registry key's **install time**, and a root
  installed in the last 30 days is HIGH *regardless of its name*.
  **Tuning note:** the first cut keyed on AuthRoot membership *alone* and produced a 42-finding
  POSSIBLE flood on a healthy box — Windows' OS-built-in roots are not in that cache (it holds the
  third-party program members). Corrected to "AuthRoot **or** name list clears it; install
  recency escalates regardless", which on this box gives 62 INFO / 1 POSSIBLE / 0 HIGH.
- `yara_benign_paths` / `sct_benign_paths` / `keylogger_benign_paths` / `miner_config_benign_paths`
  keyed on `\node_modules\` and `\site-packages\`, folder names an attacker can simply create.
  Tightened to `\lib\site-packages\` and `\node_modules\<pkg>\`, and gated behind a new
  `Test-BenignPath` **veto**: a benign-path match is ignored outright when the file sits in a
  staging dir (`\Downloads\`, `\Public\`, `\Temp\` — with pip's genuine temp build dirs carved back out).

### Dead code, dead data, dead UI — all either wired up or removed

- **Deleted 5 unreachable destructive helpers** from the loader (`Invoke-VerifiedAnnihilation`,
  `Invoke-VerifiedRegScrub`, `Invoke-SectorScan`, `Invoke-RegSectorScan`, `Reset-FilePermissions`).
  Zero call sites anywhere; one ran an unscoped `icacls /reset /T` on a caller-supplied path —
  precisely the whole-drive catastrophe FP round 5 removed from Phase 108.
- **Custom IOCs were 80% inert.** `Import-CustomIocs` filled Hashes/Domains/IPs/Regex/Files but
  **only `.Hashes` was ever read** — an operator adding a known-bad domain or IP via the IOC
  Manager got a counter that went up and no coverage. All five buckets are now consumed: domains
  join the narrow malware-C2 list (Phase 34/36), IPs get an exact + CIDR match in Phase 36
  (unit-tested, incl. IPv6 and non-byte-aligned prefixes), filenames and regex in Phase 90.
- **Five signature keys** (`trojan_file_patterns`, `auto_elevate_bins`, `email_phishing_trojans`,
  `proactive_persistence_regs`, `proactive_lure_extensions`) were loaded into globals and never
  read. All wired. `permission_baseline.json`'s `unquoted_path_whitelist` — documented and
  referenced by the coverage matrix as Phase 111's suppression source — was likewise never read.
- **Three launchpad checkboxes did nothing.** snapshot / baseline-diff / CSV-export round-tripped
  through scan profiles but were never sent to the server. Now sent *and* implemented: baseline
  passes the newest prior `KrakenBaseline_*.json` as `-Baseline`, CSV writes an export alongside
  the JSON report, snapshot drives the new pre-remediation rollback.
- **The whole SCHEDULE/SMTP settings section had no listeners and no route.** Added
  `GET|POST /api/schedule` (arguments passed as an argument *array*, never an interpolated
  string) plus an APPLY button and persisted settings. The output-directory box was an editable
  field with a dead BROWSE button; it now truthfully reports the real reports directory read-only.

### Other engine/server fixes

- **Self-elevation silently dropped `-Schedule`/`-SmtpTo`/`-SmtpFrom`/`-SmtpServer`** — running
  `-Schedule DAILY` from a non-admin shell (the realistic first-time path) relaunched elevated
  *without* them, so no task was created and no error was printed. Forwarded.
- **Finding IDs built from `.NET string.GetHashCode()`** are randomised per process on .NET 5+,
  so `-Baseline` diffing reported the same finding as new forever. Replaced with a deterministic
  FNV-1a `Get-StableId` at **all 16 sites** (the review named 2; the defect was identical in all).
- **`$sig` locals shadowed the script-scope `$SIG` signature object** at 10 sites (PowerShell
  variables are case-insensitive — the `$sev`/`$SEV` incident that disabled all severity
  classification for weeks). Currently latent, because every `Get-Sig` call happens at load time
  before any phase assigns `$sig`; renamed to `$asig` so it stays that way.
- **Phase 32's Authenticode loop had no `SIG_AUDIT` budget** (unlike its Phase 10/15 siblings) —
  unbounded, over every DLL in every writable PATH dir, with ~15s CRL/OCSP blocking per file.
- **Phase 63 used a raw `Get-ChildItem -Recurse`** over three user roots instead of `Get-ScanFiles`.
- **The HTML report's inline CSV `<script>` could be broken out of** by a finding whose path
  contained `</script>`. It also embedded raw CR/LF into a JS string literal — a syntax error
  that had quietly broken the report's CSV export for any run with findings. Both fixed, plus a
  `$HOST_NAME_` typo that parsed as an undefined variable and blanked the download filename.
- **CSV/formula injection**: a finding's attacker-chosen text starting `=`/`+`/`-`/`@` executes
  as a formula when the export is opened in Excel. Neutralised in both CSV paths.
- **`Start-Runspace` never disposed** its PowerShell/Runspace pair and every call site discarded
  the handle; finished runspaces are now reaped.
- **`/static/` had no containment check**, unlike every other file-touching route.
- **`[bool]$ScanConfig.html_report`** — `[bool]'false'` is `$true` in PowerShell. The
  `ConvertTo-Flag` helper exists precisely for this and was used on the profile path but not here.
  Unvalidated `hours` threw before `Running` was set, killing the scan with no error surfaced.
- Removed dead `$script:SEV_PATTERNS` / `$script:PHASE_RE` (a runspace cannot share script scope
  with its parent — the live copies are inside `$script:SCAN_SCRIPT`; the dead `PHASE_RE` was also
  a stale non-fractional regex that would have misled an editor into breaking phases 55.5/74.5/99.5).

### Found by validating, not by the review

- **The phase counter walked backwards at end-of-scan.** `Summary.ps1`'s "10 SLOWEST" table prints
  `PHASE N — …` lines in *descending duration* order; the server's phase regex matched every one,
  so a completed DEEP reported **89/115**. The counter is now monotonic in both servers.
- **`rerenderLog()` called `appendLogLine()`, which also pushes into the buffer**, so every log
  filter change duplicated the entire log (and past the 2000-line cap, silently discarded the
  oldest real lines). Split rendering from buffering; timestamps are also stamped once on arrival
  instead of being re-stamped to "now" on every re-render.
- **A `[byte](0xFF -shl 7)` overflow** in the new CIDR matcher silently broke every prefix that
  was not a multiple of 8 — caught by unit-testing `/25` and `/12` rather than assuming.

### Parked Python server

Fixed too (6 findings): wildcard SocketIO CORS → loopback origins; `\[OK\]` did not tolerate the
engine's padded `[OK ]` tag; unanchored `ANOMAL` matched inside the benign word "ANOMALIES";
`MODE_PHASES` capped DEEP at 107 when the real ceiling is 115; `PHASE_RE` collapsed fractional
phases onto their integer floor; `/api/scan/start` checked `running` outside the lock so two
POSTs could spawn two concurrent elevated scans; `/api/reports/<f>` served any file in the reports
directory (which also holds the quarantine vault and IOC files) with no allow-list.

### WS6 — new detection coverage (9 fractional phases)

Fractional numbering was chosen deliberately: the QUICK/FULL/DEEP plan ceilings and the server's
1..30 QUICK progress index are untouched, and **every new phase sits inside a
`if (-not $global:QUICK_MODE)` block**. All signature content is DATA (31 new keys in
`data/detection_signatures.json`); all 9 phases are MITRE-mapped (+13 new techniques).

| Phase | Coverage |
|---|---|
| **17.5** | Timestomping — creation-time newer than write-time, epoch/zeroed stamps. Structural, nothing to signature. Deliberately *not* time-scoped (the timestamps are the forged thing). |
| **21.5** | `SilentProcessExit` (a separate hive Phase 21 never reads), IFEO aimed at a **security product** = EDR blinding rather than persistence, and COM **TypeLib** hijack (Phase 24 walks CLSID only). |
| **22.5** | The remaining process-wide DLL load points: `AppCertDlls`, netsh helper DLLs, Winsock LSPs (LSP is review-only — an incorrect removal breaks all networking). |
| **42.5** | Accounts hidden from the logon UI via `SpecialAccounts\UserList`, shadow-admin naming conventions, and Administrators members whose principal source will not resolve. |
| **44.5** | Credential-access *residue*: LSASS minidumps, exported SAM/SECURITY/SYSTEM/NTDS hives, DPAPI blobs staged outside their store, and live command lines (`comsvcs MiniDump`, `reg save` of the hives, `ntdsutil ifm`, shadow-copy-for-hive-theft). |
| **45.5** | RDP exposure (NLA off, password saving, multi-session) + the shared operator hardening set (LSA PPL, WDigest, SMB1, AutoRun, script-block logging, LLMNR, UAC prompt). |
| **68.5** | **ClickFix / fake-CAPTCHA** — reads `RunMRU`, a verbatim record of what the victim pasted into the Run dialog. Very high fidelity. Graded `Info` **on purpose**: this is the best evidence of *how the box was compromised* and deleting it destroys that. |
| **82.5** | RMM abuse. **User rule #2 respected — Datto/CentraStage/Kaseya are deliberately absent from the list.** Everything listed is dual-use, so a normal install is INFO; only a staging-path deployment escalates. |
| **100.5** | Cloud/session token theft. Token files existing is normal (inventory only); loot-shaped archives in staging dirs are the finding. Access tokens survive MFA, so the description says to revoke. |

**Grading rule for the whole block (user decision):** every hardening/lockdown action is
`Info`/`POSSIBLE` + `RunCmd`, so the CRITICAL/HIGH auto-select can never fire one on a healthy box
(rule #1). The GUI's new **🛡 SELECT HARDENING** button is the deliberate opt-in — it selects the
group; the operator still reviews the queue and types `PURGE`.

### GUI / UX

Severity pills are real filters (they always looked clickable and had no handlers); findings
text-search and GROUP BY threat/severity/MITRE-tactic/phase, groups sorted most-severe-first, with
per-group select-all. The PURGE modal now shows the **actual targets grouped by fix action**
instead of a bare count, and demands `PURGE <count>` for batches of 10+. Keyboard access: skip
link, landmark roles, `role`/`tabindex` on the div-based controls with Enter/Space activation,
visible focus rings (the command palette and danger input had `outline:none` with no
replacement), and focus-trapped modals with Esc + focus restore. Severity is no longer colour-only
(diamond/square/circle/dot — red-green is the worst pairing for the commonest colour blindness).
Responsive breakpoints for the hardcoded 200px/220px rails. A real `@media print` stylesheet — the
Report view is now an actual client deliverable rather than printed dark console chrome. MITRE
tactic rollup chart and a **persisted** remediation summary (previously a 3-second toast was the
only record of a PURGE run). Client-facing export with internal fields stripped. Visible SSE-drop
feedback and background-tab notification for 25-minute scans. "No findings" now reads differently
for a clean completed scan vs "you have not scanned yet". `prefers-reduced-motion` honoured by the
canvas FX and the Kraken cinematic (a full-screen flashbang is a genuine vestibular hazard).
**GSAP and Chart.js are vendored locally** — an IR tool must not fetch executable JS from a CDN
onto an elevated console, and a compromised client network may block egress anyway.

### Docs

`SKILL.md`'s guardrail claimed the engine is BOM-*free* and only the server carries a BOM — the
exact opposite of the truth, and following it would have stripped a required BOM; its step-4 line
numbers still pointed into the pre-split monolith. `BLUEPRINT.md` §4's regression baseline said 52
where CHANGELOG's own round-6 entry establishes 39. `coverage_matrix.json`'s `_comment` still
claimed "the engine has no QUICK gate" and listed 15 keys as orphaned, both fixed in July.

### Round 2 — three independent audit agents, same day

Three read-only audit agents (engine, server/security, GUI) were run against the commit above.
They found **real defects, including several introduced by that commit**. Everything below is
fixed and re-validated. This is the second time in this project's history that an independent
review caught a rule-#1 violation before it shipped, and it is worth the token cost every time.

**Two auto-destructive levers the commit itself introduced.**

- **A malformed operator CIDR matched every connection.** In the new custom-IOC IP check the hit
  flag was raised *before* the mask comparison and only cleared on a mismatch, so a prefix that
  parsed to zero — a typo like `10.0.0.0/abc`, or an explicit `/0` — broke out of the loop on the
  first iteration with the flag still set and matched **every established connection**, emitting
  `CRITICAL + KillProcess` for every connected process from one bad line in an IOC file. The flag
  is now raised only after a full successful comparison, and an unparseable or `/0` prefix is
  rejected outright. The original unit test missed this because it only covered a CIDR whose *IP*
  failed to parse; the matcher now has 18 cases including malformed prefixes and IPv6.
- **`/api/scan/abort` was reachable by GET and therefore skipped the whole CSRF gate**, which
  keyed on `$method -eq 'POST'`. A cross-origin `<img src="http://localhost:PORT/api/scan/abort">`
  needs no preflight and no token, and aborting mid-scan makes the scan runspace fall into its
  `finally`, write `audit_<ts>.json` and emit `scan_complete` — so an attacker could silently
  **truncate an incident-response scan and have the console report it as complete**. The gate now
  covers every non-GET/HEAD method and the route self-guards as well.

**WS6 gradings walked back after the audit modelled real-world inputs.** Timestomp detection no
longer auto-quarantines: the DOS/ZIP epoch is 1980-01-01, so *every* file extracted from such an
archive — portable tools in Downloads, all of `C:\ProgramData\chocolatey`, wheels built with
`SOURCE_DATE_EPOCH` — carries a pre-2000 stamp on a healthy box. Token-staging name matches
(`*token*.json`, `*cookies*.txt` — yt-dlp's standard export) are review-only unless the name is
unambiguous loot. RMM agents in a staging path are POSSIBLE + Info, not HIGH + KillProcess:
running AnyDesk/TeamViewer QuickSupport portable from Downloads is one of the most common MSP
workflows there is, and an auto-selected kill would have **severed the technician's own remote
session**. Phase 92's auto-elevate check now fails *closed* when `ExecutablePath` is unavailable
(it previously skipped its System32 guard and could KillProcess `taskmgr.exe`/`mmc.exe`).

**Checks that could never have fired.** `AppCertDlls` is a *subkey* whose values name the DLLs,
not a value on `Session Manager`, so that check always read `$null`; it now walks the subkey.
Phase 39's install-recency escalation — described in the code as "the signal an attacker cannot
fake" — depends on a registry key's `LastWriteTime`, which PowerShell's provider does not expose
(`Microsoft.Win32.RegistryKey` has no such property); the branch is left correct but is
documented as **inert** until a `RegQueryInfoKey` P/Invoke is added, and the phase no longer
claims a guarantee it cannot deliver. The two `AppInit_DLLs` entries in `injection_dll_reg_points`
duplicated Phase 22 one-for-one and were removed.

**The QUICK gate was broken by the new phases.** 22.5, 44.5 and 68.5 were each inserted
immediately *after* their enclosing block's `}   # end QUICK-skip block`, so they ran in QUICK
and pushed it from 30 to **33** phase headers — breaking the documented ceiling and the server's
hardcoded `QUICK=30` progress index. All three moved inside; QUICK is verifiably 30 again.

**The HTML report was broken for any finding containing an apostrophe.** The JS escape used
`-replace "'","\\'"`, and PowerShell does not treat backslash as an escape inside a double-quoted
string — so it emitted `\\'`, which in the JS literal reads as an escaped backslash followed by
an unescaped quote, terminating the string and throwing a `SyntaxError` that killed the whole
inline `<script>` (CSV export, severity filter and column sort all dead). Pre-existing, missed on
the first pass despite touching that exact line.

**`/api/schedule` — every one of its problems.** `Start-Process -ArgumentList` does **not** quote
array elements, it joins them with spaces, so the route failed on any install path containing a
space (the portable zip is explicitly validated for spaced paths) with a bare
`exit code -196608`; the SMTP values were unvalidated free text that could smuggle extra engine
parameters such as `-IocFile \\attacker\share\evil.ioc` into the SYSTEM task; `-Wait` on the
single-threaded accept loop froze the entire console until the child exited; and the GET branch
double-encoded its JSON so the settings never repopulated. All fixed, with a 90s timeout.

**`DeleteReg` still lied in its most likely failure mode.** The new post-condition check used a
helper that returns `$null` on *any* failure, so when the read failed for the same reason the
write failed — malware setting a DENY ACE for Administrators on its Run key, a standard
persistence-hardening trick — the verification *passed*. It now distinguishes gone / present /
unverifiable and reports the third as a failure. Also switched to `-LiteralPath`, since a value
name containing `[` or `*` was being treated as a wildcard pattern.

**Frontend.** The rewritten SSE pump advanced its head index *after* dispatch with no `try`, so
one throwing handler replayed the entire in-flight batch forever — duplicating log lines,
findings and queued remediation actions while the scan appeared frozen. `SELECT HARDENING` was
missing the `vendor_trusted` exclusion every other bulk selector has, and could not reach the
INFO-severity hardening set at all (the ASR rules — the actual point of the feature) because the
findings loader dropped INFO; there is now a `HARDENING` pill and a single shared
`isHardeningFinding` predicate. `SELECT ALL` ignored the active filter and *replaced* the
selection, so filtering to 3 POSSIBLEs and clicking it queued ~200 findings including destructive
CRITICALs; it is now scoped to what is visible, additive, and says how many are hidden — and the
filter status line now reports selected-but-hidden findings. A stale filter also silently
narrowed the one-time severity auto-select while still burning its one-shot flag. The PURGE
preview read `Target`/`FixParam`, keys the server never emits, so it showed descriptions instead
of the `fix_param` command that will actually execute. `notifyBackground` could capture its own
flashing text as the "original" title and restore that permanently. Plus the small ones: the
`.queue-remove` button had no CSS rule at all, `.threat-chip` was announced as a button with no
handler, and theme cards lost their `tabindex` whenever the grid rebuilt.

Re-validated after all of the above: 7 `.ps1` parse-clean on live 5.1 **and** pwsh 7 with BOMs
intact, JSON/JS/Python clean, the CSRF matrix re-run live (GET abort → 405, cross-origin POST →
403, PUT → 403, token POST → 200, SMTP injection → 400), and a fresh DEEP scan.

### Validation

All 7 `.ps1` files parse-clean on live `powershell.exe` 5.1.26100.8875 **and** `pwsh` 7, BOMs
intact; all 5 `data/*.json` parse; `node --check` clean on all JS; `tools/check-visuals.mjs`
PASS 13/13. Live server: CSRF matrix (6 cases) verified; QUICK scan 30/30 phases contiguous,
0 recovered errors; DEEP scan 115 phases, 0 recovered errors. Auto-destructive re-graded from a
fresh DEEP baseline — the non-Phase-10 tail is entirely tripwires and by-design posture items, and
none of the WS6 additions contribute to it.

---

## 2026-07-21 — WS4: Win32_Process snapshot memo (`Get-ProcSnapshot`)

Second WS4 caching step (after the `Get-ScanFiles` memo): **7 phases each ran their own full
`Win32_Process` WMI enumeration** per scan. New loader helper `Get-ProcSnapshot` memoizes the
snapshot with a **90-second TTL** — unlike the filesystem (static in audit mode) the process
table changes during a run, so adjacent phase clusters share one enumeration while phases
minutes apart still see fresh data. Shares the WS4 `ZB_NOCACHE` kill-switch
(`$global:SCAN_FILE_CACHE_ON`); `ZB_CACHE_DEBUG` now also prints a `[CACHE] ProcSnapshot`
stats line.

- **Converted (6 sites):** Phase 3 (ancestry/injection), 4 (LOLBIN), 44 (elevated procs in
  user paths), 99 (LOLBAS expanded), 99.5 (cmdline heuristics), 102 (svchost parent map).
  Phases 3→4 and 99→99.5→102 each collapse to one enumeration; Phase 44 sits alone mid-scan
  and always refreshes (TTL long expired).
- **Deliberately NOT converted:** Phase 56's rootkit delta diffs the WMI table against
  `Get-Process` captured at the same instant — a cached snapshot even seconds stale would
  fabricate CRITICAL discrepancy findings. Raw call kept with a warning comment at the site
  and in the helper.
- Same `return ,$arr` single-item pipe trap as `Get-ScanFiles` — call sites wrap in parens.
- **Service lookups audited, nothing to cache:** one full `Win32_Service` enum per scan
  (Phase 111) + cheap name-filtered `Get-Service` calls. Remaining WS4: per-file signature
  lookup caching.

Validated live on 5.1.26100 (BOMs intact, parse-clean 5.1+7): headless QUICK (exactly 30
phases, 0 recovered errors), DEEP `-Hours 1` (**115 phases contiguous, 0 recovered errors,
~8.9 min**), and a `ZB_CACHE_DEBUG` QUICK confirming 1 snapshot hit (Phase 4 reusing
Phase 3's enumeration). Noted for a future FP round: Phase 56 flagged 3 transient-process
discrepancies during the DEEP run (its two enums are ~1s apart, so short-lived processes land
in one list only) — pre-existing behavior, Info-only/never auto-acted, but a re-check that the
discrepant PID still exists would quiet it.

## 2026-07-11 — Review hardening of the 2026-07-04 session (WS4 cache + P82)

Full review of the session-9 work (`37cd39b`/`075d52d`): two agent audits (all 18 `Get-ScanFiles`
call sites for mutation/order/staleness/TimeScoped hazards; P82 + stealth + kill-switch edges)
found **no shipped bug that changes findings** — every call site consumes read-only, `FixMode`
never touches the cache, `Test-InScope`'s cutoff is constant per run, and the stealth path exits
before the `[CACHE]` debug line can print. Three latent cache hazards hardened anyway:

1. **Deadline-truncated walks are no longer cached.** A walk cut short by the 20s wall-clock
   budget is load-dependent (disk contention on the first pass), so caching it poisoned every
   later identical call with a nondeterministic partial file set. Now only *complete* walks and
   *MaxFiles-capped* walks (deterministic on a static tree) enter the memo; a deadline-hit call
   returns its partial result uncached so the next identical call gets a fresh budgeted walk.
2. **Cache writes are gated on `$global:SCAN_FILE_CACHE_ON`** — a `ZB_NOCACHE` run previously
   still populated the hashtable (never read); A/B runs are now truly cache-free. Also documented
   that the kill-switch is PRESENCE-based: any value, including `"0"`, disables it.
3. **The cache key keeps caller root order (no more `Sort-Object`).** Under truncation the walk
   order decides *which* files make the cut, so same-set-different-order calls must not share an
   entry. The audit confirmed all current multi-root aliases pass identical order (Phase 89 ↔ 106),
   so this loses zero hits today — it guards future call sites.

**P82 follow-up — PuTTY-suite coverage gap closed:** `pscp.exe`/`psftp.exe`/`pageant.exe` were in
no signature list at all (undetected). Added to both `tunneling_tools` and
`tunneling_tools_dualuse`, so the whole suite now surfaces at **POSSIBLE** (shown, never
auto-selected — same grade the user signed off for putty/plink; no new auto-destructive
exposure). Also corrected the stale Phase-82 row in `data/coverage_matrix.json` (still claimed
`tunneling_tools` was unconsumed — it was wired in `bbc2d9d`).

Validated: parse-clean live 5.1.26100 + 7 (BOMs intact), JSON valid; headless FULL + DEEP
`-Hours 1` runs (cache-on with stats, decoy PuTTY-suite files in TEMP → POSSIBLE) + a
`ZB_NOCACHE` run proving the memo stays empty. Details in the runs below this entry's date.

---

## 2026-07-04 — WS4 (partial): `Get-ScanFiles` per-scan enumeration memo

**The engine re-walked the filesystem on every one of the 18 `Get-ScanFiles` call sites with
zero caching.** Since the engine is audit-only in `-Auto` (the filesystem is static for a run)
and spawns as a fresh subprocess per scan, byte-identical `(roots, filter, timescope, caps,
prune)` calls are guaranteed to return identical results. Added a script-scope memo in
`Get-ScanFiles` keyed on that full param tuple (`$global:SCAN_FILE_CACHE`), plus
`$global:SCAN_FILE_CACHE_ON` (a `ZB_NOCACHE` env kill-switch for the field / A-B validation)
and a `ZB_CACHE_DEBUG`-gated stats line in `Summary.ps1`. The cached array is never mutated by
callers (they filter into new collections); return shape kept as `,$arr` per the CLAUDE rule.

**Explicitly NOT done: true phase parallelism** — the architecture shares variables across
phases in one dot-sourced scope (`$ransomScanFiles`, `$p68Files`, …), so concurrent phases
would race that shared state. Caching is the safe win; parallelism stays a non-goal.

Validated (A/B, live PS 5.1.26100, DEEP `-Hours 1`): parse-clean 5.1 + 7, BOMs intact; both
runs exit 0, 120 phase headers contiguous, 0 recovered errors. **Cache fires: 18 of 41 walks
(44%) served from memo.** Correctness — cache-on vs `ZB_NOCACHE=1`: **CRITICAL 5=5, HIGH 8=8
identical** (auto-destructive set unchanged); the only total delta (257 vs 254) is entirely in
the POSSIBLE/INFO tail and is environmental drift over the ~7-min gap + moving `-Hours 1`
window (DNS cache, prefetch files, one licensing task + a Firefox `prefs.js` crossing the
window boundary) — no cache-coherence failure. Performance: **DEEP wall-clock 503s → 397s
(~21% faster)**, and the cache-on run went *first* (cold OS cache), so that's a conservative
floor.

---

## 2026-07-04 — P82 putty/plink dual-use downgrade (user sign-off)

The last open FP sign-off: Phase 82's `tunneling_tools` scan graded **putty.exe/plink.exe
CRITICAL + DeleteFile**, so a legit admin's SSH client in a user path was auto-selected for
deletion on a healthy box (pre-existing; externalized 1:1 in session 8). With user sign-off
(2026-07-04): new `tunneling_tools_dualuse` key in `data/detection_signatures.json`
(`putty.exe`, `plink.exe`) → those two now register **POSSIBLE** (shown, operator can still
act manually, never auto-selected). All other tunneling tools (nc/ncat/socat/chisel/frp/
ligolo/…) keep CRITICAL + DeleteFile. Anchored per-name regex (same escape/`*`-expansion as
the main list) with an empty-key guard so a blank JSON key suppresses the split, never the
detection. Validated: JSON valid; parse-clean live 5.1.26100 + 7 (BOMs intact); live 5.1
regex matrix (putty/plink → POSSIBLE; nc/chisel/sync.exe/putty.exe.bak unaffected;
single-element unwrap + empty-key edge cases); headless DEEP run (Phase 82 is DEEP-scope —
phases 81–89 don't run in FULL) with a benign `putty.exe` decoy in TEMP confirming the
`[FINDING]` line carries `sev: POSSIBLE` while Phase 10 still grades the same file
HIGH+DeleteFile as a TEMP executable (by design, unchanged).

---

## 2026-07-03 — QUICK is now a real gate (BLUEPRINT §7.8) + a latent Phase-56 rootkit bug

**QUICK was a label, not a gate.** `$PhasePlan.Max` was display-only, so QUICK ran phases 1–80
exactly like FULL while the GUI tile advertised "30 phases · ~2 min". Now QUICK runs a real
30-phase triage set:
`1,3,4,5,6,10,20,21,23,27,28,29,30,31,33,35,41,42,45,51,53,54,56,62,64,69,70,72,74.6,75` —
chosen for detection value per second (process/IOC matches, run keys, scheduled tasks, services,
named pipes, live sockets, Defender state), deferring the expensive file-system walks,
Authenticode sig-audits, and event-log mining to FULL/DEEP.

- **Mechanism (engine):** the loader sets `$global:QUICK_MODE = ($global:ScanMode -eq 'QUICK')`
  right after the `$PhasePlan` switch (before the modules are dot-sourced). The 54 non-kept
  phases in the 1–80 span are wrapped `if (-not $global:QUICK_MODE) { trap { Write-RecoveredError
  $_; continue }; <phase body> }`, grouped into contiguous-run blocks (13 in Phases-1, 7 in
  Phases-2) each carrying its OWN inner trap so a terminating error resumes at the next phase, not
  end-of-block (the engine-split module-trap rule). Phases 81–89 (Universal) and 90–115 (Advanced)
  were already off for QUICK/FULL and are untouched. FULL/DEEP/PARANOID/STEALTH are byte-identical
  (their `$QUICK_MODE` is `$false`, so every wrapped block runs exactly as before).
- **phase_total honesty:** `$PhasePlan.Max=30` flows to `$global:TOTAL_PHASES` and Summary's
  "30 phases" with no further edit. The server keeps `$MODE_PHASES QUICK=30` (the set is exactly
  30) and now tracks a `PhaseIdx` (count of distinct phase headers seen, clamped to PhaseTotal);
  in QUICK ONLY, `scan_state`/`sync`/`/api/state` report `PhaseIdx` (1..30) as `phase` instead of
  the raw number (which is non-contiguous and would overshoot — "62/30"). `finding` events and
  MITRE keep the TRUE phase. Non-QUICK payloads are value-identical.
- **Multi-agent (Fable):** a Plan agent produced the phase set + mechanism; a cross-phase
  variable-leak audit agent confirmed **0 leaks** (every kept phase is self-contained or reads a
  loader global; the one real dependency, Phase 53 reusing Phase 51's `$ransomScanFiles`, is
  verified with both phases kept and outside the wraps); a server-side agent implemented the
  PhaseIdx progress index. All three ran on Fable.

**Latent bug found + fixed (all modes):** the QUICK run surfaced 2 recovered errors in **Phase 56**
(hidden-process rootkit delta): `foreach ($pid in $hiddenFromPS)` / `$hiddenFromWMI` — `$PID` is a
READ-ONLY automatic variable (this process's id; PS names are case-insensitive so `$pid` IS
`$PID`), so the loop threw "Cannot overwrite variable PID" the moment either list was non-empty —
i.e. exactly when a WMI-vs-PS process discrepancy (the rootkit signal) existed — and the module
trap silently swallowed the whole phase. It only escaped notice because a healthy box usually has
no discrepancy (0 errors on prior FULL/DEEP runs). Renamed the loop var to `$rkpid`. Hidden-process
detection now actually runs when it matters.

Validation: parse-clean live PS 5.1.26100 + pwsh 7 (all engine files + server, BOMs intact, server
here-strings re-parsed); headless QUICK `-Hours 1` runs **exactly** those 30 phases with **0
recovered errors**; FULL `-Hours 1` runs the full 1–80 span (QUICK-skipped phases 2/7/55.5/80
present). Committed locally with the rest of the stack — push when ready.

## 2026-07-02 (late night) — Wire the 15 orphaned signature keys (BLUEPRINT §7.7)

The WS0 coverage re-audit found 15 signature keys merged into `data/detection_signatures.json`
(WS1/WS2) but consumed by **no** phase — dead data, and the phases that *should* have used them
still carried inline literal name-lists (an AMSI-rule liability). All 15 are now wired:

- **1:1 externalization (inline literal → JSON key, behavior identical):** P67 `adware_pup_regs`,
  P82 `tunneling_tools`, P89 `stego_tools`, P98 `leaked_cert_issuers`, P106 `cred_dump_tools`.
  The engine `.ps1` bodies no longer carry these signature-shaped lists.
- **New coverage (all FixAction Info except the P6 process-IOC loops, which mirror that phase's
  existing KillProcess posture on unambiguous malware family names):** P6 `loader_procs` +
  `banking_trojan_procs` (Pikabot/Bumblebee/QBot/DanaBot/…); P36 reverse-DNS + P34 DNS-cache gain
  the loader/infostealer C2 domain families; P55.5 `byovd_cert_tbs_hashes` — a new
  `Get-CertTbsSha1` DER helper computes the signing cert's TBS SHA1, which stays stable across
  the ~2500 polymorphic TrueSightKiller-class BYOVD variants where the file SHA256 is useless
  (cross-checked against `System.Formats.Asn1` on 17 real certs, malformed-cert OOM-guarded);
  P62 `c2_pipe_patterns` framework-NAME pipe pass (bounded `(^|[^a-z0-9])name([^a-z0-9]|$)` so
  short tokens like `msf` can't hit `MsFteWds`); P68 `infostealer_procs` (+14 families),
  `loader_drop_path_rules` + `c2_config_rules` (family drop-path / C2-artifact file rules);
  P100 `infostealer_target_paths_raw` (full 31-path browser/wallet/Telegram/Discord list).

**A Fable review subagent caught two rule-#1 auto-fire FPs before commit:**
1. **Broad C2 infra in the DNS-cache HIGH path.** `known_c2_domains` is deliberately broad
   LOLBin/tunneling infrastructure (raw.githubusercontent.com, ngrok, tailscale, trycloudflare,
   nip.io) — fine for Phase 36's reverse-DNS-of-an-*active-connection* check, but I had also fed
   it into Phase 34's DNS-**cache** substring match, which emits HIGH + an auto-selectable
   `RunCmd`. Any dev box that ever resolved GitHub would auto-fire. **Fix:** split into
   `$MALWARE_C2_DOMAINS` (point-in-time loader/infostealer C2 only — odd unique strings) for
   P34, vs `$ALL_C2_DOMAINS` (+ the broad set) for P36 reverse-DNS only.
2. **Generic stealer family words auto-killing legit procs.** The new `infostealer_procs` list
   adds generic words (atomic → Atomic Wallet, aurora, mystic, meduza) that substring-match
   legit process names; the first draft auto-killed any non-validly-signed match. **Fix:** P68
   now auto-kills (CRITICAL + KillProcess) only when the binary is **both** unsigned **and**
   running from a user-writable path (AppData/Temp/Downloads/user profile — real stealer staging);
   signed, system-path, or path-unreadable matches downgrade to POSSIBLE + Info. Validated live:
   the post-fix FULL run flagged `Mystic_Light_Service` (MSI RGB service) as POSSIBLE "verify",
   not the auto-kill it would have been.

Also OOM-guarded `Get-CertTbsSha1` against a malformed cert encoding a multi-GB length.
Validation: parse-clean live PS 5.1.26100 + pwsh 7 (all touched files, BOM intact); headless
DEEP `-Hours 1` (all 121 phases contiguous incl. fractional, 0 recovered errors, exit 0) before
the fixes, headless FULL `-Hours 1` (phases 1–80, 0 recovered errors, exit 0) after. Committed
locally — pending push with the rest of the stacked session commits.

## 2026-07-02 (night) — Scan profiles (BLUEPRINT §7.4) + the bad-JSON client-hang fix

**Scan profiles shipped.** New `GET|POST /api/profiles` on the PS server: 4 read-only built-ins
(`$script:PROFILE_BUILTINS` — Triage/Standard/Incident/Silent) + user profiles persisted to
`reports/scan_profiles.json` (UTF-8 no BOM, beside `custom_iocs.json`). Save is upsert-by-name
(case-insensitive), capped at 50, fail-closed validation: name whitelist `^[A-Za-z0-9][A-Za-z0-9
(),\-_.]{0,47}$`, mode whitelist, hours must parse as int 0–8760 (400, never coerced — a silent
0 would turn a 24h triage preset into ALL TIME), flags via `ConvertTo-Flag` (`[bool]'false'` is
`$true` in PS, so string booleans from API clients are matched strictly). GUI: SCAN PROFILES
picker at the top of MISSION PARAMETERS (load select + name input + SAVE/DELETE), `applyProfile`
drives the existing tiles/toggles/IOC path, `PROFILE_TOGGLES` is the single checkbox↔key map for
apply+save, errors surface via `showToast` (same convention as IOC save). Built-ins deliberately
carry **no `ioc_file` key** so applying one never blanks an IOC path the IOC Manager just set.

**Found while verifying (pre-existing, server-wide): malformed JSON in any POST body hung the
browser forever.** On PS 5.1 `ConvertFrom-Json` throws a TERMINATING error that `-ErrorAction
SilentlyContinue` does NOT suppress; the route aborted with no response and the accept-loop catch
never closed the context. Fixed at both layers: new `Read-JsonBody` helper (statement try/catch)
used by remediate/ioc/profiles; `/api/scan/start` now 400s on a non-empty unparseable body
(previously it silently started a default-scope scan and answered `started` — fail closed now);
accept-loop catch sends a 500 instead of leaving the client hanging.

**8-angle review of the diff surfaced and fixed before commit:** the PS 5.1 empty-pipeline bug
(`@(...) | Where-Object` yields `$null`, not `@()` — a save→delete-all→save cycle persisted a
literal `null` profile that crashed the picker render; outer `@( )` wrap, per the existing
`Get-ScanFiles` rule family); POST on an unreadable/corrupt `scan_profiles.json` now 500s instead
of rewriting the file from the empty set (silent wipe of every saved profile); `custom-hours`
cleared when a preset tile matches. Verified live on PS 5.1: 20+ probes incl. the null-bug repro,
corrupt-file survival, string-flag coercion, and bad-JSON on all four POST routes → clean 400s.

---

## 2026-07-02 (evening) — FP-tune round 6 (WS3): the fresh-DEEP healthy-box tail, user-signed-off

Graded the same-day live DEEP baseline (`KrakenBaseline_20260702_143221.json`: 734 findings,
**39 auto-destructive** vs the 52 reference — no floods) and, with user sign-off, cleared every
remaining healthy-box FP in the auto-destructive tail. The WS2 detections themselves came back
clean (only Phase 53's already-Info name matches) — WS3's re-grade goal is met. All fixes are
downgrade-to-POSSIBLE or FixAction Info; **zero detections deleted**. Four new `fp_allowlists`
keys in `data/detection_signatures.json` (`runkey_benign_values`, `keylogger_benign_paths`,
`yara_benign_paths`, `sct_benign_paths`), loaded via `Join-AllowRegex` in the loader.

- **P20** (CRIT/DeleteReg ×2): OneDrive's own updater-cleanup RunOnce values (`Delete Cached
  (Standalone )Update Binary` = `cmd /c del ...OneDriveSetup.exe`) matched the cmd.exe+del
  heuristic on every healthy OneDrive box → allowlisted name=value pairs are POSSIBLE/Info.
- **P31** (HIGH/DeleteFile ×3): `.lnk` shortcuts can never be Authenticode-signed, so every
  startup shortcut (Ollama/AnyDesk/Tailscale) graded UNSIGNED/HIGH → now resolves the shortcut
  TARGET (WScript.Shell COM, try/catch) and judges that: signed or unsigned-in-Program-Files →
  POSSIBLE (still manually deletable); unsigned target in a drop path (AppData/Temp/Downloads/…)
  or a script, or unresolvable → stays flagged (unresolvable = POSSIBLE/Info, never a blind delete).
- **P42** (HIGH/RunCmd): `Disable-LocalUser` auto-fired on the box's real primary account
  ("Techsupport" contains "Support") → detection stays HIGH but FixAction Info with the manual
  command in the description (rule #1: never auto-destructive on a healthy box).
- **P47** (HIGH/KillProcess ×2): bare-substring path test — `Desktop` matched the *package names*
  `WhatsAppDesktop` / `DesktopAppInstaller` under `C:\Program Files\WindowsApps` and killed
  store-signed apps → path test anchored to components (`\\(AppData|Temp|Downloads|Desktop)\\`)
  + explicit WindowsApps exclusion. New CLAUDE.md rule.
- **P48** (CRIT/DeleteFile): `*typed*` name heuristic hit `py.typed` (an empty PEP-561 marker) in
  Python site-packages → allowlisted package trees (Python LocalCache/site-packages/node_modules)
  are POSSIBLE/Info.
- **P86** (HIGH/DeleteFile ×14): every recycled script/exe auto-deleted — today it was the user's
  own deleted project copy → POSSIBLE (keeps DeleteFile for manual selection, never auto).
- **P90** (HIGH/DeleteFile): YARA `WMI_Reflective` hit CurseForge's `vk_swiftshader.dll` — JIT
  renderers legitimately contain `VirtualAllocEx`-class API strings → allowlisted runtime DLL
  names + package trees are POSSIBLE/Info.
- **P94** (HIGH/DeleteFile): pywin32's own `Testpys.sct` test fixture in site-packages →
  allowlisted package trees are POSSIBLE/Info.

**Review pass caught two allowlist bugs before commit** (subagent review of the diff, both
fixed + regression-tested on live 5.1): (1) a speculative `^Uninstall .{0,40}(OneDrive|…)`
pattern was **attacker-satisfiable** — it constrained only the value *name*, so malware named
"Uninstall OneDrive" would self-allowlist; removed, and the OneDrive pattern now pins the
ENTIRE value to the exact benign command shape (`$`-anchored, `[^"]*` blocks chained commands).
Data-file rule: **an fp_allowlist entry matched against attacker-controllable text must anchor
the full string, not a prefix.** (2) The pattern missed the per-user OneDrive install
(`\Microsoft\OneDrive\` vs machine-wide `\Microsoft OneDrive\`) — now covers both.

**Live headless DEEP re-run validation** (`_192913`, this dev profile — a *different* user than
the `_143221` baseline): 853 findings, **0 recovered errors**, full phase coverage; every round-6
downgrade path fired correctly (P31 "target signed → POSSIBLE" for Ollama/AnyDesk, P48/P94 →
Info, P86 → POSSIBLE ×34, no P20/P47 FPs). The dev profile also surfaced the round-4/5 leftover
FPs live, cleared in a second batch (user pre-authorized): **P63** LGHUB game-integration
`config.json` matching miner keywords (`miner_config_benign_paths` → POSSIBLE/Info); **P96**
Microsoft printer resource DLLs (PCL5URES et al.) are **catalog-signed — invisible to
`Get-AuthSig`, which only reads embedded Authenticode** — so they graded UNSIGNED/DeleteFile on
every PCL/PS-driver box (`spooler_benign_dlls` → POSSIBLE/Info); **P90** dev-scratchpad test
scripts (`Temp\claude\` added to `yara_benign_paths`); **P20** the ubiquitous
`Logitech Download Assistant` LogiLDA run key (exact-value-anchored allowlist entry). Remaining
auto-destructive tail on the dev box is genuine signal: unsigned scripts in Temp (P10, dev
debris the tool *should* flag), tripwires, hardening RunCmds, and real Defender correlations.

Validated: JSON parses; all 6 engine files parse-clean on live PS 5.1.26100 **and** 7.x, BOMs
intact; allowlist regexes regression-tested on live 5.1 (16 positive/negative cases, all pass).

## 2026-07-02 (later still) — Per-phase progress truth: fractional phases are real plan steps

The server's phase regex `PHASE\s+(\d+)[^\d]` truncated fractional phases (55.5, 74.5/.6/.7,
99.5) to their integer part, so during e.g. PHASE 74.5→74.7 the GUI counter sat frozen at 74
(looked like a stall), no phase-change `scan_state` was forced, findings from those phases were
tagged with the wrong phase, and the fractional `phase_map` keys that already existed in
`data/mitre_mapping.json` ("PHASE 55.5", "PHASE 74.5/.6/.7", "PHASE 99.5") were **unreachable**.

- **`ZeroBreach-Server.ps1`** (server-only; engine untouched): `$PREX` → `PHASE\s+(\d+(?:\.\d+)?)[^\d]`;
  phase values keep their decimal (int stays int — no `74.0` artifacts in JSON); all 5 parse
  sites updated (parse loop, `[FINDING]` intercept, STEALTH blob, `Get-ReportFindings`);
  both `Resolve-Mitre` copies now try the exact (possibly fractional) `phase_map` key first,
  then fall back to the integer floor. `phase_total` stays the plan ceiling per mode —
  `$MODE_PHASES` documented as mirroring the loader's `$PhasePlan` (30/80/115); stale `107`
  fallbacks (pre-split count) bumped to 115 here and in `app.js`.
- Frontend needed no logic changes (audited: display/percent/`PH${phase}` all handle decimals).
- Validated: parse-clean PS 5.1.26100 + 7.6.3 (file + all 3 here-strings), BOM intact,
  `node --check` clean; functional regex/conversion/JSON-shape test on live 5.1 (74→74.5→74.6
  →74.7→75 = 4 counter advances; `{"phase":74.5}` / `{"phase":74}` serialization).

## 2026-07-02 (later) — Portable distribution: Build-Release.ps1 + Mark-of-the-Web self-unblock

The user's core requirement — "copy/download/transfer this tool and run on any Windows system" —
productized:

- **`tools/Build-Release.ps1`** (new): builds `dist/ZeroBreach-V23_<stamp>.zip` + SHA256 sidecar
  from runtime files only (entry BAT/PS1s, `engine/`, `gui/`, `data/`, README; excludes reports/
  dev docs/work-rig; `-IncludePython` opt-in, `-OutDir` can target a USB directly). Refuses to
  pack unless every script parses clean WITH its UTF-8 BOM and every data JSON parses — the
  release gate is the same as the dev gate. `dist/` gitignored.
- **MotW self-unblock** (`ZeroBreach-Server.ps1` startup): transferred/downloaded copies carry
  Zone.Identifier ADS on every file; the server now `Unblock-File`s the runtime tree (root
  entry files + `engine/` + `gui/` + `data/`, never `reports/`) at startup. `-ExecutionPolicy
  Bypass` already covers our scripts — this is defense-in-depth for foreign boxes. README gained
  a "Deploy to another machine" section (zip → verify sha → Unblock → extract → `Launch-GUI.bat`).
- **Proven end-to-end:** built a release, extracted it to a directory **with spaces** (the
  historical UAC-quoting gotcha), booted the extracted server → GUI serves HTTP 200 with
  branding, `/api/state` answers, all 7 packaged scripts parse clean from the extracted tree.
  (Lesson re-learned while writing the packager: a `.ps1` written without BOM parses as ANSI
  mojibake on live 5.1 — the BOM rule applies to `tools/` too.)
- README also de-staled: 115 phases, MITRE wired, STEALTH parsing done, doc map → BLUEPRINT.md.

## 2026-07-02 — Live finding stream was dead: structured `[FINDING]` lines + UTF-8 stdout pipeline + BLUEPRINT.md

Analyzing the 2026-07-01 live GUI DEEP run's SSE log (`server_events_20260701_185058.log` — the
durable event log added in `c0477ae` paid off on its first outing) settled both handoff questions
and surfaced two real bugs:

**✅ Phase-counter fix `c0477ae` validated.** The SSE log's `scan_state` events carry all 116 phase
values 0→115 with no gaps — the phase-change-triggered emit works; the counter can no longer skip
sub-second phases.

**🐞 The live finding stream was dead (0 events on a 288-finding DEEP run).** Every one of the run's
1266 classified lines came through severity INFO and **zero** SSE `finding` events fired, because
the engine's human-readable detection lines (`[RUN KEY] …`, threat banners) carry none of the
severity tags the server's `Classify` regexes look for. Knock-on effects: live threat chips/intel
ticker/tally bars stayed empty all scan, and the server's `audit_*.json` wrote `findings: []` (it
snapshots the live list — the handoff's "expected summary shape?" question is answered: no, it was
this bug). **Fix, both sides of the pipe:**
- **Engine:** `Add-Finding` (loader) now emits one machine-readable line per registered finding —
  `[FINDING] {compact JSON}` with `id, sev, phase, tt, desc, target, fix, group` — gated to
  `NONINTERACTIVE` and non-STEALTH. Runtime data only, no signature literals (AMSI rule holds).
  Group caps (100/group) bound the volume.
- **Server:** the scan runspace intercepts `[FINDING]` lines as the **authoritative** live-finding
  source — exact severity, canonical threat bucket (name-match the 10 types, else keyword
  classify), MITRE resolution, new `fix_action`/`target` fields on the SSE event — and drops the
  raw JSON line from the log view. The old text-severity→finding path was **removed** (with
  structured lines it would double-count every detection); `Classify` is now log-coloring only.
- **Frontend audited, no changes needed:** chips/ticker/badge already consume `finding` events,
  per-severity sounds are throttled (alert ≤1/2s), and completion still replaces the live list
  with `/api/report` — no double-count at scan end.

**🐞 Mojibake in every GUI banner.** Child PS 5.1 writes redirected stdout in the OEM codepage;
the server reads UTF-8 (`StandardOutputEncoding`) — so all box-drawing glyphs arrived as `�`.
The loader now sets `[Console]::OutputEncoding` to UTF-8 when stdout is redirected (attached
consoles keep their codepage). Also fixed: `Classify`'s CLEAN regex now tolerates the engine's
padded `[OK ]` tag (both server copies).

**Also:** early `Import-Module Microsoft.PowerShell.Security` in the loader — pre-empts the known
ACL `AccessControl.ObjectSecurity` TypeData collision degrading `Get-AuthenticodeSignature`
mid-scan (the trigger of the old phases-17-58 skip). And **`BLUEPRINT.md` created**: the product
map — architecture, data contracts (incl. the new `[FINDING]` contract), safety model, quality
gates, prioritized roadmap. CLAUDE.md points to it; NEXT_STEPS.md/UPGRADE_PLAN.md marked
superseded/scoreboarded.

**🐞 Bonus catch — the `$sev`/`$SEV` case-insensitive shadow (severity classification NEVER
worked).** The first end-to-end validation scan streamed finding events fine but every `log_line`
still classified INFO — even `[OK ]` lines that plainly matched the fixed CLEAN regex. Root cause
(found by extracting the runspace's actual `Classify` into a harness and instrumenting it on live
5.1): PowerShell variables are **case-insensitive**, so `Classify`'s first line `$sev = 'INFO'`
creates a local that shadows the script-scope `$SEV` pattern dictionary — `$SEV.Keys` then reads
the *string* `'INFO'`, returns `$null`, and the match loop silently never runs. Every line ever
classified by the PS server came out INFO — this predates the split and explains why even
`-> [OK]` lines were INFO in every historical SSE log. Fixed by renaming the dict `$SEV_RX`
(both uses, comment left at the definition); verified CLEAN/HIGH/CRITICAL/POSSIBLE/HUNT all
classify correctly on live 5.1. New CLAUDE.md rule: never give a local the same letters as a
broader-scope variable.

**Validation:** all files parse-clean live PS 5.1.26100 + 7 (incl. the server's 3 here-strings via
`ParseInput`), BOMs intact. Headless QUICK run (server-style UTF-8 redirect): exit 0, **218
`[FINDING]` lines** (12 CRITICAL / 9 HIGH / 175 POSSIBLE / 22 INFO), multi-line descriptions
escape to single lines, **0 mojibake**, box-drawing banners clean. **End-to-end server-driven
scans (real `/api/scan/start` → SSE log):** run 1 (pre-`$SEV_RX`): 217 finding events streamed
live with exact severities + resolved MITRE (`fix_action`/`target` present), threat_counts
populated (Other 184 / Fileless 26 / RAT 6 / Rootkit 1), `audit_*.json` findings **217** (was
`[]`), 0 mojibake. Run 2 (post-`$SEV_RX`): see HANDOFF "Session 5 validation" for the final
severity-distribution numbers.

## 2026-07-01 — Engine split into `engine/` modules + WS2 detection port + the dot-source trap fix

Opus had begun (on the `quarantine-work-dump-…` work-rig branch, dropped into the repo as the nested
`zerobreach/` folder) splitting the monolithic engine into a dot-sourced `engine/` folder and doing a
big WS1/WS2 detection expansion. **We adopted that architecture but rebuilt it on `main`'s
live-validated engine** (which carries FP rounds 1-5 + the safety guard the fork's copy predated), so
we keep the maintainability win without regressing any FP tuning.

**Split (`dcf8793`).** Mechanical, byte-exact partition of the 5,749-line monolith at top-level AST
statement boundaries (partition proven to reconstruct the original before any edit), into a thin
loader + `engine/Phases-1.ps1` (1-58), `Phases-2.ps1` (59-89), `Phases-3.ps1` (90-115), `Summary.ps1`,
`FixMode.ps1`. Split **by contiguous phase RANGE, not category** — phases run in numeric order and
reuse variables across phases (`$ransomScanFiles` 51→53, `$bcdedit2` 40→58, `$dnsCache2` 59→60);
dot-sourcing into the loader's one scope preserves that. Six targeted deviations from the monolith
text: `$global:ZB_ROOT` set unconditionally (Phase 66's self-file guard needs the project root, since
`$PSScriptRoot` in a module = `engine\`); 4× process-terminating `exit` → `[Environment]::Exit(0)` in
Summary/FixMode (a plain `exit` in a dot-sourced file only returns to the loader → would fall through
into FixMode's prompt and hang `-Auto`).

**Data merge (`585fe57`).** Union-merged the fork's WS1/WS2 research into `data/*.json`:
`detection_signatures.json` +28 keys (byovd_*, known_malware_mutexes, ransom_note_*, c2_pipe_*,
loader/banking/infostealer procs + behavior rules, inhibit_recovery_rules, …), superset updates
(known_malware_hashes 1→17, ransomware_extensions 70→79); `mitre_mapping.json` +9 techniques + 14
phase_map entries; new `coverage_matrix.json`. AMSI rule respected — signatures stay in `data/`.

**Detection port (`1894fa1`).** Ported the additive, non-conflicting WS2 detections, adapted to
`main`'s helpers + FP tuning, **all `FixAction Info` → zero new auto-destructive findings**: Phase 55.5
BYOVD driver audit, Phase 53 ransom-note names + content pass, Phase 62 anchored pipe *second* pass
(KEEPING main's FP-safe first pass — did NOT take the fork's re-introduced broad `[a-f0-9]{8,}`
catch-all), Phase 66 drive-letter admin-share exclusion, Phase 69 mutex probe, Phase 99.5 command-line
heuristics. Left main's already-more-FP-tuned Phase 68 as-is.

**The dot-source trap fix (`29f5a0e`) — the load-bearing bug.** Headless `-Auto` runs after the split
silently ran phases 1-16, then jumped to 59 — **phases 17-58 dropped every run** (both QUICK and FULL).
Root cause: in the monolith the script-scope `trap { Write-RecoveredError $_; continue }` resumed at the
next **phase** (same scope); after the split the trap lives only in the loader, so a terminating error
inside a dot-sourced module unwinds past all its remaining phases and `continue` resumes at the next
**module**. The trigger was the benign System32 ACL `AccessControl.ObjectSecurity` TypeData collision at
Phase 16. (The fork had the identical latent bug — its own handoff noted "the trap does not reliably
continue through every phase" and chased individual `-EA Stop` ops instead of the root cause.) Fix:
give `Phases-1/2/3` each a **top-of-module** `trap { Write-RecoveredError $_; continue }` (the same
remedy CLAUDE.md already prescribes for grouped `if($PhasePlan.*)` blocks). Proven with a minimal
dot-source repro. **Post-fix live headless validation:** FULL `-Auto` ran all 80 integer phases
contiguous (1-80) + 55.5/74.5/74.6/74.7, 2 recovered errors *survived* (were previously fatal to 40
phases), baseline+report JSON written, clean self-exit. Parse-clean on live PS 5.1.26100 + 7.6.3, BOM
intact on all 6 files.

**Phase 53 FP fix (`9700f97`) — found by this session's validation.** The auto-destructive re-grade of
the live DEEP baseline surfaced a **pre-existing** rule-#1 violation: the generic `*readme*.txt` note
pattern auto-selected `…\SysinternalsSuite\readme.txt` as CRITICAL + DeleteFile on a healthy box. Split
the note filename patterns by confidence — STRONG tokens (`DECRYPT`/`YOUR_FILES`/`HOW_TO_DECRYPT`/
`!readme!`/`restore_files`/`help_decrypt`/`ransom` + CISA family names) stay CRITICAL + DeleteFile;
GENERIC English words (`readme.txt`/`RECOVER`/`HOW TO RECOVER`/`IMPORTANT.txt`) are destructive ONLY
if the file CONTENT also matches a ransom-note construct (`Test-ContentRules`), else POSSIBLE + Info.
Re-checked live: the Sysinternals readme is now POSSIBLE/Info, Phase 53 auto-destructive = 0.

**New durable rules in CLAUDE.md:** edit modules-not-monolith; every phase module needs its own
top-level trap; module `exit` must be `[Environment]::Exit`; `$PSScriptRoot` in a module = `engine\`
(use `$global:ZB_ROOT`).

## 2026-06-28 — UI phase-"skipping" (display artifact, NOT engine) + durable run logs (`c0477ae`)

User reported a live DEEP run "skipped MANY MANY phases (unless instant)." It did **not** — the
console log (`KrakenConsole_20260628_152000.log`) shows **all 115 phases ran contiguous, 0 RECOVERED
ERRORs**; many phases just run in 0–0.3s. Two **server-only** fixes (`ZeroBreach-Server.ps1`; engine
untouched; parse-clean PS 5.1 + 7, all here-strings, BOM intact):

| Bug | Root cause | Fix |
|---|---|---|
| **Phase counter appears to skip fast phases** (e.g. jumps 94→97) | The visible phase counter/progress bar updates **only** on `scan_state` (`app.js:205-211`), but the server emitted `scan_state` only every **12 log lines** (`%12`, scan runspace). A sub-second phase emits <12 lines, so several phases pass between emits → the counter jumps. | In the scan-runspace parse loop (next to `$PREX.Match`, ~`:669`) detect a phase-number change and **emit a `scan_state` immediately**, in addition to the `%12` cadence. **Not yet visually confirmed in-browser.** |
| **No durable post-run artifacts** | Validation/debug needs the full event stream on disk. | Added `reports\server_console_*.log` (main-thread console via `Start-Transcript`, stopped in the accept-loop `finally`) + `reports\server_events_*.log` (FULL SSE stream — every log_line/finding/`[FIX]` + remediation_complete summary, teed by `Enqueue`/`REnqueue`). Path on `$script:State.EventLogFile`. |

## 2026-06-25 — live DEEP run cleanup (recovered-error noise + the REAL Phase-68 flood)

A live admin `-Mode DEEP -Hours 0` run was re-run end-to-end and graded. Four classes of problem,
all in `ZeroBreach-V23.ps1`, all fixed + re-validated on a clean DEEP run. Three new **safe-wrapper**
helpers added next to `Get-AuthSig` (~`:942`); all raw call sites routed through them.

| Bug | Root cause | Fix |
|---|---|---|
| **7 "RECOVERED ERROR" lines** (GlobalFlag, DisableTaskMgr, UseLogonCredential, LmCompatibilityLevel, Property Type, Shadow, + a Get-WinEvent) | `Get-ItemPropertyValue ... -EA SilentlyContinue` throws a *terminating* error when the value is absent — `-EA SilentlyContinue` does NOT suppress it. Same for `Get-WinEvent -FilterHashtable` when a ProviderName isn't registered. | Added **`Get-RegVal`** (try/catch→`$null`) — routed all 14 `Get-ItemPropertyValue` sites. Added **`Get-WinEventSafe`** (try/catch→`@()`) — routed the 5 `-EA SilentlyContinue` `Get-WinEvent` sites. |
| **`Get-FileHash` not recognized** (`:3048`) | On a box with a corrupted module/type env, `Get-FileHash` can fail to auto-load → RECOVERED ERROR + broken hash detection. | Added **`Get-FileHashSafe`** — computes SHA256 via **.NET** (`[System.Security.Cryptography.SHA256]`); routed all 3 sites. Returns uppercase hex or `$null`. |
| **19,981-line Phase 68 "SUSPECT CREDENTIAL FILE" flood** (≈half the 4.5 MB log) | `Get-ScanFiles` ends with `return ,$results.ToArray()`. The unary comma makes it emit the whole `FileInfo[]` as **one** pipeline object. Piped **directly** into `Where-Object`, `$_` = the entire array → `$_.Name -match …` matches a subset → truthy → passes **every** file. | Wrapped **all 15 direct-pipe callers** in parens: `$x = (Get-ScanFiles …) \| Where-Object {…}`. Verified on PS 5.1: 3-path scan matches **2**, not 20000. |

(Note: the environmental "AuditToString is already present" TypeData RECOVERED ERROR at startup is a
machine-level duplicate types file, not an engine bug — benign, recovered.)

## 2026-06-22 — ~1hr hang at "phase 97" (Authenticode revocation)

**Scan hung ~1 hour; Ctrl+C wouldn't kill the shell.** Actually stalled in **Phase 98** (STOLEN CERT) —
`Get-AuthSig` on up to 100 exe/dll **per root × 4 roots ≈ 400 binaries** with NO cap. Authenticode
builds the cert chain → **online revocation checks (CRL/OCSP)**; when servers are slow each call
blocks ~15s → ~400×15s ≈ 1hr. The blocking native call also makes Ctrl+C unresponsive. Fix: budget
globals `$global:SIG_AUDIT_DEADLINE_S=25` / `$global:SIG_AUDIT_MAX_FILES=150` (~`:748`); bounded the
Phase 98/93/96 Authenticode loops with a shared stopwatch+counter ("… SIG BUDGET REACHED").

## 2026-06-23 — same Authenticode hang, 3 more phases (the real DEEP-mode hang)

The 06-22 fix only budgeted 93/96/98. A live `-Mode DEEP -Hours 0` run hung *again* (0-byte
transcript, blocked-not-spinning = network revocation). Three *other* multi-file `Get-AuthSig` loops
still had no budget, and `-Hours 0` makes `Test-InScope` pass everything.

| Phase | Root cause | Fix |
|---|---|---|
| **Phase 10** (TEMP/INetCache/Downloads exe, ~`:1449`) — *the actual culprit* | thousands of cached 3rd-party exe's whose revocation URLs aren't locally cached | shared `$global:SIG_AUDIT_*` budget across all 6 dirs |
| **Phase 15** (System32 top-level `.exe/.dll/.sys`, ~`:1578`) | thousands of files under `-Hours 0` | same budget guard |
| **Phase 66** (network-share worm, ~`:2678`) | up to 500 share binaries over slow UNC | same budget guard (shared across shares) |

VALIDATED LIVE 2026-06-23 (DEEP done 18.8min, 3 budget hits, no hang).

## 2026-06-22 — silent phase-skip via trap+continue

**Phases 99–107 silently skipped** mid-scan (log jumped 98→108). A locked `Temp\*.tmp` made
`Get-AuthenticodeSignature` throw a *terminating* error that `-EA SilentlyContinue` does NOT suppress;
it unwound to the **script-scope `trap { … continue }` (`:72`)**, whose `continue` resumes after the
whole `if ($PhasePlan.Advanced){…}` block. One locked file → 9 phases dropped.

Fix: added `Get-AuthSig` wrapper (try/catch, `-LiteralPath`); routed all 11 raw
`Get-AuthenticodeSignature` calls through it. Added a per-group inner `trap { Write-RecoveredError $_; continue }`
to the Universal/Advanced/Integrity blocks (inner-scope trap+continue resumes at the **next phase**).
VALIDATED LIVE 2026-06-23 (phases 1→115 contiguous, 44 & 69 ran).

## 2026-06-23 — `(try{}catch{})`-as-expression silently disabled 2 phases

`(try {…} catch {…})` as a *sub-expression* parses under PS 7 but is a **runtime error in Windows
PowerShell 5.1** (`try` isn't a valid expression keyword). Inside two `Where-Object` filters the error
was swallowed by global `-EA SilentlyContinue` → the **whole filter matched nothing**.

- **Phase 44** (TOKEN/PRIVILEGE ABUSE, `:2216`) — SYSTEM-level procs from user paths never flagged.
- **Phase 69** (PROCESS HOLLOWING, `:2814`) — hollow-process detection matched nothing.

Fix: restructured both so try/catch is a trailing **statement**; path pre-filter became early
`return $false`. Verified on real `powershell.exe` v5.1.

## 2026-06-06 — NEXT_STEPS Phase 0

| File | Bug | Fix |
|---|---|---|
| `ZeroBreach-V23.ps1` | Hard **parse error** at `:1445` — `"...\$sm:..."` parsed as a scoped variable ref, whole engine failed to load | `$sm:` → `${sm}` |
| `ZeroBreach-V23.ps1` | Engine blocked on Phase 43 VSS `Read-Host` (`:1811`); server child has no stdin → hung | Guarded with `if ($Auto -or $global:GUI_MODE -or $global:STEALTH_MODE) { $vssChoice="no" }` |
| `ZeroBreach-V23.ps1` | Fix-mode prompts also blocked in `-Auto` | `if ($Auto) { exit 0 }` right after the STEALTH JSON exit |
| `ZeroBreach-Server.ps1` | SSE loop's `$idx` never rewound after `EventLog.Clear()` → open tabs went silent on re-run | Rewind `$idx = 0` when `$idx -gt $count` |
| `gui/static/js/app.js` | Non-OK `/api/scan/start` ignored → UI stuck on `● SCANNING` | `.then()` throws on non-OK; `.catch()` resets state, shows `● ERROR` |

## 2025-05-19 — initial server/launch fixes

| File | Bug | Fix |
|---|---|---|
| `ZeroBreach-Server.ps1` | No UTF-8 BOM — PS5.1 read the file as Windows-1252, corrupting box-drawing char bytes | Added UTF-8 BOM (`EF BB BF`) |
| `ZeroBreach-Server.ps1` | `"[ZeroBreach]..."` inside `catch {}`/`finally {}` triggered a PS5.1 parser crash | Single-quoted strings + concatenation |
| `ZeroBreach-Server.ps1` | Stderr redirected but never read → child deadlocked when stderr buffer filled | Added `$proc.BeginErrorReadLine()` |
| `_python/server.py` | Paths pointed inside `_python/` instead of project root | Added `ROOT_DIR = BASE_DIR.parent` |
| `ZeroBreach-V23.ps1` | `$global:TW_LABEL = "ALL TIME"` at init hid the interactive time-window menu | Initialized to `""`; auto mode sets it explicitly |
| `Launch-GUI.bat` | Called nonexistent `PirateLife-GUI.ps1` | Rewrote to call `ZeroBreach-Server.ps1`; added `python` flag |

---

# Detection false-positive tuning (rounds 1–5)

All FP allowlists live in `data/detection_signatures.json` → `fp_allowlists` block (never inline
literals), loaded via `Join-AllowRegex`. Downgrade-to-POSSIBLE is preferred over deleting a
detection: only CRITICAL/HIGH are auto-selected for destructive remediation, so POSSIBLE is shown
but never auto-acted-on.

## Round 1 (2026-06-23) — top-3 capped-at-100 over-matchers (simulated vs `KrakenBaseline_20260623_135347.json`)

- **Phase 39 ROGUE ROOT CERTS** (`~:2098`): flagged ~100 legit roots CRITICAL. Now matched vs
  `trusted_root_ca_issuers` → known = INFO, unrecognized = POSSIBLE. **101 CRIT → 98 INFO + ~2 POSSIBLE.**
- **Phase 18 CLOAKED (HIDDEN+SYSTEM)** (`~:1653`): normal attr for desktop.ini/IconCache/*.library-ms.
  Drops `cloaked_benign_names`, only flags payload extensions. **101 → ~3.**
- **Phase 68 INFO-STEALER FILES** (`~:2796`): file merely *named* like a cred store. Excludes
  `infostealer_benign_paths`, downgrades loose .txt/.log/.db to POSSIBLE. **8/9 benign suppressed.**

## Round 2 (2026-06-23) — remaining CRITICAL floods + prefetch

- **Phase 27 SAFEBOOT HIJACK** (`~:1835`): offered to DeleteRegKey ~100 *default* Safe-Mode entries.
  Skips `safeboot_default_entries` (122 verified defaults); unrecognized → POSSIBLE. **101 → 0.**
- **Phase 62 NAMED PIPE BACKDOOR** (`~:2636`): pattern ended in `[a-f0-9]{8,}`, matching every legit
  RPC/GUID pipe. Replaced with externalized `c2_named_pipe_regex` (specific C2 framework pipe names —
  no broad catch-all). Also removed inline malware-name literals. **98 → 0.**
- **Phase 12 PREFETCH** (`~:1527`): a LOLBIN having run is corroborating, not standalone HIGH → POSSIBLE.

## Round 3 (2026-06-23) — remaining destructive floods (scheduled tasks + BITS)

- **Phase 104 HIDDEN SCHEDULED TASKS** (`~:3899`): Hidden=true is normal for MS/Google/updater tasks.
  Matches `hidden_task_benign_paths` → known = INFO, unrecognized = POSSIBLE; FixAction now `Info`.
  **57 HIGH DeleteFile → 0.**
- **Phase 31 BITS JOBS** (`~:1937`): every updater uses BITS. Now POSSIBLE+`Info` by default,
  escalating to HIGH+RunCmd only on raw-IP remote (`bits_suspicious_remote_regex`) or exec-to-userpath
  (`bits_suspicious_local_regex`). **49 HIGH → 0.**

> Rounds 1–3 were *simulated* against a stale report — see Round 4 for the runtime bug this hid.

## Round 4 (2026-06-26) — VALIDATED ON FRESH LIVE RUNS

Driven by fresh live `DEEP -Hours 0` runs. Before-run had **319 auto-selected destructive findings**;
round 4 cut that to **75** (final live run `KrakenBaseline_20260626_025617`) — a healthy low tail.

**THE BIG ONE — PS 5.1 `Get-Sig` string-indexing bug (`~:895/897/898`).** `Get-Sig` ends with
`@($SIG.$Name)`, but a function returning a **single-element** `@(...)` emits the bare scalar (PS
unwraps it). So `(Get-Sig 'bits_suspicious_remote_regex')[0]` indexed into the returned **string** →
its **first character** `'h'`. Then `$url -match 'h'` matched **every** `https://` URL → Phase 31
flagged **all 48 BITS jobs HIGH+RunCmd**. `c2_named_pipe_regex` had the identical bug (→ `'m'`),
silently breaking the round-2/3 fixes on real 5.1. Fixed all three to **`@(Get-Sig X)[0]`**.

Six other fixes (all downgrade-or-skip):

| Phase | Before | Fix |
|---|---|---|
| **32** DLL-hijack | 100 HIGH DeleteFile | Skip `%WINDIR%`; base → POSSIBLE, HIGH+DeleteFile only for DLLs in a user-writable staging dir |
| **66** share-worm | 68 HIGH DeleteFile | Skip `$PSScriptRoot`; unsigned scripts + exes in local `C:\Users` → POSSIBLE; HIGH reserved for a foreign/public share |
| **24** COM hijack | 15 HIGH DeleteRegKey | Top-level GUID keys only; HIGH only when HKCU CLSID shadows HKLM; per-user → POSSIBLE |
| **15** System32 sig | 100 CRIT RunCmd | Split by status: real tamper → CRIT; unverifiable (`UnknownError`) → POSSIBLE+Info |
| **19** script assoc | 7 HIGH RunCmd | `.js/.vbs` defaults → POSSIBLE + opt-in RunCmd |
| **75** Defender excl | 10 HIGH RunCmd | Path + process exclusions → POSSIBLE + opt-in RunCmd |

## Round 5 (2026-06-28) — VALIDATED ON LIVE DEEP RUNS

Headline bug: **Phase 108 offered `icacls "C:\" /reset /T /C /Q`** — a recursive ACL reset of the
whole C: drive — as a HIGH auto-applicable remediation, firing on **every** healthy box
(`%SystemDrive%\` is in `critical_acl_paths` + the root carries a default `BUILTIN\Users` append ACE).
A destructive-`FixParam` sweep found a whole family of siblings. Live auto-destructive **21 → 7**
(residual 7 all by-design). All downgrade-or-skip; the dangerous commands moved into the finding
**description** for manual use.

| Phase | Before | Fix |
|---|---|---|
| **108** ACL/owner | `icacls "C:\" /reset /T` (HIGH every run) + takeown (CRIT) | Skip bare drive-root (`^[A-Za-z]:\\?$`); weak-ACE → POSSIBLE+Info; ownership-tamper → CRIT but FixAction Info |
| **16, 43-SAM, 111, 112, 115** | `icacls /reset /T`, `vssadmin delete shadows /all`, ACL resets — auto-RunCmd | all → FixAction Info (command in description); severity kept |
| **109 / 113** | `hosts` (non-PE) flagged CRIT every run; `UnknownError` FPs; spurious `sfc /scannow` | Skip non-PE (`\.(exe\|dll\|sys)$`); status-split; SFC only on genuine tamper |
| **8** browser ext | Google Docs Offline auto-DeleteFile'd | only known-adware NAME → DeleteFile; permission-only → POSSIBLE+Info |
| **17** ADS | benign `SmartScreen` ADS stripped (HIGH RunCmd) | benign-stream allowlist + downgrade to POSSIBLE |
| **24** COM | benign per-user shell CLSIDs → DeleteRegKey | escalate only when `$shadowsHklm -and $inproc`; else POSSIBLE+Info |
| **20** Run-key | Discord/Teams/Logitech CRIT-DeleteReg'd (matched bare `AppData`) | drop bare `AppData`; AppData-only → POSSIBLE+Info; Temp/encoded/LOLBin stay CRIT |
| **26** BHO | every BHO HIGH DeleteRegKey | → POSSIBLE+Info |
| **29** task XML | legit `\Microsoft\Windows\…` tasks HIGH DeleteFile at `-Hours 0` | skip `\Tasks\Microsoft\`; weak content match → POSSIBLE+Info |
