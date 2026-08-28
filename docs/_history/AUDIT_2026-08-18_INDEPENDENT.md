# Scythe — Independent Audit (second pass), 2026-08-18

**Auditor:** fresh independent read of the live stack. I deliberately did **not** read the finding
bodies of `SECURITY_AUDIT_2026-08-18.md` before auditing, so overlap below is *independent
confirmation*, not agreement with a document I had just read. Reconciliation with that pass is in
§7.

**Scope:** live stack only — `Scythe-Server.ps1`, `Scythe-V23.ps1`, `engine/*.ps1`,
`gui/**`, `data/**`, `tools/**`, `Launch-GUI.bat`. Parked `_python/` and `_archive/` excluded per
instruction (risk notes only, §6).

**NOTHING HERE HAS BEEN FIXED. NOTES ONLY.** Every finding is for Opus/Fable to action.

### Method + honest limits — read this before trusting a severity

This was **static analysis only.** The audit box is Linux and has **no PowerShell installed at
all** (`which pwsh powershell` → nothing), so:

- Zero findings were runtime-confirmed. Nothing was executed, parsed by a real 5.1 runtime, or
  reproduced.
- Findings marked **[STATIC]** are certain from reading alone (a dead variable, a missing `trap`,
  a hardcoded URL). Findings marked **[NEEDS REPRO]** depend on Windows runtime behaviour I could
  not test (http.sys URL canonicalisation, `Remove-Item -Recurse` junction semantics, PS 5.1 error
  classes). Do not let a fix pass treat [NEEDS REPRO] as proven.
- I also do **not** have a malware sample set or a detonation lab, so §5 (detection quality) is
  reasoning about rules, not measured detection rates. Treat it as hypotheses to test, not results.

Twice during this audit my own `grep` returned a **false "0 matches"** (an output-compression layer
in the tooling swallowed results). Both times I re-ran with `grep -F` and corrected myself — once
about quote-escaping, once about GSAP/Chart.js being unused. **Any future audit of this repo should
verify negative grep results with `grep -F` / `grep -c` before concluding "absent."** One of the
corrections is noted in §7 because the *previous* audit's claim was right and my first read was
wrong.

---

## 0. STATUS UPDATE — empirical testing + fixes applied

After the initial static pass I installed **PowerShell 7.6.5 on this Linux box**, which allowed two
things that were previously impossible: parse-checking all 7 shipped files, and **executing the real
guard functions** (extracted from the shipped source via AST, not retyped) against attack vectors.
.NET regex behaves identically on Linux, so regex-based guard results are valid; anything touching
the Windows filesystem or registry is still `[NEEDS REPRO]`.

**Parse gate:** 7/7 files clean under PS 7.6.5, BOMs intact. *(PS 7 ≠ PS 5.1 — this does not prove
5.1 cleanliness. The `(try{}catch{})` and array-unwrap traps only surface on the real 5.1 runtime.)*

### Empirically settled

| Finding | Result |
|---|---|
| **C2 injection** | **PROVEN.** Phase 64's FixParam parses into **2 statements** with the injected command as statement 2. Phase 29's escaped version parses into 1. |
| **H7 path bypass** | **CONFIRMED, but far narrower than I guessed.** Only **forward slashes** bypass (`C:/Windows/System32/evil.exe` → ALLOWED, `C:/Users/bob/.ssh/id_rsa` → ALLOWED). |
| H7 — vectors I hypothesised | **REFUTED — chaff, do not fix.** 8.3 short names, UNC admin shares, `\\?\`, `\\?\GLOBALROOT`, `%SystemRoot%`, `..` traversal, trailing space: **all correctly blocked** by the unanchored `\\(System32\|SysWOW64\|WinSxS)\\` clause. |
| **NEW — H7b: `RunCmd` content is never inspected** | **CONFIRMED.** Every one of `vssadmin delete shadows /all /quiet`, `netsh advfirewall reset`, `cipher /w:C`, `wbadmin delete catalog`, `reg delete HKLM\SOFTWARE /f`, `bcdedit /set safeboot minimal`, `Stop-Service WinDefend`, `net user administrator <pw>` passes the guard **untouched**. The "HARD BLOCK, defence-in-depth" claim holds only for path-shaped FixParams; for the single most dangerous action (54 call sites) the guard is a **no-op**. |
| **H3 `Get-FixClass`** | **CONFIRMED.** `RunCmd`+CRITICAL returned `RECOMMENDED+SAFE`; `$destructive` was assigned and never read. |
| C2 — WMI sites (`Phases-1.ps1:820,828`) | **REFUTED — already escaped** via `$fName`/`$cName` at 815/824. Not vulnerable. |
| C2 — IFEO site (`Phases-3.ps1:852`) | **REFUTED** — `$ifeo` is a constructed constant path, not attacker-controlled. |
| C2 — `Phases-2.ps1:834` | **REFUTED** — `$svcName` iterates the literal `@("WinRM","sshd")`. |

### Fixes applied this session (all parse-clean, BOMs preserved)

| Finding | Change |
|---|---|
| **C2** | Added `ConvertTo-PsLiteral` to the loader and applied it at **10 interpolation sites** across `Phases-1/2/3`. Re-tested: the Phase 64 FixParam now parses to **1 statement**, and `-TaskName` still round-trips to the exact original name (a naive escape would have broken the remediation itself). |
| **H3** | `Get-FixClass` rewritten. `RunCmd` moved to `$destructive`; `$safe` reduced to `Info`+`Quarantine`; `$destructive` is now load-bearing and a `DESTRUCTIVE` tag is emitted. "SAFE ONLY" now selects only genuinely non-damaging actions. Verified against all 7 actions × 2 severities. |
| **H4** | Module-level `trap { Write-RecoveredError $_; continue }` added as the first statement of `Summary.ps1` and `FixMode.ps1`. |
| **H8** | Added `ConvertTo-CsvSafeCell` and wired it into `Get-CsvReport` — neutralises leading `= + - @ \t \r \n`. **Note: the engine's HTML report has a *second* CSV writer (`Summary.ps1:251`, `exportCSV()` in embedded JS) that is NOT yet fixed.** |

### Session 2 (overnight) — CRITICAL + HIGH tier closed

| Finding | Change |
|---|---|
| **C1** | Per-launch 64-hex token from `RNGCryptoServiceProvider` required on every `/api/*` call (`?t=` or `X-SCYTHE-Token`); Origin lockdown on every route; listener rebound to `127.0.0.1`; **all** `Access-Control-Allow-*` headers removed incl. SSE + preflight; nosniff/Referrer-Policy/X-Frame-Options/CSP added. Frontend `scytheApi()` wraps all 13 call sites, token cached in sessionStorage then stripped from the URL, tokenless load shows a plain-language overlay. |
| **C3** | GSAP + Chart.js vendored to `gui/static/js/vendor/` (verified against cdnjs's published SRI), 27 woff2 subsets + `fonts.css` vendored, `@import` removed, both scripts `defer`red, build manifest extended with `$requiredDirs`. **Verified in Chrome: zero non-local requests.** |
| **H1** | Snapshot is now a folder of individually-valid `.reg` exports + a generated `Restore.cmd` + `README.txt`; `Checkpoint-Computer` actually attempted and honestly reported; banner and all three stale `regedit /S` references corrected. |
| **H2** | `ReadToEndAsync` replaces the discard-everything `BeginErrorReadLine`; `ExitCode` read; non-zero exit **or** zero phases parsed emits `scan_failed` (never `scan_complete`); stderr surfaced; remediation stays locked; GUI renders a red "NOT A CLEAN RESULT" panel. |
| **H5** | `Get-KillParam` encodes `pid\|name\|startTicks` at all 26 sites; both executors re-verify identity and skip on a recycled PID. |
| **H6** | `-Recurse` dropped from `DeleteFile`; reparse points and directories refused; server re-guards the **resolved** path; engine moved to `-LiteralPath`. |
| **H7** | `ConvertTo-GuardPath` normalises before every test — **the confirmed forward-slash bypass is closed**, and all previously-blocked vectors still block. |
| **H7b** | `Test-DestructiveRunCmd` + 21 direction-aware patterns. All 8 audit vectors blocked; all 17 real engine `RunCmd` fixes still allowed (`netsh advfirewall reset` is a genuine engine fix despite appearing on the dangerous list). |
| **H9** | `Running`/`Remediating` claimed synchronously on the request thread, released if the runspace fails to launch. |
| **H10** | `Get-RRegVal` + `Add-RPendingDelete` mirrors; both reboot-delete sites fixed; failure to queue now reported loudly. |
| **H8 (completed)** | Engine-side CSV writer now uses `ConvertTo-CsvSafeCell`. **Also fixed a bug not in this audit:** raw newlines were embedded in a single-quoted JS literal, so the HTML report's entire inline `<script>` was a SyntaxError — Export CSV, search, severity filters and column sorting were dead in every report. Rebuilt via `ConvertTo-Json` + `</` → `<\/`. |

**Regression suite added:** `tools/tests/Run-SecurityTests.ps1` — 135 assertions, all green.
Each test pulls the real functions out of the shipped source via the AST, so a test cannot
drift from the code it guards.

### Session 3 (2026-08-19) — MEDIUM tier closed

**M1–M11 are all closed**, along with the "newly noted" gap below. Commits `a62e132` (M2/M3/M4/M7),
`66eb11b` (M6/M8), `21e6ce5` (M1 + the engine guard), `6bd7410` (M5/M9/M10/M11). Narrative in
`CHANGELOG.md` → 2026-08-19; durable rules in `CLAUDE.md`.

Two things worth flagging because they change the audit's own conclusions:

* **M1 was bigger than reported, and part of it was a guard bug.** Running every engine
  `Add-Finding` through the real guard found **six** always-blocked fixes, not two. It also found
  the guard refusing *legitimate repairs*: the `RunCmd` path rules matched a path merely
  **mentioned** in a command (so restoring Winlogon `Userinit` was blocked by its own restore
  value), and `KillProcess` matched critical process names against the finding's **prose** (so
  "SYSTEM-level process running from user path" was blocked by the word SYSTEM). Both are now
  precise; deleting/renaming/overwriting a protected path is still refused.
* **`Test-GuardMirrorSync.ps1` had a hole.** It never loaded the guard's regex tables, so both
  copies were matching `''` — which matches everything — and agreeing for the wrong reason. It now
  loads every table and compares **three** copies (the engine's `Invoke-FixMode` guard is the new
  one).

**Newly noted (closed):** `engine/FixMode.ps1`'s interactive `Invoke-FixMode` had **no
protected-target guard at all**. A third mirror (`Test-EProtected` and its tables) now lives in the
loader and hard-blocks there, reporting `BLOCKED (PROTECTED)` in the fix summary and the report log.

### Session 4 (2026-08-19, later) — §5 items 1, 3 and 4 closed

Three of the seven §5 hypotheses could be settled by reading the code and testing the regexes
directly — no lab, no clean-machine baseline — so they are fixed and locked down by
`tools/tests/Test-FpAnchors.ps1` (54 assertions; verified to fail when the fixes are reverted).

| Item | Outcome |
|---|---|
| **§5.1** severity prose mis-colours | **Fixed.** The engine's bracket tag is now authoritative; the prose table is a fallback for untagged lines only. `[HUNT] CHECKING FOR SUSPICIOUS...` no longer grades HIGH, `-> [OK ] NO ANOMALOUS SERVICES.` no longer grades POSSIBLE. Mirrored in `_python/server.py` (whose `\[OK\]` also missed the engine's padded `[OK ]`). |
| **§5.2** threat buckets too broad | **Not a defect as filed.** `Classify`'s bucket is only a *fallback* for a finding whose own `tt` doesn't map to one of the 10 canonical names — ordinary log lines never reach the threat chips. A mis-bucketed finding is cosmetic. No change. |
| **§5.3** miner-task `coin` | **Fixed.** `coin` → `coin.?miner\|coinhive`, `pool\.` → `\bpool\.`. Was CRITICAL + `RunCmd Unregister-ScheduledTask` (auto-selected) firing on Coinbase/Coinstar/CoinTracker/`liverpool.exe` — a user-rule-#1 violation on a healthy box. |
| **§5.4** rogue-task bare `cmd` | **Fixed.** `\bcmd\b`, `[\\/%]AppData[\\/%]`, `[\\/%]Temp[\\/%]`, `\.jse?\b`. Bare `\.js` had been flagging every `--config foo.json`. All 11 true-positive vectors, including the CLAUDE.md tripwire, still fire. |
| **§5.5** `C:\Windows\Temp` unremediable | Open — a **decision**, not a bug. |
| **§5.7** alert-triage entry point | Open — a **feature**, not a fix. |

Also added `tools/tests/Verify-OnWindows.ps1`: the Windows half of validation (real 5.1 parse gate
incl. the runspace here-strings, the M9 ACL round-trip, the M5 urlacl add/delete cycle, log
retention, `HttpListener` bind, and with `-Live` the token/Origin/IOC/traversal surface over HTTP).

### Still open

§5.5 and §5.7 (a decision and a feature), the GUI pass, and **the live Windows run** — nothing in
sessions 2, 3 or 4 has been executed on Windows; the ACL and `netsh` code paths added for M5/M9
still have never run. `Verify-OnWindows.ps1` exists precisely to make that run one command.

---

## 1. CRITICAL

### C1 — Zero authentication + wildcard CORS on an API that deletes files and runs commands as admin
**[STATIC — chain is certain; only the port-discovery step is timing-dependent]**
`Scythe-Server.ps1` — `Write-JsonResponse` / `Send-StaticFile` / SSE all set
`Access-Control-Allow-Origin: *`; the `OPTIONS` handler additionally returns
`Access-Control-Allow-Methods: GET, POST, OPTIONS` and `Access-Control-Allow-Headers: Content-Type`.
There is no token, no `Origin` check, no CSRF nonce, and no `SameSite` anything (there are no
cookies to lean on either).

The server runs **elevated** (self-elevates at line ~26) and exposes:

| Route | What a foreign web page gains |
|---|---|
| `POST /api/remediate` | `DeleteFile`, `DeleteReg`, `DeleteRegKey`, `KillProcess`, **`RunCmd`**, `Quarantine` |
| `GET /api/report?name=` | full findings incl. absolute paths, and **`fix_param`** |
| `GET /api/sysinfo` | hostname, username, OS, Defender on/off |
| `POST /api/scan/start` | start scans; `GET /api/scan/abort` aborts (no method check) |

**Why the usual mitigations don't hold here.** The listener binds `http://localhost:$Port/`, so
DNS-rebinding *is* blocked — http.sys matches the `Host` header against the prefix and a rebound
host returns 400. But plain cross-origin `fetch()` from `https://evil.example` sends
`Host: localhost:PORT`, which **matches**, and `ACAO: *` lets the attacker page *read* the reply.
The random port is the only real barrier, and `GET /api/sysinfo` is a perfect oracle to sweep for
it from JS in a few seconds.

**Full chain:** operator is running Scythe on a box mid-incident → opens any tab (or a malicious
ad loads) → page sweeps localhost for the sysinfo oracle → `GET /api/report` to read a real finding's
`ID` → `POST /api/remediate {report, ids:[thatID]}` → the runspace executes that finding's
`FixAction`. If it is a `RunCmd` finding, that is **arbitrary command execution as admin, with no
operator interaction at all** — the PURGE modal is client-side only and is simply not in the path.

**Suggested direction (not applied):** bind to `127.0.0.1`, mint a random per-launch token, put it
in the URL the server opens, require it on every `/api/*` call, drop `ACAO: *` entirely (same-origin
needs no CORS header), and reject any request carrying an `Origin` header that isn't the server's
own. Add `X-Content-Type-Options: nosniff` and a restrictive CSP while you're in there.

---

### C2 — PowerShell injection into `RunCmd` FixParams (real, but only at *some* call sites)
**[STATIC for the code paths; [NEEDS REPRO] for whether Windows lets each specific artifact hold a `'`]**
`engine/FixMode.ps1:666-670` and the server's mirror both do
`[scriptblock]::Create($f.FixParam); & $sb` — i.e. `Invoke-Expression`. Many phases build that
FixParam by interpolating attacker-named artifacts into **single-quoted** PS literals.

The engine **already knows the fix** and applies it in two places:

```powershell
engine/Phases-1.ps1:479   $adsFile     = $s.FileName  -replace "'","''"     # Phase 17 — correct
engine/Phases-1.ps1:773   $taskNameEsc = $task.TaskName -replace "'","''"   # Phase 29 — correct
```

**The smoking gun** — the identical data type, one phase later, unescaped:

```powershell
engine/Phases-2.ps1:211   -FixParam "Unregister-ScheduledTask -TaskName '$($task.TaskName)' ..."
```
Phase 29 escapes the task name. **Phase 64 does not.** Same object, same property, same cmdlet.
And Phase 64's finding is `$SEV_CRITICAL`, so it is **auto-selected** in the GUI. A miner that
registers a task named `x';iex(...);'` gets its payload executed the moment the operator types
PURGE on a *correctly detected real threat*.

**Reachable (attacker fully controls the string):**

| Site | Interpolated | Severity | Auto-selected? |
|---|---|---|---|
| `Phases-2.ps1:211` | scheduled task name | CRITICAL | **yes** |
| `Phases-1.ps1:820,828` | WMI `__EventFilter` / `__EventConsumer` `Name` | — verify | verify |
| `Phases-1.ps1:762` | service key name (`$svc.PSChildName`) | — verify | verify |
| `Phases-2.ps1:852` | IFEO subkey (image file name) | — verify | verify |
| `Phases-2.ps1:792,801` | Defender exclusion path/process | POSSIBLE | no (manual click) |
| `Phases-1.ps1:1079` | firewall rule `Name` | POSSIBLE | no |
| `Phases-1.ps1:239` | `.lnk` full path | — verify | verify |

WMI subscription names (820/828) deserve priority: `__EventFilter`/`__EventConsumer` is a top-tier
persistence TTP, the name is 100% attacker-chosen, and it accepts characters a filename won't.

**Explicitly NOT vulnerable — do not "fix" these (chaff):**
- `Phases-2.ps1:834` — `$svcName` comes from the literal `@("WinRM","sshd")`. Not attacker data.
- `Phases-1.ps1:1106,1119` — cert `Thumbprint`, hex only.
- `Phases-1.ps1:849` — BITS `JobId`, a GUID.
- `Phases-3.ps1:996` — `$dv.key` / `$dv.name` come from our own `data/*.json`.
- `Phases-1.ps1:433`, `1265` — paths under `System32`, so `Test-ProtectedTarget`'s
  `\\(System32|SysWOW64|WinSxS)\\` **hard-blocks execution** regardless. (See M1 — that block
  creates a different problem.)

**Suggested direction:** escape at the boundary, not per-site — a single `ConvertTo-PsLiteral`
helper in the loader, applied to every interpolation, so a new phase can't reintroduce this.
Better still, retire free-text `RunCmd` for a structured `{verb, args[]}` FixParam the executor
dispatches without `[scriptblock]::Create`.

---

### C3 — An admin-privileged IR console pulls code from three public origins, with no SRI
**[STATIC — certain]** `gui/templates/index.html:34-35` and `gui/static/css/main.css:6`

> **Severity disagreement, flagged deliberately.** The earlier audit found the two CDN script tags
> and filed them as **L4 (LOW)**. I rate the same code **CRITICAL**. The reasoning is in this
> section — chiefly that it chains directly into C1's unauthenticated remediation API, and that this
> tool runs specifically on hosts whose DNS/TLS/proxy trust is already suspect. A fix pass should
> resolve this disagreement consciously rather than defaulting to the lower rating. The third
> origin (Google Fonts, below) was not in that audit.

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
```

No `integrity=`, no `crossorigin`, no local copy, no pin beyond the version in the path. Whatever
cdnjs returns executes with full DOM access in the page that can call `POST /api/remediate` — which,
per **C1**, needs no authentication. So: **remote JS → admin RCE**, chained.

What makes this worse than the usual "add SRI" note is *where this tool runs*. Scythe is
deployed onto **machines that are already compromised**, and it detects — in its own phases — the
exact primitives an attacker uses to control that fetch:

- Phase 36/37 — hosts-file hijack and DNS poisoning
- Phase 39 — rogue root CA in the trust store
- Phase 37 — malicious proxy configuration

So a box that fails Scythe's own Phase 36/37/39 checks can feed Scythe's GUI attacker-chosen
JavaScript. **The tool is vulnerable to the conditions it exists to find.**

Both libraries **are** used and both are correctly guarded (`if (window.gsap)` at `app.js:84,826`;
`if (!window.Chart) return` at `app.js:1499`), so an offline box degrades rather than crashes — I
initially believed they were unused and that was wrong. But two consequences remain:

1. **Silent capability loss offline.** No internet → the threat radar chart (`drawRadarChart`)
   simply never renders, with no message. An operator on an air-gapped or network-isolated incident
   box gets a quietly incomplete report.
2. **This is very likely the real cause of the blank/grey boot screen.** Both tags are
   **render-blocking in `<head>`** with no `defer`/`async`. Offline or behind a black-holing proxy,
   parsing stalls on connect timeouts — which is exactly the symptom the inline boot watchdog
   (`index.html:7-31`, 9s timeout, 2 reloads) was written to paper over. Vendoring these locally
   may let that whole workaround be deleted.

Also note `tools/Build-Release.ps1`'s `$requiredFiles` manifest ships **no vendored JS**, so the
"portable" zip is not actually self-contained. This directly blocks the standalone/portable goal
(§6).

**Suggested direction:** vendor both into `gui/static/js/vendor/`, add them to the build manifest,
add SRI only if you keep any remote origin at all, and add `defer`.

---

## 2. HIGH

### H1 — The rollback snapshot is advertised, promises more than it does, and produces an invalid `.reg`
**[STATIC — the file-format defect is certain from the code]** `engine/FixMode.ps1:8, 22-52`

The banner says *"A registry/VSS rollback snapshot will be created BEFORE any fixes."* Three
separate problems:

1. **The `.reg` file cannot be imported.** Line 43 builds the bundle starting with
   `@("SCYTHE V22 SNAPSHOT | ...", "="*80)` and then concatenates the raw text of five separate
   `reg export` outputs. `regedit /S` requires `Windows Registry Editor Version 5.00` as the
   **first line**; here the first line is a banner. Every concatenated export also carries its own
   header line mid-file. The advertised recovery command at line 49/756
   (`regedit /S "$SNAPSHOT_PATH"`) will therefore **fail**. The safety net the operator is told to
   rely on before destructive fixes does not work.
2. **There is no VSS snapshot at all.** `Checkpoint-Computer`, `vssadmin create`, `SystemRestore` —
   none appear anywhere in the engine. The word "VSS" in the banner is unbacked.
3. **No file-system rollback.** `DeleteFile` is irreversible and nothing snapshots it.
   (`Quarantine` *is* properly reversible — see §4.)

Also: `reg export HKLM\SYSTEM\CurrentControlSet\Services` and `HKCU\SOFTWARE\Classes\CLSID` are
very large on a real machine; this runs synchronously before the fix UI appears.

**Suggested direction:** write each export as its own file in a snapshot *folder* and emit a
`Restore.cmd` that imports them in order; or drop the `.reg` approach for
`Checkpoint-Computer -Description "Scythe pre-fix"` and be honest in the banner about what is
and isn't covered.

### H2 — A crashed engine is indistinguishable from a clean machine
**[STATIC — certain]** `Scythe-Server.ps1`, scan runspace.

- `$proc.BeginErrorReadLine()` is called but **no `ErrorDataReceived` handler is ever registered**.
  This correctly prevents a stderr-buffer deadlock, and then discards every byte of stderr.
- `$proc.ExitCode` is **never read**. The `finally` block emits `scan_complete` unconditionally.

So when the engine dies — and CLAUDE.md documents the exact scenario, *AMSI blocking the script at
load → exit 1, no output* — the GUI shows a completed scan with 0 findings and a green "SYSTEM
APPEARS CLEAN". For an incident-response tool this is the worst possible failure mode: a false
all-clear on a box someone is actively deciding to reimage or not. Both `server_console_*.log` and
`server_events_*.log` capture nothing useful, because stderr never entered either.

**Suggested direction:** capture stderr via the event handler into the event log, read `ExitCode`
in the `finally`, and emit a distinct `scan_failed` event the GUI renders as an error, not a
clean bill of health.

### H3 — `Get-FixClass` calls `RunCmd` and `KillProcess` "SAFE", and its destructive list is dead code
**[STATIC — certain]** `Scythe-V23.ps1:1175-1184`

```powershell
$destructive = @('DeleteFile','DeleteReg')          # assigned, never read
$safe        = @('Info','RunCmd','KillProcess','Quarantine')
```

`$destructive` is never referenced again — dead variable, so nothing is ever *labelled* destructive.
And `RunCmd` — the one action that runs arbitrary code, including `vssadmin delete shadows /all
/quiet` and `netsh advfirewall reset` — is on the **safe** list. The "🛡 SAFE ONLY" preset
(`FixMode.ps1:308`) therefore selects `RunCmd` items, filtered only by `Severity -ne 'INFO'`.

Practical effect: the two genuinely destructive `RunCmd` options *are* `$SEV_INFO`
(`Phases-1.ps1:1223` VSS purge, `1084` firewall reset), so "SAFE ONLY" excludes them — the User
Rule #1 auto-select guarantee **holds**. But it holds by accident of severity, not by design, and
one future `$SEV_HIGH` on a destructive `RunCmd` silently breaks it. The label is also actively
misleading to an operator reading the UI.

**Suggested direction:** classify on the *action's blast radius*, not the enum name — `RunCmd`
should never be "SAFE"; and either use `$destructive` or delete it.

### H4 — `FixMode.ps1` and `Summary.ps1` have **no** module-level `trap` — violating the project's own hard rule
**[STATIC — certain]** Measured: `Phases-1.ps1` 14 traps, `Phases-2.ps1` 9, `Phases-3.ps1` 3,
**`Summary.ps1` 0, `FixMode.ps1` 0.**

CLAUDE.md states this as a hard rule ("Every phase module needs its OWN top-level `trap`"), because
the loader's script-scope trap resumes at the next **dot-source statement** — i.e. the next module.
The consequence here is specific and nasty: `Summary.ps1` is what calls
`[Environment]::Exit(0)` for `-Auto` runs (line ~310). If any terminating error fires in
`Summary.ps1` *before* that line, control unwinds to the loader trap, which resumes at the next
module — **`FixMode.ps1`** — whose interactive prompts block forever on a server-spawned child with
no stdin. That is precisely the `-Auto` hang CHANGELOG says was already fixed once.

**Suggested direction:** add `trap { Write-RecoveredError $_; continue }` as the first statement of
both files, exactly as the three phase modules do.

### H5 — `KillProcess` fires on a stale PID with no identity re-validation
**[STATIC]** `Scythe-Server.ps1` (remediation runspace) and `engine/FixMode.ps1:657-668`.

`FixParam` is a PID captured during the scan. Remediation may run many minutes later. Both copies do
`Get-Process -Id $procId` → `Stop-Process -Force` and **never compare the process name/path/start
time against the finding**. Windows recycles PIDs freely. The operator confirms "kill the miner"
and kills whatever now holds that number.

Note the protected-target guard does not save you: it matches critical process names against the
**finding's description text** (`$d`), which still describes the *old* process.

**Suggested direction:** record name + `StartTime` in the finding and require both to match before
`Stop-Process`; otherwise report `skipped — process identity changed`.

### H6 — `DeleteFile` passes `-Recurse` and may follow junctions
**[NEEDS REPRO — PS 5.1 junction semantics must be confirmed on Windows]**
Both executors run `Remove-Item -LiteralPath $f.FixParam -Recurse -Force` for an action named
*Delete **File***. Two concerns:

- `-Recurse` on what should be a single file means a `FixParam` that resolves to a directory
  deletes the whole tree.
- Historically `Remove-Item -Recurse` on a **directory junction** in PS 5.1 could traverse into the
  target rather than removing the reparse point. Malware planting a junction at a flagged path
  pointing at `...\Documents` would turn one approved deletion into mass data loss.

There is also **no re-check of `Test-ProtectedTarget` against the resolved path** — the guard runs
on the literal string, so a reparse point whose *string* looks innocuous passes.

**Suggested direction:** confirm the junction behaviour on a real 5.1 box first (this is a
tripwire-testable case), then drop `-Recurse` for `DeleteFile`, reject reparse points explicitly,
and re-evaluate the guard on the fully-resolved path.

### H7 — `Test-ProtectedTarget` matches raw strings, so path normalisation bypasses it
**[NEEDS REPRO per-vector]** Both copies (main thread + `Test-RProtected` mirror) test the
**unnormalised** `FixParam`:

```powershell
if ($p -match '(?i)^[a-z]:\\windows\\' -or $p -match '(?i)\\(System32|SysWOW64|WinSxS)\\')
```

Candidate bypasses to test: `C:/Windows/...` (forward slashes), `\\?\C:\Windows\...`,
`\\localhost\C$\Windows\...`, `C:\WINDOW~1\...` (8.3 short name), `%SystemRoot%\...`, and relative
paths. Any that reach the executor without matching would let a hard-blocked destructive action
through on manual override.

Separately, the `^[a-z]:\\windows\\` anchor means the guard covers **`C:\Windows\Temp`** — an
extremely common malware drop location — so real threats there can never be auto-remediated. That
is the safe direction to fail, but it is a coverage gap worth a conscious decision (see M1).

**Suggested direction:** normalise once via
`[System.IO.Path]::GetFullPath()` + `GetLongPathName` before any guard test, and compare
canonicalised prefixes rather than regex-matching raw strings.

### H8 — CSV export is a formula-injection vector aimed straight at the MSP's Excel
**[STATIC — certain]** `Scythe-Server.ps1`, `Get-CsvReport`:

```powershell
$line = ($cells | ForEach-Object { '"' + ($_ -replace '"','""') + '"' }) -join ','
```

Quoting is correct for CSV, and **irrelevant to the attack** — Excel strips quotes and then
evaluates a leading `=`, `+`, `-`, `@`, tab or CR as a formula. The `Detail` column is malware-
controlled text (file names, task names, registry values). This matters more than usual here
because exporting findings to CSV and mailing them to a client is the product's actual workflow, so
the payload lands on a *different* machine than the one being remediated.

**Suggested direction:** prefix any cell starting with `= + - @ \t \r` with a single quote, in both
`Get-CsvReport` and any engine-side CSV writer.

### H9 — TOCTOU on the concurrency guards: two scans (or two remediations) can run at once
**[STATIC]** The routes check `$script:State.Running` / `.Remediating`, but **both flags are set
inside the background runspace**, after `Start-Runspace` returns and the 200 is written. Two POSTs
landing close together both pass the check. Two engine processes writing the same `reports/`, or
**two remediation passes executing the same destructive fix list**, is a real outcome — and C1 means
a hostile page can issue them deliberately.

**Suggested direction:** set the flag synchronously on the request thread (interlocked/lock) before
launching the runspace.

### H10 — The locked-file fallback is broken on exactly the common case
**[NEEDS REPRO — depends on PS 5.1 error class]** In both `DeleteFile` and `Quarantine`, the
reboot-delete fallback reads:

```powershell
$cur = Get-ItemPropertyValue $rpk "PendingFileRenameOperations" -ErrorAction SilentlyContinue
```

CLAUDE.md's own rule says `Get-ItemPropertyValue` throws a **terminating** "property not found"
error that `-ErrorAction SilentlyContinue` does **not** suppress — which is why the engine has a
`Get-RegVal` wrapper. On a healthy machine that value usually doesn't exist. So the first time a
locked malicious file needs queueing for reboot deletion, this likely throws into the per-finding
`catch`, logs `-> ERROR:`, increments `$failed`, and **never queues the delete** — while
`Quarantine` has already copied the file to the vault, leaving the original live on disk.

Note the engine copy (`FixMode.ps1:629`) correctly uses `Get-RegVal`; only the **server** copy uses
the raw cmdlet. Same drift pattern as C2.

---

## 3. MEDIUM

- **M1 — A CRITICAL detection with a permanently impossible fix.** `STICKY_*` (Phase 45, sticky-keys
  backdoor, `$SEV_CRITICAL`) ships `FixAction RunCmd` = `Rename-Item '$af' '$af.kraken'`, where
  `$af` is under `System32`. It is therefore **auto-selected** in the GUI and then **always hard-
  blocked** by the protected-target guard. The operator sees the tool's #1 classic backdoor found,
  pre-ticked, and reported `blocked` every time. The guard is right; the remediation design is
  wrong. Same shape at `Phases-1.ps1:433` (tampered System32 binary). Consider `FixAction Info`
  with the exact manual command (and an SFC/DISM restore path) in the description.
- **M2 — Runspace and memory leaks.** `Start-Runspace` never disposes; every SSE connection creates
  a runspace that loops `while ($SseState.Listening)` **forever** — a browser refresh leaks one per
  reload, each waking every 40 ms. `$State.EventLog` is an unbounded `ArrayList` holding every log
  line of a 115-phase scan, and each new SSE client replays it **from index 0**. Long console
  sessions will grow badly.
- **M3 — `applied` double-counts.** In the server's remediation switch, the `default` branch sets
  `$skipped++` **and** `$ok = $true`; since the unknown action isn't in `@('Info','None','')`, the
  trailing `if` also fires `$applied++`. One finding, two counters. `remediation_complete` totals
  won't reconcile.
- **M4 — STEALTH findings are second-class.** The STEALTH post-processing block builds findings
  without `fix_action` or `target` (the live path sets both), so `inferAction()` silently falls back
  to its text heuristic. It also only increments `ThreatCounts` `if ($tt)`, where the live path
  defaults to `'Other'` — so STEALTH threat counters undercount versus `findings_count`.
- **M5 — Persistent machine side-effect on listener failure.** The `HttpListenerException` handler
  runs `netsh http add urlacl url=... user=...`, which writes a **permanent, system-wide** URL
  reservation that is never removed. On a client machine, a portable IR tool should not leave that
  behind. It also silently ignores failure of the `netsh` call itself.
- **M6 — IOC ingestion is unvalidated.** `POST /api/ioc` writes user strings straight into
  `custom_iocs.ioc` as `hash:` / `ip:` / `domain:` / `regex:` / `file:` lines with **no newline
  stripping** — a value containing `\r\n` injects arbitrary extra IOC lines (e.g. a "domain" that
  smuggles a `regex:` entry). `regex:` entries are also never compiled-tested or length-capped, so a
  catastrophic-backtracking pattern hangs the next scan. No cap on entry count or file size either.
- **M7 — Dead, wrong phase regex on the main thread.** `$script:PHASE_RE = [regex]'PHASE\s+(\d+)[^\d]'`
  does **not** capture fractional phases, contradicting the documented behaviour and the runspace's
  correct `$PREX`. Confirm it's genuinely unused and delete it — leaving a wrong copy next to a right
  one is how the `Classify`/`$SEV` shadowing bug happened.
- **M8 — Escaping gaps in the GUI (defence-in-depth).** `escapeHtml` (`app.js:1613`) handles
  `& < > "` but **not `'`** — safe today only because every sink uses double-quoted attributes; any
  future single-quoted attribute becomes an injection point. Separately `finding.id`
  (`data-id="${finding.id}"`), `finding.severity` (`class="item-sev ${...}"`), `finding.phase` and
  `data.results_path` are interpolated **unescaped**. Most engine IDs are sanitised with
  `-replace '[^a-z0-9]',''`, but not all — `CTRL114_$($es.name)`, `DEFTAMP114_$($dv.name)`,
  `CONTENT_$($cr.Name)_...` come through raw from `data/*.json`. Low exploitability, cheap to close.
- **M9 — Possible local privilege escalation via `reports/`.** `RunCmd` executes whatever string is
  in the report JSON, on the stated assumption that "FixParam is generated by our own engine into
  the trusted report file." If `reports/` inherits ACLs granting a non-admin user write access
  (likely when the project lives under a user profile, e.g. `Downloads\`), that user can author a
  `KrakenBaseline_*.json` and wait for an admin to remediate — **standard-user → SYSTEM**. Worth an
  explicit ACL hardening step on `reports/` creation, plus an integrity check (HMAC over the report,
  keyed per launch) before any `RunCmd`.
- **M10 — Sensitive output, no retention policy.** `server_console_*.log` and `server_events_*.log`
  are written per launch with no rotation, capped size, or cleanup, and contain hostnames,
  usernames, full paths and every finding. Quarantined **live malware** accumulates in
  `reports/quarantine/` indefinitely with a manifest. For an MSP touching multiple clients' machines
  this is a data-handling question, not just a disk-space one.
- **M11 — Global error suppression in the server.** `Set-StrictMode -Off` +
  `$ErrorActionPreference = 'SilentlyContinue'` at file scope, plus `catch {}` swallowing everything
  in `Write-JsonResponse`, `Send-StaticFile`, `Write-DownloadResponse`, and the MITRE load. Combined
  with H2, the server is close to undebuggable when something goes wrong in the field.

---

## 4. Independently verified as **sound** — don't "fix" these

Listing these so a fix pass doesn't churn correct code:

- **Mode allow-listing is correct and the comment explains why.** `$mode` is constrained to the five
  enum values before being interpolated unquoted into the child argument string. `$hours` is
  `[int]`-cast. `$iocFile` is quoted *and* `Test-Path`-gated, and Windows filenames cannot contain
  `"`, so argument smuggling via the IOC path doesn't work.
- **Report-name validation is properly basename-locked.** `[System.IO.Path]::GetFileName()` then
  `^(KrakenBaseline_|audit_).*\.json$`, on both `/api/report` and `/api/remediate`. Traversal via
  the `report` parameter fails.
- **`Read-JsonBody`'s statement-level `try/catch` is load-bearing and correct**, and `/api/scan/start`
  and `/api/profiles` both **fail closed** on bad JSON rather than starting a default-scope scan.
  The comments explaining why are accurate.
- **`ConvertTo-Flag` is a genuine bug-fix**, not ceremony — `[bool]'false'` really is `$true` in
  PowerShell, and without it a client sending string booleans would silently enable stealth/paranoid.
- **The profile-save path is careful:** name regex-validated, built-ins reserved, mode allow-listed,
  `hours` *rejected* rather than coerced (the comment about a 24h preset silently becoming all-time
  is a real trap correctly avoided), 50-profile cap, and a corrupt `scan_profiles.json` fails the
  save instead of overwriting every saved profile with an empty set.
- **`Quarantine` is genuinely reversible** — SHA256 recorded, `.quar` extension neutralises
  double-click, JSON restore manifest written. This is the right default and matches the stated rule.
- **XSS on the main finding paths is properly handled.** `escapeHtml` is applied to every
  finding-text sink I checked (`app.js:806, 885, 1094, 1157, 1215`) and to all three badge helpers'
  `title` attributes. See M8 for the remaining edges.
- **`ScanEpoch` SSE rewind is the correct fix** for the reconnect-boundary race, and the comment
  explaining why count-comparison failed is accurate.
- **Fractional-phase handling in the runspace** (`$PREX`, the `phase_map` exact-then-floor lookup in
  both `Resolve-Mitre` copies) matches the documented design.
- **UTF-8-without-BOM writes via `[System.IO.File]::WriteAllText`** are correct for PS 5.1, and the
  reasoning in the comments is right.
- **All 7 shipped `.ps1` files carry the UTF-8 BOM** (verified by byte inspection), and
  `Build-Release.ps1` gates on both BOM presence and `Parser::ParseFile` success — a genuinely good
  release gate.
- **No bare `exit` remains in `engine/*.ps1`** — all four are `[Environment]::Exit(0)`. That
  regression is properly closed (though see H4: the *traps* that protect the path to those exits are
  missing).

---

## 5. Detection quality — hypotheses, not measurements

I could not measure detection rates (no lab, no samples, no Windows). These are code-reading
concerns to **test**, ranked by how much I'd bet on them.

1. **`Classify`'s severity regex will mis-colour on ordinary text.** `POSSIBLE = 'ANOMAL'`,
   `HIGH = 'SUSPICIOUS'`, `CRITICAL = 'BLATANT'` are substring matches against *any* log line —
   including the engine's own descriptive prose. This is cosmetic (log colouring only, per the
   documented design) but it will produce confusing red lines on clean scans.
2. **Threat-type keyword buckets are extremely broad.** `TKW.Worm` includes `'network share'`,
   `TKW.Other` includes `'cve-'`, `TKW.Miner` includes `'miner'`. Any line mentioning a network
   share gets bucketed as Worm, inflating the threat chips the operator triages on. Test against a
   clean-machine FULL scan and count non-zero buckets.
3. **`Phases-2.ps1:206` miner-task heuristic is regex-broad:**
   `$exe -match "xmr|stratum|pool\.|mining|coin|hashrate"` → `$SEV_CRITICAL`, auto-selected,
   destructive. `coin` alone will match legitimate software (anything Coinbase-adjacent, `coinst`,
   vendor paths containing "coin"). Combined with C2's unescaped task name, this is the highest-risk
   rule in the codebase. **Test first.**
4. **`Phases-1.ps1:772` rogue-task regex includes bare `cmd`** in an alternation matched against
   `$exe + " " + $args`. `cmd` as a substring will match a great many legitimate task command lines.
   `$SEV_CRITICAL`. Worth measuring FP rate on a clean box.
5. **Coverage gap worth a decision, not a bug:** `C:\Windows\Temp` is inside the protected-path
   guard (H7), so genuine malware there is detected but never remediable.
6. **The signature file is well organised** — 81 keys, `fp_allowlists` separated from signatures,
   and each allowlist carries a `_comment_*` explaining its rationale. That discipline is unusually
   good; keep it.
7. **Re the Wacatac tickets specifically:** `Wacatac.B!ml` is Defender's **ML-generic** bucket, not a
   family — the `!ml` suffix means a model fired. It is one of Defender's highest-FP labels. Nothing
   in the current pipeline turns "Kaseya sent me a Wacatac alert" into a fast FP/real verdict. The
   highest-leverage feature here is not more detection — it's an **alert-triage entry point**: take
   the alert JSON, pull the file path + hash, check signature/publisher/prevalence/parent process,
   and emit a defensible verdict. `.claude/skills/ingest-malware-alert` is the right hook; it
   currently grows *detection* coverage, not *triage* output.

---

## 6. Architecture & packaging — standalone + portable (assessment only, nothing built)

**Where it stands.** The stack is already closer to portable than it looks: pure PowerShell 5.1
(shipped on every Windows 10/11), no runtime install, a working `Build-Release.ps1` that validates
parse + BOM + JSON and emits a zip with a `.sha256` sidecar, and a startup `Unblock-File` sweep that
handles Mark-of-the-Web on transferred copies. That's a solid base.

**Blockers to a genuinely standalone artifact, in priority order:**

1. **The CDN dependency (C3).** A "portable" tool that silently loses a chart without internet isn't
   portable. Vendor GSAP + Chart.js and add them to `$requiredFiles`. Cheapest high-value fix here.
2. **No authentication (C1).** Shipping this to more machines multiplies the exposed surface. Fix
   before any wider distribution.
3. **Persistent machine side-effects.** The `netsh http add urlacl` fallback (M5) leaves a permanent
   reservation on a client's machine. A portable tool should be removable without a trace.
4. **`reports/` lives next to the binaries.** On a USB stick that means client A's findings,
   `server_events_*.log`, and **quarantined live malware** travel to client B. The launcher already
   handles a read-only drive gracefully; it should also let `-OutDir` default somewhere per-machine.
5. **No signing.** An unsigned `.bat` + `.ps1` bundle that self-elevates is exactly the shape
   AV/SmartScreen flags, and MSP endpoints often block it outright. Authenticode-signing the `.ps1`
   files and the release zip is likely a prerequisite for field use.

**On "standalone program" vs "portable script" — my recommendation:** keep **one** codebase and
treat "portable" as a *build output*, not a second implementation. `Build-Release.ps1` already
produces it; a second hand-maintained script version will drift from the engine within weeks (this
repo has already lived through one work-rig fork). If you want a `portable/` folder, make it the
zip's extraction target, not a parallel source tree.

**On the Tauri rewrite** (per `_archive/` — build cache only, no source): a native shell would fix
C1 and C3 structurally, since there'd be no HTTP listener and no remote origin. But it is a rewrite
of the delivery layer, not the engine, and the engine is where the value is. I'd fix C1/C3 in the
current stack first — they're days, not months — rather than treat the rewrite as the fix.

---

## 7. Reconciliation with `SECURITY_AUDIT_2026-08-18.md`

I audited first and compared after. Result:

- **Independently confirmed:** the `RunCmd` injection class (their C1 / my C2), `Get-FixClass`
  mislabelling (C3 / H3), missing traps in `FixMode.ps1` + `Summary.ps1` (M5 / H4), stale-PID
  `KillProcess` (H3 / H5), `DeleteFile -Recurse` (H6 / H6), no-auth + wildcard CORS (H2 / C1),
  rollback snapshot limited to 5 registry keys (M6 / H1), IOC newline injection (M2 / M6),
  and `Test-ProtectedTarget` not inspecting `RunCmd` content (H7 / H7). Two independent passes
  reaching the same conclusions raises confidence on all of these.
- **I was wrong once, they were right.** I initially reported that no quote-escaping existed
  anywhere in the codebase — a tooling artifact returned a false "0 matches". Their claim that
  `Phases-1.ps1:479` already escapes correctly is accurate, and it's now the *model* for C2's fix.
- **Correction to an earlier draft of this document.** I first wrote that C3 (CDN/SRI) was absent
  from their pass. **That was wrong** — it is their **L4**, filed as LOW. The error came from a
  malformed `grep -F` with alternation, the same class of mistake noted at the top. What stands is
  not novelty but a **severity disagreement** (LOW vs CRITICAL — see the box in C3), plus the
  Google Fonts `@import` in `main.css:6`, which genuinely is not in their document.
- **Not in their pass (new here):** H1's specific finding that the `.reg` bundle is **structurally
  invalid** and that the promised **VSS snapshot doesn't exist**, H2 (stderr + exit code discarded →
  false all-clear), H9 (TOCTOU on the concurrency flags), H10 (`Get-ItemPropertyValue` breaking the
  reboot-delete fallback in the *server* copy only), M1 (sticky-keys: CRITICAL, auto-selected,
  permanently blocked), M2, M3, M4, M8, M10, M11, and §5/§6.
- **Where I'd temper their framing:** the auto-select safety guarantee (User Rule #1) currently
  **holds** — I checked the destructive `RunCmd` sites and the two genuinely dangerous ones
  (`vssadmin delete shadows /all`, `netsh advfirewall reset`) are `$SEV_INFO`, so no auto-select
  path reaches them. It holds by severity accident rather than by design (H3), which is worth
  fixing, but the tool is not currently shipping an auto-destructive fix on a healthy box.

---

## 8. Suggested fix order

1. **C1** (auth + CORS) — everything else's blast radius depends on it.
2. **C2** (central escaping helper; start with `Phases-2.ps1:211` and the WMI sites).
3. **C3** (vendor the two libraries; likely lets the boot watchdog go too).
4. **H2** (exit code + stderr) — a false all-clear is the worst bug an IR tool can have.
5. **H4** (two `trap` lines — smallest fix on this list, prevents a known regression).
6. **H1** (rollback actually working, or the banner telling the truth).
7. **H3, H5, H8, H9, H10**, then MEDIUM.

Everything in §5 should be **measured on a clean machine before any rule is changed** — the FP-tuning
history in `CHANGELOG.md` shows this project already learned that lesson the expensive way.
