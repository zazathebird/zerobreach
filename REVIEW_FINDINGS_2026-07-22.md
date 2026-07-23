# ZeroBreach Full-Repo Review — 2026-07-22

**Audience:** a fresh model (Fable/Opus) picking this up to fix. **Nothing in this repo was edited during
this review** — it is static analysis + sandboxed non-destructive parse/syntax checks only, run via a
multi-agent workflow (88 sub-agents) plus 2 dedicated follow-up agents. Every bug/security finding below
went through **adversarial verification**: 2 independent skeptic agents tried to refute each one before it
was kept. 57 of 59 raw findings survived; the 2 refuted ones are listed at the bottom for transparency.

**Before fixing anything:** re-read the cited file:line yourself — line numbers can drift if anything else
changed since this was written. Follow `CLAUDE.md`'s hard rules throughout, especially: anchor path/name
tests to path **components** (never bare substrings), never let a destructive `FixParam` be reachable by
the CRITICAL/HIGH auto-select path on a healthy box, keep signature/allowlist literals out of `.ps1` source
(AMSI), and give every phase module its own top-level `trap { Write-RecoveredError $_; continue }`. A
cluster of the HIGH findings below (#2, #3, #4, #10) are **the same anti-pattern repeated** — bare
`"AppData|Temp"` substring matches on attacker-influenceable text, exactly the bug class CLAUDE.md already
documents as fixed once (Phase 20, Phase 47) but not applied everywhere. Consider fixing that whole cluster
in one pass using the same anchored-regex precedent (`'\\(AppData|Temp|Downloads|Desktop)\\'`) already
established in the codebase.

---

## Sandbox / parse-check results — all green

Non-destructive checks only (AST parsing, `node --check`, `python -m py_compile`, JSON parse, BOM byte
inspection — nothing was executed):

- **All 7 core `.ps1` files** (`ZeroBreach-V23.ps1`, `ZeroBreach-Server.ps1`, `engine/Phases-1/2/3.ps1`,
  `engine/Summary.ps1`, `engine/FixMode.ps1`) parse-clean on **both** live `powershell.exe` 5.1.26100.8875
  and `pwsh` 7.6.4, and **all** carry the required UTF-8 BOM (`EF BB BF`).
- **All 5 `data/*.json` files** parse cleanly, no duplicate keys. A few empty arrays exist
  (`mitre_mapping.json`'s `PHASE 105+` techniques, `coverage_matrix.json`'s baseline-diff meta-phase,
  `ioc_defaults.json`'s `hashes`/`regex`, `permission_baseline.json`'s `unquoted_path_whitelist`) — these
  read as intentional placeholders, not corruption (the last one is actually a real bug though, see #41).
- **All 5 GUI `.js` files** pass `node --check` with no syntax errors.
- **`_python/server.py`** passes `python -m py_compile` with no errors.

No parse/encoding/BOM regressions anywhere. The problems below are all logic/security/design issues, not
syntax breakage.

---

## Priority fix list — bugs & security, by severity

### CRITICAL (2)

**1. `engine/Summary.ps1` is missing its required top-level `trap`.** *(bug, phases3_summary_fixmode)*
CLAUDE.md names `Summary.ps1` explicitly as one of the modules that needs its own
`trap { Write-RecoveredError $_; continue }` as the first statement, because the loader's script-scope trap
only resumes at the *next dot-sourced file*, not the next line in the current one. Verified: this file has
no such trap. Any uncaught terminating error anywhere in `Summary.ps1` before the STEALTH/Auto exit checks
falls straight through into `FixMode.ps1`'s interactive prompts — this is the exact "hung `-Auto` run"
failure mode CLAUDE.md's engine-split rules were written to prevent, reintroduced in the one file the rule
explicitly names.

**2. `ZeroBreach-Server.ps1` sets `Access-Control-Allow-Origin: *` with no CSRF/origin protection on
state-changing routes, including remediation.** *(security, ps_server, line ~1217)* Every response sets
`Access-Control-Allow-Origin: *` (lines 175, 197, 211, 506) and the OPTIONS preflight handler answers with
`Access-Control-Allow-Methods: GET, POST, OPTIONS` / `Access-Control-Allow-Headers: Content-Type` — this
explicitly permits **cross-origin JSON POSTs to succeed with their response readable**, meaning any other
webpage the operator has open in the same browser (a malicious ad, a compromised site, anything) can call
`POST /api/remediate` directly and trigger real destructive remediation (file deletes, reg deletes, process
kills) on the machine being audited — **completely bypassing the GUI's typed-`PURGE` confirmation modal**,
which is the one safety backstop CLAUDE.md treats as load-bearing for destructive actions. This is a
locally-bound server (`HttpListener`, elevated), but "locally bound" doesn't mean "only the GUI can reach
it" — anything running in the operator's browser can.

### HIGH (17)

**3. Self-elevation relaunch silently drops `-Schedule`/`-SmtpTo`/`-SmtpFrom`/`-SmtpServer`.**
*(bug, loader_phases1, `ZeroBreach-V23.ps1:93`)* The elevation relaunch `$argList` (lines 90-104) forwards
only `-Stealth/-Paranoid/-Auto/-Html/-Mode/-Hours/-IocFile/-Baseline/-OutDir`. Running
`.\ZeroBreach-V23.ps1 -Schedule DAILY` from a non-admin shell (the realistic first-time setup path) triggers
the elevation relaunch *without* `-Schedule`; the elevated child never reaches the schedule-registration
block. No error is printed — the operator believes a scheduled task was created when it silently wasn't.

**4. Phase 36's live-connection check flags any process merely containing `"AppData"`/`"Temp"` in its path
as HIGH + auto-selected `KillProcess`.** *(bug, loader_phases1, `engine/Phases-1.ps1:1033`)* No
path-component anchoring, no allowlist. Any Electron/updater app that autostarts from `%LocalAppData%`
(Discord, Slack, Teams, Spotify — exactly the class CLAUDE.md documents Phase 20 already had to special-case)
and holds a connection on a port outside `{80,443,8080,8443}` gets killed on PURGE.

**5. Phase 28's rogue-service scan matches `ImagePath` on bare `"AppData"`/`"Temp"` and fires CRITICAL +
`RunCmd` that stops/disables/deletes the service.** *(bug, loader_phases1, `engine/Phases-1.ps1:754`)* Same
unanchored-substring bug, but here the auto-fired action is `Stop-Service; Set-Service -StartupType
Disabled; sc.exe delete` — a legitimate third-party service (backup/VPN-helper installed under AppData) gets
permanently deleted on a healthy box.

**6. Phase 29's scheduled-task audit matches action `Execute+Arguments` on bare `"AppData"`/`"cmd"` and
fires CRITICAL + `RunCmd` that unregisters the task.** *(bug, loader_phases1, `engine/Phases-1.ps1:772`)*
Only the `\Microsoft\` task folder is excluded — every third-party auto-updater/launcher task (which
commonly execute from AppData or invoke `cmd.exe /c`) matches. The sibling task-*content* check a few lines
below was already correctly downgraded to POSSIBLE for this exact reason; the *action* check was never
brought in line.

**7. Phase 69 (and identically Phase 83) gate an auto-fireable `KillProcess` on bare
`-match "AppData|Temp"`.** *(bug, phases2, `engine/Phases-2.ps1:440`)* Reintroduces the exact bug class that
caused the historical WhatsAppDesktop false auto-kill (CLAUDE.md's own worked example), just in two phases
that never got the anchored-regex fix applied.

**8. Phase 63's miner-config scan uses raw `Get-ChildItem -Recurse`** over TEMP/LOCALAPPDATA/AppData\Roaming
instead of the mandated `Get-ScanFiles` wrapper. *(performance, phases2, `engine/Phases-2.ps1:175`)* This is
precisely the pattern CLAUDE.md's rule #7 forbids (unbounded walk, no cache-dir pruning, no OneDrive
placeholder skip, no wall-clock cap).

**9. `engine/FixMode.ps1` is also missing its required top-level trap.** *(bug, phases3_summary_fixmode,
`engine/FixMode.ps1:1`)* CLAUDE.md names this file explicitly too. Since `FixMode.ps1` is the *last*
dot-sourced module, an uncaught error here means the whole script just ends silently — including inside the
WinForms dashboard code — with no confirmation shown to the operator that remediation did or didn't
complete.

**10. The pre-remediation rollback snapshot is not a valid `.reg` file.** *(bug, phases3_summary_fixmode,
`engine/FixMode.ps1:41`)* Built by concatenating raw `reg export` output after a custom banner
(`"ZEROBREACH V22 SNAPSHOT | ..."` + a `=`-separator line) instead of the required
`"Windows Registry Editor Version 5.00"` magic header. The restore command the tool prints to the operator
(`regedit /S "$SNAPSHOT_PATH"`) will fail to import anything — the rollback safety net is non-functional.

**11. The standalone HTML forensic report's inline CSV-export `<script>` block embeds raw,
non-HTML-escaped finding text.** *(security, phases3_summary_fixmode, `engine/Summary.ps1:134`)*
`Write-HtmlReport` HTML-encodes the visible table row correctly, but the CSV string built inside a
`<script>` tag uses the raw `$_.Description`/`$_.Target` with only CSV-quote doubling — a malicious file
path or registry value containing `</script>` breaks out and injects executable HTML/JS into a report a
technician might open and share.

**12. Raw `Get-ItemPropertyValue` call in the remediation runspace's reboot-queue fallback throws a
terminating error whenever `PendingFileRenameOperations` doesn't already exist.** *(bug, ps_server,
`ZeroBreach-Server.ps1:1066`)* CLAUDE.md explicitly bans this exact raw call (must use `Get-RegVal`). Breaks
the locked-malware-file deletion path — the most common real-world case (a fresh, never-rebooted box has no
existing `PendingFileRenameOperations` value).

**13. The `DeleteReg` remediation action reports success (`applied++`) without ever verifying the value was
actually removed.** *(bug, ps_server, `ZeroBreach-Server.ps1:1074`)* Every sibling fix action
(`DeleteFile`/`DeleteRegKey`/`KillProcess`) verifies the post-condition before reporting OK; `DeleteReg`
alone calls `Remove-ItemProperty ... -ErrorAction SilentlyContinue` and reports success unconditionally.

**14. Snapshot/Baseline-Diff/CSV-export checkboxes are rendered and saved in scan profiles but are never
sent to the server when a scan starts.** *(bug, gui_frontend, `gui/static/js/app.js:731`)*
`PROFILE_TOGGLES` correctly round-trips `opt-snapshot`/`opt-baseline`/`opt-csv` through save/apply profile,
but `startScan()`'s `config` object never forwards them — these three features are unreachable from the GUI
regardless of what the operator selects.

**15. `cloaked_benign_names` allowlist entries are unanchored bare substrings matched against
attacker-controllable filenames.** *(security, data_signatures, `data/detection_signatures.json:844`)*
Phase 18's cloaked (Hidden+System) file scan excludes any candidate whose name contains a substring like
`"iconcache"`/`"thumbcache"` — a hidden+system malware executable can evade detection entirely just by
naming itself with that substring anywhere in its filename.

**16. `trusted_root_ca_issuers` is a list of unanchored bare words matched against a certificate's
Subject+Issuer text.** *(security, data_signatures, `data/detection_signatures.json:778`)* Phase 39's rogue
root-CA audit downgrades severity to INFO if the cert's Subject/Issuer contains a word like `"microsoft"`,
`"windows"`, `"amazon"` anywhere — an attacker with local admin planting a rogue root CA for MITM can simply
name it `"Microsoft Update CA"` to self-clear the finding.

**17. Custom IOC ingestion only ever matches the Hashes bucket; Domains/IPs/Regex/Files entries are parsed
and counted but never consulted by any detection phase.** *(bug, data_signatures, `data/ioc_defaults.json`)*
`Import-CustomIocs` populates `$global:CustomIocs.{Hashes,Domains,IPs,Regex,Files}` from `-IocFile`/the IOC
Manager, but only `.Hashes` is ever read anywhere in `engine/*.ps1` — an operator who adds a known-bad
domain/IP/regex/filename via the IOC Manager gets silent no-op coverage for everything except hashes.

**18. Skill guardrail (`.claude/skills/ingest-malware-alert/SKILL.md:54`) falsely claims only
`ZeroBreach-Server.ps1` carries a UTF-8 BOM and the engine is BOM-free.** *(docs-drift, docs_consistency)*
Directly contradicts CLAUDE.md's repeated, explicit rule that every engine file (loader + all 5
`engine/*.ps1` modules) is BOM-saved — confirmed true by this review's own byte-level sandbox check above.
A model following this skill's guardrail as written could strip a required BOM.

**19. Skill's engine-coverage workflow (step 4) targets the pre-split monolithic `ZeroBreach-V23.ps1` with
line numbers that no longer exist.** *(docs-drift, docs_consistency,
`.claude/skills/ingest-malware-alert/SKILL.md:36`)* The loader is now 1456 lines; the skill's cited line
resolves inside unrelated dead code (`Invoke-VerifiedAnnihilation`/`Invoke-VerifiedRegScrub`, see #9 in the
Low section) rather than the real `Get-Sig` block (~line 940). Following this skill as written sends new
detection coverage to the wrong file/location post-engine-split.

### MEDIUM (22)

20. **Browser-shortcut-hijack `RunCmd` fix interpolates the attacker-controllable `.lnk` filename into a
    single-quoted PowerShell string without escaping embedded single quotes.** *(security, loader_phases1,
    `engine/Phases-1.ps1:239`)* Windows filenames may legally contain `'`; an attacker who already planted
    a hijacked shortcut can break out of the string.
21. **`$sig` locals silently clobber the script-scope `$SIG` signature-data object** (PowerShell variables
    are case-insensitive). *(bug, loader_phases1, `engine/Phases-1.ps1:294`, ≥7 sites)* The same bug class
    that disabled all severity classification for weeks (the `$sev`/`$SEV` incident) — worth a full repo
    grep for any local named `sig`/`Sig` at the shared dot-sourced scope.
22. **Known-adware/PUP vendor names and keylogger registry paths are embedded as literal string lists
    directly in `.ps1` source** instead of `data/detection_signatures.json`. *(security, loader_phases1,
    `ZeroBreach-V23.ps1:902` + `engine/Phases-1.ps1` Phase 48)* Bypasses the project's own AMSI-safety
    externalization pattern used for every other signature list.
23. **Phase 32's DLL-search-order-hijack Authenticode loop has no `$global:SIG_AUDIT_*` deadline/count
    budget**, unlike sibling loops in Phases 10/15. *(performance, loader_phases1,
    `engine/Phases-1.ps1:924`)* Can block ~15s/file on CRL/OCSP for every unfiltered, unbounded DLL in every
    writable PATH directory.
24. **Finding IDs built from raw `.NET string.GetHashCode()`** (DNS tunneling + Defender-history
    correlation) are not stable across process runs under pwsh/.NET 5+. *(bug, phases2,
    `engine/Phases-2.ps1:46`)* Silently breaks the `-Baseline` diff feature for these finding types.
25. **Phase 59's beacon-domain allowlist excludes any DNS entry whose name merely *contains* a trusted
    vendor word** (`microsoft|windows|google|...`). *(security, phases2, `engine/Phases-2.ps1:15`)* Attacker
    fully controls the beaconed domain name — trivially evadable.
26. **Phase 90 (YARA-Lite) and Phase 94 (COM-scriptlet) benign-path allowlists match generic,
    attacker-creatable folder names** (`\node_modules\`, `\site-packages\`). *(security,
    phases3_summary_fixmode, `engine/Phases-3.ps1:31`)* A dropper can self-allowlist by naming its
    containing folder after the pattern.
27. **`SCAN_SCRIPT` casts `html_report`/`paranoid`/`stealth` with raw `[bool]`** instead of the project's own
    `ConvertTo-Flag` helper. *(bug, ps_server, `ZeroBreach-Server.ps1:682`)* Reintroduces the documented
    `[bool]"false"` → `$true` bug (any non-empty string is truthy) that `ConvertTo-Flag` exists specifically
    to prevent — and *is* correctly used for the profile-save path, just not this one.
28. **The scan-start `hours` field has no validation/fallback**, unlike `mode` (which fails closed to FULL).
    *(bug, ps_server, `ZeroBreach-Server.ps1:681`)* A non-numeric `hours` in the POST body throws before
    `Running=true` is even set, silently killing the scan with no error surfaced to the client.
29. **`Get-CsvReport` doesn't neutralize CSV/formula-injection characters** (`=`, `+`, `-`, `@`).
    *(security, ps_server, `ZeroBreach-Server.ps1:275`)* An attacker-chosen filename in a finding can execute
    as a formula/DDE payload when the exported CSV is opened in Excel.
30. **`Start-Runspace` never disposes the PowerShell/Runspace objects it creates**, and every call site
    discards the returned handle via `Out-Null`. *(performance, ps_server, `ZeroBreach-Server.ps1:484`)*
    Leaks handles/threads over a long-running server session.
31. **`dispatchEvent()` is declared as a top-level global function, silently shadowing native
    `window.dispatchEvent`** (`EventTarget.prototype`). *(bug, gui_frontend, `gui/static/js/app.js:192`)*
32. **Several Settings-view controls have no event listeners and their values are never read anywhere**:
    output directory, SMTP server/from/to, schedule dropdown, IOC-file browse button. *(bug, gui_frontend)*
    Dead UI — the whole "SCHEDULE"/"SMTP" settings section does nothing.
33. **GSAP and Chart.js load unconditionally from `cdnjs.cloudflare.com`**, an external network dependency
    in a tool meant to run standalone/USB-portable on an incident host. *(security, gui_frontend,
    `gui/templates/index.html:34`)* No SRI hash, no local fallback — if the CDN is unreachable or
    compromised on a client's network, behavior degrades or is at risk.
34. **The canvas background renderers (matrix rain, particles, waveform, radar, etc.) never check
    `prefers-reduced-motion`**, unlike the newer CINE_FX overlays. *(improvement, gui_frontend,
    `gui/static/js/fx.js:476`)*
35. **`coverage_matrix.json`'s own top-level `_comment` is stale** — claims "the engine has no QUICK gate"
    and lists 15 signature keys as orphaned, both since fixed (2026-07-02/03). *(docs-drift, data_signatures,
    `data/coverage_matrix.json:2`)*
36. **`server.py`'s CLEAN regex `\[OK\]` doesn't tolerate the padded `[OK ]` tag the engine actually emits**,
    unlike the canonical PS-server regex which explicitly accounts for the trailing space. *(bug,
    python_server, `_python/server.py:81`)*
37. **`server.py`'s POSSIBLE regex's unanchored `ANOMAL` substring matches inside the benign word
    "ANOMALIES"**, turning a clean line into a false POSSIBLE. *(bug, python_server,
    `_python/server.py:80`)*
38. **`server.py`'s `MODE_PHASES` caps DEEP/PARANOID/STEALTH at 107 phases** (and `scan_state`'s default
    `phase_total`), but the engine's real ceiling for those modes is now 115 (WS2 port added the integrity
    phases 108-115). *(bug, python_server, `_python/server.py:59`)*
39. **`server.py`'s `SocketIO` uses wildcard CORS with no CSRF/origin protection**, same class of bug as
    finding #2 above. *(security, python_server, `_python/server.py:35`)*
40. **`HANDOFF.md` has not been updated for the most recent completed+pushed session** (2026-07-21, commit
    `22e582a`, the `Get-ProcSnapshot` WS4 work) — still only covers through session 10. *(docs-drift,
    docs_consistency)*
41. **`BLUEPRINT.md` §4's regression-metric baseline ("currently 52, all by-design") is inconsistent with
    `CHANGELOG.md`'s own same-day round-6 entry**, which establishes 39 as the fresh cleared baseline.
    *(docs-drift, docs_consistency, `BLUEPRINT.md:106`)*

### LOW (15)

42. Several destructive helper functions in the loader (`Invoke-VerifiedAnnihilation`,
    `Invoke-VerifiedRegScrub`, `Invoke-SectorScan`, `Invoke-RegSectorScan`, `Reset-FilePermissions`) are
    **dead code** — no call sites anywhere in the repo — and one runs an unscoped `icacls /reset /T` on a
    caller-supplied path. *(improvement, loader_phases1, `ZeroBreach-V23.ps1:643`)* Worth deleting outright
    given rule #1's "never ship a destructive lever that could fire" spirit, even though it's currently
    unreachable.
43. Phase 61's `FixAction` ternary for RAT config-path findings evaluates to `"DeleteFile"` on **both**
    branches regardless of the `Test-Path -PathType Container` check — dead conditional, looks like a
    half-finished edit. *(improvement, phases2, `engine/Phases-2.ps1:70`)*
44. Phases 71/72/73 keep detection keyword/domain/path-glob lists inline in the `.ps1` rather than
    externalized, unlike nearly every sibling list in the same file. *(addition, phases2,
    `engine/Phases-2.ps1:502`)*
45. **Dead leftover `$script:PHASE_RE`/`$script:SEV_PATTERNS`** in `ZeroBreach-Server.ps1:158` — flagged
    independently by two different review dimensions (ps_server and docs_consistency). Never referenced
    anywhere else in the file (each runspace embeds its own copy since a runspace can't share script scope
    with the parent). `PHASE_RE` is also a stale *non*-fractional-aware regex that could mislead a future
    editor into "fixing" a runspace copy to match it. *(improvement/docs-drift)*
46. The `/static/` file-serving route builds its filesystem path with a naive string substitution and no
    basename-lock/containment check, unlike every other file-touching route in this file. *(improvement,
    ps_server, `ZeroBreach-Server.ps1:1176`)*
47. `finding.id` is interpolated unescaped into a `data-id="..."` attribute and `finding.threat_type`
    (group name) unescaped into `innerHTML`, unlike every other finding-derived field in the same render
    functions. *(security, gui_frontend, `gui/static/js/app.js:1095`)*
48. The ~19s Kraken unlock cinematic (full-screen flashbang, rapid glitch frames, hard screen shakes) never
    checks `prefers-reduced-motion`. *(improvement, gui_frontend, `gui/static/js/kraken.js`)*
49. The SSE event pump drains queued events with `EV_QUEUE.shift()` in a per-frame loop — O(n) per call,
    ~O(n²) total across a large burst, working against the batching's own stated goal. *(performance,
    gui_frontend, `gui/static/js/app.js:188`)*
50. `unquoted_path_whitelist` is documented and referenced by `coverage_matrix.json` as a Phase 111 data
    source, but is never actually read via `Get-Perm` anywhere in the engine — Phase 111 flags every
    unquoted service path with zero whitelist suppression. *(bug, data_signatures,
    `data/permission_baseline.json:130`)*
51. Five signature keys (`trojan_file_patterns`, `auto_elevate_bins`, `email_phishing_trojans`,
    `proactive_persistence_regs`, `proactive_lure_extensions`) are loaded into globals but never read by any
    phase — dead data. *(addition, data_signatures, `data/detection_signatures.json:354`)*
52. `mitre_mapping.json`'s single `"PHASE 69"` entry only carries T1055.012 (Process Hollowing), even though
    Phase 69 emits two distinct finding types under that phase key — the mutex-probe findings get
    mis-tagged with a hollowing technique. *(improvement, data_signatures, `data/mitre_mapping.json:1633`)*
53. `server.py`'s `PHASE_RE` only captures integer phase numbers — fractional phases (55.5, 74.5-74.7, 99.5)
    collapse onto their integer floor, unlike the PS server's fractional-aware regex. *(bug, python_server,
    `_python/server.py:62`)*
54. `/api/scan/start` checks `scan_state["running"]` synchronously, but the flag is only set `True` inside
    the background thread — two near-simultaneous POSTs can both pass the guard and spawn two concurrent
    elevated PowerShell scans. *(bug, python_server, `_python/server.py:296`)*
55. `/api/reports/<filename>` serves any file under `reports/` with no filename allow-list, unlike the PS
    server's documented `^(KrakenBaseline_|audit_).*\.json$` validation. *(improvement, python_server,
    `_python/server.py:324`)*
56. `BLUEPRINT.md` §7's "Now" section instructs to "push the unpushed local commits on main," but HEAD
    already equals `origin/main` — stale instruction. *(docs-drift, docs_consistency, `BLUEPRINT.md:152`)*

---

## Refuted findings (dropped — listed for transparency, not action items)

These were proposed by a first-pass reviewer and then refuted by both adversarial verifiers. Included so a
human/model reviewing this document can sanity-check the verification process rather than just trusting it:

- **Phase 33 HOSTS_PURGE** (`engine/Phases-1.ps1:973`) — claimed the "any hosts file that isn't purely
  default loopback" check strips legitimate custom entries (ad-block lists, dev overrides) on a HIGH +
  auto-selected `RunCmd` rewrite. Verifiers found this described real behavior but disagreed on whether it
  rises to a reportable bug vs. accepted-tradeoff detection design — kept out of the fix list pending a
  human call on whether it's actually a problem.
- **`server.py`'s `scan_state` SocketIO event field mismatch** (`_python/server.py:254`) — claimed the event
  is emitted with two different incomplete field sets depending on code path, matching neither the README's
  documented shape. Refuted as not a functional bug (Python parked/lower-priority server; the GUI does not
  consume this server).

---

## GUI / UX improvement proposals (separate dedicated review pass, not a bug hunt)

Ranked roughly by impact. None of these are bugs — they're design/UX gaps worth closing given this app's
real users are MSP technicians triaging findings under time pressure on a real client machine.

1. **No search/sort/filter in the findings triage view.** The severity pills (`#pill-critical` etc.) look
   clickable but have zero click handlers — they're static counters, not filters, despite the log view's
   `.log-filter` chips already proving the pattern works. Add: wire the pills as toggle filters, add a
   text-search box over `STATE.findings` (already fully in memory, no round-trip needed), add a
   GROUP BY (Threat Type / MITRE Tactic / Severity) toggle, add per-group "select all in group."
2. **The PURGE confirmation modal hides the action list it's confirming.** `showDangerConfirm()` covers the
   `#action-queue` the operator just reviewed and shows only a count string — the operator has to trust
   memory before typing `PURGE`. Add a scrollable preview of the actual targets/actions inside the modal,
   grouped by fix-action type, and consider requiring the typed word to include the count for large batches.
3. **Zero keyboard accessibility.** No `aria-*`, `role=`, or `tabindex` anywhere except decorative
   `aria-hidden`; nearly every interactive control is a `<div>`/`<span>` with a click handler, not a
   `<button>`. `#cmd-input`/`#danger-input` set `outline: none` with no replacement focus style — the two
   highest-stakes dialogs in the app (command palette, destructive-action confirm) are keyboard-invisible.
4. **Severity encoding is color-only** (`--threat-critical` red / `--threat-high` orange /
   `--threat-possible` yellow / `--threat-clean` green — red/green is the worst pairing for the most common
   color blindness). Add a shape/pattern distinction or make the emoji-prefix convention consistent
   everywhere severity renders (currently inconsistent between render functions).
5. **No responsive breakpoints at all** — `#sidenav` (200px) and `#intel-panel` (220px) are hardcoded, `html,
   body { overflow: hidden }` assumes everything always fits. Given the stated laptop/small-window use case,
   add a breakpoint that collapses the side rails on narrow viewports.
6. **No visible feedback when SSE drops mid-scan**, and "no findings" is indistinguishable from "you forgot
   to scan." Add a toast + distinct heartbeat state on connection loss, and differentiate the empty-findings
   state for a genuinely clean completed scan.
7. **Export/reporting UX isn't built for the actual deliverable** (a client incident writeup). `window.print()`
   has no print stylesheet (prints the full dark console chrome); JSON export dumps raw internal fields;
   there's no persisted remediation summary after a PURGE run (currently only a 3-second toast). Add a
   `@media print` stylesheet, a "remediation report" section in the Report view, and optionally a
   client-facing export mode that strips internal fields.
8. **Command palette (Ctrl+K), the 12-theme system, and the KRAKEN easter egg are fully hidden** — no
   on-screen affordance anywhere. Cheap fix: a subtle hint in the boot sequence or Settings header.
9. **No cross-tab/background notification** when a 25-30 minute DEEP/PARANOID scan or remediation finishes.
   Flip `document.title` when `document.hidden`, optionally offer a `Notification` permission prompt from
   Settings (not on page load).
10. **MITRE data is per-finding only, no scan-level technique rollup**, even though every finding already
    carries `mitre.tactic` and Chart.js is already loaded for the existing threat-type radar. Cheap to add
    a tactic-frequency panel/second chart tab.

Smaller batch-in items: log-panel text search, per-item removal from the remediation queue, and surfacing
the engine's existing `-Baseline` diff capability as a "compare to previous scan" picker in the GUI.

---

## Standalone C-port assessment (separate dedicated research pass — planning content, no code)

Full context: the user intends to eventually rewrite this as a standalone C application. This section
inventories what that requires. **Key finding: the GUI (`gui/` — HTML/CSS/JS) and all `data/*.json` files
need no changes at all** — they're already language-agnostic; only the PowerShell server + engine need
porting, and the SSE/JSON contract between them is well-specified enough to port piecewise.

### Recommended order: server first, then engine phases by risk group — never a full simultaneous rewrite

1. **Port the HTTP+SSE server first** (mongoose/civetweb or similar embeddable C HTTP lib), reproducing the
   existing route table and exact SSE payload shapes (`log_line`/`finding`/`scan_state`/`scan_complete`/
   `remediation_complete`/`sync`). Keep spawning the *existing* PowerShell engine as a subprocess via
   `CreateProcess` with piped stdout, parsing the same `[FINDING] {json}` / `PHASE N` line contract. Lowest
   risk, validates the most mechanical part of the stack, leaves the ~115 phases of hard-won FP-tuning
   history untouched.
2. **Port engine phases in groups**, starting with the QUICK-mode 30-phase set (cheap Win32 API calls: run
   keys, processes, tasks, services, pipes, network) and saving the WS2 additions (BYOVD, ransom-note,
   C2-pipe, mutex, cmdline-heuristics) and the Phase 108-115 permission/integrity block for last — those
   encode the most FP-tuning history and need the most careful re-validation. **Validate every ported group
   by diffing its CRITICAL/HIGH output against the still-running PowerShell reference implementation on the
   same box** — this is the cheapest trustworthy correctness check available for a detection tool.
3. Never attempt a full simultaneous rewrite — it discards the ability to diff against known-good output and
   leaves no working artifact during the port window.

### Windows/PowerShell mechanism → C equivalent (inventory)

| Category | Current (PS) | C equivalent |
|---|---|---|
| Registry | `Get-RegVal`/`Get-ItemProperty`, `Remove-ItemProperty` | `RegQueryValueEx`/`RegGetValue`/`RegDeleteValue` (`<winreg.h>`) |
| WMI/CIM (`Win32_Process`, `Win32_Service`, `Win32_Share`, WMI persistence subscriptions) | `Get-CimInstance` | `CreateToolhelp32Snapshot`+`Process32First/Next` for processes; `EnumServicesStatusEx` for services; `NetShareEnum` for shares. **Keep a thin COM/WMI client just for `__EventFilter`/`__EventConsumer` persistence detection** — no clean non-WMI equivalent exists for that one check. Phase 99.5's command-line heuristics also depends entirely on `Win32_Process.CommandLine`, which has no cheap non-WMI source (undocumented `NtQueryInformationProcess` otherwise) — budget extra time here. |
| Authenticode | `Get-AuthSig` (wraps `Get-AuthenticodeSignature` + the `$global:SIG_AUDIT_*` revocation-check budget) | `WinVerifyTrust` (wintrust.dll) — request `WTD_REVOKE_NONE` for bulk passes instead of fighting a wall-clock deadline against a cmdlet that always does an online check; this is a genuine improvement opportunity, not just a port. |
| Event Log | `Get-WinEventSafe` (wraps `Get-WinEvent -FilterHashtable`) | `EvtQuery`/`EvtNext`/`EvtRender` (`<winevt.h>`) — returns error codes instead of throwing, so the "safe wrapper" pattern's *reason* disappears (no terminating-exception risk), but the *check-the-return-code* discipline still has to be followed. |
| Scheduled tasks | `Get-ScheduledTask`, `Register-ScheduledTask` | Task Scheduler COM API (`ITaskService`) for registration; raw XML read of `%WINDIR%\System32\Tasks\` for read-only audit (avoids COM entirely for enumeration). |
| Process/mutex/pipe | `Get-Process`, `[Threading.Mutex]::OpenExisting`, `[IO.Directory]::GetFiles("\\.\pipe\")` | `Toolhelp32Snapshot`, `OpenMutex(SYNCHRONIZE,...)`, `FindFirstFile`/`FindNextFile` on `\\.\pipe\*`. |
| ACLs | `Get-Acl`/`Set-Acl`, `Get-WeakAces` (substring identity match) | `GetNamedSecurityInfo`/`SetNamedSecurityInfo` + `GetAce`, compared against well-known SIDs via `ConvertStringSidToSid` — **more correct than the current substring match**. |
| Elevation | `Start-Process -Verb RunAs` + re-passed args | `GetTokenInformation(TokenElevation)` check + `ShellExecuteEx` with `lpVerb="runas"`. |
| AMSI constraint | signatures forced into `data/*.json` to avoid `ScriptContainedMaliciousContent` | **Doesn't apply to a compiled binary** — AMSI scans script text, not compiled code. Recommend keeping signatures externalized anyway (field-updatable without recompiling, avoids reintroducing the same problem via AV heuristic/string-table detection on the binary itself), but the hard requirement relaxes. |

### PowerShell idioms with no direct C equivalent — need deliberate design

- **Per-phase fault isolation** (`trap {...; continue}`) — the single most load-bearing idiom in this
  codebase (see finding #1/#9 above for what happens when it's missing even in PowerShell). Recommended C
  design: a phase table of function pointers walked by a supervising loop, each call wrapped in Windows SEH
  (`__try`/`__except(EXCEPTION_EXECUTE_HANDLER)`) as the outer backstop, **plus** explicit per-phase return
  codes for expected error paths — SEH alone isn't reliable for corruption, and return-code discipline alone
  has no safety net for what a developer forgot to check. Do both; don't rely on either alone as "the trap."
- **Data-driven signature/allowlist matching** — use `cJSON` (single-file, easy to vendor) for the JSON data
  files (already language-agnostic, reuse as-is) and **PCRE2** for regex (closest match to .NET-flavor regex
  semantics the existing anchored allowlist patterns rely on — avoid hand-rolling, this codebase's own FP
  history shows these patterns are already subtle with a mature engine).
- **Memory/lifetime management** for what are currently PowerShell arrays/hashtables rebuilt every scan
  (findings list, file-enumeration memo, process-snapshot cache, signature-verdict cache) — needs explicit
  ownership rules (who frees a shared cache buffer) that PowerShell's GC hides entirely today.
- Note: **the `,$arr` single-item-pipe-unwrap bug class and the `(fn)[0]` scalar-unwrap bug class both
  disappear entirely in C** (arrays are always arrays) — the port eliminates two whole entries from
  CLAUDE.md's bug-lesson list, at the cost of introducing C's own footguns (below).

### New risks a C port introduces that don't exist today

- **Memory-safety bugs become possible in a tool that runs elevated and parses attacker-controlled input as
  its core job** (filenames, Run-key values, task actions, pipe/mutex names, service ImagePaths, file
  content for entropy/content-rule phases) — a buffer overflow while parsing a malicious registry value,
  running as SYSTEM or elevated admin, is materially worse than the PowerShell equivalent (which at worst
  throws an exception the trap catches). Mandate bounds-checked string handling and fuzz every parser that
  touches attacker-controlled fields before shipping.
- **Silent phase skips get *easier* to introduce, not harder**, unless the SEH-wrapped phase-table design
  above is followed rigorously — PowerShell's `trap` is a default safety net even for code the phase author
  never explicitly guarded; C has no equivalent default. A C port that doesn't replicate an equally
  aggressive default fault barrier regresses to *worse* than the pre-fix PowerShell behavior (recall: this
  exact failure mode, a benign ACL collision silently dropping phases 17-58, is CLAUDE.md's hardest-won
  rule).
- **Loss of WMI's relational richness** (one query gives `CommandLine`/`Owner`/`ExecutablePath` together;
  native APIs need several separate, some undocumented, calls per item) raises real per-phase cost,
  concentrated in the WMI-heavy phases named above.

---

## Review methodology (for reference)

Run as a background multi-agent workflow: sandboxed non-destructive parse/BOM/syntax checks (4 agents) in
parallel, then 8 subsystem-dimension reviews (loader+Phases-1, Phases-2, Phases-3+Summary+FixMode, PS
server, GUI frontend, data/signatures, parked Python server, docs consistency) each reading its files in
full against a checklist of this codebase's documented historical bug classes, then adversarial verification
(2 independent skeptic agents per bug/security finding, kept unless both refuted it) — 88 total agents, ~5M
tokens, 813 tool calls. Two additional dedicated agents ran in parallel for the GUI/UX and C-port sections
above. No files were modified by any part of this review.
