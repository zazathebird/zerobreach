# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repo.

> **`BLUEPRINT.md` is the product map** (architecture, data contracts, safety model, roadmap) —
> read it first for orientation. **Detailed bug-fix history and the FP-tuning rounds live in
> `CHANGELOG.md`.** This file keeps the durable **rules** only. When you fix something
> noteworthy, add a dated entry to `CHANGELOG.md` and, if it produces a new "never do X"
> lesson, a rule below.

## What This Project Is

ZeroBreach V23 "Kraken Console" is a **Windows-only MSP incident-response tool**: a PowerShell HTTP
server sits between a cyberpunk HTML/JS frontend and a PowerShell scan engine (`ZeroBreach-V23.ps1`)
that runs **~115 phases** of malware detection. A parked Python/Flask server (`_python/server.py`) is
an alternative to the PS server. The engine still self-identifies as "V22" in some strings (scheduled
task name `ZeroBreach_V22_Scheduled`, banners) — **intentional, not a bug to fix.**

## Launching

```powershell
Launch-GUI.bat            # Default — pure PowerShell server, no Python (recommended)
Launch-GUI.bat python     # Python/Flask server (needs deps installed first)
```

`Launch-GUI.bat` self-elevates to admin, then launches `ZeroBreach-Server.ps1`. On failure the window
stays open and writes `zerobreach_launch_error.log` to the project root. Requires Windows 10/11,
PowerShell 5.1+, admin rights.

## Architecture

**Data flow (both servers):** Browser → POST `/api/scan/start` → server spawns `ZeroBreach-V23.ps1`
→ stdout streamed line-by-line → parsed/classified → events pushed to frontend in real time.

**Three layers:**
1. **Server** — `ZeroBreach-Server.ps1` (default) or `_python/server.py`. Hosts the UI, manages scan
   state, spawns and reads the PS subprocess.
2. **`gui/static/js/app.js`** — all frontend logic; view switching (boot → config → scan →
   remediation). Native `EventSource('/api/events')` (SSE) — **matches the PS server; there is no
   SSE/SocketIO mismatch** (the Python server uses SocketIO, but it's parked).
3. **`ZeroBreach-V23.ps1`** — the scan engine. Called via subprocess; **not modified for UI changes.**

### File structure

```
├── Launch-GUI.bat              Entry point (self-elevates)
├── ZeroBreach-Server.ps1       Pure-PS HTTP server (default). HttpListener + SSE at /api/events.
│                               SAVED WITH UTF-8 BOM — do not remove (see rules).
├── ZeroBreach-V23.ps1          THIN LOADER (also BOM). param()/elevation/schedule/globals/ALL
│                               helpers/Get-Sig/Get-Perm/banner/resilience trap/menus, then
│                               dot-sources engine/* in execution order. Self-elevates via RunAs.
├── engine/                     Dot-sourced phase modules (each UTF-8 BOM). Split BY RANGE, not
│   │                           category — phases run in numeric order and reuse vars across
│   │                           phases; dot-sourcing into the loader's ONE scope preserves that.
│   ├── Phases-1.ps1            Sections 1-11, phases 1-58 (incl. 55.5 BYOVD)
│   ├── Phases-2.ps1            Sections 12-16 front, phases 59-89 (incl. 69 mutex, 74.5/.6/.7)
│   ├── Phases-3.ps1            if($PhasePlan.Advanced) 90-105+ (incl. 99.5) + Integrity 108-115
│   ├── Summary.ps1             risk score + audit summary + stealth/auto exits
│   └── FixMode.ps1             fix-mode entry, rollback snapshot, Invoke-FixMode
├── gui/
│   ├── templates/index.html    Single-page app (the only copy; served by both servers)
│   └── static/
│       ├── css/main.css        Core styles + base :root CSS vars
│       ├── css/fx.css          VFX overlays, cmd palette, danger modal, cinematic FX toggles
│       └── js/  (load order: sound → themes → fx → kraken → app)
│           ├── app.js          SSE client, views, cmd palette (Ctrl+K), PURGE modal, CINE_FX
│           ├── sound.js        ZBSound — synthesized Web Audio SFX (no audio files)
│           ├── themes.js       ZBThemes — 12 themes + secret KRAKEN theme (inline body CSS vars)
│           ├── fx.js           ZBFX — canvas renderers + intensity tiers OFF/LITE/FULL/MAX
│           └── kraken.js       ZBKraken — ~19s "kraken" unlock cinematic
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

### Scan Engine CLI (`ZeroBreach-V23.ps1`)

Self-elevates (`Start-Process -Verb RunAs`, re-passing args). Params:

| Param | Values | Notes |
|---|---|---|
| `-Mode` | `QUICK \| FULL \| DEEP \| PARANOID \| STEALTH` | Empty = interactive menu |
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
(QUICK 30 / FULL 80 / DEEP+ 115, mirroring the loader's `$PhasePlan`).
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
- **The engine is `ZeroBreach-V23.ps1` (thin loader) + `engine/*.ps1` (dot-sourced phase modules).**
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
  `$global:ZB_ROOT` (set unconditionally near the top of the loader) for project-root paths.
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

### PowerShell engine safety (`ZeroBreach-V23.ps1`)
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
- **FP allowlists are NOT signatures** — they go in the `fp_allowlists` block of that same JSON, loaded
  via `Join-AllowRegex` (empty key → `(?!)`, suppresses nothing). No new literal lists in the `.ps1`.
- **An allowlist entry matched against attacker-controllable text (run-key values, command lines,
  task actions) must pin the ENTIRE string to the exact benign shape** — `^…$` anchors, bounded
  wildcards like `[^"]*` (never `.*` spanning the name/value boundary). A name-only prefix pattern
  lets malware self-allowlist by naming its value e.g. "Uninstall OneDrive" (caught in review,
  2026-07-02). Path-only allowlists are fine — attackers don't control where OneDrive installs.
- **Prefer downgrade-to-POSSIBLE over deleting a detection.** POSSIBLE is shown but never auto-acted-on.

### Remediation safety (`ZeroBreach-Server.ps1` — engine stays audit-only in `-Auto`)
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
  call is not — **wrap every new fetch/EventSource URL in `zbApi()`** or it will 401. Static assets
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
  `ZeroBreach-Server.ps1`), the remediation runspace (`…-RGuardPath` / `Test-RDestructiveRunCmd` /
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

### Security regression suite
- `powershell -NoProfile -File tools\tests\Run-SecurityTests.ps1` from the project root — 289
  assertions covering C1/H1/H2/H5/H7/H7b/H8, M1-M11 and the §5 FP anchors, the parse+BOM gate, and
  the embedded runspace here-strings. Every test pulls the real functions out of the shipped source
  **via the AST**, so a test cannot drift from the code it guards. **`ParseFile` on
  `ZeroBreach-Server.ps1` does NOT validate the runspace here-strings** (`$script:SCAN_SCRIPT`,
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
- **Adding a cinematic effect = one `CINE_FX` entry in `app.js` + the matching `body.zbfx-<id>` CSS**
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
- **HTTP routes** (`ZeroBreach-Server.ps1`): `GET|POST /api/profiles` (scan profiles — 4 read-only
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
  `zb_god=1`); synthesized sound; canvas VFX; command palette (Ctrl+K); EXECUTE REMEDIATION requires
  typing `PURGE`. **MSP Mode**: type "msp"/"gannon"/"staples" pre-scan → `gannon-orange` theme + badge.
- **Boot self-heal** — inline watchdog in `index.html <head>` reloads once (capped at 2 via
  `sessionStorage.zb_boot_retry`) if `window.__ZB_BOOTED` isn't set within 9s; server polls
  `Invoke-WebRequest` until 200 before opening the browser.

## Remediation test tripwires (safe, benign — never commit)

To validate scan→findings→remediation **without real malware**, drop inert artifacts named
`ZeroBreach_TEST_DELETEME` that trip a detection phase with a known fix action, then run a FULL/DEEP
scan (all time) → FINDINGS → REMEDIATION → `PURGE`. `.bat`/`.cmd` are plain text (zero AV risk).

| Artifact | Detection | Severity | FixAction |
|---|---|---|---|
| `%TEMP%\ZeroBreach_TEST_DELETEME.bat` | Phase 10 — exe-ext in Temp | HIGH | `DeleteFile` |
| `Downloads\ZeroBreach_TEST_DELETEME.cmd` | Phase 10 — exe-ext in Downloads | POSSIBLE | `DeleteFile` |
| `HKCU:\…\Run\ZeroBreach_TEST_DELETEME` | Phase 20 — Run-key data matches `Temp` | CRITICAL | `DeleteReg` |
| `…\Content.Outlook\ZBTEST\invoice_…DELETEME.bat` | Phase 74.5 — attach-ext in Outlook cache | HIGH | `Quarantine` |
| Scheduled task `\ZeroBreach_TEST_DELETEME` (disabled) | Phase 29 — action matches `cmd` | CRITICAL | `RunCmd` |

```powershell
# Create
$b = "@echo off`r`nREM ZEROBREACH TEST TRIPWIRE - SAFE TO DELETE"
Set-Content "$env:TEMP\ZeroBreach_TEST_DELETEME.bat" $b -Encoding ASCII
Set-Content "$env:USERPROFILE\Downloads\ZeroBreach_TEST_DELETEME.cmd" $b -Encoding ASCII
New-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name ZeroBreach_TEST_DELETEME `
  -Value '"%TEMP%\ZeroBreach_TEST_DELETEME_noexec.exe" --zerobreach-test' -PropertyType String -Force
$c = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\INetCache\Content.Outlook\ZBTEST'
New-Item -ItemType Directory $c -Force | Out-Null
Set-Content (Join-Path $c 'invoice_ZeroBreach_TEST_DELETEME.bat') $b -Encoding ASCII
$s = New-ScheduledTaskSettingsSet; $s.Enabled = $false
Register-ScheduledTask ZeroBreach_TEST_DELETEME -Force -Settings $s `
  -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c rem ZeroBreach_TEST_DELETEME benign no-op')

# Cleanup
del "$env:TEMP\ZeroBreach_TEST_DELETEME.bat","$env:USERPROFILE\Downloads\ZeroBreach_TEST_DELETEME.cmd" 2>$null
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v ZeroBreach_TEST_DELETEME /f 2>$null
Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\Content.Outlook\ZBTEST" -Recurse -Force 2>$null
Unregister-ScheduledTask ZeroBreach_TEST_DELETEME -Confirm:$false 2>$null
```

## Known Gotchas

- **Admin elevation**: both servers + `Launch-GUI.bat` self-elevate.
- **Port**: PS server uses `Get-FreePort` (TcpListener on port 0); Python scans from 5000.
- **Encoding**: Python subprocess output uses `encoding="utf-8", errors="replace"`.
- **PS self-detection**: Phase 2 Script Block Logging may flag the script's own run — it has a
  self-filter; verify it works.

## Outstanding Work

The bulk of the roadmap is **done and merged** (scan-blocking prompts, re-run handling, MITRE, IOC
Manager, HTML/CSV export, STEALTH parsing, real remediation, safety guard, FP rounds 1–5, engine
split + WS2 port, live finding stream + UTF-8 pipeline, VFX/themes/sound). The 2026-07-01 browser
DEEP run **passed the scan/engine path live** (115 phases contiguous, phase counter validated).
**The last standing acceptance item is the browser click-through** of destructive remediation
(PURGE + protected HARD block), export downloads, IOC save→re-scan, and STEALTH — now also
eyeballing the live finding ticker/chips and clean banner glyphs. **The prioritized roadmap lives
in `BLUEPRINT.md` §7** (WS3 FP-tune of the WS2 detections, FP sign-off list, per-phase progress
truth, scan profiles, coverage-matrix re-audit, USB field test; `NEXT_STEPS.md`/`UPGRADE_PLAN.md`
are historical context).
