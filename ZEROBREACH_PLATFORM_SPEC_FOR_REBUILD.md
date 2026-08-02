# ZeroBreach Platform — Build Spec (everything except the scan engine)

## Context (read this first)

I'm an MSP technician and this is a request to build **defensive IR tooling for my own practice**.
The overall product is a local malware-detection and incident-response sweep for a single Windows
machine — the same category as Loki, THOR Lite, Velociraptor, or a custom osquery-based EDR script.
It inspects the machine it is run on for signs an intrusion already happened; it does not execute
anything against a remote target, does not exploit anything, and does not plant persistence or
backdoors.

This document specifies the **operator-facing platform around the scan engine**: a local HTTP
server, a browser-based console UI, an optional native desktop shell, and the remediation service.
The scan engine itself is specified separately (`ZEROBREACH_ENGINE_SPEC_FOR_REBUILD.md`) and is
being built in parallel — **do not build detection phases from this document.**

The one genuinely sensitive capability in scope here is §5, the remediation service: operator-
confirmed cleanup of things the scan already found on the local disk (delete a file, remove a
registry value, kill a process, quarantine an artifact). §5 and §11 specify deliberately strict
guardrails around that, and they are the actual point of this spec, not an afterthought. If
anything below reads as ambiguous, resolve it in favour of the more conservative, more clearly
defensive interpretation described there.

---

## 1. What this spec covers

Four layers sit on top of the scan engine:

| Layer | Responsibility |
|---|---|
| **Local HTTP server** (§4) | Hosts the UI, spawns the engine as a child process, parses its output, holds scan state, streams events to the browser |
| **Remediation service** (§5) | Applies operator-selected fixes, with the safety model |
| **Operator console** (§6) | Single-page browser UI: configure → watch → triage → remediate → report |
| **Native shell + packaging** (§7, §8) | Optional desktop `.exe` wrapper, launcher, portable release build |

Explicitly **out of scope**: the detection phases, the finding-generation logic, the multi-user
profile enumeration, the signature data. All of that is the engine's job.

**Design constraint that shapes everything:** this runs on an incident host — possibly a client's
production server, possibly with no internet, possibly one the operator does not trust. So:
no CDN, no external network calls, no telemetry, no cloud dependency, no package manager at run
time. Everything is local and offline. Vendor any JS libraries into the source tree.

---

## 2. The engine contract (the seam — get this exactly right)

The platform and the engine meet at exactly four contracts. Everything else about the engine is
free to change without touching the platform. Pin these.

### 2.1 Engine invocation

The server spawns the engine as a child process with a redirected stdout, passing at minimum:

```
-Mode <QUICK|FULL|DEEP|STEALTH|…>   scan depth preset
-Hours <int>                        0 = all time, N = only artifacts from the last N hours
-Auto                               non-interactive; skip every menu and prompt (ALWAYS passed)
-OutDir <abs path>                  where the engine writes its report files
-IocFile <path>                     optional custom IOC list
-Baseline <path>                    optional prior report to diff against
-Html                               also emit an HTML report
```

Two rules learned the hard way:

- **The server must be able to pass every flag it advises the operator to use.** In the current
  build the server prints "re-run with `-LoadUserHives`" in a blocking message, and the GUI has no
  way to pass that flag — the advice is unfollowable from the primary entry point. If a flag
  exists and matters to an operator, surface it in the UI.
- **The child's stdout encoding must be UTF-8 on both sides.** The engine sets its console output
  encoding to UTF-8 when stdout is redirected; the server reads with a UTF-8 decoder. Changing one
  side alone renders every box-drawing banner as mojibake.

### 2.2 The `[FINDING]` line — the only source of findings

The engine emits **one line per finding** on stdout:

```
[FINDING] {"id":"…","sev":"CRITICAL","phase":20,"tt":"RAT","desc":"…","target":"…","fix":"DeleteReg","group":"Persistence"}
```

Base keys: `id, sev, phase, tt, desc, target, fix, group`. Optional evidence keys, emitted only
when a check actually has them — the server expands each to a longer name for the UI:

| wire key | expanded | | wire key | expanded |
|---|---|---|---|---|
| `sha256` | sha256 | | `esrc` | evidence_source |
| `signer` | signer | | `etime` | event_time |
| `sigstat` | signature_status | | `tname` | threat_name |
| `ftime` | file_write_time | | `conf` | confidence |
| `fage` | file_age_hours | | `verdict` | verdict |
| `fsize` | file_size | | `corrob` | corroboration |
| `zone` | zone_id | | `caveat` | caveat |
| `url` / `refurl` | host_url / referrer_url | | `proc` / `pproc` | process_name / parent_process |

**`verdict = LIKELY-FALSE-POSITIVE` has behaviour attached: it suppresses auto-selection.** It is
the only evidence field the platform acts on rather than merely displays.

Two hard rules:

- **The `[FINDING]` line is the *only* way a finding enters the system.** Do not also classify
  free text into findings. An earlier build did both and double-counted every detection. The
  engine's human-readable output carries no severity tags precisely so this temptation fails
  loudly rather than silently.
- The server strips `[FINDING]` lines out of the log view — they are data, not console output.

### 2.3 Console output for the log view

Every other stdout line is human-readable console output, streamed to the UI verbatim and
severity-coloured **for display only** by tag prefix: `[CRIT]` → CRITICAL, `[WARN]` → HIGH,
`[OK ]` → CLEAN (note the padding — a matcher must tolerate the trailing space), `[HUNT]` → HUNT,
`[INFO]` → INFO. Threat-type keywords in the line drive a coloured threat bucket
(RAT / Rootkit / Ransomware / Keylogger / Worm / Miner / Trojan / Spyware / Fileless / Other).

Phase progress is parsed from phase banner lines of the form `PHASE <n>` followed by a
non-digit — where `<n>` may be fractional (`74.5`) and **the decimal must be preserved**, both for
progress and for the finding's recorded phase.

**The phase counter must be monotonic — never let a parsed number move it backwards.** The
engine's end-of-run "slowest phases" table prints `PHASE N` lines in descending-duration order,
and a naive parser reports a finished scan as 89/115 forever. Ignore any parsed phase lower than
the current one, and clamp the index to the plan total.

### 2.4 The report file

At end of run the engine writes a JSON report (`<prefix>_<yyyyMMdd_HHmmss>.json`) into `-OutDir`
containing the full findings array with `FixAction` / `FixParam` — richer than the live stream.
The remediation service reads **this file**, not the live stream, so an operator can remediate
from a scan that finished hours ago. The server also exposes it for baseline diffing.

**A filtered or partial run must be marked as such inside the report.** If the platform ever gains
a "run only these checks" feature (§6.7), the resulting report must carry a field recording the
filter. Without it, a 2-check scan produces a client-facing deliverable headed "FULL (80 checks) —
LOW, SYSTEM APPEARS CLEAN", and selecting that report as a baseline makes the next full scan report
the entire unscanned surface as newly appeared.

---

## 3. Architecture

```
Browser / native window
        |  HTTP + Server-Sent Events (localhost only)
        v
Local HTTP server  ---spawn--->  scan engine (child process, stdout parsed line by line)
        |                        remediation runspace (separate, mutually exclusive)
        v
   reports/  — scan JSON, HTML/CSV exports, quarantine vault, audit logs, durable server logs
```

One process, one port, bound to loopback. The server is both the web host and the process
supervisor. There is no database — scan state lives in memory and on disk as report files.

---

## 4. The local HTTP server

### 4.1 Startup

1. **Self-elevate to administrator.** The engine needs admin to read other users' registry hives,
   protected directories and the Security event log. Re-launch elevated and exit the unelevated
   parent.
2. **Pick a free ephemeral port** (bind port 0, read the assigned port, release). Do not hardcode
   one — incident hosts have unpredictable port usage.
3. **Bind to loopback only.** Never bind `0.0.0.0`.
4. Create the reports directory; if that fails, abort loudly with the reason (read-only drive,
   ejected USB) rather than continuing and failing later.
5. Strip the Mark-of-the-Web from the shipped files, so a release downloaded as a zip does not hit
   execution warnings. Do not touch the reports directory.
6. Poll the server's own URL until it answers 200, **then** open the browser. Opening it first
   produces a race the operator sees as a broken page.
7. Open durable log files for the session and write both the console stream and the structured
   event stream to disk. When something goes wrong mid-incident these files are the only record.

### 4.2 Route table

| Route | Method | Purpose |
|---|---|---|
| `/` , `/static/*` | GET | Serve the console UI |
| `/api/csrf` | GET | Issue the per-process CSRF token |
| `/api/state` | GET | Full state snapshot |
| `/api/events` | GET | Server-Sent Events stream (§4.5) |
| `/api/sysinfo` | GET | Host name, OS, admin status, engine version |
| `/api/scan/start` | POST only | Start a scan from a config object |
| `/api/scan/abort` | POST only | Abort the running scan |
| `/api/findings` | GET | Live findings array |
| `/api/reports` | GET | List of report files |
| `/api/report?name=` | GET | One report, MITRE-enriched, with fix actions |
| `/api/report/diff?a=&b=` | GET | Baseline comparison |
| `/api/remediate` | POST only | Apply selected fixes (§5) |
| `/api/export/html` , `/api/export/csv` | GET | Server-rendered download of current findings |
| `/api/ioc` | GET/POST | IOC manager (§6.6) |
| `/api/profiles` | GET/POST | Scan profiles (§6.5) |
| `/api/schedule` | GET/POST | Scheduled-scan management |
| `/favicon.ico` | GET | 204 |

Rules that must hold across the table:

- **POST-only routes return 405 for other verbs, not 200.** A state-changing route reachable by
  GET is reachable by an `<img src>` on any page in the operator's browser.
- **Validate every path parameter against an anchored allowlist pattern and lock it to the reports
  directory by basename.** `?name=` must not be able to escape upward.
- **Parse request bodies through one fail-closed helper.** A malformed JSON body must produce a
  400, never an unhandled throw — in the original, a naive parse threw a terminating error that
  left the client hanging with no response at all.
- **Cap the request body size *before* reading and parsing it,** not after. A length check that
  runs after the body is fully read and deserialized is not a cap.

### 4.3 The request-security gate

**Locally bound is not the same as only-the-GUI-can-reach-it.** Every page in the operator's
browser can also reach `http://localhost:<port>`. A wildcard CORS header plus a permissive preflight
once let any website drive real destructive remediation on the incident host, bypassing the typed
confirmation entirely.

Requirements:

- **Never send `Access-Control-Allow-Origin: *`.**
- **A single gate function runs ahead of the route dispatch, not inside individual handlers** — so
  a newly added POST route cannot forget it.
- Browser-origin requests (those carrying `Origin`/`Referer`) must present a valid per-process CSRF
  token, issued at `/api/csrf`. Reject cross-origin outright.
- Requests with no `Origin`/`Referer` at all are treated as local non-browser clients (scripted
  automation, test harnesses) and pass without a token. This is a deliberate trade-off: it keeps
  headless scripting workable without weakening the browser-facing gate. Do not "fix" a harness by
  loosening the browser path.
- The UI attaches the token in **one** place — a single `postJSON()` wrapper every POST goes
  through. Scattering token handling across call sites guarantees one gets missed.

### 4.4 Scan lifecycle and state

State object, held in memory: `running`, `scanComplete`, `phase`, `phaseTotal`, `phaseName`,
`section`, `elapsed`, `threatCounts`, `findings[]`, `eventLog[]`, the child process handle, a scan
epoch counter, and the path of the report the engine last wrote.

- Build the engine argument list from the posted config; **validate every value that reaches the
  command line against an anchored pattern.** Anything numeric must match `^[0-9]+…$` — use
  explicit digit ranges, not a shorthand class that also accepts Unicode digits — and trim before
  matching.
- `phaseTotal` comes from the mode's plan ceiling. **If the run is filtered to a subset, derive the
  total from the filter,** or the progress bar freezes partway while the UI declares the scan
  complete.
- **Abort must actually kill the child**, and the handle it kills must be the current one.
- On scan start, reset findings/log/counters and bump the scan epoch so late events from a previous
  run are discarded rather than mixed in.
- **STEALTH-style silent modes**: the engine emits a single compressed JSON blob at the end instead
  of a live stream. Buffer stdout for these and parse after the child exits.

### 4.5 Server-Sent Events

| Event | Payload |
|---|---|
| `log_line` | `text, severity, phase, elapsed` |
| `finding` | `id, line, severity, threat_type, phase, mitre {id,name,tactic,url}, fix_action, target, timestamp` + the expanded evidence fields from §2.2 |
| `scan_state` | `phase, phase_total, phase_name, section, elapsed, threat_counts, running` |
| `scan_complete` | `findings_count, threat_counts, elapsed, results_path, engine_report` |
| `remediation_complete` | `applied, failed, skipped, blocked, snapshot, auditLog` |
| `sync` | Full state snapshot, sent on every connect/reconnect |

**Emit `scan_state` on every phase change, plus a periodic tick.** A tick alone (the original threw
one every 12 log lines) skips sub-second phases and the operator reports "it's skipping checks".
Anything that must track phase precisely hangs off the phase-change emit, never the tick.

`sync` on connect is what makes reconnects and a second browser tab work — the client must be able
to rebuild its entire view from one message.

### 4.6 MITRE ATT&CK enrichment

The server loads an ATT&CK mapping file at start and resolves a technique for each finding:
keyword match on the finding text → threat-type map → check-number map, first hit wins. Attach
`{id, name, tactic, url}` for a clickable badge in the UI and a per-tactic rollup in the report.

Guard the fallbacks: a finding with no meaningful check number (coverage/honesty findings the
engine emits about its own blind spots) must not fall through into loose keyword matching. In the
original, a coverage finding whose text contained "TEMPORARY PROFILE" matched the keyword `temp`
and inherited an unrelated technique — a wrong ATT&CK badge on a client deliverable.

---

## 5. The remediation service and the safety model

**This is the section that matters most,** because this code runs with admin rights against
production machines that may turn out to be perfectly healthy.

### 5.1 Action set

`DeleteFile`, `DeleteReg` (a registry *value*), `DeleteRegKey`, `KillProcess`, `RunCmd`,
`Quarantine`, and `Info` (no automated action — the finding's description tells the operator what
to run by hand). These exact strings arrive on the wire in the finding's `fix` field and the
dispatch switches on them verbatim — see `ZEROBREACH_FINDING_EMIT_CONTRACT.md` §5.

**Every dispatch switch over these must have a default arm that counts the unrecognized action as
skipped.** In the current build one of two parallel switches lacks it, so an unknown action falls
through silently and is counted in neither applied, failed, nor skipped — it vanishes from the
operator's tally. If there are two copies of this switch anywhere, that duplication is itself a
defect; prefer one.

### 5.2 Protected targets — a hard block, in depth

A hardcoded protected list that **no operator override can bypass**, enforced at every layer:
the server tags the finding, the UI disables the control, and the remediation worker refuses again
at execution time and reports the attempt as `blocked`.

Coverage: the certificate trust store; `C:\Windows`, System32, SysWOW64, WinSxS; shell and core OS
files; user dotfiles; SafeBoot and core OS registry keys; killing critical system processes.

**And the tool's own files and process.** The current build protects the tool's *process* from
`KillProcess` but has no path exclusion for `DeleteFile`/`Quarantine` anywhere — so the content
scanner can quarantine the tool's own script files and break the next run. It is safe today only by
coincidence (none of the tool's files happen to trip the corroboration test), which is not an
invariant. Exclude the install root by path, explicitly, in every destructive path.

Related: the tool writes an HTML report containing finding text, the browser saves it to Downloads,
and Downloads is a scan root. **Anything the tool writes must be excluded from anything the tool
scans**, or it will detect itself next run.

### 5.3 Vendor-trusted — a soft signal

A name list of legitimate RMM / remote-support tooling (Datto, CentraStage, Kaseya, and similar).
Findings matching it get a visible trust badge and are excluded from auto-selection, but the
operator can still act on them — a legitimate vendor name can appear on a genuinely compromised
install. A vendor name found in a *suspicious path*, or alongside an independent malicious signal,
is **not** trusted and stays flagged.

### 5.4 Selection rules — both of them

1. **Auto-selection is CRITICAL/HIGH severity + a destructive action, and nothing else.** POSSIBLE
   and INFO are displayed but never pre-checked. This is the lever behind every false-positive
   downgrade: demoting a noisy detection to POSSIBLE removes it from the destructive path without
   removing the detection.
2. **Any bulk "select all" control must apply the same severity gate.** This is the single most
   expensive lesson in the project. The original's SELECT ALL filtered only on
   protected / vendor-trusted / likely-false-positive — *not on severity* — so an INFO finding
   carrying a destructive command was queued by one click. A live example shipped: an INFO finding
   whose fix parameter was `vssadmin delete shadows /all /quiet`, one SELECT ALL → confirm away from
   destroying every restore point and VSS-backed backup on an incident host, where they are often
   the only recovery path left.

   "Not auto-selected" is **not** the same as "not one-click reachable". Grade every destructive
   fix parameter against the bulk path, not just the auto-select path.

3. Any "apply hardening / posture" bulk control is a separate, deliberate opt-in, and hardening
   actions themselves are operator-only: `Info`, or POSSIBLE severity — never CRITICAL/HIGH with a
   destructive action, which would put them on the auto-select path.

### 5.5 Prefer reversible

Quarantine over delete for anything that is not hash-confirmed known-bad. Quarantine moves the file
into a vault directory inside reports, renames it with a neutral extension, and writes a sibling
JSON manifest:

```json
{ "OriginalPath": "…", "QuarantinedAs": "…", "SHA256": "…",
  "ThreatType": "…", "Severity": "…", "Description": "…",
  "QuarantinedAt": "…", "RebootQueuedForOriginal": false,
  "RestoreNote": "how to put it back" }
```

If the file is locked, queue the original for removal at next boot and record that in the manifest
so the operator knows the action is pending rather than done.

### 5.6 Verification must distinguish "gone" from "couldn't check"

A verification helper that returns "absent" on *any* failure passes in exactly the case that
matters: malware sets a deny-ACE on its own registry key, the delete fails silently, the read fails
the same way, and the operator is told the persistence was removed. Use a **tri-state** —
`gone` / `still present` / `unverifiable` — and report unverifiable as a failure, never as success.
Apply the same rule to the *pre*-check: "already absent, skipping" must not be inferred from an
access-denied read.

### 5.7 The concurrency guard

One remediation at a time, and no remediation concurrent with a scan.

- **The flag must be set by the same code that checks it**, before dispatch — not inside the worker
  the dispatch spawns. Measured on the original: the gap between the route answering and a
  worker-set flag actually rising was ~74 ms for a trivial worker and 100–200 ms for the real one.
  **No true concurrency is needed to slip through that** — plain sequential requests over loopback
  fit inside it.
- **Wrap the set→dispatch region in a sentinel + `finally`**, never a list of inline resets:
  `try { …; dispatched = true } finally { if (!dispatched) reset() }`. The original's fix created
  the mirror defect — a path-parsing call between the set and the dispatch throws on certain
  characters, the exception unwound past every inline reset, and the flag stuck on, returning
  "remediation already running" for the life of the process. One malformed request permanently
  disabled the tool's core function, mid-incident, with nothing in the UI explaining why.
- **The scan-start route needs the same treatment and the same mutual exclusion.** In the current
  build it has neither: starting a scan during a live remediation clears the findings and event log
  the remediation worker is still writing into, and starting two scans orphans the first engine
  process as unkillable while both write reports to the same second-granularity filename.
- If the accept loop is single-threaded, a plain check-then-set is safe **only because of that** —
  say so in a comment, because whoever later makes request handling concurrent silently restores the
  race.

### 5.8 Typed confirmation

Applying a batch requires the operator to type a literal word (the original uses `PURGE`) into a
modal that lists what is about to happen. This is deliberate friction. Keep it. A checkbox or a
second click is not equivalent.

### 5.9 Tamper-evident audit log

Every action appends one JSON line to `remediation_audit_<stamp>.jsonl`:

```
{ "seq": n, "ts": "ISO-8601", "id": "…", "threatType": "…", "severity": "…",
  "action": "…", "target": "…", "result": "…", "detail": "…", "prevHash": "…" }
```

Each entry's hash is computed over `prevHash + entry`, forming a chain an operator can later verify
to prove exactly what was changed and when. Optionally also write a registry rollback snapshot
before the batch, when the operator asks for one.

**The HTTP response is not proof of anything.** The remediation route answers immediately and the
work happens asynchronously. Verification means checking the filesystem/registry, the durable event
log, and the audit chain — never the response body. Anything that reports success must do so from
the audit record, not from "the request was accepted".

---

## 6. The operator console (browser UI)

A single-page app, vanilla or lightweight-framework, served by the local server. No build step is
required for it to run; no CDN.

### 6.1 Views and flow

`boot → launchpad (configure) → scan monitor (live) → findings (triage) → remediation (queue and
apply) → report`, plus an IOC manager and a settings view. Side navigation between them; the flow
is a sequence but any view is reachable at any time.

Include a **boot self-heal watchdog**: if the app has not signalled that it booted within ~9
seconds, reload once (capped at two attempts via session storage). Incident hosts have slow, odd
browsers and a blank page with no recourse is a bad first impression of an IR tool.

### 6.2 Live scan monitor

Streaming console log with severity colouring, a phase counter and progress bar, an elapsed clock,
and per-threat-type counter chips.

- **Batch DOM updates.** A real scan emits tens of thousands of lines; appending each one
  individually froze the original. Queue incoming events and flush on an animation frame.
- Cap retained log lines, with filtering (by severity chip) and a search box over the buffer.
- Include a heartbeat: if no event has arrived for a while, say so rather than looking alive.
- Autoscroll, toggleable, and it must not fight the operator scrolling up to read something.

### 6.3 Findings and triage

Group findings (by threat type, severity, or check), each row showing severity, description,
target, an ATT&CK badge, and any evidence fields the engine supplied (hash, signer, signature
status, file age, zone, parent process, verdict, caveat).

Badges that change behaviour: `protected` (checkbox disabled, cannot be queued), `vendor trusted`
(green badge, still actionable), `likely false positive` (excluded from auto-selection).

Selection controls: individual checkboxes, **auto-selection on first render per §5.4.1**, a bulk
select-all **that applies the severity gate per §5.4.2**, a separate hardening opt-in, severity
filter pills and a search box.

The remediation view shows the queue, lets items be removed, and gates execution behind the typed
confirmation modal. On completion, show applied / failed / skipped / blocked counts and the audit
log path — and keep that summary somewhere durable in the report view, not only in a toast that
disappears after three seconds.

### 6.4 Report view

Risk dial, threat-type radar, per-tactic ATT&CK rollup, an executive summary with a four-tier
verdict, a trend chart across saved baselines, and the remediation outcome.

Exports: **HTML** and **CSV** rendered server-side and downloaded; **JSON** dumped client-side; and
a **client report** — a sanitized JSON projection that strips finding IDs, fix actions, fix
parameters and internal flags, keeping only severity, category, description, ATT&CK fields and
timestamp. That last one exists because the raw dump leaks internal plumbing that should not leave
the shop. A print stylesheet that hides all chrome and survives greyscale (encode severity as shape,
not only colour) makes the report view directly printable.

### 6.5 Scan profiles

Named presets (mode + time window + options), a handful of read-only built-ins plus operator-saved
ones persisted as JSON in the reports directory. Save is upsert-by-name with fail-closed validation.
Built-ins should deliberately omit keys they do not mean to set — a built-in that carries an empty
IOC path will blank the operator's configured IOC file when applied.

### 6.6 IOC manager

Operator-managed hashes, IPs/CIDRs, domains, regexes and filenames. Persisted as JSON, and written
out in the prefixed line format the engine ingests (`hash:` / `ip:` / `domain:` / `regex:` /
`file:`), then passed to the next scan.

**IOC ingestion stays a deliberate, reviewable, per-entry act.** See §6.7.

### 6.7 If you build a "paste an alert" convenience feature — read this first

A tempting feature: paste a Defender/Datto alert, auto-extract indicators and auto-narrow the scan.
The original built it and it introduced the single worst safety defect in the project's history.

The extraction merged every domain, IP and file path scraped from prose straight into the live IOC
file, with no per-entry review. Downstream, a custom IOC domain matches a process's reverse DNS as a
**substring** at CRITICAL + kill-process, and a custom filename matches on the bare **leaf name** at
HIGH + quarantine. So an operator pasting an alert email that merely mentions
`security.microsoft.com`, a file-server IP, and a path containing `chrome.exe` armed the next scan
to auto-select killing every Microsoft-resolving process and quarantining every `chrome.exe` on the
box. Aggravating detail: version strings like `Agent 1.0.0.1` are syntactically valid IPv4 and were
extracted as IOC IPs.

If you build this:

- **Never auto-feed text-extracted indicators into a destructive matching path.** Extraction from
  prose is inherently low-precision.
- Make the IOC merge a **separate, explicitly confirmed action with per-entry checkboxes**, not a
  side effect of "apply this scan".
- Cap anything auto-extracted well below the auto-select grade.
- If a sub-step fails, do not report overall success. The original's IOC save swallowed its error
  and the flow still reported "custom scan applied".
- If the feature also narrows which checks run, **model the interaction with the mode gate before
  shipping**. The original's narrowing was AND-ed onto the existing mode gate, and the mode it
  auto-suggested silently dropped most of the checks the panel said it had selected — including,
  for a pasted phishing alert, the flagship email-attachment check. The scan then reported clean.
  A partial-match case must warn; only warning at zero matches leaves the common case silent.
- **A narrowed run must not report as a full one** — see §2.4.

### 6.8 Feature layer

The console is deliberately styled — this is a tool an operator stares at for twenty minutes while
a scan runs, and the original's users like it. Multiple selectable themes driven by CSS custom
properties, synthesized Web Audio feedback (no audio files), a canvas background VFX system with
intensity tiers (off / lite / full / max), independently toggleable cinematic overlay effects all
**defaulting to off**, and a `Ctrl+K` command palette covering navigation and the main actions.

Two rules: **honour `prefers-reduced-motion`** (drop to a static tier by default and disable chart
animations), and **keep everything keyboard reachable** with visible focus rings. An effect should
be addable by adding one entry to a list plus one CSS rule keyed off a body class — no bespoke
wiring per effect.

---

## 7. Native desktop shell (optional)

A thin native window wrapping the same unmodified server, for operators who would rather have an
`.exe` than a browser tab. The original uses Tauri v2 (Rust), reusing the same web UI.

- **Spawn the server as a child process** with a hidden window, on a free port, and point the
  webview at `http://localhost:<port>/`.
- **Tie the child to the parent's lifetime with an OS-level guarantee**, not just a cooperative
  shutdown — a Windows Job Object with kill-on-close. A crashed or force-killed shell must not leave
  an elevated engine running. Kill the child explicitly on window close and on app exit too, and be
  careful that only the *main* window's close does so, not a splash window's.
- **Preflight the webview runtime before creating any window.** If the runtime is missing, show a
  message box pointing at the installer and exit with a **distinct exit code** (the original uses 3,
  deliberately not 1). Provide an unattended opt-out (env var or flag) that skips the dialog and
  exits immediately, so automation does not hang on a modal. Put a hard deadline on the dialog.
- **Poll for readiness with a deadline** (the original: 300 ms interval, 45 s cap) and check whether
  the child already exited on each iteration, so a server that dies at startup reports *that* rather
  than timing out.
- **Write a debug log from the first line of `main`**, to a fixed path, and name that path in every
  error message. A native shell with no console and a silent failure is undiagnosable.

---

## 8. Launcher and packaging

**Launcher**: a script that self-elevates, launches the server, and — critically — **on failure
keeps the window open, writes an error log next to itself, and prints the exit code and the log
contents**. A launcher that flashes and vanishes is the single most common "it doesn't work" report.

**Portable release build**: a script that validates before it packages — every runtime file present,
every script parses on the real target runtime, every JSON file parses — and only then produces a
timestamped zip plus a SHA256 sidecar. Include an empty reports directory in the archive. Keep the
required-file manifest honest: the current one omits a data file the custom-scan feature needs, so a
release ships that feature broken.

**A parse check must run on the real runtime version being shipped to,** not a newer one. Several of
this project's worst bugs (single-element array unwrapping, sub-expression restrictions, text
decoding of files without a byte-order mark) reproduce only on the older runtime.

---

## 9. Data files consumed outside the engine

Keep these as external JSON, loaded at start:

- **ATT&CK mapping** — tactics, techniques (`id → {name, tactics[], url}`), and three lookup maps:
  keyword substring → technique, threat-type → technique list, check-number → technique list.
  Document the lookup priority.
- **IOC defaults** — starter hashes / IPs / domains / regexes / filenames.
- **Category map** (only if building §6.7) — category → {label, check numbers, keywords}, plus an
  always-include baseline set. If you build it, **verify that the checks which actually consume
  each input are present in the map**: in the original, the checks that consume IOC hashes and
  filenames appear in *no* category, so a pasted hash could never match anything while the UI said
  it would.

---

## 10. Testing — the part that was skipped, and what it cost

The original's test harness **logged thirteen assertion counts and then wrote its success marker
unconditionally.** Every count could be zero and it still printed `DONE.` It produced a documented
"clean PASS, re-validated against current HEAD" while being structurally incapable of reporting
failure — which is why a seven-agent static review later found defects in every area and the test
suite had found none.

Minimum bar for any harness in this project:

1. **A computed verdict line and a differentiated exit code.** Logging is not asserting.
2. **No completion marker on a failed or timed-out run** — and clear stale markers before starting,
   or a re-run reports success in milliseconds off the previous run's marker while nothing has run.
3. **At least one deliberate break-it run proving the harness actually goes red.**
4. **Every assertion must be *capable* of firing.** Four of the original's asserted the absence of
   output the product never emits under any condition, or grepped an unanchored substring with no
   threshold.
5. **Clear the staged input tree between runs.** A recursive copy onto an existing destination
   *nests* rather than overwrites, so the harness tested the first run's code forever.
6. **Check exit codes of native commands explicitly** — a failed build otherwise leaves a stale
   binary under test and the harness reports PASS on pre-fix code.
7. **Never fire a host-wide destructive recovery action unprompted** from a harness. The original's
   orchestrator ran a service restart that kills every VM and WSL distro on the operator's machine,
   after printing a message telling the operator to confirm it was safe first.

Cover the remediation path specifically: neither of the original's harnesses ever called the
remediation route, yet the documentation cited that path as live-proven.

---

## 11. Cross-cutting safety rules (the short list)

Everything above condenses to these. If a change violates one, it is wrong regardless of how
convenient it is.

1. **The tool must never auto-select or auto-apply anything that damages a healthy system.** Grade
   every destructive action against *every* path that can reach it in one click, not just the
   primary one.
2. **Defense in depth for protected targets** — server, UI, and worker each refuse independently.
3. **Never print a clean result for a check that could not have run.** "Didn't look" and "looked and
   it's clean" are different answers, and conflating them on an incident host is worse than no
   output at all. This applies to the platform too: a filtered scan, a truncated report, a failed
   enrichment.
4. **Fail closed.** A guard flag is raised only after the full check passes; a missing input means
   skip the action, not fall through into it; an unverifiable result is a failure.
5. **Reversible by default.** Quarantine over delete; snapshot before registry changes.
6. **Everything destructive is logged to the tamper-evident chain**, and the chain — not an HTTP
   response — is the record.
7. **No wildcard CORS, no GET-reachable state change, one CSRF choke point, one security gate ahead
   of dispatch.**
8. **Text extracted from untrusted input never auto-arms a destructive path.**

---

## 12. Suggested build order

1. **The engine contract (§2) as a stub** — a fake engine that prints a few `[FINDING]` lines and
   phase banners. Build the whole platform against this first; it makes every layer testable before
   the real engine exists, and it forces the contract to be honest.
2. **Server skeleton** — elevation, port, static hosting, the security gate, `/api/state`, SSE.
3. **Scan lifecycle** — spawn, parse, stream. Now the live monitor works end to end.
4. **Console UI** — launchpad, monitor, findings. Get the selection model (§5.4) right here, before
   any destructive code exists to select *for*.
5. **Remediation service** — §5 in full, including the audit chain and the concurrency guard, with
   the harness bar from §10 applied to it specifically. This is the one part where "we'll test it
   later" is not acceptable.
6. **Reporting and export**, then IOC manager and profiles.
7. **Native shell and packaging** last — they wrap a working product.

Swap the stub for the real engine at any point after step 3; if §2 was honest, nothing else changes.
