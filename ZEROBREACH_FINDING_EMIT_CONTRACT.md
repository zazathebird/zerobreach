# ZeroBreach — Engine Output Contract

**Audience: whoever is writing the scan engine.** This is the exact stdout format the surrounding
platform (HTTP server + console UI + remediation service) parses. It is the *only* interface
between the two halves. Everything else about the engine — language, structure, which checks it
runs — is free.

This sheet exists because `ZEROBREACH_ENGINE_SPEC_FOR_REBUILD.md` §5 describes the finding *model*
in prose (`severity`, `description`, `fix_action`) while the platform parses a **shorter wire
format with two extra fields**. Where the two disagree, **this sheet wins** — it is what the
already-working server actually consumes, so an engine that matches it can be dropped into the
existing platform and tested against a known-good UI today.

---

## 1. Two kinds of stdout line

The engine writes everything to stdout. The platform splits it into exactly two streams:

| Line shape | Treated as |
|---|---|
| `[FINDING] {json}` | **Structured data.** Parsed into a finding. Removed from the log view. |
| anything else | **Console output.** Streamed to the operator's log view verbatim, colour-coded. |

**Findings enter the system through `[FINDING]` lines and nowhere else.** Do not also encode
severity into the human-readable text hoping the platform will pick it up — an earlier build
classified both ways and double-counted every detection. Human-readable output deliberately
carries no severity semantics.

---

## 2. The `[FINDING]` line

Literal prefix `[FINDING]`, one space, then **compact single-line JSON** (no pretty-printing, no
embedded newlines — one finding per line, always).

```
[FINDING] {"id":"RUNKEY_a3f21c08","sev":"CRITICAL","phase":20,"tt":"Trojan","desc":"Run key value points into %TEMP%","target":"HKCU\\...\\Run\\Updater","fix":"DeleteReg","group":"Persistence"}
```

### Base keys — all eight, always present

| key | type | notes |
|---|---|---|
| `id` | string | Stable, deterministic. See §3. |
| `sev` | string | `CRITICAL` \| `HIGH` \| `POSSIBLE` \| `INFO` |
| `phase` | number | Check number. **Keep the decimal on fractionals** (`74.5`, not `74`). |
| `tt` | string | Threat type — see §4. |
| `desc` | string | Human-readable: what was found and why it's suspicious. |
| `target` | string | The file path / registry key / process / task affected. |
| `fix` | string | Fix action — see §5. |
| `group` | string | Category label for report grouping (`Persistence`, `C2`, …). |

`phase` and `tt` are the two the engine spec's §5 list omits. Both are load-bearing: `phase` drives
progress correlation and the ATT&CK check-number fallback; `tt` drives the live threat counters and
the ATT&CK threat-type lookup. Emitting `"Other"` for `tt` is fine when nothing better fits;
omitting it is not.

### Optional evidence keys

Emit only when the check genuinely has the value. The platform expands each to a longer name for
display; absent keys are simply not rendered.

| wire | expands to | | wire | expands to |
|---|---|---|---|---|
| `sha256` | sha256 | | `proc` | process_name |
| `signer` | signer | | `pproc` | parent_process |
| `sigstat` | signature_status | | `esrc` | evidence_source |
| `ftime` | file_write_time | | `etime` | event_time |
| `fage` | file_age_hours | | `tname` | threat_name |
| `fsize` | file_size | | `conf` | confidence |
| `zone` | zone_id | | `verdict` | verdict |
| `url` | host_url | | `corrob` | corroboration |
| `refurl` | referrer_url | | `caveat` | caveat |

**One of these has behaviour attached, not just display:**

> `"verdict":"LIKELY-FALSE-POSITIVE"` **suppresses auto-selection** for that finding.

That is the intended way to ship a detection you're unsure about at full severity without putting
it on the destructive path. The other evidence keys are purely informational.

`verdict` also carries `UNPROVEN` for "this check could not actually run" (§7).

### Worked examples

```
[FINDING] {"id":"MASQPE_7d1e44b2","sev":"HIGH","phase":90,"tt":"Trojan","desc":"File has .txt extension but MZ/PE magic bytes","target":"C:\\Users\\bob\\Downloads\\notes.txt","fix":"Quarantine","group":"Masquerading","sha256":"9f2b...","fsize":184320,"zone":"3","url":"http://example.invalid/n.txt"}

[FINDING] {"id":"DUMPTOOL_1a9c03fe","sev":"POSSIBLE","phase":106,"tt":"Other","desc":"Credential-dumping tool present; Authenticode signature is valid Microsoft Corporation, so this is likely a legitimate admin toolkit","target":"C:\\Tools\\SysinternalsSuite\\procdump64.exe","fix":"Info","group":"Credential Access","signer":"Microsoft Corporation","sigstat":"Valid","verdict":"LIKELY-FALSE-POSITIVE"}

[FINDING] {"id":"PROCAUDIT_BLIND","sev":"INFO","phase":107,"tt":"Other","desc":"Process-creation auditing is disabled on this host; the 4688 command-line checks could not run. This is NOT a clean result.","target":"Security event log","fix":"Info","group":"Scan Coverage","verdict":"UNPROVEN"}
```

Note the JSON string escaping on Windows paths: `\\` for a backslash.

---

## 3. Finding IDs

**Deterministic across runs and across processes**, so a re-run diffed against a prior baseline
doesn't report everything as new. Use a stable hash (FNV-1a over UTF-8 is what the current build
uses) — **never a language-runtime string hash**, which is randomised per process on modern .NET
and made every baseline diff report the same finding as new forever.

**Unique per *thing found*, not per name.** The platform de-duplicates on `id` with an early
discard, so a too-weak ID doesn't merely mislabel — it **silently drops** every later match. Real
cases from the current build:

- An ID built from a filename that is *always* `config.json` collapsed every miner config on the
  box into one finding.
- `procdump.exe` in two user profiles hashed to one ID; the second user's copy was never
  remediated.
- The same browser extension in Chrome and Edge shares a store ID; the Edge copy was discarded and
  left installed.

Hash the full path plus any real discriminator (the user SID for per-user artifacts, the stream
name for alternate data streams, the value name for registry values). Where one object is reachable
by two paths (junctions, redirected folders), key on identity — name + size + mtime — rather than
the path string.

---

## 4. Threat types (`tt`)

`RAT` · `Rootkit` · `Ransomware` · `Keylogger` · `Worm` · `Miner` · `Trojan` · `Spyware` ·
`Fileless` · `Other`

These drive the live counter chips and one of the ATT&CK lookups. Anything outside the list falls
through to `Other`.

---

## 5. Fix actions (`fix`)

**Exact strings — the remediation service switches on these:**

| value | effect |
|---|---|
| `DeleteFile` | Delete the file at `FixParam` |
| `DeleteReg` | Delete a registry **value** |
| `DeleteRegKey` | Delete a registry **key** |
| `KillProcess` | Terminate the process |
| `RunCmd` | Execute the command in `FixParam` |
| `Quarantine` | Move to the vault + write a restore manifest (**reversible — prefer this**) |
| `Info` | No automated action; the operator reads the description and acts by hand |

The first six are **destructive**. `Info` is not.

### The safety rule that governs this field

> **`CRITICAL`/`HIGH` + a destructive action = auto-selected for remediation.** That combination
> pre-checks the finding in the UI, and the operator's bulk confirm applies it.

So the severity/action pair *is* the safety decision. Consequences:

- **Never ship a destructive `FixParam` that could fire on a healthy box.** No `icacls /reset /T`,
  no `vssadmin delete shadows /all`, no recursive deletes, no drive-root operations. Put the
  command in `desc` and use `fix":"Info"`.
- **Hardening / posture / lockdown actions are operator-only** — `Info`, or at most `POSSIBLE`.
  Never CRITICAL/HIGH with a destructive action, which would auto-fire them on a clean machine.
- **Downgrade to `POSSIBLE` rather than deleting a noisy detection.** POSSIBLE is displayed but
  never auto-selected — it's the pressure-release valve for anything you're unsure about.
- Prefer `Quarantine` over `DeleteFile` for anything not hash-confirmed malware.
- Gate tool-name detections on a signature check before going destructive. The current build ships
  a CRITICAL + `DeleteFile` on a bare `procdump*.exe` glob with no Authenticode gate — it deletes
  Microsoft's signed Sysinternals ProcDump off a technician's own toolkit.

Note the platform *also* enforces a hard-blocked protected-target list (OS directories, cert store,
the tool's own files) independently, at three layers. That's a backstop, not a licence — the engine
is expected to get the severity/action pair right on its own.

---

## 6. Console output (everything that isn't a `[FINDING]` line)

Streamed to the operator's live log and colour-coded on a tag prefix:

| prefix | renders as |
|---|---|
| `[CRIT]` | CRITICAL |
| `[WARN]` | HIGH |
| `[OK ]` | CLEAN — **note the padding space; keep it exactly as shown** |
| `[HUNT]` | HUNT |
| `[INFO]` | INFO |

### Phase banners

Print one banner as each check starts. The platform parses `PHASE <n>` followed by a non-digit:

```
PHASE 74.5 — Outlook attachment cache scan
```

- **Keep the decimal on fractional numbers.** They count as real plan steps.
- **Anything printed later that mentions a phase number must not move the counter backwards.** The
  platform ignores a lower number defensively — an end-of-run "slowest checks" table printed in
  descending order otherwise reports a finished scan as stuck at 89/115 forever — but don't rely on
  that being the only such guard.

### Encoding

**Write stdout as UTF-8 when it is redirected.** The platform reads with a UTF-8 decoder. A
mismatch renders every box-drawing banner in the operator's console as mojibake.

---

## 7. Never print a clean result for a check that could not run

The single most important output rule, and it applies to the console line *and* the finding stream.

A green `0 SUSPICIOUS PROCESS-CREATION EVENTS` from a host where process auditing is switched off
is worse than no output at all — it's a false all-clear on an incident host. Any check whose
visibility depends on a policy setting, log retention, file access, a mounted registry hive, or an
enumeration budget must test that precondition and, when it fails, emit an explicit **"this check
was blind"** finding (INFO + `Info` + `"verdict":"UNPROVEN"`) *instead of* — never as well as — the
clean line.

Prefer an **empirical** precondition test over a configuration one: *does the log actually contain
any such event?* beats parsing a policy tool, which is localised and can be misread. A config
source may act only as a **veto** — able to push the verdict toward "blind", never toward "clean" —
and an unrecognised value degrades to unknown, not to clean.

Same principle applies to budgets: if a filesystem or registry walk hits its cap and returns early,
that is a truncated result, not a clean one. Say so, and scale the budget with the number of roots
being walked — a fixed budget shared across N user profiles silently gives profiles 2..N zero
coverage while the check still prints green. That was the most consequential bug in the current
engine.

---

## 8. Command-line interface

The platform spawns the engine with a redirected stdout and passes:

| flag | meaning |
|---|---|
| `-Mode <QUICK\|FULL\|DEEP\|…>` | Depth preset |
| `-Hours <int>` | `0` = all time, `N` = only artifacts from the last N hours |
| `-Auto` | Non-interactive: skip every menu and prompt. **Always passed.** |
| `-OutDir <abs path>` | Where to write report files |
| `-IocFile <path>` | Optional custom IOC list |
| `-Baseline <path>` | Optional prior report to diff against |
| `-Html` | Also emit an HTML report |

`-Auto` must be absolute — a single interactive prompt reached under `-Auto` hangs the server-driven
scan with no output and no error, which is indistinguishable from a crash.

Any additional flag the engine supports needs a corresponding UI control. The current build prints
"re-run with `-LoadUserHives`" in a blocking message for a flag the GUI has no way to pass.

### IOC file format

Prefixed lines, one per indicator: `hash:` · `ip:` · `domain:` · `regex:` · `file:`

---

## 9. The report file

At end of run, write `<prefix>_<yyyyMMdd_HHmmss>.json` into `-OutDir` containing the full findings
array with the fix action **and its parameter** (`FixParam` — the actual path/command, which is
deliberately *not* in the live stream). The remediation service reads this file rather than the
live stream, so an operator can act on a scan that finished hours ago.

**If the run was narrowed to a subset of checks, record that in the report.** Without a marker, a
two-check scan produces a client-facing deliverable headed "FULL (80 checks) — LOW, SYSTEM APPEARS
CLEAN", and picking that file as a baseline makes the next full scan report the entire unscanned
surface as newly appeared.

---

## 10. Checklist

- [ ] `[FINDING]` prefix, compact JSON, one line per finding, no embedded newlines
- [ ] All eight base keys on every finding, including `phase` (decimal preserved) and `tt`
- [ ] IDs deterministic across processes and unique per *thing*, not per name
- [ ] `fix` uses the exact strings in §5
- [ ] No CRITICAL/HIGH + destructive action that can fire on a healthy machine
- [ ] Hardening actions are `Info` or `POSSIBLE`
- [ ] Uncertain detections use `POSSIBLE`, or `"verdict":"LIKELY-FALSE-POSITIVE"`
- [ ] Blind checks emit `UNPROVEN` instead of a clean line
- [ ] Console lines tagged `[CRIT]`/`[WARN]`/`[OK ]`/`[HUNT]`/`[INFO]`
- [ ] `PHASE <n>` banner per check
- [ ] stdout is UTF-8 when redirected
- [ ] `-Auto` reaches no prompt, ever
- [ ] Report JSON written to `-OutDir` with `FixParam` included

**Fastest way to verify all of it:** point the existing `ZeroBreach-Server.ps1` at the new engine
and run a scan. Findings appearing live in the UI with correct severities, working ATT&CK badges,
a progress counter that reaches the ceiling and never rewinds, and a populated remediation queue
means the contract is met end to end.
