# Operator features: IOC extraction, baselines, vault lifecycle, reports

Companion to `CUSTOM_SCANS.md`. These are the operator conveniences layered on top of the
scan presets — each one deliberately shaped by the spec §6 safety model.

## Time budget (`--max-minutes`) and cancellation coverage

`--max-minutes N` puts a hard wall-clock cap on a scan — useful when a maintenance window
is fixed and DEEP would overrun it. The deadline is a cooperative cancel, and (same for a
Ctrl+C interrupt) **every phase that never got to run is reported as UNCHECKED** in the
checks list and summary, so a timed-out scan exits 3 ("coverage gaps") and can never be
mistaken for a clean full run (spec §6.7). Like other per-run decisions, a profile cannot
set it.

## Engagement metadata (`--case`, `--operator`)

`--case INC-2026-081 --operator pat` stamps the case id and operator name into the JSON
report (`case_id` / `operator`) and the HTML header — so a report handed to a client or
attached to a ticket is self-identifying. Per-run only; never saved into profiles.

## Reading reports back (`scythescan report show`)

`scythescan report show <file>` re-renders any saved report — plain `.json` or the STEALTH
`.json.gz` blob (detected by content, so a renamed file still loads): summary, findings,
checks that did not complete, phase timings. Exit codes mirror a live scan (0 clean,
2 findings, 3 coverage gaps), so scripts can consume a stealth blob the same way as a run.

## Linting rules files (`scythescan rules lint`)

`scythescan rules lint <file>` loads a custom rules/IOC file exactly the way a scan would —
JSON rules shape or plain-text indicator lines — and reports the sets and entry counts it
produced plus every load error (malformed JSON, bad regexes, empty patterns), without
scanning anything. Catch the typo'd regex at authoring time, not mid-engagement.

## Extracting IOCs from a pasted alert (`--extract-iocs`)

You often arrive at a machine holding free-form text: an EDR alert, a threat-intel note, a
ticket. Save it to a file and run:

```
scythescan --mode FULL --extract-iocs alert.txt
```

The engine extracts indicator candidates — SHA-256 hashes, IPv4 addresses, domains,
suspicious filenames — including defanged forms (`hxxp://`, `evil[.]com`). Then, per
spec §6.6, **each candidate is shown individually** with the source line it came from and
any caution (private/reserved IP, looks-like-a-version-number), and is armed only if you
answer `y` to that specific item:

- There is no "yes to all". Text-extracted IOCs are low-precision by nature — version
  strings parse as valid IPs, a mentioned domain isn't necessarily malicious.
- Confirmed indicators are **detection-only for this run**: they land in the `custom.*`
  signature sets at POSSIBLE severity with no fix action, so a hit produces a finding for
  you to review, never a queued destructive action.
- They are never written to a profile or any persistent file — arming is a per-run,
  per-indicator decision.
- Incompatible with STEALTH mode (the confirmation conversation needs a console).

If you have already-vetted indicators, `--ioc-file` remains the right tool: one indicator
per line, no interactive review, same detection-only discipline.

## Baseline sanity warnings (`--baseline`)

Baseline-diff mode suppresses findings whose deterministic ids appeared in a prior run —
which means a *wrong* baseline silently hides real findings. Before applying one, the
engine now warns (on stderr, without stopping the scan) when the baseline:

- was created on a **different host** — a foreign baseline can suppress real findings on
  this machine;
- is **more than 30 days old** — the machine may have drifted; refresh with
  `--save-baseline`;
- is **future-dated** beyond clock-skew tolerance — clock skew or an edited file.

The count of baseline-suppressed findings is always disclosed in the summary, as before.

## Vault lifecycle: `verify` and `purge`

`scythescan vault verify` integrity-checks every vaulted file against the SHA-256 recorded in
its manifest at quarantine time — read-only, and the companion to the tamper-evident
action log: together they prove both *what was done* and *that the evidence is intact*.
Items report as ok, no-hash (couldn't be hashed at quarantine time — unprovable either
way, never assumed fine), MISSING, or TAMPERED; any missing/tampered item makes the
command exit 2.

Quarantine is reversible by design (spec §6.4) — but a confirmed-bad file shouldn't sit in
the vault forever. `scythescan vault purge <id>` permanently deletes one quarantined file and
its manifest:

- shows the original path, hash, and size first, then requires the typed
  `CONFIRM` word (same friction as remediation, spec §6.9);
- refuses ids that look like paths and any manifest whose vault file points outside the
  vault root — a tampered manifest cannot turn purge into an arbitrary-file delete;
- writes a `purge_from_vault` entry (with the file's SHA-256) to the tamper-evident
  action log, so what was destroyed remains provable.

## `scythescan log verify` and the truncation anchor

The action log is a hash chain, which catches an entry being edited or removed from the
middle. It cannot, on its own, catch **truncation** — deleting entries from the end leaves a
shorter chain that still verifies link by link, which would let the record of what was
destroyed be quietly erased. So every append also writes an anchor file beside the log
(`action-log.jsonl.anchor`: entry count, last sequence number, head hash), and `log verify`
reports one of three outcomes (from four internal `ChainState` values — `Broken` and
`Truncated` both surface as TAMPER EVIDENT):

- **OK** (exit 0) — every link verifies and the anchor confirms the end of the log.
- **TAMPER EVIDENT** (exit 2) — an entry was edited or removed mid-chain, or the log is
  shorter than the anchor records (or missing entirely) — i.e. truncated.
- **UNVERIFIABLE** (exit 3) — the links verify, but the anchor is absent or stale, so
  truncation cannot be ruled out. This is deliberately **not** reported as OK: a chain whose
  completeness could not be checked is a coverage gap, the same rule spec §6.7 applies to
  scan checks.

The anchor is not a secret and can be deleted along with the log. What it buys is that
shortening the record now takes two consistent edits instead of one, and that the tool never
claims an unprovable log is intact.

## `scythescan categories`

Prints the detection categories in the running build — phase number, group name (the token
`--only`/`--skip` and profiles accept), minimum scan mode, and the phase's full name. Read
from the actual scanner list, so it can never drift from the code.

## Per-phase timings in reports

The JSON (and HTML) report now carries a `phases` array — phase number, name,
`elapsed_seconds`, findings count for every phase that actually executed (including one
that crashed or was cancelled mid-run; skipped/excluded phases record nothing, they are
already disclosed as unchecked). Useful for spotting where DEEP runs spend their time and
for tuning budgets.
