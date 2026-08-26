# ZeroBreach Scan Engine — Build Spec

> **Status: this is the contract for the NATIVE engine, and it has been implemented.** The engine
> described below exists as the C# / .NET 8 `zbscan` in this repository — all 10 phases, the §6
> safety model, remediation, reporting, and operator tooling. §8 permitted a compiled language
> provided the destructive remediation logic stays in a separate auditable module; it does
> (`ZeroBreach.Remediation`). This document is kept **unchanged as the normative requirements
> source** — read it for *why* a rule exists. For the architecture as built and the catalog of
> what each check inspects, see `INSTRUCTIONS_AI.md`.
>
> **Scope note (2026-08-22):** the repo ships **two maintained engines** — this native one, and
> the PowerShell fallback (`ZeroBreach-V23.ps1` + `engine/*.ps1`, 162 phases). This spec governs
> the native engine only; its mode table below (QUICK/FULL/DEEP/STEALTH) does not describe the PS
> engine, which additionally has `-Mode HUNT` (phases 134-162). **`BLUEPRINT.md` §2 is the
> top-level map of both** — start there, not here. The V23 engine referenced as an ancestor in
> the Context section is not merely an ancestor any more; it is the maintained fallback, in this
> same repo.
>
> §1's rule that this is "explicitly not a network scanner, or something that touches any machine
> other than the one it's run on" is **still in force and applies to both engines** — it is what
> justified building PS phases 153-156 host-side and dropping the briefed `-ScanLan` switch.

## Context (read this first)

I'm an MSP technician and this is a request to build **defensive IR tooling for my own practice** —
a local malware-detection sweep, in the same category as Loki, THOR Lite, Velociraptor, or a
custom osquery-based EDR script. It scans the machine it's run on for signs an intrusion already
happened; it does not execute anything against a remote target, does not exploit anything, and
does not plant persistence or backdoors. The only "destructive" capability anywhere in this spec
is optional, operator-confirmed cleanup of things the scan already found on the local disk
(delete a file, remove a registry value, kill a process) — and §6 below specifies deliberately
strict guardrails around that (auto-action only on high-confidence findings, hard-blocked
protected paths, typed confirmation, reversible-by-default actions, tamper-evident logging). If
anything below reads as ambiguous, resolve it in favor of the more conservative, more
clearly-defensive interpretation described in §6 — that section is the actual point of the spec,
not an afterthought.

This is a spec for a **standalone Windows malware-detection / incident-response scan engine**,
extracted from an existing working project (ZeroBreach V23 "Kraken Console"). It describes the
engine only — no GUI, no HTTP server, no native shell. The goal is a self-contained script (or
small set of scripts) that a technician can run on a Windows machine to sweep it for signs of
compromise and report findings, with a clear, conservative safety model around any remediation.

---

## 1. What the tool does

A single technician-run scan that:

1. Walks the local filesystem, registry, running processes, scheduled tasks, WMI subscriptions,
   network connections, and Windows Event Log for **indicators of compromise** — both known-bad
   signatures and generic suspicious *patterns* (not signature-matching specific commercial AV
   vendor rule sets — behavioral/structural heuristics).
2. Classifies each hit as a **finding**: a severity, a description, a MITRE ATT&CK mapping, and a
   suggested remediation action.
3. Reports findings to the operator (console output and/or a JSON/HTML report).
4. Optionally lets the operator **remediate** selected findings (delete a file, remove a registry
   value, kill a process, quarantine an artifact) — but only after explicit, typed confirmation,
   and never for anything that could plausibly be a false positive or system-critical.

It is explicitly **not**: a real-time protection product, a network scanner, an exploitation
framework, or something that touches any machine other than the one it's run on.

## 2. Scan modes

A single CLI entry point with a small number of preset depths, so the operator can trade time for
thoroughness:

| Mode | Rough scope | Use case |
|---|---|---|
| QUICK | A small fixed set of the highest-signal checks (~30 checks) | Fast triage, "is this box obviously infected" |
| FULL | A broader set covering most categories | Standard IR engagement |
| DEEP | Everything, including slower/more exhaustive checks (registry hive walks, full YARA-lite content scanning, boot integrity, ACL/permission checks) | Confirmed incident, time not a constraint |
| STEALTH | Same depth as FULL/DEEP but silent — no console chatter, single compressed JSON blob at the end | Running unattended / logging-averse environments |

Other flags worth having: a time-window filter ("only look at things created/modified in the last
N hours"), a custom IOC file (hashes/IPs/domains/filenames to also check for), and a "diff against
a prior baseline scan" mode so re-runs only flag *new* findings.

## 3. Detection categories (what it looks for)

Organize checks into numbered "phases" that run in sequence and print a banner as each starts —
this makes progress legible and makes it easy to add more checks later without restructuring
anything. Category buckets, roughly in order of how a real intrusion is usually investigated:

- **Persistence** — Run/RunOnce registry keys, scheduled tasks, services, WMI event
  subscriptions, startup folder items, browser extensions, Office macro/add-in trust settings,
  AppInit/IFEO/COM hijack points, shell extensions.
- **Defense evasion** — AMSI/ETW tampering indicators, disabled security tooling, unusual
  process-injection artifacts, LOLBin abuse patterns (living-off-the-land binaries used in
  atypical ways), timestomping (file times inconsistent with filesystem journal order).
- **Command & control / RAT** — known C2 framework artifacts (named pipes, config file shapes,
  beacon-like periodic DNS/HTTP patterns), remote-access-tool residue, tunneling tool presence
  (dual-use — flag but don't auto-act).
- **Credential access** — credential-dumping tool presence (by hash/signed-binary check, not by
  bare filename), LSA protection state, NTLM policy, DPAPI artifact anomalies.
- **Ransomware indicators** — ransom-note filename patterns, known-extension renames, abnormally
  high file entropy in user document folders, Volume Shadow Copy deletion commands.
  **Never auto-delete shadow copies — that command is exactly the kind of thing that should be
  Info-only, operator-run-by-hand, never scriptable in one click.**
- **Email/phishing residue** — malicious-construct matching in cached mail attachments (not full
  mailbox scanning — scope to the attachment cache, never the multi-gigabyte mail store).
- **Rootkit / boot integrity** — hidden process/handle discrepancies (compare two different
  enumeration methods and flag mismatches), driver signature/BYOVD (bring-your-own-vulnerable-
  driver) checks, boot configuration tampering, MBR/bootkit indicators.
- **Permission/ACL integrity** — comparing critical system file/registry permissions against a
  known-good baseline, flagging unexpected ownership or ACE changes.
- **General file/content scanning** — a lightweight YARA-like content matcher (magic-byte sniff +
  bounded read + pattern match) over a budgeted set of files, for known malware family strings —
  should require content corroboration (not bare tool-name matching) to avoid flagging security
  research or documentation that merely *mentions* a malware family by name.

None of this needs literal malicious byte sequences hardcoded into the main script — put any
signature strings/hashes/patterns in an external data file the script loads at runtime. This
keeps the engine script itself readable by AV/AMSI without tripping "contains malicious content"
heuristics, and makes it easy to update signatures without touching logic.

## 4. Multi-user awareness

On a shared/multi-user machine, don't just check the running technician's own profile — enumerate
every user profile on the box (via the registry `ProfileList` key) and check each one's per-user
persistence locations (Run keys, startup folder, browser data, Office trust settings). For a
logged-off user, their registry hive isn't mounted by default — make loading it an explicit opt-in
flag, never automatic, and always report clearly when a profile's registry was *not* checked
rather than silently treating "didn't look" the same as "looked and it's clean."

**This is the single most important architectural lesson from the existing project**: whatever
enumeration budget/cap you put on a filesystem or registry walk (file count limits, time
deadlines), that budget has to scale with the number of things being walked, and the walk has to
signal when it was cut short. A shared fixed budget across N users' profiles means later profiles
silently get zero coverage while the tool still reports "clean" — which is worse than not
scanning at all, because it's actively misleading.

## 5. The finding data model

Every finding should carry, at minimum:

```
id          - a stable, deterministic identifier (hash of the real identity of the thing found —
              full path + relevant discriminator, NOT just a filename, NOT a random/process-based
              hash — so re-running the scan doesn't report the same thing as "new" every time,
              and so two different things with the same filename don't collide into one ID)
severity    - CRITICAL | HIGH | POSSIBLE | INFO
description - human-readable explanation of what was found and why it's suspicious
target      - the file path / registry key / process / task name affected
fix_action  - none | delete_file | delete_registry_value | kill_process | quarantine | run_command
fix_param   - the actual command/path needed to apply fix_action, if any
mitre       - ATT&CK technique ID/name/tactic, where mappable
group       - a category label for grouping in a report (matches the category list in §3)
```

## 6. The safety model (do not compromise on this)

This is the part that matters most, because the tool runs with admin rights against production
machines that might turn out to be perfectly healthy:

1. **Auto-select for remediation is CRITICAL/HIGH severity + a destructive fix_action, and
   nothing else.** POSSIBLE and INFO findings are shown to the operator and can be acted on
   manually, but are never pre-checked/auto-queued.
2. **A hardcoded "protected targets" list is a hard block that no override can bypass** —
   core OS directories, the certificate trust store, the tool's own files/process. Check this
   in every code path that can trigger a destructive action, not just the primary one.
3. **A "vendor trusted" soft-list** (known legitimate RMM/remote-support tooling by name) —
   flagged with a trust badge but still actionable, since a legitimate vendor name can still
   appear on a genuinely compromised install.
4. **Prefer reversible actions.** Quarantine (move to an internal vault folder + rename +
   write a small JSON manifest with the original path, so it can be restored) over outright
   delete, for anything that isn't a hash-confirmed, known-bad file.
5. **Any bulk "select all remaining findings" UI/CLI action must filter on the same severity
   gate as the individual auto-select logic** — a bulk action that only filters on
   "not already excluded" reopens exactly the hole rule #1 exists to close, because an
   INFO-severity finding can still carry a destructive fix_param meant to be read and typed
   by hand, not queued.
6. **Never auto-feed anything extracted from free-form/untrusted text (a pasted alert, a
   log excerpt) directly into a destructive matching path.** If you build any "paste an alert,
   auto-extract IOCs" convenience feature later, treat every extracted indicator as needing
   individual operator confirmation before it's live — text-extracted IOCs are low-precision
   (version strings parse as valid IPs, a mentioned domain isn't necessarily malicious) and
   auto-arming them onto a kill/delete path is a real way to damage a healthy machine.
7. **Never print a "clean" result for a check that couldn't actually run.** If a precondition
   is missing (a log source is disabled, a hive failed to load, an enumeration hit its budget
   and returned early), say so explicitly — a distinct "this check was inconclusive" state,
   never silently folded into "nothing found."
8. **A guard flag that gates a destructive action must be set by the code that checks it, and
   reset by every path away from it — including exceptions.** Use a set-then-`finally`-reset
   pattern for any "is a remediation currently running" concurrency guard, not a list of
   inline resets you have to remember to keep complete.
9. **Require a typed confirmation before applying any batch of remediations** (e.g. operator
   must type the literal word "CONFIRM" or similar, not just click a button) — this is a
   deliberate friction point, keep it.
10. **Log every remediation action taken to an append-only, tamper-evident log** (a simple
    hash chain — each entry's hash includes the previous entry's hash — is enough) so an
    operator can later prove exactly what was changed and when.

## 7. Output / reporting

- Live progress to the console as each phase runs (phase number, name, elapsed time).
- A structured findings list emitted in a machine-parseable form (one JSON object per finding,
  on its own line, is a good choice — simple to consume, simple to append to a report file, and
  trivially greppable).
- An end-of-run summary: total findings by severity, an overall risk verdict, elapsed time.
- Optionally, an HTML report for handing to a client, and a JSON report for feeding into
  whatever tooling (a wrapper UI, a ticketing system) is consuming this.

## 8. Suggested tech shape

The original is PowerShell (fits naturally into a Windows admin/IR workflow — no runtime to
install, runs from a signed, trusted interpreter, has native access to the registry/WMI/Windows
Event Log). That's a reasonable default for a "just the engine" rebuild too, since PowerShell
being Microsoft-signed means only the *script content* needs AV/AMSI-safe handling (keep
signature data in an external file, not inline string literals, for that reason), whereas a
compiled `.exe` doing the same filesystem/registry/process operations reads to endpoint security
products as much more suspicious with none of the code-signing reputation to offset it.

If a compiled language is preferred instead (better performance on deep filesystem/registry
walks, access to things PowerShell genuinely can't reach — raw NTFS metadata, ESE database
files, decompressing Prefetch), that's a legitimate choice too — just keep any actual
destructive remediation logic in a clearly separate, minimal module so it's easy to audit
against the rules in §6 independent of the (much larger) detection logic.

---

**Summary of what to ask a fresh session to build:** a Windows scan engine that walks the
categories in §3 across every user profile per §4, emits findings shaped per §5, follows the
safety rules in §6 without exception, and reports per §7 — starting with just a handful of
high-signal checks (persistence + a couple of C2/ransomware indicators) to get the finding
model and safety gates right, then expanding category by category.
