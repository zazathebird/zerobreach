# Triage: symptom-driven scan creation + adaptive scanning

`zbscan triage` turns a plain-language description of a sick machine into a custom scan —
and any scan can adapt mid-run to what it finds.

## Describing symptoms

Three ways in:

```
zbscan triage --symptoms "ransom note on the desktop, files renamed .locked, Defender is off"
zbscan triage --symptoms-file ticket-4711.txt
zbscan triage                      # interactive symptom wizard (12 questions + free text)
```

The text is matched against a curated symptom database (`Triage/symptoms.json`, embedded —
40+ symptom patterns covering how technicians and end-users actually describe infections:
ransom notes, browser redirects, loud fans, fake AV popups, mouse moving by itself, spam
sent to contacts, programs that come back after removal, …). Each match maps to detection
categories with a rationale, and the deepest suggested mode wins.

The derived plan is shown in full — what matched, why, what didn't map — and **you confirm
before anything runs**. Flags you type alongside `triage` beat the derived plan, exactly
like a profile. Two safety properties are fixed:

- **Nothing matched → the scan gets BROADER, not narrower**: full FULL-mode scan of all
  categories, with the unmapped text disclosed. A guess that silently narrowed the scan
  would be a false-clean generator (spec §6.7).
- Triage never runs in STEALTH (deriving and confirming a plan is a console conversation).

The database is an editable data file (same philosophy as signatures); a site can extend
it without a rebuild.

## Optional LLM assist (`--llm-assist`)

With `ZB_GEMINI_API_KEY` set, the symptom text (and nothing else — never anything from the
machine being scanned) is also sent to Google Gemini for a second opinion. Its reply is
treated as untrusted text per spec §6.6:

- it can only *suggest* categories/modes from the engine's own list — everything else it
  says is shown under "[rejected LLM output, not used]";
- suggestions that would **widen or deepen** the scan are offered for a y/N confirmation;
  a suggestion to narrow or go shallower is never even offered;
- the engine works identically without the key — assist failure falls back to the offline
  map with a note.

## Adaptive scanning (`--adaptive`, always on for triage)

Between phases, the engine extracts IPs, domains, hashes, and filenames from the findings
already raised and arms them as **detection-only** indicators (POSSIBLE severity, no fix
action — same discipline as operator IOCs) in the `custom.*` sets, so later phases hunt
what earlier phases surfaced. A C2 hit in phase 3 means the event-log phase greps for that
address too.

Every armed indicator is recorded as a **lead**. After the run:

- `<stem>-leads.json` — full lead records (indicator, kind, source finding, phase);
- `<stem>-leads.iocs.txt` — the indicators as a ready-to-use IOC file;
- `<stem>-followup.profile.json` — a generated DEEP scan profile (no category narrowing —
  a follow-up widens, never narrows) with the leads armed via the IOC file.

The follow-up is **generated, never auto-run**: the engine shows its scope and asks y/N to
chain it immediately (one level — a follow-up never chains a third pass); decline and it
prints the command to run later. In STEALTH, files are written and nothing is asked.

Findings that a later phase raises **because** of an armed lead are marked with the id of the
finding they descend from (`derived_from` in the report). They are real findings and are
reported normally, but the cross-phase correlation pass will not let them corroborate: a
finding that exists only because an earlier finding went looking for it is that finding's echo,
and counting it as an independent second opinion would let one original signal escalate its own
severity.

Escalation has no path into remediation: the §6 model (severity gate, protected targets,
typed CONFIRM, action log) is untouched by anything triage or adaptation does.
