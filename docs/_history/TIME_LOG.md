# TIME_LOG.md — Estimated Time Spent (full project history)

Generated 2026-07-03 from `git log` — the **entire** repository history, 2026-05-19 → 2026-07-03.

## Methodology

This is a **commit-gap estimate** (the same approach tools like `git-hours` use) — there's no
time tracker, so this is inferred from commit timestamps, not measured directly:

- Commits are sorted chronologically. If two consecutive commits are ≤2 hours apart, the gap
  between them counts as active work time.
- A gap >2 hours starts a **new session**, which gets a flat 30-minute credit for the first
  commit (can't infer real duration from a cold start).
- This **undercounts** real effort: it excludes reading/thinking time before a session's first
  commit, time spent on live scans (DEEP runs take 9-19 minutes each per `HANDOFF.md`/memory
  notes) and browser click-through testing between commits >2h apart, and any day with no commit
  at all. Loosening the gap to 3-4h (fewer, longer sessions) pushes the same history to
  ~28-34h — treat **27-32h** as the realistic band, not a precise figure.

**Total estimated: ~27.0 hours across 12 days, 17 work sessions, 66 commits.**

---

## 2026-05-19 (Tuesday) — 0.5h · 1 session · 2 commits

Repository created (`first commit`) and the pre-existing legacy codebase uploaded in bulk via
GitHub's "Add files via upload" flow. This is not new development in this tracked history — it
was superseded three weeks later by the 2026-06-09 rewrite, which the project treats as the real
initial commit (see `CLAUDE.md`: "the engine still self-identifies as V22 in some strings" —
that lineage traces back to this upload).

## 2026-06-09 (Tuesday) — 0.7h · 1 session · 2 commits

True project baseline. "Initial commit" establishes Scythe V23 "Kraken Console" — the
PowerShell scan engine plus the cyberpunk HTML/JS frontend (themes, sound, VFX, kraken cinematic)
— as the current tree. Followed immediately by a merge folding in the old 2026-05-19 upload
history so the legacy files stop conflicting with it.

## 2026-06-16 (Tuesday) — 0.8h · 1 session · 2 commits

Housekeeping day. Created local Claude Code working files for the assistant to use across
sessions, and pulled in a raw automated session dump captured from a separate "work rig" machine
— research and detection material that later sessions (2026-07-01/02) mined for WS1/WS2
signature content.

## 2026-06-22 (Monday) — 4.0h · 1 session · 4 commits

First real detection-engineering day:
- Added email attachment phishing/trojan detection (**Phase 74.5**), deliberately scoped to
  Outlook attachment caches rather than the multi-GB OST file.
- Bounded the recursive file-walk scans and added a proactive-hardening deployment policy.
- Cut WMI query storms and deferred multi-minute repair operations behind a new error trap.
- Merged all of that quarantine-branch work (perf improvements + WMI optimization + phishing
  detection) into `main`.

## 2026-06-23 (Tuesday) — 8.5h · 3 sessions · 18 commits

**The biggest day of the project.** Three distinct sessions:

**Early morning (03:05-03:06):**
- Fixed Authenticode signature-check hangs — unbounded CRL/OCSP revocation lookups were blocking
  the scan — plus general output floods and a UI freeze.
- Fixed a PowerShell 5.1 bug where `(try{}catch{})` used as an expression silently disabled
  Phases 44 and 69 (works fine on PS 7, breaks on 5.1).

**Late morning through evening (11:30-18:26), the long stretch:**
- Added bespoke per-theme canvas backgrounds and a per-view FX layer; built an FX visual-audit
  harness/checker.
- Wired **MITRE ATT&CK tagging, the IOC Manager, HTML/CSV export, STEALTH-mode parsing, and real
  remediation** end-to-end — the single largest feature-wiring commit in the project.
- Documented the benign remediation test tripwires (the `Scythe_TEST_DELETEME` artifacts
  used to validate scan → findings → remediation without real malware).
- Built the **two-layer remediation safety guard**: a hard block on protected/system-critical
  resources first, then a frontend Layer 2 plus a completion-modal count fix.
- Added trusted-vendor handling for Datto/CentraStage/Kaseya RMM partner tooling (soft-trust,
  not an auto-exclude — an independent malicious signal still overrides it).
- Shipped opt-in cinematic FX toggles plus boot self-heal (the watchdog that reloads the page if
  the app doesn't finish booting).
- Ran FP-tuning **round 1** (cert/cloaked/info-stealer over-matchers) and **round 2** (SafeBoot +
  named-pipe CRITICAL floods).

**Late night (22:57-22:58):**
- FP-tuning **round 3** (Hidden Tasks + BITS HIGH floods downgraded to non-destructive).

`HANDOFF.md` was updated repeatedly throughout the day to record progress between sessions.

## 2026-06-25 (Thursday) — 0.5h · 1 session · 1 commit

Fixed live DEEP-run noise and the real Phase-68 credential-flood bug in the engine — a
`Get-ScanFiles` piping issue (`return ,$arr` forcing the whole array through a filter as one
item) that was matching far more files than intended.

## 2026-06-26 (Friday) — 0.9h · 1 session · 4 commits

- **FP-tuning round 4**: killed 7 live auto-destructive false-positive floods, plus a PowerShell
  5.1 `Get-Sig` string-indexing bug (a single-element array silently unwraps to a string, so
  `[0]` indexed its first character instead of the array's first element).
- **Round 4b**, immediately after: fixed Phases 32 and 66 so the engine never auto-deletes
  developer-tool DLLs or the user's own executables.
- Documented the round — auto-destructive findings down from 319 to 75, validated on 3 live
  DEEP runs — and logged a HANDOFF to triage the remaining 75.

## 2026-06-28 (Sunday) — 2.2h · 1 session · 6 commits

**FP-tuning round 5, the biggest safety fix of the project**: killed a Phase-108
`icacls C:\ /reset /T` command that would reset ACLs across the **entire C: drive** on any
healthy machine, plus its ACL-cluster sibling phases. Recorded the commit, then re-graded a live
`-Hours 0` run (auto-destructive findings down to 52, confirmed the Phase-29 fix held). Also
shipped durable per-run server logs and made `scan_state` fire on every phase change instead of
a throttled tick, fixing the UI's apparent "skipped phases" symptom (it was a display artifact,
not a real engine skip). Wrote a next-steps runbook for the still-open live GUI validation.

## 2026-06-29 (Monday) — 0.5h · 1 session · 1 commit

Docs-only day: confirmed session-2's work (durable logs + the phase-skip display fix) was pushed
to origin.

## 2026-07-01 (Wednesday) — 1.8h · 2 sessions · 10 commits

**Afternoon (14:53):** Consolidated all standing rules into `CLAUDE.md` and started
`CHANGELOG.md` for bug-fix history.

**Evening (18:01-18:48), the engine split:**
- Rewrote `Scythe-V23.ps1` from one monolithic script into a thin loader plus dot-sourced
  `engine/Phases-1/2/3.ps1` modules.
- Merged in WS1/WS2 detection research from a separate work-rig branch.
- Ported those WS2 detections into the new split modules (all graded `FixAction Info` —
  non-destructive).
- Added a module-level resilience trap to each phase module, after discovering the split had a
  trap-scoping bug that could silently skip whole phase ranges (a terminating error resumed at
  the next dot-sourced *module*, not the next *phase*, dropping everything after it in that
  module).
- Fixed a Phase 53 false positive: generic ransom-note filenames now need content confirmation
  before delete.
- Documented the new split architecture and logged a session-4 handoff.

## 2026-07-02 (Thursday) — 6.1h · 3 sessions · 14 commits

**Just after midnight (00:57):** Recorded that the first live GUI DEEP run passed all 115 phases
with 0 errors.

**Early morning (01:52-02:37):**
- Found and fixed why the live finding stream had gone dead: a case-insensitive `$sev`/`$SEV`
  variable shadow that had silently disabled severity classification for weeks, plus a UTF-8
  stdout pipeline bug causing mojibake in the console banners.
- Wrote `BLUEPRINT.md` as the new product map, superseding the old planning docs.
- Built a portable release zip with Mark-of-the-Web self-unblocking.
- Made the server's phase counter track fractional phases (55.5, 74.5-.7, 99.5) as real plan
  steps instead of rounding them away.

**Mid-afternoon (14:57):** An additional commit landed more Claude Code changes.

**Evening (19:42-20:59):**
- **FP-tuning round 6** — cleared the remaining healthy-box auto-destructive tail.
- Shipped scan profiles (save/apply named scan configurations) and fixed a bug where a malformed
  JSON POST body would hang the client with no response, across every route.
- Regenerated the coverage-matrix audit against the new split engine.

**Late evening (22:36-22:38):** Wired up 15 signature keys that had been sitting unused in the
detection-signatures data file.

## 2026-07-03 (Friday) — 0.5h · 1 session · 2 commits

Made QUICK mode a real enforced 30-phase gate instead of just a label. Fixed a latent
rootkit-detection bug where a local `$pid` variable was clobbering PowerShell's automatic `$PID`
variable — the same class of case-insensitive shadow bug as the `$SEV` one from two days earlier.

---

## Totals

| Metric | Value |
|---|---|
| Estimated hours | ~27.0h |
| Days with activity | 12 |
| Work sessions | 17 |
| Commits | 66 |
| Authors | Patrick (60), zazathebird (6) |

## Notable days

- **2026-06-23** (8.5h) and **2026-07-02** (6.1h) are by far the two heaviest days — both
  FP-tuning + feature-wiring pushes running late into the night.
- **2026-06-28**'s FP-tuning round 5 is the single most consequential fix in the log: it removed
  a command that would have reset filesystem permissions across an entire healthy C: drive.
- **2026-07-01**'s engine split (a structural rewrite touching 6 files) shows only 1.8h of
  commit-gap time despite being one of the most consequential architectural changes in the
  project — the day's two sessions were separated by more than the 2h cutoff, so research/design
  time in between isn't captured. Treat low numbers on architecturally heavy days as a
  methodology artifact, not a sign of less effort.
- **2026-05-19** is a bulk upload of pre-existing code, not original development performed during
  this engagement — flag this to your boss separately if billing should exclude it.

---

## Quick-view chart — hours per day

```
Date         Day   Hours  |0    1    2    3    4    5    6    7    8    9
2026-05-19   Tue    0.5   |██
2026-06-09   Tue    0.7   |███
2026-06-16   Tue    0.8   |███
2026-06-22   Mon    4.0   |████████████████
2026-06-23   Tue    8.5   |██████████████████████████████████
2026-06-25   Thu    0.5   |██
2026-06-26   Fri    0.9   |████
2026-06-28   Sun    2.2   |█████████
2026-06-29   Mon    0.5   |██
2026-07-01   Wed    1.8   |███████
2026-07-02   Thu    6.1   |████████████████████████
2026-07-03   Fri    0.5   |██
             ───────────
             TOTAL 27.0h
```

| Date | Day | Hours |
|---|---|---|
| 2026-05-19 | Tue | 0.5 |
| 2026-06-09 | Tue | 0.7 |
| 2026-06-16 | Tue | 0.8 |
| 2026-06-22 | Mon | 4.0 |
| 2026-06-23 | Tue | **8.5** |
| 2026-06-25 | Thu | 0.5 |
| 2026-06-26 | Fri | 0.9 |
| 2026-06-28 | Sun | 2.2 |
| 2026-06-29 | Mon | 0.5 |
| 2026-07-01 | Wed | 1.8 |
| 2026-07-02 | Thu | **6.1** |
| 2026-07-03 | Fri | 0.5 |
| **Total** | | **27.0** |
