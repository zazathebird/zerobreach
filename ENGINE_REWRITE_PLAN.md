# Engine Rewrite Plan — ZeroBreach (2026-07-27)

**Status: APPROVED IN PRINCIPLE, NOT STARTED.** Operator approved a rewrite ("rewrite the engine
using whatever you want") on 2026-07-27 after reviewing the audit in `REVIEW_FINDINGS_2026-07-27.md`.
This document records the design, the sequencing, and — most importantly — **why the rewrite is
sequenced behind two prerequisites** rather than started immediately.

Read `REVIEW_FINDINGS_2026-07-27.md` first. **That document is the specification for this one.**

---

## 0. The decision in one paragraph

Rewrite the **evidence/forensics engine** in Rust as a read-only sidecar, and **port the detection
engine incrementally behind a differential-testing harness** — not big-bang. Keep all **destructive
remediation in PowerShell**. The 140 detection phases are not the valuable asset; the **six rounds of
false-positive tuning and the live-graded safety baseline** are, and a big-bang rewrite resets them to
zero with no way to notice.

---

## 1. Why rewrite at all — the honest case

Not "PowerShell is bad." Three specific, measured reasons.

### 1.1 PowerShell has a hard ceiling this project has already hit

`EVIDENCE_ENGINE_PLAN.md` §3 Tier C **declined five high-value forensic sources purely because
PS 5.1 cannot reach them**:

| Declined source | Stated reason | In Rust |
|---|---|---|
| **SRUM** (`SRUDB.dat`) — "best host-side exfil evidence there is" | ESE database, locked, no in-box managed reader | ordinary work |
| **`$MFT`** | needs raw volume handle + ~2000-line NTFS parser | `ntfs` crate |
| **Full Prefetch parse** | needs `RtlDecompressBufferEx` P/Invoke — "where pure PowerShell starts straining" | ordinary work |
| **Browser history** | "no SQLite provider exists in PS 5.1" → degraded to regex scraping | `rusqlite` |
| **USN journal** | "the one item that could realistically hang a scan" | bounded streaming |

The **next** phase of planned work (the A-series evidence engine + the operator's requested Event
Viewer / IR collection GUI) is precisely where this ceiling binds hardest.

### 1.2 True parallelism is structurally impossible in the current design

`BLUEPRINT.md` §7 records it: *"True phase parallelism is ruled out — phases share variables across a
single dot-sourced scope, so concurrent execution would race that state."* That is not a tuning
problem, it is the architecture. DEEP takes ~9.5 min single-threaded.

### 1.3 **The audit's bug classes are mostly unrepresentable in a well-typed engine**

This is the strongest argument and it emerged *from* the review, not before it. Mapping the findings
to language-level defences:

| Finding class | Example | Rust makes it |
|---|---|---|
| Silent budget exhaustion → false clean | **P1-1** (`Get-ScanFiles` returns no truncation signal; profiles 2..N unscanned, phase prints `[OK]`) | `enum Scan { Complete(Vec<F>), Truncated { got, reason } }` — **cannot be ignored**; no `[OK]` path exists for `Truncated` |
| "Couldn't check" rendered as "nothing there" | **FC-1…FC-5, P1-7, P1-10, P1-11, P6-19** (9 separate live paths) | `Verdict::Clean` constructible **only** from a `Coverage` proof token |
| Consumer phase runs without producer | **FC-1** (`-Phases 58` without 54 → "BCD CLEAN") | explicit dependency edges; a missing input is a type error, not a `$null` |
| Finding-ID collision silently discards | **P1-5** (same extension in Chrome + Edge → Edge copy dropped) | identity is a struct, not a hand-built string |
| Rule-#1 auto-destruct | **R1-1, R1-2, P1-2, P1-3, P1-4** | destructive actions live in a separate crate behind a capability type; a read-only collector *cannot* name them |
| Invisible control-flow loss | **REG-1** (trap `continue` granularity silently changed from statement to phase across ~134 phases) | `Result` + `?` — no invisible resumption |
| Case-insensitive variable shadowing clobbering caller state | documented repeatedly in `CLAUDE.md` | does not exist |
| `,$arr` / single-element unwrap / `(try{}catch{})` | an entire `CLAUDE.md` section | do not exist |

**But note carefully what Rust does *not* fix.** R1-1 (IOC auto-harvest), FC-2 (TRIAGE drops the
requested phases), FC-3 (pasted hash reaches no consumer phase) are **design** bugs — a category→phase
map built without modelling the mode gate. A rewrite in any language reproduces them verbatim. The
defence against that class is the differential harness in §4, not the compiler.

---

## 2. Why NOT a big-bang rewrite — the constraint that sets the sequencing

### 2.1 The irreplaceable asset is the tuning, not the code

15,447 lines of PowerShell is recoverable. What is not: six documented FP rounds, the
`Test-ProtectedTarget` / `Test-VendorTrusted` three-layer guard, and a healthy-box auto-destructive
baseline of **8**. Every one of those rounds exists because a live run caught something static
reasoning missed. `data/detection_signatures.json` (2,540 lines) and the severity/FixAction grade of
each finding encode that knowledge as much as the code does.

### 2.2 **The regression suite cannot currently report failure**

This is the blocking constraint. From the audit: `harness-malware-detection.ps1:212-277` only *logs*
counts — every count can be `0` and it still writes `MALWARE_DETECTION_DONE` (TEST-1). Re-runs read the
previous run's log (TEST-2) and test a stale engine (TEST-3). A failed build is undetected (TEST-4).

**A rewrite validated by that harness would look green and be broken, and it would be discovered on a
client machine.** Repairing the harness is therefore not housekeeping — it is the prerequisite that
makes a rewrite survivable at all.

### 2.3 Compiled binaries carry a real EDR cost — which shapes the split

Operator has stated they can add exclusions to their own stack. That does not settle it:

- An unsigned `.exe` has **no SmartScreen/EDR reputation** and is judged on behaviour alone;
  `powershell.exe` is Microsoft-signed and only the *script* is AMSI-scanned.
- The forensic behaviours are the worst possible profile: raw volume handles (`\\.\C:`), USN reads,
  VSS, hive parsing — indistinguishable from ransomware by behaviour.
- **This is an MSP tool: it runs on *client* endpoints.** Per-client exclusions for an unsigned binary
  don't scale, and an AV exclusion carved out for the IR tool is itself an attack surface — an
  attacker who learns `zb-evidence.exe` is excluded has a free hiding place.

**Design consequence.** The most malware-like actions this tool takes are `KillProcess`, `DeleteFile`,
`DeleteReg`, `Quarantine`. Moving those into an unsigned binary maximises exactly the surface needing
exclusions. So:

- **Rust sidecar** — read-only collection and parsing. Suspicious to EDR; never writes, kills, deletes.
- **PowerShell** — retains all destructive remediation, already FP-tuned, executed by a
  Microsoft-signed host.

Real mitigation is **code signing** (already an open item in `BLUEPRINT.md`), not exclusions.

---

## 3. Target architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ native-app/  (Tauri v2, Rust — EXISTS TODAY, builds today)          │
│   window → http://127.0.0.1:<port>                                  │
└─────────────────────────────────────────────────────────────────────┘
                              │ spawns, Job-Object-tied
┌─────────────────────────────────────────────────────────────────────┐
│ ZeroBreach-Server.ps1  (PowerShell — UNCHANGED role)                │
│   HttpListener · SSE · scan state · REMEDIATION (stays here)        │
└───────────────┬──────────────────────────────┬──────────────────────┘
                │ stdout: [FINDING] {json}     │ stdout: [FINDING] {json}
┌───────────────▼──────────────┐  ┌────────────▼──────────────────────┐
│ ZeroBreach-V23.ps1 + engine/ │  │ zb-evidence.exe   (Rust — NEW)    │
│ 140 detection phases         │  │ READ-ONLY forensic collection     │
│ ported incrementally (§4)    │  │ A-series · SRUM · $MFT · USN ·    │
│                              │  │ Prefetch · SQLite · event logs    │
└──────────────────────────────┘  └───────────────────────────────────┘
```

**The contract is the existing one.** Both children emit `[FINDING] {compact JSON}` stdout lines with
keys `id, sev, phase, tt, desc, target, fix, group` — the format the server already parses into SSE
`finding` events. **No server change is needed to accept a Rust child.** That is deliberate: it means
the sidecar can be introduced with zero risk to the working pipeline, and it is why the evidence
engine is the correct first Rust deliverable.

### 3.1 Crate layout

```
zb-rs/
├── zb-core/         finding types, Severity, Verdict, Coverage proof tokens, [FINDING] emitter
├── zb-evidence/     A-series collectors (event logs, Defender, Recycle Bin, UserAssist, Prefetch…)
├── zb-forensics/    the PS-impossible tier: $MFT, USN, SRUM, ShimCache, Amcache, SQLite
├── zb-detect/       ported detection phases (Stage 3 — empty until then)
└── zb-cli/          zb-evidence.exe — arg parsing, budget, output
```

`zb-core` is where the type-level guarantees from §1.3 live. Nothing else may construct a
`Verdict::Clean`.

### 3.2 The one non-negotiable API

```rust
// A collector can NEVER return a bare "nothing found".
pub enum Outcome<T> {
    Found(Vec<T>, Coverage),
    Clean(Coverage),                       // Coverage is unforgeable proof the check could fire
    Blind { reason: BlindReason },         // -> emits an honesty finding, never an [OK] line
}
```

`Coverage` records what was actually examined (roots walked, records read, time window, truncation).
`Clean(Coverage)` cannot be built without it. **This single type makes FC-1…FC-5, P1-1, P1-7, P1-10,
P1-11 and P6-19 — nine of the audit's findings — structurally unrepresentable.**

---

## 4. Sequencing

### Stage 0 — Fix the audit findings *(prerequisite, PowerShell)*
Per `REVIEW_FINDINGS_2026-07-27.md` §"Suggested fix order". Priorities 0–2 minimum: **P1-1** (the
`Get-ScanFiles` truncation signal), the six rule-#1 violations, AVAIL-1/AVAIL-3/P1-6.

Rationale: the current engine remains the production tool throughout the rewrite and is the
**differential reference** for Stage 3. Porting known-broken behaviour and then diffing against it
would enshrine the bugs.

### Stage 1 — Make the harness capable of failing *(prerequisite)*
TEST-1…TEST-5 plus the `>>` fix. Then extend it into the **differential harness** Stage 3 depends on:

```
run PS engine  --> findings set A  }
                                   } diff on (id, severity, fix_action, target)
run Rust engine --> findings set B }
```

Any divergence is a port bug until proven otherwise. **This is what preserves the FP tuning instead of
re-earning it** — the entire justification for not doing a big-bang rewrite.

Acceptance: deliberately break a detection and confirm the harness goes red. A harness that has never
failed has not been tested.

### Stage 2 — `zb-evidence.exe`, greenfield *(first Rust deliverable)*
The A-series, in `EVIDENCE_ENGINE_PLAN.md` §8 order: **A1** log-availability census first (it makes
every later negative result interpretable), then **A2/A3** Defender evidence, then A4–A8, then A9–A17.
Plus the Tier B/C items PowerShell had to decline.

Delivers the operator's requested **Event Viewer / IR GUI** (decided 2026-07-27: **both live view and
export package**). Greenfield ⇒ no tuning to re-earn. Proves the toolchain, the `[FINDING]` contract
and the EDR posture before anything load-bearing depends on Rust.

**Blocked on a sensitive-data policy** (`EVIDENCE_ENGINE_PLAN.md` §5.5): event logs and browser history
carry credentials and PII, and the export path writes them to disk. Decide redaction/scoping *before*
building the exporter, not after.

### Stage 3 — Port detection phases incrementally, behind the diff
Phase group by phase group, each landing green on the differential harness before the next starts.
Order by value-per-risk: start with phases that are pure functions of collected evidence; leave
anything feeding a destructive `FixAction` until last, and re-grade the auto-destructive baseline at
every step.

### Stage 4 — Retire what is fully ported
Only when the diff has been green across a full DEEP on a **multi-profile** box for a sustained period.
Remediation stays in PowerShell indefinitely (§2.3).

---

## 5. Constraints inherited from `CLAUDE.md` (non-negotiable)

1. **Rule #1** — never auto-select or auto-apply anything that damages a healthy system. In Rust:
   destructive actions live behind a capability type the collector crates cannot name.
2. **Never print a clean result for a check that could not have fired** — enforced by §3.2's `Outcome`.
3. **Prefer `Quarantine` over `DeleteFile`**; reversible by default.
4. **Signatures stay in `data/*.json`**, never compiled-in literals — the AMSI rationale is weaker for a
   binary, but a single source of truth across both engines matters more, and the PS engine still needs it.
5. **Hardening/lockdown actions are operator-only** (`Info`/`POSSIBLE` + `RunCmd`).
6. **Validate on the real target runtime**, not a simulation.
7. **A written plan's premises are claims, not facts — measure them before implementing.** This document
   included. Every performance/feasibility claim above should be re-measured before it is relied on.

---

## 6. Open decisions

| # | Decision | Owner | Blocks |
|---|---|---|---|
| 1 | R1-1 fix shape: per-IOC confirmation UI vs. drop domains/IPs from auto-merge entirely | operator | Stage 0 |
| 2 | Sensitive-data policy for evidence export (redaction? scoping? retention?) | operator | Stage 2 exporter |
| 3 | Code-signing certificate — the real answer to §2.3 | operator | Stage 2 field use |
| 4 | Multi-profile grading box (or synthetic profile set) — the current baseline of 8 is 2-profile and cannot see P1-2/P1-3/P1-4/P6-15 | operator | verifying rule-#1 fixes |
| 5 | Merge `session12/review-remediation-ws6` → `main` (decided: after review fixes) | done | Stage 0 completion |

---

## 7. What this plan explicitly does NOT do

- **No big-bang rewrite.** §2.1/§2.2.
- **No rewrite of remediation.** §2.3.
- **No removal of the PowerShell engine** until the diff is durably green (Stage 4).
- **No new detections during the port.** A port that also changes behaviour cannot be diffed.
- **No claim that Rust fixes the design bugs.** R1-1, FC-2 and FC-3 would port verbatim; §1.3 closing note.
