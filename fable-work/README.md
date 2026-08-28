# fable-work — parallel work package for Scythe V23

Open **this folder** as its own project. `CLAUDE.md` here is the rule book for the session;
you do not need the parent tree's documentation and you should not load it.

## The one-paragraph context

Scythe V23 is a Windows endpoint audit-and-reporting tool used by a managed-service
provider. A PowerShell HTTP server sits between a browser front end and a PowerShell scan engine
that walks the machine and writes a run record. This package is the work that surrounds that
engine — what the operator sees, what gets handed to the client, how long a run takes, how it
ships, and how it is tested. **None of these tasks read or write the scan modules.**

## Why the split exists

The main session is rebuilding the engine's newest band. That work and this work touch disjoint
file sets on purpose, so both can proceed at once and merge without conflict.

**Every deliverable here is a new file.** Read `tasks/00_INTEGRATION.md` before starting — it
lists the files that are never yours, what to do when a task looks like it needs one of them,
and what you hand back.

## Task list

Do them in order. G1 is where the value is concentrated; if you finish only two, finish G1 and
G2.

| # | Task | Size | Deliverable |
|---|---|---|---|
| [G1](tasks/G1_report_renderer.md) | Standalone report renderer | L | `tools/New-ScanReport.ps1` |
| [G2](tasks/G2_compare_runs.md) | What changed between two runs | M | `tools/Compare-ScanRuns.ps1` |
| [G3](tasks/G3_timing_report.md) | Where the wall-clock goes | M | `tools/Get-PhaseTimingReport.ps1` |
| [G4](tasks/G4_offline_report_viewer.md) | Offline report viewer page | M | `gui/viewer.html` + assets |
| [G5](tasks/G5_server_parity_tests.md) | Parity tests for the mirrored tables | M | two test files |
| [G6](tasks/G6_coverage_matrix.md) | Regenerate the coverage matrix | M | `tools/New-CoverageMatrix.ps1` |
| [G7](tasks/G7_test_harness.md) | Shared assertions + machine-readable results | S–M | `tools/tests/lib/ScytheAssert.ps1` |
| [G8](tasks/G8_standalone_packaging.md) | Standalone packaging study | L | `PACKAGING_STUDY.md` + prototype |

## Reference

- `reference/REPORT_DATA.md` — the shape of every file the tasks read: the run record, the
  finding schema, the MITRE map, the console log. **Read this before G1, G2 or G3.**
- `reference/LOADER_HELPERS.txt` — helper functions available in the engine's scope. Several
  wrap cmdlets that throw terminating errors which `-EA SilentlyContinue` does not suppress; if
  you call into engine territory at all, use the wrapper.

## Ignore `_deferred/`

`tasks/_deferred/` and `reference/_deferred/` hold the other work package. They are large,
unrelated to everything here, and reading them wastes the session's context. Each has a README
saying the same thing.

## Definition of done, per task

1. Everything parses clean under both parsers; BOM intact on every `.ps1`.
2. Tests ship with the change and **each assertion has been shown to fail when the code it
   guards is reverted.**
3. A `HANDOFF_FABLE.md` entry: what you built, what you could not verify from Linux, what needs
   a Windows box, and anything you wanted to change in a file you were not allowed to touch.

## Ask, don't assume

Each brief ends with the questions already known to be open. There will be more. A question
costs a minute; a wrong assumption about what belongs in a client-facing report costs the task.
