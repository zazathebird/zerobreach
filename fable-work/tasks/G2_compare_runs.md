# G2 — `tools/Compare-ScanRuns.ps1`: what changed between two runs

**Priority 2. Size: M. New files only.**

## The problem

The engine accepts `-Baseline <path>` and records a `BaselineDelta` in the run record, but that
delta is one-directional: it lists what is new. Nobody can currently answer "did last week's
cleanup actually stick?", which is the question an MSP gets asked on the follow-up visit.

## Deliverables

```
tools/Compare-ScanRuns.ps1
tools/tests/Test-CompareScanRuns.ps1
tools/tests/fixtures/run_before.json
tools/tests/fixtures/run_after.json
```

## Interface

```powershell
tools\Compare-ScanRuns.ps1 -Reference <path> -Current <path> [-Format Object|Text|Json|Html]
                           [-IncludeInfo] [-OutFile <path>]
```

Default `-Format Object` returns a structured result; the other formats render it. Same rule as
G1 — compute once into an object, render from the object.

## The comparison

Join on `ID`. Four buckets:

- **Resolved** — in reference, not in current. The good news, and it should be first.
- **New** — in current, not in reference.
- **Persistent** — in both, same severity.
- **Changed** — in both, severity moved. Report the direction.

`INFO` findings are excluded unless `-IncludeInfo`; they are the bulk of the volume and they
drown the signal. `GROUPCAP_*` rows are always excluded — they are flood-guard metadata, not
findings.

Also report, at the run level: severity totals for both runs side by side, risk score delta,
mode and time window for each, and **an explicit warning when the two runs used different modes
or different time windows.** A DEEP run compared against a QUICK run will show dozens of
"resolved" findings that were simply never looked for, and someone will believe it. That warning
is the most important line in the output.

Accept more than two runs for a trend: `-Reference a.json -Current b.json,c.json,d.json`
produces a table of severity counts per run in timestamp order. Keep it to counts — a full
four-way join is not worth the complexity.

## Tests

1. Known before/after fixtures produce exactly the expected four buckets.
2. A severity change is reported as changed, in the right direction, and appears in no other
   bucket.
3. `INFO` is excluded by default and included with `-IncludeInfo`.
4. `GROUPCAP_*` never appears in any bucket.
5. Mismatched modes emit the warning; matched modes do not.
6. An empty reference run (a clean machine) means every current finding is new, and the tool
   says that in one sentence rather than listing 600 rows as "regressions".
7. Two runs with identical content produce zero new, zero resolved.

Prove each fails on revert.

## Ask before you build

- Should a finding whose `ID` changed but whose `Target` is identical count as persistent? The
  IDs are mostly derived from the target, but not universally, and getting this wrong in either
  direction produces a misleading report.
