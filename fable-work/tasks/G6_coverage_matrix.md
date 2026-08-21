# G6 — regenerate the coverage matrix from the source

**Priority 6. Size: M. New tool, new output file.**

## The problem

`data/coverage_matrix.json` is a phase-by-phase map of what the engine checks. It was generated
once, by hand-assisted analysis, against a version of the engine that has since been split into
modules and grown two new bands. It is now stale, and a stale coverage map is worse than none:
it is the document someone consults to decide what is already handled.

## Deliverables

```
tools/New-CoverageMatrix.ps1
data/coverage_matrix.generated.json      your output — a NEW filename, not the existing file
tools/tests/Test-CoverageMatrix.ps1
```

**Write to `coverage_matrix.generated.json`.** Do not overwrite `data/coverage_matrix.json`;
the main session will diff and promote it. Handing back a replacement for a file someone else
may have edited is how work gets silently lost.

## Method

Walk `engine/*.ps1` with the PowerShell AST. For each phase header call, capture:

- phase number, keeping the decimal on fractional phases
- title and category from the header arguments
- which module it lives in
- which mode gate it sits inside — the plan flags are named on the phase-plan object, and a
  phase's gate is the nearest enclosing `if` on one of them
- the distinct severities it can emit, from its finding calls
- the distinct fix actions it can emit
- which signature-set keys it reads, from the signature-lookup calls
- whether it is one of the phases skipped in the fastest mode

Emit a stable schema, sorted by phase number numerically — **not lexically**, or `10` lands
between `1` and `2` and the file becomes hard to diff.

Then produce a companion summary: phases per module, per mode, per fix action; every signature
key read but not present in the signature file; and every key present but read by nothing. Both
lists are actionable — the first is a bug, the second is dead weight.

## Constraints

- **Read-only on `engine/` and `ZeroBreach-V23.ps1`.** Parse them, never write them.
- Must run on Linux under `pwsh` 7 while parsing files written for PowerShell 5.1. The AST
  parser handles this; the runtime would not.
- Deterministic output: same input, byte-identical file. No timestamps inside the JSON body
  except one `generated_from` field carrying the git commit, and make that overridable so the
  tests can pin it.

## Tests

1. Phase count matches the highest phase number reachable in the mode with the highest ceiling,
   allowing for the fractional extras — assert the exact set, not the count alone.
2. Fractional phases appear with their decimals and sort numerically.
3. Every phase has a non-empty mode gate; a phase with no detectable gate is a finding the tool
   must report rather than silently defaulting.
4. Running twice produces byte-identical output.
5. A phase that emits a destructive fix action is captured as such — build a small fixture
   module for this rather than depending on the real engine's current contents, so the test does
   not break every time a phase is tuned.
6. The orphaned-key lists are correct against a fixture pair.

Prove each fails on revert.
