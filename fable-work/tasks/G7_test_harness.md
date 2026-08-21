# G7 — test harness ergonomics: shared assertions and a machine-readable result

**Priority 7. Size: S–M. New files only.**

## The problem

The regression suite is now around 611 assertions across a dozen files, and each test file
carries its own copy of the assertion helpers. They have already drifted: some print a red line
and continue, some throw, and the exit code is assembled by hand. There is also no machine-
readable output, so nothing can gate on it automatically.

## Deliverables

```
tools/tests/lib/ZbAssert.ps1              shared assertion helpers, dot-sourced
tools/tests/New-TestReport.ps1            JUnit XML + a one-page HTML summary
tools/tests/Test-ZbAssert.ps1             tests for the assertion helpers themselves
```

**Do not edit the existing test files** to use the new library — the main session has several of
them open. Ship the library, ship its tests, and write the migration as a note in
`HANDOFF_FABLE.md` listing which file gets which mechanical change. Migration lands later, in
one commit, when nobody else is holding those files.

## `ZbAssert.ps1`

Provide at minimum: true, false, equality, collection-contains, string-matches, throws, and a
"section" grouping helper. Every helper records a structured result — name, section, outcome,
expected, actual, and the source location — into a collection the runner reads. Printing is a
rendering step over that collection, never the primary output.

Rules the existing suite learned the hard way:

- **Never name a helper with a single letter.** Built-in aliases outrank functions in command
  resolution, so `H` silently becomes `Get-History` and the assertion never runs. This has
  happened in this repo.
- **An assertion whose input is `$null` must fail, loudly, as a distinct outcome.** In
  PowerShell `-match ''` is true, so a table that failed to load makes a comparison pass for
  entirely the wrong reason. Add an explicit "input was empty" outcome and make the runner treat
  it as a failure, not a skip.
- Failures must carry the actual value. "Assertion failed" with no value costs a debugging
  round-trip every time.

## `New-TestReport.ps1`

Consume the structured results and emit JUnit XML plus a small self-contained HTML page. Non-
zero exit on any failure or empty-input outcome. No remote assets in the HTML.

## Tests

1. Each helper passes on a passing case and fails on a failing case.
2. A `$null` or empty input produces the empty-input outcome, not a pass.
3. A helper name of one character is rejected at load — assert the library itself defines no
   such name.
4. The JUnit XML validates against the schema and the counts match the result collection.
5. Exit code is non-zero when any result is a failure or an empty-input outcome, zero otherwise.

Prove each fails on revert.
