# HANDOFF_FABLE.md — merge instruction sheet

One entry per task, newest at the bottom. Every path is relative to the project root.

---

## G1 — standalone report renderer

### What was built

`tools/New-ScanReport.ps1` reads a finished run record and writes one self-contained HTML
report: header, generated executive summary, a top-10 "what to do first" group list, a
tactic-by-severity rollup with an explicit Unmapped row, the full findings table (grouped,
collapsed by default, severity/group filters, group ordering, CSV download), run health, and —
with `-Compare` — a new/resolved/persisting diff joined on `ID`. Every number is computed into
a summary object first and rendered from it; `-PassThru` emits that object for the tests.

### New files

```
tools/New-ScanReport.ps1
tools/tests/Test-ScanReport.ps1
tools/tests/fixtures/run_small.json
tools/tests/fixtures/run_large.json
```

`run_large.json` (1,200 findings) is generated deterministically by `New-ScytheLargeRunFixture`
inside the test file, which regenerates it if it is ever deleted. The technique-map fixture and
the comparison baseline are derived into a temp directory at test run time, so the shipped file
list stays exactly the four above.

### Product decisions taken (confirmed with the requester 2026-08-20)

- INFO findings are shown but collapsed, and excluded from "What to do first".
- Neutral, unbranded look; `-Title` carries the client name.
- CSV is delivered both ways: a download button in the report **and** an optional `-Csv`
  sidecar switch; both use the same text built by the one guard helper (`Protect-ScytheCsvCell`).
- A missing/unreadable `data/mitre_mapping.json` warns and renders everything as Unmapped
  with a visible notice, rather than failing the report.

### Verified from Linux

- Both `.ps1` parse clean under pwsh 7.4.6; BOM `ef bb bf` intact on both.
- All 48 assertions pass; 1,200-finding render takes ~3.4 s and produces a 0.73 MB file
  (limits: 10 s / 5 MB).
- **Fail-on-revert:** a 19-mutation matrix (each reverting one guard: GROUPCAP exclusion,
  unknown-severity bucket, Unmapped row, technique resolution, fractional-key-first, floor
  fallback, `</` JSON escape, HTML encoding, CSV formula guard, baseline GROUPCAP exclusion,
  phase shortfall, Clean flag, plain clean sentence, input validation, tally cross-check,
  missing-map tolerance, output size, render time, summary prose) was run; every mutation made
  the suite fail. 18 were caught by the named assertion; `missing-map-fatal` (reverting
  warn-and-continue to a throw) kills the suite with a non-zero exit before that assertion
  prints — detected, but not by name.
- Inline JS syntax-checked with Node 22; the JSON data island round-trips a description
  containing `</script>` intact. Rendered report exercised in Chromium: group expand/collapse,
  severity filters, group ordering, and dark theme all work; zero console errors.

### Needs a Windows box

1. Run the tests under Windows PowerShell 5.1: `powershell -File tools\tests\Test-ScanReport.ps1`
   (exit code 0 = pass). Nothing in the tool touches registry/COM/etc., but the PS 5.1 parser
   behaviours in BLUEPRINT §8 can only be proven on the real runtime.
2. Open a generated report in Edge **from a `file://` path** and click "Download CSV". The page
   carries a strict CSP meta (`default-src 'none'`; inline style/script allowed); the button
   uses a Blob URL, which desktop browsers treat as a download rather than a CSP-governed
   fetch, but that is the one interaction I could not exercise from here exactly as shipped.
3. Print-to-PDF one report and check table headers repeat and nothing clips at the right margin.

### First real run (owner, after merge)

```powershell
tools\New-ScanReport.ps1 -Path reports\audit_<latest>.json -Csv -PassThru
```

Then diff the `-PassThru` severity counts against the engine's own HTML report for the same run.

### Findings / wanted-but-not-allowed changes

- **A fifth copy of the mode→ceiling table now exists** in `New-ScanReport.ps1` (needed for the
  "phase timings short of the mode's ceiling" note; the run record only carries the mode
  string). No existing file was touched, but when I build G5 I will extend the parity test to
  read this file's table too, so all five copies are proven to agree.
- BLUEPRINT §4 says keyword_map matches "the finding's text". I match against `Description`
  only (not `Target`). If the product matches on more than that, say so and I will adjust —
  it is one function (`Resolve-ScytheTechniques`).
- Rollup attribution: a finding that resolves to several techniques/tactics is counted **once**,
  under the first technique's first tactic — required so rollup totals reconcile with the
  summary counts (test 2). If the product wants multi-tactic counting instead, the reconcile
  rule needs a decision first.

---

## G2 — what changed between two runs

### What was built

`tools/Compare-ScanRuns.ps1` joins two run records strictly on finding `ID` into the four
buckets (Resolved first — it is the answer to "did the cleanup stick?"), reports run-level
severity totals side by side, the risk delta, and an explicit warning when the runs used
different modes or time windows — rendered before anything else, in every format. Several
`-Current` paths produce a counts-only severity trend table in timestamp order. Formats:
Object (default), Text, Json, Html; `-OutFile` writes the rendering.

Per the 2026-08-20 decision: strict ID join, plus a **"possible ID drift" advisory** listing
resolved/new pairs that share an identical Target and ThreatType — they stay in their buckets,
the advisory exists so a renamed ID is reviewed rather than read as a fix plus a regression.

### New files

```
tools/Compare-ScanRuns.ps1
tools/tests/Test-CompareScanRuns.ps1
tools/tests/fixtures/run_before.json
tools/tests/fixtures/run_after.json
```

The QUICK-mode variant, empty reference, and third trend run are derived into a temp directory
at test time.

### Verified from Linux

- Parses clean under pwsh 7.4.6, BOM intact; all 53 assertions pass.
- **Fail-on-revert:** 15 mutations (GROUPCAP joined, INFO filter, direction inversion,
  changed-merged-into-persistent, both warning polarities, empty-reference flag and sentence,
  drift advisory, risk-delta sign, trend ordering by name, trend mode warning, resolved/new
  bucket logic, HTML encoding) — every one makes the suite fail on the named assertion(s).
  The HTML-encoding gap was found by this very matrix (fixtures initially carried no hostile
  markup) and closed by adding hostile text to `run_after.json` plus two assertions.

### Needs a Windows box

- `powershell -File tools\tests\Test-CompareScanRuns.ps1` under 5.1 (exit 0 = pass). The tool
  is pure data processing — no registry/COM — so 5.1 parser behaviour is the only open risk.

### First real run (owner, after merge)

```powershell
tools\Compare-ScanRuns.ps1 -Reference reports\KrakenBaseline_<older>.json `
                           -Current reports\audit_<newer>.json -Format Text
```

### Findings

- The mode-mismatch warning deliberately avoids naming phase ceilings (30/80/133/162) so this
  file does not become a sixth copy of the mirrored table; it says "different modes check
  different numbers of phases" instead.
- Severity totals at run level always include INFO (and OTHER for unknown labels), even when
  the buckets exclude INFO — so the side-by-side table always reconciles with G1's report.

---

## G3 — where the wall-clock goes

### What was built

`tools/Get-PhaseTimingReport.ps1` reads phase timings from a run record (preferred) or a
console log (`TIMING:` form only; the decorated console twin is ignored), and reports: total
and per-phase times with shares, the slowest `-Top`, how many phases cover 80% of the time, a
ceiling-shortfall warning ("a correctness signal wearing a performance costume"), a truncated-
log detection (phase started, never timed), and a budget gate against the new
`data/phase_budgets.json` — **the script exits 1 when the mode's total budget is exceeded**, so
it can gate a release. `-Compare` produces a per-phase delta table sorted by absolute change.

**Duplicate `TIMING:` lines (decision 2026-08-20): the tool keeps the LAST value per phase and
reports how many lines it discarded.** This follows the G3 brief over BLUEPRINT §5's
"sum, and record the repeat count" — the blueprint sentence should probably be updated to say
the sum rule does not apply to this tool, so the two documents stop disagreeing.

### New files

```
tools/Get-PhaseTimingReport.ps1
data/phase_budgets.json                (seed: QUICK 120, all other modes 0 = unbudgeted)
tools/tests/Test-PhaseTimingReport.ps1
tools/tests/fixtures/console_sample.log
```

The tests also reuse `run_small.json` (budget gate, shortfall, source preference) and
`run_before.json` (comparison) from G1/G2.

### Verified from Linux

- Parses clean under pwsh 7.4.6, BOM intact; all 40 assertions pass.
- **Fail-on-revert:** 15 named mutations, all detected (take-first-instead-of-last, duplicate
  counter, fractional truncation, decorated-line parsing, incomplete flag, budget gate, exit
  code, share denominator, P80 short-circuit, source preference, comparison sort, removed
  status, shortfall, HTML encoding, per-phase overrun). One informational probe: the *run
  record* reader's duplicate counter is not separately asserted (run records essentially never
  carry duplicate phases; the log path — where duplicates actually occur — is fully guarded).

### Needs a Windows box / a real run

- `powershell -File tools\tests\Test-PhaseTimingReport.ps1` under 5.1.
- **The tool needs one real run to validate against** (the brief anticipates this). What I
  would want measured: one QUICK run on a representative client machine, then
  `tools\Get-PhaseTimingReport.ps1 -Path reports\audit_<stamp>.json -Format Text` — checking
  (a) the total against the 120 s budget and the exit code, (b) that the phase count matches
  30, and (c) `-LogPath reports\KrakenConsole_<stamp>.log` against the same scan to confirm
  the log parser agrees with the record within a second or two. Then re-run after the two
  caching layers are toggled and use `-Compare` to attribute the difference to phases.
- My "phase started but never finished" detection treats any non-TIMING log line naming
  `PHASE <n>` as a start marker. If real console logs echo phase labels in finding lines, this
  will over-report incomplete phases — one real log will show it immediately; the fix is
  anchoring on the real header decoration, which I could not see from here.

### Findings

- This file carries another copy of the mode→ceiling table (the brief requires the ceiling in
  the output and the record only carries the mode string). Both G1's and G3's copies are on
  the G5 parity list.
- `data/phase_budgets.json` is a new top-level data file, per the brief. Keys are snake_case
  (`mode_totals`, `phase_budgets`) matching the other data-file conventions; per-phase keys
  are phase-number strings with fractional numbers kept ("74.5").

---

## G4 — offline report viewer

### What was built

`gui/viewer.html` + `gui/static/js/viewer.js` + `gui/static/css/viewer.css`: a standalone page
opened from the filesystem. File input and drop target accept one or more run records, parsed
entirely in the page. Views: per-run summary cards; a findings table with severity chips,
group filter, and text filter; a group-collapsed mode (default — rows render only when a group
is opened, so 1,200 findings never build 1,200 DOM rows) and a paginated flat mode (100/page);
a side-by-side comparison (resolved/new/persisting, joined on ID, flood-cap markers excluded)
when exactly two files are loaded. CSV export of the current filtered view routes every cell
through the same formula-injection guard as the rest of the product. Filter state deep-links
via the URL fragment; the fragment is parsed defensively on the way back in (whitelisted keys,
whitelisted enum values, length caps, try/catch).

### New files

```
gui/viewer.html
gui/static/js/viewer.js
gui/static/css/viewer.css
tools/tests/Test-ViewerAssets.ps1
```

### Decisions taken (confirmed 2026-08-20)

- **Release zip: yes.** `tools/Build-Release.ps1` belongs to the main session, so the change is
  a note, not a patch: *add the three files above to the staged file list* (I could not open
  the file to give line numbers — the list the brief mentions is the place).
- **Theme tokens: self-contained.** BLUEPRINT does not name `main.css`'s tokens and the parent
  tree is off-limits, so `viewer.css` defines its own `--scythe-*` tokens (complete light + dark
  palettes) and `viewer.html` links `main.css` first so the product theme wins wherever it
  defines the same names. Reconciling is a token-mapping pass at the top of `viewer.css`, one
  look at `main.css` required.

### Verified from Linux

- All 41 source-level assertions pass (pwsh 7.4.6, BOM on the test file); `node --check`
  passes on viewer.js.
- Exercised in Chromium over localhost: loaded `run_before.json` + `run_after.json`
  (comparison correct: 4 resolved / 3 new / 3 both, INFO included), hostile
  `<img onerror>` and `</script>` strings render as inert text, severity chips / group
  expand / flat-view pagination / tab switching all work, deep link
  `#view=flat&sev=CRITICAL,HIGH&q=unsigned` restores the exact filter state, and the
  1,200-finding fixture loads instantly with correct counts. Zero console errors throughout.
- **Fail-on-revert:** 9 mutations detected by name (escHtml dropping `'`, CSV guard dropping
  `@`, an unsafe innerHTML write, a remote @font-face, a literal remote URL, a script src
  escaping `gui/static/`, link order flipped, a `fetch()` call, reduced-motion removed). The
  link-order assertion was itself fixed after the matrix caught it matching a comment. The
  innerHTML scanner is proven inside the shipped test against an embedded deliberately-unsafe
  sample (the "deliberately failing case" the brief asks for).

### Known limits (deliberate, documented)

- The no-remote scan is source-level: a URL built by string concatenation would dodge it (the
  matrix demonstrates this). The `fetch`/`XMLHttpRequest`/`WebSocket`/`sendBeacon`/
  `EventSource` scan closes the practical exfiltration routes; a runtime CSP would be
  stronger, but a CSP meta breaks linked local assets on `file://` (opaque origin), which is
  the page's whole point — noted here rather than silently traded away.
- The innerHTML rule is a statement-level heuristic (escHtml must appear before the statement's
  first semicolon). It caught one real ordering issue in my own code during development.
- Viewer comparison includes INFO findings (counts say so); the G2 CLI defaults to excluding
  them. Different surfaces, both labelled — flag if you want them aligned.

### Needs a Windows box

- Double-click `gui\viewer.html` from Explorer (a real `file://` open, Edge and Chrome), drop
  two records on it, export CSV, and print one page. All exercised here over localhost only.
- `powershell -File tools\tests\Test-ViewerAssets.ps1` under 5.1.

---

## G5 — parity tests for the mirrored tables (documented scope; five shapes pending)

### What was built

`tools/tests/Test-ServerParity.ps1` extracts the mode→ceiling table from **five** declarations
at runtime and compares them: `$MODE_PHASES` in `Scythe-Server.ps1` (PowerShell AST),
`MODE_PHASES` in `_python/server.py` (targeted regex), the engine's `$PhasePlan` switch `Max=`
values (AST, default branch skipped), and the two copies the G1/G3 tools introduced
(`$script:ScytheModeCeiling` in `New-ScanReport.ps1` and `Get-PhaseTimingReport.ps1` — always read
from the real files). Nothing is restated in the test body; every table is asserted non-empty
before it may agree (the vacuous-pass trap). Without `-Root` the three root declarations run
against generated fixtures reproducing the BLUEPRINT §6 syntax; `-Root <path>` aims at the
real tree, read-only.

`tools/tests/Test-EventContract.ps1` encodes the §6 event contract as the specification,
ships the required-vs-available comparison machinery with the same non-empty guards, and
checks the contract-level rules that are checkable today (seven events; `scan_complete` and
`scan_failed` distinct; snake_case payloads left snake_case).

### Decision (2026-08-20): documented scope now, gaps stubbed visibly

BLUEPRINT §6 documents three ceiling declarations and the event field lists, but **not** these
five shapes, and the parent tree is off-limits, so they are pending config blocks
(`$ScythePendingShapes` / `$ScythePendingExtractors`) that print `todo` lines on every run — and
**enabling one without implementing it fails the run** rather than passing vacuously:

1. the front-end ceiling default (file + declaration syntax),
2. the mode whitelist in each server,
3. the severity tag tables in both servers (including the padded `[OK ]` form),
4. the category bucket tables in both servers,
5. server payload construction / front-end event reads / front-end route list + server
   dispatch / the authenticated `/api/` wrapper name.

One paste each (a few lines, added to BLUEPRINT §6 ideally) turns the remaining brief
assertions (2–8) into real extractions. I deliberately did not guess any of these syntaxes —
a guessed extractor that happens to match nothing would "agree" forever.

### Fail-on-revert

Built into every run, per the brief's instruction that fixture-editing is the stronger proof:
scratch copies with a one-unit drift, a missing mode, and an absent table must each be caught
(and are). Additionally proven against a real file: temporarily drifting
`New-ScanReport.ps1`'s HUNT ceiling to 161 makes the suite fail and the report names the mode
and every declaration's value. The event-contract machinery likewise self-proves: a conforming
set passes, a removed `threat_counts` is caught by name, unloaded/empty sets fail.

### The command the owner runs against the real tree

```powershell
powershell -File tools\tests\Test-ServerParity.ps1 -Root C:\path\to\scythe
powershell -File tools\tests\Test-EventContract.ps1        # extractors pending; runs its self-proof
```

Exit 0 = parity holds. Any divergence prints `mismatch: mode <M> disagrees: <file>=<n>, ...`
— put that line in this file with the exact source locations rather than editing the tables,
which are files this work package must not touch.

---

## G6 — regenerate the coverage matrix

### What was built

`tools/New-CoverageMatrix.ps1` walks every `.ps1` under `-Root` with the AST (read-only,
never regex, never executed) and writes the phase-by-phase matrix: number (fractional kept),
title, category, module, mode gate (nearest enclosing `if` on a `$PhasePlan` flag — non-plan
`if`s are skipped, an `-or` of flags records all of them as `Deep+Hunt`), distinct severities
(rank order, expressions recorded as `dynamic`, never dropped), distinct fix actions,
signature keys read, finding-call count, and a skipped-in-QUICK flag. The summary counts
phases per module / mode / gate / fix action and lists: ungated phases (recorded as `null`,
reported, never defaulted), duplicate phase numbers, headers whose phase number is an
expression, preflight finding calls above any header, and — with `-SignaturePath` — keys read
but missing from the file (a bug) and keys present but read by nothing (dead weight); without
the file those two lists are `null`, so "not checked" cannot be misread as "clean".

JSON is serialised by the script itself (not `ConvertTo-Json`), ordinal-sorted throughout, so
the same input is byte-identical regardless of PowerShell version; the only provenance field
is `generated_from` (`-GeneratedFrom` pins it, else the root's git commit, else `unknown`).
Phases sort numerically — the brief's `10`-between-`1`-and-`2` failure mode has a named
assertion. A root yielding zero phase headers is exit 2 and **no file** — an empty matrix
that "diffs clean" would hide a wrong `-Root`. The tool also refuses to write the promoted
filename `coverage_matrix.json`; output goes to `coverage_matrix.generated.json` per the
brief, and the main session diffs and promotes.

### New files

```
tools/New-CoverageMatrix.ps1
data/coverage_matrix.generated.json      (fixture-generated schema demo — see below)
tools/tests/Test-CoverageMatrix.ps1
```

Fixture engine modules (five, covering integer + fractional numbers, every mode gate, an
ungated phase, several severities on one phase, destructive fix actions, signature reads,
backtick continuations, calls nested in `if`/`foreach`, preflight output, a duplicate phase
number, a dynamic signature key and a dynamic phase header) are authored by the test into a
temp directory at run time, so the shipped file list stays exactly the three above.

**The shipped `coverage_matrix.generated.json` is the tool's output for those fixtures**
(`generated_from: "fixture-demo"`), shipped as a schema demonstration; the test asserts it is
byte-identical to a fresh fixture run, so it can never drift from the tool. The real matrix
is produced by the owner's first run (command below) and will overwrite it.

### Undocumented shapes — same policy as G5, resolved by parameters instead of stubs

BLUEPRINT §7 documents `Add-Finding` and §6 documents `$PhasePlan`; those are the defaults.
It does **not** document the phase-header call, the signature-lookup call, their parameter
names, or the signature file's name. Rather than guess, every one is a tool parameter
(`-PhaseHeaderCommand`, `-SignatureLookupCommand`, `-PhaseParameter`, `-TitleParameter`,
`-CategoryParameter`, `-SignatureKeyParameter`, `-PlanVariable`, `-SignaturePath`) with the
fixture-convention defaults (`Write-PhaseHeader -Phase -Title -Category`,
`Get-SignatureSet -Key`). A wrong name cannot pass silently: zero headers is a hard exit 2.
**Owner: confirm the real names (ideally paste the real header call into BLUEPRINT §7) —
they are command-line arguments, no code change needed.**

### Verified from Linux

- Both `.ps1` parse clean under pwsh 7.4.6, BOM intact; the matrix JSON is UTF-8 no BOM, LF.
- All 52 assertions pass; reruns are byte-identical (SHA256-compared).
- **Fail-on-revert: a 28-mutation matrix** (lexical sort, floored fractionals, defaulted
  gate, stop-at-first-`if` gate walk, nondeterministic output, dropped fix actions, swapped
  orphan lists, dropped dynamic severity, alphabetical severities, preflight attributed,
  empty-matrix-allowed, QUICK-ceiling drift, duplicate report dropped, dynamic key recorded
  as literal, silent unparsed header, promoted-name refusal removed, first-flag-only or-gate,
  empty-instead-of-null orphans, signature attribution dropped, finding counter dropped,
  per-module zeroed, module list emptied, nonzero exit, module tiebreak dropped, flag name
  lost, severity capture dropped, QUICK-skip polarity, shipped-file drift) — 27 of 28 fail on
  the named assertion; one probe variant (`if` clause returning its flags unconditionally,
  yielding an empty-string gate) kills the suite with a JSON parse error before the named
  assertion prints — detected, but not by name (same class as G1's `missing-map-fatal`).
- `tools/tests/Test-ServerParity.ps1` (my own G5 deliverable, updated — not a violation of
  the new-files rule, which protects the parent project's files) now reads this tool's
  `$script:ScytheModeCeiling` as declaration #6; drifting HUNT to 161 in the real file makes
  parity fail naming the mode and every declaration's value; restored, all green.

### Needs a Windows box

- `powershell -File tools\tests\Test-CoverageMatrix.ps1` under 5.1 (exit 0 = pass). Pure
  parsing and data processing — no registry/COM — so §8 parser behaviour is the only open
  risk. Two 5.1 behaviours are deliberately worked around and worth eyeballing there: the
  `,$array` return convention at every sort-helper call site, and single-`string[]`
  `Array.Sort` (the keys/items overload sorts a converted copy of the items under pwsh —
  found while building this).

### First real run (owner, after merge)

```powershell
tools\New-CoverageMatrix.ps1 -Root engine -SignaturePath data\<signature file> `
    -PhaseHeaderCommand <real header verb> -SignatureLookupCommand <real lookup verb>
```

Add the entry script (and any other file holding phases) to `-Root` as a second entry, e.g.
`-Root engine, Scythe-V23.ps1`. Then diff `data\coverage_matrix.generated.json` against
`data\coverage_matrix.json` and promote. Sanity checks for the first run: `phase_count`
against the HUNT ceiling's reachable set, `ungated_phases` (should be empty — anything listed
is an engine finding), `headers_unparsed`, and both orphan-key lists.

### Findings

- **Sixth copy of the mode→ceiling table** (`$script:ScytheModeCeiling`) — required because
  "skipped in QUICK" and "phases per mode" are ceiling properties and the source only carries
  flags. Registered in the G5 parity test, proven above.
- The matrix records mode **gates as flag names** (`Deep`, `Quick+Full`), not mode names —
  the flag→mode mapping lives in the elided `...` of the `$PhasePlan` switch (BLUEPRINT §6)
  and is not documented. "Phases per mode" is therefore computed from ceilings, not gates. If
  the owner pastes the full `$PhasePlan` branch shape into the blueprint, the tool could
  translate flags to modes — happy to add it.
- Duplicate phase numbers are listed (both declarations kept, ordered by module) rather than
  merged — a duplicate is an engine finding the matrix must surface, not smooth over.

---

## G7 — shared assertions and a machine-readable result

### What was built

`tools/tests/lib/ScytheAssert.ps1` — dot-sourced assertion library. Helpers: `Assert-ScytheTrue`,
`Assert-ScytheFalse`, `Assert-ScytheEqual`, `Assert-ScytheContains`, `Assert-ScytheMatch`, `Assert-ScytheThrows`,
`Set-ScytheSection`, plus `Get-ScytheResults` (snapshot), `Reset-ScytheResults`, `Export-ScytheResults`
(JSON, the machine-readable hand-off) and `Complete-ScytheTestRun` (summary + exit code). Every
helper records name / section / outcome / expected / actual / file / line into a collection;
the console line is rendered from the record. Three outcomes: `pass`, `fail`, and **`empty`**
— input never loaded (`$null`, or empty string where a value was required). `empty` is a
failure with its own name, never a skip: `Assert-ScytheEqual '' ''` is `empty` (the `'' -eq ''`
failed-to-load trap), `Assert-ScytheMatch` with an empty pattern is `empty` (`-match ''` is
true). Failures always carry the actual value (truncated at 500 chars).

`tools/tests/New-TestReport.ps1` — consumes one or more exported result files, emits JUnit
XML (one `<testsuite>` per input file; `fail` → `<failure type="AssertionFailure">`, `empty`
→ `<error type="EmptyInput">` — distinct, both gate) and a self-contained HTML page (totals,
per-section counts, every non-pass with expected/actual/location; no scripts, no remote
assets, everything escaped). Exit 0 all pass; 1 any fail or empty; **2 when the input holds
zero records** — a suite that recorded nothing must never gate as green.

Typical run, once a suite is migrated:

```powershell
pwsh tools/tests/Test-Something.ps1          # ends with Complete-ScytheTestRun -ExportPath r.json
pwsh tools/tests/New-TestReport.ps1 -Path r.json      # junit + html + gate
```

### New files

```
tools/tests/lib/ScytheAssert.ps1
tools/tests/New-TestReport.ps1
tools/tests/Test-ScytheAssert.ps1
```

### Verified from Linux

- All three parse clean under pwsh 7.4.6, BOM intact; all 70 assertions pass.
- The JUnit XML is validated against an XSD embedded in the test (the schema doubles as the
  written contract for what the tool emits), with a negative control proving the validator
  can reject; counts are cross-checked against the record collection; a hostile assertion
  name (`<img onerror>`, quotes, apostrophe) round-trips escaped in both XML and HTML.
- **Fail-on-revert: a 22-mutation matrix** (null-as-plain-fail, empty-equal comparison,
  empty-pattern match, empty-collection contains, quiet-block passes, actual dropped from
  record, location dropped, section dropped, live collection returned, export filtering
  passes, exit 0 on fail, empty-as-pass in Complete, a smuggled one-letter function, a
  smuggled alias, empty→failure element, exit 0 on failure, empty not gating, zero records
  allowed, hardcoded counts, classname dropped, HTML unescaped, HTML remote asset) — **all
  22 fail on the named assertion**, staged against mutated copies so shipped files were
  never touched.

### Needs a Windows box

- `powershell -File tools\tests\Test-ScytheAssert.ps1` under 5.1 (exit 0 = pass). Everything is
  pure logic + `System.Xml`; the specific 5.1 risks worth an eye: `Get-PSCallStack` frame
  shapes (source-location capture) and `ConvertTo-Json -InputObject` array behaviour in
  `Export-ScytheResults`.

### Migration note (mechanical, LATER, one commit — existing test files not touched now)

Per the brief, no existing test file was edited. Each of the in-package suites
(`Test-ScanReport`, `Test-CompareScanRuns`, `Test-PhaseTimingReport`, `Test-ViewerAssets`,
`Test-ServerParity`, `Test-EventContract`, `Test-CoverageMatrix`) — and the parent-tree
suites — gets the same four changes:

1. Delete the local state block (`$script:ScythePass/ScytheFail/ScytheFailures`) and the local
   `Assert-ScytheTrue`/`Assert-ScytheEqual` definitions; add
   `. (Join-Path $PSScriptRoot 'lib/ScytheAssert.ps1')` after `$ErrorActionPreference = 'Stop'`.
2. Call sites keep working unchanged: parameter names and order match the incumbent pattern
   (`Assert-ScytheTrue -Condition ... -Name ...`; `Assert-ScytheEqual $Expected $Actual $Name`).
3. Replace bare `Write-Host '<section>'` headers with `Set-ScytheSection '<section>'`.
4. Replace the hand-rolled trailer (count line, failure list, `exit`) with
   `Complete-ScytheTestRun -ExportPath "$PSScriptRoot\results\<name>.json"` (or no export).

**One semantic review per file before the swap:** the library returns `empty` (a failure)
where the local helpers passed, but only when the *actual* is `$null` or an empty **string**.
The suite's many `Assert-ScytheEqual 0 <count>` sites are safe — an integer 0 stringifies to
`'0'`, which is not empty. What must be rephrased (as `Assert-ScytheTrue ($x -eq '') ...` or a
count check) is any call whose correct actual is `''` or `$null`. Grep for `Assert-ScytheEqual ''`
first; the seven in-package suites have zero such sites (checked 2026-08-20), so the swap is
expected to be clean here — the parent-tree suites need the same grep. Where a property can
legitimately be null-or-value, the new `empty` outcome is the desired behaviour: it surfaces
a table that failed to load instead of letting `'' -eq ''` pass.

Suggested order: migrate `Test-EventContract` first (smallest), run it both ways, then the
rest in one commit.

---

## G8 — standalone packaging: study and prototype

### What was built

**`PACKAGING_STUDY.md`** (top level) — the analysis, first and most important. The
recommendation is the brief's explicitly-valid outcome: **keep the zip-plus-launcher; spend
the budget on code signing; revisit a real host application only after a signing identity
has accumulated reputation.** Script-to-exe conversion is disqualified by the data-file
boundary (rule text embedded in a script body is AMSI-scanned at load and has blocked the
engine before, silently); a self-extracting archive keeps data as files only in a vanishing
temp directory, failing the path/output requirement; a host application is the right end
state and the wrong next step while unsigned. The study costs the signing ladder (OV / EV /
Azure Trusted Signing, with lead times and what reputation accrual actually needs), and
names the first zero-risk action: Authenticode-sign the `.ps1` files inside the existing
zip as soon as any certificate exists.

**`tools/prototype/Build-SingleFile.ps1`** — the prototype for the recommended option:
"single file" as one **verified build artifact**. It stages exactly the runtime file set
(entry points, `engine\*.ps1`, `data\*.json`, `gui\**`) from `-Root` (read-only), runs the
four packaging-contract checks against the staged copies, and **refuses to build** (exit 3,
each violation named with file and line) on any hit; on success it writes `manifest.json`
(every file, size, SHA-256) into one zip. `tools/Build-Release.ps1` untouched — this is the
parallel experiment the brief asked for.

**`tools/tests/Test-PackagingContract.ps1`** — asserts the four load-bearing properties
against fixture trees authored at run time (the G5/G6 pattern: real launcher/server are
out of scope here, so fixtures reproduce the documented shapes and the engine-specific
names are parameters): (1) every path expression in launcher-role scripts resolves through
the project-root global, with the single bootstrap assignment allowed and anything else
named by file and line; (2) rule data staged as separate files, embedded in no script, and
"no data at all" is a refusal; (3) staged-set completeness from references extracted out of
the scripts themselves, with zero-extracted-references itself a failure; (4) the UTF-8
declaration present on both the reader (server) and writer (engine) side.

### New files

```
PACKAGING_STUDY.md
tools/prototype/Build-SingleFile.ps1
tools/tests/Test-PackagingContract.ps1
```

### Undocumented names — parameters, not guesses

The project-root global's name, the entry-file names, and the exact encoding-declaration
syntax are not in BLUEPRINT.md. All are parameters (`-ProjectRootVariable` default `ScytheRoot`,
`-LauncherFile`/`-ServerFile`/`-EngineFile` defaulting to the documented file names,
`-EncodingPattern` matching `...OutputEncoding = ...UTF8...` forms). **Owner: supply the
real root-global name** (and the encoding pattern if the real declaration differs) —
arguments only, no code change.

### Verified from Linux

- All three `.ps1` parse clean under pwsh 7.4.6, BOM intact; all 32 assertions pass; the
  conforming fixture builds a zip whose manifest hashes verify against the staged files.
- **Fail-on-revert: a 14-mutation matrix** against builder copies (audit skipped, any
  assignment treated as bootstrap, embed check skipped, zero-data allowed, completeness
  skipped, both vacuous guards removed, launcher references unchecked, each encoding side
  unchecked, exit 0 on violations, extension filter dropped, faked manifest hash, data not
  staged, `%~dp0` glue regression) — **all 14 fail on the named assertion**. The
  fixture-variant proofs (each property refused on a broken tree) are additionally built
  into every ordinary run of the suite.

### Needs a Windows box / the owner

The full checklist is the last section of `PACKAGING_STUDY.md` — build against the real
tree, run the contract test with `-Root`, extract-and-run on a clean VM with mark-of-the-web
(UAC prompt, live streaming without mojibake), confirm `reports\` lands beside the install
and not in `%TEMP%` (including when started from `System32` via Run-as-administrator),
manifest audit, and the signing step once a certificate exists. The two commands:

```powershell
tools\prototype\Build-SingleFile.ps1 -Root . -ProjectRootVariable <real name> -OutPath dist\Scythe-Standalone.zip
powershell -File tools\tests\Test-PackagingContract.ps1 -Root <tree> -ProjectRootVariable <real name>
```

An exit 3 naming real launcher lines is the §2 path audit working — fix or report the named
lines, do not suppress the check.

### Findings

- The brief's completeness test needs a way to tell input files from runtime-created output
  directories; the builder requires only references **with a file extension** to be staged
  (the `reports` directory reference is proven exempt by a named assertion). If the real
  launcher opens an extensionless file, that reference would be missed — none is documented;
  flagging rather than guessing.
- `tools/prototype/` is a new directory outside the path list in `tasks/00_INTEGRATION.md`,
  but it is the exact deliverable path the G8 brief names; brief taken as authoritative.

---

## Package status after G6–G8 (2026-08-20)

All eight tasks complete. Nine test suites, 355 assertions, all green under pwsh 7.4.6;
every suite also proven fail-on-revert (G6: 28 mutations, G7: 22, G8: 14, G1–G5 as recorded
in their entries). Outstanding for the owner, collected from the entries above: Windows 5.1
runs of every suite; the G5 pending shapes (five pastes); the G6 real-tree generation with
the real call names; the G7 migration commit; the G8 real-tree audit and the Windows
first-run checklist; and the real names for `-ProjectRootVariable` / phase-header /
signature-lookup commands, ideally added to `BLUEPRINT.md` §6–§7 so the parameters' defaults
can be retired.

---
