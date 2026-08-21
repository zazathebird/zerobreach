# G1 — `tools/New-ScanReport.ps1`: a standalone report renderer

**Priority 1. Size: L. Zero file collisions — every deliverable is a new file.**

## The problem

A run drops `reports/audit_<stamp>.json` with 500–800 rows in it and an HTML report that is
essentially that same flat table with colours. What the person holding it actually needs is the
answer to "what do I tell the client, and what do I do first?" — and today they get that by
scrolling.

The renderer is a **post-processing tool**. It never runs during a scan, it reads a finished run
record, and it writes one self-contained HTML file. That separation is the whole point: it can
be rewritten, re-run against old reports, and iterated on without touching the engine.

## Deliverables

```
tools/New-ScanReport.ps1                 the renderer
tools/tests/Test-ScanReport.ps1          its tests
tools/tests/fixtures/run_small.json      hand-written, ~12 findings, every severity
tools/tests/fixtures/run_large.json      generated, 1200 findings, for the volume assertions
```

Nothing else. If you find yourself wanting to edit `engine/Summary.ps1`, stop — that file
belongs to the main session and the whole design here is to stay out of it.

## Interface

```powershell
tools\New-ScanReport.ps1 -Path reports\audit_20260819_143221.json `
                         -OutFile reports\Report_20260819.html `
                         [-Compare reports\KrakenBaseline_20260812_090000.json] `
                         [-Title "Acme Ltd — August audit"] `
                         [-PassThru]
```

- `-Path` accepts either report filename form. Validate it parses and has a `Findings` array
  before doing anything else; a clear error beats a null-reference three functions deep.
- `-OutFile` defaults to the input path with `.json` swapped for `_report.html`.
- `-PassThru` emits the computed summary object to the pipeline so the tests can assert on the
  numbers without parsing HTML. **Build every number into that object first and render from
  it** — a renderer that computes inline is untestable.

## What the report contains, in order

**1. Header.** Client title if given, host, user, mode, time window, run timestamp, wall-clock
total from `PhaseTimings`, and the risk score with its label.

**2. Executive summary — the part that matters.** Five or six sentences of generated prose, not
a table. It must say: how many phases ran and whether any were skipped; the counts by severity;
the single highest-severity group and what it is; whether this run is better or worse than the
comparison run if one was given; and — when there is nothing above `POSSIBLE` — say so plainly
and without hedging. A clean machine deserves a clean answer.

**3. What to do first.** Findings sorted by severity, then by group size descending, capped at
the top 10 groups. One row per **group**, not per finding: group label, severity, how many
findings, and the first description as the example. An operator triages by group.

**4. Tactic rollup.** Resolve each finding to MITRE technique ids using the order documented in
`reference/REPORT_DATA.md`, map those to tactics, and render a tactic-by-severity matrix. Show
every tactic in the file — the empty rows are informative, they are the coverage story.
Findings that resolve to nothing go in an explicit "unmapped" row; silently dropping them makes
the totals disagree with section 2, and a report whose own numbers disagree is worthless.

**5. Full findings table.** Sortable, filterable by severity and group, and it must stay usable
at 1,200 rows — collapse groups by default and expand on click.

**6. Run health.** `RecoveredErrors` in full, the phase-timing table sorted slowest first, and
an explicit note when `PhaseTimings.Count` is short of the mode's ceiling.

**7. Comparison** (only with `-Compare`). New findings, resolved findings, and ones present in
both, joined on `ID`. `ID` is stable across runs for the same artifact; `Timestamp` is not a
join key — see `reference/REPORT_DATA.md`.

## Hard constraints

- **One file, no network.** Inline every style and script. No CDN, no web font, no remote
  image. This report gets emailed and opened on machines with no internet, and the product rule
  is that nothing it produces reaches out.
- **Encode everything.** `Description` and `Target` contain paths and text that came off the
  scanned machine. HTML-encode on the way into markup. Where you embed data for the inline
  script, build it with `ConvertTo-Json -Compress` and then `-replace '</','<\/'` — never a
  chain of string replacements. Hand-escaping this exact thing once produced a syntax error
  that silently killed every interactive feature in the report, in every report generated for
  months, with no visible symptom.
- **Any CSV you emit runs each cell through a formula-injection guard.** A leading `=`, `+`,
  `-`, `@`, tab or carriage return must be neutralised. Correct CSV quoting does not stop a
  spreadsheet evaluating the cell, and mailing exported findings to a client is the actual
  workflow this product exists to serve. Copy `ConvertTo-CsvSafeCell` from the loader —
  `reference/LOADER_HELPERS.txt` lists it — rather than inventing a second version.
- **Print stylesheet.** These get printed to PDF. Table headers repeat, backgrounds drop out,
  nothing is clipped at the right margin.
- Readable in both light and dark; do not assume either.

## Tests

`Test-ScanReport.ps1` runs on Linux under `pwsh`. Assert against `-PassThru`, not the HTML,
except where the assertion is genuinely about markup:

1. Severity counts equal the fixture's, and `GROUPCAP_*` rows are excluded from them.
2. Tactic rollup totals plus the unmapped count equal the total finding count. This is the
   assertion that catches the tactic-name-versus-id inversion.
3. Fractional phases resolve to their own `phase_map` key, and an unknown fractional phase falls
   back to the integer floor.
4. A finding whose description contains `</script>` does not terminate the inline script block.
5. A finding whose description begins with `=` is neutralised in CSV output.
6. `-Compare` against a fixture with two removed and three added findings reports exactly that.
7. The 1,200-finding fixture renders in under 10 seconds and the output is under 5 MB.
8. A run record with an empty `Findings` array produces a valid report that states the machine
   is clean, rather than throwing or emitting an empty page.

Prove each assertion fails when you revert what it guards. Say in `HANDOFF_FABLE.md` which ones
you could not prove that way and why.

## Ask before you build

- Should the client-facing summary hide `INFO` findings entirely, or show them collapsed?
- Is there a brand or letterhead for client-facing output, or is the in-product look right?
