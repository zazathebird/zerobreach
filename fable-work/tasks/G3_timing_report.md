# G3 — `tools/Get-PhaseTimingReport.ps1`: where the wall-clock actually goes

**Priority 3. Size: M. New files only.**

## The problem

There is a standing performance goal — **QUICK mode under two minutes** — and no way to measure
progress against it. The data exists: every phase records its duration into `PhaseTimings`, and
the console log carries a `TIMING:` line per phase. Nothing consumes either beyond a top-10 list
printed to the console at the end of a run.

Two caching layers landed recently (file enumeration, signature verification) with their
improvement estimated rather than measured. This tool is what turns that into a number.

## Deliverables

```
tools/Get-PhaseTimingReport.ps1
data/phase_budgets.json               new file, the per-mode budget table
tools/tests/Test-PhaseTimingReport.ps1
tools/tests/fixtures/console_sample.log
```

`data/phase_budgets.json` is a new top-level file, not an edit to an existing one.

## Interface

```powershell
tools\Get-PhaseTimingReport.ps1 [-Path <run.json>] [-LogPath <console.log>]
                                [-Compare <run.json>] [-Budget data\phase_budgets.json]
                                [-Format Text|Json|Html] [-Top 20]
```

Accept either source. Prefer the run record when both are given, and say which one you used —
they can disagree, because the log covers the whole server session while the run record covers
one scan.

Parse the log with the `TIMING:` form, not the console form; the console line carries
box-drawing and leading spaces that vary. Keep fractional phase numbers intact.

## Output

- Total wall-clock, phase count, and the mode's expected ceiling
  (`QUICK 30`, `FULL 80`, `DEEP`/`PARANOID`/`STEALTH` `133`, `HUNT 162`), with any shortfall
  called out — a short count means phases did not run, which is a correctness signal wearing a
  performance costume.
- Slowest N phases with each one's share of the total.
- Cumulative distribution: how many phases account for 80% of the time. On this engine the
  answer is usually a handful, and knowing which ones directs all the optimisation effort.
- Budget check: per-mode total budget and optional per-phase budgets from
  `data/phase_budgets.json`. Exit non-zero when the total is over budget so this can gate a
  release later. Seed the file with the mode totals only (`QUICK 120`, others `0` meaning
  unbudgeted) and let per-phase entries be added over time.
- With `-Compare`, a per-phase delta table sorted by absolute change, so a caching change can be
  attributed to specific phases rather than to a total.

## Tests

1. The fixture log parses to the expected phase count and total.
2. A fractional phase (`PHASE 74.5`) keeps its decimal and is not merged into `74`.
3. A truncated log — the last phase never finished — is handled without throwing and is
   reported as incomplete.
4. Duplicate `TIMING:` lines for the same phase (a re-run in one server session) are not
   double-counted; the tool takes the last one and says it did.
5. Over-budget input exits non-zero; under-budget exits zero.
6. Percentages sum to 100 within rounding.

Prove each fails on revert.

## Note

You cannot produce real timings from Linux — the phases are Windows-specific. Work from the
fixture and from any log already in `reports/`. Record in `HANDOFF_FABLE.md` that the tool needs
one real run to validate against, and what you would want measured.
