# HANDOFF — Scythe

**One entry per task, in the template below. Append; do not rewrite someone else's entry.**

Several sessions work in this package at once, so entries land out of order. Organise by task id,
not by date, and when you revisit a task add a dated note under its existing heading rather than
opening a second one. A reader should be able to take the *latest dated note* under a heading as
that task's current status.

All build and test claims are for Linux, .NET 8 — `dotnet build` / `dotnet test` on
`scythe-work.sln`, zero warnings (`TreatWarningsAsErrors` is on globally via
`Directory.Build.props`). If you could not run something, say so and give the exact command that
would run it, rather than leaving the claim unqualified.

**The judgement calls are the most valuable part of this document.** Every task here is a reader
over a documented format, and every format has corners the documentation settles ambiguously or
not at all. When you decide one, the decision is invisible in the code and expensive to rediscover
— record it here with the reasoning, not just the outcome.

---

## Entry template

```markdown
## <Task id> — <task title>

**Status.** Complete | Partial (what remains) | Blocked (on what).

**What was built.** Two or three sentences. What the library does, and the shape of the entry
point a caller uses.

**Files.** The exact new-file list, relative to the project directory. Every file, including
tests and fixtures — this list is what makes the merge a `git add` rather than a negotiation.

**Tests.** Count and how they are grouped, plus the three fixture classes (ordinary,
awkward-but-valid, malformed) and what each covers. State explicitly that every assertion was
shown to fail when the code it guards is reverted, or name the ones that were not.

**Judgement calls.** Each ambiguity in the spec or the format, what you chose, and why. Include
the ones you are confident about — confidence is not the same as being right, and the next
reader cannot tell which is which without your reasoning.

**Could not verify.** Anything the fixtures cannot settle: version differences, a layout only a
real machine produces, an epoch you could not confirm. Give the exact command or the exact real
artifact that would settle it.

**Shared types.** Which of the duplicated types you declared (three-state result, `ScanBudget`,
per-project state enum), and whether the duplication argued for or against a shared
`Scythe.Common` at merge time. This is a vote with evidence attached — cast it.

**Dependencies taken.** Project references added, against the README's graph. Flag any edge the
graph does not list.

**Wanted to change outside my project.** Anything you would have edited if the rules allowed —
a brief that was wrong, a reference section that was ambiguous, a convention that fought you.
Nothing here is a complaint; it is the next revision of the package.
```

---

<!-- Entries begin here. Track Q first — see tasks/00_INTEGRATION.md § Order. -->

## Q1 — Time normalisation

*2026-08-28.*

**Status.** Complete.

**What was built.** `Scythe.Time` decodes the eight timestamp encodings tabulated in
`reference/11.1_time.md` §11.1 into one `NormalisedTimestamp` that carries the moment together
with its precision, its zone certainty, which sentinel matched if the field was never written,
the source encoding, and the raw bytes as they appeared. A caller calls a `TimeDecoder.Decode*`
method per encoding — scalar overloads for a value already read out, span overloads for the
fixed-width forms — and gets a `TimeResult<T>` in one of the three package states. Comparison
(`TimeComparer.Compare`) is precision-aware and returns four outcomes; formatting
(`TimeFormatter.Format`) is fixed per precision and never consults the host.

**Files.** All new; nothing outside these two directories was edited except adding both projects
to `scythe-work.sln`.

```
Scythe.Time/Scythe.Time.csproj
Scythe.Time/ScanBudget.cs
Scythe.Time/TimeResult.cs
Scythe.Time/TimeEncoding.cs
Scythe.Time/TimePrecision.cs
Scythe.Time/ZoneCertainty.cs
Scythe.Time/TimePresence.cs
Scythe.Time/RawTimeValue.cs
Scythe.Time/NormalisedTimestamp.cs
Scythe.Time/Readings.cs
Scythe.Time/TimeDecoder.cs
Scythe.Time/TimeDecoder.Spans.cs
Scythe.Time/TimeComparison.cs
Scythe.Time/TimeComparer.cs
Scythe.Time/TimeFormatter.cs

Scythe.Time.Tests/Scythe.Time.Tests.csproj
Scythe.Time.Tests/AssemblyInfo.cs
Scythe.Time.Tests/Fixtures/TimeFixtures.cs
Scythe.Time.Tests/OrdinaryDecodeTests.cs
Scythe.Time.Tests/AwkwardButValidTests.cs
Scythe.Time.Tests/SentinelTests.cs
Scythe.Time.Tests/MalformedTests.cs
Scythe.Time.Tests/ComparisonTests.cs
Scythe.Time.Tests/FormattingTests.cs
Scythe.Time.Tests/DeterminismTests.cs
Scythe.Time.Tests/BudgetCanaryTests.cs
```

**Tests.** 134 tests, grouped one file per concern. `dotnet build` and `dotnet test` on
`scythe-work.sln` are green on Linux with zero warnings.

- *Ordinary* (`OrdinaryDecodeTests`) — each encoding round-trips a current-decade instant with the
  expected value, precision and zone; each epoch boundary; the span overloads agree with the
  scalar ones.
- *Awkward but valid* (`AwkwardButValidTests`) — the packed pair at 1980 and at 2107; the 32-bit
  counter above `0x7FFFFFFF` under both signednesses with the ambiguity reported; the variant form
  negative, pinned against a naive `AddDays`; the split counter with its members transposed; a
  decimal string with leading zeros and surrounding whitespace at the twenty-digit boundary.
- *Malformed* (`MalformedTests`) — short spans for every fixed-width form; every out-of-range
  packed and split-calendar field, each asserting the offending field is named; `NaN`, both
  infinities and out-of-range magnitudes; one tick past the maximum representable count; a
  400-digit and a ten-million-character decimal string; and a sweep of ~44 000 packed word pairs
  asserting nothing throws.
- *Sentinels* — one test per encoding's "never set" pattern, each asserting `Absent`, the specific
  `SentinelKind`, and that the formatted output contains **no digit at all** (stronger than "no
  year", so it cannot be mistaken for a date whatever the encoding).
- *Budget canaries* — input past `MaxInputBytes` is `Incomplete` with the budget named; the same
  bytes under the default budget are `Failed` on length instead; and input inside the budget still
  decodes, so the guard is shown to be quiet as well as loud.
- *Determinism* — formatting and the full N×N comparison matrix render byte-identically under
  three host cultures and two host time zones, and across repeated runs.

**Every assertion was shown to fail when the code it guards is reverted**, by mutation rather than
by inspection. Thirty mutations were applied one at a time to the library — each sentinel dropped,
each range and field check neutered, both epochs moved by a day, the split counter's members
transposed, the packed pair made to claim UTC and one-second precision, `NotComparable` dropped,
the comparison window's overlap made inclusive and its widening removed, both offset signs
flipped, the formatter's `InvariantCulture` argument removed, the absent rendering replaced with a
date, and `TimeResult.Incomplete` collapsed into `Ok` at the factory. **All thirty were killed,
none survived**, and 29 were killed by the specific test written for them. Two findings came out
of that run and are fixed rather than merely noted:

- No test caught a flipped sign on a *recorded* offset, because every test that attached one used
  `TimeSpan.Zero`, where the sign cannot show. Two tests now pin it in both directions:
  `ARecordedOffsetAnchorsTheReadingInTheDirectionThatSubtractsIt` and
  `APositiveRecordedOffsetAnchorsTheOtherWay`.
- The determinism tests originally named real cultures. `InvariantGlobalization` is set for the
  whole package in `Directory.Build.props`, so a named culture either throws or behaves
  invariantly — and a culture that behaves invariantly would let a missing
  `CultureInfo.InvariantCulture` argument sail straight through. The tests now clone the invariant
  culture and mutate its `TimeSeparator`, which bites regardless, and
  `TheHostileCulturesWouldActuallyChangeAnUnguardedFormat` is the negative control proving the
  hostile culture is not inert. **Anyone writing culture-sensitivity tests elsewhere in this
  package needs to know this** — it is the kind of test that passes for the wrong reason.

**Judgement calls.**

1. **The comparison window is centred on the value, not run forward from it.** `reference/11.1`
   says "the value, widened by its precision", which admits both readings. I took centred —
   `[v − w/2, v + w/2]` — because the reference's own formatting marker for the two-second form is
   `±1s`, which is a statement that the moment lies either side of the value. The alternative is
   defensible on different grounds: the packed pair *truncates* its seconds field, so physically
   the true instant lies in `[v, v + 2s)`. If a later track finds that half-open reading matters,
   the change is one line in `TimeComparer.CompareWindows` — but it will move outcomes, and the
   brief's own worked example ("the same pair with one coarsened to two-second precision is
   `NotDistinguishable`") only comes out right under the centred reading.
2. **Window overlap is tested strictly (`<`), not inclusively.** Two second-counter values exactly
   one second apart have windows that touch at an endpoint; an inclusive test would call them
   `NotDistinguishable`, which would collapse every second-resolution comparison in the package.
   Equal values produce degenerate windows at 100 ns precision, so there is an explicit fallthrough
   returning `NotDistinguishable` when the centres coincide.
3. **Two values that are *both* zone-unknown are compared, not refused.** The reference's condition
   for `NotComparable` is literally "one zone is unknown and the other is not". Comparing two local
   readings is only honest if they came from the same machine; the design position is that a caller
   comparing two local readings is asserting exactly that. If that is wrong, the fix is to return
   `NotComparable` when *either* side is unanchored — one condition in `TimeComparer.Compare`.
4. **The eight split calendar fields are taken by name, not as a span.** §11.1 gives the field set
   but never the order the fields sit in on disk. Rather than guess a layout, the entry point takes
   eight named parameters and the reader that located the structure maps its own order onto them.
   This is the one place I would otherwise have had to guess, and guessing would have produced a
   decoder that is silently wrong for any producer using a different order. **This is an open
   question for the package, not just for me** — see *Could not verify*.
5. **All-bits-set is not a sentinel for the decimal-string form.** The table lists that row's "not
   set" patterns as `"0"`, empty and whitespace-only, and does not list all-bits-set, so the text
   `"18446744073709551615"` is an out-of-range count and therefore `Failed`. Reading the table
   exactly matters here: treating it as an absence would make a corrupt field vanish from a report
   rather than be flagged. Contrast the binary counters, where the table *does* list it.
6. **Split-pair sentinels are checked on the members, not on the assembled count.** A low member of
   `0xFFFFFFFF` beside a high member of `0` is an ordinary count of about seven minutes past the
   epoch. Testing the assembled value would have swallowed it. Pinned by
   `SplitCounter1601_OnlyTheWholeGroupIsASentinel`.
7. **The packed pair's day field is validated against the length of the month.** The brief asks for
   a "day 32" case, but the day field is five bits and tops out at 31, so day 32 is not
   representable and no test can construct it. The reachable overrun is a day past the end of a
   short month — 31 April, 30 February — which is just as malformed and far likelier; those are
   what the tests cover, with a leap-day case as the negative control.
8. **A split-calendar `second` field of 60 is `Failed`.** `DateTime` cannot represent a leap second,
   so accepting 60 would mean silently renumbering the value to `:59` or to the next minute. The
   reference does not say whether producers ever write 60 here.
9. **The day-of-week field is range-checked but not cross-checked against the date.** Zero is both
   "Sunday" and the value producers leave when they do not fill the field in, so a disagreement
   cannot be distinguished from an omission and must not be treated as malformed.
10. **Variant values are rounded to the millisecond they are attributed.** The mantissa resolves
    finer over the usable range, but §11.1 says to attribute millisecond precision, and carrying
    sub-millisecond mantissa noise into a value whose formatter prints three digits would be
    keeping precision the library has just declared it does not have.
11. **Truncated spans are `Incomplete`, not `Failed`.** Nothing about the field is malformed; the
    caller did not supply all of it. `AnEmptySpanIsNeverMistakenForTheZeroSentinel` pins the
    distinction that matters most: a zeroed eight-byte field says "never written", and no field at
    all says nothing.
12. **`ScanBudget` is an optional parameter defaulting to `ScanBudget.Default`, and only
    `MaxInputBytes` binds.** Every entry point here except the decimal-string form takes a
    fixed-width scalar, so there is no loop to bound, no container to recurse into and no output to
    expand. The other three members are carried rather than dropped so that a caller can set one
    budget per artifact and hand the same object to every reader in the package. Flagging this
    because a reviewer expecting a required budget argument will notice the difference.
13. **Raw bytes are written little-endian explicitly**, not via `BitConverter`, so the raw rendering
    does not change with the processor running the reader.
14. **Zone markers for `LocalOffsetRecorded` and `Unknown` are mine.** §11.1's table gives markers
    only for `Utc` and the local-unrecorded case. I render them ` (local, offset ±HH:MM)` and
    ` (zone unknown)`. Both are pinned by test, so if the package wants different text it is a
    one-line change in `TimeFormatter` plus the two assertions.

**Could not verify.**

- **The on-disk field order of the eight-element split calendar structure.** Not in §11.1, and no
  fixture can settle it — a fixture would only encode whatever order I assumed. Sidestepped by
  taking named parameters (judgement call 4), so nothing in this library is wrong either way, but
  **the first Track E task that reads this structure has to answer it**, and should record the
  answer in `reference/11.1_time.md` rather than in its own code. Settled by: one real record
  containing the structure with a known timestamp, or an authoritative statement of the layout.
- **Whether the variant day count carries local or UTC readings in the artifacts this package
  reads.** Q1 open question 1, unanswered. Decoded as `ZoneCertainty.Unknown` per the brief's
  stated assumption, which degrades comparison to `NotComparable` — the safe direction — and
  `NarrowUnknownZone` lets a caller settle it per artifact. Settled by: one artifact of a known
  producer with a timestamp whose true zone is independently known.
- **Whether producers ever write `second == 60`** in the split calendar form (judgement call 8).
- **Agreement with what a live Windows machine actually writes**, for every encoding. Everything
  here is proven against fixtures I authored. Settled by decoding a real artifact of each kind and
  comparing against a reference implementation's output.

**Shared types.** Declared `ScanBudget` (exact shape from §3), `TimeResultState` (`Ok` /
`Incomplete` / `Failed`) and the generic `TimeResult<T>` carrying `Value`, `Reason` and `Position`.

**My vote: a shared `Scythe.Common` is worth it, but only for `ScanBudget`.** `ScanBudget` is a
pure data record with no per-project variation — thirty-seven identical copies is thirty-seven
chances to let one drift, and a caller composing several libraries has to construct one per
assembly for no reason. The result type is a weaker case than it looks: mine is generic over the
payload and carries a `Position` that only the position-bearing formats populate, and I would
expect other tracks to want members mine does not have. If only one type moves, move `ScanBudget`.

One deliberate deviation from the shared shape, flagged rather than hidden: `TimeResult<T>` allows
`Incomplete` to carry a partial `Value`, which the 32-bit ambiguous decode uses to return both
candidate readings. It is still an unfinished answer and is never collapsed into `Ok` — the
mutation that collapsed it at the factory was killed by test.

**Dependencies taken.** None. `Scythe.Time` references nothing; the test project references only
xUnit at the three pinned versions and the library. This matches the README's graph, where Q1 is a
source of edges and a target of none.

**Wanted to change outside my project.**

1. **`reference/11.1_time.md`, the variant day count paragraph, is internally inconsistent.** It
   says the naive `AddDays` is "wrong by twice the fractional part — six hours of error on a value
   like `-1.25`". Those two statements disagree: the fractional part of `-1.25` is a quarter day,
   six hours, so twice it is *twelve* hours, and twelve is what the arithmetic gives. Correct
   conversion of `-1.25` is 1899-12-29 06:00; naive is 1899-12-28 18:00; the gap is twelve hours,
   pinned by `VariantDayCount_NegativeValueDisagreesWithANaiveAddDays`. The formula in that
   paragraph is right and I implemented it; only the worked figure is wrong. Suggested edit:
   "twelve hours of error on a value like `-1.25`".
2. **`reference/11.1_time.md` should record the split calendar field order** once someone
   establishes it, and should say explicitly which markers to use for `LocalOffsetRecorded` and
   `Unknown` (judgement call 14) — three of the four zone states are currently unrendered by the
   table.
3. **The brief's "day 32" malformed case for the packed date is not constructible** (judgement
   call 7). Suggested edit to `tasks/Q1_time_normalisation.md`: replace "day 32" with "a day past
   the end of the month".
4. **`Directory.Build.props` sets `InvariantGlobalization`, which quietly weakens every
   culture-sensitivity test in the package.** I worked around it inside my own tests rather than
   changing the file. Worth a comment in `Directory.Build.props` pointing at the technique, since
   the next author to write "run it under `fr-FR`" will get a test that passes for the wrong
   reason. This is the finding from this task most likely to matter to someone else.

## Q2 — Text encoding detection and decoding

*2026-09-02.*

**Status.** Complete.

**What was built.** `Scythe.Text` takes a byte buffer and answers two questions separately.
`TextDetector.Detect(bytes, hint?, budget?)` says what encoding the bytes are in — byte-order
mark first (longest first), then structural UTF-8 validation, then the markless UTF-16 null
distribution, then a ranked scoring of eight embedded single-byte code pages — and returns a
`DetectionResult` carrying the encoding, an ordered `DetectionConfidence`, the mark length, the
full ranked candidate list, the sampled extents scoring covered, what became of the caller's hint,
and the original bytes. `TextDecoder.DecodeStrict` / `DecodeReporting(bytes, encoding, budget?)`
turn bytes into text under a named encoding: strict is `Incomplete` with a reason and a position
at the first undecodable byte and carries no text; reporting is `Ok` with text plus
`UndecodableRuns`, each run carrying both its byte coordinates and its character coordinates, and
`SourceReplacementCharacterCount` so a tool-inserted `U+FFFD` and a file-original one are
distinguishable. The single-byte tables are generated into `CodePages.g.cs` by the
`gen_codepages.py` kept beside them; the library consults no host encoding provider at runtime.

**Files.** All new; nothing outside these two directories was edited except adding both projects
to `scythe-work.sln`.

```
Scythe.Text/Scythe.Text.csproj
Scythe.Text/ScanBudget.cs
Scythe.Text/TextResult.cs
Scythe.Text/TextEncodingKind.cs
Scythe.Text/DetectionConfidence.cs
Scythe.Text/DetectionHint.cs
Scythe.Text/DetectionResult.cs
Scythe.Text/DecodedText.cs
Scythe.Text/ByteOrderMark.cs
Scythe.Text/BufferScan.cs
Scythe.Text/CodePage.cs
Scythe.Text/CodePages.g.cs
Scythe.Text/gen_codepages.py
Scythe.Text/CodePageScorer.cs
Scythe.Text/TextDetector.cs
Scythe.Text/TextDecoder.cs

Scythe.Text.Tests/Scythe.Text.Tests.csproj
Scythe.Text.Tests/AssemblyInfo.cs
Scythe.Text.Tests/Fixtures/TextFixtures.cs
Scythe.Text.Tests/OrdinaryDetectionTests.cs
Scythe.Text.Tests/OrdinaryDecodeTests.cs
Scythe.Text.Tests/AwkwardButValidTests.cs
Scythe.Text.Tests/Utf8RejectionTests.cs
Scythe.Text.Tests/MalformedAndBudgetTests.cs
Scythe.Text.Tests/ReplacementAttributionInvariantTests.cs
Scythe.Text.Tests/DeterminismTests.cs
Scythe.Text.Tests/CodePageTableTests.cs
```

**Tests.** 157 tests, one file per concern. `dotnet build` and `dotnet test` on
`scythe-work.sln` are green on Linux with zero warnings.

- *Ordinary* (`OrdinaryDetectionTests`, 24; `OrdinaryDecodeTests`, 19) — UTF-8 with and without a
  mark; ASCII; UTF-16 both orders, marked and markless; UTF-32 both orders; one buffer per
  supported page holding its characteristic letters, asserted at the top of the ranking; the
  empty buffer (`Ok`, ASCII, empty text); a buffer holding only a mark; the six recognised-but-
  not-decoded marks named; `OriginalBytes` is the buffer as received.
- *Awkward but valid* (`AwkwardButValidTests`, 22) — the UTF-32 LE pinning fixture; all-ASCII
  reported as ASCII; markless Cyrillic UTF-16 at Low rather than a confident wrong answer, and
  rescued to Medium by a hint; an odd-length buffer, with and without a hint; a ten-byte buffer
  below the UTF-16 minimum; an array of little-endian 32-bit integers (nulls on both sides);
  the `0x80`–`0x9F` Windows/ISO family split; undefined entries discriminating two letter
  pages; a genuinely tied buffer reporting `Ambiguous`; a genuine `U+FFFD` surviving with the
  runs empty; a hint contradicting a mark; a page hint breaking a tie; a UTF-8 hint on ASCII
  bytes agreeing; an unpaired surrogate reported not replaced; a windows-1252 hole as a hole; the
  control-density cap; CJK-looking ASCII bytes under a UTF-16 hint; and one characterisation
  test of the reference weights (judgement call 12).
- *UTF-8 rejection* (`Utf8RejectionTests`, 34) — the eleven ill-formed classes in the brief
  (`C0`, `C1`, `E0 80`, `E0 9F`, `ED A0`, `ED BF`, `F0 8F`, `F4 90`, `F5`, `FF`, a bare
  continuation), each asserted to be exactly one run at the right offset and length in reporting
  mode, refused with that position in strict mode, and not detected as UTF-8 or ASCII; plus a
  lead byte truncated at end of buffer.
- *Malformed and budget* (`MalformedAndBudgetTests`, 11) — the `MaxInputBytes` canary pair (over
  is `Incomplete` naming the budget; at the limit still runs); the default 64 MiB budget bites;
  4 MiB constructed so every page scores negative, returning Low with the sampled extent bounded;
  a million undecodable runs stopping at `MaxMatches` with the runs so far; a single lead byte;
  a truncated four-byte mark; an odd trailing UTF-16 byte; an ill-formed UTF-32 unit; an
  unrecognised encoding kind is `Failed`, not a throw; a hint on an over-budget buffer.
- *The invariant* (`ReplacementAttributionInvariantTests`, 5) — named for the property: every
  `U+FFFD` not covered by a run was in the source, in UTF-8 and UTF-16, with a negative control
  proving the helper can go red and a fixture where multi-byte characters shift the two
  coordinate systems apart.
- *Determinism* (`DeterminismTests`, 5) — detection and both decodes byte-identical under three
  host cultures, the candidate list reversed, and the same input twice.
- *Tables* (`CodePageTableTests`, 37) — the embedded tables pinned against hand-written values
  from the published mappings: the exact undefined holes per Windows page, the ISO pages' C1
  range, spot letters per page, the cp437 Greek block as a foreign script, the ASCII half
  transparent everywhere, and the canonical order.

**Every assertion was shown to fail when the code it guards is reverted**, by mutation. Thirty-
five mutations were applied to the library one at a time — the UTF-32 LE mark row moved below the
UTF-16 rows; each of the five bolded UTF-8 second-byte ranges widened; `C0`/`C1` accepted as leads;
the undefined-entry, C1-control and hint-bias weights zeroed; the canonical tie-break dropped;
strict decode made substituting; run recording dropped; run coalescing dropped; the run's
character index zeroed; the source-replacement counter frozen; the unpaired surrogate replaced;
the mark skip removed; UTF-16 byte order flipped; `MaxMatches` and both `MaxInputBytes` checks
removed; the sampling bound removed; the odd-length, minimum-length, opposite-side, dominant-side,
tie and control-density thresholds each neutered; the mark-versus-hint contradiction hidden; ASCII
reported as UTF-8; the recognised-but-not-decoded path made `Ok`; a windows-1252 hole filled with
a plausible character; and `TextResult.Incomplete` collapsed into `Ok` at the factory. **All
thirty-five were killed**, 33 by the specific test written for them (the other two were probes,
below). Two findings from the run are fixed rather than noted:

- Nothing pinned the 16-byte minimum for markless UTF-16, and nothing pinned the rule that nulls
  on the *opposite* side disqualify it — both thresholds could be deleted and the suite stayed
  green. `AMarklessBufferShorterThanSixteenBytesIsNotJudgedByItsNullDistribution` and
  `NullsOnBothSidesDisqualifyUtf16EvenWhenTheDominantSideIsSaturated` (an array of small
  little-endian integers, which is what that pattern looks like in the wild) now hold them.
- Anyone repeating this technique here: `if (false)` is not a usable mutation under
  `TreatWarningsAsErrors` — the unreachable-code warning is a build error. Use a runtime-opaque
  false such as `x > int.MaxValue`.

**Judgement calls.**

1. **A buffer that validates as UTF-8 but contains NUL bytes is not decided at the UTF-8 step.**
   Markless Latin-script UTF-16 is, byte for byte, valid "ASCII with NULs", so deciding on
   validity alone would call every such file ASCII. NULs send the buffer to the UTF-16 heuristic
   first; if that declines, the structural answer (UTF-8 or ASCII) is returned at **Low**, because
   NULs inside single-byte text are anomalous. This is the only place ASCII is reported below High.
2. **A control-density cap, which the reference does not have.** Greek or CJK UTF-16 read
   byte-wise is a letter byte then `0x03` (or similar), over and over: not valid UTF-8, no nulls,
   so it reaches single-byte scoring, where some Cyrillic page happily assigns letters to the odd
   bytes and wins at High. C0 controls other than tab, LF and CR at ≥10% of the buffer cap any
   ASCII or single-byte answer at Low. `ControlByteDensityCapsASingleByteAnswerAtLowConfidence`
   pins it; the threshold is a constant with a comment. Without this the library returns a
   confident wrong answer on every markless non-Latin UTF-16 file.
3. **Hint semantics (open question 2).** A hint never bypasses validation. A mark beats it and the
   contradiction is reported. A UTF-16 hint is *followed* at Medium only where the bytes cannot
   settle the question — an even-length buffer that is either all-ASCII-with-no-NULs (CJK UTF-16
   looks like that) or not clean UTF-8 with a null pattern too weak to score — and never for an odd
   length. A single-byte page hint adds +2 per non-ASCII byte to that page: enough to break a tie
   between pages that map the bytes identically, not enough to overturn an undefined-entry hit.
   A UTF-8 or single-byte hint on all-ASCII bytes is *agreed*, because ASCII decodes identically
   under all of them; the answer stays ASCII because that is what the bytes are. The seven
   `HintOutcome` values are the contract; `NotEvaluated` is what a hint gets when the buffer was
   over budget and detection never ran — reporting it as contradicted would be a false claim.
4. **The confidence is computed on the raw summed score, using integer arithmetic.** The
   reference gives the per-byte scores "normalised by their count"; the normalised figure is
   exposed on every candidate (`ScorePerNonAsciiByte`) but the divisor is the same for every
   candidate, so ranking and the 5%/15% gap tests come out identical on the raw sums and avoid a
   floating-point comparison. The tie-break is the documented canonical order (1252, 1250, 1251,
   8859-1, 8859-2, 8859-5, 437, 850), pinned by `TheCanonicalOrderIsTheDocumentedOne`.
5. **Which bytes count as "punctuation or a symbol common in prose" (+1) is mine.** The reference
   names quotes, dashes and currency; the concrete set is the `PROSE` list in `gen_codepages.py`
   (NBSP, soft hyphen, ¡ ¿ § ¶ © ® ™ №, the guillemets and curly quotes, en/em dash, ellipsis,
   bullet, per-mille, middle dot, the currency signs, degree and the vulgar fractions). Box-drawing
   and block characters in the OEM pages are "other symbol" at 0. The micro sign is treated as a
   symbol, not a letter, although Unicode categorises it `Ll`. Script membership is by block
   (Latin, Greek, Cyrillic); the Greek block in cp437 is a *foreign-script* letter for that page.
6. **Sampling (open question 3).** `BufferScan` — UTF-8 validation, the null distribution and the
   control count — runs over the whole buffer, as the brief assumed; it is one linear pass with no
   allocation. Single-byte scoring reads a 64 KiB prefix, 16 KiB from the middle and 16 KiB from
   the end of anything larger than 96 KiB, and `SampledRanges` reports exactly what it read.
7. **One `U+FFFD` per byte-adjacent run (open question 4).** Consecutive undecodable bytes
   coalesce, so two adjacent bad UTF-32 units are one eight-byte run and `E2 82` at end of buffer
   is one two-byte run. `CharLength` is therefore always 1 today; it is carried so the contract
   does not change if that decision does.
8. **A truncated four-byte mark is read for what is actually present.** `FF FE 00` is listed in
   the brief under malformed. Only the two-byte UTF-16 LE mark is fully there, so detection says
   UTF-16 LE with a two-byte mark, and the reporting decode carries the dangling `00` as a
   one-byte run at offset 2. The alternative — refusing because the bytes *might* have been a
   UTF-32 mark — would refuse every two-byte UTF-16 LE file whose first character's low byte is
   `00`, which is every Latin-script one.
9. **UTF-32 surrogate code points and values above `U+10FFFF` are undecodable runs; UTF-16
   unpaired surrogates are not.** A lone surrogate is a legal UTF-16 code unit and a legal `char`,
   so it is kept and listed in `UnpairedSurrogates` with both coordinates. A UTF-32 unit in the
   surrogate range is not a scalar value in any reading of the format, so it is damage.
10. **Strict failures carry an empty-text `DecodedText`, not `null`.** `OriginalBytes` has to be
    on every result including strict failures, so the value is present with `Text` empty,
    `MarkLength` set and the runs empty; `Position` is the offending byte offset.
11. **`OriginalBytes` is the caller's array by reference, not a copy.** Copying would double
    memory for every 64 MiB buffer, and the tests assert `Same`. A caller that mutates the array
    after the call changes what the result reports; that is documented on `Detect`.
12. **The reference's scoring weights, implemented exactly, mis-rank ordinary French.** This is
    the finding from this task most likely to matter to a consumer. A primary-script letter scores
    +3 and +2 more beside each ASCII letter; a prose symbol scores +1. So any page that maps a
    symbol byte to a *letter* beats the page that maps it to the symbol. cp850 maps windows-1252's
    curly apostrophe (`0x92`) to `Æ` and `é` (`0xE9`) to `Ú`, and wins `c’est l’été` **at High
    confidence** (cp850 = 23, windows-1252 = 12). iso-8859-2 maps the guillemets to `Ť`/`ť` and
    edges windows-1252 on `« détails »` (13 to 9, reported `Ambiguous`). I did not change the
    weights: the brief says to read the reference exactly, and retuning a scoring table by feel
    without a corpus is how the next confident wrong answer gets in. It is pinned by
    `KnownLimitation_TheReferenceWeightsRankCp850AboveWindows1252OnCurlyApostropheFrench`, whose
    failure message says what to do when the weights change. See *Wanted to change*.
13. **`ScanBudget` is optional and only `MaxInputBytes` and `MaxMatches` bind**, matching Q1's
    position. `MaxMatches` ceilings the undecodable-run list: the reporting decode returns
    `Incomplete` naming the budget, with the text and runs gathered up to that offset. `Deadline`
    is not enforced: every pass is linear in the input, scoring is bounded by sampling, and there
    is no recursion, so a wall-clock check would add a timer to a function with nothing to cut
    short. `MaxNestingDepth` has nothing to bound. Both are carried so a caller can hand one
    budget to every reader in the package.
14. **Empty input is `Ok`, ASCII, High**, and a hint on it is `AgreedWithEvidence`: zero bytes are
    valid in every encoding and neither confirm nor contradict anything.

**Could not verify.**

- **Agreement with what real producers write.** Everything here is proven against fixtures
  encoded through the library's own tables, with `CodePageTableTests` pinning those tables against
  hand-typed values from the published mappings as the independent check. Settled by: a file of
  each encoding from a known producer, run through `TextDetector.Detect` and compared with a
  reference implementation.
- **"The host's default encoding varied where the framework allows."** It does not allow it. On
  .NET 8 `Encoding.Default` is always UTF-8 and cannot be changed; there is no host default page to
  vary and the library never consults one. The culture half of that determinism requirement is
  tested (three hostile cultures, with a negative control proving they bite). See *Wanted to
  change* for the brief's wording.
- **The scoring weights on a real corpus** (judgement call 12). Only constructed sentences were
  tried. Settled by: a labelled corpus of single-byte files per page, scored, with the confusion
  matrix recorded in `reference/11.2_text.md`.

**Shared types.** Declared `ScanBudget` (exact shape from §3, identical to Q1's), `TextResultState`
and `TextResult<T>` (`Value`, `Reason`, `Position`), with the same deliberate deviation as Q1:
`Incomplete` may carry a partial value, which the reporting decode uses to return the runs gathered
before `MaxMatches` and which strict failures use to carry `OriginalBytes`. Never collapsed into
`Ok`; the mutation that did so was killed by thirteen tests.

**My vote on `Scythe.Common`: same as Q1's — move `ScanBudget`, and only `ScanBudget`.** Q1's
`TimeResult<T>` and my `TextResult<T>` happen to have the same three members, which is an argument
for merging them, but neither of us needed `Position` to mean the same thing, and the next track
will want a member neither of us has.

**Dependencies taken.** None. `Scythe.Text` references nothing; the test project references only
xUnit at the three pinned versions and the library. `InternalsVisibleTo` is granted to the test
project so the determinism suite can score with the candidate list reversed.

**Wanted to change outside my project.**

1. **`reference/11.2_text.md`, the single-byte weights** (judgement call 12). A prose symbol at +1
   against a letter at +3 (+2 more beside ASCII) means the OEM and ISO-2 pages, which map
   windows-1252's `0x80`–`0x9F` punctuation to letters, win ordinary Western prose whenever curly
   punctuation sits inside words. Two candidate fixes, either of which should be validated on a
   corpus before landing: score a prose symbol *between two ASCII letters* (an apostrophe's only
   habitat) at +3 rather than +1, or score an accented letter run that contains no vowel-like
   letter for the page's language at −2. I would not guess between them.
2. **`tasks/Q2_text_encoding_detection.md`, the determinism paragraph**: "with the host's default
   encoding varied where the framework allows" is not achievable on .NET 8 and reads as a coverage
   gap when it is not. Suggested edit: "the host's default encoding is fixed on .NET Core and the
   library never consults it; assert that by review".
3. **The brief's "truncated four-byte mark" malformed case** does not say what to return
   (judgement call 8). Whichever reading the package wants, it should be in the reference so the
   next reader that meets `FF FE 00` at the start of a value agrees with this one.
4. **`Directory.Build.props`**: same as Q1's note 4 — `InvariantGlobalization` silently weakens
   named-culture tests; the clone-and-mutate technique in `DeterminismTests` is the workaround and
   deserves a pointer in the props file.
5. **Every reader that hands bytes to this library should pass a hint where it has one** — the
   hive value type, the shell-link Unicode flag. The hint is what rescues non-Latin UTF-16 (judgement
   call 3), and a consumer that omits it will see Low-confidence answers on exactly the buffers a
   flag would have settled.

---

## K4 — Technique reference map

*2026-09-02.*

**Status.** Complete.

**What was built.** `Scythe.Techniques` loads a technique reference map from JSON bytes
(`TechniqueMapLoader.Load(ReadOnlyMemory<byte>, ScanBudget?)`, plus a `string` overload),
validates it to the letter of `reference/07.4_technique_map.md`, and hands back a
`TechniqueMap` whose invariants — strict identifier format, every sub-technique's parent
present, no duplicates, every keyword rule pointing at a real entry — are guaranteed by
construction. A caller then builds a `TechniqueResolver` from the map and its checks' declared
mappings (`TechniqueResolver.Create(map, IReadOnlyList<CheckMapping>)`) and calls
`ResolveAll(IReadOnlyList<Finding>, ScanBudget?)` to get a `TechniqueRun`: one
`FindingResolution` per finding in input order, plus a `TechniqueRollup`. `FindingResolution` is
an abstract type with exactly two subtypes, `ResolvedFinding` (entry, strategy, rule ordinal) and
`UnresolvedFinding` (a `UnresolvedReason` enum, a detail string, and the list of strategies
tried with why each declined); it has no identifier member of its own, so there is nothing for
a caller to null-coalesce. `Resolve(Finding)` runs the chain for one finding and is public for
the per-strategy tests.

**Files.** All new; nothing outside these two directories was touched.

```
Scythe.Techniques/Scythe.Techniques.csproj
Scythe.Techniques/ScanBudget.cs
Scythe.Techniques/TechniqueResult.cs
Scythe.Techniques/TechniqueIdentifier.cs
Scythe.Techniques/TechniqueEntry.cs
Scythe.Techniques/KeywordRule.cs
Scythe.Techniques/TechniqueMap.cs
Scythe.Techniques/TechniqueMapLoader.cs
Scythe.Techniques/Finding.cs                 (Finding and CheckMapping records)
Scythe.Techniques/FindingResolution.cs       (ResolutionStrategy, UnresolvedReason, StrategyAttempt,
                                              FindingResolution, ResolvedFinding, UnresolvedFinding)
Scythe.Techniques/TechniqueResolver.cs
Scythe.Techniques/TechniqueRun.cs
Scythe.Techniques/TechniqueRollup.cs         (CountedName, StrategyCount, UnresolvedReasonCount, TechniqueRollup)

Scythe.Techniques.Tests/Scythe.Techniques.Tests.csproj
Scythe.Techniques.Tests/AssemblyInfo.cs
Scythe.Techniques.Tests/Fixtures/MapFixtures.cs
Scythe.Techniques.Tests/MapLoadingTests.cs
Scythe.Techniques.Tests/MapValidationTests.cs
Scythe.Techniques.Tests/MapMalformedTests.cs
Scythe.Techniques.Tests/ResolutionChainTests.cs
Scythe.Techniques.Tests/StrictnessTests.cs
Scythe.Techniques.Tests/KeywordRuleTests.cs
Scythe.Techniques.Tests/RollupTests.cs
Scythe.Techniques.Tests/DeterminismTests.cs
Scythe.Techniques.Tests/BudgetCanaryTests.cs
```

**Tests.** 191 tests, one file per concern. `dotnet build` and `dotnet test` on
`Scythe.Techniques.Tests/Scythe.Techniques.Tests.csproj` are green on Linux with zero warnings.
The projects were **not** added to `scythe-work.sln` (coordinator's job); the command that
verifies the whole-solution claim once they are is `dotnet test scythe-work.sln`.

The fixture is a programmatic `MapBuilder` that emits the JSON text; `Raw*` members inject
arbitrary text so each malformation is produced deliberately. `MapFixtures.Standard()` is six
entries (three techniques, three sub-techniques, one sub-technique in a different category from
its parent so category roll-up is observable) and three keyword rules.

- *Ordinary* (`MapLoadingTests`, `ResolutionChainTests`, `RollupTests`) — the standard map
  loads with every section; ordinal sort regardless of file order; exact case-sensitive lookup;
  single-entry and empty maps; each strategy in isolation with the reported strategy and rule
  ordinal; every chain-order pairing (explicit > check, check > keyword, explicit > keyword, all
  three); agreeing duplicate check mappings collapse, disagreeing ones fail construction naming
  the check; the named rollup tests (sub-technique-only run reports both sub and parent counts
  from the two documented members; direct counts sum to the resolved count while rolled-up
  counts exceed it by exactly the number of sub-technique findings); category roll-up when the
  parent's category differs and when it is shared; strategy and reason counts; ordinal-equals-
  numeric identifier ordering (`T0999 < T1003 < T1003.001 < T1003.010 < T1021`); the empty run.
- *Awkward but valid* — parent listed after its sub-technique; UTF-8 BOM prefix; URL kept
  verbatim (upper-case host, query, fragment — not normalised through `Uri`); Unicode and inner
  whitespace in name and category; a 3,000-character URL; a keyword at exactly the minimum
  length; a specific rule before a generic one (negative control for the unreachable-rule
  check); 5,000 flat entries under the default budget; identifier-shaped text in a description
  and inside a path in a description (asserted *not* treated as identifiers); null and empty
  descriptions against the keyword strategy; a 2 MB description; soft hyphen inside a keyword
  match (ordinal, not culture).
- *Malformed* (`MapValidationTests`, `MapMalformedTests`) — nineteen identifier shapes including
  `t1234`, `T123`, `T1234.1`, padded, Arabic-Indic and full-width digits, each asserting the
  entry index and offending text are in the message; orphan sub-technique naming both
  identifiers; exact duplicate and case-only duplicate; missing / empty / whitespace / padded
  name, category and URL (15 theory cases) each naming entry and field; nine bad URLs including
  a bare Unix path and `C:\` path (both of which `Uri.TryCreate` accepts as absolute `file:`
  URIs), `ftp:`, `mailto:`, `javascript:` and hostless `https://`; unknown field at root, entry
  and rule (including `Id` vs `id`); duplicate JSON keys at root and entry; wrong JSON types
  including `null`; root that is an array; `entries` missing or not an array; rule pointing at
  an absent entry, malformed rule id, rule missing either field, keyword under the minimum,
  padded keyword, five canary-matching keywords, repeated and subsumed keywords; over-ceiling
  name / category / URL / keyword. At the byte level: not JSON, empty, whitespace-only,
  truncated (position within the cut), BOM-prefixed syntax error with file-relative position,
  trailing garbage, second root value, comments, trailing comma, invalid UTF-8 inside a string,
  nesting inside the budget but outside the schema (`Failed`, not `Incomplete`), every
  single-byte mutation of the standard map under a seeded RNG (no throw; most `Failed`, some
  `Ok`), and every prefix truncation (all `Failed`).
- *Named strictness tests* (`StrictnessTests`) — explicit identifier absent from the map is
  unresolved with that reason and one attempt only, despite a mapped check and a matching rule
  on the same finding; malformed explicit identifier likewise; check identifier absent from the
  map is unresolved with two attempts and no keyword attempt; the "map older than checks" case
  surfaces in the rollup by reason; an unresolvable finding appears in both `Resolutions` and
  `Rollup.Unresolved` and is in no category; the reason names each strategy's refusal; empty
  map gives three distinct coherent reasons; a reflection test pins that `FindingResolution`
  exposes no `Identifier` or `Entry` member.
- *Keyword rules* — first match wins; all six permutations of three mutually matching rules
  each yield position 0; order stable across repeated loads; case-insensitive, substring,
  ordinal.
- *Budget canaries* — one loud test and one quiet negative control per dimension: bytes (over by
  one / exactly at), depth (40 levels / the standard map needs exactly three, so depth 3 loads
  and depth 2 is `Incomplete`), entry count and rule count (`Incomplete` with **no partial
  map**), findings count (`Incomplete` carrying only the findings processed), zero deadline on
  the loader with and without rules, and on the resolver.
- *Determinism* — full run text byte-identical across two runs; eight seeded shuffles of a
  mixed ten-finding run give byte-identical identifier sets and category counts; a map written
  in reverse entry order renders identically; the per-finding list follows input order.

**Every assertion was shown to fail when the code it guards is reverted**, by mutation, with a
script that applied one change at a time, ran the suite and restored the file. Twenty-nine
mutations: each of the three "does not fall through" returns removed; keyword chain reversed;
keyword strategy misreported as check mapping; resolver `MaxMatches` and deadline checks
removed; unresolved findings dropped from the rollup; parent identifier roll-up and parent
category roll-up removed; category sort made culture-sensitive; orphan check, unknown-field
check, canary check, unreachable-rule check, byte budget, depth budget, entry-count budget,
loader deadline, URL scheme check, padding check, BOM skip, UTF-8 check and field-length ceiling
each removed; `char.IsDigit` substituted for the ASCII check; identifiers trimmed; lower-case
`t` accepted; keyword match made case-sensitive; and `TechniqueResult.Incomplete` collapsed into
`Ok` at the factory. **All twenty-nine were killed, each by the specific test written for it.**
One finding came out of the run and is fixed rather than noted: removing the deadline check in
the *entries* loop originally survived, because the identical check in the *rules* loop fired
on the standard fixture. `AZeroDeadlineStopsTheLoaderEvenWhenTheMapHasNoRules` now isolates
the first check.

Two things about the mutation run worth passing on. First, `if (false)` as a mutation does not
compile under `TreatWarningsAsErrors` (CS0162, unreachable code) and reports as a build failure
that a careless script reads as "survived"; a runtime-false condition is needed. Second, the
culture-sensitive-sort mutation used `InvariantCultureIgnoreCase` and was killed by
`CategoriesAreSortedOrdinally` (`B`, `a`, `b`) — but note Q1's warning that
`InvariantGlobalization` makes plain `InvariantCulture` comparisons ordinal, so a mutation to
*that* would survive for the wrong reason. The test's `B/a/b` fixture kills the case-folding
variant, which is the realistic "improvement" someone would make.

**Judgement calls.**

1. **The map file is JSON, shaped `{"entries":[...],"rules":[...]}`.** The reference says "a
   data file" and the brief's malformed-input list says "not JSON at all", so JSON. `entries` is
   required (an empty array is the valid empty map, per the brief); `rules` is optional and
   absent means no rules (a map with no curated rules is a legitimate stage, not an error). No
   version or schema field, because none was specified and any field I invented would be an
   "unknown field" to a file written against the real schema.
2. **Keyword rules live in the map file** (open question 2's stated assumption), as
   `{"keyword": "...", "id": "T1234"}`, matched as an ordinal case-insensitive substring of the
   description. Substring rather than whole-word because descriptions contain paths and command
   lines where token boundaries are unreliable; case-insensitive because the same rule should
   match `PowerShell` and `powershell`; ordinal so the outcome cannot vary with a culture table.
3. **Nothing is trimmed, anywhere.** The brief asked for a decision on surrounding whitespace in
   identifiers and a test either way. I reject it — in the map (`Failed` naming the entry and
   saying "surrounding whitespace; identifiers are not trimmed"), in an explicit identifier on a
   finding (unresolved, `ExplicitIdentifierMalformed`), and in name, category, URL and keyword.
   The reason is the one the brief gives for case: a near-miss that loads leniently then fails
   to match the same identifier written correctly elsewhere, and a category with a trailing
   space becomes a phantom category with one member. Pinned by
   `SurroundingWhitespaceIsNamedAsSuch`, `AnExplicitIdentifierIsNotTrimmedOrRepaired` and the
   padded rows of `AMissingEmptyOrPaddedFieldIsFailedNamingEntryAndField`.
4. **Digits are the ten ASCII digits only.** `char.IsDigit` accepts Arabic-Indic and full-width
   digits, which would let `T١٢٣٤` load and then never match `T1234`. Pinned by two theory rows;
   the `char.IsDigit` mutation was killed.
5. **A reference URL must be `http` or `https` with a host.** The reference says "well-formed
   absolute URL", but on Linux `Uri.TryCreate("/x", UriKind.Absolute)` and
   `Uri.TryCreate("C:\\x", ...)` both succeed as `file:` URIs, so "absolute" alone would accept
   a path typed into the URL column. `javascript:` and `mailto:` are also absolute. If the
   provider's map carries a non-http reference scheme, this is one condition in
   `TechniqueMapLoader.CheckUrl`. String validation only; nothing is fetched.
6. **The URL is kept as the curator wrote it, not as a `Uri`.** `Uri` lower-cases the host and
   may add a trailing slash; a report should show the reference exactly as curated.
7. **Keyword rule specificity (open question 3): minimum four characters, and no rule may match
   any of eight fixed generic canary descriptions** (`TechniqueMapLoader.KeywordRuleCanaries`,
   public so the provider can review them). The canaries are built from the common nouns of a
   finding — file, process, value, path, registry key, service, user, system — so `file` or
   `registry key` is rejected while `scheduled task`, `powershell` and `run key` load. The
   constants are estimates with nothing behind them but the brief's reasoning; see *Could not
   verify*.
8. **A later rule whose keyword contains an earlier rule's keyword is rejected as unreachable.**
   Any description the later rule matches has already matched the earlier one, so under
   first-match-wins the later rule can never fire. Rejecting it at load makes rule order a
   reviewable fact rather than a silent one. Same keyword twice is the degenerate case. The
   reverse order — specific first, generic second — loads.
9. **Duplicate detection is case-insensitive even though the format check already rejects lower
   case.** Belt and braces: the reference names case-only duplicates as a rule in their own
   right, and if the format check is ever relaxed the duplicate rule must not silently go with it.
10. **Unknown fields are matched case-sensitively** — `Id` is an unknown field, not a spelling of
    `id` — and **duplicate JSON keys are `Failed`** even though `JsonDocument` would accept them
    (last wins), because a file with two `name` fields on one entry was written by a tool this
    library does not know.
11. **One identifier per finding and per check** (open question 1's stated assumption). Two
    check mappings for one check that name the same identifier collapse to one; two that
    disagree are a `Failed` at `TechniqueResolver.Create` naming the check and saying "one
    identifier per check", so the future multi-identifier shape announces itself rather than
    picking one silently. `Finding` and `CheckMapping` document the extension.
12. **A malformed identifier in a check mapping fails resolver construction; an identifier
    absent from the map does not.** The former is a programming error in a check; the latter is
    the map being older than the checks (open question 5), which must reach the report as
    per-finding `CheckIdentifierAbsentFromMap` so the census shows what the map is missing.
13. **A finding's explicit identifier is examined only when non-null.** `null` means "the check
    attached nothing" and lets the chain continue; any non-null string — including empty — is a
    deliberate assertion and is either resolved or unresolved with an explicit-identifier
    reason. `CheckId` is the opposite: `null` and empty both mean "names no check", because an
    empty check id is not a plausible deliberate value.
14. **`UnresolvedReason` is an enum with four values**, and `NoStrategyProduced` carries the
    per-strategy refusals in `Attempts` so "check declares no mapping" and "no description" and
    "no rules loaded" and "3 rules, none matched" stay distinguishable without string parsing.
15. **Category roll-up counts the parent's category too**, so a sub-technique finding whose parent
    shares its category counts that category twice in the rolled-up member. This is what "the
    parent technique was observed" means for categories, it is stated in the type remarks, and
    it is pinned by `CategoryRollUpCountsASharedCategoryTwiceForOneSubTechniqueFinding` so it
    cannot drift silently either way. The direct member is the one that sums.
16. **A budget-stopped map load returns no partial map.** A map that resolves the first 5,000
    identifiers and not the rest would look whole to a resolver. A budget-stopped *run* does
    return the findings processed so far (with a rollup over them), because a partial list of
    per-finding resolutions is honest as long as the state says `Incomplete`.
17. **Nesting deeper than `MaxNestingDepth` is `Incomplete`; nesting inside the budget but
    outside the schema is `Failed`.** The first is a budget the reader did not finish under; the
    second is a file the reader read completely and found wrong. Depth counts containers open at
    once, root included, matching `Utf8JsonReader.MaxDepth`'s meaning — the standard map needs
    exactly three. Note the reader's `CurrentDepth` reports a Start token at its parent's depth;
    the loader corrects for that, with a comment.
18. **A UTF-8 BOM is skipped; invalid UTF-8 anywhere is `Failed` with the offset.** The reader
    accepts invalid UTF-8 inside a string and throws only when the string is materialised, so
    the loader validates the whole input first with `Rune.DecodeFromUtf8`.
19. **The deadline is a `Stopwatch` checked once per entry, rule and finding.** `TimeSpan.Zero`
    trips deterministically on the first item, which is what the canaries use. No `DateTime.Now`
    appears in any result.
20. **Descriptions are not budgeted.** A 2 MB description is searched in linear time and the test
    shows it; there is no output expansion to cap. If a caller needs a ceiling, it belongs on the
    finding producer.

**Could not verify.**

- **The real map file's schema.** Every fixture encodes my field names (`entries`, `rules`,
  `id`, `name`, `category`, `url`, `keyword`). The strictness rule means the first real file
  will fail on its first unknown field and name it — which is the reconciliation exercise
  `reference/07.5_unverifiable.md` describes for §7.3, and it applies here identically.
  Settled by: `TechniqueMapLoader.Load(File.ReadAllBytes("<the provider's map>"))` from a
  caller, reading the `Reason`.
- **Whether the provider's category vocabulary contains only http(s) reference URLs**
  (judgement call 5) and **whether any real identifier falls outside `T####` / `T####.###`**.
  Same command.
- **The keyword-rule thresholds** (judgement call 7): the four-character minimum and the eight
  canaries are estimates. Settled by loading the provider's real rule set and seeing which rules
  the canaries reject, then by resolving a real run and checking `CountsByStrategy` and the
  identifier distribution for a rule that captured a disproportionate share.
- **Whether categories should be validated against a fixed list** (open question 4). Not done;
  a typo currently creates a phantom category with one member, which the direct category counts
  will show as a count of one.

**Shared types.** Declared `ScanBudget` (exact shape from §3, all four members bind here),
`TechniqueResultState` (`Ok` / `Incomplete` / `Failed`) and the generic `TechniqueResult<T>`
carrying `Value`, `Reason` and `Position`, copied from `Scythe.Time` with only the rename.
`Incomplete` carries a partial `Value` for the resolver (the findings processed) and `null` for
the loader (judgement call 16) — same semantics as Q1's partial reading.

**My vote: shared `ScanBudget`, yes; shared result type, weak yes.** The budget is a pure record
and this project's copy is character-for-character Q1's with a different remarks block. The
result type is also identical in shape, and I found no member I wanted that it lacked;
`Position` is populated here for JSON syntax failures and null for semantic ones, which fits
its documented meaning. Two projects agreeing exactly is mild evidence the generic
`Result<T>` would hold across the package.

**Dependencies taken.** None. `Scythe.Techniques` references nothing but the BCL
(`System.Text.Json` for parsing, `System.Text.Rune` for UTF-8 validation); the test project
references xUnit at the three pinned versions and the library. K4 is not an edge in the README
graph in either direction; K3's record model is consumed by projection onto `Finding`, not by
reference, as the brief's "Out" section says.

**Wanted to change outside my project.**

1. **`reference/07.4_technique_map.md` should state the map file's concrete schema** — the field
   names and which are required — once a real file exists, and record the keyword-rule matching
   semantics (substring, case-insensitive, ordinal) and the specificity constants. Every one of
   those is a judgement call above that the next reader will have to rediscover from code.
2. **`reference/07.4` says "a URL that is not a well-formed absolute URL" and should say "an
   http or https URL with a host"**, or whatever the provider's map actually carries, because
   `Uri.TryCreate(..., UriKind.Absolute)` on Linux accepts bare paths (judgement call 5).
3. **`tasks/00_INTEGRATION.md` / `reference/00_shared.md` could warn that `if (false)` is not a
   usable mutation** under `TreatWarningsAsErrors` — CS0162 turns it into a build failure that
   a script reads as a surviving mutant. A one-line note next to the canary rule would save the
   next author the half hour.
4. **The brief's "identifier strings with surrounding whitespace (decide whether to trim)"
   could be settled package-wide as "never trim"**, since every other strictness rule in the
   brief points that way and a per-project decision invites two libraries to disagree.

---

## K2 — Scoring and rollup

*2026-09-02.*

**Status.** Complete.

**What was built.** `Scythe.Scoring` turns the scoring projection of a run record into a
`RunRollup`: severity counts (all five levels, zero counts included, highest first), per-check
counts (every inventory check, zero counts included, by id ordinally), a `CoverageStatement`
(three separate status totals, every distinct inconclusive and skipped reason with the checks that
gave it, and a one-sentence statement that never contains a percentage) and a `CleanlinessScore`
(0–100, higher is cleaner, with the `ScoreContribution` list that sums exactly to it and the
`ScoreWeights.Version` that produced it). One entry point: `Rollup.Compute(RollupInput input,
ScanBudget? budget = null)` returning `ScoringResult<RunRollup>`. All arithmetic is in the integer
domain (`long` sums, `int` points); there is no floating point anywhere on the public surface, and
a reflection test enforces that.

**Files.** All new; nothing outside these two directories was touched.

```
Scythe.Scoring/Scythe.Scoring.csproj
Scythe.Scoring/ScanBudget.cs
Scythe.Scoring/ScoringResult.cs
Scythe.Scoring/Severity.cs
Scythe.Scoring/CheckStatus.cs
Scythe.Scoring/RollupInput.cs
Scythe.Scoring/ScoreWeights.cs
Scythe.Scoring/SeverityCount.cs
Scythe.Scoring/CheckCount.cs
Scythe.Scoring/CoverageStatement.cs
Scythe.Scoring/ScoreContribution.cs
Scythe.Scoring/CleanlinessScore.cs
Scythe.Scoring/RunRollup.cs
Scythe.Scoring/Rollup.cs

Scythe.Scoring.Tests/Scythe.Scoring.Tests.csproj
Scythe.Scoring.Tests/AssemblyInfo.cs
Scythe.Scoring.Tests/Fixtures/RecordBuilder.cs
Scythe.Scoring.Tests/OrdinaryRollupTests.cs
Scythe.Scoring.Tests/CoverageTests.cs
Scythe.Scoring.Tests/ScoreCompositionTests.cs
Scythe.Scoring.Tests/ProhibitedMemberTests.cs
Scythe.Scoring.Tests/OrderingAndZeroCountTests.cs
Scythe.Scoring.Tests/DeterminismTests.cs
Scythe.Scoring.Tests/MalformedTests.cs
Scythe.Scoring.Tests/BudgetCanaryTests.cs
```

**Tests.** 139 tests, one file per concern. `dotnet build` and `dotnet test` on
`Scythe.Scoring.Tests/Scythe.Scoring.Tests.csproj` are green on Linux with zero warnings. (Built
and tested per project, not via `scythe-work.sln`, because the solution is the coordinator's to
edit; the command that verifies the whole is `dotnet test scythe-work.sln` once both projects are
added.)

- *Ordinary* (`OrdinaryRollupTests`, 15) — a five-check, five-finding record with every count,
  the coverage totals, the hand-worked score (`100 − (15+5+5+2+1) = 72`, three of four attempted
  completed, `floor(72 × 3/4) = 54`), the contribution list in order, the
  sum-to-value identity, the weights version, a null budget, and findings from an inconclusive
  check still being counted.
- *Awkward but valid* (`CoverageTests`, `ScoreCompositionTests`, `OrderingAndZeroCountTests`) —
  the brief's named coverage test (a third inconclusive, no findings → 66, every distinct reason
  reported); the three totals independent and summing to the inventory; skipped checks reported
  but not depressing the score; one inconclusive among a thousand still below the maximum; reasons
  differing only in whitespace collapsed to one; both range ends reachable, by findings and by
  coverage separately; exactly 100 points of findings versus 101 (saturation contribution appears
  only past the range); the separability test (findings-only 50 and coverage-only 50 told apart
  from the contributions alone); rounding always downwards; ordinal ordering of check ids
  (`"1numeric" < "B" < "Z" < "_under" < "a" < "check10" < "check2"`), reasons and ids within a
  reason; zero-count entries for every severity and every check; a null title.
- *Malformed* (`MalformedTests`, 27 cases) — null input, null lists, null entries, blank ids on
  checks and findings, blank producing-check id, the orphan finding (Failed naming the finding, the
  check and the position), case-mismatched check id treated as an orphan, duplicate finding id,
  duplicate check id (both naming both positions), undefined `Severity` and `CheckStatus` values
  including `int.MinValue`/`int.MaxValue`, first-defect-wins, and a nine-record sweep asserting
  nothing throws.
- *Prohibited members* (`ProhibitedMemberTests`, 19) — the brief's named reflection test over
  every public type and member in the assembly, matched on whole PascalCase words; a second test
  confining the word "Score" to the four score-side names; a third refusing any `float` /
  `double` / `decimal` / `Half` member anywhere on the surface (the unnamed near-miss); and
  negative controls proving the word splitter catches `PassRate`, `CompletionRate`,
  `HealthIndex`, `CoverageRatio`… and does not trip on `Separate`, `Generated`, `Operate`.
- *Determinism* (`DeterminismTests`, 11) — five seeded shuffles of a nine-check, eight-finding
  record serialise byte-identically to the unshuffled one; a negative control proves the shuffle
  changes the input order; Incomplete and Failed results are likewise stable; no timestamp appears
  in the output.
- *Budget canaries* (`BudgetCanaryTests`, 8) — past `MaxMatches` is Incomplete with **no** value
  and the budget named; exactly at the limit is Ok; checks count as well as findings; the default
  budget refuses 10 001 entries; a zero budget; 50 000 findings counted exactly with a 969 900-point
  saturation contribution and no overflow; 100 000 checks with one inconclusive scaled to 99.

**Every assertion was shown to fail when the code it guards is reverted**, by mutation rather
than by inspection. Twenty-three mutations were applied one at a time to the library and the
suite run after each (script: `k2_mutate.py` in the session scratchpad, restores automatically):
coverage scaling dropped (15 tests red), `PassRate` added to `CoverageStatement` (1 — the
reflection test, with its explanatory message), `Score` added to `CoverageStatement` (1),
a `double` member added to `CoverageStatement` (1), Inconclusive folded into Completed (18),
orphan check removed (3), duplicate-finding check removed (1), duplicate-check check removed (3),
budget check removed (4), Incomplete collapsed into Ok at the end of `Compute` (9), check
ordering made case-insensitive (1), zero-count severities dropped (5), zero-count checks dropped
(33), Informational weight set to zero (8), findings floor removed (4), nothing-attempted branch
removed (4), Skipped made to depress the score (4), reason normalisation removed (5), coverage
rounding made upwards (8), severity counts made ascending (4), baseline lowered to 99 (15),
blank-finding-id check removed (3), undefined-severity check removed (3). **All twenty-three were
killed.** One thing learned doing it: a guard mutated to `if (false)` does not compile under
`TreatWarningsAsErrors` (CS0162), so guard mutations need a runtime-false condition such as
`if (input.Checks.Count < 0)`. Anyone repeating the exercise elsewhere in the package will hit
the same thing.

**Judgement calls.**

1. **The input is a projection, not a copy of `RunRecord`.** `reference/07_records.md` says the
   record is defined once in `Scythe.Reporting` and no other project may declare its own copy;
   the README graph lists no K3→K2 edge and `Scythe.Reporting` did not exist when this started.
   `tasks/00_INTEGRATION.md` says: take the data as a parameter, never stub. So `RollupInput` /
   `CheckInput` / `FindingInput` carry only what the arithmetic reads — ids, title, status,
   reason, severity, producing check — and none of the run's identity, times, mode,
   descriptions, targets or properties. A caller holding a `RunRecord` maps field for field. If
   the combining pass decides the edge should exist, the adapter is a dozen lines and the input
   types can be deleted; I would not object.
2. **`Severity` has five members in this order: Informational, Low, Medium, High, Critical.**
   `07_records.md` names the enum and says its order is meaningful but never lists its members.
   The only place in the package that enumerates them is the severity mapping table in
   `reference/15.1_interchange.md` §15.1.5, so that is the source. **If `Scythe.Reporting`
   declares a different set or order, the two must be reconciled before any score is trusted** —
   see *Could not verify* and *Wanted to change*.
3. **Composition is multiplicative, in integers:** `score = floor((100 − min(Σ count×weight, 100))
   × (attempted − inconclusive) / attempted)`, where `attempted = Completed + Inconclusive`. The
   brief says "a coverage factor that caps the achievable maximum in proportion to the
   inconclusive share"; a factor that scales what findings leave is the literal reading and gives
   the property the brief wants (a third inconclusive → at most 66 whatever the findings). The
   alternative — `min(afterFindings, cap)` — leaves the coverage contribution at zero whenever
   findings already took more than the cap, which makes "how much did coverage cost" a less useful
   number. Either is one expression in `Rollup.ComposeScore`.
4. **Skipped checks are outside the denominator of the coverage factor.** Open question 3 says
   Skipped is expected and Inconclusive is a gap; putting Skipped in `attempted` would let a run
   with many skipped checks dilute its inconclusive share, which is the more flattering and
   therefore the wrong direction. Skipped is still in every *count* and in `InventorySize`
   (rule 2: never dropped from a denominator that is reported). Stated in `CoverageStatement`'s
   documentation so a reader can challenge it.
5. **Rounding is always downwards** and any inconclusive check keeps the score below 100 (one in
   a hundred thousand → 99). Rounding up would flatter coverage, which is the one direction this
   library must never err in. Pinned by `RoundingIsAlwaysDownwards`.
6. **Weights: 1 / 2 / 5 / 15 / 40, coverage weight 100 hundredths, version `"1"`.** Estimates,
   per `reference/07.5_unverifiable.md`; strictly increasing, none zero, all in `ScoreWeights`,
   not caller-supplied. The findings deduction is linear and saturates at the floor, so a hundred
   Informational findings score 0 — arguably harsh, but every alternative (diminishing returns,
   per-check caps) hides findings in a way the contributions could not explain in one line. When
   real records exist the constants change and `Version` bumps.
7. **A missing `StatusReason` on an Inconclusive or Skipped check is `Incomplete` with the full
   partial rollup, not `Failed` and not `Ok`.** Failed would throw away every number over one
   missing string; Ok would present a coverage statement that cannot say why part of the host
   went unexamined — and the brief says the reason strings are the operative content. The
   missing ids are listed in `InconclusiveWithoutReason` / `SkippedWithoutReason` and in the
   result's reason. Whitespace-only counts as missing; surrounding whitespace is trimmed so
   `"locked"` and `"locked "` are one reason. Skipped is held to the same rule as Inconclusive
   for consistency with the model ("required when Inconclusive or Skipped"), though it never
   affects the score.
8. **A record in which no check was attempted (empty inventory, or every check Skipped) is
   `Incomplete` with a partial rollup whose score is 0.** An empty run reading as 100 is the exact
   outcome the brief calls the worst this product can produce; 0 with a coverage contribution of
   −100 saying "no check was attempted" cannot be mistaken for a clean machine. A record whose
   checks were all attempted but all Inconclusive is `Ok` with score 0 — that is a finished answer
   about a run that examined nothing.
9. **Orphan findings, duplicate finding ids, duplicate check ids, blank ids and undefined enum
   values are all `Failed`,** with the offender named and `Position` set to its index in the list
   the message names. Each is a record-construction bug; counting around any of them hides it
   behind a plausible number. The inventory is validated before the findings, so the first
   defect reported is the earliest in that order.
10. **Ids are compared exactly and ordinally.** `"Autoruns"` is not `"autoruns"`; a finding naming
    the latter when the inventory has the former is an orphan. Case-folding would be a guess
    about the producer.
11. **A null `Title` is carried as `""`, not refused.** It is rendering payload, not arithmetic,
    and refusing a whole rollup over it would be disproportionate; the result carries no null in
    a non-nullable slot.
12. **Only `MaxMatches` binds.** It caps checks plus findings, and when exceeded the result is
    `Incomplete` with **no** value: a rollup over the first N findings is precisely the lie the
    library exists to prevent. `Deadline` is not consulted — a pure function cannot honour a
    wall clock without ceasing to be deterministic — and `MaxInputBytes` / `MaxNestingDepth` have
    nothing to bind. All four are carried so one budget serves the whole package.
13. **The score type is `CleanlinessScore`,** named for its direction (more cleanliness is
    cleaner), with `Minimum = 0` and `Maximum = 100` as constants and the composition in its
    documentation. `HealthScore` and `Grade` were the obvious names and are both on the forbidden
    list for good reason.
14. **The prohibited-member test matches whole PascalCase words, not substrings,** so `Separate`
    does not trip `Rate`. The list is `Pass*`, `Rate(s)`, `Percent*`, `Pct`, `Ratio(s)`,
    `Fraction`, `Proportion`, `Share`, `Quotient`, `Health*`, `Grade*`, `Index` everywhere, and
    `Score(s|d)` everywhere except `CleanlinessScore`, `ScoreContribution`, `ScoreWeights` and
    `RunRollup.Score`. A third test refuses any floating-point or decimal public member — the
    unnamed near-miss. The failure message states the reasoning, as the brief asks.
15. **Coverage contribution is always present, even at zero effect,** so a reader never has to
    infer "coverage cost nothing" from an absence.

**Could not verify.**

- **Whether `Scythe.Reporting`'s `Severity` has these five members in this order** (judgement
  call 2). Settled by: `grep -n "enum Severity" -A8 Scythe.Reporting/*.cs` once K3 lands, and if
  it differs, `Scythe.Scoring/Severity.cs` and `ScoreWeights.WeightFor` change together with a
  `Version` bump.
- **The weights and the coverage factor against real records.** `reference/07.5_unverifiable.md`
  names the coverage weighting as an estimate. Settled by: run the host's engine on a handful of
  real client workstations, export the records, map them to `RollupInput`, and look at whether
  the distribution of scores separates machines a technician would separate. The constants live
  in `ScoreWeights`; change them there and bump `Version`.
- **Whether the mapping from a real `RunRecord` to `RollupInput` is lossless for scoring.**
  Settled by: one real record loaded through `Scythe.Reporting`'s strict loader and projected;
  every `CheckEntry` and `Finding` field the projection drops should be one scoring does not read.

**Shared types.** Declared `ScanBudget` (exact shape from §3), `ScoringResultState`
(`Ok` / `Incomplete` / `Failed`) and the generic `ScoringResult<T>` with `Value`, `Reason`,
`Position`, `IsOk` and the three factories, copied from `Scythe.Time` with only the rename.
`Position` here is a list index rather than a byte offset; the message says which list.

**My vote: a shared `Scythe.Common` for `ScanBudget` and for the result type, and — separately
and more urgently — the record model must not be duplicated.** `ScanBudget` is identical in every
project and only one member of it binds here. The result type is now three identical copies
(Time, Text, Scoring) differing in name only, which is weak evidence against Q1's "other tracks
will want members mine does not have". But the type duplication that actually matters in this
track is `Severity` / `CheckStatus`: I have declared both because I could not reference
`Scythe.Reporting`, and if K3's `Severity` differs from mine the score is silently wrong. That is
an argument for the K3→K2 edge, not for `Scythe.Common`.

**Dependencies taken.** None. `Scythe.Scoring` references nothing; the test project references
xUnit at the three pinned versions and the library. The README graph lists no edge into or out of
K2. The natural edge — K3 `Scythe.Reporting` → K2 for the record model — is not in the graph and
was not taken; see judgement call 1.

**Wanted to change outside my project.**

1. **`reference/07_records.md` should list the members of `Severity`,** in order. It says the
   order is meaningful to §7.2 and then does not state it; the only enumeration in the package is
   in Track U's mapping table, which K2 has no reason to read. Suggested edit: add
   `public enum Severity { Informational, Low, Medium, High, Critical }` to the record-model
   block.
2. **The README graph should carry a `K3 Reporting ──▸ K1, K2, K4, U1, U2` edge, or the record
   section should say the model is a hand-off shape.** `07_records.md` forbids other projects
   declaring the model; `00_INTEGRATION.md` forbids referencing a project that does not exist;
   the graph lists no edge. Every Track K and Track U task has to resolve that three-way tension
   alone, and the resolutions will differ. I chose a projection (judgement call 1); K1 and K4 may
   have chosen otherwise.
3. **`tasks/K2_scoring_and_rollup.md` should say what the coverage factor's denominator is.**
   "In proportion to the inconclusive share" admits attempted-only and whole-inventory readings
   with different numbers (judgement call 4). One sentence settles it.
4. **The brief's reflection-test list could name `Index`, `Fraction`, `Proportion` and `Share`**
   alongside the ones it gives; they are the near-misses a reviewer reaches for once `Rate` and
   `Percent` are refused.

---

## Coordinator note — 2026-09-02 parallel run, interrupted

*2026-09-02, written by the coordinating session.*

Ten task sessions ran in parallel and all ten were stopped by a weekly usage limit. This note
records what that left behind so no entry below is read as more complete than it is.
**`RESUME.md` in this folder is the authoritative state document** — task-by-task status, the
first compiler error in each unfinished project, and the order to pick the work back up.

**Entries owed.** `Q3` (`Scythe.Identity`), `K1` (`Scythe.Correlation`), `E3`
(`Scythe.ShellItems`) and `W1` (`Scythe.TestKit`) are **finished, green and committed, but have
no entry in this file.** Each session was killed after its code went green and before it wrote
its handoff. The judgement calls behind those four projects are not recoverable from the
sessions; whoever writes the entries will be reconstructing them by reading the code, and the
entry should say so plainly rather than presenting a reconstruction as the original reasoning.

**Five projects are unfinished and are deliberately not in `scythe-work.sln`:** `Scythe.Artifacts`
(E1), `Scythe.Hives` (E2), `Scythe.Reporting` (K3), `Scythe.FileSystem` (M1) and `Scythe.Journal`
(M2). In four of the five the library is complete and a single test file was cut off mid-write;
`RESUME.md` names the file and line for each.

**One change was made outside a task project**, which `tasks/00_INTEGRATION.md` asks to be
recorded here rather than made silently. `Scythe.TestKit/Scythe.TestKit.csproj` gained
`<IsTestProject>false</IsTestProject>`. W1 references xunit as a library for its
`[DifferentialFact]`, so `dotnet test scythe-work.sln` treated the library itself as a test
assembly and exited 1 while every test passed. With the property set the solution run exits 0.
The alternative — dropping the xunit reference — would have cost W1 the visible-skip behaviour
its brief asks for, so the property is the smaller change.

**Two findings for later sessions.** A test run taken while another session is writing can report
failures that do not exist: `Scythe.Correlation` showed 31 failures of 212 mid-run and 212/212
green immediately afterwards, so re-run before believing a failure. And `if (false)` cannot be
used for a fail-on-revert mutation check, because CS0162 under `TreatWarningsAsErrors` turns it
into a build failure that reads as a surviving test; use a runtime-false condition.
