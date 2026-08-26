# HANDOFF — fable-work-2

One entry per task. Every judgement call where the spec was ambiguous is recorded here;
that list is the most valuable part of this document. All build/test claims are for Linux,
.NET 8 (`dotnet build` / `dotnet test` on `fable-work-2.sln`), zero warnings
(`TreatWarningsAsErrors` is on globally via `Directory.Build.props`).

A reference `yara` 4.5.5 CLI was installed during development and the engine is
**differentially tested against it**: string-match offsets, full-rule verdicts, and every
ambiguous modifier corner below marked "pinned against reference" was decided by running
the real binary, not from memory. The differential tests live in
`ZeroBreach.Rules.Tests/Yara/DifferentialTests.cs` and `CorpusValidationTests.cs`
(`DifferentialVerdictTests`); they run automatically when a `yara` binary is present at
`/usr/bin/yara` or `/usr/local/bin/yara` and pass vacuously otherwise — **install yara on
CI so they bite**.

---

## A1 — YARA rule parser → AST

**What was built.** A hand-written lexer, recursive-descent parser (precedence-climbing
condition parser with the reference operator table), hex-string sub-parser, and a
cross-file structural validator. Output is a typed AST plus a full diagnostic list —
parsing recovers at rule boundaries so one broken rule does not hide the next problem.

**Files** (relative to `ZeroBreach.Rules/`):
- `Common/OperationState.cs`, `Common/ScanBudget.cs` (shared BLUEPRINT §2/§3 types)
- `Yara/Parsing/Diagnostic.cs` — severities, stable `DiagnosticCode` enum, `SourceLocation`
- `Yara/Parsing/YaraToken.cs`, `Yara/Parsing/YaraLexer.cs`
- `Yara/Parsing/HexStringParser.cs` (raw-text sub-parser for `{ ... }` bodies)
- `Yara/Parsing/Ast.cs` — all AST records
- `Yara/Parsing/YaraParser.cs`
- `Yara/Parsing/YaraValidator.cs`
Tests: `ZeroBreach.Rules.Tests/Yara/ParserTests.cs`.

**Judgement calls.**
- *Text-string escapes*: exactly `\t \n \r \" \\ \xNN`. `\r` is a superset of very old
  reference versions but present in modern ones; anything else is an
  `InvalidEscapeSequence` error, because a silently mis-unescaped pattern never matches.
- *Unreferenced strings are errors* (reference behaviour), not warnings.
- *Rule references resolve backward only* (reference behaviour): a forward reference is
  its own diagnostic (`ForwardRuleReference`) since the fix (reordering) is not obvious
  from "unknown identifier". Cycle detection (DFS) is kept as a backstop and is what a
  self-reference triggers.
- *`rule` with no `meta` at all*: **warning** (`NoMetaSection`), per the brief's open
  question. Public corpora are inconsistent; filter by code if it is too noisy.
- *Duplicate meta keys are legal* (reference allows them); duplicate tags are errors.
- *Comments win over regexes*: `//` and `/*` are always comments, so an empty regex
  literal cannot be written — matches the reference lexer's priorities.
- *Include position is not honoured*: included files' rules are inserted **before** the
  including file's rules regardless of where the `include` sits in the file, so backward
  references from includer into include resolve. Flagged: if a real corpus interleaves
  rules and includes order-sensitively, this needs revisiting.
- *`include` resolves via a caller-supplied resolver callback* (assumed per the brief's
  open question) — the library never touches the file system.
- Identifiers capped at 128 chars (reference cap); expression nesting capped at 200;
  error diagnostics capped at 500 per compile (warnings uncapped — a large corpus warns
  legitimately). All three caps produce diagnostics, not crashes.
- *Hex strings*: jumps cannot start/end a string; unbounded jumps disallowed inside
  alternations; alternation nesting capped at 16; max bounded jump 4096; `~??` rejected
  as matching nothing. YARA 4.3 `~` negation is supported.
- Modifier-combination rejections follow the reference: `nocase`×`xor`/`base64`/`base64wide`,
  `xor`×`base64`/`base64wide`, `fullword`×`base64`/`base64wide`. Note `base64 wide`,
  `base64 ascii`, `xor fullword` are **legal** (verified against the reference binary).
- `base64` strings must be ≥ 3 bytes; alphabets exactly 64 distinct chars.

**Verified fails-on-revert**: rejection tests were written red-first against the
diagnostics they assert; spot-mutations run during A2–A4 work (see A4 entry).

## A2 — YARA pattern matching engine

**What was built.** Two-tier matcher: every literal variant (modifier expansion:
encodings × xor keys × base64 permutations) goes into one of two Aho-Corasick automatons
(case-sensitive over raw bytes; case-insensitive over ASCII-folded bytes) scanned in a
single pass; hex strings and regexes compile to one shared byte-NFA executed by a
priority-ordered Pike VM (linear time, immune to catastrophic backtracking by
construction). Regexes are parsed by a hand-written parser for the YARA regex dialect —
no backtracking engine anywhere.

**Files**: `Yara/Matching/RegexAst.cs`, `RegexParser.cs`, `NfaProgram.cs` (builder +
min/max-length + first-byte-set + anchoredness analysis), `PikeVm.cs`,
`LiteralVariants.cs`, `AhoCorasick.cs`, `CompiledStringSet.cs`, `StringScanner.cs`.
Tests: `ZeroBreach.Rules.Tests/Yara/MatcherTests.cs`, `DifferentialTests.cs`.

**The one deliberate divergence from reference YARA — owner-confirmed.**
BLUEPRINT §4.3 says `#s` counts **non-overlapping** matches; reference YARA counts one
match per starting offset, overlaps included (`#a` of `"aa"` in `"aaa"` is 2 upstream,
1 here). Asked the owner mid-task; the answer was **BLUEPRINT semantics**. Implementation:
the match *list* stays reference-compatible (one match per starting offset, so `@s[i]`,
`!s[i]`, `$s at`, `$s in` behave exactly like upstream), and only the *count* `#s` is the
greedy left-to-right non-overlapping count (shortest-at-offset, which maximises the count
and is canonical/deterministic). `#s in (range)` applies the same non-overlap rule
restricted to matches starting in the range. Pinned by
`CountingAndOrderTests.MatchListKeepsOnePerStartingOffsetButCountIsNonOverlapping` and
`StringQueryEvaluationTests.CountUsesNonOverlappingSemantics`. Differential fixtures avoid
overlapping data for `#` so everything else is cross-checked.

**Semantics pinned by running the reference binary** (each has a test):
- Hex jumps are **lazy** (shortest span): `{ 41 [0-2] 42 }` on `"ABB"` matches 2 bytes.
- Regex `*` is greedy, `*?` lazy, and the reported length follows thread priority
  (`/a.*b/` on `"aXbYb"` → 5; `/a.*?b/` → 3).
- `^`/`$` anchor to buffer start/end (offset 0 / EOF), not line boundaries.
- Bare `xor` = keys 0–255 **including** 0 (the plaintext).
- `base64 wide` encodes the **plaintext** as UTF-16LE first, then base64 — it is *not*
  `base64wide` (which widens the base64 output). Permutation trimming (leading 0/2/3
  chars, one trailing char when the tail group is partial) reproduced byte-for-byte.
- `fullword` boundaries use **isalnum** (underscore is a boundary) on **raw** bytes (no
  xor decoding of neighbours); wide fullword uses the (alnum, 0x00) pair test. Regex `\b`
  differs: underscore *is* a word character there. Both pinned.
- `\s` in regexes = space, \t, \r, \n, \v, \f.
- `nocase` is ASCII-only case folding, never Unicode.

**Design decisions.**
- *Multi-pattern approach* (brief requirement): Aho-Corasick for all literal variants —
  one pass over the buffer regardless of rule count; NFA work reserved for hex/regex,
  prefiltered by first-byte sets and skipped when the remaining buffer is shorter than
  the pattern's minimum length. Chosen over per-pattern `IndexOf` loops because a corpus
  has thousands of literals, and over a DFA because construction cost and memory for
  256-symbol DFAs of arbitrary rule content is unpredictable.
- *Unbounded-jump / quadratic risk* (brief asked to say which): matching a hex/regex
  pattern is an anchored Pike-VM run per candidate offset — worst case O(n·m) per string.
  It is **budgeted**, not bounded: `BudgetDefaults.PerPatternDeadline` (150 ms) per string,
  checked every 1024 candidate offsets, yielding per-string `Incomplete` with the offset
  reached. Additionally *provable* pathology is rejected at compile time (below).
- *Compile-time rejections* (BLUEPRINT §3): nested unbounded quantifiers (`(a+)+b` —
  the canary), counted repetitions > 4096, NFA programs > 30k instructions, hex strings
  with no constraining byte at all (`{ ?? ?? }` or only negations — note the reference
  *accepts* these with a "slow scan" warning; BLUEPRINT explicitly sanctions rejection,
  so this is a deliberate, documented divergence), and any pattern that can match empty.
- Matching runs under the whole-scan deadline too; `MaxMatches` and `MaxInputBytes` are
  enforced with reasons. All limits are named constants.
- Wide regexes are compiled by interleaving `0x00` byte instructions; `\b`/`^`/`$`
  assertions in wide programs test raw byte positions (encoded space) — corner noted, no
  reference probe was run for wide-`\b` (rare in corpora).
- `\xNN` escapes stay exact bytes even under `nocase` (the author named a byte value).
  Not probed against the reference — flagged as a possible divergence corner.

## A3 — YARA condition evaluator

**What was built.** Tri-state evaluator over the AST: `True/False/Incomplete` with a
distinct in-band `undefined` value (reference semantics). Every operator from BLUEPRINT
§4.2, `for`/`of` in all forms, integer readers, rule references.

**Files**: `Yara/Evaluation/YaraValue.cs`, `EvaluationContext.cs`, `ConditionEvaluator.cs`.
Tests: `ZeroBreach.Rules.Tests/Yara/EvaluatorTests.cs`.

**The load-bearing rule — incompleteness never becomes a confident answer.**
`undefined` (out-of-range read, missing index, overflow, division by zero) is *semantic*
absence: false in boolean context, exactly like the reference (`not uint16(100) == 0`
does not fire on a 3-byte file — pinned against the binary). `Incomplete` (a budget died
somewhere) is different: it propagates through Kleene logic — `false and incomplete` is
false (decided), `true and incomplete` is Incomplete, `incomplete or true` is True, and an
incomplete left operand does **not** short-circuit: the right side is evaluated because a
false right side still decides a conjunction. Quantifiers count incomplete items honestly:
`N of` is True when definite-trues ≥ N, False when trues+incompletes < N, else Incomplete.
All pinned in `IncompletenessPropagationTests` with hand-built incomplete match sets, and
shown to fail when the combiner is mutated to collapse Incomplete→False.

**Judgement calls.**
- A string with matches found but an unfinished scan is **confidently true** (`$a`); its
  **count is not** (`#a` → Incomplete — a partial count is a lower bound and comparing it
  would launder the truncation). `@a[i]`/`!a[i]` within the found matches are trustworthy;
  past them, Incomplete when the scan was cut, undefined when it completed.
- *Inverted ranges* (`$a in (5..1)`, `for i in (5..1)`): the reference raises a per-rule
  scan **error**. This engine reports the rule **Incomplete** with the reason — the honest
  equivalent of "this rule got no answer" in a result model without per-rule errors.
- *Percent quantifier*: required count is `ceil(p·n/100)` — pinned against the reference
  (33% of 3 needs 1, 50% of 3 needs 2).
- *Loops are capped* at `ConditionEvaluator.MaxLoopIterations` (100 000) → Incomplete
  with reason (evaluator-level budget canary in the tests), plus the scan deadline is
  checked inside loops.
- Shifts: negative count → undefined; count ≥ 64 → 0 (reference behaviour). Arithmetic
  overflow, `/0`, `%0`, `long.MinValue` edge cases → undefined.
- `entrypoint` is undefined unless the host supplies it (`ScanBytes(..., entrypoint:)`) —
  computing it needs PE knowledge that lives in B1, and wiring B1→A3 was out of scope by
  the integration rules; flagged below.
- `global` is scoped to the **source file** (brief's recommended assumption): a failing
  global suppresses that file's rules only — pinned by
  `GlobalSuppressionIsScopedToItsSourceFile`. An *incomplete* global makes every
  non-false rule of its file Incomplete ("the gate is unresolved"), which is a designed
  behaviour with no reference equivalent.
- Condition-level `matches` regexes are compiled through the same NFA engine (no
  backtracking); a failure to compile evaluates as undefined (A4 validates them at
  compile time in practice via string compilation of the same dialect).

## A4 — Scan API, resource guards, corpus validation

**What was built.** `YaraCompiler.Compile(sources, includeResolver)` →
`CompileResult{State, Diagnostics, Rules}`; `new YaraScanner(options).ScanBytes(compiled,
data, budget, entrypoint)` → `ScanResult{State, Reason, Matches, IncompleteRules}`.
Compilation happens once on a dedicated 64 MiB-stack thread (hostile-input recursion can
never take down the host process); the compiled set is immutable and shared freely across
threads; scans allocate per-call state only.

**Files**: `Yara/CompiledRuleSet.cs`, `Yara/YaraCompiler.cs`, `Yara/YaraScanner.cs`.
Tests: `ZeroBreach.Rules.Tests/Yara/ScannerApiTests.cs`, `CorpusValidationTests.cs`.

**Guarantees, each with a test:**
- Failed compile ⇒ `Rules == null`. A malformed file can never become a rule set that
  silently matches nothing.
- `import` of an unimplemented module ⇒ compile is **Incomplete** naming the modules;
  dependent rules are excluded and every scan reports them in `IncompleteRules`; rules
  *referencing* an excluded rule become Incomplete transitively. Never a silent skip.
  (No modules are implemented; `pe` etc. all take this path.)
- Budget exhaustion ⇒ scan `Incomplete` **naming the unfinished rules** with reasons;
  a slow rule is isolated (per-string 150 ms budgets) and fast rules still report.
- Concurrent scans over one compiled set produce identical, deterministic results
  (asserted with Parallel.For over mixed buffers).
- Caps: 50 000 rules, 2 000 000 expanded literal patterns per set (xor × 256 is visible
  via `CompiledRuleSet.LiteralPatternCount`); include depth 16; include duplicates/cycles
  are errors.
- Match cap / input-size cap / whole-scan deadline all yield Incomplete with reasons.

**The brief's open question — disabling budget-blown rules.** Implemented behind
`YaraScannerOptions(DisableRulesExceedingBudget: true)`, default **off**. When on, a rule
whose patterns blow the per-pattern budget is remembered (per scanner instance, per
compiled set) and skipped on later scans — reported Incomplete with reason "disabled…",
its strings excluded from the NFA pass. Recommendation: **on** for bulk sweeps over
thousands of files (protects throughput; the rule is still visibly Incomplete on every
file, so nothing is silent), **off** when per-file results must be independent of scan
order. Tested both ways.

**Corpus validation.** `CorpusValidationTests` compiles a **synthetic** corpus (15 rules
written in the styles public rule sets use: meta-heavy family rules, MZ-gated packer
checks, xor/base64 hunting, hex alternation shellcode idioms, count/offset conditions,
private-rule chaining) and scans seven synthetic buffers with planted artifacts,
asserting exact verdicts and determinism, then writes `CORPUS_REPORT.md` (rule counts,
diagnostics by kind, compile time, throughput). `DifferentialVerdictTests` additionally
runs the **same corpus and buffers through the reference `yara` binary and asserts the
fired-rule sets are identical** — that ran green against yara 4.5.5 here.

This corpus is synthetic. **The owner's first job on merge** is validating against real
public rule sets. Exact command (on a machine with the repos cloned):
```
git clone --depth 1 https://github.com/Neo23x0/signature-base
dotnet test ZeroBreach.Rules.Tests --filter FullyQualifiedName~Corpus \
  -e ZB_EXTERNAL_CORPUS_DIR=$PWD/signature-base/yara
```
(the env-var hook is *not yet implemented* — either add a corpus-directory test reading
`ZB_EXTERNAL_CORPUS_DIR`, or simpler: run a small console harness that calls
`YaraCompiler.Compile` over every `.yar` in the directory and reports the
compiled/diagnostic/unsupported-module counts. The API is two calls; the harness is ~30
lines. Expect module-using rules (`pe`, `math`, `elf`) to be reported Incomplete — that
is by design — and expect a tail of exotic 4.x constructs (e.g. `of them at`, dictionary
iterators) to fail loudly at parse; the diagnostics will name them precisely.)

**Known unimplemented constructs** (fail loudly at compile, never silently): YARA modules
(`pe`, `math`, `hash`, …), dictionary/array `for` iterators over module data,
`N of them at <offset>` (4.3+), `defined`-less module edge cases. `entrypoint` evaluates
undefined unless the host passes it.

**Fail-on-revert evidence (A1–A4).** Beyond red-first assertion development, targeted
mutations were run and observed to fail the named tests, then reverted:
1. non-overlap counting guard removed (`if (m.Offset >= nextFree)` → `if (true)`) ⇒
   `CountUsesNonOverlappingSemantics`, `MatchListKeepsOnePerStartingOffset…` fail;
2. Kleene combiner collapsed Incomplete→False in `and`/`or` ⇒ three
   `IncompletenessPropagationTests` fail;
3. (during development) fullword underscore predicate ⇒ caught live by the differential
   suite against the reference binary — the fix and its pin are
   `FullwordRequiresNonWordNeighbours` + the `"word" fullword` differential fixture.
Not every one of the ~300 assertions was individually mutation-verified; the ones above
cover the highest-stakes guards (count semantics, honesty of Incomplete, boundary
semantics). Assertion-by-assertion mutation of the whole suite is the gap, and a
`dotnet stryker` run is the way to close it if the owner wants it closed.

**Wanted outside my scope**: (1) the host should pass `entrypoint` from its PE parser
(B1) when scanning PE files; (2) CI should install the `yara` package so the
differential suites run; (3) a shared `ZeroBreach.Core` for the BLUEPRINT §2/§3 types
instead of one copy per project — the integration rules forbade a new shared project, so
each project defines its own.

---

---

## A5 — Sigma rule engine

**Status: complete.** `dotnet build fable-work-2.sln`: 13 projects, 0 errors, 0 warnings.
`dotnet test ZeroBreach.Rules.Tests`: **429/429 green** (307 pre-existing YARA + 122 new
Sigma), zero warnings, on Linux/.NET 8. Reference `yara` 4.5.5 was present at
`/usr/bin/yara` during the run, so the YARA differential suites were live, not vacuous.
Finishing A5 also resolved the build break that had been blocking `ZeroBreach.Rules`
(`CompiledSigmaRule` was referenced by the half-finished `SigmaTypes.cs` but not defined).

### What was built

A Sigma detection-rule engine per `tasks/A5_sigma.md` / `BLUEPRINT.md` §5: compile one
Sigma rule (YAML text) to `CompiledSigmaRule`, evaluate it against
`IReadOnlyDictionary<string, object?>` event records under a `ScanBudget`, with tri-state
results (`Ok` / `Incomplete` / `Failed`).

- **YAML layer** (inherited from the pre-reboot agent, kept): minimal block/flow parser
  for the Sigma subset; anchors, aliases, tags, directives, multi-documents and duplicate
  mapping keys are rejected loudly with line/column.
- **Compiler** (`SigmaCompiler.Compile`): logsource, metadata, detection items (mapping,
  list-of-mappings = OR, list-of-scalars = keywords), the full modifier set required by
  the brief (`contains`, `startswith`, `endswith`, `re`, `all`, `base64`, `base64offset`,
  `cidr`, `windash`), `null` values, `*`/`?` wildcards with Sigma escaping.
- **Condition parser**: `and`/`or`/`not` (precedence or < and < not), parentheses,
  `N|any|all of them|name|pattern*`, condition lists (OR), aggregation part after `|`
  parsed-not-evaluated.
- **Evaluator**: Kleene three-valued logic; per-record field snapshot with
  case-insensitive lookup; wall-clock deadline and input-size budgets; memoised
  detection-item results; optional logsource gating and rule→record field-name map.

### New/changed files

New, `ZeroBreach.Rules/Sigma/`:
- `SigmaMatchers.cs` — `TriState`, glob/regex/cidr/null value matchers, windash fold
- `SigmaDetection.cs` — evaluation context, field tests, detection items
- `SigmaCondition.cs` — condition AST + recursive-descent parser
- `SigmaCompiler.cs` — public compile entry point, modifier validation, transforms
- `CompiledSigmaRule.cs` — the public rule object + `Evaluate`

New, `ZeroBreach.Rules.Tests/Sigma/`:
- `SigmaTestHelpers.cs`, `SigmaMatchTests.cs`, `SigmaConditionTests.cs`,
  `SigmaBudgetTests.cs`, `SigmaCompileTests.cs` — 122 tests

Edited (pre-existing A5 files, inside scope):
- `Sigma/Yaml/YamlParser.cs` — **one genuine bug fix**: `TryFindKey` threw
  "expected ':' after quoted key" for a quoted scalar that is not a key (e.g. the
  ubiquitous `- 'keyword'` sequence item); it now returns "not a key" so the line parses
  as a value. Nothing else in the inherited YAML layer was changed.
- `SigmaTypes.cs` — untouched.

Nothing outside `ZeroBreach.Rules/Sigma/**` and `ZeroBreach.Rules.Tests/Sigma/**` was
created or modified. YARA sources untouched.

### Budgets and tri-state discipline

- `re` values compile to .NET `Regex` (backtracking engine, `CultureInvariant`) with
  `BudgetDefaults.PerPatternDeadline` (150 ms) baked in as the match timeout. A timeout
  returns **Incomplete with a reason, never false**. Canary test:
  `(a+)+$` against `"aaa…a!"` must come back Incomplete
  (`SigmaBudgetTests.PathologicalRegex_BlowsItsBudget_AndReportsIncomplete_NotFalse`).
- Wall-clock `ScanBudget.Deadline` is checked at every field test and keyword sweep;
  `MaxInputBytes` is checked against the record's total field-value size before
  evaluation. Both yield Incomplete with the reason.
- Kleene logic keeps sound definite answers definite: `false AND incomplete` is Ok/false,
  `true OR incomplete` is Ok/true, everything genuinely dependent on an incomplete
  sub-result propagates Incomplete. All four corners plus `not` and quantifier counting
  are pinned by tests.
- Aggregation (`| count() …`, `| near …`) and `timeframe` are parsed (function name
  validated), surfaced on the rule (`RequiresCorrelation`, `AggregationText`,
  `Timeframe`), and evaluation returns **Incomplete always** — a per-record answer to a
  correlation rule would be confidently wrong in both directions. Logsource mismatch
  still short-circuits to Ok/false first (the rule genuinely does not apply).
- Glob matching is the single-star backtracking algorithm — polynomial
  (O(pattern × input)), so plain values cannot blow up the way a regex can.

### Semantic judgement calls (all pinned by tests)

1. **`re` is case-sensitive and unanchored** (search semantics) — reference Sigma's one
   case-sensitive value form, while plain values compare case-insensitively.
2. **`Field: null` matches present-with-null only; a missing field matches nothing** —
   exactly as the task brief pins it. Note: reference Sigma *backends* commonly compile
   `null` to "field does not exist", i.e. missing ≡ null. The brief's wording overrides;
   **owner should confirm** this is the wanted behaviour for the host's records.
3. **windash** = canonicalising `-`, `/`, `–` (U+2013), `—` (U+2014), `―` (U+2015) to
   `-` on *both* pattern and input. Equivalent to the reference expand-all-variants
   behaviour and additionally handles mixed variants per occurrence.
4. **base64/base64offset encode the value as UTF-8**; there is no `wide`/`utf16`
   sub-modifier support (those are rejected at compile time like any unsupported
   modifier). `base64offset` uses the reference sigmac/pySigma slicing table
   (start `[0,2,3]`, end `[none,-3,-2]` indexed by `(len+i)%3`), not a re-derivation.
   Base64 comparison inherits the default case-insensitive comparison, matching what
   reference backends produce; strictly, base64 is case-sensitive, so this is a slight
   false-positive hazard inherited from the reference. Wildcards inside base64 values are
   a compile error (reference behaviour).
5. **Unsupported value modifiers fail at compile time** with the modifier named and the
   supported set listed — the brief's recommended answer to its open question.
6. **Statically unsatisfiable quantifiers are compile errors**: `N of X` with N greater
   than the number of matching selections, and a name pattern matching no selection. A
   rule that silently never matches is indistinguishable from a passing scan.
7. **Selection names** must be `[A-Za-z_][A-Za-z0-9_]*` and not a condition keyword;
   condition identifiers resolve **case-sensitively** (keywords are lowercase), matching
   the reference grammar. Top-level/rule-structure keys (`title`, `detection`, …) are
   found case-insensitively.
8. **Keyword selections** (list of scalars) match with contains semantics against every
   value of every field, wildcards honoured. A single bare scalar is a one-keyword
   selection. Mixed scalar/mapping lists are compile errors.
9. **Multi-valued record fields** (any non-string `IEnumerable`) match if any element
   matches. Sub-modifier `all` linkage applies across *values of the rule*, not elements.
10. **`title` and `logsource` are required** (spec-mandated sections); a rule without
    them fails compile. Logsource components the rule omits are wildcards; a record
    source omitting a component the rule names does not satisfy it.
11. **Determinism with hostile records**: case-colliding record keys (e.g. `Field` and
    `field`) resolve to the ordinal-smallest key regardless of dictionary enumeration
    order; keyword sweeps iterate fields in ordinal order.
12. **CIDR**: field text must look like an address (dotted quad for v4, `:` for v6)
    before `IPAddress.TryParse` is consulted — the BCL's lenient integer forms ("1" →
    0.0.0.1) must not count on attacker-chosen text. IPv4-mapped IPv6 record values are
    compared as IPv4. Rule-side CIDR values are validated at compile time.
13. **Condition lists are OR** of their entries (v1 spec multi-condition form).
14. **Sigma value escaping**: `\*`/`\?` literal wildcard, `\\` one backslash, lone `\`
    before anything else literal — so single-backslash Windows paths mean what they say.
15. **No compile-time ReDoS proof for `re`** — instead a 4096-char pattern cap plus the
    150 ms match timeout (Incomplete). Reliable static detection of catastrophic
    backtracking is out of scope; the budget bounds the damage and the canary pins it.
16. **One rule per document**: multi-document YAML (rule collections, `action: global`)
    is rejected loudly, not silently merged. Fine for per-file rule feeds; flag if the
    host ships multi-rule files.
17. **Field-name mapping** defaults to identity (host assumed to supply Sigma's standard
    Windows field names); `SigmaEvaluationOptions.FieldNameMap` is the single mapping
    table. **Owner must confirm the host's actual field names** (brief's open question).

### Mutation (fail-on-revert) checks — 10 performed

Each: `cp` pristine backup → apply mutation → run Sigma suite → observe failures →
restore → `cmp` byte-identical (no git; this folder is not a repo). All restored clean.

| # | Mutation | Caught by |
|---|---|---|
| 1 | Missing field treated as present-with-null | NullValue_MatchesPresentNullField_NotMissingField |
| 2 | Regex timeout collapsed to false | canary + 4 Kleene tests (5 failures) |
| 3 | OR collapses Incomplete into false | IncompleteOrFalse_StaysIncomplete |
| 4 | U+2015 dropped from windash set | Windash_MatchesEveryDashVariant("―nop") |
| 5 | base64offset start offsets zeroed | 3 alignment tests |
| 6 | `all` linkage degraded to OR | AllModifier_TurnsValueListIntoAnd |
| 7 | Exact anchoring degraded to contains | PlainValue + StarWildcard tests |
| 8 | Correlation gate disabled (‖→&&) | 3 aggregation/timeframe tests |
| 9 | Case folding removed (case-sensitive values) | 5 case-insensitivity tests |
| 10 | Case-collision key pick flipped (< → >) | CaseCollidingRecordKeys determinism test |

### What could not be verified, and what would verify it

- **The public Sigma corpus at scale.** No corpus is available here and simulating one
  would be a fake result. On a machine with network: clone `github.com/SigmaHQ/sigma`,
  run `SigmaCompiler.Compile` over `rules/windows/**/*.yml`, and review the reject
  reasons — rejects should be only: unsupported modifiers outside the brief's set
  (`expand`, `fieldref`, `lt`/`gt`, `utf16`…), multi-document collections, and YAML
  features outside the subset. Anything else is a parser gap.
- **Differential semantics against a reference implementation.** Unlike YARA (where a
  reference binary pinned every corner), no Sigma reference evaluator was available.
  `pip install pysigma` and comparing modifier-by-modifier transformation output
  (especially `base64offset` variants and windash expansion) would pin calls 3–4
  externally instead of from the reference source.
- **The host's real event-record field names** (judgement call 17) — owner confirmation.

### Wanted outside scope

Nothing needed changing outside `ZeroBreach.Rules`. Two notes for the owner:
- This fragment should be merged into `HANDOFF_FABLE2.md` at the package-level merge
  step (per `CONTINUE.md` §5/§7), alongside the other task fragments.
- C2 (rule linter) shares `ZeroBreach.Rules` and can now proceed — A5 no longer blocks
  the project from compiling.

---

## B1 — PE structure parser

**Status: complete.** `dotnet build` / `dotnet test` on `ZeroBreach.Formats.Tests` green on
Linux: **66/66 tests, zero warnings** (warnings-as-errors global). Built/tested in isolation
from the solution because the unrelated A5 Sigma break still blocks `ZeroBreach.Rules`.

**Build-state note (shared-project churn):** while B1 was finishing, the concurrent B2 agent
was already writing `ZeroBreach.Formats/Containers/*` into this shared project; as of this
handoff its in-progress `Containers/OleTypes.cs` fails to compile (CS9032 ×3), which breaks
any full build of `ZeroBreach.Formats`. That code is B2's and was deliberately left
untouched. B1's own sources were re-verified green after that churn appeared, via an
isolated copy containing exactly `Directory.Build.props` + `ZeroBreach.Formats/{Common,Pe}`
+ `ZeroBreach.Formats.Tests`: 66/66, zero warnings. Once B2 finishes its files, the shared
project should build whole; nothing in B1 depends on `Containers/`.

### What was built

`ZeroBreach.Formats.Pe.PeParser` — static PE32/PE32+ parser over a byte buffer, per
BLUEPRINT §6 and `tasks/B1_pe_parser.md`. The type declarations left by the previous agent
(`PeImage`, `PeMetrics`, `PeParseResult`, `PeParserLimits`, `Common/OperationState`,
`Common/ScanBudget`) were kept exactly as found and implemented against; **no pre-existing
file was modified**.

Parses: DOS header, COFF header, optional header (both magics), data directories, section
table, imports (name + ordinal, both thunk widths), exports (names, biased ordinals,
forwarders, unnamed slots), resource tree (named + id entries, data leaves), certificate
directory (presence/offset/size; bytes on demand via `PeParser.GetCertificateBytes`), debug
directory with CodeView/RSDS GUID+age+PDB path, Rich header, TLS directory + callbacks.
Metrics: per-section and whole-file Shannon entropy, entry-point location flags, W+X,
raw-0-with-large-virtual, uncommon section name, overlay offset/size, import counts, TLS
callback count. No verdict properties — facts only.

### Exact new-file list

- `ZeroBreach.Formats/Pe/PeParser.cs` (parser session, RVA mapper, entropy)
- `ZeroBreach.Formats.Tests/PeFixtureBuilder.cs` (byte-level PE builder; all fixtures authored in test code)
- `ZeroBreach.Formats.Tests/TestSupport.cs` (default-budget helper, canonical result dumper)
- `ZeroBreach.Formats.Tests/PeHeaderTests.cs`
- `ZeroBreach.Formats.Tests/PeImportExportTests.cs`
- `ZeroBreach.Formats.Tests/PeResourceAndExtrasTests.cs`
- `ZeroBreach.Formats.Tests/PeMetricsTests.cs`
- `ZeroBreach.Formats.Tests/PeHostileTests.cs`
- `ZeroBreach.Formats.Tests/PeBudgetTests.cs`

### Mutation (fail-on-revert) checks

9 mutations via `cp` backup / `cmp`-verified byte-identical restore (no git):

| Mutation | Killed by |
|---|---|
| `FromParse` collapses Incomplete→Ok | 14 tests |
| section-count cap removed | `SectionCount65535_…` |
| unreadable-section entropy null→0.0 | 2 entropy-null tests |
| deadline check disabled | budget canary |
| entry-point `>=` → `>` | `EntryPoint_AtExactSectionStart_IsInside` |
| entry-point `<` → `<=` | `EntryPoint_OnePastSectionEnd_IsOutside` |
| ordinal mask `&0xFFFF` → `&0xFF` | **survived at first** — fixture ordinals all fit one byte. Test strengthened to ordinal 515; now killed in both PE32 and PE32+ |
| overlay computation disabled | overlay + signed-file tests |
| resource cycle guard removed | self-referencing-tree test |

### Semantic judgement calls (each pinned by a test)

1. **Failed vs Incomplete split:** `Failed` through the optional-header *fixed* fields (no
   MZ, bad e_lfanew, no PE sig, truncated COFF/optional header, unknown magic, lying
   `SizeOfOptionalHeader`). From the data-directory table onward, damage is `Incomplete`
   with everything recovered so far. Never collapsed.
2. **`DataDirectories` reports only non-empty slots** (all 16 are read internally). A list
   of 14 zero rows is noise; presence of e.g. the CLR directory still surfaces as its row.
3. **`NumberOfRvaAndSizes` > 16** → capped at 16 *with an Incomplete reason* (the file
   declared content that was not read). Count also capped by `SizeOfOptionalHeader` room.
4. **Section count > 96** (loader's own limit) → table not read at all + reason; a corrupt
   count would only yield garbage sections.
5. **RVA mapping:** RVAs below `SizeOfHeaders` map 1:1; otherwise an RVA must fall inside a
   section's *raw* range (`SizeOfRawData`, not `VirtualSize` — virtual-only bytes do not
   exist in the file). Multi-byte structures are then bounds-checked against the **file**,
   not the section end, so an array crossing a section's raw end reads adjacent file bytes,
   as most real tools do.
6. **Entry-point containment window** is `[VA, VA + max(VirtualSize, SizeOfRawData))`, both
   boundaries mutation-tested. Zero entry point sets neither flag (DLL/resource-only norm).
7. **Entropy:** log₂ over the byte histogram of the whole window (section raw bytes clamped
   to the file; whole buffer for file entropy), range [0,8]. No readable bytes → `null`,
   never 0.0. A raw range overhanging EOF → entropy over the readable part + reason.
8. **Overlay** = file length − max(`SizeOfHeaders`, every section raw end, each clamped).
   The certificate table conventionally lives there, so a signed file reports an overlay —
   deliberate and documented in `PeMetrics`.
9. **`TimeDateStamp == 0` → null**, not 1970 (reproducible-build convention).
10. **Rich header** that does not decode cleanly (no DanS, misaligned entries) is treated as
    *absent*, no reason: it is undocumented and absence is not an anomaly.
11. **Imports:** INT (`OriginalFirstThunk`) preferred, `FirstThunk` fallback, as the loader
    does. Ordinal = low 16 bits only. Unreadable names → `null` + reason, never invented.
12. **Exports:** forwarder = function RVA inside the export directory range; unused slots
    (RVA 0, no name) omitted; several names on one index each get an entry; name with
    out-of-range ordinal index → reason.
13. **Resource cycles:** one global visited set per tree — a legitimately *shared* subtree
    (DAG) would also be reported as a cycle and not re-descended. Real files do not share
    subtrees; chosen as the safe direction.
14. **TLS `Present` is true whenever directory RVA ≠ 0**, even if the struct or callback
    array is unreadable (then + reason). Callback values are reported as stored (VAs);
    `AddressOfCallBacks` is converted VA→RVA via ImageBase with underflow guards.
15. **Budget mapping:** `MaxInputBytes` refuses oversize input up front (`Incomplete`, no
    image). `Deadline` gates every directory walk and loop (comparison is `>=`, so a zero
    deadline trips deterministically — that is the canary). `MaxNestingDepth` caps resource
    depth (min with `MaxResourceDepth`). **`MaxMatches` is unused** — nothing here is
    match-shaped. Metrics are still computed after a deadline trip: they are linear in the
    input, which `MaxInputBytes` already bounds, and a partially parsed file still deserves
    honest entropy/overlay numbers.
16. **Section names** decoded Latin-1 to first NUL; common-name set is case-sensitive
    (`.TEXT` is flagged, deliberately).

### Open questions from the brief (answered as assumed)

- Certificate: presence/offset/size + `GetCertificateBytes` on demand — as the brief's
  "assume the latter". No signature verification (needs Windows).
- .NET/CLI metadata: **not parsed** (as assumed). The CLR directory's presence is visible
  in `DataDirectories` (index 14, "ClrRuntime"). If the host cares that a binary is
  managed, a follow-up task should parse the COR20 header — flagging as the brief asked.

### Not verified here / needs the owner's machine

- Behaviour against real-world binaries at scale. Suggested check on Windows:
  parse `C:\Windows\System32\*.dll` + a packed-sample corpus and diff structure output
  against `dumpbin /headers /imports /exports` or Python `pefile`. Everything here is
  validated against self-authored fixtures only (as the package prescribes).
- Real performance on a technician's laptop (entropy pass is O(n), single-threaded).
- WIN_CERTIFICATE inner structure (bCertificate parsing) — bytes are handed over raw.
- Delay-load imports (directory 13) are surfaced only as a directory row, not walked.

### Wanted outside this task's scope (findings, not changes)

- None in `Common/` — `OperationState`/`ScanBudget` were reused as-is; B2 can share them
  unchanged. No file outside `ZeroBreach.Formats(.Tests)` was touched.

---

## B2 — Container reader (ZIP / OLE / OOXML)

**Status: complete.** `dotnet build` / `dotnet test` on `ZeroBreach.Formats.Tests` green on
Linux: **135/135 tests (66 B1 + 69 B2), zero warnings** (warnings-as-errors global). B1's
tests were run and pass alongside; nothing under `Pe/`, `Common/`, or B1's test files was
touched. `Common/OperationState` and `Common/ScanBudget` are reused, not recreated.

### What was built

`ZeroBreach.Formats.Containers` — stream-based readers per BLUEPRINT §7 and
`tasks/B2_containers.md`. Nothing is ever written to disk; input is a byte buffer, output is
structure plus bytes on request. No verdicts: traversal names, lying headers, encrypted
entries and macro parts are *surfaced*, never judged.

- **`ZipReader`** — end-of-central-directory search (strictly anchored), central-directory
  enumeration, local-header cross-check with per-field disagreement reporting, entry
  decompression (stored + deflate) under deadline / per-entry-ratio / shared-total-expansion
  guards, CRC-32 verification against both header sets, CP437/UTF-8 name decoding, DOS
  timestamp decoding, path-anomaly classification, overlap detection.
- **`OleReader`** — CFB v3/v4 header, DIFAT/FAT/mini-FAT, directory red-black tree walked
  in-order (deterministic), FAT- and mini-stream reads. Cycle detection with visited sets
  and step caps on every chain (FAT, DIFAT, mini-FAT, directory tree).
- **`OoxmlReader`** — OOXML = ZIP with `[Content_Types].xml`. Content-type resolution
  (Override > extension Default), package relationships from `_rels/.rels`, macro-part
  detection by content type (`application/vnd.ms-office.vbaProject`) *or* name
  (`vbaProject.bin`), part bytes on request. Metadata XML parsed with `DtdProcessing.Prohibit`,
  null resolver, bounded characters.
- **`ContainerWalker`** — nested-container recursion (zip-in-zip, OLE-in-zip, OOXML-in-zip,
  containers inside OLE streams), bounded by `ScanBudget.MaxNestingDepth`, one shared
  `ExpansionGuard` across all levels. Overall `Ok` only when every byte of every level was
  seen; anything unseen (encrypted, corrupt inner, depth/deadline/guard cutoff) makes the
  walk `Incomplete` with the path named.
- **`ExpansionGuard`** — cumulative expanded-bytes cap shared across reads, so a bomb split
  across entries or nesting levels is caught in aggregate.
- **`ContainerLimits`** — every cap as a named constant.
- **`Crc32`** — own table-driven implementation (System.IO.Hashing is a package, not in-box;
  no package dependencies allowed). The test suite carries an independent bitwise CRC-32 so
  agreement is meaningful.

### Exact new-file list

Sources (`ZeroBreach.Formats/Containers/`):
- `ContainerLimits.cs`
- `ExpansionGuard.cs`
- `Crc32.cs`
- `ZipTypes.cs`
- `ZipReader.cs`
- `OleTypes.cs`
- `OleReader.cs`
- `OoxmlTypes.cs`
- `OoxmlReader.cs`
- `ContainerWalker.cs`

Tests (`ZeroBreach.Formats.Tests/Containers/`, namespace `ZeroBreach.Formats.Tests.Containers`):
- `ZipFixtureBuilder.cs` (hand-written ZIP bytes with per-field lying overrides)
- `ZipReaderTests.cs` (13)
- `ZipHostileTests.cs` (19, incl. 7 traversal theory cases)
- `OleFixtureBuilder.cs` (hand-assembled CFB v3 sector layouts)
- `OleReaderTests.cs` (14)
- `OoxmlReaderTests.cs` (12)
- `ContainerWalkerTests.cs` (11)

One pre-existing-file fix within my own files only: `OleTypes.cs` initially declared
`internal required` members on a public class (CS9032) — the break B1's handoff noted — fixed
by dropping `required` on the three internal properties. No file outside `Containers/` was
edited.

### Mutation checks (all restored byte-identical, cmp-verified; no git used)

Each reverted guard made its assertion fail:
1. Ratio guard disabled → `Canary_KnownBomb_StoppedByRatioGuard` fails.
2. Encrypted entry collapsed to `Ok` + empty bytes → `EncryptedEntry_ReportedPresentButUnreadable` fails.
3. `..` segment detection removed → 3 of 7 `TraversalNames` cases fail (absolute/drive cases
   rightly unaffected).
4. CRC mismatch recording dropped → `LyingCentralDirectory_BothSidesReported` fails.
5. Walker depth cap bypassed → `NestedZips_OnePastTheLimit` fails.
6. `DtdProcessing.Prohibit` weakened to `Ignore` → `DoctypeInContentTypes_FailsLoudly` fails
   (the fixture is deliberately well-formed apart from the DOCTYPE, so it pins the guard
   itself, not incidental parse errors).
7. CFB v3 size mask removed → `Version3SizeField_HighHalfIsGarbage_Masked` fails.
8. `ZipReadResult.From` collapsing `Incomplete` into `Ok` → `EntryCountOverBudgetCap` fails.

Budget canaries as required: known 8 MiB→~8 KiB deflate bomb stopped by the ratio guard
(direct read and nested inside a walk), total-expansion guard tripped across entries,
`Deadline = Zero` canaries on `ZipReader.Read`, `ReadEntry`, `OleReader.Read`, and
`ContainerWalker.Walk`.

### Judgement calls (pinned by tests)

- **Deflate bitstream via BCL `DeflateStream`.** The brief says to parse the *container
  structures* myself; every ZIP structure (EOCD, CD, local headers) is hand-parsed, and the
  BCL is used only to inflate the raw bitstream, chunked so guards run mid-expansion. The
  BCL is in-box, allowed by CLAUDE.md ("no NuGet dependency"); writing a deflate
  decompressor from scratch was judged out of proportion to the task.
- **CD vs local headers: report both, merge nothing** (per the brief's open question). The
  *physical data slice* has to pick one: the local header's sizes are used (it sits adjacent
  to the data), except when a data descriptor (flag bit 3) makes the local values structural
  zeros, where the CD's are used. Actual-output guards defend against either lying.
- **CRC mismatch on a fully-decompressed entry is `Ok` + `CrcMatchesCentralDirectory/LocalHeader = false`
  + notes**, not `Incomplete`: the recovered bytes are complete; it is the *metadata* that
  lies, and that is a signal for the host. Truncation, by contrast, is `Incomplete` and no
  bytes are returned — a truncated read is never handed over as a clean one.
- **EOCD search is strictly anchored**: a candidate record must have its comment end exactly
  at end-of-buffer. A ZIP with trailing junk after the EOCD is `Failed`. (Self-extractor
  prefixes — junk *before* — are unaffected.)
- **ZIP64 and multi-disk → `Incomplete` "not supported"** with no entries; 0xFFFF/0xFFFFFFFF
  sentinels are never treated as real counts (fail closed rather than misparse).
- **Central directory extending past its own EOCD → `Incomplete`** (truncation is the common
  cause) with no entries; corrupt deflate *inside* an intact-length region → `Failed`.
- **Ratio guard**: 100:1 with a 64 KiB floor (deflate maxes ~1032:1; the floor stops tiny
  legitimate entries from tripping it). Declared sizes are additionally checked at
  enumeration time as a per-entry anomaly, but the authoritative guard runs on actual output.
- **Traversal**: `..` only counts as a full segment (`a..b.txt` is clean); anomalies are
  flags on the entry; the name is surfaced raw; no resolved/normalised path exists anywhere
  in the API.
- **Names without flag bit 11 are CP437** (own 128-char high table, incl. 0xFF → NBSP), not
  Latin-1/UTF-8; a flagged-UTF-8 name containing invalid sequences is decoded with
  replacement chars and flagged.
- **Invalid DOS timestamps are `null` + anomaly**, never a made-up date.
- **OLE spec-fixed fields are enforced loudly**: sector shift contradicting the major
  version, mini shift ≠ 6, cutoff ≠ 4096 → `Failed` (self-contradiction is malformation);
  major version ∉ {3,4} → `Incomplete` (unsupported variant). v3 stream sizes are masked to
  32 bits (real writers leave garbage in the high half).
- **OLE cycles**: a FAT/mini-FAT chain cycle during a stream read is `Failed` (data
  unrecoverable); a directory-*tree* cycle is an `Incomplete` reason and the tree walked
  before the cycle is still surfaced.
- **OOXML**: no `[Content_Types].xml` → `Failed` ("a ZIP but not an OOXML package");
  missing `_rels/.rels` → package anomaly but `Ok` (macro detection doesn't need it);
  encrypted parts make the package `Incomplete` and the part is marked; a DOCTYPE in
  metadata XML → `Failed` (XXE attempt against the scanner).
- **Walker semantics**: root container is depth 1; a nested container at depth
  `MaxNestingDepth` is walked, one past is reported and not walked. Per-node states are kept
  (a corrupt inner archive is a `Failed` *node*), and the overall state is `Incomplete`
  whenever anything was not seen; `Failed` only when the root itself is unreadable. OLE
  stream bytes count against the shared expansion guard too (raw, but resident).

### Could not verify from here (and what would)

- **Real-world archives**: only self-authored fixtures were used, per the work-package
  rules. Verify on the owner's machine against real `.docm`/`.xlsm`/`.doc` files and zips
  produced by Info-ZIP/7-Zip/Windows Explorer:
  `dotnet test ZeroBreach.Formats.Tests` plus an ad-hoc harness feeding
  `ContainerWalker.Walk` a directory of real samples.
- **CFB version 4 (4096-byte sectors)**: the code path exists (shift 12, offset formula
  shared) but the fixture builder is v3-only, so v4 is untested. A real v4 file (rare;
  produced by some MSI/insane-size docs) would exercise it.
- **Data-descriptor archives from real writers**: the bit-3 handling is tested only with
  synthetic zeros-in-local-header fixtures.
- **Real AES-encrypted zips** (method 99 + AE-x extra field): detection is by flag/method
  only; a real WinZip-AES sample would confirm.
- Performance at 64 MiB inputs on a technician's laptop.

### Wanted outside my scope (findings, not licences)

- `ScanBudget` (in `Common/`, B1-owned, untouched) has no expanded-bytes field, so the total
  expansion cap lives in `ContainerLimits`/`ExpansionGuard` defaults instead of the host's
  budget. If the host should configure it per scan, `ScanBudget` could grow a
  `MaxExpandedBytes` — a one-line addition plus threading; left as a finding.
- `.7z` / `.rar` / `.tar.gz` are out of scope per the brief's own assumption ("ZIP, OLE and
  OOXML cover the overwhelming majority of what arrives by email"); flagging here as the
  brief asks. The walker's `Sniff` is the single place to extend.
- This fragment should be merged into `HANDOFF_FABLE2.md` at the end, per `CONTINUE.md` §7.

---

## C1 — Windows path normalisation library (`ZeroBreach.Paths`)

**Status: complete.** `dotnet test ZeroBreach.Paths.Tests/ZeroBreach.Paths.Tests.csproj` —
**418 passed, 0 failed, 0 warnings** on Linux, .NET SDK 8.0.424. Built against fixtures only;
no file-system access anywhere in the library (verified by construction: no `System.IO` usage,
no process environment, no current directory).

> Note: the task was resumed twice (reboot, then a session-limit kill). The first partial agent
> wrote the eight type/table files; this session kept every one of those designs unchanged and
> added the normaliser core, the containment API, the tests, and this handoff.

---

### 1. What was built

**Normaliser** — `PathNormalizer.Normalize(string, IReadOnlyDictionary<string,string>?)`
→ `NormalizedPath`. Pipeline: caller-dictionary `%VAR%` expansion → separator direction →
root/prefix parsing (`\\?\`, `\\.\`, `\\?\UNC\`, GLOBALROOT, plain UNC, drive-absolute,
drive-relative `C:foo`, root-relative `\foo`, relative) → duplicate-separator collapse →
`.`/`..` resolution with root clamping → trailing dot/space rules (documented Win32
`GetFullPathName` semantics) → alternate-data-stream split → trailing-separator removal →
invariant-lower-case comparison form. Every rewrite lands in `Transformations` (the
"normalised from X to Y" audit trail); everything suspicious lands in `Flags`
(8.3 shapes, reserved device names, homoglyphs, ADS, clamped traversal, loopback/admin UNC —
flagged, never resolved or folded). Malformed input → `Failed` with a reason naming the
offending component/character; **no partial results** (all derived properties null/empty).
Normalisation itself never returns `Incomplete`; that state belongs to comparison.

**Containment (headline)** — `PathContainment.IsInside(candidate, directory)`
→ `ContainmentResult { State, Verdict (Inside/Equal/Outside), Reason, IsInside }`.
Segment-based prefix comparison on canonical forms — `C:\FooBar` is not inside `C:\Foo`, at any
depth. Cross-form containment holds: `\\?\C:\Foo\x` (and `\\.\C:\Foo\x`, `//?/…`) IS inside
`C:\Foo`. Fail-closed: anything unprovable from strings is `Incomplete`, and `IsInside` is
structurally false off the `Ok` state.

### 2. Exact file list (all new; nothing outside these two directories was touched)

`ZeroBreach.Paths/`:
- Pre-existing from the first partial agent (kept as-is, one comment-level contract honoured
  throughout): `CharacterSets.cs`, `NormalizedPath.cs`, `OperationState.cs`, `PathFlags.cs`,
  `PathKind.cs`, `PathLimits.cs`, `PathRootSpace.cs`, `PathTransformation.cs`, `ZeroBreach.Paths.csproj`
- New this session: **`PathNormalizer.cs`**, **`PathContainment.cs`**, **`ContainmentResult.cs`**

`ZeroBreach.Paths.Tests/` (all new this session except the csproj):
- **`NormalizationCoreTests.cs`** — separators, dots, dup separators, trailing dot/space rules,
  case, audit trail (order + snapshot chaining), never-Incomplete
- **`RootFormTests.cs`** — every root syntax, kind/space/root assignments, cross-form canonical equality
- **`StreamsAndFlagsTests.cs`** — ADS incl. `::$DATA` and `$I30:$INDEX_ALLOCATION`, reserved
  names, 8.3 shapes, homoglyphs (flagged-not-folded pinned)
- **`EnvironmentExpansionTests.cs`** — dictionary expansion, case-insensitivity, determinism,
  unresolved-variable failure, single-pass, literal `%`
- **`MalformedInputTests.cs`** — every failure family, no-input-ever-throws sweep, **canaries**
  (length ceiling enforced; max-length `a\..\`-repeated hostile input completes < 2 s; 8 000-deep
  traversal clamps)
- **`ContainmentTests.cs`** — the `C:\Foo`/`C:\FooBar` off-by-one (root-level and mid-path),
  equal/one-level/many-level, UNC, cross-form, streams, undecidable namespaces, malformed,
  structural fail-closed property
- **`GuardBypassTests.cs`** — the adversarial corpus: ~27 inside-spellings (slashes, case, dots,
  `..` laundering, trailing dots/spaces, NT prefixes, ADS, combinations) must be caught Inside;
  ~11 unprovable spellings (loopback/admin shares, GLOBALROOT, device, relative forms) must be
  `Incomplete`; and the master property — **no attack spelling ever comes back Ok/Outside**
- **`IdempotenceAndDeterminismTests.cs`** — 50-fixture sweep: `Normalize(NormalizedDisplay)` is a
  fixpoint (display, canonical, root, segments, stream identity), same-input-same-result, and
  self-containment agreement between normaliser and containment engine

### 3. Mutation (fail-on-revert) checks

All via `cp` backups, restored byte-identically (`cmp`-verified), no git. Script preserved at
the session scratchpad (`mutate.py`); final pristine run re-verified green after each.

| Mutation (reverted behaviour) | Killed by |
|---|---|
| M01 segment equality → `StartsWith` (classic prefix bypass) | 2 tests |
| M02 `Incomplete` collapsed into `Ok/Outside` (tri-state violation) | 35 tests |
| M03 forward slashes not rewritten (the shipped bug) | 13 tests |
| M04 `..` not clamped at the root | 5 tests |
| M05 path-end dot/space trim disabled | 15 tests |
| M06 ADS handling disabled | 23 tests |
| M07 homoglyph detection disabled | 11 tests |
| M08 `Equal` no longer counts as inside | 44 tests |
| M09 reserved device names never flagged | 9 tests |
| M10 load-bearing trailing separator dropped (idempotence break) | 2 tests |
| M11 unresolved env var silently expands to empty | 2 tests |

### 4. Judgement calls (every one pinned by a test)

**Fail-closed calls — the ones to review first:**
1. **Unresolved `%VAR%` → `Failed`.** Windows' `ExpandEnvironmentStrings` would leave the token
   literal; a guard comparing against literal `%SystemRoot%` text is not comparing against the
   path the operation will touch. Side effect: a legitimate filename containing two stray `%`
   around name-like text (e.g. `C:\a 5% b 10% c`) fails closed. Implausible names (containing
   `\ / : " < > | * ?` or controls) stay literal; expansion is single-pass (hostile dictionary
   cannot loop); lookup is case-insensitive with a deterministic ordinal-smallest-key tie-break.
2. **`\\?\` verbatim paths are normalised anyway** (Windows would pass them to the kernel
   untouched). Required for the brief's cross-form containment ("a `\\?\` path IS inside its
   plain-form parent"); `PathFlags.VerbatimPrefix` preserves what the caller wrote. Corollary:
   wildcards and trailing dots in `\\?\` paths are rejected/trimmed here where Windows would
   pass them through — fail-closed, flagged.
3. **`VerbatimPrefix` is only for a literal backslash `\\?\`** — `//?/C:/x` reaches the same
   namespace but is not a verbatim path on real Windows.
4. **`IsInside` includes `Equal`.** A guard protecting `C:\Foo` must refuse destroying `C:\Foo`
   itself. Callers needing the distinction read `Verdict`.
5. **Only Drive and UNC namespaces are comparable.** Device (`\\.\HarddiskVolume2\…`) and
   GLOBALROOT paths may alias any volume → always `Incomplete`, even device-vs-same-device
   (uniformity over cleverness). Relative / root-relative / drive-relative (`C:foo`) →
   `Incomplete` (no base directory to resolve against).
6. **Loopback (`localhost`, `127.0.0.1`) and administrative (`X$`, `ADMIN$`) shares** are
   flagged, and any cross-namespace (UNC↔drive) comparison involving those flags is
   `Incomplete`. A **plain** remote share vs a local drive is `Ok/Outside` — deliberately, so
   the guard does not refuse every network operation; pinned both ways.
7. **Colon placement:** legal only as the drive colon or in the final component of a path not
   ending in a separator (the ADS position). `C:\dir:s\x` and `C:\dir:s\` → `Failed`.
   `C:\:stream` (stream on an empty name — Windows would open a stream on the directory) →
   `Failed`. A colon in a segment that `..` removes is accepted (matches GetFullPathName's
   textual resolution).
8. **A directory argument carrying a named stream** → `Incomplete` (nothing is "inside" a
   stream); a candidate equal to the directory but carrying a named stream → `Inside`
   (subordinate content on the protected object).

**Windows-semantics modelling (documented `GetFullPathName` rules):**
9. Trailing dots/spaces: each segment loses **exactly one** trailing `.` (`a.` → `a`; `a..` and
   `...` untouched — 3+ dots is a valid name); the **path end** loses all trailing dots and
   spaces unless the path ends in a separator; `.`/`..` are exempt. So `C:\a \` keeps the
   trailing-space name and its **load-bearing separator survives in the display form** (removing
   it would change which object the string names — this is also what makes the idempotence
   sweep honest). Path-end trim runs **before** the stream split (`f:s...` → stream `s`).
10. `::$DATA` is the file itself: same `CanonicalFull` as the plain path, `DefaultDataStream`
    flag, no distinct stream identity; `f:s` ≡ `f:s:$DATA` (`CanonicalStream` defaults the type).
11. `..` clamps at every root (drive, `\\server\share`, device, GLOBALROOT) with flag + audit
    record; unrooted paths keep leading `..`; a relative path resolving to nothing renders `"."`.
12. `\\?\C:\x` and `\\.\C:\x` land in **Drive** space (compare equal to `C:\x`); `\\?\UNC\` and
    `\\.\UNC\` in UNC space; `\\?\GLOBALROOT` and `\\.\GLOBALROOT` in GlobalRoot space.
13. UNC needs server **and** share (`\\server` → `Failed`); duplicate separators inside the UNC
    root region collapse under the same rule as everywhere else. Reserved-name/8.3 flags apply
    to path segments (not server/share); homoglyph flags apply to server/share/device/stream too.
14. Reserved set includes `CONIN$`/`CONOUT$` and superscript `COM¹`–`³`/`LPT¹`–`³`; excludes
    `COM0`/`LPT0`; matched on the base name before the first dot (`NUL.tar.gz` is reserved) —
    per the first agent's table, kept and now pinned.
15. Non-letter drive (`1:\x`) → `Failed`. Case folding is `ToLowerInvariant` per the brief;
    see §5 for the caveat.

### 5. What could not be verified from here, and what would verify it

- **Agreement with real `GetFullPathNameW`/`RtlDosPathNameToNtPathName`** on the awkward
  corners (§4.9's dot/space rules, `//?/` handling, colon-before-`..`). Everything here follows
  the documented rules ("File path formats on Windows systems" — Normalization), but the
  documentation is known to lag the implementation. **Verify:** on a Windows box, run the
  fixture list in `IdempotenceAndDeterminismTests.Fixtures()` plus `GuardBypassTests`' corpora
  through `GetFullPathNameW` and diff against `NormalizedDisplay`. I can write that probe
  harness if wanted; it is ~50 lines of P/Invoke that must live outside this library.
- **Case-folding fidelity:** NTFS compares names via its volume `$UpCase` table
  (an *upper*-casing), not invariant *lower*-casing. They agree on virtually everything
  technicians will meet, but exotic points (`ß`, `İ`, some Cyrillic/Greek additions on old
  volumes) can differ. The brief's assumption ("invariant lower-casing, assume no locale
  disagreement") is implemented and hereby flagged as an assumption.
- **Aliasing invisible to string logic:** junctions, symlinks, hard links, mount points,
  `SUBST`, mapped drives, and 8.3 short names can make two textually-unrelated paths the same
  object. Out of scope by design (needs the file system); the flags
  (`ShortNameComponent`, `LoopbackUncServer`, `AdministrativeShare`) carry the evidence, but
  **the host guard must resolve reparse points/8.3 on-machine before trusting `Ok/Outside`**.
  This is the single most important integration note.

### 6. Wishes outside `ZeroBreach.Paths` (findings, not licences)

- The host should **log `NormalizedPath.Transformations`** whenever the guard refuses — that is
  the "normalised from X to Y" line the brief asks for, already computed.
- The host must treat `Incomplete` from `PathContainment` as **refuse**; the API cannot force
  that at the call site. Worth a lint/code-review rule in the host repo.
- `OperationState` is now defined per-project three times across this package (Paths, Intel,
  Formats) — intentional under the "own project only" rule; a shared kernel type would be a
  nice merge-time unification.

### 7. Verification commands

```bash
export PATH="$HOME/.dotnet:$PATH"; export DOTNET_CLI_TELEMETRY_OPTOUT=1
cd /home/user/Downloads/claude/fable-work-2
dotnet test ZeroBreach.Paths.Tests/ZeroBreach.Paths.Tests.csproj   # 418 passed, 0 warnings
```

---

## C2 — Signature and rule linter

**Status: complete.** `dotnet build fable-work-2.sln` 13 projects, 0 warnings;
`dotnet test ZeroBreach.Rules.Tests` **529/529 green** (307 YARA + 122 Sigma pre-existing,
**100 new Linting tests**), with `/usr/bin/yara` 4.5.5 present so the differential suites
were not vacuous. Nothing outside `Linting/` was created or edited.

### What was built

A linter for the host's BLUEPRINT §9 JSON rule content (named indicator sets +
`fp_allowlists`), namespace `ZeroBreach.Rules.Linting`, as a library plus an in-library
CI entry point. Every §9 defect class has its own stable `LintCode`, a severity, and a
message naming the file, key, entry and line/column:

| Code | Severity | What it catches |
|---|---|---|
| `SchemaViolation`, `DuplicateKey` | Error | wrong shape; a duplicated key silently replacing a definition |
| `DuplicateEntry`, `EmptyIndicatorSet` | Warning | copy-paste noise; a set that can never match |
| `RegexDoesNotCompile` | Error | entry compiles to nothing (looks like a passing check) |
| `DoubleEscapedClass` | Warning | `\\d` written where `\d` was meant, one JSON escape too deep |
| `CatastrophicBacktracking` | Error | budget blown against a bait battery (measured, 150 ms/probe) |
| `UniversalAllowlist` | **Critical** | entry matches all 8 unrelated canaries — suppresses everything |
| `UnanchoredAllowlist` | Error | not `^…$`-anchored end to end (self-allowlisting malware) |
| `AllowlistSwallowsDetection` | Warning | allowlist matches a witness generated from its own detection |
| `IndicatorTooShort` | Warning | longest *required* literal run < 4 chars |
| `IndicatorCollidesWithLegitimateName` | Error | matches the starter corpus of real software names |
| `DanglingReference`, `OrphanSet` | Error / Warning | reference to a missing set; a set nothing references |
| `ReferenceAnalysisInactive` | Info | no reference data — the skipped check is visible, never silent |

Results are the shared tri-state (`OperationState`): `Failed` = unparseable JSON (message
with line/column, **no findings list** — no partial results on error), `Incomplete` =
size/deadline budget hit (reason + honestly-partial findings), `Ok` = complete,
deterministic, position-sorted findings. Rendering: human text and machine JSON
(`LintReport`), both byte-stable. CLI (`LintTool.Run`): exit 0 clean / 1 findings at
threshold (Error+; `--fail-on-warning` includes warnings) / 2 did-not-complete;
`--format text|json`, `--manifest <file>` (JSON array of host-consumed set names).

### Exact new-file list

Sources (`ZeroBreach.Rules/Linting/`): `LintDiagnostics.cs`, `LintOptions.cs`,
`LintResult.cs`, `LintReport.cs`, `LintTool.cs`, `RuleFileModel.cs`, `RuleFileLinter.cs`,
`AllowlistCanaries.cs`, `CollisionCorpus.cs`, `BacktrackingProbe.cs`,
`Json/JsonSource.cs`, `Json/JsonSourceParser.cs`, `Patterns/PatternAst.cs`,
`Patterns/PatternParser.cs`, `Patterns/PatternInsight.cs`.

Tests (`ZeroBreach.Rules.Tests/Linting/`): `LintTestHelpers.cs`,
`JsonSourceParserTests.cs`, `SchemaAndReferenceTests.cs`, `RegexDiagnosticTests.cs`,
`AllowlistSafetyTests.cs`, `IndicatorQualityTests.cs`, `BacktrackingBudgetTests.cs`,
`LintToolTests.cs`, `DeterminismTests.cs`.

Plus this file. One shared-file edit only: none — the solution/test csproj glob picked the
files up.

### Fail-on-revert evidence

Ten targeted mutations, each run against the 100-test Linting suite, each observed to
fail tests (count in brackets), each file then restored and verified byte-identical with
`cmp`: universal-allowlist all-canaries guard [3]; anchoring both-ends requirement [4];
backtracking timeout swallowed [5, includes the mandatory `^(a+)+$` canary]; JSON parse
failure collapsed to Ok [1]; deterministic sort removed [1]; per-entry deadline check
disabled [1]; double-escape heuristic broken [3]; CLI exit code forced clean [4];
short-indicator threshold zeroed [4]; dangling-reference test inverted [4]. The three
"the check-material itself stays varied" tests (canary set, collision corpus, bait
battery) guard against the silent-no-op failure mode BLUEPRINT §3 warns about.
Backtracking canaries were chosen **empirically on this runtime** (.NET 8 defeats some
textbook patterns): `^(a+)+$`, `^(a|aa)+$`, `^(.*a){20}$`, `^([a-z]+)*!$`, `^(\d+)*x$`
all verified to blow a 150 ms budget against the bait battery.

### Judgement calls (each pinned by a test)

1. **`references` schema invented.** §9 demands orphan/dangling detection but defines no
   reference syntax. Chosen: optional top-level `"references": { "<consumer>": ["set", …] }`
   plus an external manifest (`LintOptions.ExternalReferences` / `--manifest`). With no
   reference data at all, the analysis emits an Info `ReferenceAnalysisInactive` instead
   of silently skipping. **Owner should confirm the real linkage shape** — if the host
   already encodes set↔phase pairings elsewhere, feed them through the manifest.
2. **All entries are treated as .NET regexes**, compiled `IgnoreCase | CultureInvariant`
   with a match timeout — the way the host (a .NET tool matching Windows paths/names)
   would consume them. If any set is actually literal-substring semantics, its entries
   with metacharacters will (correctly, loudly) fail the compile check.
3. **JSONC accepted, conservatively**: `//` and `/* */` comments allowed (the §9 example
   is fenced `jsonc`); trailing commas, single quotes, unquoted keys rejected with
   guidance. Duplicate keys are Errors, not last-wins.
4. **Double-escape heuristic refined** to stay quiet on real paths: fires on `\\` + class
   letter only when the letter is quantified (`\\d+`) or stands alone (`\\s$`); `\\data`,
   `\\bin` do not fire. `\\\d` (literal backslash then a real `\d`) does not fire.
5. **"Too short/generic"** = longest *required* literal run < 4, computed conservatively
   over the pattern AST (alternation takes the weakest branch; optional pieces break
   runs; may undercount, never overcount). Consequence, deliberate: an all-class pattern
   like `[0-9a-f]{64}` is flagged — it matches any hash whatsoever.
6. **Swallow check is witness-based**: a concrete string is generated from each
   indicator's own structure, verified against its own regex, then tested against every
   allowlist entry. No witness → check skips silently for that entry (it is Warning-level
   and best-effort; regex-containment is the exact-but-undecidable alternative).
   Universal entries are excluded — they already carry Critical.
7. **Anchoring** requires every top-level alternation branch anchored both ends
   (`^a$|b$` fails); `\A`/`\z`/`\Z` count; escaped `\$` does not.
8. **Reference names compare ordinally (case-sensitive)**: a case-mismatched reference is
   reported (dangling + orphan) rather than guessed at.
9. **Incomplete is loud in the CLI**: any non-Ok state exits 2, and the text report ends
   with an `INCOMPLETE:` line so a truncated lint cannot scroll past as clean.
10. **Severity scale has `Critical`** above Error, reserved for the fails-open universal
    allowlist; both fail CI.
11. **Sigma/YARA rule linting is out of C2's scope** — the brief scopes C2 to §9 JSON
    content, and the YARA/Sigma compilers already carry their own diagnostic surfaces.

### Could not verify / would verify it

- **Real rule files.** Everything ran against authored fixtures. Run the tool over the
  production JSON: wrap `LintTool.Run` in a `Main` (one line, see below) and lint the
  shipped content with the real consumer manifest. Expect judgement calls 1–2 to be the
  ones that surface any mismatch.
- **Timing margins on slower hardware.** The catastrophic canaries blow 150 ms by orders
  of magnitude and healthy patterns run in microseconds, so flapping is unlikely, but the
  boundary is inherently machine-dependent; a pattern sitting exactly at the budget edge
  could differ between runs. This is the one documented exception to bit-perfect
  determinism, shared with every budgeted component in this package.
- **Collision corpus breadth.** The 65-name starter list is a floor, not a fleet. Feed a
  real inventory via `LintOptions.AdditionalCollisionNames`.

### Wanted outside `Linting/` (findings, not licences)

1. **A real console project** (`ZeroBreach.Rules.LintCli`) so CI gets a binary:
   `public static int Main(string[] args) => LintTool.Run(args, Console.Out, Console.Error);`
   Not created — the integration rules forbid new projects/`.sln` edits from a task.
2. The shared `ZeroBreach.Core` point from the A4 handoff stands: this task reused
   `OperationState`/`BudgetDefaults` from `ZeroBreach.Rules.Common` (same project, so no
   duplication here), but the Json/Patterns mini-parsers could serve other tracks too.
3. CI should run the linter (`--fail-on-warning` recommended once the existing content is
   clean) and keep `yara` installed for the A-track differential suites.

---

## D1 — IOC feed normaliser (`ZeroBreach.Intel`)

**Status: complete.** 143 tests green, zero warnings, `net8.0`, no packages beyond xUnit
(JSON via `System.Text.Json`, XML via `System.Xml` — both in-box BCL).

Run: `dotnet test ZeroBreach.Intel.Tests/ZeroBreach.Intel.Tests.csproj`
(the solution-wide build is still broken by the unrelated half-finished A5 Sigma work).

This task was resumed twice: once from the pre-reboot state (model/defanger/validator on
disk, per `CONTINUE.md` §3) and once mid-mutation-check after a session reset. The
pre-existing designs (`Candidate.cs`, `Defanger.cs`, `FeedSource.cs`, `Indicator.cs`,
`IndicatorType.cs`, `IndicatorValidator.cs`, `IngestResult.cs`, `OperationState.cs`) were
kept unchanged and built upon. After the second resume, every source file was verified
byte-identical to its pristine `cp` backup (`cmp`) before work continued.

### What was built

The four feed readers, the normalising pipeline, and the full test suite:

- **`FeedNormalizer.Ingest(feeds, budget?)`** — the public entry point. Per candidate:
  trim → defang restore (before validation, recorded as `WasDefanged`) → type resolution
  (plain-text inference, IP-family resolution, filename-vs-path split) → validation →
  case-insensitive dedup preserving first-seen source → batch cap. Batch and per-feed
  tri-state per the shape documented in `IngestResult.cs`.
- **STIX 2.x** (`StixReader` + `StixPatternParser`) — bundle `objects`, `indicator`
  objects, OR-joined equality patterns; confidence / `valid_until` / name+labels carried.
- **MISP** (`MispReader`) — `Event.Attribute[]` + `Event.Object[].Attribute[]`,
  composite types split, `threat_level_id` → severity, category+comment → label.
- **OpenIOC XML** (`OpenIocReader`) — `Indicator`/`IndicatorItem` trees,
  `XmlReader` with `DtdProcessing.Prohibit` + `XmlResolver = null` +
  `MaxCharactersFromEntities = 0` + `MaxCharactersInDocument` from the budget; nesting
  bounded by `MaxNestingDepth` → `Incomplete`.
- **Plain text** (`PlainTextReader`) — one per line, `#`/`;` comments, types inferred.
- **`IngestBudget`** — deadline / max input bytes / indicator cap / nesting depth, BLUEPRINT
  §3 defaults as named constants.

### Exact file list

New files:

```
ZeroBreach.Intel/IngestBudget.cs
ZeroBreach.Intel/PlainTextReader.cs
ZeroBreach.Intel/StixPatternParser.cs
ZeroBreach.Intel/StixReader.cs
ZeroBreach.Intel/MispReader.cs
ZeroBreach.Intel/OpenIocReader.cs
ZeroBreach.Intel/FeedNormalizer.cs
ZeroBreach.Intel.Tests/TestData.cs
ZeroBreach.Intel.Tests/DefangerTests.cs
ZeroBreach.Intel.Tests/ValidatorTests.cs
ZeroBreach.Intel.Tests/StixFeedTests.cs
ZeroBreach.Intel.Tests/MispFeedTests.cs
ZeroBreach.Intel.Tests/OpenIocFeedTests.cs
ZeroBreach.Intel.Tests/PlainTextFeedTests.cs
ZeroBreach.Intel.Tests/PipelineTests.cs
```

Modified (own project only): `ZeroBreach.Intel/ZeroBreach.Intel.csproj` — added
`InternalsVisibleTo ZeroBreach.Intel.Tests` so the validator/defanger can be unit-tested
directly; everything else is tested through the public `FeedNormalizer` surface.

### The XXE / DOCTYPE gate

Three tests in `OpenIocFeedTests` pin it: an external-entity (`file:///etc/passwd`)
payload, an internal-entity payload, and a billion-laughs DOCTYPE all yield `Failed`
with zero indicators; a fourth test proves predefined entities (`&amp;`) still work, so
the gate is DTDs, not entities generally. The internal-entity test is the sharp one: it
asserts the entity's value never comes out the other side as an indicator, which is what
fails first if `DtdProcessing` is ever flipped to `Parse` (mutation M5 below proved all
three fail). Note: the DTD-prohibited `XmlException` carries **no position**
(`LineNumber == 0`), so that one message names the DTD instead of inventing "line 0";
all other XML/JSON failures carry one-based line/column.

### Mutation (fail-on-revert) checks

All via `cp` backup → edit → `dotnet test` → restore → `cmp` byte-identical (no git).

| # | Reverted behaviour | Failing tests |
|---|---|---|
| M1 | Defang dot-restoration disabled | 12 |
| M2 | IPv4 leading-zero rejection removed | 1 |
| M3 | Dedup key made case-sensitive | 1 (after fix below) |
| M4 | Indicator cap never enforced | 2 |
| M5 | `DtdProcessing.Prohibit` → `Parse` | 3 (all DOCTYPE tests) |
| M6 | Malformed JSON → empty `Ok` feed | 3 |
| M7 | Deadline never checked | 1 (the budget canary) |

**Honest finding:** M3 initially survived — 142/142 stayed green with a case-sensitive
dedup key, because every dedup test used types whose *normalisation* already lowercases
(hashes, domains, URLs). The assertion was a false claim of coverage. Added
`Dedup_IsCaseInsensitive_ForCasePreservingTypes` (two `FilePath` values differing only in
case), which fails under M3. This is exactly why the fail-on-revert rule exists.

Budget canary: `DeadlineCanary_ZeroDeadline_YieldsIncomplete_NeverSilentlyOk` uses an
already-expired deadline (`FromTicks(-1)`, so the outcome cannot race the stopwatch) and
asserts `Incomplete` + reason; M7 shows it trips when enforcement is removed.

### Judgement calls (each pinned by a test)

1. **STIX patterning subset** (brief's open question, conservative option taken): only
   OR-joined `=` comparisons, at observation and comparison level. AND, FOLLOWEDBY,
   qualifiers, `!=`/`LIKE`/`MATCHES`, and unknown object paths reject the **whole
   pattern**, naming the construct — including a mixed `[supported OR unsupported]`
   pattern, because one indicator object is one assertion and extracting half of it
   fabricates indicators the feed never asserted.
2. **STIX revoked indicators** are rejected with reason "indicator is revoked" (the spec
   says a revoked object must not be used; using it resurrects a withdrawal, dropping it
   silently hides one).
3. **Bad STIX metadata rejects the indicator**: unparseable `valid_until` or non-integer
   `confidence` rejects the whole indicator loudly rather than silently shedding the
   metadata. Arguably strict; flip to "keep + warn" only with a reporting channel for it.
4. **Non-indicator STIX objects** (malware, relationship, …) are skipped *without* a
   rejection — they are not indicator candidates, so this is not silent dropping.
5. **MISP `to_ids: false`** and **`deleted: true`** attributes are rejected with reasons
   (the analyst said not-for-detection / tombstone; neither silently used nor dropped).
6. **MISP composites** split into one candidate per part; the `port` half of
   `ip-…|port` and the data half of `regkey|value` are not indicator kinds in this model
   and are dropped by design while the IP/key survives.
7. **MISP `link` type is unmapped** (rejected loudly) — in practice a reference URL, not
   an IOC. Add to the map if the owner disagrees.
8. **OpenIOC: only `condition="is"`** is extracted; `contains` etc. are substring
   semantics this typed model cannot represent, rejected with the condition named.
9. **A well-formed but wrong-shaped document is `Failed`, never an empty clean feed**:
   non-`ioc` XML root, STIX without an `objects` array, MISP without `Event`. An empty
   result from a wrong file is indistinguishable from a clean feed.
10. **Plain-text inference never yields `Filename` or `Mutex`** — a bare token is
    indistinguishable from a domain, so `evil.exe` classifies as `Domain` (test pins it).
    Feeds that mean filenames must use a typed format.
11. **Expired indicators are kept** with `Expiry` set (brief: host decides).
12. **Oversized feed is refused unparsed** (`Incomplete`), not truncated-and-parsed —
    half a JSON document can parse as a smaller valid-looking feed.
13. **Deadline vs cap accounting**: `TruncatedCount` counts only cap-truncated valid
    candidates (as its doc says); candidates/feeds unprocessed at the deadline are
    reported through `Incomplete` states and messages ("after processing N of M").
14. **JSON depth** is bounded by `JsonDocument` `MaxDepth = 64` (named constant), not the
    budget's depth-8 — real MISP exports legitimately nest ~6 levels of JSON; the budget's
    depth bounds the OpenIOC `Indicator` tree instead. Over-deep JSON is `Failed` with
    position.
15. Dedup key is `(type, ToLowerInvariant(normalized))`; the same string as two different
    types is deliberately *not* a duplicate (test pins it).

### Not verified from here (owner's machine)

- Behaviour against **real** STIX/MISP/OpenIOC exports at scale — fixtures here are
  authored to the subset in `BLUEPRINT.md` §10 and the public format docs. Verify with:
  `dotnet run` a small harness (or a scratch xunit test) calling
  `FeedNormalizer.Ingest` over a genuine vendor export of each format, and eyeball the
  per-feed `RejectionCountsByReason` — the design guarantees gaps show up there as
  loud "unmapped/unsupported" counts rather than silence.
- The MISP attribute-type and OpenIOC search-path maps cover the common core only. That
  is safe (unmapped → rejected with the type/path named) but a real feed may want more
  mappings; the rejection report is the discovery mechanism.
- Wall-clock deadline behaviour under real load (tests only pin the enforcement logic).

### Wanted outside `ZeroBreach.Intel/` (findings, not done)

- Nothing required. Two nits for the merge owner: `FeedResult.TruncatedCount`'s doc
  comment ties it to the cap; deadline-unprocessed work is reported via `Message` — if a
  numeric counter for that is wanted it is a one-line addition to the record. And
  `Defanger` (pre-existing) replaces `hxxp` anywhere in a value, so a value containing
  `hxxp` mid-word is altered; acceptable for indicator values, noted for completeness.

---

## D2 — Baseline diff engine (`ZeroBreach.Diff`)

### D2 — Baseline diff engine

**What was built.** A pure, static diff engine (`BaselineDiff.Diff(baseline, current,
options?)`) over two host-produced `RunRecord`s from the same machine. Output is a data
structure (`DiffResult`), never text: the four finding sets (**new / resolved / persisting /
changed**, with field-by-field `FieldChange` detail on changed), **first-class coverage
deltas** (`Regression / Improvement / Added / Removed` per check), comparability
**warnings** (stale baseline, clock skew, mode-string mismatch, narrower baseline
inventory, id-contract anomalies), and a hard **Failed** state for non-comparable inputs.
Dictionary joins keyed ordinally on the host's stable ids — O(n + m) in findings and
checks — then every output list is sorted ordinally by id, so results are deterministic
and independent of input order. Neither input is ever mutated; a refused diff carries no
partial output of any kind.

**Files** (all new):
- `ZeroBreach.Diff/ZeroBreach.Diff.csproj`
- `ZeroBreach.Diff/RunRecord.cs` — `RunRecord`, `Finding`, `FindingSeverity`,
  `CheckResult`, `CheckStatus` (the input model)
- `ZeroBreach.Diff/DiffResult.cs` — `DiffResult`, `ChangedFinding`, `FieldChange`,
  `CoverageDelta`, `CoverageChangeKind`, `OperationState` (the output model)
- `ZeroBreach.Diff/DiffOptions.cs` — `MaxBaselineAge` knob
- `ZeroBreach.Diff/BaselineDiff.cs` — the engine
- `ZeroBreach.Diff.Tests/ZeroBreach.Diff.Tests.csproj`
- `ZeroBreach.Diff.Tests/TestData.cs` — fixture builders + a canonical deep renderer
  (walks every value in stored order; used both for determinism byte-comparisons and to
  prove non-mutation including element order)
- `ZeroBreach.Diff.Tests/FindingDeltaTests.cs` (10 tests)
- `ZeroBreach.Diff.Tests/CoverageDeltaTests.cs` (6 tests)
- `ZeroBreach.Diff.Tests/ComparabilityTests.cs` (9 tests)
- `ZeroBreach.Diff.Tests/DeterminismTests.cs` (6 tests)

**Build/test:** 31/31 green on Linux, zero warnings (`dotnet test
ZeroBreach.Diff.Tests/ZeroBreach.Diff.Tests.csproj`), re-verified 2026-08-26. Every test
in the brief's minimum list is present, plus duplicate-id rejection, clock skew,
null-vs-empty property bags, failed-diff non-mutation, and a 5000-findings-a-side
performance guard.

**Judgement calls.**
- *Changed-vs-new classification.* The join key is `Finding.Id` alone, compared
  **ordinally, case-sensitively** (host ids are opaque; folding case would merge distinct
  ids). Id only in current ⇒ new; only in baseline ⇒ resolved; in both with zero material
  field differences ⇒ persisting (the **current** run's snapshot is what is reported); in
  both with ≥1 difference ⇒ changed, carrying both snapshots plus the field list.
- *What counts as "changed" is wider than BLUEPRINT §11's letter.* §11 says "same id,
  different **severity or description**"; the implementation also treats **category**,
  **target**, and every **property-bag entry** as material, because the task brief
  requires field-by-field change reporting and a severity-only view would hide (e.g.) a
  hash change on a persisting autorun. Property changes are computed over the ordinal
  union of keys; a key present on only one side is reported with `null` on the absent
  side; field names are `"category"`, `"target"`, `"severity"`, `"description"`,
  `"property:<key>"`.
- *Category/target change under a stable id* — the brief's second open question ("should
  be impossible by construction; assert it and flag if otherwise"). Implemented exactly
  that way: since the id hashes over category and target, such a change means the host's
  identity contract is suspect, so it is reported as a change **and** flagged with an
  explicit "identity contract may be broken" warning naming the finding — never silently
  trusted, never dropped. Pinned by `TargetChangeUnderStableId_ReportedAsChanged_AndContractWarned`.
- *Timestamps never participate in change detection.* The timestamp lives on the
  `RunRecord`, not the `Finding`, precisely so re-observing an unchanged artifact cannot
  look like a change.
- *Null and empty property bags are equivalent* — treating them as different would report
  a phantom change every time the host normalises one to the other. Pinned.
- *Different machine is `Failed`, not a warning* (BLUEPRINT §11 hard requirement), with an
  error naming both machine ids, and **no partial output**: every list including
  `Warnings` is empty on refusal. Machine ids compared ordinally/case-sensitively (if the
  host's ids are case-insensitive, the host normalises them — flagged below).
- *Duplicate finding id or check id in either record is also `Failed`* — this goes beyond
  the brief. Rationale: the ids are the join key; a duplicate means the host's identity
  contract is broken, and a diff over a broken join key is untrustworthy in **both**
  directions (arbitrarily picking one duplicate could manufacture or suppress deltas).
  Loud refusal beats a quietly wrong answer, per the package's core rule. The error names
  which record ("baseline"/"current") and which id.
- *"Narrower" is judged from the check inventory, not the mode string* — the brief's
  first open question, implemented as its recommended assumption (any check in the
  current inventory absent from the baseline's), **assumed, not owner-confirmed**. The
  warning names the missing check ids and states the consequence ("findings from these
  checks will all appear as new"). A mode-**string** mismatch is a separate advisory
  warning only — a renamed or lying label cannot hide narrowness, and matching labels
  cannot fake comparability. The empty-baseline case (everything new) deliberately also
  fires the narrower warning: it is the extreme of the same situation. Both directions
  pinned (`NarrowerBaseline_WarnsNamingMissingChecks_DetectedFromInventoryNotModeString`,
  `ModeStringMismatch_Warns_EvenWhenInventoriesMatch`).
- *Coverage delta semantics.* `Completed` is the only status meaning "the answer is
  trustworthy", so **Regression** = was `Completed`, now anything else (`Inconclusive`
  *or* `NotRun`); **Improvement** is the reverse. `Inconclusive ↔ NotRun` is
  **deliberately not reported**: neither side had visibility, so nothing about what the
  technician can trust changed — pinned by `InconclusiveToNotRunAndBack_NotReported`.
  Checks entering/leaving the inventory are their own kinds (**Added**/**Removed**) with
  `null` status on the absent side, rather than being forced into
  regression/improvement. Host-recorded reasons ("access denied to hive", "disabled by
  policy") are carried through on both sides. Coverage deltas are computed and emitted
  even when every finding list is empty — the false-all-clear guard, pinned by
  `CompletedToInconclusive_IsRegression_EvenWithZeroFindingChanges`.
- *Staleness is measured against the current run's timestamp, not wall-clock now* — no
  `DateTime.Now` in a result: the answer to "was the baseline too old when this run was
  taken" must not change with when the diff is computed, or determinism dies. Null
  `MaxBaselineAge` disables the check entirely (no built-in default threshold — that is
  policy, and it belongs to the caller).
- *Baseline newer than current* ⇒ a clock-skew warning ("clock skew, or the runs may be
  swapped"). A negative age also **suppresses the staleness check** for that pair (the
  skew warning replaces it) — a nonsense age compared against a threshold would be noise
  on top of the real problem.
- *Warning ordering is fixed and deterministic*: skew/staleness, then mode mismatch, then
  narrower-inventory, then id-contract warnings sorted ordinally (they are generated
  during the finding join, whose dictionary order is not guaranteed, hence the sort).
- *`OperationState.Incomplete` exists but is never produced.* Diffing is a pure
  structural join with no budget and no partially-parseable input — there is no
  truncation path, so no budget canary is required or possible here (the CLAUDE.md canary
  rule applies to modules that *match under a budget*; this one does not). The enum
  member is kept so the tri-state shape matches the rest of the package, and the XML doc
  on the enum says exactly this.
- *Performance*: dictionary joins are O(n + m); the only super-linear step is the final
  ordinal sort of each output list. `LargeInputs_DiffCompletesQuickly` (5000 findings a
  side, 200 checks) guards against an accidental quadratic join, with a deliberately
  generous 5 s bound so it cannot flake on a slow runner.

**Fail-on-revert evidence.** Four targeted mutations were applied to `BaselineDiff.cs`,
each observed to fail the tests guarding it, then reverted (backup via `cp`; this folder
is not a git repo):
1. machine-id hard error removed ⇒ the different-machine refusal tests fail;
2. coverage-regression emission removed ⇒ the regression tests fail;
3. changed-vs-new classification broken ⇒ the changed/new set tests fail;
4. deterministic-ordering sort removed ⇒ `ShuffledInputOrder_ProducesIdenticalOutput`
   and `OutputsAreSortedOrdinallyById` fail.
After the fourth check, `BaselineDiff.cs` was verified **byte-identical to its pristine
backup**, so no mutation was left behind (this was re-confirmed after the machine reboot
that interrupted the original session — see `CONTINUE.md` §3). Not every one of the 31
tests' assertions was individually mutation-verified; the four above cover the
highest-stakes guards. A `dotnet stryker` run is the way to close the remainder if wanted.

**What could not be verified, and what would verify it** (BLUEPRINT §12).
- *No real host run records exist yet.* Every fixture is synthetic. The load-bearing
  assumptions about the host's contract — finding/check ids unique within a record, the
  id genuinely hashing over category + target + discriminator, machine ids stable and
  case-consistent across visits — are enforced or relied upon here but cannot be proven
  from this side. **Verify by**: once the host emits real `RunRecord`s, diff two
  consecutive real runs of one machine and confirm (a) zero duplicate-id refusals, (b)
  zero "identity contract may be broken" warnings, (c) an unchanged machine diffs to
  all-persisting.
- *Two semantic choices need owner sign-off* (assumed per the brief, not confirmed):
  the inventory-based definition of "narrower", and the non-reporting of
  `Inconclusive ↔ NotRun` transitions. Both are one-line changes if the owner wants them
  otherwise; each has a pinning test that would go red.
- *Real-world scale/latency on a technician's laptop* — the 5000-a-side test bounds
  algorithmic complexity on this machine only; not simulated further, per §12.

**Wanted outside my scope** (findings, not licences):
- The same as A4's third point, now with a fourth copy: `OperationState` is re-declared
  per project because the integration rules forbid a shared project. A future
  `ZeroBreach.Core` should own the BLUEPRINT §2 types; note D2's copy documents that
  `Incomplete` is unused here, which a shared type's doc comment could not say — a small
  per-project remarks section would be needed.
- The host should always record a `Reason` on non-`Completed` checks; the coverage-delta
  output carries it faithfully, and a regression with a null reason is far less
  actionable for the technician at the desk.
- Whatever renders `DiffResult` must surface `Warnings` (especially the narrower-baseline
  and id-contract ones) alongside the finding sets, not below the fold — a rendered
  "2 new findings" with a suppressed "baseline was narrower" warning recreates exactly
  the misleading diff this engine exists to prevent.

---

## D3 — Configuration baseline evaluator (`ZeroBreach.Baseline`)

Status: **complete.** `dotnet test ZeroBreach.Baseline.Tests/ZeroBreach.Baseline.Tests.csproj`
— **118/118 green, zero warnings** (warnings-as-errors on), net8.0 on Linux, no packages
beyond xUnit. Do not verify via the solution file: the A5 Sigma break in `ZeroBreach.Rules`
still fails `fable-work-2.sln` and is unrelated to this task.

This task was resumed after a crash: the library (9 files, ~1300 lines) was already on disk
and its designs were kept as-is. The resume session found the JSON loader actually complete,
added one rule to it (empty `checks` array is rejected — see judgement call 1), and wrote the
entire test suite, the mutation checks, and this handoff.

### What it is

A pure join: a declarative **check table** (what each setting should be) × the host's
**observations** (what was actually read) → one **result per check**, each Compliant /
NonCompliant / NotApplicable / Undetermined, plus a rollup of the four counts. No machine
access, no mutation of either input, deterministic output in table order.

- **Model** — `SettingValue` (discriminated integer/boolean/string), `BaselineCheck` /
  `CheckTable`, `AbsenceRule` (compliant / nonCompliant / means-default(X)),
  `CheckComparison` (equals, not-equals, at-least, one-of, none-of), `SettingObservation`
  (present / absent / read-failed), per-instance observation maps, `MachineContext` +
  `ApplicabilityCondition`.
- **`CheckTableValidator`** — rejects a defective table before anything is evaluated:
  duplicate/blank ids, blank title/settingKey/remediation, severity or any enum outside its
  set, comparison/absence-default value kind disagreeing with the declared type, at-least on
  a non-integer check, empty one-of/none-of lists, string check without declared case
  sensitivity, multi-instance check without an empty-collection rule, empty applicability
  predicate. All defects reported (not just the first), attributed by check id or by
  `checks[i]` position when the id itself is blank.
- **`BaselineEvaluator`** — validation gate (a bad table evaluates NOTHING: Failed state,
  empty results, **null** rollup), then per-check evaluation.
- **`CheckTableJsonLoader`** — strict loader for the JSON format this library defines
  (documented in the file header). Unknown/duplicate properties, wrong JSON types, unknown
  enum strings, and cross-type value coercion (`"14"` for an integer check) are all loud
  errors with `checks[i].field` positions; JSON syntax errors carry one-based line/position.
  Semantic validation runs at load too, so a bad table fails at load, not at first use.

### Exact file list

Library (`ZeroBreach.Baseline/`) — written pre-crash, kept; one addition marked:

- `ZeroBreach.Baseline.csproj`
- `AbsenceRule.cs`, `Checks.cs`, `Comparison.cs`, `Observations.cs`, `Results.cs`,
  `SettingValue.cs`, `BaselineEvaluator.cs`, `CheckTableValidator.cs`
- `CheckTableJsonLoader.cs` — **modified in resume**: added rejection of an empty
  `checks` array (~6 lines). Everything else untouched.

Tests (`ZeroBreach.Baseline.Tests/`) — all written in the resume session except the csproj:

- `ZeroBreach.Baseline.Tests.csproj` (pre-existing)
- `GlobalUsings.cs`, `TestData.cs`
- `EvaluatorCoreTests.cs` (10), `ComparisonTests.cs` (13), `AbsenceRuleTests.cs` (7),
  `MultiInstanceTests.cs` (9 incl. theory rows), `ApplicabilityTests.cs` (6),
  `ValidatorTests.cs` (27), `JsonLoaderTests.cs` (40), `DeterminismTests.cs` (4)

Plus this file, `HANDOFF_D3.md`, at the repo root.

### The brief's test list — where each item is pinned

| Brief item | Test |
|---|---|
| each of the four results produced | `EvaluatorCoreTests.AllFourResultsAreProduced_…` |
| every comparison operator | `ComparisonTests.*` |
| at-least passing on a stricter value | `AtLeast_PassesOnStricterValueThanExpected` |
| all three absence rules | `AbsenceRuleTests.*` |
| missing under "default is X" evaluates against X | `AbsenceMeansDefault_EvaluatesAgainstTheDefault_NotAgainstAbsence` (both directions: default strict enough passes, default too lax fails) |
| undetermined never counted as compliant | `ReadFailure_IsUndetermined_…`, `UndeterminedIsCountedSeparately_…`, mutation M1 |
| no exposed pass-rate that hides it | `NoExposedPassRate_ThatCouldAbsorbUndetermined` (reflection over the result surface) |
| multi-instance 2-of-5 bad, naming exactly those two | `TwoOfFiveInstancesBad_FailsNamingExactlyThoseTwo` |
| multi-instance all comply | `AllInstancesComply_Passes` |
| empty-collection decision | `EmptyInstanceCollection_FollowsTheCheckDeclaredRule` (theory over all three rules) |
| applicability neither pass nor fail | `NonMatchingContext_YieldsNotApplicable_CountedAsNeitherPassNorFail` |
| case-sensitive vs insensitive disagree on same input | `CaseSensitiveAndInsensitiveChecks_DisagreeOnTheSameInput` (+ inside one-of/none-of) |
| every table validation rejects rather than evaluates | `ValidatorTests.*`, `BadTable_EvaluatesNothing_FailedStateEmptyResultsNullRollup` |
| determinism across repeated runs | `DeterminismTests.RepeatedRuns_…`, `DictionaryInsertionOrder_…` |
| neither input mutated | `DeterminismTests.NeitherInputIsMutated` |

### Mutation (fail-on-revert) checks

13 mutations, each applied to a `cp` backup'd file, test run, then restored and verified
byte-identical with `cmp`. Every one was caught by at least one targeted failing test;
final pristine run 118/118.

| # | Mutation | Caught by (representative) |
|---|---|---|
| M1 | read-failed → Compliant | 5 tests incl. `ReadFailure_IsUndetermined_NeverCompliant` |
| M2 | absence-means-default blindly passes | `AbsenceMeansDefault_EvaluatesAgainstTheDefault_…` |
| M3 | at-least → strict equality | 9 tests incl. `AtLeast_PassesOnStricterValueThanExpected` |
| M4 | failing instance ids dropped from reason | `TwoOfFiveInstancesBad_FailsNamingExactlyThoseTwo` |
| M5 | instance-outcome sort removed | `InstanceOutcomes_AreSortedByInstanceIdOrdinal_…`, determinism |
| M6 | declared case sensitivity ignored | both case-sensitivity tests |
| M7 | validation gate bypassed | `BadTable_EvaluatesNothing_…` |
| M8 | duplicate-id rule dropped | validator + loader duplicate tests |
| M9 | unknown JSON properties accepted | `UnknownCheckProperty_Fails_SoATypoCannotDisableAField` |
| M10 | empty `checks` array loads | `EmptyChecksArray_Fails_NeverLoadsAsATableWithNoChecks` |
| M11 | NotApplicable counted into Compliant | rollup tests |
| M12 | observed type mismatch → Compliant | both type-mismatch tests |
| M13 | string case-sensitivity validation dropped | validator + loader tests |

Two mutation attempts did not compile (one invalid C#, one hit `TreatWarningsAsErrors` via
CS0162 unreachable code); both were redone as compilable semantic mutations (M2, M7 above),
so every counted mutation is a genuine behaviour change caught by an assertion.

### Judgement calls (each pinned by a test)

1. **An empty `checks` array fails to load.** The task rules say a malformed table must never
   load as "a table with no checks"; a shipped file with zero checks verifies nothing and its
   output reads like a clean run, so the loader rejects it as an authoring mistake.
   *Asymmetry, deliberate:* an in-memory `CheckTable` with zero checks still validates and
   evaluates (to an honest all-zero rollup with `Total = 0`) — a caller that filters checks
   programmatically may legitimately reach zero, and the zero total is in front of them.
   Loader-only strictness targets the human-edited artifact.
2. **A setting key entirely missing from the observations is Undetermined**, distinct from an
   explicit `Absent` observation. Absent is a fact about the machine (the absence rule
   applies); never-reported means nothing was verified — even when absence is declared
   compliant (`ExplicitAbsent_IsDistinctFromNoObservation`).
3. **Instancing shape mismatches are Undetermined** — a single-instance check whose key shows
   up only per-instance (or vice versa) is a collection defect, not evidence either way.
4. **Observed type ≠ declared type is Undetermined**, same reasoning; the JSON loader
   additionally refuses type coercion in the table itself (no `"14"` for an integer).
5. **Multi-instance mixing:** any definite instance failure ⇒ NonCompliant, with unreadable
   instances still surfaced in the reason and outcomes (a finding must not hide a coverage
   gap); no failures but ≥1 unreadable instance ⇒ Undetermined, never a pass. Instance
   outcomes list only non-compliant/undetermined instances, sorted ordinal by id.
6. **Empty instance collection is a required per-check declaration** (compliant /
   nonCompliant / undetermined) — validated, no default, because zero shares is trivially
   fine while zero network interfaces means the probe went wrong.
7. **Applicability:** missing context key ⇒ predicate false ⇒ NotApplicable; key/value match
   is ordinal-ignore-case (roles are identifiers); NotApplicable is decided before the
   comparison and takes precedence over a missing observation.
8. **String comparison is ordinal in both modes** — never culture-sensitive; pinned with the
   Turkish dotless-i corner (`ı` ≠ `i` even under OrdinalIgnoreCase).
9. **No pass rate anywhere on the result surface** — `RollupCounts` exposes the four counts
   and their sum only; a reflection test rejects any member named like rate/percent/ratio/
   score/passed/compliance appearing on `RollupCounts` or `EvaluationResult`.
10. **`ObservedValue` stays null when the absence default was compared** — reporting the
    default as observed would fabricate a reading the host never made.
11. **`Incomplete` is never produced by this evaluator** (defined in `EvaluationState` for
    package uniformity). Evaluation is a pure in-memory join with no budget-consuming step,
    so the BLUEPRINT §3 budget/canary requirement does not attach here; there is nothing to
    budget and no pattern matching that could be pathological. If a future comparison ever
    grows a regex or glob, it must gain a budget and a canary at that point.
12. **Brief's open questions:** value type model is the discriminated `SettingValue` (the
    prior agent's choice, kept — mismatches are first-class detectable states, worth the
    extra code). Check-on-check dependencies: **not supported**, recorded as a limitation.
    Range comparison: **not added** (needs owner confirmation of a real case; at-least +
    a not-exceeding bound would compose into one comparison if confirmed). Table format:
    JSON, loader in this project; populating it with real content is not this task.

### What could not be verified here, and what would verify it

- **Real check tables and real host observations.** Everything ran against authored
  fixtures. Verification: load the provider's actual table through `CheckTableJsonLoader`
  and eyeball the error list (it should be empty), then evaluate one real machine's
  observation dump and review the per-check reasons with a technician.
- **The observation key comparer contract.** Lookup uses the dictionaries' own comparers
  (documented on `BaselineObservations`); the host must build them OrdinalIgnoreCase if its
  setting keys need it. Not verifiable from here — worth a one-line check in the host's
  wiring code.
- **Performance at a few hundred checks × a few thousand instances.** The join is linear in
  checks + instances plus an O(k log k) sort of failing instances, so this is safe by
  construction, but no benchmark was run.

### Wanted outside this project (findings, not licences)

- Nothing edited outside `ZeroBreach.Baseline*/`. One wish: the shared tri-state enum
  (`Ok/Incomplete/Failed`) is now declared per-project across the package (`EvaluationState`
  here, `OperationState` in Intel/Paths/Formats). A single shared `ZeroBreach.Common` type
  would remove the drift risk at merge time — owner's call.
