# G5 — parity tests for the two servers and the mirrored tables

**Priority 5. Size: M. New test files only.**

## The problem

Several tables exist in more than one copy on purpose, and they must agree:

- The **mode phase ceilings** (`QUICK 30`, `FULL 80`, `DEEP`/`PARANOID`/`STEALTH` `133`,
  `HUNT 162`) are declared in four places: the engine loader's phase plan, the PowerShell
  server, the parked Python server, and the front-end default.
- The **severity tag table** and the **threat bucket table** exist in both servers. The bracket
  tag the engine prints is authoritative; the prose keywords are a fallback for untagged lines
  only. That distinction is load-bearing — when a prose word was allowed to classify a tagged
  line, a clean scan painted its own progress log red, because the engine prints banner lines
  containing the very words the fallback looks for.
- The **event contract** — the field names in each server-to-client message — must match what
  the front end reads.

Drift in any of these is silent. There is no test today.

## Deliverables

```
tools/tests/Test-ServerParity.ps1
tools/tests/Test-EventContract.ps1
```

Read-only against `ZeroBreach-V23.ps1`, `ZeroBreach-Server.ps1`, `_python/server.py`,
`gui/static/js/app.js`. **Change none of them.** If you find a real divergence, write it up in
`HANDOFF_FABLE.md` with the exact line references and let the main session fix it — a
one-character edit in those files is a merge conflict.

## Method

Extract, do not hardcode. Pull the tables out of the shipped sources — via the PowerShell AST
for the `.ps1` files, and via a targeted regex or Python's own `ast` module for `server.py` —
then compare. A test that restates the expected values in its own body passes forever after
someone changes the code, which is the failure mode this whole suite exists to avoid.

Two traps that have caught people writing tests in this repo:

- In the PowerShell AST, `-match` is the token kind **`Imatch`**, not `Match`, because
  case-insensitive is the default. Searching for `Match` finds nothing and the test passes
  vacuously.
- **One-letter helper function names collide with built-in aliases** and the alias wins command
  resolution. `H` is `Get-History`. Name helpers properly.

Every table your test relies on must actually be **loaded** by the test. An unloaded variable is
`$null`, `-match ''` is true, and the test then agrees for the wrong reason. Assert that each
extracted table is non-empty before comparing.

## Assertions

1. All four declarations of each mode ceiling agree.
2. The mode whitelists in both servers hold the same set.
3. Severity tag tables match between servers, and the padded `[OK ]` form is matched — the
   engine pads that tag and a regex without the trailing space misses every clean line.
4. Threat bucket tables match between servers.
5. Neither server has a bracket tag in its prose table or a prose word in its tag table.
6. Every field the front end reads off an event exists in the corresponding server payload, in
   both servers.
7. Every route the front end calls exists in the PowerShell server's request handler.
8. Every front-end call to an `/api/` path goes through the authenticated wrapper. An
   unwrapped call is rejected at runtime with no useful message, and this has bitten before.

Prove each fails on revert — for the read-only ones, prove it by temporarily editing a copy of
the source in a scratch directory, not the real file.
