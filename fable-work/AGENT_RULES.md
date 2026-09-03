# Rules for implementing one Scythe task (read fully before starting)

You are implementing exactly ONE task in the repo at /home/user/Downloads/scythe-work.
Other agents are implementing other tasks in the same folder AT THE SAME TIME, so:

## Hard constraints (concurrency)
1. Create ONLY these two directories and write ONLY inside them:
   `Scythe.<Name>/` and `Scythe.<Name>.Tests/` (the name your brief gives).
2. DO NOT edit `scythe-work.sln`, `HANDOFF.md`, `README.md`, `CLAUDE.md`, `tasks/`, `reference/`,
   `Directory.Build.props`, or any other project. Do not run `dotnet sln add`. Do not `git commit`.
   The coordinator adds projects to the solution, appends handoffs and commits.
3. Write your HANDOFF entry to
   `/tmp/claude-1000/-home-user-Downloads-scythe-work/f99679e2-11b5-43cd-8f4d-4049eeec5335/scratchpad/handoff/<TASKID>.md`
   using the exact entry template in the top of `HANDOFF.md` (heading `## <Task id> — <task title>`,
   then a `*2026-09-02.*` date line, then Status / What was built / Files / Tests / Judgement calls /
   Could not verify / Shared types / Dependencies taken / Wanted to change outside my project).
   Look at the existing Q1 entry in HANDOFF.md (lines 63-285) for the expected depth.
4. Build and test ONLY your own projects, never the whole solution:
   ```bash
   export PATH="$HOME/.dotnet:$PATH"
   cd /home/user/Downloads/scythe-work
   dotnet build Scythe.<Name>.Tests/Scythe.<Name>.Tests.csproj
   dotnet test  Scythe.<Name>.Tests/Scythe.<Name>.Tests.csproj
   ```
   Other agents' builds run concurrently; if a build fails with a transient file-lock or
   "being used by another process" error, just retry.

## What to read (and nothing more)
- `CLAUDE.md` (all of it), `tasks/00_INTEGRATION.md`, `MERGE.md`
- `reference/00_shared.md`
- Your brief `tasks/<TASKID>_*.md`
- The ONE reference file your brief cites (e.g. `reference/04.2_hives.md`), plus the track's
  `*_unverifiable.md` file if it exists (for the "Could not verify" section).
- If your brief takes a project reference on another Scythe project (only the edges in the README
  graph), read that project's public types to use them correctly.
- Existing `Scythe.Time/` and `Scythe.Text/` are finished examples of the expected style, csproj
  shape, test layout and handoff depth. Copy the csproj shapes exactly.
- Do NOT read anything outside the repo folder. No network access exists.

## Toolchain facts
- `dotnet` is at `~/.dotnet` (SDK 8.0.424). `export PATH="$HOME/.dotnet:$PATH"`.
- No network: the test csproj MUST pin exactly
  `Microsoft.NET.Test.Sdk 17.8.0`, `xunit 2.6.6`, `xunit.runner.visualstudio 2.5.6`. No other packages.
- `Directory.Build.props` already sets net8.0, C# 12, Nullable, ImplicitUsings,
  TreatWarningsAsErrors, Deterministic, InvariantGlobalization. Your csproj only sets
  AssemblyName/RootNamespace (and IsPackable=false + references for the test project). Match
  `Scythe.Time/Scythe.Time.csproj` and `Scythe.Time.Tests/Scythe.Time.Tests.csproj` exactly.
- Test projects include an `AssemblyInfo.cs` with `[assembly: CollectionBehavior(DisableTestParallelization = true)]`.
- Zero warnings. XML doc comments are welcome but not required; if you add `<summary>` on some
  public members you do not need them on all (GenerateDocumentationFile is off).

## Shared types (declare your own copy, identical shape)
Every project declares its own `ScanBudget` and a three-state result. Copy the shapes from
`Scythe.Time/ScanBudget.cs` and `Scythe.Time/TimeResult.cs` verbatim, renaming `TimeResult` /
`TimeResultState` to `<Prefix>Result` / `<Prefix>ResultState` for your project (e.g. `HiveResult`,
`HiveResultState`). Same members, same order, same semantics: `Ok(value)`,
`Incomplete(partial, reason)`, `Failed(message, position)`, `State`, `Value`, `Reason`,
`Position`, `IsOk`.

## Correctness bar (from CLAUDE.md / 00_shared.md — non-negotiable)
- `Incomplete` is never `Ok` with fewer results. Every truncation, budget exhaustion, unsupported
  variant and unrecognised version returns Incomplete with a reason.
- Never throw for an expected outcome; malformed input never throws (wrap nothing in
  try/catch-all as a substitute for bounds checking — validate every offset/length before slicing,
  through one bounds-checked reader type).
- Track visited offsets to refuse cycles. Output ceilings on any expansion. Model
  absent / zero / sentinel distinctly.
- Deterministic: ordinal sorts, no DateTime.Now, no unseeded randomness.
- No file-system, process, network or OS API access in the library. Target net8.0 only.
- Result member names say what a thing IS, never a verdict (`IsValid`, `Trusted`... forbidden).
- Where the brief or reference is ambiguous about a layout, epoch or version difference, you
  CANNOT ask a human. Choose the option that declines to answer (Incomplete / unknown / report
  the version) over the option that guesses, and record it under "Judgement calls".

## Tests (all required)
- Fixture BUILDER (programmatic), not checked-in binary files. Three classes: ordinary,
  awkward-but-valid (the corners your reference section names), malformed (truncated, lying
  lengths/counts, cycles, absurd values, deep nesting).
- Budget canary tests: pathological input known to trip each budget dimension, asserted Incomplete.
- Round-trip determinism: same input twice, byte-identical serialised output asserted.
- Direct assertions that truncation / unknown-version paths are `Incomplete`, not `Ok`.
- Each assertion must fail when the code it guards is reverted. Actually do this for the guards
  and canaries (mutate the guard, watch the test go red, restore) and say in the handoff which
  ones you verified this way.
- Aim for the depth of the existing Q1/Q2 suites (roughly 100+ tests for an L task, 60+ for M).

## Finish
Run the build and test commands above until green with zero warnings. Then write the handoff
file (step 3). Your final message to the coordinator should be SHORT: the task id, test count,
the two directories created, any project references taken, and anything you could not complete.
