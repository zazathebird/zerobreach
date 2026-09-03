# MERGE — handing work back

Work in this folder is done one project at a time and combined afterwards. This file says what
"finished" has to look like for that to be a file copy rather than a negotiation.

## What a finished task hands back

```
Scythe.<Name>/            the library project
Scythe.<Name>.Tests/      its xUnit project
scythe-work.sln                with both projects added
HANDOFF.md                one appended entry
```

Nothing else. No edits to another task's project, no edits to `README.md`, `CLAUDE.md`,
`tasks/` or `reference/` unless the task was to change them — and if it was, run
`python3 tools/check_briefs.py` and confirm it still exits 0.

## What has to be true before it is finished

1. `dotnet build` and `dotnet test` green on Linux, zero warnings, from this folder's
   `scythe-work.sln`. (`export PATH="$HOME/.dotnet:$PATH"` first.)
2. `net8.0`, xUnit only, no other package references.
3. Every assertion shown to fail when the code it guards is reverted.
4. All three fixture classes present: ordinary, awkward-but-valid, malformed.
5. Determinism asserted explicitly: same input twice, byte-identical output.

## What the combining pass needs from your handoff entry

These four are the ones that are expensive to reconstruct later, so write them even when they
feel obvious:

- **The exact new-file list.** This is what makes combining mechanical.
- **Every judgement call** where the specification was ambiguous, what you chose, and why.
  The decision is invisible in the code and costly to rediscover.
- **Which shared types you declared** — the three-state result, `ScanBudget`, the per-project
  state enum — and whether the duplication argued for or against collecting them into one
  `Scythe.Common` later. That is a vote with evidence attached; cast it.
- **What you could not settle from fixtures**, with the exact command or the exact real file
  that would settle it.

## Naming

Keep the `Scythe.` prefix consistent throughout your project — directory names, `.csproj`
filenames, `AssemblyName`, `RootNamespace` and every namespace declaration — and do not hard-code
the namespace as a string anywhere it could drift from the declaration. Consistency here is what
makes combining a copy rather than an edit.
