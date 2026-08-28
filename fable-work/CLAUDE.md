# CLAUDE.md — fable-work

Project instructions for a session opened with **this folder as its working directory**.

## What this folder is

`fable-work/` is a **parallel work package** for Scythe V23, a Windows endpoint
audit-and-reporting tool for a managed-service provider. The main session works in the parent
tree; this package holds work that does not touch any file the main session is editing, so both
can run at once and the results merge cleanly.

The work in `tasks/` is **product and infrastructure work**: reporting, the operator UI, run
timing, packaging, test tooling and the parked Python server. None of it requires reading or
writing the detection modules.

## Scope rules

- **Stay inside the file list each task names under "Deliverables".** If a task seems to need a
  file outside that list, stop and say so rather than widening scope.
- **Do not open `tasks/_deferred/` or `reference/_deferred/`.** Those hold a different work
  package that belongs to the main session; reading them here wastes context and creates merge
  conflicts. A `README.md` in each explains what they are.
- **Do not edit `engine/`, `Scythe-V23.ps1` or `data/detection_signatures.json`** in the
  parent tree. Those are the main session's.

## The runtime, and the four traps that actually bite

Target runtime is **Windows PowerShell 5.1**. Development happens on Linux, so everything must
also parse under `pwsh` 7. Four PS 5.1 behaviours have each cost this project a shipped bug:

1. **Variables are case-insensitive.** A local `$sev` silently shadows a script-scope `$SEV`
   hashtable; `$SEV.Keys` then reads a *string* and returns `$null` with no error.
2. **`try/catch` is statement-only.** `(try{...}catch{...})` as a sub-expression parses under
   PS 7 and throws at runtime on 5.1. Restructure with early returns.
3. **A single-element array unwraps to a scalar.** `(fn ...)[0]` therefore indexes the first
   *character of a string*. Write `@(fn ...)[0]`.
4. **A backtick immediately before a closing double-quote escapes it** and the string never
   terminates. Do not put backtick-quoted inline commands inside a double-quoted string.

Every `.ps1` in this project is saved **UTF-8 with BOM**, LF line endings. Removing the BOM
breaks the launcher. Copy the byte prefix from an existing file.

## Style

- PowerShell files use `Verb-Noun` function names and 4-space indent.
- Front-end code lives in `gui/static/js` and `gui/static/css`; it is vanilla ES2019, no build
  step, no package manager, and **no remote origins** — assets are vendored locally and the page
  CSP pins to `'self'`.
- Match the comment density of the file you are editing.

## Definition of done

1. Everything parses clean under both parsers, BOM intact where it applies.
2. Tests ship with the change, and **you have shown each new assertion fails when the code it
   guards is reverted.** A test that passes for the wrong reason is worse than no test.
3. A short `HANDOFF_FABLE.md` entry: what you built, what you could not verify from Linux, and
   what needs a Windows box.

## Ask, don't assume

If a task is ambiguous about product behaviour — what a report should contain, what an operator
should see — ask. Guessing produces work that has to be redone.
