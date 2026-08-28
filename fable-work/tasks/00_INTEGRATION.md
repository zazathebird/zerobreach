# 00 — Integration protocol

Read this before starting any task.

## The rule that makes parallel work possible

**Every deliverable in this package is a new file.** Not one task edits a file that already
exists in the parent tree. That is not a stylistic choice — it is the entire reason two sessions
can run at once, and it makes the merge a `git add` rather than a negotiation.

If a task looks like it needs an edit to an existing file, that is a finding, not a licence.
Write it up in `HANDOFF_FABLE.md` with the exact file, line and change, and move on. The main
session applies it in one commit when nobody else is holding the file.

### Files that are never yours

```
Scythe-V23.ps1          the loader
Scythe-Server.ps1       the server
engine/*.ps1                the scan modules
data/detection_signatures.json
gui/templates/index.html
tools/Build-Release.ps1
tools/tests/Run-SecurityTests.ps1
_python/server.py
```

Read them freely. Do not write them.

## What you hand back

```
<the files each task lists under Deliverables>
HANDOFF_FABLE.md            one entry per task
```

`HANDOFF_FABLE.md` is the merge instruction sheet. Per task:

- what you built, in two or three sentences
- the exact file list, with new-file paths relative to the project root
- **what you could not verify from Linux, and what would verify it on Windows** — be specific
  enough that someone with a Windows box can run the check without reading your code
- any change you wanted to make to a file you were not allowed to touch, with line references
- any assertion you could not prove fails-on-revert, and why

## Validating from here

Development is on Linux; the target runtime is Windows PowerShell 5.1. What you can and cannot
prove from this box:

**Can:** that everything parses under `pwsh` 7; that the BOM is intact; that JSON is well-formed
and its regexes compile; that pure-logic functions behave; that AST-based tests find what they
claim to find; that generated HTML is well-formed and its inline script parses.

**Cannot:** anything touching the Windows registry, the process table, the event log, scheduled
tasks, file ACLs, code-signature verification, or COM. Nor the PS 5.1 parser itself — several of
its behaviours (the single-element unwrap, `try/catch` as a sub-expression) only surface on the
real runtime. **Do not simulate these and report the simulation as a result.** Write down what
needs a Windows box.

A `pwsh` binary may already exist under the session scratchpad from an earlier run; look before
installing one. `find /tmp/claude-1000 -name pwsh -type f 2>/dev/null | head -3`

## Parse and BOM check

Every `.ps1` you ship must pass both:

```powershell
$t=$null; $e=$null
[System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$t, [ref]$e) | Out-Null
if ($e.Count) { $e | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" } }
```

```bash
head -c 3 "$f" | od -An -tx1     # expect: ef bb bf
```

**A caveat that has cost this project real time:** `ParseFile` on a script containing large
here-strings does **not** validate the contents of those here-strings. If you write a here-string
holding code, it needs its own parse check — extract it and parse the extracted text.

## Tests

Every task ships tests, and every assertion must be shown to **fail when the code it guards is
reverted**. An assertion that passes both ways is worse than none, because it is a claim of
coverage that is not there. Where the thing under test is a file you may not edit, prove it on a
copy in a scratch directory.

Prefer extracting the real functions from the shipped source via the AST over restating them in
the test body. A test that carries its own copy of the logic passes forever after the real logic
changes.

## Questions

Ask. A task that is ambiguous about product behaviour — what belongs in a client-facing summary,
whether a tool should overwrite or emit alongside — is cheaper to clarify than to redo. Each
brief ends with the questions already known to be open; there will be others.
