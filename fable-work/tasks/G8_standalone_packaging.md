# G8 — standalone packaging: design study and prototype

**Priority 8. Size: L. Design first, prototype second. Supersedes the earlier F8 draft.**

The stated product goal is to ship as a single application rather than a tree of scripts a
technician has to unzip. This brief is deliberately a **study before a build**, because the
difficulty is not the packing step — it is what the packing step breaks.

## Deliverables

```
fable-work/PACKAGING_STUDY.md         the written analysis, first and most important
tools/prototype/Build-SingleFile.ps1  a prototype, only after the study
tools/tests/Test-PackagingContract.ps1
```

Do not modify `tools/Build-Release.ps1`. It is the working release path and it belongs to the
main session. The prototype is a parallel experiment.

## What the study must cover

**1. Reputation.** A brand-new unsigned executable that enumerates processes and modifies system
configuration is, to every endpoint protection product on the market, indistinguishable from
something worth quarantining. Without a code-signing certificate and accumulated reputation,
expect the tool to be blocked on arrival at a client site. This is the dominant risk and it is
commercial rather than technical. Cost it out: certificate type, validation timeline, what
reputation accrual actually requires, and what the interim experience looks like.

**2. Path resolution.** The tool resolves its data files, its modules and its output directory
relative to the script root. Packed, there is no script root. A single global already exists as
the choke point for the project root, which is most of the work — but every path expression in
the launcher needs auditing against a packed layout, and the output directory in particular must
land somewhere the technician can find it, not inside a temporary extraction folder that
disappears.

**3. The data-file boundary.** The engine deliberately keeps its rule content in `data/*.json`
rather than inline in the scripts, because content embedded in a script is inspected at load
time by the platform's script-scanning interface and script-shaped rule text has previously
caused the whole engine to be blocked before it produced a single line of output. Any packaging
approach that embeds those files back into a script body reintroduces that failure, and the
failure mode is silent: the tool appears to run and finds nothing. Establish whether the
candidate packer keeps them as separate files on disk at runtime. **If it does not, the approach
is disqualified** — say so plainly rather than proposing a workaround.

**4. Elevation and the console.** The launcher self-elevates and the server reads the engine's
standard output line by line with a fixed text encoding on both ends. Packing changes how the
console is attached and how the child process is created. Establish what happens to the redirect
and to the encoding agreement; a mismatch on either side turns the live output into unreadable
characters, and a broken redirect makes the run look dead.

**5. Update path.** Today an update is a new zip. Packed, decide: replace the executable, or
keep the rule data outside it so content updates do not require a new binary? The second is
almost certainly right, and it interacts with item 3.

**6. Candidates.** Evaluate at least: keeping the current zip-plus-launcher, script-to-executable
conversion, a self-extracting archive, and a real host application. For each: reputation impact,
whether item 3 survives, build complexity, update story, and what a technician sees on first
run. **A recommendation to change nothing is a valid outcome** if that is what the analysis
supports — say so and show the reasoning.

## The prototype

Only after the study, and only for the recommended option. It must produce something that runs,
finds its data files, writes its output where the study says it should, and streams output
correctly. Verifying that on Windows is the main session's job; your job is to make it obvious
what to check. List those checks explicitly at the end of `PACKAGING_STUDY.md`.

## Tests

`Test-PackagingContract.ps1` runs on Linux and asserts the properties the study identifies as
load-bearing:

1. Every path expression in the launcher resolves through the project-root global rather than
   the script-root automatic variable.
2. The rule data files are staged as separate files, not embedded.
3. The staged file list contains everything the runtime needs — enumerate what the launcher and
   server open, and assert each is staged.
4. The encoding agreement is declared on both sides of the process boundary.

Prove each fails on revert.
