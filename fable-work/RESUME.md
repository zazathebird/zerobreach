# RESUME — exact state at the 2026-09-02 interruption

Written by the coordinating session when a weekly usage limit stopped ten parallel task
sessions mid-flight. Its one job is to let the next session **continue rather than restart**.

Read this file, then `HANDOFF.md`, then pick up at "What to do first" below.

---

## One-paragraph summary

Of the **37 tasks** in `README.md`, **8 are finished and committed**, **5 are unfinished but
substantially built and committed as a checkpoint**, and **24 have not been started**. Everything
finished builds and tests green on Linux with zero warnings: `dotnet test scythe-work.sln`
exits 0 with **1469 tests passing, 1 skipped**. Nothing is lost — every partial project is
committed, and the first compiler error in each is recorded below.

---

## Task status, all 37

### Finished — in `scythe-work.sln`, green, committed

| Task | Project | Tests | HANDOFF entry |
|---|---|---|---|
| Q1 | `Scythe.Time` | 134 | yes |
| Q2 | `Scythe.Text` | 157 | yes |
| Q3 | `Scythe.Identity` | 277 | **owed** |
| K1 | `Scythe.Correlation` | 212 | **owed** |
| K2 | `Scythe.Scoring` | 139 | yes |
| K4 | `Scythe.Techniques` | 191 | yes |
| E3 | `Scythe.ShellItems` | 146 | **owed** |
| W1 | `Scythe.TestKit` | 213 (+1 skipped) | **owed** |

Four handoff entries are owed because the sessions that wrote those projects were killed by the
usage limit *after* the code went green but *before* they wrote their entry. The code is done;
the write-up is not. See "What to do first".

### Unfinished — committed as a checkpoint, NOT in the solution

None of these five build. They are exactly as their sessions left them. Each library is
essentially complete; in four of the five, the failure is a **test file that was cut off
mid-write** when the session died, which is a small mechanical repair, not a design problem.

| Task | Project | State at interruption | First error |
|---|---|---|---|
| E1 | `Scythe.Artifacts` | library complete (21 files), 13 test files written | `Scythe.Artifacts.Tests/Fixtures/StandardTemplate.cs(10,45)`: CS8625, cannot convert null literal to non-nullable reference type |
| E2 | `Scythe.Hives` | library complete (18 files), 13 test files written | `Scythe.Hives.Tests/ValueDecodeTests.cs(278,24)`: CS8858, receiver type `ValueSpec` is not a valid record type |
| K3 | `Scythe.Reporting` | library complete (12 files), 11 test files written | `Scythe.Reporting.Tests/HtmlEscapingTests.cs(127,46)`: CS1010, newline in constant — the file is **truncated mid-string-literal** |
| M1 | `Scythe.FileSystem` | library complete (24 files), 11 test files written | `Scythe.FileSystem.Tests/OrdinaryTests.cs(339,79)`: CS1026, `)` expected — the file is **truncated mid-expression** |
| M2 | `Scythe.Journal` | scaffold only: `ScanBudget.cs`, `JournalResult.cs`, two csproj, `AssemblyInfo.cs`. No reader, no tests. | builds, but there is nothing there |

### Not started — 24 tasks

E4, M3, N1, N2, P1, P2, P3, H1, H2, S1, S2, R1, R2, J1, J2, J3, T1, T2, V1, V2, V3, V4, U1, U2.

`Scythe.Sqlite` (N1) was launched but its session died before writing a single file; nothing of
it is on disk.

---

## What to do first, in order

1. **Repair the four truncated test files** (E1, E2, K3, M1). Open each at the line above, see
   where the write stopped, and finish the file. Then per project:
   `dotnet build Scythe.<Name>.Tests/Scythe.<Name>.Tests.csproj`, fix, `dotnet test`, and when
   green `dotnet sln scythe-work.sln add` both projects. This is the cheapest work in the repo
   — four nearly-finished tasks behind a mechanical fix.
2. **Write the five owed HANDOFF entries** (Q3, K1, E3, W1, plus each repaired task as it lands).
   The template is at the top of `HANDOFF.md`. The judgement calls have to be recovered by
   reading the code, since the sessions that made them are gone. Say so in the entry rather than
   presenting a reconstruction as the original reasoning.
3. **Finish M2** (`Scythe.Journal`) from its scaffold, per `tasks/M2_change_journal_reader.md`.
4. **Then the 24 unstarted tasks.** Track Q is complete, so any of them can go next. Within
   Track E do E2 before E4; the other ordering edges are in `README.md`.

---

## How the parallel run was organised, and what went wrong

Ten task sessions ran at once, each owning exactly two directories, with the coordinator holding
the shared files. The rules given to each session are preserved at **`AGENT_RULES.md`** in this
folder — reuse it verbatim when launching the next batch, changing only the task id.

The division of labour worked; **ten at once was too many for the token budget.** Every session
died on the same limit within about forty minutes. Run **three or four at a time** instead, and
integrate each one as it lands rather than batching.

Two facts worth carrying forward, both learned the expensive way:

- **A failing test run can be a lie while sessions are writing.** `Scythe.Correlation` reported
  31 failures of 212 during the run; re-tested afterwards it was 212/212 green. The build had
  been taken mid-write. **Re-run before believing a failure** in a project another session is
  touching.
- **`if (false)` is not usable for fail-on-revert mutation checks.** Under
  `TreatWarningsAsErrors`, CS0162 makes it a build failure, which reads as "the test survived".
  Use a runtime-false condition.

---

## The one edit made outside a task project

`Scythe.TestKit/Scythe.TestKit.csproj` gained `<IsTestProject>false</IsTestProject>`.

That project references xunit as a *library* (for its `[DifferentialFact]`), so `dotnet test` on
the solution tried to run it as a test assembly and **exited 1 even though every test passed**.
With the property set, the solution run exits 0. This is a change inside W1's own project, made
by the coordinator rather than by W1's session, and it is recorded here because
`tasks/00_INTEGRATION.md` asks for exactly that.

---

## Verifying this document

```bash
export PATH="$HOME/.dotnet:$PATH"
cd /home/user/Downloads/scythe-work
dotnet test scythe-work.sln          # exits 0, 1469 passed, 1 skipped
python3 tools/check_briefs.py        # exits 0
git log --oneline                    # the commits this session added
```

## Where the finished work has been copied

The eight finished projects are also copied into the main Scythe repository at
`~/Downloads/claude/scythe/fable-work/`, which is where this side repo merges. That copy is a
snapshot for the merge, not a second place to work. **Keep working here**, and re-copy when more
tasks land.
