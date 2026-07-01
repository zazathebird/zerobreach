# .handoff — continue this project on another machine

Everything Claude Code needs to resume *exactly* where we left off. The code travels with git;
this folder carries the two things that normally don't: the **session memory** and a **one-page
state summary**.

## Steps on the new PC

1. **Clone / pull** the branch that has the latest work:
   ```powershell
   git clone https://github.com/zazathebird/zerobreach.git
   cd zerobreach
   git checkout quarantine-work-dump-20260616-151402
   ```
   (This branch — NOT `main` — is the tip. See "Branch" below.)

2. **Restore the Claude Code session memory** (so the assistant loads all prior context/decisions):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .handoff\restore-memory.ps1
   ```
   It copies `.handoff/session-memory/*.md` into `%USERPROFILE%\.claude\projects\<path-hash>\memory\`,
   computing the same path-hash Claude Code uses — so it works wherever you cloned.

3. **Start Claude Code** in the repo. `MEMORY.md` (the index) plus the WS0/WS1/WS2 and engine-split
   notes load automatically. Then read **`../HANDOFF_WS1_WS2.md`** (repo root) for the current state
   and the prioritized next step.

## Where things stand (short version)

- WS1 (externalize signature name-lists) and WS2 (detection-coverage expansion: loaders, banking
  trojans, infostealers, 2024-25 ransomware, modern C2, BYOVD) are **done and pushed**.
- Big finding: **phases 67–115 had never run in headless `-Auto` mode** (a Phase 66 bug aborted every
  scan there). Fixed 3 back-half bugs; the engine now reaches ~Phase 76.
- **Next task:** finish the full headless run clean through Phase 115 (fix the tail of pre-existing
  `-ErrorAction Stop`/null bugs in phases 75–115). Details + method in `HANDOFF_WS1_WS2.md`.

## Notes

- `session-memory/` is a **point-in-time snapshot** (2026-07-01). If you keep working on the original
  machine, its live memory will drift ahead of this copy; re-snapshot before the next handoff.
- The engine is the **split/modular** form: thin loader `ZeroBreach-V23.ps1` dot-sourcing
  `engine/Phases-1|2|3.ps1`, `engine/Summary.ps1`, `engine/FixMode.ps1`.

## Branch

Work is on **`quarantine-work-dump-20260616-151402`**, not `main`. If you'd rather continue on `main`,
merge/PR it first (this session deliberately did not touch `main`).
