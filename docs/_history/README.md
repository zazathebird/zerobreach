# _archive/

Superseded/historical files, kept rather than deleted. See `SECURITY_AUDIT_2026-08-18.md` at the
repo root for the full reasoning behind each move.

- `NEXT_STEPS.md`, `UPGRADE_PLAN.md` — self-marked superseded 2026-07-02; BLUEPRINT.md §7 is now
  the authoritative roadmap.
- `NIGHT_RUN_PLAN.md` — one-time overnight test-run plan, fully executed.
- `TIME_LOG.md` / `.csv` / `.xlsx` — dated git-log-derived time estimate, generated 2026-07-03,
  not updated since.
- `claude working files` — empty stray file, no known content or references.
- `scythe-main-dump/` — everything that was in the untracked `scythe-main/` folder dropped
  into the repo root on 2026-08-18. Turned out to contain no source code (no Cargo.toml, no .rs
  files) — only a Rust/Tauri build cache and two real client scan-report HTML files. **Gitignored**
  (see `.gitignore`) — the build cache is 335MB of reproducible compiler output, and the reports
  contain real machine data (paths, hostname, installed software) that shouldn't be pushed to a
  remote. Kept locally per instruction, for later verification against the source PC.
