# F8 — Standalone EXE packaging workstream

**Priority 8.** Size: L. This is a *design + prototype* task, not a detection task.

The stated goal is for Scythe to ship as a standalone application rather than a PowerShell
tree. This brief is the honest version of what that costs, because the cost is not in the packing
step — it is in everything the packing step breaks.

## What actually breaks

1. **AMSI / AV reputation.** A brand-new unsigned EXE that enumerates processes, reads LSASS-
   adjacent registry, walks memory and deletes files **is** what a dropper looks like. Without an
   EV code-signing certificate and accumulated SmartScreen reputation, expect it to be quarantined
   on arrival at client sites. This is the single largest risk and it is commercial, not technical.
   Budget for an EV cert.
2. **`$PSScriptRoot` disappears.** The engine resolves `data\*.json`, `engine\*.ps1` and
   `reports\` relative to it. A packed EXE needs an explicit extraction/asset root. `$global:SCYTHE_ROOT`
   already exists as the single choke point — good — but every `Join-Path $PSScriptRoot` in the
   *loader* needs auditing.
3. **The AMSI data-file exemption is lost.** Signatures live in `data/*.json` specifically because
   data files are not AMSI-scanned. Embedding them as resources inside the EXE may pull them back
   into scanned content. **Keep `data/` external and beside the EXE** — this also preserves the
   integrity-manifest model in `engine/Phases-0.ps1` and lets signatures be updated without a
   rebuild.
4. **Self-elevation.** The loader currently relaunches itself via `Start-Process -Verb RunAs`
   re-passing `param()` args. An EXE needs a manifest (`requireAdministrator`) or an equivalent
   relaunch path, and the server reads the child's stdout — a relaunch that orphans that pipe
   makes the GUI think the scan died.
5. **The test suite is AST-based.** Every test pulls the real functions out of the shipped
   `.ps1` via the PowerShell parser. Compiling to a binary does not break that (the `.ps1` remains
   the source of truth) **as long as the EXE is built from those exact files** — so the build must
   verify the manifest, not just copy.

## Recommended shape

**Keep `engine/*.ps1` as the source of truth. Wrap, do not rewrite.**

- A thin native/`.NET` host EXE that carries an embedded PowerShell runtime invocation, ships
  `engine/` and `data/` beside it (or self-extracts them to a per-launch temp dir and cleans up —
  "leave nothing behind" is a standing rule), and applies the `requireAdministrator` manifest.
- `tools/Build-Release.ps1` already validates parse + BOM and stages a fixed file list. Extend it
  rather than replacing it, and make it run `tools/New-IntegrityManifest.ps1` before packing so
  the shipped build can verify itself.
- Ship the PowerShell tree **as well**. It is the debuggable form, it is what the test suite runs
  against, and a technician on a locked-down box where the EXE is blocked still has a working tool.

## Deliverables

1. A written comparison of PS2EXE vs a custom .NET host vs self-extracting archive, judged on:
   AV reputation, `$PSScriptRoot` handling, elevation, stdout fidelity to the server, and whether
   the existing test suite still guards the shipped artifact.
2. A **prototype** for the recommended option that produces a running EXE on a Windows box.
3. The `Build-Release.ps1` changes.
4. A written statement of what could not be verified without an EV certificate.

Do not start this before F1-F3 are done. It is the highest-effort, lowest-detection-value item on
the list, and it is easy to burn a whole session on signing problems.
