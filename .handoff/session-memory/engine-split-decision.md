---
name: engine-split-decision
description: "Engine split DONE 2026-06-29: ZeroBreach-V23.ps1 is now a thin loader dot-sourcing engine/*.ps1. Validated end-to-end. Key rule: exit in dot-sourced modules must be [Environment]::Exit."
metadata: 
  node_type: memory
  type: project
  originSessionId: 61c4c782-f2cc-484a-a5b8-7eaf8879eec8
---

## Engine split — ✅ DONE & validated 2026-06-29

`ZeroBreach-V23.ps1` (was a 5350-line monolith) is now a **thin loader** (lines 1-1175: param,
elevation, schedule, globals, all helpers, Get-Sig/Get-Perm, banner, resilience trap — all
`$PSScriptRoot` usage) that dot-sources, in execution order:
`engine/Phases-1.ps1` (phases 1-~54), `engine/Phases-2.ps1` (55-89), `engine/Phases-3.ps1` (90-115),
`engine/Summary.ps1` (risk score + reports + exit), `engine/FixMode.ps1` (remediation UI). All carry
UTF-8 BOM. Full as-built + rationale in repo doc **`ENGINE_SPLIT_PLAN.md`**.

**Split BY RANGE, not by category** — phases execute linearly and reuse vars across phases
(`$ransomScanFiles` 51→52→53, `$bcdedit2` 40→58, `$dnsCache2` 59→60); category grouping would reorder
and break that. Dot-sourcing into the loader's single scope preserves vars/functions/trap exactly.

**Validated:** parse-clean ×6, byte-exact reconstruction (zero code change), headless `-Auto` QUICK
run completes + writes 2 report JSONs (606 findings) + **exits cleanly on its own**, no AMSI block.
Server/`Launch-GUI.bat` interface unchanged (same filename + args). Only QUICK was machine-tested; a
live admin FULL run through phase 115 is still worth doing for timing/acceptance.

**⚠ KEY RULE learned the hard way:** `exit`/`exit 0` inside a **dot-sourced** module does NOT
terminate the process — it returns to the loader (which then runs the next module). This hung `-Auto`
mode (Summary's exit fell into FixMode's prompt). **Any `exit` in `engine/*.ps1` meant to stop the
engine MUST be `[Environment]::Exit(N)`.** Applied in Summary.ps1 + FixMode.ps1. Loader's own exits
(elevation/schedule) are fine (not dot-sourced).

Also fixed this session: **Phase 66** network-share scan hung on the `C$` admin share (whole `C:\`);
now excludes drive-letter admin shares (`engine/Phases-2.ps1`).

**Benefit unlocked:** WS1/WS2 detection agents can now edit separate phase modules without colliding.

**Related:** [[ws0-inventory-blocking-task]] [[powershell-only-direction]] [[amsi-blocks-engine]]
