# Handoff — WS1 + WS2 complete; back-half validation is next (2026-06-30/07-01)

Self-contained cross-machine handoff (session memory does NOT travel with the repo).
Read together with `UPGRADE_PLAN.md`, `WS0_COVERAGE_GAPS.md`, `CLAUDE.md`.

## Done & pushed (branch `quarantine-work-dump-20260616-151402`)

- **WS1 (GAP 2) — `f88f4ca`** — Externalized 9 inline AV-signature name-lists out of
  `engine/*.ps1` into `data/detection_signatures.json` (AMSI/portability). New keys:
  c2_pipe_patterns, adware_pup_regs, infostealer_procs, tunneling_tools, stego_tools,
  leaked_cert_issuers, cred_dump_tools. Consolidations: Phase 4 → shared `lolbas_expanded`;
  Phase 72 → shared `suspicious_dns_domains` (+`.onion`, +`freeddns.com`).

- **WS2 (GAP 3) part 1 — `b2fdd87`** — Detection expansion researched by 5 parallel agents
  (loaders, banking trojans, infostealers, 2024-25 ransomware, modern C2 + BYOVD) from public
  sources only (MITRE, abuse.ch, CISA #StopRansomware, LOLDrivers, LOLBAS, SigmaHQ, vendor
  reports). ~20 new data keys incl. byovd_driver_names (87), ransom_note_filenames (26),
  c2_pipe_regex_anchored, inhibit_recovery_rules, *_behavior_rules. Merged: infostealer_procs
  12→26, ransomware_extensions +8, known_malware_hashes 1→17 (now active in hash matching).

- **WS2 part 2 + back-half fixes — `aabd075`** — Wired: Phase 62 anchored C2 pipes, Phase 53
  ransom-note filenames + content rules, **Phase 55.5 (new) BYOVD driver audit**, Phase 69
  mutex probe, **Phase 99.5 (new) command-line heuristics pass**.

## ⚠ Key discovery: phases 67–115 had never run in headless/`-Auto` mode

A pre-existing **Phase 66** bug (`$_.Name -notmatch "^(...)\$$"` was double-quoted, so PowerShell
consumed `$$` as the `$$` auto-var, leaving a trailing `\` → *"Illegal \ at end of pattern"*
terminating error) aborted every auto scan at phase 66. That masked a tail of latent bugs in the
whole back half. Fixed this session (engine now reaches ~Phase 76, was 66):

1. **Phase 66 regex** — single-quoted it (`'^([A-Za-z]|ADMIN|IPC|print)\$$'`).
2. **Phase 68 flood** — the info-stealer file scan flagged ANY file named login/cookie/wallet under
   TEMP/APPDATA and `DeleteFile`'d it → **13,314 findings + data-loss risk**. Replaced with a
   bounded ~31-path credential-store check (`infostealer_target_paths_raw`), INFO/Info. 13,314 → 9.
3. **`Get-FileHash` "not recognized"** at runtime (engine context breaks on-demand module autoload
   via a mid-autoload TypeData collision tripping the resilience trap) silently defeated ALL hash
   matching → added module-independent `.NET` `Get-Sha256File` helper (loader), swapped all 4 sites.

## NEXT (prioritized)

1. **Full headless run clean through Phase 115** — the long-outstanding acceptance test. Iterate:
   `Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ZeroBreach-V23.ps1 -Mode FULL -Hours 0 -Auto -OutDir <tmp>'`, then read the `KrakenConsole_*.log` in OutDir for
   `RECOVERED ERROR` lines and the max `PHASE N` header reached; fix each unguarded
   `-ErrorAction Stop`/null op and re-run. Next known blocker: a Terminal-Services **"Shadow"**
   registry read (~phase 76). `$ErrorActionPreference` is already `SilentlyContinue` (V23:61), so
   remaining aborts are specific `-EA Stop`/null ops. The resilience trap (V23:72 `trap{…;continue}`)
   does NOT reliably continue through every phase.
2. Same autoload issue silently degrades `Get-AuthenticodeSignature` (wrapped in try/catch in
   `Get-AuthSig`, so it returns null rather than aborting) — signature checks are effectively no-ops.
   Consider an early `Import-Module Microsoft.PowerShell.Security,Microsoft.PowerShell.Utility` in the
   loader, or a .NET fallback.
3. Then WS3 (false-positive tuning), WS5 (MITRE tagging — `phase_map` is ready in
   `data/mitre_mapping.json`), WS6 (remediation wiring / STEALTH JSON).

## Validation loop (run after every engine edit)
Parse: `[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$null,[ref]$e)` → 0 errors
on `ZeroBreach-V23.ps1` + all `engine/*.ps1`. Keep the UTF-8 **BOM** on the two `.ps1` servers.
AMSI: path-only headless run; PASS = phases stream, stderr has no `ScriptContainedMaliciousContent`.
