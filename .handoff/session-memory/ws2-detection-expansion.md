---
name: ws2-detection-expansion
description: "WS2 (GAP 3) DONE 2026-06-30: expanded detection coverage (loaders/banking/infostealers/2024-25 ransomware/C2/BYOVD) externalized to data + wired. Fixing Phase 66 exposed that phases 67-115 never ran headless; tail of latent bugs remains."
metadata: 
  node_type: memory
  type: project
  originSessionId: b52570c5-fb96-4a42-9efa-04f184417bca
---

## WS2 — detection-coverage expansion — DONE 2026-06-30 (commits b2fdd87, aabd075)

Built by **5 parallel research agents** (one per malware domain), each pulling only from approved
public sources (MITRE, abuse.ch/Feodo/ThreatFox, CISA #StopRansomware, LOLDrivers, LOLBAS, SigmaHQ,
vendor reports — no darkweb/Tor), returning **data-only drafts** (no file edits); main session
integrated/deduped/validated as single author. Agent fan-out worked well here because domains are
independent — contrast WS1 which had to be solo (collisions on one engine file). [[ws1-externalize-namelists]]

**Part 1 (b2fdd87) — data externalization.** New keys in `data/detection_signatures.json`:
c2_pipe_regex_anchored, c2_config_rules, banking_named_pipes, known_malware_mutexes,
byovd_driver_names (87) + byovd_driver_sha256 + byovd_cert_tbs_hashes, loader_procs/_drop_path_rules/
_behavior_rules/_c2_domains, banking_trojan_procs/_behavior_rules, infostealer_c2_domains/
_target_paths_raw/_behavior_rules, ransom_note_filenames (26)/_content_rules, inhibit_recovery_rules.
Merged: infostealer_procs 12→26, ransomware_extensions +8, known_malware_hashes 1→17 (now active).
Consolidation calls: deduped Pikabot mutex + pikabot/bumblebee procs; dropped FP-risky placeholders.

**Part 2 (aabd075) — wiring.** Phase 62 anchored C2 pipes (+ banking pipe), Phase 53 ransom-note
filenames + content rules, **Phase 55.5 NEW** BYOVD driver audit (Win32_SystemDriver vs LOLDrivers
names, FixAction Info — dual-use), Phase 69 mutex probe (Mutex.OpenExisting), **Phase 99.5 NEW**
consolidated Win32_Process command-line rules pass.

## ⚠ BIG DISCOVERY: phases 67-115 had NEVER run in headless/-Auto mode
A pre-existing **Phase 66 bug** aborted every `-Auto` scan there: `$_.Name -notmatch
"^(...)\$$"` was double-quoted, so PS consumed `$$` as the `$$` automatic var → trailing `\` →
"Illegal \ at end of pattern" terminating error. So the back half was untested and full of latent
bugs. **Fixing each unblocks the next** (engine now reaches ~Phase 76, was 66). Fixed this session:
- Phase 66 regex (single-quote it).
- Phase 68 flood: name-match scan over TEMP/APPDATA flagged ANY login/cookie/wallet-named file and
  **DeleteFile'd** it → 13,314 findings + data-loss risk. Replaced with bounded ~31-path
  credential-store check (infostealer_target_paths), INFO/Info. 13,314→9.
- `Get-FileHash` "not recognized" at runtime (engine context breaks on-demand module autoload via a
  mid-autoload TypeData collision tripping the resilience trap) → silently defeated ALL hash
  matching. Added module-independent `.NET` **Get-Sha256File** helper (loader), swapped all 4 sites.

**RULE learned:** the resilience trap (`trap {...; continue}`, loader L72) does NOT cleanly continue
through every subsequent phase — an unguarded terminating error (`-ErrorAction Stop` on an
expected-missing reg property/null op) still aborts the rest. `$ErrorActionPreference` is already
`SilentlyContinue` (L61), so remaining aborts are specific `-EA Stop`/null ops in phases 75-115.

## NEXT (still outstanding — the long-standing acceptance test)
Full **headless FULL/-Auto run clean through Phase 115**. Iteratively fix the tail of latent
back-half bugs (next known: a Terminal Services "Shadow" registry read ~phase 76). Also: same
autoload issue silently degrades `Get-AuthenticodeSignature` (wrapped in try/catch in Get-AuthSig so
it doesn't abort, but signature checks return null) — consider an early `Import-Module` or .NET
fallback. Then WS3 (FP tuning), WS5 (MITRE tagging — phase_map ready), WS6 (remediation/STEALTH).

**Related:** [[ws1-externalize-namelists]] [[ws0-inventory-blocking-task]] [[engine-split-decision]] [[amsi-blocks-engine]]
