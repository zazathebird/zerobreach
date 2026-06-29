# ZeroBreach — "Opus Treatment" Upgrade Plan (post-/clear handoff)

> **Read this AFTER a context clear**, together with `CLAUDE.md`, `NEXT_STEPS.md`, and the
> saved memories. Written 2026-06-06. This is the work plan for the *major detection &
> quality upgrade* the user requested. The original tool was built with Sonnet 4.6; the goal
> is to take it as far as possible with Opus 4.8.

## User's directive (verbatim intent)
- Go over **every** feature, every malware form, every component. Improve, upgrade, increase
  productivity, and increase the number of things that can be flagged. "Give it the Opus
  treatment and improve it to the max." Take time and do it right.
- **Use as many sub-agents as needed** to get it done (the user explicitly authorized this).
  Parallelize the research/drafting across agents; the main session integrates and validates.
- Do this in a **fresh session after /clear**, not in the session that wrote this file.

## Hard boundaries (do not cross)
- **No darkweb. No Tor.** The user offered to set up Tor — politely decline; it is not needed
  and adds legal/safety/reliability risk for an MSP. Malware-detection intel is *better* from
  authoritative public sources. Pull from these instead (via WebSearch/WebFetch as needed):
  - **MITRE ATT&CK** (techniques/tactics) — already partially planned via `data/mitre_mapping.json`.
  - **abuse.ch**: ThreatFox (IOCs), URLhaus (malware URLs), Feodo Tracker (botnet C2),
    MalwareBazaar (samples/hashes), SSLBL.
  - **LOLBAS** project (living-off-the-land binaries) and **GTFOBins** (cross-ref).
  - **Sigma** detection rules (sigma-hq) — rich, convertible to our heuristics.
  - **Microsoft / CISA / vendor threat reports** (Mandiant, CrowdStrike, Cisco Talos, ESET,
    Kaspersky Securelist, Red Canary "Threat Detection Report").
  - **Emerging Threats / Snort** community rules for network IOCs.
- Stay **PowerShell-only** (see [[powershell-only-direction]]); do **not** touch `_python/`.
- Keep the tool **defensive**: it detects/audits and (optionally, user-driven) remediates. Do
  not add offensive capability, C2, or AV-evasion of the *host's* protections. (Avoiding AMSI
  *false positives* on our own code is fine and expected — see "Architecture rule" below.)

## Architecture rule learned this session (AMSI)
Defender AMSI blocked the engine because its signature **string literals** looked malicious.
Fix = keep signatures in **data files** (`data/*.json`), not in the `.ps1`. Data read via
`Get-Content|ConvertFrom-Json` is NOT AMSI-scanned. **Every new batch of signatures/IOCs MUST
go into `data/*.json`, never inline.** This is both the AMSI fix and clean architecture.
Already done: `data/detection_signatures.json` (the IOC databases). See `amsi-blocks-engine`
memory.

After ANY engine edit, re-run the two validations (see "Validation loop" at bottom).

---

## Workstreams (suggested agent fan-out)

Spin up agents per workstream; each researches public sources, drafts `data/*.json` +
heuristic logic, and hands back diffs. The main session integrates, de-dupes, parse-checks,
and AMSI-tests. **Inventory the existing 107 phases FIRST** so we extend rather than duplicate.

### WS0 — Inventory & gap analysis — ✅ DONE 2026-06-29
Mapped all **119 phases** (1–115 incl. 74.5/74.6/74.7 + 105+) of `ZeroBreach-V23.ps1`. Outputs
shipped: **`data/coverage_matrix.json`** (phase → detection → MITRE technique → data source +
`signature_source` flag), **`WS0_COVERAGE_GAPS.md`** (the gap list, GAP 1–5), and 9 new techniques
added to `data/mitre_mapping.json`. 105 distinct techniques; all 12 active tactics covered.
Decision also made this session: **moderate engine split** into a dot-sourced `engine/` folder
(see **`ENGINE_SPLIT_PLAN.md`** in the repo) — do it as its own validated workstream before WS1–WS6.
Key gap callouts for the workstreams below: GAP 1 = backfill `phase_map` (74.5/74.6/74.7/105+/108–115);
GAP 2 = externalize inline name-lists (WS1); GAP 3 = new domains loaders/banking-trojans/BYOVD (WS2).

### WS1 — Finish AMSI / portability hardening (quick, high value)
Externalize or keyword-split the ~15 **inline attack-regexes** still in the script (they did
NOT trip Defender's current defs but could on other machines/updated defs). Anchors found
2026-06-06: V23 lines ~925 (`VirtualAlloc|WriteProcessMemory|GetDelegateForFunctionPointer`),
944, 1180, 1329, 1465, 1482, 1496, 1548, 2236 (`meterpreter|cobaltstrike|...|sliver`), 2294,
2668, 2970, 2999, 3093, 3360. Move pattern strings into `data/detection_signatures.json` (new
keys) or split hot keywords across string concatenation so the contiguous signature never
appears in source. Re-AMSI-test.

### WS2 — Detection coverage expansion (the big one) — externalize ALL to data/*.json
Audit + expand each malware/technique domain. For each: refresh known names/hashes/paths/regex
from the public sources above, add families/TTPs that are missing, and tune. Domains:
- **RATs / C2 frameworks** (extend `known_rat_procs`, `known_c2_domains`; add Brute Ratel,
  Mythic, Havoc, Sliver C2 patterns, Cobalt Strike beacon configs, named-pipe patterns).
- **Ransomware** (extend `ransomware_extensions`, ransom-note patterns; add 2024-2025 families:
  Akira, BlackBasta, Rhysida, Medusa, Play, Cactus, INC, Hunters Intl, Qilin/Agenda, etc.).
- **Infostealers** (NEW domain — RedLine, Raccoon, Vidar, Lumma, StealC, Rhadamanthys, Atomic
  (macOS n/a), Meduza; browser-credential/cookie/wallet theft paths).
- **Loaders / droppers** (GootLoader, BumbleBee, IcedID, PikaBot, SocGholish, Latrodectus).
- **Banking trojans / botnets** (Emotet, QakBot, TrickBot, Dridex, Ursnif, DanaBot).
- **Fileless / LOLBins** (expand `lolbas_expanded` from LOLBAS; AMSI/ETW tamper, WMI/MSHTA/
  regsvr32/rundll32/certutil/bitsadmin cradles, PowerShell `-enc` cradles).
- **Persistence** (ATT&CK TA0003: run keys, scheduled tasks, services, WMI event subs, COM
  hijack, IFEO, accessibility-tool hijack, startup folder, BITS jobs, logon scripts).
- **Credential access** (LSASS dumping tools/paths, DPAPI, SAM/SYSTEM hive theft, Kerberoast,
  DCSync indicators, browser cred stores).
- **Defense evasion** (AMSI/ETW patching by *malware*, Defender tamper, log clearing, timestomp,
  signed-binary proxy exec).
- **Rootkits / bootkits** (driver-based, BYOVD vulnerable-driver list, UEFI hints).
- **Miners** (extend `known_miner_procs`, `stratum_ports`, pool domains).
- **Exfiltration** (rclone/mega/cloud CLIs, DNS tunneling, large-archive staging).
- **Supply-chain / dev-tool abuse** (malicious npm/pip/nuget hints, IDE task hijack).
- **Spyware/stalkerware/keyloggers** (extend `known_keylogger_procs`).
> Output of WS2: enriched `data/detection_signatures.json` + new `data/*.json` files per domain
> as needed, plus new/extended phases or heuristics wired to them.

### WS3 — Accuracy & false-positive tuning
Reduce noise: better allowlisting (signed Microsoft binaries, legit admin tools), context-aware
severity (path + signature + behavior, not single keyword), and a confidence score per finding.
Verify the script's self-detection filter (`script_own_strings`) still suppresses its own hits.

### WS4 — Performance
Parallelize independent phases with runspace pools / `ForEach-Object -Parallel` (PS7) with a
PS5.1 fallback. Cache expensive calls (CIM, Get-AuthenticodeSignature). Target a faster QUICK
mode without losing coverage.

### WS5 — Reporting, scoring & MITRE tagging
Wire `data/mitre_mapping.json` (keyword/threat-type/phase → technique) so every finding shows
technique ID + tactic + URL. Add an overall risk score, an executive summary, and richer HTML.
(See CLAUDE.md "Outstanding Work".)

### WS6 — Remediation & STEALTH
Wire `btn-execute` to real, user-confirmed remediation; surface the rollback-snapshot path.
Implement STEALTH-mode JSON parsing in both servers (currently neither parses it).

---

## Validation loop (run after every engine change)
1. **Parse:** `[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$null,[ref]$errs)`
   → must be 0 errors. (Both `.ps1` files.)
2. **AMSI:** run the engine with a **path-only** command line (no signature words on the
   cmdline, or Defender blocks the *spawn* with EPERM):
   `Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "<path>" -Mode QUICK -Hours 0 -Auto -OutDir "<reports>"' -NoNewWindow -RedirectStandardError err.txt`
   with an ~12s timeout, then kill. PASS = banner/phases stream and stderr has **no**
   `ScriptContainedMaliciousContent`.
3. **BOM:** any rewrite of `ZeroBreach-V23.ps1` / `ZeroBreach-Server.ps1` MUST keep the UTF-8
   BOM (`EF BB BF`) — use `[IO.File]::WriteAllText($p,$txt,(New-Object System.Text.UTF8Encoding($true)))`.
4. **JSON outputs** stay UTF-8 **no-BOM** (`UTF8Encoding($false)`) — see NEXT_STEPS Phase 1.
5. **Live GUI run:** `Launch-GUI.bat` as admin → scan reaches Phase 107 → JSON in `reports/` →
   clean re-run. (The one acceptance test still outstanding.)

## Key file:line anchors (verified 2026-06-06)
- Signature loader / `Get-Sig`: `ZeroBreach-V23.ps1` ~line 639 (replaces old inline IOC block).
- Signature data: `data/detection_signatures.json`.
- YARA-lite consumer: `ZeroBreach-V23.ps1:~2843` (`$rule.Pattern` / `$rule.Severity`).
- Inline regexes to harden (WS1): see list above.
- MITRE mapping (ready, unused): `data/mitre_mapping.json`.
- IOC import format: `data/ioc_defaults.json` (`-IocFile`).

## Definition of done
Coverage matrix exists; every signature/IOC lives in `data/*.json` (no inline literals);
detection domains in WS2 refreshed from public sources with MITRE tags; false-positive tuning
in place; faster scan; richer report with technique tagging; passes the full validation loop
including a live Phase-107 GUI run on a clean machine with no Defender exclusion.
