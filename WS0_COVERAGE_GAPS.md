# WS0 — Coverage Matrix & Gap Analysis (2026-06-29)

Output of the WS0 inventory (the blocking task in `UPGRADE_PLAN.md`). Full machine-readable
matrix: **`data/coverage_matrix.json`** — every phase mapped to its detection, MITRE
ATT&CK technique(s), data source, and a `signature_source` classification. This file is the
short human gap list that the WS1–WS6 workstreams key off.

## Inventory at a glance
- **119 phases** inventoried (PHASE 1–115 incl. sub-phases 74.5/74.6/74.7 and 105+).
- **105 distinct ATT&CK techniques** referenced across the engine.
- **All 12 active tactics covered.** Strongest: Defense Evasion (36 techniques), Persistence (26),
  Privilege Escalation (25). Lighter: Credential Access (9), Collection (7), C2 (7), Lateral
  Movement (6), Execution (6), Impact (4), Discovery (3), Initial Access (2), Exfiltration (1).
  Reconnaissance / Resource Development are pre-compromise and intentionally absent.
- `signature_source` tally: **15 externalized**, **5 partial**, **46 inline**, **53 n/a**
  (behavioral/registry/cmdlet phases that carry no signature strings).

## GAP 1 — MITRE phase_map is stale (quick fix, do first)
`data/mitre_mapping.json` `phase_map` covers PHASE 1–107 only. It is **missing** 74.5, 74.6,
74.7, 105+, and **108–115**. `coverage_matrix.json` already assigns techniques for these (and 9
new techniques — T1059.005/.007, T1562.002, T1566.001, T1574 + .007/.009/.010/.011 — were added
to the `techniques` catalog). **Action:** backfill those phases into `phase_map` so the runtime
finding-tagger (once wired in WS5) covers the newer phases too.

## GAP 2 — Inline signature literals to externalize (WS1, AMSI/portability)
46 phases match against literals written directly in the `.ps1`. Most are *behavioral* regexes
(IEX|EncodedCommand|DownloadString style) — lower AMSI risk but still worth externalizing for
cross-machine tuning. The **higher-priority ones are inline *name lists*** that read like AV
signatures and are exactly what AMSI/Defender can trip on:
- **PHASE 62** — named-pipe C2 framework names (meterpreter|cobaltstrike|njrat|havoc|sliver…). → new `c2_pipe_patterns` key.
- **PHASE 67** — adware/PUP family names (Conduit/SearchProtect/Trovi/Babylon/Delta…). → new `adware_pup_names`.
- **PHASE 68** — infostealer family names (RedLine/Raccoon/Vidar/Azorult/Formbook/AgentTesla/Lokibot…). → new `infostealer_procs`.
- **PHASE 98** — leaked code-signing cert issuers. → new `leaked_cert_issuers`.
- **PHASE 106** — credential-dumper tool names (procdump/nanodump/pypykatz/lsassy/handlekatz…). → new `cred_dump_tools`.
- **PHASE 82 / 89** — tunneling tool / stego tool name lists. → `tunneling_tools`, `stego_tools`.
- **PHASE 72** — botnet DDNS domains; overlaps `suspicious_dns_domains` — **merge, don't duplicate**.
- **PHASE 4** — inline 46-LOLBIN list overlaps `lolbas_expanded` — **consolidate**.
Full per-phase list of inline/partial phases is in the matrix (`signature_source` ∈ {inline,partial}).

## GAP 3 — Underrepresented malware domains (WS2, the big one)
- **Loaders / droppers — NO coverage.** GootLoader, BumbleBee, IcedID, PikaBot, SocGholish, Latrodectus. New domain + data key.
- **Banking trojans / botnets — weak.** Only a generic DDNS reverse-DNS check (Phase 72). No named Emotet/QakBot/TrickBot/Dridex/Ursnif/DanaBot coverage.
- **Infostealers — inline + dated.** Phase 68 misses Lumma, StealC, Rhadamanthys, Meduza. Promote to a maintained `infostealer_procs` data key and refresh.
- **Ransomware families — extensions only.** `ransomware_extensions` is solid but there are no 2024–2025 family *names/notes* (Akira, BlackBasta, Rhysida, Medusa, Play, Cactus, INC, Qilin/Agenda, Hunters Intl).
- **Modern C2 frameworks — thin.** `known_rat_procs` + inline pipe names; add Brute Ratel / Mythic / Havoc / Sliver beacon-config and named-pipe patterns as data.
- **BYOVD / vulnerable drivers — generic only.** Phase 55 flags *unsigned* drivers but there is no known-vulnerable-(signed)-driver hash/name list (the actual BYOVD risk is signed-but-vulnerable).
- **Supply-chain / dev-tool abuse — none.** Malicious npm/pip/nuget hints, IDE task hijack.

## GAP 4 — Accuracy / false-positive risk (WS3)
Several phases are **shallow name-only** process matches with high FP potential: PHASE 49
(clipboard/screen-capture by proc name), PHASE 71 (phishing overlay by proc name). These need
context (path + signature + behavior) and a confidence score, not single-keyword matching.

## GAP 5 — Lightest tactics to grow (WS2/WS5)
Exfiltration (1 technique — only Phase 89), Collection, and Discovery are thin. Initial Access is
email-phishing only. Candidates: cloud-CLI exfil (rclone/megacmd/aws/az), DNS-over-HTTPS exfil,
large-archive staging correlation, clipboard/screenshot collection with behavioral context.

## Suggested order
1. GAP 1 (backfill phase_map) — minutes, unblocks WS5 MITRE tagging.
2. GAP 2 (externalize inline name-lists) — WS1; AMSI + portability hardening.
3. GAP 3 (new domains) — WS2; biggest detection uplift. Externalize ALL to `data/*.json`.
4. GAP 4/5 — WS3 FP tuning + tactic breadth, alongside WS2.
