---
name: ws1-externalize-namelists
description: "WS1 (GAP 2) DONE 2026-06-30: 9 inline signature name-lists moved out of engine/*.ps1 into data/detection_signatures.json. Next is WS2 (GAP 3, new malware families) — the agent-parallel one."
metadata: 
  node_type: memory
  type: project
  originSessionId: b52570c5-fb96-4a42-9efa-04f184417bca
---

## WS1 — externalize inline signature name-lists — ✅ DONE 2026-06-30 (commit f88f4ca)

Moved the 9 inline lists that read like AV signatures out of the engine modules into
`data/detection_signatures.json` (AMSI/portability hardening). One data key per phase; content is
**byte-identical** to the pre-externalization lists — refreshing the families is WS2, deliberately
kept separate so this change is pure-externalization and easy to validate.

- New keys: `c2_pipe_patterns` (P62), `adware_pup_regs` (P67), `infostealer_procs` (P68),
  `tunneling_tools` (P82), `stego_tools` (P89), `leaked_cert_issuers` (P98), `cred_dump_tools` (P106).
- **2 consolidations (no duplicate lists):** P4 now uses shared `lolbas_expanded`; P72 matches
  reverse-DNS against shared `suspicious_dns_domains` (+ `.onion`, added `freeddns.com`) → 7→44 patterns.
- Loader (`ZeroBreach-V23.ps1` ~L834) wires 7 new `Get-Sig` globals. Phases consume them bare
  (dot-sourced into loader scope, same as `$LOLBAS_EXPANDED`/`$KNOWN_RAT_PROCS`).
- Phase regexes rebuilt at runtime with `[regex]::Escape` so externalized tokens can't inject
  regex metachars. P62 keeps the generic `[a-f0-9]{8,}` hex tail inline (not a signature).

**Validated:** JSON valid + all keys present; all `.ps1` + `engine/*.ps1` parse 0 errors; loader
UTF-8 BOM intact; runtime regex builds compile + match samples; grep confirms no inline signature
literals remain in `engine/` for these families. (AMSI strictly improved — change only removes literals.)

**NOT done:** the ~15 generic behavioral attack-regexes (IEX|DownloadString|EncodedCommand style,
e.g. P99 cmdline trigger) — lower priority, don't read like AV sigs, left inline.

**Next: WS2 (GAP 3)** — the big detection-coverage expansion (loaders/droppers, banking trojans,
2024-25 ransomware families, modern C2, BYOVD vuln-driver list, infostealer refresh). Research-heavy
and naturally parallel by malware domain → **this is the one to fan out across agents** (user OK'd
agents + "max Opus"). Externalize ALL new sigs to `data/*.json`.

**Related:** [[ws0-inventory-blocking-task]] [[engine-split-decision]] [[amsi-blocks-engine]]
