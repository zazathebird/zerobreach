---
name: ws0-inventory-blocking-task
description: "WS0 (inventory & gap analysis) is DONE (2026-06-29). coverage_matrix.json + WS0_COVERAGE_GAPS.md exist. Next: GAP 1 (backfill phase_map) then the engine split, then WS1-WS6."
metadata:
  node_type: memory
  type: project
  originSessionId: de06bd10-f8fa-40e8-ab74-af98e79c1465
---

## WS0 — Inventory & Gap Analysis — ✅ DONE 2026-06-29

**Deliverables shipped (committed):**
1. `data/coverage_matrix.json` — all **119 phases** (PHASE 1–115 incl. 74.5/74.6/74.7 and 105+)
   mapped to: detection summary, MITRE ATT&CK technique(s) (id+name+tactic+url), data_source
   tokens, and a `signature_source` flag (externalized / partial / inline / n/a).
2. `WS0_COVERAGE_GAPS.md` (repo root) — the short gap list (GAP 1–5) keyed to WS1–WS6.
3. `data/mitre_mapping.json` — added 9 techniques (T1059.005/.007, T1562.002, T1566.001,
   T1574 + .007/.009/.010/.011) so the new privesc/email phases resolve.

**Headline numbers:** 105 distinct techniques; all 12 active tactics covered (strong on Defense
Evasion/Persistence/PrivEsc; thin on Exfiltration/Collection/Discovery). signature_source: 15
externalized, 5 partial, 46 inline, 53 n/a.

**Built by 4 parallel Explore agents** over phase-line ranges, then merged in Python and resolved
against `mitre_mapping.json`. (Parallel fan-out worked well; non-overlapping line ranges + a strict
JSON schema avoided duplication.)

**Next steps (in order):** GAP 1 = backfill `phase_map` with 74.5/74.6/74.7/105+/108–115 (minutes,
unblocks WS5). Then execute the **engine split** ([[engine-split-decision]]) as its own validated
workstream. Then WS1 (externalize inline name-lists — GAP 2) and WS2 (new malware domains — GAP 3).

**Related:** [[engine-split-decision]] [[upgrade-plan-overview]]
