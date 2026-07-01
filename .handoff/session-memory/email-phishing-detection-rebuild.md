---
name: email-phishing-detection-rebuild
description: "How ZeroBreach's email/phishing detection + reversible quarantine + proactive hardening is structured (Phases 74.5/74.6/74.7)"
metadata: 
  node_type: memory
  type: project
  originSessionId: f2309b93-385c-4c8b-acf1-dfd7fe59d3a4
---

ZeroBreach's email-trojan response (rebuilt 2026-06-22, driven by real Datto/Defender alerts in `client_alerts/`):

- **Phase 74.5** scans Outlook attachment/diagnostic caches (`email_scan_paths_raw`), NOT the OST/PST. Confidence-scored, auto-quarantines actionable hits.
- **Phase 74.6** correlates `Get-MpThreatDetection`/`Get-MpThreat` — residual-on-disk → quarantine.
- **Phase 74.7** proactive adversary-informed hardening (Office macro/attachment, WSH, Defender PUA, ASR rules) as opt-in `RunCmd` fixes.
- **`Quarantine` FixAction** = reversible vault move to `reports/quarantine/` + `.quar.json` manifest. Prefer over `DeleteFile` unless hash-confirmed.
- All signatures in `data/detection_signatures.json` (AMSI rule). `email_content_rules` match constructs, not AV signature names.
- Skill `.claude/skills/ingest-malware-alert/` automates ingesting future alerts.

**User preferences observed:** wants proactive (not just reactive) defense, reversible quarantine over deletion, and the tool to wipe common persistence/foothold locations clean. Next up: [[perf-deep-dive-todo]].
