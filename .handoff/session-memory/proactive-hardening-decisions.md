---
name: proactive-hardening-decisions
description: User-approved deployment policy for ZeroBreach Phase 74.7 proactive hardening (ASR/macros/WSH) on business machines
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 9039492f-668a-4f30-96d6-1287b4495683
---

The user runs ZeroBreach on **business machines in professional environments** and cannot have things
broken or "random rules" set up that affect basic (non-tech-savvy) end users. They asked to be consulted
on **each** hardening rule/block before it ships.

**Decisions (2026-06-22) for Phase 74.7 — all fixes stay opt-in `RunCmd`, never auto-applied:**
- **ASR rules: split by false-positive risk.** 3 low-FP rules → **Block** (email exec content, JS/VBS
  launching downloads, Office creating executables). 3 higher-FP rules → **Audit/log-only** (Office
  child processes, obfuscated scripts, Win32-from-macros) — promote to Block per-client after telemetry.
- **Office macros: VBAWarnings=2** (block internet/email-sourced macros, prompt for local trusted), NOT
  `4`/disable-all (would silently break legit business Excel/Word macros).
- **Windows Script Host disable: keep as opt-in flag** (legacy logon scripts may need it).

**Why:** false positives / broken macros / dead logon scripts on a client machine are worse than a
slightly weaker default; the tech promotes to enforcement once validated.

**How to apply:** when adding any new hardening/blocking rule, default to the least-disruptive safe
option, prefer Audit-first for anything FP-prone, and ASK per rule before enabling. The user is
comfortable enabling low-FP protections outright. Relates to [[email-phishing-detection-rebuild]].
