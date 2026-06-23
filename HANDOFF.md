# RESUME HANDOFF — 2026-06-23 (battery cutoff)

Pick this up in a new session / different PC. Everything below is committed to **`main`**
(local only — not pushed). Latest commit: `0cf6529`.

## Where we are

Today's work (all committed): MITRE tagging, IOC Manager, HTML/CSV export, STEALTH parsing,
**real GUI remediation**, benign test tripwires, and a **system-damage safety guard**. The scan
engine `ZeroBreach-V23.ps1` is deliberately untouched. See CLAUDE.md → "Feature wiring completed
2026-06-23" + "Remediation test tripwires".

### The big finding from the live scan
A real DEEP scan produced **1305 findings, ~772 auto-selected destructive — overwhelmingly FALSE
POSITIVES**, including dangerous ones (would delete 100 root CAs incl. Microsoft/Amazon, the user's
`.bashrc`/`.gitconfig`/`.claude.json`, IconCache, and KILL the running `claude` process). The
detection engine is NOT false-positive-tuned (known: `UPGRADE_PLAN.md` WS3). **Do not trust
auto-remediation until FP tuning is done.**

### User's #1 priority (verbatim)
"I don't want this tool to EVER select anything that will damage the system. That is priority
number one." → Implemented as defense-in-depth. **Conservative by design**: a real threat in a
protected location is *audited but never auto-acted-on* (operator handles manually).

## DONE this session (committed)
- `0cf6529` **Safety guard (Layers 1 + 3 — the execution backstop):**
  - `Test-ProtectedTarget` (main thread, ~`ZeroBreach-Server.ps1` near `Get-EngineReportFindings`):
    flags cert trust store / Windows+System32+WinSxS / shell-system files / user dotfiles /
    SafeBoot + core OS registry / KillProcess of critical procs or the IR tool. `Get-EngineReportFindings`
    now adds `protected` + `protected_reason` to every finding served to the GUI.
  - `Test-RProtected` (mirror, inside `$script:REMEDIATE_SCRIPT`): **hard-blocks** any selected fix
    on a protected resource — logs `[BLOCKED] protected (...)`, increments `$blocked`, `continue`s.
    `remediation_complete` now carries `blocked`.
  - **Verified**: against the live report it blocks 285 destructive ops (100 cert, 100 SafeBoot, 67
    Windows-dir, 12 shell/system, 5 dotfile, 1 kill-claude) and still allows legit Temp/Downloads
    deletes. Server parses clean on PS 5.1 + 7 (all 3 here-strings).

## TODO — remaining, in priority order

### 1. Frontend safety Layer 2 (`gui/static/js/app.js`) — DO FIRST
Findings now arrive with `finding.protected` (bool) + `finding.protected_reason` (string).
- **Never auto-select protected.** In `renderFindingsTree()` the `autoCheck` line is currently:
  `const autoCheck = finding.severity === 'CRITICAL' || finding.severity === 'HIGH';`
  → change to also require `&& !finding.protected`.
- **Disable the checkbox** for protected findings (can't be selected at all) and show a `🛡 PROTECTED`
  badge with `title=finding.protected_reason`. (Add a `protectedBadge(finding)` helper next to
  `mitreBadge()`, render it in the tree item; add `.item-protected` CSS in `main.css`.)
- **Belt-and-suspenders** in `executeRemediation()`: `const ids = findings.filter(f => !f.protected).map(f => f.id);`
- **Show blocked count** in `onRemediationComplete(data)` — include `data.blocked` in the toast/label.
- Re-run `node --check gui/static/js/app.js`.

### 2. Completion-modal count fix (`gui/static/js/app.js`) — task #9
The modal shows `data.findings_count` from the live SSE line-parse, which is ~0 in GUI mode (engine
emits clean output, server's per-line classifier matches nothing) → "0 found", then `loadEngineFindings()`
populates the real list afterward ("loads showing"). Fix: in `loadEngineFindings(name)`, after the
`fetch('/api/report...')` resolves, update the modal's TOTAL FINDINGS stat to `list.length` (full
engine total) and THREAT DETECTIONS to `notable.length`. The modal element is `#modal-summary`
`.complete-stat-num` (nums[0]=findings, nums[1]=threats).

### 3. (Lower) FP tuning of detection — the root cause
The engine over-matches (round-100 capped groups = "matched everything"). Examples to fix in
`ZeroBreach-V23.ps1` (engine — coordinate, higher risk): "Info-Stealer" matched `.node/.ses/.tmp`;
"COM Scriptlet" matched `.json/.db`; "Cloaked/Hidden" matched every hidden+system file; "Network
Share Worms" matched dotfiles as "unsigned executable in open share"; "Rogue Certificates" flagged
every root CA. This is `UPGRADE_PLAN.md` WS3. The safety guard makes this non-catastrophic, but the
noise is the real usability problem.

## Validation commands
```
# PS parse (both runtimes) + here-strings:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File /tmp/zbparse.ps1 -F "<abs path>\ZeroBreach-Server.ps1"
pwsh -NoProfile -File /tmp/zbparse.ps1 -F "<abs>\ZeroBreach-Server.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File /tmp/zbvalidate.ps1 -File "<abs>\ZeroBreach-Server.ps1"
# (zbparse.ps1 / zbvalidate.ps1 are in the scratchpad-recreatable; see git log for what they do — or
#  re-derive: ParseFile for the file, and a regex that extracts every @'...'@ here-string and ParseInputs it.)
node --check gui/static/js/app.js
node tools/check-visuals.mjs   # FX audit, expect PASS 13/13 (kill stray zb-vfx-profile browser first)
```

## Live test tripwires (still on the user's machine, named ZeroBreach_TEST_DELETEME)
5 benign artifacts validate scan→findings→remediation (DeleteFile×2, DeleteReg, Quarantine, RunCmd).
Recreate/cleanup commands + detection logic are in CLAUDE.md → "Remediation test tripwires".
The newest engine report analyzed: `reports/KrakenBaseline_20260623_135347.json`.
