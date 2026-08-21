# NOTE - Detection vocabulary in this file is deliberate.
# Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
# named malware families, are detection category labels, operator-facing report text, or
# MITRE ATT&CK tactic names (a published standard). ZeroBreach is a defensive incident-
# response tool; these strings are what it reports, not what it does. See CLAUDE.md,
# "The detection vocabulary is deliberate". Do not sanitise them.

trap { Write-RecoveredError $_; continue }   # module-level resilience (see CLAUDE.md engine-split rule)

# ══════════════════════════════════════════════════════════════════════════════
#  HUNT BAND — PHASES 146-159   ·   PARALLEL WORK PACKAGE (see fable-work/)
#
#  STUB. This module is owned by the parallel work package in fable-work/ and is
#  dot-sourced unconditionally so the release stager's fixed file list stays valid
#  (a missing module ships a release that dies at startup — CLAUDE.md).
#
#  Scope, per fable-work/README.md:
#    146      PE structural analysis (with the rule engine, task F3)
#    147      cloud identity + DevOps credential theft            (task F1)
#    148-152  lateral movement, AD, credential dumping            (task F2)
#    153-156  LAN band — opt-in, read-only, requires -ScanLan     (task F6)
#    157      remaining persistence surface                       (task F4)
#    158      supply chain + developer tooling                    (task F5)
#    159      UEFI / ESP integrity                                (task F7)
#
#  Until it is filled in, HUNT runs 134-145 and 160-162 and simply skips this span.
#  The phase COUNTER is unaffected: $PhasePlan.Max is the plan ceiling, and the GUI
#  tracks headers actually emitted, so an empty module reads as a fast span, not as
#  an error.
# ══════════════════════════════════════════════════════════════════════════════
if ($PhasePlan.Hunt) {
    trap { Write-RecoveredError $_; continue }   # localize faults: resume at next phase, not end-of-group
    if (-not $global:STEALTH_MODE) {
        Write-Host "  [i] Phases 146-159 are not built in this release (parallel work package)." -ForegroundColor DarkGray
    }
    Write-Log "PHASES 146-159: module stub — parallel work package not yet merged."
}
