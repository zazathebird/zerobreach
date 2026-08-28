# 00 — Integration protocol

## What you hand back

```
engine/Phases-6.ps1              new file, yours alone (phases 146-159)
ws7_signatures_fable.json        NEW top-level keys only — a fragment, not the whole DB
tools/tests/Test-Hunt-Fable.ps1  your tests
HANDOFF_FABLE.md                 what you built / what you could not verify
```

Do **not** hand back an edited `data/detection_signatures.json`. The main session is adding keys
to it concurrently and a whole-file replacement would silently drop them. The fragment is merged
with an additive script that refuses to overwrite an existing key.

## The signature fragment

`ws7_signatures_fable.json` is a flat object of new top-level keys, matching the schema the real
DB uses (allowlists are **flat top-level keys**, not nested under an `fp_allowlists` object —
that is a common wrong assumption):

```json
{
  "_comment_cloud_cred_paths": "Phase 147. Env-var-expanded at load via ExpandString.",
  "cloud_cred_paths_raw": [ "$env:USERPROFILE\\.aws\\credentials" ],
  "_comment_cloud_cred_benign_paths": "Phase 147 allowlist. Anchored to path components.",
  "cloud_cred_benign_paths": [ "\\\\node_modules\\\\" ]
}
```

Conventions the DB already follows and you must match:
- A `_comment_<key>` string immediately before each key, saying which phase consumes it and why
  the entries are shaped the way they are.
- `*_raw` suffix for any list containing `$env:` variables — the loader expands those with
  `ExpandString` at load time.
- Allowlists are named `*_benign_*` and are consumed through `Join-AllowRegex`.

## Escaping — this is where these files actually break

Each entry is **a JSON string holding a .NET regex holding a Windows path**, so a backslash is
escaped twice. Real bugs shipped from exactly this:
- `_MEI\\d+` in JSON is the regex `_MEI\d+`… but `_MEI\\\\d+` is a literal backslash followed by
  `d`, which silently disabled an entire allowlist.
- A rule anchored with `$` cannot match when the phase tests it against a **composed** string
  (`"<TargetPath> <Arguments>"`). Match a boundary — `("|\s|$)` — instead.

**Verify with this before handing back** (Python, no PowerShell needed):

```python
import json, re
d = json.load(open('ws7_signatures_fable.json'))
canaries = ['C:\\Windows\\System32\\svchost.exe', 'HKLM:\\SOFTWARE\\Vendor\\Product',
            '9', 'zqx', 'Some Product Name 2026']
for k, v in d.items():
    if k.startswith('_comment') or not isinstance(v, list): continue
    for pat in v:
        if '$env:' in pat: continue                      # expanded at load, not a regex
        try: rx = re.compile(pat, re.I)
        except Exception as e: print('NOCOMPILE', k, pat, e); continue
        if 'benign' in k and all(rx.search(c) for c in canaries):
            print('UNIVERSAL — WILL BE REFUSED AT LOAD', k, pat)
```

That last check is not advisory. The engine now sanitises every allowlist inside
`Join-AllowRegex`: a pattern that matches all five canaries is **dropped at load and reported as
a CRITICAL "signature set tampering" finding**, because an allowlist that matches everything is
an off switch for the phases that use it (`ADVERSARY_ANALYSIS.md` E1). Your over-broad pattern
will not merely be noisy — it will make the tool accuse itself of being compromised.

## Phase numbering

Yours is **146-159 inclusive**. Do not use a number outside that range, and do not use fractional
phases — the ceiling arithmetic (`$PhasePlan.Max = 162`) is mirrored in four places and the test
suite checks them together.

## The module skeleton

```powershell
<BOM>trap { Write-RecoveredError $_; continue }   # module-level: resume at the NEXT phase in THIS module

# ...banner comment: what the band does and why...

# helpers (unconditional, so the AST tests can find them)
function Get-ScytheSomething { ... }

if ($PhasePlan.Hunt) {
    trap { Write-RecoveredError $_; continue }   # localize faults inside the group

    Show-PhaseHeader "PHASE 146" "TITLE IN CAPS" "CATEGORY"
    Out-Typewriter "WHAT THIS PHASE IS DOING..." "HUNT"
    # ...body...
    Add-Finding -ID "TAG146_$(...)" -Phase "PHASE 146" `
        -ThreatType "..." -Severity $SEV_POSSIBLE `
        -Description "..." `
        -Target "..." -FixAction "Info" -Group "..."
    Stop-PhaseTiming
}
```

**Both traps are mandatory.** The loader's trap resumes at the next *dot-sourced module*, so
without a module-level trap one terminating error skips every remaining phase in your file. This
is not hypothetical: a benign ACL TypeData collision at phase 16 once silently dropped phases
17-58 in production.

## Writing a Description

The description is the product. It is what an MSP technician reads at 2am and what gets pasted
into a client report, and because this band is `FixAction "Info"` the description **is** the
remediation. Every one should answer:

1. What was found, with the concrete value (path, key, PID, address).
2. Why it is suspicious — the technique, ideally with its MITRE ID.
3. **What is benign about it** — the honest false-positive case. Every phase in this band fires
   on healthy managed endpoints somewhere.
4. The exact next command the operator should run.

Look at `reference/Phases-5.ps1.reference` phase 141 for the shape. Note that it spends three
sentences telling the operator why a .NET process here is weak evidence. That is the standard.

## PowerShell escaping trap inside descriptions

A backtick immediately before a closing double-quote escapes it and the string never terminates.
Do not wrap inline commands in markdown backticks inside a `-Description`. Use single quotes.
This cost the main session a build.
