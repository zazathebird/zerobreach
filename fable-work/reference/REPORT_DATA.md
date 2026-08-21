# Reference — the data every reporting task in this package reads

Everything below is produced by the scan engine. **You do not need to read the engine to use
it.** These shapes are stable and are what `tools/New-ScanReport.ps1`, the comparison tool and
the timing tool consume.

## Where the files land

A run writes into `reports/` (created automatically, `-OutDir` overrides it):

| File | Contents |
|---|---|
| `audit_<stamp>.json` | the run record, schema below |
| `KrakenBaseline_<stamp>.json` | byte-identical copy, kept as the comparison baseline |
| `ZeroBreach_<stamp>.txt` | the plain-text log |
| `ZeroBreach_<stamp>.html` | the engine's own HTML report (`-Html`) |
| `KrakenConsole_<stamp>.log` | the server's durable console log |

Both JSON files are **UTF-8 without BOM**. Read them with `Get-Content -Raw | ConvertFrom-Json`
on PowerShell, or `json.load` in Python.

## Run record schema

```jsonc
{
  "Timestamp":  "2026-08-19T14:32:07.1234567-04:00",  // ISO 8601 round-trip
  "Host":       "WORKSTATION-04",
  "User":       "DOMAIN\\tech",
  "Mode":       "DEEP",                 // QUICK | FULL | DEEP | PARANOID | STEALTH | HUNT
  "TimeWindow": "LAST 24 HOURS",        // human label; "ALL TIME" when -Hours 0
  "RiskScore":  138,                    // integer, unbounded
  "RiskLabel":  "ELEVATED",
  "Paranoid":   false,
  "Stealth":    false,

  "Findings":        [ /* Finding, below */ ],
  "PhaseTimings":    [ { "Phase": "PHASE 47 — SOME TITLE", "Seconds": 12.4 } ],
  "RecoveredErrors": [ "string, one per recovered fault" ],
  "BaselineDelta":   [ /* Findings present in this run and not in the -Baseline run */ ],

  "ThreatTally": {
    "RAT": 0, "Rootkit": 0, "Ransomware": 0, "Keylogger": 0, "Miner": 0,
    "Worm": 0, "Spyware": 0, "Trojan": 0, "Backdoor": 0, "UACBypass": 0
  }
}
```

### Finding

```jsonc
{
  "ID":          "P47_a1b2c3",      // unique within a run; the natural join key
  "Phase":       "PHASE 47",        // may be fractional: "PHASE 74.5". "PREFLIGHT" also occurs.
  "ThreatType":  "Trojan",
  "Severity":    "CRITICAL",        // CRITICAL | HIGH | POSSIBLE | INFO
  "Description": "operator-facing prose — this is the product",
  "Target":      "C:\\path\\or\\HKLM:\\key\\or\\a PID",
  "FixAction":   "Info",            // Info | None | DeleteFile | DeleteReg | DeleteRegKey |
                                    // KillProcess | RunCmd | Quarantine
  "FixParam":    "",
  "Group":       "some grouping label",   // defaults to Phase
  "Selected":    true,                    // engine's own default tick state
  "Timestamp":   "2026-08-19 14:32:07"    // NOTE: the time the SCAN ran, not the artifact's age
}
```

Two things about `Timestamp` that matter for any trend or timeline feature:

- **Every finding in a run shares essentially the same timestamp.** It records when the scan
  reached that phase, not when the thing it found came into existence. Do not build a timeline
  or cluster findings on it.
- The format is local time with no zone. The run-level `Timestamp` at the top of the record is
  the one with an offset — prefer it whenever you need an absolute instant.

### Severity ordering

`CRITICAL > HIGH > POSSIBLE > INFO`. Sort with an explicit map; alphabetical order is wrong and
`POSSIBLE` sorting above `INFO` by accident has masked bugs before.

### Volume

A real DEEP run on a working machine produces **500–800 findings**, overwhelmingly `INFO` and
`POSSIBLE`. Anything you render must stay usable at 1,000 rows: paginate, virtualise, or
collapse by group — do not emit 1,000 DOM nodes and hope.

There is also a flood guard: a group that exceeds its cap emits one summary finding whose `ID`
starts with `GROUPCAP_` and whose `FixAction` is `None`. Treat those as metadata, not findings —
counting them as detections inflates every total.

## MITRE mapping — `data/mitre_mapping.json`

Read-only for every task in this package. Top-level keys:

| Key | Shape | Use |
|---|---|---|
| `metadata` | object | name/version |
| `tactics` | `{ "TA0001": "Initial Access", ... }` | tactic id → display name |
| `techniques` | `{ "T1003.001": { "name": ..., "tactics": ["Credential Access"], "url": ... } }` | the technique table |
| `threat_type_map` | `{ "RAT": ["T1219", ...] }` | finding `ThreatType` → technique ids |
| `keyword_map` | `{ "<lowercase substring>": ["T####"] }` | matched against the finding text |
| `phase_map` | `{ "47": ["T####"], "74.5": [...] }` | phase number → technique ids |

**Resolution order used everywhere else in the product, and which you must match:**
`keyword_map` → `threat_type_map` → `phase_map`. For `phase_map`, look up the **fractional**
key first (`"74.5"`), then fall back to the integer floor (`"74"`). Note `techniques[].tactics`
holds tactic **display names**, not `TA####` ids — a rollup keyed on ids has to invert `tactics`
first, and getting this backwards produces a silently empty rollup.

Keys beginning `_comment` appear inside `keyword_map` and `phase_map`. Skip them.

## Console log — `reports/KrakenConsole_<stamp>.log`

Line-oriented. The two patterns worth parsing:

```
  ⏱  PHASE 47 — SOME TITLE took 12.4s
TIMING: PHASE 47 — SOME TITLE took 12.4s
```

The first is console output (leading spaces, U+23F1 then two spaces); the second is the log
line. Parse the `TIMING:` form — it is stable and free of the console's box-drawing.

Phase headers match `PHASE\s+(\d+(?:\.\d+)?)[^\d]`. **Keep the decimal** — fractional phases are
real plan steps, and truncating them to integers double-counts.

Phase ceilings per mode, which any progress or coverage math must use:
`QUICK 30`, `FULL 80`, `DEEP` / `PARANOID` / `STEALTH` `133`, `HUNT 162`.
