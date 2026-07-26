# ZeroBreach — Evidence Engine Plan (2026-07-26)

Plan of record for turning ZeroBreach from a **present-state file scanner** into an **incident-response
evidence engine**, and shipping it as a single portable `.exe`.

Written from two grounded audits performed 2026-07-26 (current-coverage map + forensic-artifact
feasibility). Nothing here is speculative capability: every item was checked against the real code or
against what Windows actually exposes to PowerShell 5.1 on a live box.

---

## 0. Why this exists — the Wacatac problem

The operator is an MSP receiving Autotask tickets relaying Microsoft Defender alerts, very often
`Trojan:Win32/Wacatac.B!ml`.

**Wacatac is not a malware family.** The `!ml` suffix means the verdict came from a machine-learning
model, not a signature. That bucket contains real infostealers and loaders *and* a large share of
false positives (cracked software, keygens, NSIS installers, unsigned scripts, game mods). There is
no stable artifact to write a "Wacatac signature" against, and any attempt to do so is chasing a
label rather than a threat.

The questions the tool must actually answer are:

1. **Is this ticket real, or is it a false positive?** (triage — the volume problem)
2. **If real, what happened on this box?** (scope — the incident problem)
3. **Is it still here?** (containment — what the tool already does today)

Only #3 is currently addressed. #1 and #2 require evidence the engine does not collect: **event logs
and forensic artifacts**. Critically, this evidence **survives the payload** — after self-deletion,
after Defender quarantines it, after a tech "cleaned it." A file scanner sees a clean box and says
"clean." That is the failure mode this plan fixes.

### 0.1 Proof this is not theoretical — from the operator's own scan data

`reports/KrakenBaseline_20260724_152817.json:1453`:

> Defender flagged `Trojan:Win32/Wacatac.C!ml` … but the file is STILL PRESENT:
> `…\PirateLife-Native\obj\Debug\net8.0-windows10.0.19041.0\PirateLifeNative.dll`
> — graded **CRITICAL + Quarantine**

That is a developer's freshly-compiled build artifact in an `obj\Debug\` output directory. Because
`Quarantine` is in the auto-destructive set, it was **auto-selected for remediation**. The engine had
every signal needed to downgrade it — build-output path class, file age of minutes, zero
corroborating findings on that path — and used none of them.

This is the FP-flood problem in miniature, on the operator's own box, from the exact alert family
that generates most of their tickets.

### 0.2 The scope is all commodity SMB/RMM alerts, not just Wacatac

Real ticket mix: generic ML trojans (`Wacatac`, `Sabsik`, `Occamy`, `Zpevdo`), **PUP/adware**
(`PUA:Win32/*`, bundleware, browser hijackers, "driver updater"/"PC cleaner" families), coinminers,
RATs/remote-access tooling misuse, credential stealers, ransomware precursors, and MITRE-mapped
technique alerts from EDR. The design must therefore key on **threat CLASS + evidence**, never on a
single vendor label. See §5 (ingestion) and §5.1 (class coverage).

---

## 1. Architecture decision: EXTEND, do not rewrite

**Rewriting was considered and rejected.** Reasons, in order of weight:

- The ~140 phases encode **six documented false-positive tuning rounds**. That tuning is the
  difference between a tool an MSP trusts and one that cries wolf on every healthy box. A rewrite
  re-earns it on client machines.
- The safety model (rule #1, `Test-ProtectedTarget` hard blocks, auto-select grading) is
  battle-tested. Session 16 demonstrated how easily *new* code violates it.
- The 2026-07-26 detection gap was **not architectural**. It was one design decision (gate content
  inspection on filename) in two places, diagnosed and fixed in hours.
- A rewrite means months with no working tool while the ticket queue keeps filling.

**The honest caveat:** 140 sequential phases across three files sharing one dot-sourced scope *is* a
real scaling constraint — it is why a local named `$auto` could silently disable the whole engine
(session 16). The remedy is disciplined module addition plus the parse/validation gates now in place,
not a ground-up rebuild.

**Therefore:**

| Piece | Where it goes |
|---|---|
| Evidence collection | **New module** `engine/Evidence.ps1`, dot-sourced like `Phases-1/2/3` |
| Correlation + verdict | **New stage** after the phases, before `Summary.ps1` |
| Alert triage entry point | New CLI param + server route |
| Existing 140 phases | Largely untouched; targeted bug fixes only |

The new module **must** follow the engine-split rules in `CLAUDE.md`: own top-level
`trap { Write-RecoveredError $_; continue }` as its first statement, `[Environment]::Exit()` never a
bare `exit`, `$global:ZB_ROOT` not `$PSScriptRoot`, UTF-8 BOM, parse-clean on PS 5.1 **and** 7.

---

## 2. Prerequisite bug fixes — do these FIRST

These are defects in shipped code found during the audits. Several make existing findings actively
misleading, and everything in §3 inherits them.

### P1 — `HKCU` is the wrong user (correctness prerequisite, affects ~6 existing phases)
The engine self-elevates via `Start-Process -Verb RunAs`. On a standard-user endpoint — the normal
MSP case — the tech supplies admin credentials, so `HKCU`, `$env:APPDATA` and `$env:LOCALAPPDATA`
resolve to the **admin's** profile, not the victim's. Nothing in the codebase enumerates
`HKEY_USERS` or `ProfileList` (zero grep hits).

Already degraded by this: Phase 20 (Run keys), Phase 24 (COM hijack), Phase 7/8 (browser paths),
Phase 68.5 (RunMRU, `Phases-2.ps1:452`), Phase 100 (`Phases-3.ps1:687`).

Fix: enumerate `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` for SIDs +
`ProfileImagePath`. For logged-on users use the already-mounted `Registry::HKEY_USERS\<SID>`; for
logged-off users `reg load` their `NTUSER.DAT`/`UsrClass.dat` (**locked while logged on** — try HKU
first, always pair with `reg unload`). Provide one helper, e.g. `Get-UserHives`, and migrate the
affected phases to it.

### P2 — event-log queries are truncated and slow (`Phases-3.ps1:1120, 1155, 1179`)
`Get-WinEvent -FilterHashtable @{...} -MaxEvents 2000 | Where-Object { Test-InScope $_.TimeCreated }`
takes the **newest N** and *then* filters by time. On a busy box, 2000 × 4624 can be 20 minutes of
history — the `-Hours` window silently collapses. Put `StartTime` **inside** the FilterHashtable
(server-side XPath, evaluated by the EventLog service): correct *and* far cheaper.

Also: `$_.Message -match ...` (`:1158`) lazily renders through the provider message DLL at ~1–3
ms/event → seconds per phase. Use `-FilterXPath`/EventData predicates or `.Properties[n].Value`.
Also: these three sites call `Get-WinEvent` **raw**, bypassing the existing `Get-WinEventSafe`
wrapper — a `CLAUDE.md` rule breach. Also: `[xml]$_.ToXml()` is parsed **twice per event**
(`:1123` inside `Where-Object`, again at `:1138`).

### P3 — 4688 checks are structurally blind on a default box (`Phases-3.ps1:1155-1174`)
"Audit Process Creation" is **off by default** on Win10/11, and command-line capture is a **second,
independent** policy (`HKLM\...\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled=1`).
Without it, 4688 carries no arguments — so the phase's regexes (`powershell.*-enc`,
`certutil.*-decode`) **cannot match**, yet it prints "0 SUSPICIOUS 4688 PROCESS EVENTS."

Fix: read both policy states (`auditpol /get /subcategory:"Process Creation"` + the registry value)
and emit an explicit **"this check was blind"** finding when off. Never print a clean result for a
check that could not have fired.

### P4 — Phase 11 destroys evidence (`Phases-1.ps1:480-497`)
It opens the `Recent`/JumpList folders, **counts** the files, and emits an INFO finding whose only
action is a `RunCmd` to **delete them**. Those `.lnk` files carry TargetPath, Arguments,
WorkingDirectory and the original volume serial — and Phase 10.5 (`Phases-1.ps1:394-438`) already
contains a working LNK parser one file away. Stop offering to delete; start parsing.

### P5 — Phase 12 contains dead code and a false title (`Phases-1.ps1:499-516`)
Titled "PREFETCH & SHIMCACHE"; the body only reads Prefetch. Its regex alternatives
`RUNDLL32.*APPDATA` / `POWERSHELL.*-ENC` **cannot match**, because `.pf` filenames are
`NAME.EXE-<8 hex>` and contain no paths or arguments.

### P6 — Phase 91 opens the right stream and throws away the answer (`Phases-3.ps1:268-286`)
It checks only for the *absence* of `Zone.Identifier`. The stream, when present, contains **`HostUrl`
and `ReferrerUrl`** — the download source and referring page. Read them.

### P7 — the operator's most common alert name cannot match (`Phases-2.ps1:770-772`)
`email_phishing_trojans` contains `"Trojan:Script/Wacatac"` and the match is
`"$tname".StartsWith("$pf")`. **`Trojan:Win32/Wacatac.B!ml` does not start with that string.** There
is no `!ml` / `!MTB` / `!MSR` suffix awareness anywhere in the repo.

Fix: normalise Defender verdicts into `(platform, family, variant, confidence-suffix)` before
matching, and match on **family**. Treat `!ml`/`!MTB` as an explicit *low-confidence, ML-derived*
tier that REQUIRES corroboration before any destructive grading.

### P8 — Phase 74.6 grades a Defender residual CRITICAL + Quarantine with zero corroboration
(`Phases-2.ps1:777-791`) — see §0.1 for the proven false positive. It infers status purely from
`Test-Path` and never reads the properties `Get-MpThreatDetection` already returns:
`ThreatStatusID` (was it actually remediated / **Allowed** / still Active), `CleaningActionID`,
`RemediationTime`, `LastThreatStatusChangeTime`, `DetectionSourceTypeID`, and — highest value of all
— **`ProcessName`, the process Defender attributed the drop to**. It also never hashes the file,
never checks its signer, never considers its age or path class.

Fix: read those properties; require corroboration before CRITICAL; add a path-class demotion for
build-output/dev directories (`\obj\`, `\bin\Debug\`, `\node_modules\`, `\target\`) via
`Test-BenignPath`.

### P9 — the triage-relevant phases are DEEP-only (`ZeroBreach-V23.ps1:1602-1609`)
FULL stops at 80. That gates out MoTW (91), the YARA/hash sweep (90), UAC-bypass staging (92),
malware command-line heuristics (99.5), browser-credential access (100), token staging (100.5),
svchost masquerade (102), hidden tasks (104), correlation (105), memory dumps (106), event-log
hunting (107) **and all Defender tamper / security-control-health checks (114)**.

A tech running FULL on a Wacatac ticket gets none of it. Either the triage entry point (§5) must
force the needed phases regardless of mode, or a dedicated TRIAGE plan must exist.

### P10 — `Add-Finding`'s fixed schema blocks any verdict (structural, `ZeroBreach-V23.ps1:498-541`)
The record is 9 fields: `ID, Phase, ThreatType, Severity, Description, Target, FixAction, FixParam,
Group`. There is **no field for hash, signer, publisher, file age, MoTW zone/URL, size, parent
process, or evidence-source**. Phases jam context into `Description` prose, and the server re-derives
`protected`/`vendor_trusted` by regexing that prose (`ZeroBreach-Server.ps1:456-489`).

**A structured benign/malicious verdict cannot be produced under the current contract.** Extending
this record is a prerequisite for §4. Add optional named parameters (backwards-compatible), and
carry them through `[FINDING]` JSON → server → GUI.

### P11 — Phase 30 auto-destructs on legitimate managed boxes (`Phases-1.ps1:1285-1311`)
Every WMI subscription is graded CRITICAL + `RunCmd` (`Remove-WmiObject`). Filters are name-filtered
only by `BVTFilter|SCM`; **consumers have no filter at all**. SCCM, Dell Command, HP, Lenovo Vantage
and several backup agents legitimately register subscriptions — this is an auto-selected destructive
action that can fire on a healthy managed endpoint (**rule #1**). Needs a vendor allowlist and a live
re-grade on an SCCM-managed box.

Separately: `$wmiBindings` is fetched (`:1290`) and used only in a zero-count test. The
`__FilterToConsumerBinding` — **the object that actually arms the persistence** — produces no finding,
and the generated fix removes filter+consumer while leaving the binding orphaned.

### P12 — `accessibility_binaries` has three sources of truth
`detection_signatures.json` (8 entries, **orphaned — never read**), `permission_baseline.json` (7,
read via `Get-Perm` at `Phases-3.ps1:1321`), and a hardcoded inline list of 6 at `Phases-1.ps1:2099`.
They have drifted: the JSON copy has `hh.exe`, the baseline does not, so the HTML-Help IFEO backdoor
is listed but never checked. Editing the JSON copy has no effect at all.

### P13 — stale engine copies under `native-app/src-tauri/target/`
`target/{debug,release}/engine-root/ZeroBreach-V23.ps1` exist and the release copy **differs from
source**. Anything run from `target\` silently executes outdated signature-loading code. Never edit
them; ensure the build refreshes them.

---

## 3. Evidence workstreams

Ordered by **evidence value per unit of effort**. Tier A items are default-on and cheap; build these
before anything glamorous.

### Tier A — cheap, default-on, highest value

| # | Item | Why |
|---|---|---|
| **A1** | **Log-availability census** — `Get-WinEvent -ListLog` (`IsEnabled`, `RecordCount`, `MaximumSizeInBytes`, `LogMode`) + oldest record per log | **Do this first.** Makes every other negative result interpretable: "Security log only covers 4h; the alert was 3 days ago; absence of evidence is meaningless." Sub-second, no volume risk. Without it the tool's confident "nothing found" lines are misleading. |
| **A2** | **Defender/Operational log** 1116/1117 (detection + action, **with the creating process and full path**), 5001/5010/5012 (protection disabled), **5007** (config change, old→new — proves an exclusion was added *and later removed*), 1006/1007, 1121/1122 (ASR), 1015, 2050 | Highest-value log for the tool's own primary use case and **not read at all** today. Phase 74.6 uses only `Get-MpThreatDetection`, which goes empty after reboot/platform update. Default-on, but **1 MB default cap — rolls fast**. |
| **A3** | **Defender `DetectionHistory`** string-scrape (`C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\`) + `MPLog-*.log` + `MpCmdRun.exe -Restore -ListAll` | The durable form of A2; survives when the cmdlet returns empty. Binary but densely UTF-16; scrape, don't parse. **Do NOT build the quarantine RC4 parser** — `-ListAll` gets the same answer. |
| **A4** | **Security 4720 / 4726 / 4732** (account created / deleted / added to group) | `4732` + `S-1-5-32-544` is one of the highest-fidelity, lowest-FP compromise indicators that exists, **and it is default-logged**. Catches the create-use-delete case that live Phase 42 cannot see. Trivial volume. |
| **A5** | **Security 4625 / 4672** | Default-on; brute force and anomalous privilege assignment. Currently only 4624 is read. |
| **A6** | **RDP: TS-LocalSessionManager 21/22/25 + RemoteConnectionManager 1149** | 1149 carries the **source IP**. RDP is the #1 SMB ransomware entry vector. Answers "did anyone connect, from where" — which no current phase does. Default-on, trivial volume. |
| **A7** | **BITS-Client 59/3/60** | Event 59 records the **remote URL** of a transfer. One of very few places the *source URL of a payload survives its deletion*. Default-on. Filter `*.microsoft.com`/`windowsupdate` and the residue is tiny. |
| **A8** | **Classic "Windows PowerShell" log, event 400 `HostApplication`** | **The best default-on evidence source the engine is missing.** Carries the full `powershell.exe` command line (`-enc <base64>`, `-nop -w hidden`, download cradles) with **no policy prerequisites** — works on a totally unmanaged endpoint where 4688 and script-block logging are both off. |
| **A9** | **Recycle Bin `$I` records** | ~15 lines of `BitConverter` (header, size@8, deletion FILETIME@16, UTF-16LE path@28). Yields **original full path + deletion time**, per-user via the SID folder. Phase 86 reads only `$R` payloads today. |
| **A10** | **Zone.Identifier `HostUrl`/`ReferrerUrl`** | See P6 — the engine already opens the stream. |
| **A11** | **WER `Report.wer`** (plain text) + Application 1000/1001/1002 | Proves a **now-deleted binary executed**; crashes in `lsass.exe`/`MsMpEng.exe`/the RMM agent are failed-credential-dump / failed-EDR-kill signatures. Phase 106 scans `.dmp` and ignores the informative text file beside it. |
| **A12** | **UserAssist** (ROT13 names; run count@4, last-exec FILETIME@60) + **MUICache** (plain REG_SZ) | Execution evidence persisting after deletion. **Caveat to state in the finding: GUI/Explorer-launched only** — proves *the user double-clicked it*, which for phishing is exactly the question. Inherits P1. |
| **A13** | **`Recent\*.lnk` target extraction** | Phase 10.5's LNK parser already exists; Phase 11 currently only counts. Survives target deletion, identifies removable media. |
| **A14** | **Prefetch ↔ filesystem correlation** | No binary parsing needed: a `.pf` whose executable no longer exists anywhere = **"this ran and is now gone."** Plus `LastWriteTime` ≈ last execution. |
| **A15** | **Scheduled-task `TaskCache\Tree` key LastWriteTime** | The task XML's `<Date>` is attacker-controllable; the registry key write time is not. `Get-RegKeyLastWriteTime` (`ZeroBreach-V23.ps1:1277`) already exists. |
| **A16** | **WMI-Activity 5861** (permanent event consumer) | Definitive WMI-persistence artifact with the full WQL + consumer command line; catches consumers registered *and removed*, which live Phase 30 cannot. Default-on, rare, near-zero FP. |
| **A17** | **System 7034/7031/7040** filtered to a security-service allowlist | A security service crashing repeatedly = defense evasion. **Do not ingest 7036 broadly** (very noisy). |

### Tier B — real work, real payoff
- **ShimCache** binary parse (`HKLM\SYSTEM\...\AppCompatCache`). **Two honesty caveats that must appear
  in any finding built on it: (i) on Win8+ it does NOT prove execution** — presence means the shim
  engine saw the file, which happens on directory browsing; **(ii) it is only flushed to registry at
  shutdown**, so on a box not rebooted since the incident the entries are absent.
- **USN journal** via streamed `fsutil usn readjournal C: csv`. Best "what happened to files that no
  longer exist" source without an `$MFT` parser. **This is the one item that could realistically hang
  a scan** — output can be hundreds of MB. Must be `ProcessStartInfo` + `ReadLine()` streaming with a
  wall-clock deadline and hard line cap; never captured into a variable. Retention is often hours.
- **Browser `History` URL scrape** — download source + referrer. **No SQLite provider exists in PS 5.1
  / .NET Framework**; open with `FileShare.ReadWrite` (locked while browser runs) and regex for URLs.
  Label the finding as a heuristic extraction. **Do not attempt a real SQLite parser.**
- **ShellBags** — string-scrape `BagMRU` for path-shaped fragments (the 80% answer). Full
  `ITEMIDLIST` parsing is not worth it.
- **Full `.pf` parse** — needs `RtlDecompressBufferEx` P/Invoke for Win10/11 MAM compression. Yields
  last 8 execution times + loaded-file list. This is where "pure PowerShell" starts straining.

### Tier C — declined, with reasons
- **SRUM** (`SRUDB.dat`) — per-app bytes sent/received is the best host-side exfil evidence there is,
  but it is an **ESE database, locked, with no in-box managed reader** (ManagedEsent is not in .NET
  Framework; `esentutl` won't dump rows). Requires VSS + a from-scratch ESE parser. **Declined.**
  Affordable substitutes: BITS 59 URLs, Zone.Identifier, Sysmon 3/22.
- **Amcache.hve** — excellent (path + **SHA1** of deleted binaries), but the hive is locked and
  acquisition needs a **VSS snapshot — a system state change**, which conflicts with the audit-only
  scanning contract. If ever pursued, gate behind explicit operator opt-in, never in an automatic
  DEEP scan. Free partial substitute: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`.
- **`$MFT`** — needs a raw volume handle + ~2000-line NTFS parser. **Declined.** Cheap substitute for
  its main prize (timestomping): forged `SetFileTime` values almost always land on whole seconds —
  `.Ticks % 10000000 -eq 0` is one line and near-zero FP on user-directory executables.
- **JumpList CFB parsing**, **Windows Timeline** (`ActivitiesCache.db` — SQLite, locked, and the
  feature was removed in Win11 22H2 so it is mostly empty), **4103 module logging** (off by default,
  enormous volume, overlaps 4104). **Declined.**
- **Sysmon** — read **opportunistically** when the channel exists (cheap `-ListLog` check first).
  When present it dwarfs everything else here.

### Tier D — anti-forensics (a machine with destroyed evidence had something to hide)
Security **1100** (log service shutdown — stops logging without generating a 1102; Phase 1 covers
1102/104 but not this), coverage collapse (oldest record far younger than the incident; log resized
below default), channel `IsEnabled=$false`, `auditpol` explicitly set to No Auditing (distinguish
from never-configured), script-block logging **turned off** (key exists with value 0, or key
LastWriteTime inside the incident window), Prefetch disabled/purged, **USN journal deleted**
(`FirstUsn` age << uptime), Recycle Bin `$R`/`$I` desync, Defender 5007 exclusion round-trips,
timestomping (whole-second FILETIME tell), security-service disruption, `.evtx` files with recent
creation time and tiny size.

---

## 4. Correlation + verdict layer (the genuinely new architecture)

Today the engine emits a flat list of independent findings. Proving infection means **relating** them.

- **Timeline assembly** — normalise every evidence item to `(timestamp, source, actor, object,
  confidence)` and sort. The output an MSP actually wants is a narrative: *"14:02 BITS downloaded X
  from URL; 14:02 Zone.Identifier confirms that URL; 14:03 Prefetch shows X ran; 14:03 Defender 1116
  detected Wacatac at that path; 14:03 1117 action=quarantine **failed**; 14:05 Run key created;
  14:06 4732 added user to Administrators."*
- **Verdict scoring** — combine corroborating independent sources into `CONFIRMED / LIKELY /
  UNPROVEN / LIKELY-FALSE-POSITIVE`. One ML alert alone is *not* evidence. An ML alert **plus**
  execution evidence **plus** persistence **plus** a fresh admin account is.
- **FP suppression inputs** — Authenticode signer, MoTW/zone origin, file age, install location,
  `Test-VendorTrusted`, whether the path is a known-good vendor/RMM tree. A signed vendor binary in
  `Program Files` with a clean origin and no corroborating evidence should be reported as
  **likely false positive**, explicitly.
- **Evidence-availability caveat propagation** — every verdict must carry what could *not* be checked
  (from A1), so "UNPROVEN" is distinguishable from "CLEAN."

Rule #1 still governs: this layer **classifies**, it does not act. Nothing here may auto-select a
destructive `FixAction`.

---

## 5. Alert ingestion framework — pluggable readers

The operator's tickets arrive in many shapes. Rather than one Wacatac path, build a **normaliser +
pluggable readers**: anything that can be parsed becomes a common `ZBAlert` object, which then drives
a targeted scan, an audit, and a fix proposal.

### 5.0 The normalised alert contract

```
ZBAlert = {
  source        # datto | defender-evtx | defender-cmdlet | sentinelone | csv | text | mitre | manual
  raw           # verbatim original, always retained for the report
  detected_utc
  threat_name   # vendor label, verbatim
  platform      # Win32 | Script | MSIL | ...      (parsed from Defender-style names)
  family        # Wacatac | Sabsik | AgentTesla | ...
  variant       # B, C, ...
  confidence    # signature | !ml | !MTB | !MSR | heuristic   <- drives grading
  class         # trojan | pup | adware | miner | rat | stealer | ransomware | hacktool | worm
  severity_src  # vendor's own severity
  file_path[]   # may be empty
  sha256[] md5[] sha1[]
  process[]     # attributed process, when the source provides it
  user
  host
  mitre[]       # T#### / T####.###
  action_taken  # quarantined | removed | allowed | failed | none
  url[] ip[] domain[]
}
```

**Rule: `confidence` gates grading.** An `!ml`/`!MTB` verdict alone may never produce a destructive
auto-selected finding — it must be corroborated by independent evidence (§4). This is the direct fix
for §0.1.

### 5.1 Readers to implement

| Reader | Input | Notes |
|---|---|---|
| **Defender event log** | `Microsoft-Windows-Windows Defender/Operational` 1116/1117/1006/1007/5007 | Richest in-box source; also yields `action_taken` and the attributed process. See A2. |
| **Defender cmdlet** | `Get-MpThreatDetection` / `Get-MpThreat` | Already partly used; must read the discarded properties (P8). |
| **Defender history files** | `DetectionHistory` + `MPLog-*` | Durable fallback (A3). |
| **Datto RMM / Autotask** | pasted ticket body, or exported JSON/CSV | Field names vary by monitor; write a tolerant mapper, keep `raw`. |
| **Generic EDR JSON** | SentinelOne / CrowdStrike / Huntress-style export | Map by best-effort key aliases; never hard-fail on unknown keys. |
| **CSV** | any columnar export | Header-driven mapping with an alias table. |
| **Free-text paste** | the ticket email itself | Regex-extract paths, hashes, threat names, URLs, IPs, MITRE IDs. Lowest fidelity, highest convenience — **the one the operator will use most.** |
| **MITRE technique** | `T1055`, `T1547.001`, … | Resolve via `data/mitre_mapping.json` to the phases that cover it; run those, report coverage honestly (including "not covered"). |
| **IOC file** | existing `-IocFile` format | Already exists; fold into the same contract. |

All readers live behind one interface so a new source is a data/mapping addition, not new engine
logic. Mapping tables and alias lists belong in `data/`, not in `.ps1` (AMSI rule).

### 5.2 Threat-class coverage (beyond trojans)

`class` selects which evidence and which remediation posture apply:

- **PUP / adware / bundleware** — the highest-volume, lowest-severity ticket class. Needs: browser
  extension/policy audit, scheduled-task and service inventory for "updater" shims, uninstall-entry
  correlation, search-provider and proxy/PAC hijack checks. Remediation is **operator-approved
  uninstall**, never silent deletion. Existing `adware_pup_regs` (24) is a starting point, not
  coverage.
- **Coinminer** — existing stratum-port and `known_miner_procs` coverage; add sustained-CPU/GPU and
  persistence correlation.
- **RAT / remote-access misuse** — distinguish *installed legitimately by the MSP* (`Test-VendorTrusted`)
  from *installed by an attacker* (unsigned, user path, no matching uninstall entry, recent).
- **Stealer** — already strong on target paths; add the browser-download provenance and staging
  correlation.
- **Ransomware precursor** — shadow-copy deletion, recovery inhibition, mass-rename bursts (USN),
  ransom-note filenames. Detection only; **never** auto-act.
- **Hacktool / dual-use** — flag with vendor/publisher context; these are the classic "the MSP's own
  tech installed it" false positives.

### 5.4 Universal paste ingestion — "throw anything at it"

The operator pastes whatever the ticket contains: Autotask/Datto ticket bodies, a JSON export, EDR
output, RocketCyber SOC notes, or all three concatenated. The tool must take the blob, find what is
relevant, and produce a game plan. **No format negotiation with the user.**

**Pipeline:** `raw blob` → *format sniff* (JSON / CSV / XML / key-value / log lines / prose — a blob
may contain several, so sniff per-region, never whole-file) → *structured parse where possible* →
*free-text extraction over the remainder* → *entity normalisation + dedup* → *noise suppression* →
*relevance scoring* → `ZBAlert[]` → scan plan.

**Retain, don't destroy.** The raw paste is provenance: it proves where an indicator came from, and
when extraction definitions improve you will want to re-parse old tickets. Park the unmatched
remainder next to the report; never delete it. (It inherits the sensitivity rules in §5.5.)

**Extraction definition catalogue** — all patterns live in `data/` JSON, never in `.ps1` (AMSI), so
they are editable without touching the engine:

- **Hashes** — SHA256/SHA1/MD5, with surrounding-context capture; reject hash-shaped strings that are
  actually GUIDs, JWT segments, git SHAs or base64.
- **File paths** — Windows absolute, UNC (`\\host\share`), env-var forms (`%TEMP%`,
  `$env:APPDATA`), quoted paths with spaces, paths embedded in command lines, Defender resource
  prefixes (`file:_`, `webfile:_`, `containerfile:_`, `process:_`, `regkey:_`, `runkey:_`).
- **Registry keys** — `HKLM\`/`HKCU\`/`HKU\`/`HKEY_*`, and PowerShell `HKLM:\` forms.
- **Network** — IPv4/IPv6, CIDR, domains, URLs, and **defanged forms** (`hxxp`, `[.]`, `(dot)`,
  `[:]`, `\.`) which SOC tools emit constantly and which naive regexes miss.
- **Threat names** — Defender grammar `Type:Platform/Family.Variant!suffix` decomposed into the
  `ZBAlert` fields; plus vendor label forms from SentinelOne, CrowdStrike, Sophos, ESET, Malwarebytes,
  and RocketCyber rule names.
- **Confidence suffixes** — `!ml`, `!MTB`, `!MSR`, `!rfn`, `!bit`, `!lnk`, `!ibt`, `!dha` — each mapped
  to a confidence tier that gates grading (§5.0).
- **PUA/PUP grammar** — `PUA:`/`PUP.`/`Riskware`/`not-a-virus:` prefixes, which must route to the
  PUP class and its softer remediation posture (§5.2).
- **MITRE** — `T1234`, `T1234.001`, tactic names; resolved via `data/mitre_mapping.json`.
- **CVE** — `CVE-YYYY-NNNNN` → patch-hygiene checks.
- **Process / service / task / mutex names**, **command lines**, **base64 blobs** (decode-and-rescan),
  **ports**, **usernames / SIDs / SAM names**, **hostnames / FQDNs**, **MAC addresses**, **email
  addresses**, **certificate thumbprints**, **GUIDs/CLSIDs**, **ticket IDs**, and **timestamps** in
  the many formats these platforms emit (ISO-8601, US `M/d/yyyy h:mm tt`, epoch, FILETIME).
- **Vendor field aliases** — one alias table mapping e.g. `threatName`/`ThreatName`/`detection_name`/
  `RuleName`/`malwareName` → `threat_name`; same for path, hash, host, user, action. Adding a vendor
  is a data edit.

**Noise suppression** (so the game plan is not 400 lines of the operator's own infrastructure):
RFC1918/loopback/link-local IPs, the org's own domains and hostname patterns, Microsoft/vendor signer
names, known-good RMM paths (`Test-VendorTrusted`), the ticketing platform's own URLs, and boilerplate
signature blocks. Suppressed items are *demoted and kept*, never silently dropped.

**Relevance scoring** — each extracted entity carries `(value, type, confidence, provenance-offset)`.
An entity that appears in a structured field outranks the same value scraped from prose. The game
plan is ordered by score, and every line states which phase/check will act on it — including
**"no coverage for this"**, stated explicitly rather than omitted.

### 5.5 Sensitive data handling (operator requirement)

Pasted tickets routinely contain hostnames, internal IPs, MAC addresses, usernames and client
identifiers that must not end up in a report that gets attached to a ticket or emailed onward.

**First, the reassurance:** ZeroBreach runs entirely locally and transmits nothing. Pasting into the
tool is not disclosure. **The exposure is the exported report** — that is what gets controlled.

**The trap to avoid:** naive redaction destroys the evidence. A malicious external IP or C2 domain
*is* the finding. Redaction must therefore classify, not blanket-match.

| Class | Examples | Treatment |
|---|---|---|
| **Internal / PII** | RFC1918 + loopback IPs, MAC addresses, local hostnames, usernames, SIDs, email addresses, client/site names, ticket IDs | **Pseudonymise by default** |
| **Threat indicator** | public IPs, C2 domains, payload URLs, hashes, malware paths | **Never redacted** — they are the answer |
| **Ambiguous** | a public IP that is also the client's own WAN address; a user profile path that is both PII and the payload location | Pseudonymise the *identity* component, keep the *structural* one: `C:\Users\<USER-1>\AppData\Local\Temp\evil.exe` |

**Pseudonymise, don't delete.** Replace with stable tokens — `HOST-1`, `USER-2`, `IP-3` — so the
analytical value survives: the reader can still see that the same host appears in four findings
without learning its name. Blanket `[REDACTED]` destroys that correlation.

- A **local-only key map** (token → real value) is written beside the report, clearly marked
  sensitive, so the tech can de-anonymise locally. It is never embedded in the report itself.
- **Redaction is ON by default for every outbound artifact** — HTML/CSV export, clipboard copy, the
  emailed scheduled-scan report — with a conscious, logged opt-out for internal use.
- The parked raw paste (§5.4) and the key map are both **sensitive artifacts**: same folder
  treatment as the quarantine vault, excluded from any "send report" path.
- Redaction happens at the **render/export boundary**, not at ingestion — the engine reasons over
  real values, and only the output is sanitised. Redacting at ingestion would break matching.

### 5.3 Triage entry point

- Engine: new params (e.g. `-TriageAlert <file|json>`, `-TriageThreat`, `-TriagePath`, `-TriageHash`)
  running a focused, fast subset — **not** a full 115-phase DEEP — but forcing the triage-relevant
  phases regardless of mode (see P9).
- Server: a route + GUI panel that accepts a pasted ticket.
- Output: verdict + timeline + proposed fixes, with everything that could *not* be checked stated
  explicitly (A1).
- The existing `ingest-malware-alert` skill remains the path for turning a *new* family into durable
  signature coverage; this is its runtime counterpart for triaging an *incoming* ticket.

---

## 6. Packaging — the portable `.exe`

**Requirement:** one file, copy to USB or download to a client server, run on any office/client/family
machine, no install, no internet.

**Decision: bundle fixed-version WebView2.** Size is explicitly NOT a constraint — the operator's only
absolute is *"the program has to work flawlessly."* Prefer the self-contained, no-dependency option
every time, at any size.

- Tauri renders via WebView2. A stripped/offline client box may not have it — and after the
  2026-07-26 fix the app would correctly but uselessly show a dialog and exit.
- **The session-16 WebView2 fix is what makes this work**: the old probe checked only the EdgeUpdate
  *registry key*, which a fixed-version deployment never writes, so it would have hard-refused the
  very configuration now chosen. The new primary probe goes through the WebView2 loader, which
  honours `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER`.
- Startup: extract the embedded fixed-version payload next to the exe, or to `%LOCALAPPDATA%` when
  run from read-only USB; set `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER`; launch normally.
- **Defensive fallback retained:** if extraction is impossible (locked-down box, no writable path),
  run headless and emit the self-contained HTML report, opening it in the default browser. Every
  Windows box has a browser; not all have WebView2.
- `tools/Build-Release.ps1` currently has **zero** `native-app`/Tauri awareness — it must be extended
  to produce this artifact.

---

## 7. Constraints every workstream inherits

Non-negotiable, from `CLAUDE.md` and the session-16 lessons:

1. **Rule #1** — nothing damaging may ever auto-fire on a healthy box. Evidence findings are
   inherently `Info`/`POSSIBLE`; a heuristic must never be CRITICAL/HIGH + a destructive `FixAction`.
2. **New detections get a fractional phase inside a non-QUICK block**, plus the `phase_map` entry in
   `data/mitre_mapping.json`. QUICK must stay exactly 30 phases — **count it afterwards**.
3. **Signature literals live in `data/detection_signatures.json`**, never in `.ps1` (AMSI blocks the
   engine at load). This applies with full force to LOLBIN lists, Defender family patterns, benign
   BITS-URL allowlists and event-ID→meaning maps.
4. **Every bulk loop carries a deadline + count budget.** The existing `SCAN_*` / `SIG_AUDIT_*`
   budgets **do not cover event-log or journal reads** — a new budget class is required.
5. **Case-insensitive shadowing** — never name a local the same letters as a broader-scope variable.
   `$auto` silently reassigned the loader's `[switch]$Auto` and would have hung every server-driven
   scan (bool→switch coerces silently; string→switch throws).
6. **Validate on real `powershell.exe` 5.1**, not a PS 7 simulation; keep UTF-8 BOM; parse-clean on
   both runtimes. Use the session-16 gate scripts.
7. **Audit-only during scanning.** The one item that would violate this (VSS for Amcache) is
   excluded.
8. **A new detection is not done until graded against a fresh DEEP baseline on a healthy box.**
   **The "7" figure this document originally quoted is stale and must not be used as a regression
   signal.** It dates from FP round 5 (2026-06-28) on a `-Hours 1` scan. Measured 2026-07-26 on an
   all-time QUICK run, this dev box reported **94** — of which **92 were Phase 10** alone (executable
   extensions in `%TEMP%`, almost entirely accumulated Claude Code harness debris). After the
   2026-07-26 Phase 10 and Phase 30 fixes the same run should report roughly **50**, essentially all
   still Phase 10. **Always attribute an auto-destructive count by phase before treating a change in
   it as a regression** — a single noisy phase dominates the total and makes the headline number
   meaningless on its own. This machine is no longer a clean baseline reference.

---

## 8. Sequencing

> **Status as of 2026-07-26 (session 18).** Step 0 and all of step 1 **except P1** are DONE and
> committed on `session12/review-remediation-ws6`. See `CHANGELOG.md` for the four entries.
> **P1 is the next task**, and has its own committed implementation spec:
> **`P1_MULTIUSER_HIVE_SPEC.md`** — read that, not §2's P1 paragraph, which underestimates the work
> by roughly 8× (~50 call sites, not "~6 phases") and whose line numbers are stale.

0. ~~**P7 + P8 first**~~ — **DONE** (`7d61932`). Defender verdict normaliser + Phase 74.6 rebuilt
   around corroboration; 24 auto-selected FPs → 0.
1. **P1–P6, P9–P13** remaining prerequisite fixes (P1 before anything user-scoped; **P10 before §4**,
   since no verdict can be expressed without the schema).
   - ~~P2, P3, P6, P13~~ **DONE** (`391b6c4`) — event-log truncation, 4688 blindness, Zone.Identifier
     origin, stale-engine dev build.
   - ~~P9, P10~~ **DONE** (`675c957`) — TRIAGE mode (71 phases), 18-field finding schema.
   - ~~P4, P5, P11, P12~~ **DONE** (`1a852af`) — plus the Phase 10 FP tune. Closed a live rule-#1
     violation: Phase 30 auto-selected stock Windows' own `SCM Event Log Consumer` for
     `Remove-WmiObject` on every healthy box.
   - **P1 — OUTSTANDING. This is the next task.** Spec: `P1_MULTIUSER_HIVE_SPEC.md`. Its §0.0 records
     three operator decisions already made (opt-in `-LoadUserHives` **off by default** with a named
     honesty finding per skipped profile; a one-time `-Baseline` re-capture accepted; test account
     approved) and its §0.1 documents the `zbtest2` acceptance-test profile **already created on the
     dev box** — do not re-ask any of these, and do not tear that account down before sign-off.
2. **A1** log-availability census (makes all later results interpretable).
3. **A2–A3** Defender evidence (the primary use case).
4. **A4–A8** default-on Security/RDP/BITS/PowerShell-400 evidence.
5. **A9–A17** artifact quick wins.
6. **§4** correlation + verdict layer.
7. **§5** alert triage entry point.
8. **§6** packaging.
9. Tier B, opportunistically.

Re-grade the healthy-box auto-destructive count after each stage. Re-run the session-16 sandbox
harnesses (parse gate → teardown → Stage F/G) as the regression suite.
