# INSTRUCTIONS_AI.md — ZeroBreach Scan Engine: architecture & detection catalog

**What this is:** the engineering reference for the **native (`zbscan`) engine as built** — the
C# / .NET 8 one. It describes the real architecture, the contracts a scanner codes against, where
each safety rule is enforced, and what all 63 checks actually inspect.

**This file does not cover the PowerShell engine.** The repo ships two maintained engines; the PS
fallback (`ZeroBreach-V23.ps1` + `engine/*.ps1`, 162 phases) is documented in `CLAUDE.md` and
`BLUEPRINT.md` §2. Nothing below applies to it.

**Authority:** `_ENGINE_SPEC_FOR_REBUILD.md` is the contract. This file describes the
implementation of it. If the two disagree, the spec wins — and within the spec, §6 (the safety
model) wins over everything. Section references of the form "§6.7" mean the spec's §6, item 7.

**What the engine is:** a defensive, technician-run, local-only Windows IR scan engine (Loki /
THOR Lite category). It detects indicators of compromise on the machine it runs on and
optionally lets the operator remediate findings behind strict guardrails. It never touches a
remote machine, never runs unattended remediation, and never executes anything it finds.

**Status:** all 10 phases, the §6 safety model, remediation, reporting, custom scans, operator
tooling, and triage are implemented. 293 tests (279 pass, 14 skip off-Windows). Also present and
not yet catalogued below: `Scanning/IScanLogger.cs`, `ZeroBreach.Cli/RunTranscript.cs`, the
`--log <path>` run-transcript flag (`CliOptions.cs`), and the `RunTranscriptTests` suite.

---

## 1. Architecture

### 1.1 Projects

```
ZeroBreach.sln
├── ZeroBreach.Core           model, contracts, budgets, profiles, signatures, reporting, triage
│   ├── Model/                Finding, Severity, FixAction, CheckStatus, MitreRef
│   ├── Scanning/             IScanner, ScanContext, IFindingSink, FindingCollector,
│   │                         EnumerationBudget, PhaseRunner, ScanDepth, ScanProfile, PhaseTiming
│   ├── Profiles/             ProfileEnumerator, UserProfile, HiveLoader
│   ├── Signatures/           SignatureDb, IndicatorEntry, IocExtractor, base.json
│   ├── Reporting/            ScanReport, ScanSummary, FindingJson, HtmlReport, Baseline
│   ├── Triage/               SymptomMap, EscalationEngine, FollowUpPlan, symptoms.json
│   └── Util/                 FileHasher
├── ZeroBreach.Scanners       the 10 phase scanners + Signatures/<category>.json   [READ-ONLY]
├── ZeroBreach.Remediation    ProtectedTargets, RemediationPlanner, ConfirmationGate,
│                             RemediationExecutor, QuarantineVault, ActionLog, ZbPaths
├── ZeroBreach.Cli            zbscan: Program, CliOptions, sessions (remediation / IOC / triage)
└── ZeroBreach.Tests          xUnit
```

All target `net8.0-windows`; `ZeroBreach.Cli` builds `zbscan` as `win-x64`.

### 1.2 The read-only / destructive split

**This separation is architectural, not stylistic.** `ZeroBreach.Core` and
`ZeroBreach.Scanners` contain no destructive operation at all — nothing in `ScanContext` exposes
one. Every mutation of the machine lives in `ZeroBreach.Remediation`, which is small enough to
audit against spec §6 in isolation without reading the (much larger) detection code.

`ScannerReadOnlyAuditTests` enforces it: it greps the Scanners **and Core** sources for mutating
APIs and fails CI if one appears, so a violation is caught by the build rather than by code
review. Scanners have **no** exemptions. Core has exactly three audited ones — `Reporting/`,
`HiveLoader` (opt-in hive mounting, spec §4), and `FollowUpPlan` — all of which write only to the
operator-chosen output dir, never to a scan target; the rest of Triage stays fully audited. A
companion test asserts the audit actually found sources, so it cannot pass silently because a
path walk broke.

Do not add a mutating call to Core or Scanners. If a check genuinely needs one, that is a design
conversation, not a local edit.

### 1.3 Scan flow

```
CliOptions.Parse → profile/triage resolution → SignatureDb.LoadEmbedded (+ rules/IOC files)
  → ProfileEnumerator (+ HiveLoader if --load-hives) → ScanContext
  → PhaseRunner: for each IScanner in Phase order, banner → Run(ctx, sink) → timing
       (escalation between phases when --adaptive)
  → FindingCollector holds findings + check statuses + phase timings
  → Baseline diff (if --baseline) → ScanReport (JSON / JSON.GZ / HTML) → summary → exit code
  → if --interactive: RemediationSession (the only path into ZeroBreach.Remediation)
```

---

## 2. Core contracts

### 2.1 Finding (spec §5)

`ZeroBreach.Core/Model/Finding.cs` — `Id`, `Severity`, `Description`, `Target`, `FixAction`,
`FixParam`, `Mitre`, `Group`, plus `VendorTrusted` (§6.3 soft list badge), `HashConfirmed`
(gates delete-vs-quarantine), and `Check` (the catalog id, e.g. `PERS-001`).

`FixAction`: `None`, `DeleteFile`, `DeleteRegistryValue`, `KillProcess`, `Quarantine`,
`RunCommand`. `IsExecutable()` excludes `RunCommand` — that is what keeps display-only findings
out of every batch.

Fix-param forms, which `ProtectedTargets` vets in exactly these shapes:

| FixAction | FixParam |
|---|---|
| `DeleteFile` / `Quarantine` | full file path |
| `DeleteRegistryValue` | `HIVE\Key\Path::ValueName` (HKLM/HKU form) |
| `KillProcess` | `<pid>:<processName>` |

### 2.2 Deterministic finding ids (spec §5)

`Finding.ComputeId(group, target, discriminator)` = first 16 bytes of
`SHA256(group ␟ target ␟ discriminator)`, all lowercased, hex.

The **discriminator** is what makes two similar artifacts distinct: the profile SID for
per-user artifacts, the value name (and data) for registry hits, the rule/indicator for
signature hits, the full image path for a process — **never the PID**, never a timestamp, never
anything per-run. A re-scan of an unchanged machine must produce identical ids; baseline diff,
adaptive escalation, and ACL drift detection all key on that. Two users' identically-named
artifacts must produce two findings (the original project had a bug collapsing them).

### 2.3 The check ledger (spec §6.7)

Every check reports exactly one status per scope through `IFindingSink`:

```csharp
sink.Completed(phase, check, detail);          // ran, whether or not it found anything
sink.Inconclusive(phase, check, reason);       // could not look, or looked partially
sink.Skipped(phase, check, reason);            // deliberately not run (depth, exclusion, opt-in)
sink.CompleteOrInconclusive(phase, check, budget, scope);   // standard end-of-walk
```

"Didn't look" is never reported as "clean". Access denied, a disabled log channel, an unmounted
hive, an exhausted budget, an unexpected exception — all become `Inconclusive` naming the scope.
Every check body carries its own try/catch so one crash cannot take down a phase.

This propagates all the way out: inconclusive and skipped checks appear by name and reason in
the summary and in every report format, and they drive **exit code 3** ("coverage gaps"), which
is why a narrowed, timed-out, or partially-blind scan can never be mistaken for a clean one.

### 2.4 Enumeration budgets (spec §4 — the most important lesson)

`ScanContext.CreateBudget(baseMaxItems, baseMaxTime)` returns a fresh `EnumerationBudget`,
scaled by depth via `ctx.BudgetScale`.

- **One budget per walked unit** — per user profile, per independent root. Never one budget
  shared across N profiles: that silently gives later profiles zero coverage while the tool
  still reports clean, which is worse than not scanning at all.
- `TryConsume()` returning false latches `Exhausted`, and the owning check is then **required**
  to end `Inconclusive` for that walk's scope. `CompleteOrInconclusive` does this correctly;
  use it.

### 2.5 User profiles (spec §4)

`ProfileEnumerator` reads `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` and
yields a `UserProfile` per user: SID, profile path, and hive state.

- Filesystem locations under `p.ProfilePath` are walkable regardless of hive state.
- A logged-off user's registry hive is only mounted when the operator passes `--load-hives`
  (`HiveLoader`, always unloaded in a `finally`). Never automatic — it is an explicit per-run
  opt-in that a saved profile deliberately cannot express.
- `p.OpenHiveRoot() == null` means that profile's registry checks report
  `sink.Skipped(..., "profile <user>: hive not mounted (run with --load-hives)")`.

### 2.6 ScanContext

`Depth` (`Quick`/`Full`/`Deep`), `SinceUtc`, `Signatures`, `Profiles`, `HiveLoadingEnabled`,
`Log`, `Cancel`, `BudgetScale`, `CreateBudget(...)`, `WithinTimeWindow(utc)`.

`WithinTimeWindow` returns true when the timestamp is **unreadable**: an artifact whose time
cannot be read is never excluded by `--since`, because unreadable timestamps are something
malware can arrange, and a time-narrowed scan that silently dropped them would be an evasion
primitive.

`ctx.Cancel.ThrowIfCancellationRequested()` belongs inside every long loop — it is what makes
`--max-minutes` and Ctrl+C leave honest UNCHECKED phases behind rather than a truncated report.

### 2.7 Signatures

`SignatureDb` loads embedded `Signatures/*.json` from Core and Scanners, plus operator-supplied
`--rules` / `--ioc-file` / `--extract-iocs` content. Sets are addressed as
`ctx.Signatures.Set("<category>.<set_name>")`; `IsVendorTrusted(name)` backs the §6.3 badge.

**No indicator strings, hashes, or IOC patterns live inline in C#** beyond structural constants
(the registry paths a check enumerates are fine). This keeps the binary readable to endpoint
security products and lets signatures update without touching logic. Files are JSONC — `//`
comments are allowed — so they are not parseable by a strict JSON reader.

Format:

```json
{
  "sets": {
    "persistence.startup_suspect_ext": [
      { "pattern": "*.vbs", "kind": "glob", "severity": "high",
        "technique": "T1547.001", "techniqueName": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence", "note": "script in startup folder" }
    ]
  },
  "vendorTrusted": ["..."]
}
```

`kind`: `literal` (add `"substring": true` for contains), `glob`, `regex`, `sha256`.
`severity`: `info|possible|high|critical`. Any content-string indicator that could plausibly hit
documentation or research **must** carry `"needsCorroboration": true`, which structurally caps
its standalone contribution at `Possible`.

Load errors (malformed JSON, bad regex, empty pattern) are collected in `LoadErrors` and
surfaced rather than swallowed; `zbscan rules lint` exists to catch them before an engagement.

### 2.8 Escalation-derived findings

When `--adaptive` is on, escalation arms indicators taken from findings already raised. Any
finding a LATER phase reports on an artifact one of those indicators names is that earlier
finding's echo — the engine went looking for it. `FindingCollector` stamps such findings with
`DerivedFromFindingId` (the id of the source finding) and the report carries it as
`derived_from`.

The stamp exists because the correlation pass must not treat an echo as agreement: without it,
one original signal armed an indicator, a later phase re-found the same artifact, and
correlation counted "two independent checks across two phases" and raised the severity — a
finding corroborating itself. Attribution is deliberately generous (matching the indicator
against target or fix param is enough) because the only consequence is withholding a
severity increase, and over-withholding is the safe direction.

The phase comparison matters: escalation runs *after* a phase, so a finding is never marked by
an indicator its own phase armed. Findings from operator-supplied IOCs are never marked at all —
an indicator the operator brought from outside the machine is genuinely independent evidence.

---

## 3. The safety model, and where each rule is enforced

Spec §6 is the point of the project. Each rule below is enforced in exactly one place so it
cannot drift, and defense-in-depth means the executor re-checks even what the UI already did.

| Spec rule | Enforced by | Guarded by test |
|---|---|---|
| §6.1 auto-select = CRITICAL/HIGH **and** executable destructive action | `RemediationPlanner.QualifiesForAutoSelect` | `SafetyGateTests` |
| §6.2 hardcoded protected targets, no override | `ProtectedTargets.Check` | `ProtectedTargetsTests` |
| §6.3 vendor-trusted soft list (badge, still actionable) | `Finding.VendorTrusted` / `SignatureDb.IsVendorTrusted` | `SignatureDbTests` |
| §6.4 prefer reversible: non-hash-confirmed delete → quarantine | `RemediationExecutor` | `RemediationExecutorTests` |
| §6.5 bulk select shares the individual gate | `RemediationPlanner.BulkSelect` | `SafetyGateTests` |
| §6.6 text-extracted IOCs need individual confirmation | `IocReviewSession` + `IocExtractor` | `IocExtractorTests` |
| §6.7 never "clean" for a check that could not run | `IFindingSink` ledger + exit code 3 | `ScanReportTests`, `CancellationCoverageTests` |
| §6.8 guard flag set-then-`finally`-reset | `RemediationExecutor` (`Interlocked` + `finally`) | `RemediationExecutorTests` |
| §6.9 typed `CONFIRM` before any batch | `ConfirmationGate` + re-validated in the executor | `SafetyGateTests` |
| §6.10 append-only hash-chained action log | `ActionLog` | `ActionLogTests` |

### 3.1 Protected targets (§6.2)

`ProtectedTargets` is a hard block with **no configuration input, no flag, and no API to
bypass a Blocked verdict**. It covers core OS directories (with one deliberate carve-out:
`%WINDIR%\Temp`, a common malware drop location containing no OS-critical files), the
certificate trust store, LSA / boot / code-integrity registry keys, OS-critical processes, and
security tooling (an IR tool must not be usable to switch off protection).

Path comparison is done on a resolved form, so the block cannot be dodged by syntax: the `\\?\`
prefix is stripped, `.`/`..` and slashes are normalized, 8.3 short names (`PROGRA~1`) are
expanded when the file exists, and trailing dots/spaces the Win32 layer would ignore are
dropped. `Check` is called **immediately before every action**, not only at planning time.

### 3.2 Remediation execution (§6.4, §6.8, §6.9, §6.10)

`RemediationExecutor.ExecuteBatch` re-enforces every gate even if a caller is buggy:

- the typed confirmation is validated here, not only in the UI;
- the protected-targets check runs immediately before each action;
- a `DeleteFile` without `HashConfirmed` is **downgraded to quarantine** by the executor itself;
- `RunCommand` is never executed, ever — there is no code path in this tool that executes a
  string it found on the machine;
- a process is killed only when the live process's name still matches the name recorded at scan
  time, because PIDs get reused;
- only registry **values** are deleted, never keys;
- the concurrency guard is `Interlocked` set-then-`finally`-reset;
- every attempt and outcome — including refusals — is appended to the action log.

### 3.3 Evidence integrity (§6.10)

`ActionLog` writes JSONL where each entry's hash covers the previous entry's hash, under an
exclusive file lock so two processes cannot fork the chain. `VerifyChain()` re-walks it and
names the first broken sequence number.

A hash chain alone cannot detect **truncation**: removing entries from the end leaves a shorter
chain whose every link still verifies, so the record of what was destroyed could be quietly
erased. Each append therefore also writes an anchor file beside the log (entry count, last seq,
head hash), and verification reports four distinct states — `Intact`, `Broken` (an entry edited
or removed mid-chain), `Truncated` (the log is shorter than the anchor, or gone entirely), and
`Unverifiable` (no anchor, or a stale one — the links verify but completeness cannot be proven).
The anchor is not a secret and can be deleted too; what it buys is that shortening the record now
requires editing two files consistently, and that an unprovable chain is never reported as OK.
`zbscan log verify` exits 0 / 2 / 3 accordingly — `Unverifiable` is a coverage gap, not a clean
result (§6.7). `QuarantineVault.VerifyAll()` is the companion: it
re-hashes every vaulted file against the SHA-256 recorded at quarantine time, reporting `Ok`,
`HashMismatch`, `FileMissing`, or `HashUnknown` — "couldn't be hashed at quarantine time" is
never assumed fine. Together they prove both *what was done* and *that the evidence is intact*.

`QuarantineVault.Purge` is the one irreversible vault operation; it refuses any manifest whose
vault file points outside the vault root, so a tampered manifest cannot turn purge into an
arbitrary-file delete, and it is gated behind the same typed `CONFIRM` and logged like any
remediation.

State lives under `%ProgramData%\ZeroBreach` (`ZbPaths`): `Vault\`, `action-log.jsonl`.

---

## 4. Scan surface

### 4.1 Modes and depth

`ScanDepth` is `Quick` ⊂ `Full` ⊂ `Deep`. **STEALTH is not a depth** — it is an output mode
(silent console, one compressed `.json.gz` blob) combined with FULL depth. Each scanner declares
a `MinDepth`; individual sub-checks gate further on `ctx.Depth` so QUICK stays fast (registry
reads and small fixed file sets only).

### 4.2 Commands and flags

`zbscan` subcommands: `scan` (default), `triage`, `categories`, `report show`, `rules lint`,
`vault list|verify|restore|purge`, `log verify|show`, `help`. The authoritative flag list is
`CliOptions.Usage`; operator-facing explanations live in `docs/`.

Exit codes: **0** clean · **2** findings · **3** coverage gaps (inconclusive / skipped /
unchecked) · **1** usage or operational error. `zbscan report show` mirrors them, so a saved
STEALTH blob is consumable by a script exactly like a live run.

### 4.3 Custom scans, operator tooling, triage

These are documented for operators, and the docs are the specification of their behavior:

- `docs/CUSTOM_SCANS.md` — `--only`/`--skip` category selection, saved scan profiles, and what
  a profile can never express (`--load-hives`, `--interactive`, baselines — all per-run).
- `docs/OPERATOR_FEATURES.md` — `--max-minutes`, `--case`/`--operator`, `report show`,
  `rules lint`, `--extract-iocs`, baseline sanity warnings, vault `verify`/`purge`,
  `categories`, per-phase timings.
- `docs/TRIAGE.md` — symptom-driven scan derivation (`SymptomMap` + `Triage/symptoms.json`),
  adaptive in-run escalation (`EscalationEngine`, leads, generated follow-up profile), and the
  optional Gemini assist whose output is treated as untrusted text.

Two invariants worth restating because they are safety properties, not features: a triage guess
that matches nothing makes the scan **broader**, never narrower; and nothing in triage,
escalation, or IOC extraction has a path into remediation — everything they arm is
detection-only, `Possible`, with no fix action.

---

## 5. Detection catalog

Conventions: each check has an id (`PERS-001` …) and a depth tier; *(per-profile)* means it
iterates `ctx.Profiles` with a fresh budget each. Severities below are the defaults —
corroboration raises them, dual-use caps them. All pattern/name/hash tables come from the
category's signature file, never inline.

### Phase 1 — Persistence (`PersistenceScanner`, QUICK)

- **PERS-001 Run/RunOnce keys** *(per-profile)* — HKLM plus the 32-bit view plus each
  `HKU\<SID>` under `...\CurrentVersion\Run*`. Signals: value data pointing into user-writable
  dirs, encoded PowerShell (`-enc`, `FromBase64String`), `mshta`/`rundll32` with URL or script
  args, orphaned targets. T1547.001. Fix: `DeleteRegistryValue` at HIGH+.
- **PERS-002 Startup folders** *(per-profile)* — per-user and all-users Startup. `.lnk` targets
  into user-writable paths (resolved read-only via WScript.Shell), scripts, double extensions.
  Fix: `Quarantine`.
- **PERS-003 Scheduled tasks** — task objects plus the raw XML under `System32\Tasks` (the XML
  shows what the API hides): actions in user-writable paths, encoded PS, `Hidden`, logon/boot
  triggers with blank author, names imitating `\Microsoft\Windows\` tasks. T1053.005. Fix:
  display-only `RunCommand` for the task, `Quarantine` for the payload file.
- **PERS-004 Services** — `Win32_BaseService`, so kernel-mode **driver** services are covered
  alongside user-mode ones (`Win32_Service` alone cannot see a rootkit's registration).
  ImagePath in a user-writable dir (HIGH), unquoted path with spaces (T1574.009), unsigned
  binary, svchost-hosted service whose ServiceDll sits outside System32, and a registered
  binary that is **missing from disk** (the mirror of PERS-003's missing task target). Native
  image paths (`\??\`, `\SystemRoot\`, System32-relative) are resolved first, or every driver
  would silently skip signature and hash inspection; an unresolvable form yields no finding
  rather than a guess. T1543.003.
- **PERS-005 WMI event subscriptions** — `root\subscription`: `__EventFilter`,
  `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `__FilterToConsumerBinding`. Any
  command-line/script consumer is at least POSSIBLE; matching script content is CRITICAL.
  T1546.003.
- **PERS-006 Winlogon / AppInit / IFEO** — `Shell` ≠ `explorer.exe`, `Userinit` with extra
  entries, `AppInit_DLLs` non-empty with loading enabled (T1546.010), IFEO `Debugger` and
  `GlobalFlag`+`SilentProcessExit` pairs (T1546.012).
- **PERS-007 COM hijack** *(per-profile)* — `HKU\<SID>\Software\Classes\CLSID\*\InprocServer32`
  defaults pointing at user-writable paths: per-user COM overriding HKLM is the classic hijack.
  T1546.015. Budgeted walk.
- **PERS-008 Browser extensions** *(per-profile, FULL)* — Chromium `Extensions\<id>\<ver>\
  manifest.json` (bounded read) for broad-permission unpacked extensions and known-bad ids;
  Firefox `extensions.json`.
- **PERS-009 Office trust & Outlook** *(per-profile, FULL)* — VBA warning policy set to enable-
  all, Trusted Locations in user-writable paths, Outlook `WebView`/homepage keys (T1137.004),
  recently modified `VbaProject.OTM`.
- **PERS-010 Shell extensions** *(DEEP)* — context-handler CLSIDs resolving to user-writable
  DLLs. Budgeted registry walk.

Evidence is accumulated as weighted signals: Info-level notes never arm a finding on their own,
and an indicator marked `NeedsCorroboration` caps at POSSIBLE standalone.

### Phase 2 — Defense evasion (`DefenseEvasionScanner`, QUICK)

- **DEFE-001 Defender state** — real-time protection off (HIGH), tamper protection off, and
  every exclusion path/process enumerated as INFO — the exclusion list *is* the finding, since
  it is the quietest attacker move available. Defender unavailable (third-party AV) →
  Inconclusive, not clean. Tamper-protection state comes from Defender's own WMI provider
  (`MSFT_MpComputerStatus.IsTamperProtected`), never from the `Features\TamperProtection`
  registry value, whose encoding varies by build and management state; when the provider cannot
  be reached the state is a disclosed coverage gap, never asserted.
- **DEFE-002 AMSI / ETW tamper** — AMSI provider registrations pointing at non-standard DLLs,
  `amsi.dll` present outside System32 (search-order hijack), EventLog autologger disabled.
  Known-good provider roots are structural constants.
- **DEFE-003 Event log health** — EventLog service state, per-channel enabled/max-size, recent
  clear events (Security 1102 / System 104). A disabled log is both a finding here and the
  reason a Phase 10 check reports Inconclusive.
- **DEFE-004 PowerShell logging posture** — ScriptBlockLogging / ModuleLogging / Transcription
  policy keys. Recently *disabled* (key last-write inside the window, read via
  `RegQueryInfoKeyW`) is far more interesting than never-enabled.
- **DEFE-005 LOLBin activity** *(FULL)* — from Security 4688 command lines, falling back to
  Prefetch: `certutil -urlcache/-decode`, `mshta http`, `regsvr32 /i:http scrobj`, `rundll32`
  with `javascript:`, `bitsadmin /transfer`, script hosts running from temp. Neither source
  available → Inconclusive, never clean.
- **DEFE-006 Timestomp heuristic** *(DEEP)* — executables in user-writable dirs whose creation
  time matches a known OS binary's or is inconsistent with filesystem ordering. Always
  POSSIBLE, and the description says it is a heuristic.

### Phase 3 — C2 / RAT (`C2Scanner`, QUICK)

Dual-use is the defining problem of this phase: an RMM agent, a reverse proxy, and a tunneling
client look identical to a legitimate deployment of the same tool. **Anything whose
maliciousness depends on context rather than content caps at POSSIBLE** (INFO when
vendor-trusted) with `FixAction.None`. Only inherently attacker-specific artifacts go higher.

- **C2-001 Named pipes** — enumerates the pipe namespace and matches against the `named_pipes`
  patterns (Cobalt-Strike-style `msagent_##`/`postex_####`, other implant shapes). Pipe match
  plus an owning process outside System32 is CRITICAL; a match alone is HIGH. `KillProcess` is
  offered only when the owning image is itself in a user-writable path.
- **C2-002 Network connections** — for each established/listening endpoint, PID attribution via
  `GetExtendedTcpTable`, then owner image path and signature state. Owner in a user-writable dir
  (HIGH), `0.0.0.0` listeners on non-standard ports owned by unsigned binaries (HIGH), peers in
  the `c2_ips` set (CRITICAL). RFC1918/loopback peers are excluded from external-C2 logic but
  still reported at INFO when the owner is unsigned. Discriminator = owner image + remote
  address + port + protocol, never the PID or ephemeral local port. A companion check
  correlates `custom.domains` IOCs against the DNS client cache and current remotes.
- **C2-003 DNS beacon periodicity** *(FULL)* — requires
  `Microsoft-Windows-DNS-Client/Operational`; without it, Inconclusive naming the channel.
  Buckets queries per domain and flags regular inter-arrival intervals by coefficient of
  variation (jitter-tolerant, threshold from the data file), with known-telemetry domains
  excluded and the exclusion stated in the description. Always POSSIBLE, always no fix — this
  is an analyst lead, not something to act on.
- **C2-004 RMM / remote-access inventory** — uninstall keys (both views, plus per-profile),
  services, and running processes matched against `rmm_tools`, each entry carrying the §6.3
  vendor-trusted flag. A trusted match is INFO with the badge and a note that it is legitimate
  software commonly abused for hands-on-keyboard access; it stays manually actionable but fails
  the auto-select gate by construction. Unknown tooling in a user-writable path, or installed
  inside the time window, is POSSIBLE→HIGH. **Nothing here is ever auto-uninstalled** — killing
  an MSP's own RMM agent mid-engagement is the self-inflicted outage §6 exists to prevent.
- **C2-005 Tunneling / proxy tooling** — `netsh interface portproxy` entries read from the
  backing registry key (not by shelling out, so localization can't break it): an external-to-
  internal forward on a workstation is HIGH. Plus SSH reverse-tunnel configs in user profiles,
  tunneling processes, and tunneling binaries on disk. Fix is display-only `RunCommand`.
- **C2-006 Implant config residue** *(FULL)* — bounded scans for the *shapes* in
  `config_shapes`: narrow size band with high entropy behind a specific magic prefix, oversized
  base64 blobs in `.lnk`/`.hta`/`.js`. Benign format magics are excluded from the entropy
  heuristic. One signal is POSSIBLE; two independent signals are HIGH.
- **C2-007 Host-resolution and proxy tampering** — `hosts` entries redirecting security-vendor
  or OS-update domains (HIGH — classic AV blinding), per-user `ProxyServer`/`AutoConfigURL`
  (`AutoConfigURL` to a raw IP is HIGH), and adapter DNS servers that are neither DHCP-assigned
  nor well-known. All `FixAction.None`: network config changes are for the operator to make
  deliberately.

Authenticode evidence in this phase distinguishes "no embedded signature" from "signature could
not be verified", and only asserts "unsigned" for images outside trusted roots.

### Phase 4 — Credential access (`CredentialAccessScanner`, FULL)

Detection is by **hash and content, never bare filename**: a file named `mimikatz.exe` may be a
renamed calculator in a training folder, and `svc_helper.exe` may be the real thing. Name
matches only raise a finding that hash or content already justified. This phase never opens,
parses, or decrypts credential material — presence, location, and metadata only. That is a hard
scope boundary, not a performance choice.

- **CRED-001 Dumping-tool presence** — SHA-256 against `known_bad_hashes` → CRITICAL
  (hash-confirmed is the one case where delete is justified; quarantine remains preferred).
  Unmatched candidates go to the content matcher: a content match with an unsigned or invalid
  signature is HIGH → `Quarantine`. A name-only match is POSSIBLE and says "name match only,
  not corroborated" in the description.
- **CRED-002 LSA protection posture** — `RunAsPPL` absent/0, RestrictedAdmin anomalies,
  Credential Guard state. Reported as a hardening gap, not evidence of compromise; the key is
  in the protected-registry list, so these are report-only by construction.
- **CRED-003 WDigest / NTLM policy** — `UseLogonCredential = 1` is HIGH (it forces cleartext
  credentials into memory and has no legitimate modern use; T1112 + T1003.001).
  `LmCompatibilityLevel` below 3 and `NoLMHash = 0` are POSSIBLE hardening findings. No fix
  action — policy belongs in configuration management, not an IR tool.
- **CRED-004 LSASS access telemetry and dump files** — Sysmon 10 / Defender operational log;
  neither present → Inconclusive. Dump files (`lsass*.dmp`, minidumps in temp whose module list
  contains lsass) are CRITICAL → `Quarantine`, with the description stating that the dump is
  **evidence to preserve**, not to delete.
- **CRED-005 Registry hive copies** — `SAM`/`SYSTEM`/`SECURITY` copies outside
  `System32\config`, detected by `regf` header magic plus size band rather than by name.
  CRITICAL → `Quarantine`. Also `reg save` / `esentutl` residue.
- **CRED-006 DPAPI and browser credential-store artifacts** *(per-profile)* — masterkey dirs
  with unexpected ownership or in-window modification; a `Login Data` copied out of its profile
  (into `%TEMP%`, say) is HIGH, because legitimate software reads it in place.
- **CRED-007 Credential-adjacent command lines** — tasks and services referencing `vaultcmd`,
  `cmdkey /list`, `ntdsutil`, `esentutl` against a hive, or `reg save hklm\sam`. HIGH.

### Phase 5 — Ransomware indicators (`RansomwareScanner`, QUICK)

- **RANS-001 Ransom notes** *(per-profile)* — document/desktop/downloads roots and drive roots
  under a per-profile budget, matched against `ransom_note_patterns`. Name alone is POSSIBLE;
  name plus note-like content (bounded read containing payment/contact/onion patterns) is
  CRITICAL. Notes are **evidence**: no fix action, and the description says to preserve them.
- **RANS-002 Known extension renames** — counts files matching `known_ransom_extensions`, and
  reports **one aggregate finding per extension per root** with a count. Not one finding per
  file: a hundred thousand findings is a denial of service against the operator.
- **RANS-003 Entropy anomaly** *(FULL)* — samples files with normally-low-entropy extensions
  (`.txt`, `.csv`, `.rtf`, `.sql`, `.log`; already-compressed formats like `.docx` excluded),
  computes Shannon entropy over a bounded prefix, and reports one aggregate finding stating the
  sampled fraction and sample size. High entropy alone is POSSIBLE; with a note or extension
  match it is CRITICAL. **If the budget ran out before the sample floor was reached, the check
  is Inconclusive, not clean.**
- **RANS-004 Recovery tampering** — evidence of the destructive commands rather than running
  them: `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`,
  `bcdedit /set recoveryenabled no` and friends, found in 4688 / PowerShell 4104 command lines,
  scheduled-task actions, and service ImagePaths; plus current shadow-copy and BCD state read
  read-only. CRITICAL when a deletion command is evidenced. **Fix action is `None` or
  display-only `RunCommand`, never anything executable** — spec §3 and §6.8 name this case
  directly, and the code carries a region comment saying so, for the future contributor who
  tries to add a helpful fix button.
- **RANS-005 Recovery environment (WinRE)** — WinRE disabled inside the window is POSSIBLE→HIGH
  alongside other Phase 5 hits.
- **RANS-006 Mass modification** *(DEEP)* — in-window modification rate per document root,
  aggregate only; escalates the phase verdict in combination with other Phase 5 findings.

### Phase 6 — Email / phishing residue (`EmailResidueScanner`, FULL)

**Hard scope boundary (spec §3): the per-user attachment cache only. The engine never
enumerates, opens, or parses an OST/PST mail store** — it is multi-gigabyte, locked, and
contains the client's entire correspondence; reading it is both a performance disaster and a
privacy problem a scan engine has no business creating.

- **MAIL-001 Attachment cache** *(per-profile)* — resolves `OutlookSecureTempFolder` per profile
  and per Office version (absent value → Inconclusive for that profile, not clean) and walks it
  under a per-profile budget. Flags macro-capable documents, archive-wrapped executables,
  `.iso`/`.img`/`.vhd` containers (standard MOTW-evasion delivery), `.lnk`, double extensions. A
  macro-capable file plus an actual macro-content signal (`vbaProject.bin` seen by reading the
  zip central directory, no full extraction) is HIGH → `Quarantine`. A bare `.docm` is POSSIBLE
  at most — people legitimately receive macro documents.
- **MAIL-002 Mark-of-the-Web provenance** *(per-profile)* — reads the `Zone.Identifier`
  alternate data stream for Downloads and cache candidates; ADS unavailable (non-NTFS) →
  Inconclusive. `ZoneId=3` with a `HostUrl` matching an IOC domain is HIGH. An executable with
  **no** MOTW whose siblings all have one is POSSIBLE — stripped MOTW is an evasion, but also a
  normal artifact of copying from a USB stick, and the description says so.
- **MAIL-003 Script droppers** — candidates from MAIL-001/002 go through the content matcher; a
  corroborated match is HIGH → `Quarantine`.
- **MAIL-004 Outlook client-side persistence** — deliberately overlapping PERS-009: rules blobs
  with run-application/run-script actions, and `VbaProject.OTM` modified in-window. The rules
  blob format is not parsed — presence and mtime tell the operator where to look. HIGH when it
  changed in-window on a box with other Phase 1/6 findings.

### Phase 7 — Rootkit / boot integrity (`RootkitBootScanner`, FULL)

Read-only throughout, and several checks need elevation. Unelevated, each affected check reports
Inconclusive with reason `"requires elevation"` — it never disappears from the ledger.

- **ROOT-001 Process enumeration discrepancy** — enumerates processes by independent means and
  diffs them. Discrepancies are **re-checked before reporting**, because short-lived processes
  are the dominant false positive and a naive diff produces noise on every busy machine. HIGH,
  no fix action: a hidden process is a forensics lead, not something to kill blind.
- **ROOT-002 Driver inventory & BYOVD** — drivers by service record and by file, under budget:
  signature status, signer, SHA-256, matched against `vulnerable_drivers` (legitimately signed
  drivers with known exploitable primitives). Unsigned drivers currently running are HIGH.
  Loaded drivers carry no fix — unloading one from a scan tool risks bugchecking a production
  box; a non-running driver *file* may carry `Quarantine`. The loose-`.sys` sweep is DEEP-only,
  so below DEEP it is reported as its own **Skipped** ledger entry — "N registered drivers
  checked" must not read as full coverage of the drivers directory (§6.7).
- **ROOT-003 Boot configuration (BCD)** — `testsigning`, `nointegritychecks`, custom bootdebug,
  `recoveryenabled no`, unexpected loader paths. `testsigning`/`nointegritychecks` is HIGH: it
  is the precondition for loading an unsigned rootkit driver. Display-only `RunCommand`, since a
  wrong BCD edit is a non-booting machine.
- **ROOT-004 Secure Boot / firmware posture** — Secure Boot state and UEFI vs MBR boot mode;
  legacy BIOS is INFO ("not applicable"), not a failure.
- **ROOT-005 MBR bootstrap inspection** *(DEEP, elevated)* — opens `\\.\PHYSICALDRIVE0`
  **read-only**, hashes the first sector, compares against known-good bootstrap hashes.
  Mismatch is POSSIBLE, with the description noting that OEM tooling and multi-boot loaders also
  produce mismatches. There is no remediation path for this check, by design.
- **ROOT-006 Kernel-mode integrity posture** — HVCI / memory integrity and Device Guard
  services; disabled-but-capable is POSSIBLE.

### Phase 8 — Permission / ACL integrity (`AclIntegrityScanner`, DEEP)

Principals are matched by **well-known SID, never by localized account name**. Effective rights
are computed as allow-minus-deny with generic bits normalized. Every finding is `FixAction.None`
or a display-only Info `RunCommand`: `icacls` repair has real blast radius and stays a
deliberate operator action, so the recommended command appears in the description only.

- **ACL-001 System path ACL drift** — write/modify granted to broad low-privilege principals
  (Everyone, Authenticated Users, BUILTIN\Users) on high-value system paths, and owners that
  are not TrustedInstaller/Administrators/SYSTEM. A writable system binary is a direct
  privilege-escalation primitive.
- **ACL-002 Service binary and service key permissions** — either the ImagePath binary or
  `HKLM\SYSTEM\CurrentControlSet\Services\<name>` writable by a non-admin principal.
- **ACL-003 Unquoted service paths with writable interception points** — an unquoted path is
  only exploitable when an intermediate directory is writable, so the check computes that rather
  than flagging every unquoted path. Unquoted **and** writable is HIGH; unquoted alone is INFO.
  That precision is what keeps an operator reading the report instead of skimming it.
- **ACL-004 Startup-adjacent directory permissions** *(per-profile)* — all-users Startup, the
  Start Menu tree, and the scheduled-task directory writable by non-admins.
- **ACL-005 ACL baseline comparison** — reported as **Skipped** with an explicit reason:
  scanners are read-only and cannot persist a baseline snapshot, so drift detection is provided
  by the engine-level `--baseline` mode instead, which works precisely because this scanner's
  finding ids are deterministic. Never silently absent.

### Phase 9 — Content scanning (`ContentScanScanner`, DEEP)

The engine's one piece of real algorithmic surface: a YARA-lite matcher driven entirely by rules
in the signature file.

1. **Candidate selection** — never walks `C:\` wholesale. Roots are per-profile user-writable
   hot paths (Downloads, Desktop, Temp, AppData) each with a **fresh budget per profile**, plus
   machine temp/public/ProgramData roots each with their own budget.
2. **Cheap gates before expensive work**: extension/name filter → size band → magic-byte sniff
   (a `.txt` starting with `MZ` is itself a finding) → bounded read of head and tail only, never
   the whole file → pattern match.
3. **Encoding** — matches against both a latin-1 and a UTF-16LE view, so wide-string constants
   inside PE files are caught. No unpacking, decompression, or emulation: a malware-parsing
   surface is the last thing this tool should grow.
4. **Corroboration is structural, not advisory** (spec §3). Every content-string indicator is
   marked `NeedsCorroboration` in the signature file, so a single hit can never exceed
   `Possible` — a saved vendor advisory, an IR report on the technician's desktop, or this
   project's own spec must not escalate. Reaching the indicator's own severity requires 2+
   independent signals (distinct indicators, a magic/extension mismatch, or a filename trick),
   and content matches alone are hard-capped at HIGH: **CRITICAL requires hash confirmation, and
   the shipped known-bad hash set is intentionally empty** (operator-extendable; no fabricated
   hashes).
5. **Self-exclusion** — the tool's own directory, its signature data, the quarantine vault, and
   the report output are removed from the candidate set. Otherwise the signature file matches
   itself and every run reports the scanner as malware; this is a real bug that ships in tools
   of this kind.

Checks: **CONT-001** rule matching, **CONT-002** magic/extension mismatch, **CONT-003** filename
tricks (RTL-override characters, double extensions, homoglyphs and trailing whitespace in
executable names — these have essentially no legitimate use), **CONT-004** custom-IOC matching
over the same candidate set.

### Phase 10 — Event Log correlation (`EventLogScanner`, FULL)

All access goes through `System.Diagnostics.Eventing.Reader` with XPath filters bounded by event
id, time window, and enumeration budget — **never an unfiltered read of a large log**, which
would hang the scan. Every channel gets a precondition probe: disabled or unreadable makes the
dependent check Inconclusive **naming the channel**; "readable but no matches" is Completed.
This phase is where §6.7 earns its keep, because a cleared or disabled Security log is the most
common state on a compromised machine. Default lookback when no `--since` is given: 14 days at
FULL, 30 at DEEP, and every check states the window it used.

- **EVTX-001 Log clearing** — Security 1102, System 104. HIGH, CRITICAL inside the window, with
  who and when in the description.
- **EVTX-002 Service installation** — System 7045 (and Security 4697 where audited), with the
  ImagePath from the event. A 7045 for a service that no longer exists is HIGH:
  install-run-remove is a classic pattern — except for platform components that install and
  remove themselves by design, listed in `eventlog.service_install_benign_transient`
  (Defender's randomly-named `MpKsl*` definition drivers fired this on every clean box). A
  match still produces a finding, but never a transient- or path-derived severity; an
  operator's own IOC hit still outranks the allowance.
- **EVTX-003 Process creation heuristics** — Security 4688. Without command-line auditing the
  check degrades to name-only matching and reports **partial coverage as Inconclusive**, not
  Completed. Flags Office/browser parents spawning script hosts or shells, reconnaissance bursts
  (`whoami`, `net group "domain admins"`, `nltest`) from one parent, and the LOLBin table shared
  with DEFE-005.
- **EVTX-004 Account manipulation** — 4720 create, 4732/4728 privileged-group additions, 4738,
  4724 password reset, and 4625 bursts followed by a 4624 success (spray→hit). Local admin
  additions in the window are HIGH — unless the member is a machine-managed principal (virtual
  service account, IIS app pool, machine account, matched by well-known SID), which is what
  installers add routinely. Windows writes a literal `-` in `MemberName` when only the SID was
  logged; that is treated as absent and the SID carries the identity, so the finding always
  names someone the operator can act on.
- **EVTX-005 Remote access logons** — 4624 type 10 (RDP) and type 3 from non-RFC1918 sources,
  RDP `RemoteConnectionManager` 1149, and successful logons for accounts with no interactive
  history. POSSIBLE→HIGH with source addresses listed.
- **EVTX-006 PowerShell activity** — 4104 script blocks matching `script_patterns` (encoded
  commands, download cradles, AMSI-bypass shapes), 4103 module logs, and 400/403 engine
  lifecycle showing a downgrade to v2 (`HostVersion 2.0` is a deliberate logging bypass → HIGH).
  ScriptBlockLogging never enabled → Inconclusive.
- **EVTX-007 Defender history** — 1116/1117 detections and 5001/5010/5012 protection-disabled
  events. **A prior detection the product did not fully remediate is exactly the lead this scan
  exists to follow up**: HIGH, quoting the threat name and path.
- **EVTX-008 WMI activity** *(DEEP)* — `WMI-Activity/Operational` 5857/5860/5861 permanent
  consumer registration, cross-referenced with PERS-005.
- **EVTX-CORR cross-phase correlation** — after the phases, findings are grouped by normalized
  path-like target, **excluding escalation-derived findings** (§2.8 — a finding that exists only
  because an earlier finding armed the indicator that found it is that finding's echo, not a
  second opinion; counting it let one signal escalate itself). When ≥2 distinct check ids from
  ≥2 distinct phases hit the same target, a
  **new** correlation finding is emitted (`group = correlation`, severity one step above the
  highest contributor, capped at CRITICAL) referencing the contributing ids. Original findings
  are **never mutated** — baseline diff depends on their stability, and an operator needs to see
  the raw signals. The discriminator is the sorted list of contributing check ids, so the
  correlation finding is itself deterministic. If the sink does not expose collected findings,
  the pass reports Skipped rather than silently doing nothing.

---

## 6. Testing

`dotnet test` — 293 tests. Windows-only semantics (protected dirs, registry, remediation paths)
use `[SkippableFact]` with `Skip.IfNot(OperatingSystem.IsWindows(), ...)`; that is the right
pattern for new ones. Never weaken an assertion to make it pass off-Windows.

The suites that matter most when changing behavior:

- `SafetyGateTests`, `ProtectedTargetsTests`, `RemediationExecutorTests`, `ActionLogTests`,
  `QuarantineVaultTests` — the §6 model. A change that makes one of these go red is a safety
  regression until proven otherwise.
- `ScannerReadOnlyAuditTests` — the read-only/destructive split, enforced by source grep.
- `CoreModelTests` — deterministic ids: same input → same id; same filename in two directories →
  different ids; same path with different value data → different ids.
- `CancellationCoverageTests`, `PhaseFilterTests`, `PhaseTimingTests`, `ScanReportTests` —
  coverage honesty: cancelled, excluded, and timed-out phases surface as UNCHECKED and reach the
  exit code.
- `LiveRunRegressionTests` — defects found on the first live Windows run: event-field identity,
  machine-managed principals, native service-image resolution, the benign-transient service
  allowance, and the circular-corroboration guard. Each test names the wrong behavior it locks
  out; they are the regression floor for false positives on healthy machines.
- `SignatureDbTests`, `IocExtractorTests`, `SymptomMapTests`, `EscalationTests`,
  `ScanProfileTests`, `CliOptionsTests`, `BaselineTests`, `CategorySelectionTests`,
  `GeminiSymptomAssistTests` — data-driven surfaces where a typo would otherwise silently change
  scan scope.

## 7. Extending the engine

- **A new check in an existing category** — add it to that scanner, add its indicators to that
  category's signature JSON, follow `docs/SCANNER_GUIDE.md`.
- **A new category** — a new `IScanner` with the next phase number, its own signature file, and
  its group name added to the category list in `CliOptions.Usage`. `zbscan categories` reads the
  live scanner list, so it cannot drift.
- **A new remediation capability** — this is the one change that needs the spec re-read first.
  It must go in `ZeroBreach.Remediation`, pass `ProtectedTargets` immediately before acting,
  respect the severity gate and typed confirmation, prefer a reversible form, and append to the
  action log. If it cannot be made reversible, it is probably a display-only `RunCommand`.
- **New operator features** — keep per-run safety decisions (`--load-hives`, `--interactive`,
  baselines) out of anything a config file can set, and document the feature in `docs/`.
