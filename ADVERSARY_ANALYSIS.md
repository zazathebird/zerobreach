# Scythe — Adversarial Assessment (WS7 input)

> ## ⚠ HISTORICAL — read the status table before believing any claim below
>
> **This document was written 2026-08-19 against the engine at 133 phases. It is written in the
> present tense and most of its "this is missing" claims are now CLOSED.** It is kept because the
> reasoning is what produced the 134-162 band, and because an assessment rewritten to match the
> code it produced is worth nothing. **Do not cite a claim from this file without checking it
> against the table below.** Engine is now **162 phases** (133 DEEP / 162 HUNT).
>
> | Item | Was | Now |
> |---|---|---|
> | E1 poison the signature DB | CRITICAL, "currently undetectable" | **CLOSED** — `Phases-0.ps1` preflight verifies the manifest and refuses universal FP allowlists |
> | E2 force 32-bit / WOW64 | "exactly one WOW64-aware line in the tree" | **CLOSED** — `SCYTHE_IS_WOW64`/`SCYTHE_SYS32` in the loader, Phase 0 reports it, phase 137 cross-views Registry64 |
> | E3 single-view trust | open | **CLOSED** — 134-138 |
> | E4 timestomp | open | **CLOSED** — 139 |
> | E5 namespace tricks | open | **CLOSED** — 140 |
> | E6 fixed task name / budget starvation | open | **STILL OPEN.** Task name is deliberately fixed (`CLAUDE.md`); group-cap rollup is still silent at INFO |
> | E7 no HMAC on reports / quarantine manifests | open | **STILL OPEN** |
> | B1 no memory inspection anywhere | open | **CLOSED** — 141-145. This is the single most misleading section in the file as written |
> | B2/146 PE structure · B3/147 cloud identity · B4/148-152 lateral+AD | open | **CLOSED** — 146/147 built 2026-08-30, 148-152 built 2026-08-31 (B4 narrowed: no directory enumeration, no ADCS probe) |
> | B5 the LAN | open | **PARTIALLY CLOSED, and re-scoped** — see the note below |
> | B6/157 · B7/158 · B8/159 | open | **CLOSED** — built 2026-08-30 (B8 narrowed: mounts no ESP) |
> | B9 no correlation | open | **CLOSED** — 160/161 |
> | B10 no timeline / evidence package | open | **CLOSED** — 162 |
> | B11 `yara_lite_rules` shape | open | **STILL OPEN** |
>
> **B5 / phases 153-156 — the one item this file gets actively wrong.** It says 153-156 would be
> "the only code in Scythe that touches another machine", gated behind `-Mode HUNT` *and* a
> `-ScanLan` switch. **That is not what was built.** 153-156 (2026-08-22) are **host-side only** —
> registry and CIM reads of the machine's own posture, sending no packets and enumerating no
> network — and **no `-ScanLan` switch exists or will be added.** The active off-box items in
> this section (probe a nonexistent name, rogue DHCP, ARP anomalies, mitm6, peer sweep) were
> **deliberately dropped, not deferred**; they are not pending work. Reasoning in `CLAUDE.md`
> ("Network-exposure band 153-156") and evidence in `docs/ATTACK_LOG.md`.
>
> **`WS7_WORK_ORDER.md` does not exist** and never shipped. The remaining briefs are
> `fable-work/tasks/` (F1-F7).

**Date:** 2026-08-19 · **Branch:** `security/audit-2026-08-18` · **Target:** engine at 133 phases
(now 162 — see the banner above)
**Authorization:** built at the request of the tool's author, who holds documented Anthropic CVP
approval for this project. This document is detection engineering: every evasion below is paired
with the detection that closes it.

**Method.** Five passes over the same engine, each from a different chair:
*red-team operator with SYSTEM* (how do I blind this thing?), *pentester* (what does it not look
at?), *ransomware affiliate* (what do I need it to miss for one hour?), *offsec/AD admin* (what
does it miss about the network, not the host?), and *DFIR lead* (having found something, can I
actually work the incident from its output?).

Verdict up front: **the host-artifact coverage is genuinely strong** — 133 phases (now 162) is more disk and
registry surface than most commercial agents check. The weaknesses are not "missing signatures."
They are three structural ones, and they are the whole assessment:

1. **The engine trusts its own inputs.** Signature DB, baseline files, and the Win32 API are all
   consumed without verification. Every one is attacker-writable on a box the attacker owns.
   *(Now closed — `Phases-0.ps1` preflight.)*
2. **The engine only looks at disk and registry.** There is no memory, no PE structure, no network
   peer, and no identity/cloud surface. Everything that never touches disk is invisible by design.
   *(Memory closed — 141-145. Network exposure closed host-side — 153-156. PE structure and cloud
   identity still open — 146/147.)*
3. **The engine emits findings, not an incident.** 734 independent findings with no correlation is
   a list, not an answer. The operator does the analysis the tool should have done.
   *(Now closed — 160-162.)*

---

## Part 1 — Attacking Scythe itself

I have SYSTEM. Scythe lands on my box. Here is what I do, in the order I would do it.

### E1 · Poison the signature database — CRITICAL, trivial, currently undetectable

`data/detection_signatures.json` is read at runtime by `Get-Sig` with **no integrity check of any
kind** (`Scythe-V23.ps1:959`). The file is plain JSON next to the engine.

I do not delete detections — a missing key is conspicuous and `Join-AllowRegex` fails closed to
`(?!)`. I go the other way and **widen the allowlists**, which fail *open* by design:

```
"fp_allowlists": { "<any_key>": [ ".*" ] }
```

Every phase downstream of that key now suppresses everything it finds, prints its normal `[OK ]`
banner, and the operator gets a clean bill of health from a fully instrumented scan. Same trick on
`data/permission_baseline.json` neutralises phases 108–115. This is the single highest-value,
lowest-effort attack on the tool and it leaves no artifact the tool looks for.

Worse for an MSP: the release zip is *designed* to be copied to a USB stick and carried between
client sites. Poison one technician's copy and every subsequent engagement returns clean.

**Closure:** embedded SHA256 manifest of every `data/*.json`, verified before the first phase.
Mismatch is a CRITICAL finding and the scan continues in *degraded* mode with allowlists disabled
rather than aborting — refusing to run is itself a denial-of-service the attacker would then use.
Additionally: refuse to honour any allowlist entry that is trivially universal (`.*`, `.+`, `^.*$`,
empty-alternation) regardless of manifest state, and report it. See WS7 Phase 0.

### E2 · Force the scanner into 32-bit — CRITICAL, one registry value

There is **exactly one WOW64-aware line in the entire tree** (`engine/Phases-1.ps1:669`). Nothing
checks `[Environment]::Is64BitProcess`.

If Scythe runs as a 32-bit process on x64 Windows, the OS silently lies to it:
`C:\Windows\System32` redirects to `SysWOW64`, and `HKLM\SOFTWARE` redirects to `Wow6432Node`. My
payload in the *real* System32 and my *real* run keys are in the half of the machine the scanner
cannot see. Phase 15 (System32 unsigned binary audit), Phase 109 (system binary integrity), Phase
113 (recently modified protected files) and every `HKLM\SOFTWARE` phase are reading a different
operating system than the one they think they are.

I do not even need to attack this — a technician launching the 32-bit shell, an RMM agent that
spawns 32-bit, or a PS2EXE build compiled x86 hands it to me for free. **This is far more likely to
fire by accident than by attack, which makes it a correctness bug as much as a security one.**

**Closure:** assert `Is64BitProcess -eq Is64BitOperatingSystem` at startup; if false, relaunch
through `%WINDIR%\Sysnative\...` and, failing that, emit CRITICAL and mark every affected phase's
results untrustworthy. Use `Sysnative` and the `Registry64` view explicitly in the System32 and
`HKLM\SOFTWARE` phases regardless. WS7 Phase 0.

### E3 · Single-view trust — the engine asks the OS and believes the answer

Every phase enumerates through one API: `Get-Process`, `Get-ChildItem`, `Get-ItemProperty`,
`Get-ScheduledTask`, `Get-Service`. A user-mode hook in the scanner's own process — or a minifilter
or kernel callback — makes any of those return a filtered view. The tool has no way to notice,
because it never asks a second time by a different route.

Phase 56 is the honourable exception (WMI vs `Get-Process` discrepancy) and it is exactly the right
idea, applied once. It should be the engine's default posture, not one phase.

Concretely, today I can hide:

| I hide | From | Because |
|---|---|---|
| A scheduled task | P29, P104 | Delete the task's `SD` value under `…\Schedule\TaskCache\Tree\<name>`. The task keeps running; `Get-ScheduledTask`, `schtasks` and the Task Scheduler UI all stop listing it. **This is free and it works on a fully patched box.** |
| A service | P28, P57 | `Get-Service` reflects the SCM; the registry under `CurrentControlSet\Services` is truth. Nothing diffs them. |
| A file | P10, P15, P18, everything file-based | Hooked `NtQueryDirectoryFile`, or namespace tricks — see E6. |
| A registry value | every registry phase | Hooked `NtEnumerateValueKey`, or a NUL-embedded value name, which `reg.exe` and the .NET registry APIs cannot enumerate but the kernel happily loads. |
| A process | P3, P6, P56 partially | PPID spoofing defeats the ancestry logic in P3 outright: `UpdateProcThreadAttribute` lets me name any parent I like, so my `powershell.exe` shows `explorer.exe` as its parent and the Office-spawns-shell heuristic never fires. |

**Closure:** a cross-view discrepancy band. Enumerate each of {tasks, services, processes, run keys,
drivers} by **two independent routes** and report *any* disagreement as a rootkit indicator in its
own right — the discrepancy is the detection, and it does not require knowing the rootkit. This is
the single highest-value new capability in the whole assessment. WS7 Phases 134–138.

### E4 · Timestomp past the time window

`-Hours N` filters on file timestamps. `$STANDARD_INFORMATION` timestamps are writable from user
mode — `(Get-Item x).CreationTime = '2019-01-01'` is a one-liner, no privilege required. My dropper
is outside every window the operator picks, and the MSP default is a bounded window, not all-time.

The `$FILE_NAME` attribute timestamps in the MFT are **not** writable through any documented API.
`$SI` earlier than `$FN`, or `$SI` with a zeroed sub-second component (the signature of nearly every
timestomping tool, which copies second-resolution values), is high-confidence evidence of tampering
and is worth more than the file itself.

**Closure:** MFT `$SI`-vs-`$FN` comparison over the scan set, plus USN journal cross-reference —
the journal records the create with its real time even after the timestamps are rewritten. WS7
Phase 139.

### E5 · Namespace tricks the engine's own APIs cannot reach

PowerShell's `-LiteralPath` still bottoms out in Win32 path handling. Not reachable today:

- **Trailing dot or space** (`evil.exe.` / `evil.exe `) — creatable via `\\?\`, opens fine at
  runtime, but Win32 canonicalisation strips the trailing character so `Test-Path`/`Get-Item` on the
  displayed name resolves to something else or nothing.
- **Reserved device names** (`CON`, `NUL`, `LPT1`) as path components via `\\?\`.
- **>260-char paths** where the tool did not opt into long paths.
- **RTLO / homoglyph filenames** — `invoice\u202Egpj.exe` renders as `invoicejpg.exe` in every UI
  including Scythe's own output. Cheap to detect, currently not detected.
- **ADS on a directory** (`C:\Windows\Temp:payload`) — P17 scans file streams.
- **Junction/reparse redirection** so the enumerated path and the executed path differ.

**Closure:** enumerate the scan set with `\\?\`-prefixed long-path APIs, flag any name whose Win32
canonical form differs from its raw form, and flag bidi/homoglyph characters in executable names.
WS7 Phase 140.

### E6 · Kill or starve the scan

The scan is `powershell.exe` with a predictable command line and, when scheduled, a **fixed task
name (`Scythe_V22_Scheduled`) at a fixed 02:00**. I can watch for it and sleep, or kill it. The
engine's resilience trap guarantees it runs to completion — but a killed process produces no
`scan_complete`, and the operator sees a failed scan and re-runs it, which I also survive.

Lower-effort and nastier: I do not kill it, I *starve* it. `$global:SIG_AUDIT_DEADLINE_S`,
`Get-ScanFiles` caps, and the group cap of 100 findings are all documented budget limits. I generate
150 junk findings in a group I know is capped, and the real one lands past the cap and is
suppressed into a `GROUPCAP_` summary line.

**Closure:** self-integrity + tamper phase (WS7 Phase 0): detect debugger/hooks in own process,
randomise the scheduled-task name and time at registration, and make group-cap suppression *loud* —
a capped group that contained a CRITICAL must escalate, never silently roll up.

### E7 · The evidence itself

`reports\` is ACL-hardened for non-admins (M9) but I am SYSTEM. Quarantined items sit in
`reports\quarantine\` with a `.quar.json` restore manifest and are deliberately never auto-deleted.
I rewrite the manifest to point a restore at a path of my choosing, or I edit the prior baseline
JSON so the next `-Baseline` diff shows no change. The report hash check (M11) covers the
*remediation* path only — it does not cover a baseline consumed by a later scan.

**Closure:** HMAC every report and quarantine manifest with a per-install key stored outside the
report tree; verify on load; treat a baseline that fails verification as absent, not as clean.

---

## Part 2 — What walks past all 133 phases *(now 162 — see banner)*

### B1 · Memory — the entire category is missing

**[SUPERSEDED — phases 141-145 now do memory inspection. Original text follows.]** There is **no memory inspection anywhere in the engine.** Phase 93, the "deep DLL/module injection
scan," enumerates `$p.Modules` — the loader's module list. Anything that never enters that list is
invisible:

- **Reflective / manually-mapped DLLs** — no module entry, by definition. This is the default for
  Cobalt Strike, Sliver, Havoc, Brute Ratel, and every commodity loader shipped since about 2015.
- **Module stomping** — I load a real signed DLL and overwrite its `.text`. The module list shows a
  legitimate signed Microsoft DLL at a legitimate path. Phase 93 checks the signature *of the file
  on disk*, which is still perfectly valid.
- **Private RX/RWX commits** holding shellcode with no backing file at all.
- **.NET `Assembly.Load(byte[])`** — Donut, Covenant Grunts, SharpSploit, every `execute-assembly`.
  Nothing on disk, nothing in the module list, and the CLR is loaded into a process that has no
  business hosting it (`notepad.exe` with `clr.dll` mapped is a five-line detection that does not
  exist).
- **Threads whose start address does not fall inside any mapped module** — the single most reliable
  memory signal there is, and it is cheap: `VirtualQueryEx` over the thread start address, check
  `MEM_IMAGE` vs `MEM_PRIVATE`.

Phase 90's "YARA-lite" scan is file-only. A real scanner scans process memory.

**This is the largest single gap in the tool** and it is what separates "artifact scanner" from
"IR tool." WS7 Phases 141–145.

### B2 · PE structure — files are matched, never parsed

Every file-based phase asks two questions: does the path/name match a pattern, and is it
Authenticode-signed. Neither survives contact with a packed or novel sample. Not asked today:

- Section entropy (a `.text` at 7.8 is packed, full stop), section names (`UPX0`, `.themida`,
  `.vmp0`, `.aspack`), `SizeOfRawData == 0` with a large `VirtualSize`.
- Import table shape — `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` in one binary is
  an injector no matter what it is called; an import table with **fewer than five imports** is an
  API-hashing loader.
- Overlay size (appended payload), embedded PEs in resources, TLS callbacks (pre-`main` execution).
- Compile timestamp in the future, or before the file's own creation.
- `.NET` metadata present, plus obfuscator markers (ConfuserEx, SmartAssembly, .NET Reactor).
- **Signed-but-invalid**: the signature parses, names a real vendor, and does not verify. Today
  `Get-AuthSig` gives a status; nothing separates "unsigned" from "someone tried to look signed."

WS7 Phase 146 + the rule-engine upgrade.

### B3 · Cloud identity and DevOps secrets — zero coverage

I grepped for it. `.aws`, `.azure`, kubeconfig, `.ssh`, `.git-credentials`, `.npmrc`,
`.docker/config.json` appear **nowhere** in the signature DB or the engine. Coverage stops at
browser password stores, FileZilla, WinSCP and PuTTY.

This is the biggest *modern* gap. On a managed endpoint in 2026, the crown jewels are not the local
SAM — they are:

- `%USERPROFILE%\.aws\credentials`, `.azure\msal_token_cache.bin`, `.azure\accessTokens.json`
- **Entra Primary Refresh Token** artifacts and the `Cloud AP` / `Ngc` key material — a stolen PRT
  is tenant-wide SSO and survives a password reset
- `.kube\config`, `.docker\config.json`, `%APPDATA%\gcloud\credentials.db`
- `.ssh\id_*`, `.git-credentials`, `.npmrc` `_authToken`, `.pypirc`, `.netrc`
- CI/CD tokens in env vars and `.env` files, Terraform state, `azureProfile.json`
- Windows Credential Manager vault and DPAPI masterkey exfil (`%APPDATA%\Microsoft\Protect\<SID>\`)

For an MSP this is the whole business: one stolen `.azure` token cache on one technician's laptop is
every client tenant. WS7 Phase 147.

### B4 · Lateral movement and AD — thin, and the lab is built for it

You are testing on a private network of infectable peers, so this matters more than usual. Present:
P66 (share worm), P88 (domain trust), P76/P77 (RDP/WinRM). Missing:

- **Inbound lateral evidence**: `PSEXESVC` / arbitrary service created and deleted within minutes
  (Event 7045 + 7036), `ADMIN$`/`IPC$` session history, `wmiprvse.exe` or `services.exe` as parent
  of a shell, WinRM `wsmprovhost.exe` children, DCOM (`MMC20.Application`, `ShellWindows`).
- **Credential theft in progress**: any handle to `lsass.exe` from a non-Defender process, MiniDump
  artifacts, `lsass.dmp` anywhere, `comsvcs.dll MiniDump` command lines, SAM/SYSTEM/SECURITY hive
  copies, `ntds.dit`/`IFM` output, VSS created and deleted in the same minute.
- **Kerberos abuse**: tickets with 10-year lifetimes or absent PAC (golden), RC4 (`0x17`) service
  tickets on an AES domain (Kerberoast), AS-REP roastable accounts, `4769` volume anomalies, and —
  cheap and decisive — `klist` output that disagrees with the machine's own domain membership.
- **NTLM relay / coercion**: SMB signing off, `4624 Type 3` NTLM logons from workstations,
  PetitPotam/PrinterBug callback artifacts, WebClient service started on a workstation (WebDAV
  coercion primitive).
- **Delegation and ACL abuse** readable from a domain-joined host: unconstrained delegation, RBCD
  (`msDS-AllowedToActOnBehalfOfOtherIdentity`), `AdminSDHolder` drift, ADCS ESC1/ESC8 template
  misconfiguration. A workstation can query all of this with no special rights, and it is exactly
  what an operator wants to know.

WS7 Phases 148–152.

### B5 · The LAN — the tool never looks off-box

**[SUPERSEDED — see the B5 note in the banner. 153-156 cover network exposure host-side.]** Nothing in 133 phases examines the network the host is sitting on. In your lab this is the
difference between "patient zero looks clean" and "patient zero is being poisoned by the box next
to it":

- **LLMNR / NBT-NS / mDNS poisoning** (Responder, Inveigh) — the classic first move on any internal
  engagement. Detectable passively and cheaply: send a resolution request for a name that cannot
  exist and see whether anything answers. **A response is proof.** That is a five-line detection
  with essentially zero false-positive rate and it does not exist.
- **Rogue DHCP** — a second DHCP offer for a `DHCPDISCOVER`.
- **ARP anomalies** — one MAC claiming several IPs, or the gateway MAC changing mid-scan.
- **IPv6 takeover (mitm6)** — a rogue RA / DHCPv6 server, on a network with no legitimate IPv6.
- **Peer exposure sweep** — for each peer in the ARP cache: open SMB with signing disabled, SMBv1,
  null-session-readable shares, RDP without NLA, WinRM, and unauthenticated admin shares. This is
  the "what can patient zero reach" question, and it is the question an MSP actually gets asked.

**[NOT WHAT WAS BUILT — 153-156 are host-side, send no packets, and there is no `-ScanLan`.]**

Strictly opt-in and rate-limited — this is the one band that touches other machines, so it is
gated behind an explicit `-Mode HUNT` **plus** a `-ScanLan` switch, defaults off, and never writes.
WS7 Phases 153–156.

### B6 · Persistence mechanisms still uncovered

The autostart coverage is good and I still found these unlisted. Each is a real, in-the-wild
technique, each is a handful of lines:

`COR_PROFILER` .NET profiler hijack (env-var or registry, loads my DLL into every .NET process) ·
Active Setup `StubPath` (runs at every first-logon, per-user, survives profile reset) ·
`SilentProcessExit\MonitorProcess` (also a credential-dumping primitive against lsass) ·
WER `ReflectDebugger` / `Hangs\Debugger` · Time Providers (`W32Time\TimeProviders` DLL, runs as
SYSTEM in svchost) · Print Monitors and Port Monitors (SYSTEM, spooler-loaded) · Netsh helper DLLs ·
Winsock LSP / `Protocol_Catalog9` · `ShellServiceObjectDelayLoad` / `SharedTaskScheduler` ·
`SCRNSAVE.EXE` · `AutodialDLL` · Terminal Services `InitialProgram` · service **trigger** start ·
`.NET` `AppDomainManager` via `.config` sidecar (P95 covers the registry route only) ·
MSIX/AppX sideload + `AppExecutionAlias` hijack · `.settingcontent-ms` / `.library-ms` / `.url` /
`.appref-ms` droppers · **hidden scheduled task via SD deletion** (see E3 — the one I would
actually use).

WS7 Phase 157.

### B7 · Supply chain and developer tooling

Untouched, and on a developer or technician workstation it is the softest surface in the building:
VS Code / Cursor extensions (arbitrary code at startup, sideloadable from `.vsix`, no signature
requirement) · `.vscode/tasks.json` with `runOn: folderOpen` (opening a repo executes it) ·
git hooks (`post-checkout`, `post-merge` — execute on clone) · npm/pip/nuget install scripts ·
typosquatted dependencies · malicious `.gitconfig` aliases and `core.fsmonitor` (code execution on
any git command) · MSBuild inline tasks · Jupyter kernel specs.

WS7 Phase 158.

### B8 · Firmware and boot

P58 covers MBR, P80 covers Secure Boot/TPM status. Missing: EFI System Partition file inventory and
hashes, `bootmgfw.efi` / `winload.efi` integrity, Secure Boot `dbx` revocation currency (BlackLotus
depends on an un-updated `dbx`), UEFI variable anomalies, and the `bootkitty`-class
`\EFI\Microsoft\Boot\` foreign-file check. WS7 Phase 159.

### B9 · No correlation — 734 findings is a list, not an incident

Every finding is independent. The tool never says: *"at 14:02 a macro-enabled attachment was opened;
at 14:02 Word spawned PowerShell with an encoded command; at 14:03 a Run key appeared pointing at
`%APPDATA%\svc.exe`; at 14:03 that binary beaconed to a domain registered nine days ago; at 14:07
shadow copies were deleted."* That is one incident with a timeline, five techniques, and an obvious
patient zero — and every one of those five facts is already detected today, by five different
phases, and presented as five unrelated rows.

Correlation is the cheapest tenfold in this document. It requires no new detection: it re-uses what
the engine already finds, groups findings by time proximity, shared process lineage, shared file
path and shared MITRE tactic, and scores the resulting chains. An operator who gets three scored
attack chains instead of 734 rows is a different product.

WS7 Phases 160–161.

### B10 · No timeline, no evidence package

There is no DFIR output. The data to build a proper timeline is already being collected in pieces by
phases 11, 12, 107, 123, 124: MFT/USN, registry LastWrite, event logs, prefetch, BAM/UserAssist,
browser history, LNK/jumplists, Amcache/Shimcache. Merged into one time-ordered, filterable
super-timeline and exported alongside the findings, that is the artifact an operator hands to a
client, an insurer, or a court. WS7 Phase 162 + export.

### B11 · The rule engine is one regex per rule

`yara_lite_rules` is `{ Name, Pattern, Severity }` — a single regex matched against file text. It
cannot express: multiple strings with an N-of-M condition, hex patterns with wildcards
(`6A 40 68 00 30 00 00 6A 14 8D 91 ?? ?? 00 00`), `wide`/`ascii`/`nocase`/`fullword` modifiers,
offset constraints, `filesize` bounds, or the `uint16(0) == 0x5A4D` header test that keeps a rule
from wasting time on non-PEs. That means public YARA rule packs — the entire open detection
ecosystem — cannot be used, and rules must be hand-degraded into single regexes that are both less
precise and more expensive.

A real matcher is maybe 400 lines of PowerShell/.NET and it multiplies the value of every signature
in the DB. WS7 rule engine.

---

## Part 3 — Priority order

Ranked by (attacker cost to evade today) × (defensive value) ÷ (implementation cost).

| # | Item | Why it is first | WS7 |
|---|---|---|---|
| 1 | **Self-integrity: signature manifest + WOW64 + universal-allowlist refusal** | Everything else is worthless if the DB can be edited and the scanner can be blinded by bitness. Cheap. | Phase 0 |
| 2 | **Cross-view discrepancy detection** | Turns "I trust the API" into "I catch the rootkit." Detects unknown implants without signatures. Hidden-SD tasks alone justify it. | 134–138 |
| 3 | **Memory: unbacked-executable regions + thread start addresses + CLR-in-odd-process** | The whole missing category. Catches Cobalt Strike / Sliver / Havoc / donut generically. | 141–145 |
| 4 | **Correlation + attack-chain scoring** | Zero new detection, largest operator-value multiplier in the document. | 160–161 |
| 5 | **Cloud identity + DevOps secret theft** | The 2026 crown jewels, currently zero coverage, and MSP-existential. | 147 |
| 6 | **Real YARA-compatible rule engine** | Unlocks the public rule ecosystem; multiplies every existing signature. | engine |
| 7 | **Lateral / AD / credential-theft artifacts** | Directly matches the lab you are building. | 148–152 |
| 8 | **PE structural + packer analysis** | Catches novel samples that match no signature. | 146 |
| 9 | **Timeline + evidence package** | Turns findings into a deliverable. | 162 |
| 10 | **Remaining persistence, supply chain, LAN, UEFI, anti-forensics** | Breadth. Individually cheap, collectively large. | 139/140/153–159 |

### Standing constraints these must respect

Rule #1 is not negotiable and this band makes it easy to violate: **every new detection ships
`FixAction "Info"`.** The cross-view and memory phases in particular produce findings on healthy
machines (an EDR *is* a legitimate hooking rootkit by every signal in Phase 134), and a CRITICAL +
`KillProcess` on an EDR's hook would be auto-selected. The correct posture is Info, an allowlist for
known-good EDR vendors, and an FP round on real hardware before anything becomes actionable.

**[FALSE AS BUILT — nothing in Scythe touches another machine, and no `-ScanLan` exists.
The paragraph's own closing argument is exactly why the band was built host-side instead.]**

Second: the LAN band (153–156) is the only code in Scythe that touches a machine other than the
one it runs on. It stays behind `-Mode HUNT` **and** an explicit `-ScanLan` switch, defaults off,
never writes to a peer, and rate-limits — because an IR tool that portscans a client's production
network unprompted is an incident of its own.
