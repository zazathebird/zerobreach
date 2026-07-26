# P1 — `HKCU` / `$env:` is the wrong user: implementation spec

**Status:** design spec, ready to implement. Produced 2026-07-26 against the working tree of
branch `session12/review-remediation-ws6`.
**Scope:** fix P1 from `EVIDENCE_ENGINE_PLAN.md` §2.
**Audience:** the implementation agent. This document is the sole source of truth; it assumes no
other context.

**Repository state when this was written:** three other agents were concurrently editing
`engine/Phases-1.ps1`, `engine/Phases-3.ps1`, `ZeroBreach-V23.ps1` and `ZeroBreach-Server.ps1`.
Every code reference below is therefore anchored to a **distinctive snippet or phase name**, never
to a line number. Line numbers in the original plan (`Phases-2.ps1:452`, `Phases-3.ps1:687`) are
stale — ignore them and grep for the anchors.

---

## 0.0 OPERATOR DECISIONS — already made, do not re-ask

The three open questions this spec raised were put to the operator on 2026-07-26 and answered.
**These are settled. Implement to them.**

| # | Question | Decision |
|---|---|---|
| 1 | Gating for `reg load` of a logged-off user's `NTUSER.DAT` | **Opt-in `-LoadUserHives`, OFF by default**, never active in STEALTH. Already-mounted hives (logged-on users) are always read. Every profile skipped because the flag was off must produce a **named honesty finding** — the report must say *"zbtest2's registry was NOT examined"*, never imply clean. Rationale: this spec reproduced an unrecoverable hive leak, and `EVIDENCE_ENGINE_PLAN.md` §7.7 already declined VSS/Amcache on the same audit-only grounds. |
| 2 | ~20 finding IDs change because `Target` gains the username, breaking `-Baseline` diffs once | **Accepted.** Ship it and re-capture baselines. There is no correct shim — an ID that encoded the wrong user was wrong. Call it out prominently in `CHANGELOG.md` so a diff showing ~20 phantom-new findings is explainable rather than alarming. |
| 3 | The acceptance test needs a second local profile, which this box did not have | **Approved and ALREADY DONE — see §0.1 below.** |

### 0.1 The test environment already exists — do not recreate it

A standard (non-admin) local account **`zbtest2`** was created on this box on 2026-07-26 specifically
for this fix, and its profile was fully materialised. State at handoff:

```
ProfileList:  S-1-5-21-2934201606-2785436122-4267783230-1001  C:\Users\user      (logged on)
              S-1-5-21-2934201606-2785436122-4267783230-1003  C:\Users\zbtest2   (LOGGED OFF)

HKEY_USERS:   .DEFAULT, S-1-5-19, S-1-5-20, ...-1001, ...-1001_Classes, S-1-5-18
                                            ^ zbtest2's hive is NOT mounted
```

`C:\Users\zbtest2\NTUSER.DAT` and
`C:\Users\zbtest2\AppData\Local\Microsoft\Windows\UsrClass.dat` both exist.

This is exactly the scenario P1 exists to fix: a victim profile whose registry the engine physically
cannot reach, while `HKCU` silently resolves to the technician's hive instead. It exercises the
opt-in `reg load` path, the honesty finding, and the per-user filesystem paths all at once.

The account password is in the session scratchpad file `zbtest2-credentials.txt`. **If that
scratchpad is gone** (it is session-scoped and does not survive a `/clear`), reset it with
`Set-LocalUser -Name zbtest2 -Password (Read-Host -AsSecureString)` rather than deleting and
recreating the account — the SID and profile are what make the test meaningful.

**Teardown, once P1 is signed off:** `Remove-LocalUser zbtest2`, delete `C:\Users\zbtest2`, and remove
its `ProfileList` SID key. Do **not** tear it down before the acceptance test in §6.4 has passed.

---

## 0. Executive summary

The engine self-elevates with `Start-Process -Verb RunAs`. On a standard-user endpoint — the normal
MSP case — the technician supplies **admin** credentials, so the elevated process's `HKCU`,
`$env:APPDATA`, `$env:LOCALAPPDATA`, `$env:USERPROFILE` and `$env:TEMP` all resolve to the
**admin's** profile, not the victim's. Every per-user detection is looking in the wrong place and
reporting clean because it never looked at the infected profile.

Confirmed by grep: nothing in the repository references `HKEY_USERS`, `ProfileList`, `reg load`,
`reg unload` or `HKU:` in any `.ps1`. Zero hits. Also zero hits for `GetFolderPath`, `$HOME` and
hardcoded `C:\Users\<name>` shapes — so the *only* per-user mechanisms in use are `HKCU:` and
`$env:*`, which simplifies the migration surface.

**The problem is much larger than the plan's "~6 phases".** Measured inventory:

| Category | Count |
|---|---|
| Registry call sites (`HKCU:`) needing migration | **20** (`R1`–`R20`), spanning ~20 phases |
| Filesystem root-set sites (`$env:APPDATA` / `LOCALAPPDATA` / `USERPROFILE` / `TEMP`) | **31** (`F1`–`F31`) |
| Signature lists in `data/detection_signatures.json` baked to the admin's profile at load time | **7 + 5 raw-path lists** |
| Sites correctly left alone | ~15 (see §1.3) |

Two additional defects were found during the audit, both inside P1's blast radius and both worth
fixing in the same workstream:

1. **`dpapi_theft_paths_raw` (Phase 44.5) and `cloud_token_paths_raw` (Phase 100.5) are dead
   lists.** They use `%APPDATA%`-style syntax, but the loader expands them with
   `$ExecutionContext.InvokeCommand.ExpandString(...)`, which only expands `$env:` form. Probed on
   the live box:
   ```
   ExpandString on percent-form : [%APPDATA%\Microsoft\Protect]
   ExpandString on dollar-form  : [C:\Users\user\AppData\Roaming\Microsoft\Protect]
   Test-Path percent-form: False
   Get-Item percent-form (non-literal): False
   ```
   Both lists currently match nothing at all. Phase 44.5's DPAPI-store inventory and Phase 100.5's
   `TOKENSTORES_PRESENT` finding have never fired.

2. **Finding-ID collisions across users.** Many affected sites build IDs from a value *name* only
   (`RUNKEY_$prop`, `COM_$guid`, `EXT_$($ext.Name)`, `FILELESS_$($prop.Name)`, `GPO_$pol`,
   `PROXY_ENABLE`, `AMSI_DISABLED`, `BROWSER_CACHE_*`, `CERT_USER_*`). `Add-Finding` de-dupes on ID
   with `foreach ($existing in $global:AuditFindings) { if ($existing.ID -eq $ID) { return } }`, so
   **the second user's finding would be silently discarded.** Migration without fixing the IDs is
   worse than not migrating. See §5.3.

**Headline risk:** P1 surfaces more findings by design, and a large fraction of the migrated sites
land in the auto-select set (CRITICAL/HIGH + a destructive `FixAction`), multiplied by profile
count. That is a direct rule-#1 exposure and it governs the rollout order. See §5.1.

---

## 1. Complete call-site inventory

Verdicts: **MIGRATE** (genuinely needs the victim's profile) · **KEEP** (correctly the current user
or machine-wide) · **AMBIGUOUS-ASK** (needs an operator/product decision before migrating).

The **QUICK** column records whether the site executes in QUICK mode. Derived by mapping each phase
header against the `if (-not $global:QUICK_MODE) {` / `}   # end QUICK-skip block` bands:

```
Phases-1 QUICK-skip bands (non-QUICK):   21-46, 198-291, 380-775, 844-1021, 1038-1130,
                                         1385-1507, 1534-1555, 1569-1841, 1886-2097,
                                         2117-2396, 2424-2446, 2535-2596, 2630-2662
Phases-2 QUICK-skip bands (non-QUICK):   7-89, 156-208, 238-480, 551-567, 593-752,
                                         984-1328, 1369-1474
Phases-3:                                entirely DEEP/Advanced+Integrity gated
```
(Band boundaries are approximate to the file as read; re-derive them if the modules have moved. The
*conclusions* below — which specific phases run in QUICK — are what matters.)

### 1.1 Registry — `HKCU:` / `HKEY_CURRENT_USER`

| # | File · Phase | Snippet anchor (grep for this) | QUICK | Grade + FixAction today | Verdict |
|---|---|---|---|---|---|
| **R1** | `Phases-1.ps1` · **PHASE 5** — AMSI BYPASS & ETW PATCH DETECTION | `Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows Script\Settings" -Name "AmsiEnable"` | ✔ yes | CRITICAL + `DeleteReg` | **MIGRATE** |
| **R2** | `Phases-1.ps1` · **PHASE 20** — RUN / RUNONCE HEURISTIC SCRUB | `$runPaths = @(` followed by `"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",` | ✔ yes | CRITICAL + `DeleteReg` (POSSIBLE + `Info` on the `$RUNKEY_BENIGN_RE` / AppData branches) | **MIGRATE** — the headline case |
| **R3** | `Phases-1.ps1` · **PHASE 21.5** — SILENT-PROCESS-EXIT / EDR-BLINDING IFEO / COM TYPELIB HIJACK | `foreach ($tlRoot in $COM_TYPELIB_ROOTS)` → data key `com_typelib_hijack_roots` = `["HKCU:\\SOFTWARE\\Classes\\TypeLib", "HKCU:\\SOFTWARE\\Classes\\CLSID"]` | ✖ no | HIGH + `DeleteRegKey` | **MIGRATE** (data-side, §4.3) |
| **R4** | `Phases-1.ps1` · **PHASE 24** — COM OBJECT HIJACK AUDIT (HKCU CLSID OVERRIDES) | `$hkcuClsid = "HKCU:\SOFTWARE\Classes\CLSID"` | ✖ no | HIGH + `DeleteRegKey` (shadow branch) / POSSIBLE + `Info` | **MIGRATE** |
| **R5** | `Phases-1.ps1` · **PHASE 25** — GPO LOCKDOWN | `$gpoU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"` | ✖ no | HIGH + `DeleteReg` | **MIGRATE** |
| **R6** | `Phases-1.ps1` · **PHASE 35** — PROXY & WINHTTP POISON RESET | `$proxyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"` | ✔ yes | CRITICAL + `RunCmd` | **MIGRATE** — critical: the `FixParam` embeds `$proxyPath` twice, so unmigrated it *resets the admin's proxy and leaves the victim's hijack fully armed* |
| **R7** | `Phases-1.ps1` · **PHASE 39** — ROGUE ROOT CERTIFICATE AUDIT | `@{ Cert='Cert:\CurrentUser\Root';  Reg='HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'; Label='CurrentUser'; Id='USER' }` | ✖ no | `Info` only | **AMBIGUOUS-ASK** — the `Cert:` PSDrive has no per-SID form. Per-user coverage means reading and parsing raw cert blobs from `HKU\<SID>\...\SystemCertificates\Root\Certificates`. Real work, `Info`-only payoff. Recommend deferring (§7.2) |
| **R8** | `Phases-1.ps1` · **PHASE 48** — KEYLOGGER FILE & REGISTRY ARTIFACT SCAN | `$klRegPaths = $KEYLOGGER_REG_PATHS` → data key `keylogger_reg_paths` (7 × `HKCU:\SOFTWARE\<vendor>`) | ✖ no | CRITICAL + `DeleteRegKey` | **MIGRATE** (data-side) |
| **R9** | `Phases-1.ps1` · **PHASE 49.5** — CLIPBOARD CRYPTOCURRENCY ADDRESS-SWAP (CLIPPER) | `$clipperRunPaths = @(` followed by `"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",` | ✖ no | POSSIBLE + `Info` | **MIGRATE** — zero rule-#1 risk, good first migration |
| **R10** | `Phases-2.ps1` · **PHASE 61** — RAT CONFIGURATION FILE & REGISTRY SCAN | `foreach ($rrp in $RAT_REG_PATHS)` → data key `rat_reg_paths` (12 × `HKCU:\SOFTWARE\<rat>`) | ✖ no | CRITICAL + `DeleteRegKey` | **MIGRATE** (data-side) |
| **R11** | `Phases-2.ps1` · **PHASE 65** — WORM AUTORUN & USB SPREAD DETECTION | `-FixParam "Set-ItemProperty 'HKLM:\...\Policies\Explorer' NoDriveTypeAutoRun 0xFF ...; Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 0xFF ..."` | ✖ no | hardening `RunCmd` | **AMBIGUOUS-ASK** — hardening write, see §5.5 |
| **R12** | `Phases-2.ps1` · **PHASE 67** — ADWARE / PUP / SPYWARE REGISTRY SCAN | `$adwarePaths = $ADWARE_PUP_REGS` → data key `adware_pup_regs` (21 × `HKCU:`, 3 × `HKLM:`) | ✖ no | HIGH + `DeleteRegKey` | **MIGRATE** (data-side; requires the user/machine split, §4.3) |
| **R13** | `Phases-2.ps1` · **PHASE 68.5** — CLICKFIX / FAKE-CAPTCHA CLIPBOARD LURE RESIDUE | `if ($RUNMRU_REG_PATH -and (Test-Path -LiteralPath $RUNMRU_REG_PATH))` → data key `runmru_reg_path` = `"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"` | ✖ no | `Info` only (severity from `$CLIPBOARD_LURE_RULES`) | **MIGRATE — highest evidentiary priority.** RunMRU is a verbatim record of what the victim typed into Win+R. Reading the *admin's* RunMRU is guaranteed empty. Zero rule-#1 risk |
| **R14** | `Phases-2.ps1` · **PHASE 70** — FILELESS REGISTRY PAYLOAD DETECTION | `$filelessPaths = @(` followed by `"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",` and `"HKCU:\Environment"` and `"HKCU:\SOFTWARE\Classes\CLSID"` | ✔ yes | CRITICAL + `DeleteReg` | **MIGRATE** |
| **R15** | `Phases-2.ps1` · **PHASE 74** — MACRO / OFFICE / OUTLOOK PERSISTENCE AUDIT | four sites: `Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name "VBAWarnings"` · `$outlookPath = "HKCU:\SOFTWARE\Microsoft\Office\*\Outlook\WebView"` · `Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Office\*\Addins\*'` · `foreach ($clsRoot in @('HKCU:\SOFTWARE\Classes','HKLM:\SOFTWARE\Classes',...))` | ✖ no | HIGH + `RunCmd` (VBAWarnings); POSSIBLE + `Info` (add-ins) | **MIGRATE** |
| **R16** | `Phases-2.ps1` · **PHASE 74.7** — PROACTIVE ANTI-REINFECTION HARDENING | `foreach ($ok in $PROACTIVE_OFFICE_KEYS)` · `foreach ($pr in $PROACTIVE_PERSIST_REGS)` · `$lxKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$lx\UserChoice"` | ✖ no | operator-only `RunCmd` / `Info` | **AMBIGUOUS-ASK** — split audit half (MIGRATE) from write half (ask). §5.5 |
| **R17** | `Phases-2.ps1` · **PHASE 84** — APPLOCKER / GPO POLICY BYPASS AUDIT | `$srpPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"` | ✖ no | — | **MIGRATE** |
| **R18** | `Phases-2.ps1` · **PHASE 85** — LOLBIN PERSISTENCE (INSTALLUTIL / MSIEXEC) | `foreach ($fp in @("HKCU:\SOFTWARE\Microsoft\InstallShield","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer"))` | ✖ no | — | **MIGRATE** |
| **R19** | `Phases-3.ps1` · **PHASE 92** — UAC AUTO-ELEVATE BYPASS REGISTRY STAGING | `foreach ($ub in $UAC_BYPASS_REGS)` → data key `uac_bypass_regs` (5 × `HKCU:\Software\Classes\<x>\shell\open\command`) | DEEP only | CRITICAL + `DeleteRegKey` | **MIGRATE — top tier.** UAC-bypass staging lives in the victim's hive by definition; the admin's hive will never hold it |
| **R20** | `Phases-3.ps1` · **PHASE 94** — COM SCRIPTLET (.SCT/.WSC) ABUSE & SQUIBLYDOO | `foreach ($rp in @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))` | DEEP only | CRITICAL + `DeleteReg` | **MIGRATE** |

Non-actionable `HKCU` mentions (comments / display strings only, no change needed):
`Phases-1.ps1` Phase 24 header text and its explanatory comments; `Phases-1.ps1` Phase 21.5 comment
`# short and finds nothing. Scoped to HKCU deliberately:`; `Phases-2.ps1` Phase 74.7 comment
`# attachment OPENS instead of RUNS. Per-extension and per-user (HKCU)`; `Phases-3.ps1` Phase 105
comment `# It becomes a real finding only when that SAME CLSID is also the target of a genuine HKCU`;
`ZeroBreach-V23.ps1` `Get-RegKeyLastWriteTime` comment `(HKLM:\... / HKCU:\...)`.

### 1.2 Filesystem — `$env:APPDATA` / `LOCALAPPDATA` / `USERPROFILE` / `TEMP`

All **MIGRATE** unless the Verdict column says otherwise.

| # | File · Phase | Snippet anchor | QUICK | Grade + FixAction today | Notes / Verdict |
|---|---|---|---|---|---|
| **F1** | `Phases-1.ps1` · **PHASE 7** — BROWSER CACHE & SERVICE WORKER AUDIT | `$browserCachePaths = @(` — 7 entries, `$env:LOCALAPPDATA` / `$env:APPDATA` | ✖ | INFO + `DeleteFile` | **AMBIGUOUS-ASK** — pure inventory. 8 profiles × 7 browsers = 56 rows. Recommend collapsing to ONE aggregate INFO finding (§4.4, §7.4) |
| **F2** | `Phases-1.ps1` · **PHASE 8** — BROWSER EXTENSION SANITIZATION | `$extPaths = @(` — Chrome / Edge / Brave `\User Data\Default\Extensions` | ✖ | **CRITICAL + `DeleteFile`** (name-match branch); POSSIBLE + `Info` | MIGRATE |
| **F3** | `Phases-1.ps1` · **PHASE 9** — BROWSER HIJACK — SHORTCUT & HOMEPAGE AUDIT | `$shortcutDirs = @("$env:USERPROFILE\Desktop","$env:APPDATA\Microsoft\Windows\Start Menu\Programs","$env:PUBLIC\Desktop")` and `$chromePrefs = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"` | ✖ | CRITICAL + `RunCmd`; HIGH + `Info` | MIGRATE (`$env:PUBLIC\Desktop` stays machine-wide) |
| **F4** | `Phases-1.ps1` · **PHASE 10** — TEMP / DOWNLOAD DIRECTORY ANOMALY SWEEP | `$targetDirs = @(` with `@{P=$env:TEMP; L="User TEMP"}`, `@{P="$env:LOCALAPPDATA\Temp"...}`, `@{P="$env:USERPROFILE\Downloads"...}`, `@{P="$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache"...}` | ✔ yes | HIGH / CRITICAL + `DeleteFile` | MIGRATE. **Biggest FP-flood risk in the whole workstream** — session 17 recorded 92 of this box's 94 auto-destructive findings coming from Phase 10 alone (`%TEMP%\claude\` harness debris). That count multiplies per profile. `$env:WINDIR\Temp` and `$env:PUBLIC\Downloads` entries stay machine-wide |
| **F5** | `Phases-1.ps1` · **PHASE 10.5** — MALICIOUS LNK/SHORTCUT DOWNLOADER SWEEP | `"$env:USERPROFILE\Downloads",` / `"$env:USERPROFILE\Desktop",` / `"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"` | ✖ | | MIGRATE |
| **F6** | `Phases-1.ps1` · **PHASE 10.6** — NPM/PIP POSTINSTALL SUPPLY-CHAIN EXFIL SWEEP | `$npmPkgFiles = (Get-ScanFiles -Path @($env:USERPROFILE,"$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads") -Filter 'package.json' -TimeScoped)` | ✖ | | MIGRATE (low priority) |
| **F7** | `Phases-1.ps1` · **PHASE 11** — RECENT DOCUMENTS & JUMP LIST SCRUB | `"$env:APPDATA\Microsoft\Windows\Recent",` + `\AutomaticDestinations` + `\CustomDestinations` | ✖ | INFO + `RunCmd` (delete) | MIGRATE. **Coordinate with P4**, which rewrites this phase from "count and offer to delete" into an LNK-parsing evidence source. Per-user is a prerequisite for P4's value |
| **F8** | `Phases-1.ps1` · **PHASE 17** — ALTERNATE DATA STREAM (ADS) PARASITE SCAN | `foreach ($adsDir in @("$env:LOCALAPPDATA","$env:TEMP","$env:USERPROFILE\Downloads"))` | ✖ | | MIGRATE |
| **F9** | `Phases-1.ps1` · **PHASE 17.5** — TIMESTOMP DETECTION | `$tsRoots = @($env:TEMP, $env:LOCALAPPDATA, $env:APPDATA, "$env:USERPROFILE\Downloads", "$env:ProgramData")` | ✖ | | MIGRATE (`$env:ProgramData` stays machine-wide) |
| **F10** | `Phases-1.ps1` · **PHASE 18** — DEEP CLOAKED PARASITE SCAN | `foreach ($ht in @($env:PUBLIC,$env:LOCALAPPDATA,$env:TEMP,"$env:USERPROFILE\AppData\Roaming"))` | ✖ | | MIGRATE (`$env:PUBLIC` machine-wide) |
| **F11** | `Phases-1.ps1` · **PHASE 31** — BITS / POWERSHELL PROFILE / STARTUP PERSISTENCE | `foreach ($sp in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"))` **and** `foreach ($prof in @($PROFILE.AllUsersAllHosts,$PROFILE.AllUsersCurrentHost,$PROFILE.CurrentUserAllHosts,$PROFILE.CurrentUserCurrentHost))` | ✔ yes | HIGH + `DeleteFile` | MIGRATE the `$env:APPDATA` Startup root and the two `$PROFILE.CurrentUser*` entries. `$env:ALLUSERSPROFILE` and `$PROFILE.AllUsers*` stay. **See §5.2 — `$PROFILE` is an automatic variable and this phase reads it** |
| **F12** | `Phases-1.ps1` · **PHASE 32.5** — DLL SIDE-LOADING | `$sideloadRoots = @($env:LOCALAPPDATA, $env:APPDATA, $env:TEMP, $env:ProgramData, "$env:USERPROFILE\Downloads")` and `$sideloadHardRoots = @($env:LOCALAPPDATA, $env:APPDATA, $env:TEMP, $env:ProgramData)` | ✖ | | MIGRATE. Note `$sideloadHardRoots` is used for an exact-root comparison (`.TrimEnd('\').ToLower()`) — it must gain every profile's roots or the HIGH escalation gate silently stops matching |
| **F13** | `Phases-1.ps1` · **PHASE 44.5** — CREDENTIAL ACCESS ARTIFACTS | `$credRoots = @($env:TEMP, "$env:WINDIR\Temp", $env:LOCALAPPDATA, $env:APPDATA, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:ProgramData", "$env:PUBLIC")` · `$dpapiStaged = (Get-ScanFiles -Path @($env:TEMP, "$env:USERPROFILE\Downloads", "$env:PUBLIC", "$env:ProgramData"))` · `foreach ($dp in $DPAPI_THEFT_PATHS)` | ✖ | CRITICAL + `Quarantine` | MIGRATE. **`$DPAPI_THEFT_PATHS` is dead today** (`%VAR%` bug, §0) — fix as part of this |
| **F14** | `Phases-1.ps1` · **PHASE 48** — KEYLOGGER FILE SCAN | `$klSearchPaths  = @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA,"$env:USERPROFILE\Documents")` | ✖ | CRITICAL + `DeleteFile` | MIGRATE |
| **F15** | `Phases-1.ps1` · **PHASE 49.5** — CLIPPER | `$clipperScriptRoots = @($env:TEMP, $env:LOCALAPPDATA, $env:APPDATA, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:ProgramData)` | ✖ | POSSIBLE + `Info` | MIGRATE |
| **F16** | `Phases-1.ps1` · **PHASE 51** — RANSOMWARE EXTENSION VELOCITY | `"$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Pictures",` / `"$env:USERPROFILE\Downloads","$env:USERPROFILE\Videos","$env:USERPROFILE\Music",` / `"$env:USERPROFILE\OneDrive","$env:PUBLIC"` | ✖ | | MIGRATE. Highest-value filesystem migration after F4/F22 — ransomware encrypts the *victim's* documents |
| **F17** | `Phases-2.ps1` · **PHASE 63** — CPU ABUSE & MINER PROCESS DETECTION | `$minerConfigFiles = (Get-ScanFiles -Path @($env:TEMP,$env:LOCALAPPDATA,"$env:USERPROFILE\AppData\Roaming")` | ✖ | | MIGRATE |
| **F18** | `Phases-2.ps1` · **PHASE 66** — NETWORK SHARE WORM PROPAGATION and **PHASE 77** — SSH & WINRM | `$usersRoot = Split-Path $env:USERPROFILE -Parent` · `$sshUsersRoot = Split-Path $env:USERPROFILE -Parent` | ✖ | | **MIGRATE-LITE.** Already all-users in intent, but derives the Users root from the *admin's* profile. Breaks when profiles live on `D:\` or a redirected root. Replace with the distinct `ProfileImagePath` parents from `Get-UserHives` |
| **F19** | `Phases-2.ps1` · **PHASE 68** — INFO-STEALER ARTIFACT SCAN | `$p68Files = @((Get-ScanFiles -Path @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA) -TimeScoped))` | ✖ | HIGH + `DeleteFile` | MIGRATE |
| **F20** | `Phases-2.ps1` · **PHASE 73** — EXPLOIT KIT ARTIFACT | `$exploitPaths = @("$env:TEMP\*shellcode*","$env:TEMP\*exploit*","$env:TEMP\*payload*","$env:LOCALAPPDATA\*shellcode*","$env:LOCALAPPDATA\*cobalt*","$env:LOCALAPPDATA\*beacon*")` | ✖ | | MIGRATE |
| **F21** | `Phases-2.ps1` · **PHASE 74** — OFFICE ADD-INS | `$officeAddinFolder = Join-Path $env:APPDATA 'Microsoft\AddIns'` | ✖ | POSSIBLE + `Info` | MIGRATE |
| **F22** | `Phases-2.ps1` · **PHASE 74.5** — EMAIL ATTACHMENT MALWARE SCAN (OUTLOOK CACHE) | `$emailAttachPaths = @($EMAIL_SCAN_PATHS) | Where-Object { $_ -and (Test-Path -LiteralPath $_ ...) }` → data key `email_scan_paths_raw` (8 paths) **plus** the inline list `"$env:LOCALAPPDATA\Microsoft\Windows\INetCache\Content.Outlook",` / `"$env:USERPROFILE\Downloads",` / `"$env:USERPROFILE\Desktop",` / `$env:TEMP` | ✖ | HIGH + `Quarantine` | MIGRATE — **top tier.** This is the phishing entry point and the operator's primary ticket source |
| **F23** | `Phases-2.ps1` · **PHASE 82.5** — REMOTE MONITORING TOOL ABUSE | `$tunnelRoots = @($env:TEMP,$env:LOCALAPPDATA,$env:USERPROFILE,"$env:WINDIR\Temp")` | ✖ | | MIGRATE |
| **F24** | `Phases-2.ps1` · **PHASE 89** — FINAL SWEEP — EXFIL CHANNELS & STEGO | `$stegoHits = (Get-ScanFiles -Path @($env:TEMP,$env:LOCALAPPDATA,$env:USERPROFILE)) | Where-Object { $_.Name -match $stegoRegex }` | ✖ | | MIGRATE. **Note the parenthesised `Get-ScanFiles` — preserve the parens** (`return ,$arr` pipe trap) |
| **F25** | `Phases-3.ps1` · **PHASE 90** — YARA-LITE BINARY STRING SCAN | `$yaraRoots = @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop",$env:APPDATA,$env:LOCALAPPDATA,$env:TEMP)` | DEEP | HIGH + `Quarantine` | MIGRATE |
| **F26** | `Phases-3.ps1` · **PHASE 91** — MARK-OF-THE-WEB | `foreach ($root in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop"))` | DEEP | | MIGRATE. Coordinate with **P6** (read `HostUrl`/`ReferrerUrl` from the stream) |
| **F27** | `Phases-3.ps1` · **PHASES 93 / 94 / 97 / 97.5 / 103** | five near-identical loops: `foreach ($root in @($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA,"$env:USERPROFILE\Downloads"))` · `foreach ($root in @($env:TEMP,$env:LOCALAPPDATA,"$env:LOCALAPPDATA\Apps","$env:USERPROFILE\Downloads"))` · `foreach ($root in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop",$env:TEMP))` | DEEP | HIGH + `DeleteFile` (94) | MIGRATE. Good candidate for a single shared `$zbUserRoots` helper variable computed once per scan |
| **F28** | `Phases-3.ps1` · **PHASE 100** — BROWSER PASSWORD/COOKIE DB RECENT ACCESS | `$credDbs = $INFOSTEALER_TARGET_PATHS` → data key `infostealer_target_paths_raw` (31 paths, `$env:LOCALAPPDATA`/`$env:APPDATA`, wildcards for multi-profile browsers) | DEEP | POSSIBLE + `Info` | MIGRATE — **top tier for evidence**, zero rule-#1 risk |
| **F29** | `Phases-3.ps1` · **PHASE 100.5** — CLOUD & SESSION TOKEN THEFT STAGING | `$tokRoots = @($env:TEMP, "$env:USERPROFILE\Downloads", "$env:PUBLIC", "$env:ProgramData", "$env:LOCALAPPDATA")` · `foreach ($tp in $CLOUD_TOKEN_PATHS)` | DEEP | INFO + `Info` | MIGRATE. **`$CLOUD_TOKEN_PATHS` is dead today** (`%VAR%` bug) — `TOKENSTORES_PRESENT` has never fired |
| **F30** | `Phases-3.ps1` · **PHASE 106** — MEMORY DUMP ARTIFACT SCAN | `"$env:LOCALAPPDATA\CrashDumps",` / `"$env:APPDATA\CrashDumps",` / `"$env:TEMP\*.dmp",` / `"$env:USERPROFILE\AppData\Local\Temp\*.dmp"` and `$dumpHits = (Get-ScanFiles -Path @($env:TEMP,$env:LOCALAPPDATA,$env:USERPROFILE))` | DEEP | | MIGRATE. Coordinate with **A11** (WER `Report.wer`) |
| **F31** | `Phases-2.ps1` · **PHASE 61** — RAT CONFIG FILES | `foreach ($rcp in $RAT_CONFIG_PATHS)` → data key `rat_config_paths_raw` (20 paths, `$env:APPDATA` / `$env:TEMP` / `$env:LOCALAPPDATA`) | ✖ | **CRITICAL + `DeleteFile`** | MIGRATE (data-side) |

### 1.3 KEEP — verified correct, do not touch

| Site | Anchor | Why KEEP |
|---|---|---|
| Loader | `$USER_NAME  = $env:USERNAME` | Identifies the *scan run context*, which is genuinely the admin. Correct — but the **banner label must change** so an operator is not misled (§4.6) |
| Loader | `$AUDIT_JSON    = Join-Path $env:TEMP "ZeroBreach_AuditCache_$(Get-Date -Format 'yyyyMMdd').json"` | The tool's own cache |
| Loader | `$flagFile = Join-Path $env:TEMP "ZeroBreach_KillFlag_..."` (in `Start-ShellKillWatcher`) | The tool's own IPC |
| Loader | comment `# Get-ChildItem -Recurse over $env:USERPROFILE drags in browser caches` | Comment only |
| All phases | `$env:WINDIR`, `$env:SystemRoot`, `$env:ProgramData`, `$env:ALLUSERSPROFILE`, `$env:PUBLIC` | Machine-wide by definition |
| `Phases-1.ps1` PHASE 10 | `@{P="$env:WINDIR\Temp"; L="Windows TEMP"}`, `@{P="$env:PUBLIC\Downloads"; L="Public Downloads"}` | Machine-wide; must be lifted OUT of the per-profile loop (§4.4) |
| `Phases-1.ps1` PHASE 31 | `$PROFILE.AllUsersAllHosts`, `$PROFILE.AllUsersCurrentHost` | Machine-wide PowerShell profiles |
| `Phases-2.ps1` PHASE 86 | `$recycleBin = (Get-ScanFiles -Path "C:\`$Recycle.Bin" -TimeScoped)` | Already all-users (per-SID subfolders). **Keep the walk**, but the finding should resolve and name the owning user from the SID folder — that is A9's prerequisite |
| `Phases-2.ps1` PHASE 87 | `$gpoScriptPaths = @("$env:WINDIR\System32\GroupPolicy\Machine\Scripts","$env:WINDIR\System32\GroupPolicy\User\Scripts")` | Machine-wide GPO store, despite the `User` in the path |
| `Phases-3.ps1` PHASES 108–115 | `Expand-EnvPath "%WINDIR%\System32"` and `Get-Perm 'critical_acl_paths'` | Machine-wide |
| `engine/FixMode.ps1` | 5 × `$env:*` | Interactive operator UI running as the operator by design |
| `ZeroBreach-Server.ps1` | all `$env:` | The server's own paths |
| All `HKLM:` registry paths | Phases 21, 22, 22.5, 23, 26, 27, 28, 29, 30, 41, 42.5, 45.5, 75, 108–115 | Machine-wide by definition |

---

## 2. `Get-UserHives` — helper design

### 2.0 Where it lives

**In the loader `ZeroBreach-V23.ps1`**, in the helper block — place it after `Get-RegVal` and before
`Test-PathGone`, near `Get-ScanFiles` / `Get-ProcSnapshot`.

Reasons this is not negotiable:
- `CLAUDE.md`: helpers live in the loader, phases live in `engine/*.ps1`.
- `$PSScriptRoot` inside a module resolves to `engine\`, not the project root. The helper needs
  `$global:ZB_ROOT` semantics.
- All modules dot-source into the loader's single scope, so a loader-defined function is visible to
  every phase without any import.
- The scan runspace in `ZeroBreach-Server.ps1` **cannot see** loader functions. If any server-side
  code ever needs `Get-UserHives`, it must be **re-declared inside** `$script:SCAN_SCRIPT` /
  `$script:REMEDIATE_SCRIPT`. Do not assume inheritance.

### 2.1 Exact signature

```powershell
function Get-UserHives {
    param(
        [switch]$IncludeService,      # also return S-1-5-18/19/20 (default: excluded)
        [switch]$AllowLoad,           # permit `reg load` of logged-off hives (default OFF — §2.6)
        [int]$MaxProfiles  = $global:UH_MAX_PROFILES,
        [int]$DeadlineSecs = $global:UH_DEADLINE_S
    )
    # ... body ...
    return ,$arr
}
```

> **`return ,$arr` reproduces the `Get-ScanFiles` single-item pipe trap.** Callers must wrap in
> parens when piping: `(Get-UserHives) | Where-Object {...}` — **never** `Get-UserHives | ...`.
> `@(Get-UserHives)` does **not** fix it. A bare `foreach ($zbHive in Get-UserHives)` is safe.
> Put that warning in the function's header comment verbatim, exactly as `Get-ScanFiles` and
> `Get-ProcSnapshot` already do.

### 2.2 Returned object shape

One `[pscustomobject]` per profile. Every field is required — consumers depend on all of them.

| Property | Type | Meaning |
|---|---|---|
| `Sid` | string | `S-1-5-21-2934201606-2785436122-4267783230-1001`. Any `.bak` suffix stripped |
| `User` | string | `WIN11\user` via SID→NTAccount translation. Falls back to `Split-Path $ProfilePath -Leaf` when the account is deleted or orphaned |
| `ProfilePath` | string | `ProfileImagePath` after `[Environment]::ExpandEnvironmentVariables` — it is a `REG_EXPAND_SZ` and `%SystemDrive%\Users\x` is common on imaged boxes |
| `HivePath` | string | `Registry::HKEY_USERS\<Sid>` for a mounted hive, `Registry::HKEY_USERS\<MountName>` for a loaded one, **`$null` when the hive is not available**. This is the string every migrated registry site concatenates onto |
| `ClassesHivePath` | string | See §2.5. `Registry::HKEY_USERS\<Sid>\Software\Classes` when mounted; the separate `UsrClass.dat` mount when loaded; `$null` when unavailable |
| `WasMounted` | bool | `$true` = the hive was already present in `HKEY_USERS` (user is logged on) |
| `Loaded` | bool | `$true` = **this call performed a `reg load`**; an unload is owed |
| `MustUnload` | bool | Alias of `Loaded`, named for readability at the call site |
| `MountName` | string | The `HKU\<name>` argument for `reg unload` (`ZB_UH_<8 hex>`). `$null` when `WasMounted` |
| `ClassesMountName` | string | Same, for the `UsrClass.dat` mount. `$null` unless a classes hive was loaded |
| `NtUserDat` | string | `<ProfilePath>\NTUSER.DAT` |
| `UsrClassDat` | string | `<ProfilePath>\AppData\Local\Microsoft\Windows\UsrClass.dat` |
| `ProfileReachable` | bool | `$false` for an unreachable / UNC roaming profile. **Every filesystem consumer must check this before touching the path** (§5.4) |
| `IsCurrent` | bool | `$true` when `Sid` equals the running identity's SID — lets a site say "this is the account the scan is running as" |
| `Source` | string | `'HKU'` · `'RegLoad'` · `'NotMounted'`. Carried into finding descriptions as provenance |
| `Rid` | int | The trailing RID (`1001`, `500`, ...). Informational — used to tag the built-in Administrator/Guest, never to exclude |

### 2.3 Filtering non-human accounts — measured on the live box

**Probe: `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`**
```
  SID=S-1-5-18                                        State=0 Flags=12  Path=C:\WINDOWS\system32\config\systemprofile
  SID=S-1-5-19                                        State=0 Flags=0   Path=C:\WINDOWS\ServiceProfiles\LocalService
  SID=S-1-5-20                                        State=0 Flags=0   Path=C:\WINDOWS\ServiceProfiles\NetworkService
  SID=S-1-5-21-2934201606-2785436122-4267783230-1001  State=0 Flags=0   Path=C:\Users\user
```

**Probe: SID → account translation**
```
  S-1-5-18                                          -> NT AUTHORITY\SYSTEM
  S-1-5-19                                          -> NT AUTHORITY\LOCAL SERVICE
  S-1-5-20                                          -> NT AUTHORITY\NETWORK SERVICE
  S-1-5-21-2934201606-2785436122-4267783230-1001    -> WIN11\user
```

**Probe: mounted `HKEY_USERS`, classified**
```
  .DEFAULT                                                  [DEFAULT-ALIAS]
  S-1-5-19                                                  [SERVICE]
  S-1-5-20                                                  [SERVICE]
  S-1-5-21-2934201606-2785436122-4267783230-1001            [HUMAN-CANDIDATE]
  S-1-5-21-2934201606-2785436122-4267783230-1001_Classes    [CLASSES]
  S-1-5-18                                                  [SERVICE]
```

**Filter rules, applied in this order:**

1. **Enumerate `ProfileList`, not `HKEY_USERS`.** `ProfileList` is the authority: it includes
   logged-off users and excludes the `.DEFAULT` / `_Classes` noise. Use `HKEY_USERS` only as a
   *lookup* to decide `WasMounted`.
2. **Skip `.bak` entries** — `if ($zbSid -match '\.bak$') { continue }`. None exist on this box, but
   they appear after a failed profile load and their `ProfileImagePath` is often stale. *Optional
   evidence value:* a `.bak` entry is the fingerprint of a profile-corruption / temp-profile event;
   consider an INFO finding recording it.
3. **Require the human SID shape:** `'^S-1-5-21-\d+-\d+-\d+-\d+$'`. This single rule eliminates
   `S-1-5-18`, `S-1-5-19`, `S-1-5-20` and `.DEFAULT`. Do **not** filter on the substring `S-1-5-18`
   — a domain SID can legitimately contain those digits in another position.
4. **Reject `_Classes`:** `-notlike '*_Classes'`. It never appears in `ProfileList`, but guard
   anyway in case a caller feeds an `HKEY_USERS`-derived name.
5. **Path-based service/template exclusions:** skip when `ProfileImagePath` matches
   `'(?i)\\(ServiceProfiles|systemprofile)\\'`, or is `C:\Users\Default`, `Default User`, or
   `C:\Users\Public`. Redundant with rule 3, kept as belt and braces.
6. **`defaultuser0`** — the OOBE staging account. It has a real `S-1-5-21` SID, so rule 3 will not
   catch it. Exclude by **profile leaf name**: `'(?i)^defaultuser\d*$'`.
7. **RID `-500` / `-501` are NOT excluded.** Built-in Administrator and Guest are real,
   human-usable profiles that can be infected. Record `Rid` and tag them; never filter them out.
8. **Do not filter on `State` or `Flags`.** On this box every profile — including all three service
   profiles — reads `State=0`. The values are useless as a human/non-human discriminator.
9. **De-duplicate by SID**, preferring the non-`.bak` entry.
10. `-IncludeService` bypasses rules 3/5 to return `S-1-5-18/19/20`. Present for completeness and
    for a possible future "SYSTEM profile persistence" check. **Not used by any P1 migration.**

### 2.4 The `reg load` hazard — measured, not assumed

Every statement below is a probe result on this box: real `powershell.exe` **5.1.26100.8875**,
elevated (`IsAdmin: True`), user `WIN11\user`, Windows 11 Pro 10.0.26200.

#### (a) A logged-on user's `NTUSER.DAT` is locked — confirmed

```
=== 1. can we reg load a LOGGED-ON user NTUSER.DAT? ===
    exists: True
    reg load exit=1 out=ERROR: The process cannot access the file because it is being used
                          by another process.
```

**Therefore: always try `Registry::HKEY_USERS\<SID>` first.** `reg load` is attempted only when the
SID is absent from `HKEY_USERS`.

#### (b) Privileges — elevated is sufficient, no P/Invoke needed

`reg load` of an *unlocked* hive succeeded in **0.05 s** with no explicit enabling of
`SeBackupPrivilege` / `SeRestorePrivilege`:

```
    reg load exit=0 in 0.05s out=The operation completed successfully.
```

`reg.exe` acquires the privileges itself from the elevated token. No privilege-adjustment P/Invoke
is required. If the engine is somehow *not* elevated, `reg load` fails cleanly with a non-zero exit
code — the helper must degrade to HKU-only, never throw.

#### (c) THE critical hazard — the unload can be permanently defeated by the caller

First reproduction (the hive **leaked**):

```
=== 2. copy Default NTUSER.DAT and load the COPY ===
    copy ok
    reg load exit=0 in 0.05s out=The operation completed successfully.
    --- 2a. read via provider (Get-ChildItem) then unload WITHOUT gc ---
    top-level subkeys: 10 -> AppEvents,Console,Control Panel,Environment,EUDC,Keyboard Layout,
                             Microsoft,Network,Software,System
    Run key readable: True
    --- 2b. unload attempt #1 (no gc, handles possibly open) ---
    unload exit=1 out=ERROR: Access is denied.
    --- 2c. [gc]::Collect + WaitForPendingFinalizers, retry ---
    unload-after-gc exit=1 out=ERROR: Access is denied.        <-- gc did NOT rescue it
=== 3. does the load survive / leak? ===
    HKU children now: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-21-...-1001,
                      S-1-5-21-...-1001_Classes,ZBP1_TEST,S-1-5-18
                                                  ^^^^^^^^^ LEAKED
```

From a **fresh process**, the same unload succeeded instantly:

```
fresh-process unload exit=0 out=The operation completed successfully.
```

→ the handles are held by the **PowerShell process that read the hive**, not by any external agent.

Root cause isolated by follow-up probes (cases A–M):

| Case | What the caller did | `reg unload` result |
|---|---|---|
| **A** | load, **no reads at all** | ✅ `exit=0` clean |
| **B** | `Get-ItemProperty` only (no subkey enumeration) | ✅ `exit=0` clean, **no gc needed** |
| **F** | `Get-Item` (single key), result **still in a live variable** | ❌ `Access is denied` → ✅ after `Remove-Variable` + gc |
| **K** | `Get-ChildItem` result **held in `$zbKids`** (live), then 2× gc | ❌ **`Access is denied` — gc cannot help while a reference is rooted** |
| **K′** | same, then `Remove-Variable zbKids` + gc | ✅ `exit=0` clean |
| **H** | `Get-ChildItem` piped to `$null`, then gc | ✅ `exit=0` clean |
| **L** | `Get-ChildItem ... \| ForEach-Object { $_.PSChildName }` (**only strings escape**) | ✅ `exit=0` clean with one gc |
| **I** | .NET `OpenSubKey` + explicit `.Close()` / `.Dispose()` in `finally` | ✅ `exit=0` clean, no gc needed |
| **C** | .NET `OpenSubKey` **leaked** (never disposed) | ❌ denied → ✅ after gc (finalizer ran) |

Verbatim, the decisive pair:

```
=== K. keep $zbKids alive, gc, unload ===
    kids held in variable: 10
    unload WITH live ref + gc         : exit=1 ERROR: Access is denied.
    unload AFTER Remove-Variable + gc : exit=0 The operation completed successfully.
=== L. project only the strings we need (no RegistryKey escapes the pipeline) ===
    names held (strings only): 10
    unload : exit=0 The operation completed successfully.
```

**Conclusion. `[gc]::Collect()` IS the correct mitigation and IS required — but it is necessary and
not sufficient.** It works only when **no live variable still holds a `RegistryKey` / `PSObject`
rooted in the mounted hive.** The earlier "gc didn't help" result was caused by four live variables
(`$kids`, `$run`, `$sf`, `$sf2`) still in script scope at gc time.

**Consequence of getting this wrong:** a leaked hive keeps the victim's `NTUSER.DAT` **locked for
the remaining life of the engine process**. That user's next logon yields a **temporary profile**
with an empty desktop — a visible outage on a client machine, caused by the IR tool.

#### (c′) Mandated read discipline inside a loaded hive (`Source -eq 'RegLoad'`)

- ✔ `Get-ItemProperty` / the engine's `Get-RegVal` wrapper — safe, no handle retention.
- ✔ `Get-ChildItem ... | ForEach-Object { $_.PSChildName }` — **project to strings inside the same
  pipeline**; never let `RegistryKey` objects land in a variable.
- ✔ .NET `[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, ...)`
  with `.Close()` + `.Dispose()` in a `finally` — safe and deterministic; use this if a site needs
  raw `REG_EXPAND_SZ` values (`RegistryValueOptions::DoNotExpandEnvironmentNames`, §3.2).
- ✖ **FORBIDDEN:** `$k = @(Get-ChildItem 'Registry::HKEY_USERS\<mount>\...')`. If a site genuinely
  needs key objects — Phase 24 uses `$k.PSPath`, Phase 21.5 uses `-Recurse -Depth 4` — it must first
  project to the strings it needs (`PSChildName`, plus values read through `Get-RegVal`) and must
  not retain the object past the loop iteration.
- After all reads and before the unload: `Remove-Variable` every holder, then
  `[gc]::Collect(); [gc]::WaitForPendingFinalizers(); [gc]::Collect()`.

#### (d) Unload placement — `finally` plus an unconditional scan-end backstop

Two layers, because `finally` alone is not enough in this engine.

```powershell
# module/loader scope: registry of every mount THIS SCAN created
$global:UH_LOADED_MOUNTS = New-Object System.Collections.ArrayList

# inside Get-UserHives, per profile:
$zbMount = 'ZB_UH_' + (Get-StableId "$zbSid")     # deterministic, collision-safe, 8 hex
try {
    $null = & reg.exe load "HKU\$zbMount" $zbNtUser 2>&1
    if ($LASTEXITCODE -eq 0) {
        $null = $global:UH_LOADED_MOUNTS.Add($zbMount)
        # ... build the object with Loaded=$true, MountName=$zbMount ...
    }
} catch { }   # never throw out of the helper
```

- **Caller-side contract:** any phase consuming `Get-UserHives -AllowLoad` calls `Close-UserHives`
  in a `finally`.
- **Backstop, unconditional:** `engine/Summary.ps1` — which already runs at the end of every mode
  and already owns the `[Environment]::Exit()` calls — must call `Close-UserHives -All` **before**
  exiting. This matters because `try/finally` in a dot-sourced phase body does **not** run on
  `[Environment]::Exit(N)` or on a hard process kill from the GUI abort button.
- Also call `Close-UserHives -All` from the loader's resilience trap path.
- **Retry contract:** attempt unload → on failure `[gc]::Collect(); [gc]::WaitForPendingFinalizers()`
  → attempt again → on second failure emit a **HIGH severity, `FixAction Info`** finding naming the
  user and the mount, carrying the exact operator command `reg unload HKU\<mount>` and the warning
  that the profile stays locked until the scan process exits. **Never swallow it silently. Never
  CRITICAL + a destructive action** (rule #1).

#### (e) Cost

A full cycle — `reg load` → read Run key + User Shell Folders + enumerate `Software\Classes\CLSID` →
gc → `reg unload` — measured:

```
=== M. how long does reg load + a realistic read + unload take? ===
    read+unload elapsed 35ms ; exit=0 The operation completed successfully.
```

Loading is not the expense. The **filesystem walks it unlocks** are (§2.7 budget division).

### 2.5 The classes hive — two measured facts

**Fact 1 — for a logged-on user, `HKU\<SID>\Software\Classes` and `HKU\<SID>_Classes` are the same
store** (the former is a registry symbolic link). Probed:

```
=== Classes hive: HKU\<SID>_Classes vs HKU\<SID>\Software\Classes ===
  _Classes\CLSID count             : 6
  <SID>\Software\Classes\CLSID cnt : 6
  HKCU:\SOFTWARE\Classes\CLSID cnt : 6
```

→ For `WasMounted` profiles set
`ClassesHivePath = "Registry::HKEY_USERS\$Sid\Software\Classes"`. One string, simpler, and it makes
the migration of R3 / R4 / R14 / R15 / R19 a pure prefix substitution.

**Fact 2 — for a `reg load`ed `NTUSER.DAT` it is NOT the same.** `Software\Classes` exists but is
nearly empty; the real per-user class registrations live in `UsrClass.dat`. Probed:

```
  load NTUSER exit=0
  NTUSER.DAT has Software\Classes : True
  CLSID subkeys inside NTUSER hive: 1          (vs 6 for the live user)
  has Volatile Environment        : False
  unload exit=0 The operation completed successfully.
```

And the file exists where expected:
```
  C:\Users\user\AppData\Local\Microsoft\Windows\UsrClass.dat exists=True
```

→ For `Loaded` profiles, `UsrClass.dat` must be loaded as a **second, separate mount**, and
`ClassesHivePath` must point at it. It carries its own `Loaded` / unload obligation, tracked in
`$global:UH_LOADED_MOUNTS` as a distinct entry with its own `ClassesMountName`.

**Without this, a logged-off user's COM-hijack (R4) and UAC-bypass (R19) checks are structurally
blind** — both techniques live in `Software\Classes`.

**Recommendation:** load `UsrClass.dat` only when `-AllowLoad` is set **and** a consumer actually
needs classes. Track a `NeedsClasses` hint or simply always load both when `-AllowLoad` is on — at
35 ms per cycle the cost is negligible and the conditional logic is more likely to be got wrong.

### 2.6 Is `reg load` compatible with "audit-only during scanning"? — recommendation

`EVIDENCE_ENGINE_PLAN.md` §7 constraint 7 states **"Audit-only during scanning"**, and §3 Tier C
declined Amcache specifically because acquiring it "needs a **VSS snapshot — a system state
change**, which conflicts with the audit-only scanning contract," adding that if ever pursued it
should be "gate[d] behind explicit operator opt-in, never in an automatic DEEP scan."

**Recommendation, stated firmly: `reg load` IS a system state change. Ship it OFF by default,
behind an explicit operator opt-in.**

Reasoning, in order of weight:

1. **It is observably a mutation, not a read.** It mounts a hive into the live registry where it is
   visible to *every process on the box*; it takes a write-capable handle on `NTUSER.DAT`; it
   touches the hive's `.LOG1` / `.LOG2` transaction files. That is categorically different from
   `Get-ItemProperty` against an already-mounted hive, which is a pure read.
2. **The failure mode is user-visible damage, and it was reproduced, not theorised.** §2.4(c) shows
   a hive that could not be unmounted for the life of the process. The victim's profile stays
   locked; their next logon yields a temporary profile. Worse than VSS in one specific respect: VSS
   can only be triggered by code that explicitly asks for it, whereas a hive leak can be caused by
   an *unrelated* phase author writing `$k = Get-ChildItem ...` — a mistake the existing code style
   makes constantly and correctly everywhere else.
3. **Precedent and consistency.** The plan already drew this exact line for Amcache. `reg load` is
   the same category at lower severity. Drawing the line differently here would make the constraint
   arbitrary.
4. **The default costs almost nothing.** On a live incident the accounts that matter are usually
   logged on, or were logged on recently enough that their hive is still mounted. HKU-only covers
   the common case completely and is an unambiguous pure read.
5. **But the evidence is genuinely valuable when it applies** — a shared reception PC where the
   infected user logged off two days ago is exactly what an IR triage tool should handle. So it must
   be *available*, just deliberate.

**Concrete gating to implement:**

- **Default:** `Get-UserHives` returns only profiles already present in `HKEY_USERS`. Logged-off
  profiles are **still returned**, with `WasMounted=$false`, `Loaded=$false`, `Source='NotMounted'`,
  `HivePath=$null`, `ClassesHivePath=$null`. Callers skip them for registry work but can still
  report on them, and can still use `ProfilePath` for **filesystem** work (the filesystem needs no
  hive).
- **Opt-in:** a new loader `param()` switch — **name it `-LoadUserHives`**. Do not choose a name
  whose letters collide with any existing loader parameter (`$mode $hours $auto $html $baseline
  $schedule $stealth $paranoid $outdir $iocfile $smtpto $smtpfrom $smtpserver`). Store it as
  `$global:UH_ALLOW_LOAD = [bool]$LoadUserHives -or [bool]$env:ZB_LOAD_HIVES`, using the same
  **presence-based** env convention as `$global:SCAN_FILE_CACHE_ON = -not $env:ZB_NOCACHE` so a
  headless harness can enable it without a CLI change.
- **Never load in STEALTH mode.** Guard on `$global:STEALTH_MODE` — stealth's entire contract is
  minimal footprint.
- **Server surface:** if `/api/scan/start` ever exposes this, it must be an explicit operator
  checkbox in the GUI, defaulted off, never part of a saved scan profile's silent defaults.
- **When loading is off, the engine must SAY SO rather than reporting clean.** See §4.9.

### 2.7 Budgets, caching, and the companion function

#### Budgets — a new budget class

`EVIDENCE_ENGINE_PLAN.md` §7 constraint 4 requires every bulk loop to carry a deadline + count
budget, and notes the existing `SCAN_*` / `SIG_AUDIT_*` budgets do not cover new work classes.

```powershell
$global:UH_MAX_PROFILES  = 25    # hard cap on profiles returned
$global:UH_DEADLINE_S    = 20    # wall-clock for the whole enumeration, including loads
$global:UH_MAX_LOADS     = 10    # hard cap on `reg load` operations per scan
$global:UH_UNC_TIMEOUT_S = 3     # per-profile reachability probe ceiling (§5.4)
```

**Behaviour on exceeding any cap: stop enumerating, return what you have, and register an INFO
finding stating that the cap was hit and how many profiles were skipped.** Never truncate silently —
a silently truncated profile list reproduces exactly the class of bug P1 exists to fix.

#### Downstream budget division — mandatory

**`Get-ScanFiles`'s `MaxFiles` / `DeadlineSecs` are PER CALL, not per scan.** Wrapping a
`Get-ScanFiles` call in `foreach ($zbHive in Get-UserHives)` multiplies the wall-clock budget by the
profile count: 8 profiles × 20 s = **160 s for one phase**. On a terminal-server box with 30
profiles this alone would hang the GUI.

Every per-profile `Get-ScanFiles` call site must divide:

```powershell
$zbHives = @(Get-UserHives)
$zbPerHiveDeadline = [Math]::Max(4, [int]($global:SCAN_DEADLINE_S / [Math]::Max(1, $zbHives.Count)))
$zbPerHiveFiles    = [Math]::Max(500, [int]($global:SCAN_MAX_FILES / [Math]::Max(1, $zbHives.Count)))
# ...
(Get-ScanFiles -Path $zbRoots -TimeScoped -DeadlineSecs $zbPerHiveDeadline -MaxFiles $zbPerHiveFiles) | Where-Object { ... }
```

Two important consequences:
- **Passing non-default `DeadlineSecs` / `MaxFiles` changes the `Get-ScanFiles` cache key**
  (`"|M=$MaxFiles|D=$DeadlineSecs|"` are part of `$ck`), so per-profile calls will not alias with
  legacy full-budget calls. That is correct behaviour, but it means the memo hit rate drops. Expect
  a modest slowdown and verify against the `PHASE N — ... took` timings.
- **A better alternative where the phase allows it:** pass *all* profiles' roots to a **single**
  `Get-ScanFiles` call (it already accepts `[string[]]$Path`) and attribute each returned file back
  to a profile by longest-prefix match on `FullName`. One budget, one walk, full attribution.
  **Prefer this shape** for F4, F9, F12, F13, F14, F15, F19, F25, F27, F30. Reserve the per-profile
  loop for sites that genuinely need per-profile isolation.
  - Caveat: `Get-ScanFiles` keeps **caller order** in its cache key deliberately, because under
    truncation the walk order decides which files make the cut. Build the multi-profile root array
    in a **deterministic order** (sort by SID) so the memo is stable across phases.

The same division applies to `$global:SIG_AUDIT_DEADLINE_S` / `$global:SIG_AUDIT_MAX_FILES` in any
per-profile loop that calls `Get-AuthSig` (F2, F5, F11, F12, F25).

#### Caching — yes, memoise

Consistent with the existing `$global:SCAN_FILE_CACHE` and `$global:PROC_SNAP_CACHE` memos:

```powershell
$global:USER_HIVE_CACHE    = @{}
$global:USER_HIVE_CACHE_ON = $global:SCAN_FILE_CACHE_ON   # shares the ZB_NOCACHE kill-switch
$global:USER_PATH_CACHE    = @{}                          # for Get-UserPaths, keyed on SID
```

- **Key: the parameter tuple**, `"$IncludeService|$AllowLoad"`. `-AllowLoad` genuinely changes the
  result set, so a scalar cache would be wrong. Use a hashtable keyed on that string, not a bare
  variable.
- **No TTL.** Unlike the process table (which is why `Get-ProcSnapshot` has a 90 s TTL),
  `ProfileList` is effectively static for the duration of a scan.
- **Do not cache a truncated result.** If `UH_DEADLINE_S`, `UH_MAX_PROFILES` or `UH_MAX_LOADS` was
  hit, return the partial array but do **not** store it — same reasoning `Get-ScanFiles` uses for
  refusing to cache a deadline-truncated walk.
- **`Close-UserHives` must invalidate the cache**, because after unload the `Loaded` entries'
  `HivePath` values are stale and pointing at mounts that no longer exist.
- Honour `ZB_NOCACHE` exactly as the other memos do: presence-based, any value (even `"0"`) disables.

#### `Close-UserHives` — companion function (loader)

```powershell
function Close-UserHives {
    param(
        [switch]$All,                 # unload every mount this scan created
        [string[]]$MountName          # or just these
    )
    # 1. Remove-Variable / null out any cached objects that could root a RegistryKey.
    # 2. [gc]::Collect(); [gc]::WaitForPendingFinalizers(); [gc]::Collect()
    # 3. foreach mount: reg.exe unload "HKU\$m"
    #    on non-zero exit -> gc again -> retry once
    #    on second failure -> Add-Finding HIGH + FixAction Info naming the user + mount +
    #                          the literal command `reg unload HKU\<mount>` + the warning that
    #                          the profile stays locked until this process exits.
    # 4. Remove successfully unloaded mounts from $global:UH_LOADED_MOUNTS.
    # 5. $global:USER_HIVE_CACHE = @{}   (invalidate)
    # Must NEVER throw.
}
```

Call sites:
- Each phase that used `-AllowLoad`, in a `finally`.
- **`engine/Summary.ps1`, unconditionally, before every `[Environment]::Exit(N)`.** This is the
  backstop that survives `-Auto` server-driven runs.
- The loader's resilience-trap path.

---

## 3. `Get-UserPaths` and `Expand-UserPathTemplate` — the path helpers

Registry is only half the problem. `$env:APPDATA` and friends need a per-user equivalent.

### 3.1 `Get-UserPaths` — exact signature and shape

```powershell
function Get-UserPaths {
    param([Parameter(Mandatory)]$Hive)      # one object returned by Get-UserHives
    # memoised in $global:USER_PATH_CACHE keyed on $Hive.Sid, honouring ZB_NOCACHE
}
```

Returned `[pscustomobject]`:

| Property | Meaning |
|---|---|
| `Sid`, `User` | copied from the hive object, so a caller only needs this one object |
| `Profile` | `<ProfilePath>` |
| `AppData` | Roaming AppData |
| `LocalAppData` | Local AppData |
| `Temp` | per-user temp |
| `Downloads`, `Desktop`, `Documents`, `Pictures`, `Videos`, `Music`, `Favorites` | known folders |
| `Startup`, `StartMenu`, `Programs`, `Recent`, `INetCache` | shell folders |
| `OneDrive` | OneDrive root, or `$null` |
| `Redirected` | `$true` if any resolved path falls outside `Profile`; `$false` if all inside; **`$null` = unknown** (fallback construction was used) |
| `Reachable` | copied from `$Hive.ProfileReachable` |
| `Source` | `'VolatileEnv'` · `'UserShellFolders'` · `'Constructed'` |

### 3.2 Resolution order — do NOT just append `\AppData\Roaming`

Folder redirection and the `User Shell Folders` key genuinely move these. Resolve in this order:

**1. `Volatile Environment` — best source, logged-on users only.** Probed on the live user:

```
=== Volatile Environment (per-user env from a mounted hive) ===
    LOGONSERVER = \\WIN11
    USERDOMAIN = WIN11
    USERNAME = user
    USERPROFILE = C:\Users\user
    HOMEPATH = \Users\user
    HOMEDRIVE = C:
    APPDATA = C:\Users\user\AppData\Roaming
    LOCALAPPDATA = C:\Users\user\AppData\Local
    USERDOMAIN_ROAMINGPROFILE = WIN11
```

Path: `Registry::HKEY_USERS\<SID>\Volatile Environment`. This is the user's *actual live
environment* — precisely what `$env:APPDATA` would be inside their session. Use it whenever present.

**Measured caveat: it does NOT exist in a `reg load`ed hive** — it is volatile by construction:
```
  has Volatile Environment        : False        (loaded Default NTUSER.DAT)
```
So it covers `WasMounted` profiles only.

**2. `...\Explorer\User Shell Folders` — primary for loaded hives, authoritative for redirection.**
Path: `Registry::HKEY_USERS\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`.
Probed on the live user:

```
    AppData      = C:\Users\user\AppData\Roaming
    Cache        = C:\Users\user\AppData\Local\Microsoft\Windows\INetCache
    Cookies      = C:\Users\user\AppData\Local\Microsoft\Windows\INetCookies
    Desktop      = C:\Users\user\Desktop
    Favorites    = C:\Users\user\Favorites
    History      = C:\Users\user\AppData\Local\Microsoft\Windows\History
    Local AppData= C:\Users\user\AppData\Local
    My Music     = C:\Users\user\Music
    My Pictures  = C:\Users\user\Pictures
    My Video     = C:\Users\user\Videos
    NetHood      = C:\Users\user\AppData\Roaming\Microsoft\Windows\Network Shortcuts
    Personal     = C:\Users\user\Documents
    PrintHood    = C:\Users\user\AppData\Roaming\Microsoft\Windows\Printer Shortcuts
    Programs     = C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs
    Recent       = C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent
    SendTo       = C:\Users\user\AppData\Roaming\Microsoft\Windows\SendTo
    Start Menu   = C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu
    Startup      = C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    Templates    = C:\Users\user\AppData\Roaming\Microsoft\Windows\Templates
    {374DE290-123F-4565-9164-39C4925E467B} = C:\Users\user\Downloads
```

Four must-know details:

- **Value-name mapping is not obvious.** `Personal` = **Documents**. `Local AppData` has a space.
  `Cache` = INetCache. `My Music` / `My Pictures` / `My Video` keep the legacy `My ` prefix.
- **Downloads has NO friendly name** — it is the GUID
  **`{374DE290-123F-4565-9164-39C4925E467B}`**. Hardcode it.
- **Values are `REG_EXPAND_SZ` containing `%USERPROFILE%`.** Confirmed on a loaded hive:
  ```
  USF AppData raw: %USERPROFILE%\AppData\Roaming
  ```
  **CRITICAL: do NOT use `[Environment]::ExpandEnvironmentVariables` on these** — it would expand
  `%USERPROFILE%` to the **admin's** path and silently reintroduce the exact bug P1 exists to fix.
  Read the raw value (`[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames` via the
  .NET API, or accept the provider's already-expanded value **only** for `WasMounted` profiles where
  the provider expands against the right user), then substitute manually:
  ```powershell
  $zbVal = $zbRaw -replace '(?i)%USERPROFILE%', $Hive.ProfilePath.Replace('$','$$')
  $zbVal = $zbVal -replace '(?i)%HOMEDRIVE%%HOMEPATH%', $Hive.ProfilePath.Replace('$','$$')
  $zbVal = [Environment]::ExpandEnvironmentVariables($zbVal)   # only machine-scope vars remain
  ```
  Note the `$` doubling: `-replace`'s replacement string treats `$` as a capture reference.
- **Prefer `User Shell Folders` over `Shell Folders`.** The latter is an Explorer-maintained cache;
  on this box it contained only the sentinel value:
  ```
  SF  !Do not use this registry key = Use the SHGetFolderPath or SHGetKnownFolderPath function instead
  ```

**3. Fallback — construct from `ProfilePath`** when neither source is available (logged-off profile
with hive loading disabled):

```
AppData      = <Profile>\AppData\Roaming
LocalAppData = <Profile>\AppData\Local
Temp         = <Profile>\AppData\Local\Temp
Downloads    = <Profile>\Downloads
Desktop      = <Profile>\Desktop
Documents    = <Profile>\Documents
INetCache    = <Profile>\AppData\Local\Microsoft\Windows\INetCache
Startup      = <Profile>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
Recent       = <Profile>\AppData\Roaming\Microsoft\Windows\Recent
```

**Set `Redirected = $null` (unknown), not `$false`.** Consumers of a fallback-derived path must
carry a caveat in their finding: a redirected Documents folder living on a file server means the
ransomware / document scan looked somewhere that does not hold the user's documents, and reporting
that as clean is exactly the P3-class dishonesty the plan forbids.

**4. `Temp` has no `User Shell Folders` entry.** Derive as `<LocalAppData>\Temp`. If the box sets a
per-user `TEMP` override it lives in `Registry::HKEY_USERS\<SID>\Environment` (`TEMP` / `TMP`,
`REG_EXPAND_SZ`) — read that when present, applying the same `%USERPROFILE%` substitution rule.

**5. `OneDrive`** — check `Registry::HKEY_USERS\<SID>\Environment\OneDrive`, then
`...\Software\Microsoft\OneDrive\Accounts\Business1\UserFolder`. F16 (Phase 51) references
`"$env:USERPROFILE\OneDrive"`; the constructed fallback is usually right but the `Environment` value
is authoritative.

**6. Set `Redirected = $true`** whenever any resolved path does not start with `Profile`. This is
itself worth surfacing to the operator — it tells them a whole class of file-based checks looked at
a network share, and it interacts with the UNC hazard in §5.4.

### 3.3 `Expand-UserPathTemplate` — the data-side resolver

```powershell
function Expand-UserPathTemplate {
    param([string]$Template, $UserPaths)      # $UserPaths from Get-UserPaths
    # Substitutes: {USERPROFILE} {APPDATA} {LOCALAPPDATA} {TEMP} {DOWNLOADS}
    #              {DESKTOP} {DOCUMENTS} {STARTUP} {RECENT} {INETCACHE} {ONEDRIVE}
    # Leaves machine-scope %VAR% forms to [Environment]::ExpandEnvironmentVariables.
    # Returns $null when a required token has no value (caller skips, never emits a
    # half-substituted path).
}
```

**Why a `{TOKEN}` syntax rather than keeping `$env:`:**
- It is unambiguous and cannot be silently expanded by a stray `ExpandString` or
  `ExpandEnvironmentVariables` call.
- It makes the `%VAR%`-versus-`$env:` class of bug — **which is live in two lists today** — structurally
  impossible: an unsubstituted `{APPDATA}` is glaringly visible in a log line, whereas an
  unsubstituted `%APPDATA%` looks like a legitimate Windows path and silently matches nothing.
- Signature literals stay in `data/detection_signatures.json`, so the AMSI rule is untouched. The
  token syntax is generic mechanism, not signature content.

---

## 4. Per-call-site migration instructions

### 4.1 Canonical registry migration pattern

**Before** (Phase 20 shape):
```powershell
$runPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ...
)
foreach ($rp in $runPaths) {
    if (Test-Path $rp) {
        $keys = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        foreach ($prop in (...)) { ...grading... }
    }
}
```

**After:**
```powershell
# Machine-wide roots: enumerated ONCE, OUTSIDE the profile loop. This is the primary
# anti-flood mechanism -- see section 4.4.
$zbRunMachine = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)
# Per-user roots expressed HIVE-RELATIVE (no HKCU:, no leading backslash).
$zbRunUserRel = @(
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)

$zbTargets = @()
foreach ($zbRp in $zbRunMachine) {
    $zbTargets += @{ Path = $zbRp; User = 'MACHINE'; Sid = 'MACHINE'; Src = 'HKLM' }
}
foreach ($zbHive in (Get-UserHives)) {
    if (-not $zbHive.HivePath) { continue }        # not mounted + loading disabled -> section 4.9
    foreach ($zbRel in $zbRunUserRel) {
        $zbTargets += @{ Path = "$($zbHive.HivePath)\$zbRel"
                         User = $zbHive.User; Sid = $zbHive.Sid; Src = $zbHive.Source }
    }
}

foreach ($zbT in $zbTargets) {
    Out-Typewriter "AUDITING HIVE: $($zbT.Path)" "INFO"
    if (-not (Test-Path $zbT.Path)) { continue }
    $zbKeys = Get-ItemProperty -Path $zbT.Path -ErrorAction SilentlyContinue
    foreach ($zbProp in ($zbKeys.psobject.properties | Where-Object { $_.Name -notmatch "^PS" }).Name) {
        $zbVal = $zbKeys.$zbProp
        # ... EXISTING grading logic, unchanged: the $val -match "Temp|cmd\.exe|..." test,
        #     the $RUNKEY_BENIGN_RE allowlist branch, the AppData POSSIBLE branch ...
    }
}
```

Properties of this shape:
- Machine roots enumerated once, not once per profile.
- The relative-path split is what makes the data-side migration (§4.3) mechanical.
- Existing grading and FP-tuning logic is **untouched** — this is deliberately a plumbing change.
- `Get-RegVal` is used for scalar reads (never `Get-ItemPropertyValue`); `Get-ItemProperty` for
  whole-key enumeration, which is the safe read shape inside a loaded hive (§2.4 case B).

### 4.2 Finding `Target`, `Description` and `ID`

**The affected username MUST be visible in the finding.** An operator seeing "Run key found" needs
to know *whose*. Mandatory for every migrated site:

- **`Target`** — prefix the user:
  - value target: `"[$($zbT.User)] $($zbT.Path)|$zbProp"`
  - key target: `"[$($zbT.User)] $zbPath"`
  - machine-wide target: `"[MACHINE] $zbPath"`
- **`Description`** — lead with the user, and state provenance when the hive was loaded:
  > `Malicious Run key for user CONTOSO\jsmith (S-1-5-21-...-1104 — logged off, hive read from NTUSER.DAT): [HKU\...\Run] Updater = C:\Users\jsmith\AppData\Local\Temp\x.exe`
- **`ID` — must incorporate the SID.** Without it, `Add-Finding`'s de-dupe silently drops the second
  user's finding. Use the existing stable hasher:
  ```powershell
  -ID "RUNKEY_$(Get-StableId "$($zbT.Sid)|$($zbT.Path)|$zbProp")"
  ```
  **Never `.GetHashCode()`** — it is randomised per process on .NET 5+/pwsh 7, which breaks
  `-Baseline` diffing forever. `Get-StableId` is FNV-1a over UTF-8 and deterministic across
  processes and runtimes.

**Note on `FixParam` separator collision:** several sites use `"$path|$name"` as the `DeleteReg`
FixParam, and the server splits on `"\|", 2`. Registry paths cannot contain `|`, and the
`Registry::HKEY_USERS\<SID>\...` form does not introduce one, so the existing split remains correct.
**Do not put the `[User]` prefix into `FixParam`** — only into `Target` and `Description`. FixParam
must stay a machine-parseable path.

### 4.3 Data-side migration — `data/detection_signatures.json`

Twelve keys currently bake in the running user. **Do not migrate these by editing each phase.**
Convert them to hive-relative / token form and resolve at the call site.

#### Registry list conversions

| Key | Current | Change to | Consumer |
|---|---|---|---|
| `rat_reg_paths` | `"HKCU:\\SOFTWARE\\njRAT"` × 12 | `"SOFTWARE\\njRAT"` (hive-relative) | Phase 61 (R10) |
| `keylogger_reg_paths` | `"HKCU:\\SOFTWARE\\Ardamax"` × 7 | `"SOFTWARE\\Ardamax"` | Phase 48 (R8) |
| `uac_bypass_regs` | `"HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command"` × 5 | `"Software\\Classes\\ms-settings\\shell\\open\\command"` | Phase 92 (R19) |
| `com_typelib_hijack_roots` | `["HKCU:\\SOFTWARE\\Classes\\TypeLib","HKCU:\\SOFTWARE\\Classes\\CLSID"]` | `["SOFTWARE\\Classes\\TypeLib","SOFTWARE\\Classes\\CLSID"]` | Phase 21.5 (R3) |
| `runmru_reg_path` | `"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"` | `"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"` | Phase 68.5 (R13) |
| `adware_pup_regs` | **mixed** 21 × `HKCU:` + 3 × `HKLM:` | **split into two keys:** `adware_pup_regs_user` (hive-relative) and `adware_pup_regs_machine` (absolute `HKLM:`) | Phase 67 (R12) |
| `proactive_persistence_regs` | array of `{Path, Why}` with mixed `HKCU:`/`HKLM:` | add `"Scope": "user"` or `"machine"` to each object; make user paths hive-relative | Phase 74.7 (R16) |
| `proactive_office_keys` | array of `{Path, Name, SafeValue, Why}`, all `HKCU:` | make `Path` hive-relative, add `"Scope": "user"` | Phase 74.7 (R16) |

**Backwards-compatibility guard.** The loader reads these via `Get-Sig`, which returns `@()` for a
missing key. To keep the change safe if the JSON and the `.ps1` land out of step, the call sites
should tolerate **both** forms:
```powershell
# strip a leading HKCU:\ if a legacy JSON is still in place
$zbRel = "$zbEntry" -replace '(?i)^HK(CU|EY_CURRENT_USER):?\\', ''
```
This is 1 line and removes an entire class of deployment mismatch.

#### Path list conversions (`*_raw` keys)

| Key | Current | Change to | Consumer |
|---|---|---|---|
| `rat_config_paths_raw` | `"$env:APPDATA\\server.exe"` × 20 | `"{APPDATA}\\server.exe"` | Phase 61 (F31) |
| `email_scan_paths_raw` | `"$env:LOCALAPPDATA\\Microsoft\\Olk\\Attachments"` × 8 | `"{LOCALAPPDATA}\\Microsoft\\Olk\\Attachments"` | Phase 74.5 (F22) |
| `infostealer_target_paths_raw` | `"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\*\\Login Data"` × 31 | `"{LOCALAPPDATA}\\Google\\Chrome\\User Data\\*\\Login Data"` | Phase 100 (F28) |
| `dpapi_theft_paths_raw` | `"%APPDATA%\\Microsoft\\Protect"` × 4 — **BROKEN TODAY** | `"{APPDATA}\\Microsoft\\Protect"` | Phase 44.5 (F13) |
| `cloud_token_paths_raw` | `"%USERPROFILE%\\.aws\\credentials"` × 16 — **BROKEN TODAY** | `"{USERPROFILE}\\.aws\\credentials"` | Phase 100.5 (F29) |

#### Kill the loader's eager expansion

These five loader lines expand **once, at load time, against the admin's environment**:

```powershell
$RAT_CONFIG_PATHS       = @((Get-Sig 'rat_config_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$EMAIL_SCAN_PATHS       = @((Get-Sig 'email_scan_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$DPAPI_THEFT_PATHS      = @((Get-Sig 'dpapi_theft_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$CLOUD_TOKEN_PATHS      = @((Get-Sig 'cloud_token_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
$INFOSTEALER_TARGET_PATHS = @((Get-Sig 'infostealer_target_paths_raw') | ForEach-Object { $ExecutionContext.InvokeCommand.ExpandString($_) })
```

**Replace each with the raw template array**, and resolve per profile at the call site:

```powershell
$RAT_CONFIG_TEMPLATES     = Get-Sig 'rat_config_paths_raw'          # templates, NOT expanded
# ... at the call site ...
foreach ($zbHive in (Get-UserHives)) {
    if (-not $zbHive.ProfileReachable) { continue }
    $zbUp = Get-UserPaths $zbHive
    foreach ($zbTpl in $RAT_CONFIG_TEMPLATES) {
        $zbPath = Expand-UserPathTemplate $zbTpl $zbUp
        if (-not $zbPath) { continue }
        if (Test-Path $zbPath) { ... }
    }
}
```

Keep the variable **names** if you like, but they now hold templates — rename to `*_TEMPLATES` so a
future reader cannot mistake them for resolved paths.

### 4.4 Flood control — how each site avoids 8× the findings

**Requirement: a box with 8 profiles must not produce 8× the findings for a machine-wide
condition.** Five mechanisms, in order of importance:

1. **Machine roots enumerated once, outside the profile loop.** This is the main one. Concretely:
   - the `HKLM:` half of R2 (Phase 20), R9 (49.5), R14 (70), R20 (94), R12 (67), R15 (74)
   - `$env:WINDIR\Temp` and `$env:PUBLIC\Downloads` in F4 (Phase 10)
   - `$env:ProgramData` in F9, F12, F13, F15, F29
   - `$env:PUBLIC` in F10, F13, F29
   - `$env:ALLUSERSPROFILE` and `$PROFILE.AllUsers*` in F11
   Each must be lifted out and tagged `[MACHINE]`.

2. **De-duplicate resolved paths.** After `Get-UserPaths`, `Select-Object -Unique` the combined root
   set. Two cases this catches: several redirected profiles collapsing onto the same server share,
   and `<Profile>\AppData\Local\Temp` for the scan-context user being identical to `$env:TEMP` —
   which would otherwise scan the admin twice and double-report.

3. **Aggregate INFO inventory into a single finding.** F1 (Phase 7 browser caches) and F29
   (Phase 100.5 `TOKENSTORES_PRESENT`) are *inventory*, not detections. Emit **one** finding per
   phase summarising all profiles:
   > `Browser cache folders present for 3 of 4 profiles: jsmith (4 browsers), mjones (2), admin (1).`
   Not one row per profile per browser.

4. **`Add-Finding`'s existing group cap is the safety NET, not the plan.**
   `$global:FINDING_GROUP_CAP` (default 100) rolls the tail into a `GROUPCAP_*` summary finding.
   Hitting it means real per-user findings were **suppressed**. Treat a new `GROUPCAP_*` finding
   appearing post-P1 as a **test failure**, not as flood control working. Only consider raising the
   cap after live grading proves a legitimate multi-profile box exceeds it.

5. **Per-profile budget division** (§2.7) so a wide box degrades in *time* gracefully rather than by
   silently dropping profiles.

### 4.5 Grading changes

**P1 requires no severity changes in principle** — the same condition in the correct hive deserves
the same grade. Two deliberate exceptions:

- **Cap findings from a `reg load`ed (logged-off) profile at HIGH, and prefer `FixAction Info`.**
  The evidence is a snapshot of an offline hive; the user is not logged on, so nothing from that
  hive is currently executing. Combined with §4.7, this makes loaded-hive findings advisory.
- **F1 (Phase 7)** currently pairs `INFO` with `DeleteFile`, which is an odd combination that
  becomes an odd *list* once multiplied. Fold into the aggregate INFO finding with `FixAction Info`.

### 4.6 Reporting the scan context honestly

The loader sets `$USER_NAME = $env:USERNAME` and prints it in the banner. Post-P1 this is actively
misleading, because the findings now span several users.

- Relabel the banner line to **`SCAN RUNNING AS: <admin>  |  PROFILES EXAMINED: <n> of <m>`**.
- At the first migrated phase, emit one INFO finding listing every profile discovered: SID, account
  name, profile path, `WasMounted`, `ProfileReachable`, and whether it was examined. This is the P1
  half of the plan's **A1 log-availability census** and it feeds §4 (correlation) caveat propagation.

### 4.7 `FixParam` — the hard constraint

**A `FixParam` must never point into a temporarily-mounted hive.**

Remediation runs **later, in a different process** — `$script:REMEDIATE_SCRIPT` inside
`ZeroBreach-Server.ps1`, spawned from `POST /api/remediate`, long after the engine exited and the
`ZB_UH_*` mount vanished. A FixParam of `Registry::HKEY_USERS\ZB_UH_a1b2c3d4\...` would silently
target nothing, and the server's tri-state verifiers (`Test-RRegValueGone` / `Test-RPathGone`) would
then have to reason about a path that never existed — the exact "verification passes because the
read failed" failure the tri-state contract was written to prevent.

Rules:

- **`WasMounted` profiles** (`Registry::HKEY_USERS\<SID>\...` is a real, persistent path as long as
  the user stays logged on): `FixParam` may use that form. Both server handlers pass `$f.FixParam`
  straight into `Remove-ItemProperty -LiteralPath` / `Remove-Item -LiteralPath`, which accept
  provider-qualified paths. **Verify end-to-end before shipping** (rollout step 6).
  - Residual risk to note in the description: if the user logs off between scan and remediation, the
    hive unmounts and the path disappears. `Test-RPathGone` returns `'gone'` for a missing path, so
    the tool would report success for an unperformed removal. **Mitigation:** the remediation
    handler should treat a `Registry::HKEY_USERS\S-1-5-21-*` path whose SID is absent from
    `HKEY_USERS` at remediation time as **`blocked`**, not `applied`. Add this check to
    `$script:REMEDIATE_SCRIPT`.
- **`Loaded` profiles: `FixAction Info` only.** Put the full operator command in the description:
  ```
  reg load HKU\ZBFIX "C:\Users\jsmith\NTUSER.DAT"
  Remove-ItemProperty -LiteralPath 'Registry::HKEY_USERS\ZBFIX\SOFTWARE\...\Run' -Name 'Updater' -Force
  reg unload HKU\ZBFIX
  ```
  This is rule #1's own prescription for an action the operator must run by hand.
- **R6 (Phase 35) specifically.** Its FixParam is
  `"Set-ItemProperty -Path '$proxyPath' -Name ProxyEnable -Value 0 -Force; Remove-ItemProperty -Path '$proxyPath' -Name ProxyServer -Force; netsh winhttp reset proxy"`. Two problems:
  (a) `$proxyPath` must be rebuilt per hive; (b) `netsh winhttp reset proxy` is **machine-scope** and
  must be emitted **once**, not once per profile. Split it into a separate machine-level finding.

### 4.8 `Test-ProtectedTarget` interaction — audited

`Test-ProtectedTarget` lives in `ZeroBreach-Server.ps1` and is **mirrored inside
`$script:REMEDIATE_SCRIPT`** (a runspace cannot see the parent's functions). It matches substrings of
`$Param` / `$Target` / `$Desc`. Audited against the new path shapes:

- ✅ `if ($p -match '(?i)\\SafeBoot')` — substring, still fires on `Registry::HKEY_USERS\<SID>\...\SafeBoot`.
- ✅ `if ($Action -match '(?i)DeleteReg' -and $p -match '(?i)\\(SYSTEM\\CurrentControlSet\\(Services|Control)|Microsoft\\Windows NT\\CurrentVersion\\(Winlogon|Image File Execution Options|SystemRestore)|Cryptography)')` — substring, unaffected by the prefix change.
- ⚠️ `if ($p -match '(?i)\\(desktop\.ini|iconcache\.db|thumbs\.db|ntuser\.dat|usrclass\.dat)')` → *"Windows shell/system file"*. It tests `$p` (FixParam), **not** the description, so a description mentioning `NTUSER.DAT` will not trip it — good. But any FixParam containing the literal `NTUSER.DAT` **will** be hard-blocked. That is the correct outcome and is another reason loaded-hive findings must be `Info` (§4.7).
- ⚠️ `if ($p -match '(?i)\\Users\\[^\\]+\\\.[^\\]+$' -or $p -match '(?i)\\\.(ssh|gnupg|aws|azure|kube|docker|config)\\' ...)` → *"user shell/git/ssh/cloud config (dotfile)"*. Once F13/F29 emit **other** users' `C:\Users\jsmith\.aws\credentials`, this correctly hard-blocks. Confirm the GUI's `protected` badge shows the right user.
- **No regression:** the guard is scope-agnostic; nothing in it is `HKCU:`-specific.
- **Do ADD one rule, in BOTH copies:** a `Registry::HKEY_USERS\<SID>` path whose SID is
  `S-1-5-18`, `S-1-5-19`, `S-1-5-20` or `.DEFAULT` is a **service/system hive** and must be hard-blocked.
  `Get-UserHives` excludes them by default, but `-IncludeService` exists and a future caller could
  pass it.
- **Do ADD the logged-off check** from §4.7 to `$script:REMEDIATE_SCRIPT`.
- Keep both copies in sync — `CLAUDE.md` calls this out explicitly.

### 4.9 Honesty findings — never report clean for a check that could not run

Three distinct cases. Each gets an explicit finding; none may be silently skipped.

**(a) Profile not examined because the hive is not loaded and loading is disabled**
```
Severity: INFO      FixAction: Info      Group: "Scan Coverage"
ID: "UNSCANNED_HIVE_$(Get-StableId $zbHive.Sid)"
Target: "[<User>] <ProfilePath>"
Description:
  "User 'CONTOSO\jsmith' (S-1-5-21-...-1104) was NOT examined for registry-based persistence:
   their hive is not loaded (the user is logged off) and hive loading is disabled by default.
   THIS IS NOT A CLEAN RESULT for that user. Re-run with -LoadUserHives, or have the user log
   on, to cover this profile. Filesystem checks for this profile <did / did not> run."
```

**(b) Profile unreachable (UNC / roaming, §5.4)**
```
Severity: INFO      FixAction: Info      Group: "Scan Coverage"
Description:
  "User 'CONTOSO\jsmith' has a roaming profile on an unreachable path (\\fs01\profiles\jsmith).
   No file-based check could run for this user. Registry checks <did / did not> run
   (hive <was / was not> mounted locally)."
```

**(c) Budget cap hit**
```
Severity: INFO      FixAction: Info      Group: "Scan Coverage"
Description:
  "Profile enumeration stopped at the configured cap (25 profiles / 20 s / 10 hive loads).
   N profile(s) were not examined: <names>. Results for those users are unknown, not clean."
```

**(d) Hive would not unload (§2.4d)**
```
Severity: HIGH      FixAction: Info      Group: "Scan Coverage"
Description:
  "The registry hive loaded for user 'CONTOSO\jsmith' could not be unloaded (mount ZB_UH_a1b2c3d4).
   Their profile stays locked until this scan process exits, and a logon before then would give
   them a TEMPORARY PROFILE. If the scan has already exited, run: reg unload HKU\ZB_UH_a1b2c3d4"
```

This mirrors the plan's **P3** principle — *"Never print a clean result for a check that could not
have fired"* — and feeds directly into **A1** (log-availability census) and **§4** (verdict caveat
propagation).

---

## 5. Rule compliance and risk

### 5.1 Rule #1 — P1 INCREASES the auto-destructive set. This is the headline risk.

`CLAUDE.md` user rule #1: *"The tool must NEVER auto-select or auto-apply anything that damages the
system."* Auto-select = **CRITICAL or HIGH severity + a destructive `FixAction`** (`DeleteFile`,
`DeleteReg`, `DeleteRegKey`, `KillProcess`, `RunCmd`, `Quarantine`).

P1 surfaces more findings by design. These migrated sites land findings directly in the
auto-destructive set, **multiplied by profile count**:

| Site | Grade + action | Risk assessment |
|---|---|---|
| **R2 · Phase 20** Run keys | CRITICAL + `DeleteReg` | **Highest.** Every profile's Run key is now in scope, and this phase already contributes to the healthy-box baseline |
| **F4 · Phase 10** Temp/Downloads | HIGH + `DeleteFile` | **Highest filesystem risk.** Session 17 recorded **92 of this box's 94** auto-destructive findings coming from Phase 10 alone, hitting `%TEMP%\claude\` harness debris. That count multiplies per profile. Phase 10 consults **no** benign-path list — it is an open FP-tuning candidate independently of P1 |
| **R14 · Phase 70** fileless | CRITICAL + `DeleteReg` | High — `HKCU:\Environment` and `Software\Classes\CLSID` exist for every user, so every profile is walked |
| **R6 · Phase 35** proxy | CRITICAL + `RunCmd` | High — **every user with a corporate PAC/proxy configured now produces a CRITICAL**. Needs a live re-grade on a proxied box specifically |
| **R19 · Phase 92** UAC bypass | CRITICAL + `DeleteRegKey` | Historically low FP, but now × profiles |
| **R4 · Phase 24** COM hijack | HIGH + `DeleteRegKey` | Medium — the "must shadow HKLM **and** have a server override" gate holds, but runs × profiles |
| **R3 · Phase 21.5** TypeLib | HIGH + `DeleteRegKey` | Medium — already live-tuned once for the Microsoft Teams Meeting Add-in FP. **That tuning must be re-verified per profile**: every profile with Teams reproduces the same shape |
| **R1 · Phase 5** AmsiEnable | CRITICAL + `DeleteReg` | Low — key rarely exists |
| **R5 · Phase 25** GPO lockdown | HIGH + `DeleteReg` | Low |
| **R8 / R10 / R12** keylogger / RAT / adware vendor keys | CRITICAL / HIGH + `DeleteRegKey` | Low — these keys never exist on a clean box (that is why `DeleteRegKey` was considered safe to auto-select) |
| **R20 · Phase 94** Squiblydoo Run key | CRITICAL + `DeleteReg` | Low — requires a `regsvr32 /i:URL` pattern |
| **R15 · Phase 74** VBAWarnings=1 | HIGH + `RunCmd` | Medium — one per profile with Office configured that way |
| **F2 · Phase 8** browser extensions | CRITICAL + `DeleteFile` | Medium — name-match branch only, but × profiles |
| **F11 · Phase 31** startup folder | HIGH + `DeleteFile` | Medium |
| **F13 · Phase 44.5** cred artifacts | CRITICAL + `Quarantine` | Medium — was live-tuned down from 99 FPs once already (GUID-filename heuristic); re-verify |
| **F22 · Phase 74.5** Outlook attachments | HIGH + `Quarantine` | Medium |
| **F25 · Phase 90** YARA-lite | HIGH + `Quarantine` | Medium |
| **F27 · Phase 94** COM scriptlets | HIGH + `DeleteFile` | Medium |
| **F31 · Phase 61** RAT config files | **CRITICAL + `DeleteFile`** | Low — literal known-RAT filenames |
| **F14 · Phase 48** keylogger files | CRITICAL + `DeleteFile` | Medium — already allowlisted via `$KEYLOG_BENIGN_RE` / `Test-BenignPath`; verify the allowlist still applies per profile |
| **F19 · Phase 68** infostealer artifacts | HIGH + `DeleteFile` | Medium |
| **F3 · Phase 9** shortcut hijack | CRITICAL + `RunCmd` | Low |

**Sites with ZERO rule-#1 risk** (Info/POSSIBLE only — migrate these first): R9 (49.5), R13 (68.5),
R17 (84), R18 (85), F1 (7), F15 (49.5), F21 (74), F28 (100), F29 (100.5), plus the F13/F29 dead-list
fixes.

**Mandatory gate before merge:** re-grade the healthy-box auto-destructive count **on a box with at
least two real profiles**, **attributed per phase**.

- `EVIDENCE_ENGINE_PLAN.md` §7 constraint 8 states the current healthy-box baseline as **7**.
- Session 17 recorded **this dev box at 94**, of which 92 were Phase 10 hitting `%TEMP%\claude\`
  debris.
- **Therefore the raw total is not a usable signal on this box.** Compute the delta **per phase** and
  judge each phase's delta on its own.

**Recommended sequencing hedge:** land the Info/POSSIBLE-only sites first, grade, then land the
destructive-capable ones **one cluster at a time**. Migrating Phase 20 and Phase 10 in the same
commit as fifteen other sites makes the re-grade uninterpretable — which is precisely how WS6's
first cut pushed the auto-destructive count from 41 to 136 undetected.

### 5.2 Case-insensitive shadowing — including two AUTOMATIC variables

PowerShell variables are **case-insensitive**, and the engine is one dot-sourced scope: a local in a
phase body can assign the loader's `param()` variables. A local `$auto` silently reassigns
`[switch]$Auto` and hangs every server-driven scan with no output and no error.

**Prefix every new local `$zb*` / `$zbUh*`.**

**Forbidden — loader `param()` variables:**
`$auto $mode $hours $html $baseline $schedule $stealth $paranoid $outdir $iocfile $smtpto $smtpfrom $smtpserver`

**P1-specific hazards a naive implementation WILL hit:**

- **`$profile` is a PowerShell AUTOMATIC variable.** Writing
  `foreach ($profile in Get-UserHives) { ... }` clobbers `$PROFILE` — and **`Phases-1.ps1` PHASE 31
  reads `$PROFILE.AllUsersAllHosts` / `$PROFILE.CurrentUserAllHosts`** in the same dot-sourced
  scope. It would silently stop detecting malicious PowerShell profiles, with no error. This is the
  `$auto` bug class exactly, and Phase 31 is itself a P1 migration target (F11), so the collision is
  very likely. **Use `$zbHive` / `$zbProf`.**
- **`$home` is automatic** — `$HOME` is the same variable, case-insensitively. Never name anything
  `$home`, `$Home`, `$HOME`.
- **`$host`** is automatic (the host UI object). Never use it for a hostname.
- **`$pid` is READ-ONLY** and automatic. (Precedent: a `$pid` local in Phase 56 clobbered `$PID` and
  fabricated rootkit findings; it was renamed `$rkpid`.)
- **`$args`, `$input`, `$pwd`, `$psitem`, `$error`, `$matches`** — avoid.
- **Existing engine globals to avoid colliding with:** `$SIG`, `$PERM`, `$SEV_*`, `$PhasePlan`,
  `$USER_NAME`, `$AUDIT_JSON`, `$LOG_LINES`.

**Recommended names:** `$zbHive`, `$zbHives`, `$zbUp` (user paths), `$zbSid`, `$zbUser`,
`$zbUhMount`, `$zbRel`, `$zbT`, `$zbTargets`, `$zbRoots`, `$zbTpl`, `$zbPath`.

### 5.3 `Get-StableId` and `-Baseline` diffing — YES, this breaks existing finding IDs

**Direct answer: migrating a site changes its finding IDs, and the `-Baseline` diff will report
every migrated finding as NEW exactly once.**

Two distinct mechanisms:

**Mechanism 1 — IDs that MUST change (correctness, non-negotiable).**
Every ID built from a name-only fragment must gain the SID or it collides across users and
`Add-Finding` silently drops the duplicate:

| Current ID shape | Phase | Collides because |
|---|---|---|
| `RUNKEY_$($prop -replace '[^a-z0-9]','')` | 20 | two users with a `OneDrive` Run value → one ID |
| `COM_$($guid -replace '[^a-z0-9]','')` | 24 | same CLSID registered per-user by two users |
| `EXT_$($ext.Name)` | 8 | the same extension installed in two profiles |
| `FILELESS_$($prop.Name -replace '[^a-z0-9]','')` | 70 | same value name |
| `GPO_$pol` / `GPO_M_$pol` | 25 | `DisableTaskMgr` for two users |
| `PROXY_ENABLE` | 35 | **fixed string** — only ever one finding, ever |
| `AMSI_DISABLED` | 5 | **fixed string** |
| `BROWSER_CACHE_$($bc.L -replace ' ','')` | 7 | label only |
| `CERT_$($cs.Id)_$($cert.Thumbprint.Substring(0,8))` | 39 | `Id='USER'` is constant across users |
| `CLICKFIX_$($mp.Name)_$(Get-StableId $mruCmd)` | 68.5 | two users pasting the same command |
| `TOKENSTORES_PRESENT` | 100.5 | **fixed string** |
| `MACRO_TRUST_$($mt.PSPath -replace '[^a-z0-9]','')` | 74 | PSPath-derived → changes, but does not collide |

**Mechanism 2 — IDs that change incidentally.**
Sites already hashing a path change because `HKCU:\...` becomes `Registry::HKEY_USERS\<SID>\...`:
`TYPELIB_$(Get-StableId "$($tl.PSPath)")` (21.5), `KLREG_*` (48), `RATREG_*` / `RATFILE_*` (61),
`ADWARE_*` (67), `UACBYPASS_*` (92), `SQUIBLY_*` (94), `CLIPPER_RUN_*` (49.5), `ADDIN_*` (74),
`CREDDB_*` (100), and every filesystem-path-derived ID whose path now names a different user.

**Answers to the specific questions:**

- **Does migrating break `-Baseline` diffing?** Yes, once, at the migrated sites.
- **Can it be avoided with a compat shim?** **No, and do not attempt one.** Preserving the old ID for
  the scan-context user would defeat Mechanism 1 and reintroduce the cross-user collision. Collision
  safety wins over diff continuity — a dropped finding is a missed infection.
- **Is the churn recurring?** **No.** `Get-StableId` is FNV-1a over UTF-8 with a `uint64` accumulator
  and an explicit 32-bit mask; it is deterministic across processes **and** across PS 5.1 / pwsh 7.
  The new IDs are stable forever after. (This is why `.GetHashCode()` is banned: it is randomised
  per process on .NET 5+, so IDs derived from it change every run and the diff reports the same
  finding as new *forever*.)

**Required mitigation:**
1. **The migration commit must state, in `CHANGELOG.md` and the PR body:** *"P1 changes finding IDs
   at ~20 sites. Any `-Baseline` snapshot captured before this commit will report those findings as
   new on the first run after. Re-capture the baseline."*
2. **Phase 105+ (`BASELINE DIFF — New Findings Since Snapshot`)** will produce one large false "new"
   block on that first run. Have it emit an INFO note when the loaded baseline predates the P1
   commit — cheap, and it prevents an operator chasing a phantom incident.
3. **Re-capture the healthy-box baseline** as part of rollout step 9.

### 5.4 The UNC / roaming-profile trap — measured, and it is a HANG, not a throw

`ProfileImagePath` **can** point at a UNC path (roaming profiles). This is P1's specific version of
the known `Test-Path`-on-unreachable-UNC hazard.

`Test-Path` on an unreachable UNC path did **not** throw on this box — but it did something
arguably worse. Verbatim probe output:

```
--- LITERAL: \\10.255.255.1\share\prof
    returned [False] in 42.2s
--- GLOB   : \\10.255.255.1\share\prof
    returned [False] in 0s
--- LITERAL: \\zbnosuchhost99\share\prof
    returned [False] in 5.5s
--- GLOB   : \\zbnosuchhost99\share\prof
    returned [False] in 0s
--- LITERAL: \\zbnosuchhost99\share
    returned [False] in 0s
--- LITERAL: \\zbnosuchhost99
    returned [False] in 0s
--- LITERAL: \\10.255.255.1\share\*
    returned [False] in 0s
```

Two things to read out of this:
- **42.2 seconds, silently, with no error** for an unrouteable IP. On a box with three roaming
  profiles that is over two minutes of dead time before the first finding.
- **The second and later identical calls returned in 0 s** — negative DNS/SMB caching. **A naive
  retest looks completely fine.** Anyone re-testing this must use a fresh, never-probed host/IP.

Separately, the project's own recorded experience (session 17) is that `Test-Path` on an unreachable
UNC path **can** throw a terminating `IOException` that `-ErrorAction SilentlyContinue` does **not**
suppress. Inside a phase module that unwinds to the module trap and **skips every remaining phase in
that module**.

**The guard must therefore defend against BOTH outcomes:**

```powershell
# 1. TEXTUAL tests FIRST, before any filesystem access.
$zbReachable = $true
if ($zbPip -match '^\\\\') {
    # UNC roaming profile: do NOT probe by default -- 42s stalls, and it may throw.
    $zbReachable = $false
}
elseif ($zbPip -notmatch '^[A-Za-z]:\\') {
    $zbReachable = $false                      # not a local absolute path at all
}
else {
    # 2. Local path: bounded probe, wrapped. -EA SilentlyContinue is NOT sufficient.
    try   { $zbReachable = [bool](Test-Path -LiteralPath $zbPip -ErrorAction SilentlyContinue) }
    catch { $zbReachable = $false }
}
```

If a UNC probe is ever genuinely required (operator opt-in), bound it in a job with a hard timeout:

```powershell
$zbReachable = $false
try {
    $zbJob = Start-Job { param($p) Test-Path -LiteralPath $p } -ArgumentList $zbPip
    if (Wait-Job $zbJob -Timeout $global:UH_UNC_TIMEOUT_S) { $zbReachable = [bool](Receive-Job $zbJob) }
    Remove-Job $zbJob -Force -ErrorAction SilentlyContinue
} catch { $zbReachable = $false }
```

**Rules:**
- `Get-UserHives` sets `ProfileReachable` **exactly once** per profile. **No downstream site
  re-probes.** One 42 s stall inside the helper is survivable; the same stall repeated across the 31
  filesystem call sites is a dead scan.
- A `ProfileReachable = $false` profile is **still returned** — its **registry** side may work
  perfectly if the hive happens to be mounted locally. Only filesystem consumers skip it, and it
  gets honesty finding (b) from §4.9.
- **`Get-UserHives` must never throw.** It lives in the loader, so a throw propagates into whichever
  module called it and takes out the rest of that module. Wrap the whole body; on total failure
  return `,@()` plus a HIGH `FixAction Info` finding.
- `Get-ScanFiles` already wraps its own `Test-Path` in `try { } catch { continue }` — that
  protection is per root, so it survives, but it does not protect against the 42 s stall. Filter
  unreachable roots out **before** calling it.

### 5.5 Hardening sites — operator-only, and ask before widening

R11 (Phase 65 autorun `RunCmd`) and R16 (Phase 74.7: `$PROACTIVE_OFFICE_KEYS`,
`$PROACTIVE_PERSIST_REGS`, the `FileExts\...\UserChoice` remap) all write to `HKCU`. Migrating them
means **hardening every profile on the box** — a materially larger blast radius than today.

`EVIDENCE_ENGINE_PLAN.md` §7 constraint 1 and `CLAUDE.md` both state: *"Hardening / lockdown /
posture actions are OPERATOR-ONLY: `Info` or `POSSIBLE` + `RunCmd`. Never `CRITICAL`/`HIGH` with a
destructive action."* The GUI's **SELECT HARDENING** button is the deliberate opt-in.

**Recommendation — split the two halves:**

- **Audit / inventory half → MIGRATE.** Phase 74.7's `$PROACTIVE_PERSIST_REGS` autorun-surface
  inventory and the `VBAWarnings` / `Level` reads should absolutely cover every profile. Reading
  every user's macro-security setting is exactly right and carries no risk.
- **Write half → AMBIGUOUS-ASK.** Keep the `RunCmd` FixParams single-user by default, but **state
  explicitly in the description which user the command applies to** (today it silently means "the
  admin running the scan", which is nearly useless for the hardening's actual purpose). Offer an
  "apply to all profiles" variant only if the operator asks for it.

### 5.6 Other rule checks

| Rule | P1 compliance |
|---|---|
| **`Get-RegVal`, not `Get-ItemPropertyValue`** | ✔ Every migrated scalar read uses `Get-RegVal`. It takes `-Path`, so `Registry::HKEY_USERS\...` works unchanged. `-EA SilentlyContinue` does not suppress `Get-ItemPropertyValue`'s terminating errors — the wrapper exists for that reason |
| **Never pipe `Get-ScanFiles` directly** | ⚠️ **Watch closely.** Migration converts single roots into per-profile loops and multi-root arrays. `(Get-ScanFiles -Path $zbRoots) \| Where-Object` **must keep its parens** — `return ,$arr` makes the whole array arrive as one item, so the filter silently matches everything or nothing. `@(Get-ScanFiles ...)` does **not** fix it. Affected: F6, F13, F14, F17, F19, F21, F24, F30 |
| **Never `(fn ...)[0]` when fn may return a single value** | ⚠️ `Get-UserHives` returns `,$arr` so `(Get-UserHives)[0]` happens to be safe — **use `@(Get-UserHives)[0]` anyway**. The existing loader pattern `@(Get-Sig 'runmru_reg_path')[0]` is correct; preserve it when converting that key |
| **`try/catch` is statement-only on PS 5.1** | ⚠️ The UNC guard and the load/unload wrapper are the risky spots. Never write `(try{...}catch{...})` as a sub-expression — it parses on PS 7 and runtime-errors on 5.1 |
| **`$global:ZB_ROOT`, not `$PSScriptRoot`** | ✔ All new helpers live in the loader; no new module-relative paths |
| **`Get-StableId`, not `.GetHashCode()`** | ✔ Mandated in §4.2 |
| **No signature literals in `.ps1`** | ✔ Every list change is data-side (§4.3). The `{TOKEN}` resolver is generic mechanism, not signature content. AMSI rule untouched |
| **Every bulk loop carries a deadline + count budget** | ✔ §2.7 defines the `UH_*` budget class and mandates per-profile division of `SCAN_*` / `SIG_AUDIT_*` |
| **Each module keeps its own top-level `trap`** | ✔ No new modules; existing `trap { Write-RecoveredError $_; continue }` statements untouched. Grouped QUICK-skip blocks keep their inner traps |
| **`[Environment]::Exit(N)` in modules, not bare `exit`** | ✔ No new exits. `Close-UserHives -All` must be called *before* `Summary.ps1`'s existing `[Environment]::Exit()` calls |
| **PHASE HEADER COUNTS MUST NOT CHANGE** | ✔ **P1 adds ZERO `Show-PhaseHeader` calls.** Phases-1 = 70, Phases-2 = 40, Phases-3 = 30 all stay exact. **QUICK stays exactly 30 ungated headers.** P1 is a modification of existing phase bodies only — **confirmed.** Six migrated sites (R1, R2, R6, R14, F4, F11) do run in QUICK, so QUICK gets *slower*, but its header count is untouched. Re-count after every commit anyway |
| **New detections get a fractional phase in a non-QUICK block** | n/a — P1 introduces no new detections |
| **UTF-8 BOM, parse-clean on PS 5.1 AND pwsh 7** | ✔ Standard gate; all 6 engine files |
| **Validate on real `powershell.exe` 5.1** | ✔ The `,$arr` unwrap, `(try{})` sub-expression and single-element-unwrap behaviours only surface on the real 5.1 runtime |
| **Runspace isolation** | ⚠️ If any server-side code needs `Get-UserHives`, it must be **re-declared inside** `$script:SCAN_SCRIPT` / `$script:REMEDIATE_SCRIPT`. A parent-only helper referenced from a runspace silently resolves to nothing |
| **`Read-JsonBody` for POST bodies** | n/a unless a new server route is added |

---

## 6. Rollout — 9 stages, with the evidence that proves each

### 6.0 This box's profile inventory — the binding constraint on testing

```
=== timing: full Get-UserHives-shaped enumeration ===
  enumerated 1 human profile(s) in 57ms
    S-1-5-21-2934201606-2785436122-4267783230-1001 | WIN11\user | C:\Users\user | mounted=True
```

**This development box has exactly ONE human profile.** Three service profiles
(`S-1-5-18/19/20`), no `.bak` entries, no `defaultuser0`, no roaming or UNC profiles.
`UsrClass.dat` present. The `ZeroBreach_TEST_DELETEME` Run-key tripwire is currently present in that
profile (visible in the probe: `Run values: Steam,Overwolf,Discord,Mozilla-Firefox-...,ZeroBreach_TEST_DELETEME`).

**Consequence: P1 cannot be meaningfully validated here.** Every multi-profile behaviour — flood
control, ID collision, the `reg load` path, `Close-UserHives`, per-profile budget division,
cross-user attribution — is untestable on a one-profile box. A green run here proves only that
nothing regressed for the current user.

**A second local profile must be created before P1 can be signed off.** Windows Sandbox is **not** a
substitute: it has a single profile too.

### 6.1 The nine stages

| # | Work | Evidence that proves it correct |
|---|---|---|
| **0** | **Prepare the test box.** Create local account `zbtest2`, log on once (this materialises the profile and `UsrClass.dat`), log off. Plant a Run-key tripwire **in zbtest2's hive** and file tripwires in **zbtest2's** Temp/Downloads/Outlook-cache — mirroring the standard `ZeroBreach_TEST_DELETEME` pattern but under `C:\Users\zbtest2`. Capture a **pre-P1 DEEP baseline** | `ProfileList` shows 2 human SIDs; `Get-ChildItem Registry::HKEY_USERS` shows only 1 (zbtest2 logged off). **The pre-P1 DEEP run must MISS all four zbtest2 tripwires.** That miss is the proof the defect is real and the only run where a clean result is the expected result |
| **1** | **Helpers only, no phase changes.** Add `Get-UserHives`, `Close-UserHives`, `Get-UserPaths`, `Expand-UserPathTemplate`, the `UH_*` budget globals, the `USER_HIVE_CACHE` / `USER_PATH_CACHE` memos, and the `-LoadUserHives` param to `ZeroBreach-V23.ps1` | Standalone harness (ASCII + UTF-8 BOM, parse-checked on 5.1 **before** running — a BOM-less `.ps1` containing an em dash fails to parse and executes **zero** statements): enumerates 2 profiles; correctly classifies mounted vs not; filters `.bak` / service / `defaultuser0`; translates both SIDs. Parse-clean on 5.1 **and** 7. **A full DEEP run with zero call-site changes must produce a byte-identical finding set to the step-0 baseline** |
| **2** | **`reg load` + `Close-UserHives` leak-proofing**, exercised via `-LoadUserHives` against zbtest2 | `reg unload` returns exit 0. `Get-ChildItem Registry::HKEY_USERS` shows **no `ZB_UH_*` residue** after the engine exits. `C:\Users\zbtest2\NTUSER.DAT` is not locked — **log zbtest2 back on and confirm they get their real profile, not a temporary one.** Then deliberately break it (hold a `Get-ChildItem` result in a variable) and confirm honesty finding (d) fires with HIGH + `Info` |
| **3** | **Info/POSSIBLE-only migrations.** R9 (49.5), R13 (68.5 RunMRU), R17 (84), R18 (85), F1 (7, aggregated), F28 (100), F29 (100.5), plus the `%VAR%` → `{TOKEN}` fix for `dpapi_theft_paths_raw` and `cloud_token_paths_raw` | Plant a ClickFix-shaped RunMRU value in zbtest2's hive; DEEP must report it **naming zbtest2**. Phase 44.5's DPAPI `Write-Log` lines and Phase 100.5's `TOKENSTORES_PRESENT` finding now actually fire — they never have. **Auto-destructive count must not move at all** |
| **4** | **Data-side conversion** (§4.3): the 8 registry keys + 5 `*_raw` path keys; remove the 5 eager `ExpandString` loader lines; add the legacy `HKCU:\` strip guard | `data/detection_signatures.json` still parses (`tools/Build-Release.ps1` JSON gate). Phases 61, 48, 92, 21.5, 68.5, 67, 74.7, 74.5, 100, 44.5, 100.5 all still fire on the current user exactly as before |
| **5** | **Registry destructive cluster**, as ONE reviewable commit: R2 (20), R14 (70), R19 (92), R4 (24), R3 (21.5), R5 (25), R1 (5), R6 (35 incl. the FixParam rebuild + `netsh` split), R8/R10/R12 (48/61/67), R20 (94), R15 (74) | zbtest2's planted Run key appears **with `[WIN11\zbtest2]` in Target and Description**. The admin's identical-name key appears as a **separate finding with a distinct ID** — this proves the SID reached `Get-StableId`'s input and Mechanism-1 collisions are fixed. **Re-grade auto-destructive per phase** |
| **6** | **End-to-end remediation proof** on an `HKU\<SID>` FixParam, plus the two `$script:REMEDIATE_SCRIPT` additions from §4.7/§4.8 | `POST /api/remediate` for the zbtest2 Run-key finding, then verify **on the filesystem/registry**, in `reports/server_events_*.log` (`applied:1`), and in `reports/remediation_audit_*.jsonl`. **`{"status":"started"}` proves nothing** — the response is asynchronous. Two calls back-to-back return 400; sequence them ~30 s apart. Separately: log zbtest2 off, retry the same remediation, confirm it reports **`blocked`**, not `applied` |
| **7** | **Filesystem cluster.** Priority order: F4 (10), F22 (74.5), F16 (51), F11 (31), F2 (8), F13 (44.5) — then the long tail F3, F5–F10, F12, F14, F15, F17–F21, F23–F27, F30, F31 | zbtest2's file tripwires found and attributed. **Per-profile budget division verified: DEEP wall-clock must NOT scale linearly with profile count.** Compare the `PHASE N — ... took` lines against the step-0 baseline; investigate any phase more than 2× slower |
| **8** | **Flood-control verification** (§4.4) | With 2 profiles: machine-wide conditions (HKLM Run keys, `$env:WINDIR\Temp` hits, `$env:PUBLIC` hits) appear **exactly once** and are tagged `[MACHINE]`. **No `GROUPCAP_*` finding exists that did not exist pre-P1.** Phase 7 emits one aggregate INFO row, not 2 × 7 |
| **9** | **Honesty findings (§4.9), banner relabel (§4.6), baseline re-capture, docs** | With `-LoadUserHives` **off** and zbtest2 logged off, DEEP emits the "was NOT examined" INFO finding **naming zbtest2**. Banner reads `SCAN RUNNING AS: ... | PROFILES EXAMINED: n of m`. New healthy-box baseline captured and recorded. `CHANGELOG.md` entry written, including the finding-ID churn disclosure from §5.3 |

### 6.2 Regression gates — run at EVERY stage, not just at the end

1. **Parse gate on real `powershell.exe` 5.1 AND `pwsh` 7** for all 6 engine files
   (`ZeroBreach-V23.ps1`, `engine/Phases-1.ps1`, `engine/Phases-2.ps1`, `engine/Phases-3.ps1`,
   `engine/Summary.ps1`, `engine/FixMode.ps1`). **UTF-8 BOM intact on every one.**
2. **Header counts re-counted after every commit**: count `Show-PhaseHeader "PHASE` occurrences per
   module — Phases-1 = **70**, Phases-2 = **40**, Phases-3 = **30**. **QUICK must run exactly 30
   ungated headers.**
3. **`RECOVERED ERROR` count = 0** in `KrakenConsole_*.log`, and a **contiguous
   `PHASE N — ... took` sequence with no hard gap.** A gap immediately after a `RECOVERED ERROR`
   means a module trap was defeated and every remaining phase in that module was skipped.
4. **`HKEY_USERS` clean after every run.** Make this an **explicit scripted assertion**, not an
   eyeball check:
   ```powershell
   $leak = @(Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -like 'ZB_UH_*' })
   if ($leak.Count) { throw "HIVE LEAK: $($leak.PSChildName -join ',')" }
   ```
5. **QUICK still completes**, and within a sane time — six migrated sites run in QUICK. Time it.
6. **Any script driving a hidden-window run must redirect stdout AND stderr to a file**, with an
   unconditional line-flushed first log write, so an empty log is itself proof the body never ran.
7. **Windows Sandbox teardown**: verify no `vmmemWindowsSandbox` VM is alive before launching
   another (`Restart-Service vmcompute -Force` clears an orphan). Only one at a time.
8. Re-run the session-16 sandbox harnesses (parse gate → teardown → Stage F/G) as the regression
   suite.

### 6.3 The acceptance test — the one that actually proves P1 works

Everything above is mechanism. **This is the test that decides whether P1 is done:**

> Plant the standard tripwire set **in zbtest2's profile only**:
> - Run key `ZeroBreach_TEST_DELETEME` in zbtest2's hive, value pointing at `%TEMP%\...noexec.exe`
> - `ZeroBreach_TEST_DELETEME.bat` in `C:\Users\zbtest2\AppData\Local\Temp`
> - `ZeroBreach_TEST_DELETEME.cmd` in `C:\Users\zbtest2\Downloads`
> - `invoice_ZeroBreach_TEST_DELETEME.bat` in zbtest2's `...\INetCache\Content.Outlook\ZBTEST\`
>
> Log zbtest2 **off**. Run a DEEP scan as the admin.
>
> | Run | Expected |
> |---|---|
> | **Pre-P1** | **ZERO of the four are found.** Run this first — it is the proof the defect is real, and it is the only run where a clean result is correct |
> | **Post-P1, WITHOUT `-LoadUserHives`** | The **three filesystem** tripwires are found and attributed to `WIN11\zbtest2`. The **registry** one is not — and honesty finding (a) names zbtest2 explicitly as not examined |
> | **Post-P1, WITH `-LoadUserHives`** | **All four** found and attributed to zbtest2. `HKEY_USERS` clean afterwards. **zbtest2's next logon gives their real profile, not a temporary one** |
>
> Cleanup afterwards: remove all four tripwires, delete the `zbtest2` profile only if the test box is
> disposable — otherwise keep it, because every future P1-adjacent change needs it.

---

## 7. Open decisions for the operator

| # | Decision | Recommendation |
|---|---|---|
| **7.1** | **`reg load` gating** — is mounting/unmounting a hive compatible with "audit-only during scanning"? | **Firm: OFF by default, `-LoadUserHives` opt-in, never in STEALTH, with a named honesty finding for every profile skipped.** Full reasoning in §2.6. The deciding evidence is that an unrecoverable hive leak was **reproduced** (§2.4c), and that the plan already declined VSS/Amcache on exactly this ground |
| **7.2** | **R7 — Phase 39 `Cert:\CurrentUser\Root`** | **Defer.** Per-user coverage needs raw cert-blob parsing out of each hive for an `Info`-only payoff. In the meantime, change the finding text to say explicitly that **only the scan-context user's personal root store was examined** |
| **7.3** | **R11 / R16 — hardening writes (Phase 65, Phase 74.7)** | **Split.** Migrate the audit/inventory half; leave the write half single-user, but make the description state *which* user it applies to. Offer "apply to all profiles" only on request (§5.5) |
| **7.4** | **F1 — Phase 7 browser-cache inventory** | **Collapse to one aggregate INFO finding.** 8 profiles × 7 browsers = 56 rows of pure inventory otherwise. Confirm this is acceptable |
| **7.5** | **Baseline re-capture** | P1 changes finding IDs at ~20 sites. **There is no correct shim** (§5.3). Confirm the operator accepts a one-time re-baseline |
| **7.6** | **Test environment** | This box has **one** human profile (§6.0). **A second profile must be created before P1 can be signed off.** Nothing in the multi-profile behaviour is verifiable otherwise, and Windows Sandbox does not help |
| **7.7** | **Sequencing vs the rest of the plan** | P1's scope is ~5× the plan's estimate. Recommend it becomes its own workstream rather than a "prerequisite bug fix". It genuinely blocks A12 (UserAssist/MUICache — the plan already notes "Inherits P1") and materially improves A9, A13, A14. It does **not** block P7/P8 (already shipped), A1, A2, A3, A4–A8 |

---

## Appendix A — probe methodology and full outputs

All probes ran on this box: real `powershell.exe` **5.1.26100.8875**, elevated (`IsAdmin: True`),
user `WIN11\user`, Windows 11 Pro 10.0.26200. Scripts were written **ASCII + UTF-8 BOM** into the
scratchpad (never into the repository) and parse-checked before execution, per the harness rules.

Probe scripts, all in
`C:\Users\user\AppData\Local\Temp\claude\C--Users-user-project-zerobreach-main\ea66253b-5a9d-425f-8ddc-fc7874cf5509\scratchpad\`:

| Script | Establishes |
|---|---|
| `zbp1-unc.ps1` | `Test-Path` behaviour and latency on unreachable UNC (§5.4) |
| `zbp1-regload.ps1` | Locked live hive; the first, leaking unload failure (§2.4a, §2.4c) |
| `zbp1-regload2.ps1` | Cases A–D: no-read, `Get-ItemProperty`-only, .NET dispose, child-process unload |
| `zbp1-regload3.ps1` | Cases F–I: single-key `Get-Item`, aggressive release, gc-only, strict dispose |
| `zbp1-regload4.ps1` | Cases K–M: live-reference-defeats-gc, string projection, timing |
| `zbp1-enum.ps1` | ProfileList, SID translation, HKEY_USERS classification, `Volatile Environment`, `User Shell Folders`, `Registry::` wildcard support, `_Classes` equivalence |
| `zbp1-classes.ps1` | NTUSER.DAT vs UsrClass.dat classes divergence; enumeration timing |

### A.1 `Test-Path` on unreachable UNC

```
PROBE START unc
--- LITERAL: \\10.255.255.1\share\prof
    returned [False] in 42.2s
--- GLOB   : \\10.255.255.1\share\prof
    returned [False] in 0s
--- LITERAL: \\zbnosuchhost99\share\prof
    returned [False] in 5.5s
--- GLOB   : \\zbnosuchhost99\share\prof
    returned [False] in 0s
--- LITERAL: \\zbnosuchhost99\share
    returned [False] in 0s
--- GLOB   : \\zbnosuchhost99\share
    returned [False] in 0s
--- LITERAL: \\zbnosuchhost99
    returned [False] in 0s
--- GLOB   : \\zbnosuchhost99
    returned [False] in 0s
--- LITERAL: \\10.255.255.1\share\*
    returned [False] in 0s
--- GLOB   : \\10.255.255.1\share\*
    returned [False] in 0s
--- LITERAL: \\zbnosuchhost99\share\*
    returned [False] in 0s
--- GLOB   : \\zbnosuchhost99\share\*
    returned [False] in 0s
PROBE END unc
```

### A.2 `reg load` / `reg unload` — the leak reproduction

```
PROBE START regload
=== 1. can we reg load a LOGGED-ON user NTUSER.DAT? ===
    exists: True
    reg load exit=1 out=ERROR: The process cannot access the file because it is being used by
                          another process. | System.Management.Automation.RemoteException
=== 2. copy Default NTUSER.DAT and load the COPY ===
    copy ok
    reg load exit=0 in 0.05s out=The operation completed successfully.
    --- 2a. read via provider (Get-ChildItem) then unload WITHOUT gc ---
    top-level subkeys: 10 -> AppEvents,Console,Control Panel,Environment,EUDC,Keyboard Layout,
                             Microsoft,Network,Software,System
    Run key readable: True
      USF AppData = C:\Users\user\AppData\Roaming
      USF Cache = C:\Users\user\AppData\Local\Microsoft\Windows\INetCache
      USF Cookies = C:\Users\user\AppData\Local\Microsoft\Windows\INetCookies
      USF Desktop = C:\Users\user\Desktop
      USF Favorites = C:\Users\user\Favorites
      USF History = C:\Users\user\AppData\Local\Microsoft\Windows\History
      USF Local AppData = C:\Users\user\AppData\Local
      USF My Music = C:\Users\user\Music
      USF My Pictures = C:\Users\user\Pictures
      USF My Video = C:\Users\user\Videos
      USF NetHood = C:\Users\user\AppData\Roaming\Microsoft\Windows\Network Shortcuts
      USF Personal = C:\Users\user\Documents
      USF PrintHood = C:\Users\user\AppData\Roaming\Microsoft\Windows\Printer Shortcuts
      USF Programs = C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs
      USF Recent = C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent
      USF SendTo = C:\Users\user\AppData\Roaming\Microsoft\Windows\SendTo
      USF Start Menu = C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu
      USF Startup = C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
      USF Templates = C:\Users\user\AppData\Roaming\Microsoft\Windows\Templates
      USF {374DE290-123F-4565-9164-39C4925E467B} = C:\Users\user\Downloads
      SF  !Do not use this registry key = Use the SHGetFolderPath or SHGetKnownFolderPath function instead
    --- 2b. unload attempt #1 (no gc, handles possibly open) ---
    unload exit=1 out=ERROR: Access is denied. System.Management.Automation.RemoteException
    --- 2c. [gc]::Collect + WaitForPendingFinalizers, retry ---
    unload-after-gc exit=1 out=ERROR: Access is denied. System.Management.Automation.RemoteException
=== 3. does the load survive / leak? ===
    HKU children now: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-21-2934201606-2785436122-4267783230-1001,
                      S-1-5-21-2934201606-2785436122-4267783230-1001_Classes,ZBP1_TEST,S-1-5-18
    leftover: zbp1_ntuser_copy.dat
PROBE END regload
```

From a fresh process:
```
fresh-process unload exit=0 out=The operation completed successfully.
.DEFAULT,S-1-5-19,S-1-5-20,S-1-5-21-2934201606-2785436122-4267783230-1001,
S-1-5-21-2934201606-2785436122-4267783230-1001_Classes,S-1-5-18
```

### A.3 Handle-lifetime isolation (cases A–D)

```
PROBE START regload2
=== A. load, NO reads at all, unload ===
    exit=0 The operation completed successfully.
=== B. load, Get-ItemProperty ONLY (no Get-ChildItem), gc, unload ===
    read ok: True
    unload no-gc : exit=0 The operation completed successfully.
    unload post-gc: exit=1 ERROR: The parameter is incorrect.        (already unloaded)
=== C. load, .NET RegistryKey OpenSubKey + explicit Close/Dispose, unload ===
    values: OneDriveSetup
    USF AppData raw: %USERPROFILE%\AppData\Roaming
    subkeynames count: 10
    unload no-gc  : exit=1 ERROR: Access is denied.     (one OpenSubKey was leaked on purpose)
    unload post-gc: exit=0 The operation completed successfully.
=== D. load, provider read, then unload via a CHILD powershell process ===
    in-proc unload : exit=1 ERROR: Access is denied.
    in-proc retry  : exit=1
    child-proc unload exit=1
=== E. leftovers ===
    HKU: ...,ZBP1_D,S-1-5-18
PROBE END regload2
```
(Case D never invoked gc — see A.4 case K/K′ for the corrected experiment.)

### A.4 Handle release — cases F–M (the decisive results)

```
PROBE START regload3
    HKU after cleanup: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-21-...-1001,
                       S-1-5-21-...-1001_Classes,S-1-5-18
=== F. Get-Item (single key, no enumeration) ===
    got: True
    unload      : exit=1 ERROR: Access is denied.
    unload +gc  : exit=0 The operation completed successfully.
=== G. Get-ChildItem, aggressive release attempts ===
    kids: 10
    unload after Close+Dispose+3xgc : exit=0 The operation completed successfully.
=== H. Get-ChildItem WITHOUT closing, gc only ===
    unload gc-only : exit=0 The operation completed successfully.
=== I. .NET GetSubKeyNames with strict Dispose ===
    subkeys: 10
    unload strict-dispose : exit=0 The operation completed successfully.
=== J. leftovers ===
    HKU: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-21-...-1001,S-1-5-21-...-1001_Classes,S-1-5-18
PROBE END regload3
```

```
PROBE START regload4 - does a LIVE variable reference defeat gc?
=== K. keep $zbKids alive, gc, unload ===
    kids held in variable: 10
    unload WITH live ref + gc : exit=1 ERROR: Access is denied.
    unload AFTER Remove-Variable + gc : exit=0 The operation completed successfully.
=== L. project only the strings we need (no RegistryKey escapes the pipeline) ===
    names held (strings only): 10
    unload : exit=0 The operation completed successfully.
=== M. how long does reg load + a realistic read + unload take? ===
    read+unload elapsed 35ms ; exit=0 The operation completed successfully.
    HKU: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-21-...-1001,S-1-5-21-...-1001_Classes,S-1-5-18
PROBE END regload4
```

### A.5 Profile enumeration, shell folders, classes hive

```
PROBE START enum
=== raw ProfileList entries (incl .bak) ===
  SID=S-1-5-18  State=0 Flags=12  Path=C:\WINDOWS\system32\config\systemprofile
  SID=S-1-5-19  State=0 Flags=0  Path=C:\WINDOWS\ServiceProfiles\LocalService
  SID=S-1-5-20  State=0 Flags=0  Path=C:\WINDOWS\ServiceProfiles\NetworkService
  SID=S-1-5-21-2934201606-2785436122-4267783230-1001  State=0 Flags=0  Path=C:\Users\user
=== SID -> account name translation ===
  S-1-5-18 -> NT AUTHORITY\SYSTEM
  S-1-5-19 -> NT AUTHORITY\LOCAL SERVICE
  S-1-5-20 -> NT AUTHORITY\NETWORK SERVICE
  S-1-5-21-2934201606-2785436122-4267783230-1001 -> WIN11\user
=== HKEY_USERS mounted, classified ===
  .DEFAULT  [DEFAULT-ALIAS]
  S-1-5-19  [SERVICE]
  S-1-5-20  [SERVICE]
  S-1-5-21-2934201606-2785436122-4267783230-1001  [HUMAN-CANDIDATE]
  S-1-5-21-2934201606-2785436122-4267783230-1001_Classes  [CLASSES]
  S-1-5-18  [SERVICE]
=== reads through Registry:: on a live mounted hive ===
  Run values: Steam,Overwolf,Discord,Mozilla-Firefox-308046B0AF4A39CB,ZeroBreach_TEST_DELETEME
  elapsed 62ms
=== WILDCARD provider path under Registry:: (Phase 74 shape) ===
  wildcard match count: 0
  HKCU equivalent count: 0
=== Classes hive: HKU\<SID>_Classes vs HKU\<SID>\Software\Classes ===
  _Classes\CLSID count            : 6
  <SID>\Software\Classes\CLSID cnt: 6
  HKCU:\SOFTWARE\Classes\CLSID cnt: 6
=== UsrClass.dat location on disk ===
  C:\Users\user\AppData\Local\Microsoft\Windows\UsrClass.dat exists=True
=== Volatile Environment (per-user env from a mounted hive) ===
    LOGONSERVER = \\WIN11
    USERDOMAIN = WIN11
    USERNAME = user
    USERPROFILE = C:\Users\user
    HOMEPATH = \Users\user
    HOMEDRIVE = C:
    APPDATA = C:\Users\user\AppData\Roaming
    LOCALAPPDATA = C:\Users\user\AppData\Local
    USERDOMAIN_ROAMINGPROFILE = WIN11
=== live user User Shell Folders (redirection source) ===
    AppData = C:\Users\user\AppData\Roaming
    Cache = C:\Users\user\AppData\Local\Microsoft\Windows\INetCache
    Cookies = C:\Users\user\AppData\Local\Microsoft\Windows\INetCookies
    Desktop = C:\Users\user\Desktop
    Favorites = C:\Users\user\Favorites
    History = C:\Users\user\AppData\Local\Microsoft\Windows\History
    Local AppData = C:\Users\user\AppData\Local
    My Music = C:\Users\user\Music
    My Pictures = C:\Users\user\Pictures
    My Video = C:\Users\user\Videos
    NetHood = C:\Users\user\AppData\Roaming\Microsoft\Windows\Network Shortcuts
    Personal = C:\Users\user\Documents
    PrintHood = C:\Users\user\AppData\Roaming\Microsoft\Windows\Printer Shortcuts
    Programs = C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs
    Recent = C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent
    SendTo = C:\Users\user\AppData\Roaming\Microsoft\Windows\SendTo
    Start Menu = C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu
    Startup = C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    Templates = C:\Users\user\AppData\Roaming\Microsoft\Windows\Templates
    {374DE290-123F-4565-9164-39C4925E467B} = C:\Users\user\Downloads
PROBE END enum
```

Notable: the `Registry::HKEY_USERS\<SID>\...\Office\*\*\Security` **wildcard provider path works
identically to the `HKCU:` form** (both returned 0 here because no Office is installed) — so R15's
wildcard shape migrates unchanged.

### A.6 NTUSER.DAT vs UsrClass.dat, and enumeration timing

```
PROBE START classes
  load NTUSER exit=0
  NTUSER.DAT has Software\Classes : True
  CLSID subkeys inside NTUSER hive: 1
  has Volatile Environment        : False
  unload exit=0 The operation completed successfully.
=== timing: full Get-UserHives-shaped enumeration ===
  enumerated 1 human profile(s) in 57ms
    S-1-5-21-2934201606-2785436122-4267783230-1001 | WIN11\user | C:\Users\user | mounted=True
PROBE END classes
```

### A.7 `ExpandString` on `%VAR%` — the dead-list proof

```
ExpandString on percent-form : [%APPDATA%\Microsoft\Protect]
ExpandString on dollar-form  : [C:\Users\user\AppData\Roaming\Microsoft\Protect]
Test-Path percent-form: False
Get-Item percent-form (non-literal): False
```

### A.8 Cleanup verification

Temporary hive copies were deleted and every test mount unloaded. Final state:

```
HKU now: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-21-2934201606-2785436122-4267783230-1001,
         S-1-5-21-2934201606-2785436122-4267783230-1001_Classes,S-1-5-18
```

— byte-identical to the pre-probe state.

**No repository file was created, modified or deleted during this audit, and no `git` command was
run.**

---

## Appendix B — quick grep index for the implementer

```
# every HKCU registry site
rg -n "HKCU|HKEY_CURRENT_USER" engine/*.ps1 ZeroBreach-V23.ps1

# every per-user env site
rg -n '\$env:(APPDATA|LOCALAPPDATA|USERPROFILE|TEMP|TMP|HOMEPATH|HOMEDRIVE|USERNAME)' engine/*.ps1 ZeroBreach-V23.ps1

# the eager-expansion loader lines to delete
rg -n "InvokeCommand.ExpandString" ZeroBreach-V23.ps1

# the data keys to convert
rg -n "rat_reg_paths|keylogger_reg_paths|uac_bypass_regs|com_typelib_hijack_roots|runmru_reg_path|adware_pup_regs|proactive_persistence_regs|proactive_office_keys|rat_config_paths_raw|email_scan_paths_raw|infostealer_target_paths_raw|dpapi_theft_paths_raw|cloud_token_paths_raw" data/detection_signatures.json

# confirm no HKEY_USERS work exists yet (must be zero before you start)
rg -n "HKEY_USERS|ProfileList|reg load|reg unload|HKU:" --glob '*.ps1' .

# header counts after every commit
rg -c 'Show-PhaseHeader "PHASE' engine/Phases-1.ps1 engine/Phases-2.ps1 engine/Phases-3.ps1
#   expected: 70 / 40 / 30

# hive-leak assertion after every run
powershell -NoProfile -Command "@(Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -like 'ZB_UH_*' }).Count"
#   expected: 0
```

**Never edit `native-app/src-tauri/target/{debug,release}/engine-root/`** — those are build copies of
`ZeroBreach-*.ps1`, `engine/`, `gui/` and `data/`. Repo-wide greps will hit them. Always check the
path before editing.

---

*End of spec.*


