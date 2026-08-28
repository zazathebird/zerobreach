# Scythe Test Lab — Build & Test Guide

**Purpose:** a physically isolated lab that exercises every feature of Scythe, and specifically
proves or kills the findings in `docs/_history/AUDIT_2026-08-18_INDEPENDENT.md` that static analysis could not
settle.

**One boundary, stated once so it's not a surprise later:** I'll design the lab, write the test
cases, and analyse whatever output you bring back. **I won't source or execute live malware
samples** — that part is yours. Everything in Tiers 0–2 below needs *no* malware at all and still
proves the large majority of the audit findings; Tier 3 is where live samples come in, and it's
yours to run.

The pleasant surprise: **most of what needs testing is provable with completely benign artifacts.**
The scheduled-task injection (C2) is proven by registering a task whose *name* contains an
apostrophe. No malware involved. Same for the protected-path bypass, the rollback file, the
false-all-clear bug, and the CSRF chain.

---

## 1. What the lab is for

| Tier | Needs malware? | Proves |
|---|---|---|
| **0 — Inert tripwires** | No | End-to-end scan → finding → remediate → PURGE, per `CLAUDE.md` |
| **1 — EICAR** | No (EICAR is not malware) | Defender interop, quarantine path, AMSI behaviour |
| **2 — Benign persistence mimicry** | No | C2 injection, H7 path bypass, H1 rollback, H2 false all-clear, H6 junction, H10 reboot-queue, C1 CSRF, C3 offline |
| **3 — Live samples** | Yes — your call, your sourcing | True-positive detection rates, real FP baseline, worm propagation |

Tier 2 is the highest value per unit of risk. Do it first. If Tier 2 finds five real bugs — and I
expect it to — you'll want them fixed before a live sample is anywhere near the lab.

---

## 2. Hardware & topology

### Minimum viable (Tier 0–2)
```
   [ VICTIM-1 ]───┐
                  ├──[ dumb switch ]     ← NO uplink cable. Not "disabled". Physically absent.
   [ OPERATOR ]───┘
```

### Full (adds Tier 3 + worm testing)
```
   [ VICTIM-1  Win10/11 ]───┐
   [ VICTIM-2  Win10/11 ]───┼──[ dumb switch, no uplink ]
   [ OPERATOR  (any OS)  ]──┘
```

**Rules that are not negotiable if you want the isolation to be real:**

1. **The switch has no uplink.** Not a disabled port, not a firewall rule — no cable in the WAN
   port, and ideally the router removed from the lab entirely. A dumb unmanaged switch is *better*
   than a router here: fewer ways to accidentally route.
2. **Wi-Fi off in BIOS/UEFI on every lab machine**, not just in Windows. Malware re-enabling a
   Windows-level radio toggle is a well-trodden path; firmware-disabled is not.
3. **No Bluetooth, no tethering, no USB Wi-Fi dongles** anywhere in the room during a Tier-3 run.
4. **Nothing that has ever touched the lab goes back to your main network.** Not the USB stick, not
   the switch, not the cables (cables are fine, honestly, but the stick absolutely is not).
5. **Static IPs, no DHCP server** — e.g. `10.99.0.10/24`, `.11`, `.20`. No DNS. If malware wants to
   resolve a C2 domain, it should fail, and you should be able to *see* it fail.
6. **The OPERATOR machine is also a victim.** Treat it as burned. Do not SSH into it from your
   real network, do not log into anything real on it.

### Identity hygiene
Your "Homer Simpson" instinct is exactly right, and worth doing properly:

- Local accounts only. **Never** a Microsoft account, never Entra/AD-joined to anything real.
- Fake everything: name, org, email, timezone if you like. No real client names anywhere — this
  matters because Scythe writes hostnames and usernames into `reports/`.
- **No credential reuse.** Not a variation of a real password. Assume anything typed on VICTIM-1
  is in an attacker's hands.
- No cloud sign-ins, no OneDrive, no browser profile sync. Scythe scans `AppData` and browser
  paths; you don't want real tokens there.

---

## 3. Imaging & rollback

- **Clonezilla** (or `dd` to an external disk) a full baseline image of each victim **before**
  anything is installed. Windows System Restore is not sufficient — you're testing a tool that
  *deletes shadow copies*.
- Keep the baseline image on a disk that is **only ever connected to a powered-off victim**, or to
  the operator machine, never to your real network.
- Re-image between Tier-3 samples. Not "clean up and continue" — re-image.
- Label images by hostname + date. You will lose track otherwise.

---

## 4. Software baseline on each victim

Install before imaging, so the baseline is representative:

- Windows 10 or 11, fully updated, **Defender left ON** (you're testing Defender interop).
- PowerShell 5.1 (built in) — **the engine must be tested on 5.1, not 7.** Several audit findings
  hinge on 5.1-specific behaviour.
- A handful of ordinary apps so the FP baseline is realistic: Chrome or Firefox, 7-Zip, Notepad++,
  VLC. Optionally an RMM agent if you can spare a trial — the `Test-VendorTrusted` path is untested.
- **Do NOT install the CDN-dependent assets by "just letting it reach the internet once."** The
  offline behaviour is a test case (C3), not an inconvenience.

---

## 5. Test matrix

Each test names the audit finding it settles. Record: what you did, what Scythe reported,
what actually happened on disk.

### Tier 0 — Inert tripwires (start here)

Use the script already in `CLAUDE.md` ("Remediation test tripwires"). It creates five benign
artifacts that trip five different phases with five different `FixAction`s.

| # | Test | Expected | Settles |
|---|---|---|---|
| 0.1 | Run the tripwire creation block, then a FULL scan (all time) | 5 findings, correct severities | Baseline pipeline |
| 0.2 | Findings → Remediation → type `PURGE` | `applied:4 skipped:1`, artifacts gone | Remediation path |
| 0.3 | Re-run scan | 0 tripwire findings | Idempotency |
| 0.4 | Check `reports/quarantine/` | `.quar` + `.quar.json` manifest present | Quarantine reversibility |
| 0.5 | Restore from the manifest's `RestoreNote` | File returns intact, hash matches | Rollback claim |

### Tier 1 — EICAR

EICAR is a standardised **non-malicious** test string, safe to use.

| # | Test | Expected | Settles |
|---|---|---|---|
| 1.1 | Drop `eicar.com` in `%TEMP%`, scan | Detected; Defender may grab it first | Defender interop |
| 1.2 | Add a Defender exclusion for that folder first, then scan | Phase 75 flags the **exclusion** as POSSIBLE | Exclusion detection |
| 1.3 | Remediate the exclusion finding | Exclusion removed, nothing else touched | C2 fix (Defender path) |

### Tier 2 — Benign persistence mimicry ★ highest value

> ## ⚠ THIS SECTION IS PRE-FIX. Read this before running any of it.
>
> **Every audit finding Tier 2 tells you to reproduce was fixed on 2026-08-18** and now has a
> regression test in `tools/tests/` wired into `Run-SecurityTests.ps1`. The "Expected:" lines
> below describe the **old, broken** behaviour. Run these cases as **regression verification on
> Windows** — the expected result is now the opposite of what each one says.
>
> | Case | Says | Now |
> |---|---|---|
> | 2.2 forward-slash path bypass | not caught by `Test-ProtectedTarget` | **blocked** — input normalised before every test (H7/H7b); `Test-H7-Guard.ps1`, `Test-GuardMirrorSync.ps1` |
> | 2.3 rollback `.reg` unusable | "Expected: it fails" | **succeeds** — snapshot is now a directory of valid exports plus a generated `Restore.cmd`; a real `Checkpoint-Computer` is attempted and reported |
> | 2.4 false all-clear | "GUI shows a *completed* scan with 0 findings… the most dangerous bug in the audit" | **fixed** — stderr via `ReadToEndAsync`, exit code judged, a failed run emits `scan_failed` and never `scan_complete`; `Test-H2-EngineExit.ps1` |
> | 2.5 junction traversal | "Fail: `canary.txt` is gone" | **fixed** — `DeleteFile` no longer passes `-Recurse` and refuses reparse points and directories (H6) |
> | 2.6 reboot-queue fallback throws | "the fallback throws… never queued" | **fixed** — raw `Get-ItemPropertyValue` removed (H10) |
> | 2.7 wildcard-CORS chain | "Do this before fixing C1" | **fixed** — per-launch token on every `/api/*`, Origin lockdown, `127.0.0.1` bind, all CORS headers removed; `Test-C1-Auth.ps1` |
> | 2.8 CDN / Google-Fonts dependency | radar chart and font fail offline | **fixed** — everything vendored under `gui/static/`, CSP pinned to `'self'` (C3). Expect a full offline render, zero non-local requests |
>
> **Run `powershell -NoProfile -File tools\tests\Run-SecurityTests.ps1` first.** It already covers
> all of the above on Linux; the lab's job is to confirm it on real Windows, not to rediscover it.
>
> **The real gap Tier 2 does not cover: phases 134-162.** They have never met the PS 5.1 parser, a
> live registry provider or a real process table. **153-156 need no malware at all** — they are
> registry/CIM reads — so they belong in Tier 0/2 and are the cheapest high-value lab work
> available. Expect an FP round on 136/139/141.


These create *artifacts that look like malware persistence* without any malicious code. This is
where the audit findings get settled.

**2.1 — C2 injection (the big one).** Register a scheduled task whose **name** contains an
apostrophe and a benign payload:

```powershell
$q = [char]39
$name = "SCYTHETEST${q};Write-Host 'INJECTION-FIRED';#"
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-nop -c exit'
$s = New-ScheduledTaskSettingsSet; $s.Enabled = $false
Register-ScheduledTask -TaskName $name -Action $a -Settings $s -Force
```
Scan → the task should be flagged (Phase 29 and/or 64) → remediate it.
**Pass:** the task is removed and `INJECTION-FIRED` never appears in the log.
**Fail (pre-fix behaviour):** `INJECTION-FIRED` appears — that is admin code execution.
*This test is the reason the fix went in. Run it before and after.*

**2.2 — H7 forward-slash guard bypass.** Confirmed on Linux against the real function: a path
written with forward slashes is **not** caught by `Test-ProtectedTarget`. Create a finding whose
`FixParam` is a forward-slash path under Windows (a registry Run value is the easiest injection
point, since malware controls that string) and confirm whether the guard blocks it.
**Pass:** blocked. **Fail:** allowed — the "hard block" is bypassable with a `/`.

**2.3 — H1 rollback snapshot.** Run the engine's interactive fix mode so a snapshot is produced,
then simply attempt the documented recovery: `regedit /S "reports\KrakenSnapshot_*.reg"`.
**Expected (per static analysis): it fails**, because the file starts with a banner line instead of
`Windows Registry Editor Version 5.00`. Also confirm no restore point was created — the banner
promises "registry/VSS" and no VSS code exists.

**2.4 — H2 false all-clear.** Simulate an engine that dies at load. Easiest: temporarily rename
`engine/Phases-1.ps1`, then start a scan from the GUI.
**Expected (per static analysis):** the GUI shows a *completed* scan with 0 findings and a clean
banner, because stderr is discarded and `ExitCode` is never read. **This is the most dangerous bug
in the audit** — verify it, because it means "clean" is unreliable.

**2.5 — H6 junction following.** Create a directory junction and point it at a folder with
throwaway files, flag it, and remediate with `DeleteFile`:
```powershell
mkdir C:\SCYTHETEST\real; "canary" | Out-File C:\SCYTHETEST\real\canary.txt
cmd /c mklink /J C:\SCYTHETEST\link C:\SCYTHETEST\real
```
**Pass:** only the junction is removed, `canary.txt` survives.
**Fail:** `canary.txt` is gone — `Remove-Item -Recurse` traversed the reparse point.

**2.6 — H10 reboot-queue.** On a machine where `PendingFileRenameOperations` does **not** exist
(check first: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'`), lock a
file (open it in an app) and remediate it.
**Expected:** the fallback throws, logs `-> ERROR:`, and the file is never queued.

**2.7 — C1 CSRF.** From the operator machine, with Scythe running on VICTIM-1, open a local
HTML file containing a cross-origin `fetch()` to `http://localhost:<port>/api/sysinfo` — run it in
the **victim's own browser** to model the real attack. If it returns JSON readable by the page, the
wildcard-CORS chain is confirmed. Then check whether `POST /api/remediate` is reachable the same way.
**Do this before fixing C1**, so you can see the difference after.

**2.8 — C3 offline degradation.** With no internet (which is the lab's normal state), load the GUI.
Watch for: how long the page takes to paint, whether the threat radar chart renders at all, and
whether the Orbitron display font falls back to monospace. All three are the CDN/Google-Fonts
dependency showing.

**2.9 — WMI persistence.** Create a benign `__EventFilter` + `__EventConsumer` pair and confirm
Phase 30 flags both and remediates cleanly. (These sites were already correctly escaped — this
verifies that, rather than hunting a bug.)

**2.10 — BCD.** `bcdedit /set testsigning on` → scan → expect a CRITICAL from Phase 40 → remediate
→ confirm it's turned back off. **Reboot into a known-good state afterwards.**

### Tier 3 — Live samples (your side)

Only after Tiers 0–2 pass and the criticals are fixed. Two things worth designing for:

- **FP baseline first.** Run a DEEP scan on a *clean* imaged victim and record every finding. That
  number is your false-positive floor, and it's the single most useful measurement for the Kaseya
  ticket problem. Anything the tool reports on a clean box is noise you'll see on every client.
- **Worm testing needs VICTIM-2.** Share a folder from VICTIM-1, map it on VICTIM-2, and verify
  Phase 66 walks shares without walking the whole drive (it excludes `C$`/`D$` admin shares by
  design — confirm that holds).

---

## 6. Instrumentation — capture this every run

- `reports/server_console_*.log` and `reports/server_events_*.log` (the full SSE stream).
- `reports/KrakenBaseline_*.json` — the rich findings with `FixAction`/`FixParam`. **This is the
  most valuable artifact for me**; it shows exactly what command the tool intended to run.
- Windows Event Log: Security 4688 (process creation) if you enable it, plus Defender's
  operational log.
- A before/after `dir /s /b` of any folder a test touched.
- For Tier 3: Sysmon with a standard config, and a `pcap` from the switch if you have a managed one
  with port mirroring (worth it — you'll see C2 attempts fail).

Bring back the `KrakenBaseline_*.json` plus the event log and I can tell you what the tool decided
and why, without needing the sample.

---

## 7. Teardown

1. Power off. Re-image from baseline. Do not "clean up."
2. The USB stick used for transfer stays in the lab, permanently. Buy a second one; they're £5.
3. If a Tier-3 sample ever touched a machine you later want back on your real network: full disk
   wipe and OS reinstall, not a re-image. Firmware-persistent malware is rare but this is the one
   place the paranoia is cheap.
4. Wipe `reports/` before the tool is copied anywhere — it contains hostnames, usernames, full
   paths, and possibly quarantined live samples in `reports/quarantine/`.

---

## 8. Suggested order

1. Build the lab, image the victims, verify no route out (`ping 8.8.8.8` must fail, `nslookup` must
   fail).
2. **Tier 0** — proves the pipeline works at all.
3. **Tier 2.4 (false all-clear)** and **2.1 (injection)** — the two findings that most change how
   much you can trust the tool.
4. Rest of Tier 2.
5. Fix whatever Tier 2 surfaces.
6. Clean-box DEEP scan for the FP baseline.
7. Tier 3.
