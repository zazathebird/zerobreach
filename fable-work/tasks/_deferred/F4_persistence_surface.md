# F4 — Phase 157: the remaining persistence surface

**Priority 4.** `ADVERSARY_ANALYSIS.md` §B6. Size: M.

The autostart coverage is genuinely good — and these are still missing. Each is real, in the wild,
and each is a handful of lines. Treat this as one phase with many small independent checks, each
in its own `try`, so one failure cannot cost the others.

| Mechanism | Where | Note |
|---|---|---|
| **Hidden scheduled task via SD deletion** | — | **Already done** in phase 134. Do not duplicate. |
| `COR_PROFILER` .NET profiler hijack | `HKCU/HKLM\Environment`, `\SOFTWARE\Microsoft\.NETFramework` | Loads an arbitrary DLL into **every** .NET process. Phase 0 checks the engine's own env; this is the machine-wide persistence. APM agents (AppDynamics, Dynatrace, New Relic) set it legitimately. |
| Active Setup `StubPath` | `SOFTWARE\Microsoft\Active Setup\Installed Components\*` | Runs once per user at first logon, survives profile reset. |
| `SilentProcessExit` `MonitorProcess` | `...\Windows NT\CurrentVersion\SilentProcessExit\*` | Persistence **and** an lsass-dumping primitive. |
| WER `ReflectDebugger` / `Hangs\Debugger` | `...\Windows Error Reporting\` | Sibling of IFEO, far less watched. |
| Time Providers | `...\Services\W32Time\TimeProviders\*` | DLL loaded as SYSTEM inside svchost. |
| Print Monitors / Port Monitors | `SYSTEM\CurrentControlSet\Control\Print\Monitors\*` | SYSTEM, spooler-loaded. Distinct from PrintNightmare (phase 96). |
| Netsh helper DLLs | `SOFTWARE\Microsoft\Netsh` | Loaded whenever `netsh` runs. |
| Winsock LSP | `...\WinSock2\Parameters\Protocol_Catalog9\*` | Injects into every networked process. |
| `ShellServiceObjectDelayLoad`, `SharedTaskScheduler` | `...\Explorer\` | Explorer-loaded. |
| `SCRNSAVE.EXE` | `HKCU\Control Panel\Desktop` | Ancient, still works, rarely checked. |
| `AutodialDLL` | `SYSTEM\CurrentControlSet\Services\WinSock2\Parameters` | Loaded by anything using WinINet. |
| Terminal Services `InitialProgram` | `...\Terminal Server\WinStations\RDP-Tcp` | Runs on every RDP logon. |
| Service **trigger** start | `...\Services\<name>\TriggerInfo` | A service that looks disabled but starts on an event. |
| `AppDomainManager` via `.config` sidecar | next to any managed `.exe` | Phase 95 covers the registry route only. |
| `AppExecutionAlias` hijack | `...\CurrentVersion\App Paths`, WindowsApps aliases | Typing `python` runs the attacker's binary. |
| `.settingcontent-ms` / `.library-ms` / `.url` / `.appref-ms` | user dirs | Dropper file types with `DeepLink`/execution payloads. |

## Rules specific to this task

- **Everything is `FixAction "Info"`.** Several of these live under
  `SYSTEM\CurrentControlSet\Control`, which the remediation guard **refuses**. A CRITICAL finding
  with a destructive fix on a guard-protected target is auto-selected in the GUI and then reported
  `blocked` on **every machine** — that is the exact anti-pattern audit M1 closed, and there is a
  test (`Test-M-Tier.ps1`) that will fail your build for it. Put the manual command in the
  description instead.
- Read `HKLM\SOFTWARE` paths through **`Get-RegVal64` / `Get-RegNames64` / `Get-RegSubKeys64`**
  (already in the loader). The normal provider is WOW64-redirected and a 32-bit engine reads the
  wrong hive entirely.
- For every DLL-loading mechanism, resolve the DLL and check it with `Get-SignatureVerdict`. An
  unsigned DLL in a user-writable path is the finding; the mechanism existing is often normal.

## Deliverables

Phase 157, signature keys with per-mechanism benign allowlists, tests that each mechanism's
detection fires against a synthetic registry fixture (see `reference/ExtendedSmoke.Harness.ps1`
— it already stubs an in-memory registry and is the only test in the repo that executes engine
code).
