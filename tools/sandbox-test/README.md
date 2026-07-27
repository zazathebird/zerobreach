# Sandbox malware / native-shell test harnesses

Two reusable, disposable-VM test harnesses that were previously built and run only inside a
Claude Code scratchpad temp directory (2026-07-26) — nearly lost, then recovered and rewritten
here 2026-07-27 so results and the harnesses themselves live in the repo. See `CHANGELOG.md`
("Recovered evidence" and the Stage-D3/malware-detection re-validation entries) for the full
narrative and numbers from the runs that produced this folder.

## What's here

- `harness-malware-detection.ps1` — guest-side script. Detonates 5 real, correctly-decrypted
  theZoo malware families (KRBanker, VolatileCedar.Explosion, Green_Caterpillar.1575.A,
  W97M.Class.AU, X97M.Sugar.A) plus a masquerade-rename test (`.pdf`), an extension-less hash-IOC
  test, and EICAR, then runs a DEEP scan and asserts: masquerading-PE findings, macro-document
  findings, known-hash IOC findings, YARA-lite hits, a sane (non-flooded) auto-destructive count,
  0 `RECOVERED ERROR`s, and (since 2026-07-27) that P1's multi-user hive coverage and Build Custom
  Scan's `-Phases` filter didn't interfere.
- `harness-webview2-dialog.ps1` — guest-side script. Launches `zerobreach-native.exe` on a box
  with no WebView2 Runtime installed and proves the fatal-dialog fix end to end: debug log fires,
  the native `MessageBoxW` dialog is genuinely on screen (screenshot captured, not just a log
  line), and the process self-terminates with exit code 3 within its 120s deadline.
- `Invoke-SandboxTest.ps1` — host-side orchestrator. Stages the right payload, writes a `.wsb`
  pointing at `work/<stage>/{in,out}` (gitignored), checks for a stale `vmmemWindowsSandbox` and
  restarts `vmcompute` if needed, launches the sandbox, and polls for the harness's completion
  marker. Run it from an elevated PowerShell session with Windows Sandbox enabled:

  ```powershell
  .\Invoke-SandboxTest.ps1 -Stage WebView2Dialog
  .\Invoke-SandboxTest.ps1 -Stage MalwareDetection -TimeoutMinutes 90
  ```

  It does not interpret results — read `work\<stage>\out\*.log` afterward.

## Hard-won rules these encode (see CLAUDE.md for the full list)

- theZoo archives are password-protected (`infected`); `tar` cannot decrypt them and silently
  writes 0-byte files. Extraction uses `7za.exe -pinfected` (bootstrapped via `7zr.exe`, which
  handles only `.7z` — the zip-capable `7za.exe` ships inside `7zXXXX-extra.7z`), and the harness
  hard-fails if any sourced sample lands at 0 bytes.
- All malware download/extraction/detonation happens **inside** the sandbox, never on the host.
  Don't "optimize" this by pre-downloading samples to the host filesystem — a real Windows
  machine's own Defender can flag/quarantine them even zipped, and the whole point of the sandbox
  is disposability.
- Any `.ps1` here must stay plain ASCII (no em dashes/smart quotes/box-drawing) and be re-saved
  with a UTF-8 BOM after editing, then parse-checked on real `powershell.exe` 5.1 — a BOM-less
  file with non-ASCII content fails to parse with **zero output**, indistinguishable from a hang.
  After editing either harness `.ps1`, re-run:
  ```powershell
  $p = ".\harness-....ps1"
  [IO.File]::WriteAllText($p, (Get-Content $p -Raw), (New-Object Text.UTF8Encoding($true)))
  powershell.exe -NoProfile -Command "$e=$null; [System.Management.Automation.Language.Parser]::ParseFile('$p',[ref]$null,[ref]$e); if($e.Count){$e}else{'PARSE_OK'}"
  ```
- Windows Sandbox is single-instance and does not reap its VM when its processes are killed —
  `vmmemWindowsSandbox` can survive indefinitely and silently block the next launch. The
  orchestrator checks for this and restarts `vmcompute` if needed; always verify no sandbox VM is
  alive before launching another by hand too.
- `WebView2Dialog` needs a **freshly built** `zerobreach-native.exe` — a stale exe silently tests
  old code and produces a misleading "inconclusive" result (exactly what happened 2026-07-26: the
  tested build's debug-log wording didn't even match current `main.rs`, proving it predated the
  fix's hardening). `Invoke-SandboxTest.ps1` refuses to run against an exe older than `main.rs`
  unless you pass `-SkipBuild` explicitly.
- `work/` is gitignored (malware, multi-hundred-KB JSON reports, and screenshots don't belong in
  the repo) — commit only the harness/orchestrator scripts themselves.
