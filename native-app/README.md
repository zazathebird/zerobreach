# ZeroBreach Native Shell (Milestone 1)

A real native Windows `.exe` wrapping the existing, unmodified PowerShell server + `gui/` —
double-click, no browser tab, no visible console window. This is **not** the Three.js 3D GUI
redesign (that's the actual long-term goal, tracked separately) — it's the smallest change that
gets a genuine native app in front of the user: same server, same HTML/JS/CSS GUI, running inside
a Tauri window instead of a browser tab.

## How it works

0. Before any window is built, `main()` writes `dlog("main() started")` and then runs
   `fatal_if_webview2_missing()` — a WebView2 preflight (`tauri::webview_version()`, falling back to
   `RegGetValueW` probes of the WebView2 client GUID under HKLM / HKLM\WOW6432Node / HKCU). If the
   runtime is absent it shows a `MessageBoxW` and terminates with **exit code 3**. This exists
   because the app previously hung *completely silently* on a WebView2-less machine — no window, no
   dialog, no debug log, no exit — as WebView2's own loader waited forever on an install prompt that
   nothing was there to click. The preflight is skipped under `ZB_UNATTENDED` / `--unattended` /
   `--no-ui`.
1. `src-tauri/src/main.rs` spawns `ZeroBreach-Server.ps1` as a hidden child process
   (`-WindowStyle Hidden`, **not** the Win32 `CREATE_NO_WINDOW` creation flag — the legacy
   PowerShell console host needs an allocated console to function at all, just not a visible one).
2. It picks a free TCP port itself and passes `-Port <n> -NoBrowser` (both already-existing,
   already-supported server params — the server itself is untouched).
3. Polls the port with a raw TCP connect until the HTTP listener comes up (45s deadline), then
   opens a second window — label **`main`** — pointed at `http://localhost:<port>/` (must be
   `localhost`, not `127.0.0.1` — the server's `HttpListener` only registers the `localhost` prefix
   and rejects any other Host header with `400 Bad Request - Invalid Hostname`) and closes the boot
   splash (label **`boot`**, declared in `tauri.conf.json`).
4. Kills the child process on window-close / app-exit — **and, independently, at the OS level**: the
   child is assigned to a Windows **Job Object** with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so a
   force-kill (Task Manager "End Task"), a panic or a crash cannot orphan a still-listening,
   admin-elevated `ZeroBreach-Server.ps1`. The cooperative hooks alone did not cover that; this was
   verified against a real `Stop-Process -Force`. Note the close hook is wired to the `main` window
   only — closing the boot splash by itself does not kill the child.
5. Engine-root resolution is `app.path().resource_dir()` in release; the
   `CARGO_MANIFEST_DIR/../..` checkout fallback is `#[cfg(debug_assertions)]`-gated, so a release
   binary never probes the build machine's paths.

The `.exe` itself requests admin elevation via its manifest
(`src-tauri/windows/app.manifest`, `requireAdministrator`) — every existing ZeroBreach entry point
already self-elevates via `Start-Process -Verb RunAs`, and if this shell launched unelevated, the
PS server child would immediately re-launch *itself* elevated, orphaning the Rust side's `Child`
handle. Elevating the shell means the server's own `IsInRole` check passes immediately and it
never re-launches.

## Build / run

Build prerequisites: Node.js + npm, Rust (`rustup`), MSVC Build Tools (`Desktop development with C++`
workload — installed via `winget install Microsoft.VisualStudio.2022.BuildTools --override
"--add Microsoft.VisualStudio.Workload.VCTools"`).

**Runtime prerequisite: the Microsoft Edge WebView2 Runtime.** The NSIS installer handles it
(`webviewInstallMode: downloadBootstrapper`), but a bare copy of `zerobreach-native.exe` does not —
without WebView2 the app exits 3 with a message box (see step 0 above).

```powershell
cd native-app
npm install
npx tauri build      # -> src-tauri/target/release/zerobreach-native.exe
                      # -> src-tauri/target/release/bundle/nsis/ZeroBreach_<ver>_x64-setup.exe
```

`npx tauri dev` also works for iterating on the frontend (`index.html`/`src/main.js`) — it
launches the same Rust shell against a Vite dev server instead of the built `dist/`.

## Debugging

The release build has no console (`windows_subsystem = "windows"`), so `main.rs` writes a plain
timestamped log to `%TEMP%\zerobreach_native_debug.log` at every meaningful step (engine root
resolution, spawn result, port polling, window creation) — check that first if the app doesn't
seem to be doing anything. `cargo build` (debug profile, from `src-tauri/`) produces a build with
a real console for interactive debugging.

## Known gotchas hit building this (kept here so they don't get re-discovered the hard way)

- **`app.path().resource_dir()` returns a `\\?\`-prefixed extended-length path on Windows.**
  `ZeroBreach-Server.ps1` was never written expecting that prefix in `$PSScriptRoot`-derived
  paths — every route 500'd (`GET /` returned `{"error":"internal server error"}`) until the
  resource dir was run through `dunce::simplified()` before use.
- **A custom Windows app manifest *replaces* Tauri's generated one wholesale, it doesn't merge.**
  The `requireAdministrator` manifest needs its own `Microsoft.Windows.Common-Controls` v6
  dependency block too, or the built `.exe` fails to even start with a native
  `TaskDialogIndirect` "Entry Point Not Found" dialog (ComCtl32 v5, the default when no manifest
  declares v6, doesn't export that function — `wry`/`tao` need it).
- **`CREATE_NO_WINDOW` (the Win32 process-creation flag) is the wrong tool for hiding the PS
  server's console.** It doesn't allocate a console for the child *at all*, which breaks the
  legacy `powershell.exe` ConsoleHost outright. Use `-WindowStyle Hidden` instead — a real
  (invisible) console gets allocated and `Write-Host`/`[Console]::` calls keep working.
- **A missing WebView2 Runtime produced a total silent hang, not an error.** No window, no dialog,
  no `%TEMP%\zerobreach_native_debug.log` (the first `dlog()` lived in the `.setup()` thread, which
  was never reached), no Application-log event. Hence the rule now baked into `main()`: log before
  the framework starts, and never rely on an OS prompt in an unattended/kiosk/RDP context. Reproduced
  live in a fresh Windows Sandbox image, which ships without WebView2.
- **`src-tauri/target/{debug,release}/engine-root/` contains full COPIES of `ZeroBreach-*.ps1`,
  `engine/`, `gui/` and `data/`** (staged by `bundle.resources`). They are build output, they are
  gitignored, and repo-wide greps hit them — always check the path before editing. Editing a copy
  changes nothing; running a stale copy debugs the wrong code.

## Not done here (deliberately)

The Three.js 3D GUI, real branding (the current icon is a placeholder cyan-diamond generated via
`System.Drawing`, not final art), and a decision on whether this should replace or coexist with
`Launch-GUI.bat` as the documented primary entry point are all separate follow-up work.

## Status / unverified (as of 2026-07-26)

- The **portable `.exe`** has been run and screenshot-verified rendering the real GUI, and the
  Job-Object cleanup was verified against an actual force-kill.
- The **NSIS installer** (`bundle/nsis/ZeroBreach_0.1.0_x64-setup.exe`) builds, but has **never been
  installed or tested**.
- The **WebView2 preflight** is built and staged but had not been confirmed end-to-end in a
  WebView2-less sandbox at the time of writing (the "Stage D" harness for it exists, unrun).
- `tools/Build-Release.ps1` (the portable-zip builder) has **no `native-app` awareness** — it
  packages the `Launch-GUI.bat` distribution only.
- Report output paths were written for a dev checkout; verify at least once that `reports/` lands
  somewhere sane when running from an installed/bundled resource dir.
