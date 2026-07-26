# ZeroBreach Native Shell (Milestone 1)

A real native Windows `.exe` wrapping the existing, unmodified PowerShell server + `gui/` —
double-click, no browser tab, no visible console window. This is **not** the Three.js 3D GUI
redesign (that's the actual long-term goal, tracked separately) — it's the smallest change that
gets a genuine native app in front of the user: same server, same HTML/JS/CSS GUI, running inside
a Tauri window instead of a browser tab.

## How it works

1. `src-tauri/src/main.rs` spawns `ZeroBreach-Server.ps1` as a hidden child process
   (`-WindowStyle Hidden`, **not** the Win32 `CREATE_NO_WINDOW` creation flag — the legacy
   PowerShell console host needs an allocated console to function at all, just not a visible one).
2. It picks a free TCP port itself and passes `-Port <n> -NoBrowser` (both already-existing,
   already-supported server params — the server itself is untouched).
3. Polls the port with a raw TCP connect until the HTTP listener comes up (45s deadline), then
   opens a second window pointed at `http://localhost:<port>/` (must be `localhost`, not
   `127.0.0.1` — the server's `HttpListener` only registers the `localhost` prefix and rejects
   any other Host header with `400 Bad Request - Invalid Hostname`) and closes the boot splash.
4. Kills the child process on window-close / app-exit.

The `.exe` itself requests admin elevation via its manifest
(`src-tauri/windows/app.manifest`, `requireAdministrator`) — every existing ZeroBreach entry point
already self-elevates via `Start-Process -Verb RunAs`, and if this shell launched unelevated, the
PS server child would immediately re-launch *itself* elevated, orphaning the Rust side's `Child`
handle. Elevating the shell means the server's own `IsInRole` check passes immediately and it
never re-launches.

## Build / run

Prerequisites: Node.js + npm, Rust (`rustup`), MSVC Build Tools (`Desktop development with C++`
workload — installed via `winget install Microsoft.VisualStudio.2022.BuildTools --override
"--add Microsoft.VisualStudio.Workload.VCTools"`).

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

## Not done here (deliberately)

The Three.js 3D GUI, real branding (the current icon is a placeholder cyan-diamond generated via
`System.Drawing`, not final art), and a decision on whether this should replace or coexist with
`Launch-GUI.bat` as the documented primary entry point are all separate follow-up work.
