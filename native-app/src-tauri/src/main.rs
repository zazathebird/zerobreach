// ZeroBreach native shell — Milestone 1: a real native window wrapping the existing,
// already-proven PowerShell server + gui/ (not a rewrite). It spawns
// ZeroBreach-Server.ps1 as a child process, waits for its HTTP listener to come up,
// then opens a second window pointed at that local URL and closes the boot splash.
// The Three.js 3D GUI (the actual long-term goal) replaces gui/ in a later pass —
// this pass only has to prove the "double-click .exe, no browser, no console window"
// experience works end to end.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::io::Write as _;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};

struct ServerState {
    child: Mutex<Option<Child>>,
    status: Mutex<ServerStatus>,
}

#[derive(Clone, Serialize, Default)]
struct ServerStatus {
    ready: bool,
    url: Option<String>,
    error: Option<String>,
}

// Bundled builds get the server tree copied under the resource dir (tauri.conf.json's
// bundle.resources -> "engine-root/"). `cargo tauri dev` does not copy resources every
// run, so fall back to the real project root two levels up from this crate — native-app
// deliberately lives INSIDE the zerobreach-main checkout for exactly this reason.
fn find_engine_root(app: &AppHandle) -> Option<PathBuf> {
    if let Ok(res) = app.path().resource_dir() {
        // dunce::simplified strips the \\?\ extended-length-path prefix that resource_dir()
        // returns on Windows. ZeroBreach-Server.ps1 derives $PSScriptRoot/relative paths from
        // whatever literal path it was launched with — handed the \\?\-prefixed form, every
        // route 500'd (confirmed live: GET / returned {"error":"internal server error"}).
        let res = dunce::simplified(&res).to_path_buf();
        let candidate = res.join("engine-root").join("ZeroBreach-Server.ps1");
        if candidate.is_file() {
            return Some(res.join("engine-root"));
        }
    }
    let dev_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    if dev_root.join("ZeroBreach-Server.ps1").is_file() {
        return Some(dev_root);
    }
    None
}

fn pick_free_port() -> u16 {
    // Bind to port 0 to ask the OS for a free one, then drop the listener before the
    // PS server binds it. Small TOCTOU window (acceptable for a localhost-only dev
    // tool); ZeroBreach-Server.ps1 itself falls back to Get-FreePort if this one is
    // somehow already gone by the time it tries to listen.
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(51823)
}

fn port_is_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(250),
    )
    .is_ok()
}

fn set_status(app: &AppHandle, status: ServerStatus) {
    let state = app.state::<ServerState>();
    *state.status.lock().unwrap() = status.clone();
    if let Some(err) = &status.error {
        let _ = app.emit("zerobreach://server-error", err.clone());
    } else if status.ready {
        if let Some(url) = &status.url {
            let _ = app.emit("zerobreach://server-ready", url.clone());
        }
    }
}

fn emit_progress(app: &AppHandle, msg: &str) {
    dlog(msg);
    let _ = app.emit("zerobreach://server-status", msg);
}

// The release build has no console (windows_subsystem = "windows"), so this is the ONLY
// way to see what happened when something goes wrong outside a debugger — a plain
// append-only text file next to nothing fancy, always on, negligible cost.
fn dlog(msg: &str) {
    let path = std::env::temp_dir().join("zerobreach_native_debug.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "[{:?}] {msg}", std::time::SystemTime::now());
    }
}

fn spawn_server(app: AppHandle) {
    std::thread::spawn(move || {
        dlog("spawn_server thread started");
        let Some(engine_root) = find_engine_root(&app) else {
            dlog("find_engine_root returned None");
            set_status(
                &app,
                ServerStatus {
                    ready: false,
                    url: None,
                    error: Some(
                        "Could not locate ZeroBreach-Server.ps1 (bundled resources missing and no dev checkout found next to native-app/)."
                            .into(),
                    ),
                },
            );
            return;
        };

        let script = engine_root.join("ZeroBreach-Server.ps1");
        let port = pick_free_port();
        dlog(&format!(
            "engine_root={} script={} port={port}",
            engine_root.display(),
            script.display()
        ));
        emit_progress(&app, &format!("launching engine on port {port}…"));

        let mut cmd = Command::new("powershell.exe");
        cmd.current_dir(&engine_root)
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                // -WindowStyle Hidden, NOT the Win32 CREATE_NO_WINDOW creation flag: the legacy
                // Windows PowerShell ConsoleHost (powershell.exe, not pwsh.exe) initializes a
                // real console and can misbehave/fail outright if none is allocated for the
                // process at all. -WindowStyle Hidden still allocates one, just invisibly, so
                // Write-Host / [Console]:: calls inside ZeroBreach-Server.ps1 keep working.
                "-WindowStyle",
                "Hidden",
                "-File",
            ])
            .arg(&script)
            .args(["-Port", &port.to_string(), "-NoBrowser"]);

        let child = match cmd.spawn() {
            Ok(c) => {
                dlog(&format!("powershell.exe spawned, pid={}", c.id()));
                c
            }
            Err(e) => {
                dlog(&format!("spawn() failed: {e}"));
                set_status(
                    &app,
                    ServerStatus {
                        ready: false,
                        url: None,
                        error: Some(format!("Failed to launch ZeroBreach-Server.ps1: {e}")),
                    },
                );
                return;
            }
        };
        *app.state::<ServerState>().child.lock().unwrap() = Some(child);

        emit_progress(&app, "waiting for the local engine to come online…");
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if port_is_open(port) {
                break;
            }
            // The child exiting before the port ever opens means the script itself errored
            // out (bad args, execution-policy block, etc.) — surface that immediately
            // instead of burning the full 45s timeout on a process that's already gone.
            {
                let server_state = app.state::<ServerState>();
                let mut guard = server_state.child.lock().unwrap();
                if let Some(c) = guard.as_mut() {
                    if let Ok(Some(exit)) = c.try_wait() {
                        dlog(&format!("powershell.exe exited early: {exit}"));
                        drop(guard);
                        let log_path = std::env::temp_dir().join("zerobreach_native_debug.log");
                        set_status(
                            &app,
                            ServerStatus {
                                ready: false,
                                url: None,
                                error: Some(format!(
                                    "ZeroBreach-Server.ps1 exited before starting ({exit}) — see {} for details.",
                                    log_path.display()
                                )),
                            },
                        );
                        return;
                    }
                }
            }
            if Instant::now() > deadline {
                set_status(
                    &app,
                    ServerStatus {
                        ready: false,
                        url: None,
                        error: Some(
                            "Timed out waiting for the local engine to start (45s). Check reports/ for a launch error log."
                                .into(),
                        ),
                    },
                );
                return;
            }
            // Elevation prompt (UAC) blocks the child until the operator answers it —
            // this loop just keeps polling rather than treating that as a failure.
            std::thread::sleep(Duration::from_millis(300));
        }

        // Must be "localhost", not "127.0.0.1": ZeroBreach-Server.ps1's HttpListener only
        // registers the "http://localhost:$Port/" prefix, and HttpListener validates the
        // request's Host header against the registered prefix literally — a request with
        // Host: 127.0.0.1 gets rejected with "400 Bad Request - Invalid Hostname" even though
        // the raw TCP connect (used for the readiness poll above) succeeds fine either way.
        let url = format!("http://localhost:{port}/");
        set_status(
            &app,
            ServerStatus {
                ready: true,
                url: Some(url.clone()),
                error: None,
            },
        );

        // Swap the boot splash for a real window pointed at the live GUI.
        let app2 = app.clone();
        let _ = app.run_on_main_thread(move || {
            let built = WebviewWindowBuilder::new(
                &app2,
                "main",
                WebviewUrl::External(url.parse().unwrap()),
            )
            .title("ZeroBreach — Kraken Console")
            .inner_size(1440.0, 900.0)
            .min_inner_size(1100.0, 700.0)
            .center()
            .build();

            match built {
                Ok(_) => {
                    if let Some(boot) = app2.get_webview_window("boot") {
                        let _ = boot.close();
                    }
                }
                Err(e) => {
                    let _ = app2.emit(
                        "zerobreach://server-error",
                        format!("Engine is up but the console window failed to open: {e}"),
                    );
                }
            }
        });
    });
}

#[tauri::command]
fn get_server_status(app: AppHandle) -> ServerStatus {
    app.state::<ServerState>().status.lock().unwrap().clone()
}

fn kill_child(app: &AppHandle) {
    if let Some(mut child) = app.state::<ServerState>().child.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn main() {
    // Elevation is handled by the app manifest (requireAdministrator, see
    // native-app/src-tauri/windows/app.manifest) — by the time this runs the process
    // token is already elevated, so ZeroBreach-Server.ps1's own IsInRole check passes
    // and it never re-launches itself via RunAs (which would orphan this Child handle).
    tauri::Builder::default()
        .manage(ServerState {
            child: Mutex::new(None),
            status: Mutex::new(ServerStatus::default()),
        })
        .invoke_handler(tauri::generate_handler![get_server_status])
        .setup(|app| {
            spawn_server(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                if window.label() == "main" {
                    kill_child(window.app_handle());
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building the ZeroBreach native shell")
        .run(|app_handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                kill_child(app_handle);
            }
        });
}
