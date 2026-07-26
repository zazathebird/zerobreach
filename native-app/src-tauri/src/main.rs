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

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows_sys::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

// A Windows Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ties the elevated PS server
// child's lifetime to THIS process at the OS level — unlike the WindowEvent/RunEvent hooks
// below, this also covers a force-kill (Task Manager "End Task"), a panic, or a crash, none of
// which run any of our cooperative cleanup code. Stored as `usize` (not the raw HANDLE pointer
// type) purely so it can live in a `Mutex` shared across threads without an unsafe Send/Sync
// impl — HANDLE is just an opaque numeric value from the Win32 API's point of view.
#[cfg(windows)]
fn create_kill_on_close_job() -> Option<usize> {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return None;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if ok == 0 {
            CloseHandle(job);
            return None;
        }
        Some(job as usize)
    }
}

#[cfg(windows)]
fn assign_child_to_job(job: usize, child: &Child) -> bool {
    unsafe { AssignProcessToJobObject(job as _, child.as_raw_handle() as _) != 0 }
}

struct ServerState {
    child: Mutex<Option<Child>>,
    #[cfg(windows)]
    job: Mutex<Option<usize>>,
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
    // Debug-only: `cargo tauri dev` doesn't stage bundle.resources, so fall back to the real
    // checkout root. Gated behind debug_assertions so a release binary never carries (or acts
    // on) the build machine's own absolute checkout path — a release build with no staged
    // resources should report the real "can't find the engine" error, not silently probe a
    // path that only ever existed on whoever compiled it.
    #[cfg(debug_assertions)]
    {
        let dev_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");
        if dev_root.join("ZeroBreach-Server.ps1").is_file() {
            return Some(dev_root);
        }
    }
    None
}

fn pick_free_port() -> u16 {
    // Bind to port 0 to ask the OS for a free one, then drop the listener before the PS
    // server binds it. Small TOCTOU window (acceptable for a localhost-only dev tool run by
    // its own operator). NOTE this app always passes an explicit -Port, so
    // ZeroBreach-Server.ps1's own `if ($Port -eq 0) { $Port = Get-FreePort }` fallback never
    // runs for launches from here — if the port really is gone by the time the script tries
    // to bind it, $Listener.Start() throws, the script attempts a netsh url-acl retry, and on
    // failure exits 1 (caught by the try_wait() early-exit check below, not silently retried
    // with a different port).
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
    *lock_or_recover(&state.status) = status.clone();
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
                #[cfg(windows)]
                {
                    if let Some(job) = create_kill_on_close_job() {
                        if assign_child_to_job(job, &c) {
                            dlog("child assigned to kill-on-close job object");
                            *lock_or_recover(&app.state::<ServerState>().job) = Some(job);
                        } else {
                            // AssignProcessToJobObject failed after the job was successfully
                            // created — without this, the job HANDLE would never be stored
                            // (nothing else references it) and never closed, leaking it for
                            // the life of the process (found in a follow-up review pass).
                            unsafe { CloseHandle(job as _) };
                            dlog("AssignProcessToJobObject failed — falling back to cooperative-only cleanup");
                        }
                    } else {
                        dlog("CreateJobObjectW failed — falling back to cooperative-only cleanup");
                    }
                }
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
        *lock_or_recover(&app.state::<ServerState>().child) = Some(child);

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
                let mut guard = lock_or_recover(&server_state.child);
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
                        error: Some(format!(
                            "Timed out waiting for the local engine to start (45s). See {} for details.",
                            std::env::temp_dir().join("zerobreach_native_debug.log").display()
                        )),
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
                    // Window creation failed after we already told everyone ready=true — undo
                    // that, or a caller of get_server_status() after this point would see
                    // ready:true + a URL while no "main" window actually exists.
                    set_status(
                        &app2,
                        ServerStatus {
                            ready: false,
                            url: None,
                            error: Some(format!("Engine is up but the console window failed to open: {e}")),
                        },
                    );
                }
            }
        });
    });
}

#[tauri::command]
fn get_server_status(app: AppHandle) -> ServerStatus {
    lock_or_recover(&app.state::<ServerState>().status).clone()
}

// A Mutex poisoned by an unrelated panic elsewhere must not also take down kill_child — that's
// exactly the cleanup path that most needs to still run when something has already gone wrong.
// The lock is only ever held for plain data-copy/assignment (never across a fallible operation
// that could itself panic mid-guard), so recovering the possibly-stale-but-structurally-fine
// inner value is safe here.
fn lock_or_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn kill_child(app: &AppHandle) {
    dlog("kill_child called");
    if let Some(mut child) = lock_or_recover(&app.state::<ServerState>().child).take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    #[cfg(windows)]
    {
        // Closing the job handle also fires KILL_ON_JOB_CLOSE — redundant with child.kill()
        // above on the happy path, but it's the real backstop for a force-kill/panic/crash of
        // THIS process, which never runs this function at all (that's the whole reason the job
        // object exists — see create_kill_on_close_job's doc comment).
        if let Some(job) = lock_or_recover(&app.state::<ServerState>().job).take() {
            unsafe { CloseHandle(job as _) };
        }
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
            #[cfg(windows)]
            job: Mutex::new(None),
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
