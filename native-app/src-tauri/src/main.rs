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
#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    RegGetValueW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_TOPMOST,
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

// Detects the WebView2 Runtime the same way Microsoft's own distribution docs do
// (learn.microsoft.com/microsoft-edge/webview2/concepts/distribution): a non-empty "pv"
// (product version) string under the WebView2 Client GUID, which is identical across every
// Evergreen channel/installer. Checked in per-machine (native 64-bit view), per-machine
// (WOW6432Node — a 64-bit process does NOT see this view unless the path says so explicitly),
// then per-user order, because a non-admin Evergreen install writes to HKCU instead of HKLM.
#[cfg(windows)]
fn webview2_runtime_installed() -> bool {
    const CLIENT_SUBKEY: &str =
        "SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    const CLIENT_SUBKEY_WOW6432: &str =
        "SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

    fn has_nonempty_pv(hive: HKEY, subkey: &str) -> bool {
        let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let value_w: Vec<u16> = "pv".encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = [0u16; 128];
        let mut size = (buf.len() * std::mem::size_of::<u16>()) as u32;
        let status = unsafe {
            RegGetValueW(
                hive,
                subkey_w.as_ptr(),
                value_w.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        // ERROR_MORE_DATA (234): the value exists but is longer than our 128-u16 buffer, which a
        // Chromium version string never is. The value EXISTING is itself decent evidence of an
        // install, so report installed. Note this is the PERMISSIVE direction, not the safe one:
        // a wrong "installed" restores the silent hang, whereas a wrong "missing" produces a loud,
        // logged, self-explanatory exit. Kept because the probability is ~0, but logged so it is
        // never invisible if it does happen.
        const ERROR_MORE_DATA: u32 = 234;
        if status == ERROR_MORE_DATA {
            dlog(&format!("WebView2 pv probe: subkey={subkey} -> ERROR_MORE_DATA (value longer than buffer); treating as installed"));
            return true;
        }
        if status != 0 {
            // Log the failure branch too. This guard exists BECAUSE a failure mode was
            // undiagnosable, so the broken machine is exactly the one that must not be silent:
            // 2 = ERROR_FILE_NOT_FOUND (genuinely absent), 5 = ERROR_ACCESS_DENIED (GPO/ACL),
            // 1630 = ERROR_UNSUPPORTED_TYPE (pv present but not a REG_SZ) are very different
            // stories and used to be indistinguishable in the log.
            dlog(&format!("WebView2 pv probe: subkey={subkey} -> not readable (status={status})"));
            return false;
        }
        // Microsoft's distribution doc is explicit that "not installed" covers a pv that is
        // absent, null, an empty string, OR the literal "0.0.0.0" — and 0.0.0.0 is exactly what
        // EdgeUpdate leaves behind after an uninstall or a rolled-back Evergreen update, i.e.
        // precisely the population this guard exists for. Checking only "non-empty" (size > 2)
        // let that case through, which silently restored the original silent hang.
        // size is in BYTES and includes the trailing NUL RegGetValueW writes for RRF_RT_REG_SZ.
        let chars = ((size as usize) / 2).saturating_sub(1).min(buf.len());
        let pv = String::from_utf16_lossy(&buf[..chars]);
        let pv = pv.trim_end_matches('\0').trim();
        dlog(&format!("WebView2 pv probe: subkey={subkey} -> '{pv}'"));
        !pv.is_empty() && pv != "0.0.0.0"
    }

    // Ask the WebView2 loader itself FIRST. This is the same resolution wry performs when it
    // creates the environment, so unlike the registry it honors the two override paths that
    // register no EdgeUpdate key at all:
    //   * WEBVIEW2_BROWSER_EXECUTABLE_FOLDER - a fixed-version runtime shipped alongside the app,
    //     which is precisely the answer for the USB-portable/offline MSP scenario. A registry-only
    //     probe would hard-refuse to start on a machine where the app would have run perfectly -
    //     i.e. it would block the very workaround for the problem this guard exists to catch.
    //   * WEBVIEW2_RELEASE_CHANNEL_PREFERENCE - Edge Beta/Dev/Canary as the backing platform,
    //     which register under different GUIDs than the Evergreen Runtime.
    // The registry probe stays as the fallback (and as the diagnostic that names which hive matched).
    match tauri::webview_version() {
        Ok(v) if !v.is_empty() && v != "0.0.0.0" => {
            dlog(&format!("WebView2 detected via loader: version '{v}'"));
            return true;
        }
        Ok(v) => dlog(&format!("WebView2 loader returned an unusable version '{v}' - falling back to the registry probe")),
        Err(e) => dlog(&format!("WebView2 loader lookup failed ({e}) - falling back to the registry probe")),
    }

    has_nonempty_pv(HKEY_LOCAL_MACHINE, CLIENT_SUBKEY)
        || has_nonempty_pv(HKEY_LOCAL_MACHINE, CLIENT_SUBKEY_WOW6432)
        || has_nonempty_pv(HKEY_CURRENT_USER, CLIENT_SUBKEY)
}

// Without this, a machine missing WebView2 hangs completely silently: the "boot" window in
// tauri.conf.json gets created by .build()/.run() before our .setup() closure (and its dlog
// calls) ever fires, WebView2's own loader puts up a native "install WebView2?" prompt to back
// it, and with no interactive user to answer that prompt (unattended/LogonCommand/kiosk/RDP —
// confirmed live in a Windows Sandbox with no WebView2 registered: HasExited=False forever, no
// log file ever created) the process just sits there forever. Checking first and failing loud
// with a plain Win32 message box — no webview involved, so it can't hang the same way — turns
// that into an immediate, visible, logged exit instead.
#[cfg(windows)]
fn fatal_if_webview2_missing() {
    if webview2_runtime_installed() {
        return;
    }
    dlog("WebView2 Runtime not found (checked HKLM/HKLM-WOW6432Node/HKCU) — refusing to build a webview");

    // Distinct from 1: exit code 1 already means "generic failure" throughout this stack
    // (spawn_server treats a child exit-1 as a script error), so an RMM/watchdog wrapper
    // otherwise cannot tell "WebView2 missing" from any other failure.
    const EXIT_WEBVIEW2_MISSING: i32 = 3;

    // The bug being fixed is "a modal nobody can click blocks forever unattended". A plain
    // blocking MessageBoxW has exactly that property — it made the hang visible and logged,
    // but did not remove it. Unattended callers opt out entirely; everyone else gets the box
    // on a worker thread with a hard deadline enforced here, so the process ALWAYS exits.
    // args_os, NOT args: std::env::args() PANICS on non-Unicode argv, and with panic = "abort"
    // in the release profile that turns a clean exit-3 into a WER crash.
    // The command line is the load-bearing channel of the two: because the manifest is
    // requireAdministrator, over-the-shoulder elevation (a standard user entering a DIFFERENT
    // admin's credentials) builds the environment from the admin account, so ZB_UNATTENDED set by
    // the caller is invisible there. --unattended always survives. The env var is best-effort.
    let unattended = std::env::var_os("ZB_UNATTENDED").is_some()
        || std::env::args_os().any(|a| a == "--unattended" || a == "--no-ui");
    if unattended {
        dlog("unattended mode (ZB_UNATTENDED/--unattended/--no-ui) — skipping the dialog, exiting now");
        std::process::exit(EXIT_WEBVIEW2_MISSING);
    }

    // Shared so the MAIN thread can report what actually happened instead of inferring it from
    // is_finished(). When MessageBoxW returns 0 (non-interactive window station) the worker
    // finishes instantly, and reporting that as "dialog dismissed" would re-introduce exactly the
    // defect this round fixed: a log line claiming a user interaction that never occurred.
    // -1 = worker has not reported yet.
    let box_rc = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(-1));
    let box_rc_worker = std::sync::Arc::clone(&box_rc);

    let worker = std::thread::spawn(move || {
        let text: Vec<u16> = "ZeroBreach requires the Microsoft Edge WebView2 Runtime, which is not installed on this machine.\n\n\
Install it from:\nhttps://developer.microsoft.com/microsoft-edge/webview2/\n\n\
(If you installed ZeroBreach with the installer, re-running it installs WebView2 automatically.)\n\n\
ZeroBreach will now exit."
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let title: Vec<u16> = "ZeroBreach \u{2014} WebView2 Runtime Required"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let rc = unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND,
            )
        };
        // Returning 0 means the box never displayed (e.g. a non-interactive window station).
        // The old code logged "message box dismissed" unconditionally, which reported a user
        // interaction that never happened — and threw away the one diagnostic that says
        // whether the dialog is actually on screen.
        box_rc_worker.store(rc, std::sync::atomic::Ordering::SeqCst);
        if rc == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            dlog(&format!("MessageBoxW FAILED (rc=0), GetLastError={err} — no dialog was displayed"));
        } else {
            dlog(&format!("message box returned {rc} (dismissed by user)"));
        }
    });

    // 120s, not 30s: the dialog vanishes with the process when the deadline fires, so too short a
    // window yanks the message off screen before an operator who stepped away can read it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while !worker.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    match box_rc.load(std::sync::atomic::Ordering::SeqCst) {
        -1 => dlog("exiting after WebView2-missing notice (120s deadline reached, dialog was never dismissed)"),
        0 => dlog("exiting after WebView2-missing notice (no dialog could be displayed — non-interactive session)"),
        rc => dlog(&format!("exiting after WebView2-missing notice (dialog dismissed, rc={rc})")),
    }

    // TerminateProcess, not process::exit. exit() runs atexit handlers and then ExitProcess, which
    // kills the worker wherever it happens to be and runs DLL_PROCESS_DETACH under the loader
    // lock — and MessageBoxW delay-loads comctl32/uxtheme and resource DLLs on first call, so a
    // worker killed while holding the loader lock deadlocks detach and the process hangs forever:
    // exactly the outcome this whole guard exists to eliminate. TerminateProcess runs no atexit
    // handlers and takes no loader lock, so the exit is unconditional.
    unsafe {
        windows_sys::Win32::System::Threading::TerminateProcess(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            EXIT_WEBVIEW2_MISSING as u32,
        );
    }
    // Unreachable in practice; keeps the function's control flow well-formed.
    std::process::exit(EXIT_WEBVIEW2_MISSING);
}

fn main() {
    // Literal first statement of main(), before tauri::Builder even runs — the only proof in
    // a release build (no console; windows_subsystem = "windows") of how far execution got if
    // everything after this hangs or panics before spawn_server's own dlog calls are reached
    // (exactly what happened with the WebView2-missing hang this function guards against below).
    dlog("main() started");

    // Must run before ANY webview window is built (including the "boot" window declared in
    // tauri.conf.json, which tauri::Builder creates during .build()/.run() — before .setup()
    // fires). See fatal_if_webview2_missing's doc comment for why this matters.
    #[cfg(windows)]
    fatal_if_webview2_missing();

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
