"""
ZeroBreach V23 — Python/Flask WebSocket Bridge
Spawns PowerShell engine, streams output to HTML frontend via SocketIO.
"""

import os
import sys
import json
import re
import subprocess
import threading
import time
import socket
import platform
import webbrowser
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

# ── App Setup ─────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
ROOT_DIR = BASE_DIR.parent  # project root (one level up from _python/)
PS_SCRIPT = ROOT_DIR / "ZeroBreach-V23.ps1"
REPORTS_DIR = ROOT_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(ROOT_DIR / "gui" / "templates"),
    static_folder=str(ROOT_DIR / "gui" / "static"),
)
app.config["SECRET_KEY"] = "zerobreach-kraken-2024"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Global Scan State ─────────────────────────────────────────────────────────
scan_state = {
    "running": False,
    "phase": 0,
    "phase_total": 107,
    "phase_name": "",
    "section": "",
    "mode": "FULL",
    "elapsed": 0,
    "findings": [],
    "threat_counts": {
        "RAT": 0, "Rootkit": 0, "Ransomware": 0, "Keylogger": 0,
        "Worm": 0, "Miner": 0, "Trojan": 0, "Spyware": 0,
        "Fileless": 0, "Other": 0
    },
    "scan_complete": False,
    "audit_results_path": None
}
scan_process = None
scan_lock = threading.Lock()

# ── Phase count per mode ───────────────────────────────────────────────────────
MODE_PHASES = {"QUICK": 30, "FULL": 80, "DEEP": 107, "PARANOID": 107, "STEALTH": 107}

# ── Output line parser ─────────────────────────────────────────────────────────
PHASE_RE = re.compile(r"PHASE\s+(\d+)[^\d]", re.IGNORECASE)
SECTION_RE = re.compile(r"SECTION[:\s]+(.+)", re.IGNORECASE)
THREAT_MAP = {
    "RAT": ["rat", "c2", "beacon", "asyncrat", "njrat", "remcos", "darkcomet"],
    "Rootkit": ["rootkit", "kernel driver", "bootkit", "mbr", "hidden process"],
    "Ransomware": ["ransomware", "ransom", "extension velocity", "high entropy", "ransom note"],
    "Keylogger": ["keylogger", "keystroke", "clipboard"],
    "Worm": ["worm", "autorun", "usb spread", "network share"],
    "Miner": ["cryptominer", "miner", "cpu abuse", "xmrig"],
    "Trojan": ["trojan", "dropper", "downloader", "loader"],
    "Spyware": ["spyware", "adware", "pup", "info-stealer", "stealer"],
    "Fileless": ["fileless", "base64 blob", "registry payload", "amsi bypass", "etw"],
    "Other": ["backdoor", "rootkit", "exploit", "cve-", "lolbin", "uac bypass"]
}

SEVERITY_PATTERNS = {
    "CRITICAL": re.compile(r"\[CRIT\]|CRITICAL|\[!!\]|THREAT BANNER|IOC HIT|BLATANT", re.I),
    "HIGH":     re.compile(r"\[HIGH\]|HIGH SEVERITY|\[WARN\]|SUSPICIOUS", re.I),
    "POSSIBLE": re.compile(r"\[POSSIBLE\]|POSSIBLE|FLAGGED|ANOMAL", re.I),
    "CLEAN":    re.compile(r"\[OK\]|CLEAN|NO .* FOUND|-> \[OK\]", re.I),
    "INFO":     re.compile(r"\[INFO\]|\[VER\]|EXECUTED|EVALUATED", re.I),
    "HUNT":     re.compile(r"\[HUNT\]|SCANNING|CHECKING|AUDITING", re.I),
}

def classify_line(line: str) -> dict:
    severity = "INFO"
    for sev, pat in SEVERITY_PATTERNS.items():
        if pat.search(line):
            severity = sev
            break

    threat_type = None
    ll = line.lower()
    for ttype, keywords in THREAT_MAP.items():
        if any(k in ll for k in keywords):
            threat_type = ttype
            break

    return {"severity": severity, "threat_type": threat_type}

def increment_threat(threat_type: str):
    if threat_type and threat_type in scan_state["threat_counts"]:
        scan_state["threat_counts"][threat_type] += 1
    elif threat_type:
        scan_state["threat_counts"]["Other"] += 1

# ── PowerShell launcher ────────────────────────────────────────────────────────
def build_ps_command(config: dict) -> list:
    hours = config.get("hours", 0)
    mode = config.get("mode", "FULL")
    paranoid = config.get("paranoid", False)
    stealth = config.get("stealth", False)
    html_report = config.get("html_report", True)
    ioc_file = config.get("ioc_file", "")
    baseline = config.get("baseline", "")
    out_dir = str(REPORTS_DIR)

    args = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(PS_SCRIPT),
        "-Mode", mode,
        "-Hours", str(hours),
        "-Auto",
        "-OutDir", out_dir
    ]
    if html_report:
        args.append("-Html")
    if paranoid:
        args.append("-Paranoid")
    if stealth:
        args.append("-Stealth")
    if ioc_file:
        args += ["-IocFile", ioc_file]
    if baseline:
        args += ["-Baseline", baseline]

    return args

def run_scan(config: dict):
    global scan_process
    with scan_lock:
        scan_state["running"] = True
        scan_state["scan_complete"] = False
        scan_state["phase"] = 0
        scan_state["findings"] = []
        scan_state["threat_counts"] = {k: 0 for k in scan_state["threat_counts"]}
        scan_state["phase_total"] = MODE_PHASES.get(config.get("mode", "FULL"), 107)
        scan_state["mode"] = config.get("mode", "FULL")

    start_time = time.time()
    cmd = build_ps_command(config)

    try:
        scan_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )

        for raw_line in scan_process.stdout:
            if not scan_state["running"]:
                scan_process.terminate()
                break

            line = raw_line.rstrip()
            if not line:
                continue

            elapsed = int(time.time() - start_time)
            scan_state["elapsed"] = elapsed

            # Phase detection
            pm = PHASE_RE.search(line)
            if pm:
                scan_state["phase"] = int(pm.group(1))

            # Section detection
            sm = SECTION_RE.search(line)
            if sm:
                scan_state["section"] = sm.group(1).strip()

            # Phase name from header lines
            if "PHASE" in line.upper() and "──" in line:
                parts = line.split("──")
                if len(parts) >= 3:
                    scan_state["phase_name"] = parts[2].strip().strip("─").strip()

            classified = classify_line(line)

            # Track findings
            if classified["severity"] in ("CRITICAL", "HIGH", "POSSIBLE"):
                finding = {
                    "id": len(scan_state["findings"]),
                    "line": line,
                    "severity": classified["severity"],
                    "threat_type": classified["threat_type"],
                    "phase": scan_state["phase"],
                    "timestamp": datetime.now().strftime("%H:%M:%S")
                }
                scan_state["findings"].append(finding)
                if classified["threat_type"]:
                    increment_threat(classified["threat_type"])

                socketio.emit("finding", finding)

            # Stream all lines to log
            socketio.emit("log_line", {
                "text": line,
                "severity": classified["severity"],
                "phase": scan_state["phase"],
                "elapsed": elapsed
            })

            # Emit state update every 2 seconds via periodic thread
        
        scan_process.wait()

    except Exception as e:
        socketio.emit("log_line", {"text": f"[ERROR] {e}", "severity": "CRITICAL", "phase": 0, "elapsed": 0})

    finally:
        scan_state["running"] = False
        scan_state["scan_complete"] = True

        # Save audit results
        results_path = REPORTS_DIR / f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_path, "w") as f:
            json.dump({
                "findings": scan_state["findings"],
                "threat_counts": scan_state["threat_counts"],
                "mode": scan_state["mode"],
                "elapsed": scan_state["elapsed"],
                "timestamp": datetime.now().isoformat()
            }, f, indent=2)
        scan_state["audit_results_path"] = str(results_path)

        socketio.emit("scan_complete", {
            "findings_count": len(scan_state["findings"]),
            "threat_counts": scan_state["threat_counts"],
            "elapsed": scan_state["elapsed"],
            "results_path": str(results_path)
        })

# ── Periodic state broadcaster ─────────────────────────────────────────────────
def state_broadcaster():
    while True:
        if scan_state["running"]:
            socketio.emit("scan_state", {
                "phase": scan_state["phase"],
                "phase_total": scan_state["phase_total"],
                "phase_name": scan_state["phase_name"],
                "section": scan_state["section"],
                "elapsed": scan_state["elapsed"],
                "threat_counts": scan_state["threat_counts"],
                "findings_count": len(scan_state["findings"])
            })
        time.sleep(1)

broadcaster_thread = threading.Thread(target=state_broadcaster, daemon=True)
broadcaster_thread.start()

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/sysinfo")
def sysinfo():
    import psutil
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        hostname = socket.gethostname()
        username = os.environ.get("USERNAME", "Unknown")
        os_ver = platform.version()
        return jsonify({
            "hostname": hostname,
            "username": username,
            "os": f"Windows {platform.release()}",
            "os_ver": os_ver,
            "cpu": cpu,
            "ram_used": mem.percent,
            "ram_total": round(mem.total / (1024**3), 1)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    if scan_state["running"]:
        return jsonify({"error": "Scan already running"}), 400
    config = request.json or {}
    thread = threading.Thread(target=run_scan, args=(config,), daemon=True)
    thread.start()
    return jsonify({"status": "started"})

@app.route("/api/scan/abort", methods=["POST"])
def abort_scan():
    global scan_process
    scan_state["running"] = False
    if scan_process:
        scan_process.terminate()
    return jsonify({"status": "aborted"})

@app.route("/api/scan/state")
def get_state():
    return jsonify(scan_state)

@app.route("/api/findings")
def get_findings():
    return jsonify(scan_state["findings"])

@app.route("/api/reports")
def list_reports():
    files = sorted(REPORTS_DIR.glob("*.json"), reverse=True)
    return jsonify([{"name": f.name, "path": str(f), "size": f.stat().st_size} for f in files[:20]])

@app.route("/api/reports/<filename>")
def get_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

@socketio.on("connect")
def on_connect():
    emit("connected", {"status": "ZeroBreach bridge online"})

@socketio.on("ping_state")
def on_ping():
    emit("scan_state", {
        "phase": scan_state["phase"],
        "phase_total": scan_state["phase_total"],
        "phase_name": scan_state["phase_name"],
        "elapsed": scan_state["elapsed"],
        "threat_counts": scan_state["threat_counts"],
        "running": scan_state["running"],
        "scan_complete": scan_state["scan_complete"]
    })

# ── Entry Point ────────────────────────────────────────────────────────────────
def find_free_port(start=5000):
    for port in range(start, start + 100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("localhost", port)) != 0:
                return port
    return start

if __name__ == "__main__":
    port = find_free_port()
    url = f"http://localhost:{port}"
    print(f"[ZeroBreach] Starting server on {url}")
    
    def open_browser():
        time.sleep(1.2)
        webbrowser.open(url)
    
    threading.Thread(target=open_browser, daemon=True).start()
    socketio.run(app, host="127.0.0.1", port=port, debug=False, allow_unsafe_werkzeug=True)
