from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import hashlib
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory, session
from flask_socketio import SocketIO, disconnect, emit

from payload_runner import PayloadRunner, discover, parse_metadata, safe_slug

BASE = Path(__file__).resolve().parent
CONFIG_PATH = BASE / "config.json"
PAYLOADS = BASE / "payloads"
LOOT = BASE / "loot"


def load_config():
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def save_config(config):
    temp = CONFIG_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    temp.replace(CONFIG_PATH)


config = load_config()
app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = os.environ.get("CITYPOP_SESSION_KEY", secrets.token_hex(32))
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins=[])
runner = PayloadRunner(PAYLOADS, LOOT, BASE / "state")


def authorized():
    token = request.headers.get("X-CityPop-Token") or request.args.get("token")
    return bool(session.get("authorized") or (token and secrets.compare_digest(token, config["auth_token"])))


def require_auth(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not authorized():
            abort(401)
        return fn(*args, **kwargs)
    return wrapped


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.post("/api/login")
def login():
    supplied = (request.get_json(silent=True) or {}).get("token", "")
    if not secrets.compare_digest(supplied, config["auth_token"]):
        return jsonify(error="invalid token"), 401
    session["authorized"] = True
    return jsonify(ok=True, acknowledged=config.get("acknowledged", False))


@app.post("/api/acknowledge")
@require_auth
def acknowledge():
    global config
    config["acknowledged"] = True
    save_config(config)
    return jsonify(ok=True)


@app.get("/api/payloads")
@require_auth
def payload_list():
    return jsonify(payloads=discover(PAYLOADS), category_order=config["category_order"])


def default_route_interface():
    try:
        output = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=4
        )
        for line in output.splitlines():
            parts = line.split()
            if "dev" in parts and parts.index("dev") + 1 < len(parts):
                return parts[parts.index("dev") + 1]
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def interface_inventory():
    rows = []
    default_iface = default_route_interface()
    net_root = Path("/sys/class/net")
    if not net_root.exists():
        return rows
    for path in sorted(net_root.iterdir()):
        name = path.name
        try:
            operstate = (path / "operstate").read_text().strip()
        except OSError:
            operstate = "unknown"
        try:
            address = (path / "address").read_text().strip()
        except OSError:
            address = ""
        try:
            result = subprocess.run(
                ["ip", "-j", "address", "show", "dev", name],
                capture_output=True, text=True, timeout=4,
            )
            data = json.loads(result.stdout or "[]")
            addresses = [
                item.get("local") for item in (data[0].get("addr_info", []) if data else [])
                if item.get("local")
            ]
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, IndexError):
            addresses = []
        wireless = (path / "wireless").exists()
        mode = ""
        if wireless and shutil.which("iw"):
            try:
                info = subprocess.check_output(
                    ["iw", "dev", name, "info"], text=True,
                    stderr=subprocess.DEVNULL, timeout=4,
                )
                match = re.search(r"^\s*type\s+(\S+)", info, re.M)
                mode = match.group(1) if match else ""
            except (OSError, subprocess.SubprocessError):
                pass
        device_path = os.path.realpath(str(path / "device"))
        driver_path = os.path.realpath(str(path / "device" / "driver"))
        rows.append({
            "name": name, "state": operstate, "mac": address,
            "addresses": addresses, "wireless": wireless, "mode": mode,
            "driver": os.path.basename(driver_path) if driver_path else "",
            "onboard": "mmc" in device_path or os.path.basename(driver_path) == "brcmfmac",
            "default_route": name == default_iface,
            "safety": "CITY POP ROUTE · DO NOT MODIFY" if name == default_iface else "available",
        })
    return rows


def system_inventory():
    memory = {}
    try:
        values = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            values[key] = int(value.strip().split()[0]) * 1024
        memory = {"total": values.get("MemTotal", 0), "available": values.get("MemAvailable", 0)}
    except (OSError, ValueError):
        pass
    temperature = None
    try:
        temperature = round(int(Path("/sys/class/thermal/thermal_zone0/temp").read_text()) / 1000, 1)
    except (OSError, ValueError):
        pass
    disk = shutil.disk_usage(BASE)
    return {
        "hostname": socket.gethostname(), "temperature_c": temperature,
        "memory": memory,
        "disk": {"total": disk.total, "free": disk.free, "used": disk.used},
        "gps": bool(list(Path("/dev").glob("ttyACM*")) + list(Path("/dev").glob("ttyUSB*"))),
        "bluetooth": Path("/sys/class/bluetooth").exists() and any(Path("/sys/class/bluetooth").glob("hci*")),
        "sdr": bool(shutil.which("rtl_test") or shutil.which("hackrf_info")),
        "nfc": bool(list(Path("/dev").glob("ttyUSB*")) or list(Path("/dev").glob("ttyACM*"))),
    }


@app.get("/api/hardware")
@require_auth
def hardware_status():
    return jsonify(system=system_inventory(), interfaces=interface_inventory())


def literal_commands(source: str):
    commands = set(re.findall(
        r"(?:which\(|shutil\.which\(|\[)\s*['\"]([a-zA-Z0-9_.+-]+)['\"]", source
    ))
    common = {
        "sudo", "ip", "iw", "nmap", "tshark", "tcpdump", "hostapd",
        "dnsmasq", "aircrack-ng", "hciconfig", "hcitool", "bluetoothctl",
        "rtl_test", "mmcli", "gpspipe", "tcpreplay", "john", "gobuster",
    }
    return sorted(command for command in commands if command in common)


@app.get("/api/preflight/<path:payload_id>")
@require_auth
def payload_preflight(payload_id):
    path = runner.resolve(payload_id)
    meta = parse_metadata(path)
    source = path.read_text(encoding="utf-8", errors="replace")
    commands = literal_commands(source)
    checks = [
        {"label": f"command · {command}", "ok": bool(shutil.which(command)),
         "detail": shutil.which(command) or "not installed"}
        for command in commands
    ]
    interfaces = interface_inventory()
    if meta["category"] == "wifi":
        wireless = [item for item in interfaces if item["wireless"]]
        checks.append({"label": "Wi-Fi adapter", "ok": bool(wireless),
                       "detail": ", ".join(item["name"] for item in wireless) or "none detected"})
    if meta["category"] == "bluetooth":
        checks.append({"label": "Bluetooth adapter", "ok": system_inventory()["bluetooth"],
                       "detail": "detected" if system_inventory()["bluetooth"] else "none detected"})
    if meta["category"] == "sdr":
        checks.append({"label": "SDR tooling", "ok": system_inventory()["sdr"],
                       "detail": "detected" if system_inventory()["sdr"] else "optional hardware/tool missing"})
    warnings = []
    route_names = [item["name"] for item in interfaces if item["default_route"]]
    if meta["category"] in {"wifi", "network", "evasion"} and route_names:
        warnings.append(f"Protect the City Pop route: {', '.join(route_names)}")
    return jsonify(
        payload={"id": payload_id, "name": meta["name"], "danger": meta["danger"]},
        ready=all(item["ok"] for item in checks), checks=checks,
        warnings=warnings, estimated_impact="high" if meta["danger"] else "normal",
    )


@app.get("/api/runtime")
@require_auth
def runtime_status():
    try:
        since = max(0, int(request.args.get("since", "0")))
    except ValueError:
        since = 0
    return jsonify(runner.snapshot(since))


@app.get("/api/executions")
@require_auth
def execution_history():
    engagement = request.args.get("engagement")
    return jsonify(executions=runner.execution_history(engagement))


@app.get("/api/payload/<path:payload_id>")
@require_auth
def payload_get(payload_id):
    path = runner.resolve(payload_id)
    return jsonify(id=payload_id, source=path.read_text(encoding="utf-8"))


@app.put("/api/payload/<path:payload_id>")
@require_auth
def payload_save(payload_id):
    path = (PAYLOADS / payload_id).resolve()
    if PAYLOADS.resolve() not in path.parents or path.suffix not in {".py", ".sh", ""}:
        abort(400)
    source = (request.get_json(silent=True) or {}).get("source", "")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(source, encoding="utf-8")
    try:
        meta = parse_metadata(temp)
        if meta["category"] != path.parent.name:
            raise ValueError("@category must match the parent folder")
    except ValueError as error:
        temp.unlink(missing_ok=True)
        return jsonify(error=str(error)), 400
    temp.replace(path)
    path.chmod(0o750)
    return jsonify(ok=True)


@app.get("/api/loot")
@require_auth
def loot_list():
    files = []
    engagement = request.args.get("engagement", "").strip()
    root = LOOT / safe_slug(engagement) if engagement else LOOT
    if not root.exists():
        return jsonify(files=[])
    for path in sorted(root.rglob("*")):
        if path.is_file():
            stat = path.stat()
            files.append({"path": str(path.relative_to(LOOT)), "size": stat.st_size, "mtime": stat.st_mtime})
    return jsonify(files=files)


@app.post("/api/report")
@require_auth
def generate_report():
    data = request.get_json(silent=True) or {}
    display_name = str(data.get("engagement", "")).strip()[:80]
    if not display_name:
        return jsonify(error="engagement is required"), 400
    slug = safe_slug(display_name)
    root = LOOT / slug
    root.mkdir(parents=True, exist_ok=True)
    notes = str(data.get("notes", "")).strip()[:5000]
    executions = runner.execution_history(slug)
    artifact_rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "engagement-report.md":
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            artifact_rows.append((str(path.relative_to(root)), path.stat().st_size, digest))
        except OSError:
            continue
    lines = [
        f"# City Pop Engagement Report — {display_name}", "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}", "",
        "## Operator Notes", "", notes or "No operator notes supplied.", "",
        "## Execution Timeline", "",
    ]
    if executions:
        for item in reversed(executions):
            status = "running" if item.get("exit_code") is None else f"exit {item['exit_code']}"
            lines.append(
                f"- `{item.get('started_at')}` — **{item.get('name')}** "
                f"(`{item.get('payload_id')}`), {status}, {item.get('duration_seconds') or 0}s"
            )
    else:
        lines.append("No recorded executions.")
    lines.extend(["", "## Artifact Inventory", ""])
    if artifact_rows:
        lines.extend(["| Path | Bytes | SHA-256 |", "|---|---:|---|"])
        lines.extend(f"| `{path}` | {size} | `{digest}` |" for path, size, digest in artifact_rows)
    else:
        lines.append("No engagement artifacts.")
    lines.extend([
        "", "## Scope and Safety", "",
        "This report reflects operator-provided scope and tool output. Validate findings before relying on them.", "",
    ])
    report = root / "engagement-report.md"
    report.write_text("\n".join(lines), encoding="utf-8")
    return jsonify(ok=True, path=str(report.relative_to(LOOT)))


def safe_loot_path(name):
    path = (LOOT / name).resolve()
    if LOOT.resolve() not in path.parents or not path.is_file():
        abort(404)
    return path


@app.get("/api/loot/download/<path:name>")
@require_auth
def loot_download(name):
    path = safe_loot_path(name)
    return send_from_directory(path.parent, path.name, as_attachment=True)


@app.get("/api/loot/preview/<path:name>")
@require_auth
def loot_preview(name):
    path = safe_loot_path(name)
    if path.stat().st_size > 512_000:
        return jsonify(error="file too large to preview"), 413
    return jsonify(content=path.read_text(encoding="utf-8", errors="replace"))


@app.delete("/api/loot/<path:name>")
@require_auth
def loot_delete(name):
    path = safe_loot_path(name)
    path.unlink()
    # Clean up empty artifact directories while never removing loot itself.
    parent = path.parent
    while parent != LOOT and LOOT.resolve() in parent.resolve().parents:
        try:
            parent.rmdir()
        except OSError:
            break
        parent = parent.parent
    return jsonify(ok=True, deleted=name)


@app.delete("/api/loot")
@require_auth
def loot_delete_all():
    data = request.get_json(silent=True) or {}
    if data.get("confirm") != "DELETE ALL":
        return jsonify(error="confirmation required"), 400
    deleted = 0
    LOOT.mkdir(parents=True, exist_ok=True)
    engagement = str(data.get("engagement", "")).strip()
    target = LOOT / safe_slug(engagement) if engagement else LOOT
    if not target.exists():
        return jsonify(ok=True, deleted=0)
    children = list(target.iterdir()) if target == LOOT else [target]
    for child in children:
        if child.is_symlink() or child.is_file():
            child.unlink()
            deleted += 1
        elif child.is_dir():
            deleted += sum(1 for path in child.rglob("*") if path.is_file() or path.is_symlink())
            shutil.rmtree(child)
    return jsonify(ok=True, deleted=deleted, engagement=engagement or None)


def socket_authorized(auth):
    token = (auth or {}).get("token", "")
    return bool(session.get("authorized") or (token and secrets.compare_digest(token, config["auth_token"])))


@socketio.on("connect")
def on_connect(auth):
    if not socket_authorized(auth):
        return False
    emit("linked", {"ok": True})


def validate_consent(data):
    target = str(data.get("target", "")).strip()
    return data.get("authorized") is True and data.get("in_scope") is True and 0 < len(target) <= 255


def engagement_name(data):
    return str((data or {}).get("engagement", "")).strip()[:80]


@socketio.on("run_payload")
def run_payload(data):
    if not validate_consent(data or {}):
        emit("error", {"message": "Authorization, in-scope confirmation, and a target/context are required."})
        return
    name = engagement_name(data)
    if not name:
        emit("error", {"message": "An engagement name is required for operation logging."})
        return
    args = [str(x)[:512] for x in (data.get("args") or [])][:12]
    try:
        started = runner.start(
            request.sid, str(data.get("id", "")), args, socketio.emit, name
        )
    except (OSError, ValueError) as error:
        emit("error", {"message": str(error)})
        return
    if not started:
        emit("error", {"message": "Another operation is already running."})


@socketio.on("run_command")
def run_command(data):
    if not validate_consent(data or {}) or data.get("unlocked") is not True:
        emit("error", {"message": "Unlock and confirm authorization/scope first."})
        return
    command = str(data.get("command", ""))[:2048].strip()
    name = engagement_name(data)
    if not name:
        emit("error", {"message": "An engagement name is required for command logging."})
        return
    if command and not runner.command(request.sid, command, socketio.emit, name):
        emit("error", {"message": "Another operation is already running."})

@socketio.on("input_response")
def input_response(data):
    data = data or {}
    request_id = str(data.get("request_id", ""))[:128]
    value = data.get("value")
    if isinstance(value, str):
        value = value[:2048]
    if not request_id or not runner.respond(request.sid, request_id, value):
        emit("error", {"message": "That input request is no longer active."})


@socketio.on("stop")
def stop():
    emit("stopped", {"ok": runner.stop(request.sid)})


@socketio.on("disconnect")
def on_disconnect():
    # Payloads survive temporary phone/radio disconnects. An authenticated
    # client can recover state through /api/runtime and stop explicitly.
    pass


if __name__ == "__main__":
    socketio.run(app, host=config["bind"], port=int(config["port"]), allow_unsafe_werkzeug=True)
