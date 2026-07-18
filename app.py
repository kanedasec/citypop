from __future__ import annotations

import json
import os
import secrets
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory, session
from flask_socketio import SocketIO, disconnect, emit

from payload_runner import PayloadRunner, discover, parse_metadata

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
runner = PayloadRunner(PAYLOADS, LOOT)


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
    for path in sorted(LOOT.rglob("*")):
        if path.is_file():
            stat = path.stat()
            files.append({"path": str(path.relative_to(LOOT)), "size": stat.st_size, "mtime": stat.st_mtime})
    return jsonify(files=files)


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


@socketio.on("run_payload")
def run_payload(data):
    if not validate_consent(data or {}):
        emit("error", {"message": "Authorization, in-scope confirmation, and a target/context are required."})
        return
    args = [str(x)[:512] for x in (data.get("args") or [])][:12]
    try:
        started = runner.start(request.sid, str(data.get("id", "")), args, socketio.emit)
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
    if command and not runner.command(request.sid, command, socketio.emit):
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
    runner.stop(request.sid)


if __name__ == "__main__":
    socketio.run(app, host=config["bind"], port=int(config["port"]), allow_unsafe_werkzeug=True)
