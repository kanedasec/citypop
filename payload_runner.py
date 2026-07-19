"""Payload discovery and single-process execution for City Pop."""
from __future__ import annotations

import os
import json
import re
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

META_RE = re.compile(r"^#\s*@([a-z_]+):\s*(.*?)\s*$")
REQUIRED = {"name", "desc", "category", "danger"}
INPUT_PREFIX = "CITYPOP_INPUT_REQUEST:"


def parse_metadata(path: Path) -> dict:
    meta: dict[str, str] = {}
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line in list(source)[:30]:
            match = META_RE.match(line)
            if match:
                meta[match.group(1)] = match.group(2)
            elif meta and line.strip() and not line.startswith("#"):
                break
    missing = REQUIRED - meta.keys()
    if missing:
        raise ValueError(f"missing metadata: {', '.join(sorted(missing))}")
    if meta["danger"].lower() not in {"true", "false"}:
        raise ValueError("@danger must be true or false")
    meta["danger"] = meta["danger"].lower() == "true"
    active = meta.get("active", "false").lower()
    if active not in {"true", "false"}:
        raise ValueError("@active must be true or false")
    meta["active"] = active == "true"
    web = meta.get("web", "true").lower()
    if web not in {"true", "false"}:
        raise ValueError("@web must be true or false")
    meta["web"] = web == "true"
    meta["inputs"] = json.loads(meta.get("inputs", "[]"))
    return meta


def discover(root: Path) -> list[dict]:
    result = []
    for path in sorted(root.glob("*/*")):
        if not path.is_file() or path.name.startswith((".", "_")) or path.suffix == ".md":
            continue
        try:
            meta = parse_metadata(path)
        except (OSError, ValueError):
            continue
        meta.update({"id": str(path.relative_to(root)), "filename": path.name})
        result.append(meta)
    return result


@dataclass
class Running:
    process: subprocess.Popen
    owner: str
    name: str
    pending_request: str | None = None


class PayloadRunner:
    def __init__(self, root: Path, loot: Path):
        self.root = root.resolve()
        self.loot = loot.resolve()
        self.lock = threading.Lock()
        self.running: Running | None = None

    def resolve(self, payload_id: str) -> Path:
        path = (self.root / payload_id).resolve()
        if self.root not in path.parents or not path.is_file():
            raise ValueError("invalid payload")
        parse_metadata(path)
        return path

    def start(self, owner: str, payload_id: str, args: list[str], emit: Callable,
              engagement_name: str = "engagement") -> bool:
        path = self.resolve(payload_id)
        meta = parse_metadata(path)
        if not meta["web"]:
            raise ValueError(f"{meta['name']} requires the device LCD/GPIO controls and cannot run from the web UI")
        # Use the interpreter that is running City Pop.  When the web app is
        # started from .venv this guarantees every Python payload sees the
        # same installed dependencies instead of falling back to system
        # Python.
        command = ([sys.executable, "-u", str(path)] if path.suffix == ".py" else ["bash", str(path)]) + args
        return self._spawn(owner, meta["name"], command, emit, engagement_name)

    def command(self, owner: str, command: str, emit: Callable,
                engagement_name: str = "engagement") -> bool:
        return self._spawn(owner, "command", ["bash", "-lc", command], emit, engagement_name)

    def _spawn(self, owner: str, name: str, command: list[str], emit: Callable,
               engagement_name: str) -> bool:
        with self.lock:
            if self.running and self.running.process.poll() is None:
                return False
            env = os.environ.copy()
            env.update({"CITYPOP_ROOT": str(self.root.parent), "CITYPOP_LOOT": str(self.loot),
                        "CITYPOP_INTERACTIVE": "1", "PYTHONUNBUFFERED": "1"})
            # Executing a file inside payloads/<category>/ makes that category
            # directory Python's initial import root. Export City Pop's project
            # root so shared imports such as payloads._web_input always resolve.
            python_paths = [str(self.root.parent)]
            if env.get("PYTHONPATH"):
                python_paths.append(env["PYTHONPATH"])
            env["PYTHONPATH"] = os.pathsep.join(python_paths)
            proc = subprocess.Popen(command, cwd=self.root.parent, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, bufsize=1,
                                    start_new_session=True, env=env)
            self.running = Running(proc, owner, name)
        threading.Thread(
            target=self._stream,
            args=(proc, owner, name, engagement_name, emit),
            daemon=True,
        ).start()
        return True

    def _stream(self, proc: subprocess.Popen, owner: str, name: str,
                engagement_name: str, emit: Callable) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", name).strip("_") or "run"
        safe_engagement = re.sub(
            r"[^a-zA-Z0-9_-]+", "_", engagement_name
        ).strip("_")[:80] or "engagement"
        log_path = self.loot / "logs" / f"{stamp}_{safe_engagement}_{safe_name}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("w", encoding="utf-8") as log:
            assert proc.stdout is not None
            for line in proc.stdout:
                if line.startswith(INPUT_PREFIX):
                    request_data = json.loads(line[len(INPUT_PREFIX):])
                    request_id = str(request_data["request_id"])
                    with self.lock:
                        if self.running and self.running.process is proc:
                            self.running.pending_request = request_id
                    emit("input_request", request_data, to=owner)
                    continue
                log.write(line)
                log.flush()
                emit("output", {"line": line.rstrip("\n")}, to=owner)
        code = proc.wait()
        emit("finished", {"exit_code": code, "log": str(log_path.relative_to(self.loot))}, to=owner)
        with self.lock:
            if self.running and self.running.process is proc:
                self.running = None

    def respond(self, owner: str, request_id: str, value) -> bool:
        with self.lock:
            running = self.running
            if (not running or running.owner != owner or running.process.poll() is not None
                    or running.pending_request != request_id or running.process.stdin is None):
                return False
            running.pending_request = None
            stdin = running.process.stdin
        try:
            stdin.write(json.dumps({"request_id": request_id, "value": value}) + "\n")
            stdin.flush()
            return True
        except (BrokenPipeError, OSError):
            return False

    def stop(self, owner: str | None = None) -> bool:
        with self.lock:
            running = self.running
        if not running or running.process.poll() is not None or (owner and running.owner != owner):
            return False
        os.killpg(running.process.pid, signal.SIGTERM)
        try:
            running.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(running.process.pid, signal.SIGKILL)
        return True
