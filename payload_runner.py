"""Payload discovery and persistent single-process execution for City Pop."""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from payload_analysis import analyze_payload

META_RE = re.compile(r"^#\s*@([a-z_]+):\s*(.*?)\s*$")
REQUIRED = {"name", "desc", "category", "danger"}
INPUT_PREFIX = "CITYPOP_INPUT_REQUEST:"
URL_RE = re.compile(r"https?://[^\s<>\"']+")


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
        meta["capabilities"] = analyze_payload(path, meta)
        meta.update({"id": str(path.relative_to(root)), "filename": path.name})
        result.append(meta)
    return result


def safe_slug(value: str, fallback: str = "engagement", limit: int = 80) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "_", value).strip("_")[:limit] or fallback


@dataclass
class Running:
    process: subprocess.Popen
    run_id: str
    owner: str
    name: str
    payload_id: str
    engagement: str
    engagement_slug: str
    args: list[str]
    started_at: str
    started_monotonic: float
    log_path: Path
    artifacts_before: set[str] = field(default_factory=set)
    pending_request: str | None = None
    pending_request_data: dict | None = None


class PayloadRunner:
    def __init__(self, root: Path, loot: Path, state: Path | None = None):
        self.root = root.resolve()
        self.loot = loot.resolve()
        self.state = (state or self.root.parent / "state").resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.history_path = self.state / "executions.json"
        self.lock = threading.Lock()
        self.running: Running | None = None
        self.output = deque(maxlen=1500)
        self.sequence = 0
        self.history = self._load_history()

    def _load_history(self) -> list[dict]:
        try:
            data = json.loads(self.history_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _save_history(self) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        temp = self.history_path.with_suffix(".tmp")
        temp.write_text(json.dumps(self.history[-500:], indent=2) + "\n", encoding="utf-8")
        temp.replace(self.history_path)

    def resolve(self, payload_id: str) -> Path:
        path = (self.root / payload_id).resolve()
        if self.root not in path.parents or not path.is_file():
            raise ValueError("invalid payload")
        parse_metadata(path)
        return path

    def _loot_files(self) -> set[str]:
        if not self.loot.exists():
            return set()
        return {
            str(path.relative_to(self.loot))
            for path in self.loot.rglob("*")
            if path.is_file()
        }

    def _append_output(self, line: str, kind: str = "output") -> dict:
        with self.lock:
            self.sequence += 1
            item = {
                "seq": self.sequence,
                "time": datetime.now(timezone.utc).isoformat(),
                "line": line,
                "kind": kind,
            }
            self.output.append(item)
        return item

    def start(self, owner: str, payload_id: str, args: list[str], emit: Callable,
              engagement_name: str = "engagement") -> bool:
        path = self.resolve(payload_id)
        meta = parse_metadata(path)
        if not meta["web"]:
            raise ValueError(f"{meta['name']} is not available through the web UI")
        command = ([sys.executable, "-u", str(path)] if path.suffix == ".py" else ["bash", str(path)]) + args
        redacted = []
        for index, value in enumerate(args):
            spec = meta.get("inputs", [])[index] if index < len(meta.get("inputs", [])) else {}
            redacted.append("••••••" if spec.get("type") == "password" else value)
        return self._spawn(owner, meta["name"], payload_id, command, redacted, emit, engagement_name)

    def command(self, owner: str, command: str, emit: Callable,
                engagement_name: str = "engagement") -> bool:
        return self._spawn(
            owner, "command", "command", ["bash", "-lc", command],
            ["[command redacted]"], emit, engagement_name,
        )

    def _spawn(self, owner: str, name: str, payload_id: str, command: list[str],
               display_args: list[str], emit: Callable, engagement_name: str) -> bool:
        with self.lock:
            if self.running and self.running.process.poll() is None:
                return False
            engagement_slug = safe_slug(engagement_name)
            engagement_loot = self.loot / engagement_slug
            engagement_loot.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            safe_name = safe_slug(name, "run")
            log_path = engagement_loot / "logs" / f"{stamp}_{engagement_slug}_{safe_name}.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            env = os.environ.copy()
            env.update({
                "CITYPOP_ROOT": str(self.root.parent),
                "CITYPOP_LOOT": str(engagement_loot),
                "CITYPOP_ENGAGEMENT": engagement_name,
                "CITYPOP_ENGAGEMENT_SLUG": engagement_slug,
                "CITYPOP_INTERACTIVE": "1",
                "PYTHONUNBUFFERED": "1",
            })
            python_paths = [str(self.root.parent)]
            if env.get("PYTHONPATH"):
                python_paths.append(env["PYTHONPATH"])
            env["PYTHONPATH"] = os.pathsep.join(python_paths)
            proc = subprocess.Popen(
                command, cwd=self.root.parent, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True,
                bufsize=1, start_new_session=True, env=env,
            )
            started_at = datetime.now(timezone.utc).isoformat()
            run = Running(
                process=proc, run_id=uuid.uuid4().hex, owner=owner, name=name,
                payload_id=payload_id, engagement=engagement_name,
                engagement_slug=engagement_slug, args=display_args,
                started_at=started_at, started_monotonic=time.monotonic(),
                log_path=log_path, artifacts_before=self._loot_files(),
            )
            self.running = run
            self.history.append({
                "run_id": run.run_id, "payload_id": payload_id, "name": name,
                "engagement": engagement_name, "engagement_slug": engagement_slug,
                "args": display_args, "started_at": started_at, "finished_at": None,
                "duration_seconds": None, "exit_code": None,
                "log": str(log_path.relative_to(self.loot)), "artifacts": [],
            })
            self._save_history()
        emit("output", self._append_output(
            f"▸ {payload_id} · engagement {engagement_name}", "start"
        ))
        threading.Thread(target=self._stream, args=(run, emit), daemon=True).start()
        return True

    def _stream(self, run: Running, emit: Callable) -> None:
        links: set[str] = set()
        with run.log_path.open("w", encoding="utf-8") as log:
            assert run.process.stdout is not None
            for line in run.process.stdout:
                if line.startswith(INPUT_PREFIX):
                    try:
                        request_data = json.loads(line[len(INPUT_PREFIX):])
                        request_id = str(request_data["request_id"])
                    except (json.JSONDecodeError, KeyError):
                        continue
                    with self.lock:
                        if self.running and self.running.process is run.process:
                            self.running.pending_request = request_id
                            self.running.pending_request_data = request_data
                    emit("input_request", request_data)
                    continue
                clean = line.rstrip("\n")
                log.write(line)
                log.flush()
                item = self._append_output(clean)
                emit("output", item)
                for url in URL_RE.findall(clean):
                    normalized = url.rstrip(".,;)")
                    if normalized not in links:
                        links.add(normalized)
                        emit("runtime_link", {"url": normalized, "label": clean[:160]})
        code = run.process.wait()
        duration = round(time.monotonic() - run.started_monotonic, 2)
        created = sorted(self._loot_files() - run.artifacts_before)
        log_relative = str(run.log_path.relative_to(self.loot))
        artifacts = [path for path in created if path != log_relative]
        for path in artifacts:
            emit("artifact", {"path": path, "run_id": run.run_id})
        finished = {
            "run_id": run.run_id, "exit_code": code, "log": log_relative,
            "duration_seconds": duration, "artifacts": artifacts,
        }
        finished_item = self._append_output(
            f"» finished · exit {code} · {duration:.1f}s · log {log_relative}",
            "finished",
        )
        finished["output"] = finished_item
        emit("finished", finished)
        with self.lock:
            for item in reversed(self.history):
                if item.get("run_id") == run.run_id:
                    item.update({
                        "finished_at": datetime.now(timezone.utc).isoformat(),
                        "duration_seconds": duration, "exit_code": code,
                        "artifacts": artifacts, "links": sorted(links),
                    })
                    break
            self._save_history()
            if self.running and self.running.process is run.process:
                self.running = None

    def snapshot(self, since: int = 0) -> dict:
        with self.lock:
            run = self.running
            current = None
            if run and run.process.poll() is None:
                current = {
                    "run_id": run.run_id, "payload_id": run.payload_id,
                    "name": run.name, "engagement": run.engagement,
                    "engagement_slug": run.engagement_slug, "args": run.args,
                    "started_at": run.started_at,
                    "elapsed_seconds": round(time.monotonic() - run.started_monotonic, 1),
                    "log": str(run.log_path.relative_to(self.loot)),
                    "pending_input": run.pending_request_data,
                }
            output = [item for item in self.output if item["seq"] > since]
            return {"running": current, "output": output, "last_seq": self.sequence}

    def execution_history(self, engagement: str | None = None) -> list[dict]:
        with self.lock:
            rows = list(reversed(self.history))
        if engagement:
            rows = [row for row in rows if row.get("engagement_slug") == engagement]
        return rows

    def respond(self, owner: str, request_id: str, value) -> bool:
        with self.lock:
            running = self.running
            if (not running or running.process.poll() is not None
                    or running.pending_request != request_id or running.process.stdin is None):
                return False
            running.pending_request = None
            running.pending_request_data = None
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
        if not running or running.process.poll() is not None:
            return False
        os.killpg(running.process.pid, signal.SIGTERM)
        try:
            running.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(running.process.pid, signal.SIGKILL)
        return True
