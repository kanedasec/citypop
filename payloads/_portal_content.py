"""Shared static-template hosting for DNS spoof and captive-portal payloads."""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

TEMPLATE_ROOT = Path(__file__).resolve().parents[1] / "templates" / "dns"
FIELD_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
SENSITIVE_FIELD_PARTS = {"sensitive"}
event_log_lock = threading.Lock()


def allowed_submission_fields(value) -> list[str]:
    """Return declared non-sensitive awareness fields with conservative names."""
    if not isinstance(value, list):
        return []
    fields = []
    for item in value[:12]:
        name = str(item).strip().lower()
        tokens = set(name.split("_"))
        sensitive = any(
            part in tokens or (len(part) >= 5 and part in name)
            for part in SENSITIVE_FIELD_PARTS
        )
        if FIELD_NAME_RE.fullmatch(name) and not sensitive and name not in fields:
            fields.append(name)
    return fields


def discover_templates(root: Path = TEMPLATE_ROOT, include_none: bool = True) -> list[dict]:
    """Return contained, symlink-free static sites with an index page."""
    choices = []
    if include_none:
        choices.append({
            "value": "none",
            "label": "DNS only — do not start a web server; the response IP hosts its own service",
            "path": None,
            "submission_fields": [],
        })
    if not root.is_dir():
        return choices
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or directory.is_symlink() or not (directory / "index.html").is_file():
            continue
        if any(path.is_symlink() for path in directory.rglob("*")):
            continue
        metadata = {}
        try:
            metadata = json.loads((directory / "template.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
        name = str(metadata.get("name") or directory.name.replace("-", " ").title())[:80]
        description = str(metadata.get("description") or "serve this local static template")[:180]
        choices.append({
            "value": directory.name,
            "label": f"{name} — {description}",
            "path": directory.resolve(),
            "submission_fields": allowed_submission_fields(metadata.get("submission_fields")),
        })
    return choices


def append_event(log_path: Path, event: dict) -> None:
    with event_log_lock, log_path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(event, ensure_ascii=False) + "\n")


def template_handler(directory: Path, event_log: Path, submission_fields: list[str]):
    """Serve a static site and accept only its declared non-sensitive fields."""
    allowed_fields = set(submission_fields)

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(directory), **kwargs)

        def guess_type(self, path):
            content_type = super().guess_type(path)
            textual_types = {
                "application/javascript", "application/json",
                "application/xhtml+xml", "application/xml", "image/svg+xml",
            }
            if (
                "charset=" not in content_type.lower()
                and (content_type.startswith("text/") or content_type in textual_types)
            ):
                return f"{content_type}; charset=utf-8"
            return content_type

        def do_POST(self):
            if urlsplit(self.path).path != "/submit":
                self.send_error(404, "Submission endpoint not found")
                return
            if not allowed_fields:
                self.send_error(403, "This template does not accept submissions")
                return
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if content_type != "application/x-www-form-urlencoded" or not 0 < length <= 8192:
                self.send_error(400, "Expected a small URL-encoded form submission")
                return
            try:
                fields = parse_qs(
                    self.rfile.read(length).decode("utf-8", errors="replace"),
                    keep_blank_values=True, max_num_fields=20,
                )
            except ValueError:
                self.send_error(400, "Invalid form submission")
                return
            if not fields or not set(fields).issubset(allowed_fields):
                self.send_error(400, "Unexpected or prohibited form fields")
                return
            cleaned = {name: str(values[-1])[:500] for name, values in fields.items()}
            append_event(event_log, {
                "event": "form_submission",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client": self.client_address[0],
                "fields": cleaned,
            })
            print(
                f"Awareness response from {self.client_address[0]} · fields={list(cleaned)}",
                flush=True,
            )
            self.send_response(303)
            self.send_header("Location", "/thanks.html")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def log_message(self, fmt, *args):
            append_event(event_log, {
                "event": "http_request",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client": self.client_address[0],
                "method": self.command,
                "path": urlsplit(self.path).path,
                "message": fmt % args,
            })
            print(f"HTTP {self.client_address[0]} · {self.command} {self.path}", flush=True)

    return Handler
