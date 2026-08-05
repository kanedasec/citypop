#!/usr/bin/env python3
# @name: Validated Transparent Bridge Capture
# @desc: Bridge two explicitly selected physical Ethernet interfaces, capture traversing traffic, validate setup, and restore link state on exit.
# @category: network
# @danger: true
# @active: true
# @web: true
# @maturity: limited
"""
RaspyJack Payload – Stealth Bridge MITM
---------------------------------------------------------
- Requires explicit selection of 2 physical, unaddressed Ethernet interfaces
- Creates a transparent bridge (br0) with NO IP (stealth)
- Starts tcpdump on br0 (PCAP)
- Live protocol counters via tshark

Controls
--------
  CLI  -- Run: python3 silent_bridge.py [duration_seconds]
          Eligible interfaces are validated and selected through prompts.
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
from payloads._web_input import request_input

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


class BridgeError(RuntimeError):
    pass


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _checked(cmd):
    result = _run(cmd)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip() or f"exit {result.returncode}"
        raise BridgeError(f"{' '.join(cmd)}: {detail}")
    return result


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


def _physical_ethernet_ifaces():
    found = []
    for name in sorted(os.listdir("/sys/class/net")):
        base = f"/sys/class/net/{name}"
        if name in ("lo", BRIDGE) or os.path.isdir(f"{base}/wireless"):
            continue
        if not os.path.exists(f"{base}/device") or _read(f"{base}/type") != "1":
            continue
        if not _iface_has_carrier(name):
            continue
        # Never flush or enslave an addressed interface; it may carry City Pop.
        if _iface_ip(name):
            continue
        found.append(name)
    return found


def _choose_bridge_ports():
    interfaces = _physical_ethernet_ifaces()
    if len(interfaces) < 2:
        raise BridgeError(
            "two carrier-up, unaddressed physical Ethernet interfaces are required; "
            "Wi-Fi, Tailscale, VPN, Docker, and management interfaces are rejected"
        )
    first = str(request_input(
        "Select first unaddressed physical Ethernet bridge port",
        input_type="select", choices=interfaces, required=True,
    ))
    second_choices = [name for name in interfaces if name != first]
    second = str(request_input(
        "Select second unaddressed physical Ethernet bridge port",
        input_type="select", choices=second_choices, required=True,
    ))
    if first not in interfaces or second not in second_choices:
        raise BridgeError("invalid bridge-interface selection")
    return first, second


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


def ensure_bridge_cleanup(if1, if2, original_states=None):
    for interface in (if1, if2):
        _run(["ip", "link", "set", interface, "nomaster"])
        _run(["ip", "link", "set", interface, "promisc", "off"])
    _run(["ip", "link", "set", BRIDGE, "down"])
    _run(["ip", "link", "del", BRIDGE])
    for interface in (if1, if2):
        state = (original_states or {}).get(interface, "up")
        _run(["ip", "link", "set", interface, "up" if state == "up" else "down"])


def setup_bridge(if1, if2):
    if os.path.exists(f"/sys/class/net/{BRIDGE}"):
        raise BridgeError(f"{BRIDGE} already exists; stop the prior bridge first")
    states = {if1: _iface_operstate(if1), if2: _iface_operstate(if2)}
    try:
        _checked(["ip", "link", "add", BRIDGE, "type", "bridge"])
        for interface in (if1, if2):
            _checked(["ip", "link", "set", interface, "master", BRIDGE])
            _checked(["ip", "link", "set", interface, "promisc", "on"])
            _checked(["ip", "link", "set", interface, "up"])
        _checked(["ip", "link", "set", BRIDGE, "up"])
        for interface in (if1, if2):
            if not os.path.exists(f"/sys/class/net/{BRIDGE}/brif/{interface}"):
                raise BridgeError(f"{interface} did not join {BRIDGE}")
    except Exception:
        ensure_bridge_cleanup(if1, if2, states)
        raise
    return states


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

    print("Transparent bridge: validating physical Ethernet interfaces...", flush=True)
    try:
        if1, if2 = _choose_bridge_ports()
    except BridgeError as exc:
        print(f"Bridge preflight failed: {exc}", flush=True)
        return 1
    ip1 = _iface_ip(if1) or "-"
    ip2 = _iface_ip(if2) or "-"
    print(f"IF1: {if1} (ip={ip1})", flush=True)
    print(f"IF2: {if2} (ip={ip2})", flush=True)

    print(f"Setting up stealth bridge {if1} <-> {if2}...", flush=True)
    try:
        original_states = setup_bridge(if1, if2)
    except BridgeError as exc:
        print(f"Bridge setup failed and was rolled back: {exc}", flush=True)
        return 1

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
        ensure_bridge_cleanup(if1, if2, original_states)
        print_stats(if1, if2)
        print("Stealth bridge stopped.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
