#!/usr/bin/env python3
# @name: MITM Traffic Shaper
# @desc: Uses Linux tc (traffic control) to limit and shape traffic on the bridge interface during MITM operations, keeping latency under suspicio...
# @category: evasion
# @danger: true
# @active: true
"""
RaspyJack Payload -- MITM Traffic Shaper
=========================================
Author: 7h30th3r0n3

Uses Linux `tc` (traffic control) to limit and shape traffic on the bridge
interface during MITM operations, keeping latency under suspicious thresholds
to maintain stealth.

Usage
-----
    traffic_shaper.py [interface] [bandwidth_mbit|auto]

    interface      -- interface to shape (prompted from a detected list
                       if omitted; falls back to br0/eth0/wlan0 detection)
    bandwidth_mbit -- bandwidth limit in Mbps (1-100, default 10), or
                       "auto" to measure baseline latency first and pick a
                       matching limit

Applies HTB/SFQ shaping to the interface and prints periodic latency and
queue-stat status lines until interrupted with Ctrl-C, at which point all
tc rules are removed and a final summary (including per-protocol counters)
is printed.

Requires: iproute2 (tc command)
"""

from payloads._web_input import request_input
import os
import sys
import time
import subprocess
import re

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_IFACE = "br0"
FALLBACK_IFACES = ["br0", "eth0", "wlan0"]
MIN_BW_MBIT = 1
MAX_BW_MBIT = 100
DEFAULT_BW_MBIT = 10
STATUS_INTERVAL = 5.0

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _detect_interface():
    """Detect the best interface for traffic shaping."""
    for candidate in FALLBACK_IFACES:
        try:
            r = subprocess.run(
                ["ip", "link", "show", candidate],
                capture_output=True, text=True, timeout=5,
            )
            if "UP" in r.stdout:
                return candidate
        except Exception:
            pass
    return DEFAULT_IFACE

# ---------------------------------------------------------------------------
# TC (traffic control) commands
# ---------------------------------------------------------------------------

def _run_tc(args):
    """Run a tc command and return (success, output)."""
    try:
        r = subprocess.run(
            ["tc"] + args,
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as exc:
        return False, str(exc)


def _apply_shaping(iface_name, bw_mbit):
    """Apply HTB qdisc with bandwidth limit."""
    # Remove existing rules first
    _run_tc(["qdisc", "del", "dev", iface_name, "root"])
    time.sleep(0.1)

    # Add root HTB qdisc
    ok, msg = _run_tc([
        "qdisc", "add", "dev", iface_name, "root", "handle", "1:",
        "htb", "default", "10",
    ])
    if not ok:
        return False, msg

    # Add class with bandwidth limit
    rate = f"{bw_mbit}mbit"
    burst = f"{max(bw_mbit * 2, 15)}k"
    ok, msg = _run_tc([
        "class", "add", "dev", iface_name, "parent", "1:",
        "classid", "1:10", "htb",
        "rate", rate, "burst", burst, "cburst", burst,
    ])
    if not ok:
        return False, msg

    # Add SFQ for fairness within the class
    ok, msg = _run_tc([
        "qdisc", "add", "dev", iface_name, "parent", "1:10",
        "handle", "10:", "sfq", "perturb", "10",
    ])
    return ok, msg


def _remove_shaping(iface_name):
    """Remove all tc rules from the interface."""
    return _run_tc(["qdisc", "del", "dev", iface_name, "root"])


def _get_queue_stats(iface_name):
    """Parse tc -s qdisc output for queue statistics."""
    ok, output = _run_tc(["-s", "qdisc", "show", "dev", iface_name])
    stats = {"sent": 0, "dropped": 0, "overlimits": 0, "backlog": 0}
    if not ok:
        return stats

    sent_match = re.search(r"Sent (\d+) bytes (\d+) pkt", output)
    if sent_match:
        stats["sent"] = int(sent_match.group(2))

    dropped_match = re.search(r"dropped (\d+)", output)
    if dropped_match:
        stats["dropped"] = int(dropped_match.group(1))

    overlimits_match = re.search(r"overlimits (\d+)", output)
    if overlimits_match:
        stats["overlimits"] = int(overlimits_match.group(1))

    backlog_match = re.search(r"backlog (\d+)b", output)
    if backlog_match:
        stats["backlog"] = int(backlog_match.group(1))

    return stats

# ---------------------------------------------------------------------------
# Latency measurement
# ---------------------------------------------------------------------------

def _measure_latency(target="8.8.8.8"):
    """Measure round-trip latency using ping."""
    try:
        r = subprocess.run(
            ["ping", "-c", "3", "-W", "2", target],
            capture_output=True, text=True, timeout=10,
        )
        match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", r.stdout)
        if match:
            return float(match.group(1))
    except Exception:
        pass
    return 0.0

# ---------------------------------------------------------------------------
# Per-protocol stats
# ---------------------------------------------------------------------------

def _get_proto_stats():
    """Get per-protocol traffic stats via /proc/net/snmp."""
    stats = []
    try:
        with open("/proc/net/snmp") as f:
            lines = f.readlines()
        for i in range(0, len(lines) - 1, 2):
            header = lines[i].strip().split()
            values = lines[i + 1].strip().split()
            proto = header[0].rstrip(":")
            if proto in ("Tcp", "Udp", "Icmp"):
                # Find InSegs/InDatagrams/InMsgs and Out equivalents
                for j, field in enumerate(header[1:], 1):
                    if field.startswith("In") and "Seg" in field or field.startswith("In") and "Dat" in field:
                        in_val = int(values[j]) if j < len(values) else 0
                        stats.append(f"{proto}: In={in_val}")
                        break
                else:
                    stats.append(f"{proto}: active")
    except Exception:
        stats.append("Stats unavailable")
    return stats

# ---------------------------------------------------------------------------
# Auto-mode: measure baseline then set shaping to match
# ---------------------------------------------------------------------------

def _measure_baseline():
    """Measure baseline latency before shaping. Returns (avg_latency, bandwidth_mbit)."""
    print("Measuring baseline latency...", flush=True)

    latencies = []
    for _ in range(3):
        lat = _measure_latency()
        if lat > 0:
            latencies.append(lat)
        time.sleep(1)

    if not latencies:
        print("Baseline measurement failed.", flush=True)
        return None, DEFAULT_BW_MBIT

    avg = sum(latencies) / len(latencies)
    # Heuristic: lower bandwidth for higher baseline latency
    if avg < 10:
        bandwidth_mbit = 50
    elif avg < 30:
        bandwidth_mbit = 20
    elif avg < 100:
        bandwidth_mbit = 10
    else:
        bandwidth_mbit = 5

    print(f"Baseline: {avg:.1f}ms -> {bandwidth_mbit}Mbps", flush=True)
    return avg, bandwidth_mbit

# ---------------------------------------------------------------------------
# Interface / bandwidth selection
# ---------------------------------------------------------------------------

def _prompt_interface():
    ifaces = list_interfaces("any")
    if not ifaces:
        return None
    if len(ifaces) == 1:
        return ifaces[0]["name"]

    print("Available interfaces:", flush=True)
    for i, ifc in enumerate(ifaces, 1):
        state = "up" if ifc["is_up"] else "down"
        print(f"  {i}. {ifc['name']} ({state}, {ifc['ip'] or 'no ip'})", flush=True)

    while True:
        choice = request_input("Select interface number (blank to cancel): ").strip()
        if not choice:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(ifaces):
            return ifaces[int(choice) - 1]["name"]
        print("Invalid selection, try again.", flush=True)


def _resolve_interface(arg):
    known = [i["name"] for i in list_interfaces("any")]
    if arg:
        if known and arg not in known:
            print(f"Interface '{arg}' not found. Available: {', '.join(known)}", flush=True)
            return None
        return arg
    if not known:
        fallback = _detect_interface()
        print(f"No interfaces detected; falling back to {fallback}", flush=True)
        return fallback
    return _prompt_interface()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    iface_arg = sys.argv[1] if len(sys.argv) > 1 else None
    bw_arg = sys.argv[2] if len(sys.argv) > 2 else None

    iface = _resolve_interface(iface_arg)
    if not iface:
        print("No interface selected. Exiting.", flush=True)
        return 1

    baseline_latency_ms = 0.0
    if bw_arg and bw_arg.lower() == "auto":
        baseline_latency_ms, bandwidth_mbit = _measure_baseline()
    elif bw_arg:
        try:
            bandwidth_mbit = max(MIN_BW_MBIT, min(MAX_BW_MBIT, int(bw_arg)))
        except ValueError:
            print(f"Invalid bandwidth '{bw_arg}'; must be an integer or 'auto'.", flush=True)
            return 1
    else:
        bandwidth_mbit = DEFAULT_BW_MBIT

    print(f"Applying traffic shaping on {iface}: {bandwidth_mbit} Mbps limit", flush=True)
    ok, msg = _apply_shaping(iface, bandwidth_mbit)
    if not ok:
        print(f"Failed to apply shaping: {msg}", flush=True)
        return 1

    print(f"Traffic shaping active on {iface}. Press Ctrl-C to stop and remove.", flush=True)
    try:
        while True:
            time.sleep(STATUS_INTERVAL)
            lat = _measure_latency()
            qs = _get_queue_stats(iface)
            print(
                f"[status] latency={lat:.1f}ms BW={bandwidth_mbit}Mbps "
                f"sent={qs['sent']} dropped={qs['dropped']} overlimits={qs['overlimits']}",
                flush=True,
            )
    except KeyboardInterrupt:
        print("\nStopping traffic shaping...", flush=True)
    finally:
        _remove_shaping(iface)
        print(f"Removed tc rules from {iface}.", flush=True)
        print("Per-protocol stats at exit:", flush=True)
        for line in _get_proto_stats():
            print(f"  {line}", flush=True)
        if baseline_latency_ms:
            print(f"Baseline latency was {baseline_latency_ms:.1f}ms", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
