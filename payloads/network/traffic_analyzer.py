#!/usr/bin/env python3
# @name: Live Traffic Analyzer
# @desc: Capture a selected interface and publish a temporary web dashboard of protocol, endpoint, conversation, rate, and packet statistics; print its endpoint in the terminal.
# @category: network
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"view","label":"Primary table","type":"select","choices":["protocols","endpoints","conversations"],"default":"protocols"},{"name":"seconds","label":"Dashboard duration","type":"number","default":"60"}]

import shutil
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from payloads._dashboard import DashboardServer
from payloads._web_input import request_input


def main() -> int:
    if not shutil.which("tshark"):
        print("tshark is not installed.")
        return 2
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    if not interfaces:
        print("No capture interfaces were found.")
        return 1
    interface = str(request_input("Select capture interface", input_type="select", choices=interfaces))
    view = sys.argv[1] if len(sys.argv) > 1 else "protocols"
    try:
        seconds = max(1, min(int(sys.argv[2] if len(sys.argv) > 2 else "60"), 3600))
    except ValueError:
        print("Duration must be a whole number.")
        return 2
    if view not in {"protocols", "endpoints", "conversations"}:
        print("Unknown dashboard view.")
        return 2

    lock = threading.Lock()
    protocols, endpoints, conversations = Counter(), Counter(), Counter()
    packets = total_bytes = 0
    started = time.monotonic()

    command = [
        "tshark", "-l", "-n", "-i", interface, "-a", f"duration:{seconds}",
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
        "-e", "frame.len", "-e", "_ws.col.Protocol",
        "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

    def read_packets():
        nonlocal packets, total_bytes
        assert process.stdout is not None
        for line in process.stdout:
            fields = line.rstrip("\n").split("\t")
            fields += [""] * (6 - len(fields))
            length, protocol, ipv4_src, ipv6_src, ipv4_dst, ipv6_dst = fields[:6]
            source, destination = ipv4_src or ipv6_src or "unknown", ipv4_dst or ipv6_dst or "unknown"
            try:
                size = int(length)
            except ValueError:
                size = 0
            with lock:
                packets += 1
                total_bytes += size
                protocols[protocol or "unknown"] += 1
                endpoints[source] += 1
                endpoints[destination] += 1
                conversations[f"{source} ↔ {destination}"] += 1

    threading.Thread(target=read_packets, daemon=True).start()

    def rows(counter, key):
        return [{key: name, "packets": count} for name, count in counter.most_common(50)]

    def snapshot():
        with lock:
            tables = {
                "protocols": rows(protocols, "protocol"),
                "endpoints": rows(endpoints, "endpoint"),
                "conversations": rows(conversations, "conversation"),
            }
            primary = tables.pop(view)
            return {
                "status": "capturing" if process.poll() is None else "complete",
                "interface": interface,
                "elapsed_seconds": round(time.monotonic() - started, 1),
                "packets": packets,
                "bytes": total_bytes,
                view: primary,
                **tables,
            }

    dashboard = DashboardServer("Live Traffic Analyzer", snapshot)
    try:
        print(f"Dashboard: {dashboard.start()}", flush=True)
    except OSError as exc:
        print(f"Dashboard unavailable: {exc}", flush=True)
    print(f"Analyzing {interface} for {seconds} seconds…", flush=True)
    try:
        code = process.wait(timeout=seconds + 30)
    except subprocess.TimeoutExpired:
        process.terminate()
        code = process.wait(timeout=5)
    with lock:
        print(f"Captured {packets} packets / {total_bytes} bytes", flush=True)
        for name, count in protocols.most_common(15):
            print(f"  {name}: {count}", flush=True)
    dashboard.stop()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
