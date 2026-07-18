#!/usr/bin/env python3
# @name: PCAP Packet Replayer
# @desc: Lists .pcap files from the loot directory and replays them using scapy.
# @category: utilities
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"speed","label":"Replay speed","type":"select","choices":["realtime","5x","maximum"],"default":"realtime"},{"name":"loops","label":"Replay count","type":"number","default":"1"}]

import os
import shutil
import subprocess
import sys
from pathlib import Path

from payloads._web_input import request_input

ROOT = Path(os.environ.get("CITYPOP_ROOT", Path(__file__).resolve().parents[2])).resolve()
LOOT = ROOT / "loot"


def main() -> int:
    tcpreplay = shutil.which("tcpreplay")
    if not tcpreplay:
        print("tcpreplay is not installed.")
        return 2
    captures = sorted((p for p in LOOT.rglob("*") if p.suffix.lower() in {".cap", ".pcap", ".pcapng"}), key=lambda p: p.stat().st_mtime, reverse=True)
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    if not captures or not interfaces:
        print("A capture in loot/ and a non-loopback network interface are required.")
        return 1
    cap_index = int(request_input("Select capture", input_type="select", choices=[
        {"value": str(i), "label": str(p.relative_to(LOOT))} for i, p in enumerate(captures)
    ]))
    interface = str(request_input("Select output interface", input_type="select", choices=interfaces))
    speed = sys.argv[1] if len(sys.argv) > 1 else "realtime"
    try:
        loops = max(1, min(int(sys.argv[2] if len(sys.argv) > 2 else "1"), 100))
    except ValueError:
        print("Replay count must be a whole number from 1 to 100.")
        return 2
    command = [tcpreplay, "--intf1", interface, "--loop", str(loops)]
    if speed == "maximum":
        command.append("--topspeed")
    elif speed == "5x":
        command.extend(["--multiplier", "5"])
    command.append(str(captures[cap_index]))
    print(f"Replaying on {interface}; only use this on an authorized network.", flush=True)
    return subprocess.run(command, timeout=1800).returncode


if __name__ == "__main__":
    raise SystemExit(main())
