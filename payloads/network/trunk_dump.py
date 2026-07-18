#!/usr/bin/env python3
# @name: VLAN Trunk Capture
# @desc: 802.1Q trunk negotiation + multi-VLAN traffic dump.
# @category: network
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Capture duration","type":"number","default":"60"},{"name":"limit","label":"Packet limit","type":"number","default":"10000"}]

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from payloads._web_input import request_input


def main() -> int:
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    interface = str(request_input("Select trunk interface", input_type="select", choices=interfaces))
    try:
        seconds = max(1, min(int(sys.argv[1] if len(sys.argv) > 1 else "60"), 3600))
        limit = max(1, min(int(sys.argv[2] if len(sys.argv) > 2 else "10000"), 1_000_000))
    except ValueError:
        print("Duration and packet limit must be whole numbers.")
        return 2
    root = Path(os.environ.get("CITYPOP_ROOT", Path(__file__).resolve().parents[2]))
    output_dir = root / "loot" / "Network"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"vlan_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.pcap"
    print(f"Capturing tagged frames on {interface}…", flush=True)
    result = subprocess.run(["timeout", str(seconds), "tcpdump", "-U", "-nn", "-i", interface, "-c", str(limit), "-w", str(output), "vlan"], timeout=seconds + 15)
    if output.exists():
        print(f"Saved {output.stat().st_size} bytes to {output.relative_to(root)}")
    return 0 if result.returncode in {0, 124} else result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
